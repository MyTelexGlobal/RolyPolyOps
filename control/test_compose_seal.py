import base64
import concurrent.futures
import copy
import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import shutil
import subprocess
import unittest
from unittest import mock
import uuid

try:
    from .compose_seal import ALGORITHM, AAD_FIELDS, Sealer, SealError, canonical
except ImportError:
    from compose_seal import ALGORITHM, AAD_FIELDS, Sealer, SealError, canonical


def identity():
    return str(uuid.uuid4())


def envelope(sealer, metadata, *, generation=1, request_id=None, mode="create", expires=None):
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    public = sealer.public()
    outer = {"v": 1, "algorithm": ALGORITHM, "nodeId": sealer.node_id, "keyId": public["id"], "storageId": metadata["id"],
             "requestId": request_id or identity(), "bindingGeneration": generation, "mode": mode,
             "expiresAt": expires or (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()}
    inner = {"metadata": metadata, "repoPassword": "repository-sentinel", "credentials": {"username": "user", "password": "credential-sentinel"},
             "requestId": outer["requestId"], "bindingGeneration": generation, "mode": mode}
    key, iv = AESGCM.generate_key(256), os.urandom(12)
    pub = serialization.load_der_public_key(base64.b64decode(public["publicKey"]))
    wrapped = pub.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    encrypted = AESGCM(key).encrypt(iv, canonical(inner), canonical({**{k: outer[k] for k in AAD_FIELDS}, "purpose": "storage"}))
    outer.update(wrappedKey=base64.b64encode(wrapped).decode(), iv=base64.b64encode(iv).decode(), ciphertext=base64.b64encode(encrypted).decode())
    return outer


class SealTests(unittest.TestCase):
    def setUp(self):
        try:
            import cryptography
        except ImportError:
            self.skipTest("cryptography 41+ not installed")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sealer = Sealer(self.temp.name, identity())
        sid = identity()
        self.metadata = {"id": sid, "name": "Independent service", "kind": "rest", "endpoint": "https://storage.example/" + sid}

    def test_real_crypto_round_trip_and_persistent_key(self):
        sealed = envelope(self.sealer, self.metadata)
        opened = self.sealer.open(sealed, storage_id=self.metadata["id"], mode="create", metadata=self.metadata)
        self.assertEqual(opened["repoPassword"], "repository-sentinel")
        self.assertEqual(self.sealer.public(), Sealer(self.temp.name, self.sealer.node_id).public())
        self.assertEqual(Path(self.temp.name, "seal-key.pem").stat().st_mode & 0o777, 0o600)
        self.assertNotIn("sentinel", json.dumps(sealed))

    def test_actual_webcrypto_node_envelope_opens_with_agent_library(self):
        node = shutil.which("node")
        if not node:
            self.skipTest("Node WebCrypto unavailable")
        public = self.sealer.public()
        payload = {"key": public, "nodeId": self.sealer.node_id, "metadata": self.metadata, "requestId": identity(),
                   "expiresAt": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat()}
        script = r"""
const {webcrypto} = require('crypto');
let input = '';
process.stdin.on('data', b => input += b);
process.stdin.on('end', async () => {
 const x = JSON.parse(input), c = webcrypto.subtle;
 const o = {v:1,algorithm:'RSA-OAEP-256+A256GCM',nodeId:x.nodeId,keyId:x.key.id,storageId:x.metadata.id,requestId:x.requestId,bindingGeneration:1,mode:'create',expiresAt:x.expiresAt};
 const a = {v:o.v,nodeId:o.nodeId,keyId:o.keyId,storageId:o.storageId,requestId:o.requestId,bindingGeneration:o.bindingGeneration,mode:o.mode,expiresAt:o.expiresAt,purpose:'storage'};
 const ordered = {}; Object.keys(a).sort().forEach(k => ordered[k] = a[k]);
 const plain = {metadata:x.metadata,repoPassword:'webcrypto-sentinel',credentials:{username:'u',password:'p'},bindingGeneration:1,requestId:o.requestId,mode:'create'};
 const pub = await c.importKey('spki',Buffer.from(x.key.publicKey,'base64'),{name:'RSA-OAEP',hash:'SHA-256'},false,['wrapKey']);
 const key = await c.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
 const iv = webcrypto.getRandomValues(new Uint8Array(12));
 o.wrappedKey = Buffer.from(await c.wrapKey('raw',key,pub,{name:'RSA-OAEP'})).toString('base64');
 o.iv = Buffer.from(iv).toString('base64');
 o.ciphertext = Buffer.from(await c.encrypt({name:'AES-GCM',iv,additionalData:Buffer.from(JSON.stringify(ordered)),tagLength:128},key,Buffer.from(JSON.stringify(plain)))).toString('base64');
 process.stdout.write(JSON.stringify(o));
});
"""
        result = subprocess.run([node, "-e", script], input=json.dumps(payload), capture_output=True, text=True, timeout=20, check=True)
        opened = self.sealer.open(json.loads(result.stdout), storage_id=self.metadata["id"], mode="create", metadata=self.metadata)
        self.assertEqual(opened["repoPassword"], "webcrypto-sentinel")

    def test_all_aad_and_cipher_fields_reject_tamper(self):
        original = envelope(self.sealer, self.metadata)
        for key in original:
            with self.subTest(key=key):
                changed = copy.deepcopy(original)
                value = changed[key]
                if key == "bindingGeneration":
                    changed[key] += 1
                elif key == "v":
                    changed[key] = 2
                elif key in {"wrappedKey", "iv", "ciphertext"}:
                    data = bytearray(base64.b64decode(value))
                    data[-1] ^= 1
                    changed[key] = base64.b64encode(data).decode()
                elif key == "expiresAt":
                    changed[key] = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=4)).isoformat()
                elif key in {"nodeId", "storageId", "requestId"}:
                    changed[key] = identity()
                elif key == "mode":
                    changed[key] = "attach"
                else:
                    changed[key] = value + "x"
                with self.assertRaises(SealError):
                    self.sealer.open(changed, storage_id=self.metadata["id"], mode="create", metadata=self.metadata)

    def test_exact_metadata_and_expiry_before_apply(self):
        value = envelope(self.sealer, self.metadata)
        with self.assertRaisesRegex(SealError, "envelope_plaintext_mismatch"):
            self.sealer.open(value, storage_id=self.metadata["id"], mode="create", metadata=self.metadata | {"endpoint": "https://elsewhere.example/repo"})
        value = envelope(self.sealer, self.metadata, expires=(dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat())
        with self.assertRaisesRegex(SealError, "envelope_expired"):
            self.sealer.open(value, storage_id=self.metadata["id"], mode="create")

    def test_racing_first_use_publishes_one_complete_identity(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            keys = list(pool.map(lambda _: Sealer(self.temp.name, self.sealer.node_id).public(), range(5)))
        self.assertTrue(all(k == keys[0] for k in keys))
        self.assertFalse(list(Path(self.temp.name).glob(".seal-key.*")))

    def test_interrupted_temp_write_never_publishes_final_key(self):
        with mock.patch("os.fsync", side_effect=OSError("interrupted")):
            with self.assertRaises(OSError):
                self.sealer.public()
        self.assertFalse(Path(self.temp.name, "seal-key.pem").exists())
        self.assertTrue(self.sealer.public()["id"])

    def test_final_symlink_or_truncated_key_is_never_replaced(self):
        path = Path(self.temp.name, "seal-key.pem")
        path.write_bytes(b"truncated")
        path.chmod(0o600)
        with self.assertRaisesRegex(SealError, "invalid_private_key"):
            self.sealer.public()
        self.assertEqual(path.read_bytes(), b"truncated")
        path.unlink()
        sentinel = Path(self.temp.name, "sentinel")
        sentinel.write_text("untouched")
        sentinel.chmod(0o600)
        path.symlink_to(sentinel)
        with self.assertRaisesRegex(SealError, "unsafe_key_permissions"):
            self.sealer.public()
        self.assertEqual(sentinel.read_text(), "untouched")


if __name__ == "__main__":
    unittest.main()
