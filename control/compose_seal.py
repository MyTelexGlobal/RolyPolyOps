"""Versioned WebCrypto-compatible credential envelopes. No import-time crypto dependency."""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import uuid

ALGORITHM = "RSA-OAEP-256+A256GCM"
AAD_FIELDS = ("v", "nodeId", "keyId", "storageId", "requestId", "bindingGeneration", "mode", "expiresAt")


class SealError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _crypto():
    try:
        import cryptography
        if int(cryptography.__version__.split(".")[0]) < 41:
            raise ImportError()
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return hashes, serialization, rsa, padding, AESGCM
    except ImportError:
        raise SealError("cryptography_unavailable") from None


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        return False


def _binary(value, size=None):
    try:
        if not isinstance(value, str) or len(value) > 24000:
            raise ValueError()
        raw = base64.b64decode(value, validate=True)
        if size is not None and len(raw) != size:
            raise ValueError()
        return raw
    except (ValueError, TypeError):
        raise SealError("invalid_envelope") from None


class Sealer:
    def __init__(self, state, node_id):
        if not _uuid(node_id):
            raise SealError("invalid_node_id")
        self.state = Path(state)
        self.node_id = node_id
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        self.path = self.state / "seal-key.pem"

    def _key(self):
        hashes, serialization, rsa, padding, aes = _crypto()
        if not self.path.exists() and not self.path.is_symlink():
            key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            temporary = self.state / (".seal-key." + uuid.uuid4().hex + ".pem")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
                try:
                    os.link(temporary, self.path, follow_symlinks=False)
                except FileExistsError:
                    pass
                d = os.open(self.state, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(d)
                finally:
                    os.close(d)
            finally:
                temporary.unlink(missing_ok=True)
        info = self.path.lstat()
        if not self.path.is_file() or self.path.is_symlink() or info.st_mode & 0o077 or info.st_uid != os.geteuid():
            raise SealError("unsafe_key_permissions")
        try:
            key = serialization.load_pem_private_key(self.path.read_bytes(), password=None)
        except Exception:
            raise SealError("invalid_private_key") from None
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 3072:
            raise SealError("invalid_private_key")
        return key

    def public(self):
        _, serialization, _, _, _ = _crypto()
        raw = self._key().public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
        return {"id": hashlib.sha256(raw).hexdigest(), "publicKey": base64.b64encode(raw).decode(),
                "algorithm": ALGORITHM}

    def open(self, envelope, *, storage_id, mode, metadata=None, now=None):
        expected = set(AAD_FIELDS) | {"algorithm", "wrappedKey", "iv", "ciphertext"}
        if not isinstance(envelope, dict) or set(envelope) != expected:
            raise SealError("invalid_envelope")
        if (type(envelope["v"]) is not int or envelope["v"] != 1 or
                envelope["algorithm"] != ALGORITHM or envelope["nodeId"] != self.node_id or
                envelope["storageId"] != storage_id or not _uuid(storage_id) or
                not _uuid(envelope["requestId"]) or envelope["mode"] != mode or (not isinstance(mode, str) or mode not in {"create", "attach"}) or
                type(envelope["bindingGeneration"]) is not int or envelope["bindingGeneration"] < 1):
            raise SealError("envelope_binding_mismatch")
        if envelope["keyId"] != self.public()["id"]:
            raise SealError("envelope_key_mismatch")
        try:
            expires = dt.datetime.fromisoformat(envelope["expiresAt"].replace("Z", "+00:00"))
            if expires.utcoffset() != dt.timedelta(0):
                raise ValueError()
        except (ValueError, AttributeError, TypeError):
            raise SealError("invalid_envelope") from None
        current = now or dt.datetime.now(dt.timezone.utc)
        if expires <= current:
            raise SealError("envelope_expired")
        if expires > current + dt.timedelta(minutes=15):
            raise SealError("envelope_expiry_invalid")
        wrapped = _binary(envelope["wrappedKey"], 384)
        iv = _binary(envelope["iv"], 12)
        ciphertext = _binary(envelope["ciphertext"])
        if not 17 <= len(ciphertext) <= 16384 + 16:
            raise SealError("invalid_envelope")
        aad = canonical({**{k: envelope[k] for k in AAD_FIELDS}, "purpose": "storage"})
        hashes, _, _, padding, AESGCM = _crypto()
        try:
            key = self._key().decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                                           algorithm=hashes.SHA256(), label=None))
            if len(key) != 32:
                raise ValueError()
            plaintext = AESGCM(key).decrypt(iv, ciphertext, aad)
            inner = json.loads(plaintext.decode("utf-8"))
        except Exception:
            raise SealError("envelope_authentication_failed") from None
        if (not isinstance(inner, dict) or set(inner) != {"metadata", "repoPassword", "credentials", "bindingGeneration", "requestId", "mode"}
                or any(inner[k] != envelope[k] for k in ("bindingGeneration", "requestId", "mode"))
                or not isinstance(inner["metadata"], dict) or inner["metadata"].get("id") != storage_id
                or (metadata is not None and inner["metadata"] != metadata)
                or not isinstance(inner["credentials"], dict) or not isinstance(inner["repoPassword"], str)
                or not 1 <= len(inner["repoPassword"]) <= 4096):
            raise SealError("envelope_plaintext_mismatch")
        return inner
