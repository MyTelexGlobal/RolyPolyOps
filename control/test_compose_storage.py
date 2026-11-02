import contextlib
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

try:
    from . import compose_storage as storage
    from .compose_seal import Sealer
    from .test_compose_seal import envelope
except ImportError:
    import compose_storage as storage
    from compose_seal import Sealer
    from test_compose_seal import envelope


def uid():
    return str(uuid.uuid4())


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.sid, self.node = uid(), uid()
        self.metadata = {"id": self.sid, "name": "Dedicated storage", "kind": "rest", "endpoint": "https://storage.example/" + self.sid}
        self.manager = storage.StorageManager(self.temp.name, Sealer(self.temp.name, self.node))

    def sealed(self, **kwargs):
        try:
            return envelope(self.manager.sealer, self.metadata, **kwargs)
        except ImportError:
            self.skipTest("cryptography 41+ not installed")

    def test_metadata_blocks_local_backends_userinfo_controls_and_dotpaths(self):
        for endpoint in ("file:///tmp/repo", "https://user:pass@example.com/repo", "https://example.com/repo?q=x", "https://example.com/%2e%2e/root", "https://example.com/a\\b", "https://example.com/a\n"):
            with self.subTest(endpoint=endpoint), self.assertRaises(storage.StorageError):
                storage.validate_metadata(self.metadata | {"endpoint": endpoint})
        for key in ("command", "repoPassword", "credentials"):
            with self.assertRaises(storage.StorageError):
                storage.validate_metadata(self.metadata | {key: "forbidden"})

    def test_dns_rejects_mixed_private_answers(self):
        answers = [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with mock.patch.object(storage.socket, "getaddrinfo", return_value=answers):
            with self.assertRaisesRegex(storage.StorageError, "storage_address_forbidden"):
                storage.public_addresses("storage.example", 443)

    def test_rest_positive_empty_checks_every_resource(self):
        calls = []
        def request(url, headers, proxy, **kwargs):
            calls.append(url)
            return None if url.endswith("/config") else b"[]"
        with mock.patch.object(storage, "_request", side_effect=request):
            proof = storage.prove_empty(self.metadata, {"username": "u", "password": "p"}, "proxy")
        self.assertTrue(proof["complete"])
        self.assertEqual(len(calls), 6)
        self.assertTrue(all(url.startswith(self.metadata["endpoint"] + "/") for url in calls))

    def test_fresh_authenticated_rest_namespace_404_is_positive_absence(self):
        with mock.patch.object(storage, "_request", return_value=None) as request:
            proof = storage.prove_empty(self.metadata, {"username": "u", "password": "p"}, "proxy")
        self.assertTrue(proof["complete"])
        self.assertEqual(request.call_count, 6)
        self.assertTrue(all(call.kwargs.get("allow_missing") is True for call in request.call_args_list))
        for code in ("storage_listing_failed", "storage_transport_failed"):
            with mock.patch.object(storage, "_request", side_effect=storage.StorageError(code)), self.assertRaisesRegex(storage.StorageError, code):
                storage.prove_empty(self.metadata, {"username": "wrong", "password": "wrong"}, "proxy")

    def test_rest_foreign_content_and_errors_never_mean_empty(self):
        for output in (b'[ {"name":"foreign"} ]', b'{"error":"denied"}', b'not-json'):
            with mock.patch.object(storage, "_request", side_effect=[None, output]):
                with self.assertRaises(storage.StorageError):
                    storage.prove_empty(self.metadata, {"username": "u", "password": "p"}, "proxy")
        with mock.patch.object(storage, "_request", side_effect=storage.StorageError("storage_listing_failed")):
            with self.assertRaisesRegex(storage.StorageError, "storage_listing_failed"):
                storage.prove_empty(self.metadata, {"username": "u", "password": "p"}, "proxy")

    def test_s3_populated_late_page_and_missing_continuation_fail(self):
        metadata = {"id": self.sid, "name": "S3", "kind": "s3", "endpoint": "https://s3.example", "bucket": "dedicated-bucket", "prefix": "backup/" + self.sid, "region": "us-east-1"}
        credentials = {"accessKeyId": "key", "secretAccessKey": "secret"}
        first = ('<ListBucketResult><Name>dedicated-bucket</Name><Prefix>' + metadata['prefix'] + '/</Prefix><IsTruncated>true</IsTruncated><NextContinuationToken>next+token</NextContinuationToken></ListBucketResult>').encode()
        second = b'<ListBucketResult><IsTruncated>false</IsTruncated><Contents><Key>foreign</Key></Contents></ListBucketResult>'
        with mock.patch.object(storage, "_request", side_effect=[first, second]) as request:
            with self.assertRaisesRegex(storage.StorageError, "storage_namespace_not_empty"):
                storage.prove_empty(metadata, credentials, "proxy")
            self.assertIn("continuation-token=next%2Btoken", request.call_args[0][0])
        with mock.patch.object(storage, "_request", return_value=('<ListBucketResult><Name>dedicated-bucket</Name><Prefix>' + metadata['prefix'] + '/</Prefix><IsTruncated>true</IsTruncated></ListBucketResult>').encode()):
            with self.assertRaisesRegex(storage.StorageError, "storage_listing_incomplete"):
                storage.prove_empty(metadata, credentials, "proxy")

    def test_init_intent_before_effect_and_reconcile_without_reinit(self):
        sealed = self.sealed()
        operation = uid()
        params = {"storageId": self.sid, "metadata": self.metadata, "mode": "create", "envelope": sealed}
        @contextlib.contextmanager
        def session(binding):
            yield {}, "proxy"
        def run(env, args, **kwargs):
            value = storage.read(self.manager.directory / (self.sid + ".json"))
            self.assertEqual(value["status"], "init_pending")
            self.assertTrue(value["emptyProof"]["complete"])
            raise storage.StorageError("repository_timeout", unknown=True)
        with mock.patch.object(self.manager, "session", session), mock.patch.object(storage, "prove_empty", return_value={"complete": True}), mock.patch.object(self.manager, "_run", side_effect=run):
            with self.assertRaisesRegex(storage.StorageError, "repository_init_unknown") as error:
                self.manager.configure(operation, params)
            self.assertTrue(error.exception.unknown)
        with mock.patch.object(self.manager, "session", session), mock.patch.object(self.manager, "_config", return_value="a" * 64), mock.patch.object(self.manager, "_run") as run:
            result = self.manager.reconcile(operation)
        self.assertEqual(result["status"], "succeeded")
        self.assertEqual(result["result"]["repositoryId"], "a" * 64)
        run.assert_not_called()
        self.assertNotIn("sentinel", json.dumps(result))

    def test_generation_request_and_approved_metadata_are_bound(self):
        request = uid()
        sealed = self.sealed(request_id=request)
        with mock.patch.object(self.manager, "session", side_effect=storage.StorageError("storage_transport_failed")):
            with self.assertRaises(storage.StorageError):
                self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata, "mode": "create", "envelope": sealed})
        for value in (sealed, self.sealed(generation=2, request_id=request)):
            with self.assertRaisesRegex(storage.StorageError, "binding_generation_stale"):
                self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata, "mode": "create", "envelope": value})
        with self.assertRaisesRegex(storage.StorageError, "approved_metadata_required"):
            self.manager.configure(uid(), {"storageId": self.sid, "mode": "create", "envelope": self.sealed(generation=3)})
        with self.assertRaisesRegex(Exception, "envelope_plaintext_mismatch"):
            self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata | {"name": "changed"}, "mode": "create", "envelope": self.sealed(generation=3)})

    def test_first_unknown_source_discovery_attach_reads_config_without_init(self):
        sealed = self.sealed(mode="attach")
        @contextlib.contextmanager
        def session(binding):
            yield {}, "proxy"
        with mock.patch.object(self.manager, "session", session), mock.patch.object(self.manager, "_run", return_value=json.dumps({"id": "a" * 64}).encode()) as run, mock.patch.object(storage, "prove_empty") as empty:
            result = self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata, "mode": "attach", "envelope": sealed, "discoverRepositoryId": True})
        self.assertEqual(result["repositoryId"], "a" * 64)
        self.assertTrue(result["connected"])
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[1], ["cat", "config"])
        empty.assert_not_called()
        self.assertNotIn("sentinel", json.dumps(result))

    def test_discovery_attach_wrong_password_has_no_init_or_success(self):
        @contextlib.contextmanager
        def session(binding):
            yield {}, "proxy"
        with mock.patch.object(self.manager, "session", session), mock.patch.object(self.manager, "_run", side_effect=storage.StorageError("repository_access_failed")) as run, mock.patch.object(storage, "prove_empty") as empty:
            with self.assertRaisesRegex(storage.StorageError, "repository_access_failed"):
                self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata, "mode": "attach", "envelope": self.sealed(mode="attach"), "discoverRepositoryId": True})
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[1], ["cat", "config"])
        empty.assert_not_called()
        self.assertEqual(storage.read(self.manager.directory / (self.sid + ".json"))["status"], "accepted")

    def test_known_identity_cannot_be_replaced_or_rediscovered_after_failed_rotation(self):
        previous = {"status": "accepted", "bindingGeneration": 1, "consumedRequests": [], "authoritativeRepositoryId": "a" * 64}
        storage.atomic(self.manager.directory / (self.sid + ".json"), previous)
        for extra, error in (({"discoverRepositoryId": True}, "expected_repository_required"), ({}, "expected_repository_required"), ({"expectedRepositoryId": "b" * 64}, "repository_identity_mismatch")):
            params = {"storageId": self.sid, "metadata": self.metadata, "mode": "attach", "envelope": self.sealed(mode="attach", generation=2), **extra}
            with self.subTest(extra=extra), mock.patch.object(self.manager, "_password") as password, mock.patch.object(self.manager, "session") as session:
                with self.assertRaisesRegex(storage.StorageError, error):
                    self.manager.configure(uid(), params)
                password.assert_not_called()
                session.assert_not_called()
        self.assertEqual(storage.read(self.manager.directory / (self.sid + ".json")), previous)

    def test_missing_recipient_identity_and_forged_discovery_shapes_fail_before_application(self):
        for mode, extra, error in (("attach", {}, "expected_repository_required"), ("attach", {"discoverRepositoryId": False}, "invalid_repository_discovery"), ("attach", {"discoverRepositoryId": 1}, "invalid_repository_discovery"), ("attach", {"discoverRepositoryId": True, "expectedRepositoryId": None}, "invalid_repository_discovery"), ("create", {"discoverRepositoryId": True}, "invalid_repository_discovery")):
            params = {"storageId": self.sid, "metadata": self.metadata, "mode": mode, "envelope": self.sealed(mode=mode), **extra}
            with self.subTest(mode=mode, extra=extra), mock.patch.object(self.manager, "_password") as password:
                with self.assertRaisesRegex(storage.StorageError, error):
                    self.manager.configure(uid(), params)
                password.assert_not_called()

    def test_attach_mismatch_never_inits_and_password_not_in_argv(self):
        sealed = self.sealed(mode="attach")
        @contextlib.contextmanager
        def session(binding):
            yield {}, "proxy"
        with mock.patch.object(self.manager, "session", session), mock.patch.object(self.manager, "_config", return_value="b" * 64), mock.patch.object(storage, "prove_empty") as empty:
            with self.assertRaisesRegex(storage.StorageError, "repository_identity_mismatch"):
                self.manager.configure(uid(), {"storageId": self.sid, "metadata": self.metadata, "mode": "attach", "envelope": sealed, "expectedRepositoryId": "a" * 64})
        empty.assert_not_called()
        with mock.patch.object(storage.subprocess, "run", return_value=mock.Mock(returncode=0, stdout=b"{}")) as run:
            self.manager._run({"RESTIC_PASSWORD_FILE": "private-file"}, ["cat", "config"])
        self.assertNotIn("sentinel", repr(run.call_args.args))


if __name__ == "__main__":
    unittest.main()
