"""Pre-start recovery policy checks; no Docker or root access required."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("restore_policy", Path(__file__).parent.parent / "demo/ops/restore-policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class RestorePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "service"
        (self.root / "state/files").mkdir(parents=True)
        (self.root / "secrets").mkdir()
        (self.root / "state/files/recovery-proof.txt").write_text("proof")
        (self.root / "secrets/db_password").write_text("fixture-password")
        self.template = (Path(__file__).parent.parent / "demo/compose.yaml").read_bytes()
        (self.root / "compose.yaml").write_bytes(self.template)
        self.manifest = {"format": "rolypolyops-demo-v1", "webImage": "sha256:" + "a" * 64, "dbImage": "sha256:" + "b" * 64}

    def tearDown(self):
        self.temp.cleanup()

    def test_captured_environment_cannot_override_compose_execution(self):
        (self.root / ".env").write_text("COMPOSE_FILE=/outside/untrusted.yaml\nCOMPOSE_PROFILES=untrusted\nWEB_IMAGE=untrusted\n")
        result = policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A - PREVIEW")
        value = (self.root / ".env").read_text()
        self.assertNotIn("COMPOSE_FILE", value)
        self.assertNotIn("COMPOSE_PROFILES", value)
        self.assertNotIn("untrusted", value)
        self.assertIn("WEB_PORT=18082", value)
        self.assertEqual(result["webImage"][0], self.manifest["webImage"])
        self.assertEqual((self.root / ".env").stat().st_mode & 0o777, 0o600)

    def test_unrecognized_runtime_definition_rejected_before_start(self):
        (self.root / "compose.yaml").write_text("services: {web: {privileged: true}}")
        with self.assertRaisesRegex(ValueError, "unsupported_compose_definition"):
            policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A")
        self.assertFalse((self.root / ".env").exists())

    def test_symlink_cannot_mount_outside_recovery_directory(self):
        (self.root / "state/files/recovery-proof.txt").unlink()
        (self.root / "state/files/recovery-proof.txt").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "unsupported_file_type"):
            policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A")

    def test_environment_symlink_is_rejected(self):
        (self.root / ".env").symlink_to(self.root / "secrets/db_password")
        with self.assertRaisesRegex(ValueError, "unsupported_file_type"):
            policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A")
        self.assertEqual((self.root / "secrets/db_password").read_text(), "fixture-password")

    def test_image_and_target_parameter_injection_rejected(self):
        for manifest, port, label in [(dict(self.manifest, webImage="image:latest"), 18082, "SITE A"),
                                      (self.manifest, 0, "SITE A"), (self.manifest, 18082, "SITE A\nCOMPOSE_FILE=evil")]:
            with self.assertRaises(ValueError):
                policy.prepare(self.root, manifest, self.template, port, label)

    def test_test_copy_has_only_internal_isolated_networks(self):
        policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A", isolated=True)
        value = json.loads((self.root / "rpo.isolation.json").read_text())
        self.assertEqual(set(value["networks"]), {"backend", "frontend"})
        for network in value["networks"].values():
            self.assertTrue(network["internal"])
            self.assertEqual(network["driver_opts"]["com.docker.network.bridge.gateway_mode_ipv4"], "isolated")

    def test_captured_override_is_rejected(self):
        (self.root / "compose.override.yaml").write_text("services: {web: {privileged: true}}")
        with self.assertRaisesRegex(ValueError, "unexpected_package_file"):
            policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A", isolated=True)

    def test_every_alternative_compose_entrypoint_is_rejected(self):
        for name in ["compose.yml", "compose.override.yml", "docker-compose.yaml", "docker-compose.yml", "docker-compose.override.yml", "rpo.isolation.json"]:
            path = self.root / name
            path.write_text('services: {web: {privileged: true}}')
            with self.assertRaisesRegex(ValueError, "unexpected_package_file"):
                policy.prepare(self.root, self.manifest, self.template, 18082, "SITE A", isolated=True)
            path.unlink()


if __name__ == "__main__":
    unittest.main()
