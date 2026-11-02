"""Host authority, replay and receipt recovery checks without privileged execution."""
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error
import urllib.request
import uuid

from control import agent


def job(action="backup", **extra):
    return {"id": str(uuid.uuid4()), "nonce": "n" * 40, "action": action,
            "snapshotId": None, "parameters": {}, **extra}


class HostAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.config = {"controller": "https://control.example.test/ops", "nodeId": str(uuid.uuid4()), "token": "t" * 48, "role": "primary"}
        self.agent = agent.Agent(self.config, self.state)

    def tearDown(self):
        self.temp.cleanup()

    def test_only_typed_actions_and_exact_snapshots(self):
        for value in [job("shell"), job("restore-check", snapshotId="latest"),
                      job("restore-check", snapshotId="a" * 64 + ";id"),
                      job("backup", parameters={"command": "id"}), job("backup", repository="/etc")]:
            with self.assertRaises(ValueError):
                agent.validate_job(value)
        agent.validate_job(job("restore-check", snapshotId="a" * 64))

    def test_redirect_never_forwards_agent_authority(self):
        request = urllib.request.Request("https://control.example.test/ops/agent/sync", headers={"Authorization": "Bearer secret"})
        with self.assertRaises(urllib.error.HTTPError) as raised:
            agent.NoRedirect().redirect_request(request, None, 302, "redirect", {}, "https://another.example/")
        raised.exception.close()

    def test_insecure_or_credential_urls_rejected(self):
        for url in ["http://example.test/ops", "https://user:pass@example.test/ops", "https://example.test/ops?token=a"]:
            with self.assertRaises(ValueError):
                agent.Agent(dict(self.config, controller=url), self.state)
        with self.assertRaises(ValueError):
            agent.Agent(dict(self.config, controller="http://another.test/ops"), self.state, allow_http=True)

    def test_lost_dispatch_reply_and_ack_do_not_repeat_execution(self):
        request = job()
        calls = []
        def execute(value, path, receipt):
            calls.append(value["id"])
            receipt.update(status="succeeded", result={"snapshot": "a" * 64})
            agent.atomic(path, receipt)
        with patch.object(self.agent, "execute", side_effect=execute):
            self.agent.start(request)
            self.agent.worker.join(2)
            self.agent.start(request)
            self.agent.acknowledge([request["id"]], {request["id"]: "succeeded"})
            self.assertEqual(self.agent.reports(), [])
            self.agent.start(request)
            self.assertEqual(calls, [request["id"]])
            self.assertTrue((self.state / "jobs" / (request["id"] + ".json")).exists())

    def test_same_identity_different_nonce_is_rejected(self):
        request = job()
        with patch.object(self.agent, "execute"):
            self.agent.start(request)
            self.agent.worker.join(2)
            with self.assertRaises(ValueError):
                self.agent.start(dict(request, nonce="x" * 40))

    def test_running_ack_cannot_hide_result_completed_during_network_request(self):
        request = job()
        path = self.state / "jobs" / (request["id"] + ".json")
        agent.atomic(path, {"id": request["id"], "nonce": request["nonce"], "status": "succeeded"})
        self.agent.acknowledge([request["id"]], {request["id"]: "running"})
        self.assertEqual(self.agent.reports()[0]["status"], "succeeded")
        self.agent.acknowledge([request["id"]], {request["id"]: "succeeded"})
        self.assertEqual(self.agent.reports(), [])

    def test_interrupted_receipt_is_unknown_and_not_rerun(self):
        request = job()
        with patch.object(self.agent, "execute") as execute:
            self.agent.start(request)
            self.agent.worker.join(2)
            self.assertEqual(execute.call_count, 1)
        restarted = agent.Agent(self.config, self.state)
        self.assertEqual(restarted.reports()[0]["status"], "outcome_unknown")
        with patch.object(restarted, "execute") as execute:
            restarted.start(request)
            execute.assert_not_called()

    def test_reconcile_without_receipt_never_executes_original_action(self):
        request = job(reconcile=True)
        with patch.object(self.agent, "execute") as execute:
            self.agent.start(request)
            execute.assert_not_called()
        report = self.agent.reports()[0]
        self.assertEqual(report["status"], "outcome_unknown")
        self.assertEqual(report["error"], "receipt_missing")

    def test_recovery_node_cannot_run_primary_backup(self):
        self.agent.config["role"] = "recovery"
        request = job()
        path = self.state / "jobs" / (request["id"] + ".json")
        receipt = {"id": request["id"], "nonce": request["nonce"], "status": "running"}
        with patch.object(agent, "package_env", return_value={"PATH": "/usr/bin"}), patch.object(agent.Path, "is_file", return_value=True), patch.object(self.agent, "command") as command:
            self.agent.execute(request, path, receipt)
            command.assert_not_called()
        result = agent.read_json(path)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error"], "primary_required")

    def test_preview_removal_is_bound_to_the_owned_preview_id(self):
        owned = str(uuid.uuid4())
        agent.atomic(self.state / "preview.json", {"id": owned, "base": "/never/delete", "root": "/never/delete"})
        request = job("remove-preview", parameters={"previewId": str(uuid.uuid4())})
        path = self.state / "jobs" / (request["id"] + ".json")
        with patch.object(agent, "package_env", return_value={"PATH": "/usr/bin"}), patch.object(agent.Path, "is_file", return_value=True), patch.object(self.agent, "command") as command:
            self.agent.execute(request, path, {"id": request["id"], "status": "running"})
            command.assert_not_called()
        self.assertEqual(agent.read_json(path)["error"], "preview_ownership_invalid")
        self.assertEqual(agent.read_json(self.state / "preview.json")["id"], owned)

    def test_private_receipt_permissions(self):
        target = self.state / "receipt.json"
        agent.atomic(target, {"secret": "not-for-log"})
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(target.read_text()), {"secret": "not-for-log"})

    def test_reconcile_uses_operation_proof_not_an_unrelated_latest_success(self):
        request = job("restore-check", snapshotId="a" * 64)
        path = self.state / "jobs" / (request["id"] + ".json")
        receipt = {"id": request["id"], "nonce": request["nonce"], "status": "outcome_unknown"}
        lab = self.state / "lab"
        agent.atomic(lab / "last-restore-check.json", {"operationId": str(uuid.uuid4()), "snapshot": "a" * 64})
        original_open = os.open
        def redirected_open(name, flags, mode=0o777):
            return original_open(str(self.state / "test.lock") if str(name) == "/run/lock/rolypolyops-lab.lock" else name, flags, mode)
        with patch.object(agent, "LAB_STATE", lab), patch.object(agent.os, "open", side_effect=redirected_open):
            self.agent.reconcile(request, path, receipt)
            self.assertEqual(agent.read_json(path)["status"], "outcome_unknown")
            agent.atomic(lab / "operation-proofs" / (request["id"] + ".json"), {"operationId": request["id"], "snapshot": "a" * 64, "checks": ["database-values"]})
            self.agent.reconcile(request, path, receipt)
            self.assertEqual(agent.read_json(path)["status"], "outcome_unknown")
            agent.atomic(lab / "operation-proofs" / (request["id"] + ".json"), {"operationId": request["id"], "snapshot": "a" * 64, "checks": sorted(agent.RESTORE_CHECKS)})
            self.agent.reconcile(request, path, receipt)
            self.assertEqual(agent.read_json(path)["status"], "succeeded")
            self.assertEqual(agent.read_json(path)["result"]["snapshot"], "a" * 64)

    def test_reconcile_schedule_checks_actual_enabled_interval(self):
        request = job("set-schedule", parameters={"interval": "hourly"})
        path = self.state / "jobs" / (request["id"] + ".json")
        receipt = {"id": request["id"], "nonce": request["nonce"], "status": "outcome_unknown"}
        original_open = os.open
        def redirected_open(name, flags, mode=0o777):
            return original_open(str(self.state / "test.lock") if str(name) == "/run/lock/rolypolyops-lab.lock" else name, flags, mode)
        with patch.object(agent, "LAB_STATE", self.state / "lab"), patch.object(agent.os, "open", side_effect=redirected_open), patch.object(agent, "timer_status", return_value={"enabled": True, "interval": "daily"}):
            self.agent.reconcile(request, path, receipt)
            self.assertEqual(agent.read_json(path)["status"], "outcome_unknown")
        with patch.object(agent, "LAB_STATE", self.state / "lab"), patch.object(agent.os, "open", side_effect=redirected_open), patch.object(agent, "timer_status", return_value={"enabled": True, "interval": "hourly"}):
            self.agent.reconcile(request, path, receipt)
            self.assertEqual(agent.read_json(path)["status"], "succeeded")

    def redirected_open(self, name, flags, mode=0o777):
        return self.saved_open(str(self.state / "test.lock") if str(name) == "/run/lock/rolypolyops-lab.lock" else name, flags, mode)

    def test_receipt_loss_while_dispatched_cannot_repeat_mutation(self):
        request = job()
        with patch.object(self.agent, "execute") as execute:
            self.agent.start(request)
            self.agent.worker.join(2)
            (self.state / "jobs" / (request["id"] + ".json")).unlink()
            self.agent.start(request)
            self.assertEqual(execute.call_count, 1)
        self.assertEqual(self.agent.reports()[0]["status"], "outcome_unknown")

    def test_receipt_directory_loss_changes_incarnation(self):
        old = self.agent.instance
        shutil.rmtree(self.state / "jobs")
        self.agent.ensure_identity()
        self.assertNotEqual(self.agent.instance, old)
        self.assertTrue((self.state / "jobs/incarnation").exists())

    def test_nonobject_proof_keeps_unknown_without_crashing(self):
        request = job("verify")
        lab = self.state / "lab"
        proof = lab / "operation-proofs" / (request["id"] + ".json")
        proof.parent.mkdir(parents=True)
        proof.write_text('["invalid-proof"]')
        receipt = {"id": request["id"], "nonce": request["nonce"], "status": "outcome_unknown"}
        path = self.state / "jobs" / (request["id"] + ".json")
        self.saved_open = os.open
        with patch.object(agent, "LAB_STATE", lab), patch.object(agent.os, "open", side_effect=self.redirected_open):
            self.agent.reconcile(request, path, receipt)
        self.assertEqual(agent.read_json(path)["status"], "outcome_unknown")

    def test_orphan_inspection_clears_idle_uncertainty_without_replay(self):
        identity = str(uuid.uuid4())
        self.saved_open = os.open
        with patch.object(agent, "LAB_STATE", self.state / "lab"), patch.object(agent, "PREVIEWS", self.state / "previews"), patch.object(agent.os, "open", side_effect=self.redirected_open), patch.object(self.agent, "command") as execute, patch.object(agent, "run") as subprocess:
            self.assertTrue(self.agent.inspect_orphan(identity, "n" * 40))
            execute.assert_not_called()
            subprocess.assert_not_called()
        receipt = agent.read_json(self.state / "jobs" / (identity + ".json"))
        self.assertEqual(receipt["status"], "failed")
        self.assertTrue(receipt["inspected"])
        self.assertFalse(receipt["result"]["originalActionRepeated"])

    def test_orphan_inspection_defers_when_operation_lock_held(self):
        self.saved_open = os.open
        identity = str(uuid.uuid4())
        with patch.object(agent.os, "open", side_effect=self.redirected_open), patch.object(agent.fcntl, "flock", side_effect=BlockingIOError):
            self.assertFalse(self.agent.inspect_orphan(identity))
        self.assertFalse((self.state / "jobs" / (identity + ".json")).exists())

    def test_acknowledged_newer_receipts_do_not_starve_old_unacknowledged_result(self):
        identity = str(uuid.uuid4())
        path = self.state / "jobs" / (identity + ".json")
        agent.atomic(path, {"id": identity, "nonce": "n" * 40, "status": "succeeded"})
        for _ in range(105):
            other = str(uuid.uuid4())
            agent.atomic(self.state / "jobs" / (other + ".json"), {"id": other, "nonce": "n" * 40, "status": "succeeded", "acknowledged": True})
        self.assertEqual([r["id"] for r in self.agent.reports()], [identity])


if __name__ == "__main__":
    unittest.main()
