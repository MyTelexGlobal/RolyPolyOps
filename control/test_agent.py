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

    def test_inspection_preserves_current_source_without_preview_receipt(self):
        lab = self.state / "lab"
        identity = str(uuid.uuid4())
        root = lab / "restore.guardtest"
        (root / "service").mkdir(parents=True)
        agent.atomic(root / ".operation.json", {"id": identity, "action": "restore-check"})
        for record in ("active.json", "standby.json", None):
            for old in ("active.json", "standby.json"):
                (lab / old).unlink(missing_ok=True)
            if record:
                agent.atomic(lab / record, {"root": str(root)})
            env = {"RPO_ROOT": str(root / "service")} if record is None else {}
            with patch.object(agent, "LAB_STATE", lab), patch.object(agent, "PREVIEWS", self.state / "previews"), patch.object(agent, "package_env", return_value=env), patch.object(agent, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "inspection_live_standby"):
                    self.agent.cleanup_temporary(identity)
                run.assert_not_called()
            self.assertTrue((root / "service").is_dir())

    def test_inspection_refuses_unknown_current_source_configuration(self):
        lab = self.state / "lab"
        identity = str(uuid.uuid4())
        root = lab / "restore.guardtest"
        root.mkdir(parents=True)
        agent.atomic(root / ".operation.json", {"id": identity, "action": "restore-check"})
        for env, record in [(None, None), ({}, "not-json"), ({}, "{}"), ({}, '{"root":"relative"}')]:
            if record is not None:
                (lab / "active.json").write_text(record)
            with patch.object(agent, "LAB_STATE", lab), patch.object(agent, "PREVIEWS", self.state / "previews"), patch.object(agent, "package_env", return_value=env), patch.object(agent, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "inspection_source_"):
                    self.agent.cleanup_temporary(identity)
                run.assert_not_called()
            self.assertTrue(root.is_dir())

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
        with patch.object(agent, "LAB_STATE", self.state / "lab"), patch.object(agent, "PREVIEWS", self.state / "previews"), patch.object(agent.os, "open", side_effect=self.redirected_open), patch.object(agent, "package_env", return_value={}), patch.object(self.agent, "command") as execute, patch.object(agent, "run") as subprocess:
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


class GenericAdapterTests(unittest.TestCase):
    def setUp(self):
        from types import SimpleNamespace
        self.temp = tempfile.TemporaryDirectory()
        self.state = Path(self.temp.name)
        self.config = {"controller": "https://control.example.test/ops", "nodeId": str(uuid.uuid4()), "token": "t" * 48, "role": "recovery"}
        self.agent = agent.Agent(self.config, self.state)
        self.service = str(uuid.uuid4())
        self.storage = str(uuid.uuid4())
        class EngineError(RuntimeError):
            def __init__(self, code, unknown=False):
                super().__init__(code)
                self.code, self.unknown = code, unknown
        self.EngineError = EngineError
        self.fake = SimpleNamespace(EngineError=EngineError, validate_job=lambda value: None)
        self.module_patch = patch.object(agent, "engine_module", return_value=self.fake)
        self.module_patch.start()
        from unittest.mock import Mock
        self.engine = Mock()
        self.agent._engine = self.engine
        self.engine.owns_operation.return_value = False

    def tearDown(self):
        self.module_patch.stop()
        self.temp.cleanup()

    def request(self, action="compose-verify", **extra):
        return job(action, parameters={"serviceId":self.service,"storageId":self.storage}, **extra)

    def start(self, request):
        self.agent.start(request)
        self.agent.worker.join(2)
        return agent.read_json(self.state / "jobs" / (request['id']+'.json'))

    def verify_result(self):
        return {"serviceId":self.service,"storageId":self.storage,"repositoryId":"b"*64,"verified":True,"checks":["repository-data"]}

    def test_generic_executes_without_lab_or_primary_role_and_retries_once(self):
        request = self.request()
        self.engine.execute.return_value = dict(self.verify_result(),credentials="SECRET",config={"repoPassword":"SECRET"})
        with patch.object(agent, "package_env", side_effect=AssertionError("legacy path used")):
            receipt = self.start(request)
            self.agent.start(request)
        self.assertEqual(receipt['status'],'succeeded')
        self.engine.execute.assert_called_once()
        self.assertNotIn('SECRET',json.dumps(receipt))
        changed = dict(request,nonce='different'*8)
        with self.assertRaisesRegex(ValueError,'identity conflict'):
            self.agent.start(changed)

    def test_engine_unknown_busy_and_unexpected_errors_are_distinct(self):
        for error,state,code in [(self.EngineError('operation_busy'),'failed','operation_busy'),(self.EngineError('capture_interrupted',True),'outcome_unknown','capture_interrupted'),(RuntimeError('RAW_SECRET'),'outcome_unknown','operation_failed')]:
            with self.subTest(code=code):
                request=self.request()
                self.engine.execute.side_effect=error
                # Each subcase uses a clean authority to avoid the intentional
                # preceding unknown-outcome hold blocking later dispatch.
                isolated=agent.Agent(self.config,self.state/request['id'])
                isolated._engine=self.engine
                isolated.start(request);isolated.worker.join(2)
                receipt=isolated.reports()[0]
                self.assertEqual((receipt['status'],receipt['error']),(state,code))
                self.assertNotIn('RAW_SECRET',json.dumps(receipt))

    def test_bad_generic_proof_remains_unknown_and_blocks_new_work(self):
        self.engine.execute.return_value=dict(self.verify_result(),serviceId=str(uuid.uuid4()))
        receipt=self.start(self.request())
        self.assertEqual((receipt['status'],receipt['error']),('outcome_unknown','result_unverified'))
        with self.assertRaisesRegex(ValueError,'Reconciliation required'):
            self.agent.start(self.request())

    def test_reconcile_uses_engine_inspection_and_never_executes_again(self):
        request=self.request()
        self.engine.execute.side_effect=self.EngineError('interrupted',True)
        self.start(request)
        self.engine.reconcile.return_value={'status':'succeeded','result':self.verify_result()}
        with patch.object(agent, 'package_env', side_effect=AssertionError('legacy reconciliation used')):
            self.agent.start(dict(request,reconcile=True))
        self.engine.execute.assert_called_once()
        self.engine.reconcile.assert_called_once()
        self.assertEqual(self.agent.reports()[0]['status'],'succeeded')

    def test_generic_orphan_journal_never_uses_demo_cleanup(self):
        identity=str(uuid.uuid4())
        self.engine.owns_operation.return_value=True
        self.engine.inspect_operation.return_value={'status':'succeeded','result':{'private':'SECRET'}}
        with patch.object(self.agent,'cleanup_temporary',side_effect=AssertionError('demo cleanup used')):
            self.assertTrue(self.agent.inspect_orphan(identity))
        self.engine.inspect_operation.assert_called_once_with(identity)
        receipt=self.agent.reports()[0]
        self.assertTrue(receipt['inspected'])
        self.assertNotIn('SECRET',json.dumps(receipt))
        self.engine.execute.assert_not_called()

    def test_unknown_generic_orphan_stays_unsettled(self):
        self.engine.owns_operation.return_value=True
        self.engine.inspect_operation.return_value={'status':'outcome_unknown','error':'needs_inspection'}
        with patch.object(self.agent,'cleanup_temporary',side_effect=AssertionError('demo cleanup used')):
            self.assertFalse(self.agent.inspect_orphan(str(uuid.uuid4())))
        self.assertEqual(self.agent.reports(),[])

    def test_storage_receipt_purges_sealed_body_and_preserves_replay_fingerprint(self):
        request=self.request('storage-configure')
        rid=str(uuid.uuid4())
        request['parameters']={'storageId':self.storage,'mode':'attach','metadata':{'id':self.storage},'envelope':{'requestId':rid,'bindingGeneration':2,'ciphertext':'CIPHERTEXT_MARKER'}}
        self.engine.execute.return_value={'storageId':self.storage,'repositoryId':'b'*64,'connected':True,'bindingGeneration':2,'requestId':rid}
        receipt=self.start(request)
        encoded=(self.state/'jobs'/(request['id']+'.json')).read_text()
        self.assertNotIn('CIPHERTEXT_MARKER',encoded)
        self.assertIn('envelopeDigest',encoded)
        # A network retry still carries the identical original sealed request.
        original=dict(request,parameters={'storageId':self.storage,'mode':'attach','metadata':{'id':self.storage},'envelope':{'requestId':rid,'bindingGeneration':2,'ciphertext':'CIPHERTEXT_MARKER'}})
        self.agent.start(original)
        self.engine.execute.assert_called_once()


class StorageWorkerObservationTests(unittest.TestCase):
    def setUp(self):
        from unittest.mock import Mock
        self.temp=tempfile.TemporaryDirectory()
        self.state=Path(self.temp.name)
        self.config={"controller":"https://control.example.test/ops","nodeId":str(uuid.uuid4()),"token":"t"*48,"role":"primary","storageWorkerUser":"own-test-storage"}
        self.agent=agent.Agent(self.config,self.state)
        self.engine=Mock();self.agent._engine=self.engine

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def public_key():
        import base64,hashlib
        raw=bytes.fromhex('308201a2300d06092a864886f70d01010105000382018f003082018a0282018100')+bytes([129])*384+bytes.fromhex('0203010001')
        return {'id':hashlib.sha256(raw).hexdigest(),'publicKey':base64.b64encode(raw).decode(),'algorithm':'RSA-OAEP-256+A256GCM'}

    def test_root_selected_worker_pin_is_passed_unchanged_to_lazy_engine(self):
        from unittest.mock import Mock
        module=Mock();module.ManagedEngine.return_value=self.engine
        self.agent._engine=None
        with patch.object(agent,'engine_module',return_value=module):
            self.assertIs(self.agent.engine(),self.engine)
            self.assertIs(self.agent.engine(),self.engine)
        module.ManagedEngine.assert_called_once_with(self.config,self.state/'managed')
        self.assertEqual(self.config['storageWorkerUser'],'own-test-storage')

    def test_malformed_root_worker_option_is_rejected_before_state_creation(self):
        for bad in (False,[],{},1,'root;id','a/b','has space'):
            with self.subTest(bad=bad):
                path=self.state/'not-created'
                with self.assertRaisesRegex(ValueError,'invalid_storage_worker'):
                    agent.Agent(dict(self.config,storageWorkerUser=bad),path)
                self.assertFalse(path.exists())

    def test_unavailable_isolation_remains_unready_with_safe_code_and_journal(self):
        operation=str(uuid.uuid4())
        self.engine.observe.return_value={'ready':False,'error':'transport_cleanup_unverified','key':self.public_key(),'operations':[{'id':operation,'status':'outcome_unknown','credentials':'PRIVATE_MARKER'}],'credentials':'PRIVATE_MARKER','storageWorkerUser':'PRIVATE_MARKER'}
        with patch.object(agent,'observe',return_value={'supported':True,'observedAt':agent.now(),'serviceHealthy':True}):
            result=self.agent.observe_once()
        self.assertTrue(result['supported'])
        self.assertFalse(result['compose']['ready'])
        self.assertEqual(result['compose']['error'],'transport_cleanup_unverified')
        self.assertEqual(result['compose']['operations'],[{'id':operation,'status':'outcome_unknown'}])
        self.assertNotIn('PRIVATE_MARKER',json.dumps(result))
        self.engine.recover.assert_called_once()
        self.engine.execute.assert_not_called()

    def test_failed_recovery_uses_only_local_observation_and_preserves_unknown_hold(self):
        operation=str(uuid.uuid4())
        self.engine.recover.side_effect=RuntimeError('PRIVATE_RECOVERY_MARKER')
        self.engine.observe.return_value={'ready':True,'key':self.public_key(),'operations':[{'id':operation,'status':'outcome_unknown','parameters':{'password':'PRIVATE_MARKER'}}],'credentials':'PRIVATE_MARKER'}
        with patch.object(agent,'observe',return_value={'supported':False,'observedAt':agent.now()}):
            result=self.agent.observe_once()
        self.engine.observe.assert_called_once_with(local_only=True)
        self.assertFalse(result['compose']['ready'])
        self.assertEqual(result['compose']['error'],'compose_recovery_required')
        self.assertEqual(result['compose']['key'],self.public_key())
        self.assertEqual(result['compose']['operations'],[{'id':operation,'status':'outcome_unknown'}])
        self.assertNotIn('PRIVATE_',json.dumps(result))
        self.assertEqual(self.agent.reports(),[])
        self.engine.execute.assert_not_called()

    def test_unavailable_valid_marker_does_not_hide_existing_recovery_reports(self):
        config=dict(self.config,storageWorkerMarker='/trusted-unavailable/storage-worker.json')
        instance=agent.Agent(config,self.state/'restart')
        instance._engine=self.engine
        operation=str(uuid.uuid4())
        self.engine.recover.side_effect=RuntimeError('PRIVATE_MARKER_FAILURE')
        self.engine.observe.return_value={'ready':False,'key':self.public_key(),'operations':[{'id':operation,'status':'outcome_unknown'}]}
        with patch.object(agent,'observe',return_value={'supported':False,'observedAt':agent.now()}):
            report=instance.observe_once()
        self.assertEqual(report['compose']['operations'],[{'id':operation,'status':'outcome_unknown'}])
        self.assertEqual(report['compose']['error'],'compose_recovery_required')
        self.engine.observe.assert_called_once_with(local_only=True)
        self.engine.execute.assert_not_called()

    def test_failed_local_recovery_read_stays_unavailable_without_exception_data(self):
        self.engine.recover.side_effect=RuntimeError('PRIVATE_RECOVERY_MARKER')
        self.engine.observe.side_effect=RuntimeError('PRIVATE_LOCAL_MARKER')
        with patch.object(agent,'observe',return_value={'supported':False,'observedAt':agent.now()}):
            result=self.agent.observe_once()
        self.engine.observe.assert_called_once_with(local_only=True)
        self.assertFalse(result['compose']['ready'])
        self.assertNotIn('PRIVATE_',json.dumps(result))
        self.engine.execute.assert_not_called()

    def test_busy_snapshot_observation_is_not_a_fake_job_or_unknown_hold(self):
        self.engine.observe.return_value={'ready':True,'error':'snapshot_inventory_unavailable','key':self.public_key(),'operations':[]}
        with patch.object(agent,'observe',return_value={'supported':False,'observedAt':agent.now()}):
            result=self.agent.observe_once()
        self.assertEqual(result['compose']['error'],'snapshot_inventory_unavailable')
        self.assertEqual(result['compose']['operations'],[])
        self.assertEqual(self.agent.reports(),[])
        self.engine.execute.assert_not_called()


class StorageWorkerMarkerTrustTests(unittest.TestCase):
    @staticmethod
    def metadata(directory=True,uid=0,permissions=0o755,symlink=False):
        import stat
        kind=stat.S_IFLNK if symlink else stat.S_IFDIR if directory else stat.S_IFREG
        return os.stat_result([kind|permissions,1,1,1,uid,0,0,0,0,0])

    def hierarchy(self):
        return {Path('/'):self.metadata(),Path('/trusted'):self.metadata(),Path('/trusted/instance'):self.metadata(permissions=0o700),Path('/trusted/instance/storage-worker.json'):self.metadata(directory=False,permissions=0o600)}

    def inspect(self,records):
        def read(path):
            if path not in records:raise FileNotFoundError()
            value=records[path]
            if isinstance(value,Exception):raise value
            return value
        return read

    def test_marker_syntax_rejects_type_controls_aliases_and_traversal_before_state(self):
        config={'controller':'https://control.example.test/ops','nodeId':str(uuid.uuid4()),'token':'t'*48,'role':'primary'}
        invalid=(None,True,1,[],{},'relative','https://example/x','file:///x','/','//etc/x','/etc//x','/etc/./x','/etc/../x','/etc/x/','/etc/x\n','/etc/x\x00','/etc/x\x85','/etc/'+('x'*4097),'/etc/x\ud800')
        with tempfile.TemporaryDirectory() as temporary:
            state=Path(temporary)/'must-not-exist'
            for value in invalid:
                with self.subTest(value_type=type(value).__name__):
                    with self.assertRaisesRegex(ValueError,'invalid_storage_worker_marker'):
                        agent.Agent(dict(config,storageWorkerMarker=value),state)
                    self.assertFalse(state.exists())

    def test_every_parent_must_be_root_owned_nonwritable_and_not_a_symlink(self):
        marker='/trusted/instance/storage-worker.json'
        for parent in (Path('/'),Path('/trusted'),Path('/trusted/instance')):
            for bad in (self.metadata(uid=1000),self.metadata(permissions=0o777),self.metadata(symlink=True),PermissionError('PRIVATE_PATH')):
                records=self.hierarchy();records[parent]=bad
                with self.subTest(parent=str(parent),bad_type=type(bad).__name__),patch.object(Path,'lstat',new=self.inspect(records)):
                    with self.assertRaisesRegex(ValueError,'untrusted_storage_worker_marker'):
                        agent.validate_storage_worker_marker(marker)
        records=self.hierarchy();del records[Path('/trusted/instance')]
        with patch.object(Path,'lstat',new=self.inspect(records)):
            with self.assertRaisesRegex(ValueError,'untrusted_storage_worker_marker'):
                agent.validate_storage_worker_marker(marker)

    def test_directory_creation_is_limited_to_the_selected_trusted_chain(self):
        records={Path('/'):self.metadata(),Path('/trusted'):self.metadata()};created=[]
        def make(path,mode=0o777):
            created.append((path,mode));records[path]=self.metadata(permissions=mode)
        with patch.object(Path,'lstat',new=self.inspect(records)),patch.object(Path,'mkdir',new=make):
            agent.validate_storage_marker_parents(Path('/trusted/new-instance'),create=True)
        self.assertEqual(created,[(Path('/trusted/new-instance'),0o700)])
        created.clear();records[Path('/trusted')]=self.metadata(permissions=0o777)
        with patch.object(Path,'lstat',new=self.inspect(records)),patch.object(Path,'mkdir',new=make):
            with self.assertRaisesRegex(ValueError,'untrusted_storage_worker_marker'):
                agent.validate_storage_marker_parents(Path('/trusted/other-instance'),create=True)
        self.assertEqual(created,[])

    def test_marker_itself_requires_regular_root0600(self):
        marker=Path('/trusted/instance/storage-worker.json')
        with patch.object(Path,'lstat',new=self.inspect(self.hierarchy())):
            self.assertEqual(agent.validate_storage_worker_marker(str(marker)),marker)
        for bad in (self.metadata(directory=False,uid=1000,permissions=0o600),self.metadata(directory=False,permissions=0o640),self.metadata(directory=False,permissions=0o644),self.metadata(directory=False,permissions=0o600,symlink=True),self.metadata(permissions=0o600),FileNotFoundError()):
            records=self.hierarchy();records[marker]=bad
            with self.subTest(bad_type=type(bad).__name__),patch.object(Path,'lstat',new=self.inspect(records)):
                with self.assertRaisesRegex(ValueError,'untrusted_storage_worker_marker'):
                    agent.validate_storage_worker_marker(str(marker))

    def test_missing_optional_field_never_reads_default_marker(self):
        config={'controller':'https://control.example.test/ops','nodeId':str(uuid.uuid4()),'token':'t'*48,'role':'primary'}
        with tempfile.TemporaryDirectory() as temporary,patch.object(agent,'storage_worker_marker_path',side_effect=AssertionError('marker selection not requested')):
            instance=agent.Agent(config,temporary)
        self.assertNotIn('storageWorkerMarker',instance.config)


if __name__ == "__main__":
    unittest.main()
