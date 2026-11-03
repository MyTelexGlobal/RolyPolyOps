import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock
import uuid

try:
    from . import compose_engine as engine
    from . import compose_helper as helper
    from .compose_storage import atomic, read
except ImportError:
    import compose_engine as engine
    import compose_helper as helper
    from compose_storage import atomic, read


def uid():
    return str(uuid.uuid4())


def tar_entry(archive, name, content=b"", kind=None, link=None, mode=0o640, pax=None):
    member = tarfile.TarInfo(name)
    member.uid, member.gid, member.mode, member.mtime = 1201, 1202, mode, 1700000000
    member.type = kind or tarfile.REGTYPE
    member.linkname = link or ""
    member.pax_headers = pax or {}
    member.size = len(content) if member.isfile() else 0
    archive.addfile(member, io.BytesIO(content) if member.isfile() else None)


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.engine = engine.ManagedEngine({"nodeId": uid()}, self.root / "managed")
        self.sid, self.storage = uid(), uid()

    def job(self, action="compose-backup", params=None):
        return {"id": uid(), "nonce": "n" * 32, "action": action, "parameters": params or {"serviceId": self.sid, "storageId": self.storage}}

    def archive(self, entries):
        path = self.root / (uid() + ".tar")
        with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as out:
            for entry in entries:
                tar_entry(out, **entry)
        return path

    def source(self):
        config = self.root / "compose.json"
        config.write_text("{}")
        c = {"Id": "a" * 64, "Image": "sha256:" + "b" * 64, "State": {"Running": False, "StartedAt": "2026-11-01T12:00:00.000000000Z"}, "RestartCount": 0, "Mounts": [], "Config": {"Labels": {"com.docker.compose.project": "ordinary"}}}
        service = {"id": self.sid, "projectId": "ordinary", "fingerprint": "c" * 64, "storageId": self.storage, "sourceState": "capture_stopped", "captureOperation": uid(), "backupInterval": "hourly", "project": {"inputs": {str(config): helper.digest(config)}}}
        journal = {"id": service["captureOperation"], "action": "compose-backup", "status": "running", "stage": "source-stopped", "parameters": {"serviceId": self.sid, "storageId": self.storage}, "resume": {"serviceId": self.sid, "containers": [{"id": c["Id"], "imageId": c["Image"], "mountSignature": []}]}}
        return service, journal, c

    def test_job_snapshot_scope_and_no_shell_parameters(self):
        params = {"serviceId": self.sid, "storageId": self.storage, "snapshotId": "a" * 64}
        valid = self.job("compose-restore", params) | {"snapshotId": "a" * 64}
        engine.validate_job(valid)
        for changed in (valid | {"snapshotId": "b" * 64}, self.job(params={**params, "command": "echo bypass"}), valid | {"parameters": params | {"restoreId": uid()}}):
            with self.assertRaises(engine.EngineError):
                engine.validate_job(changed)
        with self.assertRaises(engine.EngineError):
            engine.validate_job(self.job("compose-activate", {"serviceId": self.sid, "restoreId": uid(), "sourceStopJobId": uid(), "interval": "hourly", "ports": [], "allowEgress": False}))

    def test_activation_host_ip_is_string_and_equivalent_ipv6_slots_do_not_mutate_job(self):
        port = {"service": "app", "target": 8080, "published": 18190, "hostIp": "127.0.0.1", "protocol": "tcp"}
        params = {"serviceId": self.sid, "restoreId": uid(), "sourceStopJobId": uid(), "interval": "hourly", "ports": [port], "allowEgress": True}
        for value in (3325256711, True, 0, False, None, "fe80::1%eth0"):
            with self.subTest(value=value), self.assertRaisesRegex(engine.EngineError, "invalid_ports"):
                engine.validate_job(self.job("compose-activate", params | {"ports": [port | {"hostIp": value}]}))
        duplicate = params | {"ports": [port | {"hostIp": "::1"}, port | {"hostIp": "0:0:0:0:0:0:0:1"}]}
        job = self.job("compose-activate", duplicate)
        before = copy.deepcopy(job)
        with self.assertRaisesRegex(engine.EngineError, "invalid_ports"):
            engine.validate_job(job)
        self.assertEqual(job, before)
        valid = self.job("compose-activate", params | {"ports": [port, port | {"hostIp": "0:0:0:0:0:0:0:1"}]})
        before = copy.deepcopy(valid)
        engine.validate_job(valid)
        self.assertEqual(valid, before)

    def test_create_job_cannot_preassign_repository_identity(self):
        for expected in ("a" * 64, None, False):
            job = self.job("storage-configure", {"storageId": self.storage, "mode": "create", "envelope": {}, "expectedRepositoryId": expected})
            before = copy.deepcopy(job)
            with self.subTest(expected=expected), self.assertRaisesRegex(engine.EngineError, "create_repository_id_preassigned"):
                engine.validate_job(job)
            self.assertEqual(job, before)

    def test_controller_only_repository_discovery_flag_has_exact_schema(self):
        params = {"storageId": self.storage, "metadata": {"id": self.storage}, "mode": "attach", "envelope": {}, "discoverRepositoryId": True}
        engine.validate_job(self.job("storage-configure", params))
        for change in ({"discoverRepositoryId": False}, {"discoverRepositoryId": 1}, {"mode": "create"}, {"expectedRepositoryId": None}, {"expectedRepositoryId": "a" * 64}):
            with self.subTest(change=change), self.assertRaisesRegex(engine.EngineError, "invalid_repository_discovery"):
                engine.validate_job(self.job("storage-configure", params | change))

    def test_archive_preserves_numeric_safe_metadata_and_internal_links(self):
        archive = self.archive([{"name": "payload", "kind": tarfile.DIRTYPE, "mode": 0o750}, {"name": "payload/file", "content": b"independent data"}, {"name": "payload/link", "kind": tarfile.SYMTYPE, "link": "file"}, {"name": "payload/hard", "kind": tarfile.LNKTYPE, "link": "payload/file"}])
        value = helper.inspect_archive(archive)
        self.assertEqual(value["files"], 4)
        actual = next(e for e in value["entries"] if e["path"] == "payload/file")
        self.assertEqual((actual["uid"], actual["gid"], actual["mode"]), (1201, 1202, 0o640))
        self.assertEqual(actual["sha256"], hashlib.sha256(b"independent data").hexdigest())

    def test_archive_negative_boundaries_before_any_extract(self):
        cases = [
            [{"name": "../sentinel"}], [{"name": "/absolute"}], [{"name": "payload/a"}, {"name": "payload/a"}],
            [{"name": "payload/x", "kind": tarfile.FIFOTYPE}], [{"name": "payload/x", "mode": 0o4644}],
            [{"name": "payload/x", "pax": {"SCHILY.xattr.security.capability": "execution"}}],
            [{"name": "payload/x", "kind": tarfile.SYMTYPE, "link": "../../sentinel"}],
            [{"name": "payload/x", "kind": tarfile.SYMTYPE, "link": "/etc/passwd"}],
            [{"name": "payload/x", "kind": tarfile.SYMTYPE, "link": "y"}, {"name": "payload/x/child"}, {"name": "payload/y", "kind": tarfile.DIRTYPE}],
            [{"name": "payload/x", "pax": {"SCHILY.acl.access": "user:alice:rwx"}}],
            [{"name": "payload/" + "/".join(["d"] * 65)}],
        ]
        sentinel = self.root / "sentinel"
        sentinel.write_text("intact")
        for entries in cases:
            with self.subTest(entries=entries), self.assertRaises(helper.ArchiveError):
                helper.inspect_archive(self.archive(entries))
        self.assertEqual(sentinel.read_text(), "intact")

    def test_archive_quota_and_symlink_parent_even_if_late(self):
        path = self.archive([{"name": "payload/a/file"}, {"name": "payload/a", "kind": tarfile.SYMTYPE, "link": "b"}, {"name": "payload/b", "kind": tarfile.DIRTYPE}])
        with self.assertRaisesRegex(helper.ArchiveError, "archive_link_parent"):
            helper.inspect_archive(path)
        with mock.patch.object(helper, "MAX_FILES", 1), self.assertRaisesRegex(helper.ArchiveError, "archive_file_limit"):
            helper.inspect_archive(self.archive([{"name": "payload", "kind": tarfile.DIRTYPE}, {"name": "payload/file"}]))
        with mock.patch.object(helper, "MAX_BYTES", 1), self.assertRaisesRegex(helper.ArchiveError, "archive_byte_limit"):
            helper.inspect_archive(self.archive([{"name": "payload", "content": b"ab"}]))

    def test_model_unsafe_fields_and_external_resources_refused(self):
        model = {"services": {"app": {"image": "local:built", "read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}}, "networks": {"default": {}}}
        self.engine._validate_model(model)
        for injected in ({"privileged": True}, {"network_mode": "host"}, {"cap_add": ["SYS_ADMIN"]}, {"devices": ["/dev/mem"]}, {"post_start": [{"command": "unsafe"}]}, {"deploy": {"replicas": 2}}):
            with self.subTest(injected=injected), self.assertRaises(engine.EngineError):
                self.engine._validate_model({"services": {"app": model["services"]["app"] | injected}})
        with self.assertRaises(engine.EngineError):
            self.engine._validate_model(model | {"networks": {"default": {"external": True}}})
        with self.assertRaises(engine.EngineError):
            self.engine._validate_model(model | {"volumes": {"data": {"driver_opts": {"device": "/"}}}})

    def test_yaml_guard_accepts_local_merged_inputs_before_compose(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML 6+ not installed")
        paths = []
        for index, content in enumerate(("services:\n  app:\n    image: local:built\n    environment:\n      extends: harmless-value\n", '{"services":{"app":{"image":"local:built"}}}', "x-defaults: &defaults\n  read_only: true\nservices:\n  app:\n    <<: *defaults\n    image: local:built\n")):
            path = self.root / (str(index) + ".yaml")
            path.write_text(content)
            paths.append(str(path))
        self.engine._precheck_compose(paths)

    def test_yaml_remote_duplicate_cycle_and_custom_tags_never_reach_docker(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("PyYAML 6+ not installed")
        values = ["include: https://remote.invalid/file.yaml\nservices: {}\n", "services:\n  app:\n    extends: {file: https://remote.invalid/app.yaml, service: app}\n", "services:\n  app:\n    provider: {type: arbitrary}\n", "include: https://remote.invalid/x\ninclude: []\n", "x: &cycle [*cycle]\nservices: {}\n", "services: !!python/object/apply:os.system [id]\n", "x: &base\n  include: https://remote.invalid/x\n<<: *base\nservices: {}\n"]
        for content in values:
            path = self.root / "unsafe.yaml"
            path.write_text(content)
            labels = {"com.docker.compose.project": "ordinary", "com.docker.compose.project.config_files": str(path), "com.docker.compose.project.working_dir": str(self.root)}
            containers = [{"Config": {"Labels": labels}}]
            with self.subTest(content=content), mock.patch.object(self.engine, "_compose") as compose:
                with self.assertRaises(engine.EngineError):
                    self.engine._project("ordinary", containers)
                compose.assert_not_called()

    def test_current_mount_sources_never_include_control_paths(self):
        for path in ("/", "/etc", "/dev", "/var", str(self.engine.state), str(self.root)):
            with self.subTest(path=path), self.assertRaises(engine.EngineError):
                self.engine._safe_source(path)
        ordinary = self.root / "ordinary-data"
        ordinary.mkdir()
        self.assertEqual(self.engine._safe_source(str(ordinary)), str(ordinary.resolve()))

    def test_exact_active_owned_bind_config_secret_roots_are_new_sources(self):
        rid, cid = uid(), "d" * 64
        directory = self.engine.state / "stages" / rid
        directory.mkdir()
        runtime = directory / "runtime.json"
        atomic(runtime, {"services": {}})
        mappings, mounts = {}, []
        for index, label in enumerate(("data", "config", "secret")):
            path = directory / ("mount-" + str(index)) / "extracted" / "payload"
            path.parent.mkdir(parents=True)
            if label == "data":
                path.mkdir()
            else:
                path.write_text("private fixture " + label)
            mappings["bind:" + label] = {"kind": "bind", "source": str(path)}
            mounts.append({"Type": "bind", "Source": str(path)})
        record = {"id": rid, "serviceId": self.sid, "state": "active", "projectId": "new-source", "directory": str(directory), "runtimeDigest": helper.digest(runtime), "containerIds": {"app": cid}, "mappings": mappings}
        atomic(self.engine._restore_path(rid), record)
        self.engine._save_service({"id": self.sid, "projectId": "new-source", "activeRestoreId": rid, "sourceState": "running"})
        labels = self.engine._owned_labels(rid, self.sid, "restore") | {helper.OWNER + ".restore": rid, "com.docker.compose.project": "new-source"}
        container = {"Id": cid, "Config": {"Labels": labels}, "Mounts": mounts}
        with mock.patch.object(self.engine, "_inspect", return_value=[container]):
            for mapping in mappings.values():
                self.assertEqual(self.engine._safe_source(mapping["source"], owned_service=self.sid, restore_id=rid, container_id=cid), mapping["source"])
            for forbidden in (self.engine.state, directory, directory / "mount-0", runtime):
                with self.subTest(forbidden=forbidden), self.assertRaises(engine.EngineError):
                    self.engine._safe_source(str(forbidden), owned_service=self.sid, restore_id=rid, container_id=cid)
            with self.assertRaises(engine.EngineError):
                self.engine._safe_source(next(iter(mappings.values()))["source"], owned_service=self.sid, restore_id=uid(), container_id=cid)
            with self.assertRaises(engine.EngineError):
                self.engine._safe_source(next(iter(mappings.values()))["source"], owned_service=self.sid, restore_id=rid, container_id="foreign")
        forged = copy.deepcopy(container)
        forged["Config"]["Labels"][helper.OWNER + ".service"] = uid()
        with mock.patch.object(self.engine, "_inspect", return_value=[forged]), self.assertRaises(engine.EngineError):
            self.engine._safe_source(next(iter(mappings.values()))["source"], owned_service=self.sid, restore_id=rid, container_id=cid)
        for private in ("seal-key.pem", "storages/credentials", "operations/journal"):
            path = self.engine.state / private
            path.parent.mkdir(exist_ok=True)
            path.write_text("must never be application data")
            record["mappings"]["forged"] = {"kind": "bind", "source": str(path)}
            atomic(self.engine._restore_path(rid), record)
            with self.subTest(private=private), self.assertRaises(engine.EngineError):
                self.engine._safe_source(str(path), owned_service=self.sid, restore_id=rid, container_id=cid)

    def test_recover_kills_owned_helper_before_starting_exact_source(self):
        service, journal, container = self.source()
        self.engine._save_service(service)
        atomic(self.engine._journal_path(journal["id"]), journal)
        effects = []
        def inspect(ids):
            return [container]
        def docker(*args, **kwargs):
            effects.append(args)
            if args[0] == "start":
                container["State"]["Running"] = True
            return b""
        with mock.patch.object(self.engine, "_terminate_helpers", side_effect=lambda j: effects.append(("kill-and-wait-helper",))), mock.patch.object(self.engine, "_inspect", side_effect=inspect), mock.patch.object(self.engine, "docker", side_effect=docker):
            result = self.engine.recover()
        self.assertEqual(effects, [("kill-and-wait-helper",), ("start", container["Id"])])
        self.assertEqual(result[0]["status"], "failed")
        self.assertEqual(self.engine._service(self.sid)["sourceState"], "running")
        self.assertTrue(read(self.engine._journal_path(journal["id"]))["sourceResumed"])

    def test_helper_ownership_failure_never_resumes_source(self):
        service, journal, container = self.source()
        self.engine._save_service(service)
        atomic(self.engine._journal_path(journal["id"]), journal)
        with mock.patch.object(self.engine, "_terminate_helpers", side_effect=engine.EngineError("helper_ownership_unverified", unknown=True)), mock.patch.object(self.engine, "docker") as docker:
            result = self.engine.recover()
        self.assertEqual(result[0]["status"], "outcome_unknown")
        self.assertEqual(self.engine._service(self.sid)["sourceState"], "unknown")
        docker.assert_not_called()

    def test_fenced_source_is_never_automatically_resumed(self):
        service, journal, container = self.source()
        service["sourceState"] = "fenced"
        self.engine._save_service(service)
        atomic(self.engine._journal_path(journal["id"]), journal)
        with mock.patch.object(self.engine, "docker") as docker:
            self.assertEqual(self.engine.recover(), [])
        docker.assert_not_called()

    def test_shared_flock_busy_has_no_effect_and_is_not_unknown(self):
        with self.engine.lock():
            with self.assertRaises(engine.EngineError) as caught:
                self.engine.execute(self.job())
        self.assertEqual(caught.exception.code, "operation_busy")
        self.assertFalse(caught.exception.unknown)
        self.assertEqual(list((self.engine.state / "operations").glob("*.json")), [])

    def test_duplicate_execution_and_reconciliation_never_replay(self):
        job = self.job("compose-register", {"serviceId": self.sid, "projectId": "ordinary", "fingerprint": "a" * 64, "storageId": self.storage, "backupInterval": "hourly", "exclusiveWriters": True})
        result = {"serviceId": self.sid, "registered": True, "projectId": "ordinary", "fingerprint": "a" * 64}
        with mock.patch.object(self.engine, "_register", return_value=result) as register:
            self.assertEqual(self.engine.execute(job), result)
            self.assertEqual(self.engine.execute(job), result)
            self.assertEqual(self.engine.reconcile({"id": job["id"], "parameters": {}})["result"], result)
        self.assertEqual(register.call_count, 1)
        with self.assertRaisesRegex(engine.EngineError, "operation_identity_conflict"):
            self.engine.execute(job | {"nonce": "different" * 4})

    def test_unknown_inspection_is_not_a_second_action(self):
        job = self.job()
        atomic(self.engine._journal_path(job["id"]), {"id": job["id"], "action": job["action"], "parameters": job["parameters"], "status": "outcome_unknown", "stage": "upload"})
        with mock.patch.object(self.engine, "_backup") as backup:
            result = self.engine.reconcile({"id": job["id"]})
        backup.assert_not_called()
        self.assertEqual(result["status"], "outcome_unknown")

    def test_capture_copy_failure_resumes_source_before_returning_failed(self):
        service, journal, container = self.source()
        service.update(sourceState="running", captureOperation=None)
        project = {"fingerprint": service["fingerprint"], "platform": ["linux", "amd64", ""], "mounts": {"volume:data": {"kind": "volume", "source": "data", "file": False}}, "images": {}, "containers": [{"id": container["Id"]}]}
        service["project"].update(project)
        self.engine._save_service(service)
        self.engine.current = {"id": uid(), "action": "compose-backup", "status": "running"}
        effects = []
        def helper_call(image, sid, args, **kwargs):
            effects.append(args[0])
            if args[0] == "inspect":
                return {"files": 1, "bytes": 3}
            raise engine.EngineError("archive_capture_failed")
        def resume(saved_service, saved_journal):
            effects.append("resume")
            self.assertEqual(saved_service["sourceState"], "capture_stopped")
            self.assertTrue(saved_journal["resume"]["containers"])
        container["State"]["Running"] = True
        def docker(*args, **kwargs):
            effects.append(args[0])
            if args[0] == "stop":
                container["State"]["Running"] = False
            return b""
        with mock.patch.object(self.engine.storage, "preflight"), mock.patch.object(self.engine.storage, "binding", return_value={"repositoryId": "a" * 64}), mock.patch.object(self.engine, "_project", return_value=project), mock.patch.object(self.engine, "_helper_image", return_value={"id": "helper", "dockerRef": "helper", "size": 1}), mock.patch.object(self.engine, "_helper", side_effect=helper_call), mock.patch.object(self.engine, "_reserve", return_value={}), mock.patch.object(self.engine, "_inspect", side_effect=lambda ids: [container]), mock.patch.object(self.engine, "docker", side_effect=docker), mock.patch.object(self.engine, "_resume_capture", side_effect=resume), mock.patch.object(self.engine.storage, "run") as upload:
            with self.assertRaisesRegex(engine.EngineError, "archive_capture_failed"):
                self.engine._backup({"serviceId": self.sid, "storageId": self.storage})
        self.assertEqual(effects, ["inspect", "stop", "pack", "resume"])
        upload.assert_not_called()

    def test_occupied_or_racing_volume_never_reaches_data_extraction(self):
        record = {"id": uid(), "serviceId": self.sid, "resources": []}
        labels = self.engine._owned_labels(record["id"], self.sid, "restore")
        with mock.patch.object(self.engine, "docker", return_value=b"owned-name\n") as docker:
            with self.assertRaisesRegex(engine.EngineError, "restore_resource_occupied"):
                self.engine._new_resource(record, "volume", "owned-name", labels)
        self.assertEqual(docker.call_count, 1)
        with mock.patch.object(self.engine, "docker", return_value=b""), mock.patch.object(self.engine, "_json", return_value=[{"Labels": {"foreign": "sentinel"}, "Driver": "local"}]):
            with self.assertRaisesRegex(engine.EngineError, "restore_resource_occupied"):
                self.engine._new_resource(record, "volume", "racing-name", labels)
        self.assertFalse(record["resources"][-1]["created"])

    def test_internal_network_created_and_owned_before_generated_app_start(self):
        record = {"id": uid(), "serviceId": self.sid, "resources": []}
        labels = self.engine._owned_labels(record["id"], self.sid, "restore") | {helper.OWNER + ".restore": record["id"]}
        with mock.patch.object(self.engine, "docker", return_value=b"") as docker, mock.patch.object(self.engine, "_json", return_value=[{"Labels": labels, "Driver": "bridge"}]):
            self.engine._prepare_networks(record, {"networks": {"default": {"name": "fresh-network", "external": True}}})
        create = next(call.args for call in docker.call_args_list if call.args[:2] == ("network", "create"))
        self.assertIn("--internal", create)
        self.assertIn("com.docker.network.bridge.gateway_mode_ipv4=isolated", create)
        self.assertIn("com.docker.network.bridge.gateway_mode_ipv6=isolated", create)
        self.assertTrue(record["resources"][0]["created"])

    def test_overlapping_writer_uses_inspection_not_volume_host_file_reads(self):
        foreign = {"Id": "foreign", "Mounts": [{"Type": "bind", "Source": "/var/lib/docker", "Destination": "/host-docker", "RW": True}]}
        with mock.patch.object(self.engine, "docker", return_value=b"foreign"), mock.patch.object(self.engine, "_inspect", return_value=[foreign]):
            with self.assertRaisesRegex(engine.EngineError, "external_docker_writer"):
                self.engine._check_other_writers({"volume:data": {"kind": "volume", "source": "data", "writerPath": "/var/lib/docker/volumes/data/_data"}}, set())

    def test_repeated_stop_preserves_first_original_policy_timer_set(self):
        service, journal, container = self.source()
        service.update(sourceState="fenced", fence={"operationId": uid(), "containers": [{"id": container["Id"], "restart": {"Name": "always"}, "running": True}], "timer": {"enabled": True, "interval": "hourly"}})
        first = copy.deepcopy(service["fence"])
        self.engine._save_service(service)
        self.engine.current = {"id": uid(), "action": "compose-stop", "status": "running"}
        with mock.patch.object(self.engine, "_assert_fence"), mock.patch.object(self.engine, "docker") as docker:
            result = self.engine._stop({"serviceId": self.sid, "fingerprint": service["fingerprint"]})
        self.assertTrue(result["fenced"])
        self.assertEqual(self.engine._service(self.sid)["fence"], first)
        docker.assert_not_called()

    def test_remove_protects_current_source_despite_valid_preview_record(self):
        rid = uid()
        record = {"id": rid, "serviceId": self.sid, "state": "isolated_ready", "projectId": "owned-project"}
        atomic(self.engine._restore_path(rid), record)
        self.engine._save_service({"id": self.sid, "projectId": record["projectId"], "sourceState": "running"})
        with mock.patch.object(self.engine, "docker") as docker:
            with self.assertRaisesRegex(engine.EngineError, "current_source_protected"):
                self.engine._remove({"serviceId": self.sid, "restoreId": rid})
        docker.assert_not_called()

    def test_generated_runtime_remaps_data_omits_operational_labels_and_ports(self):
        rid = uid()
        manifest = {"runtime": {"name": "source", "services": {"app": {"image": "reserved:exact", "environment": {"SECRET": "private"}, "build": ".", "container_name": "source-app", "labels": {"traefik.enable": "true"}, "restart": "always", "ports": [{"target": 80, "published": "80"}], "volumes": []}}, "networks": {"default": {"name": "source-network"}}}, "containers": [{"service": "app", "imageId": "sha256:" + "a" * 64, "restart": {"Name": "always"}, "mounts": [{"key": "volume:data", "target": "/data", "readOnly": False}]}]}
        record = {"id": rid, "serviceId": self.sid, "projectId": "rpo-unique"}
        mapping = {"volume:data": {"kind": "volume", "source": "rpo-unique-v0", "logical": "data0"}}
        runtime = self.engine._runtime(manifest, record, mapping)
        app = runtime["services"]["app"]
        for key in ("build", "container_name", "ports"):
            self.assertNotIn(key, app)
        self.assertNotIn("traefik.enable", app["labels"])
        self.assertEqual(app["environment"]["SECRET"], "private")
        self.assertEqual(app["restart"], "no")
        self.assertTrue(runtime["networks"]["default"]["external"])
        self.assertEqual(runtime["networks"]["default"]["name"], "rpo-unique-n0")
        self.assertEqual(app["volumes"][0]["source"], "data0")
        self.assertEqual(runtime["volumes"]["data0"]["name"], "rpo-unique-v0")

    def image_archive(self, *, corrupt=False):
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as out:
            tar_entry(out, "bin/tool", b"executable", mode=0o4755)
            tar_entry(out, "var/run", kind=tarfile.SYMTYPE, link="/run")
        raw = layer.getvalue()
        config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(raw).hexdigest()]}}).encode()
        image_id = "sha256:" + hashlib.sha256(config).hexdigest()
        alias = "rolypolyops-reserved/sha256-" + image_id[7:] + ":bundle"
        layer_path = "blobs/sha256/" + hashlib.sha256(raw).hexdigest()
        config_path = "blobs/sha256/" + image_id[7:]
        path = self.archive([{"name": "manifest.json", "content": json.dumps([{"Config": config_path, "RepoTags": [alias], "Layers": [layer_path]}]).encode()}, {"name": config_path, "content": config}, {"name": layer_path, "content": raw + (b"tamper" if corrupt else b"")}])
        identities = {image_id: {"id": image_id, "os": "linux", "architecture": "amd64", "variant": "", "alias": alias}}
        return path, identities

    def test_legacy_config_root_is_proven_without_native_descriptor(self):
        path, identities = self.image_archive()
        config_id = next(iter(identities))
        def command(*args, **kwargs):
            if args[:2] == ("image", "save"):
                self.assertEqual(args[-1], config_id)
                Path(args[args.index("--output") + 1]).write_bytes(path.read_bytes())
            return b""
        with mock.patch.object(self.engine, "_json", return_value=[{"Id": config_id, "Size": 1}]), mock.patch.object(self.engine, "docker", side_effect=command):
            result = self.engine._container_image_info({"Image": config_id, "Config": {"Image": "legacy:built"}}, ["linux", "amd64", ""])
        self.assertEqual(result["id"], config_id)
        self.assertEqual(result["proofKind"], "legacy-config")

    def docker29_images(self, *, changed_tag=False, foreign=False, omit_root=False):
        def native_archive(marker, architecture):
            path, _ = self.image_archive()
            with tarfile.open(path) as archive:
                files = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
            item = json.loads(files["manifest.json"])[0]
            parsed = json.loads(files.pop(item["Config"]))
            parsed.update(architecture=architecture, created=marker)
            config = json.dumps(parsed).encode()
            cfg = "sha256:" + hashlib.sha256(config).hexdigest()
            config_name = "blobs/sha256/" + cfg[7:]
            files[config_name] = config
            alias = "rolypolyops-reserved/sha256-" + cfg[7:] + ":bundle"
            layers = [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": "sha256:" + name.rsplit("/", 1)[-1], "size": len(files[name])} for name in item["Layers"]]
            native = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": cfg, "size": len(config)}, "layers": layers}).encode()
            child = "sha256:" + hashlib.sha256(native).hexdigest()
            descriptor = {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": child, "size": len(native), "platform": {"os": "linux", "architecture": architecture}}
            index = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [descriptor]}).encode()
            root = "sha256:" + hashlib.sha256(index).hexdigest()
            root_descriptor = {"mediaType": "application/vnd.oci.image.index.v1+json", "digest": root, "size": len(index)}
            files["manifest.json"] = json.dumps([{"Config": config_name, "RepoTags": [alias], "Layers": item["Layers"]}]).encode()
            files["blobs/sha256/" + child[7:]] = native
            if not omit_root:
                files["blobs/sha256/" + root[7:]] = index
            files["index.json"] = json.dumps({"schemaVersion": 2, "manifests": [root_descriptor | {"annotations": {"io.containerd.image.name": alias, "org.opencontainers.image.ref.name": "bundle"}}]}).encode()
            path = self.archive([{"name": name, "content": content} for name, content in files.items()])
            return {"root": root, "child": child, "config": cfg, "descriptor": descriptor, "rootDescriptor": root_descriptor, "archive": path, "alias": alias}
        primary = native_archive("original", "arm64" if foreign else "amd64")
        changed = native_archive("retargeted", "amd64") if changed_tag else primary
        entries = {primary["root"]: primary, changed["root"]: changed}
        def inspect(*args):
            if args[:2] == ("network", "inspect"):
                return [{"Driver": "bridge", "Labels": {"com.docker.compose.project": "ordinary"}}]
            if args[:2] != ("image", "inspect"):
                raise AssertionError(args)
            reference = args[-1]
            entry = changed if reference == "fixture:built" else primary if reference in {primary["root"], "reserved:bundle", primary["alias"]} else None
            if entry is None:
                raise engine.EngineError("docker_operation_failed")
            if "--platform" in args:
                return [{"Id": entry["child"], "Descriptor": entry["descriptor"], "Size": 1}]
            return [{"Id": entry["root"], "Descriptor": entry["rootDescriptor"], "Size": 1}]
        def command(*args, **kwargs):
            if args[:2] == ("image", "save"):
                self.assertIn(args[-1], entries, "only unfiltered immutable lookup roots are exportable")
                Path(args[args.index("--output") + 1]).write_bytes(entries[args[-1]]["archive"].read_bytes())
            return b""
        primary.update(inspect=inspect, command=command)
        return primary

    def test_docker29_distinct_index_manifest_config_chain_and_cached_root_export(self):
        data = self.docker29_images()
        self.assertEqual(len({data["root"], data["child"], data["config"]}), 3)
        container = {"Image": data["root"], "ImageManifestDescriptor": data["descriptor"], "Config": {"Image": "fixture:built"}}
        with mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=data["command"]) as commands:
            result = self.engine._container_image_info(container, ["linux", "amd64", ""])
            again = self.engine._container_image_info(container, ["linux", "amd64", ""])
        self.assertEqual(result["id"], data["config"])
        self.assertEqual(result["dockerRef"], data["root"])
        self.assertEqual(result["manifestDigest"], data["child"])
        self.assertTrue(result["rootIndexBytesVerified"])
        self.assertEqual(result, again)
        self.assertEqual(sum(call.args[:2] == ("image", "save") for call in commands.call_args_list), 1)
        self.engine._image_archive(data["archive"], {data["config"]: result | {"alias": data["alias"]}})

    def test_native_chain_rejects_config_tamper_and_cached_config_claim_tamper(self):
        data = self.docker29_images()
        with mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=data["command"]):
            self.engine._image_info(data["root"], ["linux", "amd64", ""])
            cache = next((self.engine.state / "image-proofs").glob("*.json"))
            proof = read(cache)
            proof["id"] = "sha256:" + "0" * 64
            atomic(cache, proof)
            with self.assertRaisesRegex(engine.EngineError, "image_proof_corrupt"):
                self.engine._image_info(data["root"], ["linux", "amd64", ""])
            cache.unlink()
            with tarfile.open(data["archive"]) as archive:
                files = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
            config_name = "blobs/sha256/" + data["config"][7:]
            parsed = json.loads(files[config_name])
            parsed["created"] = "tampered without changing authenticated manifest"
            files[config_name] = json.dumps(parsed).encode()
            data["archive"] = self.archive([{"name": name, "content": value} for name, value in files.items()])
            with self.assertRaisesRegex(engine.EngineError, "image_identity_unverified"):
                self.engine._image_info(data["root"], ["linux", "amd64", ""])

    def test_docker29_tag_retarget_foreign_platform_and_wrong_container_descriptor_refused(self):
        for changed, foreign, wrong_child, false_config_field in ((True, False, False, False), (False, True, False, False), (False, False, True, False), (False, False, False, True)):
            data = self.docker29_images(changed_tag=changed, foreign=foreign)
            descriptor = data["descriptor"] | ({"digest": "sha256:" + "0" * 64} if wrong_child else {})
            container = {"Image": data["config"] if false_config_field else data["root"], "ImageManifestDescriptor": descriptor, "Config": {"Image": "fixture:built"}}
            with self.subTest(changed=changed, foreign=foreign, wrong_child=wrong_child, false_config_field=false_config_field), mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=data["command"]):
                with self.assertRaisesRegex(engine.EngineError, "image_identity_(mismatch|unverified)"):
                    self.engine._container_image_info(container, ["linux", "amd64", ""])

    def test_docker29_filtered_export_can_omit_index_but_not_actual_child_config_chain(self):
        data = self.docker29_images(omit_root=True)
        container = {"Image": data["root"], "ImageManifestDescriptor": data["descriptor"], "Config": {"Image": "fixture:built"}}
        with mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=data["command"]):
            proof = self.engine._container_image_info(container, ["linux", "amd64", ""])
        self.assertEqual(proof["id"], data["config"])
        self.assertFalse(proof["rootIndexBytesVerified"])
        self.assertEqual(proof["manifestDigest"], data["descriptor"]["digest"])

    def test_docker29_full_discovery_reports_internal_tcp_targets(self):
        data = self.docker29_images()
        path = self.root / "ordinary.json"
        path.write_text("{}")
        labels = {"com.docker.compose.project": "ordinary", "com.docker.compose.service": "app", "com.docker.compose.project.config_files": str(path), "com.docker.compose.project.working_dir": str(self.root)}
        container = {"Id": "a" * 64, "Image": data["root"], "ImageManifestDescriptor": data["descriptor"], "Config": {"Image": "fixture:built", "Labels": labels, "Env": ["MARKER=private"]}, "HostConfig": {}, "State": {"Running": True}, "Mounts": [], "NetworkSettings": {"Networks": {"ordinary_default": {"NetworkID": "network"}}}}
        ports = [{"target": 8080, "published": "18190", "protocol": "tcp"}, {"target": 8080, "published": "18191", "protocol": "tcp"}, {"target": 9000, "published": "18999"}, {"target": 8053, "published": "53", "protocol": "udp"}, {"target": 9001, "published": "18200", "protocol": "sctp"}]
        model = {"services": {"app": {"image": "fixture:built", "environment": {"MARKER": "private"}, "ports": ports, "networks": {"default": None}}}, "networks": {"default": {"name": "ordinary_default"}}}
        with mock.patch.object(self.engine, "_platform", return_value=["linux", "amd64", ""]), mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=data["command"]), mock.patch.object(self.engine, "_precheck_compose"), mock.patch.object(self.engine, "_compose", return_value=json.dumps(model).encode()):
            project = self.engine._project("ordinary", [container])
        self.assertEqual(project["containers"][0]["imageId"], data["config"])
        self.assertEqual(project["images"][data["config"]]["dockerRef"], data["root"])
        self.assertEqual(project["services"][0]["ports"], [8080, 9000])
        self.assertNotIn("private", json.dumps(self.engine._safe_project(project)))

    def test_internal_tcp_exposure_ranges_are_unique_bounded_and_host_ports_are_not_targets(self):
        desired = {"ports": [{"target": 8080, "published": "18190", "protocol": "tcp"}, {"target": 8080, "published": "18191"}, {"target": 53, "published": "5353", "protocol": "udp"}], "expose": ["9000/tcp", "9001-9002/tcp", "8053/udp"]}
        config = {"ExposedPorts": {"8080/tcp": {}, "9003/tcp": {}, "9004/udp": {}}}
        self.assertEqual(self.engine._target_ports(desired, config), [8080, 9000, 9001, 9002, 9003])
        for invalid in ("0", "65536", "1-100", "nonsense", True):
            with self.subTest(invalid=invalid), self.assertRaises(engine.EngineError):
                self.engine._target_ports({"expose": [invalid]}, {})

    def test_docker29_restored_runtime_proves_actual_native_child_and_reserved_alias(self):
        data = self.docker29_images()
        rid = uid()
        record = {"id": rid, "serviceId": self.sid, "projectId": "owned-runtime", "mappings": {}, "ports": []}
        labels = self.engine._owned_labels(rid, self.sid, "restore") | {helper.OWNER + ".restore": rid, "com.docker.compose.project": record["projectId"], "com.docker.compose.service": "app"}
        container = {"Id": "a" * 64, "Image": data["root"], "ImageManifestDescriptor": data["descriptor"], "State": {"Running": True}, "Config": {"Image": "reserved:bundle", "Labels": labels, "Env": []}, "HostConfig": {}, "Mounts": [], "NetworkSettings": {"Networks": {"own-network": {"NetworkID": "network"}}, "Ports": {}}}
        manifest = {"platform": ["linux", "amd64", ""], "runtime": {"services": {"app": {"environment": {}}}}, "containers": [{"service": "app", "imageId": data["config"], "mounts": []}], "images": {data["config"]: {"alias": "reserved:bundle"}}}
        def inspect(*args):
            if args[:2] == ("network", "inspect"):
                return [{"Driver": "bridge", "Internal": True, "Labels": labels, "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated", "com.docker.network.bridge.gateway_mode_ipv6": "isolated"}}]
            return data["inspect"](*args)
        with mock.patch.object(self.engine, "_restore_containers", return_value=[container]), mock.patch.object(self.engine, "_json", side_effect=inspect), mock.patch.object(self.engine, "docker", side_effect=data["command"]):
            self.assertEqual(self.engine._runtime_checks(record, manifest)["app"]["Image"], data["root"])

    def test_helper_runs_exportable_root_and_verifies_actual_manifest_config_chain(self):
        data = self.docker29_images()
        for wrong in (False, True):
            self.engine.current = {"id": uid(), "action": "compose-backup", "status": "running"}
            cid = "c" * 64
            def command(*args, **kwargs):
                if args[0] == "create":
                    self.assertIn(data["root"], args)
                    self.assertNotIn(data["child"], args)
                    self.assertNotIn(data["config"], args)
                    return cid.encode()
                if args[0] == "start":
                    return b'{"files":1,"bytes":3}'
                return data["command"](*args, **kwargs)
            def inspect(ids):
                labels = self.engine.current["helpers"][-1]["labels"]
                descriptor = data["descriptor"] | ({"digest": "sha256:" + "0" * 64} if wrong else {})
                return [{"Id": cid, "Image": data["root"], "ImageManifestDescriptor": descriptor, "Config": {"Labels": labels}, "State": {"Running": False, "ExitCode": 0}}]
            with mock.patch.object(self.engine, "_platform", return_value=["linux", "amd64", ""]), mock.patch.object(self.engine, "_json", side_effect=data["inspect"]), mock.patch.object(self.engine, "docker", side_effect=command), mock.patch.object(self.engine, "_inspect", side_effect=inspect), mock.patch.object(self.engine, "_terminate_helpers") as terminate:
                if wrong:
                    with self.assertRaisesRegex(engine.EngineError, "helper_ownership_unverified"):
                        self.engine._helper(data["root"], self.sid, ["inspect", "/data/payload"])
                else:
                    self.assertEqual(self.engine._helper(data["root"], self.sid, ["inspect", "/data/payload"])["files"], 1)
                terminate.assert_called_once()

    def test_addresses_keep_public_entries_and_report_empty_or_invalid_entries_partial(self):
        values = [{"ifname": "eth0", "addr_info": [{"family": "inet", "scope": "global", "local": "8.8.8.8"}, {}, {"family": "inet6", "scope": "global", "local": "2001:4860:4860::8888"}, {"family": "inet", "scope": "global", "local": "10.1.2.3"}, {"family": "inet", "scope": "global", "local": "not-an-ip"}]}, {"ifname": "br-abc", "addr_info": [{"family": "inet", "scope": "global", "local": "1.1.1.1"}, {}]}]
        with mock.patch.object(self.engine, "_run", return_value=json.dumps(values).encode()), mock.patch.object(self.engine.sealer, "public", return_value={"id": "key"}), mock.patch.object(self.engine, "_containers", side_effect=engine.EngineError("observation_deadline")):
            result = self.engine.observe()
        self.assertEqual(result["addresses"], ["2001:4860:4860::8888", "8.8.8.8"])
        self.assertTrue(result["addressesPartial"])
        self.assertEqual(result["addressesError"], "address_inventory_partial")
        self.assertEqual(result["error"], "observation_deadline")

    def test_pre_extraction_virtual_link_graph_rejects_escape_and_cycles_preserves_direct_links(self):
        entries = [{"name": "payload", "kind": tarfile.DIRTYPE}, {"name": "payload/sym", "kind": tarfile.SYMTYPE, "link": "."}, {"name": "payload/x", "content": b"x"}, {"name": "payload/d", "kind": tarfile.DIRTYPE}, {"name": "payload/d/l", "kind": tarfile.SYMTYPE, "link": "../sym/../x"}, {"name": "payload/s1", "kind": tarfile.SYMTYPE, "link": "sym/.."}, {"name": "payload/s2", "kind": tarfile.SYMTYPE, "link": "s1/.."}]
        with self.assertRaisesRegex(helper.ArchiveError, "archive_link_unsafe"):
            helper.inspect_archive(self.archive(entries))
        cyclic = [{"name": "payload", "kind": tarfile.DIRTYPE}, {"name": "payload/a", "kind": tarfile.SYMTYPE, "link": "b"}, {"name": "payload/b", "kind": tarfile.SYMTYPE, "link": "a"}]
        with self.assertRaisesRegex(helper.ArchiveError, "archive_link_unsafe"):
            helper.inspect_archive(self.archive(cyclic))
        safe = [{"name": "payload", "kind": tarfile.DIRTYPE}, {"name": "payload/d", "kind": tarfile.DIRTYPE}, {"name": "payload/d/file", "content": b"safe"}, {"name": "payload/root", "kind": tarfile.SYMTYPE, "link": "."}, {"name": "payload/file", "kind": tarfile.SYMTYPE, "link": "d/file"}, {"name": "payload/d/link", "kind": tarfile.SYMTYPE, "link": "file"}]
        self.assertEqual(helper.inspect_archive(self.archive(safe))["files"], 6)

    def test_same_direct_link_policy_is_checked_during_source_preflight(self):
        payload = self.root / "payload"
        payload.mkdir()
        (payload / "file").write_text("safe")
        (payload / "direct").symlink_to("file")
        with mock.patch.object(os, "listxattr", create=True, return_value=[]):
            self.assertEqual(helper.inspect_tree(payload)["files"], 3)
            (payload / "chain").symlink_to("direct")
            with self.assertRaisesRegex(helper.ArchiveError, "archive_link_unsafe"):
                helper.inspect_tree(payload)
        archive = self.archive([{"name": "payload", "kind": tarfile.DIRTYPE}, {"name": "payload/file", "content": b"safe"}, {"name": "payload/direct", "kind": tarfile.SYMTYPE, "link": "file"}, {"name": "payload/chain", "kind": tarfile.SYMTYPE, "link": "direct"}])
        with self.assertRaisesRegex(helper.ArchiveError, "archive_link_unsafe"):
            helper.inspect_archive(archive)

    def _native_files(self, data):
        with tarfile.open(data["archive"]) as archive:
            return {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}

    def test_every_native_index_entrypoint_is_bound_to_legacy_verified_config_and_alias(self):
        data = self.docker29_images()
        files = self._native_files(data)
        old_config = json.loads(files["blobs/sha256/" + data["config"][7:]])
        old_config["config"] = {"Entrypoint": ["/unverified-image"]}
        config_raw = json.dumps(old_config).encode()
        config_id = "sha256:" + hashlib.sha256(config_raw).hexdigest()
        native = json.loads(files["blobs/sha256/" + data["child"][7:]])
        native["config"].update(digest=config_id, size=len(config_raw))
        native_raw = json.dumps(native).encode()
        native_id = "sha256:" + hashlib.sha256(native_raw).hexdigest()
        files["blobs/sha256/" + config_id[7:]] = config_raw
        files["blobs/sha256/" + native_id[7:]] = native_raw
        index = json.loads(files["index.json"])
        index["manifests"][0].update(mediaType="application/vnd.oci.image.manifest.v1+json", digest=native_id, size=len(native_raw))
        files["index.json"] = json.dumps(index).encode()
        path = self.archive([{"name": name, "content": content} for name, content in files.items()])
        identities = {data["config"]: {"id": data["config"], "os": "linux", "architecture": "amd64", "variant": "", "alias": data["alias"]}}
        with self.assertRaisesRegex(engine.EngineError, "image_identity_unverified"):
            self.engine._image_archive(path, identities)

    def _author_bundle(self, *, mutate=None, dishonest=False):
        data = self.docker29_images()
        images = {data["config"]: {"id": data["config"], "alias": data["alias"], "os": "linux", "architecture": "amd64", "variant": ""}}
        measured = self.engine._image_archive(data["archive"], images)
        images[data["config"]]["size"] = 1 if dishonest else measured[data["config"]]["requiredBytes"]
        operation, service, repository = uid(), uid(), "a" * 64
        runtime = {"name": "source", "services": {"app": {"image": data["alias"], "environment": {}}}}
        manifest = {"format": "rolypolyops-compose-v1", "serviceId": service, "repositoryId": repository, "operationId": operation, "sourceFingerprint": "b" * 64, "platform": ["linux", "amd64", ""], "runtime": runtime, "containers": [{"id": "source-app", "service": "app", "imageId": data["config"], "mounts": []}], "archives": [], "images": images, "imagesSha256": helper.digest(data["archive"]), "helperId": data["config"]}
        if mutate:
            mutate(manifest)
        manifest["runtimeDigest"] = hashlib.sha256(helper.canonical(manifest["runtime"])).hexdigest()
        raw = helper.canonical(manifest)
        path = self.archive([{"name": "manifest.json", "content": raw}, {"name": "images.tar", "content": data["archive"].read_bytes()}])
        directory = self.root / uid()
        directory.mkdir()
        point = {"manifestDigest": hashlib.sha256(raw).hexdigest(), "sourceFingerprint": "b" * 64, "operationId": operation}
        return path, directory, service, repository, point, measured

    def test_bundle_runtime_identity_is_bound_and_honest_measured_budget_is_required(self):
        path, directory, service, repository, point, measured = self._author_bundle()
        validated = self.engine._bundle(path, directory, service_id=service, repository_id=repository, point=point)
        self.assertEqual(validated["measuredImages"], measured)
        for mutate in (lambda m: m["runtime"]["services"]["app"].update(image="foreign-preexisting:latest"), lambda m: m["containers"].append(dict(m["containers"][0])), lambda m: m["containers"][0].update(imageId="sha256:" + "0" * 64), lambda m: m["containers"][0].update(service="foreign")):
            path, directory, service, repository, point, _ = self._author_bundle(mutate=mutate)
            with self.assertRaisesRegex(engine.EngineError, "compose_image_binding_invalid"):
                self.engine._bundle(path, directory, service_id=service, repository_id=repository, point=point)
        path, directory, service, repository, point, _ = self._author_bundle(dishonest=True)
        with self.assertRaisesRegex(engine.EngineError, "bundle_image_budget_mismatch"):
            self.engine._bundle(path, directory, service_id=service, repository_id=repository, point=point)

    def test_image_layer_gzip_expansion_is_measured_with_hard_limits_and_native_semantics(self):
        import gzip
        layer = io.BytesIO()
        with tarfile.open(fileobj=layer, mode="w") as archive:
            tar_entry(archive, "data", b"x" * 65536)
        raw = layer.getvalue()
        compressed = gzip.compress(raw)
        archive_path = self.archive([{"name": "layer", "content": compressed}])
        with tarfile.open(archive_path) as archive:
            measured = self.engine._measure_image_layer(archive, "layer")
        self.assertEqual(measured["expandedBytes"], len(raw))
        self.assertEqual(measured["logicalBytes"], 65536)
        self.assertGreater(measured["requiredBytes"], len(compressed) * 10)
        with mock.patch.object(engine, "MAX_BYTES", 32768), tarfile.open(archive_path) as archive:
            with self.assertRaisesRegex(engine.EngineError, "image_expanded_byte_limit"):
                self.engine._measure_image_layer(archive, "layer")
        unsupported = self.archive([{"name": "layer", "content": b"\x28\xb5\x2f\xfdunsupported"}])
        with tarfile.open(unsupported) as archive, self.assertRaisesRegex(engine.EngineError, "image_compression_unsupported"):
            self.engine._measure_image_layer(archive, "layer")

    def test_capture_export_records_measured_conservative_image_budget(self):
        data = self.docker29_images()
        stage = self.root / "export"
        stage.mkdir()
        def command(*args, **kwargs):
            if args[:2] == ("image", "save") and args[-1] == data["alias"]:
                Path(args[args.index("--output") + 1]).write_bytes(data["archive"].read_bytes())
                return b""
            return data["command"](*args, **kwargs)
        image = {"id": data["config"], "dockerRef": data["root"], "os": "linux", "architecture": "amd64", "variant": "", "size": 1}
        with mock.patch.object(self.engine, "docker", side_effect=command):
            images = self.engine._export_images(stage, {data["config"]: image})
        required = images[data["config"]]["measuredImage"]["requiredBytes"]
        self.assertGreater(required, 1)
        self.assertGreaterEqual(images[data["config"]]["size"], required)
        with mock.patch.object(engine.shutil, "disk_usage", return_value=mock.Mock(free=required * 3 + 512 * 1024 ** 2 - 1)):
            with self.assertRaisesRegex(engine.EngineError, "insufficient_staging_space"):
                self.engine._reserve(0, required, 1)

    def test_oci_or_legacy_secondary_tags_cannot_overwrite_other_images(self):
        for name, document in (("index.json", {"manifests": [{"annotations": {"io.containerd.image.name": "production:latest", "org.opencontainers.image.ref.name": "latest"}}]}), ("repositories", {"production": {"latest": "a" * 64}})):
            path, identities = self.image_archive()
            with tarfile.open(path, "a") as archive:
                tar_entry(archive, name, json.dumps(document).encode())
            with self.subTest(name=name), self.assertRaisesRegex(engine.EngineError, "image_identity_unverified"):
                self.engine._image_archive(path, identities)

    def test_native_image_rootfs_semantics_do_not_weaken_host_data_rules(self):
        path, identities = self.image_archive()
        self.engine._image_archive(path, identities)
        data = self.archive([{"name": "payload/tool", "mode": 0o4755}])
        with self.assertRaises(helper.ArchiveError):
            helper.inspect_archive(data)
        corrupt, identities = self.image_archive(corrupt=True)
        with self.assertRaisesRegex(engine.EngineError, "image_identity_unverified"):
            self.engine._image_archive(corrupt, identities)

    def test_worker_marker_is_only_root_config_and_never_a_job_parameter(self):
        marker = "/etc/isolated-instance/storage-worker.json"
        with mock.patch.object(engine.StorageManager, "preflight") as probe:
            isolated = engine.ManagedEngine({"nodeId": self.engine.node_id, "storageWorkerUser": "isolated-worker", "storageWorkerMarker": marker}, self.root / "isolated")
        self.assertEqual(isolated.storage.transport.worker_user, "isolated-worker")
        self.assertEqual(isolated.storage.transport.marker_path, marker)
        self.assertFalse((isolated.state / "transport-settings.json").exists())
        probe.assert_not_called()
        for field in ("storageWorkerMarker", "storageWorkerUser", "marker_path"):
            job = self.job()
            job["parameters"][field] = marker
            with self.assertRaises(engine.EngineError):
                engine.validate_job(job)

    def test_storage_cleanup_failure_blocks_source_compensation_and_reconciliation(self):
        service, journal, container = self.source()
        self.engine._save_service(service)
        atomic(self.engine._journal_path(journal["id"]), journal)
        with mock.patch.object(self.engine.storage, "recover", side_effect=engine.StorageError("transport_cleanup_unverified", True)), mock.patch.object(self.engine, "_resume_capture") as resume, mock.patch.object(self.engine, "_terminate_helpers") as helpers, mock.patch.object(self.engine.storage, "reconcile") as reconcile:
            with self.assertRaisesRegex(engine.StorageError, "transport_cleanup_unverified"):
                self.engine.recover()
        resume.assert_not_called(); helpers.assert_not_called(); reconcile.assert_not_called()
        self.assertEqual(self.engine._service(self.sid)["sourceState"], "capture_stopped")

    def test_local_only_observation_preserves_key_and_unknown_without_external_calls(self):
        self.engine.sealer.path.write_text("existing key")
        os.chmod(self.engine.sealer.path, 0o600)
        operation = uid()
        atomic(self.engine._journal_path(operation), {"id": operation, "action": "compose-backup", "origin": "timer", "status": "running", "stage": "repository-write-intent", "parameters": {"sentinel": "private"}})
        with mock.patch.object(self.engine.sealer, "public", return_value={"keyId": "existing"}), mock.patch.object(self.engine, "docker") as docker, mock.patch.object(self.engine, "_timer") as timer, mock.patch.object(self.engine.storage, "preflight") as probe, mock.patch.object(self.engine.storage, "run") as run, mock.patch.object(self.engine.storage, "recover") as recover:
            result = self.engine.observe(local_only=True)
        self.assertFalse(result["ready"])
        self.assertEqual(result["error"], "compose_recovery_required")
        self.assertEqual(result["key"], {"keyId": "existing"})
        self.assertEqual(result["operations"][0]["status"], "outcome_unknown")
        self.assertEqual(result["operations"][0]["origin"], "timer")
        self.assertNotIn("sentinel", json.dumps(result))
        for call in (docker, timer, probe, run, recover):
            call.assert_not_called()

    def test_local_only_observation_never_creates_missing_key(self):
        with mock.patch.object(self.engine.sealer, "public") as public:
            result = self.engine.observe(local_only=True)
        public.assert_not_called()
        self.assertNotIn("key", result)
        self.assertFalse(self.engine.sealer.path.exists())

    def test_busy_observation_skips_network_without_orphan_or_probe(self):
        service, _, _ = self.source()
        service["sourceState"] = "running"
        self.engine._save_service(service)
        with self.engine.lock(), mock.patch.object(self.engine, "_observe_addresses", return_value=[]), mock.patch.object(self.engine.sealer, "public", return_value={"keyId": "key"}), mock.patch.object(self.engine, "_containers", return_value=[]), mock.patch.object(self.engine, "_timer", return_value={}), mock.patch.object(self.engine, "_snapshots") as snapshots, mock.patch.object(self.engine.storage, "preflight") as probe:
            self.engine._local.addresses_partial = False
            result = self.engine.observe()
        snapshots.assert_not_called(); probe.assert_not_called()
        self.assertEqual(result["services"][0]["snapshotError"], "snapshot_inventory_unavailable")
        self.assertEqual(result["operations"], [])

    def test_backup_preflight_fails_before_cold_pause_or_helper(self):
        service, _, _ = self.source()
        service["sourceState"] = "running"
        self.engine._save_service(service)
        with mock.patch.object(self.engine.storage, "binding", return_value={}), mock.patch.object(self.engine.storage, "preflight", side_effect=engine.StorageError("network_isolation_unavailable")), mock.patch.object(self.engine, "_helper") as helper_call, mock.patch.object(self.engine, "docker") as docker:
            with self.assertRaisesRegex(engine.StorageError, "network_isolation_unavailable"):
                self.engine._backup({"serviceId": self.sid, "storageId": self.storage})
        helper_call.assert_not_called(); docker.assert_not_called()
        self.assertEqual(self.engine._service(self.sid)["sourceState"], "running")

    def test_capture_final_quiescence_rejects_running_restart_and_restart_then_stop(self):
        for mode in ("running", "stopped-again", "unchanged", "all-stopped", "missing", "extra"):
            with self.subTest(mode=mode):
                service, _, first = self.source()
                service["sourceState"] = "running"
                second = copy.deepcopy(first)
                second["Id"] = "d" * 64
                first["State"]["Running"] = mode != "all-stopped"
                containers = [first, second]
                project = {"fingerprint": service["fingerprint"], "platform": ["linux", "amd64", ""], "mounts": {"volume:data": {"kind": "volume", "source": "data", "file": False}}, "images": {}, "containers": [{"id": c["Id"]} for c in containers]}
                service["project"].update(project)
                self.engine._save_service(service)
                self.engine.current = {"id": uid(), "action": "compose-backup", "status": "running"}
                effects = []
                def helper_call(image, sid, args, **kwargs):
                    if args[0] == "inspect":
                        return {"files": 1, "bytes": 3}
                    if mode in {"running", "stopped-again"}:
                        first["State"].update(Running=mode == "running", StartedAt="2026-11-02T13:00:00.000000001Z")
                        first["RestartCount"] = 1
                    elif mode == "missing":
                        first["State"].pop("StartedAt")
                    return {}
                def docker(*args, **kwargs):
                    effects.append(args)
                    if args[0] == "stop":
                        for c in containers:
                            c["State"]["Running"] = False
                    elif args[0] == "start":
                        next(c for c in containers if c["Id"] == args[1])["State"]["Running"] = True
                    return b""
                def inspect(ids):
                    return [c for c in containers if c["Id"] in ids]
                final = lambda: containers + ([copy.deepcopy(second) | {"Id": "e" * 64}] if mode == "extra" else [])
                with mock.patch.object(self.engine.storage, "preflight"), mock.patch.object(self.engine.storage, "binding", return_value={"repositoryId": "a" * 64}), mock.patch.object(self.engine, "_project", return_value=project), mock.patch.object(self.engine, "_helper_image", return_value={"id": "helper", "dockerRef": "helper", "size": 1}), mock.patch.object(self.engine, "_helper", side_effect=helper_call), mock.patch.object(self.engine, "_reserve", return_value={}), mock.patch.object(self.engine, "_inspect", side_effect=inspect), mock.patch.object(self.engine, "_containers", side_effect=final), mock.patch.object(self.engine, "docker", side_effect=docker), mock.patch.object(self.engine, "_terminate_helpers", side_effect=lambda journal: effects.append(("helpers-dead",))), mock.patch.object(engine, "inspect_archive", return_value={"sha256": "a" * 64, "files": 1, "bytes": 3, "entries": []}), mock.patch.object(self.engine, "_export_images", side_effect=engine.EngineError("export-reached")) as export, mock.patch.object(self.engine.storage, "run") as upload:
                    expected = "export-reached" if mode in {"unchanged", "all-stopped"} else "capture_source_restarted" if mode in {"running", "stopped-again"} else "capture_source_changed"
                    with self.assertRaisesRegex(engine.EngineError, expected):
                        self.engine._backup({"serviceId": self.sid, "storageId": self.storage})
                self.assertEqual(export.call_count, 1 if mode in {"unchanged", "all-stopped"} else 0)
                upload.assert_not_called()
                starts = [args for args in effects if args[0] == "start"]
                self.assertEqual(starts, [] if mode in {"running", "all-stopped"} else [("start", first["Id"])])
                if mode == "all-stopped":
                    self.assertFalse(any(args[0] == "stop" for args in effects))
                self.assertFalse(second["State"]["Running"])
                if starts:
                    self.assertLess(effects.index(("helpers-dead",)), effects.index(starts[0]))

    def test_missing_native_capture_fields_fail_before_stop(self):
        base = {"Id": "a" * 64, "State": {"Running": False, "StartedAt": "2026-11-01T12:00:00Z"}, "RestartCount": 0}
        for change in ({"RestartCount": True}, {"RestartCount": -1}, {"State": {"Running": False}}, {"State": {"Running": False, "StartedAt": "invented"}}):
            with self.assertRaisesRegex(engine.EngineError, "capture_source_changed"):
                self.engine._capture_observations([base | change], {base["Id"]})
        self.assertEqual(self.engine._capture_observations([base], {base["Id"]})[base["Id"]]["restartCount"], 0)



if __name__ == "__main__":
    unittest.main()
