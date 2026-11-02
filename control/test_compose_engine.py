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
        c = {"Id": "a" * 64, "Image": "sha256:" + "b" * 64, "State": {"Running": False}, "Mounts": [], "Config": {"Labels": {"com.docker.compose.project": "ordinary"}}}
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
        with mock.patch.object(self.engine.storage, "binding", return_value={"repositoryId": "a" * 64}), mock.patch.object(self.engine, "_project", return_value=project), mock.patch.object(self.engine, "_helper_image", return_value={"id": "helper", "dockerRef": "helper", "size": 1}), mock.patch.object(self.engine, "_helper", side_effect=helper_call), mock.patch.object(self.engine, "_reserve", return_value={}), mock.patch.object(self.engine, "_inspect", side_effect=lambda ids: [container]), mock.patch.object(self.engine, "docker", side_effect=docker), mock.patch.object(self.engine, "_resume_capture", side_effect=resume), mock.patch.object(self.engine.storage, "run") as upload:
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

    def test_platform_export_proves_config_identity_when_display_id_differs(self):
        path, identities = self.image_archive()
        expected = next(iter(identities))
        display = "sha256:" + "f" * 64
        def docker(*args, **kwargs):
            if args[:2] == ("image", "save"):
                target = Path(args[args.index("--output") + 1])
                target.write_bytes(path.read_bytes())
            return b""
        with mock.patch.object(self.engine, "_json", return_value=[{"Id": display, "Size": 1}]), mock.patch.object(self.engine, "docker", side_effect=docker) as command:
            first = self.engine._image_info("local-built:application", ["linux", "amd64", ""])
            second = self.engine._image_info("other-alias:same-content", ["linux", "amd64", ""])
        self.assertEqual(first["id"], expected)
        self.assertNotEqual(first["id"], display)
        self.assertEqual(first["dockerRef"], display)
        self.assertEqual(first, second)
        self.assertEqual(command.call_count, 1)
        self.assertIn("--platform", command.call_args.args)

    def docker29_images(self, *, changed_tag=False, foreign=False):
        path, identities = self.image_archive()
        expected = next(iter(identities))
        native, other = "sha256:" + "f" * 64, "sha256:" + "e" * 64
        if foreign:
            with tarfile.open(path) as archive:
                files = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
            manifest = json.loads(files["manifest.json"])
            config_path = manifest[0]["Config"]
            parsed = json.loads(files[config_path])
            parsed["architecture"] = "arm64"
            config = json.dumps(parsed).encode()
            expected = "sha256:" + hashlib.sha256(config).hexdigest()
            manifest[0]["Config"] = "blobs/sha256/" + expected[7:]
            files.pop(config_path)
            files[manifest[0]["Config"]] = config
            files["manifest.json"] = json.dumps(manifest).encode()
            path = self.archive([{"name": name, "content": content} for name, content in files.items()])
        def inspect(*args):
            if args[:2] == ("network", "inspect"):
                return [{"Driver": "bridge", "Labels": {"com.docker.compose.project": "ordinary"}}]
            if args[:2] != ("image", "inspect"):
                raise AssertionError(args)
            reference = args[-1]
            if reference == expected:
                raise engine.EngineError("docker_operation_failed")
            if reference in {native, "fixture:built", "reserved:bundle"}:
                return [{"Id": other if changed_tag and reference == "fixture:built" else native, "Size": 1}]
            raise engine.EngineError("docker_operation_failed")
        def command(*args, **kwargs):
            if args[:2] == ("image", "save"):
                target = Path(args[args.index("--output") + 1])
                if args[-1] == other:
                    # A new valid export with another config identity must never be associated with the old container.
                    with tarfile.open(path) as archive:
                        files = {m.name: archive.extractfile(m).read() for m in archive if m.isfile()}
                    manifest = json.loads(files["manifest.json"])
                    old_config = manifest[0]["Config"]
                    config = json.loads(files[old_config])
                    config["created"] = "different-tag-content"
                    raw = json.dumps(config).encode()
                    new_config = "blobs/sha256/" + hashlib.sha256(raw).hexdigest()
                    files.pop(old_config)
                    files[new_config] = raw
                    manifest[0]["Config"] = new_config
                    files["manifest.json"] = json.dumps(manifest).encode()
                    with tarfile.open(target, "w") as archive:
                        for name, content in files.items():
                            tar_entry(archive, name, content)
                else:
                    target.write_bytes(path.read_bytes())
            elif args[:2] == ("image", "ls"):
                return (native + "\n").encode()
            return b""
        return expected, native, inspect, command

    def test_docker29_config_digest_uninspectable_binds_native_descriptor_and_current_tag(self):
        expected, native, inspect, command = self.docker29_images()
        container = {"Image": expected, "ImageManifestDescriptor": {"digest": native}, "Config": {"Image": "fixture:built"}}
        with mock.patch.object(self.engine, "_json", side_effect=inspect) as lookups, mock.patch.object(self.engine, "docker", side_effect=command):
            result = self.engine._container_image_info(container, ["linux", "amd64", ""])
            again = self.engine._container_image_info(container, ["linux", "amd64", ""])
        self.assertEqual(result["id"], expected)
        self.assertEqual(result["dockerRef"], native)
        self.assertEqual(result, again)
        self.assertTrue(any(call.args[-1] == native for call in lookups.call_args_list))
        self.assertTrue(list((self.engine.state / "container-image-proofs").glob("*.json")))

    def test_docker29_tag_candidate_requires_exact_config_and_foreign_platform_fails(self):
        for changed, foreign in ((True, False), (False, True)):
            expected, native, inspect, command = self.docker29_images(changed_tag=changed, foreign=foreign)
            container = {"Image": expected, "ImageManifestDescriptor": {"digest": native}, "Config": {"Image": "fixture:built"}}
            with self.subTest(changed=changed, foreign=foreign), mock.patch.object(self.engine, "_json", side_effect=inspect), mock.patch.object(self.engine, "docker", side_effect=command):
                with self.assertRaisesRegex(engine.EngineError, "image_identity_(mismatch|unverified)"):
                    self.engine._container_image_info(container, ["linux", "amd64", ""])

    def test_docker29_catalog_lookup_is_local_bounded_and_byte_proven(self):
        expected, native, inspect, command = self.docker29_images()
        container = {"Image": expected, "Config": {}}
        with mock.patch.object(self.engine, "_json", side_effect=inspect), mock.patch.object(self.engine, "docker", side_effect=command):
            result = self.engine._container_image_info(container, ["linux", "amd64", ""])
        self.assertEqual(result["id"], expected)
        self.assertEqual(result["dockerRef"], native)

    def test_docker29_full_source_discovery_with_config_only_container_image(self):
        expected, native, inspect, command = self.docker29_images()
        path = self.root / "ordinary.json"
        path.write_text("{}")
        labels = {"com.docker.compose.project": "ordinary", "com.docker.compose.service": "app", "com.docker.compose.project.config_files": str(path), "com.docker.compose.project.working_dir": str(self.root)}
        container = {"Id": "a" * 64, "Image": expected, "ImageManifestDescriptor": {"digest": native}, "Config": {"Image": "fixture:built", "Labels": labels, "Env": ["MARKER=private"]}, "HostConfig": {}, "State": {"Running": True}, "Mounts": [], "NetworkSettings": {"Networks": {"ordinary_default": {"NetworkID": "network"}}}}
        model = {"services": {"app": {"image": "fixture:built", "environment": {"MARKER": "private"}, "networks": {"default": None}}}, "networks": {"default": {"name": "ordinary_default"}}}
        with mock.patch.object(self.engine, "_platform", return_value=["linux", "amd64", ""]), mock.patch.object(self.engine, "_json", side_effect=inspect), mock.patch.object(self.engine, "docker", side_effect=command), mock.patch.object(self.engine, "_precheck_compose"), mock.patch.object(self.engine, "_compose", return_value=json.dumps(model).encode()):
            project = self.engine._project("ordinary", [container])
        self.assertEqual(project["containers"][0]["imageId"], expected)
        self.assertEqual(project["images"][expected]["dockerRef"], native)
        self.assertEqual(len(project["fingerprint"]), 64)
        self.assertNotIn("private", json.dumps(self.engine._safe_project(project)))

    def test_docker29_restored_runtime_proves_container_and_reserved_alias(self):
        expected, native, inspect, command = self.docker29_images()
        rid = uid()
        record = {"id": rid, "serviceId": self.sid, "projectId": "owned-runtime", "mappings": {}, "ports": []}
        labels = self.engine._owned_labels(rid, self.sid, "restore") | {helper.OWNER + ".restore": rid, "com.docker.compose.project": record["projectId"], "com.docker.compose.service": "app"}
        container = {"Id": "a" * 64, "Image": expected, "ImageManifestDescriptor": {"digest": native}, "State": {"Running": True}, "Config": {"Image": "reserved:bundle", "Labels": labels, "Env": []}, "HostConfig": {}, "Mounts": [], "NetworkSettings": {"Networks": {"own-network": {"NetworkID": "network"}}, "Ports": {}}}
        manifest = {"platform": ["linux", "amd64", ""], "runtime": {"services": {"app": {"environment": {}}}}, "containers": [{"service": "app", "imageId": expected, "mounts": []}], "images": {expected: {"alias": "reserved:bundle"}}}
        def local_inspect(*args):
            if args[:2] == ("network", "inspect"):
                return [{"Driver": "bridge", "Internal": True, "Labels": labels, "Options": {"com.docker.network.bridge.gateway_mode_ipv4": "isolated", "com.docker.network.bridge.gateway_mode_ipv6": "isolated"}}]
            return inspect(*args)
        with mock.patch.object(self.engine, "_restore_containers", return_value=[container]), mock.patch.object(self.engine, "_json", side_effect=local_inspect), mock.patch.object(self.engine, "docker", side_effect=command):
            result = self.engine._runtime_checks(record, manifest)
        self.assertEqual(result["app"]["Image"], expected)

    def test_helper_uses_native_reference_but_checks_actual_config_digest(self):
        cfg, native, cid = "sha256:" + "a" * 64, "sha256:" + "b" * 64, "c" * 64
        for wrong in (False, True):
            self.engine.current = {"id": uid(), "action": "compose-backup", "status": "running"}
            def command(*args, **kwargs):
                if args[0] == "create":
                    self.assertIn(native, args)
                    self.assertNotIn(cfg, args)
                    return cid.encode()
                return b'{"files":1,"bytes":3}'
            def inspect(ids):
                labels = self.engine.current["helpers"][-1]["labels"]
                return [{"Id": cid, "Image": "sha256:" + "d" * 64 if wrong else cfg, "Config": {"Labels": labels}, "State": {"Running": False, "ExitCode": 0}}]
            with mock.patch.object(self.engine, "_image_info", return_value={"id": cfg, "dockerRef": native}), mock.patch.object(self.engine, "docker", side_effect=command), mock.patch.object(self.engine, "_inspect", side_effect=inspect), mock.patch.object(self.engine, "_terminate_helpers") as terminate:
                if wrong:
                    with self.assertRaisesRegex(engine.EngineError, "helper_ownership_unverified"):
                        self.engine._helper(native, self.sid, ["inspect", "/data/payload"])
                else:
                    self.assertEqual(self.engine._helper(native, self.sid, ["inspect", "/data/payload"])["files"], 1)
                terminate.assert_called_once()

    def test_addresses_observed_before_a_discovery_deadline_failure(self):
        addresses = [{"addr_info": [{"local": "192.0.2.10"}, {"local": "127.0.0.1"}]}]
        with mock.patch.object(self.engine, "_run", return_value=json.dumps(addresses).encode()), mock.patch.object(self.engine.sealer, "public", return_value={"id": "key"}), mock.patch.object(self.engine, "_containers", side_effect=engine.EngineError("observation_deadline")):
            result = self.engine.observe()
        self.assertEqual(result["addresses"], ["192.0.2.10"])
        self.assertEqual(result["error"], "observation_deadline")

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


if __name__ == "__main__":
    unittest.main()
