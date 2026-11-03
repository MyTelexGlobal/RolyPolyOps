#!/usr/bin/env python3
"""Managed Compose capture, exact isolated restore and durable source authority."""
import argparse
import base64
import contextlib
import copy
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tarfile
import threading
import time
import uuid

try:
    from .compose_helper import ArchiveError, HELPER_IMAGE, MAX_BYTES, OWNER, canonical, digest, inspect_archive
    from .compose_seal import Sealer, SealError
    from .compose_storage import StorageError, StorageManager, atomic, read
except ImportError:
    from compose_helper import ArchiveError, HELPER_IMAGE, MAX_BYTES, OWNER, canonical, digest, inspect_archive
    from compose_seal import Sealer, SealError
    from compose_storage import StorageError, StorageManager, atomic, read

GENERIC_ACTIONS = {"storage-configure", "compose-register", "compose-backup", "compose-verify", "compose-restore",
                   "compose-remove", "compose-schedule", "compose-stop", "compose-activate", "compose-resume"}
HEX = re.compile(r"^[a-f0-9]{64}$")
NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$")
INTERVALS = {"15min": "*-*-* *:00/15:00 UTC", "hourly": "hourly", "daily": "daily"}
DOCKER = ["docker", "--host", "unix:///var/run/docker.sock"]
SERVICE_KEYS = {"build", "cap_drop", "command", "configs", "container_name", "depends_on", "entrypoint", "environment", "env_file", "expose", "healthcheck", "image", "init", "labels", "logging", "networks", "ports", "read_only", "restart", "secrets", "security_opt", "stdin_open", "stop_grace_period", "stop_signal", "tty", "user", "group_add", "volumes", "working_dir", "cpu_shares", "cpus", "mem_limit", "mem_reservation", "pids_limit", "ulimits", "deploy", "profiles", "pull_policy", "attach"}


class EngineError(Exception):
    def __init__(self, code, unknown=False):
        self.code, self.unknown = code, unknown
        super().__init__(code)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def is_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def validate_job(job):
    if not isinstance(job, dict) or set(job) - {"id", "nonce", "action", "snapshotId", "parameters", "reconcile"}:
        raise EngineError("invalid_job")
    if not is_uuid(job.get("id")) or not isinstance(job.get("action"), str) or job.get("action") not in GENERIC_ACTIONS or not isinstance(job.get("nonce"), str) or not 16 <= len(job["nonce"]) <= 256:
        raise EngineError("invalid_job")
    p, action = job.get("parameters"), job["action"]
    if not isinstance(p, dict):
        raise EngineError("invalid_parameters")
    required = {
        "storage-configure": {"storageId", "envelope", "mode"},
        "compose-register": {"serviceId", "projectId", "fingerprint", "storageId", "backupInterval", "exclusiveWriters"},
        "compose-backup": {"serviceId", "storageId"}, "compose-verify": {"serviceId", "storageId"},
        "compose-restore": {"serviceId", "storageId", "snapshotId"},
        "compose-remove": {"serviceId", "restoreId"}, "compose-schedule": {"serviceId", "interval"},
        "compose-stop": {"serviceId", "fingerprint"},
        "compose-activate": {"serviceId", "restoreId", "sourceStopJobId", "interval", "ports", "allowEgress"},
        "compose-resume": {"serviceId"},
    }[action]
    optional = {"storage-configure": {"expectedRepositoryId", "metadata", "discoverRepositoryId"}, "compose-register": {"healthCheck"},
                "compose-activate": {"sourceStopProof"}, "compose-resume": {"fingerprint", "interval", "activationGroupId", "targetAbsenceProof"}}.get(action, set())
    if not required <= set(p) or set(p) - required - optional:
        raise EngineError("invalid_parameters")
    for field in ("serviceId", "storageId", "restoreId", "sourceStopJobId", "activationGroupId"):
        if field in p and not is_uuid(p[field]):
            raise EngineError("invalid_" + field)
    if "fingerprint" in p and not HEX.fullmatch(p["fingerprint"] if isinstance(p["fingerprint"], str) else ""):
        raise EngineError("invalid_fingerprint")
    if "interval" in p and (not isinstance(p["interval"], str) or p["interval"] not in INTERVALS) or "backupInterval" in p and (not isinstance(p["backupInterval"], str) or p["backupInterval"] not in INTERVALS):
        raise EngineError("invalid_schedule")
    if action == "storage-configure" and ((not isinstance(p["mode"], str) or p["mode"] not in {"create", "attach"}) or not isinstance(p["envelope"], dict)):
        raise EngineError("invalid_parameters")
    if action == "storage-configure" and p["mode"] == "create" and "expectedRepositoryId" in p:
        raise EngineError("create_repository_id_preassigned")
    if action == "storage-configure" and "discoverRepositoryId" in p:
        if p["discoverRepositoryId"] is not True or p["mode"] != "attach" or "expectedRepositoryId" in p:
            raise EngineError("invalid_repository_discovery")
    if action == "storage-configure" and "expectedRepositoryId" in p and (not isinstance(p["expectedRepositoryId"], str) or not HEX.fullmatch(p["expectedRepositoryId"])):
        raise EngineError("invalid_repository_identity")
    if action == "compose-register":
        if not NAME.fullmatch(p["projectId"] if isinstance(p["projectId"], str) else "") or p["exclusiveWriters"] is not True:
            raise EngineError("exclusive_writers_required")
        if "healthCheck" in p:
            h = p["healthCheck"]
            if (not isinstance(h, dict) or set(h) != {"service", "port", "path", "expectedStatus"} or (not isinstance(h.get("service"), str) or not NAME.fullmatch(h["service"]))
                    or type(h["port"]) is not int or not 1 <= h["port"] <= 65535 or type(h["expectedStatus"]) is not int or not 100 <= h["expectedStatus"] <= 599
                    or not isinstance(h["path"], str) or not h["path"].startswith("/") or h["path"].startswith("//") or len(h["path"]) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in h["path"])):
                raise EngineError("invalid_health_check")
    if action == "compose-restore" and (not HEX.fullmatch(p["snapshotId"] if isinstance(p["snapshotId"], str) else "") or job.get("snapshotId") != p["snapshotId"]):
        raise EngineError("invalid_snapshot")
    if action == "compose-activate":
        if p["allowEgress"] is not True or not isinstance(p["ports"], list) or len(p["ports"]) > 40:
            raise EngineError("invalid_activation")
        used = set()
        for port in p["ports"]:
            if (not isinstance(port, dict) or set(port) != {"service", "target", "published", "hostIp", "protocol"}
                    or (not isinstance(port.get("service"), str) or not NAME.fullmatch(port["service"])) or port["protocol"] != "tcp"
                    or any(type(port[k]) is not int or not 1 <= port[k] <= 65535 for k in ("target", "published"))):
                raise EngineError("invalid_ports")
            try:
                if not isinstance(port["hostIp"], str) or "%" in port["hostIp"]:
                    raise ValueError()
                address = ipaddress.ip_address(port["hostIp"])
            except (ValueError, TypeError):
                raise EngineError("invalid_ports") from None
            key = (str(address), port["published"])
            if key in used:
                raise EngineError("invalid_ports")
            used.add(key)
    return job


def has_health(container):
    test = container.get("Config", {}).get("Healthcheck", {}).get("Test")
    return isinstance(test, list) and bool(test) and test[0] != "NONE"


class ManagedEngine:
    def __init__(self, config, state):
        if not isinstance(config, dict) or not is_uuid(config.get("nodeId")):
            raise EngineError("invalid_node_id")
        self.config, self.state = config, Path(state).resolve()
        self.node_id = config["nodeId"]
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state, 0o700)
        for name in ("operations", "services", "restores", "stages"):
            (self.state / name).mkdir(mode=0o700, exist_ok=True)
        self.sealer = Sealer(self.state, self.node_id)
        self.storage = StorageManager(self.state, self.sealer, worker_user=config.get("storageWorkerUser"), marker_path=config.get("storageWorkerMarker"))
        self.current = None
        self._local = threading.local()

    @contextlib.contextmanager
    def lock(self):
        fd = os.open(self.state / "engine.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        acquired = False
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise EngineError("operation_busy") from None
            acquired = True
            self._local.engine_locked = True
            yield
        finally:
            if acquired:
                self._local.engine_locked = False
            os.close(fd)

    def _run(self, args, timeout=60, *, data=None, cwd=None, error="docker_operation_failed", allow_error=False):
        env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.state), "LANG": "C.UTF-8"}
        deadline = getattr(self._local, "observation_deadline", None)
        if deadline is not None:
            timeout = min(timeout, deadline - time.monotonic())
            if timeout <= 0:
                raise EngineError("observation_deadline")
        try:
            value = subprocess.run(args, input=data, stdin=subprocess.DEVNULL if data is None else None, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, env=env, cwd=cwd, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise EngineError("operation_timeout", unknown=True) from None
        except OSError:
            raise EngineError("prerequisite_unavailable") from None
        if value.returncode and not allow_error:
            raise EngineError(error)
        if len(value.stdout) > 32 * 1024 * 1024:
            raise EngineError("result_limit")
        return value.stdout

    def docker(self, *args, timeout=60, error="docker_operation_failed", allow_error=False):
        return self._run(DOCKER + list(args), timeout=timeout, error=error, allow_error=allow_error)

    def _json(self, *args):
        try:
            return json.loads(self.docker(*args))
        except (ValueError, TypeError):
            raise EngineError("docker_result_invalid") from None

    def _inspect(self, ids):
        return self._json("inspect", *ids) if ids else []

    def _journal_path(self, identity):
        if not is_uuid(identity):
            raise EngineError("invalid_operation_id")
        return self.state / "operations" / (identity + ".json")

    def _journal(self, **changes):
        if self.current is None:
            raise EngineError("operation_context_missing")
        self.current.update(changes)
        atomic(self._journal_path(self.current["id"]), self.current)

    def _service_path(self, identity):
        if not is_uuid(identity):
            raise EngineError("invalid_service_id")
        return self.state / "services" / (identity + ".json")

    def _service(self, identity):
        value = read(self._service_path(identity))
        if not value:
            raise EngineError("service_not_registered")
        return value

    def _save_service(self, value):
        atomic(self._service_path(value["id"]), value)

    def _restore_path(self, identity):
        if not is_uuid(identity):
            raise EngineError("invalid_restore_id")
        return self.state / "restores" / (identity + ".json")

    def _restore(self, identity, service_id):
        value = read(self._restore_path(identity))
        if not value or value.get("serviceId") != service_id:
            raise EngineError("restore_not_found")
        return value

    def _compose(self, project, files, directory, *args):
        if not NAME.fullmatch(project) or not files or len(files) > 20:
            raise EngineError("compose_labels_invalid")
        command = DOCKER + ["compose", "--project-directory", directory, "--project-name", project]
        for path in files:
            command += ["--file", path]
        return self._run(command + list(args), cwd=directory, timeout=180)

    def _containers(self):
        ids = self.docker("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project").decode().split()
        if len(ids) > 400:
            raise EngineError("discovery_limit")
        return self._inspect(ids)

    def _owned_source_record(self, service_id, restore_id=None):
        service = self._service(service_id)
        identity = service.get("activeRestoreId")
        if not is_uuid(identity) or (restore_id is not None and restore_id != identity):
            raise EngineError("mount_source_unsafe")
        record = self._restore(identity, service_id)
        directory = self.state / "stages" / identity
        if (record.get("state") != "active" or record.get("directory") != str(directory) or directory.is_symlink()
                or service.get("projectId") != record.get("projectId") or not isinstance(record.get("containerIds"), dict)
                or not record["containerIds"] or digest(directory / "runtime.json") != record.get("runtimeDigest")):
            raise EngineError("mount_source_unsafe")
        return record

    def _safe_source(self, source, *, owned_service=None, restore_id=None, container_id=None):
        path = Path(source)
        if not path.is_absolute() or path.is_symlink() or not path.exists() or any(c in str(path) for c in ",\n\r"):
            raise EngineError("mount_source_unsafe")
        if not (path.is_file() or path.is_dir()):
            raise EngineError("mount_source_unsafe")
        real = path.resolve()
        if real in self.state.parents:
            raise EngineError("mount_source_unsafe")
        if self.state == real or self.state in real.parents:
            if not owned_service:
                raise EngineError("mount_source_unsafe")
            record = self._owned_source_record(owned_service, restore_id)
            allowed = {str(Path(m["source"]).resolve()) for m in record.get("mappings", {}).values() if m.get("kind") == "bind"}
            root = self.state / "stages" / record["id"]
            if str(real) not in allowed or root not in real.parents or container_id not in record["containerIds"].values():
                raise EngineError("mount_source_unsafe")
            relative = real.relative_to(root)
            if len(relative.parts) < 3 or not re.fullmatch(r"mount-[0-9]{1,3}", relative.parts[0]) or relative.parts[1:3] != ("extracted", "payload"):
                raise EngineError("mount_source_unsafe")
            actual = self._inspect([container_id])[0]
            expected = self._owned_labels(record["id"], owned_service, "restore") | {OWNER + ".restore": record["id"]}
            if (not self._labels_match(actual.get("Config", {}).get("Labels", {}), expected)
                    or actual.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != record["projectId"]
                    or not any(m.get("Type") == "bind" and Path(m["Source"]).resolve() == real for m in actual.get("Mounts", []))):
                raise EngineError("mount_source_unsafe")
            return str(real)
        banned = [Path(x).resolve() for x in ("/proc", "/sys", "/dev", "/run", "/var/run", "/var/lib/docker", "/var/lib/containerd", "/etc/ssh", "/etc/rolypolyops", "/root/.ssh", "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/systemd", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot")]
        for item in banned:
            if real == item or item in real.parents or real in item.parents:
                raise EngineError("mount_source_unsafe")
        return str(real)

    def _validate_model(self, model, *, owned=False):
        if not isinstance(model, dict) or set(model) - {"name", "services", "volumes", "networks", "configs", "secrets"}:
            raise EngineError("compose_model_unsupported")
        services = model.get("services")
        if not isinstance(services, dict) or not 1 <= len(services) <= 20:
            raise EngineError("compose_service_limit")
        for name, service in services.items():
            if not NAME.fullmatch(name) or not isinstance(service, dict) or set(service) - SERVICE_KEYS:
                raise EngineError("compose_field_unsupported")
            if any(s not in {"no-new-privileges", "no-new-privileges:true"} for s in service.get("security_opt", [])):
                raise EngineError("compose_security_unsupported")
            deploy = service.get("deploy", {})
            if set(deploy) - {"resources", "replicas"} or deploy.get("replicas", 1) != 1 or set(deploy.get("resources", {})) - {"limits", "reservations"}:
                raise EngineError("compose_replicas_unsupported")
            for resource in deploy.get("resources", {}).values():
                if set(resource) - {"cpus", "memory", "pids"}:
                    raise EngineError("compose_resources_unsupported")
            logging = service.get("logging", {})
            if logging.get("driver", "json-file") not in {"json-file", "local", "none"}:
                raise EngineError("compose_logging_unsupported")
            if service.get("profiles"):
                # Canonical model must describe exactly the enabled, observed service set.
                raise EngineError("compose_profiles_unresolved")
            for volume in service.get("volumes", []):
                if not isinstance(volume, dict) or volume.get("type") not in {"bind", "volume"} or set(volume) - {"type", "source", "target", "read_only", "bind", "volume", "consistency"}:
                    raise EngineError("compose_mount_unsupported")
                if not volume.get("source") or not isinstance(volume.get("target"), str) or not volume["target"].startswith("/"):
                    raise EngineError("compose_mount_unsupported")
                if volume.get("bind", {}).get("propagation", "rprivate") != "rprivate" or set(volume.get("bind", {})) - {"create_host_path", "propagation"}:
                    raise EngineError("compose_mount_unsupported")
                if set(volume.get("volume", {})) - {"nocopy"}:
                    raise EngineError("compose_mount_unsupported")
            for dep in service.get("depends_on", {}):
                if dep not in services:
                    raise EngineError("compose_dependency_unresolved")
        for network in model.get("networks", {}).values():
            if network and ((network.get("external") and not owned) or network.get("driver", "bridge") != "bridge" or set(network) - {"name", "driver", "internal", "enable_ipv6", "ipam", "labels", "attachable", "external"}):
                raise EngineError("compose_network_unsupported")
        for volume in model.get("volumes", {}).values():
            if volume and (volume.get("driver", "local") != "local" or volume.get("driver_opts") or set(volume) - {"name", "driver", "labels", "external"}):
                raise EngineError("compose_volume_unsupported")
        for kind in ("configs", "secrets"):
            for item in model.get(kind, {}).values():
                if not isinstance(item, dict) or "file" not in item or set(item) - {"name", "file", "labels"}:
                    raise EngineError("compose_secret_unsupported")
        return model

    def _precheck_compose(self, files):
        try:
            import yaml
            if int(yaml.__version__.split(".")[0]) < 6:
                raise ImportError()
        except ImportError:
            raise EngineError("pyyaml_unavailable") from None
        total, visits = 0, 0
        tags = {"tag:yaml.org,2002:" + key for key in ("map", "seq", "str", "int", "float", "bool", "null", "timestamp", "merge")}
        for file in files:
            with open(file, "rb") as stream:
                raw = stream.read(4 * 1024 * 1024 + 1)
            total += len(raw)
            if len(raw) > 4 * 1024 * 1024 or total > 16 * 1024 * 1024:
                raise EngineError("compose_input_limit")
            try:
                root = yaml.compose(raw, Loader=yaml.SafeLoader)
            except (yaml.YAMLError, UnicodeError, RecursionError):
                raise EngineError("compose_input_invalid") from None
            def walk(node, ancestors, depth):
                nonlocal visits
                visits += 1
                if visits > 100000 or depth > 64 or id(node) in ancestors:
                    raise EngineError("compose_input_limit")
                if node.tag not in tags:
                    raise EngineError("compose_input_tag_unsupported")
                lineage = ancestors | {id(node)}
                if isinstance(node, yaml.MappingNode):
                    seen = set()
                    for key, value in node.value:
                        if not isinstance(key, yaml.ScalarNode) or key.value in seen:
                            raise EngineError("compose_input_duplicate_key")
                        seen.add(key.value)
                        walk(key, lineage, depth + 1)
                        walk(value, lineage, depth + 1)
                elif isinstance(node, yaml.SequenceNode):
                    for value in node.value:
                        walk(value, lineage, depth + 1)
            if not isinstance(root, yaml.MappingNode):
                raise EngineError("compose_input_invalid")
            walk(root, set(), 0)
            def merged(node):
                if not isinstance(node, yaml.MappingNode):
                    raise EngineError("compose_input_invalid")
                values = {}
                explicit = []
                for key, value in node.value:
                    if key.tag.endswith(":merge"):
                        sources = value.value if isinstance(value, yaml.SequenceNode) else [value]
                        for source in reversed(sources):
                            values.update(merged(source))
                    else:
                        explicit.append((key.value, value))
                values.update(explicit)
                return values
            top = merged(root)
            if "include" in top:
                raise EngineError("compose_remote_input_unsupported")
            if "services" in top:
                for service in merged(top["services"]).values():
                    if {"extends", "provider"} & set(merged(service)):
                        raise EngineError("compose_remote_input_unsupported")

    @staticmethod
    def _target_ports(service, config):
        targets = set()
        def add(value, protocol="tcp"):
            if protocol != "tcp":
                return
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise EngineError("compose_port_unsupported")
            text = str(value)
            if "/" in text:
                text, protocol = text.rsplit("/", 1)
                if protocol != "tcp":
                    return
            if not re.fullmatch(r"[0-9]+(?:-[0-9]+)?", text):
                raise EngineError("compose_port_unsupported")
            first, _, last = text.partition("-")
            first, last = int(first), int(last or first)
            if not 1 <= first <= last <= 65535 or last - first >= 40:
                raise EngineError("compose_port_unsupported")
            targets.update(range(first, last + 1))
            if len(targets) > 40:
                raise EngineError("compose_port_limit")
        for port in service.get("ports", []):
            if not isinstance(port, dict) or "target" not in port:
                raise EngineError("compose_port_unsupported")
            add(port["target"], port.get("protocol", "tcp"))
        for value in service.get("expose", []):
            add(value)
        for value in config.get("ExposedPorts") or {}:
            add(value)
        return sorted(targets)

    def _project(self, project, containers=None, *, owned_service=None):
        containers = self._containers() if containers is None else containers
        selected = [c for c in containers if c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") == project]
        if not selected or len(selected) > 20:
            raise EngineError("compose_project_unavailable")
        labels = selected[0]["Config"]["Labels"]
        if owned_service and not labels.get(OWNER + ".restore"):
            raise EngineError("owned_restore_not_source")
        if labels.get(OWNER + ".restore"):
            if labels.get(OWNER + ".service") != owned_service:
                raise EngineError("owned_restore_not_source")
            owned_record = self._owned_source_record(owned_service, labels[OWNER + ".restore"])
            if {c["Id"] for c in selected} != set(owned_record["containerIds"].values()):
                raise EngineError("owned_restore_not_source")
        files = labels.get("com.docker.compose.project.config_files", "").split(",")
        directory = labels.get("com.docker.compose.project.working_dir", "")
        if not Path(directory).is_absolute() or not Path(directory).is_dir() or any(not Path(p).is_absolute() or not Path(p).is_file() or Path(p).is_symlink() for p in files):
            raise EngineError("compose_labels_invalid")
        self._precheck_compose(files)
        try:
            model = json.loads(self._compose(project, files, directory, "config", "--format", "json"))
        except ValueError:
            raise EngineError("compose_model_invalid") from None
        self._validate_model(model, owned=owned_service is not None)
        identities, mounts, inputs, seen, image_info = [], {}, {}, set(), {}
        mount_count = 0
        for file in files:
            inputs[str(Path(file).resolve())] = digest(file)
        for kind in ("configs", "secrets"):
            for item in model.get(kind, {}).values():
                path = self._safe_source(item["file"])
                if not Path(path).is_file():
                    raise EngineError("compose_secret_unsupported")
                inputs[path] = digest(path)
        safe_services = []
        host_platform = self._platform()
        for container in selected:
            config, host = container.get("Config", {}), container.get("HostConfig", {})
            cl = config.get("Labels", {})
            if owned_service:
                expected_owner = self._owned_labels(owned_record["id"], owned_service, "restore") | {OWNER + ".restore": owned_record["id"]}
                if not self._labels_match(cl, expected_owner):
                    raise EngineError("owned_restore_not_source")
            service = cl.get("com.docker.compose.service")
            if service not in model["services"] or service in seen or cl.get("com.docker.compose.oneoff", "False").lower() != "false":
                raise EngineError("compose_replica_unsupported")
            if not container.get("State", {}).get("Running"):
                raise EngineError("compose_project_not_running")
            seen.add(service)
            if (host.get("Privileged") or host.get("PidMode") == "host" or host.get("IpcMode") not in {"", "private", None}
                    or host.get("NetworkMode") in {"host", "none"} or host.get("Devices") or host.get("DeviceRequests") or host.get("CapAdd")
                    or any(x not in {"no-new-privileges", "no-new-privileges:true"} for x in host.get("SecurityOpt", []) or [])):
                raise EngineError("container_security_unsupported")
            declared_networks = model["services"][service].get("networks", {"default": {}})
            expected_networks = {(model.get("networks", {}).get(n) or {}).get("name", project + "_" + n) for n in declared_networks}
            actual_networks = container.get("NetworkSettings", {}).get("Networks", {})
            if set(actual_networks) != expected_networks:
                raise EngineError("compose_network_drift")
            for network_name, network in actual_networks.items():
                network_info = self._json("network", "inspect", network["NetworkID"])[0]
                if network_info.get("Driver") != "bridge" or (not owned_service and network_info.get("Labels", {}).get("com.docker.compose.project") != project):
                    raise EngineError("compose_network_unsupported")
                if owned_service and (network_info.get("Labels", {}).get(OWNER + ".service") != owned_service or network_info.get("Labels", {}).get(OWNER + ".restore") != cl.get(OWNER + ".restore")):
                    raise EngineError("compose_network_ownership_unverified")
            runtime_env = dict(value.split("=", 1) for value in config.get("Env", []) if "=" in value)
            expected_env = model["services"][service].get("environment", {})
            if not isinstance(expected_env, dict) or any(value is None or runtime_env.get(key) != str(value) for key, value in expected_env.items()):
                raise EngineError("compose_environment_drift")
            desired = model["services"][service]
            for field, actual in (("command", config.get("Cmd")), ("entrypoint", config.get("Entrypoint"))):
                if field in desired and desired[field] not in (None, actual):
                    raise EngineError("compose_container_drift")
            docker_image = container.get("Image", "")
            image = self._container_image_info(container, host_platform)
            actual_image = image["id"]
            image_info[actual_image] = image
            desired_image = desired.get("image")
            if desired_image and self._image_info(desired_image, host_platform)["id"] != actual_image:
                raise EngineError("compose_image_drift")
            desired["environment"] = runtime_env
            runtime_mounts = []
            declared_targets = {m["target"] for m in desired.get("volumes", [])}
            for kind in ("configs", "secrets"):
                for reference in desired.get(kind, []):
                    source = reference if isinstance(reference, str) else reference["source"]
                    target = (reference.get("target") if isinstance(reference, dict) else None) or ("/run/secrets/" + source if kind == "secrets" else "/" + source)
                    declared_targets.add(target)
            for mount in container.get("Mounts", []):
                mount_count += 1
                if mount_count > 100:
                    raise EngineError("compose_mount_limit")
                target = mount.get("Destination")
                if target not in declared_targets or mount.get("Type") not in {"bind", "volume"}:
                    raise EngineError("untracked_mount")
                if mount["Type"] == "bind":
                    source = self._safe_source(mount["Source"], owned_service=owned_service, restore_id=cl.get(OWNER + ".restore"), container_id=container["Id"])
                    key = "bind:" + source
                    descriptor = {"kind": "bind", "source": source, "file": Path(source).is_file(), "writerPath": source}
                else:
                    source = mount.get("Name", "")
                    v = self._json("volume", "inspect", source)[0]
                    if v.get("Driver") != "local" or v.get("Options") or not source:
                        raise EngineError("volume_driver_unsupported")
                    if owned_service and (not self._labels_match(v.get("Labels", {}), expected_owner) or not any(r.get("kind") == "volume" and r.get("name") == source and r.get("created") for r in owned_record.get("resources", []))):
                        raise EngineError("volume_ownership_unverified")
                    key = "volume:" + source
                    descriptor = {"kind": "volume", "source": source, "file": False, "writerPath": mount.get("Source")}
                if len(mounts) >= 100 and key not in mounts:
                    raise EngineError("compose_mount_limit")
                mounts[key] = descriptor
                runtime_mounts.append({"key": key, "target": target, "readOnly": not mount.get("RW", False)})
            if declared_targets != {m["target"] for m in runtime_mounts}:
                raise EngineError("compose_mount_drift")
            identities.append({"id": container["Id"], "service": service, "imageId": actual_image, "dockerImageRef": docker_image, "mounts": sorted(runtime_mounts, key=lambda m: m["target"]),
                               "restart": host.get("RestartPolicy", {"Name": "no", "MaximumRetryCount": 0})})
            ports = self._target_ports(desired, config)
            safe_services.append({"name": service, "imageId": actual_image, "healthcheck": bool(config.get("Healthcheck", {}).get("Test")) and config.get("Healthcheck", {}).get("Test", [""])[0] != "NONE", "ports": ports})
        if seen != set(model["services"]):
            raise EngineError("compose_service_set_drift")
        self._check_other_writers(mounts, {c["Id"] for c in selected})
        fingerprint = hashlib.sha256(canonical({"model": model, "containers": sorted(identities, key=lambda x: x["service"]), "inputs": inputs})).hexdigest()
        platforms = {(v["os"], v["architecture"], v["variant"]) for v in image_info.values()}
        if len(platforms) != 1:
            raise EngineError("image_platform_mismatch")
        return {"id": project, "name": project, "fingerprint": fingerprint, "model": model, "containers": identities,
                "mounts": mounts, "files": files, "directory": directory, "images": image_info, "platform": list(next(iter(platforms))),
                "services": safe_services, "inputs": inputs}

    def _check_other_writers(self, mounts, excluded):
        ids = self.docker("ps", "--quiet").decode().split()
        for container in self._inspect(ids):
            if container["Id"] in excluded:
                continue
            for actual in container.get("Mounts", []):
                if not actual.get("RW", False):
                    continue
                for mount in mounts.values():
                    if mount["kind"] == "volume" and actual.get("Type") == "volume" and actual.get("Name") == mount["source"]:
                        raise EngineError("external_docker_writer")
                    if mount.get("writerPath") and actual.get("Source"):
                        # Inspect-only paths detect bind/volume parent overlap; volume contents are read only through helpers.
                        a, b = Path(actual["Source"]).resolve(), Path(mount["writerPath"]).resolve()
                        if a == b or a in b.parents or b in a.parents:
                            raise EngineError("external_docker_writer")

    def _safe_project(self, value):
        return {"id": value["id"], "name": value["name"], "fingerprint": value["fingerprint"], "supported": True, "reasons": [],
                "services": value["services"], "mounts": [{"kind": m["kind"], "target": ref["target"], "label": m["source"], "readOnly": ref["readOnly"]}
                  for c in value["containers"] for ref in c["mounts"] for m in [value["mounts"][ref["key"]]]],
                "estimatedBytes": sum(v["size"] for v in value["images"].values()), "architecture": "/".join(x for x in value["platform"] if x)}

    def _owned_labels(self, operation, service, purpose):
        return {OWNER + ".operation": operation, OWNER + ".service": service, OWNER + ".purpose": purpose, OWNER + ".node": self.node_id}

    def _labels_match(self, actual, expected):
        return isinstance(actual, dict) and all(actual.get(k) == v for k, v in expected.items())

    def _helper(self, image, service_id, arguments, *, source=None, stage=None, destination_volume=None, network=None, purpose="capture-helper"):
        expected_image = self._image_info(image)
        op = self.current["id"]
        name = "rpo-helper-" + op.replace("-", "")[:24] + "-" + uuid.uuid4().hex[:8]
        labels = self._owned_labels(op, service_id, purpose)
        helpers = self.current.get("helpers", []) + [{"name": name, "labels": labels, "imageId": expected_image["id"], "imageProof": expected_image}]
        self._journal(helpers=helpers)
        args = ["create", "--name", name, "--network", network or "none", "--read-only", "--pids-limit", "64", "--memory", "512m", "--cpus", "1", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH", "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--security-opt", "no-new-privileges"]
        for key, value in labels.items():
            args += ["--label", key + "=" + value]
        tool = Path(__file__).with_name("compose_helper.py").resolve()
        args += ["--mount", "type=bind,src=" + str(tool) + ",dst=/tool/compose_helper.py,readonly"]
        if source:
            args += ["--mount", "type=" + source["kind"] + ",src=" + source["source"] + ",dst=/data/payload,readonly" + (",volume-nocopy" if source["kind"] == "volume" else "")]
        if stage:
            args += ["--mount", "type=bind,src=" + str(stage) + ",dst=/stage"]
        if destination_volume:
            # /stage/extracted is a new owned directory; only this selected new volume is writable.
            args += ["--mount", "type=volume,src=" + destination_volume + ",dst=/stage/extracted/payload"]
        args += [image, "python3", "/tool/compose_helper.py", *arguments]
        identity = self.docker(*args).decode().strip()
        helpers[-1]["id"] = identity
        self._journal(helpers=helpers)
        try:
            raw = self.docker("start", "--attach", identity, timeout=3600, error="helper_failed", allow_error=True)
            actual = self._inspect([identity])[0]
            if not self._labels_match(actual.get("Config", {}).get("Labels", {}), labels) or actual.get("State", {}).get("Running") or not self._container_matches_image(actual, expected_image):
                raise EngineError("helper_ownership_unverified", unknown=True)
            value = json.loads(raw)
            if isinstance(value, dict) and re.fullmatch(r"[a-z_]{1,64}", value.get("error", "")):
                raise EngineError(value["error"])
            if not isinstance(value, dict) or actual.get("State", {}).get("ExitCode") != 0:
                raise EngineError("helper_failed")
            return value
        except (ValueError, KeyError, IndexError):
            raise EngineError("helper_result_invalid") from None
        finally:
            # A failed/timeout helper is terminated before caller may resume a source.
            self._terminate_helpers(self.current)

    def _terminate_helpers(self, journal):
        listed = self.docker("ps", "--all", "--quiet").decode().split()
        actuals = self._inspect(listed)
        by_name = {c.get("Name", "").lstrip("/"): c for c in actuals}
        expected = {item["name"]: item for item in journal.get("helpers", [])}
        # Catch creation completed just before a crash writing the returned container id.
        for container in actuals:
            labels = container.get("Config", {}).get("Labels", {})
            if labels.get(OWNER + ".operation") == journal["id"] and labels.get(OWNER + ".purpose", "").endswith("helper"):
                name = container.get("Name", "").lstrip("/")
                if name not in expected:
                    raise EngineError("helper_ownership_unverified", unknown=True)
        for name, item in expected.items():
            container = by_name.get(name)
            if container is None:
                if item.get("id") and any(c["Id"] == item["id"] for c in actuals):
                    raise EngineError("helper_ownership_unverified", unknown=True)
                continue
            if (item.get("id") and container["Id"] != item["id"]) or (item.get("imageProof") and not self._container_matches_image(container, item["imageProof"])) or (not item.get("imageProof") and item.get("imageId") and container.get("Image") != item["imageId"]) or not self._labels_match(container.get("Config", {}).get("Labels", {}), item["labels"]):
                raise EngineError("helper_ownership_unverified", unknown=True)
            identity = container["Id"]
            if container.get("State", {}).get("Running"):
                self.docker("kill", identity)
            waited = self.docker("wait", identity, timeout=30).decode().strip()
            if not re.fullmatch(r"-?[0-9]+", waited):
                raise EngineError("helper_termination_unverified", unknown=True)
            remaining = self._inspect([identity])[0]
            if remaining.get("State", {}).get("Running"):
                raise EngineError("helper_termination_unverified", unknown=True)
            self.docker("rm", identity)

    def _reserve(self, logical_bytes, image_bytes=0, file_count=100000):
        budget = logical_bytes * 3 + image_bytes * 3 + 512 * 1024 ** 2
        disk = shutil.disk_usage(self.state)
        fs = os.statvfs(self.state)
        if logical_bytes + image_bytes > MAX_BYTES or disk.free < budget or fs.f_favail < file_count * 2 + 1000:
            raise EngineError("insufficient_staging_space")
        return {"logicalBytes": logical_bytes, "imageBytes": image_bytes, "requiredBytes": budget, "freeBytes": disk.free, "freeInodes": fs.f_favail, "fileCount": file_count}

    @staticmethod
    def _descriptor(value):
        if not isinstance(value, dict) or not re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("digest", "")) or type(value.get("size")) is not int or not 0 < value["size"] <= MAX_BYTES:
            raise EngineError("image_identity_unverified")
        result = {k: value[k] for k in ("digest", "size", "mediaType") if k in value}
        if "platform" in value:
            p = value["platform"]
            if not isinstance(p, dict):
                raise EngineError("image_identity_unverified")
            result["platform"] = {k: p[k] for k in ("os", "architecture", "variant") if p.get(k)}
        return result

    def _native_chain(self, archive, item, platform, selected_descriptor=None, root_descriptor=None):
        def raw_member(name, maximum=4 * 1024 * 1024):
            member = archive.getmember(name)
            if not member.isfile() or not 0 <= member.size <= maximum:
                raise ValueError()
            return archive.extractfile(member).read()
        raw = raw_member(item["Config"])
        config = json.loads(raw)
        config_id = "sha256:" + hashlib.sha256(raw).hexdigest()
        actual_platform = [config["os"], config["architecture"], config.get("variant") or ""]
        if actual_platform != platform:
            raise ValueError()
        proof = {"id": config_id, "os": actual_platform[0], "architecture": actual_platform[1], "variant": actual_platform[2], "proofKind": "legacy-config", "manifestDigest": None, "configEvidence": base64.b64encode(raw).decode()}
        if selected_descriptor is None:
            return proof
        selected_descriptor = self._descriptor(selected_descriptor)
        manifest_types = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
        index_types = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
        if selected_descriptor.get("mediaType") not in manifest_types:
            raise ValueError()
        selected_platform = selected_descriptor.get("platform")
        if selected_platform and [selected_platform.get("os"), selected_platform.get("architecture"), selected_platform.get("variant") or ""] != platform:
            raise ValueError()
        def blob(descriptor, maximum=4 * 1024 * 1024):
            descriptor = self._descriptor(descriptor)
            value = raw_member("blobs/sha256/" + descriptor["digest"][7:], maximum)
            if len(value) != descriptor["size"] or "sha256:" + hashlib.sha256(value).hexdigest() != descriptor["digest"]:
                raise ValueError()
            return value
        native_raw = blob(selected_descriptor)
        native = json.loads(native_raw)
        if native.get("schemaVersion") != 2 or native.get("mediaType", selected_descriptor["mediaType"]) not in manifest_types:
            raise ValueError()
        cfg = self._descriptor(native["config"])
        if cfg["digest"] != config_id or cfg["size"] != len(raw):
            raise ValueError()
        if blob(cfg) != raw:
            raise ValueError()
        layers = native.get("layers")
        if not isinstance(layers, list) or len(layers) > 1000 or len(layers) != len(item.get("Layers", [])):
            raise ValueError()
        for layer, name in zip(layers, item["Layers"]):
            layer = self._descriptor(layer)
            if name != "blobs/sha256/" + layer["digest"][7:]:
                raise ValueError()
            member = archive.getmember(name)
            if not member.isfile() or member.size != layer["size"]:
                raise ValueError()
            h = hashlib.sha256()
            stream = archive.extractfile(member)
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(block)
            if "sha256:" + h.hexdigest() != layer["digest"]:
                raise ValueError()
        root_verified, index_evidence = False, {}
        if root_descriptor and root_descriptor.get("mediaType") in index_types:
            root_name = "blobs/sha256/" + root_descriptor["digest"][7:]
            if root_name in archive.getnames():
                visited = set()
                def contains(descriptor, depth=0):
                    if depth > 16 or len(visited) > 1000 or descriptor["digest"] in visited:
                        raise ValueError()
                    visited.add(descriptor["digest"])
                    index_raw = blob(descriptor)
                    index_evidence[descriptor["digest"]] = base64.b64encode(index_raw).decode()
                    if sum(len(value) for value in index_evidence.values()) > 24 * 1024 * 1024:
                        raise ValueError()
                    node = json.loads(index_raw)
                    if node.get("schemaVersion") != 2 or not isinstance(node.get("manifests"), list):
                        raise ValueError()
                    for child in node["manifests"]:
                        child = self._descriptor(child)
                        if child["digest"] == selected_descriptor["digest"]:
                            if child["size"] != selected_descriptor["size"] or child.get("mediaType") != selected_descriptor.get("mediaType"):
                                raise ValueError()
                            return True
                        if child.get("mediaType") in index_types and "blobs/sha256/" + child["digest"][7:] in archive.getnames() and contains(child, depth + 1):
                            return True
                    return False
                if not contains(root_descriptor):
                    raise ValueError()
                root_verified = True
        proof.update(proofKind="native-manifest", manifestDigest=selected_descriptor["digest"], selectedDescriptor=selected_descriptor, rootIndexBytesVerified=root_verified, manifestEvidence=base64.b64encode(native_raw).decode(), indexEvidence=index_evidence)
        return proof

    def _check_image_evidence(self, identity, platform):
        def decoded(value):
            if not isinstance(value, str) or len(value) > 6 * 1024 * 1024:
                raise ValueError()
            return base64.b64decode(value, validate=True)
        raw = decoded(identity["configEvidence"])
        config = json.loads(raw)
        if "sha256:" + hashlib.sha256(raw).hexdigest() != identity["id"] or [config["os"], config["architecture"], config.get("variant") or ""] != platform:
            raise ValueError()
        if identity["proofKind"] == "legacy-config":
            if identity["dockerRef"] != identity["id"]:
                raise ValueError()
            return
        selected = identity["selectedDescriptor"]
        raw_manifest = decoded(identity["manifestEvidence"])
        if "sha256:" + hashlib.sha256(raw_manifest).hexdigest() != selected["digest"] or len(raw_manifest) != selected["size"] or identity["manifestDigest"] != selected["digest"]:
            raise ValueError()
        native = json.loads(raw_manifest)
        if native["config"]["digest"] != identity["id"] or native["config"]["size"] != len(raw):
            raise ValueError()
        if identity.get("rootIndexBytesVerified"):
            indexes = identity["indexEvidence"]
            if not isinstance(indexes, dict) or len(indexes) > 1000 or sum(len(v) for v in indexes.values()) > 24 * 1024 * 1024:
                raise ValueError()
            visited = set()
            def contains(descriptor, depth=0):
                if depth > 16 or descriptor["digest"] in visited:
                    raise ValueError()
                visited.add(descriptor["digest"])
                value = decoded(indexes[descriptor["digest"]])
                if "sha256:" + hashlib.sha256(value).hexdigest() != descriptor["digest"] or len(value) != descriptor["size"]:
                    raise ValueError()
                for child in json.loads(value)["manifests"]:
                    if child["digest"] == selected["digest"] and child["size"] == selected["size"] and child.get("mediaType") == selected.get("mediaType"):
                        return True
                    if child["digest"] in indexes and contains(child, depth + 1):
                        return True
                return False
            if not contains(identity["rootDescriptor"]):
                raise ValueError()

    def _image_info(self, reference, platform=None):
        platform = platform or self._platform()
        if not isinstance(reference, str) or not 1 <= len(reference) <= 2048 or reference.startswith("-") or any(ord(c) < 33 or ord(c) == 127 for c in reference):
            raise EngineError("image_reference_invalid")
        selected = "/".join(x for x in platform if x)
        # The unfiltered lookup root is exportable. A platform-filtered inspect.Id may be only a non-addressable child.
        root = self._json("image", "inspect", reference)[0]
        actual = self._json("image", "inspect", "--platform", selected, reference)[0]
        root_id = root.get("Id")
        if not isinstance(root_id, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", root_id):
            raise EngineError("image_identity_unverified")
        root_descriptor = self._descriptor(root["Descriptor"]) if root.get("Descriptor") else None
        if root_descriptor and root_descriptor["digest"] != root_id:
            raise EngineError("image_identity_unverified")
        selected_descriptor = self._descriptor(actual["Descriptor"]) if actual.get("Descriptor") else None
        if selected_descriptor and selected_descriptor["digest"] != actual.get("Id"):
            raise EngineError("image_identity_unverified")
        key = hashlib.sha256(canonical([3, root_id, root_descriptor, selected_descriptor, platform])).hexdigest()
        proofs = self.state / "image-proofs"
        proofs.mkdir(mode=0o700, exist_ok=True)
        cached = read(proofs / (key + ".json"))
        if cached:
            if (not isinstance(cached, dict) or cached.get("v") != 3 or not re.fullmatch(r"sha256:[a-f0-9]{64}", cached.get("id", ""))
                    or [cached.get("os"), cached.get("architecture"), cached.get("variant", "")] != platform
                    or cached.get("dockerRef") != root_id or cached.get("rootDescriptor") != root_descriptor
                    or cached.get("selectedDescriptor") != selected_descriptor):
                raise EngineError("image_proof_corrupt")
            try:
                self._check_image_evidence(cached, platform)
            except (ValueError, TypeError, KeyError, RecursionError):
                raise EngineError("image_proof_corrupt") from None
            return cached
        size = actual.get("Size", root.get("Size", 0))
        if type(size) is not int or size < 0 or shutil.disk_usage(self.state).free < size * 2 + 512 * 1024 ** 2:
            raise EngineError("insufficient_staging_space")
        path = proofs / ("." + uuid.uuid4().hex + ".tar")
        try:
            self.docker("image", "save", "--platform", selected, "--output", str(path), root_id, timeout=3600)
            inspect_archive(path, data=False)
            with tarfile.open(path) as archive:
                member = archive.getmember("manifest.json")
                if not member.isfile() or member.size > 1024 * 1024:
                    raise ValueError()
                values = json.load(archive.extractfile(member))
                if not isinstance(values, list) or len(values) != 1:
                    raise ValueError()
                identity = self._native_chain(archive, values[0], platform, selected_descriptor, root_descriptor)
                if selected_descriptor is None and (root_id != identity["id"] or actual.get("Id") != identity["id"] or root_descriptor):
                    raise ValueError()
                identity.update(v=3, size=size, dockerRef=root_id, rootDescriptor=root_descriptor, selectedDescriptor=selected_descriptor)
                atomic(proofs / (key + ".json"), identity)
                return identity
        except (ValueError, KeyError, TypeError, tarfile.TarError, OSError, RecursionError):
            raise EngineError("image_identity_unverified") from None
        finally:
            path.unlink(missing_ok=True)

    def _container_matches_image(self, container, identity):
        if container.get("Image") != identity.get("dockerRef"):
            return False
        if identity.get("proofKind") == "legacy-config":
            return identity["id"] == container.get("Image") and not container.get("ImageManifestDescriptor")
        descriptor = container.get("ImageManifestDescriptor")
        try:
            descriptor = self._descriptor(descriptor)
        except EngineError:
            return False
        selected = identity.get("selectedDescriptor", {})
        if any(descriptor.get(key) != selected.get(key) for key in ("digest", "size", "mediaType")):
            return False
        p = descriptor.get("platform")
        return not p or [p.get("os"), p.get("architecture"), p.get("variant") or ""] == [identity["os"], identity["architecture"], identity.get("variant") or ""]

    def _container_image_info(self, container, platform=None):
        """Prove the actual native root + platform manifest -> config chain, or a verified legacy config root."""
        platform = platform or self._platform()
        expected_root = container.get("Image")
        if not isinstance(expected_root, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_root):
            raise EngineError("image_identity_unverified")
        tag = container.get("Config", {}).get("Image")
        if tag is not None and not isinstance(tag, str):
            raise EngineError("image_identity_unverified")
        match = None
        for candidate in dict.fromkeys([expected_root, tag] if tag else [expected_root]):
            try:
                identity = self._image_info(candidate, platform)
            except EngineError as error:
                if error.code != "docker_operation_failed":
                    raise
                continue
            if not self._container_matches_image(container, identity):
                raise EngineError("image_identity_mismatch")
            if match and (match["id"] != identity["id"] or match.get("manifestDigest") != identity.get("manifestDigest")):
                raise EngineError("image_identity_ambiguous")
            match = identity
        if match is None:
            raise EngineError("image_identity_unverified")
        return match

    def _helper_image(self, platform=None, known_id=None):
        return self._image_info(known_id or HELPER_IMAGE, platform)

    def _source_guard(self, service):
        if service.get("sourceState") in {"fenced", "unknown", "capture_stopped"}:
            raise EngineError("source_" + service["sourceState"], unknown=service["sourceState"] == "unknown")

    def _register(self, params):
        existing = read(self._service_path(params["serviceId"]))
        if existing and existing.get("sourceState") in {"fenced", "unknown", "capture_stopped"}:
            raise EngineError("source_state_blocks_import")
        if len(list((self.state / "services").glob("*.json"))) >= 20 and not existing:
            raise EngineError("service_limit")
        binding = self.storage.binding(params["storageId"])
        project = self._project(params["projectId"])
        if project["fingerprint"] != params["fingerprint"]:
            raise EngineError("source_drift")
        if params.get("healthCheck", {}).get("service", next(iter(project["model"]["services"]))) not in project["model"]["services"]:
            raise EngineError("invalid_health_check")
        helper = self._helper_image(project["platform"])
        totals = [self._helper(helper["dockerRef"], params["serviceId"], ["inspect", "/data/payload"], source=mount) for mount in project["mounts"].values()]
        self._reserve(sum(v["bytes"] for v in totals), sum(i["size"] for i in project["images"].values()) + helper["size"], sum(t["files"] for t in totals))
        service = {"id": params["serviceId"], "projectId": params["projectId"], "fingerprint": params["fingerprint"], "storageId": params["storageId"],
                   "backupInterval": params["backupInterval"], "exclusiveWriters": True, "healthCheck": params.get("healthCheck"),
                   "sourceState": "running", "project": project, "sourceNodeId": self.node_id, "registeredAt": now()}
        if existing:
            service.update({k: existing[k] for k in ("latestBackup", "schedule") if k in existing})
        self._save_service(service)
        return {"serviceId": service["id"], "registered": True, "projectId": service["projectId"], "fingerprint": service["fingerprint"]}

    @staticmethod
    def _capture_mounts(signature):
        # Docker's Mounts array is unordered. Keep every typed identity and its multiplicity.
        if not isinstance(signature, list) or len(signature) > 100:
            raise EngineError("capture_source_changed", unknown=True)
        result = []
        for item in signature:
            if (not isinstance(item, list) or len(item) != 4 or not isinstance(item[0], str) or item[0] not in {"bind", "volume"}
                    or any(not isinstance(v, str) or not v or len(v) > 4096 or "\x00" in v for v in item[1:3])
                    or not item[2].startswith("/") or type(item[3]) is not bool
                    or (item[0] == "bind" and not item[1].startswith("/"))
                    or (item[0] == "volume" and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", item[1]))):
                raise EngineError("capture_source_changed", unknown=True)
            result.append(tuple(item))
        if len({item[2] for item in result}) != len(result):
            raise EngineError("capture_source_changed", unknown=True)
        return sorted(result)

    @classmethod
    def _capture_container_mounts(cls, container):
        mounts = container.get("Mounts")
        if not isinstance(mounts, list) or any(not isinstance(m, dict) for m in mounts):
            raise EngineError("capture_source_changed", unknown=True)
        return cls._capture_mounts([[m.get("Type"), m.get("Name") if m.get("Type") == "volume" else m.get("Source"), m.get("Destination"), m.get("RW")] for m in mounts])

    def _capture_compensation_authority(self, service, journal):
        identity = journal.get("id")
        params, obligation = journal.get("parameters"), journal.get("resume")
        project = service.get("project")
        if (not is_uuid(identity) or service.get("captureOperation") != identity or not is_uuid(service.get("id"))
                or service.get("sourceState") not in {"capture_stopped", "unknown"} or service.get("fence")
                or journal.get("action") != "compose-backup" or journal.get("status") not in {"running", "outcome_unknown"}
                or journal.get("stage") not in {"capture-intent", "source-stopped", "data-archived"}
                or journal.get("sourceResumed") is not False or (journal.get("resumeComplete") is not None and journal.get("resumeComplete") is not False)
                or any(key in journal for key in ("manifestDigest", "repositoryId", "result", "activationResult", "resumeFence"))
                or not isinstance(journal.get("requestDigest"), str) or not HEX.fullmatch(journal["requestDigest"])
                or not isinstance(params, dict) or set(params) != {"serviceId", "storageId"}
                or params["serviceId"] != service["id"] or params["storageId"] != service.get("storageId") or not is_uuid(params["storageId"])
                or not isinstance(obligation, dict) or set(obligation) != {"serviceId", "containers"} or obligation["serviceId"] != service["id"]
                or service.get("exclusiveWriters") is not True or service.get("sourceNodeId") != self.node_id
                or not isinstance(service.get("projectId"), str) or not service["projectId"] or not isinstance(project, dict)):
            raise EngineError("capture_resume_ownership_unverified", unknown=True)
        originals, prior = project.get("containers"), obligation["containers"]
        inputs, mounts = project.get("inputs"), project.get("mounts")
        if (not isinstance(originals, list) or not 1 <= len(originals) <= 100 or not isinstance(prior, list) or len(prior) > 100
                or not isinstance(inputs, dict) or not 1 <= len(inputs) <= 100 or not isinstance(mounts, dict) or len(mounts) > 100
                or any(not isinstance(path, str) or len(path) > 4096 or "\x00" in path or not Path(path).is_absolute() or not isinstance(value, str) or not HEX.fullmatch(value) for path, value in inputs.items())):
            raise EngineError("capture_resume_ownership_unverified", unknown=True)
        by_id = {}
        for item in originals:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str) or not HEX.fullmatch(item["id"]) or item["id"] in by_id
                    or not isinstance(item.get("dockerImageRef"), str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", item["dockerImageRef"])
                    or not isinstance(item.get("mounts"), list) or len(item["mounts"]) > 100):
                raise EngineError("capture_resume_ownership_unverified", unknown=True)
            signature = []
            for reference in item["mounts"]:
                if not isinstance(reference, dict) or type(reference.get("readOnly")) is not bool:
                    raise EngineError("capture_resume_ownership_unverified", unknown=True)
                mount = mounts.get(reference.get("key"))
                if not isinstance(mount, dict):
                    raise EngineError("capture_resume_ownership_unverified", unknown=True)
                signature.append([mount.get("kind"), mount.get("source"), reference.get("target"), not reference["readOnly"]])
            by_id[item["id"]] = (item["dockerImageRef"], self._capture_mounts(signature))
        seen = set()
        for item in prior:
            if not isinstance(item, dict) or set(item) != {"id", "imageId", "mountSignature"} or not isinstance(item.get("id"), str) or item["id"] not in by_id or item["id"] in seen:
                raise EngineError("capture_resume_ownership_unverified", unknown=True)
            seen.add(item["id"])
            if (item["imageId"], self._capture_mounts(item["mountSignature"])) != by_id[item["id"]]:
                raise EngineError("capture_source_changed", unknown=True)
        helpers = journal.get("helpers", [])
        if not isinstance(helpers, list) or len(helpers) > 200:
            raise EngineError("capture_resume_ownership_unverified", unknown=True)
        for item in helpers:
            if (not isinstance(item, dict) or not isinstance(item.get("name"), str)
                    or not re.fullmatch("rpo-helper-" + identity.replace("-", "")[:24] + r"-[a-f0-9]{8}", item["name"])
                    or item.get("labels") != self._owned_labels(identity, service["id"], "capture-helper")):
                raise EngineError("capture_resume_ownership_unverified", unknown=True)
        return by_id

    def _compensate_capture(self, service, journal):
        try:
            originals = self._capture_compensation_authority(service, journal)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError):
            raise EngineError("capture_resume_ownership_unverified", unknown=True) from None
        # Cleanup is repeated here because inspection must be safe independently of its caller.
        self.storage.recover()
        prior = {key: journal.get(key) for key in ("status", "stage", "error", "completedAt")}
        self._resume_capture(service, journal, originals=originals)
        journal["captureCompensation"] = {"prior": prior, "at": now()}
        journal.update(status="failed", error="capture_interrupted", stage="source-resumed", completedAt=now())
        atomic(self._journal_path(journal["id"]), journal)
        return {"status": "failed", "error": "capture_interrupted", "stage": "source-resumed"}

    def _resume_capture(self, service, journal, *, originals=None):
        if service.get("sourceState") not in ({"capture_stopped", "unknown"} if originals is not None else {"capture_stopped"}) or service.get("captureOperation") != journal["id"]:
            raise EngineError("capture_resume_ownership_unverified", unknown=True)
        self._terminate_helpers(journal)
        expected = journal.get("resume", {}).get("containers", [])
        if not isinstance(expected, list) or len(expected) > 100 or any(not isinstance(c, dict) or not isinstance(c.get("id"), str) for c in expected):
            raise EngineError("capture_source_changed", unknown=True)
        ids = [c["id"] for c in expected]
        if len(set(ids)) != len(ids):
            raise EngineError("capture_source_changed", unknown=True)
        actual = ([c for c in self._containers() if c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") == service["projectId"]]
                  if originals is not None else self._inspect(ids))
        if len(actual) != len(originals if originals is not None else ids) or {c["Id"] for c in actual} != set(originals if originals is not None else ids):
            raise EngineError("capture_source_changed", unknown=True)
        for container in actual:
            identity = next((c for c in expected if c["id"] == container["Id"]), None)
            baseline = originals[container["Id"]] if originals is not None else (identity.get("imageId"), self._capture_mounts(identity.get("mountSignature")))
            if (container.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != service["projectId"]
                    or container.get("Image") != baseline[0] or self._capture_container_mounts(container) != baseline[1]
                    or type(container.get("State", {}).get("Running")) is not bool):
                raise EngineError("capture_source_changed", unknown=True)
        for path, expected_hash in service["project"]["inputs"].items():
            if not Path(path).is_file() or Path(path).is_symlink() or digest(path) != expected_hash:
                raise EngineError("capture_source_changed", unknown=True)
        self._check_other_writers(service["project"].get("mounts", {}), {c["Id"] for c in actual})
        for container in actual:
            if container["Id"] in ids and not container["State"]["Running"]:
                self.docker("start", container["Id"])
        check = self._inspect(ids)
        if len(check) != len(ids) or {c["Id"] for c in check} != set(ids) or not all(c.get("State", {}).get("Running") is True for c in check):
            raise EngineError("source_resume_failed", unknown=True)
        service.update(sourceState="running")
        service.pop("captureOperation", None)
        self._save_service(service)
        journal.update(sourceResumed=True, resumeComplete=True)
        atomic(self._journal_path(journal["id"]), journal)

    def _measure_image_layer(self, archive, name):
        import gzip
        import zlib
        member = archive.getmember(name)
        if not member.isfile():
            raise ValueError()
        source = archive.extractfile(member)
        head = source.read(6)
        source.seek(0)
        if head.startswith(b"\x28\xb5\x2f\xfd") or head.startswith(b"BZh") or head.startswith(b"\xfd7zXZ"):
            raise EngineError("image_compression_unsupported")
        stream = gzip.GzipFile(fileobj=source) if head.startswith(b"\x1f\x8b") else source
        class Measured:
            def __init__(self):
                self.count, self.hasher = 0, hashlib.sha256()
            def read(self, count=1024 * 1024):
                block = stream.read(min(count if count >= 0 else 1024 * 1024, 1024 * 1024))
                self.count += len(block)
                if self.count > MAX_BYTES:
                    raise EngineError("image_expanded_byte_limit")
                self.hasher.update(block)
                return block
        measured = Measured()
        logical, files = 0, 0
        try:
            with tarfile.open(fileobj=measured, mode="r|") as layer:
                for entry in layer:
                    files += 1
                    logical += entry.size
                    if files > 100000 or entry.size < 0 or logical > MAX_BYTES:
                        raise EngineError("image_expanded_byte_limit")
            # Include tar padding and compressed members in the diff-id and actual load budget.
            while measured.read():
                pass
        except (tarfile.TarError, EOFError, OSError, ValueError, zlib.error):
            raise EngineError("image_layer_invalid") from None
        finally:
            if stream is not source:
                stream.close()
            source.close()
        required = measured.count + logical
        if required > MAX_BYTES:
            raise EngineError("image_expanded_byte_limit")
        return {"diffId": "sha256:" + measured.hasher.hexdigest(), "expandedBytes": measured.count, "logicalBytes": logical, "files": files, "requiredBytes": required}

    def _oci_entrypoints(self, archive, identities, measured_layer):
        if "index.json" not in archive.getnames():
            if "oci-layout" in archive.getnames():
                raise ValueError()
            return 0
        def document(name):
            member = archive.getmember(name)
            if not member.isfile() or member.size > 4 * 1024 * 1024:
                raise ValueError()
            return json.loads(archive.extractfile(member).read()), member.size
        index, metadata_bytes = document("index.json")
        if index.get("schemaVersion") != 2 or not isinstance(index.get("manifests"), list) or not 1 <= len(index["manifests"]) <= 1000:
            raise ValueError()
        aliases = {item["alias"]: identity for identity, item in identities.items()}
        platforms = {(v["os"], v["architecture"], v.get("variant") or "") for v in identities.values()}
        seen, slots, nodes = set(), {}, 0
        names = set(archive.getnames())
        def alias_of(annotations, inherited):
            if annotations is None:
                return inherited
            if not isinstance(annotations, dict):
                raise ValueError()
            full, short = annotations.get("io.containerd.image.name"), annotations.get("org.opencontainers.image.ref.name")
            def canonical_alias(value):
                if not isinstance(value, str):
                    raise ValueError()
                value = value.removeprefix("docker.io/")
                if value not in aliases:
                    raise ValueError()
                return value
            value = canonical_alias(full) if full is not None else inherited
            if short is not None:
                if short == "bundle" and value:
                    pass
                else:
                    other = canonical_alias(short)
                    if value is not None and value != other:
                        raise ValueError()
                    value = other
            if inherited is not None and value is not None and inherited != value:
                raise ValueError()
            return value
        def walk(raw_descriptor, inherited=None, ancestors=frozenset(), depth=0, top=False):
            nonlocal metadata_bytes, nodes
            descriptor = self._descriptor(raw_descriptor)
            digest_value = descriptor["digest"]
            nodes += 1
            if depth > 16 or nodes > 1000 or digest_value in ancestors:
                raise ValueError()
            alias = alias_of(raw_descriptor.get("annotations"), inherited)
            name = "blobs/sha256/" + digest_value[7:]
            p = descriptor.get("platform")
            if name not in names:
                # A platform-filtered Docker save can keep index references to absent foreign/attestation blobs.
                if not top and p and (p.get("os"), p.get("architecture"), p.get("variant") or "") not in platforms:
                    return set()
                raise ValueError()
            member = archive.getmember(name)
            if member.size != descriptor["size"]:
                raise ValueError()
            node, size = document(name)
            metadata_bytes += size
            if node.get("schemaVersion") != 2 or node.get("mediaType", descriptor.get("mediaType")) != descriptor.get("mediaType"):
                raise ValueError()
            if "manifests" in node:
                if "config" in node or "layers" in node:
                    raise ValueError()
                if descriptor.get("mediaType") not in {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"} or not isinstance(node["manifests"], list) or not node["manifests"]:
                    raise ValueError()
                found = set()
                for child in node["manifests"]:
                    found |= walk(child, alias, ancestors | {digest_value}, depth + 1)
                if not found:
                    raise ValueError()
                return found
            if descriptor.get("mediaType") not in {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}:
                raise ValueError()
            cfg = self._descriptor(node["config"])
            identity = cfg["digest"]
            if identity not in identities:
                raise ValueError()
            config_name = "blobs/sha256/" + identity[7:]
            config, config_size = document(config_name)
            metadata_bytes += config_size
            expected = identities[identity]
            actual_platform = (config["os"], config["architecture"], config.get("variant") or "")
            if cfg["size"] != config_size or actual_platform != (expected["os"], expected["architecture"], expected.get("variant") or "") or (p and actual_platform != (p.get("os"), p.get("architecture"), p.get("variant") or "")):
                raise ValueError()
            if alias is None or aliases.get(alias) != identity:
                raise ValueError()
            if alias in slots and slots[alias] != identity:
                raise ValueError()
            slots[alias] = identity
            layers, diff_ids = node.get("layers"), config.get("rootfs", {}).get("diff_ids")
            if not isinstance(layers, list) or not isinstance(diff_ids, list) or len(layers) != len(diff_ids):
                raise ValueError()
            for raw_layer, expected_diff in zip(layers, diff_ids):
                layer = self._descriptor(raw_layer)
                layer_name = "blobs/sha256/" + layer["digest"][7:]
                if archive.getmember(layer_name).size != layer["size"] or measured_layer(layer_name)["diffId"] != expected_diff:
                    raise ValueError()
            seen.add(identity)
            return {identity}
        for root in index["manifests"]:
            walk(root, top=True)
        if seen != set(identities) or set(slots) != set(aliases):
            raise ValueError()
        return metadata_bytes

    def _image_archive(self, path, identities):
        inspect_archive(path, data=False)
        try:
            with tarfile.open(path) as archive:
                member = archive.getmember("manifest.json")
                if member.size > 1024 * 1024:
                    raise ValueError()
                manifests = json.load(archive.extractfile(member))
                if not isinstance(manifests, list) or len(manifests) != len(identities) or not 1 <= len(manifests) <= 21:
                    raise ValueError()
                seen, measurements, layer_cache = set(), {}, {}
                def measured_layer(name):
                    if name not in layer_cache:
                        layer_cache[name] = self._measure_image_layer(archive, name)
                    return layer_cache[name]
                for item in manifests:
                    config_name = item["Config"]
                    config_member = archive.getmember(config_name)
                    if config_member.size > 4 * 1024 * 1024:
                        raise ValueError()
                    raw = archive.extractfile(config_member).read()
                    identity = "sha256:" + hashlib.sha256(raw).hexdigest()
                    if identity not in identities:
                        raise ValueError()
                    config = json.loads(raw)
                    expected = identities[identity]
                    if expected.get("alias") != "rolypolyops-reserved/sha256-" + identity[7:] + ":bundle":
                        raise ValueError()
                    if expected.get("proofKind") == "native-manifest":
                        proven = self._native_chain(archive, item, [expected["os"], expected["architecture"], expected.get("variant") or ""], expected.get("selectedDescriptor"), expected.get("rootDescriptor"))
                        if proven["id"] != identity or proven.get("manifestDigest") != expected.get("manifestDigest"):
                            raise ValueError()
                    if (config.get("os"), config.get("architecture"), config.get("variant") or "") != (expected["os"], expected["architecture"], expected.get("variant") or ""):
                        raise ValueError()
                    aliases = item.get("RepoTags", [])
                    if aliases != [expected["alias"]]:
                        raise ValueError()
                    layers = item.get("Layers", [])
                    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
                    if len(layers) != len(diff_ids):
                        raise ValueError()
                    required, logical, expanded, file_count = len(raw), 0, 0, 0
                    for layer, expected_diff in zip(layers, diff_ids):
                        stats = measured_layer(layer)
                        if stats["diffId"] != expected_diff:
                            raise ValueError()
                        required += stats["requiredBytes"]
                        logical += stats["logicalBytes"]
                        expanded += stats["expandedBytes"]
                        file_count += stats["files"]
                    if required > MAX_BYTES:
                        raise EngineError("image_expanded_byte_limit")
                    measurements[identity] = {"requiredBytes": required, "logicalBytes": logical, "expandedBytes": expanded, "files": file_count}
                    seen.add(identity)
                if seen != set(identities):
                    raise ValueError()
                aliases = {item["alias"] for item in identities.values()}
                allowed_names = aliases | {"docker.io/" + name for name in aliases}
                annotation_nodes = 0
                def check_annotations(node, depth=0):
                    nonlocal annotation_nodes
                    annotation_nodes += 1
                    if depth > 64 or annotation_nodes > 100000:
                        raise ValueError()
                    if isinstance(node, dict):
                        annotations = node.get("annotations", {})
                        if isinstance(annotations, dict):
                            full = annotations.get("io.containerd.image.name")
                            short = annotations.get("org.opencontainers.image.ref.name")
                            if full is not None and full not in allowed_names:
                                raise ValueError()
                            if short is not None and short not in allowed_names and not (short == "bundle" and full in allowed_names):
                                raise ValueError()
                        for child in node.values():
                            check_annotations(child, depth + 1)
                    elif isinstance(node, list):
                        for child in node:
                            check_annotations(child, depth + 1)
                if "repositories" in archive.getnames():
                    member = archive.getmember("repositories")
                    if member.size > 1024 * 1024:
                        raise ValueError()
                    repositories = json.load(archive.extractfile(member))
                    if not isinstance(repositories, dict) or any(repo + ":" + tag not in aliases for repo, tags in repositories.items() for tag in tags):
                        raise ValueError()
                for member in archive.getmembers():
                    if member.isdir():
                        continue
                    name = member.name
                    if member.size <= 4 * 1024 * 1024 and (name == "index.json" or name.startswith("blobs/sha256/")):
                        try:
                            document = json.load(archive.extractfile(member))
                        except (ValueError, UnicodeError):
                            document = None
                        if document is not None:
                            check_annotations(document)
                    if re.fullmatch(r"blobs/sha256/[a-f0-9]{64}", name):
                        h = hashlib.sha256()
                        stream = archive.extractfile(member)
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            h.update(block)
                        if h.hexdigest() != name.rsplit("/", 1)[-1]:
                            raise ValueError()
                    elif not (name in {"manifest.json", "repositories", "index.json", "oci-layout"}
                              or re.fullmatch(r"[a-f0-9]{64}\.json", name)
                              or re.fullmatch(r"[a-f0-9]{64}/(?:layer.tar|json|VERSION)", name)):
                        raise ValueError()
                metadata_bytes = self._oci_entrypoints(archive, identities, measured_layer)
                for measurement in measurements.values():
                    measurement["requiredBytes"] += metadata_bytes
                if sum(value["requiredBytes"] for value in measurements.values()) > MAX_BYTES:
                    raise EngineError("image_expanded_byte_limit")
                return measurements
        except (KeyError, ValueError, TypeError, tarfile.TarError, OSError, RecursionError):
            raise EngineError("image_identity_unverified") from None

    def _normalize_export_index(self, path, identities):
        """Normalize only a fresh owned export; general/import validation remains strict."""
        import io
        import stat
        path = Path(path)
        operation = self.current.get("id") if isinstance(self.current, dict) else None
        if (not is_uuid(operation) or self.current.get("action") != "compose-backup"
                or path != self.state / "stages" / operation / "images.tar"):
            raise EngineError("image_export_ownership_unverified")
        for directory in (self.state, self.state / "stages", path.parent):
            value = directory.lstat()
            if not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid() or value.st_mode & 0o077:
                raise EngineError("image_export_ownership_unverified")
        original = path.lstat()
        if not stat.S_ISREG(original.st_mode) or original.st_uid != os.geteuid() or original.st_mode & 0o022 or original.st_nlink != 1:
            raise EngineError("image_export_ownership_unverified")
        inspect_archive(path, data=False)
        temporary = None
        try:
            with tarfile.open(path, "r:*") as archive:
                names = archive.getnames()
                if "index.json" not in names:
                    return self._image_archive(path, identities)
                visits = 0
                def document(name):
                    member = archive.getmember(name)
                    if not member.isfile() or member.size > 4 * 1024 * 1024:
                        raise ValueError()
                    raw = archive.extractfile(member).read()
                    return json.loads(raw), raw
                def blob(value):
                    nonlocal visits
                    visits += 1
                    if visits > 1000:
                        raise ValueError()
                    descriptor = self._descriptor(value)
                    node, raw = document("blobs/sha256/" + descriptor["digest"][7:])
                    if len(raw) != descriptor["size"] or "sha256:" + hashlib.sha256(raw).hexdigest() != descriptor["digest"]:
                        raise ValueError()
                    return node
                index, _ = document("index.json")
                roots = index.get("manifests")
                if index.get("schemaVersion") != 2 or not isinstance(roots, list) or not 1 <= len(roots) <= 1000:
                    raise ValueError()
                aliases = {image["alias"] for image in identities.values()}
                selected = {image["manifestDigest"] for image in identities.values() if image.get("proofKind") == "native-manifest" and image.get("selectedDescriptor", {}).get("digest") == image.get("manifestDigest")}
                runtime, extra = [], []
                for root in roots:
                    descriptor = self._descriptor(root)
                    annotations = root.get("annotations", {})
                    if not isinstance(annotations, dict):
                        raise ValueError()
                    alias = annotations.get("io.containerd.image.name")
                    alias = alias.removeprefix("docker.io/") if isinstance(alias, str) else alias
                    if descriptor["digest"] in selected or alias in aliases:
                        runtime.append(root)
                    else:
                        extra.append(root)
                if not extra:
                    return self._image_archive(path, identities)
                runtime_targets = {root["digest"] for root in runtime} & selected
                if not runtime_targets:
                    raise ValueError()
                visits = len(roots)
                for root in extra:
                    if root.get("mediaType") != "application/vnd.oci.image.manifest.v1+json":
                        raise ValueError()
                    annotations = root.get("annotations", {})
                    if set(annotations) - {"vnd.docker.reference.type", "vnd.docker.reference.digest", "io.containerd.manifest.subject"}:
                        raise ValueError()
                    platform = root.get("platform")
                    if platform is not None and (not isinstance(platform, dict) or platform.get("os") != "unknown" or platform.get("architecture") != "unknown" or platform.get("variant") not in {None, ""}):
                        raise ValueError()
                    native = blob(root)
                    if (native.get("schemaVersion") != 2 or native.get("mediaType") != "application/vnd.oci.image.manifest.v1+json"
                            or "artifactType" in native or "subject" in native):
                        raise ValueError()
                    config_descriptor = native["config"]
                    if config_descriptor.get("mediaType") != "application/vnd.oci.image.config.v1+json":
                        raise ValueError()
                    config = blob(config_descriptor)
                    if (set(config) != {"architecture", "config", "os", "rootfs"} or config.get("os") != "unknown"
                            or config.get("architecture") != "unknown" or config.get("config") != {}):
                        raise ValueError()
                    layers, targets = native.get("layers"), set()
                    if not isinstance(layers, list) or not 1 <= len(layers) <= 1000:
                        raise ValueError()
                    for layer in layers:
                        if layer.get("mediaType") != "application/vnd.in-toto+json":
                            raise ValueError()
                        statement = blob(layer)
                        if (not isinstance(statement, dict) or statement.get("_type") not in {"https://in-toto.io/Statement/v0.1", "https://in-toto.io/Statement/v1"}
                                or not isinstance(statement.get("predicateType"), str) or not statement["predicateType"]
                                or not isinstance(statement.get("predicate"), dict)
                                or statement["predicateType"] != layer.get("annotations", {}).get("in-toto.io/predicate-type")):
                            raise ValueError()
                        subjects = statement.get("subject")
                        if not isinstance(subjects, list) or not 1 <= len(subjects) <= 1000:
                            raise ValueError()
                        for subject in subjects:
                            if not isinstance(subject, dict) or not isinstance(subject.get("name"), str) or not subject["name"] or len(subject["name"]) > 4096:
                                raise ValueError()
                            digest_map = subject.get("digest")
                            if (not isinstance(digest_map, dict) or set(digest_map) != {"sha256"}
                                    or not isinstance(digest_map["sha256"], str) or not HEX.fullmatch(digest_map["sha256"])):
                                raise ValueError()
                            targets.add("sha256:" + digest_map["sha256"])
                    rootfs = config.get("rootfs")
                    if (not isinstance(rootfs, dict) or rootfs.get("type") != "layers" or rootfs.get("diff_ids") != [layer["digest"] for layer in layers]
                            or len(targets) != 1 or not targets <= runtime_targets):
                        raise ValueError()
                    if (annotations.get("vnd.docker.reference.type", "attestation-manifest") != "attestation-manifest"
                            or annotations.get("vnd.docker.reference.digest", next(iter(targets))) != next(iter(targets))
                            or annotations.get("io.containerd.manifest.subject", next(iter(targets))) != next(iter(targets))):
                        raise ValueError()
                index["manifests"] = runtime
                replacement = canonical(index)
                if len(replacement) > 4 * 1024 * 1024 or shutil.disk_usage(path.parent).free < original.st_size + 4 * 1024 * 1024 + tarfile.RECORDSIZE:
                    raise EngineError("insufficient_staging_space")
                temporary = path.with_name(".images-normalized-" + uuid.uuid4().hex + ".tar")
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    os.fchmod(stream.fileno(), 0o600)
                    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as output:
                        for member in archive.getmembers():
                            copied = copy.copy(member)
                            copied.pax_headers = dict(member.pax_headers)
                            if member.name == "index.json":
                                copied.size = len(replacement)
                                if "size" in copied.pax_headers:
                                    copied.pax_headers["size"] = str(copied.size)
                                output.addfile(copied, io.BytesIO(replacement))
                            else:
                                output.addfile(copied, archive.extractfile(member) if member.isfile() else None)
            measured = self._image_archive(temporary, identities)
            current = path.lstat()
            if (current.st_ino, current.st_dev, current.st_size, current.st_mtime_ns) != (original.st_ino, original.st_dev, original.st_size, original.st_mtime_ns):
                raise EngineError("image_export_ownership_unverified")
            descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
            temporary = None
            try:
                descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            except OSError:
                # Publication occurred, but durability is unverified. Caller must not upload.
                raise EngineError("image_export_commit_unverified") from None
            return measured
        except (KeyError, ValueError, TypeError, AttributeError, tarfile.TarError, OSError, RecursionError):
            raise EngineError("image_identity_unverified") from None
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def _export_images(self, stage, images):
        descriptors = copy.deepcopy(images)
        for identity, item in descriptors.items():
            alias = "rolypolyops-reserved/sha256-" + identity[7:] + ":bundle"
            item["alias"] = alias
            # Never replace an existing tag with another config identity.
            matching = self.docker("image", "ls", "--quiet", "--no-trunc", alias).decode().split()
            if matching and self._image_info(alias, [item["os"], item["architecture"], item.get("variant", "")])["id"] != identity:
                raise EngineError("reserved_image_alias_occupied")
            self.docker("image", "tag", item.get("dockerRef", identity), alias)
        image_path = stage / "images.tar"
        platform = "/".join(x for x in (next(iter(descriptors.values()))["os"], next(iter(descriptors.values()))["architecture"], next(iter(descriptors.values())).get("variant", "")) if x)
        args = ["image", "save", "--platform", platform, "--output", str(image_path), *[item["alias"] for item in descriptors.values()]]
        self.docker(*args, timeout=3600)
        measured = self._normalize_export_index(image_path, descriptors)
        for identity, item in descriptors.items():
            item["size"] = max(item.get("size", 0), measured[identity]["requiredBytes"])
            item["measuredImage"] = measured[identity]
        return descriptors

    @staticmethod
    def _capture_observations(containers, expected):
        if len(containers) != len(expected) or {c.get("Id") for c in containers} != expected:
            raise EngineError("capture_source_changed")
        result = {}
        for container in containers:
            state = container.get("State", {})
            started, count, running = state.get("StartedAt"), container.get("RestartCount"), state.get("Running")
            if (not isinstance(started, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z", started)
                    or type(count) is not int or count < 0 or type(running) is not bool):
                raise EngineError("capture_source_changed")
            try:
                dt.datetime.fromisoformat(started[:-1] + "+00:00")
            except ValueError:
                raise EngineError("capture_source_changed") from None
            result[container["Id"]] = {"startedAt": started, "restartCount": count, "running": running}
        return result

    @staticmethod
    def _cleanup_pending(journal):
        if "payloadCleanup" not in journal:
            return False
        value = journal["payloadCleanup"]
        try:
            files = value["files"]
            names = [item["path"] for item in files]
            return (type(value.get("version")) is not int or value["version"] != 1 or value.get("complete") is not True
                    or value.get("operationId") != journal.get("id") or value.get("serviceId") != journal["parameters"]["serviceId"]
                    or value.get("action") != journal.get("action") or not HEX.fullmatch(value["manifestDigest"])
                    or (value.get("action") == "compose-backup" and value["manifestDigest"] != journal.get("manifestDigest"))
                    or not isinstance(files, list) or not 2 <= len(files) <= 202 or len(set(names)) != len(names)
                    or not {"bundle.tar", "images.tar"} <= set(names)
                    or any(not re.fullmatch(r"bundle\.tar|images\.tar|data-[0-9]{1,3}\.tar|mount-[0-9]{1,3}/archive\.tar", name) for name in names)
                    or any(set(item) != {"path", "bytes", "sha256"} or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_BYTES * 2
                           or not HEX.fullmatch(item["sha256"]) for item in files))
        except (ValueError, KeyError, TypeError, AttributeError):
            return True

    def _cleanup_payloads(self, journal):
        """Remove only redundant, proven-success payload files; never application data."""
        import stat
        try:
            def require(value):
                if not value:
                    raise EngineError("payload_cleanup_unverified", unknown=True)
            require(getattr(self._local, "engine_locked", False))
            identity, action, params = journal.get("id"), journal.get("action"), journal.get("parameters")
            require(is_uuid(identity) and action in {"compose-backup", "compose-restore"} and isinstance(params, dict)
                    and is_uuid(params.get("serviceId")) and is_uuid(params.get("storageId"))
                    and journal.get("status") in {"running", "outcome_unknown", "succeeded"})
            uid, directory = os.geteuid(), self.state / "stages" / identity
            def trusted(path, *, folder=False):
                value = path.lstat()
                require((stat.S_ISDIR(value.st_mode) if folder else stat.S_ISREG(value.st_mode))
                        and value.st_uid in ({0, uid} if folder else {uid}) and not value.st_mode & 0o022
                        and (folder or value.st_nlink == 1))
                return value
            helpers = journal.get("helpers", [])
            require(isinstance(helpers, list) and len(helpers) <= 200)
            for helper in helpers:
                purpose = helper.get("labels", {}).get(OWNER + ".purpose")
                require(purpose in {"capture-helper", "restore-helper", "health-helper"}
                        and helper.get("labels") == self._owned_labels(identity, params["serviceId"], purpose))
            for parent in reversed(directory.parents):
                trusted(parent, folder=True)
            trusted(directory, folder=True)
            trusted(self._journal_path(identity).parent, folder=True)
            trusted(self._journal_path(identity))
            require(self._inspection_journal(identity) == journal)
            request_digest = journal.get("requestDigest")
            if request_digest is None and "requestDigest" not in journal:
                require(journal.get("origin") == "activation" and is_uuid(journal.get("parentId")))
                trusted(self._journal_path(journal["parentId"]))
                parent = self._inspection_journal(journal["parentId"])
                require(parent.get("action") == "compose-activate" and parent.get("parameters", {}).get("serviceId") == params["serviceId"])
            else:
                require(isinstance(request_digest, str) and HEX.fullmatch(request_digest))
            manifest_path = directory / "manifest.json"
            require(trusted(manifest_path).st_size <= 16 * 1024 * 1024)
            manifest = read(manifest_path)
            manifest_digest = digest(manifest_path)
            service_id = params["serviceId"]
            require(manifest.get("format") == "rolypolyops-compose-v1" and manifest.get("serviceId") == service_id
                    and is_uuid(manifest.get("operationId")))
            self.storage.recover()
            binding = self.storage.binding(params["storageId"])
            require(binding["repositoryId"] == manifest.get("repositoryId"))
            protected = set()
            if action == "compose-backup":
                require(set(params) == {"serviceId", "storageId"} and manifest["operationId"] == identity
                        and journal.get("sourceResumed") is True and journal.get("manifestDigest") == manifest_digest
                        and journal.get("repositoryId") == manifest["repositoryId"])
                trusted(self._service_path(service_id).parent, folder=True)
                trusted(self._service_path(service_id))
                service = self._service(service_id)
                latest = service.get("latestBackup", {})
                require(service.get("sourceState") == "running" and service.get("storageId") == params["storageId"]
                        and service.get("sourceNodeId") == self.node_id and service.get("fingerprint") == manifest.get("sourceFingerprint")
                        and latest.get("serviceId") == service_id and latest.get("repositoryId") == manifest["repositoryId"]
                        and latest.get("manifestDigest") == manifest_digest and latest.get("sourceResumed") is True
                        and latest.get("sourceFingerprint") == manifest["sourceFingerprint"])
                points = self._snapshots(binding, service_id, operation=identity)
                require(len([point for point in points if point.get("id") == latest.get("snapshot") and point.get("operationId") == identity
                             and point.get("manifestDigest") == manifest_digest and point.get("sourceFingerprint") == manifest["sourceFingerprint"]]) == 1)
                protected = {Path(path) for path in service["project"]["inputs"]}
            else:
                require(set(params) == {"serviceId", "storageId", "snapshotId"} and journal.get("restoreId") == identity)
                trusted(self._restore_path(identity).parent, folder=True)
                trusted(self._restore_path(identity))
                record = self._restore(identity, service_id)
                require(record.get("id") == identity and record.get("state") == "isolated_ready" and record.get("directory") == str(directory)
                        and record.get("manifestDigest") == manifest_digest and record.get("repositoryId") == manifest["repositoryId"]
                        and record.get("storageId") == params["storageId"] and record.get("snapshot") == params["snapshotId"]
                        and record.get("sourceFingerprint") == manifest.get("sourceFingerprint"))
                trusted(directory / "runtime.json")
                require(digest(directory / "runtime.json") == record.get("runtimeDigest"))
                current = self._runtime_checks(record, manifest)
                require({name: container["Id"] for name, container in current.items()} == record.get("containerIds"))
                for mapping in record.get("mappings", {}).values():
                    if mapping.get("kind") == "bind":
                        path = Path(mapping["source"])
                        relative = path.relative_to(directory)
                        require(len(relative.parts) >= 3 and re.fullmatch(r"mount-[0-9]{1,3}", relative.parts[0])
                                and relative.parts[1:3] == ("extracted", "payload") and ".." not in relative.parts)
                        protected.add(path)
            archives = manifest.get("archives")
            require(isinstance(archives, list) and len(archives) <= 100 and isinstance(manifest.get("imagesSha256"), str) and HEX.fullmatch(manifest["imagesSha256"]))
            hashes = {"bundle.tar": None, "images.tar": manifest["imagesSha256"]}
            for index, item in enumerate(archives):
                name = item.get("filename")
                require(isinstance(name, str) and re.fullmatch(r"data-[0-9]{1,3}\.tar", name) and name not in hashes
                        and isinstance(item.get("sha256"), str) and HEX.fullmatch(item["sha256"]))
                hashes[name] = item["sha256"]
                if action == "compose-restore":
                    hashes["mount-" + str(index) + "/archive.tar"] = item["sha256"]
            for name in hashes:
                path = directory / name
                trusted(path.parent, folder=True)
                require(all(path != source and path not in source.parents for source in protected))
            self.storage.recover()
            self._terminate_helpers(journal)
            self._check_other_writers({name: {"kind": "bind", "source": str(directory / name), "writerPath": str(directory / name)} for name in hashes}, set())
            def fingerprint(path):
                value = trusted(path)
                require(value.st_size <= MAX_BYTES * 2)
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    actual = os.fstat(descriptor)
                    require((actual.st_dev, actual.st_ino, actual.st_size) == (value.st_dev, value.st_ino, value.st_size))
                    h = hashlib.sha256()
                    with os.fdopen(descriptor, "rb", closefd=False) as stream:
                        for block in iter(lambda: stream.read(1024 * 1024), b""):
                            h.update(block)
                    after = os.fstat(descriptor)
                    require((after.st_size, after.st_mtime_ns) == (value.st_size, value.st_mtime_ns))
                    return {"path": str(path.relative_to(directory)), "bytes": value.st_size, "sha256": h.hexdigest()}
                finally:
                    os.close(descriptor)
            intent = journal.get("payloadCleanup")
            if "payloadCleanup" in journal:
                require(isinstance(intent, dict) and type(intent.get("version")) is int and intent["version"] == 1
                        and intent.get("operationId") == identity and intent.get("serviceId") == service_id and intent.get("action") == action
                        and intent.get("manifestDigest") == manifest_digest and type(intent.get("complete")) is bool
                        and isinstance(intent.get("files"), list) and len(intent["files"]) == len(hashes))
                files = {}
                for item in intent["files"]:
                    require(isinstance(item, dict) and set(item) == {"path", "bytes", "sha256"} and isinstance(item["path"], str)
                            and item["path"] in hashes and item["path"] not in files and type(item["bytes"]) is int and 0 <= item["bytes"] <= MAX_BYTES * 2
                            and isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"])
                            and (hashes[item["path"]] is None or item["sha256"] == hashes[item["path"]]))
                    files[item["path"]] = item
                require(set(files) == set(hashes) and sum(item["bytes"] for item in files.values()) <= MAX_BYTES * 4)
            else:
                files = {name: fingerprint(directory / name) for name in hashes}
                require(all(expected is None or files[name]["sha256"] == expected for name, expected in hashes.items()))
            # Independently bind the remaining bundle to the kept manifest, without extraction.
            bundle = directory / "bundle.tar"
            if bundle.exists() or bundle.is_symlink():
                trusted(bundle)
                package = inspect_archive(bundle, data=False)
                entries = {item["path"]: item for item in package["entries"]}
                expected = {name: value for name, value in hashes.items() if "/" not in name and name != "bundle.tar"}
                expected["manifest.json"] = manifest_digest
                require(set(entries) == set(expected) and all(entries[name]["kind"] == "file" and entries[name]["sha256"] == value for name, value in expected.items()))
            verified = []
            for name, expected in files.items():
                path = directory / name
                try:
                    actual = fingerprint(path)
                except FileNotFoundError:
                    require(intent is not None)
                    continue
                require(actual == expected and (intent is None or intent["complete"] is False))
                verified.append(path)
            if intent is None:
                intent = {"version": 1, "operationId": identity, "serviceId": service_id, "action": action, "manifestDigest": manifest_digest,
                          "files": [files[name] for name in sorted(files)], "complete": False, "createdAt": now()}
                journal["payloadCleanup"] = intent
                atomic(self._journal_path(identity), journal)
            if intent["complete"]:
                return
            if action == "compose-restore":
                # Hashing can outlive the initial runtime observation; recheck before unlinking.
                self._runtime_checks(record, manifest)
            for path in verified:
                require(fingerprint(path) == files[str(path.relative_to(directory))])
                path.unlink()
            for parent in sorted({(directory / name).parent for name in hashes}):
                descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            intent.update(complete=True, completedAt=now())
            atomic(self._journal_path(identity), journal)
        except (EngineError, StorageError, ArchiveError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, StopIteration, RecursionError):
            raise EngineError("payload_cleanup_unverified", unknown=True) from None

    def _backup(self, params):
        service = self._service(params["serviceId"])
        self._source_guard(service)
        if service["storageId"] != params["storageId"]:
            raise EngineError("service_storage_mismatch")
        binding = self.storage.binding(service["storageId"])
        self.storage.preflight()
        project = self._project(service["projectId"], owned_service=service["id"] if service.get("adopted") else None)
        if project["fingerprint"] != service["fingerprint"]:
            raise EngineError("source_drift")
        helper = self._helper_image(project["platform"], service.get("helperId"))
        totals = [self._helper(helper["dockerRef"], service["id"], ["inspect", "/data/payload"], source=m) for m in project["mounts"].values()]
        reserve = self._reserve(sum(t["bytes"] for t in totals), sum(i["size"] for i in project["images"].values()) + helper["size"], sum(t["files"] for t in totals))
        op = self.current["id"]
        stage = self.state / "stages" / op
        stage.mkdir(mode=0o700)
        actual = self._inspect([c["id"] for c in project["containers"]])
        quiescence = self._capture_observations(actual, {c["id"] for c in project["containers"]})
        stopped = [{"id": c["Id"], "imageId": c["Image"], "mountSignature": [list(item) for item in self._capture_container_mounts(c)]} for c in actual if c.get("State", {}).get("Running")]
        self._journal(stage="capture-intent", reserve=reserve, resume={"serviceId": service["id"], "containers": stopped}, sourceResumed=False)
        service.update(sourceState="capture_stopped", captureOperation=op)
        self._save_service(service)
        archives = []
        try:
            if stopped:
                self.docker("stop", "--time", "60", *[c["id"] for c in stopped], timeout=120)
            if any(c.get("State", {}).get("Running") for c in self._inspect([c["id"] for c in stopped])):
                raise EngineError("source_stop_failed")
            self._journal(stage="source-stopped")
            for index, (key, mount) in enumerate(sorted(project["mounts"].items())):
                filename = "data-" + str(index) + ".tar"
                self._helper(helper["dockerRef"], service["id"], ["pack", "/data/payload", "/stage/" + filename], source=mount, stage=stage)
                metadata = inspect_archive(stage / filename)
                archives.append({"key": key, "filename": filename, "kind": mount["kind"], "file": mount["file"], "sha256": metadata["sha256"], "files": metadata["files"], "bytes": metadata["bytes"], "metadataDigest": hashlib.sha256(canonical(metadata["entries"])).hexdigest()})
            final_containers = [c for c in self._containers() if c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") == service["projectId"]]
            final = self._capture_observations(final_containers, set(quiescence))
            if any(value["running"] or value["startedAt"] != quiescence[identity]["startedAt"] or value["restartCount"] != quiescence[identity]["restartCount"] for identity, value in final.items()):
                raise EngineError("capture_source_restarted")
            self._journal(stage="data-archived")
        finally:
            # Termination is positively proven even when copying or stop failed.
            self._resume_capture(service, self.current)
        self._journal(stage="source-resumed")
        images = dict(project["images"])
        images[helper["id"]] = helper
        image_descriptors = self._export_images(stage, images)
        self._reserve(sum(a["bytes"] for a in archives), sum(i["size"] for i in image_descriptors.values()), sum(a["files"] for a in archives) + sum(i["measuredImage"]["files"] for i in image_descriptors.values()))
        runtime = copy.deepcopy(project["model"])
        for name, item in runtime["services"].items():
            identity = next(c["imageId"] for c in project["containers"] if c["service"] == name)
            item["image"] = image_descriptors[identity]["alias"]
            item.pop("build", None)
            item.pop("env_file", None)
        manifest = {"format": "rolypolyops-compose-v1", "serviceId": service["id"], "repositoryId": binding["repositoryId"], "operationId": op,
                    "sourceFingerprint": service["fingerprint"], "capturedAt": now(), "platform": project["platform"], "runtime": runtime,
                    "runtimeDigest": hashlib.sha256(canonical(runtime)).hexdigest(), "containers": project["containers"], "archives": archives,
                    "images": image_descriptors, "imagesSha256": digest(stage / "images.tar"), "helperId": helper["id"],
                    "healthCheck": service.get("healthCheck"), "backupInterval": service["backupInterval"]}
        if len(canonical(manifest)) + 1 > 16 * 1024 * 1024:
            raise EngineError("bundle_manifest_limit")
        atomic(stage / "manifest.json", manifest)
        manifest_digest = digest(stage / "manifest.json")
        self._journal(stage="repository-write-intent", manifestDigest=manifest_digest, repositoryId=binding["repositoryId"])
        tags = ["rolypolyops-compose", "service:" + service["id"], "manifest:" + manifest_digest, "source:" + service["fingerprint"], "operation:" + op]
        args = ["backup", "--json", "--host", self.node_id]
        for tag in tags:
            args += ["--tag", tag]
        bundle = stage / "bundle.tar"
        with tarfile.open(bundle, "w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(stage.iterdir()):
                if path != bundle:
                    archive.add(path, arcname=path.name, recursive=False)
        inspect_archive(bundle, data=False)
        raw = self.storage.run(binding, args + ["--stdin", "--stdin-filename", "bundle.tar"], input_file=bundle)
        snapshot = None
        for line in raw.splitlines():
            try:
                value = json.loads(line)
                if value.get("message_type") == "summary":
                    snapshot = value.get("snapshot_id")
            except (ValueError, AttributeError):
                continue
        if not isinstance(snapshot, str) or not HEX.fullmatch(snapshot):
            raise EngineError("backup_snapshot_unverified", unknown=True)
        # Verify exact repository/tag-bound snapshot before returning a green result.
        points = self._snapshots(binding, service["id"], operation=op)
        if not any(point["id"] == snapshot and point["manifestDigest"] == manifest_digest for point in points):
            raise EngineError("backup_snapshot_unverified", unknown=True)
        result = {"serviceId": service["id"], "repositoryId": binding["repositoryId"], "snapshot": snapshot, "manifestDigest": manifest_digest,
                  "sourceFingerprint": service["fingerprint"], "sourceResumed": True, "at": now(),
                  "checks": ["source-stopped", "data-archived", "images-saved", "source-resumed", "repository-written"]}
        service["latestBackup"] = result
        if service.get("setupState") == "active_unprotected":
            service["setupState"] = "restore_required"
        self._save_service(service)
        self._cleanup_payloads(self.current)
        return result

    def _snapshots(self, binding, service_id, operation=None):
        args = ["snapshots", "--json", "--tag", "rolypolyops-compose,service:" + service_id + (",operation:" + operation if operation else "")]
        try:
            remaining = 60
            if getattr(self._local, "observation_deadline", None) is not None:
                remaining = min(remaining, self._local.observation_deadline - time.monotonic())
                if remaining <= 0:
                    raise EngineError("observation_deadline")
            values = json.loads(self.storage.run(binding, args, timeout=remaining))
        except ValueError:
            raise EngineError("snapshot_inventory_invalid") from None
        if not isinstance(values, list) or len(values) > 10000:
            raise EngineError("snapshot_inventory_limit")
        points = []
        for value in values[-100:]:
            tags = value.get("tags", [])
            def tag(prefix):
                found = [x[len(prefix):] for x in tags if isinstance(x, str) and x.startswith(prefix)]
                return found[0] if len(found) == 1 else None
            manifest, source = tag("manifest:"), tag("source:")
            if (HEX.fullmatch(value.get("id", "")) and HEX.fullmatch(manifest or "") and HEX.fullmatch(source or "")
                    and "service:" + service_id in tags and "rolypolyops-compose" in tags):
                points.append({"id": value["id"], "time": value.get("time"), "serviceId": service_id, "repositoryId": binding["repositoryId"], "manifestDigest": manifest, "sourceFingerprint": source, "operationId": tag("operation:")})
        return points

    def _bundle_image_bindings(self, manifest):
        services, containers, images = manifest["runtime"]["services"], manifest["containers"], manifest["images"]
        if not isinstance(images, dict) or not 1 <= len(images) <= 21 or not isinstance(containers, list) or len(containers) != len(services) or manifest.get("helperId") not in images:
            raise EngineError("compose_image_binding_invalid")
        seen, ids = set(), set()
        for identity, image in images.items():
            if (not isinstance(identity, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", identity) or not isinstance(image, dict)
                    or image.get("id") != identity or image.get("alias") != "rolypolyops-reserved/sha256-" + identity[7:] + ":bundle"
                    or [image.get("os"), image.get("architecture"), image.get("variant") or ""] != manifest.get("platform")):
                raise EngineError("compose_image_binding_invalid")
        for container in containers:
            if not isinstance(container, dict) or container.get("service") not in services or container["service"] in seen or not isinstance(container.get("id"), str) or not 1 <= len(container["id"]) <= 128 or container["id"] in ids:
                raise EngineError("compose_image_binding_invalid")
            seen.add(container["service"])
            ids.add(container["id"])
            image = images.get(container.get("imageId"))
            if image is None or services[container["service"]].get("image") != image["alias"]:
                raise EngineError("compose_image_binding_invalid")
        if seen != set(services):
            raise EngineError("compose_image_binding_invalid")

    def _bundle(self, path, directory, *, service_id, repository_id, point):
        package = inspect_archive(path, data=False)
        if any(e["kind"] != "file" or "/" in e["path"] for e in package["entries"]):
            raise EngineError("bundle_structure_invalid")
        if shutil.disk_usage(directory).free < package["bytes"] + 512 * 1024 ** 2:
            raise EngineError("insufficient_staging_space")
        try:
            with tarfile.open(path) as archive:
                entry = archive.getmember("manifest.json")
                if entry.size > 16 * 1024 * 1024:
                    raise ValueError()
                raw = archive.extractfile(entry).read()
                if hashlib.sha256(raw).hexdigest() != point["manifestDigest"]:
                    raise EngineError("manifest_digest_mismatch")
                manifest = json.loads(raw)
                if (manifest.get("format") != "rolypolyops-compose-v1" or manifest.get("serviceId") != service_id
                        or manifest.get("repositoryId") != repository_id or manifest.get("sourceFingerprint") != point["sourceFingerprint"]
                        or not is_uuid(manifest.get("operationId")) or manifest.get("operationId") != point.get("operationId")):
                    raise EngineError("bundle_scope_mismatch")
                self._validate_model(manifest["runtime"], owned=True)
                if hashlib.sha256(canonical(manifest["runtime"])).hexdigest() != manifest["runtimeDigest"]:
                    raise EngineError("runtime_digest_mismatch")
                self._bundle_image_bindings(manifest)
                files = {e["path"] for e in package["entries"]}
                wanted = {"manifest.json", "images.tar"} | {a["filename"] for a in manifest["archives"]}
                if files != wanted or len(manifest["archives"]) > 100 or len(manifest["images"]) > 21:
                    raise ValueError()
                for name in sorted(wanted):
                    if not re.fullmatch(r"(?:manifest\.json|images\.tar|data-[0-9]{1,3}\.tar)", name):
                        raise ValueError()
                    target = directory / name
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        shutil.copyfileobj(archive.extractfile(name), stream, 1024 * 1024)
                        stream.flush()
                        os.fsync(stream.fileno())
        except (tarfile.TarError, ValueError, KeyError, TypeError, OSError):
            raise EngineError("bundle_structure_invalid") from None
        total = 0
        for item in manifest["archives"]:
            metadata = inspect_archive(directory / item["filename"])
            if (metadata["sha256"] != item["sha256"] or metadata["files"] != item["files"] or metadata["bytes"] != item["bytes"]
                    or hashlib.sha256(canonical(metadata["entries"])).hexdigest() != item["metadataDigest"]):
                raise EngineError("bundle_data_mismatch")
            total += metadata["bytes"]
            if total > MAX_BYTES:
                raise EngineError("archive_byte_limit")
        if digest(directory / "images.tar") != manifest["imagesSha256"]:
            raise EngineError("bundle_image_mismatch")
        measured = self._image_archive(directory / "images.tar", manifest["images"])
        for identity, required in measured.items():
            declared = manifest["images"][identity].get("size")
            if type(declared) is not int or declared < required["requiredBytes"]:
                raise EngineError("bundle_image_budget_mismatch")
        if total + sum(i["requiredBytes"] for i in measured.values()) > MAX_BYTES:
            raise EngineError("image_expanded_byte_limit")
        manifest["measuredImages"] = measured
        return manifest

    def _platform(self):
        try:
            server = json.loads(self.docker("version", "--format", "{{json .Server}}"))
            return [server["Os"], server["Arch"], server.get("Variant") or ""]
        except (ValueError, KeyError, TypeError):
            raise EngineError("host_platform_unverified") from None

    def _load_images(self, directory, manifest):
        if manifest["platform"] != self._platform():
            raise EngineError("image_platform_mismatch")
        for identity, item in manifest["images"].items():
            if item.get("id") != identity or item.get("alias") != "rolypolyops-reserved/sha256-" + identity.removeprefix("sha256:") + ":bundle":
                raise EngineError("image_identity_unverified")
            occupied = self.docker("image", "ls", "--quiet", "--no-trunc", item["alias"]).decode().split()
            if occupied and self._image_info(item["alias"], manifest["platform"])["id"] != identity:
                raise EngineError("reserved_image_alias_occupied")
        self.docker("image", "load", "--platform", "/".join(x for x in manifest["platform"] if x), "--input", str(directory / "images.tar"), timeout=3600)
        for identity, item in manifest["images"].items():
            actual = self._image_info(item["alias"], manifest["platform"])
            if (actual["id"], actual["os"], actual["architecture"], actual["variant"]) != (identity, item["os"], item["architecture"], item.get("variant", "")):
                raise EngineError("image_identity_unverified")

    def _new_resource(self, record, kind, name, labels, *, options=None):
        resources = record.setdefault("resources", [])
        resources.append({"kind": kind, "name": name, "labels": labels, "created": False})
        atomic(self._restore_path(record["id"]), record)
        # Inspect exact namespaces first. No adoption of existing resources even if labels look plausible.
        output = self.docker(kind, "ls", "--format", "{{.Name}}" if kind != "container" else "{{.Names}}")
        if name in output.decode().splitlines():
            raise EngineError("restore_resource_occupied")
        args = [kind, "create", "--driver", "local" if kind == "volume" else "bridge"]
        if kind == "network":
            args += ["--ipv6"]
            if options and options.get("internal"):
                args += ["--internal", "--opt", "com.docker.network.bridge.gateway_mode_ipv4=isolated", "--opt", "com.docker.network.bridge.gateway_mode_ipv6=isolated"]
        for key, value in labels.items():
            args += ["--label", key + "=" + value]
        self.docker(*args, name)
        actual = self._json(kind, "inspect", name)[0]
        if not self._labels_match(actual.get("Labels", {}), labels):
            raise EngineError("restore_resource_occupied")
        if kind == "volume" and (actual.get("Driver") != "local" or actual.get("Options")):
            raise EngineError("restore_resource_occupied")
        resources[-1]["created"] = True
        atomic(self._restore_path(record["id"]), record)

    def _runtime(self, manifest, record, mappings, *, active=False, ports=None):
        model = copy.deepcopy(manifest["runtime"])
        project = record["projectId"]
        labels = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
        model["name"] = project
        model.pop("volumes", None)
        model.pop("configs", None)
        model.pop("secrets", None)
        # All source networks are remapped consistently. No external/static network resources survive.
        names = set(model.get("networks", {})) or {"default"}
        model["networks"] = {}
        for index, name in enumerate(sorted(names)):
            network_name = project + "-n" + str(index)
            model["networks"][name] = {"name": network_name, "external": True}
        model["volumes"] = {}
        for name, service in model["services"].items():
            original = next(c for c in manifest["containers"] if c["service"] == name)
            for field in ("build", "env_file", "container_name", "ports", "restart", "labels", "networks", "volumes", "configs", "secrets", "profiles", "pull_policy"):
                service.pop(field, None)
            service["labels"] = labels
            service["pull_policy"] = "never"
            service["restart"] = (original.get("restart", {}).get("Name") or "no") if active else "no"
            retries = original.get("restart", {}).get("MaximumRetryCount", 0)
            if active and service["restart"] == "on-failure" and retries:
                service["restart"] += ":" + str(retries)
            configured = manifest["runtime"]["services"][name].get("networks", {"default": {}})
            configured = {n: {} for n in configured} if isinstance(configured, list) else configured
            service["networks"] = {n: {"aliases": options.get("aliases", [])} if isinstance(options, dict) else {} for n, options in configured.items()}
            if any(n not in model["networks"] for n in service["networks"]):
                raise EngineError("compose_network_unsupported")
            service["volumes"] = []
            for mount in original["mounts"]:
                mapping = mappings[mount["key"]]
                reference = {"type": mapping["kind"], "source": mapping["source"], "target": mount["target"], "read_only": mount["readOnly"]}
                if mapping["kind"] == "volume":
                    logical = mapping["logical"]
                    reference["source"] = logical
                    reference["volume"] = {"nocopy": True}
                    model["volumes"][logical] = {"name": mapping["source"], "external": True}
                else:
                    reference["bind"] = {"create_host_path": False, "propagation": "rprivate"}
                service["volumes"].append(reference)
            if active:
                service["ports"] = [{"target": p["target"], "published": str(p["published"]), "host_ip": p["hostIp"], "protocol": "tcp"} for p in ports or [] if p["service"] == name]
        return model

    def _prepare_networks(self, record, runtime, *, active=False):
        labels = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
        for network in runtime["networks"].values():
            self._new_resource(record, "network", network["name"], labels, options={"internal": not active})

    def _restore_containers(self, record):
        ids = self.docker("ps", "--all", "--quiet", "--filter", "label=com.docker.compose.project=" + record["projectId"]).decode().split()
        values = self._inspect(ids)
        labels = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
        if any(not self._labels_match(c.get("Config", {}).get("Labels", {}), labels) for c in values):
            raise EngineError("restore_ownership_unverified", unknown=True)
        return values

    def _runtime_checks(self, record, manifest, *, active=False):
        containers = self._restore_containers(record)
        if len(containers) != len(manifest["runtime"]["services"]):
            raise EngineError("restore_service_set_unverified", unknown=True)
        by_service = {c["Config"]["Labels"].get("com.docker.compose.service"): c for c in containers}
        if set(by_service) != set(manifest["runtime"]["services"]):
            raise EngineError("restore_service_set_unverified", unknown=True)
        for name, container in by_service.items():
            original = next(c for c in manifest["containers"] if c["service"] == name)
            if self._container_image_info(container, manifest["platform"])["id"] != original["imageId"] or not container.get("State", {}).get("Running"):
                raise EngineError("restore_runtime_unverified")
            desired_alias = manifest["images"][original["imageId"]]["alias"]
            if self._image_info(desired_alias, manifest["platform"])["id"] != original["imageId"]:
                raise EngineError("image_identity_mismatch")
            expected_mounts = {(m["target"], record["mappings"][m["key"]]["source"], not m["readOnly"]) for m in original["mounts"]}
            actual_mounts = {(m["Destination"], m.get("Name") if m["Type"] == "volume" else m["Source"], m.get("RW", False)) for m in container.get("Mounts", [])}
            if expected_mounts != actual_mounts:
                raise EngineError("restore_mount_unverified")
            host = container.get("HostConfig", {})
            desired = manifest["runtime"]["services"][name]
            actual_env = dict(value.split("=", 1) for value in container.get("Config", {}).get("Env", []) if "=" in value)
            if (actual_env != desired.get("environment", {})
                    or container.get("Config", {}).get("User", "") != desired.get("user", "")
                    or bool(host.get("ReadonlyRootfs")) != bool(desired.get("read_only", False))
                    or set(host.get("CapDrop") or []) != set(desired.get("cap_drop", []))
                    or bool([s for s in host.get("SecurityOpt") or [] if s.startswith("no-new-privileges")]) != bool(desired.get("security_opt"))):
                raise EngineError("restore_runtime_restriction_mismatch")
            expected_ports = {(p["target"], p["published"], str(ipaddress.ip_address(p["hostIp"]))) for p in record.get("ports", []) if p["service"] == name} if active else set()
            actual_ports = {(int(key.split("/")[0]), int(binding["HostPort"]), str(ipaddress.ip_address(binding["HostIp"] or "0.0.0.0"))) for key, bindings in (host.get("PortBindings") or {}).items() for binding in bindings or [] if key.endswith("/tcp")}
            if actual_ports != expected_ports or any(not key.endswith("/tcp") and bindings for key, bindings in (host.get("PortBindings") or {}).items()):
                raise EngineError("restore_ports_unverified")
            if host.get("Privileged") or host.get("CapAdd") or host.get("Devices") or host.get("NetworkMode") in {"host", "none"}:
                raise EngineError("restore_runtime_unverified")
            if not active and (host.get("PortBindings") or any(container.get("NetworkSettings", {}).get("Ports", {}).values())):
                raise EngineError("restore_isolation_unverified")
            networks = container.get("NetworkSettings", {}).get("Networks", {})
            for network in networks.values():
                actual = self._json("network", "inspect", network["NetworkID"])[0]
                expected_labels = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
                if not self._labels_match(actual.get("Labels", {}), expected_labels) or actual.get("Driver") != "bridge":
                    raise EngineError("restore_network_unverified")
                if active and actual.get("Internal") is not False:
                    raise EngineError("activation_egress_unverified")
                if not active:
                    options = actual.get("Options", {})
                    if actual.get("Internal") is not True or options.get("com.docker.network.bridge.gateway_mode_ipv4") != "isolated" or options.get("com.docker.network.bridge.gateway_mode_ipv6") != "isolated":
                        raise EngineError("restore_isolation_unverified")
        return by_service

    def _health(self, record, manifest, *, active=False):
        deadline = time.monotonic() + 90
        while True:
            by_service = self._runtime_checks(record, manifest, active=active)
            unhealthy = [c for c in by_service.values() if has_health(c) and c.get("State", {}).get("Health", {}).get("Status") != "healthy"]
            if not unhealthy:
                break
            if time.monotonic() >= deadline:
                raise EngineError("application_health_failed")
            time.sleep(2)
        rule = manifest.get("healthCheck")
        if rule:
            container = by_service[rule["service"]]
            networks = container["NetworkSettings"]["Networks"]
            network_name = next(iter(networks))
            # Probe exact container IP on its owned network; no shell, headers or arbitrary URL host.
            address = networks[network_name].get("IPAddress")
            if not address:
                raise EngineError("health_address_unverified")
            url = "http://" + address + ":" + str(rule["port"]) + rule["path"]
            value = self._helper(manifest["images"][manifest["helperId"]]["alias"], record["serviceId"], ["http", url], network=network_name, purpose="health-helper")
            if value.get("status") != rule["expectedStatus"]:
                raise EngineError("application_health_failed")
            return True, "http"
        checks = [c for c in by_service.values() if has_health(c)]
        return (True, "docker") if len(checks) == len(by_service) else (False, "running-only")

    def _restore_snapshot(self, params):
        binding = self.storage.binding(params["storageId"])
        points = self._snapshots(binding, params["serviceId"])
        point = next((p for p in points if p["id"] == params["snapshotId"]), None)
        if point is None:
            raise EngineError("snapshot_scope_mismatch")
        identity = self.current["id"]
        directory = self.state / "stages" / identity
        directory.mkdir(mode=0o700)
        free = shutil.disk_usage(self.state).free
        if free < 1024 ** 3:
            raise EngineError("insufficient_staging_space")
        self._journal(stage="bundle-download")
        self.storage.run(binding, ["dump", params["snapshotId"], "/bundle.tar"], output_file=directory / "bundle.tar", output_limit=min(MAX_BYTES * 2, free - 512 * 1024 ** 2))
        manifest = self._bundle(directory / "bundle.tar", directory, service_id=params["serviceId"], repository_id=binding["repositoryId"], point=point)
        self._reserve(sum(a["bytes"] for a in manifest["archives"]), sum(i["requiredBytes"] for i in manifest["measuredImages"].values()), sum(a["files"] for a in manifest["archives"]) + sum(i["files"] for i in manifest["measuredImages"].values()))
        if manifest["platform"] != self._platform():
            raise EngineError("image_platform_mismatch")
        record = {"id": identity, "restoreId": identity, "serviceId": params["serviceId"], "storageId": params["storageId"], "repositoryId": binding["repositoryId"],
                  "snapshot": params["snapshotId"], "manifestDigest": point["manifestDigest"], "sourceFingerprint": point["sourceFingerprint"],
                  "state": "creating", "projectId": "rpo-" + identity.replace("-", ""), "directory": str(directory), "resources": [], "mappings": {}, "ports": [], "createdAt": now()}
        atomic(self._restore_path(identity), record)
        self._journal(stage="images-load-intent", restoreId=identity)
        # No saved helper executes before host-side validation of bundle, model, nested archives and exact image configs.
        self._load_images(directory, manifest)
        labels = self._owned_labels(identity, params["serviceId"], "restore") | {OWNER + ".restore": identity}
        bind_roots = sorted([a for a in manifest["archives"] if a["kind"] == "bind"], key=lambda a: len(a["key"]))
        for index, item in enumerate(manifest["archives"]):
            extraction = directory / ("mount-" + str(index))
            extraction.mkdir(mode=0o700)
            unpacked = extraction / "extracted"
            unpacked.mkdir(mode=0o700)
            shutil.copyfile(directory / item["filename"], extraction / "archive.tar")
            if item["kind"] == "volume":
                name = record["projectId"] + "-v" + str(index)
                self._new_resource(record, "volume", name, labels)
                (unpacked / "payload").mkdir(mode=0o700)
                self._helper(manifest["images"][manifest["helperId"]]["alias"], params["serviceId"], ["unpack", "/stage/archive.tar", "/stage/extracted"], stage=extraction, destination_volume=name, purpose="restore-helper")
                mapping = {"kind": "volume", "source": name, "logical": "data" + str(index)}
            elif item["kind"] == "bind":
                self._helper(manifest["images"][manifest["helperId"]]["alias"], params["serviceId"], ["unpack", "/stage/archive.tar", "/stage/extracted"], stage=extraction, purpose="restore-helper")
                mapping = {"kind": "bind", "source": str(unpacked / "payload")}
            else:
                raise EngineError("bundle_mount_unsupported")
            record["mappings"][item["key"]] = mapping
            atomic(self._restore_path(identity), record)
        # Nested bind references continue to address the same fresh data tree.
        for child in bind_roots:
            source = Path(child["key"].removeprefix("bind:"))
            for parent in bind_roots:
                parent_source = Path(parent["key"].removeprefix("bind:"))
                if parent != child and not parent["file"] and parent_source in source.parents:
                    record["mappings"][child["key"]]["source"] = str(Path(record["mappings"][parent["key"]]["source"]) / source.relative_to(parent_source))
                    break
        runtime = self._runtime(manifest, record, record["mappings"])
        atomic(directory / "runtime.json", runtime)
        record["runtimeDigest"] = digest(directory / "runtime.json")
        atomic(self._restore_path(identity), record)
        self._journal(stage="restore-start-intent")
        self._prepare_networks(record, runtime)
        # Compose receives only generated private configuration and cannot pull/build.
        self._compose(record["projectId"], [str(directory / "runtime.json")], str(directory), "up", "--detach", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "90")
        verified, scope = self._health(record, manifest)
        checks = ["compose-model", "data-hashes", "metadata", "image-identities", "fresh-resources", "runtime-isolation"]
        if verified:
            checks.append("application-health")
        record["containerIds"] = {c["Config"]["Labels"]["com.docker.compose.service"]: c["Id"] for c in self._restore_containers(record)}
        record.update(state="isolated_ready", checks=checks, applicationHealthVerified=verified, healthScope=scope)
        atomic(self._restore_path(identity), record)
        try:
            self._cleanup_payloads(self.current)
            self._runtime_checks(record, manifest)
        except (EngineError, StorageError):
            self._settle_stopped_restore(self.current, record)
            raise EngineError("restore_interrupted") from None
        return self._safe_restore(record)

    @staticmethod
    def _safe_restore(record):
        keys = ("serviceId", "storageId", "repositoryId", "restoreId", "snapshot", "manifestDigest", "applicationHealthVerified", "healthScope", "checks", "ports", "state", "sourceFingerprint", "projectId")
        return {k: record[k] for k in keys if k in record} | {"isolated": record.get("state") == "isolated_ready"}

    def _timer_name(self, service_id):
        if not is_uuid(service_id):
            raise EngineError("invalid_service_id")
        return "rolypolyops-compose-" + service_id

    def _timer(self, service_id):
        name = self._timer_name(service_id)
        try:
            raw = self._run(["systemctl", "show", name + ".timer", "-p", "ActiveState", "-p", "UnitFileState", "-p", "NextElapseUSecRealtime"])
            value = dict(line.split("=", 1) for line in raw.decode().splitlines() if "=" in line)
            unit = self._run(["systemctl", "cat", name + ".timer"]).decode()
            calendars = [line.split("=", 1)[1] for line in unit.splitlines() if line.startswith("OnCalendar=")]
            interval = next((key for key, calendar in INTERVALS.items() if calendars == [calendar]), None)
            return {"enabled": value.get("UnitFileState") == "enabled" and value.get("ActiveState") == "active" and interval is not None,
                    "interval": interval, "next": value.get("NextElapseUSecRealtime") or None}
        except EngineError:
            return {"enabled": False, "interval": None, "next": None}

    def _unit_text(self, path, value):
        temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            if path.is_symlink():
                raise EngineError("schedule_ownership_unverified")
            os.replace(temporary, path)
            d = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
            try:
                os.fsync(d)
            finally:
                os.close(d)
        finally:
            temporary.unlink(missing_ok=True)

    def _schedule(self, params, *, internal=False):
        service = self._service(params["serviceId"])
        if not internal:
            self._source_guard(service)
        name = self._timer_name(service["id"])
        # An exact generated header authorizes replacing these units, never a foreign same-named file.
        unit_dir = Path("/etc/systemd/system")
        header = "# RolyPolyOps Compose service " + service["id"] + "\n"
        for suffix in (".service", ".timer"):
            path = unit_dir / (name + suffix)
            if path.exists() and (path.is_symlink() or not path.read_text().startswith(header)):
                raise EngineError("schedule_ownership_unverified")
        def quoted(value):
            return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%") + '"'
        script = Path(__file__).resolve()
        command = " ".join([quoted(sys.executable), quoted(script), "backup", "--state", quoted(self.state), "--node-id", self.node_id, "--service-id", service["id"]])
        text = header + "[Unit]\nDescription=Compose service encrypted backup\nAfter=docker.service network-online.target\n\n[Service]\nType=exec\nUser=root\nUMask=0077\nExecStart=" + command + "\nRuntimeMaxSec=4h\nTimeoutStopSec=15\nRestart=on-failure\nRestartSec=60\nRestartPreventExitStatus=1\n"
        timer = header + "[Unit]\nDescription=Compose service backup schedule\n\n[Timer]\nOnCalendar=" + INTERVALS[params["interval"]] + "\nPersistent=true\nRandomizedDelaySec=30\n\n[Install]\nWantedBy=timers.target\n"
        self._journal(stage="schedule-intent")
        self._unit_text(unit_dir / (name + ".service"), text)
        self._unit_text(unit_dir / (name + ".timer"), timer)
        self._run(["systemctl", "daemon-reload"])
        self._run(["systemctl", "enable", "--now", name + ".timer"])
        actual = self._timer(service["id"])
        if not actual["enabled"] or actual["interval"] != params["interval"]:
            raise EngineError("schedule_unverified", unknown=True)
        service.update(backupInterval=params["interval"], schedule=actual)
        self._save_service(service)
        return {"serviceId": service["id"], "interval": params["interval"], "enabled": True}

    def _disable_timer(self, service_id):
        timer = self._timer(service_id)
        if timer["enabled"]:
            self._run(["systemctl", "disable", "--now", self._timer_name(service_id) + ".timer"])
        if self._timer(service_id)["enabled"]:
            raise EngineError("source_timer_disable_failed", unknown=True)
        return timer

    def _policy(self, value):
        name = value.get("Name") or "no"
        if name not in {"no", "always", "unless-stopped", "on-failure"}:
            raise EngineError("restart_policy_unsupported")
        return name + (":" + str(value.get("MaximumRetryCount", 0)) if name == "on-failure" and value.get("MaximumRetryCount") else "")

    def _assert_fence(self, service):
        fence = service.get("fence")
        if not fence or self._timer(service["id"])["enabled"]:
            raise EngineError("source_fence_unverified", unknown=True)
        values = self._inspect([c["id"] for c in fence["containers"]])
        if {c["Id"] for c in values} != {c["id"] for c in fence["containers"]}:
            raise EngineError("source_fence_unverified", unknown=True)
        for c in values:
            expected = next(v for v in fence["containers"] if v["id"] == c["Id"])
            if c.get("State", {}).get("Running") or c.get("Image") != expected["imageId"] or c.get("HostConfig", {}).get("RestartPolicy", {}).get("Name") != "no" or c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != service["projectId"]:
                raise EngineError("source_fence_unverified", unknown=True)
        for path, expected_hash in service["project"]["inputs"].items():
            if not Path(path).is_file() or digest(path) != expected_hash:
                raise EngineError("source_fence_unverified", unknown=True)

    def _stop(self, params):
        service = self._service(params["serviceId"])
        if service["fingerprint"] != params["fingerprint"]:
            raise EngineError("source_drift")
        if service.get("sourceState") == "fenced":
            self._assert_fence(service)
        else:
            self._source_guard(service)
            project = self._project(service["projectId"], owned_service=service["id"] if service.get("adopted") else None)
            if project["fingerprint"] != service["fingerprint"]:
                raise EngineError("source_drift")
            actual = self._inspect([c["id"] for c in project["containers"]])
            fence = {"operationId": self.current["id"], "fingerprint": service["fingerprint"], "timer": self._timer(service["id"]),
                     "containers": [{"id": c["Id"], "imageId": c["Image"], "running": c.get("State", {}).get("Running", False), "restart": c.get("HostConfig", {}).get("RestartPolicy", {"Name": "no"})} for c in actual]}
            self._journal(stage="fence-intent")
            service.update(sourceState="unknown", fence=fence)
            self._save_service(service)
            try:
                self._disable_timer(service["id"])
                for container in fence["containers"]:
                    self.docker("update", "--restart", "no", container["id"])
                self.docker("stop", "--time", "60", *[c["id"] for c in fence["containers"] if c["running"]], timeout=120)
                self._assert_fence(service)
            except EngineError:
                # Only verifiable rollback restores original authority; never resume after a proven fence.
                try:
                    self._restore_fence_originals(service)
                except (EngineError, StorageError):
                    service["sourceState"] = "unknown"
                    self._save_service(service)
                    raise EngineError("source_stop_unknown", unknown=True) from None
                raise EngineError("source_stop_failed") from None
            service["sourceState"] = "fenced"
            self._save_service(service)
        self._journal(stage="source-fenced")
        return {"serviceId": service["id"], "fingerprint": service["fingerprint"], "fenced": True, "stopOperationId": self.current["id"]}

    def _restore_fence_originals(self, service):
        fence = service["fence"]
        actual = self._inspect([c["id"] for c in fence["containers"]])
        if {c["Id"] for c in actual} != {c["id"] for c in fence["containers"]}:
            raise EngineError("source_resume_unverified", unknown=True)
        for c in actual:
            expected = next(v for v in fence["containers"] if v["id"] == c["Id"])
            if c.get("Image") != expected["imageId"] or c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != service["projectId"]:
                raise EngineError("source_resume_unverified", unknown=True)
        for c in fence["containers"]:
            self.docker("update", "--restart", self._policy(c["restart"]), c["id"])
            if c["running"]:
                self.docker("start", c["id"])
        if not all(c.get("State", {}).get("Running") == next(v["running"] for v in fence["containers"] if v["id"] == c["Id"]) for c in self._inspect([c["id"] for c in fence["containers"]])):
            raise EngineError("source_resume_unverified", unknown=True)
        service["sourceState"] = "running"
        self._save_service(service)
        if fence["timer"]["enabled"]:
            self._schedule({"serviceId": service["id"], "interval": fence["timer"]["interval"]}, internal=True)

    def _resume(self, params):
        service = self._service(params["serviceId"])
        if service.get("sourceState") != "fenced" or params.get("fingerprint", service["fingerprint"]) != service["fingerprint"]:
            raise EngineError("source_resume_not_fenced")
        self._assert_fence(service)
        # The authenticated controller authorizes this action only after fresh positive target-absence proof.
        self._journal(stage="source-resume-intent", resumeFence=copy.deepcopy(service["fence"]))
        self._restore_fence_originals(service)
        original = service.pop("fence")
        self._save_service(service)
        return {"serviceId": service["id"], "resumed": True, "fingerprint": service["fingerprint"],
                "interval": original["timer"].get("interval") or service["backupInterval"], "enabled": original["timer"]["enabled"]}

    def _activation(self, params):
        record = self._restore(params["restoreId"], params["serviceId"])
        if record["state"] != "isolated_ready":
            raise EngineError("restore_not_isolated")
        if not is_uuid(params["sourceStopJobId"]):
            raise EngineError("source_stop_required")
        directory = Path(record["directory"])
        if not directory.is_relative_to(self.state / "stages") or directory.name != record["id"] or directory.is_symlink():
            raise EngineError("restore_ownership_unverified")
        manifest = read(directory / "manifest.json")
        if digest(directory / "manifest.json") != record["manifestDigest"] or digest(directory / "runtime.json") != record["runtimeDigest"]:
            raise EngineError("restore_config_changed")
        self._runtime_checks(record, manifest)
        for p in params["ports"]:
            if p["service"] not in manifest["runtime"]["services"]:
                raise EngineError("invalid_ports")
        # Hold actual bind reservations until immediately before Compose publishes. Docker then atomically owns ports.
        sockets = []
        try:
            for port in params["ports"]:
                family = socket.AF_INET6 if ":" in port["hostIp"] else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM)
                try:
                    sock.bind((port["hostIp"], port["published"]))
                    sock.listen(1)
                except OSError:
                    sock.close()
                    raise EngineError("activation_port_occupied") from None
                sockets.append(sock)
            self._journal(stage="activation-intent", restoreId=record["id"], sourceStopJobId=params["sourceStopJobId"])
            record.update(state="activating", ports=params["ports"], sourceStopJobId=params["sourceStopJobId"])
            atomic(self._restore_path(record["id"]), record)
            self._compose(record["projectId"], [str(directory / "runtime.json")], str(directory), "stop", "--timeout", "60")
            # Network isolation is immutable in Docker. Remove only these verified owned stopped containers/networks.
            self._remove_runtime_only(record, require_stopped=True)
            runtime = self._runtime(manifest, record, record["mappings"], active=True, ports=params["ports"])
            atomic(directory / "runtime.json", runtime)
            self._prepare_networks(record, runtime, active=True)
            record["runtimeDigest"] = digest(directory / "runtime.json")
            atomic(self._restore_path(record["id"]), record)
        finally:
            for sock in sockets:
                sock.close()
        self._journal(stage="activation-start-intent")
        self._compose(record["projectId"], [str(directory / "runtime.json")], str(directory), "up", "--detach", "--no-build", "--pull", "never", "--wait", "--wait-timeout", "90")
        verified, scope = self._health(record, manifest, active=True)
        # Authority is durable before schedule/first capture. Any protection failure keeps the old source fenced.
        record.update(state="active", healthScope=scope, applicationHealthVerified=verified)
        record["containerIds"] = {c["Config"]["Labels"]["com.docker.compose.service"]: c["Id"] for c in self._restore_containers(record)}
        atomic(self._restore_path(record["id"]), record)
        self._save_service({"id": record["serviceId"], "projectId": record["projectId"], "activeRestoreId": record["id"], "sourceState": "unknown", "storageId": record["storageId"], "backupInterval": params["interval"], "fingerprint": record["sourceFingerprint"]})
        project = self._project(record["projectId"], owned_service=record["serviceId"])
        service = {"id": record["serviceId"], "projectId": record["projectId"], "fingerprint": project["fingerprint"], "storageId": record["storageId"],
                   "backupInterval": params["interval"], "exclusiveWriters": True, "healthCheck": manifest.get("healthCheck"), "sourceState": "running",
                   "sourceNodeId": self.node_id, "adopted": True, "helperId": manifest["images"][manifest["helperId"]]["alias"], "activeRestoreId": record["id"], "project": project, "setupState": "active_unprotected"}
        self._save_service(service)
        result = {"serviceId": service["id"], "restoreId": record["id"], "activated": True, "sourceNodeId": self.node_id,
                  "projectId": service["projectId"], "fingerprint": service["fingerprint"], "ports": params["ports"], "interval": params["interval"], "enabled": False, "protected": False}
        self._journal(stage="active-unprotected", activationResult=result)
        try:
            self._schedule({"serviceId": service["id"], "interval": params["interval"]}, internal=True)
            result["enabled"] = True
            # A distinct durable operation identity captures the first new-source point.
            parent = self.current
            child_id = str(uuid.uuid4())
            self.current = {"id": child_id, "action": "compose-backup", "parameters": {"serviceId": service["id"], "storageId": service["storageId"]}, "status": "running", "stage": "accepted", "origin": "activation", "parentId": parent["id"], "at": now()}
            atomic(self._journal_path(child_id), self.current)
            try:
                backup = self._backup(self.current["parameters"])
                self._journal(status="succeeded", result=backup, stage="complete")
                result.update(firstBackup=backup, protected=True)
            except (EngineError, StorageError, ArchiveError) as error:
                unknown = getattr(error, "unknown", False)
                self._journal(status="outcome_unknown" if unknown else "failed", error=error.code)
                if unknown:
                    raise EngineError("first_backup_unknown", unknown=True) from None
            finally:
                self.current = parent
            service = self._service(service["id"])
            service["setupState"] = "restore_required" if result["protected"] else "active_unprotected"
            self._save_service(service)
        except (EngineError, StorageError, ArchiveError) as error:
            if getattr(error, "unknown", False):
                self._journal(stage="active-protection-unknown", activationResult=result)
                raise
            # Known running new source with failed protection is a truthful partial result.
            result["protectionError"] = error.code
        self._journal(activationResult=result)
        return result

    def _remove_runtime_only(self, record, require_stopped=False):
        containers = self._restore_containers(record)
        networks = set()
        for c in containers:
            if require_stopped and c.get("State", {}).get("Running"):
                raise EngineError("restore_running")
            networks.update(n["NetworkID"] for n in c.get("NetworkSettings", {}).get("Networks", {}).values())
        expected = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
        for network in networks:
            actual = self._json("network", "inspect", network)[0]
            if not self._labels_match(actual.get("Labels", {}), expected) or set(actual.get("Containers", {})) - {c["Id"] for c in containers}:
                raise EngineError("restore_ownership_unverified")
        for c in containers:
            self.docker("rm", "--force", c["Id"])
        for network in networks:
            self.docker("network", "rm", network)

    def _stopped_restore_proof(self, journal, record):
        """Prove an owned isolated runtime stopped or absent, without claiming readiness."""
        import stat
        try:
            def require(value):
                if not value:
                    raise EngineError("restore_stopped_unverified", unknown=True)
            require(getattr(self._local, "engine_locked", False))
            identity, service_id = record.get("id"), record.get("serviceId")
            require(is_uuid(identity) and is_uuid(service_id) and journal.get("id") == identity and journal.get("action") == "compose-restore"
                    and record.get("state") in {"isolated_ready", "stopped"} and record.get("projectId") == "rpo-" + identity.replace("-", ""))
            directory = self.state / "stages" / identity
            require(record.get("directory") == str(directory))
            uid = os.geteuid()
            def trusted(path, folder=False):
                value = path.lstat()
                require((stat.S_ISDIR(value.st_mode) if folder else stat.S_ISREG(value.st_mode))
                        and value.st_uid in ({0, uid} if folder else {uid}) and not value.st_mode & 0o022
                        and (folder or value.st_nlink == 1))
                return value
            for parent in reversed(directory.parents):
                trusted(parent, True)
            for folder in (directory, self._journal_path(identity).parent, self._restore_path(identity).parent, self.state / "services"):
                trusted(folder, True)
            trusted(self._journal_path(identity));trusted(self._restore_path(identity))
            require(self._inspection_journal(identity) == journal and self._restore(identity, service_id) == record)
            params = journal.get("parameters")
            require(isinstance(params, dict) and set(params) == {"serviceId", "storageId", "snapshotId"}
                    and params["serviceId"] == service_id and params["storageId"] == record.get("storageId") and is_uuid(params["storageId"])
                    and params["snapshotId"] == record.get("snapshot") and isinstance(params["snapshotId"], str) and HEX.fullmatch(params["snapshotId"]))
            for path in (directory / "manifest.json", directory / "runtime.json"):
                require(trusted(path).st_size <= 16 * 1024 * 1024)
            manifest, runtime = read(directory / "manifest.json"), read(directory / "runtime.json")
            require(digest(directory / "manifest.json") == record.get("manifestDigest") and digest(directory / "runtime.json") == record.get("runtimeDigest")
                    and manifest.get("format") == "rolypolyops-compose-v1" and manifest.get("serviceId") == service_id
                    and manifest.get("repositoryId") == record.get("repositoryId") and manifest.get("sourceFingerprint") == record.get("sourceFingerprint")
                    and isinstance(record.get("sourceFingerprint"), str) and HEX.fullmatch(record["sourceFingerprint"]) and is_uuid(manifest.get("operationId")))
            require(canonical(runtime) == canonical(self._runtime(manifest, record, record["mappings"])))
            for path in (self.state / "services").glob("*.json"):
                trusted(path);service = read(path)
                require(service.get("activeRestoreId") != identity and service.get("projectId") != record["projectId"])
            expected_ids = record.get("containerIds")
            require(isinstance(expected_ids, dict) and 1 <= len(expected_ids) <= 100 and set(expected_ids) == set(manifest["runtime"]["services"])
                    and len(set(expected_ids.values())) == len(expected_ids) and all(isinstance(value, str) and HEX.fullmatch(value) for value in expected_ids.values()))
            labels = self._owned_labels(identity, service_id, "restore") | {OWNER + ".restore": identity}
            helpers = journal.get("helpers", [])
            require(isinstance(helpers, list) and len(helpers) <= 200)
            for helper in helpers:
                purpose = helper.get("labels", {}).get(OWNER + ".purpose")
                require(purpose in {"restore-helper", "health-helper"} and helper.get("labels") == self._owned_labels(identity, service_id, purpose))
            self.storage.recover()
            require(isinstance(record.get("repositoryId"), str) and HEX.fullmatch(record["repositoryId"]))
            self._terminate_helpers(journal)
            def inventory(*args, hex_ids=False):
                values = self.docker(*args).decode().split()
                require(len(values) <= 1000 and len(set(values)) == len(values)
                        and all(isinstance(v, str) and (HEX.fullmatch(v) if hex_ids else re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}", v)) for v in values))
                return set(values)
            ids = inventory("ps", "--all", "--quiet", "--no-trunc", hex_ids=True)
            containers = self._inspect(sorted(ids))
            require(len(containers) == len(ids) and {c["Id"] for c in containers} == ids)
            resources = record.get("resources")
            require(isinstance(resources, list) and len(resources) <= 200)
            names = {"volume": set(), "network": set()}
            for resource in resources:
                kind, name = resource.get("kind"), resource.get("name")
                require(kind in names and isinstance(name, str) and name.startswith(record["projectId"] + "-")
                        and resource.get("created") is True and resource.get("labels") == labels and name not in names[kind])
                names[kind].add(name)
            present, network_ids = {}, {}
            owned_present = ids & set(expected_ids.values())
            for kind in names:
                all_names = inventory(kind, "ls", "--format", "{{.Name}}")
                own_names = inventory(kind, "ls", "--filter", "label=" + OWNER + ".operation=" + identity, "--format", "{{.Name}}")
                require(own_names <= names[kind] and own_names <= all_names and names[kind] & all_names == own_names)
                present[kind] = own_names
                for name in sorted(own_names):
                    details = self._json(kind, "inspect", name)
                    require(isinstance(details, list) and len(details) == 1)
                    actual = details[0]
                    require(actual.get("Name") == name and self._labels_match(actual.get("Labels", {}), labels)
                            and actual.get("Driver") == ("local" if kind == "volume" else "bridge"))
                    if kind == "volume":
                        require(not actual.get("Options"))
                    else:
                        require(actual.get("Internal") is True and set(actual.get("Containers", {})) <= owned_present)
                        network_ids[name] = actual.get("Id")
            source_containers = {item["service"]: item for item in manifest["containers"]}
            by_id = {value: name for name, value in expected_ids.items()}
            for container in containers:
                current_labels = container.get("Config", {}).get("Labels", {})
                relevant = (container["Id"] in by_id or current_labels.get("com.docker.compose.project") == record["projectId"]
                            or current_labels.get(OWNER + ".restore") == identity or current_labels.get(OWNER + ".operation") == identity)
                if not relevant:
                    for mount in container.get("Mounts", []):
                        require(not (mount.get("Type") == "volume" and mount.get("Name") in names["volume"]))
                        if mount.get("Type") == "bind":
                            path = Path(mount["Source"])
                            require(path.is_absolute() and path != directory and directory not in path.parents and path not in directory.parents)
                    continue
                require(container["Id"] in by_id and self._labels_match(current_labels, labels)
                        and current_labels.get("com.docker.compose.project") == record["projectId"]
                        and current_labels.get("com.docker.compose.service") == by_id[container["Id"]])
                state, host, network = container.get("State", {}), container.get("HostConfig", {}), container.get("NetworkSettings", {})
                require(state.get("Running") is False and type(state.get("Pid")) is int and state["Pid"] == 0
                        and state.get("Paused") is False and state.get("Restarting") is False and state.get("Dead") is False
                        and state.get("Status") in {"exited", "created"} and host.get("PublishAllPorts") is False)
                for bindings in (host.get("PortBindings"), network.get("Ports")):
                    require(isinstance(bindings, dict) and all(value is None or value == [] for value in bindings.values()))
                original = source_containers[by_id[container["Id"]]]
                require(self._container_image_info(container, manifest["platform"])["id"] == original["imageId"])
                mounts = []
                for mount in original["mounts"]:
                    mapping = record["mappings"][mount["key"]]
                    mounts.append([mapping["kind"], mapping["source"], mount["target"], not mount["readOnly"]])
                require(self._capture_container_mounts(container) == self._capture_mounts(mounts))
                expected_networks = {value["name"] for value in runtime["networks"].values()}
                require(set(network.get("Networks", {})) == expected_networks and expected_networks <= present["network"])
                for name, attachment in network["Networks"].items():
                    require(attachment.get("NetworkID") == network_ids[name])
            return {"presentResources": {kind: sorted(value) for kind, value in present.items()}, "presentContainers": sorted(owned_present),
                    "manifestDigest": record["manifestDigest"], "runtimeDigest": record["runtimeDigest"]}
        except (EngineError, StorageError, ArchiveError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, StopIteration, RecursionError):
            raise EngineError("restore_stopped_unverified", unknown=True) from None

    def _settle_stopped_restore(self, journal, record):
        try:
            proof = self._stopped_restore_proof(journal, record)
            record.update(state="stopped", applicationHealthVerified=False, healthScope="stopped", ports=[],
                          checks=["runtime-stopped", "no-published-ports", "owned-resources"], stoppedProof=proof)
            atomic(self._restore_path(record["id"]), record)
            audit = journal.get("deferredPayloadCleanup", {"reason": "runtime-stopped", "at": now()})
            if not isinstance(audit, dict) or audit.get("reason") != "runtime-stopped":
                raise EngineError("restore_stopped_unverified", unknown=True)
            if "payloadCleanup" in journal:
                if "intent" in audit and audit["intent"] != journal["payloadCleanup"]:
                    raise EngineError("restore_stopped_unverified", unknown=True)
                audit["intent"] = journal.pop("payloadCleanup")
            journal["deferredPayloadCleanup"] = audit
            journal.update(status="failed", error="restore_interrupted", stage="stopped", completedAt=now())
            atomic(self._journal_path(journal["id"]), journal)
            return {"status": "failed", "error": "restore_interrupted", "stage": "stopped"}

        except (EngineError, StorageError, ArchiveError, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, StopIteration, RecursionError):
            raise EngineError("restore_stopped_unverified", unknown=True) from None

    def _remove(self, params):
        record = self._restore(params["restoreId"], params["serviceId"])
        if record["state"] not in {"isolated_ready", "stopped"}:
            raise EngineError("restore_not_removable")
        stopped = record["state"] == "stopped"
        proof = None
        if stopped:
            journal = self._inspection_journal(record["id"])
            if not journal or journal.get("status") != "failed" or journal.get("error") != "restore_interrupted":
                raise EngineError("restore_not_removable")
            proof = self._stopped_restore_proof(journal, record)
        # Every current source is protected independently from possibly missing/corrupt preview records.
        for path in (self.state / "services").glob("*.json"):
            service = read(path)
            if service.get("activeRestoreId") == record["id"] or service.get("projectId") == record["projectId"]:
                raise EngineError("current_source_protected")
        directory = Path(record["directory"])
        if directory != self.state / "stages" / record["id"] or directory.is_symlink() or not directory.is_dir():
            raise EngineError("restore_ownership_unverified")
        if digest(directory / "runtime.json") != record["runtimeDigest"]:
            raise EngineError("restore_config_changed")
        expected = self._owned_labels(record["id"], record["serviceId"], "restore") | {OWNER + ".restore": record["id"]}
        for resource in record["resources"]:
            if resource["kind"] not in {"volume", "network"} or not resource.get("created") or resource.get("labels") != expected:
                raise EngineError("restore_ownership_unverified")
            if stopped and resource["name"] not in proof["presentResources"][resource["kind"]]:
                continue
            volume = self._json(resource["kind"], "inspect", resource["name"])[0]
            if not self._labels_match(volume.get("Labels", {}), expected):
                raise EngineError("restore_ownership_unverified")
        # Another running/stopped container referencing an owned volume protects it too.
        own_ids = {c["Id"] for c in self._restore_containers(record)}
        ids = self.docker("ps", "--all", "--quiet").decode().split()
        volumes = {r["name"] for r in record["resources"] if r["kind"] == "volume"}
        for c in self._inspect(ids):
            if c["Id"] not in own_ids and any(m.get("Name") in volumes or m.get("Type") == "bind" and (Path(m["Source"]) == directory or directory in Path(m["Source"]).parents) for m in c.get("Mounts", [])):
                raise EngineError("restore_in_use")
        self._journal(stage="remove-intent", restoreId=record["id"])
        self._remove_runtime_only(record, require_stopped=True) if stopped else self._remove_runtime_only(record)
        for resource in record["resources"]:
            if resource["kind"] == "volume" and (not stopped or resource["name"] in proof["presentResources"]["volume"]):
                self.docker("volume", "rm", resource["name"])
        if stopped:
            remaining = set(self.docker("network", "ls", "--format", "{{.Name}}").decode().split())
            for resource in record["resources"]:
                if resource["kind"] == "network" and resource["name"] in remaining:
                    actual = self._json("network", "inspect", resource["name"])[0]
                    if not self._labels_match(actual.get("Labels", {}), expected) or actual.get("Containers"):
                        raise EngineError("restore_in_use")
                    self.docker("network", "rm", resource["name"])
        shutil.rmtree(directory)
        record["state"] = "removed"
        atomic(self._restore_path(record["id"]), record)
        return {"serviceId": params["serviceId"], "restoreId": record["id"], "removed": True}

    def _recover_locked(self):
        # An orphan storage writer must be proved dead before any source/helper compensation.
        self.storage.recover()
        results = []
        for path in sorted((self.state / "services").glob("*.json")):
            service = read(path)
            if service.get("sourceState") != "capture_stopped":
                continue
            identity = service.get("captureOperation")
            if not is_uuid(identity):
                service["sourceState"] = "unknown"
                self._save_service(service)
                results.append({"serviceId": service["id"], "status": "outcome_unknown", "error": "capture_journal_missing"})
                continue
            journal = read(self._journal_path(identity))
            if not journal or journal.get("resume", {}).get("serviceId") != service["id"]:
                service["sourceState"] = "unknown"
                self._save_service(service)
                results.append({"id": identity, "status": "outcome_unknown", "error": "capture_journal_missing"})
                continue
            try:
                settled = self._compensate_capture(service, journal)
                results.append({"id": identity, **settled})
            except (EngineError, StorageError, OSError) as error:
                service["sourceState"] = "unknown"
                self._save_service(service)
                journal.update(status="outcome_unknown", error=getattr(error, "code", "capture_recovery_failed"))
                atomic(self._journal_path(identity), journal)
                results.append({"id": identity, "status": "outcome_unknown", "error": journal["error"]})
        for index, path in enumerate((self.state / "operations").glob("*.json")):
            if index >= 10000:
                break
            journal = read(path)
            if journal.get("status") != "running" or not journal.get("helpers"):
                continue
            try:
                self._terminate_helpers(journal)
                status = "outcome_unknown"
                if journal.get("action") == "compose-backup" and journal.get("stage") == "accepted" and not journal.get("resume"):
                    service = self._service(journal["parameters"]["serviceId"])
                    if service.get("sourceState") == "running":
                        status = "failed"
                journal.update(status=status, error="operation_interrupted")
                atomic(path, journal)
                results.append({"id": journal["id"], "status": status, "error": journal["error"]})
            except (EngineError, StorageError, OSError) as error:
                journal.update(status="outcome_unknown", error=getattr(error, "code", "helper_recovery_failed"))
                atomic(path, journal)
                results.append({"id": journal["id"], "status": "outcome_unknown", "error": journal["error"]})
        return results

    def recover(self):
        try:
            with self.lock():
                return self._recover_locked()
        except EngineError as error:
            if error.code == "operation_busy":
                return []
            raise

    def execute(self, job):
        validate_job(job)
        identity = job["id"]
        request_digest = hashlib.sha256(canonical(job)).hexdigest()
        try:
            with self.lock():
                self.storage.recover()
                previous = read(self._journal_path(identity))
                if previous:
                    if previous.get("requestDigest") != request_digest:
                        raise EngineError("operation_identity_conflict")
                    inspected = self._inspect_locked(identity)
                    if inspected["status"] == "succeeded":
                        return inspected["result"]
                    raise EngineError(inspected.get("error", "operation_outcome_unknown"), unknown=inspected["status"] == "outcome_unknown")
                self._recover_locked()
                unknown = [read(p) for p in (self.state / "operations").glob("*.json")]
                if any(v.get("status") in {"outcome_unknown", "running"} for v in unknown):
                    raise EngineError("operation_hold", unknown=False)
                self.current = {"id": identity, "requestDigest": request_digest, "action": job["action"],
                                "parameters": {k: v for k, v in job["parameters"].items() if k not in {"envelope", "metadata"}},
                                "status": "running", "stage": "accepted", "at": now(), "origin": "timer" if self.config.get("origin") == "timer" else "controller"}
                self._journal()
                try:
                    action, params = job["action"], job["parameters"]
                    if action == "storage-configure":
                        if len(list(self.storage.directory.glob("*.json"))) >= 8 and not (self.storage.directory / (params["storageId"] + ".json")).exists():
                            raise EngineError("storage_limit")
                        result = self.storage.configure(identity, params)
                    elif action == "compose-register":
                        result = self._register(params)
                    elif action == "compose-backup":
                        result = self._backup(params)
                    elif action == "compose-verify":
                        binding = self.storage.binding(params["storageId"])
                        self.storage.run(binding, ["check", "--read-data"])
                        result = {"serviceId": params["serviceId"], "storageId": params["storageId"], "repositoryId": binding["repositoryId"], "verified": True, "checks": ["repository-data"]}
                    elif action == "compose-restore":
                        result = self._restore_snapshot(params)
                    elif action == "compose-remove":
                        result = self._remove(params)
                    elif action == "compose-schedule":
                        result = self._schedule(params)
                    elif action == "compose-stop":
                        result = self._stop(params)
                    elif action == "compose-resume":
                        result = self._resume(params)
                    else:
                        result = self._activation(params)
                    self._journal(status="succeeded", result=result, stage="complete", completedAt=now())
                    return result
                except (EngineError, StorageError, SealError, ArchiveError) as error:
                    unknown = getattr(error, "unknown", False)
                    # Activation after intent is uncertain until exact owned-resource inspection; never authorize resume here.
                    if self.current["action"] == "compose-activate" and self.current["stage"] != "accepted":
                        unknown = True
                    self._journal(status="outcome_unknown" if unknown else "failed", error=error.code, completedAt=now())
                    raise EngineError(error.code, unknown=unknown) from None
                except (OSError, ValueError, KeyError, TypeError, IndexError):
                    # Unexpected internal/filesystem failures are sanitized; dependent effects are not replayed.
                    self._journal(status="outcome_unknown", error="operation_internal_error", completedAt=now())
                    raise EngineError("operation_internal_error", unknown=True) from None
                finally:
                    self.current = None
        except (StorageError, SealError, ArchiveError) as error:
            raise EngineError(error.code, unknown=getattr(error, "unknown", False)) from None

    def owns_operation(self, identity):
        if not is_uuid(identity):
            return False
        try:
            value = read(self._journal_path(identity))
            return isinstance(value, dict) and value.get("id") == identity and value.get("action") in GENERIC_ACTIONS
        except (StorageError, OSError):
            return False

    @staticmethod
    def _safe_operation(value):
        if ManagedEngine._cleanup_pending(value):
            return {"status": "outcome_unknown", "error": "payload_cleanup_unverified"}
        status = value.get("status")
        result = {"status": status if status in {"succeeded", "failed", "outcome_unknown"} else "outcome_unknown"}
        for key in ("result", "error", "stage"):
            if key in value:
                result[key] = value[key]
        return result

    def _inspection_journal(self, identity):
        missing = object()
        value = read(self._journal_path(identity), missing)
        if value is missing:
            return None
        if not isinstance(value, dict) or not is_uuid(value.get("id")) or value["id"] != identity:
            raise EngineError("operation_identity_conflict", unknown=True)
        return value

    def _inspect_locked(self, identity):
        try:
            value = self._inspection_journal(identity)
        except EngineError as error:
            return {"status": "outcome_unknown", "error": error.code}
        if value is None:
            return None
        if value.get("status") in {"succeeded", "failed"} and not self._cleanup_pending(value):
            return self._safe_operation(value)
        if value.get("status") == "failed":
            return {"status": "outcome_unknown", "error": "payload_cleanup_unverified"}
        action, params = value["action"], value.get("parameters", {})
        # Inspections may write only proof/state after positively observed prior effects; never repeat the action.
        settled = None
        if action == "storage-configure":
            settled = self.storage.reconcile(identity)
        elif action == "compose-backup" and not value.get("sourceResumed"):
            try:
                service = self._service(params["serviceId"])
                settled = self._compensate_capture(service, value)
            except (EngineError, StorageError, OSError, ValueError, KeyError, TypeError, IndexError) as error:
                value["error"] = getattr(error, "code", "capture_resume_ownership_unverified")
        elif action == "compose-backup" and value.get("sourceResumed") and value.get("manifestDigest"):
            try:
                service = self._service(params["serviceId"])
                binding = self.storage.binding(params["storageId"])
                points = self._snapshots(binding, service["id"], operation=identity)
                points = [p for p in points if p.get("operationId") == identity and p["manifestDigest"] == value["manifestDigest"]]
                if len(points) == 1 and service.get("sourceState") == "running":
                    result = {"serviceId": service["id"], "repositoryId": binding["repositoryId"], "snapshot": points[0]["id"], "manifestDigest": value["manifestDigest"], "sourceFingerprint": points[0]["sourceFingerprint"], "sourceResumed": True, "at": points[0]["time"], "checks": ["source-stopped", "data-archived", "images-saved", "source-resumed", "repository-written"]}
                    service["latestBackup"] = result
                    self._save_service(service)
                    self._cleanup_payloads(value)
                    settled = {"status": "succeeded", "result": result}
            except (EngineError, StorageError) as error:
                if error.code == "payload_cleanup_unverified":
                    value["error"] = error.code
        elif action == "compose-stop":
            try:
                service = self._service(params["serviceId"])
                self._assert_fence(service)
                service["sourceState"] = "fenced"
                self._save_service(service)
                settled = {"status": "succeeded", "result": {"serviceId": service["id"], "fingerprint": service["fingerprint"], "fenced": True, "stopOperationId": identity}}
            except (EngineError, StorageError):
                pass
        elif action == "compose-restore":
            try:
                record = self._restore(identity, params["serviceId"])
                if record.get("state") == "stopped":
                    settled = self._settle_stopped_restore(value, record)
                elif record.get("state") == "isolated_ready":
                    try:
                        self._cleanup_payloads(value)
                        self._runtime_checks(record, read(self.state / "stages" / identity / "manifest.json"))
                        settled = {"status": "succeeded", "result": self._safe_restore(record)}
                    except (EngineError, StorageError) as error:
                        try:
                            settled = self._settle_stopped_restore(value, record)
                        except (EngineError, StorageError):
                            value["error"] = error.code
            except (EngineError, StorageError) as error:
                if error.code == "payload_cleanup_unverified" or "error" not in value:
                    value["error"] = error.code
        elif action == "compose-activate":
            try:
                record = self._restore(params["restoreId"], params["serviceId"])
                service = self._service(params["serviceId"])
                manifest = read(Path(record["directory"]) / "manifest.json")
                if record.get("state") == "active" and service.get("activeRestoreId") == record["id"]:
                    previous_current = self.current
                    self.current = value
                    try:
                        verified, scope = self._health(record, manifest, active=True)
                    finally:
                        self.current = previous_current
                    project = self._project(record["projectId"], owned_service=service["id"])
                    service.update(project=project, fingerprint=project["fingerprint"], sourceState="running", adopted=True,
                                   sourceNodeId=self.node_id, exclusiveWriters=True, healthCheck=manifest.get("healthCheck"),
                                   helperId=manifest["images"][manifest["helperId"]]["alias"], setupState="active_unprotected")
                    self._save_service(service)
                    result = value.get("activationResult") or {"serviceId": service["id"], "restoreId": record["id"], "activated": True, "sourceNodeId": self.node_id, "projectId": service["projectId"], "fingerprint": service["fingerprint"], "ports": record["ports"], "interval": service["backupInterval"], "enabled": self._timer(service["id"])["enabled"], "protected": False}
                    result["fingerprint"] = service["fingerprint"]
                    result["protected"] = bool(result.get("firstBackup"))
                    service["setupState"] = "restore_required" if result["protected"] else "active_unprotected"
                    self._save_service(service)
                    settled = {"status": "succeeded", "result": result}
                elif record.get("state") == "isolated_ready":
                    self._runtime_checks(record, manifest)
                    settled = {"status": "failed", "error": "activation_not_applied", "stage": "isolated"}
            except (EngineError, StorageError):
                pass
        elif action == "compose-remove":
            try:
                record = self._restore(params["restoreId"], params["serviceId"])
                if record.get("state") == "removed" and not Path(record["directory"]).exists() and not self._restore_containers(record):
                    absent = True
                    for kind in ("volume", "network"):
                        names = set(self.docker(kind, "ls", "--format", "{{.Name}}").decode().splitlines())
                        if any(r["kind"] == kind and r["name"] in names for r in record["resources"]):
                            absent = False
                    if absent:
                        settled = {"status": "succeeded", "result": {"serviceId": params["serviceId"], "restoreId": record["id"], "removed": True}}
            except (EngineError, StorageError):
                pass
        elif action == "compose-verify":
            settled = {"status": "failed", "error": "verification_interrupted", "stage": "inspection"}
        elif action == "compose-resume":
            try:
                service = self._service(params["serviceId"])
                fence = value.get("resumeFence")
                if service.get("sourceState") == "running" and fence:
                    actual = self._inspect([c["id"] for c in fence["containers"]])
                    correct = len(actual) == len(fence["containers"])
                    for c in actual:
                        expected = next(v for v in fence["containers"] if v["id"] == c["Id"])
                        correct = correct and c.get("Image") == expected["imageId"] and c.get("State", {}).get("Running") == expected["running"] and c.get("HostConfig", {}).get("RestartPolicy") == expected["restart"]
                    timer = self._timer(service["id"])
                    if correct and timer["enabled"] == fence["timer"]["enabled"] and (not timer["enabled"] or timer["interval"] == fence["timer"]["interval"]):
                        settled = {"status": "succeeded", "result": {"serviceId": service["id"], "resumed": True, "fingerprint": service["fingerprint"], "interval": fence["timer"].get("interval") or service["backupInterval"], "enabled": timer["enabled"]}}
            except (EngineError, StorageError, StopIteration):
                pass
        elif action == "compose-register":
            try:
                service = self._service(params["serviceId"])
                if service["fingerprint"] == params["fingerprint"]:
                    settled = {"status": "succeeded", "result": {"serviceId": service["id"], "registered": True, "projectId": service["projectId"], "fingerprint": service["fingerprint"]}}
            except (EngineError, StorageError):
                pass
        elif action == "compose-schedule":
            timer = self._timer(params["serviceId"])
            if timer["enabled"] and timer["interval"] == params["interval"]:
                settled = {"status": "succeeded", "result": {"serviceId": params["serviceId"], "interval": params["interval"], "enabled": True}}
        if settled:
            value.update(settled)
            atomic(self._journal_path(identity), value)
            return settled
        value.update(status="outcome_unknown", error=value.get("error", "operation_outcome_unknown"))
        atomic(self._journal_path(identity), value)
        return self._safe_operation(value)

    def inspect_operation(self, identity):
        if not is_uuid(identity):
            return None
        try:
            with self.lock():
                # Reject misplaced journals before recovery can perform any unrelated compensation.
                try:
                    self._inspection_journal(identity)
                except EngineError as error:
                    return {"status": "outcome_unknown", "error": error.code}
                self._recover_locked()
                return self._inspect_locked(identity)
        except (StorageError, SealError, ArchiveError) as error:
            raise EngineError(error.code, unknown=getattr(error, "unknown", False)) from None

    def reconcile(self, job):
        # Redacted terminal wire jobs are valid inspection inputs. No envelope parsing/decryption/replay.
        identity = job.get("id") if isinstance(job, dict) else None
        return self.inspect_operation(identity) or {"status": "outcome_unknown", "error": "operation_not_found"}

    def _observe_addresses(self):
        values = json.loads(self._run(["ip", "--json", "address", "show", "scope", "global"], timeout=3))
        if not isinstance(values, list):
            raise ValueError()
        addresses, partial = set(), len(values) > 1000
        for interface in values[:1000]:
            if not isinstance(interface, dict) or not isinstance(interface.get("addr_info"), list):
                partial = True
                continue
            name = interface.get("ifname", "")
            if not isinstance(name, str):
                partial = True
                continue
            entries = interface["addr_info"]
            partial = partial or len(entries) > 1000 or any(not isinstance(item, dict) or not isinstance(item.get("local"), str) or not isinstance(item.get("family"), str) or item.get("family") not in {"inet", "inet6"} or item.get("scope") != "global" for item in entries[:1000])
            linkinfo = interface.get("linkinfo") or {}
            if not isinstance(linkinfo, dict):
                partial = True
                linkinfo = {}
            if re.match(r"^(?:docker[0-9]*|br[-0-9]|bridge|veth|cni|virbr)", name) or linkinfo.get("info_kind") == "bridge":
                continue
            for item in entries[:1000]:
                if (not isinstance(item, dict) or not isinstance(item.get("family"), str) or item.get("family") not in {"inet", "inet6"} or item.get("scope") != "global" or not isinstance(item.get("local"), str)):
                    partial = True
                    continue
                try:
                    address = ipaddress.ip_address(item["local"])
                except ValueError:
                    partial = True
                    continue
                if (address.version == 4) != (item["family"] == "inet"):
                    partial = True
                    continue
                if address.is_global and not (address.is_private or address.is_reserved or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified):
                    addresses.add(str(address))
        self._local.addresses_partial = partial
        return sorted(addresses)[:20]

    def _observe_operations(self, output):
        journals = []
        for index, path in enumerate((self.state / "operations").glob("*.json")):
            if index >= 10000:
                output["operationOverflow"] = True
                break
            journals.append(read(path))
        pending = sorted([v for v in journals if v.get("status") in {"running", "outcome_unknown"}], key=lambda value: (value.get("status") != "outcome_unknown", value.get("at", ""), value.get("id", "")))
        terminal = sorted([v for v in journals if v not in pending], key=lambda v: v.get("at", ""), reverse=True)
        if len(pending) > 200:
            output["operationOverflow"] = True
        active_lock = False
        try:
            with self.lock():
                pass
        except EngineError as error:
            active_lock = error.code == "operation_busy"
        for value in (pending + terminal)[:200]:
            safe = self._safe_operation(value)
            if value.get("status") == "running" and active_lock:
                safe["status"] = "running"
            output["operations"].append({"id": value["id"], "action": value["action"], "origin": value.get("origin", "controller"), **safe})

    def _observe_local(self):
        output = {"ready": False, "error": "compose_recovery_required", "projects": [], "storages": [], "services": [], "restores": [], "addresses": [], "operations": []}
        try:
            # Never create a new key while recovery is unresolved.
            if self.sealer.path.exists() and not self.sealer.path.is_symlink():
                output["key"] = self.sealer.public()
            for path in sorted(self.storage.directory.glob("*.json"))[:8]:
                binding = read(path)
                safe = {key: binding[key] for key in ("repositoryId", "bindingGeneration", "requestId") if key in binding}
                safe.update(id=binding["metadata"]["id"], storageId=binding["metadata"]["id"], connected=binding.get("status") == "connected")
                if not safe["connected"]:
                    safe["error"] = "binding_outcome_unknown" if binding.get("status") == "init_pending" else "storage_not_connected"
                output["storages"].append(safe)
            for path in sorted((self.state / "services").glob("*.json"))[:20]:
                service = read(path)
                safe = {key: service[key] for key in ("id", "projectId", "fingerprint", "storageId", "backupInterval", "sourceState", "latestBackup", "setupState", "activeRestoreId") if key in service}
                safe.update(serviceId=service["id"], snapshots=[], snapshotError="snapshot_inventory_unavailable")
                output["services"].append(safe)
            for path in sorted((self.state / "restores").glob("*.json"))[-100:]:
                record = read(path)
                if record.get("state") != "removed":
                    output["restores"].append(self._safe_restore(record) | {"id": record["id"]})
            self._observe_operations(output)
        except (EngineError, StorageError, SealError, OSError, ValueError, KeyError, TypeError):
            # Keep the conservative error and every already-read safe field.
            pass
        return output

    def observe(self, *, local_only=False):
        if local_only:
            return self._observe_local()
        self._local.observation_deadline = time.monotonic() + 25
        output = {"ready": False, "projects": [], "storages": [], "services": [], "restores": [], "addresses": [], "operations": []}
        try:
            try:
                output["addresses"] = self._observe_addresses()
                if self._local.addresses_partial:
                    output["addressesPartial"] = True
                    output["addressesError"] = "address_inventory_partial"
            except (EngineError, ValueError, KeyError, TypeError):
                output["addressesError"] = "address_inventory_unavailable"
            output["key"] = self.sealer.public()
            containers = self._containers()
            names = sorted({c.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") for c in containers})
            if len(names) > 20:
                raise EngineError("discovery_limit")
            for name in names:
                try:
                    output["projects"].append(self._safe_project(self._project(name, containers)))
                except EngineError as error:
                    output["projects"].append({"id": name, "name": name, "supported": False, "reasons": [error.code], "services": [], "mounts": [], "estimatedBytes": 0})
            for path in sorted(self.storage.directory.glob("*.json"))[:8]:
                binding = read(path)
                safe = {k: binding[k] for k in ("repositoryId", "bindingGeneration", "requestId") if k in binding}
                safe.update(id=binding["metadata"]["id"], storageId=binding["metadata"]["id"], connected=binding.get("status") == "connected")
                if not safe["connected"]:
                    safe["error"] = "binding_outcome_unknown" if binding.get("status") == "init_pending" else "storage_not_connected"
                output["storages"].append(safe)
            for path in sorted((self.state / "services").glob("*.json"))[:20]:
                service = read(path)
                safe = {"id": service["id"], "serviceId": service["id"], "projectId": service["projectId"], "fingerprint": service["fingerprint"], "storageId": service["storageId"], "backupInterval": service["backupInterval"], "sourceState": service["sourceState"], "schedule": self._timer(service["id"]), "snapshots": []}
                for key in ("latestBackup", "setupState", "activeRestoreId"):
                    if key in service:
                        safe[key] = service[key]
                try:
                    with self.lock():
                        safe["snapshots"] = self._snapshots(self.storage.binding(service["storageId"]), service["id"])
                except (StorageError, EngineError):
                    safe["snapshotError"] = "snapshot_inventory_unavailable"
                output["services"].append(safe)
            for path in sorted((self.state / "restores").glob("*.json"))[-100:]:
                record = read(path)
                if record.get("state") != "removed":
                    output["restores"].append(self._safe_restore(record) | {"id": record["id"]})
            self._observe_operations(output)
            try:
                with self.lock():
                    self.storage.preflight(timeout=max(1, self._local.observation_deadline - time.monotonic()))
            except EngineError as error:
                if error.code != "operation_busy":
                    raise
            output["ready"] = True
        except (EngineError, StorageError, SealError, ArchiveError) as error:
            output["error"] = error.code
        except (OSError, ValueError, KeyError, TypeError):
            output["error"] = "managed_observation_failed"
        finally:
            self._local.observation_deadline = None
        return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("backup",))
    parser.add_argument("--state", required=True)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--service-id", required=True)
    args = parser.parse_args()
    try:
        engine = ManagedEngine({"nodeId": args.node_id, "origin": "timer"}, args.state)
        service = engine._service(args.service_id)
        identity = str(uuid.uuid4())
        job = {"id": identity, "nonce": uuid.uuid4().hex, "action": "compose-backup", "parameters": {"serviceId": args.service_id, "storageId": service["storageId"]}}
        result = engine.execute(job)
        print(json.dumps({"id": identity, "status": "succeeded", "result": result}))
        return 0
    except (EngineError, StorageError, SealError, ArchiveError) as error:
        print(json.dumps({"status": "outcome_unknown" if getattr(error, "unknown", False) else "failed", "error": error.code}))
        return 75 if error.code == "operation_busy" else 1


if __name__ == "__main__":
    raise SystemExit(main())
