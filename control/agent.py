#!/usr/bin/env python3
"""Outbound host service for the bundled RolyPolyOps recovery package."""
import argparse
import datetime as dt
import fcntl
import hashlib
import secrets
import json
import os
from pathlib import Path
import queue
import re
import shutil
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = "0.1.0"
LAB = "/usr/local/sbin/rolypolyops-lab"
LAB_CONFIG = "/etc/rolypolyops/lab.env"
LAB_STATE = Path("/var/lib/rolypolyops")
PREVIEWS = Path("/var/lib/rolypolyops-control-previews")
ACTIONS = {"backup", "verify", "restore-check", "restore-preview", "remove-preview", "set-schedule"}
SNAPSHOT = re.compile(r"^[a-f0-9]{64}$")
RESTORE_CHECKS = {"database-values", "file-sha256", "application-http", "app-version", "image-ids", "fresh-mounts", "runtime-restrictions"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "Redirect forbidden", headers, fp)


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / ("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_json(path, default=None):
    try:
        value = json.loads(Path(path).read_text())
        return value if isinstance(value, dict) else default
    except (OSError, ValueError):
        return default


def run(args, timeout=12, env=None):
    return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=timeout, env=env, check=False)


def package_env():
    # This root-owned configuration is never populated from browser shell input.
    p = Path(LAB_CONFIG)
    if not p.is_file() or p.stat().st_uid != 0 or p.stat().st_mode & 0o022:
        return None
    r = run(["/bin/bash", "-c", 'set -a; source "$1"; env -0', "rpo", LAB_CONFIG])
    if r.returncode:
        return None
    values = dict(item.split("=", 1) for item in r.stdout.split("\0") if "=" in item)
    env = os.environ.copy()
    env.update({k: v for k, v in values.items() if k.startswith(("RPO_", "RESTIC_"))})
    return env


def timer_status(name):
    try:
        r = run(["systemctl", "show", name, "-p", "ActiveState", "-p", "UnitFileState", "-p", "NextElapseUSecRealtime"])
        d = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
        raw = d.get("NextElapseUSecRealtime", "")
        try:
            next_run = dt.datetime.strptime(raw, "%a %Y-%m-%d %H:%M:%S %Z").replace(tzinfo=dt.timezone.utc).isoformat()
        except ValueError:
            next_run = None
        result = {"enabled": d.get("UnitFileState") == "enabled" and d.get("ActiveState") == "active", "next": next_run}
        if name == "rolypolyops-backup.timer":
            unit = run(["systemctl", "cat", name]).stdout
            calendars = []
            for line in unit.splitlines():
                if line.startswith("OnCalendar="):
                    value = line.split("=", 1)[1].strip()
                    if value:
                        calendars.append(value)
                    else:
                        calendars = []
            if len(calendars) == 1:
                value = calendars[0]
                if value == "hourly": result["interval"] = "hourly"
                elif value == "daily" or value == "*-*-* 02:00:00 UTC": result["interval"] = "daily"
                elif value == "*-*-* *:00/15:00 UTC": result["interval"] = "15min"
        return result
    except (OSError, subprocess.TimeoutExpired):
        return {"enabled": False, "next": None}


def metadata(value):
    if not isinstance(value, dict):
        return None
    return {k: value[k] for k in ("status", "snapshot", "at", "checks") if k in value}


def has_checks(value, required):
    checks = value.get("checks") if isinstance(value, dict) else None
    return isinstance(checks, list) and all(isinstance(item, str) for item in checks) and required <= set(checks)


def observe(state):
    env = package_env()
    supported = bool(env and Path(LAB).is_file())
    snapshots, snapshot_error = [], False
    if supported:
        try:
            r = run(["restic", "snapshots", "--json", "--tag", "rolypolyops-demo"], timeout=15, env=env)
            if r.returncode:
                raise ValueError()
            for s in json.loads(r.stdout)[-100:]:
                if SNAPSHOT.fullmatch(s.get("id", "")):
                    snapshots.append({"id": s["id"], "time": s["time"]})
        except (OSError, ValueError, subprocess.TimeoutExpired):
            snapshot_error = True
    active = read_json(LAB_STATE / "active.json") or read_json(LAB_STATE / "standby.json") or {}
    port = active.get("port") or int((env or {}).get("RPO_SOURCE_PORT", "8080"))
    healthy, label, service_version = None, "", ""
    try:
        if not isinstance(port, int) or not 1024 <= port <= 65535:
            raise ValueError()
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=4) as response:
            data = json.load(response)
            healthy = response.status == 200 and data.get("healthy") is True
            label, service_version = str(data.get("node", ""))[:100], str(data.get("version", ""))[:30]
    except (OSError, ValueError):
        healthy = False if supported else None
    disk = shutil.disk_usage("/var/lib")
    preview = read_json(state / "preview.json")
    return {"observedAt": now(), "supported": supported, "version": VERSION,
            "serviceHealthy": healthy, "serviceLabel": label, "serviceVersion": service_version,
            "disk": {"total": disk.total, "free": disk.free}, "snapshots": snapshots,
            "lastBackup": metadata(read_json(LAB_STATE / "last-backup.json")),
            "lastRestore": metadata(read_json(LAB_STATE / "last-restore-check.json")),
            "schedule": {"backup": timer_status("rolypolyops-backup.timer"),
                         "restore": timer_status("rolypolyops-restore-check.timer")},
            "preview": metadata(preview) | {"id": preview["id"], "createdAt": preview.get("at")} if preview else None,
            "error": "snapshot_inventory_unavailable" if snapshot_error else None}


def validate_job(job):
    if not isinstance(job, dict) or set(job) - {"id", "nonce", "action", "snapshotId", "parameters", "reconcile"}:
        raise ValueError("invalid_job")
    if str(uuid.UUID(job["id"])) != job["id"] or job.get("action") not in ACTIONS:
        raise ValueError("invalid_job")
    if not isinstance(job.get("nonce"), str) or not 16 <= len(job["nonce"]) <= 256:
        raise ValueError("invalid_job")
    if job["action"] in {"restore-check", "restore-preview"} and not SNAPSHOT.fullmatch(job.get("snapshotId", "")):
        raise ValueError("invalid_snapshot")
    if job["action"] == "set-schedule" and job.get("parameters", {}).get("interval") not in {"15min", "hourly", "daily"}:
        raise ValueError("invalid_schedule")
    expected_parameters = {"interval"} if job["action"] == "set-schedule" else ({"previewId"} if job["action"] == "remove-preview" else set())
    if not isinstance(job.get("parameters", {}), dict) or set(job.get("parameters", {})) != expected_parameters:
        raise ValueError("invalid_parameters")


class Agent:
    def __init__(self, config, state, allow_http=False):
        self.config, self.state = config, Path(state)
        parsed = urllib.parse.urlsplit(config["controller"])
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Invalid controller URL")
        if parsed.scheme != "https" and not (allow_http and parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}):
            raise ValueError("Controller must use HTTPS")
        self.origin = config["controller"].rstrip("/")
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state / "jobs").mkdir(exist_ok=True, mode=0o700)
        self.seen = {}
        self.instance = ""
        self.ensure_identity()
        self.lock, self.worker = threading.Lock(), None
        self.inspection_worker = None
        self.inventory_complete = False
        self.status = {"supported": False, "observedAt": now(), "error": "observation_pending"}
        # An interrupted receipt is never treated as permission to replay a mutation.
        for p in (self.state / "jobs").glob("*.json"):
            receipt = read_json(p)
            if receipt and receipt.get("status") == "running":
                receipt.update(status="outcome_unknown", stage="reconciliation_required", error="agent_restarted")
                atomic(p, receipt)

    def ensure_identity(self):
        directory = self.state / "jobs"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        marker = directory / "incarnation"
        identity = read_json(marker)
        try:
            valid_identity = bool(identity and str(uuid.UUID(identity.get("id", ""))) == identity["id"])
        except (ValueError, TypeError, AttributeError):
            valid_identity = False
        index = self.state / "seen.jsonl"
        rotate = not valid_identity or not index.exists()
        corrupt = False
        if not self.seen and index.exists():
            try:
                for line in index.read_text().splitlines():
                    value = json.loads(line)
                    if not isinstance(value, dict) or not isinstance(value.get("id"), str) or not isinstance(value.get("fingerprint"), str):
                        raise ValueError()
                    self.seen[value["id"]] = value["fingerprint"]
            except (OSError, ValueError):
                rotate, corrupt = True, True
        if rotate:
            identity = {"id": str(uuid.uuid4())}
            atomic(marker, identity)
            # Changing incarnation makes preexisting controller assignments uncertain.
            # The independent seen index also survives loss of just the receipt directory.
            with index.open("a") as f:
                f.flush()
                os.fsync(f.fileno())
            if corrupt:
                for path in directory.glob("*.json"):
                    receipt = read_json(path)
                    if receipt and isinstance(receipt.get("id"), str) and isinstance(receipt.get("fingerprint"), str):
                        self.seen[receipt["id"]] = receipt["fingerprint"]
                with index.open("w") as f:
                    for key, fingerprint in self.seen.items():
                        f.write(json.dumps({"id": key, "fingerprint": fingerprint}) + "\n")
                    f.flush()
                    os.fsync(f.fileno())
        self.instance = identity["id"]

    def request(self, path, data):
        raw = json.dumps(data).encode()
        req = urllib.request.Request(self.origin + path, raw,
                {"Content-Type": "application/json", "Authorization": "Bearer " + self.config["token"]}, method="POST")
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=20) as response:
            body = response.read(262145)
            if len(body) > 262144:
                raise ValueError("Response too large")
            return json.loads(body)

    def collect(self):
        while True:
            try:
                status = observe(self.state)
                with self.lock:
                    self.status = status
            except Exception:
                with self.lock:
                    self.status = {"supported": False, "observedAt": now(), "error": "observation_failed"}
            time.sleep(15)

    def reports(self):
        result = []
        for p in sorted((self.state / "jobs").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            receipt = read_json(p)
            if receipt and not receipt.get("acknowledged"):
                result.append({k: receipt[k] for k in ("id", "nonce", "status", "stage", "result", "error", "inspected") if k in receipt})
                if len(result) == 100:
                    break
        return result

    def start(self, job):
        validate_job(job)
        path = self.state / "jobs" / (job["id"] + ".json")
        existing = read_json(path)
        envelope = {k: v for k, v in job.items() if k != "reconcile"}
        fingerprint = hashlib.sha256(json.dumps(envelope, sort_keys=True).encode()).hexdigest()
        if existing:
            if existing.get("fingerprint") != fingerprint:
                raise ValueError("Job identity conflict")
            if job.get("reconcile"):
                self.reconcile(job, path, existing)
            return
        if self.worker and self.worker.is_alive():
            raise ValueError("Agent busy")
        if self.inspection_worker and self.inspection_worker.is_alive():
            raise ValueError("Inspection busy")
        if any(r["status"] == "outcome_unknown" for r in self.reports()):
            raise ValueError("Reconciliation required")
        receipt = {"id": job["id"], "nonce": job["nonce"], "status": "running", "stage": "starting", "fingerprint": fingerprint, "startedAt": now(), "action": job["action"], "envelope": envelope}
        if job.get("reconcile") or job["id"] in self.seen:
            if job["id"] in self.seen and self.seen[job["id"]] != fingerprint:
                raise ValueError("Job identity conflict")
            receipt.update(status="outcome_unknown", stage="interrupted", error="receipt_missing")
            atomic(path, receipt)
            return
        with (self.state / "seen.jsonl").open("a") as index:
            index.write(json.dumps({"id": job["id"], "fingerprint": fingerprint}) + "\n")
            index.flush()
            os.fsync(index.fileno())
        self.seen[job["id"]] = fingerprint
        atomic(path, receipt)
        self.worker = threading.Thread(target=self.execute, args=(job, path, receipt), daemon=True)
        self.worker.start()

    def command(self, args, receipt, path, env=None):
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, env=env, start_new_session=True)
        lines = queue.Queue()
        def reader():
            for line in iter(process.stdout.readline, b""):
                lines.put(line.decode("utf-8", "replace"))
            lines.put(None)
        threading.Thread(target=reader, daemon=True).start()
        deadline, tail = time.monotonic() + 1200, []
        while True:
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                raise RuntimeError("operation_timeout")
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                continue
            if line is None:
                break
            tail.append(line[-8192:])
            tail = tail[-32:]
            stage = None
            lower = line.lower()
            if "restoring" in lower or "restored" in lower:
                stage = "restoring"
            elif "check all" in lower or "read all" in lower or "checks" in lower:
                stage = "checking"
            elif "stopping" in lower:
                stage = "capturing"
            elif "starting" in lower:
                stage = "validating"
            if stage and receipt.get("stage") != stage:
                receipt["stage"] = stage
                atomic(path, receipt)
        process.wait()
        if process.returncode:
            # Raw engine output can contain credentials, data and host paths.
            raise RuntimeError("operation_failed")
        for line in reversed(tail):
            try:
                value = json.loads(line)
                if isinstance(value, dict) and "status" in value:
                    return value
            except ValueError:
                pass
        return {}

    def execute(self, job, path, receipt):
        start = time.monotonic()
        try:
            action, env = job["action"], package_env()
            if not env or not Path(LAB).is_file():
                raise RuntimeError("unsupported_package")
            if action in {"backup", "set-schedule"} and self.config["role"] != "primary":
                raise RuntimeError("primary_required")
            env["RPO_OPERATION_ID"] = job["id"]
            if action in {"restore-check", "restore-preview"}:
                inventory = run(["restic", "snapshots", "--json", job["snapshotId"]], timeout=30, env=env)
                if inventory.returncode or not any(s.get("id") == job["snapshotId"] for s in json.loads(inventory.stdout)):
                    raise RuntimeError("snapshot_unavailable")
            if action in {"backup", "verify", "restore-check"}:
                args = [LAB, action] + ([job["snapshotId"]] if action == "restore-check" else [])
                raw = self.command(args, receipt, path, env=env)
                result = metadata(raw) or {}
                if action == "verify":
                    result = {"verified": True, "checks": ["repository-data"], "at": now()}
                if action == "restore-check" and result.get("snapshot") != job["snapshotId"]:
                    raise RuntimeError("result_snapshot_mismatch")
            elif action == "restore-preview":
                if read_json(self.state / "preview.json"):
                    raise RuntimeError("preview_already_exists")
                base = PREVIEWS / job["id"]
                if base.exists():
                    raise RuntimeError("preview_directory_exists")
                env.update(RPO_STATE_DIR=str(base), RPO_RESTORE_PORT="18082", RPO_PREVIEW="1")
                raw = self.command([LAB, "restore-standby", job["snapshotId"]], receipt, path, env=env)
                private = read_json(base / "standby.json")
                if not private or private.get("snapshot") != job["snapshotId"]:
                    raise RuntimeError("preview_result_missing")
                private.update(id=job["id"], base=str(base))
                atomic(self.state / "preview.json", private)
                result = metadata(private) | {"preview": metadata(private) | {"id": job["id"], "createdAt": private.get("at")}}
            elif action == "remove-preview":
                preview = read_json(self.state / "preview.json")
                if not preview:
                    raise RuntimeError("preview_missing")
                if job["parameters"]["previewId"] != preview.get("id"):
                    raise RuntimeError("preview_ownership_invalid")
                receipt["removingPreview"] = {k: preview[k] for k in ("id", "base", "root", "project")}
                atomic(path, receipt)
                base, root = Path(preview["base"]).resolve(), Path(preview["root"]).resolve()
                if base.parent != PREVIEWS.resolve() or str(uuid.UUID(base.name)) != base.name or not root.is_relative_to(base):
                    raise RuntimeError("preview_ownership_invalid")
                project = preview["project"]
                if not re.fullmatch(r"rpo-restore-[a-z0-9]+", project):
                    raise RuntimeError("preview_ownership_invalid")
                info = run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project])
                for container in info.stdout.splitlines():
                    inspected = run(["docker", "inspect", container])
                    item = json.loads(inspected.stdout)[0]
                    if any(m["Type"] == "bind" and not Path(m["Source"]).resolve().is_relative_to(base) for m in item["Mounts"]):
                        raise RuntimeError("preview_ownership_invalid")
                self.command(self.compose_args(root / "service", project, "down", "--timeout", "20"), receipt, path)
                shutil.rmtree(base)
                (self.state / "preview.json").unlink()
                result = {"removed": True, "at": now()}
            else:
                interval = job["parameters"]["interval"]
                calendar = {"15min": "*-*-* *:00/15:00 UTC", "hourly": "hourly", "daily": "*-*-* 02:00:00 UTC"}[interval]
                drop = Path("/etc/systemd/system/rolypolyops-backup.timer.d")
                drop.mkdir(parents=True, exist_ok=True)
                target = drop / "schedule.conf"
                temporary = drop / "schedule.conf.tmp"
                temporary.write_text("[Timer]\nOnCalendar=\nOnCalendar=" + calendar + "\n")
                temporary.chmod(0o644)
                os.replace(temporary, target)
                for args in (["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "rolypolyops-backup.timer"], ["systemctl", "restart", "rolypolyops-backup.timer"]):
                    self.command(args, receipt, path)
                schedule = timer_status("rolypolyops-backup.timer")
                if not schedule["enabled"]:
                    raise RuntimeError("schedule_not_enabled")
                result = {"interval": interval, "enabled": True, "schedule": schedule, "at": now()}
            result["durationSeconds"] = round(time.monotonic() - start, 2)
            receipt.update(status="succeeded", stage="completed", result=result)
        except Exception as error:
            code = str(error) if isinstance(error, RuntimeError) else "operation_failed"
            unknown = code == "operation_timeout"
            receipt.update(status="outcome_unknown" if unknown else "failed", stage="interrupted" if unknown else "completed", error=code)
        atomic(path, receipt)

    def reconcile(self, job, path, receipt):
        if receipt["status"] in {"succeeded", "failed"}:
            receipt.pop("acknowledged", None)
            atomic(path, receipt)
            return
        if self.worker and self.worker.is_alive():
            return
        # Never release the controller's mutation lock based on a timeout alone.
        lock = os.open("/run/lock/rolypolyops-lab.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            evidence = read_json(LAB_STATE / "operation-proofs" / (job["id"] + ".json"))
            valid_proof = bool(evidence and evidence.get("operationId") == job["id"] and (
                (job["action"] == "backup" and SNAPSHOT.fullmatch(str(evidence.get("snapshot", "")))) or
                (job["action"] == "verify" and has_checks(evidence, {"repository-data"})) or
                (job["action"] == "restore-check" and evidence.get("snapshot") == job["snapshotId"] and has_checks(evidence, RESTORE_CHECKS))))
            if valid_proof:
                result = metadata(evidence) or {}
                if job["action"] == "verify": result.update(verified=True, checks=["repository-data"])
                receipt.update(status="succeeded", stage="completed", result=result)
            elif job["action"] == "set-schedule" and (timer := timer_status("rolypolyops-backup.timer"))["enabled"] and timer.get("interval") == job["parameters"]["interval"]:
                receipt.update(status="succeeded", stage="completed", result={"interval": timer["interval"], "enabled": True, "at": now()})
            elif job["action"] == "restore-preview":
                base = PREVIEWS / job["id"]
                proof = read_json(base / "operation-proofs" / (job["id"] + ".json"))
                private = read_json(base / "standby.json")
                if proof and private and proof.get("operationId") == job["id"] and private.get("snapshot") == job["snapshotId"] and Path(private.get("root", "")).resolve().is_relative_to(base.resolve()):
                    response = run(["docker", "inspect", private["project"] + "-web-1", private["project"] + "-db-1"])
                    info = json.loads(response.stdout) if response.returncode == 0 else []
                    if len(info) == 2 and all(i.get("State", {}).get("Health", {}).get("Status") == "healthy" for i in info):
                        private.update(id=job["id"], base=str(base))
                        atomic(self.state / "preview.json", private)
                        receipt.update(status="succeeded", stage="completed", result=metadata(private) | {"preview": metadata(private) | {"id": job["id"], "createdAt": private.get("at")}})
            elif job["action"] == "remove-preview" and (old := receipt.get("removingPreview")):
                base = Path(old["base"]).resolve()
                if base.parent == PREVIEWS.resolve() and not base.exists() and re.fullmatch(r"rpo-restore-[a-z0-9]+", old["project"]):
                    live = run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + old["project"]])
                    if live.returncode == 0 and not live.stdout.strip():
                        current = read_json(self.state / "preview.json")
                        if current and current.get("id") == old["id"]:
                            (self.state / "preview.json").unlink()
                        receipt.update(status="succeeded", stage="completed", result={"removed": True, "at": now()})
            else:
                receipt.update(status="outcome_unknown", stage="interrupted", error="reconciliation_required")
            receipt.pop("acknowledged", None)
            if receipt["status"] not in {"succeeded", "failed"}:
                receipt.update(status="outcome_unknown", stage="interrupted", error="reconciliation_required")
            atomic(path, receipt)
        except BlockingIOError:
            pass
        except (KeyError, TypeError, ValueError, AttributeError):
            receipt.update(status="outcome_unknown", stage="interrupted", error="reconciliation_state_invalid")
            atomic(path, receipt)
        finally:
            os.close(lock)

    @staticmethod
    def compose_args(service, project, *args):
        result = ["docker", "compose", "-f", str(service / "compose.yaml")]
        if (service / "rpo.isolation.json").is_file():
            result += ["-f", str(service / "rpo.isolation.json")]
        return result + ["--env-file", str(service / ".env"), "--project-directory", str(service), "-p", project] + list(args)

    def owned_temporary_paths(self, identity):
        paths = []
        roots = [LAB_STATE, PREVIEWS / identity]
        for base in roots:
            if base.is_symlink():
                raise RuntimeError("inspection_ownership_invalid")
            for prefix in ("capture.*", "restore.*"):
                for directory in base.glob(prefix):
                    marker = read_json(directory / ".operation.json")
                    if not marker or marker.get("id") != identity:
                        continue
                    if marker.get("action") not in {"backup", "restore-check", "restore-standby"}:
                        raise RuntimeError("inspection_ownership_invalid")
                    if directory.is_symlink() or directory.resolve().parent != base.resolve():
                        raise RuntimeError("inspection_ownership_invalid")
                    # A manually retained live standby is never in inspection cleanup scope.
                    if marker.get("action") == "restore-standby" and base == LAB_STATE:
                        raise RuntimeError("inspection_live_standby")
                    paths.append(directory)
        return paths

    def cleanup_temporary(self, identity):
        paths = self.owned_temporary_paths(identity)
        preview = read_json(self.state / "preview.json")
        if preview and preview.get("id") == identity:
            base = (PREVIEWS / identity).resolve()
            root = Path(preview.get("root", "")).resolve()
            if Path(preview.get("base", "")).resolve() != base or root.parent != base or not root.name.startswith("restore."):
                raise RuntimeError("inspection_ownership_invalid")
            env = package_env() or {}
            active = read_json(LAB_STATE / "active.json") or read_json(LAB_STATE / "standby.json") or {}
            for protected in [env.get("RPO_ROOT"), str(Path(active["root"]) / "service") if active.get("root") else None]:
                if protected and Path(protected).resolve().is_relative_to(base):
                    raise RuntimeError("inspection_live_standby")
            if root.exists() and root not in [p.resolve() for p in paths]:
                paths.append(root)
        for directory in paths:
            if directory.name.startswith("restore."):
                project = "rpo-restore-" + directory.name.split(".", 1)[1].lower()
                if not re.fullmatch(r"rpo-restore-[a-z0-9]+", project):
                    raise RuntimeError("inspection_ownership_invalid")
                response = run(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + project])
                if response.returncode:
                    raise RuntimeError("inspection_docker_unavailable")
                identities = response.stdout.split()
                networks = set()
                if identities:
                    detail = run(["docker", "inspect"] + identities)
                    if detail.returncode:
                        raise RuntimeError("inspection_docker_unavailable")
                    items = json.loads(detail.stdout)
                    actual_ids = {item["Id"] for item in items}
                    for item in items:
                        if item.get("Config", {}).get("Labels", {}).get("com.docker.compose.project") != project:
                            raise RuntimeError("inspection_ownership_invalid")
                        mounts = item.get("Mounts", [])
                        if not mounts or any(m["Type"] != "bind" or not Path(m["Source"]).resolve().is_relative_to(directory.resolve()) for m in mounts if m["Type"] != "tmpfs"):
                            raise RuntimeError("inspection_ownership_invalid")
                        networks.update(item.get("NetworkSettings", {}).get("Networks", {}))
                    for network in networks:
                        detail = run(["docker", "network", "inspect", network])
                        data = json.loads(detail.stdout)[0] if detail.returncode == 0 else {}
                        if data.get("Labels", {}).get("com.docker.compose.project") != project or set(data.get("Containers", {})) - actual_ids:
                            raise RuntimeError("inspection_ownership_invalid")
                    if run(["docker", "rm", "-f"] + identities, timeout=45).returncode:
                        raise RuntimeError("inspection_cleanup_failed")
                # Networks can survive a terminated compose-down after containers disappeared.
                detail = run(["docker", "network", "ls", "-q", "--filter", "label=com.docker.compose.project=" + project])
                if detail.returncode:
                    raise RuntimeError("inspection_docker_unavailable")
                for network in detail.stdout.split():
                    check = run(["docker", "network", "inspect", network])
                    data = json.loads(check.stdout)[0] if check.returncode == 0 else {}
                    if data.get("Containers") or data.get("Labels", {}).get("com.docker.compose.project") != project:
                        raise RuntimeError("inspection_ownership_invalid")
                    if run(["docker", "network", "rm", network]).returncode:
                        raise RuntimeError("inspection_cleanup_failed")
            shutil.rmtree(directory)
        if preview and preview.get("id") == identity:
            base = PREVIEWS / identity
            if base.exists(): shutil.rmtree(base)
            (self.state / "preview.json").unlink()

    def inspect_orphan(self, identity, nonce=None):
        try:
            if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
                return False
            if self.worker and self.worker.is_alive():
                return False
            path = self.state / "jobs" / (identity + ".json")
            receipt = read_json(path)
            if receipt and nonce and receipt.get("nonce") != nonce:
                return False
            if receipt and receipt.get("status") in {"succeeded", "failed"}:
                receipt.update(inspected=True)
                receipt.pop("acknowledged", None)
                atomic(path, receipt)
                return True
            if receipt and isinstance(receipt.get("envelope"), dict):
                self.reconcile(receipt["envelope"], path, receipt)
                receipt = read_json(path)
                if receipt and receipt.get("status") in {"succeeded", "failed"}:
                    receipt.update(inspected=True)
                    receipt.pop("acknowledged", None)
                    atomic(path, receipt)
                    return True
            # A completed preview can outlive a lost agent receipt or final acknowledgment.
            candidate = read_json(PREVIEWS / identity / "standby.json")
            if candidate and SNAPSHOT.fullmatch(str(candidate.get("snapshot", ""))):
                temporary = receipt or {"id": identity, "nonce": nonce or secrets.token_urlsafe(32), "status": "outcome_unknown"}
                self.reconcile({"id": identity, "action": "restore-preview", "snapshotId": candidate["snapshot"], "parameters": {}}, path, temporary)
                receipt = read_json(path)
                if receipt and receipt.get("status") in {"succeeded", "failed"}:
                    receipt.update(inspected=True)
                    receipt.pop("acknowledged", None)
                    atomic(path, receipt)
                    return True
            lock = os.open("/run/lock/rolypolyops-lab.lock", os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                proof = read_json(LAB_STATE / "operation-proofs" / (identity + ".json"))
                if proof and proof.get("operationId") == identity and (
                    (proof.get("status") == "backup-created" and SNAPSHOT.fullmatch(str(proof.get("snapshot", "")))) or
                    (proof.get("status") == "repository-verified" and has_checks(proof, {"repository-data"})) or
                    (proof.get("status") == "restore-check-passed" and has_checks(proof, RESTORE_CHECKS))):
                    state, result, error = "succeeded", metadata(proof), None
                else:
                    self.cleanup_temporary(identity)
                    state, result, error = "failed", {"inspectedAt": now(), "originalActionRepeated": False}, "interrupted_result_unverified"
                receipt = receipt or {"id": identity, "nonce": nonce or secrets.token_urlsafe(32)}
                receipt.update(status=state, stage="completed", result=result, inspected=True)
                receipt.pop("acknowledged", None)
                if error: receipt["error"] = error
                else: receipt.pop("error", None)
                atomic(path, receipt)
                return True
            finally:
                os.close(lock)
        except (OSError, ValueError, RuntimeError, TypeError, AttributeError, KeyError, subprocess.TimeoutExpired):
            return False

    def inspect_batch(self, identities, nonces, overflow):
        self.inventory_complete = False
        for identity in identities[:128]:
            self.inspect_orphan(identity, nonces.get(identity))
        if not overflow:
            return
        uncertain = [r["id"] for r in self.reports() if r["status"] not in {"succeeded", "failed"}]
        for base in [LAB_STATE] + ([p for p in PREVIEWS.iterdir() if p.is_dir() and not p.is_symlink()] if PREVIEWS.exists() else []):
            for marker in list(base.glob("restore.*/.operation.json")) + list(base.glob("capture.*/.operation.json")):
                value = read_json(marker)
                if value and value.get("id") not in uncertain:
                    uncertain.append(value["id"])
        for identity in uncertain[:128]:
            if not self.inspect_orphan(identity):
                return
        if len(uncertain) > 128 or (self.worker and self.worker.is_alive()):
            return
        lock = os.open("/run/lock/rolypolyops-lab.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.inventory_complete = not any(r["status"] not in {"succeeded", "failed"} for r in self.reports())
        except BlockingIOError:
            pass
        finally:
            os.close(lock)

    def acknowledge(self, identities, submitted):
        for identity in identities:
            if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9-]{36}", identity):
                continue
            path = self.state / "jobs" / (identity + ".json")
            receipt = read_json(path)
            if receipt and receipt.get("status") in {"succeeded", "failed"} and submitted.get(identity) == receipt.get("status"):
                receipt["acknowledged"] = True
                atomic(path, receipt)

    def serve(self):
        daemon_lock = os.open(self.state / "daemon.lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(daemon_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Host service is already running")
        threading.Thread(target=self.collect, daemon=True).start()
        while True:
            try:
                self.ensure_identity()
                with self.lock:
                    status = self.status.copy()
                reports = self.reports()
                payload = {"nodeId": self.config["nodeId"], "instanceId": self.instance, "status": status, "reports": reports}
                if self.inventory_complete:
                    payload["orphanInventoryComplete"] = True
                response = self.request("/agent/sync", payload)
                if payload.get("orphanInventoryComplete"):
                    self.inventory_complete = False
                self.acknowledge(response.get("acknowledged", []), {r["id"]: r["status"] for r in reports})
                if (response.get("inspectOrphans") or response.get("inspectOverflow")) and not (self.inspection_worker and self.inspection_worker.is_alive()):
                    self.inspection_worker = threading.Thread(target=self.inspect_batch, args=(response.get("inspectOrphans", []), response.get("inspectionNonces", {}), response.get("inspectOverflow") is True), daemon=True)
                    self.inspection_worker.start()
                if response.get("job"):
                    self.start(response["job"])
            except Exception:
                # Local systemd journal contains a fixed diagnostic, not remote body or secrets.
                print("Control connection unavailable; local backup schedules continue.", flush=True)
            time.sleep(4)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/rolypolyops/agent.json")
    parser.add_argument("--state", default="/var/lib/rolypolyops-agent")
    parser.add_argument("--allow-local-http", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("Host service requires root")
    os.umask(0o077)
    Agent(json.loads(Path(args.config).read_text()), args.state, args.allow_local_http).serve()


if __name__ == "__main__":
    main()
