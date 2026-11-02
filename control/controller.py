"""Authenticated control service and persistent queue for supported recovery packages."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import logging
import math
import mimetypes
import os
from pathlib import Path
import re
import secrets
import shlex
import sqlite3
import threading
import time
from datetime import datetime, timezone
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import uuid

VERSION = "0.2.0"
PREFIX = "/ops"
MAX_BODY = 262144
COOKIE = "__Host-rpo_session"
ACTIONS = {"backup", "verify", "restore-check", "restore-preview", "remove-preview", "set-schedule"}
INTERVALS = {"15min", "hourly", "daily"}
TERMINAL = {"succeeded", "failed"}
ACTIVE = {"dispatched", "running", "outcome_unknown"}
CHECKS = {"database-values", "file-sha256", "application-http", "app-version", "image-ids", "fresh-mounts", "runtime-restrictions"}
ORPHAN_LIMIT = 128
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
SLUG = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")
STAGES = {"queued", "starting", "checking", "capturing", "transferring", "restoring", "validating", "cleanup", "applying_schedule", "completed", "interrupted", "waiting"}


def stamp(value=None):
    return datetime.fromtimestamp(time.time() if value is None else value, timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def is_uuid(value):
    if not isinstance(value, str):
        return False
    try:
        return str(uuid.UUID(value)) == value
    except ValueError:
        return False


def clean_text(value, limit=100):
    if not utf8_text(value, limit) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        return None
    return value


def utf8_text(value, limit):
    if not isinstance(value, str) or len(value) > limit:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def opaque_matches(received, expected):
    if not isinstance(received, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", received):
        return False
    if not isinstance(expected, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", expected):
        return False
    return hmac.compare_digest(received.encode("ascii"), expected.encode("ascii"))


def timestamp(value, *, allow_future=False):
    if not isinstance(value, str) or len(value) > 50:
        return None
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            return None
        epoch = date.timestamp()
        if not math.isfinite(epoch) or epoch > time.time() + (366 * 86400 if allow_future else 300):
            return None
        return date.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def number(value, maximum=2**63 - 1):
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum


def fields(body, required=(), optional=()):
    if not isinstance(body, dict) or not set(required) <= body.keys() or body.keys() - set(required) - set(optional):
        raise APIError(400, "invalid_request")


def json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate JSON key")
        value[key] = item
    return value


class APIError(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


def password_hash(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode(), salt=salt, n=32768, r=8, p=1, maxmem=128 * 1024 * 1024)
    return {"salt": salt.hex(), "hash": key.hex()}


def password_matches(password, stored):
    if not utf8_text(password, 1024):
        return False
    return hmac.compare_digest(password_hash(password, bytes.fromhex(stored["salt"]))["hash"], stored["hash"])


def snapshot_list(value):
    result = []
    if not isinstance(value, list):
        return result
    for entry in value[:200]:
        if not isinstance(entry, dict) or not HEX64.fullmatch(str(entry.get("id", ""))):
            continue
        when = timestamp(entry.get("time"))
        if when is None:
            continue
        item = {"id": entry["id"], "time": when}
        if number(entry.get("size")):
            item["size"] = entry["size"]
        result.append(item)
    return sorted(result, key=lambda item: item["time"], reverse=True)


def proof(value):
    if not isinstance(value, dict):
        return None
    result = {}
    snap = value.get("snapshot", value.get("snapshotId"))
    if isinstance(snap, str) and HEX64.fullmatch(snap):
        result["snapshot"] = snap
    when = timestamp(value.get("at"))
    if when:
        result["at"] = when
    checks = value.get("checks")
    if isinstance(checks, list):
        result["checks"] = [x for x in checks[:30] if isinstance(x, str) and SLUG.fullmatch(x)]
    state = value.get("status")
    if isinstance(state, str) and SLUG.fullmatch(state):
        result["status"] = state
    for name in ("bytes", "durationSeconds"):
        if number(value.get(name)):
            result[name] = value[name]
    return result


def preview(value):
    if not isinstance(value, dict) or not is_uuid(value.get("id")):
        return None
    result = proof(value) or {}
    result["id"] = value["id"]
    created = timestamp(value.get("createdAt"))
    if created:
        result["createdAt"] = created
    return result


def sanitize_status(value):
    if not isinstance(value, dict):
        raise APIError(400, "invalid_status")
    result = {"supported": value.get("supported") is True, "serviceHealthy": value.get("serviceHealthy") if isinstance(value.get("serviceHealthy"), bool) else None, "snapshots": snapshot_list(value.get("snapshots")), "schedule": {}}
    for name, limit in (("version", 32), ("serviceLabel", 100)):
        text = clean_text(value.get(name), limit)
        if text is not None:
            result[name] = text
    observed = timestamp(value.get("observedAt"))
    if observed:
        result["observedAt"] = observed
    disk = value.get("disk")
    if isinstance(disk, dict) and number(disk.get("total")) and number(disk.get("free")) and disk["free"] <= disk["total"]:
        result["disk"] = {"total": disk["total"], "free": disk["free"]}
    for key in ("lastBackup", "lastRestore"):
        item = proof(value.get(key))
        if item is not None:
            result[key] = item
    schedules = value.get("schedule")
    if isinstance(schedules, dict):
        for key in ("backup", "restore"):
            schedule = schedules.get(key)
            if isinstance(schedule, dict) and isinstance(schedule.get("enabled"), bool):
                item = {"enabled": schedule["enabled"]}
                when = timestamp(schedule.get("next"), allow_future=True)
                if when:
                    item["next"] = when
                if isinstance(schedule.get("interval"), str) and schedule["interval"] in INTERVALS:
                    item["interval"] = schedule["interval"]
                result["schedule"][key] = item
    item = preview(value.get("preview"))
    if item is not None:
        result["preview"] = item
    if isinstance(value.get("error"), str) and SLUG.fullmatch(value["error"]):
        result["error"] = value["error"]
    if "compose" in value:
        result["compose"] = compose_control.sanitize_status(value["compose"])
    return result


try:
    from . import compose_control
except ImportError:
    import compose_control


class ManagedConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


class Control:
    def __init__(self, data_dir, origin, *, allow_http=False, web_dir=None):
        if not isinstance(origin, str) or not origin.isascii() or any(ord(char) <= 32 or ord(char) == 127 for char in origin):
            raise ValueError("A plain ASCII HTTPS origin is required")
        parsed = urlsplit(origin)
        local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"} and allow_http
        if (parsed.scheme != "https" and not local) or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
            raise ValueError("A valid HTTPS origin is required")
        host = parsed.hostname
        if not host or "%" in host:
            raise ValueError("A valid DNS or IP host is required")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            labels = host.rstrip(".").split(".")
            if len(host) > 253 or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
                raise ValueError("A valid DNS or IP host is required") from None
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("A valid origin port is required")
        expected = "[" + host + "]" if ":" in host else host
        if parsed.port is not None:
            expected += ":" + str(parsed.port)
        if parsed.netloc.lower() != expected.lower():
            raise ValueError("A plain origin host and port are required")
        default_port = 443 if parsed.scheme == "https" else 80
        canonical_host = "[" + host.lower() + "]" if ":" in host else host.lower()
        self.origin = parsed.scheme + "://" + canonical_host + (":" + str(parsed.port) if parsed.port is not None and parsed.port != default_port else "")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.data_dir.chmod(0o700)
        self.database = self.data_dir / "control.sqlite3"
        self.web_dir = Path(web_dir) if web_dir else Path(__file__).parent / "web"
        fd = os.open(self.database, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        self.database.chmod(0o600)
        self.compose = compose_control.ComposeControl(self, APIError)
        with self.connect() as db:
            self.compose.initialize(db)
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,csrf TEXT NOT NULL,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS attempts(client TEXT NOT NULL,at REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS attempts_client ON attempts(client,at);
                CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY,name TEXT NOT NULL,role TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,last_seen REAL,status TEXT NOT NULL DEFAULT '{}');
                CREATE TABLE IF NOT EXISTS enrollments(id TEXT PRIMARY KEY,code_hash TEXT NOT NULL UNIQUE,name TEXT NOT NULL,role TEXT NOT NULL,node_id TEXT,expires REAL NOT NULL,used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY,node_id TEXT NOT NULL,action TEXT NOT NULL,snapshot TEXT,parameters TEXT NOT NULL,revision INTEGER NOT NULL,expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,node_id TEXT NOT NULL,plan_id TEXT NOT NULL UNIQUE,action TEXT NOT NULL,snapshot TEXT,parameters TEXT NOT NULL,nonce TEXT NOT NULL,status TEXT NOT NULL,idempotency_key TEXT NOT NULL UNIQUE,created REAL NOT NULL,started REAL,ended REAL,stage TEXT,result TEXT,error TEXT);
                CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status,created);
                CREATE TABLE IF NOT EXISTS job_requests(key TEXT PRIMARY KEY,plan_id TEXT NOT NULL,job_id TEXT NOT NULL);
                INSERT OR IGNORE INTO job_requests SELECT idempotency_key,plan_id,id FROM jobs;
                CREATE TABLE IF NOT EXISTS orphan_reports(node_id TEXT NOT NULL,job_id TEXT NOT NULL,status TEXT NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL,PRIMARY KEY(node_id,job_id));
            """)
            for table, column, declaration in (("jobs", "reconcile_requested", "INTEGER NOT NULL DEFAULT 0"), ("jobs", "dispatch_instance", "TEXT"), ("nodes", "revoked", "INTEGER NOT NULL DEFAULT 0"), ("nodes", "instance_id", "TEXT"), ("nodes", "orphan_overflow", "INTEGER NOT NULL DEFAULT 0"), ("nodes", "overflow_inspect_requested", "INTEGER NOT NULL DEFAULT 0"), ("orphan_reports", "inspect_requested", "INTEGER NOT NULL DEFAULT 0"), ("orphan_reports", "reason", "TEXT NOT NULL DEFAULT 'missing_catalog'"), ("orphan_reports", "last_inspected_sent", "REAL NOT NULL DEFAULT 0")):
                if column not in {entry[1] for entry in db.execute("PRAGMA table_info(" + table + ")")}:
                    db.execute("ALTER TABLE " + table + " ADD COLUMN " + column + " " + declaration)
            db.commit()
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute("SELECT node_id,COUNT(*) AS amount FROM orphan_reports GROUP BY node_id HAVING COUNT(*)>?", (ORPHAN_LIMIT,)).fetchall():
                while db.execute("SELECT COUNT(*) FROM orphan_reports WHERE node_id=?", (row["node_id"],)).fetchone()[0] > ORPHAN_LIMIT:
                    self.evict_orphan(db, row["node_id"])
            if self.setting(db, "password") is None:
                password_file = self.data_dir / "admin-password"
                if password_file.exists():
                    initial = password_file.read_text().strip()
                    if not 24 <= len(initial) <= 1024:
                        raise ValueError("Invalid existing administrator credential file")
                else:
                    initial = secrets.token_urlsafe(24)
                    fd = os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "w") as out:
                        out.write(initial + "\n")
                password_file.chmod(0o600)
                self.set_setting(db, "password", password_hash(initial))
                self.set_setting(db, "needsPasswordChange", True)
            for key, value in (("revision", 1), ("setup", {"completed": False, "profile": "pair_assisted", "backupInterval": "hourly"})):
                if self.setting(db, key) is None:
                    self.set_setting(db, key, value)

    def connect(self):
        db = sqlite3.connect(self.database, timeout=20, factory=ManagedConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=20000")
        return db

    @staticmethod
    def setting(db, key):
        row = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    @staticmethod
    def set_setting(db, key, value):
        db.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, canonical(value)))

    def revision(self, db):
        return self.setting(db, "revision")

    def bump(self, db):
        value = self.revision(db) + 1
        self.set_setting(db, "revision", value)
        setup = self.setting(db, "setup")
        setup["completed"] = False
        self.set_setting(db, "setup", setup)
        return value

    def session(self, db, cookie_header):
        if not isinstance(cookie_header, str) or len(cookie_header) > 4096:
            return None
        try:
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            token = cookie[COOKIE].value
        except (KeyError, ValueError, CookieError):
            return None
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token):
            return None
        return db.execute("SELECT * FROM sessions WHERE token_hash=? AND expires>?", (digest(token), time.time())).fetchone()

    def demo_selected(self, db):
        setup=self.setting(db,"setup") or {}
        if setup.get("demoSelected") is True or setup.get("completed") is True or self.setting(db,"demoInstalledObserved") is True:
            return True
        # Older catalogs have no selection marker. A nondefault saved setting
        # proves a choice; the initial pair/hourly defaults alone do not.
        if setup.get("profile") not in (None,"pair_assisted") or setup.get("backupInterval") not in (None,"hourly"):
            return True
        placeholders=",".join("?" for _ in ACTIONS)
        if db.execute("SELECT 1 FROM jobs WHERE action IN ("+placeholders+") LIMIT 1",tuple(sorted(ACTIONS))).fetchone() or db.execute("SELECT 1 FROM plans WHERE action IN ("+placeholders+") LIMIT 1",tuple(sorted(ACTIONS))).fetchone():
            return True
        installed=any(json.loads(row["status"]).get("supported") is True for row in db.execute("SELECT status FROM nodes"))
        if installed:
            self.set_setting(db,"demoInstalledObserved",True)
        return installed

    def session_info(self, db, session):
        result = {"authenticated": session is not None, "setupRequired": self.demo_selected(db) and not self.setting(db, "setup")["completed"], "version": VERSION}
        if session is not None:
            result.update(csrf=session["csrf"], needsPasswordChange=self.setting(db, "needsPasswordChange"))
        return result

    def new_session(self, db):
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        db.execute("INSERT INTO sessions VALUES(?,?,?)", (digest(token), csrf, time.time() + 43200))
        return token, db.execute("SELECT * FROM sessions WHERE token_hash=?", (digest(token),)).fetchone()

    def login(self, db, body, client):
        fields(body, ("password",))
        password = body["password"]
        if not utf8_text(password, 1024):
            raise APIError(400, "invalid_request")
        db.execute("DELETE FROM attempts WHERE at<?", (time.time() - 900,))
        failures = db.execute("SELECT COUNT(*) FROM attempts WHERE client=?", (client,)).fetchone()[0]
        if failures >= 5:
            raise APIError(429, "login_rate_limited")
        if not password_matches(password, self.setting(db, "password")):
            db.execute("INSERT INTO attempts VALUES(?,?)", (client, time.time()))
            db.commit()
            raise APIError(401, "invalid_credentials")
        db.execute("DELETE FROM attempts WHERE client=?", (client,))
        db.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        token, session = self.new_session(db)
        return self.session_info(db, session), token

    def change_password(self, db, body):
        fields(body, ("currentPassword", "newPassword"))
        new = body["newPassword"]
        if not utf8_text(new, 256):
            raise APIError(400, "invalid_password")
        if len(new) < 16:
            raise APIError(400, "password_too_short")
        if not password_matches(body["currentPassword"], self.setting(db, "password")):
            raise APIError(403, "invalid_credentials")
        if hmac.compare_digest(new.encode("utf-8"), body["currentPassword"].encode("utf-8")):
            raise APIError(400, "password_unchanged")
        self.set_setting(db, "password", password_hash(new))
        self.set_setting(db, "needsPasswordChange", False)
        db.execute("DELETE FROM sessions")
        token, session = self.new_session(db)
        result = self.session_info(db, session)
        db.commit()
        try:
            (self.data_dir / "admin-password").unlink(missing_ok=True)
        except OSError:
            raise APIError(500, "password_changed_cleanup_failed") from None
        return result, token

    def node(self, db, node_id):
        if not is_uuid(node_id):
            raise APIError(400, "invalid_node")
        row = db.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
        if row is None:
            raise APIError(404, "node_not_found")
        return row

    @staticmethod
    def connected(node):
        return node["last_seen"] is not None and time.time() - node["last_seen"] <= 45

    @staticmethod
    def status_fresh(status):
        when = timestamp(status.get("observedAt"))
        return when is not None and time.time() - datetime.fromisoformat(when).timestamp() <= 120

    @staticmethod
    def node_has_unsettled(db, node_id):
        return db.execute("SELECT 1 FROM jobs WHERE node_id=? AND status IN ('queued','dispatched','running','outcome_unknown')", (node_id,)).fetchone() or db.execute("SELECT 1 FROM orphan_reports WHERE node_id=? AND status IN ('running','outcome_unknown')", (node_id,)).fetchone() or db.execute("SELECT 1 FROM nodes WHERE id=? AND orphan_overflow=1", (node_id,)).fetchone()

    @staticmethod
    def evict_orphan(db, node_id):
        row = db.execute("SELECT * FROM orphan_reports WHERE node_id=? ORDER BY CASE WHEN status IN ('succeeded','failed') THEN 0 ELSE 1 END,inspect_requested,first_seen LIMIT 1", (node_id,)).fetchone()
        if row is None:
            return
        if row["status"] not in TERMINAL:
            # The bounded catalog cannot forget uncertainty: keep a node-wide
            # latch until an owner-requested, authenticated host scan settles it.
            db.execute("UPDATE nodes SET orphan_overflow=1,overflow_inspect_requested=MAX(overflow_inspect_requested,?) WHERE id=?", (row["inspect_requested"], node_id))
        db.execute("DELETE FROM orphan_reports WHERE node_id=? AND job_id=?", (node_id, row["job_id"]))

    def record_orphan(self, db, node_id, job_id, state, reason="missing_catalog", *, force=False):
        row = db.execute("SELECT * FROM orphan_reports WHERE node_id=? AND job_id=?", (node_id, job_id)).fetchone()
        if row is not None:
            if row["status"] in TERMINAL and not force:
                state = row["status"]
            db.execute("UPDATE orphan_reports SET status=?,reason=?,last_seen=?,inspect_requested=CASE WHEN ? IN ('succeeded','failed') THEN 0 ELSE inspect_requested END WHERE node_id=? AND job_id=?", (state, reason if force else row["reason"], time.time(), state, node_id, job_id))
        else:
            while db.execute("SELECT COUNT(*) FROM orphan_reports WHERE node_id=?", (node_id,)).fetchone()[0] >= ORPHAN_LIMIT:
                self.evict_orphan(db, node_id)
            db.execute("INSERT INTO orphan_reports(node_id,job_id,status,first_seen,last_seen,reason) VALUES(?,?,?,?,?,?)", (node_id, job_id, state, time.time(), time.time(), reason))
        return db.execute("SELECT * FROM orphan_reports WHERE node_id=? AND job_id=?", (node_id, job_id)).fetchone()

    def inspect_orphan(self, db, node_id, job_id, body):
        fields(body)
        node = self.node(db, node_id)
        if not self.connected(node):
            raise APIError(409, "node_stale")
        row = db.execute("SELECT * FROM orphan_reports WHERE node_id=? AND job_id=?", (node_id, job_id)).fetchone()
        if row is None:
            raise APIError(404, "orphan_not_found")
        if row["status"] in TERMINAL:
            raise APIError(409, "orphan_already_resolved")
        db.execute("UPDATE orphan_reports SET inspect_requested=1 WHERE node_id=? AND job_id=?", (node_id, job_id))
        db.execute("UPDATE nodes SET overflow_inspect_requested=1 WHERE id=? AND orphan_overflow=1", (node_id,))
        return {"inspectionRequested": True, "id": job_id}

    def inspect_orphan_inventory(self, db, node_id, body):
        fields(body)
        node = self.node(db, node_id)
        if not self.connected(node) or not self.status_fresh(json.loads(node["status"])):
            raise APIError(409, "node_stale")
        pending = bool(node["orphan_overflow"])
        if pending:
            db.execute("UPDATE nodes SET overflow_inspect_requested=1 WHERE id=?", (node_id,))
        return {"inspectionRequested": pending, "scope": "inventory"}

    def enrollment(self, db, body, node_id=None):
        if node_id is None:
            fields(body, ("name", "role"))
            name, role = clean_text(body["name"], 80), body["role"]
            if not name or not isinstance(role, str) or role not in {"primary", "recovery"}:
                raise APIError(400, "invalid_request")
            if role == "primary" and db.execute("SELECT 1 FROM nodes WHERE role='primary'").fetchone():
                raise APIError(409, "primary_exists")
        else:
            fields(body)
            node = self.node(db, node_id)
            if self.node_has_unsettled(db, node_id):
                raise APIError(409, "node_busy")
            name, role = node["name"], node["role"]
            db.execute("UPDATE enrollments SET used=2 WHERE node_id=? AND used=0", (node_id,))
        code, identity, expires = secrets.token_urlsafe(32), str(uuid.uuid4()), time.time() + 900
        db.execute("INSERT INTO enrollments(id,code_hash,name,role,node_id,expires) VALUES(?,?,?,?,?,?)", (identity, digest(code), name, role, node_id, expires))
        self.bump(db)
        command = "sudo python3 control/install.py agent --controller " + shlex.quote(self.origin + PREFIX) + " --enrollment " + code
        if node_id is not None:
            command += " --replace-enrollment"
        return {"id": identity, "code": code, "expiresAt": stamp(expires), "command": command}

    def cancel_enrollment(self, db, identity, body):
        fields(body)
        row = db.execute("SELECT * FROM enrollments WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise APIError(404, "enrollment_not_found")
        if row["used"] == 1:
            raise APIError(409, "enrollment_used")
        if row["used"] == 0:
            db.execute("UPDATE enrollments SET used=2 WHERE id=?", (identity,))
            self.bump(db)
        return {"cancelled": True}

    def revoke_node(self, db, identity, body):
        fields(body)
        self.node(db, identity)
        if self.node_has_unsettled(db, identity):
            raise APIError(409, "node_busy")
        db.execute("UPDATE nodes SET revoked=1,token_hash=?,last_seen=NULL,status='{}' WHERE id=?", (digest(secrets.token_urlsafe(32)), identity))
        db.execute("UPDATE enrollments SET used=2 WHERE node_id=? AND used=0", (identity,))
        self.bump(db)
        return {"revoked": True}

    def enroll_agent(self, db, body, client="local"):
        namespace = "enroll:" + client
        db.execute("DELETE FROM attempts WHERE at<?", (time.time() - 900,))
        if db.execute("SELECT COUNT(*) FROM attempts WHERE client=?", (namespace,)).fetchone()[0] >= 10:
            raise APIError(429, "enrollment_rate_limited")
        db.execute("INSERT INTO attempts VALUES(?,?)", (namespace, time.time()))
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        fields(body, ("code", "hostname", "version"))
        if not isinstance(body["code"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", body["code"]) or not clean_text(body["hostname"], 255) or not clean_text(body["version"], 32):
            raise APIError(400, "invalid_request")
        row = db.execute("SELECT * FROM enrollments WHERE code_hash=? AND used=0 AND expires>?", (digest(body["code"]), time.time())).fetchone()
        if row is None:
            raise APIError(403, "invalid_enrollment")
        token, node_id = secrets.token_urlsafe(32), row["node_id"] or str(uuid.uuid4())
        if row["node_id"] is None:
            if row["role"] == "primary" and db.execute("SELECT 1 FROM nodes WHERE role='primary'").fetchone():
                raise APIError(409, "primary_exists")
            db.execute("INSERT INTO nodes(id,name,role,token_hash) VALUES(?,?,?,?)", (node_id, row["name"], row["role"], digest(token)))
        else:
            if self.node_has_unsettled(db, node_id):
                raise APIError(409, "node_busy")
            db.execute("UPDATE nodes SET token_hash=?,revoked=0,last_seen=NULL,status='{}' WHERE id=?", (digest(token), node_id))
        db.execute("UPDATE enrollments SET used=1 WHERE id=?", (row["id"],))
        self.bump(db)
        return {"nodeId": node_id, "token": token, "role": row["role"]}

    def public_job(self, row, db=None):
        result = {"id": row["id"], "nodeId": row["node_id"], "action": row["action"], "status": row["status"], "createdAt": stamp(row["created"])}
        for name, key in (("startedAt", "started"), ("endedAt", "ended")):
            if row[key] is not None:
                result[name] = stamp(row[key])
        for name, key in (("stage", "stage"), ("snapshotId", "snapshot"), ("error", "error")):
            if row[key] is not None:
                result[name] = row[key]
        if row["reconcile_requested"]:
            result["reconcileRequested"] = True
        if row["result"]:
            result["result"] = json.loads(row["result"])
        if row["action"] in compose_control.ACTIONS:
            params = json.loads(row["parameters"])
            for name in ("serviceId", "storageId", "restoreId"):
                if is_uuid(params.get(name)):
                    result[name] = params[name]
            if db is None:
                with self.connect() as scope_db:
                    scope = scope_db.execute("SELECT group_id,parent_id FROM compose_jobs WHERE job_id=?", (row["id"],)).fetchone()
            else:
                scope = db.execute("SELECT group_id,parent_id FROM compose_jobs WHERE job_id=?", (row["id"],)).fetchone()
            if scope:
                for name,column in (("groupId","group_id"),("parentJobId","parent_id")):
                    if is_uuid(scope[column]):
                        result[name] = scope[column]
        return result

    def mark_lost(self, db):
        db.execute("UPDATE jobs SET status='outcome_unknown',stage='interrupted',error='agent_disconnected' WHERE status IN ('dispatched','running') AND node_id IN (SELECT id FROM nodes WHERE last_seen<?)", (time.time() - 90,))

    def expire_queued(self, db):
        self.compose.settle(db)
        for row in db.execute("SELECT jobs.id,jobs.action,jobs.parameters,plans.expires,plans.revision FROM jobs JOIN plans ON plans.id=jobs.plan_id WHERE jobs.status='queued' ORDER BY jobs.created,jobs.rowid").fetchall():
            # A preceding parent may just have expired in this same pass.
            self.compose.close_dependencies(db)
            if db.execute("SELECT status FROM jobs WHERE id=?", (row["id"],)).fetchone()[0] != "queued":
                continue
            error = "plan_expired" if row["expires"] < time.time() else "revision_conflict" if row["revision"] != self.revision(db) else None
            if row["action"] == "storage-configure":
                envelope = json.loads(row["parameters"]).get("envelope", {})
                if compose_control.iso(envelope.get("expiresAt")) and compose_control.when(envelope["expiresAt"]) < time.time():
                    error = "envelope_expired"
            if error:
                db.execute("UPDATE jobs SET status='failed',stage='completed',ended=?,error=? WHERE id=?", (time.time(), error, row["id"]))
        self.compose.settle(db)

    def reconcile_job(self, db, identity, body):
        fields(body)
        job = db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()
        if job is None:
            raise APIError(404, "job_not_found")
        if job["status"] != "outcome_unknown":
            raise APIError(409, "job_not_unknown")
        if job["error"] == "catalog_delivery_state_lost":
            self.record_orphan(db, job["node_id"], identity, "outcome_unknown", "catalog_delivery_state_lost", force=True)
            self.inspect_orphan(db, job["node_id"], identity, body)
            return {"job": self.public_job(job), "inspectionRequested": True}
        db.execute("UPDATE jobs SET reconcile_requested=1 WHERE id=?", (identity,))
        return {"job": self.public_job(db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone())}

    def cancel_job(self, db, identity, body):
        fields(body)
        job = db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()
        if job is None:
            raise APIError(404, "job_not_found")
        if job["status"] == "failed" and job["error"] == "cancelled_before_dispatch":
            return {"job": self.public_job(job)}
        if job["status"] != "queued":
            raise APIError(409, "job_not_cancellable")
        db.execute("UPDATE jobs SET status='failed',stage='completed',ended=?,error='cancelled_before_dispatch' WHERE id=?", (time.time(), identity))
        self.compose.settle(db)
        return {"job": self.public_job(db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone())}

    def overview(self, db):
        self.mark_lost(db)
        self.expire_queued(db)
        nodes, alerts = [], []
        demo_selected=self.demo_selected(db)
        for row in db.execute("SELECT * FROM nodes ORDER BY name,id"):
            status = json.loads(row["status"])
            current = self.connected(row)
            nodes.append({"id": row["id"], "name": row["name"], "role": row["role"], "revoked": bool(row["revoked"]), "orphanOverflow": bool(row["orphan_overflow"]), "overflowInspectionRequested": bool(row["overflow_inspect_requested"]), "lastSeen": stamp(row["last_seen"]) if row["last_seen"] is not None else None, "connected": current, "status": status})
            if not current:
                alerts.append({"severity": "warning", "code": "node_offline", "nodeId": row["id"]})
            elif not self.status_fresh(status):
                alerts.append({"severity": "warning", "code": "service_status_stale", "nodeId": row["id"]})
            else:
                compose=status.get("compose")
                if not status.get("supported") and (demo_selected or not isinstance(compose,dict)):
                    alerts.append({"severity": "warning", "code": "package_unsupported", "nodeId": row["id"]})
                elif status.get("supported") and status.get("serviceHealthy") is not True:
                    alerts.append({"severity": "warning", "code": "service_unhealthy", "nodeId": row["id"]})
                if isinstance(compose,dict) and compose.get("ready") is not True:
                    alerts.append({"severity":"warning","code":compose.get("error","compose_not_ready"),"nodeId":row["id"]})
            disk = status.get("disk")
            if disk and disk["total"] > 0 and disk["free"] / disk["total"] < 0.1:
                alerts.append({"severity": "warning", "code": "disk_low", "nodeId": row["id"]})
        jobs = [self.public_job(row, db) for row in db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT 100")]
        if any(job["status"] == "outcome_unknown" for job in jobs):
            alerts.append({"severity": "error", "code": "operation_outcome_unknown"})
        orphans = [{"nodeId": row["node_id"], "id": row["job_id"], "status": row["status"], "inspectionRequested": bool(row["inspect_requested"]), "reason": row["reason"], "firstSeen": stamp(row["first_seen"]), "lastSeen": stamp(row["last_seen"])} for row in db.execute("SELECT * FROM orphan_reports ORDER BY CASE WHEN status IN ('succeeded','failed') THEN 1 ELSE 0 END,last_seen DESC LIMIT 512")]
        for row in db.execute("SELECT DISTINCT node_id FROM orphan_reports WHERE status IN ('running','outcome_unknown')"):
            alerts.append({"severity": "error", "code": "catalog_receipt_orphaned", "nodeId": row["node_id"]})
        for row in db.execute("SELECT id FROM nodes WHERE orphan_overflow=1"):
            alerts.append({"severity": "error", "code": "catalog_orphan_capacity", "nodeId": row["id"]})
        enrollments = [{"id": row["id"], "name": row["name"], "role": row["role"], "expiresAt": stamp(row["expires"]), "status": "used" if row["used"] == 1 else "cancelled" if row["used"] == 2 else "expired" if row["expires"] < time.time() else "pending"} for row in db.execute("SELECT * FROM enrollments ORDER BY expires DESC LIMIT 100")]
        return {"version": VERSION, "revision": self.revision(db), "setup": dict(self.setting(db, "setup"),demoSelected=demo_selected), "nodes": nodes, "enrollments": enrollments, "jobs": jobs, "orphanReports": orphans, "orphanReportLimit": ORPHAN_LIMIT, "capabilities": {"automaticFailover": False}, "alerts": alerts, **self.compose.overview(db)}

    def settings(self, db, body):
        fields(body, ("profile", "backupInterval", "expectedRevision"))
        if not isinstance(body["profile"], str) or body["profile"] not in {"single", "pair_assisted"} or not isinstance(body["backupInterval"], str) or body["backupInterval"] not in INTERVALS or not number(body["expectedRevision"]):
            raise APIError(400, "invalid_request")
        if body["expectedRevision"] != self.revision(db):
            raise APIError(409, "revision_conflict")
        if db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] < (1 if body["profile"] == "single" else 2):
            raise APIError(409, "nodes_required")
        self.set_setting(db, "setup", {"completed": False, "profile": body["profile"], "backupInterval": body["backupInterval"], "demoSelected": True})
        return {"revision": self.bump(db)}

    def plan(self, db, body):
        if isinstance(body, dict) and isinstance(body.get("action"), str) and body["action"] in compose_control.ACTIONS:
            return self.compose.plan(db, body)
        fields(body, ("nodeId", "action"), ("snapshotId", "parameters"))
        node = self.node(db, body["nodeId"])
        status = json.loads(node["status"])
        if not self.connected(node) or not self.status_fresh(status):
            raise APIError(409, "node_stale")
        if not status.get("supported"):
            raise APIError(409, "package_unsupported")
        action, snap, parameters = body["action"], body.get("snapshotId"), body.get("parameters", {})
        if not isinstance(action, str) or action not in ACTIONS or not isinstance(parameters, dict):
            raise APIError(400, "invalid_action")
        if action in {"restore-check", "restore-preview"}:
            if not isinstance(snap, str) or not HEX64.fullmatch(snap):
                raise APIError(400, "invalid_snapshot")
            if snap not in {x["id"] for x in status.get("snapshots", [])}:
                raise APIError(409, "snapshot_unavailable")
        elif snap is not None:
            raise APIError(400, "unexpected_snapshot")
        if action == "set-schedule":
            fields(parameters, ("interval",))
            if not isinstance(parameters["interval"], str) or parameters["interval"] not in INTERVALS or node["role"] != "primary":
                raise APIError(400, "invalid_schedule")
        elif action == "remove-preview":
            fields(parameters, ("previewId",))
            if not is_uuid(parameters["previewId"]) or not status.get("preview") or status["preview"]["id"] != parameters["previewId"]:
                raise APIError(409, "preview_unavailable")
        else:
            fields(parameters)
        if action == "restore-preview" and status.get("preview"):
            raise APIError(409, "preview_exists")
        if action == "backup" and (node["role"] != "primary" or status.get("serviceHealthy") is not True):
            raise APIError(409, "primary_unavailable")
        identity, expires, revision = str(uuid.uuid4()), time.time() + 600, self.revision(db)
        db.execute("INSERT INTO plans VALUES(?,?,?,?,?,?,?)", (identity, node["id"], action, snap, canonical(parameters), revision, expires))
        return {"id": identity, "nodeId": node["id"], "action": action, "snapshotId": snap, "parameters": parameters, "expiresAt": stamp(expires), "revision": revision, "summary": {"code": action, "pausesService": action == "backup", "isolated": action in {"restore-check", "restore-preview"}, "retainsCopy": action == "restore-preview"}}

    def enqueue(self, db, body):
        fields(body, ("planId", "idempotencyKey"))
        if not is_uuid(body["planId"]) or not is_uuid(body["idempotencyKey"]):
            raise APIError(400, "invalid_request")
        request = db.execute("SELECT * FROM job_requests WHERE key=?", (body["idempotencyKey"],)).fetchone()
        existing = db.execute("SELECT * FROM jobs WHERE id=?", (request["job_id"],)).fetchone() if request else None
        if existing:
            if existing["plan_id"] != body["planId"]:
                raise APIError(409, "idempotency_conflict")
            return {"job": self.public_job(existing, db)}
        existing = db.execute("SELECT * FROM jobs WHERE plan_id=?", (body["planId"],)).fetchone()
        if existing:
            db.execute("INSERT INTO job_requests VALUES(?,?,?)", (body["idempotencyKey"], body["planId"], existing["id"]))
            return {"job": self.public_job(existing, db)}
        plan = db.execute("SELECT * FROM plans WHERE id=?", (body["planId"],)).fetchone()
        if plan is None:
            raise APIError(404, "plan_not_found")
        if plan["expires"] < time.time():
            raise APIError(409, "plan_expired")
        if plan["revision"] != self.revision(db):
            raise APIError(409, "revision_conflict")
        node = self.node(db, plan["node_id"])
        if not self.connected(node) or not self.status_fresh(json.loads(node["status"])):
            raise APIError(409, "node_stale")
        identity = str(uuid.uuid4())
        db.execute("INSERT INTO jobs(id,node_id,plan_id,action,snapshot,parameters,nonce,status,idempotency_key,created,stage) VALUES(?,?,?,?,?,?,?,'queued',?,?, 'queued')", (identity, plan["node_id"], plan["id"], plan["action"], plan["snapshot"], plan["parameters"], secrets.token_urlsafe(32), body["idempotencyKey"], time.time()))
        db.execute("INSERT INTO job_requests VALUES(?,?,?)", (body["idempotencyKey"], body["planId"], identity))
        queued = db.execute("SELECT * FROM jobs WHERE id=?", (identity,)).fetchone()
        if queued["action"] in compose_control.ACTIONS:
            self.compose.track_enqueued(db, queued)
        return {"job": self.public_job(queued, db)}

    def sanitize_result(self, action, value, snapshot_id, parameters, job_id):
        if action in compose_control.ACTIONS:
            return compose_control.sanitize_result(action, value, snapshot_id, parameters, job_id)
        if not isinstance(value, dict):
            # Reached only after node and nonce verification: a malformed result is
            # unverifiable proof, so the caller records failed/result_unverified.
            return None
        result = proof(value) or {}
        if isinstance(value.get("verified"), bool):
            result["verified"] = value["verified"]
        if isinstance(value.get("interval"), str) and value["interval"] in INTERVALS:
            result["interval"] = value["interval"]
        if isinstance(value.get("enabled"), bool):
            result["enabled"] = value["enabled"]
        item = preview(value.get("preview"))
        if item is not None:
            result["preview"] = item
        if action == "backup" and not result.get("snapshot"):
            return None
        if action in {"restore-check", "restore-preview"} and (result.get("snapshot") != snapshot_id or not CHECKS <= set(result.get("checks", []))):
            return None
        if action == "restore-preview" and (not item or item["id"] != job_id or item.get("snapshot") != snapshot_id):
            return None
        if action == "verify" and result.get("verified") is not True and "repository-data" not in result.get("checks", []):
            return None
        if action == "set-schedule" and (result.get("interval") != parameters["interval"] or result.get("enabled") is not True):
            return None
        if action == "remove-preview" and value.get("removed") is not True:
            return None
        if action == "remove-preview":
            result["removed"] = True
        return result

    def sync(self, db, body, bearer):
        fields(body, ("nodeId", "instanceId", "status", "reports"), ("orphanInventoryComplete",))
        if not is_uuid(body["instanceId"]):
            raise APIError(400, "invalid_instance")
        if "orphanInventoryComplete" in body and not isinstance(body["orphanInventoryComplete"], bool):
            raise APIError(400, "invalid_request")
        if not is_uuid(body["nodeId"]) or not isinstance(bearer, str) or not re.fullmatch(r"Bearer [A-Za-z0-9_-]{32,128}", bearer):
            raise APIError(401, "agent_unauthorized")
        token = bearer[7:]
        node = db.execute("SELECT * FROM nodes WHERE id=? AND token_hash=? AND revoked=0", (body["nodeId"], digest(token))).fetchone()
        if node is None:
            raise APIError(401, "agent_unauthorized")
        instance = body["instanceId"]
        status = sanitize_status(body["status"])
        if status.get("supported") is True:
            self.set_setting(db,"demoInstalledObserved",True)
        reports = body["reports"]
        if not isinstance(reports, list) or len(reports) > 100:
            raise APIError(400, "invalid_reports")
        if node["instance_id"] != instance:
            # A new durable agent incarnation cannot inherit permission to replay
            # work remembered as queued or in flight by an older catalog.
            db.execute("UPDATE jobs SET status='failed',stage='completed',ended=?,error='agent_instance_changed' WHERE node_id=? AND status='queued'", (time.time(), node["id"]))
            db.execute("UPDATE jobs SET status='outcome_unknown',stage='interrupted',error='agent_instance_changed' WHERE node_id=? AND status IN ('dispatched','running')", (node["id"],))
        db.execute("UPDATE jobs SET status='outcome_unknown',stage='interrupted',error='agent_instance_changed' WHERE node_id=? AND status IN ('dispatched','running') AND (dispatch_instance IS NULL OR dispatch_instance<>?)", (node["id"], instance))
        acknowledged, discarded = [], []
        for report in reports:
            fields(report, ("id", "nonce", "status"), ("stage", "result", "error", "inspected"))
            if not is_uuid(report["id"]) or not isinstance(report["nonce"], str) or not isinstance(report["status"], str) or report["status"] not in {"running", "succeeded", "failed", "outcome_unknown"}:
                raise APIError(400, "invalid_report")
            if "inspected" in report and not isinstance(report["inspected"], bool):
                raise APIError(400, "invalid_report")
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", report["nonce"]):
                raise APIError(403, "job_report_forbidden")
            job = db.execute("SELECT * FROM jobs WHERE id=?", (report["id"],)).fetchone()
            if job is None:
                self.record_orphan(db, node["id"], report["id"], report["status"])
                acknowledged.append(report["id"])
                discarded.append(report["id"])
                continue
            if job["node_id"] != node["id"] or not opaque_matches(report["nonce"], job["nonce"]):
                raise APIError(403, "job_report_forbidden")
            orphan = db.execute("SELECT * FROM orphan_reports WHERE node_id=? AND job_id=?", (node["id"], job["id"])).fetchone()
            new_state = report["status"]
            rejected_success = job["status"] == "failed" and job["error"] == "result_unverified" and new_state == "succeeded"
            wrong_terminal = job["status"] in TERMINAL and ((new_state != job["status"] and not rejected_success) or (job["status"] == "failed" and job["started"] is None))
            catalog_lost = job["status"] == "queued" or job["error"] == "catalog_delivery_state_lost"
            quarantined = orphan is not None and orphan["reason"] != "missing_catalog"
            if catalog_lost or quarantined or wrong_terminal:
                reason = "catalog_delivery_state_lost" if catalog_lost else "terminal_job_conflict"
                if orphan is not None and orphan["status"] in TERMINAL and orphan["reason"] != "missing_catalog":
                    acknowledged.append(job["id"])
                    discarded.append(job["id"])
                    continue
                inspection_pending = (orphan is not None and orphan["inspect_requested"]) or node["overflow_inspect_requested"]
                if catalog_lost and job["status"] != "outcome_unknown":
                    db.execute("UPDATE jobs SET status='outcome_unknown',stage='interrupted',error='catalog_delivery_state_lost',reconcile_requested=0 WHERE id=?", (job["id"],))
                if report.get("inspected") is True and inspection_pending and new_state in TERMINAL:
                    self.record_orphan(db, node["id"], job["id"], new_state, reason, force=True)
                    if catalog_lost:
                        db.execute("UPDATE jobs SET status='failed',ended=?,stage='completed',error='catalog_delivery_state_lost',reconcile_requested=0 WHERE id=?", (time.time(), job["id"]))
                else:
                    self.record_orphan(db, node["id"], job["id"], "outcome_unknown", reason, force=True)
                acknowledged.append(job["id"])
                discarded.append(job["id"])
                continue
            if job["status"] in TERMINAL:
                acknowledged.append(job["id"])
                continue
            result, error = None, None
            if new_state == "succeeded":
                result = self.compose.validate_result(db, job, report.get("result", {})) if job["action"] in compose_control.ACTIONS else self.sanitize_result(job["action"], report.get("result", {}), job["snapshot"], json.loads(job["parameters"]), job["id"])
                if result is None:
                    new_state, error = ("outcome_unknown" if job["action"] in compose_control.ACTIONS else "failed"), "result_unverified"
            elif new_state in {"failed", "outcome_unknown"}:
                candidate = report.get("error", "operation_failed" if new_state == "failed" else "interrupted")
                error = candidate if isinstance(candidate, str) and SLUG.fullmatch(candidate) else "operation_failed"
            candidate = report.get("stage")
            stage = candidate if isinstance(candidate, str) and candidate in STAGES else ("completed" if new_state in TERMINAL else "starting")
            if job["status"] == "outcome_unknown" and new_state == "running":
                continue
            reconcile_requested = job["reconcile_requested"] if new_state == "outcome_unknown" else 0
            db.execute("UPDATE jobs SET status=?,started=COALESCE(started,?),ended=?,stage=?,result=?,error=?,reconcile_requested=? WHERE id=?", (new_state, time.time(), time.time() if new_state in TERMINAL else None, stage, canonical(result) if result is not None else None, error, reconcile_requested, job["id"]))
            acknowledged.append(job["id"])
        if body.get("orphanInventoryComplete") is True and node["overflow_inspect_requested"]:
            db.execute("UPDATE nodes SET orphan_overflow=0,overflow_inspect_requested=0 WHERE id=?", (node["id"],))
        db.execute("UPDATE nodes SET last_seen=?,status=?,instance_id=? WHERE id=?", (time.time(), canonical(status), instance, node["id"]))
        self.compose.observed(db, node["id"], status)
        self.mark_lost(db)
        self.expire_queued(db)
        active = db.execute("SELECT * FROM jobs WHERE status IN ('dispatched','running','outcome_unknown') ORDER BY created LIMIT 1").fetchone()
        if active is not None and active["node_id"] == node["id"] and active["status"] == "running" and active["id"] not in {report["id"] for report in reports}:
            db.execute("UPDATE jobs SET status='outcome_unknown',stage='interrupted',error='agent_receipt_missing' WHERE id=?", (active["id"],))
            active = db.execute("SELECT * FROM jobs WHERE id=?", (active["id"],)).fetchone()
        orphan_pending = db.execute("SELECT 1 FROM orphan_reports WHERE status IN ('running','outcome_unknown')").fetchone() is not None or db.execute("SELECT 1 FROM nodes WHERE orphan_overflow=1").fetchone() is not None
        if active is None and not orphan_pending:
            waiting = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created,id LIMIT 1").fetchone()
            if waiting is not None and waiting["node_id"] == node["id"] and self.status_fresh(status) and (status.get("compose", {}).get("ready") is True if waiting["action"] in compose_control.ACTIONS else status.get("supported")):
                if waiting["action"] == "backup" and status.get("serviceHealthy") is not True:
                    db.execute("UPDATE jobs SET status='failed',stage='completed',ended=?,error='primary_unavailable' WHERE id=?", (time.time(), waiting["id"]))
                    waiting = None
                elif waiting["action"] in {"restore-check", "restore-preview"} and waiting["snapshot"] not in {item["id"] for item in status["snapshots"]}:
                    db.execute("UPDATE jobs SET status='failed',stage='completed',ended=?,error='snapshot_unavailable' WHERE id=?", (time.time(), waiting["id"]))
                    waiting = None
            if waiting is not None and waiting["node_id"] == node["id"] and waiting["action"] in compose_control.ACTIONS:
                waiting = self.compose.dispatch(db, waiting)
            if waiting is not None and waiting["node_id"] == node["id"] and self.status_fresh(status) and (status.get("compose", {}).get("ready") is True if waiting["action"] in compose_control.ACTIONS else status.get("supported")):
                db.execute("UPDATE jobs SET status='dispatched',stage='starting',dispatch_instance=? WHERE id=?", (instance, waiting["id"]))
                active = db.execute("SELECT * FROM jobs WHERE id=?", (waiting["id"],)).fetchone()
        response = {"acknowledged": acknowledged}
        if discarded:
            response["discarded"] = discarded
        if active is not None and active["node_id"] == node["id"] and ((active["status"] == "dispatched" and active["dispatch_instance"] == instance and not orphan_pending) or active["reconcile_requested"]):
            response["job"] = {"id": active["id"], "nonce": active["nonce"], "action": active["action"], "snapshotId": active["snapshot"], "parameters": json.loads(active["parameters"])}
            if active["reconcile_requested"]:
                response["job"]["reconcile"] = True
        inspections = db.execute("SELECT orphan_reports.job_id,jobs.nonce FROM orphan_reports LEFT JOIN jobs ON jobs.id=orphan_reports.job_id AND jobs.node_id=orphan_reports.node_id WHERE orphan_reports.node_id=? AND orphan_reports.inspect_requested=1 AND orphan_reports.status IN ('running','outcome_unknown') ORDER BY last_inspected_sent,first_seen LIMIT 16", (node["id"],)).fetchall()
        if inspections:
            response["inspectOrphans"] = [item["job_id"] for item in inspections]
            response["inspectionNonces"] = {item["job_id"]: item["nonce"] for item in inspections if item["nonce"] is not None}
            db.executemany("UPDATE orphan_reports SET last_inspected_sent=? WHERE node_id=? AND job_id=?", [(time.time(), node["id"], item["job_id"]) for item in inspections])
        node_now = db.execute("SELECT * FROM nodes WHERE id=?", (node["id"],)).fetchone()
        if node_now["orphan_overflow"] and node_now["overflow_inspect_requested"]:
            response["inspectOverflow"] = True
        return response

    def complete_setup(self, db, body):
        fields(body)
        if db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','dispatched','running','outcome_unknown')").fetchone():
            raise APIError(409, "operation_in_progress")
        if db.execute("SELECT 1 FROM orphan_reports WHERE status IN ('running','outcome_unknown')").fetchone() or db.execute("SELECT 1 FROM nodes WHERE orphan_overflow=1").fetchone():
            raise APIError(409, "catalog_receipt_orphaned")
        nodes = db.execute("SELECT * FROM nodes").fetchall()
        primaries = [node for node in nodes if node["role"] == "primary"]
        setup = self.setting(db, "setup")
        recovery = [node for node in nodes if node["role"] == "recovery"] if setup["profile"] == "pair_assisted" else primaries
        if len(primaries) != 1 or not recovery:
            raise APIError(409, "nodes_required")
        primary = primaries[0]
        eligible = []
        for node in recovery:
            status = json.loads(node["status"])
            if self.connected(node) and self.status_fresh(status) and status.get("supported"):
                eligible.append(node)
        current = json.loads(primary["status"])
        if not eligible or not self.connected(primary) or not self.status_fresh(current) or not current.get("supported") or current.get("serviceHealthy") is not True:
            raise APIError(409, "nodes_not_ready")
        schedule = current.get("schedule", {}).get("backup", {})
        if schedule.get("enabled") is not True or schedule.get("interval") != setup["backupInterval"]:
            raise APIError(409, "schedule_required")
        max_age = {"15min": 1020, "hourly": 3720, "daily": 86520}[setup["backupInterval"]]
        backup = db.execute("SELECT * FROM jobs WHERE node_id=? AND action='backup' AND status='succeeded' AND ended>? ORDER BY ended DESC LIMIT 1", (primary["id"], time.time() - max_age)).fetchone()
        if backup is None:
            raise APIError(409, "backup_required")
        snapshot_id = json.loads(backup["result"])["snapshot"]
        validated = False
        for node in eligible:
            check = db.execute("SELECT * FROM jobs WHERE node_id=? AND action='restore-check' AND status='succeeded' AND snapshot=? AND ended>=? ORDER BY ended DESC LIMIT 1", (node["id"], snapshot_id, backup["ended"])).fetchone()
            if check is not None:
                validated = True
                break
        if not validated:
            raise APIError(409, "restore_check_required")
        setup["completed"] = True
        self.set_setting(db, "setup", setup)
        return {"completed": True}


def handler_for(control):
    class Handler(BaseHTTPRequestHandler):
        server_version = "RolyPolyOps"
        sys_version = ""
        timeout = 15

        def log_message(self, fmt, *args):
            return

        def reply(self, status, value=None, *, cookie=None, content_type="application/json; charset=utf-8", raw=None, extra=None):
            data = raw if raw is not None else canonical(value if value is not None else {}).encode()
            self.send_response(status)
            headers = {"Content-Type": content_type, "Content-Length": str(len(data)), "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY", "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'", "Connection": "close"}
            if cookie is not None:
                headers["Set-Cookie"] = COOKIE + "=" + cookie + "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=" + ("43200" if cookie else "0")
            if extra:
                headers.update(extra)
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            self.close_connection = True

        def body(self):
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,9}", lengths[0]):
                raise APIError(400, "invalid_body")
            length = int(lengths[0])
            if length > MAX_BODY:
                raise APIError(413, "body_too_large")
            if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise APIError(415, "json_required")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise APIError(400, "invalid_body")
            try:
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=json_object, parse_constant=lambda item: (_ for _ in ()).throw(ValueError("Invalid JSON constant")))
            except (ValueError, UnicodeError):
                raise APIError(400, "invalid_json") from None
            if not isinstance(value, dict):
                raise APIError(400, "invalid_request")
            return value

        def client_identity(self):
            peer = self.client_address[0]
            # The loopback reverse proxy must replace this header with its peer IP.
            forwarded = self.headers.get("X-RPO-Client-IP")
            try:
                if ipaddress.ip_address(peer).is_loopback and forwarded:
                    return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
            return peer

        def route(self):
            parsed = urlsplit(self.path)
            path = parsed.path
            if parsed.query or parsed.fragment:
                raise APIError(400, "unexpected_query")
            if path == PREFIX:
                return self.reply(308, extra={"Location": PREFIX + "/"})
            if not path.startswith(PREFIX + "/"):
                raise APIError(404, "not_found")
            route = path[len(PREFIX):]
            with control.connect() as db:
                if self.command in {"GET", "HEAD"} and not route.startswith(("/api/", "/agent/")):
                    target = "index.html" if route == "/" else route[1:]
                    if not re.fullmatch(r"[a-zA-Z0-9_.-]+\.(?:html|css|js|svg|png|ico)", target) or target.startswith("."):
                        raise APIError(404, "not_found")
                    asset = control.web_dir / target
                    if not asset.is_file() or asset.is_symlink():
                        raise APIError(404, "not_found")
                    return self.reply(200, raw=asset.read_bytes(), content_type=mimetypes.guess_type(target)[0] or "application/octet-stream")
                if self.command == "POST":
                    body = self.body()
                    db.execute("BEGIN IMMEDIATE")
                    if route == "/agent/enroll":
                        return self.reply_after_commit(db, 200, control.enroll_agent(db, body, self.client_identity()))
                    if route == "/agent/sync":
                        return self.reply_after_commit(db, 200, control.sync(db, body, self.headers.get("Authorization")))
                    if self.headers.get("Origin") != control.origin:
                        raise APIError(403, "origin_forbidden")
                    if route == "/api/login":
                        value, token = control.login(db, body, self.client_identity())
                        db.commit()
                        return self.reply(200, value, cookie=token)
                session = control.session(db, self.headers.get("Cookie", ""))
                if self.command in {"GET", "HEAD"} and route == "/api/session":
                    return self.reply(200, control.session_info(db, session))
                if session is None:
                    raise APIError(401, "authentication_required")
                if control.setting(db, "needsPasswordChange") and route not in {"/api/password", "/api/logout"}:
                    raise APIError(403, "password_change_required")
                if self.command == "POST":
                    if not opaque_matches(self.headers.get("X-CSRF-Token", ""), session["csrf"]):
                        raise APIError(403, "csrf_forbidden")
                    if route == "/api/logout":
                        fields(body)
                        db.execute("DELETE FROM sessions WHERE token_hash=?", (session["token_hash"],))
                        db.commit()
                        return self.reply(200, {"authenticated": False}, cookie="")
                    if route == "/api/password":
                        value, token = control.change_password(db, body)
                        db.commit()
                        return self.reply(200, value, cookie=token)
                    if control.setting(db, "needsPasswordChange"):
                        raise APIError(403, "password_change_required")
                    if route == "/api/storages":
                        return self.reply_after_commit(db, 200, control.compose.create_storage(db, body))
                    if route == "/api/services":
                        return self.reply_after_commit(db, 200, control.compose.import_service(db, body))
                    storage_route = re.fullmatch(r"/api/storages/([a-f0-9-]{36})/(prepare|connect)", route)
                    if storage_route:
                        fn = control.compose.prepare if storage_route[2] == "prepare" else control.compose.connect_storage
                        return self.reply_after_commit(db, 200, fn(db, storage_route[1], body))
                    service_route = re.fullmatch(r"/api/services/([a-f0-9-]{36})/(complete|activate|resume-source)", route)
                    if service_route:
                        fn = {"complete": control.compose.complete, "activate": control.compose.activate, "resume-source": control.compose.resume}[service_route[2]]
                        return self.reply_after_commit(db, 200, fn(db, service_route[1], body))
                    routes = {"/api/enrollments": control.enrollment, "/api/settings": control.settings, "/api/plans": control.plan, "/api/jobs": control.enqueue, "/api/setup/complete": control.complete_setup}
                    if route in routes:
                        result = routes[route](db, body)
                        return self.reply_after_commit(db, 202 if route == "/api/jobs" else 200, result)
                    reconnect = re.fullmatch(r"/api/nodes/([a-f0-9-]{36})/enrollment", route)
                    if reconnect:
                        return self.reply_after_commit(db, 200, control.enrollment(db, body, reconnect[1]))
                    revoked = re.fullmatch(r"/api/nodes/([a-f0-9-]{36})/revoke", route)
                    if revoked:
                        return self.reply_after_commit(db, 200, control.revoke_node(db, revoked[1], body))
                    cancelled = re.fullmatch(r"/api/enrollments/([a-f0-9-]{36})/cancel", route)
                    if cancelled:
                        return self.reply_after_commit(db, 200, control.cancel_enrollment(db, cancelled[1], body))
                    inventory_inspection = re.fullmatch(r"/api/nodes/([a-f0-9-]{36})/orphans/reconcile", route)
                    if inventory_inspection:
                        return self.reply_after_commit(db, 200, control.inspect_orphan_inventory(db, inventory_inspection[1], body))
                    orphan_inspection = re.fullmatch(r"/api/nodes/([a-f0-9-]{36})/orphans/([a-f0-9-]{36})/reconcile", route)
                    if orphan_inspection:
                        return self.reply_after_commit(db, 200, control.inspect_orphan(db, orphan_inspection[1], orphan_inspection[2], body))
                    job_action = re.fullmatch(r"/api/jobs/([a-f0-9-]{36})/(reconcile|cancel)", route)
                    if job_action:
                        function = control.reconcile_job if job_action[2] == "reconcile" else control.cancel_job
                        return self.reply_after_commit(db, 200, function(db, job_action[1], body))
                    raise APIError(404, "not_found")
                if self.command in {"GET", "HEAD"}:
                    if route == "/api/overview":
                        result = control.overview(db)
                        db.commit()
                        return self.reply(200, result)
                    job_match = re.fullmatch(r"/api/jobs/([a-f0-9-]{36})", route)
                    if job_match:
                        job = db.execute("SELECT * FROM jobs WHERE id=?", (job_match[1],)).fetchone()
                        if job is None:
                            raise APIError(404, "job_not_found")
                        return self.reply(200, {"job": control.public_job(job, db)})
                    raise APIError(404, "not_found")
                raise APIError(405, "method_not_allowed")

        def reply_after_commit(self, db, status, value):
            db.commit()
            return self.reply(status, value)

        def handle_request(self):
            try:
                self.route()
            except APIError as exc:
                self.reply(exc.status, {"error": exc.code})
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True
            except Exception:
                logging.exception("Control request failed")
                self.reply(500, {"error": "internal_error"})

        do_GET = handle_request
        do_HEAD = handle_request
        do_POST = handle_request
        do_PUT = handle_request
        do_DELETE = handle_request
        do_PATCH = handle_request

    return Handler


class ControlHTTPServer(ThreadingHTTPServer):
    """Limit concurrent request handlers even when clients send slow request bodies."""
    daemon_threads = True

    def __init__(self, *args, **kwargs):
        self.request_slots = threading.BoundedSemaphore(32)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.request_slots.acquire(blocking=False):
            try:
                request.settimeout(1)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.request_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


def main():
    parser = argparse.ArgumentParser(description="RolyPolyOps control service")
    parser.add_argument("command", choices=("init", "serve"))
    parser.add_argument("--data-dir", default="/var/lib/rolypolyops-control")
    parser.add_argument("--origin", required=True)
    parser.add_argument("--host", choices=("127.0.0.1",), default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--allow-http", action="store_true", help="Allow loopback HTTP for local tests")
    args = parser.parse_args()
    os.umask(0o077)
    control = Control(args.data_dir, args.origin, allow_http=args.allow_http)
    if args.command == "serve":
        server = ControlHTTPServer((args.host, args.port), handler_for(control))
        server.serve_forever()


if __name__ == "__main__":
    main()
