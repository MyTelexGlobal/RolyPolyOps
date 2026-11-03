"""Root-owned Unix broker and one-shot isolated storage execution."""
import base64
import contextlib
import grp
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid

try:
    from .compose_storage_bridge import ProtocolError, read_headers, pump, receive_frame, send_frame
except ImportError:
    from compose_storage_bridge import ProtocolError, read_headers, pump, receive_frame, send_frame

DEFAULT_WORKER_USER = "rolypolyops-storage"
MAX_RESULT = 16 * 1024 * 1024
CLEANUP_SECONDS = 15
CLEAN_ENV = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"}
ACCOUNT_MARKER = Path("/etc/rolypolyops/storage-worker.json")
RUN_ROOT = Path("/run/rolypolyops-storage")
CGROUP_ROOT = Path("/sys/fs/cgroup")


class TransportError(Exception):
    def __init__(self, code, unknown=False):
        self.code, self.unknown = code, unknown
        super().__init__(code)


def atomic(path, value):
    path = Path(path)
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def trusted(path, *, directory=False, mode=None):
    path = Path(path)
    value = path.lstat()
    if (value.st_uid != 0 or stat.S_ISLNK(value.st_mode) or value.st_mode & 0o022
            or (directory and not stat.S_ISDIR(value.st_mode))
            or (not directory and not stat.S_ISREG(value.st_mode))
            or (mode is not None and stat.S_IMODE(value.st_mode) != mode)):
        raise TransportError("network_isolation_unavailable")
    return value


def read_owned(path, maximum, *, mode=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022
                or (mode is not None and stat.S_IMODE(value.st_mode) != mode)):
            raise TransportError("network_isolation_unavailable")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise TransportError("network_isolation_unavailable")
        return raw
    finally:
        os.close(fd)


def read_json(path):
    return json.loads(read_owned(path, 65536, mode=0o600))


def pid_birth(pid):
    raw = Path("/proc", str(pid), "stat").read_text()
    return raw[raw.rfind(")") + 2:].split()[19]


def pid_gone(pid, birth):
    try:
        return pid_birth(pid) != birth
    except FileNotFoundError:
        return True
    except (OSError, ValueError, IndexError):
        return False


def process_cgroup(pid):
    rows = Path("/proc", str(pid), "cgroup").read_text().splitlines()
    if len(rows) != 1 or not rows[0].startswith("0::/"):
        raise TransportError("network_isolation_unavailable")
    return rows[0][3:]


def systemctl(unit, timeout=5):
    command = ["systemctl", "show", "--all", "--no-pager", unit]
    try:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                env=CLEAN_ENV, timeout=timeout, check=False)
        if len(result.stdout) > 256 * 1024:
            raise TransportError("transport_cleanup_unverified", True)
        value = dict(line.split("=", 1) for line in result.stdout.decode().splitlines() if "=" in line)
        if value.get("LoadState") == "not-found":
            return None
        if result.returncode or value.get("Id") != unit:
            raise TransportError("transport_cleanup_unverified", True)
        return value
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        raise TransportError("transport_cleanup_unverified", True) from None


def validate_marker_path(value=None):
    value = str(ACCOUNT_MARKER) if value is None else value
    try:
        if (not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= 4096 or not value.startswith("/")
                or value.startswith("//") or not value.isprintable()
                or any(part in {".", ".."} for part in value.split("/")) or str(Path(value)) != value):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise TransportError("network_isolation_unavailable") from None


def marker_file(value=None):
    path = Path(validate_marker_path(value))
    for parent in reversed(path.parents):
        trusted(parent, directory=True)
    trusted(path, mode=0o600)
    return path


def valid_identity(value):
    return (isinstance(value, dict) and set(value) == {"user", "uid", "gid"}
            and isinstance(value["user"], str) and re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", value["user"]) is not None
            and type(value["uid"]) is int and value["uid"] > 0 and type(value["gid"]) is int and value["gid"] > 0)


def account(worker_user, marker_path=None):
    try:
        if not isinstance(worker_user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", worker_user):
            raise ValueError()
        marker = read_json(marker_file(marker_path))
        if not valid_identity(marker):
            raise ValueError()
        user = pwd.getpwnam(worker_user)
        group = grp.getgrgid(user.pw_gid)
        expected = {"user": worker_user, "uid": user.pw_uid, "gid": user.pw_gid}
        if (marker != expected or user.pw_uid <= 0 or user.pw_gid <= 0 or group.gr_name != worker_user
                or user.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
                or any((entry.pw_gid == user.pw_gid or entry.pw_uid == user.pw_uid) and entry.pw_name != worker_user for entry in pwd.getpwall())
                or any(member != worker_user for member in group.gr_mem)
                or any((worker_user in entry.gr_mem and entry.gr_gid != user.pw_gid)
                       or (entry.gr_gid == user.pw_gid and entry.gr_name != worker_user) for entry in grp.getgrall())):
            raise ValueError()
        return expected
    except (OSError, KeyError, ValueError, TypeError):
        raise TransportError("network_isolation_unavailable") from None


def prerequisites():
    try:
        if sys.platform != "linux" or os.geteuid() != 0 or not (CGROUP_ROOT / "cgroup.controllers").is_file():
            raise ValueError()
        trusted(Path("/usr/bin/python3").resolve())
        version = subprocess.run(["/usr/bin/python3", "-c", "import sys;print('%d.%d'%sys.version_info[:2])"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV, timeout=5)
        if version.returncode or tuple(int(v) for v in version.stdout.decode().strip().split(".")) < (3, 11):
            raise ValueError()
        manager = subprocess.run(["systemd-run", "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env=CLEAN_ENV, timeout=5)
        if manager.returncode or int(manager.stdout.splitlines()[0].split()[1]) < 252:
            raise ValueError()
        binary = shutil.which("restic", path=CLEAN_ENV["PATH"])
        if not binary:
            raise ValueError()
        trusted(binary)
        return str(Path(binary).resolve())
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        raise TransportError("network_isolation_unavailable") from None


def caller():
    try:
        path = process_cgroup(os.getpid())
        unit = path.rsplit("/", 1)[-1]
        if not re.fullmatch(r"[A-Za-z0-9_.:@\\-]+\.service", unit):
            raise ValueError()
        value = systemctl(unit)
        if (not value or value.get("ActiveState") != "active" or value.get("Type") not in {"simple", "exec", "notify", "notify-reload", "dbus"}
                or value.get("ControlGroup") != path or int(value.get("MainPID", "0")) != os.getpid()
                or not re.fullmatch(r"[a-f0-9]{32}", value.get("InvocationID", ""))):
            raise ValueError()
        return {"unit": unit, "invocationId": value["InvocationID"], "pid": os.getpid(), "birth": pid_birth(os.getpid())}
    except (OSError, ValueError, TransportError):
        raise TransportError("network_isolation_unavailable") from None


def public_addresses(host, port):
    try:
        values = sorted({entry[4][0] for entry in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
        for value in values:
            address = ipaddress.ip_address(value)
            if (not address.is_global or address.is_multicast or address.is_reserved or address.is_unspecified
                    or address.is_loopback or address.is_link_local or address.is_private
                    or (address.version == 6 and (address.ipv4_mapped is not None or address.sixtofour is not None
                                                or address.teredo is not None or address in ipaddress.ip_network("64:ff9b::/96")
                                                or address in ipaddress.ip_network("64:ff9b:1::/48")))):
                raise TransportError("storage_address_forbidden")
        if not values or len(values) > 64:
            raise TransportError("storage_address_forbidden")
        return values
    except (socket.gaierror, ValueError):
        raise TransportError("storage_dns_failed") from None


def authority(host, port):
    return ("[" + host.lower() + "]" if ":" in host else host.lower()) + ":" + str(port)


class UnixHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, unix_path, token, timeout=30):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.unix_path, self.token = str(unix_path), token

    def connect(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        try:
            connection.connect(self.unix_path)
            auth = base64.b64encode(("rpo:" + self.token).encode()).decode()
            connection.sendall(("CONNECT " + authority(self.host, self.port) + " HTTP/1.1\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n").encode())
            response = bytearray()
            end = time.monotonic() + min(5, self.timeout)
            while b"\r\n\r\n" not in response:
                connection.settimeout(max(0.01, end - time.monotonic()))
                block = connection.recv(4096)
                if not block or len(response) + len(block) > 16384 or time.monotonic() >= end:
                    raise OSError()
                response.extend(block)
            head, tail = bytes(response).split(b"\r\n\r\n", 1)
            if head.split(b"\r\n", 1)[0] != b"HTTP/1.1 200 Connection Established" or tail:
                raise OSError()
            connection.settimeout(self.timeout)
            self.sock = self._context.wrap_socket(connection, server_hostname=self.host)
        except BaseException:
            connection.close()
            raise


class Broker:
    def __init__(self, path, host, port, addresses, uid, gid, cgroup, root_token, worker_token, deadline):
        self.path, self.host, self.port = Path(path), host, port
        self.authority, self.addresses = authority(host, port), tuple(addresses)
        self.uid, self.gid, self.cgroup = uid, gid, cgroup
        self.root_pid, self.root_birth = os.getpid(), pid_birth(os.getpid())
        self.root_token, self.worker_token = root_token, worker_token
        self.deadline = min(deadline, time.monotonic() + 7200)
        self.stopped, self.mutex = threading.Event(), threading.Lock()
        self.slots = threading.BoundedSemaphore(32)
        self.connections, self.threads = set(), set()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(self.path))
        os.chown(self.path, 0, gid)
        os.chmod(self.path, 0o660)
        self.listener.listen(32)
        self.listener.settimeout(0.2)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def _authorized(self, connection, authorization):
        pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        token = "Basic " + base64.b64encode(("rpo:" + (self.root_token if pid == self.root_pid and uid == 0 else self.worker_token)).encode()).decode()
        if not hmac.compare_digest(authorization, token):
            return False
        if pid == self.root_pid and uid == 0:
            return pid_birth(pid) == self.root_birth
        return uid == self.uid and gid == self.gid and process_cgroup(pid) == self.cgroup

    def handle(self, client):
        remote = None
        try:
            method, requested, headers, _, tail = read_headers(client, self.deadline)
            if method != "CONNECT" or requested.lower() != self.authority or tail or not self._authorized(client, headers.get("proxy-authorization", "")):
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length:0\r\n\r\n")
                return
            for address in self.addresses:
                if time.monotonic() >= self.deadline:
                    break
                try:
                    remote = socket.create_connection((address, self.port), timeout=min(5, max(0.1, self.deadline - time.monotonic())))
                    break
                except OSError:
                    continue
            if remote is None:
                raise OSError()
            with self.mutex:
                self.connections.add(remote)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pump(client, remote, self.deadline, self.stopped)
        except ProtocolError as error:
            try:
                status = b"503 Unavailable" if getattr(error, "limit", False) else b"403 Forbidden"
                client.sendall(b"HTTP/1.1 " + status + b"\r\nContent-Length:0\r\n\r\n")
            except OSError:
                pass
        except (OSError, TransportError, ValueError):
            pass
        finally:
            with self.mutex:
                self.connections.discard(client)
                if remote:
                    self.connections.discard(remote)
                self.threads.discard(threading.current_thread())
            client.close()
            if remote:
                remote.close()
            self.slots.release()

    def serve(self):
        while not self.stopped.is_set() and time.monotonic() < self.deadline:
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if not self.slots.acquire(blocking=False):
                try:
                    client.settimeout(0.2)
                    client.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length:0\r\n\r\n")
                except OSError:
                    pass
                client.close()
                continue
            with self.mutex:
                self.connections.add(client)
                thread = threading.Thread(target=self.handle, args=(client,), daemon=True)
                self.threads.add(thread)
            thread.start()

    def close(self, timeout=3):
        self.stopped.set()
        self.listener.close()
        with self.mutex:
            for connection in self.connections:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            threads = list(self.threads)
        end = time.monotonic() + max(0, timeout)
        for thread in [self.thread, *threads]:
            thread.join(max(0, end - time.monotonic()))
        if any(thread.is_alive() for thread in [self.thread, *threads]):
            raise TransportError("transport_cleanup_unverified", True)

    def connection(self, host, port):
        if authority(host, port) != self.authority:
            raise TransportError("storage_address_forbidden")
        return UnixHTTPSConnection(host, port, self.path, self.root_token)


def unit_properties(intent, request, password, timeout):
    values = {
        "Description": intent["marker"], "User": intent["account"]["user"], "Group": intent["account"]["user"],
        "Type": "exec", "PrivateNetwork": "yes", "CapabilityBoundingSet": "", "AmbientCapabilities": "",
        "NoNewPrivileges": "yes", "RestrictNamespaces": "yes", "ProtectControlGroups": "yes", "ProtectSystem": "strict",
        "ProtectHome": "yes", "PrivateTmp": "yes", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "SystemCallFilter": "~setns unshare mount umount2 ptrace open_by_handle_at",
        "SecureBits": "noroot noroot-locked no-setuid-fixup no-setuid-fixup-locked", "KillMode": "control-group",
        "Restart": "no", "RuntimeMaxSec": str(min(7215, timeout + CLEANUP_SECONDS)), "TimeoutStopSec": "3",
        "SendSIGKILL": "yes", "LimitCORE": "0", "UMask": "0077",
        "UnsetEnvironment": "RESTIC_REPOSITORY RESTIC_PASSWORD RESTIC_PASSWORD_FILE RESTIC_REST_USERNAME RESTIC_REST_PASSWORD AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_DEFAULT_REGION HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy",
    }
    if intent.get("caller"):
        values.update(BindsTo=intent["caller"]["unit"], After=intent["caller"]["unit"])
    args = ["systemd-run", "--quiet", "--wait", "--collect", "--pipe", "--no-ask-password", "--unit=" + intent["unit"]]
    for name, value in values.items():
        args += ["--property=" + name + "=" + value]
    args += ["--property=LoadCredential=request:" + str(request)]
    if password:
        args += ["--property=LoadCredential=password:" + str(password)]
    return args + intent["argv"]


DEFINITION_FIELDS = ("Type", "PrivateNetwork", "CapabilityBoundingSet", "AmbientCapabilities", "NoNewPrivileges", "RestrictNamespaces",
                     "ProtectControlGroups", "ProtectSystem", "ProtectHome", "PrivateTmp", "RestrictAddressFamilies", "SystemCallFilter",
                     "SecureBits", "KillMode", "Restart", "RuntimeMaxUSec", "TimeoutStopUSec", "SendSIGKILL", "LimitCORE", "UMask",
                     "BindsTo", "After", "LoadCredential", "UnsetEnvironment")


def owned_unit(value, intent):
    if not value:
        return True
    command = value.get("ExecStart", "")
    expected = "argv[]=" + " ".join(intent["argv"]) + " ;"
    fixed = {"Type": "exec", "PrivateNetwork": "yes", "NoNewPrivileges": "yes", "RestrictNamespaces": "yes",
             "ProtectControlGroups": "yes", "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes",
             "KillMode": "control-group", "Restart": "no", "SendSIGKILL": "yes", "LimitCORE": "0", "UMask": "0077"}
    sandbox = (all(value.get(key) == expected for key, expected in fixed.items())
               and all(value.get(key) in {"", "0", "0x0", "0x0000000000000000"} for key in ("CapabilityBoundingSet", "AmbientCapabilities"))
               and value.get("SecureBits") in {"15", "noroot noroot-locked no-setuid-fixup no-setuid-fixup-locked"}
               and set(value.get("RestrictAddressFamilies", "").split()) == {"AF_UNIX", "AF_INET", "AF_INET6"}
               and value.get("SystemCallFilter", "").startswith("~")
               and set(value["SystemCallFilter"].lstrip("~").split()) == {"setns", "unshare", "mount", "umount2", "ptrace", "open_by_handle_at"})
    if intent.get("caller"):
        sandbox = sandbox and all(intent["caller"]["unit"] in value.get(name, "").split() for name in ("BindsTo", "After"))
    recorded = intent.get("unitDefinition")
    unchanged = recorded is None or recorded == {key: value.get(key, "") for key in DEFINITION_FIELDS}
    return (sandbox and unchanged and value.get("Id") == intent["unit"] and value.get("Transient") == "yes"
            and value.get("Description") == intent["marker"] and value.get("User") == intent["account"]["user"]
            and value.get("Group") == intent["account"]["user"] and value.get("ControlGroup") in {intent["cgroup"], ""}
            and "path=/usr/bin/python3 ;" in command and expected in command and command.count("argv[]=") == 1
            and all(not value.get(name) for name in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload")))


def cgroup_empty(path):
    if not isinstance(path, str) or not re.fullmatch(r"/system.slice/rpo-storage-[a-f0-9]{32}\.service", path):
        return False
    directory = CGROUP_ROOT / path.lstrip("/")
    try:
        try:
            value = directory.lstat()
        except FileNotFoundError:
            return True
        if not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode):
            return False
        def inaccessible(error):
            raise error
        for root, dirs, _ in os.walk(directory, followlinks=False, onerror=inaccessible):
            for name in dirs:
                if (Path(root) / name).is_symlink():
                    return False
            if (Path(root) / "cgroup.procs").read_text().strip():
                return False
            events = dict(line.split() for line in (Path(root) / "cgroup.events").read_text().splitlines())
            if events.get("populated") != "0":
                return False
        return True
    except (OSError, ValueError):
        return False


def verify_worker_fds(pid, proof, incoming, outgoing, launcher):
    control_fd = proof.get("controlFd")
    if type(control_fd) is not int or control_fd <= 2 or set(os.listdir("/proc/" + str(pid) + "/fd")) != {"0", "1", "2", str(control_fd)}:
        raise TransportError("worker_isolation_preflight_failed")
    expected = [os.fstat(incoming.fileno()) if incoming else os.stat("/dev/null"),
                os.fstat(outgoing.fileno()) if outgoing else os.fstat(launcher.stdout.fileno())]
    for fd, value in enumerate(expected):
        actual = os.stat("/proc/" + str(pid) + "/fd/" + str(fd))
        if (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)) != (value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)):
            raise TransportError("worker_isolation_preflight_failed")
    error_fd = os.stat("/proc/" + str(pid) + "/fd/2")
    if not stat.S_ISCHR(error_fd.st_mode) or error_fd.st_rdev != os.stat("/dev/null").st_rdev:
        raise TransportError("worker_isolation_preflight_failed")


class StorageTransport:
    def __init__(self, state, worker_user=None, node_id=None, marker_path=None):
        self.state = Path(state)
        self.node_id = node_id
        self.worker_user = worker_user
        self.marker_path = marker_path
        self._selected_marker = None
        self.directory = self.state / "transport"
        self.source_dir = Path(__file__).resolve().parent
        self._account = None
        self._restic = None
        self._active = set()
        self._probe_until = 0

    def settings(self, *, recovery=False):
        path = self.state / "transport-settings.json"
        try:
            saved = read_json(path) if path.exists() or path.is_symlink() else None
            if saved is not None:
                if (not isinstance(saved, dict) or set(saved) not in ({"user", "uid", "gid"}, {"user", "uid", "gid", "markerPath"})
                        or not valid_identity({key: saved[key] for key in ("user", "uid", "gid")})
                        or ("markerPath" in saved and not isinstance(saved["markerPath"], str))):
                    raise TransportError("network_isolation_unavailable")
                pinned_marker = validate_marker_path(saved.get("markerPath"))
            else:
                if recovery or self.directory.exists() or self.directory.is_symlink():
                    raise TransportError("transport_cleanup_unverified", True)
                pinned_marker = None
            if not recovery:
                if self.worker_user is not None and (not isinstance(self.worker_user, str) or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,30}", self.worker_user)):
                    raise TransportError("network_isolation_unavailable")
                requested_marker = validate_marker_path(self.marker_path) if self.marker_path is not None else None
                if saved is not None and ((self.worker_user is not None and self.worker_user != saved["user"])
                                          or (requested_marker is not None and requested_marker != pinned_marker)):
                    raise TransportError("network_isolation_unavailable")
            else:
                requested_marker = None  # Recovery uses the old durable authority, never changed caller options.
            selected = saved["user"] if saved is not None else (self.worker_user or DEFAULT_WORKER_USER)
            selected_marker = pinned_marker or requested_marker or validate_marker_path()
            current = account(selected) if selected_marker == str(ACCOUNT_MARKER) else account(selected, marker_path=selected_marker)
            if not valid_identity(current) or (saved is not None and any(saved[key] != current[key] for key in ("user", "uid", "gid"))):
                raise TransportError("network_isolation_unavailable")
            pinned = {**current, "markerPath": selected_marker}
            # A legacy pin can only reach here through the verified default marker with the same identity.
            if saved != pinned:
                trusted(self.state, directory=True, mode=0o700)
                atomic(path, pinned)
            self._account, self._selected_marker = current, selected_marker
            return current
        except (OSError, ValueError, TypeError, KeyError):
            raise TransportError("network_isolation_unavailable") from None

    def _prerequisites(self, *, standalone=False):
        self._restic = prerequisites()
        identity = self.settings()
        parent = None if standalone else caller()
        calls = self.directory / "calls"
        if calls.exists() and any(path.stem not in self._active for path in calls.glob("*.json")):
            raise TransportError("transport_cleanup_unverified", True)
        return identity, parent

    def preflight(self, *, timeout=30):
        identity, parent = self._prerequisites()
        # A fresh engine proves the actual sandbox before generation acceptance or source pause.
        # Native calls additionally repeat their own full handshake before any backend request.
        if time.monotonic() >= self._probe_until:
            self._execute({}, ["version"], timeout=min(30, max(1, timeout)), probe=True)
            self._probe_until = time.monotonic() + 30
        return identity, parent

    def _prepare(self, *, timeout, parent, identity, action):
        trusted(self.state, directory=True, mode=0o700)
        for directory in (self.directory, self.directory / "calls"):
            directory.mkdir(mode=0o700, exist_ok=True)
            trusted(directory, directory=True, mode=0o700)
        owner_path = self.directory / "owner.json"
        if not owner_path.exists():
            atomic(owner_path, {"id": str(uuid.uuid4())})
        owner = read_json(owner_path)["id"]
        if str(uuid.UUID(owner)) != owner:
            raise TransportError("transport_cleanup_unverified", True)
        try:
            RUN_ROOT.mkdir(mode=0o711)
            os.chmod(RUN_ROOT, 0o711)
        except FileExistsError:
            pass
        trusted(RUN_ROOT, directory=True, mode=0o711)
        identifier = uuid.uuid4().hex
        directory = RUN_ROOT / identifier
        directory.mkdir(mode=0o710)
        os.chown(directory, 0, identity["gid"])
        os.chmod(directory, 0o710)
        secret = directory / "secret"
        secret.mkdir(mode=0o700)
        code = directory / "code"
        code.mkdir(mode=0o755)
        os.chmod(code, 0o755)
        unit = "rpo-storage-" + identifier + ".service"
        marker = "RolyPolyOps storage " + owner + " " + identifier
        intent = {"v": 1, "nodeId": self.node_id, "id": identifier, "owner": owner, "state": str(self.state.resolve()), "unit": unit,
                  "marker": marker, "directory": str(directory), "account": identity, "markerPath": self._selected_marker, "caller": parent,
                  "cgroup": "/system.slice/" + unit, "argv": ["/usr/bin/python3", str(code / "compose_storage_worker.py")],
                  "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(), "rootPid": os.getpid(),
                  "rootBirth": pid_birth(os.getpid()), "stage": "staging", "action": action,
                  "permissionInvocationId": None, "pids": [], "launcherCompleted": False, "rootContextClosed": True}
        path = self.directory / "calls" / (identifier + ".json")
        atomic(path, intent)
        try:
            for name in ("compose_storage_worker.py", "compose_storage_bridge.py"):
                source = self.source_dir / name
                raw = read_owned(source, 256 * 1024)
                fd = os.open(code / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
                os.fchmod(fd, 0o444)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(raw)
                    stream.flush()
                    os.fsync(stream.fileno())
            os.chmod(code, 0o555)
            intent["stage"] = "prepared"
            atomic(path, intent)
        except (OSError, ValueError, TransportError):
            self._cleanup(intent, path)
            raise TransportError("network_isolation_unavailable") from None
        return intent, path

    def _validate_intent(self, intent, path):
        owner = read_json(self.directory / "owner.json")["id"]
        identifier = intent.get("id", "")
        identity = intent.get("account", {})
        pinned = self.settings(recovery=True)
        if "markerPath" in intent and not isinstance(intent["markerPath"], str):
            raise TransportError("transport_cleanup_unverified", True)
        intent_marker = validate_marker_path(intent.get("markerPath"))
        expected_dir = RUN_ROOT / identifier
        expected_unit = "rpo-storage-" + identifier + ".service"
        if (not re.fullmatch(r"[a-f0-9]{32}", identifier) or path.name != identifier + ".json"
                or intent.get("owner") != owner or intent.get("nodeId") != self.node_id or intent.get("state") != str(self.state.resolve())
                or intent.get("directory") != str(expected_dir) or intent.get("unit") != expected_unit
                or intent.get("cgroup") != "/system.slice/" + expected_unit
                or intent.get("marker") != "RolyPolyOps storage " + owner + " " + identifier
                or intent.get("argv") != ["/usr/bin/python3", str(expected_dir / "code" / "compose_storage_worker.py")]
                or not valid_identity(identity) or identity != pinned or intent_marker != self._selected_marker):
            raise TransportError("transport_cleanup_unverified", True)
        if expected_dir.exists() or expected_dir.is_symlink():
            value = trusted(expected_dir, directory=True, mode=0o710)
            if value.st_gid != identity["gid"]:
                raise TransportError("transport_cleanup_unverified", True)
            trusted(expected_dir / "secret", directory=True, mode=0o700)
            code = trusted(expected_dir / "code", directory=True)
            if stat.S_IMODE(code.st_mode) not in ({0o755, 0o555} if intent.get("stage") == "staging" else {0o555}):
                raise TransportError("transport_cleanup_unverified", True)
        return True

    @staticmethod
    def _consume_permission(intent, path, invocation, pid, birth):
        if intent.get("permissionInvocationId") is not None or not re.fullmatch(r"[a-f0-9]{32}", invocation):
            raise TransportError("worker_execution_denied", True)
        intent["permissionInvocationId"] = invocation
        intent["stage"] = "execution-permitted"
        intent["pids"].append({"pid": pid, "birth": birth})
        atomic(path, intent)

    def _cleanup(self, intent, path, launcher=None, deadline=None, retain=False):
        end = deadline if deadline is not None else time.monotonic() + CLEANUP_SECONDS
        try:
            self._validate_intent(intent, path)
            old_boot = intent["bootId"] != Path("/proc/sys/kernel/random/boot_id").read_text().strip()
            value = systemctl(intent["unit"], timeout=min(3, max(0.1, end - time.monotonic())))
            if not owned_unit(value, intent):
                raise TransportError("transport_cleanup_unverified", True)
            changed = bool(value and intent.get("permissionInvocationId") and value.get("InvocationID") != intent["permissionInvocationId"])
            if value:
                result = subprocess.run(["systemctl", "stop", intent["unit"]], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL, env=CLEAN_ENV, timeout=min(6, max(0.1, end - time.monotonic())))
                if result.returncode:
                    raise TransportError("transport_cleanup_unverified", True)
            if launcher is not None:
                try:
                    launcher.wait(timeout=max(0.1, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    raise TransportError("transport_cleanup_unverified", True) from None
                intent["launcherCompleted"] = True
                atomic(path, intent)
            elif not old_boot and not intent.get("launcherCompleted"):
                launcher_record = intent.get("launcher")
                if intent.get("stage") in {"staging", "prepared"}:
                    pass  # No launch was attempted. Launching is durable before Popen.
                elif (not launcher_record or not pid_gone(launcher_record["pid"], launcher_record["birth"])
                      or (value is None and intent.get("permissionInvocationId") is None)):
                    raise TransportError("transport_cleanup_unverified", True)
            while True:
                value = systemctl(intent["unit"], timeout=min(2, max(0.1, end - time.monotonic())))
                if not owned_unit(value, intent):
                    raise TransportError("transport_cleanup_unverified", True)
                dead = (not value or (value.get("ActiveState") in {"inactive", "failed"} and value.get("Job", "0") in {"0", ""}))
                births_gone = old_boot or all(pid_gone(p["pid"], p["birth"]) for p in intent.get("pids", []))
                if dead and cgroup_empty(intent["cgroup"]) and births_gone and time.monotonic() <= end:
                    break
                if time.monotonic() >= end:
                    raise TransportError("transport_cleanup_unverified", True)
                time.sleep(0.05)
            root_context_dead = intent.get("rootContextClosed") is True or old_boot or pid_gone(intent["rootPid"], intent["rootBirth"])
            if changed or retain or not root_context_dead:
                if changed:
                    intent["stage"] = "changed-invocation-dead"
                atomic(path, intent)
                raise TransportError("transport_cleanup_unverified", True)
            # Only exact recorded own resources are removed after all death proofs.
            directory = Path(intent["directory"])
            if directory.exists():
                shutil.rmtree(directory)
            path.unlink()
            fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, TransportError):
            raise TransportError("transport_cleanup_unverified", True) from None

    def recover(self):
        calls = self.directory / "calls"
        if not self.directory.exists() and not self.directory.is_symlink():
            return []
        try:
            self.settings(recovery=True)
            trusted(self.directory, directory=True, mode=0o700)
            trusted(calls, directory=True, mode=0o700)
            paths = sorted(calls.glob("*.json"))
            if len(paths) > 1000:
                raise TransportError("transport_cleanup_unverified", True)
        except (OSError, ValueError, KeyError, TypeError, TransportError):
            raise TransportError("transport_cleanup_unverified", True) from None
        recovered = []
        for path in paths:
            try:
                intent = read_json(path)
                self._cleanup(intent, path)
                recovered.append(intent["id"])
            except (OSError, ValueError, KeyError, TypeError, TransportError):
                raise TransportError("transport_cleanup_unverified", True) from None
        return recovered

    @contextlib.contextmanager
    def session(self, metadata):
        # Root Python HTTPS listings use their exact parent PID token on the same Unix-only boundary.
        identity, parent = self.preflight()
        parsed = urllib.parse.urlsplit(metadata["endpoint"])
        host, port = parsed.hostname, parsed.port if parsed.port is not None else 443
        addresses = public_addresses(host, port)
        intent, path = self._prepare(timeout=7200, parent=parent, identity=identity, action="listing")
        self._active.add(intent["id"])
        broker = None
        try:
            root_token, worker_token = secrets.token_hex(32), secrets.token_hex(32)
            intent["rootContextClosed"] = False
            atomic(path, intent)
            broker = Broker(Path(intent["directory"]) / "data", host, port, addresses, identity["uid"], identity["gid"], intent["cgroup"], root_token, worker_token, time.monotonic() + 7200)
            yield broker
        finally:
            if broker:
                broker.close(timeout=CLEANUP_SECONDS)
            intent["rootContextClosed"] = True
            atomic(path, intent)
            self._cleanup(intent, path)
            self._active.discard(intent["id"])

    def execute(self, env, args, *, timeout=7200, input_file=None, output_file=None, output_limit=None, probe=False):
        try:
            return self._execute(env, args, timeout=timeout, input_file=input_file, output_file=output_file, output_limit=output_limit, probe=probe)
        except TransportError:
            raise
        except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError):
            # An interrupted setup retains its durable intent for locked recovery.
            raise TransportError("transport_cleanup_unverified", True) from None

    def _execute(self, env, args, *, timeout=7200, input_file=None, output_file=None, output_limit=None, probe=False, standalone=False):
        timeout = min(7200, max(1, timeout))
        identity, parent = self._prerequisites(standalone=standalone) if probe else self.preflight()
        if not probe:
            parsed = urllib.parse.urlsplit(env["RESTIC_REPOSITORY"].split(":", 1)[1])
            host, port = parsed.hostname, parsed.port if parsed.port is not None else 443
            addresses = public_addresses(host, port)
        intent, path = self._prepare(timeout=timeout, parent=parent, identity=identity, action="probe" if probe else "restic")
        directory = Path(intent["directory"])
        control_socket = directory / "control"
        root_token, data_token, control_token = (secrets.token_hex(32) for _ in range(3))
        deadline = time.monotonic() + timeout
        namespace = os.stat("/proc/self/ns/net")
        request = {"callId": intent["id"], "action": "probe" if probe else "restic", "uid": identity["uid"], "gid": identity["gid"],
                   "cgroup": intent["cgroup"], "hostNetns": [namespace.st_dev, namespace.st_ino], "rootPid": os.getpid(),
                   "rootBirth": pid_birth(os.getpid()), "controlSocket": str(control_socket), "dataSocket": str(directory / "data"),
                   "controlToken": control_token, "dataToken": data_token, "deadline": deadline, "args": args,
                   "env": {} if probe else {k: v for k, v in env.items() if k not in {"RESTIC_PASSWORD_FILE", "PATH", "HOME", "LANG"}},
                   "kind": "s3" if not probe and env["RESTIC_REPOSITORY"].startswith("s3:") else "rest", "restic": self._restic,
                   "outputLimit": output_limit}
        request_path = directory / "secret" / "request"
        atomic(request_path, request)
        password_path = None
        if not probe:
            password_path = directory / "secret" / "password"
            source = Path(env["RESTIC_PASSWORD_FILE"])
            data = read_owned(source, 16385, mode=0o600)
            if not data or len(data) > 16385:
                raise TransportError("network_isolation_unavailable")
            fd = os.open(password_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        listener = broker = launcher = incoming = outgoing = None
        control_thread = None
        state = {"finished": False, "error": None, "returncode": None, "connection": None}
        mutex, stopped, launched = threading.Lock(), threading.Event(), threading.Event()

        def save():
            atomic(path, intent)

        def control():
            connection = None
            try:
                listener.settimeout(0.2)
                while not stopped.is_set() and time.monotonic() < deadline:
                    try:
                        connection, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                if connection is None:
                    return
                state["connection"] = connection
                connection.settimeout(min(10, max(0.1, deadline - time.monotonic())))
                pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                message = receive_frame(connection)
                proof = message.get("proof", {})
                value = systemctl(intent["unit"])
                if (message.get("phase") != "ready" or message.get("callId") != intent["id"]
                        or not hmac.compare_digest(str(message.get("token", "")), control_token)
                        or uid != identity["uid"] or gid != identity["gid"] or proof.get("pid") != pid
                        or proof.get("birth") != pid_birth(pid) or process_cgroup(pid) != intent["cgroup"]
                        or not owned_unit(value, intent) or not value or int(value.get("MainPID", "0")) != pid
                        or not re.fullmatch(r"[a-f0-9]{32}", value.get("InvocationID", ""))
                        or proof.get("invocationId") != value["InvocationID"]
                        or proof.get("uid") != uid or proof.get("gid") != gid
                        or set(proof.get("groups", [])) - {gid} or proof.get("caps") != [0] * 5
                        or proof.get("noNewPrivs") != 1 or proof.get("securebits") != 15
                        or proof.get("netns") == request["hostNetns"] or proof.get("cgroup") != intent["cgroup"]
                        or len(proof.get("fds", [])) != 3 or any(v not in {"file", "pipe", "devnull"} for v in proof["fds"])):
                    raise TransportError("worker_isolation_preflight_failed")
                if not launched.wait(min(5, max(0, deadline - time.monotonic()))):
                    raise TransportError("worker_isolation_preflight_failed")
                verify_worker_fds(pid, proof, incoming, outgoing, launcher)
                actual_namespace = os.stat("/proc/" + str(pid) + "/ns/net")
                actual_status = dict(line.split(":", 1) for line in Path("/proc", str(pid), "status").read_text().splitlines() if ":" in line)
                if ([actual_namespace.st_dev, actual_namespace.st_ino] != proof["netns"]
                        or any(int(actual_status.get(name, "1").strip(), 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                        or actual_status.get("NoNewPrivs", "").strip() != "1"
                        or [int(v) for v in actual_status.get("Uid", "").split()] != [uid] * 4
                        or [int(v) for v in actual_status.get("Gid", "").split()] != [gid] * 4
                        or set(map(int, actual_status.get("Groups", "").split())) - {gid}):
                    raise TransportError("worker_isolation_preflight_failed")
                with mutex:
                    intent["unitDefinition"] = {key: value.get(key, "") for key in DEFINITION_FIELDS}
                    self._consume_permission(intent, path, value["InvocationID"], pid, proof["birth"])
                    # The fsynced permission above precedes go; there is never a second go.
                send_frame(connection, {"go": True, "callId": intent["id"], "invocationId": value["InvocationID"]})
                while not stopped.is_set():
                    connection.settimeout(max(0.1, deadline - time.monotonic()))
                    message = receive_frame(connection)
                    if message.get("phase") == "started" and type(message.get("pid")) is int:
                        native_pid = message["pid"]
                        if message.get("birth") is not None:
                            if not pid_gone(native_pid, message["birth"]) and process_cgroup(native_pid) != intent["cgroup"]:
                                raise TransportError("worker_isolation_preflight_failed", True)
                            with mutex:
                                intent["pids"].append({"pid": native_pid, "birth": message["birth"]})
                                save()
                    elif message.get("phase") == "finished" and type(message.get("returncode")) is int:
                        state.update(finished=True, returncode=message["returncode"])
                        break
                    elif message.get("phase") == "failed" and message.get("code") in {"worker_isolation_preflight_failed", "worker_execution_denied", "worker_bridge_failed", "repository_timeout", "worker_lifeline_lost"}:
                        state["error"] = message["code"]
                        break
                    else:
                        raise TransportError("worker_execution_denied", True)
            except (OSError, ProtocolError, TransportError, ValueError, KeyError, TypeError) as error:
                state["error"] = getattr(error, "code", "worker_lifeline_lost")
            finally:
                if broker:
                    try:
                        broker.close()
                    except TransportError:
                        # The parent repeats the bounded close and retains resources if it cannot prove closure.
                        state["contextUnverified"] = True
                if connection:
                    connection.close()

        result = bytearray()
        error = None
        try:
            intent["rootContextClosed"] = False
            save()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(control_socket))
            os.chown(control_socket, 0, identity["gid"])
            os.chmod(control_socket, 0o660)
            listener.listen(1)
            if not probe:
                broker = Broker(directory / "data", host, port, addresses, identity["uid"], identity["gid"], intent["cgroup"], root_token, data_token, deadline)
            if input_file is not None:
                fd = os.open(input_file, os.O_RDONLY | os.O_NOFOLLOW)
                incoming = os.fdopen(fd, "rb")
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise TransportError("invalid_storage_stream")
            if output_file is not None:
                if type(output_limit) is not int or not 1 <= output_limit <= 512 * 1024 ** 3:
                    raise TransportError("invalid_storage_stream")
                outgoing = os.fdopen(os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
            elif output_limit is not None:
                raise TransportError("invalid_storage_stream")
            control_thread = threading.Thread(target=control, daemon=True)
            control_thread.start()
            intent["stage"] = "launching"
            save()
            command = unit_properties(intent, request_path, password_path, timeout)
            try:
                launcher = subprocess.Popen(command, stdin=incoming if incoming else subprocess.DEVNULL,
                                            stdout=outgoing if outgoing else subprocess.PIPE, stderr=subprocess.DEVNULL, env=CLEAN_ENV, close_fds=True)
            except OSError:
                intent["launcherCompleted"] = True  # Popen reaped its failed exec; no launcher request was possible.
                save()
                raise
            with mutex:
                intent["launcher"] = {"pid": launcher.pid, "birth": pid_birth(launcher.pid)}
                save()
            launched.set()
            if launcher.stdout:
                os.set_blocking(launcher.stdout.fileno(), False)
            eof = bool(outgoing)
            while launcher.poll() is None or not eof:
                if time.monotonic() >= deadline:
                    raise TransportError("repository_timeout", args[0] in {"init", "backup"})
                if state["error"]:
                    raise TransportError(state["error"], bool(intent["permissionInvocationId"]) and not probe)
                if launcher.stdout and not eof:
                    readable, _, _ = select.select([launcher.stdout], [], [], 0.1)
                    if readable:
                        chunk = os.read(launcher.stdout.fileno(), 65536)
                        if not chunk:
                            eof = True
                        else:
                            result.extend(chunk)
                            if len(result) > MAX_RESULT:
                                raise TransportError("repository_result_limit", args[0] in {"init", "backup"})
                else:
                    stopped.wait(0.05)
            if control_thread:
                control_thread.join(min(2, max(0, deadline - time.monotonic())))
            if state["error"]:
                raise TransportError(state["error"], bool(intent["permissionInvocationId"]) and not probe)
            if not state["finished"] or launcher.returncode or state["returncode"] != 0:
                raise TransportError("worker_isolation_preflight_failed" if probe else "repository_access_failed", args[0] == "init" and bool(intent["permissionInvocationId"]))
        except TransportError as failure:
            error = failure
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
            error = TransportError("network_isolation_unavailable", bool(intent.get("permissionInvocationId")))
        finally:
            cleanup_deadline = time.monotonic() + CLEANUP_SECONDS
            stopped.set()
            if state["connection"]:
                try:
                    state["connection"].shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            if listener:
                listener.close()
            context_closed = True
            if broker:
                try:
                    broker.close()
                except TransportError:
                    context_closed = False
            if control_thread:
                control_thread.join(3)
                if control_thread.is_alive():
                    context_closed = False
            intent["rootContextClosed"] = context_closed
            save()
            try:
                self._cleanup(intent, path, launcher, deadline=cleanup_deadline, retain=not context_closed)
            except TransportError as failure:
                if intent.get("stage") == "changed-invocation-dead":
                    error = failure
                # Stop/death proof may unblock a handler that was still inside its bounded dial/show.
                if control_thread:
                    control_thread.join(max(0, min(3, cleanup_deadline - time.monotonic())))
                try:
                    if broker:
                        broker.close()
                    if control_thread and control_thread.is_alive():
                        raise TransportError("transport_cleanup_unverified", True)
                    intent["rootContextClosed"] = True
                    save()
                    if intent.get("stage") == "changed-invocation-dead":
                        raise TransportError("transport_cleanup_unverified", True)
                    self._cleanup(intent, path, launcher, deadline=cleanup_deadline)
                except TransportError as final_failure:
                    error = final_failure
            if not intent["rootContextClosed"]:
                error = TransportError("transport_cleanup_unverified", True)
            if incoming:
                incoming.close()
            if outgoing:
                try:
                    if not error or error.code != "transport_cleanup_unverified":
                        outgoing.flush()
                        os.fsync(outgoing.fileno())
                finally:
                    outgoing.close()
            if launcher and launcher.stdout:
                launcher.stdout.close()
        if error:
            raise error
        if probe:
            match = re.match(rb"restic (\d+)\.(\d+)\.(\d+)", result)
            if not match or tuple(map(int, match.groups())) < (0, 16, 0):
                raise TransportError("network_isolation_unavailable")
        return bytes(result)


def probe_runtime(worker_user=DEFAULT_WORKER_USER, source_dir=None, timeout=30, marker_path=None):
    try:
        return _probe_runtime(worker_user, source_dir, timeout, marker_path)
    except TransportError:
        raise
    except (OSError, ValueError, KeyError, TypeError, IndexError, RuntimeError):
        raise TransportError("transport_cleanup_unverified", True) from None


def _probe_runtime(worker_user, source_dir, timeout, marker_path=None):
    if type(timeout) not in {int, float} or not 1 <= timeout <= 120:
        raise TransportError("network_isolation_unavailable")
    # No credentials, no backend, no active-service prerequisite. Same isolation gate and cleanup.
    chosen_marker = validate_marker_path(marker_path)
    prerequisites()
    identity = account(worker_user) if marker_path is None else account(worker_user, marker_path=chosen_marker)
    try:
        RUN_ROOT.mkdir(mode=0o711)
        os.chmod(RUN_ROOT, 0o711)
    except FileExistsError:
        pass
    trusted(RUN_ROOT, directory=True, mode=0o711)
    state = RUN_ROOT / ("probe-" + uuid.uuid4().hex)
    state.mkdir(mode=0o700)
    transport = StorageTransport(state, worker_user, marker_path=chosen_marker)
    if source_dir is not None:
        source = Path(source_dir)
        trusted(source, directory=True)
        transport.source_dir = source.resolve()
    try:
        transport._execute({}, ["version"], timeout=timeout, probe=True, standalone=True)
    except TransportError as error:
        if not error.unknown:
            shutil.rmtree(state)
        raise
    shutil.rmtree(state)
    return {"ready": True, "user": identity["user"], "uid": identity["uid"], "gid": identity["gid"]}
