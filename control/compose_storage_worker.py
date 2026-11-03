#!/usr/bin/env python3
"""Trusted storage supervisor. Payload descriptors are inherited by native restic."""
import ctypes
import fcntl
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

try:
    from .compose_storage_bridge import ProtocolError, close_extra_fds, receive_frame, send_frame
except ImportError:
    from compose_storage_bridge import ProtocolError, close_extra_fds, receive_frame, send_frame


LIBC = ctypes.CDLL(None, use_errno=True)


class WorkerError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def pid_birth(pid):
    raw = Path("/proc", str(pid), "stat").read_text()
    return raw[raw.rfind(")") + 2:].split()[19]


def cgroup(pid="self"):
    values = Path("/proc", str(pid), "cgroup").read_text().splitlines()
    if len(values) != 1 or not values[0].startswith("0::/"):
        raise WorkerError("worker_isolation_preflight_failed")
    return values[0][3:]


def descriptor_kind(fd):
    value = os.fstat(fd)
    if stat.S_ISREG(value.st_mode):
        return "file"
    if stat.S_ISFIFO(value.st_mode):
        return "pipe"
    if stat.S_ISCHR(value.st_mode) and value.st_rdev == os.stat("/dev/null").st_rdev:
        return "devnull"
    raise WorkerError("worker_isolation_preflight_failed")


def isolation_proof(request):
    expected_uid, expected_gid = request["uid"], request["gid"]
    if (type(expected_uid) is not int or type(expected_gid) is not int or expected_uid <= 0 or expected_gid <= 0
            or os.getuid() != expected_uid or os.geteuid() != expected_uid or os.getgid() != expected_gid or os.getegid() != expected_gid
            or set(os.getgroups()) - {expected_gid}):
        raise WorkerError("worker_isolation_preflight_failed")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    if (any(int(status.get(name, "1").strip(), 16) for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
            or status.get("NoNewPrivs", "").strip() != "1"
            or [int(value) for value in status.get("Uid", "").split()] != [expected_uid] * 4
            or [int(value) for value in status.get("Gid", "").split()] != [expected_gid] * 4):
        raise WorkerError("worker_isolation_preflight_failed")
    securebits = LIBC.prctl(27, 0, 0, 0, 0)  # PR_GET_SECUREBITS: read only.
    if securebits != 15:
        raise WorkerError("worker_isolation_preflight_failed")
    namespace = os.stat("/proc/self/ns/net")
    if [namespace.st_dev, namespace.st_ino] == request["hostNetns"]:
        raise WorkerError("worker_isolation_preflight_failed")
    if cgroup() != request["cgroup"] or [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise WorkerError("worker_isolation_preflight_failed")
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        flags = struct.unpack("H", fcntl.ioctl(probe.fileno(), 0x8913, struct.pack("256s", b"lo"))[16:18])[0]
        if not flags & 1:
            raise WorkerError("worker_isolation_preflight_failed")
    finally:
        probe.close()
    for name in ("route", "ipv6_route"):
        lines = Path("/proc/self/net", name).read_text().splitlines()
        for line in lines[1:] if name == "route" else lines:
            fields = line.split()
            if fields and (fields[0] if name == "route" else fields[-1]) != "lo":
                raise WorkerError("worker_isolation_preflight_failed")
    kinds = [descriptor_kind(fd) for fd in (0, 1, 2)]
    if request.get("outputLimit") is not None and kinds[1] != "file":
        raise WorkerError("worker_isolation_preflight_failed")
    return {"pid": os.getpid(), "birth": pid_birth(os.getpid()), "uid": expected_uid, "gid": expected_gid,
            "groups": sorted(os.getgroups()), "caps": [0, 0, 0, 0, 0], "noNewPrivs": 1, "securebits": securebits,
            "netns": [namespace.st_dev, namespace.st_ino], "cgroup": cgroup(), "fds": kinds,
            "invocationId": os.environ.get("INVOCATION_ID", "")}


def valid_args(args, probe=False):
    if not isinstance(args, list) or not args or len(args) > 64 or any(not isinstance(value, str) or not 1 <= len(value) <= 2048 or any(ord(c) < 32 or ord(c) == 127 for c in value) for value in args):
        return False
    if probe:
        return args == ["version"]
    verb = args[0]
    if verb == "init":
        return args == ["init", "--repository-version", "2"]
    if verb == "cat":
        return args == ["cat", "config"]
    if verb == "check":
        return args == ["check", "--read-data"]
    if verb == "dump":
        import re
        return len(args) == 3 and re.fullmatch(r"[a-f0-9]{64}", args[1]) is not None and args[2] == "/bundle.tar"
    if verb == "snapshots":
        return len(args) == 4 and args[1:3] == ["--json", "--tag"] and args[3].startswith("rolypolyops-compose,service:")
    if verb == "backup":
        if len(args) != 17 or args[:3] != ["backup", "--json", "--host"] or args[-3:] != ["--stdin", "--stdin-filename", "bundle.tar"]:
            return False
        import uuid
        try:
            if str(uuid.UUID(args[3])) != args[3]:
                return False
        except ValueError:
            return False
        tags = args[4:-3]
        return tags[::2] == ["--tag"] * 5 and tags[1::2][0] == "rolypolyops-compose" and all(tags[1::2][index].startswith(prefix) for index, prefix in enumerate(("rolypolyops-compose", "service:", "manifest:", "source:", "operation:")))
    return False


def terminate(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
    process.wait(timeout=3)


def run(request, control, credential_dir):
    native = bridge = None
    try:
        proof = isolation_proof(request)
        close_extra_fds(keep=(control.fileno(),))
        proof["controlFd"] = control.fileno()
        send_frame(control, {"phase": "ready", "token": request["controlToken"], "callId": request["callId"], "proof": proof})
        control.settimeout(min(10, max(0.1, request["deadline"] - time.monotonic())))
        permission = receive_frame(control)
        if permission != {"go": True, "callId": request["callId"], "invocationId": proof["invocationId"]}:
            raise WorkerError("worker_execution_denied")
        probe = request["action"] == "probe"
        if not valid_args(request["args"], probe):
            raise WorkerError("worker_execution_denied")
        binary = Path(request["restic"])
        value = binary.stat()
        if not binary.is_absolute() or value.st_uid != 0 or value.st_mode & 0o6022 or not stat.S_ISREG(value.st_mode):
            raise WorkerError("worker_execution_denied")
        clean = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent"}
        if not probe:
            bridge_path = Path(__file__).with_name("compose_storage_bridge.py")
            bridge = subprocess.Popen(["/usr/bin/python3", str(bridge_path), "--deadline", str(request["deadline"])], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=clean, close_fds=True)
            bridge.stdin.write((request["dataSocket"] + "\n").encode())
            bridge.stdin.close()
            ready, _, _ = select.select([bridge.stdout], [], [], 5)
            if not ready:
                raise WorkerError("worker_bridge_failed")
            raw = bridge.stdout.readline(256)
            port = json.loads(raw)["port"]
            if type(port) is not int or not 1 <= port <= 65535:
                raise WorkerError("worker_bridge_failed")
            proxy = "http://rpo:" + request["dataToken"] + "@127.0.0.1:" + str(port)
            env = dict(clean)
            allowed = {"RESTIC_REPOSITORY", "RESTIC_REST_USERNAME", "RESTIC_REST_PASSWORD", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION"}
            if not isinstance(request["env"], dict) or set(request["env"]) - allowed or any(not isinstance(v, str) or "\x00" in v for v in request["env"].values()):
                raise WorkerError("worker_execution_denied")
            env.update(request["env"])
            env.update(HTTP_PROXY=proxy, HTTPS_PROXY=proxy, http_proxy=proxy, https_proxy=proxy, NO_PROXY="", no_proxy="", RESTIC_PASSWORD_FILE=str(credential_dir / "password"))
        else:
            env = clean
        limit = request.get("outputLimit")
        if limit is not None:
            if type(limit) is not int or not 1 <= limit <= 512 * 1024 ** 3:
                raise WorkerError("worker_execution_denied")
            resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        command = [str(binary), "--no-cache"]
        if not probe and request.get("kind") == "s3":
            command += ["-o", "s3.bucket-lookup=path"]
        native = subprocess.Popen(command + request["args"], stdin=None, stdout=None, stderr=subprocess.DEVNULL, env=env, close_fds=True)
        try:
            birth = pid_birth(native.pid)
        except FileNotFoundError:
            if native.poll() is None:
                raise
            birth = None  # Already reaped native exit; the unit's recursive cgroup proof remains mandatory.
        send_frame(control, {"phase": "started", "pid": native.pid, "birth": birth})
        control.setblocking(False)
        while native.poll() is None:
            if time.monotonic() >= request["deadline"] or (bridge and bridge.poll() is not None):
                raise WorkerError("repository_timeout")
            readable, _, _ = select.select([control], [], [], 0.1)
            if readable:
                # The lifeline carries no second permission or payload. EOF or extra data cancels the invocation.
                if control.recv(1) == b"" :
                    raise WorkerError("worker_lifeline_lost")
                raise WorkerError("worker_execution_denied")
        code = native.wait()
        terminate(bridge)
        bridge = None
        control.setblocking(True)
        control.settimeout(2)
        send_frame(control, {"phase": "finished", "returncode": code})
        return 0 if code == 0 else 1
    except (OSError, ValueError, KeyError, TypeError, ProtocolError, WorkerError) as error:
        terminate(native)
        terminate(bridge)
        try:
            send_frame(control, {"phase": "failed", "code": getattr(error, "code", "worker_isolation_preflight_failed")})
        except (OSError, ProtocolError):
            pass
        return 1
    finally:
        terminate(native)
        terminate(bridge)


def main():
    close_extra_fds()
    connection = None
    try:
        directory = Path(os.environ.get("CREDENTIALS_DIRECTORY", ""))
        if not directory.is_absolute():
            raise WorkerError("worker_isolation_preflight_failed")
        with open(directory / "request", "rb") as stream:
            raw = stream.read(65537)
        if len(raw) > 65536:
            raise WorkerError("worker_isolation_preflight_failed")
        request = json.loads(raw)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(5)
        connection.connect(request["controlSocket"])
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        if peer[1] != 0 or peer[0] != request["rootPid"] or pid_birth(peer[0]) != request["rootBirth"]:
            raise WorkerError("worker_isolation_preflight_failed")
        return run(request, connection, directory)
    except (OSError, ValueError, KeyError, TypeError, ProtocolError, WorkerError):
        return 1
    finally:
        if connection:
            connection.close()


if __name__ == "__main__":
    raise SystemExit(main())
