import base64
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

try:
    from . import compose_transport as transport
    from . import compose_storage_bridge as bridge
    from . import compose_storage_worker as worker
except ImportError:
    import compose_transport as transport
    import compose_storage_bridge as bridge
    import compose_storage_worker as worker


class BytesSocket:
    def __init__(self, data=b"", peer=(200, 1001, 1001)):
        self.data, self.sent, self.peer = data, bytearray(), peer
        self.closed = False

    def recv(self, count):
        value, self.data = self.data[:count], self.data[count:]
        return value

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        pass

    def getsockopt(self, *args):
        return struct.pack("3i", *self.peer)

    def close(self):
        self.closed = True

    def fileno(self):
        return 3


class ProtocolTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(transport.socket, "SO_PEERCRED", 17, create=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_bounded_control_frames_and_duplicate_headers(self):
        value = {"phase": "ready", "proof": {"pid": 42}}
        sock = BytesSocket()
        bridge.send_frame(sock, value)
        self.assertEqual(bridge.receive_frame(BytesSocket(bytes(sock.sent))), value)
        for raw in (struct.pack("!I", 65537), struct.pack("!I", 2) + b"[]", struct.pack("!I", 4) + b"null"):
            with self.assertRaises(bridge.ProtocolError):
                bridge.receive_frame(BytesSocket(raw))
        with self.assertRaises(bridge.ProtocolError):
            bridge.read_headers(BytesSocket(b"CONNECT x:443 HTTP/1.1\r\nX:a\r\nX:b\r\n\r\n"), time.monotonic() + 5)

    def test_header_line_field_and_deadline_limits_distinguished_from_forbidden(self):
        for raw in (b"C" * 8193, b"CONNECT x:443 HTTP/1.1\r\n" + b"X:v\r\n" * 65 + b"\r\n",
                    b"CONNECT x:443 HTTP/1.1\r\nX:" + b"v" * 16400 + b"\r\n\r\n"):
            with self.subTest(size=len(raw)), self.assertRaises(bridge.ProtocolError) as caught:
                bridge.read_headers(BytesSocket(raw), time.monotonic() + 5)
            self.assertTrue(caught.exception.limit)
        with self.assertRaises(bridge.ProtocolError) as caught:
            bridge.read_headers(BytesSocket(b""), time.monotonic() - 1)
        self.assertTrue(caught.exception.limit)
        result = bridge.read_headers(BytesSocket(b"CONNECT storage.example:443 HTTP/1.1\r\nHost:storage.example\r\n\r\n"), time.monotonic() + 5)
        self.assertEqual(result[:2], ("CONNECT", "storage.example:443"))

    def test_broker_denies_method_authority_token_and_wrong_peer_before_dial(self):
        broker = object.__new__(transport.Broker)
        broker.authority, broker.addresses, broker.port = "storage.example:443", ("8.8.8.8",), 443
        broker.uid, broker.gid, broker.cgroup = 1001, 1001, "/system.slice/owned.service"
        broker.root_pid, broker.root_birth = 100, "birth"
        broker.root_token, broker.worker_token = "root-token", "worker-token"
        broker.deadline, broker.stopped = time.monotonic() + 5, threading.Event()
        broker.mutex, broker.slots = threading.Lock(), threading.BoundedSemaphore(32)
        broker.connections, broker.threads = set(), set()
        auth = "Basic " + base64.b64encode(b"rpo:worker-token").decode()
        cases = [("GET", "storage.example:443", auth, (200, 1001, 1001)),
                 ("CONNECT", "127.0.0.1:443", auth, (200, 1001, 1001)),
                 ("CONNECT", "storage.example:443", "wrong", (200, 1001, 1001)),
                 ("CONNECT", "storage.example:443", auth, (200, 1002, 1001)),
                 ("CONNECT", "storage.example:443", auth, (200, 1001, 1002)),
                 ("CONNECT", "storage.example:443", auth, (201, 1001, 1001))]
        for method, authority, token, peer in cases:
            client = BytesSocket((method + " " + authority + " HTTP/1.1\r\nProxy-Authorization:" + token + "\r\n\r\n").encode(), peer)
            broker.slots.acquire()
            with mock.patch.object(transport.socket, "create_connection") as dial, mock.patch.object(transport, "process_cgroup", return_value="/wrong"):
                broker.handle(client)
            dial.assert_not_called()
            self.assertIn(b"403", client.sent)
        client = BytesSocket(b"X" * 8193)
        broker.slots.acquire()
        broker.handle(client)
        self.assertIn(b"503", client.sent)

    def test_root_listing_token_is_exact_pid_birth_not_arbitrary_root(self):
        broker = object.__new__(transport.Broker)
        broker.root_pid, broker.root_birth = 100, "born"
        broker.root_token, broker.worker_token = "root", "worker"
        broker.uid, broker.gid, broker.cgroup = 1001, 1001, "/owned"
        token = "Basic " + base64.b64encode(b"rpo:root").decode()
        with mock.patch.object(transport, "pid_birth", return_value="born"):
            self.assertTrue(broker._authorized(BytesSocket(peer=(100, 0, 0)), token))
            self.assertFalse(broker._authorized(BytesSocket(peer=(101, 0, 0)), token))
        with mock.patch.object(transport, "pid_birth", return_value="reused"):
            self.assertFalse(broker._authorized(BytesSocket(peer=(100, 0, 0)), token))

    def test_dns_all_answers_fixed_and_transition_forms_forbidden(self):
        good = [(socket.AF_INET, 1, 6, "", ("8.8.8.8", 443))]
        with mock.patch.object(transport.socket, "getaddrinfo", return_value=good) as dns:
            self.assertEqual(transport.public_addresses("host", 443), ["8.8.8.8"])
            dns.assert_called_once()
        for value in ("127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "::ffff:8.8.8.8", "2002:0808:0808::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "64:ff9b::808:808", "64:ff9b:1::808:808"):
            with mock.patch.object(transport.socket, "getaddrinfo", return_value=good + [(socket.AF_INET6, 1, 6, "", (value, 443))]):
                with self.subTest(value=value), self.assertRaisesRegex(transport.TransportError, "storage_address_forbidden"):
                    transport.public_addresses("host", 443)

    def test_tunnel_half_close_copies_exact_bytes_and_terminates(self):
        one, two = socket.socketpair()
        three, four = socket.socketpair()
        self.addCleanup(one.close); self.addCleanup(two.close); self.addCleanup(three.close); self.addCleanup(four.close)
        thread = threading.Thread(target=bridge.pump, args=(two, three, time.monotonic() + 3))
        thread.start()
        payload = bytes(range(256)) * 256
        def write():
            one.sendall(payload)
            one.shutdown(socket.SHUT_WR)
        writer = threading.Thread(target=write)
        writer.start()
        four.settimeout(5)
        one.settimeout(5)
        received = bytearray()
        while True:
            block = four.recv(65536)
            if not block:
                break
            received.extend(block)
        four.sendall(b"reply"); four.shutdown(socket.SHUT_WR)
        self.assertEqual(one.recv(6), b"reply")
        thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(bytes(received), payload)
        writer.join(3)
        self.assertFalse(writer.is_alive())


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runner = transport.StorageTransport(self.root)
        self.identity = {"user": transport.DEFAULT_WORKER_USER, "uid": 1001, "gid": 1001}

    def intent(self):
        identifier = "a" * 32
        return {"id": identifier, "unit": "rpo-storage-" + identifier + ".service", "cgroup": "/system.slice/rpo-storage-" + identifier + ".service",
                "marker": "exact owner", "account": self.identity, "argv": ["/usr/bin/python3", "/run/owned/compose_storage_worker.py"],
                "caller": {"unit": "agent.service"}, "directory": str(self.root / "run"), "stage": "prepared", "permissionInvocationId": "b" * 32,
                "bootId": "boot", "launcherCompleted": True, "pids": [], "rootPid": os.getpid(), "rootBirth": "born", "rootContextClosed": True}

    def unit(self, intent):
        return {"Id": intent["unit"], "Transient": "yes", "Description": intent["marker"], "User": self.identity["user"], "Group": self.identity["user"],
                "ControlGroup": intent["cgroup"], "ExecStart": "{ path=/usr/bin/python3 ; argv[]=" + " ".join(intent["argv"]) + " ; ignore_errors=no ; }",
                "KillMode": "control-group", "Restart": "no", "InvocationID": "b" * 32, "ActiveState": "active",
                "Type": "exec", "PrivateNetwork": "yes", "NoNewPrivileges": "yes", "RestrictNamespaces": "yes", "ProtectControlGroups": "yes",
                "ProtectSystem": "strict", "ProtectHome": "yes", "PrivateTmp": "yes", "SendSIGKILL": "yes", "LimitCORE": "0", "UMask": "0077",
                "CapabilityBoundingSet": "", "AmbientCapabilities": "", "SecureBits": "15", "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
                "SystemCallFilter": "~setns unshare mount umount2 ptrace open_by_handle_at", "BindsTo": "agent.service", "After": "agent.service"}

    def test_launcher_properties_have_all_gates_no_secrets_and_active_parent_order(self):
        args = transport.unit_properties(self.intent(), "/run/secret/request", "/run/secret/password", 7200)
        expected = {"--quiet", "--wait", "--collect", "--pipe", "--no-ask-password", "--property=PrivateNetwork=yes", "--property=CapabilityBoundingSet=",
                    "--property=AmbientCapabilities=", "--property=NoNewPrivileges=yes", "--property=ProtectHome=yes", "--property=ProtectSystem=strict",
                    "--property=SecureBits=noroot noroot-locked no-setuid-fixup no-setuid-fixup-locked", "--property=KillMode=control-group",
                    "--property=Restart=no", "--property=RuntimeMaxSec=7215", "--property=BindsTo=agent.service", "--property=After=agent.service"}
        self.assertTrue(expected <= set(args))
        self.assertFalse(any(value.startswith("--property=Environment=") for value in args))
        self.assertEqual(args[-2:], self.intent()["argv"])
        self.assertNotIn("preexec_fn", transport.StorageTransport._execute.__code__.co_names)

    def test_caller_requires_exact_active_main_service_not_activating_oneshot(self):
        current = {"ActiveState": "active", "Type": "exec", "ControlGroup": "/system.slice/backup.service", "MainPID": str(os.getpid()), "InvocationID": "a" * 32}
        with mock.patch.object(transport, "process_cgroup", return_value=current["ControlGroup"]), mock.patch.object(transport, "pid_birth", return_value="born"):
            with mock.patch.object(transport, "systemctl", return_value=current):
                self.assertEqual(transport.caller()["unit"], "backup.service")
            for change in ({"Type": "oneshot"}, {"ActiveState": "activating"}, {"MainPID": str(os.getpid()+1)}, {"ControlGroup": "/wrong"}):
                with mock.patch.object(transport, "systemctl", return_value=current | change), self.assertRaisesRegex(transport.TransportError, "network_isolation_unavailable"):
                    transport.caller()
        with mock.patch.object(transport, "process_cgroup", return_value="/user.slice/shell.scope"), self.assertRaises(transport.TransportError):
            transport.caller()

    def test_account_marker_exclusivity_login_and_identity_are_checked(self):
        user = types.SimpleNamespace(pw_name=self.identity["user"], pw_uid=1001, pw_gid=1001, pw_shell="/usr/sbin/nologin")
        group = types.SimpleNamespace(gr_name=self.identity["user"], gr_gid=1001, gr_mem=[])
        with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", return_value=self.identity), mock.patch.object(transport.pwd, "getpwnam", return_value=user), mock.patch.object(transport.pwd, "getpwall", return_value=[user]), mock.patch.object(transport.grp, "getgrgid", return_value=group), mock.patch.object(transport.grp, "getgrall", return_value=[group]):
            self.assertEqual(transport.account(self.identity["user"]), self.identity)
            group.gr_mem = [user.pw_name]
            self.assertEqual(transport.account(self.identity["user"]), self.identity)
            group.gr_mem = []
            for changed in (self.identity | {"uid": 0}, self.identity | {"gid": 1002}, self.identity | {"user": "another"}):
                with mock.patch.object(transport, "read_json", return_value=changed), self.assertRaises(transport.TransportError):
                    transport.account(self.identity["user"])
            with mock.patch.object(transport.pwd, "getpwall", return_value=[user, types.SimpleNamespace(pw_name="alias", pw_uid=1001, pw_gid=2000)]), self.assertRaises(transport.TransportError):
                transport.account(self.identity["user"])
            with mock.patch.object(transport.grp, "getgrall", return_value=[group, types.SimpleNamespace(gr_name="extra", gr_gid=2000, gr_mem=[user.pw_name])]), self.assertRaises(transport.TransportError):
                transport.account(self.identity["user"])
            user.pw_shell = "/bin/bash"
            with self.assertRaises(transport.TransportError):
                transport.account(self.identity["user"])

    def test_actual_isolation_probe_precedes_cached_preflight_success(self):
        with mock.patch.object(self.runner, "_prerequisites", return_value=(self.identity, {"unit": "agent.service"})), mock.patch.object(self.runner, "_execute", return_value=b"restic 0.18.0") as probe:
            self.assertEqual(self.runner.preflight()[0], self.identity)
            self.runner.preflight()
        probe.assert_called_once_with({}, ["version"], timeout=30, probe=True)
        self.runner._probe_until = 0
        with mock.patch.object(self.runner, "_prerequisites", return_value=(self.identity, {})), mock.patch.object(self.runner, "_execute", side_effect=transport.TransportError("worker_isolation_preflight_failed")), self.assertRaises(transport.TransportError):
            self.runner.preflight()
        self.assertEqual(self.runner._probe_until, 0)

    def test_persisted_account_pins_timer_and_rejects_uid_or_user_drift(self):
        def read_pin(path):
            return json.loads(Path(path).read_text())
        with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=read_pin), mock.patch.object(transport, "account", return_value=self.identity) as lookup:
            self.assertEqual(self.runner.settings(), self.identity)
            timer = transport.StorageTransport(self.root)
            self.assertEqual(timer.settings(), self.identity)
            lookup.assert_called_with(self.identity["user"])
        for changed in (self.identity | {"uid": 1002}, self.identity | {"user": "another"}):
            with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=read_pin), mock.patch.object(transport, "account", return_value=changed), self.assertRaises(transport.TransportError):
                self.runner.settings()

    def test_invalid_explicit_worker_option_never_falls_back_to_default(self):
        for value in (False, 0, "", "root", "invalid/user"):
            runner = transport.StorageTransport(self.root, value)
            with mock.patch.object(transport, "account", side_effect=transport.TransportError("network_isolation_unavailable")) as lookup:
                with self.assertRaises(transport.TransportError):
                    runner.settings()
                if value != "root":
                    lookup.assert_not_called()
                else:
                    lookup.assert_called_once_with("root")

    def test_foreign_unit_and_extra_commands_are_never_stopped(self):
        intent = self.intent()
        for changed in ({"Description": "foreign"}, {"User": "root"}, {"Group": "root"}, {"ControlGroup": "/foreign"}, {"ExecStartPost": "foreign"}, {"PrivateNetwork": "no"}, {"CapabilityBoundingSet": "CAP_NET_ADMIN"},
                        {"ExecStart": "{ path=/bin/true ; argv[]=/bin/true ; }"}):
            with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", return_value=self.unit(intent) | changed), mock.patch.object(transport.subprocess, "run") as stop:
                with self.assertRaises(transport.TransportError) as caught:
                    self.runner._cleanup(intent, self.root / "intent")
                self.assertTrue(caught.exception.unknown)
                stop.assert_not_called()

    def test_worker_fd_proof_rejects_extra_or_substituted_descriptors(self):
        incoming = mock.Mock()
        outgoing = mock.Mock()
        regular = types.SimpleNamespace(st_dev=1, st_ino=2, st_mode=stat.S_IFREG | 0o600)
        null = types.SimpleNamespace(st_dev=3, st_ino=4, st_mode=stat.S_IFCHR | 0o666, st_rdev=259)
        def observed(path):
            if str(path) in {"/dev/null", "/proc/123/fd/2"}:
                return null
            return regular
        with mock.patch.object(transport.os, "listdir", return_value=["0", "1", "2", "3"]), mock.patch.object(transport.os, "fstat", return_value=regular), mock.patch.object(transport.os, "stat", side_effect=observed):
            transport.verify_worker_fds(123, {"controlFd": 3}, incoming, outgoing, None)
            with mock.patch.object(transport.os, "listdir", return_value=["0", "1", "2", "3", "4"]), self.assertRaisesRegex(transport.TransportError, "worker_isolation_preflight_failed"):
                transport.verify_worker_fds(123, {"controlFd": 3}, incoming, outgoing, None)
            with mock.patch.object(transport.os, "fstat", return_value=types.SimpleNamespace(st_dev=1, st_ino=99, st_mode=stat.S_IFREG | 0o600)), self.assertRaises(transport.TransportError):
                transport.verify_worker_fds(123, {"controlFd": 3}, incoming, outgoing, None)

    def test_unverified_live_root_context_retains_resources_until_parent_death(self):
        intent = self.intent() | {"rootContextClosed": False}
        path = self.root / "intent.json"
        path.write_text("{}")
        Path(intent["directory"]).mkdir()
        with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", return_value=None), mock.patch.object(transport, "cgroup_empty", return_value=True), mock.patch.object(transport, "pid_gone", return_value=False):
            with self.assertRaises(transport.TransportError) as caught:
                self.runner._cleanup(intent, path)
            self.assertTrue(caught.exception.unknown)
            self.assertTrue(path.exists())
            self.assertTrue(Path(intent["directory"]).exists())
        with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", return_value=None), mock.patch.object(transport, "cgroup_empty", return_value=True), mock.patch.object(transport, "pid_gone", return_value=True):
            self.runner._cleanup(intent, path)
        self.assertFalse(path.exists())
        self.assertFalse(Path(intent["directory"]).exists())

    def test_recursive_cgroup_proof_checks_descendants_and_pid_birth(self):
        directory = self.root / "system.slice" / ("rpo-storage-" + "a" * 32 + ".service")
        child = directory / "nested"
        child.mkdir(parents=True)
        for path in (directory, child):
            (path / "cgroup.procs").write_text("")
            (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")
        with mock.patch.object(transport, "CGROUP_ROOT", self.root):
            self.assertTrue(transport.cgroup_empty("/system.slice/" + directory.name))
            (child / "cgroup.procs").write_text("123\n")
            self.assertFalse(transport.cgroup_empty("/system.slice/" + directory.name))
            self.assertFalse(transport.cgroup_empty("/foreign"))
        with mock.patch.object(transport, "pid_birth", return_value="new"):
            self.assertTrue(transport.pid_gone(10, "old"))
        with mock.patch.object(transport, "pid_birth", side_effect=PermissionError()):
            self.assertFalse(transport.pid_gone(10, "old"))

    def test_cleanup_waits_for_disappearing_cgroup_then_fsync_removes_owned_intent(self):
        intent = self.intent()
        Path(intent["directory"]).mkdir()
        path = self.root / "intent.json"
        path.write_text("{}")
        launcher = mock.Mock()
        with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", side_effect=[self.unit(intent), None, None]), mock.patch.object(transport.subprocess, "run", return_value=mock.Mock(returncode=0)) as stop, mock.patch.object(transport, "cgroup_empty", side_effect=[False, True]):
            self.runner._cleanup(intent, path, launcher)
        stop.assert_called_once()
        launcher.wait.assert_called_once()
        self.assertFalse(path.exists())
        self.assertFalse(Path(intent["directory"]).exists())

    def test_changed_invocation_is_stopped_but_retained_unknown(self):
        intent = self.intent()
        path = self.root / "intent.json"
        unit = self.unit(intent) | {"InvocationID": "c" * 32}
        with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", side_effect=[unit, None]), mock.patch.object(transport.subprocess, "run", return_value=mock.Mock(returncode=0)) as stop, mock.patch.object(transport, "cgroup_empty", return_value=True):
            with self.assertRaisesRegex(transport.TransportError, "transport_cleanup_unverified") as caught:
                self.runner._cleanup(intent, path)
        self.assertTrue(caught.exception.unknown)
        stop.assert_called_once()
        self.assertEqual(json.loads(path.read_text())["stage"], "changed-invocation-dead")

    def test_execution_permission_is_fsynced_once_and_rejects_same_or_new_invocation(self):
        path = self.root / "intent.json"
        intent = self.intent() | {"permissionInvocationId": None}
        with mock.patch.object(transport.os, "fsync", wraps=os.fsync) as sync:
            self.runner._consume_permission(intent, path, "a" * 32, 123, "born")
        self.assertEqual(json.loads(path.read_text())["permissionInvocationId"], "a" * 32)
        self.assertGreaterEqual(sync.call_count, 2)
        for invocation in ("a" * 32, "b" * 32):
            with mock.patch.object(transport, "atomic") as save, self.assertRaisesRegex(transport.TransportError, "worker_execution_denied"):
                self.runner._consume_permission(intent, path, invocation, 124, "later")
            save.assert_not_called()
        self.assertEqual(json.loads(path.read_text())["pids"], [{"pid": 123, "birth": "born"}])

    def test_unrecorded_launch_window_is_held_same_boot_and_no_replay(self):
        intent = self.intent() | {"stage": "launching", "launcherCompleted": False}
        with mock.patch.object(self.runner, "_validate_intent"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", return_value=None), mock.patch.object(transport.subprocess, "run") as launch:
            with self.assertRaises(transport.TransportError) as caught:
                self.runner._cleanup(intent, self.root / "intent")
        self.assertTrue(caught.exception.unknown)
        launch.assert_not_called()

    def test_local_platform_probe_fails_before_launch_or_backend(self):
        with mock.patch.object(transport.sys, "platform", "darwin"), mock.patch.object(transport.subprocess, "Popen") as launch, mock.patch.object(transport.socket, "getaddrinfo") as dns:
            with self.assertRaisesRegex(transport.TransportError, "network_isolation_unavailable"):
                transport.probe_runtime()
        launch.assert_not_called(); dns.assert_not_called()


class PipelineTests(unittest.TestCase):
    setUp = LifecycleTests.setUp
    intent = LifecycleTests.intent
    @contextlib.contextmanager
    def pipeline(self, code, *, cleanup_unknown=False):
        directory = self.root / "run"
        directory.mkdir()
        (directory / "secret").mkdir()
        path = self.root / "intent.json"
        intent = self.intent() | {"directory": str(directory), "permissionInvocationId": None}
        transport.atomic(path, intent)
        original_popen, original_stat = subprocess.Popen, os.stat
        launches, cleanups = [], []
        def spawn(command, **kwargs):
            try:
                value = original_popen([os.sys.executable, "-c", code], **kwargs)
            except Exception as error:
                raise AssertionError(repr(error)) from error
            launches.append((value, kwargs))
            return value
        def cleanup(value, target, launcher=None, **kwargs):
            cleanups.append((copy.deepcopy(value), target))
            if launcher:
                if launcher.poll() is None:
                    launcher.terminate()
                launcher.wait(timeout=3)
            if cleanup_unknown:
                raise transport.TransportError("transport_cleanup_unverified", True)
            target.unlink()
        def namespace(path, *args, **kwargs):
            if str(path) == "/proc/self/ns/net":
                return types.SimpleNamespace(st_dev=1, st_ino=1)
            return original_stat(path, *args, **kwargs)
        with mock.patch.object(self.runner, "_prerequisites", return_value=(self.identity, None)), mock.patch.object(self.runner, "_prepare", return_value=(intent, path)), mock.patch.object(self.runner, "_cleanup", side_effect=cleanup), mock.patch.object(transport.os, "stat", side_effect=namespace), mock.patch.object(transport.os, "chown"), mock.patch.object(transport.os, "chmod"), mock.patch.object(transport, "pid_birth", return_value="born"), mock.patch.object(transport.socket, "socket"), mock.patch.object(transport.threading, "Thread") as thread, mock.patch.object(transport.subprocess, "Popen", side_effect=spawn):
            thread.return_value.is_alive.return_value = False
            self.runner._restic = "/usr/bin/restic"
            yield launches, cleanups, path
        for process, _ in launches:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)

    def test_json_output_cap_stops_and_reaps_launcher_before_return(self):
        with self.pipeline("import os;os.write(1,b'x'*8192)") as (launches, cleanups, path), mock.patch.object(transport, "MAX_RESULT", 4096):
            with self.assertRaisesRegex(transport.TransportError, "repository_result_limit"):
                self.runner._execute({}, ["version"], timeout=3, probe=True)
            self.assertEqual(len(cleanups), 1)
            self.assertIsNotNone(launches[0][0].returncode)
            self.assertFalse(path.exists())
            self.assertEqual(launches[0][1]["stderr"], subprocess.DEVNULL)
            self.assertEqual(launches[0][1]["env"], transport.CLEAN_ENV)

    def test_timeout_cleanup_unknown_retains_durable_intent(self):
        with self.pipeline("import time;time.sleep(60)", cleanup_unknown=True) as (launches, cleanups, path):
            with self.assertRaisesRegex(transport.TransportError, "transport_cleanup_unverified") as caught:
                self.runner._execute({}, ["version"], timeout=1, probe=True)
            self.assertTrue(caught.exception.unknown)
            self.assertEqual(len(cleanups), 2)
            self.assertIsNotNone(launches[0][0].returncode)
            self.assertTrue(path.exists())

    def test_root_opens_original_input_and_exclusive_dump_fd_without_chown_or_relay(self):
        source, destination = self.root / "bundle", self.root / "dump"
        payload = bytes(range(256)) * 4096
        source.write_bytes(payload)
        code = "import os\nwhile True:\n b=os.read(0,65536)\n if not b:break\n os.write(1,b)"
        with self.pipeline(code) as (launches, cleanups, path):
            # The deliberately absent mocked lifeline cannot report a successful repository result.
            with self.assertRaisesRegex(transport.TransportError, "worker_isolation_preflight_failed"):
                self.runner._execute({}, ["version"], timeout=3, probe=True, input_file=source, output_file=destination, output_limit=len(payload))
        self.assertEqual(destination.read_bytes(), payload)
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
        self.assertEqual(source.read_bytes(), payload)
        self.assertIsNotNone(launches[0][1]["stdin"])
        self.assertIsNotNone(launches[0][1]["stdout"])
        self.assertNotIn("preexec_fn", launches[0][1])
        self.assertEqual(len(cleanups), 1)



class WorkerTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(worker, "close_extra_fds")
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_only_fixed_restic_verbs_and_paths_are_supported(self):
        for args in (["init", "--repository-version", "2"], ["cat", "config"], ["check", "--read-data"], ["dump", "a" * 64, "/bundle.tar"], ["snapshots", "--json", "--tag", "rolypolyops-compose,service:abc"]):
            self.assertTrue(worker.valid_args(args))
        for args in (["unlock"], ["prune"], ["dump", "a" * 64, "/etc/shadow"], ["cat", "config", "--option"], ["check", "--read-data", "--repo", "evil"], ["version"]):
            self.assertFalse(worker.valid_args(args))
        self.assertTrue(worker.valid_args(["version"], True))

    def test_supervisor_never_spawns_before_valid_one_time_acknowledgement(self):
        request = {"action": "probe", "controlToken": "control", "callId": "call", "deadline": time.monotonic() + 5}
        proof = {"invocationId": "a" * 32}
        for response in ({"go": False}, {"go": True, "callId": "call", "invocationId": "b" * 32}, {"go": True, "callId": "wrong", "invocationId": "a" * 32}):
            with mock.patch.object(worker, "isolation_proof", return_value=proof), mock.patch.object(worker, "send_frame"), mock.patch.object(worker, "receive_frame", return_value=response), mock.patch.object(worker.subprocess, "Popen") as native:
                self.assertEqual(worker.run(request, BytesSocket(), Path("/credentials")), 1)
                native.assert_not_called()

    def test_native_inherits_payload_descriptors_and_only_native_receives_provider_environment(self):
        request = {"action": "restic", "controlToken": "control", "callId": "call", "deadline": time.monotonic() + 5,
                   "args": ["cat", "config"], "restic": "/usr/bin/restic", "dataToken": "data", "dataSocket": "/run/owned/data",
                   "kind": "s3", "env": {"RESTIC_REPOSITORY": "s3:https://storage.example/bucket/prefix", "AWS_ACCESS_KEY_ID": "synthetic-key", "AWS_SECRET_ACCESS_KEY": "synthetic-secret"}}
        proof = {"invocationId": "a" * 32}
        native = mock.Mock(pid=123)
        native.poll.return_value = 0
        native.wait.return_value = 0
        bridge_process = mock.Mock()
        bridge_process.stdout = io.BytesIO(b'{"port":1234}\n')
        bridge_process.stdin = mock.Mock()
        bridge_process.poll.return_value = 0
        bridge_process.wait.return_value = 0
        control = mock.Mock()
        with mock.patch.object(worker, "isolation_proof", return_value=proof), mock.patch.object(worker, "receive_frame", return_value={"go": True, "callId": "call", "invocationId": "a" * 32}), mock.patch.object(worker, "send_frame") as frames, mock.patch.object(worker.Path, "stat", return_value=mock.Mock(st_uid=0, st_mode=stat.S_IFREG | 0o755)), mock.patch.object(worker.subprocess, "Popen", side_effect=[bridge_process, native]) as launch, mock.patch.object(worker.select, "select", return_value=([bridge_process.stdout], [], [])), mock.patch.object(worker, "pid_birth", return_value="born"):
            self.assertEqual(worker.run(request, control, Path("/credentials")), 0)
        bridge_call, native_call = launch.call_args_list
        self.assertNotIn("synthetic-secret", repr(bridge_call))
        self.assertIsNone(native_call.kwargs["stdin"])
        self.assertIsNone(native_call.kwargs["stdout"])
        self.assertEqual(native_call.kwargs["stderr"], subprocess.DEVNULL)
        self.assertTrue(native_call.kwargs["close_fds"])
        self.assertNotIn("preexec_fn", native_call.kwargs)
        self.assertEqual(native_call.kwargs["env"]["AWS_SECRET_ACCESS_KEY"], "synthetic-secret")
        self.assertEqual(native_call.kwargs["env"]["NO_PROXY"], "")
        self.assertIn("s3.bucket-lookup=path", native_call.args[0])
        self.assertNotIn("synthetic-secret", repr(frames.call_args_list))
        worker.close_extra_fds.assert_called_once_with(keep=(control.fileno(),))
        self.assertNotEqual(os.environ.get("AWS_SECRET_ACCESS_KEY"), "synthetic-secret")

    def test_dump_regular_fd_gate_precedes_native_and_sets_limit_without_preexec(self):
        request = {"action": "probe", "controlToken": "token", "callId": "call", "deadline": time.monotonic() + 5,
                   "args": ["version"], "restic": "/usr/bin/restic", "outputLimit": 4096}
        native = mock.Mock(pid=123)
        native.poll.return_value = 0
        native.wait.return_value = 0
        effects = []
        with mock.patch.object(worker, "isolation_proof", return_value={"invocationId": "a" * 32}), mock.patch.object(worker, "receive_frame", return_value={"go": True, "callId": "call", "invocationId": "a" * 32}), mock.patch.object(worker, "send_frame"), mock.patch.object(worker.Path, "stat", return_value=mock.Mock(st_uid=0, st_mode=stat.S_IFREG | 0o755)), mock.patch.object(worker.resource, "setrlimit", side_effect=lambda *a: effects.append(("limit", a))), mock.patch.object(worker.subprocess, "Popen", side_effect=lambda *a, **k: effects.append(("spawn", k)) or native), mock.patch.object(worker, "pid_birth", return_value="born"):
            self.assertEqual(worker.run(request, mock.Mock(), Path("/credentials")), 0)
        self.assertEqual(effects[0], ("limit", (worker.resource.RLIMIT_FSIZE, (4096, 4096))))
        self.assertEqual(effects[1][0], "spawn")
        self.assertNotIn("preexec_fn", effects[1][1])

    def test_real_grandchild_inherits_original_payload_fds_and_file_size_limit(self):
        # POSIX descriptor proof only; this does not substitute for systemd/Linux acceptance.
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            payload = bytes(range(256)) * 4096
            source = directory / "input"
            source.write_bytes(payload)
            module_dir = str(Path(worker.__file__).resolve().parent)
            script = r"""
import json,os,pathlib,subprocess,sys,time
sys.path.insert(0,sys.argv[1])
import compose_storage_worker as w
real=w.subprocess.Popen
code='import os\nwhile True:\n b=os.read(0,65536)\n if not b:break\n os.write(1,b)'
def spawn(args,**kwargs):
 return real([sys.executable,'-c',code],**kwargs)
w.subprocess.Popen=spawn
w.isolation_proof=lambda request:{'invocationId':'a'*32}
w.receive_frame=lambda connection:{'go':True,'callId':'call','invocationId':'a'*32}
w.send_frame=lambda *args:None
w.pid_birth=lambda pid:'born'
w.close_extra_fds=lambda **kwargs:None
import socket
one,two=socket.socketpair()
class Control:
 def fileno(self):return one.fileno()
 def settimeout(self,value):one.settimeout(value)
 def setblocking(self,value):one.setblocking(value)
request={'action':'probe','controlToken':'t','callId':'call','deadline':time.monotonic()+10,'args':['version'],'restic':'/usr/bin/true','outputLimit':int(sys.argv[2])}
raise SystemExit(w.run(request,Control(),pathlib.Path('/credentials')))
"""
            for limit, success in ((len(payload), True), (65536, False)):
                destination = directory / str(limit)
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with source.open("rb") as incoming, os.fdopen(fd, "wb") as outgoing:
                    completed = subprocess.run([os.sys.executable, "-c", script, module_dir, str(limit)], stdin=incoming, stdout=outgoing,
                                               stderr=subprocess.PIPE, timeout=15)
                self.assertEqual(completed.returncode == 0, success, completed.stderr.decode())
                data = destination.read_bytes()
                self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
                self.assertLessEqual(len(data), limit)
                if success:
                    self.assertEqual(data, payload)
                else:
                    self.assertEqual(data, payload[:len(data)])

    def test_socket_payload_descriptors_are_rejected(self):
        with mock.patch.object(worker.os, "fstat", return_value=mock.Mock(st_mode=stat.S_IFSOCK)):
            with self.assertRaisesRegex(worker.WorkerError, "worker_isolation_preflight_failed"):
                worker.descriptor_kind(0)


class MarkerAuthorityTests(unittest.TestCase):
    setUp = LifecycleTests.setUp
    intent = LifecycleTests.intent
    unit = LifecycleTests.unit

    @contextlib.contextmanager
    def account_boundary(self, *, marker=None, uid=1001, gid=1001, faults=None, default_inaccessible=False):
        name = self.identity["user"]
        value = marker if marker is not None else {"user": name, "uid": uid, "gid": gid}
        user = types.SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=gid, pw_shell="/usr/sbin/nologin")
        group = types.SimpleNamespace(gr_name=name, gr_gid=gid, gr_mem=[])
        seen = []
        def lstat(path):
            raw = str(path)
            seen.append(raw)
            if default_inaccessible and raw in {str(transport.ACCOUNT_MARKER), str(transport.ACCOUNT_MARKER.parent)}:
                raise PermissionError()
            if faults and raw in faults:
                fault = faults[raw]
                if isinstance(fault, BaseException):
                    raise fault
                return fault
            return types.SimpleNamespace(st_uid=0, st_mode=(stat.S_IFREG | 0o600) if raw.endswith(".json") else (stat.S_IFDIR | 0o755))
        with mock.patch.object(transport.Path, "lstat", lstat), mock.patch.object(transport, "read_json", return_value=value) as read, mock.patch.object(transport.pwd, "getpwnam", return_value=user), mock.patch.object(transport.pwd, "getpwall", return_value=[user]), mock.patch.object(transport.grp, "getgrgid", return_value=group), mock.patch.object(transport.grp, "getgrall", return_value=[group]):
            yield seen, read

    def put_pin(self, value):
        path = self.root / "transport-settings.json"
        path.write_text(json.dumps(value))
        return path

    @staticmethod
    def read_state(path):
        return json.loads(Path(path).read_bytes())

    def test_marker_path_syntax_and_types_fail_before_probe_effects(self):
        valid = "/etc/isolated-instance/storage-worker.json"
        self.assertEqual(transport.validate_marker_path(valid), valid)
        self.assertEqual(transport.validate_marker_path(), str(transport.ACCOUNT_MARKER))
        for path in (True, 0, [], {}, Path(valid), "", "relative.json", "https://host/marker.json", "file:///etc/marker.json", "$MARKER", "/etc/../marker.json", "/etc/./marker.json", "/etc//marker.json", "//etc/marker.json", "/etc/marker.json/", "/etc/a\x00.json", "/etc/a\n.json", "/etc/a\x85.json", "/etc/" + "x" * 4096):
            with self.subTest(path=repr(path)), mock.patch.object(transport, "prerequisites") as prerequisites, mock.patch.object(transport, "account") as account, mock.patch.object(transport.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(transport.TransportError, "network_isolation_unavailable"):
                    transport.probe_runtime(marker_path=path)
                prerequisites.assert_not_called(); account.assert_not_called(); launch.assert_not_called()

    def test_default_marker_compatibility_and_all_parents_verified(self):
        with self.account_boundary() as (seen, read):
            self.assertEqual(transport.account(self.identity["user"]), self.identity)
        self.assertEqual(seen, [str(path) for path in reversed(transport.ACCOUNT_MARKER.parents)] + [str(transport.ACCOUNT_MARKER)])
        read.assert_called_once_with(transport.ACCOUNT_MARKER)

    def test_custom_authority_never_reads_inaccessible_default(self):
        for marker in ("/etc/isolated-one/storage-worker.json", "/etc/isolated-two/storage-worker.json"):
            with self.account_boundary(default_inaccessible=True) as (seen, read):
                self.assertEqual(transport.account(self.identity["user"], marker_path=marker), self.identity)
            self.assertNotIn(str(transport.ACCOUNT_MARKER), seen)
            self.assertNotIn(str(transport.ACCOUNT_MARKER.parent), seen)
            read.assert_called_once_with(Path(marker))
        with self.account_boundary(default_inaccessible=True):
            with self.assertRaises(transport.TransportError):
                transport.account(self.identity["user"])

    def test_marker_missing_foreign_writable_and_symlink_chain_fail_closed(self):
        marker = "/etc/isolated/storage-worker.json"
        faults = [
            {marker: FileNotFoundError()},
            {marker: types.SimpleNamespace(st_uid=1001, st_mode=stat.S_IFREG | 0o600)},
            {marker: types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o640)},
            {marker: types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o600)},
            {"/etc/isolated": types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o777)},
            {"/etc/isolated": types.SimpleNamespace(st_uid=1001, st_mode=stat.S_IFDIR | 0o755)},
            {"/etc/isolated": types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o755)},
            {"/etc": types.SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o775)},
        ]
        for fault in faults:
            with self.subTest(fault=fault), self.account_boundary(faults=fault) as (_, read), mock.patch.object(transport.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(transport.TransportError, "network_isolation_unavailable"):
                    transport.account(self.identity["user"], marker_path=marker)
                read.assert_not_called(); launch.assert_not_called()

    def test_marker_identity_rejects_boolean_ids_even_for_native_uid_gid_one(self):
        exact = {"user": self.identity["user"], "uid": 1, "gid": 1}
        with self.account_boundary(marker=exact, uid=1, gid=1):
            self.assertEqual(transport.account(self.identity["user"]), exact)
        for changed in (exact | {"uid": True}, exact | {"gid": True}, exact | {"uid": "1"}, exact | {"gid": 1.0}, exact | {"user": True}, exact | {"extra": 1}, [exact]):
            with self.subTest(marker=changed), self.account_boundary(marker=changed, uid=1, gid=1), self.assertRaises(transport.TransportError):
                transport.account(self.identity["user"])

    def test_custom_pin_persists_for_timer_and_rejects_caller_authority_change(self):
        marker = "/etc/isolated/storage-worker.json"
        runner = transport.StorageTransport(self.root, self.identity["user"], marker_path=marker)
        with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", return_value=self.identity) as account:
            self.assertEqual(runner.settings(), self.identity)
            saved = self.read_state(self.root / "transport-settings.json")
            self.assertEqual(saved, self.identity | {"markerPath": marker})
            timer = transport.StorageTransport(self.root)
            self.assertEqual(timer.settings(), self.identity)
            self.assertEqual(timer._selected_marker, marker)
            account.assert_called_with(self.identity["user"], marker_path=marker)
            account.reset_mock()
            for changed in (transport.StorageTransport(self.root, marker_path="/etc/another/storage-worker.json"), transport.StorageTransport(self.root, "another", marker_path=marker)):
                with self.assertRaises(transport.TransportError):
                    changed.settings()
            account.assert_not_called()
            self.assertEqual(self.read_state(self.root / "transport-settings.json"), saved)

    def test_two_instances_keep_distinct_users_and_markers_without_default_fallback(self):
        second = self.root / "second"
        second.mkdir()
        identities = {"first": {"user": "worker-one", "uid": 1001, "gid": 1001}, "second": {"user": "worker-two", "uid": 2001, "gid": 2001}}
        roots = [(self.root, identities["first"], "/etc/isolated-one/storage-worker.json"), (second, identities["second"], "/etc/isolated-two/storage-worker.json")]
        def account(name, marker_path=None):
            self.assertIsNotNone(marker_path)
            matches = [identity for _, identity, marker in roots if identity["user"] == name and marker_path == marker]
            self.assertEqual(len(matches), 1)
            return matches[0]
        with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", side_effect=account):
            for state, identity, marker in roots:
                self.assertEqual(transport.StorageTransport(state, identity["user"], marker_path=marker).settings(), identity)
                self.assertEqual(transport.StorageTransport(state).settings(), identity)
                self.assertEqual(self.read_state(state / "transport-settings.json")["markerPath"], marker)

    def test_legacy_pin_upgrade_requires_identical_verified_default_and_never_custom(self):
        self.put_pin(self.identity)
        with mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", return_value=self.identity) as account:
            self.assertEqual(self.runner.settings(), self.identity)
            account.assert_called_once_with(self.identity["user"])
        self.assertEqual(self.read_state(self.root / "transport-settings.json"), self.identity | {"markerPath": str(transport.ACCOUNT_MARKER)})
        self.put_pin(self.identity)
        alternate = transport.StorageTransport(self.root, marker_path="/etc/isolated/storage-worker.json")
        with mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account") as account, mock.patch.object(transport, "atomic") as write:
            with self.assertRaises(transport.TransportError):
                alternate.settings()
            account.assert_not_called(); write.assert_not_called()
        self.assertEqual(self.read_state(self.root / "transport-settings.json"), self.identity)
        for failure in (transport.TransportError("network_isolation_unavailable"), self.identity | {"uid": 2001}):
            kwargs = {"side_effect": failure} if isinstance(failure, BaseException) else {"return_value": failure}
            with mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", **kwargs), mock.patch.object(transport, "atomic") as write:
                with self.assertRaises(transport.TransportError):
                    self.runner.settings()
                write.assert_not_called()

    def test_corrupt_pin_types_and_lost_authority_do_not_adopt_or_launch(self):
        exact = {"user": self.identity["user"], "uid": 1, "gid": 1}
        for saved in (exact | {"uid": True}, exact | {"gid": True}, exact | {"markerPath": None}, exact | {"markerPath": False}, exact | {"markerPath": "/etc/../marker.json"}):
            self.put_pin(saved)
            with mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account") as account, mock.patch.object(transport, "atomic") as write, mock.patch.object(transport.subprocess, "Popen") as launch:
                with self.assertRaises(transport.TransportError):
                    self.runner.settings()
                account.assert_not_called(); write.assert_not_called(); launch.assert_not_called()
        (self.root / "transport-settings.json").unlink()
        self.runner.directory.mkdir()
        with mock.patch.object(transport, "account") as account, mock.patch.object(transport, "atomic") as write:
            with self.assertRaises(transport.TransportError) as caught:
                self.runner.settings()
            self.assertTrue(caught.exception.unknown)
            account.assert_not_called(); write.assert_not_called()

    def test_recovery_uses_persisted_authority_not_changed_caller_configuration(self):
        marker = "/etc/isolated/storage-worker.json"
        self.put_pin(self.identity | {"markerPath": marker})
        calls = self.runner.directory / "calls"
        calls.mkdir(parents=True)
        owner = "12345678-1234-4234-8234-123456789abc"
        (self.runner.directory / "owner.json").write_text(json.dumps({"id": owner}))
        intent = self.intent() | {"owner": owner, "nodeId": None, "state": str(self.root.resolve()), "markerPath": marker}
        intent["marker"] = "RolyPolyOps storage " + owner + " " + intent["id"]
        run_root = self.root / "runs"
        intent["directory"] = str(run_root / intent["id"])
        intent["argv"] = ["/usr/bin/python3", str(Path(intent["directory"]) / "code" / "compose_storage_worker.py")]
        path = calls / (intent["id"] + ".json")
        path.write_text(json.dumps(intent))
        changed = transport.StorageTransport(self.root, "new-worker", marker_path="/etc/new-authority/storage-worker.json")
        with mock.patch.object(transport, "RUN_ROOT", run_root), mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", return_value=self.identity) as account, mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport, "systemctl", side_effect=[self.unit(intent), None]), mock.patch.object(transport.subprocess, "run", return_value=mock.Mock(returncode=0)) as stop, mock.patch.object(transport, "cgroup_empty", return_value=True):
            self.assertEqual(changed.recover(), [intent["id"]])
            account.assert_called_with(self.identity["user"], marker_path=marker)
            stop.assert_called_once()
            account.reset_mock()
            with self.assertRaises(transport.TransportError):
                changed.settings()
            account.assert_not_called()
        self.assertFalse(path.exists())

    def test_marker_loss_or_tamper_during_recovery_does_not_kill_or_create_writer(self):
        marker = "/etc/isolated/storage-worker.json"
        self.put_pin(self.identity | {"markerPath": marker})
        (self.runner.directory / "calls").mkdir(parents=True)
        for cause in ("missing", "symlink", "writable", "changed-identity"):
            with self.subTest(cause=cause), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", side_effect=transport.TransportError("network_isolation_unavailable")), mock.patch.object(transport, "systemctl") as inspect, mock.patch.object(transport.subprocess, "run") as stop, mock.patch.object(transport.subprocess, "Popen") as launch:
                with self.assertRaisesRegex(transport.TransportError, "transport_cleanup_unverified") as caught:
                    self.runner.recover()
                self.assertTrue(caught.exception.unknown)
                inspect.assert_not_called(); stop.assert_not_called(); launch.assert_not_called()

    def test_new_intent_records_the_persisted_marker_for_timer_recovery(self):
        marker = "/etc/isolated/storage-worker.json"
        self.put_pin(self.identity | {"markerPath": marker})
        run_root = self.root / "runs"
        with mock.patch.object(transport, "RUN_ROOT", run_root), mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", return_value=self.identity), mock.patch.object(transport, "read_owned", side_effect=lambda path, maximum: Path(path).read_bytes()), mock.patch.object(transport.os, "chown"), mock.patch.object(transport, "pid_birth", return_value="born"), mock.patch.object(transport.Path, "read_text", return_value="boot"), mock.patch.object(transport.subprocess, "Popen") as launch:
            self.assertEqual(self.runner.settings(), self.identity)
            intent, path = self.runner._prepare(timeout=3, parent=None, identity=self.identity, action="probe")
            self.assertEqual(intent["markerPath"], marker)
            self.assertEqual(self.read_state(path)["markerPath"], marker)
            self.assertEqual(intent["account"], self.identity)
            launch.assert_not_called()

    def test_changed_persisted_marker_cannot_authorize_an_old_intent_kill(self):
        old_marker, new_marker = "/etc/old/storage-worker.json", "/etc/new/storage-worker.json"
        self.put_pin(self.identity | {"markerPath": new_marker})
        calls = self.runner.directory / "calls"
        calls.mkdir(parents=True)
        owner = "12345678-1234-4234-8234-123456789abc"
        (self.runner.directory / "owner.json").write_text(json.dumps({"id": owner}))
        intent = self.intent() | {"owner": owner, "nodeId": None, "state": str(self.root.resolve()), "markerPath": old_marker}
        intent["marker"] = "RolyPolyOps storage " + owner + " " + intent["id"]
        run_root = self.root / "runs"
        intent["directory"] = str(run_root / intent["id"])
        intent["argv"] = ["/usr/bin/python3", str(Path(intent["directory"]) / "code" / "compose_storage_worker.py")]
        path = calls / (intent["id"] + ".json")
        path.write_text(json.dumps(intent))
        with mock.patch.object(transport, "RUN_ROOT", run_root), mock.patch.object(transport, "trusted"), mock.patch.object(transport, "read_json", side_effect=self.read_state), mock.patch.object(transport, "account", return_value=self.identity), mock.patch.object(transport, "systemctl") as inspect, mock.patch.object(transport.subprocess, "run") as stop, mock.patch.object(transport.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(transport.TransportError, "transport_cleanup_unverified") as caught:
                self.runner.recover()
            self.assertTrue(caught.exception.unknown)
            inspect.assert_not_called(); stop.assert_not_called(); launch.assert_not_called()
        self.assertTrue(path.exists())
        self.assertEqual(self.read_state(path)["markerPath"], old_marker)

    def test_probe_extension_keeps_default_call_and_passes_only_explicit_marker(self):
        for marker in (None, "/etc/isolated/storage-worker.json"):
            run_root = self.root / ("run-default" if marker is None else "run-custom")
            with mock.patch.object(transport, "RUN_ROOT", run_root), mock.patch.object(transport, "trusted"), mock.patch.object(transport, "prerequisites"), mock.patch.object(transport, "account", return_value=self.identity) as account, mock.patch.object(transport, "StorageTransport") as runner:
                self.assertTrue(transport.probe_runtime(timeout=3, marker_path=marker)["ready"])
                if marker is None:
                    account.assert_called_once_with(transport.DEFAULT_WORKER_USER)
                else:
                    account.assert_called_once_with(transport.DEFAULT_WORKER_USER, marker_path=marker)
                self.assertEqual(runner.call_args.kwargs["marker_path"], marker or str(transport.ACCOUNT_MARKER))
                runner.return_value._execute.assert_called_once_with({}, ["version"], timeout=3, probe=True, standalone=True)
                self.assertEqual(list(run_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
