#!/usr/bin/env python3
"""Bounded byte bridge for an isolated storage unit. No repository credentials."""
import argparse
import json
import os
import select
import socket
import struct
import sys
import threading
import time

MAX_CONNECTIONS = 32
MAX_LINE = 8192
MAX_HEADERS = 16384
MAX_FIELDS = 64
MAX_FRAME = 65536


class ProtocolError(Exception):
    def __init__(self, limit=False):
        self.limit = limit
        super().__init__("protocol_limit" if limit else "protocol_invalid")


def close_extra_fds(keep=()):
    with os.scandir("/proc/self/fd") as entries:
        values = [int(entry.name) for entry in entries if entry.name.isdigit() and int(entry.name) > 2 and int(entry.name) not in keep]
    for value in values:
        try:
            os.close(value)
        except OSError:
            pass


def send_frame(connection, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(raw) > MAX_FRAME:
        raise ProtocolError()
    connection.sendall(struct.pack("!I", len(raw)) + raw)


def receive_frame(connection, maximum=MAX_FRAME):
    def exact(count):
        data = bytearray()
        while len(data) < count:
            block = connection.recv(count - len(data))
            if not block:
                raise ProtocolError()
            data.extend(block)
        return bytes(data)
    length = struct.unpack("!I", exact(4))[0]
    if not 1 <= length <= maximum:
        raise ProtocolError()
    try:
        value = json.loads(exact(length))
    except (ValueError, UnicodeError):
        raise ProtocolError() from None
    if not isinstance(value, dict):
        raise ProtocolError()
    return value


def read_headers(connection, deadline):
    data = bytearray()
    end = min(deadline, time.monotonic() + 5)
    while b"\r\n\r\n" not in data:
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise ProtocolError(limit=True)
        connection.settimeout(remaining)
        try:
            block = connection.recv(min(4096, MAX_HEADERS + 1 - len(data)))
        except socket.timeout:
            raise ProtocolError(limit=True) from None
        if not block:
            raise ProtocolError()
        data.extend(block)
        first = data.find(b"\r\n")
        if len(data) > MAX_HEADERS or (first < 0 and len(data) > MAX_LINE) or first > MAX_LINE:
            raise ProtocolError(limit=True)
    head, tail = bytes(data).split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if len(lines) - 1 > MAX_FIELDS:
        raise ProtocolError(limit=True)
    try:
        method, authority, version = lines[0].decode("ascii").split(" ")
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ValueError()
        headers = {}
        for line in lines[1:]:
            if not line or line[:1] in {b" ", b"\t"} or b":" not in line:
                raise ValueError()
            key, value = line.split(b":", 1)
            key = key.decode("ascii").lower()
            if not key or any(c not in "!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz" for c in key) or key in headers:
                raise ValueError()
            value = value.strip().decode("ascii")
            if any(ord(c) < 32 or ord(c) == 127 for c in value):
                raise ValueError()
            headers[key] = value
        return method, authority, headers, bytes(data[:len(head) + 4]), tail
    except (ValueError, UnicodeError):
        raise ProtocolError() from None


def pump(left, right, deadline, stopped=None):
    """Bounded bidirectional transfer with half-close and idle deadline."""
    active = {left, right}
    idle = time.monotonic() + 60
    while active and time.monotonic() < deadline and not (stopped and stopped.is_set()):
        remaining = min(deadline, idle) - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select(list(active), [], [], min(remaining, 1))
        for source in ready:
            block = source.recv(65536)
            destination = right if source is left else left
            if not block:
                active.remove(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            destination.settimeout(min(10, max(0.1, deadline - time.monotonic())))
            destination.sendall(block)
            idle = time.monotonic() + 60


class Bridge:
    def __init__(self, unix_path, deadline):
        if not isinstance(unix_path, str) or not unix_path.startswith("/run/") or len(unix_path.encode()) > 100 or "\x00" in unix_path:
            raise ProtocolError()
        self.unix_path = unix_path
        self.deadline = min(deadline, time.monotonic() + 7200)
        self.stopped = threading.Event()
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.lock = threading.Lock()
        self.connections, self.threads = set(), set()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(MAX_CONNECTIONS)
        self.listener.settimeout(0.5)

    def _serve(self, client):
        remote = None
        try:
            method, _, _, head, tail = read_headers(client, self.deadline)
            if method != "CONNECT":
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length:0\r\nConnection:close\r\n\r\n")
                return
            remote = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            remote.settimeout(5)
            remote.connect(self.unix_path)
            with self.lock:
                self.connections.add(remote)
            remote.sendall(head + tail)
            pump(client, remote, self.deadline, self.stopped)
        except (OSError, ProtocolError) as error:
            try:
                code = b"503 Unavailable" if getattr(error, "limit", False) else b"403 Forbidden"
                client.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Length:0\r\nConnection:close\r\n\r\n")
            except OSError:
                pass
        finally:
            with self.lock:
                self.connections.discard(client)
                if remote:
                    self.connections.discard(remote)
                self.threads.discard(threading.current_thread())
            client.close()
            if remote:
                remote.close()
            self.slots.release()

    def serve(self):
        try:
            while not self.stopped.is_set() and time.monotonic() < self.deadline:
                try:
                    client, _ = self.listener.accept()
                except socket.timeout:
                    continue
                if not self.slots.acquire(blocking=False):
                    try:
                        client.sendall(b"HTTP/1.1 503 Unavailable\r\nContent-Length:0\r\nConnection:close\r\n\r\n")
                    finally:
                        client.close()
                    continue
                with self.lock:
                    self.connections.add(client)
                    thread = threading.Thread(target=self._serve, args=(client,), daemon=True)
                    self.threads.add(thread)
                thread.start()
        finally:
            self.stopped.set()
            self.listener.close()
            with self.lock:
                for connection in self.connections:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                threads = list(self.threads)
            end = time.monotonic() + 3
            for thread in threads:
                thread.join(max(0, end - time.monotonic()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--deadline", required=True, type=float)
    args = parser.parse_args()
    close_extra_fds()
    raw = sys.stdin.buffer.readline(128)
    if not raw.endswith(b"\n") or len(raw) > 101:
        return 1
    try:
        bridge = Bridge(raw[:-1].decode("utf-8"), args.deadline)
        print(json.dumps({"port": bridge.listener.getsockname()[1]}), flush=True)
        bridge.serve()
    except (OSError, ProtocolError, UnicodeError):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
