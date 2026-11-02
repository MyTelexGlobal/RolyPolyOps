#!/usr/bin/env python3
"""Data-only archive validator and constrained helper entry point."""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile

MAX_FILES = 100000
MAX_BYTES = 256 * 1024 ** 3
MAX_PATH = 4096
MAX_DEPTH = 64
HELPER_IMAGE = "python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337"
OWNER = "global.telex.rolypolyops"


class ArchiveError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _path(value):
    if (not isinstance(value, str) or not value or len(value.encode()) > MAX_PATH or "\x00" in value
            or "\\" in value or value.startswith("/") or any(ord(c) < 32 for c in value)):
        raise ArchiveError("archive_path_unsafe")
    parts = value.rstrip("/").split("/")
    if len(parts) > MAX_DEPTH or any(p in {"", ".", ".."} for p in parts):
        raise ArchiveError("archive_path_unsafe")
    return "/".join(parts)


def _link_text(target):
    if (not isinstance(target, str) or not target or target.startswith("/") or "\\" in target
            or len(target.encode()) > MAX_PATH or any(ord(c) < 32 for c in target)
            or len(target.split("/")) > MAX_DEPTH):
        raise ArchiveError("archive_link_unsafe")
    return target


def _resolve_link(name, target, hard, kinds, symbolic):
    """Resolve archive links as a virtual filesystem before any extractor sees them."""
    pending = _link_text(target).split("/")
    stack = [] if hard else name.split("/")[:-1]
    seen, hops, steps = set(), 0, 0
    while pending:
        steps += 1
        if steps > MAX_DEPTH * MAX_DEPTH:
            raise ArchiveError("archive_link_unsafe")
        part = pending.pop(0)
        if part in {"", "."}:
            continue
        if part == "..":
            if len(stack) <= 1:
                raise ArchiveError("archive_link_unsafe")
            stack.pop()
            continue
        if not stack and part != "payload":
            raise ArchiveError("archive_link_unsafe")
        candidate = "/".join(stack + [part])
        kind = kinds.get(candidate)
        if kind is None:
            raise ArchiveError("archive_link_unsafe")
        if kind == "symlink":
            if hard:
                raise ArchiveError("archive_link_unsafe")
            state = (candidate, tuple(stack), tuple(pending))
            hops += 1
            if state in seen or hops > 64:
                raise ArchiveError("archive_link_unsafe")
            seen.add(state)
            pending = _link_text(symbolic[candidate]).split("/") + pending
            continue
        stack.append(part)
        if len(stack) > MAX_DEPTH:
            raise ArchiveError("archive_link_unsafe")
        if pending and kind != "directory":
            raise ArchiveError("archive_link_unsafe")
    result = "/".join(stack)
    if not stack or stack[0] != "payload" or result not in kinds or (hard and kinds[result] != "file") or hops:
        # Direct internal links are supported; symlink-to-symlink transit remains outside the accepted data format.
        raise ArchiveError("archive_link_unsafe")
    return result


def _pax(headers):
    accepted = {}
    for key, value in headers.items():
        if key in {"path", "linkpath", "mtime", "atime", "ctime", "size", "uid", "gid", "uname", "gname"}:
            continue
        if key.startswith("SCHILY.xattr.user."):
            accepted[key] = {"base64": base64.b64encode(value.encode("utf-8", "surrogateescape")).decode()}
        elif key in {"SCHILY.acl.access", "SCHILY.acl.default"}:
            # Numeric ids only; never resolve destination account names.
            acl = value.replace("\n", ",").split(",")
            for item in acl:
                if item and not re.fullmatch(r"(?:default:)?(?:user|group|mask|other):[0-9]*:[r-][w-][x-](?::[0-9]+)?", item):
                    raise ArchiveError("archive_acl_unsupported")
            accepted[key] = value
        else:
            raise ArchiveError("archive_metadata_unsupported")
    return accepted


def inspect_archive(path, *, data=True):
    """Read every member and content before any extraction/image load. Never calls extractall."""
    entries, kinds, total, links = [], {}, 0, []
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                if len(entries) >= MAX_FILES:
                    raise ArchiveError("archive_file_limit")
                name = _path(member.name)
                if data and name.split("/")[0] != "payload":
                    raise ArchiveError("archive_path_unsafe")
                if name in kinds:
                    raise ArchiveError("archive_duplicate_path")
                if member.mode & 0o6000 or not math.isfinite(member.mtime) or member.uid < 0 or member.gid < 0:
                    raise ArchiveError("archive_metadata_unsafe")
                if member.isfile():
                    kind = "file"
                elif member.isdir():
                    kind = "directory"
                elif member.issym() and data:
                    kind = "symlink"
                elif member.islnk() and data:
                    kind = "hardlink"
                else:
                    raise ArchiveError("archive_special_file")
                if member.size < 0:
                    raise ArchiveError("archive_byte_limit")
                total += member.size
                if total > MAX_BYTES:
                    raise ArchiveError("archive_byte_limit")
                pax = _pax(member.pax_headers)
                entry = {"path": name, "kind": kind, "uid": member.uid, "gid": member.gid,
                         "mode": member.mode & 0o7777, "mtime": str(member.mtime), "size": member.size, "pax": pax}
                if kind in {"symlink", "hardlink"}:
                    _link_text(member.linkname)
                    entry["link"] = member.linkname
                    links.append((name, member.linkname, kind))
                if kind == "file":
                    stream = archive.extractfile(member)
                    h = hashlib.sha256()
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        h.update(block)
                    entry["sha256"] = h.hexdigest()
                entries.append(entry)
                kinds[name] = kind
        for name, kind in kinds.items():
            parent = name.rpartition("/")[0]
            while parent:
                if parent in kinds and kinds[parent] != "directory":
                    raise ArchiveError("archive_link_parent")
                parent = parent.rpartition("/")[0]
        virtual = dict(kinds)
        for name in kinds:
            parts = name.split("/")
            for index in range(1, len(parts)):
                virtual.setdefault("/".join(parts[:index]), "directory")
        symbolic = {name: target for name, target, kind in links if kind == "symlink"}
        for name, target, kind in links:
            _resolve_link(name, target, kind == "hardlink", virtual, symbolic)
        return {"files": len(entries), "bytes": total, "entries": sorted(entries, key=lambda x: x["path"]), "sha256": digest(path)}
    except (tarfile.TarError, OSError, UnicodeError, OverflowError):
        raise ArchiveError("archive_invalid") from None


def inspect_tree(source):
    source = Path(source)
    if not source.exists() or source.is_symlink():
        raise ArchiveError("source_path_unsafe")
    count, total, kinds, symbolic = 0, 0, {}, {}
    for base, dirs, files in os.walk(source, followlinks=False) if source.is_dir() else [(source.parent, [], [source.name])]:
        paths = [Path(base)] + [Path(base) / name for name in files] + [Path(base) / name for name in dirs if (Path(base) / name).is_symlink()] if source.is_dir() else [source]
        for path in paths:
            value = path.lstat()
            count += 1
            if count > MAX_FILES:
                raise ArchiveError("archive_file_limit")
            relative = "payload" + ("/" + str(path.relative_to(source)) if source.is_dir() and path != source else "")
            _path(relative)
            kinds[relative] = "symlink" if stat.S_ISLNK(value.st_mode) else "directory" if stat.S_ISDIR(value.st_mode) else "file"
            if value.st_mode & (stat.S_ISUID | stat.S_ISGID) or not (stat.S_ISREG(value.st_mode) or stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode)):
                raise ArchiveError("archive_metadata_unsafe")
            if stat.S_ISLNK(value.st_mode):
                symbolic[relative] = _link_text(os.readlink(path))
                try:
                    resolved = path.resolve(strict=True)
                    resolved.relative_to(source.resolve())
                except (ValueError, OSError, RuntimeError):
                    raise ArchiveError("archive_link_unsafe") from None
            for name in os.listxattr(path, follow_symlinks=False):
                if not (name.startswith("user.") or name in {"system.posix_acl_access", "system.posix_acl_default"}):
                    raise ArchiveError("archive_metadata_unsupported")
            total += value.st_size if stat.S_ISREG(value.st_mode) else 0
            if total > MAX_BYTES:
                raise ArchiveError("archive_byte_limit")
    for name, target in symbolic.items():
        _resolve_link(name, target, False, kinds, symbolic)
    return {"files": count, "bytes": total}


def pack(source, destination):
    source, destination = Path(source), Path(destination)
    if source.name != "payload" or destination.exists():
        raise ArchiveError("helper_path_unsafe")
    inspect_tree(source)
    result = subprocess.run(["tar", "--create", "--file", str(destination), "--format=pax", "--numeric-owner", "--acls", "--xattrs", "--xattrs-include=user.*", "--atime-preserve=system", "--directory", str(source.parent), "--", source.name],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        raise ArchiveError("archive_capture_failed")
    metadata = inspect_archive(destination)
    fd = os.open(destination, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return metadata


def unpack(archive, destination):
    archive, destination = Path(archive), Path(destination)
    wanted = inspect_archive(archive)
    if not destination.is_dir():
        raise ArchiveError("restore_destination_not_empty")
    existing = list(destination.iterdir())
    if existing and not (len(existing) == 1 and existing[0].name == "payload" and existing[0].is_dir() and not existing[0].is_symlink() and not any(existing[0].iterdir())):
        raise ArchiveError("restore_destination_not_empty")
    result = subprocess.run(["tar", "--extract", "--file", str(archive), "--directory", str(destination), "--numeric-owner", "--same-owner", "--same-permissions", "--delay-directory-restore", "--acls", "--xattrs", "--xattrs-include=user.*"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if result.returncode:
        raise ArchiveError("archive_extract_failed")
    # Repack independently to check bytes, IDs, modes, links, timestamps and accepted metadata.
    verify = destination / "verification.tar"
    got = pack(destination / "payload", verify)
    try:
        if got["entries"] != wanted["entries"]:
            raise ArchiveError("restore_metadata_mismatch")
    finally:
        verify.unlink(missing_ok=True)
    return {"verified": True, "files": wanted["files"], "bytes": wanted["bytes"]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("inspect", "pack", "unpack", "http"))
    parser.add_argument("source")
    parser.add_argument("destination", nargs="?")
    args = parser.parse_args()
    try:
        if args.action == "inspect":
            value = inspect_tree(args.source)
        elif args.action == "pack":
            value = pack(args.source, args.destination)
            value["metadataDigest"] = hashlib.sha256(canonical(value.pop("entries"))).hexdigest()
        elif args.action == "unpack":
            value = unpack(args.source, args.destination)
        else:
            import http.client
            import urllib.parse
            import ipaddress
            parsed = urllib.parse.urlsplit(args.source)
            if parsed.scheme != "http" or parsed.username or parsed.password or parsed.fragment or not parsed.hostname or not parsed.port:
                raise ArchiveError("health_probe_invalid")
            ipaddress.ip_address(parsed.hostname)
            connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
            try:
                connection.request("GET", urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, "")))
                response = connection.getresponse()
                value = {"status": response.status}
            finally:
                connection.close()
        print(json.dumps(value, separators=(",", ":")))
    except (ArchiveError, OSError, ValueError):
        print(json.dumps({"error": getattr(sys.exc_info()[1], "code", "helper_failed")}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
