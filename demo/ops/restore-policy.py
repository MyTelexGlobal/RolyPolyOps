#!/usr/bin/env python3
"""Reject unrecognized recovery definitions before starting any container."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def prepare(service, manifest, template, port, label, isolated=False):
    service = Path(service)
    if service.is_symlink() or not service.is_dir():
        raise ValueError("unsafe_service_root")
    if any(p.name not in {"compose.yaml", ".env", "site", "state", "secrets"} for p in service.iterdir()):
        raise ValueError("unexpected_package_file")
    for item in service.rglob("*"):
        if item.is_symlink() or not (item.is_file() or item.is_dir()):
            raise ValueError("unsupported_file_type")
    if (service / "compose.yaml").read_bytes() != template:
        raise ValueError("unsupported_compose_definition")
    for name in ("state/files/recovery-proof.txt", "secrets/db_password"):
        if not (service / name).is_file():
            raise ValueError("required_data_missing")
    if manifest.get("format") != "rolypolyops-demo-v1":
        raise ValueError("unsupported_format")
    images = {}
    for key, repo in (("webImage", "rolypolyops-demo"), ("dbImage", "rolypolyops-postgres")):
        identity = manifest.get(key, "")
        if not isinstance(identity, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", identity):
            raise ValueError("invalid_image_identity")
        images[key] = (identity, repo + ":sha-" + identity[7:19])
    if not isinstance(port, int) or not 1024 <= port <= 65535 or not re.fullmatch(r"[A-Za-z0-9 ._-]{1,80}", label):
        raise ValueError("invalid_target_parameters")
    # Discard all captured environment controls, including COMPOSE_FILE and profiles.
    temporary = service / ".env.prepared"
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"WEB_IMAGE={images['webImage'][1]}\nPOSTGRES_IMAGE={images['dbImage'][1]}\nSITE_LABEL={label}\nWEB_PORT={port}\n")
    os.replace(temporary, service / ".env")
    # Test copies cannot reach the Internet, host gateway or public traffic routes.
    override = service / "rpo.isolation.json"
    if isolated:
        options = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated", "com.docker.network.bridge.gateway_mode_ipv6": "isolated"}
        override.write_text(json.dumps({"networks": {name: {"internal": True, "driver_opts": options} for name in ("backend", "frontend")}}))
    return images


def main():
    try:
        service, manifest, archive, port, label, isolated = sys.argv[1:]
        template = Path("/etc/rolypolyops/package-compose.yaml")
        info = template.lstat()
        if template.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("untrusted_package_template")
        if isolated not in {"0", "1"}: raise ValueError("invalid_isolation")
        images = prepare(service, json.loads(Path(manifest).read_text()), template.read_bytes(), int(port), label, isolated == "1")
        subprocess.run(["docker", "load", "-i", archive], check=True, stdout=subprocess.DEVNULL)
        for identity, tag in images.values():
            subprocess.run(["docker", "tag", identity, tag], check=True)
    except Exception:
        print("Recovery package rejected before container startup; review its definition and data.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
