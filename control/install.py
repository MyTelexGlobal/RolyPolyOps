#!/usr/bin/env python3
"""Install the control service or enroll a host from a trusted source checkout."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import urllib.parse
import urllib.request

try:
    from .agent import NoRedirect, VERSION, atomic, read_json
except ImportError:
    from agent import NoRedirect, VERSION, atomic, read_json

DEST = Path("/opt/rolypolyops/control")
STATE = Path("/var/lib/rolypolyops-control")
AGENT_CONFIG = Path("/etc/rolypolyops/agent.json")
UNIT_DIR = Path("/etc/systemd/system")
CONFIG_DIR = Path("/etc/rolypolyops")


def command(args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL)


def copy_source():
    source = Path(__file__).resolve().parent
    DEST.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    DEST.parent.chmod(0o755)
    DEST.mkdir(parents=True, exist_ok=True, mode=0o755)
    DEST.chmod(0o755)
    for name in ("controller.py", "agent.py", "install.py"):
        if (source / name).is_file() and (source / name).resolve() != (DEST / name).resolve():
            shutil.copyfile(source / name, DEST / name)
            (DEST / name).chmod(0o644)
    if (source / "web").is_dir() and (source / "web").resolve() != (DEST / "web").resolve():
        shutil.copytree(source / "web", DEST / "web", dirs_exist_ok=True)
        (DEST / "web").chmod(0o755)
        for file in (DEST / "web").rglob("*"):
            file.chmod(0o755 if file.is_dir() else 0o644)


def install_package_policy():
    package = Path(__file__).resolve().parent.parent / "demo"
    if not all((package / name).is_file() for name in ("compose.yaml", "ops/labctl", "ops/restore-policy.py")):
        raise ValueError("A complete trusted release checkout is required")
    config = CONFIG_DIR
    config.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copyfile(package / "compose.yaml", config / "package-compose.yaml")
    (config / "package-compose.yaml").chmod(0o644)
    library = Path("/usr/local/lib/rolypolyops")
    library.mkdir(parents=True, exist_ok=True, mode=0o755)
    library.chmod(0o755)
    shutil.copyfile(package / "ops/restore-policy.py", library / "restore-policy.py")
    (library / "restore-policy.py").chmod(0o644)
    temporary = Path("/usr/local/sbin/.rolypolyops-lab.new")
    shutil.copyfile(package / "ops/labctl", temporary)
    temporary.chmod(0o755)
    os.replace(temporary, Path("/usr/local/sbin/rolypolyops-lab"))


def controller(origin, configure_proxy):
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError("Use an HTTPS origin without a path or credentials")
    config_dir = CONFIG_DIR
    config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    config_stat = config_dir.lstat()
    if config_dir.is_symlink() or config_stat.st_uid != 0 or config_stat.st_mode & 0o022:
        raise ValueError("Untrusted installation configuration directory")
    existing = read_json(config_dir / "control-installation.json")
    if existing and existing.get("origin") != origin.rstrip("/"):
        raise ValueError("Existing installation uses a different origin; refusing to replace it")
    try:
        account = pwd.getpwnam("rolypolyops-control")
    except KeyError:
        command(["useradd", "--system", "--home-dir", str(STATE), "--shell", "/usr/sbin/nologin", "rolypolyops-control"])
        account = pwd.getpwnam("rolypolyops-control")
    if account.pw_uid == 0:
        raise ValueError("The control account must be unprivileged")
    copy_source()
    STATE.mkdir(parents=True, exist_ok=True, mode=0o700)
    if STATE.is_symlink():
        raise ValueError("Untrusted control data directory")
    # User-writable catalog paths are opened only with the service account's authority.
    # Never recursively chown paths supplied by an unprivileged process.
    os.chown(STATE, account.pw_uid, account.pw_gid, follow_symlinks=False)
    command(["runuser", "-u", "rolypolyops-control", "--", sys.executable, str(DEST / "controller.py"), "init", "--data-dir", str(STATE), "--origin", origin])
    atomic(config_dir / "control-installation.json", {"origin": origin.rstrip("/"), "version": VERSION})
    unit = f"""[Unit]
Description=RolyPolyOps control service
After=network-online.target
Wants=network-online.target
[Service]
User=rolypolyops-control
Group=rolypolyops-control
ExecStart={sys.executable} {DEST}/controller.py serve --data-dir {STATE} --origin {origin} --host 127.0.0.1 --port 8090
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths={STATE}
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
"""
    (UNIT_DIR / "rolypolyops-control.service").write_text(unit)
    (UNIT_DIR / "rolypolyops-control.service").chmod(0o644)
    if configure_proxy:
        caddyfile = Path("/etc/caddy/Caddyfile")
        routes = Path("/etc/caddy/rolypolyops-routes")
        if not caddyfile.is_file() or "import /etc/caddy/rolypolyops-routes/*.caddy" not in caddyfile.read_text():
            raise ValueError("Proxy integration requires the managed routes import; existing proxy configuration was preserved")
        routes.mkdir(parents=True, exist_ok=True)
        route = routes / "control.caddy"
        old = route.read_bytes() if route.exists() else None
        route.write_text("handle /ops/* {\n  reverse_proxy 127.0.0.1:8090 {\n    header_up X-RPO-Client-IP {remote_host}\n  }\n}\n")
        route.chmod(0o644)
        try:
            command(["caddy", "validate", "--config", str(caddyfile)])
        except Exception:
            if old is None: route.unlink()
            else: route.write_bytes(old)
            raise
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "rolypolyops-control.service"])
    command(["systemctl", "restart", "rolypolyops-control.service"])
    if configure_proxy:
        command(["systemctl", "reload", "caddy"])
    print("Control installed. Open " + origin.rstrip("/") + "/ops/.")
    print("Initial password is stored privately at " + str(STATE / "admin-password") + ".")


def agent(controller_url, enrollment, replace=False):
    parsed = urllib.parse.urlsplit(controller_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path.rstrip("/") != "/ops":
        raise ValueError("Use the HTTPS control URL ending in /ops")
    existing = read_json(AGENT_CONFIG)
    if existing and not replace:
        if existing.get("controller") != controller_url.rstrip("/"):
            raise ValueError("Agent already belongs to another controller")
        config = existing
    else:
        if not enrollment:
            raise ValueError("An enrollment code is required")
        request = urllib.request.Request(controller_url.rstrip("/") + "/agent/enroll",
            json.dumps({"code": enrollment, "hostname": socket.gethostname(), "version": VERSION}).encode(),
            {"Content-Type": "application/json"}, method="POST")
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=20) as response:
            enrolled = json.load(response)
        if enrolled.get("role") not in {"primary", "recovery"} or not enrolled.get("token") or not enrolled.get("nodeId"):
            raise ValueError("Invalid enrollment response; use a new code if registration reply was lost")
        config = {"controller": controller_url.rstrip("/"), "nodeId": enrolled["nodeId"], "token": enrolled["token"], "role": enrolled["role"]}
        atomic(AGENT_CONFIG, config)
    copy_source()
    install_package_policy()
    unit = f"""[Unit]
Description=RolyPolyOps outbound host service
After=network-online.target docker.service
Wants=network-online.target
[Service]
ExecStart={sys.executable} {DEST}/agent.py --config {AGENT_CONFIG}
Restart=always
RestartSec=5
KillMode=control-group
TimeoutStopSec=30
UMask=0077
NoNewPrivileges=true
ProtectHome=true
[Install]
WantedBy=multi-user.target
"""
    (UNIT_DIR / "rolypolyops-agent.service").write_text(unit)
    (UNIT_DIR / "rolypolyops-agent.service").chmod(0o644)
    command(["systemctl", "daemon-reload"])
    command(["systemctl", "enable", "--now", "rolypolyops-agent.service"])
    command(["systemctl", "restart", "rolypolyops-agent.service"])
    print("Host enrolled. Check its observed state in the control panel.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("controller")
    c.add_argument("--origin", required=True)
    c.add_argument("--configure-proxy", action="store_true", help="Use the managed Caddy routes import")
    a = sub.add_parser("agent")
    a.add_argument("--controller", required=True)
    a.add_argument("--enrollment")
    a.add_argument("--replace-enrollment", action="store_true")
    args = p.parse_args()
    if os.geteuid() != 0 or sys.platform != "linux":
        p.error("Installation requires root on Linux")
    if not shutil.which("systemctl"):
        p.error("systemd is required")
    os.umask(0o077)
    try:
        if args.command == "controller": controller(args.origin, args.configure_proxy)
        else: agent(args.controller, args.enrollment, args.replace_enrollment)
    except Exception:
        print("Installation failed. Existing service data was preserved; check prerequisites and the enrollment code.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
