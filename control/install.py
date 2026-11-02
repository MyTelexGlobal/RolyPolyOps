#!/usr/bin/env python3
"""Install the control service or enroll a host from a trusted source checkout."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
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


def checked_url(value, paths):
    if not isinstance(value, str) or len(value) > 512 or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        raise ValueError("Invalid HTTPS URL")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in paths:
        raise ValueError("Use a plain HTTPS address")
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.rstrip(".").split(".")):
            raise ValueError("Invalid host")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("Invalid port")
    return parsed


def command(args):
    subprocess.run(args, check=True, stdin=subprocess.DEVNULL)


def copy_source():
    source = Path(__file__).resolve().parent
    DEST.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    DEST.parent.chmod(0o755)
    DEST.mkdir(parents=True, exist_ok=True, mode=0o755)
    DEST.chmod(0o755)
    modules = ("controller.py", "agent.py", "install.py", "compose_control.py", "compose_engine.py", "compose_storage.py", "compose_seal.py", "compose_helper.py")
    if not all((source / name).is_file() for name in modules):
        raise ValueError("A complete trusted control release checkout is required")
    for name in modules:
        if (source / name).is_file() and (source / name).resolve() != (DEST / name).resolve():
            shutil.copyfile(source / name, DEST / name)
            (DEST / name).chmod(0o644)
    if (source / "web").is_dir() and (source / "web").resolve() != (DEST / "web").resolve():
        shutil.copytree(source / "web", DEST / "web", dirs_exist_ok=True)
        (DEST / "web").chmod(0o755)
        for file in (DEST / "web").rglob("*"):
            file.chmod(0o755 if file.is_dir() else 0o644)


RUNTIME = Path("/opt/rolypolyops/agent-runtime")
HELPER = "python:3.12-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337"


def output(args):
    result = subprocess.run(args, check=True, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    return result.stdout.strip()


def version_tuple(value):
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", value)
    if not match:
        raise ValueError("prerequisite_version_unavailable")
    return tuple(int(x or 0) for x in match.groups())


def supported_packages():
    values = {}
    try:
        lines = Path("/etc/os-release").read_text().splitlines()
    except OSError:
        return False
    for line in lines:
        if "=" in line:
            k, v = line.split("=", 1)
            values[k] = v.strip('"')
    return values.get("ID") in {"ubuntu", "debian"} and shutil.which("apt-get") is not None


def install_docker():
    """Bootstrap official packages only when no Docker installation exists."""
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k,v=line.split("=",1)
            values[k]=v.strip('"')
    distribution=values.get("ID")
    codename=values.get("UBUNTU_CODENAME") or values.get("VERSION_CODENAME", "")
    architecture=output(["dpkg","--print-architecture"])
    if distribution not in {"ubuntu","debian"} or not re.fullmatch(r"[a-z][a-z0-9-]{1,31}",codename) or architecture not in {"amd64","arm64","armhf","ppc64el","s390x"}:
        prerequisite_error("supported Ubuntu/Debian Docker packages")
    # Certificate-validated HTTPS to a fixed official origin. No shell, remote
    # install script, redirected key download, or existing-daemon replacement.
    with urllib.request.build_opener(NoRedirect()).open("https://download.docker.com/linux/"+distribution+"/gpg",timeout=30) as response:
        signing_key=response.read(65537)
    if len(signing_key)>65536 or not signing_key.startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"):
        prerequisite_error("official Docker repository signing key")
    key_directory=Path("/etc/apt/keyrings")
    key_directory.mkdir(exist_ok=True,mode=0o755)
    key_path=key_directory/"rolypolyops-docker.asc"
    if key_directory.is_symlink() or key_path.is_symlink():
        raise ValueError("Untrusted package signing-key path")
    key_path.write_bytes(signing_key);key_path.chmod(0o644)
    repo_path=Path("/etc/apt/sources.list.d/rolypolyops-docker.list")
    if repo_path.is_symlink():
        raise ValueError("Untrusted package repository path")
    repo_path.write_text("deb [arch="+architecture+" signed-by="+str(key_path)+"] https://download.docker.com/linux/"+distribution+" "+codename+" stable\n")
    repo_path.chmod(0o644)
    command(["apt-get","update"])
    command(["apt-get","install","-y","--no-upgrade","--no-install-recommends","docker-ce","docker-ce-cli","containerd.io","docker-buildx-plugin","docker-compose-plugin"])


def prerequisite_error(name):
    raise ValueError("Missing or unsupported prerequisite: " + name)


def agent_prerequisites():
    """Install only missing prerequisites; never replace a working Docker."""
    if sys.version_info < (3, 11):
        prerequisite_error("Python 3.11+")
    missing_docker = shutil.which("docker") is None
    missing_restic = shutil.which("restic") is None
    packages = supported_packages() if (missing_docker or missing_restic) else False
    if missing_docker and (Path("/var/run/docker.sock").exists() or shutil.which("dockerd")):
        prerequisite_error("Docker CLI (existing daemon preserved)")
    if missing_docker or missing_restic:
        if not packages:
            prerequisite_error("Docker 29+, Compose 2.24+, restic 0.16+")
        command(["apt-get", "update"])
        if missing_docker:
            install_docker()
        if missing_restic:
            command(["apt-get", "install", "-y", "--no-upgrade", "--no-install-recommends", "restic"])
    if version_tuple(output(["docker", "version", "--format", "{{.Server.Version}}"])) < (29, 0, 0):
        prerequisite_error("rootful Docker 29+ (existing installation preserved)")
    security = json.loads(output(["docker", "info", "--format", "{{json .SecurityOptions}}"]))
    if any("rootless" in item for item in security):
        prerequisite_error("rootful Docker")
    try:
        compose_version = output(["docker", "compose", "version", "--short"])
    except (OSError, subprocess.CalledProcessError):
        if not supported_packages():
            prerequisite_error("Compose 2.24+")
        command(["apt-get", "update"])
        command(["apt-get", "install", "-y", "--no-upgrade", "--no-install-recommends", "docker-compose-plugin"])
        compose_version = output(["docker", "compose", "version", "--short"])
    if version_tuple(compose_version) < (2, 24, 0):
        prerequisite_error("Compose 2.24+ (existing installation preserved)")
    if version_tuple(output(["restic", "version"])) < (0, 16, 0):
        prerequisite_error("restic 0.16+ (existing installation preserved)")
    python = sys.executable
    def libraries_ready(executable):
        try:
            versions = output([str(executable), "-c", "import cryptography, yaml; print(cryptography.__version__ + ' ' + yaml.__version__)"]).split()
            return len(versions) == 2 and version_tuple(versions[0]) >= (41, 0, 0) and version_tuple(versions[1]) >= (6, 0, 0)
        except (OSError, ValueError, subprocess.CalledProcessError):
            return False
    if not libraries_ready(python):
        if libraries_ready(RUNTIME / "bin/python3"):
            python = str(RUNTIME / "bin/python3")
        else:
            if not supported_packages():
                prerequisite_error("cryptography 41+ and PyYAML 6+")
            command(["apt-get", "update"])
            command(["apt-get", "install", "-y", "--no-upgrade", "--no-install-recommends", "python3-cryptography", "python3-yaml", "python3-venv"])
            if not libraries_ready(python):
                if RUNTIME.is_symlink():
                    raise ValueError("Untrusted agent runtime directory")
                command([sys.executable, "-m", "venv", str(RUNTIME)])
                python = str(RUNTIME / "bin/python3")
                command([python, "-m", "pip", "install", "--only-binary=:all:", "cryptography==46.0.5", "PyYAML==6.0.3"])
                if not libraries_ready(python):
                    prerequisite_error("cryptography 41+ and PyYAML 6+")
    # Pulling an immutable pinned helper is an installer-only action. Capture
    # and restore never pull; an existing working daemon is not restarted.
    try:
        output(["docker", "image", "inspect", HELPER])
    except subprocess.CalledProcessError:
        command(["docker", "pull", HELPER])
    return python


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
    parsed = checked_url(origin, {"", "/"})
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
    parsed = checked_url(controller_url, {"/ops", "/ops/"})
    runtime_python = agent_prerequisites()
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
ExecStart={runtime_python} {DEST}/agent.py --config {AGENT_CONFIG}
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
    except Exception as exc:
        if isinstance(exc, ValueError) and str(exc).startswith("Missing or unsupported prerequisite:"):
            print(str(exc), file=sys.stderr)
        print("Installation failed. Existing service data was preserved; check prerequisites and the enrollment code.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
