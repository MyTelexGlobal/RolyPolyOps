"""Dedicated HTTPS restic bindings, positive namespace checks and pinned CONNECT transport."""
import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class StorageError(Exception):
    def __init__(self, code, unknown=False):
        self.code, self.unknown = code, unknown
        super().__init__(code)


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(canonical(value) + b"\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if tmp.exists():
            tmp.unlink()


def read(path, default=None):
    try:
        path = Path(path)
        if path.is_symlink() or path.stat().st_mode & 0o077:
            raise StorageError("unsafe_state_permissions")
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        return default
    except (ValueError, OSError):
        raise StorageError("state_corrupt") from None


def _uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def validate_metadata(metadata):
    if not isinstance(metadata, dict) or set(metadata) - {"id", "name", "kind", "endpoint", "bucket", "prefix", "region"}:
        raise StorageError("invalid_storage")
    if not _uuid(metadata.get("id")) or (not isinstance(metadata.get("kind"), str) or metadata.get("kind") not in {"rest", "s3"}):
        raise StorageError("invalid_storage")
    if not isinstance(metadata.get("name"), str) or not 1 <= len(metadata["name"]) <= 100 or any(ord(c) < 32 or ord(c) == 127 for c in metadata["name"]):
        raise StorageError("invalid_storage")
    endpoint = metadata.get("endpoint", "")
    if not isinstance(endpoint, str) or len(endpoint) > 2048 or any(ord(x) < 33 or ord(x) == 127 for x in endpoint):
        raise StorageError("invalid_storage_endpoint")
    try:
        url = urllib.parse.urlsplit(endpoint)
        port = url.port or 443
    except ValueError:
        raise StorageError("invalid_storage_endpoint") from None
    if (url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None
            or url.query or url.fragment or port < 1 or port > 65535
            or "\\" in endpoint or "%" in url.netloc or url.hostname.endswith(".")
            or any(p in {".", ".."} for p in urllib.parse.unquote(url.path).split("/"))):
        raise StorageError("invalid_storage_endpoint")
    if metadata["kind"] == "s3":
        if url.path not in {"", "/"} or (not isinstance(metadata.get("bucket"), str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", metadata["bucket"])):
            raise StorageError("invalid_storage_bucket")
        prefix = metadata.get("prefix", "")
        if (not isinstance(prefix, str) or len(prefix) > 512 or prefix.startswith("/") or "\\" in prefix
                or any(ord(c) < 32 or ord(c) == 127 for c in prefix) or (prefix and any(x in {".", ".."} for x in prefix.rstrip("/").split("/")))):
            raise StorageError("invalid_storage_prefix")
        if not isinstance(metadata.get("region", "us-east-1"), str) or not re.fullmatch(r"[a-z0-9-]{1,64}", metadata.get("region", "us-east-1")):
            raise StorageError("invalid_storage_region")
    elif any(k in metadata for k in ("bucket", "prefix", "region")):
        raise StorageError("invalid_storage")
    return url.hostname, port


def public_addresses(host, port):
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        values = sorted({item[4][0] for item in answers})
        # Refuse mixed public/private answers rather than selecting a convenient address.
        def allowed(value):
            address = ipaddress.ip_address(value)
            return address.is_global and not (address.is_multicast or address.is_unspecified or address.is_reserved or address.is_loopback or address.is_link_local or address.is_private)
        if not values or any(not allowed(value) for value in values):
            raise StorageError("storage_address_forbidden")
        return values
    except (socket.gaierror, ValueError):
        raise StorageError("storage_dns_failed") from None


class _Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = True


class _Connect(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_CONNECT(self):
        proxy = self.server
        if self.path.lower() != proxy.authority.lower() or self.headers.get("Proxy-Authorization") != proxy.auth:
            self.send_error(403)
            return
        remote = None
        try:
            addresses = public_addresses(proxy.host, proxy.port)
            # Numeric connect pins this connection; TLS retains the original authority/SNI.
            for address in addresses:
                try:
                    remote = socket.create_connection((address, proxy.port), timeout=10)
                    break
                except OSError:
                    continue
            if remote is None:
                raise OSError()
            self.send_response(200, "Connection Established")
            self.end_headers()
            self.connection.settimeout(60)
            deadline = time.monotonic() + 7200
            while time.monotonic() < deadline:
                readable, _, _ = select.select([self.connection, remote], [], [], 30)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (remote if source is self.connection else self.connection).sendall(data)
        except (OSError, StorageError):
            return
        finally:
            if remote:
                remote.close()

    def do_GET(self):
        self.send_error(403)

    do_POST = do_PUT = do_DELETE = do_HEAD = do_GET


@contextlib.contextmanager
def transport(metadata):
    host, port = validate_metadata(metadata)
    public_addresses(host, port)
    token = uuid.uuid4().hex + uuid.uuid4().hex
    server = _Proxy(("127.0.0.1", 0), _Connect)
    server.host, server.port = host, port
    server.authority = ("[" + host + "]" if ":" in host else host) + ":" + str(port)
    server.auth = "Basic " + base64.b64encode(("rpo:" + token).encode()).decode()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://rpo:" + token + "@127.0.0.1:" + str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        raise StorageError("storage_redirect_forbidden")


def _request(url, headers, proxy, *, allow_missing=False):
    # ProxyHandler observes process no_proxy. Explicitly use the HTTPS tunnel to avoid that bypass.
    parsed = urllib.parse.urlsplit(proxy)
    origin = urllib.parse.urlsplit(url)
    import http.client
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=30, context=ssl.create_default_context())
    auth = "Basic " + base64.b64encode((parsed.username + ":" + parsed.password).encode()).decode()
    connection.set_tunnel(origin.hostname, origin.port or 443, headers={"Proxy-Authorization": auth})
    try:
        path = urllib.parse.urlunsplit(("", "", origin.path or "/", origin.query, ""))
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        if allow_missing and response.status == 404:
            response.read(4096)
            return None
        if response.status != 200:
            raise StorageError("storage_listing_failed")
        data = response.read(8 * 1024 * 1024 + 1)
        if len(data) > 8 * 1024 * 1024:
            raise StorageError("storage_listing_incomplete")
        return data
    except (OSError, ssl.SSLError, http.client.HTTPException):
        raise StorageError("storage_transport_failed") from None
    finally:
        connection.close()


def _s3_headers(url, credentials, region, moment=None):
    moment = moment or dt.datetime.now(dt.timezone.utc)
    stamp, day = moment.strftime("%Y%m%dT%H%M%SZ"), moment.strftime("%Y%m%d")
    parsed = urllib.parse.urlsplit(url)
    headers = {"host": parsed.netloc, "x-amz-date": stamp, "x-amz-content-sha256": hashlib.sha256(b"").hexdigest()}
    if credentials.get("sessionToken"):
        headers["x-amz-security-token"] = credentials["sessionToken"]
    names = ";".join(sorted(headers))
    query = "&".join(k + "=" + v for k, v in sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    # parse_qsl decodes; AWS requires re-encoding each key/value separately.
    query = "&".join(urllib.parse.quote(k, safe="-_.~") + "=" + urllib.parse.quote(v, safe="-_.~")
                     for k, v in sorted(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)))
    request = "GET\n" + parsed.path + "\n" + query + "\n" + "".join(k + ":" + headers[k].strip() + "\n" for k in sorted(headers)) + "\n" + names + "\n" + headers["x-amz-content-sha256"]
    scope = day + "/" + region + "/s3/aws4_request"
    sign = "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hashlib.sha256(request.encode()).hexdigest()
    key = ("AWS4" + credentials["secretAccessKey"]).encode()
    for value in (day, region, "s3", "aws4_request"):
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, sign.encode(), hashlib.sha256).hexdigest()
    headers["authorization"] = "AWS4-HMAC-SHA256 Credential=" + credentials["accessKeyId"] + "/" + scope + ", SignedHeaders=" + names + ", Signature=" + signature
    return headers


def prove_empty(metadata, credentials, proxy):
    """Positive exact namespace listing. Errors, forbidden and partial listings fail closed."""
    if metadata["kind"] == "rest":
        auth = "Basic " + base64.b64encode((credentials["username"] + ":" + credentials["password"]).encode()).decode()
        headers = {"Authorization": auth, "Accept": "application/vnd.x.restic.rest.v2"}
        root = metadata["endpoint"].rstrip("/")
        if _request(root + "/config", headers, proxy, allow_missing=True) is not None:
            raise StorageError("storage_namespace_not_empty")
        for kind in ("data", "index", "keys", "locks", "snapshots"):
            raw = _request(root + "/" + kind + "/", headers, proxy, allow_missing=True)
            if raw is None:
                continue
            try:
                entries = json.loads(raw)
            except (ValueError, TypeError):
                raise StorageError("storage_listing_incomplete") from None
            if not isinstance(entries, list):
                raise StorageError("storage_listing_incomplete")
            if entries:
                raise StorageError("storage_namespace_not_empty")
    else:
        prefix = metadata["prefix"].rstrip("/") + "/"
        token, seen = None, set()
        # Full ListObjectsV2 pagination. No max-keys=1 shortcut / unchecked truncation.
        for page in range(10000):
            params = {"list-type": "2", "prefix": prefix}
            if token:
                params["continuation-token"] = token
            url = metadata["endpoint"].rstrip("/") + "/" + metadata["bucket"] + "?" + urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
            raw = _request(url, _s3_headers(url, credentials, metadata.get("region", "us-east-1")), proxy)
            try:
                root = ET.fromstring(raw)
                # Only the documented response root counts as a successful listing.
                if root.tag.rsplit("}", 1)[-1] != "ListBucketResult":
                    raise ValueError()
                def get(name):
                    values = [e.text for e in root if e.tag.rsplit("}", 1)[-1] == name]
                    return values[0] if len(values) == 1 else None
                if any(e.tag.rsplit("}", 1)[-1] == "Contents" for e in root):
                    raise StorageError("storage_namespace_not_empty")
                if get("Prefix") != prefix or get("Name") != metadata["bucket"]:
                    raise ValueError()
                truncated = get("IsTruncated")
                if truncated == "false":
                    break
                if truncated != "true":
                    raise ValueError()
                token = get("NextContinuationToken")
                if not token or token in seen:
                    raise ValueError()
                seen.add(token)
            except (ET.ParseError, ValueError):
                raise StorageError("storage_listing_incomplete") from None
        else:
            raise StorageError("storage_listing_incomplete")
    return {"namespaceDigest": hashlib.sha256(canonical(metadata)).hexdigest(), "checkedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "complete": True}


class StorageManager:
    def __init__(self, state, sealer):
        self.state, self.sealer = Path(state), sealer
        self.directory = self.state / "storages"
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)

    def binding(self, storage_id):
        if not _uuid(storage_id):
            raise StorageError("invalid_storage_id")
        value = read(self.directory / (storage_id + ".json"))
        if not value or value.get("status") != "connected":
            raise StorageError("storage_not_connected")
        return value

    @contextlib.contextmanager
    def session(self, binding):
        metadata, credentials = binding["metadata"], binding["credentials"]
        with transport(metadata) as proxy:
            env = {"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(self.state),
                   "HTTPS_PROXY": proxy, "HTTP_PROXY": proxy, "https_proxy": proxy, "http_proxy": proxy,
                   "NO_PROXY": "", "no_proxy": "", "RESTIC_PASSWORD_FILE": str(self.directory / (metadata["id"] + ".password"))}
            if metadata["kind"] == "rest":
                env.update(RESTIC_REPOSITORY="rest:" + metadata["endpoint"], RESTIC_REST_USERNAME=credentials["username"], RESTIC_REST_PASSWORD=credentials["password"])
            else:
                env.update(RESTIC_REPOSITORY="s3:" + metadata["endpoint"].rstrip("/") + "/" + metadata["bucket"] + "/" + metadata["prefix"],
                           AWS_ACCESS_KEY_ID=credentials["accessKeyId"], AWS_SECRET_ACCESS_KEY=credentials["secretAccessKey"],
                           AWS_DEFAULT_REGION=metadata.get("region", "us-east-1"))
                if credentials.get("sessionToken"):
                    env["AWS_SESSION_TOKEN"] = credentials["sessionToken"]
            yield env, proxy

    def _password(self, storage_id, password):
        path = self.directory / (storage_id + ".password")
        # Password may contain newlines: restic's password-file reads the first line, so reject explicitly.
        if "\n" in password or "\r" in password or "\x00" in password:
            raise StorageError("invalid_repository_password")
        tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as out:
            out.write(password + "\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        d = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
        try:
            os.fsync(d)
        finally:
            os.close(d)

    def run(self, binding, args, *, timeout=7200, cwd=None, init=False, input_file=None, output_file=None, output_limit=None):
        with self.session(binding) as (env, _):
            return self._run(env, args, timeout=timeout, cwd=cwd, init=init, input_file=input_file, output_file=output_file, output_limit=output_limit)

    def _run(self, env, args, *, timeout=7200, cwd=None, init=False, input_file=None, output_file=None, output_limit=None):
        incoming = open(input_file, "rb") if input_file else None
        outgoing = None
        try:
            if output_file:
                outgoing = os.fdopen(os.open(output_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")
            def limits():
                if output_limit:
                    import resource
                    resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
            completed = subprocess.run(["restic", "--no-cache", *args], env=env, cwd=cwd, stdin=incoming or subprocess.DEVNULL,
                                       stdout=outgoing or subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                                       preexec_fn=limits if output_limit else None)
            if outgoing:
                outgoing.flush()
                os.fsync(outgoing.fileno())
        except subprocess.TimeoutExpired:
            raise StorageError("repository_timeout", unknown=init or args[0] == "backup") from None
        except OSError:
            raise StorageError("restic_unavailable") from None
        finally:
            if incoming:
                incoming.close()
            if outgoing:
                outgoing.close()
        if completed.returncode:
            raise StorageError("repository_access_failed", unknown=False)
        if output_file:
            return b""
        if len(completed.stdout) > 16 * 1024 * 1024:
            raise StorageError("repository_result_limit")
        return completed.stdout

    def _config(self, env):
        try:
            value = json.loads(self._run(env, ["cat", "config"], timeout=45))
            identity = value["id"]
            if not re.fullmatch(r"[a-f0-9]{64}", identity):
                raise ValueError()
            return identity
        except (ValueError, KeyError, TypeError):
            raise StorageError("repository_identity_unverified") from None

    def configure(self, operation_id, params):
        storage_id, mode, envelope = params["storageId"], params["mode"], params["envelope"]
        discover = params.get("discoverRepositoryId") is True
        if "discoverRepositoryId" in params and (not discover or mode != "attach" or "expectedRepositoryId" in params):
            raise StorageError("invalid_repository_discovery")
        if "metadata" not in params:
            raise StorageError("approved_metadata_required")
        validate_metadata(params["metadata"])
        inner = self.sealer.open(envelope, storage_id=storage_id, mode=mode, metadata=params["metadata"])
        metadata = inner["metadata"]
        validate_metadata(metadata)
        credentials = inner["credentials"]
        required = {"username", "password"} if metadata["kind"] == "rest" else {"accessKeyId", "secretAccessKey"}
        optional = set() if metadata["kind"] == "rest" else {"sessionToken"}
        if not required <= set(credentials) or set(credentials) - required - optional or any(not isinstance(v, str) or len(v) > 4096 or any(c in v for c in "\x00\r\n") for v in credentials.values()):
            raise StorageError("invalid_storage_credentials")
        path = self.directory / (storage_id + ".json")
        previous = read(path, {})
        generation, request_id = inner["bindingGeneration"], inner["requestId"]
        if generation <= previous.get("bindingGeneration", 0) or request_id in previous.get("consumedRequests", []):
            raise StorageError("binding_generation_stale")
        if previous.get("status") == "init_pending":
            raise StorageError("binding_outcome_unknown", unknown=True)
        if mode == "create":
            namespace = metadata["endpoint"].rstrip("/").rsplit("/", 1)[-1] if metadata["kind"] == "rest" else metadata["prefix"].rstrip("/").rsplit("/", 1)[-1]
            if namespace != storage_id:
                raise StorageError("storage_namespace_mismatch")
        expected = params.get("expectedRepositoryId")
        authoritative = previous.get("repositoryId") or previous.get("expectedRepositoryId") or previous.get("authoritativeRepositoryId")
        if mode == "attach":
            if discover:
                if authoritative:
                    raise StorageError("expected_repository_required")
            elif not isinstance(expected, str) or not re.fullmatch(r"[a-f0-9]{64}", expected):
                raise StorageError("expected_repository_required")
            if authoritative and expected != authoritative:
                raise StorageError("repository_identity_mismatch")
        self._password(storage_id, inner["repoPassword"])
        salt = os.urandom(32)
        binding = {"metadata": metadata, "credentials": credentials, "bindingGeneration": generation, "requestId": request_id,
                   "operationId": operation_id, "mode": mode, "status": "accepted", "expectedRepositoryId": expected,
                   "authoritativeRepositoryId": authoritative, "discoverRepositoryId": discover,
                   "consumedRequests": (previous.get("consumedRequests", []) + [request_id]),
                   "passwordSalt": salt.hex(), "passwordVerifier": hashlib.scrypt(inner["repoPassword"].encode(), salt=salt, n=16384, r=8, p=1).hex()}
        # Acceptance and generation are durable even if the following probe fails.
        atomic(path, binding)
        with self.session(binding) as (env, proxy):
            if mode == "create":
                proof = prove_empty(metadata, credentials, proxy)
                binding.update(status="init_pending", emptyProof=proof)
                atomic(path, binding)
                try:
                    self._run(env, ["init", "--repository-version", "2"], timeout=120, init=True)
                except StorageError as error:
                    # Never second-init: even a nonzero exit can follow a completed remote write.
                    raise StorageError("repository_init_unknown", unknown=True) from None
            try:
                identity = self._config(env)
            except StorageError:
                if mode == "create":
                    raise StorageError("repository_init_unknown", unknown=True) from None
                raise
        if expected is not None and identity != expected:
            raise StorageError("repository_identity_mismatch")
        binding.update(status="connected", repositoryId=identity)
        atomic(path, binding)
        return self.safe(binding)

    def reconcile(self, operation_id):
        for path in self.directory.glob("*.json"):
            value = read(path)
            if value.get("operationId") != operation_id:
                continue
            if value.get("status") == "connected":
                return {"status": "succeeded", "result": self.safe(value)}
            if value.get("status") == "init_pending" and value.get("emptyProof", {}).get("complete") is True:
                try:
                    # Attach verification is inspection; never repeats init.
                    with self.session(value) as (env, _):
                        identity = self._config(env)
                    expected = value.get("repositoryId") or value.get("expectedRepositoryId")
                    if expected and identity != expected:
                        raise StorageError("repository_identity_mismatch")
                    password = (self.directory / (value["metadata"]["id"] + ".password")).read_text().removesuffix("\n")
                    actual = hashlib.scrypt(password.encode(), salt=bytes.fromhex(value["passwordSalt"]), n=16384, r=8, p=1).hex()
                    if not hmac.compare_digest(actual, value["passwordVerifier"]):
                        raise StorageError("binding_proof_mismatch")
                    value.update(status="connected", repositoryId=identity)
                    atomic(path, value)
                    return {"status": "succeeded", "result": self.safe(value)}
                except (StorageError, OSError, ValueError):
                    return {"status": "outcome_unknown", "error": "repository_init_unknown"}
            return {"status": "failed", "error": "storage_not_connected"}
        return None

    @staticmethod
    def safe(value):
        return {"storageId": value["metadata"]["id"], "repositoryId": value["repositoryId"], "connected": True,
                "bindingGeneration": value["bindingGeneration"], "requestId": value["requestId"]}
