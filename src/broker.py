#!/usr/bin/env python3
"""Local project catalog and credential broker. No raw credential export API."""
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import resource
import signal
import socket
import socketserver
import struct
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import generic_api
import google_migration
import google_search_console

VERSION = "0.6.0"
MAX_MESSAGE = 1024 * 1024
MAX_RESPONSE = 4 * 1024 * 1024
SLUG = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
PART = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
RESOURCE = r"[A-Za-z0-9_-]{1,64}"
SENSITIVE = re.compile(r"token|secret|password|authorization|private.?key|api.?key|auth.?key", re.I)


class BrokerError(Exception):
    def __init__(self, code, message, status=None):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_json(url, method="GET", data=None, headers=None):
    request = urllib.request.Request(url, method=method, headers=headers or {},
        data=None if data is None else json.dumps(data).encode())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            status, raw = response.status, response.read(MAX_RESPONSE + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(MAX_RESPONSE + 1)
    except (OSError, urllib.error.URLError):
        raise BrokerError("upstream_unavailable", "The upstream service could not be reached.") from None
    if len(raw) > MAX_RESPONSE:
        raise BrokerError("response_too_large", "The upstream response exceeded the size limit.")
    try:
        return status, json.loads(raw or b"{}")
    except (ValueError, UnicodeError):
        raise BrokerError("invalid_upstream_response", "The upstream did not return valid JSON.", status) from None


def safe_name(value):
    if not isinstance(value, str) or not value or len(value) > 512:
        raise BrokerError("invalid_name", "Use a credential name relative to the project's secret directory.")
    if not all(PART.fullmatch(part) and part not in (".", "..") for part in value.split("/")):
        raise BrokerError("invalid_name", "The credential name is invalid.")
    return value


def sanitize(value, secret=None):
    if isinstance(value, dict):
        if isinstance(value.get("name"), str) and SENSITIVE.search(value["name"]) and "value" in value:
            value = {**value, "value": "[REDACTED]"}
        return {key: "[REDACTED]" if SENSITIVE.search(str(key)) else sanitize(item, secret)
                for key, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, secret) for item in value]
    if isinstance(value, str) and secret:
        return value.replace(secret, "[REDACTED]")
    return value


class OpenBao:
    def __init__(self, address, credentials, kv_mount="secret", auth_mount="approle"):
        self.address = address.rstrip("/")
        self.credentials = credentials
        self.kv_mount = kv_mount
        self.auth_mount = auth_mount
        self.token = None
        self.expires = 0
        self.lock = threading.RLock()

    def _call(self, path, method="GET", data=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["X-Vault-Token"] = token
        return http_json(self.address + "/v1/" + path, method, data, headers)

    def _authenticate(self):
        with self.lock:
            if self.token and self.expires > time.monotonic() + 90:
                return self.token
            if self.token:
                status, result = self._call("auth/token/renew-self", "POST", {"increment": "1h"}, self.token)
                if status == 200 and result.get("auth", {}).get("lease_duration", 0) > 90:
                    self.expires = time.monotonic() + result["auth"]["lease_duration"]
                    return self.token
                self._call("auth/token/revoke-self", "POST", {}, self.token)
                self.token = None
            login = {key: self.credentials[key] for key in ("role_id", "secret_id")}
            status, result = self._call("auth/" + self.auth_mount + "/login", "POST", login)
            if status != 200 or not result.get("auth", {}).get("client_token"):
                raise BrokerError("enrollment_invalid", "The service identity could not authenticate to OpenBao.", status)
            self.token = result["auth"]["client_token"]
            self.expires = time.monotonic() + result["auth"]["lease_duration"]
            return self.token

    def call(self, path, method="GET", data=None):
        token = self._authenticate()
        status, result = self._call(path, method, data, token)
        if status in (401, 403):
            if status == 403 and self._call("auth/token/lookup-self", token=token)[0] == 200:
                return status, result
            # One retry handles externally revoked/expired sessions. It cannot
            # turn denied permissions into administrator access.
            with self.lock:
                if self.token == token:
                    self.token, self.expires = None, 0
            status, result = self._call(path, method, data, self._authenticate())
        return status, result

    def close(self):
        with self.lock:
            if self.token:
                try:
                    self._call("auth/token/revoke-self", "POST", {}, self.token)
                except BrokerError:
                    pass
                self.token = None


class Broker:
    def __init__(self, config_path, credentials, logger=None):
        self.config_path = Path(config_path)
        self.credentials = credentials
        self.clients = {}
        self.lock = threading.Lock()
        self.logger = logger or logging.getLogger("project-access")
        self.api = generic_api.ApiProxy()
        self.google = google_migration.GoogleMigration()
        self.search_console = google_search_console.GoogleSearchConsole()

    def config(self):
        try:
            config = json.loads(self.config_path.read_text())
        except (ValueError, OSError):
            raise BrokerError("configuration_unavailable", "The broker configuration is unavailable.") from None
        validate_config(config)
        return config

    def client(self, project, config):
        with self.lock:
            if project not in self.credentials:
                raise BrokerError("project_not_enrolled", "The project does not have an enrolled service identity.")
            if project not in self.clients:
                self.clients[project] = OpenBao(config["openbao_address"], self.credentials[project],
                                               config.get("kv_mount", "secret"),
                                               config.get("auth_mount", "approle"))
            return self.clients[project]

    def allowed(self, uid, config):
        return {name: project for name, project in config.get("projects", {}).items()
                if project.get("enabled", False) and (uid == 0 or uid in project.get("allowed_uids", []))}

    def project(self, uid, request):
        config = self.config()
        name = request.get("project")
        allowed = self.allowed(uid, config)
        if name not in allowed:
            raise BrokerError("project_access_denied", "This Unix identity is not granted access to that project.")
        return name, allowed[name], self.client(name, config)

    def read(self, client, prefix, name):
        status, response = client.call(client.kv_mount + "/data/" + prefix + "/" + safe_name(name))
        if status == 404:
            raise BrokerError("credential_missing", "The credential is not currently present in this project's OpenBao directory.", status)
        if status != 200:
            raise BrokerError("credential_access_denied", "The service cannot read that credential.", status)
        return response["data"]

    def entry(self, client, project, name):
        try:
            record = self.read(client, project["secret_prefix"], name)
            fields = sorted(record["data"])
            return {"name": name, "status": "available", "fields": fields,
                    "version": record.get("metadata", {}).get("version"),
                    "api": self.api.describe(record["data"]),
                    "google_migration": google_migration.describe(record["data"]),
                    "google_search_console": google_search_console.describe(record["data"])}
        except BrokerError as error:
            if error.code in ("credential_missing", "credential_access_denied"):
                return {"name": name, "status": error.code}
            raise

    def catalog(self, project, client):
        prefix = project["secret_prefix"]
        pending, names = [""], set()
        while pending:
            directory = pending.pop()
            status, result = client.call(client.kv_mount + "/metadata/" + prefix + ("/" + directory if directory else "") + "?list=true")
            if status == 404:
                continue
            if status != 200:
                raise BrokerError("catalog_access_denied", "The service could not list this project's credential names.", status)
            for value in result.get("data", {}).get("keys", []):
                candidate = directory + value
                safe_name(candidate.rstrip("/"))
                if candidate.count("/") > 12 or len(names) + len(pending) > 200:
                    raise BrokerError("catalog_limit", "The catalog exceeded its traversal limit.")
                if value.endswith("/"):
                    pending.append(candidate)
                else:
                    names.add(candidate)
        for name in project.get("expected_credentials", []):
            names.add(safe_name(name))
        return [self.entry(client, project, name) for name in sorted(names)]

    def cloudflare_route(self, profile, method, path):
        if not isinstance(path, str) or len(path) > 512:
            raise BrokerError("route_denied", "Use an approved Cloudflare API path.")
        zones = set(profile["zones"].values())
        match = re.fullmatch(r"/zones/([a-f0-9]{32})/dns_records(?:/(" + RESOURCE + r"))?", path)
        if match:
            if match[1] not in zones or method not in ({"GET", "POST"} if not match[2] else {"GET", "PUT", "PATCH", "DELETE"}):
                raise BrokerError("route_denied", "That DNS resource or operation is outside the project grant.")
            return "dns"
        base = "/accounts/" + profile["account_id"]
        if path == base + "/cfd_tunnel" and method in ("GET", "POST"):
            return "tunnels"
        if re.fullmatch(re.escape(base) + r"/cfd_tunnel/" + RESOURCE, path) and method in ("GET", "DELETE"):
            return "tunnels"
        if re.fullmatch(re.escape(base) + r"/cfd_tunnel/" + RESOURCE + r"/configurations", path) and method in ("GET", "PUT"):
            return "tunnels"
        access = re.escape(base) + r"/access/(?:apps(?:/" + RESOURCE + r")?(?:/policies(?:/" + RESOURCE + r")?)?|policies(?:/" + RESOURCE + r")?)"
        if re.fullmatch(access, path) and method in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            return "access"
        raise BrokerError("route_denied", "That API path is outside the project's Cloudflare allowlist.")

    def cloudflare(self, project, client, request):
        profile = project.get("cloudflare")
        if not profile:
            raise BrokerError("provider_not_configured", "Cloudflare tools are not configured for this project.")
        method = request.get("method", "GET")
        path = request.get("path")
        category = self.cloudflare_route(profile, method, path)
        query = request.get("query", {})
        allowed_query = {"page", "per_page", "name", "type", "is_deleted", "match", "status", "domain", "search"}
        if not isinstance(query, dict) or set(query) - allowed_query or any(not isinstance(value, (str, int, bool)) for value in query.values()):
            raise BrokerError("query_denied", "The request contains unsupported query parameters.")
        body = request.get("body")
        if method == "GET" and body is not None:
            raise BrokerError("invalid_request", "Read operations cannot contain a request body.")
        if body is not None and not isinstance(body, dict):
            raise BrokerError("invalid_request", "The request body must be a JSON object.")
        if "[REDACTED]" in json.dumps(body):
            raise BrokerError("redacted_input", "Do not submit redacted configuration fields; use a request that preserves the existing protected values.")
        if category == "tunnels" and method == "POST" and body and body.get("config_src") != "cloudflare":
            raise BrokerError("invalid_request", "New tunnels must use remotely managed configuration: config_src=cloudflare.")
        record = self.read(client, project["secret_prefix"], profile["credential"])
        key = record["data"].get(profile.get("field", "api_token"))
        if not isinstance(key, str) or not key:
            raise BrokerError("credential_field_missing", "The Cloudflare credential has no usable API-token field.")
        url = "https://api.cloudflare.com/client/v4" + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        status, result = http_json(url, method, body, {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        if status >= 300 or result.get("success") is False:
            raise BrokerError("provider_request_failed", "Cloudflare rejected or could not complete the approved API request.", status)
        return {"http_status": status, "data": sanitize(result, key)}

    def dispatch(self, uid, request):
        if not isinstance(request, dict):
            raise BrokerError("invalid_request", "Send one JSON request object.")
        action = request.get("action")
        if action == "status":
            config = self.config()
            return {"version": VERSION, "status": "running", "identity": {"unix_uid": uid},
                    "projects": sorted(self.allowed(uid, config)), "raw_credential_export": False,
                    "authorization_boundary": "Unix identity; project names and repository folders do not grant access"}
        name, project, client = self.project(uid, request)
        if action == "catalog":
            return {"project": name, "credentials": self.catalog(project, client),
                    "secret_root": client.kv_mount + "/" + project["secret_prefix"],
                    "cloudflare": project.get("cloudflare"), "refreshed": True}
        if action == "check":
            credential = safe_name(request.get("name"))
            return {"project": name, "storage_path": client.kv_mount + "/" + project["secret_prefix"] + "/" + credential,
                    **self.entry(client, project, credential)}
        if action == "cloudflare":
            return self.cloudflare(project, client, request)
        if action == "api":
            credential = safe_name(request.get("credential"))
            record = self.read(client, project["secret_prefix"], credential)
            return self.api.request((name, credential), record["data"], request)
        if action == "google_search_console_read":
            credential = safe_name(request.get("credential"))
            record = self.read(client, project["secret_prefix"], credential)
            return self.search_console.execute((name, credential), record["data"], request)
        if action == "google_read":
            if request.get("operation") not in ("identity", "storage_list", "storage_object", "gmail_profile", "gmail_labels_list", "gmail_messages_list", "gmail_message_get", "gmail_drafts_list", "gmail_draft_get"):
                raise BrokerError("google_request_denied", "Use an approved read operation.")
            credential = safe_name(request.get("credential"))
            record = self.read(client, project["secret_prefix"], credential)
            if not self.google.transfer_slot.acquire(blocking=False):
                raise BrokerError("google_busy", "A Google transfer is in progress; retry this read later.")
            try:
                metadata, payload = self.google.execute((name, credential), record["data"], request, b"")
                if len(payload) > 2 * 1024 * 1024:
                    raise BrokerError("google_use_transfer", "Use the Google transfer CLI for this large response.")
                return {"http_status": metadata["http_status"], "data": json.loads(payload)}
            finally:
                self.google.transfer_slot.release()
        raise BrokerError("unsupported_action", "The requested broker operation is not supported.")

    def google_transfer(self, uid, request, reader, writer):
        """Length-framed payloads keep the ordinary MCP request limit unchanged."""
        started, acquired = time.monotonic(), False
        result = None
        try:
            if set(request) - {"action", "project", "credential", "operation", "params", "body_bytes"}:
                raise BrokerError("invalid_request", "Unsupported Google transfer fields.")
            name, project, client = self.project(uid, request)
            credential = safe_name(request.get("credential"))
            record = self.read(client, project["secret_prefix"], credential)
            config, _ = google_migration.profile(record["data"])
            size = request.get("body_bytes", 0)
            google_migration.route(config, request.get("operation"), request.get("params", {}), size)
            acquired = self.google.transfer_slot.acquire(blocking=False)
            if not acquired:
                raise BrokerError("google_busy", "A Google transfer is in progress; retry this operation later.")
            writer.write(b'{"ok":true,"ready":true}\n')
            writer.flush()
            body = reader.read(size)
            if len(body) != size:
                raise BrokerError("google_body_incomplete", "The upload ended before the declared length; no Google request was sent.")
            metadata, payload = self.google.execute((name, credential), record["data"], request, body)
            result = {"ok": True, "result": metadata}
            writer.write(json.dumps(result).encode() + b"\n")
            writer.write(payload)
            writer.flush()
        except (BrokerError, generic_api.ApiError) as error:
            result = {"ok": False, "error": {"code": error.code, "message": error.message}}
            if error.status is not None:
                result["error"]["http_status"] = error.status
        except Exception:
            result = {"ok": False, "error": {"code": "google_transfer_uncertain", "message": "The transfer was interrupted. Reconcile writes before retrying."}}
        finally:
            if acquired:
                self.google.transfer_slot.release()
        if result and not result["ok"]:
            try:
                writer.write(json.dumps(result).encode() + b"\n")
                writer.flush()
            except OSError:
                pass
        audit = {"unix_uid": uid, "action": "google_transfer", "ok": bool(result and result["ok"]), "duration_ms": round((time.monotonic() - started) * 1000)}
        if result and not result["ok"]:
            audit["error"] = result["error"]["code"]
        self.logger.info(json.dumps(audit, separators=(",", ":")))

    def handle(self, uid, request):
        started = time.monotonic()
        try:
            result = {"ok": True, "result": self.dispatch(uid, request)}
        except (BrokerError, generic_api.ApiError) as error:
            result = {"ok": False, "error": {"code": error.code, "message": error.message}}
            if error.status is not None:
                result["error"]["http_status"] = error.status
        except Exception:
            result = {"ok": False, "error": {"code": "internal_error", "message": "The broker could not complete the request."}}
        # No request body, upstream response, credential, query, or token is logged.
        audit = {"unix_uid": uid, "ok": result["ok"], "duration_ms": round((time.monotonic() - started) * 1000)}
        if isinstance(request, dict):
            for key in ("action", "project", "method"):
                value = request.get(key)
                if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
                    audit[key] = value
        if not result["ok"]:
            audit["error"] = result["error"]["code"]
        self.logger.info(json.dumps(audit, separators=(",", ":")))
        return result

    def close(self):
        for client in self.clients.values():
            client.close()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(45)
        _, uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        line = self.rfile.readline(MAX_MESSAGE + 1)
        if len(line) > MAX_MESSAGE or not line.endswith(b"\n"):
            return
        try:
            request = json.loads(line)
        except (ValueError, UnicodeError):
            return
        if isinstance(request, dict) and request.get("action") == "google_transfer":
            self.connection.settimeout(240)
            self.server.broker.google_transfer(uid, request, self.rfile, self.wfile)
            return
        result = self.server.broker.handle(uid, request)
        self.wfile.write(json.dumps(result).encode() + b"\n")


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


def validate_config(config):
    """Reject malformed enrollment and unsafe vault destinations before login."""
    try:
        if not isinstance(config, dict) or type(config.get("schema_version")) is not int or config["schema_version"] != 1:
            raise ValueError()
        address = config["openbao_address"]
        if not isinstance(address, str) or any(c.isspace() for c in address):
            raise ValueError()
        parsed = urllib.parse.urlsplit(address)
        if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or parsed.scheme not in ("https", "http")
                or (parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1", "localhost"))):
            raise ValueError()
        parsed.port  # Validate a supplied port.
        for field, default in (("kv_mount", "secret"), ("auth_mount", "approle")):
            safe_name(config.get(field, default))
        projects = config["projects"]
        if not isinstance(projects, dict):
            raise ValueError()
        for name, project in projects.items():
            if not SLUG.fullmatch(name) or not isinstance(project, dict):
                raise ValueError()
            if type(project.get("enabled", False)) is not bool:
                raise ValueError()
            uids = project.get("allowed_uids", [])
            if not isinstance(uids, list) or any(type(uid) is not int or not 0 <= uid < 2**32 - 1 for uid in uids):
                raise ValueError()
            safe_name(project["secret_prefix"])
    except (ValueError, TypeError, KeyError, BrokerError):
        raise BrokerError("configuration_invalid", "The broker configuration is invalid.") from None


def read_credentials(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r", encoding="utf-8") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("The service credentials must be an owner-only regular file.")
        raw = source.read(MAX_MESSAGE + 1)
    if len(raw) > MAX_MESSAGE:
        raise ValueError("The service credentials exceed the size limit.")
    credentials = json.loads(raw)["projects"]
    if not isinstance(credentials, dict):
        raise ValueError("Invalid service credentials.")
    for name, registration in credentials.items():
        if (not SLUG.fullmatch(name) or not isinstance(registration, dict)
                or any(not isinstance(registration.get(key), str) or not registration[key]
                       for key in ("role_id", "secret_id"))):
            raise ValueError("Invalid service credentials.")
    return credentials


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    credential_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    defaults = {"config": os.environ.get("PROJECT_BROKER_CONFIG"),
                "socket": os.environ.get("PROJECT_ACCESS_SOCKET"),
                "credentials": os.environ.get("PROJECT_BROKER_CREDENTIALS") or
                    (str(Path(credential_dir) / "approle") if credential_dir else None),
                "audit": os.environ.get("PROJECT_BROKER_AUDIT")}
    for name, default in defaults.items():
        parser.add_argument("--" + name, default=default, required=not default)
    args = parser.parse_args(argv)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        credentials = read_credentials(args.credentials)
        broker = Broker(args.config, credentials)
        config = broker.config()
        path = Path(args.socket)
        # Never replace another service's socket or an unrelated file. Operators
        # remove a stale socket only after verifying its process has stopped.
        if path.exists() or path.is_symlink():
            raise ValueError("The socket path already exists.")
        logger = logging.getLogger("project-access")
        logger.setLevel(logging.INFO)
        logger.addHandler(RotatingFileHandler(args.audit, maxBytes=5 * 1024 * 1024, backupCount=5))
        server = Server(args.socket, Handler)
    except (OSError, ValueError, KeyError, TypeError, BrokerError):
        parser.exit(1, "Broker startup failed: check private configuration, permissions and socket availability.\n")
    server.broker = broker
    try:
        os.chmod(args.socket, 0o600)
        permitted = sorted({uid for project in config["projects"].values()
                            if project.get("enabled", False) for uid in project.get("allowed_uids", [])
                            if uid not in (0, os.geteuid())})
        if permitted:
            subprocess.run(["setfacl", "-m", ",".join("u:" + str(uid) + ":rw" for uid in permitted), args.socket],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        notify = os.environ.get("NOTIFY_SOCKET")
        if notify:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as ready:
                ready.connect("\0" + notify[1:] if notify.startswith("@") else notify)
                ready.sendall(b"READY=1")
        def stop(*_):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        broker.close()
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
