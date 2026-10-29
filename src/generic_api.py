"""Declarative HTTPS credential use. Profiles are written by OpenBao owners."""
import base64
import hashlib
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.parse

LIMIT = 4 * 1024 * 1024
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")
FIELD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
SENSITIVE = re.compile(r"token|secret|password|authorization|private.?key|api.?key|auth.?key|credential|^key$", re.I)
ROUTING_HEADERS = {"host", "connection", "content-length", "transfer-encoding", "upgrade", "expect",
                   "proxy-authorization", "proxy-connection", "te", "trailer"}
RESERVED_HEADERS = ROUTING_HEADERS | {"authorization", "cookie", "content-type", "accept-encoding"}


class ApiError(Exception):
    def __init__(self, code, message, status=None):
        self.code, self.message, self.status = code, message, status
        super().__init__(message)


def fail(code="api_profile_invalid", message="The credential's _http profile is invalid."):
    raise ApiError(code, message)


def clean_path(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 4096:
        fail("api_path_denied", "Use a path relative to the credential's API base URL.")
    current = value
    for _ in range(5):
        if any(ord(c) < 32 or ord(c) == 127 for c in current) or any(c in current for c in ("\\", "?", "#", ";")) or "//" in current:
            fail("api_path_denied", "The API path contains an unsafe component.")
        if any(part in (".", "..") for part in current.split("/")):
            fail("api_path_denied", "Path traversal is not permitted.")
        try:
            decoded = urllib.parse.unquote(current, errors="strict")
        except (ValueError, UnicodeError):
            fail("api_path_denied", "The API path encoding is invalid.")
        if decoded == current:
            return current
        current = decoded
    fail("api_path_denied", "The API path encoding is nested too deeply.")


def destination(value, token=False):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in value):
        fail()
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
        host = parsed.hostname
        if parsed.scheme != "https" or not host or parsed.username is not None or parsed.password is not None or port not in (None, 443):
            fail()
        if parsed.query or parsed.fragment or "\\" in value or host.endswith("."):
            fail()
        host = host.encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host or ".." in host:
            fail()
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            fail()
        path = parsed.path or "/"
        clean_path(path)
        if token and path == "/":
            fail()
        return "https://" + host + (path.rstrip("/") if not token else path)
    except (ValueError, UnicodeError):
        fail()


def header_name(value):
    if not isinstance(value, str) or not HEADER.fullmatch(value) or value.lower() in ROUTING_HEADERS:
        fail()
    return value


def header_value(value):
    if not isinstance(value, str) or len(value) > 16384 or any(ord(c) < 32 or ord(c) > 126 for c in value):
        fail("api_credential_invalid", "An API credential or header is not usable as an HTTP header.")
    return value


def field(data, name):
    if not isinstance(name, str) or not FIELD.fullmatch(name) or name == "_http":
        fail()
    value = data.get(name)
    if not isinstance(value, str) or not value or len(value) > 16384:
        fail("api_credential_field_missing", "A field required by the API authentication profile is missing or invalid.")
    return value


def public_addresses(host):
    try:
        addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
    except OSError:
        fail("api_upstream_unavailable", "The API hostname could not be resolved.")
    if not addresses or any(not ipaddress.ip_address(address).is_global or ipaddress.ip_address(address).is_multicast for address in addresses):
        fail("api_destination_denied", "Generic API credentials may be sent only to public HTTPS services on port 443.")
    return sorted(addresses, key=lambda address: ":" in address)


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address):
        super().__init__(host, port=443, timeout=30, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        raw = socket.create_connection((self.address, 443), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def exchange(url, method, headers, body=None):
    parsed = urllib.parse.urlsplit(url)
    addresses = public_addresses(parsed.hostname)
    connection = PinnedHTTPS(parsed.hostname, addresses[0])
    try:
        connection.request(method, (parsed.path or "/") + ("?" + parsed.query if parsed.query else ""), body, headers)
        response = connection.getresponse()
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            fail("api_response_too_large", "The API response exceeded the size limit.")
        if 300 <= response.status < 400:
            fail("api_redirect_denied", "API redirects are not followed. Check the credential's approved destination.")
        if response.getheader("Content-Encoding", "identity").lower() not in ("identity", ""):
            fail("api_response_unsupported", "The API returned an unsupported compressed response.")
        content_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
        if not raw:
            result = None
        else:
            try:
                result = json.loads(raw)
            except (ValueError, UnicodeError):
                if not content_type.startswith("text/"):
                    fail("api_response_unsupported", "The generic API tools support JSON and text responses.")
                try:
                    result = raw.decode("utf-8")
                except UnicodeError:
                    fail("api_response_unsupported", "The API response is not UTF-8 text.")
        return response.status, result
    except ApiError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        fail("api_upstream_unavailable", "The HTTPS API request could not be completed.")
    finally:
        connection.close()


def scrub(value, secrets):
    replacements = set()
    for secret in secrets:
        if isinstance(secret, str) and secret:
            replacements.update((secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret),
                                 base64.b64encode(secret.encode()).decode()))
    replacements = sorted(replacements, key=len, reverse=True)
    def text(value):
        for secret in replacements:
            value = value.replace(secret, "[REDACTED]")
        return value
    def walk(value):
        if isinstance(value, dict):
            named = isinstance(value.get("name"), str) and SENSITIVE.search(value["name"])
            return {text(str(key)): "[REDACTED]" if SENSITIVE.search(str(key)) or (named and key == "value") else walk(item)
                    for key, item in value.items()}
        if isinstance(value, list):
            return [walk(item) for item in value]
        return text(value) if isinstance(value, str) else value
    return walk(value)


def secret_values(data, auth):
    refs = {name for name in (auth.get("field", "api_token"), auth.get("username_field", "username"),
            auth.get("password_field", "password"), auth.get("client_id_field", "client_id"),
            auth.get("client_secret_field", "client_secret")) if isinstance(name, str)}
    refs.update(auth.get("fields", {}).values() if isinstance(auth.get("fields"), dict) else [])
    return [value for key, value in data.items() if isinstance(value, str) and (key in refs or SENSITIVE.search(key))]


def profile(data):
    try:
        return _profile(data)
    except ApiError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        fail()


def _profile(data):
    config = data.get("_http")
    if config is None:
        fail("api_not_configured", "Add an _http profile to this credential in OpenBao to enable generic API access.")
    if isinstance(config, str):
        try:
            config = json.loads(config)
        except (ValueError, UnicodeError):
            fail()
    allowed = {"version", "base_url", "paths", "methods", "auth", "headers", "request_headers"}
    if not isinstance(config, dict) or set(config) - allowed or config.get("version") != 1:
        fail()
    config = {**config, "base_url": destination(config.get("base_url"))}
    paths, methods = config.get("paths"), config.get("methods")
    if not isinstance(paths, list) or not paths or len(paths) > 64 or not all(isinstance(p, str) and clean_path(p) == p for p in paths):
        fail()
    if not isinstance(methods, list) or not methods or not all(isinstance(m, str) and m in METHODS for m in methods):
        fail()
    static, requested = config.get("headers", {}), config.get("request_headers", [])
    if not isinstance(static, dict) or not isinstance(requested, list) or len(static) + len(requested) > 32:
        fail()
    for key, value in static.items():
        if header_name(key).lower() in RESERVED_HEADERS or SENSITIVE.search(key):
            fail()
        header_value(value)
    if len({key.lower() for key in static}) != len(static):
        fail()
    for key in requested:
        if header_name(key).lower() in RESERVED_HEADERS or SENSITIVE.search(key):
            fail()
    auth = config.get("auth")
    if not isinstance(auth, dict):
        fail()
    kind = auth.get("type")
    if kind in ("bearer", "header", "query"):
        if set(auth) - {"type", "field", "name", "prefix"}:
            fail()
        field(data, auth.get("field", "api_token"))
        if kind != "bearer":
            header_name(auth.get("name"))
        if kind != "query":
            header_value(auth.get("prefix", "Bearer " if kind == "bearer" else "") + field(data, auth.get("field", "api_token")))
    elif kind == "path_token":
        # Owners approve exact public paths containing one whole-segment
        # placeholder. The secret is injected only after route authorization;
        # catalog metadata and callers never receive the authenticated URL.
        if set(auth) != {"type", "field"}:
            fail()
        value = field(data, auth["field"])
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", value):
            fail("api_credential_invalid", "The path credential must be a single URL-safe token.")
        for path in paths:
            if (path.endswith("/") or path.count("{credential}") != 1
                    or "{credential}" not in path.split("/")
                    or any(c in path.replace("{credential}", "") for c in "{}")):
                fail()
    elif kind == "headers":
        if set(auth) != {"type", "fields"} or not isinstance(auth["fields"], dict) or not 1 <= len(auth["fields"]) <= 16:
            fail()
        for name, ref in auth["fields"].items():
            header_name(name)
            header_value(field(data, ref))
        if len({name.lower() for name in auth["fields"]}) != len(auth["fields"]):
            fail()
    elif kind == "basic":
        if set(auth) - {"type", "username_field", "password_field"}:
            fail()
        username = field(data, auth.get("username_field", "username"))
        field(data, auth.get("password_field", "password"))
        if ":" in username:
            fail()
    elif kind == "oauth2_client_credentials":
        if set(auth) - {"type", "token_url", "client_id_field", "client_secret_field", "client_auth", "header", "prefix", "parameters"}:
            fail()
        auth = {**auth, "token_url": destination(auth.get("token_url"), token=True)}
        field(data, auth.get("client_id_field", "client_id"))
        field(data, auth.get("client_secret_field", "client_secret"))
        if auth.get("client_auth", "body") not in ("body", "basic"):
            fail()
        header_name(auth.get("header", "Authorization"))
        header_value(auth.get("prefix", "Bearer "))
        params = auth.get("parameters", {})
        if not isinstance(params, dict) or len(params) > 16 or set(params) & {"grant_type", "client_id", "client_secret"} or not all(isinstance(k, str) and isinstance(v, str) and len(k) + len(v) < 4096 for k, v in params.items()):
            fail()
    elif kind != "none" or set(auth) != {"type"}:
        fail()
    return {**config, "auth": auth}


class ApiProxy:
    def __init__(self):
        self.tokens = {}
        self.lock = threading.RLock()

    def describe(self, data):
        if "_http" not in data:
            return {"status": "not_configured"}
        try:
            config = profile(data)
            public = {key: config[key] for key in ("base_url", "paths", "methods")}
            public.update(status="ready", authentication=config["auth"]["type"], request_headers=config.get("request_headers", []))
            return scrub(public, secret_values(data, config["auth"]))
        except ApiError as error:
            return {"status": "invalid_configuration", "error_code": error.code}

    def token(self, identity, data, auth):
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        with self.lock:
            current = self.tokens.get(identity)
            if current and current["fingerprint"] == fingerprint and current["expires"] > time.monotonic() + 60:
                return current["token"]
            self.tokens.pop(identity, None)
            ident = field(data, auth.get("client_id_field", "client_id"))
            secret = field(data, auth.get("client_secret_field", "client_secret"))
            params = {**auth.get("parameters", {}), "grant_type": "client_credentials"}
            headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json", "Accept-Encoding": "identity", "User-Agent": "project-access/0.2.0"}
            if auth.get("client_auth", "body") == "basic":
                pair = urllib.parse.quote_plus(ident) + ":" + urllib.parse.quote_plus(secret)
                headers["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
            else:
                params.update(client_id=ident, client_secret=secret)
            status, result = exchange(auth["token_url"], "POST", headers, urllib.parse.urlencode(params).encode())
            if status != 200 or not isinstance(result, dict) or not isinstance(result.get("access_token"), str) or not result["access_token"]:
                raise ApiError("api_token_failed", "The API's OAuth token request failed.", status)
            expires = result.get("expires_in")
            if isinstance(expires, bool) or not isinstance(expires, (int, float)) or not 0 < expires <= 31536000:
                fail("api_token_failed", "The OAuth response has no usable expires_in value.")
            token = header_value(result["access_token"])
            self.tokens[identity] = {"fingerprint": fingerprint, "expires": time.monotonic() + expires, "token": token}
            return token

    def request(self, identity, data, request):
        if set(request) - {"action", "project", "credential", "method", "path", "query", "headers", "json_body", "form_body"}:
            fail("api_request_invalid", "The request contains unsupported arguments.")
        config = profile(data)
        method, path = request.get("method", "GET"), request.get("path")
        decoded = clean_path(path)
        if not isinstance(method, str) or method not in config["methods"] or not any(decoded.startswith(p) if p.endswith("/") else decoded == p for p in config["paths"]):
            fail("api_route_denied", "This method or path is outside the credential's approved API profile.")
        query = request.get("query", {})
        if not isinstance(query, dict) or len(query) > 128:
            fail("api_request_invalid", "Use an object for query parameters.")
        for key, value in query.items():
            values = value if isinstance(value, list) else [value]
            if not isinstance(key, str) or not all(isinstance(v, (str, int, float, bool)) for v in values):
                fail("api_request_invalid", "Query values must be strings, numbers, booleans or lists of those values.")
        query = dict(query)
        headers = {"User-Agent": "project-access/0.2.0", "Accept": "application/json", "Accept-Encoding": "identity", **config.get("headers", {})}
        additional = request.get("headers", {})
        if not isinstance(additional, dict):
            fail("api_request_invalid", "Use an object for request headers.")
        permitted = {key.lower() for key in config.get("request_headers", [])}
        for key, value in additional.items():
            if header_name(key).lower() not in permitted:
                fail("api_header_denied", "This request header is not approved by the credential's profile.")
            headers[key] = header_value(value)
        body = None
        if "json_body" in request and "form_body" in request:
            fail("api_request_invalid", "Choose either JSON or form data.")
        if "json_body" in request:
            body = json.dumps(request["json_body"], allow_nan=False).encode()
            headers["Content-Type"] = "application/json"
        if "form_body" in request:
            form = request["form_body"]
            if not isinstance(form, dict) or not all(isinstance(k, str) and isinstance(v, (str, int, float, bool)) for k, v in form.items()):
                fail("api_request_invalid", "Use an object of scalar values for form data.")
            body = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if body is not None and (method in ("GET", "HEAD") or len(body) > 1024 * 1024 or b"[REDACTED]" in body):
            fail("api_request_invalid", "The body is not valid for this request; do not submit redacted placeholders.")
        auth = config["auth"]
        secrets = secret_values(data, auth)
        kind = auth["type"]
        additions = {}
        if kind == "bearer":
            additions["Authorization"] = auth.get("prefix", "Bearer ") + field(data, auth.get("field", "api_token"))
        elif kind == "header":
            additions[auth["name"]] = auth.get("prefix", "") + field(data, auth.get("field", "api_token"))
        elif kind == "headers":
            additions = {name: field(data, ref) for name, ref in auth["fields"].items()}
        elif kind == "basic":
            pair = field(data, auth.get("username_field", "username")) + ":" + field(data, auth.get("password_field", "password"))
            additions["Authorization"] = "Basic " + base64.b64encode(pair.encode()).decode()
        elif kind == "query":
            if auth["name"] in query:
                fail("api_request_invalid", "The API authentication query parameter cannot be overridden.")
            query[auth["name"]] = field(data, auth.get("field", "api_token"))
        elif kind == "oauth2_client_credentials":
            token = self.token(identity, data, auth)
            secrets.append(token)
            additions[auth.get("header", "Authorization")] = auth.get("prefix", "Bearer ") + token
        for key, value in additions.items():
            headers = {k: v for k, v in headers.items() if k.lower() != key.lower()}
            headers[key] = header_value(value)
            secrets.append(value)
            if kind == "basic":
                secrets.append(value.removeprefix("Basic "))
        encoded = urllib.parse.urlencode(query, doseq=True)
        if len(encoded) > 32768:
            fail("api_request_invalid", "The query exceeded the size limit.")
        # Validate the entire destination again, then resolve and pin its public
        # address at the actual TLS connection. There is no second DNS lookup.
        url = config["base_url"] + path
        if kind == "path_token":
            url = config["base_url"] + decoded.replace("{credential}", field(data, auth["field"]))
        destination(url)
        status, result = exchange(url + ("?" + encoded if encoded else ""), method, headers, body)
        if status == 401 and kind == "oauth2_client_credentials":
            with self.lock:
                self.tokens.pop(identity, None)
        if not 200 <= status < 300:
            raise ApiError("api_request_failed", "The approved API request was rejected. No request was automatically replayed.", status)
        return {"http_status": status, "data": scrub(result, secrets)}
