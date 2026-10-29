"""Fixed, read-only Search Console operations using privately refreshed grants.

Profiles allocate an identity, a domain and optionally one exact property. No
caller-supplied destination, headers, request body or OAuth material is accepted.
"""
import datetime as dt
import ipaddress
import json
import re
from urllib.parse import quote, unquote, urlsplit

from generic_api import ApiError, exchange, scrub
from google_migration import GoogleMigration


PROFILE = "_google_search_console"
SCOPES = frozenset({"openid", "https://www.googleapis.com/auth/userinfo.email",
                    "https://www.googleapis.com/auth/webmasters.readonly"})
OPERATIONS = frozenset({"identity", "sites_list", "site_get", "sitemaps_list",
                        "searchanalytics_query", "url_inspection"})
MAX_RESPONSE = 2 * 1024 * 1024
MAX_REQUEST = 16384
DIMENSIONS = frozenset({"date", "query", "page", "country", "device", "searchAppearance"})
FILTER_DIMENSIONS = DIMENSIONS - {"date"}
V3 = "https://www.googleapis.com/webmasters/v3/sites"
USERINFO = "https://openidconnect.googleapis.com/v1/userinfo"
INSPECT = "https://searchconsole.googleapis.com/v1/urlInspection/index:inspect"
PERMISSIONS = frozenset({"siteOwner", "siteFullUser", "siteRestrictedUser", "siteUnverifiedUser"})


def denied(code="gsc_request_denied", message="This Search Console request is not permitted.", status=None):
    raise ApiError(code, message, status)


def _text(value, maximum=4096, empty=False):
    if (not isinstance(value, str) or (not value and not empty) or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError()
    return value


def _domain(value):
    _text(value, 253)
    value = value.lower()
    labels = value.split(".")
    if (len(labels) < 2 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                                   for x in labels)):
        raise ValueError()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError()


def _within(host, domain):
    return host == domain or host.endswith("." + domain)


def _path(value):
    current = value or "/"
    for _ in range(6):
        if (any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in current)
                or "\\" in current or any(p in (".", "..") for p in current.split("/"))
                or re.search(r"%(?![0-9a-fA-F]{2})", current)):
            raise ValueError()
        decoded = unquote(current, errors="strict")
        if decoded == current:
            return current
        current = decoded
    raise ValueError()


def _url(value, domain):
    _text(value)
    if (any(c.isspace() or ord(c) > 126 for c in value) or "\\" in value
            or re.search(r"%(?![0-9a-fA-F]{2})", value)):
        raise ValueError()
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or parsed.netloc.endswith(":")
            or not _within(_domain(parsed.hostname), domain)):
        raise ValueError()
    default_port = 443 if parsed.scheme == "https" else 80
    port = parsed.port
    if port is not None and port != default_port:
        raise ValueError()
    return parsed, _path(parsed.path), port or default_port


def _property(value, domain):
    _text(value)
    if value.startswith("sc-domain:"):
        if not _within(_domain(value[10:]), domain):
            raise ValueError()
    else:
        parsed, _, _ = _url(value, domain)
        if parsed.query or not parsed.path.endswith("/"):
            raise ValueError()
    return value


def _scope_list(value):
    return (isinstance(value, list) and len(value) == len(SCOPES)
            and all(isinstance(x, str) for x in value) and set(value) == SCOPES)


def profile(data):
    """Validate an allocation and standard authorized-user JSON, without I/O."""
    try:
        if not isinstance(data, dict):
            raise ValueError()
        config = data.get(PROFILE)
        if isinstance(config, str):
            config = json.loads(config)
        allowed = {"version", "account", "domain", "property", "grant_field", "scopes", "capabilities"}
        if (not isinstance(config, dict) or set(config) - allowed
                or type(config.get("version")) is not int or config["version"] != 1):
            raise ValueError()
        account = _text(config["account"], 254)
        if not re.fullmatch(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+", account):
            raise ValueError()
        domain = _domain(config["domain"])
        if not _scope_list(config["scopes"]):
            raise ValueError()
        caps = config["capabilities"]
        if (not isinstance(caps, list) or not caps or len(caps) > len(OPERATIONS)
                or not all(isinstance(x, str) and x in OPERATIONS for x in caps)
                or len(set(caps)) != len(caps)):
            raise ValueError()
        if "property" in config:
            _property(config["property"], domain)
        ref = config.get("grant_field", "authorized_user_json")
        if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,127}", ref):
            raise ValueError()
        grant = data[ref]
        if isinstance(grant, str):
            grant = json.loads(grant)
        if (not isinstance(grant, dict) or grant.get("type") != "authorized_user"
                or grant.get("token_uri", "https://oauth2.googleapis.com/token") != "https://oauth2.googleapis.com/token"):
            raise ValueError()
        for field in ("client_id", "client_secret", "refresh_token"):
            value = _text(grant[field], 16384)
            if any(not 33 <= ord(c) <= 126 for c in value):
                raise ValueError()
        if "scopes" in grant:
            declared = grant["scopes"].split() if isinstance(grant["scopes"], str) else grant["scopes"]
            if not _scope_list(declared):
                raise ValueError()
        # account/account_email are mutable file metadata, never identity proof.
        return {**config, "account": account.lower(), "domain": domain}, grant
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        denied("gsc_profile_invalid", "The Search Console allocation or authorized-user grant is invalid.")


def describe(data):
    if not isinstance(data, dict) or PROFILE not in data:
        return {"status": "not_configured"}
    try:
        config, _ = profile(data)
        return {"status": "ready", "authentication": "google_authorized_user",
                **{k: config[k] for k in ("account", "domain", "property", "capabilities") if k in config}}
    except ApiError as error:
        return {"status": "invalid_configuration", "error_code": error.code}


def _analytics(params):
    allowed = {"siteUrl", "startDate", "endDate", "dimensions", "rowLimit", "startRow",
               "type", "dataState", "aggregationType", "dimensionFilterGroups"}
    if set(params) - allowed:
        raise ValueError()
    dates = []
    for key in ("startDate", "endDate"):
        value = params.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise ValueError()
        dates.append(dt.date.fromisoformat(value))
    if not 0 <= (dates[1] - dates[0]).days < 90:
        raise ValueError()
    limit, offset = params.get("rowLimit", 100), params.get("startRow", 0)
    if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or offset != 0:
        raise ValueError()
    dims = params.get("dimensions", [])
    if (not isinstance(dims, list) or len(dims) > len(DIMENSIONS)
            or not all(isinstance(x, str) and x in DIMENSIONS for x in dims)
            or len(set(dims)) != len(dims)):
        raise ValueError()
    if params.get("type", "web") not in ("web", "image", "video", "news", "discover", "googleNews"):
        raise ValueError()
    if params.get("dataState", "final") != "final" or params.get("aggregationType", "auto") not in ("auto", "byPage", "byProperty"):
        raise ValueError()
    groups = params.get("dimensionFilterGroups", [])
    if not isinstance(groups, list) or len(groups) > 1:
        raise ValueError()
    for group in groups:
        if (not isinstance(group, dict) or set(group) - {"groupType", "filters"}
                or group.get("groupType", "and") != "and"):
            raise ValueError()
        filters = group.get("filters")
        if not isinstance(filters, list) or not 1 <= len(filters) <= 5:
            raise ValueError()
        for item in filters:
            if (not isinstance(item, dict) or set(item) != {"dimension", "operator", "expression"}
                    or item["dimension"] not in FILTER_DIMENSIONS
                    or item["operator"] not in ("equals", "notEquals", "contains", "notContains", "includingRegex", "excludingRegex")):
                raise ValueError()
            _text(item["expression"], 1024)
    return {**{k: v for k, v in params.items() if k != "siteUrl"},
            "rowLimit": limit, "startRow": 0, "dataState": "final"}


def route(config, operation, params):
    """Construct only fixed read routes; validate every parameter before auth."""
    try:
        if not isinstance(operation, str) or operation not in OPERATIONS or not isinstance(params, dict):
            raise ValueError()
        if operation not in config["capabilities"]:
            denied("gsc_capability_denied", "This operation is outside the Search Console allocation.")
        if operation in ("identity", "sites_list"):
            if params:
                raise ValueError()
            return "GET", USERINFO if operation == "identity" else V3, None
        selected = config.get("property")
        if selected is None:
            denied("gsc_property_required", "Pin an exact Search Console property before this operation.")
        if params.get("siteUrl", selected) != selected:
            raise ValueError()
        base = V3 + "/" + quote(selected, safe="")
        if operation in ("site_get", "sitemaps_list"):
            if set(params) - {"siteUrl"}:
                raise ValueError()
            return "GET", base + ("/sitemaps" if operation == "sitemaps_list" else ""), None
        if operation == "searchanalytics_query":
            body = _analytics(params)
            if len(json.dumps(body, allow_nan=False).encode()) > MAX_REQUEST:
                raise ValueError()
            return "POST", base + "/searchAnalytics/query", body
        if set(params) - {"siteUrl", "inspectionUrl", "languageCode"}:
            raise ValueError()
        url = params.get("inspectionUrl")
        parsed, path, port = _url(url, config["domain"])
        if selected.startswith("sc-domain:"):
            if not _within(parsed.hostname, _domain(selected[10:])):
                raise ValueError()
        else:
            prefix, _, prefix_port = _url(selected, config["domain"])
            if (parsed.scheme != prefix.scheme or parsed.hostname != prefix.hostname
                    or port != prefix_port
                    or not (parsed.path or "/").startswith(prefix.path or "/")):
                raise ValueError()
        language = params.get("languageCode", "en-US")
        if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}", language):
            raise ValueError()
        return "POST", INSPECT, {"siteUrl": selected, "inspectionUrl": url, "languageCode": language}
    except ApiError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        denied()


class GoogleSearchConsole:
    def __init__(self):
        self.auth = GoogleMigration()

    def execute(self, identity, data, request):
        config, grant = profile(data)
        if (not isinstance(request, dict)
                or set(request) - {"action", "project", "credential", "operation", "params"}):
            denied()
        operation, params = request.get("operation"), request.get("params", {})
        method, url, body = route(config, operation, params)
        encoded = json.dumps(body, allow_nan=False).encode() if body is not None else None
        try:
            token = self.auth.token(identity, data, config, grant)
        except ApiError:
            raise
        except (ValueError, TypeError, AttributeError, UnicodeError, OverflowError, RecursionError):
            denied("gsc_auth_response_invalid", "Google returned an unusable authentication response.")
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
                   "Accept-Encoding": "identity", "User-Agent": "project-access-gsc/1"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            status, result = exchange(url, method, headers, encoded)
            if not 200 <= status < 300:
                if status == 401:
                    with self.auth.lock:
                        self.auth.tokens.pop(identity, None)
                denied("gsc_upstream_rejected", "Google rejected the Search Console read; no automatic replay was attempted.", status)
            if not isinstance(result, dict) or len(json.dumps(result, allow_nan=False).encode()) > MAX_RESPONSE:
                denied("gsc_response_invalid", "Google returned an invalid or oversized Search Console response.")
            if operation == "identity":
                if result.get("email", "").lower() != config["account"] or result.get("email_verified") is not True:
                    with self.auth.lock:
                        self.auth.tokens.pop(identity, None)
                    denied("gsc_identity_mismatch", "Google did not verify the allocated account.")
                result = {k: result[k] for k in ("email", "email_verified", "sub") if k in result}
            elif operation == "sites_list":
                rows = result.get("siteEntry", [])
                if not isinstance(rows, list) or len(rows) > 10000:
                    raise ValueError()
                selected = []
                for row in rows:
                    try:
                        if not isinstance(row, dict) or row.get("permissionLevel") not in PERMISSIONS:
                            continue
                        site = _property(row.get("siteUrl"), config["domain"])
                        if "property" not in config or site == config["property"]:
                            selected.append({"siteUrl": site, "permissionLevel": row["permissionLevel"]})
                    except (ValueError, TypeError, AttributeError, UnicodeError):
                        continue
                result = {"siteEntry": selected}
            elif operation == "site_get":
                if result.get("siteUrl") != config["property"] or result.get("permissionLevel") not in PERMISSIONS:
                    raise ValueError()
                result = {k: result[k] for k in ("siteUrl", "permissionLevel")}
            elif operation == "sitemaps_list" and not isinstance(result.get("sitemap", []), list):
                raise ValueError()
            elif operation == "searchanalytics_query":
                rows = result.get("rows", [])
                if not isinstance(rows, list) or len(rows) > body["rowLimit"]:
                    raise ValueError()
            elif operation == "url_inspection" and not isinstance(result.get("inspectionResult"), dict):
                raise ValueError()
            safe_result = scrub(result, [token, grant["client_secret"], grant["refresh_token"]])
            if len(json.dumps(safe_result, allow_nan=False).encode()) > MAX_RESPONSE:
                denied("gsc_response_invalid", "Google returned an oversized Search Console response.")
            return {"http_status": status, "data": safe_result}
        except ApiError:
            raise
        except (ValueError, TypeError, AttributeError, UnicodeError, OverflowError, RecursionError):
            denied("gsc_response_invalid", "Google returned an invalid Search Console response.")
