"""Restricted Google migration transport. Credentials never leave this process.

Only fixed Google hosts/routes are implemented. No arbitrary URLs, sending mail,
deletion, grant export, local filesystem access, or automatic write retries.
"""
import hashlib
import http.client
import json
import re
import threading
import time
import urllib.parse

from generic_api import ApiError, PinnedHTTPS, public_addresses, exchange
import workspace_google

MAX_BODY = 210 * 1024 * 1024
MAX_CHUNK = 8 * 1024 * 1024
BASE_SCOPES = {"openid", "https://www.googleapis.com/auth/userinfo.email"}
SCOPE = "https://www.googleapis.com/auth/"
CAP_SCOPES = {
    "storage.read": {SCOPE + "devstorage.read_only"},
    "gmail.read": {SCOPE + "gmail.readonly"},
    "gmail.import": {SCOPE + "gmail.insert"},
    "gmail.labels.create": {SCOPE + "gmail.labels"},
    "gmail.drafts.create": {SCOPE + "gmail.compose"},
}
CAP_SCOPES.update(workspace_google.CAP_SCOPES)
ID = re.compile(r"[A-Za-z0-9_-]{1,256}")


def denied(code="google_request_denied", message="This Google migration request is not permitted.", status=None):
    raise ApiError(code, message, status)


def profile(data):
    try:
        config = data.get("_google_migration")
        if isinstance(config, str):
            config = json.loads(config)
        if (not isinstance(config, dict) or set(config) - {"version", "account", "grant_field", "scopes", "capabilities", "bucket", "share_with", "calendar_markers"}
                or config.get("version") != 1):
            raise ValueError()
        account = config["account"]
        if not isinstance(account, str) or not re.fullmatch(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+", account):
            raise ValueError()
        caps, scopes = config["capabilities"], config["scopes"]
        if (not isinstance(caps, list) or not caps or not all(isinstance(c, str) and c in CAP_SCOPES for c in caps)
                or not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes)):
            raise ValueError()
        required = BASE_SCOPES | set().union(*(CAP_SCOPES[c] for c in caps))
        if "calendar_markers" in config:
            markers = config["calendar_markers"]
            if ("calendar.import" not in caps or not isinstance(markers, dict)
                    or set(markers) != {"source_id", "source_calendar"}
                    or not all(isinstance(value, str) and re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", value)
                               for value in markers.values())
                    or len(set(markers.values())) != 2):
                raise ValueError()
        if "contacts.create" in caps:
            required.discard(SCOPE + "contacts.readonly")
        if "drive.share" in caps:
            if not re.fullmatch(r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+", config.get("share_with", "")) or config["share_with"] == account:
                raise ValueError()
        elif "share_with" in config:
            raise ValueError()
        if set(scopes) != required:
            raise ValueError()
        if "storage.read" in caps:
            if caps != ["storage.read"] or not re.fullmatch(r"dwt-takeout-export--[0-9]{6,40}", config.get("bucket", "")):
                raise ValueError()
        elif "bucket" in config:
            raise ValueError()
        ref = config.get("grant_field", "authorized_user_json")
        if not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z0-9_]{1,128}", ref):
            raise ValueError()
        grant = data[ref]
        if isinstance(grant, str):
            grant = json.loads(grant)
        if (not isinstance(grant, dict) or grant.get("type") != "authorized_user"
                or grant.get("account_email", "").lower() != account.lower()
                or grant.get("token_uri") != "https://oauth2.googleapis.com/token"
                or set(grant.get("scopes", [])) != set(scopes)):
            raise ValueError()
        for key in ("client_id", "client_secret", "refresh_token"):
            value = grant.get(key)
            if not isinstance(value, str) or not 1 <= len(value) <= 16384 or any(ord(c) < 32 for c in value):
                raise ValueError()
        return config, grant
    except (ValueError, TypeError, KeyError, AttributeError):
        denied("google_profile_invalid", "The Google migration profile or authorized-user grant is invalid.")


def describe(data):
    if "_google_migration" not in data:
        return {"status": "not_configured"}
    try:
        config, _ = profile(data)
        return {"status": "ready", "authentication": "google_authorized_user", **{
            k: config[k] for k in ("account", "capabilities", "bucket", "share_with") if k in config}}
    except ApiError as error:
        return {"status": "invalid_configuration", "error_code": error.code}


def text(value, maximum=4096):
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
        denied()
    return value


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        denied()
    return value


def fields(params, allowed):
    if not isinstance(params, dict) or set(params) - set(allowed):
        denied()


def scalar_query(params):
    result = {}
    for key, value in params.items():
        values = value if isinstance(value, list) else [value]
        if len(values) > 100:
            denied()
        normalized = []
        for v in values:
            if isinstance(v, bool):
                normalized.append(str(v).lower())
            elif isinstance(v, (str, int)):
                normalized.append(text(str(v)))
            else:
                denied()
        result[key] = normalized if isinstance(value, list) else normalized[0]
    return result


def route(config, operation, params, body_size):
    """Return a fixed route and bounded response size before accepting a body."""
    if operation in workspace_google.OPS:
        return workspace_google.route(config, operation, params, body_size)
    fields(params, {
        "identity": [], "storage_list": ["pageToken", "maxResults"],
        "storage_object": ["object", "generation"],
        "storage_download": ["object", "generation", "offset", "length"],
        "gmail_profile": [], "gmail_labels_list": [], "gmail_label_create": [],
        "gmail_messages_list": ["q", "labelIds", "maxResults", "pageToken", "includeSpamTrash"],
        "gmail_message_get": ["id", "format", "metadataHeaders", "fields"],
        "gmail_drafts_list": ["q", "maxResults", "pageToken", "includeSpamTrash"],
        "gmail_draft_get": ["id", "format"],
        "gmail_import": ["internalDateSource", "neverMarkSpam", "processForCalendar", "deleted"],
        "gmail_draft_create": [],
    }.get(operation, []))
    query, headers, method, limit = {}, {}, "GET", 4 * 1024 * 1024
    write_cap = {"gmail_import": "gmail.import", "gmail_label_create": "gmail.labels.create", "gmail_draft_create": "gmail.drafts.create"}
    if operation == "identity":
        url, capability = "https://openidconnect.googleapis.com/v1/userinfo", None
    elif operation in ("storage_list", "storage_object", "storage_download"):
        capability = "storage.read"
        url = "https://storage.googleapis.com/storage/v1/b/" + config.get("bucket", "") + "/o"
        if operation == "storage_list":
            query = {**params, "projection": "noAcl", "fields": "nextPageToken,items(name,size,generation,md5Hash,crc32c,updated,contentType,contentEncoding)"}
        else:
            obj = text(params.get("object"), 1024)
            if not obj:
                denied()
            generation = params.get("generation")
            if not isinstance(generation, str) or not re.fullmatch(r"[0-9]{1,30}", generation):
                denied()
            url += "/" + urllib.parse.quote(obj, safe="")
            query = {"generation": generation, "ifGenerationMatch": generation}
            if operation == "storage_download":
                offset, length = params.get("offset"), params.get("length")
                if type(offset) is not int or not 0 <= offset <= 5 * 1024**4 or type(length) is not int or not 1 <= length <= MAX_CHUNK:
                    denied()
                query["alt"] = "media"
                headers["Range"] = f"bytes={offset}-{offset + length - 1}"
                limit = length
    elif operation in ("gmail_profile", "gmail_labels_list", "gmail_label_create", "gmail_messages_list", "gmail_message_get", "gmail_drafts_list", "gmail_draft_get", "gmail_import", "gmail_draft_create"):
        capability = write_cap.get(operation, "gmail.read")
        paths = {"gmail_profile": "profile", "gmail_labels_list": "labels", "gmail_label_create": "labels",
                 "gmail_messages_list": "messages", "gmail_message_get": "messages/",
                 "gmail_drafts_list": "drafts", "gmail_draft_get": "drafts/",
                 "gmail_import": "messages/import", "gmail_draft_create": "drafts"}
        url = "https://gmail.googleapis.com/gmail/v1/users/me/" + paths[operation]
        query = dict(params)
        if operation in ("gmail_message_get", "gmail_draft_get"):
            url += identifier(query.pop("id", None))
            if query.get("format", "full") not in ("raw", "full", "metadata", "minimal"):
                denied()
            limit = MAX_BODY
        if operation in write_cap:
            method = "POST"
        if operation == "gmail_import":
            if query.get("internalDateSource", "dateHeader") not in ("dateHeader", "receivedTime"):
                denied()
            # Import must never process an invitation or create calendar events.
            if query.get("processForCalendar", False) is not False or query.get("deleted", False) is not False:
                denied()
            query["processForCalendar"] = False
    else:
        denied()
    if capability is not None and capability not in config["capabilities"]:
        denied("google_capability_denied", "This Google operation is outside the credential's allocated capabilities.")
    if (type(body_size) is not int or not 0 <= body_size <= MAX_BODY
            or (method == "GET" and body_size != 0) or (method == "POST" and body_size == 0)):
        denied()
    if operation == "gmail_label_create" and body_size > 16384:
        denied()
    if "maxResults" in query and (type(query["maxResults"]) is not int or not 1 <= query["maxResults"] <= (1000 if operation == "storage_list" else 500)):
        denied()
    if query:
        url += "?" + urllib.parse.urlencode(scalar_query(query), doseq=True)
    return method, url, headers, limit


def validate_body(operation, body, config=None):
    if operation in workspace_google.OPS:
        return workspace_google.validate_body(config or {}, operation, body)
    if not body:
        return
    try:
        value = json.loads(body)
        if not isinstance(value, dict):
            raise ValueError()
        if operation == "gmail_label_create":
            if set(value) - {"name", "labelListVisibility", "messageListVisibility", "color"} or not text(value.get("name"), 225):
                raise ValueError()
        else:
            if operation == "gmail_draft_create":
                if set(value) != {"message"}:
                    raise ValueError()
                value = value["message"]
            if not isinstance(value, dict) or set(value) - {"raw", "labelIds"}:
                raise ValueError()
            raw = value.get("raw")
            if not isinstance(raw, str) or not raw or not re.fullmatch(r"[A-Za-z0-9_=-]+", raw):
                raise ValueError()
            labels = value.get("labelIds", [])
            if not isinstance(labels, list) or len(labels) > 100 or not all(isinstance(x, str) and ID.fullmatch(x) for x in labels):
                raise ValueError()
    except (ValueError, UnicodeError, TypeError):
        denied("google_body_invalid", "Use a valid Gmail import, draft or label JSON body.")


def safe_rejection(payload):
    """Return only fixed labels, never Google's text, values or response body."""
    reasons={'badRequest','invalid','invalidArgument','invalidParameter','required','forbidden','notFound','duplicate','conditionNotMet','preconditionFailed','invalidSharingRequest','sharingRateLimitExceeded','insufficientFilePermissions','domainPolicy','storageQuotaExceeded','rateLimitExceeded','userRateLimitExceeded','dailyLimitExceeded','cannotModifyInheritedTeamDrivePermission','teamDriveMembershipRequired','forbiddenForNonOrganizer','timeRangeEmpty','quotaExceeded','accessNotConfigured','insufficientPermissions','invalidAttendeeEmail','invalidOrganizer','exportSizeLimitExceeded'}
    fields={'organizer','attendee','email','icaluid','start','end','recurrence','timezone','reminder','extendedproperties','conference','attachment','permission','notification','quota','sharing','storage','limit','sequence','resource','id','eventtype'}
    try:
        error=json.loads(payload).get('error',{})
        rows=error.get('errors',[])
        found=sorted({r.get('reason') for r in rows if isinstance(r,dict) and r.get('reason') in reasons})
        # Classify words from free text without returning any part of that text.
        messages=[error.get('message','')]+[r.get('message','') for r in rows if isinstance(r,dict)]
        words=set(re.findall(r'[a-z]+',' '.join(x for x in messages if isinstance(x,str)).lower()))
        labels=sorted(fields & words)
        return ' Known reasons: '+(','.join(found) or 'unclassified')+'; field categories: '+(','.join(labels) or 'unclassified')+'.'
    except (ValueError,TypeError,AttributeError):return ''


def download(url, method, headers, body, limit):
    """Bounded response; no redirects, decompression, proxies or automatic retry."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.hostname not in {"gmail.googleapis.com", "storage.googleapis.com", "openidconnect.googleapis.com", "www.googleapis.com", "people.googleapis.com"}:
        denied()
    connection = PinnedHTTPS(parsed.hostname, public_addresses(parsed.hostname)[0])
    connection.timeout = 180
    try:
        connection.request(method, parsed.path + ("?" + parsed.query if parsed.query else ""), body or None, headers)
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            # Never return provider free text. A small body is classified into
            # fixed known labels to diagnose policy and validation failures.
            details=safe_rejection(response.read(65536))
            denied("google_upstream_rejected", "Google rejected the migration request; no automatic replay was attempted."+details, response.status)
        if response.getheader("Content-Encoding", "identity").lower() not in ("", "identity"):
            denied("google_encoding_unsupported", "Google returned a compressed response; preserve stored bytes before retrying.")
        payload = response.read(limit + 1)
        if len(payload) > limit:
            denied("google_response_too_large", "Google returned more data than this operation permits.")
        if response.getheader("Content-Length") is not None and int(response.getheader("Content-Length")) != len(payload):
            denied("google_response_incomplete", "The Google response was incomplete.")
        selected = {name.lower(): response.getheader(name) for name in ("Content-Type", "Content-Range", "x-goog-generation", "x-goog-hash") if response.getheader(name) is not None}
        return response.status, selected, payload
    except ApiError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        denied("google_transport_uncertain", "The Google request did not complete reliably. Reconcile writes before retrying.")
    finally:
        connection.close()


class GoogleMigration:
    def __init__(self):
        self.tokens = {}
        self.lock = threading.RLock()
        # At most one large operation at a time; unrelated generic APIs stay available.
        self.transfer_slot = threading.BoundedSemaphore(1)

    def token(self, identity, data, config, grant):
        fingerprint = hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()
        with self.lock:
            cached = self.tokens.get(identity)
            if cached and cached[0] == fingerprint and cached[1] > time.monotonic() + 90:
                return cached[2]
            self.tokens.pop(identity, None)
            form = {"grant_type": "refresh_token", **{k: grant[k] for k in ("client_id", "client_secret", "refresh_token")}}
            status, result = exchange("https://oauth2.googleapis.com/token", "POST", {"Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "identity"}, urllib.parse.urlencode(form).encode())
            if status != 200 or not isinstance(result, dict):
                denied("google_refresh_failed", "The saved Google grant could not be refreshed; reauthorization may be needed.", status)
            token, ttl = result.get("access_token"), result.get("expires_in")
            if (not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]{1,16384}", token)
                    or type(ttl) not in (int, float) or not 120 <= ttl <= 86400
                    or str(result.get("token_type", "")).lower() != "bearer"):
                denied("google_refresh_invalid", "Google returned an unusable token response.")
            if "refresh_token" in result and result["refresh_token"] != grant["refresh_token"]:
                denied("google_rotating_grant_unsupported", "The grant requires refresh-token rotation; update it securely in OpenBao.")
            if "scope" in result and set(result["scope"].split()) != set(config["scopes"]):
                denied("google_scope_mismatch", "Google returned scopes different from the allocated grant.")
            status, who = exchange("https://openidconnect.googleapis.com/v1/userinfo", "GET", {"Authorization": "Bearer " + token, "Accept-Encoding": "identity"})
            if (status != 200 or not isinstance(who, dict) or who.get("email", "").lower() != config["account"].lower()
                    or who.get("email_verified") is not True):
                denied("google_identity_mismatch", "The Google grant did not verify as the allocated account.")
            self.tokens[identity] = (fingerprint, time.monotonic() + ttl, token)
            return token

    def execute(self, identity, data, request, body):
        config, grant = profile(data)
        allowed = {"action", "project", "credential", "operation", "params", "body_bytes"}
        if not isinstance(request, dict) or set(request) - allowed:
            denied()
        operation, params = request.get("operation"), request.get("params", {})
        method, url, headers, limit = route(config, operation, params, len(body))
        validate_body(operation, body, config)
        token = self.token(identity, data, config, grant)
        headers.update(Authorization="Bearer " + token, **{"Accept-Encoding": "identity", "Content-Type": "application/json"})
        if operation == 'calendar_private_event_patch':
            # Require an existing private migration copy. Ordinary calendar
            # invitations cannot pass this guard, regardless of OAuth scopes.
            _,check_url,_,_=workspace_google.route(config,'calendar_event_get',{'calendarId':params['calendarId'],'eventId':params['eventId']},0)
            _,_,check_payload=download(check_url,'GET',{k:v for k,v in headers.items() if k!='If-Match'},b'',4*1024*1024)
            try:
                event=json.loads(check_payload)
                private=event.get('extendedProperties',{}).get('private',{})
                markers=config.get('calendar_markers', {'source_id':'migrationSourceId', 'source_calendar':'migrationSourceCalendar'})
                valid=(event.get('privateCopy') is True and event.get('etag')==params['etag'] and
                       isinstance(private.get(markers['source_id']),str) and bool(private[markers['source_id']]) and
                       isinstance(private.get(markers['source_calendar']),str) and bool(private[markers['source_calendar']]))
            except (ValueError,TypeError,AttributeError):valid=False
            if not valid:denied('google_private_copy_required','Only an unchanged private migration event may be patched.')
        try:
            status, selected, payload = download(url, method, headers, body, limit)
        except ApiError as error:
            if error.status == 401:
                with self.lock:
                    self.tokens.pop(identity, None)
            raise
        if operation == "storage_download":
            start, length = params["offset"], params["length"]
            expected = re.fullmatch(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)", selected.get("content-range", ""))
            if (status != 206 or not expected or int(expected[1]) != start or int(expected[2]) - start + 1 != len(payload)
                    or len(payload) != min(length, int(expected[3]) - start)):
                denied("google_range_mismatch", "Google did not return the requested object range.")
            if selected.get("x-goog-generation") not in (None, params["generation"]):
                denied("google_generation_mismatch", "The export object's generation changed.")
        elif operation not in ('drive_file_download','drive_file_export'):
            try:
                decoded = json.loads(payload)
                if not isinstance(decoded, dict):
                    raise ValueError()
            except (ValueError, UnicodeError):
                denied("google_response_invalid", "Google did not return a valid JSON object.")
            if operation == "identity":
                payload = json.dumps({k: decoded.get(k) for k in ("email", "email_verified", "sub")}).encode()
        return {"http_status": status, "headers": selected, "body_bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}, payload
