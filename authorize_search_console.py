#!/usr/bin/env python3
"""Owner-run, fresh Search Console consent; no vault access or broker export.

Run on the same machine as the owner's ordinary browser. The original Desktop
client download is an explicit private input. The new grant is written only to
a new owner-only file outside Git, for the owner to enter into OpenBao normally.
Google dependencies are imported only when consent is explicitly started.
"""

import argparse
import contextlib
import http.client
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import unquote, urlsplit


SCOPES = (
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/webmasters.readonly",
)
CAPABILITIES = (
    "identity", "sites_list", "site_get", "sitemaps_list",
    "searchanalytics_query", "url_inspection",
)
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
TOKEN_URI = "https://oauth2.googleapis.com/token"
AUTH_URIS = {
    "https://accounts.google.com/o/oauth2/auth",
    "https://accounts.google.com/o/oauth2/v2/auth",
}
CODE_ROOT = Path(__file__).resolve().parent
MAX_JSON = 65536
TIMEOUT_SECONDS = 300


class AuthorizationStopped(Exception):
    """A deliberately nonsecret failure suitable for displaying to the owner."""


PHASES = frozenset({"input_preflight", "private_input", "load_dependencies",
                   "oauth_setup", "browser_callback", "token_exchange",
                   "scope_verification", "userinfo", "serialization", "private_save"})
# Only these constant labels may leave the helper. Exception messages, args,
# provider error bodies and arbitrary exception class names are never displayed.
EXCEPTION_LABELS = {
    ("google_auth_oauthlib.flow", "WSGITimeoutError"): ("callback_timeout", "WSGITimeoutError"),
    ("webbrowser", "Error"): ("browser_unavailable", "BrowserError"),
    ("requests.exceptions", "SSLError"): ("network_tls", "SSLError"),
    ("ssl", "SSLError"): ("network_tls", "SSLError"),
    ("requests.exceptions", "Timeout"): ("network_timeout", "Timeout"),
    ("requests.exceptions", "ConnectionError"): ("network_connection", "ConnectionError"),
    ("requests.exceptions", "RequestException"): ("network_request", "RequestException"),
    ("google.auth.exceptions", "TransportError"): ("network_request", "TransportError"),
    ("google.auth.exceptions", "RefreshError"): ("google_refresh", "RefreshError"),
    ("oauthlib.oauth2.rfc6749.errors", "InvalidGrantError"): ("oauth_invalid_grant", "InvalidGrantError"),
    ("oauthlib.oauth2.rfc6749.errors", "InvalidClientError"): ("oauth_invalid_client", "InvalidClientError"),
    ("oauthlib.oauth2.rfc6749.errors", "AccessDeniedError"): ("oauth_access_denied", "AccessDeniedError"),
    ("oauthlib.oauth2.rfc6749.errors", "MismatchingStateError"): ("oauth_state_mismatch", "MismatchingStateError"),
    ("oauthlib.oauth2.rfc6749.errors", "MissingTokenError"): ("oauth_token_missing", "MissingTokenError"),
    ("oauthlib.oauth2.rfc6749.errors", "MissingCodeError"): ("oauth_code_missing", "MissingCodeError"),
    ("oauthlib.oauth2.rfc6749.errors", "MissingTokenTypeError"): ("oauth_token_type_missing", "MissingTokenTypeError"),
    ("oauthlib.oauth2.rfc6749.errors", "UnauthorizedClientError"): ("oauth_unauthorized_client", "UnauthorizedClientError"),
    ("oauthlib.oauth2.rfc6749.errors", "InvalidScopeError"): ("oauth_invalid_scope", "InvalidScopeError"),
    ("oauthlib.oauth2.rfc6749.errors", "UnsupportedGrantTypeError"): ("oauth_unsupported_grant_type", "UnsupportedGrantTypeError"),
    ("oauthlib.oauth2.rfc6749.errors", "InsecureTransportError"): ("oauth_insecure_transport", "InsecureTransportError"),
    ("oauthlib.oauth2.rfc6749.errors", "ServerError"): ("oauth_server_error", "ServerError"),
    ("oauthlib.oauth2.rfc6749.errors", "TemporarilyUnavailableError"): ("oauth_temporarily_unavailable", "TemporarilyUnavailableError"),
    ("oauthlib.oauth2.rfc6749.errors", "OAuth2Error"): ("oauth_rejected", "OAuth2Error"),
    ("json.decoder", "JSONDecodeError"): ("invalid_json", "JSONDecodeError"),
    ("builtins", "ModuleNotFoundError"): ("dependency_missing", "ModuleNotFoundError"),
    ("builtins", "ImportError"): ("dependency_import", "ImportError"),
    ("builtins", "PermissionError"): ("local_permissions", "PermissionError"),
    ("builtins", "FileExistsError"): ("output_exists", "FileExistsError"),
    ("builtins", "FileNotFoundError"): ("local_path_missing", "FileNotFoundError"),
    ("builtins", "TimeoutError"): ("timeout", "TimeoutError"),
    ("builtins", "OSError"): ("local_io", "OSError"),
    ("builtins", "KeyboardInterrupt"): ("cancelled", "KeyboardInterrupt"),
    ("builtins", "UnicodeError"): ("text_decoding", "UnicodeError"),
    ("builtins", "TypeError"): ("runtime_type", "TypeError"),
    ("builtins", "ValueError"): ("runtime_value", "ValueError"),
    ("builtins", "KeyError"): ("runtime_field", "KeyError"),
    ("builtins", "AttributeError"): ("runtime_interface", "AttributeError"),
    ("builtins", "RuntimeError"): ("runtime_error", "RuntimeError"),
}
OAUTH_ERROR_CATEGORIES = {
    "invalid_request": "oauth_invalid_request",
    "unauthorized_client": "oauth_unauthorized_client",
    "invalid_scope": "oauth_invalid_scope",
    "unsupported_grant_type": "oauth_unsupported_grant_type",
    "missing_code": "oauth_code_missing",
    "insecure_transport": "oauth_insecure_transport",
    "server_error": "oauth_server_error",
    "temporarily_unavailable": "oauth_temporarily_unavailable",
    "redirect_uri_mismatch": "oauth_redirect_uri_mismatch",
    "invalid_grant": "oauth_invalid_grant",
    "invalid_client": "oauth_invalid_client",
    "access_denied": "oauth_access_denied",
    "mismatching_state": "oauth_state_mismatch",
    "missing_token": "oauth_token_missing",
    "missing_token_type": "oauth_token_type_missing",
}


class AuthorizationFailure(Exception):
    """A phase and fixed error classification, containing no original details."""
    def __init__(self, phase, error):
        self.phase = phase if phase in PHASES else "input_preflight"
        self.category, self.exception_label = "unexpected_error", "UnclassifiedError"
        if (type(error) is Warning and self.phase == "token_exchange"
                and {"old_scope", "new_scope"}.issubset(vars(error))):
            self.category, self.exception_label = "scope_changed", "OAuthScopeWarning"
        else:
            for cls in type(error).__mro__:
                labels = EXCEPTION_LABELS.get((cls.__module__, cls.__name__))
                if labels is not None:
                    self.category, self.exception_label = labels
                    break
            oauth_module = sys.modules.get("oauthlib.oauth2.rfc6749.errors")
            oauth_base = getattr(oauth_module, "OAuth2Error", None)
            if (isinstance(oauth_base, type) and oauth_base in type(error).__mro__
                    and (oauth_base.__module__, oauth_base.__name__)
                    == ("oauthlib.oauth2.rfc6749.errors", "OAuth2Error")):
                # oauthlib 4 maps several invalid_request variants to the first
                # matching class (InvalidClientIdError). The protocol enum, not
                # that misleading subclass name, determines this fixed category.
                enum = getattr(error, "error", None)
                category = OAUTH_ERROR_CATEGORIES.get(enum) if type(enum) is str else None
                if category is not None:
                    self.category = category
                else:
                    self.category, self.exception_label = "oauth_rejected", "OAuth2Error"
        super().__init__("Authorization stopped at phase=" + self.phase
                         + "; category=" + self.category
                         + "; exception=" + self.exception_label
                         + ". No grant contents or provider details are displayed.")


@contextlib.contextmanager
def diagnostic_phase(phase):
    try:
        yield
    except AuthorizationStopped as error:
        # stop() messages are trusted constants, never provider text.
        raise AuthorizationStopped(str(error) + " [phase=" + phase + "]") from None
    except AuthorizationFailure:
        raise
    except (Exception, KeyboardInterrupt) as error:
        raise AuthorizationFailure(phase, error) from None


def stop(message="Authorization stopped; no new grant was saved."):
    raise AuthorizationStopped(message)


def _text(value, maximum=4096):
    return (isinstance(value, str) and 0 < len(value) <= maximum
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def validate_account(account):
    if (not _text(account, 254) or not re.fullmatch(
            r"[A-Za-z0-9._+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}", account)):
        stop("Supply the expected actual Google sign-in email.")
    return account.casefold()


def validate_domain(domain):
    if (not _text(domain, 253) or domain != domain.lower()
            or "." not in domain or not all(re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in domain.split("."))):
        stop("Supply a plain lowercase DNS domain without a scheme or path.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    stop("Supply a DNS domain, not an IP address.")


def validate_property(property_name, domain):
    if property_name is None:
        return None
    if (not _text(property_name, 2048)
            or any(c.isspace() or ord(c) > 126 for c in property_name)):
        stop("The selected Search Console property is invalid.")
    if property_name.startswith("sc-domain:"):
        host = validate_domain(property_name[len("sc-domain:"):])
    else:
        try:
            parts = urlsplit(property_name)
            host = parts.hostname
            if (parts.scheme not in ("https", "http") or not host
                    or parts.netloc != host or parts.query or parts.fragment
                    or not parts.path.startswith("/")
                    or not parts.path.endswith("/")):
                stop("Use an exact HTTP(S) URL-prefix property ending in /.")
            decoded = parts.path
            for _ in range(3):
                decoded = unquote(decoded)
            if (not _text(decoded) or any(c.isspace() or ord(c) > 126 for c in decoded)
                    or "\\" in decoded or "//" in decoded
                    or any(p in (".", "..") for p in decoded.split("/"))
                    or "%" in decoded):
                stop("The selected Search Console property is invalid.")
            validate_domain(host)
        except ValueError:
            stop("The selected Search Console property is invalid.")
    if host != domain and not host.endswith("." + domain):
        stop("The selected property must belong to the specified domain.")
    return property_name


def _absolute_path(value):
    if (not _text(str(value)) or not Path(value).is_absolute()
            or ".." in str(value).split("/") or Path(value).suffix != ".json"):
        stop("Use an absolute private JSON file path without parent traversal.")
    return Path(value)


def _credential_text(value):
    return _text(value, 16384) and all(33 <= ord(c) <= 126 for c in value)


def _private_parent(path, *, output=False):
    """Open directories without following symlinks; retain a safe final dirfd."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        stop("This helper requires POSIX owner-only file permissions.")
    if output:
        protected = (CODE_ROOT,)
        if any(path == root or root in path.parents for root in protected):
            stop("The grant output must be outside the code and context checkouts.")
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parent.parts[1:]:
            if output:
                try:
                    os.stat(".git", dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    stop("The grant output must be outside every Git checkout.")
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                              dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if output:
            try:
                os.stat(".git", dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                stop("The grant output must be outside every Git checkout.")
        info = os.fstat(fd)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            stop("Use an existing owner-only private parent directory with mode 0700.")
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def output_target(value):
    path = _absolute_path(value)
    fd = _private_parent(path, output=True)
    try:
        try:
            os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            stop("The output already exists; choose a new private filename.")
        yield path, fd
    finally:
        os.close(fd)


def read_desktop_client(value, cloud_project):
    path = _absolute_path(value)
    parent_fd = _private_parent(path)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o077):
                stop("The original Desktop JSON must be an owner-only regular file.")
            raw = source.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            stop()
        data = json.loads(raw)
    finally:
        os.close(parent_fd)
    if not isinstance(data, dict) or "web" in data:
        stop("Use the original Desktop application download, not a Web client.")
    client = data.get("installed")
    if (not isinstance(client, dict) or client.get("project_id") != cloud_project
            or client.get("auth_uri") not in AUTH_URIS
            or client.get("token_uri") != TOKEN_URI
            or not _credential_text(client.get("client_secret"))
            or not _text(client.get("client_id"))
            or not re.fullmatch(r"[0-9]+-[A-Za-z0-9_-]+\.apps\.googleusercontent\.com", client["client_id"])):
        stop("Use the original Desktop client from the explicitly selected Cloud project.")
    # Pass only the required, validated registration to the maintained library.
    return {"installed": {key: client[key] for key in (
        "client_id", "client_secret", "project_id", "auth_uri", "token_uri")}}


def _scope_set(value):
    if isinstance(value, str):
        value = value.split()
    if (not isinstance(value, (list, tuple, set))
            or not all(_text(item) for item in value)):
        stop()
    return {"https://www.googleapis.com/auth/userinfo.email" if item == "email"
            else item for item in value}


def actual_scopes(flow, credentials):
    token = flow.oauth2session.token
    if not isinstance(token, dict):
        stop()
    returned = token.get("scope")
    granted = getattr(credentials, "granted_scopes", None)
    scopes = _scope_set(granted if granted is not None else returned)
    if returned is not None and _scope_set(returned) != scopes:
        stop()
    if scopes != set(SCOPES):
        stop("The granted permissions do not exactly match the three GSC scopes.")
    if str(token.get("token_type", "")).casefold() != "bearer":
        stop()
    if not _credential_text(getattr(credentials, "refresh_token", None)):
        stop("Google did not issue the required fresh offline grant.")
    return scopes


@contextlib.contextmanager
def quiet_authentication():
    """Do not expose URLs, callback codes, responses or HTTP debug to terminals."""
    previous = logging.root.manager.disable
    http_debug = http.client.HTTPConnection.debuglevel
    https_debug = http.client.HTTPSConnection.debuglevel
    logging.disable(logging.CRITICAL)
    http.client.HTTPConnection.debuglevel = 0
    http.client.HTTPSConnection.debuglevel = 0
    try:
        with open(os.devnull, "w") as sink:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                yield
    finally:
        http.client.HTTPConnection.debuglevel = http_debug
        http.client.HTTPSConnection.debuglevel = https_debug
        logging.disable(previous)


def load_dependencies():
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import AuthorizedSession
    return InstalledAppFlow, AuthorizedSession


def consent(client, account):
    phase = "load_dependencies"
    try:
        Flow, Session = load_dependencies()
        phase = "oauth_setup"
        flow = Flow.from_client_config(client, scopes=list(SCOPES),
                                      autogenerate_code_verifier=True)
        original_fetch = flow.fetch_token

        def fetch_token(*args, **kwargs):
            nonlocal phase
            phase = "token_exchange"
            kwargs.setdefault("timeout", 30)
            # Google's Desktop exchange specifies client fields in the form.
            # Explicit inclusion also prevents requests-oauthlib choosing Basic.
            kwargs["include_client_id"] = True
            return original_fetch(*args, **kwargs)

        # run_local_server has no token-fetch timeout option. Wrap its public
        # exchange method without changing TLS, scopes, retries or responses.
        flow.fetch_token = fetch_token
        phase = "browser_callback"
        credentials = flow.run_local_server(
            host="127.0.0.1", bind_addr="127.0.0.1", port=0,
            timeout_seconds=TIMEOUT_SECONDS, open_browser=True,
            authorization_prompt_message=None,
            success_message="Return to the owner-run helper. Verification is continuing.",
            prompt="select_account consent", login_hint=account,
            access_type="offline", include_granted_scopes="false",
        )
        phase = "scope_verification"
        scopes = actual_scopes(flow, credentials)
        phase = "userinfo"
        with Session(credentials, refresh_timeout=15) as session:
            response = session.get(USERINFO_URL, timeout=15, allow_redirects=False)
            if response.status_code != 200 or len(response.content) > MAX_JSON:
                stop()
            identity = response.json()
        if (not isinstance(identity, dict) or identity.get("email_verified") is not True
                or not _text(identity.get("email"), 254)
                or identity["email"].casefold() != account):
            stop("The consenting verified Google identity did not match the expected account.")
        email = identity["email"]
        phase = "serialization"
        grant = json.loads(credentials.to_json(strip=["token", "expiry", "rapt_token"]))
        original = client["installed"]
        if (not isinstance(grant, dict)
                or any(grant.get(key) != original[key] for key in ("client_id", "client_secret"))
                or grant.get("refresh_token") != credentials.refresh_token
                or grant.get("token_uri", TOKEN_URI) != TOKEN_URI):
            stop()
        grant.update(type="authorized_user", account=email, token_uri=TOKEN_URI,
                     scopes=sorted(scopes))
        # Never persist an access token or ID token, including unexpected fields.
        grant = {key: grant[key] for key in (
            "type", "account", "client_id", "client_secret", "refresh_token",
            "token_uri", "scopes")}
        return email, grant
    except AuthorizationStopped as error:
        raise AuthorizationStopped(str(error) + " [phase=" + phase + "]") from None
    except AuthorizationFailure:
        raise
    except (Exception, KeyboardInterrupt) as error:
        raise AuthorizationFailure(phase, error) from None


def make_record(email, grant, domain, property_name, cloud_project):
    profile = {
        "version": 1, "account": email, "domain": domain,
        "grant_field": "authorized_user_json", "scopes": list(SCOPES),
        "capabilities": list(CAPABILITIES),
    }
    if property_name is not None:
        profile["property"] = property_name
    return {
        "purpose": "Owner-consented Search Console read-only grant",
        "cloud_project_id": cloud_project,
        "account_email": email, "_google_search_console": profile,
        "authorized_user_json": grant,
    }


def write_record(target, record):
    path, parent_fd = target
    payload = (json.dumps(record, indent=2) + "\n").encode("utf-8")
    if len(payload) > MAX_JSON:
        stop()
    # Consent can take minutes. Recheck permissions, Git ancestors and the path
    # before opening the new file; never follow a substituted parent directory.
    current_fd = _private_parent(path, output=True)
    try:
        original, current = os.fstat(parent_fd), os.fstat(current_fd)
        if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
            stop()
    finally:
        os.close(current_fd)
    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=parent_fd)
    created = os.fstat(fd)
    try:
        with os.fdopen(fd, "wb") as destination:
            os.fchmod(destination.fileno(), 0o600)
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
    except BaseException:
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
                os.unlink(path.name, dir_fd=parent_fd)
        except OSError:
            pass
        raise


def authorize(client_json, account, output, domain, cloud_project, property_name=None):
    account = validate_account(account)
    domain = validate_domain(domain)
    if not isinstance(cloud_project, str) or not re.fullmatch(r"[a-z][a-z0-9-]{4,28}[a-z0-9]", cloud_project):
        stop("Supply the expected Google Cloud project ID.")
    property_name = validate_property(property_name, domain)
    with output_target(output) as target:
        with quiet_authentication():
            with diagnostic_phase("private_input"):
                client = read_desktop_client(client_json, cloud_project)
            email, grant = consent(client, account)
            with diagnostic_phase("private_save"):
                write_record(target, make_record(email, grant, domain, property_name, cloud_project))
        return target[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client-json", required=True, help="Original private Desktop client JSON")
    parser.add_argument("--account", required=True, help="Expected actual Google sign-in email")
    parser.add_argument("--output", required=True, help="New absolute JSON path in an existing private directory")
    parser.add_argument("--domain", required=True)
    parser.add_argument("--cloud-project", required=True, help="Expected Google Cloud project ID")
    parser.add_argument("--property", dest="property_name", help="Exact verified GSC property; omit for discovery only")
    args = parser.parse_args(argv)
    try:
        path = authorize(**vars(args))
    except (AuthorizationStopped, AuthorizationFailure) as error:
        print(str(error), file=sys.stderr)
        return 1
    except (Exception, KeyboardInterrupt) as error:
        print(str(AuthorizationFailure("input_preflight", error)), file=sys.stderr)
        return 1
    print("Verified new grant saved privately: " + str(path))
    print("Owner: enter this file at your chosen project's credential path using the OpenBao JSON editor.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
