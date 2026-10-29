"""Offline owner-bootstrap checks using fabricated registrations and tokens."""

import contextlib
import copy
import importlib.util
import io
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("authorize_search_console", ROOT / "authorize_search_console.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)

EMAIL = "owner@example.com"
SECRET = "FIXTURE-PRIVATE-CLIENT-SECRET"
REFRESH = "FIXTURE-PRIVATE-REFRESH-TOKEN"
ACCESS = "FIXTURE-PRIVATE-ACCESS-TOKEN"
CLIENT = {"installed": {
    "client_id": "123456-fabricated.apps.googleusercontent.com",
    "client_secret": SECRET, "project_id": "demo-cloud-project",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": auth.TOKEN_URI,
}}


class FakeCredentials:
    def __init__(self):
        self.refresh_token = REFRESH
        self.granted_scopes = list(auth.SCOPES)

    def to_json(self, strip=None):
        self.strip = strip
        return json.dumps({
            **CLIENT["installed"], "refresh_token": self.refresh_token,
            "scopes": ["REQUESTED-METADATA-IS-NOT-PROOF"], "token": ACCESS,
            "id_token": "FIXTURE-ID-TOKEN", "rapt_token": "FIXTURE-RAPT",
        })


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name)
        self.private.chmod(0o700)
        # The execution platform inserts a synthetic .git in the shared temporary
        # mount. Ignore that shared-root marker only in this fixture; markers
        # anywhere inside the fixture still exercise the real rejection logic.
        original_stat = os.stat
        temporary_root = original_stat(self.private.parent)

        def fixture_stat(path, *args, **kwargs):
            if path == ".git" and kwargs.get("dir_fd") is not None:
                directory = os.fstat(kwargs["dir_fd"])
                if (directory.st_dev, directory.st_ino) == (temporary_root.st_dev, temporary_root.st_ino):
                    raise FileNotFoundError(path)
            return original_stat(path, *args, **kwargs)

        stat_patch = patch.object(auth.os, "stat", side_effect=fixture_stat)
        stat_patch.start()
        self.addCleanup(stat_patch.stop)
        self.client_file = self.private / "client.json"
        self.client_file.write_text(json.dumps(CLIENT))
        self.client_file.chmod(0o600)
        self.output = self.private / "grant.json"
        self.credentials = FakeCredentials()
        self.flow = SimpleNamespace(oauth2session=SimpleNamespace(token={
            "scope": " ".join(auth.SCOPES), "token_type": "Bearer",
        }), fetch_token=lambda **kwargs: self.calls.setdefault("token_exchange", kwargs))
        self.identity = {"email": EMAIL, "email_verified": True, "sub": "fixture-sub"}
        self.userinfo_status = 200
        self.calls = {}
        owner = self

        class FakeFlow:
            @staticmethod
            def from_client_config(client, **kwargs):
                owner.calls["client"] = client
                owner.calls["constructor"] = kwargs
                return owner.flow

        def run_local_server(**kwargs):
            owner.calls["consent"] = kwargs
            print(ACCESS)
            logging.getLogger("google_auth_oauthlib.flow").critical(REFRESH)
            owner.flow.fetch_token(authorization_response="FIXTURE-CALLBACK")
            return owner.credentials

        self.flow.run_local_server = run_local_server

        class FakeSession:
            def __init__(self, credentials, **kwargs):
                owner.assertIs(credentials, owner.credentials)
                owner.calls["session"] = kwargs

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def get(self, url, **kwargs):
                owner.calls["userinfo"] = (url, kwargs)
                return SimpleNamespace(status_code=owner.userinfo_status, content=b"{}", json=lambda: owner.identity)

        self.dependencies = patch.object(auth, "load_dependencies", return_value=(FakeFlow, FakeSession))
        self.dependencies.start()
        self.addCleanup(self.dependencies.stop)

    def run_authorize(self, **kwargs):
        return auth.authorize(str(self.client_file), EMAIL, str(self.output),
                              **{"domain": "example.test", "cloud_project": "demo-cloud-project", **kwargs})

    def assert_stops_without_output(self, **kwargs):
        with self.assertRaises(auth.AuthorizationStopped):
            self.run_authorize(**kwargs)
        self.assertFalse(self.output.exists())

    def test_userinfo_rejection_reports_only_safe_phase_and_leaves_no_file(self):
        self.userinfo_status = 401
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            result = auth.main(['--client-json', str(self.client_file), '--account', EMAIL,
                                '--output', str(self.output), '--domain', 'example.test', '--cloud-project', 'demo-cloud-project'])
        self.assertEqual(result, 1)
        self.assertIn('phase=userinfo', output.getvalue())
        self.assertFalse(self.output.exists())
        for value in (SECRET, REFRESH, ACCESS):
            self.assertNotIn(value, output.getvalue())

    def test_fresh_consent_exact_scopes_identity_and_private_record(self):
        self.assertEqual(self.run_authorize(), self.output)
        record = json.loads(self.output.read_text())
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        profile = record["_google_search_console"]
        self.assertEqual(profile["account"], EMAIL)
        self.assertEqual(profile["domain"], "example.test")
        self.assertEqual(set(profile["scopes"]), set(auth.SCOPES))
        self.assertEqual(profile["capabilities"], list(auth.CAPABILITIES))
        self.assertNotIn("property", profile)
        grant = record["authorized_user_json"]
        self.assertEqual(grant["type"], "authorized_user")
        self.assertEqual(grant["account"], EMAIL)
        self.assertEqual(grant["refresh_token"], REFRESH)
        self.assertEqual(set(grant["scopes"]), set(auth.SCOPES))
        self.assertNotIn(ACCESS, self.output.read_text())
        self.assertNotIn("id_token", grant)
        self.assertNotIn("_google_migration", record)
        self.assertNotIn("_http", record)
        self.assertEqual(self.calls["constructor"]["autogenerate_code_verifier"], True)
        config = self.calls["consent"]
        self.assertEqual((config["host"], config["bind_addr"], config["port"]), ("127.0.0.1", "127.0.0.1", 0))
        self.assertGreater(config["timeout_seconds"], 0)
        self.assertEqual(config["include_granted_scopes"], "false")
        self.assertEqual(config["access_type"], "offline")
        self.assertEqual(set(config["prompt"].split()), {"consent", "select_account"})
        self.assertIsNone(config["authorization_prompt_message"])
        self.assertEqual(self.calls["userinfo"], (auth.USERINFO_URL, {"timeout": 15, "allow_redirects": False}))
        self.assertEqual(self.calls["session"], {"refresh_timeout": 15})
        self.assertEqual(self.calls["token_exchange"]["timeout"], 30)
        self.assertIs(self.calls["token_exchange"]["include_client_id"], True)

    def test_wrong_identity_or_unverified_email_is_rejected(self):
        for identity in ({"email": "other@example.com", "email_verified": True},
                         {"email": EMAIL, "email_verified": False}):
            with self.subTest(identity=identity):
                self.identity = identity
                self.assert_stops_without_output()

    def test_another_explicit_project_and_domain_can_be_used(self):
        data = copy.deepcopy(CLIENT)
        data['installed']['project_id'] = 'another-cloud-project'
        self.client_file.write_text(json.dumps(data))
        self.run_authorize(cloud_project='another-cloud-project', domain='another.example.test')
        record = json.loads(self.output.read_text())
        self.assertEqual(record['cloud_project_id'], 'another-cloud-project')
        self.assertEqual(record['_google_search_console']['domain'], 'another.example.test')
        self.assertNotIn('cloud_project_number', record)

    def test_missing_explicit_consent_settings_fail_before_authentication(self):
        for arguments in (['--cloud-project', 'demo-cloud-project'], ['--domain', 'example.test']):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    auth.main(['--client-json', str(self.client_file), '--account', EMAIL,
                               '--output', str(self.output), *arguments])
        self.assertNotIn('consent', self.calls)

    def test_desktop_body_client_fields_cannot_be_disabled_by_sdk_kwargs(self):
        def run_local_server(**kwargs):
            self.flow.fetch_token(include_client_id=False)
            return self.credentials
        self.flow.run_local_server = run_local_server
        self.run_authorize()
        self.assertIs(self.calls["token_exchange"]["include_client_id"], True)

    def test_actual_granted_scopes_are_required_not_requested_metadata(self):
        self.credentials.granted_scopes = None
        self.flow.oauth2session.token.pop("scope")
        self.assert_stops_without_output()

    def test_wrong_missing_or_expanded_scopes_are_rejected(self):
        for scopes in ([], [auth.SCOPES[0]], list(auth.SCOPES) + ["https://www.googleapis.com/auth/content"]):
            with self.subTest(scopes=scopes):
                self.credentials.granted_scopes = scopes
                self.flow.oauth2session.token["scope"] = " ".join(scopes)
                self.assert_stops_without_output()

    def test_token_scope_fallback_and_email_alias(self):
        self.credentials.granted_scopes = None
        self.flow.oauth2session.token["scope"] = " ".join(auth.SCOPES).replace(auth.SCOPES[1], "email")
        self.run_authorize()
        self.assertTrue(self.output.is_file())

    def test_disagreeing_actual_scope_sources_are_rejected(self):
        self.flow.oauth2session.token["scope"] = "openid"
        self.assert_stops_without_output()

    def test_missing_refresh_or_nonbearer_token_is_rejected(self):
        self.credentials.refresh_token = None
        self.assert_stops_without_output()
        self.credentials.refresh_token = REFRESH
        self.flow.oauth2session.token["token_type"] = "Other"
        self.assert_stops_without_output()

    def test_selected_property_is_preserved_and_validated(self):
        for property_name in ("sc-domain:example.test", "https://account.example.test/", "https://example.test/pages/"):
            with self.subTest(property_name=property_name):
                self.run_authorize(property_name=property_name)
                self.assertEqual(json.loads(self.output.read_text())["_google_search_console"]["property"], property_name)
                self.output.unlink()
        for property_name in ("sc-domain:evil.example", "https://evil-example.test/", "https://example.test@evil.example/", "https://example.test/%2e%2e/", "https://example.test/?token=x", "https://example.test/a b/", "https://example.test/a%20b/"):
            with self.subTest(property_name=property_name):
                self.assert_stops_without_output(property_name=property_name)

    def test_ip_addresses_are_not_allocatable_domains(self):
        self.assert_stops_without_output(domain="127.0.0.1")

    def test_existing_file_and_output_symlink_are_never_overwritten(self):
        self.output.write_text("preserve unrelated contents")
        self.assertRaises(auth.AuthorizationStopped, self.run_authorize)
        self.assertEqual(self.output.read_text(), "preserve unrelated contents")
        self.output.unlink()
        self.output.symlink_to(self.client_file)
        self.assertRaises(auth.AuthorizationStopped, self.run_authorize)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(json.loads(self.client_file.read_text()), CLIENT)
        self.assertNotIn("consent", self.calls)

    def test_parent_symlink_missing_parent_and_insecure_parent_are_rejected(self):
        link = self.private / "alias"
        link.symlink_to(self.private, target_is_directory=True)
        with self.assertRaises(OSError):
            auth.authorize(str(self.client_file), EMAIL, str(link / "grant.json"), "example.test", "demo-cloud-project")
        self.assertFalse(self.output.exists())
        with self.assertRaises(OSError):
            auth.authorize(str(self.client_file), EMAIL, str(self.private / "missing" / "grant.json"), "example.test", "demo-cloud-project")
        self.private.chmod(0o755)
        self.assert_stops_without_output()

    def test_git_directory_or_worktree_file_is_rejected(self):
        for worktree_file in (False, True):
            marker = self.private / ".git"
            if worktree_file:
                marker.write_text("gitdir: ../external-git")
            else:
                marker.mkdir()
            with self.subTest(worktree_file=worktree_file):
                self.assert_stops_without_output()
            if marker.is_dir():
                marker.rmdir()
            else:
                marker.unlink()
        with self.assertRaises(auth.AuthorizationStopped):
            with auth.output_target(str(ROOT / "grant.json")):
                pass

    def test_private_client_must_be_desktop_from_selected_project(self):
        for change in ({"project_id": "other-project"}, {"token_uri": "https://evil.example/token"}, {"auth_uri": "https://evil.example/auth"}):
            data = copy.deepcopy(CLIENT)
            data["installed"].update(change)
            self.client_file.write_text(json.dumps(data))
            with self.subTest(change=change):
                self.assert_stops_without_output()
        self.client_file.write_text(json.dumps({"web": CLIENT["installed"]}))
        self.assert_stops_without_output()

    def test_output_creation_is_exclusive_even_after_preflight(self):
        with auth.output_target(str(self.output)) as target:
            self.output.write_text("created during consent")
            with self.assertRaises(FileExistsError):
                auth.write_record(target, {"fabricated": REFRESH})
        self.assertEqual(self.output.read_text(), "created during consent")

    def test_output_parent_is_rechecked_after_consent(self):
        with auth.output_target(str(self.output)) as target:
            (self.private / ".git").mkdir()
            with self.assertRaises(auth.AuthorizationStopped):
                auth.write_record(target, {"fabricated": REFRESH})
        self.assertFalse(self.output.exists())
        (self.private / ".git").rmdir()
        with auth.output_target(str(self.output)) as target:
            self.private.chmod(0o755)
            with self.assertRaises(auth.AuthorizationStopped):
                auth.write_record(target, {"fabricated": REFRESH})
        self.assertFalse(self.output.exists())

    def test_new_file_is_0600_even_with_restrictive_umask(self):
        previous = os.umask(0o777)
        try:
            self.run_authorize()
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)

    def test_terminal_output_never_contains_tokens_or_provider_exception(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = auth.main(["--client-json", str(self.client_file), "--account", EMAIL, "--output", str(self.output), "--domain", "example.test", "--cloud-project", "demo-cloud-project"])
        self.assertEqual(result, 0)
        self.assertIn("your chosen project", stdout.getvalue())
        self.assertIn(str(self.output), stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        for secret in (SECRET, REFRESH, ACCESS):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        self.output.unlink()
        def provider_failure(**kwargs):
            print(ACCESS)
            raise RuntimeError("provider response contains " + SECRET)
        self.flow.run_local_server = provider_failure
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = auth.main(["--client-json", str(self.client_file), "--account", EMAIL, "--output", str(self.output), "--domain", "example.test", "--cloud-project", "demo-cloud-project"])
        self.assertEqual(result, 1)
        for secret in (SECRET, REFRESH, ACCESS, "Traceback"):
            self.assertNotIn(secret, stdout.getvalue() + stderr.getvalue())
        self.assertFalse(self.output.exists())

    def test_fixed_phase_categories_never_inspect_exception_text(self):
        class UnsafeError(Exception):
            def __str__(self):
                raise AssertionError("Exception text must never be inspected")
        cases = [("load_dependencies", ModuleNotFoundError(SECRET), "dependency_missing"),
                 ("oauth_setup", TypeError(SECRET), "runtime_type"),
                 ("scope_verification", ValueError(SECRET), "runtime_value"),
                 ("serialization", json.JSONDecodeError(SECRET, ACCESS, 0), "invalid_json"),
                 ("private_save", PermissionError(SECRET), "local_permissions"),
                 ("userinfo", UnsafeError(SECRET), "unexpected_error")]
        for phase, error, category in cases:
            with self.subTest(phase=phase):
                result = str(auth.AuthorizationFailure(phase, error))
                self.assertIn("phase=" + phase, result)
                self.assertIn("category=" + category, result)
                for private in (SECRET, ACCESS, REFRESH, "UnsafeError", "Traceback"):
                    self.assertNotIn(private, result)

    def test_failures_are_attributed_to_dependency_userinfo_serialization_and_save(self):
        scenarios = [("load_dependencies", "load_dependencies", ModuleNotFoundError(SECRET)),
                     ("actual_scopes", "scope_verification", RuntimeError(SECRET)),
                     ("write_record", "private_save", PermissionError(SECRET))]
        for method, phase, error in scenarios:
            with self.subTest(phase=phase), patch.object(auth, method, side_effect=error):
                with self.assertRaises(auth.AuthorizationFailure) as caught:
                    self.run_authorize()
                self.assertEqual(caught.exception.phase, phase)
                self.assertFalse(self.output.exists())
        with patch.object(self.credentials, "to_json", side_effect=ValueError(SECRET)):
            with self.assertRaises(auth.AuthorizationFailure) as caught:
                self.run_authorize()
            self.assertEqual(caught.exception.phase, "serialization")
        session = auth.load_dependencies.return_value[1]
        with patch.object(session, "get", side_effect=RuntimeError(SECRET)):
            with self.assertRaises(auth.AuthorizationFailure) as caught:
                self.run_authorize()
            self.assertEqual(caught.exception.phase, "userinfo")


class RealLibraryOfflineTests(unittest.TestCase):
    """Exercise installed maintained SDK code with every external boundary mocked."""
    def setUp(self):
        try:
            import requests
            import google_auth_oauthlib.flow as flow_module
        except ImportError:
            self.skipTest("Install requirements-bootstrap.lock to exercise the maintained SDK")
        self.requests, self.flow_module = requests, flow_module
        self.mode = "success"
        self.token_error = None
        self.state = None
        self.calls = []
        owner = self

        class Browser:
            def open(self, url, **kwargs):
                from urllib.parse import parse_qs, urlsplit
                query = parse_qs(urlsplit(url).query)
                owner.assertEqual(set(query["scope"][0].split()), set(auth.SCOPES))
                owner.assertEqual(query["code_challenge_method"], ["S256"])
                owner.assertEqual(query["include_granted_scopes"], ["false"])
                owner.redirect_uri = query["redirect_uri"][0]
                owner.code_challenge = query["code_challenge"][0]
                owner.state = query["state"][0]
                return True

        class Server:
            server_port = 54321
            def __init__(self, app):
                self.app = app
            def handle_request(self):
                self.app.last_request_uri = ("http://127.0.0.1:54321/?code=FIXTURE-CODE&state="
                                             + owner.state)
            def server_close(self):
                pass

        def make_server(host, port, app, **kwargs):
            owner.assertEqual((host, port), ("127.0.0.1", 0))
            return Server(app)

        def request(session, method, url, **kwargs):
            owner.calls.append(url)
            if url == auth.TOKEN_URI:
                owner.assertEqual(kwargs["timeout"], 30)
                data = kwargs["data"]
                owner.assertEqual(data["client_id"], CLIENT["installed"]["client_id"])
                owner.assertEqual(data["client_secret"], SECRET)
                owner.assertIsNone(kwargs.get("auth"))
                owner.assertEqual(data["code"], "FIXTURE-CODE")
                owner.assertEqual(data["grant_type"], "authorization_code")
                owner.assertEqual(data["redirect_uri"], owner.redirect_uri)
                import base64
                import hashlib
                challenge = base64.urlsafe_b64encode(hashlib.sha256(
                    data["code_verifier"].encode()).digest()).decode().rstrip("=")
                owner.assertEqual(challenge, owner.code_challenge)
                if owner.mode == "tls":
                    raise requests.exceptions.SSLError(SECRET + ACCESS)
                if owner.mode in ("invalid_grant", "enum_error"):
                    payload = {"error": owner.token_error or "invalid_grant",
                               "error_description": SECRET, "state": ACCESS,
                               "error_uri": "https://example.test/" + REFRESH}
                else:
                    scopes = list(auth.SCOPES)
                    if owner.mode == "scope_changed":
                        scopes.append("https://www.googleapis.com/auth/content")
                    payload = {"access_token": ACCESS, "refresh_token": REFRESH,
                               "expires_in": 3600, "scope": " ".join(scopes), "token_type": "Bearer"}
            elif url == auth.USERINFO_URL:
                owner.assertEqual(kwargs["timeout"], 15)
                owner.assertIs(kwargs["allow_redirects"], False)
                if owner.mode == "userinfo_tls":
                    raise requests.exceptions.SSLError(SECRET + ACCESS)
                payload = {"email": EMAIL, "email_verified": True}
            else:
                raise AssertionError("Unexpected destination; all HTTP must remain mocked")
            response = requests.Response()
            response.status_code = 400 if owner.mode in ("invalid_grant", "enum_error") else 200
            response._content = json.dumps(payload).encode()
            response.headers["Content-Type"] = "application/json"
            response.request = SimpleNamespace(url=url, headers={}, body="FIXTURE")
            return response

        self.patches = [patch.object(flow_module.wsgiref.simple_server, "make_server", side_effect=make_server),
                        patch.object(flow_module.webbrowser, "get", return_value=Browser()),
                        patch.object(requests.sessions.Session, "request", request)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def test_real_sdk_success_with_none_prompt_and_exact_scope_evidence(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            with auth.quiet_authentication():
                email, grant = auth.consent(CLIENT, EMAIL)
        self.assertEqual(email, EMAIL)
        self.assertEqual(grant["type"], "authorized_user")
        self.assertEqual(grant["refresh_token"], REFRESH)
        self.assertEqual(set(grant["scopes"]), set(auth.SCOPES))
        self.assertEqual(self.calls, [auth.TOKEN_URI, auth.USERINFO_URL])
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        self.assertNotIn("token", grant)

    def test_real_sdk_failures_report_only_fixed_phase_and_category(self):
        for mode, phase, category in [("scope_changed", "token_exchange", "scope_changed"),
                                      ("invalid_grant", "token_exchange", "oauth_invalid_grant"),
                                      ("tls", "token_exchange", "network_tls"),
                                      ("userinfo_tls", "userinfo", "network_tls")]:
            self.mode, self.calls = mode, []
            stdout, stderr = io.StringIO(), io.StringIO()
            with self.subTest(mode=mode), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                with auth.quiet_authentication(), self.assertRaises(auth.AuthorizationFailure) as caught:
                    auth.consent(CLIENT, EMAIL)
            self.assertEqual(caught.exception.phase, phase)
            self.assertEqual(caught.exception.category, category)
            diagnostic = str(caught.exception) + stdout.getvalue() + stderr.getvalue()
            for private in (SECRET, ACCESS, REFRESH, "FIXTURE-CODE", "Traceback", "https://"):
                self.assertNotIn(private, diagnostic)

    def test_oauth_error_enums_are_fixed_and_invalid_request_is_not_a_bad_id_diagnosis(self):
        cases = [("invalid_request", "oauth_invalid_request"),
                 ("unauthorized_client", "oauth_unauthorized_client"),
                 ("invalid_scope", "oauth_invalid_scope"),
                 ("unsupported_grant_type", "oauth_unsupported_grant_type"),
                 ("missing_code", "oauth_code_missing"),
                 ("insecure_transport", "oauth_insecure_transport"),
                 ("server_error", "oauth_server_error"),
                 ("temporarily_unavailable", "oauth_temporarily_unavailable"),
                 ("redirect_uri_mismatch", "oauth_redirect_uri_mismatch"),
                 (SECRET + "\n" + ACCESS, "oauth_rejected")]
        for enum, category in cases:
            self.mode, self.token_error, self.calls = "enum_error", enum, []
            with self.subTest(category=category), auth.quiet_authentication():
                with self.assertRaises(auth.AuthorizationFailure) as caught:
                    auth.consent(CLIENT, EMAIL)
            self.assertEqual(caught.exception.category, category)
            self.assertEqual(caught.exception.phase, "token_exchange")
            self.assertEqual(self.calls, [auth.TOKEN_URI])
            message = str(caught.exception)
            for private in (SECRET, ACCESS, REFRESH, "https://", "InvalidClientIdError", "Traceback"):
                self.assertNotIn(private, message)

    def test_only_real_oauth_error_instances_can_use_protocol_enum_categories(self):
        error = RuntimeError(SECRET)
        error.error = "invalid_request"
        failure = auth.AuthorizationFailure("token_exchange", error)
        self.assertEqual(failure.category, "runtime_error")
        from oauthlib.oauth2.rfc6749.errors import CustomOAuth2Error
        custom = CustomOAuth2Error(error=SECRET, description=ACCESS, uri=REFRESH)
        failure = auth.AuthorizationFailure("token_exchange", custom)
        self.assertEqual(failure.category, "oauth_rejected")
        self.assertEqual(failure.exception_label, "OAuth2Error")
        for private in (SECRET, ACCESS, REFRESH):
            self.assertNotIn(private, str(failure))


if __name__ == "__main__":
    unittest.main()
