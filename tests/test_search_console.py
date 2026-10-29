"""Synthetic Search Console allocation, request-boundary and auth tests."""
import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import google_migration as gm
import google_search_console as gsc


def record(property="sc-domain:example.test", capabilities=None):
    config = {"version": 1, "account": "operator@example.test", "domain": "example.test",
              "scopes": sorted(gsc.SCOPES), "capabilities": sorted(capabilities or gsc.OPERATIONS)}
    if property is not None:
        config["property"] = property
    return {gsc.PROFILE: config, "authorized_user_json": {
        "type": "authorized_user", "client_id": "synthetic-client.apps.googleusercontent.com",
        "client_secret": "SYNTHETIC-CLIENT-SECRET", "refresh_token": "SYNTHETIC-REFRESH-TOKEN"}}


def request(operation="site_get", params=None):
    return {"action": "google_search_console_read", "project": "demo",
            "credential": "production/google-search-console", "operation": operation,
            "params": params or {}}


def auth_replies(email="operator@example.test", verified=True):
    return [(200, {"access_token": "ya29.SYNTHETIC-ACCESS-TOKEN", "expires_in": 3600,
                   "token_type": "Bearer", "scope": " ".join(sorted(gsc.SCOPES))}),
            (200, {"email": email, "email_verified": verified, "sub": "synthetic-user"})]


SITE = {"siteUrl": "sc-domain:example.test", "permissionLevel": "siteOwner"}


class Profiles(unittest.TestCase):
    def test_standard_grant_accepts_exact_space_delimited_scope_metadata(self):
        data = record()
        data['authorized_user_json']['scopes'] = ' '.join(sorted(gsc.SCOPES))
        self.assertEqual(gsc.describe(data)['status'], 'ready')
        data['authorized_user_json']['scopes'] += ' https://www.googleapis.com/auth/content'
        self.assertEqual(gsc.describe(data)['status'], 'invalid_configuration')

    def test_standard_grant_needs_no_mutable_account_or_scope_metadata(self):
        data = record()
        self.assertEqual(gsc.describe(data)["status"], "ready")
        data["authorized_user_json"].update(account_email="someone-else@example.com", account="wrong")
        self.assertEqual(gsc.profile(data)[0]["account"], "operator@example.test")
        for key in (gsc.PROFILE, "authorized_user_json"):
            data[key] = json.dumps(data[key])
        self.assertEqual(gsc.describe(data)["status"], "ready")

    def test_catalog_is_metadata_only(self):
        self.assertEqual(gsc.describe({}), {"status": "not_configured"})
        value = gsc.describe(record())
        self.assertNotIn("SYNTHETIC", json.dumps(value))
        self.assertNotIn("authorized_user_json", value)

    def test_invalid_allocations_and_grants_are_safely_classified(self):
        mutations = [
            (gsc.PROFILE, "version", True), (gsc.PROFILE, "version", 2),
            (gsc.PROFILE, "scopes", list(gsc.SCOPES) + ["https://www.googleapis.com/auth/content"]),
            (gsc.PROFILE, "scopes", ["openid"] * 3), (gsc.PROFILE, "scopes", [[], "openid"]),
            (gsc.PROFILE, "capabilities", ["sitemap_submit"]),
            (gsc.PROFILE, "capabilities", ["identity", "identity"]),
            (gsc.PROFILE, "domain", "example.test.evil.example/"),
            (gsc.PROFILE, "domain", "127.0.0.1"),
            (gsc.PROFILE, "property", "sc-domain:evil.example"),
            (gsc.PROFILE, "property", "https://example.test.evil.example/"),
            (gsc.PROFILE, "property", "https://example.test/?override=x"),
            (gsc.PROFILE, "arbitrary_url", "https://evil.example"),
            (gsc.PROFILE, "grant_field", "../other"),
            ("authorized_user_json", "token_uri", "https://evil.example/token"),
            ("authorized_user_json", "type", "service_account"),
            ("authorized_user_json", "client_secret", "bad\nsecret"),
            ("authorized_user_json", "refresh_token", ""),
            ("authorized_user_json", "scopes", ["openid"]),
        ]
        for section, key, value in mutations:
            with self.subTest(section=section, key=key, value=value):
                data = record()
                data[section][key] = value
                result = gsc.describe(data)
                self.assertEqual(result["status"], "invalid_configuration")
                self.assertNotIn("SYNTHETIC", json.dumps(result))


class RequestBoundary(unittest.TestCase):
    def setUp(self):
        self.proxy = gsc.GoogleSearchConsole()

    def reject_before_auth(self, data, req):
        with patch.object(self.proxy.auth, "token") as auth, patch.object(gsc, "exchange") as remote:
            with self.assertRaises(gsc.ApiError):
                self.proxy.execute(("demo", "grant"), data, req)
            auth.assert_not_called()
            remote.assert_not_called()

    def test_unknown_routes_headers_bodies_and_cross_properties_fail_before_auth(self):
        for op in ["sitemap_submit", "site_add", "request_review", "https://evil.example", [], None]:
            self.reject_before_auth(record(), request(op))
        for extra in [{"headers": {}}, {"url": "https://evil.example"}, {"json_body": {}}, {"method": "POST"}]:
            self.reject_before_auth(record(), {**request(), **extra})
        for params in [{"siteUrl": "sc-domain:other.example"}, {"body": {}}, {"headers": {}},
                       {"url": "https://evil.example"}, {"siteUrl": {"property": "sc-domain:example.test"}}]:
            self.reject_before_auth(record(), request("site_get", params))
        self.reject_before_auth(record(capabilities=["sites_list"]), request("site_get"))
        self.reject_before_auth(record(property=None), request("site_get"))
        self.reject_before_auth(record(), request("sites_list", {"domain": "evil.example"}))

    def test_all_fixed_read_routes(self):
        config, _ = gsc.profile(record())
        for op, params, method, suffix in [
            ("identity", {}, "GET", "/v1/userinfo"),
            ("sites_list", {}, "GET", "/webmasters/v3/sites"),
            ("site_get", {}, "GET", "/sc-domain%3Aexample.test"),
            ("sitemaps_list", {}, "GET", "/sc-domain%3Aexample.test/sitemaps"),
            ("searchanalytics_query", {"startDate": "2026-10-01", "endDate": "2026-10-07"}, "POST", "/searchAnalytics/query"),
            ("url_inspection", {"inspectionUrl": "https://shop.example.test/products/example"}, "POST", "/urlInspection/index:inspect"),
        ]:
            with self.subTest(operation=op):
                got_method, url, _ = gsc.route(config, op, params)
                self.assertEqual(got_method, method)
                self.assertTrue(url.endswith(suffix))
                self.assertTrue(url.startswith(("https://www.googleapis.com/", "https://openidconnect.googleapis.com/", "https://searchconsole.googleapis.com/")))

    def test_inspection_rejects_lookalikes_credentials_ports_and_encoded_traversal(self):
        bad = ["https://example.test.evil.example/", "https://evil-example.test/",
               "https://operator@example.test/", "https://@example.test/",
               "https://example.test:444/", "https://example.test:/", "http://example.test:443/",
               "https://example.test/../private", "https://example.test/%2e%2e/private",
               "https://example.test/%252e%252e/private", "https://example.test/%5cprivate",
               "https://example.test/%250aprivate", "https://example.test/a#fragment",
               "https://example.test\\@evil.example/", "file:///private-file", "//example.test/",
               "https://example.test/%", "https://example.test /", "https://example.test/%zz"]
        for url in bad:
            with self.subTest(url=url):
                self.reject_before_auth(record(), request("url_inspection", {"inspectionUrl": url}))
        for extra in [{"siteUrl": "sc-domain:other.example"}, {"body": {"siteUrl": "sc-domain:other.example"}},
                      {"headers": {}}, {"languageCode": "en-US\nAuthorization"}]:
            self.reject_before_auth(record(), request("url_inspection", {"inspectionUrl": "https://example.test/", **extra}))

    def test_prefix_property_boundary_and_selected_subdomain(self):
        data = record("https://example.test/shop/")
        for url in ["https://example.test/shopping/x", "https://example.test/elsewhere/",
                    "http://example.test/shop/x", "https://sub.example.test/shop/x",
                    "https://example.test/shop/%252e%252e/elsewhere",
                    "https://example.test/shop%2fprivate", "https://example.test/shop%252fprivate",
                    "https://example.test/sh%6fp/private"]:
            self.reject_before_auth(data, request("url_inspection", {"inspectionUrl": url}))
        config, _ = gsc.profile(data)
        self.assertEqual(gsc.route(config, "url_inspection", {"inspectionUrl": "https://example.test:443/shop/x?q=1"})[2]["siteUrl"], data[gsc.PROFILE]["property"])
        self.reject_before_auth(record("sc-domain:shop.example.test"), request("url_inspection", {"inspectionUrl": "https://example.test/"}))

    def test_analytics_limits_and_nested_overrides(self):
        base = {"startDate": "2026-01-01", "endDate": "2026-03-31", "dimensions": ["page", "device"], "rowLimit": 100}
        config, _ = gsc.profile(record())
        self.assertEqual(gsc.route(config, "searchanalytics_query", base)[2]["dataState"], "final")
        for extra in [{"endDate": "2026-04-01"}, {"startDate": "2026-04-01"}, {"startDate": "2026-1-01"},
                      {"startDate": "2026-02-30"}, {"rowLimit": True}, {"rowLimit": 0}, {"rowLimit": 101},
                      {"startRow": 1}, {"dimensions": ["page", "page"]}, {"dimensions": ["securityIssue"]},
                      {"dimensions": [{}]}, {"dataState": "all"}, {"body": {"siteUrl": "sc-domain:other.example"}},
                      {"dimensionFilterGroups": [{"groupType": "and", "filters": [], "siteUrl": "other"}]},
                      {"dimensionFilterGroups": [{"filters": [{"dimension": "page", "operator": "equals", "expression": "x", "body": {}}]}]}]:
            with self.subTest(extra=extra):
                self.reject_before_auth(record(), request("searchanalytics_query", {**base, **extra}))
        good = {**base, "dimensionFilterGroups": [{"groupType": "and", "filters": [
            {"dimension": "page", "operator": "contains", "expression": "/products/"}]}]}
        self.assertEqual(gsc.route(config, "searchanalytics_query", good)[0], "POST")


class Execution(unittest.TestCase):
    def setUp(self):
        self.proxy = gsc.GoogleSearchConsole()

    def test_property_discovery_filters_before_returning_any_other_domain(self):
        sites = ["sc-domain:example.test", "sc-domain:shop.example.test", "https://example.test/",
                 "https://shop.example.test/", "sc-domain:evil.example", "https://example.test.evil.example/",
                 "https://evil-example.test/", "https://evil.example/", "https://example.test:444/"]
        payload = {"siteEntry": [{"siteUrl": s, "permissionLevel": "siteOwner"} for s in sites]}
        with patch.object(self.proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(200, payload)):
            result = self.proxy.execute(("p", "g"), record(property=None), request("sites_list"))
        self.assertEqual([x["siteUrl"] for x in result["data"]["siteEntry"]], sites[:4])
        self.assertNotIn("evil", json.dumps(result))
        with patch.object(self.proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(200, payload)):
            result = self.proxy.execute(("p", "g"), record(), request("sites_list"))
        self.assertEqual(result["data"]["siteEntry"], [SITE])

    def test_all_operations_execute_named_reads_and_preserve_empty_reports(self):
        cases = [("identity", {}, {"email": "operator@example.test", "email_verified": True, "sub": "id"}),
                 ("site_get", {}, SITE), ("sitemaps_list", {}, {}),
                 ("searchanalytics_query", {"startDate": "2026-10-01", "endDate": "2026-10-01"}, {}),
                 ("url_inspection", {"inspectionUrl": "https://example.test/"}, {"inspectionResult": {}})]
        for op, params, payload in cases:
            with self.subTest(op=op), patch.object(self.proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(200, payload)) as remote:
                result = self.proxy.execute(("p", "g"), record(), request(op, params))
                self.assertEqual(result, {"http_status": 200, "data": payload})
                self.assertEqual(remote.call_count, 1)

    def test_auth_refresh_cache_and_record_change_use_actual_verified_identity(self):
        data = record()
        data["authorized_user_json"]["account_email"] = "untrusted@example.com"
        with patch.object(gm, "exchange", side_effect=auth_replies() * 2) as auth, patch.object(gsc, "exchange", return_value=(200, SITE)) as remote:
            self.proxy.execute(("p", "g"), data, request())
            self.proxy.execute(("p", "g"), data, request())
            self.assertEqual(auth.call_count, 2)
            changed = {**data, "purpose": "record changed"}
            self.proxy.execute(("p", "g"), changed, request())
        self.assertEqual(auth.call_count, 4)
        self.assertEqual(remote.call_count, 3)
        self.assertEqual(auth.call_args_list[0].args[0], "https://oauth2.googleapis.com/token")

    def test_wrong_actual_identity_unverified_email_scopes_and_rotation_deny(self):
        for change in ("email", "verification", "scope", "rotation"):
            replies = auth_replies()
            if change == "email": replies[1][1]["email"] = "other@example.com"
            if change == "verification": replies[1][1]["email_verified"] = False
            if change == "scope": replies[0][1]["scope"] += " https://www.googleapis.com/auth/content"
            if change == "rotation": replies[0][1]["refresh_token"] = "SYNTHETIC-ROTATED-TOKEN"
            proxy = gsc.GoogleSearchConsole()
            with self.subTest(change=change), patch.object(gm, "exchange", side_effect=replies), patch.object(gsc, "exchange") as remote:
                with self.assertRaises(gsc.ApiError) as error:
                    proxy.execute(("p", "g"), record(), request())
                self.assertNotIn("SYNTHETIC", str(error.exception))
                remote.assert_not_called()
                self.assertEqual(proxy.auth.tokens, {})

    def test_malformed_auth_response_is_safe_and_does_not_reach_gsc(self):
        replies = auth_replies()
        replies[1][1]["email"] = {"unexpected": "SYNTHETIC-REFRESH-TOKEN"}
        with patch.object(gm, "exchange", side_effect=replies), patch.object(gsc, "exchange") as remote:
            with self.assertRaises(gsc.ApiError) as error:
                self.proxy.execute(("p", "g"), record(), request())
            self.assertNotIn("SYNTHETIC", str(error.exception))
            self.assertEqual(error.exception.code, "gsc_auth_response_invalid")
            remote.assert_not_called()

    def test_provider_error_is_safe_not_replayed_and_401_clears_cache(self):
        for status in (401, 403, 429):
            proxy = gsc.GoogleSearchConsole()
            proxy.auth.tokens[("p", "g")] = ("fingerprint", 1, "synthetic-token")
            with self.subTest(status=status), patch.object(proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(status, {"error": {"message": "SYNTHETIC-REFRESH-TOKEN"}})) as remote:
                with self.assertRaises(gsc.ApiError) as error:
                    proxy.execute(("p", "g"), record(), request())
                self.assertEqual(error.exception.status, status)
                self.assertNotIn("SYNTHETIC", str(error.exception))
                self.assertEqual(remote.call_count, 1)
            if status == 401:
                self.assertEqual(proxy.auth.tokens, {})

    def test_invalid_and_oversized_responses_and_secret_echoes(self):
        for payload in ("text", [], {"siteUrl": "sc-domain:other.example"},
                        {"padding": "x" * (gsc.MAX_RESPONSE + 1)}):
            with self.subTest(kind=type(payload).__name__), patch.object(self.proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(200, payload)):
                with self.assertRaises(gsc.ApiError):
                    self.proxy.execute(("p", "g"), record(), request())
        payload = {"inspectionResult": {"note": "SYNTHETIC-CLIENT-SECRET", "message": "SYNTHETIC-REFRESH-TOKEN", "nested": {"value": "synthetic-token"}}}
        with patch.object(self.proxy.auth, "token", return_value="synthetic-token"), patch.object(gsc, "exchange", return_value=(200, payload)):
            result = self.proxy.execute(("p", "g"), record(), request("url_inspection", {"inspectionUrl": "https://example.test/"}))
        self.assertNotIn("SYNTHETIC", json.dumps(result))
        self.assertNotIn("synthetic-token", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
