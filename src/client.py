#!/usr/bin/env python3
"""Metadata-only catalog and approved API calls through the local broker."""
import argparse
import json
import os
import socket
import sys

SOCKET = os.environ.get("PROJECT_ACCESS_SOCKET", "")
LIMIT = 4 * 1024 * 1024
INSTRUCTIONS = (
    "Use project_access_status to discover projects granted to the executing Unix identity, then project_catalog "
    "or project_credential_check for live credential names, _http API profiles and missing-key paths. Use api_read "
    "or api_request with a credential's relative name and an approved relative path. The broker supplies credentials "
    "and renews OAuth client-credentials tokens privately. Raw API keys are never returned. "
    "Existing cloudflare_read/cloudflare_write tools remain available. "
    "A project name or repository path cannot grant access. Ask the human to add missing keys through OpenBao; "
    "never request credential values in chat."
)


def call(request):
    if not SOCKET:
        return {"ok": False, "error": {"code": "configuration_required", "message": "Set PROJECT_ACCESS_SOCKET to the operator-provided broker socket."}}
    encoded = json.dumps(request).encode() + b"\n"
    if len(encoded) > 1024 * 1024:
        return {"ok": False, "error": {"code": "request_too_large", "message": "The request exceeded the size limit."}}
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(60)
            connection.connect(SOCKET)
            connection.sendall(encoded)
            with connection.makefile("rb") as stream:
                line = stream.readline(LIMIT + 1)
            if len(line) > LIMIT:
                raise ValueError()
            return json.loads(line)
    except (OSError, ValueError):
        return {"ok": False, "error": {"code": "broker_unavailable", "message": "The project credential service is unavailable to this Unix identity."}}


def schema(properties, required=()):
    return {"type": "object", "properties": properties, "required": list(required), "additionalProperties": False}


PROJECT = {"type": "string", "description": "A project returned by project_access_status, such as infrastructure."}
TOOLS = [
    {"name": "project_access_status", "description": "Discover the executing Unix identity's project grants and broker status. Contains no key values.",
     "inputSchema": schema({}), "annotations": {"readOnlyHint": True, "destructiveHint": False}},
    {"name": "project_catalog", "description": "Refresh a project's live OpenBao catalog: names, field names, versions, missing credentials and approved generic API profiles. Never returns values.",
     "inputSchema": schema({"project": PROJECT}, ["project"]), "annotations": {"readOnlyHint": True, "destructiveHint": False}},
    {"name": "project_credential_check", "description": "Check a relative credential name. Returns availability or a missing-key path the human can populate in OpenBao.",
     "inputSchema": schema({"project": PROJECT, "name": {"type": "string", "description": "Relative name, for example shared/cloudflare."}}, ["project", "name"]),
     "annotations": {"readOnlyHint": True, "destructiveHint": False}},
    {"name": "cloudflare_read", "description": "Read approved DNS records, Tunnels/configuration, or Access apps/policies. Use the catalog's zone/account IDs. The broker supplies the key privately.",
     "inputSchema": schema({"project": PROJECT, "path": {"type": "string", "description": "Cloudflare /zones/ZONE/dns_records or /accounts/ACCOUNT/cfd_tunnel or /accounts/ACCOUNT/access/... path, without /client/v4."}, "query": {"type": "object"}}, ["project", "path"]),
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "cloudflare_write", "description": "Make a user-requested change to approved Cloudflare DNS, Tunnel configuration or Access apps/policies. No token export or unrelated account/zone endpoints are allowed.",
     "inputSchema": schema({"project": PROJECT, "method": {"type": "string", "enum": ["POST", "PUT", "PATCH", "DELETE"]}, "path": {"type": "string"}, "query": {"type": "object"}, "body": {"type": "object"}}, ["project", "method", "path"]),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}},
]

API_PROPERTIES = {"project": PROJECT,
    "credential": {"type": "string", "description": "Relative credential name from the live catalog, such as production/shopify."},
    "path": {"type": "string", "description": "A path relative to the catalog profile's base_url, starting with /. Full URLs and traversal are refused."},
    "query": {"type": "object", "description": "Nonsecret query parameters; the broker adds any authentication parameter privately."},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Only request headers explicitly permitted by the credential's profile."}}
TOOLS.extend([
    {"name": "google_search_console_read", "description": "Read an approved Search Console property through its dedicated profile. OAuth tokens remain private; fixed reads only. Does not expose Security Issues or run live URL tests.",
     "inputSchema": schema({"project": PROJECT, "credential": {"type": "string"},
         "operation": {"type": "string", "enum": ["identity", "sites_list", "site_get", "sitemaps_list", "searchanalytics_query", "url_inspection"]},
         "params": {"type": "object"}}, ["project", "credential", "operation"]),
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "google_migration_read", "description": "Read an approved Google migration account through its _google_migration profile. OAuth grants stay private. Use the project-access google CLI for large responses and transfers.",
     "inputSchema": schema({"project": PROJECT, "credential": {"type": "string"},
         "operation": {"type": "string", "enum": ["identity", "storage_list", "storage_object", "gmail_profile", "gmail_labels_list", "gmail_messages_list", "gmail_message_get", "gmail_drafts_list", "gmail_draft_get"]},
         "params": {"type": "object"}}, ["project", "credential", "operation"]),
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "api_read", "description": "GET an approved HTTPS API using the selected project's credential. Read its live catalog API profile first. Supports declarative bearer/header/query/Basic/OAuth client-credentials authentication without provider-specific code.",
     "inputSchema": schema(API_PROPERTIES, ["project", "credential", "path"]),
     "annotations": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": True}},
    {"name": "api_request", "description": "Make an authorized POST/PUT/PATCH/DELETE request, including GraphQL or form requests, using a credential's approved HTTPS API profile. The broker supplies authentication privately. Do not supply secret values in arguments.",
     "inputSchema": schema({**API_PROPERTIES, "method": {"type": "string", "enum": ["POST", "PUT", "PATCH", "DELETE"]},
         "json_body": {}, "form_body": {"type": "object", "description": "Form-encoded data; use either json_body or form_body."}},
         ["project", "credential", "path", "method"]),
     "annotations": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True}}
])


def tool_call(name, arguments):
    if not isinstance(arguments, dict):
        return {"ok": False, "error": {"code": "invalid_arguments", "message": "Use an argument object."}}
    definition = next((tool for tool in TOOLS if tool["name"] == name), None)
    if not definition:
        return {"ok": False, "error": {"code": "unknown_tool", "message": "Unknown project-access tool."}}
    spec = definition["inputSchema"]
    if set(arguments) - set(spec["properties"]) or set(spec["required"]) - set(arguments):
        return {"ok": False, "error": {"code": "invalid_arguments", "message": "The tool arguments do not match its schema."}}
    actions = {"project_access_status": "status", "project_catalog": "catalog", "project_credential_check": "check", "cloudflare_read": "cloudflare", "cloudflare_write": "cloudflare", "api_read": "api", "api_request": "api"}
    if name in ("cloudflare_read", "api_read"):
        arguments = {**arguments, "method": "GET"}
    actions["google_migration_read"] = "google_read"
    actions["google_search_console_read"] = "google_search_console_read"
    return call({**arguments, "action": actions[name]})


def mcp():
    for line in sys.stdin:
        response = None
        request = {}
        try:
            if len(line.encode()) > 1024 * 1024:
                raise ValueError()
            request = json.loads(line)
            if not isinstance(request, dict):
                raise ValueError()
            method = request.get("method")
            if "id" not in request:
                continue
            if method == "initialize":
                supported = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
                requested = (request.get("params") or {}).get("protocolVersion")
                result = {"protocolVersion": requested if requested in supported else "2025-06-18",
                          "capabilities": {"tools": {"listChanged": False}},
                          "serverInfo": {"name": "openbao-project-access", "version": "0.6.0"},
                          "instructions": INSTRUCTIONS}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": TOOLS}
            elif method == "tools/call":
                params = request.get("params") or {}
                data = tool_call(params.get("name"), params.get("arguments", {}))
                result = {"content": [{"type": "text", "text": json.dumps(data, separators=(",", ":"))}],
                          "structuredContent": data, "isError": not data["ok"]}
            else:
                response = {"jsonrpc": "2.0", "id": request.get("id"), "error": {"code": -32601, "message": "Method not found"}}
            if response is None:
                response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
        except Exception:
            response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None,
                        "error": {"code": -32602, "message": "Invalid request"}}
        if response is not None:
            print(json.dumps(response, separators=(",", ":")), flush=True)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "google":
        from google_client import main as google_main
        return google_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    sub.add_parser("mcp")
    template = sub.add_parser("template", help="Prepare a nonsecret OpenBao record template; enter actual values only in OpenBao.")
    template.add_argument("--base-url", required=True)
    template.add_argument("--auth", choices=["none", "bearer", "header", "headers", "basic", "query", "oauth2_client_credentials"], default="bearer")
    template.add_argument("--path", action="append", default=[])
    template.add_argument("--methods", nargs="+", choices=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], default=["GET"])
    template.add_argument("--auth-name", default=None, help="Header or query parameter name; OAuth defaults to Authorization.")
    template.add_argument("--prefix", default=None, help="Authentication header prefix, including its trailing space when needed.")
    template.add_argument("--token-url")
    gsc = sub.add_parser("gsc", help="Named Search Console reads; no token export or live security scan.")
    gsc.add_argument("--project", required=True)
    gsc.add_argument("--credential", required=True)
    gsc.add_argument("--operation", required=True, choices=["identity", "sites_list", "site_get", "sitemaps_list", "searchanalytics_query", "url_inspection"])
    gsc.add_argument("--params", type=json.loads, default={})
    for action in ("catalog", "check", "cloudflare", "api"):
        part = sub.add_parser(action)
        part.add_argument("--project", required=True)
        if action == "check":
            part.add_argument("--name", required=True)
        if action == "cloudflare":
            part.add_argument("--method", choices=["GET", "POST", "PUT", "PATCH", "DELETE"], default="GET")
            part.add_argument("--path", required=True)
            part.add_argument("--query", type=json.loads, default={})
            part.add_argument("--body", type=json.loads)
        if action == "api":
            part.add_argument("--credential", required=True)
            part.add_argument("--method", choices=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], default="GET")
            part.add_argument("--path", required=True)
            part.add_argument("--query", type=json.loads, default={})
            part.add_argument("--headers", type=json.loads, default={})
            bodies = part.add_mutually_exclusive_group()
            bodies.add_argument("--json-body", type=json.loads)
            bodies.add_argument("--form-body", type=json.loads)
    args = vars(parser.parse_args())
    if args["action"] == "mcp":
        mcp()
        return 0
    if args["action"] == "template":
        from generic_api import profile, ApiError
        kind, placeholder = args["auth"], "REPLACE_SECURELY_IN_OPENBAO"
        data, auth = {}, {"type": kind}
        if kind in ("bearer", "header", "query"):
            data["api_token"] = placeholder
            auth["field"] = "api_token"
            if kind != "bearer":
                auth["name"] = args["auth_name"] or ("X-API-Key" if kind == "header" else "api_key")
        elif kind == "headers":
            data["api_token"] = placeholder
            auth["fields"] = {args["auth_name"] or "X-API-Key": "api_token"}
        elif kind == "basic":
            data.update(username=placeholder, password=placeholder)
        elif kind == "oauth2_client_credentials":
            if not args["token_url"]:
                parser.error("OAuth templates require --token-url.")
            data.update(client_id=placeholder, client_secret=placeholder)
            auth.update(token_url=args["token_url"], header=args["auth_name"] or "Authorization")
        if args["prefix"] is not None:
            if kind not in ("bearer", "header", "oauth2_client_credentials"):
                parser.error("--prefix applies to bearer, header or OAuth authentication.")
            auth["prefix"] = args["prefix"]
        config = {"version": 1, "base_url": args["base_url"], "paths": args["path"] or ["/"], "methods": args["methods"], "auth": auth}
        data["_http"] = json.dumps(config, separators=(",", ":"))
        try:
            profile(data)
        except ApiError as error:
            parser.error(error.message)
        print(json.dumps(data, indent=2))
        return 0
    if args["action"] == "gsc":
        args["action"] = "google_search_console_read"
    result = call({key: value for key, value in args.items() if value is not None})
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
