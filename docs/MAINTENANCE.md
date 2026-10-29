# Maintaining the broker

This repository contains generic code, fabricated tests and installation
examples. Keep host inventory, live hashes, private backups, operational locks,
rollout records and agent-specific instructions in an operator-owned location
outside the checkout. Existing installed services are separate from source.

## Source layout

| File | Responsibility |
| --- | --- |
| src/broker.py | Unix admission, project grants, OpenBao sessions, catalog, dispatch, audit |
| src/client.py | stdio MCP schemas and small-request CLI |
| src/generic_api.py | HTTP profile validation, public HTTPS transport, private auth, redaction |
| src/google_migration.py | Google allocations, refreshed/verified identity, transfers |
| src/workspace_google.py | Fixed Workspace routes, capabilities and body validation |
| src/google_client.py | Large/binary client protocol and checksums |
| src/google_search_console.py | Search Console allocations and named reads |
| authorize_search_console.py | Owner-run consent using explicit private inputs |
| install.py / manifest.json | Verified installation into a new prefix |

## Changes and releases

Prefer an owner-written minimal `_http` profile when existing authentication
supports the API. For new transports, validate destinations, paths, parameters,
body resources and capabilities before authentication. Never log secret values,
OAuth callbacks or raw provider errors. Bound serialized responses and preserve
no-replay behavior for writes.

Run the full unittest suite, including the optional SDK checks when changing
consent. Test installation into a new temporary prefix and a CLI/MCP round trip.
Inspect all source and examples for personal names, customer domains, machine
paths and resource identifiers. Use a local secret scanner as an additional
check; ignored files are not safe if already tracked. With Gitleaks 8.25+ run
`gitleaks git --redact --log-opts=--all .`. The included configuration retains
all default rules and excludes only SHA-256 manifest entries from the generic
API-key rule; it does not exempt tests, credentials or entire commits.

After reviewing source changes, update the release version consistently in the
broker, MCP server and installer, and regenerate the manifest:

```sh
python3 - <<'PY'
import hashlib, json
from pathlib import Path
from install import VERSION, FILES
manifest = {'version': VERSION, 'files': {
    name: hashlib.sha256((Path('src') / name).read_bytes()).hexdigest()
    for name in sorted(FILES)}}
Path('manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
PY
```

A manifest detects source drift; it is not a signature or an independent trust
root. Review the source and obtain it through a trusted channel. Keep deployment
config and credentials outside versioned installation prefixes.

## Deploy and roll back

1. Check current user authorization for the service/restart. Record expected live
   hashes, configuration and the selected release in private deployment records.
2. Install into a fresh versioned prefix. The installer rejects an existing prefix
   and never restarts a service or modifies OpenBao.
3. Coordinate active callers and migration workers using the deployment's own
   lock/runbook. A file lock only coordinates cooperating processes; it cannot
   drain arbitrary API requests. Stop the old service cleanly.
4. Update the service's executable path to the new prefix and start it. Check
   status/version, allowed identities, catalog and a bounded provider read.
5. If checks fail, stop the new service, restore the previous executable path
   and private configuration, restart and verify. Retain both prefixes until
   the operator accepts the deployment. Never replay uncertain provider writes.

For upgrades from an installation with embedded defaults, explicitly configure
all four runtime paths. Set PROJECT_ACCESS_SOCKET for every CLI/MCP caller.
The public release uses configurable KV/AppRole mount names and the MCP name
openbao-project-access. Existing client registrations may need a tool refresh.
Calendar migration markers default to migrationSourceId and
migrationSourceCalendar; an owner may preserve old marker keys through the
private allocation's calendar_markers setting (see USAGE.md).

Changes to mount names, service credentials, socket ACLs or the OpenBao address
require a coordinated restart. Project grants and records are re-read per
request, so revoking a UID's project access takes effect immediately, but newly
granted UIDs still need a socket ACL refresh/restart. Check parent-directory
traversal permissions too. An existing socket is never unlinked automatically
at startup; remove a stale socket only after confirming its process has stopped.

## Publication and history

Do not append a cleanup commit when earlier commits still contain private
information. Review every branch, tag, commit identity, message and blob before
publication; keep any original-history backup outside the repository. Prevent
old clones from pushing their old history back. A fresh clone is safest after
a rewrite.

A force push does not guarantee removal of cached commits, pull-request refs or
other clones. Follow GitHub's [sensitive-data removal guidance](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
and resolve retained data before changing visibility. Do not promise that
rewriting reachable history deletes every stored remote object.
