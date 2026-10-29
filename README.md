# OpenBao Project Broker

Give local agents scoped access to APIs without handing them API keys or OAuth
tokens. The broker authenticates to a standard OpenBao installation, checks the
caller's Unix identity and project grants, and makes approved requests on their
behalf. Agents receive a catalog and provider results; credentials stay inside
the service.

```text
Agent / CLI / MCP client
        │ Unix socket + peer UID
        ▼
Project Broker ── AppRole ── OpenBao KV v2
        │ approved destination, method and resource
        ▼
Provider API
```

The runtime uses the Python standard library. It supports declarative HTTP
profiles, renewable OAuth client credentials, scoped Cloudflare operations,
Google Workspace migration operations and read-only Search Console access.

## Install and configure

Requirements: Linux, Python 3.10+, an initialized/unsealed OpenBao server with
KV v2 and AppRole, and `setfacl` when clients use different Unix identities.
The owner-run Google consent helper additionally needs a browser and the pinned
optional dependencies in `requirements-bootstrap.lock`.

Choose a new canonical installation prefix in a trusted existing parent:

```sh
python3 install.py --prefix "$BROKER_PREFIX"            # read-only verification
python3 install.py --prefix "$BROKER_PREFIX" --install  # install code
```

The installer verifies every runtime file against `manifest.json`, refuses
existing destinations and does not configure OpenBao or start/restart services.
Follow [setup](docs/SETUP.md) for project policies, AppRole enrollment, private
configuration, socket permissions and an optional systemd service.

Configure the client with the socket chosen by the service operator:

```sh
export PROJECT_ACCESS_SOCKET="$BROKER_SOCKET"
"$BROKER_PREFIX/bin/project-access" status
"$BROKER_PREFIX/bin/project-access" catalog --project demo
"$BROKER_PREFIX/bin/project-access" mcp
```

For an MCP client, register the installed `project-access` executable with the
argument `mcp` and supply `PROJECT_ACCESS_SOCKET` in that server's environment.
It speaks JSON-RPC over stdio; no specific agent application or installed skill
is required. See [agent usage](docs/USAGE.md) and [contributor instructions](AGENTS.md).

## Security boundary

Authorization follows Unix UIDs, not directories or project names. All processes
under one UID share its grants. The broker's service identity and root can read
service credentials; run the broker under a separate administrator-managed
identity when agents must not access them. Protect the installed code, project
configuration and AppRole credentials from agent writes.

Profiles allocate capabilities. They do not replace the human's authorization
for a particular task. Generic requests use pinned public HTTPS destinations,
explicit paths/methods and private authentication. Redirects, private network
addresses and caller authentication/routing overrides are refused. Provider
credentials should have the smallest permissions needed as a second boundary.

Do not store deployment addresses, account identifiers, grants, response exports
or private operational notes here. Use operator-owned files outside the checkout;
`.env`, local JSON and private directories are ignored as an additional guard.
Environment files carry paths/settings, never provider keys. They are not loaded
automatically by Python. Owners enter provider secrets through OpenBao.

## Search Console consent

The owner runs `authorize_search_console.py` on the browser's machine, supplying
the expected Cloud project ID, sign-in account and domain explicitly. It checks
the original Desktop-client download, fixed Google endpoints, verified identity
and exact consent scopes, then saves a new private grant outside Git.
See [consent instructions](docs/CONSENT.md). No cloud project or account is
embedded in the code.

## Development

```sh
python3 -m unittest discover -s tests
python3 -m compileall -q src authorize_search_console.py install.py
```

Tests use fabricated identities and mocked provider responses; socket tests use
local Unix/loopback sockets. Optional SDK tests require the pinned consent
libraries. No live credentials are needed. See [maintenance](docs/MAINTENANCE.md)
for releases, deployment separation and rollback.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
See [NOTICE](NOTICE) for copyright attribution.
