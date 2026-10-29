# Using the broker

Repository access supplies code, not vault access. Admission uses the caller's
Unix UID and enrolled project grants. Processes under the same UID share grants.
Set PROJECT_ACCESS_SOCKET to the operator-provided socket before using the CLI
or MCP server. Keep deployment-specific agent instructions outside this repo.

## Discover before requesting

Through MCP:

1. `project_access_status` discovers live grants and service version.
2. `project_catalog` refreshes the intended project's records and transport metadata.
3. `project_credential_check` checks a specific relative name and returns a missing
   storage path when appropriate.
4. Select the transport whose status is ready and make a bounded operation within
   the user's task. A profile being ready is structural validation; successful
   provider access still needs a live check.

Equivalent discovery commands contain no credential values:

```sh
project-access status
project-access catalog --project PROJECT
project-access check --project PROJECT --name production/reporting
```

`project-access mcp` is the stdio MCP entry point. An already-running MCP client
may cache the old tool list after a broker/client upgrade; use the CLI fallback
or the client's supported tool refresh. Do not restart unrelated services merely
to change a catalog record. Broker operations never export raw credentials.

## Generic HTTP APIs

The owner saves values plus an `_http` object/string under
`KV_MOUNT/PROJECT_PREFIX/RELATIVE_NAME` (for example,
`secret/projects/demo/production/reporting`). See the nonsecret
[exact-path read example](../examples/http-read.json). Adding this record allocates
the listed destinations/paths/methods to identities already granted the project.
The read-only broker cannot create records, enroll projects or expand its grants.

Prefer a profile over code changes for supported authentication: none, bearer,
custom header(s), Basic, query parameter, OAuth client credentials or the existing
strict path-token mode. The latter injects one whole `{credential}` segment in
explicit exact routes; inspect its tests before proposing it for another API.

Prepare placeholder records, then let the owner fill them privately in OpenBao:

```sh
project-access template --base-url https://api.example.com \
  --auth bearer --path /v1/status --methods GET
project-access api --project PROJECT --credential production/reporting \
  --path /v1/status
```

Paths ending in `/` allocate a subtree; other paths are exact. Methods and paths
are explicit, so avoid broad `/` or write-method allocation by default. Public
HTTPS on port 443 is required; redirects, private destinations, caller routing/
authentication-header overrides and traversal are refused. The transport pins
public DNS results and validates TLS. Use relative request paths, not full URLs.
MCP `api_read` supplies GET; `api_request` supplies authorized JSON/form operations.
HTTP methods do not determine business authorization: a POST may be a read, while
another nominal read operation can still have side effects.

OAuth `client_credentials` is renewable privately. Generic `_http` does not turn
Google user OAuth, JWT signing, mTLS, arbitrary binary uploads or interactive
consent into supported flows. Do not put a short-lived token in a bearer record
as a substitute for the required durable integration.

## Search Console

The broker exposes `google_search_console_read`, catalog metadata under
`google_search_console`, and the CLI below. Generic `api.status=not_configured`
can coexist with a ready dedicated GSC profile; inspect the correct metadata key.
The [allocation example](../examples/google-search-console.json) is dormant until
the owner supplies a legitimately consented authorized-user grant.

The allocation binds the verified account, domain, exact three scopes and named
read capabilities. `sites_list` returns only that domain/subdomains; pin the exact
verified `property` before other reads. Callers cannot override it through bodies
or parameters. The OAuth scope can cover more properties, but the broker enforces
the allocated domain/property on exposed operations.

```sh
project-access gsc --project PROJECT --credential production/gsc \
  --operation sites_list
project-access gsc --project PROJECT --credential production/gsc \
  --operation url_inspection \
  --params '{"inspectionUrl":"https://example.test/"}'
```

Replace the fictional host/name with the actually allocated resource. Other reads
are identity, site_get, sitemaps_list and searchanalytics_query. Analytics uses
flat startDate/endDate/dimensions/rowLimit parameters, at most 90 days and 100 rows;
URL inspection uses flat inspectionUrl and optional languageCode. There is no
Security Issues report, hidden sample-URL lookup, review submission or live-page
scan. Inspection returns Google's stored index state and cannot clear a warning.

The owner consent helper accepts explicit Cloud project, account and domain
settings. Follow [consent instructions](CONSENT.md); filenames do not establish
an account's identity.

## Existing migration and Workspace operations

`_google_migration` allocations are distinct from GSC and include fixed capability/
scope/resource checks. Some capabilities write data; a grant does not authorize
every operation for every task. Legacy grant metadata requirements differ from
standard GSC authorized-user JSON; inspect `google_migration.profile`.

Use `google_migration_read` for its listed small reads. The transfer CLI supports
the fixed Workspace/migration routes, large data, binary output and explicitly
approved writes without receiving OAuth credentials:

```sh
project-access google --help
```

Use private owner-only outputs and the selected project's journal/reconciliation
rules. Requests are not automatically replayed after uncertain writes. Inspect
the actual target state before retrying. Never assume a failed transport means
the provider performed no operation.

## Interpreting failures

Missing records, denied project access, invalid allocations, unsupported flows
and rejected provider calls are different conditions. Retain safe codes/statuses;
do not seek raw token responses or undo redaction for diagnostics. A 401 may clear
an in-memory token cache but does not cause an automatic replay. Owners correct
records through their normal private OpenBao interface, then refresh the catalog.

Calendar patch operations require an unchanged ETag and a private migration copy
with nonempty `migrationSourceId` and `migrationSourceCalendar` properties. To
support an existing migration's keys, set owner-controlled allocation metadata:

```json
"calendar_markers": {"source_id": "sourceEventId", "source_calendar": "sourceCalendarId"}
```

This setting requires the `calendar.import` capability. Callers cannot override
it per request. The private-copy and ETag checks still apply. Storage reads are
limited to the explicitly allocated Workspace Takeout export bucket; arbitrary
Cloud Storage administration is not provided.
