# Agent instructions

Read README.md, docs/USAGE.md and docs/MAINTENANCE.md before changing this project.
Use docs/SETUP.md for a new installation. Deployment-specific instructions and
business context belong in an operator-managed location outside this repository.

## Use

Discover the executing identity's grants with project_access_status, then call
the intended project's live catalog/check. Use an approved relative credential
name and operation. CLI fallback is project-access. An installed agent skill is
optional; the MCP server and docs carry generic usage instructions.

Never infer grants from a checkout path, repository access or another session.
Processes under one Unix UID share grants. Do not share another user's vault
credentials or socket access as an onboarding shortcut.

Owners enter real values directly into OpenBao. Never ask for keys, passwords or
refresh tokens in chat, export them, search unrelated credential stores, or use
administrator helpers as an authentication workaround. Keep filled records,
private configuration, OAuth state and exports outside Git. Tests must use
fabricated identities, reserved example domains and temporary directories.

## Change

Inspect the checkout, revision and diff; preserve unknown edits. Prefer a minimal
_http allocation for supported authentication. New transports need fixed
operations, validation before authentication, private token handling, bounded
responses and meaningful denial/regression tests. Preserve existing capability
boundaries and avoid automatic retries of uncertain writes.

Run python3 -m unittest discover -s tests and compile changed Python. Review all
tracked files and reachable history for private information before publication.
Update manifest.json after reviewed runtime changes. Never regenerate a manifest
to disguise unreviewed source drift on an installed service.

Source publication does not authorize service deployment, a restart, new vault
grants or provider roles. Follow the operator's external deployment runbook and
current task authorization. The installer only creates a new code prefix; it
never updates a running service. Keep old code until a new deployment passes its
health checks. Do not bypass a rejected approval.
