# Setup with an existing OpenBao server

Use Linux and Python 3.10 or newer. The broker requires Linux Unix-socket peer
credentials (`SO_PEERCRED`). Install the distribution's ACL utilities (`setfacl`)
if the service and agents have different UIDs. The runtime needs no pip packages.
OpenBao must already be initialized, unsealed and reachable. Remote connections
require HTTPS with a trusted certificate; plain HTTP is permitted only on the
loopback interface. Use the system trust store or Python's SSL_CERT_FILE setting
for a private CA; do not disable verification.

Choose operator-owned locations using BROKER_PREFIX, BROKER_CONFIG_DIR,
BROKER_STATE_DIR and BROKER_SOCKET. Resolve directory symlinks before installing.
These are shell variables chosen by the operator, not built-in paths. For a
shared service, keep code/config/credentials outside agent-writable directories
and run the service as a separate unprivileged account.

## 1. Install code

Choose a **new** absolute BROKER_PREFIX under a trusted existing parent:

```sh
python3 install.py --prefix "$BROKER_PREFIX"
python3 install.py --prefix "$BROKER_PREFIX" --install
"$BROKER_PREFIX/bin/project-access" --help
```

Only code and the two launchers are installed. The service needs read/execute
access to this prefix; agents must not be able to modify it. In a shared setup,
the administrator should own the prefix and its parents.

## 2. Allocate one OpenBao project

The following uses the fictional project `demo`, KV mount `secret` and AppRole
mount `approle`. Inspect existing mounts with `bao secrets list` and
`bao auth list`; enable a KV v2 engine or AppRole only if needed. Do not replace
existing mounts. Custom mount names are supported by configuration and must also
be substituted in the policy and enrollment commands.

Run administrative commands through the operator's normal authenticated `bao`
CLI, separate from the agent environment. Never give the broker an admin token.

```sh
# Only if these mounts do not already exist:
bao secrets enable -path=secret kv-v2
bao auth enable approle

bao policy write project-broker-demo examples/project-policy.hcl
bao write auth/approle/role/project-broker-demo \
  token_policies=project-broker-demo token_no_default_policy=true \
  token_ttl=1h token_max_ttl=24h token_num_uses=0 \
  secret_id_ttl=720h secret_id_num_uses=0
```

The policy permits only listing metadata and reading values inside this project's
prefix, plus managing the service's own token. There are no secret-write,
policy-management or other-project permissions. Repeat with a separate AppRole
and policy for each project. See OpenBao's [AppRole documentation](https://openbao.org/docs/auth/approle/)
and [policy CLI reference](https://openbao.org/docs/commands/policy/write/).

Use an existing private directory outside every checkout, owned by the operator
with mode 0700. Set BROKER_CONFIG_DIR to that canonical directory. Capture new
AppRole identifiers without printing them or putting them in shell arguments:

```sh
umask 077
bao read -format=json auth/approle/role/project-broker-demo/role-id \
  > "$BROKER_CONFIG_DIR/role-id.local.json"
bao write -format=json -f auth/approle/role/project-broker-demo/secret-id \
  > "$BROKER_CONFIG_DIR/secret-id.local.json"
python3 - "$BROKER_CONFIG_DIR" <<'PY'
import json, os, sys
from pathlib import Path
root = Path(sys.argv[1])
role = json.loads((root / 'role-id.local.json').read_text())['data']['role_id']
secret = json.loads((root / 'secret-id.local.json').read_text())['data']['secret_id']
with (root / 'approle.json').open('x') as output:
    os.fchmod(output.fileno(), 0o600)
    json.dump({'projects': {'demo': {'role_id': role, 'secret_id': secret}}}, output)
(root / 'role-id.local.json').unlink()
(root / 'secret-id.local.json').unlink()
PY
```

Use new scratch filenames when repeating enrollment; do not overwrite unrelated
private files. The final file is created exclusively. For more projects, merge
registrations in a private editor rather than overwriting existing enrollment.
The sample SecretID expires after 30 days; rotate it privately and restart the
broker before expiry. This process is an operator task, never an agent tool.

## 3. Configure grants and paths

Copy `examples/projects.example.json` to `projects.json` in BROKER_CONFIG_DIR.
Set openbao_address, kv_mount, auth_mount, and the project's secret_prefix.
Set allowed_uids to the numeric UIDs of explicitly approved agent identities;
`id -u "$AGENT_USER"` can resolve an account. The example grants no non-root
UIDs. Root is always admitted; other callers require a listed UID. enabled must
also be true. A username or repository directory is not an access boundary.

Copy `.env.example` to a private environment file outside the checkout and set:

| Setting | Meaning |
| --- | --- |
| PROJECT_BROKER_CONFIG | Absolute path to the private project configuration |
| PROJECT_BROKER_CREDENTIALS | Absolute path to owner-only AppRole JSON |
| PROJECT_ACCESS_SOCKET | Absolute path for the service/client Unix socket |
| PROJECT_BROKER_AUDIT | Absolute path for rotating metadata-only audit logs |

All four are required (or use the corresponding `--config`, `--credentials`,
`--socket`, `--audit` service flags). With systemd LoadCredential, omit
PROJECT_BROKER_CREDENTIALS; the broker reads `approle` from CREDENTIALS_DIRECTORY.
There are no implicit machine paths. Do not put provider keys in environment
files. Python does not source `.env` automatically.

The service account must read config/credentials, write its socket directory and
audit directory, and access OpenBao/provider HTTPS endpoints. Its credentials
must be a regular, non-symlink file owned by the service UID or root with no group
or other access. With systemd, LoadCredential provides a private copy. Give
clients traversal access to the socket's parent directories, never access to
the credentials directory. Socket ACLs are granted only to configured UIDs.

For a foreground smoke check, run as the service identity with the four settings
exported (or pass flags). Do not run under an agent UID when secret isolation is
required:

```sh
"$BROKER_PREFIX/bin/project-broker"
```

In another approved client process:

```sh
export PROJECT_ACCESS_SOCKET="$BROKER_SOCKET"
"$BROKER_PREFIX/bin/project-access" status
"$BROKER_PREFIX/bin/project-access" catalog --project demo
```

An empty catalog is expected until the owner saves records. Copy the nonsecret
HTTP example into the OpenBao JSON editor at
`secret/projects/demo/production/reporting`, then enter the actual credential
there. Use an API/domain you control and allocate only the required paths and
methods. example.com is illustrative, not a working service.

## 4. Optional systemd service

Copy `examples/project-broker.service.example` into the administrator's system
unit directory as `openbao-project-broker.service`. Replace @PREFIX@,
@CONFIG_DIR@ and @SERVICE_USER@ with the selected canonical paths/service user.
The service's private config directory may be root-owned; its projects.json
must be readable by the service account. LoadCredential handles the root-private
AppRole file. Ensure the service can traverse/read its code prefix and config.

The unit supplies the socket, audit and config settings itself. Its runtime
folder permits traversal while the socket ACL controls access. StateDirectory
holds private logs. The unit uses only standard systemd directory specifiers;
there is no host-specific lock or hardcoded workstation path.

After reviewing the unit and coordinating any existing service:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now openbao-project-broker.service
```

Clients must set PROJECT_ACCESS_SOCKET to the resolved path from the unit's
RuntimeDirectory. Check status, catalog and a narrowly scoped provider read.
The repo installer never performs these administrative steps.

## Agent integration

Register the installed executable and `mcp` argument in any stdio MCP client,
with PROJECT_ACCESS_SOCKET supplied by the operator. A host-specific agent skill
or runbook can link to docs/USAGE.md and privately record project aliases and
paths. Keep that material outside this source repository. No agent should be
able to edit the broker's enrollment, service credentials, code or unit.
