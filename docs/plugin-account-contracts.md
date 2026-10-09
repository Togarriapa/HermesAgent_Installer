# GitHub, Composio, and Codex plugin account contracts

The account policy records in `src/hermes_installer/components/plugin_accounts.py`
validate host-owned enrollment data. They contain only opaque vault references,
exact resource identifiers, and pinned runtime metadata. They never accept a
token, URL, executable path, or caller-provided readiness result.

The vendor source is `resources/vendor/hermes-agent-resources-2.3.1/plugins/`
at the pinned Resources revision recorded in `planning/source-revisions.json`:

- `github.yaml` 1.0.1 separates repository, issue/pull-request, and workflow
  reads from task-authorized writes. Destructive/admin work also needs explicit
  confirmation and provider scope. The token is runtime-only; writes require
  post-write verification.
- `composio.yaml` 1.0.0 requires per-profile user isolation and an explicit
  toolkit allowlist. Connection creation is user-authorized, external writes
  are delegated-only, destructive calls require confirmation, and remote
  workbench, bash, and arbitrary proxy access are denied.
- `codex.yaml` 1.0.1 uses shared host-owned authentication and an assigned
  workspace. Workspace writes require task authority. Infrastructure writes,
  credential export/copy, arbitrary host access, and authority derived from a
  Codex session are denied.

`src/hermes_installer/plugin_accounts_broker.py` now provides the fixed-effect
backend layer for the Sol-reviewed wire envelope (`plugin.github.read/write/admin`,
`plugin.composio.invoke`, and `plugin.codex.run`). The handler map is keyed by
the exact operation and `plugin:<adapter>:<enrollment-target>:<generation>`.
It validates the fresh host grant, profile/principal/lineage, exact payload
digest, root-selected enrollment, fixed argument schema, bounded request and
response, and a durable idempotency record for writes. No caller supplies a
URL, arbitrary command, executable, or filesystem location.

The GitHub backend currently supports the narrow action IDs `repo.get`,
`issues.list`, `content.get`, `content.put`, and `issue.create`. It constructs
requests only to `api.github.com`, checks the repository against the exact
enrollment allowlist, resolves the token through the host vault, and verifies
content writes by reading the exact path back. Issue creation uses an
idempotency marker and verifies the returned issue by number before it can be
committed. Admin actions and all other action IDs stay unavailable.

The Composio backend calls only the fixed v3.1 tool-execution endpoint and
requires an exact enrolled tool slug, connected-account ID, pinned tool version,
and vault credential. It does not use the proxy/workbench routes. Generic
Composio execution has no generic postcondition, so mutating calls remain
ambiguous until an action-specific enrolled verifier is supplied. OAuth
connection creation is not implemented by this executor.

The Codex adapter accepts a bounded prompt and a workspace ID that resolves to
a root-selected workspace binding. It does not accept argv or caller paths and
requires write authority and an idempotency key because execution can change
workspace files. It also requires a root process broker that advertises the
pinned ARM64 toolchain lock. The broker must provide host-attested
workspace-result verification before a write can be marked committed; a
textual success field is not sufficient.

These implementations are not yet enabled in `AuthorityService`: root-owned
account/secret enrollments, per-action schemas and verifiers, Codex managed
runner receipts, and the service registration path remain prerequisites. The
fixture backend tests exercise exact destinations, allowlist denial, fixed
Composio connection/version bindings, and Codex workspace/toolchain binding;
they do not claim authentication, real account entitlement, live writes, or Pi
acceptance.
