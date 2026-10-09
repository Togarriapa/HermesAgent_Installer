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

The current runtime context does not yet provide an enrolled GitHub account
effect catalog, a Composio OAuth/connection broker, or a host-managed Codex
runner tied to the pinned ARM64 CLI and assigned-workspace identity. Therefore
these records prove policy validation only. They do not enable tools or claim
authentication, network reachability, account entitlement, functional use, or
Pi acceptance. Do not wire them through a generic provider or MCP operation;
each needs a Sol-reviewed fixed operation/payload contract and matching
root-owned handler. The fixture tests cover scope validation and fail-closed
enrollment, not external effects.
