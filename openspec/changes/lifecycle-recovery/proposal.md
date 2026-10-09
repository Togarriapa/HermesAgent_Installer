# Proposal

## Why

The requested Pi setup needs wizard/cli, isolated environments, ownership-safe idempotent checkpoints, supervised services, rollback, backups and uninstall. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `lifecycle-recovery` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `managed-lifecycle`: Wizard/CLI, isolated environments, ownership-safe idempotent checkpoints, supervised services, rollback, backups and uninstall.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/cli.py, src/hermes_installer/config.py, src/hermes_installer/state.py, src/hermes_installer/lifecycle.py, src/hermes_installer/supervision.py. Depends on installer-bootstrap-desktop. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.
