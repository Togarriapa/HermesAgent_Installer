# Proposal

## Why

The requested Pi setup needs supported account authentication and tool/inference routes with aggregate budgets, privacy eligibility and fail-closed fallback. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `providers-credentials-budgets-privacy` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `provider-routing`: Supported account authentication and tool/inference routes with aggregate budgets, privacy eligibility and fail-closed fallback.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/providers/, src/hermes_installer/credentials.py, src/hermes_installer/policy.py. Depends on installer-bootstrap-desktop. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.

## Documented ChatGPT-plan protocol refinement

PR01/PR-T01/EV-PR01 refines existing R0124/R0125/R0126 supported Codex auth/inference against dated official SIWC contract. No new provider scope, paid fallback or account-success claim.

## OmniRoute isolated runtime refinement

PR02/PR-T02/EV-PR02 binds existing selected OmniRoute source engine range to exact protected component Node source pin; no global runtime mutation or native readiness claim.
