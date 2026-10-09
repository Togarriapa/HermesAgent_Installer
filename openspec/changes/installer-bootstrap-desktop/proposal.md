# Proposal

## Why

The requested Pi setup needs fresh/adopted supported arm64 install, official agent/desktop version resolution, native user-session launch and truthful fallback. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `installer-bootstrap-desktop` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `bootstrap-desktop`: Fresh/adopted supported ARM64 install, official Agent/Desktop version resolution, native user-session launch and truthful fallback.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/preflight.py, src/hermes_installer/desktop.py, src/hermes_installer/bootstrap.py. Depends on the pinned planning/tooling baseline. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.

Hermes/resource selection v3: plans/amendments/2026-10-09-hermes-bootstrap-resource-job-selection-v3.md defines fixed stage/health recipes and activegeneration resourcejob/DAG/source/backend joins; BD-F03/LC-F03/LC-F04/HI-T09/RB-T08 tasks and nativeevidence remainopen.
