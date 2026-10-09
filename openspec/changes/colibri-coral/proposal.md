# Proposal

## Why

The requested Pi setup needs glm-5.2 arm64 experimental installation path and independent official compiled-model tpu inference. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `colibri-coral` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `hardware-inference`: GLM-5.2 ARM64 experimental installation path and independent official compiled-model TPU inference.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/components/colibri.py, src/hermes_installer/components/coral.py. Depends on installer-bootstrap-desktop, providers-credentials-budgets-privacy. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.

## Offline package-set refinement

HW01/HW-T01/EV-HW01 operationalizes original R0042 under fixed protected package.install set schema; append-only coral-protected-package-set-v1. Original HW-F03/HW-R0042 and actual delegate acceptance remain unchanged/open.

## Exact device and compiler refinement

HW02/HW-T02/EV-HW02 and HW03/HW-T03/EV-HW03 operationalize original R0042/R0115 with exact selected-device custody and reviewed fixed bounded build profiles.

Closed memory/model recipe identities v6: plans/amendments/2026-10-09-closed-memory-model-recipe-ids-v6.md and protected contract JSON define finite schema/recipe IDs, empty model launch parameters and root-owned forced scope. Actual serializer/result/ARM64 effect evidence remains pending, existing tasks open.
