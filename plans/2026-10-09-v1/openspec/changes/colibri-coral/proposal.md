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
