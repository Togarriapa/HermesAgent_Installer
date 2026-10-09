# Proposal

## Why

The requested Pi setup needs official and explicitly labeled optional community mcps, scoped authentication, harmless functional tests and bounded reconnect. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `mcp-connections` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `mcp-connectivity`: Official and explicitly labeled optional community MCPs, scoped authentication, harmless functional tests and bounded reconnect.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/mcp/. Depends on installer-bootstrap-desktop, resource-registry-import, providers-credentials-budgets-privacy. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.

### v24 native MCP handler binding

MC-F01/MC-F02 and HI-T04/08/09 use native-package-binding-contract.json native_mcp_dispatch exact source-backed in-process hook/catalog/RPC/result joins. All original native/account acceptance remains pending.

### v25 MCP lexical/config mapping

Use native_mcp_dispatch row_types/invocation_mapping/native_config exact records, same one-use lexical binding and root-backed native candidate registration. MC/HI acceptance remains pending.
