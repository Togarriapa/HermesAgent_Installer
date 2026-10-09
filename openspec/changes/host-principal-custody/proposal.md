# Proposal

## Why

The baseline requires actual host authorization and private/public runtime isolation. Profile names, injectable policy classes and transient user services cannot establish that custody; the concrete trusted host boundary must be specified before enabling native dispatch.

## What Changes

- Refine R0054/R0058/R0109/R0111/R0130/R0151/R0155 through append-only Sol amendment HI01..HI06 and separate implementation versus native acceptance tasks.
- Select root-owned host custody, distinct unprivileged service identities, kernel isolation and protected typed IPC, retaining all original obligations and AC05/06/08.
- Keep incomplete native wiring, account authority and target probes pending; no runtime acceptance or canonical runtime sync is claimed.

## Capabilities

### New Capabilities

- `host-principal-custody`: trusted host principal custody and mandatory mediated runtime dispatch.

### Modified Capabilities

None; pending baseline runtime specifications remain intact.

## Impact

Luna runtime authorization, provider/credential brokers, service generation, native Hermes tool binding and lifecycle adapters. Existing task bindings RG-F02, PR-F01/03, LC-F04 and planning/traceability.json remain authoritative. Supplemental DAG and exact tests are in planning/host-principal-custody-amendment.json. This change refines existing scope, adds no enrolled target/account, and changes no runtime code.

## Fixed local service transport refinement

HI07/HI-T07 preserves native Xpra, Colibri and reviewed memory/MCP service transport without expanding general worker network authority. Read plans/amendments/2026-10-09-fixed-local-service-connector-v1.md. No arbitrary address family, destination or account is enabled.

HI08/HI09 add concrete native per-request provenance and distinct caller/service root enrollment, resolving current integration gaps within existing host/private-routing obligations. No caller labels or process-start envelopes are promoted to native request authority.

## Fixed process inspection refinement

HI10/HI-T10/EV-HI10 concretizes existing remote native process/sandbox proof; HI07 wire names are fixed in planning/native-host-service-contract.json. See append-only fixed-process-inspection-v1.

## Cross-process native handoff refinement

HI11/HI-T11/EV-HI11 operationalizes existing HI08/PR source lineage for actual producer and gateway peer separation, without transferring bearer authority.

HI11 wire clarification in native-cross-process-bridge-v2 captures complete request directly; existing source snapshots are bounded retained ancestry, not portable effect authority.

## Exact operation rule refinement

HI12/HI-T12/EV-HI12 completes existing HI03/HI07 narrow effect semantics for multiple verbs on one target; no broadened target or wildcard authorization.

## Protected native enrollment proof fields

HI10 protected Desktop enrollment requires actual immutable app manifest and renderer role/exe/tree digests, sandbox policy, relaunch monitor artifact/digest and window-denial patch artifact/digest. Missing installed value is incomplete; planning never invents a binary or patch SHA. Renderer flags/kernel namespace/seccomp/parent lineage and actual relaunch/window control observations must come from root inspector, not caller booleans. Role-specific browser/renderer/helper expectations are pinned; mainPID-only flags/seccomp do not prove renderer sandbox. sandbox_attestation schema1 fields and invalidation rules are in native-host-service-contract.json. New process/member/exe/generation/monitor/patch change invalidates exposure until fresh complete proof; preserve original actual native negative probes.

HI11 authority.json may contain strict native_bridges list with id,producer_profile_id,gateway_profile_id,canonicalizer_artifact_id,canonicalizer_sha256,approved_operation. Root joins principals/process_profiles for actual protected roles/UID/exe/profile and provider_enrollments for exact selected effect target/recipient/model/account; current peer PIDFD/starttime/cgroup/generation comes from trusted live process registry. Unique exact producer/operation mapping; duplicate/missing/ambiguous joins or absent immutable canonicalizer digest deny. Config lists no arbitrary process/URL/role supplied by worker. Complete request capture and same protected canonicalizer semantics from v2 stay required.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.
