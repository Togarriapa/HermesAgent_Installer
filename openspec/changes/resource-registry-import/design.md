# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Use pristine `sources/<repo>/<sha>/` and separate `generations/<id>/{resolved,runtime}` plus `overlays/{local,private}`. Fetch pinned content without execution during discovery; only reviewed validator/materializer scripts may execute in an isolated workspace with no production credentials. Catalog 2.3.1 at 113f42d33be9e0c8f0f47f5ca998e687323dec83 declares eight nonrecursive roots and metadata identities; inspect rather than assume roots. Run scripts/check_catalog_consistency.py, validate_registry.py, validate_deliberation.py, validate_expansion_v21.py, validate_expansion_v22.py, validate_quality_v22.py, validate_quality_overlays_v22.py, and materialize_effective_registry.py --check-only; review check_pr_quality.py only for source change contexts and do not execute registry update notifications.

Create typed raw/resolved/authorized/runtime records: selectors/semver dependency DAG and cycles; scalar/map/list inheritance; universal/kind/domain quality; semantic overlay rebasing/quarantine; host authorization intersection; compatibility; isolation; runtime secret references; health/acceptance; atomic pointer switch. Preserve all supporting assets and paths, metadata versions and digest. Generate crosswalk per kind: profiles -> separate HERMES_HOME plus behavioral files/config, skills -> native directory contract with references, plugins/MCPs -> reviewed declared adapters and allowlists, bundles -> internal recruitment roster, channels -> Hermes-only verified identity routing, cron/webhooks -> disabled definitions until selected and configured. No declaration creates a missing server or host authority.

The enforced tool-dispatch boundary must mediate native Hermes tools, subprocesses, MCP calls, schedules, webhooks, Codex callback paths and memory/provider dispatch. A capability without mediation is unavailable, not prompt-sandboxed. Use unprivileged bounded brokers and Linux process/filesystem/network isolation where available, deny arbitrary shell/SSH/systemctl in privileged capability. Authentik System membership is freshly resolved from authenticated session principal before each homelab write; lookup failure, identity mismatch, indirect membership ambiguity and cached claims deny. Resolve alarm recipients separately and freshly. Broker target allowlists and payload-bound one-shot permissions cap resource/account scopes. No external infrastructure targets are enrolled by this plan.

Implement User -> Hermes -> Orchestrator -> internal specialists -> Orchestrator -> Hermes as correlated runtime routing. Specialists cannot bind user channels or bypass the dispatcher. Preserve contributor/evidence/dissent response metadata, DAG/ephemeral board, smallest competent recruitment, multiple instances with separate state and bounded concurrency; cancel descendants and release idle work. Never have concurrent writers share HERMES_HOME. Resource readiness reports source/text-core/individual/full-compliance independently. Atomic activation requires dependency/policy/topology tests and rollback; expanded permissions or conflicting overlays quarantine.

Use typed modular orchestration and explicit adapters rather than a monolithic shell script, because checkpointed operations and injectable command/network/filesystem interfaces make preservation and failure contracts testable. Prefer native supported upstream mechanisms over replacement frameworks; wrap them only at actual policy/compatibility boundaries.

## Risks / Trade-offs

- Upstream drift or unsupported ARM64 transitive dependency -> revalidate pinned source at component configure/update; retain previous generation and truthful unsupported state.
- Account or hardware unavailable -> finish code and synthetic fixtures, deliver executable target workflow, keep live verification unchecked.
- Secret or authority propagation -> host-managed references, mandatory dispatch mediation, synthetic canary and negative side-effect tests.
- Resource contention or partial failure -> measured limits, bounded cancellation, per-step journal, atomic activation and ownership-aware rollback.

## Migration Plan

Implement foundation tasks before dependent obligations. Stage artifacts and review dry-run against pre-state; isolated fixtures precede any authorized target install. Activate only compatible verified generations; restore previous pointer/config snapshot on failure and retain user data. Commit code/test/evidence with requirement and change IDs. Archive only completed verified scope and merge deltas into canonical specs through the installed supported workflow.

## Open Questions

Live target/account values and pending source selections are tracked in planning/blockers.json. The architecture supports source overrides and configure-later without deleting these requirements. New technical scope choices require a separate Sol-reviewed append-only amendment, never edits to the frozen baseline.

Audio/HTTP native input transport v40: `plans/amendments/2026-10-09-native-input-audio-http-channels-v40.md`; original5 channels retain required pending scope.

Original WhatsApp authenticated trigger v45: `plans/amendments/2026-10-09-whatsapp-authenticated-trigger-enrollment-v45.md`; source-backed setup/schema acquisition, originalchannel tasks remain pending.

Root channel peer delivery v48: `plans/amendments/2026-10-09-root-channel-peer-delivery-v48.md`; concrete originalchannel transport join, tasks open.

Composio selected trigger derivation v77: `plans/amendments/2026-10-10-composio-trigger-artifact-exchange-derivation-v77.md`; existing RG-F03/R0060/RB-T08 gates remain open and account setup proof stays distinct.

Existing resource child-attempt context v82: `plans/amendments/2026-10-10-resource-existing-child-attempt-context-v82.md`; existing RB-T08 task open.

Pre-active native assembly selection v84: `plans/amendments/2026-10-10-pre-active-native-assembly-selection-v84.md`; HI-T08/HI-T09/RB-T09 remain open.

Bootstrap action and derived store ownership v87: `plans/amendments/2026-10-10-bootstrap-action-derived-store-ownership-v87.md`; existing BD/HI/RB tasks remain open.

Selected resource materialization and task route v88: `plans/amendments/2026-10-10-selected-resource-materialization-task-route-v88.md`; RB-T08/HI-T09/HI-T12 remain open.

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Resource task proof DTO and custody v93: `plans/amendments/2026-10-10-resource-task-proof-dto-custody-v93.md`; RB-T08/HI-T09/HI-T12 remain open.

HTTP and audio observed event schemas v94: `plans/amendments/2026-10-10-http-audio-observed-event-schemas-v94.md`; original RG-F03/R0060/native-input obligations remain open.

Resource task authority module and seal v95: `plans/amendments/2026-10-10-resource-task-authority-module-seal-v95.md`; RB-T08/HI-T09/HI-T12 remain open.

Private loopback enforcement choice v97: `plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97.md`; existing original implementation/acceptance obligations remain open.

Local audio device/consent v118: `plans/amendments/2026-10-10-local-audio-device-consent-v118.md`; original RG-F03/R0060/HI-T08 obligations remain open.
