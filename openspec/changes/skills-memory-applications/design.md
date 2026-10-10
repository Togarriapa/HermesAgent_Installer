# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

A generic reviewed-source component contract has fetch/inspect/plan/stage/configure/functional-test/activate/status/update/rollback/uninstall methods, capability/schema fields, bounded command execution and a concrete unsupported/pending reason. Specialized adapters must implement the behavior; a clone or no-op handler is never installed/functional. Do not implement a universal shell escape under the component interface. Source overrides validate URL/identity/revision/license and retain explicit selection audit before any pending candidate activates.

Portable skill importer copies complete relative trees with helpers/assets/root references and licenses into read-only pristine SSD sources. Build deterministic dedup aliases and task/profile-scoped native skill external_dirs/generated wrappers; native precedence is project/local/create_dir/external_dirs at observed Hermes version, so record collision outcome. Audit AGENTS.md/CLAUDE.md hooks/commands separately; no global concatenation and no claiming Markdown equals hooks. Each table item has its own task and local fixture/target evidence method in planning/traceability.json and component-contracts.json. Keep ECC and OmniRoute aliases one component; Impeccable pbakaus and Emil's separate skills are distinct selections and attribution stays explicit; third-party cybersecurity procedures never execute during setup.

Scientific/scraping/browser/render/graph environments are feature-specific and isolated, not one global dependency pile. Scrapegraph-ai observed Python >=3.12 constraint requires its own environment. Hyperframes/brag share compatible pinned renderer dependencies when safe; narration/vision/Gemini generation remain modality/provider-budget gated. Jarvis/OpenExecutive/Ruflo/screenshot-to-code are isolated optional applications, started on demand, never default coordinators. Browser Use local browser is separate from paid cloud browser. Reference catalogs such as public-apis and selected harness catalogs are indexed references rather than service provisioning.

Use Hermes native one-active-external-memory mechanism where compatible, preserving native working/session memory. Build namespaced provider choices for OpenViking, claude-mem and explicitly selected Agent Memory; enforce one automatic capture owner while allowing scoped retrieval sources. Stop/flush previous owner when switching and protect incompatible DB schemas. At the observed Hermes revision OpenViking installs from the native plugin catalog at volcengine/OpenViking/examples/hermes-plugin, selected with memory.provider: openviking; configure the separate server and doctor. Its catalog plugin may auto-spawn a server inheriting the complete Hermes environment: prestart a sanitized isolated server with an environment allowlist and verify no unrelated provider tokens enter it. Set security.allow_lazy_installs: false; reviewed installer adapters own installation. Extraction/embedding separately pass privacy/capability/budget dispatcher. Prevent generated-memory recursive capture and store user/profile/source provenance. Synthetic fact -> extract -> stop/restart -> new-session retrieve is required; export/removal/backup/restore and isolation denial tests accompany each adapter. Unknown licenses limit redistribution and activation with exact status rather than deleting the item.

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

## Fixed per-profile memory connectors (SK01)

Follow planning/memory-service-connector-contract.json and memory-service-connectors-v1. Add root selected target IDs memory-openviking:<profile>, memory-claude-mem:<profile>, memory-agentmemory:<profile>, each separate service namespace/store/generation and finite route catalog under HI07/HI12. OpenViking1933 and AgentMemory3111 are pinned config facts; Claude exact port/backend must be source-config verified before enrollment, not guessed. No worker URL/port/path/method/key/project/user scope. Root forces scope, binds payload/receipt/private policy/owner generation and finite operation bounds before bytes.

Pinned Claude-mem SQLite server lacks delete while Postgres server exposes scoped memory deletion and worker family has distinct observation routes; required backend_variant and immutable route schema prevent blending them. Missing required delete/export/restore remains an exact integration obligation, not optional success. OpenViking session compound create/append/commit or extract is finite owned protocol, never fake per-memory deletion; deny uncontrolled auto-commit/provider egress and lazy embedding installs. AgentMemory dedicated per-profile store forbids its many unrelated mesh/history/Claude/team endpoints and caller project/agentID overrides.

Prestart sanitized reviewed services, verify bounded actual readiness before selectedowner use, preserve native session memory and one automatic owner. Extraction/embedding/background/derived retrieval always host-private policy and inherited complete lineage, fresh grants per real effect within original deadline. Restart/rotation/restore invalidates connectors/background grants and retains prior private store/owner generations. Native positive and hostile cross-profile/owner/URI/variant/source/restore probes required; fixture routes/health status do not establish useful or private native memory.

SK01 / SK-T01 route identity clarification: see plans/amendments/2026-10-09-memory-route-identities-v2.md and planning/memory-service-connector-contract.json. Stable per-backend Claude approved_route_ids join distinct outer effect and connector targets; no inferred missing health/delete or variant fallback. Existing task remains open.

Selected binding/memory recipes v4: plans/amendments/2026-10-09-selected-native-binding-memory-recipes-v4.md defines root no-argument peer-selected package and fixed compound route steps with fresh child grants, no caller path/provenance or reused outer grant. Existing HI-T08/09/SK-T01 remain open.

Memory compound wire v5: plans/amendments/2026-10-09-memory-compound-wire-v5.md and memory-service-connector-contract.json specify canonical body envelope/root serializer/stateful finite steps; no worker HTTPframe/scope/step authority and fresh grants each step. Existing tasks remain open.

Closed memory/model recipe identities v6: plans/amendments/2026-10-09-closed-memory-model-recipe-ids-v6.md and protected contract JSON define finite schema/recipe IDs, empty model launch parameters and root-owned forced scope. Actual serializer/result/ARM64 effect evidence remains pending, existing tasks open.

Original R0092/R0093 functional fixture refinement: plans/amendments/2026-10-09-local-component-functional-fixtures-v1.md and planning/local-component-functional-fixture-contract.json require actual pinned source+locks/upstreampipeline, syntheticvision/localHTML and real mockedLLMboundary, not skill references/surrogateprotocol. ExistingSK-R0092/0093 and EV-R0092/0093 remainopen.

Pinned source document link v1: plans/amendments/2026-10-09-pinned-source-document-link-v1.md and pinned-source-document-link-contract.json preserveoriginalGitlink metadata and allowonly exactpinnedrootstable regularcompiled documentcopy. Upstreamdocs notgovernance; R0092/SK-R0092/EV-R0092 remainopen.

Additive root-state/build-mount refinement (SK01 / SK-T01): see plans/amendments/2026-10-09-root-memory-state-build-mounts-v1.md; selected protected mount nodes and separate UID0 authority journal state are mandatory. Original scope and pending target acceptance unchanged.

Immutable source-buffer materialization v2: plans/amendments/2026-10-09-immutable-source-buffer-materialization-v2.md; exact retained original Git bytes may replace source-filesystem inode checks only when no mutable source path is used. Destination/root closure checks and existing SK-R0092 target gates remain.

Root setup/journal selection v8: plans/amendments/2026-10-09-root-setup-session-journal-catalog-v8.md specifies installed root-local initial session/intent/receipt transport and active root journal catalog. Existing HI/BD/LC/SK tasks and target evidence remain open.

Actual EOF/schema derivation v54: `plans/amendments/2026-10-09-stdin-eof-schema-derivation-v54.md`; exact root receipt joins in planning contracts, existing task IDs remain unchecked.

Memory lifecycle/whole-turn v64: `plans/amendments/2026-10-10-memory-lifecycle-whole-turn-v64.md`; actual backend/source proof required, existing task gates open.

Whole-turn handle delivery v70: `plans/amendments/2026-10-10-whole-turn-authenticated-handle-delivery-v70.md`; existing SK-T01/HI-T08/HI-T11 remain open, authenticated root input/response metadata only, actual whole-turn proof and failure evidence required.

Active row joins v71: `plans/amendments/2026-10-10-memory-lifecycle-xpra-overlay-row-joins-v71.md`; existing task/target gates remain open, actual retained source/runtime receipts required.

Root-selected lifecycle authority v80: `plans/amendments/2026-10-10-root-selected-service-lifecycle-authority-v80.md`; existing HI/RT/SK tasks open, separate actual controller and selected subject proof required.

Selected lifecycle stop canonical payload v85: `plans/amendments/2026-10-10-selected-lifecycle-stop-canonical-payload-v85.md`; existing HI-T09/HI-T13/SK-T01 remain open.

Native request observation domain v86: `plans/amendments/2026-10-10-native-request-observation-domain-v86.md`; existing HI-T11/SK-T01 remain open.

Selected application workload binding v89: `plans/amendments/2026-10-10-selected-application-workload-binding-v89.md`; existing SK-F03/R0067/R0138/AC12 implementation and acceptance obligations remain open.

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Root turn transcript encoding v96: `plans/amendments/2026-10-10-root-turn-transcript-encoding-v96.md`; SK-T01/HI-T08/HI-T11 remain open.

Memory capture enablement consent v98: `plans/amendments/2026-10-10-memory-capture-enablement-consent-v98.md`; existing SK-T01/SK-F02/SK01 obligations remain open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Application owned execution receipts v104: `plans/amendments/2026-10-10-application-owned-execution-receipts-v104.md`; actual distinct selected grant/controller/probe/manager terminal/artifact result producer required, no ResourceTask/RuntimeReview substitutes; existing implementation/acceptance tasks open.

Application request source v107: `plans/amendments/2026-10-10-application-request-source-v107.md`; actual finite installer qualification request distinct from absent native application mappings. Existing SK-F03/R0067/R0138/AC12 implementation and acceptance remain open.

Private memory endpoint adapter v108: `plans/amendments/2026-10-10-private-memory-endpoint-adapter-v108.md`; exact distinct private text/embed model/deployment/current consent and bounded protocol producer required. Existing engine lifecycle/semantic memory/acceptance remain open.

Preactive application source and qualification consent v117: `plans/amendments/2026-10-10-preactive-application-source-consent-v117.md`; actual setupsource/lock receipts beforeactive and same explicitchoice finite purposeconsent, operational authorization untouched. Existing application/AC12 gates open.

Memory lifecycle active closure v119: `plans/amendments/2026-10-10-memory-lifecycle-active-closure-v119.md`; existing lifecycle/capture/semantic acceptance obligations remain open.

Memory service enable choice v124: `plans/amendments/2026-10-10-memory-service-enable-choice-v124.md`; actual configuration producer/active service projection required, capture/semantic gates open.

Private memory observed deployments v125: `plans/amendments/2026-10-10-private-memory-observed-deployments-v125.md`; actual endpoint/model/source/load/private route proofs remain open, no download authorized.
