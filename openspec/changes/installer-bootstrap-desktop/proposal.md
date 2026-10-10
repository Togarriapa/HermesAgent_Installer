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

Protected lifecycle control v1: plans/amendments/2026-10-09-protected-lifecycle-control-v1.md defines exactrootprovision/currentintent/firstsnapshot/CASrecovery, finiteprocess.control facade andactualloadedclosureprooflimits. ExistingBD/LC/HI tasksremainopen.

Full Hermes source archive v2: plans/amendments/2026-10-09-full-hermes-source-archive-pin-v2.md and planning/protected-artifact-source-catalog.json pin complete official source/archive/export identity. Source staging is separate from runtime/install/native acceptance; existing BD/HI tasks stay open.

Build service/bootstrap provenance v7: plans/amendments/2026-10-09-build-service-bootstrap-record-provenance-v7.md defines exact dedicated build profile join and root-selected identity versus actual runtime receipt provenance. Existing HI/HW/BD/LC tasks remain open.

Root setup/journal selection v8: plans/amendments/2026-10-09-root-setup-session-journal-catalog-v8.md specifies installed root-local initial session/intent/receipt transport and active root journal catalog. Existing HI/BD/LC/SK tasks and target evidence remain open.

### v14 installed first setup

BD-F01/BD-F03/LC-F03/HI-T01 use root_local_setup_session installed_selection_catalog and first_setup_artifact_fetch in planning/protected-lifecycle-control-contract.json. Root deployment bytes and transaction-scoped CAS receipts are required; original acceptance remains open.

### v15 native health and typed admission

Use planning/protected-lifecycle-control-contract.json native_health_receipt for actual native health and planning/protected-resource-job-contract.json typed_admission/service_methods/recipe_domain for RB-T08. Original tasks/acceptance remain pending.

### v16 installed input closure joins

Use the exact installed_selection_catalog.release_root, task_runner_protocol.source_resolver and native-package-binding-contract.json initial_native_input_observer joins. Existing BD/HI/RB tasks and acceptance remain pending.

### v19 setup store and probe DTO

Use installed_selection_catalog artifact_catalog/artifact_store joins, root task canonical payload bytes and gateway_probe_response exact envelope. Existing BD/HI/RB tasks remain pending.

### v21 installed bootstrap policy source

Use installed_selection_catalog.bootstrap_policy_artifact explicit selected policy/template/receipt joins. Prepared records empty until actual runtime/health receipts; existing BD/LC/HI tasks remain pending.

### v22 runnable and health ordering

Use bootstrap_policy_artifact.activation_order: verified runnable custody publication precedes health observation, functional enablement follows actual passed current-generation health only. Existing acceptance remains pending.

### v26 usable first-stage publication

Use first_stage_policy_compiler exact stage0 constructor/choice/compile/publish/materialization/HERMES_HOME contracts before factory resolution. Existing BD/LC/HI tasks remain pending until actual native operation.

### v27 prepared native receipts and Hermes home

Use first_stage_policy_compiler exact home/prepared order/runtime artifact roles/independent Resources source and receipt_binding_rules_schema. Existing BD/LC/HI/RB tasks remain pending.

### v30 concrete closed compiler template

Use immutable installer-bootstrap-compiler-template-v1 bytes and exact root-binding grammar/stage executor in first_stage_policy_compiler. Prepared empty records until actual fact/receipt bindings. Existing BD/LC/HI tasks remain pending.

Additive observation assembly v31: `plans/amendments/2026-10-09-final-observation-assembly-v31.md`; preserve existing task IDs and open target gates. Selected root registries/current custody receipts supply actual observations; static catalog or caller claims do not.

Setup principal selection v32: `plans/amendments/2026-10-09-setup-principal-selection-v32.md` and lifecycle compiler principal_selection_receipt define exact first-setup trusted identity joins; existing tasks remain open.

Installed release/native assembly v33: `plans/amendments/2026-10-09-installed-release-native-assembly-v33.md`; exact root receipt and construction joins preserve existing task IDs and pending evidence.

Complete baseline receipt digest v34 clarifies full-tree and original160 snapshot domains: `plans/amendments/2026-10-09-complete-baseline-digest-v34.md`; no task completion.

Initial identity/terminal sequencing v35: `plans/amendments/2026-10-09-initial-identity-terminal-sequencing-v35.md`; exact existing task joins remain pending.

First-stage publication/ingress v36: `plans/amendments/2026-10-09-first-stage-publication-ingress-v36.md`; exact existing task construction joins, no completion claimed.

Official PM runtime receipt v37: `plans/amendments/2026-10-09-official-pm-runtime-receipt-v37.md`; exact root observed executable joins, existing tasks remain open.

Native candidate index delivery v38: `plans/amendments/2026-10-09-native-candidate-index-delivery-v38.md`; exact compiled member/receipt joins preserve open tasks.

Initial compilation handoff v42: `plans/amendments/2026-10-09-initial-compilation-handoff-v42.md`; exact stage0/post-policy separation, original tasks open.

First-selection/native-target v43: `plans/amendments/2026-10-09-first-selection-cas-native-target-v43.md`; exact existing task joins remain open.

Root task initial input v46: `plans/amendments/2026-10-09-root-task-initial-input-sequence-v46.md`; exact existing task sequencing, no target completion.

Root identity credential intake v47: `plans/amendments/2026-10-09-root-identity-credential-intake-v47.md`; exact original setupintake, tasks remain open.

Authentik template/actor API v49: `plans/amendments/2026-10-09-authentik-template-actor-api-v49.md`; exact source template and existing verifier, tasks open.

Root registry phase joins v50: `plans/amendments/2026-10-09-root-intake-delivery-phase-joins-v50.md`; exact existing effect/evidence phases, tasks open.

Native materialization CAS v51: `plans/amendments/2026-10-09-native-materialization-output-cas-v51.md`; exact source/output roles, tasks open.

Initial native input peer take v52: `plans/amendments/2026-10-09-native-initial-input-peer-take-v52.md`; exact source delivery beforestdin, tasks open.

Release plan/active compiler v53: `plans/amendments/2026-10-09-release-plan-active-compiler-v53.md`; exact source template/buildclaims, existing tasks open.

Live health control/output kinds v55: `plans/amendments/2026-10-09-live-health-control-output-kinds-v55.md`; existing tasks remain open until actual proof.

Native output encoding v56: `plans/amendments/2026-10-10-native-output-byte-encoding-v56.md`; actual compiler/CAS/readonly mount proof remains required and tasks open.

Native digest domains v58: `plans/amendments/2026-10-10-native-output-digest-domains-v58.md`; original compiled tree domain retained and task gates open.

Native generation/index identity v59: `plans/amendments/2026-10-10-native-generation-index-identity-v59.md`; existing HI task gates unchanged.

Selected display/loopback startup v60: `plans/amendments/2026-10-10-selected-display-loopback-startup-v60.md`; existing task/acceptance gates remain open.

Root key/source producer/catalog selection v61: `plans/amendments/2026-10-10-root-key-source-producer-composio-selection-v61.md`; existing task gates unchanged.

First source bootstrap actor v62: `plans/amendments/2026-10-10-first-source-bootstrap-actor-v62.md`; existing scope/tasks remain open.

Prepared base/reader/release manifest v63: `plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63.md`; existing gates remain open.

Bootstrap CAS/selected start grants v65: `plans/amendments/2026-10-10-bootstrap-cas-selected-start-grants-v65.md`; existing task gates unchanged.

Channel retained receipts/source choice v68: `plans/amendments/2026-10-10-channel-receipts-source-selection-v68.md`; existing task gates unchanged.

Literal bootstrap receipt binding source v72: `plans/amendments/2026-10-10-literal-bootstrap-receipt-bindings-v72.md`; existing BD/HI lifecycle gates open; actual typed root receipts required.

Prepared unresolved receipt rendering v74: `plans/amendments/2026-10-10-prepared-unresolved-receipt-rule-rendering-v74.md`; empty output identities remain dormant and actual active receipts required under existing BD/HI tasks.

Bootstrap source projection/store correction v75: `plans/amendments/2026-10-10-bootstrap-binding-projection-store-correction-v75.md`; existing BD/HI tasks remain open.

First-bootstrap pinned interpreter v76: `plans/amendments/2026-10-10-first-bootstrap-isolated-pinned-interpreter-v76.md`; existing BD/HI tasks remain open, actual isolated Linux runtime/actor proof required.

Same-process bootstrap handoff v78: `plans/amendments/2026-10-10-bootstrap-same-process-sealed-runtime-handoff-v78.md`; existing BD/HI tasks open, actual trusted re-exec proof required.

Existing typed candidate handoff v79: `plans/amendments/2026-10-10-bootstrap-existing-typed-candidate-handoff-v79.md`; existing BD/HI tasks open.

Closed root plan template selection v81: `plans/amendments/2026-10-10-closed-root-plan-template-selection-v81.md`; existing BD/HI tasks open.

Two-stage source driver interpretation v83: `plans/amendments/2026-10-10-two-stage-source-driver-interpretation-v83.md`; existing BD/HI tasks open.

Selected lifecycle stop canonical payload v85: `plans/amendments/2026-10-10-selected-lifecycle-stop-canonical-payload-v85.md`; existing HI-T09/HI-T13/SK-T01 remain open.

Native request observation domain v86: `plans/amendments/2026-10-10-native-request-observation-domain-v86.md`; existing HI-T11/SK-T01 remain open.

Pre-active native assembly selection v84: `plans/amendments/2026-10-10-pre-active-native-assembly-selection-v84.md`; HI-T08/HI-T09/RB-T09 remain open.

Bootstrap action and derived store ownership v87: `plans/amendments/2026-10-10-bootstrap-action-derived-store-ownership-v87.md`; existing BD/HI/RB tasks remain open.

Selected resource materialization and task route v88: `plans/amendments/2026-10-10-selected-resource-materialization-task-route-v88.md`; RB-T08/HI-T09/HI-T12 remain open.

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Reviewed native capability selection v91: `plans/amendments/2026-10-10-reviewed-native-capability-selection-v91.md`; HI-T03 remains open.

MCP derived schema CAS closure v92: `plans/amendments/2026-10-10-mcp-derived-schema-cas-closure-v92.md`; existing MC-F01/HI-T08 remain open.

Resource task proof DTO and custody v93: `plans/amendments/2026-10-10-resource-task-proof-dto-custody-v93.md`; RB-T08/HI-T09/HI-T12 remain open.

HTTP and audio observed event schemas v94: `plans/amendments/2026-10-10-http-audio-observed-event-schemas-v94.md`; original RG-F03/R0060/native-input obligations remain open.

Resource task authority module and seal v95: `plans/amendments/2026-10-10-resource-task-authority-module-seal-v95.md`; RB-T08/HI-T09/HI-T12 remain open.

Root turn transcript encoding v96: `plans/amendments/2026-10-10-root-turn-transcript-encoding-v96.md`; SK-T01/HI-T08/HI-T11 remain open.

Private loopback enforcement choice v97: `plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97.md`; existing original implementation/acceptance obligations remain open.

Memory capture enablement consent v98: `plans/amendments/2026-10-10-memory-capture-enablement-consent-v98.md`; existing SK-T01/SK-F02/SK01 obligations remain open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Prepared build service selection v115: `plans/amendments/2026-10-10-prepared-build-service-selection-v115.md`; source-owned setup-only exact build subject/current NSS/root selection before activeprofile, no fabricated worker. Existing build/setup/acceptance tasks remain open.

Pinned runtime release asset redirect v116: `plans/amendments/2026-10-10-pinned-runtime-release-asset-redirect-v116.md`; one exact publicCPython GitHub302 officialasset hop with TLS/header/query/integrity checks, all other NoRedirect unchanged. Existing actualbootstrap/acceptance tasks remain open.

Pinned PyYAML extraction correction v131: `plans/amendments/2026-10-10-pinned-pyyaml-wheel-members-v131.md`; unchanged exact pinned wheel additionally includes `_yaml/` and `_yaml/__init__.py`. Full RECORD/archive/isolation/probe checks remain mandatory; actual installation and acceptance remain pending.

Concrete bootstrap/source/public disclosure v149: `plans/amendments/2026-10-10-runtime-member-role-public-disclosure-v149.md`; exact runtime member layout, prepared held source distinct live import, genuine per-input public disclosure. All AC open.

Prepared source module layout v154: `plans/amendments/2026-10-10-prepared-source-module-layout-v154.md`; exact source-module members distinct root-imported module and later worker evidence. All AC open.

Root native health start v159: `plans/amendments/2026-10-10-root-native-health-start-v159.md`; actual committed runnable authority then root health admission/control before fixture input, normal enablement withheld.

Installed local qualification v160: `plans/amendments/2026-10-10-installed-local-qualification-v160.md`; finite installed source-owned fixture dispatcher with genuine production actor/receipts and cleanup, distinct Pi acceptance.

Qualification root adapter v162: `plans/amendments/2026-10-10-qualification-root-adapter-v162.md`; dedicated source-bound held root/publication/session/key namespace, actual core authority validation and untouched production constants.

Health input source delivery v163: `plans/amendments/2026-10-10-health-input-source-delivery-v163.md`; root-resolved PRIVATE fixture context, actual observer/source membership and distinct write/EOF/one-use take; no task-origin substitution.

Qualification envelope v164: `plans/amendments/2026-10-10-qualification-envelope-v164.md`; exact scoped envelope/generation/pointer/session bytes verified through held run-root FD and unchanged strict core validators.

Runtime role publication join v165: `plans/amendments/2026-10-10-runtime-role-publication-join-v165.md`; typed PM/native CAS closure and single strict atomic activation, fresh runtime committed observation independent expired setup.

Qualification key signer v166: `plans/amendments/2026-10-10-qualification-key-signer-v166.md`; genuine held key signs only exact fixture enrollment envelope before service adoption.

Qualification session storage v167: `plans/amendments/2026-10-10-qualification-session-storage-v167.md`; live session sealed/current only, retained file historical metadata without signature or authority.

Native precompile reservation v169: `plans/amendments/2026-10-10-native-precompile-reservation-v169.md`; source-backed preactive output authorization and same reservation through strict compilation/atomic publication.

Native output role correction v170: `plans/amendments/2026-10-10-native-output-role-correction-v170.md`; exact existing native-boundary-overlay/boundary-overlay, no alias or new role.

Selected window input v177: `plans/amendments/2026-10-10-selected-window-input-observation-v177.md`; actual focus-stable F24 events/current receipt, no aggregate bool proof.


Source-join producers v178: `plans/amendments/2026-10-10-source-join-producers-v178.md`. Exact retained setup/source/PM/native definition/member, finite fixture descriptor/service observation and local overlay invocation producers; all AC01..18 OPEN, baseline unchanged. Producer ownership/order and acceptance remain in HI-T178.1..5.


Reviewed source members and boundary joins v180: `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; finite exact merged module pins, corrected standalone builder role,21-field separate local-operation publication and per-worker kernel start barrier. Producer ownership/order/evidence tasks remain OPEN; baseline and all AC01..18 unchanged.


## Conditional Authentik and local-owner setup v181

Restore original R0058/R0060/R0143 conditional capability scope. Contract and sequential producer/evidence details: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. No runtime implementation or acceptance is claimed; all AC01..18 OPEN.


## Active network generation owner v182

Use the concrete RootActiveNetworkGenerationOwner/runtime signed-choice and active-publication composition in `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Replace ambiguous active_enrollment with exact current generation projection; preserve original adoption deadline and fresh revocation, release/actor/key/journal/CAS checks independently of expired setup. Own-worker kernel gate and cleanup remain mandatory, all AC01..18 OPEN.


## Concrete signed worker and active overlay producers v183

Follow `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`: exact held recipe→signed choice→service-generation producer→active PM/native custody, and signed local-owner/source/view adoption→current NSS/loaded invocation/one-use four-method grant. No setup object or static metadata becomes active authority. Source pins pending committed review, all AC01..18 OPEN.


## Network wire/digest clarification v184

Exact field sets/FKs/source and lifecycle mapping: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md` / `planning/network-row-wire-v184.json`. Generated AF_UNIX rows stay separate from existing TCP private-loopback rows; enclosing digest exists only on runtime projection. Pre-READY mount permits loader binding; effects require later actual READY/source/invocation/grant proof. All AC01..18 OPEN.


## Owner observer/source/RPC clarification v185

Exact typed registration/READY/module/source-capture and worker proxy→native.owner-overlay.execute→observed invocation→one-use grant contract: `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md` / `planning/owner-overlay-observer-wire-v185.json`. Backend61 action schemas unchanged, no synthetic observer/source authority, all AC01..18 OPEN.


## Preactive listener phase clarification v186

Actual fixed root-owned listener before recipe signing and exact authenticated active FD adoption/re-observation: `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`. No future path/socketpair or prepared receipt substitutes for active authority; no effects before adoption. Source pins pending, all AC01..18 OPEN.


## Cross-process listener activation v187

Exact supervised installed daemon/private pathname control/peer PIDFD/unit/release/source/current publication binding and one-use SCM_RIGHTS adoption: `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md` / `planning/listener-activation-channel-v187.json`. Each actor verifies only itself locally; UID0/same-process/socketpair does not prove handoff. Source pins/acceptance OPEN.


Two-actor health v191: `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md` replaces unsafe setup-session aliasing with independently current daemon commit/source proof, actual fixed source run/events and one-use authenticated setup health intent. Only consumer-completed same-generation journal witness may enable; ACK is insufficient. All acceptance/source pins remain OPEN.


## Final coherent source review v195

Exact closed source/member/catalog/preload application under existing VD-T180.6/VD-T183.5: `plans/amendments/2026-10-10-final-coherent-source-pin-review-v195.md` and `planning/final-coherent-source-pin-review-v195.json`. Source0add8c33 follows reviewed nested leaf corrections; metadata self-pinning is excluded. All original implementation/acceptance tasks and AC01..AC18 remain OPEN.


## Safe bootstrap diagnostics v196

Exact finite output redaction, reviewed two-member source update and ownership/evidence: `plans/amendments/2026-10-10-safe-bootstrap-diagnostics-source-review-v196.md` / `planning/safe-bootstrap-diagnostics-source-review-v196.json`. Guards/phases and all acceptance remain unchanged; actual source-CAS failure diagnosis is independent of still-open display/task runtime custody.


Fixed release-store publisher source review v200: `plans/amendments/2026-10-10-fixed-release-store-source-review-v200.md`. Existing HI-T149.1 admits only the exact corrected candidate-held publisher metadata and fixed root directory effect; no new pin table/catalog row or acceptance.


Actual publication core/acquisition compatibility v201: `plans/amendments/2026-10-10-publication-core-and-fixture-acquisition-v201.md`. Existing HI160/197 compiler emits authenticated core member; workload consumes exact published proof. New fixed acquisition original bound is separate from unchanged short effect leases. All acceptance OPEN.


Finite real remote choice/three-role source producer v202: `plans/amendments/2026-10-10-selected-remote-role-source-inputs-v202.md`. Workload owns actual TTY/source/runtime/NSS/build inputs; compiler consumes exact sealed inputs; original source/account/ARM64/sandbox/network acceptance remains OPEN.

Typed finite bootstrap diagnostics v203: `plans/amendments/2026-10-10-typed-bootstrap-runtime-diagnostics-v203.md`; exact source boundary RuntimeError only, no dynamic trust error text or behavior change.

Typed diagnostic source review v204: exact fd09b11d leaf replacements are in planning/typed-bootstrap-diagnostic-source-review-v204.json under BD-T203.1 / VD-T203.2. Pin application/unexcluded suite/target evidence remain open; all acceptance open.

Jarvis sole user-facing profile v205: direct user requirement and audited supported default/display_name mapping; all208 source profiles preserved,207 protected isolated delegate homes, actual native/UI/default routing and ownership-safe migration required. Contract planning/jarvis-sole-user-profile-contract-v205.json; all acceptance open.


Raspberry Pi vendor dependency refinement v207: plans/amendments/2026-10-10-raspberry-pi-nft-dependency-observation-v207.md defines only exact libc6/u3/arm64 signed evidence for reviewed Debian nft, per-archive retained trust anchors, bounded live/cache metadata and unchanged installed ELF/kernel proof. No package/key mutation; all acceptance OPEN.

Bootstrap handoff TTY reconfirmation v208: new explicit same-SHA observation after slow acquisition, same original controller/action/source/runtime joins, unchanged60s proof TTL and one-use transition. planning/bootstrap-handoff-tty-reconfirmation-v208.json; BD-T208.1/VD-T208.2 OPEN.
