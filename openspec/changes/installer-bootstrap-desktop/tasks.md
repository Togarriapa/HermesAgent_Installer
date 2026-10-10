# Tasks

Dependencies: planning baseline. Full IDs and task edges: planning/dependency-graph.json. Implementation owner: GPT-6 Luna. All boxes are incomplete; artifact completion is not implementation acceptance.

## 1. Foundation with tests and documentation

- [ ] 1.1 `BD-F01` Create typed orchestration package, thin bootstrap, configuration/result interfaces and sandboxed command runner; verify CLI help, read-only plan fixture and unsupported-host rejection; document bootstrap. Evidence: `tests/contracts/test_bootstrap.py`.
- [ ] 1.2 `BD-F02` Implement complete preflight facts and adoption inventory with ownership boundaries; verify fresh/existing ARM64 fixtures, absent graphical session, locked package manager and unrelated-service preservation; document compatibility. Evidence: `tests/contracts/test_config.py`.
- [ ] 1.3 `BD-F03` Implement pinned official Agent install and separate Desktop release/source builders, safe user-session startup and truthful fallback; verify build fixture invocation and actual native target workflow; document source build. Evidence: `tests/contracts/test_desktop.py`.

## 2. Traceable individual obligations with verification

- [ ] 2.1 `BD-R0023` Implement `R0023` in `src/hermes_installer/preflight.py`: Build an installer for this machine: Verify with `tests/contracts/test_config.py` (EV-R0023): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.2 `BD-R0024` Implement `R0024` in `src/hermes_installer/preflight.py`: Raspberry Pi 5 with 16 GB RAM. Verify with `tests/contracts/test_config.py` (EV-R0024): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.3 `BD-R0025` Implement `R0025` in `src/hermes_installer/preflight.py`: 1 TB SSD. Detect its actual usable capacity, free space, filesystem, mount, and connection type. Verify with `tests/contracts/test_config.py` (EV-R0025): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.4 `BD-R0026` Implement `R0026` in `src/hermes_installer/preflight.py`: Google Coral TPU. Detect whether it is USB or PCIe/M.2 before choosing drivers. Verify with `tests/contracts/test_config.py` (EV-R0026): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.5 `BD-R0027` Implement `R0027` in `src/hermes_installer/desktop.py`: A supported 64-bit Linux installation, preferably Raspberry Pi OS with a desktop when compatible with the selected dependencies. Verify with `tests/contracts/test_desktop.py` (EV-R0027): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.6 `BD-R0028` Implement `R0028` in `src/hermes_installer/desktop.py`: Install Hermes Desktop and its Hermes Agent backend, preinstall my profiles and skills, and integrate the requested projects and MCP connections to the extent their real upstream capabilities and my accounts permit. Verify with `tests/contracts/test_desktop.py` (EV-R0028): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.7 `BD-R0029` Implement `R0029` in `src/hermes_installer/preflight.py`: The result must work for both a fresh supported system and a machine with an existing installation. Preserve existing user data, configurations, credentials, memories, and unrelated services. Detect existing Home Assistant, model servers, speech services, and occupied ports before making changes. Verify with `tests/contracts/test_config.py` (EV-R0029): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.8 `BD-R0030` Implement `R0030` in `src/hermes_installer/preflight.py`: Do not reimage the machine, format storage, or replace an existing service as a side effect of routine installation. Verify with `tests/contracts/test_config.py` (EV-R0030): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.9 `BD-R0031` Implement `R0031` in `src/hermes_installer/config.py`: Use English for the installer and documentation. Default new installer-owned schedules and displayed times to `Europe/Lisbon`, while preserving an existing host timezone unless the user selects a change. Verify with `tests/contracts/test_config.py` (EV-R0031): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.10 `BD-R0033` Implement `R0033` in `src/hermes_installer/desktop.py`: Use NousResearch/hermes-agent (https://github.com/NousResearch/hermes-agent) as the canonical upstream. Read its current Desktop README (https://github.com/NousResearch/hermes-agent/blob/main/apps/desktop/README.md), build instructions, installation guide, and platform support (https://hermes-agent.nousresearch.com/docs/getting-started/platform-support). Verify with `tests/contracts/test_desktop.py` (EV-R0033): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.11 `BD-R0034` Implement `R0034` in `src/hermes_installer/desktop.py`: The research snapshot lists Linux aarch64 as a supported agent platform and documents `hermes desktop` for building/launching the official GUI against an existing install. It also says Linux desktop release packaging is currently disabled. Therefore: Verify with `tests/contracts/test_desktop.py` (EV-R0034): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.12 `BD-R0035` Implement `R0035` in `src/hermes_installer/desktop.py`: Prefer an official compatible release if one exists at implementation time; otherwise implement and verify the official ARM64 source-build path. Verify with `tests/contracts/test_config.py` (EV-R0035): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.13 `BD-R0036` Implement `R0036` in `src/hermes_installer/desktop.py`: Resolve Agent and Desktop versions separately when upstream releases them separately. Verify with `tests/contracts/test_desktop.py` (EV-R0036): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.14 `BD-R0037` Implement `R0037` in `src/hermes_installer/desktop.py`: Verify the native window opens under the actual graphical session, connects to the intended backend, displays imported resources, and completes a conversation. Verify with `tests/contracts/test_desktop.py` (EV-R0037): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.15 `BD-R0038` Implement `R0038` in `src/hermes_installer/desktop.py`: Run the desktop under the intended desktop user. Use appropriate user-session startup; a headless system service is not a graphical login session. Verify with `tests/contracts/test_desktop.py` (EV-R0038): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.16 `BD-R0039` Implement `R0039` in `src/hermes_installer/desktop.py`: If native Desktop is blocked, retain a working supported agent and offer its browser interface or a documented remote-Desktop connection as a clearly labeled fallback. Do not label that fallback “Desktop installed.” Record the exact failure and recovery route. Verify with `tests/contracts/test_desktop.py` (EV-R0039): User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.17 `BD-R0040` Implement `R0040` in `src/hermes_installer/desktop.py`: Do not silently substitute a community fork, an unrelated Hermes application, or an unofficial Python package. Verify with `tests/contracts/test_config.py` (EV-R0040): On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending. Update `docs/bootstrap-desktop.md` and component/evidence states; preserve explicit blockers.

## Workflow follow-up

- Review code against every requirement/scenario and actual evidence; do not archive incomplete hardware/account tasks.
- Run strict pinned OpenSpec validation and coverage; archive only verified completed changes using the installed documented workflow, preserving dated history and canonical specs.
- Sol must approve refinement via append-only amendment; keep plans/2026-10-09-v1 immutable.

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

- [ ] HI-T131.1 — Materialize only the exact pinned PyYAML compatibility members; verify negative arbitrary descendants, traversal, special files, duplicates and RECORD mismatch; retain actual runtime probe and pending acceptance.

- [ ] HI-T149.1 release builder/verifier: Exact runtime-member finite role mapping and full closure validation preserving unique interpreter; serialize bounded selected-output reservations under the existing retained-CAS cap without pruning; test retained-output capacity and end-to-end receipt minting with exact selected source/runtime handles and sealed manifest; genuine ARM64 bootstrap rerun remains separate acceptance.

- [ ] HI-T149.2 factory/source observer/native custody: Prepared held worker release-member issuer distinct actual root import and later worker mounted import/PIDFD proof; missing/unselected source or role denies.

- [ ] HI-T149.3 public permission/factory/source input: Actual rootTTY per-input public disclosure binds retained bytes/selection and source ancestry; persistent choice alone/omitted parents/private ancestry deny.

- [ ] HI-T154.1 Broker/release/factory/source observer: exact final source/installed descriptors and separate current source-membership/root-import/worker-origin proofs.

- [ ] HI-T159.1 factory/entrypoint/startup/custody/health observer: Actual committed health admission/current receipt and root-selected-service health issuer/custody route/control-before-input producer; preserve runnable-before-health/withheld enablement.

- [ ] HI-T159.2 native fixture/observer/registration source owners: Provide genuine source-reviewed health request/result fixture artifact and actual loader/input/request/tool/provider/terminal observation closure, meaningful currentness/failure integration tests.

- [ ] HI-T160.1 root entrypoint/task kernel fixture/display fixture/controller custody: Implement fixed installed qualification source dispatcher and actual owned fixture recipe/schema assets; publish measured source pins for Sol review, real runtime/session/publication producer, no test authority shortcuts.

- [ ] HI-T160.2 task/display fixture owners: Replace synthetic Linux positive fixtures with exact production graph, preserve meaningful negative/cleanup checks and source/environment evidence distinct Pi acceptance.

- [ ] HI-T162.1 Controller custody/fixture publisher/host authority/entrypoint: genuine finite fixture compiler/key/publication/session/runtime adapter and namespace/currentness negative tests.

- [ ] HI-T163.1 Health/source/authority/custody: genuine selected source/context and health capture/write/EOF/take current-peer joins and negative tests.
- [ ] HI-T163.2 Broker/release/health: exact source asset enrollment, owned seed cleanup and semantic result gate with required actual provider.

- [ ] HI-T164.1 Fixture publisher/host enrollment/authority: exact canonical envelope and held namespace loader, scoped key/signature and wrong-source/currentness negatives.

- [ ] HI-T165.1 Factory/native/compiler/publisher: genuine typed runnable role closure and single atomic activation with truthful durable recovery.
- [ ] HI-T165.2 Enrollment/authority/health: fresh current committed source/CAS observation without expired setup renewal.

- [ ] HI-T166.1 Fixture key/publisher/authority: restricted prepublication envelope signer and same-key service adoption, source/currentness/domain negatives.

- [ ] HI-T167.1 Fixture session/publisher/enrollment: historical session file never restores live authority; fresh current lease required.

- [ ] HI-T169.1 Factory/native/compiler/publisher: actual source-authorized outputs, precompile reservation and same-reservation compiled claim transition, wrong-source/currentness negatives.

- [ ] HI-T170.1 Factory/native/compiler: exact existing five role/kind pairs and unknown-role negatives.

- [ ] HI-T177.1 Display/window observer/broker/custody: genuine selected-window F24 events and independent current observation/source proof.

- [ ] `HI-T178.1` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.2` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.5` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T180.1` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `SK-T180.2` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `HI-T180.5` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.


## v181 conditional identity and independent readiness

- [ ] `BD-T181.3` Choose selected capabilities before credentials; implement genuine independent fresh local-owner setup entry point. Exact producer/order and meaningful positive/failure evidence: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. Implementation and target acceptance OPEN.


## v182 active generation custody

- [ ] `HI-T182.1` Compile and publish finite signed-source/network/worker/enrollment projection. Exact producer/order/evidence: `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Implementation and target acceptance OPEN.
- [ ] `HI-T182.3` Consume current active owner projections through helper spawn/stop/release/reload cleanup. Exact producer/order/evidence: `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Implementation and target acceptance OPEN.


## v183 exact active effect producers

- [ ] `HI-T183.1` Produce concrete held worker recipes, signed choice fields and generated service/process/network output. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.
- [ ] `HI-T183.2` Reconstruct current active PM/native worker runtime member custody independently of setup. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.

- [ ] `HI-T183.0` Implement and source-review the exact fixed held Hermes/native-loader startup recipe source producer in `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`; no guessed argv or denial-only completion.


## v184 exact wire clarification

- [ ] `HI-T184.1` Implement exact schema2 finite network/runtime/source FK rows and acyclic canonical digest mapping. Exact contract: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`; implementation/acceptance OPEN.
- [ ] `HI-T184.2` Consume current row mapping and transient enclosing digest in real owner/manager lifecycle. Exact contract: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`; implementation/acceptance OPEN.


## v185 owner observation and proxy

- [ ] `HI-T185.2` Bind actual worker proxy/native execute RPC to observed invocation/current one-use local grant and CAS. Exact contract `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md`; implementation/acceptance OPEN.


## v186 endpoint source phase

- [ ] `HI-T186.1` Create and observe actual preactive root custody socket with no effects before signed recipe. Exact contract `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`; implementation/acceptance OPEN.
- [ ] `HI-T186.2` Verify active adoption and one-use exact listener FD transfer/current active re-observation. Exact contract `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`; implementation/acceptance OPEN.


## v187 actual activation transport

- [ ] `HI-T187.1` Produce verified installed root daemon supervisor/unit/launch and distinct peer observations. Exact contract `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md`; implementation/acceptance OPEN.
- [ ] `HI-T187.2` Implement actual both-process authenticated activation channel and one-use exact listener FD adoption. Exact contract `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md`; implementation/acceptance OPEN.

- [ ] HI-T191.3 Wire fixed authenticated setup intent and current completed witness at genuine two-process callpoints. See `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md`; all acceptance OPEN.


Existing `VD-T180.6`/`VD-T183.5` handoff: apply and verify only the exact v195 source/catalog/role/import closure batch in `plans/amendments/2026-10-10-final-coherent-source-pin-review-v195.md`. This source review leaves all existing checkboxes OPEN; no duplicate task or runtime acceptance is created.


- [ ] `BD-T196.1` Implement/revalidate closed safe bootstrap step/errno output and redaction/trust failure regressions; exact source reviewed in `plans/amendments/2026-10-10-safe-bootstrap-diagnostics-source-review-v196.md`, pin application/target outcome OPEN.
- [ ] `VD-T196.2` Apply exact two source tuple updates and verify focused source/installed metadata plus actual redacted target outcome; no skipped/old-pin failure becomes acceptance. All AC01..AC18 OPEN.


Existing `HI-T149.1`/`VD-T196.2` and source integration evidence include `plans/amendments/2026-10-10-fixed-release-store-source-review-v200.md`; actual Pi publication/installed-runtime acceptance remains OPEN.


Existing HI-T160.1/HI-T197.2/.3/VD-T197.4 include actual protected-core producer/parser/currentness and fixed acquisition-only deadline in `plans/amendments/2026-10-10-publication-core-and-fixture-acquisition-v201.md`; remain OPEN.


Existing HI-T160.1/HI-T197.2/VD-T197.4 include exact remote chooser and three-role source input/build/runtime production in `plans/amendments/2026-10-10-selected-remote-role-source-inputs-v202.md`; remain OPEN.

- [ ] BD-T203.1 Bootstrap owner: exact typed finite-stage diagnostic/redaction/state tests with unchanged trust/failure behavior.
- [ ] VD-T203.2 Source review/recheck: measured committed future source pins and actual target diagnostic, no inferred DD00 stage/acceptance.

- [ ] BD-T203.1 / VD-T203.2 (v204): Apply only reviewed two leaf tuples, rerun stale-pin test unexcluded and retain actual target diagnostic evidence; no acceptance promotion.

- [ ] RB-T205.1: Implement Jarvis sole default user entry and protected isolated specialist map.
- [ ] RB-T205.2: Preserve state/secrets with journaled idempotent owned migration and deny unowned conflicts.
- [ ] VD-T205.3: Verify genuine backend/Desktop listing/routing/delegation and migration effects; acceptance separate.

- [ ] HI-T207.1: Implement v207 exact vendor libc6 signed dependency evidence and concrete per-archive keyring/index currentness, preserving other Debian package provenance.
- [ ] VD-T207.2: Verify meaningful signed-cache/control/ELF and mutation failures plus actual target evidence separately; no package mutation or runtime acceptance inference.

- [ ] BD-T208.1: Implement final-boundary explicit root TTY reconfirmation and one-use fresh proof with unchanged identity/source/runtime joins.
- [ ] VD-T208.2: Verify slow acquisition, mismatch/drift/replay/expiry failures and review actual source pins/target result separately.

- [ ] BD-T208.1 / VD-T208.2 (v211): Apply exact reviewed root_setup tuple only, run full unexcluded regressions and retain genuine target handoff evidence.

- [ ] BD-T218.1: Implement Desktop-specific selected sourcepolicy/acquisition phase and locked toolchain/dependency/license receipts.
- [ ] BD-T218.2: Consume held closure in fixed offline209212 rolebuild with native ABI/script proof.
- [ ] VD-T218.3: Verify source/phase/integrity/TLS/architecture/script/currentness failures and actual target evidence separately.

- [ ] BD-T208.1 / VD-T208.2 (v220): Integrate exact reviewed FD3 source/evidence, full coherent checks and actual target handoff; no installed selfpin or acceptance inference.


- [ ] HI-T217.1: Resource owner implements exact retained v173 compiler/source projection and strict fixture policy/catalog issuer.
- [ ] HI-T217.2: Resource owner implements genuine child runtime/task outcome and source adapter proof; missing native route remains incomplete, never substitute success.
- [ ] VD-T217.3: Integrator implements current installed journal owner, retained actual unit/PIDFD, signed historical evidence and parent result consumption/cleanup with two-process failure tests.


- [ ] HI-T217.1 / HI-T217.2 / VD-T217.3 (v224): Implement exact source-owned row serializer/recipe selection, genuine fixture NSS policy/catalog and strict complete indexing; verify actual native outcome and missing-route incomplete without fake Authentik/rows/source proof.


- [ ] HI-T230.1: Separate source-only fixture lease issuance from one-time genuine prepared process custody attachment under v230.
- [ ] VD-T230.2: Verify pre-attachment denial, exact current owner joins, original expiry and both cleanup phases; target acceptance remains open.
- [ ] BD-T232.1: Source owner implements exact BootstrapPendingStepFailure and nine fixed boundaries/formatter with actor, account, redaction, subclass and malformed-field failures.
- [ ] VD-T232.2: Review actual coherent committed diagnostic bytes under v228 and next target evidence independently; no source/acceptance promotion.
- [ ] BD-T231.2 (v231): Consume only the issuer-current v231 active authority aggregate, bind its actual canonical core bytes/hash/size and reuse its exact generation at activation. Genuine pipeline/failure evidence VD-T231.3 and target acceptance separately OPEN.


- [ ] VD-T180.6 / VD-T183.5 (v228): Apply exact reviewed8185 outer module/catalog tuples and three fixed delayed module preloads, prove isolated installed origins and retain full coherent checks/target evidence separately.
- [ ] VD-T232.2 (v228): Confirm committed exact pending diagnostic leaves and future observed target stage without inferred cause or acceptance.
- [ ] BD-T235.1: Implement the v235 exact predecessor-bound candidate selection/source/build/sealed exec transition; preserve all existing data/authority and exact pending prerequisites.
- [ ] LC-T235.2: Implement the v235 publisher-owned present pointer CAS, durable rollback/reexecution and exact pending runtime behavior.
- [ ] VD-T235.3 (v235): Verify genuine installed-predecessor candidate pipeline, pointer/controller/input drift, crash/rollback/preservation failures; target acceptance separate.
