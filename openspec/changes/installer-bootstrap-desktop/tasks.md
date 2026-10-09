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
