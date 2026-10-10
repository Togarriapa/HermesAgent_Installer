# Tasks

Dependencies: installer-bootstrap-desktop. Full IDs and task edges: planning/dependency-graph.json. Implementation owner: GPT-6 Luna. All boxes are incomplete; artifact completion is not implementation acceptance.

## 1. Foundation with tests and documentation

- [ ] 1.1 `LC-F01` Implement validated config/schema, wizard and full CLI verbs with readable/JSON results and configure-later checkpointing; verify exit codes and resumed prompts; document command reference. Evidence: `tests/contracts/test_cli.py`.
- [ ] 1.2 `LC-F02` Implement owned-path/no-symlink filesystem layer, process lock, journal and idempotent service/config generation; verify prepopulated roots, crash recovery, duplicate prevention and cancellation; document state locations. Evidence: `tests/contracts/test_state.py`.
- [ ] 1.3 `LC-F03` Implement staged updates/health/atomic rollback, consistent versioned DB backups/restore and data-preserving uninstall; verify failed update and real synthetic DB restoration; document recovery. Evidence: `tests/contracts/test_recovery.py`.
- [ ] 1.4 `LC-F04` Implement unprivileged supervision, bounded startup/restart/log rotation and graceful stop; verify occupied ports, missing user session, secret redaction and descendant cleanup; document supervision. Evidence: `tests/contracts/test_supervision.py`.

## 2. Traceable individual obligations with verification

- [ ] 2.1 `LC-R0141` Implement `R0141` in `src/hermes_installer/lifecycle.py`: Provide a simple entry point, such as `./install.sh`, backed by maintainable modular code. A thin shell bootstrap plus typed Python orchestration is a reasonable default; use another stack only if it materially improves reliability. Avoid a single giant shell script. Verify with `tests/contracts/test_lifecycle.py` (EV-R0141): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.2 `LC-R0142` Implement `R0142` in `src/hermes_installer/lifecycle.py`: The wizard must handle fresh install, existing-install adoption, component selection, storage/model paths, account setup, diagnostics, and recovery. Reuse Hermes Desktop settings where practical. A second full management application is not required; a clear terminal wizard and lifecycle CLI are sufficient. Verify with `tests/contracts/test_lifecycle.py` (EV-R0142): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.3 `LC-R0143` Implement `R0143` in `src/hermes_installer/lifecycle.py`: For every required setting, show what it is, why it is needed, the official setup link, concrete steps to obtain it, and a connection test. Collect secrets through secure input and supported credential storage. Allow “configure later” and resume without repeating successful setup. Explain account/billing prerequisites before asking for a key. Verify with `tests/contracts/test_lifecycle.py` (EV-R0143): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.4 `LC-R0144` Implement `R0144` in `src/hermes_installer/lifecycle.py`: Provide interactive and documented non-interactive operation with a validated config file, secret references, useful exit codes, and readable/JSON output. Implement these lifecycle capabilities through clear commands: Verify with `tests/contracts/test_lifecycle.py` (EV-R0144): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.5 `LC-R0145` Implement `R0145` in `src/hermes_installer/lifecycle.py`: Plan/dry-run; install; resume; status; doctor; verify. Verify with `tests/contracts/test_lifecycle.py` (EV-R0145): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.6 `LC-R0146` Implement `R0146` in `src/hermes_installer/lifecycle.py`: Configure/test a provider or MCP; select a memory provider; resolve a source URL. Verify with `tests/contracts/test_lifecycle.py` (EV-R0146): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.7 `LC-R0147` Implement `R0147` in `src/hermes_installer/lifecycle.py`: Enable/disable/start/stop a component; inspect redacted logs. Verify with `tests/contracts/test_lifecycle.py` (EV-R0147): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.8 `LC-R0148` Implement `R0148` in `src/hermes_installer/lifecycle.py`: Check/apply updates; rollback; backup/restore; uninstall. Verify with `tests/contracts/test_lifecycle.py` (EV-R0148): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.9 `LC-R0149` Implement `R0149` in `src/hermes_installer/lifecycle.py`: Preflight must detect OS/distribution/version, ARM64 architecture, available RAM, graphical session, user/sudo context, package-manager locks, network/DNS/TLS, disk capacity, existing installs, services, ports, and device access. Select supported dependency versions; do not globally replace the system Python or Node to satisfy one component. Verify with `tests/contracts/test_lifecycle.py` (EV-R0149): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.10 `LC-R0150` Implement `R0150` in `src/hermes_installer/lifecycle.py`: Use isolated environments for incompatible Python/Node/native dependencies. Prefer native ARM64 packages; use containers only where their compatible images and isolation justify them. Check native extensions, browser binaries, shared libraries, and transitive dependencies. Do not silently use x86 emulation as the Pi solution. Verify with `tests/contracts/test_lifecycle.py` (EV-R0150): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.11 `LC-R0151` Implement `R0151` in `src/hermes_installer/lifecycle.py`: Keep application data, model files, component environments, source snapshots, logs, backups, and private overlays in documented locations. Use a single configuration source of truth and generated service definitions. Avoid writing through symlinks outside managed roots or overwriting existing user settings. Verify with `tests/contracts/test_lifecycle.py` (EV-R0151): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.12 `LC-R0152` Implement `R0152` in `src/hermes_installer/lifecycle.py`: Use appropriate systemd/user-session supervision with startup ordering, restart limits, health probes, timeouts, log rotation, and clean shutdown. Detect already-managed services to prevent duplicate listeners, model processes, jobs, and memory workers. Start with conservative, configurable concurrency—for example, one browser worker and a small cloud-agent pool—and tune from measurements. Verify with `tests/contracts/test_lifecycle.py` (EV-R0152): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.13 `LC-R0153` Implement `R0153` in `src/hermes_installer/lifecycle.py`: Installations must be idempotent and resumable, with process locks and per-step checkpoints. Stage downloads, validate artifacts, and atomically switch compatible generations. Upgrades must preview relevant config/schema/permission changes and preserve user modifications. Take consistent database backups and support version-compatible restoration. Verify with `tests/contracts/test_lifecycle.py` (EV-R0153): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.14 `LC-R0154` Implement `R0154` in `src/hermes_installer/lifecycle.py`: Uninstall removes installer-owned software while retaining user data by default. Verify with `tests/contracts/test_lifecycle.py` (EV-R0154): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.15 `LC-R0155` Implement `R0155` in `src/hermes_installer/lifecycle.py`: Bind management interfaces to loopback by default. Remote access must have authentication and appropriate encrypted transport. Keep services unprivileged where possible, limit filesystem/network/tool scopes, and keep secrets out of source, command lines, screenshots, logs, and diagnostic bundles. Preserve OAuth callback validation and credential ownership. Verify with `tests/contracts/test_lifecycle.py` (EV-R0155): Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior. Update `docs/managed-lifecycle.md` and component/evidence states; preserve explicit blockers.

## Workflow follow-up

- Review code against every requirement/scenario and actual evidence; do not archive incomplete hardware/account tasks.
- Run strict pinned OpenSpec validation and coverage; archive only verified completed changes using the installed documented workflow, preserving dated history and canonical specs.
- Sol must approve refinement via append-only amendment; keep plans/2026-10-09-v1 immutable.

Hermes/resource selection v3: plans/amendments/2026-10-09-hermes-bootstrap-resource-job-selection-v3.md defines fixed stage/health recipes and activegeneration resourcejob/DAG/source/backend joins; BD-F03/LC-F03/LC-F04/HI-T09/RB-T08 tasks and nativeevidence remainopen.

Protected lifecycle control v1: plans/amendments/2026-10-09-protected-lifecycle-control-v1.md defines exactrootprovision/currentintent/firstsnapshot/CASrecovery, finiteprocess.control facade andactualloadedclosureprooflimits. ExistingBD/LC/HI tasksremainopen.

Build service/bootstrap provenance v7: plans/amendments/2026-10-09-build-service-bootstrap-record-provenance-v7.md defines exact dedicated build profile join and root-selected identity versus actual runtime receipt provenance. Existing HI/HW/BD/LC tasks remain open.

Root setup/journal selection v8: plans/amendments/2026-10-09-root-setup-session-journal-catalog-v8.md specifies installed root-local initial session/intent/receipt transport and active root journal catalog. Existing HI/BD/LC/SK tasks and target evidence remain open.

### v14 installed first setup

BD-F01/BD-F03/LC-F03/HI-T01 use root_local_setup_session installed_selection_catalog and first_setup_artifact_fetch in planning/protected-lifecycle-control-contract.json. Root deployment bytes and transaction-scoped CAS receipts are required; original acceptance remains open.

### v15 native health and typed admission

Use planning/protected-lifecycle-control-contract.json native_health_receipt for actual native health and planning/protected-resource-job-contract.json typed_admission/service_methods/recipe_domain for RB-T08. Original tasks/acceptance remain pending.

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

Initial compilation handoff v42: `plans/amendments/2026-10-09-initial-compilation-handoff-v42.md`; exact stage0/post-policy separation, original tasks open.

Root identity credential intake v47: `plans/amendments/2026-10-09-root-identity-credential-intake-v47.md`; exact original setupintake, tasks remain open.

Authentik template/actor API v49: `plans/amendments/2026-10-09-authentik-template-actor-api-v49.md`; exact source template and existing verifier, tasks open.

Release plan/active compiler v53: `plans/amendments/2026-10-09-release-plan-active-compiler-v53.md`; exact source template/buildclaims, existing tasks open.

Live health control/output kinds v55: `plans/amendments/2026-10-09-live-health-control-output-kinds-v55.md`; existing tasks remain open until actual proof.

First source bootstrap actor v62: `plans/amendments/2026-10-10-first-source-bootstrap-actor-v62.md`; existing scope/tasks remain open.


## v181 conditional identity and independent readiness

- [ ] `LC-T181.4` Persist configure-later and resume independent readiness without identity-domain or ownership widening. Exact producer/order and meaningful positive/failure evidence: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. Implementation and target acceptance OPEN.

- [ ] HI-T191.3 Preserve one-use intent, crash/resume reconciliation and actual owned cleanup without copied setup authority. See `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md`; all acceptance OPEN.

- [ ] LC-T235.2: Implement the v235 exact predecessor-bound candidate owned atomic pointer publication/conditional rollback/reexec and runtime update recovery; preserve all existing data/authority and exact pending prerequisites.
- [ ] VD-T235.3 (v235): Verify genuine installed-predecessor candidate pipeline, pointer/controller/input drift, crash/rollback/preservation failures; target acceptance separate.


- [ ] BD-T235.1 / LC-T235.2 / VD-T235.3 (v241): Apply only reviewed root_setup tuple literals after spec publication; run unexcluded narrow candidate checks and genuine full positive/current predecessor/failure/recovery evidence. Source review is separate from completion.


- [ ] BD-T242.1: Implement fixed source-update entry and genuine held predecessor/currentTTY/source-bootstrap bridge without bypassing installed actor verification.
- [ ] VD-T242.2: Review new committed bytes and verify genuine pre-v235 positive/failure/currentness/rollback/immutability on isolated and target environments; keep distribution/runtime acceptance separate.


- [ ] BD-T242.1 / VD-T242.2 (v247): Apply only exact reviewed root_setup two-table tuples and run unexcluded coherent source-update checks plus genuine full old/pre-v235 predecessor and target evidence; source approval remains separate from completion.
