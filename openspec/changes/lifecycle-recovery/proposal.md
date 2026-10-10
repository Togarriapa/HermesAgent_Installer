# Proposal

## Why

The requested Pi setup needs wizard/cli, isolated environments, ownership-safe idempotent checkpoints, supervised services, rollback, backups and uninstall. Existing source definitions and catalogs do not establish installed or target-tested behavior.

## What Changes

- Implement the full constraints and individual obligations assigned to `lifecycle-recovery` in planning/traceability.json.
- Deliver component-specific functional/failure tests and account/hardware pending states rather than clone-only completion.
- Preserve existing data and keep all externally funded/account/device actions within configured scope.

## Capabilities

### New Capabilities

- `managed-lifecycle`: Wizard/CLI, isolated environments, ownership-safe idempotent checkpoints, supervised services, rollback, backups and uninstall.

### Modified Capabilities

None; no runtime capability is currently implemented in this greenfield repository.

## Impact

Planned modules: src/hermes_installer/cli.py, src/hermes_installer/config.py, src/hermes_installer/state.py, src/hermes_installer/lifecycle.py, src/hermes_installer/supervision.py. Depends on installer-bootstrap-desktop. All implementation belongs to GPT-6 Luna; specification/refinement belongs to GPT-6.1 Sol. See design.md and explicit task/evidence DAG.

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


## Conditional Authentik and local-owner setup v181

Restore original R0058/R0060/R0143 conditional capability scope. Contract and sequential producer/evidence details: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. No runtime implementation or acceptance is claimed; all AC01..18 OPEN.


Two-actor health v191: `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md` replaces unsafe setup-session aliasing with independently current daemon commit/source proof, actual fixed source run/events and one-use authenticated setup health intent. Only consumer-completed same-generation journal witness may enable; ACK is insufficient. All acceptance/source pins remain OPEN.

Predecessor-bound candidate update v235: planning/predecessor-bound-candidate-update-v235.json requires current verified old release admission before exact candidate staging, sealed samecontroller input joins, existing publisher present CAS, durable owned rollback and candidate reexec. Distribution and runtime generation acceptance remain separate. LC-T235.2/VD-T235.3 OPEN; all AC OPEN.
