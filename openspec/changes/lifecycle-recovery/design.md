# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Choose typed Python orchestration with stdlib argparse or a pinned small CLI library only when justified. A schema-validated single config controls selected components, managed roots, secret references, schedules/timezone, policies/resources and source overrides. Immutable install intent plus durable step records carry ownership, artifact hashes, pre-state, state transitions, errors, rollback and exact resume command. Default data under configurable SSD managed root, user config/state under XDG locations; state DB SQLite with transactional backup API. Filesystem operations lstat/open-no-follow/validate all ancestors and atomic replace; deny symlink escapes.

CLI contract: ./install.sh [--config PATH] [--non-interactive] [--dry-run]; hermes-installer plan/install/resume/status/doctor/verify; provider configure/test; mcp configure/test; memory select; source resolve; component enable/disable/start/stop/logs; update check/apply; rollback; backup/restore; uninstall. Until implemented these are planned commands. Exit codes proposed: 0 requested operation complete, 2 invalid config/usage, 3 actionable pending dependency/account/hardware, 4 unsupported platform, 5 failed step, 6 policy/authorization denied, 7 busy/lock, 130 cancelled; JSON includes phase/error/retryable/blocker/resume fields. Wizard presents setting purpose, official URL, steps, prerequisite/billing, secure input, test and configure-later; resumes only unfinished tasks.

Process lock and journal protect idempotence. Package-manager lock/network/DNS/TLS/disk errors preserve checkpoints. Download to staged temp with digest; switching compatible version pointer uses atomic rename after health probes. Existing settings diff/merge preserve edits; updates preview schema/config/permissions, expanded rights quarantine. Consistent DB snapshots have schema version/artifact catalog and restore validation in temporary destination before activation; model files referenced rather than duplicated. Uninstall uses ownership ledger and leaves data by default; explicit data deletion needs separate scope.

Generate bounded unprivileged systemd user/system services with dependency/start ordering, timeouts/restart limits, health checks, logging/redaction/rotation and clean SIGTERM descendant shutdown. Detect already-managed services/listeners/jobs/memory workers first. Graphical startup belongs to user graphical session. Local APIs bind loopback; remote configured access requires auth/TLS. Default browser workers 1/local inference 1/cloud agent pool 2 subject to aggregate provider quotas; suspend competing managed heavy jobs and measure responsiveness. Isolated component environments pin ARM64 native dependencies; containers only verified architecture/isolation, never silent emulation or global Python/Node replacement.

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

Use the separate root-observed Linux-owner identity/principal/snapshot domain, finite selected owner-overlay ceiling, digest-covered native policy and genuine loaded worker joins; preserve Authentik TLS/credential/fresh System/recipient/broker checks. Contract and sequential producer/evidence details: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. No runtime implementation or acceptance is claimed; all AC01..18 OPEN.


Two-actor health v191: `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md` replaces unsafe setup-session aliasing with independently current daemon commit/source proof, actual fixed source run/events and one-use authenticated setup health intent. Only consumer-completed same-generation journal witness may enable; ACK is insufficient. All acceptance/source pins remain OPEN.

Predecessor-bound candidate update v235: planning/predecessor-bound-candidate-update-v235.json requires current verified old release admission before exact candidate staging, sealed samecontroller input joins, existing publisher present CAS, durable owned rollback and candidate reexec. Distribution and runtime generation acceptance remain separate. LC-T235.2/VD-T235.3 OPEN; all AC OPEN.


v241 narrow candidate update source review: `plans/amendments/2026-10-10-candidate-update-source-review-v241.md` and `planning/candidate-update-source-review-v241.json`. Exact committed ae399 source fixes cold recovery, complete postCAS rollback and issued FD3 cleanup. Only existing root_setup tuple updates in both tables are approved; builder/publisher remain source-held metadata, no recipe/catalog changes. Genuine full positive/unexcluded/Pi evidence and BD-T235.1/LC-T235.2/VD-T235.3/all AC OPEN.


v242 pre-v235 bridge: `plans/amendments/2026-10-10-preinstalled-source-update-entry-v242.md` / `planning/preinstalled-source-update-entry-v242.json` adds finite source-update entry using genuine present predecessor/current UPDATE TTY/fixed-origin CAS/FD3 and isolated source actor before new installed actor. Ordinary installed verifier is preserved; no oldrelease/pointer deletion, caller path/flag authority or restored seals. BD-T242.1 → VD-T242.2 and all AC OPEN.

## Immutable historical predecessor refinement v249

Preserve BD-F03/LC-F03/AC01..02 and v235/v242. Use exact source-reviewed historical whole cohort and dedicated predecessor-only receipt in `planning/version-aware-predecessor-verification-v249.json`; old installed code never becomes current actor. Full closed release/pointer custody and original deadlines remain; no target acceptance.
