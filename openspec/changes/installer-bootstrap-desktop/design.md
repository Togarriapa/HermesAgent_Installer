# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Use a thin POSIX install.sh that verifies an available supported Python and delegates to a typed Python package. The initial bootstrap must not curl-pipe remote install scripts. Build a read-only host probe before any write: /etc/os-release, uname, available RAM, lsblk/findmnt JSON, statvfs, sysfs USB/PCIe, graphical-session variables and user-session reachability, package locks, listening ports, installed services, DNS/TLS and optional Pi thermal/storage health probes. Return facts with provenance, supported/unsupported/unknown reasons and no inferred Pi success.

Represent installation as a previewable step graph with ownership, desired artifacts, credential references, rollback and privilege requirements. Adopt by recording pre-state and asking the configuration to identify existing roots; never take ownership of an unrelated service. Source acquisition uses reviewed Git commits and artifact hashes. Pinned official scripts/install.sh supports --branch, --commit, --dir, --hermes-home, --non-interactive, --skip-browser and --skip-computer-use. Invoke its reviewed verified bytes only on installer-owned staged source/runtime roots; upstream can stash/reset an existing checkout, so never blindly run it against an adopted user tree. Plan/backup/merge adoption separately and track every owned write. Resolve Agent and Desktop independently. At Hermes 7085fbf7753266fc4943c55ac04926186bc90005, official `hermes desktop` builds an Electron GUI against the existing Agent and launches `hermes serve`; old releases may use `dashboard --no-open`. Root workspace dependencies precede apps/desktop build. Linux release packaging is disabled in this observed revision, so the source path is required until compatible official artifacts are actually verified. Current official install docs require the Hermes PM-managed Python 3.14 runtime; pyproject >=3.11,<3.15 only permits older interpreters to run the updater. Installer orchestration uses its own isolated compatible runtime. Use upstream pm/lock.json and verified pinned uv/tools, not arbitrary host Node. Git/curl/tar/SHA256 and minimal-host libatomic1 prerequisites must be explicit; expose sudo-n failures. Never globally replace the host Python/Node. BUILDING.md bundled packaging remains a distinct path.

Generate a systemd user-session launcher for the selected graphical user; Desktop is not a headless root service. Validate X11/Wayland/display access, native window, intended backend identity, imported resources, Hello, cancellation, restart and harmless fixture tool. Preserve Electron sandbox: reject a path that only works with --no-sandbox as compliant; offer a supported resolution or truthful agent/browser/remote-Desktop fallback. Acceptance on a physical graphical Pi is deferred until identified and authorized; x86 headless fixtures prove only orchestration contracts.

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

## Protected artifact catalog refinement

Read plans/amendments/2026-10-09-protected-artifact-catalog-pins-v1.md and planning/protected-artifact-source-catalog.json. Baseline official script/PM lock are verified source bytes; candidates are not automatic activation. Acquire canonical managed artifacts only through protected exact catalog, including bootstrap acquisition. Unknown sourcearchive/package artifacts remain unavailable.

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
