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
