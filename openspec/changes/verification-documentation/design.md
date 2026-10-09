# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Evidence records immutable candidate Git SHA, platform (x86 fixture/native ARM64/emulation/physical Pi), target identity, component/source/artifact versions, command/exit code, start/end UTC and displayed Europe/Lisbon, assertions/results, resource measures, redacted log/artifact hashes, status/blocker and exact resume command. Report authentication, reachability, functionality, enabled state and actual-target evidence as separate fields; never compute green from config presence. Expected tests are definitions until executed. One failed required dependency prevents full registry compliance while text-core may remain usable.

Implement fixtures: fake apt lock/package errors; interrupted HTTP Range/digest mismatch/DNS/TLS/disk ENOSPC; prepopulated owned/unowned/symlink roots; fake user-session/Desktop backend; registry malformed/catalog root/inheritance/selector/quality and overlay conflicts; broker/AuthenTik hierarchy/revocation/mismatch; provider recorder proving privacy/aggregate-budget/fallback/Retry-After/capability; mock MCP schemas/reconnect/revocation; memory namespace persistence/extraction; lifecycle crash checkpoint/atomic generation/DB restore; workload scheduler pressure. Test assertions compare effects and observed output, not implementation names. Per-item tests must exercise substantive adapter operations, not only registry enumeration.

Target verifier consumes authorized target record and explicit selected account/resource inputs. It rejects accidental development-host privileged install. Tests AC01..AC12 are separately selectable with honest skip/pending when dependencies absent; JSON evidence/report does not count skip as pass. Complete code/fixtures/docs despite unavailable hardware/accounts; target scripts must be executable without inventing results. Golden baseline plus fixture CI, native ARM64 runner/container evidence and physical Pi graphical/TPU/GLM evidence are distinct lanes.

Quickstart/account guides/recovery/update/backup/uninstall and troubleshooting commands must correspond to implemented CLI help. SOURCES and COMPATIBILITY record dated primary links and pinned revisions, unknown licenses/ARM64/feature gaps. Coverage checker maps all original prompt lines, unique components and aliases, each of 12 acceptance criteria to spec/tasks/manifest/evidence or blockers; it catches dropped items and claimed-complete placeholders. CI pins toolchain/action SHAs, strict OpenSpec validation, frozen-plan integrity, coverage, meaningful fixture suite and report artifacts. Review scenarios against actual code before archive; canonical specs represent verified implemented behavior only, not artifact completeness.

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

### v28 installer-owned verifier constructors

VD-F02/VD-F04 use protected-runtime-assembly-contract.json installer_target_result_verifier exact current root target/candidate/admission/result constructors and receipts. All AC01..18 remain pending absent actual dimensions.
