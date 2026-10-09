# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Colibri adapter builds reviewed pinned source using c/setup.sh on Linux ARM64 with supported compiler/OpenMP/libgomp; Linux x86_64 binaries are rejected for target. Keep GLM-5.2 model identity/quantization/MTP/license/revision hashes independent of engine revision. The approximately 430 GB upstream package and 16 GB minimum/24 GB recommended are source claims, not measured Pi capacity or speed. Build the complete selection/download/existing-path/server adapter with no model download in this development stage. Before selection calculate final plus download/conversion staging plus OS/user/cache/log/recovery reserve; use content-addressed shards/resumable ranges, verify hashes and do not duplicate model for generic backup. Record when a model digest is unavailable and block activation rather than inventing it.

Bound local service memory/CPU/IO, parallelism one, request deadlines, cancellation and loopback/auth; do not infer swap sufficiency. Define configurable interactive criteria before measurement: default warm first-token <=30 s, generation >=1 token/s, core-chat p95 latency <=10 s while auxiliary work runs, no OOM/throttle failure; record cold/warm prompt/tokens, resident memory, SSD throughput, engine/model revisions, tool-call validity and baseline/control trials. These are initial user-configurable acceptance thresholds, not measured results or upstream guarantees. If unmet, retain experimental/manual route and report exact values. A small model may verify protocol plumbing but never passes GLM-5.2 acceptance.

Coral adapter probes USB or PCIe/M.2 and chooses documented runtime/device permissions accordingly, installs an isolated compatible inference environment and official compiled fully-quantized sample artifact. Do not downgrade host/Hermes Python. Require delegate-used evidence and output comparison from actual TPU inference; a connected device or CPU fallback fails this test. No LLM acceleration claim, camera service or surveillance workload. Absent device leaves target test pending while fixture driver-choice and failures remain implementable.

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

## Reproducible Coral sample refinement

Read plans/amendments/2026-10-09-coral-sample-v1.md and planning/coral-sample-artifact-metadata.json. Use the pinned official compiled MobileNetV2 sample after byte/digest verification, requiring real selected-delegate execution and delegated-operation evidence. Quantized zero input is a synthetic execution fixture, not a classification-accuracy benchmark. The source pin establishes no native runtime/device result and keeps all existing target tests open.
