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

## Isolated Coral compatibility runtime

Follow plans/amendments/2026-10-09-coral-component-runtime-v1.md and planning/coral-component-runtime-metadata.json for component-owned CPython3.9.25 and direct TFLite2.14.0 aarch64 delegate worker. Record Python3.9 EOL explicitly; require complete transitive hash lock, nativeglibc>=2.34, no-network kernel confinement and actual delegated inference before activation. This selects no PyCoral dependency and never changes host/Hermes Python.

## Protected artifact catalog refinement

Use planning/colibri-source-artifact-metadata.json for verified official pinned archive and documented line-ending normalization. Source lacks optional c/glm_tiny assets; no fabricated self-test success. Actual ARM64 build/full GLM acceptance remains pending.

## Protected fixed Coral package set (HW01)

Follow planning/coral-protected-package-set.json. Existing package.install single ZIP-wheelhouse contract cannot represent the two separately pinned official source wheels or prove a built CPython runtime. Add a distinct fixed package-set handler; do not relabel the old ZIP target as an available runtime. The protected set ID is coral-cp39-runtime-v1, effect target package-set:coral-cp39-runtime-v1:<protected_set_manifest_sha256>. Root-enrolled existing installer bootstrap capability binds that exact operation/target; no inferred capability spelling. Caller only schema1/setID/enrollment/generation.

Root manifest binds attested immutable component-built CPython3.9.25 runtime, cp39/aarch64/actualglibc>=2.34, exact existing catalog artifact IDs and SHA/size for NumPy1.26.4 and TFLite2.14.0. Exact catalogIDs must be recorded before enrollment; identities/hashes are source metadata, not caller authority. Canonical manifest digest and protected signature bind runtime/build/generation/source wheel/installer/policy. Source pins are already in coral-component-runtime-metadata.json; no new artifact URL or combined upstream wheelhouse claim. Preserve all source bytes, wheel metadata and license notices.

Only reviewed immutable root installer executes offline no-index/no-deps installation for the two fixed local wheel paths in dedicated service-owned staged venv; no shell/caller pip options, resolver, lazy dependencies or network. Actual runtime build/toolchain/libedgetpu qualification remains separate. Bounds<=600seconds operation cap, staged storagequota/pathownership, cancellation/reap, no global/PM3.14 downgrade. Verify imports/ABI and installed RECORD/tree, atomically activate own generation or preserve prior component/host/Hermes on failure. Fixture install/import success cannot satisfy TPU delegate inference or actual hardware AC09.

## Exact Coral device and fixed compiler enrollment

Follow planning/coral-device-build-contract.json and coral-device-build-v1 amendment. HW02 binds exact selected USB sysfs/bus/interface/current device node or PCI BDF/driver/current apex node plus major/minor/inode/generation in root custody; caller only opaque enrolled identity. Private device namespace exposes only selected TPU and safe ordinary process devices, kernel denies sibling USB/apex/hardware. No allUSB/apex wildcard or broad PrivateDevices=no. Device hotplug/reset/reenumeration invalidates generation and requires root fresh same-physical-identity attestation; reused path/ambiguity is not acceptance. Inference result includes signed launch/device selection identity, transport/generation/runtime/model/worker digests and actual delegate operations/output. Kernel target probes must prove denial and same-device use; source docs do not prove this sandbox.

HW03 uses existing process.start with fixed protected targets coral-cpython-build:start and colibri-source-build:start. Root enrolls exact source/toolchain/builder/recipe digests, fixed sanitized argv/env, readonly source and owned output staging, resource/deadline limits. Worker never supplies shell/compiler flags/script/path/URL. Dedicated unprivileged builder has no network or runtime credentials; root attests native outputs and provenance before service runtime enrollment. Missing toolchain/driver/ABI remains explicit incomplete. Bounded stages may resume with fresh authority, never extend old grant. Native builds only in identified authorized target/CI environment; no compiler/build execution on development Mac. Keep prior component generations and all original model/TPU acceptance requirements.
