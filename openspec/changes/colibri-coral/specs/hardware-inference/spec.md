# hardware-inference Delta

## Purpose

GLM-5.2 ARM64 experimental installation path and independent official compiled-model TPU inference. This contract preserves the full requested scope and separates functional evidence from pending hardware/account readiness.

## ADDED Requirements

### Requirement: R0041 source line 87
The installer SHALL satisfy this obligation: Coral accelerates compatible, compiled, fully quantized TensorFlow Lite workloads; it does not provide a general accelerator for GLM/Colibri or remote Nemotron inference. Follow Coral's compatibility documentation (https://coral.ai/docs/edgetpu/models-intro/) and the setup guide for the detected device.

#### Scenario: R0041 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Coral accelerates compatible, compiled, fully quantized TensorFlow Lite workloads; it does not provide a general accelerator for GLM/Colibri or remote Nemotron inference. Follow Coral's compatibility documentation (https://coral.ai/docs/edgetpu/models-intro/) and the setup guide for the detected device.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0041 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0041 CPU fallback never proves TPU
- **WHEN** the official compiled sample returns a valid result but its runtime records CPU execution/no EdgeTPU delegate despite device enumeration
- **THEN** TPU functional verification SHALL fail with delegate-not-used evidence; enumeration/CPU output SHALL NOT count as inference on Coral, and missing USB/PCIe hardware SHALL instead report pending-hardware

### Requirement: R0042 source line 89
The installer SHALL satisfy this obligation: Install the appropriate runtime and permissions in an isolated dependency environment. Do not downgrade Hermes or the host Python to satisfy older PyCoral packages. Test actual TPU inference with a small official compiled sample model and record that the TPU delegate was used; device enumeration alone is insufficient. Keep Coral inference separate from LLM model routing.

#### Scenario: R0042 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Install the appropriate runtime and permissions in an isolated dependency environment. Do not downgrade Hermes or the host Python to satisfy older PyCoral packages. Test actual TPU inference with a small official compiled sample model and record that the TPU delegate was used; device enumeration alone is insufficient. Keep Coral inference separate from LLM model routing.
- **AND** evidence SHALL demonstrate the observable outcome using Run the official compiled quantized sample through the selected USB/PCIe TPU delegate in an isolated compatible environment; record delegate-used output and runtime/device/model digests. Reject CPU fallback and enumeration-only success, preserve Hermes/host Python, and keep missing-device native acceptance pending.

#### Scenario: R0042 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0043 source line 89
The installer SHALL satisfy this obligation: Do not install surveillance or camera services merely to give the TPU a workload.

#### Scenario: R0043 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Do not install surveillance or camera services merely to give the TPU a workload.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0043 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0044 source line 91
The installer SHALL satisfy this obligation: Check available memory, CPU architecture/features, thermals/throttling, storage health where supported, and device access. Never infer performance from the presence of a TPU or a nominal 16 GB RAM label.

#### Scenario: R0044 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Check available memory, CPU architecture/features, thermals/throttling, storage health where supported, and device access. Never infer performance from the presence of a TPU or a nominal 16 GB RAM label.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0044 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0112 source line 198
The installer SHALL satisfy this obligation: Use JustVugg/colibri (https://github.com/JustVugg/colibri), its current quickstart (https://github.com/JustVugg/colibri/blob/main/docs/quickstart.md), and verified GLM-5.2 model artifacts.

#### Scenario: R0112 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Use JustVugg/colibri (https://github.com/JustVugg/colibri), its current quickstart (https://github.com/JustVugg/colibri/blob/main/docs/quickstart.md), and verified GLM-5.2 model artifacts.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0112 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0113 source line 200
The installer SHALL satisfy this obligation: Preserve GLM-5.2 as the requested model. At research time the recommended converted package is approximately 429 GB, and upstream lists 16 GB minimum / 24 GB recommended or measured-ready RAM. Its published low-memory laptop result is not a Pi benchmark. Do not assert acceptable performance on this Pi without measurement.

#### Scenario: R0113 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Preserve GLM-5.2 as the requested model. At research time the recommended converted package is approximately 429 GB, and upstream lists 16 GB minimum / 24 GB recommended or measured-ready RAM. Its published low-memory laptop result is not a Pi benchmark. Do not assert acceptable performance on this Pi without measurement.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0113 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0114 source line 202
The installer SHALL satisfy this obligation: Implement the complete experimental local-model path:

#### Scenario: R0114 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Implement the complete experimental local-model path:
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0114 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0115 source line 204
The installer SHALL satisfy this obligation: Build the engine for actual Linux ARM64; do not download an x86-only Linux binary.

#### Scenario: R0115 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Build the engine for actual Linux ARM64; do not download an x86-only Linux binary.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0115 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0115 Wrong engine or model identity refused
- **WHEN** the target reports aarch64 but the engine artifact is ELF x86_64, or the selected artifact identifies GLM-5.3/a smaller model instead of GLM-5.2
- **THEN** staging/activation SHALL fail with the exact architecture/model mismatch, SHALL NOT execute the wrong binary or substitute the model, and requested GLM-5.2 acceptance SHALL remain failed/pending

### Requirement: R0116 source line 205
The installer SHALL satisfy this obligation: Resolve a supported, licensed, revision-pinned model artifact and quantization, including any required MTP data. Never silently substitute GLM-5.3 or a smaller model.

#### Scenario: R0116 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Resolve a supported, licensed, revision-pinned model artifact and quantization, including any required MTP data. Never silently substitute GLM-5.3 or a smaller model.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0116 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0117 source line 206
The installer SHALL satisfy this obligation: Show total download, temporary/conversion, final-storage, and update/rollback space requirements before the user selects the large download. Support an existing model path and resumable integrity-checked downloads.

#### Scenario: R0117 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Show total download, temporary/conversion, final-storage, and update/rollback space requirements before the user selects the large download. Support an existing model path and resumable integrity-checked downloads.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0117 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0117 Insufficient staging plus reserve capacity
- **WHEN** usable available space is430GB while required final GLM files plus temporary/conversion staging and configured OS/user/recovery reserve exceed430GB
- **THEN** plan SHALL show each required quantity and deny the large download before allocation, retain any existing model reference and offer a resumable storage-path next step without deleting user data or duplicating a generic model backup

### Requirement: R0118 source line 207
The installer SHALL satisfy this obligation: Reserve space for the OS, Hermes, user data, caches, logs, and recovery. Avoid duplicating hundreds of gigabytes solely to create a generic backup.

#### Scenario: R0118 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Reserve space for the OS, Hermes, user data, caches, logs, and recovery. Avoid duplicating hundreds of gigabytes solely to create a generic backup.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0118 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0119 source line 208
The installer SHALL satisfy this obligation: Measure memory use, SSD throughput, first-token latency, prompt processing, token generation, and tool-use behavior on this host. Distinguish cold and warm tests.

#### Scenario: R0119 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Measure memory use, SSD throughput, first-token latency, prompt processing, token generation, and tool-use behavior on this host. Distinguish cold and warm tests.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0119 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0120 source line 209
The installer SHALL satisfy this obligation: Give the model a bounded, cancellable service and an authenticated/loopback API adapter appropriate to the current Colibri server.

#### Scenario: R0120 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Give the model a bounded, cancellable service and an authenticated/loopback API adapter appropriate to the current Colibri server.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0120 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0121 source line 210
The installer SHALL satisfy this obligation: Keep Desktop responsive. Restrict concurrent local inference and suspend competing installer-managed heavy workloads where necessary. Do not promise that swap solves insufficient physical RAM.

#### Scenario: R0121 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Keep Desktop responsive. Restrict concurrent local inference and suspend competing installer-managed heavy workloads where necessary. Do not promise that swap solves insufficient physical RAM.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0121 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0122 source line 211
The installer SHALL satisfy this obligation: Enable it as an interactive default only if measured behavior satisfies documented, configurable acceptance thresholds. Otherwise retain an explicitly experimental/manual route with its measured limitations.

#### Scenario: R0122 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Enable it as an interactive default only if measured behavior satisfies documented, configurable acceptance thresholds. Otherwise retain an explicitly experimental/manual route with its measured limitations.
- **AND** evidence SHALL demonstrate the observable outcome using Native architecture/artifact/device-choice fixture plus executable measured physical-target workflow; CPU or small-model substitution rejected, missing target recorded pending

#### Scenario: R0122 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0122 Measured too-slow route stays experimental
- **WHEN** actual full GLM-5.2 target measurements are warm TTFT40s and generation0.5token/s with configured limits30s and1token/s
- **THEN** the report SHALL retain exact cold/warm/model/engine/target metrics and classify the route experimental/manual; it SHALL NOT become the interactive default or mark a small test model as passing GLM acceptance

### Requirement: R0123 source line 213
The installer SHALL satisfy this obligation: Build this support even if the target hardware is unavailable during development. Clearly separate implementing the installation path from having downloaded and tested the model on the actual Pi. An optional smaller model can be offered separately; it must never count as the requested GLM model passing.

#### Scenario: R0123 fulfilled constraint
- **WHEN** the hardware adapter evaluates recorded native ARM64 architecture, storage/model digests and detected USB or PCIe TPU facts before its selected verification workflow
- **THEN** Build this support even if the target hardware is unavailable during development. Clearly separate implementing the installation path from having downloaded and tested the model on the actual Pi. An optional smaller model can be offered separately; it must never count as the requested GLM model passing.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0123 unavailable or failed prerequisite
- **WHEN** engine or model identity mismatches, required storage/device access is unavailable or measured target behavior misses configured thresholds
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: Protected fixed Coral package set (HW01)

Coral dependencies SHALL install only from a protected fixed package-set manifest binding the isolated attested CPython runtime and exact pinned NumPy/TFLite wheels. Caller-selected paths, URLs, resolver inputs or extra packages SHALL deny. Offline bounded installation SHALL preserve source bytes/licenses and prior component generation without changing host or Hermes runtimes.

#### Scenario: Exact offline package set

- **WHEN** Coral installation selects the protected package set for its attested isolated runtime
- **THEN** root installs only both exact fixed wheels offline or rejects incompatible/stale/tampered inputs before effects while preserving host, Hermes and prior component generation

### Requirement: Exact selected Coral device custody (HW02)

Coral inference SHALL bind a root-selected attested USB or PCIe device identity and current generation, expose only its exact device node under kernel isolation and bind delegate evidence to that same selection. Caller device selectors, wildcard permissions, ambiguous replacement and stale hotplug identity SHALL deny.

#### Scenario: Changed or caller-selected protected input

- **WHEN** caller supplies a device/build path or protected generation/source identity changes
- **THEN** root denies before execution or device access and preserves prior owned generation; no native or hardware acceptance is inferred

### Requirement: Fixed bounded source build profiles (HW03)

Required native source builds SHALL use protected fixed build profiles over exact source/toolchain artifacts and reviewed immutable recipes, with isolated unprivileged bounded execution and attested outputs. Caller shell, flags, scripts, paths or URLs SHALL not select build authority; unavailable prerequisites SHALL remain incomplete.

#### Scenario: Changed or caller-selected protected input

- **WHEN** caller supplies a device/build path or protected generation/source identity changes
- **THEN** root denies before execution or device access and preserves prior owned generation; no native or hardware acceptance is inferred

### Requirement: Closed selected recipe identities
The installer SHALL use finite source-bound request/recipe/validator IDs with root-enforced scope and fixed parameter-free model launches; absent actual validator identity SHALL remain unavailable.

#### Scenario: Caller supplies scope or model launch parameters
- **WHEN** caller attempts to replace root scope, URI, device or fixed build/inference parameters
- **THEN** reject before backend/launch bytes and preserve exact incomplete native evidence.
