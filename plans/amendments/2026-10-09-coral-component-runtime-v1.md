# Sol refinement: isolated Coral compatibility runtime — 2026-10-09 v1

GPT-6.1 Sol refines existing R0042/HW-F03/HW-R0042/EV-R0042; GPT-6 Luna implements. Frozen baseline and unique tag remain intact; all original/RB/RP/HI obligations are preserved. No new task/acceptance or global/Hermes downgrade is introduced.

## Why and selected source

The selected official compiled TPU inference worker uses the direct TensorFlow Lite delegate API. Its reviewed available official Linuxaarch64 CPython3.9 wheel cannot run in Hermes PM Python3.14. Provision a separately component-owned CPython3.9.25 prefix/venv with exact source and TFLite2.14.0 cp39 manylinux2_34 aarch64 wheel in planning/coral-component-runtime-metadata.json. Sol independently verified temporary source/wheel bytes and hashes over TLS; no source build, wheel installation or native inference was performed. PyCoral package is not required by this selected worker and must not be falsely claimed installed/functionally tested.

## Compatibility and containment

Python3.9.25 is the final source-only release and reached EOL2025-10-31 according to its official release page. This is an explicitly legacy compatibility environment, never current supported Python or full production-compliance evidence. Keep it confined to bounded offline inference: no inherited credentials/proxy environment, no network, immutable source/runtime paths and actual host filesystem/process/credential isolation. Preserve official Hermes PM runtime and host Python. Require actual nativeLinuxaarch64, glibc>=2.34 and compatible detected device/runtime. A missing build dependency, unsupported libc/driver or unmet confinement remains an exact unavailable/resume state rather than system-library replacement.

Review and hash-pin all transitive dependencies, including the selected compatible NumPy ABI, before deployment; the two pins here are not a complete install lock. Disable lazy pip resolution/install and reject missing artifacts. Actual sample digest/device/delegated-op/output evidence plus bounded cancellation and denial probes remain required. Python source integrity alone, available wheels, or a successful CPU invocation cannot establish target acceptance.

## Evidence and validation

Primary release/PyPI/Coral references and exact independently observed bytes/hashes are in metadata. Existing HW-F03/HW-R0042 fixtures, docs and executable native workflow cover the implementation; target acceptance remains separately pending. No physical Pi action, new spending, model download or global dependency mutation was performed during this refinement.
