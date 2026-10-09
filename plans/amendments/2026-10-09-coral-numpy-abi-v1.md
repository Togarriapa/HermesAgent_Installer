# Sol refinement: Coral NumPy ABI pin — 2026-10-09 v1

Additive completion of the preceding isolated Coral compatibility source selection, preserving frozen baseline/tag and existing R0042/HW-F03/HW-R0042/EV-R0042. GPT-6.1 Sol owns source refinement; GPT-6 Luna implements. No new requirement/task or target acceptance is introduced.

The selected worker uses NumPy alongside direct TFLite runtime. Pin NumPy1.26.4 official PyPI cp39 manylinux2_17 aarch64 wheel, SHA256d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764,14,226,281bytes. Sol independently compared official PyPI metadata and temporary downloaded bytes over verified TLS. Full source URL/ABI/license and task links are retained in planning/coral-component-runtime-metadata.json and source-revisions.json. Retain wheel bundled licenses. This avoids implicit dependency resolution or incompatible NumPy2 ABI.

These three Python artifacts identify the selected inference worker dependencies, not all native libedgetpu drivers or CPython source-build toolchain. Luna must still verify actual target driver/glibc/toolchain, complete installer lock/integrity, bounded offline kernel confinement, delegated TPU execution and preservation before activation. Python3.9 EOL remains explicit. No install/build/TPU inference was performed by Sol; all native target evidence remains separately pending.
