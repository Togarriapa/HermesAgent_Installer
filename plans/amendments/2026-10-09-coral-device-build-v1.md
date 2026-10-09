# Exact Coral device and fixed source build custody v1

Sol additive refinement of original R0042/R0054/R0115 and existing HI02/HI09/HW01. Add HW02/HW-T02/EV-HW02 and HW03/HW-T03/EV-HW03 with dependency graph bindings. Frozen baseline/tag and all18AC unchanged; no new product scope/device substitution or runtime claim.

## Exact Coral device and fixed compiler enrollment

Follow planning/coral-device-build-contract.json and coral-device-build-v1 amendment. HW02 binds exact selected USB sysfs/bus/interface/current device node or PCI BDF/driver/current apex node plus major/minor/inode/generation in root custody; caller only opaque enrolled identity. Private device namespace exposes only selected TPU and safe ordinary process devices, kernel denies sibling USB/apex/hardware. No allUSB/apex wildcard or broad PrivateDevices=no. Device hotplug/reset/reenumeration invalidates generation and requires root fresh same-physical-identity attestation; reused path/ambiguity is not acceptance. Inference result includes signed launch/device selection identity, transport/generation/runtime/model/worker digests and actual delegate operations/output. Kernel target probes must prove denial and same-device use; source docs do not prove this sandbox.

HW03 uses existing process.start with fixed protected targets coral-cpython-build:start and colibri-source-build:start. Root enrolls exact source/toolchain/builder/recipe digests, fixed sanitized argv/env, readonly source and owned output staging, resource/deadline limits. Worker never supplies shell/compiler flags/script/path/URL. Dedicated unprivileged builder has no network or runtime credentials; root attests native outputs and provenance before service runtime enrollment. Missing toolchain/driver/ABI remains explicit incomplete. Bounded stages may resume with fresh authority, never extend old grant. Native builds only in identified authorized target/CI environment; no compiler/build execution on development Mac. Keep prior component generations and all original model/TPU acceptance requirements.

Primary transport background:
- https://coral.ai/docs/accelerator/get-started/
- https://coral.ai/docs/m2/get-started/

Installer-specific selected-node isolation design requires actual kernel/native evidence; docs/device enumeration/fixture builders cannot prove it.
