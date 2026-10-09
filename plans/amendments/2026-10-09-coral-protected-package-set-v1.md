# Coral protected package set v1

Sol additive refinement of original R0042 and existing isolated runtime source pin amendments. Add HW01/HW-T01/EV-HW01, prerequisites HI-T01/HI-T09/BD-F01. No new product scope, no alternate model, frozen baseline/tag and all18 target gates unchanged.

## Protected fixed Coral package set (HW01)

Follow planning/coral-protected-package-set.json. Existing package.install single ZIP-wheelhouse contract cannot represent the two separately pinned official source wheels or prove a built CPython runtime. Add a distinct fixed package-set handler; do not relabel the old ZIP target as an available runtime. The protected set ID is coral-cp39-runtime-v1, effect target package-set:coral-cp39-runtime-v1:<protected_set_manifest_sha256>. Root-enrolled existing installer bootstrap capability binds that exact operation/target; no inferred capability spelling. Caller only schema1/setID/enrollment/generation.

Root manifest binds attested immutable component-built CPython3.9.25 runtime, cp39/aarch64/actualglibc>=2.34, exact existing catalog artifact IDs and SHA/size for NumPy1.26.4 and TFLite2.14.0. Exact catalogIDs must be recorded before enrollment; identities/hashes are source metadata, not caller authority. Canonical manifest digest and protected signature bind runtime/build/generation/source wheel/installer/policy. Source pins are already in coral-component-runtime-metadata.json; no new artifact URL or combined upstream wheelhouse claim. Preserve all source bytes, wheel metadata and license notices.

Only reviewed immutable root installer executes offline no-index/no-deps installation for the two fixed local wheel paths in dedicated service-owned staged venv; no shell/caller pip options, resolver, lazy dependencies or network. Actual runtime build/toolchain/libedgetpu qualification remains separate. Bounds<=600seconds operation cap, staged storagequota/pathownership, cancellation/reap, no global/PM3.14 downgrade. Verify imports/ABI and installed RECORD/tree, atomically activate own generation or preserve prior component/host/Hermes on failure. Fixture install/import success cannot satisfy TPU delegate inference or actual hardware AC09.

All package/runtime/native inference evidence remains distinct and open until observed; source pin verification alone is not installation.
