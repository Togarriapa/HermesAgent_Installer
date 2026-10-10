# Root installer release build inputs

This module is the stage-zero producer for the installed-stage publisher. It
does not mutate system services or publish the active deployment pointer.
Candidate selection is root-local and explicit; the builder does not accept a
caller path or caller manifest.

Before choosing first-source bootstrap, root setup calls
`observe_deployment_predecessor()`. It returns a sealed
`VerifiedDeploymentPredecessor`: `absent` follows secure fixed-parent and
no-follow missing-leaf proof, while `present-verified` requires the full
installed release verifier and retains its receipt behind an opaque short-lived
handle. Corrupt, foreign, and unreadable current pointers fail closed. A
present receipt can be resolved only through
`resolve_verified_deployment_release(handle)`; the proof can recheck its fixed
pointer with `verify_current()`.

`RootInstallerDistributionSourceCAS.acquire_selected()` fetches only from the
fixed HTTPS repository origin. It verifies the selected commit, immutable
baseline tag object/commit/tree, complete baseline byte map, reviewed
amendment map, and source artifact catalog. It exports regular Git blobs to a
bounded root-owned CAS, rejects links and special files, writes a canonical
source manifest plus private typed receipt, fsyncs the staging tree, and
atomically renames the completed candidate entry. Retained source receipts
re-open through no-follow descriptors and recheck file hashes, ownership,
modes, device/inode identity, and the complete file set.

`RootInstallerInterpreterRegistry.provision_selected_bootstrap_interpreter()`
acquires only the reviewed CPython 3.14.7 Linux aarch64/glibc archive and the
exact PyYAML 6.0.3 CPython 3.14 wheel pinned by the selected
`requirements-runtime.txt`. It disables ambient proxies and permits only the
reviewed CPython URL's single HTTPS release-asset redirect, checks TLS response
size and payload hashes, rejects unsafe archive members, verifies
wheel tags and every RECORD hash/size, then writes only the selected package
into the dedicated prefix. Its actual interpreter probe checks CPython
version, cache tag, SOABI, machine, ELF architecture, package version and
import origin. Private runtime receipt files allow no-path resolution after
the process image changes.

`RootInstallerInterpreterRegistry.observe_current_bootstrap_interpreter()`
measures the actual running executable and its protected isolated runtime
prefix. It verifies the Python requirement and hash-pinned installer runtime
requirements, then issues registry handles for observed installed package
closures. Provisioning alone is not current-actor proof; the same-PID sealed
FD3 re-exec handoff and actual selected-source module observation remain
required. This development Mac has not exercised Linux ARM64 provisioning or
re-execution.

`RootSourceBootstrapActorVerifier` binds the current root PIDFD/start time,
actual interpreter executable, and loaded installer module origins/bytes to
the retained source and runtime receipts. The first publication path does not
depend on an already active deployment. `RootInstalledReleaseBuilder` then
stages the fixed launcher, isolated interpreter closure, loaded installer
modules, exact templates/catalog, frozen baseline, amendments, and generated
root setup plan. Its opaque one-use build receipt retains a no-follow output
directory descriptor and a canonical `release-manifest.json`; the manifest
excludes itself, while both manifest and role-closure digest cover each
sorted path, hash, size, mode, and role.

`RootInstalledStagePublisher` consumes the sealed receipt and owns final
deployment layout and active-pointer compare-and-swap. This module exposes no
caller path, manifest, artifact-role map, or output bytes as authority. Tests
cover retained receipt custody, file identity changes, single-use build
receipts, unsafe link rejection, path normalization, runtime RECORD failures,
and hash-pinned runtime lock parsing. Fixture tests do not establish Linux
root, ARM64, or Pi acceptance.

Requirement/task trace: `BD-F01`, `LC-F03`, and the `first_source_bootstrap`,
`release_build_input`, and `installed_deployment_receipt` contracts in
`planning/protected-lifecycle-control-contract.json`. Root-launcher handoff,
stage publisher integration, and target acceptance remain separate evidence.
