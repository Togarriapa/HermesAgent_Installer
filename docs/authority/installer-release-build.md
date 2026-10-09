# Root installer release build inputs

This module is the stage-zero producer for the installed-stage publisher. It
does not choose a candidate, install packages, mutate system services, or
publish the active deployment pointer. Candidate selection and the isolated
runtime handoff remain root-launcher responsibilities; the source builder
accepts only an exact commit SHA from that root-local path.

`RootInstallerDistributionSourceCAS.acquire_selected()` fetches only from the
fixed HTTPS repository origin. It verifies the selected commit, the immutable
baseline tag object/commit/tree, the complete baseline byte map, the reviewed
amendment map, and the source artifact catalog. It exports regular Git blobs
to a bounded root-owned CAS, rejects links and special files, writes a
canonical source manifest plus a private typed receipt, fsyncs the staging
tree, and atomically renames the completed candidate entry. Retained source
receipts re-open through no-follow descriptors and recheck file hashes,
ownership, modes, device/inode identity, and the complete file set.

`RootInstallerInterpreterRegistry.observe_current_bootstrap_interpreter()`
measures the actual running executable and its protected isolated runtime
prefix. It verifies the Python requirement and hash-pinned installer runtime
requirements, then issues registry handles for observed installed package
closures. It does not accept a caller path or caller-supplied executable hash.
The root launcher must provision and execute the approved dedicated installer
runtime before asking this registry for a receipt.

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
receipts, unsafe link rejection, path normalization, and hash-pinned runtime
lock parsing. These fixture tests do not establish Linux root, ARM64, or Pi
acceptance.

Requirement/task trace: `BD-F01`, `LC-F03`, and the `first_source_bootstrap`,
`release_build_input`, and `installed_deployment_receipt` contracts in
`planning/protected-lifecycle-control-contract.json`. Their wider root
launcher, runtime provisioning, publisher, and target-acceptance evidence
remain separate implementation work.
