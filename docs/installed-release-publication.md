# Installed root release publication

`RootInstalledReleaseBuilder.build_selected(...)` produces a one-use handle for a
root-retained, source- and interpreter-bound build closure. The installer passes
only that handle to `RootInstalledStagePublisher.publish_installed_stage()`.
The publisher resolves the sealed receipt itself; callers cannot choose a
release directory, deployment-record path, file map, or manifest.

Publication stages the verified closure below
`/usr/lib/hermes-installer/releases/`, writes the fixed
`release-manifest.json`, fsyncs file and directory contents, seals the tree,
and installs the candidate directory without replacing an existing name. An
existing candidate is reusable only when every byte, mode, owner, and listed
path matches the retained build receipt and no extra entries exist. The fixed
`/var/lib/hermes-installer/deployments/current.json` record is the last write.
Its update is serialized by a root-owned lock and checks the sealed
`DeploymentPredecessor` state, digest, inode, and parent identity immediately
before compare-and-swap. The installed-release verifier validates the exact
new tree before the pointer is made current.

This publisher establishes installed release custody and stage-zero inputs.
It does not establish account authentication, native setup completion,
service health, target-platform qualification, or Pi acceptance. The policy
generation publisher separately publishes compiler-produced prepared or
active policy bytes and binds promotion to current root receipts. Initial
policy publication remains `prepared`; a later root-held policy promotion is
recorded as `active-committed` only after its compiler claim, prepared
generation, service generation, and runtime/materialization receipt closure
are joined in the immutable descriptor and root journal. Native-output
reservation code can call
`PolicyPublicationReceiptResolver.verify_current_active_claim(...)` to resolve
the current selection again and require the exact active claim and
materialization receipt tuple.

The filesystem contract tests use owned temporary directories for successful
publication, stale-pointer denial, collision preservation, and injected
pointer-replace failure. They do not emulate root, Linux process identity,
native installation, or production filesystem permissions. The installed
publisher deliberately refuses to run outside the installed Linux root
process; production effects require the isolated Linux root fixture/CI path.
