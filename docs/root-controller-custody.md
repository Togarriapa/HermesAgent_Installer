# Root Resources controller custody

`RootControllerRoleResolver.resolve_for_event(root_event_handle, node_id)` is
the root-only process custody gate used by the source-event registry before it
issues a cron, webhook, channel, or bundle-node context. The registry supplies
an immutable event binding from its retained event handle. The resolver joins
the exact active role row, observer enrollment, selected backend, node
operation, and service-generation digest; it does not accept role, process,
operation, body digest, or deadline claims from a worker.

The role catalog must be built from `service_generations.resource_controller_roles`
and carry the digest of that same active generation. Each row pins one systemd
unit, daemon executable artifact and hash, loaded role-module artifact and hash,
controller release generation, source observers, backend enrollments,
operations, and a bounded lease. Unknown fields, duplicate identifiers,
ambiguous joins, and expired or changed generations fail closed.

`SystemdMainPidInspector` reads the selected unit's live `MainPID` and cgroup,
opens a pidfd, then verifies root UID, process start time, executable path and
digest, and PID, mount, and user namespace identity against the root namespace.
It repeats the process checks after opening the pidfd. The caller receives a
separately owned duplicate; `RootControllerRoleCustody.close()` releases it,
and `revalidate()` checks the same MainPID, generation, role proof, deadline,
and namespace evidence again before use.

The daemon's root artifact loader must pass role module bytes from its active
protected artifact catalog to `RootControllerRoleModuleRegistry.load_verified`.
The registry hashes and loads those exact bytes as a module in the selected
daemon process, then retains an opaque in-memory proof bound to the process
start time, active service-generation digest, module artifact, and controller
release. A matching source-file hash, worker callback, resource job artifact,
or process label cannot create this proof. Revoke the generation's module
proofs when replacing or retiring that service generation.

The nonprivileged contract tests use controlled inspectors to exercise exact
joins, stale generations, missing module proofs, duplicate pidfd ownership,
and cleanup. `test_root_controller_custody_linux.py` runs inside its own
temporary systemd service in the Linux root-custody workflow and checks the
real systemd MainPID, procfs cgroup/executable/namespaces, loaded module
registry, and pidfd. A macOS skip is only a platform limitation; it does not
qualify the Linux systemd path. This implementation and fixture do not establish
Pi installation, real selected-resource events, or complete RB-T08 acceptance.
