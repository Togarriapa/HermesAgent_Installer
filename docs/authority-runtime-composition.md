# Root authority runtime composition

`compose_root_authority_runtime` joins one root `AuthorityService` epoch to the
matching protected enrollment, artifact catalog, credential vault, and
`RootRuntimeBindings` instance. Call it after `build_root_runtime_bindings`
and `AuthorityService` construction, then keep the returned object for the
service lifetime. The process manager and connector are reused from those
bindings; the composition layer never creates duplicate instances.

The returned `RootAuthorityRuntime` exposes the bound build/device catalogs,
remote-session enrollments, artifact-store resolver, live-peer and loaded
native-package custody lookups, the fixed operation/native-package/device
resolvers, and a root-journal resolver that accepts only the active protected
generation digest before delegating to the protected catalog. Its `boot_epoch`
is the service's fresh authority epoch. It parses
resource backend and body-recipe records from the active protected generation
plus per-node scope bindings and validators, then registers a `ResourceJobAuthority`
only for records that join the active backend, source issuer, observer, recipes,
and service effect rules. The job
ledger is created only when such a fully joined job exists and requires the
daemon's fixed private store path.

When the active generation contains typed `MemoryServiceEnrollment` rows, the
factory builds the memory runtime using those rows, the same protected service
catalog, process manager, credential vault, and digest-bound root-journal
resolver. Its per-step effect adapter is attached to the existing
`AuthorityService`; it creates no second process manager, connector, or
caller-selected state path. The factory installs only selected `memory.search`
handlers that have an exact protected effect rule, a resolved authority-state
root, and a fixed compound recipe. Capture remains unavailable without a
root-observed event join. Missing enrollment or a stale journal generation
leaves the memory route unregistered.

The source registry, native result observer, and remote session authority are
read from the live service so daemon code may attach each actual root-built
instance after this factory returns. `prune()` and `close()` delegate to those
instances and stop the remote lease watchdog. Derived source-observer
enrollments are exposed as typed metadata candidates; they cannot issue
receipts until live loaded-closure and peer-bound delivery resolvers are
available. Active source/job rows without
the required root observer and proof joins remain unroutable. The HI12 loopback
fixture exercises bounded HTTP framing and the real AuthorityService grant and
handler path, while replacing only the OS namespace-entry boundary on macOS. It
does not exercise the `build_memory_runtime` root-journal constructor or prove
namespace isolation. Local composition and loopback fixtures do not establish
native invocation, account, tunnel, or Raspberry Pi acceptance.

Build execution reuses the protected build and artifact catalogs, existing
root content-addressed store, and shared managed-process manager. The current
inspector has no enrolled CPython runtime probe, so it offers only the fixed
Colibri build handler. Composition installs that handler only when the active
service generation joins its protected build profile and exact `process.start`
rule. Coral/CPython remains unregistered until a root-managed probe is
available.
