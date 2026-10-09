# Root-selected native profile and skill materialization

`RootNativeMaterialization` is constructed by the installed root setup factory
from the sealed `RootSelectedInstallationBinding`, the verified vendored
`NativeRegistry`, and the policy-selected private roots. The current policy
mapping selects `service_parent_root/home` as `HERMES_HOME`, the distinct
`service_parent_root/data` root, and the active root-journal child
`native-materialization`. No RPC field or public enrollment receipt carries
these paths.

The operation is identifier-only:

```python
receipt = materializer.stage_selected(
    enrollment_id=selected_enrollment,
    service_generation=prepared_generation,
    resource_profile_id=selected_resource_profile,
)
```

The sealed binding rechecks the prepared enrollment, generation, resource
profile, protected digest, service UID/GID, selected root identities, and
source-receipt handle. The registry compiler resolves only the selected
profile's dependency closure from the exact bundled Resources revision. It
maps the generated identity into `HERMES_HOME/profiles/<id>/` and skills into
that profile's `skills/` directory. Root publishes files by held directory
descriptors with no-follow traversal, service ownership, fsync, and per-file
atomic replacement. Existing unowned or modified bytes are retained as
overlays. A write interrupted between files remains journaled and resumes only
under the same enrollment digest, generation, profile, and bundle digest;
profile identity is written last. Conflicting profile identity or skill bytes
leave the operation without an activation receipt.

Before returning a receipt, the operation asks `discover_and_load_selected` to
use the pinned Hermes source APIs and the factory-selected Hermes Python 3.14
interpreter to discover this profile and load every skill in its selected
closure. It does not invoke a model or contact an account. The receipt contains
only opaque handles, profile/skill IDs, source and closure digests,
per-resource states, and expiry. It is not a `RootRuntimeArtifactReceipt` and
does not prove executable identity, functional health, credentials, or effect
authorization. After the fixed health step, lifecycle may consume this receipt
once with the exact current enrollment, generation, and selected resource
profile. A new generation or protected digest invalidates the pending receipt.

The factory must resolve the Hermes source and Python interpreter from trusted
source/runtime receipts and keep both paths private. No host Python fallback is
permitted. If the official PM-managed Python 3.14 runtime is not available, the
operation fails closed and reports that runtime prerequisite; it does not
substitute the development interpreter.

Development fixtures validate compilation and crosswalk selection using the
full vendored registry, along with path-tamper rejection and the root-only call
boundary. They do not run the privileged installer on macOS or establish Pi,
ARM64, account, health, or target acceptance. Runtime discovery is implemented
but remains unverified on this development host because the official PM Python
3.14 executable is not present here.
