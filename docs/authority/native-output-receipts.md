# Native output receipts

`RootMaterializationReceiptRegistry` publishes the finite outputs of the pinned
root native compiler into a root-owned immutable content-addressed store. It
is separate from `NativeMaterializationReceipt`, which records that the
selected Hermes profile/skills were discovered and staged, and from installed
release receipts. A stored profile or skills file is not an executable
runtime-artifact receipt.

The root setup factory constructs the registry through the private
`_from_root_factory(binding=..., cas_root=..., journal_root=...)` entry point,
using policy-selected root-owned CAS and journal directories plus a sealed
`RootNativeOutputBinding`. Public methods
accept role names and output bytes/member declarations only inside root
composition; no filesystem path crosses an RPC boundary. The binding selects
the package and generation, exact generated artifact identity, setup and
prepared-generation scope, compiler receipt, source receipt handles, and
expiry. Generated outputs require an actual compiler artifact identity/hash.
The Resources source receipt instead has null compiler fields and records the
verified source-mint module's producer identity/hash. The registry checks
those values before and after publication and again before one-use activation
resolution.

The accepted roles and member shapes come from the v51 runtime-artifact
contract: the packaged Resources source archive, compiled closure archive,
entrypoint `manifest.json`, action resolver `resolver/resolver`, boundary
overlay output, and candidate index `catalog/native-candidates.json`. The
candidate index has its own receipt and must also be the same byte sequence
inside the compiled closure. The index is bounded and checked against its
schema-1 identity fields. The entrypoint/index linkage and complete candidate
row schema are validated by the pinned native loader. Every archive is
checked for duplicate or unsafe paths, links and special files, exact
file-member digest/size/mode manifest, and the configured count and expanded
size limits. Native generated JSON is canonical UTF-8 without duplicate keys,
nonstandard constants, BOM, or trailing newline. The compiled closure uses an
uncompressed deterministic PAX tar and fixed metadata/modes. Its archive
artifact hash, complete archive member-tree hash, and entrypoint's selected
`closure_files` tree hash remain separate digest domains. The boundary overlay
is a canonical manifest at `overlay/manifest.json`; every listed source-pinned
member must match bytes under `closure/` in the compiled closure. The Resources
source is checked against the fixed packaged archive SHA/size and the full
739-file/692-declaration registry inventory.

Publication creates a pending journal record, writes a digest-named CAS object
without replacing existing objects, fsyncs it, revalidates the selected
generation, and only then marks the receipt issued. A retry may complete an
identical pending publication. A conflicting role/output in the same
transaction is denied. Resolution checks current binding, CAS owner/mode/
size/hash, role, generation and expiry; it then consumes the receipt once.
Native output receipts are cross-checked at publication and resolution: the
candidate index must match its closure member, entrypoint manifest, resolver,
and overlay manifest must match their closure members, and every overlay row
must match a selected closure file.

## Evidence and limits

The contract tests validate the fixed source archive, full inventory, member
manifest integrity, path rejection, candidate index schema/closure pairing,
and non-root denial. The root-owned CAS end-to-end fixture runs only where the
test process is root and was skipped in the ordinary development environment.
This producer is not evidence that the installed root factory currently
invokes the pinned compiler, that the target installed the artifacts, or that
Hermes can functionally invoke them. Those require the separate root setup,
source/PM receipt, native discovery, and target acceptance integrations.
