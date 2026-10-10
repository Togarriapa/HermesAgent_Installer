## Purpose

Protect host authority and private runtime data through enforced principal custody and mandatory mediated native dispatch.

## ADDED Requirements

### Requirement: Trusted host custody (HI01)

The installer SHALL keep privileged authority, credentials and executable service configuration outside every model, Desktop and specialist writable namespace, with distinct restricted host identities and authenticated narrowly scoped IPC.

#### Scenario: HI01 denied effect and preservation

- **WHEN** an untrusted worker replaces a module, service file, credential path or IPC principal
- **THEN** the host rejects activation/request before privileged effects and preserves unrelated files

### Requirement: Kernel enforced worker isolation (HI02)

Native workers SHALL enforce filesystem, process, network and credential separation at the host boundary. Profile state separation or a user service alone SHALL not establish isolation; unavailable confinement SHALL leave affected capabilities disabled.

#### Scenario: HI02 denied effect and preservation

- **WHEN** a real worker reads private sibling files, traverses symlinks, signals another worker, reaches a forbidden destination or reads host credentials
- **THEN** kernel controls deny each operation and the observation identifies actual UID, namespace and target; a mock denial is recorded separately

### Requirement: Authoritative identity and recipient gating (HI03)

Every homelab write and alarm delivery SHALL use a freshly authenticated principal and complete authoritative Authentik System membership hierarchy or recipient lookup, intersected with fixed enrolled target and action scope. Missing, ambiguous, stale or unavailable authority SHALL deny before effects.

#### Scenario: HI03 denied effect and preservation

- **WHEN** direct membership is removed, indirect membership cycles or cannot be completed, identity mismatches or recipient authority changes
- **THEN** no host write or outbound alarm occurs; exact denial and secure resume fields are recorded without cached-claim fallback

### Requirement: Mandatory native dispatch mediation (HI04)

Every enabled native tool, subprocess, MCP, schedule, webhook, delegated callback and memory/provider request SHALL pass enforced capability, sensitivity, recipient and zero-default-budget policy before effects. Bypassing an installed entrypoint SHALL deny or leave that capability unavailable.

#### Scenario: HI04 denied effect and preservation

- **WHEN** private tool or memory context attempts a public-only route on initial, retry, fallback or background execution
- **THEN** no request or secret reaches the ineligible route and a directly invoked native bypass cannot evade the host boundary

### Requirement: Ownership safe custody lifecycle (HI05)

Custody generation activation, restart, rotation, rollback, backup and uninstall SHALL preserve user data and unowned services, invalidate old grants and retain only secure credential references. Partial failure SHALL leave the prior valid generation or explicit disabled recoverable state.

#### Scenario: HI05 denied effect and preservation

- **WHEN** activation fails after custody staging or an old IPC grant is replayed after rollback/rotation
- **THEN** prior owned generation is recovered safely or remains disabled; stale grant is rejected, unrelated bytes and credentials are preserved

### Requirement: Separate native acceptance evidence (HI06)

Verification SHALL record fixture, Linux kernel, native ARM64 and actual target/account evidence separately for host isolation, mandatory dispatch and Authentik authority. No generated unit text, class name, source inventory or transient user service SHALL pass missing native/account acceptance.

#### Scenario: HI06 denied effect and preservation

- **WHEN** contract fixtures pass while real native worker denial or authoritative account probes are missing
- **THEN** implementation evidence remains distinct; target tasks stay open with exact next step and no full-compliance label


### Requirement: Protected fixed local service transport (HI07)

The host SHALL connect native local TCP services only through authenticated typed, principal/generation-bound fixed-target connectors into dedicated private namespaces. General workers SHALL retain network denial; caller-selected destinations and external or sibling access SHALL deny before bytes. Connector grants, streams and lifecycle SHALL remain bounded and revocable.

#### Scenario: HI07 target and lease denial

- **WHEN** a worker supplies another target/namespace, arbitrary address/path, stale grant or expired stream lease
- **THEN** no unauthorized bytes or connection occur; isolated local-service transport is cancelled at its original deadline and unrelated services remain untouched

#### Scenario: HI07 admitted native local transport

- **WHEN** the enrolled native service and authenticated principal have a current payload-bound grant for the selected generation
- **THEN** the host SHALL relay only approved protocol routes inside that service private namespace with bounded byte/worker/deadline limits; Access authorization SHALL precede all remote native pixels, HTTP bytes and input, and expiry/revocation SHALL close both relay directions

### Requirement: Trusted native request and source lineage (HI08)

Every native request and derived event SHALL use host-issued context receipts bound to authenticated source bytes, enrolled process/profile/generation and complete parent lineage. Sensitivity SHALL inherit all contributors; unknown or caller-labeled provenance SHALL not authorize public dispatch. Native primary, auxiliary, tool, memory, background and delegated paths SHALL be wired to this boundary.

#### Scenario: HI08 complete native identity and denied substitution

- **WHEN** a native auxiliary/title/retry request drops a private parent or presents a process-start context as request authority
- **THEN** no ineligible provider/tool effect occurs; the broker validates final payload and complete fresh source closure or reports exact incomplete wiring

### Requirement: Protected enrollment and distinct owned roots (HI09)

Host enrollment SHALL resolve opaque profile/generation IDs into immutable executable/runtime/socket policies and distinct restricted service home/work/data roots. Caller operation/journal roots SHALL remain separate. Workers SHALL not choose physical roots, scripts, sockets, PIDs or namespace destinations; contexts and service connectors SHALL bind attested enrolled identity.

#### Scenario: HI09 complete native identity and denied substitution

- **WHEN** a caller confuses its journal root with a service home or supplies a physical cwd/socket/PID override
- **THEN** host rejects before effects; valid enrollment uses distinct owner-scoped roots, correct process identity and preserved unrelated files

### Requirement: Registered native process attestation (HI10)

Native process inspection SHALL resolve only opaque registered process/generation handles and attest current cgroup descendants with stable kernel identity, pinned executable and renderer lineage/sandbox evidence. Caller PID/path/argv claims SHALL not authorize inspection or exposure; incomplete or stale attestation SHALL deny affected remote readiness.

#### Scenario: Changed renderer identity

- **WHEN** native renderer relaunch changes process identity or caller supplies a sibling PID
- **THEN** host denies or reports incomplete before remote exposure; only current registered descendants are attested

### Requirement: One-use native producer gateway bridge (HI11)

Cross-process native source handoff SHALL use root-issued one-use bridge state bound to both attested producer and selected gateway identities/generations, complete source closure, exact final normalized payload, operation/retry and bounded lease. Gateway dispatch SHALL authenticate its peer and atomically consume admission before effects; opaque references or caller headers SHALL not grant portable authority.

#### Scenario: Cross-process stale or replayed reference

- **WHEN** separate gateway resolves a native source reference with different PID/generation/payload or replays an attempt
- **THEN** root denies before bytes; valid paired identities use exact final digest/full source closure and consume each attempt once

#### Scenario: Incomplete request envelope or retry reuse

- **WHEN** producer captures messages without full SDK fields or reuses a prior bridge on retry
- **THEN** root rejects final effect mismatch/replay before bytes; a new complete request capture and fresh one-use bridge preserves full bounded parent ancestry

### Requirement: Operation-bound fixed effect rules (HI12)

Protected effect rules SHALL key exact capability, operation and enrolled target together; grants SHALL bind the same tuple and canonical payload. Shared targets SHALL not imply cross-operation permission. Connector frame operations SHALL each use fresh one-use bounded grants without extending original stream lease; trusted expiry/revocation cleanup SHALL remain independent.

#### Scenario: Same target different operation

- **WHEN** same service target has open/read/write/close rules or caller changes operation under a prior target grant
- **THEN** root evaluates only exact enrolled operation tuple and consumes bounded frame grant; wrong operation/replay denies and expiry cleanup still closes the stream

### Requirement: Protected native enrollment proof (HI10/HI11 refinement)

Desktop renderer and native bridge enrollment SHALL use actual protected installed artifact digests and unambiguous root-owned identity/policy mappings. Inspector attestation SHALL derive fresh role-specific process/sandbox/relaunch/window evidence; missing pins, caller booleans or main-process-only proof SHALL leave native exposure incomplete.

#### Scenario: Missing renderer or bridge canonicalizer pin

- **WHEN** protected enrollment lacks actual renderer/monitor/patch/canonicalizer digest or identity join is ambiguous
- **THEN** root denies affected native exposure/dispatch with exact incomplete evidence and never substitutes caller-provided claims

### Requirement: Protected native composition
The installer SHALL bind actual native producer package/adapter closure through immutable root-selected profile generation and observed issuer channels, and SHALL apply the same protected route normalization policy before final request digest and gateway effect. Caller registration/labels SHALL not establish provenance.

#### Scenario: Mutable package or divergent normalization
- **WHEN** native closure, peer generation, issuer provenance or route-normalized final payload differs from protected enrollment
- **THEN** deny before effect bytes and retain exact incomplete implementation/native evidence state.

### Requirement: Protected resolver reader
The installer SHALL expose only peer-bound selected immutable resolver records via path-free native.resolver.read and SHALL re-resolve current protected effect enrollment on every dispatch.

#### Scenario: Caller reuses stale resolver as permission
- **WHEN** profile generation, handler, scope or policy changed after reading resolver
- **THEN** deny affected effect before bytes; presentation records confer no authority.

### Requirement: Fixed operation and voice session selection
The installer SHALL resolve only protected fixed operation recipes and current root-authorized device/session handles; caller inputs SHALL not select physical executable, path, environment or device. Raw captured voice SHALL be bounded ephemeral memory only.

#### Scenario: Forged recipe or expired voice session
- **WHEN** selected operation parameters escape its schema or voice session is stale, sibling-owned or lacks trusted permission
- **THEN** reject before execution/capture and cancel owned expired resources.

### Requirement: Native protected configuration identities
The installer SHALL validate strict root-owned package/issuer catalogs and distinct canonical normalization-policy and installed module hashes with actual current enrollment joins.

#### Scenario: Partial hash or unobserved configured issuer
- **WHEN** policy/module digest is missing or source observer only exists as configuration text
- **THEN** keep affected native effect unavailable and require actual identity/observer evidence.

### Requirement: Fixed recipe parameter grammar
The installer SHALL validate only bounded root-selected scalar parameter schemas and exact literal/parameter argv tokens, one element each, with no interpolation or caller physical resource selection.

#### Scenario: Caller injects path or extra parameter
- **WHEN** parameter is untyped, unbounded, extra or outside exact scalar grammar
- **THEN** reject before launch without shell expansion or alternate recipe fallback.

### Requirement: Selected package and compound memory admission
The installer SHALL resolve native package from actual enrolled peer and SHALL authorize each fixed compound memory step separately under same bounded root-owned admission and source lineage.

#### Scenario: Caller chooses package or reuses compound grant
- **WHEN** caller claims alternate package/scope or repeats one consumed authorization across steps
- **THEN** reject before bytes and retain owned cleanup journal with no sibling deletion.

### Requirement: Canonical native record digests
The installer SHALL validate exact canonical resolver/policy document digest preimages, reject duplicate keys and keep module/archive hashes distinct.

#### Scenario: Self hash or wrapper bytes substituted
- **WHEN** digest uses wrong preimage or archive/module identity in place of canonical document
- **THEN** reject enrollment before effects; verified presentation does not confer authority.

### Requirement: Fixed memory compound wire
The installer SHALL enforce canonical typed memory compound write envelopes with root-derived HTTP frames and atomic root current-step state, separate from stream protocols.

#### Scenario: Forged HTTP frame or skipped compound step
- **WHEN** caller submits arbitrary HTTP bytes, wrong job/step or reused frame grant
- **THEN** reject before backend bytes with owned failure/cleanup journal and no sibling scope mutation.

### Requirement: Root-observed remote session bridge
The installer SHALL verify actual Access JWT and fresh root selected policy at root authority, join verified identity to current native profile and bind every asset/input/stream operation to fixed connector session lease/generation. Gateway local or selfsigned claims SHALL not authorize root effects.

#### Scenario: Forged gateway claims or expired active stream
- **WHEN** root JWT/policy/principal verification fails or active lease revokes/expires
- **THEN** deny before bytes or close both stream directions within tested bounded lease and preserve setup/read/tunnel credential separation.

### Requirement: Closed selected recipe identities
The installer SHALL use finite source-bound request/recipe/validator IDs with root-enforced scope and fixed parameter-free model launches; absent actual validator identity SHALL remain unavailable.

#### Scenario: Caller supplies scope or model launch parameters
- **WHEN** caller attempts to replace root scope, URI, device or fixed build/inference parameters
- **THEN** reject before backend/launch bytes and preserve exact incomplete native evidence.

### Requirement: Independent device profile epoch join
The installer SHALL compare selected device identity generation to protected expected_device_generation independently from process profile generation.

#### Scenario: Device epoch changes under live profile
- **WHEN** hotplug or replacement changes selected device identity epoch
- **THEN** invalidate inference enrollment/active grant and require root reattestation without sibling/all-device fallback.

### Requirement: Root private observed source capture
The installer SHALL issue qualified source receipts only through root-private actual registered observer/event joins and exact bounded observed bytes, with peer, generation, parent closure, recipient and lease bindings. Worker submitted capture SHALL remain UNKNOWN/private.

#### Scenario: Worker claims tool result or authentic user input
- **WHEN** actual registered root observer/event/invocation evidence is absent, stale or replayed
- **THEN** deny qualified receipt before effect and preserve private unknown provenance without omitted original functionality.

### Requirement: Typed remote root session wire
The installer SHALL expose distinct one-shot asset and leased WebSocket admissions through peer-bound opaque root handles and finite typed connector operations that check current session state and fresh exact grants internally.

#### Scenario: Asset handle reused for WebSocket or caller chooses connector
- **WHEN** caller reuses consumed asset admission, selects target/path or sends frame after root lease expiry
- **THEN** reject before bytes and close owned relay without localcontext or raw FD bypass.

### Requirement: Protected runtime assembly identities
The installer SHALL load strict root-owned active generation catalogs, verify immutable native closure/device kernel isolation, attest actual successful build output dynamically and sign the exact full connector effect payload digest.

#### Scenario: Preclaimed build hash or partial effect digest
- **WHEN** output was not actually attested after terminal success, closure/import/device identity differs or grant signs only partial payload
- **THEN** deny activation/effect without permissive fallback and preserve truthful failure/native evidence.

### Requirement: Active source and package build consistency
The installer SHALL bind source issuer records into active generation digest, use selection-only build RPC and activate package runtime actual hashes only from verified successful postbuild receipts.

#### Scenario: Mutable sidecar or predicted runtime hash
- **WHEN** source issuer differs from active snapshot or package manifest claims a prebuilt unknown executable digest
- **THEN** reject activation and retain prior owned generation with exact pending build/source reason.

### Requirement: Selected Hermes and resource runtime recipes
The installer SHALL resolve fixed parameter-free Hermes stage/health recipes and active protected resource job DAG/source/backend joins, retaining official PM runtime and actual functional health evidence.

#### Scenario: Caller supplies bootstrap paths or source-only health
- **WHEN** caller overrides recipe/roots/argv or only inventory/status exists without actual selected native workflow
- **THEN** reject overrides or keep functional readiness incomplete, preserve prior generation and exact resume reason.

### Requirement: Root remote controller and native principal binding
The installer SHALL bind verified remote native principal and actual gateway kernel controller separately through a dedicated root-internal one-use connector issuer, active protected policy/OTP enrollment and actual origin/token/closure receipts. Normal worker contexts SHALL not be relabelled and gateway SHALL receive no policy/setup credential resolver.

#### Scenario: Gateway context relabel or metadata-only origin activation
- **WHEN** caller claims native principal from gateway context or activation lacks actual current root readiness/token/mount proof
- **THEN** deny before bytes/activation, preserve configured checkpoint and exact native/account resume requirements.

### Requirement: Distinct native manifest digest domains
The installer SHALL verify native manifest.json against explicit entrypoint_sha256 and original resource manifest against its separate source identity, with fixed closure paths and no assumed digest equality.

#### Scenario: Source manifest digest substitutes native entrypoint pin
- **WHEN** loader receives wrong digestdomain or callerselected module path
- **THEN** deny loader activation before imports and retain exact incomplete closure evidence.

### Requirement: Protected lifecycle provision and control
The installer SHALL derive enrollment provision and finite process control effects from actual trusted root transaction/peer/owned livehandle state, preserve first-snapshot trust provenance and atomic recoverable generation changes, and SHALL not accept worker bearer targets or ready assertions.

#### Scenario: Forged bootstrap intent or stale process control
- **WHEN** caller supplies unregistered bootstrap intent, claimed roots/identity or stale/sibling control handle
- **THEN** reject before effects, preserve prior generation/private state and require actual root target/ownership evidence.

### Requirement: Selected backend and actual gateway role bindings
The installer SHALL resolve protected resource backend/body recipe/action/source/consent scope before each child effect and SHALL verify actual launched gateway role against explicit HI13 protected profile-role association.

#### Scenario: Legacy backend metadata or unobserved gateway role
- **WHEN** only declared backend/role metadata exists without current root selected effect/actual launch proof
- **THEN** deny backend/admission before bytes and retain exact incomplete implementation/native evidence.

### Requirement: Protected authority state and selected build mount separation
The installer SHALL separate UID0 authority journal state from service-writable data, and resolve build paths only from finite protected artifact mount recipes.

#### Scenario: Wrong state owner or caller build path
- **WHEN** authority state aliases writable service data or a build request supplies an unselected path or mount token
- **THEN** the root rejects the operation before effects; no fixture or source status proves native completion

### Requirement: Exact protected execution joins
The installer SHALL resolve each effect from its exact selected active node, scope, observer and setup role joins, with fresh bounded authority and immutable result ancestry.

#### Scenario: Mismatched backend or setup identity
- **WHEN** a node selects a different backend, an event/result lacks root-observed closure, or runtime tunnel identity requests setup writer/probe authority
- **THEN** root rejects before effects and preserves pending original acceptance; no caller booleans or consumed grants substitute for proof

### Requirement: Root-observed native invocation ancestry
The installer SHALL bind native tool and memory invocation ancestry to actual root-observed response/event handles and selected loaded actions, with fresh per-effect authority.

#### Scenario: Worker invents current invocation
- **WHEN** a worker supplies a forged response/call handle or changes observed action arguments
- **THEN** root rejects before effects and does not mint source or user provenance from caller assertions

### Requirement: Selected native profile task recipe
The installer SHALL resolve resource profile tasks through selected protected process recipes and native package bindings, and pass root-constructed task data through bounded stdin only.

#### Scenario: Manifest attempts process selection
- **WHEN** a resource manifest or worker supplies executable, profile path, argv or reusable parent grant as execution authority
- **THEN** root rejects and resolves only its selected per-node process binding with a fresh exact child grant

### Requirement: Complete pinned source archive identity
The installer SHALL verify the complete selected Hermes source archive against exact byte, tree, mode and narrowly enumerated export-normalization evidence before source staging.

#### Scenario: Export identity mismatch
- **WHEN** an archive has an unknown transformed file, missing member, escaped path or mismatched source/archive identity
- **THEN** root rejects staging and never substitutes partial source or source-only completion evidence

### Requirement: Actual selected service and runtime provenance
The installer SHALL bind build service identity to a protected current service enrollment and derive bootstrap executable pins only from actual completed runtime receipts.

#### Scenario: Source hash used as runtime identity
- **WHEN** a prepared profile substitutes a source archive hash or unjoined output UID for executable/service proof
- **THEN** root rejects execution publication and retains the original incomplete checkpoint

### Requirement: Root-local setup and journal provenance
The installer SHALL authenticate initial provision through its installed root-local setup session and transaction-scoped artifact receipts, and resolve authority state from protected root journal selection.

#### Scenario: Worker fabricates bootstrap actor
- **WHEN** a worker supplies root labels, another transaction receipt or a writable journal mapping
- **THEN** root rejects before provision/state effects without requiring or inventing a first active worker context

### Requirement: Observed native metadata and bounded composite effects
The installer SHALL resolve source observers from explicit selected adapter joins and deliver provider metadata only through peer/request/response-bound root lookup; composite effects SHALL preserve exact outer matching and fresh root child authority.

#### Scenario: Composite tool requests an unselected child
- **WHEN** worker code invokes a different action/digest or claims response metadata without exact root lookup
- **THEN** root denies before effects and executes only its reviewed finite selected workflow under fresh per-step grants

### Requirement: Exact selected finite voice recipes
The installer SHALL verify the actual immutable selected voice workflow recipe and registered primitive handlers while preserving session-specific permission and fresh child authority.

#### Scenario: Recipe bytes available without handler
- **WHEN** a selected recipe is verified but actual root engine, primitive handler or trusted session permission is missing
- **THEN** capability remains incomplete and no recipe/fixture status claims native effect success

### Requirement: Separate private setup probe authority
The installer SHALL authorize private origin probes through a separate root-owned setup binding and exact fresh connector effects, without fabricating public Access sessions or worker profile contexts.

#### Scenario: Setup probe submitted to public issuer
- **WHEN** a private probe handle or synthetic Access context reaches the public remote connector issuer
- **THEN** it is rejected, and only the separate root-private exact probe issuer may admit selected local app readiness operations

### Requirement: Native loaded closure observation

The implementation SHALL enforce this protocol. HI-T08 / HI-T09: use planning/protected-runtime-assembly-contract.json native_custody_proof_protocol; immutable mount metadata alone cannot establish readiness, source provenance or action success.

#### Scenario: Missing concrete runtime proof
- **WHEN** the exact protocol or current kernel/native observations are unavailable
- **THEN** the affected task remains incomplete and no fixture or mount-only evidence establishes acceptance.

### Requirement: Finite loader progress receiver

The root receiver SHALL enforce native_custody_proof_protocol.progress_wire framing, selected-role custody and ordered finite observations before issuing a loaded closure proof.

#### Scenario: Forged or incomplete loader event
- **WHEN** progress frames are malformed, stale, replayed or incomplete
- **THEN** no readiness proof is issued and existing task acceptance remains pending.

### Requirement: Private probe principal and sequence joins

The private probe issuer SHALL resolve the actual protected native PrincipalBinding, separate effect and connector frame sequences, and admit only immutable per-action child probe handles.

#### Scenario: Child action substitution
- **WHEN** an asset, action, principal or sequence differs from current root selection
- **THEN** admission is denied before connector bytes.

### Requirement: Root observed initial input closure

The implementation SHALL resolve actual installed release custody and full admitted source receipt closure before issuing native input provenance. Private or unknown sensitivity SHALL remain unchanged absent separate reviewed clearance.

#### Scenario: Digest without source closure
- **WHEN** only a digest or caller provenance label is available
- **THEN** no trusted input receipt or admitted native effect is created.

### Requirement: Supported loader and current task controller

The implementation SHALL use the exact named systemd FD transfer and kernel-authenticated loader progress contract, and SHALL distinguish historical source lineage from current verified execution controller.

#### Scenario: Historical capsule mistaken for current peer
- **WHEN** only serialized source metadata or manager socket credentials are available
- **THEN** no live producer or loader proof is fabricated.

### Requirement: Protected setup store and bounded probe response

The implementation SHALL resolve the protected setup catalog/store and validate the exact bounded private probe response against current root admission and actual observations.

#### Scenario: Untrusted injected catalog or response
- **WHEN** selected artifact custody or probe envelope/observation binding differs
- **THEN** provisioning/readiness cannot be marked complete.

### Requirement: Exact root peer delivery and controller roles

The implementation SHALL use explicit protected observer delivery role joins and actual kernel controller DTOs with exact PIDFD ownership.

#### Scenario: Unenrolled cross-peer selection
- **WHEN** no exact current observer delivery mapping exists
- **THEN** cross-peer delivery is denied without target-string inference.

### Requirement: Actual root resource controller enrollment

Root event context issuance SHALL require the exact active daemon/module/observer/backend role record and current kernel identity before fresh child effects.

#### Scenario: Unverified root dispatcher role
- **WHEN** role/module/kernel/event/body bindings are absent or stale
- **THEN** no context or child effect is fabricated.

### Requirement: Protected native MCP call binding

Installer-managed native MCP calls SHALL resolve exact observed invocation/name/schema to current enrolled backend/resource and fresh protected MCP effect before bytes.

#### Scenario: Native call mapping mismatch
- **WHEN** name/schema/resource/package/peer or one-use invocation binding differs
- **THEN** no MCP effect or credential reaches the unselected backend.

### Requirement: Exact native MCP lexical and configuration mapping

Installer-owned MCP calls SHALL retain exact protected server/tool/schema and same lexical invocation binding while preventing direct worker transport bypass.

#### Scenario: Configured direct transport bypass
- **WHEN** an installer-owned entry attempts direct worker effects instead of the selected broker
- **THEN** no MCP bytes or credentials are forwarded.

### Requirement: Actual task native and credential closure

Successful task completion SHALL bind actual native execution receipts and distinct service/resource epochs. Webhook verification SHALL use explicit protected placeholder-to-vault-role mapping.

#### Scenario: Native or credential mapping absence
- **WHEN** the current exact native or scoped credential join is missing
- **THEN** no successful task capsule or authenticated webhook event is fabricated.

Root-selected lifecycle authority v80: `plans/amendments/2026-10-10-root-selected-service-lifecycle-authority-v80.md`; existing HI/RT/SK tasks open, separate actual controller and selected subject proof required.

Native registration projection v99: `plans/amendments/2026-10-10-native-registration-projection-v99.md`; one candidate per actual source registration, finite root selector/workflow and local registry/owner-overlay routes preserve all18 scope; source and actual dispatch proof required, all gates open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.
