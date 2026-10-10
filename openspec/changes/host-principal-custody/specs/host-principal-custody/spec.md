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

Verified Xpra source pin v101: `plans/amendments/2026-10-10-xpra-verified-source-pin-v101.md`; exact source tree/finite links/actual transform and runtime proof required; no source-only acceptance or missing native-family waiver. Existing tasks open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Private loopback host tool pins v103: `plans/amendments/2026-10-10-private-loopback-host-tool-pins-v103.md`; finite actual package/executable/dependency/namespace proof, no source-only or target acceptance; existing tasks remain open.

Application owned execution receipts v104: `plans/amendments/2026-10-10-application-owned-execution-receipts-v104.md`; actual distinct selected grant/controller/probe/manager terminal/artifact result producer required, no ResourceTask/RuntimeReview substitutes; existing implementation/acceptance tasks open.

### Requirement: Finite installed host tool observation
The system SHALL use the v105 root-only HostToolObservationRegistry and exact measured variant catalog to authenticate installed nft and complete loader/dependency closure against signed distribution package evidence before network effects. It SHALL revalidate held bytes, current installed state, selected generation and lease; source package measurements and Coral package receipts SHALL NOT prove host execution.

#### Scenario: Installed dependency changes
- **WHEN** a held dependency, installed package state, keyring or selected generation changes or expires
- **THEN** nft execution and network launch are denied until a fresh valid observation and required kernel probes succeed.

### Requirement: Finite managed Xpra transformation
The system SHALL execute only the v106 selected empty-parameter Xpra build recipe under actual official PM runtime and pinned installed transform module, retaining original source and distinct regular staging closure. It SHALL require actual managed terminal and dynamic output attestation before overlay publication.

#### Scenario: Archive hash presented as executable identity
- **WHEN** a builder selection supplies an archive SHA or local fixture output in place of actual executable or managed output proof
- **THEN** build admission or publication is denied.

### Requirement: Exact regular Xpra build topology
The system SHALL use the v109 source-verified transform module and exact original regular staging directory topology, mount the PM builder executable as a file and publish the archive as non-executable data.

#### Scenario: Missing source topology
- **WHEN** staging omits a required original manifest directory or changes the selected source links
- **THEN** transformation denies instead of changing source identity.

### Requirement: Source bounded local registration results
The system SHALL use exact v110 local handler result envelopes and recursive public JSON limits while preserving untrusted source classification and actual owner CAS controls. It SHALL NOT replace protected passthrough backend result authority with generic object schemas.

#### Scenario: Protected backend schema missing
- **WHEN** finance, wallet or source-receipt output lacks its actual bounded typed backend result schema
- **THEN** that executable candidate remains unavailable without omitting the original family acceptance obligation.

### Requirement: Exact selected link target bytes
The system SHALL verify all five selected Xpra link target strings, SHA256 and byte sizes against the original source manifest before reconstruction using the v111 committed module.

#### Scenario: Link target hash mismatch
- **WHEN** any target byte digest or size differs
- **THEN** build staging denies without broadening symlink authority.

### Requirement: Actual local schema artifact receipt join
The system SHALL bind each v112 local result schema ID to exact packaged bytes and actual root source receipt plus installed bounded validator before executable registration. It SHALL preserve pre-active assembly receipt staging distinct from active generation publication.

#### Scenario: Source table presented as receipt
- **WHEN** a source-reviewed schema table lacks actual packaged artifact and installed validator proof
- **THEN** executable registration remains unavailable.

### Requirement: Separate protected native action and registration records
The system SHALL use v113 exact typed action, registration and workflow arrays to join actual source42 Hermes registrations to source61 backend routes, selected schemas/observers/effects and staged installation receipts before atomic active publication. It SHALL preserve original canonical invocation arguments and independent child authorization.

#### Scenario: Multiple actions share one adapter
- **WHEN** source registrations select multiple reviewed actions under one adapter
- **THEN** unique action binding IDs preserve each exact route instead of collapsing or inferring action authority from tool names.

### Requirement: Bounded passthrough result data
The system SHALL wrap source handler passthrough results in the v113 bounded closed tool-result envelope without treating backend data as authority or execution success. Actual operation/account/receipt validation remains required.

#### Scenario: Backend data claims authorization
- **WHEN** returned JSON contains authority-like or readiness fields
- **THEN** those fields remain untrusted data and cannot affect authorization or acceptance.

### Requirement: Exact catalog compatible local schema identities
The system SHALL use the v114 literal catalog-compatible schema/artifact IDs for eight local result schemas without widening static catalog grammar or minting aliases.

#### Scenario: Earlier impossible identity
- **WHEN** a source row contains the superseded colon artifact ID
- **THEN** selection fails until the corrected exact source map is used.

### Requirement: Prepared setup build subject selection
The system SHALL use the v115 exact root setup build service template and actual dedicated NSS/root/current controller receipts for the finite Xpra managed build without requiring an active native service generation. It SHALL preserve empty prepared active service records and distinguish the controller from the actual launched build child.

#### Scenario: First setup lacks active worker profile
- **WHEN** a valid root prepared transaction selects the finite build
- **THEN** its sealed setup-only subject is independently validated without manufacturing an active worker identity.

### Requirement: Bounded source-derived native financial and web results

The installer SHALL validate source-derived financial observations and web result artifacts using v120 exact selected schemas and actual root receipt currentness, preserving untrusted result semantics.

#### Scenario: False web artifact receipt

- **WHEN** a web result supplies a structurally valid receipt that does not resolve current root artifact/source membership
- **THEN** result promotion is denied and no provenance or authority is inferred from the returned dictionary

### Requirement: Source exact financial account alias domain

The installer SHALL preserve v121 actual source account alias regex and128-character bound when validating selected financial observations.

#### Scenario: Valid selected alias exceeds96 characters

- **WHEN** the actual selected alias satisfies the source128-character domain
- **THEN** it is not rejected solely by the superseded v120 max96 ceiling; all other proof and output checks remain required

### Requirement: Independent selected native process role association

The installer SHALL join observer process identity to explicit v123 protected process-role module/source/current loaded proofs, independently of action adapters.

#### Scenario: Action adapter is supplied as a process role

- **WHEN** an observer role has no exact protected process-role member/current loaded module proof
- **THEN** source capture is denied even if a selected action adapter exists with the same name or artifact digest

### Requirement: Actual root retained web content provenance

The installer SHALL issue native web result metadata only from v126 genuine root authorized response observation, bounded captured CAS and current profile/effect/native/transport/source ancestry.

#### Scenario: Transport dictionary without root captured receipt

- **WHEN** a transport response provides a hash and receipt dictionary without root registry membership and actual captured content
- **THEN** native result provenance promotion is denied, while the transport observation remains distinguishable from an artifact receipt

### Requirement: Setup intent selectors and current private profile proof
The system SHALL distinguish stable root setup principal/namespace/private-purpose intent from current <=30s authenticated authority snapshots, using the v133 exact source/subject/session/generation joins. It SHALL mint a distinct private-purpose selection only from the actual adopted native principal/profile and verified v91 owner-private namespace source within actual root TTY configuration.

#### Scenario: Identity changes during preparation
- **WHEN** refreshed Authentik subject, groups, policy or selected namespace differs from the retained choice
- **THEN** the phase denies without extending old receipts, widening permission or substituting a Resources profile.

### Requirement: Authenticated selected process-role delivery
The system SHALL deliver exact v123 role records through the v134 verified manifest and resolver digest join, and accept loaded-role proof only from actual selected import observations independently checked against held closure/source/current process custody.

#### Scenario: Manifest role has not been imported
- **WHEN** a catalog role exists but the current loader has no matching actual module origin observation
- **THEN** the role is unavailable for source issuance and no loaded proof is inferred from an adapter.

### Requirement: Genuine preactive native policy configuration source v137
The installer SHALL prepare native action, registration, workflow, process-role and observer policy from actual root-selected source and target evidence before initial assembly; prepared empty capability state and static schema inventory SHALL NOT substitute for permission or force an active-before-assembly cycle.

#### Scenario: A selected family lacks target or source proof
- **WHEN** a required target/account/permission/schema/observer/runtime source is not observed
- **THEN** all-family coverage retains the registration as configurable pending with exact next step, emits no unproved executable candidate and preserves the original functional obligation

### Requirement: Purpose-bound PUBLIC input web permission v138
The installer SHALL authorize public web egress only from genuine root-observed PUBLIC input and current exact selected public web permission; PRIVATE or UNKNOWN source ancestry SHALL remain denied even when a public scope is configured.

#### Scenario: Private input requests an enrolled public website
- **WHEN** any retained parent/input source is PRIVATE or UNKNOWN or the public permission is absent/revoked/expired
- **THEN** public web dispatch and retries are denied without dropping ancestry, widening private consent or adding budget

### Requirement: Current web registration source receipt cohort v140
The installer SHALL select all registrations sharing the updated web/voice/epic source module only against its current actual held release module receipt and renewed source capture; old audit inventory SHALL NOT authenticate changed bytes.

#### Scenario: Source receipt identifies historical module bytes
- **WHEN** current selected module SHA differs from the retained registration/action source receipt
- **THEN** assembly denies the stale join and requires actual current source observation without editing immutable audit evidence

### Requirement: Current bounded finance registration source cohort v141
The installer SHALL bind the updated financial source module and all its actual registrations to current held source/schema receipts and bounded selected-alias observations; stale inventory or generic backend output SHALL NOT substitute for source/execution authority.

#### Scenario: Root financial read omits selected account alias
- **WHEN** the read result lacks the actual root-selected alias or violates the closed scalar/UTF8/byte bounds
- **THEN** the native result is denied without fabricating an alias or promoting backend claims to account/transaction proof

### Requirement: Protected public web scope source v142
The installer SHALL publish only source-selected public web scopes with exact target, effect and configuration receipt joins and SHALL require separate current PUBLIC input permission.

#### Scenario: Private input names a configured public URL
- **WHEN** a request carries PRIVATE or UNKNOWN ancestry despite a configured public scope
- **THEN** egress is denied without widening the private consent or interpreting scope configuration as input permission

### Requirement: Durable setup source choice signing v143
The installer SHALL retain purpose-specific setup choices through genuine existing key custody and protected journal records and SHALL adopt them only through actual active publication before issuing fresh runtime permissions.

#### Scenario: Setup process-local choice seal survives no durable adoption
- **WHEN** runtime permission is requested from a choice without verified durable signature and publication adoption
- **THEN** permission is denied rather than constructing a parallel authority service or treating old setup evidence as current authority

### Requirement: Completed source choice ordering v146
The installer SHALL distinguish held root observation from completed signed choice and full source verification, accurately name release identity and authenticate complete public scope payloads from retained configuration.

#### Scenario: Fixed root is observed before child choice
- **WHEN** only the fixed model store root is held
- **THEN** no completed choice or model source proof is signed until the actual TTY selection and applicable source evidence exist

### Requirement: Distinct runtime member and public input evidence v149
The installer SHALL preserve unique interpreter identity, exact runtime member closure and distinct prepared/live role proofs, and SHALL require actual per-input root disclosure for first public egress.

#### Scenario: Persistent public config has no disclosed input
- **WHEN** a public web request has no actual root-observed per-input disclosure and ancestry proof
- **THEN** no PUBLIC receipt is issued merely from profile configuration or missing parents

### Requirement: Durable adopted public choice currentness v153
The installer SHALL verify current signed source choice/revocation and active adoption beyond setup closure while requiring separate fresh per-input installed-root TTY disclosure and effect authority.

#### Scenario: Original signed choice is revoked under unchanged active pointer
- **WHEN** the root journal choice epoch/revocation changes
- **THEN** the adoption/current permission denies despite an unchanged policy pointer and never extends an expired setup or runtime lease

### Requirement: Prepared source module layout v154
The installer SHALL bind the two reviewed worker source members with source-module role and the root-imported definition adapter with its distinct module identity.

#### Scenario: Prepared worker source is available before worker launch
- **WHEN** a verified held release includes the exact source-module bytes
- **THEN** the factory may prove source membership without claiming root import or live worker origin, and later worker evidence remains independently required

### Requirement: Runtime choice revocation source v156
The installer SHALL consume genuine current installed actor and one-use foreground TTY revocation observation tied to the displayed adopted choice before signing a durable revoked epoch.

#### Scenario: Revocation request carries caller epoch or expired setup proof
- **WHEN** no genuine current runtime revocation observation exists
- **THEN** the registry denies without changing the signed choice or restoring an expired lease

### Requirement: Native capture profiles v158
The installer SHALL validate raw root-observed result bytes against the exact selected protected result schema before source capture and deliver only genuine current peer-bound handles.

#### Scenario: Worker supplies a ToolMessage without a completed root result
- **WHEN** no matching current root invocation/result/schema observation exists
- **THEN** source capture denies and no worker message or generic object schema supplies authority

### Requirement: Root native health start v159
The installer SHALL admit health only from genuine committed runnable enrollment and bind the root-selected service grant, transaction, fixture and live control before authenticated input.

#### Scenario: Only a prepared generation is available
- **WHEN** health is requested without a current committed runnable enrollment receipt
- **THEN** health start denies and ordinary enablement stays withheld until actual same-generation semantic health succeeds

### Requirement: Installed local qualification v160
The installer SHALL dispatch only fixed source-reviewed local qualification suites under its genuine installed actor and execute production authority paths with actual owned fixture receipts.

#### Scenario: Qualification caller supplies arbitrary test code or policy JSON
- **WHEN** input exceeds the finite installed suite selector
- **THEN** dispatch denies and no actor/session/grant shortcut is created

### Requirement: Application build admission v161
The installer SHALL execute application runtime preparation only through a finite root-selected managed build profile, genuine held input/service/output proofs and one-use setup grant.

#### Scenario: Final selection lacks a reviewed source driver or backend closure
- **WHEN** an application environment build is requested
- **THEN** custody denies before start without inventing a driver hash, caller script, future output digest or active runtime row

### Requirement: Qualification root adapter v162
The installer SHALL isolate fixture publication/session/key authority under the exact observed recipe-owned run root while preserving production constants and source/kernel effect validation.

#### Scenario: Fixture handle is presented to production consumer
- **WHEN** a qualification session or signed fixture receipt targets production authority
- **THEN** production denies the distinct namespace/type/key and no arbitrary path override is accepted

### Requirement: Health input source delivery v163
The installer SHALL bind selected health fixture input to the actual started native peer, PRIVATE source context and distinct actual capture/write/EOF/take receipts.

#### Scenario: Captured health source has no completed stdin delivery
- **WHEN** native input take lacks exact successful write and EOF receipts for the current health peer
- **THEN** delivery denies and no health success is recorded

### Requirement: Qualification envelope v164
The installer SHALL verify the exact fixture-only canonical authority/catalog envelope and current owned namespace before parsing enrollment.

#### Scenario: Fixture catalog is swapped
- **WHEN** catalog bytes disagree with the signed envelope or current fixture pointer
- **THEN** the dedicated loader denies before creating any authority service

### Requirement: Runtime role publication join v165
The installer SHALL activate from the same genuine PM and native CAS receipt closure used by strict active compilation and SHALL freshly verify current committed enrollment for runtime health.

#### Scenario: Generated native receipt is presented as static source receipt
- **WHEN** activation receives a generated output through unrelated static artifact lookup
- **THEN** it denies until the exact typed producer/CAS/source role projection is resolved

### Requirement: Qualification key signer v166
The installer SHALL sign only the exact fixture envelope with the genuine held fixture key before constructing its actual authority service.

#### Scenario: Caller requests another signature domain
- **WHEN** a fixture signer is used for unrelated data or production authority
- **THEN** the restricted facade denies

### Requirement: Qualification session storage v167
The installer SHALL retain live fixture session authority only in its current sealed registry and SHALL treat any session file as historical metadata.

#### Scenario: Historical session file is reopened
- **WHEN** no current genuine fixture lease and session registry membership exist
- **THEN** the historical file cannot authorize an effect

### Requirement: Application Python entrypoint relocation v168
The installer SHALL bind the regular environment interpreter to actual held PM executable bytes and normalize only source-reviewed console script shebangs to its selected final generation.

#### Scenario: Script requests ambient interpreter
- **WHEN** installed script depends on /usr/bin/env or an unrelated interpreter path
- **THEN** materialization denies until exact selected interpreter normalization is verified

### Requirement: Native precompile reservation v169
The installer SHALL authorize and reserve actual generated outputs from genuine current setup source selection before compiling their strict active rows.

#### Scenario: Prepared native package catalog is empty
- **WHEN** genuine source-backed assembly has produced five valid selected outputs
- **THEN** authorization resolves the sealed setup selection and never requires future active package policy

### Requirement: Native output role correction v170
The installer SHALL use exact source-established native output roles and output kinds.

#### Scenario: Unknown overlay role is supplied
- **WHEN** a receipt uses native-overlay-archive rather than native-boundary-overlay
- **THEN** reservation and projection deny the unknown literal

### Requirement: MCP discovery capture v171
The installer SHALL separately validate and retain actual selected MCP discovery responses before deriving schemas, without treating metadata as tool execution.

#### Scenario: Tools call is labelled discovery
- **WHEN** actual retained request method is tools/call
- **THEN** the selected tool result schema gate applies and discovery profile cannot bypass it

### Requirement: Owner overlay operations v172
The installer SHALL authorize source-established owner overlay methods through separate protected operation rows and genuine current owned profile CAS grants.

#### Scenario: Local registration has no selected view receipt
- **WHEN** source inventory names a local method without a current owned view/target/schema/source join
- **THEN** it remains precisely pending and never becomes an executable backend action

### Requirement: Fixture resource materialization v173
The installer SHALL derive owned fixture Resources rows from actual source-bound fixture materialization and discovery.

#### Scenario: Production materialization has different identities
- **WHEN** a production receipt cannot join the generated fixture namespace and profile
- **THEN** it SHALL NOT be relabeled, and fixture compilation waits for its own actual materialization receipt

### Requirement: Initial public TTY source v174
The installer SHALL require actual fresh foreground input and per-input public disclosure before initial public source issuance.

#### Scenario: Existing task input is private
- **WHEN** task stdin already has PRIVATE source ancestry
- **THEN** the initial public TTY producer SHALL NOT relabel it or issue a public source receipt

### Requirement: Application effect sources v175
The installer SHALL admit only the source-reviewed fixed qualification effect stages and separately verify runtime ABI.

#### Scenario: Hyperframes qualification runs
- **WHEN** the selected fixed Hyperframes effect recipe is admitted
- **THEN** exactly render, ffprobe and framehash stages are allowed with one-use linked grants and actual cleanup evidence

### Requirement: Python runtime configuration relocation v176
The installer SHALL bind relocated Python environments to a genuinely held PM base runtime closure.

#### Scenario: Only interpreter executable bytes exist
- **WHEN** the base standard-library/runtime closure is not currently verified
- **THEN** the environment remains pending and cannot obtain runnable or ABI acceptance

### Requirement: Selected window input observation v177
The installer SHALL verify actual press and release on the selected owned window before accepting display input qualification.

#### Scenario: Focus changes or only injector success exists
- **WHEN** same-window delivery cannot be independently verified
- **THEN** qualification remains incomplete and any partial effect is reported truthfully


### Requirement: Source-join producers v178
The installer SHALL implement the source-owned receipt joins and closed fixture descriptor in `plans/amendments/2026-10-10-source-join-producers-v178.md` before compiling executable native or fixture authority.

#### Scenario: Genuine current source graph
- **WHEN** the exact held setup/source/PM, selected definition/member/effect/schema/role and separately observed fixture service receipts are current
- **THEN** the compiler SHALL consume their retained immutable projection and actual generated/materialized/discovered bytes, keeping fixture evidence separate from production and AC acceptance

#### Scenario: Missing or misjoined producer
- **WHEN** a required source/effect/member/observer/service receipt is absent, stale, altered or from another namespace
- **THEN** affected capability remains precisely pending, no caller path or production-row relabeling fills the gap, and no denial-only callback counts as implementation

### Requirement: Selected native executable closure v179
The installer SHALL apply `plans/amendments/2026-10-10-selected-native-executable-closure-v179.md` while preserving full source coverage and pending unavailable capabilities.

#### Scenario: Current selected owned local closure
- **WHEN** current source, schema, selected target/effect and preactive role declarations join every selected executable registration
- **THEN** the projector and assembler SHALL consume exactly that retained closure without requiring unavailable account/provider/device effects

#### Scenario: Omitted or extra executable row
- **WHEN** a selected required join is missing or an unselected executable row is supplied
- **THEN** compilation SHALL deny before output, keeping full pending coverage and all AC acceptance OPEN


### Requirement: Reviewed source members and boundary joins v180
The installer SHALL apply only the exact finite reviewed source/member/role mappings and genuine producer joins in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`.

#### Scenario: Reviewed source reaches runtime
- **WHEN** committed source pins are packaged and exact current membership/import/selection receipts are verified
- **THEN** separate owner-overlay rows SHALL remain digest-covered through loading/invocation, standalone build driver SHALL use its dedicated held execution source and PM runtime, and each worker SHALL pass its own cgroup kernel gate before app code

#### Scenario: Missing or unsupported producer
- **WHEN** a source/member/role/schema/loaded proof is missing or kernel enforcement permits a forbidden bind
- **THEN** startup/effect remains unavailable, no network lease or acceptance is issued, and owned cleanup SHALL be verified without weakening negative expectations


### Requirement: Conditional Authentik and genuine local owner v181
The installer SHALL implement the exclusive typed identity domains, finite selected capabilities, independent setup and genuine current producer joins in `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`, preserving R0058/R0060/R0143 and all privileged Authentik/broker requirements.

#### Scenario: Independent selected local capability
- **WHEN** the installed root setup selects an observed nonroot Linux owner and reviewed local capability rows without Authentik-dependent capabilities
- **THEN** independent prepared materialization and fully authorized local effects SHALL proceed through current owner/service/profile/view/policy/loaded-worker receipts, while missing provider or account dependencies remain precisely pending

#### Scenario: Privileged dependency absent or identity stale
- **WHEN** a local principal requests homelab/recipient authority or a current identity, selected effect, loaded proof or required Authentik dependency is missing
- **THEN** the affected action SHALL deny before effect, preserve independent owned work, and report configure-later/resume without claiming full compliance or synthesizing Authentik authority


### Requirement: Concrete active network generation owner v182
The installer SHALL implement the exact finite compiler projection, post-setup owner and helper manager custody/revalidation lifecycle in `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`, with no bare currentness callback or setup receipt substitution.

#### Scenario: Valid adoption after setup expiry
- **WHEN** a signed native policy choice was adopted before its original deadline and current active release/actor/key/publication/source/revocation/journal/worker row proofs all match
- **THEN** only its exact selected helper/worker MAY reach the own-cgroup kernel start barrier, and app release requires fresh current owner and actual enforcement evidence

#### Scenario: Active proof changes or enforcement unavailable
- **WHEN** revocation/CAS/code/actor/journal/profile currentness changes or a forbidden kernel bind succeeds
- **THEN** app startup SHALL deny with no network lease, owned cleanup SHALL be verified, and unsupported enforcement SHALL remain unavailable without acceptance


### Requirement: Signed worker and active overlay producers v183
The installer SHALL implement the exact source/type/method/output producer joins and exclusive finite scopes in `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`.

#### Scenario: Genuine source survives as current active custody
- **WHEN** actual held worker/source/PM/native/view receipts enter signed selected recipe and tagged local-owner adoption during genuine active publication
- **THEN** after setup expiry only independently verified current runtime source/NSS/enrollment/loaded process and one-use selected grant MAY permit its four exact owned overlay methods

#### Scenario: Missing source or stale active authority
- **WHEN** recipe/source/member/view/NSS/current choice/loaded peer proof is absent or mismatched, revoked, late-adopted or replaced
- **THEN** app/effect SHALL deny before execution, preserve independent source readiness and never derive host/AuthentiK authority or network permission from static metadata/choice presence


### Requirement: Acyclic finite network rows v184
The installer SHALL use the exact closed versioned field sets, full-row canonical hashes and producer/currentness/FK rules in `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`.

#### Scenario: Exact generated source rows
- **WHEN** real signed recipe/source and held runtime/identity roots produce the finite schema2 AF_UNIX rows
- **THEN** current runtime MAY attach the separately verified enclosing generation digest and reach its worker barrier without feeding that digest back into generated rows

#### Scenario: Wire or phase proof invalid
- **WHEN** fields/FKs/digests/versions/current source differ or only pre-READY mount custody exists for an effect
- **THEN** startup/effect SHALL deny without inventing TCP/source/loaded authority or successful acceptance


### Requirement: Concrete owner registration capture and RPC v185
The installer SHALL implement the exact tagged role/registration/READY/source schema and fixed proxy/RPC joins in `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md`.

#### Scenario: Actual observed selected local call
- **WHEN** the current loaded owner role and actual READY registrations, captured provider call/schema and root one-use selected grant all match
- **THEN** only the four fixed local methods MAY reach current owned CAS/read through the protected RPC

#### Scenario: Registration or captured authority absent
- **WHEN** source/role/READY/peer/schema/choice/invocation proof is synthetic, stale or absent
- **THEN** the effect SHALL deny before side effect without skipping backend checks or fabricating local observer/provider provenance


### Requirement: Genuine preactive listener custody v186
The installer SHALL resolve the endpoint source phase through actual root-held listener custody and current authenticated active transfer in `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`.

#### Scenario: Endpoint observed before recipe
- **WHEN** the current prepared owned account/root and installed root custodian bind and observe the exact fixed socket
- **THEN** source recipe MAY retain actual prepared socket custody while every effect remains unavailable until verified active adoption and re-observation

#### Scenario: Custody or phase invalid
- **WHEN** socket/root/actor/account/transfer/publication identity changes or adoption is absent/expired
- **THEN** worker start/effect SHALL deny, preserve foreign conflicts and verify only owned cleanup without claiming future target proof


### Requirement: Actual supervised listener activation v187
The installer SHALL implement the actual both-process supervisor/peer/activation channel and current one-use FD custody in `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md`.

#### Scenario: Exact installed daemon handoff
- **WHEN** independently current setup actor and supervised installed daemon join the protected activation record, real peer PIDFD/unit/launch and current publication/source/socket
- **THEN** only that daemon MAY adopt the held listener after one-use FD transfer and verified acknowledgment

#### Scenario: Cross-process proof invalid
- **WHEN** remote actor is treated as local, only UID0 or same-process channel is known, or peer/unit/source/CAS/FD differs
- **THEN** adoption/startup SHALL deny and owned cleanup/conflict preservation remain mandatory with all acceptance pending


### Requirement: Exact paired owner result source v188
The installer SHALL enforce the separately signed result enrollment, issuer/channel and actual root handler member joins in `plans/amendments/2026-10-10-owner-result-source-selector-v188.md`.

#### Scenario: Genuine completed local effect
- **WHEN** the exact signed result observer and current root handler source join the consumed invocation grant and actual completed CAS/read
- **THEN** root MAY issue the fixed owner tool-result capture with actual invocation parents

#### Scenario: Result source selection absent or changed
- **WHEN** only a matching generic backend observer exists or selected result/source/schema/parent/currentness is invalid
- **THEN** result issuance SHALL deny without inventing authority or repeating a completed effect


### Requirement: Finite native module execution v188
The manager SHALL admit the fixed reviewed Hermes CLI recipe only using the privately issued current active worker/source/runtime/package proof in v188, preserving generic interpreter child validation.

#### Scenario: No genuine native launch proof
- **WHEN** recipe, source, runtime, package or active network proof is missing or changed
- **THEN** startup SHALL deny with no lease and verified owned cleanup


### Requirement: Independently current committed PM executable v189
The selected native worker SHALL resolve its exact observed committed venv executable through the private receipt/source/publication/closure owner in `plans/amendments/2026-10-10-committed-pm-executable-identity-v189.md`, preserving generic catalog checks.

#### Scenario: Genuine observed venv executable
- **WHEN** the selected signed native recipe and current protected runtime join the actual complete PM receipt and held executable/venv closure
- **THEN** the consumer MAY admit that exact executable identity without relabeling base artifacts

#### Scenario: Runtime identity not proven
- **WHEN** observed identity, receipt, current adoption/source, executable or full closure is missing or differs
- **THEN** startup SHALL deny with no caller identity map or generic static-check waiver


### Requirement: Staged same-worker namespace handshake v190
The manager/helper SHALL implement the exact schema2 protocol in `plans/amendments/2026-10-10-same-worker-namespace-handshake-v190.md` and observe the actual owned helper namespace before probes and app release.

#### Scenario: Namespace exists only after helper starts
- **WHEN** the fixed reviewed helper is launched without app imports/input
- **THEN** root SHALL observe its actual MainPID/PIDFD/unit/cgroup/netns before issuing the authenticated namespace gate

#### Scenario: Missing or changed observed namespace grant
- **WHEN** gate or peer/source/probe/release evidence is absent, replayed or mismatched
- **THEN** app start and network lease SHALL deny with verified owned cleanup


### Requirement: Two-actor same-generation functional health v191
The installer SHALL enforce the independent daemon commit/source proof and fixed authenticated setup health intent in `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md`, without transferring live setup authority.

#### Scenario: Real daemon health completion
- **WHEN** the actual selected source/native run produces passed same-generation semantic health and verified terminal cleanup
- **THEN** only its concrete root consumer MAY issue the current committed journal witness used for functional enablement

#### Scenario: Transport or copied setup proof only
- **WHEN** only ACK, copied DTO, wrong generation/source, stale intent or incomplete observer/terminal evidence exists
- **THEN** functional enablement SHALL remain pending with one-use reconciliation and owned cleanup


### Requirement: Exact native worker selected views v192
The manager SHALL separate host source identity from worker-visible executable/argv and verify complete selected mounted views under `plans/amendments/2026-10-10-native-worker-selected-view-paths-v192.md`.

#### Scenario: Protected source hidden in worker namespace
- **WHEN** exact selected immutable venv/base/package/runtime views are required for fixed worker execution
- **THEN** only private source-derived mounts and actual inode/hash/mount observation MAY supply worker paths

#### Scenario: View not proven
- **WHEN** source dependency, readable contract, mount, executable or package proof is absent or changed
- **THEN** startup SHALL deny without unmasking broad host roots or caller path/environment fallback


### Requirement: Distinct native view source and target custody v193
The manager SHALL enforce exact source/member/owned target proof under `plans/amendments/2026-10-10-native-worker-view-member-bind-custody-v193.md`; a synthetic target root SHALL NOT be relabeled as the source directory inode.

#### Scenario: Protected output source directory not traversable
- **WHEN** the exact five held native output files are individually readonly bound into a root-owned readable private view
- **THEN** source root permissions SHALL remain intact and actual target root/member identity SHALL be independently observed

#### Scenario: Sparse view not exact
- **WHEN** target has extra/changed/unreadable member, foreign mount or unproven source/current namespace
- **THEN** startup SHALL deny without source permission repair or broad host exposure


### Requirement: Genuine health event causal ancestry v194
Health SHALL retain each actual native event ancestry meaning and verify the exact source/control causal graph under `plans/amendments/2026-10-10-health-event-causal-ancestry-v194.md`; uniform source closure equality SHALL NOT be fabricated.

#### Scenario: Native digest meanings differ
- **WHEN** signed input lineage and actual invocation/result receipt closure differ but genuine source/control causal relations match the selected health run
- **THEN** the root observer MAY bind the actual completed DAG proof and final result closure separately

#### Scenario: Causal proof absent
- **WHEN** event ancestry is relabeled, foreign, incomplete or replaced by fixture/package hashes
- **THEN** health completion and functional enablement SHALL deny


## ADDED Requirements

### Requirement: Final coherent source tuple application
The installer SHALL apply only the exact committed source/member/catalog/role/import closure tuple list in `plans/amendments/2026-10-10-final-coherent-source-pin-review-v195.md` and `planning/final-coherent-source-pin-review-v195.json`, preserving independent source, installed import, loaded native and current effect/health evidence.

#### Scenario: Exact finite pin application
- **WHEN** Luna applies the reviewed source0add8c33 batch after specification publication
- **THEN** exact byte hashes/sizes, canonical member roles/modes, required PlanResolver aliases and actual import closure SHALL agree, with no source metadata self-hash cycle or caller-derived pin

#### Scenario: Source evidence does not activate runtime
- **WHEN** source review or fixture tests pass but actual loaded/current source, helper, invocation, health or target evidence is absent
- **THEN** affected execution SHALL remain denied or unavailable and all original AC01..AC18 acceptance SHALL remain OPEN


## ADDED Requirements

### Requirement: Genuine installed startup and qualification authority
The installer SHALL use the exact closed process/session/source/publication contract in `plans/amendments/2026-10-10-installed-startup-qualification-custody-v197.md` to compose selected display startup and fixed installed qualification effects.

#### Scenario: Setup and daemon are different actors
- **WHEN** the daemon admits a selected startup from root setup
- **THEN** a bounded one-use authenticated original-deadline startup intent and actual controller PIDFD/current protected source selection SHALL be required, with no copied store or recreated setup handle

#### Scenario: Fixed qualification has a real producer
- **WHEN** display or task qualification runs
- **THEN** its current owned controller, actual source/PM/materialized fixture publication/session and isolated composed runtime SHALL drive the production typed effect path and verified cleanup; missing proof or unsupported kernel SHALL not count as passed


### Requirement: Durable selected overlay startup custody

The installer SHALL adopt Xpra receipts only through the v198 schema2 signed current build/CAS/catalog and selected-startup joins, without copying process-local setup entries or using the Xauthority signing domain.

#### Scenario: Cold daemon receives genuine current overlay

- **WHEN** the independently composed daemon resolves the exact current signed selection, schema2 envelope, attestation, held CAS output and source observations
- **THEN** it may admit the selected startup only within the original admission deadline; completed active workers remain governed by independent active runtime policy after installer close

#### Scenario: Durable or lifecycle proof is absent

- **WHEN** any current source/build/selection/signature join is absent, expired or replaced, or only an ACK exists
- **THEN** startup remains denied or unavailable, with owned incomplete-start cleanup and no fabricated completed active worker proof

### Requirement: Home Assistant root enrollment MC-R0101
The installer SHALL enroll an existing Home Assistant MCP instance only through current root-held credential/source selection and strict protected publication, allowing reviewed selected-entity reads.

#### Scenario: Dashboard login or generic setup ID exists
- **WHEN** no actual protected API credential and selected read schema have been verified
- **THEN** connection remains pending and no worker-created authority or device action is permitted

#### Scenario: Credential is revoked after a successful read
- **WHEN** reconnect receives unauthorized or revoked credential evidence
- **THEN** new reads are denied, stale transport handles are retired and HA configuration remains unchanged

### Requirement: Actual setup and fixture source producers

The installer SHALL produce the v199 current setup startup projection from actual selected source roles and protected publication, and independently issue the child-owned closed qualification source transaction/session before fixture publication.

#### Scenario: Current producers issue genuine selections

- **WHEN** actual selected source roles and protected publication are current, or the independently observed fixed fixture controller issues its own source transaction
- **THEN** only the concrete owner may issue its private startup projection or fixture source session, preserving original deadlines and source/PM custody

#### Scenario: Caller identity or acquisition cycle is substituted

- **WHEN** caller rows, copied session handles, stale receipts, production activation under fixture authority or publication as source-session prerequisite is attempted
- **THEN** the operation is denied without a capability proof or acceptance promotion

### Requirement: Home Assistant actual Assist resource scope
The installer SHALL bind Assist reads to actual observed selected exposure or unique source-supported human resource filters through a typed root choice.

#### Scenario: GetLiveContext exposes an unfiltered overview
- **WHEN** current explicit exposure-set selection or unique reviewed filter proof is absent
- **THEN** the read remains pending and no entity-ID read or whole-house permission is inferred

### Requirement: Current publication-owned protected core

The installer SHALL use the v201 actual active compiler-produced protected core member and concrete publication owner proof, and preserve distinct fixed acquisition and effect deadlines.

#### Scenario: Current core and acquisition authority

- **WHEN** actual typed source selections produce a schema2 active publication or a new fixed-suite controller issues its original acquisition lease
- **THEN** the concrete consumer validates the complete protected core and original deadline without copying process-local authority or widening effect leases

#### Scenario: Historical snapshot or renewed lease substituted

- **WHEN** fixed /etc or schema1 bytes are relabelled as published core, caller proof is supplied, or an expired acquisition deadline is renewed
- **THEN** the operation denies and remains incomplete without runtime acceptance


### Requirement: Genuine selected remote role source inputs

The installer SHALL issue the v202 root-TTY choice and exactly three source-backed startup role receipts through concrete retained source/runtime/build/NSS owners before compiling protected remote startup authority.

#### Scenario: Actual selected sources form role inputs

- **WHEN** the current fixed choice, principal, source/toolchain/dependency/runtime and build receipts are genuine
- **THEN** the exact producer may issue compiler inputs, with Xpra patch adoption after core publication and before intent, preserving independent account/native readiness

#### Scenario: Declared identity is substituted for runtime proof

- **WHEN** source archives, future handles, caller rows, missing ARM64 dependencies or unowned Cloudflare configuration are relabelled as ready role receipts
- **THEN** admission denies without disabling sandbox or wrong-port enforcement or claiming acceptance

### Requirement: Typed finite bootstrap RuntimeError diagnostics v203
The installer SHALL expose only a reviewed constant stage for exact source-owned typed bootstrap failures while preserving ordinary type-only trust errors and fail-closed behavior.

#### Scenario: Arbitrary RuntimeError or subclass reaches formatter
- **WHEN** the exception is not the exact validated new diagnostic type
- **THEN** the previous safe type-only failure behavior remains and no arbitrary message/path/secret is emitted

## ADDED Requirements

### Requirement: Exact typed diagnostic source cohort v204
The installer SHALL apply only the reviewed fd09b11d leaf tuples from planning/typed-bootstrap-diagnostic-source-review-v204.json while preserving v203 fail-closed diagnostics and all other source rows.

#### Scenario: Old expected leaf rejects new source
- **WHEN** the old pin test rejects the reviewed new bytes
- **THEN** the exact two leaf rows are applied and the complete unexcluded checks remain required before source enrollment, without claiming target acceptance


### Requirement: Fixture-owned actual NSS subject

The installer SHALL issue the v206 unprivileged fixture subject receipt only from its same child-owned source session, actual NSS identity and scoped protected transaction/controller, separately from normal production setup.

#### Scenario: Actual fixture identity selects discovery subject

- **WHEN** the fixed-suite choice and current child fixture transaction create or own the actual scoped NSS account
- **THEN** its private issuer may select the observed UID/GID for real discovery custody, with separate process and cleanup evidence

#### Scenario: Production or marker identity is substituted

- **WHEN** an unrelated normal session, production marker, caller UID or copied receipt is offered as fixture authority
- **THEN** launch denies and preserves unrelated identity/data, without enrollment or acceptance promotion

## ADDED Requirements

### Requirement: Fresh root TTY handoff after acquisition
The installer SHALL require the independent explicit same-candidate foreground TTY observation in planning/bootstrap-handoff-tty-reconfirmation-v208.json before delayed bootstrap handoff, without extending an expired proof or widening authority.

#### Scenario: Acquisition outlasts initial TTY proof
- **WHEN** fixed selected source/runtime staging outlasts the initial60s observation
- **THEN** a new explicit exact-SHA re-entry and same-controller current proof are required before one-use handoff; original expired lineage is not current authorization

#### Scenario: Reconfirmation drifts or repeats
- **WHEN** candidate/action/controller/TTY changes or the transition proof is expired or consumed
- **THEN** handoff fails closed and preserves owned staged data without acquiring service authority

## ADDED Requirements

### Requirement: Exact reconfirmation source leaf v211
The installer SHALL apply only the root_setup source tuple in planning/bootstrap-handoff-reconfirmation-source-review-v211.json, preserving all other reviewed members and v208 authority boundaries.

#### Scenario: Previous root setup source pin differs
- **WHEN** the previous expected tuple rejects committed reconfirmation bytes
- **THEN** only the reviewed root_setup leaf is replaced and full unexcluded verification remains required without target acceptance inference

## ADDED Requirements

### Requirement: Current selected Jarvis delegate home custody
The installer SHALL bind each protected selected delegate task to its current held owned home through planning/jarvis-selected-task-home-custody-v213.json and the existing consumed task effect grant.

#### Scenario: Root discovers inaccessible delegate home
- **WHEN** root discovery succeeds but serviceUID cannot traverse private host ancestors
- **THEN** custody mounts only the held selected home at fixed/hermes and verifies actual unprivileged native load without loosening root permissions or granting primary rights

#### Scenario: Home or authorization changes
- **WHEN** home FD/source/materialization/runtime/principal/namespace/policy binding is stale or foreign
- **THEN** task start fails closed and sibling/primary homes remain inaccessible

## ADDED Requirements

### Requirement: Published home facts and live task proof separation
The installer SHALL use the corrected field split in planning/jarvis-published-home-live-task-split-v214.json without fabricating future task enrollments in published source-home rows.

#### Scenario: Compile home crosswalk before tasks exist
- **WHEN** verified source homes are published before task admission
- **THEN** only actual source/home/runtime/principal/namespace facts are compiled and live task/context/process/resource facts are resolved later through genuine current grants

## ADDED Requirements

### Requirement: Distinct selected source profile and service identity
The installer SHALL use planning/jarvis-source-profile-task-identity-v215.json to distinguish verified source_profile_id from actual protected service profile_id and derive task home leases from retained typed live admissions.

#### Scenario: Delegate source differs from task service profile
- **WHEN** a current protected backend selects an internal source profile
- **THEN** source_profile_id resolves exact current owned home while service profile/principal/namespace/grant checks remain unchanged and no additional serviceprofile identity is fabricated

## ADDED Requirements

### Requirement: Dedicated official Desktop acquisition authority
The installer SHALL use planning/official-desktop-build-acquisition-v218.json for Desktop-specific locked source acquisition and offline build toolchain receipts without relabelling application consent.

#### Scenario: Existing Node bytes selected for Desktop
- **WHEN** the exact reviewed Node archive is reused by the Desktop builder
- **THEN** only current selected Desktop phase/sourcepolicy may issue receipts and npm/native lifecycle/network effects remain independently bounded

## ADDED Requirements

### Requirement: Fixed sealed descriptor exec inheritance
The installer SHALL carry only its previously authorized sealedFD3 through existingfixedexec using the reviewed inheritance readback in planning/sealed-bootstrap-fd3-source-review-v220.json while retaining allsource/controller/oneuse/expiry/seal checks.

#### Scenario: Sealed memfd is already descriptor three
- **WHEN** the selected sealedmemfd already occupiesFD3 with CLOEXEC
- **THEN** the fixedhelper explicitly clears CLOEXEC and verifies inheritance before existingexec without renewing authority or changing installed memberpins

#### Scenario: Sealed handoff memfd is already descriptor 3
- **WHEN** the fixed same-process re-exec installs its sealed transition memfd and that source descriptor is already 3 with close-on-exec set
- **THEN** it explicitly clears and verifies close-on-exec on descriptor 3 before exec, and the child validates the same sealed bytes and journal binding
## ADDED Requirements

### Requirement: Actual remote role source definition producer
The installer SHALL use planning/official-remote-role-definition-producer-v222.json to select exact source-held roledefinitions and genuine current role receipts before activepromotion.

#### Scenario: Prepared enrollment has no runnable records
- **WHEN** initial remote role preparation occurs with empty preparedrecords
- **THEN** exact source-only definitions issue actualtransaction identityselections and only complete observedNSS/runtime/network/source joins may be promoted

## ADDED Requirements

### Requirement: Fresh current published PM runtime for delegate homes
The installer SHALL use planning/current-published-pm-home-runtime-v221.json to verify current published PM/home identity through genuine fresh held bytes without extending setup receipts.
The installer SHALL use planning/current-published-pm-home-runtime-v221.json to verify currentpublishedPM/home identity through genuinefreshheldbytes without extending setup receipts.

#### Scenario: Setup receipt expires before delegate task
- **WHEN** the installedcurrentpublication remainsvalid aftersetup expiry or daemonrestart
- **THEN** the existingcommittedPMresolver reopens currentreceipt/executable/fullclosure and issues fresh typedproof matching exacthomeprojection; oldsetupseal is not restored
- **WHEN** the installed current publication remains valid after setup expiry or daemon restart
- **THEN** the existing committed PM resolver reopens current receipt, executable and full closure and issues a fresh typed proof matching the exact home projection; an old setup seal is not restored

## ADDED Requirements

### Requirement: Current retained active enrollment projection
The installer SHALL retain actual service NSS, principal/namespace, PM/native closure, source/effect policy and native generation receipts in the sealed v231 aggregate; validate strict identity-domain active core before publication according to planning/active-authority-receipt-aggregate-v231.json.

#### Scenario: Current source receipts join active compilation
- **WHEN** the prepared catalog is dormant and a selected worker/local policy is complete
- **THEN** the pure root renderer derives actual service/process/effect rows and keeps the aggregate nonactive until the same current publication and enrollment CAS commit

## ADDED Requirements

### Requirement: Retained oneshot terminal evidence
The installer SHALL accept literal active/exited for its retained qualification oneshot only under the complete v233 exit/invocation/PIDFD/cgroup predicate, preserving original custody and deadlines.

#### Scenario: Retained child has exited successfully
- **WHEN** the exact launched invocation has MainPID zero, recorded normal successful exit, dead retained PIDFD and empty owned cgroup
- **THEN** the parent MAY consume independently validated signed result evidence and collect only that quiescent owned unit

#### Scenario: Active unit is not the retained terminal
- **WHEN** substate, exit tuple, invocation, cgroup or live-process checks disagree
- **THEN** terminal admission and collection SHALL deny without relabeling state or renewing authority

### Requirement: Genuine selected root service process authority
The installer SHALL implement planning/root-service-process-authority-lane-v236.json with a separately selected source-reviewed root-service six-operation declaration and exact current typed task/health/control admission issuer. Local owner capabilities SHALL retain their actual selected overlay ceiling, and complete service identity/process rule/currentness/kernel checks SHALL remain mandatory.

#### Scenario: Root admitted worker starts under distinct process policy
- **WHEN** actual source-selected process declarations and retained root task or health admissions join the current protected worker service/namespace/runtime/home generation
- **THEN** a fresh one-use root-process proof is consumed before the exact managed worker effect while the local socket user gains no process or unrelated effect capability

#### Scenario: Process source or issuer is incomplete
- **WHEN** any of the six reviewed operation targets, exact rule/handler/schema joins, current root admission or consumed proof is missing, foreign, altered or stale
- **THEN** active enrollment/start fails with the exact prerequisite and no fabricated usercaps, relaxed validation, uid0 allow or copied launchproof substitute

## ADDED Requirements

### Requirement: Actual root process source and health home proof joins
The installer SHALL use planning/root-service-process-proof-joins-v236b.json for exact retained primary health-home custody, current runtime policy/epoch and distinct fresh published declaration proof. Service generation schema4 SHALL preserve exact v225 schema3 remote semantics and add only the strict root process array.

#### Scenario: Health and runtime declarations are current
- **WHEN** actual retained health admission joins the published primaryhermes/default row, held owned home and current PM runtime, and current adopted source declarations are verified through held installed members
- **THEN** the root binds those exact proofs to its process admission and manager use, with current policy adapter revision and service startup epoch independently verified

#### Scenario: Restart or schema conflicts cannot reuse setup proof
- **WHEN** a reader restarts, a setup seal/lease expired, a homehash has no actual producer or schema3 is used for root process rows
- **THEN** the reader requires a fresh current published declaration/home source proof and exact schema4 validation or remains unavailable; no reconstructed seal, inferred hash or altered legacy digest is accepted

## ADDED Requirements

### Requirement: Independent read-only cold declaration custody
The installer SHALL apply planning/root-service-process-cold-source-custody-v236b.json to verify signed adopted choice and installed declaration custody before full strict parsing, then repeat ordinary real runtime validation before all serving and effects.

#### Scenario: Current cold sources permit strict runtime composition
- **WHEN** current held core, release, existing protected key, signed adoption and revocation journals and declaration members verify through independent read-only custody
- **THEN** the ordinary strict parser validates the published declaration, and the genuine dormant runtime repeats its service-bound validators before activation

#### Scenario: A construction or currentness gap denies activation
- **WHEN** source custody or ordinary runtime validation fails or changes between phases
- **THEN** partial custody is closed and no socket, native unit, task, health, root or user effect is enabled; no fake service or reconstructed setup proof is accepted


## ADDED Requirements

### Requirement: Preactive remote output receipt pipeline
The installer SHALL publish and materialize remote build outputs only through the exact v239 executor-retained terminal proof, selected role adapter observation and current owned output/data-root custody, without unrelated enrolled profile substitution.

#### Scenario: Genuine managed role build completes
- **WHEN** the exact retained role plan and runner terminal prove successful cleanup and independent output readback passes
- **THEN** the root MAY publish immutable package/attestation and materialization receipts for existing v209/v202 and v225 joins

#### Scenario: Metadata cannot prove a build
- **WHEN** a caller supplies result fields, output rows or foreign/expired receipt identities without exact current issuer membership
- **THEN** publication and runnable receipt issuance SHALL deny and preserve owned rollback boundaries


### Requirement: Remote enrollment reservation and prepared network source
The installer SHALL derive the v202 aggregate remote identity and prepared network policy only from the exact v239 root-issued same-transaction reservation and current source/NSS role receipts. Actual v225 kernel lease proof SHALL remain separate and required before startup.

#### Scenario: Prepared network has source authority
- **WHEN** exact current root choice/config/role definitions and all three role/NSS receipts join the retained reservation and policy source
- **THEN** the root MAY emit the fixed policy rows for compiler publication without claiming observed kernel namespace or future active generation

#### Scenario: Caller strings are not enrollment proof
- **WHEN** hostname, supplied IDs or incomplete role/policy evidence replaces the root reservation
- **THEN** aggregate issuance SHALL deny without creating a runnable network or active identity
