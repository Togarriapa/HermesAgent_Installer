## ADDED Requirements

### Requirement: Self-contained owned source bundle (RB01)

Package the complete pristine tracked Resources snapshot, all eight catalog roots and catalog/quality/schema/validator/materializer/supporting files at the pinned revision. Installation and repair SHALL not fetch or require the Resources upstream repository.

#### Scenario: RB01 observable operation

- **WHEN** upstream DNS/network unavailable during install
- **THEN** verify bundle digests and generate native artifacts using only packaged Resources input; no Resources HTTP/git request

### Requirement: Native materialization and discovery (RB02)

Compile every valid profile, skill, plugin, MCP, bundle, channel, cron and webhook into the installed Hermes native mechanism or an explicit reviewed operational adapter. SHALL preserve the all-item source-to-native crosswalk; YAML copies and inventory rows alone SHALL not count as materialization.

#### Scenario: RB02 observable operation

- **WHEN** all 692 declarations are processed
- **THEN** every item has native destination/adapter identity and discoverability evidence or exact incomplete reason; profiles/skills have actual native discovery and selected workflow invocation

### Requirement: Compatible full-content enrichment (RB03)

Resolve referenced pinned projects to compatible full content, helpers, assets and hooks, preserving licenses/provenance and installing actual entrypoints with declared dependencies. SHALL wire that content into profile/orchestrator workflows rather than paste reference summaries.

#### Scenario: RB03 observable operation

- **WHEN** a referenced skill uses a relative helper and runtime hook
- **THEN** native invocation resolves preserved helper/assets, exercises actual hook and reports its effect through the owning workflow; incompatible or unlicensed reference is incomplete

### Requirement: Ownership-safe generations and restoration (RB04)

Stage source, enrichment and native generations separately from user/private overlays; SHALL reject path escapes, preserve unrelated existing content, quarantine conflicting or permission-expanding overlays and restore the last working generation atomically.

#### Scenario: RB04 observable operation

- **WHEN** enrichment or health verification fails after staging against an existing customized installation
- **THEN** previous generation and private/user bytes remain intact; staged incomplete artifacts do not become enabled; retry and restore reproduce the crosswalk

### Requirement: Honest completion and offline acceptance (RB05)

SHALL distinguish bundled, validated, materialized, discovered, authenticated, functional, enabled and target-verified states for every resource and enrichment. All required dependencies/accounts remain incomplete until genuinely verified. Full completion SHALL require meaningful native workflows and all applicable acceptance, not copied/import metadata.

#### Scenario: RB05 observable operation

- **WHEN** required MCP account is absent but its declaration and configuration exist
- **THEN** resource and full-compliance remain incomplete with scoped next step; no fabricated native operation, account success or missing-required-as-optional status

### Requirement: Fixed read-only registry discovery (RB06)

Implement the bundled mcp-registry and agent37-discovery plugins through host-authorized fixed registry.read metadata operations. SHALL bind public query provenance, exact service/action and bounded parameters before network bytes; deny caller URL/method, redirects, publication, installation and execution. Discovery results remain untrusted and never activate resources.

#### Scenario: Authorized bounded metadata discovery

- **WHEN** selected native discovery plugin submits an authorized public metadata query
- **THEN** root performs only enrolled bounded read, returns untrusted metadata, and rejects private/unknown query, arbitrary destination and activation

### Requirement: Protected selected event and bounded bundle jobs (RB07)

Selected cron, webhook, channel and bundle resources SHALL use protected enrollment and authenticated event provenance before effects. Root SHALL admit bounded immutable jobs and issue fresh reduced-scope grants separately for every child/attempt, preserving complete source lineage, recipient scope, private routing, concurrency limits and generation revocation. Registration SHALL not auto-enable resources.

#### Scenario: Authenticated selected event job

- **WHEN** a selected recurring/webhook/channel event starts a multi-child workflow
- **THEN** root authenticates event and current selection, consumes one job admission, issues fresh scoped per-child grants and denies replay/unselected/private-route/overlimit/stale generation before effects

### Requirement: RB08 Protected original plugin effects
The installer SHALL enforce the pinned manifest obligations through protected finite selected action schemas, immutable handler identity, exact operation/target grants, current private source lineage and scoped root credential references. External writes SHALL require independent runtime task/user-order authority and required one-shot human confirmation of the exact final payload; durable duplicate/ambiguity journals SHALL prevent blind retries.

#### Scenario: Forged or ambiguous plugin effect
- **WHEN** a native plugin supplies an unenrolled action, altered digest, caller confirmation, sibling account, consumed grant or ambiguous prior write
- **THEN** reject before backend bytes, retain truthful state and require the exact missing scope, reconciliation or fresh authority without weakening original functionality.

### Requirement: Protected native composition
The installer SHALL bind actual native producer package/adapter closure through immutable root-selected profile generation and observed issuer channels, and SHALL apply the same protected route normalization policy before final request digest and gateway effect. Caller registration/labels SHALL not establish provenance.

#### Scenario: Mutable package or divergent normalization
- **WHEN** native closure, peer generation, issuer provenance or route-normalized final payload differs from protected enrollment
- **THEN** deny before effect bytes and retain exact incomplete implementation/native evidence state.

### Requirement: RB08 Selected facade argument schemas
The installer SHALL enforce the finite source-bound Epic and voice facade action schemas with extra fields forbidden and root-owned lifecycle/session/artifact references.

#### Scenario: Caller asserts accepted Epic or microphone permission
- **WHEN** caller supplies lifecycle/session claims without current root verified receipt
- **THEN** reject before deletion, microphone bytes or backend dispatch.

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

### Requirement: Protected voice result receipts
The installer SHALL expose only strict bounded transcript/source receipt or owned audio artifact receipt fields; raw PCM, paths, URLs and credentials SHALL not appear in tool results.

#### Scenario: Voice service returns raw or extra fields
- **WHEN** result violates selected strict receipt schema or lacks actual root-observed provenance
- **THEN** reject result and preserve exact incomplete action state without leaking raw capture.

### Requirement: Selected Hermes and resource runtime recipes
The installer SHALL resolve fixed parameter-free Hermes stage/health recipes and active protected resource job DAG/source/backend joins, retaining official PM runtime and actual functional health evidence.

#### Scenario: Caller supplies bootstrap paths or source-only health
- **WHEN** caller overrides recipe/roots/argv or only inventory/status exists without actual selected native workflow
- **THEN** reject overrides or keep functional readiness incomplete, preserve prior generation and exact resume reason.

### Requirement: Selected backend and actual gateway role bindings
The installer SHALL resolve protected resource backend/body recipe/action/source/consent scope before each child effect and SHALL verify actual launched gateway role against explicit HI13 protected profile-role association.

#### Scenario: Legacy backend metadata or unobserved gateway role
- **WHEN** only declared backend/role metadata exists without current root selected effect/actual launch proof
- **THEN** deny backend/admission before bytes and retain exact incomplete implementation/native evidence.

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

### Requirement: Resource profile task terminal protocol

The implementation SHALL enforce this protocol. RB-T08 / EV-RB07: use the exact root task runner protocol in planning/protected-resource-job-contract.json, including one-shot admitted UTF8 stdin plus EOF, actual terminal validation and result-capsule lineage; launch or fixture status cannot establish completion.

#### Scenario: Missing concrete runtime proof
- **WHEN** the exact protocol or current kernel/native observations are unavailable
- **THEN** the affected task remains incomplete and no fixture or mount-only evidence establishes acceptance.

### Requirement: Native health and typed task proof

The implementation SHALL enforce the applicable native health receipt and typed task admission contracts. Use planning/protected-lifecycle-control-contract.json native_health_receipt for actual native health and planning/protected-resource-job-contract.json typed_admission/service_methods/recipe_domain for RB-T08. Original tasks/acceptance remain pending.

#### Scenario: Status without native result
- **WHEN** only source/status/exit evidence is available
- **THEN** functional health and task result acceptance remain incomplete.

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

### Requirement: Selected task result artifact validation

The root SHALL validate actual complete task stdout using its exact selected protected result schema before result capsule or DAG advancement. Generic text or exit0 SHALL NOT create authoritative output fields.

#### Scenario: Unregistered output schema
- **WHEN** output lacks a current registered finite schema validator or violates its exact bounds
- **THEN** completion fails and no success capsule advances dependent nodes.

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

### Requirement: Prepared native materialization receipt closure

Root materialization SHALL occur under verified prepared transaction and exact fixed CAS output roles before runnable activation. HERMES_HOME SHALL equal selected service_home_root_id. Resources source proof SHALL remain independent from Hermes source proof.

#### Scenario: Source or role substitution
- **WHEN** a native output receipt substitutes another source or role
- **THEN** active record publication is denied.

### Requirement: Actual task native and credential closure

Successful task completion SHALL bind actual native execution receipts and distinct service/resource epochs. Webhook verification SHALL use explicit protected placeholder-to-vault-role mapping.

#### Scenario: Native or credential mapping absence
- **WHEN** the current exact native or scoped credential join is missing
- **THEN** no successful task capsule or authenticated webhook event is fabricated.

### Requirement: Existing observation assembly joins
The implementation SHALL apply the exact root registry, principal-selection and protected observation joins relevant to this change in `plans/amendments/2026-10-09-final-observation-assembly-v31.md`.

#### Scenario: Static selection lacks actual runtime proof
- **WHEN** an actual current role, display, source event or terminal execution receipt is absent
- **THEN** the affected observation remains pending and no caller claim or catalog presence substitutes for runtime evidence

### Requirement: Installed closure and native construction joins
The implementation SHALL use the applicable exact root release and native assembly joins in the v33 amendment before activating selected runtime behavior.

#### Scenario: First input precedes provider pending pair
- **WHEN** the selected actual producer receives root observed initial input before a provider pair exists
- **THEN** root resolves the target through actual execution custody and loader proof, without guessing a pending pair or trusting worker selectors

### Requirement: Noncircular root observation receipts
The implementation SHALL use exact v35 initial identity and terminal companion joins applicable to this change.

#### Scenario: Companion proof follows immutable terminal
- **WHEN** root custody has issued the actual terminal receipt
- **THEN** root native registry binds a separate verified companion receipt without fabricating or modifying custody evidence

### Requirement: Noncircular immutable first-stage publication
The implementation SHALL use the exact applicable v36 release roles, immutable policy publication and pre-event root ingress custody joins.

#### Scenario: First ingress has no source receipt yet
- **WHEN** root resolves selected ingress controller custody
- **THEN** actual process/module/selected ingress proof is checked independently before atomically minting the source receipt and event handle

### Requirement: Protected native candidate index delivery
The implementation SHALL verify the selected fixed candidate-index closure member through exact entrypoint manifest and package pins before native discovery.

#### Scenario: Ordinary cache has a matching tool name
- **WHEN** no verified selected candidate index exists
- **THEN** native protected discovery remains pending without adopting the cache schema or caller metadata
