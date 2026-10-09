# bootstrap-desktop Delta

## Purpose

Fresh/adopted supported ARM64 install, official Agent/Desktop version resolution, native user-session launch and truthful fallback. This contract preserves the full requested scope and separates functional evidence from pending hardware/account readiness.

## ADDED Requirements

### Requirement: R0023 source line 55
The installer SHALL satisfy this obligation: Build an installer for this machine:

#### Scenario: R0023 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Build an installer for this machine:
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0023 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0024 source line 57
The installer SHALL satisfy this obligation: Raspberry Pi 5 with 16 GB RAM.

#### Scenario: R0024 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Raspberry Pi 5 with 16 GB RAM.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0024 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0025 source line 58
The installer SHALL satisfy this obligation: 1 TB SSD. Detect its actual usable capacity, free space, filesystem, mount, and connection type.

#### Scenario: R0025 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** 1 TB SSD. Detect its actual usable capacity, free space, filesystem, mount, and connection type.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0025 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0026 source line 59
The installer SHALL satisfy this obligation: Google Coral TPU. Detect whether it is USB or PCIe/M.2 before choosing drivers.

#### Scenario: R0026 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Google Coral TPU. Detect whether it is USB or PCIe/M.2 before choosing drivers.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0026 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0027 source line 60
The installer SHALL satisfy this obligation: A supported 64-bit Linux installation, preferably Raspberry Pi OS with a desktop when compatible with the selected dependencies.

#### Scenario: R0027 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** A supported 64-bit Linux installation, preferably Raspberry Pi OS with a desktop when compatible with the selected dependencies.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0027 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0028 source line 62
The installer SHALL satisfy this obligation: Install Hermes Desktop and its Hermes Agent backend, preinstall my profiles and skills, and integrate the requested projects and MCP connections to the extent their real upstream capabilities and my accounts permit.

#### Scenario: R0028 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Install Hermes Desktop and its Hermes Agent backend, preinstall my profiles and skills, and integrate the requested projects and MCP connections to the extent their real upstream capabilities and my accounts permit.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0028 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0029 source line 64
The installer SHALL satisfy this obligation: The result must work for both a fresh supported system and a machine with an existing installation. Preserve existing user data, configurations, credentials, memories, and unrelated services. Detect existing Home Assistant, model servers, speech services, and occupied ports before making changes.

#### Scenario: R0029 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** The result must work for both a fresh supported system and a machine with an existing installation. Preserve existing user data, configurations, credentials, memories, and unrelated services. Detect existing Home Assistant, model servers, speech services, and occupied ports before making changes.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0029 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0029 Adoption conflict preserves unowned service
- **WHEN** an existing Home Assistant service occupies the requested port and its config contains a sentinel not owned by this installer
- **THEN** plan SHALL report the collision and an explicit alternate/configure-later route; install SHALL NOT stop/replace that service, change its sentinel bytes or count it as installer-owned

### Requirement: R0030 source line 64
The installer SHALL satisfy this obligation: Do not reimage the machine, format storage, or replace an existing service as a side effect of routine installation.

#### Scenario: R0030 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Do not reimage the machine, format storage, or replace an existing service as a side effect of routine installation.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0030 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0031 source line 66
The installer SHALL satisfy this obligation: Use English for the installer and documentation. Default new installer-owned schedules and displayed times to `Europe/Lisbon`, while preserving an existing host timezone unless the user selects a change.

#### Scenario: R0031 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Use English for the installer and documentation. Default new installer-owned schedules and displayed times to `Europe/Lisbon`, while preserving an existing host timezone unless the user selects a change.
- **AND** evidence SHALL demonstrate the observable outcome using Config/wizard fixture asserts English output, Europe/Lisbon new schedule/display default and unchanged existing host timezone unless explicitly selected

#### Scenario: R0031 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0033 source line 74
The installer SHALL satisfy this obligation: Use NousResearch/hermes-agent (https://github.com/NousResearch/hermes-agent) as the canonical upstream. Read its current Desktop README (https://github.com/NousResearch/hermes-agent/blob/main/apps/desktop/README.md), build instructions, installation guide, and platform support (https://hermes-agent.nousresearch.com/docs/getting-started/platform-support).

#### Scenario: R0033 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Use NousResearch/hermes-agent (https://github.com/NousResearch/hermes-agent) as the canonical upstream. Read its current Desktop README (https://github.com/NousResearch/hermes-agent/blob/main/apps/desktop/README.md), build instructions, installation guide, and platform support (https://hermes-agent.nousresearch.com/docs/getting-started/platform-support).
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0033 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0034 source line 76
The installer SHALL satisfy this obligation: The research snapshot lists Linux aarch64 as a supported agent platform and documents `hermes desktop` for building/launching the official GUI against an existing install. It also says Linux desktop release packaging is currently disabled. Therefore:

#### Scenario: R0034 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** The research snapshot lists Linux aarch64 as a supported agent platform and documents `hermes desktop` for building/launching the official GUI against an existing install. It also says Linux desktop release packaging is currently disabled. Therefore:
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0034 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0035 source line 78
The installer SHALL satisfy this obligation: Prefer an official compatible release if one exists at implementation time; otherwise implement and verify the official ARM64 source-build path.

#### Scenario: R0035 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Prefer an official compatible release if one exists at implementation time; otherwise implement and verify the official ARM64 source-build path.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0035 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0036 source line 79
The installer SHALL satisfy this obligation: Resolve Agent and Desktop versions separately when upstream releases them separately.

#### Scenario: R0036 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Resolve Agent and Desktop versions separately when upstream releases them separately.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0036 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0037 source line 80
The installer SHALL satisfy this obligation: Verify the native window opens under the actual graphical session, connects to the intended backend, displays imported resources, and completes a conversation.

#### Scenario: R0037 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Verify the native window opens under the actual graphical session, connects to the intended backend, displays imported resources, and completes a conversation.
- **AND** evidence SHALL demonstrate the observable outcome using On the actual authorized Pi graphical session, probe the official native window, intended backend identity, imported resources and synthetic Hello conversation; fixture GUI launch/control tests prove orchestration only and missing Pi remains pending

#### Scenario: R0037 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0037 Wrong graphical user or disabled sandbox
- **WHEN** the Desktop launch fixture has no selected-user display session, or its only successful launcher requires --no-sandbox
- **THEN** the adapter SHALL report native Desktop unavailable, SHALL NOT start a root/headless or unsandboxed native GUI, and SHALL preserve an agent/browser fallback with separate status; the native-window acceptance remains pending/failed

### Requirement: R0038 source line 81
The installer SHALL satisfy this obligation: Run the desktop under the intended desktop user. Use appropriate user-session startup; a headless system service is not a graphical login session.

#### Scenario: R0038 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Run the desktop under the intended desktop user. Use appropriate user-session startup; a headless system service is not a graphical login session.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0038 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0039 source line 82
The installer SHALL satisfy this obligation: If native Desktop is blocked, retain a working supported agent and offer its browser interface or a documented remote-Desktop connection as a clearly labeled fallback. Do not label that fallback “Desktop installed.” Record the exact failure and recovery route.

#### Scenario: R0039 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** If native Desktop is blocked, retain a working supported agent and offer its browser interface or a documented remote-Desktop connection as a clearly labeled fallback. Do not label that fallback “Desktop installed.” Record the exact failure and recovery route.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0039 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0040 source line 83
The installer SHALL satisfy this obligation: Do not silently substitute a community fork, an unrelated Hermes application, or an unofficial Python package.

#### Scenario: R0040 fulfilled constraint
- **WHEN** the installer plans a fresh or adopted ARM64 Linux fixture with recorded OS, disk, existing-service and graphical-user facts
- **THEN** Do not silently substitute a community fork, an unrelated Hermes application, or an unofficial Python package.
- **AND** evidence SHALL demonstrate the observable outcome using User-session/official-source build and fallback fixtures assert the exact obligation; native window/backend/resource/tool/cancellation proof is separately required on authorized graphical Pi

#### Scenario: R0040 unavailable or failed prerequisite
- **WHEN** the host is x86_64, the selected graphical session is absent, or an existing unowned service occupies the intended port
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: Selected Hermes and resource runtime recipes
The installer SHALL resolve fixed parameter-free Hermes stage/health recipes and active protected resource job DAG/source/backend joins, retaining official PM runtime and actual functional health evidence.

#### Scenario: Caller supplies bootstrap paths or source-only health
- **WHEN** caller overrides recipe/roots/argv or only inventory/status exists without actual selected native workflow
- **THEN** reject overrides or keep functional readiness incomplete, preserve prior generation and exact resume reason.

### Requirement: Protected lifecycle provision and control
The installer SHALL derive enrollment provision and finite process control effects from actual trusted root transaction/peer/owned livehandle state, preserve first-snapshot trust provenance and atomic recoverable generation changes, and SHALL not accept worker bearer targets or ready assertions.

#### Scenario: Forged bootstrap intent or stale process control
- **WHEN** caller supplies unregistered bootstrap intent, claimed roots/identity or stale/sibling control handle
- **THEN** reject before effects, preserve prior generation/private state and require actual root target/ownership evidence.

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

### Requirement: Installed root first setup acquisition

First setup SHALL verify the installed root actor/plan catalog and acquire selected artifacts through the root-local transaction-bound CAS fetch contract without requiring an active worker.

#### Scenario: Unverified setup actor or source
- **WHEN** actor closure, plan, catalog or source receipt verification fails
- **THEN** provisioning remains incomplete without activating a worker profile.

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

### Requirement: Protected setup store and bounded probe response

The implementation SHALL resolve the protected setup catalog/store and validate the exact bounded private probe response against current root admission and actual observations.

#### Scenario: Untrusted injected catalog or response
- **WHEN** selected artifact custody or probe envelope/observation binding differs
- **THEN** provisioning/readiness cannot be marked complete.

### Requirement: Selected installed bootstrap policy

The root factory SHALL resolve the exact installed reviewed bootstrap policy and actual transaction-bound receipt fields before publishing active records.

#### Scenario: Missing executable receipt
- **WHEN** an active template binding lacks an actual verified runnable artifact receipt
- **THEN** no active service record is synthesized from defaults or source archive identity.

### Requirement: Non-circular functional health activation

Runnable authority publication SHALL require actual artifact receipts; functional enablement SHALL separately require actual passed health against that committed generation.

#### Scenario: Runnable record without functional health
- **WHEN** runnable custody exists but health has not passed
- **THEN** functional enablement and installation acceptance remain pending.

### Requirement: Concrete first-stage policy publication

The installed root entrypoint SHALL compile and publish reviewed closed-template policy/catalog bytes from actual selected release/NSS/ownedroot observations before invoking the policy factory. HERMES_HOME SHALL use explicit service data root/hermes.

#### Scenario: First install without policy files
- **WHEN** no policy generation exists
- **THEN** verified stage0 publication constructs it without an active worker or caller authority rows.

### Requirement: Prepared native materialization receipt closure

Root materialization SHALL occur under verified prepared transaction and exact fixed CAS output roles before runnable activation. HERMES_HOME SHALL equal selected service_home_root_id. Resources source proof SHALL remain independent from Hermes source proof.

#### Scenario: Source or role substitution
- **WHEN** a native output receipt substitutes another source or role
- **THEN** active record publication is denied.

### Requirement: Closed first-stage source template

The compiler SHALL use the exact pinned closed template and finite actual root fact bindings; prepared stage SHALL not require an active worker.

#### Scenario: Missing runtime or identity binding
- **WHEN** a required root binding has not been actually verified
- **THEN** no active record is synthesized and preparation reports exact prerequisite.

### Requirement: Existing observation assembly joins
The implementation SHALL apply the exact root registry, principal-selection and protected observation joins relevant to this change in `plans/amendments/2026-10-09-final-observation-assembly-v31.md`.

#### Scenario: Static selection lacks actual runtime proof
- **WHEN** an actual current role, display, source event or terminal execution receipt is absent
- **THEN** the affected observation remains pending and no caller claim or catalog presence substitutes for runtime evidence

### Requirement: Root observed first setup principal selection
The compiler SHALL resolve selected authenticated principal receipt through the root setup registry before publishing concrete identity rows.

#### Scenario: No active worker exists during first setup
- **WHEN** actual selected authenticated identity and dedicated NSS allocation are verified in the root setup transaction
- **THEN** the compiler binds the exact principal fields without requiring a previous active worker profile or fabricating a principal from operator UID

### Requirement: Installed closure and native construction joins
The implementation SHALL use the applicable exact root release and native assembly joins in the v33 amendment before activating selected runtime behavior.

#### Scenario: First input precedes provider pending pair
- **WHEN** the selected actual producer receives root observed initial input before a provider pair exists
- **THEN** root resolves the target through actual execution custody and loader proof, without guessing a pending pair or trusting worker selectors

### Requirement: Complete frozen baseline receipt digest
The deployment verifier SHALL distinguish the complete frozen-tree SHA256 map from the original160 snapshot file manifest.

#### Scenario: Frozen metadata is present
- **WHEN** computing baseline_tree_sha256
- **THEN** every regular frozen file including hashes.json is included, while original160 snapshot entries are checked separately against their bytes

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

### Requirement: Official committed PM runtime identity
The implementation SHALL resolve the exact selected official committed PM dependency environment through the v37 root runtime receipt.

#### Scenario: PM source or sync receipt alone exists
- **WHEN** actual selected runtime executable identity and source/lock/tool joins have not been verified
- **THEN** runtime activation and functional health remain pending, without substituting a source archive digest or system Python

### Requirement: Protected native candidate index delivery
The implementation SHALL verify the selected fixed candidate-index closure member through exact entrypoint manifest and package pins before native discovery.

#### Scenario: Ordinary cache has a matching tool name
- **WHEN** no verified selected candidate index exists
- **THEN** native protected discovery remains pending without adopting the cache schema or caller metadata

### Requirement: Root initial compilation precedes policy session
The implementation SHALL create and verify the exact v42 internal stage0 compilation context without requiring a policy-dependent setup session.

#### Scenario: No bootstrap policy exists yet
- **WHEN** the actual installed root actor compiles initial selected policy
- **THEN** root internal stage0 custody authorizes fixed compilation and one-use publication handoff before normal setup session creation

### Requirement: Exact first selection and live input target
The implementation SHALL enforce v43 exact first-publication predecessor and admitted-source plus actual-process target join.

#### Scenario: Admission exists before process launch
- **WHEN** no actual managed producer and loader proof exists
- **THEN** root cannot deliver initial source context or write task stdin by guessing a PID or pending bridge

### Requirement: Root initial input before single task stdin effect
The implementation SHALL follow v46 concrete internal coordinator sequence during the single selected launch effect.

#### Scenario: Initial source delivery fails
- **WHEN** actual loader/input custody cannot produce a verified receipt before original deadline
- **THEN** custody closes the owned unit before stdin and never infers source after EOF

### Requirement: Root secure initial identity intake
The implementation SHALL bind the exact v47 masked intake and policy selection to the actual root stage0 transaction.

#### Scenario: User journal contains a credential reference
- **WHEN** it has no verified root vault custody/scope receipt
- **THEN** it cannot authorize identity observation or policy publication and exact secure intake remains pending

### Requirement: Verified initial identity template revision
The implementation SHALL resolve the exact v49 immutable identity template through the actual root installed deployment closure.

#### Scenario: Only a session digest exists
- **WHEN** identity policy revision is needed
- **THEN** root resolves actual verified template bytes rather than inventing a module constant or trusting a caller revision

### Requirement: Explicit root registry phases
The implementation SHALL distinguish v50 draft/bound identity selection and evidence lookup/one-use stdin consumption.

#### Scenario: Source is queued but not delivered
- **WHEN** root validates initial input receipt
- **THEN** queued source alone cannot permit stdin and actual producer delivery/current binding is required

### Requirement: Actual native materialization output CAS
The implementation SHALL apply v51 exact source and compiled artifact role/closure joins.

#### Scenario: Compiler produces a source and compiled digest
- **WHEN** importing actual generated output into root CAS
- **THEN** distinct byte/tree domains and transaction roles remain verified without substituting planning or source hashes for executable output

### Requirement: Actual producer initial source take
The implementation SHALL use v52 fixed peer-authenticated no-selector source delivery before selected task stdin.

#### Scenario: Initial peer does not know a receipt identifier
- **WHEN** actual rootselected initial input has been captured
- **THEN** protected endpoint resolves the unique matching execution input for that peer without exposing metadata in the prompt or requiring a pending provider pair

### Requirement: Verified release plan and active compilation
The implementation SHALL apply v53 exact source template/deployed plan and active receipt compilation joins.

#### Scenario: Runtime outputs become available after preparation
- **WHEN** publishing runnable active policy
- **THEN** root active compiler verifies actual current runtime/materialization/identity receipts rather than using an initial-only claim or caller authority rows

### Requirement: Live selected native health control
The installer SHALL begin native health observation from a root-retained live selected process control before fixture input, retaining actual native events and a separate semantic health receipt.

#### Scenario: Terminal-only health presentation
- **WHEN** only stdout or exit status exists without the required live native event closure
- **THEN** health remains incomplete and functional acceptance is not asserted

### Requirement: Exact native output byte encoding
The installer SHALL bind generated native CAS artifacts to the fixed reviewed role encoding, source/member receipts and distinct archive/member-tree digests.

#### Scenario: Alternate or unverified native output
- **WHEN** generated output uses unknown archive members, alternate encoding or mismatched source/member hashes
- **THEN** activation is denied and native acceptance remains pending

### Requirement: Distinct native closure and archive digests
The installer SHALL preserve the canonical closure_files tree digest for compiled_closure_sha256 and use separate archive artifact digest for CAS bytes.

#### Scenario: Archive hash substituted for closure tree
- **WHEN** a package substitutes archive bytes SHA for the selected compiled tree hash
- **THEN** mount and binder verification reject the mismatched digest domain

### Requirement: Distinct native generation joins
The installer SHALL resolve process and native package generations separately and preserve exact candidate index identity across receipts and manifest.

#### Scenario: Generation domain substitution
- **WHEN** an observer uses package generation as live process generation
- **THEN** peer proof admission denies the inconsistent join

### Requirement: Fixed selected display and loopback startup
The installer SHALL launch only enrolled official Desktop/display/gateway recipes with exact Xauthority mount and private loopback role/port bindings.

#### Scenario: Ambient display or broad network substitution
- **WHEN** a worker supplies display credentials, arbitrary port or unenrolled network role
- **THEN** startup or connection denies before app bytes and remote acceptance remains pending

### Requirement: Actual root key and selected catalog authority
The installer SHALL derive first-publication key identity and authenticated selected catalog reads from actual root custody/session receipts, preserving distinct source producer roles.

#### Scenario: Generic bootstrap authority substituted
- **WHEN** bootstrap enrollment authorization is presented as Composio catalog or channel effect permission
- **THEN** the separate selected catalog authority denies the substitution
