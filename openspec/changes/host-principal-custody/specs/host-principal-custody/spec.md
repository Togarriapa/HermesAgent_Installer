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
