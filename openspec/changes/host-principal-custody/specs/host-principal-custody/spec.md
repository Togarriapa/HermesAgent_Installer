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

