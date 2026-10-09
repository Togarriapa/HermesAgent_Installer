# managed-lifecycle Delta

## Purpose

Wizard/CLI, isolated environments, ownership-safe idempotent checkpoints, supervised services, rollback, backups and uninstall. This contract preserves the full requested scope and separates functional evidence from pending hardware/account readiness.

## ADDED Requirements

### Requirement: R0141 source line 253
The installer SHALL satisfy this obligation: Provide a simple entry point, such as `./install.sh`, backed by maintainable modular code. A thin shell bootstrap plus typed Python orchestration is a reasonable default; use another stack only if it materially improves reliability. Avoid a single giant shell script.

#### Scenario: R0141 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Provide a simple entry point, such as `./install.sh`, backed by maintainable modular code. A thin shell bootstrap plus typed Python orchestration is a reasonable default; use another stack only if it materially improves reliability. Avoid a single giant shell script.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0141 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0142 source line 255
The installer SHALL satisfy this obligation: The wizard must handle fresh install, existing-install adoption, component selection, storage/model paths, account setup, diagnostics, and recovery. Reuse Hermes Desktop settings where practical. A second full management application is not required; a clear terminal wizard and lifecycle CLI are sufficient.

#### Scenario: R0142 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** The wizard must handle fresh install, existing-install adoption, component selection, storage/model paths, account setup, diagnostics, and recovery. Reuse Hermes Desktop settings where practical. A second full management application is not required; a clear terminal wizard and lifecycle CLI are sufficient.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0142 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0143 source line 257
The installer SHALL satisfy this obligation: For every required setting, show what it is, why it is needed, the official setup link, concrete steps to obtain it, and a connection test. Collect secrets through secure input and supported credential storage. Allow “configure later” and resume without repeating successful setup. Explain account/billing prerequisites before asking for a key.

#### Scenario: R0143 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** For every required setting, show what it is, why it is needed, the official setup link, concrete steps to obtain it, and a connection test. Collect secrets through secure input and supported credential storage. Allow “configure later” and resume without repeating successful setup. Explain account/billing prerequisites before asking for a key.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0143 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0144 source line 259
The installer SHALL satisfy this obligation: Provide interactive and documented non-interactive operation with a validated config file, secret references, useful exit codes, and readable/JSON output. Implement these lifecycle capabilities through clear commands:

#### Scenario: R0144 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Provide interactive and documented non-interactive operation with a validated config file, secret references, useful exit codes, and readable/JSON output. Implement these lifecycle capabilities through clear commands:
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0144 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0145 source line 261
The installer SHALL satisfy this obligation: Plan/dry-run; install; resume; status; doctor; verify.

#### Scenario: R0145 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Plan/dry-run; install; resume; status; doctor; verify.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0145 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0146 source line 262
The installer SHALL satisfy this obligation: Configure/test a provider or MCP; select a memory provider; resolve a source URL.

#### Scenario: R0146 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Configure/test a provider or MCP; select a memory provider; resolve a source URL.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0146 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0147 source line 263
The installer SHALL satisfy this obligation: Enable/disable/start/stop a component; inspect redacted logs.

#### Scenario: R0147 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Enable/disable/start/stop a component; inspect redacted logs.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0147 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0148 source line 264
The installer SHALL satisfy this obligation: Check/apply updates; rollback; backup/restore; uninstall.

#### Scenario: R0148 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Check/apply updates; rollback; backup/restore; uninstall.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0148 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0149 source line 266
The installer SHALL satisfy this obligation: Preflight must detect OS/distribution/version, ARM64 architecture, available RAM, graphical session, user/sudo context, package-manager locks, network/DNS/TLS, disk capacity, existing installs, services, ports, and device access. Select supported dependency versions; do not globally replace the system Python or Node to satisfy one component.

#### Scenario: R0149 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Preflight must detect OS/distribution/version, ARM64 architecture, available RAM, graphical session, user/sudo context, package-manager locks, network/DNS/TLS, disk capacity, existing installs, services, ports, and device access. Select supported dependency versions; do not globally replace the system Python or Node to satisfy one component.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0149 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0150 source line 268
The installer SHALL satisfy this obligation: Use isolated environments for incompatible Python/Node/native dependencies. Prefer native ARM64 packages; use containers only where their compatible images and isolation justify them. Check native extensions, browser binaries, shared libraries, and transitive dependencies. Do not silently use x86 emulation as the Pi solution.

#### Scenario: R0150 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Use isolated environments for incompatible Python/Node/native dependencies. Prefer native ARM64 packages; use containers only where their compatible images and isolation justify them. Check native extensions, browser binaries, shared libraries, and transitive dependencies. Do not silently use x86 emulation as the Pi solution.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0150 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0151 source line 270
The installer SHALL satisfy this obligation: Keep application data, model files, component environments, source snapshots, logs, backups, and private overlays in documented locations. Use a single configuration source of truth and generated service definitions. Avoid writing through symlinks outside managed roots or overwriting existing user settings.

#### Scenario: R0151 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Keep application data, model files, component environments, source snapshots, logs, backups, and private overlays in documented locations. Use a single configuration source of truth and generated service definitions. Avoid writing through symlinks outside managed roots or overwriting existing user settings.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0151 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0151 Managed path symlink escape denied
- **WHEN** a path inside the managed root is a symlink to an unrelated outside directory containing a sentinel and install/restore attempts to write through it
- **THEN** the ownership/filesystem layer SHALL reject the write before following the symlink, preserve outside sentinel bytes and report the unsafe path with an actionable selected-root next step

### Requirement: R0152 source line 272
The installer SHALL satisfy this obligation: Use appropriate systemd/user-session supervision with startup ordering, restart limits, health probes, timeouts, log rotation, and clean shutdown. Detect already-managed services to prevent duplicate listeners, model processes, jobs, and memory workers. Start with conservative, configurable concurrency—for example, one browser worker and a small cloud-agent pool—and tune from measurements.

#### Scenario: R0152 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Use appropriate systemd/user-session supervision with startup ordering, restart limits, health probes, timeouts, log rotation, and clean shutdown. Detect already-managed services to prevent duplicate listeners, model processes, jobs, and memory workers. Start with conservative, configurable concurrency—for example, one browser worker and a small cloud-agent pool—and tune from measurements.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0152 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0153 source line 274
The installer SHALL satisfy this obligation: Installations must be idempotent and resumable, with process locks and per-step checkpoints. Stage downloads, validate artifacts, and atomically switch compatible generations. Upgrades must preview relevant config/schema/permission changes and preserve user modifications. Take consistent database backups and support version-compatible restoration.

#### Scenario: R0153 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Installations must be idempotent and resumable, with process locks and per-step checkpoints. Stage downloads, validate artifacts, and atomically switch compatible generations. Upgrades must preview relevant config/schema/permission changes and preserve user modifications. Take consistent database backups and support version-compatible restoration.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0153 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0153 Failed candidate update preserves old generation
- **WHEN** working generation A is active and candidate B fails a health probe after staging a schema/config change
- **THEN** the active pointer/service/config SHALL remain or return to A, user modifications SHALL remain intact, B SHALL be recorded failed with rollback/resume evidence and no partial success label

#### Scenario: R0153 Consistent real database restore
- **WHEN** a synthetic DB contains row alpha, a consistent schema-versioned backup is taken, alpha is changed/deleted, then a compatible restore runs
- **THEN** restored queries SHALL return the exact backed-up row and verified integrity in a staged destination before activation; corrupt/incompatible backup SHALL be rejected while preserving the prior live DB

#### Scenario: R0153 Repeated install after crash checkpoint
- **WHEN** the installer crashes after one owned service/config step is durably checkpointed, then resume and a second install run use the same intent
- **THEN** resume SHALL verify and reuse completed owned work, finish only pending steps and produce exactly one instance of each selected service/profile/skill/job/account/MCP entry; unrelated files/services SHALL remain byte-for-byte preserved

### Requirement: R0154 source line 274
The installer SHALL satisfy this obligation: Uninstall removes installer-owned software while retaining user data by default.

#### Scenario: R0154 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Uninstall removes installer-owned software while retaining user data by default.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0154 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0155 source line 276
The installer SHALL satisfy this obligation: Bind management interfaces to loopback by default. Remote access must have authentication and appropriate encrypted transport. Keep services unprivileged where possible, limit filesystem/network/tool scopes, and keep secrets out of source, command lines, screenshots, logs, and diagnostic bundles. Preserve OAuth callback validation and credential ownership.

#### Scenario: R0155 fulfilled constraint
- **WHEN** the requested CLI operation runs against a temporary owned root with preexisting unowned data, journal checkpoints, configuration and synthetic database
- **THEN** Bind management interfaces to loopback by default. Remote access must have authentication and appropriate encrypted transport. Keep services unprivileged where possible, limit filesystem/network/tool scopes, and keep secrets out of source, command lines, screenshots, logs, and diagnostic bundles. Preserve OAuth callback validation and credential ownership.
- **AND** evidence SHALL demonstrate the observable outcome using Temporary owned/unowned roots and injected process/package/network/filesystem failure fixtures exercise the stated CLI/lifecycle operation; compare exact state/data preservation, idempotence, recovery and blocked exit/report/resume behavior

#### Scenario: R0155 unavailable or failed prerequisite
- **WHEN** a crash, process/package lock, disk failure, symlink escape, schema mismatch or failed candidate health check interrupts the operation
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

### Requirement: Root initial compilation precedes policy session
The implementation SHALL create and verify the exact v42 internal stage0 compilation context without requiring a policy-dependent setup session.

#### Scenario: No bootstrap policy exists yet
- **WHEN** the actual installed root actor compiles initial selected policy
- **THEN** root internal stage0 custody authorizes fixed compilation and one-use publication handoff before normal setup session creation

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
