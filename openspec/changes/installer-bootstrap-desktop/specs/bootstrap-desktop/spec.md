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
