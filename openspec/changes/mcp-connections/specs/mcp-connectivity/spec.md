# mcp-connectivity Delta

## Purpose

Official and explicitly labeled optional community MCPs, scoped authentication, harmless functional tests and bounded reconnect. This contract preserves the full requested scope and separates functional evidence from pending hardware/account readiness.

## ADDED Requirements

### Requirement: R0097 source line 168
The installer SHALL satisfy this obligation: Figma MCP: Prefer the official remote server, currently `https://mcp.figma.com/mcp`; authenticate and test actual account capabilities.

#### Scenario: R0097 fulfilled constraint
- **WHEN** the selected Figma MCP fixture transport initializes, discovers read and write schemas and requests only the allowlisted read on a selected fixture resource
- **THEN** Figma MCP: Prefer the official remote server, currently `https://mcp.figma.com/mcp`; authenticate and test actual account capabilities.
- **AND** evidence SHALL demonstrate the observable outcome using Initialize/tools-list plus read selected fixture/mock and eventual chosen file; revoked token/plan denial and no write tests; fixture and pending/live states remain separate

#### Scenario: R0097 unavailable or failed prerequisite
- **WHEN** Figma MCP returns401/revoked credentials, an unknown tool schema or a configured deadline expires
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0098 source line 169
The installer SHALL satisfy this obligation: Playwright MCP, written “playright”: Local official MCP using a pinned `@playwright/mcp` package and verified ARM64 browser.

#### Scenario: R0098 fulfilled constraint
- **WHEN** the selected Playwright MCP, written “playright” fixture transport initializes, discovers read and write schemas and requests only the allowlisted read on a selected fixture resource
- **THEN** Playwright MCP, written “playright”: Local official MCP using a pinned `@playwright/mcp` package and verified ARM64 browser.
- **AND** evidence SHALL demonstrate the observable outcome using Local fixture navigation/accessibility snapshot/screenshot; inspect output image and timeout/cancel/reconnect; no personal cookies or --no-sandbox; fixture and pending/live states remain separate

#### Scenario: R0098 unavailable or failed prerequisite
- **WHEN** Playwright MCP, written “playright” returns401/revoked credentials, an unknown tool schema or a configured deadline expires
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0099 source line 170
The installer SHALL satisfy this obligation: Revenue Cat MCP: Current remote endpoint `https://mcp.revenuecat.ai/mcp`; supported OAuth or scoped API v2 credentials.

#### Scenario: R0099 fulfilled constraint
- **WHEN** the selected Revenue Cat MCP fixture transport initializes, discovers read and write schemas and requests only the allowlisted read on a selected fixture resource
- **THEN** Revenue Cat MCP: Current remote endpoint `https://mcp.revenuecat.ai/mcp`; supported OAuth or scoped API v2 credentials.
- **AND** evidence SHALL demonstrate the observable outcome using Initialize/discovery/selected-project harmless list/read; deny product/customer/entitlement/billing/subscription writes and revoke behavior; fixture and pending/live states remain separate

#### Scenario: R0099 unavailable or failed prerequisite
- **WHEN** Revenue Cat MCP returns401/revoked credentials, an unknown tool schema or a configured deadline expires
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0100 source line 171
The installer SHALL satisfy this obligation: Google: Check account eligibility and requested services. At research time official remote servers require Developer Preview access.

#### Scenario: R0100 fulfilled constraint
- **WHEN** the selected Google fixture transport initializes, discovers read and write schemas and requests only the allowlisted read on a selected fixture resource
- **THEN** Google: Check account eligibility and requested services. At research time official remote servers require Developer Preview access.
- **AND** evidence SHALL demonstrate the observable outcome using Read-only per-service selected-resource calls; callback/refresh/revoked scope fixtures; no send/edit/calendar creation; fixture and pending/live states remain separate

#### Scenario: R0100 unavailable or failed prerequisite
- **WHEN** Google returns401/revoked credentials, an unknown tool schema or a configured deadline expires
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0100 Read-only installation test allowlist
- **WHEN** the Google fixture discovers both read and message/document/calendar mutation tools, and installation tests request selected service resources
- **THEN** only configured minimal-scope harmless reads SHALL execute; send-message/create-meeting/modify-document calls SHALL be denied before side effects and service/account-preview eligibility SHALL be reported separately

### Requirement: R0101 source line 172
The installer SHALL satisfy this obligation: Home Assistant: Connect to the existing instance using its documented `/api/mcp` or `/api/mcp/assist` endpoint and supported authentication.

#### Scenario: R0101 fulfilled constraint
- **WHEN** the selected Home Assistant fixture transport initializes, discovers read and write schemas and requests only the allowlisted read on a selected fixture resource
- **THEN** Home Assistant: Connect to the existing instance using its documented `/api/mcp` or `/api/mcp/assist` endpoint and supported authentication.
- **AND** evidence SHALL demonstrate the observable outcome using Read selected entity/state; initialization/reconnect/revoked auth; broker denies device-control writes and no replacement instance; fixture and pending/live states remain separate

#### Scenario: R0101 unavailable or failed prerequisite
- **WHEN** Home Assistant returns401/revoked credentials, an unknown tool schema or a configured deadline expires
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0101 Existing entity read without device control
- **WHEN** an existing HA MCP instance exposes one selected entity state and a control tool while the setup verifier runs
- **THEN** verification SHALL read only the selected exposed state, preserve the existing HA deployment and deny all real device-control/replace-instance actions during setup

### Requirement: R0102 source line 174
The installer SHALL satisfy this obligation: For personal Google accounts or unavailable official preview access, evaluate the explicitly community-maintained taylorwilsdon/google_workspace_mcp (https://github.com/taylorwilsdon/google_workspace_mcp). Offer its reviewed integration as a labeled option. Do not describe it as Google's official server.

#### Scenario: R0102 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** For personal Google accounts or unavailable official preview access, evaluate the explicitly community-maintained taylorwilsdon/google_workspace_mcp (https://github.com/taylorwilsdon/google_workspace_mcp). Offer its reviewed integration as a labeled option. Do not describe it as Google's official server.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0102 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0103 source line 176
The installer SHALL satisfy this obligation: Ambiguous names must remain present in the manifest with candidate URLs and an exact next step. Build all independent functionality while awaiting selection. Add a source-override mechanism so resolving a name does not require editing installer code. Do not omit requested items to make the completion report appear cleaner.

#### Scenario: R0103 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Ambiguous names must remain present in the manifest with candidate URLs and an exact next step. Build all independent functionality while awaiting selection. Add a source-override mechanism so resolving a name does not require editing installer code. Do not omit requested items to make the completion report appear cleaner.
- **AND** evidence SHALL demonstrate the observable outcome using MCP initialized/discovered harmless read fixture with schema/cancel/reconnect/deadline/revoked-account assertions and selected-resource mutation denial

#### Scenario: R0103 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0156 source line 280
The installer SHALL satisfy this obligation: For every MCP, determine real transport, endpoint, protocol/client compatibility, authentication, tool schema, and prerequisites. Implement MCP initialization, tool discovery, an appropriate harmless functional call, reconnect, timeout, and revoked-credential behavior. Merely writing a config entry is not a passing test.

#### Scenario: R0156 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** For every MCP, determine real transport, endpoint, protocol/client compatibility, authentication, tool schema, and prerequisites. Implement MCP initialization, tool discovery, an appropriate harmless functional call, reconnect, timeout, and revoked-credential behavior. Merely writing a config entry is not a passing test.
- **AND** evidence SHALL demonstrate the observable outcome using Synthetic canary secret fixture: secure reference resolution, correct owner/scope, callback or refresh failure as applicable, no value in config/argv/log/report

#### Scenario: R0156 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0156 Revocation and bounded optional-server deadline
- **WHEN** a selected MCP fixture initializes and lists tools, then returns401 after revocation or a harmless read exceeds its configured2s deadline
- **THEN** authenticated/functional states SHALL become false/failed with exact cause; reconnect SHALL be bounded and the slow optional server SHALL NOT indefinitely block a separate basic chat request or reuse revoked credentials

### Requirement: R0157 source line 282
The installer SHALL satisfy this obligation: Google: let me select services such as Gmail, Drive/Docs/Sheets, Calendar, and Contacts. Check personal versus Workspace-account eligibility and official preview access. Guide OAuth consent, enabled APIs, callback configuration, refresh behavior, and minimal scopes. Start with read-only operations. Do not send messages, create meetings, or modify documents as installation tests.

#### Scenario: R0157 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Google: let me select services such as Gmail, Drive/Docs/Sheets, Calendar, and Contacts. Check personal versus Workspace-account eligibility and official preview access. Guide OAuth consent, enabled APIs, callback configuration, refresh behavior, and minimal scopes. Start with read-only operations. Do not send messages, create meetings, or modify documents as installation tests.
- **AND** evidence SHALL demonstrate the observable outcome using Synthetic canary secret fixture: secure reference resolution, correct owner/scope, callback or refresh failure as applicable, no value in config/argv/log/report

#### Scenario: R0157 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0158 source line 284
The installer SHALL satisfy this obligation: Home Assistant: use my existing instance, its current official MCP integration, and explicitly exposed entities. Guide authentication and test reading an appropriate entity/state. Do not install a replacement HA instance or issue real device-control commands during setup. Preserve the resource registry's control boundaries.

#### Scenario: R0158 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Home Assistant: use my existing instance, its current official MCP integration, and explicitly exposed entities. Guide authentication and test reading an appropriate entity/state. Do not install a replacement HA instance or issue real device-control commands during setup. Preserve the resource registry's control boundaries.
- **AND** evidence SHALL demonstrate the observable outcome using Denial fixture at actual dispatch/process/filesystem boundary: attempts beyond authorized scope fail before target side effect, including schedule/webhook/delegated identities and fresh lookup failure

#### Scenario: R0158 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0159 source line 286
The installer SHALL satisfy this obligation: Figma: use the official remote endpoint where available, guide login, verify plan/tool availability, and test access to a file I select. Do not require unofficial Figma desktop packages on the Pi.

#### Scenario: R0159 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Figma: use the official remote endpoint where available, guide login, verify plan/tool availability, and test access to a file I select. Do not require unofficial Figma desktop packages on the Pi.
- **AND** evidence SHALL demonstrate the observable outcome using MCP initialized/discovered harmless read fixture with schema/cancel/reconnect/deadline/revoked-account assertions and selected-resource mutation denial

#### Scenario: R0159 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0160 source line 288
The installer SHALL satisfy this obligation: Playwright: install a supported headless ARM64 browser and create isolated browser profiles. Test a local fixture page with navigation, an accessibility snapshot, and a screenshot. Preserve the browser sandbox; any platform-specific limitation needs a documented supported resolution. Do not import personal browser cookies automatically.

#### Scenario: R0160 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Playwright: install a supported headless ARM64 browser and create isolated browser profiles. Test a local fixture page with navigation, an accessibility snapshot, and a screenshot. Preserve the browser sandbox; any platform-specific limitation needs a documented supported resolution. Do not import personal browser cookies automatically.
- **AND** evidence SHALL demonstrate the observable outcome using Denial fixture at actual dispatch/process/filesystem boundary: attempts beyond authorized scope fail before target side effect, including schedule/webhook/delegated identities and fresh lookup failure

#### Scenario: R0160 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0160 Sandboxed browser fixture evidence
- **WHEN** the Playwright adapter opens a new isolated profile against a local fixture with an accessible labeled button
- **THEN** verification SHALL navigate, record the accessibility snapshot and save/inspect a screenshot artifact with digest using the native ARM64 browser/sandbox; it SHALL NOT import personal cookies or count --no-sandbox as a supported solution

### Requirement: R0161 source line 290
The installer SHALL satisfy this obligation: RevenueCat: use the official remote server and my selected project, with scoped OAuth or API credentials. Prefer read-only setup tests. Do not change products, entitlements, customer records, billing, or subscriptions to prove the connection works.

#### Scenario: R0161 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** RevenueCat: use the official remote server and my selected project, with scoped OAuth or API credentials. Prefer read-only setup tests. Do not change products, entitlements, customer records, billing, or subscriptions to prove the connection works.
- **AND** evidence SHALL demonstrate the observable outcome using Synthetic canary secret fixture: secure reference resolution, correct owner/scope, callback or refresh failure as applicable, no value in config/argv/log/report

#### Scenario: R0161 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0161 Selected project read without billing mutation
- **WHEN** the RevenueCat fixture account selects project P while discovery includes product/entitlement/customer/subscription mutation tools
- **THEN** the verifier SHALL use an allowlisted read for P and deny mutation/cross-project access before any side effect; successful discovery alone SHALL NOT mark the connection functional

### Requirement: R0162 source line 292
The installer SHALL satisfy this obligation: Use tool allowlists and bounded discovery/startup concurrency. Cache or lazily initialize servers where Hermes supports it, while validating first-use failure handling. One slow optional server must not leave a basic chat request hanging indefinitely.

#### Scenario: R0162 fulfilled constraint
- **WHEN** the selected MCP adapter initializes the configured fixture transport, discovers its schema and invokes an allowlisted harmless read on a selected synthetic resource
- **THEN** Use tool allowlists and bounded discovery/startup concurrency. Cache or lazily initialize servers where Hermes supports it, while validating first-use failure handling. One slow optional server must not leave a basic chat request hanging indefinitely.
- **AND** evidence SHALL demonstrate the observable outcome using MCP initialized/discovered harmless read fixture with schema/cancel/reconnect/deadline/revoked-account assertions and selected-resource mutation denial

#### Scenario: R0162 unavailable or failed prerequisite
- **WHEN** the server returns revoked authentication, malformed tool schema or exceeds its configured startup/call deadline
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

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

### Requirement: Installed closure and native construction joins
The implementation SHALL use the applicable exact root release and native assembly joins in the v33 amendment before activating selected runtime behavior.

#### Scenario: First input precedes provider pending pair
- **WHEN** the selected actual producer receives root observed initial input before a provider pair exists
- **THEN** root resolves the target through actual execution custody and loader proof, without guessing a pending pair or trusting worker selectors

### Requirement: Protected native candidate index delivery
The implementation SHALL verify the selected fixed candidate-index closure member through exact entrypoint manifest and package pins before native discovery.

#### Scenario: Ordinary cache has a matching tool name
- **WHEN** no verified selected candidate index exists
- **THEN** native protected discovery remains pending without adopting the cache schema or caller metadata

### Requirement: Native schema artifact provenance
The implementation SHALL resolve exact selected argument/result schema artifacts through v39 protected package/action joins.

#### Scenario: Tool name exists without selected schema bytes
- **WHEN** no verified selected schema artifact resolves
- **THEN** the candidate remains unavailable without inferring schema from the name or ordinary cache

### Requirement: Explicit protected native toolset owner
The implementation SHALL obtain native server/toolset ownership and presentation description from the verified candidate index.

#### Scenario: Tool name resembles a different server
- **WHEN** registering a protected native candidate
- **THEN** ownership follows the explicit root-selected server field and parameters-only schema digest, without parsing its name

### Requirement: Exact native registration and retained source joins
The implementation SHALL apply the v44 source snapshot and native registration distinctions without repeated one-use resolution.

#### Scenario: Root source was already consumed for launch
- **WHEN** binding the actual running task to native observation registry
- **THEN** the same verified source snapshot is passed internally and revalidated, without resolving or reusing parent authorization again

### Requirement: Root actual EOF and schema source receipts
The installer SHALL require actual custody write/EOF receipts for task completion and exact root-derived schema receipts for native schema artifacts where applicable.

#### Scenario: Forged or mismatched receipt
- **WHEN** a caller substitutes stdout success, a fabricated receipt or a generic fetched archive for required root observations
- **THEN** the installer denies completion or schema admission without marking target acceptance complete

MCP derived schema CAS closure v92: `plans/amendments/2026-10-10-mcp-derived-schema-cas-closure-v92.md`; existing MC-F01/HI-T08 remain open.
