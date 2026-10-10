# provider-routing Delta

## Purpose

Supported account authentication and tool/inference routes with aggregate budgets, privacy eligibility and fail-closed fallback. This contract preserves the full requested scope and separates functional evidence from pending hardware/account readiness.

## ADDED Requirements

### Requirement: R0032 source line 68
The installer SHALL satisfy this obligation: Default to zero additional metered spending. Existing subscription access can be used through supported authentication. Any paid model, cloud browser, image generation, embedding, transcription, or other paid API must remain disabled until a budget and account are deliberately configured.

#### Scenario: R0032 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Default to zero additional metered spending. Existing subscription access can be used through supported authentication. Any paid model, cloud browser, image generation, embedding, transcription, or other paid API must remain disabled until a budget and account are deliberately configured.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0032 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0032 Zero budget and paid fallback
- **WHEN** aggregate metered budget is zero and the free configured route fails while a proxy advertises a paid default fallback
- **THEN** dispatch SHALL reject the paid route before any HTTP request, keep the requested free model identity unchanged, return an unavailable-route result and record zero paid-endpoint calls across delegated/background retries

### Requirement: R0068 source line 129
The installer SHALL satisfy this obligation: OmniRoute; omniroute: One routing service with deduplicated aliases; verify its ARM64 path and restrict configured providers/fallbacks.

#### Scenario: R0068 fulfilled constraint
- **WHEN** the explicitly selected OmniRoute; omniroute on-demand adapter receives a local synthetic functional fixture with supported dependency and provider capabilities
- **THEN** OmniRoute; omniroute: One routing service with deduplicated aliases; verify its ARM64 path and restrict configured providers/fallbacks.
- **AND** evidence SHALL demonstrate the observable outcome using Send synthetic tool-call route through service and recording endpoints; paid/private fallback/loop/compression/retry denial asserted; fixture and pending/live states remain separate

#### Scenario: R0068 unavailable or failed prerequisite
- **WHEN** OmniRoute; omniroute dependency/ARM64/account/capability checks fail or a requested operation exceeds its allowed policy/resource scope
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0104 source line 182
The installer SHALL satisfy this obligation: Requested remote model: Nemotron 3 Ultra Free. Research-time OpenRouter identifier:

#### Scenario: R0104 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Requested remote model: Nemotron 3 Ultra Free. Research-time OpenRouter identifier:
- **AND** evidence SHALL demonstrate the observable outcome using Evidence/coverage fixture asserts complete original scope and explicit platform/result/blocker, rejects skipped or configured-only success, and verifies redaction/provenance/commands

#### Scenario: R0104 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0105 source line 185
The installer SHALL satisfy this obligation: nvidia/nemotron-3-ultra-550b-a55b:free

#### Scenario: R0105 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** nvidia/nemotron-3-ultra-550b-a55b:free
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0105 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0106 source line 188
The installer SHALL satisfy this obligation: Check the live model entry (https://openrouter.ai/nvidia/nemotron-3-ultra-550b-a55b:free), model catalog, supported parameters, context/output limits, token prices, account access, and rate limits during configuration. Perform an actual minimal inference and tool-calling test.

#### Scenario: R0106 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Check the live model entry (https://openrouter.ai/nvidia/nemotron-3-ultra-550b-a55b:free), model catalog, supported parameters, context/output limits, token prices, account access, and rate limits during configuration. Perform an actual minimal inference and tool-calling test.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0106 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0106 Unsupported provider parameter and modality
- **WHEN** the live-model fixture allows tools/tool_choice but lacks response_format and is text-only while a component asks for structured-output mode or screenshot understanding
- **THEN** the adapter SHALL omit unsupported parameters and deny the unavailable vision capability with an explicit compatible-provider next step; skill availability SHALL NOT label the task operational

### Requirement: R0107 source line 188
The installer SHALL satisfy this obligation: Do not infer entitlement from a model appearing in a catalog or enforce unsupported parameters such as structured-output modes without checking them.

#### Scenario: R0107 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Do not infer entitlement from a model appearing in a catalog or enforce unsupported parameters such as structured-output modes without checking them.
- **AND** evidence SHALL demonstrate the observable outcome using Denial fixture at actual dispatch/process/filesystem boundary: attempts beyond authorized scope fail before target side effect, including schedule/webhook/delegated identities and fresh lookup failure

#### Scenario: R0107 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0108 source line 190
The installer SHALL satisfy this obligation: Handle unavailable models, expired keys, 429 responses, `Retry-After`, timeouts, and cancellation with bounded retries and clear status. Configure an explicit fallback allowlist; never silently choose a paid model or remove the `:free` suffix. Limit provider use across all agents collectively.

#### Scenario: R0108 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Handle unavailable models, expired keys, 429 responses, `Retry-After`, timeouts, and cancellation with bounded retries and clear status. Configure an explicit fallback allowlist; never silently choose a paid model or remove the `:free` suffix. Limit provider use across all agents collectively.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0108 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0108 Retry deadline and cancellation
- **WHEN** the provider fixture returns429 with Retry-After3s, configured attempts are3 and total deadline10s, then cancellation is requested
- **THEN** retry SHALL respect Retry-After while within the configured total limits; cancellation SHALL stop pending dispatch, attempts SHALL NOT exceed3, no paid/disallowed model SHALL be contacted and status SHALL distinguish quota/rate-limit/cancel from authentication

### Requirement: R0109 source line 192
The installer SHALL satisfy this obligation: The researched free endpoint excludes confidential/personal submissions and logs usage for specified provider purposes. Recheck these conditions and enforce compatible data routing. Private Google content, Home Assistant data, personal memory, private repositories, tool results, and extracted summaries must not be sent to an incompatible free route.

#### Scenario: R0109 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** The researched free endpoint excludes confidential/personal submissions and logs usage for specified provider purposes. Recheck these conditions and enforce compatible data routing. Private Google content, Home Assistant data, personal memory, private repositories, tool results, and extracted summaries must not be sent to an incompatible free route.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0109 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0109 Private derived context cannot reach free endpoint
- **WHEN** a Google read/tool result is classified private and its summary, system context or memory extraction attempts the configured Nemotron public-only endpoint with no eligible private route
- **THEN** the actual dispatcher SHALL return private-route-unavailable before network dispatch for each derived/retry/background request; the recording endpoint SHALL receive zero private requests and no automatic fallback SHALL relabel the data public

### Requirement: R0110 source line 192
The installer SHALL satisfy this obligation: Apply this to system context, memory extraction, background work, retries, and fallbacks as well as the initial message.

#### Scenario: R0110 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Apply this to system context, memory extraction, background work, retries, and fallbacks as well as the initial message.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0110 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0111 source line 194
The installer SHALL satisfy this obligation: Provide separate public/non-sensitive and private-capable execution configurations. Route private work only through a locally running model or another configured provider whose applicable terms and user settings permit it. If none is usable, show a specific unavailable route rather than leaking private context through a fallback.

#### Scenario: R0111 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Provide separate public/non-sensitive and private-capable execution configurations. Route private work only through a locally running model or another configured provider whose applicable terms and user settings permit it. If none is usable, show a specific unavailable route rather than leaking private context through a fallback.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0111 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0124 source line 217
The installer SHALL satisfy this obligation: Connect my existing Codex access through supported OpenAI authentication (https://developers.openai.com/codex/auth) and the installed Hermes version's documented provider/integration mechanisms. Distinguish ChatGPT/Codex subscription sign-in from separately billed OpenAI API-key usage.

#### Scenario: R0124 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Connect my existing Codex access through supported OpenAI authentication (https://developers.openai.com/codex/auth) and the installed Hermes version's documented provider/integration mechanisms. Distinguish ChatGPT/Codex subscription sign-in from separately billed OpenAI API-key usage.
- **AND** evidence SHALL demonstrate the observable outcome using Evidence/coverage fixture asserts complete original scope and explicit platform/result/blocker, rejects skipped or configured-only success, and verifies redaction/provenance/commands

#### Scenario: R0124 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0125 source line 219
The installer SHALL satisfy this obligation: Implement host-managed authentication, including an appropriate browser/device-code or headless workflow. Reuse supported credential references; do not copy reusable OAuth credentials into each profile, repository, container image, or agent workspace. Preserve refresh-token ownership and revocation behavior.

#### Scenario: R0125 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Implement host-managed authentication, including an appropriate browser/device-code or headless workflow. Reuse supported credential references; do not copy reusable OAuth credentials into each profile, repository, container image, or agent workspace. Preserve refresh-token ownership and revocation behavior.
- **AND** evidence SHALL demonstrate the observable outcome using Synthetic canary secret fixture: secure reference resolution, correct owner/scope, callback or refresh failure as applicable, no value in config/argv/log/report

#### Scenario: R0125 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

#### Scenario: R0125 Shared credential refresh ownership
- **WHEN** two profile workers reference one supported OAuth host credential whose refresh token is single-use and one refresh request succeeds
- **THEN** the host broker SHALL serialize refresh ownership and expose only authorized references/results; it SHALL NOT copy reusable token values into profile roots/argv/logs or let the second worker race the consumed refresh token

### Requirement: R0126 source line 221
The installer SHALL satisfy this obligation: Support Codex as a bounded coding tool for relevant profiles, and as an inference provider only through a documented supported integration. Do not invent a generic OpenAI-compatible API by replaying subscription tokens. Validate actual inference or a small coding task inside a temporary workspace; report authentication, entitlement, quota, and functional status separately.

#### Scenario: R0126 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Support Codex as a bounded coding tool for relevant profiles, and as an inference provider only through a documented supported integration. Do not invent a generic OpenAI-compatible API by replaying subscription tokens. Validate actual inference or a small coding task inside a temporary workspace; report authentication, entitlement, quota, and functional status separately.
- **AND** evidence SHALL demonstrate the observable outcome using HTTP Range/digest and filesystem capacity fixtures: verify required capacity calculation, interrupted resume, mismatch/ENOSPC containment and preservation of prior generation

#### Scenario: R0126 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0127 source line 225
The installer SHALL satisfy this obligation: Retain my requested Claude Free account in the setup inventory, but do not promise that a consumer free login provides Claude Code, Anthropic API, or third-party inference access. Check current Anthropic authentication documentation (https://code.claude.com/docs/en/authentication) and applicable third-party account rules.

#### Scenario: R0127 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Retain my requested Claude Free account in the setup inventory, but do not promise that a consumer free login provides Claude Code, Anthropic API, or third-party inference access. Check current Anthropic authentication documentation (https://code.claude.com/docs/en/authentication) and applicable third-party account rules.
- **AND** evidence SHALL demonstrate the observable outcome using Evidence/coverage fixture asserts complete original scope and explicit platform/result/blocker, rejects skipped or configured-only success, and verifies redaction/provenance/commands

#### Scenario: R0127 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0128 source line 227
The installer SHALL satisfy this obligation: If the account is ineligible, mark automatic Claude inference unavailable and explain the supported account/API alternatives without purchasing anything. Continue installing the rest. Do not use cookie extraction, session scraping, identity spoofing, or an unofficial web-to-API bridge. Applications such as Jarvis or Banana with additional client/provider requirements need their own honest dependency status.

#### Scenario: R0128 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** If the account is ineligible, mark automatic Claude inference unavailable and explain the supported account/API alternatives without purchasing anything. Continue installing the rest. Do not use cookie extraction, session scraping, identity spoofing, or an unofficial web-to-API bridge. Applications such as Jarvis or Banana with additional client/provider requirements need their own honest dependency status.
- **AND** evidence SHALL demonstrate the observable outcome using Evidence/coverage fixture asserts complete original scope and explicit platform/result/blocker, rejects skipped or configured-only success, and verifies redaction/provenance/commands

#### Scenario: R0128 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0129 source line 231
The installer SHALL satisfy this obligation: Install/configure the verified OmniRoute component as the selected routing layer where its supported features help. Avoid stacking redundant gateways around native Hermes providers. If a direct provider connection is required, document that route while retaining OmniRoute's explicit component status.

#### Scenario: R0129 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Install/configure the verified OmniRoute component as the selected routing layer where its supported features help. Avoid stacking redundant gateways around native Hermes providers. If a direct provider connection is required, document that route while retaining OmniRoute's explicit component status.
- **AND** evidence SHALL demonstrate the observable outcome using Evidence/coverage fixture asserts complete original scope and explicit platform/result/blocker, rejects skipped or configured-only success, and verifies redaction/provenance/commands

#### Scenario: R0129 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: R0130 source line 233
The installer SHALL satisfy this obligation: Apply model allowlists, capability checks, privacy eligibility, aggregate budgets, bounded retries, health checks, and loop prevention through the actual dispatch path. Do not let a proxy's default fallback, compression feature, or advertised free-provider list override those requirements or corrupt tool calls.

#### Scenario: R0130 fulfilled constraint
- **WHEN** the dispatch adapter receives a synthetic request with account reference, exact model allowlist, sensitivity class, capability and configured aggregate budget
- **THEN** Apply model allowlists, capability checks, privacy eligibility, aggregate budgets, bounded retries, health checks, and loop prevention through the actual dispatch path. Do not let a proxy's default fallback, compression feature, or advertised free-provider list override those requirements or corrupt tool calls.
- **AND** evidence SHALL demonstrate the observable outcome using Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason

#### Scenario: R0130 unavailable or failed prerequisite
- **WHEN** the selected account is ineligible, the requested route exceeds budget/privacy scope or a bounded network/authentication attempt fails
- **THEN** The installer SHALL report an actionable blocked/failed result, preserve prior owned data/state, and SHALL NOT claim this obligation passed without the required evidence.

### Requirement: Supported ChatGPT-plan inference protocol (PR01)

The supported ChatGPT-plan inference adapter SHALL follow the current documented authorization and HTTP/SSE request contract, bind normalized final payload to fresh host source/effect authority and consume through successful terminal completion. Unsupported fields/tools, missing permission, incomplete streams and usage failures SHALL not establish usable inference or trigger paid fallback.

#### Scenario: Terminal stream and actual permission

- **WHEN** selected ChatGPT-plan inference returns partial events or lacks granted plan permission
- **THEN** route reports incomplete/unavailable and does not claim successful inference, entitlement or use a paid fallback

### Requirement: Pinned isolated OmniRoute runtime (PR02)

OmniRoute SHALL run with an isolated protected Node runtime satisfying its pinned source engine contract and verified artifact/ABI/dependency lock. Caller/global Node paths or semver-only checks SHALL not establish native readiness. Build and service enrollment SHALL preserve original source/privacy/budget dispatch policy and keep unsupported runtime/dependencies incomplete.

#### Scenario: Ineligible host Node

- **WHEN** host Node version or writable module path is incompatible with the pinned source contract
- **THEN** root uses only verified selected isolated runtime or reports incomplete; host/Hermes runtime and original privacy/budget policy remain preserved

### Requirement: Protected native composition
The installer SHALL bind actual native producer package/adapter closure through immutable root-selected profile generation and observed issuer channels, and SHALL apply the same protected route normalization policy before final request digest and gateway effect. Caller registration/labels SHALL not establish provenance.

#### Scenario: Mutable package or divergent normalization
- **WHEN** native closure, peer generation, issuer provenance or route-normalized final payload differs from protected enrollment
- **THEN** deny before effect bytes and retain exact incomplete implementation/native evidence state.

### Requirement: Native protected configuration identities
The installer SHALL validate strict root-owned package/issuer catalogs and distinct canonical normalization-policy and installed module hashes with actual current enrollment joins.

#### Scenario: Partial hash or unobserved configured issuer
- **WHEN** policy/module digest is missing or source observer only exists as configuration text
- **THEN** keep affected native effect unavailable and require actual identity/observer evidence.

### Requirement: Root-observed native invocation ancestry
The installer SHALL bind native tool and memory invocation ancestry to actual root-observed response/event handles and selected loaded actions, with fresh per-effect authority.

#### Scenario: Worker invents current invocation
- **WHEN** a worker supplies a forged response/call handle or changes observed action arguments
- **THEN** root rejects before effects and does not mint source or user provenance from caller assertions

### Requirement: Observed native metadata and bounded composite effects
The installer SHALL resolve source observers from explicit selected adapter joins and deliver provider metadata only through peer/request/response-bound root lookup; composite effects SHALL preserve exact outer matching and fresh root child authority.

#### Scenario: Composite tool requests an unselected child
- **WHEN** worker code invokes a different action/digest or claims response metadata without exact root lookup
- **THEN** root denies before effects and executes only its reviewed finite selected workflow under fresh per-step grants

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.

### Requirement: Purpose-bound PUBLIC input web permission v138
The installer SHALL authorize public web egress only from genuine root-observed PUBLIC input and current exact selected public web permission; PRIVATE or UNKNOWN source ancestry SHALL remain denied even when a public scope is configured.

#### Scenario: Private input requests an enrolled public website
- **WHEN** any retained parent/input source is PRIVATE or UNKNOWN or the public permission is absent/revoked/expired
- **THEN** public web dispatch and retries are denied without dropping ancestry, widening private consent or adding budget

### Requirement: Distinct runtime member and public input evidence v149
The installer SHALL preserve unique interpreter identity, exact runtime member closure and distinct prepared/live role proofs, and SHALL require actual per-input root disclosure for first public egress.

#### Scenario: Persistent public config has no disclosed input
- **WHEN** a public web request has no actual root-observed per-input disclosure and ancestry proof
- **THEN** no PUBLIC receipt is issued merely from profile configuration or missing parents

### Requirement: Stable private binding and current observation separation v151
The installer SHALL select private endpoint/model binding IDs before startup and resolve genuine current runtime observations only after actual listener/load/source proof.

#### Scenario: Configured private endpoint has no live process
- **WHEN** only the protected endpoint binding exists
- **THEN** no runtime route or deployment receipt is fabricated from that configured identity

### Requirement: Durable adopted public choice currentness v153
The installer SHALL verify current signed source choice/revocation and active adoption beyond setup closure while requiring separate fresh per-input installed-root TTY disclosure and effect authority.

#### Scenario: Original signed choice is revoked under unchanged active pointer
- **WHEN** the root journal choice epoch/revocation changes
- **THEN** the adoption/current permission denies despite an unchanged policy pointer and never extends an expired setup or runtime lease

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
