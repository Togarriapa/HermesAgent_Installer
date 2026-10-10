# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

Use one normalized route policy and a dispatcher wrapping every inference, tool request, auxiliary extraction/embedding, background request and retry. Policies carry sensitivity classification, allowed destinations/models, modalities/tool support, cost ceiling, aggregate account/agent usage, cancellation and deadline. Default paid capability disabled; unknown pricing or data eligibility denies. Reserve budget atomically before dispatch, reconcile reported/estimated usage conservatively, cap retry count and cumulative latency, honor Retry-After and never remove :free. Explicit allowlists apply through OmniRoute as well as native direct routes; loop IDs prevent proxy recursion and compression must preserve tool schemas.

Nemotron model must remain nvidia/nemotron-3-ultra-550b-a55b:free. Refresh live catalog parameters/prices/terms during configuration and record the dated response; a catalog entry does not prove account inference/tool entitlement. Current primary catalog reports text-only, 1M context, max completion 65,536, zero prompt/completion pricing and tools/tool_choice; response_format is absent. Do not set unsupported structured-output parameters. Endpoint terms explicitly prohibit confidential/personal uploads and retain usage for NVIDIA purposes; enforce eligibility even if price stays free. Public synthetic tests may use that route; private repositories, Google/HA/tool results, memories, summaries and system context require eligible local/private-capable destinations. Propagate sensitivity labels to derived content; prove failures and retries do not leak it. A provider unavailable/private route is a useful blocked state.

Credential broker accepts references, secure prompt input and supported host-managed stores, validates OAuth callbacks, serializes refresh ownership, and redacts runtime environment/log/evidence. Profiles and isolated workers reference credentials; never clone reusable OAuth refresh material. Existing ChatGPT/Codex auth is separate from API billing. Hermes documents an opt-in Codex app-server runtime at pinned SHA; it removes agent-context delegate_task/memory/session_search/todo and automatically migrates plugins/MCPs. Keep registry coordinator on default Hermes runtime unless full mediation and topology evidence exist; offer bounded Codex coding tasks in temporary workspace, and permit inference only through upstream supported provider routes. Do not replay subscription tokens into a fabricated compatibility API. Filter unselected/paid native callback tools and migrated plugins.

Claude Free remains inventory, with eligibility checked from current official docs; ineligible account yields unavailable inference and explicit supported alternatives without buying or session scraping. Jarvis/Banana have separate requirements. OmniRoute install adapter reviews ARM64/service version, explicit provider allowlist/loopback/auth, and verifies no fallback bypass; if direct native route is needed retain OmniRoute component status.

Use typed modular orchestration and explicit adapters rather than a monolithic shell script, because checkpointed operations and injectable command/network/filesystem interfaces make preservation and failure contracts testable. Prefer native supported upstream mechanisms over replacement frameworks; wrap them only at actual policy/compatibility boundaries.

## Risks / Trade-offs

- Upstream drift or unsupported ARM64 transitive dependency -> revalidate pinned source at component configure/update; retain previous generation and truthful unsupported state.
- Account or hardware unavailable -> finish code and synthetic fixtures, deliver executable target workflow, keep live verification unchecked.
- Secret or authority propagation -> host-managed references, mandatory dispatch mediation, synthetic canary and negative side-effect tests.
- Resource contention or partial failure -> measured limits, bounded cancellation, per-step journal, atomic activation and ownership-aware rollback.

## Migration Plan

Implement foundation tasks before dependent obligations. Stage artifacts and review dry-run against pre-state; isolated fixtures precede any authorized target install. Activate only compatible verified generations; restore previous pointer/config snapshot on failure and retain user data. Commit code/test/evidence with requirement and change IDs. Archive only completed verified scope and merge deltas into canonical specs through the installed supported workflow.

## Open Questions

Live target/account values and pending source selections are tracked in planning/blockers.json. The architecture supports source overrides and configure-later without deleting these requirements. New technical scope choices require a separate Sol-reviewed append-only amendment, never edits to the frozen baseline.

## Documented ChatGPT-plan protocol refinement (PR01)

Read planning/codex-siwc-protocol-contract.json and append-only codex-siwc-protocol-v1. Existing codex_responses.py selected unsupported fields/system role and forced stream=false; this must change before route readiness. Use documented selected-account authorization with fresh PKCE/state/nonce, issued clientID, exact callback/resource, validated signed IDtoken/account and granted planusage permission. Keep tokens in sole protected root credential custody, not worker argv/env/profile copies. Account registration/refresh/actual consent remains separately enrolled, never fabricated by fixtures.

Root sends eligible final normalized array input to fixed verified-TLS /v1/responses with store=false and stream=true. Reject unsupported fields/tools explicitly; a reviewed native mapping to instructions/developer may preserve system intent but must retain full content/source receipts. No silent context loss. Compute HI08 final canonical payload digest after all supported transformations; fresh per-attempt context/grant enforces model/account/capability/source/recipient/budget. Catalog rows indicate discovery only.

Consume bounded SSE through response.completed before inference success. Partial text/HTTP200/EOF is insufficient; distinguish failed/incomplete/errors/usage-limit/unavailable/timeout/cancel/revoke and malformed/oversized streams. Bound frame/events/aggregate bytes and original deadline/current context lease, close network independently on expiry/cancel. No hidden retries, paid fallback or credential-bearing worker stream. Record partial results as incomplete with redacted diagnostics, not successful entitlement. Tool calls only eligible documented selected-model forms; actual local execution still mediated separately. Native gateway may adapt completed output to its supported local protocol only after validated terminal completion and preserved tool/result semantics.

Primary docs checked2026-10-09: models-and-inference, preview-limitations and sign-in under https://developers.openai.com/siwc/token-sharing-open-source/. These describe preview compatibility, not entitlement of an unenrolled account. Existing PR-F02/PR-F03 and PR-R0124/25/26 remain open. New PR-T01 evidence includes recording SSE terminal/failure fixtures and unsupported/auth/source/retry/cancel negatives; actual selected-account completed inference remains separate.

## Pinned OmniRoute Node compatibility (PR02)

The selected source4ea24a2f8e1faf8a606c8b8dce45e5b1ab6c9bb0/package.json v3.8.52 declares >=22.22.2 <23 || >=24.0.0 <27 (official pinned manifest read2026-10-09). Existing protected PM source catalog declares Node26.7.0 LinuxARM64 archive SHAafc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d, which meets that source range. Node20.19 is not eligible. This is a source/range decision, not artifact-byte/native support evidence.

Use a separately staged component-owned protected instance of that exact selected Node artifact; host/globalNode and HermesPM runtime stay preserved. Verify root catalog bytes/hash/license/nativeABI, complete pinned dependency lock and reviewed fixed build recipe before enrollment. Protect executable/PATH/module roots/output generation under host custody; no caller npm flags/URL/path, unreviewed resolver/postinstall/lazy dependencies or writable import ancestors. Root fixed bounded build/start profile applies actual reviewed dependencies/ARM64 native health; incomplete source/toolchain/module/ABI remains exact unavailable state. Source catalog acquisition and runtime egress remain distinct controlled operations.

planning/omniroute-runtime-contract.json records exact source/range/pin and evidence separation. Original OmniRoute source/privacy/tool/recipient/zero-budget and loop/fallback constraints still apply; engine match cannot authorize direct provider egress or paid fallback. PR-T02 supplements existing PR-F03/PR-R0130; actual native build and provider operation remain open.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.

Native protected config v3: plans/amendments/2026-10-09-native-protected-config-v3.md specifies strict native-packages.json package/issuer joins and separate canonical normalization-policy/module hashes. Existing HI08/09/11/RB08/provider tasks remain open; config presence is not actual observer/native evidence.

Native observed invocation context v6: plans/amendments/2026-10-09-native-observed-invocation-context-v6.md and planning/native-package-binding-contract.json define exact root response/call handles and begin/ancestry DTOs; existing HI-T08/09/11/RB-T09/provider tasks remain open.

Native observer/delivery/composite v9: plans/amendments/2026-10-09-native-observer-delivery-composite-v9.md defines exact adapter issuer joins, root-issued response lookup transport and strict outer→root finite child workflows. Existing HI/PR/RB tasks remain open.

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.

Public input/web permission v138: `plans/amendments/2026-10-10-public-input-web-permission-v138.md`; actual PUBLIC input plus purpose-specific finite scope permission, zero budget and per-retry currentness; no private consent widening or profile-based classification. All AC remain open.

Concrete bootstrap/source/public disclosure v149: `plans/amendments/2026-10-10-runtime-member-role-public-disclosure-v149.md`; exact runtime member layout, prepared held source distinct live import, genuine per-input public disclosure. All AC open.

Stable private endpoint/model binding v151: `plans/amendments/2026-10-10-stable-private-endpoint-binding-v151.md`; source-selected IDs before process observation, genuine runtime receipt proofs after startup. All AC open.
