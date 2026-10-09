# Provider routing and account eligibility

Provider use is opt-in and fails closed. The default additional metered budget is zero. A model catalog, the `:free` suffix, source configuration, or a credential reference does not establish account entitlement or effective account privacy settings.

## Dispatch boundary

All managed provider requests use the shared Dispatcher. It normalizes the model, token bound, plugins, tool schema and provider routing fields before transport. Unsupported modalities and provider-side tools are rejected. Routes have exact model allowlists, maximum sensitivity, capability and known price fields. Unknown prices and private work without an eligible private route are unavailable. Paid calls require a deliberately configured positive aggregate budget, reserve spend before the network request, reconcile usage conservatively, and keep reservations for ambiguous failures.

Dispatcher requires an injected host `context_authorizer`. It must validate current caller identity and issue a short-lived grant bound to principal, profile, namespace, trace, capability and current policy revision. It must compute sensitivity from trusted provenance and derived-content lineage. Context labels are correlation input only; they do not grant access. The dispatcher reauthorizes before every provider attempt, rejects a changed or expired grant, limits the transport deadline to the grant lifetime, and cancels an in-flight request on expiry. Without that host verifier, provider dispatch is unavailable.

Retries are bounded, cancellation-aware and deadline-limited. Retry-After is clamped. Fallback routes are explicit policy entries and must satisfy the same model, sensitivity, capability, price and budget checks. Provider-side fallback, plugins, compression and unreviewed transforms are disabled in the public OpenRouter request.

## OpenRouter Nemotron

The pinned public route is `nvidia/nemotron-3-ultra-550b-a55b:free` at the fixed OpenRouter endpoint. The adapter requires current authoritative account-policy evidence before resolving the key or opening a network client. Evidence binds the model, private credential reference, credential fingerprint, account-policy snapshot and expiry. Synthetic eligibility evidence is accepted only by opted-in test fixtures. Production has no authoritative verifier yet, so OpenRouter inference remains unavailable until account and model eligibility are proven at configuration time.

The public route accepts text and ordinary function tools only. Image/audio/video inputs, server-side tools, response-format modes, caller-selected plugins, model overrides and fallback lists are rejected. Do not send private Google or Home Assistant content, private repositories, personal memory, tool results, system context or derived summaries to this route.

## Codex and Claude

Codex subscription sign-in and separately billed OpenAI API keys are distinct. Use only a supported host-managed Codex authentication path and Hermes-documented integration. Never replay subscription credentials through a fabricated OpenAI-compatible API. Bounded coding and inference remain unavailable until the installed Hermes version exposes a reviewed adapter, the host broker binds its identity and capability, and the relevant account access is confirmed.

Keep Claude Free in the account inventory. A consumer login alone does not prove Claude Code, Anthropic API, or third-party inference eligibility. If the current supported account path cannot be verified, automatic Claude inference is unavailable. Do not extract browser cookies or bridge the consumer web session to an API. Applications such as Jarvis and Banana retain their own dependency and provider status.

## OmniRoute

OmniRoute is not a verified installed service in this repository state. Before enabling it, verify its pinned source and ARM64 dependency path, then configure an explicit provider allowlist and bounded loopback service. Do not accept its advertised free-provider list as account proof or allow proxy defaults to bypass route policy. Until the service path and recording-endpoint failure fixtures pass on supported ARM64, keep it pending and use a direct verified provider adapter only where policy permits.

## Evidence status

Contract fixtures demonstrate policy behavior against synthetic transports and synthetic account proof. They do not establish external account entitlement, live provider terms, actual account-level privacy settings, host process/filesystem isolation, or live Pi inference. Account, model, provider service, and target acceptance must be recorded separately with fresh evidence. No user credential or external account is enrolled by this code.
