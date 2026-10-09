# Supported Codex ChatGPT-plan protocol v1

Sol additive implementation refinement of original R0124/R0125/R0126 and PR-F02/PR-F03. Frozen baseline, selected providers and all18 original target gates unchanged. Add PR01/PR-T01/EV-PR01 with prerequisites PR-F01/HI-T08/HI-T09.

## Documented ChatGPT-plan protocol refinement (PR01)

Read planning/codex-siwc-protocol-contract.json and append-only codex-siwc-protocol-v1. Existing codex_responses.py selected unsupported fields/system role and forced stream=false; this must change before route readiness. Use documented selected-account authorization with fresh PKCE/state/nonce, issued clientID, exact callback/resource, validated signed IDtoken/account and granted planusage permission. Keep tokens in sole protected root credential custody, not worker argv/env/profile copies. Account registration/refresh/actual consent remains separately enrolled, never fabricated by fixtures.

Root sends eligible final normalized array input to fixed verified-TLS /v1/responses with store=false and stream=true. Reject unsupported fields/tools explicitly; a reviewed native mapping to instructions/developer may preserve system intent but must retain full content/source receipts. No silent context loss. Compute HI08 final canonical payload digest after all supported transformations; fresh per-attempt context/grant enforces model/account/capability/source/recipient/budget. Catalog rows indicate discovery only.

Consume bounded SSE through response.completed before inference success. Partial text/HTTP200/EOF is insufficient; distinguish failed/incomplete/errors/usage-limit/unavailable/timeout/cancel/revoke and malformed/oversized streams. Bound frame/events/aggregate bytes and original deadline/current context lease, close network independently on expiry/cancel. No hidden retries, paid fallback or credential-bearing worker stream. Record partial results as incomplete with redacted diagnostics, not successful entitlement. Tool calls only eligible documented selected-model forms; actual local execution still mediated separately. Native gateway may adapt completed output to its supported local protocol only after validated terminal completion and preserved tool/result semantics.

Primary docs checked2026-10-09: models-and-inference, preview-limitations and sign-in under https://developers.openai.com/siwc/token-sharing-open-source/. These describe preview compatibility, not entitlement of an unenrolled account. Existing PR-F02/PR-F03 and PR-R0124/25/26 remain open. New PR-T01 evidence includes recording SSE terminal/failure fixtures and unsupported/auth/source/retry/cancel negatives; actual selected-account completed inference remains separate.

Primary references:

- https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference
- https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations
- https://developers.openai.com/siwc/token-sharing-open-source/sign-in
