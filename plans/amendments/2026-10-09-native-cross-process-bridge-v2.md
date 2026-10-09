# Native cross-process full-envelope clarification v2

Sol append-only clarification of HI11/HI-T11/EV-HI11, original HI08/provider source scope and v1 amendment. No new product requirement, frozen baseline/18AC unchanged.

## Full request capture clarification

HI11 prepare_native_event signature is prepare_native_event(payload:bytes, *, parent_receipt_handles=(), purpose,intent_id,trace_id,retry_index=0). Root directly observes exact complete SDK request envelope, not only messages. Existing source.capture receipt remains bounded immutable ancestry; its retention is not reusable effect permission. New prepare captures exact new attempt and joins full parents, then protected same canonicalizer derives expected final provider body. Gateway dispatch_native_request(handle,normalized_payload:bytes,retry_index=0) compares exact digest under authenticated fixed gateway peer and atomically performs effect. Missing model/tool/stream/request fields or normalization mismatch cannot be repaired by caller claims. Each retry needs a newly captured complete envelope and fresh bridge/root retry admission; no old bridge reuse or source ancestry deletion. Actual paired PID/exe/UID/generation values must be enrolled from observed host artifacts, not fabricated in planning.

Evidence: actual complete producer capture→separate gateway normalization positive; missing model/tool fields, wrong normalizer, stale/wrong peer, concurrent replay and failed retry reuse denied. Original task remains open.
