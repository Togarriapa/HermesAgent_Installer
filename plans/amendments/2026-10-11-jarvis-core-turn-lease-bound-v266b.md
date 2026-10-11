# Core turn authorization lease clarification v266b

v265 says original <=30-second leases, while v263 allows explicit fresh protected HTTP renewal within original JWT expiry and forbids expired-lease revival. The bound applies to each authorization lease, not a hard 30-second total assistant turn. This clarification retains the same core/UI tasks and does not lengthen any original proof, JWT or backend deadline.

An owned turn may continue through distinct newly issued leases only while its current lease and original bounds remain live. Each issuance requires a real fresh protected heartbeat with independent JWT/Unix ingress/current core checks, same-origin CSRF and one-use turn nonce. Old leases/proofs are never mutated/restamped/revived. Every stream byte needs live authorization and <=5-second witness; SSE segments remain <=4 seconds. Missing/refused/stale witness denies and cancels exact turn within freshness bound.

The turn deadline is min(original admitted JWT expiry, initial acceptance +600 seconds, any stricter original backend/task deadline). Later JWT does not extend it or change principal/ownership. Actual >30-second success, revocation/expiry/replay failures and cancellation must be proved on Pi; all acceptance OPEN. See planning/jarvis-core-turn-lease-bound-v266b.json. No local validation or runtime change.
