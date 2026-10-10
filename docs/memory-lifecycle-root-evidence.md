# Root memory lifecycle evidence

`RootMemoryPrestartReceiptRegistry` re-resolves the active memory enrollment and
fixed empty-parameter start recipe, then opens every selected executable/runtime/
child artifact with `O_NOFOLLOW`. It verifies the held file identity, owner,
link count, read-only mode, length, and SHA-256 before retaining a short-lived
root-journal receipt. Receipt resolution reopens and rehashes the same closure;
an opaque handle alone never proves membership or currentness.

The receipt also requires the v119
`RootMemoryServiceEnablementSelection` from the active protected generation.
It must join the same principal, profile, namespace, provider/backend, service
generation, owner generation, and fixed start operation. Its handle, digest,
and revocation epoch are included in the source closure and rechecked on every
currentness test. Private-route selection and automatic-capture consent are
separate purposes and cannot authorize service startup. The repository does
not yet publish this lifecycle choice in the active catalog, so production
prestart observation currently fails closed.

`RootMemorySemanticReadinessRegistry` accepts only a manager-owned selected
service process receipt and resolves a fresh process identity lease before
probing. OpenViking and AgentMemory use their reviewed fixed search operations
with a generated non-user canary query; the actual bounded request and result
schema are retained with the process identity and active source closure. Health
and liveness routes are never treated as semantic proof. Backends without a
reviewed request serializer and result validator, including the current
Claude-mem variants, remain unavailable for semantic readiness.

The controlled-root fixtures exercise source receipt persistence across
registry recreation, artifact replacement rejection, missing enablement choice,
revocation/currentness, foreign-handle rejection, and fixed semantic route
selection. These fixtures do not establish an active TTY enablement producer,
managed memory start custody, live provider readiness, or target acceptance.
