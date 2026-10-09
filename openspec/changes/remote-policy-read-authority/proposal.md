# Why

A fresh HTTP request with an unexpired Access JWT does not prove current out-of-band policy membership. Existing R0206 needs actual fresh authority while R0209 forbids setup/API secrets in the gateway.

# What Changes

Add RP01..RP06 and AC17 through the append-only Sol amendment and additive planning mapping. Securely enroll separate minimum-read authority; isolate verifier custody from gateway/Desktop/cloudflared; enforce exact fresh reads, cancellation and observation-anchored leases; preserve automatic setup and lifecycle safety. No runtime implementation in this change.

# Capabilities

## New Capabilities

- `remote-policy-read-authority`: separate verifier read-role, secure custody and truthful bounded policy/revocation evidence.

## Modified Capabilities

None; additive refinement to pending remote requirements, no weakened canonical behavior.

# Impact

Remote installer credential/configuration workflow, verifier process/IPC, gateway renewal, ownership journal/lifecycle and AC13/15/17 evidence. All211 original requirements, AC01..16, owned Resources amendment and frozen baseline remain intact.
