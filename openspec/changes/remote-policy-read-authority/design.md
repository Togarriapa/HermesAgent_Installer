# Design

## Context

Read plans/amendments/2026-10-09-remote-policy-read-v1.md and planning/remote-policy-read-amendment.json. Source7a90f5 has app/policy callbacks and off-loop9s waits; this does not establish separate credential custody, OTP resource check, cancellation or production readiness.

## Decisions

Use dedicated isolated least-privilege read-verifier service, protected credential custody and authenticated typed local IPC. Gateway never receives secret/reference/resolver and cannot select arbitrary endpoints. API transport fixed Cloudflare TLS GETs only, exact journaled account/app/complete policies/selected OTP IdP, bounded pagination/body/total9sdeadline. Fresh responses bound to principal/session/config/nonce and observation interval; deny incomplete/malformed/changed/broadened policies and unsupported semantics. Separate supplied Read token, no assumed token minting or management credential reuse. Preserve blank hostname, emailOTP, automatic scoped provisioning and configure-later/resume.

Lease<=read-start+60s and JWTexpiry, watchdog<=5s; subtract read latency rather than add fresh60s at response completion. While renewal waits retain original expiry; cancel/reap bounded workers, discard late responses and prevent accumulated blocked threads. No blocking callback on stream loop. Existing multi-GET cannot guarantee atomic snapshot: validate consistency and retain observation timing in redacted evidence.

OS custody/IPC/credential separation is actual authorization, not class naming. Services under separate restricted identities, no shared writable module/runtime/profile files; management token setup-only and tunnel token-file cloudflared-only. Secret-safe lifecycle owns local references/files only, never revokes unowned tokens/OTP resources. Restore/rotation clears grants and validates new generation before activation.

## Risks and validation

Policy reads establish current explicit policy membership, not token-revocation status. Separate local logout, edge logout, Cloudflare app/user token revoke and policy-edit acceptance. A tested revocation-sensitive authority must deny renewal; absent evidence remains incomplete, not silent pass. Timings include read latency/provider visibility;65s claim only with measured event and last frame/input, no undocumented introspection assumption. Unit fake-JWT checks cannot prove production custody/target revocation.

## Migration

Luna consumes additive RP mapping alongside original211 and RB mapping. Six unchecked tasks plus AC17, no frozen files or shared runtime implementation touched. CI strict spec/frozen checks, meaningful runtime fixtures and separately authorized target probes precede completion/archive. Preserve complete owned Resources bundle offline update/repair path.
