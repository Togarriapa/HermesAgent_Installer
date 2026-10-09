## ADDED Requirements

### Requirement: Separate read credential enrollment (RP01)

The installer SHALL securely collect or resolve a distinct account-scoped minimum-read Access credential for an isolated policy verifier, independently of the setup-management token and tunnel credential. It SHALL keep blank hostname and automatic owned setup, request only genuinely missing fields, and report configure-later/incomplete when the read authority is unavailable.

#### Scenario: RP01 enforced effect

- **WHEN** only setup-management token is supplied
- **THEN** owned setup can checkpoint, but remote activation and session issue remain incomplete with exact read-reference resume field; no management-token runtime fallback

### Requirement: Isolated verifier credential custody (RP02)

A dedicated least-privilege verifier SHALL hold the read credential in protected host custody. Desktop, cloudflared and the browser-facing gateway SHALL receive no setup/read secret or resolver; gateway receives only authenticated, narrowly scoped decision messages. The verifier SHALL perform fixed GET requests for journal-selected account/app/policy/OTP identity and SHALL expose no generic API proxy or mutation operation.

#### Scenario: RP02 enforced effect

- **WHEN** a compromised gateway requests another account, arbitrary URL, write method or secret dump
- **THEN** verifier rejects before network effects; OS identity/socket/filesystem/process controls prevent credential reading; secret canaries absent from argv/environment/logs/repr/profile/evidence

### Requirement: Fresh exact Access membership authority (RP03)

Before initial authorization, socket opening and each separate protected-HTTP renewal, the verifier SHALL freshly read the exact owned app, complete bounded app-policy set and selected identity-provider resource, match sole intended OTP IdP, exact hostname and explicit email policy with no broadened/unsupported rules, and deny errors, conflicts, missing pages, unsupported policy semantics or stale observations. Valid JWT signatures and a fresh HTTP request alone SHALL not establish current policy membership.

#### Scenario: RP03 enforced effect

- **WHEN** a still-valid JWT is presented after allowed-email removal, extra policy addition, IdP replacement or read failure
- **THEN** no new grant or lease extension occurs; the previous bounded lease expires without fallback; malformed/order-only policy responses are interpreted with explicit safe semantics

### Requirement: Bounded freshness and cancellable read decisions (RP04)

Each verifier request SHALL have a hard total deadline at most9 seconds including bounded TLS reads/pages/retries, bounded workers/queue and cancellation that cannot leave accumulating secret-bearing tasks. Decisions SHALL be single-use, bound to authenticated peer/principal/app/config/nonce and monotonic observation interval. Lease deadline SHALL be no later than read-start+60 seconds or JWT expiry; watchdog SHALL stop input/output within5 seconds of the deadline. Late results SHALL never renew expired/cancelled sessions.

#### Scenario: RP04 enforced effect

- **WHEN** a renewal read hangs or completes9 seconds after a policy removal concurrent with the read
- **THEN** existing lease is not extended while waiting; pending operation is bounded and discarded on timeout/cancel; read latency does not add to60-second authorization age; no accumulating threads or replayed allow

### Requirement: Read-role lifecycle and secret preservation (RP05)

Setup SHALL retain management credential only in secure setup custody and SHALL never mint API tokens using assumed administrator grants. Read credential rotation/expiry/revocation, disable, restart, update, backup/restore and uninstall SHALL preserve ownership, securely reference credentials, invalidate old decisions and fail closed until current authority is verified. Uninstall SHALL remove only owned local credential artifacts, never revoke or delete unowned account tokens/resources.

#### Scenario: RP05 enforced effect

- **WHEN** restored configuration names a missing/expired read reference or verifier service stops
- **THEN** remote remains incomplete, all leases stop at their existing deadlines or earlier, no setup-secret promotion or plaintext backup leak; resumable secure rotation and fresh validation required

### Requirement: Distinct revocation evidence and readiness (RP06)

Verification SHALL distinguish policy/email removal, local logout, Cloudflare application/user token revocation, JWT expiry, read-token revocation and verifier/network outage. A policy read SHALL not be claimed to prove JWT/token revocation. Remote readiness SHALL require actual production verifier custody and transport plus signed-JWT/HTTP/WS tests and exact-target/account evidence for AC15; no usable-by-default60-second shortcut.

#### Scenario: RP06 enforced effect

- **WHEN** policy-removal fixture passes but Cloudflare token-revoke behavior has not been observed
- **THEN** policy enforcement evidence is recorded separately; token/logout revocation acceptance stays pending rather than inferred or waived; live bounds identify event timing and provider visibility
