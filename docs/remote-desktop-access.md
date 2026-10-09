# Browser access to Hermes Desktop (RT-F01..RT-F03, AC13..AC15)

Remote access publishes one explicitly chosen hostname through a dedicated Cloudflare Tunnel. The hostname prompt starts blank, with no default domain. Setup requests allowed email addresses and a scoped Cloudflare management API token through hidden input, or resolves an approved secret reference. It separately asks for a minimum-read Access policy token reference using a protected keyring, secret-store, or private file locator; process-environment references are rejected for verifier credentials. Leaving it blank checkpoints the journaled OTP provider selection, Access app, and exact email policy at `access_ready`, records `POLICY_READ_REFERENCE_REQUIRED`, and leaves the tunnel and DNS unpublished. Resume with `remote_desktop.policy_read_token_ref` after placing the narrowly scoped token in the host credential store. The management token is never used as a verifier fallback. Setup discovers active authorized zones and the account attached to the selected zone. Only an isolated verifier custodian under its own installer-owned service identity resolves the read reference; the browser gateway receives a fixed AF_UNIX decision interface and never sees the secret or resolver. The verifier runs under a distinct non-root service UID from the gateway. It performs bounded GET-only reads of the exact owned Access app (resource UUID and its separate `aud` tag), every policy page, and the OTP identity provider, then repeats the reads to reject observed in-flight changes. Requests bind the signed JWT, principal, profile, config digest, action, session, peer UID and one-use nonce. Decisions fail closed after a cancellable nine-second read deadline. The read secret remains out of the gateway, Desktop, cloudflared, command arguments, environment, logs and checkpoint data. Until that reference is configured with account Access-application and policy read permissions, remote access remains unavailable. Missing account enrollment, permissions, certificate coverage, Pi runtime, or native isolation leaves access pending with a concrete resume step. Setup does not purchase a plan or broaden the requested scope.

Provision a dedicated installer-owned tunnel, exact DNS hostname, Cloudflare Access self-hosted application, email one-time-code identity provider, and allow-email policy. Reuse only compatible resources with verified ownership. Conflicts stop before mutation. Write an ownership journal before effects; after ambiguous API failures, read and reconcile the intended resource before retrying. Before each activation or resume attempt, the isolated minimum-read verifier rereads the exact owned app, complete policy set, and OTP provider. Activation also requires the native origin readiness check and a protected tunnel-token writer; the token is persisted to its dedicated private file before DNS is created. A missing, failed, or stale verifier/origin/token-store result leaves the hostname unpublished. The catch-all ingress returns 404.

Only the official Hermes Desktop Linux ARM64 app is streamed through a dedicated unprivileged Xpra seamless session and pinned minimal HTML5 client. The bridge does not attach to the host desktop. The command uses Xpra's supported seamless mode and real server options to disable shell, command handling, new commands, DBus, file movement/opening, URL opening, clipboard, printing, audio, camera, HTTP scripts, remote logging, and SSH/RFB/RDP upgrades. Xpra's `desktop`, `shadow`, and `proxy` names select broader modes; they are not boolean flags and are never used. The pinned upstream parser contract checks the generated argv at commit `521b0d2e762c770b2641d258b93d23575fa9cbea`. The service also disables daemonization and Xpra's own systemd launching so the reviewed installer supervisor owns the server process. Server window rules deny unmatched windows. Hidden client controls do not count as enforcement. Verify Electron renderer sandbox state on every launch; a no-sandbox fallback leaves remote access unavailable. Target-installed Xpra CLI compatibility remains part of Pi acceptance.

The loopback gateway allows only the pinned HTML5 client entrypoint, bundled JavaScript/CSS/icon assets, session, renewal and WebSocket routes; it denies Xpra connect, clipboard, digest, MITM, service-worker and diagnostic pages. The stock Xpra server menu is removed from presentation, while the server disables its corresponding operations independently; hiding controls is never the authorization boundary. HTTP asset frames and active connector streams have fixed size, time and concurrency bounds. The gateway checks only the enrolled hostname, browser Origin and exact route shape, then passes the raw Access JWT to the authenticated root authority. Root verifies the JWT signature, fixed issuer/audience, time claims and enrolled email allowlist, derives the principal/profile binding, and reads current application, every policy page and OTP provider from root-selected configuration before issuing an opaque, route-specific handle. Gateway-local claims, email headers, a PolicyGrant, or a self-signed context cannot authorize connector bytes. Root binds the handle to the gateway peer/generation, Desktop generation and fixed Xpra route; HTTP assets use one-shot handles, while WebSocket handles are leased and cannot change route. The gateway keeps root handles and renewal nonces server-side and returns only local session identifiers/challenges to the browser. Server leases cap at 60 seconds and a root/gateway watchdog checks no slower than five seconds. Renewal uses a separate fresh Access-protected HTTP request and one-use root challenge; stream frames cannot renew themselves. A lease deadline is anchored to fresh root authorization and no later than JWT expiry. Root connector reads/writes validate active session state and revoke/cancel both directions on closure or expiry. This does not claim immediate revocation where no tested current-policy or token/session revocation source is available. Explicit logout/revoke and policy removal are separate acceptance probes. Edge token expiry is not assumed to close an upgraded socket.

The setup management token is setup-only. Runtime cloudflared reads a dedicated tunnel token from a protected file; neither token enters command-line arguments, process environment, logs, evidence, or Desktop profile files. Disable, rollback, and uninstall reconcile resource IDs from the journal and remove only resources created by the installer.

## State and evidence

Configured means explicit hostname, zone, allowed emails, management secret reference, and a distinct policy-read token reference validate. `access_ready` is a resumable setup checkpoint and does not imply a live tunnel. Pending account means API permissions or Zero Trust enrollment are missing. Pending target means live Pi/account behavior remains unverified. Active requires Access, verifier, and origin readiness followed by ordered route activation. Code fixtures do not prove Pi acceptance.

Target acceptance records exact Pi/account identity, unauthorized HTTP and WebSocket denials before bytes/input, genuine Desktop pixels/control, blocked foreign-window and command attempts, Electron sandbox status, live socket expiry, policy-removal renewal denial, explicit logout closure, token revocation, user revocation, Access-app/IdP revocation, and owned-resource recovery as separate observations. Policy edits never imply that JWT or provider revocation was tested. Each unobserved revocation result remains pending. Do not record JWTs, API or tunnel tokens, email codes or credential values. Use the installer workflow configure/resume and doctor/verify commands with the remote_desktop hostname, allowed_emails, management_token_ref, and policy_read_token_ref; resolve each reference through the installer credential interface.

Live account setup is authorized by the installation choice once valid scoped credentials are supplied. Development and fixture runs do not mutate Cloudflare or activate a hostname.

## Root-observed session bridge (HI13 / HI-T13 / EV-HI13)

`authority.remote_sessions.RemoteSessionAuthority` is the root-side session coordinator. Its `RemoteSessionEnrollment` binds the exact hostname/origin, RS256 issuer/audience/JWKS origin, allowed-email reference, policy verifier and digest, registered gateway artifact/profile/generation, native Desktop profile/generation, fixed Xpra routes and connector target, and a protected subject/email-to-host-profile map. `RootRemoteAccessVerifier` invokes the strict Access JWT verifier in the root process and performs a fresh selected-policy read through the separate read-only verifier credential before any connector can open. The gateway request schema contains only request ID, hostname, origin, fixed route/action and a client nonce; email, subject, token fingerprint, policy grant, connector URL, PID and lease claims are rejected as extra fields.

Admission returns only an opaque 256-bit root lookup handle and bounded session metadata. The root session table retains the verified subject/email/fingerprint, mapped principal/profile, actual gateway process identity, selected policy revision/config digest, native and gateway generations, route, JWT deadline and lease. Renewal uses a separate root-issued one-use challenge, re-verifies the submitted Access token and current policy, and requires the same subject/email/profile and unchanged generations. Asset admissions allow one connector and one bodyless GET/HEAD write frame whose path must be in the pinned Xpra client-asset manifest; all other asset writes are denied. The returned asset bytes are limited to 2 MiB. WebSocket sessions use one root connector, a shared sequential frame number and a 1 MiB per-frame limit. The connector authorizer receives only root-derived bindings and mints a fresh one-use HI12 grant over the exact canonical HI07 payload, including operation, route, target, session, generation, sequence, deadline and bounded frame bytes. A five-second frame deadline, 60-second maximum lease, and watchdog interval no greater than five seconds close live relays on expiry, identity/configuration drift, cancellation, or verifier failure. Root connector cleanup remains available after an expired grant and cannot carry data.

The executable implementation and signed JWT/policy/connector negative tests are fixture evidence only. `AuthorityService` registration, the protected enrollment loader, production root gateway process resolver, HI12 connector backend and its grant issuer must be wired before the remote bridge can be activated. Live Cloudflare edge renewal/revocation, native Desktop bytes/window confinement, and target/account acceptance remain open. No Cloudflare account or Pi was contacted by these fixture tests; a passing fixture is not EV-HI13 target acceptance.


## Policy-read custodian service

Fresh Access membership checks use a second least-privilege credential scoped to read the installer-owned Access application, all its policies, the exact OTP provider, and account metadata needed for those reads. This is distinct from setup-management credentials. It is resolved only inside a dedicated non-root custodian process; the browser gateway has no resolver, token reference, or Cloudflare API credential. The custodian's persisted JSON contains only journaled resource IDs, the fixed issuer and JWKS, email set, audience tag, credential reference, socket path and numeric service identities. Config is a service-owned private regular file. The gateway and custodian have different UIDs; the AF_UNIX socket is service-owned, non-world-accessible, and authenticated with Linux peer credentials. Parent directories reject symlinks, foreign ownership, and group/world write access. The root authority accepts only the fixed HI13 admit/challenge/renew/close and remote connector operations. Its protected enrollment selects the issuer, audience, JWKS origin, allowlist reference, policy-verifier enrollment, gateway/Desktop generations and route IDs; caller payloads cannot choose a principal, profile, connector target, lease or credential reference.

An exact current-policy decision requires repeated bounded reads of the same application, complete bounded policy set and selected OTP provider. Resolver, API, cancellation or time-bound failure denies. The runtime lock contains only the dedicated component environment. The separate CI fixture lock targets x86-64 Python 3.13 and is test-only; it does not replace the hash-pinned ARM64 Python 3.14 runtime lock or prove Pi readiness.

Host startup and shutdown still require the installer-owned systemd/cgroup supervisor and native service acceptance. A fixture UID exchange proves the Linux peer-credential boundary only; it is not proof of systemd custody, Pi identity, Access-policy propagation, Desktop sandbox, or Xpra process/window confinement.
# Root tunnel credential and origin readiness

The active root enrollment selects the Cloudflare tunnel, account, secret
reference, runtime UID and protected token sink. The root authority resolves
only the dedicated tunnel credential and writes it beneath a root-owned `0700`
directory to a `0400` file. The unprivileged cloudflared systemd unit receives
that file through systemd `LoadCredential=`; the service reads only its private
credential copy, and the gateway receives no token. Cloudflare management
credentials remain in setup storage. The writer uses a durable intent before
publishing, descriptor-anchored atomic create-only publication, and an
ownership journal containing only the credential digest and file identity. A
pre-existing or changed sink stops setup without replacement. Installer and
gateway receipts contain only selected IDs and protected inode metadata, never
token bytes, token digest, or filesystem path.
The root validates Cloudflare's encoded tunnel-token envelope against the
selected account and tunnel UUID using the pinned [`cloudflared` 2026.10.0 token fields](https://github.com/cloudflare/cloudflared/blob/2026.10.0/connection/connection.go).

Cloudflare route activation requires a signed, short-lived
`RootOriginReadinessReceipt` from the root authority. It binds the active
gateway and Desktop generations, connector target, policy digest/revision and
service generation, and the opaque handle for one root-registered probe. Root
checks the gateway and native Desktop PIDFDs, start time, pinned executable,
cgroup, namespaces and mount. A separate setup transaction binds the current
setup process, selected tunnel response, dedicated writer role and probe role;
its one-use origin-probe handle expires within 30 seconds. The root client
connects only to the active catalog's private AF_UNIX socket, verifies the
gateway peer PID/UID/GID, and sends three bounded per-action commands, each
with a fresh immutable child handle: pinned asset GET, pinned asset HEAD, and
WebSocket attach. The gateway returns measured bytes, status and digests; its
response cannot set readiness booleans. The root joins those results with
separately root-observed loopback listener and denial-route facts plus a
native-window observation bound to the selected Desktop PIDFD and WebSocket
stream. Missing boundary/window observers, a stale proof, or an unexpected
route response leaves readiness unavailable. Root registers its own signed
probe receipt only after all joins pass. Receipts expire within 30 seconds and
must pass root signature, selection, digest and expiry checks at the activation
boundary. The isolated loopback/AF_UNIX fixture proves byte-level protocol
behavior; it does not prove production observers, connector custody, or target
readiness.

Fixture evidence exercises private file effects, collision refusal, signed
receipt validation and real isolated loopback socket exchanges. It does not
enroll or prove a live Cloudflare account, Pi, browser identity, or native
Hermes Desktop target.
