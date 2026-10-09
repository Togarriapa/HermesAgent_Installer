# Remote Desktop access Delta

## Purpose

Provide automatically configured Cloudflare-protected browser access only to the official native Hermes Desktop app, preserving host/user/cloud resource isolation and truthful target readiness.

## ADDED Requirements

### Requirement: R0196 direct-user remote Desktop obligation
The wizard SHALL ask for the desired hostname with an empty input and no prefilled/default domain, validate it and require explicit user selection for noninteractive configuration.

#### Scenario: R0196 Blank hostname and historical value
- **WHEN** wizard starts with no configured hostname or user submits blank/invalid input
- **THEN** the input SHALL remain blank initially; blank/invalid data SHALL be rejected without API mutation; hermes.togarriapahome.uk SHALL NOT be silently supplied

#### Scenario: R0196 Explicit hostname
- **WHEN** the user enters a valid authorized hostname through wizard or validated config
- **THEN** plan SHALL use exactly that hostname and show the matched account/zone; no unrelated DNS names SHALL be modified

### Requirement: R0197 direct-user remote Desktop obligation
The wizard SHALL securely request a scoped Cloudflare API token or secret reference, explain official permissions and discover authorized account/zone without logging token values.

#### Scenario: R0197 Scoped token discovery
- **WHEN** secure input/reference resolves a token with read access to one account and the zone containing the entered hostname
- **THEN** discovery SHALL identify the exact authorized account/zone, validate needed edit permissions and prompt selection only for genuine ambiguity; secrets SHALL not appear in source/argv/log/evidence

#### Scenario: R0197 Insufficient token
- **WHEN** token validation returns403 or no matching editable zone
- **THEN** setup SHALL stop before mutation with exact missing permission/ownership and resume guidance; no global API key or broader unrelated authority SHALL be requested automatically

### Requirement: R0198 direct-user remote Desktop obligation
The installer SHALL automatically provision or reuse a dedicated installer-owned Cloudflare Tunnel and least-privilege runtime credential under the selected account.

#### Scenario: R0198 Create owned tunnel
- **WHEN** selected token/account/hostname intent is valid and no matching owned tunnel exists
- **THEN** adapter SHALL create one tagged/ledger-owned tunnel, capture its resource ID/checkpoint and generate runtime-only cloudflared credentials through secure references; admin API token SHALL NOT enter runtime Desktop/cloudflared environment

#### Scenario: R0198 Idempotent reuse
- **WHEN** resume/repeated install finds the same owned resource IDs and compatible config
- **THEN** adapter SHALL reuse rather than duplicate tunnel, reconcile actual state before retry after ambiguous API result and preserve any unowned tunnel

### Requirement: R0199 direct-user remote Desktop obligation
The installer SHALL automatically configure the exact DNS hostname route and tunnel ingress to the loopback Desktop authorization gateway with a terminal404 catch-all.

#### Scenario: R0199 Exact ingress and DNS
- **WHEN** owned tunnel has healthy loopback gateway and the entered hostname has no conflicting unowned DNS record
- **THEN** adapter SHALL create the exact tunnel DNS route/hostname ingress plus final404 catch-all and SHALL NOT expose raw Desktop/backend/Xpra/SSH/host-management ports

#### Scenario: R0199 Conflicting DNS
- **WHEN** hostname already has an unowned conflicting DNS record or another tunnel ingress
- **THEN** adapter SHALL leave that record/tunnel unchanged, report the conflict and selected-identity resume step, and SHALL NOT overwrite/repoint it blindly

### Requirement: R0200 direct-user remote Desktop obligation
The installer SHALL automatically configure Cloudflare Access self-hosted application, email one-time-code login and explicit allowed-email policy for the entered hostname.

#### Scenario: R0200 Automatic email-code Access
- **WHEN** the configured allowed-email list is nonempty and token permits reviewed Access application/policy/identity-provider operations
- **THEN** adapter SHALL create/reuse only the owned app/policy and documented compatible one-time-code provider, bind entire hostname HTTP and WebSocket routes, and require allowlisted identity before any origin content

#### Scenario: R0200 Conflicting or unsupported Access
- **WHEN** an unowned broad Access app overlaps hostname, provider/account eligibility is unavailable or policy cannot be verified
- **THEN** activation SHALL fail closed with exact state/resume reason; no public/bypass policy, local-password substitute, paid purchase or modification to unrelated account policies SHALL occur

### Requirement: R0201 direct-user remote Desktop obligation
Remote origin SHALL validate signed Cloudflare Access JWT algorithm, signature, configured issuer/audience, time claims and allowed principal before serving any asset, pixel, control or stream.

#### Scenario: R0201 JWT denial matrix
- **WHEN** GET asset/page or WebSocket upgrade presents missing/forged/expired/wrong-issuer/wrong-audience JWT or unallowed email
- **THEN** gateway SHALL reject before forwarding upstream bytes/controls, ignore spoofed email-only headers and record redacted denial; user/backend session SHALL not start

#### Scenario: R0201 Verified JWT and key rotation
- **WHEN** request carries valid configured Access JWT and currently trusted HTTPS JWKS key
- **THEN** gateway SHALL admit only configured paths/principal with bounded key cache/clock tolerance; unknown keys or unavailable stale trust data SHALL fail closed

### Requirement: R0202 direct-user remote Desktop obligation
Remote gateway SHALL allow only dedicated Desktop client assets/session/renewal/WebSocket routes and reject arbitrary targets, paths, origins and backend-management transports.

#### Scenario: R0202 Route and transport denial
- **WHEN** authenticated browser requests /terminal,/ssh,/api/backend or supplies arbitrary Xpra server URL/display/hostname
- **THEN** gateway SHALL return denied404/403 without upstream connection; no shell, full host desktop, backend management or arbitrary origin proxy SHALL be exposed

#### Scenario: R0202 Fixed upstream
- **WHEN** allowlisted Desktop WebSocket handshake uses expected browser origin and principal-bound session token
- **THEN** gateway SHALL route only to the owned loopback application-stream session and strip/limit untrusted forwarding headers; raw bridge listener remains private

### Requirement: R0203 direct-user remote Desktop obligation
The remote bridge SHALL stream the genuine official Hermes Desktop application in a dedicated constrained native session, never a web dashboard or whole existing host desktop.

#### Scenario: R0203 Only native app windows
- **WHEN** authorized principal starts the selected remote session on a supported ARM64 Pi
- **THEN** bridge SHALL launch pinned official Hermes Desktop under the intended unprivileged user/session and export only its allowed application windows; no host-panel/terminal/desktop capture appears

#### Scenario: R0203 Unsupported app-only confinement
- **WHEN** only shadow/full-desktop mode, insecure Electron sandbox escape or unrelated application-window forwarding works
- **THEN** remote Desktop SHALL remain unavailable with exact supported-resolution next step; a browser dashboard or unsandboxed whole-display fallback SHALL NOT be labeled protected Hermes Desktop

### Requirement: R0204 direct-user remote Desktop obligation
The bridge SHALL disable remote new-command/session/shell/control, file transfer/opening, clipboard, printing, device/audio and unnecessary proxy/debug features through server controls.

#### Scenario: R0204 Host escape attempt
- **WHEN** authenticated fixture client submits start-command,start-desktop,shell/control,file/clipboard/printing or arbitrary-display packets
- **THEN** actual bridge/server policy SHALL deny without spawning processes/opening files/accessing host devices; hiding HTML controls alone SHALL not count as enforcement

#### Scenario: R0204 Restricted client
- **WHEN** minimal client connects to fixed admitted native app session
- **THEN** only necessary screen/input operations SHALL load; retained browser/Electron sandbox and private X authority SHALL isolate the session from unowned host display/processes

### Requirement: R0205 direct-user remote Desktop obligation
Each remote browser session SHALL bind verified Access principal and native profile state; concurrent access SHALL respect configured one-session limits and prevent cross-user state/session hijack.

#### Scenario: R0205 Cross-principal replay
- **WHEN** user B replays user A session ticket or requests A display/home while both are allowed-email identities
- **THEN** gateway/session broker SHALL deny before pixels/context/input, keep profile namespaces separate and never run concurrent writers in one HERMES_HOME

#### Scenario: R0205 Resource limit
- **WHEN** one managed remote session is active and a second request would exceed configured CPU/RAM/concurrency allowance
- **THEN** new request SHALL return a bounded busy/queue response, preserve core chat and existing session, and not create duplicate native workers

### Requirement: R0206 direct-user remote Desktop obligation
Active WebSocket input/output SHALL stop on JWT expiry or stale authorization lease; revocation SHALL be enforced through bounded fresh protected HTTP renewal, not assumed edge socket termination.

#### Scenario: R0206 Long-lived socket expiry
- **WHEN** an admitted WebSocket JWT expires or its short authorization lease is not renewed through a fresh protected request
- **THEN** gateway watchdog SHALL close forwarding/input by configured bounds and discard the ticket; an existing socket SHALL not remain authorized merely because its initial upgrade passed

#### Scenario: R0206 Revoked session
- **WHEN** edge denies fresh protected renewal after Access revocation/allowed-email removal
- **THEN** origin SHALL stop the stream within at most configured lease duration, require fresh login to reconnect and fail closed when current validity cannot be established; WS frames cannot renew their own lease

### Requirement: R0207 direct-user remote Desktop obligation
Cloudflare/remote component lifecycle SHALL be checkpointed, idempotent and ownership-aware across automatic setup, resume, update, rollback, disable and uninstall.

#### Scenario: R0207 Partial API failure
- **WHEN** tunnel/app/DNS creation succeeds partially then a timeout/429/process crash occurs
- **THEN** journal SHALL retain exact owned IDs, reconcile remote result before retry and resume without duplicates; rollback SHALL touch only positively owned resources and preserve unrelated DNS/apps/tunnels/policies

#### Scenario: R0207 Config update rollback
- **WHEN** owned hostname/policy/service update fails health/auth/app-only checks
- **THEN** prior protected working configuration SHALL remain/restored, external changes with uncertain ownership SHALL be quarantined and active public routes SHALL never bypass Access while recovering

### Requirement: R0208 direct-user remote Desktop obligation
Cloudflare setup SHALL activate public DNS/ingress only after Access protection and loopback origin validation are ready, with a fail-closed transaction order.

#### Scenario: R0208 No exposure window
- **WHEN** setup is interrupted after tunnel creation but before validated Access policy or gateway health
- **THEN** public route SHALL remain absent/inactive or terminate404; no native GUI/assets/backend SHALL be reachable unauthenticated during any intermediate checkpoint

#### Scenario: R0208 Protection first
- **WHEN** Access app/policy, JWT gateway and constrained native session checks pass
- **THEN** DNS/ingress activation SHALL be the final bounded owned-resource step followed by unauthorized HTTP/WS and allowed-principal functional probes

### Requirement: R0209 direct-user remote Desktop obligation
Cloudflare management token SHALL remain only in secure setup credential storage; runtime cloudflared receives dedicated tunnel credential and gateway receives only necessary nonsecret trust/session configuration.

#### Scenario: R0209 Secret canary separation
- **WHEN** setup token and tunnel credential are synthetic distinguishable canaries and runtime services start
- **THEN** runtime env/argv/logs/config/evidence SHALL contain no setup/admin token; tunnel credential SHALL be delivered through supported secret-file/reference mechanism and sensitive diagnostic fields redacted

#### Scenario: R0209 Revoke or rotate
- **WHEN** runtime tunnel token is revoked/rotated while a scoped management reference remains unavailable
- **THEN** runtime SHALL fail/recover with explicit credential status and bounded reconnect; it SHALL not escalate to the management token or leak secret values

### Requirement: R0210 direct-user remote Desktop obligation
The wizard/CLI SHALL support configure-later, secure noninteractive references, automatic setup resumption and component doctor/verify without repeated routine approvals.

#### Scenario: R0210 Configure later
- **WHEN** user skips hostname/token/allowed emails or no target is enrolled
- **THEN** other independent installer work SHALL continue; remote component SHALL be pending with exact missing field and resumable command, never green or dropped

#### Scenario: R0210 Noninteractive setup
- **WHEN** validated hostname/account-selection/allowed-email and secret-reference config is supplied
- **THEN** installer SHALL perform already-authorized scoped owned-resource setup automatically, emit structured checkpoint/errors and request input only for genuine ownership/conflict/account ambiguity

### Requirement: R0211 direct-user remote Desktop obligation
Remote acceptance SHALL separately prove unauthorized HTTP/WS denial, actual official Desktop pixels/control, app-only confinement, expiry/revocation and owned-resource recovery on the exact target/account.

#### Scenario: R0211 Fixture versus live proof
- **WHEN** API/JWT/bridge fixtures pass but physical Pi/Cloudflare credentials are absent
- **THEN** code/config/fixtures/docs/executable target-verifier SHALL be delivered, while live protected Desktop/account/DNS acceptance remains pending with exact target/credential resume input

#### Scenario: R0211 Actual target functional proof
- **WHEN** enrolled Pi/Cloudflare account and allowed test principal are selected
- **THEN** verifier SHALL record candidate/source/service/resource IDs, unauthorized GET/assets/WS denial, native Hello/tool/cancel/restart and expiry/revocation/isolation/lifecycle results with redacted digests; configured-only tunnel status SHALL not pass

### Requirement: Root-observed remote session bridge
The installer SHALL verify actual Access JWT and fresh root selected policy at root authority, join verified identity to current native profile and bind every asset/input/stream operation to fixed connector session lease/generation. Gateway local or selfsigned claims SHALL not authorize root effects.

#### Scenario: Forged gateway claims or expired active stream
- **WHEN** root JWT/policy/principal verification fails or active lease revokes/expires
- **THEN** deny before bytes or close both stream directions within tested bounded lease and preserve setup/read/tunnel credential separation.

### Requirement: Typed remote root session wire
The installer SHALL expose distinct one-shot asset and leased WebSocket admissions through peer-bound opaque root handles and finite typed connector operations that check current session state and fresh exact grants internally.

#### Scenario: Asset handle reused for WebSocket or caller chooses connector
- **WHEN** caller reuses consumed asset admission, selects target/path or sends frame after root lease expiry
- **THEN** reject before bytes and close owned relay without localcontext or raw FD bypass.

### Requirement: Protected runtime assembly identities
The installer SHALL load strict root-owned active generation catalogs, verify immutable native closure/device kernel isolation, attest actual successful build output dynamically and sign the exact full connector effect payload digest.

#### Scenario: Preclaimed build hash or partial effect digest
- **WHEN** output was not actually attested after terminal success, closure/import/device identity differs or grant signs only partial payload
- **THEN** deny activation/effect without permissive fallback and preserve truthful failure/native evidence.

### Requirement: Root remote controller and native principal binding
The installer SHALL bind verified remote native principal and actual gateway kernel controller separately through a dedicated root-internal one-use connector issuer, active protected policy/OTP enrollment and actual origin/token/closure receipts. Normal worker contexts SHALL not be relabelled and gateway SHALL receive no policy/setup credential resolver.

#### Scenario: Gateway context relabel or metadata-only origin activation
- **WHEN** caller claims native principal from gateway context or activation lacks actual current root readiness/token/mount proof
- **THEN** deny before bytes/activation, preserve configured checkpoint and exact native/account resume requirements.

### Requirement: Selected backend and actual gateway role bindings
The installer SHALL resolve protected resource backend/body recipe/action/source/consent scope before each child effect and SHALL verify actual launched gateway role against explicit HI13 protected profile-role association.

#### Scenario: Legacy backend metadata or unobserved gateway role
- **WHEN** only declared backend/role metadata exists without current root selected effect/actual launch proof
- **THEN** deny backend/admission before bytes and retain exact incomplete implementation/native evidence.

### Requirement: Exact protected execution joins
The installer SHALL resolve each effect from its exact selected active node, scope, observer and setup role joins, with fresh bounded authority and immutable result ancestry.

#### Scenario: Mismatched backend or setup identity
- **WHEN** a node selects a different backend, an event/result lacks root-observed closure, or runtime tunnel identity requests setup writer/probe authority
- **THEN** root rejects before effects and preserves pending original acceptance; no caller booleans or consumed grants substitute for proof

### Requirement: Separate private setup probe authority
The installer SHALL authorize private origin probes through a separate root-owned setup binding and exact fresh connector effects, without fabricating public Access sessions or worker profile contexts.

#### Scenario: Setup probe submitted to public issuer
- **WHEN** a private probe handle or synthetic Access context reaches the public remote connector issuer
- **THEN** it is rejected, and only the separate root-private exact probe issuer may admit selected local app readiness operations

### Requirement: Existing observation assembly joins
The implementation SHALL apply the exact root registry, principal-selection and protected observation joins relevant to this change in `plans/amendments/2026-10-09-final-observation-assembly-v31.md`.

#### Scenario: Static selection lacks actual runtime proof
- **WHEN** an actual current role, display, source event or terminal execution receipt is absent
- **THEN** the affected observation remains pending and no caller claim or catalog presence substitutes for runtime evidence

### Requirement: Fixed selected display and loopback startup
The installer SHALL launch only enrolled official Desktop/display/gateway recipes with exact Xauthority mount and private loopback role/port bindings.

#### Scenario: Ambient display or broad network substitution
- **WHEN** a worker supplies display credentials, arbitrary port or unenrolled network role
- **THEN** startup or connection denies before app bytes and remote acceptance remains pending

### Requirement: Root selected startup and predecessor custody
The installer SHALL use actual root source CAS/predecessor proofs and finite selected startup admission with fresh role-specific child grants.

#### Scenario: Unbound startup or deployment predecessor
- **WHEN** caller state substitutes root startup admission or ignores an existing deployment pointer
- **THEN** startup/publication denies without overwriting unowned or mismatched state

### Requirement: Actual selected Xpra root credential
The installer SHALL prevent selected Xpra from regenerating or exposing root display cookie and verify the fixed readonly root credential is used by its owned virtual X server and official Desktop.

#### Scenario: Writable cookie or secret argv fallback
- **WHEN** selected startup falls back to a generated cookie or passes secret cookie values in argv/logs
- **THEN** startup fails closed and remote readiness is not asserted
