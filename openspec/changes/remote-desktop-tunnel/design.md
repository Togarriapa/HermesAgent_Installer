# Design

## Context

See proposal and planning/user-additions/2026-10-09-remote-desktop.md. The final direct instruction overrides suggested hostname prefill: prompt is blank. Access email one-time codes are selected; do not implement a separate local-password system. The user authorizes automatic scoped setup from secure installer token input; no Pi/account token exists in this development session.

## Goals / Non-Goals

Goals: native application-only browser access, automatic owned Cloudflare setup, enforceable admission/session/recovery contracts and executable target evidence.
Non-Goals: whole-host desktop/shadow/SSH/web-dashboard substitution, public raw backend management, unowned cloud resource overwrite or live account/host mutations in this planning stage.

## Decisions

Use a reviewed supported Linux ARM64 Xpra seamless application server and its pinned minimal HTML5 client behind an installer-owned loopback HTTP/WebSocket authorization gateway. Official Xpra seamless mode exports application windows; desktop/shadow modes expose broader desktop and are forbidden. Native official Hermes Electron remains the app; this is a transport/session adapter, never a dashboard substitute. Native Linux ARM64 Debian servers are upstream tier3, so no Pi packaging/functionality promise is made. X11 dedicated session is the documented broad-compatibility path; experimental Wayland is not assumed supported. Verify pinned CLI flags/options and dependencies before generating services, do not blindly use outdated example `start` names.

Create dedicated unprivileged per-principal/profile application sessions with private X authority and no host display capture/window manager/terminal. Export only approved Hermes app windows/process lineage; deny unrelated windows and automatic external-browser/open-command launches. Server must disable start-new-commands, desktop/shadow/proxy session creation, shell/control/dbus, file-transfer/open-files, clipboard, printing, webcam/audio/device integration, remote logs and unneeded HTTP diagnostics. Hiding the HTML menu is only UX; raw protocol denial is required. Use minimal fixed-upstream HTML client, not the upstream generic connect/start/display form. Keep Electron/browser sandbox; Xpra's optional seccomp/Landlock support is architecture/kernel dependent and is not assumed ARM64 isolation. Actual OS confinement and mandatory registry dispatch remain required; unsupported confinement blocks only remote activation with exact reason.

Gateway accepts only fixed routes for client assets, principal session attach, protected renewal and WebSocket. Validate Access JWT with an audited pinned library, allowed asymmetric algorithm and HTTPS team-domain JWKS; require configured issuer/audience/exp/nbf and allowed email, bounded key cache/clock skew, reject forged email headers. Bind sessions/tickets to verified principal and profile, validate browser Origin and expected hostname, strip unsafe forwarded headers and deny arbitrary target/path/display. All raw origin/bridge/backend listeners bind loopback or owned Unix sockets; only cloudflared reaches the gateway. Authentication precedes bytes/pixels/input/worker spawn, including assets.

Cloudflare validates HTTP requests, but an already-upgraded WS may survive edge identity expiry/revocation. Implement short server-side authorization lease (default60s, configurable capped maximum60s) plus expiry watchdog (default5s), renewable only via separate freshly Access-protected HTTP challenge/renewal bound to principal/socket and one-shot nonce. WS frames cannot renew their own authorization. Leases never outlive JWT exp. Fresh edge renewal after policy removal/session revocation must be denied in actual tests; missing/uncertain renewal closes stream. Signature checks alone do not detect revocation. If upstream/account cannot provide the tested renewal/revocation semantics, fail closed and report remote unavailable rather than claiming protection. This narrows revocation to bounded<=60s, not instantaneous edge WS termination.

Cloudflare API adapter uses secure management token reference only during setup/check/update. Discover matching active zones with Zone Zone Read (dashboard Zone Read), derive account ID from zone response rather than require broad account enumeration, and verify scoped Cloudflare Tunnel Write/Edit, DNS Write/Edit, Access Apps and Policies Write, and Organizations/Identity Providers/Groups Write when creating OTP provider. Fetch the Zero Trust organization via GET /accounts/{account_id}/access/organizations and its auth_domain for JWT issuer; absent enrollment produces actionable configure-later rather than a paid purchase. Match account/zone uniquely when possible, prompt only genuine ambiguity. Configure Access app allowed_idps to the exact reviewed OTP provider ID (type onetimepin); otherwise the API can default to all IdPs. Reuse compatible existing OTP without owning/removing unrelated settings. Validate zone/certificate coverage for entered hostname; deeper names needing a paid certificate stop under zero-spending policy. Journal exact intent/resource ownership IDs and pre-state before mutations. Prepare Access email-code identity provider/app/allow-email policy and guarded loopback origin before final exact-hostname DNS/ingress activation; catch-all404 covers unmatched requests. Adopt only positively owned matching resources; conflicts/unowned overlapping DNS/apps/tunnels stop with actionable status, no blind overwrite. Pin official cloudflared2026.10.0 Linux ARM64 asset SHA256 e6422b9d4f72d3194bc5a38676f13667c06666523217b842a877d72a80b5ac08 (37687584bytes). Remote-managed tunnel uses config_src=cloudflare and documented ingress/config API. Selected release supports --token-file (>=2025.4.0); use protected runtime token file, never the upstream service-install TOKEN argv example or management API token in runtime env. Read actual state after ambiguous network failures before retry; API429 and permission errors are bounded. Runtime services are owned and unprivileged; update/disable/rollback/uninstall reconcile only owned resources, preserving unrelated account policies and host services. Shared existing email-code provider may be reused but never removed or altered as if installer-owned.

## Risks / Trade-offs

- Seamless Xpra does not by itself enforce host authorization -> dedicated native session/process/window policies plus real raw-protocol denial and window leakage tests; block if not proven.
- Linux ARM64 packaging/kernel feature drift -> native supported packages or reviewed source build; no x86 emulation/no-sandbox escape; record actual package/image digests.
- WebSocket edge auth expiry is not active-socket revocation -> bounded fresh protected HTTP lease enforcement, negative expiry/revocation/current-validity tests.
- Token privilege/ambiguous mutation/cloud conflict -> scope discovery, secret separation, ownership journal, reconcile before retry and no unowned overwrite.
- Temporary public exposure on partial setup -> protection/gateway first; route activation last; interrupted checkpoints yield404/denied, never unprotected content.

## Migration Plan

Implement API recorder/JWT/clock/bridge fixtures and docs in foundation tasks. Add config fields with blank hostname and allowed-email secure setup; propagate refs only. Stage native session/gateway/service; preview exact owned cloud operations then execute already-authorized scope automatically. Verify unauthorized HTTP/assets/WS and allowed principal/native app/expiry/revocation; only then claim remote protected. Preserve all original twelve acceptance workflows and add AC13..15. Missing Pi/token blocks live mutation/tests only; all code/fixtures/docs/target workflow remain required.

Root-observed remote session bridge HI13: plans/amendments/2026-10-09-remote-root-session-bridge-v1.md and planning/remote-root-session-bridge-contract.json specify actual JWT/current policy/root principal binding, no gateway selfsigned claim substitute, fixed allbytes connector lease and active revocation. Management/read/tunnel credential separation preserved; native/account evidence open.

HI13 remote root wire v2: plans/amendments/2026-10-09-remote-root-session-wire-v2.md defines typed opaque responses/challenge/rootselectedconnectorframes, distinct one-shotasset/leasedWS, internal freshHI12grant enforcement. ExistingHI-T13/RT-F03 and actualtarget evidence remainopen.

Protected runtime assembly v1: plans/amendments/2026-10-09-protected-runtime-assembly-v1.md and planning/protected-runtime-assembly-contract.json define rootactivegeneration catalog, exact native closure/import/mount, devicekernelpolicy, dynamicbuild outputreceipt and fullcanonical effectdigest/rootpeeridentity. ExistingHI07/08/09/11/13/HW02/03 tasks/evidence remainopen.

Remote dual-principal issuer/closure proof v3: plans/amendments/2026-10-09-remote-dual-principal-issuer-closure-proof-v3.md binds activeenrollment OTP/principal/gateway records, dedicatedroot perframeissuer withoutcontextrelabel, isolatedverifierclient, actualtoken/origin receipts and loadedclosure proofs. ExistingHI08/09/11/13/RP/RTtasksremainopen.

Resource backend/remote role v4: plans/amendments/2026-10-09-resource-backend-remote-role-v4.md defines activeRB07 selectedbackend/bodyrecipe joins/freshchildeffects andexplicitHI13profile-role plusactualrootlaunchproof. ExistingRB-T08/HI-T13remainopen.

Resource DAG/remote setup joins v5 (HI13 / EV-HI13 and original remote setup tasks): see plans/amendments/2026-10-09-resource-dag-remote-setup-joins-v5.md and the live resource/native/assembly/remote contracts. Per-node protected joins and root-observed provenance are mandatory; existing implementation and target acceptance remain open.

Private origin probe connector v11: plans/amendments/2026-10-09-private-origin-probe-connector-v11.md defines separate root-private typed issuer/consumer using exact existing HI12 payload/operation authority. Public RemoteSessionBinding/Access path unchanged; all HI13/remote target tasks remain open.

Additive observation assembly v31: `plans/amendments/2026-10-09-final-observation-assembly-v31.md`; preserve existing task IDs and open target gates. Selected root registries/current custody receipts supply actual observations; static catalog or caller claims do not.

Selected display/loopback startup v60: `plans/amendments/2026-10-10-selected-display-loopback-startup-v60.md`; existing task/acceptance gates remain open.

Bootstrap CAS/selected start grants v65: `plans/amendments/2026-10-10-bootstrap-cas-selected-start-grants-v65.md`; existing task gates unchanged.

Xpra root cookie v69: `plans/amendments/2026-10-10-xpra-root-cookie-source-refinement-v69.md`; actual selected patch/startup proof required and existing gates open.

Active row joins v71: `plans/amendments/2026-10-10-memory-lifecycle-xpra-overlay-row-joins-v71.md`; existing task/target gates remain open, actual retained source/runtime receipts required.

Xpra root overlay receipt API v73: `plans/amendments/2026-10-10-xpra-overlay-root-receipt-api-v73.md`; existing RT/HI tasks remain open pending actual source/runtime proof.

Root-selected lifecycle authority v80: `plans/amendments/2026-10-10-root-selected-service-lifecycle-authority-v80.md`; existing HI/RT/SK tasks open, separate actual controller and selected subject proof required.

Selected lifecycle stop canonical payload v85: `plans/amendments/2026-10-10-selected-lifecycle-stop-canonical-payload-v85.md`; existing HI-T09/HI-T13/SK-T01 remain open.

Bootstrap action and derived store ownership v87: `plans/amendments/2026-10-10-bootstrap-action-derived-store-ownership-v87.md`; existing BD/HI/RB tasks remain open.

Private loopback enforcement choice v97: `plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97.md`; existing original implementation/acceptance obligations remain open.

Verified Xpra source pin v101: `plans/amendments/2026-10-10-xpra-verified-source-pin-v101.md`; exact source tree/finite links/actual transform and runtime proof required; no source-only acceptance or missing native-family waiver. Existing tasks open.

Private loopback host tool pins v103: `plans/amendments/2026-10-10-private-loopback-host-tool-pins-v103.md`; finite actual package/executable/dependency/namespace proof, no source-only or target acceptance; existing tasks remain open.

Host tool observation v105: `plans/amendments/2026-10-10-host-tool-observation-v105.md`; actual network-owned signed host package/held dependency producer required. Existing implementation and acceptance tasks remain open.

Xpra managed transform v106: `plans/amendments/2026-10-10-xpra-managed-transform-v106.md`; finite managed target and actual PM/module/source/terminal/CAS receipts required. Existing HI-T09/HI-T13 implementation and acceptance remain open.

Xpra regular source build pin v109: `plans/amendments/2026-10-10-xpra-regular-source-build-pin-v109.md`; exact module/source topology, file builder root and data output role. Existing managed proof/acceptance tasks open.

Xpra link target source pin v111: `plans/amendments/2026-10-10-xpra-link-target-source-pin-v111.md`; final committed module and exact five link target byte hashes/sizes; managed proof/acceptance still required.

Loopback inert kernel templates v122: `plans/amendments/2026-10-10-loopback-inert-kernel-templates-v122.md`; actual nft/namespace/subject and AC13..15 proof remain open.


Reviewed source members and boundary joins v180: `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; finite exact merged module pins, corrected standalone builder role,21-field separate local-operation publication and per-worker kernel start barrier. Producer ownership/order/evidence tasks remain OPEN; baseline and all AC01..18 unchanged.


Concrete remote runtime substrate v209: `plans/amendments/2026-10-10-concrete-remote-runtime-substrate-v209.md` and `planning/concrete-remote-runtime-substrate-v209.json`; source acquisition/build/materialized runtime are distinct; v202 outer schemas, namespace ports and sandbox/TLS remain unchanged. All implementation/target gates OPEN.


Production remote role NSS/protected roots v212: `plans/amendments/2026-10-10-production-remote-role-nss-roots-v212.md` / `planning/production-remote-role-nss-roots-v212.json`; genuine three distinct accounts/current descriptors/journal/adoption, preserved foreign state and unchanged native-worker receipt. Finite v209 AppDir target fields corrected; source pins and all AC OPEN.

Officialremote roledefinition222: source-only held3roledescriptor→currentchoice/transaction-generated identityselection→actualNSS/roots/runtime/network→strictactiveadoption. planning/official-remote-role-definition-producer-v222.json; no preparedrecords/futureaccountauthority.


Xpra native build acquisition v219: `plans/amendments/2026-10-10-xpra-native-build-acquisition-v219.md` / `planning/xpra-native-build-acquisition-v219.json`; owner implements actual signed native/PM314 backend/transform receipt producers, corrected fixed offline recipe and independent qualification. New source pins and all AC OPEN.


Tested gateway source review v223: `plans/amendments/2026-10-10-tested-gateway-source-members-v223.md` / `planning/tested-gateway-source-members-v223.json`; exact tested leaf/schema pins, eighteen-member import closure, held libpython config and gateway-only lib64 link, separate synthetic-authority ARM64 fixture/production runtime/target evidence. All AC OPEN.


## Durable remote identity currentness v225

Use the exact schemas/APIs in `planning/current-remote-identity-adoption-v225.json`: source projection precedes publication; immutable signed adoption follows exact committed receipt. Current protected member/core/journal/NSS/root/lease observations issue fresh receipts after restart without restored setup seals. Publication-before-journal crashes deny activation until original authorized transaction completes. Source pins and all runtime/target acceptance remain pending.


## Desktop native source/build closure v226

`planning/official-desktop-native-build-inputs-v226.json` fixes owner registry and retained FD receipt fields. Exact Electron ABI/local headers and signed private sysroot feed offline locked rebuild; prepared native degraded=false and complete original workspace prevent lazy staging fallback. Original prepared dir build produces full independently observed AppDir, ELF/library/PTY/sandbox proof, separate from final runtime/active/target acceptance. No guessed header/dependency/schema pins or ambient Mac/global libraries.


v225 schema placement is authority.service_generations schema3, exact schema2 fields/validators plus remote_service_identity_source_records; canonical digest includes selectors. No enabled remote means absent member/descriptor null/SHA null/size0; enabled requires complete matching member/core/descriptor/claim/receipt. Existing1/2 do not issue v225 identity receipts. See append-only v225 schema clarification.


## Preactive source authority and acyclic build inputs v227

Exact `planning/preactive-xpra-acquisition-build-v227.json` separates quarantined download from signed dependency/license admission and no-egress role build. Actual setup transform grants/manager output precede active patch adoption. Member digest excludes config; config carries member digest; final receipt binds config/member/setup/schema. Concrete sealed role plans enforce actual argv/mount/output/role caps and original controller deadline; no actor substitute, old receipt renewal or generic shared defaults.


## Types-only auxiliary workspace input v229

Use exact `planning/official-desktop-ws-types-repair-v229.json` source artifact/member/dependency proofs through existing v226 current native registry. Originalrootlock@types/node22.20.1 satisfies wildcard withoutfetch. Disposable node_modules/@types/ws injection is explicitly digest-bound auxiliary projection, never fictional original lock membership, fake declarations or runtime substitution. Actual original compiler and nativeAppDir qualification remain separate.


## v234 Gateway digests and owned cleanup

Use the closed Gateway field sets and canonical acyclic projections in the v234 JSON. Reserve cleanup journal intent before namespace creation; retain creator placeholder/mount/namespace facts. Cleanup uses original sealed custody, fresh signed nft readback and zero owned members without active verification or renewal. Partial mismatches remain journaled recovery-pending.

Contract: `plans/amendments/2026-10-10-gateway-digests-owned-network-cleanup-v234.md` and `planning/gateway-digests-owned-network-cleanup-v234.json`; all AC OPEN.


## v237 Preactive native manager composition

Use ManagedProcessEffectHandler.from_current_root_setup(binding,registry) and ManagedBuildJobRunner.from_current_root_setup(handler,binding,registry). The existing remote executor derives its own current _RootPreparedBuildRuntime; generic active profiles/effects deny. Preserve original actor/source/PM/NSS/controller custody and drain verified-owned job lifecycle before registry FD closure.

Exact contract: `planning/preactive-native-build-manager-composition-v237.json`; all AC OPEN.


## v238 Concrete Xpra source policy

Use v238 exact closed schema, immutable observed source tuples and current signed acquisition/grant/CAS checks. Explicit dependency groups preserve signed versions/Provides/Multi-Arch; finite doc-link license references are checked against complete held graph. Candidate recipe/CP314 build/HTML5/session remain independently pending.

Exact source contract: `planning/xpra-native-source-policy-v238.json`; all AC OPEN.
