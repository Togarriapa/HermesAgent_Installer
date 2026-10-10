# Tasks

Implement using GPT-6 Luna; Sol owns refinements. Later user additions are separately preserved; all original scope remains. No live cloud/host action is performed by this plan.

## 1. Foundation with tests and docs

- [ ] 1.1 `RT-F01` Implement secure Cloudflare API discovery/owned-resource transaction adapter with recording HTTP fixtures; verify scoped permissions, no public exposure window, conflict preservation, ambiguous-failure reconciliation and no repeated-approval setup; document token/domain/email setup. Dependencies: BD-F01, LC-F01, LC-F02, PR-F01. Evidence: `tests/contracts/test_cloudflare_setup.py`.
- [ ] 1.2 `RT-F02` Implement origin JWT/session/lease gateway and reviewed constrained official native app bridge; verify actual deny before pixels/control, only fixed upstream, expiry/revocation/command/window isolation; document browser-only native Desktop access. Dependencies: BD-F03, RG-F02, RG-F03, LC-F04. Evidence: `tests/contracts/test_remote_gateway.py`.
- [ ] 1.3 `RT-F03` Implement remote lifecycle/doctor/verification CLI and authorized-target browser workflow; verify recovery/idempotency/redaction and protected native-window tests; document configure-later/resume. Dependencies: RT-F01, RT-F02, LC-F03. Evidence: `tests/acceptance/test_remote_desktop.py`.

## 2. Individual direct-user obligations

- [ ] 2.1 `RT-R0196` Implement `R0196` in `src/hermes_installer/remote/config.py`: The wizard SHALL ask for the desired hostname with an empty input and no prefilled/default domain, validate it and require explicit user selection for noninteractive configuration. Verify `tests/contracts/test_remote_config.py` (EV-R0196) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.2 `RT-R0197` Implement `R0197` in `src/hermes_installer/remote/cloudflare.py`: The wizard SHALL securely request a scoped Cloudflare API token or secret reference, explain official permissions and discover authorized account/zone without logging token values. Verify `tests/contracts/test_remote_cloudflare.py` (EV-R0197) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.3 `RT-R0198` Implement `R0198` in `src/hermes_installer/remote/cloudflare.py`: The installer SHALL automatically provision or reuse a dedicated installer-owned Cloudflare Tunnel and least-privilege runtime credential under the selected account. Verify `tests/contracts/test_remote_cloudflare.py` (EV-R0198) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.4 `RT-R0199` Implement `R0199` in `src/hermes_installer/remote/cloudflare.py`: The installer SHALL automatically configure the exact DNS hostname route and tunnel ingress to the loopback Desktop authorization gateway with a terminal404 catch-all. Verify `tests/contracts/test_remote_cloudflare.py` (EV-R0199) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.5 `RT-R0200` Implement `R0200` in `src/hermes_installer/remote/cloudflare.py`: The installer SHALL automatically configure Cloudflare Access self-hosted application, email one-time-code login and explicit allowed-email policy for the entered hostname. Verify `tests/contracts/test_remote_cloudflare.py` (EV-R0200) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.6 `RT-R0201` Implement `R0201` in `src/hermes_installer/remote/gateway.py`: Remote origin SHALL validate signed Cloudflare Access JWT algorithm, signature, configured issuer/audience, time claims and allowed principal before serving any asset, pixel, control or stream. Verify `tests/contracts/test_remote_gateway.py` (EV-R0201) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.7 `RT-R0202` Implement `R0202` in `src/hermes_installer/remote/gateway.py`: Remote gateway SHALL allow only dedicated Desktop client assets/session/renewal/WebSocket routes and reject arbitrary targets, paths, origins and backend-management transports. Verify `tests/contracts/test_remote_gateway.py` (EV-R0202) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.8 `RT-R0203` Implement `R0203` in `src/hermes_installer/remote/session.py`: The remote bridge SHALL stream the genuine official Hermes Desktop application in a dedicated constrained native session, never a web dashboard or whole existing host desktop. Verify `tests/contracts/test_remote_session.py` (EV-R0203) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.9 `RT-R0204` Implement `R0204` in `src/hermes_installer/remote/session.py`: The bridge SHALL disable remote new-command/session/shell/control, file transfer/opening, clipboard, printing, device/audio and unnecessary proxy/debug features through server controls. Verify `tests/contracts/test_remote_session.py` (EV-R0204) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.10 `RT-R0205` Implement `R0205` in `src/hermes_installer/remote/session.py`: Each remote browser session SHALL bind verified Access principal and native profile state; concurrent access SHALL respect configured one-session limits and prevent cross-user state/session hijack. Verify `tests/contracts/test_remote_session.py` (EV-R0205) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.11 `RT-R0206` Implement `R0206` in `src/hermes_installer/remote/gateway.py`: Active WebSocket input/output SHALL stop on JWT expiry or stale authorization lease; revocation SHALL be enforced through bounded fresh protected HTTP renewal, not assumed edge socket termination. Verify `tests/contracts/test_remote_gateway.py` (EV-R0206) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.12 `RT-R0207` Implement `R0207` in `src/hermes_installer/remote/lifecycle.py`: Cloudflare/remote component lifecycle SHALL be checkpointed, idempotent and ownership-aware across automatic setup, resume, update, rollback, disable and uninstall. Verify `tests/contracts/test_remote_lifecycle.py` (EV-R0207) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.13 `RT-R0208` Implement `R0208` in `src/hermes_installer/remote/cloudflare.py`: Cloudflare setup SHALL activate public DNS/ingress only after Access protection and loopback origin validation are ready, with a fail-closed transaction order. Verify `tests/contracts/test_remote_cloudflare.py` (EV-R0208) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.14 `RT-R0209` Implement `R0209` in `src/hermes_installer/remote/credentials.py`: Cloudflare management token SHALL remain only in secure setup credential storage; runtime cloudflared receives dedicated tunnel credential and gateway receives only necessary nonsecret trust/session configuration. Verify `tests/contracts/test_remote_credentials.py` (EV-R0209) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.15 `RT-R0210` Implement `R0210` in `src/hermes_installer/remote/config.py`: The wizard/CLI SHALL support configure-later, secure noninteractive references, automatic setup resumption and component doctor/verify without repeated routine approvals. Verify `tests/contracts/test_remote_config.py` (EV-R0210) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.
- [ ] 2.16 `RT-R0211` Implement `R0211` in `src/hermes_installer/remote/verify.py`: Remote acceptance SHALL separately prove unauthorized HTTP/WS denial, actual official Desktop pixels/control, app-only confinement, expiry/revocation and owned-resource recovery on the exact target/account. Verify `tests/contracts/test_remote_verify.py` (EV-R0211) against the explicit scenario inputs/denials/effects. Document `docs/remote-desktop-access.md` and exact configured/pending/account/target states.

## Workflow follow-up

- Run strict specification/coverage/failure tests; keep live Cloudflare/Pi app-only/auth/revocation acceptance open until performed.
- Archive only genuinely verified scope, preserving immutable baseline and separate Sol amendments.

RT-F03 remote native acceptance additionally requires HI-T13 / EV-HI13 root-observed JWT/policy connector session and actual bounded active revocation; current task remains open.

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

- [ ] HI-T122.1: network owner implement exact inert fallback invariant and retained typed root link/address/route/kernel/nft/subject proof.

- [ ] HI-T122.2: kernel-capable isolated test proves known DOWN templates accepted only with actual nft/capability closure, UP/address/key/route/master/unknown/veth mutation denied. Missing privileges leaves test and live acceptance pending.

- [ ] `HI-T180.4` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `HI-T180.5` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.


Concrete remote runtime substrate v209: `plans/amendments/2026-10-10-concrete-remote-runtime-substrate-v209.md` and `planning/concrete-remote-runtime-substrate-v209.json`; source acquisition/build/materialized runtime are distinct; v202 outer schemas, namespace ports and sandbox/TLS remain unchanged. All implementation/target gates OPEN.

- [ ] `RT-T209.1` Implement retained three-role runtime registry/current source-to-role projection and root factory join under v209; source pins and target acceptance remain pending.

- [ ] `RT-T209.2` Implement actual locked Xpra native acquisition and fixed runnable managed builder under v209; source pins and target acceptance remain pending.

- [ ] `RT-T209.3` Implement lock-derived npm acquisition, separate Electron ARM64 payload and upstream prepared AppDir builder under v209; source pins and target acceptance remain pending.

- [ ] `RT-T209.4` Implement gateway locked component runtime/fixed driver builder and finite custody execution lane under v209; source pins and target acceptance remain pending.

- [ ] `VD-T209.5` Verify actual source/build/CAS/materialization/role joins and specified substitution/expiry/cancel/sandbox failures under v209; source pins and target acceptance remain pending.


Production remote role NSS/protected roots v212: `plans/amendments/2026-10-10-production-remote-role-nss-roots-v212.md` / `planning/production-remote-role-nss-roots-v212.json`; genuine three distinct accounts/current descriptors/journal/adoption, preserved foreign state and unchanged native-worker receipt. Finite v209 AppDir target fields corrected; source pins and all AC OPEN.

- [ ] `RT-T212.1` Implement actual production remote role account/shared group/protected root issuer and current root-factory joins under v212; all target acceptance remains OPEN.

- [ ] `RT-T212.2` Integrate exact current publisher adoption and manager-verified-dead journaled owned rollback under v212; all target acceptance remains OPEN.

- [ ] `VD-T212.3` Exercise real isolated Linux NSS/root effects and current choice/receipt/adoption plus collision/replay/cleanup failure contracts under v212; all target acceptance remains OPEN.

- [ ] RT-T222.1: Implement exact helddefinition/parser/source receipt and transactionrole selections.
- [ ] RT-T222.2: Join actual212NSS/209runtime/network and strictactivepublication/adoption.
- [ ] VD-T222.3: Verify source/choice/identity/currentness failures and actual target effects separately.
