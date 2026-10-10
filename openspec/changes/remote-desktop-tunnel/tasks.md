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


Xpra native build acquisition v219: `plans/amendments/2026-10-10-xpra-native-build-acquisition-v219.md` / `planning/xpra-native-build-acquisition-v219.json`; owner implements actual signed native/PM314 backend/transform receipt producers, corrected fixed offline recipe and independent qualification. New source pins and all AC OPEN.

- [ ] `RT-T219.1` Implement genuine signed native package and isolated CP314 Python backend acquisition/receipt producer under v219; all acceptance OPEN.

- [ ] `RT-T219.2` Wire exact source/transform/PM/member/config joins and corrected offline native build/qualification under v219; all acceptance OPEN.

- [ ] `VD-T219.3` Verify isolated ARM64 real build/session and specified signature/ABI/source/currentness/RPATH/cleanup failures under v219; all acceptance OPEN.


Tested gateway source review v223: `plans/amendments/2026-10-10-tested-gateway-source-members-v223.md` / `planning/tested-gateway-source-members-v223.json`; exact tested leaf/schema pins, eighteen-member import closure, held libpython config and gateway-only lib64 link, separate synthetic-authority ARM64 fixture/production runtime/target evidence. All AC OPEN.

- [ ] `RT-T223.1` Apply exact tested gateway source/schema tuples and complete runtime import/sourcegroup closure under v223; all runtime/target acceptance OPEN.

- [ ] `RT-T223.2` Complete genuine current source/PM/wheel/native config/CAS/final-runtime joins and exact gateway-only directory-link policy under v223; all runtime/target acceptance OPEN.

- [ ] `VD-T223.3` Verify real sealed source/build/materialization joins and specified source/ELF/link/currentness/fake-authority failures under v223; all runtime/target acceptance OPEN.


## Current remote identity adoption v225

- [ ] `RT-T225.1` Implement actual retained source projection, compiler member/core selectors and typed signed immutable existing transaction-journal adoption writer.
- [ ] `RT-T225.2` Implement fresh active identity/private role observations and genuine current root network lease resolver under exact v225 APIs.
- [ ] `VD-T225.3` Verify actual publication/journal restart joins and specified missing proof/replay/signature/currentness/NSS/kernel/cleanup failures; target acceptance OPEN.


## Official Desktop native build inputs v226

- [ ] `RT-T226.1` Implement actual current official header/native/signedARM64 sysroot source acquisition and held native input registry under v226.
- [ ] `RT-T226.2` Complete actual offline ElectronABI node-pty/helpers, original workspace typecheck/build and prepared AppDir with independent ELF/PTY/sandbox observer.
- [ ] `VD-T226.3` Verify real isolated ARM64 build and specified header/ABI/dependency/egress/degraded/currentness/link/sandbox/cancel failures; all target acceptance OPEN.


- [ ] `VD-T225.3` Also test exact schema3 placement/legacy validator preservation and disabled absent/null/zero versus enabled complete-member representation; reject mixed states.


## Pre-active Xpra acquisition and managed role plan v227

- [ ] `RT-T227.1` Implement actual selected fixedHTTPS request/grant/native verifier/dynamic component sourceCAS producer and root binding.
- [ ] `RT-T227.2` Implement actual preactive transform manager/CAS/independent overlay receipt and acyclic member/config/final input digest projections.
- [ ] `RT-T227.3` Implement sealed exact managed role plan/current output-controller custody, fixed driver argv/mounts and role-specific caps under v227.
- [ ] `VD-T227.4` Verify genuine setup acquisition/CAS/transform/input/manager joins and specified TLS/replay/foreign/closure/expiry/revocation/network/cleanup failures; all target acceptance OPEN.


## Official Desktop ws typecheck repair v229

- [ ] `RT-T229.1` Implement exact separately admitted auxiliary declaration receipt and owned disposable workspace projection without originalsource/lock edits.
- [ ] `RT-T229.2` Run actual original ARM64 typecheck before/after and continue genuine v226 native/workspace/AppDir build.
- [ ] `VD-T229.3` Verify exact archive/SRI/member/dependency/currentness/foreign conflict/API rejection and real original compiler effects; all target acceptance OPEN.


## v234 Gateway digests and owned cleanup

- [ ] RT-T234.1 Implement exact Gateway member/config/output/observer digest split; independently recheck ARM64 fixture.
- [ ] RT-T234.2 Implement private reserved creation/cleanup journal and custody; remove only original owned resources after expiry/revocation.
- [ ] VD-T234.3 Test digest mutations, foreign resources, nonempty members, missing tool and durable phase/CAS failure preservation.

Contract: `plans/amendments/2026-10-10-gateway-digests-owned-network-cleanup-v234.md` and `planning/gateway-digests-owned-network-cleanup-v234.json`; all AC OPEN.


## v237 Preactive native manager composition

- [ ] RT-T237.1 Implement source-bound native setup-only handler/runner and session hook.
- [ ] RT-T237.2 Wire actual root choice/concrete providers/preparation/complete aggregate and verified-dead cleanup.
- [ ] VD-T237.3 Test empty prepared composition and wrong-owner/currentness/effect/cancellation/mount journal failures.

Exact contract: `planning/preactive-native-build-manager-composition-v237.json`; all AC OPEN.


## v238 Concrete Xpra source policy

- [ ] RT-T238.1 Enroll concrete policy/keyring and exact closed dependency/license verifier.
- [ ] RT-T238.2 Acquire/build actual offline PM314/native/HTML5/session closure and observe outputs.
- [ ] VD-T238.3 Exercise signature/version/provider/qualifier/license/hash/CP313/lazy-path failures.

Exact source contract: `planning/xpra-native-source-policy-v238.json`; all AC OPEN.


- [ ] RT-T239.1: Retain genuine remote executor terminal proof and implement narrow remote CAS/attestation package issuer.
- [ ] RT-T239.2: Materialize exact role package through current held data-root custody and issue v209/v202 runtime receipts for v225 adoption.
- [ ] VD-T239.4: Verify terminal forgery, source/schema/root races, expiry, cross-role and owned rollback failures plus actual pipeline effect; target acceptance separate.
- [ ] RT-T239.3: Issue same-transaction remote enrollment reservation and current source/NSS-derived private-network policy selection; wire exact v202 aggregate and separate v225 kernel lease.

## v240 Measured Desktop headers and managed interface

- [ ] RT-T240.1 Implement exact held headers and truthful upstream commit-build stamp wrapper.
- [ ] RT-T240.2 Implement fixed Desktop driver and measured plan/output/current receipts.
- [ ] VD-T240.3 Test source/stamp/ABI/digest/caps/link failures and actual offline ARM64 effects; all AC OPEN.

Exact contract: `planning/official-desktop-measured-headers-managed-plan-v240.json`.


## Gateway source and wheel issuer refinement v244

- [ ] RT-T244.1 Implement fixed held release source receipt/member projection and reviewed exact source-member cohort.
- [ ] RT-T244.2 Implement Gateway lock/PM/choice-bound bounded acquisition, license verification, immutable CAS and retained provider/source projection integration.
- [ ] VD-T244.3 Exercise spoofed receipts, changed lock/source/PM, stale choice, cancellation, conflicting CAS, bounded dependency/license failure and genuine ARM64 production positives; target acceptance separately open.

## v246 Acyclic source and active digest

- [ ] RT-T246.1: Emit exact remote source schema2 without misleading generation component hash and bind adoption to actual active_service_generation_id/digest; preserve current genuine aggregate and prepared lineage.
- [ ] RT-T246.2: Validate immutable schema2 published member and strict current source/core/claim/receipt/adoption full active generation joins, preserving v225 absent remote and schema3/schema4.
- [ ] VD-T246.3: Verify genuine acyclic source-to-full-generation-to-adoption pipeline, prepared/component confusion, unrelated-row fullhash changes, tamper/restart/disabled failures; target acceptance OPEN.

## v245 Xpra source graph and HTML5

- [ ] RT-T245.1 Implement actual signed graph/private sysroot and independent single glibc transform observer.
- [ ] RT-T245.2 Implement held official HTML5 acquisition/license/source-data install.
- [ ] VD-T245.3 Test exact graph/hash/license/currentness failures and managed ARM64 HTML5 session; all AC OPEN.

Exact contract: `planning/xpra-sysroot-html5-v245.json`.


## Gateway license and official acquisition custody v248

- [ ] RT-T248.1 Implement exact held policy source and wheel/metadata/notice eligibility issuer with preserved package notices.
- [ ] RT-T248.2 Implement root-only no-proxy/no-redirect official metadata/file transport, DNS/TLS/currentness/cancellation custody and v244 CAS integration without subprocess network.
- [ ] VD-T248.3 Verify metadata/license mismatch, unsafe archive, redirect/private DNS/changed hash, deadline/cancel cleanup and all13 genuine selected wheel positives; native/Pi acceptance separately open.


### Gateway license policy role correction v248b

Apply `planning/gateway-license-policy-release-role-v248b.json`: existing gateway-source-member for the exact separate policy row, no generic source enum or inclusion in application input closure. RT-T248.1/.2 and VD-T248.3 remain open.


## v250 Original Xpra archive link count correction

- [ ] RT-T250.1 Consume exact3093 symlink/0 hardlink source cohort and reject changed origin/kind.
- [ ] VD-T250.2 Verify independent raw archive facts and preserve currentness/managed runtime gates; all AC OPEN.

Exact contract: `planning/xpra-link-count-correction-v250.json`.


## v251 Desktop native source and packaging

- [ ] RT-T251.1 Implement distinct held Desktop policy/verifier/one-use grant/CAS and native provider; exact signed253 package and licensing closure, failure/currentness/cancellation effects.
- [ ] RT-T251.2 Produce independently observed native/sysroot/prepared packaging manifests with actual offline compiler/HUD/Electron ABI and licensed owned PNG toolset, preserve sandbox/stamp and v240 fixed driver.
- [ ] VD-T251.3 Exercise changed signature/index/hash/control/relations/license/links, wrong issuer/role/choice/controller, cancellation, PNG failures and actual managed ARM64 output; genuine runtime/Pi acceptance separately open.

Exact contract: `planning/official-desktop-native-source-policy-v251.json`; all AC OPEN.


## v251b Non-circular Desktop native pipeline

- [ ] RT-T251b.1 Implement true prebuild input manifest/provider and remove native generated outputs as source prerequisites, preserving genuine signed/source/current receipt joins.
- [ ] RT-T251b.2 Generate native tree/joined manifest through actual fixed managed driver and independently reopen retained packaged native facts before receipt; no hash-only native completion.
- [ ] VD-T251b.3 Test missing/generated-input cycle, forged native result, absent retained tree, selfhash, ABI/packaged mapping/cancellation/currentness failure and genuine bounded offline ARM64 pipeline; runtime acceptance separate.


## v251c Packaging source and generated record

- [ ] RT-T251c.1 Implement source-only packaging intent and deterministic origin-bound normalized inputs receipts/closure with separate tar-byte digest; remove future prepared fields from prebuild.
- [ ] RT-T251c.2 Generate true upstream prepared.json through fixed driver after materialization/native effects and retain/reobserve it in actual AppDir joined output.
- [ ] VD-T251c.3 Test stale path/source, missing notice/helper/library, normalization/tar hash confusion, forged future prepared proof, link/extra member/selfhash/currentness/cancellation failures and genuine bounded offline prepared packaging effects.
- [ ] HI-T254.1: Integrate same-owned still-live fresh observation renewal with current protected generation/source/adoption/NSS joins and atomic FD custody.
- [ ] LC-T254.2: Separate actual network observation from unchanged finite process/start/access deadlines, continuously supervise and stop exact managed unit on currentness failure; preserve cleanup domain.
- [ ] VD-T254.3: Verify actual refresh/currentness/expiry/concurrency/watchdog/terminal/access failures and original recipe cap, leaving sustained Desktop/native acceptance separate OPEN.


- [ ] RT-T256.1: Implement issuer-only source authority snapshot and durable private root CAS/journal content custody without weakening old expiry/build guards.
- [ ] RT-T256.2: Implement independent signed metadata/control/full399 license reobservation and new atomic current closure/member receipts; wire actual Xpra input provider/central full verifier.
- [ ] VD-T256.3: Verify aggregate-age/old-expiry denial/new-current positive/cancel/tamper/restart/metadata/license/authority failures and genuine source-to-build fixture effects, target acceptance OPEN.
