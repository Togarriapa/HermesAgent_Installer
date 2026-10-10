# Proposal

## Why

The user needs authenticated browser access from a Cloudflare Tunnel to the genuine Hermes Desktop on the Pi without exposing the host desktop or management services. Automatic secure setup must start from a blank user-selected hostname and scoped token.

## What Changes

- Add native app-only browser streaming through an authenticated loopback gateway.
- Automatically provision/reuse only owned Cloudflare tunnel/DNS/Access/email-code resources with transaction/resume/recovery.
- Enforce page/asset/WS authorization, JWT validation, principal isolation and bounded live socket expiry/revocation.
- Preserve original twelve acceptance criteria and add AC13..15 for this direct-user extension.

## Capabilities

### New Capabilities

- `remote-desktop-access`: Automatic owned Cloudflare enrollment and protected browser-only official native Hermes Desktop streaming.

### Modified Capabilities

None; earlier installer capabilities remain active proposals. Their integration DAG/evidence now includes this change.

## Impact

src/hermes_installer/remote/, secure credential/config/lifecycle adapters, dedicated application session/services, Cloudflare API/Access/tunnel configuration, browser tests and docs. No live Pi/account/DNS mutation is performed by this planning change.

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


## Current remote identity adoption v225

Add actual precommit three-role source member, current core selectors and postpublication signed enrollment-journal adoption; fresh active identity/network resolvers follow `plans/amendments/2026-10-10-current-remote-identity-adoption-v225.md`. RT-T225.1/.2 and VD-T225.3 remain OPEN.


## Actual official Desktop native inputs v226

Implement bounded official Electron headers/ABI, signed ARM64 compiler/sysroot/runtime dependencies, exact workspace/native preparation and independent AppDir build/qualification under `plans/amendments/2026-10-10-official-desktop-native-build-inputs-v226.md`; missing producers must be implemented. RT-T226.1/.2 and VD-T226.3 OPEN.


v225 compiler clarification: append-only schema clarification fixes authority envelope1/service-generations3 placement and disabled absent-member/null digest/zero size without fictional adoption records; existing tasks OPEN.


## Preactive Xpra producers and role plans v227

Implement actual one-use fixedHTTPS setup acquisition/dynamic sourceCAS, existing preactive transform executor and acyclic member/config/final receipt projections plus fixed managed role plans under `plans/amendments/2026-10-10-preactive-xpra-acquisition-build-v227.md`. RT-T227.1/.2/.3 and VD-T227.4 remain OPEN.


## Official Desktop ws type repair v229

Add exact MIT @types/ws8.18.2 as separately reviewed types-only auxiliarytoolchain/workspace projection under `plans/amendments/2026-10-10-official-desktop-ws-types-repair-v229.md`; original source/lock and runtimews unchanged. Actual ARM64 original compiler/nativeAppDir effects remain required; tasks OPEN.


## v234 Gateway digests and owned cleanup

v234 corrects actual Gateway digest circularity and provides cleanup-only retained ownership after lease expiry/revocation; scope and ports unchanged.

Contract: `plans/amendments/2026-10-10-gateway-digests-owned-network-cleanup-v234.md` and `planning/gateway-digests-owned-network-cleanup-v234.json`; all AC OPEN.


## v237 Preactive native manager composition

Break the actual preactive/active manager cycle with sealed native setup-only factories; invoke the existing genuine root choice/provider/build/aggregate flow.

Exact contract: `planning/preactive-native-build-manager-composition-v237.json`; all AC OPEN.


## v238 Concrete Xpra source policy

Supply the previously absent actual held Xpra native source policy/keyring member from bounded verified official sources, with full dependency/license evidence.

Exact source contract: `planning/xpra-native-source-policy-v238.json`; all AC OPEN.


## Remote output receipt pipeline v239
## v240 Measured Desktop headers and managed interface

See `planning/preactive-remote-build-output-receipts-v239.json`: executor-owned terminal membership precedes exact adapter observation, immutable CAS/attestation and root-held data-root materialization. Only genuine typed proofs mint v209/v202 runtime receipts; v225 owns publication/restart adoption. Existing scopes/deadlines and all AC remain open.
Measured official headers and fixed offline Desktop managed interface are now specified in v240, preserving source provenance and pending AppDir/caps. No runtime acceptance.

The v239 aggregate also consumes exact root-issued enrollment reservation and prepared source/NSS network policy selection; actual postpublication kernel/network lease is separate and mandatory. No caller ID or future generation is inferred.
Exact contract: `planning/official-desktop-measured-headers-managed-plan-v240.json`.
