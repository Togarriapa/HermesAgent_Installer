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


## Gateway source and wheel issuer refinement v244
## v245 Xpra source graph and HTML5

Preserve AC13..15 and v202/v209/v239. Consume the exact finite source-only held release and selected Gateway locked-wheel CAS issuer in `planning/gateway-source-wheel-issuers-v244.json`. Public rows/raw bodies do not authorize; actual retained source/PM/choice/FD/license/currentness proofs precede offline build. No source pins or acceptance declared.
Remote source digest v246: planning/remote-source-active-digest-acyclic-v246.json removes impossible source self-dependency through exact source schema2, preserves prepared lineage and full active generation algorithm, and requires post-publication receipt/core/claim/adoption joins via actual active_service_generation fields. All AC OPEN.
v245 supplies exact official HTML5 source observations and signed DEB link/sysroot ABI needed by the real43-extension diagnostic build; positive managed session remains pending.

Exact contract: `planning/xpra-sysroot-html5-v245.json`.


## Gateway license and official acquisition custody v248

Preserve AC13..15 and v244. Exact-wheel held policy/eligibility and root-only bounded direct official PyPI transport are defined in `planning/gateway-wheel-license-transport-v248.json`; raw metadata, caller license approval and pip network do not authorize admission. All acceptance remains open.


### Gateway license policy role correction v248b

Apply `planning/gateway-license-policy-release-role-v248b.json`: existing gateway-source-member for the exact separate policy row, no generic source enum or inclusion in application input closure. RT-T248.1/.2 and VD-T248.3 remain open.


## v250 Original Xpra archive link count correction

Append-only v250 corrects only v245 cohort count: original399 signed-policy archives contain3093 symlinks and zero hardlinks; original graph file/hash remain correct. Preserve all source/currentness/private-root/transform/runtime gates.

Exact contract: `planning/xpra-link-count-correction-v250.json`.


## v251 Desktop native signed-source policy
## Current owned network observation v254

Extends frozen v226/v229/v240 for R0028/R0035/R0037/R0203/R0204/R0211. This append-only source contract supplies the previously missing genuine Desktop-specific policy; it does not approve a runtime or modify earlier plans.

The exact contract is `planning/official-desktop-native-source-policy-v251.json`. The immutable source policy contains 35 Desktop compiler/HUD/Electron native roots, 253 official signed Debian arm64/all rows (169,912,236 archive bytes), 752 exact selected dependency edges and 253 copyright references. Direct original archive inspection observes 744,817,279 expanded bytes, 1,854 symlinks and two hardlinks. Source Release/Packages/archives were independently verified; actual ARM64 sqv authenticated both InRelease messages against the retained keyring. Installed-image facts only selected roots and never substitute for signed source or current runtime receipts. Reuse of cached public source bytes does not reuse Xpra authority.

Native owner implements the closed Desktop policy/verifier/request/grant/quarantine/CAS types and composes them inside its existing current native provider. The contract fixes signatures, descriptor currentness, original root choice/controller/PM/NSS/transaction joins, one-use budget, full signed dependency/control/license proof and protected private CAS. Missing trusted verifier or current proof denies acquisition admission. No generic apt install, caller URL, script execution, global Python downgrade or Xpra receipt alias is authorized.

Packaging uses the measured official 7zip archive and official npm wasm-vips 0.0.17, retaining actual licenses and third-party notices. The unlicensed upstream icons wrapper is excluded. Driver owner supplies independently implemented `desktop_icon_set.mjs`, stages it as the prepared icons tool and uses the exact licensed vips JS/WASM. Its finite PNG-only interface and bounds are in the separate source packaging policy. The actual offline ARM64 helper experiment is an observation, not a source-code pin or prepared packaging receipt; effect/dimension and rejection tests plus committed source review must precede issuance.

Actual native/sysroot/package manifests project held current receipt objects. Exact official PM314, Node26 build, Electron40.10.2 binary/headers, native compiler and ELF dependency identities remain separate. Private origin-bound link resolution and hardlink materialization cannot access ambient paths. Preserve the v240 fixed prepared AppDir invocation, honest source stamp, enabled Electron sandbox and final installed ownership/mode proof.

RT-T251.1 → RT-T251.2 → VD-T251.3 are OPEN. Luna native owner implements actual acquisition/CAS/provider; Luna Desktop owner implements actual native/package driver and licensed icons integration. Whole-build caps and packaged renderer/backend qualification remain genuinely pending. No null managed plan may execute; all AC and Pi acceptance remain OPEN. Baseline and older amendments remain unchanged.


## v251b Native build input/output direction

Extends v240/v251 for R0028/R0035/R0037/R0203/R0204/R0211. The complete joined v251 native manifest describes actual generated node-pty/HUD/stage-native-deps outputs. Requiring it or native-deps.tar as a prebuild input creates a cycle and is forbidden. Earlier artifacts remain immutable.

Exact contract: `planning/official-desktop-native-build-direction-v251b.json`. Native provider supplies distinct source-only native-prebuild-inputs.json plus genuine current signed package/sysroot/compiler/license/header/source/npm/Electron and prepared tool inputs. The fixed driver owns actual offline native effects, native staging and upstream build/prepared packaging. The complete joined native-build.json and its native stage tree are retained inside final AppDir only after effects. The output observer independently reopens these bytes, checks exact upstream native prepared rows, native ELF/ABI, packaged mappings and original input lineage before any output receipt. Source facts cannot fake generated native receipts.

Use fresh manager-owned fixed work/desktop descriptor custody and fixed final output/desktop-appdir. Preserve acyclic member/recipe closures and exact outer output fields; qualification binds generated native manifest bytes without a self-hash. No arbitrary paths or unobserved temporary-tree claims. Native completion remains distinct from sandbox/backend/renderer/session qualification.

RT-T251b.1 → RT-T251b.2 → VD-T251b.3 are OPEN. No full-build caps are invented; null plan stays denied pending genuine full-pipeline measurement and reviewed limits. All AC and target acceptance remain OPEN.


## v251c Genuine prepared packaging direction

Extends immutable v240/v251/v251b for R0028/R0035/R0037/R0203/R0204/R0211. Provider-held source archives cannot prove the future upstream prepared.json generated by publishPackagingInputs at the actual fixed driver workspace. Requiring that completed record as a prebuild input is circular; relabeling the upstream record as intent would conceal the boundary.

Exact contract: `planning/official-desktop-prepared-packaging-direction-v251c.json`. Source provider supplies original official packaging/archive/license and reviewed owned helper receipts, normalized inputs.tar, explicit origin-normalization manifest and separately named toolset-intent.json. The prebuild section removes generated prepared fields. Exact tar byte SHA and canonical normalized member closure are distinct; archive/member/recipe/final closure facts cannot be substituted for one another. Original v251 signed source facts are unchanged.

Driver validates these actual source inputs, performs genuine fixed native effects, invokes the real upstream packaging producer in its manager-owned fresh workspace and retains its true prepared.json inside final AppDir. Generated native-build.json binds actual prepared bytes and separate source/member facts. Independent output observer reopens generated native/toolset/package bytes and all current original input receipt joins before issuance. Unknown tools, stale paths, missing notices, unlicensed wrapper or missing actual native proof deny.

RT-T251c.1 → RT-T251c.2 → VD-T251c.3 are OPEN; Luna source/native provider and Desktop driver owners implement their respective real stages. No Python implementation, resource cap or runtime/Pi acceptance is claimed. Missing whole-build measured caps remain denied; all AC OPEN.
`planning/current-owned-remote-network-observation-v254.json` separates fresh same-owned <=30s kernel/tool observations from original one-use start, actual <=600s finite recipe and independent Access/socket/tunnel deadlines. Complete current generation/adoption/NSS/kernel watchdog must stop exact owned unit on failure; no expiry resurrection or cleanup renewal. Sustained Desktop acceptance remains OPEN, no global Jarvis timeout inferred.


## Durable source custody/fresh Xpra observation v256

`planning/durable-source-custody-fresh-xpra-observation-v256.json` specifies private immutable content custody independently of expired acquisition proofs, current source-only snapshot and new whole399 signed/control/license observation. Existing expiry/full build guards remain strict; no caller policy/path/provider, expired seal revival or TTL widening. All source/native acceptance OPEN.
