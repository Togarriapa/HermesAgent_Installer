# Proposal

## Why

The baseline requires actual host authorization and private/public runtime isolation. Profile names, injectable policy classes and transient user services cannot establish that custody; the concrete trusted host boundary must be specified before enabling native dispatch.

## What Changes

- Refine R0054/R0058/R0109/R0111/R0130/R0151/R0155 through append-only Sol amendment HI01..HI06 and separate implementation versus native acceptance tasks.
- Select root-owned host custody, distinct unprivileged service identities, kernel isolation and protected typed IPC, retaining all original obligations and AC05/06/08.
- Keep incomplete native wiring, account authority and target probes pending; no runtime acceptance or canonical runtime sync is claimed.

## Capabilities

### New Capabilities

- `host-principal-custody`: trusted host principal custody and mandatory mediated runtime dispatch.

### Modified Capabilities

None; pending baseline runtime specifications remain intact.

## Impact

Luna runtime authorization, provider/credential brokers, service generation, native Hermes tool binding and lifecycle adapters. Existing task bindings RG-F02, PR-F01/03, LC-F04 and planning/traceability.json remain authoritative. Supplemental DAG and exact tests are in planning/host-principal-custody-amendment.json. This change refines existing scope, adds no enrolled target/account, and changes no runtime code.

## Fixed local service transport refinement

HI07/HI-T07 preserves native Xpra, Colibri and reviewed memory/MCP service transport without expanding general worker network authority. Read plans/amendments/2026-10-09-fixed-local-service-connector-v1.md. No arbitrary address family, destination or account is enabled.

HI08/HI09 add concrete native per-request provenance and distinct caller/service root enrollment, resolving current integration gaps within existing host/private-routing obligations. No caller labels or process-start envelopes are promoted to native request authority.

## Fixed process inspection refinement

HI10/HI-T10/EV-HI10 concretizes existing remote native process/sandbox proof; HI07 wire names are fixed in planning/native-host-service-contract.json. See append-only fixed-process-inspection-v1.

## Cross-process native handoff refinement

HI11/HI-T11/EV-HI11 operationalizes existing HI08/PR source lineage for actual producer and gateway peer separation, without transferring bearer authority.

HI11 wire clarification in native-cross-process-bridge-v2 captures complete request directly; existing source snapshots are bounded retained ancestry, not portable effect authority.

## Exact operation rule refinement

HI12/HI-T12/EV-HI12 completes existing HI03/HI07 narrow effect semantics for multiple verbs on one target; no broadened target or wildcard authorization.

## Protected native enrollment proof fields

HI10 protected Desktop enrollment requires actual immutable app manifest and renderer role/exe/tree digests, sandbox policy, relaunch monitor artifact/digest and window-denial patch artifact/digest. Missing installed value is incomplete; planning never invents a binary or patch SHA. Renderer flags/kernel namespace/seccomp/parent lineage and actual relaunch/window control observations must come from root inspector, not caller booleans. Role-specific browser/renderer/helper expectations are pinned; mainPID-only flags/seccomp do not prove renderer sandbox. sandbox_attestation schema1 fields and invalidation rules are in native-host-service-contract.json. New process/member/exe/generation/monitor/patch change invalidates exposure until fresh complete proof; preserve original actual native negative probes.

HI11 authority.json may contain strict native_bridges list with id,producer_profile_id,gateway_profile_id,canonicalizer_artifact_id,canonicalizer_sha256,approved_operation. Root joins principals/process_profiles for actual protected roles/UID/exe/profile and provider_enrollments for exact selected effect target/recipient/model/account; current peer PIDFD/starttime/cgroup/generation comes from trusted live process registry. Unique exact producer/operation mapping; duplicate/missing/ambiguous joins or absent immutable canonicalizer digest deny. Config lists no arbitrary process/URL/role supplied by worker. Complete request capture and same protected canonicalizer semantics from v2 stay required.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.

Native resolver reader v2: planning/native-package-binding-contract.json and plans/amendments/2026-10-09-native-resolver-reader-v2.md define peer-bound path-free immutable reader and presentation-only resolver; root re-resolves every effect. Existing HI-T08/09/RB-T09 remain open; document facade schemas retain actual tool/device/native evidence gates.

Fixed recipe/session clarification: plans/amendments/2026-10-09-fixed-operation-recipes-voice-sessions-v1.md defines selection-only operation_recipes and bounded root-observed voice sessions. Existing HI-T09/HW-T03/RB-T09 remain open; no caller shell/device/session authorization claims.

Native protected config v3: plans/amendments/2026-10-09-native-protected-config-v3.md specifies strict native-packages.json package/issuer joins and separate canonical normalization-policy/module hashes. Existing HI08/09/11/RB08/provider tasks remain open; config presence is not actual observer/native evidence.

Operation parameter grammar v2: plans/amendments/2026-10-09-operation-parameter-grammar-v2.md and native-package-binding-contract.json define exact root scalar schema catalog and argv token grammar; recipe ID distinct from process.start and full digest bound. Existing tasks remain open.

Selected binding/memory recipes v4: plans/amendments/2026-10-09-selected-native-binding-memory-recipes-v4.md defines root no-argument peer-selected package and fixed compound route steps with fresh child grants, no caller path/provenance or reused outer grant. Existing HI-T08/09/SK-T01 remain open.

Canonical native digest v4: plans/amendments/2026-10-09-native-canonical-digests-v4.md defines exact hash preimages/encoding and separates document/module/archive identities; existing HI08/09/11 tasks remain open.

Memory compound wire v5: plans/amendments/2026-10-09-memory-compound-wire-v5.md and memory-service-connector-contract.json specify canonical body envelope/root serializer/stateful finite steps; no worker HTTPframe/scope/step authority and fresh grants each step. Existing tasks remain open.

Root-observed remote session bridge HI13: plans/amendments/2026-10-09-remote-root-session-bridge-v1.md and planning/remote-root-session-bridge-contract.json specify actual JWT/current policy/root principal binding, no gateway selfsigned claim substitute, fixed allbytes connector lease and active revocation. Management/read/tunnel credential separation preserved; native/account evidence open.

Closed memory/model recipe identities v6: plans/amendments/2026-10-09-closed-memory-model-recipe-ids-v6.md and protected contract JSON define finite schema/recipe IDs, empty model launch parameters and root-owned forced scope. Actual serializer/result/ARM64 effect evidence remains pending, existing tasks open.

Device/profile generation join v2: plans/amendments/2026-10-09-device-profile-generation-join-v2.md defines independent exact epochs and protected expected_device_generation join. ExistingHI09/HW02 evidence remains open.

Root-observed source wire v5: plans/amendments/2026-10-09-root-observed-source-wire-v5.md and native-package-binding-contract.json define root-private observed capture/event joins and peer/cryptographic/replay bounds. ExistingHI-T08/09/11remainopen, no worker issuer labels.

HI13 remote root wire v2: plans/amendments/2026-10-09-remote-root-session-wire-v2.md defines typed opaque responses/challenge/rootselectedconnectorframes, distinct one-shotasset/leasedWS, internal freshHI12grant enforcement. ExistingHI-T13/RT-F03 and actualtarget evidence remainopen.

Protected runtime assembly v1: plans/amendments/2026-10-09-protected-runtime-assembly-v1.md and planning/protected-runtime-assembly-contract.json define rootactivegeneration catalog, exact native closure/import/mount, devicekernelpolicy, dynamicbuild outputreceipt and fullcanonical effectdigest/rootpeeridentity. ExistingHI07/08/09/11/13/HW02/03 tasks/evidence remainopen.

Active source/package/build consistency v2: plans/amendments/2026-10-09-active-source-package-build-consistency-v2.md reconciles source_issuers in active generation, selected build RPC, binder closuredigest and prebuildselection/postbuildactivated package manifest. ExistingHI08/09/HW01/03tasksremainopen.

Hermes/resource selection v3: plans/amendments/2026-10-09-hermes-bootstrap-resource-job-selection-v3.md defines fixed stage/health recipes and activegeneration resourcejob/DAG/source/backend joins; BD-F03/LC-F03/LC-F04/HI-T09/RB-T08 tasks and nativeevidence remainopen.

Remote dual-principal issuer/closure proof v3: plans/amendments/2026-10-09-remote-dual-principal-issuer-closure-proof-v3.md binds activeenrollment OTP/principal/gateway records, dedicatedroot perframeissuer withoutcontextrelabel, isolatedverifierclient, actualtoken/origin receipts and loadedclosure proofs. ExistingHI08/09/11/13/RP/RTtasksremainopen.

Native manifest digest domains v4: plans/amendments/2026-10-09-native-manifest-digest-domains-v4.md distinguishes binderentrypointSHA/fixedmanifest.json+closure layout from source ResourceIdentity/resolver hashes. Existingtasksremainopen.

Protected lifecycle control v1: plans/amendments/2026-10-09-protected-lifecycle-control-v1.md defines exactrootprovision/currentintent/firstsnapshot/CASrecovery, finiteprocess.control facade andactualloadedclosureprooflimits. ExistingBD/LC/HI tasksremainopen.

Resource backend/remote role v4: plans/amendments/2026-10-09-resource-backend-remote-role-v4.md defines activeRB07 selectedbackend/bodyrecipe joins/freshchildeffects andexplicitHI13profile-role plusactualrootlaunchproof. ExistingRB-T08/HI-T13remainopen.

Additive root-state/build-mount refinement (HI09 / HI-T09 / HI12 / HI-T12): see plans/amendments/2026-10-09-root-memory-state-build-mounts-v1.md; selected protected mount nodes and separate UID0 authority journal state are mandatory. Original scope and pending target acceptance unchanged.

Resource DAG/remote setup joins v5 (HI08/09/12/13 / HI-T08/09/12/13): see plans/amendments/2026-10-09-resource-dag-remote-setup-joins-v5.md and the live resource/native/assembly/remote contracts. Per-node protected joins and root-observed provenance are mandatory; existing implementation and target acceptance remain open.

Native observed invocation context v6: plans/amendments/2026-10-09-native-observed-invocation-context-v6.md and planning/native-package-binding-contract.json define exact root response/call handles and begin/ancestry DTOs; existing HI-T08/09/11/RB-T09/provider tasks remain open.

Resource profile execution v6: plans/amendments/2026-10-09-resource-profile-task-execution-v6.md and planning/protected-resource-job-contract.json bind each task backend to existing protected process recipe/native package with fresh child process.start. Existing RB-T08/HI-T09 remain open.

Full Hermes source archive v2: plans/amendments/2026-10-09-full-hermes-source-archive-pin-v2.md and planning/protected-artifact-source-catalog.json pin complete official source/archive/export identity. Source staging is separate from runtime/install/native acceptance; existing BD/HI tasks stay open.

Build service/bootstrap provenance v7: plans/amendments/2026-10-09-build-service-bootstrap-record-provenance-v7.md defines exact dedicated build profile join and root-selected identity versus actual runtime receipt provenance. Existing HI/HW/BD/LC tasks remain open.

Root setup/journal selection v8: plans/amendments/2026-10-09-root-setup-session-journal-catalog-v8.md specifies installed root-local initial session/intent/receipt transport and active root journal catalog. Existing HI/BD/LC/SK tasks and target evidence remain open.

Native observer/delivery/composite v9: plans/amendments/2026-10-09-native-observer-delivery-composite-v9.md defines exact adapter issuer joins, root-issued response lookup transport and strict outer→root finite child workflows. Existing HI/PR/RB tasks remain open.

Voice immutable workflow artifacts v10: plans/amendments/2026-10-09-voice-workflow-artifacts-v10.md and its JSON artifacts define exact selected recipes/action/schema/hash; actual root engine/primitive/native acceptance remains pending.

Private origin probe connector v11: plans/amendments/2026-10-09-private-origin-probe-connector-v11.md defines separate root-private typed issuer/consumer using exact existing HI12 payload/operation authority. Public RemoteSessionBinding/Access path unchanged; all HI13/remote target tasks remain open.

### v11 protocol refinement

HI-T08 / HI-T09: use planning/protected-runtime-assembly-contract.json native_custody_proof_protocol; immutable mount metadata alone cannot establish readiness, source provenance or action success. Existing task IDs and unchecked acceptance states are preserved.

### v12 loader progress framing

HI-T08/HI-T09 use native_custody_proof_protocol.progress_wire in planning/protected-runtime-assembly-contract.json; concrete root receiver and actual selected loader observations are required. Acceptance remains unchecked.

### v13 private probe joins

HI-T12/HI-T13 use private_origin_probe.connector_authority principal_join, sequence_domains and per_action_probe in planning/remote-root-session-bridge-contract.json; current protected native principal and immutable root child handles are mandatory. Acceptance remains pending.

### v16 installed input closure joins

Use the exact installed_selection_catalog.release_root, task_runner_protocol.source_resolver and native-package-binding-contract.json initial_native_input_observer joins. Existing BD/HI/RB tasks and acceptance remain pending.

### v17 supported loader and task controller

Use assembly native_custody_proof_protocol.systemd_transport/pending_pair_selector and resource task_runner_protocol.neutral_types/controller_source_split/root_event_context. Existing HI/RB tasks remain open; actual kernel effects required.

### v19 setup store and probe DTO

Use installed_selection_catalog artifact_catalog/artifact_store joins, root task canonical payload bytes and gateway_probe_response exact envelope. Existing BD/HI/RB tasks remain pending.

### v20 exact root peer/controller DTOs

Use pending_pair_DTO and task_runner_protocol.RootTaskController exact records/role mapping/PIDFD ownership. Existing HI/RB tasks remain pending.

### v23 root resource controller enrollment

Use active resource_controller_roles and root_controller_role_catalog exact actual daemon/module/source/backend/operation joins; current handler module SHA and stricter effective result bounds apply. HI/RB tasks remain pending.

### v24 native MCP handler binding

MC-F01/MC-F02 and HI-T04/08/09 use native-package-binding-contract.json native_mcp_dispatch exact source-backed in-process hook/catalog/RPC/result joins. All original native/account acceptance remains pending.

### v25 MCP lexical/config mapping

Use native_mcp_dispatch row_types/invocation_mapping/native_config exact records, same one-use lexical binding and root-backed native candidate registration. MC/HI acceptance remains pending.

### v29 native task and credential joins

Use separate result generation_api domains, task_runner_protocol.native_execution_receipt and backend_enrollments.credential_bindings exact active joins. Existing HI/RB tasks remain pending.

Root-selected lifecycle authority v80: `plans/amendments/2026-10-10-root-selected-service-lifecycle-authority-v80.md`; existing HI/RT/SK tasks open, separate actual controller and selected subject proof required.

Native registration projection v99: `plans/amendments/2026-10-10-native-registration-projection-v99.md`; exact source registration/selector/local-family coverage required; existing implementation and acceptance tasks remain open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.

Verified Xpra source pin v101: `plans/amendments/2026-10-10-xpra-verified-source-pin-v101.md`; exact source tree/finite links/actual transform and runtime proof required; no source-only acceptance or missing native-family waiver. Existing tasks open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Private loopback host tool pins v103: `plans/amendments/2026-10-10-private-loopback-host-tool-pins-v103.md`; finite actual package/executable/dependency/namespace proof, no source-only or target acceptance; existing tasks remain open.

Application owned execution receipts v104: `plans/amendments/2026-10-10-application-owned-execution-receipts-v104.md`; actual distinct selected grant/controller/probe/manager terminal/artifact result producer required, no ResourceTask/RuntimeReview substitutes; existing implementation/acceptance tasks open.

Host tool observation v105: `plans/amendments/2026-10-10-host-tool-observation-v105.md`; finite network-owned host package producer, actual held installed dependency closure/currentness, no Coral receipt substitute. Existing implementation and acceptance tasks remain open.

Xpra managed transform v106: `plans/amendments/2026-10-10-xpra-managed-transform-v106.md`; finite managed target and actual PM/module/source/terminal/CAS receipts required. Existing HI-T09/HI-T13 implementation and acceptance remain open.

Xpra regular source build pin v109: `plans/amendments/2026-10-10-xpra-regular-source-build-pin-v109.md`; exact module/source topology, file builder root and data output role. Existing managed proof/acceptance tasks open.

Native local result bounds v110: `plans/amendments/2026-10-10-native-local-result-bounds-v110.md`; actual eight local schemas/recursive transport budget and unchanged protected result gates, no all18 omission. Implementation/acceptance tasks remain open.

Xpra link target source pin v111: `plans/amendments/2026-10-10-xpra-link-target-source-pin-v111.md`; final committed module and exact five link target byte hashes/sizes; managed proof/acceptance still required.

Native local schema artifacts v112: `plans/amendments/2026-10-10-native-local-schema-artifacts-v112.md`; eight literal source schema IDs/hashes and actual packaged receipt/validator/generation join. Existing all18 implementation/acceptance tasks remain open.

Protected native registration records v113: `plans/amendments/2026-10-10-protected-native-registration-records-v113.md`; separate42 registration/61action protected arrays from actual preactive source selections, typed workflows/observers/schemas, bounded backend-data wrappers. Existing HI-T08/HI-T11/HI-T12 and all18 acceptance remain open.

Native schema catalog identities v114: `plans/amendments/2026-10-10-native-schema-catalog-identities-v114.md`; exact eight literal catalog-compatible IDs, sourcebytes unchanged; actual receipt/assembly/acceptance still open.

Prepared build service selection v115: `plans/amendments/2026-10-10-prepared-build-service-selection-v115.md`; source-owned setup-only exact build subject/current NSS/root selection before activeprofile, no fabricated worker. Existing build/setup/acceptance tasks remain open.

Native financial/web bounded results v120: `plans/amendments/2026-10-10-native-financial-web-results-v120.md`; HI-T08/HI-T11 implementation and actual acceptance remain open.

Financial alias source bound v121: `plans/amendments/2026-10-10-financial-alias-source-bound-v121.md`; source128-character alias domain preserved, HI-T120 obligations open.

Native process role association v123: `plans/amendments/2026-10-10-native-process-role-association-v123.md`; actual role/source/loaded observer joins and acceptance remain open.

Web content root receipt v126: `plans/amendments/2026-10-10-web-content-root-receipt-v126.md`; actual bounded captured source/CAS/handler proof required; HI-T08/HI-T11 acceptance open.

Setup selectors/private profile v133: `plans/amendments/2026-10-10-setup-selector-private-profile-v133.md`; persistent root intent versus fresh actual identity/namespace snapshots, genuine v91 source-bound purpose profile choice. No authority lease extension or Resources alias; all AC remain open.

Native process-role delivery v134: `plans/amendments/2026-10-10-native-process-role-delivery-v134.md`; exact manifest role rows/digest and actual loader import observations with independently verified root custody, not adapter inference or catalog-only loaded proof. All AC open.

Initial native policy source v137: `plans/amendments/2026-10-10-native-policy-preparation-source-v137.md`; root TTY setup-owned actual target/effect/role/observer selection feeds first assembly, no active-before-selection, static-source authority or live proof inference. All eighteen obligations/AC remain open.

Public input/web permission v138: `plans/amendments/2026-10-10-public-input-web-permission-v138.md`; actual PUBLIC input plus purpose-specific finite scope permission, zero budget and per-retry currentness; no private consent widening or profile-based classification. All AC remain open.

Web registration source cohort v140: `plans/amendments/2026-10-10-web-registration-source-pin-v140.md`; actual current module pins/receipts and renewed register-call capture, historical source inventory unchanged, all AC open.

Finance registration source cohort v141: `plans/amendments/2026-10-10-finance-registration-source-pin-v141.md`; actual held current module and refreshed finite registration/schema source joins, bounded data distinct account/execution authority; all AC open.

Protected public web scope source v142: `plans/amendments/2026-10-10-protected-public-web-scopes-v142.md`; actual root configuration/source selection projects into nonrecursive active scopes independently of per-input PUBLIC egress permission. All AC open.

Durable setup choice signing v143: `plans/amendments/2026-10-10-durable-setup-choice-signing-v143.md`; actual same-key custody normal-session bridge and held release member source replace nonexistent pre-active AuthorityService. Publisher adoption distinct fresh runtime permissions. All AC open.

Source choice identity/order v146: `plans/amendments/2026-10-10-model-choice-observation-order-v146.md`; actual held root observation, completed TTY/source choice and later model verification, correctly named release digest and canonical public scope source. All AC open.

Concrete bootstrap/source/public disclosure v149: `plans/amendments/2026-10-10-runtime-member-role-public-disclosure-v149.md`; exact runtime member layout, prepared held source distinct live import, genuine per-input public disclosure. All AC open.

Runtime public choice currentness v153: `plans/amendments/2026-10-10-runtime-public-choice-currentness-v153.md`; durable adopted preference/current signed source epoch distinct fresh runtime effect/input proof, no setupTTL extension. All AC open.

Prepared source module layout v154: `plans/amendments/2026-10-10-prepared-source-module-layout-v154.md`; exact source-module members distinct root-imported module and later worker evidence. All AC open.

Runtime choice revocation source v156: `plans/amendments/2026-10-10-runtime-choice-revocation-source-v156.md`; genuine current installed actor/one-use displayed-choice TTY action, no expired setup authority.

Native capture profiles v158: `plans/amendments/2026-10-10-native-capture-profiles-v158.md`; genuine raw root input/result source and exact selected validator/action/role joins, separate presentation evidence.

Root native health start v159: `plans/amendments/2026-10-10-root-native-health-start-v159.md`; actual committed runnable authority then root health admission/control before fixture input, normal enablement withheld.

Installed local qualification v160: `plans/amendments/2026-10-10-installed-local-qualification-v160.md`; finite installed source-owned fixture dispatcher with genuine production actor/receipts and cleanup, distinct Pi acceptance.

Application build admission v161: `plans/amendments/2026-10-10-application-build-admission-v161.md`; finite actual setup managed app profile/input/output/grant and fixed source driver recipe, post-terminal output/probe evidence.

Qualification root adapter v162: `plans/amendments/2026-10-10-qualification-root-adapter-v162.md`; dedicated source-bound held root/publication/session/key namespace, actual core authority validation and untouched production constants.

Health input source delivery v163: `plans/amendments/2026-10-10-health-input-source-delivery-v163.md`; root-resolved PRIVATE fixture context, actual observer/source membership and distinct write/EOF/one-use take; no task-origin substitution.

Qualification envelope v164: `plans/amendments/2026-10-10-qualification-envelope-v164.md`; exact scoped envelope/generation/pointer/session bytes verified through held run-root FD and unchanged strict core validators.

Runtime role publication join v165: `plans/amendments/2026-10-10-runtime-role-publication-join-v165.md`; typed PM/native CAS closure and single strict atomic activation, fresh runtime committed observation independent expired setup.

Qualification key signer v166: `plans/amendments/2026-10-10-qualification-key-signer-v166.md`; genuine held key signs only exact fixture enrollment envelope before service adoption.

Qualification session storage v167: `plans/amendments/2026-10-10-qualification-session-storage-v167.md`; live session sealed/current only, retained file historical metadata without signature or authority.

Application Python entrypoint relocation v168: `plans/amendments/2026-10-10-application-python-entrypoint-relocation-v168.md`; exact held PM interpreter and finite source script normalization bound final observed tree, no ambient PATH.

Native precompile reservation v169: `plans/amendments/2026-10-10-native-precompile-reservation-v169.md`; source-backed preactive output authorization and same reservation through strict compilation/atomic publication.

Native output role correction v170: `plans/amendments/2026-10-10-native-output-role-correction-v170.md`; exact existing native-boundary-overlay/boundary-overlay, no alias or new role.

MCP discovery capture v171: `plans/amendments/2026-10-10-mcp-discovery-capture-v171.md`; genuine retained tools/list witness distinct selected tools/call result schema.

Owner overlay operations v172: `plans/amendments/2026-10-10-owner-overlay-operations-v172.md`; separate genuine4local operation rows from61backend actions, preserve42source roster/fullscope and precise pending states.

Fixture resource materialization v173: `plans/amendments/2026-10-10-fixture-resource-materialization-v173.md`; actual separately generated fixture source/materialization/discovery, never production-row relabeling.

Initial public TTY source v174: `plans/amendments/2026-10-10-initial-public-tty-source-v174.md`; actual fresh root foreground input/disclosure/source precedes admission, never promotes PRIVATE task input.

Application effect sources v175: `plans/amendments/2026-10-10-application-effect-sources-v175.md`; measured finite source members and exact stage counts remain distinct from ABI and provider acceptance.

Python config relocation v176: `plans/amendments/2026-10-10-python-runtime-config-relocation-v176.md`; actual uv-generated config and held PM base closure constrain normalization.

Selected window input v177: `plans/amendments/2026-10-10-selected-window-input-observation-v177.md`; actual focus-stable F24 events/current receipt, no aggregate bool proof.


Source-join producers v178: `plans/amendments/2026-10-10-source-join-producers-v178.md`. Exact retained setup/source/PM/native definition/member, finite fixture descriptor/service observation and local overlay invocation producers; all AC01..18 OPEN, baseline unchanged. Producer ownership/order and acceptance remain in HI-T178.1..5.

Selected native executable closure v179: `plans/amendments/2026-10-10-selected-native-executable-closure-v179.md`. Exact selected completeness, full42/61/2 inventory and18 obligations preserved; unavailable effects pending, preactive declarations distinct from loaded proof; all AC01..18 OPEN.


Reviewed source members and boundary joins v180: `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; finite exact merged module pins, corrected standalone builder role,21-field separate local-operation publication and per-worker kernel start barrier. Producer ownership/order/evidence tasks remain OPEN; baseline and all AC01..18 unchanged.


## Conditional Authentik and local-owner setup v181

Restore original R0058/R0060/R0143 conditional capability scope. Contract and sequential producer/evidence details: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. No runtime implementation or acceptance is claimed; all AC01..18 OPEN.


## Active network generation owner v182

Use the concrete RootActiveNetworkGenerationOwner/runtime signed-choice and active-publication composition in `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Replace ambiguous active_enrollment with exact current generation projection; preserve original adoption deadline and fresh revocation, release/actor/key/journal/CAS checks independently of expired setup. Own-worker kernel gate and cleanup remain mandatory, all AC01..18 OPEN.


## Concrete signed worker and active overlay producers v183

Follow `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`: exact held recipe→signed choice→service-generation producer→active PM/native custody, and signed local-owner/source/view adoption→current NSS/loaded invocation/one-use four-method grant. No setup object or static metadata becomes active authority. Source pins pending committed review, all AC01..18 OPEN.


## Network wire/digest clarification v184

Exact field sets/FKs/source and lifecycle mapping: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md` / `planning/network-row-wire-v184.json`. Generated AF_UNIX rows stay separate from existing TCP private-loopback rows; enclosing digest exists only on runtime projection. Pre-READY mount permits loader binding; effects require later actual READY/source/invocation/grant proof. All AC01..18 OPEN.


## Owner observer/source/RPC clarification v185

Exact typed registration/READY/module/source-capture and worker proxy→native.owner-overlay.execute→observed invocation→one-use grant contract: `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md` / `planning/owner-overlay-observer-wire-v185.json`. Backend61 action schemas unchanged, no synthetic observer/source authority, all AC01..18 OPEN.


## Preactive listener phase clarification v186

Actual fixed root-owned listener before recipe signing and exact authenticated active FD adoption/re-observation: `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`. No future path/socketpair or prepared receipt substitutes for active authority; no effects before adoption. Source pins pending, all AC01..18 OPEN.


## Cross-process listener activation v187

Exact supervised installed daemon/private pathname control/peer PIDFD/unit/release/source/current publication binding and one-use SCM_RIGHTS adoption: `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md` / `planning/listener-activation-channel-v187.json`. Each actor verifies only itself locally; UID0/same-process/socketpair does not prove handoff. Source pins/acceptance OPEN.


Owner result source v188: `plans/amendments/2026-10-10-owner-result-source-selector-v188.md` adds exact separately signed tool-result enrollment/issuer/channel/root-handler member, paired to the invocation and consumed grant. Generic backend observer matching is insufficient; all acceptance/source pins remain pending.

Finite native worker mode v188 also resolves the fixed reviewed Hermes -m recipe versus generic child-script matcher contradiction through a private current active worker launch proof; generic interpreter rules remain unchanged.


Committed PM identity v189: `plans/amendments/2026-10-10-committed-pm-executable-identity-v189.md` supplies exact independently verified venv executable metadata to the selected native worker parser/runtime consumer, preserving generic static catalog checks and base/venv distinction. No source pin approval or acceptance.


Same-worker namespace handshake v190: `plans/amendments/2026-10-10-same-worker-namespace-handshake-v190.md` fixes schema2 helper-only initial launch, real owned MainPID namespace observation, authenticated namespace gate then actual probes and separate one-use app release. No future namespace/skip/source pin approval.


Two-actor health v191: `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md` replaces unsafe setup-session aliasing with independently current daemon commit/source proof, actual fixed source run/events and one-use authenticated setup health intent. Only consumer-completed same-generation journal witness may enable; ACK is insufficient. All acceptance/source pins remain OPEN.


Selected view paths v192: `plans/amendments/2026-10-10-native-worker-selected-view-paths-v192.md` separates host source executable custody from fixed worker argv/path, retains byte-identical full PM venv/base closure and actual native output/package/helper views, and requires postmount inode/hash proof before release. No caller paths or broad host exposure; pins/acceptance remain OPEN.


Selected member custody v193: `plans/amendments/2026-10-10-native-worker-view-member-bind-custody-v193.md` permits only exact five native-output file binds into a separately owned readable target tree, preserving original protected root/member proof and empty hidden source parents; exact private selected/observed APIs distinguish source and target identity. All pins/acceptance OPEN.
