# Tasks

GPT-6 Luna implements; Sol owns refinement. All original and RB/RP tasks remain unchanged. Exact DAG: planning/host-principal-custody-amendment.json.

## 1. Trusted host custody

- [ ] 1.1 `HI-T01` Implement HI01: Trusted host custody; prerequisites BD-F01, LC-F01, PR-F01. Verify EV-HI01: the host rejects activation/request before privileged effects and preserves unrelated files. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## 2. Kernel enforced worker isolation

- [ ] 2.1 `HI-T02` Implement HI02: Kernel enforced worker isolation; prerequisites HI-T01, RG-F02. Verify EV-HI02: kernel controls deny each operation and the observation identifies actual UID, namespace and target; a mock denial is recorded separately. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## 3. Authoritative identity and recipient gating

- [ ] 3.1 `HI-T03` Implement HI03: Authoritative identity and recipient gating; prerequisites HI-T01, RG-F02. Verify EV-HI03: no host write or outbound alarm occurs; exact denial and secure resume fields are recorded without cached-claim fallback. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## 4. Mandatory native dispatch mediation

- [ ] 4.1 `HI-T04` Implement HI04: Mandatory native dispatch mediation; prerequisites HI-T02, HI-T03, PR-F03, HI-T07, HI-T08, HI-T09. Verify EV-HI04: no request or secret reaches the ineligible route and a directly invoked native bypass cannot evade the host boundary. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## 5. Ownership safe custody lifecycle

- [ ] 5.1 `HI-T05` Implement HI05: Ownership safe custody lifecycle; prerequisites HI-T01, HI-T02, LC-F04, HI-T07, HI-T08, HI-T09. Verify EV-HI05: prior owned generation is recovered safely or remains disabled; stale grant is rejected, unrelated bytes and credentials are preserved. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## 6. Separate native acceptance evidence

- [ ] 6.1 `HI-T06` Implement HI06: Separate native acceptance evidence; prerequisites HI-T02, HI-T03, HI-T04, HI-T05, HI-T07, HI-T08, HI-T09. Verify EV-HI06: implementation evidence remains distinct; target tasks stay open with exact next step and no full-compliance label. Deliver meaningful effect/failure tests and docs/host-principal-custody.md; keep implementation and actual-target acceptance separate.

## Workflow follow-up

- Preserve frozen baseline, all original aliases/obligations and RP/RB amendments; review exact native/account evidence before archive or canonical runtime sync.

## 7. Fixed native local-service transport

- [ ] 7.1 `HI-T07` Implement HI07 protected target catalog and typed private-namespace local connector; prerequisites HI-T01, HI-T02, HI-T03, HI-T09. Verify EV-HI07 through actual distinct UIDs/namespaces/cgroups: allowed fixed synthetic local TCP request plus denied arbitrary target/port/URL/namespace, sibling/external traffic, stale generation/nonce, queue exhaustion, cancellation and retained-handle expiry. Add meaningful effect/failure tests and docs/host-principal-custody.md; native Xpra/Colibri/memory/MCP target acceptance remains separately pending.

## 8. Trusted native request and source lineage

- [ ] 8.1 `HI-T08` Implement HI08; prerequisites HI-T01, HI-T03, HI-T09. Verify EV-HI08: no ineligible provider/tool effect occurs; the broker validates final payload and complete fresh source closure or reports exact incomplete wiring. Exercise actual native hooks and distinct UID/process effects, forged/dropped/stale lineage, private derived payloads and separate owner roots; deliver docs/host-principal-custody.md and meaningful failure tests. Native target acceptance remains separately pending.

## 9. Protected enrollment and distinct owned roots

- [ ] 9.1 `HI-T09` Implement HI09; prerequisites HI-T01, HI-T02. Verify EV-HI09: host rejects before effects; valid enrollment uses distinct owner-scoped roots, correct process identity and preserved unrelated files. Exercise actual native hooks and distinct UID/process effects, forged/dropped/stale lineage, private derived payloads and separate owner roots; deliver docs/host-principal-custody.md and meaningful failure tests. Native target acceptance remains separately pending.

## 10. Registered native process attestation

- [ ] 10.1 `HI-T10` Implement HI10 fixed process.inspect root registered-handle descendant attestation; prerequisites HI-T01, HI-T02, HI-T09. Evidence EV-HI10: actual renderer sandbox/parent/cgroup/relaunch observation and forged sibling PID/path/stale generation failures, fixture/native evidence separate.

## 11. One-use native source bridge

- [ ] 11.1 `HI-T11` Implement HI11 root paired producer/gateway one-use source bridge; prerequisites HI-T08, HI-T09. Evidence EV-HI11: actual two-process native positive dispatch plus wrong peer/exe/generation/digest/closure/concurrent reuse/retry replay/lease/revocation negatives before bytes. Preserve original native coverage/private routing and separate fixture/target evidence.

HI-T11 must capture complete SDK envelope before prepare, not messages alone, and preserve bounded immutable parent ancestry across new per-attempt bridges; exact API signatures in native-cross-process-bridge-contract.json.

## 12. Exact operation-bound effect rules

- [ ] 12.1 `HI-T12` Implement HI12 protected capability/operation/target index and per-frame one-use connector grants; prerequisites HI-T03, HI-T07, HI-T09. Evidence EV-HI12: same-target distinct operations plus wrong operation/legacy pair/duplicate/replay/frame digest/deadline failures; watchdog/owner cancellation closes even after authority expires. Native evidence separate/open.

HI-T10 and HI-T11 additionally require protected-native-enrollment-v1 fields and actual host-observed pins/role joins; no caller renderer/monitor/patch proof or invented process enrollment. All target checks remain open.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.

Native resolver reader v2: planning/native-package-binding-contract.json and plans/amendments/2026-10-09-native-resolver-reader-v2.md define peer-bound path-free immutable reader and presentation-only resolver; root re-resolves every effect. Existing HI-T08/09/RB-T09 remain open; document facade schemas retain actual tool/device/native evidence gates.

Fixed recipe/session clarification: plans/amendments/2026-10-09-fixed-operation-recipes-voice-sessions-v1.md defines selection-only operation_recipes and bounded root-observed voice sessions. Existing HI-T09/HW-T03/RB-T09 remain open; no caller shell/device/session authorization claims.

Native protected config v3: plans/amendments/2026-10-09-native-protected-config-v3.md specifies strict native-packages.json package/issuer joins and separate canonical normalization-policy/module hashes. Existing HI08/09/11/RB08/provider tasks remain open; config presence is not actual observer/native evidence.

Operation parameter grammar v2: plans/amendments/2026-10-09-operation-parameter-grammar-v2.md and native-package-binding-contract.json define exact root scalar schema catalog and argv token grammar; recipe ID distinct from process.start and full digest bound. Existing tasks remain open.

Selected binding/memory recipes v4: plans/amendments/2026-10-09-selected-native-binding-memory-recipes-v4.md defines root no-argument peer-selected package and fixed compound route steps with fresh child grants, no caller path/provenance or reused outer grant. Existing HI-T08/09/SK-T01 remain open.

Canonical native digest v4: plans/amendments/2026-10-09-native-canonical-digests-v4.md defines exact hash preimages/encoding and separates document/module/archive identities; existing HI08/09/11 tasks remain open.

Memory compound wire v5: plans/amendments/2026-10-09-memory-compound-wire-v5.md and memory-service-connector-contract.json specify canonical body envelope/root serializer/stateful finite steps; no worker HTTPframe/scope/step authority and fresh grants each step. Existing tasks remain open.

## 13. Root-observed remote session admission

- [ ] 13.1 `HI-T13` Implement HI13 root-observed remote session admit/renew/close; prerequisites HI-T07, HI-T09, HI-T12, RP-T02, RP-T03, RP-T04. Evidence EV-HI13: actual root verified Access/native positive and forged claim/JWT/profile/config/replay/revocation negatives before allbytes; account/native acceptance open.

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

- [ ] HI-T120.1: registration/component owner apply exact finite financial/web result validators and genuine root artifact receipt resolver; no generic object schema.

- [ ] HI-T120.2: factory/schema observer/enrollment join actual packaged result schemas and external registration foreign keys; actual42 registration/61 backend effect proof separate.

- [ ] HI-T120.3: test oversized/nonfinite/control/credential output, false web receipt, stale profile/owner/expiry and untrusted redirect/content semantics; real effects and acceptance remain open.

Financial alias source bound v121: `plans/amendments/2026-10-10-financial-alias-source-bound-v121.md`; source128-character alias domain preserved, HI-T120 obligations open.

Native process role association v123: `plans/amendments/2026-10-10-native-process-role-association-v123.md`; actual role/source/loaded observer joins and acceptance remain open.

- [x] HI-T123.1: enrollment/runtime owner strict process_role_records parser/getter and exact profile/module/observer/action FK checks.

- [ ] HI-T123.2: factory/registration/assembler owner produce reviewed root staged definitions/role module source receipts before active publish; do not wait for pre-existing active rows.

- [ ] HI-T123.3: source/custody owner independently join actual loaded role/source proof to producer and exact selected action; test wrong role module/adapter/observer and two generations; actual native runtime acceptance open.

Web content root receipt v126: `plans/amendments/2026-10-10-web-content-root-receipt-v126.md`; actual bounded captured source/CAS/handler proof required; HI-T08/HI-T11 acceptance open.

- [ ] HI-T126.1: broker implement actual bounded dynamic root CAS/response observation/receipt resolver and root handler callpoint, distinct transport versus source/artifact proof.

- [ ] HI-T126.2: web/native/turn owners consume exact typed root receipt projection and retained ancestry; no synthesized opaque handles.

- [ ] HI-T126.3: test forged effect/native/transport, false CAS hash/inode, profile/owner/expiry mismatch, duplicate bytes across profiles, output limits and untrusted content/source semantics; real account/runtime acceptance open.

- [ ] HI-T133.1 bootstrap enrollment: stable selector intent and fresh atomic <=30s identity/namespace pair; changed subject/groups/policy/revocation/session tests

- [ ] SK-T133.2 factory: genuine purpose-bound private profile selection and same-configuration TTY producer; memory/model/app consumers use selectors and fresh receipts, never Resources aliases or old authority lease

- [ ] SK-T133.3 factory/consent/model/source owners: genuine selector/profile choice persistence and current phase joins; source preparation across snapshot renewal succeeds only same actual binding, changed identity/private-purpose/source denies

- [ ] HI-T134.1 native assembler: exact manifest role projection/hash and resolver digest join from sealed preactive definitions; CAS/role/FK/source mismatch tests

- [ ] HI-T134.2 boundary/loader/custody: validated selected role delivery and actual import event proof, root held member/PIDFD/mount currentness, no catalog-only loaded claim

- [ ] HI-T134.3 source/factory/runtime: root validated loaded-role proof to current selected observer registration/action joins; missing/changed role/import denies

- [ ] HI-T137.1 factory/native policy preparation: Implement actual root TTY selected native component/action/target configuration and sealed preactive policy registry feeding existing assembly; finite choice/target/current identity/source proof failures and phase renewal.

- [ ] HI-T137.2 component target/source owners: Implement finite reviewed per-component target/account/vault/permission observation adapters and protected source-role/observer definition producer; preserve configurable pending for absent auth/rights/runtime, no installation-test writes/messages.

- [ ] HI-T137.3 registration projection/source observer/native assembler/active compiler: Produce exact 61 action/42 registration/workflow/process-role/schema/observer joins from actual staged records, real root source receipts; compile then atomically publish real outputs without active-before-assembly cycle, verify all-family coverage and missing proof denial.

- [ ] PR-T138.1 factory/consent: Actual same normal configuration public-web permission producer and current root source selection snapshots; no defaults/private alias.

- [ ] HI-T138.2 source input/host authority: Actual PUBLIC source observation and initial selected input proof -> signed finite permission/source ceiling; per-dispatch nonconsuming epoch revalidation, private/UNKNOWN ancestry negative tests.

- [ ] RB-T138.3 web/native integration: Current bounded public web scope projection, actual public-only fixture positive through genuine source/authority/transport/CAS/result joins; SSRF/redirect/private ancestry/revocation/zero-budget failures. Public fixture proves only fixture behavior, not live acceptance.

- [ ] HI-T140.1 native source/projection/factory: Consume current held module pin, re-observe exact registration/action/schema source joins and current registration capture; stale source receipts/hash deny.

- [ ] RB-T140.2 web/native integration: Preserve genuine raw receipt/result/media/operation joins and PUBLIC-only egress positive with private ancestry/revocation negatives; actual runtime/account/ARM acceptance remains open.

- [ ] HI-T141.1 finance/native source/projection/factory: Current installed source/schema receipt and fresh exact registration/finite selector capture against pinned module; stale/forged source, malformed observations/alias and forbidden account fields deny.

- [ ] HI-T141.2 finance/native integration: Actual bounded observation fixture path/source ancestry and separate finance/wallet account/effect/current permission failures; no outbound transaction or account/live acceptance claim.

- [ ] HI-T142.1 native target/factory/publisher: Actual source-owned TTY public scope configuration, retained target/config source observation, first active projection and exact effect/source FK validation.

- [ ] HI-T142.2 host enrollment/authority: Strict active table/getter and PUBLIC per-input permission join; missing/conflicting source, PRIVATE ancestry, stale selection and out-of-scope URLs deny.

- [ ] HI-T143.1 bootstrap enrollment/factory/consent: Existing key custody normal-session adoption/resume and finite durable choice signer/registry, genuine TTY source methods and release member receipts; no parallel key/service.

- [ ] HI-T143.2 factory/active publisher/runtime composer: Actual signed choice adoption into selected generation and fresh runtime purpose projections; changed source/key/subject/epoch, expired snapshots and unadopted intent deny.

- [ ] SK-T146.1 factory/model selection/consent: Actual unsigned held root observation -> root TTY complete choice -> genuine small source member receipts -> durable choice -> full model-tree observer order; deployment digest named accurately.

- [ ] HI-T146.2 native target/factory/enrollment: Expose current retained canonical public scope payload resolver and compare complete payload hash/FKs; preserve operation/capability separation.

- [ ] HI-T149.1 release builder/verifier: Exact runtime-member finite role mapping and full closure validation preserving unique interpreter; genuine ARM64 bootstrap rerun separate acceptance.

- [ ] HI-T149.2 factory/source observer/native custody: Prepared held worker release-member issuer distinct actual root import and later worker mounted import/PIDFD proof; missing/unselected source or role denies.

- [ ] HI-T149.3 public permission/factory/source input: Actual rootTTY per-input public disclosure binds retained bytes/selection and source ancestry; persistent choice alone/omitted parents/private ancestry deny.

- [ ] HI-T153.1 consent/publisher/enrollment/runtime composer: Genuine durable adoption/current original source row+signature+epoch/revoke resolver beyond setupTTL, truthful postcommit recovery; no pointer-only verification.

- [ ] HI-T153.2 publicTTY/consent/factory/source input: Runtime disclosure constructor with actual installed actor/oneuse rootTTY source adapter, distinctconsentID signedproducer/public-web source literal; no live setup dependency/private relabel.

- [ ] HI-T154.1 Broker/release/factory/source observer: exact final source/installed descriptors and separate current source-membership/root-import/worker-origin proofs.

- [ ] HI-T156.1 Consent/publicTTY/host authority: actual runtime rootTTY revocation observation, finite signer transition and durable current epoch verification.

- [ ] HI-T158.1 source observer/native observer/registration/factory: Publish held capture profile members; actual selected schema/result validator FKs and finite source/action rows; root effect/provider issuer then exact peer presentation delivery. Negative raw worker capture/malformed/stale/private ancestry tests.

- [ ] HI-T158.2 host authority/consent: Exact finite revocation signature domain and closed canonical typed envelope, current row verification; no arbitrary signer.

- [ ] HI-T159.1 factory/entrypoint/startup/custody/health observer: Actual committed health admission/current receipt and root-selected-service health issuer/custody route/control-before-input producer; preserve runnable-before-health/withheld enablement.

- [ ] HI-T159.2 native fixture/observer/registration source owners: Provide genuine source-reviewed health request/result fixture artifact and actual loader/input/request/tool/provider/terminal observation closure, meaningful currentness/failure integration tests.

- [ ] HI-T160.1 root entrypoint/task kernel fixture/display fixture/controller custody: Implement fixed installed qualification source dispatcher and actual owned fixture recipe/schema assets; publish measured source pins for Sol review, real runtime/session/publication producer, no test authority shortcuts.

- [ ] HI-T160.2 task/display fixture owners: Replace synthetic Linux positive fixtures with exact production graph, preserve meaningful negative/cleanup checks and source/environment evidence distinct Pi acceptance.

- [ ] SK-T161.1 application builder/factory/custody: Implement sealed finite app admission/private FixedBuildProfile/output/service held inputs and one-use setup grant adapter; actual managed runner union/currentness/cleanup/denial tests.

- [ ] SK-T161.2 application builder/source broker: Implement fixed standalone multistep driver, provide actual committed source/member pins for Sol review, finite mount/argv/phase recipe and genuine terminal/archive/extraction/probe receipts.

- [ ] HI-T162.1 Controller custody/fixture publisher/host authority/entrypoint: genuine finite fixture compiler/key/publication/session/runtime adapter and namespace/currentness negative tests.

- [ ] HI-T163.1 Health/source/authority/custody: genuine selected source/context and health capture/write/EOF/take current-peer joins and negative tests.
- [ ] HI-T163.2 Broker/release/health: exact source asset enrollment, owned seed cleanup and semantic result gate with required actual provider.

- [ ] HI-T164.1 Fixture publisher/host enrollment/authority: exact canonical envelope and held namespace loader, scoped key/signature and wrong-source/currentness negatives.

- [ ] HI-T165.1 Factory/native/compiler/publisher: genuine typed runnable role closure and single atomic activation with truthful durable recovery.
- [ ] HI-T165.2 Enrollment/authority/health: fresh current committed source/CAS observation without expired setup renewal.

- [ ] HI-T166.1 Fixture key/publisher/authority: restricted prepublication envelope signer and same-key service adoption, source/currentness/domain negatives.

- [ ] HI-T167.1 Fixture session/publisher/enrollment: historical session file never restores live authority; fresh current lease required.

- [ ] SK-T168.1 Application builder/materializer/selection/execution: regular held PM interpreter entrypoint, finite source shebang normalization and final manifest/probe joins.

- [ ] HI-T169.1 Factory/native/compiler/publisher: actual source-authorized outputs, precompile reservation and same-reservation compiled claim transition, wrong-source/currentness negatives.

- [ ] HI-T170.1 Factory/native/compiler: exact existing five role/kind pairs and unknown-role negatives.

- [ ] HI-T171.1 Native/MCP/source/broker/policy: actual tools/list request/result witness capture before derivation, current source/peer/schema and wrong-method negatives.

- [ ] HI-T172.1 Local/native/enrollment/factory/observer: genuine owner view/target/current source operations, separate row parser/FKs/grants/root result witness and exact pending coverage.

- [ ] HI-T173.1 Resource runtime/controller/enrollment: implement genuine fixed fixture source generation, native materialization/discovery receipt and strict current projection.

- [ ] HI-T174.1 Event issuer/TTY/consent/observer/composer: actual initial public source producer before admission and strict current disclosure/replay/ancestry tests.

- [ ] SK-T175.1 Broker/factory/execution/wiring/custody: enroll exact effect sources, derive finite stage admissions, observe actual terminal/semantic/cleanup receipts.

- [ ] SK-T176.1 PM/builder/materializer/selector: held base runtime closure and exact measured config/wrapper relocation with current source and original/final digests.

- [ ] HI-T177.1 Display/window observer/broker/custody: genuine selected-window F24 events and independent current observation/source proof.

- [ ] `HI-T178.1` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.2` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.3` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.4` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [x] HI-T179.1 Implement/verify retained source-owner selected executable closure and exact projector/assembler/member/currentness denials under v179. Evidence: `docs/native-selected-source-composition-v179.md`; local source fixture only, HI-T178.1 and live acceptance remain OPEN.

- [ ] HI-T179.2 Live loaded-worker/PIDFD and external target/account/provider/device acceptance; all AC01..18 remain OPEN.

- [ ] `HI-T180.1` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `HI-T180.3` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `HI-T180.4` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.

- [ ] `HI-T180.5` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.


## v181 conditional identity and independent readiness

- [ ] `HI-T181.1` Observe genuine local owner and issue separate typed current principal/snapshot; retain strict Authentik receipt domain. Exact producer/order and meaningful positive/failure evidence: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. Implementation and target acceptance OPEN.
- [ ] `HI-T181.2` Select finite local overlay capabilities and preserve identity domain through active policy/native publication/loaded invocation. Exact producer/order and meaningful positive/failure evidence: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. Implementation and target acceptance OPEN.


## v182 active generation custody

- [ ] `HI-T182.1` Compile and publish finite signed-source/network/worker/enrollment projection. Exact producer/order/evidence: `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Implementation and target acceptance OPEN.
- [ ] `HI-T182.2` Own exact post-setup active generation, signed source/revocation and actor/key/journal revalidation. Exact producer/order/evidence: `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Implementation and target acceptance OPEN.
- [ ] `HI-T182.3` Consume current active owner projections through helper spawn/stop/release/reload cleanup. Exact producer/order/evidence: `plans/amendments/2026-10-10-active-network-generation-owner-v182.md`. Implementation and target acceptance OPEN.


## v183 exact active effect producers

- [ ] `HI-T183.1` Produce concrete held worker recipes, signed choice fields and generated service/process/network output. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.
- [ ] `HI-T183.2` Reconstruct current active PM/native worker runtime member custody independently of setup. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.
- [ ] `HI-T183.3` Publish signed tagged local-owner and exact overlay source/view/target/effect adoption. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.
- [ ] `HI-T183.4` Implement independent active NSS/source/view/loaded invocation/grant four-method owner. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.

- [ ] `HI-T183.0` Implement and source-review the exact fixed held Hermes/native-loader startup recipe source producer in `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`; no guessed argv or denial-only completion.


## v184 exact wire clarification

- [ ] `HI-T184.1` Implement exact schema2 finite network/runtime/source FK rows and acyclic canonical digest mapping. Exact contract: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`; implementation/acceptance OPEN.
- [ ] `HI-T184.2` Consume current row mapping and transient enclosing digest in real owner/manager lifecycle. Exact contract: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`; implementation/acceptance OPEN.


## v185 owner observation and proxy

- [ ] `HI-T185.1` Publish and resolve concrete tagged owner registration observer and captured-source schemas. Exact contract `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md`; implementation/acceptance OPEN.
- [ ] `HI-T185.2` Bind actual worker proxy/native execute RPC to observed invocation/current one-use local grant and CAS. Exact contract `plans/amendments/2026-10-10-owner-overlay-observer-capture-rpc-v185.md`; implementation/acceptance OPEN.


## v186 endpoint source phase

- [ ] `HI-T186.1` Create and observe actual preactive root custody socket with no effects before signed recipe. Exact contract `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`; implementation/acceptance OPEN.
- [ ] `HI-T186.2` Verify active adoption and one-use exact listener FD transfer/current active re-observation. Exact contract `plans/amendments/2026-10-10-preactive-authority-listener-custody-v186.md`; implementation/acceptance OPEN.


## v187 actual activation transport

- [ ] `HI-T187.1` Produce verified installed root daemon supervisor/unit/launch and distinct peer observations. Exact contract `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md`; implementation/acceptance OPEN.
- [ ] `HI-T187.2` Implement actual both-process authenticated activation channel and one-use exact listener FD adoption. Exact contract `plans/amendments/2026-10-10-supervised-listener-activation-channel-v187.md`; implementation/acceptance OPEN.


- [ ] HI-T188.1 Implement exact paired owner result source publication/active issuer and completed-effect capture. See `plans/amendments/2026-10-10-owner-result-source-selector-v188.md`; all AC remain OPEN.

- [ ] HI-T188.3 Implement exact typed active native Hermes module launch at manager admission/barrier. See v188; acceptance OPEN.

- [ ] HI-T189.1 Implement exact committed PM executable descriptor/private resolver/parser-runtime consumer. See `plans/amendments/2026-10-10-committed-pm-executable-identity-v189.md`; all acceptance OPEN.

- [ ] HI-T190.1 Implement exact helper/manager staged namespace gate and same-PID release. See `plans/amendments/2026-10-10-same-worker-namespace-handshake-v190.md`; acceptance OPEN.

- [ ] HI-T191.1/2 Implement exact source/run producer and independent daemon commit/health consumer. See `plans/amendments/2026-10-10-two-actor-health-commit-custody-v191.md`; all acceptance OPEN.

- [ ] HI-T192.1 Implement exact dual-path native view projection and actual selected mount custody. See `plans/amendments/2026-10-10-native-worker-selected-view-paths-v192.md`; acceptance OPEN.

- [ ] HI-T193.1 Implement exact source/target native member view compatibility and private observed APIs. See `plans/amendments/2026-10-10-native-worker-view-member-bind-custody-v193.md`; acceptance OPEN.

- [ ] HI-T194.1/2 Implement exact causal native event resolver/proof and matching receipt/completion consumer. See `plans/amendments/2026-10-10-health-event-causal-ancestry-v194.md`; acceptance OPEN.


Existing `VD-T180.6`/`VD-T183.5` handoff: apply and verify only the exact v195 source/catalog/role/import closure batch in `plans/amendments/2026-10-10-final-coherent-source-pin-review-v195.md`. This source review leaves all existing checkboxes OPEN; no duplicate task or runtime acceptance is created.


- [ ] `HI-T197.1` Implement live setup-issued fixed startup intent, cancellation and authenticated adopted-channel transport; exact contract `plans/amendments/2026-10-10-installed-startup-qualification-custody-v197.md`.
- [ ] `HI-T197.2` Compose genuine daemon intent registry/tagged display admission/controller PIDFD and attach before dispatch; no copied setup session.
- [ ] `HI-T197.3` Implement fixed owned qualification controller/source/PM/materializer/publication/session/runtime composer and both installed dispatch suites; preserve HI-T160/173/178 dependencies.
- [ ] `VD-T197.4` Replace synthetic positive display/task fixtures with genuine composed authority/custody/effects, replay/currentness/BPF/cleanup failures; all AC01..AC18 OPEN.


Existing `HI-T197.1`/`HI-T197.2`/`VD-T197.4` remain OPEN and include exact durable overlay adoption and completed-start lifecycle failures in `plans/amendments/2026-10-10-durable-xpra-startup-adoption-v198.md`; no duplicate task or acceptance claim.

- [ ] MC-R0101.1 HA/factory/vault/compiler/composer: actual root instance credential/source selection, bounded grant discovery/read and strict publication/adoption.
- [ ] MC-R0101.2 HA: protected transport/vault/publication fixtures, reconnect/revoke/write-denial/TLS/schema/CAS/redaction and separate actual-target evidence.

Existing HI-T197.1/.2/.3, HI-T173.1/178.2 and VD-T197.4 include the exact source producer ownership/order in `plans/amendments/2026-10-10-setup-startup-and-fixture-source-producers-v199.md`; remain OPEN.

- [ ] MC-R0101.3 HA/factory/consent/parser/broker: actual typed choice/exposure/current scope/schema/result/grant joins.
- [ ] MC-R0101.4 HA: real-schema Assist read fixtures, ambiguity/new exposure/unfiltered/action/revoke/TLS denial and distinct actual-target acceptance.

Existing HI-T160.1/HI-T197.2/.3/VD-T197.4 include actual protected-core producer/parser/currentness and fixed acquisition-only deadline in `plans/amendments/2026-10-10-publication-core-and-fixture-acquisition-v201.md`; remain OPEN.


Existing HI-T160.1/HI-T197.2/VD-T197.4 include exact remote chooser and three-role source input/build/runtime production in `plans/amendments/2026-10-10-selected-remote-role-source-inputs-v202.md`; remain OPEN.

- [ ] BD-T203.1 Bootstrap owner: exact typed finite-stage diagnostic/redaction/state tests with unchanged trust/failure behavior.
- [ ] VD-T203.2 Source review/recheck: measured committed future source pins and actual target diagnostic, no inferred DD00 stage/acceptance.

- [ ] BD-T203.1 / VD-T203.2 (v204): Apply only reviewed two leaf tuples, rerun stale-pin test unexcluded and retain actual target diagnostic evidence; no acceptance promotion.


Existing HI-T173.1/HI-T178.2/HI-T197.3/VD-T197.4 include exact fixture subject NSS issuer/custody/cleanup in `plans/amendments/2026-10-10-fixture-subject-nss-custody-v206.md`; remain OPEN.

- [ ] BD-T208.1: Implement final-boundary explicit root TTY reconfirmation and one-use fresh proof with unchanged identity/source/runtime joins.
- [ ] VD-T208.2: Verify slow acquisition, mismatch/drift/replay/expiry failures and review actual source pins/target result separately.

- [ ] BD-T208.1 / VD-T208.2 (v211): Apply exact reviewed root_setup tuple only, run full unexcluded regressions and retain genuine target handoff evidence.

- [ ] RB-T213.1: Produce current held-home completed materialization/active source crosswalk joins.
- [ ] HI-T213.2: Wire selected task/home digest/grant to actual fixed/hermes custody mount.
- [ ] VD-T213.3: Verify unprivileged delegate effects, isolation, stale/grant/source denial and cleanup.

RB-T213.1/HI-T213.2 also require actual publication-owned core crosswalk/member readback and post-setup restart/current active home registry; setup-only maps cannot complete Jarvis delegate scope.

- [ ] RB-T213.1 / HI-T213.2 / VD-T213.3 (v214): Implement exact published source-home vs live selected-task split, current core claim/readback and actual delegate grant/mount evidence.

- [ ] RB-T213.1 / HI-T213.2 / VD-T213.3 (v215): Implement distinct protected source mapping, typed live admission/home binding, unchanged service identity and genuine prepared/publication claim joins.

- [ ] BD-T218.1: Implement Desktop-specific selected sourcepolicy/acquisition phase and locked toolchain/dependency/license receipts.
- [ ] BD-T218.2: Consume held closure in fixed offline209212 rolebuild with native ABI/script proof.
- [ ] VD-T218.3: Verify source/phase/integrity/TLS/architecture/script/currentness failures and actual target evidence separately.

- [ ] BD-T208.1 / VD-T208.2 (v220): Integrate exact reviewed FD3 source/evidence, full coherent checks and actual target handoff; no installed selfpin or acceptance inference.

- [ ] RT-T222.1: Implement exact helddefinition/parser/source receipt and transactionrole selections.
- [ ] RT-T222.2: Join actual212NSS/209runtime/network and strictactivepublication/adoption.
- [ ] VD-T222.3: Verify source/choice/identity/currentness failures and actual target effects separately.

- [ ] HI-T221.1: Implement exactfreshpublishedhomePMadapter/projectionmetadata/FDverification.
- [ ] HI-T221.2: Wire currentPMproof into activehome/taskbinding aftersetup/restart.
- [ ] VD-T221.3: Verify fresh/stale/restart/projection/source/member/namespace failures and actualeffects separately.
- [x] BD-T208.1 FD3 defect: explicitly clear and verify close-on-exec for the same-fd placement case; preserve seals and handoff identity checks.
- [x] VD-T208.2 FD3 regression: real ARM64 Linux Python 3.14 fork/exec positive and CLOEXEC negative controls; repository Linux integration test added.
- [ ] VD-T208.2 target: repeat exact handoff on enrolled Pi and retain genuine target result; development container evidence is not Pi acceptance.
- [ ] HI-T221.1: Implement exact fresh published-home PM adapter, projection metadata and FD verification.
- [ ] HI-T221.2: Wire current PM proof into active home/task binding after setup and restart.
- [ ] VD-T221.3: Verify fresh/stale/restart/projection/source/member/namespace failures and actual effects separately.

- [ ] HI-T231.1 (v231): Retain actual service NSS, principal/namespace, PM/native closure, source/effect policy and native generation receipts in the sealed v231 aggregate; validate strict identity-domain active core before publication. Genuine pipeline/failure evidence VD-T231.3 and target acceptance separately OPEN.


- [ ] HI-T233.1: Implement retained oneshot terminal DTO/current verification and purpose-owned collection under v233.
- [ ] VD-T233.2: Validate real systemd terminal/transport, drift/failure/foreign cleanup cases and independent native acceptance.
- [ ] HI-T236.1: Produce actual selected reviewed six-operation process declaration and strict protected root-service process binding separately from local user overlay caps.
- [ ] HI-T236.2: Integrate typed current source/task/health/control process admission and one-use consume into actual root manager paths; preserve all kernel and child authority checks.
- [ ] VD-T236.3: Verify strict dual domain enrollment plus genuine task/health process effects, unchanged user ceiling and replay/currentness/sibling isolation failures; target acceptance separate.

- [ ] HI-T236.1 / HI-T236.2 / VD-T236.3 (v236b): Implement exact retained health primaryhome binding, current runtime epoch/policy revision, prepared-vs-published declaration getter/restart source custody and schema4; verify all genuine positive/currentness/legacy failures.

- [ ] HI-T236.1 / HI-T236.2 / VD-T236.3 (v236b cold custody): Implement independent read-only signed adopted-choice/current key/member issuer, strict cold parser declaration bridge, and ordinary exact runtime revalidation before activation; test restart/races/deny-before-effects.


- [ ] RT-T239.1: Retain genuine remote executor terminal proof and implement narrow remote CAS/attestation package issuer.
- [ ] RT-T239.2: Materialize exact role package through current held data-root custody and issue v209/v202 runtime receipts for v225 adoption.
- [ ] VD-T239.4: Verify terminal forgery, source/schema/root races, expiry, cross-role and owned rollback failures plus actual pipeline effect; target acceptance separate.

- [ ] RT-T239.3: Issue same-transaction remote enrollment reservation and current source/NSS-derived private-network policy selection; wire exact v202 aggregate and separate v225 kernel lease.


## Gateway source and wheel issuer refinement v244

- [ ] RT-T244.1 Implement fixed held release source receipt/member projection and reviewed exact source-member cohort.
- [ ] RT-T244.2 Implement Gateway lock/PM/choice-bound bounded acquisition, license verification, immutable CAS and retained provider/source projection integration.
- [ ] VD-T244.3 Exercise spoofed receipts, changed lock/source/PM, stale choice, cancellation, conflicting CAS, bounded dependency/license failure and genuine ARM64 production positives; target acceptance separately open.


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
