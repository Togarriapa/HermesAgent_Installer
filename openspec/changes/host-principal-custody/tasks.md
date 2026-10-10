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

- [ ] HI-T123.1: enrollment/runtime owner strict process_role_records parser/getter and exact profile/module/observer/action FK checks.

- [ ] HI-T123.2: factory/registration/assembler owner produce reviewed root staged definitions/role module source receipts before active publish; do not wait for pre-existing active rows.

- [ ] HI-T123.3: source/custody owner independently join actual loaded role/source proof to producer and exact selected action; test wrong role module/adapter/observer and two generations; actual native runtime acceptance open.

Web content root receipt v126: `plans/amendments/2026-10-10-web-content-root-receipt-v126.md`; actual bounded captured source/CAS/handler proof required; HI-T08/HI-T11 acceptance open.

- [ ] HI-T126.1: broker implement actual bounded dynamic root CAS/response observation/receipt resolver and root handler callpoint, distinct transport versus source/artifact proof.

- [ ] HI-T126.2: web/native/turn owners consume exact typed root receipt projection and retained ancestry; no synthesized opaque handles.

- [ ] HI-T126.3: test forged effect/native/transport, false CAS hash/inode, profile/owner/expiry mismatch, duplicate bytes across profiles, output limits and untrusted content/source semantics; real account/runtime acceptance open.

- [ ] HI-T133.1 bootstrap enrollment: stable selector intent and fresh atomic <=30s identity/namespace pair; changed subject/groups/policy/revocation/session tests

- [ ] SK-T133.2 factory: genuine purpose-bound private profile selection and same-configuration TTY producer; memory/model/app consumers use selectors and fresh receipts, never Resources aliases or old authority lease

- [ ] SK-T133.3 factory/consent/model/source owners: genuine selector/profile choice persistence and current phase joins; source preparation across snapshot renewal succeeds only same actual binding, changed identity/private-purpose/source denies
