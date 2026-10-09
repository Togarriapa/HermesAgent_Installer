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
