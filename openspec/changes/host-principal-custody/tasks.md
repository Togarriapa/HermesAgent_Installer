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
