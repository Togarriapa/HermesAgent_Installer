# Tasks

Dependencies: installer-bootstrap-desktop. Full IDs and task edges: planning/dependency-graph.json. Implementation owner: GPT-6 Luna. All boxes are incomplete; artifact completion is not implementation acceptance.

## 1. Foundation with tests and documentation

- [ ] 1.1 `RG-F01` Implement reviewed source fetch, root-driven discovery, validator runner, selectors/inheritance/quality materialization; verify all eight kinds, cycle/missing-version failure and provenance digest; document pipeline. Evidence: `tests/contracts/test_registry_resolution.py`.
- [ ] 1.2 `RG-F02` Implement host authorization intersection, bounded broker, Authentik fresh checks and denied-capability status; verify process/filesystem/network/account/schedule denial and token hierarchy/revocation fixtures; document policy. Evidence: `tests/contracts/test_registry_authorization.py`.
- [ ] 1.3 `RG-F03` Implement Hermes-only correlated orchestration/runtime crosswalk and state isolation; verify direct specialist rejection, dissent/contributor metadata, cancellation, concurrent HERMES_HOME denial; document topology. Evidence: `tests/contracts/test_registry_topology.py`.
- [ ] 1.4 `RG-F04` Implement overlay rebasing/quarantine and atomic generations; verify permission expansion, private overlay preservation, failed health and rollback; document update contract. Evidence: `tests/contracts/test_registry_generations.py`.

## 2. Traceable individual obligations with verification

- [ ] 2.1 `RG-R0045` Implement `R0045` in `src/hermes_installer/registry/adapter.py`: Source: Togarriapa/HermesAgent_Resources (https://github.com/Togarriapa/HermesAgent_Resources). Verify with `tests/contracts/test_adapter.py` (EV-R0045): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.2 `RG-R0046` Implement `R0046` in `src/hermes_installer/registry/adapter.py`: This is a custom declarative registry, not simply a directory of native Hermes skills. Inspect `README.md`, `catalog.yaml`, `SPEC.md`, `RUNTIME_IMPORT.md`, `TOPOLOGY.md`, `ORCHESTRATION.md`, `PROFILE_MATRIX.md`, `INTEGRATION_MATRIX.md`, `EXTERNAL_INTEGRATIONS.md`, `QUALITY_POLICY.yaml`, and the supplied validators/materializer. Verify with `tests/contracts/test_adapter.py` (EV-R0046): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.3 `RG-R0047` Implement `R0047` in `src/hermes_installer/registry/adapter.py`: Build a version-aware importer that: Verify with `tests/contracts/test_adapter.py` (EV-R0047): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.4 `RG-R0048` Implement `R0048` in `src/hermes_installer/registry/adapter.py`: Fetches a pinned commit without executing fetched content during discovery. Verify with `tests/contracts/test_adapter.py` (EV-R0048): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.5 `RG-R0049` Implement `R0049` in `src/hermes_installer/registry/adapter.py`: Discovers resources from the catalog's declared manifest roots rather than a hard-coded list. Include Profiles, Skills, Plugins, MCPs, Bundles, Channels, Crons, and Webhooks in the inventory. Verify with `tests/contracts/test_adapter.py` (EV-R0049): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.6 `RG-R0050` Implement `R0050` in `src/hermes_installer/registry/adapter.py`: Runs the repository's applicable validation tools, resolves dependency selectors and inheritance, and materializes effective specifications using its existing tooling where appropriate. Verify with `tests/contracts/test_adapter.py` (EV-R0050): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.7 `RG-R0051` Implement `R0051` in `src/hermes_installer/registry/adapter.py`: Produces an explicit crosswalk from the custom schema to the installed Hermes version's real profiles, skills, plugins, tool configuration, and runtime mechanisms. Generate an adapter where required; do not assume native Hermes understands `hermes.togarriapa/v1` YAML. Verify with `tests/contracts/test_adapter.py` (EV-R0051): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.8 `RG-R0052` Implement `R0052` in `src/hermes_installer/policy.py`: Preserves provenance, resource identities, versions, supporting files, and source paths. Keep generated artifacts separate from pristine source and private/local overlays. Verify with `tests/contracts/test_policy.py` (EV-R0052): Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.9 `RG-R0053` Implement `R0053` in `src/hermes_installer/registry/adapter.py`: Makes all valid declared profiles and skills discoverable. Report dependencies that prevent a particular capability from becoming usable. Do not fabricate MCP servers or provider implementations from their declarative names. Verify with `tests/contracts/test_adapter.py` (EV-R0053): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.10 `RG-R0054` Implement `R0054` in `src/hermes_installer/runtime/authorization.py`: Enforces relevant execution boundaries through actual runtime controls, not merely persona text. Native Hermes profiles separate state; do not assume they provide filesystem or process sandboxing. Verify with `tests/contracts/test_authorization.py` (EV-R0054): Denial fixture at actual dispatch/process/filesystem boundary: attempts beyond authorized scope fail before target side effect, including schedule/webhook/delegated identities and fresh lookup failure. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.11 `RG-R0055` Implement `R0055` in `src/hermes_installer/policy.py`: Activates a validated generation atomically and retains a rollback target. Updates must preserve local/private learning and quarantine conflicting or permission-expanding changes. Verify with `tests/contracts/test_policy.py` (EV-R0055): Recording dispatch fixture: assert exact destination/model/data classification and aggregate budget; deny paid/private-ineligible retry/fallback/extraction and preserve unavailable-route reason. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.12 `RG-R0056` Implement `R0056` in `src/hermes_installer/registry/adapter.py`: Preserve the repository's intended topology: user → Hermes → Orchestrator → internal specialists/teams → Orchestrator → Hermes. Specialists must not become independent user-facing channels. Preserve the declared response contract, scoped recruitment, contributor reporting, and material dissent where applicable. Verify with `tests/contracts/test_adapter.py` (EV-R0056): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.13 `RG-R0057` Implement `R0057` in `src/hermes_installer/registry/adapter.py`: Use resource-aware limits on concurrent agents rather than launching a process for every profile at boot. Verify with `tests/contracts/test_adapter.py` (EV-R0057): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.14 `RG-R0058` Implement `R0058` in `src/hermes_installer/runtime/authorization.py`: The repository's materializer explicitly does not apply host authorization. Finish that integration in the runtime adapter and test it. For example, if enabling its homelab administration capability, enforce its Authentik identity/group and bounded-broker requirements. If those dependencies are absent, leave that capability unavailable and report why; Verify with `tests/contracts/test_authorization.py` (EV-R0058): Denial fixture at actual dispatch/process/filesystem boundary: attempts beyond authorized scope fail before target side effect, including schedule/webhook/delegated identities and fresh lookup failure. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.15 `RG-R0059` Implement `R0059` in `src/hermes_installer/registry/adapter.py`: do not replace the checks with an instruction to the model. Verify with `tests/contracts/test_adapter.py` (EV-R0059): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.16 `RG-R0060` Implement `R0060` in `src/hermes_installer/registry/adapter.py`: Importing registry definitions must not automatically enable every scheduled task, financial integration, outbound messaging channel, webhook, or external account. Register those definitions and activate only the capabilities selected and configured for this installation. Distinguish text-core readiness, individual resource readiness, and full registry compliance. Verify with `tests/contracts/test_adapter.py` (EV-R0060): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.
- [ ] 2.17 `RG-R0061` Implement `R0061` in `src/hermes_installer/registry/adapter.py`: Missing required dependencies must not be silently rewritten as optional or counted as compliant. Verify with `tests/contracts/test_adapter.py` (EV-R0061): Catalog/inheritance/quality/topology fixture asserts source constraint, missing dependency fail-closed, complete source/runtime crosswalk and independent readiness state; compare generated artifacts/provenance. Update `docs/registry-runtime.md` and component/evidence states; preserve explicit blockers.

## Workflow follow-up

- Review code against every requirement/scenario and actual evidence; do not archive incomplete hardware/account tasks.
- Run strict pinned OpenSpec validation and coverage; archive only verified completed changes using the installed documented workflow, preserving dated history and canonical specs.
- Sol must approve refinement via append-only amendment; keep plans/2026-10-09-v1 immutable.

Audio/HTTP native input transport v40: `plans/amendments/2026-10-09-native-input-audio-http-channels-v40.md`; original5 channels retain required pending scope.

Original WhatsApp authenticated trigger v45: `plans/amendments/2026-10-09-whatsapp-authenticated-trigger-enrollment-v45.md`; source-backed setup/schema acquisition, originalchannel tasks remain pending.

Root channel peer delivery v48: `plans/amendments/2026-10-09-root-channel-peer-delivery-v48.md`; concrete originalchannel transport join, tasks open.

Composio selected trigger derivation v77: `plans/amendments/2026-10-10-composio-trigger-artifact-exchange-derivation-v77.md`; existing RG-F03/R0060/RB-T08 gates remain open and account setup proof stays distinct.

Existing resource child-attempt context v82: `plans/amendments/2026-10-10-resource-existing-child-attempt-context-v82.md`; existing RB-T08 task open.

Pre-active native assembly selection v84: `plans/amendments/2026-10-10-pre-active-native-assembly-selection-v84.md`; HI-T08/HI-T09/RB-T09 remain open.

Bootstrap action and derived store ownership v87: `plans/amendments/2026-10-10-bootstrap-action-derived-store-ownership-v87.md`; existing BD/HI/RB tasks remain open.

Selected resource materialization and task route v88: `plans/amendments/2026-10-10-selected-resource-materialization-task-route-v88.md`; RB-T08/HI-T09/HI-T12 remain open.

Nonrecursive selections and private source ceilings v90: `plans/amendments/2026-10-10-nonrecursive-selection-private-source-ceilings-v90.md`; existing original implementation and acceptance tasks remain open.

Resource task proof DTO and custody v93: `plans/amendments/2026-10-10-resource-task-proof-dto-custody-v93.md`; RB-T08/HI-T09/HI-T12 remain open.

HTTP and audio observed event schemas v94: `plans/amendments/2026-10-10-http-audio-observed-event-schemas-v94.md`; original RG-F03/R0060/native-input obligations remain open.

Resource task authority module and seal v95: `plans/amendments/2026-10-10-resource-task-authority-module-seal-v95.md`; RB-T08/HI-T09/HI-T12 remain open.

Private loopback enforcement choice v97: `plans/amendments/2026-10-10-private-loopback-enforcement-choice-v97.md`; existing original implementation/acceptance obligations remain open.

Local audio device/consent v118: `plans/amendments/2026-10-10-local-audio-device-consent-v118.md`; original RG-F03/R0060/HI-T08 obligations remain open.

- [ ] RG-T118.1: audio owner retain exact device/TTY/runtime/controller proof and enforce cancellation/lease during blocking capture.

- [ ] RG-T118.2: source/controller owner join selected audio v94 schema and retained one-use capture/consent artifact into genuine source issuance without fabricated identity.

- [ ] RG-T118.3: test changed enumeration, default fallback, runtime closure mismatch, overflow, revocation/cancel/timeout and byte zeroization; actual device/OS/ARM acceptance remains pending.

Channel retained peer delivery v129: `plans/amendments/2026-10-10-channel-retained-peer-delivery-v129.md`; genuine reduced source/context issuer/store required, real channel acceptance open.

- [ ] HI-T129.1: channel owner replace placeholder publish with actual retained-event/current native peer proof and atomic reduced issuer/store queue join.

- [ ] HI-T129.2: source/controller/authority/native-input owner implement fixed root delivery derivation and genuine peer-bound handles with distinct source versus target identity.

- [ ] HI-T129.3: test forged syntactic handles, old peer/epoch/generation, source retarget, missing ancestry/consent/store, duplicate publication and partial issuance rollback; actual all-five channel runtime acceptance open.

- [ ] `HI-T178.3` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T178.4` Implement and verify the exact producer ownership/order/positive and failure acceptance in `plans/amendments/2026-10-10-source-join-producers-v178.md`; fixture results never close AC01..18.

- [ ] `HI-T180.3` Implement the exact owner/order/source-member/role and positive/failure evidence contract in `plans/amendments/2026-10-10-reviewed-source-members-boundary-joins-v180.md`; source review does not close runtime or AC acceptance.


## v181 conditional identity and independent readiness

- [ ] `HI-T181.2` Select finite local overlay capabilities and preserve identity domain through active policy/native publication/loaded invocation. Exact producer/order and meaningful positive/failure evidence: `plans/amendments/2026-10-10-conditional-authentik-local-owner-setup-v181.md`. Implementation and target acceptance OPEN.


## v183 exact active effect producers

- [ ] `HI-T183.3` Publish signed tagged local-owner and exact overlay source/view/target/effect adoption. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.
- [ ] `HI-T183.4` Implement independent active NSS/source/view/loaded invocation/grant four-method owner. Producer/type/order/evidence contract: `plans/amendments/2026-10-10-signed-worker-recipes-active-overlay-producers-v183.md`. Implementation and acceptance OPEN.


## v184 exact wire clarification

- [ ] `VD-T184.3` Verify exact parser/roundtrip/hash/FK failures and pre-READY bind vs later effect-proof ordering. Exact contract: `plans/amendments/2026-10-10-network-row-wire-digest-boundaries-v184.md`; implementation/acceptance OPEN.
