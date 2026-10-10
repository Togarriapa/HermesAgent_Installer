# Design

## Context

Existing resource-registry-import has a pristine/resolved/authorized/runtime pipeline but assumes pinned source fetch. This user-authorized amendment replaces installation dependence on Resources upstream with an owned release snapshot while keeping upstream provenance and optional explicit future-source update separate.

## Decisions

Bundle the entire739-file tracked tree from113f42d33be9e0c8f0f47f5ca998e687323dec83 under a versioned installer-owned data root. A build manifest records Git tree/blob IDs, content SHA256, modes and root/count identity. Include schemas, catalog, quality policies, validators/materializer and documents. Verify package layout/digests before using it, forbid traversal/unsafe links, and use installed package resources rather than developer working-directory assumptions. Do not execute source during discovery.

Drive all eight kinds from catalog roots through existing selectors/inheritance/quality/overlay/host-authorization pipeline. Maintain exhaustive692-declaration crosswalk from source identity to actual native destination, reviewed adapter/entrypoint, dependencies, effective policy and independent readiness states. Profiles materialize native behavioral/config/state assets; skills preserve full native directory structure; plugins/MCPs use real reviewed adapters; bundles recruit scoped internal workers; channels/crons/webhooks register safely disabled until selected/authenticated. No persona text substitutes for enforced policy.

For each referenced project, use pinned provenance plus license/ARM64/dependency review to obtain full compatible content (including helpers/assets/hooks), deterministic naming and collision handling. Enrichment manifest records original file→native path→workflow consumer and a functional probe. Wire actual hooks/entrypoints into selected workflows; full compatibility failure leaves exact affected capability incomplete. Preserve resource identities and original content; never replace a required dependency with invented implementation or silently optionalize it.

Stage complete source/enrichment/native generations separately from private overlays. Validate native discovery, policy and health before atomic activation; preserve existing unrelated native files and user edits, quarantine conflicting or permission-expanding overlays. Interrupted build/install/update/recovery uses owned journal and prior-generation restore. Never duplicate secrets or concurrent-writer HERMES_HOME.

## Risks and verification

Upstream absence must not break owned Resources installation/repair. Referenced third-party content can still need explicitly pinned review and its own dependency acquisition; self-contained Resources does not fabricate third-party accounts. Fixture contracts deny Resources network calls and exercise meaningful filesystem/adaptor/hook effects; authorized native target evidence exercises discovery, actual workflow, full item readiness, overlay collision, failed generation and restore. All tests and runtime evidence remain pending; copied metadata/string assertions cannot complete these tasks.

## Migration

Consume additive planning/resources-bundle-amendment.json alongside existing211 requirements. Implement RB-T01..05 after their existing RG foundations; keep all live original mappings and frozen files unchanged. CI validates strict OpenSpec plus original immutable hashes/tree. Archive only verified behavior; unresolved target/account/resource obligations stay open.

## Fixed discovery transport (RB06)

The pinned Resources plugin declarations permit read-only discovery/metadata, deny install/execute/publication and require source review. A protected host `registry.read` effect maps fixed service ID and typed action to exact HTTPS GET routes. Workers supply normalized bounded fields, never URL/host/method/header/socket. Root verifies current HostContext, complete query-source provenance, recipient, request digest and one-use effect grant before external bytes; unknown/private query is not eligible for public registry egress. Host uses verified TLS, fixed origin, no redirects or credential forwarding. Returned metadata is untrusted; index ranking and download/source URLs never authorize execution, installation or activation.

MCP service `mcp-registry`: origin https://registry.modelcontextprotocol.io. List GET /v0.1/servers permits bounded search, version=latest, cursor and limit. Version history GET /v0.1/servers/{encoded-name}/versions and detail /versions/{encoded-version} permit only include_deleted=false; do not invent pagination there. Encode path segments and reject path escape or destination override.

Agent37 service `agent37-discovery`: origin https://www.agent37.com. Selected API routes observed by components owner from official page implementation: GET /api/skills/search with query, limit<=30, offset, owner, repo, sort in relevance/updated and fixed minStars=10/recentlyUpdated=30; detail GET /api/skills/{id}, ID restricted to returned 32-hex identifier. Project only bounded public metadata; omit content/executable instructions. This route is an observed website implementation, not a claimed stable documented API; incompatible drift leaves discovery incomplete with exact next step.

Installer policy bounds (not upstream capability claims): normalized query<=256 UTF-8 bytes, limit<=30, at most3 pages/90 entries per operation, response<=2MiB, whole operation<=9seconds, finite cursor/ID cache bound to same caller/session/source receipt. Every follow-up page/detail requires current authorization and bounded remaining deadline; malformed/oversized responses and redirects fail before activation. Record source timestamps/provenance, independent fixture/native/live read states, no credential/account or licensing inference. Tests must count actual outbound effects/denials and payload projection; string inventory does not complete RB-T07 or original RB acceptance.

Primary MCP documentation was read directly: https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/api/official-registry-api.md and official OpenAPI. Agent37 exact route observations were supplied by the components owner after official-page/script and live GET inspection; this Sol turn independently confirms fixed source declaration and official page identity, not all delegated wire observations. Preserve that evidence distinction.

## Protected selected resource event jobs (RB07)

Follow planning/protected-resource-job-contract.json. This operationalizes original R0054/R0056/R0058/R0060 and all-kind RB02/RB03. Root enrollment fixes selected resource/kind/profile/account/credential refs/action graph/recipient and consent revision; caller selection labels or arbitrary cron/URL/graph are not authority. Protected scheduler captures actual enrolled timer event and current selection/consent before issuing source provenance; root webhook ingress resolves selected route, root-only HMAC secret reference, bounded exact bytes, protocol freshness and durable replay claim before job admission. Replay store is atomic, bounded, preserved over restart/rotation and fails closed on ambiguous/full state. Root selected official channel/account connector authenticates inbound event; outbound effects require fresh recipient/scope policy and runtime consent. No external installation-test messaging.

resource.job.admit consumes one exact fresh parent admission for the root reviewed immutable DAG and creates a bounded protected job ledger. It does not return reusable child authority. resource.job.child.admit atomically admits each eligible node with complete inherited source/result receipts, reduced capability/recipient scope and fresh one-use child effect grant for exact selected action/target/final payload/retry. Existing one-child perform_delegated_effect remains one-use; do not loop/reuse its parent grant. Root maintains node state, dependency satisfaction, finite graph/concurrency/aggregate budget/deadline, and invalidates pending/running child grants on generation change/revocation/cancel. Retries need distinct fresh grants and unchanged complete lineage. Unknown/private content never routes public because of schedule/background/bundle labels.

Fixed wire operations/targets and positive/negative evidence are in the JSON contract. Native adapters must actually invoke selected backend handlers, not only write schedule definitions or construct Python fixture objects. Register resources disabled unless user selected/configured; original topology and all692 functional obligations preserved. Account/hardware/native acceptance remains separate and open.

## Protected original plugin effects (RB08)

RB08 / RB-T09 / EV-RB08 are defined by planning/protected-plugin-effect-contract.json. All pinned manifest capabilities and deny/confirmation/privacy constraints remain mandatory. Root-selected finite schemas, exact operations/targets and immutable handler identity resolve accounts/endpoints/paths/secrets; no generic HTTP, shell or model-issued authority. Runtime external writes require separately trusted task/user-order authority, not deployment consent. Financial and destructive actions require one-shot exact-final-payload confirmation; durable idempotency and ambiguity reconciliation prevent replay.

See planning/protected-plugin-effect-contract.json and plans/amendments/2026-10-09-protected-plugin-effects-v1.md. RB-T09 evidence EV-RB08 distinguishes implementation from actual native/account acceptance.

Protected native composition clarification: plans/amendments/2026-10-09-native-package-binding-v1.md, planning/native-package-binding-contract.json and native-cross-process-bridge-contract.json define root-selected immutable package/resolver, observed source channels and shared route normalization. Existing HI-T08/09/11, RB-T09 and PR-F03/PR-T01 remain open; no caller provenance or late payload mutation.

RB08 selected facade schemas: planning/protected-plugin-effect-contract.json and plans/amendments/2026-10-09-plugin-facade-action-schemas-v2.md. Root Epic lifecycle/voice session receipts required; backend mapping remains separately source-reviewed. Existing RB-T09 stays open.

Native resolver reader v2: planning/native-package-binding-contract.json and plans/amendments/2026-10-09-native-resolver-reader-v2.md define peer-bound path-free immutable reader and presentation-only resolver; root re-resolves every effect. Existing HI-T08/09/RB-T09 remain open; document facade schemas retain actual tool/device/native evidence gates.

Fixed recipe/session clarification: plans/amendments/2026-10-09-fixed-operation-recipes-voice-sessions-v1.md defines selection-only operation_recipes and bounded root-observed voice sessions. Existing HI-T09/HW-T03/RB-T09 remain open; no caller shell/device/session authorization claims.

Native protected config v3: plans/amendments/2026-10-09-native-protected-config-v3.md specifies strict native-packages.json package/issuer joins and separate canonical normalization-policy/module hashes. Existing HI08/09/11/RB08/provider tasks remain open; config presence is not actual observer/native evidence.

RB08 voice result receipts v3: plans/amendments/2026-10-09-voice-result-receipts-v3.md defines exact STT/TTS typed output without raw PCM/path/secret; actual root-observed receipts required, existing RB-T09 remains open.

Hermes/resource selection v3: plans/amendments/2026-10-09-hermes-bootstrap-resource-job-selection-v3.md defines fixed stage/health recipes and activegeneration resourcejob/DAG/source/backend joins; BD-F03/LC-F03/LC-F04/HI-T09/RB-T08 tasks and nativeevidence remainopen.

Resource backend/remote role v4: plans/amendments/2026-10-09-resource-backend-remote-role-v4.md defines activeRB07 selectedbackend/bodyrecipe joins/freshchildeffects andexplicitHI13profile-role plusactualrootlaunchproof. ExistingRB-T08/HI-T13remainopen.

Resource DAG/remote setup joins v5 (RB07 / RB-T08): see plans/amendments/2026-10-09-resource-dag-remote-setup-joins-v5.md and the live resource/native/assembly/remote contracts. Per-node protected joins and root-observed provenance are mandatory; existing implementation and target acceptance remain open.

Native observed invocation context v6: plans/amendments/2026-10-09-native-observed-invocation-context-v6.md and planning/native-package-binding-contract.json define exact root response/call handles and begin/ancestry DTOs; existing HI-T08/09/11/RB-T09/provider tasks remain open.

Resource profile execution v6: plans/amendments/2026-10-09-resource-profile-task-execution-v6.md and planning/protected-resource-job-contract.json bind each task backend to existing protected process recipe/native package with fresh child process.start. Existing RB-T08/HI-T09 remain open.

Native observer/delivery/composite v9: plans/amendments/2026-10-09-native-observer-delivery-composite-v9.md defines exact adapter issuer joins, root-issued response lookup transport and strict outer→root finite child workflows. Existing HI/PR/RB tasks remain open.

Voice immutable workflow artifacts v10: plans/amendments/2026-10-09-voice-workflow-artifacts-v10.md and its JSON artifacts define exact selected recipes/action/schema/hash; actual root engine/primitive/native acceptance remains pending.

### v11 protocol refinement

RB-T08 / EV-RB07: use the exact root task runner protocol in planning/protected-resource-job-contract.json, including one-shot admitted UTF8 stdin plus EOF, actual terminal validation and result-capsule lineage; launch or fixture status cannot establish completion. Existing task IDs and unchecked acceptance states are preserved.

### v15 native health and typed admission

Use planning/protected-lifecycle-control-contract.json native_health_receipt for actual native health and planning/protected-resource-job-contract.json typed_admission/service_methods/recipe_domain for RB-T08. Original tasks/acceptance remain pending.

### v16 installed input closure joins

Use the exact installed_selection_catalog.release_root, task_runner_protocol.source_resolver and native-package-binding-contract.json initial_native_input_observer joins. Existing BD/HI/RB tasks and acceptance remain pending.

### v17 supported loader and task controller

Use assembly native_custody_proof_protocol.systemd_transport/pending_pair_selector and resource task_runner_protocol.neutral_types/controller_source_split/root_event_context. Existing HI/RB tasks remain open; actual kernel effects required.

### v18 root result schema validation

RB-T08 uses protected-resource-job-contract.json task_result_validator and immutable schema-hermes-task-text-result-v1 artifact. Other JSON output requires exact registered strict protected schema; acceptance remains pending.

### v19 setup store and probe DTO

Use installed_selection_catalog artifact_catalog/artifact_store joins, root task canonical payload bytes and gateway_probe_response exact envelope. Existing BD/HI/RB tasks remain pending.

### v20 exact root peer/controller DTOs

Use pending_pair_DTO and task_runner_protocol.RootTaskController exact records/role mapping/PIDFD ownership. Existing HI/RB tasks remain pending.

### v23 root resource controller enrollment

Use active resource_controller_roles and root_controller_role_catalog exact actual daemon/module/source/backend/operation joins; current handler module SHA and stricter effective result bounds apply. HI/RB tasks remain pending.

### v27 prepared native receipts and Hermes home

Use first_stage_policy_compiler exact home/prepared order/runtime artifact roles/independent Resources source and receipt_binding_rules_schema. Existing BD/LC/HI/RB tasks remain pending.

### v29 native task and credential joins

Use separate result generation_api domains, task_runner_protocol.native_execution_receipt and backend_enrollments.credential_bindings exact active joins. Existing HI/RB tasks remain pending.

Additive observation assembly v31: `plans/amendments/2026-10-09-final-observation-assembly-v31.md`; preserve existing task IDs and open target gates. Selected root registries/current custody receipts supply actual observations; static catalog or caller claims do not.

Installed release/native assembly v33: `plans/amendments/2026-10-09-installed-release-native-assembly-v33.md`; exact root receipt and construction joins preserve existing task IDs and pending evidence.

Initial identity/terminal sequencing v35: `plans/amendments/2026-10-09-initial-identity-terminal-sequencing-v35.md`; exact existing task joins remain pending.

First-stage publication/ingress v36: `plans/amendments/2026-10-09-first-stage-publication-ingress-v36.md`; exact existing task construction joins, no completion claimed.

Native candidate index delivery v38: `plans/amendments/2026-10-09-native-candidate-index-delivery-v38.md`; exact compiled member/receipt joins preserve open tasks.

Native schema artifact joins v39: `plans/amendments/2026-10-09-native-schema-artifact-joins-v39.md`; exact selected schema source mapping, original tasks remain pending.

Audio/HTTP native input transport v40: `plans/amendments/2026-10-09-native-input-audio-http-channels-v40.md`; original5 channels retain required pending scope.

Candidate toolset envelope v41: `plans/amendments/2026-10-09-native-candidate-toolset-envelope-v41.md`; exact source-backed owner/envelope metadata, tasks stay open.

First-selection/native-target v43: `plans/amendments/2026-10-09-first-selection-cas-native-target-v43.md`; exact existing task joins remain open.

Native registration/source snapshot v44: `plans/amendments/2026-10-09-native-registration-source-snapshot-v44.md`; exact existing task join, target gates open.

Original WhatsApp authenticated trigger v45: `plans/amendments/2026-10-09-whatsapp-authenticated-trigger-enrollment-v45.md`; source-backed setup/schema acquisition, originalchannel tasks remain pending.

Root task initial input v46: `plans/amendments/2026-10-09-root-task-initial-input-sequence-v46.md`; exact existing task sequencing, no target completion.

Root channel peer delivery v48: `plans/amendments/2026-10-09-root-channel-peer-delivery-v48.md`; concrete originalchannel transport join, tasks open.

Root registry phase joins v50: `plans/amendments/2026-10-09-root-intake-delivery-phase-joins-v50.md`; exact existing effect/evidence phases, tasks open.

Native materialization CAS v51: `plans/amendments/2026-10-09-native-materialization-output-cas-v51.md`; exact source/output roles, tasks open.

Initial native input peer take v52: `plans/amendments/2026-10-09-native-initial-input-peer-take-v52.md`; exact source delivery beforestdin, tasks open.

Actual EOF/schema derivation v54: `plans/amendments/2026-10-09-stdin-eof-schema-derivation-v54.md`; exact root receipt joins in planning contracts, existing task IDs remain unchecked.

Native output encoding v56: `plans/amendments/2026-10-10-native-output-byte-encoding-v56.md`; actual compiler/CAS/readonly mount proof remains required and tasks open.

Frozen task handle phase v57: `plans/amendments/2026-10-10-frozen-task-handle-write-phase-v57.md`; RB-T08 remains open.

Root key/source producer/catalog selection v61: `plans/amendments/2026-10-10-root-key-source-producer-composio-selection-v61.md`; existing task gates unchanged.

First source bootstrap actor v62: `plans/amendments/2026-10-10-first-source-bootstrap-actor-v62.md`; existing scope/tasks remain open.

Prepared base/reader/release manifest v63: `plans/amendments/2026-10-10-prepared-base-reader-release-manifest-v63.md`; existing gates remain open.

Raw resource event/result closure v66: `plans/amendments/2026-10-10-resource-raw-event-result-closure-v66.md`; existing RB task gates open.

Resource capture schemas v67: `plans/amendments/2026-10-10-resource-capture-schema-artifacts-v67.md`; existing task/acceptance gates open.

Channel retained receipts/source choice v68: `plans/amendments/2026-10-10-channel-receipts-source-selection-v68.md`; existing task gates unchanged.

Native registration projection v99: `plans/amendments/2026-10-10-native-registration-projection-v99.md`; exact source registration/selector/local-family coverage required; existing implementation and acceptance tasks remain open.

Private input recipient consent v100: `plans/amendments/2026-10-10-private-input-recipient-consent-v100.md`; actual root observed private-route choice/current input binding/epoch required, no capture-consent substitution; existing implementation/acceptance gates open.

Verified Xpra source pin v101: `plans/amendments/2026-10-10-xpra-verified-source-pin-v101.md`; exact source tree/finite links/actual transform and runtime proof required; no source-only acceptance or missing native-family waiver. Existing tasks open.

Selected runtime/profile currentness v102: `plans/amendments/2026-10-10-selected-runtime-profile-currentness-v102.md`; actual independent Resources choice/PM journal root/current consent and recipe-bound application limits; existing implementation/acceptance tasks open.

Owner overlay operations v172: `plans/amendments/2026-10-10-owner-overlay-operations-v172.md`; separate genuine4local operation rows from61backend actions, preserve42source roster/fullscope and precise pending states.

Fixture resource materialization v173: `plans/amendments/2026-10-10-fixture-resource-materialization-v173.md`; actual separately generated fixture source/materialization/discovery, never production-row relabeling.

Initial public TTY source v174: `plans/amendments/2026-10-10-initial-public-tty-source-v174.md`; actual fresh root foreground input/disclosure/source precedes admission, never promotes PRIVATE task input.

Jarvis sole user-facing profile v205: direct user requirement and audited supported default/display_name mapping; all208 source profiles preserved,207 protected isolated delegate homes, actual native/UI/default routing and ownership-safe migration required. Contract planning/jarvis-sole-user-profile-contract-v205.json; all acceptance open.

Jarvis selected task home custody v213: planning/jarvis-selected-task-home-custody-v213.json; current active held home→existing consumed task grant→fixed/hermes unprivileged mount. Root discovery not usability; all208/source/toolpolicy/namespace/private-public boundaries preserved. RB-T213.1/HI-T213.2/VD-T213.3 OPEN.

RB-T213.1/HI-T213.2 also require actual publication-owned core crosswalk/member readback and post-setup restart/current active home registry; setup-only maps cannot complete Jarvis delegate scope.

Jarvis214 corrects213 source-home/live-task field split: exact16 published facts; task process/resource/profilegen/context epochs are joined only at actual grant. Core/restart/207delegates/mount scope unchanged; planning/jarvis-published-home-live-task-split-v214.json.

Jarvis source-profile task identity v215: distinct protected source_profile_id/home_binding_id mapping, actual serviceprofile_id unchanged; typed live admission deadlines/currentgrant and prepared-vs-published16facts in planning/jarvis-source-profile-task-identity-v215.json.

CurrentpublishedPMhome runtime221: reuseexistingfreshcommittedPMresolver, exact11keyprojection/currentcore/receipt/venvFDproof; noexpiredsetupseal/newdurablehandle. planning/current-published-pm-home-runtime-v221.json HI-T221.1/.2 VD-T221.3 OPEN.
Active authority receipt aggregate v231: planning/active-authority-receipt-aggregate-v231.json closes the empty-prepared/active-core producer gap through a genuine session-owned retained receipt aggregate, pure prepublication rendering and strict identity-domain active parser; same aggregate generation reaches compiler, publisher and enrollment CAS. No caller core/rows, synthetic runtime or publication dependency cycle. HI-T231.1/BD-T231.2/VD-T231.3 OPEN; all AC OPEN.

Root service process lane v236: planning/root-service-process-authority-lane-v236.json requires actual selected6operation source declaration, separate strict protected root service binding and genuine resource-task/health admission issuer/consume; local user overlay ceiling and allow_effect remain unchanged. No weakened process validators/fakecaps or launchproof-as-grant. HI-T236.1/.2/VD-T236.3 OPEN; all AC OPEN.

Root process proof joins v236b: planning/root-service-process-proof-joins-v236b.json requires actual primaryhermes/default health-home FD/PM/currentcore binding, runtime service epoch/current adapter revision, distinct published declaration source proof and schema4 preserving exact v225schema3. No inferred profile field, claimdigest alias or restored setupseal. Existing236tasks/allACOPEN.

Cold process custody v236b: planning/root-service-process-cold-source-custody-v236b.json supersedes post-compose-only declaration construction with independent verification-only selected-key/journal/core/heldsource custody before strict parsing, then genuine dormant runtime ordinary adoptedchoice revalidation before all serving/effects. Existing tasks/allAC OPEN.


## Native plugin backend composition v253

Append-only contract `planning/native-plugin-backend-composition-v253.json` closes the actual missing root account/action/target enrollment and production broker composition. Preserve original full registration/action/workflow scope, current package/source/grants, privacy and zero additional budget. HA remains deferred; all target/account acceptance OPEN.
Root-owned sealed source/account/target observations feed the v231 active aggregate and strict protected catalog. Production runtime composes the existing fixed broker factories; arbitrary caller rows/provider callbacks and FixtureEffects cannot establish this path.


v253b source API review: `planning/native-plugin-producer-sealed-api-v253b.json` requires retained sealed vault/journal dependency getter, independent current result schema FK, fixed new GitHub /user observer and pending writes until actual attestor. No acceptance change.
