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
