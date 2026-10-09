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
