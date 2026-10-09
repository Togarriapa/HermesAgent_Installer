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
