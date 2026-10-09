# Design

## Context

See proposal.md for motivation. This empty authorized installer repository has a pinned planning toolchain; no runtime behavior is implemented. The canonical Hermes/registry observed revisions are recorded in SOURCES.md.

## Goals / Non-Goals

**Goals:** Implement all linked source obligations with observable contracts, per-item adapters and meaningful failure tests.

**Non-Goals:** This planning commit does not install software on the development Mac or enroll external hardware/accounts/infrastructure. Missing dependencies remain active scope and explicit blockers.

## Decisions

A generic reviewed-source component contract has fetch/inspect/plan/stage/configure/functional-test/activate/status/update/rollback/uninstall methods, capability/schema fields, bounded command execution and a concrete unsupported/pending reason. Specialized adapters must implement the behavior; a clone or no-op handler is never installed/functional. Do not implement a universal shell escape under the component interface. Source overrides validate URL/identity/revision/license and retain explicit selection audit before any pending candidate activates.

Portable skill importer copies complete relative trees with helpers/assets/root references and licenses into read-only pristine SSD sources. Build deterministic dedup aliases and task/profile-scoped native skill external_dirs/generated wrappers; native precedence is project/local/create_dir/external_dirs at observed Hermes version, so record collision outcome. Audit AGENTS.md/CLAUDE.md hooks/commands separately; no global concatenation and no claiming Markdown equals hooks. Each table item has its own task and local fixture/target evidence method in planning/traceability.json and component-contracts.json. Keep ECC and OmniRoute aliases one component; Impeccable pbakaus and Emil's separate skills are distinct selections and attribution stays explicit; third-party cybersecurity procedures never execute during setup.

Scientific/scraping/browser/render/graph environments are feature-specific and isolated, not one global dependency pile. Scrapegraph-ai observed Python >=3.12 constraint requires its own environment. Hyperframes/brag share compatible pinned renderer dependencies when safe; narration/vision/Gemini generation remain modality/provider-budget gated. Jarvis/OpenExecutive/Ruflo/screenshot-to-code are isolated optional applications, started on demand, never default coordinators. Browser Use local browser is separate from paid cloud browser. Reference catalogs such as public-apis and selected harness catalogs are indexed references rather than service provisioning.

Use Hermes native one-active-external-memory mechanism where compatible, preserving native working/session memory. Build namespaced provider choices for OpenViking, claude-mem and explicitly selected Agent Memory; enforce one automatic capture owner while allowing scoped retrieval sources. Stop/flush previous owner when switching and protect incompatible DB schemas. At the observed Hermes revision OpenViking installs from the native plugin catalog at volcengine/OpenViking/examples/hermes-plugin, selected with memory.provider: openviking; configure the separate server and doctor. Its catalog plugin may auto-spawn a server inheriting the complete Hermes environment: prestart a sanitized isolated server with an environment allowlist and verify no unrelated provider tokens enter it. Set security.allow_lazy_installs: false; reviewed installer adapters own installation. Extraction/embedding separately pass privacy/capability/budget dispatcher. Prevent generated-memory recursive capture and store user/profile/source provenance. Synthetic fact -> extract -> stop/restart -> new-session retrieve is required; export/removal/backup/restore and isolation denial tests accompany each adapter. Unknown licenses limit redistribution and activation with exact status rather than deleting the item.

Use typed modular orchestration and explicit adapters rather than a monolithic shell script, because checkpointed operations and injectable command/network/filesystem interfaces make preservation and failure contracts testable. Prefer native supported upstream mechanisms over replacement frameworks; wrap them only at actual policy/compatibility boundaries.

## Risks / Trade-offs

- Upstream drift or unsupported ARM64 transitive dependency -> revalidate pinned source at component configure/update; retain previous generation and truthful unsupported state.
- Account or hardware unavailable -> finish code and synthetic fixtures, deliver executable target workflow, keep live verification unchecked.
- Secret or authority propagation -> host-managed references, mandatory dispatch mediation, synthetic canary and negative side-effect tests.
- Resource contention or partial failure -> measured limits, bounded cancellation, per-step journal, atomic activation and ownership-aware rollback.

## Migration Plan

Implement foundation tasks before dependent obligations. Stage artifacts and review dry-run against pre-state; isolated fixtures precede any authorized target install. Activate only compatible verified generations; restore previous pointer/config snapshot on failure and retain user data. Commit code/test/evidence with requirement and change IDs. Archive only completed verified scope and merge deltas into canonical specs through the installed supported workflow.

## Open Questions

Live target/account values and pending source selections are tracked in planning/blockers.json. The architecture supports source overrides and configure-later without deleting these requirements. New technical scope choices require a separate Sol-reviewed append-only amendment, never edits to the frozen baseline.
