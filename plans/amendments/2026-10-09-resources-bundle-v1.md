# Sol amendment: owned Resources bundle and native enrichment

Date: 2026-10-09. Author model: GPT-6.1 Sol. Development owner: GPT-6 Luna.

## Authority and immutability

The user states that Togarriapa/HermesAgent_Resources is theirs and explicitly authorizes pulling it locally and bundling actual content inside this installer so the source repository can later be deleted. All profiles/skills/plugins/etc must be physically materialized in native Hermes, discoverable and usable, enriched with compatible full content/helpers/assets/hooks from referenced repositories, and wired into working workflows. Copied/import metadata is insufficient; unresolved required accounts/dependencies remain incomplete. No deletion of the original repository is requested now. No Mac installer/tests, Pi operations, external account mutation or spending is authorized by this refinement.

This append-only amendment refines R0045 and R0048–R0061 without removing any of the 211 baseline requirements or AC01–AC15. Baseline commit 653ac5fbc7a02613c9951859a7d794599603459b, plans/2026-10-09-v1 and its immutable tag remain untouched. Integration base: 336e4031672a1aa36fb1533b64eb07a6d38b9703. Subsequent changes to this amendment require a new separately versioned Sol amendment.

## Exact bundle contract

Resources version2.3.1, commit 113f42d33be9e0c8f0f47f5ca998e687323dec83, Git tree c0c994b5e0b96b90cfd2fc564ea8632dff124308: 739 tracked files,692 YAML declarations (208 profiles,396 skills,18 plugins,3 MCPs,55 bundles,5 channels,4 crons,3 webhooks). Package the complete tracked tree with path/blob/per-file SHA256 manifest, executable modes and source notices; all eight catalog roots and required schemas, quality files, validators/materializer and supporting documents remain available offline. Source discovery does not execute arbitrary content. Build packaging verifies exact tree/counts and forbids unsafe links/path escapes. Native generation never modifies pristine bundled sources.

User ownership and explicit copying instruction resolves the absent Resources LICENSE vendoring blocker for this requested installer. Preserve provenance/notices and the dated authorization; do not invent an open-source grant or extend this permission to third-party dependencies. Referenced-project licenses and compatibility remain independently reviewed.

## Additive requirements and tasks

- **RB01 — Self-contained owned source bundle:** Package the complete pristine tracked Resources snapshot, all eight catalog roots and catalog/quality/schema/validator/materializer/supporting files at the pinned revision. Installation and repair SHALL not fetch or require the Resources upstream repository. Task RB-T01; evidence EV-RB01.
- **RB02 — Native materialization and discovery:** Compile every valid profile, skill, plugin, MCP, bundle, channel, cron and webhook into the installed Hermes native mechanism or an explicit reviewed operational adapter. SHALL preserve the all-item source-to-native crosswalk; YAML copies and inventory rows alone SHALL not count as materialization. Task RB-T02; evidence EV-RB02.
- **RB03 — Compatible full-content enrichment:** Resolve referenced pinned projects to compatible full content, helpers, assets and hooks, preserving licenses/provenance and installing actual entrypoints with declared dependencies. SHALL wire that content into profile/orchestrator workflows rather than paste reference summaries. Task RB-T03; evidence EV-RB03.
- **RB04 — Ownership-safe generations and restoration:** Stage source, enrichment and native generations separately from user/private overlays; SHALL reject path escapes, preserve unrelated existing content, quarantine conflicting or permission-expanding overlays and restore the last working generation atomically. Task RB-T04; evidence EV-RB04.
- **RB05 — Honest completion and offline acceptance:** SHALL distinguish bundled, validated, materialized, discovered, authenticated, functional, enabled and target-verified states for every resource and enrichment. All required dependencies/accounts remain incomplete until genuinely verified. Full completion SHALL require meaningful native workflows and all applicable acceptance, not copied/import metadata. Task RB-T05; evidence EV-RB05.


Task dependency DAG and exact original requirement linkage live in planning/resources-bundle-amendment.json. RB-T01 → RB-T02 → RB-T03 → RB-T04 → RB-T05, with RG-F01/02/03/04 prerequisites. Native crosswalk and enrichment integrate with existing registry, skill, lifecycle and workflow adapters, not a second disconnected importer.

## Concrete verification and acceptance AC16

- **EV-RB01:** WHEN upstream DNS/network unavailable during install, THEN verify bundle digests and generate native artifacts using only packaged Resources input; no Resources HTTP/git request.
- **EV-RB02:** WHEN all 692 declarations are processed, THEN every item has native destination/adapter identity and discoverability evidence or exact incomplete reason; profiles/skills have actual native discovery and selected workflow invocation.
- **EV-RB03:** WHEN a referenced skill uses a relative helper and runtime hook, THEN native invocation resolves preserved helper/assets, exercises actual hook and reports its effect through the owning workflow; incompatible or unlicensed reference is incomplete.
- **EV-RB04:** WHEN enrichment or health verification fails after staging against an existing customized installation, THEN previous generation and private/user bytes remain intact; staged incomplete artifacts do not become enabled; retry and restore reproduce the crosswalk.
- **EV-RB05:** WHEN required MCP account is absent but its declaration and configuration exist, THEN resource and full-compliance remain incomplete with scoped next step; no fabricated native operation, account success or missing-required-as-optional status.


With Resources upstream unavailable or deleted, a release must install/repair from its owned bundled tree and produce actual native discovery and effectful workflows. Validate every resource identity and full enrichment path against its source manifest; representative kind-level probes do not prove every resource functional. Preserve unrelated content/private overlays; inject hook/helper failures, account absence, permission expansion and interrupted activation; prove quarantine, no unintended effects and exact restore/retry. Record bundled/validated/materialized/discovered/authenticated/functional/enabled/target-verified states separately. Disabled unselected external channels/schedules remain safe, while missing mandatory dependencies block full compliance. A small metadata test or copied YAML is never AC16 evidence.

## Handoff and truthful status

All five development tasks, RB-T06 verification and AC16 are pending. CI must run pinned strict OpenSpec validation and frozen-tree/hash checks; no local runtime commands were run for this refinement. Luna must implement release packaging, native adapters/enrichment, substantive fixture tests and an executable authorized-target offline acceptance workflow before checking task completion. Keep original 211 obligations intact and consume this additive mapping alongside them. Runtime/account/target verification remains pending; do not delete Resources upstream until the user independently chooses to after verified self-contained release and recovery.
