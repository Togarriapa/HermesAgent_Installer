## ADDED Requirements

### Requirement: Self-contained owned source bundle (RB01)

Package the complete pristine tracked Resources snapshot, all eight catalog roots and catalog/quality/schema/validator/materializer/supporting files at the pinned revision. Installation and repair SHALL not fetch or require the Resources upstream repository.

#### Scenario: RB01 observable operation

- **WHEN** upstream DNS/network unavailable during install
- **THEN** verify bundle digests and generate native artifacts using only packaged Resources input; no Resources HTTP/git request

### Requirement: Native materialization and discovery (RB02)

Compile every valid profile, skill, plugin, MCP, bundle, channel, cron and webhook into the installed Hermes native mechanism or an explicit reviewed operational adapter. SHALL preserve the all-item source-to-native crosswalk; YAML copies and inventory rows alone SHALL not count as materialization.

#### Scenario: RB02 observable operation

- **WHEN** all 692 declarations are processed
- **THEN** every item has native destination/adapter identity and discoverability evidence or exact incomplete reason; profiles/skills have actual native discovery and selected workflow invocation

### Requirement: Compatible full-content enrichment (RB03)

Resolve referenced pinned projects to compatible full content, helpers, assets and hooks, preserving licenses/provenance and installing actual entrypoints with declared dependencies. SHALL wire that content into profile/orchestrator workflows rather than paste reference summaries.

#### Scenario: RB03 observable operation

- **WHEN** a referenced skill uses a relative helper and runtime hook
- **THEN** native invocation resolves preserved helper/assets, exercises actual hook and reports its effect through the owning workflow; incompatible or unlicensed reference is incomplete

### Requirement: Ownership-safe generations and restoration (RB04)

Stage source, enrichment and native generations separately from user/private overlays; SHALL reject path escapes, preserve unrelated existing content, quarantine conflicting or permission-expanding overlays and restore the last working generation atomically.

#### Scenario: RB04 observable operation

- **WHEN** enrichment or health verification fails after staging against an existing customized installation
- **THEN** previous generation and private/user bytes remain intact; staged incomplete artifacts do not become enabled; retry and restore reproduce the crosswalk

### Requirement: Honest completion and offline acceptance (RB05)

SHALL distinguish bundled, validated, materialized, discovered, authenticated, functional, enabled and target-verified states for every resource and enrichment. All required dependencies/accounts remain incomplete until genuinely verified. Full completion SHALL require meaningful native workflows and all applicable acceptance, not copied/import metadata.

#### Scenario: RB05 observable operation

- **WHEN** required MCP account is absent but its declaration and configuration exist
- **THEN** resource and full-compliance remain incomplete with scoped next step; no fabricated native operation, account success or missing-required-as-optional status
