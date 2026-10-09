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

### Requirement: Fixed read-only registry discovery (RB06)

Implement the bundled mcp-registry and agent37-discovery plugins through host-authorized fixed registry.read metadata operations. SHALL bind public query provenance, exact service/action and bounded parameters before network bytes; deny caller URL/method, redirects, publication, installation and execution. Discovery results remain untrusted and never activate resources.

#### Scenario: Authorized bounded metadata discovery

- **WHEN** selected native discovery plugin submits an authorized public metadata query
- **THEN** root performs only enrolled bounded read, returns untrusted metadata, and rejects private/unknown query, arbitrary destination and activation

### Requirement: Protected selected event and bounded bundle jobs (RB07)

Selected cron, webhook, channel and bundle resources SHALL use protected enrollment and authenticated event provenance before effects. Root SHALL admit bounded immutable jobs and issue fresh reduced-scope grants separately for every child/attempt, preserving complete source lineage, recipient scope, private routing, concurrency limits and generation revocation. Registration SHALL not auto-enable resources.

#### Scenario: Authenticated selected event job

- **WHEN** a selected recurring/webhook/channel event starts a multi-child workflow
- **THEN** root authenticates event and current selection, consumes one job admission, issues fresh scoped per-child grants and denies replay/unselected/private-route/overlimit/stale generation before effects

### Requirement: RB08 Protected original plugin effects
The installer SHALL enforce the pinned manifest obligations through protected finite selected action schemas, immutable handler identity, exact operation/target grants, current private source lineage and scoped root credential references. External writes SHALL require independent runtime task/user-order authority and required one-shot human confirmation of the exact final payload; durable duplicate/ambiguity journals SHALL prevent blind retries.

#### Scenario: Forged or ambiguous plugin effect
- **WHEN** a native plugin supplies an unenrolled action, altered digest, caller confirmation, sibling account, consumed grant or ambiguous prior write
- **THEN** reject before backend bytes, retain truthful state and require the exact missing scope, reconciliation or fresh authority without weakening original functionality.

### Requirement: Protected native composition
The installer SHALL bind actual native producer package/adapter closure through immutable root-selected profile generation and observed issuer channels, and SHALL apply the same protected route normalization policy before final request digest and gateway effect. Caller registration/labels SHALL not establish provenance.

#### Scenario: Mutable package or divergent normalization
- **WHEN** native closure, peer generation, issuer provenance or route-normalized final payload differs from protected enrollment
- **THEN** deny before effect bytes and retain exact incomplete implementation/native evidence state.

### Requirement: RB08 Selected facade argument schemas
The installer SHALL enforce the finite source-bound Epic and voice facade action schemas with extra fields forbidden and root-owned lifecycle/session/artifact references.

#### Scenario: Caller asserts accepted Epic or microphone permission
- **WHEN** caller supplies lifecycle/session claims without current root verified receipt
- **THEN** reject before deletion, microphone bytes or backend dispatch.

### Requirement: Protected resolver reader
The installer SHALL expose only peer-bound selected immutable resolver records via path-free native.resolver.read and SHALL re-resolve current protected effect enrollment on every dispatch.

#### Scenario: Caller reuses stale resolver as permission
- **WHEN** profile generation, handler, scope or policy changed after reading resolver
- **THEN** deny affected effect before bytes; presentation records confer no authority.
