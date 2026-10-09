# Resource Quality and Completeness Contract

`QUALITY_POLICY.yaml` is the registry-wide quality layer for every resource indexed by `catalog.yaml`. It exists to make the effective configuration complete without duplicating the same safety, evidence, retry, verification, observability, and lifecycle boilerplate into hundreds of manifests.

## Effective resource composition

For quality and behavior constraints, the importer composes configuration from low to high precedence:

1. the universal defaults in `QUALITY_POLICY.yaml`;
2. the kind defaults for Profile, Skill, Plugin, MCP, Channel, Cron, Webhook, or Bundle;
3. every matching domain overlay;
4. the resource manifest itself;
5. local host/runtime policy;
6. current explicit user authority where an action legitimately requires it.

Maps merge recursively. Lists append with duplicate removal. Higher-precedence scalars replace lower-precedence scalars.

The quality layer is **restrictive/defaulting only**. It may complete missing verification, failure-handling, privacy, observability, or other generic operating behavior; it may never manufacture specialist expertise or grant a tool, credential, filesystem root, network target, account permission, user-facing route, side effect, financial authority, physical-control authority, or other capability that the resource/host did not already possess.

Host/runtime authorization remains authoritative.

## Direct substance versus inherited defaults

A resource is not complete merely because the effective merged object contains every generic quality field. The manifest itself must directly declare the behavior that identifies and bounds that resource.

Direct substance is intentionally kind-specific:

- Profiles require real role-specific instructions, responsibilities, workflow, or method content.
- Skills require an actionable specialist procedure, workflow, process, method, or equivalent ordered guidance. A description plus a short `principles` list does **not** constitute expertise.
- Plugins and MCPs require an explicit capability surface together with provider/runtime and security/permission boundaries.
- Channels require explicit Hermes-only inbound/outbound routing and channel policy.
- Crons require schedule/action declarations plus direct denial of authority derived from the schedule.
- Webhooks require authentication, replay/deduplication controls, and direct denial of authority derived merely from receipt.
- Bundles require an actual imported starting roster and may not expand authority.

Inherited defaults may make execution safer; they may not be used to disguise an otherwise content-free manifest.

## What “complete” means

Every effective resource must state enough information for another runtime or profile to use it without guessing its operating contract.

### Profile

An effective Profile defines:

- declared-role scope and out-of-scope delegation;
- intake of goals, constraints, assumptions, and current context;
- an inspect/plan/perform/verify/handoff workflow;
- evidence freshness, source traceability, and uncertainty handling;
- decision and trade-off rules;
- execution/side-effect authority boundaries;
- collaboration and recruitment handoff context;
- failure and escalation behavior;
- privacy/secret handling;
- observability/audit expectations;
- structured output expectations.

Only Hermes may be user-facing. A Profile cannot acquire authority from recruitment, scaling, bundle membership, previous similar work, or inference.

### Skill

An effective Skill defines:

- expected inputs and preconditions;
- a reusable domain procedure;
- evidence/input traceability;
- verification and success criteria;
- common failure modes;
- outputs and limitations;
- whether side effects exist and how they are authorized.

Every Skill manifest must contain substantive specialist method content that another agent can actually follow. Qualifying content normally includes an ordered `procedure`, `workflow`, `process`, `method`, `steps`, `playbook`, or equivalent instruction set with multiple meaningful operations. Token principles, labels, or slogans do not satisfy this requirement by themselves.

Analytical/advisory Skills should normally state their verification criteria and `sideEffects: none`. Skills that can lead to side effects must distinguish planning/advice from the independently authorized execution path.

### Plugin

An effective Plugin defines:

- explicit capability exposure and default-deny behavior;
- credential isolation and least privilege;
- network timeout/retry/TLS behavior where applicable;
- write/destructive/financial side-effect rules;
- failure behavior;
- audit/redaction behavior;
- provider/source provenance expectations.

A provider connection never grants a Profile authority by itself. Capability exposure should be allow-listed or otherwise bounded rather than inferred from a provider name.

### MCP

An effective MCP definition specifies explicit tools/roots or another bounded capability surface, runtime isolation, credentials, operation timeouts, side-effect policy, failure handling, auditing, and source/version provenance. Where a server supports root or toolset restriction, the manifest should use it rather than expose the full server by default.

### Channel

An effective user channel specifies identity/admission, Hermes-only routing, session isolation, payload/rate/attachment limits, replay or message-ID deduplication, privacy/logging, delivery failure behavior, and observability.

No channel may expose a non-Hermes Profile directly.

### Cron

An effective Cron defines schedule/timezone, concurrency, idempotency, misfire behavior, timeouts/retries, mutation authority, failure notification, Hermes routing for user-visible results, and audit records.

A schedule is never standing authorization for an otherwise privileged side effect. `authorityFromSchedule: deny` must be present directly in the Cron manifest; an inherited default alone is not considered a sufficient authority boundary for scheduled execution.

### Webhook

An effective Webhook defines authentication, event/schema validation, replay protection, deduplication, payload/rate limits, side-effect authority, safe failure behavior, audit records, and Hermes routing for user-visible results.

Receipt of a webhook is evidence that an event arrived; it is not implicit authorization to perform unrelated external writes. `authorityFromWebhookReceipt: deny` must be present directly, and state-changing/event-driven webhooks require replay and deduplication controls appropriate to the sender.

### Bundle

An effective Bundle defines its purpose, starting composition, dynamic recruitment behavior, authority non-escalation, deliberation mode, lifecycle/release rules, completion verification, and contributor/delegation observability.

Bundles compose resources; they do not create new permissions.

## Infrastructure authorization and alarms

Infrastructure writes remain bounded by current Authentik effective-group authorization. Where a manifest sends an infrastructure or registry-health alarm to privileged recipients, the resource must:

- require the effective Authentik `System` group;
- resolve recipients at delivery time rather than treating a static list as authority;
- evaluate direct and indirect membership according to the host authorization adapter;
- fail closed when recipient authorization cannot be verified;
- preserve separate destructive-action confirmation, rollback, and post-change verification requirements.

A Cron, Webhook, alarm, bundle, provider connection, cached claim, or prior successful authorization never creates fresh infrastructure mutation authority.

## Domain overlays

`QUALITY_POLICY.yaml` applies additional constraints when resource names/tags indicate a domain with recurring risks or evidence requirements. Current overlays cover:

- legal/regulatory/privacy;
- finance/investment/insurance;
- health/psychology/nutrition;
- children/education;
- physical engineering/property/farm/automotive/additive manufacturing;
- Catholic theology/tradition/family guidance;
- research/information integrity/history;
- software/data/infrastructure;
- professional translation.

The overlays are intentionally conservative and additive. A resource may define stricter or more detailed rules.

## Materialization

Runtime/importer implementations should materialize the effective policy before instantiating a resource and retain both:

- the declared manifest; and
- the effective merged contract with the quality-policy version that produced it.

Secret placeholders remain unresolved during registry parsing/materialization. Runtime injection happens only after authorization and isolation policy are applied.

## Validation

`python scripts/validate_quality_v22.py` iterates every catalog entry individually, applies the quality policy, and checks that the resulting effective contract is complete for its kind. It additionally rejects resources whose direct manifest does not contain the kind-specific substance that inheritance cannot safely manufacture.

For Skills, the validator requires substantive procedural/method content rather than accepting `principles` alone. For Plugins/MCPs it checks explicit bounded capabilities and security policy; for Crons/Webhooks it checks direct authority-denial declarations; and for infrastructure notifications it checks the Authentik `System` recipient boundary.

The validator is complementary to:

- `validate_registry.py` — envelope, dependencies, topology and key integration invariants;
- `validate_deliberation.py` — debate and six-section Hermes response invariants;
- `validate_expansion_v21.py` — specialist expansion coverage and high-risk role boundaries.

## Evolution rule

Global quality defaults are a restrictive registry policy rather than a resource capability version. Updating them must:

1. remain non-authority-expanding;
2. preserve all explicit resource boundaries;
3. pass the full validation suite;
4. document behavior-affecting changes;
5. preserve learned/private overlays;
6. allow rollback to the prior quality-policy version.

If a resource itself gains a new capability, changes its professional responsibility, changes an integration permission, or otherwise changes its public manifest contract, its own semantic version must still be bumped normally.
