# Resource Evolution and Learned Overlays

Hermes updates use layered composition rather than replacing effective agent configuration. The system should gain useful local experience **without forgetting it, publishing it accidentally, or allowing learning/update notifications to become authority**.

## Effective behavior order

From low to high behavior/configuration precedence:

1. registry quality defaults/domain overlays;
2. published resolved resource declaration;
3. local experience overlay;
4. private user-learned overlay;
5. current explicit session context.

Host/runtime policy is outside this chain and is the absolute authorization ceiling. No layer can add tools, accounts, filesystem/network access, transactions, physical control or user-facing routes beyond it.

## Overlay content

Local experience may retain installation-specific known-good procedures, hardware/runtime facts, recurring failures/mitigations, provider characteristics and validated workflow optimizations. Private user overlays may retain appropriate owner-scoped preferences/context. Neither layer stores secrets or is automatically published.

## Update discovery

Updates can be discovered by the daily reconcile job or by an authenticated `registry-update-available` webhook emitted after GitHub validates `main`.

A notification is **only a candidate signal**. Resource Evolution Manager must verify the repository and immutable commit, compare it with the deployed revision, and rerun local candidate validation. Webhook authentication proves message origin under the shared secret; it does not grant import, filesystem, tool or activation authority.

## Candidate update pipeline

For each candidate:

1. fetch the immutable upstream commit and verify repository/ref provenance;
2. discover/validate raw resources and dependencies/inheritance;
3. materialize effective resources using the candidate `QUALITY_POLICY.yaml`;
4. compare resource versions, permissions, integrations and compatibility with the deployed generation;
5. three-way semantically rebase local/private overlays;
6. surface conflicts instead of silently choosing a side;
7. run registry/deliberation/quality regression checks and relevant runtime smoke tests;
8. quarantine authority-expanding, ambiguous, breaking or incompatible changes;
9. create a rollback snapshot and candidate generation;
10. atomically activate only when host policy permits the classified change;
11. run health/acceptance checks and automatically roll back failed activation;
12. report import-ready/quarantined/applied outcome through Hermes.

## Conflict handling

Semantic conflicts include a removed field/tool assumed by an overlay, a learned procedure made unsafe by new policy, incompatible operational instructions, permission broadening, or a learned preference contradicted by current explicit instruction. Ambiguous conflicts are quarantined.

## Privacy and publication

User-specific learning remains local/private. A useful lesson may become an upstream improvement only after de-identification/generalization, secret/authority review and normal resource versioning/validation. Publishing a generalized lesson does not automatically delete the local overlay that proved it useful.

## Rollback/history

Retain prior upstream ref, policy version, effective materialization, overlay revisions and dependency/integration resolution metadata. Rollback restores a prior effective generation without discarding learned overlays; overlay history is independently reversible.

## Observability

Record candidate/deployed refs, notice delivery ID when applicable, policy/catalog versions, classifications, resource digest, changed resources, permission diff, conflicts, validation/overlay results, activation/rollback result and user-visible action needed. Redact secret/private values.
