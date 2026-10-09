# Hermes Resource Manifest v1

## Purpose

The manifest contract makes Hermes resources portable, reviewable, composable, dynamically recruitable, safely updateable and safe to share. The registry describes capability/configuration; **host/runtime policy and provisioned credentials remain the authorization ceiling**.

## Required resource envelope

Every discovered resource contains:

```yaml
apiVersion: hermes.togarriapa/v1
kind: Profile | Skill | Plugin | MCP | Cron | Webhook | Channel | Bundle
metadata:
  name: lowercase-kebab-case
  version: 1.0.0
  description: human-readable purpose
  tags: []
spec: {}
```

`Catalog` and `RegistryQualityPolicy` are repository-control documents, not importable resources.

## Discovery-driven catalog

`catalog.yaml` declares one non-recursive root for each resource kind and `*.yaml` as the manifest pattern. The manifest itself is the canonical identity source: directory determines the expected kind, filename must equal `metadata.name`, and `metadata.version` is semantic version.

A valid resource file is automatically part of the registry; contributors never maintain a second list. CI discovers all manifests, validates identity/dependencies/inheritance, emits deterministic kind counts and a SHA-256 resource digest, and fails closed on malformed or conflicting resources.

The catalog version is the registry release version and must increase when the resource set changes relative to the merge base.

## Dependencies and inheritance

`spec.requires` uses selectors such as `docker-ops@^1.0.0`. Importers resolve selectors by kind/name/version and fail closed when missing or incompatible.

Profiles, Skills and Bundles may `extend` another resource of the same kind. Scalars replace, maps merge recursively and lists append/deduplicate. Cycles are invalid. Dependencies/inheritance expose declared behavior/capability only within the host authorization ceiling.

## Effective quality

`QUALITY_POLICY.yaml` is the **single canonical** registry quality document. It applies conservative universal and kind-specific defaults plus narrowly matched domain overlays. It never grants credentials, tools, account permissions, filesystem roots, network targets, user-facing routes, transactions, signing, physical control or other authority.

Composition from low to high behavior precedence is:

`universal/kind defaults < domain overlays < resolved manifest < local experience overlay < private user overlay < current session context`

Host authorization is not another precedence layer; it surrounds the result. Explicit user authorization may unlock a confirmation-gated action only when the host/resource/account scope already permits it.

See `RESOURCE_QUALITY.md` and `SECURITY.md`.

## Secrets

Manifests use `${ENV_VAR}` or explicit runtime credential references. Validation/materialization must leave them unresolved. Secrets and private learned data never belong in Git, PRs, logs, generated artifacts, Kanban items or Profile-visible text.

## Conversation topology

`User <-> Hermes <-> Orchestrator <-> Specialists / Teams`

Hermes is the sole user-facing Profile. Channels reject direct specialist targeting. Orchestrator/Team Leaders are internal, may dynamically recruit any registered Profile and multiple instances, and never gain authority through recruitment or scaling. Clarifications, scheduled results, webhook outcomes and specialist output return through Hermes.

See `TOPOLOGY.md`.

## Orchestration and deliberation

Work is dependency-graph based. Independent packages should run concurrently when safe; concurrent writers require isolation/serialized integration. Bundles are starting rosters, not recruitment ceilings. Material decisions may use independent first pass, critique/steelman, Debate Analyst and evidence-based synthesis. Majority vote never overrides evidence, user constraints, safety or authorization.

Every Epic has an ephemeral Kanban until accepted completion. See `ORCHESTRATION.md` and `DELIBERATION.md`.

## External integrations

Plugins/MCPs expose only declared operations and use runtime-only credentials. Connectivity is not permission. State-changing calls are authorized at action time, bounded by timeout/retry/idempotency policy, verified afterward and reconciled before retry after ambiguous failures.

Composio is allowlist-based. Home Assistant/voice remains local-first and scoped. WhatsApp is Business-only. Kobo access uses user-exported notebook files and approved cloud/USB sideload paths; Kobo-account scraping, store purchases, deletion and DRM circumvention are denied.

See `EXTERNAL_INTEGRATIONS.md`.

## Crons and Webhooks

A schedule or event receipt is a trigger, not authority. Crons/Webhooks may request work already permitted by their resource/host policy but cannot mint permissions. Signed registry-update notifications identify a candidate commit only; Resource Evolution Manager must validate and classify the candidate before import/activation.

## Learned overlays and updates

Published resources are the replaceable upstream base. Local experience and private user-learned overlays survive upstream replacement and are semantically rebased. They may improve procedure/preferences but cannot expand authority.

A validated GitHub `main` update may emit a signed `registry-update-available` notice. The runtime pins the referenced commit, reruns validation/materialization, rebases overlays, compares permissions/compatibility, stages a candidate generation and atomically activates only if local policy permits. See `RESOURCE_EVOLUTION.md` and `RUNTIME_IMPORT.md`.

## Versioning

Do not silently mutate a published resource contract: bump its semantic version. New/deleted resources require a catalog-version bump. Registry-wide restrictive quality changes bump `QUALITY_POLICY.yaml` when they become a release. CI checks PR versioning against the base branch.

Derived Profile/integration tables are not committed as static Markdown; `scripts/render_registry_reference.py` renders them from manifests on demand.

## Validation

```bash
python scripts/check_catalog_consistency.py
python scripts/validate_registry.py
python scripts/validate_deliberation.py
python scripts/validate_expansion_v21.py
python scripts/validate_expansion_v22.py
python scripts/validate_quality_v22.py
python scripts/validate_quality_overlays_v22.py
python scripts/render_registry_reference.py --output /tmp/registry-reference.md
python scripts/materialize_effective_registry.py --check-only
```

On PRs, `scripts/check_pr_quality.py` additionally checks semantic-version/catalog changes and canonical-document hygiene.
