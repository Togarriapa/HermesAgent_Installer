# HermesAgent Resources

A versioned registry of Hermes capabilities and operating contracts. The repository describes what resources are and how they behave; **host/runtime policy, credential scope, and explicit authorization remain the capability ceiling**.

## Architecture

`User <-> Hermes <-> Orchestrator <-> Specialist Profiles / Team Bundles`

- Hermes is the only user-facing Profile and all user channels bind to Hermes.
- Orchestrator decomposes work, recruits any suitable registered Profile, runs safe independent work in parallel, and reconciles results.
- Team Leaders and specialists are internal-only.
- Bundles are starting rosters, not permission pools or recruitment ceilings.
- Scaling creates capacity, never authority.
- Material decisions may use evidence-driven deliberation; credible dissent is preserved.

See `TOPOLOGY.md`, `ORCHESTRATION.md`, and `DELIBERATION.md`.

## Registry discovery and catalog integrity

`catalog.yaml` declares eight non-recursive manifest roots: Profiles, Skills, Plugins, MCPs, Crons, Webhooks, Channels, and Bundles. Every direct `*.yaml` manifest in those roots is discovered from its own metadata; there is no duplicated hand-maintained resource list.

CI verifies filename/name/kind/version consistency, dependency and inheritance selectors, deterministic catalog digest, topology/security invariants, semantic-version bumps on changed resources, and a catalog-version bump whenever the resource set changes.

`PROFILE_MATRIX.md` and `INTEGRATION_MATRIX.md` remain the canonical human-readable responsibility/integration summaries. Exact current dependency tables are generated from manifests with:

```bash
python scripts/render_registry_reference.py
```

Versioned matrix supplements are forbidden.

## Effective quality

`QUALITY_POLICY.yaml` is the single canonical restrictive/defaulting quality policy. It supplies common evidence, verification, privacy, retry, failure, audit, lifecycle, and authority-non-escalation behavior plus narrowly matched domain overlays.

Behavior composition is:

`kind defaults < domain overlays < resolved manifest < local experience overlay < private user overlay < current session context`

Host/runtime authorization surrounds that entire composition and cannot be expanded by prompts, learning, Bundles, schedules, webhooks, or confirmation.

See `RESOURCE_QUALITY.md`, `SPEC.md`, and `SECURITY.md`.

## Capability coverage

The registry covers software/infrastructure/data/AI; product/operations/people; finance/investment/accounting; law/privacy; home/property/farm; education; research/humanities; Catholic theology/tradition/liturgy; traditional and historical living/remedies; fitness; translation; architecture/fabrication; ebook/Kobo workflows; and Authentik-gated homelab operations.

See `CAPABILITY_COVERAGE.md` and `PROFILE_MATRIX.md`.

## Homelab infrastructure operations

The homelab operations layer covers bounded Hermes/Nextcloud host diagnostics and maintenance, Nextcloud administration, backup/recovery, Cloudflare tunnel/DNS operations, cross-service incident diagnosis, and a periodic read-only health review.

- Authentik is the authoritative Hermes user/group source for infrastructure privileges.
- Only Hermes users with current effective membership in Authentik group `System` may execute infrastructure-changing actions or receive infrastructure alarms.
- Membership is freshly checked before every infrastructure write; alarm recipients are freshly resolved at delivery time; lookup failure fails closed.
- Cached group membership, static recipient lists, prompt claims, Bundles, schedules and webhooks never create infrastructure authority.
- `authentik-authorization` is read-only; it cannot administer Authentik users/groups/roles.
- `homelab-ops-broker` exposes approved operations only; raw SSH, arbitrary shell/commands and unrestricted Nextcloud/Docker/systemd/filesystem operations are denied.
- `cloudflare-homelab` is restricted to configured homelab zone/hostnames/tunnels and uses least-privilege provider credentials.
- The `homelab-health-review` schedule is read-only and cannot remediate from schedule authority.
- Home Assistant remains the smart-home/device automation control plane rather than duplicating routine HA/Starlink automations here.

`System` membership is necessary, not sufficient, for risky work: destructive/irreversible actions retain explicit confirmation, rollback and verification requirements. See `SECURITY.md`, `INTEGRATION_MATRIX.md`, `EXTERNAL_INTEGRATIONS.md`, and `RUNTIME_IMPORT.md`.

## Kobo / ebook workflow

Kobo support is deliberately based on documented/user-controlled transfer paths rather than an invented general Kobo API.

Typical flow:

`Kobo exported notes / Hermes results -> Kobo specialist -> Ebook Planner -> Writer -> Editor/Publisher -> Designer -> Converter -> EPUB validation -> explicit delivery to Kobo`

- `kobo-bridge` handles approved user-authorized Dropbox/Google Drive/USB workflows with device capability detection.
- `ebook-toolchain` supplies host-managed conversion, packaging and EPUB validation.
- Notebook ingestion is exported/authorized-file only and preserves notebook/page provenance.
- Outbound ebook delivery requires an explicit user order and successful artifact validation.
- Kobo credential scraping, store purchasing, destructive library actions and DRM circumvention are denied.

See `INTEGRATION_MATRIX.md` for the canonical integration boundary.

## Financial and crypto separation

Research/management Profiles may analyse and recommend. Real-value execution stays isolated behind dedicated execution operators and exact one-shot authorization/confirmation contracts; autonomous crypto experimentation remains testnet-only. See `FINANCIAL_ACCESS.md` and `INVESTMENT_GOVERNANCE.md`.

## Resource evolution and update notifications

GitHub CI validates registry changes. After a successful validation run on `main`, an optional workflow can send an HMAC-signed `registry-update-available` event to the live Hermes runtime. The event is **notification, not authority**: Resource Evolution Manager must fetch the immutable commit, validate/materialize it, rebase private/local overlays, compare permission surfaces, and classify it as import-ready or quarantined before activation.

See `RESOURCE_EVOLUTION.md` and `RUNTIME_IMPORT.md`.

## GitHub quality automation

- `.github/workflows/validate.yml` — PR/main quality gate.
- `.github/workflows/registry-maintenance.yml` — scheduled/manual deep registry audit.
- `.github/workflows/notify-hermes.yml` — signed update-available notification after validated `main` changes.
- `.github/dependabot.yml` — weekly GitHub Actions dependency updates.
- `scripts/check_catalog_consistency.py` — deterministic discovery/count/digest audit.
- `scripts/check_pr_quality.py` — semantic-versioning, catalog-version, canonical-doc and link hygiene checks.

Repository branch protection should require the validation workflow before merge.

## Resource layout

- `profiles/` — durable professional/operational responsibilities
- `skills/` — reusable methods and procedures
- `plugins/` — bounded integrations/runtime toolchains
- `mcps/` — bounded MCP definitions
- `channels/` — Hermes-only communication adapters
- `crons/` — recurring jobs
- `webhooks/` — authenticated events
- `bundles/` — starting team compositions
- `templates/` — canonical starters
- `scripts/` — discovery, validation, materialization and generated-reference tooling
- `catalog.yaml` — discovery and fail-closed catalog contract
- `QUALITY_POLICY.yaml` — canonical effective-quality policy

## Canonical documentation

Keep these living documents current instead of adding versioned supplements:

- `README.md` — repository overview
- `SPEC.md` — manifest/discovery/composition contract
- `TOPOLOGY.md` — user/channel/session routing
- `ORCHESTRATION.md` — work packaging, teams and execution
- `DELIBERATION.md` — internal debate and Hermes response contract
- `PROFILE_MATRIX.md` — Profile responsibility/boundary map
- `INTEGRATION_MATRIX.md` — integration/authority map
- `CAPABILITY_COVERAGE.md` — current domain coverage
- `RESOURCE_QUALITY.md` — completeness requirements
- `RESOURCE_EVOLUTION.md` — updates and learned overlays
- `RUNTIME_IMPORT.md` — provisioner/import lifecycle
- `EXTERNAL_INTEGRATIONS.md` — integration admission/provider rules
- `SECURITY.md` — security boundary and secrets
- `FINANCIAL_ACCESS.md` / `INVESTMENT_GOVERNANCE.md` — financial domain
- `CONTRIBUTING.md` — change and PR rules

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

On pull requests, CI additionally runs `scripts/check_pr_quality.py` against the base branch. See `CONTRIBUTING.md`.
