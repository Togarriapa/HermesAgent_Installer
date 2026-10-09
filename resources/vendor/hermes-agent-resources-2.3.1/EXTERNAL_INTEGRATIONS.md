# External Integration Governance

External providers are capability sources, **not authorization sources**. Connected or technically callable does not mean a Profile may use an operation; local host policy, resource declarations, account scope and action authorization remain authoritative.

## Admission lifecycle

Prefer first-party implementation/documentation, then official protocol registries, then reviewed managed providers. Public marketplaces are discovery only; unknown/unverifiable sources are rejected.

A new or upgraded integration moves through:

`discovered -> provenance-reviewed -> permission/data-flow-reviewed -> isolated-test -> approved/pinned -> deployed -> monitored -> upgraded/revoked`

Record source/version, transport/network destinations, credentials/account scope, exposed operations/side effects, filesystem/process access, external data flow/retention, timeout/rate/retry behavior, audit/redaction, rollback/revocation and allowed requesting resources.

## Runtime contract

- unlisted operations are denied;
- credentials stay runtime-only and are never returned to Profiles as text;
- operation/target/account scope is authorized per call;
- external calls use bounded timeout/backoff/retry;
- state-changing calls use idempotency/dedup where possible;
- ambiguous partial failures are reconciled before retry;
- provider request IDs are retained where available;
- revoked/expired credentials fail closed.

`QUALITY_POLICY.yaml` supplies the common restrictive Plugin/MCP behavior.

## Authentik and homelab infrastructure

Authentik is the authoritative Hermes user/group source for infrastructure mutation and infrastructure alarm delivery. `authentik-authorization` is deliberately read-only: it resolves the trusted session principal, reads active-user/effective-group information, verifies effective membership in `System`, and resolves the current `System` recipient set for alarms. It cannot create/update/delete users, alter group membership, administer roles, or treat user-supplied claims as identity evidence.

`homelab-ops-broker` is a host-managed allowlisted administration surface for the Hermes and Nextcloud hosts. It may expose host/service/container health, bounded logs, backups, approved service/container lifecycle, approved recovery and constrained Nextcloud administration. Raw SSH, arbitrary shell/commands, arbitrary `occ`, arbitrary Docker/systemd targets, secret readback and unrestricted filesystem access are denied. Every write requires a fresh successful Authentik `System` check before invocation; destructive operations retain explicit confirmation requirements.

`cloudflare-homelab` is restricted to the configured account/zone plus the approved homelab hostnames and tunnel IDs. Reads can support diagnosis; DNS/tunnel writes require fresh `System` membership. Account administration, token administration, billing access, unrelated zones/tunnels, broad DNS mutation and tunnel deletion are denied. Prefer Cloudflare API tokens scoped to the minimum required zone/account resources and permission groups.

The periodic `homelab-health-review` is read-only. It can detect/correlate incidents but cannot remediate from schedule authority. Infrastructure alarms route through Hermes only after the recipients are freshly resolved as effective Authentik `System` members at delivery time; static recipient lists are not authority.

Home Assistant remains the device/smart-home control plane rather than duplicating routine Starlink polling or HA automations in this integration set.

## Composio

The shared Composio Plugin is default-deny. Connections are user-scoped; Profiles require explicit toolkit/tool allowlists and reviewed production pins. Remote workbench, arbitrary proxy and unlisted capabilities remain denied. Connection creation is user-authorized and external writes remain delegated-only.

## WhatsApp Business

WhatsApp support is Business-only through the scoped provider. Inbound/outbound traffic routes through Hermes, account administration/destructive tools are denied, and proactive outbound behavior requires delegated/template-authorized handling.

## Home Assistant and local voice

Home Assistant uses least-privilege MCP exposure. The local-first Wyoming voice stack may use Speech-to-Phrase, Whisper, Piper and optional openWakeWord. Voice activation does not create Home Assistant control authority; raw audio retention/cloud fallback are denied by default.

## GitHub and Epic Kanban

GitHub uses the smallest repository/tool/token scope required. Read-only is preferred; writes are explicit. Ephemeral GitHub Projects v2 boards may be deleted only after accepted Epic completion and archived completion summary. Project lifecycle permission does not imply repository-admin authority.

## Registry-update notification

After the main validation workflow succeeds, `.github/workflows/notify-hermes.yml` may send a signed `registry-update-available` event to a configured Hermes endpoint. Delivery is disabled unless repository variable `HERMES_REGISTRY_UPDATE_ENABLED=true` and both `HERMES_REGISTRY_UPDATE_URL` and `HERMES_REGISTRY_UPDATE_SECRET` secrets are configured.

The notice contains an immutable commit, catalog version, discovered-resource digest/counts and changed paths. `webhooks/registry-update-notice.yaml` treats receipt as a trigger for Resource Evolution Manager assessment; receipt **never authorizes import or activation**.

## Kobo and ebook publishing

The Kobo integration intentionally avoids private/reverse-engineered account automation. It operates on user-exported files and supported sideload paths.

`kobo-bridge` provides three bounded adapters:

- **Dropbox** — user-authorized OAuth connection and the Kobo application folder when supported by the device;
- **Google Drive** — user-authorized OAuth connection when the configured Kobo model/firmware supports it;
- **USB** — approved mounted-device fallback for exported annotations/notebooks and non-DRM EPUB/PDF sideloading.

Before cloud transfer the runtime detects the configured Kobo model/capability rather than assuming support. Notebook ingestion is read-only from exported files. Outbound ebook delivery requires an explicit user order, validated EPUB/PDF artifact and overwrite confirmation when a destination conflicts.

Denied operations include Kobo-account credential scraping, Kobo-web scraping, store purchases, account changes, notebook mutation, device-content deletion and DRM circumvention.

`ebook-toolchain` is host-managed and may use approved Pandoc/EPUBCheck/Calibre conversion binaries. It preserves source artifacts, validates EPUB before delivery and has external network disabled by default.

## MCP / third-party discovery

Prefer the official MCP Registry where applicable, then inspect the actual implementation/release. Evaluate transport, authentication, tools/roots, filesystem/shell/process/network access, maintenance, data handling and rollback. Discovery metadata never authorizes installation or execution.

## Upgrades and revocation

Treat provider/toolkit/version changes as permission-surface changes. Diff schemas/permissions/network/data flow, test with least privilege, update pins/rollback references, activate atomically and monitor initial calls. On compromise or unexpected expansion, revoke credentials/connection first, disable the resource, preserve redacted evidence and investigate before re-enabling.

## Review chain

Typical admission review is:

`Integration Curator -> Cybersecurity Analyst -> Systems Architect -> relevant domain owner -> Team Leader/Orchestrator`

Privacy/GDPR, legal, financial-risk or other specialists join when the integration's data/authority warrants it.
