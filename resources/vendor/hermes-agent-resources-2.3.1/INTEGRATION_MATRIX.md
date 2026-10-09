# Integration Matrix

This is the canonical human-readable integration posture for Hermes resources. Exact Plugin/MCP/Channel/Cron/Webhook manifests remain the machine-readable source of truth and are validated through registry discovery.

Do **not** create versioned integration-matrix supplements. Update this file when an integration class or authority boundary changes.

| Integration | Typical consumers | Access / side effects | Key boundary |
| --- | --- | --- | --- |
| Codex | Developers, AI engineering, data/analytics | Repository/code operations as host-authorized | Shared host-managed auth; credentials are not copied into agent workspaces |
| GitHub Plugin / MCP | Development, research, registry evolution | Repository reads/writes within scoped token | Least privilege; production/repository mutations require declared authority |
| Web | Research-oriented Profiles | Read current public information | Source provenance/freshness; no account authority implied |
| Filesystem MCP | Profiles with approved workspace access | Bounded roots only | No implicit access outside configured roots |
| Home Assistant MCP | Smart-home/Home Assistant roles | Scoped HA operations | Physical/home automation actions remain authorization- and safety-gated |
| Authentik Authorization | Homelab Infrastructure Operator / Hermes runtime | Read trusted user identity and effective groups; resolve alarm recipients | Read-only; infrastructure writes and alarms require fresh effective `System` membership; fail closed |
| Homelab Ops Broker | Homelab Infrastructure Operator | Read host/Nextcloud health; bounded service/container/backup/recovery/Nextcloud writes | Hermes + Nextcloud targets only; no raw SSH/arbitrary shell; every write requires fresh `System` authorization |
| Cloudflare Homelab | Homelab Infrastructure Operator | Read approved DNS/tunnel state; bounded approved DNS/tunnel writes | Approved zone/hostnames/tunnels only; writes require fresh `System`; no account/token/billing administration |
| Composio | Approved external SaaS integrations | Provider/toolkit-specific | Runtime OAuth only; toolkit exposure must remain explicit |
| Financial Data Hub | Financial Data Steward / analysis roles | Read/reconcile financial data | No raw credentials; read access is distinct from execution |
| Financial Execution Gateway | Financial Execution Operator | Real-value order/payment actions | Exact one-shot user order + fresh confirmation + reconciliation |
| Agent Live Wallet | Crypto Live Wallet Operator | Live signing/broadcast through approved wallet path | Exact transaction authorization; no autonomous real-value spending |
| Agent Sandbox Wallet | Crypto Sandbox Operator | Testnet-only experimentation | No real-value networks/assets |
| Kobo Bridge | Kobo Integration Specialist; Kobo Library & Notebook Specialist | Read exported notebooks; explicit DRM-free ebook delivery | Approved Dropbox/Google Drive/USB paths only; no account scraping, DRM removal, store purchases, deletion, or unrequested delivery |
| Ebook Toolchain | Ebook Planner/Writer/Designer/Converter/Editor | Local document conversion, packaging and validation | Preserve source artifacts; no DRM circumvention; validate EPUB before delivery |
| Voice Pipeline | Hermes | STT/TTS around Hermes | Specialists never receive direct user-channel binding |
| Resource Overlay Store | Resource Evolution Manager | Private/local learned overlays | Private learning is not published and cannot grant permissions |
| Epic Kanban | Orchestrator / Team Leaders | Ephemeral work coordination | Board state does not create authority |

## Homelab infrastructure authorization model

The authenticated Hermes session principal is mapped to Authentik. Only users with current effective membership in Authentik group `System`, including indirect membership, are eligible for infrastructure-changing operations or infrastructure alarms.

Mutation authorization is checked immediately before the target tool call. Alarm recipients are independently resolved at delivery time. Authentik lookup failure, ambiguous identity, missing/ambiguous group or unverified membership fails closed. Cached membership, static recipient lists, prompts, Bundles, schedules and webhooks never substitute for the lookup.

The scheduled `homelab-health-review` is read-only: it may detect/correlate incidents but cannot remediate from schedule authority. Home Assistant remains the smart-home/device automation control plane rather than duplicating its routine automations in Hermes infrastructure operations.

## Kobo transport model

Kobo integration is deliberately transport-based rather than dependent on an undocumented general Kobo API.

- **Notebook intake:** user-exported notebook files from approved storage/device paths; preserve originals and notebook/page provenance.
- **Cloud delivery:** DRM-free EPUB/PDF through a supported user-authorized Kobo Dropbox or Google Drive workflow when the configured device/model supports it.
- **USB fallback:** explicit mounted-device sideload when cloud delivery is unavailable or unsupported.
- **Outbound delivery:** only after an explicit user request and successful artifact validation.
- **Denied:** Kobo credential scraping, web scraping as an account-control mechanism, DRM removal/circumvention, purchases, destructive library changes, or notebook writes unless a future documented integration is deliberately reviewed and authorized.

## Notification / import integration

A successful validation run on `main` may trigger `.github/workflows/notify-hermes.yml`. It builds a deterministic registry-update notice and posts an HMAC-signed `registry-update-available` event to the configured Hermes endpoint.

The event is **notification only**. `registry-update-notice` routes it to Resource Evolution Manager for immutable-commit fetch, validation/materialization, overlay rebase and permission-diff assessment. Webhook receipt never authorizes activation.

## Default rule

External integrations are default-deny unless declared by the resource and allowed by host/runtime policy. Bundle membership, scheduled execution, webhook receipt, prompts, learned overlays, or prior similar tasks cannot expand the integration surface.
