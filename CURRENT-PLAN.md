# Current plan: official Hermes core and Jarvis

This is the sole current execution plan. Full functional scope and component aliases are in [current-scope.json](requirements/current-scope.json); the one current OpenSpec change is [jarvis-core-platform](openspec/changes/jarvis-core-platform/). This is a development project with incomplete release acceptance.

1. **Core installer — BD-T266.1.** Install/adopt/resume/rollback official pinned headless Hermes, separately owned service, actual chat/stop/history and stored-session restart. Preserve existing HOME, Codex auth references, PM-managed Python3.14, memories, data and unrelated services. Existing-target migration and fresh clean installation require separate proof.
2. **Individual ports — HI-T266.2.** Verify capabilities one at a time: complete durable Bots rooms/groups/relay; skills; plugins/MCP; messaging; jobs; rich events/approvals; scoped browser; files/artifacts; profiles/memory; voice; settings/model/account menus. Exact native conveniences receive an explicit browser alternative or pending status. Inventory/source availability does not prove operation.
3. **Jarvis UI — RT-T266.3.** Deliver accessible responsive owner/family web interaction over finite authenticated server adapters; real mobile keyboard, streaming, history and stop. Core plus one useful port enables UI work while other ports continue. Permissions and ownership are server-derived; a shared profile/home is not a process/filesystem/memory sandbox.
4. **Full Resources — RB-T266.4.** Retain all208 source identities, Jarvis as the one user-facing identity and207 internal identities, original inheritance/permissions/skills/assets/provenance and actual delegated dispatch/enrichment. Every requested component and alias remains tracked.
5. **Review — VD-T266.5.** Verify full end-to-end effects, denials, concurrency, resource limits, backup/restore, updates, restart/reboot/resume, rollback and account/hardware functionality on the identified Pi. All full acceptance remains OPEN.
6. **Finished documentation — VD-T268.1.** After actual review, publish verified release usage/operations/troubleshooting/contributor/AI guides. These current development guides do not claim a stable finished product.

## Core and public transport contract

Use the pinned official `hermes serve` → private authenticated `/api/ws` → `tui_gateway.ws` engine. Privately bind actual `session.create`, `prompt.submit`, history/replay, interrupt and `session.resume`; do not introduce the distinct API-server listener or expose arbitrary RPC/URLs/backend controls. Map authenticated principal → opaque conversation → stored_session_id; live session IDs are generation-local and replaced atomically after verified resume.

Retain existing owned Cloudflare OTP/Access binding. Verify JWT signature/algorithm/issuer/audience/time/principal before bytes; require same-origin CSRF and protected backend credential custody. For each exact owned turn, deadline is min(original admitted JWT expiry, initial monotonic acceptance+600s, stricter backend deadline). A fresh protected nonce heartbeat may issue a new distinct <=30s lease before expiry, never extend/restamp old proof or revive a run. Every byte requires <=5s fresh ingress revocation witness; SSE segments <=4s. Missing/refused/stale authorization cancels the exact owned turn. Later JWT cannot enlarge the original ceiling.

## Owned cleanup — BD-T267.1 and VD-T267.2

Desktop/Xpra/native presentation is excluded from active installation; Desktop source is only a functional benchmark. Remove only journal/inventory-verified owned units/processes/dedicated files after both independent private core proof and working replacement protected public owner chat, expiry/revocation and restart/recovery proof. Preserve recovery backups, HOME/auth/PM/Resources, shared tunnels, shared packages/configuration and unrelated services. Do not strand the existing owned URL or blanket-purge packages. Unknown/shared ownership remains pending.

## Functional constraints

Use real modular typed Python adapters and official reviewed upstreams. Native ARM64 dependencies/account authentication/functional operation/enablement are distinct states. Zero additional metered spending applies across public/private dispatch, retries, fallback, extraction, embeddings and background jobs; no silent paid or private-to-ineligible-free fallback. Keep one automatic long-term memory owner per active profile. Secrets remain protected references, never source/argv/logs/browser storage or duplicated profile credentials.

GLM-5.2 remains the required Colibri model; do not substitute a smaller model to pass acceptance or start a huge download without separate authorization. Coral requires actual delegate-used TPU inference, independently of LLM routing. Every component/MCP/account receives actual harmless selected-resource evidence, truthful unavailable status and exact resume action. Browser sandbox and TLS stay enabled. HA live configuration remains deferred. Android assistant/wake-word features remain device/account/security qualification work; accessible text/push-to-talk remains the practical initial route.

## Workflow and evidence

GPT-6.1 Sol owns specifications and scope; GPT-6 Luna implements the validated current change. The user authorizes routine sequential handoff and code pushes for this repository. Tests, fixtures, previews, servers, OpenSpec/npm validators and target acceptance run **only on the identified Pi through the root browser**. Local source/spec reading, editing and Git are permitted. Do not run the privileged installer on the development Mac, spend, reimage/format, replace unrelated services or send outbound test messages.

Keep implementation and live acceptance separate in the current tasks. Source, parser availability, a fixture, download, healthy process or one chat does not prove full release/Resources/parity acceptance. Current evidence reports remain factual records, not instructions. Git history and existing tags are preserved; obsolete plans are removed from current branch files and never used as an execution queue.
