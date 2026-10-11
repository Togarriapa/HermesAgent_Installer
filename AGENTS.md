# HermesAgent Installer engineering instructions

Authorized repository: https://github.com/Togarriapa/HermesAgent_Installer only. It is independent of HermesAgent_Resources and other installer repositories.

Read [CURRENT-PLAN.md](CURRENT-PLAN.md) first, then [requirements/current-scope.json](requirements/current-scope.json) and the four artifacts under [openspec/changes/jarvis-core-platform](openspec/changes/jarvis-core-platform/). They are the current scope. No obsolete plan or tag snapshot reinstates Desktop/Xpra installation or a native-only product. No obsolete baseline/amendment files are required at branch HEAD. Preserve existing Git history and tag refs; no force push, history rewrite, or tag movement/deletion.

## Ownership and implementation

GPT-6.1 Sol owns specification/tasks/refinement; GPT-6 Luna implements from the validated current plan. The user authorized this sequential handoff and routine implementation/code pushes in this repository. Preserve full functional scope, all component aliases and AC01..18 in the current scope registry. Keep the sole current change proposal, specs, design and checkbox tasks coherent. Update current scope directly when Sol refines it; do not regenerate an amendment forest or old plan archive.

Official headless core precedes individual capability ports, responsive Jarvis, full Resources and review. Desktop is a capability benchmark only. Complete Bots server-owned groups/relay, original208 Resources identities, required GLM-5.2/Coral, budgets/privacy/accounts and all integrations remain obligations. No placeholder, clone, inventory, configuration/discovery, process health or one chat proves functional parity/acceptance. Mark implementation and live acceptance separately; blocked capabilities remain unavailable with precise next action.

## Validation

All tests/fixtures/previews/servers/npm/npx/OpenSpec validators run only on the identified Pi via the root browser. Local source/spec reads, edits and Git are allowed. Do not run the privileged installer on the development Mac. The pinned OpenSpec1.14.1/node toolchain is development-only. On the Pi inspect actual status/instructions for jarvis-core-platform and follow its schema. Run strict specs/current-scope validation plus meaningful effect/failure/integration tests there. Canonical runtime specs contain verified behavior only; do not force archive or acceptance.

### UI/UX review is a pre-deployment gate

Every change to a user-visible feature, behavior, navigation/menu, or setting requires a candidate-bound UI/UX review record before deployment, even when the code change appears small. Use [the focused review template](docs/evidence/uiux-review-template.md) and link the record from the change/PR. Review the relevant screens at their actual rendered state and record evidence; source inspection, a test fixture, or a design mock alone is not a UI review. The review is a usability/design gate, not release acceptance.

The focused review records placement and naming, duplicate navigation, desktop/tablet/mobile layout and touch targets, keyboard and focus behavior, reduced-motion behavior, loading/empty/error/unavailable states, destructive consequences and recovery, content-retention implications (especially for integrations such as Obsidian), and whether visible capability claims match actual API provenance and behavior. Include a redacted screenshot or equivalent capture of each relevant view, with candidate SHA and route/state. If a review item cannot be exercised, mark it not reviewed and state the blocker; never fill a review result with inferred success.

Changes that introduce or materially alter a primary journey, shell/navigation architecture, multi-route interaction, authorization boundary, or cross-surface input/state behavior require a full-shell review in addition to focused screen checks. A deployment must wait until the scoped review exists and identified blocking UX issues are resolved or explicitly kept unavailable. Keep product implementation and target acceptance status separate.

The active scope remains [the jarvis-core-platform OpenSpec change](openspec/changes/jarvis-core-platform/), including its proposal, spec, design and task artifacts. UI/UX review adds evidence for user-facing behavior; it does not replace Sol-owned specification changes or authorize editing those artifacts outside the normal handoff.

## Runtime safety

Preserve HOME/Codex auth references, memories, data, overlays, PM runtime, Resources, backups, shared tunnel and unrelated services. Use official Hermes PM-managed Python3.14 separately from isolated installer/component runtimes; no global downgrade. Preserve browser sandbox and TLS, sanitize OpenViking startup and disable unreviewed lazy installs. Zero additional metered budget applies at every dispatch/retry/fallback/background/extraction boundary; private/public eligibility stays separate. No new spending, huge model download, reimage/format, unrelated service replacement or outbound installation-test messaging. Secrets never belong in source, argv, logs, evidence, browser storage or duplicated profile credentials. Profiles are not process/filesystem sandboxes.

Use actual hermes serve private authenticated /api/ws contracts and finite server adapters. Server derives principal/conversation/stored-session/live-session/run ownership; no arbitrary RPC/URLs/shell/backend-management public proxy. Keep Cloudflare Access OTP/binding, JWT-before-bytes, same-origin CSRF, protected token files and setup-only management credentials. Original JWT/600s/stricter turn ceiling cannot grow; distinct <=30s leases require fresh protected nonce heartbeat, <=5s ingress witness per byte and <=4s SSE segments. Deny/cancel stale/revoked/expired state without revival.

Owned Desktop/Xpra cleanup requires independent core plus working replacement protected public owner chat/security/restart/recovery proof. Delete only journal-verified owned dedicated artifacts; preserve shared or uncertain objects and exact recovery. No blanket apt purge or URL stranding. HA configuration remains deferred.

## Repository tools

Use relevant installed skills proportionally; read full SKILL.md when needed. Source and licenses are current execution inputs in contracts/, not obsolete plans. Use the host's supported browser tools. Optional memory capture requires explicit user request. Subagents/parallel work require explicit user or applicable repository authorization.
