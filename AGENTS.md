# HermesAgent Installer engineering contract

Authorized repository: https://github.com/Togarriapa/HermesAgent_Installer. This project is independent from the declarative HermesAgent_Resources registry and other installer repositories. Do not import another repository's governance.

## Model ownership and immutable scope

- GPT-6.1 Sol owns specification, task creation and refinement. GPT-6 Luna implements development from the validated plan. The user authorized this sequential model handoff; routine implementation does not require another approval.
- Baseline `plans/2026-10-09-v1/` is frozen by the unique annotated tag `hermes-installer-plan-2026-10-09-v1`. Never edit/delete/rewrite its files, force-push its history or move/delete/reuse its tag. Keep live `planning/` and `openspec/` ledgers current. Refinements require Sol and new append-only files under `plans/amendments/`; identify baseline requirements, why, new tasks and evidence, validate and commit separately. Preserve requested scope.
- CI compares the full baseline tree to its tag plus exact file hashes. This detects drift; repository admins can still bypass branch/tag controls. Protect the tag/ref externally if stronger enforcement is needed; never claim hashes prevent authorized remote ref deletion.

## OpenSpec throughout development

Run `npm ci` using `.node-version`; OpenSpec is pinned at 1.14.1 and is a development tool, not a required Pi service. Use generated Codex skills in `.agents/skills/`: openspec-propose, openspec-apply-change, openspec-update-change, openspec-sync-specs, openspec-archive-change, openspec-explore. Codex has skills, not assumed Claude slash commands; verify is not generated in the core profile, so perform evidence-based review directly.

Before working, inspect `npx --no-install openspec status --change <actual-id> --json` and `npx --no-install openspec instructions apply --change <actual-id> --json`; read its proposal/specs/design/tasks and planning dependency graph. Follow actual schema instructions and preserve all four artifacts. The direct user request authorizes autonomous implementation after this specification handoff and routine refinement; generic generated planning/confirmation guidance does not revoke it. Scope-changing refinement remains Sol-owned.

For every substantive change, use proposal, delta specs, design and checkbox tasks. Canonical `openspec/specs/` contains implemented verified behavior only; currently only planning governance is implemented. Do not sync runtime proposals into canonical specs as if installed. Every code/evidence commit links change and requirement/task IDs. Mark implementation and live acceptance separately; unfinished target/account tasks remain open. Run `npm run validate:specs`, `npm run validate:plan`, and meaningful contract/failure tests. Review drift before archive; use `npx --no-install openspec archive <actual-id> --yes` only when genuinely verified, merging specs and retaining dated history. Never weaken scope or skip validation to force archive.

## Implementation safety and truthful evidence

Use modular typed Python orchestration and reviewed component adapters; no placeholder handler can be claimed complete. Read all original obligations/aliases/AC mappings. Meaningful tests exercise effects, failures and integrations; inventory text/string checks prove coverage only. Source download/configuration/discovery is distinct from authentication, functional operation, enablement and target verification.

Do not run the privileged host installer on this development Mac. Use temporary fixtures or identified isolated test environments. Physical Pi access, accounts and external service targets require identification and applicable user authorization; none is enrolled by this baseline. No new spending, huge model download, reimage/format, unrelated service replacement or outbound installation-test messaging. Current repository code pushes are authorized.

Preserve data, credentials, memories, overlays and unrelated services. Default additional metered budget zero; public/free and private routes remain distinct at every dispatch/retry/background/extraction boundary. Secrets never belong in source/argv/logs/evidence or duplicated profile credential files. Native profiles do not constitute a filesystem/process sandbox. Missing runtime authorization, license, dependency/account or native ARM64 support leaves the affected capability unavailable with exact next step/resume command.

Use official Hermes PM-managed runtime/toolchain (observed Python3.14), separately isolated installer/component runtimes; no global downgrade. Preserve browser/Electron sandbox and TLS verification. Prestart OpenViking with sanitized environment; disable unreviewed lazy installs. GLM-5.2 is the required model and Coral proof requires delegate-used TPU inference, never a substitute model or device enumeration.

## Direct Cloudflare/Desktop addition

Follow planning/user-additions/2026-10-09-remote-desktop.md. Hostname prompt starts blank (no prefill/default). Securely collect scoped Cloudflare token/reference inside installer and automatically configure only owned account/zone tunnel/DNS/Access application/OTP allowlist resources, with no repeated routine confirmations. Preserve unowned conflicts and journal recovery. Expose only the official native Desktop app via constrained session/loopback JWT gateway; no dashboard/full-host desktop/shell/backend-management public substitute. Validate Access JWT before all bytes/input and implement bounded active-WebSocket expiry/revocation leases. Keep setup management token out of cloudflared/Desktop runtime; use verified protected tunnel token file. No live target/account mutation in this planning session; code/fixtures/docs/AC13..15 are required now.

## Direct user override — core-first Jarvis, 11 October 2026

Append-only v266 and `openspec/changes/jarvis-core-platform/` supersede the earlier native-Desktop-only product requirement. Install/adopt official core Hermes first; reversibly retire owned Desktop after independent core proof, port capabilities individually, then responsive Jarvis UI, full Resources and end-to-end review. Preserve all other scope, data/Codex auth, secrets, WIP and owned Cloudflare OTP/binding security. Public exposure is finite authenticated Jarvis adapters, never raw backend management/shell/RPC. HA is deferred. All tests, fixtures, previews and npm validation run only on Pi via root browser; local source/spec reading/editing and Git are permitted.

## Active plan cleanup — v267

Read planning/ACTIVE-PLAN.md first. Desktop is removed from active install/Pi product paths and remains capability benchmark only. Legacy installer-bootstrap-desktop/remote-desktop-tunnel changes are preserved at openspec/superseded/v267, not passed acceptance. Cleanup only verified owned Desktop/Xpra artifacts after independent core proof; preserve core home/auth/PM/Resources/backups/unrelated services, no blanket apt purge. Frozen baseline and immutable amendments remain historical and unchanged.
