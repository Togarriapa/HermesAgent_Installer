# Jarvis core runtime evidence

Requirement/task mapping: `jarvis-core-platform`; BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, VD-T266.5. This is a dated partial-evidence snapshot for 2026-10-11, not release qualification; exact observation times were not supplied.

## Deployed Pi source and validation

Source `12b9e83dd246052558ba64f4299b52ad63e2b5f1` is deployed at <https://jarvis.togarriapahome.uk/>. The deployment preserved the existing private core process, which serves on `127.0.0.1:8766`. Official Hermes remains the unmodified source generation `7085fbf7753266fc4943c55ac04926186bc90005`, using PM-managed Python 3.14.7 and the existing Codex authentication.

The public route is protected by Cloudflare Access email OTP and the gateway's origin JWT, binding, and conversation-ownership checks. A fresh email-OTP login succeeded. The broader public denial, expiry, revocation, and long-lived-session matrices remain open.

The earlier development candidate `d8d15533a240732bc0bacac5a97ed165cc773cbc` is superseded and is not the current deployed public UI. Its Overview/Integrations navigation work, Plugins/MCP menu rename, mission prompt/consumer binding and cold-model readiness changes remain development-only. At this snapshot, the public site still serves the 12b source with 13 menus; no joined Pi-suite result for that earlier candidate was reported.

## Latest live implementation checkpoint

Candidate `3b9d13e7bb9a6fcdd380ca032587d7a7ad0d18b1` passed 173 Pi UI contract tests and composed JavaScript syntax checks; the root deployment preserved the existing core PID. The public Overview's central reactor telemetry has been observed. This does not establish overall stability or acceptance.

A small name request completed according to stored counters, which showed 8 completed, 1 failed, 9 total. After reload, another chat ended with the client-side SSE message “Connection interrupted” and a blank response. This delivery failure is under investigation; the counters alone do not prove the response reached the user. A responsive Pi v1 attempt failed safely with an `Uncaught` error; responsive v2 diagnostics are still running.

The later `5be` Pi suite reported 346 passed and 4 skipped. UI candidate `4fef` then reported 176 Pi tests passed with 21 warnings; this is source-candidate evidence, not full release acceptance. Official Hermes core, plugin, and `-P` behavior remains on the legacy path and has not been adopted. Observed Experts completions currently come only from Planner; Teams have no joined expert execution. The Obsidian R0090 four-artifact/leaf proposal and UI `6a9` are source-only; central installer and RPC binding remain in progress, and no native Obsidian app is installed.

The Pi run for source `12b9e83dd246052558ba64f4299b52ad63e2b5f1` reported 199 tests passed, 17 warnings, no skips, in 15.27 seconds; generated JavaScript syntax passed. Strict OpenSpec, current-plan, and status/apply checks passed, with eight broad acceptance groups still open. Pi test logs are retained under `/var/tmp/hermes-jarvis-core-checks-20261011/`. The prior `8cfbee0a4` test/deployment logs remain under `/var/tmp/hermes-jarvis-core-checks-20261011/` and `/var/tmp/hermes-jarvis-deploy-8cfbee0a4/`, respectively; those are historical paths, not evidence of the 12b deployment run.

The later exact native Resources refresh produced receipt `15493e256…`. Root-helper/manual-skill checks reported 23 passed in 11.61 seconds. The native readback verified all 396 bundled skill digests and the 449-skill total (53 stock plus 396 bundled), the owned member tree, unchanged lifecycle state, and the preserved core PID. This resolves the earlier pending receipt-refresh readback; it does not qualify all imported operations or resource obligations. The compiled primary content differs from the raw SOUL file, and the imported primary logic has not been proven active. Managed-block implementation remains in progress.

The later source candidate `5f35ccc` passed 240 admin and 2 root checks. A still newer `dfb` suite was run, but its result had not been read when this record was prepared; no pass is claimed for it. These are source-validation results, not deployment or acceptance evidence for the public 12b source.

## Product semantics: implementation pending

The intended user-facing model is **Jarvis as the sole master**. Experts are internal specialized workers, not separately presented user identities. Teams are sets of Experts. Skills are methods available to Jarvis and its internal workers; they are not additional agents. OneShot and Kanban are selective workflows: use OneShot for bounded tasks and Kanban only when work is deliberately tracked on a board. Neither is mandatory for every request.

At task start, autonomy applies only when the user explicitly delegated it. Otherwise Jarvis pauses for owner approval before taking action. Jarvis reviews proposed final effects and is the only component that may perform them. This is the intended authority model, not a claim about current runtime behavior. The source/UI semantic correction and its acceptance remain pending. Do not interpret the native profile inventory as Bot DM accounts, or a capability named `orchestrator` as a mandatory master agent. All 219 requirements, 62 capability/component mappings, and AC01–AC18 remain open.

## Observed public UI and owner use

After the fresh email-OTP login, the interface displayed Chat, Sessions, Overview, Capabilities, Models, Settings, Missions, Bots, Logs, Integrations, Learning, Tools & Skills, and Files. The 13 visible menus are not proof that every capability is complete.

- Models read the configured provider as `openai-codex`, profile as `gpt-6-luna`, and `credentialConfigured` as true. An approved request using that same selection returned `conversationSelection: gpt-6-luna·selected-for-session`. This verifies request selection only; it does not show durable default selection or cold-resume behavior.
- A subsequent real public chat completed and displayed **“Jarvis model selection is ready.”** This confirms the chat completed after the selection observation; the response alone does not identify the model used or prove a durable default. A private screenshot is retained at `/private/tmp/jarvis-live-model-chat-20261011.png`.
- An actual owner chat returned **“I'm Jarvis, your assistant.”** Existing conversations restored their message history. After several minutes idle, a later turn showed **“Jarvis is ready.”** The exact elapsed duration was not recorded; full idle, restart, and cold-resume boundaries remain unqualified.
- Logs displayed a completed status bar and event timeline. Native session counters showed total 24,978, input 1,134, output 36, reasoning 25, prompt 24,942, cache hit 95, and context 272,000. Duration and cost are unknown.
- Native inventory reported 63 toolsets and 449 skills: 53 stock plus all 396 bundled Resources skills. The offline import preserved 208 source profile records, including 207 internal records, and 88 other declarations. These inventories do not establish functional use, effective permissions, or full parity.
- Capabilities search for `orchestrator` returned one `Bundled` match; this inventory result does not make Orchestrator a required user-facing role or establish readiness.
- Settings displayed 180 browser voices and controls for rate, pitch, language, density, text size, reduced motion, and read-aloud. Local preferences use browser local storage; consent is not stored. Broader settings-source review and phone speech input, audio output, and wake-word behavior remain pending.
- A harmless mission draft was saved and previewed, not executed.

Private-core chat identity/history and one owned-unit restart/resume were previously observed on candidate `8753c8353743925328030f1e72fddc4670a6d175`; see [`jarvis-core-pi.json`](../../evidence/current/jarvis-core-pi.json). This is separate from the deployed public source and does not prove durable public model selection.

Private operator screenshots from this UI observation are retained outside the repository at `/private/tmp/jarvis-live-voice-settings-20261011.png`, `/private/tmp/jarvis-live-activity-charts-20261011.png`, `/private/tmp/jarvis-live-model-controls-20261011.png`, and `/private/tmp/jarvis-live-model-chat-20261011.png`.

## Remaining acceptance

The selected model was accepted for a request and a subsequent chat completed, but the response does not establish model attribution, a durable default, or cold resume. The native receipt refresh succeeded; the offline bundle is portable, while activation of the imported primary logic, managed-block work, and operational use remain separate unfinished work. The plan tracks 219 requirements and 62 capability/component mappings; counts, menus, and status output do not complete those obligations.

Phone access/input and practical family usability are unqualified. The current UI's HTML textarea has not been directly tested on a phone; no failure of its soft keyboard is claimed. Family concurrency, mission execution, Bots/channel configuration, browser-use controls, native learning effects, all 219 requirements, all 62 mappings, full capability parity, fresh installation, reboot/recovery, and the public denial/expiry/revocation matrix remain open. Home Assistant is deferred.

All initial AC01–AC18 and all five core migration tasks remain open. This snapshot makes no full-installer, complete Resources, phone-usability, reboot, or overall acceptance claim. No metered cost or unobserved behavior is inferred.
