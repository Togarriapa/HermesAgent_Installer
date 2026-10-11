# Jarvis core runtime evidence

Requirement/task mapping: `jarvis-core-platform`; BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, VD-T266.5. These are operator-reported partial observations, not release qualification. Exact timestamps were not supplied for this snapshot.

## Current Pi and deployed source

The root operator reports source candidate `12b9e83dd246052558ba64f4299b52ad63e2b5f1` deployed at `https://jarvis.togarriapahome.uk/`. The official Hermes source remains the unmodified `7085fbf7753266fc4943c55ac04926186bc90005`, using PM-managed Python 3.14.7 and the existing Codex account. The private core process was preserved during the deployment. A post-deployment Resources receipt refresh is still pending: an independent native readback found a digest mismatch, so no refreshed receipt is treated as ready.

The Pi run reported 199 tests passed, 17 warnings, no skips, in 15.27 seconds. Generated JavaScript syntax, strict OpenSpec, current-plan validation, and OpenSpec status/apply checks passed; the status/apply output showed eight tasks still open. These results do not qualify the public product, every UI action, installation, Resources, or acceptance.

## Observed public interface and real owner use

After a fresh Cloudflare email-OTP login, the public interface exposed Chat, Sessions, Overview, Capabilities, Models, Settings, Missions, Bots, Logs, Integrations, Learning, Tools & Skills, and Files. Menu visibility is not proof of capability completion.

- The Models page read the configured provider as `openai-codex` and profile as `gpt6Luna`, with credentials configured. An immediate request using the approved same `gpt6Luna` selection returned `conversationSelection: gpt6Luna·selected-for-session`. This proves selection for that request only; durable default inference and cold resume remain pending.
- Logs showed a completed status bar and event timeline. The displayed native-session counters were total 24,978, input 1,134, output 36, reasoning 25, prompt 24,942, cache hit 95, and context 272,000. Turn duration and cost were unknown and are not inferred.
- Settings exposed 180 browser voices plus rate, pitch, language, density, text-size, reduced-motion, and read-aloud controls. Local preference changes worked and were not persisted as consent. Phone speech input, audio output, and wake-word behavior remain unqualified.
- Capabilities search for `orchestrator` returned one `Bundled` match; readiness remains pending. The native inventory reported 63 toolsets and 449 skills. Inventory and discovery do not establish functional use or full parity.
- A mission draft could be previewed; it was not executed.
- After an idle interval of several minutes, a new turn displayed `Jarvis is ready.` This is one observation, not proof of all reaping thresholds, restart, or cold-resume behavior.

The earlier isolated private-core evidence is recorded in [`jarvis-core-pi.json`](../../evidence/current/jarvis-core-pi.json): a live Jarvis response and one owned-unit restart/resume with prior READY history. That earlier observation is separate from this deployed public candidate and does not qualify public chat or durable model selection.

## Remaining acceptance

The Resources receipt refresh and its native-readback digest mismatch remain unresolved. The initial 208 profile/396 skill inventory and current 63-toolset/449-skill discovery do not establish all 219 resource identities, the 62 capability mappings, functional parity, or imported action behavior. Bots, channel setup, full mission execution, native learning, browser-use controls, and complete capability behavior remain open.

Phone chat text entry has not been verified: the user reports that tapping the chat box does not bring up the soft keyboard. This makes practical phone and family use pending despite the prior phone viewer pixels. Family concurrency, multiple-user behavior, physical reboot, all restart/reaping boundaries, cold resume, public denial/expiry/revocation matrices, and fresh installer acceptance remain open. Home Assistant remains deferred.

All initial AC01–AC18 remain open. BD-T266.1, HI-T266.2, RT-T266.3, RB-T266.4, and VD-T266.5 remain open; observed slices are partial evidence only. Resources deletion remains unsafe. Private screenshots were retained outside the repository at `/private/tmp/jarvis-live-voice-settings-20261011.png`, `/private/tmp/jarvis-live-activity-charts-20261011.png`, and `/private/tmp/jarvis-live-model-controls-20261011.png`; they are not included here. No metered cost or unobserved outcome is inferred.
