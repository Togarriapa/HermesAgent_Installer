# Hermes Core / Jarvis video-reference audit — 2026-10-11

Scope: UI/UX and demonstrated features for Hermes Core/Jarvis; assess command-centre-first use on desktop, mobile and tablets, alongside voice (STT/TTS), chat settings, stats and graphs. Source order follows the user-provided links. This is a frame-sampled visual review, not a claim of full-duration viewing. For each source, the frame evidence is separated from YouTube page metadata and description text. YouTube’s accessibility tree marked captions unavailable on the long-form pages sampled; no transcript export was available through this browser surface. No media was downloaded.

## Source ledger

1. [GPT-6 Astra Finally Built the Ultimate JARVIS](https://www.youtube.com/watch?v=s3WkutktHsw) — Shab Noor | AI For Operators; 15:58; page showed 31K views, 3 weeks ago.
   - **Frame evidence, 0:02:** a dark “PREVIOUS ATTEMPTS” slide with five side-by-side mini app panes labelled v1–v5. Each has a circular microphone control and a minimal input/status line. Pane copy is too small to read.
   - **Feature/UX takeaway:** make assistant iterations or run states inspectable as a compact history, with clear voice entry. Avoid implying the tiny pane content was legible or feature-complete.

2. [I Created the AI Assistant We All Dreamed Of (Iron Man Jarvis)](https://www.youtube.com/watch?v=MeEZpjGrpm0) — Naz Louis; 13:33; page showed 416K views, 9 months ago.
   - **Frame evidence, 1:09:** filmed desk demo. A wide monitor shows a dark assistant panel with a cyan circular “A.D.A” centre mark, compact text below, and a line of colored circular controls along the bottom; a second monitor at left shows code. Presenter and large burned-in caption also appear. Opening at 0:02 is a cinematic Iron Man-like lab scene.
   - **Feature/UX takeaway:** a distinct assistant home with one unmistakable active state and a persistent quick-action row; keep implementation details in a secondary surface. The frame does not establish what each control does.

3. [I Built JARVIS with Claude Code + GPT-6 Astra.. Now it Can Speak ANY Language](https://www.youtube.com/watch?v=acsXZP3SA6w) — Zubair Trabzada | AI Workshop; 13:35; page showed 12K views, 2 days ago.
   - **Frame evidence, 0:00:** app in a browser at localhost:4179. Dark layout with a left rail containing a list, a central node graph, a right circular assistant indicator plus stacked controls/status badges, and a bottom row of circular actions. Presenter picture-in-picture is at lower left; chapter chip says “JARVIS Speaks Any Language.”
   - **Metadata/description evidence:** title and description promote multilingual speech; this frame alone does not prove language switching or audio behavior.
   - **Feature/UX takeaway:** command centre as the first surface: status and task/integration map first, with chat or voice as a clear action.

4. [I Built a Real JARVIS to Control My Phone! 💀](https://www.youtube.com/shorts/V6kvapGV9qk) — @jarvis_ai_spark; YouTube Shorts page; title visible in page accessibility text.
   - **Frame evidence, sampled Shorts frame:** portrait video shows a laptop keyboard and a dark code editor/file tree. Its overlaid text says “I Built a Real life JARVIS to Control My Phone!” The phone-control UI itself was not visible in this sampled frame.
   - **Feature/UX takeaway:** phone control is the source’s stated premise; treat it as a mobile requirement to investigate, not a verified demo result. Hermes should be designed responsively, with touch-sized actions and a readable narrow-screen command-centre layout.

5. [How I Built JARVIS with No Code (Tutorial w/ Lovable, ElevenLabs, n8n)](https://www.youtube.com/watch?v=KUvSzvFeZls) — Nate Herk | AI Automation; 34:25; page showed 240K views, 1 year ago.
   - **Frame evidence, 0:00 “Quick Demos”:** split-screen: dark JARVIS pane at left with an “Online” label and glowing assistant orb; visual workflow canvas at right, Webhook → Jarvis Tools Agent → Respond to Webhook. Connected nodes visibly include 4o, Simple Memory, Tavily, Calculator; lower branches include Email, Calendar, Contact and Content agents. Presenter picture-in-picture at lower right.
   - **Feature/UX takeaway:** make triggers, agent, tools, memory and destinations visible as inspectable nodes; preserve a live assistant surface beside the workflow view. This frame is a demo overview, not proof each integration worked.

6. [[Free on Github] My Jarvis AI Assistant](https://www.youtube.com/watch?v=FiOTrxq9ckM) — jaredrhod; 9:08; page showed 400K views, 1 month ago.
   - **Frame evidence, 0:00:** cinematic dark green circuit-board background, central illuminated “J.A.R.V.I.S.” plate and a small green “SPEAKING” indicator at top right. At 1:00, the sampled frame is the presenter speaking to camera, not the app.
   - **Page description evidence (not a seen demo):** description says Jarvis “talks,” remembers prior work, pushes back on ideas, and performs work on the machine.
   - **Feature/UX takeaway:** visible speech/activity state and inspectable memory/action history are sensible design directions; the sampled frames do not demonstrate them.

7. [A Jarvis Build That Actually Does Things](https://www.youtube.com/watch?v=6Tb41ORADgs) — jaredrhod; 0:45; page showed 18K views, 2 months ago.
   - **Frame evidence, 0:00:** the same J.A.R.V.I.S. cinematic title treatment/circuit-board background and green speaking indicator. No working product UI was visible in the sampled frame.
   - **Page description evidence (not visual proof):** describes a single offline HTML file using browser Canvas 2D and vanilla JavaScript for a Jarvis visualizer.
   - **Feature/UX takeaway:** the speaking indicator suggests a clear idle/listening/speaking state; favor a lightweight responsive visualizer when voice is active. No feature behaviour was verified.

8. [How To Make A Jarvis](https://www.youtube.com/watch?v=cQqOkx5qnWo) — jaredrhod; 4:08; page showed 222K views, 3 months ago.
   - **Frame evidence, 0:00:** presenter at a desk with microphone; no assistant UI in the sampled frame.
   - **Page description evidence (not visual proof):** says the tutorial first covers gathering/retrieving information and completing tasks. The visible description begins, “A Jarvis is useless if it can't gather and retrieve information or complete tasks for you.”
   - **Feature/UX takeaway:** organize the dashboard around retrieval and task results, with sources and completion state. The sampled frame does not verify a particular interface.

9. [How to build a PREMIUM Hermes Agent Mission Control Dashboard 2.0 (Step-by-Step Guide)](https://www.youtube.com/watch?v=Iup815Xz_ZU) — Komputer Mechanic; 1:16:49; page showed 79K views, 2 months ago.
   - **Frame evidence, 53:27, chapter “Build an AI Agent Mission Control Dashboard”:** split screen. Left is a Telegram-style Hermes team view with channels (#reach, #scribe, #scout, #command, #dev), an agent message and an area/agent routing table. Right is a tutorial/document view headed “Explore the Hermes Data Sources (Read-Only)” and “Build server.py — The Read-Only Data Layer.”
   - **Feature/UX takeaway:** make fleet/agent routing visible and label source inspection read-only in the UI. Dashboard may surface status without implying write authority.

10. [How to build a JARVIS-themed PREMIUM Hermes Mission Control dashboard](https://www.youtube.com/watch?v=u7f0ygnrvf8) — Komputer Mechanic; 1:39:34; page showed 31K views, 1 month ago.
   - **Frame evidence, 1:15:16, chapter “Schedule and Library Tabs + SerpApi Real-Time Web Search”:** split-screen tutorial with a dark application/library pane at right, showing a “LIBRARY” sidebar and a long numbered task/instruction list; code/editor pane at left; presenter picture-in-picture at lower right. Text on the task page is too small to read reliably.
   - **Feature/UX takeaway:** give schedules and saved resources persistent first-class navigation alongside a dashboard; do not bury the library in chat history. The named chapter confirms the topics covered, but no specific search result or schedule execution is verified from this frame.

## Source idea: saved Reels → reusable skill

[Turn your saved reels into a Claude skill](https://www.murphmaxxing.com/vault/saved-reels-to-claude-skill) — canonical URL used without tracking parameters.
- The page itself could not be loaded in the browser. The publisher’s official homepage search result describes the flow: watch saved Reels, transcribe them, check techniques against official docs and the user’s projects, then produce a ranked list of actions. This supports the concept, not a review of the source page’s full text.
- Hermes adaptation: a self-improvement intake queue with saved references, transcript and frame notes, claim/source checks, fit to the current project, and a ranked action backlog. Keep source evidence attached to each proposed improvement so a title or transcript is never mistaken for visual proof.

## Cross-source recommendations for Hermes Core / Jarvis

- Make the default screen a **command centre**: system/agent status, recent runs, scheduled work, saved resources, and actionable metrics/graphs. Keep chat available as a prominent mode, not the whole application.
- Put **voice state** where it is instantly readable (idle/listening/processing/speaking/error), with obvious mic/TTS controls and transcript text the user can correct. The 0:02 and 1:09 frames above show visual inspiration; they do not prove robust STT/TTS.
- Show **workflow and delegation paths** as inspectable trigger → agent → tools/memory → result flows; expose per-step state and errors, and label read-only versus action-capable surfaces.
- Keep **stats and graphs** tied to real event data, with time range and definitions; avoid decorative “live” claims without measured state.
- Make the command centre responsive for **tablets and phones**: reflow graph into a readable list/detail view, preserve primary voice/actions, and use touch-sized controls. Only source 4 explicitly names phone control; its sampled frame shows laptop code, so this is a design inference, not observed mobile UI.
- Turn reference intake into an **evidence-backed improvement loop**: save URL, timestamped observation, transcript when available, official-doc corroboration, fit/risk, and an ordered next-step proposal.

## Coverage and limits

All ten supplied URLs were opened in an agent-created YouTube tab and at least one actual playback frame was inspected per source. Selected deep frames were sampled where the player’s saved progress exposed them. This does not amount to full-duration viewing of the long videos. Page titles, view counts, chapter names and descriptions are page metadata; they are not treated as proof of demonstrated behavior. Captions were marked unavailable on the sampled long-form pages, and no transcript export was exposed in this browser surface. The Murphmaxxing article route returned an access failure; only its official-site search snippet was usable.

## Deep-demo coverage attempt (2026-10-11)

Requested follow-up: read every visible chapter title and sample six distinct demo states from each long tutorial, including dashboard/menu, statistics/graphs, library/capabilities, model settings, schedule/Kanban, and voice where present. **This coverage is incomplete.** The existing source ledger has one actual playback frame each for these videos; the extra saved-progress/AX observation below is an actual page label but does not meet the 12-frame requirement.

- **Iup815Xz_ZU:** existing actual frame at 53:27 is described in source 9 above. The current task only has its chapter title “Build an AI Agent Mission Control Dashboard” and that frame. It does not have a fresh playback capture for statistics/graphs, model settings, schedule/Kanban, or voice, nor an enumeration of all chapter titles. No evidence is added for those features.
- **u7f0ygnrvf8:** existing actual frame at 1:15:16 is described in source 10 above. A visible player/AX chapter label reads “Voice Mode Setup: Free Local Kokoro vs ElevenLabs + Keyboard Shortcuts” (around 1:15:18); this is chapter metadata only, not proof of a voice-settings screen or functioning TTS. No fresh frame evidence for dashboard/menu, statistics/graphs, capability/library details, model settings, schedule/Kanban, or voice controls is available here.
- **Access/tool boundary:** CUA reported both `iab` and `chrome` browser targets unavailable. Browser Use CLI documentation was checked; its local Chrome daemon failed diagnostics (`daemon alive` false; active connections 0), and its first read-only connection attempt did not attach. The web fetch exposed only YouTube page shell metadata. No supported native YouTube transcript-export control was reachable, so no transcript was requested or fabricated. No media was downloaded, no workaround was attempted, and no existing Chrome tabs were touched.

These findings must remain labeled as one-frame/source-page observations. Completing the requested chapter inventory and 12 distinct demo-frame sample requires a functioning supported browser connection to the two public playback pages.
