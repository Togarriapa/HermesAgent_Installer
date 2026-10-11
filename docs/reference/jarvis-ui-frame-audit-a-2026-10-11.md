# Jarvis UI/UX video reference audit

Date: 2026-10-11

## Scope and evidence standard

Reviewed all ten user-supplied YouTube pages in one agent-created temporary in-app browser tab. For each video, captured at least one screenshot of the video player during actual playback. A player timestamp is recorded only when visible in the player UI; Shorts timestamps are approximate opening frames because their player exposed no time readout. Sampled frames do not establish what appears in the rest of a video. YouTube page title, channel, length and description are metadata; they are not treated as visual evidence. Some sampled players exposed “Subtitles/closed captions unavailable,” which does not establish transcript unavailability. For h9SsHkRSHxo, the page Transcript tab was opened but remained on a loading spinner with only the heading “Nexora Walkthrough”; no lines became visible in this browser session. The official YouTube captions API documents that listing requires authorized scope and downloading captions requires permission to edit the video, so no public-owner transcript export was available through that API ([captions.list](https://developers.google.com/youtube/v3/docs/captions/list), [captions.download](https://developers.google.com/youtube/v3/docs/captions/download)). No reference page required login or was inaccessible during the visual sample. Screenshots were inspected live and are not embedded in this text ledger.

## Source-by-source ledger

1. [7 Hermes Agent Upgrades You NEED To Implement Today](https://www.youtube.com/watch?v=h9SsHkRSHxo) — Komputer Mechanic; 9:46 (page metadata: 74K views, 5d ago at review).
   - **Actual frames:** 0:00 title card “Hermes Agent” on warm dark background, ringed by small colored role/avatar icons. 0:16 a simulated Telegram window reads “JUST A CHATBOT” with a plain user greeting and agent reply. 0:36 chapter overlay “Tip 1: Build an AI Agent Team, Not One Agent”; the same conversation shows suggested requests (“Research my three competitors”, “Write this week’s newsletter”) and a compact result summary (“Done ✓ Monday: content, Tuesday: calls…”), with “TIP 1 · A CREW” indicator.
   - **UX/feature evidence:** Keep chat as a direct interaction route, offer task-relevant starter actions, and expose team/crew routing where it helps. This supports quick controls connected to the current task; it does not establish chat as the main dashboard.

2. [Turn Your Hermes Agent into JARVIS From Ironman (100% FREE)](https://www.youtube.com/watch?v=RqwXffETwsc) — Damian Malliaros; 17:00 (61K views, 1mo ago at review).
   - **Actual frame:** 0:14 blue-gradient explainer card: document icon, dashed path, text “Pulls data from all of the apps”; presenter video inset at lower right. No working application screen was visible in this sampled frame.
   - **UX/feature evidence:** State the cross-app capability in plain language and show a concrete status/flow. The frame is an explainer graphic, not proof of a running integration.

3. [Hermes Built Its Own Iron Man JARVIS (Voice-Controlled)](https://www.youtube.com/watch?v=AqhYvItgMOE) — Shab Noor | AI For Operators; 20:42 (28K views, 2mo ago at review).
   - **Actual frame:** 10:50 chapter “When it doesn't come out right (the fix)”: black cinematic slide with “CODING” struck through, “DIRECTING” highlighted in yellow, and subtitle “NOT MAGIC INTELLIGENCE — JUST A WEBPAGE TALKING TO AN AGENT.” This sample is an editorial card, not product UI.
   - **UX/feature evidence:** Describe the agent as a directed tool with visible outcomes and recovery, rather than implying magic. The caption’s specific “webpage talking to an agent” framing makes the UI boundary legible.

4. [How I Built JARVIS with Hermes Agent in 10 Minutes (No Coding)](https://www.youtube.com/watch?v=zCTKDgETwUQ) — Edwin Chen | AI Automation; 15:07 (1.3K views, 9d ago at review).
   - **Actual frames:** 0:02 white radial-motion title card, oversized black “Hermes Agent” wordmark and illustrated anime-style avatar. 0:16 presenter on camera; no product surface appears in this sampled frame.
   - **UX/feature evidence:** This sample provides branding/pacing evidence only. It does not substantiate any dashboard or feature behavior.

5. [Hermes Agent lets you build Jarvis irl #ai #jarvis](https://www.youtube.com/shorts/6smKhzEXM_s) — @lukebuildsai; Shorts.
   - **Actual opening frame (approx. 0:00):** portrait video of a person at a dark multi-monitor workstation with a blue radial “Jarvis” display. Overlay text says “POV: Jarvis is building you a $30k MRR app”; “Wake up!” caption is visible.
   - **UX/feature evidence:** This is aspirational workstation imagery and a short dramatic caption, not a demonstrated software interaction. The busy multimonitor setup is not a usability pattern to copy.

6. [Hermes Jarvis Blew My Mind (Here's Why)](https://www.youtube.com/watch?v=ufPb_ESGy-w) — ProfitArc; 10:22 (679 views, 3mo ago at review).
   - **Actual frame:** 0:00 screen-recorded browser UI titled “Agentic OS — Mission Control.” The left rail groups “Mission Control,” Paperclip, AI Agent Mastermind, Pipeline, Agent Kanban and an agent roster. The center is headed “Hermes,” with tabs for Chat, Talk, Hermes-Jarvis, Studio, Sessions, Workspace, MCPs, Manage, Control Room and Goal Mode. The main card is one large voice orb with a connection/listening status and a few mode controls; a command-palette control sits top right. A compact event strip is visible below the orb.
   - **UX/feature evidence:** Strongest command-centre reference: a stable home, grouped navigation, one prominent live activity/status card, voice as an available mode, and a global command entry. It also shows the over-complexity risk: too many destinations and tabs compete with the main task. Reduce the groups and labels substantially.
   - **Metadata description (not visual proof):** says the assistant executes tasks such as opening Obsidian and Google using voice commands.

7. [I Built a PREMIUM Misson Control for My 16 Hermes Agents (FREE PROMPTS)](https://www.youtube.com/watch?v=Ytpp65paFpY) — Komputer Mechanic; 28:10 (34K views, 13d ago at review).
   - **Actual frame:** 8:07 chapter “Voice Mode: Talk to Your …” shows a light explainer card “Your voice, there and back.” It depicts a four-step path: “You talk” into the voice tab → Chrome writes speech to text → Hermes agent answers in text → Piper reads it out. This is an explainer card in the video, not an observed live app interaction.
   - **UX/feature evidence:** Make voice input/output stages and current state explicit, preserve visible text as a fallback/result, and label which stage handled the request. Voice should be an optional route, not an invisible mode switch.

8. [Turn Your Hermes Agent into JARVIS From Ironman (Runs 24/7)](https://www.youtube.com/watch?v=O2iSLGL3wo8) — Damian Malliaros; 23:46 (33K views, 1mo ago at review).
   - **Actual frame:** 2:30, chapter “Why it needs the cloud”: screen-recorded browser presentation page with heading “So why does this need to run 24/7?”, a short explanatory line, three separate issue cards (“Close your laptop, it stops”; “Nothing runs overnight”; “No morning brief”), then a green resolution strip about hosting it somewhere that never sleeps. Presenter is inset at lower right. This is a presentation inside the video, not a product dashboard.
   - **UX/feature evidence:** Explain architecture or availability with a short progression: problem, concrete effects, resolution. Use compact cards and one clear takeaway rather than burying the user in server terminology.

9. [Build Your Own Jarvis & Ultron Ai Assistant 🤖🔥](https://www.youtube.com/shorts/2NKpA6smfwg) — @neuralstack-p5d; Shorts.
   - **Actual opening frame (approx. 0:00):** portrait “NeuralStack” title card over a multimonitor coding desk, text “How I Built My Own Real JARVIS Voice Assistant” and “Full Jarvis AI Setup Tutorial.” The visible monitors show code/editor content; no assistant UI interaction is demonstrated in this opening frame.
   - **UX/feature evidence:** Tutorial branding and maker-workstation imagery only; no direct dashboard pattern.

10. [I Built JARVIS with Claude Code (INSANE Results!)](https://www.youtube.com/watch?v=Acw0NtkyNtM) — Zubair Trabzada | AI Workshop; 11:01 (100K views, 1mo ago at review).
    - **Actual frames:** 0:00–0:02 chapter “Jarvis Intro Demo” shows a dark browser-based interface, a dense multicolor node-link map across most of the canvas, a large filter/category panel on the right, a left topic-suite and force-control panel, a separate circular “J.A.R.V.I.S. / LISTENING” element on the right side of the workspace, and voice prompt/control icons along the bottom. “Coming Up…” overlay is also visible.
    - **UX/feature evidence:** The graph/filters/voice affordance imply knowledge navigation and voice control, but the composition is visibly busy. Do not make a dense graph, simultaneous control panels, or an animated voice orb compete as the default view. Preserve only the functions with clear user demand and tuck specialist graph exploration into a dedicated route.

## Cross-reference design cues

- Make Overview/Mission Control the landing surface; give it one clear current-state card with genuine status and a concise activity/event strip.
- Use a short left navigation grouped by purpose. Avoid exposing every feature as a peer-level destination or placing several rows of mode tabs across the home view.
- Provide a top-level command entry and contextual quick actions; route team/crew use from relevant tasks and keep chat as a dedicated workspace option.
- Make voice an explicit optional input/output control with a visible listening/processing/result state and text retained for readability and recovery.
- Use compact explanatory cards for setup, availability, or failures: one problem, concrete consequences, clear resolution. Avoid cinematic claims or ornamental visuals standing in for product state.
- Keep the orb subordinate to status and action. A large orb is supported by a single voice-focused card in one sampled UI; a separate orb plus graph plus filter walls is the complexity warning in another.

## Limits

The ledger records sampled player frames, not a full review of every second. Items 2–5, 7–9 include explainer, title, or aspirational footage rather than a demonstrated full application flow. The h9SsHkRSHxo Transcript tab did not finish loading in the supplemental browser inspection; its CC-unavailable player control is not treated as evidence that a transcript does not exist. Page counts/relative ages are volatile display metadata and are included only to identify what was visible on 2026-10-11.

## Deeper visual sample: h9SsHkRSHxo

YouTube's visible “In this video → Chapters” panel exposed these full chapter labels/times (all read in the page UI): 0:00 “Hermes Agent Is More Than a Chatbot”; 0:29 “Tip 1: Build an AI Agent Team, Not One Agent”; 1:39 “Hermes Agent Multiple Agents in Telegram Topics”; 1:58 “Tip 2: You Don't Need the Most Expensive Model”; 3:03 “Use Your ChatGPT Subscription in Hermes Agent”; 3:28 “Tip 3: Hermes Agent Memory (LLM Wiki)”; 4:51 “Tip 4: Hermes Agent Cron Jobs (Work Without You)”; 5:21 “The Trick That Keeps Your Phone Quiet”; 5:48 “Tip 5: Connect Your Tools Safely (Composio)”; 6:56 “Prompt Injection: Email Is Information, Not Orders”; 7:23 “Tip 6: Multiple Hermes Setups on One Server (Docker)”; 8:02 “Tip 7: Hermes Agent Mission Control (NEXORA)”; 9:33 “Thanks for Watching.” These are creator-authored chapter headings, not independent feature verification.

Additional playback screenshots beyond the earlier three samples:

- **1:39, Multiple Agents / Telegram Topics:** dark animated explainer layout; “CREW HQ · TOPICS” card lists `# General`, `# Research`, `# Writer`, alongside a separate ORCHESTRATOR avatar. This communicates channelized delegation and a distinct coordinator; it is an illustration, not a live Telegram capture.
- **3:28, Memory:** Telegram-like simulated UI shows `Orchestrator · CONTEXT · 30% FULL`, with a separate “LOST IN THE SUMMARY” note and five concrete memory facts (client/invoice contact, report style, Sunday constraint, launch date, logo choice). The assistant’s summary is visibly lossy. Action cue: show context/memory health and retain user-approved durable facts where useful; do not hide what the summary dropped.
- **4:51, Cron/jobs:** editorial slide contrasts “Only when you talk to it” with an agent marked `WORKING` and a user bubble. The chapter describes cron jobs, while the captured slide is a conceptual contrast; it does not demonstrate a scheduler, schedule editor, or job history.
- **5:48, tool access:** infographic depicts an EMAIL AGENT, envelope, dashed link, lock and Inbox card with “It needs a tool to get in.” This is a legible least-access metaphor, not proof of Composio connection setup or permission UX.
- **6:56, injection guardrails:** frame displays three rules: “ONE AGENT ONLY”, “READ-ONLY FIRST”, “EMAIL ≠ INSTRUCTIONS”; email/research/writer/developer agent figures are crossed out beside the email agent. It makes a practical approval/scope policy scannable, but is a graphic rather than an enforced policy screen.
- **7:23, multiple setups:** typographic chapter card says “Run several Hermes setups on one server.” No Docker configuration, resource isolation, or management UI is visible in this frame.
- **8:02, Mission Control:** chapter card says “Build your own mission control.” No NEXORA dashboard controls appear in this sampled frame; do not cite this chapter sample as dashboard evidence.

## Deeper visual sample: ufPb_ESGy-w

The page showed title, channel, duration and description metadata. It did not expose an “In this video” chapters panel in the sampled page UI; therefore there is no chapter list to enumerate here. I sampled the actual video player by visible playback timestamps across the 10:22 runtime. These are screen recordings embedded in the creator’s video (including creator data/demo content), not the target Hermes repository’s interface and not evidence of behavior in this project.

- **0:02:** Hermes-Jarvis page: role-specific navigation on the left; top tabs `Chat`, `Talk`, `Hermes-Jarvis`, `Studio`, `Sessions`, `Workspace`, `MCPs`, `Manage`, `Control Room`, `Goal Mode`; central large voice orb; status text; wall-mode action; lower explicit `Realtime ON`, `Live OFF`, `Wake word OFF`, `Auto`, `Briefing` and persona controls; a session panel has `History` and `End` actions. A man’s camera inset occupies the lower left. This is demonstrably a voice-focused page, not a dashboard Overview.
- **0:27:** same voice view now has a transcript-like interaction area. The user says “Open up Obsidian for me”; the activity reads `Opening Obsidian…` and `Opening https://google.com…`. The “Realtime” listener/speaker state is shown adjacent to visible text, making voice state and transcript inspectable together.
- **1:53:** same panel records the prior request, agent opening status, and conversational reply; the center orb remains. This is a changed session state, not a different page.
- **2:58:** a gallery/grid view shows many named artifacts/projects as cards (e.g. “Build Out A Snake Game 4”, “Prompt Heist Stealth Prompt Engi…”, “Stillness Meditation”, “Pulse Habit Tracker”, “Budget Tracker App”, “Focus Todo App”, “Aurora Dreams”, “Fireworks Finale”). Left rail expands to a long model/agent roster including Gemini, Antigravity, Codex, Kimi Code, GLM 5.2, Grok Build, Free Claude Code, Fusion, Local. The collection demonstrates breadth but the many peer services reinforce the need to keep the default nav short.
- **4:02:** “Daily Briefing” card for Sunday 21 June with Daily/Weekly toggle, five suggested focus items, “Open action items · 9” checklist, and theme chips such as Vault wiki restructure, SEO keyword mapping, AIPB funnel review, transcript corrections, infrastructure decisions and health targets. This is a useful actionable summary layout; its many rows should be collapsed to a short priority list on an Overview.
- **5:06:** scrolled lower menu exposes `Loop`, `SEO`, `Video`, `Music`, `Game Studio`, `Thumbnails`, `Notebook`, `Kanban`, `Memory`; briefing extends into themes, “Worked on” chips and an “On your mind” section. This supports navigation grouping / optional specialist views, while showing the crowding cost of making all capabilities peers.
- **6:11:** full-screen voice dashboard includes status `ONLINE`, mode `AUTO`, wake word `OFF`, voice `DANIEL · EN-GB`, and measured bars (Neural Throughput, Core Load, Signal, Latency). Right-side Daily Briefing summary shows counts (9 open items, 9 notes touched, 15 recent captures), suggested focus tasks, plus Daily/Weekly controls. These are visible demo metrics, not verified runtime telemetry from our project; any analogous values must come from real state.
- **7:15:** “Briefing History” panel lists five saved daily/weekly briefings, dates, and concise summaries; each is a reopenable past entry. A history drawer is a useful secondary destination without crowding home.
- **8:19:** the Hermes page header and top workspace route tabs are fully visible again, along with the persistent orb/voice status. The tabs occupy a long single row and support treating Chat/Talk as one dedicated workspace with quick actions elsewhere.
- **9:23:** the recording leaves the local app and shows the creator’s Skool “AI Profit Boardroom” About page with community/classroom/calendar/member/map/leaderboard navigation and membership pricing. This is not Mission Control or a settings screen, so it is excluded as product UI evidence.

No sampled frame showed the actual Kanban board, team roster detail or settings form, although Kanban and Manage were visible as navigation labels. The explicit per-user ask to review settings/Kanban/team views is thus only partly verifiable from this sample; do not claim those screens were inspected. The video is a sequence of UI views, not a chaptered feature walkthrough in the page UI. A practical adaptation is an Overview home with one truthful state card and today's few actions; compact navigation for Overview, Agents/Teams, Sessions/Chat, Skills and Activity/Settings; preserve voice/chat as optional input, not the home layout. Teams should be named/selected in context, and settings should stay in the dedicated settings view. This synthesis is separate from the video-specific observations above.
