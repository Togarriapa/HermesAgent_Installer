# Jarvis UI/UX video reference audit

Date: 2026-10-11

## Scope and evidence standard

Reviewed all ten user-supplied YouTube pages in one agent-created temporary in-app browser tab. For each video, captured at least one screenshot of the video player during actual playback. A player timestamp is recorded only when visible in the player UI; Shorts timestamps are approximate opening frames because their player exposed no time readout. Sampled frames do not establish what appears in the rest of a video. YouTube page title, channel, length and description are metadata; they are not treated as visual evidence. The sampled videos showed “Subtitles/closed captions unavailable” in the player accessibility state. No transcript export interface was available in the browser tool, so no transcript claims are made. No reference page required login or was inaccessible during the visual sample. Screenshots were inspected live and are not embedded in this text ledger.

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

The ledger records sampled player frames, not a full review of every second. Items 2–5, 7–9 include explainer, title, or aspirational footage rather than a demonstrated full application flow. Captions were reported unavailable and no transcript export path was exposed. Page counts/relative ages are volatile display metadata and are included only to identify what was visible on 2026-10-11.
