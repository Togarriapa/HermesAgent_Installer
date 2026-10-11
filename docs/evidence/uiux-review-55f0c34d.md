# UI/UX review checkpoint: reactor visibility and connection state

R0203 / RT-T266.3 / VD-T266.5. Candidate source: `55f0c34d8b95bd2e845958d2462e769d8715f6b5`. Review date: 2026-10-11 UTC. **Disposition: controlled-render checks passed; live affected-flow review remains pending. This record does not clear deployment or full acceptance.**

The changed flow is the Overview reactor's visible/hidden, connected/offline and reduced-motion state. Background chat-history refresh errors also remain separate from a completed reply. Menu destinations, conversation data, provider credentials and the running Core were not changed by this candidate.

## Exact Pi evidence

- Archive: `core-source-presence-network-final.tar.gz`; SHA-256 `3ba8d9fc7e047e3fc37675d15820464353afeeed9c1b3acf397c1dcd7bf5626f`.
- Pi source: `/var/tmp/hermes-jarvis-core-checks-20261011/ui-networkpresencefinal-source`.
- Contract suite: **179 passed**, 21 warnings, 6.59 seconds. Composed and feature JavaScript syntax checks passed. Logs: `candidate-networkpresencefinal-ui-{run,tests}.log` in the Pi checks directory.
- Pi-only sandboxed Chromium probe v9: SHA-256 `a7f756348774c649860716608f6b2aeda0508fb6286dc1d8209fbf8b1ec3d541`. Report: `/var/tmp/hermes-jarvis-core-checks-20261011/responsive-networkpresencefinal-v9/responsive-fixture-report.json`; `result=pass`, `failed_checks=[]`.
- Actual controlled renders: phone 390×844, tablet 768×1024, desktop 1440×900. At every size, all six central-motion checks passed: foreground quiet/connected state, a running central animation, measured transform change, reduced-motion cessation, hidden-page cessation and offline cessation. The v8 overall grade was invalid because it omitted motion failures; use v9 evidence only.
- Six captured Overview/Chat PNGs remain in the report directory, named `<device>-<width>x<height>-<overview|chat>-fixture.png`. These contain synthetic, loopback-authenticated fixture data; no model or microphone was used.

## Review boundaries and next checks

The live predecessor `dabdc4916` was separately observed at an actual browser viewport of 390×844: the Conversations popup and native chat textarea were reachable, and voice opt-in exposed its controls. Its central animation lacked the section visibility attribute; the new candidate supplies it and stops motion while network state is unverified.

Controlled renders and measurements establish only their stated layout and state behavior. A reviewer still needs to inspect the exact candidate's live phone/tablet/desktop screens, keyboard/focus, visible response/history-error agreement, reconnection and actual Access state before deployment clearance. Physical phone keyboard, microphone/STT/TTS/wake behavior, family concurrency, native capability effects and full installer acceptance are not established here. Keep these pending; do not infer their success from visible controls or fixture results.

All 219 requirements and eight broad acceptance groups remain open. Every subsequent affected feature, behavior, menu or settings edit requires a refreshed review record under the repository's UI/UX gate.
