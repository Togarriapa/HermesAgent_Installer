"""Small, accessible overview fragment for the existing protected owner projection."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class="overview-page" aria-labelledby="overview-title">
  <section class="command-centre-shell" aria-label="Jarvis command centre">
  <section class="overview-stage" data-activity="unknown" data-in-viewport="false" aria-label="Jarvis activity">
    <aside class="overview-rail" aria-label="Recent accepted turn outcomes">
      <div class="overview-readout"><span>Accepted · 7 days</span><strong data-metric="total">Unknown</strong><small>Owner turns</small></div>
      <div class="overview-readout"><span>Completed</span><strong data-metric="completed">Unknown</strong><small>Observed outcomes</small></div>
    </aside>
    <div class="reactor-presence">
      <div class="reactor-figure" aria-hidden="true">
        <svg viewBox="0 0 240 240" focusable="false">
          <circle class="reactor-dial" cx="120" cy="120" r="116"/>
          <circle class="reactor-orbit reactor-orbit-outer" cx="120" cy="120" r="111"/>
          <circle class="reactor-orbit reactor-orbit-inner" cx="120" cy="120" r="93"/>
          <path class="reactor-segment reactor-segment-north" d="M120 10A110 110 0 0 1 211 58"/>
          <path class="reactor-segment reactor-segment-east" d="M230 120A110 110 0 0 1 174 215"/>
          <path class="reactor-segment reactor-segment-south" d="M120 230A110 110 0 0 1 28 175"/>
          <path class="reactor-segment reactor-segment-west" d="M10 120A110 110 0 0 1 65 29"/>
          <circle class="reactor-instrument-track" cx="120" cy="120" r="83"/>
          <circle class="reactor-chamber" cx="120" cy="120" r="75"/>
          <g class="reactor-iris" aria-hidden="true">
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z"/>
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z" transform="rotate(60 120 120)"/>
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z" transform="rotate(120 120 120)"/>
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z" transform="rotate(180 120 120)"/>
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z" transform="rotate(240 120 120)"/>
            <path class="reactor-iris-blade" d="M120 62C137 56 153 63 163 77C147 70 134 73 120 84Z" transform="rotate(300 120 120)"/>
          </g>
          <circle class="reactor-core" cx="120" cy="120" r="57"/>
          <circle class="reactor-lens" cx="120" cy="120" r="43"/>
          <circle class="reactor-aperture" cx="120" cy="120" r="7"/>
          <path class="reactor-axis" d="M120 2v12m0 212v12M2 120h12m212 0h12"/>
          <path class="reactor-ticks" d="M120 24v10m0 172v10M24 120h10m172 0h10M52 52l8 8m120 120 8 8m0-136-8 8M60 180l-8 8"/>
          <circle class="reactor-node" cx="120" cy="4" r="2.5"/><circle class="reactor-node" cx="236" cy="120" r="2.5"/>
          <circle class="reactor-node" cx="120" cy="236" r="2.5"/><circle class="reactor-node" cx="4" cy="120" r="2.5"/>
        </svg>
        <span class="reactor-label">J.A.R.V.I.S.<small>PERSONAL ASSISTANT</small></span>
      </div>
      <h1 id="overview-title">At your service.</h1>
      <p class="reactor-state" data-reactor-state role="status" aria-live="polite">Checking current service observation…</p>
      <section class="reactor-connection" aria-labelledby="overview-core-heading">
        <div><h2 id="overview-core-heading">Service status</h2><p data-core-status role="status" aria-live="polite">Checking verified status</p></div>
        <p data-core-readiness>Functional readiness has not been verified.</p>
        <p data-core-observed>No verified observation time</p>
      </section>
    </div>
    <aside class="overview-rail" aria-label="Current activity and conversation count">
      <div class="overview-readout"><span>In progress</span><strong data-metric="active">Unknown</strong><small data-reactor-active-label>Current owner turns</small></div>
      <div class="overview-readout overview-attention"><span>Failed</span><strong data-metric="failed">Unknown</strong><small>Observed outcomes</small></div>
      <div class="overview-readout"><span>Private chats</span><strong data-conversation-count>Unknown</strong><small>In your history</small></div>
    </aside>
  </section>
  <section class="command-panel" aria-labelledby="command-title">
    <h2 id="command-title" class="visually-hidden">Send a message to Jarvis</h2>
    <div class="command-intro"><span class="command-kicker">MESSAGE JARVIS</span><span id="overview-command-target" class="command-target" role="status" aria-live="polite">A new conversation will start when you send.</span></div>
    <form data-command-form class="command-form">
      <label class="visually-hidden" for="command-input">Ask Jarvis</label>
      <textarea id="command-input" name="command" rows="1" maxlength="8000" placeholder="Ask Jarvis anything…" autocomplete="off" autocapitalize="sentences" inputmode="text" enterkeyhint="send" aria-describedby="command-hint"></textarea>
      <button type="submit" aria-label="Send command to Jarvis"><span>Send to Jarvis</span><span aria-hidden="true">↑</span></button>
    </form>
    <p id="command-hint">Enter to send · Shift + Enter for a new line. Suggestions fill this message and wait for you to send.</p>
    <div class="quick-actions" aria-label="Suggested commands">
      <button type="button" data-new-conversation>New conversation</button>
      <button type="button" data-command-prompt="Review my pending missions and explain what is awaiting execution.">Review pending missions</button>
      <button type="button" data-command-prompt="Summarize my recent Jarvis activity and its available source evidence.">Summarize recent activity</button>
      <button type="button" data-command-prompt="Help me find the right installed skill or tool for this task: ">Find a skill or tool</button>
      <button type="button" data-command-prompt="Review the current status of my configured integrations and report anything unavailable. Do not change their configuration.">Check integrations</button>
    </div>
  </section>
  </section>
  <section class="ecosystem-card" data-ecosystem-card data-ecosystem-state="unavailable" data-activity-flow="idle" data-in-viewport="false" aria-labelledby="overview-ecosystem-title">
    <header class="ecosystem-heading"><div><p class="overview-kicker">NATIVE ACTIVITY</p><h2 id="overview-ecosystem-title">Expert &amp; Team activity</h2></div>
      <button type="button" data-view="activity">Open Activity</button></header>
    <p class="ecosystem-status" data-ecosystem-status role="status" aria-live="polite">Loading native Expert observations…</p>
    <div class="ecosystem-identities">
      <div><h3>Expert instances</h3><p data-expert-identity>Loading native instance names…</p></div>
      <div><h3>Selected Team</h3><p data-selected-team>Loading Team membership observation…</p></div>
    </div>
    <p class="ecosystem-summary" data-ecosystem-summary>Waiting for current native observations.</p>
    <ol class="handoff-graph" data-handoff-graph aria-label="Native Expert instances linked to their observed events" hidden></ol>
    <p class="ecosystem-provenance">Names and states come from root-observed native instances. Team membership appears only when independently verified; animated handoffs require a separate recorded directed relation.</p>
  </section>
  <div id="jarvis-ecosystem-feature-host" data-feature-host="ecosystem-fleet"></div>
  <div class="overview-toolbar"><p data-observation role="status" aria-live="polite">Loading measured data…</p><button type="button" data-refresh>Refresh</button></div>
  <p class="overview-window" data-window></p>
  <details class="overview-details">
    <summary>Explore activity and work</summary>
    <div class="overview-detail-body">
      <div class="overview-lower-grid">
        <section class="overview-card" aria-labelledby="overview-duration-title">
          <div class="overview-heading"><div><h2 id="overview-duration-title">Recent elapsed time</h2></div></div>
          <p data-duration-basis>Loading duration coverage…</p>
          <ol class="overview-bars" data-duration-bars aria-label="Recent turn durations"></ol>
          <table><caption>Recent terminal turns</caption><thead><tr><th scope="col">Accepted</th><th scope="col">Outcome</th><th scope="col">Elapsed</th></tr></thead>
            <tbody data-duration-rows></tbody></table>
          <p data-duration-coverage></p>
        </section>
        <section class="overview-card" aria-labelledby="overview-work-title">
          <div class="overview-heading"><div><h2 id="overview-work-title">Work &amp; resources</h2></div></div>
          <dl class="overview-facts"><div><dt>Approved missions awaiting execution</dt><dd data-missions>Unknown</dd></div>
            <div><dt>Paused schedules</dt><dd data-schedules>Unknown</dd></div>
            <div><dt>Native skills discovered</dt><dd data-resource-skills>Unknown</dd></div>
            <div><dt>Internal profiles discovered</dt><dd data-resource-profiles>Unknown</dd></div></dl>
          <p class="overview-provenance" data-pending-note></p>
          <p class="overview-provenance" data-resource-state>Discovery status unavailable.</p>
          <p class="overview-provenance" data-dispatch>Dispatched identity count unavailable.</p>
        </section>
      </div>
      <section class="overview-card overview-history" aria-labelledby="overview-history-title">
        <div class="overview-heading"><div><h2 id="overview-history-title">Accepted turns by day</h2></div></div>
        <table><caption>UTC dates and accepted owned turns</caption><thead><tr><th scope="col">Date</th><th scope="col">Turns</th></tr></thead>
          <tbody data-day-rows></tbody></table>
      </section>
    </div>
  </details>
</section>"""

_CSS = """
[data-feature-root="overview"] .quick-actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}
[data-feature-root="overview"] .quick-actions button{min-height:44px;padding:.45rem .8rem;border:1px solid rgba(112,190,199,.2);border-radius:999px;background:rgba(7,29,36,.7);color:#c4dbde;cursor:pointer}
[data-feature-root="overview"] .overview-toolbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin:1.5rem 0 .4rem}
[data-feature-root="overview"] .overview-toolbar [data-observation],[data-feature-root="overview"] .overview-window{margin:0;color:#98b0b4;font-size:.76rem;line-height:1.5}
[data-feature-root="overview"][data-stale="true"] .overview-toolbar [data-observation]{color:#e9c783}
[data-feature-root="overview"] .overview-toolbar button{min-height:44px;border:1px solid var(--line-strong);border-radius:9px;background:rgba(12,49,58,.4);color:#dff8f9;padding:.5rem .9rem;font:inherit;font-size:.78rem;cursor:pointer}
[data-feature-root="overview"] .overview-window{margin-bottom:.8rem}
[data-feature-root="overview"] .overview-lower-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:.85rem;margin-top:.85rem}
[data-feature-root="overview"] .overview-card{margin:1rem 0;padding:clamp(.9rem,2vw,1.2rem);border:1px solid var(--border,#294047);border-radius:15px;background:var(--panel,#0d1d23);overflow:auto}
[data-feature-root="overview"] .overview-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root="overview"] .overview-card h2{margin:.15rem 0;font-size:1.05rem;font-weight:560}
[data-feature-root="overview"] .overview-card p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="overview"] .overview-history{margin-top:.85rem;background:rgba(10,28,35,.82);border-color:rgba(102,188,202,.16)}
@media(max-width:900px){[data-feature-root="overview"] .overview-lower-grid{grid-template-columns:1fr}}
@media(max-width:560px){[data-feature-root="overview"] .quick-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(hover:hover) and (pointer:fine){[data-feature-root="overview"] .quick-actions button:hover{border-color:rgba(88,228,235,.48);background:rgba(18,76,85,.68);color:#f2ffff}}
"""


_CSS += """
[data-feature-root="overview"] .overview-page{max-width:1400px;margin:0 auto;padding:clamp(1rem,3vw,2.5rem);color:var(--text,#edf5f6)}
[data-feature-root="overview"] .overview-stage{min-height:530px;display:grid;grid-template-columns:minmax(140px,.8fr) minmax(340px,1.7fr) minmax(160px,.9fr);align-items:center;gap:clamp(18px,3vw,46px);padding:0 0 clamp(1rem,2vw,1.75rem)}
[data-feature-root="overview"] .overview-rail{display:grid;align-content:center;gap:.65rem;min-width:0}
[data-feature-root="overview"] .overview-readout{min-width:0;padding:1rem 0;border-top:1px solid rgba(117,191,199,.24)}
[data-feature-root="overview"] .overview-readout:last-child{border-bottom:1px solid rgba(117,191,199,.16)}
[data-feature-root="overview"] .overview-readout>span{display:block;color:#b0cbce;font-size:.7rem;font-weight:570;letter-spacing:.08em;text-transform:uppercase}
[data-feature-root="overview"] .overview-readout strong{display:block;margin:.45rem 0 .18rem;color:#efffff;font-size:clamp(1.5rem,2.5vw,2.25rem);font-weight:530;line-height:1.08;letter-spacing:-.045em;font-variant-numeric:tabular-nums}
[data-feature-root="overview"] .overview-readout small{display:block;color:#a1bdc1;font-size:.68rem;line-height:1.45}
[data-feature-root="overview"] .overview-attention[data-attention="true"] strong{color:#e8bf78}
[data-feature-root="overview"] .reactor-presence{min-width:0;display:flex;flex-direction:column;align-items:center;text-align:center}
[data-feature-root="overview"] .reactor-figure{position:relative;width:clamp(300px,34vw,430px);max-width:100%;aspect-ratio:1;display:grid;place-items:center;filter:drop-shadow(0 19px 38px rgba(0,0,0,.38))}
[data-feature-root="overview"] .reactor-figure:before{content:"";position:absolute;inset:13%;border-radius:50%;background:radial-gradient(circle,rgba(71,219,230,.21),rgba(18,111,122,.12) 44%,rgba(8,46,55,.05) 65%,transparent 75%)}
[data-feature-root="overview"] .reactor-figure svg{position:relative;width:100%;height:100%;overflow:visible}
[data-feature-root="overview"] .reactor-dial,[data-feature-root="overview"] .reactor-orbit,[data-feature-root="overview"] .reactor-chamber,[data-feature-root="overview"] .reactor-core{fill:none;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-dial{stroke:rgba(146,203,208,.3);stroke-width:.8;stroke-dasharray:1 3}
[data-feature-root="overview"] .reactor-orbit-outer{stroke:rgba(78,222,231,.8);stroke-width:1.1;stroke-dasharray:2 5}
[data-feature-root="overview"] .reactor-orbit-inner{stroke:rgba(121,232,237,.58);stroke-width:1.1;stroke-dasharray:38 8 4 9}
[data-feature-root="overview"] .reactor-segment{fill:none;stroke:rgba(136,231,235,.72);stroke-width:1;stroke-linecap:round;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-segment-east,[data-feature-root="overview"] .reactor-segment-west{stroke:rgba(103,190,202,.58);stroke-dasharray:1 2}
[data-feature-root="overview"] .reactor-instrument-track{fill:none;stroke:rgba(122,221,227,.24);stroke-width:.7;stroke-dasharray:1 4;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-chamber{fill:rgba(5,26,33,.65);stroke:rgba(138,239,241,.84);stroke-width:1.3;stroke-dasharray:88 10 17 8}
[data-feature-root="overview"] .reactor-iris-blade{fill:rgba(71,207,216,.12);stroke:rgba(146,236,239,.66);stroke-width:.8;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-core{fill:rgba(39,193,204,.08);stroke:rgba(155,245,246,.83);stroke-width:1.2;filter:drop-shadow(0 0 11px rgba(67,222,231,.34))}
[data-feature-root="overview"] .reactor-aperture{fill:rgba(185,255,255,.82);stroke:rgba(255,255,255,.9);stroke-width:.8;filter:drop-shadow(0 0 7px rgba(67,222,231,.72));vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-lens{fill:rgba(43,198,208,.06);stroke:rgba(119,235,239,.46);stroke-width:.8;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-axis{fill:none;stroke:rgba(89,212,222,.34);stroke-width:.9;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-ticks{fill:none;stroke:rgba(160,233,236,.5);stroke-width:1.1;vector-effect:non-scaling-stroke}
[data-feature-root="overview"] .reactor-node{fill:#d8ffff;filter:drop-shadow(0 0 4px rgba(82,229,237,.8))}
[data-feature-root="overview"] .reactor-label{position:absolute;left:50%;top:50%;display:grid;gap:.45rem;transform:translate(-50%,-50%);color:#f0ffff;font:550 clamp(.85rem,1.45vw,1.12rem)/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.2em;text-shadow:0 0 20px rgba(77,230,237,.68);white-space:nowrap}
[data-feature-root="overview"] .reactor-label small{color:#9ce7e9;font-size:.48rem;letter-spacing:.19em}
[data-feature-root="overview"] .reactor-presence h1{margin:-1.7rem 0 0;color:#f2ffff;font-size:clamp(2rem,3.4vw,2.9rem);font-weight:520;line-height:1.1;letter-spacing:-.045em;text-wrap:balance}
[data-feature-root="overview"] .reactor-state{min-height:1.5rem;margin:.5rem 0 .75rem;color:#c1dade;font-size:.78rem;line-height:1.5}
[data-feature-root="overview"] .reactor-connection{width:min(100%,480px);display:grid;grid-template-columns:1fr 1.15fr;gap:.1rem 1rem;padding:.8rem .25rem 0;border-top:1px solid rgba(117,191,199,.19);text-align:left}
[data-feature-root="overview"] .reactor-connection h2{margin:0 0 .2rem;color:#afc9cc;font-size:.66rem;font-weight:620;letter-spacing:.08em;text-transform:uppercase}
[data-feature-root="overview"] .reactor-connection p{margin:.15rem 0;color:#b6cccf;font-size:.66rem;line-height:1.45}
[data-feature-root="overview"] .reactor-connection [data-core-status]{color:#e8f7f7;font-size:.74rem;font-weight:580}
[data-feature-root="overview"] .reactor-connection [data-core-observed]{grid-column:1/-1;color:#95afb3}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="active"] .reactor-orbit-outer{stroke:#efc57c;animation:jarvis-reactor-pulse 1.8s ease-in-out infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="active"] .reactor-core{stroke:#f1d39a;fill:rgba(211,158,67,.1)}
[data-feature-root="overview"] .overview-stage[data-activity="quiet"] .reactor-state{color:#aee0dc}
[data-feature-root="overview"] .overview-stage[data-activity="unknown"] .reactor-state{color:#e8c581}
[data-feature-root="overview"] .overview-stage[data-core-state="unverified"] .reactor-figure{opacity:.52;filter:saturate(.45) drop-shadow(0 10px 22px rgba(0,0,0,.25))}
[data-feature-root="overview"][data-stale="true"] .overview-stage .reactor-dial,[data-feature-root="overview"][data-stale="true"] .overview-stage .reactor-orbit{animation:none!important;transform:none!important}
@keyframes jarvis-reactor-turn{to{transform:rotate(1turn)}}
@keyframes jarvis-reactor-reverse{to{transform:rotate(-1turn)}}
@keyframes jarvis-reactor-pulse{0%,100%{opacity:.62;stroke-width:1.1}50%{opacity:1;stroke-width:2}}
[data-feature-root="overview"] .overview-stage[data-in-viewport="true"][data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-orbit-inner{transform-box:view-box;transform-origin:120px 120px;animation:jarvis-reactor-turn 22s linear infinite}
[data-feature-root="overview"] .overview-stage[data-in-viewport="true"][data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-dial{transform-box:view-box;transform-origin:120px 120px;animation:jarvis-reactor-reverse 36s linear infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="quiet"] .reactor-orbit-inner{animation-duration:44s}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="quiet"] .reactor-dial{animation-duration:72s}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-assistant-state="thinking"] .reactor-orbit-outer{stroke:#8fe7eb;animation:jarvis-reactor-pulse 2.4s ease-in-out infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-assistant-state="listening"] .reactor-orbit-outer{stroke:#efc57c;stroke-dasharray:12 7;animation:jarvis-reactor-pulse 3.2s ease-in-out infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-assistant-state="speaking"] .reactor-orbit-inner{stroke:#a6f0f1;animation-duration:14s}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-assistant-state="error"] .reactor-core{stroke:#e8bf78;fill:rgba(211,158,67,.1)}
[data-feature-root="overview"] .overview-toolbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.65rem 0;border-top:1px solid rgba(117,191,199,.15);border-bottom:1px solid rgba(117,191,199,.15)}
[data-feature-root="overview"] .overview-toolbar [data-observation]{margin:0;color:#a8c2c5;font-size:.72rem;line-height:1.5}
[data-feature-root="overview"] .overview-toolbar button{min-width:92px;min-height:44px;border:1px solid rgba(95,199,208,.3);border-radius:9px;background:rgba(8,36,44,.68);color:#e1f9fa;padding:.5rem .9rem;font:inherit;font-size:.75rem;cursor:pointer}
[data-feature-root="overview"] .overview-toolbar button:disabled{opacity:.55;cursor:wait}
[data-feature-root="overview"] .overview-window{margin:.65rem 0 1rem;color:#9fb8bc;font-size:.68rem;line-height:1.5}
[data-feature-root="overview"] .command-panel{max-width:1000px;margin:1rem auto 1.75rem;padding:1rem clamp(1rem,2.5vw,1.6rem);border:1px solid rgba(88,228,235,.28);border-radius:16px;background:linear-gradient(115deg,rgba(8,27,34,.98),rgba(7,22,29,.97));box-shadow:0 16px 42px rgba(0,0,0,.24),inset 0 1px rgba(222,255,255,.04)}
[data-feature-root="overview"] .command-intro{display:flex;justify-content:space-between;gap:1rem;color:#a9c2c5;font-size:.68rem}
[data-feature-root="overview"] .command-target{max-width:min(52ch,58vw);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;text-align:right}
[data-feature-root="overview"] .command-kicker{color:#9be7ea;font-size:.65rem;font-weight:650;letter-spacing:.13em}
[data-feature-root="overview"] .command-form{display:flex;align-items:stretch;gap:.6rem;margin-top:.65rem;padding:.5rem;border:1px solid rgba(88,228,235,.29);border-radius:12px;background:rgba(3,17,23,.78)}
[data-feature-root="overview"] .command-form textarea{width:100%;min-width:0;min-height:54px;max-height:144px;resize:vertical;padding:.75rem .65rem;border:0;outline:0;background:transparent;color:var(--text,#edf5f6);font:inherit;font-size:1rem;line-height:1.5;caret-color:var(--cyan,#58e4eb)}
[data-feature-root="overview"] .command-form textarea:focus-visible{outline:2px solid var(--cyan,#58e4eb);outline-offset:-2px;border-radius:6px}
[data-feature-root="overview"] .command-form textarea::placeholder{color:#91a9ae}
[data-feature-root="overview"] .command-form button{display:flex;align-items:center;justify-content:center;gap:.65rem;min-width:138px;min-height:54px;padding:.65rem .85rem;border:1px solid rgba(93,228,235,.5);border-radius:9px;background:#146b75;color:#f1ffff;font-size:.78rem;font-weight:650;cursor:pointer}
[data-feature-root="overview"] .command-form button:disabled{opacity:.55;cursor:wait}
[data-feature-root="overview"] .command-form button:focus-visible,[data-feature-root="overview"] .quick-actions button:focus-visible,[data-feature-root="overview"] .overview-toolbar button:focus-visible,[data-feature-root="overview"] .overview-details summary:focus-visible{outline:2px solid var(--cyan,#58e4eb);outline-offset:2px}
[data-feature-root="overview"] #command-hint{margin:.55rem .15rem 0;color:#9ab3b7;font-size:.69rem;line-height:1.5}
[data-feature-root="overview"] .quick-actions{display:flex;flex-wrap:wrap;gap:.45rem;margin-top:.7rem}
[data-feature-root="overview"] .quick-actions button{min-height:44px;padding:.4rem .7rem;border:1px solid rgba(112,190,199,.21);border-radius:8px;background:rgba(7,29,36,.56);color:#c9dfe1;font-size:.7rem;cursor:pointer}
[data-feature-root="overview"] .quick-actions button:first-child{color:#a8edeb;border-color:rgba(88,228,235,.32)}
[data-feature-root="overview"] .overview-details{border-top:1px solid rgba(117,191,199,.19)}
[data-feature-root="overview"] .overview-details>summary{min-height:52px;display:flex;align-items:center;justify-content:space-between;gap:1rem;color:#d7e8e9;font-size:.84rem;font-weight:600;cursor:pointer;list-style:none}
[data-feature-root="overview"] .overview-details>summary::-webkit-details-marker{display:none}
[data-feature-root="overview"] .overview-details>summary:after{content:"";width:7px;height:7px;border-right:1px solid currentColor;border-bottom:1px solid currentColor;transform:rotate(45deg);transition:transform 150ms ease}
[data-feature-root="overview"] .overview-details[open]>summary:after{transform:rotate(225deg)}
[data-feature-root="overview"] .overview-detail-body{padding:.5rem 0 1rem}
[data-feature-root="overview"] .overview-lower-grid{display:grid;grid-template-columns:minmax(0,1.12fr) minmax(280px,.88fr);gap:clamp(1rem,3vw,2.2rem)}
[data-feature-root="overview"] .overview-card{min-width:0;margin:1rem 0;padding:1rem 0;border:0;border-top:1px solid rgba(117,191,199,.19);border-radius:0;background:transparent;overflow:auto}
[data-feature-root="overview"] .overview-heading h2{margin:.2rem 0;color:#e7f5f6;font-size:1rem;font-weight:590}
[data-feature-root="overview"] .overview-card p{color:#a6bdc0;font-size:.73rem;line-height:1.5}
[data-feature-root="overview"] table{width:100%;border-collapse:collapse;margin:.9rem 0;text-align:left;font-size:.72rem}
[data-feature-root="overview"] caption{text-align:left;font-weight:650;padding:.35rem 0}
[data-feature-root="overview"] th,[data-feature-root="overview"] td{padding:.55rem .45rem;border-bottom:1px solid rgba(117,191,199,.14);font-variant-numeric:tabular-nums}
[data-feature-root="overview"] th{color:#b9d0d2;font-weight:580}
[data-feature-root="overview"] td{color:#d6e6e7}
[data-feature-root="overview"] .overview-bars{list-style:none;margin:.5rem 0;padding:0}
[data-feature-root="overview"] .overview-bars li{display:grid;grid-template-columns:minmax(5rem,1fr) minmax(5rem,2fr) auto;gap:.7rem;align-items:center;padding:.4rem 0;color:#b1c7c9;font-size:.68rem}
[data-feature-root="overview"] progress{width:100%;min-height:10px;accent-color:var(--cyan,#58e4eb)}
[data-feature-root="overview"] .overview-facts{display:grid;gap:0;margin:.7rem 0}
[data-feature-root="overview"] .overview-facts div{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;padding:.7rem 0;border-bottom:1px solid rgba(123,197,213,.12)}
[data-feature-root="overview"] dt{color:#9fb8bc;font-size:.75rem}[data-feature-root="overview"] dd{margin:0;color:#e2f2f3;font-weight:600;font-variant-numeric:tabular-nums}
[data-feature-root="overview"] .overview-provenance{color:#9db5b8;font-size:.68rem;line-height:1.5}
[data-feature-root="overview"] .ecosystem-card{margin:1.3rem auto;padding:1rem 0;border-top:1px solid rgba(117,191,199,.22);border-bottom:1px solid rgba(117,191,199,.14)}
[data-feature-root="overview"] .ecosystem-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root="overview"] .ecosystem-heading h2{margin:.25rem 0;color:#e7f5f6;font-size:1rem;font-weight:590}
[data-feature-root="overview"] .ecosystem-heading button{min-height:44px;padding:.55rem .8rem;border:1px solid rgba(88,228,235,.27);border-radius:9px;background:rgba(24,102,111,.16);color:#d8f8fa;font:inherit;font-size:.78rem;cursor:pointer}
[data-feature-root="overview"] .ecosystem-heading button:focus-visible{outline:2px solid var(--cyan,#58e4eb);outline-offset:2px}
[data-feature-root="overview"] .ecosystem-status{margin:.45rem 0;color:#c2d9db;font-size:.8rem;line-height:1.5}
[data-feature-root="overview"] .ecosystem-identities{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin:.7rem 0}
[data-feature-root="overview"] .ecosystem-identities>div{min-width:0;padding:.65rem .75rem;border-left:2px solid rgba(88,228,235,.35);background:rgba(255,255,255,.025)}
[data-feature-root="overview"] .ecosystem-identities h3{margin:0;color:#bfd3d5;font-size:.7rem;font-weight:650}
[data-feature-root="overview"] .ecosystem-identities p,[data-feature-root="overview"] .ecosystem-summary{margin:.25rem 0 0;color:#9db5b8;font-size:.72rem;line-height:1.5}
[data-feature-root="overview"] .handoff-graph{display:grid;gap:.5rem;margin:.8rem 0;padding:0;list-style:none}
[data-feature-root="overview"] .handoff-route{display:grid;grid-template-columns:minmax(6rem,.8fr) minmax(2.2rem,.4fr) minmax(0,1.4fr);align-items:center;gap:.55rem;min-width:0}
[data-feature-root="overview"] .handoff-node{min-width:0;padding:.55rem .65rem;border:1px solid rgba(88,228,235,.2);border-radius:9px;background:rgba(11,35,42,.6)}
[data-feature-root="overview"] .handoff-node strong,[data-feature-root="overview"] .handoff-node small{display:block;overflow-wrap:anywhere}
[data-feature-root="overview"] .handoff-node strong{color:#d8f2f3;font-size:.72rem;font-weight:620}
[data-feature-root="overview"] .handoff-node small{margin-top:.18rem;color:#97b1b5;font-size:.64rem;line-height:1.4}
[data-feature-root="overview"] .handoff-edge{position:relative;height:2px;overflow:hidden;background:rgba(88,228,235,.24)}
[data-feature-root="overview"] .handoff-edge:after{position:absolute;inset:0 auto 0 0;width:40%;content:"";background:#58e4eb;opacity:0;transform:translateX(-110%)}
[data-feature-root="overview"] [data-activity-flow="active"]:is([data-ecosystem-state="current"],[data-ecosystem-state="partial"])[data-in-viewport="true"] .handoff-route[data-has-observed-relation="true"][data-instance-state="running"] .handoff-edge:after{opacity:.9;animation:handoff-observation-flow 1.6s linear infinite}
[data-feature-root="overview"] .ecosystem-provenance{margin:.65rem 0 0;color:#829da2;font-size:.66rem;line-height:1.5}
@keyframes handoff-observation-flow{to{transform:translateX(280%)}}
@media(max-width:980px){
 [data-feature-root="overview"] .overview-stage{grid-template-columns:repeat(2,minmax(0,1fr));grid-template-rows:auto auto;gap:0 1.5rem}
 [data-feature-root="overview"] .reactor-presence{grid-column:1/-1;grid-row:1}
 [data-feature-root="overview"] .overview-rail:first-of-type{grid-column:1;grid-row:2;grid-template-columns:1fr;gap:0}
 [data-feature-root="overview"] .overview-rail:last-child{grid-column:2;grid-row:2;grid-template-columns:1fr;gap:0}
}
@media(max-width:620px){
 [data-feature-root="overview"] .overview-page{padding:1rem 1rem 5.5rem}
 [data-feature-root="overview"] .overview-stage{display:flex;flex-direction:column;gap:1rem;min-height:0;padding-bottom:1.1rem}
 [data-feature-root="overview"] .reactor-presence{order:-1;width:100%}
 [data-feature-root="overview"] .reactor-figure{width:min(82vw,350px)}
 [data-feature-root="overview"] .reactor-presence h1{margin-top:-1.25rem;font-size:clamp(1.9rem,8vw,2.4rem)}
 [data-feature-root="overview"] .reactor-connection{grid-template-columns:1fr;gap:.35rem}
 [data-feature-root="overview"] .reactor-connection [data-core-observed]{grid-column:auto}
 [data-feature-root="overview"] .overview-rail{width:100%;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 1rem}
 [data-feature-root="overview"] .overview-rail:last-child{grid-template-columns:repeat(3,minmax(0,1fr))}
 [data-feature-root="overview"] .overview-readout{padding:.75rem 0}
 [data-feature-root="overview"] .overview-readout strong{font-size:1.5rem}
 [data-feature-root="overview"] .command-form{align-items:stretch;flex-direction:column}
 [data-feature-root="overview"] .command-form button{width:100%}
 [data-feature-root="overview"] .quick-actions{display:flex;flex-wrap:wrap;overflow:visible;gap:.45rem;padding-bottom:.3rem}
 [data-feature-root="overview"] .quick-actions button{flex:1 1 auto;justify-content:center}
 [data-feature-root="overview"] .overview-lower-grid{grid-template-columns:1fr}
 [data-feature-root="overview"] .overview-toolbar{align-items:flex-start}
 [data-feature-root="overview"] .overview-toolbar [data-observation]{max-width:32ch}
 [data-feature-root="overview"] .ecosystem-identities{grid-template-columns:1fr;gap:.45rem}
}
@media(max-width:360px){
 [data-feature-root="overview"] .overview-rail:last-child{grid-template-columns:repeat(2,minmax(0,1fr))}
 [data-feature-root="overview"] .overview-rail:last-child .overview-readout:last-child{grid-column:1/-1}
 [data-feature-root="overview"] .overview-readout>span{font-size:.62rem}
 [data-feature-root="overview"] .overview-readout strong{font-size:1.35rem}
}
@media(hover:hover) and (pointer:fine){[data-feature-root="overview"] .quick-actions button:hover,[data-feature-root="overview"] .overview-toolbar button:hover{border-color:rgba(88,228,235,.52);background:rgba(18,76,85,.45);color:#f2ffff}[data-feature-root="overview"] .command-form button:hover{filter:brightness(1.12)}}
@media(prefers-reduced-motion:reduce){[data-feature-root="overview"] .reactor-dial,[data-feature-root="overview"] .reactor-orbit-inner,[data-feature-root="overview"] .reactor-orbit-outer{animation:none!important;transform:none!important}[data-feature-root="overview"] *{transition-duration:0s!important;transition-delay:0s!important}}
[data-feature-root="overview"] .ecosystem-card:is([data-ecosystem-state="stale"],[data-ecosystem-state="partial"]) .ecosystem-status{color:#dbb66f}
html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .handoff-edge:after{animation:none!important;transform:none!important;opacity:0!important}
@media(prefers-reduced-motion:reduce){[data-feature-root="overview"] .handoff-edge:after{animation:none!important;transform:none!important;opacity:0!important}}
html:not([data-page-visible="true"]) [data-feature-root="overview"] .handoff-edge:after,
[data-feature-root="overview"]:not([data-network-online="true"]) .handoff-edge:after,
[data-feature-root="overview"] [data-ecosystem-card]:not([data-in-viewport="true"]) .handoff-edge:after{animation:none!important;transform:none!important;opacity:0!important}
[data-feature-root="overview"][data-stale="true"] .overview-stage .reactor-orbit-outer{stroke:#dbb66f;opacity:.45}
html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-dial,html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-orbit-inner,html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-orbit-outer{animation:none!important;transform:none!important}
/* A fresh response is necessary, but it is not sufficient while hidden/offline. */
html:not([data-page-visible="true"]) [data-feature-root="overview"] .overview-stage .reactor-dial,
html:not([data-page-visible="true"]) [data-feature-root="overview"] .overview-stage .reactor-orbit,
[data-feature-root="overview"]:not([data-network-online="true"]) .overview-stage .reactor-dial,
[data-feature-root="overview"]:not([data-network-online="true"]) .overview-stage .reactor-orbit{animation:none!important;transform:none!important}
[data-feature-root="overview"] .overview-stage:not([data-in-viewport="true"]) .reactor-dial,
[data-feature-root="overview"] .overview-stage:not([data-in-viewport="true"]) .reactor-orbit{animation:none!important;transform:none!important}
"""

_CSS += """
[data-feature-root="overview"] .command-centre-shell{position:relative;isolation:isolate;overflow:hidden;margin:0 0 clamp(1.25rem,3vw,2.5rem);padding:clamp(.65rem,1.7vw,1.4rem);border:1px solid rgba(88,228,235,.25);border-radius:clamp(18px,2.2vw,30px);background:radial-gradient(ellipse at 50% 22%,rgba(31,146,159,.12),transparent 48%),linear-gradient(145deg,rgba(6,22,29,.96),rgba(8,30,37,.94) 52%,rgba(5,19,26,.98));box-shadow:inset 0 1px rgba(230,255,255,.06),0 24px 64px rgba(0,0,0,.24)}
[data-feature-root="overview"] .command-centre-shell:before{position:absolute;z-index:0;inset:0;content:"";pointer-events:none;background:linear-gradient(90deg,transparent 0,rgba(87,224,232,.055) 50%,transparent 100%),repeating-linear-gradient(0deg,transparent 0 39px,rgba(129,208,214,.035) 40px),repeating-linear-gradient(90deg,transparent 0 39px,rgba(129,208,214,.035) 40px);mask-image:linear-gradient(to bottom,black,transparent 88%)}
[data-feature-root="overview"] .command-centre-shell:after{position:absolute;z-index:0;top:-16rem;left:50%;width:min(72vw,900px);aspect-ratio:1;content:"";pointer-events:none;transform:translateX(-50%);border:1px solid rgba(88,228,235,.08);border-radius:50%;box-shadow:0 0 0 24px rgba(88,228,235,.025),0 0 0 58px rgba(88,228,235,.018),inset 0 0 80px rgba(88,228,235,.025)}
[data-feature-root="overview"] .command-centre-shell>.overview-stage,[data-feature-root="overview"] .command-centre-shell>.command-panel{position:relative;z-index:1}
[data-feature-root="overview"] .command-centre-shell>.overview-stage{min-height:clamp(500px,48vw,650px);padding:clamp(.3rem,1.3vw,1.1rem) clamp(.2rem,1vw,.9rem) 1.4rem;gap:clamp(1rem,2.6vw,3rem)}
[data-feature-root="overview"] .command-centre-shell .reactor-figure{width:clamp(285px,31vw,410px)}
[data-feature-root="overview"] .command-centre-shell .overview-rail{gap:.55rem;align-content:center}
[data-feature-root="overview"] .command-centre-shell .overview-readout{position:relative;overflow:hidden;padding:.9rem 1rem;border:1px solid rgba(112,218,225,.18);border-radius:12px;background:linear-gradient(145deg,rgba(14,47,56,.76),rgba(6,23,30,.8));box-shadow:inset 0 1px rgba(235,255,255,.045),0 10px 24px rgba(0,0,0,.12)}
[data-feature-root="overview"] .command-centre-shell .overview-readout:before{position:absolute;top:0;left:1rem;width:2.4rem;height:1px;content:"";background:rgba(111,234,238,.68)}
[data-feature-root="overview"] .command-centre-shell .overview-readout:last-child{border-bottom:1px solid rgba(112,218,225,.18)}
[data-feature-root="overview"] .command-centre-shell .overview-readout>span{font-size:.65rem;letter-spacing:.11em}
[data-feature-root="overview"] .command-centre-shell .overview-readout strong{margin:.35rem 0;font-size:clamp(1.4rem,2.2vw,2rem)}
[data-feature-root="overview"] .command-centre-shell .overview-readout small{font-size:.66rem}
[data-feature-root="overview"] .command-centre-shell .command-panel{max-width:1050px;margin:0 auto;padding:clamp(1rem,2vw,1.5rem);border-color:rgba(100,231,237,.3);background:linear-gradient(115deg,rgba(5,20,27,.98),rgba(8,31,39,.96));box-shadow:0 18px 38px rgba(0,0,0,.22),inset 0 1px rgba(222,255,255,.05)}
[data-feature-root="overview"] .command-centre-shell .command-form{min-height:54px}
[data-feature-root="overview"] .command-centre-shell .command-form textarea{font-size:1.02rem}
[data-feature-root="overview"] .command-centre-shell .command-intro{align-items:flex-start}
[data-feature-root="overview"] .command-centre-shell .command-target{max-width:62ch;white-space:normal;overflow-wrap:anywhere}
[data-feature-root="overview"] #jarvis-ecosystem-feature-host{min-height:0}
@media(max-width:980px){[data-feature-root="overview"] .command-centre-shell>.overview-stage{min-height:0;padding-inline:.2rem}}
@media(max-width:620px){[data-feature-root="overview"] .command-centre-shell{padding:.55rem;border-radius:18px}[data-feature-root="overview"] .command-centre-shell>.overview-stage{padding:.25rem .45rem 1rem}[data-feature-root="overview"] .command-centre-shell .reactor-figure{width:min(78vw,330px)}[data-feature-root="overview"] .command-centre-shell .command-panel{padding:.9rem}[data-feature-root="overview"] .command-centre-shell .command-intro{flex-direction:column;gap:.35rem}[data-feature-root="overview"] .command-centre-shell .command-target{text-align:left;max-width:100%}}
@media(prefers-reduced-motion:reduce){[data-feature-root="overview"] .command-centre-shell:after{box-shadow:none}}
"""

_MOUNT = r"""function mount(container, api, state, mountScope) {
  function overviewScopeIsCurrent(scope, generation, currentGeneration, stopped) {
    return !stopped && generation === currentGeneration
      && !(scope && scope.signal && scope.signal.aborted)
      && (!scope || typeof scope.isCurrent !== 'function' || scope.isCurrent());
  }
  function projectAssistantPresence(state) {
    return ['listening','thinking','speaking','error'].includes(state) ? state : null;
  }
  function projectNativeEcosystem(snapshot, now, coreVerified) {
    const observation = snapshot && snapshot.observation;
    const observedAt = observation && typeof observation.observed_at === 'string'
      ? Date.parse(observation.observed_at) : NaN;
    const age = now - observedAt;
    if (!observation || !['quiet','observed','partial'].includes(observation.state)
        || !Array.isArray(snapshot.instances) || !Array.isArray(snapshot.teams) || !Array.isArray(snapshot.relations)
        || !Number.isFinite(observedAt)) {
      return {state:'unavailable', instances:[], teams:[], summary:null, active:false};
    }
    const fresh = Boolean(coreVerified && age >= -30000 && age <= 120000);
    const instanceIds = new Set(snapshot.instances
      .filter(instance => instance && typeof instance.id === 'string').map(instance => instance.id));
    const relationEndpoints = new Set();
    const relations = Array.isArray(snapshot.relations) ? snapshot.relations.slice(0,200) : [];
    for (const relation of relations) {
      if (!relation || relation.kind !== 'completed_message'
          || !['current','partial'].includes(relation.state)
          || typeof relation.from !== 'string' || typeof relation.to !== 'string'
          || relation.from === relation.to || !instanceIds.has(relation.from) || !instanceIds.has(relation.to)) continue;
      relationEndpoints.add(relation.from);
      relationEndpoints.add(relation.to);
    }
    const instances = snapshot.instances.filter(instance => instance
      && typeof instance.display_name === 'string' && typeof instance.profile_id === 'string'
      && typeof instance.state === 'string' && typeof instance.stale === 'boolean'
      && Array.isArray(instance.events)).slice(0,12).map(instance => ({
        display_name:instance.display_name, profile_id:instance.profile_id,
        state:instance.state, stale:instance.stale,
        hasObservedRelation:typeof instance.id === 'string' && relationEndpoints.has(instance.id),
        events:instance.events.filter(event => event && typeof event.kind === 'string'
          && typeof event.status === 'string' && typeof event.at === 'string')
          .slice(-20).map(event => ({kind:event.kind, status:event.status, at:event.at,
            duration_ms:event.duration_ms, tool_count:event.tool_count})),
      }));
    const hasVerifiedTeamMembership = fresh && snapshot.schema === 2 && snapshot.pending
      && snapshot.pending.team_membership === 'verified';
    const teams = (hasVerifiedTeamMembership ? snapshot.teams : []).filter(team => team && typeof team.name === 'string')
      .slice(0,8).map(team => ({name:team.name}));
    const active = fresh && instances.some(instance => !instance.stale && instance.state === 'running');
    return {state:!fresh ? 'stale' : observation.state === 'quiet' ? 'empty'
        : observation.state === 'partial' ? 'partial' : 'current',
      instances, teams, summary:snapshot.summary ? {
        completed_executions:snapshot.summary.completed_executions,
        observed_completed_executions:snapshot.summary.observed_completed_executions,
        response_duration_ms:snapshot.summary.response_duration_ms,
        response_duration_coverage:snapshot.summary.response_duration_coverage,
      } : null, active, observedAt:observation.observed_at,
      pending:{team_membership:snapshot.pending && snapshot.pending.team_membership},
      hasVerifiedTeamMembership};
  }

  const root = container.querySelector('[data-feature-root="overview"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const refreshButton = $('[data-refresh]');
  const stage = $('.overview-stage');
  const ecosystemCard = $('[data-ecosystem-card]');
  const handoffGraph = $('[data-handoff-graph]');
  let stopped = false;
  let stageObserver = null;
  let assistantHudObserver = null;
  let lastTurnCounts = null;
  let lastCoreVerified = false;
  let ecosystemObserver = null;
  let ecosystemPollTimer = null;
  let ecosystemGeneration = 0;
  let ecosystemRefreshing = false;
  let ecosystemHasSnapshot = false;
  let lastObservation = null;
  let coreFreshnessTimer = null;
  let coreFreshUntil = 0;
  let lastCoreObservedAt = null;
  let refreshGeneration = 0;
  root.dataset.pageVisible = String(document.visibilityState === 'visible');
  root.dataset.networkOnline = 'checking';
  stage.dataset.inViewport = 'false';
  function node(tag, value) { const item = document.createElement(tag); item.textContent = value; return item; }
  function number(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function format(value) { return value === null ? 'Unknown' : value.toLocaleString(); }
  function time(value) { const parsed = typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'Unknown'; }
  function handoffTime(value) {
    const milliseconds = typeof value === 'string' ? Date.parse(value) : NaN;
    return Number.isFinite(milliseconds) ? new Date(milliseconds).toLocaleString() : 'Unknown time';
  }
  const ecosystemEventLabels = {
    admitted:'Execution admitted', attempt:'Execution attempt', response:'Native response',
    tool_call:'Native tool calls', completed:'Execution completed',
  };
  function renderNativeEcosystem(snapshot, coreVerified) {
    const projection = projectNativeEcosystem(snapshot, Date.now(), coreVerified);
    ecosystemCard.dataset.ecosystemState = projection.state;
    ecosystemCard.dataset.activityFlow = projection.active ? 'active' : 'idle';
    handoffGraph.replaceChildren();
    handoffGraph.hidden = projection.instances.length === 0;
    if (projection.state === 'unavailable') {
      $('[data-ecosystem-status]').textContent = 'Root-observed Expert data is unavailable.';
      $('[data-expert-identity]').textContent = 'Instance names and states are unavailable.';
      $('[data-selected-team]').textContent = 'Team membership is unavailable.';
      $('[data-ecosystem-summary]').textContent = 'No current native instance summary is available.';
      return;
    }
    if (projection.state === 'empty') {
      $('[data-ecosystem-status]').textContent = 'No native Expert instances were observed.';
      $('[data-expert-identity]').textContent = 'No instances in this snapshot.';
      $('[data-selected-team]').textContent = 'No independently verified Team membership is available.';
      $('[data-ecosystem-summary]').textContent = 'No instance counts or durations are available.';
      return;
    }
    $('[data-ecosystem-status]').textContent = projection.state === 'current'
      ? projection.active ? 'Current native snapshot · a named Expert instance is running.'
        : 'Current native Expert snapshot observed.'
      : projection.state === 'partial' ? projection.active
        ? 'Partial native snapshot · a named Expert is running; aggregate coverage is incomplete.'
        : 'Partial native snapshot · some fields or instances may be missing.'
      : 'Showing a historical native snapshot; current state is unverified.';
    const summary = projection.summary || {};
    const observedInstances = number(summary.observed_instances);
    const instanceLabel = observedInstances === null ? `${format(projection.instances.length)} shown`
      : `${format(observedInstances)} observed${observedInstances > projection.instances.length ? `; showing ${format(projection.instances.length)}` : ''}`;
    const instancePlural = observedInstances === 1 || observedInstances === null && projection.instances.length === 1 ? '' : 's';
    $('[data-expert-identity]').textContent = `${instanceLabel} native instance${instancePlural} in this snapshot.`;
    $('[data-selected-team]').textContent = projection.teams.length && projection.hasVerifiedTeamMembership
      ? projection.teams.map(team => team.name).join(', ')
      : 'No independently verified Team membership is available.';
    const observedCompleted = number(summary.observed_completed_executions);
    const completed = number(summary.completed_executions);
    const observedDuration = number(summary.response_duration_ms);
    const durationCoverage = number(summary.response_duration_coverage);
    const parts = [`${instanceLabel} native instance${instancePlural}`];
    if (completed !== null) parts.push(`${format(completed)} completed executions`);
    else if (observedCompleted !== null) parts.push(`${format(observedCompleted)} observed completions; total is partial`);
    if (observedDuration !== null && durationCoverage !== null && durationCoverage > 0) {
      parts.push(`${(observedDuration / 1000).toFixed(1)} s across ${format(durationCoverage)} observed responses`);
    }
    $('[data-ecosystem-summary]').textContent = parts.join(' · ');
    for (const instance of projection.instances) {
      const stateLabel = instance.stale ? 'unknown · stale source'
        : projection.state === 'current' ? instance.state
        : `${instance.state} · ${projection.state} snapshot`;
      const row = document.createElement('li');
      row.className = 'handoff-route';
      row.dataset.instanceState = instance.stale ? 'stale' : instance.state;
      row.dataset.hasObservedRelation = String(instance.hasObservedRelation);
      const source = document.createElement('div');
      source.className = 'handoff-node';
      const sourceLabel = document.createElement('strong');
      sourceLabel.textContent = instance.display_name;
      const sourceTime = document.createElement('small');
      sourceTime.textContent = `${instance.profile_id} · ${stateLabel}`;
      source.append(sourceLabel, sourceTime);
      const edge = document.createElement('span');
      edge.className = 'handoff-edge';
      edge.setAttribute('aria-hidden', 'true');
      const target = document.createElement('div');
      target.className = 'handoff-node';
      const events = Array.isArray(instance.events) ? instance.events : [];
      const latest = events.reduce((best, event) => !best || Date.parse(event.at) > Date.parse(best.at) ? event : best, null);
      const targetLabel = document.createElement('strong');
      targetLabel.textContent = latest ? ecosystemEventLabels[latest.kind] || 'Native event' : 'No event in snapshot';
      const targetState = document.createElement('small');
      targetState.textContent = latest
        ? `${latest.status} · ${handoffTime(latest.at)}`
        : 'No event detail is available for this instance.';
      const details = [targetLabel, targetState];
      if (latest && Number.isSafeInteger(latest.duration_ms) && latest.duration_ms >= 0) {
        const duration = document.createElement('small');
        duration.textContent = `Observed response duration · ${latest.duration_ms} ms`;
        details.push(duration);
      }
      target.append(...details);
      row.append(source, edge, target);
      handoffGraph.append(row);
    }
  }
  function invalidateHandoffs(reason) {
    ecosystemGeneration += 1;
    ecosystemRefreshing = false;
    if (!ecosystemCard) return;
    ecosystemCard.dataset.ecosystemState = reason === 'hidden' || reason === 'offline' || reason === 'stale' ? 'stale' : 'unavailable';
    ecosystemCard.dataset.activityFlow = 'idle';
    if (!ecosystemHasSnapshot) {
      $('[data-expert-identity]').textContent = 'Instance names and states are unavailable.';
      $('[data-selected-team]').textContent = 'Team membership is unavailable.';
      $('[data-ecosystem-summary]').textContent = 'No current native instance summary is available.';
    }
    $('[data-ecosystem-status]').textContent = reason === 'offline'
      ? 'Offline · native Expert activity is unverified.'
      : reason === 'hidden' ? 'Dashboard paused · native Expert activity is unverified.'
      : 'Current native Expert activity is unverified.';
  }
  async function refreshEcosystem() {
    if (stopped || !ecosystemCard || ecosystemRefreshing) return;
    if (document.visibilityState !== 'visible' || navigator.onLine === false
        || root.dataset.coreState !== 'verified' || ecosystemCard.dataset.inViewport !== 'true') {
      if (document.visibilityState !== 'visible' || navigator.onLine === false
          || root.dataset.coreState !== 'verified') invalidateHandoffs(
        navigator.onLine === false ? 'offline' : document.visibilityState !== 'visible' ? 'hidden' : 'stale');
      return;
    }
    const generation = ++ecosystemGeneration;
    ecosystemRefreshing = true;
    try {
      const page = await api.get('/chat/api/ecosystem');
      if (!overviewScopeIsCurrent(mountScope, generation, ecosystemGeneration, stopped)) return;
      const coreVerified = root.dataset.coreState === 'verified'
        && document.visibilityState === 'visible' && navigator.onLine !== false;
      renderNativeEcosystem(page, coreVerified);
      ecosystemHasSnapshot = true;
    } catch (_error) {
      if (overviewScopeIsCurrent(mountScope, generation, ecosystemGeneration, stopped)) {
        invalidateHandoffs('unavailable');
      }
    } finally {
      if (generation === ecosystemGeneration) ecosystemRefreshing = false;
    }
  }
  function renderCounts(counts, coreVerified) {
    lastTurnCounts = counts;
    lastCoreVerified = coreVerified;
    for (const key of ['total','completed','active','failed']) {
      const target = $(`[data-metric="${key}"]`);
      if (target) target.textContent = format(number(counts && counts[key]));
    }
    const failed = number(counts && counts.failed);
    const active = number(counts && counts.active);
    $('[data-metric="failed"]').closest('.overview-readout').dataset.attention = String(failed !== null && failed > 0);
    const stage = $('.overview-stage');
    const activity = $('[data-reactor-state]');
    const assistantState = projectAssistantPresence(document.getElementById('assistant-hud')?.dataset.state);
    stage.dataset.assistantState = assistantState || 'none';
    if (!coreVerified) {
      stage.dataset.coreState = 'unverified';
      stage.dataset.activity = 'unknown';
      activity.textContent = active === null
        ? 'Service observation unavailable; current activity is unverified.'
        : `${format(active)} accepted turn${active === 1 ? '' : 's'} in progress; service observation is unverified.`;
    } else if (assistantState) {
      stage.dataset.coreState = 'verified';
      stage.dataset.activity = assistantState === 'error' ? 'unknown' : 'active';
      activity.textContent = ({
        listening: 'Listening · Jarvis voice input is active.',
        thinking: 'Thinking · Jarvis is responding to an active turn.',
        speaking: 'Speaking · Jarvis is reading a completed reply aloud.',
        error: 'Needs attention · Jarvis reported an interaction error.',
      })[assistantState];
    } else if (active > 0) {
      stage.dataset.coreState = 'verified';
      stage.dataset.activity = 'active';
      activity.textContent = `${format(active)} accepted turn${active === 1 ? '' : 's'} in progress.`;
    } else if (active === null) {
      stage.dataset.coreState = 'verified';
      stage.dataset.activity = 'unknown';
      activity.textContent = 'Service observed · current activity could not be verified.';
    } else {
      stage.dataset.coreState = 'verified';
      stage.dataset.activity = 'quiet';
      activity.textContent = 'Ready · standby. No accepted turns in progress.';
    }
    $('[data-reactor-active-label]').textContent = !coreVerified
      ? 'Service observation unverified' : active === null
      ? 'Current activity unavailable' : active === 1 ? 'Accepted turn in progress' : 'Accepted turns in progress';
  }
  function markCoreStale(reason = 'stale') {
    if (stopped) return;
    lastCoreVerified = false;
    if (coreFreshnessTimer !== null) clearTimeout(coreFreshnessTimer);
    coreFreshnessTimer = null;
    coreFreshUntil = 0;
    root.dataset.coreState = 'unverified';
    root.dataset.stale = 'true';
    const stage = $('.overview-stage');
    stage.dataset.coreState = 'unverified';
    stage.dataset.activity = 'unknown';
    stage.dataset.assistantState = 'none';
    $('[data-core-status]').textContent = reason === 'offline' ? 'Offline · service status unverified'
      : reason === 'hidden' ? 'Dashboard paused · service status unverified'
      : 'Last service observation is stale';
    $('[data-core-readiness]').textContent = 'Current service readiness is unverified.';
    $('[data-core-observed]').textContent = `Observed ${time(lastCoreObservedAt)} · ${reason === 'offline' ? 'offline' : reason === 'hidden' ? 'paused' : 'stale'}`;
    $('[data-reactor-state]').textContent = reason === 'offline' ? 'Device is offline; service activity is unverified.'
      : reason === 'hidden' ? 'Dashboard paused while this page was hidden.'
      : 'Service observation is stale; current activity is unverified.';
    $('[data-reactor-active-label]').textContent = reason === 'offline' ? 'Offline · unverified'
      : reason === 'hidden' ? 'Paused while hidden' : 'Service observation stale';
    invalidateHandoffs(reason);
  }
  function recheckCoreFreshness() {
    if (coreFreshUntil && Date.now() >= coreFreshUntil) markCoreStale();
  }
  function renderCore(core) {
    lastCoreObservedAt = typeof core.observedAt === 'string' ? core.observedAt : null;
    const observedAt = typeof core.observedAt === 'string' ? Date.parse(core.observedAt) : NaN;
    const age = Date.now() - observedAt;
    const verified = core.status === 'process-observed'
      && Number.isFinite(observedAt) && age >= -30000 && age <= 120000;
    coreFreshUntil = verified ? observedAt + 120000 : 0;
    if (coreFreshnessTimer !== null) clearTimeout(coreFreshnessTimer);
    coreFreshnessTimer = verified ? setTimeout(recheckCoreFreshness, Math.max(0, coreFreshUntil - Date.now())) : null;
    root.dataset.coreState = verified ? 'verified' : 'unverified';
    $('[data-core-status]').textContent = verified
      ? 'Service process observed' : core.status === 'process-observed' ? 'Last service observation is stale' : 'Service observation unavailable';
    $('[data-core-readiness]').textContent = verified && core.readiness === 'current-core-witness'
      ? 'Current core witness; functional readiness is not independently verified.'
      : 'Functional readiness is unverified.';
    $('[data-core-observed]').textContent = `Observed ${time(core.observedAt)}${verified ? '' : ' · not current'}`;
    return verified;
  }
  function render(data) {
    const chat = data && data.chat || {}; const stats = chat.statistics || {};
    const window = stats.window || {}; const counts = stats.turnCounts || {};
    const coreVerified = renderCore(data && data.core || {});
    renderCounts(counts, coreVerified);
    lastObservation = time(stats.observedAt);
    root.dataset.stale = 'false';
    if (!coreVerified) root.dataset.stale = 'true';
    $('[data-observation]').textContent = `Owner activity updated ${lastObservation}.`;
    $('[data-window]').textContent = `Window: ${time(window.startAt)} to ${time(window.endAt)} · ${window.timezone === 'UTC' ? 'UTC' : 'timezone unknown'} · ${window.basis || 'Window basis unavailable'}`;
    $('[data-conversation-count]').textContent = format(number(chat.conversationCount));
    const days = Array.isArray(chat.turnCountsByDay) ? chat.turnCountsByDay : [];
    const dayRows = $('[data-day-rows]'); dayRows.replaceChildren();
    for (const day of days) { const row = document.createElement('tr'); row.append(node('th',typeof day.date === 'string' ? day.date : 'Unknown'),node('td',format(number(day.total)))); dayRows.append(row); }
    const duration = stats.duration || {}; const samples = Array.isArray(duration.samples) ? duration.samples : [];
    $('[data-duration-basis]').textContent = duration.basis || 'Elapsed-time basis unavailable.';
    const durationRows = $('[data-duration-rows]'); const durationBars = $('[data-duration-bars]'); durationRows.replaceChildren(); durationBars.replaceChildren();
    const valid = samples.filter(item => item && Number.isSafeInteger(item.durationMs) && item.durationMs >= 0 && typeof item.status === 'string');
    const omitted = number(duration.omittedCount) || 0;
    const maxDuration = Math.max(1,...valid.map(item => item.durationMs));
    for (const sample of valid) {
      const elapsed = `${(sample.durationMs / 1000).toFixed(2)} s`;
      const row = document.createElement('tr'); row.append(node('td',time(sample.acceptedAt)),node('td',sample.status),node('td',elapsed)); durationRows.append(row);
      const barRow = document.createElement('li'); barRow.append(node('span',time(sample.acceptedAt)));
      const bar = document.createElement('progress'); bar.max=maxDuration; bar.value=sample.durationMs; bar.setAttribute('aria-label',`${sample.status} turn elapsed ${elapsed}`);
      barRow.append(bar,node('span',elapsed)); durationBars.append(barRow);
    }
    $('[data-duration-coverage]').textContent = valid.length
      ? `${valid.length} recent terminal turns shown${omitted ? `; ${omitted} omitted from this bounded measurement.` : '.'}`
      : omitted ? `${omitted} terminal-turn duration records were omitted; no valid sample is available.`
      : 'No terminal turn durations were recorded in this window.';
    const mission = data && data.missions || {};
    $('[data-missions]').textContent = mission.state === 'observed' ? format(number(mission.approvedPendingCount)) : 'Unavailable';
    const schedule = data && data.schedules || {};
    $('[data-schedules]').textContent = schedule.state === 'observed' ? format(number(schedule.pausedCount)) : 'Unavailable';
    $('[data-pending-note]').textContent = [mission.reason,schedule.reason].filter(value => typeof value === 'string').join(' ');
    const discovery = data && data.resources && data.resources.discovery || {};
    $('[data-resource-state]').textContent = `Discovery: ${discovery.state || 'unknown'}; last observed ${time(discovery.observedAt)}.`;
    $('[data-resource-skills]').textContent = format(number(discovery.counts && discovery.counts.native_skills));
    $('[data-resource-profiles]').textContent = format(number(discovery.counts && discovery.counts.internal_profiles));
    const dispatch = data && data.resources && data.resources.dispatch || {};
    $('[data-dispatch]').textContent = `Dispatched identities: ${dispatch.state === 'observed' ? format(number(dispatch.count)) : 'Unavailable'}. ${dispatch.reason || ''}`;
    refreshEcosystem();
  }
  if (typeof IntersectionObserver === 'function') {
    stageObserver = new IntersectionObserver((entries) => {
      if (stopped) return;
      for (const entry of entries) {
        if (entry.target === stage) stage.dataset.inViewport = String(entry.isIntersecting && entry.intersectionRatio > 0);
      }
    }, {threshold: 0});
    stageObserver.observe(stage);
    ecosystemObserver = new IntersectionObserver((entries) => {
      if (stopped) return;
      for (const entry of entries) {
        if (entry.target === ecosystemCard) {
          ecosystemCard.dataset.inViewport = String(entry.isIntersecting && entry.intersectionRatio > 0);
          if (entry.isIntersecting && entry.intersectionRatio > 0) refreshEcosystem();
          else invalidateHandoffs('offscreen');
        }
      }
    }, {threshold: 0});
    ecosystemObserver.observe(ecosystemCard);
  } else {
    ecosystemCard.dataset.inViewport = 'true';
  }
  const assistantHud = document.getElementById('assistant-hud');
  if (assistantHud && typeof MutationObserver === 'function') {
    assistantHudObserver = new MutationObserver(() => {
      if (lastTurnCounts !== null && lastCoreVerified) renderCounts(lastTurnCounts, true);
    });
    assistantHudObserver.observe(assistantHud, {attributes:true, attributeFilter:['data-state']});
  }
  async function refresh() {
    if (stopped) return;
    if (document.visibilityState !== 'visible' || navigator.onLine === false) {
      root.dataset.networkOnline = 'false';
      markCoreStale(navigator.onLine === false ? 'offline' : 'hidden');
      return;
    }
    refreshButton.disabled = true;
    const generation = ++refreshGeneration;
    $('[data-observation]').textContent = 'Refreshing measured owner data…';
    try {
      const data = await api.get('/chat/api/overview');
      if (!stopped && generation === refreshGeneration && document.visibilityState === 'visible' && navigator.onLine !== false) {
        root.dataset.networkOnline = 'true';
        render(data);
      } else if (!stopped && generation === refreshGeneration) {
        root.dataset.networkOnline = 'false';
        markCoreStale(navigator.onLine === false ? 'offline' : 'hidden');
      }
    }
    catch (_error) {
      if (!stopped && generation === refreshGeneration) {
        root.dataset.stale = 'true';
        markCoreStale();
        $('[data-observation]').textContent = lastObservation
          ? `Refresh failed · showing the last successful observation from ${lastObservation}.`
          : 'Current measured owner data is unavailable; no earlier observation is cached.';
      }
    }
    finally { if (generation === refreshGeneration) refreshButton.disabled = false; }
  }
  const commandForm = $('[data-command-form]');
  const commandInput = $('#command-input');
  async function submitCommand(event) {
    event.preventDefault();
    const text = commandInput.value.trim();
    if (!text || stopped) return;
    const button = commandForm.querySelector('button[type="submit"]');
    if (button.disabled) return;
    button.disabled = true; commandInput.disabled = true;
    try { await api.command(text); commandInput.value = ''; }
    catch (_error) { $('[data-observation]').textContent = 'Command not sent. Your text remains here; try again or open Chat.'; }
    finally { button.disabled = false; commandInput.disabled = false; }
  }
  commandForm.addEventListener('submit',submitCommand);
  const newConversation = $('[data-new-conversation]');
  async function startNewConversation() {
    newConversation.disabled = true;
    try { await api.newConversation(); }
    catch (_error) { $('[data-observation]').textContent = 'Jarvis could not start a new conversation. Open Chats to try again.'; }
    finally { newConversation.disabled = false; }
  }
  newConversation.addEventListener('click',startNewConversation);
  const promptButtons = [...root.querySelectorAll('[data-command-prompt]')];
  const promptHandlers = new Map();
  for (const button of promptButtons) {
    const handler = () => {
      commandInput.value = button.dataset.commandPrompt;
      commandInput.dispatchEvent(new Event('input',{bubbles:true}));
      commandInput.focus({preventScroll:true});
      commandInput.setSelectionRange(commandInput.value.length,commandInput.value.length);
    };
    promptHandlers.set(button,handler);
    button.addEventListener('click',handler);
  }
  commandInput.addEventListener('keydown',event => {
    if (event.key === 'Enter' && !event.shiftKey && !event.isComposing) {
      event.preventDefault(); commandForm.requestSubmit();
    }
  });
  commandInput.addEventListener('input',() => {
    commandInput.style.height='auto'; commandInput.style.height=`${Math.min(commandInput.scrollHeight,144)}px`;
  });
  function onVisibilityChange() {
    refreshGeneration += 1;
    root.dataset.pageVisible = String(document.visibilityState === 'visible');
    if (document.visibilityState !== 'visible') {
      root.dataset.networkOnline = 'false';
      markCoreStale('hidden');
    } else if (navigator.onLine === false) {
      root.dataset.networkOnline = 'false';
      markCoreStale('offline');
    } else {
      root.dataset.networkOnline = 'checking';
      refresh();
    }
  }
  function onNetworkChange() {
    refreshGeneration += 1;
    if (navigator.onLine === false) {
      root.dataset.networkOnline = 'false';
      markCoreStale('offline');
    } else {
      root.dataset.networkOnline = 'checking';
      if (document.visibilityState === 'visible') refresh();
    }
  }
  refreshButton.addEventListener('click',refresh); refresh();
  ecosystemPollTimer = window.setInterval(refreshEcosystem, 5000);
  document.addEventListener('visibilitychange',onVisibilityChange);
  window.addEventListener('offline',onNetworkChange);
  window.addEventListener('online',onNetworkChange);
  return function cleanup() { stopped=true; ecosystemGeneration += 1; ecosystemRefreshing=false; if (ecosystemPollTimer !== null) clearInterval(ecosystemPollTimer); if (ecosystemObserver) ecosystemObserver.disconnect(); ecosystemCard.dataset.inViewport='false'; ecosystemCard.dataset.activityFlow='idle'; if (coreFreshnessTimer !== null) clearTimeout(coreFreshnessTimer); if (stageObserver) stageObserver.disconnect(); if (assistantHudObserver) assistantHudObserver.disconnect(); stage.dataset.inViewport='false'; refreshButton.disabled=false; commandForm.querySelector('button[type="submit"]').disabled=false; commandInput.disabled=false; newConversation.disabled=false; refreshButton.removeEventListener('click',refresh); commandForm.removeEventListener('submit',submitCommand); newConversation.removeEventListener('click',startNewConversation); document.removeEventListener('visibilitychange',onVisibilityChange); window.removeEventListener('offline',onNetworkChange); window.removeEventListener('online',onNetworkChange); for (const button of promptButtons) button.removeEventListener('click',promptHandlers.get(button)); };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="overview",
    nav_label="Overview",
    title="Overview",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(("GET", "/chat/api/overview"), ("GET", "/chat/api/ecosystem")),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
