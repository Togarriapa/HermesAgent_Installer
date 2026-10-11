"""Small, accessible overview fragment for the existing protected owner projection."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class="overview-page" aria-labelledby="overview-title">
  <section class="overview-stage" data-activity="unknown" aria-label="Jarvis activity">
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
          <circle class="reactor-chamber" cx="120" cy="120" r="75"/>
          <circle class="reactor-core" cx="120" cy="120" r="57"/>
          <circle class="reactor-lens" cx="120" cy="120" r="43"/>
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
    <div class="command-intro"><span class="command-kicker">MESSAGE JARVIS</span><span>Private workspace</span></div>
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
[data-feature-root="overview"] .overview-page{max-width:1240px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root="overview"] .command-heading{max-width:820px;margin:0 0 1.2rem}
[data-feature-root="overview"] .command-heading h1{margin:.2rem 0;font-size:clamp(1.8rem,4vw,2.8rem);font-weight:560;letter-spacing:-.04em}
[data-feature-root="overview"] .command-heading>p:last-child{max-width:720px;margin:.5rem 0;color:var(--muted,#9bafb4);font-size:.94rem;line-height:1.6}
[data-feature-root="overview"] .overview-page header>p:last-child,[data-feature-root="overview"] .overview-page>p,[data-feature-root="overview"] .overview-card p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="overview"] .overview-eyebrow{color:var(--accent,#83d9ca);font-size:.72rem;letter-spacing:.13em}
[data-feature-root="overview"] .command-panel{position:relative;margin:1.4rem 0;padding:clamp(1rem,2.5vw,1.5rem);border:1px solid rgba(88,228,235,.28);border-radius:18px;background:radial-gradient(ellipse at 4% 0%,rgba(38,181,193,.15),transparent 55%),linear-gradient(140deg,rgba(13,43,52,.94),rgba(8,23,30,.96));box-shadow:inset 0 1px rgba(255,255,255,.05),0 18px 48px rgba(0,0,0,.17)}
[data-feature-root="overview"] .command-intro{display:flex;align-items:center;justify-content:space-between;gap:1rem;color:#8eaaaf;font-size:.72rem}
[data-feature-root="overview"] .command-kicker,.data-source-mark{color:#83d9de;font:600 .65rem/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em}
[data-feature-root="overview"] .command-form{display:flex;align-items:flex-end;gap:.6rem;margin-top:.65rem;padding:.55rem;border:1px solid rgba(88,228,235,.34);border-radius:14px;background:rgba(3,17,23,.74)}
[data-feature-root="overview"] .command-form textarea{width:100%;min-width:0;min-height:50px;max-height:144px;resize:vertical;padding:.8rem .65rem;border:0;outline:0;background:transparent;color:var(--text,#edf5f6);font:inherit;font-size:1rem;line-height:1.5}
[data-feature-root="overview"] .command-form textarea::placeholder{color:#708b91}
[data-feature-root="overview"] .command-form button{display:flex;align-items:center;justify-content:center;gap:.7rem;min-width:144px;min-height:48px;padding:.65rem .85rem;border:1px solid rgba(93,228,235,.55);border-radius:10px;background:linear-gradient(135deg,#168895,#12626e);color:#efffff;font-size:.82rem;font-weight:650;cursor:pointer}
[data-feature-root="overview"] .command-form button:disabled{opacity:.55;cursor:wait}
[data-feature-root="overview"] #command-hint{margin:.6rem .2rem 0;color:#819ca1;font-size:.72rem;line-height:1.55}
[data-feature-root="overview"] .quick-actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}
[data-feature-root="overview"] .quick-actions button{display:flex;align-items:center;gap:.5rem;min-height:44px;padding:.45rem .8rem;border-color:rgba(112,190,199,.2);border-radius:999px;background:rgba(7,29,36,.7);color:#c4dbde;font-size:.76rem;cursor:pointer;transition:background-color 140ms ease,border-color 140ms ease,color 140ms ease}
[data-feature-root="overview"] .overview-toolbar{display:flex;justify-content:space-between;align-items:center;gap:1rem;margin:1.5rem 0 .4rem}
[data-feature-root="overview"] .overview-toolbar .overview-eyebrow{margin:0 0 .3rem}
[data-feature-root="overview"] .overview-toolbar [data-observation], [data-feature-root="overview"] .overview-window{margin:0;color:#98b0b4;font-size:.76rem;line-height:1.5}
[data-feature-root="overview"][data-stale="true"] .overview-toolbar [data-observation]{color:#e9c783}
[data-feature-root="overview"] .overview-toolbar button{min-height:44px;border:1px solid var(--line-strong);border-radius:9px;background:rgba(12,49,58,.4);color:#dff8f9;padding:.5rem .9rem;font:inherit;font-size:.78rem;cursor:pointer}
[data-feature-root="overview"] .overview-window{margin-bottom:.8rem}
[data-feature-root="overview"] .core-summary{display:grid;grid-template-columns:minmax(0,1fr) minmax(180px,auto);align-items:center;gap:.2rem 1rem;margin:.8rem 0;border-color:rgba(112,190,199,.16);background:rgba(9,27,34,.72)}
[data-feature-root="overview"] .core-summary .overview-heading{grid-row:1 / span 3}
[data-feature-root="overview"] .core-summary p{margin:.1rem 0;text-align:right;font-size:.74rem}
[data-feature-root="overview"] .measure-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem}
[data-feature-root="overview"] .measure-card{min-width:0;display:grid;gap:.55rem;padding:1rem 1.1rem;border:1px solid rgba(102,188,202,.18);border-radius:14px;background:linear-gradient(145deg,rgba(15,40,48,.84),rgba(8,24,31,.88));box-shadow:inset 0 1px rgba(255,255,255,.035)}
[data-feature-root="overview"] .measure-card span{color:#9eb7ba;font-size:.75rem}
[data-feature-root="overview"] .measure-card strong{color:#e8fbfc;font-size:clamp(1.5rem,2.7vw,2.15rem);font-weight:560;font-variant-numeric:tabular-nums;letter-spacing:-.04em}
[data-feature-root="overview"] .measure-card small{color:#789398;font-size:.67rem}
[data-feature-root="overview"] .measure-primary{border-color:rgba(88,228,235,.34);background:radial-gradient(ellipse at top right,rgba(48,176,189,.14),transparent 66%),linear-gradient(145deg,rgba(15,48,57,.9),rgba(8,24,31,.88))}
[data-feature-root="overview"] .measure-attention[data-attention="true"] strong{color:#e9c783}
[data-feature-root="overview"] .overview-lower-grid{display:grid;grid-template-columns:minmax(0,1.15fr) minmax(300px,.85fr);gap:.85rem;margin-top:.85rem}
[data-feature-root="overview"] .overview-card{margin:1rem 0;padding:clamp(.9rem,2vw,1.2rem);border:1px solid var(--border,#294047);border-radius:15px;background:var(--panel,#0d1d23);overflow:auto}
[data-feature-root="overview"] .overview-lower-grid .overview-card{margin:0;background:linear-gradient(145deg,rgba(15,40,48,.84),rgba(8,24,31,.88));border-color:rgba(102,188,202,.18)}
[data-feature-root="overview"] .overview-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root="overview"] .overview-heading .overview-eyebrow{margin:0 0 .25rem}
[data-feature-root="overview"] .overview-card h2{margin:.15rem 0;font-size:1.05rem;font-weight:560}
[data-feature-root="overview"] button{min-height:42px;border:1px solid var(--border,#38515a);border-radius:9px;background:transparent;color:inherit;padding:.45rem .8rem;font:inherit}
[data-feature-root="overview"] button:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root="overview"] table{width:100%;border-collapse:collapse;margin:1rem 0;text-align:left}
[data-feature-root="overview"] caption{text-align:left;font-weight:650;padding:.35rem 0}
[data-feature-root="overview"] th,[data-feature-root="overview"] td{padding:.5rem;border-bottom:1px solid var(--border,#294047);font-variant-numeric:tabular-nums}
[data-feature-root="overview"] .overview-bars{list-style:none;margin:.5rem 0;padding:0}
[data-feature-root="overview"] .overview-bars li{display:grid;grid-template-columns:minmax(5rem,1fr) minmax(5rem,2fr) auto;gap:.7rem;align-items:center;padding:.3rem 0}
[data-feature-root="overview"] progress{width:100%;accent-color:var(--accent,#83d9ca)}
[data-feature-root="overview"] .overview-facts{display:grid;gap:.35rem;margin:.9rem 0}
[data-feature-root="overview"] .overview-facts div{display:flex;justify-content:space-between;align-items:baseline;gap:1rem;padding:.75rem 0;border-bottom:1px solid rgba(123,197,213,.12)}
[data-feature-root="overview"] dt{color:var(--muted,#9bafb4);font-size:.78rem}[data-feature-root="overview"] dd{margin:0;color:#e3f5f6;font-weight:600;font-variant-numeric:tabular-nums}
[data-feature-root="overview"] .overview-provenance{color:#819ca1;font-size:.72rem;line-height:1.55}
[data-feature-root="overview"] .overview-history{margin-top:.85rem;background:rgba(10,28,35,.82);border-color:rgba(102,188,202,.16)}
@media(max-width:900px){[data-feature-root="overview"] .measure-grid{grid-template-columns:repeat(2,minmax(0,1fr))}[data-feature-root="overview"] .overview-lower-grid{grid-template-columns:1fr}}
@media(max-width:560px){[data-feature-root="overview"] .overview-page{padding:1rem 1rem 5.5rem}[data-feature-root="overview"] .command-form{align-items:stretch;flex-direction:column}[data-feature-root="overview"] .command-form button{width:100%}[data-feature-root="overview"] .quick-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}[data-feature-root="overview"] .quick-actions button{justify-content:flex-start;padding-inline:.65rem;font-size:.69rem}[data-feature-root="overview"] .overview-facts div{align-items:flex-start;flex-direction:column;gap:.25rem}[data-feature-root="overview"] .core-summary{grid-template-columns:1fr}[data-feature-root="overview"] .core-summary .overview-heading{grid-row:auto}[data-feature-root="overview"] .core-summary p{text-align:left}}
@media(hover:hover) and (pointer:fine){[data-feature-root="overview"] .command-form button{transition:filter 140ms ease,border-color 140ms ease}[data-feature-root="overview"] .command-form button:hover{filter:brightness(1.13);border-color:var(--cyan)}[data-feature-root="overview"] .quick-actions button:hover{border-color:rgba(88,228,235,.48);background:rgba(18,76,85,.68);color:#f2ffff}}
@media(prefers-reduced-motion:reduce){[data-feature-root="overview"] .quick-actions button,[data-feature-root="overview"] .command-form button{transition:none}}
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
[data-feature-root="overview"] .reactor-chamber{fill:rgba(5,26,33,.65);stroke:rgba(138,239,241,.84);stroke-width:1.3;stroke-dasharray:88 10 17 8}
[data-feature-root="overview"] .reactor-core{fill:rgba(39,193,204,.08);stroke:rgba(155,245,246,.83);stroke-width:1.2;filter:drop-shadow(0 0 11px rgba(67,222,231,.34))}
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
[data-feature-root="overview"] .overview-stage[data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-orbit-inner{transform-box:view-box;transform-origin:120px 120px;animation:jarvis-reactor-turn 22s linear infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-dial{transform-box:view-box;transform-origin:120px 120px;animation:jarvis-reactor-reverse 36s linear infinite}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="quiet"] .reactor-orbit-inner{animation-duration:44s}
[data-feature-root="overview"] .overview-stage[data-core-state="verified"][data-activity="quiet"] .reactor-dial{animation-duration:72s}
[data-feature-root="overview"] .overview-toolbar{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.65rem 0;border-top:1px solid rgba(117,191,199,.15);border-bottom:1px solid rgba(117,191,199,.15)}
[data-feature-root="overview"] .overview-toolbar [data-observation]{margin:0;color:#a8c2c5;font-size:.72rem;line-height:1.5}
[data-feature-root="overview"] .overview-toolbar button{min-width:92px;min-height:44px;border:1px solid rgba(95,199,208,.3);border-radius:9px;background:rgba(8,36,44,.68);color:#e1f9fa;padding:.5rem .9rem;font:inherit;font-size:.75rem;cursor:pointer}
[data-feature-root="overview"] .overview-toolbar button:disabled{opacity:.55;cursor:wait}
[data-feature-root="overview"] .overview-window{margin:.65rem 0 1rem;color:#9fb8bc;font-size:.68rem;line-height:1.5}
[data-feature-root="overview"] .command-panel{max-width:1000px;margin:1rem auto 1.75rem;padding:1rem clamp(1rem,2.5vw,1.6rem);border:1px solid rgba(88,228,235,.28);border-radius:16px;background:linear-gradient(115deg,rgba(8,27,34,.98),rgba(7,22,29,.97));box-shadow:0 16px 42px rgba(0,0,0,.24),inset 0 1px rgba(222,255,255,.04)}
[data-feature-root="overview"] .command-intro{display:flex;justify-content:space-between;gap:1rem;color:#a9c2c5;font-size:.68rem}
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
}
@media(max-width:360px){
 [data-feature-root="overview"] .overview-rail:last-child{grid-template-columns:repeat(2,minmax(0,1fr))}
 [data-feature-root="overview"] .overview-rail:last-child .overview-readout:last-child{grid-column:1/-1}
 [data-feature-root="overview"] .overview-readout>span{font-size:.62rem}
 [data-feature-root="overview"] .overview-readout strong{font-size:1.35rem}
}
@media(hover:hover) and (pointer:fine){[data-feature-root="overview"] .quick-actions button:hover,[data-feature-root="overview"] .overview-toolbar button:hover{border-color:rgba(88,228,235,.52);background:rgba(18,76,85,.45);color:#f2ffff}[data-feature-root="overview"] .command-form button:hover{filter:brightness(1.12)}}
@media(prefers-reduced-motion:reduce){html:not([data-jarvis-motion="full"]) [data-feature-root="overview"] .reactor-dial,html:not([data-jarvis-motion="full"]) [data-feature-root="overview"] .reactor-orbit-inner,html:not([data-jarvis-motion="full"]) [data-feature-root="overview"] .reactor-orbit-outer{animation:none!important;transform:none!important}html:not([data-jarvis-motion="full"]) [data-feature-root="overview"] *{transition-duration:0s!important;transition-delay:0s!important}}
@media(prefers-reduced-motion:reduce){html[data-jarvis-motion="full"] [data-feature-root="overview"] .overview-stage[data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-orbit-inner{animation:jarvis-reactor-turn 22s linear infinite!important}html[data-jarvis-motion="full"] [data-feature-root="overview"] .overview-stage[data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"]) .reactor-dial{animation:jarvis-reactor-reverse 36s linear infinite!important}}
[data-feature-root="overview"][data-stale="true"] .overview-stage .reactor-orbit-outer{stroke:#dbb66f;opacity:.45}
html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-dial,html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-orbit-inner,html[data-jarvis-motion="reduce"] [data-feature-root="overview"] .reactor-orbit-outer{animation:none!important;transform:none!important}
"""

_MOUNT = r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="overview"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const refreshButton = $('[data-refresh]');
  let stopped = false;
  let lastObservation = null;
  let coreFreshnessTimer = null;
  let coreFreshUntil = 0;
  let lastCoreObservedAt = null;
  function node(tag, value) { const item = document.createElement(tag); item.textContent = value; return item; }
  function number(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function format(value) { return value === null ? 'Unknown' : value.toLocaleString(); }
  function time(value) { const parsed = typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'Unknown'; }
  function renderCounts(counts, coreVerified) {
    for (const key of ['total','completed','active','failed']) {
      const target = $(`[data-metric="${key}"]`);
      if (target) target.textContent = format(number(counts && counts[key]));
    }
    const failed = number(counts && counts.failed);
    const active = number(counts && counts.active);
    $('[data-metric="failed"]').closest('.overview-readout').dataset.attention = String(failed !== null && failed > 0);
    const stage = $('.overview-stage');
    const activity = $('[data-reactor-state]');
    if (!coreVerified) {
      stage.dataset.coreState = 'unverified';
      stage.dataset.activity = 'unknown';
      activity.textContent = active === null
        ? 'Service observation unavailable; current activity is unverified.'
        : `${format(active)} accepted turn${active === 1 ? '' : 's'} in progress; service observation is unverified.`;
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
  function markCoreStale() {
    if (stopped) return;
    if (coreFreshnessTimer !== null) clearTimeout(coreFreshnessTimer);
    coreFreshnessTimer = null;
    coreFreshUntil = 0;
    root.dataset.coreState = 'unverified';
    root.dataset.stale = 'true';
    const stage = $('.overview-stage');
    stage.dataset.coreState = 'unverified';
    stage.dataset.activity = 'unknown';
    $('[data-core-status]').textContent = 'Last service observation is stale';
    $('[data-core-readiness]').textContent = 'Current service readiness is unverified.';
    $('[data-core-observed]').textContent = `Observed ${time(lastCoreObservedAt)} · stale`;
    $('[data-reactor-state]').textContent = 'Service observation is stale; current activity is unverified.';
    $('[data-reactor-active-label]').textContent = 'Service observation stale';
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
  }
  async function refresh() {
    if (stopped) return;
    refreshButton.disabled = true;
    $('[data-observation]').textContent = 'Refreshing measured owner data…';
    try { const data = await api.get('/chat/api/overview'); if (!stopped) render(data); }
    catch (_error) {
      if (!stopped) {
        root.dataset.stale = 'true';
        markCoreStale();
        $('[data-observation]').textContent = lastObservation
          ? `Refresh failed · showing the last successful observation from ${lastObservation}.`
          : 'Current measured owner data is unavailable; no earlier observation is cached.';
      }
    }
    finally { refreshButton.disabled = false; }
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
  refreshButton.addEventListener('click',refresh); refresh();
  document.addEventListener('visibilitychange',recheckCoreFreshness);
  return function cleanup() { stopped=true; if (coreFreshnessTimer !== null) clearTimeout(coreFreshnessTimer); refreshButton.disabled=false; commandForm.querySelector('button[type="submit"]').disabled=false; commandInput.disabled=false; newConversation.disabled=false; refreshButton.removeEventListener('click',refresh); commandForm.removeEventListener('submit',submitCommand); newConversation.removeEventListener('click',startNewConversation); document.removeEventListener('visibilitychange',recheckCoreFreshness); for (const button of promptButtons) button.removeEventListener('click',promptHandlers.get(button)); };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="overview",
    nav_label="Overview",
    title="Overview",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(("GET", "/chat/api/overview"),),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
