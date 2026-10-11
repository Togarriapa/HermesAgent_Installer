"""Small, accessible overview fragment for the existing protected owner projection."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class="overview-page" aria-labelledby="overview-title">
  <header class="command-heading"><p class="overview-eyebrow">JARVIS · COMMAND CENTRE</p><h1 id="overview-title">What needs your attention?</h1>
    <p>One assistant for your conversations, missions and tools. Internal experts and Teams help Jarvis prepare work; Skills are reusable capabilities.</p></header>
  <section class="command-panel" aria-labelledby="command-title">
    <div class="command-intro"><span class="command-kicker">YOUR COMMAND</span><span>Private owner workspace</span></div>
    <form data-command-form class="command-form">
      <label class="visually-hidden" for="command-input">Ask Jarvis</label>
      <textarea id="command-input" name="command" rows="1" maxlength="8000" placeholder="Ask Jarvis anything…" autocomplete="off" autocapitalize="sentences" inputmode="text" enterkeyhint="send" aria-describedby="command-hint"></textarea>
      <button type="submit" aria-label="Send command to Jarvis"><span>Send to Jarvis</span><span aria-hidden="true">↑</span></button>
    </form>
    <p id="command-hint">Enter to send · Shift + Enter for a new line. Suggestions fill the message and wait for you to send. Mission starts and final actions keep their approval rules.</p>
    <div class="quick-actions" aria-label="Suggested commands">
      <button type="button" data-new-conversation><span aria-hidden="true">＋</span> New conversation</button>
      <button type="button" data-command-prompt="Review my pending missions and explain what is awaiting execution."><span aria-hidden="true">◇</span> Review pending missions</button>
      <button type="button" data-command-prompt="Summarize my recent Jarvis activity and its available source evidence."><span aria-hidden="true">⌁</span> Summarize recent activity</button>
      <button type="button" data-command-prompt="Help me find the right installed skill or tool for this task: "><span aria-hidden="true">⌘</span> Find a skill or tool</button>
      <button type="button" data-command-prompt="Review the current status of my configured integrations and report anything unavailable. Do not change their configuration."><span aria-hidden="true">↗</span> Check integrations</button>
    </div>
  </section>
  <div class="overview-toolbar"><div><p class="overview-eyebrow">OWNER OBSERVATIONS</p><p data-observation role="status" aria-live="polite">Loading measured data…</p></div><button type="button" data-refresh>Refresh</button></div>
  <p class="overview-window" data-window></p>
  <section class="measure-grid" aria-label="Measured turn outcomes">
    <article class="measure-card measure-primary"><span>Accepted in window</span><strong data-metric="total">Unknown</strong><small>Owned Jarvis turns</small></article>
    <article class="measure-card"><span>Completed</span><strong data-metric="completed">Unknown</strong><small>Observed terminal state</small></article>
    <article class="measure-card"><span>Active</span><strong data-metric="active">Unknown</strong><small>Current accepted work</small></article>
    <article class="measure-card measure-attention"><span>Failed</span><strong data-metric="failed">Unknown</strong><small>Observed terminal state</small></article>
  </section>
  <section class="overview-card core-summary" aria-labelledby="overview-core-heading">
    <div class="overview-heading"><div><p class="overview-eyebrow">SERVICE WITNESS</p><h2 id="overview-core-heading">Core service</h2></div><span class="data-source-mark">OWNER PROJECTION</span></div>
    <p data-core-status role="status" aria-live="polite">Checking verified status</p>
    <p data-core-readiness>Functional readiness has not been verified.</p>
    <p data-core-observed>No verified observation time</p>
  </section>
  <div class="overview-lower-grid">
    <section class="overview-card" aria-labelledby="overview-duration-title">
      <div class="overview-heading"><div><p class="overview-eyebrow">TURN TIMING</p><h2 id="overview-duration-title">Recent elapsed time</h2></div><span class="data-source-mark">MEASURED</span></div>
      <p data-duration-basis>Loading duration coverage…</p>
      <ol class="overview-bars" data-duration-bars aria-label="Recent turn durations"></ol>
      <table><caption>Recent terminal turns</caption><thead><tr><th scope="col">Accepted</th><th scope="col">Outcome</th><th scope="col">Elapsed</th></tr></thead>
        <tbody data-duration-rows></tbody></table>
      <p data-duration-coverage></p>
    </section>
    <section class="overview-card" aria-labelledby="overview-work-title">
      <div class="overview-heading"><div><p class="overview-eyebrow">CURRENT QUEUE</p><h2 id="overview-work-title">Work &amp; resources</h2></div></div>
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
    <div class="overview-heading"><div><p class="overview-eyebrow">SEVEN DAY WINDOW</p><h2 id="overview-history-title">Accepted turns by day</h2></div></div>
    <table><caption>UTC dates and accepted owned turns</caption><thead><tr><th scope="col">Date</th><th scope="col">Turns</th></tr></thead>
      <tbody data-day-rows></tbody></table>
  </section>
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

_MOUNT = r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="overview"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const refreshButton = $('[data-refresh]');
  let stopped = false;
  let lastObservation = null;
  function node(tag, value) { const item = document.createElement(tag); item.textContent = value; return item; }
  function number(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function format(value) { return value === null ? 'Unknown' : value.toLocaleString(); }
  function time(value) { const parsed = typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'Unknown'; }
  function renderCounts(counts) {
    for (const key of ['total','completed','active','failed']) {
      const target = $(`[data-metric="${key}"]`);
      if (target) target.textContent = format(number(counts && counts[key]));
    }
    $('[data-metric="failed"]').closest('.measure-card').dataset.attention = String(number(counts && counts.failed) > 0);
  }
  function render(data) {
    const chat = data && data.chat || {}; const stats = chat.statistics || {};
    const window = stats.window || {}; const counts = stats.turnCounts || {};
    renderCounts(counts);
    lastObservation = time(stats.observedAt);
    root.dataset.stale = 'false';
    $('[data-observation]').textContent = `Source: protected owner turn store · observed ${lastObservation}.`;
    $('[data-window]').textContent = `Window: ${time(window.startAt)} to ${time(window.endAt)} · ${window.timezone === 'UTC' ? 'UTC' : 'timezone unknown'} · ${window.basis || 'Window basis unavailable'}`;
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
    catch (_error) { $('[data-observation]').textContent = 'Jarvis could not start a new conversation. Use Sessions in Conversations to retry.'; }
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
  return function cleanup() { stopped=true; refreshButton.disabled=false; commandForm.querySelector('button[type="submit"]').disabled=false; commandInput.disabled=false; newConversation.disabled=false; refreshButton.removeEventListener('click',refresh); commandForm.removeEventListener('submit',submitCommand); newConversation.removeEventListener('click',startNewConversation); for (const button of promptButtons) button.removeEventListener('click',promptHandlers.get(button)); };
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
