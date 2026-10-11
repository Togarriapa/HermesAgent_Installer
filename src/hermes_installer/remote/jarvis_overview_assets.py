"""Small, accessible overview fragment for the existing protected owner projection."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class="overview-page" aria-labelledby="overview-title">
  <header><p class="overview-eyebrow">MEASURED OWNER DATA</p><h1 id="overview-title">Overview</h1>
    <p>Turn status and elapsed time from your owned Jarvis store.</p></header>
  <p data-observation role="status" aria-live="polite">Loading the measured window…</p>
  <section class="overview-card" aria-labelledby="overview-turns-title">
    <div class="overview-heading"><h2 id="overview-turns-title">Turn outcomes</h2>
      <button type="button" data-refresh>Refresh</button></div>
    <p data-window></p><ul class="overview-bars" data-status-bars aria-label="Turn counts by status"></ul>
    <table><caption>Turn counts in the measured window</caption><thead><tr><th scope="col">Status</th><th scope="col">Count</th></tr></thead>
      <tbody data-status-rows></tbody></table>
    <table><caption>Daily accepted turns, UTC</caption><thead><tr><th scope="col">Date</th><th scope="col">Turns</th></tr></thead>
      <tbody data-day-rows></tbody></table>
  </section>
  <section class="overview-card" aria-labelledby="overview-duration-title">
    <h2 id="overview-duration-title">Recent turn elapsed time</h2>
    <p data-duration-basis>Loading duration coverage…</p>
    <ol class="overview-bars" data-duration-bars aria-label="Recent turn durations"></ol>
    <table><caption>Recent terminal turns</caption><thead><tr><th scope="col">Accepted</th><th scope="col">Outcome</th><th scope="col">Elapsed</th></tr></thead>
      <tbody data-duration-rows></tbody></table>
    <p data-duration-coverage></p>
  </section>
  <section class="overview-card" aria-labelledby="overview-pending-title"><h2 id="overview-pending-title">Pending work</h2>
    <dl><div><dt>Approved missions awaiting execution</dt><dd data-missions>Unavailable</dd></div>
      <div><dt>Paused schedules</dt><dd data-schedules>Unavailable</dd></div></dl>
    <p data-pending-note></p>
  </section>
  <section class="overview-card" aria-labelledby="overview-resources-title"><h2 id="overview-resources-title">Resources</h2>
    <p data-resource-state>Discovery status unavailable.</p>
    <ul data-resource-counts></ul><p data-dispatch>Dispatched identity count unavailable.</p>
  </section>
</section>"""

_CSS = """
[data-feature-root="overview"] .overview-page{max-width:980px;margin:0 auto;padding:clamp(1rem,3vw,2rem);color:var(--text,#edf5f6)}
[data-feature-root="overview"] .overview-page header>p:last-child,[data-feature-root="overview"] .overview-page>p,[data-feature-root="overview"] .overview-card p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="overview"] .overview-eyebrow{color:var(--accent,#83d9ca);font-size:.72rem;letter-spacing:.13em}
[data-feature-root="overview"] .overview-page h1{font-size:clamp(1.8rem,4vw,2.5rem);margin:.3rem 0}
[data-feature-root="overview"] .overview-card{margin:1rem 0;padding:clamp(.9rem,2vw,1.2rem);border:1px solid var(--border,#294047);border-radius:15px;background:var(--panel,#0d1d23);overflow:auto}
[data-feature-root="overview"] .overview-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root="overview"] .overview-card h2{font-size:1.05rem}
[data-feature-root="overview"] button{min-height:42px;border:1px solid var(--border,#38515a);border-radius:9px;background:transparent;color:inherit;padding:.45rem .8rem;font:inherit}
[data-feature-root="overview"] button:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root="overview"] table{width:100%;border-collapse:collapse;margin:1rem 0;text-align:left}
[data-feature-root="overview"] caption{text-align:left;font-weight:650;padding:.35rem 0}
[data-feature-root="overview"] th,[data-feature-root="overview"] td{padding:.5rem;border-bottom:1px solid var(--border,#294047);font-variant-numeric:tabular-nums}
[data-feature-root="overview"] .overview-bars{list-style:none;margin:.5rem 0;padding:0}
[data-feature-root="overview"] .overview-bars li{display:grid;grid-template-columns:minmax(5rem,1fr) minmax(5rem,2fr) auto;gap:.7rem;align-items:center;padding:.3rem 0}
[data-feature-root="overview"] progress{width:100%;accent-color:var(--accent,#83d9ca)}
[data-feature-root="overview"] dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:.75rem}
[data-feature-root="overview"] dl div{padding:.7rem;border-radius:9px;background:rgba(255,255,255,.035)}
[data-feature-root="overview"] dt{color:var(--muted,#9bafb4);font-size:.82rem}[data-feature-root="overview"] dd{margin:.35rem 0 0}
"""

_MOUNT = r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="overview"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const refreshButton = $('[data-refresh]');
  let stopped = false;
  function node(tag, value) { const item = document.createElement(tag); item.textContent = value; return item; }
  function number(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function format(value) { return value === null ? 'Unknown' : value.toLocaleString(); }
  function time(value) { const parsed = typeof value === 'string' ? Date.parse(value) : NaN; return Number.isFinite(parsed) ? new Date(parsed).toLocaleString() : 'Unknown'; }
  function renderCounts(counts) {
    const labels = [['active','Active'],['completed','Completed'],['failed','Failed'],['cancelled','Cancelled'],['unknown','Other or unknown']];
    const rows = $('[data-status-rows]'); const bars = $('[data-status-bars]');
    rows.replaceChildren(); bars.replaceChildren();
    const values = labels.map(([key,label]) => [key,label,number(counts && counts[key])]);
    const max = Math.max(1,...values.map(item => item[2] || 0));
    for (const [key,label,value] of values) {
      const row = document.createElement('tr'); row.append(node('th',label),node('td',format(value))); rows.append(row);
      const barRow = document.createElement('li'); barRow.append(node('span',label));
      const bar = document.createElement('progress'); bar.max=max; bar.value=value || 0; bar.setAttribute('aria-label',`${label}: ${format(value)}`);
      barRow.append(bar,node('span',format(value))); bars.append(barRow);
    }
  }
  function render(data) {
    const chat = data && data.chat || {}; const stats = chat.statistics || {};
    const window = stats.window || {}; const counts = stats.turnCounts || {};
    renderCounts(counts);
    $('[data-observation]').textContent = `Observed ${time(stats.observedAt)}. Counts cover ${window.timezone === 'UTC' ? 'UTC' : 'an unknown timezone'} turns accepted during the stated window.`;
    $('[data-window]').textContent = `${time(window.startAt)} to ${time(window.endAt)} · ${window.basis || 'Window basis unavailable'}`;
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
    const countsNode = $('[data-resource-counts]'); countsNode.replaceChildren();
    const resourceLabels = [['native_skills','Discovered native skills'],['internal_profiles','Discovered internal profiles'],['source_profiles_preserved','Preserved source profiles'],['other_declarations_preserved','Preserved other declarations']];
    for (const [key,label] of resourceLabels) { const li=node('li',`${label}: ${format(number(discovery.counts && discovery.counts[key]))}`); countsNode.append(li); }
    const dispatch = data && data.resources && data.resources.dispatch || {};
    $('[data-dispatch]').textContent = `Dispatched identities: ${dispatch.state === 'observed' ? format(number(dispatch.count)) : 'Unavailable'}. ${dispatch.reason || ''}`;
  }
  async function refresh() {
    if (stopped) return;
    refreshButton.disabled = true;
    $('[data-observation]').textContent = 'Refreshing measured owner data…';
    try { const data = await api.get('/chat/api/overview'); if (!stopped) render(data); }
    catch (_error) { if (!stopped) $('[data-observation]').textContent = 'The measured overview is temporarily unavailable.'; }
    finally { if (!stopped) refreshButton.disabled = false; }
  }
  refreshButton.addEventListener('click',refresh); refresh();
  return function cleanup() { stopped=true; refreshButton.removeEventListener('click',refresh); };
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
