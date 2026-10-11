"""Owner-only Runtime & Logs detail for the protected Jarvis feature shell.

The view consumes only the existing owner event feed and exact-turn event/usage
routes. Hermes' current public projection does not identify tool families, so
browser activity is explicitly unavailable instead of inferred from tool events.
"""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class=\"runtime-page\" aria-labelledby=\"runtime-title\">
  <header class=\"runtime-heading\"><p class=\"runtime-eyebrow\">RUNTIME · PRIVATE ACTIVITY</p>
    <h1 id=\"runtime-title\">Runtime &amp; Logs</h1>
    <p>Recorded Hermes events from your owned Jarvis turns. Event text, tool arguments and results are not exposed here.</p>
  </header>
  <div class=\"runtime-grid\">
    <section class=\"runtime-card\" aria-labelledby=\"runtime-state-title\">
      <p class=\"runtime-eyebrow\">SELECTED TURN</p><h2 id=\"runtime-state-title\">Recorded status</h2>
      <label class=\"runtime-label\" for=\"runtime-turn\">Choose an owned turn with recorded activity</label>
      <select id=\"runtime-turn\" data-turn aria-describedby=\"runtime-note\"><option value=\"\">Loading recorded turns…</option></select>
      <dl class=\"runtime-summary\"><div><dt>Turn outcome</dt><dd data-outcome>Not recorded</dd></div>
        <div><dt>Recovery</dt><dd>Not established by this event feed</dd></div></dl>
      <p class=\"runtime-note\" data-note id=\"runtime-note\" role=\"status\" aria-live=\"polite\">Loading owner activity…</p>
    </section>
    <section class=\"runtime-card\" aria-labelledby=\"browser-state-title\">
      <p class=\"runtime-eyebrow\">BROWSER TOOL</p><h2 id=\"browser-state-title\">Activity status</h2>
      <p class=\"runtime-unavailable\" data-browser>Unavailable: Hermes activity stream does not provide verified browser-tool attribution.</p>
      <p class=\"runtime-note\">Generic tool events are not enough to identify browser use. No browser controls or screenshots are available in this view.</p>
    </section>
  </div>
  <section class=\"runtime-card\" aria-labelledby=\"runtime-usage-title\">
    <div class=\"runtime-card-heading\"><div><p class=\"runtime-eyebrow\">HERMES COUNTERS</p><h2 id=\"runtime-usage-title\">Usage snapshot</h2></div>
      <button type=\"button\" data-refresh>Refresh</button></div>
    <div class=\"runtime-usage-chart\" data-usage-chart role=\"group\" aria-label=\"Reported token counters for this session snapshot\"></div>
    <p class=\"runtime-empty\" data-usage-chart-empty hidden>No supported token counter was reported for this snapshot.</p>
    <dl class=\"runtime-usage\" data-usage><div><dt>Usage</dt><dd>Unavailable</dd></div></dl>
    <p class=\"runtime-note\">Counters are session-cumulative snapshots and may overlap; they are not added together. Billed cost is unknown because this event feed does not report it.</p>
  </section>
  <section class=\"runtime-card\" aria-labelledby=\"runtime-insights-title\">
    <div class=\"runtime-card-heading\"><div><p class=\"runtime-eyebrow\">MEASURED IN THIS TURN</p><h2 id=\"runtime-insights-title\">Status and duration</h2></div></div>
    <div class=\"runtime-insights-grid\">
      <section aria-labelledby=\"runtime-status-chart-title\"><h3 id=\"runtime-status-chart-title\">Recorded event statuses</h3>
        <ul class=\"runtime-chart-list\" data-status-chart></ul>
        <p class=\"runtime-empty\" data-status-empty hidden>No status events are recorded.</p></section>
      <section aria-labelledby=\"runtime-duration-chart-title\"><h3 id=\"runtime-duration-chart-title\">Reported durations</h3>
        <dl class=\"runtime-duration-stats\"><div><dt>Measured events</dt><dd data-duration-count>0</dd></div>
          <div><dt>Median</dt><dd data-duration-median>Unknown</dd></div><div><dt>Longest</dt><dd data-duration-max>Unknown</dd></div></dl>
        <ol class=\"runtime-chart-list\" data-duration-chart></ol>
        <p class=\"runtime-empty\" data-duration-empty hidden>No durations were reported for this turn.</p>
        <p class=\"runtime-note\">Each bar is a reported event duration. Event durations may overlap and are never summed.</p></section>
    </div>
    <p class=\"runtime-note\" data-insights-note>Status counts and duration statistics summarize the loaded event page; older event pages are excluded when present.</p>
  </section>
  <section class=\"runtime-card\" aria-labelledby=\"runtime-events-title\">
    <div class=\"runtime-card-heading\"><div><p class=\"runtime-eyebrow\">AUTHENTIC EVENT TIMELINE</p><h2 id=\"runtime-events-title\">Turn events</h2></div></div>
    <ol class=\"runtime-events\" data-events aria-live=\"polite\"></ol>
    <p class=\"runtime-empty\" data-empty hidden>No native events were recorded for this turn.</p>
  </section>
</section>"""

_CSS = """
[data-feature-root=\"activity\"] .runtime-page{max-width:1040px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"activity\"] .runtime-heading{margin-bottom:1.25rem}
[data-feature-root=\"activity\"] .runtime-heading h1{margin:.35rem 0;font-size:clamp(1.8rem,3vw,2.55rem)}
[data-feature-root=\"activity\"] .runtime-heading p:last-child,[data-feature-root=\"activity\"] .runtime-note{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root=\"activity\"] .runtime-eyebrow{margin:0 0 .35rem;color:var(--accent,#83d9ca);font-size:.7rem;letter-spacing:.13em;font-weight:700}
[data-feature-root=\"activity\"] .runtime-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}
[data-feature-root=\"activity\"] .runtime-card{min-width:0;border:1px solid var(--border,#294047);border-radius:16px;background:var(--panel,#0d1d23);padding:clamp(.9rem,2vw,1.2rem);margin:1rem 0}
[data-feature-root=\"activity\"] .runtime-card h2{font-size:1.05rem;margin:.25rem 0 .9rem}
[data-feature-root=\"activity\"] .runtime-card-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root=\"activity\"] .runtime-label,[data-feature-root=\"activity\"] .runtime-summary dt,[data-feature-root=\"activity\"] .runtime-usage dt{font-size:.78rem;color:var(--muted,#9bafb4)}
[data-feature-root=\"activity\"] select{display:block;width:100%;min-height:44px;margin:.45rem 0 1rem;padding:.55rem;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;font:inherit}
[data-feature-root=\"activity\"] button{min-height:42px;padding:.5rem .8rem;border:1px solid var(--border,#38515a);border-radius:9px;background:transparent;color:inherit;font:inherit;cursor:pointer}
[data-feature-root=\"activity\"] button:focus-visible,[data-feature-root=\"activity\"] select:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root=\"activity\"] .runtime-summary,[data-feature-root=\"activity\"] .runtime-usage{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.6rem;margin:.5rem 0}
[data-feature-root=\"activity\"] .runtime-summary div,[data-feature-root=\"activity\"] .runtime-usage div{min-width:0;padding:.65rem;border-radius:10px;background:rgba(255,255,255,.035)}
[data-feature-root=\"activity\"] .runtime-summary dd,[data-feature-root=\"activity\"] .runtime-usage dd{margin:.25rem 0 0;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
[data-feature-root=\"activity\"] .runtime-insights-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1.25rem}
[data-feature-root=\"activity\"] .runtime-insights-grid h3{margin:.3rem 0 .7rem;font-size:.9rem}
[data-feature-root=\"activity\"] .runtime-chart-list{display:grid;gap:.45rem;list-style:none;margin:.5rem 0;padding:0}
[data-feature-root=\"activity\"] .runtime-chart-list li{display:grid;grid-template-columns:minmax(90px,.7fr) minmax(60px,1fr) auto;gap:.6rem;align-items:center;font-size:.78rem}
[data-feature-root=\"activity\"] .runtime-chart-list progress{display:block;width:100%;height:.7rem;accent-color:var(--accent,#83d9ca)}
[data-feature-root=\"activity\"] .runtime-chart-value{font-variant-numeric:tabular-nums;color:var(--muted,#9bafb4)}
[data-feature-root=\"activity\"] .runtime-duration-stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.4rem;margin:.4rem 0}
[data-feature-root=\"activity\"] .runtime-duration-stats div{padding:.5rem;border-radius:8px;background:rgba(255,255,255,.035)}
[data-feature-root=\"activity\"] .runtime-duration-stats dt{font-size:.7rem;color:var(--muted,#9bafb4)}
[data-feature-root=\"activity\"] .runtime-duration-stats dd{margin:.2rem 0 0;font-variant-numeric:tabular-nums}
[data-feature-root=\"activity\"] .runtime-usage-chart{display:grid;gap:.5rem;margin:.75rem 0}
[data-feature-root=\"activity\"] .runtime-usage-chart:empty{display:none}
[data-feature-root=\"activity\"] .runtime-usage-chart li{display:grid;grid-template-columns:minmax(100px,.65fr) minmax(80px,1fr) auto;gap:.6rem;align-items:center;font-size:.78rem}
[data-feature-root=\"activity\"] .runtime-usage-chart progress{display:block;width:100%;height:.75rem;accent-color:var(--accent,#83d9ca)}
[data-feature-root=\"activity\"] .runtime-usage-chart ul{display:grid;gap:.45rem;list-style:none;margin:0;padding:0}
[data-feature-root=\"activity\"] .runtime-unavailable{padding:.75rem;border-left:3px solid var(--muted,#9bafb4);background:rgba(255,255,255,.035);line-height:1.5}
[data-feature-root=\"activity\"] .runtime-events{list-style:none;margin:0;padding:0}
[data-feature-root=\"activity\"] .runtime-events li{display:grid;grid-template-columns:minmax(130px,1fr) minmax(90px,.6fr) minmax(130px,1fr);gap:.65rem;padding:.8rem .15rem;border-top:1px solid var(--border,#20373e);align-items:start}
[data-feature-root=\"activity\"] .runtime-event-type{font-weight:650}
[data-feature-root=\"activity\"] .runtime-meta,[data-feature-root=\"activity\"] .runtime-empty{font-size:.82rem;color:var(--muted,#9bafb4);overflow-wrap:anywhere}
[data-feature-root=\"activity\"] [hidden]{display:none!important}
@media(max-width:680px){[data-feature-root=\"activity\"] .runtime-grid{grid-template-columns:1fr}[data-feature-root=\"activity\"] .runtime-events li{grid-template-columns:1fr auto}[data-feature-root=\"activity\"] .runtime-events li .runtime-meta:last-child{grid-column:1/-1}}
@media(max-width:680px){[data-feature-root=\"activity\"] .runtime-insights-grid{grid-template-columns:1fr}}
"""

_MOUNT = r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="activity"]') || container;
  const select = root.querySelector('[data-turn]');
  const eventsNode = root.querySelector('[data-events]');
  const usageNode = root.querySelector('[data-usage]');
  const usageChartNode = root.querySelector('[data-usage-chart]');
  const usageChartEmptyNode = root.querySelector('[data-usage-chart-empty]');
  const statusChartNode = root.querySelector('[data-status-chart]');
  const statusEmptyNode = root.querySelector('[data-status-empty]');
  const durationChartNode = root.querySelector('[data-duration-chart]');
  const durationEmptyNode = root.querySelector('[data-duration-empty]');
  const durationCountNode = root.querySelector('[data-duration-count]');
  const durationMedianNode = root.querySelector('[data-duration-median]');
  const durationMaxNode = root.querySelector('[data-duration-max]');
  const insightsNoteNode = root.querySelector('[data-insights-note]');
  const outcomeNode = root.querySelector('[data-outcome]');
  const emptyNode = root.querySelector('[data-empty]');
  const noteNode = root.querySelector('[data-note]');
  const refreshButton = root.querySelector('[data-refresh]');
  let stopped = false;
  let refreshing = false;
  let selectedTurn = '';
  let requestVersion = 0;
  const labels = Object.freeze({
    'tool.start': 'Tool started', 'tool.complete': 'Tool returned', 'tool.generating': 'Tool preparing',
    'status.update': 'Status update', 'subagent.spawn_requested': 'Delegation queued',
    'subagent.start': 'Delegation started', 'subagent.progress': 'Delegation progress',
    'subagent.thinking': 'Delegation thinking', 'subagent.tool': 'Delegated tool activity',
    'subagent.complete': 'Delegation completed', 'approval': 'Approval requested',
    'approval.cancelled': 'Approval cancelled', 'request.cancel': 'Request cancelled',
    'todo.updated': 'Task list updated', 'session.usage': 'Usage observed',
    'message.complete': 'Turn completion observed'
  });
  const counterLabels = Object.freeze([
    ['input', 'Input tokens'], ['output', 'Output tokens'], ['reasoning', 'Reasoning tokens'],
    ['prompt', 'Prompt tokens'], ['completion', 'Completion tokens'], ['total', 'Total tokens'],
    ['calls', 'Calls'], ['compressions', 'Compressions'], ['context_used', 'Context used'],
    ['context_max', 'Context maximum'], ['cache_hit_pct', 'Cache hit percent'],
    ['cache_read', 'Cache read'], ['cache_write', 'Cache write'], ['active_subagents', 'Active subagents']
  ]);
  function node(tag, value, className) {
    const item = document.createElement(tag);
    if (className) item.className = className;
    item.textContent = value;
    return item;
  }
  function formatDuration(milliseconds) {
    const rounded = Math.round(milliseconds * 10) / 10;
    if (rounded >= 1000) {
      return `${(rounded / 1000).toFixed(2).replace(/0+$/, '').replace(/\.$/, '')} s`;
    }
    return `${rounded} ms`;
  }
  function validId(value) {
    return typeof value === 'string' && /^[A-Za-z0-9_-]{24,80}$/.test(value);
  }
  function validEvents(value) {
    return Array.isArray(value) && value.every(event => event && typeof event === 'object'
      && Object.prototype.hasOwnProperty.call(labels, event.type) && typeof event.status === 'string'
      && event.status.length <= 32 && Number.isSafeInteger(event.sequence));
  }
  function renderUsage(data) {
    usageNode.replaceChildren();
    usageChartNode.replaceChildren();
    const usage = data && data.usage && typeof data.usage === 'object' ? data.usage : null;
    if (!usage) {
      usageNode.append(node('div', 'No usage snapshot was recorded for this turn.'));
      usageChartEmptyNode.hidden = false;
      return;
    }
    for (const [key, label] of counterLabels) {
      const raw = usage[key];
      const value = Number.isSafeInteger(raw) && raw >= 0 ? String(raw) : 'Not reported';
      const row = document.createElement('div');
      row.append(node('dt', label), node('dd', value));
      usageNode.append(row);
    }
    const cost = document.createElement('div');
    cost.append(node('dt', 'Billed cost'), node('dd', 'Unknown'));
    usageNode.append(cost);

    // Prefer one total counter. Without it, show the input/output pair; never add
    // aliases, component counters, or repeated snapshots together.
    let tokenRows = [];
    if (Number.isSafeInteger(usage.total) && usage.total >= 0) {
      tokenRows = [['total', 'Total tokens']];
    } else {
      tokenRows = [['input', 'Input tokens'], ['output', 'Output tokens']]
        .filter(([key]) => Number.isSafeInteger(usage[key]) && usage[key] >= 0);
      if (!tokenRows.length) {
        tokenRows = [['prompt', 'Prompt tokens'], ['completion', 'Completion tokens']]
          .filter(([key]) => Number.isSafeInteger(usage[key]) && usage[key] >= 0);
      }
    }
    usageChartEmptyNode.hidden = tokenRows.length !== 0;
    if (tokenRows.length) {
      const list = document.createElement('ul');
      const maximum = Math.max(1, ...tokenRows.map(([key]) => usage[key]));
      for (const [key, label] of tokenRows) {
        const value = usage[key];
        const row = document.createElement('li');
        const bar = document.createElement('progress');
        bar.max = maximum;
        bar.value = value;
        bar.setAttribute('aria-label', `${label}: ${value}`);
        row.append(node('span', label), bar, node('span', String(value), 'runtime-chart-value'));
        list.append(row);
      }
      usageChartNode.append(list);
    }
  }
  function renderInsights(events, hasOlderEvents) {
    statusChartNode.replaceChildren();
    durationChartNode.replaceChildren();
    insightsNoteNode.textContent = hasOlderEvents
      ? 'Statistics summarize the latest loaded event page only; older events remain outside this chart.'
      : 'Statistics summarize recorded events returned for the selected owner turn.';
    const statusCounts = new Map();
    for (const event of events) statusCounts.set(event.status, (statusCounts.get(event.status) || 0) + 1);
    const statuses = [...statusCounts.keys()].sort((left, right) =>
      statusCounts.get(right) - statusCounts.get(left) || left.localeCompare(right));
    statusEmptyNode.hidden = statuses.length !== 0;
    const maxStatusCount = Math.max(1, ...statuses.map(status => statusCounts.get(status)));
    for (const status of statuses) {
      const count = statusCounts.get(status);
      const row = document.createElement('li');
      const bar = document.createElement('progress');
      bar.max = maxStatusCount;
      bar.value = count;
      bar.setAttribute('aria-label', `${status}: ${count} events`);
      row.append(node('span', status), bar, node('span', String(count), 'runtime-chart-value'));
      statusChartNode.append(row);
    }

    const measured = events.filter(event => Number.isSafeInteger(event.duration_ms)
      && event.duration_ms >= 0).map(event => ({type: event.type, status: event.status, duration: event.duration_ms}));
    durationCountNode.textContent = String(measured.length);
    durationChartNode.replaceChildren();
    durationEmptyNode.hidden = measured.length !== 0;
    if (!measured.length) {
      durationMedianNode.textContent = 'Unknown';
      durationMaxNode.textContent = 'Unknown';
      return;
    }
    const ordered = [...measured].sort((left, right) => left.duration - right.duration);
    const middle = Math.floor(ordered.length / 2);
    const median = ordered.length % 2
      ? ordered[middle].duration
      : (ordered[middle - 1].duration + ordered[middle].duration) / 2;
    const maximum = ordered[ordered.length - 1].duration;
    durationMedianNode.textContent = formatDuration(median);
    durationMaxNode.textContent = formatDuration(maximum);
    const visible = [...measured].sort((left, right) => right.duration - left.duration).slice(0, 8);
    const scale = Math.max(1, maximum);
    for (const item of visible) {
      const row = document.createElement('li');
      const label = `${labels[item.type]} · ${item.status}`;
      const bar = document.createElement('progress');
      bar.max = scale;
      bar.value = item.duration;
      bar.setAttribute('aria-label', `${label}: ${formatDuration(item.duration)}`);
      row.append(node('span', label), bar, node('span', formatDuration(item.duration), 'runtime-chart-value'));
      durationChartNode.append(row);
    }
  }
  function renderEvents(events) {
    eventsNode.replaceChildren();
    for (const event of events) {
      const row = document.createElement('li');
      row.append(node('span', labels[event.type], 'runtime-event-type'));
      row.append(node('span', event.status, 'runtime-meta'));
      const details = [];
      if (Number.isSafeInteger(event.duration_ms) && event.duration_ms >= 0) details.push(`${event.duration_ms} ms`);
      if (typeof event.observed_at === 'number' && Number.isFinite(event.observed_at)) {
        details.push(new Date(event.observed_at * 1000).toLocaleString());
      }
      row.append(node('span', details.join(' · ') || 'Recorded', 'runtime-meta'));
      eventsNode.append(row);
    }
    emptyNode.hidden = events.length !== 0;
  }
  function renderTurns(items) {
    const counts = new Map();
    const newest = new Map();
    for (const item of items) {
      if (!item || !validId(item.turnId) || typeof item.observed_at !== 'number'
          || !Number.isFinite(item.observed_at)) continue;
      counts.set(item.turnId, (counts.get(item.turnId) || 0) + 1);
      if (!newest.has(item.turnId) || newest.get(item.turnId) < item.observed_at) {
        newest.set(item.turnId, item.observed_at);
      }
    }
    const turnIds = [...counts.keys()].sort((left, right) => newest.get(right) - newest.get(left));
    select.replaceChildren();
    if (!turnIds.length) {
      select.append(node('option', 'No turns with recorded activity', ''));
      select.value = '';
      return '';
    }
    for (const [index, turnId] of turnIds.entries()) {
      const option = node('option', `Turn ${index + 1} · ${new Date(newest.get(turnId) * 1000).toLocaleString()} · ${counts.get(turnId)} recent event${counts.get(turnId) === 1 ? '' : 's'}`);
      option.value = turnId;
      select.append(option);
    }
    const next = turnIds.includes(selectedTurn) ? selectedTurn : turnIds[0];
    select.value = next;
    return next;
  }
  async function loadTurn(turnId, version) {
    const [activity, usage] = await Promise.all([
      api.get(`/chat/api/turns/${encodeURIComponent(turnId)}/activity`),
      api.get(`/chat/api/turns/${encodeURIComponent(turnId)}/usage`)
    ]);
    if (stopped || version !== requestVersion) return;
    if (!activity || activity.turnId !== turnId || !validEvents(activity.events)) {
      throw new Error('turn activity unavailable');
    }
    renderEvents(activity.events);
    renderInsights(activity.events, Boolean(activity.nextBefore));
    renderUsage(usage);
    const completed = [...activity.events].reverse().find(event => event.type === 'message.complete');
    outcomeNode.textContent = completed ? completed.status : 'Not recorded';
    noteNode.textContent = activity.nextBefore
      ? 'Showing the latest recorded events for this owner turn. Older event pages are not exposed in this view.'
      : 'Showing the recorded events for this owner turn. Event text and tool results are not retained.';
  }
  async function refresh() {
    if (stopped || refreshing) return;
    refreshing = true;
    const version = ++requestVersion;
    refreshButton.disabled = true;
    try {
      const page = await api.get('/chat/api/activity');
      if (stopped || version !== requestVersion) return;
      if (!page || !Array.isArray(page.events)) throw new Error('activity unavailable');
      const turnId = renderTurns(page.events);
      selectedTurn = turnId;
      if (!turnId) {
        renderEvents([]);
        renderInsights([]);
        renderUsage(null);
        outcomeNode.textContent = 'Not recorded';
        noteNode.textContent = 'No owner turns with recorded activity are available.';
        return;
      }
      await loadTurn(turnId, version);
    } catch (_) {
      if (!stopped && version === requestVersion) {
        eventsNode.replaceChildren();
        renderInsights([]);
        renderUsage(null);
        outcomeNode.textContent = 'Unavailable';
        emptyNode.hidden = false;
        noteNode.textContent = 'Owner activity is temporarily unavailable or the selected turn is no longer current.';
      }
    } finally {
      refreshing = false;
      if (!stopped && version === requestVersion) refreshButton.disabled = false;
    }
  }
  function chooseTurn() {
    const value = select.value;
    if (!validId(value)) return;
    selectedTurn = value;
    const version = ++requestVersion;
    noteNode.textContent = 'Loading the selected owner turn…';
    refreshButton.disabled = true;
    loadTurn(value, version).catch(() => {
      if (!stopped && version === requestVersion) {
        eventsNode.replaceChildren();
        renderInsights([]);
        renderUsage(null);
        outcomeNode.textContent = 'Unavailable';
        emptyNode.hidden = false;
        noteNode.textContent = 'Owner activity is temporarily unavailable or the selected turn is no longer current.';
      }
    }).finally(() => {
      if (!stopped && version === requestVersion) refreshButton.disabled = false;
    });
  }
  select.addEventListener('change', chooseTurn);
  refreshButton.addEventListener('click', refresh);
  const pollTimer = window.setInterval(refresh, 7000);
  refresh();
  return function cleanup() {
    stopped = true;
    window.clearInterval(pollTimer);
    select.removeEventListener('change', chooseTurn);
    refreshButton.removeEventListener('click', refresh);
  };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="activity",
    nav_label="Logs",
    title="Runtime & Logs",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/activity"),
        ("GET", "/chat/api/turns/{id}/activity"),
        ("GET", "/chat/api/turns/{id}/usage"),
    ),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
