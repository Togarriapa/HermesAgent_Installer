"""Static Activity feature fragment for the Jarvis feature shell."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class=\"activity-page\" aria-labelledby=\"activity-title\">
  <header class=\"activity-heading\"><p class=\"eyebrow\">RECORDED ACTIVITY</p><h1 id=\"activity-title\">Activity</h1>
    <p>Native observations from your recent assistant turns.</p></header>
  <section class=\"activity-card\" aria-labelledby=\"usage-title\">
    <div class=\"activity-card-heading\"><div><p class=\"eyebrow\">LATEST TURN</p><h2 id=\"usage-title\">Session usage snapshot</h2></div>
      <button type=\"button\" data-refresh>Refresh</button></div>
    <dl class=\"activity-usage\" data-usage><div><dt>Usage</dt><dd>Loading…</dd></div></dl>
    <p class=\"activity-note\" data-note role=\"status\" aria-live=\"polite\">Hermes reports cumulative session counters; a per-turn usage delta is unavailable.</p>
  </section>
  <section class=\"activity-card\" aria-labelledby=\"timeline-title\">
    <div class=\"activity-card-heading\"><div><p class=\"eyebrow\">TIMELINE</p><h2 id=\"timeline-title\">Recent turns</h2></div></div>
    <ol class=\"activity-list\" data-events aria-live=\"polite\"></ol>
    <p class=\"activity-empty\" data-empty hidden>No native activity has been recorded yet.</p>
  </section>
  <section class=\"activity-card\" aria-labelledby=\"effect-title\">
    <div class=\"activity-card-heading\"><div><p class=\"eyebrow\">OWNER REVIEW</p><h2 id=\"effect-title\">Pending tool actions</h2></div></div>
    <ol class=\"activity-list\" data-final-effects aria-live=\"polite\"></ol>
    <p class=\"activity-empty\" data-final-effects-empty>No tool action is waiting for your approval.</p>
    <p class=\"activity-note\" data-final-effects-note role=\"status\" aria-live=\"polite\">Only exact actions from your current Jarvis turn can be approved.</p>
  </section>
</section>"""

_CSS = """
[data-feature-root=\"activity\"] .activity-page{max-width:980px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"activity\"] .activity-heading{margin-bottom:1.5rem}
[data-feature-root=\"activity\"] .activity-heading h1{margin:.35rem 0;font-size:clamp(1.8rem,4vw,2.6rem)}
[data-feature-root=\"activity\"] .activity-heading p:last-child,[data-feature-root=\"activity\"] .activity-note{color:var(--muted,#9bafb4)}
[data-feature-root=\"activity\"] .eyebrow{font-size:.72rem;letter-spacing:.14em;color:var(--accent,#83d9ca);margin:0}
[data-feature-root=\"activity\"] .activity-card{border:1px solid var(--border,#294047);border-radius:16px;background:var(--panel,#0d1d23);padding:1.15rem;margin:1rem 0}
[data-feature-root=\"activity\"] .activity-card-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root=\"activity\"] h2{font-size:1.05rem;margin:.3rem 0 .8rem}
[data-feature-root=\"activity\"] button{background:transparent;border:1px solid var(--border,#38515a);color:inherit;border-radius:8px;padding:.5rem .8rem;cursor:pointer}
[data-feature-root=\"activity\"] .activity-usage{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.65rem;margin:.5rem 0}
[data-feature-root=\"activity\"] .activity-usage div{padding:.65rem;border-radius:10px;background:rgba(255,255,255,.035)}
[data-feature-root=\"activity\"] dt{font-size:.75rem;color:var(--muted,#9bafb4)}
[data-feature-root=\"activity\"] dd{margin:.25rem 0 0;font-variant-numeric:tabular-nums}
[data-feature-root=\"activity\"] .activity-list{list-style:none;margin:0;padding:0}
[data-feature-root=\"activity\"] .activity-list li{display:grid;grid-template-columns:minmax(110px,1fr) minmax(90px,.5fr) 1fr;gap:.75rem;padding:.75rem .2rem;border-top:1px solid var(--border,#20373e);align-items:center}
[data-feature-root=\"activity\"] .activity-kind{font-weight:600}
[data-feature-root=\"activity\"] .activity-meta{color:var(--muted,#9bafb4);font-size:.82rem}
[data-feature-root=\"activity\"] .activity-empty{color:var(--muted,#9bafb4)}
@media(max-width:560px){[data-feature-root=\"activity\"] .activity-list li{grid-template-columns:1fr auto}[data-feature-root=\"activity\"] .activity-meta:last-child{grid-column:1/-1}}
"""

_MOUNT = r"""function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="activity"]') || container;
  const eventsNode = root.querySelector('[data-events]');
  const usageNode = root.querySelector('[data-usage]');
  const emptyNode = root.querySelector('[data-empty]');
  const noteNode = root.querySelector('[data-note]');
  const effectsNode = root.querySelector('[data-final-effects]');
  const effectsEmptyNode = root.querySelector('[data-final-effects-empty]');
  const effectsNoteNode = root.querySelector('[data-final-effects-note]');
  const refreshButton = root.querySelector('[data-refresh]');
  let stopped = false;
  let refreshing = false;
  let newestTurn = null;
  const decisionRecords = new Map();
  let inFlightDecision = null;
  let finalEffectItems = [];
  let finalEffectTurn = null;
  let effectsRenderRevision = 0;
  let decisionButtons = [];
  const labels = {
    'tool.start': 'Tool started', 'tool.complete': 'Tool returned', 'tool.generating': 'Tool preparing',
    'status.update': 'Status update', 'subagent.spawn_requested': 'Delegation queued',
    'subagent.start': 'Delegation started', 'subagent.progress': 'Delegation progress',
    'subagent.thinking': 'Delegation thinking', 'subagent.tool': 'Delegated tool activity',
    'subagent.complete': 'Delegation completed', 'approval': 'Approval requested',
    'approval.cancelled': 'Approval cancelled', 'request.cancel': 'Request cancelled',
    'todo.updated': 'Task list updated', 'session.usage': 'Usage observed', 'message.complete': 'Turn completed'
  };
  function cell(tag, value, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value;
    return node;
  }
  function renderUsage(data) {
    usageNode.replaceChildren();
    const usage = data && data.usage;
    if (!usage) {
      usageNode.append(cell('div', 'No usage counters reported by Hermes.'));
      return;
    }
    for (const [key, label] of [['input','Input tokens'],['output','Output tokens'],['total','Total tokens'],['calls','Calls'],['reasoning','Reasoning tokens']]) {
      const value = Number.isSafeInteger(usage[key]) ? String(usage[key]) : 'Unknown';
      const row = document.createElement('div'); row.append(cell('dt', label), cell('dd', value)); usageNode.append(row);
    }
    const cost = usage.cost_usd === null ? 'Unknown' : String(usage.cost_usd);
    const row = document.createElement('div'); row.append(cell('dt','Cost'), cell('dd',cost)); usageNode.append(row);
  }
  function renderEvents(items) {
    eventsNode.replaceChildren();
    const list = Array.isArray(items) ? items : [];
    for (const event of list) {
      const row = document.createElement('li');
      const label = labels[event.type] || 'Native activity';
      row.append(cell('span', label, 'activity-kind'));
      const status = typeof event.status === 'string' ? event.status : 'observed';
      row.append(cell('span', status, 'activity-meta'));
      const details = [];
      if (Number.isSafeInteger(event.duration_ms)) details.push(`${event.duration_ms} ms`);
      if (typeof event.observed_at === 'number') details.push(new Date(event.observed_at * 1000).toLocaleString());
      row.append(cell('span', details.join(' · ') || 'Recorded', 'activity-meta'));
      eventsNode.append(row);
    }
    emptyNode.hidden = list.length > 0;
  }
  function renderFinalEffects(items, turnId) {
    const revision = ++effectsRenderRevision;
    finalEffectItems = Array.isArray(items) ? items : [];
    finalEffectTurn = turnId;
    effectsNode.replaceChildren();
    decisionButtons = [];
    const list = finalEffectItems;
    for (const item of list) {
      if (!item || typeof item.pendingId !== 'string' || typeof item.reviewSha256 !== 'string'
          || item.turnId !== turnId || !['approved', 'denied'].includes(item.status)) continue;
      const record = decisionRecords.get(JSON.stringify([turnId, item.pendingId, item.reviewSha256]));
      if (record && record.state !== 'confirmed') {
        record.state = 'confirmed'; record.confirmedStatus = item.status;
        if (inFlightDecision === record) inFlightDecision = null;
      }
    }
    const currentRecords = list.map(item => item && typeof item.pendingId === 'string'
      && typeof item.reviewSha256 === 'string' && item.turnId === turnId
      ? decisionRecords.get(JSON.stringify([turnId, item.pendingId, item.reviewSha256])) : null);
    if (inFlightDecision && inFlightDecision.turnId === turnId) {
      effectsNoteNode.textContent = 'Submitting your decision for this exact review…';
    } else if (currentRecords.some(record => record && record.state === 'unknown')) {
      effectsNoteNode.textContent = 'Decision outcome unknown for this exact review. Inspect current status; other reviews remain independent.';
    } else if (currentRecords.some(record => record && record.state === 'confirmed')) {
      effectsNoteNode.textContent = 'Owner decision confirmed for the exact reviewed request. Tool action completion is separate.';
    } else {
      effectsNoteNode.textContent = 'Only exact actions from your current Jarvis turn can be approved.';
    }
    for (const item of list) {
      if (!item || typeof item.pendingId !== 'string' || typeof item.reviewSha256 !== 'string'
          || item.turnId !== turnId || !item.preview) continue;
      const key = JSON.stringify([turnId, item.pendingId, item.reviewSha256]);
      const record = decisionRecords.get(key);
      const row = document.createElement('li');
      row.style.gridTemplateColumns = '1fr';
      row.append(cell('strong', `Review ${String(item.preview.tool_name || 'tool action')}`));
      if (record && record.state === 'confirmed') {
        row.append(cell('span', `Owner decision confirmed: ${record.confirmedStatus}. This does not confirm that the tool action completed.`, 'activity-meta'));
        effectsNode.append(row);
        continue;
      }
      if (item.status !== 'pending') {
        row.append(cell('span', `Observed status: ${String(item.status)}. This is separate from tool action completion.`, 'activity-meta'));
        effectsNode.append(row);
        continue;
      }
      const detail = cell('pre', JSON.stringify(item.preview, null, 2), 'activity-meta');
      detail.style.whiteSpace = 'pre-wrap';
      detail.style.overflowWrap = 'anywhere';
      row.append(detail);
      const controls = document.createElement('div');
      for (const [decision, label] of [['approve','Approve once'], ['deny','Deny']]) {
        const button = cell('button', label);
        button.type = 'button';
        button.disabled = inFlightDecision !== null || Boolean(record);
        decisionButtons.push(button);
        button.addEventListener('click', async () => {
          const currentRow = () => !stopped && revision === effectsRenderRevision
            && finalEffectTurn === turnId && effectsNode.contains(row)
            && finalEffectItems.some(candidate => candidate && candidate.pendingId === item.pendingId
              && candidate.reviewSha256 === item.reviewSha256 && candidate.turnId === turnId
              && candidate.status === 'pending');
          if (!currentRow() || inFlightDecision) return;
          const existing = decisionRecords.get(key);
          if (existing) return;
          const attempt = {key, turnId, pendingId: item.pendingId, reviewSha256: item.reviewSha256,
            decision, idempotencyKey: crypto.randomUUID().replaceAll('-', ''), state: 'submitting'};
          decisionRecords.set(key, attempt); inFlightDecision = attempt;
          for (const control of decisionButtons) control.disabled = true;
          effectsNoteNode.textContent = 'Submitting your decision…';
          try {
            const result = await api.post(`/chat/api/turns/${encodeURIComponent(turnId)}/final-effects/decision`, {
              pending_id: attempt.pendingId, review_sha256: attempt.reviewSha256,
              decision: attempt.decision, idempotency_key: attempt.idempotencyKey
            });
            if (stopped || decisionRecords.get(key) !== attempt || attempt.state === 'confirmed') return;
            const expectedStatus = attempt.decision === 'approve' ? 'approved' : 'denied';
            if (!result || result.pendingId !== attempt.pendingId || result.status !== expectedStatus) {
              attempt.state = 'unknown';
              if (inFlightDecision === attempt) inFlightDecision = null;
              if (newestTurn === attempt.turnId && !stopped) {
                effectsNoteNode.textContent = 'Decision outcome unknown for this exact review. Inspect current status; other reviews remain independent.';
                if (finalEffectTurn === attempt.turnId) renderFinalEffects(finalEffectItems, attempt.turnId);
              }
              return;
            }
            attempt.state = 'confirmed'; attempt.confirmedStatus = result.status;
            if (inFlightDecision === attempt) inFlightDecision = null;
            if (newestTurn === attempt.turnId && finalEffectTurn === attempt.turnId && !stopped) {
              effectsNoteNode.textContent = `Owner decision confirmed: ${result.status}. This does not confirm that the tool action completed.`;
              renderFinalEffects(finalEffectItems, attempt.turnId);
            }
          } catch (_) {
            if (!stopped && decisionRecords.get(key) === attempt && attempt.state !== 'confirmed') {
              attempt.state = 'unknown';
              if (inFlightDecision === attempt) inFlightDecision = null;
              if (newestTurn === attempt.turnId && !stopped) {
                effectsNoteNode.textContent = 'Decision outcome unknown for this exact review. Inspect current status; other reviews remain independent.';
                if (finalEffectTurn === attempt.turnId) renderFinalEffects(finalEffectItems, attempt.turnId);
              }
            }
          }
        });
        controls.append(button);
      }
      row.append(controls);
      effectsNode.append(row);
    }
    effectsEmptyNode.hidden = effectsNode.children.length > 0;
  }
  async function refresh() {
    if (stopped || refreshing) return;
    refreshing = true;
    refreshButton.disabled = true;
    noteNode.textContent = '';
    try {
      const pageData = await api.get('/chat/api/activity?limit=50');
      if (stopped) return;
      renderEvents(pageData.events);
      const latest = Array.isArray(pageData.events) ? pageData.events.find(item => item && typeof item.turnId === 'string') : null;
      if (latest && latest.turnId !== newestTurn) {
        renderUsage(null);
        const usage = await api.get(`/chat/api/turns/${encodeURIComponent(latest.turnId)}/usage`);
        if (stopped) return;
        newestTurn = latest.turnId;
        renderUsage(usage);
        const approvals = await api.get(`/chat/api/turns/${encodeURIComponent(latest.turnId)}/final-effects`);
        if (stopped) return;
        renderFinalEffects(approvals.requests, latest.turnId);
      } else if (!latest) {
        newestTurn = null;
        renderUsage(null);
        renderFinalEffects([], '');
      } else {
        const approvals = await api.get(`/chat/api/turns/${encodeURIComponent(latest.turnId)}/final-effects`);
        if (stopped) return;
        renderFinalEffects(approvals.requests, latest.turnId);
      }
      noteNode.textContent = pageData.nextPage ? 'Showing the latest recorded events. Hermes reports cumulative session counters; a per-turn usage delta is unavailable.' : 'Activity is recorded from this owner’s current Jarvis turns. Hermes reports cumulative session counters; a per-turn usage delta is unavailable.';
    } catch (error) {
      if (!stopped) noteNode.textContent = 'Activity is temporarily unavailable.';
    } finally {
      refreshing = false;
      if (!stopped) refreshButton.disabled = false;
    }
  }
  refreshButton.addEventListener('click', refresh);
  const pollTimer = window.setInterval(refresh, 5000);
  refresh();
  return function cleanup() {
    stopped = true;
    effectsRenderRevision++;
    window.clearInterval(pollTimer);
    refreshButton.removeEventListener('click', refresh);
  };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="activity",
    nav_label="Activity",
    title="Activity",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/activity"),
        ("GET", "/chat/api/turns/{id}/activity"),
        ("GET", "/chat/api/turns/{id}/usage"),
        ("GET", "/chat/api/turns/{turn_id}/final-effects"),
        ("POST", "/chat/api/turns/{turn_id}/final-effects/decision"),
    ),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
