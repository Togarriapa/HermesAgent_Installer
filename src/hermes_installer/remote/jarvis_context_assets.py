"""Static owner session-context view; all untrusted values are rendered as text."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="context",
    nav_label="Context",
    title="Context & workspace",
    view_html=(
        '<section class="context-page" aria-labelledby="context-title">'
        '<header><p class="context-eyebrow">YOUR OWNED SESSION</p><h1 id="context-title">Context &amp; workspace</h1>'
        '<p>Inspect context usage for one of your Jarvis conversations.</p></header>'
        '<label for="context-conversation">Conversation</label> '
        '<select id="context-conversation" data-conversation><option value="">Choose a conversation</option></select> '
        '<button type="button" data-refresh>Refresh</button>'
        '<p data-status role="status" aria-live="polite">Choose a conversation to inspect its context.</p>'
        '<section class="context-card" aria-labelledby="context-usage-title"><h2 id="context-usage-title">Context window</h2>'
        '<p data-usage></p><ul data-categories aria-label="Context tokens by category"></ul></section>'
        '<section class="context-card" aria-labelledby="context-session-title"><h2 id="context-session-title">Session status</h2>'
        '<dl><div><dt>Running</dt><dd data-running>Unknown</dd></div><div><dt>Created</dt><dd data-created>Unknown</dd></div>'
        '<div><dt>Last activity</dt><dd data-activity>Unknown</dd></div><div><dt>Tokens reported</dt><dd data-tokens>Unknown</dd></div></dl></section>'
        '<section class="context-card" aria-labelledby="context-persona-title"><h2 id="context-persona-title">Primary persona</h2>'
        '<p data-persona>Verified source status is pending.</p></section>'
        '<section class="context-card" aria-labelledby="context-workspace-title"><h2 id="context-workspace-title">Workspace</h2>'
        '<p data-workspace>Owned workspace details are pending a reviewed read-only source.</p></section>'
        '</section>'
    ),
    css=(
        '[data-feature-root="context"] .context-page{max-width:58rem;margin:auto;padding:clamp(1rem,3vw,2rem);color:var(--text,#edf5f6)}'
        '[data-feature-root="context"] .context-page header>p,[data-feature-root="context"] .context-card p{color:var(--muted,#9bafb4);line-height:1.5}'
        '[data-feature-root="context"] .context-eyebrow{color:var(--accent,#83d9ca);font-size:.72rem;letter-spacing:.13em}'
        '[data-feature-root="context"] .context-card{margin:1rem 0;padding:1rem;border:1px solid var(--border,#294047);border-radius:14px;background:var(--panel,#0d1d23)}'
        '[data-feature-root="context"] select,[data-feature-root="context"] button{min-height:42px;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;padding:.45rem .7rem;font:inherit}'
        '[data-feature-root="context"] button:focus-visible,[data-feature-root="context"] select:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}'
        '[data-feature-root="context"] ul{padding:0;list-style:none;display:grid;gap:.5rem}'
        '[data-feature-root="context"] li{display:grid;grid-template-columns:minmax(7rem,1fr) minmax(5rem,2fr) auto;align-items:center;gap:.7rem}'
        '[data-feature-root="context"] progress{width:100%;accent-color:var(--accent,#83d9ca)}'
        '[data-feature-root="context"] dl{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.5rem}'
        '[data-feature-root="context"] dl div{padding:.65rem;background:rgba(255,255,255,.035);border-radius:8px}'
        '[data-feature-root="context"] dt{color:var(--muted,#9bafb4);font-size:.82rem}[data-feature-root="context"] dd{margin:.3rem 0 0;font-variant-numeric:tabular-nums}'
    ),
    api_routes=(
        ("GET", "/chat/api/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/context"),
    ),
    mount_js=r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="context"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const selector = $('[data-conversation]'), refreshButton = $('[data-refresh]');
  let stopped = false, selected = '';
  function text(selector, value) { $(selector).textContent = value; }
  function safeCount(value) { return Number.isSafeInteger(value) && value >= 0 ? value : null; }
  function render(data) {
    const context = data && data.context || {}, status = data && data.status || {};
    text('[data-status]', data && data.state === 'observed' ? 'Context observed from the selected owned session.' : 'Some session context data is unavailable.');
    text('[data-usage]', context.state === 'observed'
      ? `${safeCount(context.contextUsed) ?? 'Unknown'} of ${safeCount(context.contextMax) ?? 'Unknown'} tokens · ${safeCount(context.contextPercent) ?? 'Unknown'}% · ${context.estimated ? 'estimated' : 'reported'} · ${context.model || 'model unavailable'}`
      : 'Context usage is unavailable.');
    const list = $('[data-categories]'); list.replaceChildren();
    const categories = context.state === 'observed' && Array.isArray(context.categories) ? context.categories : [];
    const maximum = Math.max(1,...categories.map(item => safeCount(item && item.tokens) || 0));
    for (const item of categories) {
      if (!item || typeof item.label !== 'string' || safeCount(item.tokens) === null) continue;
      const row = document.createElement('li'), label = document.createElement('span'); label.textContent = item.label;
      const bar = document.createElement('progress'); bar.max = maximum; bar.value = item.tokens; bar.setAttribute('aria-label', `${item.label}: ${item.tokens} tokens`);
      const count = document.createElement('span'); count.textContent = item.tokens.toLocaleString(); row.append(label,bar,count); list.append(row);
    }
    text('[data-running]', status.state === 'observed' ? (status.running ? 'Yes' : 'No') : 'Unknown');
    text('[data-created]', status.state === 'observed' ? status.created : 'Unknown');
    text('[data-activity]', status.state === 'observed' ? status.lastActivity : 'Unknown');
    text('[data-tokens]', status.state === 'observed' ? Number(status.tokens).toLocaleString() : 'Unknown');
    text('[data-persona]', data && data.primaryPersona && data.primaryPersona.state === 'observed'
      ? 'Verified primary persona source is current.' : 'Verified primary persona source status is pending.');
    text('[data-workspace]', data && data.workspace && data.workspace.state === 'observed'
      ? 'Owned workspace details observed.' : 'Owned workspace details are pending a reviewed read-only source.');
  }
  async function load() {
    if (stopped || !selected) return;
    refreshButton.disabled = true; text('[data-status]', 'Loading owned session context…');
    try { const result = await api.get(`/chat/api/conversations/${encodeURIComponent(selected)}/context`); if (!stopped) render(result); }
    catch { if (!stopped) text('[data-status]', 'Owned session context is temporarily unavailable.'); }
    finally { if (!stopped) refreshButton.disabled = false; }
  }
  async function loadConversations() {
    try {
      const result = await api.get('/chat/api/conversations');
      const rows = result && Array.isArray(result.conversations) ? result.conversations : [];
      for (const row of rows) {
        if (!row || typeof row.id !== 'string' || !/^[A-Za-z0-9_-]{24,80}$/.test(row.id)) continue;
        const option = document.createElement('option'); option.value = row.id;
        option.textContent = typeof row.title === 'string' && row.title ? row.title : 'Jarvis conversation';
        selector.append(option);
      }
    } catch { if (!stopped) text('[data-status]', 'Your conversations could not be loaded.'); }
  }
  function changed() { selected = selector.value; load(); }
  selector.addEventListener('change', changed); refreshButton.addEventListener('click', load);
  loadConversations();
  return function cleanup() { stopped = true; selector.removeEventListener('change', changed); refreshButton.removeEventListener('click', load); };
}""",
    unmount_js="function unmount() {}",
)
