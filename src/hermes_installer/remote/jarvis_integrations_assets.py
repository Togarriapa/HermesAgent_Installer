"""Small read-only Jarvis integration readiness menu.

The menu consumes only the existing owner capability catalog and channel status
reads. Catalog presence is not configuration or account readiness; missing
native status stays unknown with a concrete installer setup step.
"""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = '''<section class="integration-page" data-feature-root="integrations" aria-labelledby="integrations-title">
  <header class="integration-header">
    <div><p class="integration-eyebrow">SETUP READINESS</p><h2 id="integrations-title">Integrations</h2>
      <p>Review bundled channel and webhook options, then continue setup securely in the installer.</p></div>
    <button type="button" data-integration-refresh>Refresh</button>
  </header>
  <div class="integration-controls">
    <label for="integration-kind">Integration type</label>
    <select id="integration-kind" data-integration-kind>
      <option value="channels">Channels</option><option value="webhooks">Webhooks</option><option value="pairing">Device pairing</option>
    </select>
  </div>
  <p data-integration-status role="status" aria-live="polite">Waiting for current owner status.</p>
  <div data-integration-list class="integration-list"></div>
  <section class="integration-next" aria-labelledby="integration-next-title">
    <h3 id="integration-next-title">Continue securely</h3>
    <p data-integration-next>Run the installer on the target and use its scoped setup prompts. Credentials are not collected here.</p>
    <code data-installer-command>hermes-installer setup</code>
    <button type="button" data-copy-command>Copy setup command</button>
    <p data-copy-status role="status" aria-live="polite"></p>
  </section>
  <p class="integration-note">Bundled means a setup definition is present. It does not prove an account, grant, credential, connection, or adapter is ready. Unknown means the current reviewed owner API cannot establish that state.</p>
</section>'''

_CSS = '''[data-feature-root="integrations"]{max-width:920px;margin:0 auto;padding:clamp(18px,3vw,32px);color:var(--text,#edf5f6)}
[data-feature-root="integrations"] .integration-header{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
[data-feature-root="integrations"] .integration-eyebrow{margin:0 0 7px;color:var(--muted,#9bafb4);font-size:.72rem;letter-spacing:.14em}
[data-feature-root="integrations"] h2{margin:0;font-size:clamp(1.5rem,3vw,2rem)}
[data-feature-root="integrations"] p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="integrations"] button,[data-feature-root="integrations"] select{min-height:42px;padding:9px 12px;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;font:inherit}
[data-feature-root="integrations"] button{cursor:pointer}
[data-feature-root="integrations"] button:focus-visible,[data-feature-root="integrations"] select:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root="integrations"] .integration-controls{display:grid;gap:7px;max-width:360px;margin:20px 0 12px}
[data-feature-root="integrations"] .integration-controls label{font-size:.85rem;color:var(--muted,#9bafb4)}
[data-feature-root="integrations"] [data-integration-status]{min-height:1.5em}
[data-feature-root="integrations"] .integration-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,270px),1fr));gap:10px}
[data-feature-root="integrations"] .integration-card,[data-feature-root="integrations"] .integration-next{padding:15px;border:1px solid var(--border,#294047);border-radius:12px;background:var(--panel,#0d1d23)}
[data-feature-root="integrations"] .integration-card h3,[data-feature-root="integrations"] .integration-next h3{margin:0 0 9px;font-size:1rem}
[data-feature-root="integrations"] .integration-card p{margin:5px 0;font-size:.88rem;overflow-wrap:anywhere}
[data-feature-root="integrations"] .integration-next{margin-top:16px}
[data-feature-root="integrations"] code{display:inline-block;margin:0 9px 8px 0;padding:7px 9px;border-radius:7px;background:rgba(0,0,0,.2);font-size:.85rem}
[data-feature-root="integrations"] .integration-note{font-size:.8rem}
@media(max-width:600px){[data-feature-root="integrations"] .integration-header{flex-direction:column}[data-feature-root="integrations"] .integration-header button{width:100%}}'''

_MOUNT = r'''function mount(container, api) {
  const root = container.querySelector('[data-feature-root="integrations"]') || container;
  const select = root.querySelector('[data-integration-kind]');
  const list = root.querySelector('[data-integration-list]');
  const status = root.querySelector('[data-integration-status]');
  const refresh = root.querySelector('[data-integration-refresh]');
  const copy = root.querySelector('[data-copy-command]');
  const copyStatus = root.querySelector('[data-copy-status]');
  const command = root.querySelector('[data-installer-command]');
  let active = true, loading = false, catalog = null, channelSnapshot = null;
  const add = (parent, tag, value, className) => {
    const node = document.createElement(tag); if (className) node.className = className;
    node.textContent = String(value ?? 'Unknown'); parent.append(node); return node;
  };
  const validCatalog = (data) => data && data.readiness === 'pending'
    && data.source && data.source.kind === 'offline-bundle'
    && data.source.catalogVersion === '2.3.1'
    && data.source.revision === '113f42d33be9e0c8f0f47f5ca998e687323dec83'
    && Array.isArray(data.items) && data.items.length === 692
    && data.items.every((item) => item && typeof item.id === 'string' && typeof item.name === 'string'
      && item.id.length <= 120 && item.name.length <= 120 && !/[\x00-\x1f\x7f]/.test(item.name)
      && typeof item.kind === 'string' && item.state === 'bundled' && item.readiness === 'pending');
  const validChannels = (data) => data && data.schema === 1 && Array.isArray(data.channels)
    && Array.isArray(data.pending_reasons) && typeof data.observed_at === 'string'
    && data.pending_reasons.length <= 16 && data.pending_reasons.every((reason) => typeof reason === 'string' && reason.length <= 300)
    && data.channels.length <= 64 && data.channels.every((item) => item
      && Object.keys(item).sort().join(',') === 'configured,connected,enabled,opaque_id,state,type'
      && typeof item.opaque_id === 'string' && item.opaque_id.length <= 80 && typeof item.type === 'string' && item.type.length <= 80
      && [true,false,null].includes(item.configured) && [true,false,null].includes(item.enabled)
      && [true,false,null].includes(item.connected) && typeof item.state === 'string' && item.state.length <= 120);
  const field = (card, label, value) => add(card, 'p', label + ': ' + (value === true ? 'Yes' : value === false ? 'No' : typeof value === 'string' && value ? value : 'Unknown'));
  function currentRows() {
    const kind = select.value;
    if (kind === 'pairing') return [{name:'Device pairing', state:'unknown', source:'No owner-readable pairing status or catalog adapter is available.'}];
    if (!catalog) return [];
    return catalog.items.filter((item) => item.kind === kind).map((item) => ({name:item.name, id:item.id, state:'bundled'}));
  }
  function render() {
    if (!active) return;
    list.replaceChildren();
    const rows = currentRows();
    if (!rows.length) {
      add(list, 'p', catalog ? 'No bundled entries are listed for this type.' : 'The verified capability catalog is unavailable.');
      return;
    }
    for (const item of rows) {
      const card = document.createElement('article'); card.className = 'integration-card';
      add(card, 'h3', item.name);
      if (item.state === 'bundled') field(card, 'Catalog', 'Bundled definition · readiness pending');
      const normalized = item.name.toLowerCase();
      const observed = channelSnapshot && channelSnapshot.channels.find((row) => row.type.toLowerCase() === normalized);
      if (select.value === 'channels' && observed) {
        field(card, 'Configured', observed.configured);
        field(card, 'Enabled', observed.enabled);
        field(card, 'Connected', observed.connected);
        field(card, 'Observed', 'Current owner status row · ' + observed.state);
        field(card, 'Missing credential/account/grant', 'Unknown; current status API does not expose these details');
      } else {
        field(card, 'Configured', 'Unknown');
        field(card, 'Observed', channelSnapshot && select.value === 'channels' ? 'No matching row; configuration remains unknown' : 'Unknown');
        field(card, 'Missing account/grant/credential', 'Unknown; inspect through secure installer setup');
        const pending = channelSnapshot && channelSnapshot.pending_reasons.find((reason) => reason.includes('No reviewed native messaging status reader is available'));
        field(card, 'Status adapter', select.value === 'channels'
          ? (pending || (channelSnapshot ? 'No matching status row was returned; type readiness remains unknown' : 'Owner channel status read is unavailable; readiness remains unknown'))
          : 'Missing: no owner-readable status adapter is available');
      }
      field(card, 'Next step', 'Run the installer setup command below and select ' + item.name + '.');
      list.append(card);
    }
  }
  async function load() {
    if (!active || loading) return;
    loading = true; refresh.disabled = true; status.textContent = 'Reading the fixed owner catalog and channel status…';
    const results = await Promise.allSettled([
      api.get('/chat/api/capabilities'), api.get('/chat/api/channels'),
    ]);
    if (!active) return;
    catalog = results[0].status === 'fulfilled' && validCatalog(results[0].value) ? results[0].value : null;
    channelSnapshot = results[1].status === 'fulfilled' && validChannels(results[1].value) ? results[1].value : null;
    const observedAt = channelSnapshot && channelSnapshot.observed_at || 'unknown';
    status.textContent = `Catalog ${catalog ? 'verified from the fixed offline bundle' : 'unavailable'} · channel status observed at ${observedAt}. Unsupported status remains unknown.`;
    render(); loading = false; refresh.disabled = false;
  }
  const selectionChanged = () => render();
  const copyCommand = async () => {
    if (!active || !command) return;
    try { await navigator.clipboard.writeText(command.textContent); copyStatus.textContent = 'Setup command copied.'; }
    catch (_) { copyStatus.textContent = 'Copy is unavailable; select and copy the command shown above.'; }
  };
  refresh.addEventListener('click', load); select.addEventListener('change', selectionChanged); copy.addEventListener('click', copyCommand);
  void load();
  return () => { active = false; refresh.removeEventListener('click', load); select.removeEventListener('change', selectionChanged); copy.removeEventListener('click', copyCommand); list.replaceChildren(); };
}'''

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="integrations",
    nav_label="Integrations",
    title="Integration readiness",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/capabilities"),
        ("GET", "/chat/api/channels"),
    ),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
