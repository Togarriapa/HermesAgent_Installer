"""Static, owner-facing read surface for the Obsidian second brain."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class=\"second-brain-page\" aria-labelledby=\"second-brain-title\">
  <header class=\"second-brain-heading\"><p class=\"second-brain-kicker\">OBSIDIAN · PRIVATE KNOWLEDGE</p>
    <h1 id=\"second-brain-title\">Second brain</h1>
    <p>Your owner-bound notes, real links, and searchable knowledge. Note content is shown as plain Markdown text.</p></header>
  <section class=\"brain-signal\" aria-label=\"Vault observation\">
    <div><span>VAULT</span><strong data-vault-state>Checking…</strong><small data-vault-observed></small></div>
    <dl><div><dt>Notes</dt><dd data-count-notes>—</dd></div><div><dt>Resolved links</dt><dd data-count-links>—</dd></div>
      <div><dt>Unresolved</dt><dd data-count-unresolved>—</dd></div><div><dt>Private drafts</dt><dd data-count-drafts>—</dd></div></dl>
    <p data-coverage></p>
  </section>
  <div class=\"brain-workspace\">
    <section class=\"brain-browser\" aria-labelledby=\"brain-browser-title\">
      <h2 id=\"brain-browser-title\">Find a note</h2>
      <form data-search-form role=\"search\"><label class=\"visually-hidden\" for=\"brain-query\">Search notes</label>
        <input id=\"brain-query\" data-query type=\"search\" maxlength=\"160\" autocomplete=\"off\" placeholder=\"Search titles, notes, tags…\">
        <button type=\"submit\" data-search-button>Search</button></form>
      <div class=\"brain-list-head\"><h3 data-results-title>Recent notes</h3><button type=\"button\" data-refresh>Refresh</button></div>
      <ul data-note-list aria-label=\"Vault notes\"></ul><p data-list-empty hidden>No notes are available in this vault yet.</p>
      <button type=\"button\" data-more hidden>Load more notes</button>
    </section>
    <section class=\"brain-reader\" aria-labelledby=\"brain-reader-title\">
      <div class=\"brain-reader-heading\"><div><h2 id=\"brain-reader-title\" data-reader-title tabindex=\"-1\">Select a note</h2><p data-reader-meta></p></div></div>
      <pre data-note-body tabindex=\"0\" aria-label=\"Selected note in plain Markdown text\">Choose a note from your vault to read it here.</pre>
      <section class=\"brain-links\" aria-label=\"Note relationships\">
        <div><h3>Links</h3><ul data-note-links></ul></div><div><h3>Backlinks</h3><ul data-note-backlinks></ul></div>
        <div><h3>Unresolved links</h3><ul data-note-unresolved></ul></div>
      </section>
    </section>
  </div>
  <section class=\"brain-graph\" aria-labelledby=\"brain-graph-title\">
    <div class=\"brain-graph-heading\"><div><p class=\"second-brain-kicker\">DERIVED FROM VAULT LINKS</p><h2 id=\"brain-graph-title\">Knowledge map</h2></div>
      <button type=\"button\" data-graph-refresh>Refresh map</button></div>
    <p class=\"brain-graph-note\" data-graph-status>Connections represent indexed Obsidian links only; they do not imply communication or execution.</p>
    <p class=\"brain-graph-note\">Node rings show saved vault tags; filters match any selected tag. Solid arrows are wikilinks; dashed arrows are Markdown links.</p>
    <p class=\"brain-graph-note\">The map contains note links only. Expert, team, review, and activity relationships appear only when their source records are available.</p>
    <p class=\"brain-graph-note\">Notes remain in your private vault when a chat or project is removed.</p>
    <div class=\"brain-graph-tools\"><div data-graph-legend aria-label=\"Filter notes by their actual Obsidian tags\"></div>
      <div class=\"brain-graph-zoom\" aria-label=\"Knowledge map controls\"><button type=\"button\" data-zoom-out aria-label=\"Zoom out\">−</button><button type=\"button\" data-zoom-in aria-label=\"Zoom in\">+</button><button type=\"button\" data-zoom-reset>Reset map</button></div></div>
    <div class=\"brain-graph-layout\"><svg data-graph viewBox=\"0 0 1000 620\" role=\"group\" tabindex=\"0\" aria-label=\"Map of actual linked notes. Drag to pan; use plus and minus buttons to zoom.\"><g data-graph-scene></g></svg>
      <ol data-graph-list aria-label=\"Knowledge map links\"></ol></div>
  </section>
  <p class=\"brain-safety-note\" role=\"note\">Vault text is untrusted Markdown, displayed without executing HTML or fetching embeds. Shared-note review and writes are unavailable until the owner-authorized review route is active.</p>
  <p data-status class=\"brain-status\" role=\"status\" aria-live=\"polite\">Loading your private vault…</p>
</section>"""


_CSS = """
[data-feature-root=\"second-brain\"] .second-brain-page{max-width:1240px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"second-brain\"] .second-brain-heading{margin-bottom:1.4rem}
[data-feature-root=\"second-brain\"] .second-brain-heading h1{margin:.25rem 0;font-size:clamp(2rem,4vw,3rem);letter-spacing:-.035em}
[data-feature-root=\"second-brain\"] .second-brain-heading>p:last-child,[data-feature-root=\"second-brain\"] .brain-graph-note,[data-feature-root=\"second-brain\"] .brain-safety-note{max-width:72ch;color:var(--muted,#9bafb4);line-height:1.55}
[data-feature-root=\"second-brain\"] .second-brain-kicker{margin:0;color:var(--accent,#83d9ca);font:600 .7rem/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.15em}
[data-feature-root=\"second-brain\"] .brain-signal{display:grid;grid-template-columns:minmax(170px,.8fr) minmax(0,3fr);gap:.25rem 1.4rem;align-items:center;border-block:1px solid rgba(91,199,211,.25);padding:1rem 0;margin:0 0 1.2rem}
[data-feature-root=\"second-brain\"] .brain-signal>div:first-child{display:grid;gap:.35rem}
[data-feature-root=\"second-brain\"] .brain-signal>div:first-child span{color:#8cb8be;font:600 .65rem/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em}
[data-feature-root=\"second-brain\"] .brain-signal>div:first-child strong{color:#ddffff;font-size:1.05rem}
[data-feature-root=\"second-brain\"] .brain-signal>div:first-child small{color:var(--muted,#9bafb4);font-size:.72rem}
[data-feature-root=\"second-brain\"] .brain-signal dl{display:grid;grid-template-columns:repeat(4,minmax(80px,1fr));gap:.7rem;margin:0}
[data-feature-root=\"second-brain\"] .brain-signal dl>div{display:grid;gap:.2rem}
[data-feature-root=\"second-brain\"] .brain-signal dt{color:#8cb8be;font-size:.69rem}
[data-feature-root=\"second-brain\"] .brain-signal dd{margin:0;color:#e7fcfd;font-variant-numeric:tabular-nums;font-weight:600}
[data-feature-root=\"second-brain\"] .brain-signal>p{grid-column:1/-1;margin:.25rem 0 0;color:var(--muted,#9bafb4);font-size:.73rem}
[data-feature-root=\"second-brain\"] .brain-workspace{display:grid;grid-template-columns:minmax(250px,.75fr) minmax(0,1.7fr);gap:1rem;align-items:start}
[data-feature-root=\"second-brain\"] .brain-browser,[data-feature-root=\"second-brain\"] .brain-reader,[data-feature-root=\"second-brain\"] .brain-graph{min-width:0;border-top:1px solid rgba(91,199,211,.25);padding:1rem 0}
[data-feature-root=\"second-brain\"] .brain-browser h2,[data-feature-root=\"second-brain\"] .brain-reader h2,[data-feature-root=\"second-brain\"] .brain-graph h2{margin:.1rem 0 .8rem;font-size:1.06rem}
[data-feature-root=\"second-brain\"] form[data-search-form]{display:flex;gap:.5rem}
[data-feature-root=\"second-brain\"] input[data-query]{min-width:0;flex:1;min-height:44px;padding:.65rem .75rem;border:1px solid #31515a;border-radius:9px;background:#09191f;color:#edfafa;font:inherit}
[data-feature-root=\"second-brain\"] button{min-height:44px;padding:.55rem .85rem;border:1px solid #31515a;border-radius:9px;background:rgba(14,44,52,.75);color:#e4fafa;font:inherit;cursor:pointer;transition:border-color .16s ease,color .16s ease,background-color .16s ease}
[data-feature-root=\"second-brain\"] button:hover{border-color:#69d5de;background:rgba(22,70,79,.7)}
[data-feature-root=\"second-brain\"] button:focus-visible,[data-feature-root=\"second-brain\"] input:focus-visible,[data-feature-root=\"second-brain\"] [data-note-body]:focus-visible{outline:2px solid #8de7eb;outline-offset:3px}
[data-feature-root=\"second-brain\"] button:disabled{opacity:.55;cursor:wait}
[data-feature-root=\"second-brain\"] .brain-list-head,.brain-graph-heading,.brain-reader-heading{display:flex;align-items:center;justify-content:space-between;gap:.8rem}
[data-feature-root=\"second-brain\"] .brain-list-head{margin:.95rem 0 .25rem}
[data-feature-root=\"second-brain\"] .brain-list-head h3,[data-feature-root=\"second-brain\"] .brain-links h3{margin:.3rem 0;font-size:.81rem;color:#a9c6ca}
[data-feature-root=\"second-brain\"] [data-note-list],[data-feature-root=\"second-brain\"] .brain-links ul{list-style:none;margin:0;padding:0}
[data-feature-root=\"second-brain\"] [data-note-list] li{border-top:1px solid rgba(91,199,211,.14)}
[data-feature-root=\"second-brain\"] [data-note-list] button{display:grid;width:100%;min-height:56px;text-align:left;gap:.2rem;border:0;border-radius:0;background:transparent;padding:.65rem .4rem}
[data-feature-root=\"second-brain\"] [data-note-list] button[aria-current=\"true\"]{color:#aaf7f5;background:rgba(65,198,207,.09)}
[data-feature-root=\"second-brain\"] .brain-note-title{overflow-wrap:anywhere;font-weight:600}
[data-feature-root=\"second-brain\"] .brain-note-meta{color:var(--muted,#9bafb4);font-size:.7rem;line-height:1.45;overflow-wrap:anywhere}
[data-feature-root=\"second-brain\"] [data-note-body]{min-height:220px;max-height:560px;overflow:auto;margin:0;padding:1rem;border:1px solid rgba(91,199,211,.17);border-radius:9px;background:#08171c;color:#d5e7e9;font:400 .84rem/1.65 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;overflow-wrap:anywhere;tab-size:2}
[data-feature-root=\"second-brain\"] .brain-reader-heading>div{min-width:0;max-width:100%}
[data-feature-root=\"second-brain\"] .brain-reader-heading p{max-width:100%;margin:.2rem 0 .7rem;color:var(--muted,#9bafb4);font-size:.72rem;line-height:1.5;overflow-wrap:anywhere}
[data-feature-root=\"second-brain\"] .brain-links{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.7rem;margin-top:.9rem}
[data-feature-root=\"second-brain\"] .brain-links li{padding:.15rem 0;color:#9bb6bb;font-size:.74rem;line-height:1.45;overflow-wrap:anywhere}
[data-feature-root=\"second-brain\"] .brain-links button{min-height:44px;border:0;padding:.2rem .25rem;color:#95e7e9;background:transparent;text-align:left;font-size:inherit}
[data-feature-root=\"second-brain\"] .brain-graph{margin-top:1rem}
[data-feature-root=\"second-brain\"] .brain-graph-tools{display:flex;justify-content:space-between;align-items:center;gap:.8rem;margin:.8rem 0}
[data-feature-root=\"second-brain\"] [data-graph-legend]{display:flex;flex-wrap:wrap;gap:.4rem}
[data-feature-root=\"second-brain\"] [data-graph-legend] button{display:inline-flex;align-items:center;gap:.45rem;min-height:44px;padding:.35rem .65rem;font-size:.74rem}
[data-feature-root=\"second-brain\"] .brain-legend-dot{width:.65rem;height:.65rem;border-radius:50%;background:var(--tag-color);box-shadow:0 0 10px color-mix(in srgb,var(--tag-color),transparent 55%)}
[data-feature-root=\"second-brain\"] [data-graph-legend] button[aria-pressed=\"false\"]{opacity:.48}
[data-feature-root=\"second-brain\"] .brain-graph-zoom{display:flex;gap:.35rem}
[data-feature-root=\"second-brain\"] .brain-graph-zoom button{min-width:44px}
[data-feature-root=\"second-brain\"] [data-graph]{display:block;width:100%;height:auto;aspect-ratio:1000/620;min-height:300px;border:1px solid rgba(91,199,211,.17);border-radius:10px;background:radial-gradient(ellipse at center,rgba(20,88,99,.18),transparent 72%);touch-action:none;cursor:grab}
[data-feature-root=\"second-brain\"] [data-graph]:active{cursor:grabbing}
[data-feature-root=\"second-brain\"] [data-graph] .brain-edge{stroke-width:1.6;opacity:.68}
[data-feature-root=\"second-brain\"] [data-graph] .brain-edge[data-link-kind=\"markdown\"]{stroke-dasharray:5 4}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node circle{fill:#0b1d24;stroke-width:2;filter:drop-shadow(0 0 5px color-mix(in srgb,var(--tag-color),transparent 45%))}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node .brain-tag-arc{fill:none;stroke-width:4;stroke-linecap:round}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node:hover circle,[data-feature-root=\"second-brain\"] [data-graph] .brain-node:focus circle{stroke-width:4;filter:drop-shadow(0 0 9px var(--tag-color))}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node[aria-current=\"true\"] circle{stroke-width:4;filter:drop-shadow(0 0 9px var(--tag-color))}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node text{fill:#daf7f8;font:11px ui-sans-serif,system-ui,sans-serif;text-anchor:middle}
[data-feature-root=\"second-brain\"] [data-graph] .brain-node{cursor:pointer}
[data-feature-root=\"second-brain\"] [data-graph-list]{max-height:340px;overflow:auto;margin:.2rem 0;padding-left:1.25rem;color:#a9c6ca;font-size:.78rem;line-height:1.7}
[data-feature-root=\"second-brain\"] [data-graph-list] li{padding:.2rem 0}
[data-feature-root=\"second-brain\"] [data-graph-list] button{min-height:44px;border:0;padding:.2rem .25rem;color:#95e7e9;background:transparent;text-align:left;font-size:inherit}
[data-feature-root=\"second-brain\"] .brain-graph-note,[data-feature-root=\"second-brain\"] .brain-safety-note,[data-feature-root=\"second-brain\"] .brain-status{font-size:.74rem}
[data-feature-root=\"second-brain\"] .brain-safety-note{margin-top:1.4rem}
[data-feature-root=\"second-brain\"] .brain-status{min-height:1.3em;color:#8fc3c7}
[data-feature-root=\"second-brain\"] [hidden]{display:none!important}
.visually-hidden{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:760px){[data-feature-root=\"second-brain\"] .brain-signal{grid-template-columns:1fr;gap:.8rem}[data-feature-root=\"second-brain\"] .brain-signal dl{grid-template-columns:repeat(2,minmax(0,1fr))}[data-feature-root=\"second-brain\"] .brain-workspace{grid-template-columns:1fr}[data-feature-root=\"second-brain\"] .brain-graph-layout{grid-template-columns:1fr}[data-feature-root=\"second-brain\"] .brain-graph [data-graph]{min-height:200px}}
@media(max-width:520px){[data-feature-root=\"second-brain\"] .brain-links{grid-template-columns:1fr}[data-feature-root=\"second-brain\"] .brain-graph-heading{align-items:flex-start}[data-feature-root=\"second-brain\"] .brain-signal dl{gap:.65rem}.second-brain-page{padding:1rem}}
@media(max-width:640px){[data-feature-root=\"second-brain\"] .brain-graph-tools{align-items:flex-start;flex-direction:column}[data-feature-root=\"second-brain\"] [data-graph]{min-height:220px}}
@media(prefers-reduced-motion:reduce){[data-feature-root=\"second-brain\"] button{transition:none}[data-feature-root=\"second-brain\"] [data-graph] .brain-node circle{filter:none}}
"""


_MOUNT = r"""function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="second-brain"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const status = $('[data-status]');
  const list = $('[data-note-list]');
  const body = $('[data-note-body]');
  const queryInput = $('[data-query]');
  const searchButton = $('[data-search-button]');
  const refreshButton = $('[data-refresh]');
  const moreButton = $('[data-more]');
  const graphRefreshButton = $('[data-graph-refresh]');
  const graph = $('[data-graph]');
  const graphScene = $('[data-graph-scene]');
  const graphLegend = $('[data-graph-legend]');
  const graphList = $('[data-graph-list]');
  const zoomInButton = $('[data-zoom-in]');
  const zoomOutButton = $('[data-zoom-out]');
  const zoomResetButton = $('[data-zoom-reset]');
  const noteLimit = 20;
  let stopped = false, busy = false, cursor = null, mode = 'recent', currentNoteId = null;
  let notes = [];
  let graphData = null, selectedTags = null;
  let graphScale = 1, graphPanX = 0, graphPanY = 0, drag = null;
  const apiRoot = '/chat/api/second-brain';
  const SVG = 'http://www.w3.org/2000/svg';

  function addText(parent, tag, value, className) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = typeof value === 'string' ? value : '';
    parent.append(node);
    return node;
  }
  function safeCount(value) { return Number.isSafeInteger(value) && value >= 0 ? String(value) : 'Unknown'; }
  function statusText(value) { return typeof value === 'string' && value ? value : 'unknown'; }
  function encodedId(value) {
    if (typeof value !== 'string' || !value || value.length > 160) throw new Error('Invalid note reference.');
    return encodeURIComponent(value);
  }
  function timestamp(value) {
    if ((typeof value !== 'string' && typeof value !== 'number') || !value || !Number.isFinite(typeof value === 'number' ? value : Date.parse(value))) return 'Observation time unavailable';
    const parsed = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(parsed.valueOf()) ? 'Observation time unavailable' : 'Observed ' + parsed.toLocaleString();
  }
  function queryPath(path, params) {
    const query = new URLSearchParams(params);
    return path + '?' + query.toString();
  }
  function updateStatus(text, isError = false) {
    status.textContent = text;
    status.dataset.state = isError ? 'error' : 'ready';
  }
  function listRoute(currentCursor = null) {
    const params = {limit: String(noteLimit)};
    if (currentCursor) params.cursor = currentCursor;
    if (mode === 'search') params.query = queryInput.value.trim();
    return queryPath(apiRoot + (mode === 'search' ? '/search' : '/notes'), params);
  }
  function renderNoteRows(rows, append = false) {
    if (!append) list.replaceChildren();
    for (const item of Array.isArray(rows) ? rows : []) {
      if (!item || typeof item.noteId !== 'string' || !item.noteId || typeof item.title !== 'string') continue;
      const row = document.createElement('li');
      const button = document.createElement('button');
      button.type = 'button';
      button.dataset.noteId = item.noteId;
      button.setAttribute('aria-current', item.noteId === currentNoteId ? 'true' : 'false');
      addText(button, 'span', item.title, 'brain-note-title');
      const tags = Array.isArray(item.tags) && item.tags.some(tag => typeof tag === 'string' && tag.trim()) ? item.tags.filter(tag => typeof tag === 'string' && tag.trim()).slice(0, 6).join(' · ') : 'Uncategorized';
      const meta = [timestampShort(item.updatedAt), tags, typeof item.excerpt === 'string' ? item.excerpt : ''].filter(Boolean).join(' · ');
      addText(button, 'span', meta, 'brain-note-meta');
      button.addEventListener('click', () => openNote(item.noteId));
      row.append(button);
      list.append(row);
    }
    $('[data-list-empty]').hidden = list.childElementCount > 0;
  }
  function timestampShort(value) {
    if ((typeof value !== 'string' && typeof value !== 'number') || !value || !Number.isFinite(typeof value === 'number' ? value : Date.parse(value))) return '';
    const parsed = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(parsed.valueOf()) ? '' : parsed.toLocaleDateString();
  }
  function renderNotePage(data, append = false) {
    if (!data || !Array.isArray(data.notes)) throw new Error('The vault returned an invalid note page.');
    notes = append ? notes.concat(data.notes) : data.notes.slice();
    cursor = typeof data.nextCursor === 'string' && data.nextCursor ? data.nextCursor : null;
    renderNoteRows(data.notes, append);
    moreButton.hidden = !cursor;
    $('[data-results-title]').textContent = mode === 'search' ? 'Search results' : 'Recent notes';
  }
  function renderSummary(summary) {
    if (!summary || !summary.coverage) throw new Error('Vault summary is unavailable.');
    $('[data-count-notes]').textContent = safeCount(summary.noteCount);
    $('[data-count-links]').textContent = safeCount(summary.linkCount);
    $('[data-count-unresolved]').textContent = safeCount(summary.unresolvedLinkCount);
    $('[data-count-drafts]').textContent = safeCount(summary.draftCount);
    $('[data-vault-state]').textContent = statusText(summary.state);
    $('[data-vault-observed]').textContent = timestamp(summary.observedAt);
    const coverage = summary.coverage;
    $('[data-coverage]').textContent = coverage && Number.isSafeInteger(coverage.scanned) && Number.isSafeInteger(coverage.limit)
      ? `Index coverage: ${coverage.scanned} of ${coverage.limit} notes scanned${coverage.partial ? ' · partial view' : ''}.`
      : 'Index coverage is not reported.';
  }
  function renderRelationships(listSelector, rows, targetField = 'toNoteId', unresolved = false) {
    const target = $(listSelector);
    target.replaceChildren();
    for (const link of Array.isArray(rows) ? rows : []) {
      if (!link || (unresolved ? typeof link.label !== 'string' : typeof link[targetField] !== 'string')) continue;
      const item = document.createElement('li');
      if (unresolved) addText(item, 'span', link.label + ' · unresolved');
      else {
        const button = document.createElement('button');
        button.type = 'button';
        button.textContent = typeof link.label === 'string' ? link.label : 'Open linked note';
        button.addEventListener('click', () => openNote(link[targetField]));
        item.append(button);
      }
      target.append(item);
    }
    if (!target.childElementCount) addText(target, 'li', unresolved ? 'No unresolved links.' : 'No linked notes.');
  }
  async function openNote(noteId) {
    if (stopped || busy) return;
    busy = true;
    currentNoteId = noteId;
    setGraphSelection();
    renderNoteRows(notes);
    $('[data-reader-title]').textContent = 'Loading note…';
    body.textContent = '';
    renderRelationships('[data-note-links]', []);
    renderRelationships('[data-note-backlinks]', []);
    renderRelationships('[data-note-unresolved]', [], null, true);
    try {
      const encoded = encodedId(noteId);
      const [note, links] = await Promise.all([
        api.get(apiRoot + '/notes/' + encoded),
        api.get(apiRoot + '/notes/' + encoded + '/links')
      ]);
      if (stopped) return;
      if (!note || note.noteId !== noteId || typeof note.markdown !== 'string') throw new Error('This note is unavailable.');
      $('[data-reader-title]').textContent = typeof note.title === 'string' ? note.title : 'Untitled note';
      const summary = notes.find(item => item && item.noteId === noteId);
      const noteMetadata = [timestampShort(note.updatedAt), summary && Array.isArray(summary.tags) && summary.tags.length ? 'Tags: ' + summary.tags.join(', ') : 'Uncategorized', typeof note.contentSha256 === 'string' ? 'SHA-256 ' + note.contentSha256 : 'Content digest unavailable'].filter(Boolean);
      $('[data-reader-meta]').textContent = noteMetadata.join(' · ');
      body.textContent = note.markdown;
      renderRelationships('[data-note-links]', links && links.links, 'toNoteId');
      renderRelationships('[data-note-backlinks]', links && links.backlinks, 'fromNoteId');
      renderRelationships('[data-note-unresolved]', links && links.unresolved, null, true);
      $('[data-reader-title]').focus({preventScroll: true});
      $('.brain-reader').scrollIntoView({block: 'start', behavior: 'auto'});
      updateStatus('Opened ' + (typeof note.title === 'string' ? note.title : 'note') + '.');
    } catch (_) {
      if (!stopped) {
        $('[data-reader-title]').textContent = 'Note unavailable';
        body.textContent = 'The selected note or its link index could not be loaded.';
        updateStatus('This note or its link index is temporarily unavailable.', true);
      }
    } finally { busy = false; }
  }
  async function refreshNotes(append = false) {
    if (stopped || busy) return;
    busy = true;
    refreshButton.disabled = true;
    searchButton.disabled = true;
    moreButton.disabled = true;
    try {
      const data = await api.get(listRoute(append ? cursor : null));
      if (stopped) return;
      renderNotePage(data, append);
      updateStatus(mode === 'search' ? 'Search complete.' : 'Vault notes refreshed.');
    } catch (_) {
      if (!stopped) updateStatus('The vault note list is temporarily unavailable.', true);
    } finally {
      busy = false;
      if (!stopped) { refreshButton.disabled = false; searchButton.disabled = false; moreButton.disabled = false; }
    }
  }
  async function refreshSummary() {
    try {
      const data = await api.get(apiRoot + '/overview');
      if (!stopped) renderSummary(data);
    } catch (_) {
      if (!stopped) {
        $('[data-vault-state]').textContent = 'unavailable';
        $('[data-coverage]').textContent = 'The private vault summary is temporarily unavailable.';
      }
    }
  }
  function noteTags(node) {
    return Array.isArray(node.tags) ? [...new Set(node.tags.filter(tag => typeof tag === 'string' && tag.trim()).map(tag => tag.trim()))] : [];
  }
  function tagCategory(node) { return noteTags(node)[0] || 'Uncategorized'; }
  function tagColor(tag) {
    let hash = 2166136261;
    for (const character of tag) hash = Math.imul(hash ^ character.charCodeAt(0), 16777619);
    return `hsl(${(hash >>> 0) % 360} 76% 66%)`;
  }
  function graphTransform() { graphScene.setAttribute('transform', `translate(${graphPanX} ${graphPanY}) scale(${graphScale})`); }
  function graphCategories(nodes) {
    const categories = new Set();
    for (const node of nodes) {
      const tags = noteTags(node);
      if (tags.length) tags.forEach(tag => categories.add(tag));
      else categories.add('Uncategorized');
    }
    return [...categories].sort((a, b) => a.localeCompare(b));
  }
  function renderGraphLegend(categories) {
    graphLegend.replaceChildren();
    const allButton = document.createElement('button');
    allButton.type = 'button'; allButton.setAttribute('aria-pressed', selectedTags === null ? 'true' : 'false');
    addText(allButton, 'span', 'All tags');
    allButton.addEventListener('click', () => { selectedTags = null; renderGraph(graphData); });
    graphLegend.append(allButton);
    for (const category of categories) {
      const button = document.createElement('button'); button.type = 'button';
      button.setAttribute('aria-pressed', selectedTags === null || selectedTags.has(category) ? 'true' : 'false');
      const swatch = addText(button, 'span', '', 'brain-legend-dot');
      swatch.style.setProperty('--tag-color', tagColor(category));
      addText(button, 'span', category);
      button.addEventListener('click', () => {
        if (selectedTags === null) selectedTags = new Set(categories);
        if (selectedTags.has(category)) selectedTags.delete(category); else selectedTags.add(category);
        renderGraph(graphData);
      });
      graphLegend.append(button);
    }
  }
  function graphNoteButton(parent, node, label) {
    const button = document.createElement('button'); button.type = 'button';
    button.textContent = label; button.addEventListener('click', () => openNote(node.noteId)); parent.append(button); return button;
  }
  function graphLayout(nodes, edges) {
    const positions = new Map(), forces = new Map();
    nodes.forEach((node, index) => {
      const angle = index * 2.399963229728653;
      const radius = nodes.length < 2 ? 0 : 210 * Math.sqrt((index + .5) / nodes.length);
      positions.set(node.noteId, {x: 500 + Math.cos(angle) * radius, y: 310 + Math.sin(angle) * radius});
    });
    const links = edges.filter(edge => positions.has(edge.fromNoteId) && positions.has(edge.toNoteId)
      && edge.fromNoteId !== edge.toNoteId);
    const spacing = Math.min(108, Math.max(48, 720 / Math.sqrt(Math.max(nodes.length, 1))));
    for (let iteration = 0; iteration < 52; iteration++) {
      forces.clear();
      for (const node of nodes) forces.set(node.noteId, {x: 0, y: 0});
      for (let left = 0; left < nodes.length; left++) {
        const a = positions.get(nodes[left].noteId), fa = forces.get(nodes[left].noteId);
        for (let right = left + 1; right < nodes.length; right++) {
          const b = positions.get(nodes[right].noteId), fb = forces.get(nodes[right].noteId);
          let dx = a.x - b.x, dy = a.y - b.y;
          const distance = Math.max(1, Math.hypot(dx, dy));
          const push = Math.min(3.4, 560 / (distance * distance));
          dx = dx / distance * push; dy = dy / distance * push;
          fa.x += dx; fa.y += dy; fb.x -= dx; fb.y -= dy;
        }
      }
      for (const edge of links) {
        const a = positions.get(edge.fromNoteId), b = positions.get(edge.toNoteId);
        const fa = forces.get(edge.fromNoteId), fb = forces.get(edge.toNoteId);
        let dx = b.x - a.x, dy = b.y - a.y;
        const distance = Math.max(1, Math.hypot(dx, dy));
        const pull = Math.min(2.4, (distance - spacing) * .012);
        dx = dx / distance * pull; dy = dy / distance * pull;
        fa.x += dx; fa.y += dy; fb.x -= dx; fb.y -= dy;
      }
      const cooling = 1 - iteration / 58;
      for (const node of nodes) {
        const point = positions.get(node.noteId), force = forces.get(node.noteId);
        point.x = Math.max(45, Math.min(955, point.x + force.x * cooling));
        point.y = Math.max(45, Math.min(575, point.y + force.y * cooling));
      }
    }
    return positions;
  }
  function graphTagArcs(group, node, point) {
    const tags = noteTags(node).slice(0, 6);
    if (tags.length < 2) return;
    const step = 360 / tags.length, gap = Math.min(8, step / 4);
    tags.forEach((tag, index) => {
      const start = (-90 + index * step + gap / 2) * Math.PI / 180;
      const end = (-90 + (index + 1) * step - gap / 2) * Math.PI / 180;
      const x1 = point.x + 24 * Math.cos(start), y1 = point.y + 24 * Math.sin(start);
      const x2 = point.x + 24 * Math.cos(end), y2 = point.y + 24 * Math.sin(end);
      const arc = document.createElementNS(SVG, 'path');
      arc.setAttribute('class', 'brain-tag-arc');
      arc.setAttribute('d', `M ${x1} ${y1} A 24 24 0 0 1 ${x2} ${y2}`);
      arc.setAttribute('stroke', tagColor(tag)); arc.setAttribute('aria-hidden', 'true'); group.append(arc);
    });
  }
  function setGraphSelection() {
    graphScene.querySelectorAll('.brain-node').forEach(node => {
      const selected = node.getAttribute('data-note-id') === currentNoteId;
      node.setAttribute('aria-current', selected ? 'true' : 'false');
    });
  }
  function renderGraph(data) {
    if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges) || !Array.isArray(data.unresolved)) throw new Error('The vault graph returned an invalid snapshot.');
    graphData = data;
    graphScene.replaceChildren(); graphList.replaceChildren();
    const allNodes = data.nodes.filter(node => node && typeof node.noteId === 'string' && typeof node.title === 'string');
    const categories = graphCategories(allNodes);
    if (selectedTags !== null) for (const tag of [...selectedTags]) if (!categories.includes(tag)) selectedTags.delete(tag);
    renderGraphLegend(categories);
    const nodes = allNodes.filter(node => selectedTags === null || (noteTags(node).length ? noteTags(node).some(tag => selectedTags.has(tag)) : selectedTags.has('Uncategorized')));
    const ids = new Set(nodes.map(node => node.noteId));
    const edges = data.edges.filter(edge => edge && ids.has(edge.fromNoteId) && ids.has(edge.toNoteId));
    $('[data-graph-status]').textContent = allNodes.length
      ? `${nodes.length} of ${allNodes.length} indexed notes shown · ${edges.length} actual note links · ${data.unresolved.length} unresolved references${data.partial ? ' · partial coverage' : ''}. Colors and filters use note tags; only resolved vault links are drawn.`
      : 'No notes are present in this vault snapshot yet.';
    if (!nodes.length) { addText(graphList, 'li', 'No notes match these tag filters.'); return; }
    const positions = graphLayout(nodes, edges);
    const markerIds = new Map(), defs = document.createElementNS(SVG, 'defs');
    function markerFor(color) {
      if (markerIds.has(color)) return markerIds.get(color);
      const id = `brain-arrow-${markerIds.size}`;
      const marker = document.createElementNS(SVG, 'marker');
      marker.setAttribute('id', id); marker.setAttribute('viewBox', '0 0 8 8');
      marker.setAttribute('markerWidth', '8'); marker.setAttribute('markerHeight', '8');
      marker.setAttribute('markerUnits', 'userSpaceOnUse'); marker.setAttribute('refX', '7');
      marker.setAttribute('refY', '4'); marker.setAttribute('orient', 'auto');
      const head = document.createElementNS(SVG, 'path');
      head.setAttribute('d', 'M 0 0 L 8 4 L 0 8 z'); head.setAttribute('fill', color);
      marker.append(head); defs.append(marker); markerIds.set(color, id); return id;
    }
    graphScene.append(defs);
    for (const edge of edges) {
      const from = positions.get(edge.fromNoteId), to = positions.get(edge.toNoteId);
      const fromNode = nodes.find(node => node.noteId === edge.fromNoteId), toNode = nodes.find(node => node.noteId === edge.toNoteId);
      if (!from || !to || !fromNode || !toNode) continue;
      const dx = to.x - from.x, dy = to.y - from.y;
      const distance = Math.max(1, Math.hypot(dx, dy));
      const ux = dx / distance, uy = dy / distance;
      const sourceOffset = Math.min(22, distance * .32), targetOffset = Math.min(28, distance * .42);
      const path = document.createElementNS(SVG, 'path');
      path.setAttribute('d', `M ${from.x + ux * sourceOffset} ${from.y + uy * sourceOffset} L ${to.x - ux * targetOffset} ${to.y - uy * targetOffset}`);
      const color = tagColor(tagCategory(fromNode));
      path.setAttribute('class', 'brain-edge'); path.setAttribute('fill', 'none');
      path.setAttribute('data-link-kind', edge.kind === 'markdown' ? 'markdown' : 'wikilink');
      path.setAttribute('stroke', color); path.setAttribute('marker-end', `url(#${markerFor(color)})`);
      const description = document.createElementNS(SVG, 'title');
      description.textContent = `${fromNode.title} links to ${toNode.title} (${edge.kind === 'markdown' ? 'Markdown link' : 'Obsidian wikilink'})`;
      path.append(description); graphScene.append(path);
      const item = document.createElement('li');
      graphNoteButton(item, fromNode, fromNode.title);
      addText(item, 'span', ` links to · ${typeof edge.kind === 'string' ? edge.kind : 'vault link'} · `);
      graphNoteButton(item, toNode, toNode.title); graphList.append(item);
    }
    if (!edges.length) addText(graphList, 'li', 'No resolved links match these tag filters.');
    for (const node of nodes) {
      const point = positions.get(node.noteId), category = tagCategory(node), group = document.createElementNS(SVG, 'g');
      group.setAttribute('class', 'brain-node'); group.setAttribute('tabindex', '0'); group.setAttribute('role', 'button');
      const tags = noteTags(node);
      const tagLabel = tags.length ? tags.slice(0, 6).join(', ') + (tags.length > 6 ? `, and ${tags.length - 6} more` : '') : 'Uncategorized';
      group.setAttribute('aria-label', `Open note ${node.title}; tags ${tagLabel}`);
      group.setAttribute('data-note-id', node.noteId); group.setAttribute('aria-current', 'false');
      group.style.setProperty('--tag-color', tagColor(category));
      const circle = document.createElementNS(SVG, 'circle'); circle.setAttribute('cx', String(point.x)); circle.setAttribute('cy', String(point.y)); circle.setAttribute('r', '19'); circle.setAttribute('stroke', tagColor(category)); group.append(circle);
      graphTagArcs(group, node, point);
      const label = document.createElementNS(SVG, 'text'); label.setAttribute('x', String(point.x)); label.setAttribute('y', String(point.y + 32));
      label.textContent = node.title.length > 24 ? node.title.slice(0, 23) + '…' : node.title; group.append(label);
      const activate = () => openNote(node.noteId);
      group.addEventListener('click', activate);
      group.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); activate(); } });
      graphScene.append(group);
    }
    setGraphSelection();
    graphTransform();
  }
  async function refreshGraph() {
    if (stopped) return;
    graphRefreshButton.disabled = true;
    try {
      const data = await api.get(apiRoot + '/graph');
      if (!stopped) renderGraph(data);
    } catch (_) {
      if (!stopped) $('[data-graph-status]').textContent = 'The vault graph is temporarily unavailable.';
    } finally { if (!stopped) graphRefreshButton.disabled = false; }
  }
  function setGraphZoom(nextScale) {
    graphScale = Math.max(.55, Math.min(3.5, nextScale)); graphTransform();
  }
  function onZoomIn() { setGraphZoom(graphScale * 1.2); }
  function onZoomOut() { setGraphZoom(graphScale / 1.2); }
  function onZoomReset() { graphScale = 1; graphPanX = 0; graphPanY = 0; graphTransform(); }
  function onGraphPointerDown(event) {
    if (event.target.closest('.brain-node')) return;
    drag = {pointerId: event.pointerId, x: event.clientX, y: event.clientY};
    graph.setPointerCapture(event.pointerId);
  }
  function onGraphPointerMove(event) {
    if (!drag || drag.pointerId !== event.pointerId) return;
    const rect = graph.getBoundingClientRect();
    graphPanX += (event.clientX - drag.x) * 1000 / rect.width / graphScale;
    graphPanY += (event.clientY - drag.y) * 620 / rect.height / graphScale;
    drag.x = event.clientX; drag.y = event.clientY; graphTransform();
  }
  function onGraphPointerUp(event) {
    if (!drag || drag.pointerId !== event.pointerId) return;
    drag = null;
    if (graph.hasPointerCapture(event.pointerId)) graph.releasePointerCapture(event.pointerId);
  }
  function onGraphWheel(event) { event.preventDefault(); setGraphZoom(graphScale * (event.deltaY < 0 ? 1.12 : 1 / 1.12)); }
  function onGraphKeydown(event) {
    if (event.target !== graph) return;
    if (event.key === '+' || event.key === '=') { event.preventDefault(); onZoomIn(); }
    else if (event.key === '-' || event.key === '_') { event.preventDefault(); onZoomOut(); }
    else if (event.key === '0') { event.preventDefault(); onZoomReset(); }
    else if (event.key.startsWith('Arrow')) {
      event.preventDefault(); const shift = event.shiftKey ? 48 : 20;
      if (event.key === 'ArrowLeft') graphPanX += shift;
      if (event.key === 'ArrowRight') graphPanX -= shift;
      if (event.key === 'ArrowUp') graphPanY += shift;
      if (event.key === 'ArrowDown') graphPanY -= shift;
      graphTransform();
    }
  }
  graph.addEventListener('pointerdown', onGraphPointerDown);
  graph.addEventListener('pointermove', onGraphPointerMove);
  graph.addEventListener('pointerup', onGraphPointerUp);
  graph.addEventListener('pointercancel', onGraphPointerUp);
  graph.addEventListener('wheel', onGraphWheel, {passive: false});
  graph.addEventListener('keydown', onGraphKeydown);
  zoomInButton.addEventListener('click', onZoomIn);
  zoomOutButton.addEventListener('click', onZoomOut);
  zoomResetButton.addEventListener('click', onZoomReset);
  function onSearch(event) {
    event.preventDefault();
    if (!queryInput.value.trim()) { mode = 'recent'; cursor = null; refreshNotes(); return; }
    mode = 'search'; cursor = null; refreshNotes();
  }
  function onRefresh() { mode = 'recent'; cursor = null; refreshNotes(); refreshSummary(); }
  function onMore() { if (cursor) refreshNotes(true); }
  $('[data-search-form]').addEventListener('submit', onSearch);
  refreshButton.addEventListener('click', onRefresh);
  moreButton.addEventListener('click', onMore);
  graphRefreshButton.addEventListener('click', refreshGraph);
  refreshSummary(); refreshNotes(); refreshGraph();
  return function cleanup() {
    stopped = true;
    $('[data-search-form]').removeEventListener('submit', onSearch);
    refreshButton.removeEventListener('click', onRefresh);
    moreButton.removeEventListener('click', onMore);
    graphRefreshButton.removeEventListener('click', refreshGraph);
    graph.removeEventListener('pointerdown', onGraphPointerDown);
    graph.removeEventListener('pointermove', onGraphPointerMove);
    graph.removeEventListener('pointerup', onGraphPointerUp);
    graph.removeEventListener('pointercancel', onGraphPointerUp);
    graph.removeEventListener('wheel', onGraphWheel);
    graph.removeEventListener('keydown', onGraphKeydown);
    zoomInButton.removeEventListener('click', onZoomIn);
    zoomOutButton.removeEventListener('click', onZoomOut);
    zoomResetButton.removeEventListener('click', onZoomReset);
  };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="second-brain",
    nav_label="Second brain",
    title="Second brain",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/second-brain/overview"),
        ("GET", "/chat/api/second-brain/notes"),
        ("GET", "/chat/api/second-brain/search"),
        ("GET", "/chat/api/second-brain/notes/{note_id}"),
        ("GET", "/chat/api/second-brain/notes/{note_id}/links"),
        ("GET", "/chat/api/second-brain/graph"),
    ),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
