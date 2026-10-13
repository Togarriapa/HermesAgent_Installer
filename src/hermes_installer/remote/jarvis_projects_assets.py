"""Static feature fragment for owner-authored Projects and ordinary project chats."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

_VIEW = """<section class=\"projects-page\" aria-labelledby=\"projects-title\">
  <header class=\"projects-heading\"><p class=\"eyebrow\">YOUR WORKSPACES</p><h1 id=\"projects-title\">Projects</h1>
    <p>Keep chats for one goal together. Set shared guidance and notes for each project.</p>
    <details class=\"project-context-guidance\"><summary>When does Jarvis use shared project notes?</summary>
      <p>On verified Codex Responses turns, Jarvis can include this project’s guidance, shared notes, recent project-chat excerpts and selected Obsidian notes. If the context cannot be checked, or another transport handles the message, Jarvis leaves it out. Project notes guide replies; they do not grant access.</p>
    </details></header>
  <div class=\"projects-layout\"><section class=\"projects-list\" aria-labelledby=\"projects-list-title\" data-projects-section aria-busy=\"true\">
    <div class=\"projects-list-heading\"><h2 id=\"projects-list-title\">Your projects</h2><div class=\"projects-list-actions\"><button type=\"button\" data-refresh aria-label=\"Refresh projects\">Refresh</button><button type=\"button\" data-new>New project</button></div></div>
    <ul data-project-list aria-label=\"Your projects\"></ul><p data-project-loading role=\"status\">Loading your projects…</p>
    <p data-project-empty hidden>No projects yet. Create one to keep chats and notes together.</p>
    <p data-project-error role=\"alert\" hidden>Projects could not be loaded. Check your connection and try again. <button type=\"button\" data-project-retry>Retry</button></p>
  </section><section class=\"project-editor\" aria-labelledby=\"project-editor-title\">
    <h2 id=\"project-editor-title\" data-editor-title tabindex=\"-1\">Create a project</h2>
    <form data-form><label>Project name<input name=\"title\" maxlength=\"120\" required></label>
      <label>Guidance for project chats<textarea name=\"instructions\" maxlength=\"8000\" rows=\"4\" placeholder=\"What should Jarvis keep in mind for these chats?\"></textarea></label>
      <label>Shared notes<textarea name=\"sharedMemory\" maxlength=\"8000\" rows=\"4\" placeholder=\"Notes to carry between chats in this project\"></textarea></label>
      <section class=\"project-knowledge\" aria-labelledby=\"project-knowledge-title\">
        <h3 id=\"project-knowledge-title\">Owner vault notes</h3>
        <p class=\"projects-note\">Browse recent notes or search your owner vault. Browsing and previewing never changes this project.</p>
        <div class=\"project-note-search\" data-note-search role=\"search\">
          <label for=\"project-note-query\">Find a note</label><input id=\"project-note-query\" type=\"search\" maxlength=\"256\" autocomplete=\"off\" data-note-query>
          <button type=\"button\" data-note-search-submit>Search</button><button type=\"button\" data-note-browse>Browse recent</button>
        </div>
        <p class=\"projects-note\" id=\"projects-notes-status\" data-notes-status role=\"status\">Loading notes from your owner vault…</p>
        <button class=\"notes-retry\" type=\"button\" data-notes-retry hidden>Retry loading notes</button>
        <ul class=\"project-note-results\" data-note-results aria-label=\"Owner vault note results\"></ul>
        <p class=\"projects-note\" data-note-empty hidden>No notes match this view.</p>
        <button class=\"notes-retry\" type=\"button\" data-note-more hidden>Load more notes</button>
        <h4>Selected project notes</h4><ul class=\"project-note-chips\" data-note-selected aria-label=\"Selected project note links\"></ul>
        <section class=\"project-note-preview\" data-note-preview aria-labelledby=\"project-note-preview-title\" hidden>
          <h4 id=\"project-note-preview-title\" data-preview-title tabindex=\"-1\">Note preview</h4>
          <p class=\"projects-note\" data-preview-meta></p><pre data-preview-markdown></pre>
          <p class=\"projects-note\" data-preview-status role=\"status\"></p>
        </section>
      </section>
      <p class=\"projects-note project-retention\" id=\"projects-note-retention\">Linked notes stay in your Obsidian vault. Removing a link here does not delete a note.</p>
      <div class=\"project-actions\"><button type=\"submit\" data-save>Save project</button><button type=\"button\" data-cancel>Cancel</button>
        <button type=\"button\" data-save-recovery hidden>Resolve save result</button>
        <button type=\"button\" data-archive hidden>Move to Trash</button></div></form>
    <section class=\"project-chats\" aria-labelledby=\"project-chats-title\"><div class=\"project-chats-heading\"><h3 id=\"project-chats-title\">Chats in this project</h3><button type=\"button\" data-view=\"chat\">Open Chats</button></div>
      <ul data-chats></ul><p data-chat-empty>Select a project to see its chats.</p>
      <p class=\"projects-note\">Open a conversation from Chats. Moving a chat here changes its project link; it does not combine chat histories.</p>
      <label>Move an existing chat here<select data-conversation disabled><option value=\"\">Choose a chat…</option></select></label>
      <button type=\"button\" data-add-chat disabled>Move chat to project</button></section>
    <section class=\"project-trash\" aria-labelledby=\"project-trash-title\"><h3 id=\"project-trash-title\">Trash</h3>
      <p class=\"projects-note\">Projects in Trash can be restored. Their chat history and note links stay saved; Obsidian notes remain in your vault. Project context is paused while a project is in Trash.</p>
      <ul data-trash></ul><p data-trash-loading role=\"status\">Loading Trash…</p><p data-trash-empty hidden>No projects in Trash.</p></section>
  </section></div><p data-status role=\"status\" aria-live=\"polite\"></p>
</section>"""

_CSS = """
[data-feature-root=\"projects\"] .projects-page{max-width:1120px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"projects\"] .projects-heading{margin-bottom:1.5rem}[data-feature-root=\"projects\"] .projects-heading h1{margin:.35rem 0;font-size:clamp(1.8rem,4vw,2.6rem)}
[data-feature-root=\"projects\"] .projects-heading>p,[data-feature-root=\"projects\"] .projects-note{color:var(--muted,#9bafb4);line-height:1.55;max-width:70ch}
[data-feature-root=\"projects\"] .project-context-guidance{max-width:70ch;margin-top:.75rem;color:#bfd0d3;font-size:.82rem;line-height:1.55}
[data-feature-root=\"projects\"] .project-context-guidance summary{width:fit-content;cursor:pointer;color:#a8d9d7}
[data-feature-root=\"projects\"] .project-context-guidance p{margin:.5rem 0 0;color:var(--muted,#9bafb4)}
[data-feature-root=\"projects\"] .eyebrow{font-size:.72rem;letter-spacing:.14em;color:var(--accent,#83d9ca);margin:0}
[data-feature-root=\"projects\"] .projects-layout{display:grid;grid-template-columns:minmax(210px,.7fr) minmax(0,1.5fr);gap:1.5rem}
[data-feature-root=\"projects\"] .projects-list,[data-feature-root=\"projects\"] .project-editor{border-top:1px solid var(--border,#294047);padding-top:.8rem;min-width:0}
[data-feature-root=\"projects\"] .projects-list-heading{display:flex;align-items:center;justify-content:space-between;gap:.5rem}
[data-feature-root=\"projects\"] .projects-list-actions,[data-feature-root=\"projects\"] .project-chats-heading{display:flex;align-items:center;gap:.5rem;min-width:0}
[data-feature-root=\"projects\"] .project-chats-heading{justify-content:space-between}
[data-feature-root=\"projects\"] .projects-list-heading h2,[data-feature-root=\"projects\"] .project-chats-heading h3{min-width:0}
[data-feature-root=\"projects\"] [data-project-loading],[data-feature-root=\"projects\"] [data-project-error]{color:var(--muted,#9bafb4);font-size:.8rem;line-height:1.5}
[data-feature-root=\"projects\"] [data-project-error] button{margin-left:.35rem}
[data-feature-root=\"projects\"] h2,[data-feature-root=\"projects\"] h3{font-size:1rem;margin:.3rem 0 .8rem}
[data-feature-root=\"projects\"] button,[data-feature-root=\"projects\"] input,[data-feature-root=\"projects\"] textarea,[data-feature-root=\"projects\"] select{font:inherit;color:inherit;border:1px solid var(--border,#38515a);border-radius:8px;background:#09191f;padding:.55rem .7rem}
[data-feature-root=\"projects\"] button{cursor:pointer;background:rgba(14,44,52,.75)}[data-feature-root=\"projects\"] button:focus-visible,[data-feature-root=\"projects\"] input:focus-visible,[data-feature-root=\"projects\"] textarea:focus-visible,[data-feature-root=\"projects\"] select:focus-visible{outline:2px solid #8de7eb;outline-offset:2px}
[data-feature-root=\"projects\"] [data-project-list],[data-feature-root=\"projects\"] [data-chats]{list-style:none;margin:0;padding:0}
[data-feature-root=\"projects\"] [data-project-list] li{border-top:1px solid var(--border,#20373e)}[data-feature-root=\"projects\"] [data-project-list] button{display:flex;justify-content:space-between;align-items:center;gap:.75rem;width:100%;min-height:44px;text-align:left;border:0;background:transparent;padding:.8rem .4rem;overflow-wrap:anywhere}
[data-feature-root=\"projects\"] [data-project-list] button small{flex:none;color:var(--muted,#9bafb4);font-size:.68rem}
[data-feature-root=\"projects\"] [data-project-list] button[aria-current=true]{color:#aaf7f5;background:rgba(65,198,207,.09)}
[data-feature-root=\"projects\"] form{display:grid;gap:.85rem}[data-feature-root=\"projects\"] label{display:grid;gap:.35rem;font-size:.83rem;color:#b5c9cc}
[data-feature-root=\"projects\"] .projects-note{font-size:.73rem;margin:0}[data-feature-root=\"projects\"] .project-chats,[data-feature-root=\"projects\"] .project-trash{border-top:1px solid var(--border,#294047);margin-top:1.25rem;padding-top:.75rem}
[data-feature-root=\"projects\"] .project-retention{padding:.5rem .65rem;border-left:2px solid rgba(131,217,202,.45);background:rgba(131,217,202,.045)}
[data-feature-root=\"projects\"] .notes-retry{justify-self:start;min-height:40px;font-size:.76rem}
[data-feature-root=\"projects\"] .project-knowledge{display:grid;gap:.6rem;border-top:1px solid var(--border,#294047);padding-top:.8rem}
[data-feature-root=\"projects\"] .project-knowledge h3,[data-feature-root=\"projects\"] .project-knowledge h4{margin:.2rem 0}
[data-feature-root=\"projects\"] .project-note-search{display:grid;grid-template-columns:minmax(0,1fr) auto auto;align-items:end;gap:.5rem}
[data-feature-root=\"projects\"] .project-note-search label{grid-column:1/-1}
[data-feature-root=\"projects\"] .project-note-results,[data-feature-root=\"projects\"] .project-note-chips{list-style:none;margin:0;padding:0;display:grid;gap:.4rem}
[data-feature-root=\"projects\"] .project-note-results li,[data-feature-root=\"projects\"] .project-note-chips li{display:flex;align-items:center;justify-content:space-between;gap:.55rem;padding:.5rem .6rem;border:1px solid var(--border,#294047);border-radius:8px;min-width:0}
[data-feature-root=\"projects\"] .project-note-results li span,[data-feature-root=\"projects\"] .project-note-chips li span{overflow-wrap:anywhere}
[data-feature-root=\"projects\"] .project-note-row-actions{display:flex;gap:.35rem;flex:none}
[data-feature-root=\"projects\"] .project-note-row-actions button,[data-feature-root=\"projects\"] .project-note-chips button{min-height:38px;font-size:.74rem}
[data-feature-root=\"projects\"] .project-note-preview{border:1px solid var(--border,#294047);border-radius:9px;padding:.7rem;background:rgba(7,22,28,.55);min-width:0}
[data-feature-root=\"projects\"] .project-note-preview pre{max-height:20rem;overflow:auto;margin:.55rem 0 0;white-space:pre-wrap;overflow-wrap:anywhere;font:inherit;font-size:.77rem;line-height:1.55;color:#d7e7e9}
[data-feature-root=\"projects\"] .project-actions{display:flex;flex-wrap:wrap;gap:.5rem}
[data-feature-root=\"projects\"] [data-chats] li{padding:.55rem 0;border-top:1px solid var(--border,#20373e)}[data-feature-root=\"projects\"] [data-status]{min-height:1.5em;color:#9bafb4}
[data-feature-root=\"projects\"] [hidden]{display:none!important}
@media(max-width:680px){[data-feature-root=\"projects\"] .projects-page{padding:1rem}[data-feature-root=\"projects\"] .projects-layout{grid-template-columns:1fr;gap:1rem}[data-feature-root=\"projects\"] .projects-list-actions{gap:.35rem}[data-feature-root=\"projects\"] button{min-height:44px}[data-feature-root=\"projects\"] .projects-list-actions button,[data-feature-root=\"projects\"] .project-chats-heading button{padding-inline:.55rem;font-size:.78rem}[data-feature-root=\"projects\"] .project-editor>h2{scroll-margin-top:1rem}}
@media(max-width:480px){[data-feature-root=\"projects\"] .project-note-search{grid-template-columns:1fr 1fr}[data-feature-root=\"projects\"] .project-note-search label,[data-feature-root=\"projects\"] .project-note-search input{grid-column:1/-1}[data-feature-root=\"projects\"] .project-note-row-actions{flex-wrap:wrap;justify-content:flex-end}}
"""

_MOUNT = r"""function mount(container, api, state, scope = {}) {
  const root = container.querySelector('[data-feature-root="projects"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const list = $('[data-project-list]'), empty = $('[data-project-empty]'), trash = $('[data-trash]');
  const projectsSection = $('[data-projects-section]'), projectLoading = $('[data-project-loading]');
  const projectError = $('[data-project-error]'), refreshButton = $('[data-refresh]');
  const retryProjects = $('[data-project-retry]'), retryNotes = $('[data-notes-retry]');
  const newProject = $('[data-new]');
  const trashEmpty = $('[data-trash-empty]'), trashLoading = $('[data-trash-loading]');
  const form = $('[data-form]'), status = $('[data-status]'), chatList = $('[data-chats]');
  const chatEmpty = $('[data-chat-empty]'), conversationSelect = $('[data-conversation]');
  const addChat = $('[data-add-chat]'), save = $('[data-save]'), archive = $('[data-archive]');
  const noteSearch = $('[data-note-search]'), noteQuery = $('[data-note-query]');
  const noteSearchButton = $('[data-note-search-submit]'), noteBrowse = $('[data-note-browse]');
  const noteResults = $('[data-note-results]'), noteEmpty = $('[data-note-empty]');
  const noteMore = $('[data-note-more]'), noteSelected = $('[data-note-selected]');
  const notePreview = $('[data-note-preview]'), previewTitle = $('[data-preview-title]');
  const previewMeta = $('[data-preview-meta]'), previewMarkdown = $('[data-preview-markdown]');
  const previewStatus = $('[data-preview-status]'), cancel = $('[data-cancel]');
  const saveRecovery = $('[data-save-recovery]');
  let stopped = false, projects = [], selected = null, chats = [], vaultNotes = new Map();
  let selectedNoteIds = new Set(), noteRows = [], noteCursor = null, noteMode = 'recent', noteSearchText = '';
  let vaultNotesState = 'loading', noteReadRevision = 0, previewRevision = 0, selectionRevision = 0, projectRevision = 0;
  let savePending = false, uncertainSave = null;
  let projectsLoaded = false;
  const lifecycle = new AbortController();
  const signal = scope.signal || lifecycle.signal;
  const isCurrent = () => !stopped
    && (typeof scope.isCurrent !== 'function' || scope.isCurrent());
  const key = () => { const bytes = crypto.getRandomValues(new Uint8Array(24));
    return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=',''); };
  const text = (node, value) => { if (isCurrent()) node.textContent = typeof value === 'string' ? value : ''; };
  async function call(path, options = {}) {
    const response = await fetch(path, {credentials:'same-origin', cache:'no-store', signal, ...options});
    if (!response.ok) throw new Error(response.status === 404 ? 'That project or chat is unavailable.' : 'The request could not be completed.');
    return response.status === 204 ? {} : response.json();
  }
  function field(name) { return form.elements.namedItem(name); }
  const normalizeProjectText = value => value.replace(/^[\t\n\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+|[\t\n\r \x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+$/g, '');
  const validNoteId = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);
  function clearPreview(message = '') {
    previewRevision += 1;
    notePreview.hidden = true; previewTitle.textContent = 'Note preview';
    previewMeta.textContent = ''; previewMarkdown.textContent = ''; previewStatus.textContent = message;
  }
  function renderSelectedNotes() {
    if (!isCurrent()) return;
    noteSelected.replaceChildren();
    for (const id of selectedNoteIds) {
      const li = document.createElement('li'), label = document.createElement('span');
      const note = vaultNotes.get(id);
      text(label, note ? note.title : 'Unavailable note reference: ' + id);
      const actions = document.createElement('div'); actions.className = 'project-note-row-actions';
      const preview = document.createElement('button'); preview.type = 'button'; preview.textContent = 'Preview';
      preview.setAttribute('aria-label', 'Preview project note ' + (note ? note.title : id));
      preview.disabled = savePending || Boolean(uncertainSave);
      preview.addEventListener('click', () => { void previewNote(id); }, {signal});
      const remove = document.createElement('button'); remove.type = 'button'; remove.textContent = 'Remove link';
      remove.setAttribute('aria-label', 'Remove project link ' + id);
      remove.disabled = savePending || Boolean(uncertainSave);
      remove.addEventListener('click', () => changeNoteSelection(id, false), {signal});
      actions.append(preview, remove); li.append(label, actions); noteSelected.append(li);
    }
    if (!selectedNoteIds.size) {
      const emptyNote = document.createElement('li'); text(emptyNote, 'No notes are selected for this project.'); noteSelected.append(emptyNote);
    }
  }
  function renderNoteRows() {
    if (!isCurrent()) return;
    noteResults.replaceChildren();
    for (const note of noteRows) {
      const li = document.createElement('li'), label = document.createElement('span');
      text(label, note.title);
      const actions = document.createElement('div'); actions.className = 'project-note-row-actions';
      const preview = document.createElement('button'); preview.type = 'button'; preview.textContent = 'Preview';
      preview.setAttribute('aria-label', 'Preview ' + note.title); preview.disabled = savePending || Boolean(uncertainSave);
      preview.addEventListener('click', () => { void previewNote(note.noteId); }, {signal});
      const linked = selectedNoteIds.has(note.noteId);
      const choose = document.createElement('button'); choose.type = 'button'; choose.textContent = linked ? 'Remove link' : 'Add link';
      choose.setAttribute('aria-pressed', String(linked)); choose.disabled = savePending || Boolean(uncertainSave);
      choose.addEventListener('click', () => changeNoteSelection(note.noteId, !selectedNoteIds.has(note.noteId)), {signal});
      actions.append(preview, choose); li.append(label, actions); noteResults.append(li);
    }
    noteEmpty.hidden = noteRows.length > 0 || vaultNotesState === 'loading';
    noteMore.hidden = !noteCursor || noteRows.length >= 160;
    noteMore.disabled = savePending || Boolean(uncertainSave);
  }
  function changeNoteSelection(noteId, add) {
    if (!isCurrent() || savePending || uncertainSave
        || (add && (!validNoteId(noteId) || !vaultNotes.has(noteId) || selectedNoteIds.size >= 50))) return;
    if (add) selectedNoteIds.add(noteId); else selectedNoteIds.delete(noteId);
    selectionRevision += 1;
    clearPreview('Preview again after changing selected notes.');
    renderSelectedNotes(); renderNoteRows();
  }
  function selectProject(project, moveFocus = false) {
    if (!isCurrent() || savePending || uncertainSave) return;
    projectRevision += 1;
    selectionRevision += 1;
    noteReadRevision += 1;
    clearPreview();
    selected = project; form.elements.title.value = project ? project.title : '';
    form.elements.instructions.value = project ? project.instructions : '';
    form.elements.sharedMemory.value = project ? project.sharedMemory : '';
    selectedNoteIds = new Set(Array.isArray(project && project.obsidianNoteIds)
      ? project.obsidianNoteIds.filter(validNoteId) : []);
    renderSelectedNotes(); renderNoteRows();
    $('[data-editor-title]').textContent = project ? 'Project settings' : 'Create a project';
    save.textContent = project ? 'Save changes' : 'Create project';
    archive.hidden = !project;
    conversationSelect.disabled = !project;
    addChat.disabled = !project;
    conversationSelect.value = '';
    for (const button of list.querySelectorAll('button')) button.setAttribute('aria-current', String(button.dataset.id === (project && project.id)));
    renderChats(project ? project.chats : []);
    if (moveFocus) $('[data-editor-title]').focus({preventScroll:false});
  }
  function renderChats(items) {
    if (!isCurrent()) return;
    chatList.replaceChildren();
    for (const chat of items || []) {
      const li = document.createElement('li'), label = document.createElement('span'), remove = document.createElement('button');
      text(label, chat.title || 'Untitled chat'); remove.type = 'button'; remove.textContent = 'Remove from project';
      remove.addEventListener('click', async () => {
        if (!isCurrent()) return;
        remove.disabled = true;
        try { await call('/chat/api/conversations/' + encodeURIComponent(chat.id) + '/project',
          {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
           body:JSON.stringify({projectId:null})});
          const refreshed = await refresh();
          text(status, refreshed ? 'Chat removed from this project. It remains available in Chats.'
            : 'Chat removed from this project, but the lists could not refresh. Use Refresh to confirm.'); }
        catch (error) { text(status, error.message || 'Chat could not be moved.'); }
        finally { if (isCurrent()) remove.disabled = false; }
      }, {signal});
      li.append(label, remove); chatList.append(li);
    }
    chatEmpty.hidden = (items || []).length > 0;
    chatEmpty.textContent = selected
      ? 'No chats are linked yet. Move an existing chat here or start one from Chats.'
      : 'Select a project to see its chats.';
  }
  function render() {
    if (!isCurrent()) return;
    list.replaceChildren();
    for (const project of projects) { const li = document.createElement('li'), button = document.createElement('button');
      const title = document.createElement('span'), open = document.createElement('small');
      button.type = 'button'; button.dataset.id = project.id; button.disabled = savePending || Boolean(uncertainSave); title.textContent = project.title; open.textContent = 'Open';
      button.append(title, open);
      button.setAttribute('aria-label', `Open project ${project.title}`);
      button.addEventListener('click', () => { if (isCurrent()) selectProject(project, true); }, {signal}); li.append(button); list.append(li); }
    empty.hidden = projects.length > 0 || projectLoading.hidden === false;
    if (selected) {
      const current = projects.find(item => item.id === selected.id);
      if (current) selected = current;
      else selectProject(null);
    }
    for (const button of list.querySelectorAll('button')) button.setAttribute('aria-current', String(button.dataset.id === (selected && selected.id)));
    renderChats(selected ? selected.chats : []);
  }
  async function refresh() {
    if (!isCurrent()) return false;
    projectLoading.hidden = false; projectLoading.textContent = projectsLoaded ? 'Refreshing projects…' : 'Loading your projects…';
    trashLoading.hidden = false; trashEmpty.hidden = true;
    projectError.hidden = true; empty.hidden = true;
    projectsSection.setAttribute('aria-busy', 'true'); refreshButton.disabled = true;
    try {
      const [projectData, conversationData, trashData] = await Promise.all([
        call('/chat/api/projects'), call('/chat/api/conversations'), call('/chat/api/projects/trash')]);
      if (!isCurrent()) return false;
      projects = Array.isArray(projectData.projects) ? projectData.projects : [];
      chats = Array.isArray(conversationData.conversations) ? conversationData.conversations : [];
      projectsLoaded = true;
      trash.replaceChildren();
      const deleted = Array.isArray(trashData.projects) ? trashData.projects : [];
      for (const project of deleted) { const li = document.createElement('li'), label = document.createElement('span'), restore = document.createElement('button');
        text(label, project.title); restore.type = 'button'; restore.textContent = 'Restore';
        restore.addEventListener('click', async () => { if (!isCurrent()) return; restore.disabled = true;
          try {
            await call('/chat/api/projects/' + encodeURIComponent(project.id) + '/restore',
              {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()}, body:JSON.stringify({version:project.version})});
            const refreshed = await refresh();
            text(status, refreshed ? 'Project restored. Its shared context is active again.'
              : 'Project restored, but the lists could not refresh. Use Refresh to confirm.');
          } catch (error) { text(status, error.message || 'Project could not be restored.'); }
          finally { if (isCurrent()) restore.disabled = false; }
        }, {signal}); li.append(label, restore); trash.append(li); }
      trashLoading.hidden = true; trashEmpty.hidden = deleted.length > 0;
      projectLoading.hidden = true; trashLoading.hidden = true; projectsSection.setAttribute('aria-busy', 'false');
      projectError.hidden = true; refreshButton.disabled = false;
      const priorConversation = conversationSelect.value;
      render(); conversationSelect.replaceChildren(new Option('Choose a chat…',''));
      for (const chat of chats) conversationSelect.add(new Option(chat.title || 'Untitled chat', chat.id));
      if (chats.some(chat => chat.id === priorConversation)) conversationSelect.value = priorConversation;
      conversationSelect.disabled = !selected; addChat.disabled = !selected;
      empty.hidden = projects.length > 0;
      return true;
    } catch (_error) {
      if (!isCurrent()) return false;
      projectLoading.hidden = true; trashLoading.hidden = true; trashEmpty.hidden = true;
      projectsSection.setAttribute('aria-busy', 'false');
      refreshButton.disabled = false;
      projectError.hidden = projects.length > 0;
      empty.hidden = true;
      text(status, projects.length ? 'Could not refresh. Showing the last loaded projects.' : '');
      return false;
    }
  }
  function notePagePath(mode, query, cursor) {
    const params = new URLSearchParams({limit:'20'});
    if (mode === 'search') params.set('query', query);
    if (cursor) params.set('cursor', cursor);
    return '/chat/api/second-brain/' + (mode === 'search' ? 'search' : 'notes') + '?' + params.toString();
  }
  async function loadNotePage(mode = noteMode, query = noteSearchText, cursor = null, append = false) {
    if (!isCurrent() || savePending || uncertainSave) return false;
    const requestRevision = ++noteReadRevision;
    const projectId = selected && selected.id || null, capturedProjectRevision = projectRevision;
    noteMode = mode === 'search' && query.trim() ? 'search' : 'recent';
    noteSearchText = noteMode === 'search' ? query.trim().slice(0, 256) : '';
    const requestCursor = append ? noteCursor : null;
    if (append && (!requestCursor || !noteRows.length)) return false;
    if (!append) { noteRows = []; noteCursor = null; }
    vaultNotesState = 'loading'; retryNotes.hidden = true;
    noteMore.disabled = true;
    $('[data-notes-status]').textContent = noteMode === 'search' ? 'Searching your owner vault…' : 'Loading recent owner notes…';
    renderNoteRows();
    const current = () => isCurrent() && requestRevision === noteReadRevision
      && capturedProjectRevision === projectRevision
      && projectId === (selected && selected.id || null);
    try {
      const data = await call(notePagePath(noteMode, noteSearchText, requestCursor));
      if (!current()) return false;
      if (!data || !Array.isArray(data.notes)
          || (data.nextCursor !== null && typeof data.nextCursor !== 'string')) throw new Error('Invalid owner note page.');
      const valid = data.notes.filter(note => note && typeof note.noteId === 'string'
        && validNoteId(note.noteId) && typeof note.title === 'string');
      for (const note of valid) vaultNotes.set(note.noteId, note);
      const rows = append ? noteRows.slice() : [];
      const seen = new Set(rows.map(note => note.noteId));
      for (const note of valid) if (!seen.has(note.noteId) && rows.length < 160) {
        rows.push(note); seen.add(note.noteId);
      }
      noteRows = rows;
      noteCursor = noteRows.length < 160 && typeof data.nextCursor === 'string' && data.nextCursor
        ? data.nextCursor : null;
      vaultNotesState = 'ready';
      const coverage = data.partial === true ? ' The vault reported a partial scan; saved links are unchanged.' : '';
      $('[data-notes-status]').textContent = (noteMode === 'search'
        ? `Search returned ${noteRows.length} notes.` : `Showing ${noteRows.length} recent owner notes.`) + coverage;
      renderNoteRows(); renderSelectedNotes();
      return true;
    } catch (_error) {
      if (!current()) return false;
      vaultNotesState = 'unavailable';
      $('[data-notes-status]').textContent = 'Owner notes could not be loaded. Saved links stay unchanged; retry before adding links.';
      retryNotes.hidden = false;
      renderNoteRows(); renderSelectedNotes();
      return false;
    } finally {
      if (current()) noteMore.disabled = savePending || Boolean(uncertainSave);
    }
  }
  async function previewNote(noteId) {
    if (!isCurrent() || savePending || uncertainSave || !validNoteId(noteId)) return;
    const requestRevision = ++previewRevision;
    const projectId = selected && selected.id || null, projectRevision = selectionRevision;
    const expected = vaultNotes.get(noteId);
    const expectedDigest = expected && typeof expected.contentSha256 === 'string' ? expected.contentSha256 : null;
    const current = () => isCurrent() && requestRevision === previewRevision
      && projectRevision === selectionRevision && projectId === (selected && selected.id || null);
    notePreview.hidden = false; previewTitle.textContent = 'Loading note preview…';
    previewMeta.textContent = ''; previewMarkdown.textContent = ''; previewStatus.textContent = 'Reading this exact owner note…';
    try {
      const note = await call('/chat/api/second-brain/notes/' + encodeURIComponent(noteId));
      if (!current()) return;
      if (!note || note.noteId !== noteId || typeof note.title !== 'string' || typeof note.markdown !== 'string'
          || typeof note.contentSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(note.contentSha256)
          || (expectedDigest && expectedDigest !== note.contentSha256)) throw new Error('The note changed or is unavailable. Refresh the owner note list and try again.');
      if (typeof note.updatedAt !== 'string' && (typeof note.updatedAt !== 'number' || !Number.isFinite(note.updatedAt))) {
        throw new Error('The note returned invalid currentness metadata.');
      }
      previewTitle.textContent = note.title || 'Untitled note';
      previewMeta.textContent = `Updated ${String(note.updatedAt)} · SHA-256 ${note.contentSha256}`;
      previewMarkdown.textContent = note.markdown;
      previewStatus.textContent = 'Plain text preview. Markdown is not rendered and external content is not fetched.';
    } catch (error) {
      if (!current()) return;
      previewTitle.textContent = 'Note preview unavailable';
      previewMarkdown.textContent = '';
      previewStatus.textContent = error.message || 'This owner note could not be verified.';
    } finally { if (current()) previewStatus.setAttribute('aria-busy', 'false'); }
  }
  refreshButton.addEventListener('click', async () => {
    const refreshed = await refresh();
    text(status, refreshed ? 'Projects refreshed.' : 'Projects could not be refreshed.');
  }, {signal});
  retryProjects.addEventListener('click', async () => {
    const refreshed = await refresh();
    if (refreshed) text(status, 'Projects refreshed.');
  }, {signal});
  const searchNotes = () => {
    const query = noteQuery.value.trim();
    void loadNotePage(query ? 'search' : 'recent', query, null, false);
  };
  noteSearchButton.addEventListener('click', searchNotes, {signal});
  noteQuery.addEventListener('keydown', event => { if (event.key === 'Enter') { event.preventDefault(); searchNotes(); } }, {signal});
  noteBrowse.addEventListener('click', () => { noteQuery.value = ''; void loadNotePage('recent', '', null, false); }, {signal});
  retryNotes.addEventListener('click', () => { void loadNotePage(noteMode, noteSearchText, null, false); }, {signal});
  noteMore.addEventListener('click', () => { void loadNotePage(noteMode, noteSearchText, noteCursor, true); }, {signal});
  function cancelProjectDraft() {
    if (!isCurrent() || savePending || uncertainSave) return;
    selectProject(selected); text(status, 'Changes discarded.');
  }
  cancel.addEventListener('click', cancelProjectDraft, {signal});
  newProject.addEventListener('click', () => { if (!isCurrent() || savePending || uncertainSave) return; selectProject(null); form.elements.title.focus(); }, {signal});
  async function submitSnapshot(snapshot) {
    if (!isCurrent() || savePending) return;
    savePending = true; save.disabled = true; saveRecovery.disabled = true;
    text(status, 'Saving project…');
    try {
      const result = await call(snapshot.path, {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':snapshot.key}, body:JSON.stringify(snapshot.payload)});
      if (!isCurrent()) return;
      const project = result && result.project;
      if (!project || typeof project.id !== 'string' || (snapshot.projectId && project.id !== snapshot.projectId)
          || project.title !== snapshot.payload.title
          || project.instructions !== snapshot.payload.instructions || project.sharedMemory !== snapshot.payload.sharedMemory
          || !Array.isArray(project.obsidianNoteIds)
          || JSON.stringify(project.obsidianNoteIds) !== JSON.stringify(snapshot.payload.obsidianNoteIds)
          || snapshot.payload.obsidianNoteIds.length > 50 || !Number.isInteger(project.version)
          || (Number.isInteger(snapshot.payload.version) && project.version !== snapshot.payload.version + 1)) {
        throw new Error('The server returned a different project result. Resolve this Save before submitting again.');
      }
      uncertainSave = null; saveRecovery.hidden = true;
      savePending = false;
      if (selectionRevision === snapshot.revision) selectProject(project);
      await refresh();
      text(status, 'Project saved and confirmed.');
    } catch (error) {
      if (!isCurrent()) return;
      uncertainSave = snapshot; saveRecovery.hidden = false;
      text(status, 'Save result is unknown. Resolve this exact request before another Save; your note links remain unchanged. ' + (error.message || ''));
    } finally {
      if (isCurrent()) {
        savePending = false; save.disabled = Boolean(uncertainSave); saveRecovery.hidden = !uncertainSave;
        saveRecovery.disabled = false; renderSelectedNotes(); renderNoteRows();
      }
    }
  }
  function submitCurrentProject(event) {
    event.preventDefault(); if (!isCurrent() || savePending || uncertainSave) return;
    const payload = {title:normalizeProjectText(form.elements.title.value),
      instructions:normalizeProjectText(form.elements.instructions.value),
      sharedMemory:normalizeProjectText(form.elements.sharedMemory.value), obsidianNoteIds:Array.from(selectedNoteIds)};
    if (payload.obsidianNoteIds.length > 50) { text(status, 'A project can link at most 50 notes. Remove extra links before saving.'); return; }
    const target = selected;
    if (target) payload.version = target.version;
    return submitSnapshot({payload, projectId:target && target.id || null,
      path:target ? '/chat/api/projects/' + encodeURIComponent(target.id) : '/chat/api/projects',
      key:key(), revision:selectionRevision});
  }
  form.addEventListener('submit', submitCurrentProject, {signal});
  async function resolveSaveResult() {
    if (!isCurrent() || savePending || !uncertainSave) return;
    const snapshot = uncertainSave;
    if (!snapshot.projectId) { await submitSnapshot(snapshot); return; }
    savePending = true; save.disabled = true; saveRecovery.disabled = true;
    text(status, 'Reading the project to confirm the previous Save…');
    try {
      const result = await call('/chat/api/projects/' + encodeURIComponent(snapshot.projectId));
      if (!isCurrent() || uncertainSave !== snapshot) return;
      const project = result && (result.project || result);
      if (!project || project.id !== snapshot.projectId) throw new Error('Project readback was not verified.');
      const same = project.title === snapshot.payload.title && project.instructions === snapshot.payload.instructions
        && project.sharedMemory === snapshot.payload.sharedMemory
        && JSON.stringify(project.obsidianNoteIds) === JSON.stringify(snapshot.payload.obsidianNoteIds)
        && Number.isInteger(project.version) && project.version > snapshot.payload.version;
      uncertainSave = null; saveRecovery.hidden = true;
      savePending = false;
      if (selectionRevision === snapshot.revision) {
        selected = project;
        if (same) selectProject(project);
        else { form.elements.title.value = snapshot.payload.title; form.elements.instructions.value = snapshot.payload.instructions;
          form.elements.sharedMemory.value = snapshot.payload.sharedMemory; }
      }
      text(status, same ? 'The previous Save is confirmed by project readback.'
        : 'Readback found a different current project. Review this draft against the current server version before saving again.');
    } catch (error) {
      if (isCurrent()) text(status, 'Project readback failed; keep this request unresolved and retry Resolve. ' + (error.message || ''));
    } finally {
      if (isCurrent()) { savePending = false; save.disabled = Boolean(uncertainSave); saveRecovery.hidden = !uncertainSave; saveRecovery.disabled = false; }
    }
  }
  saveRecovery.addEventListener('click', resolveSaveResult, {signal});
  archive.addEventListener('click', async () => {
    if (!isCurrent() || !selected || savePending || uncertainSave) return;
    if (!window.confirm('Move this project to Trash? Its chats and note links stay saved, Obsidian notes remain in your vault, and project context pauses until you restore it.')) return;
    const archivedProject = selected, submittedRevision = selectionRevision;
    archive.disabled = true; text(status, 'Moving project to Trash…');
    let moved = false;
    try { await call('/chat/api/projects/' + encodeURIComponent(archivedProject.id) + '/trash',
      {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
       body:JSON.stringify({version:archivedProject.version})});
      if (!isCurrent()) return;
      moved = true;
      if (selectionRevision === submittedRevision) selectProject(null);
      const refreshed = await refresh();
      text(status, refreshed ? 'Project moved to Trash. Chat history and Obsidian notes are unchanged; project context is paused.'
        : 'Project moved to Trash, but the lists could not refresh. Use Refresh to confirm.');
    } catch (error) { text(status, moved ? 'Project moved to Trash, but could not refresh the lists.' : error.message || 'Project could not be moved to Trash.'); }
    finally { if (isCurrent()) archive.disabled = false; }
  }, {signal});
  conversationSelect.addEventListener('change', () => { if (isCurrent()) addChat.disabled = !selected || !conversationSelect.value; }, {signal});
  addChat.addEventListener('click', async () => {
    if (!isCurrent() || !selected || !conversationSelect.value || savePending || uncertainSave) return;
    const targetProjectId = selected.id, submittedRevision = selectionRevision;
    const conversationId = conversationSelect.value;
    addChat.disabled = true; text(status, 'Moving chat to project…');
    let moved = false;
    try { await call('/chat/api/conversations/' + encodeURIComponent(conversationId) + '/project',
      {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
       body:JSON.stringify({projectId:targetProjectId})});
      if (!isCurrent()) return;
      moved = true;
      if (selectionRevision === submittedRevision) conversationSelect.value = '';
      const refreshed = await refresh();
      text(status, refreshed ? 'Chat moved to this project. It remains available in Chats.'
        : 'Chat moved, but the lists could not refresh. Use Refresh to confirm.');
    } catch (error) { text(status, moved ? 'Chat moved, but could not refresh the lists.' : error.message || 'Chat could not be moved.'); }
    finally { if (isCurrent()) addChat.disabled = !selected; }
  }, {signal});
  refresh();
  void loadNotePage('recent', '', null, false);
  return () => { stopped = true; lifecycle.abort(); };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="projects", nav_label="Projects", title="Projects", view_html=_VIEW,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/projects"), ("GET", "/chat/api/projects/trash"),
        ("POST", "/chat/api/projects"),
        ("GET", "/chat/api/projects/{project_id}"),
        ("POST", "/chat/api/projects/{project_id}"),
        ("POST", "/chat/api/projects/{project_id}/trash"),
        ("POST", "/chat/api/projects/{project_id}/restore"),
        ("POST", "/chat/api/conversations/{conversation_id}/project"),
        ("GET", "/chat/api/conversations"),
        ("GET", "/chat/api/second-brain/notes"),
        ("GET", "/chat/api/second-brain/search"),
        ("GET", "/chat/api/second-brain/notes/{note_id}"),
        ("GET", "/chat/api/conversations/trash"),
        ("POST", "/chat/api/conversations/{conversation_id}/trash"),
        ("POST", "/chat/api/conversations/{conversation_id}/restore"),
    ),
    mount_js=_MOUNT, unmount_js=_UNMOUNT,
)
