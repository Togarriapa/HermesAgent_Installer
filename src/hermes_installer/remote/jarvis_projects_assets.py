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
      <label>Obsidian notes to include<select name=\"obsidianNoteIds\" data-notes multiple size=\"6\" aria-describedby=\"projects-notes-status projects-note-retention\"></select></label>
      <p class=\"projects-note\" id=\"projects-notes-status\" data-notes-status role=\"status\">Loading notes from your owner vault…</p>
      <button class=\"notes-retry\" type=\"button\" data-notes-retry hidden>Retry loading notes</button>
      <p class=\"projects-note project-retention\" id=\"projects-note-retention\">Linked notes stay in your Obsidian vault. Removing a link here does not delete a note.</p>
      <div class=\"project-actions\"><button type=\"submit\" data-save>Save project</button>
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
[data-feature-root=\"projects\"] [data-chats] li{padding:.55rem 0;border-top:1px solid var(--border,#20373e)}[data-feature-root=\"projects\"] [data-status]{min-height:1.5em;color:#9bafb4}
[data-feature-root=\"projects\"] [hidden]{display:none!important}
@media(max-width:680px){[data-feature-root=\"projects\"] .projects-page{padding:1rem}[data-feature-root=\"projects\"] .projects-layout{grid-template-columns:1fr;gap:1rem}[data-feature-root=\"projects\"] .projects-list-actions{gap:.35rem}[data-feature-root=\"projects\"] button{min-height:44px}[data-feature-root=\"projects\"] .projects-list-actions button,[data-feature-root=\"projects\"] .project-chats-heading button{padding-inline:.55rem;font-size:.78rem}[data-feature-root=\"projects\"] .project-editor>h2{scroll-margin-top:1rem}}
"""

_MOUNT = r"""function mount(container, api, state, scope = {}) {
  const root = container.querySelector('[data-feature-root="projects"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const list = $('[data-project-list]'), empty = $('[data-project-empty]'), trash = $('[data-trash]');
  const projectsSection = $('[data-projects-section]'), projectLoading = $('[data-project-loading]');
  const projectError = $('[data-project-error]'), refreshButton = $('[data-refresh]');
  const retryProjects = $('[data-project-retry]'), retryNotes = $('[data-notes-retry]');
  const trashEmpty = $('[data-trash-empty]'), trashLoading = $('[data-trash-loading]');
  const form = $('[data-form]'), status = $('[data-status]'), chatList = $('[data-chats]');
  const chatEmpty = $('[data-chat-empty]'), conversationSelect = $('[data-conversation]');
  const addChat = $('[data-add-chat]'), save = $('[data-save]'), archive = $('[data-archive]');
  let stopped = false, projects = [], selected = null, chats = [], vaultNotes = [], vaultNotesState = 'loading';
  let projectsLoaded = false, selectionRevision = 0;
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
  function selectProject(project, moveFocus = false) {
    if (!isCurrent()) return;
    selectionRevision += 1;
    selected = project; form.elements.title.value = project ? project.title : '';
    form.elements.instructions.value = project ? project.instructions : '';
    form.elements.sharedMemory.value = project ? project.sharedMemory : '';
    renderNoteOptions(project ? (project.obsidianNoteIds || []) : []);
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
  function renderNoteOptions(selectedIds) {
    if (!isCurrent()) return;
    const control = form.elements.obsidianNoteIds;
    control.replaceChildren();
    const byId = new Map(vaultNotes.map(note => [note.noteId, note]));
    for (const note of vaultNotes) {
      if (!note || typeof note.noteId !== 'string' || typeof note.title !== 'string') continue;
      const option = new Option(note.title, note.noteId);
      option.selected = selectedIds.includes(note.noteId);
      control.add(option);
    }
    for (const id of selectedIds) if (!byId.has(id)) {
      const option = new Option('Unavailable note reference: ' + id, id);
      option.selected = true;
      control.add(option);
    }
    control.disabled = vaultNotesState !== 'ready';
    $('[data-notes-status]').textContent = vaultNotesState === 'loading'
      ? 'Loading notes from your Obsidian vault…'
      : vaultNotesState === 'unavailable'
        ? 'The Obsidian note list could not be loaded. Existing links stay saved; retry before changing them.'
        : vaultNotes.length
          ? 'Select the notes Jarvis should use with this project.'
          : 'No notes were returned by the vault. Existing links stay saved.';
    retryNotes.hidden = vaultNotesState !== 'unavailable';
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
      button.type = 'button'; button.dataset.id = project.id; title.textContent = project.title; open.textContent = 'Open';
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
  async function loadVaultNotes() {
    if (!isCurrent()) return;
    vaultNotesState = 'loading'; retryNotes.hidden = true; retryNotes.disabled = true;
    renderNoteOptions(selected ? selected.obsidianNoteIds || [] : []);
    try {
      const data = await call('/chat/api/second-brain/notes?limit=50');
      if (!isCurrent()) return;
      vaultNotes = Array.isArray(data.notes) ? data.notes : [];
      vaultNotesState = 'ready';
      renderNoteOptions(selected ? selected.obsidianNoteIds || [] : []);
    } catch (_error) {
      if (!isCurrent()) return;
      vaultNotesState = 'unavailable';
      renderNoteOptions(selected ? selected.obsidianNoteIds || [] : []);
    } finally { if (isCurrent()) retryNotes.disabled = false; }
  }
  refreshButton.addEventListener('click', async () => {
    const refreshed = await refresh();
    text(status, refreshed ? 'Projects refreshed.' : 'Projects could not be refreshed.');
  }, {signal});
  retryProjects.addEventListener('click', async () => {
    const refreshed = await refresh();
    if (refreshed) text(status, 'Projects refreshed.');
  }, {signal});
  retryNotes.addEventListener('click', loadVaultNotes, {signal});
  $('[data-new]').addEventListener('click', () => { if (!isCurrent()) return; selectProject(null); form.elements.title.focus(); }, {signal});
  form.addEventListener('submit', async event => {
    event.preventDefault(); if (!isCurrent()) return; save.disabled = true; text(status, 'Saving project…');
    const submittedRevision = selectionRevision;
    const noteIds = Array.from(form.elements.obsidianNoteIds.selectedOptions, option => option.value);
    const payload = {title:form.elements.title.value, instructions:form.elements.instructions.value,
      sharedMemory:form.elements.sharedMemory.value, obsidianNoteIds:noteIds};
    if (selected) payload.version = selected.version;
    let saved = false;
    try {
      const result = await call(selected ? '/chat/api/projects/' + encodeURIComponent(selected.id) : '/chat/api/projects',
        {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()}, body:JSON.stringify(payload)});
      if (!isCurrent()) return;
      if (selectionRevision === submittedRevision) selectProject(result.project);
      saved = true;
      const refreshed = await refresh();
      text(status, refreshed ? 'Project saved.' : 'Project saved, but the lists could not refresh. Use Refresh to confirm.');
    } catch (error) { text(status, saved ? 'Project saved, but could not refresh the lists.' : error.message || 'Project could not be saved.'); }
    finally { if (isCurrent()) save.disabled = false; }
  }, {signal});
  archive.addEventListener('click', async () => {
    if (!isCurrent() || !selected) return;
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
    if (!isCurrent() || !selected || !conversationSelect.value) return;
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
  loadVaultNotes();
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
        ("GET", "/chat/api/conversations/trash"),
        ("POST", "/chat/api/conversations/{conversation_id}/trash"),
        ("POST", "/chat/api/conversations/{conversation_id}/restore"),
    ),
    mount_js=_MOUNT, unmount_js=_UNMOUNT,
)
