"""Static feature fragment for owner-authored Projects and ordinary project chats."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

_VIEW = """<section class=\"projects-page\" aria-labelledby=\"projects-title\">
  <header class=\"projects-heading\"><p class=\"eyebrow\">YOUR WORKSPACES</p><h1 id=\"projects-title\">Projects</h1>
    <p>Group chats around a shared goal. On verified Codex Responses turns, Jarvis adds this project’s instructions, saved context, recent project-chat excerpts, and selected owner-vault notes through the current root-observed context. Other transports and stale or unavailable context receive no project block; project data never grants permissions.</p></header>
  <div class=\"projects-layout\"><section class=\"projects-list\" aria-labelledby=\"projects-list-title\">
    <div class=\"projects-list-heading\"><h2 id=\"projects-list-title\">Projects</h2><button type=\"button\" data-new>New project</button></div>
    <ul data-project-list aria-label=\"Your projects\"></ul><p data-project-empty hidden>No projects yet. Create one to group chats.</p>
  </section><section class=\"project-editor\" aria-labelledby=\"project-editor-title\">
    <h2 id=\"project-editor-title\" data-editor-title>Create a project</h2>
    <form data-form><label>Project name<input name=\"title\" maxlength=\"120\" required></label>
      <label>Instructions for chats<textarea name=\"instructions\" maxlength=\"8000\" rows=\"4\" placeholder=\"What should Jarvis keep in mind for this project?\"></textarea></label>
      <label>Saved project context<textarea name=\"sharedMemory\" maxlength=\"8000\" rows=\"4\" placeholder=\"Owner-written notes or pointers to selected Obsidian notes\"></textarea></label>
      <label>Obsidian notes to share<select name=\"obsidianNoteIds\" data-notes multiple size=\"6\" aria-describedby=\"projects-notes-status\"></select></label>
      <p class=\"projects-note\" id=\"projects-notes-status\" data-notes-status role=\"status\">Loading notes from your owner vault…</p>
      <div class=\"project-actions\"><button type=\"submit\" data-save>Save project</button>
        <button type=\"button\" data-archive hidden>Delete project</button></div></form>
    <section class=\"project-chats\" aria-labelledby=\"project-chats-title\"><h3 id=\"project-chats-title\">Chats in this project</h3>
      <ul data-chats></ul><p data-chat-empty>Select a project to see its chats.</p>
      <label>Add an existing chat<select data-conversation><option value=\"\">Choose a chat…</option></select></label>
      <button type=\"button\" data-add-chat disabled>Add chat</button></section>
    <section class=\"project-trash\" aria-labelledby=\"project-trash-title\"><h3 id=\"project-trash-title\">Trash</h3>
      <p class=\"projects-note\">Deleted projects are retained here until you restore them. Their chats and Obsidian notes remain available.</p>
      <ul data-trash></ul><p data-trash-empty>No deleted projects.</p></section>
  </section></div><p data-status role=\"status\" aria-live=\"polite\"></p>
</section>"""

_CSS = """
[data-feature-root=\"projects\"] .projects-page{max-width:1120px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"projects\"] .projects-heading{margin-bottom:1.5rem}.projects-heading h1{margin:.35rem 0;font-size:clamp(1.8rem,4vw,2.6rem)}
[data-feature-root=\"projects\"] .projects-heading p:last-child,[data-feature-root=\"projects\"] .projects-note{color:var(--muted,#9bafb4);line-height:1.55;max-width:70ch}
[data-feature-root=\"projects\"] .eyebrow{font-size:.72rem;letter-spacing:.14em;color:var(--accent,#83d9ca);margin:0}
[data-feature-root=\"projects\"] .projects-layout{display:grid;grid-template-columns:minmax(210px,.7fr) minmax(0,1.5fr);gap:1.5rem}
[data-feature-root=\"projects\"] .projects-list,[data-feature-root=\"projects\"] .project-editor{border-top:1px solid var(--border,#294047);padding-top:.8rem;min-width:0}
[data-feature-root=\"projects\"] .projects-list-heading{display:flex;align-items:center;justify-content:space-between;gap:.5rem}
[data-feature-root=\"projects\"] h2,[data-feature-root=\"projects\"] h3{font-size:1rem;margin:.3rem 0 .8rem}
[data-feature-root=\"projects\"] button,[data-feature-root=\"projects\"] input,[data-feature-root=\"projects\"] textarea,[data-feature-root=\"projects\"] select{font:inherit;color:inherit;border:1px solid var(--border,#38515a);border-radius:8px;background:#09191f;padding:.55rem .7rem}
[data-feature-root=\"projects\"] button{cursor:pointer;background:rgba(14,44,52,.75)}[data-feature-root=\"projects\"] button:focus-visible,[data-feature-root=\"projects\"] input:focus-visible,[data-feature-root=\"projects\"] textarea:focus-visible,[data-feature-root=\"projects\"] select:focus-visible{outline:2px solid #8de7eb;outline-offset:2px}
[data-feature-root=\"projects\"] [data-project-list],[data-feature-root=\"projects\"] [data-chats]{list-style:none;margin:0;padding:0}
[data-feature-root=\"projects\"] [data-project-list] li{border-top:1px solid var(--border,#20373e)}[data-feature-root=\"projects\"] [data-project-list] button{width:100%;text-align:left;border:0;background:transparent;padding:.8rem .4rem}
[data-feature-root=\"projects\"] [data-project-list] button[aria-current=true]{color:#aaf7f5;background:rgba(65,198,207,.09)}
[data-feature-root=\"projects\"] form{display:grid;gap:.85rem}[data-feature-root=\"projects\"] label{display:grid;gap:.35rem;font-size:.83rem;color:#b5c9cc}
[data-feature-root=\"projects\"] .projects-note{font-size:.73rem;margin:0}[data-feature-root=\"projects\"] .project-chats,[data-feature-root=\"projects\"] .project-trash{border-top:1px solid var(--border,#294047);margin-top:1.25rem;padding-top:.75rem}
[data-feature-root=\"projects\"] [data-chats] li{padding:.55rem 0;border-top:1px solid var(--border,#20373e)}[data-feature-root=\"projects\"] [data-status]{min-height:1.5em;color:#9bafb4}
[data-feature-root=\"projects\"] [hidden]{display:none!important}
@media(max-width:680px){[data-feature-root=\"projects\"] .projects-layout{grid-template-columns:1fr}}
"""

_MOUNT = r"""function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="projects"]') || container;
  const $ = (selector) => root.querySelector(selector);
  const list = $('[data-project-list]'), empty = $('[data-project-empty]'), trash = $('[data-trash]');
  const trashEmpty = $('[data-trash-empty]');
  const form = $('[data-form]'), status = $('[data-status]'), chatList = $('[data-chats]');
  const chatEmpty = $('[data-chat-empty]'), conversationSelect = $('[data-conversation]');
  const addChat = $('[data-add-chat]'), save = $('[data-save]'), archive = $('[data-archive]');
  let stopped = false, projects = [], selected = null, chats = [], vaultNotes = [];
  const key = () => { const bytes = crypto.getRandomValues(new Uint8Array(24));
    return btoa(String.fromCharCode(...bytes)).replaceAll('+','-').replaceAll('/','_').replaceAll('=',''); };
  const text = (node, value) => { node.textContent = typeof value === 'string' ? value : ''; };
  async function call(path, options = {}) {
    const response = await fetch(path, {credentials:'same-origin', cache:'no-store', ...options});
    if (!response.ok) throw new Error(response.status === 404 ? 'That project or chat is unavailable.' : 'The request could not be completed.');
    return response.status === 204 ? {} : response.json();
  }
  function field(name) { return form.elements.namedItem(name); }
  function selectProject(project) {
    selected = project; form.elements.title.value = project ? project.title : '';
    form.elements.instructions.value = project ? project.instructions : '';
    form.elements.sharedMemory.value = project ? project.sharedMemory : '';
    renderNoteOptions(project ? (project.obsidianNoteIds || []) : []);
    $('[data-editor-title]').textContent = project ? 'Project settings' : 'Create a project';
    save.textContent = project ? 'Save changes' : 'Create project';
    archive.hidden = !project;
    for (const button of list.querySelectorAll('button')) button.setAttribute('aria-current', String(button.dataset.id === (project && project.id)));
    renderChats(project ? project.chats : []);
  }
  function renderNoteOptions(selectedIds) {
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
    $('[data-notes-status]').textContent = vaultNotes.length
      ? 'Choose notes from the current owner vault list. Their current content is added only to a verified Codex Responses turn for this project; other transports and unavailable or stale vault context omit it.'
      : 'The owner vault note list is unavailable; existing links remain saved.';
  }
  function renderChats(items) {
    chatList.replaceChildren();
    for (const chat of items || []) {
      const li = document.createElement('li'), label = document.createElement('span'), remove = document.createElement('button');
      text(label, chat.title || 'Untitled chat'); remove.type = 'button'; remove.textContent = 'Remove';
      remove.addEventListener('click', async () => {
        remove.disabled = true;
        try { await call('/chat/api/conversations/' + encodeURIComponent(chat.id) + '/project',
          {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
           body:JSON.stringify({projectId:null})}); await refresh(); text(status, 'Chat removed from project.'); }
        catch (error) { text(status, error.message || 'Chat could not be moved.'); }
        finally { remove.disabled = false; }
      });
      li.append(label, remove); chatList.append(li);
    }
    chatEmpty.hidden = (items || []).length > 0;
  }
  function render() {
    list.replaceChildren();
    for (const project of projects) { const li = document.createElement('li'), button = document.createElement('button');
      button.type = 'button'; button.dataset.id = project.id; button.textContent = project.title;
      button.addEventListener('click', () => selectProject(project)); li.append(button); list.append(li); }
    empty.hidden = projects.length > 0;
    if (selected) selected = projects.find(item => item.id === selected.id) || null;
    selectProject(selected);
  }
  async function refresh() {
    const [projectData, conversationData, trashData] = await Promise.all([
      call('/chat/api/projects'), call('/chat/api/conversations'), call('/chat/api/projects/trash')]);
    projects = Array.isArray(projectData.projects) ? projectData.projects : [];
    chats = Array.isArray(conversationData.conversations) ? conversationData.conversations : [];
    trash.replaceChildren();
    const deleted = Array.isArray(trashData.projects) ? trashData.projects : [];
    for (const project of deleted) { const li = document.createElement('li'), label = document.createElement('span'), restore = document.createElement('button');
      text(label, project.title); restore.type = 'button'; restore.textContent = 'Restore';
      restore.addEventListener('click', async () => { restore.disabled = true;
        try { await call('/chat/api/projects/' + encodeURIComponent(project.id) + '/restore',
          {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()}, body:JSON.stringify({version:project.version})});
          await refresh(); text(status, 'Project restored with its chats.'); }
        catch (error) { text(status, error.message || 'Project could not be restored.'); }
        finally { restore.disabled = false; }
      }); li.append(label, restore); trash.append(li); }
    trashEmpty.hidden = deleted.length > 0;
    const current = selected && projects.find(item => item.id === selected.id);
    render(); conversationSelect.replaceChildren(new Option('Choose a chat…',''));
    for (const chat of chats) conversationSelect.add(new Option(chat.title || 'Untitled chat', chat.id));
    if (current && current.chats) renderChats(current.chats);
  }
  $('[data-new]').addEventListener('click', () => { selectProject(null); form.elements.title.focus(); });
  form.addEventListener('submit', async event => {
    event.preventDefault(); save.disabled = true; text(status, 'Saving project…');
    const noteIds = Array.from(form.elements.obsidianNoteIds.selectedOptions, option => option.value);
    const payload = {title:form.elements.title.value, instructions:form.elements.instructions.value,
      sharedMemory:form.elements.sharedMemory.value, obsidianNoteIds:noteIds};
    if (selected) payload.version = selected.version;
    try {
      const result = await call(selected ? '/chat/api/projects/' + encodeURIComponent(selected.id) : '/chat/api/projects',
        {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()}, body:JSON.stringify(payload)});
      selected = result.project; await refresh(); text(status, 'Project saved.');
    } catch (error) { text(status, error.message || 'Project could not be saved.'); }
    finally { save.disabled = false; }
  });
  archive.addEventListener('click', async () => {
    if (!selected) return;
    if (!window.confirm('Move this project to Trash? Its chats and linked note references will be retained here.')) return;
    archive.disabled = true; text(status, 'Moving project to Trash…');
    try { await call('/chat/api/projects/' + encodeURIComponent(selected.id) + '/trash',
      {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
       body:JSON.stringify({version:selected.version})});
      selected = null; await refresh(); text(status, 'Project moved to Trash. Its chats remain available in Chats.');
    } catch (error) { text(status, error.message || 'Project could not be deleted.'); }
    finally { archive.disabled = false; }
  });
  conversationSelect.addEventListener('change', () => { addChat.disabled = !selected || !conversationSelect.value; });
  addChat.addEventListener('click', async () => {
    if (!selected || !conversationSelect.value) return;
    addChat.disabled = true; text(status, 'Adding chat…');
    try { await call('/chat/api/conversations/' + encodeURIComponent(conversationSelect.value) + '/project',
      {method:'POST', headers:{'Content-Type':'application/json','Idempotency-Key':key()},
       body:JSON.stringify({projectId:selected.id})});
      conversationSelect.value = ''; await refresh(); text(status, 'Chat added to project.');
    } catch (error) { text(status, error.message || 'Chat could not be added.'); }
    finally { addChat.disabled = !selected; }
  });
  refresh().then(() => text(status, '')).catch(error => text(status, error.message || 'Projects are unavailable.'));
  call('/chat/api/second-brain/notes?limit=50').then(data => {
    vaultNotes = Array.isArray(data.notes) ? data.notes : [];
    renderNoteOptions(selected ? selected.obsidianNoteIds || [] : []);
  }).catch(() => {
    vaultNotes = [];
    renderNoteOptions(selected ? selected.obsidianNoteIds || [] : []);
  });
  return () => { stopped = true; };
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
