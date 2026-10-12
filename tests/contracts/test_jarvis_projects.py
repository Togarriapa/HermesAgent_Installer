from __future__ import annotations

import secrets
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatStore, JarvisChatDenied
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_projects import JarvisProjectConflict, JarvisProjectsStore
from hermes_installer.remote.jarvis_projects_assets import FEATURE_ASSETS


def idem() -> str:
    return secrets.token_urlsafe(24)


def owned_chat(store: JarvisChatStore, subject: str, suffix: str) -> str:
    return store.create_conversation(subject, f"runtime-{suffix}", f"stored-session-{suffix}",
                                     "generation-a")["id"]


def test_project_context_uses_only_actual_saved_messages_and_owner_fields(tmp_path):
    path = tmp_path / "chat.sqlite3"
    chats = JarvisChatStore(path)
    projects = JarvisProjectsStore(chats)
    first = owned_chat(chats, "owner-a", "one")
    second = owned_chat(chats, "owner-a", "two")
    foreign = owned_chat(chats, "owner-b", "three")
    with chats._connect() as db:
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?)", ("m1", first, "user", "launch plan", 1.0))
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?)", ("m2", second, "assistant", "saved answer", 2.0))
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?)", ("m3", foreign, "user", "private foreign text", 3.0))
    payload = {"title": "Launch", "instructions": "Use concise updates.",
               "sharedMemory": "Release target is October.", "obsidianNoteIds": ["release-plan"]}
    project, replay = projects.create("owner-a", idem(), payload)
    assert not replay
    for chat_id in (first, second):
        projects.move_chat("owner-a", chat_id, idem(), {"projectId": project["id"]})
    context = projects.context("owner-a", first)
    assert "Use concise updates." in context
    assert "Release target is October." in context
    assert "launch plan" in context and "saved answer" in context
    assert "private foreign text" not in context
    assert "Selected owner Obsidian note IDs" in context
    assert "release-plan" in projects.list("owner-a")[0]["obsidianNoteIds"]
    assert projects.list("owner-b") == []
    with pytest.raises(JarvisChatDenied):
        projects.context("owner-b", first)
    # The schema and values survive reconstruction of the feature store and chat store.
    reopened = JarvisProjectsStore(JarvisChatStore(path))
    assert reopened.get("owner-a", project["id"])["sharedMemory"] == "Release target is October."


def test_project_idempotency_and_version_compare_and_swap(tmp_path):
    projects = JarvisProjectsStore(JarvisChatStore(tmp_path / "chat.sqlite3"))
    request_key = idem()
    payload = {"title": "Research", "instructions": "", "sharedMemory": "", "obsidianNoteIds": []}
    created, replayed = projects.create("owner-a", request_key, payload)
    again, replayed_again = projects.create("owner-a", request_key, payload)
    assert replayed is False and replayed_again is True
    assert created["id"] == again["id"]
    with pytest.raises(JarvisChatDenied):
        projects.create("owner-a", request_key, {**payload, "title": "Different"})
    update_key = idem()
    updated, replay = projects.update("owner-a", created["id"], update_key,
        {"title": "Research 2", "instructions": "Use primary sources.", "sharedMemory": "",
         "obsidianNoteIds": [], "version": created["version"]})
    assert not replay and updated["version"] == 2
    with pytest.raises(JarvisChatDenied):
        projects.update("owner-a", created["id"], idem(),
            {"title": "Stale", "instructions": "", "sharedMemory": "",
             "obsidianNoteIds": [], "version": created["version"]})
    archived, replay = projects.archive("owner-a", created["id"], idem(), {"version": updated["version"]})
    assert not replay and archived["archived"] is True
    assert projects.list("owner-a") == []
    assert projects.trash("owner-a")[0]["id"] == created["id"]
    restored, replay = projects.restore("owner-a", created["id"], idem(), {"version": archived["version"]})
    assert not replay and restored["archived"] is False and restored["version"] == archived["version"] + 1
    assert projects.get("owner-a", created["id"])["title"] == "Research 2"
    with pytest.raises(JarvisChatDenied):
        projects.update("owner-a", created["id"], idem(),
            {"title": "Archived", "instructions": "", "sharedMemory": "",
             "obsidianNoteIds": [], "version": archived["version"]})


def test_project_chat_move_is_owner_bound_and_idempotency_is_target_bound(tmp_path):
    chats = JarvisChatStore(tmp_path / "chat.sqlite3")
    projects = JarvisProjectsStore(chats)
    first_chat = owned_chat(chats, "owner-a", "one")
    second_chat = owned_chat(chats, "owner-a", "two")
    foreign_chat = owned_chat(chats, "owner-b", "three")
    first = projects.create("owner-a", idem(), {"title":"A", "instructions":"",
        "sharedMemory":"", "obsidianNoteIds":[]})[0]
    second = projects.create("owner-a", idem(), {"title":"B", "instructions":"",
        "sharedMemory":"", "obsidianNoteIds":[]})[0]
    move_key = idem()
    projects.move_chat("owner-a", first_chat, move_key, {"projectId":first["id"]})
    with pytest.raises(JarvisChatDenied):
        projects.move_chat("owner-a", first_chat, move_key, {"projectId":second["id"]})
    with pytest.raises(JarvisChatDenied):
        projects.move_chat("owner-a", foreign_chat, idem(), {"projectId":first["id"]})
    projects.move_chat("owner-a", second_chat, idem(), {"projectId":first["id"]})
    projects.move_chat("owner-a", second_chat, idem(), {"projectId":second["id"]})
    assert [chat["id"] for chat in projects.get("owner-a", second["id"])["chats"]] == [second_chat]


def test_conversation_trash_is_recoverable_and_preserves_chat_and_project_links(tmp_path):
    path = tmp_path / "chat.sqlite3"
    chats = JarvisChatStore(path)
    projects = JarvisProjectsStore(chats)
    conversation_id = owned_chat(chats, "owner-a", "one")
    with chats._connect() as db:
        db.execute("INSERT INTO messages VALUES(?,?,?,?,?)",
                   ("keep-message", conversation_id, "user", "keep this history", 1.0))
    project = projects.create("owner-a", idem(), {"title":"Kept", "instructions":"",
        "sharedMemory":"", "obsidianNoteIds":["note-id-1"]})[0]
    projects.move_chat("owner-a", conversation_id, idem(), {"projectId":project["id"]})
    key = idem()
    trashed, replay = projects.trash_conversation("owner-a", conversation_id, key, 1)
    assert not replay and trashed["deleted"] is True and trashed["version"] == 1
    again, replay = projects.trash_conversation("owner-a", conversation_id, key, 1)
    assert replay and again == trashed
    assert not projects.conversation_is_live("owner-a", conversation_id)
    assert projects.conversation_version("owner-a", conversation_id) == 1
    assert projects.conversation_trash("owner-a")[0]["id"] == conversation_id
    assert projects.visible_conversations("owner-a") == []
    assert projects.conversation_trash("owner-b") == []
    assert projects.get("owner-a", project["id"])["chats"] == []
    assert chats.list_conversations("owner-a") == []
    with pytest.raises(JarvisChatDenied):
        chats.get_conversation("owner-a", conversation_id)
    with pytest.raises(JarvisChatDenied):
        chats.messages("owner-a", conversation_id)
    with pytest.raises(JarvisChatDenied):
        chats.begin_turn("owner-a", conversation_id, "should stay blocked", idem(),
                         ChatPrincipal("owner-a", time.monotonic() + 30,
                                       time.monotonic() + 5, "generation-a"))
    # Hiding a chat is a reversible tombstone; its transcript and selected Obsidian
    # note references remain retained for restoration.
    with chats._connect() as db:
        assert db.execute("SELECT content FROM messages WHERE conversation_id=?",
                          (conversation_id,)).fetchone()[0] == "keep this history"
    assert projects.get("owner-a", project["id"])["obsidianNoteIds"] == ["note-id-1"]
    restored, replay = projects.restore_conversation("owner-a", conversation_id, idem(), 1)
    assert not replay and restored["deleted"] is False and restored["version"] == 2
    assert projects.conversation_is_live("owner-a", conversation_id)
    assert projects.conversation_version("owner-a", conversation_id) == 2
    assert chats.messages("owner-a", conversation_id)[0]["content"] == "keep this history"
    assert projects.get("owner-a", project["id"])["chats"][0]["id"] == conversation_id
    reloaded = JarvisProjectsStore(JarvisChatStore(path))
    assert reloaded.conversation_is_live("owner-a", conversation_id)
    assert reloaded.conversation_version("owner-a", conversation_id) == 2
    reloaded.trash_conversation("owner-a", conversation_id, idem(), 2)
    assert reloaded.conversation_trash("owner-a")[0]["version"] == 3


def test_projects_assets_describe_the_verified_turn_context_boundary():
    validate_feature_assets((FEATURE_ASSETS,))
    assert FEATURE_ASSETS.feature_id == "projects"
    html, js = FEATURE_ASSETS.view_html, FEATURE_ASSETS.mount_js
    assert "sharedMemory" in FEATURE_ASSETS.mount_js
    assert "scope.signal || lifecycle.signal" in FEATURE_ASSETS.mount_js
    assert "scope.isCurrent()" in FEATURE_ASSETS.mount_js
    assert "if (!isCurrent()) return;" in FEATURE_ASSETS.mount_js
    assert "innerHTML" not in FEATURE_ASSETS.mount_js
    assert "data-notes" in html and "data-project-loading" in html and "data-project-error" in html
    assert "data-project-empty" in html and 'aria-busy="true"' in html
    assert "data-project-retry" in html and "data-notes-retry" in html
    assert "/chat/api/second-brain/notes?limit=50" in js
    assert "verified Codex Responses turns" in html
    assert "another transport handles the message, Jarvis leaves it out" in html
    assert "Project notes guide replies; they do not grant access." in html
    assert "Linked notes stay in your Obsidian vault. Removing a link here does not delete a note." in html
    assert "Obsidian notes remain in your vault. Project context is paused while a project is in Trash." in html
    assert "Move this project to Trash? Its chats and note links stay saved" in js
    assert "Open Chats" in html and "Open project ${project.title}" in js
    assert "Moving a chat here changes its project link; it does not combine chat histories." in html
    assert "Move chat to project" in html and "Remove from project" in js
    assert "data-project-loading" in js and "aria-busy" in js and "Projects refreshed." in js
    assert "retry before changing them" in js and "loadVaultNotes" in js
    assert "control.disabled = vaultNotesState !== 'ready'" in js
    assert "projectsLoaded ? 'Refreshing projects…' : 'Loading your projects…'" in js
    assert "const submittedRevision = selectionRevision" in js
    assert "if (selectionRevision === submittedRevision) selectProject(result.project)" in js
    assert "function render()" in js and "else selectProject(null)" in js
    assert "render(); conversationSelect.replaceChildren" in js
    assert "if (chats.some(chat => chat.id === priorConversation)) conversationSelect.value = priorConversation" in js
    assert "selectProject(selected);" not in js
    assert "const targetProjectId = selected.id, submittedRevision = selectionRevision" in js
    assert "if (selectionRevision === submittedRevision) conversationSelect.value = ''" in js
    assert "Chat removed from this project. It remains available in Chats." in js
    assert "projectData.projects" in js and "conversationData.conversations" in js
    assert "call('/chat/api/conversations/' + encodeURIComponent(conversationId) + '/project'" in js
    assert "body:JSON.stringify({projectId:null})" in js


def test_projects_refresh_completes_after_render_for_nonempty_and_empty_results():
    source = FEATURE_ASSETS.mount_js
    refresh = "async function refresh() {" + source.split(
        "async function refresh() {", 1
    )[1].split("\n  async function loadVaultNotes()", 1)[0]
    harness = r'''
function node() { return {hidden:true, disabled:false, textContent:'', value:'',
  setAttribute(){}, replaceChildren(){}, add(){}}; }
async function exercise(projectRows) {
  const projectLoading=node(), trashLoading=node(), trashEmpty=node(), empty=node();
  const projectError=node(), projectsSection=node(), refreshButton=node(), trash=node();
  const conversationSelect=node(), addChat=node();
  let projects=[], chats=[], selected=null, projectsLoaded=false, rendered=0;
  const isCurrent=()=>true;
  const render=()=>{ rendered++; };
  const text=(target,value)=>{ target.textContent=value; };
  const call=async path => {
    if (path === '/chat/api/projects') return {projects:projectRows};
    if (path === '/chat/api/conversations') return {conversations:[]};
    if (path === '/chat/api/projects/trash') return {projects:[]};
    throw new Error('Unexpected read: '+path);
  };
''' + refresh + r'''
  const result = await refresh();
  assert.equal(result, true, 'a successful response must not be reclassified as a refresh failure');
  assert.equal(projectsLoaded, true);
  assert.equal(rendered, 1);
  assert.equal(projectError.hidden, true);
  assert.equal(projectsSection.attributes['aria-busy'], 'false');
  assert.equal(empty.hidden, projectRows.length > 0,
    'the empty-state visibility must match the response after render');
}
const assert = require('node:assert/strict');
global.Option = function(label, value){ this.text=label; this.value=value; };
// Add the attribute recorder used by the production refresh effect.
const originalNode = node;
node = function(){ const value=originalNode(); value.attributes={};
  value.setAttribute=(key,entry)=>{value.attributes[key]=entry;}; return value; };
(async()=>{ await exercise([{id:'p1',title:'One',chats:[]}]); await exercise([]); })()
  .catch(error=>{ console.error(error); process.exitCode=1; });
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "projects-refresh-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_trashing_chat_conflicts_with_active_turn_and_versions_survive_restore(tmp_path):
    chats = JarvisChatStore(tmp_path / "chat.sqlite3")
    projects = JarvisProjectsStore(chats)
    conversation_id = owned_chat(chats, "owner-a", "one")
    with chats._connect() as db:
        db.execute("""INSERT INTO turns(id,owner,conversation_id,idempotency_hash,request_hash,status,
            heartbeat_nonce,heartbeat_expiry,jwt_expiry,created,updated)
            VALUES(?,?,?,?,?,'running','nonce',9999999999,9999999999,1,1)""",
            ("turn-one", chats._owner("owner-a"), conversation_id, "idem-hash", "request-hash"))
    with pytest.raises(JarvisProjectConflict):
        projects.trash_conversation("owner-a", conversation_id, idem(), 1)
    assert projects.visible_conversations("owner-a")[0]["version"] == 1
