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
    assert "data-note-search" in html and "data-note-results" in html and "data-note-preview" in html
    assert "data-note-selected" in html and "data-note-more" in html
    assert "noteSearchButton.addEventListener('click', searchNotes" in js and "noteBrowse.addEventListener" in js
    assert "loadNotePage('recent', '', null, false)" in js
    assert "'/chat/api/second-brain/notes?'" in js and "'/chat/api/second-brain/search?'" in js
    assert "'/chat/api/second-brain/notes/' + encodeURIComponent(noteId)" in js
    assert "noteReadRevision" in js and "capturedProjectRevision === projectRevision" in js
    assert "previewRevision" in js and "expectedDigest !== note.contentSha256" in js
    assert "Plain text preview. Markdown is not rendered and external content is not fetched." in js
    assert "Array.from(selectedNoteIds)" in js and "snapshot.payload" in js
    assert "uncertainSave = snapshot" in js and "Resolve this exact request" in js
    assert "obsidianNoteIds:selectedNoteIds" not in js
    assert "selectedNoteIds.size >= 50" in js and "obsidianNoteIds.length > 50" in js
    assert "/^[A-Za-z0-9_-]{1,96}$/" in js
    assert "project.id !== snapshot.projectId" in js
    assert "normalizeProjectText(form.elements.title.value)" in js
    assert "function cancelProjectDraft()" in js and "cancel.addEventListener('click', cancelProjectDraft" in js
    assert "form.addEventListener('submit', submitCurrentProject" in js
    assert "saveRecovery.addEventListener('click', resolveSaveResult" in js
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
    assert "Saved links stay unchanged; retry before adding links." in js
    assert "projectsLoaded ? 'Refreshing projects…' : 'Loading your projects…'" in js
    assert "revision:selectionRevision" in js
    assert "function render()" in js and "else selectProject(null)" in js
    assert "render(); conversationSelect.replaceChildren" in js
    assert "if (chats.some(chat => chat.id === priorConversation)) conversationSelect.value = priorConversation" in js
    assert "Changes discarded." in js
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
    )[1].split("\n  function notePagePath", 1)[0]
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
(async()=>{ await exercise([{id:'p1',title:'One',chats:[]}]); await exercise([]); console.log('PROJECTS_REFRESH_HARNESS_COMPLETE'); })()
  .catch(error=>{ console.error(error); process.exitCode=1; });
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "projects-refresh-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PROJECTS_REFRESH_HARNESS_COMPLETE" in result.stdout


def test_project_note_page_reads_ignore_aba_success_and_error_and_keep_get_targets():
    source = FEATURE_ASSETS.mount_js
    page_path = "function notePagePath(" + source.split(
        "function notePagePath(", 1
    )[1].split("\n  async function loadNotePage", 1)[0]
    loader = page_path + "\nasync function loadNotePage(" + source.split(
        "async function loadNotePage(", 1
    )[1].split("\n  async function previewNote", 1)[0]
    harness = r'''
const assert = require('node:assert/strict');
let selected={id:'A'}, projectRevision=1, selectionRevision=1, noteReadRevision=0;
let savePending=false, uncertainSave=null, stopped=false, noteMode='recent', noteSearchText='';
let noteRows=[], noteCursor=null, vaultNotesState='loading', vaultNotes=new Map();
const targets=[], pending=[];
const isCurrent=()=>!stopped, retryNotes={hidden:true}, noteMore={disabled:false};
const noteEmpty={hidden:false};
const $=()=>({textContent:''});
const renderNoteRows=()=>{}, renderSelectedNotes=()=>{};
const call=path=>{targets.push(path); return new Promise((resolve,reject)=>pending.push({resolve,reject}));};
''' + loader + r'''
(async()=>{
  const oldA=loadNotePage('recent','',null,false);
  selected={id:'B'}; projectRevision++;
  const staleB=loadNotePage('search','secret',null,false);
  selected={id:'A'}; projectRevision++;
  const currentA=loadNotePage('recent','',null,false);
  assert.deepEqual(targets,['/chat/api/second-brain/notes?limit=20','/chat/api/second-brain/search?limit=20&query=secret','/chat/api/second-brain/notes?limit=20']);
  pending[2].resolve({notes:[{noteId:'owner-note',title:'Current'}],nextCursor:'v1:20'});
  assert.equal(await currentA,true);
  pending[0].reject(new Error('obsolete denial')); assert.equal(await oldA,false);
  pending[1].resolve({notes:[{noteId:'foreign-result',title:'Stale'}],nextCursor:null}); assert.equal(await staleB,false);
  assert.deepEqual(noteRows.map(note=>note.noteId),['owner-note']);
  assert.equal(noteCursor,'v1:20');
  const page=loadNotePage('recent','',noteCursor,true);
  assert.equal(targets[3],'/chat/api/second-brain/notes?limit=20&cursor=v1%3A20');
  pending[3].resolve({notes:[{noteId:'next-note',title:'Next'}],nextCursor:null});
  assert.equal(await page,true); assert.deepEqual(noteRows.map(note=>note.noteId),['owner-note','next-note']);
  console.log('PROJECT_NOTE_READ_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "project-note-read-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PROJECT_NOTE_READ_HARNESS_COMPLETE" in result.stdout


def test_project_note_preview_and_save_effects_are_deferred_and_target_bound():
    source = FEATURE_ASSETS.mount_js
    preview = "async function previewNote(" + source.split(
        "async function previewNote(", 1
    )[1].split("\n  refreshButton.addEventListener", 1)[0]
    submit = "async function submitSnapshot(" + source.split(
        "async function submitSnapshot(", 1
    )[1].split("\n  form.addEventListener('submit'", 1)[0]
    harness = r'''
const assert=require('node:assert/strict');
let selected={id:'project-A'},selectionRevision=1,previewRevision=0,stopped=false;
let savePending=false,uncertainSave=null;
const targets=[],pending=[];
const node=()=>({hidden:true,disabled:false,textContent:'',setAttribute(){}});
const notePreview=node(),previewTitle=node(),previewMeta=node(),previewMarkdown=node(),previewStatus=node();
const vaultNotes=new Map([['note-one',{contentSha256:'a'.repeat(64)}]]);
const isCurrent=()=>!stopped,call=(path,options)=>{targets.push({path,options});return new Promise((resolve,reject)=>pending.push({resolve,reject}));};
const status=node(),save=node(),saveRecovery=node();
const text=(target,value)=>{target.textContent=value;};
const renderSelectedNotes=()=>{},renderNoteRows=()=>{},refresh=async()=>true;
let selectedProject=null;
function selectProject(project){selectedProject=project;}
''' + preview + "\n" + submit + r'''
(async()=>{
  const stale=previewNote('note-one');
  assert.equal(targets[0].path,'/chat/api/second-brain/notes/note-one');
  selected={id:'project-B'};selectionRevision++;
  pending[0].resolve({noteId:'note-one',title:'Stale title',markdown:'stale',contentSha256:'a'.repeat(64),updatedAt:1});
  await stale;assert.equal(previewMarkdown.textContent,'');
  selected={id:'project-A'};selectionRevision++;
  const current=previewNote('note-one');
  pending[1].resolve({noteId:'note-one',title:'Current',markdown:'<script>literal</script>',contentSha256:'a'.repeat(64),updatedAt:2});
  await current;assert.equal(previewTitle.textContent,'Current');
  assert.equal(previewMarkdown.textContent,'<script>literal</script>');
  assert.equal(Object.hasOwn(previewMarkdown,'innerHTML'),false);
  const foreign=previewNote('note-one');
  pending[2].resolve({noteId:'another-owner-note',title:'Foreign',markdown:'private',contentSha256:'a'.repeat(64),updatedAt:3});
  await foreign;assert.equal(previewMarkdown.textContent,'');
  assert.match(previewStatus.textContent,/unavailable|verified/i);
  const changed=previewNote('note-one');
  pending[3].resolve({noteId:'note-one',title:'Changed digest',markdown:'do not show',contentSha256:'b'.repeat(64),updatedAt:4});
  await changed;assert.equal(previewMarkdown.textContent,'');assert.match(previewStatus.textContent,/changed|unavailable/i);
  const snapshot={projectId:'project-A',path:'/chat/api/projects/project-A',key:'same-idempotency-key',revision:selectionRevision,
    payload:{title:'Name',instructions:'Guidance',sharedMemory:'Memory',obsidianNoteIds:['note-one'],version:4}};
  assert.equal(targets.filter(item=>item.options&&item.options.method==='POST').length,0,'reads and draft preview must not write');
  const saving=submitSnapshot(snapshot);
  assert.equal(targets.at(-1).path,snapshot.path);
  assert.equal(targets.at(-1).options.headers['Idempotency-Key'],snapshot.key);
  assert.deepEqual(JSON.parse(targets.at(-1).options.body),snapshot.payload);
  pending[4].resolve({project:{id:'project-A',title:'Name',instructions:'Guidance',sharedMemory:'Memory',obsidianNoteIds:['note-one'],version:5}});
  await saving;assert.equal(selectedProject.id,'project-A');assert.equal(uncertainSave,null);
  const mismatched={...snapshot,key:'mismatch-key'};
  const rejected=submitSnapshot(mismatched);
  pending[5].resolve({project:{id:'project-B',title:'Name',instructions:'Guidance',sharedMemory:'Memory',obsidianNoteIds:['note-one'],version:5}});
  await rejected;assert.equal(uncertainSave,mismatched);
  assert.equal(targets.length,6,'mismatched result must not trigger an automatic retry');
  uncertainSave=null;stopped=false;
  const leaving=previewNote('note-one'); stopped=true;
  const loadingTitle=previewTitle.textContent;
  pending[6].resolve({noteId:'note-one',title:'After unmount',markdown:'ignored',contentSha256:'a'.repeat(64),updatedAt:5});
  await leaving;assert.equal(previewTitle.textContent,loadingTitle,'unmounted preview must not mutate its former DOM');
  console.log('PROJECT_NOTE_PREVIEW_SAVE_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "project-note-preview-save-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PROJECT_NOTE_PREVIEW_SAVE_HARNESS_COMPLETE" in result.stdout


def test_project_dom_cancel_validation_and_save_recovery_use_explicit_actions():
    source = FEATURE_ASSETS.mount_js
    normalize = "const normalizeProjectText = " + source.split(
        "const normalizeProjectText = ", 1
    )[1].split("\n  const validNoteId", 1)[0]
    valid_id = "const validNoteId = " + source.split(
        "const validNoteId = ", 1
    )[1].split(";\n  function clearPreview", 1)[0] + ";"
    snippets = [
        "function renderSelectedNotes()" + source.split("function renderSelectedNotes()", 1)[1].split("\n  function renderNoteRows", 1)[0],
        "function changeNoteSelection(" + source.split("function changeNoteSelection(", 1)[1].split("\n  function selectProject", 1)[0],
        "function selectProject(" + source.split("function selectProject(", 1)[1].split("\n  function renderChats", 1)[0],
        "function cancelProjectDraft()" + source.split("function cancelProjectDraft()", 1)[1].split("\n  cancel.addEventListener", 1)[0],
        "async function submitSnapshot(" + source.split("async function submitSnapshot(", 1)[1].split("\n  function submitCurrentProject", 1)[0],
        "function submitCurrentProject(" + source.split("function submitCurrentProject(", 1)[1].split("\n  form.addEventListener('submit'", 1)[0],
        "async function resolveSaveResult()" + source.split("async function resolveSaveResult()", 1)[1].split("\n  saveRecovery.addEventListener", 1)[0],
    ]
    harness = r'''
const assert=require('node:assert/strict');
function element(tag='div'){return {tag,children:[],hidden:false,disabled:false,value:'',textContent:'',dataset:{},attributes:{},
  append(...items){this.children.push(...items);},replaceChildren(...items){this.children=[...items];},setAttribute(k,v){this.attributes[k]=v;},
  addEventListener(k,fn){this.handlers=this.handlers||{};this.handlers[k]=fn;},focus(){}};}
global.document={createElement:element};
let stopped=false,savePending=false,uncertainSave=null,selectionRevision=1,projectRevision=0,noteReadRevision=0,previewRevision=0;
let selected=null,selectedNoteIds=new Set(),noteRows=[],noteCursor=null,vaultNotesState='ready',vaultNotes=new Map();
let calls=[],pending=[],keyCounter=0;
const isCurrent=()=>!stopped,signal={},status=element(),save=element(),saveRecovery=element(),archive=element();
const conversationSelect=element(),addChat=element(),list={querySelectorAll:()=>[]},noteSelected=element(),noteResults=element(),noteEmpty=element(),noteMore=element();
const form={elements:{title:{value:''},instructions:{value:''},sharedMemory:{value:''}},addEventListener(k,fn){this.handlers=this.handlers||{};this.handlers[k]=fn;}};
const cancel=element(),notePreview=element(),previewTitle=element(),previewMeta=element(),previewMarkdown=element(),previewStatus=element();
const $=()=>element(),text=(n,v)=>{n.textContent=v;},clearPreview=()=>{},renderNoteRows=()=>{},renderChats=()=>{};
const refresh=async()=>true,call=(path,options)=>{calls.push({path,options});return new Promise((resolve,reject)=>pending.push({resolve,reject}));};
const key=()=>`idem-${++keyCounter}`,previewNote=()=>{};
''' + normalize + "\n" + valid_id + "\n" + "\n".join(snippets) + r'''
(async()=>{
  const original={id:'project-A',title:'Saved',instructions:'',sharedMemory:'',obsidianNoteIds:['removed-note'],version:4,chats:[]};
  selected=original;selectedNoteIds=new Set(original.obsidianNoteIds);vaultNotes.set('valid-note',{title:'Known'});
  renderSelectedNotes();
  assert.equal(noteSelected.children[0].children[0].textContent,'Unavailable note reference: removed-note');
  selectedNoteIds.add('valid-note');cancelProjectDraft();
  assert.deepEqual([...selectedNoteIds],['removed-note'],'Cancel restores exact original links');
  assert.equal(noteSelected.children[0].children[0].textContent,'Unavailable note reference: removed-note');
  assert.equal(validNoteId('bad/id'),false);assert.equal(validNoteId('x'.repeat(97)),false);
  selectedNoteIds=new Set(Array.from({length:50},(_,i)=>`n${i}`));vaultNotes.set('extra-note',{title:'Extra'});
  changeNoteSelection('extra-note',true);assert.equal(selectedNoteIds.size,50,'51st link is denied');
  vaultNotes.set('bad/id',{title:'Invalid'});changeNoteSelection('bad/id',true);assert.equal(selectedNoteIds.size,50,'invalid note IDs cannot be staged');
  assert.equal(normalizeProjectText('\ufeffTitle\ufeff'),'\ufeffTitle\ufeff','BOM is not stripped');
  assert.equal(normalizeProjectText('\u000bTitle\u000b'),'\u000bTitle\u000b','forbidden C0 remains for native rejection');
  selected=original;selectedNoteIds=new Set(['removed-note']);selectionRevision=10;
  form.elements.title.value=' \u0085Renamed\u0085 ';
  form.elements.instructions.value=' Instructions ';form.elements.sharedMemory.value=' Memory ';
  const submitted=submitCurrentProject({preventDefault(){}});
  assert.equal(calls.length,1);assert.equal(calls[0].path,'/chat/api/projects/project-A');
  assert.deepEqual(JSON.parse(calls[0].options.body),{title:'Renamed',instructions:'Instructions',sharedMemory:'Memory',obsidianNoteIds:['removed-note'],version:4});
  assert.equal(calls[0].options.headers['Idempotency-Key'],'idem-1');
  pending[0].resolve({project:{id:'project-A',title:'Renamed',instructions:'Instructions',sharedMemory:'Memory',obsidianNoteIds:['removed-note'],version:5}});
  await submitted;
  const failed=submitCurrentProject({preventDefault(){}});
  pending[1].reject(new Error('network denied'));await failed;
  assert.equal(save.disabled,true);const countBeforeBlockedSubmit=calls.length;
  await submitCurrentProject({preventDefault(){}});assert.equal(calls.length,countBeforeBlockedSubmit,'uncertain Save blocks repeat');
  const resolving=resolveSaveResult();assert.equal(calls[2].path,'/chat/api/projects/project-A');
  pending[2].resolve({project:{id:'project-A',title:'Renamed',instructions:'Instructions',sharedMemory:'Memory',obsidianNoteIds:['removed-note'],version:6}});
  await resolving;assert.equal(uncertainSave,null);assert.equal(selected.version,6,'readback refreshes current project version');
  form.elements.title.value='New draft';const explicitRetry=submitCurrentProject({preventDefault(){}});
  assert.equal(calls[3].options.headers['Idempotency-Key'],'idem-3');
  assert.equal(JSON.parse(calls[3].options.body).version,6,'explicit retry uses readback version');
  pending[3].reject(new Error('denied again'));await explicitRetry;
  console.log('PROJECT_DOM_RECOVERY_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "project-dom-recovery-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PROJECT_DOM_RECOVERY_HARNESS_COMPLETE" in result.stdout


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
