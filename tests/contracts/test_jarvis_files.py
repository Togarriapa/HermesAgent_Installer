from __future__ import annotations

import asyncio
import base64
import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatDenied, JarvisChatStore
from hermes_installer.remote.jarvis_chat import JarvisChatService
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.core_client import NativeFileAttachment
from hermes_installer.remote.jarvis_files import (
    JarvisFilesStore,
    _read_upload,
    upload_file,
)
from hermes_installer.remote.jarvis_files_assets import FEATURE_ASSETS


def _principal(subject="owner-a", generation="core-generation-a"):
    now = time.monotonic()
    return ChatPrincipal(subject, now + 120, now + 4, generation)


def _conversation(store, subject="owner-a"):
    return store.create_conversation(
        subject, f"runtime-{subject}", f"stored-{subject}", "core-generation-a")


def _reserve(files, conversation, *, subject="owner-a", key="file-request-key-00000001",
             content=b"safe notes\n"):
    return files.reserve(
        subject=subject, conversation_id=conversation["id"],
        core_generation="core-generation-a", idempotency_key=key,
        name="notes.txt", mime_type="text/plain", content=content)


def test_file_reservation_is_idempotent_closed_and_one_shot_per_exact_turn(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)

    receipt, created = _reserve(files, conversation)
    replay, created_again = _reserve(files, conversation)
    assert created is True and created_again is False
    assert replay == receipt
    assert receipt["state"] == "pending"
    assert "ref_text" not in receipt

    with pytest.raises(JarvisChatDenied, match="idempotency"):
        _reserve(files, conversation, content=b"different content\n")

    receipt = files.complete(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a", file_id=receipt["id"],
        ref_text="@file:attachments/notes.txt")
    assert receipt["state"] == "ready"
    assert "ref_text" not in receipt

    turn_id, _nonce, _ = chat.begin_turn(
        "owner-a", conversation["id"], "summarize my notes", "turn-request-key-00000001",
        _principal())
    refs = files.claim_pending(
        subject="owner-a", conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a")
    assert refs == ("@file:attachments/notes.txt",)
    assert files.claim_pending(
        subject="owner-a", conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a") == ()
    assert files.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")[0]["state"] == "attached"
    with pytest.raises(JarvisChatDenied):
        files.for_conversation(subject="owner-b", conversation_id=conversation["id"],
                               core_generation="core-generation-a")


def test_file_claim_denies_foreign_or_wrong_generation_turn_and_stale_conversation(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)
    receipt, _ = _reserve(files, conversation)
    files.complete(subject="owner-a", conversation_id=conversation["id"],
                   core_generation="core-generation-a", file_id=receipt["id"],
                   ref_text="@file:attachments/notes.txt")
    turn_id, _nonce, _ = chat.begin_turn(
        "owner-a", conversation["id"], "read this", "turn-request-key-00000002", _principal())

    with pytest.raises(JarvisChatDenied):
        files.claim_pending(subject="owner-b", conversation_id=conversation["id"],
                            turn_id=turn_id, core_generation="core-generation-a")
    with pytest.raises(JarvisChatDenied):
        files.claim_pending(subject="owner-a", conversation_id=conversation["id"],
                            turn_id=turn_id, core_generation="core-generation-b")
    with pytest.raises(JarvisChatDenied):
        files.for_conversation(subject="owner-a", conversation_id=conversation["id"],
                               core_generation="core-generation-b")


def test_uncertain_native_upload_is_never_retried_after_store_recovery(tmp_path):
    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    files = JarvisFilesStore(chat)
    conversation = _conversation(chat)
    receipt, created = _reserve(files, conversation)
    assert created

    recovered = JarvisFilesStore(chat)
    rows = recovered.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")
    assert rows[0]["id"] == receipt["id"]
    assert rows[0]["state"] == "unavailable"
    replay, replayed = _reserve(recovered, conversation)
    assert replayed is False
    assert replay["state"] == "unavailable"


def test_file_upload_parser_accepts_only_bounded_utf8_text_with_safe_basename():
    from aiohttp import web

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, body):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    body = {"name": "notes.md", "content_base64": base64.b64encode(b"hello\n").decode(),
            "idempotency_key": "file-request-key-00000002"}
    assert asyncio.run(_read_upload(Request(body))) == (
        "notes.md", "text/markdown", b"hello\n", "file-request-key-00000002")

    for invalid in (
        {**body, "name": "../private.txt"},
        {**body, "name": "notes.pdf"},
        {**body, "content_base64": base64.b64encode(b"bad\x00text").decode()},
        {**body, "content_base64": base64.b64encode(b"\xff").decode()},
        {**body, "extra": "unreviewed"},
    ):
        with pytest.raises(web.HTTPException):
            asyncio.run(_read_upload(Request(invalid)))


def test_upload_stages_native_attachment_once_and_retry_only_reads_receipt(tmp_path):
    from types import SimpleNamespace

    payload = b"owner supplied notes\n"
    key = "file-request-key-00000003"
    body = {"name": "notes.txt", "content_base64": base64.b64encode(payload).decode(),
            "idempotency_key": key}

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, service, conversation_id):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)
            self.match_info = {"conversation_id": conversation_id}
            self.app = {"jarvis_chat_service": service}

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    class Backend:
        def __init__(self):
            self.attachments = []

        async def attach_file(self, session_id, *, name, media_type, content):
            self.attachments.append((session_id, name, media_type, content))
            return NativeFileAttachment(name, "@file:attachments/notes.txt")

    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = _conversation(chat)
    backend = Backend()
    service = JarvisChatService(
        chat, backend, principal_from_request=lambda _request: _principal())
    request = Request(service, conversation["id"])

    first = asyncio.run(upload_file(request))
    second = asyncio.run(upload_file(request))
    assert first.status == 201
    assert second.status == 200
    assert len(backend.attachments) == 1
    assert backend.attachments[0] == (
        "runtime-owner-a", "notes.txt", "text/plain", payload)
    assert "ref_text" not in first.text
    receipt = service.files_store.for_conversation(
        subject="owner-a", conversation_id=conversation["id"],
        core_generation="core-generation-a")
    assert receipt[0]["state"] == "ready"


def test_uncertain_upload_failure_is_closed_and_same_key_does_not_repeat_native_effect(tmp_path):
    from aiohttp import web
    from types import SimpleNamespace

    body = {"name": "notes.txt", "content_base64": base64.b64encode(b"hello").decode(),
            "idempotency_key": "file-request-key-00000004"}

    class Request:
        content_type = "application/json"
        headers = {}

        def __init__(self, service, conversation_id):
            self.raw = json.dumps(body, separators=(",", ":")).encode()
            self.content_length = len(self.raw)
            self.match_info = {"conversation_id": conversation_id}
            self.app = {"jarvis_chat_service": service}

        def clone(self, **_kwargs):
            return self

        async def read(self):
            return self.raw

    class Backend:
        def __init__(self):
            self.calls = 0

        async def attach_file(self, *_args, **_kwargs):
            self.calls += 1
            raise RuntimeError("uncertain upstream failure")

    chat = JarvisChatStore(tmp_path / "chat.sqlite3")
    conversation = _conversation(chat)
    backend = Backend()
    service = JarvisChatService(
        chat, backend, principal_from_request=lambda _request: _principal())
    request = Request(service, conversation["id"])

    with pytest.raises(web.HTTPServiceUnavailable):
        asyncio.run(upload_file(request))
    with pytest.raises(web.HTTPConflict):
        asyncio.run(upload_file(request))
    assert backend.calls == 1


def test_files_feature_is_static_and_declares_only_fixed_owner_routes():
    validate_feature_assets((FEATURE_ASSETS,))

    assert FEATURE_ASSETS.feature_id == "files"
    assert FEATURE_ASSETS.api_routes == (
        ("GET", "/chat/api/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/files"),
        ("POST", "/chat/api/conversations/{conversation_id}/files"),
    )
    assert "textContent" in FEATURE_ASSETS.mount_js
    assert "innerHTML" not in FEATURE_ASSETS.mount_js
    assert "download" in FEATURE_ASSETS.view_html.lower()


def test_file_status_reads_follow_latest_conversation_and_revision():
    if shutil.which("node") is None:
        pytest.skip("Node.js is needed to execute the browser script race fixture")

    harness = r"""
const assert = require('node:assert/strict');
class Target {
  constructor() { this.children=[]; this.listeners={}; this.hidden=false; this.disabled=false; this._textContent=''; this.value=''; }
  get textContent() { return this._textContent || this.children.map(child=>child.textContent || '').join(''); }
  set textContent(value) { this._textContent=String(value); }
  addEventListener(name, fn) { this.listeners[name]=fn; }
  removeEventListener(name) { delete this.listeners[name]; }
  replaceChildren(...items) { this.children=[...items]; }
  append(...items) { this.children.push(...items); if (this.kind==='select' && !this.value && items[0]) this.value=items[0].value; }
  get childElementCount() { return this.children.length; }
  fire(name) { return this.listeners[name]?.(); }
}
function deferred() { let resolve, reject; const promise=new Promise((a,b)=>{resolve=a;reject=b}); return {promise,resolve,reject}; }
const selectors = new Map([
 ['[data-feature-root="files"]', null], ['[data-conversation]', Object.assign(new Target(), {kind:'select'})],
 ['[data-file]', Object.assign(new Target(), {files:[]})], ['[data-upload]', new Target()],
 ['[data-refresh]', new Target()], ['[data-note]', new Target()], ['[data-preview]', new Target()],
 ['[data-preview-meta]', new Target()], ['[data-preview-bytes]', new Target()],
 ['[data-files]', new Target()], ['[data-empty]', new Target()]
]);
const root={querySelector:s=>selectors.get(s)}; selectors.set('[data-feature-root="files"]',root);
global.document={createElement:()=>new Target()};
const reads=[], posts=[];
const api={get(path){ if(path==='/chat/api/conversations') return Promise.resolve({conversations:[{id:'A'},{id:'B'}]}); const d=deferred(); reads.push({path,d}); return d.promise; },post(path,body){const d=deferred();posts.push({path,body,d});return d.promise;}};
global.TextDecoder=TextDecoder;
global.btoa=value=>Buffer.from(value,'binary').toString('base64');
global.crypto={randomUUID:()=> '12345678-1234-1234-1234-123456789abc'};
const mount = new Function('return (' + MOUNT + ')')();
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 const cleanup=mount(root,api); await flush();
 const select=selectors.get('[data-conversation]'), fileInput=selectors.get('[data-file]'), upload=selectors.get('[data-upload]'), list=selectors.get('[data-files]'), note=selectors.get('[data-note]'), refresh=selectors.get('[data-refresh]');
 assert.equal(reads[0].path,'/chat/api/conversations/A/files');
 select.value='B'; select.fire('change');
 assert.equal(reads[1].path,'/chat/api/conversations/B/files','a newer conversation read starts while the older read is pending');
 reads[1].d.resolve({files:[{id:'b',name:'B file'}]}); await flush();
 assert.equal(list.children[0].children[0].children[0].textContent,'B file');
 const status=note.textContent;
 reads[0].d.reject(Error('obsolete A failure')); await flush();
 assert.equal(note.textContent,status,'obsolete failure cannot overwrite current status');
 assert.equal(list.children[0].children[0].children[0].textContent,'B file');
 select.value='A'; select.fire('change');
 select.value='B'; select.fire('change');
 select.value='A'; select.fire('change');
 assert.deepEqual(reads.slice(2).map(row=>row.path),[
  '/chat/api/conversations/A/files','/chat/api/conversations/B/files','/chat/api/conversations/A/files']);
 reads[4].d.resolve({files:[{id:'new-a',name:'Newest A'}]}); await flush();
 assert.equal(list.children[0].children[0].children[0].textContent,'Newest A');
 const currentStatus=note.textContent;
 reads[2].d.resolve({files:[{id:'old-a',name:'Obsolete A'}]}); await flush();
 assert.equal(list.children[0].children[0].children[0].textContent,'Newest A','ABA-stale success cannot replace the newest same-ID result');
 assert.equal(note.textContent,currentStatus);
 assert.equal(refresh.disabled,false,'obsolete finally cannot alter current refresh control state');
 select.value=''; select.fire('change');
 assert.equal(list.children.length,0,'empty selection clears the list');
 const readsWithEmptySelection=reads.length;
 assert.equal(readsWithEmptySelection,5,'empty selection emits no file-status request');
 select.value='A'; select.fire('change');
 assert.equal(reads[5].path,'/chat/api/conversations/A/files');
 const payload=new TextEncoder().encode('hello');
 const file={name:'notes.txt',size:payload.length,arrayBuffer:async()=>payload.buffer};
 fileInput.files=[file]; fileInput.fire('change'); await flush();
 const staging=upload.fire('click'); await flush();
 assert.equal(posts.length,1,'one stage attempt is emitted');
 assert.equal(posts[0].path,'/chat/api/conversations/A/files');
 assert.equal(select.disabled,true,'conversation switching stays locked during stage');
 refresh.fire('click');
 assert.equal(reads[6].path,'/chat/api/conversations/A/files','file status can refresh while the upload is in flight');
 posts[0].d.resolve({id:'receipt'}); await flush();
 assert.equal(reads[7].path,'/chat/api/conversations/A/files','successful stage keeps its receipt readback');
 reads[7].d.resolve({files:[{id:'receipt',name:'Receipt'}]}); await staging;
 assert.equal(list.children[0].children[0].children[0].textContent,'Receipt');
 reads[6].d.resolve({files:[{id:'old-refresh',name:'Older refresh'}]}); await flush();
 assert.equal(list.children[0].children[0].children[0].textContent,'Receipt','older in-flight refresh cannot overwrite newer stage receipt readback');
 fileInput.files=[file]; fileInput.fire('change'); await flush();
 const secondStage=upload.fire('click'); await flush();
 assert.equal(posts.length,2);
 posts[1].d.resolve({id:'second-receipt'}); await flush();
 assert.equal(reads[8].path,'/chat/api/conversations/A/files','second successful stage begins guarded receipt readback');
 const beforeUnmount=list.children[0].children[0].children[0].textContent;
 cleanup(); reads[8].d.resolve({files:[{id:'late-stage',name:'Late stage receipt'}]}); await secondStage;
 assert.equal(list.children[0].children[0].children[0].textContent,beforeUnmount,'stage receipt completion cannot mutate an unmounted view');
})().catch(error=>{console.error(error);process.exitCode=1});
""".replace("MOUNT", FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "files-refresh-race.js"
        script.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
