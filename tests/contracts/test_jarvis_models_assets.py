from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from hermes_installer.remote.jarvis_models_assets import FEATURE_ASSETS


def test_models_draft_restores_only_a_trusted_current_choice_after_catalog_rebuild():
    source = FEATURE_ASSETS.mount_js
    assert 'last.state === "selected-for-session"' in source
    assert 'last.state === "deferred-next-turn"' in source
    assert 'last === null && data.profileModel' in source
    assert "choice.selectedIndex = preferredOption ? preferredOption.index : -1" in source
    assert "The conversation selection is not confirmed as a selectable model; choose explicitly." in source
    assert "No current conversation model is known; choose explicitly." in source


def test_models_context_selects_only_a_conversation_returned_by_the_owner_list():
    harness = r'''const assert = require("node:assert/strict");
const ownerConversationId = "cccccccccccccccccccccccccccccccc";
const otherConversationId = "dddddddddddddddddddddddddddddddd";
const rows = [{id: ownerConversationId, title: "Current chat"}, {id: otherConversationId, title: "Other chat"}];
class Option {
  constructor(text, value) { this.textContent = text; this.value = value; this.disabled = false; }
}
class Select {
  constructor() { this.options = []; this._value = ""; this.disabled = false; this.listeners = new Map(); }
  get value() { return this._value; }
  set value(value) { this._value = value; }
  get selectedIndex() { return this.options.findIndex((item) => item.value === this._value); }
  set selectedIndex(index) { this._value = index >= 0 && this.options[index] ? this.options[index].value : ""; }
  replaceChildren(...items) { this.options = []; this._value = ""; for (const item of items) this.add(item); }
  add(item) { item.index = this.options.length; this.options.push(item); }
  append(item) { this.add(item); }
  addEventListener(name, handler) { this.listeners.set(name, handler); }
  removeEventListener(name) { this.listeners.delete(name); }
}
const fields = new Map([
  ["[data-models-status]", {textContent: ""}],
  ["[data-models-choice]", new Select()],
  ["[data-models-apply]", {disabled: true, addEventListener() {}, removeEventListener() {}}],
  ["[data-models-conversation]", new Select()],
  ["[data-models-provider]", {textContent: ""}],
  ["[data-models-model]", {textContent: ""}],
  ["[data-models-account]", {textContent: ""}],
  ["[data-models-selection]", {textContent: ""}],
  ["[data-models-catalog]", {textContent: ""}]
]);
const root = {querySelector(selector) { return fields.get(selector) || null; }};
const requests = [];
const api = {
  async get(path) {
    requests.push({method: "GET", path});
    if (path === "/chat/api/models/conversations") return {conversations: rows};
    const id = path.split("/").at(-2);
    return {
      status: "observed",
      models: Array.from({length: 9}, (_, index) => ({id: `model-${index}`, selectable: true, status: "available"})),
      provider: {status: "configured-unverified", id: "openai-codex"},
      profileModel: {status: "configured-unverified", id: "model-0"},
      codexCredential: "configured", conversationSelection: null,
      selectionAvailability: "available",
      revision: {revision: `revision-for-${id}`, approval_nonce: `nonce-for-${id}`}
    };
  },
  async post(path) { requests.push({method: "POST", path}); return {state: "selected-for-session"}; }
};
const document = {createElement() { return new Option("", ""); }};
const crypto = {getRandomValues(bytes) { bytes.fill(7); return bytes; }};
MOUNT
async function exercise(initialConversationId) {
  requests.length = 0;
  const cleanup = mount(root, api, {initialConversationId});
  const reset = {
    conversationDisabled: fields.get("[data-models-conversation]").disabled,
    conversationValue: fields.get("[data-models-conversation]").value,
    choiceDisabled: fields.get("[data-models-choice]").disabled,
    choiceOptions: fields.get("[data-models-choice]").options.map((option) => option.textContent),
    applyDisabled: fields.get("[data-models-apply]").disabled,
    provider: fields.get("[data-models-provider]").textContent,
    model: fields.get("[data-models-model]").textContent,
    account: fields.get("[data-models-account]").textContent,
    selection: fields.get("[data-models-selection]").textContent
  };
  await new Promise((resolve) => setImmediate(resolve));
  const conversation = fields.get("[data-models-conversation]");
  const choice = fields.get("[data-models-choice]");
  assert.equal(requests[0].path, "/chat/api/models/conversations");
  assert.equal(requests.filter((item) => item.method === "POST").length, 0);
  cleanup();
  return {conversation, choice, reset, requests: [...requests]};
}
(async () => {
  const current = await exercise(ownerConversationId);
  assert.equal(current.conversation.value, ownerConversationId);
  assert.deepEqual(current.requests.map(({method, path}) => [method, path]), [
    ["GET", "/chat/api/models/conversations"],
    ["GET", `/chat/api/conversations/${ownerConversationId}/model-settings`]
  ]);
  assert.equal(current.requests.some((item) => item.method === "POST"), false);
  assert.equal(current.choice.disabled, false);

  for (const contextId of ["eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "../private", undefined]) {
    const untrusted = await exercise(contextId);
    assert.deepEqual(untrusted.reset, {
      conversationDisabled: true,
      conversationValue: "",
      choiceDisabled: true,
      choiceOptions: ["Choose a conversation first"],
      applyDisabled: true,
      provider: "Pending verification",
      model: "Pending verification",
      account: "Unknown",
      selection: "Not observed"
    });
    assert.equal(untrusted.conversation.value, "");
    assert.deepEqual(untrusted.requests.map(({method, path}) => [method, path]), [
      ["GET", "/chat/api/models/conversations"]
    ]);
    assert.equal(untrusted.choice.disabled, true);
    assert.equal(untrusted.requests.some((item) => item.method === "POST"), false);
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("MOUNT", FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "models-context-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_models_reads_and_selection_are_current_bound_and_single_flight():
    harness = r'''const assert = require("node:assert/strict");
const A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
class Option { constructor(text,value) { this.textContent=text; this.value=value; this.disabled=false; } }
class Select {
  constructor() { this.options=[]; this._value=""; this.disabled=false; this.listeners=new Map(); }
  get value() { return this._value; }
  set value(value) { this._value=value; }
  get selectedIndex() { return this.options.findIndex(option=>option.value===this._value); }
  set selectedIndex(index) { this._value=index>=0&&this.options[index]?this.options[index].value:""; }
  replaceChildren(...items) { this.options=[]; this._value=""; for (const item of items) this.add(item); }
  add(item) { item.index=this.options.length; this.options.push(item); }
  append(item) { this.add(item); }
  addEventListener(name,handler) { this.listeners.set(name,handler); }
  removeEventListener(name) { this.listeners.delete(name); }
  fire(name) { return this.listeners.get(name)?.(); }
}
function deferred() { let resolve,reject; const promise=new Promise((a,b)=>{resolve=a;reject=b}); return {promise,resolve,reject}; }
const fields=new Map([
 ["[data-models-status]",{textContent:""}], ["[data-models-choice]",new Select()],
 ["[data-models-apply]",{disabled:true,addEventListener(name,handler){this.handler=handler;},removeEventListener(){}}],
 ["[data-models-conversation]",new Select()],
 ...["provider","model","account","selection","catalog"].map(name=>[`[data-models-${name}]`,{textContent:""}])
]);
const root={querySelector(selector){return fields.get(selector)||null;}};
global.Option=Option; global.document={createElement(){return new Option("","");}};
global.crypto={getRandomValues(bytes){bytes.fill(9);return bytes;}};
const reads=[],posts=[];
const api={
 get(path){if(path==="/chat/api/models/conversations")return Promise.resolve({conversations:[{id:A,title:"A"},{id:B,title:"B"}]});const d=deferred();reads.push({path,d});return d.promise;},
 post(path,body){const d=deferred();posts.push({path,body,d});return d.promise;}
};
function settings(label,revision){return {status:"observed",models:Array.from({length:9},(_,i)=>({id:`model-${i}`,selectable:true,status:"available"})),provider:{status:"configured-unverified",id:`provider-${label}`},profileModel:{status:"configured-unverified",id:"model-0"},codexCredential:"configured",conversationSelection:null,selectionAvailability:"available",revision:{revision,approval_nonce:`nonce-${revision}`}};}
MOUNT
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 const cleanup=mount(root,api), conversation=fields.get("[data-models-conversation]"), choice=fields.get("[data-models-choice]"), apply=fields.get("[data-models-apply]"), status=fields.get("[data-models-status]"), provider=fields.get("[data-models-provider]"), model=fields.get("[data-models-model]"), account=fields.get("[data-models-account]"), selection=fields.get("[data-models-selection]");
 await flush();
 conversation.value=A; conversation.fire("change");
 assert.equal(reads[0].path,`/chat/api/conversations/${A}/model-settings`);
 conversation.value=B; conversation.fire("change");
 assert.equal(reads[1].path,`/chat/api/conversations/${B}/model-settings`,'newest conversation read starts while the older read is pending');
 assert.equal(provider.textContent,"Pending verification"); assert.equal(model.textContent,"Pending verification"); assert.equal(account.textContent,"Unknown"); assert.equal(selection.textContent,"Not observed");
 conversation.value=A; conversation.fire("change");
 assert.equal(reads[2].path,`/chat/api/conversations/${A}/model-settings`);
 reads[2].d.resolve(settings("newest-A","revision-A-new")); await flush();
 assert.equal(provider.textContent,"provider-newest-A");
 const currentStatus=status.textContent;
 reads[0].d.resolve(settings("obsolete-A","revision-A-old")); reads[1].d.reject(Error("obsolete B failure")); await flush();
 assert.equal(provider.textContent,"provider-newest-A","same-ID ABA stale success cannot replace current data");
 assert.equal(status.textContent,currentStatus,"stale error cannot overwrite current status");

 conversation.value=B; conversation.fire("change");
 reads[3].d.resolve({status:"observed",models:[]}); await flush();
 assert.equal(provider.textContent,"Unknown","malformed current result clears previous observed values");
 assert.equal(choice.disabled,true); assert.equal(apply.disabled,true);
 conversation.value=B; conversation.fire("change");
 reads[4].d.resolve(settings("ready-B","revision-B")); await flush();
 assert.equal(provider.textContent,"provider-ready-B"); assert.equal(apply.disabled,false);
 choice.value="model-2";
 const applying=apply.handler();
 assert.equal(apply.disabled,true,'apply becomes pending immediately');
 assert.equal(posts.length,1);
 assert.equal(posts[0].path,`/chat/api/conversations/${B}/model-selection`);
 assert.deepEqual({...posts[0].body}, {model_id:"model-2",revision:"revision-B",approval_nonce:"nonce-revision-B",idempotency_key:"090909090909090909090909090909090909090909090909"});
 choice.value="model-3"; choice.fire("change");
 assert.equal(apply.disabled,true,'changing the choice cannot unlock an in-flight mutation');
 await apply.handler();
 assert.equal(posts.length,1,'second apply is ignored while the first mutation is pending');
 conversation.value=A; conversation.fire("change");
 reads[5].d.resolve(settings("current-A","revision-current-A")); await flush();
 const statusForA=status.textContent;
 posts[0].d.resolve({state:"selected-for-session"}); await applying; await flush();
 assert.equal(status.textContent,statusForA,'POST completion after switching cannot overwrite the new conversation');
 assert.equal(reads.length,6,'stale POST completion does not launch old-conversation readback');
 assert.equal(apply.disabled,false,'pending state releases against the current valid snapshot');
 const unknown=apply.handler();
 assert.equal(posts.length,2); assert.equal(posts[1].path,`/chat/api/conversations/${A}/model-selection`);
 posts[1].d.resolve({state:"unknown-pending"}); await flush();
 assert.equal(reads[6].path,`/chat/api/conversations/${A}/model-settings`,'unknown result performs status readback without repeating mutation');
 reads[6].d.resolve(settings("unknown-A","revision-unknown-A")); await unknown; await flush();
 assert.match(status.textContent,/native result is unknown/);
 assert.equal(posts.length,2,'unknown pending is not retried automatically');

 conversation.fire("change");
 assert.equal(reads[7].path,`/chat/api/conversations/${A}/model-settings`);
 cleanup();
 const afterUnmount=status.textContent;
 reads[7].d.resolve(settings("after-unmount","revision-late")); await flush();
 assert.equal(status.textContent,afterUnmount,'late settings completion after unmount is ignored');
})().catch(error=>{console.error(error);process.exitCode=1});
'''.replace("MOUNT", FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "models-currentness-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
