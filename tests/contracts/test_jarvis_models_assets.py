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
  fields.get("[data-models-conversation]").replaceChildren();
  fields.get("[data-models-choice]").replaceChildren();
  fields.get("[data-models-apply]").disabled = true;
  requests.length = 0;
  const cleanup = mount(root, api, {initialConversationId});
  await new Promise((resolve) => setImmediate(resolve));
  const conversation = fields.get("[data-models-conversation]");
  const choice = fields.get("[data-models-choice]");
  assert.equal(requests[0].path, "/chat/api/models/conversations");
  assert.equal(requests.filter((item) => item.method === "POST").length, 0);
  cleanup();
  return {conversation, choice, requests: [...requests]};
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
