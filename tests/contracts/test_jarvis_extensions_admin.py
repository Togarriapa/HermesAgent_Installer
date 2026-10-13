from __future__ import annotations

import asyncio
import subprocess
import tempfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.remote.core_client import CoreRpcClient
from hermes_installer.remote.jarvis_chat import JarvisChatDenied
from hermes_installer.remote.jarvis_extensions_admin import (
    _valid_plugin_setting,
    _source_label,
    _plugin_config_revision,
    build_extension_snapshot,
)
from hermes_installer.remote.jarvis_extensions_assets import FEATURE_ASSETS
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets


class _FixedClient(CoreRpcClient):
    def __init__(self, result):
        self.result = result
        self.calls = []
        self.responses = []

    async def _rpc(self, method, params):
        self.calls.append((method, params))
        return self.responses.pop(0) if self.responses else self.result


def test_extension_writes_use_only_fixed_native_management_actions():
    client = _FixedClient({"installed": True, "name": "research-helper"})
    assert asyncio.run(client.install_skill("research-helper")) == {
        "installed": True, "name": "research-helper",
    }
    assert client.calls[-1] == ("skills.manage", {"action": "install", "query": "research-helper"})

    client.result = {"ok": True, "plugin_name": "owner-helper"}
    assert asyncio.run(client.install_plugin("owner-helper"))["ok"] is True
    assert client.calls[-1] == ("plugins.manage", {
        "action": "install", "catalog_name": "owner-helper", "enable": False, "force": False,
    })

    client.result = {"ok": True, "name": "owner-helper"}
    assert asyncio.run(client.remove_plugin("owner-helper")) == {
        "ok": True, "name": "owner-helper", "reversible": False,
    }
    assert client.calls[-1] == ("plugins.manage", {"action": "remove", "name": "owner-helper"})

    client.responses = [{"ok": True, "removed": True}, {"servers": []}]
    assert asyncio.run(client.remove_mcp("github")) == {
        "ok": True, "name": "github", "removed": True,
    }
    assert client.calls[-2:] == [
        ("mcp.servers.remove", {"name": "github"}),
        ("mcp.servers.list", {}),
    ]


def test_mcp_removal_requires_native_absence_readback():
    client = _FixedClient({})
    client.responses = [
        {"ok": True, "removed": True},
        {"servers": [{"name": "github", "transport": "http", "enabled": True,
                      "source": "config"}]},
    ]
    with pytest.raises(JarvisChatDenied, match="not reflected"):
        asyncio.run(client.remove_mcp("github"))


def test_extension_native_write_postconditions_fail_closed():
    client = _FixedClient({"ok": True, "name": "different"})
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.remove_plugin("owner-helper"))
    client.result = {"installed": False, "name": "owner-helper"}
    with pytest.raises(JarvisChatDenied):
        asyncio.run(client.install_skill("owner-helper"))
    client.result = {"output": "1 skill(s) available", "result": {
        "added": [], "removed": [], "unchanged": [], "total": 1, "commands": 1,
    }}
    assert asyncio.run(client.reload_skills()) == {"total": 1, "commands": 1}
    assert client.calls[-1] == ("skills.reload", {})


def test_extension_snapshot_keeps_provenance_and_prefixes_builtins():
    result = build_extension_snapshot(
        skills=[{"category": "general", "names": ["web-facts", "local-procedure"]}],
        plugins=[
            {"name": "web", "key": "web", "version": "1.2.0", "source": "bundled",
             "status": "enabled", "settings_schema": []},
            {"name": "owner-tool-package", "key": "owner-tool", "version": "1.0", "source": "user",
             "status": "disabled", "settings_schema": [{"key": "mode", "type": "string"}]},
        ],
        mcps=[
            {"name": "github", "transport": "http", "enabled": True, "source": "config",
             "config_revision": "not-a-jarvis-owner-proof"},
            {"name": "plugin-server", "transport": "stdio", "enabled": True, "source": "plugin",
             "plugin": "web"},
            {"name": "unverified-server", "transport": "stdio", "enabled": True, "source": "plugin",
             "plugin": "missing-provider"},
        ],
        skill_catalog={"web-facts"},
    )

    by_identity = {(item["kind"], item["name"]): item for item in result["items"]}
    assert by_identity[("plugins", "web")]["label"] == "Hermes web"
    assert by_identity[("plugins", "web")]["source"] == "builtin"
    assert by_identity[("plugins", "owner-tool-package")]["source"] == "useradded"
    assert by_identity[("plugins", "owner-tool-package")]["editable"] is True
    assert by_identity[("plugins", "owner-tool-package")]["removable"] is True
    assert by_identity[("plugins", "owner-tool-package")]["key"] == "owner-tool"
    assert by_identity[("skills", "web-facts")]["source"] == "bundledResources"
    assert by_identity[("skills", "local-procedure")]["source"] == "unknown"
    assert by_identity[("mcps", "github")]["source"] == "unknown"
    assert by_identity[("mcps", "github")]["removable"] is False
    assert by_identity[("mcps", "plugin-server")]["source"] == "builtin"
    assert by_identity[("mcps", "plugin-server")]["label"] == "Hermes plugin-server"
    assert by_identity[("mcps", "plugin-server")]["removable"] is False
    assert by_identity[("mcps", "unverified-server")]["source"] == "unknown"
    assert by_identity[("mcps", "unverified-server")]["removable"] is False
    # Resource overlays and owner-added Hermes-home entrypoints use the
    # source-bound root adapter. Unrecognized native rows remain read-only.
    assert result["availableActions"]["skills"]["edit"] is True
    assert result["availableActions"]["skills"]["remove"] is True
    assert "Hermes stock skills remain read-only" in result["availableActions"]["skills"]["reason"]
    assert result["availableActions"]["plugins"]["remove"] is True
    assert result["availableActions"]["plugins"]["update"] is False
    assert result["availableActions"]["mcps"]["edit"] is False


def test_mcp_removal_ownership_requires_exact_jarvis_add_readback_fingerprint():
    from hermes_installer.remote.jarvis_extensions_admin import _mcp_config_revision

    row = {"name": "github", "transport": "http", "enabled": True,
           "source": "config"}
    revision = _mcp_config_revision(row)
    assert revision is not None
    unknown = build_extension_snapshot(skills=[], plugins=[], mcps=[row])
    owned = build_extension_snapshot(skills=[], plugins=[], mcps=[row],
        owner_added_mcp_revisions={"github": revision})
    changed = build_extension_snapshot(skills=[], plugins=[], mcps=[
        {**row, "enabled": False}], owner_added_mcp_revisions={"github": revision})

    assert unknown["items"][0]["source"] == "unknown"
    assert unknown["items"][0]["removable"] is False
    assert owned["items"][0]["source"] == "useradded"
    assert owned["items"][0]["removable"] is True
    assert changed["items"][0]["source"] == "unknown"
    assert changed["items"][0]["removable"] is False


def test_malformed_native_owner_fingerprints_never_match_an_empty_ledger():
    malformed_plugin = {"name": "catalog-helper", "key": "catalog-helper", "version": "1.2.0",
        "source": "catalog", "catalog_name": "owner/catalog-helper", "status": "disabled",
        "settings_schema": [], "settings_revision": "a" * 64}
    malformed_mcp = {"name": "broken-server", "transport": "unsupported", "enabled": True,
                     "source": "config"}
    snapshot = build_extension_snapshot(skills=[], plugins=[malformed_plugin], mcps=[malformed_mcp])
    by_kind = {row["kind"]: row for row in snapshot["items"]}

    assert by_kind["plugins"]["source"] == "unknown"
    assert by_kind["plugins"]["removable"] is False
    assert by_kind["mcps"]["source"] == "unknown"
    assert by_kind["mcps"]["removable"] is False


def test_catalog_plugin_ownership_requires_exact_jarvis_install_readback_fingerprint():
    row = {"name": "catalog-helper", "key": "catalog-helper", "version": "1.2.0",
           "source": "catalog", "catalog_name": "owner/catalog-helper",
           "installed_sha": "b" * 40, "catalog_sha": "c" * 40,
           "status": "disabled", "settings_schema": [], "settings_revision": "a" * 64}
    revision = _plugin_config_revision(row)
    assert revision is not None
    unknown = build_extension_snapshot(skills=[], plugins=[row], mcps=[])
    owned = build_extension_snapshot(skills=[], plugins=[row], mcps=[],
        owner_added_plugin_revisions={"catalog-helper": revision})
    edited = build_extension_snapshot(skills=[], plugins=[{**row, "settings_revision": "d" * 64,
        "status": "enabled"}], mcps=[],
        owner_added_plugin_revisions={"catalog-helper": revision})
    changed = build_extension_snapshot(skills=[], plugins=[{**row, "installed_sha": "d" * 40}], mcps=[],
        owner_added_plugin_revisions={"catalog-helper": revision})
    foreign = build_extension_snapshot(skills=[], plugins=[{**row, "catalog_name": "foreign/plugin"}], mcps=[],
        owner_added_plugin_revisions={"catalog-helper": revision})

    assert unknown["items"][0]["source"] == "unknown"
    assert unknown["items"][0]["editable"] is False
    assert unknown["items"][0]["removable"] is False
    assert owned["items"][0]["source"] == "useradded"
    assert owned["items"][0]["removable"] is True
    assert edited["items"][0]["source"] == "useradded"
    assert edited["items"][0]["removable"] is True
    assert changed["items"][0]["source"] == "unknown"
    assert foreign["items"][0]["source"] == "unknown"


def test_skill_snapshot_joins_root_manifest_to_native_skills_and_preserves_source():
    result = build_extension_snapshot(
        skills=[{"category": "general", "names": ["owner-helper"]}],
        plugins=[], mcps=[], skill_catalog={"resource-helper"},
        native_skill_files=[
            SimpleNamespace(skill_id="owner-helper", display_name="owner-helper",
                sha256="a" * 64, source="owner-added", editable=True, overlay_active=False),
            SimpleNamespace(skill_id="resource-helper", display_name="resource-helper",
                sha256="b" * 64, source="resources", editable=True, overlay_active=False),
            SimpleNamespace(skill_id="resource-edit", display_name="resource-edit",
                sha256="c" * 64, source="resources", editable=True, overlay_active=True),
        ], archived_skill_files=[
            {"skill_id": "resource-helper", "source": "resources", "versions": [
                {"restore_id": "d" * 64, "sha256": "e" * 64}]},
            {"skill_id": "archived-owner-helper", "source": "owner-added", "versions": [
                {"restore_id": "restore-token_0123456789", "sha256": "f" * 64}]},
        ])
    by_name = {row["name"]: row for row in result["items"] if row["kind"] == "skills"}
    assert by_name["owner-helper"]["source"] == "useradded"
    assert by_name["owner-helper"]["editable"] is True
    assert by_name["owner-helper"]["loaded"] is True
    assert by_name["resource-helper"]["source"] == "bundledResources"
    assert by_name["resource-helper"]["originLabel"] == "Resources (owner overlay)"
    assert by_name["resource-helper"]["overlayActive"] is False
    assert by_name["resource-helper"]["removable"] is False
    assert by_name["resource-edit"]["overlayActive"] is True
    assert by_name["resource-edit"]["removable"] is True
    assert by_name["resource-helper"]["archivedVersions"][0]["restoreId"] == "d" * 64
    assert by_name["archived-owner-helper"]["archivedVersions"][0]["restoreId"] == "restore-token_0123456789"
    assert result["availableActions"]["skills"]["edit"] is True
    assert result["availableActions"]["skills"]["remove"] is True


def test_extension_snapshot_rejects_unbounded_native_inventory():
    with pytest.raises(ValueError, match="exceeded its bound"):
        build_extension_snapshot(skills=[], plugins=[{}] * 513, mcps=[])


def test_extension_snapshot_renders_449_native_skills_without_claiming_unknown_provenance():
    names = [f"resource-skill-{index:03d}" for index in range(396)]
    names.extend(f"unclassified-skill-{index:03d}" for index in range(53))
    snapshot = build_extension_snapshot(
        skills=[{"category": "general", "names": names}], plugins=[], mcps=[],
        skill_catalog=set(names[:396]))
    rows = [row for row in snapshot["items"] if row["kind"] == "skills"]
    resources = [row for row in rows if row["source"] == "bundledResources"]
    unknown = [row for row in rows if row["source"] == "unknown"]

    assert len(rows) == 449
    assert len(resources) == 396
    assert all(row["removable"] is False for row in resources)
    assert len(unknown) == 53
    assert all(row["removable"] is False for row in unknown)


@pytest.mark.parametrize(("source", "provenance", "label"), [
    ("bundled", "builtin", "Hermes files"),
    ("user", "useradded", "files"),
    ("catalog", "unknown", "files"),
    ("config", "unknown", "files"),
    ("plugin", "unknown", "files"),
    ("entrypoint", "unknown", "files"),
    ("unrecognized", "unknown", "files"),
])
def test_provenance_labels_are_truthful(source, provenance, label):
    assert _source_label(source, "files") == (provenance, label)


def test_plugin_setting_edits_match_the_native_nonsecret_schema():
    assert _valid_plugin_setting({"type": "enum", "choices": ["safe", "strict"]}, "strict")
    assert not _valid_plugin_setting({"type": "enum", "choices": ["safe", "strict"]}, "unsafe")
    assert not _valid_plugin_setting({"type": "secret"}, "secret-value")
    assert not _valid_plugin_setting({"type": "number"}, True)


def test_extensions_feature_asset_uses_only_fixed_routes():
    validate_feature_assets((FEATURE_ASSETS,))
    assert ("GET", "/chat/api/extensions") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/plugins/remove") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/edit") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/remove") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/restore-list") in FEATURE_ASSETS.api_routes
    assert ("POST", "/chat/api/extensions/skills/restore") in FEATURE_ASSETS.api_routes


def test_extensions_mount_unmount_remount_owns_one_submit_and_ignores_late_results():
    harness = r'''
class Target {
  constructor() { this.listeners = new Map(); this.children = []; this.disabled = false; this.textContent = ''; }
  addEventListener(type, listener, options = {}) {
    if (options.signal && options.signal.aborted) return;
    const entry = {listener, once: options.once === true};
    const rows = this.listeners.get(type) || []; rows.push(entry); this.listeners.set(type, rows);
    if (options.signal) options.signal.addEventListener('abort', () => {
      this.listeners.set(type, (this.listeners.get(type) || []).filter((row) => row !== entry));
    }, {once: true});
  }
  async dispatch(type, event = {}) {
    for (const entry of [...(this.listeners.get(type) || [])]) {
      if (entry.once) this.listeners.set(type, (this.listeners.get(type) || []).filter((row) => row !== entry));
      await entry.listener(event);
    }
  }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  remove() { this.removed = true; }
  querySelector(selector) { return this.selectors.get(selector); }
  reset() { this.resetCount = (this.resetCount || 0) + 1; }
}
const root = new Target(); root.selectors = new Map();
const list = new Target(), status = new Target(), refresh = new Target();
const skillForm = new Target(); skillForm.value = 'web-facts';
for (const [selector, element] of [
  ['[data-extension-list]', list], ['[data-extension-status]', status],
  ['[data-extension-refresh]', refresh], ['[data-add-skill]', skillForm],
  ['[data-add-plugin]', new Target()], ['[data-add-mcp]', new Target()]
]) root.selectors.set(selector, element);
root.querySelector = (selector) => selector === '[data-feature-root="extensions"]' ? root : Target.prototype.querySelector.call(root, selector);
global.document = {createElement: () => new Target()};
global.FormData = class { constructor(form) { this.form = form; } get(key) { return key === 'identifier' ? this.form.value : null; } };
global.window = {prompt: (message) => (message.match(/Type (.+) to confirm/) || [])[1] || null, confirm: () => true};
global.crypto = {getRandomValues: (bytes) => { bytes.fill(7); return bytes; }};
global.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
MOUNT
'''.replace('MOUNT', FEATURE_ASSETS.mount_js)
    harness += r'''
const snapshot = {schema: 1, revision: 'r1', readiness: 'observed', items: []};
let gets = 0, posts = [], releaseFirstGet, releasePost;
const api = {
  get: () => ++gets === 1 ? new Promise((resolve) => { releaseFirstGet = resolve; }) : Promise.resolve(snapshot),
  post: (path, body) => { posts.push({path, body}); return new Promise((resolve) => { releasePost = resolve; }); }
};
const flush = () => new Promise((resolve) => setImmediate(resolve));
(async () => {
  const unmountFirst = mount(root, api); await flush(); unmountFirst();
  const unmountSecond = mount(root, api); await flush();
  const mountedStatus = status.textContent;
  releaseFirstGet(snapshot); await flush();
  assert.equal(status.textContent, mountedStatus, 'a late inventory read from an inactive mount cannot update the view');
  const submitEvent = {preventDefault() { this.prevented = true; }};
  const submission = skillForm.dispatch('submit', submitEvent);
  await flush();
  assert.equal(submitEvent.prevented, true);
  assert.equal(posts.length, 1, 'remount leaves exactly one live owner-add submit handler');
  assert.equal(posts[0].path, '/chat/api/extensions/skills/add');
  const pendingStatus = status.textContent;
  unmountSecond(); releasePost({status: 'applied'}); await submission; await flush();
  assert.equal(status.textContent, pendingStatus, 'a late mutation result cannot update an unmounted view');
  assert.equal(gets, 2, 'inactive mutation completion does not launch another inventory read');
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "extensions-mount-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_extensions_deferred_actions_keep_exact_source_and_require_readback_recovery():
    harness = r'''
class Target {
  constructor(tagName='div') { this.tagName=tagName; this.listeners=new Map(); this.children=[]; this.disabled=false; this.textContent=''; this.value=''; this.attributes={}; }
  append(...nodes) { for (const node of nodes) { node.parent=this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children=[]; this.append(...nodes); }
  remove() { if (this.parent) this.parent.children=this.parent.children.filter(node=>node!==this); this.removed=true; }
  setAttribute(key,value) { this.attributes[key]=value; }
  addEventListener(type,listener,options={}) {
    if (options.signal && options.signal.aborted) return;
    const entry={listener,once:options.once===true}; const rows=this.listeners.get(type)||[]; rows.push(entry); this.listeners.set(type,rows);
    if (options.signal) options.signal.addEventListener('abort',()=>this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry)),{once:true});
  }
  dispatch(type,event={}) {
    for (const entry of [...(this.listeners.get(type)||[])]) {
      if (entry.once) this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry));
      const result=entry.listener(event); if (result && typeof result.then==='function') return result;
    }
  }
  querySelector(selector) {
    if (this.selectors && this.selectors.has(selector)) return this.selectors.get(selector);
    const wanted=selector.toLowerCase();
    const visit=node=>{ for (const child of node.children) { if (child.tagName===wanted) return child; const found=visit(child); if (found) return found; } return null; };
    return visit(this);
  }
  reset() { const input=this.querySelector('input'); if (input) input.value=''; }
  showModal() { this.open=true; }
  close() { this.open=false; this.dispatch('close'); }
  focus() {}
}
function deferred() { let resolve,reject; const promise=new Promise((yes,no)=>{resolve=yes;reject=no;}); return {promise,resolve,reject}; }
function all(node) { return [node,...node.children.flatMap(all)]; }
function button(root,label) { return all(root).find(node=>node.tagName==='button'&&node.textContent===label); }
function makeSnapshot(revision) { return {schema:1,revision,readiness:'observed',items:[{
  kind:'skills',id:'owner-skill-id',name:'owner-helper',label:'Owner helper',source:'useradded',
  originLabel:'Hermes home (owner-added)',editable:true,removable:true,loaded:true,category:'native',
  actionState:'loaded',archivedVersions:[]}]}; }
function makeRoot() {
  const root=new Target(); root.selectors=new Map();
  const list=new Target(),status=new Target(),refresh=new Target('button'); refresh.textContent='Refresh';
  root.append(list,status,refresh);
  root.selectors.set('[data-extension-list]',list); root.selectors.set('[data-extension-status]',status);
  root.selectors.set('[data-extension-refresh]',refresh);
  for (const key of ['skill','plugin','mcp']) {
    const form=new Target('form'),input=new Target('input'),submit=new Target('button'); submit.textContent='Add';
    form.append(input,submit); root.selectors.set(`[data-add-${key}]`,form); root.append(form);
  }
  root.selectors.set('[data-feature-root="extensions"]',root);
  return {root,list,status,refresh};
}
function makeApi() {
  const gets=[],posts=[];
  return {gets,posts,get(path) { const d=deferred(); gets.push({path,...d}); return d.promise; },
    post(path,body) { const d=deferred(); posts.push({path,body,...d}); return d.promise; }};
}
global.document={createElement:tag=>new Target(tag)};
global.FormData=class { constructor(form) { this.form=form; } get(key) { return key==='identifier' ? this.form.querySelector('input').value : null; } };
global.window={prompt:message=>{const match=message.match(/^Type (.+) to confirm/);return match?match[1]:null;},confirm:()=>true};
global.crypto={getRandomValues:bytes=>{bytes.fill(5);return bytes;}};
global.btoa=value=>Buffer.from(value,'binary').toString('base64');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
  const view=makeRoot(),api=makeApi(),unmount=mount(view.root,api);
  assert.equal(api.gets[0].path,'/chat/api/extensions');
  api.gets[0].resolve(makeSnapshot('source-1')); await flush();

  // A delayed file read is bound to the old source revision across inventory refresh.
  const oldRead=button(view.root,'Edit skill').dispatch('click');
  assert.equal(api.posts.length,1);
  assert.equal(api.posts[0].path,'/chat/api/extensions/skills/read');
  assert.deepEqual(api.posts[0].body,{item_id:'owner-skill-id',revision:'source-1'});
  view.refresh.dispatch('click');
  assert.equal(view.refresh.disabled,true);
  api.gets[1].resolve(makeSnapshot('source-2')); await flush();
  api.posts[0].resolve({content:'old reviewed source'}); await oldRead;
  assert.equal(all(view.root).filter(node=>node.tagName==='dialog').length,0);
  assert.match(view.status.textContent,/inventory changed while the skill was loading/);
  assert.equal(api.posts.length,1,'a stale file read never becomes an edit request');

  // Refreshing while the editor is open must reject its old source, never substitute source-3.
  const openedRead=button(view.root,'Edit skill').dispatch('click');
  api.posts[1].resolve({content:'source-2 body'}); await openedRead;
  const dialog=all(view.root).find(node=>node.tagName==='dialog');
  assert.ok(dialog && dialog.open);
  view.refresh.dispatch('click'); api.gets[2].resolve(makeSnapshot('source-3')); await flush();
  const staleSave=button(dialog,'Save skill').dispatch('click'); await staleSave;
  assert.equal(api.posts.length,2,'an editor opened at source-2 cannot write after source-3 refresh');
  assert.match(view.status.textContent,/inventory changed while this editor was open/);

  // One confirmed edit serializes the whole UI; an uncertain outcome waits for explicit readback.
  const currentRead=button(view.root,'Edit skill').dispatch('click');
  api.posts[2].resolve({content:'source-3 body'}); await currentRead;
  const currentDialog=all(view.root).find(node=>node.tagName==='dialog');
  const area=all(currentDialog).find(node=>node.tagName==='textarea'); area.value='reviewed source-3 edit';
  const save=button(currentDialog,'Save skill').dispatch('click'); await flush();
  assert.equal(api.posts.length,4);
  assert.equal(api.posts[3].path,'/chat/api/extensions/skills/edit');
  assert.deepEqual(Object.keys(api.posts[3].body).sort(),['confirmation','content','idempotency_key','item_id','revision']);
  assert.equal(api.posts[3].body.item_id,'owner-skill-id');
  assert.equal(api.posts[3].body.revision,'source-3');
  assert.equal(api.posts[3].body.content,'reviewed source-3 edit');
  assert.match(api.posts[3].body.idempotency_key,/^[A-Za-z0-9_-]{32}$/);
  assert.equal(view.refresh.disabled,true);
  assert.ok(all(view.root).filter(node=>node.tagName==='button'&&node!==view.refresh).every(node=>node.disabled),
    'every owner action is disabled while a confirmed mutation is pending');
  button(view.root,'Archive skill').dispatch('click'); await flush();
  assert.equal(api.posts.length,4,'another card cannot mint a second request or idempotency key while busy');
  api.posts[3].resolve({status:'applied'}); await flush();
  assert.equal(api.gets.length,4,'applied response triggers exactly one current inventory readback');
  api.gets[3].resolve(makeSnapshot('source-4')); await save;
  assert.match(view.status.textContent,/Owner action reported applied; current inventory readback completed/);
  assert.equal(button(view.root,'Edit skill').disabled,false);

  // A rejected mutation remains unknown and cannot auto-retry; explicit refresh recovers actions.
  const nextRead=button(view.root,'Edit skill').dispatch('click');
  api.posts[4].resolve({content:'source-4 body'}); await nextRead;
  const nextDialog=all(view.root).find(node=>node.tagName==='dialog');
  const failingSave=button(nextDialog,'Save skill').dispatch('click'); await flush();
  assert.equal(api.posts[5].body.revision,'source-4');
  api.posts[5].reject(new Error('write response lost')); await failingSave;
  assert.match(view.status.textContent,/outcome is unknown/);
  assert.equal(api.gets.length,4,'uncertain write does not launch an automatic read or repeat effect');
  assert.equal(view.refresh.disabled,false);
  assert.equal(button(view.root,'Edit skill').disabled,true);
  view.refresh.dispatch('click'); api.gets[4].resolve(makeSnapshot('source-5')); await flush();
  assert.match(view.status.textContent,/Inventory refreshed; review the observed source/);
  assert.equal(button(view.root,'Edit skill').disabled,false);

  // Rejected file reads stay read-only, and an unmounted late read cannot open an editor.
  const rejectedRead=button(view.root,'Edit skill').dispatch('click');
  api.posts[6].reject(new Error('read unavailable')); await rejectedRead;
  assert.match(view.status.textContent,/Current skill source is unavailable/);
  assert.equal(api.posts.length,7);
  view.refresh.dispatch('click'); api.gets[5].resolve(makeSnapshot('source-6')); await flush();
  const lateRead=button(view.root,'Edit skill').dispatch('click');
  assert.deepEqual(api.posts[7].body,{item_id:'owner-skill-id',revision:'source-6'});
  const statusAtUnmount=view.status.textContent; unmount();
  api.posts[7].resolve({content:'late body'}); await lateRead;
  assert.equal(all(view.root).filter(node=>node.tagName==='dialog').length,0);
  assert.equal(view.status.textContent,statusAtUnmount);
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('MOUNT', FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "extensions-source-revision-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_plugin_settings_form_is_typed_exact_and_revision_bound():
    harness = r'''
class Target {
  constructor(tagName='div') { this.tagName=tagName; this.listeners=new Map(); this.children=[]; this.disabled=false; this.textContent=''; this.value=''; this.attributes={}; this.open=false; }
  append(...nodes) { for (const node of nodes) { node.parent=this; this.children.push(node); } }
  replaceChildren(...nodes) { this.children=[]; this.append(...nodes); }
  remove() { if (this.parent) this.parent.children=this.parent.children.filter(node=>node!==this); this.removed=true; }
  setAttribute(key,value) { this.attributes[key]=value; }
  addEventListener(type,listener,options={}) {
    if (options.signal && options.signal.aborted) return;
    const entry={listener,once:options.once===true}; const rows=this.listeners.get(type)||[]; rows.push(entry); this.listeners.set(type,rows);
    if (options.signal) options.signal.addEventListener('abort',()=>this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry)),{once:true});
  }
  dispatch(type,event={}) {
    for (const entry of [...(this.listeners.get(type)||[])]) {
      if (entry.once) this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry));
      const result=entry.listener(event); if (result && typeof result.then==='function') return result;
    }
  }
  querySelector(selector) {
    if (this.selectors && this.selectors.has(selector)) return this.selectors.get(selector);
    const wanted=selector.toLowerCase();
    const visit=node=>{ for (const child of node.children) { if (child.tagName===wanted) return child; const found=visit(child); if (found) return found; } return null; };
    return visit(this);
  }
  showModal() { this.open=true; }
  close() { this.open=false; this.dispatch('close'); }
  focus() { global.document.activeElement=this; }
}
function deferred() { let resolve,reject; const promise=new Promise((yes,no)=>{resolve=yes;reject=no;}); return {promise,resolve,reject}; }
function all(node) { return [node,...node.children.flatMap(all)]; }
function button(root,label) { return all(root).find(node=>node.tagName==='button'&&node.textContent===label); }
function makeSnapshot(revision,settings=validSettings()) { return {schema:1,revision,readiness:'observed',items:[{
  kind:'plugins',id:'owner-plugin-id',name:'safe-package',label:'Safe package',source:'useradded',editable:true,removable:true,
  settingsRevision:'a'.repeat(64),settings}]}; }
function validSettings() { return [
  {key:'site_name',label:'Site name',type:'string',value:'Home',required:true},
  {key:'enabled',label:'Enabled',type:'boolean',value:true,required:true},
  {key:'mode',label:'Mode',type:'enum',choices:['safe','strict'],value:'strict',required:true},
  {key:'limit',label:'Limit',type:'number',value:2,required:true},
  {key:'notes',label:'Ordinary URL and markup text',type:'string',value:'https://docs.example/start',required:false}
]; }
function makeRoot() {
  const root=new Target(); root.selectors=new Map();
  const list=new Target(),status=new Target(),refresh=new Target('button'); refresh.textContent='Refresh';
  root.append(list,status,refresh);
  root.selectors.set('[data-extension-list]',list); root.selectors.set('[data-extension-status]',status); root.selectors.set('[data-extension-refresh]',refresh);
  for (const key of ['skill','plugin','mcp']) { const form=new Target('form'),input=new Target('input'),submit=new Target('button'); form.append(input,submit); root.selectors.set(`[data-add-${key}]`,form); root.append(form); }
  root.selectors.set('[data-feature-root="extensions"]',root); return {root,list,status,refresh};
}
function makeApi() { const gets=[],posts=[]; return {gets,posts,get(path) { const d=deferred(); gets.push({path,...d}); return d.promise; },post(path,body) { const d=deferred(); posts.push({path,body,...d}); return d.promise; }}; }
global.document={activeElement:null,createElement:tag=>new Target(tag)};
global.FormData=class { constructor(form) { this.form=form; } get() { return null; } };
global.window={prompt:message=>{const match=message.match(/^Type (.+) to confirm/);return match?match[1]:null;},confirm:()=>true};
global.crypto={getRandomValues:bytes=>{bytes.fill(5);return bytes;}};
global.btoa=value=>Buffer.from(value,'binary').toString('base64');
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function editor(view) { return all(view.list).find(node=>node.tagName==='dialog'); }
function field(dialog,key) { return all(dialog).find(node=>node.id && node.id===key); }
function settingInput(dialog,index) { return all(dialog).find(node=>node.id===`extension-setting-${index}`); }
function submit(dialog) { const form=all(dialog).find(node=>node.tagName==='form'); form.dispatch('submit',{preventDefault(){this.prevented=true;}}); }
(async()=>{
  const view=makeRoot(),api=makeApi(),unmount=mount(view.root,api);
  api.gets[0].resolve(makeSnapshot('source-1')); await flush();
  const opener=button(view.list,'Edit settings'); opener.focus(); opener.dispatch('click');
  let dialog=editor(view); assert.ok(dialog && dialog.open);
  assert.match(all(dialog).map(node=>node.textContent).join(' '),/Plugin: safe-package · Source: useradded · Inventory revision: source-1 · Native settings revision: a{64}/);
  assert.match(all(dialog).map(node=>node.textContent).join(' '),/Nothing changes until you choose Save/);
  const string=settingInput(dialog,0),bool=settingInput(dialog,1),enumeration=settingInput(dialog,2),number=settingInput(dialog,3);
  assert.equal(string.tagName,'textarea'); assert.equal(string.maxLength,4096,'the form allows 2048 Unicode code points before applying the native limit');
  assert.equal(bool.tagName,'select'); assert.equal(enumeration.tagName,'select'); assert.equal(number.type,'number'); assert.equal(number.step,'any');

  // Each native type rejects implicit, empty, or invalid values before any POST.
  bool.value=''; submit(dialog); assert.match(all(dialog).map(node=>node.textContent).join(' '),/Choose true or false explicitly/); assert.equal(api.posts.length,0);
  bool.value='boolean:false'; enumeration.value=''; submit(dialog); assert.match(all(dialog).map(node=>node.textContent).join(' '),/Choose one exact native option/); assert.equal(api.posts.length,0);
  enumeration.value='choice:0'; number.value='Infinity'; submit(dialog); assert.match(all(dialog).map(node=>node.textContent).join(' '),/Enter a finite number/); assert.equal(api.posts.length,0);
  number.value='2.5'; string.value='   '; submit(dialog); assert.match(all(dialog).map(node=>node.textContent).join(' '),/This setting is required/); assert.equal(api.posts.length,0);
  assert.equal(document.activeElement,string,'invalid submission focuses the first invalid control');

  string.value='Office'; settingInput(dialog,4).value=''; submit(dialog); await flush();
  assert.equal(api.posts.length,1); assert.equal(api.posts[0].path,'/chat/api/extensions/plugins/edit');
  assert.deepEqual(Object.keys(api.posts[0].body).sort(),['confirmation','idempotency_key','item_id','revision','values']);
  assert.equal(api.posts[0].body.item_id,'owner-plugin-id'); assert.equal(api.posts[0].body.revision,'source-1');
  assert.equal(api.posts[0].body.confirmation,'EDIT Safe package');
  assert.deepEqual({...api.posts[0].body.values},{site_name:'Office',enabled:false,mode:'safe',limit:2.5,notes:''});
  assert.match(api.posts[0].body.idempotency_key,/^[A-Za-z0-9_-]{32}$/);
  assert.ok(all(view.root).filter(node=>node.tagName==='button'&&node!==view.refresh).every(node=>node.disabled), 'all owner actions stay blocked during the confirmed mutation');
  api.posts[0].resolve({status:'applied'}); await flush(); assert.equal(api.gets.length,2);
  api.gets[1].resolve(makeSnapshot('source-2')); await flush();
  assert.match(view.status.textContent,/current inventory readback completed/);

  // Cancel, Escape, and unmount close without writes and return focus to the invoking card action.
  let currentOpener=button(view.list,'Edit settings'); currentOpener.focus(); currentOpener.dispatch('click'); dialog=editor(view);
  button(dialog,'Cancel').dispatch('click'); assert.equal(document.activeElement,currentOpener); assert.equal(api.posts.length,1);
  currentOpener=button(view.list,'Edit settings'); currentOpener.focus(); currentOpener.dispatch('click'); dialog=editor(view);
  dialog.close(); assert.equal(document.activeElement,currentOpener,'native Escape close restores opener focus'); assert.equal(api.posts.length,1);
  currentOpener=button(view.list,'Edit settings'); currentOpener.focus(); currentOpener.dispatch('click'); dialog=editor(view);
  unmount(); assert.equal(document.activeElement,currentOpener,'unmount closes editor and restores focus'); assert.equal(api.posts.length,1);

  // Malformed schemas remain visible as pending and cannot be silently narrowed into an edit.
  const badView=makeRoot(),badApi=makeApi(),dispose=mount(badView.root,badApi);
  badApi.gets[0].resolve(makeSnapshot('bad-rev',[{key:'opaque',label:'Opaque',type:'secret',value:'hidden'}])); await flush();
  const badOpener=button(badView.list,'Edit settings'); badOpener.dispatch('click'); const pending=editor(badView);
  assert.match(all(pending).map(node=>node.textContent).join(' '),/Editing remains pending/);
  assert.equal(button(pending,'Save settings').disabled,true);
  assert.equal(all(pending).some(node=>node.textContent==='hidden'),false,'untrusted unsupported values are never rendered');
  pending.close(); assert.equal(badApi.posts.length,0); dispose();

  // Schema-valid prose, URL-like values, optional empty strings, and markup-looking text remain inert DOM values.
  const textView=makeRoot(),textApi=makeApi(),textCleanup=mount(textView.root,textApi);
  const textSettings=[{key:'caption',label:'<em>Caption</em>',type:'string',value:'https://docs.example/start',required:false}];
  textApi.gets[0].resolve(makeSnapshot('text-rev',textSettings)); await flush();
  const textOpener=button(textView.list,'Edit settings'); textOpener.dispatch('click'); const textDialog=editor(textView);
  assert.equal(all(textDialog).some(node=>node.tagName==='em'),false,'schema labels render as text, never markup');
  const textValue=settingInput(textDialog,0); textValue.value='<img src=x onerror=alert(1)>';
  submit(textDialog); await flush();
  assert.equal(textApi.posts[0].body.values.caption,'<img src=x onerror=alert(1)>');
  assert.equal(all(textView.root).some(node=>node.tagName==='img'),false,'schema values stay inert and do not create markup');
  textApi.posts[0].resolve({status:'applied'}); await flush(); textApi.gets[1].resolve(makeSnapshot('text-rev-2',textSettings)); await flush(); textCleanup();

  // A refresh while an editor is open cannot rebind the form to a newer inventory revision.
  const staleView=makeRoot(),staleApi=makeApi(),clean=mount(staleView.root,staleApi);
  staleApi.gets[0].resolve(makeSnapshot('stale-1')); await flush();
  const staleOpener=button(staleView.list,'Edit settings'); staleOpener.dispatch('click'); const staleDialog=editor(staleView);
  staleView.refresh.dispatch('click'); staleApi.gets[1].resolve(makeSnapshot('stale-2')); await flush();
  submit(staleDialog); await flush(); assert.equal(staleApi.posts.length,0); assert.match(staleView.status.textContent,/source changed while this editor was open/);
  assert.equal(document.activeElement,staleOpener); clean();
  console.log('PLUGIN_SETTINGS_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('MOUNT', FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "plugin-settings-form-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PLUGIN_SETTINGS_HARNESS_COMPLETE" in result.stdout, "deferred plugin settings scenarios did not complete"
