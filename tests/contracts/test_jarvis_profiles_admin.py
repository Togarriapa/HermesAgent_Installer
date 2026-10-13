from __future__ import annotations

import hashlib
import subprocess
import tempfile
from pathlib import Path

import pytest

from hermes_installer.remote.jarvis_chat import JarvisChatDenied
from hermes_installer.remote.jarvis_profiles_admin import (
    JarvisProfileAdmin, ProfileAdminDescriptor, ProfileAdminFile,
    ProfileAdminWriteResult, reviewed_profiles_admin_feature,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class _Provider:
    def __init__(self):
        self.files = {("hermes", "soul"): "Jarvis owner prompt\n",
                      ("dev-peter", "soul"): "Internal profile prompt\n"}
        self.generation = "a" * 64
        self.writes = []
        self.profile_rows = (
            ProfileAdminDescriptor("hermes", "Jarvis", "jarvis", self.generation, ("soul",)),
            ProfileAdminDescriptor("dev-peter", "Dev Peter", "expert", self.generation, ("soul",)),
        )

    def list_profiles(self, *, subject, core_generation, access_jwt, accepted_ingress):
        return self.profile_rows

    def read_file(self, *, subject, core_generation, profile_key, file_kind, access_jwt, accepted_ingress):
        value = self.files[(profile_key, file_kind)]
        return ProfileAdminFile(profile_key, file_kind, "SOUL.md", self.generation,
                                value, _sha(value), True)

    def write_generation(self, *, subject, core_generation, profile_key, file_kind,
                         expected_sha256, content, idempotency_key, access_jwt, accepted_ingress):
        before = self.files[(profile_key, file_kind)]
        if _sha(before) != expected_sha256:
            return ProfileAdminWriteResult("conflict", None, _sha(before), None, False)
        self.files[(profile_key, file_kind)] = content
        self.generation = _sha(self.generation + _sha(content))
        self.writes.append((profile_key, file_kind, idempotency_key))
        return ProfileAdminWriteResult("active", self.generation, _sha(content), "recovery-safe-id-12345", True)


def test_opaque_profile_ids_bind_owner_and_current_core_generation_and_never_expose_paths():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    snapshot = admin.list_profiles(subject="owner-a", core_generation="core-a",
                                   access_jwt="jwt", accepted_ingress=object())
    assert [item["kind"] for item in snapshot["profiles"]] == ["jarvis", "expert"]
    assert all("path" not in item for item in snapshot["profiles"])
    profile_id = snapshot["profiles"][1]["id"]
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-b", core_generation="core-a", profile_id=profile_id,
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-a", core_generation="core-b", profile_id=profile_id,
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())
    with pytest.raises(JarvisChatDenied):
        admin.read_file(subject="owner-a", core_generation="core-a", profile_id="../SOUL.md",
                        file_kind="soul", access_jwt="jwt", accepted_ingress=object())


@pytest.mark.parametrize("count", [65, 208])
def test_profile_inventory_accepts_complete_current_rows_through_native_bound(count):
    provider = _Provider()
    provider.profile_rows = (ProfileAdminDescriptor("hermes", "Jarvis", "jarvis",
        provider.generation, ("soul",)),) + tuple(
        ProfileAdminDescriptor(f"expert-{index}", f"Expert {index}", "expert",
            provider.generation, ("soul",)) for index in range(count - 1))
    result = JarvisProfileAdmin(provider).list_profiles(subject="owner-a", core_generation="core-a",
        access_jwt="jwt", accepted_ingress=object())
    assert len(result["profiles"]) == count
    assert sum(row["kind"] == "jarvis" for row in result["profiles"]) == 1
    assert all(row["files"] == [{"kind": "soul", "name": "SOUL.md", "editable": True}]
               for row in result["profiles"])


def test_profile_inventory_denies_over_bound_duplicates_and_missing_jarvis():
    provider = _Provider()
    jarvis = provider.profile_rows[0]
    provider.profile_rows = (jarvis,) + tuple(ProfileAdminDescriptor(
        f"expert-{index}", f"Expert {index}", "expert", provider.generation, ())
        for index in range(208))
    admin = JarvisProfileAdmin(provider)
    with pytest.raises(JarvisChatDenied):
        admin.list_profiles(subject="owner-a", core_generation="core-a", access_jwt="jwt",
                            accepted_ingress=object())
    provider.profile_rows = (jarvis, jarvis)
    with pytest.raises(JarvisChatDenied):
        admin.list_profiles(subject="owner-a", core_generation="core-a", access_jwt="jwt",
                            accepted_ingress=object())
    provider.profile_rows = (ProfileAdminDescriptor("dev-peter", "Dev Peter", "expert",
        provider.generation, ("soul",)),)
    with pytest.raises(JarvisChatDenied):
        admin.list_profiles(subject="owner-a", core_generation="core-a", access_jwt="jwt",
                            accepted_ingress=object())
    provider.profile_rows = (jarvis, ProfileAdminDescriptor("bad key", "Broken", "expert",
        provider.generation, ("soul",)))
    with pytest.raises(JarvisChatDenied):
        admin.list_profiles(subject="owner-a", core_generation="core-a", access_jwt="jwt",
                            accepted_ingress=object())


def test_save_requires_fresh_single_use_review_token_and_exact_file_cas():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][1]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    proposed = initial["content"] + "Use concise answers.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    assert "Use concise answers." in preview["diff"]
    saved = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567890")
    assert saved["state"] == "active" and saved["effectiveReadback"] is True
    assert len(provider.writes) == 1
    with pytest.raises(JarvisChatDenied):
        admin.save(**auth, profile_id=profile_id, file_kind="soul",
            base_sha256=initial["sha256"], content=proposed,
            preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567890")


def test_primary_soul_prefix_is_editable_through_the_reviewed_transaction():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][0]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    assert initial["editable"] is True
    assert initial["protectedSuffix"] == ""
    proposed = initial["content"] + "Owner-managed prompt prefix.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    saved = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="primary_prefix_edit_1234567890")
    assert saved["state"] == "active"
    assert provider.files[("hermes", "soul")] == proposed
    assert len(provider.writes) == 1


def test_source_race_consumes_preview_without_repeating_the_write():
    provider = _Provider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][1]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    proposed = initial["content"] + "Changed by owner.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    provider.files[("dev-peter", "soul")] = "concurrent edit\n"
    result = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="idempotency_key_1234567891")
    assert result["state"] == "conflict"
    assert provider.writes == []


def test_primary_soul_preview_and_save_keep_the_managed_suffix_protected():
    class _ManagedProvider(_Provider):
        suffix = "\n<!-- managed Jarvis block -->\nPinned instructions.\n"

        def read_file(self, *, subject, core_generation, profile_key, file_kind,
                      access_jwt, accepted_ingress):
            prefix = self.files[(profile_key, file_kind)]
            return ProfileAdminFile(profile_key, file_kind, "SOUL.md", self.generation,
                prefix, _sha(prefix + self.suffix), True, self.suffix, True)

        def write_generation(self, *, subject, core_generation, profile_key, file_kind,
                             expected_sha256, content, idempotency_key, access_jwt, accepted_ingress):
            before = self.files[(profile_key, file_kind)]
            assert expected_sha256 == _sha(before + self.suffix)
            assert "managed Jarvis block" not in content
            self.files[(profile_key, file_kind)] = content
            self.writes.append((profile_key, file_kind, idempotency_key))
            return ProfileAdminWriteResult("active", self.generation, _sha(content),
                "prefix-edit-recovery-id", True)

    provider = _ManagedProvider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][0]["id"]
    initial = admin.read_file(**auth, profile_id=profile_id, file_kind="soul")
    assert initial["content"] == "Jarvis owner prompt\n"
    assert initial["protectedSuffix"] == provider.suffix
    assert initial["managedPrimary"] is True
    proposed = initial["content"] + "Use concise answers.\n"
    preview = admin.preview(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed)
    assert "Use concise answers." in preview["diff"]
    assert "managed Jarvis block" not in preview["diff"]
    saved = admin.save(**auth, profile_id=profile_id, file_kind="soul",
        base_sha256=initial["sha256"], content=proposed,
        preview_token=preview["previewToken"], idempotency_key="prefix_edit_key_1234567890")
    assert saved["state"] == "active"
    assert provider.files[("hermes", "soul")] == proposed


def test_profile_file_projection_rejects_a_modified_protected_suffix():
    class _TamperedProvider(_Provider):
        def read_file(self, *, subject, core_generation, profile_key, file_kind,
                      access_jwt, accepted_ingress):
            value = self.files[(profile_key, file_kind)]
            return ProfileAdminFile(profile_key, file_kind, "SOUL.md", self.generation,
                value, _sha(value), True, "unverified protected suffix", True)

    provider = _TamperedProvider()
    admin = JarvisProfileAdmin(provider)
    auth = {"subject": "owner-a", "core_generation": "core-a",
            "access_jwt": "jwt", "accepted_ingress": object()}
    profile_id = admin.list_profiles(**auth)["profiles"][0]["id"]
    with pytest.raises(JarvisChatDenied):
        admin.read_file(**auth, profile_id=profile_id, file_kind="soul")


def test_editor_fragment_uses_fixed_routes_and_never_opens_expert_chat():
    feature = reviewed_profiles_admin_feature()
    assert ("POST", "/chat/api/profiles/{profile_id}/save") in feature.api_routes
    assert "textarea" in feature.view_html and "Review changes" in feature.view_html
    assert "Experts remain internal workers" in feature.view_html
    assert "chat with" not in feature.mount_js.lower()
    assert "localStorage" not in feature.mount_js and "sessionStorage" not in feature.mount_js
    assert "file.editable===true" in feature.mount_js
    assert "value.managedPrimary?\"Jarvis owner prefix · managed overlay stays protected\"" in feature.mount_js
    assert "protectedContent.textContent=value.protectedSuffix" in feature.mount_js


def test_editor_review_is_bound_to_exact_snapshot_and_recovers_after_denied_preview_and_save():
    feature = reviewed_profiles_admin_feature()
    harness = r'''
const cryptoNode = require('node:crypto');
class Target {
  constructor() { this.value=''; this.disabled=false; this.hidden=false; this.textContent=''; this.options=[]; this.listeners={}; }
  addEventListener(name, fn) { this.listeners[name]=fn; }
  dispatch(name) { return this.listeners[name]({target:this}); }
  replaceChildren(...nodes) { this.options=[...nodes]; }
  add(node) { this.options.push(node); }
  get optionsLength() { return this.options.length; }
  querySelector() { return null; }
}
global.Option=class { constructor(text,value) { this.text=text; this.value=value; } };
let deferNextDigest=false, releaseDigest;
Object.defineProperty(globalThis,'crypto',{configurable:true,writable:true,value:{getRandomValues(bytes){bytes.fill(3);return bytes;},subtle:{digest(_alg,data){const result=cryptoNode.createHash('sha256').update(Buffer.from(data)).digest();if(deferNextDigest){deferNextDigest=false;return new Promise(resolve=>{releaseDigest=()=>resolve(result);});}return Promise.resolve(result);}}}});
const selectors=['[data-profile-status]','[data-profile-select]','[data-profile-search]','[data-profile-count]','[data-profile-empty]','[data-file-select]','[data-profile-editor]','[data-profile-review]','[data-profile-save]','[data-profile-diff]','[data-protected-section]','[data-protected-content]','[data-editor-title]','[data-editor-state]','[data-profile-generation]'];
const nodes=new Map(selectors.map(key=>[key,new Target()]));
const root={querySelector:key=>nodes.get(key)};
const status=nodes.get('[data-profile-status]'), profile=nodes.get('[data-profile-select]'), search=nodes.get('[data-profile-search]'), count=nodes.get('[data-profile-count]'), empty=nodes.get('[data-profile-empty]'), files=nodes.get('[data-file-select]');
''' + r'''
const editor=nodes.get('[data-profile-editor]'), review=nodes.get('[data-profile-review]'), save=nodes.get('[data-profile-save]');
const profileId='a'.repeat(64), content='Original\n', proposed=content+'Edited\n';
const hash=value=>cryptoNode.createHash('sha256').update(value).digest('hex');
const profileRow={id:profileId,name:'Jarvis',kind:'jarvis',sourceGeneration:'generation-1',files:[{kind:'soul',name:'SOUL.md',editable:true}]};
let inventory=[profileRow];
let previewCalls=0, saveCalls=0, releaseStalePreview, releaseUnmountPreview, releaseDeniedSave, activeContent=content;
const saveBodies=[];
const api={
 get:async path=>path==='/chat/api/profiles'?{profiles:inventory}:{profileId,fileKind:'soul',fileName:'SOUL.md',content:activeContent,protectedSuffix:'',managedPrimary:false,editable:true,sha256:hash(activeContent),sourceGeneration:'generation-1',effective:true},
 post:(path,body)=>{
  if(path.endsWith('/preview')){
   previewCalls++;
   if(previewCalls===1)return new Promise(resolve=>{releaseStalePreview=()=>resolve({diff:'stale diff',previewToken:'stale-token',contentSha256:hash(body.content),baseSha256:body.base_sha256});});
   if(previewCalls===5)return new Promise(resolve=>{releaseUnmountPreview=()=>resolve({diff:'late diff',previewToken:'late-token',contentSha256:hash(body.content),baseSha256:body.base_sha256});});
   return Promise.resolve({diff:'reviewed diff',previewToken:'token-'+previewCalls,contentSha256:hash(body.content),baseSha256:body.base_sha256});
  }
  saveCalls++;saveBodies.push({path,body});
  if(saveCalls===1)return new Promise(resolve=>{releaseDeniedSave=()=>resolve({state:'conflict',effectiveReadback:false});});
  activeContent=proposed; return Promise.resolve({state:'active',effectiveReadback:true,sha256:hash(proposed)});
 }
};
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 const unmount=mount(root,api); await flush();
 profile.value=profileId; await profile.dispatch('change'); files.value='soul'; await files.dispatch('change'); await flush(); await flush();
 assert.equal(editor.value,content);
 editor.value=proposed; editor.dispatch('input');
 const pendingReview=review.dispatch('click'); await flush();
 editor.value=proposed+'changed while pending\n'; editor.dispatch('input');
 releaseStalePreview(); await pendingReview;
 assert.equal(save.disabled,true,'late preview cannot authorize edited content');
 editor.value=proposed; editor.dispatch('input');
 deferNextDigest=true; const digestReview=review.dispatch('click'); await flush();
 assert.equal(typeof releaseDigest,'function','preview digest is pending');
 profile.value=''; await profile.dispatch('change');
 profile.value=profileId; await profile.dispatch('change'); files.value='soul'; await files.dispatch('change'); await flush(); await flush();
 releaseDigest(); await digestReview;
 assert.equal(save.disabled,true,'selection ABA during digest cannot authorize a preview');
 editor.value=proposed; editor.dispatch('input'); await review.dispatch('click');
 assert.equal(save.disabled,false,'a fresh exact snapshot preview enables save');
 search.value='does-not-match'; search.dispatch('input');
 assert.equal(profile.value,profileId,'filtering retains the selected profile');
 assert.equal(editor.value,proposed,'filtering does not reload or replace the exact editor snapshot');
 assert.equal(save.disabled,false,'filtering does not invalidate the reviewed snapshot');
 assert.equal(empty.hidden,false,'a no-match search has an accessible empty state');
 search.value=''; search.dispatch('input');
 const pendingSave=save.dispatch('click'); await flush();
 releaseDeniedSave(); await pendingSave;
 assert.equal(saveCalls,1,'denied save is not retried automatically');
 assert.match(status.textContent,/source changed/i);
 await review.dispatch('click'); assert.equal(save.disabled,false,'conflict recovery requires a fresh preview');
 await save.dispatch('click');
 assert.equal(saveCalls,2);
 assert.deepEqual(saveBodies[1],{path:`/chat/api/profiles/${profileId}/save`,body:{file_kind:'soul',base_sha256:hash(content),content:proposed,preview_token:'token-4',idempotency_key:saveBodies[1].body.idempotency_key}});
 assert.equal(activeContent,proposed,'successful reviewed save has the expected source effect');
 assert.equal(editor.value,proposed,'effective readback refreshes the editor from the saved source');
 editor.value=proposed+'later edit\n'; editor.dispatch('input');
 const pendingUnmount=review.dispatch('click'); await flush();
 const beforeLatePreview=status.textContent; unmount(); releaseUnmountPreview(); await pendingUnmount;
 assert.equal(status.textContent,beforeLatePreview,'unmounted editor ignores delayed preview completion');
 assert.equal(save.disabled,true,'unmounted editor cannot retain a save grant');
 inventory=[profileRow,...Array.from({length:207},(_,index)=>({id:(index+1).toString(16).padStart(64,'0'),name:`Expert ${index}`,kind:'expert',sourceGeneration:'generation-1',files:[{kind:'soul',name:'SOUL.md',editable:true}]}))];
 const fullUnmount=mount(root,api); await flush();
 assert.equal(profile.options.length,209,'208 real rows, including one Jarvis, render with the placeholder');
 assert.match(count.textContent,/208 matching profiles · 208 existing editable native file records/,'visible count reflects actual file records');
 fullUnmount();
 profile.replaceChildren(new Option('Loading profiles…',''));
 inventory=[profileRow,...Array.from({length:208},(_,index)=>({id:(index+1).toString(16).padStart(64,'0'),name:`Expert ${index}`,kind:'expert',sourceGeneration:'generation-1',files:[{kind:'soul',name:'SOUL.md',editable:true}]}))];
 mount(root,api); await flush();
 assert.equal(profile.options.length,1,'209 profile rows are denied and leave only the initial loading placeholder');
 assert.equal(profile.options[0].text,'Loading profiles…');
 assert.match(status.textContent,/unavailable/i);
 console.log('PROFILE_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "profiles-admin-mount-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + feature.mount_js + "\n" + harness,
                       encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False,
                                timeout=15)
    assert result.returncode == 0, result.stderr
    assert "PROFILE_HARNESS_COMPLETE" in result.stdout
