from __future__ import annotations

import time

import pytest

from hermes_installer.remote.jarvis_activity import JarvisActivityStore, NativeActivityEvent
from hermes_installer.remote.jarvis_chat import (
    ChatPrincipal,
    JarvisChatDenied,
    JarvisChatStore,
)
from hermes_installer.remote.jarvis_activity_assets import FEATURE_ASSETS


def _principal(subject="owner-a", generation="core-generation-a"):
    return ChatPrincipal(subject, time.monotonic() + 120, time.monotonic() + 4, generation)


def _turn(store, subject="owner-a"):
    conversation = store.create_conversation(
        subject, f"runtime-{subject}", f"stored-{subject}", "core-generation-a")
    turn_id, _nonce, _conversation = store.begin_turn(
        subject, conversation["id"], "question", "request-key-0000000001", _principal(subject))
    return conversation, turn_id


def test_activity_requires_exact_native_type_and_owner_session_generation_lease(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    event = NativeActivityEvent("tool.start", "running", "runtime-owner-a", "native-tool-1")

    recorded = activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event)
    assert recorded["type"] == "tool.start"
    assert recorded["status"] == "running"
    assert recorded["source_event_id"].startswith("evt_")

    assert activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event) is None
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal("owner-b"), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a", event=event)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(generation="core-generation-b"),
            conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-b", event=event)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a",
            event=NativeActivityEvent("tool.start", "running", "another-runtime"))


def test_activity_persists_closed_projection_and_owner_only_pages(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    event = NativeActivityEvent(
        "session.usage", "observed", "runtime-owner-a", "usage-1",
        duration_ms=12_345, usage=(("input", 120), ("output", 33), ("cache_hit_pct", 82)))
    activity.record_core_event(
        principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
        core_generation="core-generation-a", event=event)

    events, next_before = activity.for_turn("owner-a", turn_id)
    usage = activity.usage_for_turn("owner-a", turn_id)
    assert next_before is None
    assert events[0]["usage"]["input"] == 120
    assert events[0]["usage"]["cache_hit_pct"] == 82
    assert events[0]["usage"]["cost_usd"] is None
    assert usage["cost_usd"] is None
    assert usage["cost_status"] == "unknown"
    assert usage["usage_scope"] == "session_cumulative_snapshot"
    with pytest.raises(JarvisChatDenied, match="turn is unavailable"):
        activity.for_turn("owner-b", turn_id)
    assert activity.recent_for_owner("owner-a")["events"][0]["turnId"] == turn_id
    assert activity.recent_for_owner("owner-b")["events"] == []

    with store._connect() as db:
        payloads = [row[0] for row in db.execute(
            "SELECT data FROM turn_events WHERE turn_id=? AND name='activity.event'", (turn_id,))]
    assert len(payloads) == 1
    assert "runtime-owner-a" not in payloads[0]
    assert "tool-args" not in payloads[0]


def test_activity_accepts_no_untyped_browser_observations(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    with pytest.raises(JarvisChatDenied):
        activity.record_core_event(
            principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a",
            event={"event_type": "tool.start", "session_id": "runtime-owner-a"})


def test_native_child_correlation_is_private_stable_and_turn_scoped(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    activity = JarvisActivityStore(store)
    conversation, turn_id = _turn(store)
    for event_type, status in (("subagent.start", "running"),
                               ("subagent.complete", "completed")):
        recorded = activity.record_core_event(
            principal=_principal(), conversation_id=conversation["id"], turn_id=turn_id,
            core_generation="core-generation-a",
            event=NativeActivityEvent(event_type, status, "runtime-owner-a",
                                      source_identity="child-control-id",
                                      child_session_id="native-child-session-42"))
        assert recorded["type"] == event_type
        assert "child_session_id" not in recorded and "child_ref" not in recorded

    child_rows = activity.native_child_events_for_turn("owner-a", turn_id)
    assert [row["type"] for row in child_rows] == ["subagent.start", "subagent.complete"]
    assert len({row["child_ref"] for row in child_rows}) == 1
    assert len(child_rows[0]["child_ref"]) == 64
    with pytest.raises(JarvisChatDenied, match="turn is unavailable"):
        activity.native_child_events_for_turn("owner-b", turn_id)


def test_activity_decision_dom_serializes_exact_review_and_reconciles_observed_status():
    import shutil
    import subprocess
    import tempfile
    from pathlib import Path

    if shutil.which("node") is None:
        pytest.skip("Node.js is needed to execute the Activity decision race fixture")
    harness = r'''
class Target {
  constructor() { this.children=[]; this.listeners={}; this.disabled=false; this.hidden=false; this.textContent=''; this.style={}; }
  addEventListener(name,fn) { this.listeners[name]=fn; }
  removeEventListener(name) { delete this.listeners[name]; }
  replaceChildren(...items) { this.children=[...items]; }
  append(...items) { this.children.push(...items); }
  contains(node) { return this===node || this.children.some(child=>child.contains?.(node)); }
  setAttribute() {}
  fire(name) { return this.listeners[name]?.(); }
}
function deferred() { let resolve,reject; const promise=new Promise((a,b)=>{resolve=a;reject=b}); return {promise,resolve,reject}; }
const selectors=['[data-events]','[data-usage]','[data-empty]','[data-note]','[data-final-effects]','[data-final-effects-empty]','[data-final-effects-note]','[data-refresh]'];
const nodes=new Map(selectors.map(selector=>[selector,new Target()]));
const root={querySelector:selector=>nodes.get(selector)};
global.document={createElement:()=>new Target()};
let poll, intervalCleared=false, effectRows=[]; const posts=[]; let keyCount=0;
global.window={setInterval(fn){poll=fn;return 91;},clearInterval(id){assert.equal(id,91);intervalCleared=true;}};
global.crypto={randomUUID(){keyCount++;return `key-${keyCount}`;}};
const api={
 get(path){
  if(path==='/chat/api/activity?limit=50')return Promise.resolve({events:[{turnId:'turn-1',type:'approval',status:'pending'}]});
  if(path==='/chat/api/turns/turn-1/usage')return Promise.resolve({usage:{input:1,output:2,total:3,calls:1,reasoning:0,cost_usd:null}});
  if(path==='/chat/api/turns/turn-1/final-effects')return Promise.resolve({turnId:'turn-1',requests:effectRows});
  throw Error('unexpected GET '+path);
 },
 post(path,body){const d=deferred();posts.push({path,body,d});return d.promise;}
};
const mount=new Function('return ('+MOUNT+')')();
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const buttons=()=>nodes.get('[data-final-effects]').children[0]?.children[2]?.children||[];
const effectsNote=()=>nodes.get('[data-final-effects-note]').textContent;
async function pollOnce(){await poll();await flush();await flush();}
(async()=>{
 const cleanup=mount(root,api); await flush(); await flush(); await flush();
 const pending={pendingId:'1'.repeat(64),turnId:'turn-1',reviewSha256:'2'.repeat(64),toolName:'write_file',preview:{tool_name:'write_file'},status:'pending'};
 effectRows=[pending]; await pollOnce();
 const staleApprove=buttons()[0]; await pollOnce(); await staleApprove.fire('click');
 assert.equal(posts.length,0,'callback from a replaced row is ignored');
 const [approve,deny]=buttons();
 const firstDecision=approve.fire('click'); await flush();
 await deny.fire('click'); await approve.fire('click');
 assert.equal(posts.length,1,'opposing and repeated clicks share one decision request');
 assert.equal(posts[0].path,'/chat/api/turns/turn-1/final-effects/decision');
 assert.deepEqual(posts[0].body,{pending_id:pending.pendingId,review_sha256:pending.reviewSha256,decision:'approve',idempotency_key:'key-1'});
 assert.equal(approve.disabled,true); assert.equal(deny.disabled,true);
 posts[0].d.resolve({pendingId:'9'.repeat(64),status:'approved'});
 await firstDecision; await flush(); await flush();
 assert.match(effectsNote(),/outcome unknown/i,'mismatched response cannot confirm a decision');
 assert.equal(buttons()[0].disabled,true); assert.equal(buttons()[1].disabled,true);
 assert.equal(posts.length,1,'unknown decision is never automatically replayed');
 effectRows=[{...pending,status:'approved'}]; await pollOnce();
 assert.match(effectsNote(),/Owner decision observed: approved/i);
 assert.match(effectsNote(),/does not confirm that the tool action completed/i);
 assert.equal(buttons().length,0,'only current observed status clears the pending decision');

 const pendingDeny={...pending,pendingId:'3'.repeat(64),reviewSha256:'4'.repeat(64),status:'pending'};
 effectRows=[pendingDeny]; await pollOnce();
 const denyRetry=buttons()[1].fire('click'); await flush();
 assert.equal(posts.length,2); posts[1].d.reject(Error('response lost')); await denyRetry;
 assert.match(effectsNote(),/outcome unknown/i);
 await pollOnce(); assert.equal(buttons()[0].disabled,true); assert.equal(buttons()[1].disabled,true);
 assert.equal(posts.length,2,'polling an unresolved review does not issue another decision');
 effectRows=[{...pendingDeny,status:'denied'}]; await pollOnce();
 assert.match(effectsNote(),/Owner decision observed: denied/i);

 const pendingAccepted={...pending,pendingId:'7'.repeat(64),reviewSha256:'8'.repeat(64),status:'pending'};
 effectRows=[pendingAccepted]; await pollOnce();
 const acceptedDecision=buttons()[0].fire('click'); await flush();
 assert.equal(posts.length,3);
 posts[2].d.resolve({pendingId:pendingAccepted.pendingId,status:'approved'}); await acceptedDecision;
 assert.match(effectsNote(),/current status still shows this review pending/i);
 assert.doesNotMatch(effectsNote(),/Owner decision observed/i,'POST response alone does not reconcile read status');
 assert.equal(buttons()[0].disabled,true); assert.equal(buttons()[1].disabled,true);
 effectRows=[{...pendingAccepted,status:'approved'}]; await pollOnce();
 assert.match(effectsNote(),/Owner decision observed: approved/i);

 const pendingUnmount={...pending,pendingId:'5'.repeat(64),reviewSha256:'6'.repeat(64),status:'pending'};
 effectRows=[pendingUnmount]; await pollOnce();
 const unmountedDecision=buttons()[0].fire('click'); await flush();
 assert.equal(posts.length,4);
 const beforeUnmount=effectsNote(); cleanup(); posts[3].d.reject(Error('late response')); await unmountedDecision;
 assert.equal(effectsNote(),beforeUnmount,'late decision failure cannot update an unmounted view');
 assert.equal(intervalCleared,true);
 assert.equal(posts.length,4,'unmount does not replay an unresolved decision');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('MOUNT', FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        script = Path(temporary) / "activity-decision-race.js"
        script.write_text("const assert=require('node:assert/strict');\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(script)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
