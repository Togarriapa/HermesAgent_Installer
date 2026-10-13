from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile

from hermes_installer.remote.jarvis_ecosystem_assets import FEATURE_ASSETS
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets


def test_ecosystem_feature_is_a_fixed_read_only_asset():
    validate_feature_assets((FEATURE_ASSETS,))
    assert FEATURE_ASSETS.feature_id == "ecosystem"
    assert FEATURE_ASSETS.api_routes == (("GET", "/chat/api/ecosystem"),)
    assert "data-ecosystem-roster" in FEATURE_ASSETS.view_html
    assert "data-ecosystem-graph" in FEATURE_ASSETS.view_html
    assert "data-ecosystem-detail" in FEATURE_ASSETS.view_html
    assert "data-ecosystem-search" in FEATURE_ASSETS.view_html
    assert "data-ecosystem-filter" in FEATURE_ASSETS.view_html
    assert "prefers-reduced-motion:reduce" in FEATURE_ASSETS.css
    assert "function cleanup()" in FEATURE_ASSETS.mount_js
    assert "setInterval" not in FEATURE_ASSETS.mount_js
    assert "api.post" not in FEATURE_ASSETS.mount_js


def test_ecosystem_dom_renders_only_verified_directed_edges_and_cleans_up():
    harness = r'''
class Target {
  constructor(tagName='div') { this.tagName=tagName; this.children=[]; this.listeners=new Map(); this.attributes={}; this.dataset={}; this.disabled=false; this.hidden=false; this.value=''; this._text=''; }
  set textContent(value) { this._text=String(value); this.children=[]; }
  get textContent() { return this._text || this.children.map(child=>child.textContent).join(''); }
  append(...nodes) { for(const node of nodes){node.parent=this;this.children.push(node);} }
  replaceChildren(...nodes) { this.children=[];this.append(...nodes); }
  setAttribute(key,value) { this.attributes[key]=String(value); }
  getAttribute(key) { return this.attributes[key] ?? null; }
  addEventListener(type,listener,options={}) {
    if(options.signal?.aborted)return;
    const entry={listener,once:options.once===true};const rows=this.listeners.get(type)||[];rows.push(entry);this.listeners.set(type,rows);
    if(options.signal)options.signal.addEventListener('abort',()=>this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry)),{once:true});
  }
  dispatch(type,event={}) { for(const entry of [...(this.listeners.get(type)||[])]){if(entry.once)this.listeners.set(type,(this.listeners.get(type)||[]).filter(row=>row!==entry));entry.listener(event);} }
  removeEventListener(type,listener) { this.listeners.set(type,(this.listeners.get(type)||[]).filter(entry=>entry.listener!==listener)); }
  querySelector(selector) {
    if(this.selectors?.has(selector))return this.selectors.get(selector);
    const wanted=selector.toLowerCase();
    const visit=node=>{for(const child of node.children){if(selector==='button'&&child.tagName==='button')return child;if(child.tagName===wanted)return child;const found=visit(child);if(found)return found;}return null;};
    return visit(this);
  }
  querySelectorAll(selector) { const found=[];const visit=node=>{for(const child of node.children){if(selector==='button'&&child.tagName==='button')found.push(child);visit(child);}};visit(this);return found; }
}
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return{promise,resolve,reject};}
function all(node){return[node,...node.children.flatMap(all)];}
function nodes(root,selector){return all(root).filter(node=>node.dataset.selector===selector);}
function makeRoot(){
 const root=new Target();root.dataset.featureRoot='ecosystem';root.selectors=new Map();
 const selectors=['[data-ecosystem-status]','[data-ecosystem-coverage]','[data-ecosystem-refresh]','[data-ecosystem-search]','[data-ecosystem-filter]','[data-ecosystem-roster]','[data-ecosystem-graph]','[data-ecosystem-teams]','[data-ecosystem-roster-empty]','[data-ecosystem-graph-empty]','[data-ecosystem-teams-empty]','[data-ecosystem-detail]','[data-ecosystem-events]'];
 for(const selector of selectors){const el=new Target(selector.includes('refresh')?'button':selector.includes('search')?'input':selector.includes('filter')?'select':'div');el.dataset.selector=selector;if(selector.includes('filter'))el.value='all';root.selectors.set(selector,el);root.append(el);}
 root.querySelector=selector=>selector==='[data-feature-root="ecosystem"]'?root:Target.prototype.querySelector.call(root,selector);
 return root;
}
const now=Date.now();
const data={schema:2,observation:{state:'observed',observed_at:new Date(now).toISOString(),partial:false},summary:{observed_instances:2,observed_completed_executions:2},pending:{team_membership:'verified',communication_edges:'verified'},
 instances:[
  {id:'e'.repeat(32),display_name:'Dev <img src=x>',profile_id:'developer',state:'completed',stale:false,source_revision:'source-5',mission_id:'m'.repeat(32),mission_revision:3,events:[{kind:'completed',status:'completed',at:new Date(now).toISOString()}]},
  {id:'r'.repeat(32),display_name:'Researcher',profile_id:'researcher',state:'completed',stale:false,source_revision:'source-5',mission_id:'m'.repeat(32),mission_revision:3,events:[]}
 ],
 teams:[{id:'t'.repeat(32),team_execution_key:'t'.repeat(32),name:'review-team',team_id:'review-team',mission_id:'m'.repeat(32),mission_revision:3,members:['e'.repeat(32),'r'.repeat(32)],state:'current',coverage:'observed-callbacks',partial:false}],
 relations:[{id:'q'.repeat(32),team_execution_key:'t'.repeat(32),mission_id:'m'.repeat(32),mission_revision:3,from:'e'.repeat(32),to:'r'.repeat(32),kind:'completed_message',state:'current',coverage:'observed-callbacks',at:new Date(now).toISOString()}]};
function api(){const gets=[];return{gets,get(path){const item={path,...deferred()};gets.push(item);return item.promise;}};}
global.document={visibilityState:'visible',createElement:tag=>new Target(tag),addEventListener(){}};
global.window={addEventListener(){},removeEventListener(){}};Object.defineProperty(global,'navigator',{value:{onLine:true},configurable:true});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
(async()=>{
 const root=makeRoot(),client=api(),cleanup=mount(root,client);
 assert.equal(client.gets.length,1);assert.equal(client.gets[0].path,'/chat/api/ecosystem');
 client.gets[0].resolve(data);await flush();
 assert.equal(root.dataset.state,'current');
 const roster=nodes(root,'[data-ecosystem-roster]')[0],graph=nodes(root,'[data-ecosystem-graph]')[0],teams=nodes(root,'[data-ecosystem-teams]')[0];
 assert.equal(roster.children.length,2);assert.equal(graph.children.length,1);assert.equal(teams.children.length,1);
 assert.match(graph.textContent,/Dev <img src=x>.*→.*Researcher/);assert.equal(all(root).some(node=>node.tagName==='img'),false,'untrusted labels are text, not markup');
 const arrow=all(graph).find(node=>node.className==='ecosystem-arrow');assert.equal(arrow.dataset.pulse,'true','a fresh included relation pulses once');
 roster.children[0].children[0].dispatch('click');assert.match(nodes(root,'[data-ecosystem-detail]')[0].textContent,/Dev <img src=x>.*developer.*source-5.*Mission/);
 nodes(root,'[data-ecosystem-search]')[0].value='researcher';nodes(root,'[data-ecosystem-search]')[0].dispatch('input');
 assert.equal(roster.children.length,1);assert.equal(graph.children.length,0,'graph omits edges whose endpoint is filtered out');
 nodes(root,'[data-ecosystem-search]')[0].value='';nodes(root,'[data-ecosystem-search]')[0].dispatch('input');

 // A repeated exact relation cannot pulse again; an error degrades the retained read to stale.
 nodes(root,'[data-ecosystem-refresh]')[0].dispatch('click');assert.equal(client.gets.length,2);
 client.gets[1].resolve(data);await flush();assert.equal(all(graph).find(node=>node.className==='ecosystem-arrow').dataset.pulse,undefined);
 nodes(root,'[data-ecosystem-refresh]')[0].dispatch('click');client.gets[2].reject(new Error('unavailable'));await flush();
 assert.equal(root.dataset.state,'stale');assert.match(nodes(root,'[data-ecosystem-status]')[0].textContent,/previous snapshot as stale/);
 assert.equal(client.gets.length,3,'the view has no ambient polling loop');

 // Schema 1 stays roster-only with an honest lineage limitation.
 nodes(root,'[data-ecosystem-refresh]')[0].dispatch('click');
 const schema1={schema:1,observation:{state:'observed',observed_at:new Date(Date.now()).toISOString(),partial:false},summary:{observed_instances:1,observed_completed_executions:1},instances:[data.instances[0]],teams:[],relations:[],pending:{}};
 client.gets[3].resolve(schema1);await flush();assert.equal(root.dataset.state,'current');assert.equal(graph.children.length,0);
 assert.match(nodes(root,'[data-ecosystem-coverage]')[0].textContent,/schema 1 has no verified Team lineage/);
 cleanup();assert.equal(nodes(root,'[data-ecosystem-refresh]')[0].disabled,true);

 // An in-flight response after unmount cannot repopulate the view.
 const lateRoot=makeRoot(),lateApi=api(),dispose=mount(lateRoot,lateApi);dispose();
 const statusBefore=nodes(lateRoot,'[data-ecosystem-status]')[0].textContent;
 lateApi.gets[0].resolve(data);await flush();assert.equal(nodes(lateRoot,'[data-ecosystem-status]')[0].textContent,statusBefore);
 console.log('ECOSYSTEM_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''.replace('MOUNT', FEATURE_ASSETS.mount_js)
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "ecosystem-assets-harness.js"
        path.write_text("const assert=require('node:assert/strict');\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "ECOSYSTEM_HARNESS_COMPLETE" in result.stdout, "deferred ecosystem scenarios did not complete"
