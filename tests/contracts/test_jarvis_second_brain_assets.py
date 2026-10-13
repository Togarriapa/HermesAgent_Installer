"""Static contract coverage for the owner-bound Obsidian dashboard leaf."""
from __future__ import annotations

import unittest
import subprocess
import tempfile
from pathlib import Path

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS as REGISTERED_ASSETS
from hermes_installer.remote.jarvis_obsidian_vault import FEATURE_ROUTES
from hermes_installer.remote.jarvis_second_brain_assets import FEATURE_ASSETS


class JarvisSecondBrainAssetTests(unittest.TestCase):
    def test_feature_declares_only_the_reviewed_owner_read_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertEqual(FEATURE_ASSETS.feature_id, "second-brain")
        self.assertIn(FEATURE_ASSETS, REGISTERED_ASSETS)
        self.assertEqual(FEATURE_ASSETS.api_routes, FEATURE_ROUTES)
        self.assertEqual(FEATURE_ASSETS.api_routes, (
            ("GET", "/chat/api/second-brain/overview"),
            ("GET", "/chat/api/second-brain/notes"),
            ("GET", "/chat/api/second-brain/search"),
            ("GET", "/chat/api/second-brain/notes/{note_id}"),
            ("GET", "/chat/api/second-brain/notes/{note_id}/links"),
            ("GET", "/chat/api/second-brain/graph"),
        ))

    def test_vault_content_is_text_only_and_graph_uses_real_link_dtos(self):
        self.assertIn("data-note-body", FEATURE_ASSETS.view_html)
        self.assertIn("data-graph-list", FEATURE_ASSETS.view_html)
        self.assertNotIn("innerHTML", FEATURE_ASSETS.mount_js)
        self.assertIn("body.textContent=note.markdown", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.fromNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.toNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("data.unresolved.length", FEATURE_ASSETS.mount_js)
        self.assertIn("summary.noteCount", FEATURE_ASSETS.mount_js)
        self.assertIn("summary.observedAt", FEATURE_ASSETS.mount_js)
        self.assertIn("link[targetField]", FEATURE_ASSETS.mount_js)
        self.assertIn("note.markdown", FEATURE_ASSETS.mount_js)
        self.assertIn("Connections represent indexed Obsidian links only", FEATURE_ASSETS.view_html)
        self.assertRegex(FEATURE_ASSETS.view_html, r"\bdo not imply communication or execution\b")

    def test_read_view_has_keyboard_touch_and_reduced_motion_paths(self):
        self.assertIn("data-search-form", FEATURE_ASSETS.view_html)
        self.assertIn("data-more", FEATURE_ASSETS.view_html)
        self.assertIn("min-height:44px", FEATURE_ASSETS.css)
        self.assertIn("focus-visible", FEATURE_ASSETS.css)
        self.assertIn("prefers-reduced-motion:reduce", FEATURE_ASSETS.css)
        self.assertIn("aria-live=\"polite\"", FEATURE_ASSETS.view_html)


    def test_knowledge_map_filters_by_saved_tags_and_draws_real_directional_links(self):
        self.assertIn("function tagCategory(node)", FEATURE_ASSETS.mount_js)
        self.assertIn("node.tags", FEATURE_ASSETS.mount_js)
        self.assertIn("selectedTags", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.fromNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.toNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("noteTags(node).some(tag=>selectedTags.has(tag))", FEATURE_ASSETS.mount_js)
        self.assertIn("tags.forEach(tag=>categories.add(tag))", FEATURE_ASSETS.mount_js)
        self.assertIn("ids.has(edge.fromNoteId)&&ids.has(edge.toNoteId)", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.kind==='markdown' ? 'markdown':'wikilink'", FEATURE_ASSETS.mount_js)
        self.assertIn("function graphTagArcs(group,node,point)", FEATURE_ASSETS.mount_js)
        self.assertIn("function setGraphSelection()", FEATURE_ASSETS.mount_js)
        self.assertIn("path.setAttribute('data-link-kind'", FEATURE_ASSETS.mount_js)
        self.assertIn("path.setAttribute('marker-end'", FEATURE_ASSETS.mount_js)
        self.assertIn("tagColor(tag)", FEATURE_ASSETS.mount_js)
        self.assertNotIn("animateMotion", FEATURE_ASSETS.mount_js)
        self.assertIn("data-zoom-in", FEATURE_ASSETS.view_html)
        self.assertIn("data-zoom-out", FEATURE_ASSETS.view_html)
        self.assertIn("data-graph-list", FEATURE_ASSETS.view_html)
        self.assertIn("Notes remain in your private vault when a chat or project is removed", FEATURE_ASSETS.view_html)
        self.assertIn("Node rings show saved vault tags", FEATURE_ASSETS.view_html)
        self.assertIn("Solid arrows are wikilinks; dashed arrows are Markdown links", FEATURE_ASSETS.view_html)
        self.assertIn("source records are available", FEATURE_ASSETS.view_html)
        self.assertIn("filters match any selected tag", FEATURE_ASSETS.view_html.lower())

    def test_knowledge_map_list_alternative_includes_isolated_notes(self):
        self.assertIn("data-graph-notes", FEATURE_ASSETS.view_html)
        self.assertIn("Notes in this map", FEATURE_ASSETS.view_html)
        self.assertIn("const graphNotes=$('[data-graph-notes]')", FEATURE_ASSETS.mount_js)
        self.assertIn("item.append(button);graphNotes.append(item)", FEATURE_ASSETS.mount_js)
        self.assertIn("graphNotes.querySelectorAll('button[data-note-id]')", FEATURE_ASSETS.mount_js)
        self.assertIn("button.addEventListener('click',()=>openNote(node.noteId))", FEATURE_ASSETS.mount_js)

    def test_focused_neighborhood_detail_and_recovery_use_current_vault_dtos(self):
        self.assertLessEqual(len(FEATURE_ASSETS.mount_js.encode("utf-8")), 30_000)
        self.assertIn('data-graph-detail', FEATURE_ASSETS.view_html)
        self.assertIn('data-graph-focus', FEATURE_ASSETS.view_html)
        self.assertIn('data-graph-reset', FEATURE_ASSETS.view_html)
        self.assertIn('data-graph-back', FEATURE_ASSETS.view_html)
        self.assertIn('function focusNeighborhood(noteId=currentNoteId)', FEATURE_ASSETS.mount_js)
        self.assertIn('function showFullGraph()', FEATURE_ASSETS.mount_js)
        self.assertIn('async function goBackNote()', FEATURE_ASSETS.mount_js)
        self.assertIn('new Set([graphFocusNoteId])', FEATURE_ASSETS.mount_js)
        self.assertIn('graphLayout(nodes,edges,graphFocusNoteId)', FEATURE_ASSETS.mount_js)
        self.assertIn("relationships.backlinks", FEATURE_ASSETS.mount_js)
        self.assertIn("relationships.unresolved", FEATURE_ASSETS.mount_js)
        self.assertIn('partial coverage', FEATURE_ASSETS.mount_js)
        self.assertIn('Author and review lineage are not included in this note projection.', FEATURE_ASSETS.mount_js)
        self.assertIn('function onGraphFocus()', FEATURE_ASSETS.mount_js)
        self.assertIn('function onGraphReset()', FEATURE_ASSETS.mount_js)
        self.assertIn('function onGraphBack()', FEATURE_ASSETS.mount_js)
        self.assertIn('graphBackButton.removeEventListener(\'click\',onGraphBack)', FEATURE_ASSETS.mount_js)

    def test_graph_navigation_and_note_readback_dom_harness(self):
        harness = r'''const assert = require('node:assert/strict');
class Element {
  constructor(tag='div') { this.tagName=tag; this.children=[]; this.dataset={}; this.attributes={}; this.listeners={}; this.style={setProperty(){}}; this.textContent=''; this.disabled=false; this.hidden=false; this.scrolls=0; this.focuses=0; }
  get childElementCount() { return this.children.length; }
  append(...items) { for (const item of items) { if (item && typeof item === 'object') this.children.push(item); } }
  replaceChildren(...items) { this.children=[]; this.append(...items); }
  setAttribute(k,v) { this.attributes[k]=String(v); if (k==='data-note-id') this.dataset.noteId=String(v); }
  getAttribute(k) { return this.attributes[k] ?? null; }
  addEventListener(k,fn) { (this.listeners[k] ||= []).push(fn); }
  removeEventListener(k,fn) { this.listeners[k]=(this.listeners[k]||[]).filter(x=>x!==fn); }
  dispatch(k,event={}) { for (const fn of this.listeners[k]||[]) fn(event); }
  querySelectorAll(selector) { const result=[]; const visit=node=>{ for (const child of node.children) { if (selector==='.brain-node' && child.attributes.class==='brain-node') result.push(child); if (selector==='button[data-note-id]' && child.tagName==='button' && child.dataset.noteId) result.push(child); if (selector==='button' && child.tagName==='button') result.push(child); if (selector==='.brain-edge' && child.attributes.class==='brain-edge') result.push(child); visit(child); } }; visit(this); return result; }
  appendChild(node) { this.append(node); return node; }
  scrollIntoView() { this.scrolls++; }
  focus() { this.focuses++; }
  getBoundingClientRect() { return {width:1000,height:620}; }
  setPointerCapture() {} hasPointerCapture() { return false; } releasePointerCapture() {}
}
const selectors = ['[data-status]','[data-note-list]','[data-note-body]','[data-query]','[data-search-button]','[data-refresh]','[data-more]','[data-graph-refresh]','[data-graph]','[data-graph-scene]','[data-graph-legend]','[data-graph-list]','[data-graph-notes]','[data-graph-notes-title]','[data-graph-detail-content]','[data-graph-read]','[data-graph-focus]','[data-graph-reset]','[data-graph-back]','[data-zoom-in]','[data-zoom-out]','[data-zoom-reset]','[data-list-empty]','[data-results-title]','[data-count-notes]','[data-count-links]','[data-count-unresolved]','[data-count-drafts]','[data-vault-state]','[data-vault-observed]','[data-coverage]','[data-reader-title]','[data-reader-meta]','[data-note-links]','[data-note-backlinks]','[data-note-unresolved]','[data-graph-status]','[data-search-form]','.brain-reader'];
const root=new Element(), els=new Map(selectors.map(s=>[s,new Element()])); root.querySelector=s=>els.get(s) || null;
global.document={createElement:t=>new Element(t),createElementNS:(ns,t)=>new Element(t)};
MOUNT
const nodes=[{noteId:'A',title:'Incoming',tags:['Research']},{noteId:'B',title:'Center',tags:['Research','Pinned']},{noteId:'C',title:'Outgoing',tags:['Ops']},{noteId:'D',title:'Unrelated',tags:['Ops']},{noteId:'E',title:'Isolated note',tags:['Archive']}];
const graph={nodes,edges:[{fromNoteId:'A',toNoteId:'B',kind:'wikilink'},{fromNoteId:'B',toNoteId:'C',kind:'markdown'},{fromNoteId:'C',toNoteId:'D',kind:'wikilink'}],unresolved:[{fromNoteId:'B',label:'Missing page'}],partial:true,scanned:7};
const note=(id)=>({noteId:id,title:id,markdown:'<script>inert</script> **plain**',updatedAt:'2026-10-13T00:00:00Z',contentSha256:'abc'});
const requests=[]; let foreign=false, fail=false, deferred=[];
const api={get:async path=>{requests.push(path); if(path.endsWith('/overview')) return {coverage:{scanned:7,limit:20,partial:true},noteCount:4,linkCount:3,unresolvedLinkCount:1,draftCount:0,state:'ready',observedAt:'2026-10-13T00:00:00Z'}; if(path.includes('/graph')) return graph; if(path.includes('/notes?')) return {notes,nextCursor:null}; if(path.includes('/notes/Pending')) return new Promise(resolve=>deferred.push(()=>resolve(path.endsWith('/links')?{noteId:'Pending',links:[],backlinks:[],unresolved:[]}:note('Pending')))); if(path.endsWith('/links')) {const id=decodeURIComponent(path.split('/').at(-2)); return {noteId:id,links:[],backlinks:[{fromNoteId:'A',label:'Incoming'}],unresolved:[{label:'Missing page'}]};} if(path.includes('/notes/')) {if(fail) throw Error('offline'); const id=decodeURIComponent(path.split('/').at(-1)); return foreign?{...note(id),noteId:'foreign'}:note(id);} throw Error('unexpected GET '+path);}};
const mounted=mount(root,api,{});
const flush=()=>new Promise(resolve=>setImmediate(resolve));
const ids=()=>els.get('[data-graph-scene]').querySelectorAll('.brain-node').map(n=>n.dataset.noteId).sort();
(async()=>{
 await flush();
 assert.deepEqual(ids(),['A','B','C','D','E']);
 const isolated=els.get('[data-graph-notes]').querySelectorAll('button[data-note-id]').find(b=>b.dataset.noteId==='E');
 assert(isolated,'isolated vault note is included in the accessible list alternative');
 assert.equal(graph.edges.some(e=>e.fromNoteId==='E'||e.toNoteId==='E'),false,'fixture note has no graph edges');
 isolated.dispatch('click'); await flush(); assert(requests.some(p=>p.endsWith('/notes/E')),'isolated note opens through the real note read route');
 assert(requests.some(p=>p.endsWith('/notes/E/links')),'isolated note reads its current resolved links');
 assert.equal(els.get('[data-reader-title]').textContent,'E','reader identity follows the selected isolated note');
 assert.equal(els.get('[data-note-body]').textContent,'<script>inert</script> **plain**','isolated Markdown remains inert text');
 assert.equal(els.get('[data-note-backlinks]').querySelectorAll('button').length,1,'current isolated-note backlink DTO is rendered');
 const layout=__secondBrainHarness.graphLayout(nodes.slice(0,3),graph.edges.slice(0,2),'B');
 assert.deepEqual(layout.get('B'),{x:500,y:310});
 __secondBrainHarness.focusNeighborhood('B');
 assert.deepEqual(ids(),['A','B','C']);
 assert.equal(els.get('[data-graph-scene]').querySelectorAll('.brain-edge').length,2,'focused map keeps actual incoming and outgoing edges');
 assert.match(els.get('[data-graph-status]').textContent,/partial coverage/);
 assert.match(els.get('[data-graph-status]').textContent,/7 notes scanned/);
 els.get('[data-graph-reset]').dispatch('click'); assert.deepEqual(ids(),['A','B','C','D','E']);
 const center=els.get('[data-graph-notes]').querySelectorAll('button[data-note-id]').find(b=>b.dataset.noteId==='B'); center.dispatch('click'); await flush();
 assert(requests.some(p=>p.endsWith('/notes/B'))); assert(requests.some(p=>p.endsWith('/notes/B/links')));
 assert.equal(els.get('[data-note-body]').textContent,'<script>inert</script> **plain**','Markdown remains text, not executable HTML');
 assert.equal(els.get('[data-graph-read]').disabled,false); els.get('[data-graph-read]').dispatch('click');
 assert(els.get('[data-note-body]').focuses>0); assert(els.get('.brain-reader').scrolls>0,'detail read action reaches the existing note reader');
 const backlink=els.get('[data-graph-detail-content]').querySelectorAll('button').find(b=>b.textContent==='Incoming'); backlink.dispatch('click'); await flush();
 assert.equal(els.get('[data-reader-title]').textContent,'A');
 els.get('[data-graph-back]').dispatch('click'); await flush(); assert.equal(els.get('[data-reader-title]').textContent,'B');
 fail=true; await __secondBrainHarness.openNote('C'); assert.equal(els.get('[data-reader-title]').textContent,'Note unavailable');
 fail=false; foreign=true; await __secondBrainHarness.openNote('D'); assert.equal(els.get('[data-reader-title]').textContent,'Note unavailable','foreign note identity is rejected');
 foreign=false; __secondBrainHarness.renderGraph(graph); const research=els.get('[data-graph-legend]').children.find(b=>b.children.some(x=>x.textContent==='Research')); research.dispatch('click');
 assert(ids().length<4,'saved-tag filters apply to actual indexed notes');
 const pending=__secondBrainHarness.openNote('Pending'); await flush(); assert.equal(deferred.length,2,'note and links reads are independently pending');
 const before=els.get('[data-note-body]').textContent; mounted(); for(const release of deferred) release(); await pending;
 assert.equal(els.get('[data-note-body]').textContent,before,'late response after unmount cannot restore or replace the reader');
 console.log('SECOND_BRAIN_DOM_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
        cleanup_marker = "return function cleanup(){"
        self.assertEqual(FEATURE_ASSETS.mount_js.count(cleanup_marker), 1)
        harness = harness.replace(
            "MOUNT",
            FEATURE_ASSETS.mount_js.replace(
                cleanup_marker,
                "globalThis.__secondBrainHarness={graphLayout,focusNeighborhood,renderGraph,openNote};\n  "
                + cleanup_marker,
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "second-brain-dom-harness.js"
            script.write_text(harness, encoding="utf-8")
            result = subprocess.run(["node", str(script)], capture_output=True, text=True, check=False, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SECOND_BRAIN_DOM_HARNESS_COMPLETE", result.stdout)


if __name__ == "__main__":
    unittest.main()
