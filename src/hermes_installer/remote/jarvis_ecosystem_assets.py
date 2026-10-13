"""Static owner-facing Expert and Team ecosystem view."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class=\"ecosystem-page\" data-feature-root=\"ecosystem\" data-state=\"unknown\" aria-labelledby=\"ecosystem-title\">
  <header class=\"ecosystem-header\"><div><p class=\"ecosystem-kicker\">NATIVE EXECUTION OBSERVATIONS</p><h1 id=\"ecosystem-title\">Expert ecosystem</h1>
    <p>Inspect named execution instances, verified Team membership, and observed completed communication.</p></div>
    <button type=\"button\" data-ecosystem-refresh>Refresh observations</button></header>
  <p data-ecosystem-status role=\"status\" aria-live=\"polite\">Current native observations are unknown.</p>
  <div class=\"ecosystem-controls\"><label>Find an instance, Team, or mission<input type=\"search\" data-ecosystem-search autocomplete=\"off\"></label>
    <label>Show<select data-ecosystem-filter><option value=\"all\">All observations</option><option value=\"current\">Current</option><option value=\"historical\">Historical</option><option value=\"stale\">Stale</option><option value=\"partial\">Partial</option><option value=\"unknown\">Unknown</option></select></label></div>
  <p class=\"ecosystem-coverage\" data-ecosystem-coverage>Coverage is unknown.</p>
  <div class=\"ecosystem-layout\">
    <section class=\"ecosystem-panel\" aria-labelledby=\"ecosystem-roster-title\"><h2 id=\"ecosystem-roster-title\">Instance roster</h2>
      <ol data-ecosystem-roster class=\"ecosystem-roster\"></ol><p data-ecosystem-roster-empty class=\"ecosystem-empty\">No current roster is available.</p></section>
    <section class=\"ecosystem-panel ecosystem-network-panel\" aria-labelledby=\"ecosystem-network-title\"><h2 id=\"ecosystem-network-title\">Observed communication</h2>
      <div class=\"ecosystem-scene-frame\" data-ecosystem-scene-frame><svg data-ecosystem-scene tabindex=\"-1\" viewBox=\"0 0 720 360\" role=\"img\" aria-label=\"Directed network of observed execution instances\"><defs><marker id=\"ecosystem-arrowhead\" markerWidth=\"8\" markerHeight=\"8\" refX=\"7\" refY=\"4\" orient=\"auto\"><path d=\"M0,0 L8,4 L0,8 z\" fill=\"#83d9de\"></path></marker></defs><g data-ecosystem-scene-links></g><g data-ecosystem-scene-nodes></g></svg></div>
      <div class=\"ecosystem-scene-actions\"><button type=\"button\" data-ecosystem-fit>Fit network</button><span data-ecosystem-selected tabindex=\"-1\" aria-live=\"polite\">No instance selected.</span></div>
      <ol data-ecosystem-graph class=\"ecosystem-graph\" aria-label=\"Directed, root-observed completed messages\"></ol>
      <p data-ecosystem-graph-empty class=\"ecosystem-empty\">No verified completed-message relations are available.</p>
      <p class=\"ecosystem-legend\"><span aria-hidden=\"true\">●</span> Instance &nbsp; <span aria-hidden=\"true\">→</span> Verified sender to recipient &nbsp; <span data-ecosystem-motion>Motion only marks a new, fresh observed relation.</span></p>
      <h3>Verified Team membership</h3><ol data-ecosystem-teams class=\"ecosystem-teams\"></ol><p data-ecosystem-teams-empty class=\"ecosystem-empty\">No independently verified Team membership is available.</p></section>
  </div>
  <section class=\"ecosystem-panel ecosystem-detail\" aria-labelledby=\"ecosystem-detail-title\" aria-live=\"polite\"><h2 id=\"ecosystem-detail-title\">Instance detail</h2><p data-ecosystem-detail>Select an instance to inspect its observed source and events.</p><ol data-ecosystem-events></ol></section>
  <p class=\"ecosystem-footnote\">Catalog declarations do not prove an active instance or communication. This read-only view cannot launch work or grant authority.</p>
</section>"""

_CSS = """[data-feature-root=\"ecosystem\"]{max-width:1180px;margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#edf5f6)}
[data-feature-root=\"ecosystem\"] .ecosystem-header{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem}
[data-feature-root=\"ecosystem\"] h1{margin:.3rem 0;font-size:clamp(1.7rem,4vw,2.5rem)}
[data-feature-root=\"ecosystem\"] h2{margin:.2rem 0 .9rem;font-size:1.08rem}
[data-feature-root=\"ecosystem\"] h3{margin:1.2rem 0 .5rem;font-size:.9rem}
[data-feature-root=\"ecosystem\"] p{line-height:1.5}
[data-feature-root=\"ecosystem\"] .ecosystem-kicker{margin:0;color:var(--accent,#83d9ca);font-size:.7rem;letter-spacing:.14em}
[data-feature-root=\"ecosystem\"] .ecosystem-header>div>p:last-child,[data-feature-root=\"ecosystem\"] .ecosystem-status,[data-feature-root=\"ecosystem\"] .ecosystem-coverage,[data-feature-root=\"ecosystem\"] .ecosystem-legend,[data-feature-root=\"ecosystem\"] .ecosystem-footnote{color:var(--muted,#9bafb4)}
[data-feature-root=\"ecosystem\"] button,[data-feature-root=\"ecosystem\"] input,[data-feature-root=\"ecosystem\"] select{min-height:44px;padding:.55rem .75rem;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;font:inherit}
[data-feature-root=\"ecosystem\"] button{cursor:pointer}
[data-feature-root=\"ecosystem\"] button:focus-visible,[data-feature-root=\"ecosystem\"] input:focus-visible,[data-feature-root=\"ecosystem\"] select:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root=\"ecosystem\"] .ecosystem-controls{display:flex;flex-wrap:wrap;gap:.8rem;margin:1rem 0}
[data-feature-root=\"ecosystem\"] .ecosystem-controls label{display:grid;gap:.35rem;min-width:min(100%,220px);font-size:.8rem;color:var(--muted,#9bafb4)}
[data-feature-root=\"ecosystem\"] .ecosystem-controls input{min-width:min(70vw,340px)}
[data-feature-root=\"ecosystem\"] .ecosystem-layout{display:grid;grid-template-columns:minmax(240px,.8fr) minmax(0,1.2fr);gap:1rem;align-items:start}
[data-feature-root=\"ecosystem\"] .ecosystem-panel{min-width:0;padding:clamp(.9rem,2vw,1.2rem);border:1px solid var(--border,#294047);border-radius:15px;background:var(--panel,#0d1d23)}
[data-feature-root=\"ecosystem\"] .ecosystem-roster,[data-feature-root=\"ecosystem\"] .ecosystem-graph,[data-feature-root=\"ecosystem\"] .ecosystem-teams,[data-feature-root=\"ecosystem\"] [data-ecosystem-events]{list-style:none;margin:0;padding:0}
[data-feature-root=\"ecosystem\"] .ecosystem-roster li,[data-feature-root=\"ecosystem\"] .ecosystem-teams li{margin:.45rem 0}
[data-feature-root=\"ecosystem\"] .ecosystem-instance{width:100%;display:flex;justify-content:space-between;gap:.7rem;text-align:left;align-items:center}
[data-feature-root=\"ecosystem\"] .ecosystem-instance[aria-pressed=\"true\"]{border-color:var(--accent,#83d9ca);background:rgba(38,181,193,.15)}
[data-feature-root=\"ecosystem\"] .ecosystem-instance small{color:var(--muted,#9bafb4);text-align:right}
[data-feature-root=\"ecosystem\"] .ecosystem-graph li{display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);align-items:center;gap:.6rem;padding:.65rem 0;border-top:1px solid var(--border,#20373e)}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-frame{overflow:auto;max-height:480px;margin:.4rem 0;border:1px solid var(--border,#20373e);border-radius:12px;background:radial-gradient(ellipse at 50% 45%,rgba(35,93,101,.18),transparent 70%)}
[data-feature-root=\"ecosystem\"] [data-ecosystem-scene]{display:block;width:100%;height:auto;min-height:180px}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-link{fill:none;stroke:#83d9de;stroke-width:2;marker-end:url(#ecosystem-arrowhead)}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-node{cursor:pointer;outline:none}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-node circle{fill:#10343a;stroke:#83d9de;stroke-width:2}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-node[aria-pressed=\"true\"] circle,[data-feature-root=\"ecosystem\"] .ecosystem-scene-node:focus-visible circle{stroke:#fff;stroke-width:4}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-node text{fill:#edf5f6;font:12px system-ui,sans-serif;text-anchor:middle;pointer-events:none}
[data-feature-root=\"ecosystem\"] .ecosystem-scene-actions{display:flex;align-items:center;gap:.7rem;margin:.5rem 0;color:var(--muted,#9bafb4);font-size:.8rem}
[data-feature-root=\"ecosystem\"] .ecosystem-relation-endpoints{grid-column:1/-1;display:grid;grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);align-items:center;gap:.6rem}
[data-feature-root=\"ecosystem\"] .ecosystem-graph li>small{grid-column:1/-1}
[data-feature-root=\"ecosystem\"] .ecosystem-endpoint{min-width:0;overflow-wrap:anywhere}
[data-feature-root=\"ecosystem\"] .ecosystem-arrow{font-size:1.2rem;color:#83d9de}
[data-feature-root=\"ecosystem\"] .ecosystem-arrow[data-pulse=\"true\"]{animation:ecosystem-relation-pulse 1.1s ease-out 1}
@keyframes ecosystem-relation-pulse{0%{opacity:.25;transform:scale(.8)}45%{opacity:1;transform:scale(1.25)}100%{opacity:1;transform:scale(1)}}
[data-feature-root=\"ecosystem\"] .ecosystem-graph small,[data-feature-root=\"ecosystem\"] .ecosystem-teams small{display:block;color:var(--muted,#9bafb4);font-size:.74rem}
[data-feature-root=\"ecosystem\"] .ecosystem-detail{margin-top:1rem}
[data-feature-root=\"ecosystem\"] [data-ecosystem-events] li{padding:.55rem 0;border-top:1px solid var(--border,#20373e);overflow-wrap:anywhere}
[data-feature-root=\"ecosystem\"] .ecosystem-empty{color:var(--muted,#9bafb4)}
[data-feature-root=\"ecosystem\"][data-state=\"partial\"] .ecosystem-status,[data-feature-root=\"ecosystem\"][data-state=\"stale\"] .ecosystem-status{color:#e9c783}
[data-feature-root=\"ecosystem\"][data-state=\"unknown\"] .ecosystem-arrow[data-pulse=\"true\"],[data-feature-root=\"ecosystem\"][data-state=\"stale\"] .ecosystem-arrow[data-pulse=\"true\"]{animation:none}
@media(prefers-reduced-motion:reduce){[data-feature-root=\"ecosystem\"] *,[data-feature-root=\"ecosystem\"] *::before,[data-feature-root=\"ecosystem\"] *::after{animation:none!important;scroll-behavior:auto!important}}
html[data-jarvis-motion=\"reduce\"] [data-feature-root=\"ecosystem\"] *,html[data-jarvis-motion=\"reduce\"] [data-feature-root=\"ecosystem\"] *::before,html[data-jarvis-motion=\"reduce\"] [data-feature-root=\"ecosystem\"] *::after{animation:none!important}
@media(max-width:700px){[data-feature-root=\"ecosystem\"] .ecosystem-header{flex-direction:column}[data-feature-root=\"ecosystem\"] .ecosystem-header button{width:100%}[data-feature-root=\"ecosystem\"] .ecosystem-layout{grid-template-columns:minmax(0,1fr)}}
@media(max-width:420px){[data-feature-root=\"ecosystem\"] .ecosystem-graph li{grid-template-columns:minmax(0,1fr) auto minmax(0,1fr);gap:.35rem;font-size:.84rem}[data-feature-root=\"ecosystem\"] .ecosystem-instance{align-items:flex-start;flex-direction:column}}
"""

_MOUNT = r'''function mount(container, api) {
  const root = container.querySelector('[data-feature-root="ecosystem"]') || container;
  const $ = selector => root.querySelector(selector);
  const status = $('[data-ecosystem-status]'), coverage = $('[data-ecosystem-coverage]');
  const refreshButton = $('[data-ecosystem-refresh]'), searchInput = $('[data-ecosystem-search]');
  const filterSelect = $('[data-ecosystem-filter]'), roster = $('[data-ecosystem-roster]');
  const graph = $('[data-ecosystem-graph]'), teamsList = $('[data-ecosystem-teams]');
  const scene = $('[data-ecosystem-scene]'), sceneLinks = $('[data-ecosystem-scene-links]'), sceneNodes = $('[data-ecosystem-scene-nodes]');
  const fitButton = $('[data-ecosystem-fit]'), selectedLabel = $('[data-ecosystem-selected]'), sceneFrame = $('[data-ecosystem-scene-frame]');
  const rosterEmpty = $('[data-ecosystem-roster-empty]'), graphEmpty = $('[data-ecosystem-graph-empty]');
  const teamsEmpty = $('[data-ecosystem-teams-empty]'), detail = $('[data-ecosystem-detail]');
  const eventList = $('[data-ecosystem-events]');
  let stopped = false, loading = false, generation = 0, snapshot = null, selectedId = null, sceneVisible = true, freshnessTimer = null;
  const seenPulses = new Set();
  const listeners = new AbortController();
  const instanceStates = new Set(['admitted','running','responded','completed','unknown']);
  const lineageStates = new Set(['current','historical','stale','partial']);
  const opaque = value => typeof value === 'string' && value.length >= 24 && value.length <= 64;
  const label = value => typeof value === 'string' ? value.slice(0,160) : '';
  const textNode = (tag,value,className) => { const node=document.createElement(tag); if(className)node.className=className; node.textContent=String(value ?? 'Unknown'); return node; };
  function normalize(data) {
    if (!data || ![1,2].includes(data.schema) || !data.observation
        || !['quiet','observed','partial'].includes(data.observation.state)
        || typeof data.observation.observed_at !== 'string'
        || !Array.isArray(data.instances) || data.instances.length > 100
        || data.schema === 2 && (!Array.isArray(data.teams) || data.teams.length > 100
          || !Array.isArray(data.relations) || data.relations.length > 200)) return null;
    const instanceMap = new Map(), instances=[];
    for (const item of data.instances) {
      if (!item || !opaque(item.id) || instanceMap.has(item.id) || typeof item.display_name !== 'string'
          || typeof item.profile_id !== 'string' || !instanceStates.has(item.state)
          || typeof item.stale !== 'boolean' || !Array.isArray(item.events) || item.events.length > 200) return null;
      const row={...item,display_name:label(item.display_name),profile_id:label(item.profile_id),events:item.events.slice(0,200)};
      instanceMap.set(item.id,row); instances.push(row);
    }
    let teams=[], relations=[], omittedTeams=0, omittedRelations=0;
    if (data.schema === 2) {
      const teamMap = new Map(), claimedMembers = new Set(), seenTeamIds = new Set();
      if (data.pending?.team_membership === 'verified') for (const item of data.teams) {
        if (!item || !opaque(item.id) || item.team_execution_key !== item.id || seenTeamIds.has(item.id)
            || !opaque(item.mission_id) || !Number.isSafeInteger(item.mission_revision) || item.mission_revision < 1
            || typeof item.team_id !== 'string' || !Array.isArray(item.members) || !item.members.length || item.members.length > 32
            || !lineageStates.has(item.state) || !['observed-callbacks','partial'].includes(item.coverage)) continue;
        seenTeamIds.add(item.id);
        const members=item.members.map(id=>instanceMap.get(id));
        if (members.some(row=>!row || row.mission_id!==item.mission_id || row.mission_revision!==item.mission_revision)
            || new Set(item.members).size!==item.members.length || item.members.some(id=>claimedMembers.has(id))) { omittedTeams++; continue; }
        item.members.forEach(id=>claimedMembers.add(id)); teamMap.set(item.id,item);
        teams.push({...item,name:label(item.name || item.team_id)});
      }
      if (data.pending?.team_membership === 'verified') omittedTeams += data.teams.length - teams.length - omittedTeams;
      const seenRelationIds = new Set();
      if (data.pending?.communication_edges === 'verified') for (const item of data.relations) {
        if (!item || !opaque(item.id) || !opaque(item.team_execution_key) || !teamMap.has(item.team_execution_key)
            || seenRelationIds.has(item.id)
            || !opaque(item.mission_id) || !Number.isSafeInteger(item.mission_revision)
            || item.kind!=='completed_message' || !lineageStates.has(item.state)
            || !['observed-callbacks','partial'].includes(item.coverage) || !opaque(item.from) || !opaque(item.to) || item.from===item.to) continue;
        const team=teamMap.get(item.team_execution_key), from=instanceMap.get(item.from), to=instanceMap.get(item.to);
        const at=Date.parse(item.at);
        if (!team.members.includes(item.from) || !team.members.includes(item.to)
            || team.mission_id!==item.mission_id || team.mission_revision!==item.mission_revision
            || !from || !to
            || from.mission_id!==item.mission_id || to.mission_id!==item.mission_id
            || from.mission_revision!==item.mission_revision || to.mission_revision!==item.mission_revision
            || !Number.isFinite(at)) { omittedRelations++; continue; }
        seenRelationIds.add(item.id);
        relations.push({...item,team_name:team.name,from_name:from.display_name,to_name:to.display_name,at_ms:at,
          team_current:team.state==='current' && team.coverage==='observed-callbacks',
          from_current:!from.stale && from.state!=='unknown',to_current:!to.stale && to.state!=='unknown'});
      }
      if (data.pending?.communication_edges === 'verified') omittedRelations += data.relations.length - relations.length - omittedRelations;
    }
    const observedAt=Date.parse(data.observation.observed_at);
    return {schema:data.schema,observation:data.observation,summary:data.summary || {},instances,teams,relations,
      pending:data.pending || {},observedAt,instanceMap,omittedTeams,omittedRelations,
      partial:data.observation.state==='partial' || data.observation.partial===true
        || instances.some(row=>row.stale) || teams.some(row=>row.partial) || relations.some(row=>row.partial)
        || omittedTeams>0 || omittedRelations>0};
  }
  function liveNow(row) {
    return !!snapshot && !loading && !stopped && (root.dataset.state==='current'||root.dataset.state==='partial') && document.visibilityState==='visible'
      && navigator.onLine!==false && sceneVisible && snapshot.observation.state!=='quiet' && row.partial!==true
      && row.team_current===true && row.from_current===true && row.to_current===true
      && Number.isFinite(snapshot.observedAt) && Date.now()-snapshot.observedAt>=-30000
      && Date.now()-snapshot.observedAt<=120000 && row.state==='current'
      && row.coverage==='observed-callbacks' && Date.now()-row.at_ms>=-30000 && Date.now()-row.at_ms<=120000;
  }
  function setStatus(message,state) { root.dataset.state=state; status.textContent=message; }
  function visibleRows() {
    const query=searchInput.value.trim().toLocaleLowerCase(), filter=filterSelect.value;
    return snapshot.instances.filter(row=>{
      const rowState=root.dataset.state==='stale' || row.stale ? 'stale'
        : row.state==='unknown' ? 'unknown' : root.dataset.state==='partial' ? 'partial' : 'current';
      return (!filter || filter==='all' || rowState===filter)
        && (!query || `${row.display_name} ${row.profile_id} ${row.mission_id || ''}`.toLocaleLowerCase().includes(query));
    });
  }
  function effectiveLineageState(row) {
    if (root.dataset.state==='stale') return 'stale';
    if (root.dataset.state==='partial' || row.partial) return 'partial';
    return row.state;
  }
  function renderDetail(row) {
    eventList.replaceChildren();
    if (!row) { detail.textContent='Select an instance to inspect its observed source and events.'; return; }
    detail.textContent=`${row.display_name} · ${row.profile_id} · Execution ${row.id} · Reported ${row.state}${row.stale || root.dataset.state==='stale'?' · stale snapshot; current state unknown':''}`
      + ` · Source revision ${row.source_revision || 'Unknown'} · Mission ${row.mission_id || 'Unknown'}`
      + (row.mission_revision ? ` revision ${row.mission_revision}` : '')
      + ` · Snapshot observed ${snapshot.observation.observed_at}`;
    const events=row.events.filter(event=>event && typeof event.kind==='string' && typeof event.status==='string' && typeof event.at==='string').slice(-20);
    detail.append(textNode('p',`${Number.isSafeInteger(row.observed_response_duration_ms)?`${row.observed_response_duration_ms} ms observed response duration`:'Observed response duration unknown'} · ${Number.isSafeInteger(row.response_duration_coverage)?`${row.response_duration_coverage} observed responses with duration`:'response duration coverage unknown'}`));
    for (const event of events) {
      const line=document.createElement('li');
      const when=Number.isFinite(Date.parse(event.at)) ? event.at : 'Unknown time';
      line.textContent=`${event.kind} · ${event.status} · ${when}`
        + (Number.isSafeInteger(event.duration_ms) ? ` · ${event.duration_ms} ms` : event.duration_ms===null?' · duration unavailable':' · duration unknown');
      eventList.append(line);
    }
    if (!events.length) eventList.append(textNode('li','No event detail is available in this observation.'));
  }
  function render() {
    if (!snapshot) return;
    const visible=visibleRows(), visibleIds=new Set(visible.map(row=>row.id));
    if (!selectedId || !visibleIds.has(selectedId)) selectedId=visible.length ? visible[0].id : null;
    selectedLabel.textContent=selectedId?`Selected ${snapshot.instanceMap.get(selectedId).display_name} · execution ${selectedId}`:'No instance selected.';
    roster.replaceChildren(); graph.replaceChildren(); teamsList.replaceChildren(); sceneLinks.replaceChildren(); sceneNodes.replaceChildren();
    rosterEmpty.hidden=visible.length>0;
    for (const row of visible) {
      const li=document.createElement('li'), button=document.createElement('button');
      button.type='button'; button.className='ecosystem-instance'; button.dataset.instanceId=row.id;
      button.setAttribute('aria-pressed',String(selectedId===row.id));
      const effective=root.dataset.state==='stale' || row.stale?' · stale snapshot; current state unknown'
        : root.dataset.state==='partial'?' · partial snapshot':'';
      const tools=Number.isSafeInteger(row.observed_tool_calls)?`${row.observed_tool_calls} observed tool calls`:'tool count unknown';
      const completed=Number.isSafeInteger(row.completed_executions)?`${row.completed_executions} observed completions`:'completion count unknown';
      button.append(textNode('span',row.display_name),textNode('small',`${row.profile_id} · reported ${row.state}${effective} · ${tools} · ${completed}`));
      button.addEventListener('click',()=>{selectedId=row.id;render();renderDetail(snapshot.instanceMap.get(row.id));});
      li.append(button); roster.append(li);
    }
    const relations=snapshot.relations.filter(row=>visibleIds.has(row.from)&&visibleIds.has(row.to)
      && (!filterSelect.value || filterSelect.value==='all' || effectiveLineageState(row)===filterSelect.value));
    graphEmpty.hidden=relations.length>0;
    const ordered=[...relations].sort((a,b)=>a.at_ms-b.at_ms || a.id.localeCompare(b.id));
    const sceneRows=[...visible].sort((a,b)=>a.id.localeCompare(b.id));
    const points=new Map(sceneRows.map((row,index)=>[row.id,{x:90+(index%4)*180,y:75+Math.floor(index/4)*125}]));
    for (const relation of ordered) {
      const from=points.get(relation.from),to=points.get(relation.to); if(!from||!to)continue;
      const path=document.createElementNS('http://www.w3.org/2000/svg','path');
      path.setAttribute('d',`M ${from.x} ${from.y} L ${to.x} ${to.y}`);path.setAttribute('class','ecosystem-scene-link');
      path.setAttribute('aria-label',`${relation.from_name} to ${relation.to_name}: verified completed message`);sceneLinks.append(path);
    }
    for (const row of sceneRows) {
      const point=points.get(row.id),group=document.createElementNS('http://www.w3.org/2000/svg','g');
      group.setAttribute('class','ecosystem-scene-node');group.setAttribute('tabindex','0');group.setAttribute('role','button');
      group.setAttribute('aria-label',`${row.display_name}, execution ${row.id}, profile ${row.profile_id}`);
      group.setAttribute('aria-pressed',String(selectedId===row.id));group.dataset.instanceId=row.id;
      const title=document.createElementNS('http://www.w3.org/2000/svg','title');title.textContent=`${row.display_name} · execution ${row.id}`;
      const circle=document.createElementNS('http://www.w3.org/2000/svg','circle');circle.setAttribute('cx',String(point.x));circle.setAttribute('cy',String(point.y));circle.setAttribute('r','25');
      const name=document.createElementNS('http://www.w3.org/2000/svg','text');name.setAttribute('x',String(point.x));name.setAttribute('y',String(point.y+43));name.textContent=row.display_name.slice(0,28);
      const key=document.createElementNS('http://www.w3.org/2000/svg','text');key.setAttribute('x',String(point.x));key.setAttribute('y',String(point.y+58));key.textContent=`Execution …${row.id.slice(-8)}`;
      group.append(title,circle,name,key);
      const select=()=>{selectedId=row.id;render();selectedLabel.focus?.();};
      group.addEventListener('click',select);group.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();select();}});
      sceneNodes.append(group);
    }
    scene.setAttribute('viewBox',`0 0 720 ${Math.max(360,Math.ceil(sceneRows.length/4)*125+50)}`);
    for (const relation of ordered) {
      const li=document.createElement('li'); li.dataset.relationId=relation.id;
      const source=textNode('span',relation.from_name,'ecosystem-endpoint');
      const arrow=textNode('span','→','ecosystem-arrow'); arrow.setAttribute('aria-label','sent a verified completed message to');
      const target=textNode('span',relation.to_name,'ecosystem-endpoint');
      const details=textNode('small',`Relation ${relation.id} · Team ${relation.team_execution_key} (${relation.team_name}) · Mission ${relation.mission_id} rev ${relation.mission_revision} · ${relation.from} → ${relation.to} · ${relation.at} · ${root.dataset.state==='stale'?'stale snapshot · ':''}${relation.state} · ${relation.coverage}`);
      const endpoints=document.createElement('div'); endpoints.className='ecosystem-relation-endpoints'; endpoints.append(source,arrow,target);
      li.append(endpoints,details);
      const canPulse=liveNow(relation) && !seenPulses.has(relation.id);
      if (canPulse) { seenPulses.add(relation.id); if(seenPulses.size>200)seenPulses.delete(seenPulses.values().next().value); arrow.dataset.pulse='true'; arrow.addEventListener('animationend',()=>delete arrow.dataset.pulse,{once:true}); }
      graph.append(li);
    }
    const teams=snapshot.teams.filter(team=>team.members.some(id=>visibleIds.has(id))
      && (!filterSelect.value || filterSelect.value==='all' || effectiveLineageState(team)===filterSelect.value));
    teamsEmpty.hidden=teams.length>0;
    for (const team of teams) {
      const li=document.createElement('li');
      const memberDetails=team.members.map(id=>`${snapshot.instanceMap.get(id)?.display_name || 'Unknown'} (${id})`).join(', ');
      li.append(textNode('strong',`${team.name} · ${team.id}`),textNode('small',`${root.dataset.state==='stale'?'stale snapshot · ':''}${team.state} · ${team.coverage} · Source ${team.source_revision} · Mission ${team.mission_id} rev ${team.mission_revision} · ${memberDetails}`));
      teamsList.append(li);
    }
    for (const button of roster.querySelectorAll('button')) button.setAttribute('aria-pressed',String(button.dataset.instanceId===selectedId));
    renderDetail(selectedId ? snapshot.instanceMap.get(selectedId) : null);
    const summary=snapshot.summary || {}, total=Number.isSafeInteger(summary.observed_instances)?summary.observed_instances:snapshot.instances.length;
    const completion=Number.isSafeInteger(summary.observed_completed_executions)?`${summary.observed_completed_executions} observed completions`:'Completion count unknown';
    const window=snapshot.observation.window || {}, windowText=`Window ${window.from || 'unknown'} to ${window.to || 'unknown'} (${Number.isFinite(window.seconds)?window.seconds:'unknown'} seconds)`;
    const coverageText=typeof snapshot.observation.coverage==='string'?snapshot.observation.coverage:'unknown coverage';
    const duration=Number.isSafeInteger(summary.response_duration_ms)&&summary.response_duration_coverage>0?`${summary.response_duration_ms} ms observed response duration`:'observed response duration unknown';
    const durationCoverage=Number.isSafeInteger(summary.response_duration_coverage)?`${summary.response_duration_coverage} observed responses with duration`:'response duration coverage unknown';
    coverage.textContent=`${visible.length} of ${total} observed instances · ${completion} · ${duration} (${durationCoverage}) · ${windowText} · ${coverageText} · Observed ${snapshot.observation.observed_at} · ${snapshot.schema===1?'schema 1 has no verified Team lineage':`${snapshot.teams.length} verified Team instances · ${snapshot.relations.length} verified completed-message relations`}`
      + (snapshot.partial?' · partial or stale coverage; totals may be incomplete':'')
      + (snapshot.omittedTeams || snapshot.omittedRelations ? ` · omitted ${snapshot.omittedTeams} invalid Team rows and ${snapshot.omittedRelations} invalid relation rows` : '');
  }
  async function refresh() {
    if (stopped || loading) return;
    if (freshnessTimer) { clearTimeout(freshnessTimer); freshnessTimer=null; }
    loading=true; const current=++generation; refreshButton.disabled=true;
    if (snapshot) { setStatus('Refreshing; the previous snapshot is historical until a new read completes.','stale'); render(); }
    else setStatus('Reading current native observations…','unknown');
    try {
      const data=await api.get('/chat/api/ecosystem');
      if (stopped || current!==generation) return;
      const next=normalize(data);
      if (!next) throw new Error('invalid ecosystem projection');
      snapshot=next;
      if (freshnessTimer) clearTimeout(freshnessTimer);
      if (next.observation.state==='quiet') setStatus('No native instances were observed in this window.','empty');
      else if (next.partial) setStatus('Aggregate observation is partial; only individually verified fresh relations may appear as observed events.','partial');
      else if (!Number.isFinite(next.observedAt) || Date.now()-next.observedAt>120000 || Date.now()-next.observedAt< -30000)
        setStatus('The last native snapshot is historical; current state is unknown.','stale');
      else setStatus('Current root-observed native execution snapshot.','current');
    } catch (_) {
      if (stopped || current!==generation) return;
      if (snapshot) { setStatus('Refresh failed; showing the previous snapshot as stale.','stale'); render(); }
      else { setStatus('Native ecosystem observations are unavailable.','unknown'); coverage.textContent='Coverage is unknown; refresh when the protected source is available.'; roster.replaceChildren();graph.replaceChildren();teamsList.replaceChildren();renderDetail(null); }
    } finally {
      if (!stopped && current===generation) {
        loading=false; refreshButton.disabled=false;
        if(snapshot && (root.dataset.state==='current'||root.dataset.state==='partial') && Number.isFinite(snapshot.observedAt)) {
          const wait=Math.max(0,snapshot.observedAt+120000-Date.now()+1);
          freshnessTimer=setTimeout(()=>{if(!stopped && snapshot && Date.now()-snapshot.observedAt>120000){setStatus('The last native snapshot is historical; current state is unknown.','stale');render();}},wait);
        }
        render();
      }
    }
  }
  refreshButton.addEventListener('click',refresh,{signal:listeners.signal});
  searchInput.addEventListener('input',render,{signal:listeners.signal});
  filterSelect.addEventListener('change',render,{signal:listeners.signal});
  const onVisibility=()=>{ if (document.visibilityState!=='visible' && snapshot) { setStatus('Dashboard hidden; current activity is not being animated.','stale'); render(); } };
  const onOffline=()=>{ if (snapshot) { setStatus('Offline; current native activity is unknown.','stale'); render(); } };
  const onOnline=()=>{ if (snapshot) setStatus('Online; refresh to verify current native activity.','stale'); };
  document.addEventListener('visibilitychange',onVisibility,{signal:listeners.signal});
  window.addEventListener('offline',onOffline,{signal:listeners.signal});
  window.addEventListener('online',onOnline,{signal:listeners.signal});
  fitButton.addEventListener('click',()=>{const height=Math.max(360,Math.ceil(sceneNodes.children.length/4)*125+50);scene.setAttribute('viewBox',`0 0 720 ${height}`);scene.focus?.();},{signal:listeners.signal});
  const intersection=typeof IntersectionObserver==='function'?new IntersectionObserver(entries=>{sceneVisible=!!entries[0]?.isIntersecting;if(!sceneVisible)render();},{threshold:0.01}):null;
  intersection?.observe(sceneFrame);
  window.addEventListener('resize',()=>{scene.setAttribute('viewBox',`0 0 720 ${Math.max(360,Math.ceil(sceneNodes.children.length/4)*125+50)}`);},{signal:listeners.signal});
  void refresh();
  return function cleanup() { stopped=true; generation+=1; loading=false;if(freshnessTimer)clearTimeout(freshnessTimer);intersection?.disconnect();listeners.abort();refreshButton.disabled=true; };
}'''

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="ecosystem",
    nav_label="Ecosystem",
    title="Expert ecosystem",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(("GET", "/chat/api/ecosystem"),),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
