"""Owner Extensions view: catalog setup and direct edits through finite owner routes."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_extensions_admin import FEATURE_ROUTES


_VIEW = '''<section class="extensions-page" data-feature-root="extensions" aria-labelledby="extensions-title">
  <header class="extensions-head"><div><p class="extensions-kicker">OWNER SETUP</p><h2 id="extensions-title">Extensions</h2>
    <p>Manage skills, plugins, and MCP servers for the current Hermes profile. Each write is an owner action.</p></div>
    <button type="button" data-extension-refresh>Refresh</button></header>
  <p data-extension-status role="status" aria-live="polite">Loading the current native inventory.</p>
  <div class="extension-adds">
    <form data-add-skill><h3>Add a skill</h3><label>Official skill search term<input name="identifier" maxlength="160" required autocomplete="off"></label><button>Add skill</button></form>
    <form data-add-plugin><h3>Add a plugin</h3><label>Curated catalog name<input name="catalog_name" maxlength="160" required autocomplete="off"></label><button>Add plugin</button></form>
    <form data-add-mcp><h3>Add an MCP server</h3><label>Official catalog name<input name="catalog_name" maxlength="160" required autocomplete="off"></label><button>Add MCP server</button><p>Credentials and custom commands are not collected here.</p></form>
  </div>
  <div data-extension-list class="extension-list"></div>
  <p class="extensions-note">Hermes stock skills are read-only. Resources skills are edited as owner overlays; archiving an overlay reveals the pinned base again. Hermes-home owner-added skills can be archived with a recoverable backup. Restore is available for listed archived versions. Custom MCP connection edits are unavailable in the pinned Hermes API.</p>
</section>'''

_CSS = '''[data-feature-root="extensions"]{max-width:1100px;margin:0 auto;padding:clamp(18px,3vw,32px);color:var(--text,#edf5f6)}
[data-feature-root="extensions"] .extensions-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
[data-feature-root="extensions"] .extensions-kicker{margin:0 0 7px;color:var(--muted,#9bafb4);font-size:.72rem;letter-spacing:.14em}
[data-feature-root="extensions"] h2{margin:0;font-size:clamp(1.5rem,3vw,2rem)}
[data-feature-root="extensions"] p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="extensions"] button,[data-feature-root="extensions"] input{min-height:42px;padding:9px 12px;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;font:inherit}
[data-feature-root="extensions"] button{cursor:pointer}
[data-feature-root="extensions"] button:focus-visible,[data-feature-root="extensions"] input:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root="extensions"] .extension-adds{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,235px),1fr));gap:12px;margin:18px 0}
[data-feature-root="extensions"] form,.extension-card{padding:15px;border:1px solid var(--border,#294047);border-radius:12px;background:var(--panel,#0d1d23)}
[data-feature-root="extensions"] form h3,.extension-card h3{margin:0 0 10px;font-size:1rem}
[data-feature-root="extensions"] label{display:grid;gap:6px;margin:8px 0;color:var(--muted,#9bafb4);font-size:.83rem}
[data-feature-root="extensions"] form button{margin-top:8px}
[data-feature-root="extensions"] .extension-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,270px),1fr));gap:10px}
[data-feature-root="extensions"] .extension-card p{margin:6px 0;font-size:.86rem;overflow-wrap:anywhere}
[data-feature-root="extensions"] .extension-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
[data-feature-root="extensions"] .extension-note{font-size:.8rem}
[data-feature-root="extensions"] dialog{width:min(760px,92vw);border:1px solid #3c858b;border-radius:10px;background:#0b1b20;color:#e4f3f3;padding:16px}
[data-feature-root="extensions"] dialog::backdrop{background:rgba(0,0,0,.72)}
[data-feature-root="extensions"] dialog textarea{width:100%;min-height:360px;resize:vertical;border:1px solid #315058;border-radius:6px;background:#061115;color:#e4f3f3;padding:12px;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
@media(max-width:600px){[data-feature-root="extensions"] .extensions-head{flex-direction:column}[data-feature-root="extensions"] .extensions-head button{width:100%}}'''

_MOUNT = r'''function mount(container, api) {
  const root = container.querySelector('[data-feature-root="extensions"]') || container;
  const list = root.querySelector('[data-extension-list]'), status = root.querySelector('[data-extension-status]');
  const refresh = root.querySelector('[data-extension-refresh]');
  const lifecycle = new AbortController(), signal = lifecycle.signal, editors = new Set();
  const controls = new Set(), renderedControls = new Set();
  const forms = ['[data-add-skill]','[data-add-plugin]','[data-add-mcp]'].map(selector => root.querySelector(selector));
  let active = true, snapshot = null, busy = false, inventoryLoading = false, pendingSkillReads = 0;
  let recoveryRequired = false, inventoryReadRevision = 0;
  const actionsBlocked = () => busy || inventoryLoading || pendingSkillReads > 0 || recoveryRequired || !snapshot;
  function syncControls() {
    const disabled = actionsBlocked();
    for (const control of controls) control.disabled = disabled;
    refresh.disabled = busy || inventoryLoading;
  }
  const text = (parent, tag, value) => {
    const node = document.createElement(tag); node.textContent = String(value ?? 'Unknown');
    if (tag === 'button') { controls.add(node); renderedControls.add(node); node.disabled = actionsBlocked(); }
    parent.append(node); return node;
  };
  for (const form of forms) {
    const input = form.querySelector('input'), button = form.querySelector('button');
    if (input) controls.add(input); if (button) controls.add(button);
  }
  const makeKey = () => { const bytes = new Uint8Array(24); crypto.getRandomValues(bytes); return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); };
  function exactConfirm(phrase) { return window.prompt(`Type ${phrase} to confirm this owner action.`) === phrase; }
  function sourceStillCurrent(item, sourceRevision) {
    return !!snapshot && snapshot.revision === sourceRevision && snapshot.items.some(candidate =>
      candidate && candidate.id === item.id && candidate.kind === item.kind
        && candidate.source === item.source && candidate.editable === item.editable);
  }
  async function mutate(path, body, phrase, sourceRevision) {
    if (!active || actionsBlocked()) return;
    if (typeof sourceRevision !== 'string' || sourceRevision !== snapshot.revision) {
      recoveryRequired = true; status.textContent = 'The extension source changed. Refresh the inventory before another owner action.'; syncControls(); return;
    }
    if (!exactConfirm(phrase)) return;
    if (!active || actionsBlocked() || sourceRevision !== snapshot.revision) return;
    busy = true; status.textContent = 'Applying the confirmed owner action…'; syncControls();
    let appliedMessage = null;
    try { const result = await api.post(path, {...body, confirmation:phrase, idempotency_key:makeKey(), revision:sourceRevision});
      if (!active) return;
      if (result && result.status === 'applied') {
        appliedMessage = result.result && result.result.recoveryId
          ? `${result.result.action==='restore'?'Restored':'Archived'} skill version ${result.result.recoveryId}`
          : 'Owner action reported applied';
        recoveryRequired = true;
        status.textContent = `${appliedMessage}; reading current inventory.`;
      } else {
        recoveryRequired = true;
        status.textContent = 'The action outcome is unknown and may still be pending. Refresh current inventory before another owner action; do not repeat it yet.';
      }
    } catch (_) {
      if (active) { recoveryRequired = true; status.textContent = 'The action outcome is unknown and may still be pending. Refresh current inventory before another owner action; do not repeat it yet.'; }
    } finally {
      if (active) {
        busy = false; syncControls();
        if (appliedMessage) await load({afterApplied: appliedMessage});
      }
    }
  }
  function card(item, sourceRevision) {
    const box = document.createElement('article'); box.className='extension-card';
    text(box,'h3',item.label); text(box,'p',`${item.kind} · ${item.kind==='skills'?(item.originLabel||item.source):item.source}`);
    const detail = item.kind === 'plugins' ? `${item.state || 'status unknown'} · ${item.version || 'version unknown'}`
      : item.kind === 'mcps' ? `${item.transport} · ${item.enabled ? 'enabled' : 'disabled'} · ${item.originLabel || 'source unverified'}` : `${item.category} · ${item.actionState || (item.loaded ? 'loaded' : 'source present, not loaded')}`;
    text(box,'p',detail);
    if (item.updateAvailable === true) text(box,'p','A catalog update is available. Jarvis cannot apply it because the pinned native settings API has no reviewed update action.');
    const actions = document.createElement('div'); actions.className='extension-actions';
    if (item.kind === 'skills' && ['useradded','bundledResources'].includes(item.source) && item.editable) {
      const edit=text(actions,'button','Edit skill'); edit.type='button'; edit.addEventListener('click',async()=>{
        if (!active || actionsBlocked()) return;
        pendingSkillReads += 1; status.textContent='Reading current skill source…'; syncControls();
        try {
          const file=await api.post('/chat/api/extensions/skills/read',{item_id:item.id,revision:sourceRevision});
          if (!active) return;
          if (!sourceStillCurrent(item, sourceRevision)) {
            status.textContent='The inventory changed while the skill was loading. Reopen the current skill before editing.';
            return;
          }
          const dialog=document.createElement('dialog'); dialog.setAttribute('aria-labelledby','extension-skill-edit-title');
          const form=document.createElement('form'); form.method='dialog';
          const heading=text(form,'h3',`Edit ${item.label}`); heading.id='extension-skill-edit-title';
          const area=document.createElement('textarea'); area.value=file.content; area.maxLength=65536; area.rows=22; area.setAttribute('aria-label','Skill instructions'); controls.add(area);
          const save=document.createElement('button'); save.type='button'; save.textContent='Save skill'; controls.add(save);
          const cancel=document.createElement('button'); cancel.type='button'; cancel.textContent='Cancel'; controls.add(cancel);
          form.append(area,save,cancel); dialog.append(form); root.append(dialog);
          cancel.addEventListener('click',()=>dialog.close(),{signal});
          save.addEventListener('click',async()=>{
            if (!active || actionsBlocked()) return;
            if (!sourceStillCurrent(item, sourceRevision)) {
              status.textContent='The inventory changed while this editor was open. Close it and reopen the current skill to review the current source before saving.';
              dialog.close(); dialog.remove(); editors.delete(dialog); return;
            }
            const content=area.value; dialog.close(); dialog.remove(); editors.delete(dialog);
            await mutate('/chat/api/extensions/skills/edit',{item_id:item.id,content},`EDIT ${item.label}`,sourceRevision);
          },{signal});
          dialog.addEventListener('close',()=>{
            dialog.remove(); editors.delete(dialog); controls.delete(area); controls.delete(save); controls.delete(cancel);
          },{once:true,signal});
          editors.add(dialog); status.textContent='Current skill source is loaded for review.'; syncControls(); dialog.showModal(); area.focus();
        } catch (_) {
          if (active && snapshot && snapshot.revision === sourceRevision && !busy && !inventoryLoading)
            status.textContent='Current skill source is unavailable; refresh and retry.';
        } finally { if (active) { pendingSkillReads = Math.max(0, pendingSkillReads - 1); syncControls(); } }
      },{signal});
      if (item.removable) { const archive=text(actions,'button',item.source==='bundledResources'?'Archive overlay':'Archive skill'); archive.type='button'; archive.addEventListener('click',()=>{
        const resource = item.source==='bundledResources';
        const warning = resource
          ? `Archive the owner overlay for ${item.label}? Hermes will use the pinned Bundled Resources base again. The previous overlay is retained for recovery.`
          : `Archive ${item.label}? Its owner-added SKILL.md entrypoint is moved out of discovery. A root-private recovery backup is retained.`;
        if (!window.confirm(warning)) return;
        void mutate('/chat/api/extensions/skills/remove',{item_id:item.id},`${resource?'ARCHIVE OVERLAY':'ARCHIVE (RECOVERABLE)'} ${item.label}`,sourceRevision);
      },{signal}); }
    }
    if (item.kind==='skills' && Array.isArray(item.archivedVersions) && item.archivedVersions.length
        && (item.source==='bundledResources' || (item.source==='useradded' && !item.editable))) {
      const restore=text(actions,'button','Restore archived version'); restore.type='button'; restore.addEventListener('click',async()=>{
        const versions=item.archivedVersions;
        const choices=versions.map((version,index)=>`${index+1}: ${version.sha256.slice(0,12)} · ${version.restoreId.slice(0,12)}`).join('\n');
        const selected=Number(window.prompt(`Choose the archived version to restore for ${item.label}:\n${choices}`, '1'));
        if (!Number.isInteger(selected)||selected<1||selected>versions.length) return;
        const version=versions[selected-1];
        await mutate('/chat/api/extensions/skills/restore',{item_id:item.id,restore_id:version.restoreId,restore_sha256:version.sha256},`RESTORE ${item.label} ${version.restoreId}`,sourceRevision);
      },{signal});
    }
    if (item.kind === 'plugins' && item.editable && Array.isArray(item.settings) && item.settings.some((field)=>['string','number','boolean','enum'].includes(field.type))) {
      const edit = text(actions,'button','Edit settings'); edit.type='button'; edit.addEventListener('click',async()=>{
        const values={};
        for (const field of item.settings) { if (!field || !['string','number','boolean','enum'].includes(field.type)) continue;
          const current = field.value === undefined || field.value === null ? '' : String(field.value);
          const entered = window.prompt(`${field.label || field.key}${field.required?' (required)':''}`,current);
          if (entered === null) return; if (field.type==='boolean') values[field.key]=entered.toLowerCase()==='true';
          else if (field.type==='number') { const number=Number(entered); if (!Number.isFinite(number)) { status.textContent='Enter a valid number.'; return; } values[field.key]=number; }
          else values[field.key]=entered;
        }
        if (Object.keys(values).length) await mutate('/chat/api/extensions/plugins/edit',{item_id:item.id,values},`EDIT ${item.label}`,sourceRevision);
      },{signal});
      if (item.source==='useradded') { const toggle = text(actions,'button',item.state==='enabled'?'Disable':'Enable'); toggle.type='button'; toggle.addEventListener('click',()=>{
        const enabled = item.state!=='enabled'; const phrase=`${enabled?'ENABLE':'DISABLE'} ${item.label}`;
        void mutate('/chat/api/extensions/plugins/toggle',{item_id:item.id,enabled},phrase,sourceRevision);
      },{signal}); }
    }
    if (item.kind==='plugins' && item.removable && item.source==='useradded') {
      const remove=text(actions,'button','Remove permanently'); remove.type='button'; remove.addEventListener('click',()=>{
        const warning=`Permanently remove ${item.label} from this Hermes profile? This deletes its plugin package and registration and cannot be undone from this dashboard. It does not target your Obsidian vault.`;
        if (!window.confirm(warning)) return;
        void mutate('/chat/api/extensions/plugins/remove',{item_id:item.id},`DELETE PERMANENTLY ${item.label}`,sourceRevision);
      },{signal});
    }
    if (item.kind==='mcps' && item.removable) { const remove=text(actions,'button','Remove server'); remove.type='button'; remove.addEventListener('click',()=>{
      const kind=item.kind; void mutate(`/chat/api/extensions/${kind}/remove`,{item_id:item.id},`DELETE ${item.label}`,sourceRevision);
    },{signal}); }
    box.append(actions); return box;
  }
  function render() {
    for (const control of renderedControls) controls.delete(control);
    renderedControls.clear(); list.replaceChildren();
    if (!snapshot || !Array.isArray(snapshot.items)) { syncControls(); return; }
    const sourceRevision=snapshot.revision;
    for (const item of snapshot.items) list.append(card(item,sourceRevision));
    syncControls();
  }
  async function load(options = {}) {
    if (!active || busy) return;
    const readRevision=++inventoryReadRevision, hadRecovery=recoveryRequired;
    inventoryLoading=true; status.textContent='Reading current Hermes inventory…'; syncControls();
    try {
      const data=await api.get('/chat/api/extensions');
      if (!active || readRevision !== inventoryReadRevision) return;
      if (!data || data.schema!==1 || !Array.isArray(data.items) || typeof data.revision!=='string') throw Error();
      snapshot=data;
      if (options.explicit === true || options.afterApplied) recoveryRequired=false;
      render();
      const observed=`${data.items.length} current extension records · ${data.readiness}.`;
      status.textContent=options.afterApplied
        ? `${observed} ${options.afterApplied}; current inventory readback completed.`
        : options.explicit === true && hadRecovery
          ? `${observed} Inventory refreshed; review the observed source before another owner action.`
          : observed;
    } catch (_) {
      if (active && readRevision === inventoryReadRevision) {
        snapshot=null; recoveryRequired=true; list.replaceChildren();
        status.textContent=options.afterApplied
          ? `${options.afterApplied}, but current inventory readback is unavailable. Refresh before another owner action.`
          : 'Current extension inventory is unavailable.';
      }
    } finally {
      if (active && readRevision === inventoryReadRevision) { inventoryLoading=false; syncControls(); }
    }
  }
  function bind(formSelector, path, key, endpoint, verb) { const form=root.querySelector(formSelector); form.addEventListener('submit',async(event)=>{
    event.preventDefault(); if(!snapshot||actionsBlocked())return; const sourceRevision=snapshot.revision;
    const value=new FormData(form).get(key); if(typeof value!=='string'||!value.trim())return;
    const phrase=`${verb} ${value.trim()}`; const body={[key]:value.trim()}; await mutate(path,body,phrase,sourceRevision); if (active) form.reset();
  },{signal}); }
  bind('[data-add-skill]','/chat/api/extensions/skills/add','identifier','identifier','ADD');
  bind('[data-add-plugin]','/chat/api/extensions/plugins/add','catalog_name','catalog_name','ADD');
  bind('[data-add-mcp]','/chat/api/extensions/mcps/add','catalog_name','catalog_name','ADD');
  refresh.addEventListener('click',()=>load({explicit:true}),{signal}); void load();
  return ()=>{active=false;lifecycle.abort();for(const dialog of editors){if(dialog.open)dialog.close();dialog.remove();}editors.clear();list.replaceChildren();};
}'''

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="extensions",
    nav_label="Extensions",
    title="Owner extensions",
    view_html=_VIEW,
    css=_CSS,
    api_routes=tuple((method, path) for method, path in (
        ("GET", "/chat/api/extensions"), *FEATURE_ROUTES[1:])),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
