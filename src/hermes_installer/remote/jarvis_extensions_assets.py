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
  <section class="inventory-tools" aria-label="Filter native extension inventory">
    <label>Search Skills, Plugins, and MCP servers<input type="search" data-inventory-search autocomplete="off"></label>
    <label>Show<select data-inventory-kind><option value="all">All types</option><option value="skills">Skills</option><option value="plugins">Plugins</option><option value="mcps">MCP servers</option></select></label>
    <p data-inventory-count role="status" aria-live="polite">Waiting for current inventory.</p>
  </section>
  <div data-extension-list class="extension-list"></div>
  <p data-inventory-empty hidden>No native Skills, Plugins, or MCP servers are currently reported.</p>
  <p data-inventory-no-match hidden>No current inventory records match these filters.</p>
  <p class="extensions-note">Hermes stock skills are read-only. Resources skills are edited as owner overlays; archiving an overlay reveals the pinned base again. Hermes-home owner-added skills can be archived with a recoverable backup. Restore is available for listed archived versions. Custom MCP connection edits are unavailable in the pinned Hermes API.</p>
</section>'''

_CSS = '''[data-feature-root="extensions"]{max-width:1100px;margin:0 auto;padding:clamp(18px,3vw,32px);color:var(--text,#edf5f6)}
[data-feature-root="extensions"] .extensions-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start}
[data-feature-root="extensions"] .extensions-kicker{margin:0 0 7px;color:var(--muted,#9bafb4);font-size:.72rem;letter-spacing:.14em}
[data-feature-root="extensions"] h2{margin:0;font-size:clamp(1.5rem,3vw,2rem)}
[data-feature-root="extensions"] p{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root="extensions"] button,[data-feature-root="extensions"] input,[data-feature-root="extensions"] select{min-height:42px;padding:9px 12px;border:1px solid var(--border,#38515a);border-radius:9px;background:var(--panel,#0d1d23);color:inherit;font:inherit}
[data-feature-root="extensions"] button{cursor:pointer}
[data-feature-root="extensions"] button:focus-visible,[data-feature-root="extensions"] input:focus-visible,[data-feature-root="extensions"] select:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:2px}
[data-feature-root="extensions"] .extension-adds{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,235px),1fr));gap:12px;margin:18px 0}
[data-feature-root="extensions"] form,.extension-card{padding:15px;border:1px solid var(--border,#294047);border-radius:12px;background:var(--panel,#0d1d23)}
[data-feature-root="extensions"] form h3,.extension-card h3{margin:0 0 10px;font-size:1rem}
[data-feature-root="extensions"] label{display:grid;gap:6px;margin:8px 0;color:var(--muted,#9bafb4);font-size:.83rem}
[data-feature-root="extensions"] form button{margin-top:8px}
[data-feature-root="extensions"] .extension-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,270px),1fr));gap:10px}
[data-feature-root="extensions"] .inventory-tools{display:grid;grid-template-columns:minmax(220px,1fr) minmax(150px,.35fr);align-items:end;gap:12px;margin:18px 0}
[data-feature-root="extensions"] .inventory-tools label{margin:0}
[data-feature-root="extensions"] .inventory-tools input,[data-feature-root="extensions"] .inventory-tools select{width:100%}
[data-feature-root="extensions"] [data-inventory-count]{grid-column:1/-1;margin:0;font-size:.82rem}
[data-feature-root="extensions"] [data-inventory-empty],[data-feature-root="extensions"] [data-inventory-no-match]{padding:18px;border:1px dashed var(--border,#38515a);border-radius:10px}
[data-feature-root="extensions"] .extension-card p{margin:6px 0;font-size:.86rem;overflow-wrap:anywhere}
[data-feature-root="extensions"] .extension-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
[data-feature-root="extensions"] .extension-note{font-size:.8rem}
[data-feature-root="extensions"] dialog{width:min(760px,92vw);border:1px solid #3c858b;border-radius:10px;background:#0b1b20;color:#e4f3f3;padding:16px}
[data-feature-root="extensions"] dialog::backdrop{background:rgba(0,0,0,.72)}
[data-feature-root="extensions"] dialog textarea,[data-feature-root="extensions"] dialog pre{width:100%;min-height:150px;max-height:320px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;border:1px solid #315058;border-radius:6px;background:#061115;color:#e4f3f3;padding:12px;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
[data-feature-root="extensions"] dialog textarea{min-height:260px;resize:vertical}
[data-feature-root="extensions"] dialog .settings-fields{display:grid;gap:12px;margin:16px 0}
[data-feature-root="extensions"] dialog .settings-field{display:grid;gap:6px}
[data-feature-root="extensions"] dialog .settings-field label{color:#d7e7e9;font-size:.9rem}
[data-feature-root="extensions"] dialog .settings-field input,[data-feature-root="extensions"] dialog .settings-field select,[data-feature-root="extensions"] dialog .settings-field textarea{width:100%;min-height:42px;border:1px solid #315058;border-radius:7px;background:#061115;color:#e4f3f3;padding:9px;font:inherit}
[data-feature-root="extensions"] dialog .settings-field [aria-invalid="true"]{border-color:#ff9393}
[data-feature-root="extensions"] dialog .settings-help{margin:0;font-size:.78rem;color:#aabfc3}
[data-feature-root="extensions"] dialog .settings-error{margin:0;color:#ffb0b0;font-size:.82rem}
[data-feature-root="extensions"] dialog [role="alert"]{padding:10px;border-left:3px solid #e59c58;background:rgba(229,156,88,.1)}
[data-feature-root="extensions"] dialog .settings-actions{display:flex;flex-wrap:wrap;gap:8px;justify-content:flex-end;margin-top:16px}
@media(max-width:600px){[data-feature-root="extensions"] .extensions-head{flex-direction:column}[data-feature-root="extensions"] .extensions-head button{width:100%}[data-feature-root="extensions"] .inventory-tools{grid-template-columns:1fr}}'''

# Keep the reviewed source indented while dropping only line-leading JS whitespace from the fixed browser asset.
_MOUNT = "\n".join(line.lstrip() for line in r'''function mount(container, api) {
  const root = container.querySelector('[data-feature-root="extensions"]') || container;
  const list = root.querySelector('[data-extension-list]'), status = root.querySelector('[data-extension-status]');
  const search = root.querySelector('[data-inventory-search]'), kindFilter = root.querySelector('[data-inventory-kind]');
  const inventoryCount = root.querySelector('[data-inventory-count]'), emptyState = root.querySelector('[data-inventory-empty]');
  const noMatch = root.querySelector('[data-inventory-no-match]');
  const refresh = root.querySelector('[data-extension-refresh]');
  const lifecycle = new AbortController(), signal = lifecycle.signal, editors = new Set();
  const controls = new Set(), renderedControls = new Set(), settingsDialogControls = new Set();
  const forms = ['[data-add-skill]','[data-add-plugin]','[data-add-mcp]'].map(selector => root.querySelector(selector));
  let active = true, snapshot = null, busy = false, inventoryLoading = false, pendingSkillReads = 0;
  let selectedSkillId = null, selectedSkillEpoch = 0;
  let settingsDialogOpen = false;
  let recoveryRequired = false, inventoryReadRevision = 0;
  const coreActionsBlocked = () => busy || inventoryLoading || pendingSkillReads > 0 || recoveryRequired || !snapshot;
  const actionsBlocked = () => coreActionsBlocked() || settingsDialogOpen;
  function syncControls() {
    const disabled = coreActionsBlocked();
    for (const control of controls)
      control.disabled = disabled || (settingsDialogOpen && !settingsDialogControls.has(control));
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
        && candidate.name === item.name && candidate.sha256 === item.sha256
        && candidate.source === item.source && candidate.editable === item.editable);
  }
  function skillSelectionCurrent(item, sourceRevision, selectionEpoch) {
    return active && selectedSkillId === item.id && selectedSkillEpoch === selectionEpoch
      && sourceStillCurrent(item,sourceRevision);
  }
  const sensitiveSettingName = /(?:credential|secret|password|token|api[_ -]?key|private[_ -]?key|command|shell|path|file)/i;
  function safeSettingName(value, maximum) {
    return typeof value === 'string' && value.length > 0 && value.length <= maximum
      && !/[\x00-\x1f\x7f]/.test(value) && !sensitiveSettingName.test(value);
  }
  function safeSettingText(value, maximum=160) {
    return typeof value === 'string' && value.length <= maximum;
  }
  function inspectPluginSettings(settings) {
    const kinds = new Set(['string','number','boolean','enum']), keys = new Set();
    if (!Array.isArray(settings) || settings.length < 1 || settings.length > 32)
      return {fields:[], pending:true};
    const fields=[];
    for (const field of settings) {
      if (!field || typeof field !== 'object' || !kinds.has(field.type)
          || !safeSettingName(field.key,160)
          || keys.has(field.key) || (field.required !== undefined && typeof field.required !== 'boolean'))
        return {fields:[], pending:true};
      keys.add(field.key);
      const label=field.label === undefined ? field.key : field.label;
      if (!safeSettingText(label,120)) return {fields:[], pending:true};
      const choices = field.type === 'enum' ? field.choices : undefined;
      if (field.type === 'enum' && (!Array.isArray(choices) || choices.length < 1 || choices.length > 64
          || choices.some(choice => !safeSettingText(choice) || choices.filter(value => value === choice).length !== 1)))
        return {fields:[], pending:true};
      const value=field.value;
      if (value !== undefined && value !== null) {
        if (field.type === 'string' && (typeof value !== 'string' || Array.from(value).length > 2048))
          return {fields:[], pending:true};
        if (field.type === 'number' && (typeof value !== 'number' || !Number.isFinite(value)))
          return {fields:[], pending:true};
        if (field.type === 'boolean' && typeof value !== 'boolean') return {fields:[], pending:true};
        if (field.type === 'enum' && (typeof value !== 'string' || !choices.includes(value)))
          return {fields:[], pending:true};
      }
      fields.push({key:field.key,label,type:field.type,required:field.required === true,
        value,choices});
    }
    return {fields,pending:false};
  }
  function openPluginSettings(item, sourceRevision, opener) {
    const inspected=inspectPluginSettings(item.settings);
    const contextSafe=safeSettingText(item.name || item.label,160) && safeSettingText(item.label,160)
      && safeSettingText(item.source,80) && safeSettingText(sourceRevision,128);
    const schema=contextSafe ? inspected : {fields:[],pending:true};
    const displayLabel=contextSafe ? item.label : 'Unavailable plugin';
    const dialog=document.createElement('dialog');
    dialog.setAttribute('aria-labelledby','extension-plugin-settings-title');
    dialog._extensionOpener=opener;
    const form=document.createElement('form'); form.method='dialog';
    const heading=text(form,'h3',`Edit settings: ${displayLabel}`); heading.id='extension-plugin-settings-title';
    const scope=document.createElement('p'); scope.className='settings-help';
    const nativeSettingsRevision=typeof item.settingsRevision==='string' && /^[0-9a-f]{64}$/.test(item.settingsRevision)
      ? item.settingsRevision : 'Unknown';
    scope.textContent=`Plugin: ${contextSafe ? item.name || item.label : 'Unavailable'} · Source: ${contextSafe ? item.source : 'Unavailable'} · Inventory revision: ${contextSafe ? sourceRevision : 'Unavailable'} · Native settings revision: ${nativeSettingsRevision}`;
    form.append(scope);
    const consequence=document.createElement('p'); consequence.className='settings-help';
    consequence.textContent='Saving submits these typed values through the owner-confirmed native plugin settings action. Nothing changes until you choose Save and confirm the exact edit phrase.';
    form.append(consequence);
    const pending=document.createElement('p'); pending.setAttribute('role','alert'); pending.setAttribute('aria-live','polite');
    pending.textContent=schema.pending
      ? 'Native settings are unavailable, unsupported, or malformed. Editing remains pending; no values were changed.'
      : '';
    pending.hidden=!schema.pending; form.append(pending);
    const fields=document.createElement('div'); fields.className='settings-fields';
    const entries=[];
    if (!schema.pending) schema.fields.forEach((field,index)=>{
      const row=document.createElement('div'); row.className='settings-field';
      const label=document.createElement('label'); label.htmlFor=`extension-setting-${index}`; label.textContent=field.label;
      let input;
      if (field.type === 'boolean' || field.type === 'enum') {
        input=document.createElement('select');
        const placeholder=document.createElement('option'); placeholder.value='';
        placeholder.textContent=field.type === 'boolean' ? 'Choose true or false' : 'Choose a value'; input.append(placeholder);
        const values=field.type === 'boolean' ? ['true','false'] : field.choices;
        values.forEach((choice,choiceIndex)=>{
          const option=document.createElement('option');
          option.value=field.type === 'boolean' ? `boolean:${choice}` : `choice:${choiceIndex}`;
          option.textContent=String(choice); input.append(option);
        });
        if (field.type === 'boolean' && typeof field.value === 'boolean') input.value=`boolean:${field.value}`;
        if (field.type === 'enum' && typeof field.value === 'string' && field.choices.includes(field.value)) input.value=`choice:${field.choices.indexOf(field.value)}`;
      } else if (field.type === 'number') {
        input=document.createElement('input'); input.type='number'; input.step='any';
        if (typeof field.value === 'number' && Number.isFinite(field.value)) input.value=String(field.value);
      } else {
        input=document.createElement('textarea'); input.maxLength=4096; input.rows=3;
        if (typeof field.value === 'string') input.value=field.value;
        if (field.required) input.required=true;
      }
      input.id=`extension-setting-${index}`; input.setAttribute('aria-describedby',`extension-setting-help-${index} extension-setting-error-${index}`);
      if (field.type !== 'string' && field.required) input.required=true;
      const help=document.createElement('p'); help.className='settings-help'; help.id=`extension-setting-help-${index}`;
      help.textContent=field.type === 'boolean' && field.value === undefined
        ? 'Current value is unknown. Choose true or false explicitly.'
        : field.type === 'enum' && field.value === undefined
          ? 'No current choice is known. Select an exact native option; no default is guessed.'
          : field.type === 'number' && field.value === undefined
            ? 'Enter a finite number explicitly.'
            : field.type === 'string' ? 'Text value, limited to 2048 characters.' : '';
      const error=document.createElement('p'); error.className='settings-error'; error.id=`extension-setting-error-${index}`;
      error.setAttribute('role','alert'); error.hidden=true;
      row.append(label,input,help,error); fields.append(row);
      controls.add(input); settingsDialogControls.add(input);
      entries.push({field,input,error});
    });
    form.append(fields);
    const actions=document.createElement('div'); actions.className='settings-actions';
    const save=document.createElement('button'); save.type='submit'; save.textContent='Save settings';
    const cancel=document.createElement('button'); cancel.type='button'; cancel.textContent='Cancel';
    controls.add(save); controls.add(cancel);
    if (!schema.pending) settingsDialogControls.add(save);
    settingsDialogControls.add(cancel);
    if (schema.pending) save.disabled=true;
    actions.append(save,cancel); form.append(actions); dialog.append(form); root.append(dialog);
    let submitted=false;
    async function submitSettings(event) {
      event.preventDefault();
      if (!active || submitted || coreActionsBlocked()) return;
      if (!sourceStillCurrent(item,sourceRevision)) {
        status.textContent='The plugin source changed while this editor was open. Close it, refresh, and reopen current settings before saving.';
        dialog.close(); return;
      }
      if (schema.pending) return;
      const values=Object.create(null); let firstInvalid=null;
      for (const entry of entries) {
        const {field,input,error}=entry, raw=input.value;
        let value, message='';
        if (field.type === 'boolean') {
          if (raw !== 'boolean:true' && raw !== 'boolean:false') message='Choose true or false explicitly.';
          else value=raw === 'boolean:true';
        } else if (field.type === 'enum') {
          const match=typeof raw === 'string' && /^choice:(\d+)$/.exec(raw);
          const index=match ? Number(match[1]) : -1;
          if (!Number.isInteger(index) || index < 0 || index >= field.choices.length) message='Choose one exact native option.';
          else value=field.choices[index];
        } else if (field.type === 'number') {
          if (typeof raw !== 'string' || !raw.trim()) message='Enter a finite number explicitly.';
          else { const number=Number(raw); if (!Number.isFinite(number)) message='Enter a finite number.'; else value=number; }
        } else {
          if (typeof raw !== 'string' || Array.from(raw).length > 2048) message='Use no more than 2048 characters.';
          else if (field.required && raw === '') message='This setting is required.';
          else value=raw;
        }
        if (message) {
          error.textContent=message; error.hidden=false; input.setAttribute('aria-invalid','true');
          if (!firstInvalid) firstInvalid=input;
        } else {
          error.textContent=''; error.hidden=true; input.setAttribute('aria-invalid','false'); values[field.key]=value;
        }
      }
      if (firstInvalid) { status.textContent='Review the highlighted setting errors before saving.'; firstInvalid.focus(); return; }
      if (!Object.keys(values).length) { status.textContent='No supported settings are available to save.'; return; }
      submitted=true; dialog.close();
      await mutate('/chat/api/extensions/plugins/edit',{item_id:item.id,values},`EDIT ${displayLabel}`,sourceRevision);
    }
    form.addEventListener('submit',submitSettings,{signal});
    cancel.addEventListener('click',()=>dialog.close(),{signal});
    dialog.addEventListener('close',()=>{
      settingsDialogOpen=false; dialog.remove(); editors.delete(dialog);
      for (const entry of entries) { controls.delete(entry.input); settingsDialogControls.delete(entry.input); }
      controls.delete(save); controls.delete(cancel); settingsDialogControls.delete(save); settingsDialogControls.delete(cancel);
      syncControls(); if (opener && typeof opener.focus === 'function') opener.focus();
    },{once:true,signal});
    editors.add(dialog); settingsDialogOpen=true; syncControls(); dialog.showModal();
    const firstInput=entries.length ? entries[0].input : cancel;
    if (firstInput && typeof firstInput.focus === 'function') firstInput.focus();
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
        selectedSkillId=item.id; const selectionEpoch=++selectedSkillEpoch;
        pendingSkillReads += 1; status.textContent='Reading current skill source…'; syncControls();
        try {
          const file=await api.post('/chat/api/extensions/skills/read',{item_id:item.id,revision:sourceRevision});
          if (!active) return;
          if (!skillSelectionCurrent(item,sourceRevision,selectionEpoch)) {
            status.textContent='The inventory changed while the skill was loading. Reopen the current skill before editing.';
            return;
          }
          if (!file || file.name!==item.name || typeof file.content!=='string' || file.content.length>65536
              || !/^[0-9a-f]{64}$/.test(file.sha256) || file.sha256!==item.sha256
              || !/^[0-9a-f]{64}$/.test(file.sourceGeneration) || typeof file.effective!=='boolean') {
            status.textContent='Current skill source provenance or digest is incomplete. Refresh before reviewing a write.';
            return;
          }
          const dialog=document.createElement('dialog'); dialog.setAttribute('aria-labelledby','extension-skill-edit-title');
          const form=document.createElement('form'); form.method='dialog';
          const heading=text(form,'h3',`Edit ${item.label}`); heading.id='extension-skill-edit-title';
          const provenance=text(form,'p',`Source: ${item.originLabel||item.source} · Current SHA-256: ${file.sha256} · Source generation: ${file.sourceGeneration} · Native effective readback: ${file.effective?'confirmed':'not confirmed'}`);
          provenance.className='settings-help';
          text(form,'p','Review the exact captured source beside the proposed text. This editor is inert; no code or skill is run here.');
          const beforeLabel=text(form,'h4','Captured source before');
          const before=document.createElement('pre'); before.setAttribute('aria-label','Exact captured source before edit'); before.textContent=file.content;
          const area=document.createElement('textarea'); area.value=file.content; area.maxLength=65536; area.rows=16; area.setAttribute('aria-label','Proposed source after edit; inert text editor'); controls.add(area);
          const save=document.createElement('button'); save.type='button'; save.textContent='Save skill'; controls.add(save);
          const cancel=document.createElement('button'); cancel.type='button'; cancel.textContent='Cancel'; controls.add(cancel);
          form.append(beforeLabel,before,text(form,'p','Proposed source after'),area,save,cancel); dialog.append(form); root.append(dialog);
          cancel.addEventListener('click',()=>dialog.close(),{signal});
          save.addEventListener('click',async()=>{
            if (!skillSelectionCurrent(item,sourceRevision,selectionEpoch) || actionsBlocked()) {
              status.textContent='The inventory changed while this editor was open. Close it and reopen the current skill to review the current source before saving.';
              dialog.close(); dialog.remove(); editors.delete(dialog); return;
            }
            const content=area.value;
            if (content===file.content) { status.textContent='No source changes to review or save.'; return; }
            dialog.close(); dialog.remove(); editors.delete(dialog);
            await mutate('/chat/api/extensions/skills/edit',{item_id:item.id,content},`EDIT ${item.label}`,sourceRevision);
          },{signal});
          dialog.addEventListener('close',()=>{
            dialog.remove(); editors.delete(dialog); controls.delete(area); controls.delete(save); controls.delete(cancel);
          },{once:true,signal});
          editors.add(dialog); status.textContent='Current skill source, provenance, and before/after text are ready for owner review.'; syncControls(); dialog.showModal(); area.focus();
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
        if (!active || actionsBlocked()) return;
        selectedSkillId=item.id; const selectionEpoch=++selectedSkillEpoch;
        pendingSkillReads += 1; status.textContent='Reading archived version identities…'; syncControls();
        try {
          const archive=await api.post('/chat/api/extensions/skills/restore-list',{item_id:item.id,revision:sourceRevision});
          if (!active) return;
          if (!skillSelectionCurrent(item,sourceRevision,selectionEpoch)) {
            status.textContent='The inventory or selected skill changed while archived versions were loading. Refresh and select the current skill.';
            return;
          }
          if (!archive || archive.skill!==item.label || !Array.isArray(archive.versions) || archive.versions.length>64
              || archive.versions.some(version=>!version || !/^[A-Za-z0-9_-]{16,96}$/.test(version.restoreId||'')
                || !/^[0-9a-f]{64}$/.test(version.sha256||'')))
            throw Error();
          if (!archive.versions.length) { status.textContent='No archived versions are currently available for this skill.'; return; }
          const dialog=document.createElement('dialog'); dialog.setAttribute('aria-labelledby','extension-restore-title');
          const form=document.createElement('form'); form.method='dialog';
          const heading=text(form,'h3',`Restore ${item.label}`); heading.id='extension-restore-title';
          text(form,'p','Choose an exact archived identity by restore ID and SHA-256. Archive contents and dates are not exposed by the native interface.');
          const label=document.createElement('label'); label.textContent='Archived version';
          const select=document.createElement('select'); select.setAttribute('aria-label','Archived version identity');
          const placeholder=document.createElement('option'); placeholder.value=''; placeholder.textContent='Choose a version'; select.append(placeholder);
          archive.versions.forEach((version,index)=>{const option=document.createElement('option');option.value=String(index);option.textContent=`${version.sha256} · ${version.restoreId}`;select.append(option);});
          label.append(select); text(form,'p','Selection alone does not restore; the next step asks you to confirm the exact restore ID.');
          const restore=text(form,'button','Review and restore'); restore.type='button'; restore.disabled=true;
          const cancel=text(form,'button','Cancel'); cancel.type='button'; form.append(label,restore,cancel); dialog.append(form); root.append(dialog);
          select.addEventListener('change',()=>{restore.disabled=select.value==='' || !skillSelectionCurrent(item,sourceRevision,selectionEpoch);},{signal});
          cancel.addEventListener('click',()=>dialog.close(),{signal});
          restore.addEventListener('click',async()=>{
            if (!skillSelectionCurrent(item,sourceRevision,selectionEpoch) || actionsBlocked()) {
              status.textContent='The selected skill or inventory changed. Refresh before restoring an archived version.'; dialog.close(); return;
            }
            const index=Number(select.value), version=archive.versions[index];
            if (!Number.isInteger(index) || index<0 || !version) return;
            dialog.close(); await mutate('/chat/api/extensions/skills/restore',
              {item_id:item.id,restore_id:version.restoreId,restore_sha256:version.sha256},
              `RESTORE ${item.label} ${version.restoreId}`,sourceRevision);
          },{signal});
          dialog.addEventListener('close',()=>{dialog.remove();editors.delete(dialog);},{once:true,signal});
          editors.add(dialog); status.textContent='Current archived version identities are ready for exact selection.'; dialog.showModal(); select.focus();
        } catch (_) {
          if (active && skillSelectionCurrent(item,sourceRevision,selectionEpoch))
            status.textContent='Archived version identities are unavailable or malformed. Refresh and retry.';
        } finally { if (active) { pendingSkillReads=Math.max(0,pendingSkillReads-1); syncControls(); } }
      },{signal});
    }
    if (item.kind === 'plugins' && item.editable) {
      const edit = text(actions,'button','Edit settings'); edit.type='button'; edit.addEventListener('click',async()=>{
        if (!active || actionsBlocked()) return;
        openPluginSettings(item,sourceRevision,edit);
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
    if (!snapshot || !Array.isArray(snapshot.items)) { inventoryCount.textContent='Current inventory unavailable.'; emptyState.hidden=true; noMatch.hidden=true; syncControls(); return; }
    const sourceRevision=snapshot.revision, query=search.value.trim().toLowerCase(), kind=kindFilter.value;
    const matches=snapshot.items.filter(item=>(kind==='all'||item.kind===kind)
      && (!query || [item.label,item.name,item.kind,item.source,item.originLabel,item.category,item.state,item.version,item.transport]
        .some(value=>typeof value==='string'&&value.toLowerCase().includes(query))));
    inventoryCount.textContent=`Showing ${matches.length} of ${snapshot.items.length} current native extension records.`;
    emptyState.hidden=snapshot.items.length!==0; noMatch.hidden=snapshot.items.length===0||matches.length!==0;
    for (const item of matches) list.append(card(item,sourceRevision));
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
      const previousRevision=snapshot && snapshot.revision;
      snapshot=data;
      if (previousRevision && previousRevision!==data.revision) { selectedSkillId=null; selectedSkillEpoch+=1; }
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
        snapshot=null; recoveryRequired=true; list.replaceChildren(); inventoryCount.textContent='Current inventory unavailable.'; emptyState.hidden=true; noMatch.hidden=true;
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
  search.addEventListener('input',render,{signal}); kindFilter.addEventListener('change',render,{signal});
  refresh.addEventListener('click',()=>load({explicit:true}),{signal}); void load();
  return ()=>{active=false;for(const dialog of editors){if(dialog.open)dialog.close();dialog.remove();}lifecycle.abort();editors.clear();list.replaceChildren();};
}'''.splitlines())

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
