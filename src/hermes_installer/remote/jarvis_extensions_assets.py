"""Owner Extensions view: catalog setup and direct edits through finite owner routes."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


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
  <p class="extensions-note">“Hermes” identifies a built-in plugin. Bundled Resources and owner-added items show their observed source. Skill editing/removal and custom MCP connection edits are unavailable in the pinned Hermes API.</p>
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
@media(max-width:600px){[data-feature-root="extensions"] .extensions-head{flex-direction:column}[data-feature-root="extensions"] .extensions-head button{width:100%}}'''

_MOUNT = r'''function mount(container, api) {
  const root = container.querySelector('[data-feature-root="extensions"]') || container;
  const list = root.querySelector('[data-extension-list]'), status = root.querySelector('[data-extension-status]');
  const refresh = root.querySelector('[data-extension-refresh]');
  let active = true, snapshot = null, busy = false;
  const text = (parent, tag, value) => { const node = document.createElement(tag); node.textContent = String(value ?? 'Unknown'); parent.append(node); return node; };
  const makeKey = () => { const bytes = new Uint8Array(24); crypto.getRandomValues(bytes); return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,''); };
  function exactConfirm(phrase) { return window.prompt(`Type ${phrase} to confirm this owner action.`) === phrase; }
  async function mutate(path, body, phrase) {
    if (!exactConfirm(phrase)) return;
    busy = true; status.textContent = 'Applying the confirmed owner action…';
    try { const result = await api.post(path, {...body, confirmation:phrase, idempotency_key:makeKey(), revision:snapshot.revision});
      status.textContent = result && result.status === 'applied' ? 'Owner action applied; refreshing observed state.' : 'The action may still be pending. Refresh to check current state.';
    } catch (_) { status.textContent = 'The action was not confirmed. Refresh to see the current native state.'; }
    finally { busy = false; await load(); }
  }
  function card(item) {
    const box = document.createElement('article'); box.className='extension-card';
    text(box,'h3',item.label); text(box,'p',`${item.kind} · ${item.source}`);
    const detail = item.kind === 'plugins' ? `${item.state || 'status unknown'} · ${item.version || 'version unknown'}`
      : item.kind === 'mcps' ? `${item.transport} · ${item.enabled ? 'enabled' : 'disabled'}` : item.category;
    text(box,'p',detail);
    if (item.updateAvailable === true) text(box,'p','A catalog update is available; review remains required.');
    const actions = document.createElement('div'); actions.className='extension-actions';
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
        if (Object.keys(values).length) await mutate('/chat/api/extensions/plugins/edit',{item_id:item.id,values},`EDIT ${item.label}`);
      });
      if (item.source==='useradded') { const toggle = text(actions,'button',item.state==='enabled'?'Disable':'Enable'); toggle.type='button'; toggle.addEventListener('click',()=>{
        const enabled = item.state!=='enabled'; const phrase=`${enabled?'ENABLE':'DISABLE'} ${item.label}`;
        void mutate('/chat/api/extensions/plugins/toggle',{item_id:item.id,enabled},phrase);
      }); }
    }
    if (item.kind==='plugins' && item.removable && item.source==='useradded') {
      const remove=text(actions,'button','Remove permanently'); remove.type='button'; remove.addEventListener('click',()=>{
        const warning=`Permanently remove ${item.label} from this Hermes profile? This deletes its plugin package and registration and cannot be undone from this dashboard. It does not target your Obsidian vault.`;
        if (!window.confirm(warning)) return;
        void mutate('/chat/api/extensions/plugins/remove',{item_id:item.id},`DELETE PERMANENTLY ${item.label}`);
      });
    }
    if (item.kind==='mcps' && item.removable) { const remove=text(actions,'button','Remove server'); remove.type='button'; remove.addEventListener('click',()=>{
      const kind=item.kind; void mutate(`/chat/api/extensions/${kind}/remove`,{item_id:item.id},`DELETE ${item.label}`);
    }); }
    box.append(actions); return box;
  }
  function render() { list.replaceChildren(); if (!snapshot || !Array.isArray(snapshot.items)) return;
    for (const item of snapshot.items) list.append(card(item));
  }
  async function load() { if (!active || busy) return; refresh.disabled=true; status.textContent='Reading current Hermes inventory…';
    try { const data=await api.get('/chat/api/extensions'); if (!data || data.schema!==1 || !Array.isArray(data.items) || typeof data.revision!=='string') throw Error();
      snapshot=data; render(); status.textContent=`${data.items.length} current extension records · ${data.readiness}.`;
    } catch (_) { snapshot=null; list.replaceChildren(); status.textContent='Current extension inventory is unavailable.'; }
    finally { if(active) refresh.disabled=false; }
  }
  function bind(formSelector, path, key, endpoint, verb) { const form=root.querySelector(formSelector); form.addEventListener('submit',async(event)=>{
    event.preventDefault(); if(!snapshot||busy)return; const value=new FormData(form).get(key); if(typeof value!=='string'||!value.trim())return;
    const phrase=`${verb} ${value.trim()}`; const body={[key]:value.trim()}; await mutate(path,body,phrase); form.reset();
  }); }
  bind('[data-add-skill]','/chat/api/extensions/skills/add','identifier','identifier','ADD');
  bind('[data-add-plugin]','/chat/api/extensions/plugins/add','catalog_name','catalog_name','ADD');
  bind('[data-add-mcp]','/chat/api/extensions/mcps/add','catalog_name','catalog_name','ADD');
  refresh.addEventListener('click',load); void load();
  return ()=>{active=false;refresh.removeEventListener('click',load);list.replaceChildren();};
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
