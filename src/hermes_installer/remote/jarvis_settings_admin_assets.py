"""Static Jarvis control for Hermes' persistent default reasoning effort."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW_HTML = '''
<section class="settings-admin-card" aria-labelledby="settings-admin-title">
  <h2 id="settings-admin-title">Agent settings</h2>
  <p class="muted" data-settings-status role="status" aria-live="polite">Loading native profile settings.</p>
  <div class="settings-admin-row" data-setting-id="agent.reasoning_effort">
    <div><h3>Default reasoning effort</h3><p>Sets Hermes’ profile default for future conversations.</p></div>
    <label for="settings-reasoning">Reasoning effort</label>
    <select id="settings-reasoning" data-settings-reasoning disabled>
      <option value="">Loading…</option>
      <option value="none">Off</option><option value="minimal">Minimal</option>
      <option value="low">Low</option><option value="medium">Medium</option>
      <option value="high">High</option><option value="xhigh">Extra high</option>
      <option value="max">Maximum</option><option value="ultra">Ultra</option>
    </select>
    <button type="button" data-settings-save disabled>Save default</button>
  </div>
  <div class="settings-admin-row" data-setting-id="display.busy_input_mode">
    <div><h3>When a native conversation is busy</h3><p>Choose how Hermes handles another message during an active native turn.</p></div>
    <label for="settings-busy-input">Busy input behavior</label>
    <select id="settings-busy-input" data-settings-busy disabled>
      <option value="">Loading…</option><option value="queue">Queue the message</option>
      <option value="steer">Steer the active turn</option><option value="interrupt">Interrupt the active turn</option>
    </select>
    <button type="button" data-settings-save-busy disabled>Save behavior</button>
  </div>
  <p class="muted settings-admin-note" data-settings-note>The selected value is read from Hermes’ native profile config. Provider and model support can vary; this setting does not prove a later request used that effort.</p>
  <p class="muted settings-admin-note">Busy input behavior applies to native Hermes conversations. Jarvis handles its own concurrent-message policy separately.</p>
</section>
'''

_CSS = '''.settings-admin-card{max-width:900px;margin:0 auto}.settings-admin-card>h2{margin:0}.settings-admin-row{display:grid;grid-template-columns:minmax(0,1fr) minmax(150px,220px) auto;align-items:center;gap:12px 18px;margin-top:18px;padding:18px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.48)}.settings-admin-row h3{margin:0;font-size:14px;color:#d5edef}.settings-admin-row p{margin:5px 0 0;color:#8ba5aa;font-size:12px}.settings-admin-row label{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}.settings-admin-row select,.settings-admin-row button{min-height:44px;border:1px solid var(--line);border-radius:8px;background:#101e24;color:#e1f4f5;padding:8px 12px}.settings-admin-row button{background:#245865;cursor:pointer}.settings-admin-row button:disabled,.settings-admin-row select:disabled{opacity:.55;cursor:not-allowed}.settings-admin-row :focus-visible{outline:2px solid #61c3d1;outline-offset:2px}.settings-admin-note{max-width:760px;margin:14px 0 0;font-size:11px}@media(max-width:640px){.settings-admin-row{grid-template-columns:1fr}.settings-admin-row label{position:static;width:auto;height:auto;margin:0;clip:auto;white-space:normal;color:#8ba5aa;font-size:12px}}'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true;
  let loading = false;
  let saving = false;
  let revision = null;
  let current = null;
  const select = root.querySelector("[data-settings-reasoning]");
  const save = root.querySelector("[data-settings-save]");
  const busySelect = root.querySelector("[data-settings-busy]");
  const saveBusy = root.querySelector("[data-settings-save-busy]");
  const status = root.querySelector("[data-settings-status]");
  const note = root.querySelector("[data-settings-note]");
  const allowed = new Set(["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"]);
  const allowedBusy = new Set(["queue", "steer", "interrupt"]);
  let busyRevision = null;
  let busyCurrent = null;
  let busyLoading = false;
  let busySaving = false;
  const show = (message) => { if (active) status.textContent = message; };
  const update = () => { save.disabled = loading || saving || !revision || !current || !allowed.has(select.value) || select.value === current; };
  const updateBusy = () => { saveBusy.disabled = busyLoading || busySaving || !busyRevision || !busyCurrent || !allowedBusy.has(busySelect.value) || busySelect.value === busyCurrent; };
  async function refresh() {
    loading = true; revision = null; current = null; select.disabled = true; update();
    show("Loading native profile settings.");
    try {
      const data = await api.get("/chat/api/settings/reasoning-effort");
      if (!active) return;
      if (!data || data.status !== "observed" || !data.setting || data.setting.id !== "agent.reasoning_effort"
          || !allowed.has(data.setting.value) || !Array.isArray(data.allowedValues)
          || data.allowedValues.length !== allowed.size || data.allowedValues.some((value) => !allowed.has(value))
          || data.applyScope !== "future-conversations" || typeof data.revision !== "string") throw new Error("invalid settings");
      current = data.setting.value; revision = data.revision;
      select.value = current; select.disabled = false;
      note.textContent = `Current native profile default: ${current}. Applies to future conversations; provider and model support can vary.`;
      show("Hermes’ native profile default is current.");
    } catch (_) {
      if (!active) return;
      select.disabled = true; revision = null; current = null;
      note.textContent = "Native settings are unavailable; no change was made.";
      show("Could not verify the native reasoning default.");
    } finally { loading = false; update(); }
  }
  async function saveDefault() {
    if (saving || !revision || !current || !allowed.has(select.value) || select.value === current) return;
    saving = true; update(); show("Saving the native profile default.");
    const chosen = select.value;
    try {
      const result = await api.post("/chat/api/settings/reasoning-effort", {effort: chosen, revision});
      if (!active) return;
      if (!result || result.state !== "saved-for-profile" || result.effort !== chosen
          || result.applyScope !== "future-conversations") throw new Error("unverified result");
      show(`Hermes saved ${chosen} as the default for future conversations.`);
      await refresh();
    } catch (_) {
      if (!active) return;
      revision = null; update();
      show("The native result is unknown. Refresh settings before trying again.");
    } finally { saving = false; update(); }
  }
  async function refreshBusy() {
    busyLoading = true; busyRevision = null; busyCurrent = null; busySelect.disabled = true; updateBusy();
    try {
      const data = await api.get("/chat/api/settings/busy-input");
      if (!active) return;
      if (!data || data.status !== "observed" || !data.setting || data.setting.id !== "display.busy_input_mode"
          || !allowedBusy.has(data.setting.value) || !Array.isArray(data.allowedValues)
          || data.allowedValues.length !== allowedBusy.size || data.allowedValues.some((value) => !allowedBusy.has(value))
          || data.applyScope !== "native-conversation-input" || typeof data.revision !== "string") throw new Error("invalid settings");
      busyCurrent = data.setting.value; busyRevision = data.revision;
      busySelect.value = busyCurrent; busySelect.disabled = false;
      show("Native Hermes busy-input behavior is current.");
    } catch (_) {
      if (!active) return;
      busySelect.disabled = true; busyRevision = null; busyCurrent = null;
      show("Native Hermes busy-input behavior is unavailable.");
    } finally { busyLoading = false; updateBusy(); }
  }
  async function saveBusyDefault() {
    if (busySaving || !busyRevision || !busyCurrent || !allowedBusy.has(busySelect.value) || busySelect.value === busyCurrent) return;
    busySaving = true; updateBusy(); show("Saving native busy-input behavior.");
    const chosen = busySelect.value;
    try {
      const result = await api.post("/chat/api/settings/busy-input", {mode: chosen, revision: busyRevision});
      if (!active) return;
      if (!result || result.state !== "saved-for-profile" || result.mode !== chosen
          || result.applyScope !== "native-conversation-input") throw new Error("unverified result");
      show(`Hermes saved ${chosen} as its native busy-input behavior.`);
      await refreshBusy();
    } catch (_) {
      if (!active) return;
      busyRevision = null; updateBusy();
      show("The native result is unknown. Refresh settings before trying again.");
    } finally { busySaving = false; updateBusy(); }
  }
  select.addEventListener("change", update);
  busySelect.addEventListener("change", updateBusy);
  save.addEventListener("click", saveDefault);
  saveBusy.addEventListener("click", saveBusyDefault);
  void Promise.all([refresh(), refreshBusy()]);
  return () => { active = false; select.removeEventListener("change", update); busySelect.removeEventListener("change", updateBusy); save.removeEventListener("click", saveDefault); saveBusy.removeEventListener("click", saveBusyDefault); };
}'''

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="settings-admin",
    nav_label="Agent settings",
    title="Agent settings",
    view_html=_VIEW_HTML,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/settings/reasoning-effort"),
        ("POST", "/chat/api/settings/reasoning-effort"),
        ("GET", "/chat/api/settings/busy-input"),
        ("POST", "/chat/api/settings/busy-input"),
    ),
    mount_js=_MOUNT_JS,
    unmount_js="function unmount() {}",
)
