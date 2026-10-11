"""Static native-settings feature contribution for the shared Jarvis shell registry."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW_HTML = '''
<section class="data-card native-controls-card" aria-labelledby="native-controls-title">
  <h2 id="native-controls-title">Native integrations</h2>
  <p class="muted" data-native-status role="status" aria-live="polite">Waiting for a current status snapshot.</p>
  <dl class="native-config-list">
    <div><dt>Configured provider</dt><dd data-provider>Pending verification</dd></div>
    <div><dt>Configured model</dt><dd data-model>Pending verification</dd></div>
    <div><dt>Account authentication</dt><dd data-account>Unknown</dd></div>
    <div><dt>Core version</dt><dd data-core>Pending verification</dd></div>
  </dl>
  <p class="muted">Configured labels do not verify account authentication or the route used for a response.</p>
  <div class="native-controls-grid">
    <section class="native-controls-group" aria-labelledby="native-plugin-title">
      <h3 id="native-plugin-title">Loaded plugins</h3>
      <p class="muted" data-plugin-state>Status unavailable.</p>
      <ul class="native-controls-list" data-plugin-list></ul>
    </section>
    <section class="native-controls-group" aria-labelledby="native-mcp-title">
      <h3 id="native-mcp-title">MCP server status</h3>
      <p class="muted" data-mcp-state>Status unavailable.</p>
      <ul class="native-controls-list" data-mcp-list></ul>
    </section>
  </div>
  <p class="muted native-controls-note">These are read-only process observations. Empty or unavailable plugin state does not establish that no plugins are installed; MCP connection state does not prove a tool call will succeed.</p>
</section>
'''

_CSS = '''.native-controls-card{max-width:1080px;margin:0 auto}.native-controls-card>h2{margin:0}.native-config-list{margin:15px 0 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:28px}.native-config-list>div{display:flex;justify-content:space-between;gap:14px;padding:11px 0;border-bottom:1px solid var(--line)}.native-config-list dt{color:#8ba5aa;font-size:12px}.native-config-list dd{margin:0;text-align:right;color:#e1f4f5;font-size:12px;overflow-wrap:anywhere}.native-controls-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin-top:18px}.native-controls-group{min-width:0;padding:16px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.48)}.native-controls-group h3{margin:0;color:#d5edef;font-size:12px;font-weight:600}.native-controls-list{display:grid;gap:8px;margin:12px 0 0;padding:0;list-style:none}.native-controls-list:empty{display:none}.native-control-row{display:flex;justify-content:space-between;gap:14px;padding:10px 0;border-bottom:1px solid var(--line);font-size:12px}.native-control-row:last-child{border-bottom:0}.native-control-name{min-width:0;overflow-wrap:anywhere;color:#e1f4f5}.native-control-detail{flex:none;color:#91aaae;text-align:right}.native-controls-note{max-width:820px;margin:14px 0 0;font-size:11px}@media(max-width:760px){.native-config-list,.native-controls-grid{grid-template-columns:1fr}.native-controls-group{padding:14px}.native-control-row{gap:8px}}'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true;
  const query = (selector) => root.querySelector(selector);
  const put = (selector, value) => { const node = query(selector); if (node) node.textContent = value; };
  const clear = (selector) => { const node = query(selector); if (node) node.replaceChildren(); };
  const addRow = (selector, label, detail) => {
    const list = query(selector);
    if (!list) return;
    const item = document.createElement("li"); item.className = "native-control-row";
    const name = document.createElement("span"); name.className = "native-control-name"; name.textContent = label;
    const state = document.createElement("span"); state.className = "native-control-detail"; state.textContent = detail;
    item.append(name, state); list.append(item);
  };
  const validLabel = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._ -]{0,79}$/.test(value);
  const validSetting = (value, status) => value && value.status === status && typeof value.value === "string"
    ? value.value : "Pending verification";
  async function refresh() {
    try {
      const data = await api.get("/chat/api/settings");
      if (!active) return;
      if (!data || data.readiness !== "pending" || !data.plugins || !data.mcp) throw new Error("settings snapshot incomplete");
      put("[data-provider]", data.provider && data.provider.status === "configured-unverified"
        ? `${validSetting(data.provider, "configured-unverified")} · configured, unverified` : "Pending verification");
      put("[data-model]", data.model && data.model.status === "configured-unverified"
        ? `${validSetting(data.model, "configured-unverified")} · configured, unverified` : "Pending verification");
      put("[data-core]", validSetting(data.coreVersion, "verified"));
      put("[data-account]", data.accountState && data.accountState.value === "unknown" ? "Unknown" : "Pending verification");
      put("[data-native-status]", "Read-only status from the current authenticated core generation.");
      clear("[data-plugin-list]"); clear("[data-mcp-list]");
      if (data.plugins.state === "observed" && Array.isArray(data.plugins.items) && data.plugins.items.length <= 64 && data.plugins.items.length) {
        put("[data-plugin-state]", "Loaded plugin records reported by the current process.");
        for (const item of data.plugins.items) {
          if (!item || !validLabel(item.label) || typeof item.enabled !== "boolean" || typeof item.loaded !== "boolean") continue;
          const version = typeof item.version === "string" && item.version.length <= 64 ? ` · ${item.version}` : "";
          addRow("[data-plugin-list]", item.label + version, `${item.loaded ? "loaded" : "not loaded"} · ${item.enabled ? "enabled" : "disabled"}`);
        }
        if (!query("[data-plugin-list]").childElementCount) put("[data-plugin-state]", "Plugin records were not available in a displayable form.");
      } else {
        put("[data-plugin-state]", "Plugin load state is unknown; an empty result does not mean none are installed.");
      }
      const transports = new Set(["http", "stdio", "unknown"]);
      const statuses = new Set(["connected", "disabled", "connecting", "failed", "lazy", "configured"]);
      if (data.mcp.state === "observed" && Array.isArray(data.mcp.servers) && data.mcp.servers.length <= 64 && typeof data.mcp.checkedAt === "string") {
        put("[data-mcp-state]", `Cached status observed ${data.mcp.checkedAt}.`);
        for (const item of data.mcp.servers) {
          if (!item || !validLabel(item.label) || !transports.has(item.transport)
              || (item.status !== null && !statuses.has(item.status))) continue;
          const parts = [item.status || "status unknown", item.transport];
          if (Number.isInteger(item.toolCount) && item.toolCount >= 0) parts.push(`${item.toolCount} tools`);
          if (item.connected === true) parts.push("connected");
          if (item.disabled === true) parts.push("disabled");
          addRow("[data-mcp-list]", item.label, parts.join(" · "));
        }
        if (!query("[data-mcp-list]").childElementCount) put("[data-mcp-state]", "No MCP servers were reported in the observed snapshot.");
      } else {
        put("[data-mcp-state]", "MCP status is unknown or unavailable.");
      }
    } catch (_) {
      if (active) put("[data-native-status]", "Current native settings are unavailable.");
    }
  }
  void refresh();
  return () => { active = false; clear("[data-plugin-list]"); clear("[data-mcp-list]"); };
}'''

_UNMOUNT_JS = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="native-controls",
    nav_label="Integrations",
    title="Native integrations",
    view_html=_VIEW_HTML,
    css=_CSS,
    api_routes=(("GET", "/chat/api/settings"),),
    mount_js=_MOUNT_JS,
    unmount_js=_UNMOUNT_JS,
)
