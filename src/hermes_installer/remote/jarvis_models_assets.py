"""Static Models settings view backed only by the sanitized settings API."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW_HTML = '''
<section class="models-settings-card" aria-labelledby="models-settings-title">
  <h2 id="models-settings-title">Models</h2>
  <p class="muted" data-models-status role="status" aria-live="polite">Waiting for a current settings snapshot.</p>
  <dl class="models-settings-values">
    <div><dt>Configured provider</dt><dd data-models-provider>Pending verification</dd></div>
    <div><dt>Configured model</dt><dd data-models-model>Pending verification</dd></div>
    <div><dt>Account authentication</dt><dd data-models-account>Unknown</dd></div>
  </dl>
  <section class="models-selection-draft" aria-labelledby="models-draft-title">
    <h3 id="models-draft-title">Selection draft</h3>
    <p class="muted" data-models-catalog>The native provider/model catalog is unavailable.</p>
    <label for="models-provider-draft">Provider</label>
    <select id="models-provider-draft" disabled aria-describedby="models-catalog-help"><option>Unavailable</option></select>
    <label for="models-model-draft">Model</label>
    <select id="models-model-draft" disabled aria-describedby="models-catalog-help"><option>Unavailable</option></select>
    <p id="models-catalog-help" class="muted">Choices and authenticated readiness require current native metadata. No configuration has been changed.</p>
  </section>
  <p class="muted models-settings-note">Configured labels do not establish account authentication, model availability, route eligibility, or successful inference.</p>
</section>
'''

_CSS = '''.models-settings-card{max-width:900px;margin:0 auto}.models-settings-card>h2{margin:0}.models-settings-values{margin:15px 0 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:28px}.models-settings-values>div{display:flex;justify-content:space-between;gap:14px;padding:11px 0;border-bottom:1px solid var(--line)}.models-settings-values dt{color:#8ba5aa;font-size:12px}.models-settings-values dd{margin:0;text-align:right;color:#e1f4f5;font-size:12px;overflow-wrap:anywhere}.models-selection-draft{display:grid;grid-template-columns:120px minmax(0,1fr);align-items:center;gap:10px 14px;margin-top:20px;padding:16px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.48)}.models-selection-draft h3,.models-selection-draft p{grid-column:1/-1;margin:0}.models-selection-draft h3{font-size:13px;color:#d5edef}.models-selection-draft label{font-size:12px;color:#8ba5aa}.models-selection-draft select{min-height:38px;width:100%;border:1px solid var(--line);border-radius:8px;background:#101e24;color:#91aaae;padding:7px 10px}.models-settings-note{max-width:760px;margin:14px 0 0;font-size:11px}@media(max-width:640px){.models-settings-values{grid-template-columns:1fr}.models-selection-draft{grid-template-columns:1fr}.models-selection-draft h3,.models-selection-draft p{grid-column:1}}
'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true;
  const put = (selector, text) => { const node = root.querySelector(selector); if (node) node.textContent = text; };
  const configured = (row) => row && row.status === "configured-unverified"
    && typeof row.value === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,159}$/.test(row.value)
    && !row.value.includes("://") && !row.value.includes("\\") && !row.value.startsWith("/")
    ? `${row.value} · configured, unverified` : "Pending verification";
  async function refresh() {
    try {
      const data = await api.get("/chat/api/settings");
      if (!active) return;
      if (!data || data.readiness !== "pending" || !data.provider || !data.model || !data.accountState)
        throw new Error("settings snapshot incomplete");
      put("[data-models-provider]", configured(data.provider));
      put("[data-models-model]", configured(data.model));
      put("[data-models-account]", data.accountState.value === "unknown" ? "Unknown" : "Pending verification");
      put("[data-models-status]", "Current effective settings are available as sanitized labels.");
      put("[data-models-catalog]", "Native provider/model catalog unavailable; selection remains a draft-only placeholder.");
    } catch (_) {
      if (active) {
        put("[data-models-status]", "Current model settings are unavailable.");
        put("[data-models-provider]", "Pending verification");
        put("[data-models-model]", "Pending verification");
        put("[data-models-account]", "Unknown");
      }
    }
  }
  void refresh();
  return () => { active = false; };
}'''

_UNMOUNT_JS = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="models-settings",
    nav_label="Models",
    title="Models",
    view_html=_VIEW_HTML,
    css=_CSS,
    api_routes=(("GET", "/chat/api/settings"),),
    mount_js=_MOUNT_JS,
    unmount_js=_UNMOUNT_JS,
)
