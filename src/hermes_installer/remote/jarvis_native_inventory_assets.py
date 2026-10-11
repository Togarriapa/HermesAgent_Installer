"""Static Tools & Skills view for source-bound native capability inventory."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW_HTML = '''
<section class="data-card native-inventory-card" aria-labelledby="native-inventory-title">
  <h2 id="native-inventory-title">Native tools &amp; skills</h2>
  <p class="muted">Browse names discovered by the current Hermes process. This read-only view does not enable or install anything.</p>
  <div class="native-inventory-actions">
    <label for="native-inventory-search">Filter tools and skills</label>
    <input id="native-inventory-search" type="search" autocomplete="off" spellcheck="false" placeholder="Search names or groups">
    <button type="button" data-inventory-refresh>Refresh inventory</button>
  </div>
  <p class="muted" data-inventory-status role="status" aria-live="polite">Waiting for a current native inventory.</p>
  <section class="native-inventory-section" aria-labelledby="native-toolsets-title">
    <h3 id="native-toolsets-title">Toolsets and tool names</h3>
    <p class="muted" data-toolsets-state>Toolset inventory unavailable.</p>
    <div class="native-inventory-groups" data-toolsets></div>
  </section>
  <section class="native-inventory-section" aria-labelledby="native-skills-title">
    <h3 id="native-skills-title">Discovered skills</h3>
    <p class="muted" data-skills-state>Skill discovery unavailable.</p>
    <div class="native-inventory-groups" data-skills></div>
  </section>
  <p class="muted native-inventory-note">Toolset selection is configuration metadata, not proof that every tool is available or functional. Skills are discovered names only; their contents, file paths, activation and use are not shown.</p>
</section>
'''

_CSS = '''.native-inventory-card{max-width:1080px;margin:0 auto}.native-inventory-card>h2{margin:0}.native-inventory-actions{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 12px;align-items:center;margin:16px 0}.native-inventory-actions label{grid-column:1/-1;color:#8ba5aa;font-size:12px}.native-inventory-actions input{min-width:0;width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:9px;background:#0c1f26;color:#e1f4f5;font:inherit}.native-inventory-actions input:focus-visible,.native-inventory-actions button:focus-visible,.native-inventory-groups summary:focus-visible{outline:2px solid #69e5e7;outline-offset:2px}.native-inventory-actions button{min-height:40px;padding:9px 12px;white-space:nowrap;border:1px solid var(--line-strong);border-radius:9px;background:rgba(25,128,139,.13);color:#dcfbfc;font:inherit;font-size:12px;cursor:pointer}.native-inventory-actions button:hover:not(:disabled){background:rgba(23,142,153,.22);border-color:rgba(88,228,235,.62)}.native-inventory-actions button:disabled{opacity:.6;cursor:wait}.native-inventory-section{margin-top:22px}.native-inventory-section h3{margin:0;color:#d5edef;font-size:13px;font-weight:600}.native-inventory-groups{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:10px}.native-inventory-group{min-width:0;border:1px solid var(--line);border-radius:10px;background:rgba(12,31,38,.48)}.native-inventory-group summary{padding:12px;color:#e1f4f5;cursor:pointer;font-size:12px;overflow-wrap:anywhere}.native-inventory-group[open] summary{border-bottom:1px solid var(--line)}.native-inventory-members{display:flex;flex-wrap:wrap;gap:6px;margin:0;padding:11px 12px;list-style:none}.native-inventory-member{max-width:100%;padding:4px 7px;border:1px solid rgba(125,167,175,.22);border-radius:6px;color:#acc4c8;font-size:11px;overflow-wrap:anywhere}.native-inventory-note{max-width:850px;margin-top:18px;font-size:11px}@media(max-width:760px){.native-inventory-actions{grid-template-columns:1fr}.native-inventory-actions label{grid-column:auto}.native-inventory-actions button{justify-self:start}.native-inventory-groups{grid-template-columns:1fr}}'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true;
  let latest = null;
  const search = root.querySelector("#native-inventory-search");
  const refreshButton = root.querySelector("[data-inventory-refresh]");
  const setText = (selector, value) => { const node = root.querySelector(selector); if (node) node.textContent = value; };
  const safeToolset = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}$/.test(value) && !value.includes("://") && !value.includes("\\");
  const safeTool = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/.test(value) && !value.includes("://") && !value.includes("\\");
  const safeCategory = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(value);
  const safeSkill = (value) => typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$/.test(value);
  function group(container, name, items, label, filter, matcher) {
    const details = document.createElement("details"); details.className = "native-inventory-group";
    const summary = document.createElement("summary"); summary.textContent = label; details.append(summary);
    const normalized = filter.toLowerCase();
    const matches = items.filter((item) => matcher(item).toLowerCase().includes(normalized));
    const nameMatches = name.toLowerCase().includes(normalized);
    if (!normalized) return { details, items };
    if (!nameMatches && !matches.length) return null;
    if (matches.length || !nameMatches) {
      const list = document.createElement("ul"); list.className = "native-inventory-members";
      for (const item of (nameMatches ? items : matches)) {
        const row = document.createElement("li"); row.className = "native-inventory-member"; row.textContent = matcher(item); list.append(row);
      }
      details.append(list); details.open = true;
    }
    return { details, items };
  }
  function renderGroups(selector, rows, filter) {
    const container = root.querySelector(selector);
    if (!container) return;
    container.replaceChildren();
    if (!rows.length) return;
    for (const row of rows) {
      const built = group(container, row.name, row.items, row.label, filter, (item) => item);
      if (!built) continue;
      const { details, items } = built;
      details.addEventListener("toggle", () => {
        if (!active || !details.open || details.querySelector(".native-inventory-members")) return;
        const list = document.createElement("ul"); list.className = "native-inventory-members";
        for (const item of items) {
          const member = document.createElement("li"); member.className = "native-inventory-member"; member.textContent = item; list.append(member);
        }
        details.append(list);
      });
      container.append(details);
    }
  }
  function render() {
    if (!latest) return;
    const filter = search ? search.value.trim() : "";
    const toolRows = latest.tools.items.map((item) => {
      const selection = item.selection === true ? "selection reported" : item.selection === false ? "not selected" : "selection ambiguous";
      return { name: item.name, items: item.tools, label: `${item.name} · ${item.toolCount} tools · ${selection}` };
    });
    renderGroups("[data-toolsets]", toolRows, filter);
    const skillRows = latest.skills.categories.map((category) => ({
      name: category.name, items: category.skills, label: `${category.name} · ${category.skills.length} discovered`,
    }));
    renderGroups("[data-skills]", skillRows, filter);
  }
  function validTools(value) {
    if (!value || value.state !== "observed" || !["reported", "ambiguous"].includes(value.selectionState)
        || !Array.isArray(value.items) || value.items.length < 1 || value.items.length > 256) return false;
    let total = 0;
    let anyNotSelected = false;
    const valid = value.items.every((row) => {
      if (!row || !safeToolset(row.name) || ![true, false, null].includes(row.selection)
          || !Number.isInteger(row.toolCount) || row.toolCount < 0 || row.toolCount > 512
          || !Array.isArray(row.tools) || row.tools.length !== row.toolCount || !row.tools.every(safeTool)) return false;
      if (row.selection === false) anyNotSelected = true;
      total += row.tools.length;
      return total <= 8000;
    });
    if (!valid) return false;
    return value.selectionState === "reported"
      ? anyNotSelected && value.items.every((row) => row.selection !== null)
      : value.items.every((row) => row.selection === null);
  }
  function validSkills(value) {
    if (!value || value.state !== "discovered" || !Array.isArray(value.categories)
        || value.categories.length < 1 || value.categories.length > 128
        || !Number.isInteger(value.count) || value.count < 1 || value.count > 4000) return false;
    let total = 0;
    const valid = value.categories.every((row) => {
      if (!row || !safeCategory(row.name) || !Array.isArray(row.skills)
          || row.skills.length < 1 || row.skills.length > 512 || !row.skills.every(safeSkill)) return false;
      total += row.skills.length;
      return total <= 4000;
    });
    return valid && total === value.count;
  }
  async function refresh() {
    if (!active || !refreshButton) return;
    refreshButton.disabled = true;
    refreshButton.setAttribute("aria-busy", "true");
    setText("[data-inventory-status]", "Reading the current native inventory…");
    try {
      const data = await api.get("/chat/api/native-capabilities");
      if (!active) return;
      if (!data || data.schema !== 1) throw new Error("inventory schema mismatch");
      latest = data;
      const toolsOk = validTools(data.tools);
      const skillsOk = validSkills(data.skills);
      if (!toolsOk) setText("[data-toolsets-state]", "Native toolset inventory is unknown or unavailable.");
      else if (data.tools.selectionState === "ambiguous") setText("[data-toolsets-state]", "Toolset names were observed. The native selection flags are ambiguous when every row is marked selected; tool readiness is not checked.");
      else setText("[data-toolsets-state]", "Toolset names and configured selection flags were observed from the current core. Selection does not prove tool availability or successful use.");
      if (!skillsOk) setText("[data-skills-state]", "Skill discovery is unknown or unavailable.");
      else setText("[data-skills-state]", `${data.skills.count} skill names were discovered for the current core profile. This does not prove they are loaded in a chat.`);
      if (!toolsOk) latest.tools.items = [];
      if (!skillsOk) latest.skills.categories = [];
      render();
      setText("[data-inventory-status]", "Inventory refreshed from the current authenticated core generation.");
    } catch (_) {
      if (active) {
        latest = null;
        root.querySelector("[data-toolsets]")?.replaceChildren();
        root.querySelector("[data-skills]")?.replaceChildren();
        setText("[data-toolsets-state]", "Native toolset inventory is unknown or unavailable.");
        setText("[data-skills-state]", "Skill discovery is unknown or unavailable.");
        setText("[data-inventory-status]", "Current native inventory is unavailable.");
      }
    } finally {
      if (active) { refreshButton.disabled = false; refreshButton.removeAttribute("aria-busy"); }
    }
  }
  const onSearch = () => render();
  if (search) search.addEventListener("input", onSearch);
  if (refreshButton) refreshButton.addEventListener("click", refresh);
  void refresh();
  return () => {
    active = false;
    if (search) search.removeEventListener("input", onSearch);
    if (refreshButton) refreshButton.removeEventListener("click", refresh);
    root.querySelector("[data-toolsets]")?.replaceChildren();
    root.querySelector("[data-skills]")?.replaceChildren();
  };
}'''

_UNMOUNT_JS = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="native-inventory",
    nav_label="Tools & Skills",
    title="Native tools & skills",
    view_html=_VIEW_HTML,
    css=_CSS,
    api_routes=(("GET", "/chat/api/native-capabilities"),),
    mount_js=_MOUNT_JS,
    unmount_js=_UNMOUNT_JS,
)
