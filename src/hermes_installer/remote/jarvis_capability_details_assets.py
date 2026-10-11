"""Static embedded detail fragment for Jarvis' existing Capabilities panel.

This fragment consumes only the already protected capability, native inventory,
and native learning GET projections. The parent shell owns composition and passes
its fixed-route read function to ``mount``; this module defines no new endpoint.
"""
from __future__ import annotations


VIEW_HTML = '''
<section class="capability-workspace" aria-labelledby="capability-workspace-title">
  <div class="capability-workspace-heading">
    <div><p class="capability-workspace-kicker">SOURCE AND RUNTIME DETAILS</p>
      <h2 id="capability-workspace-title">Capability details</h2>
      <p>Search bundled declarations alongside names seen by the current Hermes process. Each badge states what its source proves.</p>
    </div>
    <button type="button" data-capability-refresh>Refresh details</button>
  </div>
  <div class="capability-workspace-controls">
    <label for="capability-workspace-search">Find a skill, tool, or profile</label>
    <input id="capability-workspace-search" type="search" autocomplete="off" spellcheck="false" placeholder="Search by name, ID, or group">
    <label for="capability-workspace-kind">Source</label>
    <select id="capability-workspace-kind">
      <option value="all">All sources</option><option value="catalog">Bundled catalog</option>
      <option value="native-tools">Current tool inventory</option><option value="native-skills">Current skill discovery</option>
    </select>
  </div>
  <p class="capability-workspace-status" data-capability-status role="status" aria-live="polite">Loading source-bound details…</p>
  <div class="capability-workspace-layout">
    <section aria-labelledby="capability-results-title">
      <h3 id="capability-results-title">Matching entries</h3>
      <p class="capability-workspace-count" data-capability-count></p>
      <ol class="capability-workspace-results" data-capability-results></ol>
    </section>
    <section class="capability-workspace-detail" aria-labelledby="capability-detail-title" aria-live="polite">
      <h3 id="capability-detail-title">Select an entry</h3>
      <p class="capability-workspace-muted">Descriptions, dependencies, activation, and use are shown only when the current source provides evidence for them.</p>
      <dl data-capability-detail></dl>
    </section>
  </div>
  <section class="capability-learning" aria-labelledby="capability-learning-title">
    <div class="capability-learning-heading"><div><h3 id="capability-learning-title">Native skill review</h3>
      <p class="capability-workspace-muted">Owner-only snapshot of pending native proposals. This view is read-only; approval stays in the owner Hermes conversation.</p>
    </div><button type="button" data-learning-refresh>Refresh review queue</button></div>
    <p data-learning-status role="status" aria-live="polite">Waiting for an owner review snapshot.</p>
    <ol class="capability-learning-list" data-learning-candidates></ol>
    <p class="capability-workspace-muted" data-learning-next></p>
  </section>
</section>
'''


CSS = '''
.capability-workspace{max-width:1080px;margin:28px auto 0;padding-top:24px;border-top:1px solid var(--line)}
.capability-workspace-heading,.capability-learning-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px}
.capability-workspace-kicker{margin:0 0 7px;color:#7dabb3;font-size:9px;font-weight:700;letter-spacing:.17em}
.capability-workspace-heading h2,.capability-learning h3{margin:0;color:#d8eff1;font-size:17px;font-weight:580}
.capability-workspace-heading p:not(.capability-workspace-kicker),.capability-workspace-muted{max-width:720px;color:#8ba5aa;font-size:12px;line-height:1.6}
.capability-workspace-heading button,.capability-learning-heading button{flex:none;min-height:38px;padding:8px 12px;border:1px solid var(--line-strong);border-radius:9px;background:rgba(25,128,139,.13);color:#dcfbfc;font:inherit;font-size:11px;cursor:pointer}
.capability-workspace-heading button:hover,.capability-learning-heading button:hover{background:rgba(23,142,153,.22)}
.capability-workspace-controls{display:grid;grid-template-columns:auto minmax(180px,1fr) auto minmax(150px,.45fr);align-items:center;gap:8px 12px;margin:16px 0}
.capability-workspace-controls label{color:#9eb5b9;font-size:11px}.capability-workspace-controls input,.capability-workspace-controls select{min-width:0;min-height:39px;padding:8px 10px;border:1px solid var(--line-strong);border-radius:8px;background:#0c1f26;color:var(--text);font:inherit;font-size:12px}
.capability-workspace-controls :focus-visible,.capability-workspace-heading button:focus-visible,.capability-learning-heading button:focus-visible,.capability-workspace-results button:focus-visible,.capability-learning-list summary:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.capability-workspace-status,.capability-workspace-count{color:#8ba5aa;font-size:11px}.capability-workspace-layout{display:grid;grid-template-columns:minmax(0,1.1fr) minmax(260px,.9fr);gap:14px;align-items:start}
.capability-workspace-layout h3{margin:0 0 9px;color:#cde5e8;font-size:12px;font-weight:600}.capability-workspace-results,.capability-learning-list{display:grid;gap:7px;margin:0;padding:0;list-style:none}
.capability-workspace-results button{width:100%;display:grid;gap:5px;padding:10px 11px;text-align:left;border:1px solid var(--line);border-radius:9px;background:rgba(12,31,38,.55);color:#d8eff1;cursor:pointer}
.capability-workspace-results button[aria-pressed="true"]{border-color:rgba(88,228,235,.48);background:rgba(25,128,139,.13)}
.capability-workspace-result-name{font-size:12px;font-weight:600;overflow-wrap:anywhere}.capability-workspace-result-meta{color:#90a9ad;font-size:10px;overflow-wrap:anywhere}
.capability-workspace-detail{min-width:0;padding:14px;border:1px solid var(--line);border-radius:11px;background:rgba(12,31,38,.5)}
.capability-workspace-detail dl{display:grid;gap:0;margin:12px 0 0}.capability-workspace-detail dl>div{display:grid;grid-template-columns:minmax(82px,.45fr) minmax(0,1fr);gap:12px;padding:9px 0;border-top:1px solid var(--line)}
.capability-workspace-detail dt{color:#8ba5aa;font-size:10px}.capability-workspace-detail dd{min-width:0;margin:0;color:#d2e7e9;font-size:11px;line-height:1.55;overflow-wrap:anywhere;white-space:pre-wrap}
.capability-workspace-badge{display:inline-block;width:max-content;max-width:100%;padding:3px 7px;border:1px solid var(--line-strong);border-radius:999px;color:#b9e8eb;font-size:10px}
.capability-learning{margin-top:24px;padding:17px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.42)}.capability-learning-heading{align-items:center}.capability-learning-heading h3{font-size:14px}.capability-learning-list{margin-top:12px}
.capability-learning-card{padding:12px;border:1px solid var(--line);border-radius:9px;background:rgba(7,19,25,.45)}.capability-learning-card h4{margin:0;color:#d8eff1;font-size:12px;font-weight:600}.capability-learning-meta{margin:7px 0;color:#8ba5aa;font-size:10px;line-height:1.55;overflow-wrap:anywhere}.capability-learning-card details summary{color:#c1dadd;font-size:11px;cursor:pointer}.capability-learning-diff{max-height:22rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;color:#c5d8da;font-size:10px;line-height:1.55}
@media(max-width:760px){.capability-workspace-heading,.capability-learning-heading{align-items:stretch;flex-direction:column}.capability-workspace-controls{grid-template-columns:1fr}.capability-workspace-layout{grid-template-columns:1fr}.capability-workspace-heading button,.capability-learning-heading button{align-self:flex-start}.capability-workspace-detail dl>div{grid-template-columns:90px minmax(0,1fr)}}
'''


MOUNT_JS = r'''function mount(root, read) {
  let active = true;
  let catalog = [];
  let nativeRows = [];
  let selectedKey = "";
  const search = root.querySelector("#capability-workspace-search");
  const source = root.querySelector("#capability-workspace-kind");
  const results = root.querySelector("[data-capability-results]");
  const detailTitle = root.querySelector("#capability-detail-title");
  const detail = root.querySelector("[data-capability-detail]");
  const status = root.querySelector("[data-capability-status]");
  const refreshButton = root.querySelector("[data-capability-refresh]");
  const learningButton = root.querySelector("[data-learning-refresh]");
  const learningStatus = root.querySelector("[data-learning-status]");
  const learningList = root.querySelector("[data-learning-candidates]");
  const learningNext = root.querySelector("[data-learning-next]");
  const text = (selector, value) => { const node = root.querySelector(selector); if (node) node.textContent = value; };
  const safeLabel = (value, limit = 160) => typeof value === "string" && value.length <= limit && !/[\x00-\x1f\x7f]/.test(value);
  const safeKind = (value) => ["bundles","channels","crons","mcps","plugins","profiles","skills","webhooks"].includes(value);
  function row(key, kind, name, origin, state, metadata, value) {
    return {key, kind, name, origin, state, metadata, value};
  }
  function addCatalogItems(data) {
    if (!data || data.readiness !== "pending" || !Array.isArray(data.items) || data.items.length !== 692
        || !data.source || data.source.kind !== "offline-bundle"
        || data.source.catalogVersion !== "2.3.1"
        || data.source.revision !== "113f42d33be9e0c8f0f47f5ca998e687323dec83") {
      throw new Error("catalog source is not the reviewed bounded bundle");
    }
    const counts = new Map();
    const seen = new Set();
    const rows = [];
    for (const item of data.items) {
      if (!item || !safeKind(item.kind) || !safeLabel(item.id, 120) || !safeLabel(item.name, 120)
          || !safeLabel(item.summary, 240) || item.state !== "bundled" || item.readiness !== "pending") {
        throw new Error("catalog item schema is invalid");
      }
      const key = `catalog:${item.kind}:${item.id}`;
      if (seen.has(key)) throw new Error("catalog item identity is duplicated");
      seen.add(key);
      counts.set(item.kind, (counts.get(item.kind) || 0) + 1);
      rows.push(row(key, item.kind, item.name, "Verified offline bundle", "Bundled · readiness pending",
        `Catalog ID: ${item.id}`, item));
    }
    catalog = rows;
    return {source: data.source, counts};
  }
  function addNativeItems(data) {
    const rows = [];
    let toolsetsObserved = null;
    let skillsDiscovered = null;
    if (data && data.schema === 1 && data.tools && data.tools.state === "observed"
        && ["reported","ambiguous"].includes(data.tools.selectionState)
        && Array.isArray(data.tools.items) && data.tools.items.length > 0 && data.tools.items.length <= 256) {
      let total = 0;
      let anyNotSelected = false;
      let valid = true;
      const toolRows = [];
      for (const set of data.tools.items) {
        if (!set || Object.keys(set).sort().join(",") !== "name,selection,toolCount,tools"
            || !safeLabel(set.name, 80) || !/^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,79}$/.test(set.name)
            || ![true, false, null].includes(set.selection)
            || !Number.isInteger(set.toolCount) || set.toolCount < 0 || set.toolCount > 512
            || !Array.isArray(set.tools) || set.tools.length !== set.toolCount) { valid = false; break; }
        anyNotSelected = anyNotSelected || set.selection === false;
        for (const tool of set.tools) {
          if (!safeLabel(tool, 120) || !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}$/.test(tool)) { valid = false; break; }
          total++;
          if (total > 8000) { valid = false; break; }
          const selection = set.selection === true ? "Selection reported" : set.selection === false ? "Not selected" : "Selection ambiguous";
          toolRows.push(row(`tool:${set.name}:${tool}`, "tool", tool, "Current native Core inventory",
            "Discovered name · operation unverified", `Toolset: ${set.name} · ${selection}`, {toolset:set.name,selection}));
        }
        if (!valid) break;
      }
      const selectionConsistent = data.tools.selectionState === "reported"
        ? anyNotSelected && data.tools.items.every((set) => set.selection !== null)
        : data.tools.items.every((set) => set.selection === null);
      if (valid && selectionConsistent) { rows.push(...toolRows); toolsetsObserved = data.tools.items.length; }
    }
    if (data && data.schema === 1 && data.skills && data.skills.state === "discovered"
        && Array.isArray(data.skills.categories) && data.skills.categories.length > 0 && data.skills.categories.length <= 128
        && Number.isInteger(data.skills.count) && data.skills.count > 0 && data.skills.count <= 4000) {
      let total = 0;
      let valid = true;
      const skillRows = [];
      for (const category of data.skills.categories) {
        if (!category || Object.keys(category).sort().join(",") !== "name,skills"
            || !safeLabel(category.name, 64) || !/^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/.test(category.name)
            || !Array.isArray(category.skills) || category.skills.length === 0 || category.skills.length > 512) { valid = false; break; }
        for (const skill of category.skills) {
          if (!safeLabel(skill, 100) || !/^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,99}$/.test(skill)) { valid = false; break; }
          total++;
          if (total > 4000) { valid = false; break; }
          skillRows.push(row(`native-skill:${category.name}:${skill}`, "skill", skill,
            "Current native Core discovery", "Discovered name · activation and use unverified",
            `Native category: ${category.name}`, {category:category.name}));
        }
        if (!valid) break;
      }
      if (valid && total === data.skills.count) { rows.push(...skillRows); skillsDiscovered = total; }
    }
    nativeRows = rows;
    return {toolsetsObserved, skillsDiscovered};
  }
  function detailEntry(label, value, badge = false) {
    const wrap = document.createElement("div");
    const term = document.createElement("dt"); term.textContent = label;
    const description = document.createElement("dd");
    if (badge) { const pill = document.createElement("span"); pill.className = "capability-workspace-badge"; pill.textContent = value; description.append(pill); }
    else description.textContent = value;
    wrap.append(term, description); detail.append(wrap);
  }
  function showDetail(item) {
    if (!item) return;
    selectedKey = item.key;
    detailTitle.textContent = item.name;
    detail.replaceChildren();
    detailEntry("Type", item.kind);
    detailEntry("Evidence", item.origin);
    detailEntry("State", item.state, true);
    detailEntry("Identity", item.metadata);
    if (item.value && item.value.id) {
      const value = item.value;
      detailEntry("Description", value.summary || "No description is present in this inventory projection.");
      detailEntry("Source revision", "Verified offline Hermes Resources bundle 2.3.1 · 113f42d33be9e0c8f0f47f5ca998e687323dec83");
      const deps = value.dependencies;
      if (Array.isArray(deps) && deps.length <= 64 && deps.every((dep) => safeLabel(dep, 160)))
        detailEntry("Declared dependencies", deps.length ? deps.join(" · ") : "The source declares no dependencies.");
      else detailEntry("Dependencies", "Not supplied by this bounded catalog projection; no dependency relationship is inferred.");
      if (value.kind === "profiles" && value.id !== "hermes")
        detailEntry("Profile access", "Internal profile declaration. It is not a family-selectable service.");
      detailEntry("Readiness", "Pending. Bundled presence does not prove discovery, enablement, or working behavior.");
      detailEntry("Available actions", "Enable, update, approval, and rollback adapters are unavailable in this view.");
    } else {
      detailEntry("Readiness", item.state);
      detailEntry("Dependencies", "Not reported by native discovery.");
      detailEntry("Description", "The current native inventory exposes names and limited selection metadata only.");
      detailEntry("Available actions", "This view cannot enable, configure, or invoke native tools or skills.");
    }
    render();
  }
  function render() {
    if (!active || !results) return;
    const query = search ? search.value.trim().toLocaleLowerCase() : "";
    const filter = source ? source.value : "all";
    const entries = filter === "catalog" ? catalog : filter === "native-tools" ? nativeRows.filter((item) => item.kind === "tool")
      : filter === "native-skills" ? nativeRows.filter((item) => item.kind === "skill") : [...catalog, ...nativeRows];
    const matched = entries.filter((item) => `${item.name} ${item.kind} ${item.metadata} ${item.origin}`.toLocaleLowerCase().includes(query));
    const visible = matched.slice(0, 100);
    results.replaceChildren();
    for (const item of visible) {
      const li = document.createElement("li"); const button = document.createElement("button");
      button.type = "button"; button.setAttribute("aria-pressed", String(item.key === selectedKey));
      const title = document.createElement("span"); title.className = "capability-workspace-result-name"; title.textContent = item.name;
      const meta = document.createElement("span"); meta.className = "capability-workspace-result-meta"; meta.textContent = `${item.kind} · ${item.state}`;
      button.append(title, meta); button.addEventListener("click", () => showDetail(item)); li.append(button); results.append(li);
    }
    text("[data-capability-count]", matched.length > visible.length ? `Showing ${visible.length} of ${matched.length} matches` : `${matched.length} matches`);
    if (selectedKey && !entries.some((item) => item.key === selectedKey)) { selectedKey = ""; detail.replaceChildren(); detailTitle.textContent = "Select an entry"; }
  }
  async function refreshCapabilities() {
    if (!active || !refreshButton) return;
    refreshButton.disabled = true; refreshButton.setAttribute("aria-busy", "true");
    text("[data-capability-status]", "Reading verified catalog and current native inventory…");
    try {
      const [bundleResult, nativeResult] = await Promise.allSettled([
        read.get("/chat/api/capabilities"), read.get("/chat/api/native-capabilities"),
      ]);
      if (!active) return;
      let catalogSource = "Catalog unavailable";
      let catalogError = false;
      if (bundleResult.status === "fulfilled") {
        try { const sourceInfo = addCatalogItems(bundleResult.value); catalogSource = `Catalog ${sourceInfo.source.catalogVersion} · ${catalog.length} declarations`; }
        catch (_) { catalogError = true; catalog = []; }
      } else { catalogError = true; catalog = []; }
      const nativeCounts = nativeResult.status === "fulfilled" ? addNativeItems(nativeResult.value) : {toolsetsObserved:null,skillsDiscovered:null};
      if (nativeResult.status !== "fulfilled") nativeRows = [];
      const toolsText = nativeCounts.toolsetsObserved === null ? "tool inventory unknown" : `${nativeCounts.toolsetsObserved} toolsets observed`;
      const skillsText = nativeCounts.skillsDiscovered === null ? "skill discovery unknown" : `${nativeCounts.skillsDiscovered} skill names discovered`;
      text("[data-capability-status]", `${catalogError ? "Catalog unavailable" : catalogSource}. Current Core: ${toolsText}; ${skillsText}.`);
      render();
    } catch (_) {
      if (active) text("[data-capability-status]", "One or more current sources are unavailable. Catalog, tool, and skill states remain unverified.");
    } finally {
      if (active) { refreshButton.disabled = false; refreshButton.removeAttribute("aria-busy"); }
    }
  }
  function validLearning(result) {
    if (!result || result.schema !== 1 || !["read-only-native-review","partial","unavailable"].includes(result.state)
        || !Array.isArray(result.pendingReasons) || result.pendingReasons.length > 16
        || !Array.isArray(result.candidates) || result.candidates.length > 64
        || result.canApply !== false || result.canRollback !== false) return false;
    return result.candidates.every((item) => item && /^[0-9a-f]{24}$/.test(item.id)
      && /^[0-9a-f]{64}$/.test(item.revisionSha256) && /^[0-9a-f]{64}$/.test(item.diffSha256)
      && ["create","edit","patch","write_file","remove_file","delete","batch"].includes(item.action)
      && safeLabel(item.skillLabel, 120) && safeLabel(item.summary, 240)
      && typeof item.diff === "string" && new TextEncoder().encode(item.diff).length <= 256*1024
      && typeof item.truncated === "boolean" && item.reviewState === "awaiting-native-approval");
  }
  async function refreshLearning() {
    if (!active || !learningButton) return;
    learningButton.disabled = true; learningButton.setAttribute("aria-busy", "true");
    text("[data-learning-status]", "Reading the current owner review snapshot…");
    learningList.replaceChildren(); learningNext.textContent = "";
    try {
      const result = await read.get("/chat/api/resources/learning");
      if (!active) return;
      if (!validLearning(result)) throw new Error("invalid learning snapshot");
      if (result.state === "unavailable") {
        text("[data-learning-status]", "Native skill review is unavailable.");
        text("[data-learning-next]", result.pendingReasons.join(" · ") || "The owner review source could not be verified.");
        return;
      }
      const partial = result.state === "partial";
      text("[data-learning-status]", partial
        ? `Partial root-verified snapshot · ${result.candidates.length} candidate(s); see pending reasons below.`
        : result.candidates.length ? `${result.candidates.length} root-verified candidate(s) awaiting native owner review.`
          : "No native skill candidates are waiting for review.");
      for (const item of result.candidates) {
        const li = document.createElement("li"); li.className = "capability-learning-card";
        const title = document.createElement("h4"); title.textContent = item.skillLabel || item.summary || "Skill proposal";
        const meta = document.createElement("p"); meta.className = "capability-learning-meta";
        const time = typeof item.createdAt === "number" && Number.isFinite(item.createdAt) ? new Date(item.createdAt * 1000).toLocaleString() : "time unavailable";
        meta.textContent = `${item.action} · ${item.reviewState} · ${time} · revision ${item.revisionSha256} · diff ${item.diffSha256}${item.truncated ? " · truncated" : ""}`;
        const provenance = document.createElement("p"); provenance.className = "capability-learning-meta";
        provenance.textContent = `Native candidate ${item.id}; root verified current owner ingress and skill custody. Review remains in /skills pending.`;
        const details = document.createElement("details"); const summary = document.createElement("summary"); summary.textContent = "Read candidate diff";
        const pre = document.createElement("pre"); pre.className = "capability-learning-diff";
        pre.textContent = item.diff + (item.truncated ? "\n\n[The root snapshot reports that this diff is truncated.]" : "");
        details.append(summary, pre); li.append(title, meta, provenance, details); learningList.append(li);
      }
      const next = typeof result.nextStep === "string" && result.nextStep.length <= 500 ? result.nextStep : "Review candidates in the owner Hermes conversation.";
      text("[data-learning-next]", `${next}${result.pendingReasons.length ? ` Pending: ${result.pendingReasons.join(" · ")}.` : ""}`);
    } catch (_) {
      if (active) text("[data-learning-status]", "The current owner learning snapshot is unavailable. No proposal was approved or applied.");
    } finally {
      if (active) { learningButton.disabled = false; learningButton.removeAttribute("aria-busy"); }
    }
  }
  search?.addEventListener("input", render); source?.addEventListener("change", render);
  refreshButton?.addEventListener("click", refreshCapabilities); learningButton?.addEventListener("click", refreshLearning);
  void refreshCapabilities(); void refreshLearning();
  return () => {
    active = false;
    search?.removeEventListener("input", render); source?.removeEventListener("change", render);
    refreshButton?.removeEventListener("click", refreshCapabilities); learningButton?.removeEventListener("click", refreshLearning);
    results?.replaceChildren(); learningList?.replaceChildren(); detail?.replaceChildren();
  };
}'''


API_PATHS = (
    "/chat/api/capabilities",
    "/chat/api/native-capabilities",
    "/chat/api/resources/learning",
)
