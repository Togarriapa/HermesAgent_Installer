"""Static, separate Jarvis feature contribution for profile/channel/schedule status."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

_VIEW = """<section class=\"bots-panel\" aria-labelledby=\"bots-heading\">
  <header class=\"bots-header\">
    <div><p class=\"bots-eyebrow\">STATUS</p><h2 id=\"bots-heading\">Bots, channels &amp; schedules</h2>
      <p class=\"bots-subtitle\">Live status from the current Hermes core. Profile inventory is not a Bot Mode roster.</p></div>
    <button class=\"bots-refresh\" type=\"button\" data-bots-refresh>Refresh status</button>
  </header>
  <nav class=\"bots-tabs\" aria-label=\"Status sections\">
    <button type=\"button\" data-bots-section=\"bots\" aria-current=\"page\">Bots</button>
    <button type=\"button\" data-bots-section=\"channels\">Channels</button>
    <button type=\"button\" data-bots-section=\"schedules\">Schedules</button>
  </nav>
  <p class=\"bots-status\" data-bots-status aria-live=\"polite\">Loading current status…</p>
  <div class=\"bots-pending\" data-bots-pending></div>
  <section class=\"bots-roster\" data-bots-roster hidden aria-label=\"Canonical Bot DM readiness\"></section>
  <div class=\"bots-rows\" data-bots-rows></div>
</section>"""

_CSS = """[data-feature-root=\"bots\"] .bots-panel{max-width:1050px;margin:0 auto;padding:clamp(18px,3vw,32px);color:var(--fg,#f3f5f7)}
[data-feature-root=\"bots\"] .bots-header{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}
[data-feature-root=\"bots\"] .bots-eyebrow{margin:0 0 8px;color:var(--muted,#aab2bf);font-size:.72rem;letter-spacing:.14em;font-weight:700}
[data-feature-root=\"bots\"] .bots-header h2{margin:0;font-size:clamp(1.45rem,3vw,2rem)}
[data-feature-root=\"bots\"] .bots-subtitle{margin:10px 0 0;color:var(--muted,#aab2bf);max-width:60ch;line-height:1.5}
[data-feature-root=\"bots\"] .bots-refresh,[data-feature-root=\"bots\"] .bots-tabs button{font:inherit;color:inherit;background:var(--surface,#20242c);border:1px solid var(--line,#39404b);border-radius:10px;padding:10px 14px;cursor:pointer}
[data-feature-root=\"bots\"] .bots-refresh:hover,[data-feature-root=\"bots\"] .bots-tabs button:hover{border-color:var(--accent,#80b8ff)}
[data-feature-root=\"bots\"] .bots-tabs{display:flex;gap:8px;margin:24px 0 14px;border-bottom:1px solid var(--line,#39404b);padding-bottom:12px}
[data-feature-root=\"bots\"] .bots-tabs button[aria-current=\"page\"]{background:var(--accent-soft,#263b55);border-color:var(--accent,#80b8ff)}
[data-feature-root=\"bots\"] .bots-status{color:var(--muted,#aab2bf);min-height:1.5em}
[data-feature-root=\"bots\"] .bots-pending{display:grid;gap:8px;margin:14px 0}
[data-feature-root=\"bots\"] .bots-note,[data-feature-root=\"bots\"] .bots-row{border:1px solid var(--line,#39404b);border-radius:12px;background:var(--surface,#20242c);padding:14px 16px}
[data-feature-root=\"bots\"] .bots-note{color:var(--muted,#aab2bf);line-height:1.45}
[data-feature-root=\"bots\"] .bots-rows{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:12px;margin-top:14px}
[data-feature-root=\"bots\"] .bots-row h3{font-size:1rem;margin:0 0 8px}
[data-feature-root=\"bots\"] .bots-row p{color:var(--muted,#aab2bf);margin:5px 0;overflow-wrap:anywhere}
[data-feature-root=\"bots\"] .bots-empty{padding:18px;border:1px dashed var(--line,#39404b);border-radius:12px;color:var(--muted,#aab2bf)}
[data-feature-root=\"bots\"] .bots-roster{display:grid;gap:8px;margin:14px 0}
@media(max-width:600px){[data-feature-root=\"bots\"] .bots-header{flex-direction:column}[data-feature-root=\"bots\"] .bots-refresh{width:100%}}"""

_MOUNT = r'''function mount(container, api, state) {
  let active = true;
  let requestSerial = 0;
  let selected = "bots";
  let unresolvedPauseRevision = null;
  const pauseApprovals = new Map();
  const click = async (event) => {
    const sectionButton = event.target.closest("[data-bots-section]");
    const refreshButton = event.target.closest("[data-bots-refresh]");
    const pauseButton = event.target.closest("[data-schedule-pause]");
    if (!sectionButton && !refreshButton && !pauseButton) return;
    if (pauseButton) {
      const id = pauseButton.dataset.schedulePause;
      const approval = pauseApprovals.get(id);
      if (!approval || unresolvedPauseRevision === approval.revision) return;
      pauseButton.disabled = true;
      container.querySelector("[data-bots-status]").textContent = "Submitting the one-use pause approval…";
      const keyBytes = new Uint8Array(24);
      crypto.getRandomValues(keyBytes);
      const idempotencyKey = Array.from(keyBytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
      pauseApprovals.delete(id);
      unresolvedPauseRevision = approval.revision;
      let result = { status: "pending" };
      try {
        result = await api.post("/chat/api/schedules/" + encodeURIComponent(id) + "/pause", {
          revision: approval.revision,
          approval_nonce: approval.nonce,
          idempotency_key: idempotencyKey,
        });
      } catch (_) {
        result = { status: "pending" };
      }
      if (!active) return;
      if (result.status === "paused") unresolvedPauseRevision = null;
      await load();
      if (!active) return;
      const status = container.querySelector("[data-bots-status]");
      status.textContent = result.status === "paused"
        ? "Pause was confirmed by the current Hermes core."
        : "Pause result is pending or could not be confirmed. Refresh to inspect current core status.";
      return;
    }
    if (sectionButton) {
      selected = sectionButton.dataset.botsSection;
      container.querySelectorAll("[data-bots-section]").forEach((button) => {
        if (button === sectionButton) button.setAttribute("aria-current", "page");
        else button.removeAttribute("aria-current");
      });
    }
    await load();
  };
  const node = (tag, text, className) => {
    const element = document.createElement(tag);
    if (className) element.className = className;
    element.textContent = String(text ?? "");
    return element;
  };
  const addField = (card, label, value) => card.appendChild(node("p", label + ": " + (value ?? "Unknown")));
    const render = (snapshot) => {
    const rows = container.querySelector("[data-bots-rows]");
    const pending = container.querySelector("[data-bots-pending]");
    const roster = container.querySelector("[data-bots-roster]");
    const status = container.querySelector("[data-bots-status]");
    rows.replaceChildren(); pending.replaceChildren(); roster.replaceChildren();
    roster.hidden = selected !== "bots";
    pauseApprovals.clear();
    const reason = Array.isArray(snapshot.pending_reasons) ? snapshot.pending_reasons : [];
    reason.forEach((item) => pending.appendChild(node("p", item, "bots-note")));
    if (selected === "bots" && snapshot.bot_roster) {
      const rosterSnapshot = snapshot.bot_roster;
      roster.appendChild(node("h3", "Canonical Bot DMs"));
      (Array.isArray(rosterSnapshot.profiles) ? rosterSnapshot.profiles : []).forEach((profile) => {
        const card = node("article", "", "bots-row");
        card.appendChild(node("h4", profile.label || "Enrolled Bot"));
        addField(card, "Enrollment", profile.enrollment_state);
        addField(card, "Canonical DM", profile.canonical_dm_state);
        if (profile.reason) card.appendChild(node("p", profile.reason));
        roster.appendChild(card);
      });
      (Array.isArray(rosterSnapshot.pending_reasons) ? rosterSnapshot.pending_reasons : [])
        .forEach((item) => roster.appendChild(node("p", item, "bots-note")));
      if (!Array.isArray(rosterSnapshot.profiles) || !rosterSnapshot.profiles.length) {
        roster.appendChild(node("p", "No owner-enrolled Bot profiles are currently available.", "bots-empty"));
      }
    }
    let items = [];
    if (selected === "bots") items = Array.isArray(snapshot.profiles) ? snapshot.profiles : [];
    if (selected === "channels") items = Array.isArray(snapshot.channels) ? snapshot.channels : [];
    if (selected === "schedules") items = Array.isArray(snapshot.schedules) ? snapshot.schedules : [];
    if (selected === "schedules" && unresolvedPauseRevision && items.length
        && items[0].revision !== unresolvedPauseRevision) unresolvedPauseRevision = null;
    if (!items.length) rows.appendChild(node("p", selected === "channels"
      ? "Channel state is unavailable from the reviewed native status API."
      : "No current native status rows were returned.", "bots-empty"));
    items.forEach((item) => {
      const card = node("article", "", "bots-row");
      if (selected === "bots") {
        card.appendChild(node("h3", item.display_name || "Current default profile"));
        addField(card, "State", item.state);
        addField(card, "Bot Mode", item.bot_mode_available ? "Available" : "Roster/DM status unavailable");
      } else if (selected === "channels") {
        card.appendChild(node("h3", item.type || "Channel"));
        addField(card, "Configured", item.configured);
        addField(card, "Enabled", item.enabled);
        addField(card, "Connected", item.connected);
        addField(card, "State", item.state);
      } else {
        card.appendChild(node("h3", item.label || "Scheduled job"));
        addField(card, "Enabled", item.enabled);
        addField(card, "Schedule", item.schedule_summary);
        addField(card, "Timezone", item.timezone);
        addField(card, "Next run", item.next_run_at);
        addField(card, "Last state", item.last_state);
        if (item.enabled === true && item.opaque_id && item.revision && item.pause_approval_nonce
            && item.revision !== unresolvedPauseRevision) {
          pauseApprovals.set(item.opaque_id, { revision: item.revision, nonce: item.pause_approval_nonce });
          const pause = node("button", "Pause schedule", "bots-refresh");
          pause.type = "button";
          pause.dataset.schedulePause = item.opaque_id;
          card.appendChild(pause);
        }
      }
      rows.appendChild(card);
    });
    status.textContent = "Observed " + (snapshot.observed_at || "at unknown time")
      + " · core generation " + (snapshot.core_generation || "unknown");
    if (selected === "schedules" && unresolvedPauseRevision
        && items.some((item) => item.revision === unresolvedPauseRevision)) {
      status.textContent = "Pause result is unconfirmed. Current status is shown below; no pause action from this unchanged snapshot can be submitted. Refresh status to resolve it.";
    }
  };
  const load = async () => {
    if (!active) return;
    const serial = ++requestSerial;
    pauseApprovals.clear();
    const status = container.querySelector("[data-bots-status]");
    status.textContent = "Loading current status…";
    try {
      const path = selected === "channels" ? "/chat/api/channels"
        : selected === "schedules" ? "/chat/api/schedules" : "/chat/api/bots";
      let snapshot = await api.get(path);
      if (selected === "bots") {
        try {
          const roster = await api.get("/chat/api/bot-rooms");
          snapshot = { ...snapshot, bot_roster: roster };
        } catch (_) {
          snapshot = { ...snapshot, bot_roster: { profiles: [], pending_reasons: [
            "Owner-enrolled Bot readiness is unavailable until its protected roster endpoint is connected."
          ] } };
        }
      }
      if (active && serial === requestSerial) render(snapshot);
    } catch (_) {
      if (active && serial === requestSerial) {
        status.textContent = unresolvedPauseRevision
          ? "Pause result is unconfirmed and current status could not be read. Refresh before trying another action."
          : "Status could not be read. Try refreshing after core connectivity returns.";
        container.querySelector("[data-bots-rows]").replaceChildren();
      }
    }
  };
  container.addEventListener("click", click);
  load();
  return () => { active = false; requestSerial += 1; container.removeEventListener("click", click); };
}'''

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="bots",
    nav_label="Bots",
    title="Bots, channels & schedules",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(("GET", "/chat/api/bots"), ("GET", "/chat/api/bot-rooms"),
                ("GET", "/chat/api/channels"),
                ("GET", "/chat/api/schedules"),
                ("POST", "/chat/api/schedules/{opaque_id}/pause")),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
