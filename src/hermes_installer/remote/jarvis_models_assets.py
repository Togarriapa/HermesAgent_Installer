"""Static Jarvis Models selector; every choice is verified by its owner-bound API."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW_HTML = '''
<section class="models-settings-card" aria-labelledby="models-settings-title">
  <h2 id="models-settings-title">Models</h2>
  <p class="muted" data-models-status role="status" aria-live="polite">Loading your conversations.</p>
  <label for="models-conversation">Conversation</label>
  <select id="models-conversation" data-models-conversation><option value="">Loading…</option></select>
  <dl class="models-settings-values">
    <div><dt>Codex provider</dt><dd data-models-provider>Pending verification</dd></div>
    <div><dt>Profile default</dt><dd data-models-model>Pending verification</dd></div>
    <div><dt>Codex credential</dt><dd data-models-account>Unknown</dd></div>
    <div><dt>Conversation selection</dt><dd data-models-selection>Not observed</dd></div>
  </dl>
  <section class="models-selection-draft" aria-labelledby="models-draft-title">
    <h3 id="models-draft-title">Select a model for this conversation</h3>
    <label for="models-model-draft">Codex model</label>
    <select id="models-model-draft" data-models-choice disabled><option value="">Unavailable</option></select>
    <button type="button" data-models-apply disabled>Apply to conversation</button>
    <p class="muted" data-models-catalog>Choices are loaded from the pinned Codex subscription catalog.</p>
  </section>
  <p class="muted models-settings-note">Changes use Hermes' session-scoped model method and do not change the profile default. A successful selection is not proof that a later response used that route. Spark remains unavailable until account entitlement is verified.</p>
</section>
'''

_CSS = '''.models-settings-card{max-width:900px;margin:0 auto}.models-settings-card>h2{margin:0}.models-settings-card>label{display:block;margin:16px 0 6px;color:#8ba5aa;font-size:12px}.models-settings-card select{min-height:38px;width:100%;border:1px solid var(--line);border-radius:8px;background:#101e24;color:#e1f4f5;padding:7px 10px}.models-settings-values{margin:15px 0 0;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));column-gap:28px}.models-settings-values>div{display:flex;justify-content:space-between;gap:14px;padding:11px 0;border-bottom:1px solid var(--line)}.models-settings-values dt{color:#8ba5aa;font-size:12px}.models-settings-values dd{margin:0;text-align:right;color:#e1f4f5;font-size:12px;overflow-wrap:anywhere}.models-selection-draft{display:grid;grid-template-columns:120px minmax(0,1fr);align-items:center;gap:10px 14px;margin-top:20px;padding:16px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.48)}.models-selection-draft h3,.models-selection-draft p{grid-column:1/-1;margin:0}.models-selection-draft h3{font-size:13px;color:#d5edef}.models-selection-draft label{font-size:12px;color:#8ba5aa}.models-selection-draft button{min-height:38px;border:1px solid var(--line);border-radius:8px;background:#245865;color:#e1f4f5;padding:7px 12px}.models-selection-draft button:disabled{opacity:.55}.models-settings-note{max-width:760px;margin:14px 0 0;font-size:11px}@media(max-width:640px){.models-settings-values{grid-template-columns:1fr}.models-selection-draft{grid-template-columns:1fr}.models-selection-draft h3,.models-selection-draft p{grid-column:1}}
'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true;
  let revision = null;
  let snapshot = null;
  const query = (selector) => root.querySelector(selector);
  const put = (selector, value) => { const node = query(selector); if (node) node.textContent = value; };
  const status = (value) => put("[data-models-status]", value);
  const choice = query("[data-models-choice]");
  const apply = query("[data-models-apply]");
  const conversation = query("[data-models-conversation]");
  const safeId = (value) => typeof value === "string" && /^[A-Za-z0-9_-]{24,64}$/.test(value);
  const safeModel = (value) => typeof value === "string" && /^[a-z0-9][a-z0-9.-]{0,79}$/.test(value);
  function updateApply() {
    apply.disabled = !(snapshot && revision && snapshot.selectionAvailability === "available"
      && safeId(conversation.value) && safeModel(choice.value));
  }
  function token() {
    const bytes = new Uint8Array(24); crypto.getRandomValues(bytes);
    return Array.from(bytes, (part) => part.toString(16).padStart(2, "0")).join("");
  }
  async function refreshSettings() {
    revision = null; snapshot = null; choice.disabled = true; apply.disabled = true;
    const id = conversation.value;
    if (!safeId(id)) return;
    try {
      const data = await api.get(`/chat/api/conversations/${encodeURIComponent(id)}/model-settings`);
      if (!active || id !== conversation.value) return;
      if (!data || data.status !== "observed" || !Array.isArray(data.models) || data.models.length !== 9)
        throw new Error("invalid model settings");
      snapshot = data;
      const validSetting = (item) => item && item.status === "configured-unverified"
        && typeof item.id === "string" && item.id.length <= 160 ? item.id : "Unknown";
      put("[data-models-provider]", validSetting(data.provider));
      put("[data-models-model]", validSetting(data.profileModel));
      put("[data-models-account]", data.codexCredential === "configured" ? "Configured"
        : data.codexCredential === "not-configured" ? "Not configured" : "Unknown");
      const last = data.conversationSelection;
      put("[data-models-selection]", last && safeModel(last.model)
        ? `${last.model} · ${last.state}` : "No Jarvis selection recorded");
      choice.replaceChildren();
      for (const item of data.models) {
        if (!item || !safeModel(item.id) || typeof item.selectable !== "boolean") continue;
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = item.status === "account-entitlement-unverified"
          ? `${item.id} · account entitlement unverified` : item.id;
        option.disabled = !item.selectable;
        choice.append(option);
      }
      if (choice.options.length !== 9) throw new Error("model catalog is incomplete");
      revision = data.revision && typeof data.revision.revision === "string"
        && typeof data.revision.approval_nonce === "string" ? data.revision : null;
      choice.disabled = !revision || data.selectionAvailability !== "available";
      const reasons = {
        available: "Pinned Codex subscription choices are available for this conversation.",
        "turn-active": "Model selection is unavailable while this conversation has an active turn.",
        "provider-or-credential-unverified": "The current Codex provider and credential state do not permit selection.",
        "revision-unavailable": "A short-lived current selection revision could not be issued. Refresh before selecting."
      };
      put("[data-models-catalog]", reasons[data.selectionAvailability] || "Model selection status is unknown.");
      status("Current sanitized settings are loaded for your selected conversation.");
      updateApply();
    } catch (_) {
      if (!active || id !== conversation.value) return;
      revision = null; snapshot = null;
      choice.replaceChildren(); choice.add(new Option("Unavailable", ""));
      choice.disabled = true;
      put("[data-models-provider]", "Unknown"); put("[data-models-model]", "Unknown");
      put("[data-models-account]", "Unknown"); put("[data-models-selection]", "Not observed");
      put("[data-models-catalog]", "Native model settings are unavailable; no change was made.");
      status("Current model settings are unavailable.");
    }
  }
  async function loadConversations() {
    try {
      const data = await api.get("/chat/api/models/conversations");
      if (!active || !data || !Array.isArray(data.conversations) || data.conversations.length > 100)
        throw new Error("invalid conversation list");
      conversation.replaceChildren();
      const placeholder = new Option(data.conversations.length ? "Choose a conversation" : "No conversations yet", "");
      conversation.add(placeholder);
      for (const row of data.conversations) {
        if (!row || !safeId(row.id)) continue;
        const option = new Option(typeof row.title === "string" ? row.title.slice(0, 100) : "Jarvis conversation", row.id);
        conversation.add(option);
      }
      conversation.disabled = conversation.options.length < 2;
      status(conversation.disabled ? "Create a Jarvis conversation before selecting its model."
        : "Choose one of your conversations to inspect and change its model.");
    } catch (_) {
      if (active) { conversation.replaceChildren(new Option("Conversations unavailable", "")); status("Your conversations are unavailable."); }
    }
  }
  conversation.addEventListener("change", refreshSettings);
  choice.addEventListener("change", updateApply);
  const handleApply = async () => {
    if (!snapshot || !revision || apply.disabled) return;
    apply.disabled = true;
    status("Submitting a session-scoped model selection.");
    const selectedConversation = conversation.value;
    try {
      const result = await api.post(`/chat/api/conversations/${encodeURIComponent(selectedConversation)}/model-selection`, {
        model_id: choice.value, revision: revision.revision,
        approval_nonce: revision.approval_nonce, idempotency_key: token()
      });
      if (!active || selectedConversation !== conversation.value) return;
      const messages = {
        "selected-for-session": "Hermes accepted this model for the selected conversation. Future route execution has not been observed.",
        "deferred-next-turn": "Hermes queued this model for the next turn in the selected conversation.",
        "confirmation-required": "Hermes requires a native confirmation that Jarvis does not perform.",
        "unknown-pending": "The native result is unknown; the request was not retried. Refresh status before trying again."
      };
      status(messages[result && result.state] || "The native selection result is unknown.");
      await refreshSettings();
    } catch (_) {
      if (active) status("Selection was not confirmed. Refresh model status before making another selection.");
    }
  };
  apply.addEventListener("click", handleApply);
  void loadConversations();
  return () => { active = false; conversation.removeEventListener("change", refreshSettings); choice.removeEventListener("change", updateApply); apply.removeEventListener("click", handleApply); };
}'''

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="models-settings",
    nav_label="Models",
    title="Models",
    view_html=_VIEW_HTML,
    css=_CSS,
    api_routes=(
        ("GET", "/chat/api/models/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/model-settings"),
        ("POST", "/chat/api/conversations/{conversation_id}/model-selection"),
    ),
    mount_js=_MOUNT_JS,
    unmount_js="function unmount() {}",
)
