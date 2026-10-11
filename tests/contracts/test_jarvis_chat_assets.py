from __future__ import annotations

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.jarvis_chat_assets import reviewed_chat_asset


def reviewed_client_bundle():
    _app_type, app = reviewed_chat_asset("/chat/assets/app.js")
    _feature_type, features = reviewed_chat_asset("/chat/assets/features.js")
    return "text/javascript; charset=utf-8", app + b"\n" + features


class JarvisChatAssetTests(unittest.TestCase):
    def test_chat_shell_uses_jarvis_branding_without_desktop_admin_links(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        self.assertIn("<title>Jarvis</title>", source)
        self.assertIn("<strong>JARVIS</strong>", source)
        self.assertNotIn("/client/bootstrap.html", source)
        self.assertNotIn("Owner Desktop", source)
        self.assertNotIn("owner administration", source)
        self.assertIn('id="assistant-hud" data-state="checking"', source)
        self.assertIn('id="assistant-mode" role="status" aria-live="polite"', source)

    def test_navigation_and_read_only_views_use_finite_account_scoped_endpoints(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        for label in ("Chats", "Overview", "Capabilities", "Settings"):
            with self.subTest(label=label):
                self.assertIn(f">{label}</button>", source)
        self.assertIn('id="turn-chart"', source)
        self.assertIn('id="capability-list"', source)
        self.assertIn('id="capability-search" type="search"', source)
        self.assertIn('id="capability-kind"', source)
        self.assertIn('id="capability-discovery"', source)
        self.assertIn('id="turn-active"', source)
        self.assertIn('id="session-search" type="search"', source)
        self.assertIn('id="session-count" role="status" aria-live="polite"', source)
        self.assertIn('aria-label="Owned private chats"', source)
        self.assertIn('id="capability-map" class="capability-map"', source)
        self.assertIn("Speech input", source)
        self.assertIn("Speech output", source)
        self.assertIn('id="speech-stop" type="button" aria-label="Stop reply audio"', source)
        self.assertIn("read-only integration status", source)

        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        for endpoint in ("/overview", "/capabilities", "/settings"):
            with self.subTest(endpoint=endpoint):
                self.assertIn(f"${{API}}{endpoint}", client)
        self.assertIn("turnCountsByDay", client)
        self.assertIn("function featurePathMatches(template, path)", client)
        self.assertIn("feature.mount(root, featureApi(feature)", client)
        self.assertIn("unmountFeature();", client)
        navigation = client.split("async function showView(view) {", 1)[1].split("if (selected !== \"chat\")", 1)[0]
        self.assertIn('button.setAttribute("aria-current", "page")', navigation)
        self.assertIn('primaryNav.scrollTo({ left: Math.max(0, left), behavior })', navigation)
        self.assertIn('shouldReduceMotion()', navigation)
        self.assertIn('window.matchMedia("(prefers-reduced-motion: reduce)")', client)
        self.assertNotIn('data-open-sessions="true"', page.decode("utf-8"))
        self.assertIn('data-view="chat">Chats</button>', page.decode("utf-8"))
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        self.assertIn(".nav-item{min-height:44px}", stylesheet.decode("utf-8"))
        self.assertIn("Runtime readiness pending", client)
        self.assertIn("Internal profile · catalog only; not selectable", client)
        self.assertIn('"current-core-witness": "A current process and listener were observed; functional readiness has not been verified."', client)

    def test_command_centre_groups_existing_routes_and_preserves_command_results(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        self.assertIn('<div class="workspace" data-current-view="overview">', source)
        self.assertIn('<script defer src="/chat/assets/features.js"></script>', source)
        self.assertIn('<main class="data-main" id="overview-view"', source)
        self.assertIn('data-view="overview"', source.split('data-nav-group="command-centre"', 1)[1].split("</details>", 1)[0])
        expected_groups = {
            "conversations": ("chat",),
            "work": ("missions", "bots"),
            "resources": ("capabilities", "resources-learning", "native-inventory", "files"),
            "system": ("settings", "activity", "native-controls", "models-settings"),
        }
        for group, destinations in expected_groups.items():
            with self.subTest(group=group):
                markup = source.split(f'data-nav-group="{group}"', 1)[1].split("</details>", 1)[0]
                for destination in destinations:
                    self.assertIn(f'data-view="{destination}"', markup)

        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        _registry_type, registry = reviewed_chat_asset("/chat/assets/features.js")
        for feature_id in (
            "missions", "bots", "activity", "native-controls", "resources-learning",
            "native-inventory", "files", "models-settings",
        ):
            with self.subTest(feature=feature_id):
                self.assertIn(f'id:"{feature_id}"', registry.decode("utf-8"))
        self.assertIn('const data = await request(`${API}/overview`);', client)
        sender = client.split("async function sendMessage(text) {", 1)[1].split("function createIdempotencyKey()", 1)[0]
        self.assertIn("return true;", sender)
        self.assertIn("return false;", sender)
        bridge = client.split("async function sendOverviewCommand(event) {", 1)[1].split("overviewForm.addEventListener", 1)[0]
        self.assertIn("const accepted = await sendMessage(text);", bridge)
        self.assertIn("if (accepted)", bridge)
        self.assertIn("Your text is preserved here", bridge)
        self.assertIn("overviewCommandPending", bridge)
        self.assertIn('if (feature.id === "models-settings") contextualCleanup = preselectCurrentModelConversation(root);', client)
        model_context = client.split("function preselectCurrentModelConversation(root) {", 1)[1].split("function mountFeature(feature)", 1)[0]
        self.assertIn('select.value = id;', model_context)
        self.assertIn('observer.disconnect();', model_context)
        self.assertIn('finally { if (contextualCleanup) contextualCleanup(); }', client)

    def test_capability_inventory_filter_and_details_are_data_backed(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        renderer = client.split("function renderCapabilities() {", 1)[1].split("async function loadCapabilities()", 1)[0]
        self.assertIn('byId("capability-search").value.trim().toLocaleLowerCase()', renderer)
        self.assertIn('byId("capability-kind").value', renderer)
        self.assertIn("text.includes(query)", renderer)
        self.assertIn('const isProfile = item.kind === "profiles"', renderer)
        self.assertIn('const canonical = isProfile && item.id === "hermes"', renderer)
        self.assertIn('summary.textContent = canonical ? "Jarvis · primary assistant" : item.name', renderer)
        self.assertIn("description.textContent =", renderer)
        self.assertIn("identity.textContent = isProfile", renderer)
        self.assertNotIn(".innerHTML", renderer)
        self.assertIn("source.catalogVersion", client)
        self.assertIn("function renderCapabilityMap()", client)
        self.assertIn("counts.set(item.kind", client)
        self.assertIn("fill.style.width =", client)
        self.assertIn('button.setAttribute("aria-pressed"', client)

    def test_capability_detail_workspace_is_composed_inside_existing_capabilities_panel(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        panel = markup.split('id="capabilities-view"', 1)[1].split('id="settings-view"', 1)[0]
        self.assertIn('id="capability-details-root"', panel)
        self.assertIn('id="capability-workspace-title"', panel)
        self.assertIn('id="capability-learning-title"', panel)
        self.assertNotIn("__JARVIS_CAPABILITY_DETAILS__", markup)
        self.assertEqual(markup.count('data-view="capabilities"'), 1)
        self.assertNotIn('data-view="capability-details"', markup)

        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        self.assertIn("mountCapabilitiesDetails();", client)
        self.assertIn("if (currentView === \"capabilities\") mountCapabilitiesDetails();", client)
        self.assertIn("mountCapabilityDetails(root, reader)", client)
        self.assertIn('request(path, {method:"GET"})', client)
        allowed = client.split("const allowed = new Set([", 1)[1].split("]);", 1)[0]
        self.assertEqual(set(re.findall(r'"(/chat/api/[^\"]+)"', allowed)), {
            "/chat/api/capabilities",
            "/chat/api/native-capabilities",
            "/chat/api/resources/learning",
        })
        self.assertIn("unmountCapabilitiesDetails();", client)
        self.assertIn("Review remains in /skills pending.", client)

        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        style = stylesheet.decode("utf-8")
        self.assertIn(".capability-workspace-layout", style)
        self.assertIn(".capability-learning-diff", style)

    def test_sessions_are_searchable_owned_rows_and_read_aloud_can_always_be_stopped(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        history = client.split("function renderHistory() {", 1)[1].split("function setPanel(open)", 1)[0]
        self.assertIn('ui.sessionSearch.value.trim().toLocaleLowerCase()', history)
        self.assertIn("conversations.filter((entry)", history)
        self.assertIn("loadConversation(entry.id)", history)
        self.assertIn('ui.sessionCount.textContent', history)
        self.assertIn('ui.speechStop.hidden = !synthesisSupported', client)
        self.assertIn('ui.speechStop.disabled = true', client)
        self.assertIn('ui.speechStop.disabled = false', client)

    def test_assistant_hud_reflects_real_chat_and_voice_lifecycle(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        self.assertIn('inputmode="text" autocorrect="on" spellcheck="true"', source)
        self.assertIn('id="speech-voice-status" role="status" aria-live="polite"', source)
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        for state in ("checking", "ready", "listening", "busy", "speaking", "error"):
            with self.subTest(state=state):
                self.assertIn(f'"{state}"', client)
        self.assertIn('setAssistantState("busy", "Preparing your response")', client)
        self.assertIn('setAssistantState("listening", "Listening once · review before sending")', client)
        self.assertIn('setAssistantState("speaking", "Reading the completed reply aloud")', client)
        self.assertIn('setAssistantState("error", "Needs attention")', client)
        self.assertIn('const presence = byId("jarvis-presence")', client)
        self.assertIn('presence.dataset.state = hud.dataset.state', client)
        self.assertIn('id="jarvis-presence" data-state="checking"', source)
        self.assertIn('presenceLink.textContent = label', client)
        self.assertIn("function updateSpeechVoiceStatus()", client)
        self.assertIn("no selectable voices are currently reported", client)
        self.assertIn("window.speechSynthesis.onvoiceschanged = refreshVoices", client)

    def test_overview_hologram_is_focal_and_side_telemetry_keeps_live_metrics(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        self.assertIn('class="overview-hud"', source)
        self.assertIn('class="jarvis-presence" id="jarvis-presence" data-state="checking" data-connection="checking"', source)
        self.assertIn('class="presence-core-label">J.A.R.V.I.S.', source)
        self.assertIn('class="telemetry-rail telemetry-rail-left"', source)
        self.assertIn('class="telemetry-rail telemetry-rail-right"', source)
        for metric in ("core-status", "core-readiness", "core-observed", "conversation-count", "turn-total", "turn-breakdown", "turn-active", "last-turn", "chart-caption", "turn-chart"):
            with self.subTest(metric=metric):
                self.assertEqual(source.count(f'id="{metric}"'), 1)
        self.assertIn('class="command-panel"', source)

        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        self.assertIn('request(`${API}/overview`)', client)
        self.assertIn("renderTurnChart(chat.turnCountsByDay)", client)
        self.assertIn('days.reduce((sum, day) => sum + Math.max(0, day.total), 0)', client)
        self.assertIn('presence.dataset.connection = state', client)

    def test_presence_motion_tracks_actual_page_visibility_and_reduced_motion(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        css = stylesheet.decode("utf-8")

        self.assertIn('presence.dataset.pageVisible = visible', client)
        self.assertIn('document.documentElement.dataset.pageVisible = visible', client)
        self.assertIn('document.addEventListener("visibilitychange", () => {\n    syncPageVisibility();', client)
        sync_call = client.index("  syncPageVisibility();", client.index('document.addEventListener("visibilitychange"'))
        observer_setup = client.index('  if (presence && "IntersectionObserver" in window)', sync_call)
        self.assertLess(sync_call, observer_setup)
        self.assertIn('.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-orbit-inner', css)
        self.assertIn('.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-core', css)
        self.assertIn('html:not([data-jarvis-motion="full"]) .jarvis-presence .presence-core', css)
        self.assertIn('animation:none!important;transform:none!important', css)

    def test_presence_stops_offline_until_protected_refresh_confirms_connection(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        css = stylesheet.decode("utf-8")

        offline = client.index('window.addEventListener("offline", () => {')
        online = client.index('window.addEventListener("online", async () => {')
        refresh = client.index("await refreshConversations();", online)
        ready = client.index('setConnection("ready", "Secure connection");', refresh)
        self.assertLess(offline, online)
        self.assertLess(refresh, ready)
        self.assertIn('document.documentElement.dataset.networkOnline = "false"', client[offline:online])
        self.assertIn('presence.dataset.state = "checking"', client[offline:online])
        self.assertIn('.jarvis-presence:not([data-connection="ready"]) .presence-orbit-inner', css)
        self.assertIn('.jarvis-presence:not([data-connection="ready"]) .presence-core{animation:none!important;transform:none!important}', css)

    def test_only_exact_reviewed_asset_routes_are_available(self):
        expected = {
            "/chat": "text/html; charset=utf-8",
            "/chat/": "text/html; charset=utf-8",
            "/chat/assets/app.css": "text/css; charset=utf-8",
            "/chat/assets/app.js": "text/javascript; charset=utf-8",
            "/chat/assets/features.js": "text/javascript; charset=utf-8",
        }
        for route, content_type in expected.items():
            with self.subTest(route=route):
                actual_type, body = reviewed_chat_asset(route)
                self.assertEqual(actual_type, content_type)
                self.assertTrue(body)
                self.assertLessEqual(len(body), 128 * 1024)
        for route in (
            "/chat/assets/../gateway.py", "/chat/api/conversations",
            "/chat/assets/app.js?x=1", "/chat/assets/features.js?x=1",
            "/chat/assets/%61pp.js", "/chat//assets/app.js",
        ):
            with self.subTest(route=route), self.assertRaises(ValueError):
                reviewed_chat_asset(route)

    def test_browser_bundle_passes_node_syntax_check(self):
        assets = {
            "app.js": reviewed_chat_asset("/chat/assets/app.js")[1],
            "features.js": reviewed_chat_asset("/chat/assets/features.js")[1],
        }
        with tempfile.TemporaryDirectory() as temporary:
            for name, script in assets.items():
                with self.subTest(asset=name):
                    path = Path(temporary) / name
                    path.write_bytes(script)
                    result = subprocess.run(
                        ["node", "--check", str(path)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_heartbeat_cannot_clobber_turn_and_completed_reply_is_recovered(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        turn_handlers = client.split("function watchTurn(", 1)[1].split("async function sendMessage(text)", 1)[0]
        self.assertIn('if (activeTurnId !== turnId) return;', turn_handlers)
        self.assertIn('if (activeTurnId === turnId) waiting.remove();', turn_handlers)
        renew = "async function renewHeartbeat(" + client.split(
            "async function renewHeartbeat(", 1)[1].split(
                "\n  async function reconcileCompletedTurn(", 1)[0]
        reconcile = "async function reconcileCompletedTurn(" + client.split(
            "async function reconcileCompletedTurn(", 1)[1].split(
                "\n  function startHeartbeat(", 1)[0]
        harness = r'''const assert = require("node:assert/strict");
const API = "/chat/api";
let request, activeTurnId = "old-success", conversationId = "conversation";
let heartbeatNonce = "unchanged", closed = 0, errors = 0, connections = [], recoveredSpeech = [];
function closeStream() { closed += 1; activeTurnId = null; }
function showError(message) { errors += 1; }
function setConnection(state, label) { connections.push([state, label]); }
function speakCompletedReply(text) { recoveredSpeech.push(text); }
function refreshConversations() { return Promise.resolve(); }
const assistantBody = {textContent: "partial reply"};
const waiting = {removed: false, remove() { this.removed = true; }};
RENEW
RECONCILE
(async () => {
  let resolveOld;
  request = () => new Promise((resolve) => { resolveOld = resolve; });
  let stale = renewHeartbeat("old-success", "old-nonce", () => activeTurnId === "old-success", async () => { throw new Error("must not reconcile stale work"); });
  activeTurnId = "new-turn";
  resolveOld({turnId: "old-success", nonce: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"});
  await stale;
  assert.equal(heartbeatNonce, "unchanged");
  assert.equal(closed, 0);
  assert.equal(errors, 0);

  activeTurnId = "old-failure";
  let rejectOld;
  request = () => new Promise((_resolve, reject) => { rejectOld = reject; });
  stale = renewHeartbeat("old-failure", "old-nonce", () => activeTurnId === "old-failure", async () => { throw new Error("must not reconcile stale work"); });
  activeTurnId = null;
  rejectOld(new Error("Your secure session is no longer current. Sign in again to continue."));
  await stale;
  assert.equal(closed, 0);
  assert.equal(errors, 0);

  activeTurnId = "current-invalid";
  request = async () => ({turnId: "current-invalid", nonce: "malformed"});
  await renewHeartbeat("current-invalid", "nonce", () => activeTurnId === "current-invalid", async () => false);
  assert.equal(closed, 1);
  assert.equal(errors, 1);
  assert.deepEqual(connections.at(-1), ["error", "Access unavailable"]);

  activeTurnId = "completed-turn";
  conversationId = "conversation";
  assistantBody.textContent = "partial reply";
  waiting.removed = false;
  request = async (path) => {
    if (path.endsWith("/heartbeat")) throw new Error("Your secure session is no longer current. Sign in again to continue.");
    return {messages: [
      {role: "user", content: "show my saved reply"},
      {role: "assistant", content: "Jarvis"}
    ]};
  };
  await renewHeartbeat("completed-turn", "nonce", () => activeTurnId === "completed-turn",
    () => reconcileCompletedTurn("completed-turn", "conversation", "show my saved reply", assistantBody, waiting));
  assert.equal(assistantBody.textContent, "Jarvis");
  assert.equal(waiting.removed, true);
  assert.equal(closed, 2);
  assert.deepEqual(connections.at(-1), ["ready", "Secure connection"]);
  assert.deepEqual(recoveredSpeech, ["Jarvis"]);
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("RENEW", renew).replace("RECONCILE", reconcile)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "heartbeat-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sse_retries_transient_disconnect_and_recovers_saved_completion(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        classifier = "async function classifyTurnStreamError(" + client.split(
            "async function classifyTurnStreamError(", 1)[1].split(
                "\n  function startHeartbeat(", 1)[0]
        harness = r'''const assert = require("node:assert/strict");
CLASSIFIER
(async () => {
  let reconnects = 0, reconciliations = 0;
  const retry = await classifyTurnStreamError({}, 0, async () => false, () => { reconnects += 1; });
  assert.deepEqual(retry, {kind: "reconnecting", code: ""});
  assert.equal(reconnects, 1);
  assert.equal(reconciliations, 0);

  const recovered = await classifyTurnStreamError({}, 2, async () => {
    reconciliations += 1;
    return true;
  }, () => { reconnects += 1; });
  assert.deepEqual(recovered, {kind: "recovered", code: ""});
  assert.equal(reconciliations, 1);

  const denied = await classifyTurnStreamError({data: JSON.stringify({code: "authorization"})}, 2,
    async () => { throw new Error("authorization failures must not become success"); }, () => {});
  assert.deepEqual(denied, {kind: "failed", code: "authorization"});
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("CLASSIFIER", classifier)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "sse-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_background_history_refresh_does_not_clobber_completed_reply(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        helper = "function refreshConversationsInBackground()" + client.split(
            "function refreshConversationsInBackground()", 1)[1].split(
                "\n  async function loadConversation(", 1)[0]
        self.assertEqual(client.count("refreshConversationsInBackground();"), 3)
        self.assertIn('ui.sessionCount.textContent = "Your chat list is unavailable.";', client)
        harness = r'''const assert = require("node:assert/strict");
let failure = new Error("Jarvis is unreachable. Check your connection and try again.");
let notice = "", assistantReply = "Jarvis";
function refreshConversations() { return Promise.reject(failure); }
function showError(message) { notice = message; }
HELPER
(async () => {
  await refreshConversationsInBackground();
  assert.equal(assistantReply, "Jarvis");
  assert.equal(notice, "");

  failure = new Error("Your secure session is no longer current. Sign in again to continue.");
  await refreshConversationsInBackground();
  assert.equal(assistantReply, "Jarvis");
  assert.equal(notice, failure.message);
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("HELPER", helper)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "background-history-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepted_queued_turn_exposes_stop_until_terminal_cleanup(self):
        _content_type, script = reviewed_client_bundle()
        source = script.decode("utf-8")
        self.assertIn("function renderTurnControls(active, stopping = false)", source)
        self.assertIn("ui.stop.hidden = !active", source)
        self.assertIn("renderTurnControls(true);\n    eventSource = new EventSource", source)
        self.assertIn("renderTurnControls(false);", source)
        self.assertIn("if (activeTurnId === turnId) closeStream();", source)

    def test_browser_voice_is_opt_in_reviewed_text_and_completed_reply_only(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        self.assertIn('id="voice-input" type="button"', markup)
        self.assertIn('id="voice-wake-toggle" type="button" aria-pressed="false"', markup)
        self.assertIn('id="voice-handsfree-send" type="checkbox"', markup)
        self.assertIn('id="speech-consent" type="checkbox"', markup)
        self.assertIn("outside Jarvis", markup)
        self.assertIn('id="speech-output" type="checkbox"', markup)
        self.assertIn('id="speech-voice"', markup)
        self.assertIn('id="chat-speech-consent" type="checkbox"', markup)
        self.assertIn('id="chat-speech-output" type="checkbox"', markup)
        self.assertIn('id="chat-speech-voice"', markup)
        self.assertIn('id="chat-speech-rate" type="range"', markup)
        self.assertIn('id="chat-speech-pitch" type="range"', markup)
        self.assertIn('class="chat-model-link" data-view="models-settings"', markup)
        self.assertIn('id="speech-stop" type="button"', markup)

        _content_type, script = reviewed_client_bundle()
        source = script.decode("utf-8")
        self.assertIn("window.SpeechRecognition || window.webkitSpeechRecognition", source)
        self.assertIn("current.interimResults = false", source)
        self.assertIn("Transcript added to your message. Review it before sending.", source)
        self.assertIn("speakCompletedReply(finalText)", source)
        self.assertIn("utterance.onend", source)
        self.assertIn("stopRecognition(); stopSpeech();", source)
        self.assertGreaterEqual(source.count("if (recognition !== current) return;"), 3)
        self.assertIn('&& !ui.input.disabled && !byId("main-content").hidden', source)
        self.assertIn("transcript.slice(0, Math.max(0, limit - existing.length - separator.length))", source)
        self.assertIn('document.visibilityState !== "visible"', source)
        self.assertIn('current.continuous = mode === "wake"', source)
        self.assertIn('byId("voice-handsfree-send").checked && !existingDraft', source)
        self.assertIn("ui.form.requestSubmit()", source)
        self.assertIn("Foreground wake listening ended", source)

    def test_voice_and_appearance_preferences_are_local_bounded_and_do_not_persist_consent(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        for control in ("speech-language", "speech-rate", "speech-pitch", "ui-density", "ui-text-size", "ui-motion"):
            with self.subTest(control=control):
                self.assertIn(f'id="{control}"', markup)
        self.assertIn("browser or operating system chooses the microphone", markup)
        self.assertIn("Microphone permission and voice-input consent are never saved", markup)
        self.assertIn('<option value="full">Full motion · override device</option>', markup)

        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        self.assertIn('const preferenceKey = "jarvis.ui.preferences.v1"', client)
        self.assertIn('for (const id of ["speech-output", "chat-speech-output"]) byId(id).checked = uiPreferences.readAloud', client)
        self.assertIn('current.lang = uiPreferences.language', client)
        self.assertIn('uiPreferences.motion !== "full" && window.matchMedia("(prefers-reduced-motion: reduce)").matches', client)
        self.assertIn('"language-not-supported":', client)
        self.assertIn('utterance.rate = Number(uiPreferences.rate)', client)
        self.assertIn('utterance.pitch = Number(uiPreferences.pitch)', client)
        self.assertIn('function pushToTalkEnabled()', client)
        self.assertIn('byId("chat-speech-consent").checked = enabled', client)
        self.assertIn('byId("chat-preferences").open = false', client)
        self.assertIn('byId("chat-preferences").querySelector(".chat-model-link").addEventListener("click", () => showView("models-settings"))', client)
        self.assertIn('readAloud: uiPreferences.readAloud, language: uiPreferences.language, voiceURI: uiPreferences.voiceURI', client)
        self.assertNotIn('safe.consent', client)
        self.assertIn('function shouldReduceMotion()', client)
        self.assertIn('uiPreferences.motion === "reduce" || (uiPreferences.motion !== "full" && window.matchMedia', client)
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        css = stylesheet.decode("utf-8")
        self.assertIn('html[data-jarvis-density="compact"]', css)
        self.assertIn('html[data-jarvis-text-size="large"]', css)
        self.assertIn('html[data-jarvis-motion="reduce"]', css)


if __name__ == "__main__":
    unittest.main()
