from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.jarvis_chat_assets import (
    FEATURE_CHUNK_PATHS, FEATURE_CSS_CHUNK_PATHS, reviewed_chat_asset,
)
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets


def reviewed_client_bundle():
    """Return the exact browser client asset used by focused behavior harnesses."""
    return reviewed_chat_asset("/chat/assets/app.js")


class JarvisChatAssetTests(unittest.TestCase):
    def test_registered_features_obey_the_fixed_asset_and_lifecycle_contract(self):
        validate_feature_assets(FEATURE_ASSETS)
        feature_ids = [feature.feature_id for feature in FEATURE_ASSETS]
        self.assertEqual(len(feature_ids), len(set(feature_ids)))
        for feature in FEATURE_ASSETS:
            with self.subTest(feature=feature.feature_id):
                self.assertTrue(feature.mount_js.startswith("function mount("))
                self.assertTrue(feature.unmount_js.startswith("function unmount("))

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
        self.assertIn("Jarvis is your master assistant and sole user-facing agent", source)
        self.assertIn("Expert profiles and team bundles are internal specialists", source)
        self.assertIn("not separate accounts or direct messages", source)
        self.assertIn("Skills are reusable tools", source)
        self.assertIn("owner-reported approval and review state", source)

    def test_navigation_and_read_only_views_use_finite_account_scoped_endpoints(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        for label in ("Chats", "Overview", "Capabilities", "Settings"):
            with self.subTest(label=label):
                self.assertIn(f">{label}</button>", source)
        self.assertEqual(source.count('id="overview-view"'), 1)
        self.assertEqual(source.count('data-view-panel="overview"'), 1)
        self.assertIn('id="overview-core-heading"', source)
        self.assertIn('data-core-status', source)
        for metric in ("total", "completed", "active", "failed"):
            self.assertIn(f'data-metric="{metric}"', source)
        self.assertIn('data-duration-bars', source)
        self.assertIn('id="capability-list"', source)
        self.assertIn('id="capability-search" type="search"', source)
        self.assertIn('id="capability-kind"', source)
        self.assertIn('id="capability-discovery"', source)
        self.assertIn('data-integration-kind', source)
        self.assertIn('data-integration-status', source)
        self.assertIn('id="session-search" type="search"', source)
        self.assertIn('id="session-count" role="status" aria-live="polite"', source)
        self.assertIn('id="chat-trash"', source)
        self.assertIn('id="trash-list" aria-label="Removed chats"', source)
        self.assertIn('id="history-action-status" role="status" aria-live="polite"', source)
        self.assertIn('aria-label="Owned private chats"', source)
        self.assertIn('id="capability-map" class="capability-map"', source)
        self.assertIn("Profiles and bundles</strong> are internal specialists for Jarvis team missions", source)
        self.assertIn("Speech input", source)
        self.assertIn("Speech output", source)
        self.assertIn('id="speech-stop" type="button" aria-label="Stop reply audio"', source)
        self.assertIn("read-only integration status", source)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        self.assertIn(".nav-group:not([open])>.nav-menu{display:none}", stylesheet.decode("utf-8"))
        self.assertIn("#history-close{width:44px;height:44px;min-width:44px;min-height:44px}", stylesheet.decode("utf-8"))
        for endpoint in ("/capabilities", "/settings"):
            with self.subTest(endpoint=endpoint):
                self.assertIn(f"${{API}}{endpoint}", client)
        self.assertNotIn("turnCountsByDay", client)
        self.assertNotIn("function loadOverview", client)
        self.assertNotIn("function renderTurnChart", client)
        self.assertIn("function featurePathMatches(template, path)", client)
        self.assertIn("feature.mount(root, featureApi(feature, root)", client)
        self.assertIn("mountedFeatureAbortController = abortController", client)
        self.assertIn("const mountScope = Object.freeze({", client)
        self.assertIn("feature.mount(root, featureApi(feature, root), mountContext, mountScope)", client)
        self.assertIn('feature.id === "overview" && method === "GET" && path === "/chat/api/overview"', client)
        self.assertIn("unmountFeature();", client)
        navigation = client.split(
            "async function showView(view, navSelection = view, featureContext = {}) {", 1
        )[1].split("if (selected !== \"chat\")", 1)[0]
        self.assertIn('button.setAttribute("aria-current", "page")', navigation)
        self.assertIn('group.dataset.current = String(active)', navigation)
        self.assertIn('summary.setAttribute("aria-current", "location")', navigation)
        self.assertIn('some((item) => item.dataset.view === selected)', navigation)
        self.assertIn('group.open = false;', navigation)
        self.assertIn('setAttribute("aria-expanded", "false")', navigation)
        self.assertIn('window.matchMedia("(prefers-reduced-motion: reduce)")', client)
        self.assertIn('navSelection === "sessions" && selected === "chat" ? "sessions" : selected', navigation)
        self.assertIn('if (selectedNavigation === "sessions") setPanel(true);', navigation)
        self.assertIn('button.dataset.view === selected;', navigation)
        self.assertIn('const openChats = button.dataset.view === "chat"', client)
        self.assertIn('showView(button.dataset.view, openChats ? "sessions" : button.dataset.view, featureContext);', client)
        self.assertIn('focusSelectedViewHeading(button.dataset.view);', client)
        self.assertIn('heading.focus({preventScroll: true});', client)
        self.assertIn("new MutationObserver(() => summary.setAttribute(\"aria-expanded\", String(group.open)))", client)
        self.assertIn('button.classList.contains("chat-model-link") && conversationId', client)
        self.assertIn("Object.freeze({initialConversationId: context.initialConversationId})", client)
        self.assertIn('showView("overview");', client)
        self.assertIn('data-view="chat">Chats</button>', page.decode("utf-8"))
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        self.assertIn(".nav-item{min-height:44px}", stylesheet.decode("utf-8"))
        self.assertIn("Runtime readiness pending", client)
        self.assertIn("Internal profile · catalog only; not selectable", client)
        self.assertIn(
            '"current-core-witness": "A current process and listener were observed; functional readiness has not been verified."',
            client,
        )

    def test_command_centre_direct_navigation_preserves_all_routes_and_command_results(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        features_tag = '<script defer src="/chat/assets/features.js"></script>'
        app_tag = '<script defer src="/chat/assets/app.js"></script>'
        self.assertLess(markup.index(features_tag), markup.index(app_tag))
        for chunk_path in FEATURE_CHUNK_PATHS:
            self.assertLess(markup.index(f'<script defer src="{chunk_path}"></script>'), markup.index(features_tag))
        for css_path in FEATURE_CSS_CHUNK_PATHS:
            self.assertLess(markup.index(f'<link rel="stylesheet" href="{css_path}">'),
                            markup.index(features_tag))
        primary_nav = markup.split('<nav class="primary-nav"', 1)[1].split('</nav>', 1)[0]
        expected_destinations = {"overview", "chat", "capabilities", "settings"}
        expected_destinations.update(feature.feature_id for feature in FEATURE_ASSETS)
        for destination in expected_destinations:
            with self.subTest(destination=destination):
                self.assertEqual(primary_nav.count(f'data-view="{destination}"'), 1)
        self.assertEqual(primary_nav.count('<button type="button" class="nav-item'),
                         len(expected_destinations))
        self.assertEqual(primary_nav.count('class="nav-group'), 3)
        for group in ("work", "resources", "system"):
            self.assertIn(f'data-nav-group="{group}"', primary_nav)
        resources_menu = primary_nav.split('data-nav-group="resources"', 1)[1].split("</details>", 1)[0]
        system_menu = primary_nav.split('data-nav-group="system"', 1)[1].split("</details>", 1)[0]
        self.assertIn('data-view="capabilities"', resources_menu)
        self.assertIn('data-view="settings"', system_menu)
        self.assertEqual(system_menu.count('data-view="calendar"'), 1)
        self.assertEqual(system_menu.count(">Calendar</button>"), 1)
        self.assertEqual(system_menu.count('data-view="settings-admin"'), 1)
        self.assertEqual(system_menu.count(">Agent settings</button>"), 1)
        self.assertIn('Conversation model · session only', markup)
        self.assertEqual(markup.count('data-view="overview"'), 1)
        self.assertEqual(markup.count('data-view="integrations"'), 1)
        self.assertEqual(markup.count('>Plugins &amp; MCP</button>'), 1)
        self.assertEqual(markup.count('>Integrations</button>'), 1)
        self.assertEqual(markup.count('id="overview-view"'), 1)
        self.assertEqual(markup.count('data-view-panel="overview"'), 1)
        source = page.decode("utf-8")
        self.assertIn('<div class="workspace" data-current-view="overview">', source)
        self.assertIn('<script defer src="/chat/assets/features.js"></script>', source)
        self.assertIn('<section class="data-main" id="overview-view"', source)
        primary_nav = source.split('<nav class="primary-nav"', 1)[1].split("</nav>", 1)[0]
        for destination, label in (("overview", "Overview"), ("chat", "Chats"), ("projects", "Projects")):
            with self.subTest(destination=destination):
                self.assertIn(f'data-view="{destination}"', primary_nav)
                self.assertIn(label, primary_nav)
        resources_menu = primary_nav.split('data-nav-group="resources"', 1)[1].split("</details>", 1)[0]
        self.assertEqual(resources_menu.count('data-view="second-brain"'), 1)
        self.assertEqual(resources_menu.count(">Second brain</button>"), 1)
        for label in ("Work", "Resources", "System"):
            self.assertIn(f"<summary aria-expanded=\"false\">{label}</summary>", primary_nav)
        self.assertIn('id="voice-entry" type="button" aria-label="Open voice controls"', source)


        chunk_sources = [reviewed_chat_asset(path)[1].decode("utf-8") for path in FEATURE_CHUNK_PATHS]
        _content_type, registry = reviewed_chat_asset("/chat/assets/features.js")
        registry_source = registry.decode("utf-8")
        source = "\n".join(chunk_sources)
        self.assertIn("chunkPaths.flatMap", registry_source)
        self.assertIn('Object.defineProperty(script, "jarvisReviewedFeatures"', registry_source)
        self.assertIn("writable: false, configurable: false", registry_source)
        self.assertIn('Object.defineProperty(script, "jarvisReviewedFeatureChunk"', source)
        self.assertIn("Object.freeze(features.map", source)
        self.assertNotIn("import(", registry_source + source)
        external_url_literals = set(re.findall(r"https?://[^\s\"'`<>]+", registry_source + source))
        self.assertEqual(external_url_literals, {"http://www.w3.org/2000/svg"})
        self.assertNotRegex(
            registry_source + source,
            r"(?:fetch|EventSource|WebSocket|XMLHttpRequest)\s*\(\s*[\"']https?://",
        )
        for feature in FEATURE_ASSETS:
            with self.subTest(feature=feature.feature_id):
                self.assertIn("id:" + json.dumps(feature.feature_id), source)
                self.assertIn(feature.view_html, markup)
                self.assertIn(feature.mount_js, source)
                self.assertIn(feature.unmount_js, source)
                for method, path in feature.api_routes:
                    self.assertIn('"method":"' + method + '","path":"' + path + '"', source)

        _content_type, app_script = reviewed_chat_asset("/chat/assets/app.js")
        client = app_script.decode("utf-8")
        self.assertIn('script[src="/chat/assets/features.js"]', client)
        self.assertIn("featureRegistryScript.jarvisReviewedFeatures", client)
        self.assertNotIn("__JARVIS_FEATURE_ASSETS__", client)
        self.assertTrue(any("turnCountsByDay" in chunk for chunk in chunk_sources))
        _content_type, app_script = reviewed_chat_asset("/chat/assets/app.js")
        client = app_script.decode("utf-8")

        self.assertEqual(primary_nav.count('class="nav-group'), 3)
        self.assertIn('data-nav-group="work"', primary_nav)
        self.assertIn('data-nav-group="resources"', primary_nav)
        self.assertIn('data-nav-group="system"', primary_nav)
        self.assertIn('byId("voice-entry").addEventListener("click", () => { void openVoiceControls(); });', client)

        _registry_type, registry = reviewed_chat_asset("/chat/assets/features.js")
        chunk_sources = [reviewed_chat_asset(path)[1].decode("utf-8") for path in FEATURE_CHUNK_PATHS]
        self.assertIn('item.hidden = !featuresById.has(item.dataset.requiresFeature);', client)
        for feature_id in (
            "missions", "bots", "activity", "native-controls", "resources-learning",
            "native-inventory", "files", "models-settings",
        ):
            with self.subTest(feature=feature_id):
                self.assertTrue(any(f'id:"{feature_id}"' in chunk for chunk in chunk_sources))
                self.assertIn(f'data-view="{feature_id}"', markup)
        css_assets = [reviewed_chat_asset(path)[1].decode("utf-8")
                      for path in ("/chat/assets/app.css", *FEATURE_CSS_CHUNK_PATHS)]
        css = "\n".join(css_assets)
        self.assertIn('.primary-nav>.nav-item,.primary-nav>.nav-group{flex:1 1 0;min-width:0}', css)
        overview_features = [feature for feature in FEATURE_ASSETS if feature.feature_id == "overview"]
        self.assertEqual(len(overview_features), 1)
        overview = overview_features[0]
        self.assertEqual(markup.count(overview.view_html), 1)
        self.assertEqual(source.count(overview.mount_js), 1)
        self.assertIn('class="reactor-dial"', overview.view_html)
        self.assertIn('class="reactor-orbit reactor-orbit-inner"', overview.view_html)
        self.assertIn(
            '.overview-stage[data-core-state="verified"][data-activity="active"] .reactor-orbit-outer',
            overview.css,
        )
        self.assertIn(
            '.overview-stage[data-core-state="verified"][data-activity="quiet"] .reactor-orbit-inner',
            overview.css,
        )
        self.assertIn('feature.id === "overview" && method === "GET" && path === "/chat/api/overview"', client)
        sender = client.split("async function sendMessage(text", 1)[1].split("function createIdempotencyKey()", 1)[0]
        self.assertIn("return true;", sender)
        self.assertIn("return false;", sender)
        self.assertIn('modelId: choice && typeof choice.modelId === "string" ? choice.modelId : null', sender)
        self.assertIn('reasoningEffort: choice && typeof choice.reasoningEffort === "string" ? choice.reasoningEffort : null', sender)
        self.assertIn('eventSource.addEventListener("turn.configuration"', client)
        self.assertIn('configuration.state !== "confirmed"', client)
        self.assertIn('configuration.provider !== "openai-codex"', client)
        self.assertIn('selection.availability === "available" && selection.provider === "openai-codex"', client)
        self.assertIn('if (ui.input.value === text)', sender)
        self.assertIn('ui.input.value = "";', sender)
        self.assertIn('request(`${API}/conversations/trash`)', client)
        trash = client.split("async function changeConversationTrash(", 1)[1].split("function setPanel(open)", 1)[0]
        self.assertIn('Number.isSafeInteger(version)', trash)
        self.assertIn('body: JSON.stringify({version})', trash)
        self.assertIn('headers: {"Idempotency-Key": createIdempotencyKey()}', trash)
        self.assertIn('await refreshTrash();', trash)
        self.assertIn('result.conversation.id !== id', trash)
        overview_command = client.split(
            'if (feature.id === "overview") api.command = async (text) => {', 1
        )[1].split('\n    if (feature.id === "overview") api.newConversation', 1)[0]
        self.assertIn("await showView(\"chat\");", overview_command)
        self.assertIn("const accepted = await sendMessage(text.trim());", overview_command)
        self.assertIn('if (!accepted) throw new Error("Jarvis could not safely queue this response.");', overview_command)
        self.assertIn("return true;", overview_command)
        overview = next(feature for feature in FEATURE_ASSETS if feature.feature_id == "overview")
        self.assertIn('id="overview-command-target"', overview.view_html)
        self.assertIn("A new conversation will start when you send.", overview.view_html)
        self.assertIn("updateOverviewCommandTarget();", client)
        overview_submit = overview.mount_js.split(
            "async function submitCommand(event) {", 1
        )[1].split("\n  commandForm.addEventListener", 1)[0]
        self.assertIn("await api.command(text)", overview_submit)
        self.assertIn("commandInput.value = '';", overview_submit)
        self.assertIn(
            "Command not sent. Your text remains here; try again or open Chat.", overview_submit
        )
        self.assertIn(
            "finally { button.disabled = false; commandInput.disabled = false; }", overview_submit
        )
        models = next(feature for feature in FEATURE_ASSETS if feature.feature_id == "models-settings")
        model_mount = models.mount_js
        self.assertIn("session-scoped model method", models.view_html)
        self.assertIn("do not change the profile default", models.view_html)
        self.assertIn('button.classList.contains("chat-model-link") && conversationId', client)
        self.assertIn("mountFeature(feature, featureContext);", client)
        self.assertIn("Object.freeze({initialConversationId: context.initialConversationId})", client)
        self.assertIn(
            'new Option(data.conversations.length ? "Choose a conversation" : "No conversations yet", "")',
            model_mount,
        )
        self.assertIn("const initialConversationId = safeId(context && context.initialConversationId)", model_mount)
        self.assertIn("Array.from(conversation.options).some((option) => option.value === initialConversationId)", model_mount)
        self.assertIn("if (currentConversationIsOwned)", model_mount)
        self.assertIn('conversation.addEventListener("change", refreshSettings);', model_mount)
        self.assertIn("const selectedConversation = conversation.value;", model_mount)
        self.assertIn(
            'api.post(`/chat/api/conversations/${encodeURIComponent(selectedConversation)}/model-selection`',
            model_mount,
        )
        self.assertIn("model_id: choice.value, revision: revision.revision,", model_mount)
        self.assertIn("approval_nonce: revision.approval_nonce, idempotency_key: token()", model_mount)

    def test_capability_inventory_filter_and_details_are_data_backed(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
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

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
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

        style = "\n".join(reviewed_chat_asset(path)[1].decode("utf-8")
                            for path in ("/chat/assets/app.css", *FEATURE_CSS_CHUNK_PATHS))
        self.assertIn(".capability-workspace-layout", style)
        self.assertIn(".capability-learning-diff", style)

    def test_sessions_are_searchable_owned_rows_and_read_aloud_can_always_be_stopped(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
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
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        for state in ("checking", "ready", "listening", "busy", "speaking", "error"):
            with self.subTest(state=state):
                self.assertIn(f'"{state}"', client)
        self.assertIn('setAssistantState("busy", "Preparing your response")', client)
        self.assertIn('setAssistantState("listening", "Listening once · review before sending")', client)
        self.assertIn('setAssistantState("speaking", "Reading the completed reply aloud")', client)
        self.assertIn('setAssistantState("error", "Needs attention")', client)
        self.assertIn("function updateSpeechVoiceStatus()", client)
        self.assertIn("no selectable voices are currently reported", client)
        self.assertIn("window.speechSynthesis.onvoiceschanged = refreshVoices", client)

    def test_only_exact_reviewed_asset_routes_are_available(self):
        expected = {
            "/chat": "text/html; charset=utf-8",
            "/chat/": "text/html; charset=utf-8",
            "/chat/assets/app.css": "text/css; charset=utf-8",
            "/chat/assets/app.js": "text/javascript; charset=utf-8",
        }
        expected["/chat/assets/features.js"] = "text/javascript; charset=utf-8"
        expected.update({path: "text/javascript; charset=utf-8" for path in FEATURE_CHUNK_PATHS})
        expected.update({path: "text/css; charset=utf-8" for path in FEATURE_CSS_CHUNK_PATHS})
        for route, content_type in expected.items():
            with self.subTest(route=route):
                actual_type, body = reviewed_chat_asset(route)
                self.assertEqual(actual_type, content_type)
                self.assertTrue(body)
                self.assertLessEqual(len(body), 128 * 1024)
        for route in (
            "/chat/assets/../gateway.py", "/chat/api/conversations",
            "/chat/assets/app.js?x=1", "/chat/assets/%61pp.js", "/chat//assets/app.js",
            "/chat/assets/features.js?x=1", "/chat/assets/custom.js",
        ):
            with self.subTest(route=route), self.assertRaises(ValueError):
                reviewed_chat_asset(route)
        for route in (*FEATURE_CHUNK_PATHS, *FEATURE_CSS_CHUNK_PATHS):
            with self.subTest(route=route), self.assertRaises(ValueError):
                reviewed_chat_asset(route + "?x=1")

    def test_browser_bundle_passes_node_syntax_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            asset_paths = [*FEATURE_CHUNK_PATHS, "/chat/assets/features.js", "/chat/assets/app.js"]
            for asset_path in asset_paths:
                asset_name = asset_path.rsplit("/", 1)[-1]
                with self.subTest(asset=asset_name):
                    _content_type, script = reviewed_chat_asset(asset_path)
                    path = Path(temporary) / asset_name
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
        turn_handlers = client.split("function watchTurn(", 1)[1].split("async function sendMessage(text", 1)[0]
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

    def test_overview_command_retains_draft_on_queue_failure_and_clears_only_after_queue(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        target_helper = "function updateOverviewCommandTarget() {" + client.split(
            "function updateOverviewCommandTarget() {", 1)[1].split("\n  }", 1)[0] + "\n  }"
        feature_api = "function featureApi(feature, root) {" + client.split(
            "function featureApi(feature, root) {", 1)[1].split(
                "\n  function unmountFeature()", 1)[0]
        sender = "async function sendMessage(text" + client.split(
            "async function sendMessage(text", 1)[1].split(
                "\n  function createIdempotencyKey()", 1)[0]
        overview = next(feature for feature in FEATURE_ASSETS if feature.feature_id == "overview")
        submit = "async function submitCommand(event) {" + overview.mount_js.split(
            "async function submitCommand(event) {", 1)[1].split(
                "\n  commandForm.addEventListener", 1)[0]
        routes = json.dumps(
            [{"method": method, "path": path} for method, path in overview.api_routes],
            separators=(",", ":"),
        )
        harness = r'''const assert = require("node:assert/strict");
const API = "/chat/api";
let failQueue = true;
const requests = [], views = [], errors = [];
const selectedChoice = {modelId: "reviewed-model", reasoningEffort: "high"};
const chatDraft = "A separate Chat draft";
const assistantBody = {textContent: "", parentElement: {dataset: {}}, append(node) { this.waiting = node; }};
const overviewTarget = {textContent: ""};
const ui = {
  connection: {dataset: {state: "ready"}},
  title: {textContent: "Current project chat"},
  input: {disabled: false, value: chatDraft, style: {}},
  send: {disabled: false},
  turnModel: {value: "reviewed-model"},
  turnEffort: {value: "high"}
};
let observation = {textContent: ""};
const commandInput = {value: "  retain this Overview draft  ", disabled: false};
const submitButton = {disabled: false};
const commandForm = {querySelector() { return submitButton; }};
let stopped = false, activeTurnId = null, conversationId = "existing-conversation";
const conversations = [{id: "existing-conversation", title: "Current project chat"}];
function request(path, options) {
  requests.push({path, options});
  if (failQueue) return Promise.reject(new Error("simulated queue failure"));
  return Promise.resolve({status: "queued", turnId: "queued-turn", heartbeatNonce: "nonce",
    turnConfiguration: {state: "queued", modelId: selectedChoice.modelId}});
}
function currentTurnChoice() {
  return {modelId: ui.turnModel.value || null, reasoningEffort: ui.turnEffort.value || null};
}
function clearError() {}
function stopRecognition() {}
function stopSpeech() {}
function setAssistantState() {}
function appendMessage() { return assistantBody; }
function renderTurnModelControls() {}
function showTurnConfiguration() {}
function watchTurn() {}
function refreshConversationsInBackground() {}
function showError(message) { errors.push(message); }
function showView(view) { views.push(view); return Promise.resolve(); }
function createIdempotencyKey() { return "fixed-contract-key"; }
function byId(id) {
  assert.equal(id, "overview-command-target");
  return overviewTarget;
}
TARGET_HELPER
function $(selector) {
  assert.equal(selector, "[data-observation]");
  return observation;
}
const document = {createElement() { return {className: "", textContent: ""}; }};
const routes = FEATURE_ROUTES;
let api;
FEATURE_API
SENDER
SUBMIT
(async () => {
  api = featureApi({id: "overview", routes}, {});
  updateOverviewCommandTarget();
  assert.equal(overviewTarget.textContent, "Sending to Current project chat");
  conversationId = null;
  updateOverviewCommandTarget();
  assert.equal(overviewTarget.textContent, "A new conversation will start when you send.");
  conversationId = "existing-conversation";
  const originalDraft = commandInput.value;
  await submitCommand({preventDefault() {}});
  assert.equal(commandInput.value, originalDraft);
  assert.equal(observation.textContent,
    "Command not sent. Your text remains here; try again or open Chat.");
  assert.deepEqual(errors, ["simulated queue failure"]);
  assert.deepEqual(views, ["chat"]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].path, "/chat/api/conversations/existing-conversation/turns");
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    text: originalDraft.trim(), modelId: "reviewed-model", reasoningEffort: "high"
  });
  assert.equal(ui.turnModel.value, "reviewed-model");
  assert.equal(ui.turnEffort.value, "high");
  assert.equal(ui.input.value, chatDraft);
  assert.equal(ui.input.disabled, false);
  assert.equal(submitButton.disabled, false);

  failQueue = false;
  observation.textContent = "";
  await submitCommand({preventDefault() {}});
  assert.equal(commandInput.value, "");
  assert.equal(ui.input.value, chatDraft);
  assert.equal(requests.length, 2);
  assert.equal(JSON.parse(requests[1].options.body).modelId, "reviewed-model");
  assert.equal(JSON.parse(requests[1].options.body).reasoningEffort, "high");
  assert.equal(ui.turnModel.value, "");
  assert.equal(ui.turnEffort.value, "");
  assert.equal(submitButton.disabled, false);

  ui.input.disabled = false;
  ui.send.disabled = false;
  commandInput.value = "next message uses defaults";
  await submitCommand({preventDefault() {}});
  assert.equal(requests.length, 3);
  assert.deepEqual(JSON.parse(requests[2].options.body), {
    text: "next message uses defaults", modelId: null, reasoningEffort: null
  });
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("FEATURE_ROUTES", routes).replace("FEATURE_API", feature_api).replace("SENDER", sender).replace("SUBMIT", submit).replace("TARGET_HELPER", target_helper)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "overview-command-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_second_brain_query_routes_are_bounded_get_effects(self):
        _content_type, script = reviewed_client_bundle()
        client = script.decode("utf-8")
        route_helpers = "function featurePathMatches(template, path) {" + client.split(
            "function featurePathMatches(template, path) {", 1)[1].split(
                "\n  function renderCoreStatus(", 1)[0]
        feature_api = "function featureApi(feature, root) {" + client.split(
            "function featureApi(feature, root) {", 1)[1].split(
                "\n  function unmountFeature()", 1)[0]
        asset = next(feature for feature in FEATURE_ASSETS if feature.feature_id == "second-brain")
        routes = json.dumps(
            [{"method": method, "path": path} for method, path in asset.api_routes],
            separators=(",", ":"),
        )
        harness = r'''const assert = require("node:assert/strict");
const requests = [];
function request(path, options) {
  requests.push({path, options});
  return Promise.resolve({notes: [], nextCursor: null});
}
ROUTE_HELPERS
FEATURE_API
(async () => {
  const api = featureApi({id: "second-brain", routes: FEATURE_ROUTES}, {});
  await api.get("/chat/api/second-brain/notes?limit=50");
  await api.get("/chat/api/second-brain/search?limit=20&query=project%20notes");
  await api.get("/chat/api/second-brain/notes?limit=50&cursor=v1%3A12");
  assert.deepEqual(requests, [
    {path: "/chat/api/second-brain/notes?limit=50", options: {method: "GET"}},
    {path: "/chat/api/second-brain/search?limit=20&query=project%20notes", options: {method: "GET"}},
    {path: "/chat/api/second-brain/notes?limit=50&cursor=v1%3A12", options: {method: "GET"}}
  ]);
  for (const path of [
    "/chat/api/second-brain/notes?limit=0",
    "/chat/api/second-brain/notes?limit=50&limit=1",
    "/chat/api/second-brain/notes?limit=50&unknown=x",
    "/chat/api/second-brain/notes?limit=50&cursor=v2%3A1",
    "/chat/api/second-brain/notes?limit=50&cursor=v1%3A01",
    "/chat/api/second-brain/search?limit=50",
    "/chat/api/second-brain/search?limit=50&query=%20%20",
    "/chat/api/second-brain/search?limit=50&query=one&query=two",
    "/chat/api/second-brain/search?limit=50&query=%E0%A4%A",
    "/chat/api/second-brain/search?limit=50&query=" + "x".repeat(257),
    "/chat/api/second-brain/notes?limit=50&%6cimit=1",
    "/chat/api/second-brain/notes?limit=50&cursor=%GG",
    "/chat/api/second-brain/notes?limit=50&cursor",
    "/chat/api/second-brain/notes?limit=50#fragment",
    "https://example.test/chat/api/second-brain/notes?limit=50",
    "/chat/api/second-brain/overview?limit=50"
  ]) {
    await assert.rejects(api.get(path));
  }
  assert.equal(requests.length, 3, "invalid or out-of-scope routes must never reach request()");
})().catch((error) => { console.error(error); process.exitCode = 1; });
'''.replace("FEATURE_ROUTES", routes).replace("ROUTE_HELPERS", route_helpers).replace("FEATURE_API", feature_api)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "second-brain-query-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepted_queued_turn_exposes_stop_until_terminal_cleanup(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
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
        self.assertIn('id="chat-voice-unavailable" role="status" aria-live="polite" hidden', markup)
        self.assertIn('id="voice-handsfree-send" type="checkbox"', markup)
        self.assertIn('id="speech-consent" type="checkbox"', markup)
        self.assertIn("outside Jarvis", markup)
        self.assertIn('id="speech-output" type="checkbox"', markup)
        self.assertIn('id="speech-voice"', markup)
        self.assertIn('id="speech-stop" type="button"', markup)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
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

    def test_chat_explains_voice_unavailability_in_the_composer(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        configure = "function configureVoice() {" + client.split(
            "function configureVoice() {", 1)[1].split(
                "\n  function startRecognition(", 1)[0]
        harness = r'''const assert = require("node:assert/strict");
const elements = new Map();
function byId(id) {
  if (!elements.has(id)) elements.set(id, {hidden: false, disabled: false, textContent: ""});
  return elements.get(id);
}
const ui = {speechStop: byId("speech-stop"), voiceWake: byId("voice-wake-toggle")};
let voiceSupported = false, synthesisSupported = false;
let window = {isSecureContext: true};
function pushToTalkEnabled() { return false; }
CONFIGURE
configureVoice();
assert.equal(byId("chat-voice-unavailable").hidden, false);
assert.match(byId("chat-voice-unavailable").textContent, /not available in this browser/);
window = {SpeechRecognition: function SpeechRecognition() {}, isSecureContext: false};
configureVoice();
assert.equal(byId("chat-voice-unavailable").hidden, false);
assert.match(byId("chat-voice-unavailable").textContent, /secure browser connection/);
window.isSecureContext = true;
configureVoice();
assert.equal(byId("chat-voice-unavailable").hidden, true);
assert.equal(byId("chat-speech-consent-row").hidden, false);
'''.replace("CONFIGURE", configure)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "chat-voice-unavailable-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_global_voice_entry_opens_existing_opt_in_or_truthful_unavailable_reason(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        handler = "async function openVoiceControls() {" + client.split(
            "async function openVoiceControls() {", 1
        )[1].split("\n  function setPanel(", 1)[0]
        harness = r'''const assert = require("node:assert/strict");
function target(tagName = "P") {
  return {tagName, focused:false, attributes:{}, hasAttribute(name){return name in this.attributes;},
    setAttribute(name,value){this.attributes[name]=value;}, focus(){this.focused=true;}};
}
const preferences = {open:false};
const consent = target("INPUT"), unavailable = target("P"), voiceInput = target("BUTTON");
const ui = {voiceInput};
let voiceSupported = true, consentEnabled = false, view = "overview";
function byId(id) { return id === "chat-preferences" ? preferences : id === "chat-speech-consent" ? consent : unavailable; }
function pushToTalkEnabled() { return consentEnabled; }
async function showView(name) { view = name; }
HANDLER
(async () => {
  await openVoiceControls();
  assert.equal(view, "chat");
  assert.equal(preferences.open, true);
  assert.equal(consent.focused, true, "voice stays opt-in and does not start listening");
  assert.equal(voiceInput.focused, false);
  consentEnabled = true;
  await openVoiceControls();
  assert.equal(voiceInput.focused, true, "the opted-in path points to push-to-talk without activating it");
  voiceSupported = false;
  preferences.open = false;
  await openVoiceControls();
  assert.equal(preferences.open, true);
  assert.equal(unavailable.attributes.tabindex, "-1");
  assert.equal(unavailable.focused, true, "unsupported state is surfaced instead of claiming voice is ready");
})().catch((error) => { console.error(error); process.exitCode=1; });
'''.replace("HANDLER", handler)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "global-voice-entry-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(
                ["node", str(path)], capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_browser_voice_states_follow_fake_permission_start_and_cancel_events(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        stop_start = client.index("  function stopRecognition(message = \"\") {")
        stop_end = client.index("\n  function stopSpeech(", stop_start)
        stop_source = client[stop_start:stop_end]
        start = client.index("  function startRecognition(mode = \"ptt\") {")
        end = client.index("\n  function clearError()", start)
        function_source = client[start:end]
        harness = r'''const assert = require("node:assert/strict");
const elements = new Map();
function element(id) {
  if (!elements.has(id)) elements.set(id, {checked:false, hidden:false, disabled:false,
    value:"", maxLength:8000, dataset:{}, attrs:{}, setAttribute(k,v){this.attrs[k]=v;}});
  return elements.get(id);
}
const ui = {input:element("input"), voiceInput:element("voice-input"),
  voiceStop:element("voice-stop"), voiceWake:element("voice-wake"), form:{requestSubmit(){throw Error("unexpected submit");}}};
element("speech-consent").checked = true;
element("main-content").hidden = false;
element("speech-language").value = "en-US";
element("voice-wake-controls");
const states = [];
let visibleStatus = "";
let voiceSupported = true, activeTurnId = null, recognition = null, recognitionMode = "", wakePhraseHeard = false;
const document = {visibilityState:"visible"};
const instances = [];
// This fake emits lifecycle events only; it captures and supplies no audio.
class FakeRecognition {
  constructor(){ instances.push(this); }
  start() {}
  abort(){ this.aborted = true; }
}
const window = {SpeechRecognition:FakeRecognition};
const byId = element;
const pushToTalkEnabled = () => element("speech-consent").checked;
const stopSpeech = () => {};
const showVoiceStatus = (message) => { visibleStatus = message; };
const setAssistantState = (state, label) => { states.push({state,label}); };
STOP_SOURCE
FUNCTION_SOURCE
startRecognition("ptt");
assert.equal(states[states.length - 1].state, "checking", "permission/startup must not claim listening");
assert.match(visibleStatus, /Starting browser speech recognition/);
assert.equal(ui.voiceInput.dataset.listening, "false", "the control must not claim listening before onstart");
assert.equal(ui.voiceStop.hidden, false, "the pending microphone request can still be stopped");
const denied = instances[instances.length - 1];
denied.onerror({error:"not-allowed"});
assert.equal(states[states.length - 1].state, "error", "permission denial must surface as an error");
assert.match(visibleStatus, /permission was denied/);
assert.equal(ui.voiceStop.hidden, true);
assert.equal(ui.input.disabled, false, "typed chat remains available after denial");

states.length = 0; visibleStatus = "";
startRecognition("ptt");
const started = instances[instances.length - 1];
assert.equal(states[states.length - 1].state, "checking");
assert.equal(ui.voiceInput.dataset.listening, "false");
started.onstart();
assert.equal(states[states.length - 1].state, "listening", "listening begins only on the browser start event");
assert.equal(ui.voiceInput.dataset.listening, "true");
assert.match(visibleStatus, /Listening once/);
started.onend();
assert.equal(states[states.length - 1].state, "ready", "browser end returns the assistant to idle");
assert.equal(ui.voiceStop.hidden, true);

states.length = 0;
startRecognition("wake");
const wake = instances[instances.length - 1];
assert.equal(wake.continuous, true, "wake mode requests foreground continuous recognition");
assert.equal(states[states.length - 1].state, "checking");
assert.equal(ui.voiceInput.dataset.listening, "false");
const lateStart = wake.onstart;
stopRecognition("Foreground wake listening stopped.");
assert.equal(wake.aborted, true, "explicit stop aborts the active recognizer");
assert.equal(wake.onstart, null, "stop clears the production start callback");
const stateCountAfterStop = states.length;
lateStart();
assert.equal(states.length, stateCountAfterStop, "a late browser start event after stop cannot claim listening");
assert.equal(ui.voiceInput.dataset.listening, "false");
assert.match(visibleStatus, /stopped/);
assert.equal(element("speech-consent").checked, true, "stop does not silently revoke explicit page consent");
'''.replace("STOP_SOURCE", stop_source).replace("FUNCTION_SOURCE", function_source)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "jarvis-voice-lifecycle-harness.js"
            path.write_text(harness, encoding="utf-8")
            result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_voice_and_appearance_preferences_are_local_bounded_and_do_not_persist_consent(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        for control in ("speech-language", "speech-rate", "speech-pitch", "ui-density", "ui-text-size", "ui-motion"):
            with self.subTest(control=control):
                self.assertIn(f'id="{control}"', markup)
        self.assertIn("browser or operating system chooses the microphone", markup)
        self.assertIn("Microphone permission and voice-input consent are never saved", markup)
        self.assertIn('<option value="full">Full motion when device allows</option>', markup)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        self.assertIn('const preferenceKey = "jarvis.ui.preferences.v1"', client)
        self.assertIn('byId("speech-output").checked = uiPreferences.readAloud;', client)
        self.assertIn('byId("chat-speech-output").checked = uiPreferences.readAloud;', client)
        self.assertIn('current.lang = byId("speech-language").value', client)
        self.assertIn(
            'for (const id of ["speech-language", "chat-speech-language"]) byId(id).value = uiPreferences.language;',
            client,
        )
        self.assertIn('saveUIPreferences({language: event.currentTarget.value});', client)
        self.assertIn('"language-not-supported":', client)
        self.assertIn('utterance.rate = Number(byId("speech-rate").value)', client)
        self.assertIn('utterance.pitch = Number(byId("speech-pitch").value)', client)
        self.assertIn('readAloud: uiPreferences.readAloud, language: uiPreferences.language, voiceURI: uiPreferences.voiceURI', client)
        self.assertNotIn('safe.consent', client)
        self.assertIn('function shouldReduceMotion()', client)
        self.assertIn('return uiPreferences.motion === "reduce" || window.matchMedia("(prefers-reduced-motion: reduce)").matches;', client)
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        css = stylesheet.decode("utf-8")
        self.assertIn('html[data-jarvis-density="compact"]', css)
        self.assertIn('html[data-jarvis-text-size="large"]', css)
        self.assertIn('html[data-jarvis-motion="reduce"]', css)


if __name__ == "__main__":
    unittest.main()
