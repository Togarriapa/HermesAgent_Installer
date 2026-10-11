from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.jarvis_chat_assets import reviewed_chat_asset
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS


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
        self.assertIn("Jarvis is your master assistant and sole user-facing agent", source)
        self.assertIn("Expert profiles and team bundles are internal specialists", source)
        self.assertIn("not separate accounts or direct messages", source)
        self.assertIn("Skills are reusable tools", source)
        self.assertIn("owner-reported approval and review state", source)

    def test_navigation_and_read_only_views_use_finite_account_scoped_endpoints(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        for label in ("Chat", "Sessions", "Overview", "Capabilities", "Settings"):
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
        self.assertIn('aria-label="Owned conversation sessions"', source)
        self.assertIn('id="capability-map" class="capability-map"', source)
        self.assertIn("Profiles and bundles</strong> are internal specialists for Jarvis team missions", source)
        self.assertIn("Speech input", source)
        self.assertIn("Speech output", source)
        self.assertIn('id="speech-stop" type="button" aria-label="Stop reply audio"', source)
        self.assertIn("read-only integration status", source)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        for endpoint in ("/capabilities", "/settings"):
            with self.subTest(endpoint=endpoint):
                self.assertIn(f"${{API}}{endpoint}", client)
        self.assertNotIn("turnCountsByDay", client)
        self.assertNotIn("function loadOverview", client)
        self.assertNotIn("function renderTurnChart", client)
        self.assertIn("function featurePathMatches(template, path)", client)
        self.assertIn("feature.mount(root, featureApi(feature, root)", client)
        self.assertIn('feature.id === "overview" && method === "GET" && path === "/chat/api/overview"', client)
        self.assertIn("unmountFeature();", client)
        navigation = client.split("async function showView(view, navSelection = view) {", 1)[1].split("if (selected !== \"chat\")", 1)[0]
        self.assertIn('button.setAttribute("aria-current", "page")', navigation)
        self.assertIn('group.dataset.current = String(active)', navigation)
        self.assertIn('summary.setAttribute("aria-current", "location")', navigation)
        self.assertIn('window.matchMedia("(prefers-reduced-motion: reduce)")', client)
        self.assertIn('button.dataset.openSessions === "true" ? "sessions" : button.dataset.view', navigation)
        self.assertIn('showView("chat", "sessions")', client)
        self.assertIn('showView("overview");', client)
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        self.assertIn(".nav-item{min-height:44px}", stylesheet.decode("utf-8"))
        self.assertIn("Runtime readiness pending", client)
        self.assertIn("Internal profile · catalog only; not selectable", client)
        self.assertIn('"current-core-witness": "A current process and listener were observed; functional readiness has not been verified."', client)

    def test_feature_registry_is_a_separate_ordered_immutable_fixed_asset(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        features_tag = '<script defer src="/chat/assets/features.js"></script>'
        app_tag = '<script defer src="/chat/assets/app.js"></script>'
        self.assertLess(markup.index(features_tag), markup.index(app_tag))
        primary_nav = markup.split('<nav class="primary-nav"', 1)[1].split('</nav>', 1)[0]
        self.assertEqual(primary_nav.count('<button type="button" class="nav-item"'), 4 + len(FEATURE_ASSETS))
        for group in ("command-centre", "conversations", "work", "resources", "system"):
            self.assertEqual(primary_nav.count(f'data-nav-group="{group}"'), 1)
        self.assertIn('Conversation model · session only', markup)
        self.assertEqual(markup.count('data-view="overview"'), 1)
        self.assertEqual(markup.count('data-view="integrations"'), 1)
        self.assertEqual(markup.count('>Plugins &amp; MCP</button>'), 1)
        self.assertEqual(markup.count('>Integrations</button>'), 1)
        self.assertEqual(markup.count('id="overview-view"'), 1)
        self.assertEqual(markup.count('data-view-panel="overview"'), 1)

        _content_type, registry = reviewed_chat_asset("/chat/assets/features.js")
        source = registry.decode("utf-8")
        self.assertIn('Object.defineProperty(script, "jarvisReviewedFeatures"', source)
        self.assertIn("writable: false, configurable: false", source)
        self.assertIn("Object.freeze(features.map", source)
        self.assertNotIn("import(", source)
        self.assertNotIn("https://", source)
        self.assertNotIn("http://", source)
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
        _content_type, features = reviewed_chat_asset("/chat/assets/features.js")
        self.assertIn("turnCountsByDay", features.decode("utf-8"))

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

        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        style = stylesheet.decode("utf-8")
        self.assertIn(".capability-workspace-layout", style)
        self.assertIn(".capability-learning-diff", style)

    def test_sessions_are_searchable_owned_rows_and_read_aloud_can_always_be_stopped(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        history = client.split("function renderHistory() {", 1)[1].split("async function openSessions()", 1)[0]
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
            "/chat/assets/features.js": "text/javascript; charset=utf-8",
            "/chat/assets/app.js": "text/javascript; charset=utf-8",
        }
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

    def test_browser_bundle_passes_node_syntax_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            for asset_name in ("features.js", "app.js"):
                with self.subTest(asset=asset_name):
                    _content_type, script = reviewed_chat_asset(f"/chat/assets/{asset_name}")
                    path = Path(temporary) / asset_name
                    path.write_bytes(script)
                    result = subprocess.run(
                        ["node", "--check", str(path)],
                        capture_output=True,
                        text=True,
                        check=False,
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

    def test_voice_and_appearance_preferences_are_local_bounded_and_do_not_persist_consent(self):
        _content_type, page = reviewed_chat_asset("/chat")
        markup = page.decode("utf-8")
        for control in ("speech-language", "speech-rate", "speech-pitch", "ui-density", "ui-text-size", "ui-motion"):
            with self.subTest(control=control):
                self.assertIn(f'id="{control}"', markup)
        self.assertIn("browser or operating system chooses the microphone", markup)
        self.assertIn("Microphone permission and push-to-talk consent are never saved", markup)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        self.assertIn('const preferenceKey = "jarvis.ui.preferences.v1"', client)
        self.assertIn('byId("speech-output").checked = uiPreferences.readAloud', client)
        self.assertIn('current.lang = byId("speech-language").value', client)
        self.assertIn('"language-not-supported":', client)
        self.assertIn('utterance.rate = Number(byId("speech-rate").value)', client)
        self.assertIn('utterance.pitch = Number(byId("speech-pitch").value)', client)
        self.assertIn('readAloud: uiPreferences.readAloud, language: uiPreferences.language, voiceURI: uiPreferences.voiceURI', client)
        self.assertNotIn('safe.consent', client)
        self.assertIn('function shouldReduceMotion()', client)
        self.assertIn('uiPreferences.motion === "reduce" || window.matchMedia', client)
        _content_type, stylesheet = reviewed_chat_asset("/chat/assets/app.css")
        css = stylesheet.decode("utf-8")
        self.assertIn('html[data-jarvis-density="compact"]', css)
        self.assertIn('html[data-jarvis-text-size="large"]', css)
        self.assertIn('html[data-jarvis-motion="reduce"]', css)


if __name__ == "__main__":
    unittest.main()
