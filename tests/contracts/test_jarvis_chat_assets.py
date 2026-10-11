from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.jarvis_chat_assets import reviewed_chat_asset


class JarvisChatAssetTests(unittest.TestCase):
    def test_chat_shell_uses_jarvis_branding_without_desktop_admin_links(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        self.assertIn("<title>Jarvis</title>", source)
        self.assertIn("<strong>JARVIS</strong>", source)
        self.assertNotIn("Hermes", source)
        self.assertNotIn("/client/bootstrap.html", source)
        self.assertNotIn("Owner Desktop", source)
        self.assertNotIn("owner administration", source)

    def test_navigation_and_read_only_views_use_finite_account_scoped_endpoints(self):
        _content_type, page = reviewed_chat_asset("/chat")
        source = page.decode("utf-8")
        for label in ("Chat", "Overview", "Capabilities", "Settings"):
            with self.subTest(label=label):
                self.assertIn(f">{label}</button>", source)
        self.assertIn('id="turn-chart"', source)
        self.assertIn('id="capability-list"', source)
        self.assertIn("read-only here", source)

        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        client = script.decode("utf-8")
        for endpoint in ("/overview", "/capabilities", "/settings"):
            with self.subTest(endpoint=endpoint):
                self.assertIn(f"${{API}}{endpoint}", client)
        self.assertIn("turnCountsByDay", client)

    def test_only_exact_reviewed_asset_routes_are_available(self):
        expected = {
            "/chat": "text/html; charset=utf-8",
            "/chat/": "text/html; charset=utf-8",
            "/chat/assets/app.css": "text/css; charset=utf-8",
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
        ):
            with self.subTest(route=route), self.assertRaises(ValueError):
                reviewed_chat_asset(route)

    def test_browser_bundle_passes_node_syntax_check(self):
        _content_type, script = reviewed_chat_asset("/chat/assets/app.js")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "app.js"
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


if __name__ == "__main__":
    unittest.main()
