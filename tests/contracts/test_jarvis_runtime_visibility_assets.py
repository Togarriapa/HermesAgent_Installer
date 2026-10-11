from __future__ import annotations

import unittest

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_runtime_visibility_assets import FEATURE_ASSETS


class JarvisRuntimeVisibilityAssetTests(unittest.TestCase):
    def test_runtime_logs_asset_uses_only_existing_owner_checked_activity_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertEqual(FEATURE_ASSETS.feature_id, "activity")
        self.assertEqual(FEATURE_ASSETS.nav_label, "Logs")
        self.assertEqual(FEATURE_ASSETS.api_routes, (
            ("GET", "/chat/api/activity"),
            ("GET", "/chat/api/turns/{id}/activity"),
            ("GET", "/chat/api/turns/{id}/usage"),
        ))
        self.assertNotIn("/api/backend", FEATURE_ASSETS.mount_js)
        self.assertNotIn("/api/rpc", FEATURE_ASSETS.mount_js)
        self.assertNotIn("fetch(", FEATURE_ASSETS.mount_js)

    def test_browser_attribution_and_unavailable_runtime_evidence_are_explicit(self):
        self.assertIn(
            "Hermes activity stream does not provide verified browser-tool attribution",
            FEATURE_ASSETS.view_html,
        )
        self.assertIn("Recovery", FEATURE_ASSETS.view_html)
        self.assertIn("Not established by this event feed", FEATURE_ASSETS.view_html)
        self.assertIn("Older event pages are not exposed in this view", FEATURE_ASSETS.mount_js)
        self.assertIn("Billed cost", FEATURE_ASSETS.mount_js)
        self.assertIn("'message.complete': 'Turn completion observed'", FEATURE_ASSETS.mount_js)

    def test_event_values_are_rendered_as_text_and_turn_ids_are_bounded(self):
        self.assertIn("item.textContent = value", FEATURE_ASSETS.mount_js)
        self.assertNotIn("innerHTML", FEATURE_ASSETS.mount_js)
        self.assertIn("/^[A-Za-z0-9_-]{24,80}$/", FEATURE_ASSETS.mount_js)
        self.assertIn("api.get(`/chat/api/turns/${encodeURIComponent(turnId)}/activity`)",
                      FEATURE_ASSETS.mount_js)
        self.assertIn("api.get(`/chat/api/turns/${encodeURIComponent(turnId)}/usage`)",
                      FEATURE_ASSETS.mount_js)

    def test_charts_derive_status_duration_and_single_snapshot_values(self):
        self.assertIn('data-status-chart', FEATURE_ASSETS.view_html)
        self.assertIn('data-duration-chart', FEATURE_ASSETS.view_html)
        self.assertIn('data-usage-chart', FEATURE_ASSETS.view_html)
        self.assertIn('const statusCounts = new Map()', FEATURE_ASSETS.mount_js)
        self.assertIn('event.duration_ms >= 0', FEATURE_ASSETS.mount_js)
        self.assertIn('const median = ordered.length % 2', FEATURE_ASSETS.mount_js)
        self.assertIn('const maximum = ordered[ordered.length - 1].duration', FEATURE_ASSETS.mount_js)
        self.assertIn('if (Number.isSafeInteger(usage.total)', FEATURE_ASSETS.mount_js)
        self.assertIn('tokenRows = [[\'input\', \'Input tokens\'], [\'output\', \'Output tokens\']]',
                      FEATURE_ASSETS.mount_js)
        self.assertIn('they are not added together', FEATURE_ASSETS.view_html)
        self.assertIn('Event durations may overlap and are never summed', FEATURE_ASSETS.view_html)
        self.assertIn('Billed cost is unknown', FEATURE_ASSETS.view_html)


if __name__ == "__main__":
    unittest.main()
