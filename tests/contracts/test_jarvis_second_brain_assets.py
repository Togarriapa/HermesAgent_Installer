"""Static contract coverage for the owner-bound Obsidian dashboard leaf."""
from __future__ import annotations

import unittest

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_second_brain_assets import FEATURE_ASSETS


class JarvisSecondBrainAssetTests(unittest.TestCase):
    def test_feature_declares_only_the_reviewed_owner_read_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertEqual(FEATURE_ASSETS.feature_id, "second-brain")
        self.assertEqual(FEATURE_ASSETS.api_routes, (
            ("GET", "/chat/api/second-brain/overview"),
            ("GET", "/chat/api/second-brain/notes"),
            ("GET", "/chat/api/second-brain/search"),
            ("GET", "/chat/api/second-brain/notes/{note_id}"),
            ("GET", "/chat/api/second-brain/notes/{note_id}/links"),
            ("GET", "/chat/api/second-brain/graph"),
        ))

    def test_vault_content_is_text_only_and_graph_uses_real_link_dtos(self):
        self.assertIn("data-note-body", FEATURE_ASSETS.view_html)
        self.assertIn("data-graph-list", FEATURE_ASSETS.view_html)
        self.assertNotIn("innerHTML", FEATURE_ASSETS.mount_js)
        self.assertIn("body.textContent = note.markdown", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.fromNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.toNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("data.unresolved.length", FEATURE_ASSETS.mount_js)
        self.assertIn("summary.noteCount", FEATURE_ASSETS.mount_js)
        self.assertIn("summary.observedAt", FEATURE_ASSETS.mount_js)
        self.assertIn("link[targetField]", FEATURE_ASSETS.mount_js)
        self.assertIn("note.markdown", FEATURE_ASSETS.mount_js)
        self.assertIn("does not imply communication or execution", FEATURE_ASSETS.view_html)

    def test_read_view_has_keyboard_touch_and_reduced_motion_paths(self):
        self.assertIn("data-search-form", FEATURE_ASSETS.view_html)
        self.assertIn("data-more", FEATURE_ASSETS.view_html)
        self.assertIn("min-height:44px", FEATURE_ASSETS.css)
        self.assertIn("focus-visible", FEATURE_ASSETS.css)
        self.assertIn("prefers-reduced-motion:reduce", FEATURE_ASSETS.css)
        self.assertIn("aria-live=\"polite\"", FEATURE_ASSETS.view_html)


if __name__ == "__main__":
    unittest.main()
