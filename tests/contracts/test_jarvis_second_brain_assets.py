"""Static contract coverage for the owner-bound Obsidian dashboard leaf."""
from __future__ import annotations

import unittest

from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_feature_registry import FEATURE_ASSETS as REGISTERED_ASSETS
from hermes_installer.remote.jarvis_obsidian_vault import FEATURE_ROUTES
from hermes_installer.remote.jarvis_second_brain_assets import FEATURE_ASSETS


class JarvisSecondBrainAssetTests(unittest.TestCase):
    def test_feature_declares_only_the_reviewed_owner_read_routes(self):
        validate_feature_assets((FEATURE_ASSETS,))
        self.assertEqual(FEATURE_ASSETS.feature_id, "second-brain")
        self.assertIn(FEATURE_ASSETS, REGISTERED_ASSETS)
        self.assertEqual(FEATURE_ASSETS.api_routes, FEATURE_ROUTES)
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
        self.assertIn("Connections represent indexed Obsidian links only", FEATURE_ASSETS.view_html)
        self.assertRegex(FEATURE_ASSETS.view_html, r"\bdo not imply communication or execution\b")

    def test_read_view_has_keyboard_touch_and_reduced_motion_paths(self):
        self.assertIn("data-search-form", FEATURE_ASSETS.view_html)
        self.assertIn("data-more", FEATURE_ASSETS.view_html)
        self.assertIn("min-height:44px", FEATURE_ASSETS.css)
        self.assertIn("focus-visible", FEATURE_ASSETS.css)
        self.assertIn("prefers-reduced-motion:reduce", FEATURE_ASSETS.css)
        self.assertIn("aria-live=\"polite\"", FEATURE_ASSETS.view_html)


    def test_knowledge_map_filters_by_saved_tags_and_draws_real_directional_links(self):
        self.assertIn("function tagCategory(node)", FEATURE_ASSETS.mount_js)
        self.assertIn("node.tags", FEATURE_ASSETS.mount_js)
        self.assertIn("selectedTags", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.fromNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.toNoteId", FEATURE_ASSETS.mount_js)
        self.assertIn("noteTags(node).some(tag => selectedTags.has(tag))", FEATURE_ASSETS.mount_js)
        self.assertIn("tags.forEach(tag => categories.add(tag))", FEATURE_ASSETS.mount_js)
        self.assertIn("ids.has(edge.fromNoteId) && ids.has(edge.toNoteId)", FEATURE_ASSETS.mount_js)
        self.assertIn("edge.kind === 'markdown' ? 'markdown' : 'wikilink'", FEATURE_ASSETS.mount_js)
        self.assertIn("function graphTagArcs(group, node, point)", FEATURE_ASSETS.mount_js)
        self.assertIn("function setGraphSelection()", FEATURE_ASSETS.mount_js)
        self.assertIn("path.setAttribute('data-link-kind'", FEATURE_ASSETS.mount_js)
        self.assertIn("path.setAttribute('marker-end'", FEATURE_ASSETS.mount_js)
        self.assertIn("tagColor(tag)", FEATURE_ASSETS.mount_js)
        self.assertNotIn("animateMotion", FEATURE_ASSETS.mount_js)
        self.assertIn("data-zoom-in", FEATURE_ASSETS.view_html)
        self.assertIn("data-zoom-out", FEATURE_ASSETS.view_html)
        self.assertIn("data-graph-list", FEATURE_ASSETS.view_html)
        self.assertIn("Notes remain in your private vault when a chat or project is removed", FEATURE_ASSETS.view_html)
        self.assertIn("Node rings show saved vault tags", FEATURE_ASSETS.view_html)
        self.assertIn("Solid arrows are wikilinks; dashed arrows are Markdown links", FEATURE_ASSETS.view_html)
        self.assertIn("source records are available", FEATURE_ASSETS.view_html)
        self.assertIn("filters match any selected tag", FEATURE_ASSETS.view_html.lower())


if __name__ == "__main__":
    unittest.main()
