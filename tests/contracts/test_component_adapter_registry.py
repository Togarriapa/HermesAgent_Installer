"""Pinned adapter contracts retain source choices without alias conflation."""
import unittest

from hermes_installer.components.adapters import (
    COMPONENT_ADAPTERS,
    MCP_COMPONENT_IDS,
    OPTIONAL_SOURCE_OFFERS,
    resolve_component_adapter,
    resolve_optional_source_offer,
    source_copy_specs,
)


class ComponentAdapterContractTests(unittest.TestCase):
    def test_non_mcp_cohort_has_unique_pins_and_aliases(self):
        self.assertEqual(34, len(COMPONENT_ADAPTERS))
        self.assertEqual(34, len({item.component_id for item in COMPONENT_ADAPTERS}))
        for item in COMPONENT_ADAPTERS:
            self.assertEqual(40, len(item.revision or ""))
            self.assertEqual(item, resolve_component_adapter(item.component_id))
            for alias in item.aliases:
                self.assertEqual(item.component_id, resolve_component_adapter(alias).component_id)

    def test_mcp_protocol_ownership_is_explicit(self):
        self.assertEqual(
            {"figma-mcp", "playwright-mcp", "revenuecat-mcp", "google", "home-assistant"},
            MCP_COMPONENT_IDS,
        )
        with self.assertRaises(KeyError):
            resolve_component_adapter("figma-mcp")

    def test_selected_sources_follow_explicit_source_url_and_keep_alternates(self):
        impeccable = resolve_component_adapter("pbakaus/impeccable")
        self.assertEqual("pbakaus/impeccable", impeccable.source_identity)
        self.assertEqual("d631a8827f99414d2b6daba4ef08b7f8701751d7", impeccable.revision)
        self.assertEqual("emilkowalski/skills", impeccable.alternate_sources[0].identity)

        book = resolve_component_adapter("book-to-skill")
        self.assertEqual("virgiliojr94/book-to-skill", book.source_identity)
        self.assertEqual("e180fc46365e8c1aab0120778cc8a40b9515324b", book.revision)
        self.assertEqual("apple-ouyang/book-to-skill", book.alternate_sources[0].identity)

    def test_emil_skill_pack_is_a_separate_optional_offer(self):
        self.assertEqual(1, len(OPTIONAL_SOURCE_OFFERS))
        offer = resolve_optional_source_offer("emilkowalski/skills")
        self.assertEqual("emilkowalski/skills", offer.identity)
        self.assertEqual("e8a175de22ae1e49370fc144c1f3bb9aeedf988d", offer.revision)
        with self.assertRaises(KeyError):
            resolve_component_adapter("emilkowalski/skills")

    def test_private_import_and_redistribution_review_are_separate(self):
        apple = resolve_component_adapter("apple-design")
        self.assertIsNone(apple.unresolved_reason())
        self.assertTrue(apple.redistribution_license_review_required)

    def test_applications_do_not_enter_the_skill_tree_importer(self):
        copied = source_copy_specs()
        self.assertTrue(copied)
        self.assertTrue(all(item.kind in {"skill", "reference"} for item in copied))
        with self.assertRaisesRegex(ValueError, "application-specific adapter"):
            resolve_component_adapter("adewaskar/jarvis").as_component_spec()


if __name__ == "__main__":
    unittest.main()
