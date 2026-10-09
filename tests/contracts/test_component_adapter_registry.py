"""Pinned adapter contracts retain every non-MCP source identity."""
import unittest

from hermes_installer.components.adapters import (
    COMPONENT_ADAPTERS,
    MCP_COMPONENT_IDS,
    resolve_component_adapter,
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
