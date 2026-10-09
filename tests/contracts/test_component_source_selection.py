"""Explicit source changes retain immutable Git identity and attribution."""
import unittest

from hermes_installer.components.source_selection import (
    SourceSelectionError,
    select_alternate_source,
    select_component_source,
)


class ComponentSourceSelectionTests(unittest.TestCase):
    def test_current_user_selected_identity_resolves_without_changing_attribution(self):
        chosen = select_component_source(
            "awesome-design",
            identity="bergside/awesome-design-skills",
            url="https://github.com/bergside/awesome-design-skills",
            revision="f631a09b4fcc0166f2e2c1a8c81906ef680c57e8",
            explicit_selection=False,
        )
        self.assertEqual("bergside/awesome-design-skills", chosen.selected_identity)
        self.assertEqual("selected-by-user-star-policy", chosen.source_selection)

    def test_source_update_requires_explicit_selection_and_full_pinned_url(self):
        with self.assertRaisesRegex(SourceSelectionError, "explicit source selection"):
            select_component_source(
                "awesome-design",
                identity="other/design-skills",
                url="https://github.com/other/design-skills",
                revision="a" * 40,
                explicit_selection=False,
            )
        changed = select_component_source(
            "awesome-design",
            identity="other/design-skills",
            url="https://github.com/other/design-skills",
            revision="a" * 40,
            explicit_selection=True,
            license="MIT",
        )
        self.assertEqual("explicit-source-override", changed.source_selection)
        self.assertIsNone(changed.license)
        with self.assertRaisesRegex(SourceSelectionError, "exact HTTPS GitHub"):
            select_component_source(
                "awesome-design",
                identity="other/design-skills",
                url="https://github.com/other/design-skills/tree/main",
                revision="a" * 40,
                explicit_selection=True,
            )

    def test_alternate_repository_is_a_distinct_explicit_choice(self):
        alternate = select_alternate_source("book-to-skill", identity="apple-ouyang/book-to-skill")
        self.assertEqual("apple-ouyang/book-to-skill", alternate.selected_identity)
        self.assertEqual("explicit-source-override", alternate.source_selection)
        self.assertNotEqual("virgiliojr94/book-to-skill", alternate.selected_identity)

    def test_unlisted_candidate_cannot_be_selected_as_an_alternate(self):
        with self.assertRaisesRegex(SourceSelectionError, "not a pinned alternate"):
            select_alternate_source("book-to-skill", identity="other/book-to-skill")


if __name__ == "__main__":
    unittest.main()
