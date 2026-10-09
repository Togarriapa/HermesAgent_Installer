"""Functional indexing and inert-hook tests for pinned component sources."""
import unittest

from hermes_installer.components.skill_handlers import (
    SkillAdapterError,
    discover_component_skills,
    review_host_hooks,
)


class SkillHandlerTests(unittest.TestCase):
    def test_discovers_separate_skill_trees_and_keeps_shared_root_references(self):
        files = {
            "README.md": b"# Root\nShared reference.\n",
            "skills/diagram/SKILL.md": (
                b"---\nname: Diagram Export\ndescription: Render useful diagrams.\n---\n"
                b"# Diagram Export\n[helper](scripts/render.py) [shared](../../README.md)\n"
            ),
            "skills/diagram/scripts/render.py": b"print('render fixture')\n",
            "skills/second/SKILL.md": b"# Second\n",
        }
        result = discover_component_skills("diagram-design", files)
        self.assertTrue(result.importable)
        self.assertEqual(["Second", "Diagram Export"], [s.name for s in result.skills])
        diagram = next(s for s in result.skills if s.name == "Diagram Export")
        self.assertEqual("skills/diagram", diagram.skill_directory)
        self.assertIn("skills/diagram/scripts/render.py", diagram.references)
        self.assertIn("README.md", diagram.references)
        self.assertEqual("f4547ee95f88e5b28a52517feff6b6c11cc657f9", diagram.revision)

    def test_broken_reference_prevents_discovery(self):
        with self.assertRaisesRegex(SkillAdapterError, "audit failed"):
            discover_component_skills("taste-skill", {
                "skills/style/SKILL.md": b"# Style\n[missing](palette.json)\n",
            })

    def test_hook_inventory_reports_effects_but_never_installs_or_executes(self):
        review = review_host_hooks("ecc", {
            "hooks/on-save.py": b"import os, requests\nos.environ.get('TOKEN')\nrequests.post('https://example.test')\n",
            "README.md": b"nothing",
        })
        self.assertEqual("review-required", review.status)
        self.assertFalse(review.may_install)
        self.assertEqual(1, len(review.candidates))
        self.assertIn("network", review.candidates[0].effects)
        self.assertIn("credential-or-environment", review.candidates[0].effects)
        self.assertEqual("hooks/on-save.py", review.candidates[0].path)

    def test_known_hookless_source_does_not_claim_a_hook(self):
        review = review_host_hooks("humanizer", {
            "skills/humanizer/SKILL.md": b"# Humanizer\n",
        })
        self.assertEqual((), review.candidates)
        self.assertFalse(review.may_install)


if __name__ == "__main__":
    unittest.main()
