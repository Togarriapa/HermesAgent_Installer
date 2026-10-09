"""Reference integrity prevents incomplete helper/asset trees from importing."""
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.skill_refs import audit_skill_file_map, audit_skill_references


class SkillReferenceAuditTests(unittest.TestCase):
    def test_resolves_skill_helper_asset_and_transitive_shared_markdown(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "skills" / "replica"
            (skill / "assets").mkdir(parents=True)
            (root / "shared").mkdir()
            (skill / "SKILL.md").write_text(
                "[shared helper](../../shared/helper.md)\n[asset](assets/sample.txt)\n",
                encoding="utf-8",
            )
            (root / "shared" / "helper.md").write_text(
                "See [root reference](../README.md).\n", encoding="utf-8"
            )
            (root / "shared" / "helper.py").write_text("print('fixture')\n", encoding="utf-8")
            (root / "README.md").write_text("shared root reference\n", encoding="utf-8")
            (skill / "assets" / "sample.txt").write_text("fixture\n", encoding="utf-8")

            audit = audit_skill_references(root)

            self.assertTrue(audit.complete, audit.problems)
            self.assertIn("shared/helper.md", audit.resolved_targets)
            self.assertIn("README.md", audit.resolved_targets)
            self.assertIn("skills/replica/assets/sample.txt", audit.resolved_targets)

    def test_reports_missing_helper_and_escape_without_resolving_them(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "skills" / "replica"
            skill.mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "[missing](scripts/missing.py)\n[outside](../../../outside.md)\n",
                encoding="utf-8",
            )

            audit = audit_skill_references(root)

            self.assertFalse(audit.complete)
            self.assertEqual(2, len(audit.problems))
            self.assertEqual("referenced file or directory is missing", audit.problems[0].reason)
            self.assertEqual("relative path escapes the bundled source tree", audit.problems[1].reason)
            self.assertEqual((), audit.resolved_targets)

    def test_audits_pinned_archive_mapping_before_filesystem_staging(self):
        files = {
            "skills/demo/SKILL.md": b"[helper](scripts/check.py)\\n",
            "skills/demo/scripts/check.py": b"print('ok')\\n",
            "shared/README.md": b"shared data\\n",
        }
        audit = audit_skill_file_map(files)
        self.assertTrue(audit.complete, audit.problems)
        self.assertIn("skills/demo/scripts/check.py", audit.resolved_targets)

        with self.assertRaisesRegex(ValueError, "unsafe path"):
            audit_skill_file_map({"../outside.md": b"bad"})

    def test_ignores_markdown_link_examples_inside_code_but_checks_prose(self):
        files = {
            "skills/demo/SKILL.md": (
                b"See `[missing](inline-example.md)` in this code sample.\n"
                b"\n```python\nprint('[missing](fenced-example.md)')\n```\n"
                b"\n    [missing](indented-example.md)\n"
                b"\n[real missing](actual-missing.md)\n"
            ),
        }
        audit = audit_skill_file_map(files)
        self.assertEqual(1, len(audit.problems))
        self.assertEqual("actual-missing.md", audit.problems[0].target)

    def test_reports_symlinked_helper_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            skill = root / "skills" / "replica"
            skill.mkdir(parents=True)
            outside = root / "outside.py"
            outside.write_text("pass\n", encoding="utf-8")
            (skill / "SKILL.md").write_text("[helper](helper.py)\n", encoding="utf-8")
            (skill / "helper.py").symlink_to(outside)

            audit = audit_skill_references(root)

            self.assertFalse(audit.complete)
            self.assertEqual("reference traverses a symlink", audit.problems[0].reason)


if __name__ == "__main__":
    unittest.main()
