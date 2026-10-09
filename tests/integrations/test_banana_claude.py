"""Banana source pin and safe image-generation availability boundary."""
import os
import subprocess
import unittest
from pathlib import Path

from hermes_installer.components.banana_claude import banana_claude_status
from hermes_installer.components.skill_refs import audit_skill_references


SOURCE = Path(os.environ.get("HERMES_BANANA_CLAUDE_SOURCE", "/missing/banana-claude"))
PIN = "6a2b1b51fdcc35932184f06e513646a6f6f4f7d8"


@unittest.skipUnless(SOURCE.is_dir(), "set HERMES_BANANA_CLAUDE_SOURCE to the pinned upstream checkout")
class BananaClaudeTests(unittest.TestCase):
    def test_selected_source_tree_is_complete_and_generation_fails_closed(self):
        self.assertEqual(PIN, subprocess.check_output(
            ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
        ).strip())
        self.assertEqual("AgriciDaniel/banana-claude", subprocess.check_output(
            ["git", "-C", str(SOURCE), "remote", "get-url", "origin"], text=True
        ).strip().removesuffix(".git").removesuffix("/" ).rsplit("github.com/", 1)[-1])
        audit = audit_skill_references(SOURCE)
        self.assertIn("skills/banana/SKILL.md", audit.skill_files)
        self.assertFalse(audit.problems)

        status = banana_claude_status()
        self.assertFalse(status.generation_available)
        self.assertEqual("unavailable", status.generation_status)
        self.assertFalse(status.automatic_paid_generation)
        self.assertIn("image route", status.reason)


if __name__ == "__main__":
    unittest.main()
