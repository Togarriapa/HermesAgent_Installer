"""Pinned Brag source checks with rendering/narration kept honest."""
import os
import subprocess
import unittest
from pathlib import Path

from hermes_installer.components.latent_spaces_brag import latent_spaces_brag_status
from hermes_installer.components.skill_refs import audit_skill_references


SOURCE = Path(os.environ.get("HERMES_LATENT_SPACES_BRAG_SOURCE", "/missing/brag"))
PIN = "7079945d391573edebe48fdc0a23b39c4b4e8726"


@unittest.skipUnless(SOURCE.is_dir(), "set HERMES_LATENT_SPACES_BRAG_SOURCE to the pinned upstream checkout")
class LatentSpacesBragTests(unittest.TestCase):
    def test_pinned_skills_and_local_assets_resolve_without_registering_a_second_renderer(self):
        self.assertEqual(PIN, subprocess.check_output(
            ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
        ).strip())
        audit = audit_skill_references(SOURCE)
        self.assertIn("skills/brag/SKILL.md", audit.skill_files)
        self.assertIn("skills/brag-slim/SKILL.md", audit.skill_files)
        self.assertFalse(audit.problems)
        self.assertTrue((SOURCE / "skills/brag/assets/music").is_dir())

        default = latent_spaces_brag_status()
        voice = latent_spaces_brag_status(narration_requested=True)
        self.assertEqual("hyperframes", default.renderer_component)
        self.assertFalse(default.installs_renderer)
        self.assertFalse(default.rendering_available)
        self.assertIn("fixed Hyperframes smoke fixture", default.render_status)
        self.assertFalse(default.narration_available)
        self.assertEqual("disabled: narration is opt-in", default.narration_status)
        self.assertIn("no eligible narration account and metered budget", voice.narration_status)


if __name__ == "__main__":
    unittest.main()
