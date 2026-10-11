"""Effect contracts for the explicitly separate manual Jarvis skill MVP.

These tests are prepared for an authorized isolated target only; do not run them
on a developer workstation against a real Hermes home.
"""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hermes_installer.registry.manual_jarvis_skills import (
    ManualJarvisSkillsError,
    PRIMARY_SKILLS,
    build_manual_jarvis_skills_artifact,
    install_manual_jarvis_skills,
)


class ManualJarvisSkillsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = build_manual_jarvis_skills_artifact()
        cls.digest = hashlib.sha256(cls.bundle).hexdigest()

    def make_home(self, root):
        home = Path(root) / ".hermes"
        home.mkdir()
        (home / "SOUL.md").write_text("# Jarvis\n", encoding="utf-8")
        (home / "config.yaml").write_text("provider: existing\n", encoding="utf-8")
        (home / "memories").mkdir()
        (home / "memories" / "keep.txt").write_text("preserve me\n", encoding="utf-8")
        (home / "skills").mkdir()
        (home / "skills" / "user-owned").mkdir()
        (home / "skills" / "user-owned" / "SKILL.md").write_text("user bytes\n", encoding="utf-8")
        return home

    def test_stage_is_namespaced_owned_idempotent_and_preserves_existing_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            before = {
                "soul": (home / "SOUL.md").read_bytes(),
                "config": (home / "config.yaml").read_bytes(),
                "memory": (home / "memories" / "keep.txt").read_bytes(),
                "user_skill": (home / "skills/user-owned/SKILL.md").read_bytes(),
            }
            result = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(result["state"], "staged")
            self.assertFalse(result["discovered"])
            generation = Path(result["generation_path"])
            journal = json.loads((generation / ".hermes-installer-resource-ownership.json").read_text())
            self.assertEqual(len(journal["members"]), 4)
            self.assertEqual(
                {p.parent.name for p in generation.glob("*/SKILL.md")}, set(PRIMARY_SKILLS))
            self.assertEqual((home / "SOUL.md").read_bytes(), before["soul"])
            self.assertEqual((home / "config.yaml").read_bytes(), before["config"])
            self.assertEqual((home / "memories/keep.txt").read_bytes(), before["memory"])
            self.assertEqual((home / "skills/user-owned/SKILL.md").read_bytes(), before["user_skill"])

            again = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(again["state"], "already-staged")
            self.assertEqual(again["generation_path"], result["generation_path"])

    def test_unowned_generation_conflict_and_wrong_bundle_digest_fail_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            target = home / "skills/installer-resources-113f42d33be9"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("unowned bytes\n", encoding="utf-8")
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256="0" * 64)
            self.assertEqual(sentinel.read_text(), "unowned bytes\n")
            self.assertEqual(set(p.name for p in (home / "skills").iterdir()),
                             {target.name})

    def test_modified_owned_skill_is_preserved_and_rerun_refuses_adoption(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            result = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            skill = Path(result["generation_path"]) / "conversation-gateway/SKILL.md"
            skill.write_text("user edit\n", encoding="utf-8")
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(skill.read_text(), "user edit\n")


if __name__ == "__main__":
    unittest.main()
