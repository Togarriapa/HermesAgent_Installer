"""Effect contracts for the explicitly separate manual Jarvis skill MVP.

These tests are prepared for an authorized isolated target only; do not run them
on a developer workstation against a real Hermes home.
"""
import hashlib
import io
import json
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from hermes_installer.registry.manual_jarvis_skills import (
    _BUNDLE_PROFILE_COUNT,
    _BUNDLE_SKILL_COUNT,
    ManualJarvisSkillsError,
    PRIMARY_SKILLS,
    _read_artifact,
    build_manual_jarvis_skills_artifact,
    install_and_verify_manual_jarvis_skills,
    install_manual_jarvis_skills,
)
from hermes_installer.registry.native_install import NativeInstallReceipt


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
            _manifest, artifact_files = _read_artifact(self.bundle, self.digest)
            self.assertEqual(len(journal["members"]), len(artifact_files))
            expected_skill_paths = {
                f"installer-resources-113f42d33be9/{name}"
                for name in artifact_files if name.startswith("skills/")
            }
            self.assertEqual(
                {row["path"] for row in journal["members"]
                 if row["path"].startswith("installer-resources-113f42d33be9/skills/")
                 and row["path"].endswith("/SKILL.md")},
                expected_skill_paths)
            self.assertEqual(len(list((generation / "skills").glob("*/SKILL.md"))), _BUNDLE_SKILL_COUNT)
            self.assertEqual(len(list((generation / "registry/profiles").glob("*/SOUL.md"))), _BUNDLE_PROFILE_COUNT)
            self.assertFalse((home / "profiles").exists())
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
                             {target.name, "user-owned"})
            self.assertEqual((home / "skills/user-owned/SKILL.md").read_text(), "user bytes\n")

    def test_modified_owned_skill_is_preserved_and_rerun_refuses_adoption(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            result = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            skill = Path(result["generation_path"]) / "skills/conversation-gateway/SKILL.md"
            skill.write_text("user edit\n", encoding="utf-8")
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(skill.read_text(), "user edit\n")

    def test_import_receipt_requires_actual_native_readback_for_every_bundled_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            manifest, files = _read_artifact(self.bundle, self.digest)
            skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
            content_digests = {
                f"skill:{name}": hashlib.sha256(files[f"skills/{name}/SKILL.md"]).hexdigest()
                for name in skill_ids
            }
            content_digests["profile:default"] = hashlib.sha256(
                files["registry/profiles/hermes/SOUL.md"]).hexdigest()
            receipt = NativeInstallReceipt(
                hermes_revision="7085fbf7753266fc4943c55ac04926186bc90005",
                python_version="3.14.7", profile_id="default", discovered_profile=True,
                profile_identity_loaded=True, profile_display_name="Jarvis",
                discovered_skills=skill_ids, loaded_skills=skill_ids,
                content_digests=content_digests,
            )
            with patch("hermes_installer.registry.native_install.discover_and_load_selected",
                       return_value=receipt) as discover:
                result = install_and_verify_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest,
                    hermes_source="/pin/hermes", python="/pin/python")
            self.assertEqual(result["state"], "discovered")
            self.assertTrue(result["discovered"])
            self.assertEqual(result["resource_counts"]["native_skills"], _BUNDLE_SKILL_COUNT)
            self.assertEqual(result["resource_counts"]["internal_profiles"], _BUNDLE_PROFILE_COUNT - 1)
            self.assertEqual(result["native_receipt"]["loaded_skill_count"], _BUNDLE_SKILL_COUNT)
            self.assertEqual(set(result["selectable_profile_mutations"]), set())
            self.assertTrue(result["native_receipt"]["active_prompt_matches_bundled_primary"])
            discover.assert_called_once()
            self.assertEqual(set(discover.call_args.kwargs["skill_ids"]), set(skill_ids))

    def test_import_never_claims_native_discovery_when_loaded_bytes_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            manifest, files = _read_artifact(self.bundle, self.digest)
            skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
            content_digests = {
                f"skill:{name}": hashlib.sha256(files[f"skills/{name}/SKILL.md"]).hexdigest()
                for name in skill_ids
            }
            content_digests["skill:" + skill_ids[0]] = "0" * 64
            receipt = NativeInstallReceipt(
                hermes_revision="7085fbf7753266fc4943c55ac04926186bc90005",
                python_version="3.14.7", profile_id="default", discovered_profile=True,
                profile_identity_loaded=True, profile_display_name="Jarvis",
                discovered_skills=skill_ids, loaded_skills=skill_ids,
                content_digests=content_digests,
            )
            with patch("hermes_installer.registry.native_install.discover_and_load_selected",
                       return_value=receipt):
                with self.assertRaises(ManualJarvisSkillsError):
                    install_and_verify_manual_jarvis_skills(
                        self.bundle, hermes_home=home, expected_sha256=self.digest,
                        hermes_source="/pin/hermes", python="/pin/python")
            self.assertTrue((home / "skills/installer-resources-113f42d33be9").is_dir())

    def test_artifact_reader_rejects_duplicate_archive_members(self):
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.bundle), "r") as original:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as changed:
                    for info in original.infolist():
                        changed.writestr(info.filename, original.read(info.filename))
                    duplicate = next(name for name in original.namelist()
                                     if name.startswith("skills/") and name.endswith("/SKILL.md"))
                    changed.writestr(duplicate, original.read(duplicate))
        data = output.getvalue()
        with self.assertRaises(ManualJarvisSkillsError):
            _read_artifact(data, hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
