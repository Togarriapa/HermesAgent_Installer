"""Effect contracts for the explicitly separate manual Jarvis skill MVP.

These tests are prepared for an authorized isolated target only; do not run them
on a developer workstation against a real Hermes home.
"""
import hashlib
import io
import json
import os
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
    _verify_owner_skill_overlay_transition,
    build_manual_jarvis_skills_artifact,
    install_and_verify_manual_jarvis_skills,
    install_manual_jarvis_skills,
    _verify_owned_generation,
)
from hermes_installer.registry.resources_skill_overlay import (
    ResourcesSkillOverlayError, build_effective_artifact, pinned_skill_bytes,
)
from hermes_installer.registry.native_install import NativeInstallReceipt
from hermes_installer.registry.jarvis_master_semantics import (
    JarvisSemanticsError,
    effective_profile_spec,
    overlay_identity,
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

    def test_compiled_master_semantics_are_distinct_from_verbatim_upstream(self):
        manifest, files = _read_artifact(self.bundle, self.digest)
        overlay = manifest["effective_overlay"]
        profiles = {row["source_id"]: row for row in manifest["profile_members"]}
        self.assertEqual(overlay["overlay_id"], "jarvis-master-semantics-v2")
        self.assertEqual(overlay["approval_commit"], "aab3b666023559c0d9112633212e0194dcc7af97")
        self.assertEqual(overlay["sha256"], overlay_identity()["sha256"])
        self.assertEqual(len(manifest["skill_members"]), 396)
        self.assertEqual(len(manifest["profile_members"]), 208)
        self.assertEqual(set(overlay["compiled_profiles"]), {"hermes", "orchestrator"})
        for profile_id in ("hermes", "orchestrator"):
            row = profiles[profile_id]
            self.assertNotEqual(row["upstream_compiled_identity_sha256"], row["identity_sha256"])
            original = files[f"registry/package/upstream-source/profiles/{profile_id}.yaml"]
            self.assertNotEqual(row["source_document_sha256"], row["source_declaration_sha256"])
            self.assertEqual(hashlib.sha256(original).hexdigest(), row["source_declaration_sha256"])
            self.assertEqual(overlay["source_declarations"][f"profiles/{profile_id}.yaml"],
                             hashlib.sha256(original).hexdigest())
        for profile_id, row in profiles.items():
            if profile_id not in {"hermes", "orchestrator"}:
                self.assertEqual(row["upstream_compiled_identity_sha256"], row["identity_sha256"])
        jarvis = files["registry/profiles/hermes/SOUL.md"].decode("utf-8")
        coordinator = files["registry/profiles/orchestrator/SOUL.md"].decode("utf-8")
        self.assertIn("sole user-facing MASTER", jarvis)
        self.assertIn("OneShot", jarvis)
        self.assertIn("Only Jarvis may make the final", jarvis)
        self.assertIn("not a mandatory hop", jarvis)
        self.assertNotIn("Compose every user-facing response using all six sections", jarvis)
        self.assertIn("directSpecialistDispatch: internal-only", jarvis)
        self.assertIn("without creating a project board", coordinator)
        self.assertIn("Never publish or perform final external", coordinator)
        self.assertEqual(hashlib.sha256(
            files[overlay["compiled_bundle"]["effective_archive_path"]]).hexdigest(),
            overlay["compiled_bundle"]["effective_sha256"])

    def test_master_overlay_rejects_unpinned_upstream_source(self):
        with self.assertRaises(JarvisSemanticsError):
            effective_profile_spec("hermes", {"instructions": []},
                                   {"revision": "0" * 40, "source_tree": "1" * 40})

    def test_generation_migration_proof_rejects_any_modified_owned_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            staged = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            _manifest, files = _read_artifact(self.bundle, self.digest)
            generation = Path(staged["generation_path"])
            expected_dirs = {
                "/".join(Path(name).parts[:depth])
                for name in files for depth in range(1, len(Path(name).parts))
            }
            self.assertEqual(_verify_owned_generation(generation, files, self.digest), expected_dirs)
            victim = generation / "registry/profiles/orchestrator/SOUL.md"
            victim.write_bytes(victim.read_bytes() + b"user edit")
            with self.assertRaises(ManualJarvisSkillsError):
                _verify_owned_generation(generation, files, self.digest)

    def test_resources_skill_overlay_changes_only_selected_pinned_document(self):
        original_manifest, original_files = _read_artifact(self.bundle, self.digest)
        skill_id = "conversation-gateway"
        original = pinned_skill_bytes(self.bundle, skill_id)
        edited = original + b"\nOwner note: use the reviewed local gateway.\n"
        effective, effective_sha = build_effective_artifact(self.bundle, skill_id, edited)
        next_manifest, next_files = _read_artifact(effective, effective_sha)
        self.assertEqual(original_files, _read_artifact(self.bundle, self.digest)[1])
        changed = {name for name in original_files if original_files[name] != next_files[name]}
        self.assertEqual(changed, {f"skills/{skill_id}/SKILL.md"})
        self.assertEqual(next_files[f"skills/{skill_id}/SKILL.md"], edited)
        self.assertEqual(next_manifest["source"], original_manifest["source"])
        self.assertEqual(next_manifest["profile_members"], original_manifest["profile_members"])
        _verify_owner_skill_overlay_transition(original_manifest, original_files, self.digest,
                                               next_manifest, next_files)

    def test_resources_skill_overlay_rejects_identity_change_and_protected_delta(self):
        with self.assertRaises(ResourcesSkillOverlayError):
            build_effective_artifact(self.bundle, "conversation-gateway",
                b"---\nname: other-skill\n\nnot the selected identity\n")
        original_manifest, original_files = _read_artifact(self.bundle, self.digest)
        effective, effective_sha = build_effective_artifact(self.bundle, "conversation-gateway",
            pinned_skill_bytes(self.bundle, "conversation-gateway") + b"\nowner edit\n")
        next_manifest, next_files = _read_artifact(effective, effective_sha)
        protected = "registry/profiles/orchestrator/SOUL.md"
        altered_files = dict(next_files)
        altered_files[protected] += b"unexpected change"
        with self.assertRaises(ManualJarvisSkillsError):
            _verify_owner_skill_overlay_transition(original_manifest, original_files, self.digest,
                                                   next_manifest, altered_files)

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

    def test_nested_generation_permissions_ignore_umask_and_repair_only_verified_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            previous = os.umask(0o002)
            try:
                result = install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            finally:
                os.umask(previous)
            generation = Path(result["generation_path"])
            nested = generation / "skills" / "conversation-gateway"
            self.assertEqual(nested.stat().st_mode & 0o777, 0o755)
            nested.chmod(0o775)
            unrelated = home / "skills" / "user-owned"
            unrelated.chmod(0o775)

            repeated = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)

            self.assertEqual(repeated["state"], "already-staged")
            self.assertEqual(nested.stat().st_mode & 0o777, 0o755)
            self.assertEqual(unrelated.stat().st_mode & 0o777, 0o775)

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
