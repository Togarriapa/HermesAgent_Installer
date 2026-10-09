"""Native skill binding stays within one reviewed profile data root."""
import tempfile
import unittest
from pathlib import Path

from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_binding import (
    ComponentBindingError,
    stage_component_skill,
)
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


class ComponentSkillBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.profile_root = Path(self.temporary.name) / "profiles" / "default"
        self.owned = OwnedRoot(self.profile_root)
        self.owned.ensure()
        contract = resolve_component_adapter("affaan-m/ECC")
        files = {
            "skills/demo/SKILL.md": b"---\nname: Demo\ndescription: fixture\n---\n[helper](scripts/check.py)\n",
            "skills/demo/scripts/check.py": b"print('fixture')\n",
            "LICENSE": b"MIT fixture\n",
        }
        modes = {name: 0o644 for name in files}
        self.source = VerifiedComponentSource(
            component_id=contract.component_id,
            source_identity="affaan-m/ECC",
            revision="ef648e01899ba3e8dc6371642deaaf64b4477775",
            files=files,
            file_modes=modes,
            archive_sha256="a" * 64,
            content_sha256="b" * 64,
            source_tree_sha=_git_tree(files, modes)[0],
            license="MIT",
            license_files=("LICENSE",),
            redistribution_license_review_required=False,
        )

    def with_store(self, callback):
        with process_lock(self.owned.path("installer.lock")):
            journal = Journal(self.owned.path("journal.sqlite3"))
            store = GenerationStore(self.owned, journal, mutation_locked=True)
            return callback(store)

    def test_stages_verified_source_only_under_selected_profile_and_returns_binding(self):
        result = self.with_store(lambda store: stage_component_skill(
            self.source, store, profile_id="default", profile_data_root=self.profile_root
        ))
        self.assertEqual("default", result.profile_id)
        self.assertEqual(("skills/demo/SKILL.md",), result.skill_files)
        self.assertEqual(("Demo",), result.names)
        self.assertEqual("staged_pending_native_discovery", result.status)
        self.assertTrue(result.external_dir.is_relative_to(self.profile_root.resolve()))
        self.assertEqual(
            self.source.files["skills/demo/scripts/check.py"],
            (result.external_dir / "skills/demo/scripts/check.py").read_bytes(),
        )

    def test_rejects_cross_profile_store_and_unsafe_profile_id(self):
        other = self.profile_root.parent / "another"
        other_owned = OwnedRoot(other)
        other_owned.ensure()
        with process_lock(other_owned.path("installer.lock")):
            store = GenerationStore(other_owned, Journal(other_owned.path("journal.sqlite3")), mutation_locked=True)
            with self.assertRaisesRegex(ComponentBindingError, "not rooted"):
                stage_component_skill(self.source, store, profile_id="default", profile_data_root=self.profile_root)
        with self.assertRaisesRegex(ComponentBindingError, "safe native profile"):
            self.with_store(lambda store: stage_component_skill(
                self.source, store, profile_id="../other", profile_data_root=self.profile_root
            ))

    def test_private_profile_binding_preserves_separate_redistribution_review(self):
        from dataclasses import replace
        blocked = replace(self.source, redistribution_license_review_required=True)
        result = self.with_store(lambda store: stage_component_skill(
            blocked, store, profile_id="default", profile_data_root=self.profile_root
        ))
        self.assertTrue(result.redistribution_license_review_required)
        self.assertTrue(result.external_dir.is_relative_to(self.profile_root.resolve()))


if __name__ == "__main__":
    unittest.main()
