"""Native skill binding stays within one reviewed profile data root."""
import tempfile
import unittest
import hashlib
import os
from pathlib import Path

import yaml

from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.skill_binding import (
    ComponentBindingError,
    SelectedProfileConfigTarget,
    configure_selected_profile_skill,
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

    def test_selected_profile_writer_preserves_config_and_appends_home_relative_root(self):
        class Resolver:
            def resolve_selected_profile(inner_self):
                return SelectedProfileConfigTarget(
                    "default", home, self.profile_root, os.getuid()
                )

        home = self.profile_root.parent / "hermes-home"
        home.mkdir(mode=0o700)
        config = home / "config.yaml"
        original = b"model:\n  default: example/model\nskills:\n  disabled: [legacy]\n  external_dirs: [shared]\n"
        config.write_bytes(original)
        config.chmod(0o600)
        binding = self.with_store(lambda store: stage_component_skill(
            self.source, store, profile_id="default", profile_data_root=self.profile_root
        ))
        receipt = configure_selected_profile_skill(
            binding, Resolver(), expected_config_sha256=hashlib.sha256(original).hexdigest()
        )
        self.assertEqual("configured_pending_native_discovery", receipt.status)
        parsed = yaml.safe_load(config.read_text())
        self.assertEqual("example/model", parsed["model"]["default"])
        self.assertEqual(["legacy"], parsed["skills"]["disabled"])
        self.assertEqual(["shared", str(binding.external_dir)], parsed["skills"]["external_dirs"])
        self.assertEqual(0o600, config.stat().st_mode & 0o777)

    def test_selected_profile_writer_requires_current_revision_and_selected_identity(self):
        class Resolver:
            def __init__(inner_self, profile_id):
                inner_self.profile_id = profile_id

            def resolve_selected_profile(inner_self):
                return SelectedProfileConfigTarget(
                    inner_self.profile_id, home, self.profile_root, os.getuid()
                )

        home = self.profile_root.parent / "hermes-home"
        home.mkdir(mode=0o700)
        binding = self.with_store(lambda store: stage_component_skill(
            self.source, store, profile_id="default", profile_data_root=self.profile_root
        ))
        with self.assertRaisesRegex(ComponentBindingError, "revision changed"):
            configure_selected_profile_skill(binding, Resolver("default"), expected_config_sha256="0" * 64)
        with self.assertRaisesRegex(ComponentBindingError, "does not match"):
            configure_selected_profile_skill(binding, Resolver("another"), expected_config_sha256=None)

    def test_selected_profile_writer_rejects_generation_outside_owned_data(self):
        from dataclasses import replace

        class Resolver:
            def resolve_selected_profile(inner_self):
                return SelectedProfileConfigTarget("default", home, self.profile_root, os.getuid())

        home = self.profile_root.parent / "hermes-home"
        home.mkdir(mode=0o700)
        binding = self.with_store(lambda store: stage_component_skill(
            self.source, store, profile_id="default", profile_data_root=self.profile_root
        ))
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        with self.assertRaisesRegex(ComponentBindingError, "escaped"):
            configure_selected_profile_skill(
                replace(binding, external_dir=outside), Resolver(), expected_config_sha256=None
            )

    def test_selected_profile_writer_rejects_user_controlled_symlink_ancestors(self):
        class Resolver:
            def resolve_selected_profile(inner_self):
                return SelectedProfileConfigTarget("default", linked_home, self.profile_root, os.getuid())

        real_home = self.profile_root.parent / "real-home"
        real_home.mkdir(mode=0o700)
        linked_home = self.profile_root.parent / "linked-home"
        linked_home.symlink_to(real_home, target_is_directory=True)
        binding = self.with_store(lambda store: stage_component_skill(
            self.source, store, profile_id="default", profile_data_root=self.profile_root
        ))
        with self.assertRaisesRegex(ComponentBindingError, "may not contain symlinks"):
            configure_selected_profile_skill(binding, Resolver(), expected_config_sha256=None)


if __name__ == "__main__":
    unittest.main()
