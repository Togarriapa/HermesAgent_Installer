"""Static provenance and separation tests for the reviewed cc81 predecessor cohort."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

from hermes_installer.authority import installer_release as release


class InstalledPredecessorCohortTests(unittest.TestCase):
    def test_compiled_historical_data_matches_the_reviewed_append_only_artifact(self) -> None:
        artifact = Path(__file__).resolve().parents[2] / (
            "plans/amendments/2026-10-10-version-aware-predecessor-verification-v249/"
            "cc81-reviewed-predecessor-cohort-v1.json")
        raw = artifact.read_bytes()
        self.assertEqual(len(raw), 29_545)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), release._CC81_COHORT_SHA256)
        self.assertEqual(raw.decode("utf-8"), release._CC81_COHORT_JSON)
        value = json.loads(raw)
        constants = value["constants"]
        self.assertEqual(value["cohort_id"], release._CC81_COHORT_ID)
        self.assertEqual(value["candidate_git_sha"], release._CC81_CANDIDATE)
        self.assertEqual(len(constants["REVIEWED_SOURCE_MODULES"]), 59)
        self.assertEqual(len(value["source_blobs"]), 5)
        self.assertEqual(
            next(row[2] for row in constants["REVIEWED_SOURCE_MODULES"]
                 if row[1] == "lib/python/hermes_installer/root_setup.py"),
            "5bd49b6e0105d65d342302df953ed41f6ab0f0edd2bb90d7e7c2b4b4ada30563")

    def test_old_module_uses_the_whole_selected_cohort_while_current_pins_stay_separate(self) -> None:
        historical = release._historical_cohort(release._CC81_CANDIDATE)
        old = next(row for row in historical["REVIEWED_SOURCE_MODULES"]
                   if row[1] == "lib/python/hermes_installer/root_setup.py")
        self.assertEqual(release._artifact_id_for(old[1], ["module"], cohort=historical), old[0])
        release._validate_fixed_layout_role(old[1], old[2], old[3], ["module"], cohort=historical)
        old_module_rows = {
            row[0]: release.VerifiedReleaseFile(row[0], (row[4],), row[1], row[2], row[3], 1, 1, 0o444)
            for row in historical["REVIEWED_SOURCE_MODULES"] if row[4] == "module"
        }
        old_source_rows = {
            row[0]: release.VerifiedReleaseFile(row[0], (row[4],), row[1], row[2], row[3], 1, 1, 0o444)
            for row in historical["REVIEWED_SOURCE_MODULES"] if row[4] == "source-module"
        }
        release._verify_reviewed_module_rows(old_module_rows, old_source_rows, cohort=historical)
        current = {row[0]: release.VerifiedReleaseFile(
            row[0], (row[4],), row[1], row[2], row[3], 1, 1, 0o444)
                   for row in release.REVIEWED_SOURCE_MODULES if row[4] == "module"}
        current_sources = {row[0]: release.VerifiedReleaseFile(
            row[0], (row[4],), row[1], row[2], row[3], 1, 1, 0o444)
                           for row in release.REVIEWED_SOURCE_MODULES if row[4] == "source-module"}
        self.assertNotEqual(old[2], current[old[0]].sha256)
        with self.assertRaises(release.InstallerReleaseError):
            release._verify_reviewed_module_rows(current, current_sources, cohort=historical)

    def test_historical_selector_is_exact_and_does_not_fallback_for_unknown_versions(self) -> None:
        cohort = release._historical_cohort(release._CC81_CANDIDATE)
        self.assertIsNotNone(cohort)
        self.assertEqual(len(cohort["REVIEWED_SOURCE_MODULES"]), 59)
        self.assertIsNone(release._historical_cohort("f" * 40))
        self.assertIsNone(release._historical_cohort("cc81abffe3cbb1df447889bca269d1e6c0be77eb"))

    def test_complete_historical_tree_reconstruction_uses_git_modes_and_detects_mixing(self) -> None:
        entries = {
            "a": (0o444, bytes.fromhex("5626abf0f72e58d7a153368ba57db4c673c0e171")),
            "x/b": (0o555, bytes.fromhex("f719efd430d52bcfc8566a43b2eb655688d38871")),
        }
        # Independently produced with git write-tree for files "a" and "x/b".
        expected = "c32e7b5922c2fff7fd6c974ae61430413dc589cb"
        self.assertEqual(release._git_tree_sha1_from_entries(entries), expected)
        changed = dict(entries)
        changed["x/b"] = (0o444, entries["x/b"][1])
        self.assertNotEqual(release._git_tree_sha1_from_entries(changed), expected)
        mixed_collision = {"a": entries["a"], "a/b": entries["x/b"]}
        with self.assertRaises(release.InstallerReleaseError):
            release._git_tree_sha1_from_entries(mixed_collision)

    def test_predecessor_receipt_is_distinct_and_cannot_open_actor_modules(self) -> None:
        self.assertIsNot(release.VerifiedInstallerPredecessorReleaseReceipt,
                         release.VerifiedInstallerReleaseReceipt)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            info = root.stat()
            receipt = release.VerifiedInstallerPredecessorReleaseReceipt(
                release._PREDECESSOR_SEAL, release_root=root, release_commit=release._CC81_CANDIDATE,
                deployment_receipt_sha256="0" * 64, root_device=info.st_dev, root_inode=info.st_ino,
                closure_manifest_relative_path="manifest.json", closure_manifest_sha256="1" * 64,
                baseline_tag_object="2" * 40, baseline_commit="3" * 40,
                baseline_tree_sha256="4" * 64, amendment_manifest_sha256="5" * 64,
                files=(), selected_plan_artifact_id="plan", selected_plan_sha256="6" * 64,
                root_fd=os.open(root, os.O_RDONLY | os.O_DIRECTORY), expected_uid=os.getuid(),
                historical_cohort_id=release._CC81_COHORT_ID,
                historical_cohort_sha256=release._CC81_COHORT_SHA256)
            try:
                for call in (lambda: receipt.open_file("anything"),
                             lambda: receipt.resolve_reviewed_source_module("anything"),
                             lambda: receipt.resolve_reviewed_source_artifact("anything")):
                    with self.assertRaises(release.InstallerReleaseError):
                        call()
            finally:
                receipt.close()


if __name__ == "__main__":
    unittest.main()
