"""The Browser Use ARM64 lock ships with the installer and is source-bound."""
import tempfile
import unittest
import hashlib
import json
from pathlib import Path

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.locked_runtime import (
    LockedRuntimeError,
    load_browser_use_lock_bundle,
    stage_browser_use_runtime,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


class LockedRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.bundle = load_browser_use_lock_bundle()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.owned = OwnedRoot(Path(self.temporary.name) / "managed-profile")
        self.owned.ensure()
        contract = resolve_component_adapter("browser-use")
        files = {
            "pyproject.toml": self.bundle.upstream_pyproject,
            "README.md": b"Pinned fixture source\n",
        }
        modes = {name: 0o644 for name in files}
        tree_sha, _ = _git_tree(files, modes)
        content_digest = hashlib.sha256()
        for name in sorted(files):
            content_digest.update(name.encode("utf-8") + b"\0")
            content_digest.update(f"{modes[name]:o}".encode("ascii") + b"\0")
            content_digest.update(hashlib.sha256(files[name]).digest())
        content_sha = content_digest.hexdigest()
        files["INSTALLER-SOURCE-PROVENANCE.json"] = (
            json.dumps({
                "schema": 1,
                "component_id": contract.component_id,
                "source_identity": contract.source_identity,
                "revision": contract.revision,
                "source_tree_sha": tree_sha,
                "source_content_sha256": content_sha,
            }, sort_keys=True).encode() + b"\n"
        )
        modes["INSTALLER-SOURCE-PROVENANCE.json"] = 0o644
        self.source = VerifiedComponentSource(
            component_id=contract.component_id,
            source_identity=contract.source_identity,
            revision=contract.revision,
            files=files,
            file_modes=modes,
            archive_sha256="a" * 64,
            content_sha256=content_sha,
            source_tree_sha=tree_sha,
            license="MIT",
            license_files=(),
            redistribution_license_review_required=False,
        )

    def stage(self):
        with process_lock(self.owned.path("installer.lock")):
            store = GenerationStore(
                self.owned,
                Journal(self.owned.path("journal.sqlite3")),
                mutation_locked=True,
            )
            return stage_browser_use_runtime(self.source, store)

    def test_packaged_bundle_matches_ci_provenance_and_exact_source_manifest(self):
        self.assertEqual(self.bundle.upstream_pyproject,
                         load_browser_use_lock_bundle(source_pyproject=self.source.files["pyproject.toml"]).upstream_pyproject)
        with self.assertRaisesRegex(LockedRuntimeError, "source manifest differs"):
            load_browser_use_lock_bundle(source_pyproject=b"different source")

    def test_stages_complete_source_with_reviewed_overlay_and_transitive_lock(self):
        first = self.stage()
        second = self.stage()
        self.assertEqual(first, second)
        self.assertEqual(self.bundle.overlay_pyproject, (first / "pyproject.toml").read_bytes())
        self.assertEqual(self.bundle.upstream_pyproject,
                         (first / "INSTALLER-UPSTREAM-PYPROJECT.toml").read_bytes())
        self.assertEqual(self.bundle.uv_lock, (first / "uv.lock").read_bytes())
        self.assertEqual(self.bundle.provenance,
                         (first / "INSTALLER-RUNTIME-LOCK-PROVENANCE.json").read_bytes())
        self.assertEqual(b"Pinned fixture source\n", (first / "README.md").read_bytes())

    def test_source_revision_mismatch_fails_before_staging(self):
        from dataclasses import replace
        mismatched = replace(self.source, revision="1" * 40)
        with process_lock(self.owned.path("installer.lock")):
            store = GenerationStore(
                self.owned,
                Journal(self.owned.path("journal.sqlite3")),
                mutation_locked=True,
            )
            with self.assertRaisesRegex(LockedRuntimeError, "immutable runtime pin"):
                stage_browser_use_runtime(mismatched, store)
        self.assertFalse((self.owned.root / "generations" / "browser-use-runtime-c75e8476e26d").exists())


if __name__ == "__main__":
    unittest.main()
