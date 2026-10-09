"""Functional fixture for the pinned, local-only public API reference catalog."""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.public_apis_public_apis import (
    COMPONENT_ID,
    install_public_apis_catalog,
    search_public_apis_catalog,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


def _pinned_fixture_source() -> VerifiedComponentSource:
    """Build a synthetic catalog tree with the reviewed source identity/pin."""
    contract = resolve_component_adapter(COMPONENT_ID)
    source_files = {
        "LICENSE": b"MIT License fixture; synthetic test content.\n",
        "README.md": (
            b"# Public APIs\n"
            b"\n"
            b"### Animals\n"
            b"| API | Description | Auth | HTTPS | CORS |\n"
            b"| --- | --- | --- | --- | --- |\n"
            b"| Cat Facts | Daily cat facts | No | Yes | Yes |\n"
        ),
    }
    modes = {path: 0o644 for path in source_files}
    content_digest = hashlib.sha256()
    for path in sorted(source_files):
        content_digest.update(path.encode("utf-8") + b"\0")
        content_digest.update(b"644\0")
        content_digest.update(hashlib.sha256(source_files[path]).digest())
    content_sha = content_digest.hexdigest()
    tree_sha, _ = _git_tree(source_files, modes)
    archive_sha = "a" * 64
    provenance = {
        "schema": 1,
        "component_id": contract.component_id,
        "source_identity": contract.source_identity,
        "source_url": contract.selected_source_url,
        "revision": contract.revision,
        "source_selection": contract.source_selection,
        "source_archive_sha256": archive_sha,
        "source_content_sha256": content_sha,
        "source_tree_sha": tree_sha,
        "declared_license": contract.license,
        "license_files": ["LICENSE"],
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    staged_files = dict(source_files)
    staged_files["INSTALLER-SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    return VerifiedComponentSource(
        component_id=contract.component_id,
        source_identity=contract.source_identity,
        revision=contract.revision,
        files=staged_files,
        file_modes={**modes, "INSTALLER-SOURCE-PROVENANCE.json": 0o644},
        archive_sha256=archive_sha,
        content_sha256=content_sha,
        source_tree_sha=tree_sha,
        license=contract.license,
        license_files=("LICENSE",),
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )


class PublicApisCatalogIntegrationTests(unittest.TestCase):
    def test_category_and_api_search_return_pinned_provenance_without_provisioning(self):
        contract = resolve_component_adapter(COMPONENT_ID)
        with tempfile.TemporaryDirectory() as temporary:
            data_root = Path(temporary) / "profile-data"
            owned = OwnedRoot(data_root)
            owned.ensure()
            with process_lock(owned.path("installer.lock")):
                store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
                catalog = install_public_apis_catalog(_pinned_fixture_source(), store)
                before = {
                    path.relative_to(catalog.root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in catalog.root.rglob("*") if path.is_file()
                }

                # The adapter only reads the private generation. Searching cannot
                # launch a provider or contact any of the listed services.
                with patch("urllib.request.urlopen") as urlopen, \
                        patch.object(subprocess, "Popen") as popen, \
                        patch.object(subprocess, "run") as run:
                    category = search_public_apis_catalog(catalog, "Animals")
                    api = search_public_apis_catalog(catalog, "Cat Facts")
                urlopen.assert_not_called()
                popen.assert_not_called()
                run.assert_not_called()

                after = {
                    path.relative_to(catalog.root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in catalog.root.rglob("*") if path.is_file()
                }

            self.assertEqual(before, after)
            self.assertEqual("public-apis/public-apis", contract.source_identity)
            self.assertEqual("874e5879d20843f7c2a5822cef4c0752127b3775", contract.revision)
            self.assertEqual("MIT", contract.license)
            self.assertEqual(1, len(category.hits))
            self.assertEqual("README.md", category.hits[0].path)
            self.assertEqual(3, category.hits[0].line)
            self.assertEqual(1, len(api.hits))
            self.assertEqual("README.md", api.hits[0].path)
            self.assertEqual(6, api.hits[0].line)
            for result in (category, api):
                self.assertTrue(result.complete)
                self.assertEqual(COMPONENT_ID, result.component_id)
                self.assertTrue(all(hit.source_url == "https://github.com/public-apis/public-apis"
                                    for hit in result.hits))
                self.assertTrue(all(hit.revision == contract.revision for hit in result.hits))

            # The fixture proves local search only; selection and actual-target
            # acceptance remain independently gated by the target blocker.
            self.assertFalse(contract.selected_for_runtime_activation)
            self.assertIn("B-TARGET", contract.blockers)


if __name__ == "__main__":
    unittest.main()
