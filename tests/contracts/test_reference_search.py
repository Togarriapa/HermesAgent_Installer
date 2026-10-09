"""Effect, bounds, and provenance tests for offline reference search."""
import unittest
import tempfile
import hashlib
import json
from pathlib import Path

from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.references import install_reference_catalog
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock

from hermes_installer.components.references import (
    ReferenceSearchError,
    search_reference_catalog,
)


def _verified_source(contract, files, *, archive_byte="a"):
    """Construct the exact fetcher envelope around a synthetic pinned tree."""
    modes = {name: 0o644 for name in files}
    content_digest = hashlib.sha256()
    for name in sorted(files):
        content_digest.update(name.encode("utf-8") + b"\0")
        content_digest.update(b"644\0")
        content_digest.update(hashlib.sha256(files[name]).digest())
    content_sha = content_digest.hexdigest()
    tree_sha = _git_tree(files, modes)[0]
    archive_sha = archive_byte * 64
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
        "license_files": [],
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    staged_files = dict(files)
    staged_files["INSTALLER-SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    )
    staged_modes = {**modes, "INSTALLER-SOURCE-PROVENANCE.json": 0o644}
    from hermes_installer.components.source_bundle import VerifiedComponentSource

    return VerifiedComponentSource(
        component_id=contract.component_id,
        source_identity=contract.source_identity,
        revision=contract.revision,
        files=staged_files,
        file_modes=staged_modes,
        archive_sha256=archive_sha,
        content_sha256=content_sha,
        source_tree_sha=tree_sha,
        license=contract.license,
        license_files=(),
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )


class ReferenceCatalogSearchTests(unittest.TestCase):
    def test_search_is_local_deterministic_and_returns_pinned_provenance(self):
        files = {
            "README.md": b"# APIs\nA weather API serves forecasts.\n",
            "data/list.json": b'{"name":"Weather API", "auth":"None"}\n',
            "scripts/search.py": b"weather API implementation\n",
            "nested/README.md": b"weather api usage\n",
        }
        result = search_reference_catalog("public-apis-public-apis", files, "weather API")
        self.assertEqual(["README.md", "data/list.json", "nested/README.md"],
                         [hit.path for hit in result.hits])
        self.assertEqual([2, 1, 1], [hit.line for hit in result.hits])
        self.assertTrue(result.complete)
        self.assertEqual(3, result.scanned_files)
        self.assertTrue(all(hit.revision == "874e5879d20843f7c2a5822cef4c0752127b3775"
                            for hit in result.hits))
        self.assertTrue(all(hit.source_url == "https://github.com/public-apis/public-apis"
                            for hit in result.hits))

    def test_refuses_non_catalog_sources_and_invalid_limits(self):
        with self.assertRaisesRegex(ReferenceSearchError, "not a selected reference catalog"):
            search_reference_catalog("graphify", {"README.md": b"graph"}, "graph")
        with self.assertRaisesRegex(ReferenceSearchError, "limit"):
            search_reference_catalog("awesome-design", {}, "layout", limit=0)

    def test_marks_bounded_skips_incomplete(self):
        result = search_reference_catalog(
            "awesome-design",
            {"README.md": b"design\n", "large.txt": b"x" * 1_048_577},
            "design",
        )
        self.assertEqual(1, len(result.hits))
        self.assertFalse(result.complete)

    def test_hitting_limit_marks_result_non_exhaustive(self):
        result = search_reference_catalog(
            "awesome-design",
            {"one.md": b"design\n", "two.md": b"design system\n"},
            "design",
            limit=1,
        )
        self.assertEqual(1, len(result.hits))
        self.assertFalse(result.complete)

    def test_rejects_unsafe_paths_before_reporting_results(self):
        with self.assertRaisesRegex(ReferenceSearchError, "unsafe path"):
            search_reference_catalog("awesome-harness-engineering",
                                     {"../README.md": b"agent harness"}, "harness")

    def test_rejects_empty_and_overlong_queries(self):
        for query in (" ", "q" * 161, "bad\x00query"):
            with self.subTest(query=query), self.assertRaises(ReferenceSearchError):
                search_reference_catalog("awesome-design", {}, query)

    def test_installs_owned_catalog_and_searches_with_license_review_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_root = Path(temporary) / "profile-data"
            owned = OwnedRoot(data_root)
            owned.ensure()
            contract = resolve_component_adapter("awesome-harness-engineering")
            files = {
                "README.md": b"# Harness\nUse a deterministic fixture for build pipelines.\n",
                "catalog/agents.md": b"Agent harness patterns and tests.\n",
            }
            source = _verified_source(contract, files)
            with process_lock(owned.path("installer.lock")):
                store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
                catalog = install_reference_catalog(source, store)
                result = catalog.search("deterministic fixture")
            self.assertTrue(catalog.root.is_relative_to(data_root.resolve()))
            self.assertTrue(catalog.redistribution_license_review_required)
            self.assertEqual("ai-boost/awesome-harness-engineering", result.hits[0].source_url.removeprefix("https://github.com/"))
            self.assertEqual(contract.revision, result.hits[0].revision)
            self.assertEqual("README.md", result.hits[0].path)
            self.assertTrue(result.complete)

    def test_installed_catalog_fails_closed_after_generation_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_root = Path(temporary) / "profile-data"
            owned = OwnedRoot(data_root)
            owned.ensure()
            contract = resolve_component_adapter("public-apis-public-apis")
            files = {"README.md": b"Weather API fixture\n"}
            source = _verified_source(contract, files)
            with process_lock(owned.path("installer.lock")):
                store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
                catalog = install_reference_catalog(source, store)
                target = catalog.root / "README.md"
                target.chmod(0o600)
                target.write_bytes(b"tampered\n")
                with self.assertRaisesRegex(ReferenceSearchError, "integrity check"):
                    catalog.search("weather")

    def test_installer_rejects_non_catalog_component_and_source_pin_mismatch(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as temporary:
            owned = OwnedRoot(Path(temporary) / "profile-data")
            owned.ensure()
            files = {"README.md": b"catalog"}
            contract = resolve_component_adapter("awesome-design")
            source = _verified_source(contract, files)
            with process_lock(owned.path("installer.lock")):
                store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
                with self.assertRaisesRegex(ReferenceSearchError, "not one of the selected"):
                    install_reference_catalog(replace(source, component_id="graphify"), store)
                with self.assertRaisesRegex(ReferenceSearchError, "differs from the reviewed"):
                    install_reference_catalog(replace(source, source_identity="untrusted/repository"), store)

    def test_installer_rejects_tampered_provenance_and_license_evidence(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as temporary:
            owned = OwnedRoot(Path(temporary) / "profile-data")
            owned.ensure()
            contract = resolve_component_adapter("awesome-harness-engineering")
            source = _verified_source(contract, {"README.md": b"Harness fixture\n"})
            with process_lock(owned.path("installer.lock")):
                store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
                bad_provenance = dict(source.files)
                bad_provenance["INSTALLER-SOURCE-PROVENANCE.json"] = b'{"schema":1}\n'
                with self.assertRaisesRegex(ReferenceSearchError, "provenance"):
                    install_reference_catalog(replace(source, files=bad_provenance), store)
                with self.assertRaisesRegex(ReferenceSearchError, "license evidence"):
                    install_reference_catalog(replace(source, redistribution_license_review_required=False), store)


if __name__ == "__main__":
    unittest.main()
