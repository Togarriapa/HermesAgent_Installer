"""Effect, bounds, and provenance tests for offline reference search."""
import unittest

from hermes_installer.components.references import (
    ReferenceSearchError,
    search_reference_catalog,
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

    def test_rejects_unsafe_paths_before_reporting_results(self):
        with self.assertRaisesRegex(ReferenceSearchError, "unsafe path"):
            search_reference_catalog("awesome-harness-engineering",
                                     {"../README.md": b"agent harness"}, "harness")

    def test_rejects_empty_and_overlong_queries(self):
        for query in (" ", "q" * 161, "bad\x00query"):
            with self.subTest(query=query), self.assertRaises(ReferenceSearchError):
                search_reference_catalog("awesome-design", {}, query)


if __name__ == "__main__":
    unittest.main()
