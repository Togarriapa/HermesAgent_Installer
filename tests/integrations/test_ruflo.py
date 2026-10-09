"""R0082: inspect Ruflo's MCP package and keep unqualified runtime closed."""
import unittest

from hermes_installer.components.ruflo import RufloAdapterError, review_ruflo_source


def pinned_tree() -> dict[str, bytes]:
    # Relevant package declarations from ruvnet/ruflo at the selected pin.
    return {
        "package.json": (
            b'{"name":"claude-flow","version":"3.56.1","license":"MIT",'
            b'"engines":{"node":">=20.0.0"},"dependencies":{"@claude-flow/mcp":"3.1.0"},'
            b'"optionalDependencies":{"better-sqlite3":"12.9.0",'
            b'"@ruvector/core":"^0.1.30","@ruvector/router-linux-x64-gnu":"^0.1.31",'
            b'"agentdb":"^3.0.0-alpha.17"}}'
        ),
        "v3/@claude-flow/cli/bin/mcp-server.js": b"#!/usr/bin/env node\n// pinned MCP launcher\n",
        "v3/@claude-flow/mcp/package.json": (
            b'{"name":"@claude-flow/mcp","version":"3.1.0",'
            b'"description":"Standalone MCP (Model Context Protocol) server"}'
        ),
    }


class RufloAdapterTests(unittest.TestCase):
    def test_reviews_real_mcp_surface_and_reports_native_and_scope_blockers(self):
        review = review_ruflo_source(pinned_tree())
        self.assertEqual("58e0ae7e14e68aab45a4127d6f42f567bbcfb328", review.source_revision)
        self.assertEqual("3.56.1", review.package_version)
        self.assertTrue(review.mcp_server_source_present)
        self.assertIn("better-sqlite3", review.optional_native_dependencies)
        self.assertIn("@ruvector/router-linux-x64-gnu", review.optional_native_dependencies)
        self.assertFalse(review.coordinator_replaced)
        self.assertFalse(review.may_start)
        self.assertTrue(any("ARM64" in reason for reason in review.blockers))
        self.assertTrue(any("per tool" in reason for reason in review.blockers))

    def test_refuses_wrong_package_pin(self):
        source = pinned_tree()
        source["package.json"] = source["package.json"].replace(b"3.56.1", b"3.56.2")
        with self.assertRaisesRegex(RufloAdapterError, "does not match"):
            review_ruflo_source(source)

    def test_non_linux_arm64_target_remains_unavailable(self):
        review = review_ruflo_source(pinned_tree(), target="darwin/arm64")
        self.assertFalse(review.may_start)
        self.assertIn("outside the reviewed", review.blockers[0])


if __name__ == "__main__":
    unittest.main()
