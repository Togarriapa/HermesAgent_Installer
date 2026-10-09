"""Reviewed application lock and invocation contracts."""
import unittest
import tomllib

from hermes_installer.components.application_handlers import (
    RuntimeProfileError,
    build_graphify_code_fixture,
    review_isolated_runtime,
)


class ApplicationHandlerTests(unittest.TestCase):
    def test_graphify_review_binds_exact_lock_and_keeps_functional_probe_pending(self):
        manifest = tomllib.dumps({
            "project": {"name": "graphifyy", "version": "0.9.82", "requires-python": ">=3.10"}
        }) if hasattr(tomllib, "dumps") else (
            '[project]\nname = "graphifyy"\nversion = "0.9.82"\nrequires-python = ">=3.10"\n'
        )
        lock = 'version = 1\nrequires-python = ">=3.10"\n\n[[package]]\nname = "graphifyy"\nversion = "0.9.82"\n'
        result = review_isolated_runtime("graphify", {
            "pyproject.toml": manifest.encode(),
            "uv.lock": lock.encode(),
        })
        self.assertEqual("source-locks-reviewed; functional-probe-pending", result.evidence_state)
        self.assertEqual("ef648e01899ba3e8dc6371642deaaf64b4477775", result.source_revision)
        self.assertEqual(1, len(result.lock_digests))
        self.assertFalse(result.blockers)

    def test_browser_use_missing_lock_remains_pending(self):
        result = review_isolated_runtime("browser-use", {
            "pyproject.toml": b'[project]\nname = "browser-use"\nrequires-python = ">=3.11,<4.0"\n',
        })
        self.assertEqual("pending-isolated-runtime", result.evidence_state)
        self.assertTrue(any("lock" in blocker for blocker in result.blockers))
        self.assertTrue(any("ARM64" in blocker for blocker in result.blockers))

    def test_hyperframes_and_omniroute_validate_native_runtime_floors(self):
        hyper = review_isolated_runtime("hyperframes", {
            "package.json": b"{}",
            "packages/cli/package.json": b'{"engines":{"node":">=22"}}',
            "bun.lock": b'{"lockfileVersion":1}',
        })
        self.assertEqual("source-locks-reviewed; functional-probe-pending", hyper.evidence_state)
        omni = review_isolated_runtime("omniroute", {
            "package.json": b'{"engines":{"node":">=20"}}',
            "package-lock.json": b'{"lockfileVersion":3}',
        })
        self.assertTrue(any("Node engine" in blocker for blocker in omni.blockers))

    def test_graphify_fixture_is_offline_scoped_and_uses_no_shell_or_secrets(self):
        extract, query = build_graphify_code_fixture(
            "/owned/envs/graphify",
            "/owned/fixtures/tiny-project",
            "/owned/work/graphify-probe",
        )
        self.assertEqual("/owned/envs/graphify/bin/graphify", extract.executable)
        self.assertIn("--code-only", extract.argv)
        self.assertEqual("deny", extract.network)
        self.assertIn(("GRAPHIFY_QUERY_LOG_DISABLE", "1"), extract.environment)
        self.assertEqual(90, extract.timeout_seconds)
        self.assertIn("--graph", query.argv)
        self.assertFalse(extract.credential_references)

    def test_commands_reject_relative_or_traversing_roots(self):
        for args in [
            ("relative", "/owned/f", "/owned/w"),
            ("/owned/env", "/owned/../outside", "/owned/w"),
        ]:
            with self.subTest(args=args), self.assertRaises(RuntimeProfileError):
                build_graphify_code_fixture(*args)


if __name__ == "__main__":
    unittest.main()
