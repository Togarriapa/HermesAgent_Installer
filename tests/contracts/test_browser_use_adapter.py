"""Browser Use adapter boundaries and fixture-effect verification."""
import unittest

from hermes_installer.components.application_handlers import RuntimeProfileError
from hermes_installer.components.browser_use import (
    build_browser_use_fixture_invocation,
    run_browser_use_fixture,
    verify_browser_use_fixture_result,
)


class Supervisor:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def invoke(self, spec):
        self.calls.append(spec)
        return self.result


class BrowserUseAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_invocation_is_loopback_scoped_private_and_has_no_credentials(self):
        spec = build_browser_use_fixture_invocation(
            "/owned/venvs/browser/bin/python", "http://127.0.0.1:8080/fixture", "/owned/work/browser"
        )
        self.assertEqual("browser-use", spec.component_id)
        self.assertEqual("localhost", spec.network)
        self.assertEqual("PRIVATE", spec.sensitivity)
        self.assertEqual((), spec.credential_references)
        self.assertEqual(2048, spec.memory_limit_mb)
        self.assertIn("#action", spec.argv[2])
        self.assertIn("chromium_sandbox=True", spec.argv[2])
        self.assertIn(("BROWSER_USE_HEADLESS", "1"), spec.environment)

    def test_non_loopback_or_url_mutation_is_denied(self):
        for url in (
            "https://127.0.0.1:8080/fixture",
            "http://localhost:8080/fixture",
            "http://127.0.0.1:8080/fixture?token=secret",
            "http://127.0.0.1:65536/fixture",
            "http://127.0.0.1:8080/%2e%2e/outside",
        ):
            with self.subTest(url=url), self.assertRaises(RuntimeProfileError):
                build_browser_use_fixture_invocation("/owned/venv/bin/python", url, "/owned/work")

    async def test_managed_supervisor_effects_are_checked_before_proof_is_returned(self):
        result = {"exit_code": 0, "stdout": 'HERMES_BROWSER_USE_PROOF={"navigation": true, "interaction": "interaction-ok", "screenshot_bytes": 128}\n'}
        supervisor = Supervisor(result)
        proof = await run_browser_use_fixture(
            supervisor, "/owned/venvs/browser/bin/python", "http://127.0.0.1:8080/fixture", "/owned/work/browser"
        )
        self.assertTrue(proof["navigation"])
        self.assertEqual("interaction-ok", proof["interaction"])
        self.assertEqual(1, len(supervisor.calls))
        self.assertEqual("localhost", supervisor.calls[0].network)

    def test_success_exit_without_full_effect_evidence_is_not_accepted(self):
        for result in (
            {"exit_code": 1, "stdout": ""},
            {"exit_code": 0, "stdout": ""},
            {"exit_code": 0, "stdout": 'HERMES_BROWSER_USE_PROOF={"navigation":true,"interaction":"interaction-ok","screenshot_bytes":0}\n'},
        ):
            with self.subTest(result=result), self.assertRaises(RuntimeProfileError):
                verify_browser_use_fixture_result(result)


if __name__ == "__main__":
    unittest.main()
