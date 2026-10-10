"""Browser Use adapter boundaries and fixture-effect verification."""
import json
import unittest

from hermes_installer.components.application_handlers import RuntimeProfileError
from hermes_installer.components.browser_use import (
    build_browser_use_fixture_invocation,
    build_browser_use_sync_invocation,
    run_browser_use_fixture,
    verify_browser_use_fixture_result,
)


class Supervisor:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def invoke(self, spec):
        self.calls.append(spec)
        return self.result(spec) if callable(self.result) else self.result


def _proof(url="http://127.0.0.1:8080/fixture", **overrides):
    proof = {
        "schema_version": 1,
        "navigation_url": url,
        "navigation_succeeded": True,
        "page_title": "Hermes qualification fixture",
        "initial_text": "ready",
        "click_succeeded": True,
        "interaction_text": "interaction-ok",
        "screenshot_format": "png",
        "screenshot_bytes": 128,
        "screenshot_sha256": "a" * 64,
    }
    proof.update(overrides)
    return {"exit_code": 0, "stdout": "HERMES_BROWSER_USE_PROOF=" + json.dumps(proof) + "\n"}


class BrowserUseAdapterTests(unittest.IsolatedAsyncioTestCase):
    def test_sync_invocation_consumes_staged_locked_runtime_with_managed_python(self):
        spec = build_browser_use_sync_invocation(
            "/owned/toolchain/uv", "/owned/profiles/default/components/browser-use-runtime",
            "/opt/hermes/python3.14/bin/python",
        )
        self.assertEqual("python-packages", spec.network)
        self.assertIn("--locked", spec.argv)
        self.assertIn("--no-dev", spec.argv)
        self.assertEqual("/opt/hermes/python3.14/bin/python", spec.argv[spec.argv.index("--python") + 1])
        self.assertEqual("/owned/profiles/default/components/browser-use-runtime",
                         spec.argv[spec.argv.index("--project") + 1])
        self.assertIn(("BROWSER_USE_DISABLE_EXTENSIONS", "1"), spec.environment)
        self.assertFalse(spec.credential_references)

    def test_invocation_is_loopback_scoped_private_and_has_no_credentials(self):
        spec = build_browser_use_fixture_invocation(
            "/owned/venvs/browser/bin/python", "http://127.0.0.1:8080/fixture", "/owned/work/browser"
        )
        self.assertEqual("browser-use", spec.component_id)
        self.assertEqual("localhost", spec.network)
        self.assertEqual("PRIVATE", spec.sensitivity)
        self.assertEqual((), spec.credential_references)
        self.assertEqual(2048, spec.memory_limit_mb)
        self.assertTrue(spec.argv[1].endswith("browser_use_qualification_probe.py"))
        self.assertEqual("http://127.0.0.1:8080/fixture", spec.argv[2])
        self.assertNotIn("-c", spec.argv)
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
        supervisor = Supervisor(lambda spec: _proof(spec.argv[2]))
        proof = await run_browser_use_fixture(
            supervisor, "/owned/venvs/browser/bin/python", "http://127.0.0.1:8080/fixture", "/owned/work/browser"
        )
        self.assertTrue(proof["navigation_succeeded"])
        self.assertEqual("interaction-ok", proof["interaction_text"])
        self.assertEqual(1, len(supervisor.calls))
        self.assertEqual("localhost", supervisor.calls[0].network)

    def test_success_exit_without_full_effect_evidence_is_not_accepted(self):
        for result in (
            {"exit_code": 1, "stdout": ""},
            {"exit_code": 0, "stdout": ""},
            _proof(screenshot_bytes=64),
            _proof(click_succeeded=1),
            _proof(unexpected="extra"),
            _proof(screenshot_sha256="z" * 64),
            _proof(navigation_url="http://127.0.0.1:8080/outside"),
        ):
            with self.subTest(result=result), self.assertRaises(RuntimeProfileError):
                verify_browser_use_fixture_result(result)

    async def test_proof_must_match_exact_owned_loopback_url(self):
        supervisor = Supervisor(_proof("http://127.0.0.1:8081/fixture"))
        with self.assertRaises(RuntimeProfileError):
            await run_browser_use_fixture(
                supervisor, "/owned/venvs/browser/bin/python",
                "http://127.0.0.1:8080/fixture", "/owned/work/browser",
            )


if __name__ == "__main__":
    unittest.main()
