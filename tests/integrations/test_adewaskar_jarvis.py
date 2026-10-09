from __future__ import annotations

import base64
import json
import tempfile
import time
import uuid
import unittest
import wave
from io import BytesIO
from pathlib import Path

from hermes_installer.components.adewaskar_jarvis import (
    AccountEligibility,
    JarvisIntegration,
    REQUIRED_PREREQUISITES,
    SOURCE_README_SHA256,
    SOURCE_REVISION,
    make_synthetic_voice_fixture,
)
from hermes_installer.policy import (
    BudgetLedger,
    DispatchContext,
    DispatchAuthorization,
    DispatchPolicy,
    Dispatcher,
    ProviderResponse,
    Route,
    Sensitivity,
    Sensitivity,
)
from hermes_installer.state import OwnedRoot


MODEL = "fixture/jarvis-voice:free"


class FixtureTransport:
    """In-process test transport; it has no socket or provider credentials."""

    def __init__(self):
        self.calls: list[tuple[str, bytes]] = []

    def __call__(self, route, model, payload, *, output_token_limit, timeout, trace_id, cancelled):
        self.calls.append((route.name, payload))
        return ProviderResponse(200, b"synthetic fixture reply", input_tokens=4, output_tokens=4)


class JarvisIntegrationTests(unittest.TestCase):
    def make_integration(self, root: Path):
        route = Route(
            "jarvis-fixture", "http://127.0.0.1:1/fixture", frozenset({MODEL}),
            Sensitivity.PUBLIC, True, False, 0.0, 0.0,
        )
        transport = FixtureTransport()

        def fixture_authorizer(context, capability, intent_id, now, timeout, cancelled):
            return DispatchAuthorization(
                "fixture-principal", context.profile_id, "fixture-namespace", context.trace_id,
                frozenset({"inference"}), context.effective_sensitivity, "fixture-policy",
                context.purpose, capability, intent_id, "f" * 64, str(uuid.uuid4()),
                now + min(60, timeout),
            )

        dispatcher = Dispatcher(
            DispatchPolicy({"jarvis-fixture": route}, "jarvis-fixture", metered_budget_usd=0),
            BudgetLedger(OwnedRoot(root)),
            transport,
            context_authorizer=fixture_authorizer,
        )
        return JarvisIntegration(dispatcher), transport

    def test_synthetic_audio_and_text_use_shared_dispatcher_fixture_route(self):
        with tempfile.TemporaryDirectory() as td:
            integration, transport = self.make_integration(Path(td))
            context = DispatchContext(
                "fixture-profile", "jarvis-synthetic-voice-fixture", Sensitivity.PUBLIC,
                principal_id="fixture-principal", namespace="fixture-namespace",
                provenance="sha256:" + "f" * 64, capabilities=frozenset({"inference"}),
                policy_revision="fixture-policy", grant_id="fixture-grant",
                lease_expires_at=time.monotonic() + 30,
            )
            response = integration.dispatch_synthetic_fixture(context=context, model=MODEL)

            self.assertEqual(response.body, b"synthetic fixture reply")
            self.assertEqual(len(transport.calls), 1)
            route_name, payload = transport.calls[0]
            self.assertEqual(route_name, "jarvis-fixture")
            request = json.loads(payload)
            self.assertEqual(len(request["messages"]), 1)
            content = request["messages"][0]["content"]
            self.assertIn("Synthetic voice fixture transcript: hello from synthetic voice fixture", content)
            audio = base64.b64decode(content.split("WAV base64: ", 1)[1], validate=True)
            self.assertTrue(audio.startswith(b"RIFF"))
            with wave.open(BytesIO(audio), "rb") as reader:
                self.assertEqual((reader.getnchannels(), reader.getframerate(), reader.getnframes()), (1, 8000, 800))

    def test_ineligible_or_unknown_account_denies_before_launcher(self):
        with tempfile.TemporaryDirectory() as td:
            integration, transport = self.make_integration(Path(td))
            launches: list[str] = []

            for account in (AccountEligibility.INELIGIBLE, AccountEligibility.UNKNOWN):
                decision, result = integration.activate(
                    selected_explicitly=True,
                    account=account,
                    prerequisites=REQUIRED_PREREQUISITES,
                    launcher=lambda: launches.append("started"),
                )
                self.assertFalse(decision.ready)
                self.assertEqual(decision.status, "account_ineligible")
                self.assertIsNone(result)

            self.assertEqual(launches, [])
            self.assertEqual(transport.calls, [])

    def test_launch_requires_explicit_selection_and_all_prerequisites(self):
        with tempfile.TemporaryDirectory() as td:
            integration, _transport = self.make_integration(Path(td))
            launches: list[str] = []
            base = {
                "selected_explicitly": True,
                "account": AccountEligibility.ELIGIBLE,
                "prerequisites": REQUIRED_PREREQUISITES,
                "launcher": lambda: launches.append("started"),
            }

            missing_runtime, _ = integration.activate(**(base | {"prerequisites": REQUIRED_PREREQUISITES - {"isolated_runtime"}}))
            not_selected, _ = integration.activate(**(base | {"selected_explicitly": False}))
            self.assertEqual(missing_runtime.status, "prerequisites_missing")
            self.assertEqual(not_selected.status, "not_selected")
            self.assertEqual(launches, [])

    def test_source_pin_is_recorded(self):
        self.assertEqual(SOURCE_REVISION, "1c4016afdf86f7043efc6882ceffef84ad0d8783")
        self.assertEqual(SOURCE_README_SHA256, "adb82caba1f6c000b502e08620b6b67a89e866eeab7538303e9847287f86c385")


if __name__ == "__main__":
    unittest.main()
