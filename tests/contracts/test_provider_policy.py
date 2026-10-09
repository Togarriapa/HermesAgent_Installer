from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hermes_installer.policy import (
    BudgetLedger, DispatchContext, DispatchPolicy, Dispatcher, PolicyDenied,
    ProviderResponse, Route, Sensitivity, default_public_route,
)

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"


class RecordingProvider:
    def __init__(self, responses=None):
        self.responses = list(responses or [ProviderResponse(200, b"ok", input_tokens=2, output_tokens=3)])
        self.calls = []

    def __call__(self, route, model, payload, *, timeout, trace_id):
        self.calls.append((route.name, model, payload, timeout, trace_id))
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


class ProviderPolicyTests(unittest.TestCase):
    def make(self, root, provider, *, private=False, budget=0.0, sleep=None):
        routes = {"public": default_public_route()}
        private_name = None
        if private:
            routes["private"] = Route("private", "http://127.0.0.1:8811/v1", frozenset({MODEL, "local/test"}), Sensitivity.CONFIDENTIAL, False, True, 1.0, 2.0)
            private_name = "private"
        policy = DispatchPolicy(routes, "public", private_name, metered_budget_usd=budget)
        return Dispatcher(policy, BudgetLedger(root / "budget.sqlite"), provider, sleep=sleep or (lambda _delay: None))

    def test_public_nemotron_tool_call_hits_only_exact_free_route(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            result = self.make(Path(td), provider).dispatch(DispatchContext("hermes", "chat", Sensitivity.PUBLIC), MODEL, b'{"tool_choice":"auto"}', input_tokens=8, output_token_limit=128, tool_request=True)
            self.assertEqual(result.status, 200)
            self.assertEqual(provider.calls[0][:3], ("openrouter-nemotron-free", MODEL, b'{"tool_choice":"auto"}'))

    def test_private_derived_memory_is_blocked_before_public_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            ctx = DispatchContext("hermes", "memory-extraction", Sensitivity.PUBLIC, derived_from=(Sensitivity.PRIVATE,))
            with self.assertRaisesRegex(PolicyDenied, "No private-capable route"):
                self.make(Path(td), provider).dispatch(ctx, MODEL, b"private memory", input_tokens=4, output_token_limit=32)
            self.assertEqual(provider.calls, [])

    def test_private_tool_result_cannot_fallback_to_public(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider([ProviderResponse(503, b"unavailable")])
            dispatcher = self.make(Path(td), provider, private=True, budget=0.01)
            dispatcher.policy = replace(dispatcher.policy, fallbacks={"private": ("public",)})
            ctx = DispatchContext("hermes-private", "tool-result", Sensitivity.PRIVATE)
            with self.assertRaisesRegex(PolicyDenied, "No eligible provider route"):
                dispatcher.dispatch(ctx, MODEL, b"private result", input_tokens=20, output_token_limit=32, tool_request=True)
            self.assertTrue(provider.calls)
            self.assertTrue(all(call[0] == "private" for call in provider.calls))

    def test_429_retries_are_bounded_and_retry_after_is_clamped(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider([ProviderResponse(429, b"", {"Retry-After": "999"}), ProviderResponse(200, b"ok")])
            sleeps = []
            result = self.make(Path(td), provider, sleep=sleeps.append).dispatch(DispatchContext("hermes", "chat", Sensitivity.PUBLIC), MODEL, b"{}", input_tokens=1, output_token_limit=5)
            self.assertEqual(result.status, 200)
            self.assertEqual(len(provider.calls), 2)
            self.assertEqual(sleeps, [15.0])

    def test_zero_budget_blocks_paid_request_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            paid = Route("private", "http://127.0.0.1:8811/v1", frozenset({"local/test"}), Sensitivity.CONFIDENTIAL, False, True, 4.0, 6.0)
            policy = DispatchPolicy({"public": default_public_route(), "private": paid}, "public", "private")
            dispatcher = Dispatcher(policy, BudgetLedger(Path(td) / "budget.sqlite"), provider)
            with self.assertRaisesRegex(PolicyDenied, "No eligible provider route"):
                dispatcher.dispatch(DispatchContext("hermes", "chat", Sensitivity.PRIVATE), "local/test", b"{}", input_tokens=1, output_token_limit=1)
            self.assertEqual(provider.calls, [])

    def test_ledger_reserves_and_accounts_across_dispatchers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            paid = Route("private", "http://127.0.0.1:8811/v1", frozenset({"local/test"}), Sensitivity.CONFIDENTIAL, False, True, 10.0, 10.0)
            policy = DispatchPolicy({"public": default_public_route(), "private": paid}, "public", "private", metered_budget_usd=0.003)
            path = root / "budget.sqlite"
            first = Dispatcher(policy, BudgetLedger(path), RecordingProvider([ProviderResponse(200, b"ok", input_tokens=100, output_tokens=100)]))
            first.dispatch(DispatchContext("one", "chat", Sensitivity.PRIVATE), "local/test", b"{}", input_tokens=100, output_token_limit=100)
            self.assertAlmostEqual(BudgetLedger(path).spent(), 0.002)
            second = Dispatcher(policy, BudgetLedger(path), RecordingProvider())
            with self.assertRaisesRegex(PolicyDenied, "Aggregate metered budget"):
                second.dispatch(DispatchContext("two", "summary", Sensitivity.PRIVATE), "local/test", b"{}", input_tokens=100, output_token_limit=100)

    def test_unknown_class_cancellation_and_deadline_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            dispatcher = self.make(Path(td), provider)
            with self.assertRaisesRegex(PolicyDenied, "cancelled"):
                dispatcher.dispatch(DispatchContext("hermes", "chat", Sensitivity.PUBLIC, cancelled=lambda: True), MODEL, b"{}", input_tokens=1, output_token_limit=1)
            with self.assertRaisesRegex(PolicyDenied, "No private-capable route"):
                dispatcher.dispatch(DispatchContext("hermes", "chat", Sensitivity.UNKNOWN), MODEL, b"{}", input_tokens=1, output_token_limit=1)
            with self.assertRaisesRegex(PolicyDenied, "deadline"):
                dispatcher.dispatch(DispatchContext("hermes", "chat", Sensitivity.PUBLIC, deadline=1), MODEL, b"{}", input_tokens=1, output_token_limit=1)
            self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
