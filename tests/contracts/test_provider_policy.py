from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from hermes_installer.state import OwnedRoot
from hermes_installer.policy import (
    BudgetLedger, DispatchAuthorization, DispatchContext, DispatchPolicy, Dispatcher, PolicyDenied,
    ProviderResponse, Route, Sensitivity, default_public_route, normalize_chat_request,
)

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"


def fixture_context(profile_id, purpose, sensitivity, **kwargs):
    return DispatchContext(profile_id, purpose, sensitivity,
        principal_id="fixture-principal", namespace="fixture-namespace",
        provenance="sha256:" + "f" * 64,
        capabilities=frozenset({"inference", "tool-call"}),
        policy_revision="fixture-revision", grant_id="fixture-context-grant",
        lease_expires_at=time.monotonic() + 3600, **kwargs)


def synthetic_authorizer(context, capability, intent_id, now, timeout, cancelled):
    import uuid
    return DispatchAuthorization(context.principal_id, context.profile_id, context.namespace,
        context.trace_id, context.capabilities, context.effective_sensitivity,
        context.policy_revision, context.purpose, capability, intent_id,
        context.provenance[7:], str(uuid.uuid4()),
        min(now + min(60, timeout), context.lease_expires_at))


class RecordingProvider:
    def __init__(self, responses=None):
        self.responses = list(responses or [ProviderResponse(200, b"ok", input_tokens=2, output_tokens=3)])
        self.calls = []

    def __call__(self, route, model, payload, *, output_token_limit, timeout, trace_id, cancelled=lambda:False):
        self.calls.append((route.name, model, payload, output_token_limit, timeout, trace_id))
        return self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]


class ProviderPolicyTests(unittest.TestCase):
    def ledger_root(self, parent):
        root = OwnedRoot(Path(parent) / "owned")
        root.ensure()
        return root

    def make(self, root, provider, *, private=False, budget=0.0, sleep=None):
        routes = {"public": default_public_route()}
        private_name = None
        if private:
            routes["private"] = Route("private", "http://127.0.0.1:8811/v1", frozenset({MODEL, "local/test"}), Sensitivity.CONFIDENTIAL, False, True, 1.0, 2.0)
            private_name = "private"
        policy = DispatchPolicy(routes, "public", private_name, metered_budget_usd=budget)
        return Dispatcher(policy, BudgetLedger(self.ledger_root(root)), provider, context_authorizer=synthetic_authorizer, sleep=sleep or (lambda _delay: None))

    def test_missing_host_authorizer_denies_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            dispatcher = Dispatcher(DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(self.ledger_root(Path(td))), provider)
            with self.assertRaisesRegex(PolicyDenied, "Trusted host provider authorization is unavailable"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC),
                    MODEL, b'{"messages":[{"role":"user","content":"hi"}]}',
                    input_tokens=2, output_token_limit=8)
            self.assertEqual(provider.calls, [])

    def test_authorizer_return_after_deadline_is_rejected_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            now = [0.0]
            provider = RecordingProvider()
            def late_authorizer(context, capability, intent_id, issued_at, timeout, cancelled):
                grant = synthetic_authorizer(context, capability, intent_id, issued_at, timeout, cancelled)
                now[0] = 2.0
                return grant
            dispatcher = Dispatcher(
                DispatchPolicy({"public": default_public_route()}, "public", max_dispatch_seconds=1),
                BudgetLedger(self.ledger_root(Path(td))), provider,
                context_authorizer=late_authorizer, clock=lambda: now[0],
            )
            with self.assertRaisesRegex(PolicyDenied, "exceeded the request deadline"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC), MODEL,
                    b'{"messages":[{"role":"user","content":"late auth"}]}',
                    input_tokens=2, output_token_limit=8)
            self.assertEqual(provider.calls, [])

    def test_boolean_monotonic_deadline_is_rejected(self):
        with self.assertRaisesRegex(PolicyDenied, "finite monotonic timestamp"):
            DispatchContext("hermes", "chat", Sensitivity.PUBLIC, deadline=True)

    def test_tool_body_cannot_downgrade_to_inference_capability(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            authorizations = []
            def authorizer(*args):
                authorizations.append(args[1])
                return synthetic_authorizer(*args)
            dispatcher = Dispatcher(DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(self.ledger_root(Path(td))), provider, context_authorizer=authorizer)
            with self.assertRaisesRegex(PolicyDenied, "Tool capability flag does not match"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC), MODEL,
                    b'{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x"}}]}',
                    input_tokens=2, output_token_limit=8, tool_request=False)
            self.assertEqual(authorizations, [])
            self.assertEqual(provider.calls, [])

    def test_fresh_grant_nonce_may_change_but_identity_swap_blocks_retry(self):
        from dataclasses import replace
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider([ProviderResponse(429, b"", {"Retry-After": "0"}), ProviderResponse(200, b"ok")])
            root = self.ledger_root(Path(td))
            calls = []
            def changing_authorizer(context, capability, intent_id, now, timeout, cancelled):
                grant = synthetic_authorizer(context, capability, intent_id, now, timeout, cancelled)
                calls.append(grant)
                if len(calls) >= 3:
                    return replace(grant, namespace="swapped-namespace")
                return grant
            dispatcher = Dispatcher(DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(root), provider, context_authorizer=changing_authorizer,
                sleep=lambda _delay: None)
            with self.assertRaisesRegex(PolicyDenied, "authorization changed"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC), MODEL,
                    b'{"messages":[{"role":"user","content":"retry"}]}',
                    input_tokens=2, output_token_limit=8)
            self.assertEqual(len(provider.calls), 1)
            self.assertNotEqual(calls[0].grant_id, calls[1].grant_id)

    def test_host_classification_overrides_caller_public_label(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            def private_host_policy(context, capability, intent_id, now, timeout, cancelled):
                from dataclasses import replace
                grant = synthetic_authorizer(context, capability, intent_id, now, timeout, cancelled)
                return replace(grant, effective_sensitivity=Sensitivity.PRIVATE)
            dispatcher = Dispatcher(DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(self.ledger_root(Path(td))), provider,
                context_authorizer=private_host_policy)
            with self.assertRaisesRegex(PolicyDenied, "No private-capable route"):
                dispatcher.dispatch(fixture_context("claimed-public", "chat", Sensitivity.PUBLIC),
                    MODEL, b'{"messages":[{"role":"user","content":"private"}]}',
                    input_tokens=2, output_token_limit=8)
            self.assertEqual(provider.calls, [])

    def test_public_nemotron_tool_call_hits_only_exact_free_route(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            result = self.make(Path(td), provider).dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC), MODEL, b'{"messages":[{"role":"user","content":"hi"}],"tool_choice":"auto"}', input_tokens=8, output_token_limit=128, tool_request=True)
            self.assertEqual(result.status, 200)
            self.assertEqual(provider.calls[0][0:2], ("openrouter-nemotron-free", MODEL))
            self.assertEqual(json.loads(provider.calls[0][2])["model"], MODEL)
            self.assertEqual(json.loads(provider.calls[0][2])["max_tokens"], 128)
            self.assertEqual(json.loads(provider.calls[0][2])["provider"]["allow_fallbacks"], False)

    def test_private_derived_memory_is_blocked_before_public_dispatch(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            ctx = fixture_context("hermes", "memory-extraction", Sensitivity.PUBLIC, derived_from=(Sensitivity.PRIVATE,))
            with self.assertRaisesRegex(PolicyDenied, "No private-capable route"):
                self.make(Path(td), provider).dispatch(ctx, MODEL,
                    b'{"messages":[{"role":"user","content":"private memory"}]}', input_tokens=4, output_token_limit=32)
            self.assertEqual(provider.calls, [])

    def test_private_tool_result_cannot_fallback_to_public(self):
        from dataclasses import replace

        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider([ProviderResponse(503, b"unavailable")])
            dispatcher = self.make(Path(td), provider, private=True, budget=0.01)
            dispatcher.policy = replace(dispatcher.policy, fallbacks={"private": ("public",)})
            ctx = fixture_context("hermes-private", "tool-result", Sensitivity.PRIVATE)
            with self.assertRaisesRegex(PolicyDenied, "No eligible provider route"):
                dispatcher.dispatch(ctx, MODEL, b'{"messages":[{"role":"user","content":"private result"}],"tools":[{"type":"function","function":{"name":"read","parameters":{"type":"object"}}}]}', input_tokens=20, output_token_limit=32, tool_request=True)
            self.assertTrue(provider.calls)
            self.assertTrue(all(call[0] == "private" for call in provider.calls))

    def test_429_retries_are_bounded_and_retry_after_is_clamped(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider([ProviderResponse(429, b"", {"Retry-After": "999"}), ProviderResponse(200, b"ok")])
            sleeps = []
            result = self.make(Path(td), provider, sleep=sleeps.append).dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC), MODEL, b'{"messages":[{"role":"user","content":"test"}]}', input_tokens=1, output_token_limit=5)
            self.assertEqual(result.status, 200)
            self.assertEqual(len(provider.calls), 2)
            self.assertAlmostEqual(sum(sleeps), 15.0)
            self.assertTrue(all(0 < delay <= 0.25 for delay in sleeps))

    def test_zero_budget_blocks_paid_request_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            paid = Route("private", "http://127.0.0.1:8811/v1", frozenset({"local/test"}), Sensitivity.CONFIDENTIAL, False, True, 4.0, 6.0)
            policy = DispatchPolicy({"public": default_public_route(), "private": paid}, "public", "private")
            dispatcher = Dispatcher(policy, BudgetLedger(self.ledger_root(Path(td))), provider, context_authorizer=synthetic_authorizer)
            with self.assertRaisesRegex(PolicyDenied, "No eligible provider route"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PRIVATE), "local/test", b'{"messages":[{"role":"user","content":"test"}]}', input_tokens=1, output_token_limit=1)
            self.assertEqual(provider.calls, [])

    def test_ledger_reserves_and_accounts_across_dispatchers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            payload = b'{"messages":[{"role":"user","content":"test"}]}'
            bound = max(100, len(normalize_chat_request(payload, "local/test", 100)))
            estimate = (bound + 100) / 1_000_000
            paid = Route("private", "http://127.0.0.1:8811/v1", frozenset({"local/test"}), Sensitivity.CONFIDENTIAL, False, True, 1.0, 1.0)
            policy = DispatchPolicy({"public": default_public_route(), "private": paid}, "public", "private", metered_budget_usd=estimate * 1.5)
            ledger_root = self.ledger_root(root)
            first = Dispatcher(policy, BudgetLedger(ledger_root), RecordingProvider([ProviderResponse(200, b"ok", input_tokens=100, output_tokens=100)]), context_authorizer=synthetic_authorizer)
            first.dispatch(fixture_context("one", "chat", Sensitivity.PRIVATE), "local/test", payload, input_tokens=100, output_token_limit=100)
            self.assertAlmostEqual(BudgetLedger(ledger_root).spent(), estimate)
            second = Dispatcher(policy, BudgetLedger(ledger_root), RecordingProvider(), context_authorizer=synthetic_authorizer)
            with self.assertRaisesRegex(PolicyDenied, "Aggregate metered budget"):
                second.dispatch(fixture_context("two", "summary", Sensitivity.PRIVATE), "local/test", payload, input_tokens=100, output_token_limit=100)


    def test_unknown_prices_are_never_treated_as_free(self):
        with tempfile.TemporaryDirectory() as td:
            provider=RecordingProvider()
            unknown=Route("unknown","https://provider.invalid/v1",frozenset({MODEL}),Sensitivity.PUBLIC,False,True)
            policy=DispatchPolicy({"unknown":unknown},"unknown")
            dispatcher=Dispatcher(policy,BudgetLedger(self.ledger_root(Path(td))),provider,context_authorizer=synthetic_authorizer)
            with self.assertRaisesRegex(PolicyDenied,"No eligible provider route"):
                dispatcher.dispatch(fixture_context("hermes","chat",Sensitivity.PUBLIC),MODEL,b'{"messages":[{"role":"user","content":"test"}]}',input_tokens=1,output_token_limit=1)
            self.assertEqual(provider.calls,[])

    def test_ambiguous_paid_timeout_keeps_attempt_reservation(self):
        with tempfile.TemporaryDirectory() as td:
            root=self.ledger_root(Path(td))
            payload=b'{"messages":[{"role":"user","content":"test"}]}'
            estimate=(max(1,len(normalize_chat_request(payload,"local/test",1)))+1)/1_000_000
            paid=Route("private","http://127.0.0.1:8811/v1",frozenset({"local/test"}),Sensitivity.CONFIDENTIAL,False,True,1.0,1.0)
            policy=DispatchPolicy({"public":default_public_route(),"private":paid},"public","private",metered_budget_usd=estimate*1.5,max_attempts=2)
            calls=[]
            def transport(route,model,payload,*,output_token_limit,timeout,trace_id,cancelled=lambda:False):
                calls.append(route.name)
                raise TimeoutError("fixture timeout")
            ledger=BudgetLedger(root)
            dispatcher=Dispatcher(policy,ledger,transport,context_authorizer=synthetic_authorizer)
            with self.assertRaisesRegex(PolicyDenied,"Aggregate metered budget"):
                dispatcher.dispatch(fixture_context("private","chat",Sensitivity.PRIVATE),"local/test",payload,input_tokens=1,output_token_limit=1)
            self.assertEqual(calls,["private"])
            self.assertAlmostEqual(ledger.spent(),estimate)

    def test_retry_delay_observes_cancellation_and_dispatch_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            cancelled=[False]
            provider=RecordingProvider([ProviderResponse(429,b"",{"Retry-After":"5"})])
            def sleep(delay):
                cancelled[0]=True
            dispatcher=self.make(Path(td),provider,sleep=sleep)
            context=fixture_context("hermes","chat",Sensitivity.PUBLIC,cancelled=lambda:cancelled[0])
            with self.assertRaisesRegex(PolicyDenied,"cancelled during retry delay"):
                dispatcher.dispatch(context,MODEL,b'{"messages":[{"role":"user","content":"test"}]}',input_tokens=1,output_token_limit=2)
            self.assertEqual(len(provider.calls),1)

    def test_policy_bounds_retry_after_and_fallback_graph(self):
        with self.assertRaisesRegex(ValueError,"retry-after bound"):
            DispatchPolicy({"public":default_public_route()},"public",max_retry_after_seconds=float("inf"))
        with self.assertRaisesRegex(ValueError,"fallback list exceeds"):
            DispatchPolicy({"public":default_public_route(),"a":Route("a","https://a.invalid",frozenset({MODEL}),Sensitivity.PUBLIC,False,True,0.0,0.0),"b":Route("b","https://b.invalid",frozenset({MODEL}),Sensitivity.PUBLIC,False,True,0.0,0.0),"c":Route("c","https://c.invalid",frozenset({MODEL}),Sensitivity.PUBLIC,False,True,0.0,0.0),"d":Route("d","https://d.invalid",frozenset({MODEL}),Sensitivity.PUBLIC,False,True,0.0,0.0),"e":Route("e","https://e.invalid",frozenset({MODEL}),Sensitivity.PUBLIC,False,True,0.0,0.0)},"public",fallbacks={"public":("a","b","c","d")})

    def test_unknown_class_cancellation_and_deadline_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            provider = RecordingProvider()
            dispatcher = self.make(Path(td), provider)
            with self.assertRaisesRegex(PolicyDenied, "cancelled"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC, cancelled=lambda: True), MODEL, b'{"messages":[{"role":"user","content":"test"}]}', input_tokens=1, output_token_limit=1)
            with self.assertRaisesRegex(PolicyDenied, "No private-capable route"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.UNKNOWN), MODEL, b'{"messages":[{"role":"user","content":"test"}]}', input_tokens=1, output_token_limit=1)
            with self.assertRaisesRegex(PolicyDenied, "deadline"):
                dispatcher.dispatch(fixture_context("hermes", "chat", Sensitivity.PUBLIC, deadline=1), MODEL, b'{"messages":[{"role":"user","content":"test"}]}', input_tokens=1, output_token_limit=1)
            self.assertEqual(provider.calls, [])


if __name__ == "__main__":
    unittest.main()
