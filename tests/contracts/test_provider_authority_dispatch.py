from __future__ import annotations

import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.policy import (
    BudgetLedger, DispatchPolicy, Dispatcher, PolicyDenied, ProviderResponse,
    Sensitivity, default_public_route,
)
from hermes_installer.state import OwnedRoot

MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"


class FakeAuthority:
    def __init__(self):
        self.authorizations = []
        self.verifications = []
        self.grants = []

    def authorize_effect(self, context, *, capability, target, recipient, request_digest, retry_index):
        binding = (capability, target, recipient, request_digest, retry_index)
        self.authorizations.append(binding)
        grant = SimpleNamespace(monotonic_expires_at=time.monotonic() + 20, binding=binding)
        self.grants.append(grant)
        return grant

    def verify_effect(self, grant, context, *, capability, target, recipient, request_digest, retry_index):
        binding = (capability, target, recipient, request_digest, retry_index)
        self.verifications.append(binding)
        return grant.binding == binding


class BrokerTransport:
    def __init__(self, response=None):
        self.response = response or ProviderResponse(200, b"ok")
        self.calls = []

    def __call__(self, route, model, payload, **kwargs):
        self.calls.append((route, model, payload, kwargs))
        return self.response


def host_context(*, sensitivity="public", capabilities=frozenset({"provider-inference", "provider-tool-call"})):
    return SimpleNamespace(
        principal_id="host-principal", profile_id="hermes-public", namespace_id="ns-7", uid=1000,
        purpose="native-hermes-chat", intent_id="intent-9", trace_id="trace-1",
        lineage_hash="lineage-hash", policy_revision="policy-r4",
        issued_at_monotonic=time.monotonic(), monotonic_expires_at=time.monotonic() + 30,
        capabilities=capabilities,
        nonce="context-" + str(uuid.uuid4()), grant_id="grant-" + str(uuid.uuid4()),
        signature="signature-" + str(uuid.uuid4()), sensitivity=sensitivity,
    )


class ProviderAuthorityDispatchTests(unittest.TestCase):
    def make_dispatcher(self, root, authority, transport):
        owned = OwnedRoot(Path(root) / "owned")
        owned.ensure()
        return Dispatcher(
            DispatchPolicy({"public": default_public_route()}, "public"),
            BudgetLedger(owned), transport, effect_authority=authority,
        )

    def test_tool_capability_comes_from_canonical_body_and_binds_each_effect(self):
        with tempfile.TemporaryDirectory() as td:
            authority, transport = FakeAuthority(), BrokerTransport()
            dispatcher = self.make_dispatcher(td, authority, transport)
            payload = (b'{"messages":[{"role":"user","content":"use a tool"}],'
                       b'"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}')
            dispatcher.dispatch(host_context(), MODEL, payload, input_tokens=10,
                                output_token_limit=8, tool_request=False)
            self.assertEqual(len(transport.calls), 1)
            expected = authority.authorizations[0]
            self.assertEqual(expected[0], "provider-tool-call")
            self.assertEqual(authority.verifications, [expected])
            self.assertEqual(transport.calls[0][3]["effect_grant"], authority.grants[0])
            self.assertEqual(transport.calls[0][3]["retry_index"], 0)
            self.assertEqual(transport.calls[0][3]["request_digest"], expected[3])

    def test_host_context_must_bind_exact_normalized_payload_before_authorization(self):
        with tempfile.TemporaryDirectory() as td:
            authority, transport = FakeAuthority(), BrokerTransport()
            dispatcher = self.make_dispatcher(td, authority, transport)
            payload = b'{"messages":[{"role":"user","content":"hello"}]}'
            with self.assertRaisesRegex(PolicyDenied, "not bound to the normalized"):
                dispatcher.dispatch(host_context(final_payload_digest="0" * 64), MODEL, payload,
                                    input_tokens=1, output_token_limit=8)
            self.assertEqual(authority.authorizations, [])
            self.assertEqual(transport.calls, [])

    def test_host_retry_requires_fresh_context_and_grant(self):
        class RetryTransport:
            def __init__(self):
                self.calls = []
            def __call__(self, route, model, payload, **kwargs):
                self.calls.append(kwargs)
                if len(self.calls) == 1:
                    return ProviderResponse(429, b"", {"Retry-After": "0"})
                return ProviderResponse(200, b"ok")

        with tempfile.TemporaryDirectory() as td:
            authority = FakeAuthority()
            transport = RetryTransport()
            dispatcher = self.make_dispatcher(td, authority, transport)
            payload = b'{"messages":[{"role":"user","content":"hello"}]}'
            normalized = normalize_chat_request(payload, MODEL, 8)
            digest = hashlib.sha256(normalized).hexdigest()
            contexts = [host_context(final_payload_digest=digest)]
            refreshes = []

            def refresh(_previous, *, final_payload_digest, operation, retry_index, cancelled):
                self.assertEqual(final_payload_digest, digest)
                self.assertEqual(operation, "provider.dispatch")
                refreshes.append(retry_index)
                context = host_context(final_payload_digest=digest)
                context.trace_id = "trace-1"
                context.lineage_hash = "lineage-hash"
                context.issued_at_monotonic = time.monotonic() + 0.000001
                return context

            with self.assertRaisesRegex(PolicyDenied, "fresh source-bound host context"):
                dispatcher.dispatch(contexts[0], MODEL, payload, input_tokens=1,
                                    output_token_limit=8)

            # The broker can retry only when the host event issuer supplies a
            # fresh payload-bound context for the same trusted source closure.
            result = dispatcher.dispatch(contexts[0], MODEL, payload, input_tokens=1,
                output_token_limit=8, context_refresh=refresh)
            self.assertEqual(result.status, 200)
            self.assertEqual(refreshes, [1])
            self.assertEqual([call["retry_index"] for call in transport.calls[-2:]], [0, 1])
            self.assertEqual([item[-1] for item in authority.authorizations[-2:]], [0, 1])

    def test_unknown_or_private_context_never_reaches_authority_or_transport(self):
        for classification in ("unknown", "private", "confidential"):
            with self.subTest(classification=classification), tempfile.TemporaryDirectory() as td:
                authority, transport = FakeAuthority(), BrokerTransport()
                dispatcher = self.make_dispatcher(td, authority, transport)
                with self.assertRaises(PolicyDenied):
                    dispatcher.dispatch(host_context(sensitivity=classification), MODEL,
                        b'{"messages":[{"role":"user","content":"private"}]}',
                        input_tokens=1, output_token_limit=8)
                self.assertEqual(authority.authorizations, [])
                self.assertEqual(transport.calls, [])

    def test_missing_effect_authority_fails_before_transport(self):
        with tempfile.TemporaryDirectory() as td:
            owned = OwnedRoot(Path(td) / "owned")
            owned.ensure()
            transport = BrokerTransport()
            dispatcher = Dispatcher(DispatchPolicy({"public": default_public_route()}, "public"),
                                    BudgetLedger(owned), transport)
            with self.assertRaisesRegex(PolicyDenied, "Host provider broker is unavailable"):
                dispatcher.dispatch(host_context(), MODEL,
                    b'{"messages":[{"role":"user","content":"hello"}]}',
                    input_tokens=1, output_token_limit=8)
            self.assertEqual(transport.calls, [])


if __name__ == "__main__":
    unittest.main()
