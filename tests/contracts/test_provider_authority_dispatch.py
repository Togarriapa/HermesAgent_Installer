from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.policy import (
    BudgetLedger, DispatchPolicy, Dispatcher, PolicyDenied, ProviderResponse,
    Sensitivity, default_public_route, normalize_chat_request,
)
from hermes_installer.authority.types import VerifiedEffectAuthorization
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
        issued = time.monotonic()
        grant = SimpleNamespace(
            monotonic_expires_at=issued + 20, issued_at_monotonic=issued,
            capability=capability, target=target, recipient=recipient,
            request_digest=request_digest, retry_index=retry_index, binding=binding,
        )
        self.grants.append(grant)
        return grant

    def verify_effect(self, grant, context, *, capability, target, recipient, request_digest, retry_index):
        binding = (capability, target, recipient, request_digest, retry_index)
        self.verifications.append(binding)
        if grant.binding != binding:
            raise PermissionError("fixture effect binding mismatch")
        return VerifiedEffectAuthorization(grant, "provider.dispatch", time.monotonic(), "fixture-receipt")


class BrokerTransport:
    def __init__(self, response=None):
        self.response = response or ProviderResponse(200, b"ok")
        self.calls = []

    def __call__(self, route, model, payload, **kwargs):
        self.calls.append((route, model, payload, kwargs))
        return self.response


def host_context(*, sensitivity="public", capabilities=frozenset({"provider-inference", "provider-tool-call"}),
                 final_payload_digest=None):
    return SimpleNamespace(
        principal_id="host-principal", profile_id="hermes-public", namespace_id="ns-7", uid=1000,
        purpose="native-hermes-chat", intent_id="intent-9", trace_id="trace-1",
        lineage_hash="lineage-hash", policy_revision="policy-r4",
        issued_at_monotonic=time.monotonic(), monotonic_expires_at=time.monotonic() + 30,
        capabilities=capabilities,
        nonce="context-nonce", grant_id="context-grant",
        signature="host-signature", sensitivity=sensitivity,
        final_payload_digest=final_payload_digest,
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
            normalized = normalize_chat_request(payload, MODEL, 8)
            context = host_context(final_payload_digest=hashlib.sha256(normalized).hexdigest())
            dispatcher.dispatch(context, MODEL, payload, input_tokens=10,
                                output_token_limit=8, tool_request=False)
            self.assertEqual(len(transport.calls), 1)
            expected = authority.authorizations[0]
            self.assertEqual(expected[0], "provider-tool-call")
            self.assertEqual(authority.verifications, [expected])
            self.assertEqual(transport.calls[0][3]["effect_grant"], authority.grants[0])
            self.assertEqual(transport.calls[0][3]["retry_index"], 0)
            self.assertEqual(transport.calls[0][3]["request_digest"], expected[3])

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
