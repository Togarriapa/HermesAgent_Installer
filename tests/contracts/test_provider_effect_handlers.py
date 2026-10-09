"""Effect-boundary tests for fixed root provider handlers (PR-F03/PR-R0126)."""
from __future__ import annotations

import json
import time
import unittest
from types import SimpleNamespace

from hermes_installer.codex_responses import CODEX_RECIPIENT, CODEX_TARGET
from hermes_installer.policy import (
    PROVIDER_RECIPIENT, canonical_provider_target, normalize_chat_request,
)
from hermes_installer.provider_effect_handlers import (
    CODEX_ENDPOINT, OPENROUTER_ENDPOINT, OPENROUTER_MODEL,
    ProviderEnrollment, ProviderHandlerDenied, build_provider_handlers,
)


class Admission:
    def __init__(self):
        self.calls = []

    def check_attempt(self, **kwargs):
        self.calls.append(kwargs)


class Vault:
    def __init__(self):
        self.calls = []

    def resolve_reference(self, reference, *, peer_uid, required_scope, principal_id):
        self.calls.append((reference, peer_uid, required_scope, principal_id))
        return "opaque-token-fixture"


class Network:
    calls = []

    def __init__(self, **kwargs):
        self.bounds = kwargs

    def request(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return SimpleNamespace(status=200, body=b'{"ok":true}',
                               headers={"Content-Type": "application/json",
                                        "Set-Cookie": "not-forwarded"})


def _context(sensitivity="public", capabilities=frozenset({"provider-inference"})):
    return SimpleNamespace(
        principal_id="principal-test", profile_id="profile-test",
        namespace_id="namespace-test", uid=1001, purpose="inference",
        intent_id="intent-test", trace_id="trace-test",
        policy_revision="policy-test", lineage_hash="a" * 64,
        sensitivity=sensitivity, capabilities=capabilities,
        monotonic_expires_at=time.monotonic() + 20,
    )


def _authorization(context, *, target, recipient, digest, capability="provider-inference",
                   retry_index=0, sensitivity="public"):
    return SimpleNamespace(
        principal_id=context.principal_id, profile_id=context.profile_id,
        namespace_id=context.namespace_id, uid=context.uid,
        purpose=context.purpose, intent_id=context.intent_id,
        trace_id=context.trace_id, policy_revision=context.policy_revision,
        lineage_hash=context.lineage_hash,
        monotonic_expires_at=context.monotonic_expires_at - 1,
        sensitivity=sensitivity, target=target, recipient=recipient, request_digest=digest,
        capability=capability, retry_index=retry_index,
    )


def _openrouter_enrollment(sensitivities=frozenset({"public"})):
    target = canonical_provider_target(OPENROUTER_MODEL)
    return ProviderEnrollment(
        provider="openrouter", account_id="opaque-account", principal_id="principal-test",
        target=target, recipient=PROVIDER_RECIPIENT,
        credential_ref="vault://openrouter/account",
        credential_scope="provider:openrouter:inference",
        models=frozenset({OPENROUTER_MODEL}),
        allowed_sensitivities=sensitivities,
    )


class ProviderEffectHandlerTests(unittest.TestCase):
    def setUp(self):
        Network.calls = []
        self.admission = Admission()
        self.vault = Vault()
        self.enrollment = _openrouter_enrollment()
        self.handlers = build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            admission=self.admission, vault=self.vault, network_factory=Network,
        )
        self.handler = self.handlers[("provider.dispatch", self.enrollment.target)]
        self.payload = normalize_chat_request(
            b'{"messages":[{"role":"user","content":"hello"}]}',
            OPENROUTER_MODEL, 128,
        )

    def test_exact_canonical_grant_and_fixed_https_effect(self):
        context = _context()
        digest = __import__("hashlib").sha256(self.payload).hexdigest()
        grant = _authorization(context, target=self.enrollment.target,
                               recipient=self.enrollment.recipient, digest=digest)
        response = self.handler(context=context, authorization=grant,
                                payload=self.payload, timeout=2.0, peer_pid=88,
                                cancelled=lambda: False)
        self.assertEqual(response["status"], 200)
        self.assertEqual(Network.calls[0][0], OPENROUTER_ENDPOINT)
        self.assertNotIn("Set-Cookie", response["headers"])
        self.assertEqual(self.admission.calls[0]["additional_metered_fee_usd"], 0)
        self.assertEqual(self.vault.calls, [(
            "vault://openrouter/account", 1001, "provider:openrouter:inference", "principal-test")])

    def test_wrong_digest_capability_retry_and_target_fail_before_network(self):
        context = _context()
        digest = __import__("hashlib").sha256(self.payload).hexdigest()
        for grant in (
            _authorization(context, target=self.enrollment.target,
                           recipient=self.enrollment.recipient, digest="0" * 64),
            _authorization(context, target=self.enrollment.target,
                           recipient=self.enrollment.recipient, digest=digest,
                           capability="provider-tool-call"),
            _authorization(context, target=self.enrollment.target,
                           recipient=self.enrollment.recipient, digest=digest,
                           retry_index=4),
            _authorization(context, target="https://attacker.invalid",
                           recipient=self.enrollment.recipient, digest=digest),
        ):
            with self.subTest(grant=grant):
                with self.assertRaises(ProviderHandlerDenied):
                    self.handler(context=context, authorization=grant,
                                 payload=self.payload, timeout=2.0, peer_pid=88,
                                 cancelled=lambda: False)
        self.assertEqual(Network.calls, [])

    def test_private_data_is_not_eligible_for_public_account(self):
        context = _context("private")
        digest = __import__("hashlib").sha256(self.payload).hexdigest()
        grant = _authorization(context, target=self.enrollment.target,
                               recipient=self.enrollment.recipient, digest=digest)
        grant.sensitivity = "private"
        with self.assertRaises(ProviderHandlerDenied):
            self.handler(context=context, authorization=grant, payload=self.payload,
                         timeout=2.0, peer_pid=88, cancelled=lambda: False)
        self.assertEqual(Network.calls, [])
        self.assertEqual(self.vault.calls, [])

    def test_tool_capability_is_derived_from_body(self):
        payload = normalize_chat_request(
            b'{"messages":[{"role":"user","content":"hello"}],'
            b'"tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}',
            OPENROUTER_MODEL, 128,
        )
        context = _context(capabilities=frozenset({"provider-tool-call"}))
        digest = __import__("hashlib").sha256(payload).hexdigest()
        grant = _authorization(context, target=self.enrollment.target,
                               recipient=self.enrollment.recipient, digest=digest,
                               capability="provider-tool-call")
        self.handler(context=context, authorization=grant, payload=payload,
                     timeout=2.0, peer_pid=88, cancelled=lambda: False)
        self.assertEqual(self.admission.calls[-1]["capability"], "provider-tool-call")

    def test_no_handlers_without_root_admission_or_vault(self):
        self.assertEqual(build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            admission=None, vault=self.vault), {})
        self.assertEqual(build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            admission=self.admission, vault=None), {})

    def test_enrollment_rejects_private_openrouter_and_codex_url_override(self):
        with self.assertRaises(ValueError):
            _openrouter_enrollment(frozenset({"public", "private"}))
        with self.assertRaises(ValueError):
            ProviderEnrollment(
                provider="codex", account_id="opaque-account", principal_id="principal-test", target="https://attacker.invalid",
                recipient=CODEX_RECIPIENT, credential_ref="vault://codex",
                credential_scope="openai:codex:responses",
                models=frozenset({"gpt-test"}), allowed_sensitivities=frozenset({"public"}),
            )

    def test_codex_uses_only_broker_enrolled_official_responses_endpoint(self):
        enrollment = ProviderEnrollment(
            provider="codex", account_id="opaque-codex-account",
            principal_id="principal-test", target=CODEX_TARGET,
            recipient=CODEX_RECIPIENT, credential_ref="vault://codex/account",
            credential_scope="openai:codex:responses",
            models=frozenset({"gpt-test"}),
            allowed_sensitivities=frozenset({"public"}),
        )
        handlers = build_provider_handlers(
            enrollments={(CODEX_TARGET, CODEX_RECIPIENT): enrollment},
            admission=self.admission, vault=self.vault, network_factory=Network,
        )
        handler = handlers[("provider.dispatch", CODEX_TARGET)]
        payload = b'{"input":"hello","model":"gpt-test"}'
        from hermes_installer.codex_responses import normalize_responses_request
        body, _model, _tools = normalize_responses_request(payload)
        context = _context()
        digest = __import__("hashlib").sha256(body).hexdigest()
        grant = _authorization(context, target=CODEX_TARGET,
                               recipient=CODEX_RECIPIENT, digest=digest)
        response = handler(context=context, authorization=grant,
                           payload=body, timeout=2.0, peer_pid=88,
                           cancelled=lambda: False)
        self.assertEqual(response["status"], 200)
        self.assertEqual(Network.calls[0][0], CODEX_ENDPOINT)
        self.assertEqual(self.admission.calls[-1]["provider"], "codex")
        self.assertEqual(self.vault.calls[-1][2], "openai:codex:responses")

    def test_codex_route_is_fixed_and_additional_metered_fee_is_zero(self):
        enrollment = ProviderEnrollment(
            provider="codex", account_id="opaque-codex-account", principal_id="principal-test",
            target=CODEX_TARGET, recipient=CODEX_RECIPIENT,
            credential_ref="vault://codex/account",
            credential_scope="openai:codex:responses",
            models=frozenset({"gpt-test"}),
            allowed_sensitivities=frozenset({"public"}),
        )
        handlers = build_provider_handlers(
            enrollments={(CODEX_TARGET, CODEX_RECIPIENT): enrollment},
            admission=self.admission, vault=self.vault, network_factory=Network,
        )
        self.assertIn(("provider.dispatch", CODEX_TARGET), handlers)
        self.assertEqual(CODEX_ENDPOINT, "https://api.openai.com/v1/responses")
        self.assertEqual(enrollment.additional_metered_fee_usd, 0)


if __name__ == "__main__":
    unittest.main()
