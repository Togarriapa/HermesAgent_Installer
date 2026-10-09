"""Effect-boundary tests for fixed root provider handlers (PR-F03/PR-R0126)."""
from __future__ import annotations

import json
import hashlib
import inspect
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.codex_responses import CODEX_RECIPIENT, CODEX_TARGET
from hermes_installer.policy import (
    PROVIDER_RECIPIENT, canonical_provider_target, normalize_chat_request,
)
from hermes_installer.provider_effect_handlers import (
    CODEX_ENDPOINT, OPENROUTER_ENDPOINT, OPENROUTER_MODEL,
    OpenRouterLiveAdmission, ProviderEnrollment, ProviderHandlerDenied,
    build_provider_handlers, canonical_provider_request,
)


def _normalization_policy(provider: str):
    module = Path(inspect.getsourcefile(canonical_provider_request))
    preimage = ({"id": "provider-output-reject-4096-v1", "revision": 1,
                 "route_schema_id": "provider-chat-compatible-v1",
                 "output_limit_mode": "reject-over-ceiling", "output_limit_ceiling": 4096}
                if provider == "openrouter" else
                {"id": "siwc-output-unsupported-v1", "revision": 1,
                 "route_schema_id": "siwc-responses-preview-v1",
                 "output_limit_mode": "unsupported-field-reject", "output_limit_ceiling": None})
    preimage.update({"canonicalizer_artifact_id": "provider-canonicalizer-v1",
                     "canonicalizer_sha256": hashlib.sha256(module.read_bytes()).hexdigest()})
    digest = hashlib.sha256(json.dumps(preimage, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode()).hexdigest()
    return {**preimage, "normalization_policy_sha256": digest}


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
        if url == CODEX_ENDPOINT:
            return SimpleNamespace(status=200,
                body=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_fixture","status":"completed","usage":{"input_tokens":4,"output_tokens":2}}}\n\n',
                headers={"Content-Type": "text/event-stream", "Set-Cookie": "not-forwarded"})
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
        self.normalization_policies = {(self.enrollment.target, self.enrollment.recipient):
                                       _normalization_policy("openrouter")}
        self.handlers = build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            normalization_policies=self.normalization_policies,
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

    def test_host_canonicalizer_uses_only_one_protected_model_enrollment(self):
        raw = json.dumps({"model": OPENROUTER_MODEL, "max_tokens": 128,
                          "messages": [{"role": "user", "content": "hello"}]},
                         separators=(",", ":")).encode()
        result = canonical_provider_request(
            {(self.enrollment.target, self.enrollment.recipient): self.enrollment}, raw,
            normalization_policy=_normalization_policy("openrouter"))
        expected = normalize_chat_request(raw, OPENROUTER_MODEL, 128)
        self.assertEqual(result, (expected, self.enrollment.target,
                                  self.enrollment.recipient, "provider-inference",
                                  OPENROUTER_MODEL))
        defaulted = canonical_provider_request(
            {(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            json.dumps({"model": OPENROUTER_MODEL,
                        "messages": [{"role": "user", "content": "x"}]}).encode(),
            normalization_policy=_normalization_policy("openrouter"),
        )
        self.assertEqual(json.loads(defaulted[0])["max_tokens"], 4096)

    def test_host_canonicalizer_requires_the_exact_digest_bound_route_policy(self):
        enrollment = {(self.enrollment.target, self.enrollment.recipient): self.enrollment}
        payload = json.dumps({"model": OPENROUTER_MODEL, "max_tokens": 4096,
                              "messages": []}).encode()
        record = _normalization_policy("openrouter")
        changed = {**record, "output_limit_ceiling": 8192}
        for invalid in (None, {**record, "normalization_policy_sha256": "0" * 64}, changed,
                        {**record, "revision": 2}):
            with self.subTest(policy=invalid), self.assertRaises(ProviderHandlerDenied):
                canonical_provider_request(enrollment, payload, normalization_policy=invalid)
        above = json.dumps({"model": OPENROUTER_MODEL, "max_tokens": 4097,
                            "messages": []}).encode()
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request(enrollment, above, normalization_policy=record)

    def test_host_canonicalizer_denies_missing_malformed_and_ambiguous_enrollment(self):
        raw = json.dumps({"model": OPENROUTER_MODEL,
                          "messages": [{"role": "user", "content": "hello"}]}).encode()
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request({}, raw, normalization_policy=_normalization_policy("openrouter"))
        malformed_map = {("https://attacker.invalid", self.enrollment.recipient): self.enrollment}
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request(malformed_map, raw, normalization_policy=_normalization_policy("openrouter"))
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request({
                (self.enrollment.target, self.enrollment.recipient): self.enrollment,
                (self.enrollment.target + "#duplicate", self.enrollment.recipient): self.enrollment,
            }, raw, normalization_policy=_normalization_policy("openrouter"))
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request(
                {(self.enrollment.target, self.enrollment.recipient): self.enrollment},
                b'{"model":"nvidia/nemotron-3-ultra-550b-a55b","messages":[]}',
                normalization_policy=_normalization_policy("openrouter"))
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request(
                {(self.enrollment.target, self.enrollment.recipient): self.enrollment},
                b'{"model":"nvidia/nemotron-3-ultra-550b-a55b:free",'
                b'"model":"nvidia/nemotron-3-ultra-550b-a55b:free","messages":[]}',
                normalization_policy=_normalization_policy("openrouter"))
        for invalid in (
            {"model": OPENROUTER_MODEL, "max_tokens": 4097, "messages": []},
            {"model": OPENROUTER_MODEL, "max_tokens": 100, "max_output_tokens": 50, "messages": []},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ProviderHandlerDenied):
                canonical_provider_request(
                    {(self.enrollment.target, self.enrollment.recipient): self.enrollment},
                    json.dumps(invalid).encode(),
                    normalization_policy=_normalization_policy("openrouter"))

    def test_no_handlers_without_root_admission_or_vault(self):
        self.assertEqual(build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            normalization_policies=None, admission=None, vault=self.vault), {})
        self.assertEqual(build_provider_handlers(
            enrollments={(self.enrollment.target, self.enrollment.recipient): self.enrollment},
            normalization_policies=None, admission=self.admission, vault=None), {})

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
            normalization_policies={(CODEX_TARGET, CODEX_RECIPIENT): _normalization_policy("codex")},
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
        with self.assertRaises(ProviderHandlerDenied):
            canonical_provider_request(
                {(CODEX_TARGET, CODEX_RECIPIENT): enrollment},
                b'{"input":"hello","model":"gpt-test","max_output_tokens":128}',
                normalization_policy=_normalization_policy("codex"),
            )

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
            normalization_policies={(CODEX_TARGET, CODEX_RECIPIENT): _normalization_policy("codex")},
            admission=self.admission, vault=self.vault, network_factory=Network,
        )
        self.assertIn(("provider.dispatch", CODEX_TARGET), handlers)
        self.assertEqual(CODEX_ENDPOINT, "https://api.openai.com/v1/responses")
        self.assertEqual(enrollment.additional_metered_fee_usd, 0)




class LiveAdmissionNetwork:
    def __init__(self, key_data, model_data):
        self.responses = {
            OpenRouterLiveAdmission.KEY_ENDPOINT: key_data,
            OpenRouterLiveAdmission.MODEL_ENDPOINT: model_data,
        }
        self.calls = []

    def request(self, endpoint, *, method, headers, cancelled=None):
        self.calls.append((endpoint, method, headers))
        if cancelled and cancelled():
            raise TimeoutError("cancelled")
        body = json.dumps({"data": self.responses[endpoint]}).encode()
        return SimpleNamespace(status=200, body=body, headers={"Content-Type": "application/json"})


class OpenRouterLiveAdmissionTests(unittest.TestCase):
    def _model_data(self, *, prompt="0", completion="0"):
        return {
            "id": OPENROUTER_MODEL,
            "pricing": {"prompt": prompt, "completion": completion},
            "architecture": {"input_modalities": ["text"]},
            "supported_parameters": ["tools", "tool_choice"],
            "context_length": 1_048_576,
            "top_provider": {"max_completion_tokens": 65_536},
        }

    def _attempt(self, admission, payload, **overrides):
        values = {
            "provider": "openrouter", "account_id": "opaque-account",
            "profile_id": "profile-test", "principal_id": "principal-test",
            "namespace_id": "namespace-test", "sensitivity": "public",
            "capability": "provider-inference",
            "target": canonical_provider_target(OPENROUTER_MODEL),
            "recipient": PROVIDER_RECIPIENT, "endpoint": OPENROUTER_ENDPOINT,
            "model": OPENROUTER_MODEL,
            "request_digest": __import__("hashlib").sha256(payload).hexdigest(),
            "output_limit_ceiling": 4096,
            "retry_index": 0, "additional_metered_fee_usd": 0.0,
            "credential_ref": "vault://openrouter/account",
            "credential": "opaque-test-token", "payload": payload, "timeout": 5.0,
            "cancelled": lambda: False, "expected_zero_price": True,
            "allow_fallbacks": False, "plugins_enabled": False,
            "data_collection": "deny",
        }
        values.update(overrides)
        admission.check_attempt(**values)

    def test_live_admission_checks_key_and_exact_model_metadata(self):
        payload = normalize_chat_request(
            b'{"messages":[{"role":"user","content":"hello"}]}',
            OPENROUTER_MODEL, 128,
        )
        network = LiveAdmissionNetwork(
            {"is_free_tier": True, "is_management_key": False,
             "is_provisioning_key": False, "limit_remaining": 20},
            self._model_data(),
        )
        admission = OpenRouterLiveAdmission(
            network_factory=lambda **_bounds: network,
            clock=lambda: time.time(),
        )
        self._attempt(admission, payload)
        self.assertEqual([call[0] for call in network.calls], [
            OpenRouterLiveAdmission.KEY_ENDPOINT, OpenRouterLiveAdmission.MODEL_ENDPOINT])
        self.assertTrue(all(call[1] == "GET" for call in network.calls))
        self.assertTrue(all(call[2]["Authorization"] == "Bearer opaque-test-token"
                            for call in network.calls))

    def test_nonfree_key_paid_price_and_nontext_model_fail_closed(self):
        payload = normalize_chat_request(
            b'{"messages":[{"role":"user","content":"hello"}]}',
            OPENROUTER_MODEL, 128,
        )
        cases = [
            ({"is_free_tier": False}, self._model_data()),
            ({"is_free_tier": True, "limit_remaining": 0}, self._model_data()),
            ({"is_free_tier": True}, self._model_data(prompt="0.01")),
            ({"is_free_tier": True}, {
                **self._model_data(), "architecture": {"input_modalities": ["text", "image"]}}),
        ]
        for key_data, model_data in cases:
            with self.subTest(key_data=key_data, model_data=model_data):
                network = LiveAdmissionNetwork(key_data, model_data)
                admission = OpenRouterLiveAdmission(
                    network_factory=lambda **_bounds: network)
                with self.assertRaises(ProviderHandlerDenied):
                    self._attempt(admission, payload)


if __name__ == "__main__":
    unittest.main()
