from __future__ import annotations

import hashlib
import inspect
import json
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.codex_responses import (
    CODEX_RECIPIENT, CODEX_TARGET, CodexResponsesTransport,
    normalize_responses_request,
)
from hermes_installer.policy import PolicyDenied
from hermes_installer.provider_effect_handlers import canonical_provider_request


def _normalization_policy():
    module = Path(inspect.getsourcefile(canonical_provider_request))
    record = {"id": "siwc-output-unsupported-v1", "revision": 1,
              "route_schema_id": "siwc-responses-preview-v1",
              "output_limit_mode": "unsupported-field-reject", "output_limit_ceiling": None,
              "canonicalizer_artifact_id": "provider-canonicalizer-v1",
              "canonicalizer_sha256": hashlib.sha256(module.read_bytes()).hexdigest()}
    record["normalization_policy_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
    return record


class FakeAuthority:
    def __init__(self, *, verify=True, fail_dispatch=False):
        self.verify = verify
        self.fail_dispatch = fail_dispatch
        self.issued = []
        self.verified = []
        self.calls = []
        self.native_calls = []

    def authorize_effect(self, context, *, capability, target, recipient, request_digest, retry_index):
        binding = (capability, target, recipient, request_digest, retry_index)
        issued_at = time.monotonic()
        grant = SimpleNamespace(
            binding=binding, issued_at_monotonic=issued_at,
            monotonic_expires_at=issued_at + 12, capability=capability,
            target=target, recipient=recipient, request_digest=request_digest,
            retry_index=retry_index,
        )
        self.issued.append(grant)
        return grant

    def verify_effect(self, grant, context, *, capability, target, recipient, request_digest, retry_index):
        binding = (capability, target, recipient, request_digest, retry_index)
        self.verified.append(binding)
        return SimpleNamespace(
            authorization=grant if self.verify and grant.binding == binding else None,
            operation="provider.dispatch", verified_at_monotonic=time.monotonic(),
            verification_receipt="fixture-verification-receipt",
        )

    def dispatch_codex(self, grant, *, target, recipient, request_digest, payload, timeout, cancelled=None):
        if self.fail_dispatch:
            raise RuntimeError("fake broker failure")
        self.calls.append((grant, target, recipient, request_digest, payload, timeout, cancelled))
        return SimpleNamespace(status=200,
            body=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"input_tokens":9,"output_tokens":4}}}\n\n',
            headers={"Content-Type": "text/event-stream", "Retry-After": "2", "Set-Cookie": "secret"})

    def dispatch_native_request(self, handle, normalized_payload, *, retry_index, timeout, cancelled=None):
        if self.fail_dispatch:
            raise RuntimeError("fake bridge failure")
        self.native_calls.append((handle, normalized_payload, retry_index, timeout, cancelled))
        return SimpleNamespace(status=200,
            body=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"input_tokens":9,"output_tokens":4}}}\n\n',
            headers={"Content-Type": "text/event-stream",
                     "X-Hermes-Native-Response-Ref": "r" * 40})


def context(sensitivity="private", lease=20, final_payload_digest=None):
    return SimpleNamespace(principal_id="fixture", profile_id="codex-enabled",
        namespace_id="ns-fixture", uid=1000, purpose="coding", intent_id="task",
        trace_id="codex-trace", lineage_hash="verified-source-lineage",
        policy_revision="host-policy", issued_at_monotonic=time.monotonic(),
        monotonic_expires_at=time.monotonic() + lease, nonce="ctx-nonce",
        signature="signed-context", sensitivity=sensitivity,
        capabilities=frozenset({"provider-inference", "provider-tool-call"}),
        final_payload_digest=final_payload_digest)


def request(**extra):
    body = {"model": "codex-model", "input": [{"role": "user", "content": "inspect the selected code"}]}
    body.update(extra)
    return json.dumps(body, separators=(",", ":")).encode()


class CodexResponsesTests(unittest.TestCase):
    def test_native_event_uses_single_atomic_bridge_and_requires_exact_handle(self):
        authority = FakeAuthority()
        transport = CodexResponsesTransport(authority)
        payload = request()
        normalized, _model, _tools = normalize_responses_request(payload)
        response = transport.dispatch_native_event(
            "a" * 48, payload, retry_index=2, timeout=4,
            normalization_policy=_normalization_policy(),
        )
        self.assertEqual((response.status, response.input_tokens, response.output_tokens), (200, 9, 4))
        self.assertEqual(response.headers.get("X-Hermes-Native-Response-Ref"), "r" * 40)
        self.assertEqual(len(authority.native_calls), 1)
        self.assertEqual(authority.native_calls[0][:3], ("a" * 48, normalized, 2))
        self.assertEqual(authority.calls, [])
        for invalid in ("short", "x" * 129, "x" * 48 + "!"):
            with self.subTest(handle=invalid), self.assertRaises(PolicyDenied):
                transport.dispatch_native_event(invalid, payload,
                                                normalization_policy=_normalization_policy())
        self.assertEqual(len(authority.native_calls), 1)

    def test_fixed_responses_target_binds_canonical_payload_and_tool_capability(self):
        authority = FakeAuthority()
        transport = CodexResponsesTransport(authority)
        payload = request(tools=[{"type": "namespace", "name": "fs", "tools": [{"type": "function", "name": "read_file", "parameters": {"type": "object"}}]}])
        normalized, _model, _uses_tools = normalize_responses_request(payload)
        digest = hashlib.sha256(normalized).hexdigest()
        response = transport(context(final_payload_digest=digest), payload, retry_index=1, timeout=5)
        self.assertEqual((response.status, response.input_tokens, response.output_tokens), (200, 9, 4))
        expected, _model, uses_tools = normalize_responses_request(payload)
        self.assertTrue(uses_tools)
        self.assertEqual(len(authority.calls), 1)
        grant, target, recipient, digest, sent, timeout, _cancel = authority.calls[0]
        self.assertEqual((target, recipient), (CODEX_TARGET, CODEX_RECIPIENT))
        self.assertEqual((target, recipient), ("codex://responses", "openai:codex"))
        self.assertEqual(sent, expected)
        self.assertEqual(digest, hashlib.sha256(expected).hexdigest())
        self.assertEqual(grant.binding, ("provider-tool-call", target, recipient, digest, 1))
        self.assertEqual(authority.verified, [grant.binding])
        self.assertLessEqual(timeout, 5)
        normalized = json.loads(sent)
        self.assertFalse(normalized["store"])
        self.assertTrue(normalized["stream"])
        self.assertFalse(normalized["parallel_tool_calls"])
        self.assertEqual(response.headers, {"Content-Type": "text/event-stream", "Retry-After": "2"})
        self.assertNotIn("secret", repr(transport))

    def test_each_retry_gets_new_grant_and_text_call_uses_inference_capability(self):
        authority = FakeAuthority()
        transport = CodexResponsesTransport(authority)
        body, _model, _tools = normalize_responses_request(request())
        digest = hashlib.sha256(body).hexdigest()
        transport(context(final_payload_digest=digest), request(), retry_index=0)
        transport(context(final_payload_digest=digest), request(), retry_index=1)
        self.assertEqual([grant.binding[0] for grant in authority.issued],
                         ["provider-inference", "provider-inference"])
        self.assertEqual([grant.binding[-1] for grant in authority.issued], [0, 1])
        self.assertEqual(len({grant.binding[3] for grant in authority.issued}), 1)
        self.assertIsNot(authority.issued[0], authority.issued[1])

    def test_unknown_or_confidential_context_denied_before_authority(self):
        for label in ("unknown", "confidential"):
            with self.subTest(label=label):
                authority = FakeAuthority()
                with self.assertRaises(PolicyDenied):
                    CodexResponsesTransport(authority)(context(label), request())
                self.assertEqual(authority.issued, [])
                self.assertEqual(authority.calls, [])

    def test_missing_broker_invalid_grant_cancel_and_short_leases_deny_before_egress(self):
        with self.assertRaisesRegex(PolicyDenied, "broker is unavailable"):
            CodexResponsesTransport(None)(context(), request())
        authority = FakeAuthority(verify=False)
        body, _model, _tools = normalize_responses_request(request())
        digest = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(PolicyDenied, "grant"):
            CodexResponsesTransport(authority)(context(final_payload_digest=digest), request())
        self.assertEqual(authority.calls, [])
        authority = FakeAuthority()
        with self.assertRaisesRegex(PolicyDenied, "cancelled"):
            CodexResponsesTransport(authority)(context(), request(), cancelled=lambda: True)
        self.assertEqual(authority.calls, [])
        with self.assertRaisesRegex(PolicyDenied, "lease"):
            CodexResponsesTransport(authority)(context(lease=0.01), request(), timeout=1)
        self.assertEqual(authority.calls, [])

    def test_broker_failures_are_safe_and_dont_leak_body_or_secret(self):
        authority = FakeAuthority(fail_dispatch=True)
        transport = CodexResponsesTransport(authority)
        body, _model, _tools = normalize_responses_request(request())
        digest = hashlib.sha256(body).hexdigest()
        with self.assertRaisesRegex(PolicyDenied, "broker rejected") as caught:
            transport(context(final_payload_digest=digest), request())
        self.assertNotIn("fake broker failure", str(caught.exception))
        self.assertNotIn("authorization", repr(transport).lower())

    def test_request_rejects_private_modes_modalities_fallback_and_malformed_json(self):
        bad = [
            b'{"model":"x","input":"hi","store":true}',
            b'{"model":"x","input":"hi","stream":false}',
            b'{"model":"x","input":"hi","max_output_tokens":64}',
            b'{"model":"x","input":"hi","truncation":"auto"}',
            b'{"model":"x","input":[{"role":"system","content":"private system prompt"}]}',
            b'{"model":"x","input":"hi","background":true}',
            b'{"model":"x","input":[{"role":"user","content":[{"type":"input_image","image_url":"x"}]}]}',
            request(tools=[{"type": "web_search"}]),
            request(model="https://api.openai.com/v1/responses"),
            request(model="../arbitrary"),
            b'{"model":"x","input":"hi","model":"attacker"}',
            b'{"model":"x","input":"hi","temperature":0.2}',
        ]
        for payload in bad:
            with self.subTest(payload=payload), self.assertRaises(PolicyDenied):
                normalize_responses_request(payload)

    def test_sse_requires_successful_bounded_terminal_completion(self):
        from hermes_installer.codex_responses import validate_responses_sse

        good=b'event: response.output_text.delta\ndata: {"type":"response.output_text.delta","delta":"partial"}\n\n'
        with self.assertRaisesRegex(PolicyDenied, "before response.completed"):
            validate_responses_sse(good, "text/event-stream")
        bad=b'event: response.incomplete\ndata: {"type":"response.incomplete","response":{}}\n\n'
        with self.assertRaisesRegex(PolicyDenied, "incomplete"):
            validate_responses_sse(bad, "text/event-stream")
        failure=b'event: response.failed\ndata: {"type":"response.failed","error":{"code":"subscription_sharing_usage_limit_exceeded"}}\n\n'
        with self.assertRaisesRegex(PolicyDenied, "did not complete"):
            validate_responses_sse(failure, "text/event-stream")
        unterminated=b'event: response.completed\ndata: {"type":"response.completed","response":{}}'
        with self.assertRaisesRegex(PolicyDenied, "before response.completed"):
            validate_responses_sse(unterminated, "text/event-stream")
        complete=b'event: response.completed\ndata: {"type":"response.completed","response":{"id":"resp_fixture","status":"completed","usage":{"input_tokens":7,"output_tokens":3}}}\n\n'
        self.assertEqual(validate_responses_sse(complete, "text/event-stream; charset=utf-8"), (7, 3))
        for response in ({}, {"id":"resp_fixture","usage":{"input_tokens":7,"output_tokens":3}},
                         {"id":"resp_fixture","status":"completed"}):
            event=json.dumps({"type":"response.completed","response":response}, separators=(",", ":"))
            with self.subTest(response=response), self.assertRaises(PolicyDenied):
                validate_responses_sse(("event: response.completed\ndata: "+event+"\n\n").encode(), "text/event-stream")

    def test_completed_function_call_history_round_trips_with_linked_output(self):
        authority = FakeAuthority()
        transport = CodexResponsesTransport(authority)
        tool = {"type": "namespace", "name": "fs", "tools": [{"type": "function", "name": "read_file", "parameters": {"type": "object"}}]}
        history = [
            {"type": "message", "role": "user", "content": "read README"},
            {"type": "function_call", "call_id": "call_read_1", "name": "read_file", "namespace": "fs",
             "arguments": "{\"path\":\"README.md\"}", "status": "completed"},
            {"type": "function_call_output", "call_id": "call_read_1", "namespace": "fs", "name": "read_file",
             "output": "{\"text\":\"synthetic result\"}"},
        ]
        payload = request(input=history, tools=[tool])
        normalized, model, uses_tools = normalize_responses_request(payload)
        self.assertEqual(model, "codex-model")
        self.assertTrue(uses_tools)
        digest = hashlib.sha256(normalized).hexdigest()
        response = transport(context(final_payload_digest=digest), payload, retry_index=0)
        self.assertEqual(response.status, 200)
        self.assertEqual(len(authority.calls), 1)
        self.assertEqual(authority.calls[0][4], normalized)
        sent = json.loads(authority.calls[0][4])
        self.assertEqual(sent["input"], history)
        self.assertFalse(sent["store"])
        self.assertTrue(sent["stream"])

    def test_undocumented_flat_function_tools_are_rejected_for_siwc(self):
        with self.assertRaisesRegex(PolicyDenied, "namespace"):
            normalize_responses_request(request(tools=[
                {"type": "function", "name": "read_file", "parameters": {"type": "object"}}]))

    def test_function_call_history_requires_declared_tool_and_matching_output(self):
        tool = {"type": "namespace", "name": "fs", "tools": [{"type": "function", "name": "read_file", "parameters": {"type": "object"}}]}
        call = {"type": "function_call", "call_id": "call_1", "name": "read_file", "namespace": "fs",
                "arguments": "{}", "status": "completed"}
        bad_requests = [
            request(input=[call], tools=[tool]),
            request(input=[dict(call, name="unknown"), {
                "type": "function_call_output", "call_id": "call_1", "output": "x"}], tools=[tool]),
            request(input=[call, {"type": "function_call_output", "call_id": "other", "output": "x"}], tools=[tool]),
        ]
        for payload in bad_requests:
            with self.subTest(payload=payload), self.assertRaises(PolicyDenied):
                normalize_responses_request(payload)

    def test_function_tool_output_requires_tool_capability(self):
        tool = {"type": "namespace", "name": "fs", "tools": [
            {"type": "function", "name": "read_file", "parameters": {"type": "object"}}]}
        history = [
            {"type": "function_call", "call_id": "call_1", "name": "read_file",
             "namespace": "fs", "arguments": "{}", "status": "completed"},
            {"type": "function_call_output", "call_id": "call_1", "namespace": "fs",
             "name": "read_file", "output": "fixture"},
        ]
        _, _, uses_tools = normalize_responses_request(request(input=history, tools=[tool]))
        self.assertTrue(uses_tools)


if __name__ == "__main__":
    unittest.main()
