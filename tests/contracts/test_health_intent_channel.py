"""Closed-schema checks for the fixed v191 health intent channel frames."""
from __future__ import annotations

import unittest

from hermes_installer.authority.listener_activation import (
    ListenerActivationUnavailable,
    _validate_channel_message,
)
from hermes_installer.authority.listener_activation import (
    _HEALTH_COMPLETION_FIELDS, _digest, _validate_health_receipt_evidence,
)
import base64
import hashlib


class HealthIntentChannelSchemaTests(unittest.TestCase):
    def test_health_request_has_only_opaque_intent_and_nonce(self) -> None:
        frame = {
            "schema": 1,
            "operation": "health-request",
            "intent_handle": "a" * 64,
            "intent_sha256": "b" * 64,
            "nonce": "c" * 64,
        }
        self.assertEqual(_validate_channel_message(frame), frame)

    def test_health_completion_is_a_reference_not_a_passed_claim(self) -> None:
        frame = {
            "schema": 1,
            "operation": "health-completed",
            "intent_handle": "a" * 64,
            "completion_handle": "X" * 32,
            "completion_sha256": "b" * 64,
        }
        self.assertEqual(_validate_channel_message(frame), frame)

    def test_health_channel_rejects_authority_or_result_fields(self) -> None:
        frame = {
            "schema": 1,
            "operation": "health-request",
            "intent_handle": "a" * 64,
            "intent_sha256": "b" * 64,
            "nonce": "c" * 64,
            "profile_id": "caller-selected",
        }
        with self.assertRaises(ListenerActivationUnavailable):
            _validate_channel_message(frame)

    def test_health_channel_rejects_malformed_digest_and_nonce(self) -> None:
        for field, value in (("intent_sha256", "f" * 63), ("nonce", "g" * 64)):
            frame = {
                "schema": 1,
                "operation": "health-request",
                "intent_handle": "a" * 64,
                "intent_sha256": "b" * 64,
                "nonce": "c" * 64,
            }
            frame[field] = value
            with self.subTest(field=field), self.assertRaises(ListenerActivationUnavailable):
                _validate_channel_message(frame)

    def test_durable_completion_requires_original_receipt_and_exact_event_proof(self) -> None:
        result = b'{"outcome":"passed"}'
        result_sha = hashlib.sha256(result).hexdigest()
        receipt = {
            "schema": 1, "health_receipt_handle": "r" * 43,
            "operation_id": "health-operation", "enrollment_id": "enrollment-1",
            "profile_id": "profile-1", "process_generation": "process-generation-1",
            "service_generation_digest": "a" * 64,
            "bootstrap_transaction_handle": "bootstrap-transaction-1",
            "committed_enrollment_receipt_id": "b" * 32, "process_id": "process-1",
            "loader_ready_event_id": "event-loader", "native_request_event_id": "event-request",
            "provider_result_event_id": None, "tool_invocation_event_id": "event-invocation",
            "tool_result_event_id": "event-result", "terminal_receipt_handle": "t" * 43,
            "result_schema_id": "health-result-v1", "result_sha256": result_sha,
            "parent_closure_digest": "c" * 64, "status": "passed",
            "issued_monotonic": 10.0, "expires_monotonic": 20.0,
        }
        common = {
            "operation_id": receipt["operation_id"], "enrollment_id": receipt["enrollment_id"],
            "profile_id": receipt["profile_id"], "process_generation": receipt["process_generation"],
            "service_generation_digest": receipt["service_generation_digest"],
            "process_id": receipt["process_id"], "process_pid": 42, "process_uid": 1000,
            "package_id": "package-1", "compiled_closure_sha256": "d" * 64,
            "parent_closure_digest": receipt["parent_closure_digest"],
            "observed_monotonic": 12.0, "expires_monotonic": 18.0,
            "loader_ready_event_id": None, "native_request_event_id": None,
            "provider_result_event_id": None, "tool_invocation_event_id": None,
            "tool_result_event_id": None, "terminal_receipt_handle": None,
            "result_schema_id": None, "result_bytes": None, "loaded_proof_id": None,
            "action_id": None, "provider_result_reference": None, "invocation_handle": None,
            "terminal_status": None, "cleanup_verified": False,
        }
        events = [
            {**common, "event_id": "event-loader", "event_kind": "loader-ready",
             "loader_ready_event_id": "event-loader", "loaded_proof_id": "loaded-proof"},
            {**common, "event_id": "event-request", "event_kind": "native-request",
             "native_request_event_id": "event-request"},
            {**common, "event_id": "event-invocation", "event_kind": "tool-invocation",
             "tool_invocation_event_id": "event-invocation", "native_request_event_id": "event-request",
             "action_id": "health-action", "invocation_handle": "invocation-1"},
            {**common, "event_id": "event-result", "event_kind": "tool-result",
             "tool_result_event_id": "event-result", "tool_invocation_event_id": "event-invocation",
             "result_schema_id": receipt["result_schema_id"],
             "result_bytes": base64.b64encode(result).decode("ascii"),
             "invocation_handle": "invocation-1"},
            {**common, "event_id": "event-terminal", "event_kind": "terminal",
             "terminal_receipt_handle": receipt["terminal_receipt_handle"],
             "terminal_status": "succeeded", "cleanup_verified": True},
        ]
        event_proof = sorted(events, key=lambda row: row["event_id"])
        completion = {name: None for name in _HEALTH_COMPLETION_FIELDS}
        completion.update({
            "schema": 1, "completion_handle": "g" * 43, "intent_handle": "h" * 43,
            "intent_sha256": "e" * 64,
            "committed_transaction_id": receipt["committed_enrollment_receipt_id"],
            "bootstrap_transaction_handle": receipt["bootstrap_transaction_handle"],
            "generation_id": "generation-1",
            "service_generation_digest": receipt["service_generation_digest"],
            "publication_receipt_handle": "p" * 43, "publication_sha256": "f" * 64,
            "source_choice_signed_record_sha256": "1" * 64,
            "health_definition_sha256": "2" * 64,
            "health_receipt_handle": receipt["health_receipt_handle"],
            "health_receipt_sha256": _digest(receipt),
            "result_schema_id": receipt["result_schema_id"], "result_sha256": result_sha,
            "parent_closure_digest": receipt["parent_closure_digest"],
            "terminal_receipt_handle": receipt["terminal_receipt_handle"],
            "daemon_unit_id": "hermes-authority-daemon@abc.service",
            "daemon_invocation_id": "invocation-1", "daemon_pid": 42,
            "daemon_start_ticks": 123, "daemon_actor_witness_sha256": "3" * 64,
            "completed_monotonic": 19.0,
        })
        evidence = {"health_receipt_body": receipt,
                    "health_receipt_sha256": _digest(receipt),
                    "health_event_proof": event_proof}
        _validate_health_receipt_evidence(evidence, completion)

        malformed = dict(evidence)
        malformed["health_event_proof"] = event_proof[:-1]
        with self.assertRaises(ValueError):
            _validate_health_receipt_evidence(malformed, completion)


if __name__ == "__main__":
    unittest.main()
