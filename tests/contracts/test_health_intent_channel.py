"""Closed-schema checks for the fixed v191 health intent channel frames."""
from __future__ import annotations

import unittest

from hermes_installer.authority.listener_activation import (
    ListenerActivationUnavailable,
    _validate_channel_message,
)


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


if __name__ == "__main__":
    unittest.main()
