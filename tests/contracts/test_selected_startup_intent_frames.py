"""Closed v197 startup wire-frame contract tests."""
from __future__ import annotations

import unittest

from hermes_installer.authority.listener_activation import (
    ListenerActivationUnavailable,
    _validate_channel_message,
)


class SelectedStartupIntentFrameTests(unittest.TestCase):
    def test_three_frames_accept_only_their_exact_v197_fieldsets(self) -> None:
        handle = "a" * 43
        digest = "b" * 64
        frames = (
            {"schema": 1, "operation": "startup-request", "intent_handle": handle,
             "intent_sha256": digest, "nonce": "c" * 64},
            {"schema": 1, "operation": "startup-accepted", "intent_handle": handle,
             "intent_sha256": digest},
            {"schema": 1, "operation": "startup-completed", "intent_handle": handle,
             "outcome_handle": "d" * 43, "outcome_sha256": "e" * 64},
        )
        for frame in frames:
            with self.subTest(operation=frame["operation"]):
                self.assertEqual(_validate_channel_message(frame), frame)

    def test_extra_fields_and_wrong_frame_references_fail_closed(self) -> None:
        base = {"schema": 1, "operation": "startup-request", "intent_handle": "a" * 43,
                "intent_sha256": "b" * 64, "nonce": "c" * 64}
        invalid = (
            {**base, "requested_display": ":9"},
            {**base, "nonce": "not-a-hex-nonce"},
            {**base, "intent_handle": "!" * 43},
            {"schema": 1, "operation": "startup-completed", "intent_handle": "a" * 43,
             "outcome_handle": "d" * 43, "outcome_sha256": "e" * 64, "ack": True},
            {"schema": 1, "operation": "startup-accepted", "intent_handle": "a" * 43,
             "intent_sha256": "b" * 64, "nonce": "c" * 64},
        )
        for frame in invalid:
            with self.subTest(frame=frame):
                with self.assertRaises(ListenerActivationUnavailable):
                    _validate_channel_message(frame)


if __name__ == "__main__":
    unittest.main()
