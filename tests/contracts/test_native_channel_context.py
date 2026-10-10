from __future__ import annotations

import unittest

from hermes_installer.authority.native_channel_context import NativeChannelContextDelivery


class NativeChannelContextDeliveryContract(unittest.TestCase):
    def test_wire_contains_only_peer_bound_opaque_handles_and_bounded_event_metadata(self):
        delivery = NativeChannelContextDelivery(
            schema=1,
            source_receipt_handle="s" * 43,
            producer_context_delivery_handle="c" * 43,
            payload_sha256="a" * 64,
            payload_size_bytes=128,
            expires_monotonic=40.0,
        )
        self.assertEqual(set(delivery.to_wire()), {
            "schema", "source_receipt_handle", "producer_context_delivery_handle",
            "payload_sha256", "payload_size_bytes", "expires_monotonic",
        })
        self.assertNotIn("signed_context", delivery.to_wire())
        self.assertNotIn("payload", delivery.to_wire())

    def test_wire_dto_rejects_malformed_or_unbounded_fields(self):
        base = {
            "schema": 1,
            "source_receipt_handle": "s" * 43,
            "producer_context_delivery_handle": "c" * 43,
            "payload_sha256": "a" * 64,
            "payload_size_bytes": 128,
            "expires_monotonic": 40.0,
        }
        for changes in (
            {"schema": True},
            {"source_receipt_handle": "event-handle"},
            {"payload_sha256": "z" * 64},
            {"payload_size_bytes": 0},
            {"payload_size_bytes": 262_145},
            {"expires_monotonic": float("inf")},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                NativeChannelContextDelivery(**(base | changes))


if __name__ == "__main__":
    unittest.main()
