from __future__ import annotations

import unittest
from pathlib import Path

from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, Sensitivity,
    RootCompletedNativeTurnPresentation, canonical_bytes, canonical_digest,
)


def grant(*, operation: str, target: str, body: bytes) -> EffectAuthorization:
    return EffectAuthorization(
        principal_id="principal:test", profile_id="profile:test", namespace_id="namespace:test",
        uid=1234, purpose="fixture", sensitivity=Sensitivity.UNKNOWN, trace_id="trace:test",
        policy_revision="policy:test", lineage_hash="a" * 64, capability="fixture-capability",
        intent_id="intent:test", target=target, recipient=None,
        request_digest=canonical_digest(body), retry_index=0, issued_at_monotonic=1.0,
        monotonic_expires_at=5.0, grant_id="grant:test", nonce="nonce:test",
        context_digest="b" * 64, signature="fixture-signature", final_payload_digest=canonical_digest(body),
        enrollment_id="enrollment:test", generation="generation:test", operation=operation,
    )


class AuthorityClientSelectionContracts(unittest.TestCase):
    def setUp(self):
        self.client = AuthorityClient(Path("/unused"), server_uid=0)
        self.calls = []

        def perform(authorization, *, operation, payload, timeout, cancelled=None):
            self.calls.append((authorization, operation, payload, timeout))
            return BrokeredEffectResponse(200, b'{"accepted":true}', {}, "receipt:test")

        self.client.perform_effect = perform

    def test_process_start_sends_only_selection_parameters_and_matches_digest(self):
        target = "operation:service:start"
        values = {"schema": 1, "enrollment_id": "service:test", "generation": "g1",
                  "operation_id": "coral-selected-inference-worker-v1", "parameters": {}}
        payload = canonical_bytes(values)
        authorization = grant(operation="process.start", target=target, body=payload)
        response = self.client.process_start_operation(
            authorization, enrollment_id="service:test", generation="g1",
            operation_id="coral-selected-inference-worker-v1", parameters={},
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(self.calls[0][1:3], ("process.start", payload))
        self.assertNotIn(b"argv", payload)
        with self.assertRaises(AuthorityDenied):
            self.client.process_start_operation(
                authorization, enrollment_id="service:test", generation="g1",
                operation_id="different-recipe", parameters={},
            )

    def test_package_set_sends_only_signed_manifest_selection(self):
        package_set_id = "coral-cp39-runtime-v1"
        manifest = "c" * 64
        target = f"package-set:{package_set_id}:{manifest}"
        payload = canonical_bytes({"schema": 1, "package_set_id": package_set_id,
                                   "enrollment_id": "service:test", "generation": "g1"})
        authorization = grant(operation="package.install", target=target, body=payload)
        response = self.client.install_package_set(
            authorization, package_set_id=package_set_id, manifest_sha256=manifest,
            enrollment_id="service:test", generation="g1",
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(self.calls[0][1:3], ("package.install", payload))
        self.assertNotIn(b"python", payload)

    def test_native_turn_finish_sends_only_opaque_handles_and_parses_presentation(self):
        turn_handle = "t" * 32
        response_handle = "r" * 43
        calls = []
        self.client.monotonic = lambda: 10.0
        self.client._rpc = lambda operation, payload: calls.append((operation, payload)) or {
            "schema": 1, "receipt_handle": "p" * 43, "turn_handle": turn_handle,
            "state": "completed", "expires_monotonic": 15.0,
        }
        result = self.client.finish_selected_native_turn(turn_handle, response_handle)
        self.assertIsInstance(result, RootCompletedNativeTurnPresentation)
        self.assertEqual(calls, [("native.turn.finish", {
            "schema": 1, "turn_handle": turn_handle,
            "final_response_delivery_handle": response_handle,
        })])
        self.client._rpc = lambda *_args, **_kwargs: {
            "schema": 1, "receipt_handle": "p" * 43, "turn_handle": "x" * 32,
            "state": "completed", "expires_monotonic": 15.0,
        }
        with self.assertRaises(AuthorityDenied):
            self.client.finish_selected_native_turn(turn_handle, response_handle)


if __name__ == "__main__":
    unittest.main()
