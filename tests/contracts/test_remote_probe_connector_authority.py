from __future__ import annotations

import base64
import hashlib
import json
import unittest
from dataclasses import replace

from hermes_installer.authority.remote_connector_authority import AuthorityServiceHI12Adapter
from hermes_installer.authority.remote_probe_connector_authority import (
    InternalProbeConnectorAuthorization, RootSetupProbeBinding,
    SetupProbeConnectorAuthority,
)
from hermes_installer.authority.types import AuthorityDenied


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class _HI12:
    def __init__(self):
        self._capability = "hermes-service-connect"
        self.issued = []
        self.spent = []

    def issue_remote_connector_effect(self, **kwargs):
        self.issued.append(kwargs)
        return object()

    def consume_remote_connector_effect(self, grant, **kwargs):
        self.spent.append((grant, kwargs))
        return True


class SetupProbeConnectorAuthorityContracts(unittest.TestCase):
    def setUp(self):
        self.now = 10.0
        self.handle = "h" * 43
        self.binding = RootSetupProbeBinding(
            probe_handle=self.handle, setup_transaction_handle="setup-transaction-1",
            setup_transaction_digest="1" * 64, setup_actor_identity_digest="2" * 64,
            probe_actor_identity_digest="a" * 64, gateway_identity_digest="b" * 64,
            setup_profile_id="setup-profile", setup_generation="setup-gen",
            setup_enrollment_id="setup-enrollment", setup_role_sha256="4" * 64,
            probe_enrollment_id="probe-enrollment", probe_profile_id="probe-profile",
            probe_generation="probe-gen", probe_role_sha256="3" * 64,
            gateway_profile_id="gateway-profile", gateway_generation="gateway-generation-1",
            gateway_enrollment_id="gateway-enrollment",
            native_identity_digest="c" * 64, native_enrollment_id="native-enrollment",
            native_profile_id="native-desktop", native_generation="native-generation-1",
            enrollment_id="native-enrollment", target_id="xpra-native",
            connector_target_id="xpra-native",
            approved_route_ids=("xpra-http", "xpra-websocket"), session_id="setup-probe:nonce",
            asset_ids=("f" * 64,),
            selected_action="asset-get", selected_asset_id="f" * 64,
            connector_handle=None, next_sequence=0, effect_sequence=0,
            policy_revision="policy-r1", policy_config_digest="d" * 64,
            service_generation_digest="e" * 64, principal_id="setup-actor",
            issued_monotonic=5.0, expires_monotonic=40.0, frame_deadline_monotonic=20.0,
            cancelled=lambda: False)
        self.current = [self.binding]
        self.hi12 = _HI12()
        self.authority = SetupProbeConnectorAuthority(
            resolve_binding=self._resolve, hi12=self.hi12,
            boot_epoch=lambda: "boot-1",
            advance_sequence=self._advance_sequence,
            monotonic=lambda: self.now)

    def _resolve(self, handle, uid, pid, pidfd):
        if (handle != self.handle or (uid, pid, pidfd) != (1001, 200, 8)):
            raise RuntimeError("peer mismatch")
        return self.current[0]

    def _advance_sequence(self, handle, expected_effect, expected_frame,
                          operation, connector_id, uid, pid, pidfd):
        if (handle != self.handle or (uid, pid, pidfd) != (1001, 200, 8)
                or expected_effect != self.current[0].effect_sequence
                or expected_frame != self.current[0].next_sequence):
            return False
        if operation == "connector.open":
            self.current[0] = replace(self.current[0], connector_handle=connector_id,
                                      effect_sequence=expected_effect + 1)
        elif operation in {"connector.read", "connector.write"}:
            self.current[0] = replace(self.current[0], next_sequence=expected_frame + 1,
                                      effect_sequence=expected_effect + 1)
        elif operation == "connector.close":
            self.current[0] = replace(self.current[0], connector_handle=None,
                                      effect_sequence=expected_effect + 1)
        return True

    def _open_payload(self, route="xpra-http"):
        return canonical({"schema": 1, "enrollment_id": self.binding.native_enrollment_id,
                          "generation": self.binding.native_generation,
                          "target_id": self.binding.target_id, "action": "open",
                          "approved_route_id": route, "session_id": self.binding.session_id,
                          "deadline": self.binding.expires_monotonic})

    def _issue(self, payload=None):
        return self.authority.issue_probe_connector_effect(
            self.handle, "connector.open", payload or self._open_payload(), 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8)

    def test_exact_root_derived_open_is_one_use_and_spends_hi12(self):
        payload = self._open_payload()
        auth = self._issue(payload)
        with self.assertRaises(AuthorityDenied):
            self._issue(payload)
        self.assertEqual(len(self.hi12.issued), 1)
        self.assertIsInstance(auth, InternalProbeConnectorAuthorization)
        self.assertEqual(auth.canonical_payload_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(self.hi12.issued[0]["binding"].native_profile_id, "native-desktop")
        self.assertTrue(self.authority.consume_probe_connector_effect(
            auth, self.handle, "connector.open", payload, 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8))
        self.assertTrue(self.authority.advance_probe_connector_sequence(
            self.handle, 0, 0, "connector.open", "c" * 32,
            peer_uid=1001, peer_pid=200, peer_pidfd=8))
        self.assertEqual(self.current[0].next_sequence, 0)
        self.assertEqual(self.current[0].connector_handle, "c" * 32)
        self.assertEqual(self.current[0].effect_sequence, 1)
        with self.assertRaises(AuthorityDenied):
            self.authority.consume_probe_connector_effect(
                auth, self.handle, "connector.open", payload, 0,
                peer_uid=1001, peer_pid=200, peer_pidfd=8)
        self.assertEqual(len(self.hi12.spent), 1)

    def test_sequence_cas_denies_replay_or_foreign_connector(self):
        with self.assertRaises(AuthorityDenied):
            self.authority.advance_probe_connector_sequence(
                self.handle, 0, 1, "connector.open", "c" * 32,
                peer_uid=1001, peer_pid=200, peer_pidfd=8)
        with self.assertRaises(AuthorityDenied):
            self.authority.advance_probe_connector_sequence(
                self.handle, 0, 0, "connector.open", "bad",
                peer_uid=1001, peer_pid=200, peer_pidfd=8)

    def test_cross_route_or_noncanonical_payload_denies_before_hi12(self):
        with self.assertRaises(AuthorityDenied):
            self._issue(self._open_payload("untrusted-route"))
        payload = self._open_payload()
        with self.assertRaises(AuthorityDenied):
            self._issue(payload + b" ")
        self.assertEqual(self.hi12.issued, [])

    def test_cross_peer_and_changed_native_identity_deny(self):
        payload = self._open_payload()
        with self.assertRaises(AuthorityDenied):
            self.authority.issue_probe_connector_effect(
                self.handle, "connector.open", payload, 0,
                peer_uid=1001, peer_pid=201, peer_pidfd=8)
        auth = self._issue(payload)
        self.current[0] = replace(self.binding, native_identity_digest="f" * 64)
        with self.assertRaises(AuthorityDenied):
            self.authority.consume_probe_connector_effect(
                auth, self.handle, "connector.open", payload, 0,
                peer_uid=1001, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.hi12.spent, [])

    def test_cancelled_or_expired_probe_denies_before_grant(self):
        self.current[0] = replace(self.binding, cancelled=lambda: True)
        with self.assertRaises(AuthorityDenied):
            self._issue()
        self.current[0] = replace(self.binding, expires_monotonic=9.0,
                                  frame_deadline_monotonic=8.0)
        with self.assertRaises(AuthorityDenied):
            self._issue()
        self.assertEqual(self.hi12.issued, [])

    def test_websocket_frame_uses_fixed_route_sequence_and_one_use_grant(self):
        import base64
        self.current[0] = replace(self.binding, selected_action="websocket-attach",
                                  selected_asset_id=None, connector_handle="c" * 32,
                                  next_sequence=0, effect_sequence=3)
        payload = canonical({"schema": 1, "target_id": "xpra-native",
                             "route_id": "xpra-websocket", "connector_id": "c" * 32,
                             "session_id": self.binding.session_id,
                             "generation": self.binding.native_generation,
                             "deadline": self.binding.frame_deadline_monotonic,
                             "sequence": 0,
                             "data_b64": base64.b64encode(b"probe").decode("ascii")})
        auth = self.authority.issue_probe_connector_effect(
            self.handle, "connector.write", payload, 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8)
        self.assertTrue(self.authority.consume_probe_connector_effect(
            auth, self.handle, "connector.write", payload, 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8))
        self.assertTrue(self.authority.advance_probe_connector_sequence(
            self.handle, 3, 0, "connector.write", "c" * 32,
            peer_uid=1001, peer_pid=200, peer_pidfd=8))
        self.assertEqual(self.current[0].effect_sequence, 4)
        self.assertEqual(self.current[0].next_sequence, 1)
        self.assertEqual(self.hi12.issued[0]["binding"].target_id, "xpra-native")
        self.assertEqual(self.hi12.issued[0]["sequence"], 3)
        self.assertEqual(auth.effect_sequence, 3)
        self.assertEqual(auth.frame_sequence, 0)
        self.assertEqual(self.hi12.spent[0][1]["canonical_payload"], payload)

    def test_wrong_setup_action_route_denies_before_hi12(self):
        self.current[0] = replace(self.binding, selected_action="websocket-attach",
                                  selected_asset_id=None)
        with self.assertRaises(AuthorityDenied):
            self._issue(self._open_payload("xpra-http"))
        self.assertEqual(self.hi12.issued, [])

    def test_asset_probe_write_is_root_selected_static_asset_only(self):
        asset_id = hashlib.sha256(
            b"hermes-client-asset-v1\0/client/index.html").hexdigest()
        self.current[0] = replace(self.binding, asset_ids=(asset_id,),
                                  selected_asset_id=asset_id, connector_handle="c" * 32,
                                  next_sequence=0, effect_sequence=1)
        request = b"GET /client/index.html HTTP/1.1\r\nAccept: */*\r\n\r\n"
        body = canonical({"schema": 1, "target_id": "xpra-native",
                          "route_id": "xpra-http", "connector_id": "c" * 32,
                          "session_id": self.binding.session_id,
                          "generation": self.binding.native_generation,
                          "deadline": self.binding.frame_deadline_monotonic,
                          "sequence": 0,
                          "data_b64": base64.b64encode(request).decode("ascii")})
        auth = self.authority.issue_probe_connector_effect(
            self.handle, "connector.write", body, 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8)
        self.assertTrue(self.authority.consume_probe_connector_effect(
            auth, self.handle, "connector.write", body, 0,
            peer_uid=1001, peer_pid=200, peer_pidfd=8))

        self.current[0] = replace(self.current[0], asset_ids=("0" * 64,),
                                  selected_asset_id="0" * 64)
        payload = canonical({"schema": 1, "target_id": "xpra-native",
                             "route_id": "xpra-http", "connector_id": "c" * 32,
                             "session_id": self.binding.session_id,
                             "generation": self.binding.native_generation,
                             "deadline": self.binding.frame_deadline_monotonic,
                             "sequence": 1,
                             "data_b64": base64.b64encode(request).decode("ascii")})
        with self.assertRaises(AuthorityDenied):
            self.authority.issue_probe_connector_effect(
                self.handle, "connector.write", payload, 1,
                peer_uid=1001, peer_pid=200, peer_pidfd=8)


if __name__ == "__main__":
    unittest.main()
