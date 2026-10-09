from __future__ import annotations

import base64
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.remote_sessions import RemoteAdmissionRequest
from hermes_installer.authority.types import AuthorityDenied


class RemoteAuthorityRPCContracts(unittest.TestCase):
    def setUp(self):
        self.binding = PrincipalBinding(
            1234, "principal:test", "profile:test", "namespace:test", frozenset({"fixture"}),
        )

    def _service(self, remote=None):
        return AuthorityService(
            signing_key=b"r" * 32, key_id="remote-rpc-test",
            bindings_by_uid={1234: self.binding}, rules={}, handlers={},
            remote_session_authority=remote,
        )

    def test_remote_rpc_uses_only_socket_peer_identity(self):
        observed = {}

        class Remote:
            def admit_remote_session(_self, token, request, **peer):
                observed.update(token=token, request=request, peer=peer)
                return SimpleNamespace(to_wire=lambda: {"schema": 1, "accepted": True})

        service = self._service(Remote())
        request = RemoteAdmissionRequest(
            schema=1, request_id="request:test", hostname="desktop.example.test",
            origin="https://desktop.example.test", route_id="desktop-assets-v1",
            action="asset-read", client_nonce="n" * 24,
        )
        result = service._dispatch(
            1234, 5678, 91, "admit_remote_session",
            {"access_jwt_b64": base64.b64encode(b"opaque-jwt").decode(),
             "request": request.to_wire()}, cancelled=lambda: False,
        )
        self.assertEqual(result, {"schema": 1, "accepted": True})
        self.assertEqual(observed["token"], b"opaque-jwt")
        self.assertEqual(observed["request"], request)
        self.assertEqual(observed["peer"], {"peer_uid": 1234, "peer_pid": 5678, "peer_pidfd": 91})

    def test_remote_rpc_is_unavailable_without_root_enrollment(self):
        with self.assertRaises(AuthorityDenied) as denied:
            self._service()._dispatch(
                1234, 5678, 91, "challenge_remote_session",
                {"remote_session_handle": "opaque-handle-12345678901234567890"},
                cancelled=lambda: False,
            )
        self.assertEqual(denied.exception.code, "remote.unavailable")

    def test_client_remote_facade_uses_fixed_authenticated_rpc(self):
        response = {
            "schema": 1, "remote_session_handle": "h" * 43, "session_id": "session:test",
            "admission_kind": "one-shot-asset", "principal_binding_id": "principal-ref:test",
            "profile_id": "profile:test", "gateway_generation": "gateway-v1",
            "desktop_generation": "desktop-v1", "route_id": "desktop-assets-v1",
            "issued_monotonic": 10.0, "lease_expires_monotonic": 20.0,
            "jwt_expires_monotonic": 30.0, "policy_verified_monotonic": 9.0,
            "policy_revision": "policy-v1", "policy_config_digest": "a" * 64,
        }
        calls = []
        client = AuthorityClient(Path("/run/not-used.sock"))
        client._rpc = lambda operation, payload: calls.append((operation, payload)) or response
        request = RemoteAdmissionRequest(
            schema=1, request_id="request:test", hostname="desktop.example.test",
            origin="https://desktop.example.test", route_id="desktop-assets-v1",
            action="asset-read", client_nonce="n" * 24,
        )
        result = client.remote_sessions().admit_remote_session(b"jwt-bytes", request)
        self.assertEqual(result.session_id, "session:test")
        self.assertEqual(calls[0][0], "admit_remote_session")
        self.assertEqual(set(calls[0][1]), {"access_jwt_b64", "request"})
        self.assertEqual(base64.b64decode(calls[0][1]["access_jwt_b64"]), b"jwt-bytes")


if __name__ == "__main__":
    unittest.main()
