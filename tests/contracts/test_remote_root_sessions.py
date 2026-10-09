import dataclasses
import sys
import types
import unittest

from hermes_installer.remote.root_sessions import RootRemoteSessionClient, RootSessionDenied


@dataclasses.dataclass(frozen=True)
class Request:
    schema: int
    request_id: str
    hostname: str
    origin: str
    route_id: str
    action: str
    client_nonce: str


@dataclasses.dataclass(frozen=True)
class Handle:
    value: str


@dataclasses.dataclass(frozen=True)
class Admission:
    schema: int = 1
    remote_session_handle: object = Handle("A" * 43)
    session_id: str = "root-session-1"
    admission_kind: str = "one-shot-asset"
    principal_binding_id: str = "opaque-principal"
    profile_id: str = "hermes-desktop"
    gateway_generation: str = "gateway-generation"
    desktop_generation: str = "desktop-generation"
    route_id: str = "xpra-http"
    issued_monotonic: float = 10.0
    lease_expires_monotonic: float = 40.0
    jwt_expires_monotonic: float = 50.0
    policy_verified_monotonic: float = 9.0
    policy_revision: str = "policy-rev-1"
    policy_config_digest: str = "a" * 64


class FakeAuthority:
    def __init__(self):
        self.calls = []

    def admit_remote_session(self, token, request):
        self.calls.append(("admit", token, request))
        return dataclasses.replace(Admission(), route_id=request.route_id,
                                   admission_kind=("one-shot-asset" if request.action == "asset-read" else "leased-websocket"))

    def challenge_remote_session(self, handle):
        self.calls.append(("challenge", handle))
        return types.SimpleNamespace(schema=1, session_id="root-session-1",
                                     renewal_nonce="N" * 43, expires_monotonic=20.0)

    def renew_remote_session(self, handle, token, nonce):
        self.calls.append(("renew", handle, token, nonce))
        return types.SimpleNamespace(schema=1, session_id="root-session-1",
                                     remote_session_handle=handle,
                                     lease_expires_monotonic=35.0,
                                     jwt_expires_monotonic=50.0,
                                     policy_verified_monotonic=12.0)

    def close_remote_session(self, handle):
        self.calls.append(("close", handle))
        return types.SimpleNamespace(schema=1, session_id="root-session-1", state="closed")


class RootSessionAdapterTests(unittest.TestCase):
    def setUp(self):
        authority_module = types.ModuleType("hermes_installer.authority.remote_sessions")
        authority_module.RemoteAdmissionRequest = Request
        sys.modules[authority_module.__name__] = authority_module
        self.addCleanup(sys.modules.pop, authority_module.__name__, None)
        self.authority = FakeAuthority()
        self.client = RootRemoteSessionClient(
            self.authority, "desk.example.net", "https://desk.example.net",
            frozenset({"xpra-http"}), "xpra-websocket", monotonic=lambda: 12.0,
        )

    def test_admission_passes_raw_token_and_only_contract_request_fields(self):
        admitted = self.client.admit(access_jwt="synthetic.jwt.value", action="asset-read", route_id="xpra-http")
        self.assertEqual(admitted.handle.value, "A" * 43)
        self.assertNotIn("A" * 43, repr(admitted))
        self.assertEqual(admitted.admission_kind, "one-shot-asset")
        action, token, request = self.authority.calls[0]
        self.assertEqual((action, token), ("admit", b"synthetic.jwt.value"))
        self.assertEqual(dataclasses.asdict(request).keys(), {
            "schema", "request_id", "hostname", "origin", "route_id", "action", "client_nonce"
        })
        self.assertEqual(request.action, "asset-read")
        self.assertEqual(request.route_id, "xpra-http")

    def test_action_route_mismatch_and_caller_asserted_principal_are_not_accepted(self):
        with self.assertRaises(RootSessionDenied):
            self.client.admit(access_jwt="x", action="asset-read", route_id="xpra-websocket")
        with self.assertRaises(TypeError):
            self.client.admit(access_jwt="x", action="asset-read", route_id="xpra-http", email="owner@example.net")
        self.assertEqual(self.authority.calls, [])

    def test_root_challenge_fresh_renewal_and_cleanup_are_bound_to_opaque_handle(self):
        admitted = self.client.admit(access_jwt="first.jwt", action="websocket-attach", route_id="xpra-websocket")
        challenge = self.client.challenge(admitted.handle)
        self.assertNotIn("N" * 43, repr(challenge))
        expiry = self.client.renew(handle=admitted.handle, session_id=admitted.session_id, access_jwt="renewed.jwt",
                                   renewal_nonce=challenge.renewal_nonce)
        self.assertEqual(expiry, 35.0)
        self.assertEqual(self.authority.calls[1], ("challenge", admitted.handle))
        self.assertEqual(self.authority.calls[2], ("renew", admitted.handle, b"renewed.jwt", "N" * 43))
        self.client.close(admitted.handle, session_id=admitted.session_id)
        self.assertEqual(self.authority.calls[3], ("close", admitted.handle))

    def test_renewal_cannot_substitute_a_different_root_session_handle(self):
        class WrongHandle(FakeAuthority):
            def renew_remote_session(self, handle, token, nonce):
                answer = super().renew_remote_session(handle, token, nonce)
                return types.SimpleNamespace(**{**vars(answer), "remote_session_handle": "B" * 43})

        authority = WrongHandle()
        client = RootRemoteSessionClient(authority, "desk.example.net", "https://desk.example.net",
                                         frozenset({"xpra-http"}), "xpra-websocket", monotonic=lambda: 12.0)
        admitted = client.admit(access_jwt="first.jwt", action="websocket-attach", route_id="xpra-websocket")
        challenge = client.challenge(admitted.handle)
        with self.assertRaises(RootSessionDenied):
            client.renew(handle=admitted.handle, session_id=admitted.session_id,
                         access_jwt="renewed.jwt", renewal_nonce=challenge.renewal_nonce)

    def test_renewal_lease_is_anchored_to_policy_read_time(self):
        class LateLease(FakeAuthority):
            def renew_remote_session(self, handle, token, nonce):
                return types.SimpleNamespace(schema=1, session_id="root-session-1",
                                             remote_session_handle=handle,
                                             lease_expires_monotonic=72.0,
                                             jwt_expires_monotonic=90.0,
                                             policy_verified_monotonic=11.0)

        client = RootRemoteSessionClient(LateLease(), "desk.example.net", "https://desk.example.net",
                                         frozenset({"xpra-http"}), "xpra-websocket", monotonic=lambda: 12.0)
        admitted = client.admit(access_jwt="first.jwt", action="websocket-attach", route_id="xpra-websocket")
        challenge = client.challenge(admitted.handle)
        with self.assertRaises(RootSessionDenied):
            client.renew(handle=admitted.handle, session_id=admitted.session_id,
                         access_jwt="renewed.jwt", renewal_nonce=challenge.renewal_nonce)

    def test_invalid_root_response_is_denied(self):
        class Bad(FakeAuthority):
            def admit_remote_session(self, token, request):
                return dataclasses.replace(Admission(), lease_expires_monotonic=100.0)
        client = RootRemoteSessionClient(Bad(), "desk.example.net", "https://desk.example.net",
                                         frozenset({"xpra-http"}), "xpra-websocket", monotonic=lambda: 12.0)
        with self.assertRaises(RootSessionDenied):
            client.admit(access_jwt="token", action="asset-read", route_id="xpra-http")


if __name__ == "__main__":
    unittest.main()
