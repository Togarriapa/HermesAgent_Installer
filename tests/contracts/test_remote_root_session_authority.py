from __future__ import annotations

import hashlib
import secrets
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.utils import base64url_encode

from hermes_installer.authority.remote_sessions import (
    AsyncRemotePolicyVerifierAdapter, InternalRemoteConnectorAuthorization,
    RemoteAdmissionRequest, RemoteGatewayIdentity,
    RemoteLease, RemotePrincipalBinding, RemoteRuntimeState, RemoteSessionAuthority,
    RemotePolicyDecision, RemoteSessionEnrollment, RemoteSessionHandle, RootRemoteAccessVerifier,
    _bounded_deadline, _principal_mapping_digest,
)
from hermes_installer.authority.remote_registry import RemoteSessionAuthorityRegistry
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.authority.types import canonical_digest
from hermes_installer.remote.gateway import Principal, RemotePolicy
from hermes_installer.remote.jwks import JWKSCache


ISSUER = "https://team.cloudflareaccess.com"
HOST = "desktop.example.test"
ORIGIN = f"https://{HOST}"
EMAIL = "alice@example.test"
CONFIG_DIGEST = "a" * 64
POLICY_REVISION = "access-policy-v1"


class _FreshPolicy:
    def __init__(self, allowed: bool = True):
        self.allowed = allowed
        self.fail = False
        self.config_digest = CONFIG_DIGEST
        self.nonce_override = None
        self.validity_offset = 0.0
        self.fingerprint_override = None

    def authorize_access(self, *, action, session_id, access_jwt, expected):
        if self.fail:
            raise RuntimeError("fixture secret-resolution canary must not escape")
        if not self.allowed:
            raise RuntimeError("fresh selected Access policy denied")
        now = time.monotonic()
        return RemotePolicyDecision(
            action, session_id, expected.email, expected.subject,
            self.fingerprint_override or expected.token_fingerprint,
            now, now, now + max(1, expected.expires_at - time.time()),
            min(now + 50, now + max(1, expected.expires_at - time.time())) + self.validity_offset,
            self.config_digest, self.nonce_override or secrets.token_urlsafe(32))


class _Backend:
    def __init__(self):
        self.opened = []
        self.reads = []
        self.writes = []
        self.closed = []

    def open(self, binding, *, authorization, peer_uid, peer_pid, peer_pidfd):
        self.opened.append((binding, authorization, peer_uid, peer_pid, peer_pidfd))
        return secrets.token_urlsafe(32)

    def read(self, binding, connector_handle, sequence, maximum_bytes, *,
             authorization, peer_uid, peer_pid, peer_pidfd, cancelled):
        self.reads.append((binding, authorization, sequence, maximum_bytes))
        if cancelled():
            raise RuntimeError("cancelled")
        return b"asset", True

    def write(self, binding, connector_handle, sequence, data_bytes, *,
              authorization, peer_uid, peer_pid, peer_pidfd, cancelled):
        self.writes.append((binding, authorization, sequence, data_bytes))
        if cancelled():
            raise RuntimeError("cancelled")
        return len(data_bytes)

    def close(self, binding, connector_handle, *, authorization, cleanup,
              peer_uid=None, peer_pid=None, peer_pidfd=None):
        self.closed.append((binding, connector_handle, authorization, cleanup,
                            peer_uid, peer_pid, peer_pidfd))


class RemoteRootSessionAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public = cls.private_key.public_key().public_numbers()
        cls.jwk = {
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "fixture-key",
            "n": base64url_encode(public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")).decode(),
            "e": base64url_encode(public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")).decode(),
        }

    def setUp(self):
        self.wall = time.time()
        self.monotonic = time.monotonic
        self.cache = JWKSCache(ISSUER)
        self.cache._keys = {"fixture-key": self.jwk}
        self.cache._expires_at = time.monotonic() + 600
        self.fresh = _FreshPolicy()
        policy = RemotePolicy(HOST, ISSUER, "desktop-aud", frozenset({EMAIL}), self.cache)
        self.verifier = RootRemoteAccessVerifier(
            policy=policy, jwks=self.cache, policy_verifier=self.fresh,
            policy_revision=POLICY_REVISION, config_digest=CONFIG_DIGEST,
            verifier_enrollment_id="access-read-verifier-1")
        self.mapping = RemotePrincipalBinding(
            "access-subject-1", EMAIL, "root-principal-1", "hermes-desktop", "desktop-generation-1")
        self.enrollment = RemoteSessionEnrollment(
            enrollment_id="remote-enrollment-1", hostname=HOST, expected_origin=ORIGIN,
            jwt_issuer=ISSUER, jwt_audience="desktop-aud", jwks_origin=ISSUER,
            jwt_algorithm_allowlist=("RS256",), allowed_email_reference_id="allowed-emails-ref",
            policy_verifier_enrollment_id="access-read-verifier-1", profile_id="hermes-desktop",
            gateway_profile_id="remote-gateway", gateway_role_artifact_id="desktop-gateway-v1",
            gateway_role_sha256="b" * 64, gateway_generation="gateway-generation-1",
            native_desktop_profile_id="native-hermes-desktop", native_generation="desktop-generation-1",
            desktop_generation="desktop-generation-1", connector_target_id="xpra-native",
            approved_asset_routes=("xpra-http",), websocket_route_id="xpra-websocket",
            policy_revision=POLICY_REVISION, policy_config_digest=CONFIG_DIGEST,
            principal_bindings_by_subject={self.mapping.subject: self.mapping},
        )
        self.gateway = RemoteGatewayIdentity(
            1002, 200, "123456", "b" * 64, "cg-hermes-remote", "remote-gateway",
            "gateway-generation-1", "c" * 64, gid=1002, pid_starttime_ticks="123456",
            executable_device=2049, executable_inode=7001, mount_namespace_inode=3001,
            network_namespace_inode=3002, enrollment_id="remote-enrollment-1",
            pidfd_registry_handle="registry-peer-1")
        self.gateway2 = RemoteGatewayIdentity(
            1002, 201, "123457", "b" * 64, "cg-hermes-remote", "remote-gateway",
            "gateway-generation-1", "d" * 64, gid=1002, pid_starttime_ticks="123457",
            executable_device=2049, executable_inode=7001, mount_namespace_inode=3001,
            network_namespace_inode=3002, enrollment_id="remote-enrollment-1",
            pidfd_registry_handle="registry-peer-2")
        self.snapshot = self._snapshot()
        self.backend = _Backend()
        self.authorized_ops = []

        def resolve(uid, pid, pidfd):
            if uid != 1002 or pidfd < 1:
                raise ValueError
            return {200: self.gateway, 201: self.gateway2}[pid]

        def authorize(binding, operation, payload_bytes, sequence, maximum_bytes, **_kwargs):
            digest = hashlib.sha256(payload_bytes).hexdigest()
            self.authorized_ops.append((operation, digest, sequence, maximum_bytes, binding))
            now = time.monotonic()
            return InternalRemoteConnectorAuthorization(
                binding.principal_id, binding.native_profile_id, binding.native_generation,
                binding.gateway_identity.identity_digest, binding.gateway_generation,
                binding.session_id, binding.token_fingerprint, POLICY_REVISION, CONFIG_DIGEST,
                binding.target_id, binding.route_id, operation, digest, sequence,
                secrets.token_urlsafe(32), now, min(binding.lease_expires_monotonic,
                                                     binding.frame_deadline_monotonic
                                                     if operation != "connector.open"
                                                     else binding.lease_expires_monotonic),
                binding.service_generation_digest)

        self.authority = RemoteSessionAuthority(
            enrollment=self.enrollment, verifier=self.verifier,
            gateway_identity_resolver=resolve,
            gateway_identity_is_current=lambda gateway: gateway in {self.gateway, self.gateway2},
            runtime_state=lambda: self.snapshot,
            issue_remote_connector_effect=authorize,
            connector_backend=self.backend, watchdog=False)

    def _snapshot(self):
        return RemoteRuntimeState(
            "remote-enrollment-1", POLICY_REVISION, CONFIG_DIGEST,
            "gateway-generation-1", "desktop-generation-1",
            "native-hermes-desktop", "desktop-generation-1", "b" * 64,
            "xpra-native", _principal_mapping_digest({"access-subject-1": self.mapping}),
            "f" * 64)

    def token(self, *, email=EMAIL, subject="access-subject-1", audience="desktop-aud",
              issuer=ISSUER, expires=None):
        now = self.wall
        claims = {"iss": issuer, "aud": audience, "sub": subject, "email": email,
                  "iat": now - 1, "nbf": now - 1,
                  "exp": now + 180 if expires is None else expires}
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": "fixture-key"}).encode()

    def request(self, *, action="websocket-attach", route=None, request_id=None, nonce=None,
                hostname=HOST, origin=ORIGIN):
        return RemoteAdmissionRequest(
            1, request_id or secrets.token_urlsafe(24), hostname, origin,
            route or ("xpra-websocket" if action == "websocket-attach" else "xpra-http"),
            action, nonce or secrets.token_urlsafe(24))

    def admit(self, token=None, request=None, pid=200):
        return self.authority.admit_remote_session(
            token or self.token(), request or self.request(), peer_uid=1002, peer_pid=pid,
            peer_pidfd=8)

    def test_actual_jwt_signature_audience_and_fresh_policy_are_root_verified(self):
        admitted = self.admit()
        self.assertEqual(admitted.profile_id, "hermes-desktop")
        self.assertIsNotNone(admitted.remote_session_handle.value)
        forged = self.token()[:-1] + (b"A" if self.token()[-1:] != b"A" else b"B")
        with self.assertRaises(AuthorityDenied):
            self.admit(token=forged)
        with self.assertRaises(AuthorityDenied):
            self.admit(token=self.token(audience="wrong-audience"))
        with self.assertRaises(AuthorityDenied):
            self.admit(token=self.token(expires=self.wall - 1))
        self.fresh.allowed = False
        with self.assertRaises(AuthorityDenied):
            self.admit()
        self.fresh.fail = True
        with self.assertRaises(AuthorityDenied) as failure:
            self.admit()
        self.assertNotIn("canary", str(failure.exception))

    def test_request_cannot_supply_identity_policy_or_backend_authority(self):
        request = self.request().to_wire()
        for forbidden in ("email", "subject", "policy_grant", "principal_id", "connector_url", "target_id"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaises(AuthorityDenied):
                    RemoteAdmissionRequest.from_wire({**request, forbidden: "attacker-value"})

    def test_gateway_claims_route_and_subject_profile_join_are_not_caller_selected(self):
        with self.assertRaises(AuthorityDenied):
            self.admit(request=self.request(route="attacker-url"))
        with self.assertRaises(AuthorityDenied):
            self.admit(request=self.request(hostname="other.example.test"))
        with self.assertRaises(AuthorityDenied):
            self.admit(token=self.token(subject="unmapped-subject"))
        with self.assertRaises(AuthorityDenied):
            self.admit(pid=999)

    def test_subject_mapping_may_select_different_root_enrolled_profiles(self):
        second = RemotePrincipalBinding(
            "access-subject-2", "bob@example.test", "root-principal-2",
            "hermes-desktop-secondary", "desktop-generation-secondary")
        mixed = replace(self.enrollment, profile_id=None,
                        principal_bindings_by_subject={self.mapping.subject: self.mapping,
                                                       second.subject: second})
        self.assertEqual(mixed.principal_bindings_by_subject[second.subject].profile_id,
                         "hermes-desktop-secondary")

    def test_admission_nonce_replay_is_denied(self):
        request = self.request()
        self.admit(request=request)
        with self.assertRaises(AuthorityDenied):
            self.admit(request=request)

    def test_root_rejects_replayed_or_mismatched_policy_verifier_decisions(self):
        self.fresh.nonce_override = secrets.token_urlsafe(32)
        self.admit()
        with self.assertRaises(AuthorityDenied):
            self.admit()

        self.fresh.nonce_override = None
        self.fresh.fingerprint_override = "0" * 64
        with self.assertRaises(AuthorityDenied):
            self.admit()

    def test_expired_policy_verifier_lease_is_denied(self):
        self.fresh.validity_offset = -90
        with self.assertRaises(AuthorityDenied):
            self.admit()

    def test_async_isolated_policy_client_has_typed_sync_root_adapter(self):
        class AsyncClient:
            config_digest = CONFIG_DIGEST

            async def authorize(self, *, action, session_id, access_jwt, expected):
                self.request = (action, session_id, access_jwt)
                now = time.monotonic()
                return SimpleNamespace(
                    action=action, session_id=session_id, principal=expected,
                    observed_start_monotonic=now, observed_end_monotonic=now,
                    jwt_deadline_monotonic=now + 30,
                    valid_until_monotonic=now + 20, config_digest=CONFIG_DIGEST,
                    nonce=secrets.token_urlsafe(32))

        client = AsyncClient()
        adapter = AsyncRemotePolicyVerifierAdapter(client, config_digest=CONFIG_DIGEST)
        try:
            principal = Principal(EMAIL, "sub", time.time() + 30, "f" * 64)
            result = adapter.authorize_access(
                action="issue", session_id="session-1", access_jwt=b"signed-token",
                expected=principal)
            self.assertEqual((result.action, result.session_id, result.subject),
                             ("issue", "session-1", "sub"))
            self.assertEqual(client.request, ("issue", "session-1", "signed-token"))
        finally:
            adapter.close()

    def test_fresh_one_use_challenge_renews_same_identity_and_replay_closes(self):
        admitted = self.admit()
        handle = admitted.remote_session_handle
        challenge = self.authority.challenge_remote_session(
            handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        renewed = self.authority.renew_remote_session(
            handle, self.token(), challenge.renewal_nonce,
            peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(renewed.session_id, admitted.session_id)
        with self.assertRaises(AuthorityDenied):
            self.authority.renew_remote_session(
                handle, self.token(), challenge.renewal_nonce,
                peer_uid=1002, peer_pid=200, peer_pidfd=8)

    def test_renewal_deadline_rounding_never_exceeds_sixty_seconds(self):
        # This representable monotonic value makes `start + 60 - start` equal
        # 60.00000000000001 on CPython; cap downward before minting the lease.
        start = 63.0973294985805
        expiry = _bounded_deadline(start, 60.0)
        self.assertLessEqual(expiry - start, 60.0)
        lease = RemoteLease(1, RemoteSessionHandle(secrets.token_urlsafe(32)),
                            "remote-session-1", expiry, expiry + 1,
                            start, POLICY_REVISION, CONFIG_DIGEST)
        self.assertLessEqual(lease.lease_expires_monotonic - lease.policy_verified_monotonic, 60.0)

    def test_wrong_subject_revokes_active_stream_and_watchdog_closes_generation_drift(self):
        admitted = self.admit()
        handle = admitted.remote_session_handle
        opened = self.authority.open_remote_connector(
            handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        challenge = self.authority.challenge_remote_session(
            handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        with self.assertRaises(AuthorityDenied):
            self.authority.renew_remote_session(
                handle, self.token(subject="other-subject"), challenge.renewal_nonce,
                peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertTrue(self.backend.closed)

        admitted2 = self.admit()
        opened = self.authority.open_remote_connector(
            admitted2.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.snapshot = self._snapshot().__class__(
            "remote-enrollment-1", POLICY_REVISION, CONFIG_DIGEST,
            "gateway-generation-1", "desktop-generation-changed",
            "native-hermes-desktop", "desktop-generation-changed", "b" * 64,
            "xpra-native", _principal_mapping_digest({"access-subject-1": self.mapping}),
            "f" * 64)
        self.authority.watchdog_once()
        self.assertTrue(self.backend.closed)

    def test_asset_route_is_one_open_read_only_and_bounded_before_return(self):
        admitted = self.admit(request=self.request(action="asset-read"))
        handle = admitted.remote_session_handle
        opened = self.authority.open_remote_connector(handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        request = b"GET /client/index.html HTTP/1.1\r\nAccept: */*\r\n\r\n"
        sent = self.authority.write_remote_connector(
            handle, opened.connector_handle, 0, request,
            peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(sent.accepted_bytes, len(request))
        data = self.authority.read_remote_connector(
            handle, opened.connector_handle, 1, 32, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(data.data_bytes, b"asset")
        self.assertEqual([x[0] for x in self.authorized_ops], [
            "connector.open", "connector.write", "connector.read", "connector.close"])
        self.assertTrue(self.backend.closed[-1][3] is False)
        with self.assertRaises(AuthorityDenied):
            self.authority.open_remote_connector(handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)

    def test_asset_write_is_single_canonical_get_or_head_only(self):
        for request_bytes in (
            b"POST /client/index.html HTTP/1.1\r\nContent-Length: 0\r\n\r\n",
            b"GET /client/unlisted.js HTTP/1.1\r\n\r\n",
        ):
            with self.subTest(request_bytes=request_bytes[:24]):
                admitted = self.admit(request=self.request(action="asset-read"))
                opened = self.authority.open_remote_connector(
                    admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
                with self.assertRaises(AuthorityDenied):
                    self.authority.write_remote_connector(
                        admitted.remote_session_handle, opened.connector_handle, 0, request_bytes,
                        peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.backend.writes, [])

    def test_asset_connector_cannot_write(self):
        admitted = self.admit(request=self.request(action="asset-read"))
        opened = self.authority.open_remote_connector(
            admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        with self.assertRaises(AuthorityDenied):
            self.authority.write_remote_connector(
                admitted.remote_session_handle, opened.connector_handle, 0, b"control",
                peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.backend.writes, [])

    def test_websocket_frames_use_exact_grants_and_sequence_replay_closes(self):
        admitted = self.admit()
        handle = admitted.remote_session_handle
        opened = self.authority.open_remote_connector(handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        sent = self.authority.write_remote_connector(
            handle, opened.connector_handle, 0, b"input", peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(sent.accepted_bytes, 5)
        self.assertEqual(self.authorized_ops[-1][0], "connector.write")
        binding, open_auth, *_ = self.backend.opened[-1]
        self.assertEqual(open_auth.canonical_payload_sha256, canonical_digest({
            "schema": 1, "enrollment_id": binding.enrollment_id,
            "generation": binding.native_generation, "target_id": binding.target_id,
            "action": "open", "approved_route_id": binding.route_id,
            "session_id": binding.session_id, "deadline": binding.lease_expires_monotonic}))
        write_binding, write_auth, *_ = self.backend.writes[-1]
        self.assertEqual(write_auth.canonical_payload_sha256, canonical_digest({
            "schema": 1, "target_id": write_binding.target_id, "route_id": write_binding.route_id,
            "connector_id": opened.connector_handle, "session_id": write_binding.session_id,
            "generation": write_binding.native_generation, "sequence": 0,
            "deadline": write_binding.frame_deadline_monotonic, "data_b64": "aW5wdXQ="}))
        with self.assertRaises(AuthorityDenied):
            self.authority.read_remote_connector(
                handle, opened.connector_handle, 0, 32, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertTrue(self.backend.closed)

    def test_sibling_gateway_cannot_use_or_close_session(self):
        admitted = self.admit()
        handle = admitted.remote_session_handle
        with self.assertRaises(AuthorityDenied):
            self.authority.challenge_remote_session(handle, peer_uid=1002, peer_pid=201, peer_pidfd=9)
        with self.assertRaises(AuthorityDenied):
            self.authority.close_remote_session(handle, peer_uid=1002, peer_pid=201, peer_pidfd=9)

    def test_expiry_and_current_config_drift_deny_before_connector_bytes(self):
        admitted = self.admit()
        state = self.authority._sessions[admitted.remote_session_handle]
        state.lease_expires_monotonic = time.monotonic() - 1
        with self.assertRaises(AuthorityDenied):
            self.authority.challenge_remote_session(
                admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.backend.opened, [])

        request = self.request()
        self.snapshot = RemoteRuntimeState(
            "remote-enrollment-1", "changed-policy", CONFIG_DIGEST,
            "gateway-generation-1", "desktop-generation-1",
            "native-hermes-desktop", "desktop-generation-1", "b" * 64,
            "xpra-native", _principal_mapping_digest({"access-subject-1": self.mapping}),
            "f" * 64)
        with self.assertRaises(AuthorityDenied):
            self.admit(request=request)

    def test_raw_token_and_context_are_not_in_handle_repr_or_authorization_repr(self):
        token = self.token()
        admitted = self.admit(token=token)
        self.assertNotIn(token.decode(), repr(admitted.remote_session_handle))
        opened = self.authority.open_remote_connector(
            admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        auth = self.backend.opened[-1][1]
        self.assertNotIn("access-subject-1", repr(auth))
        self.assertNotIn("alice@example.test", repr(auth))
        self.assertNotIn(token.decode(), repr(auth))

    def test_registry_routes_hostname_and_opaque_handle_to_one_authority(self):
        registry = RemoteSessionAuthorityRegistry({
            self.enrollment.enrollment_id: self.authority,
        })
        request = self.request()
        admitted = registry.admit_remote_session(
            self.token(), request, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        challenge = registry.challenge_remote_session(
            admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(challenge.session_id, admitted.session_id)
        registry.close_remote_session(
            admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        with self.assertRaises(AuthorityDenied):
            registry.challenge_remote_session(
                admitted.remote_session_handle, peer_uid=1002, peer_pid=200, peer_pidfd=8)
        with self.assertRaises(AuthorityDenied):
            registry.admit_remote_session(
                self.token(), replace(request, hostname="other.example.test"),
                peer_uid=1002, peer_pid=200, peer_pidfd=8)


if __name__ == "__main__":
    unittest.main()
