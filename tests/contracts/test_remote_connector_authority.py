"""HI13 remote connector grants recheck both principals and spend once."""
from __future__ import annotations

import hashlib
import secrets
import time
import unittest
from dataclasses import replace
from types import SimpleNamespace

from hermes_installer.authority.remote_connector_authority import (
    GatewayRoleProof, RemoteConnectorEffectAuthority,
)
from hermes_installer.authority.remote_sessions import (
    RemoteConnectorBinding, RemoteGatewayIdentity, RemoteRuntimeState,
)
from hermes_installer.authority.types import AuthorityDenied, canonical_bytes


class _HI12:
    def __init__(self):
        self.issued = []
        self.consumed = []

    def issue_remote_connector_effect(self, **kwargs):
        item = (secrets.token_urlsafe(24), kwargs)
        self.issued.append(item)
        return item

    def consume_remote_connector_effect(self, grant, **kwargs):
        if grant not in self.issued or grant in self.consumed:
            return False
        self.consumed.append(grant)
        return True


class RemoteConnectorEffectAuthorityContracts(unittest.TestCase):
    def setUp(self):
        self.now = time.monotonic()
        self.entrypoint_id = "remote-gateway-entrypoint-v1"
        self.entrypoint_digest = "e" * 64
        self.gateway_identity = RemoteGatewayIdentity(
            1002, 200, "123456", "b" * 64, "cg-remote", "remote-gateway",
            "gateway-generation-1", "c" * 64, gid=1002,
            pid_starttime_ticks="123456", executable_device=2049,
            executable_inode=7001, mount_namespace_inode=3001,
            network_namespace_inode=3002, enrollment_id="remote-enrollment-1",
            pidfd_registry_handle="registry-peer-1")
        self.enrollment = SimpleNamespace(
            enrollment_id="remote-enrollment-1", gateway_profile_id="remote-gateway",
            gateway_generation="gateway-generation-1", gateway_role_artifact_id="gateway-role-v1",
            gateway_role_sha256="b" * 64, native_desktop_profile_id="native-desktop",
            native_generation="desktop-generation-1", connector_target_id="xpra-native",
            policy_revision="policy-v1", policy_config_digest="a" * 64)
        self.state = RemoteRuntimeState(
            "remote-enrollment-1", "policy-v1", "a" * 64,
            "gateway-generation-1", "desktop-generation-1", "native-desktop",
            "desktop-generation-1", "b" * 64, "xpra-native", "d" * 64,
            "f" * 64)
        self.proof = GatewayRoleProof(
            "remote-enrollment-1", "remote-gateway", "gateway-generation-1",
            "b" * 64, "gateway-role-v1", "b" * 64, self.entrypoint_id,
            self.entrypoint_digest, "boot-epoch-1", self.now - 1, self.now + 60)
        self.current_binding = None
        self.hi12 = _HI12()
        self.authority = self._authority()
        self.binding = RemoteConnectorBinding(
            "remote-enrollment-1", "remote-session-1", "websocket-attach",
            "xpra-websocket", "xpra-native", "verified-access-subject",
            "access-principal", "user-profile", "user-profile-generation",
            "remote-gateway", "gateway-generation-1", "native-desktop",
            "desktop-generation-1", "policy-v1", "a" * 64, "f" * 64,
            "connector-id-01234567890123456789012345678901", 0,
            self.gateway_identity, "9" * 64, self.now, self.now + 45,
            self.now + 5, lambda: False)
        self.current_binding = self.binding

    def _authority(self):
        return RemoteConnectorEffectAuthority(
            runtime_state=lambda: self.state, enrollment=self.enrollment,
            boot_epoch=lambda: "boot-epoch-1",
            gateway=lambda uid, pid, pidfd: self.gateway_identity
            if (uid, pid, pidfd) == (1002, 200, 8) else (_ for _ in ()).throw(ValueError()),
            role_proof=lambda identity: self.proof,
            session_current=lambda binding, operation, sequence: binding == self.current_binding,
            hi12=self.hi12, monotonic=lambda: self.now,
            gateway_entrypoint_artifact_id=self.entrypoint_id,
            gateway_entrypoint_sha256=self.entrypoint_digest)

    def _open_payload(self, binding=None):
        b = binding or self.binding
        return canonical_bytes({
            "schema": 1, "enrollment_id": b.enrollment_id,
            "generation": b.native_generation, "target_id": b.target_id,
            "action": "open", "approved_route_id": b.route_id,
            "session_id": b.session_id, "deadline": b.lease_expires_monotonic,
        })

    def _issue(self, binding=None):
        b = binding or self.binding
        return self.authority.issue_remote_connector_effect(
            b, "connector.open", self._open_payload(b), 0,
            peer_uid=1002, peer_pid=200, peer_pidfd=8)

    def _consume(self, auth, binding=None):
        b = binding or self.binding
        return self.authority.consume_remote_connector_effect(
            auth, b, "connector.open", self._open_payload(b), 0,
            peer_uid=1002, peer_pid=200, peer_pidfd=8)

    def test_exact_dual_principal_grant_is_consumed_once(self):
        auth = self._issue()
        self.assertEqual(auth.effective_principal_id, "access-principal")
        self.assertEqual(auth.effective_native_profile_id, "native-desktop")
        self.assertEqual(auth.controller_gateway_identity_digest, self.gateway_identity.identity_digest)
        self.assertEqual(auth.canonical_payload_sha256, hashlib.sha256(self._open_payload()).hexdigest())
        self.assertTrue(self._consume(auth))
        with self.assertRaises(AuthorityDenied):
            self._consume(auth)

    def test_pid_replacement_role_proof_stale_registry_and_revocation_deny(self):
        for change in ("pid", "entrypoint", "policy", "generation"):
            with self.subTest(change=change):
                self.setUp()
                auth = self._issue()
                if change == "pid":
                    self.authority._gateway = lambda *_: replace(self.gateway_identity, pid=201)
                elif change == "entrypoint":
                    self.proof = replace(self.proof, entrypoint_sha256="0" * 64)
                elif change == "policy":
                    self.state = replace(self.state, policy_config_digest="0" * 64)
                else:
                    self.state = replace(self.state, native_generation="new-generation")
                with self.assertRaises(AuthorityDenied):
                    self._consume(auth)
        self.setUp()
        auth = self._issue()
        self.authority.revoke_session(self.binding.session_id)
        with self.assertRaises(AuthorityDenied):
            self._consume(auth)

    def test_payload_and_cross_profile_binding_mismatch_deny_without_hi12_spend(self):
        auth = self._issue()
        forged = replace(self.binding, native_profile_id="sibling-profile")
        with self.assertRaises(AuthorityDenied):
            self._consume(auth, forged)
        payload = canonical_bytes({**__import__("json").loads(self._open_payload()),
                                   "target_id": "other-target"})
        with self.assertRaises(AuthorityDenied):
            self.authority.consume_remote_connector_effect(
                auth, self.binding, "connector.open", payload, 0,
                peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.hi12.consumed, [])

    def test_expiry_and_cancellation_deny_before_hi12_issue_or_spend(self):
        expired = replace(self.binding, frame_deadline_monotonic=self.now - 1)
        self.current_binding = expired
        payload = canonical_bytes({
            "schema": 1, "enrollment_id": expired.enrollment_id,
            "generation": expired.native_generation, "target_id": expired.target_id,
            "action": "open", "approved_route_id": expired.route_id,
            "session_id": expired.session_id, "deadline": expired.lease_expires_monotonic,
        })
        # Open is governed by the original session lease; a frame effect is
        # governed by the shorter frame deadline. This write frame is expired.
        body = {"schema": 1, "target_id": expired.target_id, "route_id": expired.route_id,
                "connector_id": expired.connector_handle, "session_id": expired.session_id,
                "generation": expired.native_generation, "deadline": expired.frame_deadline_monotonic,
                "sequence": 0, "data_b64": "YQ=="}
        with self.assertRaises(AuthorityDenied):
            self.authority.issue_remote_connector_effect(
                expired, "connector.write", canonical_bytes(body), 0, 1,
                peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.hi12.issued, [])

        cancelled = replace(self.binding, cancelled=lambda: True)
        self.current_binding = cancelled
        with self.assertRaises(AuthorityDenied):
            self.authority.issue_remote_connector_effect(
                cancelled, "connector.open", self._open_payload(cancelled), 0,
                peer_uid=1002, peer_pid=200, peer_pidfd=8)
        self.assertEqual(self.hi12.issued, [])
