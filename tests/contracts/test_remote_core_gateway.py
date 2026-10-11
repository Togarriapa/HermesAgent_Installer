"""Core-mode gateway proof binding and fail-closed ingress contracts."""
from __future__ import annotations

import dataclasses
import hashlib
import stat
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.remote import core_gateway, core_gateway_inspector
from hermes_installer.remote.gateway import Principal, RemotePolicy


def _config():
    digest = "a" * 64
    return core_gateway.CoreGatewayConfig(
        hostname="jarvis.example.test",
        issuer="https://team.cloudflareaccess.com",
        audience="core-test-audience",
        allowed_emails=frozenset({"owner@example.test"}),
        gateway_uid=996, gateway_gid=981, core_uid=1000, core_gid=1000,
        boot_id="12345678-1234-1234-1234-123456789012",
        gateway_unit_sha256=digest, gateway_python_sha256=digest,
        tunnel_unit_sha256=digest, cloudflared_binary_sha256=digest,
        core_unit_sha256=digest, core_launcher_sha256=digest,
        core_python=Path("/home/admin/HermesInstaller/data/installs/" + "a" * 24
                         + "/environments/" + "b" * 32 + "/venv/bin/python"),
        core_python_sha256=digest,
        ingress_socket=core_gateway.CORE_INGRESS_SOCKET,
        config_path=core_gateway.CORE_CONFIG, config_sha256=digest)


def _root_observation(config):
    nonce = "b" * 64
    core_pid = 330
    start_ticks = "77"
    listener_inode = 8822
    invocation = "12345678-1234-1234-1234-123456789012"
    generation = hashlib.sha256(
        b"hermes-jarvis-core-generation-v1\0" +
        f"{invocation}\0{core_pid}\0{start_ticks}\0{listener_inode}".encode("ascii")
    ).hexdigest()
    claims = {
        "schema": 1, "nonce": nonce, "boot_id": config.boot_id,
        "issued_monotonic": 10.0, "expires_monotonic": 15.0,
        "peer_pid": 440, "peer_uid": 996, "peer_gid": 981,
        "peer_start_ticks": "88", "tunnel_invocation_id": invocation,
        "tunnel_unit_sha256": config.tunnel_unit_sha256,
        "tunnel_executable_sha256": config.cloudflared_binary_sha256,
        "origin_socket_device": 1, "origin_socket_inode": 2,
        "gateway_unit_sha256": config.gateway_unit_sha256,
        "core_unit_sha256": config.core_unit_sha256,
        "core_invocation_id": invocation, "core_pid": core_pid,
        "core_start_ticks": start_ticks, "core_listener_inode": listener_inode,
        "core_generation": generation, "config_sha256": config.config_sha256,
    }
    proof_sha = core_gateway_inspector._observation_digest(claims)
    return core_gateway_inspector.CoreVerifiedIngressObservation(
        **claims, proof_sha256=proof_sha, _seal=core_gateway_inspector._PROOF_SEAL)


class CoreGatewayProofTests(unittest.TestCase):
    def test_root_observation_binds_exact_claims_and_original_deadline(self):
        config = _config()
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id):
            proof = _root_observation(config)
            self.assertIs(proof.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                                               listener_identity=(1, 2), now=12.0), True)
            self.assertIs(proof.verify_current(config, peer_pid=441, peer_uid=996, peer_gid=981,
                                               listener_identity=(1, 2), now=12.0), False)
            self.assertIs(proof.verify_current(config, peer_pid=440, peer_uid=996, peer_gid=981,
                                               listener_identity=(1, 2), now=15.0), False)
            # A frozen dataclass copy must not retain authority after a claim is altered.
            changed = dataclasses.replace(proof, peer_uid=1000)
            self.assertIs(changed.verify_current(config, peer_pid=440, peer_uid=1000, peer_gid=981,
                                                 listener_identity=(1, 2), now=12.0), False)

    def test_accepted_ingress_binds_principal_peer_listener_and_root_proof(self):
        config = _config()
        fake_stat = SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2,
                                    st_uid=config.gateway_uid, st_gid=config.gateway_gid)
        with patch.object(core_gateway_inspector, "_boot_id", return_value=config.boot_id), \
             patch.object(core_gateway.os, "lstat", return_value=fake_stat), \
             patch.object(core_gateway, "_read_config_current"):
            root = _root_observation(config)
            principal = Principal("owner@example.test", "owner-subject", 2000.0, "c" * 64)
            values = dict(principal=principal, jwt_expiry=20.0, root_proof=root,
                          peer=(440, 996, 981), listener=(1, 2), issued=10.0, expiry=15.0,
                          core_generation=root.core_generation, config_sha256=config.config_sha256)
            accepted = core_gateway.CoreAcceptedIngressObservation(
                principal, 20.0, root, 440, 996, 981, 1, 2, 10.0, 15.0,
                root.core_generation, config.config_sha256,
                core_gateway._accepted_claim_digest(**values),
                core_gateway._ACCEPTED_INGRESS_SEAL)
            self.assertIs(accepted.verify_current(config, now=12.0), True)
            altered = dataclasses.replace(accepted, expires_monotonic=30.0)
            self.assertIs(altered.verify_current(config, now=12.0), False)
            self.assertIs(accepted.verify_current(config, now=15.0), False)


class CoreGatewayIngressTests(unittest.IsolatedAsyncioTestCase):
    async def test_wrong_host_is_denied_before_jwt_or_root_observation(self):
        config = _config()
        policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                              config.allowed_emails, {})

        async def unexpected_jwt(*_args, **_kwargs):
            raise AssertionError("JWT validator must not run for a wrong Host")

        def unexpected_root(*_args, **_kwargs):
            raise AssertionError("root inspector must not run for a wrong Host")

        headers = SimpleNamespace(getall=lambda key, default=():
                                  ["attacker.example.test"] if key == "Host" else ["x"])
        request = SimpleNamespace(headers=headers, method="POST", app={})
        with patch.object(core_gateway, "_validate_jwt", unexpected_jwt), \
             patch.object(core_gateway_inspector, "verify_current_ingress", unexpected_root,
                          create=True):
            with self.assertRaises(core_gateway.CoreGatewayDenied):
                await core_gateway.accept_core_ingress(request, config, policy)
