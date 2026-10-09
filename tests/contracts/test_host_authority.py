from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path

from hermes_installer.authority.client import (
    AuthorityClient, canonical_profile_target, profile_launch_envelope,
)
from hermes_installer.authority.service import (
    AuthorityService, EffectRule, PrincipalBinding,
)
from hermes_installer.authority.types import (
    AuthorityDenied, Sensitivity, canonical_digest,
)


class ProfileLaunchEnvelopeContracts(unittest.TestCase):
    def test_child_script_digest_is_bound_inside_pinned_artifact_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact_root = root / "artifact"
            artifact_root.mkdir()
            executable = artifact_root / "hermes"
            executable.write_bytes(b"pinned executable")
            child = artifact_root / "install.sh"
            child.write_bytes(b"pinned script")
            data_root = root / "profile-data"
            data_root.mkdir()
            target = canonical_profile_target("profile:one", executable, data_root)
            launch = profile_launch_envelope(
                target=target, profile_id="profile:one", executable=executable,
                artifact_sha256="a" * 64, artifact_root=artifact_root,
                cwd=artifact_root, data_root=data_root,
                argv=[str(executable.resolve()), str(child.resolve())],
                env_allowlist={}, child_artifact_hashes={
                    str(child.resolve()): canonical_digest(child.read_bytes()),
                },
            )
            self.assertEqual(launch["child_artifact_hashes"][str(child.resolve())], canonical_digest(child.read_bytes()))
            outside = root / "outside.sh"
            outside.write_bytes(b"outside")
            with self.assertRaises(AuthorityDenied):
                profile_launch_envelope(
                    target=target, profile_id="profile:one", executable=executable,
                    artifact_sha256="a" * 64, artifact_root=artifact_root,
                    cwd=artifact_root, data_root=data_root,
                    argv=[str(executable.resolve()), str(outside.resolve())],
                    env_allowlist={}, child_artifact_hashes={
                        str(outside.resolve()): canonical_digest(outside.read_bytes()),
                    },
                )


class FixturePolicy:
    revision = "fixture-17"

    def classify(self, *, purpose, intent, source_contexts, binding):
        if source_contexts:
            return max((item.sensitivity for item in source_contexts), key=lambda x: list(Sensitivity).index(x)), canonical_digest(sorted(item.lineage_hash for item in source_contexts))
        return Sensitivity.PRIVATE, canonical_digest({"purpose": purpose, "profile": binding.profile_id})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return context.sensitivity is Sensitivity.PRIVATE and retry_index <= 3


@unittest.skipUnless(hasattr(socket, "SO_PEERCRED"), "requires Linux kernel Unix peer credentials")
class HostAuthorityIPCContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.socket_path = root / "authority.sock"
        self.effects = []
        self.binding = PrincipalBinding(os.getuid(), "principal:alice", "profile:one", "namespace:one", frozenset({"memory-capture"}))
        target = "memory:openviking:capture"
        rule = EffectRule("memory-capture", "memory.capture", target)

        def handler(*, context, authorization, payload, timeout, peer_pid, cancelled):
            if cancelled():
                raise TimeoutError("cancelled")
            self.effects.append(payload)
            return {"status": 200, "body": b'{"stored":true}', "headers": {"content-type": "application/json"}, "receipt_id": "receipt-1"}

        self.service = AuthorityService(
            signing_key=b"k" * 32, key_id="fixture-key",
            bindings_by_uid={self.binding.uid: self.binding},
            rules={(rule.capability, rule.target): rule},
            handlers={(rule.operation, rule.target): handler},
            policy=FixturePolicy(),
        )
        self.stop = threading.Event()
        self.server_error = []
        def serve():
            try:
                self.service.serve_unix(
                    self.socket_path, socket_gid=os.getgid(), stop_event=self.stop,
                    expected_uid=os.getuid(), max_clients=16,
                )
            except BaseException as exc:
                self.server_error.append(exc)
        self.acceptor = threading.Thread(target=serve, daemon=True)
        self.acceptor.start()
        deadline = time.monotonic() + 2
        while not self.socket_path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        self.client = AuthorityClient(self.socket_path, server_uid=os.getuid(), timeout=2)

    def tearDown(self):
        self.stop.set()
        self.acceptor.join(timeout=1)
        self.assertFalse(self.acceptor.is_alive())
        self.assertEqual(self.server_error, [])
        self.temp.cleanup()

    def _context_and_grant(self, payload=b"capture"):
        context = self.client.context(purpose="memory-capture", intent="store approved source")
        digest = canonical_digest(payload)
        grant = self.client.authorize_effect(
            context, capability="memory-capture", target="memory:openviking:capture",
            request_digest=digest,
        )
        return context, grant, digest

    def test_peer_uid_issues_signed_context_and_fixed_broker_performs_effect(self):
        context, grant, digest = self._context_and_grant()
        self.assertEqual(context.uid, os.getuid())
        self.assertEqual(context.principal_id, "principal:alice")
        self.assertEqual(context.sensitivity, Sensitivity.PRIVATE)
        self.assertEqual(grant.request_digest, digest)
        response = self.client.memory_request(
            grant, target=grant.target, request_digest=digest,
            payload=b"capture", timeout=1,
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(self.effects, [b"capture"])

    def test_payload_tamper_replay_and_unenrolled_target_have_no_effect(self):
        context, grant, digest = self._context_and_grant()
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(grant, operation="memory.capture", payload=b"tampered", timeout=1)
        self.assertEqual(self.effects, [])

        self.client.perform_effect(grant, operation="memory.capture", payload=b"capture", timeout=1)
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(grant, operation="memory.capture", payload=b"capture", timeout=1)
        self.assertEqual(self.effects, [b"capture"])

        with self.assertRaises(AuthorityDenied):
            self.client.authorize_effect(
                context, capability="memory-capture", target="https://attacker.invalid/",
                request_digest=digest,
            )
        self.assertEqual(self.effects, [b"capture"])

    def test_signature_tamper_is_denied_by_host_before_handler(self):
        _context, grant, _digest = self._context_and_grant()
        forged = replace(grant, signature="0" * 64)
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(forged, operation="memory.capture", payload=b"capture", timeout=1)
        self.assertEqual(self.effects, [])

    def test_policy_denial_is_rechecked_at_effect_boundary(self):
        class RevokesAtBroker(FixturePolicy):
            calls = 0

            def allow_effect(inner, **kwargs):
                inner.calls += 1
                return inner.calls == 1

        policy = RevokesAtBroker()
        self.service.policy = policy
        context = self.client.context(purpose="memory-capture", intent="revocation fixture")
        payload = b"capture"
        grant = self.client.authorize_effect(
            context, capability="memory-capture", target="memory:openviking:capture",
            request_digest=canonical_digest(payload),
        )
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(grant, operation="memory.capture", payload=payload, timeout=1)
        self.assertEqual(policy.calls, 2)
        self.assertEqual(self.effects, [])


if __name__ == "__main__":
    unittest.main()
