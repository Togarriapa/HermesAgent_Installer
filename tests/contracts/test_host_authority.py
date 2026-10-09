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
from hermes_installer.authority.authentik import (
    AuthentikEnrollment, AuthentikResponse, AuthentikSystemPolicy, PrincipalIdentity,
)
from hermes_installer.authority.service import (
    AuthorityService, ChildDelegationRule, EffectRule, PrincipalBinding,
)
from hermes_installer.authority.types import (
    AuthorityDenied, EffectAuthorization, HostContext, Sensitivity, canonical_digest,
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
            digest = canonical_digest(child.read_bytes())
            store_id = f"artifact:install.sh:{digest}"
            launch = profile_launch_envelope(
                target=target, profile_id="profile:one", executable=executable,
                artifact_sha256="a" * 64, artifact_root=artifact_root,
                cwd=artifact_root, data_root=data_root,
                argv=[str(executable.resolve()), store_id],
                env_allowlist={}, child_artifact_refs={store_id: digest},
            )
            self.assertEqual(launch["child_artifact_refs"][store_id], digest)
            with self.assertRaises(AuthorityDenied):
                profile_launch_envelope(
                    target=target, profile_id="profile:one", executable=executable,
                    artifact_sha256="a" * 64, artifact_root=artifact_root,
                    cwd=artifact_root, data_root=data_root,
                    argv=[str(executable.resolve()), "artifact:outside:" + "b" * 64],
                    env_allowlist={}, child_artifact_refs={store_id: digest},
                )


class FixturePolicy:
    revision = "fixture-17"

    def classify(self, *, purpose, intent, source_contexts, binding):
        if source_contexts:
            return max((item.sensitivity for item in source_contexts), key=lambda x: list(Sensitivity).index(x)), canonical_digest(sorted(item.lineage_hash for item in source_contexts))
        return Sensitivity.PRIVATE, canonical_digest({"purpose": purpose, "profile": binding.profile_id})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return context.sensitivity is Sensitivity.PRIVATE and retry_index <= 3


class AuthentikEffectScopeContracts(unittest.TestCase):
    def setUp(self):
        self.enrollment = AuthentikEnrollment(
            principal_identities={"principal:a": PrincipalIdentity("alice", "alice@example.test", "42")},
            system_group_id="group:system", write_group_by_target={"host:demo": "group:operators"},
            recipient_group_id="group:recipients", recipient_email_by_id={},
            allowed_effects=frozenset({("profile-run", "process.start"),
                                       ("homelab-write", "host:demo")}),
        )
        self.context = HostContext(
            principal_id="principal:a", profile_id="profile:a", namespace_id="namespace:a",
            uid=1001, purpose="bootstrap", intent_id="intent:a", trace_id="trace:a",
            sensitivity=Sensitivity.UNKNOWN, lineage_hash="a" * 64,
            policy_revision="authentik-policy-v1", capabilities=frozenset({"profile-run", "homelab-write"}),
            issued_at_monotonic=10.0, monotonic_expires_at=40.0,
            nonce="nonce:a", grant_id="grant:a", signature="signed",
        )

    @staticmethod
    def _response(body):
        import json
        return AuthentikResponse(200, json.dumps(body).encode(), {"content-type": "application/json"})

    def test_local_pinned_process_effect_uses_kernel_enrollment_without_system_claim(self):
        policy = AuthentikSystemPolicy(
            enrollment=self.enrollment, actor_token=lambda _principal: None,
            directory_token=lambda: None,
            transport=lambda *_args, **_kwargs: self.fail("local effect must not query Authentik"),
        )
        rule = EffectRule("profile-run", "process.start", "process.start")
        binding = PrincipalBinding(1001, "principal:a", "profile:a", "namespace:a",
                                   frozenset({"profile-run"}))
        effects = []
        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
            effects.append((context.profile_id, payload))
            return {"status": 200, "body": b"started", "headers": {}, "receipt_id": "start"}
        service = AuthorityService(
            signing_key=b"l" * 32, key_id="local-fixture",
            bindings_by_uid={1001: binding}, rules={(rule.capability, rule.target): rule},
            handlers={(rule.operation, rule.target): handler}, policy=policy,
        )
        payload = b"{}"
        context = HostContext.from_wire(service._issue_context(1001, {
            "purpose": "bootstrap", "intent": "start-pinned-profile", "trace_id": "trace-local",
            "lease_seconds": 10, "source_contexts": [],
            "final_payload_digest": canonical_digest(payload),
            "operation": "process.start",
        }, peer_pid=os.getpid()))
        grant = service._authorize_effect(1001, {
            "context": context.to_wire(), "capability": rule.capability,
            "target": rule.target, "recipient": None,
            "request_digest": canonical_digest(payload), "retry_index": 0,
        })
        import base64
        result = service._perform_effect(1001, os.getpid(), {
            "authorization": grant, "operation": rule.operation,
            "payload": base64.b64encode(payload).decode(), "timeout": 1,
        }, cancelled=lambda: False)
        self.assertEqual(context.sensitivity, Sensitivity.UNKNOWN)
        self.assertEqual(effects, [("profile:a", payload)])
        self.assertEqual(result["status"], 200)

    def test_homelab_write_denies_when_authentik_system_membership_is_missing(self):
        policy = AuthentikSystemPolicy(
            enrollment=self.enrollment, actor_token=lambda _principal: None,
            directory_token=lambda: None,
            transport=lambda *_args, **_kwargs: self.fail("no actor token means no lookup"),
        )
        rule = EffectRule("homelab-write", "host.write", "host:demo")
        with self.assertRaises(AuthorityDenied) as denied:
            policy.allow_effect(context=replace(self.context, sensitivity=Sensitivity.PRIVATE), rule=rule,
                                request_digest="c" * 64, retry_index=0)
        self.assertEqual(denied.exception.code, "authentik.principal")

    def test_homelab_write_denies_stale_system_hierarchy(self):
        class Transport:
            def get(_self, path, *, bearer_token, timeout):
                self.assertEqual(bearer_token, "fresh-actor-token")
                self.assertGreater(timeout, 0)
                if path == "/api/v3/core/users/me/":
                    return self._response({"user": {"pk": 42, "username": "alice",
                                                     "email": "alice@example.test", "is_active": True,
                                                     "groups": []}})
                self.fail("no direct memberships means no group lookups")
        policy = AuthentikSystemPolicy(
            enrollment=self.enrollment, actor_token=lambda _principal: "fresh-actor-token",
            directory_token=lambda: None, transport=Transport(),
        )
        rule = EffectRule("homelab-write", "host.write", "host:demo")
        with self.assertRaises(AuthorityDenied) as denied:
            policy.allow_effect(context=replace(self.context, sensitivity=Sensitivity.PRIVATE), rule=rule,
                                request_digest="d" * 64, retry_index=0)
        self.assertEqual(denied.exception.code, "authentik.system-membership")


class BackgroundMemoryConsentContracts(unittest.TestCase):
    def test_expired_source_cannot_be_reissued_without_active_bound_consent(self):
        now = [100.0]
        binding = PrincipalBinding(1001, "principal:a", "profile:a", "namespace:a",
                                   frozenset({"memory-capture", "memory-extraction"}))
        targets = {
            ("memory-capture", "memory:openviking:enqueue"): EffectRule(
                "memory-capture", "memory.enqueue", "memory:openviking:enqueue"),
            ("memory-extraction", "memory:openviking:extract"): EffectRule(
                "memory-extraction", "memory.extract", "memory:openviking:extract"),
        }
        effects = []

        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
            effects.append((context.sensitivity, authorization.capability, payload))
            return {"status": 200, "body": b'{"facts":[]}', "headers": {"content-type": "application/json"}, "receipt_id": "memory-receipt"}

        service = AuthorityService(
            signing_key=b"b" * 32, key_id="fixture",
            bindings_by_uid={binding.uid: binding}, rules=targets,
            handlers={(rule.operation, rule.target): handler for rule in targets.values()},
            policy=FixturePolicy(), monotonic=lambda: now[0], wall_clock=lambda: 1_000.0,
            profile_generations={"profile:a": "generation-a"},
            background_consent_active=lambda _consent_id: True,
        )
        service.memory_owner_state = lambda _profile: ("openviking", 1)
        source = HostContext.from_wire(service._issue_context(binding.uid, {
            "purpose": "memory-capture", "intent": "source-event", "trace_id": "trace-a",
            "lease_seconds": 10.0, "source_contexts": [],
            "final_payload_digest": canonical_digest(b"source event"),
            "operation": "memory.enqueue",
        }, peer_pid=os.getpid()))
        consent = service.create_background_consent(
            source, provider_id="openviking", owner_generation=1, ttl_seconds=300)
        now[0] += 11.0

        with self.assertRaises(AuthorityDenied):
            service._issue_context(binding.uid, {
                "purpose": "memory-extract", "intent": "unapproved-refresh", "trace_id": "trace-b",
                "lease_seconds": 10.0, "source_contexts": [source.to_wire()],
                "final_payload_digest": canonical_digest(b"refresh"),
                "operation": "memory.extract",
            })
        self.assertEqual(effects, [])

        result = service.perform_memory_effect(
            source.to_wire(), consent.to_wire(), provider_id="openviking",
            owner_generation=1, action="extract", capability="memory-extraction",
            payload=b'{"schema":1}', timeout=1,
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(result.body, b'{"facts":[]}')
        self.assertEqual(effects, [(Sensitivity.PRIVATE, "memory-extraction", b'{"schema":1}')])

        service.background_consent_active = lambda _consent_id: False
        with self.assertRaises(AuthorityDenied):
            service.perform_memory_effect(
                source.to_wire(), consent.to_wire(), provider_id="openviking",
                owner_generation=1, action="extract", capability="memory-extraction",
                payload=b'{"schema":1}', timeout=1,
            )
        self.assertEqual(len(effects), 1)


class ChildDelegationContracts(unittest.TestCase):
    def test_root_handler_mints_one_child_grant_for_fixed_profile_target(self):
        parent = PrincipalBinding(1001, "principal:parent", "profile:parent", "namespace:parent",
                                  frozenset({"resource-run"}))
        child = PrincipalBinding(1002, "principal:child", "profile:child", "namespace:child",
                                 frozenset({"hermes-profile-invoke"}))
        parent_rule = EffectRule("resource-run", "resource.cron.run", "resource:cron:weekly")
        child_rule = EffectRule("hermes-profile-invoke", "process.start", "hermes-profile-invoke:child")
        delegation = ChildDelegationRule(
            "cron-weekly-child", "profile:parent", "resource-run", "resource.cron.run",
            "resource:cron:weekly", "profile:child", "hermes-profile-invoke", "process.start",
            "hermes-profile-invoke:child", None, "scheduled-hermes-profile-run")
        effects = []
        service_ref = {}

        def child_handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
            effects.append((context.profile_id, authorization.uid, authorization.target, payload))
            return {"status": 200, "body": b'{"started":true}',
                    "headers": {"content-type": "application/json"}, "receipt_id": "child-start"}

        def parent_handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
            result = service_ref["service"].perform_delegated_effect(
                authorization, delegation_id="cron-weekly-child", payload=b'{"argv":["pinned"]}',
                peer_pid=peer_pid, timeout=timeout, cancelled=cancelled)
            return {"status": result.status, "body": result.body,
                    "headers": dict(result.headers), "receipt_id": "parent-dispatch"}

        service = AuthorityService(
            signing_key=b"d" * 32, key_id="fixture",
            bindings_by_uid={parent.uid: parent, child.uid: child},
            rules={(parent_rule.capability, parent_rule.target): parent_rule,
                   (child_rule.capability, child_rule.target): child_rule},
            handlers={(parent_rule.operation, parent_rule.target): parent_handler,
                      (child_rule.operation, child_rule.target): child_handler},
            policy=FixturePolicy(), delegations={delegation.delegation_id: delegation})
        service_ref["service"] = service
        parent_payload = b'{"job":"weekly"}'
        source = HostContext.from_wire(service._issue_context(parent.uid, {
            "purpose": "resource-cron", "intent": "run-selected-job", "trace_id": "trace-child",
            "lease_seconds": 20.0, "source_contexts": [],
            "final_payload_digest": canonical_digest(parent_payload),
            "operation": "resource.cron.run",
        }, peer_pid=os.getpid()))
        parent_grant = EffectAuthorization.from_wire(service._authorize_effect(parent.uid, {
            "context": source.to_wire(), "capability": parent_rule.capability,
            "target": parent_rule.target, "recipient": None,
            "request_digest": canonical_digest(parent_payload), "retry_index": 0,
        }))
        import base64
        response = service._perform_effect(parent.uid, os.getpid(), {
            "authorization": parent_grant.to_wire(), "operation": parent_rule.operation,
            "payload": base64.b64encode(parent_payload).decode("ascii"), "timeout": 10.0,
        }, cancelled=lambda: False)
        self.assertEqual(response["status"], 200)
        self.assertEqual(effects, [("profile:child", child.uid, child_rule.target,
                                    b'{"argv":["pinned"]}')])
        with self.assertRaises(AuthorityDenied):
            service.perform_delegated_effect(parent_grant, delegation_id="cron-weekly-child",
                                             payload=b'{"argv":["again"]}', peer_pid=os.getpid(),
                                             timeout=10.0, cancelled=lambda: False)
        self.assertEqual(len(effects), 1)


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

        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
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
        digest = canonical_digest(payload)
        context = self.client.context(purpose="memory-capture", intent="store approved source",
                                      operation="memory.capture", final_payload_digest=digest)
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
        payload = b"capture"
        context = self.client.context(purpose="memory-capture", intent="revocation fixture",
                                      operation="memory.capture",
                                      final_payload_digest=canonical_digest(payload))
        grant = self.client.authorize_effect(
            context, capability="memory-capture", target="memory:openviking:capture",
            request_digest=canonical_digest(payload),
        )
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(grant, operation="memory.capture", payload=payload, timeout=1)
        self.assertEqual(policy.calls, 2)
        self.assertEqual(self.effects, [])

    def test_source_receipt_is_private_process_bound_and_one_use(self):
        payload = b"derived-memory-payload"
        source_bytes = b"private source bytes"
        handle = self.client.capture_source(source_bytes)
        context = self.client.context(
            purpose="memory-capture", intent="derived memory write",
            operation="memory.capture", source_receipt_handles=(handle,),
            final_payload_digest=canonical_digest(payload))
        self.assertEqual(len(context.source_receipts), 1)
        receipt = context.source_receipts[0]
        self.assertIs(receipt.sensitivity, Sensitivity.UNKNOWN)
        self.assertEqual(receipt.payload_digest, canonical_digest(source_bytes))
        self.assertEqual(receipt.native_process_identity, context.native_process_identity)
        grant = self.client.authorize_effect(
            context, capability="memory-capture", target="memory:openviking:capture",
            request_digest=canonical_digest(payload))
        self.client.perform_effect(grant, operation="memory.capture", payload=payload, timeout=1)
        replay = self.client.authorize_effect(
            context, capability="memory-capture", target="memory:openviking:capture",
            request_digest=canonical_digest(payload))
        with self.assertRaises(AuthorityDenied):
            self.client.perform_effect(replay, operation="memory.capture", payload=payload, timeout=1)
        self.assertEqual(self.effects, [payload])


if __name__ == "__main__":
    unittest.main()
