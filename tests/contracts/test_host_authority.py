from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

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
    AuthorityDenied, EffectAuthorization, HostContext, NativeEventHandle, Sensitivity,
    canonical_bytes, canonical_digest,
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
        binding = PrincipalBinding(os.getuid(), "principal:a", "profile:a", "namespace:a",
                                   frozenset({"profile-run"}))
        effects = []
        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd=None, cancelled):
            effects.append((context.profile_id, payload))
            return {"status": 200, "body": b"started", "headers": {}, "receipt_id": "start"}
        service = AuthorityService(
            signing_key=b"l" * 32, key_id="local-fixture",
            bindings_by_uid={binding.uid: binding}, rules={(rule.capability, rule.operation, rule.target): rule},
            handlers={(rule.operation, rule.target): handler}, policy=policy,
        )
        payload = b"{}"
        context = HostContext.from_wire(service._issue_context(binding.uid, {
            "purpose": "bootstrap", "intent": "start-pinned-profile", "trace_id": "trace-local",
            "lease_seconds": 10, "source_contexts": [],
            "final_payload_digest": canonical_digest(payload),
            "operation": "process.start",
        }))
        grant = service._authorize_effect(binding.uid, {
            "context": context.to_wire(), "capability": rule.capability,
            "target": rule.target, "recipient": None,
            "request_digest": canonical_digest(payload), "retry_index": 0,
        })
        import base64
        result = service._perform_effect(binding.uid, os.getpid(), {
            "authorization": grant, "operation": rule.operation,
            "payload": base64.b64encode(payload).decode(), "timeout": 1,
        }, cancelled=lambda: False, enforce_peer_identity=False)
        self.assertEqual(context.sensitivity, Sensitivity.UNKNOWN)
        self.assertEqual(effects, [("profile:a", payload)])
        self.assertEqual(result["status"], 200)

    def test_root_observed_source_is_unavailable_without_composed_registry(self):
        binding = PrincipalBinding(
            1234, "principal:source", "profile:source", "namespace:source",
            frozenset({"provider-inference"}),
        )
        service = AuthorityService(
            signing_key=b"s" * 32, key_id="observed-source-unavailable",
            bindings_by_uid={binding.uid: binding}, rules={}, handlers={}, policy=FixturePolicy(),
        )
        with self.assertRaises(AuthorityDenied):
            service.issue_observed_source(object())
        with self.assertRaises(AuthorityDenied):
            service._dispatch(binding.uid, 4321, 7, "issue_observed_source", {},
                              cancelled=lambda: False)

    def test_process_start_target_is_resolved_from_protected_enrollment(self):
        binding = PrincipalBinding(1234, "principal:a", "profile:a", "namespace:a",
                                   frozenset({"hermes-profile-invoke"}))
        selected_target = "coral-cpython-build:start"
        rule = EffectRule("hermes-profile-invoke", "process.start", selected_target)
        selected = SimpleNamespace(
            operation="process.start", profile_id="profile:a", principal_id="principal:a",
            service_uid=1234, enrollment_id="enroll:coral", generation="generation:1",
            operation_id="coral-cpython39-source-build-v1", target=selected_target,
        )
        service = AuthorityService(
            signing_key=b"q" * 32, key_id="selected-process-fixture",
            bindings_by_uid={1234: binding},
            rules={(rule.capability, rule.operation, rule.target): rule},
            handlers={(rule.operation, rule.target): lambda **_kwargs: {}},
            policy=FixturePolicy(),
            selected_operation_resolver=lambda enrollment, generation, operation, operation_id: (
                selected if (enrollment, generation, operation) ==
                ("enroll:coral", "generation:1", "process.start")
                and operation_id == "coral-cpython39-source-build-v1" else None),
        )
        request = {"schema": 1, "enrollment_id": "enroll:coral",
                   "generation": "generation:1", "operation_id": "coral-cpython39-source-build-v1",
                   "parameters": {}}
        digest = canonical_digest(canonical_bytes(request))
        context = service._issue_context(1234, {
            "purpose": "selected-process-operation", "intent": "build-cpython",
            "trace_id": "trace-selected-process", "lease_seconds": 10,
            "source_contexts": [], "final_payload_digest": digest,
            "operation": "process.start",
        })
        grant = service._authorize_process_start(1234, None, {
            "context": context, "enrollment_id": "enroll:coral",
            "generation": "generation:1", "operation_id": request["operation_id"],
            "request_digest": digest, "retry_index": 0,
        })
        parsed = EffectAuthorization.from_wire(grant)
        self.assertEqual(parsed.target, selected_target)
        self.assertEqual(parsed.capability, "hermes-profile-invoke")
        self.assertEqual(parsed.request_digest, digest)

    def test_process_start_target_cannot_be_selected_without_enrollment_resolver(self):
        binding = PrincipalBinding(1234, "principal:a", "profile:a", "namespace:a",
                                   frozenset({"hermes-profile-invoke"}))
        service = AuthorityService(
            signing_key=b"r" * 32, key_id="selected-process-unavailable",
            bindings_by_uid={1234: binding}, rules={}, handlers={}, policy=FixturePolicy(),
        )
        with self.assertRaises(AuthorityDenied) as denied:
            service._authorize_process_start(1234, None, {
                "context": {}, "enrollment_id": "enroll:coral", "generation": "generation:1",
                "operation_id": "coral-cpython39-source-build-v1", "request_digest": "a" * 64,
                "retry_index": 0,
            })
        self.assertEqual(denied.exception.code, "effect.unavailable")

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
        binding = PrincipalBinding(os.getuid(), "principal:a", "profile:a", "namespace:a",
                                   frozenset({"memory-capture", "memory-extraction"}))
        targets = {
            ("memory-capture", "memory.enqueue", "memory:openviking:enqueue"): EffectRule(
                "memory-capture", "memory.enqueue", "memory:openviking:enqueue"),
            ("memory-extraction", "memory.extract", "memory:openviking:extract"): EffectRule(
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
        # This contract fixture exercises consent expiry, not platform procfs
        # identity; kernel peer identity is covered by the Linux socket suite.
        service._native_process_identity = lambda _pid, _uid: "fixture-memory-process"
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
            effects.append((context.profile_id, authorization.uid, authorization.target, payload,
                            context.source_receipts, context.sensitivity))
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
            rules={(parent_rule.capability, parent_rule.operation, parent_rule.target): parent_rule,
                   (child_rule.capability, child_rule.operation, child_rule.target): child_rule},
            handlers={(parent_rule.operation, parent_rule.target): parent_handler,
                      (child_rule.operation, child_rule.target): child_handler},
            policy=FixturePolicy(), delegations={delegation.delegation_id: delegation})
        service_ref["service"] = service
        # The unit fixture uses synthetic UIDs but still exercises the same
        # grant/receipt binding path as the root-internal cross-UID dispatch.
        service._native_process_identity = lambda _pid, _uid: "fixture-parent-process"
        parent_payload = b'{"job":"weekly"}'
        base_source = HostContext.from_wire(service._issue_context(parent.uid, {
            "purpose": "resource-cron", "intent": "run-selected-job", "trace_id": "trace-child",
            "lease_seconds": 20.0, "source_contexts": [],
            "final_payload_digest": canonical_digest(parent_payload),
            "operation": "resource.cron.run",
        }, peer_pid=os.getpid()))
        receipt = service.issue_source_receipt(
            base_source, source_kind="schedule-event", origin_id="fixture-schedule",
            payload=b"root-observed-schedule", ttl_seconds=20)
        source = HostContext.from_wire(service._issue_context(parent.uid, {
            "purpose": "resource-cron", "intent": "run-selected-job", "trace_id": "trace-child",
            "lease_seconds": 20.0, "source_contexts": [],
            "source_receipts": [receipt.to_wire()],
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
                                    b'{"argv":["pinned"]}', (), Sensitivity.PRIVATE)])
        self.assertIn(receipt.receipt_id, service._source_receipts_consumed)
        with self.assertRaises(AuthorityDenied):
            service.perform_delegated_effect(parent_grant, delegation_id="cron-weekly-child",
                                             payload=b'{"argv":["again"]}', peer_pid=os.getpid(),
                                             timeout=10.0, cancelled=lambda: False)
        self.assertEqual(len(effects), 1)

        restarted = AuthorityService(
            signing_key=b"d" * 32, key_id="fixture",
            bindings_by_uid={parent.uid: parent, child.uid: child},
            rules={(parent_rule.capability, parent_rule.operation, parent_rule.target): parent_rule,
                   (child_rule.capability, child_rule.operation, child_rule.target): child_rule},
            handlers={(parent_rule.operation, parent_rule.target): parent_handler,
                      (child_rule.operation, child_rule.target): child_handler},
            policy=FixturePolicy(), delegations={delegation.delegation_id: delegation})
        with self.assertRaisesRegex(AuthorityDenied, "effect grant is stale"):
            restarted._assert_grant_current(parent_grant, parent, parent.uid)


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
            rules={(rule.capability, rule.operation, rule.target): rule},
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

    def test_generic_worker_cannot_mint_source_receipts(self):
        with self.assertRaises(AuthorityDenied) as raised:
            self.client.capture_source(b"invented source bytes")
        self.assertEqual(raised.exception.code, "source.issuer")
        with self.assertRaises(AuthorityDenied) as raised:
            self.service._dispatch(
                self.binding.uid, os.getpid(), None, "capture_source",
                {"schema": 1, "payload": "aW52ZW50ZWQgc291cmNlIGJ5dGVz", "parent_receipt_handles": []},
                cancelled=lambda: False)
        self.assertEqual(raised.exception.code, "protocol.operation")
        self.assertEqual(self.effects, [])


class NativeEventClientContracts(unittest.TestCase):
    def test_preparation_and_gateway_dispatch_are_distinct_fixed_rpcs(self):
        client = AuthorityClient(Path("/unused"), server_uid=0, timeout=2)
        client.monotonic = lambda: 50.0
        requests = []

        def rpc(operation, payload, *, timeout=None, cancelled=None):
            requests.append((operation, payload, timeout))
            if operation == "prepare_native_event":
                return {"native_event_handle": "h" * 40, "expires_monotonic": 70.0}
            return {"status": 200, "body": "b2s=", "headers": {}, "receipt_id": "root-receipt"}

        client._rpc = rpc
        event = client.prepare_native_event(
            b'{"messages":[]}', purpose="native-chat", intent_id="intent-1",
            trace_id="trace-1", retry_index=0)
        self.assertIsInstance(event, NativeEventHandle)
        self.assertEqual(requests[0][0], "prepare_native_event")
        self.assertEqual(set(requests[0][1]), {
            "schema", "payload", "parent_receipt_handles", "purpose", "intent_id",
            "trace_id", "retry_index"})
        response = client.dispatch_native_request(event.native_event_handle, b'{"model":"fixed"}')
        self.assertEqual(response.body, b"ok")
        self.assertEqual(requests[1][0], "dispatch_native_request")
        self.assertEqual(set(requests[1][1]), {
            "schema", "native_event_handle", "normalized_payload", "retry_index"})
        self.assertEqual(requests[1][1]["native_event_handle"], event.native_event_handle)

    def test_source_receipt_take_requires_root_delivery_adapter_and_authenticated_peer(self):
        class Delivery:
            def __init__(self):
                self.calls = []

            def take_source_receipt(self, handle, *, peer_uid, peer_pid, peer_pidfd):
                self.calls.append((handle, peer_uid, peer_pid, peer_pidfd))
                return handle

        binding = PrincipalBinding(1234, "principal:receipt", "profile:receipt", "namespace:receipt",
                                   frozenset({"fixture:read"}))
        delivery = Delivery()
        service = AuthorityService(
            signing_key=b"r" * 32, key_id="receipt-delivery-fixture",
            bindings_by_uid={1234: binding}, rules={}, handlers={},
            source_receipt_delivery=delivery,
        )
        payload = {"schema": 1, "receipt_handle": "h" * 40}
        result = service._dispatch(1234, 4321, 9, "source.receipt.take", payload,
                                   cancelled=lambda: False)
        self.assertEqual(result, payload)
        self.assertEqual(delivery.calls, [("h" * 40, 1234, 4321, 9)])
        unavailable = AuthorityService(
            signing_key=b"u" * 32, key_id="receipt-delivery-unavailable",
            bindings_by_uid={1234: binding}, rules={}, handlers={},
        )
        with self.assertRaises(AuthorityDenied):
            unavailable._dispatch(1234, 4321, 9, "source.receipt.take", payload,
                                  cancelled=lambda: False)

        client = AuthorityClient(Path("/unused"), server_uid=0, timeout=2)
        requests = []
        client._rpc = lambda operation, value, **_kwargs: requests.append((operation, value)) or value
        self.assertEqual(client.take_source_receipt("h" * 40), "h" * 40)
        self.assertEqual(requests, [("source.receipt.take", payload)])


class RootResolvedProcessControlContracts(unittest.TestCase):
    def test_control_selects_target_and_binds_exact_nested_body(self):
        binding = PrincipalBinding(1234, "principal:proc", "profile:proc", "namespace:proc",
                                   frozenset({"hermes-process-control"}))
        profile = SimpleNamespace(profile_id="profile:proc", generation="generation-1",
                                  owner_uid=1234,
                                  operation_targets={"process.read": "profile:proc:data:read"})
        target = profile.operation_targets["process.read"]
        rule = EffectRule("hermes-process-control", "process.read", target)
        effects = []

        class Manager:
            def resolve_process_operation(self, process_id, generation, operation, *,
                                          peer_uid, peer_pid, peer_pidfd):
                self.args = (process_id, generation, operation, peer_uid, peer_pid, peer_pidfd)
                return profile, target

        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd, cancelled):
            effects.append((context.operation, authorization.target, payload))
            return {"status": 200, "body": b"{}", "headers": {}, "receipt_id": "fixed"}

        service = AuthorityService(
            signing_key=b"p" * 32, key_id="process-control-fixture",
            bindings_by_uid={binding.uid: binding},
            rules={(rule.capability, rule.operation, rule.target): rule},
            handlers={(rule.operation, rule.target): handler}, policy=FixturePolicy(),
            profile_generations={binding.profile_id: "generation-1"},
            process_effect_handler=Manager(),
        )
        service._native_process_identity = lambda pid, uid: f"test-peer:{pid}:{uid}"
        request = {"schema": 1, "operation": "process.read", "process_id": "a" * 32,
                   "generation": "generation-1",
                   "fields": {"stream": "stdout", "maximum_bytes": 128}}
        result = service._dispatch(binding.uid, 4567, 8, "process.control", request,
                                   cancelled=lambda: False)
        expected = canonical_bytes(request)
        self.assertEqual(result["receipt_id"], "fixed")
        self.assertEqual(effects, [("process.read", target, expected)])

    def test_control_rejects_worker_target_and_missing_manager_resolver(self):
        binding = PrincipalBinding(1234, "principal:proc", "profile:proc", "namespace:proc",
                                   frozenset({"hermes-process-control"}))
        service = AuthorityService(signing_key=b"q" * 32, key_id="process-control-unavailable",
                                   bindings_by_uid={binding.uid: binding}, rules={}, handlers={})
        request = {"schema": 1, "operation": "process.stop", "process_id": "b" * 32,
                   "generation": "generation-1", "fields": {}, "target": "attacker"}
        with self.assertRaises(AuthorityDenied):
            service._dispatch(binding.uid, 4567, 8, "process.control", request,
                              cancelled=lambda: False)
        request.pop("target")
        with self.assertRaises(AuthorityDenied) as denied:
            service._dispatch(binding.uid, 4567, 8, "process.control", request,
                              cancelled=lambda: False)
        self.assertEqual(denied.exception.code, "process.control")


class AuthorityRestartReplayContracts(unittest.TestCase):
    def test_signed_grant_from_previous_service_epoch_cannot_reach_effect_handler(self):
        binding = PrincipalBinding(
            os.getuid(), "principal:restart", "profile:restart", "namespace:restart",
            frozenset({"memory-capture"}),
        )
        rule = EffectRule("memory-capture", "memory.capture", "memory:fixed:capture")
        handlers_called = []

        def handler(**_kwargs):
            handlers_called.append(True)
            return {"status": 200, "body": b"mutated", "headers": {}, "receipt_id": "fixture"}

        def create_service():
            return AuthorityService(
                signing_key=b"e" * 32, key_id="restart-epoch-fixture",
                bindings_by_uid={binding.uid: binding},
                rules={(rule.capability, rule.operation, rule.target): rule},
                handlers={(rule.operation, rule.target): handler}, policy=FixturePolicy(),
            )

        original = create_service()
        payload = b'{"schema":1}'
        with patch.object(AuthorityService, "_native_process_identity", return_value="linux-proc:fixture"):
            context = HostContext.from_wire(original._issue_context(binding.uid, {
                "purpose": "memory-capture", "intent": "restart replay probe", "trace_id": "trace-restart",
                "lease_seconds": 20, "source_contexts": [], "operation": rule.operation,
                "final_payload_digest": canonical_digest(payload),
            }, peer_pid=os.getpid()))
            grant = EffectAuthorization.from_wire(original._authorize_effect(binding.uid, {
                "context": context.to_wire(), "capability": rule.capability, "target": rule.target,
                "recipient": None, "request_digest": canonical_digest(payload), "retry_index": 0,
            }))
            restarted = create_service()
            import base64
            with self.assertRaises(AuthorityDenied):
                restarted._perform_effect(binding.uid, os.getpid(), {
                    "authorization": grant.to_wire(), "operation": rule.operation,
                    "payload": base64.b64encode(payload).decode("ascii"), "timeout": 1.0,
                }, cancelled=lambda: False)
        self.assertEqual(handlers_called, [])


if __name__ == "__main__":
    unittest.main()
