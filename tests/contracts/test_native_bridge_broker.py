"""Failure-effect proofs for the HI11 root-owned producer/gateway bridge."""
from __future__ import annotations

import base64
import hashlib
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_bridge import (
    NativeBridgeBroker, RootObserverDeliveryBinding,
)
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied, Sensitivity, canonical_digest


class _Policy:
    revision = "native-bridge-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        return Sensitivity.UNKNOWN, canonical_digest({"fixture": "unknown"})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return True


class NativeBridgeBrokerContracts(unittest.TestCase):
    def test_request_broker_attaches_to_the_concrete_root_turn_registry(self):
        from hermes_installer.authority.native_bridge import NativeBridgeBroker
        from hermes_installer.authority.native_turn_observation import RootNativeTurnObservationRegistry

        service = object()
        broker = object.__new__(NativeBridgeBroker)
        broker.service = service
        broker.native_request_observer = object()
        broker.native_turn_observer = None
        broker._lock = __import__("threading").RLock()
        turns = object.__new__(RootNativeTurnObservationRegistry)
        turns.service = service
        turns.native_bridge_broker = None
        turns._lock = __import__("threading").RLock()

        broker.attach_native_turn_observer(turns)

        self.assertIs(broker.native_turn_observer, turns)
        self.assertIs(turns.native_bridge_broker, broker)

    def test_response_registry_attaches_once_after_cycle_safe_construction(self):
        from hermes_installer.authority.native_runtime_observer import NativeInvocationRegistry

        producer = PrincipalBinding(1201, "principal:producer", "profile:producer",
                                    "namespace:producer", frozenset({"provider-inference"}))
        gateway = PrincipalBinding(1202, "principal:gateway", "profile:gateway",
                                   "namespace:gateway", frozenset({"provider-inference"}))
        rule = EffectRule("provider-inference", "provider.dispatch", "fixed-provider-target",
                          "fixed-recipient")
        service = AuthorityService(
            signing_key=b"A" * 32, key_id="native-registry-attach-fixture",
            bindings_by_uid={producer.uid: producer, gateway.uid: gateway},
            rules={(rule.capability, rule.operation, rule.target): rule}, handlers={},
            policy=_Policy(),
            profile_generations={producer.profile_id: "producer-v1", gateway.profile_id: "gateway-v1"},
            service_generation_digest="d" * 64,
        )
        source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        bridge = SimpleNamespace(
            bridge_id="bridge:attach", producer_profile_id=producer.profile_id,
            producer_uid=producer.uid, producer_generation="producer-v1",
            producer_executable_sha256="a" * 64, producer_principal_id=producer.principal_id,
            gateway_profile_id=gateway.profile_id, gateway_uid=gateway.uid,
            gateway_generation="gateway-v1", gateway_executable_sha256="b" * 64,
            gateway_principal_id=gateway.principal_id,
            canonicalizer_artifact_id="provider-canonicalizer-v1",
            canonicalizer_sha256=source_digest,
        )

        def canonicalizer(_enrollments, payload, *, normalization_policy):
            del normalization_policy
            return payload, rule.target, rule.recipient, rule.capability, "model:fixed"

        observer = SimpleNamespace(source_kind="provider-result")
        source_observers = SimpleNamespace(
            observers={"observer:result": observer},
            record_observed_event=lambda *_a, **_k: None,
            capture_observed_source=lambda *_a, **_k: None,
            take_source_receipt=lambda *_a, **_k: None,
            _resolve=lambda *_a, **_k: None,
            _resolve_package_role=lambda *_a, **_k: None,
            _resolve_loaded_package_proof=lambda *_a, **_k: None,
        )
        registry = NativeInvocationRegistry(
            service=service, source_observers=source_observers,
            bridges={bridge.bridge_id: bridge},
            provider_result_observer_ids={("provider", "target", "recipient"): "observer:result"},
            provider_tool_call_parser=lambda *_a: (), process_resolver=lambda *_a, **_k: None,
            action_resolver=lambda *_a: None,
        )
        broker = NativeBridgeBroker(
            service=service, bridges={bridge.bridge_id: bridge},
            process_resolver=lambda *_a, **_k: None, canonicalizer=canonicalizer,
            root_selected_enrollments={bridge.bridge_id: {(rule.target, rule.recipient): object()}},
            canonicalizer_sha256=source_digest,
        )
        broker.attach_provider_response_registry(registry)
        self.assertIs(broker.provider_response_registry, registry)
        with self.assertRaises(AuthorityDenied):
            broker.attach_provider_response_registry(registry)

    def test_pending_pair_is_exact_context_index_and_returns_owned_fd_duplicates(self):
        from types import SimpleNamespace
        from hermes_installer.authority.types import HostContext

        producer = PrincipalBinding(1201, "principal:producer", "profile:producer",
                                    "namespace:producer", frozenset({"provider-inference"}))
        gateway = PrincipalBinding(1202, "principal:gateway", "profile:gateway",
                                   "namespace:gateway", frozenset({"provider-inference"}))
        rule = EffectRule("provider-inference", "provider.dispatch", "fixed-provider-target",
                          "fixed-recipient")
        service = AuthorityService(
            signing_key=b"N" * 32, key_id="native-pair-fixture",
            bindings_by_uid={producer.uid: producer, gateway.uid: gateway},
            rules={(rule.capability, rule.operation, rule.target): rule}, handlers={}, policy=_Policy(),
            profile_generations={producer.profile_id: "producer-v1", gateway.profile_id: "gateway-v1"},
            service_generation_digest="d" * 64,
        )
        source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        bridge = SimpleNamespace(
            bridge_id="bridge:pair", producer_profile_id=producer.profile_id,
            producer_uid=producer.uid, producer_generation="producer-v1",
            producer_executable_sha256="a" * 64, producer_principal_id=producer.principal_id,
            gateway_profile_id=gateway.profile_id, gateway_uid=gateway.uid,
            gateway_generation="gateway-v1", gateway_executable_sha256="b" * 64,
            gateway_principal_id=gateway.principal_id,
            canonicalizer_artifact_id="provider-canonicalizer-v1",
            canonicalizer_sha256=source_digest,
        )
        def canonicalizer(_enrollments, payload, *, normalization_policy):
            del normalization_policy
            return payload, rule.target, rule.recipient, rule.capability, "model:fixed"

        bindings = (
            RootObserverDeliveryBinding("observer:producer", "producer"),
            RootObserverDeliveryBinding("observer:gateway", "gateway"),
        )
        broker = NativeBridgeBroker(
            service=service, bridges={bridge.bridge_id: bridge},
            process_resolver=lambda pid, _fd, *, profile_id, generation: identity_by_pid.get(pid),
            canonicalizer=canonicalizer,
            root_selected_enrollments={bridge.bridge_id: {(rule.target, rule.recipient): object()}},
            canonicalizer_sha256=source_digest,
            observer_delivery_bindings={bridge.bridge_id: bindings},
            peer_role_artifact_resolver=lambda _bridge, role: (f"role:{role}", "e" * 64),
        )
        producer_read, producer_write = os.pipe()
        gateway_read, gateway_write = os.pipe()
        identity_by_pid = {}
        service._native_process_identity = lambda _pid, _uid: "producer-peer"
        try:
            context_wire = service._issue_context(producer.uid, {
                "purpose": "native-fixture", "intent": "root-admitted-input",
                "trace_id": "trace-pair-fixture", "lease_seconds": 30,
                "source_contexts": [], "source_receipts": [],
                "final_payload_digest": "f" * 64, "operation": rule.operation,
            }, inherited_process_identity="producer-peer")
            context = HostContext.from_wire(context_wire)
            producer_identity = SimpleNamespace(
                profile_id=bridge.producer_profile_id, generation=bridge.producer_generation,
                kernel_uid=bridge.producer_uid, executable_sha256=bridge.producer_executable_sha256,
            )
            gateway_identity = SimpleNamespace(
                profile_id=bridge.gateway_profile_id, generation=bridge.gateway_generation,
                kernel_uid=bridge.gateway_uid, executable_sha256=bridge.gateway_executable_sha256,
            )
            identity_by_pid.update({41001: producer_identity, 41002: gateway_identity})
            pending = SimpleNamespace(
                handle="r" * 43, context=context, expires=service.monotonic() + 20,
                producer_pid=41001, producer_pidfd=producer_read,
                producer_identity=producer_identity,
            )
            pair_id = broker._register_pending_pair(
                bridge=bridge, pending=pending, gateway_pid=41002,
                gateway_pidfd=gateway_read, gateway_identity=gateway_identity,
            )
            first = broker.resolve_pending_pair_for_context(context)
            second = broker.resolve_pending_pair_for_context(context)
            self.assertEqual(first.pair_id, pair_id)
            self.assertEqual(first.parent_context_sha256, canonical_digest(context.to_wire()))
            self.assertEqual(first.observer_delivery_bindings, bindings)
            self.assertNotEqual(first.producer.pidfd, second.producer.pidfd)
            self.assertNotEqual(first.gateway.pidfd, second.gateway.pidfd)
            self.assertEqual(first.producer.role_artifact_id, "role:producer")
            altered = HostContext.from_wire({**context_wire, "trace_id": "other-trace"})
            with self.assertRaises(AuthorityDenied):
                broker.resolve_pending_pair_for_context(altered)
            for peer in (first.producer, first.gateway, second.producer, second.gateway):
                os.close(peer.pidfd)
            broker._retire_pending_pair(pair_id)
            with self.assertRaises(AuthorityDenied):
                broker.resolve_pending_pair_for_context(context)
        finally:
            broker.close()
            for fd in (producer_read, producer_write, gateway_read, gateway_write):
                os.close(fd)

    def test_worker_submitted_request_without_retained_root_input_is_denied(self):
        producer = PrincipalBinding(1201, "principal:producer", "profile:producer",
                                    "namespace:producer", frozenset({"provider-inference"}))
        gateway = PrincipalBinding(1202, "principal:gateway", "profile:gateway",
                                   "namespace:gateway", frozenset({"provider-inference"}))
        rule = EffectRule("provider-inference", "provider.dispatch", "fixed-provider-target", "fixed-recipient")
        outbound = []

        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd, cancelled):
            outbound.append(payload)
            return {"status": 200, "body": b"should-not-send", "headers": {}, "receipt_id": "fixture"}

        service = AuthorityService(
            signing_key=b"N" * 32, key_id="native-bridge-fixture",
            bindings_by_uid={producer.uid: producer, gateway.uid: gateway},
            rules={(rule.capability, rule.operation, rule.target): rule},
            handlers={(rule.operation, rule.target): handler}, policy=_Policy(),
            profile_generations={producer.profile_id: "producer-v1", gateway.profile_id: "gateway-v1"},
        )
        identity = lambda pid, uid: f"linux-proc:{canonical_digest({'pid': pid, 'uid': uid})}"
        service._native_process_identity = identity

        class Resolver:
            def __call__(self, pid, pidfd, *, profile_id, generation):
                uid = producer.uid if profile_id == producer.profile_id else gateway.uid
                sha = "a" * 64 if profile_id == producer.profile_id else "b" * 64
                return SimpleNamespace(profile_id=profile_id, generation=generation,
                                       kernel_uid=uid, executable_sha256=sha,
                                       cgroup_identity=f"cgroup:{profile_id}", namespace_identity="mnt:1;net:1")

        def canonicalizer(root_enrollments, payload, *, normalization_policy):
            self.assertEqual(set(root_enrollments), {("fixed-provider-target", "fixed-recipient")})
            self.assertEqual(normalization_policy["id"], "provider-output-reject-4096-v1")
            return payload, "fixed-provider-target", "fixed-recipient", "provider-inference", "model:fixed"

        source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        bridge = SimpleNamespace(
            bridge_id="bridge:fixture", producer_profile_id=producer.profile_id,
            producer_uid=producer.uid, producer_generation="producer-v1",
            producer_executable_sha256="a" * 64, gateway_profile_id=gateway.profile_id,
            gateway_uid=gateway.uid, gateway_generation="gateway-v1",
            gateway_executable_sha256="b" * 64, canonicalizer_artifact_id="provider-canonicalizer-v1",
            canonicalizer_sha256=source_digest, approved_operation="provider.dispatch",
            normalization_policy_id="provider-output-reject-4096-v1",
            normalization_policy_sha256="c" * 64, normalization_policy_revision=1,
            route_schema_id="provider-chat-compatible-v1", output_limit_mode="reject-over-ceiling",
            output_limit_ceiling=4096,
            target="fixed-provider-target", recipient="fixed-recipient",
        )
        broker = NativeBridgeBroker(
            service=service, bridges={bridge.bridge_id: bridge}, process_resolver=Resolver(),
            canonicalizer=canonicalizer,
            root_selected_enrollments={bridge.bridge_id: {("fixed-provider-target", "fixed-recipient"): object()}},
            canonicalizer_sha256=source_digest,
        )
        service.native_bridge_broker = broker
        producer_read, producer_write = os.pipe()
        gateway_read, gateway_write = os.pipe()
        try:
            raw = b'{"messages":[{"role":"user","content":"private"}]}'
            with self.assertRaises(AuthorityDenied) as denied:
                service._dispatch(producer.uid, 41001, producer_read,
                    "prepare_native_event", {
                "schema": 1, "payload": base64.b64encode(raw).decode("ascii"),
                "parent_receipt_handles": [], "purpose": "native-hermes-chat",
                    "intent_id": "intent:fixture", "trace_id": "trace:fixture", "retry_index": 0,
                    }, cancelled=lambda: False)
            self.assertEqual(denied.exception.code, "native.lineage")
            self.assertEqual(outbound, [])
            self.assertEqual(service._source_receipt_handles, {})
        finally:
            for fd in (producer_read, producer_write, gateway_read, gateway_write):
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
