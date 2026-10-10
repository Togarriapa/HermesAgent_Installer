"""Positive and failure-path coverage for HI11 root request observations."""
from __future__ import annotations

import hashlib
import os
import unittest
from types import SimpleNamespace

from hermes_installer.authority.native_input_observer import RootNativeInputEvent, RootNativeInputObserver
from hermes_installer.authority.native_request_observation import NativeRequestObservationRegistry
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.source_observers import (
    RootSourcePayloadCapsule, SourceObserverEnrollment, SourceObserverRegistry,
    SourceReceiptHandle,
)
from hermes_installer.authority.types import AuthorityDenied, Sensitivity, canonical_digest


class _Policy:
    revision = "native-request-observation-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        del purpose, intent, source_contexts, binding
        return Sensitivity.PRIVATE, canonical_digest({"fixture": "private"})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return True


class NativeRequestObservationContracts(unittest.TestCase):
    def setUp(self):
        self.producer = PrincipalBinding(
            1301, "principal:producer", "profile:producer", "namespace:producer",
            frozenset({"provider-inference"}))
        self.gateway = PrincipalBinding(
            1302, "principal:gateway", "profile:gateway", "namespace:gateway",
            frozenset({"provider-inference"}))
        self.rule = EffectRule("provider-inference", "provider.dispatch", "fixed-target", "fixed-recipient")
        self.service = AuthorityService(
            signing_key=b"R" * 32, key_id="native-request-observation-fixture",
            bindings_by_uid={self.producer.uid: self.producer, self.gateway.uid: self.gateway},
            rules={(self.rule.capability, self.rule.operation, self.rule.target): self.rule},
            handlers={}, policy=_Policy(),
            profile_generations={"profile:producer": "producer-v1", "profile:gateway": "gateway-v1"},
            service_generation_digest="d" * 64,
        )
        self.service._native_process_identity = lambda pid, uid: f"pid:{pid}:uid:{uid}"
        self.identity = SimpleNamespace(
            profile_id="profile:producer", generation="producer-v1", kernel_uid=self.producer.uid,
            start_ticks=777, executable_sha256="a" * 64,
            cgroup_identity="cgroup:producer", namespace_identity="mnt:1;net:1")
        self.bridge = SimpleNamespace(
            bridge_id="bridge:fixture", producer_uid=self.producer.uid,
            producer_profile_id=self.producer.profile_id, producer_generation="producer-v1",
            producer_executable_sha256="a" * 64, approved_operation="provider.dispatch",
            target="fixed-target", recipient="fixed-recipient")
        observer = SourceObserverEnrollment(
            observer_enrollment_id="observer:native-input", source_kind="native-input",
            origin_id="origin:task-input", profile_id=self.producer.profile_id,
            principal_id=self.producer.principal_id, namespace_id=self.producer.namespace_id,
            enrollment_id="enrollment:producer", generation="producer-v1",
            producer_uid=self.producer.uid, producer_executable_sha256="a" * 64,
            package_id="package:hermes", package_sha256="b" * 64,
            role_id="role:producer", role_artifact_id="artifact:producer", role_sha256="c" * 64,
            channel_id="channel:task", capture_schema_id="schema:task-input",
            source_action_id="action:authenticated-input", target_id="target:producer",
            recipient="recipient:producer", allowed_parent_source_kinds=frozenset(),
            native_package_generation="package-generation-1")
        self.source_observers = object.__new__(SourceObserverRegistry)
        self.source_observers.service = self.service
        self.source_observers.observers = {observer.observer_enrollment_id: observer}
        self.source_observers._payload_capsules = {}
        self.source_observers._lock = __import__("threading").RLock()
        self.source_observers._closed = False
        self.input_observer = object.__new__(RootNativeInputObserver)
        self.input_observer.service = self.service
        self.input_observer.source_observers = self.source_observers
        self.input_observer._events = {}
        self.process_resolver = lambda pid, fd, *, profile_id, generation: (
            self.identity if (pid == 41001 and profile_id == self.identity.profile_id
                              and generation == self.identity.generation and os.fstat(fd)) else None)
        self.now = self.service.monotonic()
        source_payload = b"root observed task input"
        self.parent_context = self.service._issue_context(
            self.producer.uid, {
                "purpose": "hermes-native-initial-input", "intent": "fixture-task",
                "trace_id": "trace:input", "lease_seconds": 30, "source_contexts": [],
                "source_receipts": [], "final_payload_digest": canonical_digest(source_payload),
                "operation": "native.request.dispatch",
            }, inherited_process_identity=f"pid:41001:uid:{self.producer.uid}")
        from hermes_installer.authority.types import HostContext
        self.parent_context = HostContext.from_wire(self.parent_context)
        receipt = self.service.issue_source_receipt(
            self.parent_context, source_kind="native-input", origin_id="input:fixture",
            payload=source_payload, ttl_seconds=30)
        self.handle = SourceReceiptHandle("h" * 43)
        with self.service._lock:
            self.service._source_receipt_handles[str(self.handle)] = receipt
        capsule = RootSourcePayloadCapsule(
            receipt_id=receipt.receipt_id, observer_enrollment_id="observer:native-input",
            event_record_id="source-event:fixture", invocation_id=self.parent_context.grant_id,
            source_kind="native-input", channel_id="channel:task", capture_schema_id="schema:task-input",
            source_action_id="action:authenticated-input", profile_id=self.producer.profile_id,
            principal_id=self.producer.principal_id, namespace_id=self.producer.namespace_id,
            generation="producer-v1", payload_bytes=source_payload,
            payload_sha256=canonical_digest(source_payload), parent_receipt_ids=(),
            parent_closure_digest=canonical_digest([]), issued_monotonic=self.now,
            expires_monotonic=self.now + 30)
        self.source_observers._payload_capsules[str(self.handle)] = (
            receipt, capsule, bytearray(source_payload), self.service.authority_epoch)
        self.input_observer._events["event:input"] = RootNativeInputEvent(
            schema=1, input_event_id="event:input", input_origin_kind="root-admitted-task",
            source_receipt_handle=str(self.handle), payload_sha256=canonical_digest(source_payload),
            payload_size_bytes=len(source_payload), producer_profile_id=self.producer.profile_id,
            producer_generation="producer-v1", parent_closure_digest=canonical_digest([]),
            observed_monotonic=self.now, expires_monotonic=self.now + 30)
        self.registry = NativeRequestObservationRegistry(
            service=self.service, source_observers=self.source_observers,
            native_input_observer=self.input_observer,
            bridges={self.bridge.bridge_id: self.bridge},
            process_resolver=self.process_resolver, monotonic=self.service.monotonic)

    def tearDown(self):
        self.registry.close()

    def _record(self, *, payload=b'{"model":"fixture","messages":[]} ', retry=0,
                handles=None, expires=None):
        handles = (str(self.handle),) if handles is None else handles
        payload_digest = canonical_digest(payload)
        context = self.service._issue_context(self.producer.uid, {
            "purpose": "native-provider-request", "intent": "root-generated-intent",
            "trace_id": "trace:request", "lease_seconds": 30, "source_contexts": [],
            "source_receipts": [self.service._source_receipt_handles[str(self.handle)].to_wire()],
            "final_payload_digest": payload_digest, "operation": self.rule.operation,
        }, peer_pid=41001)
        from hermes_installer.authority.types import HostContext
        context = HostContext.from_wire(context)
        read_fd, write_fd = os.pipe()
        try:
            return self.registry.record_request(
                bridge=self.bridge, native_request_handle=f"n{retry}".ljust(43, "x"),
                producer_pid=41001, producer_pidfd=read_fd, producer_identity=self.identity,
                canonical_request_bytes=payload, retry_index=retry,
                parent_receipt_handles=handles,
                parent_receipts=context.source_receipts,
                parent_context=context,
                expires_monotonic=self.service.monotonic() + 20 if expires is None else expires)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_private_request_is_retained_exactly_and_bound_to_signed_parent_closure(self):
        payload = b'{"model":"fixture","messages":[{"role":"user","content":"private"}]}'
        observation = self._record(payload=payload)
        self.assertEqual(observation.request_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(observation.request_size_bytes, len(payload))
        self.assertEqual(observation.parent_source_receipt_handles, (str(self.handle),))
        self.assertEqual(observation.parent_closure_digest, canonical_digest(
            [self.service._source_receipt_handles[str(self.handle)].receipt_id]))
        self.assertEqual(self.registry._records[observation.receipt_handle].parent_context.sensitivity,
                         Sensitivity.PRIVATE)
        self.assertEqual(self.registry.request_bytes(observation.receipt_handle, self.identity), payload)
        self.assertEqual(self.registry.resolve_native_request_for_handle(
            f"n0".ljust(43, "x"), self.identity), observation)

    def test_health_request_selector_requires_exact_live_input_parent_and_uniqueness(self):
        observation = self._record()
        input_event = self.input_observer._events["event:input"]
        selected = self.registry.resolve_current_health_request_for_input(
            input_event, live_producer_identity=self.identity, producer_pid=41001,
            producer_profile_id=self.producer.profile_id,
            producer_generation="producer-v1",
            native_package_generation="package-generation-1",
        )
        self.assertIs(selected.observation, observation)
        self.assertEqual(selected.parent_source_receipts[0].receipt_id,
                         self.service._source_receipt_handles[str(self.handle)].receipt_id)
        self.assertTrue(selected.canonical_request_bytes)
        self.assertIs(self.registry.verify_current_health_request_for_input(
            selected, input_event, live_producer_identity=self.identity, producer_pid=41001,
            producer_profile_id=self.producer.profile_id,
            producer_generation="producer-v1",
            native_package_generation="package-generation-1",
        ), selected)

        self._record(retry=1)
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_current_health_request_for_input(
                input_event, live_producer_identity=self.identity, producer_pid=41001,
                producer_profile_id=self.producer.profile_id,
                producer_generation="producer-v1",
                native_package_generation="package-generation-1",
            )

    def test_changed_identity_or_payload_cannot_resolve_request_record(self):
        observation = self._record()
        altered = SimpleNamespace(**{**self.identity.__dict__, "start_ticks": 778})
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_native_request(observation.receipt_handle, altered)
        stored = self.registry.request_bytes(observation.receipt_handle, self.identity)
        self.assertEqual(hashlib.sha256(stored).hexdigest(), observation.request_sha256)
        self.assertNotEqual(stored, b'{"model":"other"}')

    def test_changed_retained_bytes_fail_digest_revalidation(self):
        observation = self._record()
        record = self.registry._records[observation.receipt_handle]
        record.canonical_request_bytes[0] ^= 1
        with self.assertRaises(AuthorityDenied) as denied:
            self.registry.request_bytes(observation.receipt_handle, self.identity)
        self.assertEqual(denied.exception.code, "native.request_stale")

    def test_forged_parent_handle_and_reused_retry_are_rejected(self):
        with self.assertRaises(AuthorityDenied):
            self._record(handles=("forged-parent-handle-000000000000",))
        self._record(retry=1)
        with self.assertRaises(AuthorityDenied) as denied:
            self._record(retry=1)
        self.assertEqual(denied.exception.code, "native.request_replay")

    def test_expired_request_record_cannot_be_resolved(self):
        observation = self._record(expires=self.service.monotonic() + 0.01)
        self.service.monotonic = lambda: observation.expires_monotonic + 0.1
        self.registry.monotonic = self.service.monotonic
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_native_request(observation.receipt_handle, self.identity)


if __name__ == "__main__":
    unittest.main()
