from __future__ import annotations

import threading
import unittest
import os
import hashlib
from types import SimpleNamespace
from dataclasses import dataclass, replace
from unittest.mock import patch

from hermes_installer.authority.source_observers import (
    LiveSourceProducer,
    NativeInitialInputDelivery,
    RootNativeExecutionSelectionRegistry,
    RootSelectedNativeExecution,
    SourceObserverEnrollment,
    SourceObserverRegistry,
    SourceReceiptHandle,
    VerifiedSourceObservation,
)
from hermes_installer.authority.types import AuthorityDenied, HostContext, Sensitivity, canonical_digest
from hermes_installer.authority.types import SourceReceipt


@dataclass(frozen=True)
class _Identity:
    profile_id: str
    generation: str
    kernel_uid: int
    start_ticks: int
    executable_sha256: str


@dataclass(frozen=True)
class _TargetPeer:
    pid: int
    pidfd: int
    uid: int
    profile_id: str
    generation: str
    identity: _Identity


@dataclass(frozen=True)
class _LoadedProof:
    proof_id: str
    package_id: str
    profile_id: str
    generation: str
    compiled_closure_sha256: str
    entrypoint_sha256: str
    resolver_sha256: str
    mount_namespace_inode: int
    mount_id: str
    mount_target_digest: str
    mount_flags: frozenset[str]
    source_root_device: int
    source_root_inode: int
    target_peer_identity: _Identity
    loader_role_artifact_id: str
    loader_role_sha256: str
    loader_ready_event_id: str
    observed_entrypoint_action_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    service_generation_digest: str


@dataclass(frozen=True)
class _Adapter:
    adapter_id: str = "hermes-main"
    action_binding_id: str = "hermes-main:action:authenticated-input"
    observer_enrollment_ids: tuple[str, ...] = ("observer.native.primary",)
    adapter_artifact_id: str = "hermes-main"
    adapter_sha256: str = "b" * 64
    target_id: str = "provider.fixed"
    recipient: str = "public-provider"
    generation: str = "gen-4"
    action_id: str = "authenticated-input"
    argument_schema_id: str = "schema.arguments"
    result_schema_id: str = "schema.result"
    effect_enrollment_id: str = "provider.enrollment"
    operation: str = "provider.dispatch"
    capability: str = "provider-inference"


@dataclass(frozen=True)
class _Package:
    package_id: str = "hermes-package"
    profile_id: str = "producer-profile"
    generation: str = "gen-4"
    compiled_closure_sha256: str = "a" * 64
    source_revision: str = "pinned-revision"
    source_tree_sha256: str = "c" * 64
    compiled_closure_artifact_id: str = "compiled-closure"
    entrypoint_artifact_id: str = "entrypoint"
    entrypoint_sha256: str = "d" * 64
    resolver_artifact_id: str = "resolver"
    resolver_sha256: str = "e" * 64
    service_package_root_id: str = "package-root"
    service_mount_id: str = "mount-hermes"
    adapter_records: dict = None
    action_records: dict = None
    process_role_records: dict = None

    def __post_init__(self):
        action = _Adapter()
        role = SimpleNamespace(
            role_id="native-process-role", package_id=self.package_id,
            native_package_generation=self.generation, profile_id=self.profile_id,
            profile_generation="gen-4", role_artifact_id="native-role-module",
            role_sha256="9" * 64, role_source_receipt_handle="role-source-receipt",
            module_name="hermes_installer.runtime.native_role",
            closure_member_path="roles/native_role.py", role_source_revision="reviewed-role",
            role_source_tree_sha256="8" * 64,
            observer_enrollment_ids=("observer.native.primary",),
            action_binding_ids=(action.action_binding_id,),
        )
        object.__setattr__(self, "adapter_records", {"hermes-main": action})
        object.__setattr__(self, "action_records", {action.action_binding_id: action})
        object.__setattr__(self, "process_role_records", {role.role_id: role})


class _Service:
    def __init__(self):
        self.authority_epoch = "epoch-one"
        self._lock = threading.RLock()
        self._source_receipt_handles = {}
        self._now = 10.0
        self._issued = 0
        self.fail_issuance = False
        self.observations = []

    def monotonic(self):
        return self._now

    @staticmethod
    def _native_process_identity(pid, uid):
        return f"{pid}:{uid}"

    def _binding(self, uid):
        return _Binding(uid)

    @staticmethod
    def _verify_context_signature(_context):
        return None

    @staticmethod
    def _assert_current_context(_context, _binding, _uid):
        return None

    @staticmethod
    def _verify_source_receipt(_receipt, _binding):
        return None

    @staticmethod
    def _policy_revision():
        return "policy-1"

    def issue_observed_source(self, observation):
        if not isinstance(observation, VerifiedSourceObservation):
            raise AssertionError("service received unverified source DTO")
        self.observation_registry.consume_observation_proof(observation)
        return self._issue_fixture_receipt(observation)

    def issue_selected_input_source(self, observation):
        if not isinstance(observation, VerifiedSourceObservation):
            raise AssertionError("service received unverified selected input DTO")
        if not self.observation_registry.verify_current_selected_input_proof(
                observation, observation.selected_execution):
            raise AssertionError("selected input proof was not current before consent resolution")
        if self.observation_registry.resolve_selected_input_execution_registry(
                observation, observation.selected_execution) is None:
            raise AssertionError("consent resolver could not recover the retained selection registry")
        self.observation_registry.consume_selected_input_observation(
            observation, observation.selected_execution)
        if self.observation_registry.verify_current_selected_input_proof(
                observation, observation.selected_execution):
            raise AssertionError("selected input proof remained current after one-use consumption")
        return self._issue_fixture_receipt(observation)

    def _issue_fixture_receipt(self, observation):
        self.observations.append(observation)
        if self.fail_issuance:
            raise AuthorityDenied("source.issuer", "fixture authority issuance failed")
        self._issued += 1
        handle = SourceReceiptHandle(f"h{self._issued:047d}")
        receipt = SourceReceipt(
            receipt_id=f"receipt-{self._issued}", issuer_id="host-authority",
            source_kind=observation.source_kind, principal_id=observation.principal_id,
            profile_id=observation.profile_id, namespace_id=observation.namespace_id,
            uid=observation.producer_uid,
            # The observer proof carries the event-derived origin and the
            # authority preserves that signed value without re-appending it.
            origin_id=observation.origin_id,
            process_generation=observation.generation,
            payload_digest=observation.payload_sha256, sensitivity=Sensitivity.PRIVATE,
            parent_lineage_hash=observation.parent_context.lineage_hash,
            policy_revision="policy-1", recipient_ceiling=frozenset(),
            issued_at_monotonic=observation.issued_monotonic,
            monotonic_expires_at=observation.expires_monotonic, signature="signed",
            enrollment_id=observation.enrollment_id,
            native_process_identity=f"{observation.producer_pid}:{observation.producer_uid}",
            parent_receipt_ids=tuple(item.receipt_id for item in observation.parent_receipts),
            nonce=f"nonce-{self._issued}",
        )
        with self._lock:
            self._source_receipt_handles[handle] = receipt
        return handle


@dataclass(frozen=True)
class _Binding:
    uid: int


def _digest(byte):
    return byte * 64


def _enrollment(**changes):
    fields = dict(
        observer_enrollment_id="observer.native.primary",
        source_kind="native-input",
        origin_id="hermes.primary",
        profile_id="producer-profile",
        principal_id="producer-principal",
        namespace_id="producer-namespace",
        enrollment_id="producer-enrollment",
        generation="gen-4",
        producer_uid=2001,
        producer_executable_sha256=_digest("b"),
        package_id="hermes-package",
        package_sha256=_digest("a"),
        role_id="native-process-role",
        role_artifact_id="native-role-module",
        role_sha256=_digest("9"),
        channel_id="chat.request",
        capture_schema_id="schema.capture.request",
        source_action_id="authenticated-input",
        target_id="provider.fixed",
        recipient="public-provider",
        allowed_parent_source_kinds=frozenset({"native-input"}),
    )
    fields.update(changes)
    return SourceObserverEnrollment(**fields)


def _context(service, payload=b"captured request", source_receipts=()):
    return HostContext(
        principal_id="producer-principal", profile_id="producer-profile",
        namespace_id="producer-namespace", uid=2001, purpose="native-event",
        intent_id="intent-1", trace_id="trace-1", sensitivity=Sensitivity.UNKNOWN,
        lineage_hash=canonical_digest({"empty": True}), policy_revision="policy-1",
        capabilities=frozenset({"provider-dispatch"}), issued_at_monotonic=9.0,
        monotonic_expires_at=40.0, nonce="nonce-1", grant_id="grant-1",
        signature="signed", source_receipts=tuple(source_receipts), final_payload_digest=canonical_digest(payload),
        enrollment_id="producer-enrollment", generation="gen-4", operation="native.event.prepare",
        native_process_identity=service._native_process_identity(733, 2001),
    )


def _consumer_context(service, receipt, *, profile="gateway-profile", uid=2002):
    return HostContext(
        principal_id="gateway-principal", profile_id=profile,
        namespace_id="gateway-namespace", uid=uid, purpose="resource-job",
        intent_id="job-1", trace_id="trace-job-1", sensitivity=Sensitivity.PRIVATE,
        lineage_hash=canonical_digest({"receipt": receipt.receipt_id}),
        policy_revision="policy-1", capabilities=frozenset({"resource-job.admit"}),
        issued_at_monotonic=10.0, monotonic_expires_at=30.0,
        nonce="job-nonce", grant_id="job-grant", signature="signed",
        source_receipts=(receipt,), enrollment_id="gateway-enrollment",
        generation="gen-8", operation="resource.job.admit",
    )


class SourceObserverContracts(unittest.TestCase):
    def test_private_provider_route_candidates_are_finite_and_protected(self):
        fields = dict(
            observer_enrollment_id="observer.native.primary", source_kind="native-input",
            origin_id="hermes.primary", profile_id="producer-profile",
            principal_id="producer-principal", namespace_id="producer-namespace",
            enrollment_id="producer-enrollment", generation="gen-4", producer_uid=2001,
            producer_executable_sha256=_digest("b"), package_id="hermes-package",
            package_sha256=_digest("a"), role_id="native-process-role", role_artifact_id="native-role-module",
            role_sha256=_digest("9"), channel_id="chat.request",
            capture_schema_id="schema.capture.request", source_action_id="authenticated-input",
            target_id="provider.fixed", recipient="public-provider",
            allowed_parent_source_kinds=[], private_provider_route_ids=["route.private.codex"],
        )
        selected = SourceObserverEnrollment.from_protected_record(fields)
        self.assertEqual(selected.private_provider_route_ids, ("route.private.codex",))
        legacy = dict(fields)
        legacy.pop("private_provider_route_ids")
        self.assertEqual(SourceObserverEnrollment.from_protected_record(legacy).private_provider_route_ids, ())
        with self.assertRaises(AuthorityDenied):
            SourceObserverEnrollment.from_protected_record(
                {**fields, "private_provider_route_ids": ["route.private.codex", "route.private.codex"]})

    def setUp(self):
        self.service = _Service()
        self.enrollment = _enrollment()
        self.identity = _Identity("producer-profile", "gen-4", 2001, 811, _digest("b"))
        self.resolved = self.identity
        self.target_identity = _Identity("gateway-profile", "gen-8", 2002, 992, _digest("f"))
        self.selected_package = _Package()
        self.closed = []
        self.proof_peers = []
        self.patches = [
            patch("hermes_installer.authority.source_observers.os.dup", side_effect=lambda fd: fd + 100),
            patch("hermes_installer.authority.source_observers.os.close", side_effect=self.closed.append),
        ]
        for item in self.patches:
            item.start()
        self.addCleanup(lambda: [item.stop() for item in self.patches])
        self.registry = SourceObserverRegistry(
            service=self.service,
            observers={self.enrollment.observer_enrollment_id: self.enrollment},
            process_resolver=self.resolve,
            package_resolver=self.package,
            target_peer_resolver=self.target_peer,
            loaded_package_proof_resolver=self.loaded_package_proof,
        )
        self.service.observation_registry = self.registry

    def test_private_consent_selection_comes_from_current_root_principal_choice(self):
        handle = "c" * 43
        principal = SimpleNamespace(
            uid=self.enrollment.producer_uid,
            profile_id=self.enrollment.profile_id,
            principal_id=self.enrollment.principal_id,
            namespace_id=self.enrollment.namespace_id,
        )

        class _ConsentRegistry:
            service = self.service

            def selection_handle_for_current_profile(self, selected):
                if selected is not principal:
                    raise AuthorityDenied("consent.selection", "wrong principal")
                return handle

        self.service.private_input_consent_registry = _ConsentRegistry()
        self.service.bindings_by_uid = {principal.uid: principal}
        selections = object.__new__(RootNativeExecutionSelectionRegistry)
        selections.service = self.service
        running = SimpleNamespace(source=SimpleNamespace(
            profile_id=principal.profile_id,
            principal_id=principal.principal_id,
            namespace_id=principal.namespace_id,
        ), private_consent_selection_handle="worker-must-not-be-read")
        self.assertEqual(
            selections._private_consent_selection_handle(self.enrollment, running), handle)
        self.service.bindings_by_uid = {principal.uid: SimpleNamespace(
            uid=principal.uid, profile_id="other",
            principal_id=principal.principal_id, namespace_id=principal.namespace_id,
        )}
        with self.assertRaises(AuthorityDenied):
            selections._private_consent_selection_handle(self.enrollment, running)
        self.addCleanup(self.registry.close)

    def test_native_input_delivery_wire_is_bounded_and_contains_no_payload(self):
        delivery = NativeInitialInputDelivery(
            schema=1, source_receipt_handle="h" * 43,
            selected_execution_handle="s" * 43, input_sha256="a" * 64,
            input_size_bytes=17, expires_monotonic=25.0,
        )
        self.assertEqual(delivery.to_wire(), {
            "schema": 1, "source_receipt_handle": "h" * 43,
            "selected_execution_handle": "s" * 43, "input_sha256": "a" * 64,
            "input_size_bytes": 17, "expires_monotonic": 25.0,
        })
        self.assertNotIn("payload", delivery.to_wire())
        delivered_turn = NativeInitialInputDelivery(
            schema=1, source_receipt_handle="h" * 43,
            selected_execution_handle="s" * 43, input_sha256="a" * 64,
            input_size_bytes=17, expires_monotonic=25.0, turn_handle="t" * 43,
        )
        self.assertEqual(delivered_turn.to_wire()["turn_handle"], "t" * 43)
        for changes in (
            {"source_receipt_handle": "worker-selected"},
            {"input_sha256": "not-a-digest"},
            {"input_size_bytes": 0},
            {"expires_monotonic": float("inf")},
            {"turn_handle": "caller-selected-turn"},
        ):
            fields = {
                "schema": 1, "source_receipt_handle": "h" * 43,
                "selected_execution_handle": "s" * 43, "input_sha256": "a" * 64,
                "input_size_bytes": 17, "expires_monotonic": 25.0,
            }
            fields.update(changes)
            with self.assertRaises(ValueError):
                NativeInitialInputDelivery(**fields)

    def test_native_selection_handle_lookup_rejects_caller_forgery(self):
        from hermes_installer.authority.source_observers import RootNativeExecutionSelectionRegistry
        registry = object.__new__(RootNativeExecutionSelectionRegistry)
        registry._lock = threading.RLock()
        registry._selections = {}
        with self.assertRaises(AuthorityDenied):
            registry.resolve_selection_handle("caller-selected")
        with self.assertRaises(AuthorityDenied):
            registry.resolve_selection_handle("x" * 43)

    def resolve(self, pid, pidfd, *, profile_id, generation):
        if pidfd not in {901, 1001, 1101, 1201, 1301, 1401, 1501, 1601} or pid not in {733, 844}:
            return None
        if pid == 733 and pidfd != 901 and self.resolved != self.identity:
            return None
        identity = (self.resolved if pidfd == 901 else self.identity) if pid == 733 else self.target_identity
        if (identity.profile_id, identity.generation) != (profile_id, generation):
            return None
        return identity

    def target_peer(self, _observer, _context):
        return _TargetPeer(844, 1401, 2002, "gateway-profile", "gen-8", self.target_identity)

    def loaded_package_proof(self, identity, _observer, *, peer_pid, peer_pidfd):
        self.proof_peers.append((peer_pid, peer_pidfd))
        return _LoadedProof(
            "proof-1", self.selected_package.package_id, self.selected_package.profile_id,
            identity.generation, self.selected_package.compiled_closure_sha256,
            self.selected_package.entrypoint_sha256, self.selected_package.resolver_sha256,
            123, "mount-1", _digest("1"), frozenset({"ro", "nosuid", "nodev"}),
            8, 99, identity, "native-role-module", _digest("9"), "loader-ready-event",
            ("authenticated-input",), 9.0, 39.0, _digest("2"))

    def package(self, package_id, generation):
        return (self.selected_package if package_id == "hermes-package"
                and generation == self.selected_package.generation else None)

    def record(self, payload=b"captured request"):
        return self.registry.record_observed_event(
            self.enrollment.observer_enrollment_id,
            payload_bytes=payload,
            parent_context=_context(self.service, payload),
            peer_pid=733, peer_pidfd=901,
        )

    def test_capture_returns_root_handle_and_binds_protected_role_metadata(self):
        event_id = self.record()
        result = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        self.assertIsInstance(result, SourceReceiptHandle)
        self.assertEqual(result, f"h{1:047d}")
        observation = self.service.observations[0]
        self.assertEqual(observation.package_id, self.enrollment.package_id)
        self.assertEqual(observation.role_sha256, self.enrollment.role_sha256)
        self.assertEqual(observation.resolver_sha256, "e" * 64)
        self.assertEqual(observation.operation, "provider.dispatch")
        self.assertEqual(observation.action_id, "authenticated-input")
        self.assertEqual(observation.channel_id, self.enrollment.channel_id)
        self.assertEqual(observation.target_id, self.enrollment.target_id)
        self.assertEqual(observation.recipient, self.enrollment.recipient)
        self.assertEqual(observation.target_peer_identity, self.target_identity)
        self.assertEqual(observation.target_peer_profile_id, "gateway-profile")
        self.assertEqual(observation.target_peer_generation, "gen-8")
        self.assertEqual(observation.parent_receipts, ())
        self.assertEqual(self.proof_peers, [(733, 901), (733, 1001)])
        self.assertEqual(set(self.closed), {1001, 1401, 1501})
        delivered = self.registry.take_source_receipt(
            str(result), peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        self.assertEqual(delivered, result)
        current_handle = self.registry.resolve_delivered_source_receipt(
            str(result), peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        self.assertEqual(current_handle, result)
        with self.assertRaises(AuthorityDenied):
            self.registry.take_source_receipt(
                str(result), peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_delivered_source_receipt(
                str(result), peer_uid=2003, peer_pid=844, peer_pidfd=1501)

    def test_atomic_root_ingress_capture_does_not_expose_generated_event_id(self):
        result = self.registry.capture_observed_ingress(
            self.enrollment.observer_enrollment_id,
            payload_bytes=b"captured request",
            parent_context=_context(self.service, b"captured request"),
            peer_pid=733, peer_pidfd=901,
        )
        self.assertIsInstance(result, SourceReceiptHandle)
        self.assertEqual(self.registry._pending, {})
        self.assertNotIn("event_record_id", str(result))
        self.assertEqual(self.registry._capsule_bytes, len(b"captured request"))

    def test_selected_native_input_capture_uses_root_issued_task_target_without_hi11_pair(self):
        self.registry.target_peer_resolver = None
        self.enrollment = replace(
            self.enrollment, private_provider_route_ids=("provider.codex.private",))
        self.registry.observers[self.enrollment.observer_enrollment_id] = self.enrollment
        package_generation = "package-generation-9"
        self.enrollment = replace(
            self.enrollment, native_package_generation=package_generation)
        self.registry.observers[self.enrollment.observer_enrollment_id] = self.enrollment
        self.selected_package = replace(self.selected_package, generation=package_generation)
        role = self.selected_package.process_role_records["native-process-role"]
        action = self.selected_package.action_records["hermes-main:action:authenticated-input"]
        object.__setattr__(self.selected_package, "process_role_records", {
            "native-process-role": SimpleNamespace(
                **{**vars(role), "native_package_generation": package_generation}),
        })
        object.__setattr__(self.selected_package, "action_records", {
            "hermes-main:action:authenticated-input": replace(action, generation=package_generation),
        })
        object.__setattr__(self.selected_package, "adapter_records", {
            "hermes-main": replace(action, generation=package_generation),
        })
        selected = RootSelectedNativeExecution(
            schema=1, selection_handle="s" * 43, kind="resource-task",
            execution_handle=SimpleNamespace(parent_closure_digest=_digest("c")),
            process_handle=SimpleNamespace(process_id="managed-task-process"),
            observer_enrollment_id=self.enrollment.observer_enrollment_id,
            profile_id=self.enrollment.profile_id,
            generation=self.enrollment.generation,
            native_package_id=self.enrollment.package_id,
            native_package_generation=package_generation,
            source_action_id=self.enrollment.source_action_id,
            service_generation_digest=_digest("2"), expires_monotonic=39.0,
            private_consent_selection_handle=None,
        )
        target = SimpleNamespace(
            process_id="managed-task-process", profile_id=self.identity.profile_id,
            generation=self.identity.generation, peer_pid=733, peer_pidfd=901,
            uid=self.identity.kernel_uid, live_peer_identity=self.identity,
            loaded_package_proof=self.registry.loaded_package_proof_resolver(
                self.identity, self.enrollment, peer_pid=733, peer_pidfd=901),
            service_generation_digest=_digest("2"),
            expires_monotonic=39.0,
        )

        class _Selection:
            def resolve_current_execution(self, candidate):
                if candidate is not selected:
                    raise AuthorityDenied("resource.native_selection", "forged selection")
                return candidate

            def consume_selected_native_input_target(self, candidate, received):
                if candidate is not selected or received is not target:
                    raise AuthorityDenied("resource.native_target", "forged target")
                return received

        result = self.registry.capture_selected_native_ingress(
            self.enrollment.observer_enrollment_id, payload_bytes=b"exact stdin prompt",
            parent_context=_context(self.service, b"exact stdin prompt"),
            selected_execution=selected, target=target,
            selection_registry=_Selection(),
        )
        self.assertIsInstance(result, SourceReceiptHandle)
        self.assertIs(self.service.observations[-1].selected_execution, selected)
        self.assertEqual(self.service.observations[-1].private_provider_route_ids,
                         ("provider.codex.private",))
        self.assertEqual(self.service.observations[-1].private_consent_selection_handle,
                         None)
        self.assertEqual(self.registry._pending, {})
        self.assertEqual(self.registry._capsule_bytes, len(b"exact stdin prompt"))
        self.assertIn((733, 901), self.proof_peers)
        self.assertIs(
            self.registry.resolve_retained_selected_input_execution(result), selected)
        self.assertFalse(self.service._source_receipt_handles[result].recipient_ceiling)

        from hermes_installer.authority.native_input_observer import RootNativeInputEvent
        from hermes_installer.authority.source_observers import RootNativeInputDeliveryRegistry

        self.service.service_generation_digest = _digest("2")
        ready_event_id = "loader-ready-event"
        captured_capsule = self.registry._payload_capsules[str(result)][1]
        selected.execution_handle.parent_closure_digest = captured_capsule.parent_closure_digest
        input_event = RootNativeInputEvent(
            schema=1, input_event_id="i" * 43,
            input_origin_kind="root-admitted-task", source_receipt_handle=str(result),
            payload_sha256=hashlib.sha256(b"exact stdin prompt").hexdigest(),
            payload_size_bytes=len(b"exact stdin prompt"),
            producer_profile_id=selected.profile_id, producer_generation=selected.generation,
            parent_closure_digest=captured_capsule.parent_closure_digest, observed_monotonic=10.0,
            expires_monotonic=30.0, native_loader_ready_event_id=ready_event_id,
        )

        class _SelectedExecutions:
            source_observers = self.registry

            @staticmethod
            def resolve_current_execution(candidate):
                if candidate is not selected:
                    raise AuthorityDenied("resource.native_selection", "wrong selection")
                return candidate

            @staticmethod
            def loader_ready_event_id(candidate):
                if candidate is not selected:
                    raise AuthorityDenied("resource.native_selection", "wrong selection")
                return ready_event_id

            @staticmethod
            def revalidate_selected_native_peer(candidate, *, peer_uid, peer_pid,
                                                peer_pidfd, loader_ready_event_id):
                if (candidate is not selected or peer_uid != 2001 or peer_pid != 733
                        or loader_ready_event_id != ready_event_id
                        or self.registry.process_resolver(
                            peer_pid, peer_pidfd, profile_id=selected.profile_id,
                            generation=selected.generation) != self.identity):
                    raise AuthorityDenied("resource.native_peer", "wrong authenticated peer")
                return self.identity

        input_delivery = object.__new__(RootNativeInputDeliveryRegistry)
        input_delivery.source_observers = self.registry
        input_delivery.selected_executions = _SelectedExecutions()
        input_delivery.process_custody = object()
        input_delivery.service = self.service
        input_delivery.monotonic = self.service.monotonic
        input_delivery._lock = threading.RLock()
        input_delivery._changed = threading.Condition(input_delivery._lock)
        input_delivery._pending = {}
        input_delivery._closed = False
        input_delivery.queue_selected_input(selected, input_event)
        self.assertFalse(self.registry._receipt_delivery_bindings[str(result)].delivered)
        self.assertIsNone(input_delivery.take_selected_native_input(
            peer_uid=2002, peer_pid=733, peer_pidfd=901))
        self.assertFalse(self.registry._receipt_delivery_bindings[str(result)].delivered)
        delivered = input_delivery.take_selected_native_input(
            peer_uid=2001, peer_pid=733, peer_pidfd=901)
        self.assertEqual(delivered.source_receipt_handle, str(result))
        self.assertEqual(delivered.input_sha256, input_event.payload_sha256)
        self.assertTrue(self.registry._receipt_delivery_bindings[str(result)].delivered)
        self.assertIsNone(input_delivery.take_selected_native_input(
            peer_uid=2001, peer_pid=733, peer_pidfd=901))
        self.assertTrue(input_delivery.cancel_selected_input(selected))
        self.assertNotIn(str(result), self.service._source_receipt_handles)
        self.assertFalse(input_delivery.cancel_selected_input(selected))
        self.assertFalse(self.registry.revoke_source_handle(result))

    def test_root_recipe_capsule_is_resolved_from_signed_receipt_and_consumed_once(self):
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        receipt = self.service._source_receipt_handles[handle]
        context = _consumer_context(self.service, receipt)
        lookup = self.registry.lookup_source_handle(
            receipt.receipt_id, signed_context=context,
            peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        self.assertEqual(lookup, handle)
        capsule = self.registry.consume_source_payload_capsule(
            lookup, signed_context=context, peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        self.assertEqual(capsule.payload_bytes, b"captured request")
        self.assertEqual(capsule.payload_sha256, receipt.payload_digest)
        self.assertEqual(capsule.receipt_id, receipt.receipt_id)
        self.assertEqual(capsule.observer_enrollment_id, self.enrollment.observer_enrollment_id)
        self.assertEqual(capsule.channel_id, self.enrollment.channel_id)
        self.assertEqual(capsule.capture_schema_id, self.enrollment.capture_schema_id)
        self.assertEqual(capsule.source_action_id, self.enrollment.source_action_id)
        self.assertEqual(capsule.invocation_id, "grant-1")
        self.assertEqual(capsule.parent_receipt_ids, ())
        self.assertNotIn(str(handle), self.registry._payload_capsules)
        with self.assertRaises(AuthorityDenied):
            self.registry.consume_source_payload_capsule(
                lookup, signed_context=context, peer_uid=2002, peer_pid=844, peer_pidfd=1501)

    def test_live_source_producer_resolution_is_peer_bound_one_use_and_lease_limited(self):
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        receipt = self.service._source_receipt_handles[handle]
        args = dict(
            receipt_id=receipt.receipt_id, profile_id=receipt.profile_id,
            generation=receipt.process_generation,
            native_process_identity=receipt.native_process_identity,
            expires_monotonic=receipt.monotonic_expires_at,
        )
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_live_source_producer(**{**args, "generation": "stale"})
        producer = self.registry.resolve_live_source_producer(**args)
        self.assertIsInstance(producer, LiveSourceProducer)
        self.assertEqual(producer.pid, 733)
        self.assertEqual(producer.pidfd, 1201)
        self.assertEqual(producer.identity, self.identity)
        self.assertEqual(producer.observer_enrollment_id, self.enrollment.observer_enrollment_id)
        self.assertEqual(producer.source_action_id, self.enrollment.source_action_id)
        self.assertEqual(producer.channel_id, self.enrollment.channel_id)
        self.assertEqual(producer.loaded_package_proof,
                         self.service.observations[-1].loaded_package_proof)
        self.assertEqual(producer.authority_epoch, self.service.authority_epoch)
        os.close(producer.pidfd)
        with self.assertRaises(AuthorityDenied):
            self.registry.resolve_live_source_producer(**args)

    def test_capsule_wrong_profile_or_forged_receipt_context_denied_and_scrubbed(self):
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        receipt = self.service._source_receipt_handles[handle]
        context = _consumer_context(self.service, receipt)
        wrong_context = _consumer_context(self.service, receipt, profile="other-profile")
        with self.assertRaises(AuthorityDenied):
            self.registry.lookup_source_handle(
                receipt.receipt_id, signed_context=wrong_context,
                peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        lookup = self.registry.lookup_source_handle(
            receipt.receipt_id, signed_context=context,
            peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        bad_context = replace(context, source_receipts=())
        with self.assertRaises(AuthorityDenied):
            self.registry.consume_source_payload_capsule(
                lookup, signed_context=bad_context,
                peer_uid=2002, peer_pid=844, peer_pidfd=1501)
        self.assertEqual(self.registry._capsule_bytes, 0)
        self.assertFalse(self.registry._payload_capsules)

    def test_invocation_cancel_epoch_restart_and_expiry_scrub_capsules(self):
        handles = []
        for payload in (b"captured request", b"second event"):
            event_id = self.record(payload)
            handles.append(self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, payload))
        self.assertEqual(self.registry.cancel_invocation_payload_capsules("grant-1"), 2)
        self.assertEqual(self.registry._capsule_bytes, 0)
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        retained = self.registry._payload_capsules[str(handle)][2]
        self.service.authority_epoch = "epoch-two"
        self.registry.prune()
        self.assertEqual(self.registry._capsule_bytes, 0)
        self.assertEqual(retained, bytearray(len(retained)))

    def test_peer_delivery_rejects_wrong_identity_and_never_returns_receipt_claims(self):
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        with self.assertRaises(AuthorityDenied):
            self.registry.take_source_receipt(
                str(handle), peer_uid=2001, peer_pid=844, peer_pidfd=1501)
        with self.assertRaises(AuthorityDenied):
            self.registry.take_source_receipt(
                str(handle), peer_uid=2002, peer_pid=733, peer_pidfd=901)
        self.assertEqual(
            self.registry.take_source_receipt(
                str(handle), peer_uid=2002, peer_pid=844, peer_pidfd=1501), handle)

    def test_invocation_cancel_revokes_receipt_lookup_and_peer_delivery(self):
        event_id = self.record()
        handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        receipt_id = self.service._source_receipt_handles[handle].receipt_id
        retained = self.registry._payload_capsules[str(handle)][2]
        self.assertEqual(self.registry.cancel_invocation_payload_capsules("grant-1"), 1)
        self.assertEqual(retained, bytearray(len(retained)))
        self.assertNotIn(str(handle), self.service._source_receipt_handles)
        self.assertNotIn(receipt_id, self.registry._receipt_process_bindings)
        self.assertNotIn(str(handle), self.registry._receipt_delivery_bindings)
        with self.assertRaises(AuthorityDenied):
            self.registry.take_source_receipt(
                str(handle), peer_uid=2002, peer_pid=844, peer_pidfd=1501)

    def test_unknown_or_forged_event_id_cannot_mint_and_event_is_one_use(self):
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, "x" * 48, b"captured request")
        event_id = self.record()
        self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, event_id, b"captured request")
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_observation_dto_without_this_registry_instance_capability_is_rejected(self):
        event_id = self.record()
        event = self.registry._pending[event_id]
        # A structurally plausible DTO with a module-importable class is not
        # sufficient to reach the issuer; the registry consumes exact object
        # identity plus an instance-scoped capability.
        with self.assertRaises(AuthorityDenied):
            forged = VerifiedSourceObservation(
                observer_enrollment_id=self.enrollment.observer_enrollment_id,
                event_record_id=event_id, source_kind=self.enrollment.source_kind,
                origin_id="forged", payload_bytes=event.payload,
                payload_sha256=event.payload_sha256, parent_context=event.parent_context,
                parent_receipts=(), parent_receipt_handles=(),
                profile_id=self.enrollment.profile_id, principal_id=self.enrollment.principal_id,
                namespace_id=self.enrollment.namespace_id, enrollment_id=self.enrollment.enrollment_id,
                generation=self.enrollment.generation, producer_uid=self.enrollment.producer_uid,
                producer_pid=event.producer_pid, producer_pidfd=event.producer_pidfd,
                producer_identity=event.producer_identity, target_peer_uid=2002,
                target_peer_pid=844, target_peer_pidfd=1401,
                target_peer_profile_id="gateway-profile", target_peer_generation="gen-8",
                target_peer_identity=self.target_identity,
                loaded_package_proof=self.loaded_package_proof(
                    event.producer_identity, self.enrollment,
                    peer_pid=event.producer_pid, peer_pidfd=event.producer_pidfd),
                package_id=self.enrollment.package_id,
                package_sha256=self.enrollment.package_sha256, source_revision="pinned-revision",
                source_tree_sha256="c" * 64, compiled_closure_artifact_id="compiled-closure",
                entrypoint_artifact_id="entrypoint", entrypoint_sha256="d" * 64,
                resolver_artifact_id="resolver", resolver_sha256="e" * 64,
                service_package_root_id="package-root", service_mount_id="mount-hermes",
                role_id=self.enrollment.role_id,
                observer_role_artifact_id=self.enrollment.role_artifact_id,
                role_sha256=self.enrollment.role_sha256,
                source_action_id=self.enrollment.source_action_id,
                action_id="chat.complete", argument_schema_id="schema.arguments",
                result_schema_id="schema.result", effect_enrollment_id="provider.enrollment",
                operation="provider.dispatch", capability="provider-inference",
                invocation_id=event.invocation_id, channel_id=self.enrollment.channel_id,
                target_id=self.enrollment.target_id, recipient=self.enrollment.recipient,
                authority_epoch=event.authority_epoch, issued_monotonic=event.issued,
                expires_monotonic=event.expires, proof_nonce="z" * 48,
                _issuer_token=object(),
            )
            self.registry.consume_observation_proof(forged)

    def test_concurrent_capture_has_one_winner(self):
        event_id = self.record()
        barrier = threading.Barrier(3)
        outcomes = []

        def capture():
            barrier.wait()
            try:
                outcomes.append(self.registry.capture_observed_source(
                    self.enrollment.observer_enrollment_id, event_id, b"captured request"))
            except AuthorityDenied:
                outcomes.append("denied")

        workers = [threading.Thread(target=capture) for _ in range(2)]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(timeout=2)
        self.assertEqual(sum(isinstance(value, SourceReceiptHandle) for value in outcomes), 1)
        self.assertEqual(outcomes.count("denied"), 1)
        self.assertEqual(len(self.service.observations), 1)

    def test_submitted_bytes_or_parent_handles_cannot_replace_captured_event(self):
        event_id = self.record()
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"forged payload")
        self.assertEqual(self.registry._pending, {})
        self.assertEqual(set(self.closed), {1001, 1401, 1501})

    def test_parent_closure_requires_registered_handle_and_same_live_process_generation(self):
        first_event = self.record()
        parent_handle = self.registry.capture_observed_source(
            self.enrollment.observer_enrollment_id, first_event, b"captured request")
        parent = self.service._source_receipt_handles[parent_handle]

        second_context = _context(self.service, b"derived bytes", (parent,))
        second_event = self.registry.record_observed_event(
            self.enrollment.observer_enrollment_id,
            payload_bytes=b"derived bytes", parent_context=second_context,
            peer_pid=733, peer_pidfd=901,
            parent_receipt_handles=(parent_handle,),
        )
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, second_event, b"derived bytes")

        self.resolved = _Identity("producer-profile", "gen-4", 2001, 812, _digest("b"))
        with self.assertRaises(AuthorityDenied):
            self.registry.record_observed_event(
                self.enrollment.observer_enrollment_id,
                payload_bytes=b"third bytes", parent_context=_context(self.service, b"third bytes", (parent,)),
                peer_pid=733, peer_pidfd=901, parent_receipt_handles=(parent_handle,),
            )

    def test_wrong_observer_and_changed_pidfd_generation_or_executable_deny(self):
        with self.assertRaises(AuthorityDenied):
            self.registry.record_observed_event(
                "observer.unknown", payload_bytes=b"x", parent_context=_context(self.service, b"x"),
                peer_pid=733, peer_pidfd=901)
        event_id = self.record()
        self.resolved = _Identity("producer-profile", "gen-4", 2001, 812, _digest("c"))
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")
        self.assertEqual(set(self.closed), {1001, 1401, 1501})

    def test_package_or_adapter_replacement_after_event_capture_denies(self):
        event_id = self.record()
        self.selected_package = replace(
            self.selected_package, compiled_closure_sha256=_digest("f"))
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_changed_loaded_package_closure_proof_after_event_capture_denies(self):
        event_id = self.record()
        original = self.loaded_package_proof
        self.registry.loaded_package_proof_resolver = lambda identity, _observer, **peer: replace(
            original(identity, self.enrollment, **peer), loader_ready_event_id="replacement-event")
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_target_peer_replacement_after_event_capture_denies(self):
        event_id = self.record()
        self.target_identity = _Identity("gateway-profile", "gen-8", 2002, 993, _digest("f"))
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_restart_epoch_and_expired_lease_drop_pending_observation(self):
        event_id = self.record()
        self.service.authority_epoch = "epoch-two"
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_queue_and_service_failure_consume_or_reject_without_leaking_pidfds(self):
        full = SourceObserverRegistry(
            service=self.service,
            observers={self.enrollment.observer_enrollment_id: self.enrollment},
            process_resolver=self.resolve,
            package_resolver=self.package,
            target_peer_resolver=self.target_peer,
            loaded_package_proof_resolver=self.loaded_package_proof,
            max_pending_events=1,
        )
        first = full.record_observed_event(
            self.enrollment.observer_enrollment_id, payload_bytes=b"first",
            parent_context=_context(self.service, b"first"), peer_pid=733, peer_pidfd=901)
        with self.assertRaises(AuthorityDenied):
            full.record_observed_event(
                self.enrollment.observer_enrollment_id, payload_bytes=b"second",
                parent_context=_context(self.service, b"second"), peer_pid=733, peer_pidfd=901)
        full.close()
        self.assertEqual(full._pending, {})
        self.service.fail_issuance = True
        event_id = self.record()
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")
        self.assertNotIn(event_id, self.registry._pending)
        self.assertIn(1001, self.closed)
        self.assertIn(1001, self.closed)

    def test_expired_event_cannot_issue_receipt(self):
        event_id = self.record()
        self.service._now = 40.0
        with self.assertRaises(AuthorityDenied):
            self.registry.capture_observed_source(
                self.enrollment.observer_enrollment_id, event_id, b"captured request")

    def test_rejects_missing_root_authority_callpoint_and_mutable_or_unknown_policy(self):
        with self.assertRaises(ValueError):
            SourceObserverRegistry(service=object(), observers={"x": self.enrollment},
                                   process_resolver=self.resolve,
                                   package_resolver=self.package)
        with self.assertRaises(ValueError):
            _enrollment(allowed_parent_source_kinds={"caller-asserted-public"})
        protected = {name: getattr(self.enrollment, name)
                     for name in self.enrollment.__dataclass_fields__}
        protected["allowed_parent_source_kinds"] = ["native-input"]
        parsed = SourceObserverEnrollment.from_protected_record(protected)
        self.assertEqual(parsed.allowed_parent_source_kinds, frozenset({"native-input"}))
        with self.assertRaises(AuthorityDenied):
            SourceObserverEnrollment.from_protected_record({**protected, "sensitivity": "public"})
        with self.assertRaises(AuthorityDenied):
            SourceObserverEnrollment.index_protected_records([protected, protected])
        with self.assertRaises(AuthorityDenied):
            VerifiedSourceObservation(
                observer_enrollment_id="observer.native.primary", event_record_id="e" * 48,
                source_kind="native-input", origin_id="origin", payload_bytes=b"x",
                payload_sha256="0" * 64, parent_context=_context(self.service, b"x"),
                parent_receipts=(), parent_receipt_handles=(), profile_id="profile",
                principal_id="principal", namespace_id="namespace", enrollment_id="enrollment",
                generation="generation", producer_uid=2001, producer_pid=733, producer_pidfd=1,
                producer_identity=self.identity, target_peer_uid=2002, target_peer_pid=844,
                target_peer_pidfd=1, target_peer_profile_id="gateway-profile",
                target_peer_generation="gen-8", target_peer_identity=self.target_identity,
                loaded_package_proof=self.loaded_package_proof(
                    self.identity, self.enrollment, peer_pid=733, peer_pidfd=901),
                package_id="package", package_sha256=_digest("a"),
                source_revision="revision", source_tree_sha256=_digest("a"),
                compiled_closure_artifact_id="closure", entrypoint_artifact_id="entrypoint",
                entrypoint_sha256=_digest("b"), resolver_artifact_id="resolver",
                resolver_sha256=_digest("c"), service_package_root_id="root", service_mount_id="mount",
                role_id="role", observer_role_artifact_id="role-artifact",
                role_sha256=_digest("b"), source_action_id="action-id", invocation_id="invocation",
                action_id="action", argument_schema_id="arguments", result_schema_id="result",
                effect_enrollment_id="effect", operation="provider.dispatch", capability="provider-inference",
                channel_id="channel", target_id="target", recipient="recipient",
                authority_epoch="epoch", issued_monotonic=1.0, expires_monotonic=2.0,
                proof_nonce="z" * 48, _issuer_token=object())

if __name__ == "__main__":
    unittest.main()
