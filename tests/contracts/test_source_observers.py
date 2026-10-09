from __future__ import annotations

import threading
import unittest
from dataclasses import dataclass, replace
from unittest.mock import patch

from hermes_installer.authority.source_observers import (
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
class _Adapter:
    adapter_id: str = "hermes-main"
    adapter_sha256: str = "b" * 64
    target_id: str = "provider.fixed"
    recipient: str = "public-provider"
    generation: str = "gen-4"
    action_id: str = "chat.complete"
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

    def __post_init__(self):
        object.__setattr__(self, "adapter_records", {"hermes-main": _Adapter()})


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
        self.observations.append(observation)
        if self.fail_issuance:
            raise AuthorityDenied("source.issuer", "fixture authority issuance failed")
        self._issued += 1
        handle = SourceReceiptHandle(f"h{self._issued:047d}")
        receipt = SourceReceipt(
            receipt_id=f"receipt-{self._issued}", issuer_id="host-authority",
            source_kind=observation.source_kind, principal_id=observation.principal_id,
            profile_id=observation.profile_id, namespace_id=observation.namespace_id,
            uid=observation.producer_uid, origin_id=observation.origin_id,
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
        package_id="hermes-package",
        package_sha256=_digest("a"),
        role_id="hermes-main",
        role_sha256=_digest("b"),
        channel_id="chat.request",
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


class SourceObserverContracts(unittest.TestCase):
    def setUp(self):
        self.service = _Service()
        self.enrollment = _enrollment()
        self.identity = _Identity("producer-profile", "gen-4", 2001, 811, _digest("b"))
        self.resolved = self.identity
        self.selected_package = _Package()
        self.closed = []
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
        )
        self.addCleanup(self.registry.close)

    def resolve(self, pid, pidfd, *, profile_id, generation):
        if pidfd not in {901, 1001, 1101, 1201, 1301} or pid != 733:
            return None
        if pidfd != 901 and self.resolved != self.identity:
            return None
        identity = self.resolved if pidfd == 901 else self.identity
        if (identity.profile_id, identity.generation) != (profile_id, generation):
            return None
        return identity

    def package(self, package_id, generation):
        return (self.selected_package if package_id == "hermes-package"
                and generation == "gen-4" else None)

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
        self.assertEqual(observation.action_id, "chat.complete")
        self.assertEqual(observation.channel_id, self.enrollment.channel_id)
        self.assertEqual(observation.target_id, self.enrollment.target_id)
        self.assertEqual(observation.recipient, self.enrollment.recipient)
        self.assertEqual(observation.parent_receipts, ())
        self.assertEqual(self.closed, [1001])

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
        self.assertEqual(self.closed, [1001])

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
        self.assertEqual(self.closed, [1001])
        self.assertEqual(self.closed, [1001])

    def test_package_or_adapter_replacement_after_event_capture_denies(self):
        event_id = self.record()
        self.selected_package = replace(
            self.selected_package, compiled_closure_sha256=_digest("f"))
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
                producer_identity=self.identity, package_id="package", package_sha256=_digest("a"),
                source_revision="revision", source_tree_sha256=_digest("a"),
                compiled_closure_artifact_id="closure", entrypoint_artifact_id="entrypoint",
                entrypoint_sha256=_digest("b"), resolver_artifact_id="resolver",
                resolver_sha256=_digest("c"), service_package_root_id="root", service_mount_id="mount",
                role_id="role", role_sha256=_digest("b"), invocation_id="invocation",
                action_id="action", argument_schema_id="arguments", result_schema_id="result",
                effect_enrollment_id="effect", operation="provider.dispatch", capability="provider-inference",
                channel_id="channel", target_id="target", recipient="recipient",
                authority_epoch="epoch", issued_monotonic=1.0, expires_monotonic=2.0,
                _issuer=object())


if __name__ == "__main__":
    unittest.main()
