"""Root-private, one-use source observations for installed Hermes roles.

The registry is constructed from protected enrollment and is called only by
root observer adapters.  It is deliberately not an AuthorityService RPC and
does not accept a worker's source kind, event ID, role, package, channel,
target, recipient, sensitivity, or public-clearance claim.
"""
from __future__ import annotations

import hashlib
import hmac
import math
import os
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .types import AuthorityDenied, HostContext, Sensitivity, SourceReceipt, canonical_digest

MAX_OBSERVED_SOURCE_BYTES = 1_048_576
MAX_PARENT_RECEIPTS = 64
MAX_PENDING_EVENTS = 256
MAX_PENDING_BYTES = 8 * 1024 * 1024
MAX_RETAINED_CAPSULES = 4096
MAX_RETAINED_CAPSULE_BYTES = 8 * 1024 * 1024
MAX_EVENT_IDS_PER_EPOCH = 100_000
MAX_EVENT_LEASE_SECONDS = 600

_ALLOWED_SOURCE_KINDS = frozenset({
    "native-input", "tool-result", "memory-record", "static-context",
    "schedule-event", "webhook-event", "provider-result",
})
class SourceReceiptHandle(str):
    """Opaque in-process lookup key returned by the root authority only."""

    def __new__(cls, value: str) -> "SourceReceiptHandle":
        if not isinstance(value, str) or not 32 <= len(value) <= 128:
            raise ValueError("source receipt handle is invalid")
        return str.__new__(cls, value)


@dataclass(frozen=True, slots=True)
class SourceObserverEnrollment:
    """Exact source-observer binding loaded from protected root enrollment."""

    observer_enrollment_id: str
    source_kind: str
    origin_id: str
    profile_id: str
    principal_id: str
    namespace_id: str
    enrollment_id: str
    generation: str
    producer_uid: int
    producer_executable_sha256: str
    package_id: str
    package_sha256: str
    role_id: str
    role_artifact_id: str
    role_sha256: str
    channel_id: str
    capture_schema_id: str
    source_action_id: str
    target_id: str
    recipient: str
    allowed_parent_source_kinds: frozenset[str]
    max_event_bytes: int = MAX_OBSERVED_SOURCE_BYTES
    lease_seconds: int = 30

    @classmethod
    def from_protected_record(cls, record: Mapping[str, Any]) -> "SourceObserverEnrollment":
        required = {
            "observer_enrollment_id", "source_kind", "origin_id", "profile_id", "principal_id",
            "namespace_id", "enrollment_id", "generation", "producer_uid", "package_id",
            "producer_executable_sha256", "package_sha256", "role_id", "role_artifact_id",
            "role_sha256", "channel_id", "capture_schema_id",
            "source_action_id", "target_id", "recipient",
            "allowed_parent_source_kinds",
        }
        optional = {"max_event_bytes", "lease_seconds"}
        if (not isinstance(record, Mapping) or set(record) - (required | optional)
                or required - set(record) or not isinstance(record["allowed_parent_source_kinds"], list)
                or len(record["allowed_parent_source_kinds"]) > len(_ALLOWED_SOURCE_KINDS)
                or any(not isinstance(item, str) for item in record["allowed_parent_source_kinds"])
                or len(set(record["allowed_parent_source_kinds"])) != len(record["allowed_parent_source_kinds"])):
            raise AuthorityDenied("source.enrollment", "protected source observer schema is invalid")
        values = dict(record)
        values["allowed_parent_source_kinds"] = frozenset(values["allowed_parent_source_kinds"])
        try:
            return cls(**values)
        except (ValueError, TypeError):
            raise AuthorityDenied("source.enrollment", "protected source observer fields are invalid") from None

    @classmethod
    def index_protected_records(cls, records: Sequence[Mapping[str, Any]]) -> Mapping[str, "SourceObserverEnrollment"]:
        if (not isinstance(records, (list, tuple)) or not records
                or len(records) > 512):
            raise AuthorityDenied("source.enrollment", "protected source observer catalog is empty or oversized")
        parsed = {}
        for raw in records:
            observer = cls.from_protected_record(raw)
            if observer.observer_enrollment_id in parsed:
                raise AuthorityDenied("source.enrollment", "protected source observer ID is duplicated")
            parsed[observer.observer_enrollment_id] = observer
        return parsed

    def __post_init__(self) -> None:
        for name in (
            "observer_enrollment_id", "origin_id", "profile_id", "principal_id",
            "namespace_id", "enrollment_id", "generation", "package_id", "role_id",
            "role_artifact_id", "channel_id", "source_action_id", "target_id", "recipient",
            "capture_schema_id",
        ):
            _identifier(getattr(self, name), name)
        for name in ("producer_executable_sha256", "package_sha256", "role_sha256"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if self.source_kind not in _ALLOWED_SOURCE_KINDS:
            raise ValueError("source kind is not a fixed host source kind")
        if (type(self.producer_uid) is not int or self.producer_uid <= 0
                or not isinstance(self.allowed_parent_source_kinds, frozenset)
                or not self.allowed_parent_source_kinds.issubset(_ALLOWED_SOURCE_KINDS)
                or type(self.max_event_bytes) is not int
                or not 1 <= self.max_event_bytes <= MAX_OBSERVED_SOURCE_BYTES
                or type(self.lease_seconds) is not int
                or not 1 <= self.lease_seconds <= MAX_EVENT_LEASE_SECONDS):
            raise ValueError("source observer bounds or parent channels are invalid")


@dataclass(frozen=True, slots=True)
class VerifiedSourceObservation:
    """Private proof object the root authority accepts for receipt issuance.

    The instance-scoped token is checked and consumed by the exact registry
    injected into AuthorityService. A module-global marker would be importable
    by arbitrary in-process code and is therefore not an issuer capability.
    """

    observer_enrollment_id: str
    event_record_id: str
    source_kind: str
    origin_id: str
    payload_bytes: bytes
    payload_sha256: str
    parent_context: HostContext
    parent_receipts: tuple[SourceReceipt, ...]
    parent_receipt_handles: tuple[str, ...]
    profile_id: str
    principal_id: str
    namespace_id: str
    enrollment_id: str
    generation: str
    producer_uid: int
    producer_pid: int
    producer_pidfd: int
    producer_identity: Any
    target_peer_uid: int
    target_peer_pid: int
    target_peer_pidfd: int
    target_peer_profile_id: str
    target_peer_generation: str
    target_peer_identity: Any
    loaded_package_proof: Any
    package_id: str
    package_sha256: str
    observer_role_artifact_id: str
    source_action_id: str
    source_revision: str
    source_tree_sha256: str
    compiled_closure_artifact_id: str
    entrypoint_artifact_id: str
    entrypoint_sha256: str
    resolver_artifact_id: str
    resolver_sha256: str
    service_package_root_id: str
    service_mount_id: str
    role_id: str
    role_sha256: str
    action_id: str
    argument_schema_id: str
    result_schema_id: str
    effect_enrollment_id: str
    operation: str
    capability: str
    invocation_id: str
    channel_id: str
    target_id: str
    recipient: str
    authority_epoch: str
    issued_monotonic: float
    expires_monotonic: float
    proof_nonce: str
    _issuer_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not isinstance(self.payload_bytes, bytes) or not self.payload_bytes
                or hashlib.sha256(self.payload_bytes).hexdigest() != self.payload_sha256
                or not isinstance(self.parent_context, HostContext)
                or not isinstance(self.parent_receipts, tuple)
                or len(self.parent_receipts) > MAX_PARENT_RECEIPTS
                or any(not isinstance(item, SourceReceipt) for item in self.parent_receipts)
                or len(self.parent_receipt_handles) > MAX_PARENT_RECEIPTS
                or not self.authority_epoch
                or not isinstance(self.proof_nonce, str) or not 32 <= len(self.proof_nonce) <= 128
                or self.expires_monotonic <= self.issued_monotonic):
            raise AuthorityDenied("source.observation", "root source observation is malformed")


@dataclass(slots=True)
class _PendingObservation:
    observer: SourceObserverEnrollment
    event_record_id: str
    invocation_id: str
    payload: bytes
    payload_sha256: str
    parent_context: HostContext
    parent_receipts: tuple[SourceReceipt, ...]
    parent_handles: tuple[str, ...]
    producer_pid: int
    producer_pidfd: int
    producer_identity: Any
    selected_package: Any
    selected_adapter: Any
    loaded_package_proof: Any
    target_peer_pid: int
    target_peer_pidfd: int
    target_peer_uid: int
    target_peer_profile_id: str
    target_peer_generation: str
    target_peer_identity: Any
    authority_epoch: str
    issued: float
    expires: float


@dataclass(slots=True)
class _ReceiptProcessBinding:
    receipt_id: str
    handle: str
    pid: int
    pidfd: int
    identity: Any
    profile_id: str
    generation: str
    uid: int
    expires: float
    authority_epoch: str = ""
    observer_enrollment_id: str = ""
    source_action_id: str = ""
    channel_id: str = ""
    loaded_package_proof: Any = None
    delivered: bool = False


@dataclass(frozen=True, slots=True)
class LiveSourceProducer:
    """One-use root-only process evidence; caller owns and closes ``pidfd``."""

    receipt_id: str
    pid: int
    pidfd: int
    identity: Any
    uid: int
    profile_id: str
    generation: str
    expires_monotonic: float
    authority_epoch: str
    observer_enrollment_id: str
    source_action_id: str
    channel_id: str
    loaded_package_proof: Any


@dataclass(frozen=True, slots=True)
class RootSourcePayloadCapsule:
    """One-use root-internal payload view for a selected event recipe.

    This value must stay inside trusted root handlers. It has no wire encoder
    and is never returned by an authority RPC or to a producer worker.
    """

    receipt_id: str
    observer_enrollment_id: str
    event_record_id: str
    invocation_id: str
    source_kind: str
    channel_id: str
    capture_schema_id: str
    source_action_id: str
    profile_id: str
    principal_id: str
    namespace_id: str
    generation: str
    payload_bytes: bytes = field(repr=False)
    payload_sha256: str
    parent_receipt_ids: tuple[str, ...]
    parent_closure_digest: str
    issued_monotonic: float
    expires_monotonic: float


class SourceObserverRegistry:
    """Concrete root observer: protected enrollment -> captured event -> receipt handle."""

    def __init__(self, *, service: Any, observers: Mapping[str, SourceObserverEnrollment],
                 process_resolver: Callable[..., Any], package_resolver: Callable[[str, str], Any],
                 target_peer_resolver: Callable[[SourceObserverEnrollment, HostContext], Any] | None = None,
                 loaded_package_proof_resolver: Callable[..., Any] | None = None,
                 max_pending_events: int = MAX_PENDING_EVENTS,
                 max_pending_bytes: int = MAX_PENDING_BYTES):
        if (not observers or any(not isinstance(value, SourceObserverEnrollment)
                                 or key != value.observer_enrollment_id
                                 for key, value in observers.items())
                or not callable(process_resolver) or not callable(package_resolver)
                or type(max_pending_events) is not int or not 1 <= max_pending_events <= MAX_PENDING_EVENTS
                or type(max_pending_bytes) is not int or not MAX_OBSERVED_SOURCE_BYTES <= max_pending_bytes <= MAX_PENDING_BYTES
                or not hasattr(service, "authority_epoch")
                or not callable(getattr(service, "issue_observed_source", None))):
            raise ValueError("source observer requires protected records and the root receipt call point")
        self.service = service
        self.observers = dict(observers)
        self.process_resolver = process_resolver
        self.package_resolver = package_resolver
        self.target_peer_resolver = target_peer_resolver
        self.loaded_package_proof_resolver = loaded_package_proof_resolver
        self.max_pending_events = max_pending_events
        self.max_pending_bytes = max_pending_bytes
        self._pending: dict[str, _PendingObservation] = {}
        self._event_ids_issued: set[str] = set()
        self._pending_bytes = 0
        self._receipt_process_bindings: dict[str, _ReceiptProcessBinding] = {}
        self._receipt_delivery_bindings: dict[str, _ReceiptProcessBinding] = {}
        self._payload_capsules: dict[str, tuple[SourceReceipt, RootSourcePayloadCapsule, bytearray, str]] = {}
        self._invocation_receipt_handles: dict[str, set[str]] = {}
        self._handle_invocations: dict[str, str] = {}
        self._source_producer_resolved: set[str] = set()
        self._capsule_bytes = 0
        self._capsule_slots_reserved = 0
        self._capsule_bytes_reserved = 0
        self._receipt_slots_reserved = 0
        self._proof_token = object()
        self._proofs_pending: dict[str, int] = {}
        self._lock = threading.RLock()
        self._closed = False

    def record_observed_event(self, observer_enrollment_id: str, *, payload_bytes: bytes,
                              parent_context: HostContext, peer_pid: int, peer_pidfd: int,
                              parent_receipt_handles: Sequence[str] = ()) -> str:
        """Capture exact bytes already observed by a selected root ingress/result adapter.

        The adapter selects the observer ID from protected dispatch state. This
        method fixes every source label from that record and binds the capture
        to the currently live PIDFD identity. It always produces private source
        evidence; it has no public-clearance input.
        """
        if not isinstance(observer_enrollment_id, str):
            raise AuthorityDenied("source.observer", "source observer is not enrolled")
        observer = self.observers.get(observer_enrollment_id)
        if observer is None:
            raise AuthorityDenied("source.observer", "source observer is not enrolled")
        if self._closed:
            raise AuthorityDenied("source.closed", "root source observer is shutting down")
        if (not isinstance(payload_bytes, bytes) or not 1 <= len(payload_bytes) <= observer.max_event_bytes
                or not isinstance(parent_context, HostContext)
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not isinstance(parent_receipt_handles, (tuple, list))
                or len(parent_receipt_handles) > MAX_PARENT_RECEIPTS
                or any(not isinstance(item, str) or not item for item in parent_receipt_handles)
                or len(set(parent_receipt_handles)) != len(parent_receipt_handles)):
            raise AuthorityDenied("source.observation", "observed source input is malformed or outside its bound")
        now = self.service.monotonic()
        if (observer.source_kind == "native-input"
                and parent_context.final_payload_digest != canonical_digest(payload_bytes)):
            raise AuthorityDenied("source.payload", "native input does not match its signed root invocation context")
        if (parent_context.uid != observer.producer_uid
                or parent_context.profile_id != observer.profile_id
                or parent_context.principal_id != observer.principal_id
                or parent_context.namespace_id != observer.namespace_id
                or parent_context.enrollment_id != observer.enrollment_id
                or parent_context.generation != observer.generation
                or parent_context.monotonic_expires_at <= now
                or parent_context.native_process_identity != self.service._native_process_identity(peer_pid, observer.producer_uid)):
            raise AuthorityDenied("source.peer", "source context does not match the selected live producer enrollment")
        binding = self.service._binding(observer.producer_uid)
        self.service._verify_context_signature(parent_context)
        self.service._assert_current_context(parent_context, binding, observer.producer_uid)
        identity = self._resolve(observer, peer_pid, peer_pidfd)
        package, adapter = self._resolve_package_role(observer)
        if not callable(self.loaded_package_proof_resolver):
            raise AuthorityDenied("source.package", "root loaded-package custody proof is unavailable")
        loaded_package_proof = self._resolve_loaded_package_proof(
            identity, observer, package, now, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        if not callable(self.target_peer_resolver):
            raise AuthorityDenied("source.target", "root-selected target peer channel is unavailable")
        selected_target = self.target_peer_resolver(observer, parent_context)
        target_owned_fd = getattr(selected_target, "pidfd", None)
        pinned_target_fd = -1
        try:
            if (selected_target is None or type(getattr(selected_target, "pid", None)) is not int
                    or type(target_owned_fd) is not int or target_owned_fd < 0
                    or type(getattr(selected_target, "uid", None)) is not int
                    or not isinstance(getattr(selected_target, "profile_id", None), str)
                    or not isinstance(getattr(selected_target, "generation", None), str)):
                raise AuthorityDenied("source.target", "root-selected target peer binding is malformed")
            selected_target_identity = self.process_resolver(
                selected_target.pid, target_owned_fd,
                profile_id=selected_target.profile_id, generation=selected_target.generation)
            if (selected_target_identity is None or selected_target_identity != selected_target.identity
                    or selected_target_identity.kernel_uid != selected_target.uid):
                raise AuthorityDenied("source.target", "selected target role is not a live enrolled peer")
            parents = self._resolve_parent_closure(
                observer, parent_receipt_handles, parent_context, binding, peer_pid, identity)
            # The resolver transfers an owned PIDFD. Copy it into the event and
            # close the transferred descriptor on both success and failure.
            pinned_target_fd = os.dup(target_owned_fd)
        finally:
            if type(target_owned_fd) is int and target_owned_fd >= 0:
                os.close(target_owned_fd)
        pinned_fd = -1
        try:
            pinned_fd = os.dup(peer_pidfd)
            event_id = secrets.token_urlsafe(32)
            # The signed parent context is root-created for this actual operation;
            # caller-provided trace or intent text is not invocation identity.
            invocation_id = parent_context.grant_id
            digest = hashlib.sha256(payload_bytes).hexdigest()
            entry = _PendingObservation(
                observer, event_id, invocation_id, bytes(payload_bytes), digest,
                parent_context, parents, tuple(parent_receipt_handles), peer_pid, pinned_fd,
                identity, package, adapter, loaded_package_proof,
                selected_target.pid, pinned_target_fd,
                selected_target.uid, selected_target.profile_id, selected_target.generation,
                selected_target_identity, self.service.authority_epoch, now,
                min(parent_context.monotonic_expires_at, now + observer.lease_seconds),
            )
            with self._lock:
                if self._closed:
                    raise AuthorityDenied("source.closed", "root source observer is shutting down")
                self._prune_locked(now)
                self._prune_receipt_bindings_locked(now)
                if len(self._event_ids_issued) >= MAX_EVENT_IDS_PER_EPOCH:
                    raise AuthorityDenied("source.capacity", "root source event epoch reached its unique-ID bound")
                while event_id in self._event_ids_issued:
                    event_id = secrets.token_urlsafe(32)
                    entry.event_record_id = event_id
                if (len(self._pending) >= self.max_pending_events
                        or self._pending_bytes + len(entry.payload) > self.max_pending_bytes):
                    raise AuthorityDenied("source.capacity", "root source observation queue is full")
                self._pending[event_id] = entry
                self._event_ids_issued.add(event_id)
                self._pending_bytes += len(entry.payload)
                pinned_fd = -1
                pinned_target_fd = -1
        finally:
            if pinned_fd >= 0:
                os.close(pinned_fd)
            if pinned_target_fd >= 0:
                os.close(pinned_target_fd)
        return event_id

    def capture_observed_source(self, observer_enrollment_id: str, event_record_id: str,
                                payload_bytes: bytes,
                                parent_receipt_handles: Sequence[str] = ()) -> SourceReceiptHandle:
        """Consume one root-observed event and ask AuthorityService to issue its handle."""
        if (not isinstance(observer_enrollment_id, str)
                or not isinstance(event_record_id, str) or not 32 <= len(event_record_id) <= 128):
            raise AuthorityDenied("source.event", "root event record is invalid")
        if self._closed:
            raise AuthorityDenied("source.closed", "root source observer is shutting down")
        with self._lock:
            event = self._pending.pop(event_record_id, None)
            if event is not None:
                self._pending_bytes -= len(event.payload)
        if event is None:
            raise AuthorityDenied("source.event", "root event is unknown, expired, or already consumed")
        reserved_receipt_slot = False
        proof_registered = False
        proof: VerifiedSourceObservation | None = None
        try:
            observer = self.observers.get(observer_enrollment_id)
            now = self.service.monotonic()
            if (not isinstance(parent_receipt_handles, (tuple, list))
                    or len(parent_receipt_handles) > MAX_PARENT_RECEIPTS
                    or any(not isinstance(item, str) or not item for item in parent_receipt_handles)
                    or len(set(parent_receipt_handles)) != len(parent_receipt_handles)):
                raise AuthorityDenied("source.lineage", "parent receipt handles are malformed")
            provided_handles = tuple(parent_receipt_handles)
            if (observer is None or observer != event.observer
                    or event.authority_epoch != self.service.authority_epoch
                    or now >= event.expires or not isinstance(payload_bytes, bytes)
                    or not hmac.compare_digest(hashlib.sha256(payload_bytes).hexdigest(), event.payload_sha256)
                    or payload_bytes != event.payload or provided_handles != event.parent_handles):
                raise AuthorityDenied("source.event", "root event binding, payload, parent closure, or lease changed")
            identity = self._resolve(observer, event.producer_pid, event.producer_pidfd)
            if identity != event.producer_identity:
                raise AuthorityDenied("source.peer", "source producer identity or generation changed")
            package, adapter = self._resolve_package_role(observer)
            if package != event.selected_package or adapter != event.selected_adapter:
                raise AuthorityDenied("source.package", "selected immutable package or adapter binding changed")
            current_loaded_proof = self._resolve_loaded_package_proof(
                identity, observer, package, now,
                peer_pid=event.producer_pid, peer_pidfd=event.producer_pidfd)
            if current_loaded_proof != event.loaded_package_proof:
                raise AuthorityDenied("source.package", "loaded package mount proof changed after event capture")
            target_identity = self.process_resolver(
                event.target_peer_pid, event.target_peer_pidfd,
                profile_id=event.target_peer_profile_id,
                generation=event.target_peer_generation)
            if (target_identity is None or target_identity != event.target_peer_identity
                    or target_identity.kernel_uid != event.target_peer_uid):
                raise AuthorityDenied("source.target", "receipt target process changed after event selection")
            self.service._verify_context_signature(event.parent_context)
            self.service._assert_current_context(
                event.parent_context, self.service._binding(observer.producer_uid), observer.producer_uid)
            with self._lock:
                if self._closed:
                    raise AuthorityDenied("source.closed", "root source observer is shutting down")
                self._prune_receipt_bindings_locked(now)
                if (len(self._receipt_process_bindings) + self._receipt_slots_reserved >= 4096
                        or len(self._receipt_delivery_bindings) + self._receipt_slots_reserved >= 4096):
                    raise AuthorityDenied("source.capacity", "root source receipt identity table is full")
                if (len(self._payload_capsules) + self._capsule_slots_reserved >= MAX_RETAINED_CAPSULES
                        or self._capsule_bytes + self._capsule_bytes_reserved + len(event.payload)
                        > MAX_RETAINED_CAPSULE_BYTES):
                    raise AuthorityDenied("source.capacity", "root source payload capsule store is full")
                self._receipt_slots_reserved += 1
                self._capsule_slots_reserved += 1
                self._capsule_bytes_reserved += len(event.payload)
                reserved_receipt_slot = True
            proof = VerifiedSourceObservation(
                observer_enrollment_id=observer.observer_enrollment_id,
                event_record_id=event.event_record_id,
                source_kind=observer.source_kind,
                # Keep the event identity in the signed receipt. The authority
                # now preserves this root-derived origin verbatim rather than
                # appending a second event suffix.
                origin_id=f"{observer.origin_id}:{event.event_record_id}",
                payload_bytes=event.payload,
                payload_sha256=event.payload_sha256,
                parent_context=event.parent_context,
                parent_receipts=event.parent_receipts,
                parent_receipt_handles=event.parent_handles,
                profile_id=observer.profile_id,
                principal_id=observer.principal_id,
                namespace_id=observer.namespace_id,
                enrollment_id=observer.enrollment_id,
                generation=observer.generation,
                producer_uid=observer.producer_uid,
                producer_pid=event.producer_pid,
                producer_pidfd=event.producer_pidfd,
                producer_identity=identity,
                target_peer_uid=event.target_peer_uid,
                target_peer_pid=event.target_peer_pid,
                target_peer_pidfd=event.target_peer_pidfd,
                target_peer_profile_id=event.target_peer_profile_id,
                target_peer_generation=event.target_peer_generation,
                target_peer_identity=target_identity,
                loaded_package_proof=event.loaded_package_proof,
                package_id=observer.package_id,
                package_sha256=observer.package_sha256,
                source_revision=package.source_revision,
                source_tree_sha256=package.source_tree_sha256,
                compiled_closure_artifact_id=package.compiled_closure_artifact_id,
                entrypoint_artifact_id=package.entrypoint_artifact_id,
                entrypoint_sha256=package.entrypoint_sha256,
                resolver_artifact_id=package.resolver_artifact_id,
                resolver_sha256=package.resolver_sha256,
                service_package_root_id=package.service_package_root_id,
                service_mount_id=package.service_mount_id,
                role_id=observer.role_id,
                observer_role_artifact_id=observer.role_artifact_id,
                role_sha256=observer.role_sha256,
                source_action_id=observer.source_action_id,
                action_id=adapter.action_id,
                argument_schema_id=adapter.argument_schema_id,
                result_schema_id=adapter.result_schema_id,
                effect_enrollment_id=adapter.effect_enrollment_id,
                operation=adapter.operation,
                capability=adapter.capability,
                invocation_id=event.invocation_id,
                channel_id=observer.channel_id,
                target_id=observer.target_id,
                recipient=observer.recipient,
                authority_epoch=event.authority_epoch,
                issued_monotonic=event.issued,
                expires_monotonic=event.expires,
                proof_nonce=secrets.token_urlsafe(32),
                _issuer_token=self._proof_token,
            )
            with self._lock:
                if proof.proof_nonce in self._proofs_pending:
                    raise AuthorityDenied("source.observation", "root observation proof nonce collided")
                self._proofs_pending[proof.proof_nonce] = id(proof)
                proof_registered = True
            result = self.service.issue_observed_source(proof)
            if not isinstance(result, SourceReceiptHandle):
                raise AuthorityDenied("source.issuer", "root authority did not return an opaque receipt handle")
            with self.service._lock:
                receipt = self.service._source_receipt_handles.get(result)
            if not isinstance(receipt, SourceReceipt):
                raise AuthorityDenied("source.issuer", "root authority did not retain the signed receipt")
            expected_origin = f"{observer.origin_id}:{event.event_record_id}"
            if (receipt.issuer_id != "host-authority"
                    or receipt.source_kind != observer.source_kind
                    or receipt.origin_id != expected_origin
                    or receipt.payload_digest != event.payload_sha256
                    or receipt.sensitivity is not Sensitivity.PRIVATE
                    or receipt.profile_id != observer.profile_id
                    or receipt.principal_id != observer.principal_id
                    or receipt.namespace_id != observer.namespace_id
                    or receipt.uid != observer.producer_uid
                    or receipt.enrollment_id != observer.enrollment_id
                    or receipt.process_generation != observer.generation
                    or receipt.native_process_identity != self.service._native_process_identity(
                        event.producer_pid, observer.producer_uid)
                    or set(receipt.parent_receipt_ids) != {item.receipt_id for item in event.parent_receipts}
                    or receipt.parent_lineage_hash != event.parent_context.lineage_hash
                    or receipt.policy_revision != self.service._policy_revision()
                    or receipt.issued_at_monotonic < event.issued
                    or receipt.monotonic_expires_at > event.expires
                    or receipt.monotonic_expires_at <= now):
                raise AuthorityDenied("source.issuer", "root receipt does not match the verified observation")
            parent_ids = tuple(sorted(item.receipt_id for item in event.parent_receipts))
            capsule = RootSourcePayloadCapsule(
                receipt_id=receipt.receipt_id,
                observer_enrollment_id=observer.observer_enrollment_id,
                event_record_id=event.event_record_id,
                invocation_id=event.invocation_id,
                source_kind=observer.source_kind,
                channel_id=observer.channel_id,
                capture_schema_id=observer.capture_schema_id,
                source_action_id=observer.source_action_id,
                profile_id=observer.profile_id,
                principal_id=observer.principal_id,
                namespace_id=observer.namespace_id,
                generation=observer.generation,
                payload_bytes=bytes(event.payload),
                payload_sha256=event.payload_sha256,
                parent_receipt_ids=parent_ids,
                parent_closure_digest=canonical_digest(parent_ids),
                issued_monotonic=event.issued,
                expires_monotonic=min(event.expires, receipt.monotonic_expires_at),
            )
            receipt_fd = os.dup(event.producer_pidfd)
            delivery_fd = os.dup(event.target_peer_pidfd)
            binding = _ReceiptProcessBinding(
                receipt.receipt_id, str(result), event.producer_pid, receipt_fd,
                identity, observer.profile_id, observer.generation,
                observer.producer_uid, receipt.monotonic_expires_at,
                authority_epoch=event.authority_epoch,
                observer_enrollment_id=observer.observer_enrollment_id,
                source_action_id=observer.source_action_id,
                channel_id=observer.channel_id,
                loaded_package_proof=event.loaded_package_proof)
            delivery_binding = _ReceiptProcessBinding(
                receipt.receipt_id, str(result), event.target_peer_pid, delivery_fd,
                target_identity, event.target_peer_profile_id, event.target_peer_generation,
                event.target_peer_uid, receipt.monotonic_expires_at,
                authority_epoch=event.authority_epoch)
            try:
                with self._lock:
                    if self._closed:
                        raise AuthorityDenied("source.closed", "root source observer is shutting down")
                    self._receipt_process_bindings[receipt.receipt_id] = binding
                    self._receipt_delivery_bindings[str(result)] = delivery_binding
                    self._payload_capsules[str(result)] = (
                        receipt, capsule, bytearray(event.payload), event.authority_epoch)
                    self._invocation_receipt_handles.setdefault(event.invocation_id, set()).add(str(result))
                    self._handle_invocations[str(result)] = event.invocation_id
                    self._capsule_bytes += len(event.payload)
                    receipt_fd = -1
                    delivery_fd = -1
            finally:
                if receipt_fd >= 0:
                    os.close(receipt_fd)
                if delivery_fd >= 0:
                    os.close(delivery_fd)
            return result
        except BaseException:
            # A failed authority call must never make the event proof reusable.
            if proof_registered and proof is not None:
                with self._lock:
                    self._proofs_pending.pop(proof.proof_nonce, None)
            raise
        finally:
            if reserved_receipt_slot:
                with self._lock:
                    self._receipt_slots_reserved -= 1
                    self._capsule_slots_reserved -= 1
                    self._capsule_bytes_reserved -= len(event.payload)
            os.close(event.producer_pidfd)
            os.close(event.target_peer_pidfd)

    def take_source_receipt(self, handle: str, *, peer_uid: int, peer_pid: int,
                            peer_pidfd: int) -> SourceReceiptHandle:
        """Deliver one already-issued opaque handle to its enrolled live peer.

        This is the source-observer half of the root-created authenticated
        delivery channel. It never mints or returns signed receipt claims. The
        authority RPC supplies SO_PEERCRED UID/PID and a kernel PIDFD.
        """
        if (not isinstance(handle, str) or not 32 <= len(handle) <= 128
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("source.delivery", "receipt delivery request is malformed")
        with self._lock:
            binding = self._receipt_delivery_bindings.get(handle)
            if binding is None or binding.delivered:
                raise AuthorityDenied("source.delivery", "receipt handle is unbound, expired, or already delivered")
            if peer_uid != binding.uid or peer_pid != binding.pid:
                raise AuthorityDenied("source.delivery", "receipt handle belongs to another kernel peer")
            if self.service.monotonic() >= binding.expires:
                self._receipt_delivery_bindings.pop(handle, None)
                os.close(binding.pidfd)
                raise AuthorityDenied("source.delivery", "receipt delivery lease expired")
            live = self.process_resolver(peer_pid, peer_pidfd,
                                         profile_id=binding.profile_id,
                                         generation=binding.generation)
            retained = self.process_resolver(binding.pid, binding.pidfd,
                                             profile_id=binding.profile_id,
                                             generation=binding.generation)
            if (live is None or retained is None or live != binding.identity
                    or retained != binding.identity or live.kernel_uid != peer_uid):
                raise AuthorityDenied("source.delivery", "receipt target PIDFD identity changed")
            binding.delivered = True
            return SourceReceiptHandle(handle)

    def capture_observed_ingress(self, observer_enrollment_id: str, *,
                                 payload_bytes: bytes, parent_context: HostContext,
                                 peer_pid: int, peer_pidfd: int,
                                 parent_receipt_handles: Sequence[str] = ()) -> SourceReceiptHandle:
        """Atomically register and capture bytes from a root-selected ingress.

        The generated event ID never crosses this in-process call boundary.
        The caller must itself be a fixed root ingress adapter that selected
        the protected observer row and verified its live peer/context.
        """
        event_id = self.record_observed_event(
            observer_enrollment_id, payload_bytes=payload_bytes,
            parent_context=parent_context, peer_pid=peer_pid,
            peer_pidfd=peer_pidfd,
            parent_receipt_handles=parent_receipt_handles,
        )
        return self.capture_observed_source(
            observer_enrollment_id, event_id, payload_bytes,
            parent_receipt_handles,
        )

    def resolve_live_source_producer(self, receipt_id: str, *, profile_id: str,
                                     generation: str, native_process_identity: str,
                                     expires_monotonic: float) -> LiveSourceProducer:
        """Resolve one receipt to bounded live producer evidence for a root handler.

        This is an in-process root API. It returns at most one duplicated PIDFD
        per receipt; the caller owns and must close that descriptor.
        """
        if (not isinstance(receipt_id, str) or not receipt_id
                or not isinstance(profile_id, str) or not profile_id
                or not isinstance(generation, str) or not generation
                or not isinstance(native_process_identity, str) or not native_process_identity
                or type(expires_monotonic) not in (int, float)
                or not math.isfinite(expires_monotonic)):
            raise AuthorityDenied("source.producer", "source producer resolution request is malformed")
        with self._lock:
            if self._closed:
                raise AuthorityDenied("source.closed", "root source observer is shutting down")
            if receipt_id in self._source_producer_resolved:
                raise AuthorityDenied("source.producer", "source producer evidence was already resolved")
            binding = self._receipt_process_bindings.get(receipt_id)
            now = self.service.monotonic()
            if (binding is None or binding.authority_epoch != self.service.authority_epoch
                    or binding.expires <= now or expires_monotonic != binding.expires
                    or profile_id != binding.profile_id or generation != binding.generation
                    or native_process_identity != self.service._native_process_identity(binding.pid, binding.uid)):
                raise AuthorityDenied("source.producer", "source receipt producer binding is stale or mismatched")
            with self.service._lock:
                receipt = self.service._source_receipt_handles.get(binding.handle)
            if (receipt is None or receipt.receipt_id != receipt_id
                    or receipt.profile_id != profile_id or receipt.process_generation != generation
                    or receipt.native_process_identity != native_process_identity
                    or receipt.monotonic_expires_at != expires_monotonic
                    or receipt.uid != binding.uid):
                raise AuthorityDenied("source.producer", "signed source receipt does not match its producer binding")
            self.service._verify_source_receipt(receipt, self.service._binding(receipt.uid))
            live = self.process_resolver(binding.pid, binding.pidfd,
                                         profile_id=profile_id, generation=generation)
            if (live is None or live != binding.identity
                    or live.profile_id != profile_id or live.generation != generation
                    or live.kernel_uid != binding.uid):
                raise AuthorityDenied("source.producer", "source producer PIDFD identity is no longer current")
            observer = self.observers.get(binding.observer_enrollment_id)
            if (observer is None or observer.source_action_id != binding.source_action_id
                    or observer.channel_id != binding.channel_id):
                raise AuthorityDenied("source.producer", "source producer action enrollment is no longer selected")
            package, _adapter = self._resolve_package_role(observer)
            current_proof = self._resolve_loaded_package_proof(
                live, observer, package, now, peer_pid=binding.pid, peer_pidfd=binding.pidfd)
            if current_proof != binding.loaded_package_proof:
                raise AuthorityDenied("source.producer", "source producer loaded closure or action changed")
            try:
                duplicate = os.dup(binding.pidfd)
            except OSError:
                raise AuthorityDenied("source.producer", "source producer PIDFD could not be retained") from None
            self._source_producer_resolved.add(receipt_id)
            return LiveSourceProducer(
                receipt_id=receipt_id, pid=binding.pid, pidfd=duplicate,
                identity=live, uid=binding.uid, profile_id=profile_id,
                generation=generation, expires_monotonic=binding.expires,
                authority_epoch=binding.authority_epoch,
                observer_enrollment_id=observer.observer_enrollment_id,
                source_action_id=observer.source_action_id,
                channel_id=observer.channel_id,
                loaded_package_proof=current_proof,
            )

    def lookup_source_handle(self, receipt_id: str, *, signed_context: HostContext,
                             peer_uid: int, peer_pid: int,
                             peer_pidfd: int) -> SourceReceiptHandle:
        """Resolve a signed receipt ID to its opaque handle for a root handler.

        The receipt ID comes from a root-verified signed context; the worker
        cannot nominate a handle. This method is deliberately in-process only.
        """
        if (not isinstance(receipt_id, str) or not isinstance(signed_context, HostContext)
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not any(item.receipt_id == receipt_id for item in signed_context.source_receipts)):
            raise AuthorityDenied("source.capsule", "signed source receipt lookup is malformed or unbound")
        with self._lock:
            if self._closed:
                raise AuthorityDenied("source.closed", "root source observer is shutting down")
            found = next(((handle, row) for handle, row in self._payload_capsules.items()
                          if row[0].receipt_id == receipt_id), None)
            if found is None:
                raise AuthorityDenied("source.capsule", "source payload capsule is unavailable")
            handle, (receipt, capsule, _payload, epoch) = found
            target = self._receipt_delivery_bindings.get(handle)
            now = self.service.monotonic()
            if (epoch != self.service.authority_epoch or capsule.expires_monotonic <= now
                    or target is None or target.expires <= now or target.uid != peer_uid
                    or target.pid != peer_pid or signed_context.uid != peer_uid
                    or signed_context.profile_id != target.profile_id
                    or signed_context.generation != target.generation):
                raise AuthorityDenied("source.capsule", "source capsule target, generation, or lease changed")
            self.service._verify_context_signature(signed_context)
            self.service._assert_current_context(
                signed_context, self.service._binding(peer_uid), peer_uid)
            live = self.process_resolver(peer_pid, peer_pidfd,
                                         profile_id=target.profile_id,
                                         generation=target.generation)
            retained = self.process_resolver(target.pid, target.pidfd,
                                             profile_id=target.profile_id,
                                             generation=target.generation)
            if (live is None or retained is None or live != target.identity
                    or retained != target.identity or live.kernel_uid != peer_uid
                    or receipt != next(item for item in signed_context.source_receipts
                                       if item.receipt_id == receipt_id)):
                raise AuthorityDenied("source.capsule", "signed receipt or live consumer peer does not match")
            return SourceReceiptHandle(handle)

    def consume_source_payload_capsule(self, handle: SourceReceiptHandle, *,
                                      signed_context: HostContext, peer_uid: int,
                                      peer_pid: int, peer_pidfd: int) -> RootSourcePayloadCapsule:
        """Consume retained exact event bytes once inside an authorized root job handler.

        Callers should first obtain ``handle`` via ``lookup_source_handle``.
        This accessor is not exposed by AuthorityClient or any worker RPC.
        Failure consumes and scrubs the capsule as a fail-closed one-use action.
        """
        if not isinstance(handle, SourceReceiptHandle) or not isinstance(signed_context, HostContext):
            raise AuthorityDenied("source.capsule", "root capsule lookup key or context is invalid")
        with self._lock:
            row = self._payload_capsules.pop(str(handle), None)
            if row is not None:
                self._capsule_bytes -= len(row[2])
        if row is None:
            raise AuthorityDenied("source.capsule", "source payload capsule is unknown, expired, or consumed")
        receipt, capsule, payload, epoch = row
        try:
            now = self.service.monotonic()
            context_receipts = {item.receipt_id: item for item in signed_context.source_receipts}
            required_ids = {receipt.receipt_id, *capsule.parent_receipt_ids}
            with self._lock:
                target = self._receipt_delivery_bindings.get(str(handle))
            if (epoch != self.service.authority_epoch or capsule.expires_monotonic <= now
                    or not isinstance(peer_uid, int) or isinstance(peer_uid, bool)
                    or not isinstance(peer_pid, int) or isinstance(peer_pid, bool)
                    or not isinstance(peer_pidfd, int) or isinstance(peer_pidfd, bool) or peer_pidfd < 0
                    or target is None or target.expires <= now or peer_uid != target.uid
                    or peer_pid != target.pid or signed_context.uid != peer_uid
                    or signed_context.profile_id != target.profile_id
                    or signed_context.generation != target.generation
                    or not required_ids.issubset(context_receipts)
                    or context_receipts.get(receipt.receipt_id) != receipt
                    or capsule.parent_closure_digest != canonical_digest(capsule.parent_receipt_ids)
                    or hashlib.sha256(payload).hexdigest() != capsule.payload_sha256
                    or capsule.payload_bytes != bytes(payload)):
                raise AuthorityDenied("source.capsule", "source payload capsule binding or closure changed")
            self.service._verify_context_signature(signed_context)
            self.service._assert_current_context(
                signed_context, self.service._binding(peer_uid), peer_uid)
            live = self.process_resolver(peer_pid, peer_pidfd,
                                         profile_id=target.profile_id,
                                         generation=target.generation)
            retained = self.process_resolver(target.pid, target.pidfd,
                                             profile_id=target.profile_id,
                                             generation=target.generation)
            if (live is None or retained is None or live != target.identity
                    or retained != target.identity or live.kernel_uid != peer_uid):
                raise AuthorityDenied("source.capsule", "capsule consumer PIDFD or process generation changed")
            return capsule
        finally:
            payload[:] = b"\x00" * len(payload)

    def cancel_source_payload_capsule(self, handle: SourceReceiptHandle) -> bool:
        """Revoke a not-yet-consumed receipt handle and scrub its payload."""
        if not isinstance(handle, SourceReceiptHandle):
            raise AuthorityDenied("source.capsule", "root capsule cancellation key is invalid")
        with self._lock:
            return self._revoke_source_handle_locked(str(handle))

    def cancel_invocation_payload_capsules(self, invocation_id: str) -> int:
        """Scrub every retained payload from a cancelled root invocation."""
        if not isinstance(invocation_id, str) or not invocation_id:
            raise AuthorityDenied("source.capsule", "root invocation cancellation ID is invalid")
        with self._lock:
            handles = self._invocation_receipt_handles.pop(invocation_id, set())
            for handle in handles:
                self._revoke_source_handle_locked(handle)
            return len(handles)

    def _revoke_source_handle_locked(self, handle: str) -> bool:
        """Remove authority lookup and peer-delivery state for one receipt."""
        self._forget_invocation_handle_locked(handle)
        row = self._payload_capsules.pop(handle, None)
        if row is not None:
            self._capsule_bytes -= len(row[2])
            row[2][:] = b"\x00" * len(row[2])
            receipt_id = row[0].receipt_id
        else:
            delivery = self._receipt_delivery_bindings.get(handle)
            receipt_id = delivery.receipt_id if delivery is not None else None
        if receipt_id is None:
            return False
        self._source_producer_resolved.discard(receipt_id)
        delivery = self._receipt_delivery_bindings.pop(handle, None)
        if delivery is not None:
            os.close(delivery.pidfd)
        process = self._receipt_process_bindings.pop(receipt_id, None)
        if process is not None:
            os.close(process.pidfd)
        with self.service._lock:
            stored = self.service._source_receipt_handles.pop(handle, None)
        return row is not None or delivery is not None or process is not None or stored is not None

    def _forget_invocation_handle_locked(self, handle: str) -> None:
        invocation_id = self._handle_invocations.pop(handle, None)
        if invocation_id is None:
            return
        handles = self._invocation_receipt_handles.get(invocation_id)
        if handles is not None:
            handles.discard(handle)
            if not handles:
                self._invocation_receipt_handles.pop(invocation_id, None)

    def consume_observation_proof(self, observation: VerifiedSourceObservation) -> bool:
        """Consume a one-use instance capability before AuthorityService signs.

        AuthorityService receives this registry as a root-only injected
        dependency. Merely importing or constructing the DTO is insufficient:
        the exact object and nonce must have been emitted by this live registry
        for its pending event.
        """
        if not isinstance(observation, VerifiedSourceObservation):
            raise AuthorityDenied("source.observation", "observation proof is not registry-issued")
        with self._lock:
            expected_identity = self._proofs_pending.pop(observation.proof_nonce, None)
        if (observation._issuer_token is not self._proof_token
                or expected_identity != id(observation)):
            raise AuthorityDenied("source.observation", "observation proof is forged, stale, or already consumed")
        return True

    def _resolve_parent_closure(self, observer: SourceObserverEnrollment,
                                handles: Sequence[str], context: HostContext,
                                binding: Any, peer_pid: int,
                                producer_identity: Any) -> tuple[SourceReceipt, ...]:
        with self.service._lock:
            now = self.service.monotonic()
            self.service._source_receipt_handles = {
                key: value for key, value in self.service._source_receipt_handles.items()
                if value.monotonic_expires_at > now
            }
            by_id = {receipt.receipt_id: receipt
                     for receipt in self.service._source_receipt_handles.values()}
            selected: dict[str, SourceReceipt] = {}
            for handle in handles:
                receipt = self.service._source_receipt_handles.get(handle)
                if receipt is None:
                    raise AuthorityDenied("source.lineage", "parent source handle is unknown or expired")
                selected[receipt.receipt_id] = receipt
            pending = list(selected.values())
            while pending:
                receipt = pending.pop()
                for parent_id in receipt.parent_receipt_ids:
                    parent = by_id.get(parent_id)
                    if parent is None:
                        raise AuthorityDenied("source.lineage", "parent source receipt closure is incomplete")
                    if parent_id not in selected:
                        selected[parent_id] = parent
                        pending.append(parent)
        receipts = tuple(selected.values())
        if len(receipts) > MAX_PARENT_RECEIPTS:
            raise AuthorityDenied("source.lineage", "parent source receipt closure exceeds its bound")
        context_ids = {item.receipt_id for item in context.source_receipts}
        if context_ids != set(selected):
            raise AuthorityDenied("source.lineage", "signed parent context does not carry the complete selected closure")
        current_identity = self.service._native_process_identity(peer_pid, observer.producer_uid)
        with self._lock:
            process_bindings = {receipt.receipt_id: self._receipt_process_bindings.get(receipt.receipt_id)
                                for receipt in receipts}
        for receipt in receipts:
            receipt_binding = process_bindings[receipt.receipt_id]
            live_parent_identity = (None if receipt_binding is None else self._resolve(
                observer, receipt_binding.pid, receipt_binding.pidfd))
            if (receipt.source_kind not in observer.allowed_parent_source_kinds
                    or receipt.profile_id != observer.profile_id
                    or receipt.principal_id != observer.principal_id
                    or receipt.native_process_identity != current_identity
                    or receipt_binding is None
                    or receipt_binding.identity != producer_identity
                    or receipt_binding.pid != peer_pid
                    or live_parent_identity != producer_identity
                    or receipt_binding.expires <= self.service.monotonic()):
                raise AuthorityDenied("source.lineage", "parent source is outside the selected role or source policy")
            self.service._verify_source_receipt(receipt, binding)
        return receipts

    def _resolve(self, observer: SourceObserverEnrollment, peer_pid: int, peer_pidfd: int) -> Any:
        identity = self.process_resolver(peer_pid, peer_pidfd,
                                         profile_id=observer.profile_id,
                                         generation=observer.generation)
        if (identity is None or identity.profile_id != observer.profile_id
                or identity.generation != observer.generation
                or identity.kernel_uid != observer.producer_uid
                or identity.executable_sha256 != observer.producer_executable_sha256):
            raise AuthorityDenied("source.peer", "source producer is not a live enrolled package role")
        return identity

    def _resolve_package_role(self, observer: SourceObserverEnrollment) -> tuple[Any, Any]:
        """Join the fixed observer row to the currently selected protected package."""
        try:
            package = self.package_resolver(observer.package_id, observer.generation)
        except Exception:
            raise AuthorityDenied("source.package", "selected native package is unavailable") from None
        adapter_records = getattr(package, "adapter_records", {}) if package is not None else {}
        adapter = adapter_records.get(observer.role_id)
        role_candidates = []
        if (package is not None
                and getattr(package, "entrypoint_artifact_id", None) == observer.role_artifact_id):
            role_candidates.append(getattr(package, "entrypoint_sha256", None))
        if package is not None:
            role_candidates.extend(
                getattr(item, "adapter_sha256", None)
                for item in adapter_records.values()
                if getattr(item, "adapter_artifact_id", None) == observer.role_artifact_id
            )
        if (package is None
                or getattr(package, "package_id", None) != observer.package_id
                or getattr(package, "profile_id", None) != observer.profile_id
                or getattr(package, "generation", None) != observer.generation
                or getattr(package, "compiled_closure_sha256", None) != observer.package_sha256
                or len(role_candidates) != 1 or role_candidates[0] != observer.role_sha256
                or adapter is None
                or getattr(adapter, "adapter_id", None) != observer.role_id
                or getattr(adapter, "target_id", None) != observer.target_id
                or getattr(adapter, "recipient", None) != observer.recipient
                or getattr(adapter, "generation", None) != observer.generation):
            raise AuthorityDenied("source.package", "selected package role or protected route binding is incomplete")
        package_fields = (
            "source_revision", "source_tree_sha256", "compiled_closure_artifact_id",
            "entrypoint_artifact_id", "entrypoint_sha256", "resolver_artifact_id",
            "resolver_sha256", "service_package_root_id", "service_mount_id",
        )
        adapter_fields = (
            "action_id", "argument_schema_id", "result_schema_id", "effect_enrollment_id",
            "operation", "capability",
        )
        if (any(not isinstance(getattr(package, name, None), str) or not getattr(package, name)
                for name in package_fields)
                or any(not isinstance(getattr(adapter, name, None), str) or not getattr(adapter, name)
                       for name in adapter_fields)
                or any(len(getattr(package, name)) != 64
                       or any(char not in "0123456789abcdef" for char in getattr(package, name))
                       for name in ("source_tree_sha256", "entrypoint_sha256", "resolver_sha256"))):
            raise AuthorityDenied("source.package", "selected package closure or adapter record is incomplete")
        return package, adapter

    def _resolve_loaded_package_proof(self, identity: Any,
                                      observer: SourceObserverEnrollment,
                                      package: Any, now: float, *,
                                      peer_pid: int, peer_pidfd: int) -> Any:
        if not callable(self.loaded_package_proof_resolver):
            raise AuthorityDenied("source.package", "root loaded-package custody proof is unavailable")
        try:
            if (type(peer_pid) is not int or peer_pid <= 0
                    or type(peer_pidfd) is not int or peer_pidfd < 0):
                raise ValueError("producer peer identity is malformed")
            proof = self.loaded_package_proof_resolver(
                identity, observer, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        except Exception:
            proof = None
        required = (
            "proof_id", "package_id", "profile_id", "generation",
            "compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256",
            "mount_namespace_inode", "mount_id", "mount_target_digest", "mount_flags",
            "source_root_device", "source_root_inode", "target_peer_identity",
            "loader_role_artifact_id", "loader_role_sha256", "loader_ready_event_id",
            "observed_entrypoint_action_ids", "issued_monotonic", "expires_monotonic",
            "service_generation_digest",
        )
        if proof is None or any(not hasattr(proof, name) for name in required):
            raise AuthorityDenied("source.package", "root loaded-package proof is incomplete")
        flags = getattr(proof, "mount_flags")
        actions = getattr(proof, "observed_entrypoint_action_ids")
        digest_fields = (
            "compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256",
            "mount_target_digest", "service_generation_digest",
        )
        if (not isinstance(proof.proof_id, str) or not proof.proof_id
                or proof.package_id != package.package_id
                or proof.profile_id != observer.profile_id
                or proof.generation != observer.generation
                or proof.compiled_closure_sha256 != package.compiled_closure_sha256
                or proof.entrypoint_sha256 != package.entrypoint_sha256
                or proof.resolver_sha256 != package.resolver_sha256
                or proof.target_peer_identity != identity
                or proof.loader_role_artifact_id != observer.role_artifact_id
                or proof.loader_role_sha256 != observer.role_sha256
                or not isinstance(proof.loader_ready_event_id, str)
                or not 1 <= len(proof.loader_ready_event_id) <= 128
                or not isinstance(actions, (tuple, list, frozenset, set))
                or not 1 <= len(actions) <= 256
                or any(not isinstance(action, str) or not action for action in actions)
                or observer.source_action_id not in actions
                or not isinstance(flags, (tuple, list, frozenset, set))
                or not {"ro", "nosuid", "nodev"}.issubset(flags)
                or "rw" in flags
                or type(proof.mount_namespace_inode) is not int or proof.mount_namespace_inode <= 0
                or not isinstance(proof.mount_id, (str, int))
                or not str(proof.mount_id)
                or type(proof.source_root_device) is not int or proof.source_root_device < 0
                or type(proof.source_root_inode) is not int or proof.source_root_inode <= 0
                or type(proof.issued_monotonic) not in (float, int)
                or type(proof.expires_monotonic) not in (float, int)
                or not math.isfinite(proof.issued_monotonic)
                or not math.isfinite(proof.expires_monotonic)
                or not proof.issued_monotonic <= now < proof.expires_monotonic
                or proof.expires_monotonic - proof.issued_monotonic > MAX_EVENT_LEASE_SECONDS
                or any(not isinstance(getattr(proof, name), str)
                       or len(getattr(proof, name)) != 64
                       or any(char not in "0123456789abcdef" for char in getattr(proof, name))
                       for name in digest_fields)):
            raise AuthorityDenied("source.package", "loaded package proof does not match selected live closure")
        return proof

    def _prune_locked(self, now: float) -> None:
        for event_id, event in tuple(self._pending.items()):
            if event.expires <= now or event.authority_epoch != self.service.authority_epoch:
                self._pending.pop(event_id, None)
                self._pending_bytes -= len(event.payload)
                os.close(event.producer_pidfd)
                os.close(event.target_peer_pidfd)

    def _prune_receipt_bindings_locked(self, now: float) -> None:
        for receipt_id, binding in tuple(self._receipt_process_bindings.items()):
            if binding.expires <= now:
                self._receipt_process_bindings.pop(receipt_id, None)
                os.close(binding.pidfd)
                self._source_producer_resolved.discard(receipt_id)
        for handle, binding in tuple(self._receipt_delivery_bindings.items()):
            if binding.expires <= now:
                self._receipt_delivery_bindings.pop(handle, None)
                os.close(binding.pidfd)
                self._forget_invocation_handle_locked(handle)
        self._prune_capsules_locked(now)

    def _prune_capsules_locked(self, now: float) -> None:
        for handle, (_receipt, capsule, payload, epoch) in tuple(self._payload_capsules.items()):
            if capsule.expires_monotonic <= now or epoch != self.service.authority_epoch:
                self._payload_capsules.pop(handle, None)
                self._capsule_bytes -= len(payload)
                payload[:] = b"\x00" * len(payload)

    def close(self) -> None:
        """Release every retained PIDFD when the root authority shuts down."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for event in self._pending.values():
                os.close(event.producer_pidfd)
                os.close(event.target_peer_pidfd)
            self._pending.clear()
            self._pending_bytes = 0
            self._proofs_pending.clear()
            for binding in self._receipt_process_bindings.values():
                os.close(binding.pidfd)
            self._receipt_process_bindings.clear()
            self._source_producer_resolved.clear()
            for binding in self._receipt_delivery_bindings.values():
                os.close(binding.pidfd)
            self._receipt_delivery_bindings.clear()
            for _receipt, _capsule, payload, _epoch in self._payload_capsules.values():
                payload[:] = b"\x00" * len(payload)
            self._payload_capsules.clear()
            self._invocation_receipt_handles.clear()
            self._handle_invocations.clear()
            self._capsule_bytes = 0
            self._capsule_bytes_reserved = 0
            self._capsule_slots_reserved = 0

    def prune(self) -> None:
        """Release expired event and receipt PIDFDs from the root daemon watchdog."""
        now = self.service.monotonic()
        with self._lock:
            if self._closed:
                return
            self._prune_locked(now)
            self._prune_receipt_bindings_locked(now)


def _identifier(value: Any, name: str) -> None:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(char) < 0x21 or char in "\\\x7f" for char in value)):
        raise ValueError(f"{name} is invalid")
