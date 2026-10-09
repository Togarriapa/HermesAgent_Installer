"""Root-private, one-use source observations for installed Hermes roles.

The registry is constructed from protected enrollment and is called only by
root observer adapters.  It is deliberately not an AuthorityService RPC and
does not accept a worker's source kind, event ID, role, package, channel,
target, recipient, sensitivity, or public-clearance claim.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence

from .types import AuthorityDenied, HostContext, Sensitivity, SourceReceipt, canonical_digest

MAX_OBSERVED_SOURCE_BYTES = 1_048_576
MAX_PARENT_RECEIPTS = 64
MAX_PENDING_EVENTS = 256
MAX_PENDING_BYTES = 8 * 1024 * 1024
MAX_EVENT_IDS_PER_EPOCH = 100_000
MAX_EVENT_LEASE_SECONDS = 600

_ALLOWED_SOURCE_KINDS = frozenset({
    "native-input", "tool-result", "memory-record", "static-context",
    "schedule-event", "webhook-event", "provider-result",
})
_OBSERVATION_ISSUER = object()


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
    package_id: str
    package_sha256: str
    role_id: str
    role_sha256: str
    channel_id: str
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
            "package_sha256", "role_id", "role_sha256", "channel_id", "target_id", "recipient",
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
            "channel_id", "target_id", "recipient",
        ):
            _identifier(getattr(self, name), name)
        for name in ("package_sha256", "role_sha256"):
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

    The private constructor token prevents ordinary application code from
    accidentally constructing an observation.  Workers cannot reach this
    in-process type through the authority socket; the receiving service still
    revalidates every field and the live peer before signing.
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
    package_id: str
    package_sha256: str
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
    _issuer: object

    def __post_init__(self) -> None:
        if self._issuer is not _OBSERVATION_ISSUER:
            raise AuthorityDenied("source.observation", "source observation was not issued by the root observer")
        if (not isinstance(self.payload_bytes, bytes) or not self.payload_bytes
                or hashlib.sha256(self.payload_bytes).hexdigest() != self.payload_sha256
                or not isinstance(self.parent_context, HostContext)
                or not isinstance(self.parent_receipts, tuple)
                or len(self.parent_receipts) > MAX_PARENT_RECEIPTS
                or any(not isinstance(item, SourceReceipt) for item in self.parent_receipts)
                or len(self.parent_receipt_handles) > MAX_PARENT_RECEIPTS
                or not self.authority_epoch
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
    expires: float


class SourceObserverRegistry:
    """Concrete root observer: protected enrollment -> captured event -> receipt handle."""

    def __init__(self, *, service: Any, observers: Mapping[str, SourceObserverEnrollment],
                 process_resolver: Callable[..., Any], package_resolver: Callable[[str, str], Any],
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
        self.max_pending_events = max_pending_events
        self.max_pending_bytes = max_pending_bytes
        self._pending: dict[str, _PendingObservation] = {}
        self._event_ids_issued: set[str] = set()
        self._pending_bytes = 0
        self._receipt_process_bindings: dict[str, _ReceiptProcessBinding] = {}
        self._receipt_slots_reserved = 0
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
        parents = self._resolve_parent_closure(
            observer, parent_receipt_handles, parent_context, binding, peer_pid, identity)
        pinned_fd = os.dup(peer_pidfd)
        event_id = secrets.token_urlsafe(32)
        # The signed parent context is root-created for this actual operation;
        # caller-provided trace or intent text is not invocation identity.
        invocation_id = parent_context.grant_id
        digest = hashlib.sha256(payload_bytes).hexdigest()
        entry = _PendingObservation(
            observer, event_id, invocation_id, bytes(payload_bytes), digest,
            parent_context, parents, tuple(parent_receipt_handles), peer_pid, pinned_fd,
            identity, package, adapter, self.service.authority_epoch, now,
            min(parent_context.monotonic_expires_at, now + observer.lease_seconds),
        )
        try:
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
        finally:
            if pinned_fd >= 0:
                os.close(pinned_fd)
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
            self.service._verify_context_signature(event.parent_context)
            self.service._assert_current_context(
                event.parent_context, self.service._binding(observer.producer_uid), observer.producer_uid)
            with self._lock:
                if self._closed:
                    raise AuthorityDenied("source.closed", "root source observer is shutting down")
                self._prune_receipt_bindings_locked(now)
                if len(self._receipt_process_bindings) + self._receipt_slots_reserved >= 4096:
                    raise AuthorityDenied("source.capacity", "root source receipt identity table is full")
                self._receipt_slots_reserved += 1
                reserved_receipt_slot = True
            proof = VerifiedSourceObservation(
                observer_enrollment_id=observer.observer_enrollment_id,
                event_record_id=event.event_record_id,
                source_kind=observer.source_kind,
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
                role_sha256=observer.role_sha256,
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
                _issuer=_OBSERVATION_ISSUER,
            )
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
            receipt_fd = os.dup(event.producer_pidfd)
            binding = _ReceiptProcessBinding(
                receipt.receipt_id, str(result), event.producer_pid, receipt_fd,
                identity, receipt.monotonic_expires_at)
            try:
                with self._lock:
                    if self._closed:
                        raise AuthorityDenied("source.closed", "root source observer is shutting down")
                    self._receipt_process_bindings[receipt.receipt_id] = binding
                    receipt_fd = -1
            finally:
                if receipt_fd >= 0:
                    os.close(receipt_fd)
            return result
        finally:
            if reserved_receipt_slot:
                with self._lock:
                    self._receipt_slots_reserved -= 1
            os.close(event.producer_pidfd)

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
                or identity.executable_sha256 != observer.role_sha256):
            raise AuthorityDenied("source.peer", "source producer is not a live enrolled package role")
        return identity

    def _resolve_package_role(self, observer: SourceObserverEnrollment) -> tuple[Any, Any]:
        """Join the fixed observer row to the currently selected protected package."""
        try:
            package = self.package_resolver(observer.package_id, observer.generation)
        except Exception:
            raise AuthorityDenied("source.package", "selected native package is unavailable") from None
        adapter = getattr(package, "adapter_records", {}).get(observer.role_id) if package is not None else None
        if (package is None
                or getattr(package, "package_id", None) != observer.package_id
                or getattr(package, "profile_id", None) != observer.profile_id
                or getattr(package, "generation", None) != observer.generation
                or getattr(package, "compiled_closure_sha256", None) != observer.package_sha256
                or adapter is None
                or getattr(adapter, "adapter_id", None) != observer.role_id
                or getattr(adapter, "adapter_sha256", None) != observer.role_sha256
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

    def _prune_locked(self, now: float) -> None:
        for event_id, event in tuple(self._pending.items()):
            if event.expires <= now or event.authority_epoch != self.service.authority_epoch:
                self._pending.pop(event_id, None)
                self._pending_bytes -= len(event.payload)
                os.close(event.producer_pidfd)

    def _prune_receipt_bindings_locked(self, now: float) -> None:
        for receipt_id, binding in tuple(self._receipt_process_bindings.items()):
            if binding.expires <= now:
                self._receipt_process_bindings.pop(receipt_id, None)
                os.close(binding.pidfd)

    def close(self) -> None:
        """Release every retained PIDFD when the root authority shuts down."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for event in self._pending.values():
                os.close(event.producer_pidfd)
            self._pending.clear()
            self._pending_bytes = 0
            for binding in self._receipt_process_bindings.values():
                os.close(binding.pidfd)
            self._receipt_process_bindings.clear()

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
