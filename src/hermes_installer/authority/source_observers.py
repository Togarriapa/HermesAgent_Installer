"""Root-private, one-use source observations for installed Hermes roles.

The registry is constructed from protected enrollment and is called only by
root observer adapters.  It is deliberately not an AuthorityService RPC and
does not accept a worker's source kind, event ID, role, package, channel,
target, recipient, sensitivity, or public-clearance claim.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
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
    native_package_generation: str | None = None
    # Finite provider enrollment IDs from the exact protected SourceIssuerRecord.
    # These are only candidate routes; current consent and route policy are
    # rechecked by the root issuer before any ceiling is minted.
    private_provider_route_ids: tuple[str, ...] = ()

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
        optional = {"max_event_bytes", "lease_seconds", "native_package_generation",
                    "private_provider_route_ids"}
        if (not isinstance(record, Mapping) or set(record) - (required | optional)
                or required - set(record) or not isinstance(record["allowed_parent_source_kinds"], list)
                or len(record["allowed_parent_source_kinds"]) > len(_ALLOWED_SOURCE_KINDS)
                or any(not isinstance(item, str) for item in record["allowed_parent_source_kinds"])
                or len(set(record["allowed_parent_source_kinds"])) != len(record["allowed_parent_source_kinds"])):
            raise AuthorityDenied("source.enrollment", "protected source observer schema is invalid")
        values = dict(record)
        values["allowed_parent_source_kinds"] = frozenset(values["allowed_parent_source_kinds"])
        if "private_provider_route_ids" in values:
            if not isinstance(values["private_provider_route_ids"], (list, tuple)):
                raise AuthorityDenied("source.enrollment", "protected private provider route IDs are invalid")
            values["private_provider_route_ids"] = tuple(values["private_provider_route_ids"])
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
        if (not isinstance(self.private_provider_route_ids, tuple)
                or len(self.private_provider_route_ids) > 64
                or len(set(self.private_provider_route_ids)) != len(self.private_provider_route_ids)
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", item)
                       for item in self.private_provider_route_ids)
                or (self.private_provider_route_ids and self.source_kind != "native-input")):
            raise ValueError("private provider route IDs must be a finite unique protected tuple")
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
        if (self.native_package_generation is not None
                and (not isinstance(self.native_package_generation, str)
                     or not 1 <= len(self.native_package_generation) <= 256
                     or any(ord(char) < 0x21 or char in "\\\x7f"
                             for char in self.native_package_generation))):
            raise ValueError("native package generation is invalid")


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
    # Present only for the selected pre-stdin native input route. This exact
    # object is retained and revalidated by RootNativeExecutionSelectionRegistry.
    selected_execution: Any = field(default=None, repr=False, compare=False)
    private_provider_route_ids: tuple[str, ...] = ()
    private_consent_selection_handle: str | None = None

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
                or not isinstance(self.private_provider_route_ids, tuple)
                or len(self.private_provider_route_ids) > 64
                or len(set(self.private_provider_route_ids)) != len(self.private_provider_route_ids)
                or any(not isinstance(item, str) for item in self.private_provider_route_ids)
                or (self.private_consent_selection_handle is not None
                    and (not isinstance(self.private_consent_selection_handle, str)
                         or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.private_consent_selection_handle)))
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
class RetainedSelectedInputConsent:
    """Root-only join from an issued input receipt to current private consent.

    The consent object remains owned by RootPrivateInputConsentRegistry. This
    DTO carries exact in-process references and immutable identifiers for
    request admission; it is never serialized or returned over worker RPC.
    """

    source_receipt_handle: SourceReceiptHandle
    selection_handle: str
    consent_receipt_handle: str
    consent_id: str
    revocation_epoch: int
    selected_execution: Any = field(repr=False, compare=False)
    selection_registry: Any = field(repr=False, compare=False)
    consent: Any = field(repr=False, compare=False)
    expires_monotonic: float
    authority_epoch: str

    def __post_init__(self) -> None:
        if (not isinstance(self.source_receipt_handle, SourceReceiptHandle)
                or not isinstance(self.selection_handle, str) or len(self.selection_handle) < 32
                or not isinstance(self.consent_receipt_handle, str)
                or not isinstance(self.consent_id, str)
                or type(self.revocation_epoch) is not int or self.revocation_epoch < 0
                or not math.isfinite(self.expires_monotonic)
                or not isinstance(self.authority_epoch, str) or not self.authority_epoch):
            raise ValueError("retained private-input consent binding is malformed")


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
        self._selected_input_proofs: dict[str, tuple[Any, Any]] = {}
        self._consumed_selected_input_proofs: dict[str, tuple[int, Any, Any, float, str]] = {}
        self._selected_input_selections: dict[str, tuple[Any, Any, float, str]] = {}
        self._selected_input_consents: dict[str, RetainedSelectedInputConsent] = {}
        self._lock = threading.RLock()
        self._closed = False

    def record_observed_event(self, observer_enrollment_id: str, *, payload_bytes: bytes,
                              parent_context: HostContext, peer_pid: int, peer_pidfd: int,
                              parent_receipt_handles: Sequence[str] = (),
                              _selected_native_target: Any = None) -> str:
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
        if (_selected_native_target is not None
                and getattr(_selected_native_target, "loaded_package_proof", None)
                != loaded_package_proof):
            raise AuthorityDenied("source.package", "selected target loaded-package proof changed")
        if _selected_native_target is None and not callable(self.target_peer_resolver):
            raise AuthorityDenied("source.target", "root-selected target peer channel is unavailable")
        selected_target = (_selected_native_target if _selected_native_target is not None
                           else self.target_peer_resolver(observer, parent_context))
        selected_pid = getattr(selected_target, "peer_pid", getattr(selected_target, "pid", None))
        selected_identity = getattr(selected_target, "live_peer_identity",
                                    getattr(selected_target, "identity", None))
        selected_uid = getattr(selected_target, "uid",
                               getattr(selected_identity, "kernel_uid", None))
        selected_profile_id = getattr(selected_target, "profile_id", None)
        selected_generation = getattr(selected_target, "generation", None)
        target_owned_fd = getattr(selected_target, "peer_pidfd",
                                  getattr(selected_target, "pidfd", None))
        pinned_target_fd = -1
        try:
            if (selected_target is None or type(selected_pid) is not int
                    or type(target_owned_fd) is not int or target_owned_fd < 0
                    or type(selected_uid) is not int
                    or not isinstance(selected_profile_id, str)
                    or not isinstance(selected_generation, str)):
                raise AuthorityDenied("source.target", "root-selected target peer binding is malformed")
            selected_target_identity = self.process_resolver(
                selected_pid, target_owned_fd,
                profile_id=selected_profile_id, generation=selected_generation)
            if (selected_target_identity is None or selected_target_identity != selected_identity
                    or selected_target_identity.kernel_uid != selected_uid):
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
                selected_pid, pinned_target_fd,
                selected_uid, selected_profile_id, selected_generation,
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
                                parent_receipt_handles: Sequence[str] = (), *,
                                _selected_execution: Any = None,
                                _selection_registry: Any = None) -> SourceReceiptHandle:
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
                # Bind the event identifier in the proof itself. AuthorityService
                # preserves this root-derived value; it must not append a second
                # suffix while signing the receipt.
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
                selected_execution=_selected_execution,
                private_provider_route_ids=(observer.private_provider_route_ids
                                            if _selected_execution is not None else ()),
                private_consent_selection_handle=(
                    getattr(_selected_execution, "private_consent_selection_handle", None)
                    if _selected_execution is not None else None),
            )
            with self._lock:
                if proof.proof_nonce in self._proofs_pending:
                    raise AuthorityDenied("source.observation", "root observation proof nonce collided")
                self._proofs_pending[proof.proof_nonce] = id(proof)
                if _selected_execution is not None:
                    self._selected_input_proofs[proof.proof_nonce] = (
                        _selected_execution,
                        # Preserve the exact root registry which selected it;
                        # service revalidation cannot use a caller selector.
                        _selection_registry,
                    )
                proof_registered = True
            issue_selected = getattr(self.service, "issue_selected_input_source", None)
            if _selected_execution is not None:
                if not callable(issue_selected):
                    raise AuthorityDenied("source.native_input", "selected private input issuer is unavailable")
                result = issue_selected(proof)
            else:
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
            if proof is not None and proof.selected_execution is not None:
                key = str(result)
                with self._lock:
                    has_consent = key in self._selected_input_consents
                    has_selection = key in self._selected_input_selections
                if proof.private_consent_selection_handle is None and not has_selection:
                    self.retain_selected_input_without_egress_consent(
                        proof, proof.selected_execution, result)
                elif proof.private_consent_selection_handle is not None and not has_consent:
                    self.revoke_source_handle(result)
                    raise AuthorityDenied(
                        "source.native_input", "selected private consent was not retained with its receipt")
            return result
        except BaseException:
            # A failed authority call must never make the event proof reusable.
            if proof_registered and proof is not None:
                with self._lock:
                    self._proofs_pending.pop(proof.proof_nonce, None)
                    self._selected_input_proofs.pop(proof.proof_nonce, None)
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

    def resolve_delivered_source_receipt(self, handle: str, *, peer_uid: int,
                                         peer_pid: int, peer_pidfd: int
                                         ) -> SourceReceiptHandle:
        """Revalidate an already-delivered opaque receipt for a root coordinator.

        This is deliberately a non-consuming lookup: the producer delivery was
        consumed by :meth:`take_source_receipt`; callers may use this only to
        confirm the same current target while sequencing its one-time stdin
        phase.  It returns the same opaque token and never exposes receipt
        claims or payload bytes.
        """
        if (not isinstance(handle, str) or not 32 <= len(handle) <= 128
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("source.delivery", "receipt delivery lookup is malformed")
        now = self.service.monotonic()
        with self._lock:
            binding = self._receipt_delivery_bindings.get(handle)
            capsule_entry = self._payload_capsules.get(handle)
            if (binding is None or capsule_entry is None or not binding.delivered
                    or binding.pid != peer_pid or binding.uid != peer_uid
                    or binding.authority_epoch != self.service.authority_epoch
                    or now >= binding.expires
                    or capsule_entry[0].receipt_id != binding.receipt_id
                    or capsule_entry[3] != self.service.authority_epoch):
                raise AuthorityDenied("source.delivery", "receipt is not delivered to this current peer")
            live = self.process_resolver(peer_pid, peer_pidfd,
                                         profile_id=binding.profile_id,
                                         generation=binding.generation)
            retained = self.process_resolver(binding.pid, binding.pidfd,
                                             profile_id=binding.profile_id,
                                             generation=binding.generation)
            if (live is None or retained is None or live != binding.identity
                    or retained != binding.identity or live.kernel_uid != peer_uid):
                raise AuthorityDenied("source.delivery", "delivered receipt peer identity changed")
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

    def capture_selected_native_ingress(
        self, observer_enrollment_id: str, *, payload_bytes: bytes,
        parent_context: HostContext, selected_execution: Any,
        target: Any, selection_registry: Any,
        parent_receipt_handles: Sequence[str] = (),
    ) -> SourceReceiptHandle:
        """Capture the exact pre-EOF input for one root-selected native task.

        ``target`` must be the exact live target object issued by the attached
        selection registry. Its PIDFD ownership transfers to this call. This
        route deliberately bypasses the later HI11 pending-pair resolver: the
        selected task itself is the receipt target for its initial stdin.
        """
        if (not isinstance(observer_enrollment_id, str)
                or not callable(getattr(selection_registry,
                                        "consume_selected_native_input_target", None))):
            raise AuthorityDenied("source.native_input", "selected native input proof is unavailable")
        selected = selection_registry.resolve_current_execution(selected_execution)
        if selected.observer_enrollment_id != observer_enrollment_id:
            raise AuthorityDenied("source.native_input", "native input observer differs from root selection")
        consumed_target = selection_registry.consume_selected_native_input_target(selected, target)
        if consumed_target is not target:
            raise AuthorityDenied("source.native_input", "native target selection was not retained by root")
        observer = self.observers.get(observer_enrollment_id)
        if (observer is None or observer.source_kind != "native-input"
                or observer.profile_id != selected.profile_id
                or observer.generation != selected.generation
                or observer.package_id != selected.native_package_id):
            fd = getattr(target, "peer_pidfd", -1)
            if type(fd) is int and fd >= 0:
                os.close(fd)
            raise AuthorityDenied("source.native_input", "selected native observer changed")
        try:
            event_id = self.record_observed_event(
                observer_enrollment_id, payload_bytes=payload_bytes,
                parent_context=parent_context, peer_pid=target.peer_pid,
                peer_pidfd=target.peer_pidfd,
                parent_receipt_handles=parent_receipt_handles,
                _selected_native_target=target,
            )
            return self.capture_observed_source(
                observer_enrollment_id, event_id, payload_bytes,
                parent_receipt_handles, _selected_execution=selected,
                _selection_registry=selection_registry,
            )
        except BaseException:
            # record_observed_event takes ownership once invoked and closes the
            # target descriptor on every path. If validation failed before that
            # call, the descriptor is still owned here.
            if getattr(target, "peer_pidfd", -1) >= 0:
                try:
                    os.fstat(target.peer_pidfd)
                except OSError:
                    pass
                else:
                    os.close(target.peer_pidfd)
            raise

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
        return self.revoke_source_handle(handle)

    def revoke_source_handle(self, handle: SourceReceiptHandle) -> bool:
        """Root-only exact-token revocation for receipt and delivery cleanup."""
        if type(handle) is not SourceReceiptHandle:
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
        self._selected_input_consents.pop(handle, None)
        self._selected_input_selections.pop(handle, None)
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
        if observation.selected_execution is not None:
            raise AuthorityDenied("source.observation", "selected native input requires its dedicated issuer")
        with self._lock:
            expected_identity = self._proofs_pending.pop(observation.proof_nonce, None)
        if (observation._issuer_token is not self._proof_token
                or expected_identity != id(observation)):
            raise AuthorityDenied("source.observation", "observation proof is forged, stale, or already consumed")
        return True

    def consume_selected_input_observation(self, observation: VerifiedSourceObservation,
                                           selected_execution: Any) -> bool:
        """Consume a selected native-input proof only through its exact live selection.

        AuthorityService uses this dedicated root-only call before signing the
        native-input receipt. It prevents the generic private-source issuer
        from bypassing the selected private route/consent ceiling calculation.
        """
        if (not isinstance(observation, VerifiedSourceObservation)
                or selected_execution is not observation.selected_execution):
            raise AuthorityDenied("source.native_input", "selected input proof does not match its retained selection")
        with self._lock:
            expected = self._proofs_pending.get(observation.proof_nonce)
            retained = self._selected_input_proofs.get(observation.proof_nonce)
            if (observation._issuer_token is not self._proof_token
                    or expected != id(observation) or retained is None
                    or retained[0] is not selected_execution or retained[1] is None):
                raise AuthorityDenied("source.native_input", "selected input proof is forged or stale")
            try:
                current = retained[1].resolve_current_execution(selected_execution)
            except Exception:
                current = None
            observer = self.observers.get(observation.observer_enrollment_id)
            if (current is not selected_execution or observer is None
                    or observer.source_kind != "native-input"
                    or observation.private_provider_route_ids != observer.private_provider_route_ids
                    or observation.profile_id != selected_execution.profile_id
                    or observation.generation != selected_execution.generation
                    or observation.package_id != selected_execution.native_package_id
                    or observation.source_action_id != selected_execution.source_action_id):
                raise AuthorityDenied("source.native_input", "selected input binding or route catalog changed")
            if observation.private_consent_selection_handle != getattr(
                    selected_execution, "private_consent_selection_handle", None):
                raise AuthorityDenied("source.native_input", "private consent selection differs from retained input")
            self._proofs_pending.pop(observation.proof_nonce, None)
            self._selected_input_proofs.pop(observation.proof_nonce, None)
            self._consumed_selected_input_proofs[observation.proof_nonce] = (
                id(observation), selected_execution, retained[1],
                min(observation.expires_monotonic, self.service.monotonic() + 30.0),
                self.service.authority_epoch,
            )
        return True

    def verify_current_selected_input_proof(self, observation: VerifiedSourceObservation,
                                            selected_execution: Any) -> bool:
        """Non-consuming currentness check for the root consent issuer.

        This accepts only the exact proof instance retained by this registry,
        with its exact still-current native execution selection and protected
        observer route catalog. Consent resolution must precede proof
        consumption so the service can compute its recipient intersection.
        """
        if (type(observation) is not VerifiedSourceObservation
                or selected_execution is not observation.selected_execution
                or observation._issuer_token is not self._proof_token):
            return False
        with self._lock:
            if (self._proofs_pending.get(observation.proof_nonce) != id(observation)
                    or observation.proof_nonce not in self._selected_input_proofs):
                return False
            retained = self._selected_input_proofs[observation.proof_nonce]
            if retained[0] is not selected_execution or retained[1] is None:
                return False
            try:
                current = retained[1].resolve_current_execution(selected_execution)
            except Exception:
                return False
            observer = self.observers.get(observation.observer_enrollment_id)
            return bool(
                current is selected_execution and observer is not None
                and observer.source_kind == "native-input"
                and observation.private_provider_route_ids == observer.private_provider_route_ids
                and observation.profile_id == selected_execution.profile_id
                and observation.generation == selected_execution.generation
                and observation.package_id == selected_execution.native_package_id
                and observation.source_action_id == selected_execution.source_action_id
                and observation.private_consent_selection_handle ==
                    selected_execution.private_consent_selection_handle
                and observation.authority_epoch == self.service.authority_epoch
                and observation.expires_monotonic > self.service.monotonic()
            )

    def resolve_selected_input_execution_registry(
        self, observation: VerifiedSourceObservation, selected_execution: Any,
    ) -> Any:
        """Return the retained selection registry only for a current proof pair."""
        if not self.verify_current_selected_input_proof(observation, selected_execution):
            raise AuthorityDenied("source.native_input", "selected input proof is not current")
        with self._lock:
            retained = self._selected_input_proofs.get(observation.proof_nonce)
            if (retained is None or retained[0] is not selected_execution
                    or retained[1] is None):
                raise AuthorityDenied("source.native_input", "selected input registry binding is stale")
            return retained[1]

    def retain_selected_input_consent(
        self, observation: VerifiedSourceObservation,
        selected_execution: Any, source_receipt_handle: SourceReceiptHandle,
        consent: Any,
    ) -> RetainedSelectedInputConsent:
        """Bind freshly resolved consent to the exact signed native-input receipt.

        Called only by AuthorityService after it has consumed ``observation``
        and stored the signed receipt handle. This prevents an unissued proof,
        receipt from another task, or copied consent DTO from becoming a
        request-admission capability.
        """
        if (type(observation) is not VerifiedSourceObservation
                or type(source_receipt_handle) is not SourceReceiptHandle
                or selected_execution is not observation.selected_execution
                or observation._issuer_token is not self._proof_token):
            raise AuthorityDenied("source.native_input", "consent receipt binding is not root-issued")
        consent_registry = getattr(self.service, "private_input_consent_registry", None)
        consent_type = getattr(consent_registry, "consent_type", None)
        if consent_registry is None or not callable(
                getattr(consent_registry, "revalidate_retained_input_consent", None)):
            raise AuthorityDenied("source.native_input", "private input consent registry is unavailable")
        # RootPrivateInputConsent is imported lazily to avoid a service/module
        # cycle while keeping the proof type exact once the registry is wired.
        try:
            from .root_private_input_consent import RootPrivateInputConsent
        except ImportError:
            RootPrivateInputConsent = consent_type
        if RootPrivateInputConsent is None or type(consent) is not RootPrivateInputConsent:
            raise AuthorityDenied("source.native_input", "private input consent proof type is invalid")
        with self._lock:
            consumed = self._consumed_selected_input_proofs.get(observation.proof_nonce)
            with self.service._lock:
                receipt = self.service._source_receipt_handles.get(source_receipt_handle)
            if (consumed is None or consumed[0] != id(observation)
                    or consumed[1] is not selected_execution
                    or consumed[4] != self.service.authority_epoch
                    or self.service.monotonic() >= consumed[3]
                    or not isinstance(receipt, SourceReceipt)
                    or receipt.monotonic_expires_at <= self.service.monotonic()):
                raise AuthorityDenied("source.native_input", "selected input receipt is stale or unissued")
            route_ids = self.observers[observation.observer_enrollment_id].private_provider_route_ids
            if (getattr(consent, "selection_handle", None)
                    != observation.private_consent_selection_handle
                    or getattr(consent, "input_observation_handle", None)
                    != selected_execution.selection_handle
                    or getattr(consent, "profile_id", None) != selected_execution.profile_id
                    or getattr(consent, "service_generation_digest", None)
                    != selected_execution.service_generation_digest
                    or getattr(consent, "provider_route_ids", None) is None
                    or not set(getattr(consent, "provider_route_ids", ())).issubset(set(route_ids))
                    or not set(getattr(consent, "private_recipient_ids", ())).issubset(
                        set(receipt.recipient_ceiling))
                    or getattr(consent, "expires_monotonic", 0) <= self.service.monotonic()
                    or receipt.source_kind != "native-input"
                    or receipt.profile_id != selected_execution.profile_id
                    or receipt.process_generation != selected_execution.generation):
                raise AuthorityDenied("source.native_input", "consent does not match the selected input receipt")
            binding = RetainedSelectedInputConsent(
                source_receipt_handle=source_receipt_handle,
                selection_handle=selected_execution.selection_handle,
                consent_receipt_handle=consent.receipt_handle,
                consent_id=consent.consent_id,
                revocation_epoch=consent.revocation_epoch,
                selected_execution=selected_execution,
                selection_registry=consumed[2],
                consent=consent,
                expires_monotonic=min(receipt.monotonic_expires_at,
                                      consent.expires_monotonic),
                authority_epoch=self.service.authority_epoch,
            )
            key = str(source_receipt_handle)
            if key in self._selected_input_consents:
                raise AuthorityDenied("source.native_input", "input consent was already retained")
            self._selected_input_consents[key] = binding
            self._selected_input_selections[key] = (
                selected_execution, consumed[2], binding.expires_monotonic,
                self.service.authority_epoch,
            )
            self._consumed_selected_input_proofs.pop(observation.proof_nonce, None)
            return binding

    def retain_selected_input_without_egress_consent(
        self, observation: VerifiedSourceObservation,
        selected_execution: Any, source_receipt_handle: SourceReceiptHandle,
    ) -> None:
        """Retain a local-only input receipt while guaranteeing zero egress ceiling."""
        if (type(observation) is not VerifiedSourceObservation
                or type(source_receipt_handle) is not SourceReceiptHandle
                or selected_execution is not observation.selected_execution
                or observation.private_consent_selection_handle is not None
                or observation._issuer_token is not self._proof_token):
            raise AuthorityDenied("source.native_input", "local-only input selection is invalid")
        with self._lock:
            consumed = self._consumed_selected_input_proofs.get(observation.proof_nonce)
            with self.service._lock:
                receipt = self.service._source_receipt_handles.get(source_receipt_handle)
            if (consumed is None or consumed[0] != id(observation)
                    or consumed[1] is not selected_execution
                    or consumed[4] != self.service.authority_epoch
                    or self.service.monotonic() >= consumed[3]
                    or not isinstance(receipt, SourceReceipt)
                    or receipt.monotonic_expires_at <= self.service.monotonic()):
                raise AuthorityDenied("source.native_input", "local input receipt is stale or unissued")
            if receipt.source_kind != "native-input" or receipt.recipient_ceiling:
                raise AuthorityDenied("source.native_input", "local-only input receipt unexpectedly permits egress")
            key = str(source_receipt_handle)
            self._selected_input_selections[key] = (
                selected_execution, consumed[2], receipt.monotonic_expires_at,
                self.service.authority_epoch,
            )
            self._consumed_selected_input_proofs.pop(observation.proof_nonce, None)

    def resolve_selected_input_consent(
        self, source_receipt_handle: SourceReceiptHandle,
        selected_execution: Any,
    ) -> RetainedSelectedInputConsent:
        """Revalidate the retained consent/receipt/selection join for root dispatch."""
        if type(source_receipt_handle) is not SourceReceiptHandle:
            raise AuthorityDenied("source.native_input", "source receipt handle is invalid")
        with self._lock:
            binding = self._selected_input_consents.get(str(source_receipt_handle))
            capsule_entry = self._payload_capsules.get(str(source_receipt_handle))
            if (binding is None or binding.selected_execution is not selected_execution
                    or binding.authority_epoch != self.service.authority_epoch
                    or binding.expires_monotonic <= self.service.monotonic()
                    or capsule_entry is None or capsule_entry[3] != self.service.authority_epoch):
                raise AuthorityDenied("source.native_input", "retained consent binding is stale")
            try:
                current = binding.selection_registry.resolve_current_execution(selected_execution)
            except Exception:
                raise AuthorityDenied("source.native_input", "native input selection is no longer current") from None
            if current is not selected_execution:
                raise AuthorityDenied("source.native_input", "native input selection changed")
            consent_registry = getattr(self.service, "private_input_consent_registry", None)
            if consent_registry is None:
                raise AuthorityDenied("source.native_input", "private input consent registry is unavailable")
            renewed = consent_registry.revalidate_retained_input_consent(
                binding.consent_receipt_handle,
                retained_input_selection_handle=binding.selection_handle,
                expected_consent_id=binding.consent_id,
                expected_revocation_epoch=binding.revocation_epoch,
            )
            if renewed is not binding.consent:
                raise AuthorityDenied("source.native_input", "retained consent proof changed")
            return binding

    def resolve_retained_selected_input_execution(
        self, source_receipt_handle: SourceReceiptHandle,
    ) -> Any:
        """Resolve the exact root selection attached to a retained input receipt."""
        if type(source_receipt_handle) is not SourceReceiptHandle:
            raise AuthorityDenied("source.native_input", "source receipt handle is invalid")
        with self._lock:
            binding = self._selected_input_selections.get(str(source_receipt_handle))
            if (binding is None or binding[3] != self.service.authority_epoch
                    or binding[2] <= self.service.monotonic()):
                raise AuthorityDenied("source.native_input", "input consent binding is stale")
            current = binding[1].resolve_current_execution(binding[0])
            if current is not binding[0]:
                raise AuthorityDenied("source.native_input", "selected input execution changed")
            return binding[0]

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
        package_generation = observer.native_package_generation or observer.generation
        try:
            package = self.package_resolver(observer.package_id, package_generation)
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
                or getattr(package, "generation", None) != package_generation
                or getattr(package, "compiled_closure_sha256", None) != observer.package_sha256
                or len(role_candidates) != 1 or role_candidates[0] != observer.role_sha256
                or adapter is None
                or getattr(adapter, "adapter_id", None) != observer.role_id
                or getattr(adapter, "target_id", None) != observer.target_id
                or getattr(adapter, "recipient", None) != observer.recipient
                or getattr(adapter, "generation", None) != package_generation):
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
        for nonce, (_observation_id, _selection, _registry, expires, epoch) in tuple(
                self._consumed_selected_input_proofs.items()):
            if expires <= now or epoch != self.service.authority_epoch:
                self._consumed_selected_input_proofs.pop(nonce, None)

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
                self._selected_input_consents.pop(handle, None)
                self._selected_input_selections.pop(handle, None)
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
            self._selected_input_proofs.clear()
            self._consumed_selected_input_proofs.clear()
            self._selected_input_selections.clear()
            self._selected_input_consents.clear()
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


@dataclass(frozen=True, slots=True)
class RootSelectedNativeExecution:
    """Root-local selected task/process/package/action join for initial input."""

    schema: int
    selection_handle: str
    kind: str
    execution_handle: Any = field(repr=False, compare=False)
    process_handle: Any = field(repr=False, compare=False)
    profile_id: str
    generation: str
    native_package_id: str
    native_package_generation: str
    observer_enrollment_id: str
    source_action_id: str
    service_generation_digest: str
    expires_monotonic: float
    private_consent_selection_handle: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not isinstance(self.selection_handle, str)
                or not 32 <= len(self.selection_handle) <= 128
                or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                       for char in self.selection_handle)
                or self.kind not in {"resource-task", "native-health", "desktop-input"}
                or any(not isinstance(getattr(self, name), str) or not getattr(self, name)
                       for name in ("profile_id", "generation", "native_package_id",
                                    "native_package_generation", "observer_enrollment_id",
                                    "source_action_id", "service_generation_digest"))
                or (self.private_consent_selection_handle is not None
                    and (not isinstance(self.private_consent_selection_handle, str)
                         or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.private_consent_selection_handle)))
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("selected native execution binding is malformed")


@dataclass(frozen=True, slots=True)
class _SelectedNativeExecutionRecord:
    selection: RootSelectedNativeExecution = field(repr=False)
    running_binding: Any = field(repr=False)
    observer: SourceObserverEnrollment = field(repr=False)
    package: Any = field(repr=False)
    adapter: Any = field(repr=False)
    authority_epoch: str


class RootNativeExecutionSelectionRegistry:
    """Select one admitted running task and its unique native-input observer.

    Selection joins the exact original resource handle, already-resolved source
    snapshot, live managed-task handle, current profile/package adapter, and
    protected source-observer row.  A DTO copy or a handle from another task
    cannot be resolved.  The concrete target resolver separately binds the
    current PIDFD and loaded-package proof before any stdin capture/delivery.
    """

    def __init__(self, source_observer_registry: SourceObserverRegistry,
                 admitted_task_registry: Any, process_custody_registry: Any,
                 task_native_observation_registry: Any,
                 *, monotonic: Callable[[], float] | None = None) -> None:
        from ..managed_process_custodian import ManagedProcessEffectHandler
        from ..registry.resource_jobs import ResourceJobAuthority

        if (type(source_observer_registry) is not SourceObserverRegistry
                or not isinstance(admitted_task_registry, ResourceJobAuthority)
                or not isinstance(process_custody_registry, ManagedProcessEffectHandler)
                or source_observer_registry.service is not admitted_task_registry.service
                or not callable(getattr(task_native_observation_registry,
                                        "resolve_running_task_binding", None))):
            raise AuthorityDenied("resource.native_selection", "root native execution selection dependencies are unavailable")
        self.source_observers = source_observer_registry
        self.admitted_tasks = admitted_task_registry
        self.process_custody = process_custody_registry
        self.task_observations = task_native_observation_registry
        self.service = source_observer_registry.service
        self.monotonic = monotonic or self.service.monotonic
        if not callable(self.monotonic):
            raise ValueError("root native selection monotonic clock is required")
        self._lock = threading.RLock()
        self._selections: dict[str, _SelectedNativeExecutionRecord] = {}
        self._targets: dict[str, Any] = {}
        self._loader_ready_event_ids: dict[str, str] = {}
        self._target_resolver: Any = None
        self._closed = False

    def _private_consent_selection_handle(self, observer: SourceObserverEnrollment,
                                          running_binding: Any) -> str | None:
        """Read the active root profile preference from its exact principal row."""
        consent_registry = getattr(self.service, "private_input_consent_registry", None)
        if consent_registry is None:
            # No current profile choice is equivalent to no private provider
            # egress consent. Input capture can still proceed with an empty
            # recipient ceiling.
            return None
        resolver = getattr(consent_registry, "selection_handle_for_current_profile", None)
        if (not callable(resolver) or getattr(consent_registry, "service", None) is not self.service):
            raise AuthorityDenied("resource.native_consent", "root private input consent registry is invalid")
        source = getattr(running_binding, "source", None)
        matches = [binding for binding in self.service.bindings_by_uid.values()
                   if binding.profile_id == observer.profile_id
                   and binding.principal_id == observer.principal_id
                   and binding.namespace_id == observer.namespace_id
                   and binding.uid == observer.producer_uid
                   and binding.principal_id == getattr(source, "principal_id", None)
                   and binding.profile_id == getattr(source, "profile_id", None)
                   and binding.namespace_id == getattr(source, "namespace_id", None)]
        if len(matches) != 1:
            raise AuthorityDenied("resource.native_consent", "selected profile principal binding is ambiguous")
        handle = resolver(matches[0])
        if handle is None:
            return None
        if (not isinstance(handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)):
            raise AuthorityDenied("resource.native_consent", "root consent selection handle is malformed")
        return handle

    def select_resource_task(self, admission_handle: Any, node_id: str,
                             managed_task_handle: Any) -> RootSelectedNativeExecution:
        """Join exact root admission/source with the actual pre-EOF task handle."""
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import RootResourceJobAdmissionHandle

        if (type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(managed_task_handle) is not ManagedTaskHandle
                or node_id != admission_handle.node_id):
            raise AuthorityDenied("resource.native_selection", "initial native selection arguments are invalid")
        now = self.monotonic()
        if (self._closed or now >= admission_handle.expires_monotonic
                or admission_handle.operation_id != "hermes-resource-profile-task-v1"
                or self.admitted_tasks.task_handle_cancelled(admission_handle, node_id)):
            raise AuthorityDenied("resource.native_selection", "resource task admission is stale or cancelled")
        binding = self.task_observations.resolve_running_task_binding(
            admission_handle, node_id, managed_task_handle)
        admitted_task = getattr(binding, "admitted_task", None)
        try:
            selected_prompt = json.loads(admission_handle.task_payload.decode("utf-8"))["prompt"]
            expected_stdin_sha256 = hashlib.sha256(selected_prompt.encode("utf-8")).hexdigest()
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, AttributeError):
            raise AuthorityDenied("resource.native_selection", "admitted task prompt is malformed") from None
        if (getattr(binding, "admission_handle", None) is not admission_handle
                or getattr(binding, "managed_task_handle", None) is not managed_task_handle
                or getattr(binding, "node_id", None) != node_id
                or getattr(binding, "service_generation_digest", None)
                != self.service.service_generation_digest
                or getattr(binding, "resource_generation", None) != admission_handle.resource_generation
                or getattr(binding, "profile_id", None) != admission_handle.profile_id
                or getattr(binding, "process_generation", None) != admission_handle.process_generation
                or getattr(binding, "native_package_id", None) != admission_handle.native_package_id
                or getattr(binding, "native_package_generation", None)
                != admission_handle.native_package_generation
                or getattr(binding, "task_payload_sha256", None) != admission_handle.task_payload_sha256
                or getattr(binding, "parent_closure_digest", None)
                != admission_handle.parent_closure_digest
                or getattr(getattr(binding, "source", None), "parent_closure_digest", None)
                != admission_handle.parent_closure_digest
                or getattr(getattr(binding, "source", None), "expires_monotonic", 0) <= now
                or getattr(admitted_task, "task_payload_bytes", None) != admission_handle.task_payload
                or getattr(admitted_task, "task_payload_sha256", None) != admission_handle.task_payload_sha256
                or getattr(admitted_task, "parent_closure_digest", None)
                != admission_handle.parent_closure_digest
                or getattr(admitted_task, "stdin_sha256", None) != expected_stdin_sha256
                or now >= getattr(binding, "deadline_monotonic", 0)):
            raise AuthorityDenied("resource.native_selection", "retained admitted-task binding is stale or mismatched")
        process_state = self.process_custody._resolve_task_handle(managed_task_handle)
        process_handle = getattr(process_state, "handle", None)
        profile = getattr(process_handle, "profile", None)
        admission = getattr(process_state, "admission", None)
        if (process_handle is None or process_handle is not getattr(binding, "process_handle", None)
                or getattr(process_state, "input_closed", False) is not False
                or getattr(process_state, "consumed", True) is not False
                or getattr(process_handle, "process_id", None) != getattr(binding, "process_handle", None).process_id
                or getattr(profile, "profile_id", None) != admission_handle.profile_id
                or getattr(profile, "generation", None) != admission_handle.profile_generation
                or getattr(admission, "admission_id", None) != admission_handle.child_admission_id
                or getattr(admission, "job_id", None) != admission_handle.job_id
                or getattr(admission, "node_id", None) != node_id
                or getattr(admission, "task_payload_sha256", None)
                != admission_handle.task_payload_sha256
                or getattr(admission, "parent_closure_digest", None)
                != admission_handle.parent_closure_digest
                or getattr(admission, "native_package_id", None) != admission_handle.native_package_id
                or getattr(admission, "native_package_generation", None)
                != admission_handle.native_package_generation):
            raise AuthorityDenied("resource.native_selection", "managed process is not the selected pre-stdin task")

        candidates: list[tuple[SourceObserverEnrollment, Any, Any]] = []
        for observer in self.source_observers.observers.values():
            if (observer.source_kind != "native-input"
                    or observer.profile_id != admission_handle.profile_id
                    or observer.package_id != admission_handle.native_package_id
                    or observer.generation != admission_handle.process_generation
                    or (observer.native_package_generation is not None
                        and observer.native_package_generation != admission_handle.native_package_generation)):
                continue
            try:
                package, adapter = self.source_observers._resolve_package_role(observer)
            except AuthorityDenied:
                continue
            if (getattr(package, "package_id", None) == admission_handle.native_package_id
                    and getattr(package, "profile_id", None) == admission_handle.profile_id
                    and getattr(package, "generation", None) ==
                    (observer.native_package_generation or observer.generation)
                    and getattr(adapter, "action_id", None) == observer.source_action_id
                    and getattr(adapter, "adapter_id", None) == observer.role_id):
                candidates.append((observer, package, adapter))
        if len(candidates) != 1:
            raise AuthorityDenied("resource.native_selection", "selected package has no unique native-input observer/action join")
        observer, package, adapter = candidates[0]
        expiry = min(float(admission_handle.expires_monotonic),
                     float(binding.deadline_monotonic), float(getattr(process_state, "deadline", 0)))
        if (not math.isfinite(expiry) or expiry <= now
                or self.service.service_generation_digest != binding.service_generation_digest):
            raise AuthorityDenied("resource.native_selection", "selected task or package lease expired")
        consent_selection_handle = self._private_consent_selection_handle(observer, binding)
        selected = RootSelectedNativeExecution(
            schema=1, selection_handle=secrets.token_urlsafe(32), kind="resource-task",
            execution_handle=admission_handle, process_handle=managed_task_handle,
            profile_id=admission_handle.profile_id, generation=admission_handle.process_generation,
            native_package_id=admission_handle.native_package_id,
            native_package_generation=admission_handle.native_package_generation,
            observer_enrollment_id=observer.observer_enrollment_id,
            source_action_id=adapter.action_id,
            service_generation_digest=self.service.service_generation_digest,
            expires_monotonic=expiry,
            private_consent_selection_handle=consent_selection_handle,
        )
        record = _SelectedNativeExecutionRecord(
            selected, binding, observer, package, adapter, self.service.authority_epoch)
        with self._lock:
            self._prune_locked(now)
            if self._closed or len(self._selections) >= 128:
                raise AuthorityDenied("resource.native_capacity", "root selected execution capacity is unavailable")
            if selected.selection_handle in self._selections:
                raise AuthorityDenied("resource.native_replay", "root selection handle collided")
            self._selections[selected.selection_handle] = record
        return selected

    def resolve_current_execution(self, selected_execution: RootSelectedNativeExecution
                                  ) -> RootSelectedNativeExecution:
        """Revalidate and return only the identical root-held selection object."""
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import RootResourceJobAdmissionHandle

        if type(selected_execution) is not RootSelectedNativeExecution:
            raise AuthorityDenied("resource.native_selection", "selected execution proof type is invalid")
        with self._lock:
            record = self._selections.get(selected_execution.selection_handle)
            if record is None or record.selection is not selected_execution or self._closed:
                raise AuthorityDenied("resource.native_selection", "selected execution is forged, expired, or consumed")
        admission_handle = selected_execution.execution_handle
        task_handle = selected_execution.process_handle
        if (type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(task_handle) is not ManagedTaskHandle
                or self.monotonic() >= selected_execution.expires_monotonic
                or self.service.authority_epoch != record.authority_epoch
                or self.service.service_generation_digest != selected_execution.service_generation_digest
                or self.admitted_tasks.task_handle_cancelled(admission_handle, admission_handle.node_id)):
            raise AuthorityDenied("resource.native_selection", "selected task epoch or lease is stale")
        current = self.task_observations.resolve_running_task_binding(
            admission_handle, admission_handle.node_id, task_handle)
        if (current is not record.running_binding
                or getattr(current, "admission_handle", None) is not admission_handle
                or getattr(current, "managed_task_handle", None) is not task_handle
                or getattr(current, "service_generation_digest", None)
                != selected_execution.service_generation_digest
                or getattr(current, "process_generation", None) != selected_execution.generation
                or getattr(current, "native_package_id", None) != selected_execution.native_package_id
                or getattr(current, "native_package_generation", None)
                != selected_execution.native_package_generation):
            raise AuthorityDenied("resource.native_selection", "current running task differs from selected execution")
        state = self.process_custody._resolve_task_handle(task_handle)
        if (getattr(state, "input_closed", True) is not False
                or getattr(state, "handle", None) is not getattr(current, "process_handle", None)
                or getattr(state, "consumed", True) is not False):
            raise AuthorityDenied("resource.native_selection", "selected process is not live before stdin EOF")
        observer = self.source_observers.observers.get(selected_execution.observer_enrollment_id)
        if observer is not record.observer:
            raise AuthorityDenied("resource.native_selection", "selected package observer changed")
        package, adapter = self.source_observers._resolve_package_role(observer)
        if (package is not record.package or adapter is not record.adapter
                or adapter.action_id != selected_execution.source_action_id
                or package.package_id != selected_execution.native_package_id
                or package.generation != (observer.native_package_generation or observer.generation)):
            raise AuthorityDenied("resource.native_selection", "selected package action closure changed")
        return selected_execution

    def resolve_selection_handle(self, selection_handle: str) -> RootSelectedNativeExecution:
        """Resolve an opaque root-issued handle to its exact live selection.

        This is an in-process root lookup for turn-delivery composition. A
        worker presenting the same string over RPC cannot select a task.
        """
        if (not isinstance(selection_handle, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", selection_handle) is None):
            raise AuthorityDenied("resource.native_selection", "selected execution handle is malformed")
        with self._lock:
            record = self._selections.get(selection_handle)
            if record is None:
                raise AuthorityDenied("resource.native_selection", "selected execution handle is unknown or consumed")
            selected = record.selection
        return self.resolve_current_execution(selected)

    def resolve_current_selected_execution(self, selection_handle: str
                                           ) -> RootSelectedNativeExecution:
        """Consent-registry lookup for an opaque retained selection handle."""
        return self.resolve_selection_handle(selection_handle)

    def attach_native_input_target_resolver(self, resolver: Any) -> None:
        """Attach the concrete PIDFD/loaded-package target resolver exactly once."""
        from .native_custody_proof import RootNativeInputTargetResolver

        if (type(resolver) is not RootNativeInputTargetResolver
                or getattr(resolver, "selection_registry", None) is not self):
            raise ValueError("the concrete root native-input target resolver is required")
        with self._lock:
            if self._target_resolver is not None:
                raise AuthorityDenied("resource.native_target", "native target resolver is already attached")
            self._target_resolver = resolver

    def resolve_selected_native_input_target(self,
                                             selected_execution: RootSelectedNativeExecution) -> Any:
        """Resolve one actual PIDFD/loaded-closure target for selected input."""
        selected = self.resolve_current_execution(selected_execution)
        with self._lock:
            resolver = self._target_resolver
        if resolver is None:
            raise AuthorityDenied("resource.native_target", "root native-input target resolver is unavailable")
        target = resolver.resolve_selected_native_input_target(selected)
        record = self._selections[selected.selection_handle]
        expected_process_id = getattr(getattr(record.running_binding, "process_handle", None),
                                      "process_id", None)
        loaded = getattr(target, "loaded_package_proof", None)
        if (not isinstance(getattr(target, "process_id", None), str)
                or getattr(target, "profile_id", None) != selected.profile_id
                or getattr(target, "generation", None) != selected.generation
                or target.process_id != expected_process_id
                or type(getattr(target, "peer_pid", None)) is not int
                or target.peer_pid <= 0
                or type(getattr(target, "peer_pidfd", None)) is not int
                or target.peer_pidfd < 0
                or getattr(target, "live_peer_identity", None) is None
                or getattr(loaded, "package_id", None) != selected.native_package_id
                or getattr(loaded, "profile_id", None) != selected.profile_id
                or getattr(loaded, "generation", None) != selected.generation
                or getattr(loaded, "target_peer_identity", None) != target.live_peer_identity
                or getattr(target, "service_generation_digest", None)
                != selected.service_generation_digest
                or getattr(target, "expires_monotonic", 0) > selected.expires_monotonic):
            fd = getattr(target, "peer_pidfd", None)
            if type(fd) is int and fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise AuthorityDenied("resource.native_target", "native input target differs from selected task")
        with self._lock:
            if (self._closed or self._selections.get(selected.selection_handle) is not record
                    or selected.selection_handle in self._targets):
                try:
                    os.close(target.peer_pidfd)
                except OSError:
                    pass
                raise AuthorityDenied("resource.native_target", "native input target is stale or already selected")
            self._targets[selected.selection_handle] = target
            ready_event_id = getattr(loaded, "loader_ready_event_id", None)
            if not isinstance(ready_event_id, str) or not ready_event_id:
                self._targets.pop(selected.selection_handle, None)
                try:
                    os.close(target.peer_pidfd)
                except OSError:
                    pass
                raise AuthorityDenied("resource.native_target", "loaded package proof lacks a ready event")
            self._loader_ready_event_ids[selected.selection_handle] = ready_event_id
        return target

    def consume_selected_native_input_target(
        self, selected_execution: RootSelectedNativeExecution, target: Any,
    ) -> Any:
        """Consume the exact PIDFD target previously issued for this selection."""
        selected = self.resolve_current_execution(selected_execution)
        with self._lock:
            retained = self._targets.pop(selected.selection_handle, None)
        if retained is None or retained is not target:
            raise AuthorityDenied("resource.native_target", "native target was not issued for this selection")
        return retained

    def loader_ready_event_id(self, selected_execution: RootSelectedNativeExecution) -> str:
        selected = self.resolve_current_execution(selected_execution)
        with self._lock:
            event_id = self._loader_ready_event_ids.get(selected.selection_handle)
        if not isinstance(event_id, str) or not event_id:
            raise AuthorityDenied("resource.native_loader", "selected execution has no retained loader-ready event")
        return event_id

    def revalidate_selected_native_peer(
        self, selected_execution: RootSelectedNativeExecution, *, peer_uid: int,
        peer_pid: int, peer_pidfd: int, loader_ready_event_id: str,
    ) -> Any:
        """Recheck the selected task and loaded closure against an RPC peer."""
        selected = self.resolve_current_execution(selected_execution)
        resolver = self._target_resolver
        if resolver is None:
            raise AuthorityDenied("resource.native_target", "native target resolver is unavailable")
        target = resolver.resolve_selected_native_input_target(selected)
        try:
            identity = self.source_observers.process_resolver(
                peer_pid, peer_pidfd, profile_id=selected.profile_id,
                generation=selected.generation)
            if (type(peer_uid) is not int or peer_uid <= 0
                    or type(peer_pid) is not int or peer_pid <= 0
                    or type(peer_pidfd) is not int or peer_pidfd < 0
                    or target.peer_pid != peer_pid
                    or target.live_peer_identity != identity
                    or identity is None or identity.kernel_uid != peer_uid
                    or target.profile_id != selected.profile_id
                    or target.generation != selected.generation
                    or target.process_id != selected.process_handle.process_id
                    or target.service_generation_digest != selected.service_generation_digest
                    or target.expires_monotonic <= self.monotonic()
                    or getattr(target.loaded_package_proof, "loader_ready_event_id", None)
                    != loader_ready_event_id
                    or self.loader_ready_event_id(selected) != loader_ready_event_id):
                raise AuthorityDenied("resource.native_peer", "RPC peer is not the selected loaded native task")
            return identity
        finally:
            try:
                os.close(target.peer_pidfd)
            except OSError:
                pass

    def release_selection(self, selected_execution: RootSelectedNativeExecution) -> None:
        if type(selected_execution) is not RootSelectedNativeExecution:
            raise AuthorityDenied("resource.native_selection", "selected execution proof type is invalid")
        with self._lock:
            record = self._selections.get(selected_execution.selection_handle)
            if record is None or record.selection is not selected_execution:
                raise AuthorityDenied("resource.native_selection", "selected execution is forged or consumed")
            self._selections.pop(selected_execution.selection_handle, None)
            target = self._targets.pop(selected_execution.selection_handle, None)
            self._loader_ready_event_ids.pop(selected_execution.selection_handle, None)
        if target is not None:
            try:
                os.close(target.peer_pidfd)
            except OSError:
                pass

    def _prune_locked(self, now: float) -> None:
        for handle, record in tuple(self._selections.items()):
            if (record.selection.expires_monotonic <= now
                    or record.authority_epoch != self.service.authority_epoch
                    or record.selection.service_generation_digest != self.service.service_generation_digest):
                self._selections.pop(handle, None)
                self._loader_ready_event_ids.pop(handle, None)
                target = self._targets.pop(handle, None)
                if target is not None:
                    try:
                        os.close(target.peer_pidfd)
                    except OSError:
                        pass

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._selections.clear()
            targets = tuple(self._targets.values())
            self._targets.clear()
            self._loader_ready_event_ids.clear()
        for target in targets:
            try:
                os.close(target.peer_pidfd)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class NativeInitialInputDelivery:
    """Opaque root response after the selected native peer takes its input."""

    schema: int
    source_receipt_handle: str
    selected_execution_handle: str
    input_sha256: str
    input_size_bytes: int
    expires_monotonic: float
    turn_handle: str | None = None

    def __post_init__(self) -> None:
        if (self.schema != 1
                or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.source_receipt_handle) is None
                or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.selected_execution_handle) is None
                or not re.fullmatch(r"[0-9a-f]{64}", self.input_sha256)
                or type(self.input_size_bytes) is not int
                or not 1 <= self.input_size_bytes <= MAX_OBSERVED_SOURCE_BYTES
                or not math.isfinite(self.expires_monotonic)
                or (self.turn_handle is not None
                    and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.turn_handle) is None)):
            raise ValueError("native initial-input delivery response is malformed")

    def to_wire(self) -> dict[str, Any]:
        wire = {
            "schema": self.schema,
            "source_receipt_handle": self.source_receipt_handle,
            "selected_execution_handle": self.selected_execution_handle,
            "input_sha256": self.input_sha256,
            "input_size_bytes": self.input_size_bytes,
            "expires_monotonic": self.expires_monotonic,
        }
        if self.turn_handle is not None:
            wire["turn_handle"] = self.turn_handle
        return wire


@dataclass(slots=True)
class _PendingNativeInputDelivery:
    selected_execution: RootSelectedNativeExecution = field(repr=False)
    event: Any = field(repr=False)
    handle: str
    pid: int
    uid: int
    profile_id: str
    generation: str
    identity: Any = field(repr=False)
    authority_epoch: str
    service_generation_digest: str
    expires_monotonic: float
    turn_handle: str | None = None
    state: str = "pending"
    response: NativeInitialInputDelivery | None = None


class RootNativeInputDeliveryRegistry:
    """One-use, selector-free native.input.take queue for captured task input.

    The root queues an already captured receipt against its exact selected
    execution. The producer supplies no handle or identity selector: SO_PEERCRED
    and PIDFD identify the only queued input it may consume.
    """

    MAX_PENDING = 128

    def __init__(self, source_observer_registry: SourceObserverRegistry,
                 selected_native_execution_registry: RootNativeExecutionSelectionRegistry,
                 process_custody_registry: Any, *,
                 monotonic: Callable[[], float] | None = None):
        from ..managed_process_custodian import ManagedProcessEffectHandler

        if (type(source_observer_registry) is not SourceObserverRegistry
                or type(selected_native_execution_registry) is not RootNativeExecutionSelectionRegistry
                or selected_native_execution_registry.source_observers is not source_observer_registry
                or not isinstance(process_custody_registry, ManagedProcessEffectHandler)):
            raise AuthorityDenied("native.input.delivery", "root native input delivery dependencies are unavailable")
        self.source_observers = source_observer_registry
        self.selected_executions = selected_native_execution_registry
        self.process_custody = process_custody_registry
        self.service = source_observer_registry.service
        self.monotonic = monotonic or self.service.monotonic
        if not callable(self.monotonic):
            raise ValueError("native input delivery monotonic clock is required")
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._pending: dict[str, _PendingNativeInputDelivery] = {}
        self._closed = False

    @classmethod
    def from_root_runtime(cls, source_observer_registry: SourceObserverRegistry,
                          selected_native_execution_registry: RootNativeExecutionSelectionRegistry,
                          process_custody_registry: Any) -> "RootNativeInputDeliveryRegistry":
        return cls(source_observer_registry, selected_native_execution_registry,
                   process_custody_registry)

    def queue_selected_input(self, selected_execution: RootSelectedNativeExecution,
                             event: Any, *, turn_handle: str | None = None) -> None:
        """Retain an actual root-captured input event until its producer takes it."""
        from .native_input_observer import RootNativeInputEvent

        selected = self.selected_executions.resolve_current_execution(selected_execution)
        if (type(event) is not RootNativeInputEvent
                or event.schema != 1 or event.input_origin_kind != "root-admitted-task"
                or event.producer_profile_id != selected.profile_id
                or event.producer_generation != selected.generation
                or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", event.source_receipt_handle) is None
                or not isinstance(event.payload_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", event.payload_sha256)
                or type(event.payload_size_bytes) is not int
                or not 1 <= event.payload_size_bytes <= MAX_OBSERVED_SOURCE_BYTES
                or event.parent_closure_digest != selected.execution_handle.parent_closure_digest
                or event.expires_monotonic <= self.monotonic()
                or event.native_loader_ready_event_id
                != self.selected_executions.loader_ready_event_id(selected)
                or (turn_handle is not None
                    and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", turn_handle) is None)):
            raise AuthorityDenied("native.input.delivery", "captured event differs from selected native task")
        source = self.source_observers
        with source._lock:
            capsule_entry = source._payload_capsules.get(event.source_receipt_handle)
            delivery = source._receipt_delivery_bindings.get(event.source_receipt_handle)
            if capsule_entry is None or delivery is None:
                raise AuthorityDenied("native.input.delivery", "captured source receipt is not retained")
            receipt, capsule, payload, epoch = capsule_entry
            observer = source.observers.get(capsule.observer_enrollment_id)
            if (epoch != self.service.authority_epoch
                    or receipt.source_kind != "native-input"
                    or observer is None or observer.observer_enrollment_id != selected.observer_enrollment_id
                    or observer.profile_id != selected.profile_id
                    or observer.generation != selected.generation
                    or observer.package_id != selected.native_package_id
                    or observer.source_action_id != selected.source_action_id
                    or hashlib.sha256(payload).hexdigest() != event.payload_sha256
                    or len(payload) != event.payload_size_bytes
                    or capsule.payload_sha256 != event.payload_sha256
                    or capsule.parent_closure_digest != event.parent_closure_digest
                    or delivery.delivered
                    or delivery.authority_epoch != self.service.authority_epoch
                    or delivery.profile_id != selected.profile_id
                    or delivery.generation != selected.generation
                    or receipt.profile_id != selected.profile_id
                    or receipt.process_generation != selected.generation
                    or receipt.uid != delivery.uid
                    or event.expires_monotonic > min(delivery.expires, selected.expires_monotonic)):
                raise AuthorityDenied("native.input.delivery", "retained source receipt does not match captured input")
            try:
                duplicated = os.dup(delivery.pidfd)
            except OSError:
                raise AuthorityDenied("native.input.delivery", "selected native peer lease is unavailable") from None
            pid, uid, identity = delivery.pid, delivery.uid, delivery.identity
        try:
            current_identity = source.process_resolver(
                pid, duplicated, profile_id=selected.profile_id, generation=selected.generation)
            if current_identity is None or current_identity != identity or current_identity.kernel_uid != uid:
                raise AuthorityDenied("native.input.delivery", "captured input peer identity is no longer current")
            self.selected_executions.revalidate_selected_native_peer(
                selected, peer_uid=uid, peer_pid=pid, peer_pidfd=duplicated,
                loader_ready_event_id=event.native_loader_ready_event_id,
            )
        finally:
            os.close(duplicated)
        row = _PendingNativeInputDelivery(
            selected_execution=selected, event=event, handle=event.source_receipt_handle,
            pid=pid, uid=uid, profile_id=selected.profile_id, generation=selected.generation,
            identity=identity, authority_epoch=self.service.authority_epoch,
            service_generation_digest=selected.service_generation_digest,
            expires_monotonic=min(
                float(event.expires_monotonic), float(delivery.expires),
                float(selected.expires_monotonic)), turn_handle=turn_handle,
        )
        with self._changed:
            self._prune_locked(self.monotonic())
            if (self._closed or len(self._pending) >= self.MAX_PENDING
                    or selected.selection_handle in self._pending):
                raise AuthorityDenied("native.input.capacity", "selected native input queue is full or replayed")
            self._pending[selected.selection_handle] = row
            self._changed.notify_all()

    def take_selected_native_input(self, *, peer_uid: int, peer_pid: int,
                                   peer_pidfd: int) -> NativeInitialInputDelivery | None:
        """Take the single queue entry for this authenticated kernel peer."""
        if (type(peer_uid) is not int or peer_uid <= 0 or type(peer_pid) is not int
                or peer_pid <= 0 or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("native.input.take", "authenticated producer peer is malformed")
        with self._changed:
            self._prune_locked(self.monotonic())
            candidates = [row for row in self._pending.values()
                          if row.state == "pending" and row.pid == peer_pid and row.uid == peer_uid]
            if not candidates:
                return None
            if len(candidates) != 1:
                raise AuthorityDenied("native.input.take", "authenticated peer has ambiguous queued inputs")
            row = candidates[0]
            row.state = "taking"
        try:
            self.selected_executions.revalidate_selected_native_peer(
                row.selected_execution, peer_uid=peer_uid, peer_pid=peer_pid,
                peer_pidfd=peer_pidfd,
                loader_ready_event_id=row.event.native_loader_ready_event_id,
            )
            handle = self.source_observers.take_source_receipt(
                row.handle, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
            if str(handle) != row.handle:
                raise AuthorityDenied("native.input.take", "source registry delivered a different receipt")
            self.source_observers.resolve_delivered_source_receipt(
                row.handle, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
            response = NativeInitialInputDelivery(
                schema=1, source_receipt_handle=row.handle,
                selected_execution_handle=row.selected_execution.selection_handle,
                input_sha256=row.event.payload_sha256,
                input_size_bytes=row.event.payload_size_bytes,
                expires_monotonic=row.expires_monotonic,
                turn_handle=row.turn_handle,
            )
        except BaseException:
            with self._changed:
                self._pending.pop(row.selected_execution.selection_handle, None)
                self._changed.notify_all()
            self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
            raise
        with self._changed:
            current = self._pending.get(row.selected_execution.selection_handle)
            if current is not row or self._closed:
                self._pending.pop(row.selected_execution.selection_handle, None)
                self._changed.notify_all()
                self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
                raise AuthorityDenied("native.input.take", "queued input was cancelled during delivery")
            row.response = response
            row.state = "delivered"
            self._changed.notify_all()
        return response

    def wait_delivered(self, selected_execution: RootSelectedNativeExecution, *,
                       timeout: float, cancelled: Callable[[], bool]) -> NativeInitialInputDelivery:
        """Wait only for the actual producer RPC take, with a finite deadline."""
        selected = self.selected_executions.resolve_current_execution(selected_execution)
        if (type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 30.0 or not callable(cancelled)):
            raise AuthorityDenied("native.input.wait", "delivery wait bounds are invalid")
        deadline = min(self.monotonic() + timeout, selected.expires_monotonic)
        with self._changed:
            while True:
                row = self._pending.get(selected.selection_handle)
                if row is None or row.selected_execution is not selected:
                    raise AuthorityDenied("native.input.wait", "selected input is not queued")
                if row.state == "delivered" and row.response is not None:
                    self._pending.pop(selected.selection_handle, None)
                    return row.response
                if row.state == "failed" or self._closed:
                    raise AuthorityDenied("native.input.wait", "selected input delivery was revoked")
                if cancelled():
                    self._pending.pop(selected.selection_handle, None)
                    self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
                    raise AuthorityDenied("native.input.cancelled", "selected input delivery was cancelled")
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    self._pending.pop(selected.selection_handle, None)
                    self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
                    raise AuthorityDenied("native.input.wait", "selected producer did not take input before its deadline")
                self._changed.wait(min(remaining, 0.05))

    def cancel_selected_input(self, selected_execution: RootSelectedNativeExecution) -> bool:
        """Revoke the queued handle when its root task is cancelled or fails."""
        if type(selected_execution) is not RootSelectedNativeExecution:
            raise AuthorityDenied("native.input.cancelled", "selected execution token is invalid")
        with self._changed:
            row = self._pending.get(selected_execution.selection_handle)
            if row is None or row.selected_execution is not selected_execution:
                return False
            self._pending.pop(selected_execution.selection_handle, None)
            self._changed.notify_all()
        return self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))

    def _prune_locked(self, now: float) -> None:
        for key, row in tuple(self._pending.items()):
            if (row.expires_monotonic <= now
                    or row.authority_epoch != self.service.authority_epoch
                    or row.service_generation_digest != self.service.service_generation_digest):
                self._pending.pop(key, None)
                try:
                    self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
                except AuthorityDenied:
                    pass

    def prune(self) -> None:
        with self._changed:
            self._prune_locked(self.monotonic())
            self._changed.notify_all()

    def close(self) -> None:
        with self._changed:
            self._closed = True
            rows = tuple(self._pending.values())
            self._pending.clear()
            self._changed.notify_all()
        for row in rows:
            try:
                self.source_observers.revoke_source_handle(SourceReceiptHandle(row.handle))
            except AuthorityDenied:
                pass


def _identifier(value: Any, name: str) -> None:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(char) < 0x21 or char in "\\\x7f" for char in value)):
        raise ValueError(f"{name} is invalid")


def __getattr__(name: str) -> Any:
    """Preserve the v31 public location without duplicating its implementation."""
    if name in {"RootTaskNativeObservationRegistry", "RootTaskNativeExecutionReceipt"}:
        from . import task_native_observation
        return getattr(task_native_observation, name)
    raise AttributeError(name)
