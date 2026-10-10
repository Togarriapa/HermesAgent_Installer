"""Root-retained whole-turn observation for the pinned Hermes runtime.

This module deliberately accepts only root-owned event handles and retained
registry records.  Worker text, turn labels, and success flags are never
completion evidence.  The public RPC returns an opaque presentation; the
reconstructed transcript stays behind the root memory-capture boundary.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, canonical_bytes, canonical_digest

_MAX_TURNS = 256
_MAX_TURN_EVENTS = 512
_MAX_TRANSCRIPT_BYTES = 1_048_576
_MAX_TRANSCRIPT_EVENTS = 4096
_HANDLE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class RootCompletedNativeTurn:
    """Root-only completion record; callers receive handles, never transcript."""

    schema: int
    receipt_handle: str
    turn_handle: str
    selected_execution_handle: str
    profile_id: str
    process_generation: str
    native_package_generation: str
    service_generation_digest: str
    input_receipt_handle: str
    request_receipt_handles: tuple[str, ...]
    response_receipt_handles: tuple[str, ...]
    tool_result_receipt_handles: tuple[str, ...]
    delegation_receipt_handles: tuple[str, ...]
    transcript_sha256: str
    transcript_size_bytes: int
    parent_closure_digest: str
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        handles = (self.receipt_handle, self.turn_handle, self.selected_execution_handle,
                   self.input_receipt_handle)
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(item, str) or _HANDLE.fullmatch(item) is None
                       for item in handles)
                or not all(isinstance(item, str) and item for item in (
                    self.profile_id, self.process_generation,
                    self.native_package_generation))
                or any(not isinstance(item, tuple) or len(item) > _MAX_TURN_EVENTS
                       or any(not isinstance(handle, str) or _HANDLE.fullmatch(handle) is None
                              for handle in item)
                       or len(set(item)) != len(item)
                       for item in (self.request_receipt_handles,
                                    self.response_receipt_handles,
                                    self.tool_result_receipt_handles,
                                    self.delegation_receipt_handles))
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or not _DIGEST.fullmatch(self.transcript_sha256)
                or not _DIGEST.fullmatch(self.parent_closure_digest)
                or type(self.transcript_size_bytes) is not int
                or not 1 <= self.transcript_size_bytes <= _MAX_TRANSCRIPT_BYTES
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or not self.issued_monotonic < self.expires_monotonic <= self.issued_monotonic + 300.0):
            raise ValueError("root completed turn record is malformed")


@dataclass(frozen=True, slots=True)
class RootProviderResponseObservation:
    """Root response row exported only by the provider response registry."""

    response_observation_handle: str
    final_response_delivery_handle: str | None
    native_request_handle: str
    source_receipt_handles: tuple[str, ...]
    response_receipt_handle: str
    response_bytes: bytes = field(repr=False)
    response_sha256: str
    producer_identity: Any = field(repr=False, compare=False)
    producer_pid: int
    producer_pidfd: int = field(repr=False, compare=False)
    profile_id: str
    process_generation: str
    native_package_generation: str
    observer_enrollment_id: str
    service_generation_digest: str
    expires_monotonic: float
    complete: bool
    pending_tool_call_handles: tuple[str, ...]
    pending_delegation_handles: tuple[str, ...] = ()
    response_status: int = 200
    response_headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    request_context: Any = field(default=None, repr=False, compare=False)
    authorization: Any = field(default=None, repr=False, compare=False)
    target: str = ""
    recipient: str = ""
    request_sha256: str = ""
    retry_index: int = 0
    gateway_identity: Any = field(default=None, repr=False, compare=False)
    gateway_pid: int = 0
    gateway_pidfd: int = field(default=-1, repr=False, compare=False)
    loaded_package_proof: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (not _HANDLE.fullmatch(self.response_observation_handle)
                or (self.final_response_delivery_handle is not None
                    and not _HANDLE.fullmatch(self.final_response_delivery_handle))
                or not _HANDLE.fullmatch(self.native_request_handle)
                or not isinstance(self.source_receipt_handles, tuple)
                or not self.source_receipt_handles or len(self.source_receipt_handles) > 128
                or any(not _HANDLE.fullmatch(item) for item in self.source_receipt_handles)
                or not _HANDLE.fullmatch(self.response_receipt_handle)
                or not isinstance(self.response_bytes, bytes)
                or not 1 <= len(self.response_bytes) <= 4 * 1024 * 1024
                or not _DIGEST.fullmatch(self.response_sha256)
                or hashlib.sha256(self.response_bytes).hexdigest() != self.response_sha256
                or type(self.producer_pid) is not int or self.producer_pid <= 0
                or type(self.producer_pidfd) is not int or self.producer_pidfd < 0
                or not isinstance(self.profile_id, str) or not self.profile_id
                or not isinstance(self.process_generation, str) or not self.process_generation
                or not isinstance(self.native_package_generation, str) or not self.native_package_generation
                or not isinstance(self.observer_enrollment_id, str) or not self.observer_enrollment_id
                or not _DIGEST.fullmatch(self.service_generation_digest)
                or not math.isfinite(self.expires_monotonic)
                or type(self.complete) is not bool
                or not isinstance(self.pending_tool_call_handles, tuple)
                or len(self.pending_tool_call_handles) > 128
                or any(not _HANDLE.fullmatch(item) for item in self.pending_tool_call_handles)
                or not isinstance(self.pending_delegation_handles, tuple)
                or len(self.pending_delegation_handles) > 128
                or any(not _HANDLE.fullmatch(item) for item in self.pending_delegation_handles)
                or self.final_response_delivery_handle is not None
                or type(self.response_status) is not int or not 200 <= self.response_status < 300
                or not isinstance(self.response_headers, Mapping) or len(self.response_headers) > 32
                or any(not isinstance(key, str) or not key or len(key) > 256
                       or not isinstance(value, str) or len(value) > 4096
                       for key, value in self.response_headers.items())
                or self.request_context is None or self.authorization is None
                or self.producer_identity is None or self.gateway_identity is None
                or self.loaded_package_proof is None
                or not isinstance(self.target, str) or not self.target
                or not isinstance(self.recipient, str) or not self.recipient
                or not _DIGEST.fullmatch(self.request_sha256)
                or type(self.retry_index) is not int or not 0 <= self.retry_index <= 100
                or type(self.gateway_pid) is not int or self.gateway_pid <= 0
                or type(self.gateway_pidfd) is not int or self.gateway_pidfd < 0):
            raise ValueError("root provider response observation is malformed")


@dataclass(frozen=True, slots=True)
class RootTurnTranscriptEvent:
    """Verified event bytes supplied to the root-selected transcript parser."""

    kind: str
    receipt_handle: str
    source_kind: str
    payload_bytes: bytes = field(repr=False)


def build_root_turn_transcript(events: tuple[RootTurnTranscriptEvent, ...]) -> bytes:
    """Serialize only the exact root-retained ordered event bytes.

    This representation is intentionally an event transcript, not a claim
    that the underlying SDK payloads are already normalized chat messages.
    Downstream memory extraction treats the bounded JSON as private captured
    text and applies its own selected serializer/consent policy.
    """
    allowed_kinds = {"input", "request", "response", "tool-result", "delegation-result"}
    if not isinstance(events, tuple) or not 1 <= len(events) <= _MAX_TRANSCRIPT_EVENTS:
        raise AuthorityDenied("native.turn.transcript", "root event transcript is outside its event bound")
    rows: list[dict[str, Any]] = []
    total_payload_bytes = 0
    for sequence, event in enumerate(events):
        if (type(event) is not RootTurnTranscriptEvent
                or event.kind not in allowed_kinds
                or not isinstance(event.receipt_handle, str)
                or _HANDLE.fullmatch(event.receipt_handle) is None
                or not isinstance(event.source_kind, str) or not event.source_kind
                or len(event.source_kind) > 128
                or not isinstance(event.payload_bytes, bytes)):
            raise AuthorityDenied("native.turn.transcript", "root event transcript contains a malformed event")
        total_payload_bytes += len(event.payload_bytes)
        if total_payload_bytes > _MAX_TRANSCRIPT_BYTES:
            raise AuthorityDenied("native.turn.transcript", "root event transcript exceeds its payload bound")
        rows.append({
            "sequence": sequence,
            "event_kind": event.kind,
            "receipt_handle": event.receipt_handle,
            "source_kind": event.source_kind,
            "payload_sha256": hashlib.sha256(event.payload_bytes).hexdigest(),
            "payload_size_bytes": len(event.payload_bytes),
            "payload_b64": base64.b64encode(event.payload_bytes).decode("ascii"),
        })
    result = canonical_bytes({
        "schema": 1,
        "format": "root-observed-turn-events-v1",
        "events": rows,
    })
    if len(result) > _MAX_TRANSCRIPT_BYTES:
        raise AuthorityDenied("native.turn.transcript", "serialized root event transcript exceeds its bound")
    return result


@dataclass(slots=True)
class _Turn:
    handle: str
    selected: Any
    input_receipt_handle: str
    input_event: Any
    peer_identity: Any
    peer_pid: int
    peer_uid: int
    profile_id: str
    generation: str
    package_generation: str
    service_generation_digest: str
    parent_closure_digest: str
    expires_monotonic: float
    parent_source_handles: list[str] = field(default_factory=list)
    request_handles: list[str] = field(default_factory=list)
    request_receipts: list[str] = field(default_factory=list)
    request_observations: dict[str, Any] = field(default_factory=dict)
    request_sha256_by_handle: dict[str, str] = field(default_factory=dict)
    request_retry_index_by_handle: dict[str, int] = field(default_factory=dict)
    event_order: list[tuple[str, str]] = field(default_factory=list)
    response_handles: list[str] = field(default_factory=list)
    response_receipts: list[str] = field(default_factory=list)
    tool_result_receipts: list[str] = field(default_factory=list)
    delegation_receipts: list[str] = field(default_factory=list)
    pending_tool_handles: set[str] = field(default_factory=set)
    pending_delegation_handles: set[str] = field(default_factory=set)
    pending_tool_parent_receipt_ids: dict[str, str] = field(default_factory=dict)
    pending_delegation_parent_receipt_ids: dict[str, str] = field(default_factory=dict)
    final_response_handle: str | None = None
    final_response_observation_handle: str | None = None
    finished: bool = False


class RootNativeTurnObservationRegistry:
    """Join actual selected input, native requests/results, and final return.

    `response_resolver` must be a root-owned getter on the exact installed
    provider response registry. It returns ``RootProviderResponseObservation``
    only for bytes already captured and validated by that registry.
    """

    def __init__(self, *, service: Any, selected_execution_registry: Any,
                 input_observer: Any, source_observers: Any,
                 process_custody: Any, response_resolver: Callable[[str], Any],
                 transcript_builder: Callable[[tuple[RootTurnTranscriptEvent, ...]], bytes],
                 native_bridge_broker: Any | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (service is None
                or not callable(getattr(selected_execution_registry, "resolve_current_execution", None))
                or not callable(getattr(selected_execution_registry, "resolve_selection_handle", None))
                or not callable(getattr(input_observer, "resolve_event_for_source_handle", None))
                or not callable(getattr(source_observers, "resolve_delivered_source_receipt", None))
                or not callable(getattr(process_custody, "resolve_managed_task_process_handle", None))
                or not callable(response_resolver)
                or (native_bridge_broker is not None and not callable(
                    getattr(native_bridge_broker, "resolve_native_request_observation", None)))
                or not callable(transcript_builder)
                or not callable(monotonic)):
            raise ValueError("root native turn observation dependencies are incomplete")
        self.service = service
        self.selected_executions = selected_execution_registry
        self.input_observer = input_observer
        self.source_observers = source_observers
        self.process_custody = process_custody
        self.response_resolver = response_resolver
        self.native_bridge_broker = native_bridge_broker
        self.transcript_builder = transcript_builder
        self.monotonic = monotonic
        self._turns: dict[str, _Turn] = {}
        self._by_source: dict[str, set[str]] = {}
        self._begun_inputs: dict[str, float] = {}
        self._completed: dict[str, tuple[RootCompletedNativeTurn, bytearray]] = {}
        self._persisting_completed: set[str] = set()
        self._used_final_responses: dict[str, float] = {}
        self._memory_capture_coordinator: Any | None = None
        self._lock = threading.RLock()
        self._closed = False

    def attach_native_request_broker(self, broker: Any) -> None:
        """Attach the exact HI11 broker once, closing the turn/request cycle."""
        from .native_bridge import NativeBridgeBroker

        if (type(broker) is not NativeBridgeBroker or broker.service is not self.service
                or not callable(getattr(broker, "resolve_native_request_observation", None))
                or not callable(getattr(broker, "request_bytes", None))):
            raise AuthorityDenied("native.turn.request", "selected native request broker is incompatible")
        with self._lock:
            if self.native_bridge_broker is not None:
                raise AuthorityDenied("native.turn.request", "native request broker is already attached")
            self.native_bridge_broker = broker

    def begin_selected_turn(self, selected_execution_handle: str,
                            actual_native_input_receipt_handle: str) -> str:
        """Begin only from a retained selected execution and captured input."""
        if not self._valid_handle(selected_execution_handle) or not self._valid_handle(
                actual_native_input_receipt_handle):
            raise AuthorityDenied("native.turn.begin", "selected input handle is malformed")
        selected = self.selected_executions.resolve_selection_handle(selected_execution_handle)
        current = self.selected_executions.resolve_current_execution(selected)
        if current is not selected:
            raise AuthorityDenied("native.turn.selection", "selected execution changed before turn begin")
        event = self.input_observer.resolve_event_for_source_handle(actual_native_input_receipt_handle)
        if (event.source_receipt_handle != actual_native_input_receipt_handle
                or event.producer_profile_id != selected.profile_id
                or event.producer_generation != selected.generation
                or event.expires_monotonic <= self.monotonic()
                or event.native_loader_ready_event_id
                != self.selected_executions.loader_ready_event_id(selected)):
            raise AuthorityDenied("native.turn.input", "input event does not bind the selected live execution")
        lease = self.process_custody.resolve_managed_task_process_handle(selected.process_handle)
        if lease is None:
            raise AuthorityDenied("native.turn.peer", "selected turn producer is no longer live")
        try:
            identity = self.process_custody.resolve_live_peer(
                lease.pid, lease.pidfd, profile_id=selected.profile_id,
                generation=selected.generation,
            )
            if identity is None or identity != lease.identity:
                raise AuthorityDenied("native.turn.peer", "selected turn producer identity changed")
            with self.source_observers._lock:
                retained = self.source_observers._payload_capsules.get(
                    actual_native_input_receipt_handle)
                delivery = self.source_observers._receipt_delivery_bindings.get(
                    actual_native_input_receipt_handle)
                if retained is None or delivery is None:
                    raise AuthorityDenied("native.turn.input", "captured input receipt is not retained")
                if (delivery.delivered or delivery.authority_epoch != self.service.authority_epoch
                        or delivery.pid != lease.pid or delivery.uid != lease.uid
                        or delivery.identity != identity
                        or delivery.profile_id != selected.profile_id
                        or delivery.generation != selected.generation
                        or delivery.expires <= self.monotonic()):
                    raise AuthorityDenied("native.turn.input", "captured input is not queued for the selected peer")
        finally:
            lease.close()
        receipt = self._retained_source(actual_native_input_receipt_handle)
        if (receipt.payload_digest != event.payload_sha256
                or receipt.profile_id != selected.profile_id
                or receipt.process_generation != selected.generation
                or receipt.parent_lineage_hash != selected.execution_handle.parent_closure_digest):
            raise AuthorityDenied("native.turn.input", "retained input receipt differs from captured bytes")
        now = self.monotonic()
        expires = min(float(event.expires_monotonic), float(selected.expires_monotonic),
                      float(receipt.monotonic_expires_at))
        with self._lock:
            self._prune_locked(now)
            if (self._closed or len(self._turns) >= _MAX_TURNS or now >= expires
                    or actual_native_input_receipt_handle in self._begun_inputs):
                raise AuthorityDenied("native.turn.capacity", "selected turn registry is unavailable")
            handle = self._opaque()
            turn = _Turn(
                handle=handle, selected=selected,
                input_receipt_handle=actual_native_input_receipt_handle,
                input_event=event, peer_identity=identity, peer_pid=lease.pid,
                peer_uid=lease.uid, profile_id=selected.profile_id,
                generation=selected.generation,
                package_generation=selected.native_package_generation,
                service_generation_digest=selected.service_generation_digest,
                parent_closure_digest=event.parent_closure_digest,
                expires_monotonic=expires,
            )
            self._turns[handle] = turn
            turn.event_order.append(("input", actual_native_input_receipt_handle))
            self._begun_inputs[actual_native_input_receipt_handle] = expires
            self._by_source.setdefault(actual_native_input_receipt_handle, set()).add(handle)
            return handle

    def resolve_turn_for_source(self, source_receipt_handle: str,
                                live_producer_identity: Any) -> str:
        """Resolve lexical ancestry from a root receipt and current peer."""
        if not self._valid_handle(source_receipt_handle):
            raise AuthorityDenied("native.turn.source", "source receipt handle is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            candidates = [self._turns[item] for item in self._by_source.get(source_receipt_handle, ())
                          if item in self._turns and not self._turns[item].finished]
        matched = [turn for turn in candidates if turn.peer_identity == live_producer_identity
                   and self.selected_executions.resolve_current_execution(turn.selected) is turn.selected]
        if len(matched) != 1:
            raise AuthorityDenied("native.turn.source", "receipt has no unique current selected turn")
        return matched[0].handle

    def register_native_request(self, turn_handle: str, native_request_handle: str,
                                request_observation_handle: str,
                                request_source_receipt_handles: tuple[str, ...],
                                live_producer_identity: Any, request_sha256: str,
                                retry_index: int) -> None:
        """Attach a broker-retained exact request to its source-derived turn.

        The request handle is only a lookup key. The broker re-resolves its
        retained producer, body bytes, parent closure, generations and lease
        against this exact root turn; no request fields are accepted here.
        """
        if (not self._valid_handle(turn_handle)
                or not self._valid_handle(native_request_handle)
                or not self._valid_handle(request_observation_handle)
                or not isinstance(request_source_receipt_handles, tuple)
                or not request_source_receipt_handles
                or len(request_source_receipt_handles) > 128
                or any(not self._valid_handle(item) for item in request_source_receipt_handles)
                or not _DIGEST.fullmatch(request_sha256)
                or type(retry_index) is not int or not 0 <= retry_index <= 100):
            raise AuthorityDenied("native.turn.request", "root native request binding is malformed")
        broker = self.native_bridge_broker
        if broker is None:
            raise AuthorityDenied("native.turn.request", "root native request broker is unavailable")
        with self._lock:
            self._prune_locked(self.monotonic())
            turn = self._turns.get(turn_handle)
            if (turn is None or turn.finished
                    or request_observation_handle in turn.request_receipts
                    or native_request_handle in turn.request_handles
                    or len(turn.request_handles) >= _MAX_TURN_EVENTS):
                raise AuthorityDenied("native.turn.request", "native request is foreign, replayed, or unselected")
            request = broker.resolve_native_request_observation(
                request_observation_handle, turn_handle=turn_handle)
            from .native_bridge import RootNativeRequestObservation
            request_bytes = broker.request_bytes(
                request_observation_handle, live_producer_identity)
            for handle in request_source_receipt_handles:
                receipt = self._retained_source(handle)
                if (receipt.profile_id != turn.profile_id
                        or receipt.process_generation != turn.generation
                        or receipt.monotonic_expires_at <= self.monotonic()):
                    raise AuthorityDenied("native.turn.request", "request parent receipt is stale or foreign")
            expected_parent_ids = self._source_closure_ids(request_source_receipt_handles)
            expected_identity_digest = self._identity_digest(live_producer_identity)
            if (type(request) is not RootNativeRequestObservation
                    or request.receipt_handle != request_observation_handle
                    or request.native_request_handle != native_request_handle
                    or live_producer_identity != turn.peer_identity
                    or request.producer_process_identity != expected_identity_digest
                    or request.producer_profile_id != turn.profile_id
                    or request.producer_process_generation != turn.generation
                    or request.native_package_generation != turn.package_generation
                    or request.parent_source_receipt_handles != request_source_receipt_handles
                    or not isinstance(request.context_digest, str)
                    or not _DIGEST.fullmatch(request.context_digest)
                    or request.request_sha256 != request_sha256
                    or request.retry_index != retry_index
                    or request.expires_monotonic > turn.expires_monotonic
                    or request.expires_monotonic <= self.monotonic()
                    or request.request_size_bytes <= 0
                    or request.request_size_bytes > 4 * 1024 * 1024
                    or not _DIGEST.fullmatch(request.request_sha256)
                    or not isinstance(request_bytes, bytes)
                    or hashlib.sha256(request_bytes).hexdigest() != request.request_sha256
                    or len(request_bytes) != request.request_size_bytes
                    or expected_parent_ids != self._source_closure_ids(request.parent_source_receipt_handles)
                    or request.parent_closure_digest != canonical_digest(sorted(expected_parent_ids))):
                raise AuthorityDenied("native.turn.request", "native request observation does not retain exact turn ancestry")
            if not request_source_receipt_handles or not any(
                    turn_handle in self._by_source.get(item, set())
                    for item in request_source_receipt_handles):
                raise AuthorityDenied("native.turn.request", "native request has no source ancestry in this turn")
            if (request.context_digest != getattr(turn, "current_context_digest", request.context_digest)
                    and request.context_digest is None):
                raise AuthorityDenied("native.turn.request", "native request context digest is unavailable")
            for handle in request_source_receipt_handles:
                self._by_source.setdefault(handle, set()).add(turn_handle)
            turn.request_handles.append(native_request_handle)
            turn.request_receipts.append(request_observation_handle)
            turn.request_observations[native_request_handle] = (request, request_bytes)
            turn.event_order.append(("request", request_observation_handle))
            turn.request_sha256_by_handle[native_request_handle] = request.request_sha256
            turn.request_retry_index_by_handle[native_request_handle] = request.retry_index
            turn.parent_source_handles.extend(item for item in request_source_receipt_handles
                                              if item not in turn.parent_source_handles)
            turn.final_response_handle = None

    def register_brokered_response(self, turn_handle: str,
                                   root_response_observation_handle: str) -> str | None:
        """Associate actual complete response bytes with one retained turn.

        The response resolver is root-installed. A parsed tool call or pending
        delegation makes the response non-final and returns no finish handle.
        """
        if (not self._valid_handle(turn_handle)
                or not self._valid_handle(root_response_observation_handle)):
            raise AuthorityDenied("native.turn.response", "provider observation handle is malformed")
        response = self.response_resolver(root_response_observation_handle)
        if type(response) is not RootProviderResponseObservation:
            raise AuthorityDenied("native.turn.response", "provider response is not a root-retained observation")
        with self._lock:
            self._prune_locked(self.monotonic())
            turn = self._turns.get(turn_handle)
            if (turn is None or turn.finished or response.response_observation_handle
                    != root_response_observation_handle
                    or response.profile_id != turn.profile_id
                    or response.process_generation != turn.generation
                    or response.native_package_generation != turn.package_generation
                    or response.service_generation_digest != turn.service_generation_digest
                    or response.producer_identity != turn.peer_identity
                    or response.producer_pid != turn.peer_pid
                    or response.expires_monotonic > turn.expires_monotonic
                    or response.expires_monotonic <= self.monotonic()
                    or hashlib.sha256(response.response_bytes).hexdigest() != response.response_sha256
                    or response.response_receipt_handle not in response.source_receipt_handles
                    or response.native_request_handle not in turn.request_handles
                    or turn.request_sha256_by_handle.get(response.native_request_handle)
                       != response.request_sha256
                    or turn.request_retry_index_by_handle.get(response.native_request_handle)
                       != response.retry_index
                    or root_response_observation_handle in turn.response_handles
                    or not any(turn_handle in self._by_source.get(handle, set())
                               for handle in response.source_receipt_handles)
                    or not response.complete):
                raise AuthorityDenied("native.turn.response", "provider response does not join current turn")
            if any(handle != response.response_receipt_handle
                   and turn_handle not in self._by_source.get(handle, set())
                   for handle in response.source_receipt_handles):
                raise AuthorityDenied("native.turn.response", "provider response includes foreign parent ancestry")
            response_receipt = self._retained_source(response.response_receipt_handle)
            response_parent_ids = {
                self._retained_source(handle).receipt_id
                for handle in response.source_receipt_handles
                if handle != response.response_receipt_handle
            }
            if (response_receipt.profile_id != turn.profile_id
                    or response_receipt.process_generation != turn.generation
                    or response_receipt.monotonic_expires_at <= self.monotonic()
                    or response_receipt.payload_digest != response.response_sha256
                    or set(response_receipt.parent_receipt_ids) != response_parent_ids):
                raise AuthorityDenied("native.turn.response", "response receipt does not bind exact body and parent set")
            if (any(item in turn.pending_tool_parent_receipt_ids
                    for item in response.pending_tool_call_handles)
                    or any(item in turn.pending_delegation_parent_receipt_ids
                           for item in response.pending_delegation_handles)):
                raise AuthorityDenied("native.turn.response", "observed call or delegation handle was reused")
            for source_handle in response.source_receipt_handles:
                self._by_source.setdefault(source_handle, set()).add(turn.handle)
                if source_handle not in turn.parent_source_handles:
                    turn.parent_source_handles.append(source_handle)
            turn.response_handles.append(root_response_observation_handle)
            turn.response_receipts.append(response.response_receipt_handle)
            turn.event_order.append(("response", response.response_receipt_handle))
            turn.pending_tool_handles.update(response.pending_tool_call_handles)
            turn.pending_delegation_handles.update(response.pending_delegation_handles)
            for call_handle in response.pending_tool_call_handles:
                turn.pending_tool_parent_receipt_ids[call_handle] = response.response_receipt_handle
            for delegation_handle in response.pending_delegation_handles:
                turn.pending_delegation_parent_receipt_ids[delegation_handle] = response.response_receipt_handle
            turn.final_response_observation_handle = root_response_observation_handle
            # The completion handle is minted by this registry only after it
            # has joined the provider's retained bytes to the active turn.
            # Provider DTOs cannot choose or pre-authorize a final response.
            turn.final_response_handle = None
            if (not turn.pending_tool_handles and not turn.pending_delegation_handles
                    and response.final_response_delivery_handle is None):
                turn.final_response_handle = self._opaque()
            return turn.final_response_handle

    def record_tool_result(self, turn_handle: str, result_receipt_handle: str,
                           *, live_producer_identity: Any,
                           observed_call_handle: str) -> None:
        """Record a root-observed tool result receipt already tied to this turn."""
        if (not self._valid_handle(turn_handle) or not self._valid_handle(result_receipt_handle)
                or not self._valid_handle(observed_call_handle)):
            raise AuthorityDenied("native.turn.tool", "tool result receipt is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            turn = self._turns.get(turn_handle)
            if (turn is None or turn.finished or live_producer_identity != turn.peer_identity
                    or observed_call_handle not in turn.pending_tool_handles
                    or len(turn.tool_result_receipts) >= _MAX_TURN_EVENTS):
                raise AuthorityDenied("native.turn.tool", "tool result does not belong to an active turn")
            receipt = self._retained_source(result_receipt_handle)
            if (receipt.profile_id != turn.profile_id
                    or receipt.process_generation != turn.generation
                    or receipt.monotonic_expires_at <= self.monotonic()
                    or self._required_parent_receipt_id(observed_call_handle, turn, "tool")
                       not in receipt.parent_receipt_ids):
                raise AuthorityDenied("native.turn.tool", "tool result source receipt is stale or foreign")
            turn.tool_result_receipts.append(result_receipt_handle)
            turn.event_order.append(("tool-result", result_receipt_handle))
            turn.pending_tool_handles.remove(observed_call_handle)
            turn.pending_tool_parent_receipt_ids.pop(observed_call_handle, None)
            turn.final_response_handle = None
            self._by_source.setdefault(result_receipt_handle, set()).add(turn.handle)

    def record_delegation_result(self, turn_handle: str, result_receipt_handle: str,
                                 *, live_producer_identity: Any,
                                 delegation_handle: str) -> None:
        if (not self._valid_handle(turn_handle) or not self._valid_handle(result_receipt_handle)
                or not self._valid_handle(delegation_handle)):
            raise AuthorityDenied("native.turn.delegate", "delegation result binding is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            turn = self._turns.get(turn_handle)
            if (turn is None or turn.finished or live_producer_identity != turn.peer_identity
                    or delegation_handle not in turn.pending_delegation_handles
                    or len(turn.delegation_receipts) >= _MAX_TURN_EVENTS):
                raise AuthorityDenied("native.turn.delegate", "delegation result is foreign or unselected")
            receipt = self._retained_source(result_receipt_handle)
            if (receipt.profile_id != turn.profile_id
                    or receipt.process_generation != turn.generation
                    or receipt.monotonic_expires_at <= self.monotonic()
                    or self._required_parent_receipt_id(delegation_handle, turn, "delegation")
                       not in receipt.parent_receipt_ids):
                raise AuthorityDenied("native.turn.delegate", "delegation receipt is stale or foreign")
            turn.delegation_receipts.append(result_receipt_handle)
            turn.event_order.append(("delegation-result", result_receipt_handle))
            turn.pending_delegation_handles.remove(delegation_handle)
            turn.pending_delegation_parent_receipt_ids.pop(delegation_handle, None)
            turn.final_response_handle = None
            self._by_source.setdefault(result_receipt_handle, set()).add(turn.handle)

    def finish_selected_native_turn(self, peer_uid: int, peer_pid: int, peer_pidfd: int,
                                    turn_handle: str,
                                    final_response_delivery_handle: str) -> Any:
        """Complete only from a matching root-observed final response."""
        from .types import RootCompletedNativeTurnPresentation

        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not self._valid_handle(turn_handle)
                or not self._valid_handle(final_response_delivery_handle)):
            raise AuthorityDenied("native.turn.finish", "turn finish request is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            turn = self._turns.get(turn_handle)
            if (turn is None or turn.finished or turn.final_response_handle is None
                    or turn.final_response_handle != final_response_delivery_handle
                    or turn.pending_tool_handles or turn.pending_delegation_handles
                    or final_response_delivery_handle in self._used_final_responses
                    or peer_uid != turn.peer_uid or peer_pid != turn.peer_pid):
                raise AuthorityDenied("native.turn.finish", "turn is incomplete, foreign, or already finished")
            if self.selected_executions.resolve_current_execution(turn.selected) is not turn.selected:
                raise AuthorityDenied("native.turn.finish", "selected execution changed before completion")
        lease = self.process_custody.resolve_managed_task_process_handle(turn.selected.process_handle)
        if lease is None:
            raise AuthorityDenied("native.turn.finish", "selected turn producer exited before completion")
        try:
            current = self.process_custody.resolve_live_peer(
                peer_pid, peer_pidfd, profile_id=turn.profile_id, generation=turn.generation)
            manager_identity = self.process_custody.resolve_live_peer(
                lease.pid, lease.pidfd, profile_id=turn.profile_id, generation=turn.generation)
            if (lease.pid != turn.peer_pid or current != turn.peer_identity
                    or manager_identity != turn.peer_identity):
                raise AuthorityDenied("native.turn.peer", "turn producer PIDFD changed before completion")
        finally:
            lease.close()
        if turn.final_response_observation_handle is None:
            raise AuthorityDenied("native.turn.finish", "final response observation is unavailable")
        response = self.response_resolver(turn.final_response_observation_handle)
        if (type(response) is not RootProviderResponseObservation
                or not response.complete or response.pending_tool_call_handles
                or response.pending_delegation_handles
                or response.producer_identity != turn.peer_identity
                or response.native_request_handle not in turn.request_handles
                or response.response_observation_handle != turn.final_response_observation_handle
                or response.response_receipt_handle != turn.response_receipts[-1]
                or response.final_response_delivery_handle is not None
                or response.expires_monotonic <= self.monotonic()
                or response.response_status < 200 or response.response_status >= 300
                or hashlib.sha256(response.response_bytes).hexdigest() != response.response_sha256):
            raise AuthorityDenied("native.turn.finish", "final response observation is incomplete")
        gateway = self.process_custody.resolve_live_peer(
            response.gateway_pid, response.gateway_pidfd,
            profile_id=response.gateway_identity.profile_id,
            generation=response.gateway_identity.generation,
        )
        if gateway is None or gateway != response.gateway_identity:
            raise AuthorityDenied("native.turn.finish", "paired response gateway changed before completion")
        observer = self.source_observers.observers.get(response.observer_enrollment_id)
        if (observer is None or observer.source_kind != "provider-result"
                or observer.profile_id != turn.profile_id or observer.generation != turn.generation):
            raise AuthorityDenied("native.turn.finish", "selected source observer is no longer enrolled")
        package, _adapter = self.source_observers._resolve_package_role(observer)
        proof = self.source_observers._resolve_loaded_package_proof(
            current, observer, package, self.monotonic(),
            peer_pid=peer_pid, peer_pidfd=peer_pidfd,
        )
        if proof != response.loaded_package_proof:
            raise AuthorityDenied("native.turn.finish", "selected native package closure changed before completion")
        transcript = self._reconstruct_transcript(turn)
        digest = hashlib.sha256(transcript).hexdigest()
        now = self.monotonic()
        receipt_handle = self._opaque()
        parent_ids = self._parent_receipt_ids(turn)
        completed = RootCompletedNativeTurn(
            schema=1, receipt_handle=receipt_handle, turn_handle=turn.handle,
            selected_execution_handle=turn.selected.selection_handle,
            profile_id=turn.profile_id, process_generation=turn.generation,
            native_package_generation=turn.package_generation,
            service_generation_digest=turn.service_generation_digest,
            input_receipt_handle=turn.input_receipt_handle,
            request_receipt_handles=tuple(turn.request_receipts),
            response_receipt_handles=tuple(turn.response_receipts),
            tool_result_receipt_handles=tuple(turn.tool_result_receipts),
            delegation_receipt_handles=tuple(turn.delegation_receipts),
            transcript_sha256=digest, transcript_size_bytes=len(transcript),
            parent_closure_digest=canonical_digest(list(parent_ids)),
            issued_monotonic=now, expires_monotonic=min(turn.expires_monotonic, now + 300.0),
        )
        if not now < completed.expires_monotonic or len(transcript) > _MAX_TRANSCRIPT_BYTES:
            raise AuthorityDenied("native.turn.finish", "completed transcript exceeds its lease or size bound")
        with self._lock:
            current_turn = self._turns.get(turn.handle)
            if current_turn is not turn or turn.finished or final_response_delivery_handle in self._used_final_responses:
                raise AuthorityDenied("native.turn.replay", "turn completion raced another consumer")
            turn.finished = True
            self._used_final_responses[final_response_delivery_handle] = turn.expires_monotonic
            self._completed[receipt_handle] = (completed, bytearray(transcript))
            return RootCompletedNativeTurnPresentation(
                schema=1, receipt_handle=receipt_handle, turn_handle=turn.handle,
                state="completed", expires_monotonic=completed.expires_monotonic,
            )

    def resolve_completed_turn(self, completed_turn_handle: str) -> RootCompletedNativeTurn:
        with self._lock:
            row = self._completed.get(completed_turn_handle)
            if row is None or row[0].expires_monotonic <= self.monotonic():
                raise AuthorityDenied("native.turn.completed", "completed turn handle is unavailable")
            return row[0]

    def attach_memory_capture_coordinator(self, coordinator: Any) -> None:
        """Bind the single root-selected memory consumer by object identity."""
        from ..memory.capture import RootMemoryCaptureCoordinator

        if (type(coordinator) is not RootMemoryCaptureCoordinator
                or getattr(coordinator, "service", None) is not self.service
                or not callable(getattr(coordinator, "capture_completed_turn", None))):
            raise AuthorityDenied("native.turn.memory", "selected root memory coordinator is invalid")
        with self._lock:
            if self._memory_capture_coordinator is not None:
                raise AuthorityDenied("native.turn.memory", "root memory coordinator is already attached")
            self._memory_capture_coordinator = coordinator

    def consume_completed_turn_transcript(self, completed_turn_handle: str, *,
                                          memory_capture_coordinator: Any) -> tuple[RootCompletedNativeTurn, bytes]:
        """Root-only transfer to the selected memory capture coordinator."""
        from ..memory.capture import RootMemoryCaptureCoordinator
        if (type(memory_capture_coordinator) is not RootMemoryCaptureCoordinator
                or memory_capture_coordinator is not self._memory_capture_coordinator
                or getattr(memory_capture_coordinator, "service", None) is not self.service):
            raise AuthorityDenied("native.turn.memory", "selected root memory capture coordinator is unavailable")
        with self._lock:
            if completed_turn_handle in self._persisting_completed:
                raise AuthorityDenied("native.turn.completed", "completed turn is being persisted")
            row = self._completed.pop(completed_turn_handle, None)
            if row is None or row[0].expires_monotonic <= self.monotonic():
                raise AuthorityDenied("native.turn.completed", "completed turn handle is unavailable")
            payload = bytes(row[1])
            row[1][:] = b"\0" * len(row[1])
            return row[0], payload

    def persist_completed_turn(self, completed_turn_handle: str, *,
                               memory_capture_coordinator: Any,
                               selected_memory_enrollment_id: str,
                               background_consent_handle: str) -> str:
        """Persist via the exact attached memory coordinator, then consume.

        A failed durable write leaves the retained transcript available for a
        bounded retry. The opaque turn handle is the downstream idempotency
        key, so a crash after durable enqueue cannot create a second job.
        """
        from ..memory.capture import RootMemoryCaptureCoordinator

        if (not self._valid_handle(completed_turn_handle)
                or not isinstance(selected_memory_enrollment_id, str)
                or not selected_memory_enrollment_id
                or not self._valid_handle(background_consent_handle)):
            raise AuthorityDenied("native.turn.memory", "completed-turn persistence request is malformed")
        with self._lock:
            coordinator = self._memory_capture_coordinator
            row = self._completed.get(completed_turn_handle)
            if (coordinator is None or memory_capture_coordinator is not coordinator
                    or type(memory_capture_coordinator) is not RootMemoryCaptureCoordinator
                    or getattr(memory_capture_coordinator, "service", None) is not self.service
                    or row is None or row[0].expires_monotonic <= self.monotonic()
                    or completed_turn_handle in self._persisting_completed):
                raise AuthorityDenied("native.turn.memory", "selected completed turn is unavailable")
            self._persisting_completed.add(completed_turn_handle)
        try:
            persist = getattr(coordinator, "persist_observed_turn", None)
            if not callable(persist):
                raise AuthorityDenied("native.turn.memory", "selected memory persistence path is unavailable")
            record, transcript = row
            result = persist(
                record, bytes(transcript), completed_turn_handle=completed_turn_handle,
                selected_memory_enrollment_id=selected_memory_enrollment_id,
                background_consent_handle=background_consent_handle,
            )
            if not self._valid_handle(result):
                raise AuthorityDenied("native.turn.memory", "memory persistence returned no durable receipt")
        except BaseException:
            with self._lock:
                self._persisting_completed.discard(completed_turn_handle)
            raise
        with self._lock:
            current = self._completed.get(completed_turn_handle)
            if current is not row:
                self._persisting_completed.discard(completed_turn_handle)
                raise AuthorityDenied("native.turn.memory", "completed turn changed during persistence")
            self._completed.pop(completed_turn_handle, None)
            self._persisting_completed.discard(completed_turn_handle)
            row[1][:] = b"\0" * len(row[1])
            return result

    def cancel_selected_turn(self, turn_handle: str) -> bool:
        with self._lock:
            turn = self._turns.pop(turn_handle, None)
            if turn is None or turn.finished:
                return False
            for source in tuple(self._by_source):
                handles = self._by_source[source]
                handles.discard(turn_handle)
                if not handles:
                    self._by_source.pop(source, None)
            return True

    def _retained_source(self, handle: str) -> Any:
        source = self.source_observers
        with source._lock:
            row = source._payload_capsules.get(handle)
            if row is None:
                raise AuthorityDenied("native.turn.source", "root source payload is not retained")
            return row[0]

    def _payload(self, handle: str) -> bytes:
        with self.source_observers._lock:
            row = self.source_observers._payload_capsules.get(handle)
            if row is None:
                raise AuthorityDenied("native.turn.transcript", "turn source bytes are no longer retained")
            return bytes(row[2])

    @staticmethod
    def _required_parent_receipt_id(handle: str, turn: _Turn, kind: str) -> str:
        parents = (turn.pending_tool_parent_receipt_ids if kind == "tool"
                   else turn.pending_delegation_parent_receipt_ids)
        parent_id = parents.get(handle)
        if not isinstance(parent_id, str) or not parent_id:
            raise AuthorityDenied("native.turn.lineage", "result has no root-observed parent response")
        return parent_id

    def _parent_receipt_ids(self, turn: _Turn) -> tuple[str, ...]:
        handles = tuple(dict.fromkeys((turn.input_receipt_handle, *turn.parent_source_handles,
                                      *turn.response_receipts, *turn.tool_result_receipts,
                                      *turn.delegation_receipts)))
        rows = getattr(self.service, "_source_receipt_handles", None)
        if not isinstance(rows, Mapping):
            raise AuthorityDenied("native.turn.lineage", "root source receipt index is unavailable")
        by_receipt_id = {getattr(item, "receipt_id", None): key
                         for key, item in rows.items()}
        ids: set[str] = set()
        pending = list(handles)
        while pending:
            handle = pending.pop()
            receipt = rows.get(handle)
            if receipt is None:
                raise AuthorityDenied("native.turn.lineage", "turn parent source receipt expired")
            receipt_id = receipt.receipt_id
            if receipt_id in ids:
                continue
            ids.add(receipt_id)
            if len(ids) > _MAX_TURN_EVENTS * 4:
                raise AuthorityDenied("native.turn.lineage", "turn source receipt closure is oversized")
            for parent_id in receipt.parent_receipt_ids:
                parent_handle = by_receipt_id.get(parent_id)
                if parent_handle is None:
                    raise AuthorityDenied("native.turn.lineage", "turn ancestor source receipt expired")
                pending.append(parent_handle)
        return tuple(sorted(ids))

    def _source_closure_ids(self, handles: tuple[str, ...]) -> set[str]:
        rows = getattr(self.service, "_source_receipt_handles", None)
        if not isinstance(rows, Mapping):
            raise AuthorityDenied("native.turn.lineage", "root source receipt index is unavailable")
        by_receipt_id = {getattr(item, "receipt_id", None): key for key, item in rows.items()}
        ids: set[str] = set()
        pending = list(handles)
        while pending:
            handle = pending.pop()
            receipt = rows.get(handle)
            if receipt is None:
                raise AuthorityDenied("native.turn.lineage", "request parent source receipt expired")
            if receipt.receipt_id in ids:
                continue
            ids.add(receipt.receipt_id)
            if len(ids) > _MAX_TURN_EVENTS * 4:
                raise AuthorityDenied("native.turn.lineage", "request parent closure is oversized")
            for parent_id in receipt.parent_receipt_ids:
                parent_handle = by_receipt_id.get(parent_id)
                if parent_handle is None:
                    raise AuthorityDenied("native.turn.lineage", "request ancestor source receipt expired")
                pending.append(parent_handle)
        return ids

    @staticmethod
    def _identity_digest(identity: Any) -> str:
        values = {
            "profile_id": getattr(identity, "profile_id", None),
            "generation": getattr(identity, "generation", None),
            "kernel_uid": getattr(identity, "kernel_uid", None),
            "start_ticks": getattr(identity, "start_ticks", None),
            "executable_sha256": getattr(identity, "executable_sha256", None),
            "cgroup_identity": getattr(identity, "cgroup_identity", None),
            "namespace_identity": getattr(identity, "namespace_identity", None),
        }
        if (not isinstance(values["profile_id"], str)
                or not isinstance(values["generation"], str)
                or type(values["kernel_uid"]) is not int
                or type(values["start_ticks"]) is not int
                or not _DIGEST.fullmatch(values["executable_sha256"] or "")
                or not isinstance(values["cgroup_identity"], str)
                or not isinstance(values["namespace_identity"], str)):
            raise AuthorityDenied("native.turn.peer", "live producer identity is malformed")
        return canonical_digest(values)

    def _reconstruct_transcript(self, turn: _Turn) -> bytes:
        events: list[RootTurnTranscriptEvent] = []
        request_by_observation = {row[0].receipt_handle: row
                                  for row in turn.request_observations.values()}
        if not turn.event_order and turn.input_receipt_handle:
            # Compatibility for root-only test fixtures created before event
            # ordering was populated; live turns always retain an event order.
            order = [("input", turn.input_receipt_handle)]
        else:
            order = list(turn.event_order)
        for kind, handle in order:
            if kind == "request":
                request = request_by_observation.get(handle)
                if request is None:
                    raise AuthorityDenied("native.turn.transcript", "request observation expired")
                events.append(RootTurnTranscriptEvent(
                    kind=kind, receipt_handle=handle, source_kind="native-request",
                    payload_bytes=request[1],
                ))
                continue
            receipt = self._retained_source(handle)
            events.append(RootTurnTranscriptEvent(
                kind=kind, receipt_handle=handle, source_kind=receipt.source_kind,
                payload_bytes=self._payload(handle),
            ))
        try:
            raw = self.transcript_builder(tuple(events))
        except Exception:
            raise AuthorityDenied("native.turn.transcript", "root transcript reconstruction failed") from None
        if not isinstance(raw, bytes):
            raise AuthorityDenied("native.turn.transcript", "root transcript reconstruction was malformed")
        if len(raw) > _MAX_TRANSCRIPT_BYTES:
            raise AuthorityDenied("native.turn.transcript", "complete turn exceeds the transcript bound")
        return raw

    def _prune_locked(self, now: float) -> None:
        for source_handle, expires in tuple(self._begun_inputs.items()):
            if expires <= now:
                self._begun_inputs.pop(source_handle, None)
        for handle, turn in tuple(self._turns.items()):
            if turn.expires_monotonic <= now:
                self._turns.pop(handle, None)
                for source in tuple(self._by_source):
                    self._by_source[source].discard(handle)
                    if not self._by_source[source]:
                        self._by_source.pop(source, None)
        for handle, (record, payload) in tuple(self._completed.items()):
            if record.expires_monotonic <= now:
                self._completed.pop(handle, None)
                payload[:] = b"\0" * len(payload)
                self._persisting_completed.discard(handle)
        for handle, expires in tuple(self._used_final_responses.items()):
            if expires <= now:
                self._used_final_responses.pop(handle, None)

    @staticmethod
    def _valid_handle(value: Any) -> bool:
        return isinstance(value, str) and _HANDLE.fullmatch(value) is not None

    @staticmethod
    def _opaque() -> str:
        return secrets.token_urlsafe(32)
