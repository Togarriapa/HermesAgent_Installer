"""Root-private records for exact HI11 provider request observations.

These records attest to bytes observed at the authenticated producer boundary.
They are not source receipts and cannot upgrade the sensitivity of their
signed parent receipts.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .types import AuthorityDenied, HostContext, SourceReceipt, canonical_digest

MAX_REQUEST_RECORDS = 256
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RootNativeRequestObservation:
    """Immutable evidence fields; exact bytes and PIDFD stay root-private."""

    schema: int
    receipt_handle: str
    native_request_handle: str
    bridge_id: str
    producer_profile_id: str
    producer_process_generation: str
    native_package_generation: str
    producer_process_identity: str
    request_sha256: str
    request_size_bytes: int
    retry_index: int
    parent_source_receipt_handles: tuple[str, ...]
    parent_closure_digest: str
    context_digest: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(slots=True)
class _RequestRecord:
    observation: RootNativeRequestObservation
    bridge: Any
    producer_pid: int
    producer_pidfd: int
    producer_identity: Any
    canonical_request_bytes: bytearray
    native_request_handle: str
    parent_receipts: tuple[SourceReceipt, ...]
    parent_context: HostContext
    observer_enrollment_id: str


class NativeRequestObservationRegistry:
    """Retain root-observed requests and their authenticated producer lease."""

    def __init__(self, *, service: Any, source_observers: Any,
                 native_input_observer: Any, bridges: Mapping[str, Any],
                 process_resolver: Any, monotonic: Any):
        from .native_input_observer import RootNativeInputObserver
        from .source_observers import SourceObserverRegistry

        if (type(source_observers) is not SourceObserverRegistry
                or type(native_input_observer) is not RootNativeInputObserver
                or source_observers.service is not service
                or native_input_observer.service is not service
                or native_input_observer.source_observers is not source_observers
                or not isinstance(bridges, Mapping) or not bridges
                or not callable(process_resolver) or not callable(monotonic)):
            raise ValueError("native request observation requires the exact active root source/input graph")
        self.service = service
        self.source_observers = source_observers
        self.native_input_observer = native_input_observer
        self.bridges = dict(bridges)
        self.process_resolver = process_resolver
        self.monotonic = monotonic
        self._records: dict[str, _RequestRecord] = {}
        self._native_handle_index: dict[str, str] = {}
        self._retry_claims: dict[tuple[str, str, int], float] = {}
        self._total_bytes = 0
        self._lock = threading.RLock()

    def record_request(self, *, bridge: Any, native_request_handle: str,
                       producer_pid: int, producer_pidfd: int,
                       producer_identity: Any, canonical_request_bytes: bytes,
                       retry_index: int, parent_receipt_handles: Sequence[str],
                       parent_receipts: Sequence[SourceReceipt],
                       parent_context: HostContext,
                       expires_monotonic: float) -> RootNativeRequestObservation:
        now = self.monotonic()
        if (self.bridges.get(getattr(bridge, "bridge_id", None)) != bridge
                or not isinstance(native_request_handle, str)
                or not 32 <= len(native_request_handle) <= 128
                or type(producer_pid) is not int or producer_pid <= 0
                or type(producer_pidfd) is not int or producer_pidfd < 0
                or not isinstance(canonical_request_bytes, bytes)
                or not 1 <= len(canonical_request_bytes) <= MAX_REQUEST_BYTES
                or type(retry_index) is not int or not 0 <= retry_index <= 100
                or not isinstance(parent_receipt_handles, (tuple, list))
                or not parent_receipt_handles or len(parent_receipt_handles) > 64
                or any(not isinstance(item, str) or not item for item in parent_receipt_handles)
                or len(set(parent_receipt_handles)) != len(parent_receipt_handles)
                or not isinstance(parent_receipts, (tuple, list)) or not parent_receipts
                or not isinstance(parent_context, HostContext)
                or parent_context.uid != bridge.producer_uid
                or parent_context.profile_id != bridge.producer_profile_id
                or parent_context.generation != bridge.producer_generation
                or parent_context.final_payload_digest != canonical_digest(canonical_request_bytes)
                or parent_context.operation != bridge.approved_operation
                or not now < expires_monotonic <= parent_context.monotonic_expires_at
                or len(canonical_request_bytes) > MAX_REQUEST_BYTES):
            raise AuthorityDenied("native.request_observation", "root request observation binding is invalid")
        self.service._verify_context_signature(parent_context)
        binding = self.service._binding(bridge.producer_uid)
        self.service._assert_current_context(parent_context, binding, bridge.producer_uid,
                                             peer_pid=producer_pid)
        closure = {row.receipt_id: row for row in parent_receipts}
        if (len(closure) != len(parent_receipts)
                or set(closure) != {row.receipt_id for row in parent_context.source_receipts}
                or any(closure[key] != row for key, row in ((row.receipt_id, row)
                                                            for row in parent_context.source_receipts))):
            raise AuthorityDenied("native.request_lineage", "signed parent source closure changed")
        for row in parent_receipts:
            self.service._verify_source_receipt(row, binding)
        with self.service._lock:
            retained = {handle: self.service._source_receipt_handles.get(handle)
                        for handle in parent_receipt_handles}
        if any(value is None for value in retained.values()):
            raise AuthorityDenied("native.request_lineage", "parent source receipt handle is not retained")
        direct_ids = {row.receipt_id for row in retained.values() if row is not None}
        by_id = {row.receipt_id: row for row in parent_receipts}
        if not direct_ids or not direct_ids.issubset(by_id):
            raise AuthorityDenied("native.request_lineage", "direct parent handles do not join signed ancestry")
        parent_ids = {row.receipt_id for row in parent_receipts}
        if any(not set(row.parent_receipt_ids).issubset(parent_ids) for row in parent_receipts):
            raise AuthorityDenied("native.request_lineage", "signed parent ancestry is incomplete")

        capsules: dict[str, Any] = {}
        capsule_handles: dict[str, Any] = {}
        with self.source_observers._lock:
            for handle, (receipt, capsule, payload, epoch) in self.source_observers._payload_capsules.items():
                if (epoch == self.service.authority_epoch
                        and capsule.expires_monotonic > now
                        and receipt.receipt_id in parent_ids
                        and bytes(payload) == capsule.payload_bytes
                        and receipt.payload_digest == capsule.payload_sha256):
                    capsules[receipt.receipt_id] = capsule
                    capsule_handles[handle] = capsule
        if set(capsules) != parent_ids:
            raise AuthorityDenied("native.request_lineage", "parent source bytes are no longer retained by the root observer")
        input_events = tuple(event for event in self.native_input_observer._events.values()
                             if event.source_receipt_handle in parent_receipt_handles
                             and event.expires_monotonic > now)
        selected_inputs = []
        for event in input_events:
            capsule = capsule_handles.get(event.source_receipt_handle)
            if (capsule is not None and capsule.source_kind == "native-input"
                    and capsule.profile_id == producer_identity.profile_id
                    and capsule.generation == producer_identity.generation):
                observer = self.source_observers.observers.get(capsule.observer_enrollment_id)
                if (observer is not None and observer.source_kind == "native-input"
                        and observer.profile_id == bridge.producer_profile_id
                        and observer.generation == bridge.producer_generation):
                    selected_inputs.append((capsule, observer))
        if len(selected_inputs) != 1:
            raise AuthorityDenied("native.request_input", "request does not join one retained root-selected native input")
        input_capsule, input_observer = selected_inputs[0]
        identity_digest = canonical_digest({
            "profile_id": producer_identity.profile_id,
            "generation": producer_identity.generation,
            "kernel_uid": producer_identity.kernel_uid,
            "start_ticks": producer_identity.start_ticks,
            "executable_sha256": producer_identity.executable_sha256,
            "cgroup_identity": producer_identity.cgroup_identity,
            "namespace_identity": producer_identity.namespace_identity,
        })
        if (producer_identity.profile_id != bridge.producer_profile_id
                or producer_identity.generation != bridge.producer_generation
                or producer_identity.kernel_uid != bridge.producer_uid
                or producer_identity.executable_sha256 != bridge.producer_executable_sha256
                or not isinstance(input_observer.package_id, str)
                or not input_observer.package_id):
            raise AuthorityDenied("native.request_peer", "request producer or selected package identity changed")
        package_generation = input_observer.native_package_generation or input_observer.generation
        if not package_generation:
            raise AuthorityDenied("native.request_package", "selected native package generation is unavailable")
        parent_closure_digest = canonical_digest(sorted(parent_ids))
        receipt_handle = secrets.token_urlsafe(32)
        observation = RootNativeRequestObservation(
            schema=1, receipt_handle=receipt_handle,
            native_request_handle=native_request_handle, bridge_id=bridge.bridge_id,
            producer_profile_id=producer_identity.profile_id,
            producer_process_generation=producer_identity.generation,
            native_package_generation=package_generation,
            producer_process_identity=identity_digest,
            request_sha256=hashlib.sha256(canonical_request_bytes).hexdigest(),
            request_size_bytes=len(canonical_request_bytes), retry_index=retry_index,
            parent_source_receipt_handles=tuple(parent_receipt_handles),
            parent_closure_digest=parent_closure_digest,
            context_digest=canonical_digest(parent_context.to_wire()),
            issued_monotonic=now, expires_monotonic=expires_monotonic,
        )
        retry_key = (bridge.bridge_id, parent_closure_digest, retry_index)
        owned_fd = os.dup(producer_pidfd)
        record = _RequestRecord(
            observation, bridge, producer_pid, owned_fd, producer_identity,
            bytearray(canonical_request_bytes), native_request_handle,
            tuple(parent_receipts), parent_context,
            input_capsule.observer_enrollment_id,
        )
        with self._lock:
            self._prune_locked(now)
            if (len(self._records) >= MAX_REQUEST_RECORDS
                    or self._total_bytes + len(canonical_request_bytes) > MAX_TOTAL_BYTES
                    or receipt_handle in self._records
                    or native_request_handle in self._native_handle_index
                    or retry_key in self._retry_claims):
                os.close(owned_fd)
                raise AuthorityDenied("native.request_replay", "request handle, retry, or observation capacity is unavailable")
            self._records[receipt_handle] = record
            self._native_handle_index[native_request_handle] = receipt_handle
            self._retry_claims[retry_key] = expires_monotonic
            self._total_bytes += len(canonical_request_bytes)
        return observation

    def resolve_native_request(self, receipt_handle: str,
                               live_producer_identity: Any) -> RootNativeRequestObservation:
        with self._lock:
            self._prune_locked(self.monotonic())
            record = self._records.get(receipt_handle)
            if record is None:
                raise AuthorityDenied("native.request_observation", "request observation is unknown or expired")
            observation = record.observation
            current = self.process_resolver(
                record.producer_pid, record.producer_pidfd,
                profile_id=record.bridge.producer_profile_id,
                generation=record.bridge.producer_generation)
            now = self.monotonic()
            if (now >= observation.expires_monotonic
                    or live_producer_identity != record.producer_identity
                    or current != record.producer_identity
                    or len(record.canonical_request_bytes) != observation.request_size_bytes
                    or hashlib.sha256(record.canonical_request_bytes).hexdigest()
                    != observation.request_sha256
                    or self.bridges.get(observation.bridge_id) != record.bridge
                    or self.service.service_generation_digest is None
                    or self.service.profile_generations.get(observation.producer_profile_id)
                    != observation.producer_process_generation):
                raise AuthorityDenied("native.request_stale", "request observation producer or generation changed")
            self.service._verify_context_signature(record.parent_context)
            self.service._assert_current_context(
                record.parent_context, self.service._binding(record.bridge.producer_uid),
                record.bridge.producer_uid, peer_pid=record.producer_pid)
            with self.service._lock:
                retained = {handle: self.service._source_receipt_handles.get(handle)
                            for handle in observation.parent_source_receipt_handles}
            if any(value is None for value in retained.values()):
                raise AuthorityDenied("native.request_stale", "request parent source handle expired")
            if {value.receipt_id for value in retained.values() if value is not None} - {
                    item.receipt_id for item in record.parent_receipts}:
                raise AuthorityDenied("native.request_stale", "request parent source closure changed")
            with self.source_observers._lock:
                capsule_rows = {row[0].receipt_id: row for row in self.source_observers._payload_capsules.values()
                                if row[3] == self.service.authority_epoch
                                and row[1].expires_monotonic > now}
            capsule_ids = set(capsule_rows)
            if {item.receipt_id for item in record.parent_receipts} - capsule_ids:
                raise AuthorityDenied("native.request_stale", "request parent payload capsule expired")
            input_events = {event.source_receipt_handle for event in self.native_input_observer._events.values()
                            if event.expires_monotonic > now}
            if not (set(observation.parent_source_receipt_handles) & input_events):
                raise AuthorityDenied("native.request_stale", "retained root native input is no longer current")
            selected_observer = self.source_observers.observers.get(record.observer_enrollment_id)
            if (selected_observer is None
                    or (selected_observer.native_package_generation or selected_observer.generation)
                    != observation.native_package_generation):
                raise AuthorityDenied("native.request_stale", "selected native package generation changed")
            return observation

    def resolve_for_turn(self, receipt_handle: str, *, turn_handle: Any,
                         turn_registry: Any) -> RootNativeRequestObservation:
        """Revalidate the root request against every direct source in its turn."""
        with self._lock:
            record = self._records.get(receipt_handle)
            if record is None:
                raise AuthorityDenied("native.request_observation", "request observation is unknown or expired")
            identity = record.producer_identity
            handles = record.observation.parent_source_receipt_handles
        observation = self.resolve_native_request(receipt_handle, identity)
        for source_handle in handles:
            current_turn = turn_registry.resolve_turn_for_source(source_handle, identity)
            if current_turn != turn_handle:
                raise AuthorityDenied("native.request_turn", "request parent source no longer belongs to this turn")
        return observation

    def resolve_native_request_for_handle(self, native_request_handle: str,
                                          live_producer_identity: Any) -> RootNativeRequestObservation:
        with self._lock:
            receipt_handle = self._native_handle_index.get(native_request_handle)
        if receipt_handle is None:
            raise AuthorityDenied("native.request_observation", "native request handle has no retained observation")
        return self.resolve_native_request(receipt_handle, live_producer_identity)

    def request_bytes(self, receipt_handle: str, live_producer_identity: Any) -> bytes:
        self.resolve_native_request(receipt_handle, live_producer_identity)
        with self._lock:
            record = self._records.get(receipt_handle)
            if record is None:
                raise AuthorityDenied("native.request_observation", "request observation expired")
            payload = bytes(record.canonical_request_bytes)
            if (len(payload) != record.observation.request_size_bytes
                    or hashlib.sha256(payload).hexdigest() != record.observation.request_sha256):
                raise AuthorityDenied("native.request_changed", "retained canonical request bytes changed")
            return payload

    def revoke_native_request(self, receipt_handle: str) -> None:
        with self._lock:
            record = self._records.pop(receipt_handle, None)
            if record is None:
                return
            self._native_handle_index.pop(record.native_request_handle, None)
            self._total_bytes -= len(record.canonical_request_bytes)
            for index in range(len(record.canonical_request_bytes)):
                record.canonical_request_bytes[index] = 0
        try:
            os.close(record.producer_pidfd)
        except OSError:
            pass

    def close(self) -> None:
        with self._lock:
            handles = tuple(self._records)
        for handle in handles:
            self.revoke_native_request(handle)

    def _prune_locked(self, now: float) -> None:
        self._retry_claims = {key: expiry for key, expiry in self._retry_claims.items()
                              if expiry > now}
        for handle, record in tuple(self._records.items()):
            if now >= record.observation.expires_monotonic:
                self._records.pop(handle, None)
                self._native_handle_index.pop(record.native_request_handle, None)
                self._total_bytes -= len(record.canonical_request_bytes)
                for index in range(len(record.canonical_request_bytes)):
                    record.canonical_request_bytes[index] = 0
                try:
                    os.close(record.producer_pidfd)
                except OSError:
                    pass
