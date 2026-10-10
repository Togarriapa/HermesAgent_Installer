"""Peer-authenticated, fixed channel event delivery between root and Hermes.

This is the cross-process half of v48.  The root does not trust package IDs,
profile IDs, source labels, event bodies, or identity claims in RPC payloads.
It derives a single active channel-delivery row from the kernel peer and its
currently mounted native package, then serves bounded one-use records captured
by the root channel ingress registry.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from .types import AuthorityDenied

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVENT = 256 * 1024
_MAX_QUEUE = 64
_MAX_TOTAL = 8 * 1024 * 1024
_LEASE = 30.0
_CHANNEL_ISSUER_SEAL = object()


@dataclass(frozen=True, slots=True)
class ChannelRuntimeBinding:
    schema: int
    binding_handle: str = field(repr=False)
    delivery_binding_id: str
    profile_id: str
    generation: str
    native_package_id: str
    native_package_generation: str
    service_generation_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (self.schema != 1 or not _HANDLE.fullmatch(self.binding_handle)
                or any(not isinstance(getattr(self, name), str)
                       or not _ID.fullmatch(getattr(self, name))
                       for name in ("delivery_binding_id", "profile_id", "generation",
                                    "native_package_id", "native_package_generation"))
                or not _SHA256.fullmatch(self.service_generation_digest)
                or type(self.expires_monotonic) not in (int, float)):
            raise ValueError("channel runtime binding is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": 1, "binding_handle": self.binding_handle,
            "delivery_binding_id": self.delivery_binding_id,
            "profile_id": self.profile_id, "generation": self.generation,
            "native_package_id": self.native_package_id,
            "native_package_generation": self.native_package_generation,
            "service_generation_digest": self.service_generation_digest,
            "expires_monotonic": self.expires_monotonic,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "ChannelRuntimeBinding":
        fields = {"schema", "binding_handle", "delivery_binding_id", "profile_id",
                  "generation", "native_package_id", "native_package_generation",
                  "service_generation_digest", "expires_monotonic"}
        if not isinstance(value, dict) or set(value) != fields:
            raise AuthorityDenied("channel.binding", "root returned a malformed channel binding")
        try:
            return cls(**value)
        except (TypeError, ValueError):
            raise AuthorityDenied("channel.binding", "root returned a malformed channel binding") from None


@dataclass(frozen=True, slots=True)
class ChannelEventDelivery:
    schema: int
    delivery_handle: str = field(repr=False)
    binding_handle: str = field(repr=False)
    channel_ingress_id: str
    event_handle: str = field(repr=False)
    normalized_payload_b64: str = field(repr=False)
    payload_sha256: str
    source_receipt_handle: str = field(repr=False)
    producer_context_delivery_handle: str = field(repr=False)
    sequence: int
    expires_monotonic: float

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": 1, "delivery_handle": self.delivery_handle,
            "binding_handle": self.binding_handle,
            "channel_ingress_id": self.channel_ingress_id,
            "event_handle": self.event_handle,
            "normalized_payload_b64": self.normalized_payload_b64,
            "payload_sha256": self.payload_sha256,
            "source_receipt_handle": self.source_receipt_handle,
            "producer_context_delivery_handle": self.producer_context_delivery_handle,
            "sequence": self.sequence, "expires_monotonic": self.expires_monotonic,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "ChannelEventDelivery":
        fields = {"schema", "delivery_handle", "binding_handle", "channel_ingress_id",
                  "event_handle", "normalized_payload_b64", "payload_sha256",
                  "source_receipt_handle", "producer_context_delivery_handle",
                  "sequence", "expires_monotonic"}
        if not isinstance(value, dict) or set(value) != fields:
            raise AuthorityDenied("channel.delivery", "root returned a malformed channel event")
        if (value.get("schema") != 1
                or any(not isinstance(value.get(name), str) or not _HANDLE.fullmatch(value[name])
                       for name in ("delivery_handle", "binding_handle", "event_handle",
                                    "source_receipt_handle", "producer_context_delivery_handle"))
                or not isinstance(value.get("channel_ingress_id"), str)
                or not _ID.fullmatch(value["channel_ingress_id"])
                or not isinstance(value.get("payload_sha256"), str)
                or not _SHA256.fullmatch(value["payload_sha256"])
                or type(value.get("sequence")) is not int or value["sequence"] < 1
                or type(value.get("expires_monotonic")) not in (int, float)
                or not isinstance(value.get("normalized_payload_b64"), str)):
            raise AuthorityDenied("channel.delivery", "root returned a malformed channel event")
        try:
            raw = base64.b64decode(value["normalized_payload_b64"], validate=True)
        except Exception:
            raise AuthorityDenied("channel.delivery", "root returned an invalid channel payload") from None
        if (not 1 <= len(raw) <= _MAX_EVENT
                or hashlib.sha256(raw).hexdigest() != value["payload_sha256"]):
            raise AuthorityDenied("channel.delivery", "root channel payload digest or size is invalid")
        return cls(**value)

    @property
    def normalized_payload(self) -> bytes:
        return base64.b64decode(self.normalized_payload_b64, validate=True)


@dataclass(frozen=True, slots=True)
class VerifiedNativeChannelPeerBinding:
    """Root-created view of a current channel peer, never an RPC value."""

    binding_handle: str = field(repr=False)
    channel_ingress_id: str
    source_observer_enrollment_id: str
    profile_id: str
    generation: str
    native_package_id: str
    native_package_generation: str
    namespace_id: str
    principal_id: str
    native_process_identity_digest: str
    loaded_role_proof_handle: str
    peer_uid: int
    peer_pid: int
    issued_monotonic: float
    expires_monotonic: float
    _peer: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _CHANNEL_ISSUER_SEAL
                or not _HANDLE.fullmatch(self.binding_handle)
                or not _ID.fullmatch(self.channel_ingress_id)
                or not _ID.fullmatch(self.source_observer_enrollment_id)
                or not all(_ID.fullmatch(value) for value in (
                    self.profile_id, self.generation, self.native_package_id,
                    self.native_package_generation, self.namespace_id, self.principal_id,
                    self.loaded_role_proof_handle))
                or not _SHA256.fullmatch(self.native_process_identity_digest)
                or type(self.peer_uid) is not int or self.peer_uid <= 0
                or type(self.peer_pid) is not int or self.peer_pid <= 0
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("verified native channel peer binding is malformed")

    def duplicate_peer_pidfd(self) -> int:
        if self._seal is not _CHANNEL_ISSUER_SEAL:
            raise AuthorityDenied("channel.peer", "native peer binding was not issued by root")
        try:
            return os.dup(self._peer.pidfd)
        except (AttributeError, OSError):
            raise AuthorityDenied("channel.peer", "current native peer PIDFD is unavailable") from None


@dataclass(frozen=True, slots=True)
class RootRetainedChannelDeliveryProof:
    """Instance-bound proof joining one retained event to one current peer."""

    proof_handle: str = field(repr=False)
    event_handle: str = field(repr=False)
    event_payload_sha256: str
    event_payload_size_bytes: int
    channel_ingress_id: str
    source_observer_enrollment_id: str
    native_binding_handle: str = field(repr=False)
    native_profile_id: str
    native_profile_generation: str
    native_package_id: str
    native_package_generation: str
    namespace_id: str
    principal_id: str
    native_process_identity_digest: str
    native_loaded_role_proof_handle: str = field(repr=False)
    original_source_receipt_ids: tuple[str, ...] = field(repr=False)
    original_source_context_digest: str
    original_controller_binding_handle: str = field(repr=False)
    issued_monotonic: float
    expires_monotonic: float
    _event: Any = field(repr=False, compare=False)
    _peer: Any = field(repr=False, compare=False)
    _record: Any = field(repr=False, compare=False)
    _native_binding: Any = field(repr=False, compare=False)
    _sequence: int = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _CHANNEL_ISSUER_SEAL
                or not _HANDLE.fullmatch(self.proof_handle)
                or not _HANDLE.fullmatch(self.event_handle)
                or not _SHA256.fullmatch(self.event_payload_sha256)
                or type(self.event_payload_size_bytes) is not int
                or not 1 <= self.event_payload_size_bytes <= _MAX_EVENT
                or not _ID.fullmatch(self.channel_ingress_id)
                or not _ID.fullmatch(self.source_observer_enrollment_id)
                or not _HANDLE.fullmatch(self.native_binding_handle)
                or not all(_ID.fullmatch(value) for value in (
                    self.native_profile_id, self.native_profile_generation,
                    self.native_package_id, self.native_package_generation,
                    self.namespace_id, self.principal_id,
                    self.original_controller_binding_handle))
                or not _SHA256.fullmatch(self.native_process_identity_digest)
                or not _ID.fullmatch(self.native_loaded_role_proof_handle)
                or not isinstance(self.original_source_receipt_ids, tuple)
                or not 1 <= len(self.original_source_receipt_ids) <= 64
                or any(not _ID.fullmatch(value) for value in self.original_source_receipt_ids)
                or len(set(self.original_source_receipt_ids)) != len(self.original_source_receipt_ids)
                or not _SHA256.fullmatch(self.original_source_context_digest)
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("retained channel delivery proof is malformed")


@dataclass(frozen=True, slots=True)
class RootChannelInputDelivery:
    """Service-issued handle bundle for one peer-bound retained event."""

    delivery_handle: str = field(repr=False)
    event_handle: str = field(repr=False)
    native_binding_handle: str = field(repr=False)
    source_receipt_handle: str = field(repr=False)
    producer_context_delivery_handle: str = field(repr=False)
    payload_sha256: str
    sequence: int
    issued_monotonic: float
    expires_monotonic: float
    _issuer_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (any(not _HANDLE.fullmatch(value) for value in (
                    self.delivery_handle, self.event_handle, self.native_binding_handle,
                    self.source_receipt_handle, self.producer_context_delivery_handle))
                or not _SHA256.fullmatch(self.payload_sha256)
                or type(self.sequence) is not int or self.sequence < 1
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or self._issuer_token is None):
            raise ValueError("root channel input delivery is malformed")


@dataclass(slots=True)
class _BoundPeer:
    binding: ChannelRuntimeBinding
    row: Mapping[str, Any] = field(repr=False)
    pid: int = field(repr=False)
    uid: int = field(repr=False)
    pidfd: int = field(repr=False)
    identity: Any = field(repr=False, compare=False)
    loaded_proofs: tuple[Any, ...] = field(repr=False, compare=False)
    observers: tuple[Any, ...] = field(repr=False, compare=False)
    authority_epoch: str = field(repr=False)
    issued: float
    sequence: int = 0
    pending: list[tuple[ChannelEventDelivery, bytes, object]] = field(default_factory=list,
                                                                          repr=False)
    event_handles: set[str] = field(default_factory=set, repr=False)
    event_sequences: dict[str, int] = field(default_factory=dict, repr=False)
    reserved_event_handles: set[str] = field(default_factory=set, repr=False)
    closed: bool = False


class RootChannelPeerDeliveryRegistry:
    """Fixed root-owned bind/take registry for active Hermes channel peers.

    ``bind`` accepts only kernel SO_PEERCRED values supplied by AuthorityService.
    Peer metadata comes from the root process manager and package loader proof
    store; there is no caller-selected profile, package, PID, channel, or event.
    ``publish_captured_event`` is an in-process root collector seam and accepts
    only an exact current ``RootResourceEventHandle`` retained by the resource
    controller registry.
    """

    def __init__(self, *, service: Any, runtime_bindings: Any,
                 resource_controller_registry: Any, source_observers: Any,
                 loader_observations: Any, monotonic: Callable[[], float] = time.monotonic):
        from .resource_source_controllers import RootResourceControllerRegistry
        from .source_observers import SourceObserverEnrollment
        from .native_custody_proof import RootNativeLoaderObservationStore
        from .runtime_bindings import RootRuntimeBindings
        if (service is None or not isinstance(runtime_bindings, RootRuntimeBindings)
                or not isinstance(resource_controller_registry, RootResourceControllerRegistry)
                or resource_controller_registry.service is not service
                or not isinstance(loader_observations, RootNativeLoaderObservationStore)
                or not isinstance(getattr(source_observers, "observers", None), Mapping)
                or not callable(monotonic)):
            raise ValueError("active authority, protected channel rows, root event registry and native proofs are required")
        if (not callable(getattr(runtime_bindings.process_manager, "resolve_native_package_for_peer", None))
                or not callable(getattr(runtime_bindings.process_manager, "resolve_live_peer", None))
                or not callable(getattr(runtime_bindings, "resolve_channel_delivery_binding", None))):
            raise ValueError("root process manager and protected channel binding resolver are required")
        self.service, self.bindings = service, runtime_bindings
        self.resource_registry = resource_controller_registry
        self.source_observers, self.loader_observations = source_observers, loader_observations
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._peers: dict[str, _BoundPeer] = {}
        self._verified_peer_bindings: dict[int, VerifiedNativeChannelPeerBinding] = {}
        self._channel_proofs: dict[str, RootRetainedChannelDeliveryProof] = {}
        self._event_bytes = 0
        self._reserved_bytes = 0
        self._closed = False

    def bind(self, *, peer_uid: int, peer_pid: int, peer_pidfd: int) -> ChannelRuntimeBinding:
        """Bind the actual connected profile process to its unique current package row."""
        from .native_custody_proof import LivePeerProcess, LoadedPackageClosureProof
        from .source_observers import SourceObserverEnrollment
        if (type(peer_uid) is not int or peer_uid <= 0 or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("channel.binding", "authenticated channel peer is unavailable")
        manager = self.bindings.process_manager
        mount = manager.resolve_native_package_for_peer(peer_pid, peer_pidfd)
        if mount is None:
            raise AuthorityDenied("channel.binding", "peer has no current root-observed native package")
        profile_id, process_generation = getattr(mount, "profile_id", None), getattr(mount, "generation", None)
        package_id = getattr(getattr(mount, "mount", None), "package_id", None)
        if not all(isinstance(value, str) and _ID.fullmatch(value)
                   for value in (profile_id, process_generation, package_id)):
            raise AuthorityDenied("channel.binding", "root package resolver returned an incomplete peer binding")
        identity = manager.resolve_live_peer(peer_pid, peer_pidfd,
                                             profile_id=profile_id, generation=process_generation)
        if (identity is None or getattr(identity, "kernel_uid", None) != peer_uid
                or getattr(identity, "profile_id", None) != profile_id
                or getattr(identity, "generation", None) != process_generation):
            raise AuthorityDenied("channel.binding", "kernel peer identity differs from current process custody")
        rows = [row for row in self.bindings.channel_delivery_binding_records
                if row.get("profile_id") == profile_id
                and row.get("process_generation") == process_generation
                and row.get("native_package_id") == package_id
                and row.get("native_package_generation") == process_generation]
        if len(rows) != 1:
            raise AuthorityDenied("channel.binding", "active channel delivery binding is absent or ambiguous")
        row = self.bindings.resolve_channel_delivery_binding(
            rows[0]["id"], profile_id, process_generation, package_id, process_generation)
        package = self.bindings.resolve_native_package(package_id, process_generation)
        observer_rows = []
        proofs = []
        for observer_id in row["source_observer_enrollment_ids"]:
            observer = self.source_observers.observers.get(observer_id)
            if (observer is None or not isinstance(observer, SourceObserverEnrollment)
                    or observer.profile_id != profile_id or observer.generation != process_generation
                    or observer.package_id != package_id or observer.source_kind != "native-input"
                    or observer.channel_id not in row["allowed_channel_ingress_ids"]):
                raise AuthorityDenied("channel.binding", "protected channel observer/package join failed")
            proof = self.loader_observations.resolve_loaded_package_closure(
                LivePeerProcess(peer_pid, peer_pidfd, identity), observer)
            if (type(proof) is not LoadedPackageClosureProof
                    or proof.profile_id != profile_id or proof.generation != process_generation
                    or proof.package_id != package_id
                    or proof.target_peer_identity != identity
                    or proof.service_generation_digest != self.service.service_generation_digest
                    or proof.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("channel.binding", "current native SDK package proof is unavailable")
            observer_rows.append(observer)
            proofs.append(proof)
        now = self.monotonic()
        expires = min(now + _LEASE, *(proof.expires_monotonic for proof in proofs))
        if not now < expires:
            raise AuthorityDenied("channel.binding", "native channel peer has no live package lease")
        handle = secrets.token_urlsafe(32)
        result = ChannelRuntimeBinding(
            1, handle, row["id"], profile_id, process_generation,
            package_id, process_generation, self.service.service_generation_digest, expires)
        pidfd = os.dup(peer_pidfd)
        try:
            with self._lock:
                if self._closed or self.service.authority_epoch is None:
                    raise AuthorityDenied("channel.binding", "root channel delivery registry is closed")
                self._peers[handle] = _BoundPeer(
                    result, row, peer_pid, peer_uid, pidfd, identity,
                    tuple(proofs), tuple(observer_rows), self.service.authority_epoch, now)
                pidfd = -1
        finally:
            if pidfd >= 0:
                os.close(pidfd)
        return result

    def resolve_verified_native_peer_binding(
        self, binding_handle: str, *, channel_ingress_id: str,
        source_observer_enrollment_id: str,
    ) -> VerifiedNativeChannelPeerBinding:
        """Return a root-only, current binding for one protected observer/channel."""
        with self._lock:
            peer = self._peers.get(binding_handle)
            if peer is None or peer.closed:
                raise AuthorityDenied("channel.peer", "selected channel peer binding is unavailable")
            self._revalidate_peer(peer)
            if (channel_ingress_id not in peer.row["allowed_channel_ingress_ids"]
                    or source_observer_enrollment_id not in peer.row["source_observer_enrollment_ids"]):
                raise AuthorityDenied("channel.peer", "channel peer is not selected for this source")
            observer = next((item for item in peer.observers
                             if item.observer_enrollment_id == source_observer_enrollment_id
                             and item.channel_id == channel_ingress_id), None)
            proof = next((item for item in peer.loaded_proofs
                          if item.package_id == peer.binding.native_package_id
                          and item.profile_id == peer.binding.profile_id
                          and item.generation == peer.binding.generation), None)
            if observer is None or proof is None:
                raise AuthorityDenied("channel.peer", "current source observer or loaded-role proof is unavailable")
            identity_digest = _native_identity_digest(peer.identity)
            result = VerifiedNativeChannelPeerBinding(
                peer.binding.binding_handle, channel_ingress_id,
                source_observer_enrollment_id, peer.binding.profile_id,
                peer.binding.generation, peer.binding.native_package_id,
                peer.binding.native_package_generation, observer.namespace_id,
                observer.principal_id, identity_digest, proof.proof_id,
                peer.uid, peer.pid, self.monotonic(),
                min(peer.binding.expires_monotonic, proof.expires_monotonic),
                peer, _CHANNEL_ISSUER_SEAL,
            )
            self._verified_peer_bindings[id(result)] = result
            return result

    def prove_retained_event_for_peer(
        self, event_handle: Any, native_binding: VerifiedNativeChannelPeerBinding,
    ) -> RootRetainedChannelDeliveryProof:
        """Seal one exact retained source event to the selected live native peer."""
        from .resource_source_controllers import RootResourceEventHandle
        if (type(event_handle) is not RootResourceEventHandle
                or type(native_binding) is not VerifiedNativeChannelPeerBinding
                or native_binding._seal is not _CHANNEL_ISSUER_SEAL):
            raise AuthorityDenied("channel.proof", "retained event or native peer proof is invalid")
        with self._lock:
            if self._verified_peer_bindings.get(id(native_binding)) is not native_binding:
                raise AuthorityDenied("channel.proof", "native peer binding is not retained by this registry")
            peer = self._peers.get(native_binding.binding_handle)
            if peer is None or peer is not native_binding._peer or peer.closed:
                raise AuthorityDenied("channel.proof", "native peer binding is no longer retained")
            self._revalidate_peer(peer)
            if (native_binding.expires_monotonic <= self.monotonic()
                    or native_binding.peer_pid != peer.pid
                    or native_binding.peer_uid != peer.uid
                    or native_binding.native_process_identity_digest != _native_identity_digest(peer.identity)):
                raise AuthorityDenied("channel.proof", "native peer identity or lease changed")
            record = self.resource_registry.resolve_retained_event(event_handle)
            observer = next((item for item in peer.observers
                             if item.observer_enrollment_id == event_handle.source_observer_enrollment_id
                             and item.observer_enrollment_id == native_binding.source_observer_enrollment_id
                             and item.channel_id == native_binding.channel_ingress_id), None)
            if (record.handle is not event_handle or observer is None
                    or event_handle.source_kind != "native-input"
                    or getattr(record.parent_context, "profile_id", None) != peer.binding.profile_id
                    or getattr(record.parent_context, "generation", None) != peer.binding.generation
                    or event_handle.expires_monotonic <= self.monotonic()
                    or not isinstance(record.payload, bytes)
                    or not 1 <= len(record.payload) <= _MAX_EVENT
                    or hashlib.sha256(record.payload).hexdigest() != event_handle.payload_sha256):
                raise AuthorityDenied("channel.proof", "retained source event no longer matches selected native peer")
            if (event_handle.handle in peer.event_handles
                    or event_handle.handle in peer.reserved_event_handles
                    or len(peer.pending) + len(peer.reserved_event_handles) >= _MAX_QUEUE
                    or self._event_bytes + self._reserved_bytes + len(record.payload) > _MAX_TOTAL):
                raise AuthorityDenied("channel.replay", "channel event is already queued, reserved, or over capacity")
            try:
                envelope = json.loads(record.payload.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise AuthorityDenied("channel.proof", "retained source event envelope is malformed") from None
            controller_handle = envelope.get("controller_proof_handle") if isinstance(envelope, dict) else None
            if not isinstance(controller_handle, str) or not _HANDLE.fullmatch(controller_handle):
                raise AuthorityDenied("channel.proof", "retained source controller binding is unavailable")
            from .service import _context_digest
            peer.sequence += 1
            proof = RootRetainedChannelDeliveryProof(
                secrets.token_urlsafe(32), event_handle.handle,
                hashlib.sha256(record.payload).hexdigest(), len(record.payload),
                native_binding.channel_ingress_id, event_handle.source_observer_enrollment_id,
                peer.binding.binding_handle, peer.binding.profile_id,
                peer.binding.generation, peer.binding.native_package_id,
                peer.binding.native_package_generation, observer.namespace_id,
                observer.principal_id, _native_identity_digest(peer.identity),
                native_binding.loaded_role_proof_handle,
                tuple(event_handle.source_receipt_ids), _context_digest(record.parent_context),
                controller_handle, self.monotonic(),
                min(event_handle.expires_monotonic, peer.binding.expires_monotonic,
                    native_binding.expires_monotonic),
                event_handle, peer, record, native_binding, peer.sequence,
                _CHANNEL_ISSUER_SEAL,
            )
            if proof.expires_monotonic <= proof.issued_monotonic:
                raise AuthorityDenied("channel.proof", "retained source and native peer leases do not overlap")
            self._channel_proofs[proof.proof_handle] = proof
            peer.reserved_event_handles.add(event_handle.handle)
            self._reserved_bytes += len(record.payload)
            self._verified_peer_bindings.pop(id(native_binding), None)
            return proof

    def publish_issued_delivery(
        self, proof: RootRetainedChannelDeliveryProof,
        delivery: RootChannelInputDelivery,
    ) -> None:
        """Commit a service-issued source/context pair to the peer queue."""
        if (type(proof) is not RootRetainedChannelDeliveryProof
                or type(delivery) is not RootChannelInputDelivery
                or not self.validate_retained_channel_proof(proof)):
            raise AuthorityDenied("channel.publish", "root retained event delivery proof is unavailable")
        if (delivery.event_handle != proof.event_handle
                or delivery.native_binding_handle != proof.native_binding_handle
                or delivery.payload_sha256 != proof.event_payload_sha256
                or delivery.sequence != proof._sequence
                or delivery.issued_monotonic < proof.issued_monotonic
                or delivery.expires_monotonic > proof.expires_monotonic
                or delivery.expires_monotonic <= self.monotonic()):
            raise AuthorityDenied("channel.publish", "root-issued source/context handles do not match reserved event")
        verifier = getattr(self.service, "validate_root_channel_input_delivery", None)
        if not callable(verifier) or verifier(proof, delivery) is not True:
            raise AuthorityDenied("channel.publish", "source receipt or native context registration is not current")
        peer = proof._peer
        record = proof._record
        with self._lock:
            if (self._channel_proofs.get(proof.proof_handle) is not proof
                    or proof.event_handle not in peer.reserved_event_handles
                    or proof.event_handle in peer.event_handles
                    or not self.validate_retained_channel_proof(proof)):
                raise AuthorityDenied("channel.publish", "event reservation expired, changed, or was consumed")
            channel_delivery = ChannelEventDelivery(
                1, delivery.delivery_handle, proof.native_binding_handle,
                proof.channel_ingress_id, proof.event_handle,
                base64.b64encode(record.payload).decode("ascii"),
                proof.event_payload_sha256, delivery.source_receipt_handle,
                delivery.producer_context_delivery_handle, delivery.sequence,
                delivery.expires_monotonic,
            )
            self._channel_proofs.pop(proof.proof_handle, None)
            peer.reserved_event_handles.remove(proof.event_handle)
            peer.event_handles.add(proof.event_handle)
            self._reserved_bytes -= len(record.payload)
            peer.pending.append((channel_delivery, bytes(record.payload), record))
            peer.event_sequences[proof.event_handle] = delivery.sequence
            self._event_bytes += len(record.payload)

    def cancel_retained_channel_proof(self, proof: RootRetainedChannelDeliveryProof) -> bool:
        """Release a reservation after service source/context registration rolls back."""
        if type(proof) is not RootRetainedChannelDeliveryProof:
            return False
        with self._lock:
            if self._channel_proofs.get(proof.proof_handle) is not proof:
                return False
            self._channel_proofs.pop(proof.proof_handle, None)
            peer = proof._peer
            peer.reserved_event_handles.discard(proof.event_handle)
            self._reserved_bytes = max(0, self._reserved_bytes - proof.event_payload_size_bytes)
            return True

    def validate_retained_channel_proof(
        self, proof: RootRetainedChannelDeliveryProof, *,
        event_handle: Any = None, native_binding: VerifiedNativeChannelPeerBinding | None = None,
        retained_record: Any = None,
    ) -> bool:
        """Revalidate exact proof object/event/peer before service issuance."""
        if type(proof) is not RootRetainedChannelDeliveryProof:
            return False
        with self._lock:
            retained = self._channel_proofs.get(proof.proof_handle)
            if retained is not proof or proof._seal is not _CHANNEL_ISSUER_SEAL:
                return False
            peer = self._peers.get(proof.native_binding_handle)
            if peer is not proof._peer or peer is None or peer.closed:
                self.cancel_retained_channel_proof(proof)
                return False
            try:
                self._revalidate_peer(peer)
                record = self.resource_registry.resolve_retained_event(proof._event)
            except Exception:
                self.cancel_retained_channel_proof(proof)
                return False
            return bool(
                record is proof._record
                and proof._event is record.handle
                and (event_handle is None or event_handle is proof._event)
                and (native_binding is None or native_binding is proof._native_binding)
                and (retained_record is None or retained_record is record)
                and proof.event_payload_sha256 == hashlib.sha256(record.payload).hexdigest()
                and proof.event_payload_size_bytes == len(record.payload)
                and proof.native_process_identity_digest == _native_identity_digest(peer.identity)
                and proof.expires_monotonic > self.monotonic()
            )

    def sequence_for_retained_channel_proof(
        self, proof: RootRetainedChannelDeliveryProof,
    ) -> int:
        """Return the sequence only while this exact reservation is current."""
        if not self.validate_retained_channel_proof(proof):
            raise AuthorityDenied("channel.proof", "retained channel delivery proof is stale or unknown")
        return proof._sequence

    def resolve_retained_channel_proof(
        self, proof: RootRetainedChannelDeliveryProof,
    ) -> tuple[Any, VerifiedNativeChannelPeerBinding]:
        """Expose only the exact retained event and target binding for issuance."""
        if not self.validate_retained_channel_proof(proof):
            raise AuthorityDenied("channel.proof", "retained channel delivery proof is stale or unknown")
        return proof._event, proof._native_binding

    def publish_captured_event(self, *, channel_ingress_id: str, event_handle: Any) -> int:
        """Deliver one retained source event to its unique current native peer.

        This is an in-process root collector callpoint. It derives the selected
        channel and source observer from the retained event, selects exactly one
        already authenticated native peer whose protected row includes that
        source, and delegates fresh signed source/context issuance to
        AuthorityService. Ambiguous targets fail closed; this never fans out.
        """
        from .resource_source_controllers import RootResourceEventHandle
        if (type(event_handle) is not RootResourceEventHandle
                or not isinstance(channel_ingress_id, str)
                or not _ID.fullmatch(channel_ingress_id)):
            raise AuthorityDenied("channel.publish", "retained channel event selection is malformed")
        with self._lock:
            if self._closed:
                raise AuthorityDenied("channel.publish", "root channel delivery registry is closed")
            record = self.resource_registry.resolve_retained_event(event_handle)
            observer = self.source_observers.observers.get(
                event_handle.source_observer_enrollment_id)
            if (record.handle is not event_handle or observer is None
                    or event_handle.source_kind != "native-input"
                    or observer.source_kind != "native-input"
                    or observer.channel_id != channel_ingress_id):
                raise AuthorityDenied("channel.publish", "retained event is not enrolled for this channel")
            candidates = []
            for peer in tuple(self._peers.values()):
                if (peer.closed
                        or channel_ingress_id not in peer.row["allowed_channel_ingress_ids"]
                        or event_handle.source_observer_enrollment_id
                           not in peer.row["source_observer_enrollment_ids"]
                        or peer.binding.profile_id != getattr(record.parent_context, "profile_id", None)
                        or peer.binding.generation != getattr(record.parent_context, "generation", None)):
                    continue
                try:
                    self._revalidate_peer(peer)
                except AuthorityDenied:
                    continue
                if any(item.observer_enrollment_id == event_handle.source_observer_enrollment_id
                       and item.channel_id == channel_ingress_id for item in peer.observers):
                    candidates.append(peer)
            if len(candidates) != 1:
                raise AuthorityDenied(
                    "channel.publish",
                    "channel event has no unique current recipient peer; delivery remains unavailable",
                )
            peer = candidates[0]
            if event_handle.handle in peer.event_handles:
                sequence = peer.event_sequences.get(event_handle.handle)
                if type(sequence) is not int or sequence < 1:
                    raise AuthorityDenied("channel.replay", "previous channel event sequence is unavailable")
                return sequence
            if event_handle.handle in peer.reserved_event_handles:
                raise AuthorityDenied("channel.replay", "channel event delivery is already being issued")
            binding = self.resolve_verified_native_peer_binding(
                peer.binding.binding_handle, channel_ingress_id=channel_ingress_id,
                source_observer_enrollment_id=event_handle.source_observer_enrollment_id,
            )
        issuer = getattr(self.service, "issue_root_channel_event_delivery", None)
        if not callable(issuer):
            raise AuthorityDenied(
                "channel.publish",
                "recipient-bound source receipt and native context issuers are not installed",
            )
        delivery = issuer(event_handle, channel_ingress_id, binding)
        if type(delivery) is not RootChannelInputDelivery:
            raise AuthorityDenied("channel.publish", "root channel delivery issuer returned an invalid result")
        # The AuthorityService issuer has already atomically registered both
        # recipient-bound handles and queued the event. A receiver may take it
        # immediately after queue commit, so do not inspect the queue afterward.
        if (delivery.event_handle != event_handle.handle
                or delivery.native_binding_handle != binding.binding_handle
                or delivery.payload_sha256 != event_handle.payload_sha256):
            raise AuthorityDenied("channel.publish", "root issuer returned a mismatched event delivery")
        return delivery.sequence

    def take(self, *, peer_uid: int, peer_pid: int, peer_pidfd: int,
             binding_handle: str) -> ChannelEventDelivery | None:
        """Take one root-captured event for the currently bound kernel peer."""
        if (not isinstance(binding_handle, str) or not _HANDLE.fullmatch(binding_handle)
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("channel.delivery", "channel event lookup request is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            peer = self._peers.get(binding_handle)
            if (peer is None or peer.closed or peer.pid != peer_pid or peer.uid != peer_uid):
                raise AuthorityDenied("channel.delivery", "channel binding is absent or belongs to another peer")
            self._revalidate_peer(peer, request_pidfd=peer_pidfd)
            if not peer.pending:
                return None
            delivery, payload, record = peer.pending.pop(0)
            self._event_bytes -= len(payload)
            if (delivery.expires_monotonic <= self.monotonic()
                    or record.handle.handle != delivery.event_handle
                    or hashlib.sha256(payload).hexdigest() != delivery.payload_sha256):
                self._revoke_delivery(delivery)
                raise AuthorityDenied("channel.delivery", "queued channel event expired or changed")
            return delivery

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for peer in self._peers.values():
                self._close_peer(peer)
            self._peers.clear()
            self._verified_peer_bindings.clear()
            self._channel_proofs.clear()
            self._event_bytes = 0
            self._reserved_bytes = 0

    def revoke_profile(self, profile_id: str) -> int:
        if not isinstance(profile_id, str) or not _ID.fullmatch(profile_id):
            raise ValueError("profile ID is invalid")
        with self._lock:
            handles = [key for key, peer in self._peers.items()
                       if peer.binding.profile_id == profile_id]
            for key in handles:
                self._remove_peer(key)
            return len(handles)

    def _revalidate_peer(self, peer: _BoundPeer, *, request_pidfd: int | None = None) -> None:
        from .native_custody_proof import LivePeerProcess
        now = self.monotonic()
        if (peer.closed or peer.binding.expires_monotonic <= now
                or self.service.service_generation_digest != peer.binding.service_generation_digest
                or self.service.authority_epoch != peer.authority_epoch
                or not _pidfd_matches(peer.pidfd, peer.pid)):
            self._remove_peer(peer.binding.binding_handle)
            raise AuthorityDenied("channel.peer", "channel peer binding expired or service generation changed")
        manager = self.bindings.process_manager
        current = manager.resolve_live_peer(
            peer.pid, peer.pidfd, profile_id=peer.binding.profile_id,
            generation=peer.binding.generation)
        if current is None or current != peer.identity:
            self._remove_peer(peer.binding.binding_handle)
            raise AuthorityDenied("channel.peer", "current channel peer process identity changed")
        if request_pidfd is not None:
            observed = manager.resolve_live_peer(
                peer.pid, request_pidfd, profile_id=peer.binding.profile_id,
                generation=peer.binding.generation)
            if observed is None or observed != peer.identity:
                raise AuthorityDenied("channel.peer", "request PIDFD does not identify the bound peer")
        package = manager.resolve_native_package_for_peer(peer.pid, peer.pidfd)
        receipt = getattr(package, "mount", None)
        if (package is None or getattr(package, "profile_id", None) != peer.binding.profile_id
                or getattr(package, "generation", None) != peer.binding.generation
                or getattr(receipt, "package_id", None) != peer.binding.native_package_id):
            self._remove_peer(peer.binding.binding_handle)
            raise AuthorityDenied("channel.peer", "selected native package or process generation changed")
        for observer, old_proof in zip(peer.observers, peer.loaded_proofs, strict=True):
            new_proof = self.loader_observations.resolve_loaded_package_closure(
                LivePeerProcess(peer.pid, peer.pidfd, current), observer)
            if new_proof != old_proof:
                self._remove_peer(peer.binding.binding_handle)
                raise AuthorityDenied("channel.peer", "selected Hermes package closure or role changed")

    def _prune_locked(self, now: float) -> None:
        for key, peer in tuple(self._peers.items()):
            if peer.binding.expires_monotonic <= now:
                self._remove_peer(key)
                continue
            while peer.pending and peer.pending[0][0].expires_monotonic <= now:
                delivery, payload, _record = peer.pending.pop(0)
                self._event_bytes -= len(payload)
                self._revoke_delivery(delivery)

    def _remove_peer(self, handle: str) -> None:
        with self._lock:
            peer = self._peers.pop(handle, None)
            if peer is not None:
                peer_proofs = [value for value in self._channel_proofs.values()
                               if value._peer is peer]
                self._reserved_bytes = max(
                    0, self._reserved_bytes - sum(
                        value.event_payload_size_bytes for value in peer_proofs))
                self._verified_peer_bindings = {
                    key: value for key, value in self._verified_peer_bindings.items()
                    if value._peer is not peer
                }
                self._channel_proofs = {
                    key: value for key, value in self._channel_proofs.items()
                    if value._peer is not peer
                }
                peer.reserved_event_handles.clear()
                self._close_peer(peer)

    def _close_peer(self, peer: _BoundPeer) -> None:
        if peer.closed:
            return
        peer.closed = True
        for delivery, payload, _record in peer.pending:
            self._event_bytes -= len(payload)
            self._revoke_delivery(delivery)
        peer.pending.clear()
        try:
            os.close(peer.pidfd)
        except OSError:
            pass

    def _revoke_delivery(self, delivery: ChannelEventDelivery) -> None:
        revoke = getattr(self.service, "revoke_root_channel_input_delivery", None)
        if callable(revoke):
            try:
                revoke(delivery)
            except Exception:
                pass


def _pidfd_matches(pidfd: int, pid: int) -> bool:
    if not hasattr(os, "pidfd_open"):
        return False
    try:
        observed = os.pidfd_open(pid, 0)
    except OSError:
        return False
    try:
        return os.fstat(pidfd).st_ino == os.fstat(observed).st_ino and _pidfd_alive(pidfd)
    except OSError:
        return False
    finally:
        os.close(observed)


def _native_identity_digest(identity: Any) -> str:
    claims = {
        "kernel_uid": getattr(identity, "kernel_uid", None),
        "profile_id": getattr(identity, "profile_id", None),
        "generation": getattr(identity, "generation", None),
        "namespace_identity": getattr(identity, "namespace_identity", None),
        "start_ticks": getattr(identity, "start_ticks", None),
        "cgroup_identity": getattr(identity, "cgroup_identity", None),
        "executable_sha256": getattr(identity, "executable_sha256", None),
    }
    if (type(claims["kernel_uid"]) is not int or claims["kernel_uid"] <= 0
            or any(not isinstance(claims[key], str) or not claims[key]
                   for key in ("profile_id", "generation", "namespace_identity",
                               "cgroup_identity"))
            or type(claims["start_ticks"]) is not int or claims["start_ticks"] <= 0
            or not isinstance(claims["executable_sha256"], str)
            or not _SHA256.fullmatch(claims["executable_sha256"])):
        raise AuthorityDenied("channel.peer", "native peer identity is incomplete")
    encoded = json.dumps(claims, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _pidfd_alive(pidfd: int) -> bool:
    import select
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)
