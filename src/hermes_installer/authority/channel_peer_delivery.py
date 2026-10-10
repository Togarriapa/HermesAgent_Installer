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
        self._event_bytes = 0
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

    def publish_captured_event(self, *, channel_ingress_id: str, event_handle: Any) -> int:
        """Fail closed until event-to-peer source/context handles have an issuer.

        A retained event's signed receipt IDs are not native source-delivery
        handles. The source/context handles in ChannelEventDelivery must be
        resolved for the exact selected peer and PIDFD by a root-owned,
        one-use issuer; this registry currently has no such API.
        """
        raise AuthorityDenied(
            "channel.publish",
            "channel event delivery is unavailable: recipient-bound source and context handle issuance is not installed",
        )

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
            self._event_bytes = 0

    def revoke_profile(self, profile_id: str) -> int:
        if not isinstance(profile_id, str) or not _ID.fullmatch(profile_id):
            raise ValueError("profile ID is invalid")
        with self._lock:
            handles = [key for key, peer in self._peers.items()
                       if peer.binding.profile_id == profile_id]
            for key in handles:
                self._close_peer(self._peers.pop(key))
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
                self._close_peer(self._peers.pop(key))
                continue
            while peer.pending and peer.pending[0][0].expires_monotonic <= now:
                _, payload, _record = peer.pending.pop(0)
                self._event_bytes -= len(payload)

    def _remove_peer(self, handle: str) -> None:
        with self._lock:
            peer = self._peers.pop(handle, None)
            if peer is not None:
                self._close_peer(peer)

    def _close_peer(self, peer: _BoundPeer) -> None:
        if peer.closed:
            return
        peer.closed = True
        for _delivery, payload, _record in peer.pending:
            self._event_bytes -= len(payload)
        peer.pending.clear()
        try:
            os.close(peer.pidfd)
        except OSError:
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


def _pidfd_alive(pidfd: int) -> bool:
    import select
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not poller.poll(0)
