"""Root-private recipient-bound context registration for channel input.

Channel input is not a resource task.  This store therefore does not use the
task execution selection or its native.input.take queue.  It registers one
separate opaque context-delivery handle against a sealed retained-channel
proof, the service-signed context, the derived source receipt, and the actual
selected channel peer PIDFD.
"""
from __future__ import annotations

import hashlib
import math
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .types import AuthorityDenied, HostContext, SourceReceipt

_HANDLE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_CONTEXTS = 256
_MAX_LEASE_SECONDS = 30.0


@dataclass(frozen=True, slots=True)
class NativeChannelContextDelivery:
    """Bounded wire presentation; signed context stays inside the root."""

    schema: int
    source_receipt_handle: str
    producer_context_delivery_handle: str
    payload_sha256: str
    payload_size_bytes: int
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(getattr(self, name), str)
                       or not _HANDLE.fullmatch(getattr(self, name))
                       for name in ("source_receipt_handle", "producer_context_delivery_handle"))
                or not isinstance(self.payload_sha256, str)
                or not _SHA256.fullmatch(self.payload_sha256)
                or type(self.payload_size_bytes) is not int
                or not 1 <= self.payload_size_bytes <= 262_144
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("native channel context delivery is malformed")
        if self.source_receipt_handle == self.producer_context_delivery_handle:
            raise ValueError("source and context delivery handles must be distinct")

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "source_receipt_handle": self.source_receipt_handle,
            "producer_context_delivery_handle": self.producer_context_delivery_handle,
            "payload_sha256": self.payload_sha256,
            "payload_size_bytes": self.payload_size_bytes,
            "expires_monotonic": self.expires_monotonic,
        }


@dataclass(frozen=True, slots=True)
class RootNativeChannelContextRegistrationToken:
    """Exact object-identity token for atomic issuance rollback."""

    producer_context_delivery_handle: str
    source_receipt_handle: str
    _store_nonce: str = field(repr=False)


@dataclass(slots=True)
class _ContextRegistration:
    token: RootNativeChannelContextRegistrationToken
    proof: Any = field(repr=False)
    native_binding: Any = field(repr=False)
    source_receipt: SourceReceipt = field(repr=False)
    signed_context: HostContext = field(repr=False)
    payload_sha256: str
    payload_size_bytes: int
    peer_uid: int
    peer_pid: int
    peer_identity: Any = field(repr=False)
    profile_id: str
    generation: str
    package_id: str
    package_generation: str
    authority_epoch: str
    service_generation_digest: str
    expires_monotonic: float
    peer_pidfd: int = field(repr=False)
    consumed: bool = False


class RootNativeChannelContextStore:
    """One-use current-peer store for root-issued channel contexts.

    The source observer separately owns the source receipt and a duplicate
    delivery-target PIDFD.  This store owns another PIDFD duplicate for the
    signed context, so source provenance and context recipient binding cannot
    be confused or retargeted.
    """

    def __init__(self, *, service: Any, source_observers: Any,
                 channel_peer_registry: Any,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        from .source_observers import SourceObserverRegistry

        if (not isinstance(source_observers, SourceObserverRegistry)
                or source_observers.service is not service
                or getattr(channel_peer_registry, "__class__", type(None)).__module__
                   != "hermes_installer.authority.channel_peer_delivery"
                or getattr(channel_peer_registry, "__class__", type(None)).__name__
                   != "RootChannelPeerDeliveryRegistry"
                or not callable(getattr(channel_peer_registry, "resolve_retained_channel_proof", None))
                or not callable(getattr(channel_peer_registry, "validate_retained_channel_proof", None))
                or not callable(getattr(source_observers, "resolve_root_channel_source_delivery", None))
                or not callable(monotonic)):
            raise AuthorityDenied("native.channel.context", "root channel context store dependencies are unavailable")
        self.service = service
        self.source_observers = source_observers
        self.channel_peer_registry = channel_peer_registry
        self.monotonic = monotonic
        self._store_nonce = secrets.token_urlsafe(32)
        self._records: dict[str, _ContextRegistration] = {}
        self._lock = threading.RLock()
        self._closed = False

    def register_channel_context(
            self, *, proof: Any, native_binding: Any,
            source_receipt_handle: str, source_context: HostContext,
            event_payload_sha256: str, event_payload_size_bytes: int,
            expires_monotonic: float) -> RootNativeChannelContextRegistrationToken:
        """Register context membership for the exact reserved channel event.

        A caller cannot choose the peer, lineage, event content, or context
        claims. All those values must match the sealed channel proof and exact
        retained root event; this method mints only the new opaque handle.
        """
        from .channel_peer_delivery import (
            RootRetainedChannelDeliveryProof, VerifiedNativeChannelPeerBinding,
        )

        now = self.monotonic()
        if (type(proof) is not RootRetainedChannelDeliveryProof
                or type(native_binding) is not VerifiedNativeChannelPeerBinding
                or type(source_context) is not HostContext
                or not isinstance(source_receipt_handle, str)
                or not _HANDLE.fullmatch(source_receipt_handle)
                or not isinstance(event_payload_sha256, str)
                or not _SHA256.fullmatch(event_payload_sha256)
                or type(event_payload_size_bytes) is not int
                or not 1 <= event_payload_size_bytes <= 262_144
                or isinstance(expires_monotonic, bool)
                or type(expires_monotonic) not in (int, float)
                or not math.isfinite(expires_monotonic)):
            raise AuthorityDenied("native.channel.context", "channel context registration is malformed")
        if (proof.event_payload_sha256 != event_payload_sha256
                or proof.event_payload_size_bytes != event_payload_size_bytes
                or proof.expires_monotonic <= now
                or native_binding.binding_handle != proof.native_binding_handle):
            raise AuthorityDenied("native.channel.context", "context content or selected peer differs from proof")
        try:
            retained_event, retained_binding = self.channel_peer_registry.resolve_retained_channel_proof(proof)
            if (retained_binding is not native_binding
                    or not self.channel_peer_registry.validate_retained_channel_proof(
                        proof, event_handle=retained_event, native_binding=native_binding)):
                raise AuthorityDenied("native.channel.context", "retained channel proof is no longer current")
            event_record = self.channel_peer_registry.resource_registry.resolve_retained_event(retained_event)
            peer_fd = native_binding.duplicate_peer_pidfd()
            identity = self.source_observers.process_resolver(
                native_binding.peer_pid, peer_fd,
                profile_id=native_binding.profile_id, generation=native_binding.generation)
            current_identity = native_binding._peer.identity
            if (identity is None or identity != current_identity
                    or identity.kernel_uid != native_binding.peer_uid
                    or identity.profile_id != native_binding.profile_id
                    or identity.generation != native_binding.generation):
                raise AuthorityDenied("native.channel.context", "selected native peer PIDFD is stale")
            self.service._verify_context_signature(source_context)
            parent_receipts = tuple(event_record.parent_receipts)
            expected_parent_ids = tuple(item.receipt_id for item in parent_receipts)
            matching_receipts = [item for item in source_context.source_receipts
                                 if item.source_kind == "native-input"
                                 and item.payload_digest == proof.event_payload_sha256
                                 and item.parent_receipt_ids == expected_parent_ids]
            if len(matching_receipts) != 1:
                raise AuthorityDenied("native.channel.context", "derived channel source receipt is unavailable")
            source_receipt = matching_receipts[0]
            expected_ids = set(expected_parent_ids) | {source_receipt.receipt_id}
            self.service._verify_source_receipt(source_receipt, self.service._binding(native_binding.peer_uid))
            context_ids = tuple(item.receipt_id for item in source_context.source_receipts)
            source_binding = self.service._binding(native_binding.peer_uid)
            self.service._assert_current_context(
                source_context, source_binding, native_binding.peer_uid,
                peer_pid=native_binding.peer_pid)
            from .service import _context_digest
            if (not parent_receipts
                    or tuple(proof.original_source_receipt_ids) != expected_parent_ids
                    or tuple(source_receipt.parent_receipt_ids) != expected_parent_ids
                    or len(context_ids) != len(set(context_ids))
                    or set(context_ids) != expected_ids
                    or source_receipt.payload_digest != proof.event_payload_sha256
                    or source_receipt.source_kind != "native-input"
                    or source_context.final_payload_digest != proof.event_payload_sha256
                    or source_context.profile_id != native_binding.profile_id
                    or source_context.generation != native_binding.generation
                    or source_context.principal_id != native_binding.principal_id
                    or source_context.namespace_id != native_binding.namespace_id
                    or source_context.native_process_identity
                       != self.service._native_process_identity(native_binding.peer_pid,
                                                               native_binding.peer_uid)
                    or event_record.handle.payload_sha256 != proof.event_payload_sha256
                    or _context_digest(event_record.parent_context) != proof.original_source_context_digest
                    or event_record.handle.expires_monotonic <= now
                    or self.service.authority_epoch != event_record.handle.authority_epoch
                    or proof.expires_monotonic > min(source_receipt.monotonic_expires_at,
                                                     source_context.monotonic_expires_at)):
                raise AuthorityDenied("native.channel.context", "signed context does not bind retained event ancestry")
            expires = min(float(expires_monotonic), float(proof.expires_monotonic),
                          float(native_binding.expires_monotonic),
                          float(source_receipt.monotonic_expires_at),
                          float(source_context.monotonic_expires_at), now + _MAX_LEASE_SECONDS)
            if not now < expires:
                raise AuthorityDenied("native.channel.context", "channel context lease is expired")
            handle = secrets.token_urlsafe(32)
            while handle == source_receipt_handle:
                handle = secrets.token_urlsafe(32)
            token = RootNativeChannelContextRegistrationToken(
                handle, source_receipt_handle, self._store_nonce)
            row = _ContextRegistration(
                token=token, proof=proof, native_binding=native_binding,
                source_receipt=source_receipt, signed_context=source_context,
                payload_sha256=proof.event_payload_sha256,
                payload_size_bytes=event_payload_size_bytes, peer_uid=native_binding.peer_uid,
                peer_pid=native_binding.peer_pid, peer_identity=identity,
                profile_id=native_binding.profile_id, generation=native_binding.generation,
                package_id=native_binding.native_package_id,
                package_generation=native_binding.native_package_generation,
                authority_epoch=self.service.authority_epoch,
                service_generation_digest=self.service.service_generation_digest,
                expires_monotonic=expires, peer_pidfd=peer_fd,
            )
            with self._lock:
                self._prune_locked(now)
                if (self._closed or len(self._records) >= _MAX_CONTEXTS
                        or handle in self._records):
                    raise AuthorityDenied("native.channel.capacity", "native channel context store is unavailable")
                self._records[handle] = row
                peer_fd = -1
            return token
        except BaseException:
            if "peer_fd" in locals() and type(peer_fd) is int and peer_fd >= 0:
                try:
                    os.close(peer_fd)
                except OSError:
                    pass
            raise

    def verify_registered_channel_context(
            self, handle: str, *, proof: Any, native_binding: Any,
            source_receipt_handle: str, peer_uid: int, peer_pid: int,
            peer_pidfd: int) -> bool:
        """Non-consuming exact-membership check before channel queue commit."""
        if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            return False
        with self._lock:
            self._prune_locked(self.monotonic())
            row = self._records.get(handle)
            if (row is None or row.consumed or row.proof is not proof
                    or row.native_binding is not native_binding
                    or row.source_receipt_handle != source_receipt_handle
                    or (row.peer_uid, row.peer_pid) != (peer_uid, peer_pid)
                    or row.authority_epoch != self.service.authority_epoch
                    or row.service_generation_digest != self.service.service_generation_digest
                    or row.expires_monotonic <= self.monotonic()):
                return False
        try:
            retained_event, retained_binding = self.channel_peer_registry.resolve_retained_channel_proof(proof)
            if (retained_binding is not native_binding
                    or not self.channel_peer_registry.validate_retained_channel_proof(
                        proof, event_handle=retained_event, native_binding=native_binding)):
                return False
            live = self.source_observers.process_resolver(
                peer_pid, peer_pidfd, profile_id=row.profile_id, generation=row.generation)
            if live is None or live != row.peer_identity:
                return False
            with self.service._lock:
                retained_receipt = self.service._source_receipt_handles.get(source_receipt_handle)
            if retained_receipt is not row.source_receipt:
                return False
            self.service._verify_context_signature(row.signed_context)
            self.service._assert_current_context(
                row.signed_context, self.service._binding(peer_uid), peer_uid,
                peer_pid=peer_pid)
            delivered = self.source_observers.resolve_root_channel_source_delivery(
                source_receipt_handle, peer_uid=peer_uid, peer_pid=peer_pid,
                peer_pidfd=peer_pidfd)
            return str(delivered) == source_receipt_handle
        except Exception:
            return False

    def take_channel_context(self, *, peer_uid: int, peer_pid: int,
                             peer_pidfd: int,
                             producer_context_delivery_handle: str
                             ) -> NativeChannelContextDelivery | None:
        """Consume one context registration for its exact live native peer."""
        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not isinstance(producer_context_delivery_handle, str)
                or not _HANDLE.fullmatch(producer_context_delivery_handle)):
            raise AuthorityDenied("native.channel.context.take", "context delivery lookup is malformed")
        with self._lock:
            self._prune_locked(self.monotonic())
            row = self._records.get(producer_context_delivery_handle)
            if (row is None or row.consumed or row.peer_uid != peer_uid or row.peer_pid != peer_pid
                    or row.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("native.channel.context.take", "context handle is unknown, expired, or foreign")
            row.consumed = True
        try:
            retained_event, retained_binding = self.channel_peer_registry.resolve_retained_channel_proof(row.proof)
            if (retained_binding is not row.native_binding
                    or not self.channel_peer_registry.validate_retained_channel_proof(
                        row.proof, event_handle=retained_event, native_binding=row.native_binding)):
                raise AuthorityDenied("native.channel.context.take", "channel event or peer binding is stale")
            live = self.source_observers.process_resolver(
                peer_pid, peer_pidfd, profile_id=row.profile_id, generation=row.generation)
            if live is None or live != row.peer_identity:
                raise AuthorityDenied("native.channel.context.take", "native peer PIDFD changed")
            self.service._verify_context_signature(row.signed_context)
            self.service._assert_current_context(
                row.signed_context, self.service._binding(peer_uid), peer_uid,
                peer_pid=peer_pid)
            source_delivery = self.source_observers.resolve_root_channel_source_delivery(
                row.token.source_receipt_handle, peer_uid=peer_uid,
                peer_pid=peer_pid, peer_pidfd=peer_pidfd)
            with self.service._lock:
                retained_receipt = self.service._source_receipt_handles.get(
                    row.token.source_receipt_handle)
            if source_delivery is None or retained_receipt is not row.source_receipt:
                raise AuthorityDenied("native.channel.context.take", "source delivery membership is unavailable")
            return NativeChannelContextDelivery(
                schema=1, source_receipt_handle=row.token.source_receipt_handle,
                producer_context_delivery_handle=row.token.producer_context_delivery_handle,
                payload_sha256=row.payload_sha256, payload_size_bytes=row.payload_size_bytes,
                expires_monotonic=row.expires_monotonic,
            )
        except BaseException:
            self.revoke_channel_context(row.token)
            raise

    def revoke_channel_context(self, token: RootNativeChannelContextRegistrationToken) -> bool:
        """Rollback exact issuance token and close its owned PIDFD duplicate."""
        if (type(token) is not RootNativeChannelContextRegistrationToken
                or token._store_nonce != self._store_nonce):
            return False
        with self._lock:
            row = self._records.get(token.producer_context_delivery_handle)
            if row is None or row.token is not token:
                return False
            self._records.pop(token.producer_context_delivery_handle, None)
        try:
            os.close(row.peer_pidfd)
        except OSError:
            pass
        return True

    rollback_channel_context = revoke_channel_context

    def resolve_registered_channel_context(self, handle: str, *, peer_uid: int,
                                           peer_pid: int, peer_pidfd: int
                                           ) -> NativeChannelContextDelivery | None:
        """Resolve and consume one presentation for its authenticated peer.

        The signed context remains root-private and is never serialized. The
        consumer receives the same minimal DTO as the fixed take RPC.
        """
        return self.take_channel_context(
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            producer_context_delivery_handle=handle)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            rows = tuple(self._records.values())
            self._records.clear()
        for row in rows:
            try:
                os.close(row.peer_pidfd)
            except OSError:
                pass

    def _prune_locked(self, now: float) -> None:
        expired = [key for key, row in self._records.items()
                   if row.expires_monotonic <= now or row.authority_epoch != self.service.authority_epoch
                   or row.service_generation_digest != self.service.service_generation_digest]
        rows = [self._records.pop(key) for key in expired]
        for row in rows:
            try:
                os.close(row.peer_pidfd)
            except OSError:
                pass
