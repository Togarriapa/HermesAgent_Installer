"""Single-use producer/gateway bridge for native provider requests (HI11).

This module is constructed only by the root daemon from protected enrollment,
the root process custodian, and an artifact-pinned provider canonicalizer. A
worker can submit bytes and opaque receipt handles but cannot choose either
process, route, recipient, capability, or sensitivity.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import secrets
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, HostContext, Sensitivity, SourceReceipt, canonical_digest

MAX_EVENT_BYTES = 1_048_576
MAX_NORMALIZED_BYTES = 4 * 1024 * 1024
HANDLE_TTL = 30.0


@dataclass(slots=True)
class _PendingEvent:
    bridge_id: str
    handle: str
    context: HostContext
    normalized_payload: bytes
    retry_index: int
    expires: float
    producer_pid: int
    producer_pidfd: int
    producer_identity: Any
    capability: str


class NativeBridgeBroker:
    """Root-only atomic event admission and gateway dispatch coordinator."""

    def __init__(self, *, service: Any, bridges: Mapping[str, Any],
                 process_resolver: Callable[..., Any], canonicalizer: Callable[..., Any],
                 root_selected_enrollments: Mapping[str, Mapping[tuple[str, str], Any]],
                 canonicalizer_sha256: str):
        if (not bridges or not callable(process_resolver) or not callable(canonicalizer)
                or not root_selected_enrollments
                or set(root_selected_enrollments) != set(bridges)
                or not isinstance(canonicalizer_sha256, str) or len(canonicalizer_sha256) != 64):
            raise ValueError("native bridge requires protected enrollment and reviewed root adapters")
        source = inspect.getsourcefile(canonicalizer)
        if not source or hashlib.sha256(Path(source).read_bytes()).hexdigest() != canonicalizer_sha256:
            raise AuthorityDenied("native.canonicalizer", "provider canonicalizer does not match its protected artifact digest")
        if any(bridge.canonicalizer_artifact_id != "provider-canonicalizer-v1"
               or bridge.canonicalizer_sha256 != canonicalizer_sha256
               for bridge in bridges.values()):
            raise AuthorityDenied("native.canonicalizer", "native bridge enrollment names an unreviewed canonicalizer")
        self.service = service
        self.bridges = dict(bridges)
        self.process_resolver = process_resolver
        self.canonicalizer = canonicalizer
        self.root_selected_enrollments = {key: dict(value)
                                          for key, value in root_selected_enrollments.items()}
        self.canonicalizer_sha256 = canonicalizer_sha256
        self._pending: dict[str, _PendingEvent] = {}
        self._lock = threading.RLock()

    def prepare(self, *, uid: int, peer_pid: int, peer_pidfd: int,
                payload: Any, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        request = self._decode_request(payload, "prepare")
        binding = self.service._binding(uid)
        matches = [bridge for bridge in self.bridges.values()
                   if bridge.producer_profile_id == binding.profile_id
                   and bridge.producer_uid == uid
                   and bridge.producer_generation == self.service.profile_generations.get(binding.profile_id)]
        if len(matches) != 1:
            raise AuthorityDenied("native.issuer", "native producer has no unique protected bridge enrollment")
        bridge = matches[0]
        observed = self._resolve_peer(peer_pid, peer_pidfd, bridge.producer_profile_id,
                                      bridge.producer_generation, bridge.producer_uid,
                                      bridge.producer_executable_sha256)
        if cancelled():
            raise AuthorityDenied("native.cancelled", "native producer disconnected before capture")
        raw = self._decode_b64(request["payload"], MAX_EVENT_BYTES)
        parents = request["parent_receipt_handles"]
        if (not isinstance(parents, list) or len(parents) > 64
                or any(not isinstance(item, str) or not item for item in parents)):
            raise AuthorityDenied("native.lineage", "native parent receipt handles are malformed")
        retry = request["retry_index"]
        if type(retry) is not int or not 0 <= retry <= 100:
            raise AuthorityDenied("native.retry", "native retry index is invalid")
        purpose, intent, trace = request["purpose"], request["intent_id"], request["trace_id"]
        if (not self._text(purpose, 128) or not self._text(intent, 512)
                or not self._text(trace, 128)):
            raise AuthorityDenied("native.request", "native event metadata is malformed")

        # Resolve and consume parent handles once. Parent receipt claims remain
        # immutable ancestry; they do not grant repeat effects.
        parent_receipts = self._take_parent_closure(parents, uid, peer_pid)
        parent_context = self.service._issue_context(uid, {
            "purpose": purpose, "intent": intent, "trace_id": trace,
            "lease_seconds": HANDLE_TTL, "source_contexts": [],
            "source_receipts": [receipt.to_wire() for receipt in parent_receipts],
            "final_payload_digest": canonical_digest(raw),
            "operation": "native.event.prepare",
        }, inherited_process_identity=self.service._native_process_identity(peer_pid, uid))
        parent_context = HostContext.from_wire(parent_context)
        event_receipt = self.service.issue_source_receipt(
            parent_context, source_kind="native-input", origin_id="native-sdk-request",
            payload=raw, ttl_seconds=int(HANDLE_TTL))
        closure = {receipt.receipt_id: receipt for receipt in (*parent_receipts, event_receipt)}
        if any(not set(receipt.parent_receipt_ids).issubset(closure) for receipt in closure.values()):
            raise AuthorityDenied("native.lineage", "native source receipt closure is incomplete")

        normalized, target, recipient, capability, _model = self.canonicalizer(
            self.root_selected_enrollments[bridge.bridge_id], raw)
        if (not isinstance(normalized, bytes) or not 1 <= len(normalized) <= MAX_NORMALIZED_BYTES
                or target != bridge.target or recipient != bridge.recipient
                or capability not in {"provider-inference", "provider-tool-call"}
                or bridge.approved_operation != "provider.dispatch"):
            raise AuthorityDenied("native.canonicalizer", "canonical provider request differs from protected enrollment")
        context_wire = self.service._issue_context(uid, {
            "purpose": purpose, "intent": intent, "trace_id": trace,
            "lease_seconds": HANDLE_TTL, "source_contexts": [],
            "source_receipts": [item.to_wire() for item in closure.values()],
            "final_payload_digest": canonical_digest(normalized),
            "operation": "provider.dispatch",
        }, inherited_process_identity=self.service._native_process_identity(peer_pid, uid))
        context = HostContext.from_wire(context_wire)
        handle = secrets.token_urlsafe(32)
        expires = min(context.monotonic_expires_at, self.service.monotonic() + HANDLE_TTL)
        pinned_fd = __import__("os").dup(peer_pidfd)
        pending = _PendingEvent(bridge.bridge_id, handle, context, normalized,
                                retry, expires, peer_pid, pinned_fd, observed, capability)
        with self._lock:
            now = self.service.monotonic()
            self._prune(now)
            if len(self._pending) >= 4096:
                __import__("os").close(pinned_fd)
                raise AuthorityDenied("native.capacity", "native bridge admission is at capacity")
            self._pending[handle] = pending
        return {"native_event_handle": handle, "expires_monotonic": expires}

    def dispatch(self, *, uid: int, peer_pid: int, peer_pidfd: int,
                 payload: Any, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        request = self._decode_request(payload, "dispatch")
        handle, retry = request["native_event_handle"], request["retry_index"]
        if (not isinstance(handle, str) or not 32 <= len(handle) <= 128
                or type(retry) is not int or not 0 <= retry <= 100):
            raise AuthorityDenied("native.request", "native gateway handle or retry is invalid")
        normalized = self._decode_b64(request["normalized_payload"], MAX_NORMALIZED_BYTES)
        # Pop before any effect work. Concurrent, failed, or expired events
        # cannot be restored or replayed.
        with self._lock:
            pending = self._pending.pop(handle, None)
        if pending is None:
            raise AuthorityDenied("native.replay", "native event is unknown, expired, or already consumed")
        try:
            if self.service.monotonic() >= pending.expires or retry != pending.retry_index:
                raise AuthorityDenied("native.expired", "native event lease or retry binding is stale")
            bridge = self.bridges[pending.bridge_id]
            binding = self.service._binding(uid)
            if (binding.profile_id != bridge.gateway_profile_id
                    or uid != bridge.gateway_uid
                    or self.service.profile_generations.get(binding.profile_id) != bridge.gateway_generation):
                raise AuthorityDenied("native.gateway", "kernel peer is not the enrolled native gateway")
            gateway_identity = self._resolve_peer(peer_pid, peer_pidfd, bridge.gateway_profile_id,
                                                  bridge.gateway_generation, bridge.gateway_uid,
                                                  bridge.gateway_executable_sha256)
            current_producer = self._resolve_peer(pending.producer_pid, pending.producer_pidfd,
                                                  bridge.producer_profile_id, bridge.producer_generation,
                                                  bridge.producer_uid, bridge.producer_executable_sha256)
            if (gateway_identity is None or current_producer is None
                    or current_producer != pending.producer_identity
                    or normalized != pending.normalized_payload
                    or canonical_digest(normalized) != pending.context.final_payload_digest
                    or cancelled()):
                raise AuthorityDenied("native.binding", "native producer, gateway, digest, or lease changed")
            grant_wire = self.service._authorize_effect(pending.context.uid, {
                "context": pending.context.to_wire(), "capability": pending.capability,
                "target": bridge.target, "recipient": bridge.recipient,
                "request_digest": canonical_digest(normalized),
                "retry_index": pending.retry_index,
            })
            result = self.service._perform_effect(
                pending.context.uid, peer_pid, {
                    "authorization": grant_wire, "operation": "provider.dispatch",
                    "payload": base64.b64encode(normalized).decode("ascii"),
                    "timeout": max(0.001, pending.expires - self.service.monotonic()),
                }, cancelled=cancelled, peer_pidfd=peer_pidfd,
                enforce_peer_identity=False, reuse_source_receipts=True)
            return result
        finally:
            __import__("os").close(pending.producer_pidfd)

    def _resolve_peer(self, pid: int, pidfd: int, profile: str, generation: str,
                      uid: int, executable_sha256: str) -> Any:
        identity = self.process_resolver(pid, pidfd, profile_id=profile, generation=generation)
        if (identity is None or identity.profile_id != profile or identity.generation != generation
                or identity.kernel_uid != uid or identity.executable_sha256 != executable_sha256):
            raise AuthorityDenied("native.peer", "kernel peer is not a live enrolled process")
        return identity

    def _take_parent_closure(self, handles: list[str], uid: int,
                             peer_pid: int) -> tuple[SourceReceipt, ...]:
        now = self.service.monotonic()
        with self.service._lock:
            self.service._source_receipt_handles = {
                key: value for key, value in self.service._source_receipt_handles.items()
                if value.monotonic_expires_at > now
            }
            by_id = {value.receipt_id: value for value in self.service._source_receipt_handles.values()}
            selected: dict[str, SourceReceipt] = {}
            for handle in handles:
                receipt = self.service._source_receipt_handles.get(handle)
                if (receipt is None or receipt.uid != uid
                        or receipt.native_process_identity != self.service._native_process_identity(peer_pid, uid)):
                    raise AuthorityDenied("native.lineage", "native parent receipt is missing or belongs to another process")
                selected[receipt.receipt_id] = receipt
            pending = list(selected.values())
            while pending:
                receipt = pending.pop()
                for parent_id in receipt.parent_receipt_ids:
                    parent = by_id.get(parent_id)
                    if parent is None:
                        raise AuthorityDenied("native.lineage", "native parent receipt closure is incomplete")
                    if parent_id not in selected:
                        selected[parent_id] = parent
                        pending.append(parent)
        if len(selected) > 64:
            raise AuthorityDenied("native.lineage", "native parent receipt closure exceeds its bound")
        binding = self.service._binding(uid)
        for receipt in selected.values():
            self.service._verify_source_receipt(receipt, binding)
        return tuple(selected.values())

    @staticmethod
    def _decode_request(payload: Any, kind: str) -> dict[str, Any]:
        keys = ({"schema", "payload", "parent_receipt_handles", "purpose", "intent_id", "trace_id", "retry_index"}
                if kind == "prepare" else
                {"schema", "native_event_handle", "normalized_payload", "retry_index"})
        if not isinstance(payload, dict) or set(payload) != keys or payload.get("schema") != 1:
            raise AuthorityDenied("native.request", "native bridge request schema is invalid")
        return payload

    @staticmethod
    def _decode_b64(value: Any, limit: int) -> bytes:
        if not isinstance(value, str) or len(value) > ((limit + 2) // 3) * 4:
            raise AuthorityDenied("native.request", "native payload exceeds its bound")
        try:
            result = base64.b64decode(value, validate=True)
        except Exception:
            raise AuthorityDenied("native.request", "native payload encoding is malformed") from None
        if not 1 <= len(result) <= limit:
            raise AuthorityDenied("native.request", "native payload is empty or oversized")
        return result

    @staticmethod
    def _text(value: Any, limit: int) -> bool:
        return isinstance(value, str) and 1 <= len(value) <= limit and "\x00" not in value

    def _prune(self, now: float) -> None:
        import os
        for handle, pending in tuple(self._pending.items()):
            if pending.expires <= now:
                self._pending.pop(handle, None)
                os.close(pending.producer_pidfd)
