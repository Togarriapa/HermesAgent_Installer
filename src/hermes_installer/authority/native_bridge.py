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
import math
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from .types import (AuthorityDenied, EffectAuthorization, HostContext, Sensitivity,
                    SourceReceipt, canonical_digest)
from .native_request_observation import RootNativeRequestObservation

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
    request_observation_handle: str
    turn_handle: Any


@dataclass(frozen=True, slots=True)
class RootPendingNativePeer:
    """Root-selected live bridge peer; ``pidfd`` ownership belongs to broker."""

    role: str
    principal_id: str
    profile_id: str
    generation: str
    pid: int
    pidfd: int
    uid: int
    identity: Any
    role_artifact_id: str
    role_artifact_sha256: str


@dataclass(frozen=True, slots=True)
class RootObserverDeliveryBinding:
    observer_enrollment_id: str
    delivery_role: str


@dataclass(frozen=True, slots=True)
class RootPendingNativePair:
    """Immutable root-private pair record. Never serialized to a worker."""

    schema: int
    pair_id: str
    bridge_enrollment_id: str
    native_request_handle: str
    parent_context_sha256: str
    parent_grant_id: str
    intent_id: str
    trace_id: str
    parent_closure_digest: str
    service_generation_digest: str
    producer: RootPendingNativePeer
    gateway: RootPendingNativePeer
    observer_delivery_bindings: tuple[RootObserverDeliveryBinding, ...]
    expires_monotonic: float


@dataclass(slots=True)
class _PendingPairRecord:
    pair: RootPendingNativePair
    context_key: tuple[str, str, str, str, str]


class NativeBridgeBroker:
    """Root-only atomic event admission and gateway dispatch coordinator."""

    def __init__(self, *, service: Any, bridges: Mapping[str, Any],
                 process_resolver: Callable[..., Any], canonicalizer: Callable[..., Any],
                 root_selected_enrollments: Mapping[str, Mapping[tuple[str, str], Any]],
                 canonicalizer_sha256: str,
                 provider_response_registry: Any | None = None,
                 native_request_observer: Any | None = None,
                 observer_delivery_bindings: Mapping[str, tuple[RootObserverDeliveryBinding, ...]] | None = None,
                 peer_role_artifact_resolver: Callable[[Any, str], tuple[str, str]] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
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
        self.provider_response_registry = provider_response_registry
        self.native_request_observer = native_request_observer
        self.native_turn_observer = None
        if (observer_delivery_bindings is not None
                and (not isinstance(observer_delivery_bindings, Mapping)
                     or set(observer_delivery_bindings) != set(bridges))):
            raise ValueError("native bridge observer delivery map must match exact enrolled bridges")
        self.observer_delivery_bindings = dict(observer_delivery_bindings or {})
        if peer_role_artifact_resolver is not None and not callable(peer_role_artifact_resolver):
            raise ValueError("native bridge peer role artifact resolver must be root-callable")
        self.peer_role_artifact_resolver = peer_role_artifact_resolver
        self.monotonic = monotonic
        self._pending: dict[str, _PendingEvent] = {}
        self._pending_pairs: dict[str, _PendingPairRecord] = {}
        self._context_pair_index: dict[tuple[str, str, str, str, str], set[str]] = {}
        self._lock = threading.RLock()

    def attach_provider_response_registry(self, registry: Any) -> None:
        """Attach the root response observer once after cycle-safe construction."""
        from .native_runtime_observer import NativeInvocationRegistry

        if type(registry) is not NativeInvocationRegistry:
            raise AuthorityDenied("native.bridge_registry", "provider response registry type is invalid")
        if (registry.service is not self.service
                or registry.bridges != self.bridges
                or not callable(getattr(registry, "register_provider_response", None))
                or not callable(getattr(registry, "take_native_response_metadata", None))
                or not callable(getattr(registry, "begin_native_invocation", None))
                or not callable(getattr(registry, "get_invocation_contexts", None))):
            raise AuthorityDenied("native.bridge_registry", "provider response registry does not join this root runtime")
        with self._lock:
            if self.provider_response_registry is not None:
                raise AuthorityDenied("native.bridge_registry", "provider response registry is already attached")
            self.provider_response_registry = registry

    def attach_native_request_observer(self, registry: Any) -> None:
        """Attach the typed root request recorder after selected input wiring."""
        from .native_request_observation import NativeRequestObservationRegistry

        if (type(registry) is not NativeRequestObservationRegistry
                or registry.service is not self.service
                or registry.bridges != self.bridges
                or registry.process_resolver != self.process_resolver
                or registry.source_observers is not self.service.source_observer_registry):
            raise AuthorityDenied("native.request_observer", "root native request observer is invalid")
        with self._lock:
            if self.native_request_observer is not None:
                raise AuthorityDenied("native.request_observer", "root native request observer is already attached")
            self.native_request_observer = registry

    def attach_native_turn_observer(self, registry: Any) -> None:
        """Attach the exact root turn join once the selected input graph exists."""
        from .native_observer_wiring import RootNativeTurnObservationRegistry

        if type(registry) is not RootNativeTurnObservationRegistry:
            raise AuthorityDenied("native.request_turn", "root native turn observer has an invalid type")
        with self._lock:
            if self.native_turn_observer is not None:
                raise AuthorityDenied("native.request_turn", "root native turn observer is already attached")
            if self.native_request_observer is None or registry.service is not self.service:
                raise AuthorityDenied("native.request_turn", "request and turn observers do not join this service")
            attach_broker = getattr(registry, "attach_native_request_broker", None)
            if not callable(attach_broker):
                raise AuthorityDenied("native.request_turn", "turn observer has no typed broker attachment")
            attach_broker(self)
            self.native_turn_observer = registry

    def resolve_native_request_observation(self, receipt_handle: str, *,
                                          turn_handle: Any) -> Any:
        """Resolve a request record only while its producer and turn remain current."""
        observer, turns = self.native_request_observer, self.native_turn_observer
        if observer is None or turns is None:
            raise AuthorityDenied("native.request_observation", "root request and turn observers are unavailable")
        return observer.resolve_for_turn(
            receipt_handle, turn_handle=turn_handle, turn_registry=turns)

    def request_bytes(self, receipt_handle: str, producer_identity: Any) -> bytes:
        """Expose exact retained canonical bytes only to root in-process observers."""
        observer = self.native_request_observer
        if observer is None:
            raise AuthorityDenied("native.request_observation", "root request observer is unavailable")
        return observer.request_bytes(receipt_handle, producer_identity)

    def prepare(self, *, uid: int, peer_pid: int, peer_pidfd: int,
                payload: Any, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Root-observe, canonicalize, and atomically admit one provider attempt."""
        request = self._decode_request(payload, "prepare")
        raw = self._decode_b64(request["payload"], MAX_EVENT_BYTES)
        handles = request["parent_receipt_handles"]
        if (not isinstance(handles, list) or len(handles) > 64
                or any(not isinstance(item, str) or not item for item in handles)
                or len(set(handles)) != len(handles)
                or type(request["retry_index"]) is not int
                or not 0 <= request["retry_index"] <= 100):
            raise AuthorityDenied("native.request", "native source ancestry or retry is invalid")
        if cancelled():
            raise AuthorityDenied("effect.cancelled", "native request observation was cancelled")
        binding = self.service._binding(uid)
        candidates = [bridge for bridge in self.bridges.values()
                      if bridge.producer_uid == uid
                      and bridge.producer_profile_id == binding.profile_id
                      and bridge.producer_generation == self.service.profile_generations.get(binding.profile_id)
                      and bridge.producer_executable_sha256]
        if len(candidates) != 1:
            raise AuthorityDenied("native.producer", "authenticated peer has no unique selected provider producer")
        bridge = candidates[0]
        producer_identity = self._resolve_peer(
            peer_pid, peer_pidfd, bridge.producer_profile_id, bridge.producer_generation,
            bridge.producer_uid, bridge.producer_executable_sha256)
        parent_receipts = self._take_parent_closure(handles, uid, peer_pid)
        if not parent_receipts:
            raise AuthorityDenied("native.lineage", "provider request has no retained root-observed input ancestry")
        try:
            canonical, target, recipient, capability, _model = self.canonicalizer(
                self.root_selected_enrollments[bridge.bridge_id], raw,
                normalization_policy={
                    "id": bridge.normalization_policy_id,
                    "revision": bridge.normalization_policy_revision,
                    "route_schema_id": bridge.route_schema_id,
                    "output_limit_mode": bridge.output_limit_mode,
                    "output_limit_ceiling": bridge.output_limit_ceiling,
                })
        except Exception:
            raise AuthorityDenied("native.canonicalizer", "root provider request normalization failed") from None
        rule = self.service.rules.get((capability, bridge.approved_operation, target))
        if (not isinstance(canonical, bytes) or not 1 <= len(canonical) <= MAX_NORMALIZED_BYTES
                or target != bridge.target or recipient != bridge.recipient
                or rule is None or rule.recipient != recipient
                or (rule.operation, rule.target) not in self.service.handlers):
            raise AuthorityDenied("native.route", "canonical provider route is not the selected bridge route")
        if cancelled():
            raise AuthorityDenied("effect.cancelled", "native request observation was cancelled")
        now = self.monotonic()
        lease = min(now + HANDLE_TTL, *(row.monotonic_expires_at for row in parent_receipts))
        if lease <= now:
            raise AuthorityDenied("native.expired", "native source ancestry expired before request admission")
        context = HostContext.from_wire(self.service._issue_context(uid, {
            "purpose": "native-provider-request",
            "intent": canonical_digest({"bridge": bridge.bridge_id,
                                         "parents": sorted(row.receipt_id for row in parent_receipts),
                                         "retry": request["retry_index"]}),
            "trace_id": secrets.token_urlsafe(24),
            "lease_seconds": max(1, int(lease - now)),
            "source_contexts": [],
            "source_receipts": [row.to_wire() for row in parent_receipts],
            "final_payload_digest": canonical_digest(canonical),
            "operation": bridge.approved_operation,
        }, peer_pid=peer_pid))
        observer = self.native_request_observer
        if observer is None:
            raise AuthorityDenied("native.observer_unavailable", "root native request observation registry is unavailable")
        handle = secrets.token_urlsafe(32)
        observation = observer.record_request(
            bridge=bridge, native_request_handle=handle,
            producer_pid=peer_pid, producer_pidfd=peer_pidfd,
            producer_identity=producer_identity, canonical_request_bytes=canonical,
            retry_index=request["retry_index"], parent_receipt_handles=tuple(handles),
            parent_receipts=parent_receipts, parent_context=context,
            expires_monotonic=lease,
        )
        turn_registry = self.native_turn_observer
        if turn_registry is None:
            observer.revoke_native_request(observation.receipt_handle)
            raise AuthorityDenied("native.request_turn", "root native turn observer is unavailable")
        try:
            turn_handles = [turn_registry.resolve_turn_for_source(item, producer_identity)
                            for item in handles]
            if not turn_handles or any(item != turn_handles[0] for item in turn_handles):
                raise AuthorityDenied("native.request_turn", "request ancestry does not join one active turn")
            turn_registry.register_native_request(
                turn_handles[0], handle, observation.receipt_handle,
                tuple(handles), producer_identity, observation.request_sha256,
                observation.retry_index)
        except BaseException:
            observer.revoke_native_request(observation.receipt_handle)
            raise
        pending_fd = os.dup(peer_pidfd)
        pending = _PendingEvent(
            bridge_id=bridge.bridge_id, handle=handle, context=context,
            normalized_payload=canonical, retry_index=request["retry_index"],
            expires=lease, producer_pid=peer_pid, producer_pidfd=pending_fd,
            producer_identity=producer_identity, capability=capability,
            request_observation_handle=observation.receipt_handle,
            turn_handle=turn_handles[0],
        )
        with self._lock:
            self._prune(now)
            if cancelled():
                os.close(pending_fd)
                observer.revoke_native_request(observation.receipt_handle)
                raise AuthorityDenied("effect.cancelled", "native request admission was cancelled")
            if handle in self._pending:
                os.close(pending_fd)
                observer.revoke_native_request(observation.receipt_handle)
                raise AuthorityDenied("native.replay", "native request handle collision")
            if len(self._pending) >= 256:
                os.close(pending_fd)
                observer.revoke_native_request(observation.receipt_handle)
                raise AuthorityDenied("native.capacity", "native request admission table is full")
            self._pending[handle] = pending
        return {"native_event_handle": handle, "expires_monotonic": lease}

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
        pair_id: str | None = None
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
            request_observation = self.resolve_native_request_observation(
                pending.request_observation_handle, turn_handle=pending.turn_handle)
            if (gateway_identity is None or current_producer is None
                    or current_producer != pending.producer_identity
                    or normalized != pending.normalized_payload
                    or canonical_digest(normalized) != pending.context.final_payload_digest
                    or request_observation.native_request_handle != pending.handle
                    or request_observation.request_sha256 != canonical_digest(normalized)
                    or request_observation.retry_index != pending.retry_index
                    or request_observation.context_digest != canonical_digest(pending.context.to_wire())
                    or cancelled()):
                raise AuthorityDenied("native.binding", "native producer, gateway, digest, or lease changed")
            pair_id = self._register_pending_pair(
                bridge=bridge, pending=pending, gateway_pid=peer_pid,
                gateway_pidfd=peer_pidfd, gateway_identity=gateway_identity,
            )
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
                enforce_peer_identity=False,
                source_receipt_ids_to_consume=frozenset())
            if 200 <= result["status"] < 300:
                registry = self.provider_response_registry
                if registry is None:
                    raise AuthorityDenied(
                        "provider.observer_unavailable",
                        "successful provider result has no enrolled root response observer",
                    )
                enrollment = self.root_selected_enrollments[pending.bridge_id].get(
                    (bridge.target, bridge.recipient))
                if (enrollment is None or getattr(enrollment, "provider", None) not in {"openrouter", "codex"}
                        or getattr(enrollment, "target", None) != bridge.target
                        or getattr(enrollment, "recipient", None) != bridge.recipient):
                    raise AuthorityDenied("provider.enrollment", "provider response route is no longer enrolled")
                response_bytes = self._decode_b64(result["body"], 4 * 1024 * 1024)
                authorization = EffectAuthorization.from_wire(grant_wire)
                metadata = registry.register_provider_response(
                    bridge=bridge,
                    producer_identity=pending.producer_identity,
                    producer_pid=pending.producer_pid,
                    producer_pidfd=pending.producer_pidfd,
                    gateway_identity=gateway_identity,
                    gateway_pid=peer_pid,
                    gateway_pidfd=peer_pidfd,
                    request_context=pending.context,
                    request_source_receipts=pending.context.source_receipts,
                    authorization=authorization,
                    native_request_handle=pending.handle,
                    target=bridge.target,
                    recipient=bridge.recipient,
                    request_digest=canonical_digest(normalized),
                    response_status=result["status"],
                    response_headers=result["headers"],
                    response_bytes=response_bytes,
                    response_digest=canonical_digest(response_bytes),
                    expires_monotonic=min(pending.expires, authorization.monotonic_expires_at),
                    cancelled=cancelled,
                )
                delivery_handle = getattr(metadata, "response_delivery_handle", None)
                if (not isinstance(delivery_handle, str)
                        or not 32 <= len(delivery_handle) <= 128
                        or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                               for char in delivery_handle)):
                    raise AuthorityDenied("provider.observer_metadata", "root response delivery reference is malformed")
                result["headers"] = dict(result["headers"])
                result["headers"]["X-Hermes-Native-Response-Ref"] = delivery_handle
            return result
        finally:
            if pair_id is not None:
                self._retire_pending_pair(pair_id)
            __import__("os").close(pending.producer_pidfd)

    def resolve_pending_pair_for_context(self, parent_context: HostContext) -> RootPendingNativePair:
        """Return fresh peer PIDFD duplicates for the one active exact context pair.

        The index includes the signed context's full canonical digest and its
        grant/intent/trace/lineage fields. It cannot select by profile, target,
        recipient, caller-provided PID, or an opaque worker handle.
        """
        if not isinstance(parent_context, HostContext):
            raise AuthorityDenied("native.pair.context", "signed root context is required")
        key = self._context_key(parent_context)
        with self._lock:
            now = self.monotonic()
            self._prune(now)
            pair_ids = tuple(self._context_pair_index.get(key, ()))
            records = [self._pending_pairs[item] for item in pair_ids
                       if item in self._pending_pairs]
            if len(records) != 1:
                raise AuthorityDenied("native.pair.unavailable", "no unique active pending native pair")
            record = records[0]
            pair = record.pair
            bridge = self.bridges.get(pair.bridge_enrollment_id)
            if (record.context_key != key or now >= pair.expires_monotonic
                    or bridge is None
                    or pair.service_generation_digest != getattr(
                        self.service, "service_generation_digest", None)
                    or pair.parent_context_sha256 != canonical_digest(parent_context.to_wire())
                    or pair.parent_grant_id != parent_context.grant_id
                    or pair.intent_id != parent_context.intent_id
                    or pair.trace_id != parent_context.trace_id
                    or pair.parent_closure_digest != parent_context.lineage_hash):
                raise AuthorityDenied("native.pair.stale", "pending native pair no longer matches its context")
            self.service._verify_context_signature(parent_context)
            self.service._assert_current_context(
                parent_context, self.service._binding(pair.producer.uid), pair.producer.uid,
                peer_pid=pair.producer.pid,
            )
            for peer, selected_profile, selected_generation, selected_uid, selected_executable in (
                    (pair.producer, bridge.producer_profile_id, bridge.producer_generation,
                     bridge.producer_uid, bridge.producer_executable_sha256),
                    (pair.gateway, bridge.gateway_profile_id, bridge.gateway_generation,
                     bridge.gateway_uid, bridge.gateway_executable_sha256)):
                current = self.process_resolver(
                    peer.pid, peer.pidfd, profile_id=selected_profile,
                    generation=selected_generation,
                )
                if (current is None or current != peer.identity
                        or current.profile_id != selected_profile
                        or current.generation != selected_generation
                        or current.kernel_uid != selected_uid
                        or current.executable_sha256 != selected_executable
                        or peer.uid != selected_uid):
                    raise AuthorityDenied("native.pair.peer", "pending native pair peer is no longer live")
            try:
                producer = RootPendingNativePeer(**{
                    **{name: getattr(pair.producer, name)
                       for name in pair.producer.__dataclass_fields__},
                    "pidfd": os.dup(pair.producer.pidfd),
                })
                gateway = RootPendingNativePeer(**{
                    **{name: getattr(pair.gateway, name)
                       for name in pair.gateway.__dataclass_fields__},
                    "pidfd": os.dup(pair.gateway.pidfd),
                })
            except BaseException:
                for peer in locals().get("producer", ()), locals().get("gateway", ()):
                    if isinstance(peer, RootPendingNativePeer):
                        try:
                            os.close(peer.pidfd)
                        except OSError:
                            pass
                raise
            return RootPendingNativePair(
                schema=pair.schema, pair_id=pair.pair_id,
                bridge_enrollment_id=pair.bridge_enrollment_id,
                native_request_handle=pair.native_request_handle,
                parent_context_sha256=pair.parent_context_sha256,
                parent_grant_id=pair.parent_grant_id, intent_id=pair.intent_id,
                trace_id=pair.trace_id, parent_closure_digest=pair.parent_closure_digest,
                service_generation_digest=pair.service_generation_digest,
                producer=producer, gateway=gateway,
                observer_delivery_bindings=pair.observer_delivery_bindings,
                expires_monotonic=pair.expires_monotonic,
            )

    def _register_pending_pair(self, *, bridge: Any, pending: _PendingEvent,
                               gateway_pid: int, gateway_pidfd: int,
                               gateway_identity: Any) -> str:
        """Retain the authenticated pair for the duration of synchronous dispatch."""
        if self.peer_role_artifact_resolver is None:
            raise AuthorityDenied("native.pair.roles", "protected peer role artifact resolver is unavailable")
        bindings = self.observer_delivery_bindings.get(bridge.bridge_id)
        if (not isinstance(bindings, tuple) or not bindings
                or any(not isinstance(row, RootObserverDeliveryBinding)
                       or row.delivery_role not in {"producer", "gateway"}
                       or not row.observer_enrollment_id for row in bindings)
                or len({row.observer_enrollment_id for row in bindings}) != len(bindings)):
            raise AuthorityDenied("native.pair.bindings", "explicit observer delivery bindings are unavailable")
        producer_role = self.peer_role_artifact_resolver(bridge, "producer")
        gateway_role = self.peer_role_artifact_resolver(bridge, "gateway")
        for role in (producer_role, gateway_role):
            if (not isinstance(role, tuple) or len(role) != 2
                    or any(not isinstance(value, str) or not value for value in role)
                    or not __import__("re").fullmatch(r"[0-9a-f]{64}", role[1])):
                raise AuthorityDenied("native.pair.roles", "protected peer role artifact identity is malformed")
        producer_fd = os.dup(pending.producer_pidfd)
        gateway_fd = -1
        try:
            gateway_fd = os.dup(gateway_pidfd)
            producer = RootPendingNativePeer(
                "producer", bridge.producer_principal_id, bridge.producer_profile_id,
                bridge.producer_generation, pending.producer_pid, producer_fd,
                bridge.producer_uid, pending.producer_identity, producer_role[0], producer_role[1],
            )
            gateway = RootPendingNativePeer(
                "gateway", bridge.gateway_principal_id, bridge.gateway_profile_id,
                bridge.gateway_generation, gateway_pid, gateway_fd,
                bridge.gateway_uid, gateway_identity, gateway_role[0], gateway_role[1],
            )
            now = self.monotonic()
            expiry = min(pending.expires, pending.context.monotonic_expires_at)
            if (not math.isfinite(expiry) or expiry <= now
                    or getattr(self.service, "service_generation_digest", None) is None):
                raise AuthorityDenied("native.pair.expired", "pending native pair lease is unavailable")
            pair_id = secrets.token_urlsafe(32)
            pair = RootPendingNativePair(
                schema=1, pair_id=pair_id, bridge_enrollment_id=bridge.bridge_id,
                native_request_handle=pending.handle,
                parent_context_sha256=canonical_digest(pending.context.to_wire()),
                parent_grant_id=pending.context.grant_id, intent_id=pending.context.intent_id,
                trace_id=pending.context.trace_id, parent_closure_digest=pending.context.lineage_hash,
                service_generation_digest=self.service.service_generation_digest,
                producer=producer, gateway=gateway,
                observer_delivery_bindings=bindings, expires_monotonic=expiry,
            )
            context_key = self._context_key(pending.context)
            with self._lock:
                self._prune(now)
                if context_key in self._context_pair_index:
                    raise AuthorityDenied("native.pair.ambiguous", "context already has a current pending native pair")
                self._pending_pairs[pair_id] = _PendingPairRecord(pair, context_key)
                self._context_pair_index[context_key] = {pair_id}
            return pair_id
        except BaseException:
            for fd in (producer_fd, gateway_fd):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
            raise

    def _retire_pending_pair(self, pair_id: str) -> None:
        with self._lock:
            record = self._pending_pairs.pop(pair_id, None)
            if record is None:
                return
            ids = self._context_pair_index.get(record.context_key)
            if ids is not None:
                ids.discard(pair_id)
                if not ids:
                    self._context_pair_index.pop(record.context_key, None)
        for peer in (record.pair.producer, record.pair.gateway):
            try:
                os.close(peer.pidfd)
            except OSError:
                pass

    @staticmethod
    def _context_key(context: HostContext) -> tuple[str, str, str, str, str]:
        return (context.grant_id, context.intent_id, context.trace_id,
                canonical_digest(context.to_wire()), context.lineage_hash)

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
        for handle, pending in tuple(self._pending.items()):
            if pending.expires <= now:
                self._pending.pop(handle, None)
                try:
                    os.close(pending.producer_pidfd)
                except OSError:
                    pass
        for pair_id, record in tuple(self._pending_pairs.items()):
            if record.pair.expires_monotonic <= now:
                self._retire_pending_pair(pair_id)

    def close(self) -> None:
        with self._lock:
            handles = tuple(self._pending)
            pairs = tuple(self._pending_pairs)
            pending = [self._pending.pop(handle) for handle in handles]
        for item in pending:
            try:
                os.close(item.producer_pidfd)
            except OSError:
                pass
        for pair_id in pairs:
            self._retire_pending_pair(pair_id)
        if self.native_request_observer is not None:
            self.native_request_observer.close()
