"""Root-side adapter for selected Hermes plugins and completed native effects.

This module contains the callpoints which must stay in the authority process:
installing the already root-selected package into the pinned Hermes plugin
manager, constructing each registration context from trusted enrollment, and
turning a validated completed effect into a one-use observed source receipt.
It is deliberately not an RPC surface. The caller of ``observe_effect_result``
must be the root authority after effect validation and before returning bytes
to the worker.
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, HostContext

_MAX_RESULT_BYTES = 1_048_576
_MAX_PARENT_RECEIPTS = 64


class NativeRuntimeObserverUnavailable(PermissionError):
    """Selected native runtime wiring or root observation is unavailable."""


class NativeRuntimeObserver:
    """Root-only observer for results from registered native effects.

    Hermes' PluginManager and selected package loader run in the unprivileged
    worker. This object runs only in the root authority daemon and is called
    after the daemon validates a registered effect response.
    """

    def __init__(self, *, source_observers: Any,
                 effect_observer_ids: Mapping[tuple[str, str, str], str]) -> None:
        if (not callable(getattr(source_observers, "record_observed_event", None))
                or not callable(getattr(source_observers, "capture_observed_source", None))
                or not isinstance(effect_observer_ids, Mapping)
                or not effect_observer_ids):
            raise NativeRuntimeObserverUnavailable("trusted native observer inputs are incomplete")
        pairs: dict[tuple[str, str, str], str] = {}
        enrolled = getattr(source_observers, "observers", None)
        if not isinstance(enrolled, Mapping):
            raise NativeRuntimeObserverUnavailable("root source observer enrollment is unavailable")
        for key, observer_id in effect_observer_ids.items():
            if (not isinstance(key, tuple) or len(key) != 3
                    or any(not isinstance(part, str) or not part for part in key)
                    or not isinstance(observer_id, str) or observer_id not in enrolled):
                raise NativeRuntimeObserverUnavailable("effect observer mapping is malformed")
            observer = enrolled[observer_id]
            if getattr(observer, "source_kind", None) not in {"tool-result", "provider-result"}:
                raise NativeRuntimeObserverUnavailable("effect observer is not enrolled for a result channel")
            if key in pairs:
                raise NativeRuntimeObserverUnavailable("effect observer mapping is ambiguous")
            pairs[key] = observer_id
        self.source_observers = source_observers
        self.effect_observer_ids = pairs
        self._lock = threading.RLock()
        self._closed = False

    def observe_effect_result(self, *, service: Any, context: HostContext,
                              authorization: Any, operation: str, target: str,
                              response_status: int, result_payload: bytes, peer_pid: int,
                              peer_pidfd: int,
                              cancelled: Callable[[], bool] = lambda: False) -> str:
        """Issue a receipt for exact result bytes after a root-validated effect.

        ``authorization`` and the successful result must come from the
        authority's already validated effect path. This method repeats the
        relevant joins so accidental early or cross-target callsites fail
        closed. The returned opaque handle is for peer-bound receipt delivery;
        it carries no independent effect authority.
        """
        if (not isinstance(context, HostContext)
                or not isinstance(result_payload, bytes)
                or not 1 <= len(result_payload) <= _MAX_RESULT_BYTES
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or type(response_status) is not int or not 200 <= response_status < 300
                or not callable(cancelled)):
            raise AuthorityDenied("source.observation", "completed successful native result is malformed")
        capability = getattr(authorization, "capability", None)
        granted_operation = getattr(authorization, "operation", None)
        granted_target = getattr(authorization, "target", None)
        if (granted_operation != operation or granted_target != target
                or not isinstance(capability, str)
                or getattr(authorization, "profile_id", None) != context.profile_id
                or getattr(authorization, "principal_id", None) != context.principal_id
                or getattr(authorization, "uid", None) != context.uid
                or getattr(authorization, "generation", None) != context.generation
                or getattr(authorization, "native_process_identity", None) != context.native_process_identity
                or getattr(authorization, "source_receipts", None) != context.source_receipts):
            raise AuthorityDenied("source.binding", "result does not match the completed enrolled effect")
        observer_id = self.effect_observer_ids.get((capability, operation, target))
        observer = self.source_observers.observers.get(observer_id) if observer_id else None
        if (observer is None or getattr(observer, "profile_id", None) != context.profile_id
                or getattr(observer, "generation", None) != context.generation
                or getattr(observer, "producer_uid", None) != context.uid):
            raise AuthorityDenied("source.observer", "completed effect has no matching root observer enrollment")
        if cancelled():
            raise AuthorityDenied("source.cancelled", "native result delivery was cancelled")
        parent_handles = self._parent_handles(service, context)
        event_id = self.source_observers.record_observed_event(
            observer_id, payload_bytes=result_payload, parent_context=context,
            peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            parent_receipt_handles=parent_handles,
        )
        if cancelled():
            raise AuthorityDenied("source.cancelled", "native result was cancelled before receipt issue")
        receipt_handle = self.source_observers.capture_observed_source(
            observer_id, event_id, result_payload, parent_receipt_handles=parent_handles)
        if not isinstance(receipt_handle, str) or len(receipt_handle) < 32:
            raise AuthorityDenied("source.issuer", "root observer returned no opaque result handle")
        return str(receipt_handle)

    def close(self) -> None:
        """Stop new observations when the selected package generation is retired."""
        with self._lock:
            self._closed = True

    def _parent_handles(self, service: Any, context: HostContext) -> tuple[str, ...]:
        with self._lock:
            if self._closed:
                raise AuthorityDenied("source.closed", "selected native runtime generation is retired")
        handles = getattr(service, "_source_receipt_handles", None)
        if not isinstance(handles, Mapping):
            if context.source_receipts:
                raise AuthorityDenied("source.lineage", "root parent receipt index is unavailable")
            return ()
        by_id = {receipt.receipt_id: handle for handle, receipt in handles.items()}
        selected: list[str] = []
        for receipt in context.source_receipts:
            handle = by_id.get(receipt.receipt_id)
            if not isinstance(handle, str):
                raise AuthorityDenied("source.lineage", "root parent receipt handle is unavailable")
            selected.append(handle)
        if len(selected) > _MAX_PARENT_RECEIPTS or len(selected) != len(set(selected)):
            raise AuthorityDenied("source.lineage", "root parent receipt closure is ambiguous or oversized")
        return tuple(selected)
