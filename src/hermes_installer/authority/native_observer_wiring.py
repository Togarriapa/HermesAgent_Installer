"""Root-owned pre-stdin native task input coordination.

This coordinator runs inside the root runtime between managed task launch and
the first stdin write.  It binds the already-resolved task/source snapshot,
selects the exact native execution, captures and peer-delivers its initial
input, and retains a one-use receipt for custody to validate before EOF.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from .types import AuthorityDenied

_MAX_STDIN_BYTES = 262_144
_MAX_INPUT_LEASE = 30.0


@dataclass(slots=True)
class _InitialInputRecord:
    receipt: Any
    admission_handle: Any
    source: Any
    selected_execution: Any
    managed_task_handle: Any
    cancelled: Callable[[], bool]
    peer_pid: int
    peer_uid: int
    peer_identity: Any
    profile_id: str
    generation: str
    consumed: bool = False


class RootTaskInputCoordinator:
    """Join task custody, selected execution, source capture, and receipt.

    Dependencies are the concrete root registries.  The class is not a worker
    API and accepts no PID/profile/observer/action selector from a caller.
    """

    def __init__(self, *, task_native_observation_registry: Any,
                 selected_native_execution_registry: Any,
                 initial_native_input_observer: Any,
                 source_delivery_registry: Any,
                 process_custody_registry: Any,
                 native_input_delivery_registry: Any,
                 monotonic: Callable[[], float] = time.monotonic):
        if (not callable(getattr(task_native_observation_registry, "bind_running_task", None))
                or not callable(getattr(task_native_observation_registry, "bind_task_input", None))
                or not callable(getattr(task_native_observation_registry, "cancel_running_task", None))
                or not callable(getattr(task_native_observation_registry, "cancel_task_input", None))
                or not callable(getattr(selected_native_execution_registry, "select_resource_task", None))
                or not callable(getattr(selected_native_execution_registry, "resolve_current_execution", None))
                or not callable(getattr(selected_native_execution_registry, "resolve_selected_native_input_target", None))
                or not callable(getattr(initial_native_input_observer, "record_selected_task_input", None))
                or not callable(getattr(initial_native_input_observer, "retain_task_input_receipt", None))
                or not callable(getattr(initial_native_input_observer, "resolve_task_input_receipt", None))
                or not callable(getattr(initial_native_input_observer, "discard_task_input_observation", None))
                or not callable(getattr(source_delivery_registry, "resolve_delivered_source_receipt", None))
                or not callable(getattr(native_input_delivery_registry, "queue_selected_input", None))
                or not callable(getattr(native_input_delivery_registry, "wait_delivered", None))
                or not callable(getattr(native_input_delivery_registry, "cancel_selected_input", None))
                or not callable(getattr(process_custody_registry, "resolve_managed_task_process_handle", None))
                or not callable(monotonic)):
            raise ValueError("root task input coordinator dependencies are incomplete")
        self.task_native_observations = task_native_observation_registry
        self.selected_executions = selected_native_execution_registry
        self.input_observer = initial_native_input_observer
        self.source_delivery = source_delivery_registry
        self.process_custody = process_custody_registry
        self.native_input_delivery = native_input_delivery_registry
        self.monotonic = monotonic
        self._records: dict[str, _InitialInputRecord] = {}
        self._lock = threading.RLock()

    @classmethod
    def from_root_runtime(cls, task_native_observation_registry: Any,
                          selected_native_execution_registry: Any,
                          initial_native_input_observer: Any,
                          source_delivery_registry: Any,
                          process_custody_registry: Any,
                          native_input_delivery_registry: Any) -> "RootTaskInputCoordinator":
        return cls(
            task_native_observation_registry=task_native_observation_registry,
            selected_native_execution_registry=selected_native_execution_registry,
            initial_native_input_observer=initial_native_input_observer,
            source_delivery_registry=source_delivery_registry,
            process_custody_registry=process_custody_registry,
            native_input_delivery_registry=native_input_delivery_registry,
        )

    def prepare_initial_input(self, *, task_admission: Any, admission_handle: Any,
                              node_id: str, source: Any, managed_task_handle: Any,
                              exact_stdin: bytes, timeout: float,
                              cancelled: Callable[[], bool]) -> Any:
        """Capture/deliver initial prompt and return its retained typed receipt."""
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import (
            RootAdmittedTask, RootAdmittedTaskSource,
            RootResourceJobAdmissionHandle, RootTaskInitialInputReceipt,
        )

        now = self.monotonic()
        if (type(task_admission) is not RootAdmittedTask
                or type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(source) is not RootAdmittedTaskSource
                or type(managed_task_handle) is not ManagedTaskHandle
                or node_id != task_admission.node_id
                or admission_handle.node_id != node_id
                or not isinstance(exact_stdin, bytes)
                or not 1 <= len(exact_stdin) <= _MAX_STDIN_BYTES
                or hashlib.sha256(exact_stdin).hexdigest() != task_admission.stdin_sha256
                or len(exact_stdin) != task_admission.stdin_size_bytes
                or isinstance(timeout, bool) or type(timeout) not in (int, float)
                or not math.isfinite(timeout) or timeout <= 0
                or not callable(cancelled)
                or task_admission.admission_id != admission_handle.admission_id
                or source.parent_closure_digest != task_admission.parent_closure_digest
                or source.expires_monotonic <= now
                or task_admission.deadline_monotonic <= now):
            raise AuthorityDenied("native.input.task", "root selected initial-input arguments are invalid")
        self._check_cancelled(cancelled)

        # The caller passes the already-resolved source snapshot.  This first
        # bind is its one-use/currentness check; never resolve it again here.
        task_binding_attempted = True
        selected = None
        try:
            self.task_native_observations.bind_running_task(
                admission_handle, node_id, source, managed_task_handle)
            self._check_cancelled(cancelled)
            selected = self.selected_executions.select_resource_task(
                admission_handle, node_id, managed_task_handle)
            current = self.selected_executions.resolve_current_execution(selected)
            if (current is not selected
                    or getattr(selected, "execution_handle", None) is not admission_handle
                    or getattr(selected, "process_handle", None) is not managed_task_handle
                    or getattr(selected, "kind", None) != "resource-task"
                    or getattr(selected, "observer_enrollment_id", None) is None):
                raise AuthorityDenied("native.input.selection", "selected native execution differs from the live task")
        except BaseException:
            if selected is not None:
                self._release_selection(selected)
            cancel_running = getattr(self.task_native_observations, "cancel_running_task", None)
            if callable(cancel_running):
                try:
                    cancel_running(managed_task_handle)
                except Exception:
                    pass
            raise

        target = None
        source_handle = None
        receipt_handle = None
        initial_receipt = None
        try:
            target = self.selected_executions.resolve_selected_native_input_target(selected)
            self._check_cancelled(cancelled)
            expires = min(
                float(task_admission.deadline_monotonic), float(source.expires_monotonic),
                float(selected.expires_monotonic), float(target.expires_monotonic),
                now + min(float(timeout), _MAX_INPUT_LEASE),
            )
            if not self.monotonic() < expires:
                raise AuthorityDenied("native.input.expired", "selected task input lease has expired")
            peer_pid = target.peer_pid
            peer_uid = target.live_peer_identity.kernel_uid
            peer_identity = target.live_peer_identity
            target_profile_id = target.profile_id
            target_generation = target.generation
            target_for_capture, target = target, None
            event = self.input_observer.record_selected_task_input(
                selected_execution=selected, source=source,
                exact_stdin=exact_stdin, target=target_for_capture,
            )
            self._check_cancelled(cancelled)
            if (getattr(event, "schema", None) != 1
                    or getattr(event, "payload_sha256", None) != task_admission.stdin_sha256
                    or getattr(event, "payload_size_bytes", None) != task_admission.stdin_size_bytes
                    or getattr(event, "producer_profile_id", None) != selected.profile_id
                    or getattr(event, "producer_generation", None) != selected.generation
                    or getattr(event, "parent_closure_digest", None) != source.parent_closure_digest
                    or getattr(event, "expires_monotonic", 0) <= self.monotonic()):
                raise AuthorityDenied("native.input.receipt", "root input capture differs from the selected task")

            source_handle = getattr(event, "source_receipt_handle", None)
            self.native_input_delivery.queue_selected_input(selected, event)
            delivery = self.native_input_delivery.wait_delivered(
                selected, timeout=min(float(timeout), 30.0), cancelled=cancelled)
            from .source_observers import NativeInitialInputDelivery
            if (type(delivery) is not NativeInitialInputDelivery
                    or delivery.source_receipt_handle != source_handle
                    or delivery.selected_execution_handle != selected.selection_handle
                    or delivery.input_sha256 != task_admission.stdin_sha256
                    or delivery.input_size_bytes != task_admission.stdin_size_bytes
                    or delivery.expires_monotonic > event.expires_monotonic
                    or delivery.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("native.input.delivery", "producer take did not bind the selected input event")
            delivery_lease = self.process_custody.resolve_managed_task_process_handle(
                managed_task_handle)
            if delivery_lease is None:
                raise AuthorityDenied("native.input.delivery", "selected task exited before initial-input delivery")
            try:
                current_identity = self.process_custody.resolve_live_peer(
                    delivery_lease.pid, delivery_lease.pidfd,
                    profile_id=delivery_lease.profile_id,
                    generation=delivery_lease.generation,
                )
                if (delivery_lease.pid != peer_pid or delivery_lease.uid != peer_uid
                        or current_identity is None or current_identity != peer_identity):
                    raise AuthorityDenied("native.input.delivery", "producer peer changed before initial-input delivery")
                delivered = self.source_delivery.resolve_delivered_source_receipt(
                    str(source_handle), peer_uid=delivery_lease.uid,
                    peer_pid=delivery_lease.pid, peer_pidfd=delivery_lease.pidfd)
            finally:
                delivery_lease.close()
            if str(delivered) != str(source_handle):
                raise AuthorityDenied("native.input.delivery", "source receipt delivery handle changed")
            receipt = self._resolve_source_receipt(source_handle)
            # The input observer consumes the target PIDFD during capture; the
            # exact ready event is carried by its immutable root event record.
            ready_event_id = getattr(event, "native_loader_ready_event_id", None)
            if not isinstance(ready_event_id, str) or not ready_event_id:
                raise AuthorityDenied("native.input.loader", "root loaded-closure proof lacks loader readiness")
            service = getattr(self.source_delivery, "service", None)
            if service is None or getattr(service, "service_generation_digest", None) != selected.service_generation_digest:
                raise AuthorityDenied("native.input.epoch", "selected source delivery service epoch changed")
            receipt_handle = secrets.token_urlsafe(32)
            initial_receipt = RootTaskInitialInputReceipt(
                schema=1, receipt_handle=receipt_handle,
                task_handle=managed_task_handle.handle_id,
                admission_id=task_admission.admission_id, node_id=node_id,
                process_id=managed_task_handle.process_id,
                process_generation=selected.generation,
                selected_execution_handle=selected.selection_handle,
                source_receipt_handle=str(source_handle),
                producer_context_delivery_handle=str(source_handle),
                native_loader_ready_event_id=ready_event_id,
                stdin_sha256=task_admission.stdin_sha256,
                stdin_size_bytes=task_admission.stdin_size_bytes,
                parent_closure_digest=task_admission.parent_closure_digest,
                service_generation_digest=selected.service_generation_digest,
                resource_generation=task_admission.resource_generation,
                issued_monotonic=self.monotonic(), expires_monotonic=expires,
            )
            self.input_observer.retain_task_input_receipt(initial_receipt)
            with self._lock:
                if receipt_handle in self._records:
                    raise AuthorityDenied("native.input.replay", "task input receipt handle collided")
                self._records[receipt_handle] = _InitialInputRecord(
                    receipt=initial_receipt, admission_handle=admission_handle,
                    source=source, selected_execution=selected,
                    managed_task_handle=managed_task_handle, cancelled=cancelled,
                    peer_pid=peer_pid, peer_uid=peer_uid,
                    peer_identity=peer_identity, profile_id=target_profile_id,
                    generation=target_generation,
                )
            self.task_native_observations.bind_task_input(
                task_handle=managed_task_handle, admission=admission_handle,
                source=source, selected_execution=selected,
                initial_input=initial_receipt,
            )
            return initial_receipt
        except BaseException:
            try:
                self.native_input_delivery.cancel_selected_input(selected)
            except Exception:
                pass
            if receipt_handle is not None:
                with self._lock:
                    self._records.pop(receipt_handle, None)
            if source_handle is not None:
                cancel = getattr(self.task_native_observations, "cancel_task_input", None)
                if callable(cancel) and initial_receipt is not None:
                    try:
                        cancel(task_handle=managed_task_handle,
                               initial_input_receipt=initial_receipt)
                    except Exception:
                        pass
                self.input_observer.discard_task_input_observation(
                    source_receipt_handle=str(source_handle),
                    receipt_handle=receipt_handle,
                )
            if task_binding_attempted and initial_receipt is None:
                cancel_running = getattr(self.task_native_observations, "cancel_running_task", None)
                if callable(cancel_running):
                    try:
                        cancel_running(managed_task_handle)
                    except Exception:
                        pass
            if target is not None:
                self._close_target(target)
            self._release_selection(selected)
            raise

    def resolve_initial_input_receipt(self, receipt_handle: str, *,
                                      task_handle: Any, stdin_sha256: str,
                                      stdin_size_bytes: int) -> Any:
        """Non-consuming currentness lookup for custody before stdin write."""
        record = self._lookup_record(receipt_handle, task_handle, stdin_sha256,
                                     stdin_size_bytes, consume=False)
        return record.receipt

    def consume_initial_input_receipt(self, receipt_handle: str, *,
                                      task_handle: Any, stdin_sha256: str,
                                      stdin_size_bytes: int) -> Any:
        """Consume the receipt once for the pre-stdin write/EOF phase."""
        record = self._lookup_record(receipt_handle, task_handle, stdin_sha256,
                                     stdin_size_bytes, consume=True)
        return record.receipt

    def revoke_initial_input_receipt(self, receipt_handle: str, *,
                                     task_handle: Any) -> bool:
        """Revoke an exact prepared input on custody cancellation/failure."""
        from ..managed_process_custodian import ManagedTaskHandle

        if type(task_handle) is not ManagedTaskHandle:
            raise AuthorityDenied("native.input.receipt", "task input revocation handle is malformed")
        with self._lock:
            record = self._records.get(receipt_handle)
            if (record is None or record.managed_task_handle is not task_handle
                    or record.receipt.receipt_handle != receipt_handle):
                return False
            self._records.pop(receipt_handle, None)
            record.consumed = True
        cancel = getattr(self.task_native_observations, "cancel_task_input", None)
        if callable(cancel):
            cancel(task_handle=task_handle, initial_input_receipt=record.receipt)
        self.input_observer.discard_task_input_observation(
            source_receipt_handle=record.receipt.source_receipt_handle,
            receipt_handle=record.receipt.receipt_handle,
        )
        self.native_input_delivery.cancel_selected_input(record.selected_execution)
        release = getattr(self.selected_executions, "release_selection", None)
        if callable(release):
            try:
                release(record.selected_execution)
            except Exception:
                pass
        return True

    def _lookup_record(self, receipt_handle: str, task_handle: Any,
                       stdin_sha256: str, stdin_size_bytes: int,
                       *, consume: bool) -> _InitialInputRecord:
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import RootTaskInitialInputReceipt

        if (not isinstance(receipt_handle, str) or not 32 <= len(receipt_handle) <= 128
                or type(task_handle) is not ManagedTaskHandle
                or not isinstance(stdin_sha256, str) or len(stdin_sha256) != 64
                or type(stdin_size_bytes) is not int or not 0 <= stdin_size_bytes <= _MAX_STDIN_BYTES):
            raise AuthorityDenied("native.input.receipt", "initial input receipt lookup is malformed")
        with self._lock:
            record = self._records.get(receipt_handle)
            if (record is None or type(record.receipt) is not RootTaskInitialInputReceipt
                    or record.receipt.receipt_handle != receipt_handle
                    or record.managed_task_handle is not task_handle
                    or record.consumed or self.monotonic() >= record.receipt.expires_monotonic
                    or record.receipt.stdin_sha256 != stdin_sha256
                    or record.receipt.stdin_size_bytes != stdin_size_bytes):
                raise AuthorityDenied("native.input.receipt", "initial input receipt is stale, mismatched, or consumed")
            if record.cancelled() is not False:
                raise AuthorityDenied("native.input.cancelled", "selected task was cancelled before stdin")
        selected = self.selected_executions.resolve_current_execution(record.selected_execution)
        if selected is not record.selected_execution:
            raise AuthorityDenied("native.input.selection", "selected native task execution changed")
        lease = self.process_custody.resolve_managed_task_process_handle(task_handle)
        if lease is None:
            raise AuthorityDenied("native.input.process", "managed task is no longer live")
        try:
            if (lease.process_id != task_handle.process_id
                    or lease.pid != record.peer_pid or lease.uid != record.peer_uid
                    or lease.profile_id != record.profile_id
                    or lease.generation != record.generation
                    or lease.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("native.input.target", "current task target differs from input receipt")
            identity = self.process_custody.resolve_live_peer(
                lease.pid, lease.pidfd, profile_id=lease.profile_id,
                generation=lease.generation,
            )
            if identity is None or identity != record.peer_identity:
                raise AuthorityDenied("native.input.target", "managed task process identity changed")
            delivered = self.source_delivery.resolve_delivered_source_receipt(
                record.receipt.producer_context_delivery_handle,
                peer_uid=lease.uid, peer_pid=lease.pid, peer_pidfd=lease.pidfd,
            )
            if str(delivered) != record.receipt.source_receipt_handle:
                raise AuthorityDenied("native.input.delivery", "delivered context handle changed")
            exact_event = self.input_observer.resolve_task_input_receipt(
                record.receipt.receipt_handle)
            if exact_event is not record.receipt:
                raise AuthorityDenied("native.input.receipt", "input receipt object is not root-retained")
        finally:
            close = getattr(lease, "close", None)
            if callable(close):
                close()
        if consume:
            with self._lock:
                if record.consumed or self._records.get(receipt_handle) is not record:
                    raise AuthorityDenied("native.input.replay", "initial input receipt was consumed concurrently")
                record.consumed = True
        return record

    def _resolve_source_receipt(self, handle: Any) -> Any:
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise AuthorityDenied("native.input.receipt", "source observer returned a malformed receipt handle")
        service = getattr(self.source_delivery, "service", None)
        lock = getattr(service, "_lock", None)
        if service is None or lock is None:
            raise AuthorityDenied("native.input.receipt", "root service receipt table is unavailable")
        with lock:
            receipt = service._source_receipt_handles.get(handle)
        if receipt is None:
            raise AuthorityDenied("native.input.receipt", "source observer receipt was not retained")
        return receipt

    @staticmethod
    def _check_cancelled(cancelled: Callable[[], bool]) -> None:
        try:
            result = cancelled()
        except Exception:
            raise AuthorityDenied("native.input.cancelled", "task cancellation state is unavailable") from None
        if result is not False:
            raise AuthorityDenied("native.input.cancelled", "task was cancelled before stdin")

    @staticmethod
    def _close_target(target: Any) -> None:
        try:
            target.close()
        except Exception:
            try:
                import os
                os.close(target.peer_pidfd)
            except Exception:
                pass

    def _release_selection(self, selected: Any) -> None:
        release = getattr(self.selected_executions, "release_selection", None)
        if callable(release):
            try:
                release(selected)
            except Exception:
                pass
