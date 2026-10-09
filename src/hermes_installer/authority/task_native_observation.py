"""Root observations joining an admitted Hermes task to native execution.

This registry keeps the event evidence in the authority process. Worker output,
exit status, and caller supplied event identifiers are never treated as native
execution proof.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from ..registry.resource_jobs import RootTaskNativeExecutionReceipt
from .types import AuthorityDenied

_DIGEST = frozenset("0123456789abcdef")
_MAX_ACTIVE_TASKS = 128
_MAX_EVENT_IDS = 256
_POLL_SECONDS = 0.01


def _digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in _DIGEST for char in value))


def _opaque(value: Any) -> bool:
    return (isinstance(value, str) and 32 <= len(value) <= 128
            and all(char.isalnum() or char in "_-" for char in value))


@dataclass(slots=True)
class _TaskRun:
    admission_handle: Any
    node_id: str
    task_handle: Any
    admitted_task: Any
    custody_state: Any
    process_handle: Any
    process_identity: Any | None
    native_process_identity: str
    profile_id: str
    loaded_package_proof: Any | None
    source_closure: Any
    input_event: Any | None
    selected_execution: Any | None
    initial_input_receipt: Any | None
    authority_epoch: str
    service_generation_digest: str
    deadline: float
    required_model: bool
    required_action_ids: frozenset[str]
    requests: dict[str, str] = field(default_factory=dict)
    responses: dict[str, str] = field(default_factory=dict)
    tool_calls: dict[str, tuple[str, str, str]] = field(default_factory=dict)
    tool_results: dict[str, str] = field(default_factory=dict)
    response_receipts: dict[str, str] = field(default_factory=dict)
    observed_at: dict[str, float] = field(default_factory=dict)
    stop: threading.Event = field(default_factory=threading.Event)
    watcher: threading.Thread | None = None
    resolving: bool = False


@dataclass(frozen=True, slots=True)
class RootRunningTaskNativeBinding:
    """Root-private task selection join exposed only to source selection code."""

    admission_handle: Any
    node_id: str
    source: Any
    admitted_task: Any
    managed_task_handle: Any
    process_handle: Any
    profile_id: str
    process_generation: str
    native_package_id: str
    native_package_generation: str
    task_payload_sha256: str
    parent_closure_digest: str
    resource_generation: str
    service_generation_digest: str
    deadline_monotonic: float


class RootTaskNativeObservationRegistry:
    """Join actual input, native bridge, tool-result, custody and job evidence.

    Dependencies are concrete root registries, not worker callbacks. The
    registry binds the root coordinator's captured and delivered input before
    custody writes stdin, then watches root-owned native response records while
    that exact process remains live.
    """

    def __init__(self, source_observer_registry: Any, native_bridge_broker: Any,
                 admitted_task_registry: Any, process_custody_registry: Any,
                 *, monotonic=time.monotonic) -> None:
        from .native_bridge import NativeBridgeBroker
        from .source_observers import SourceObserverRegistry
        from .resource_jobs import ResourceJobAuthority
        from ..managed_process_custodian import ManagedProcessEffectHandler

        if (not isinstance(source_observer_registry, SourceObserverRegistry)
                or not isinstance(native_bridge_broker, NativeBridgeBroker)
                or not isinstance(admitted_task_registry, ResourceJobAuthority)
                or not isinstance(process_custody_registry, ManagedProcessEffectHandler)
                or not callable(monotonic)
                or getattr(source_observer_registry, "service", None) is None
                or getattr(native_bridge_broker, "provider_response_registry", None) is None
                or not callable(getattr(process_custody_registry, "_resolve_task_handle", None))
                or not callable(getattr(process_custody_registry, "resolve_task_terminal", None))
                or not callable(getattr(admitted_task_registry, "resolve_admitted_task_source", None))
                or not callable(getattr(admitted_task_registry, "resolve_admitted_task", None))):
            raise AuthorityDenied("resource.native_observer", "root task native observation dependencies are unavailable")
        input_observer = (getattr(source_observer_registry, "native_input_observer", None)
                          or getattr(source_observer_registry, "input_observer", None))
        if not callable(getattr(input_observer, "resolve_task_input_receipt", None)):
            raise AuthorityDenied("resource.native_observer", "root task input observer is unavailable")
        invocations = native_bridge_broker.provider_response_registry
        if not all(isinstance(getattr(invocations, name, None), dict)
                   for name in ("_responses", "_invocations")):
            raise AuthorityDenied("resource.native_observer", "root native response registry is unavailable")

        self.source_observers = source_observer_registry
        self.input_observer = input_observer
        self.native_bridge = native_bridge_broker
        self.admitted_tasks = admitted_task_registry
        self.process_custody = process_custody_registry
        self.monotonic = monotonic
        self._runs: dict[str, _TaskRun] = {}
        self._issued: dict[str, RootTaskNativeExecutionReceipt] = {}
        self._consumed_terminals: set[tuple[str, str]] = set()
        self._completed_tasks: dict[str, float] = {}
        self._lock = threading.RLock()
        self._closed = False

    def bind_running_task(self, admission_handle: Any, node_id: str, source: Any,
                          task_handle: Any) -> None:
        """Retain the exact root task/source join before native selection."""
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import (
            RootAdmittedTask as NeutralAdmittedTask,
            RootAdmittedTaskSource as NeutralTaskSource,
        )

        if type(task_handle) is not ManagedTaskHandle or type(source) is not NeutralTaskSource:
            raise AuthorityDenied("resource.native_binding", "root task binding types are invalid")
        admitted_task = self.admitted_tasks.resolve_admitted_task(admission_handle, node_id)
        if (type(admitted_task) is not NeutralAdmittedTask or node_id != admitted_task.node_id
                or not self._source_snapshot_current(admission_handle, admitted_task, source)):
            raise AuthorityDenied("resource.native_binding", "root task source snapshot is not current")
        now = self.monotonic()
        if now >= admitted_task.deadline_monotonic or not self._admitted_task_current(admitted_task):
            raise AuthorityDenied("resource.native_binding", "root task admission is stale")
        state = self.process_custody._resolve_task_handle(task_handle)
        process_handle = getattr(state, "handle", None)
        custody_admission = getattr(state, "admission", None)
        if (process_handle is None or getattr(process_handle, "process_id", None) != task_handle.process_id
                or getattr(state, "admission_handle_id", None) != admission_handle.handle_id
                or getattr(custody_admission, "task_payload_sha256", None) != admitted_task.task_payload_sha256
                or getattr(custody_admission, "parent_closure_digest", None) != admitted_task.parent_closure_digest
                or getattr(custody_admission, "native_package_generation", None) != admitted_task.native_package_generation
                or getattr(custody_admission, "process_generation", None) != admitted_task.process_generation):
            raise AuthorityDenied("resource.native_binding", "owned task does not match its admitted payload and generations")
        profile = getattr(process_handle, "profile", None)
        profile_id = getattr(profile, "profile_id", None)
        if (getattr(profile, "generation", None) != admitted_task.process_generation
                or profile_id != self._selected_task_recipe(admitted_task)[2]):
            raise AuthorityDenied("resource.native_binding", "task process profile differs from its selected backend")
        service = self.source_observers.service
        service_epoch = getattr(service, "authority_epoch", None)
        service_generation = getattr(service, "service_generation_digest", None)
        if not isinstance(service_epoch, str) or not service_epoch or not _digest(service_generation):
            raise AuthorityDenied("resource.native_epoch", "current root service epoch is unavailable")
        run = _TaskRun(
            admission_handle=admission_handle, node_id=node_id, task_handle=task_handle,
            admitted_task=admitted_task, custody_state=state, process_handle=process_handle,
            process_identity=None, native_process_identity="", profile_id=profile_id,
            loaded_package_proof=None, source_closure=source, input_event=None,
            selected_execution=None, initial_input_receipt=None,
            authority_epoch=service_epoch, service_generation_digest=service_generation,
            deadline=min(float(admitted_task.deadline_monotonic), float(source.expires_monotonic)),
            required_model=True, required_action_ids=frozenset(),
        )
        with self._lock:
            if self._closed or len(self._runs) >= _MAX_ACTIVE_TASKS:
                raise AuthorityDenied("resource.native_capacity", "root native observation capacity is unavailable")
            prior = self._runs.get(task_handle.handle_id)
            if prior is not None:
                raise AuthorityDenied("resource.native_replay", "task handle is already bound")
            if task_handle.handle_id in self._completed_tasks:
                raise AuthorityDenied("resource.native_replay", "task native observation is already complete")
            self._runs[task_handle.handle_id] = run

    def resolve_running_task_binding(self, admission_handle: Any, node_id: str,
                                     task_handle: Any) -> RootRunningTaskNativeBinding:
        """Expose a checked root-only binding to native selection registries."""
        with self._lock:
            run = self._runs.get(getattr(task_handle, "handle_id", ""))
        if (run is None or run.task_handle is not task_handle
                or run.admission_handle is not admission_handle or run.node_id != node_id
                or not self._admitted_task_current(run.admitted_task, run.profile_id)
                or getattr(self.source_observers.service, "authority_epoch", None) != run.authority_epoch
                or getattr(self.source_observers.service, "service_generation_digest", None)
                != run.service_generation_digest
                or self.monotonic() >= run.deadline):
            raise AuthorityDenied("resource.native_binding", "running task selection binding is stale")
        if not self._source_snapshot_current(
                admission_handle, run.admitted_task, run.source_closure,
                require_controller=False):
            raise AuthorityDenied("resource.native_binding", "running task source closure is stale")
        state = self.process_custody._resolve_task_handle(task_handle)
        if getattr(state, "handle", None) is not run.process_handle:
            raise AuthorityDenied("resource.native_binding", "running task process identity changed")
        return RootRunningTaskNativeBinding(
            admission_handle=run.admission_handle, node_id=run.node_id, source=run.source_closure,
            admitted_task=run.admitted_task, managed_task_handle=run.task_handle,
            process_handle=run.process_handle, profile_id=run.profile_id,
            process_generation=run.admitted_task.process_generation,
            native_package_id=run.admitted_task.native_package_id,
            native_package_generation=run.admitted_task.native_package_generation,
            task_payload_sha256=run.admitted_task.task_payload_sha256,
            parent_closure_digest=run.admitted_task.parent_closure_digest,
            resource_generation=run.admitted_task.resource_generation,
            service_generation_digest=run.service_generation_digest,
            deadline_monotonic=run.deadline,
        )

    def bind_task_input(self, *, task_handle: Any, admission: Any, source: Any,
                        selected_execution: Any, initial_input: Any) -> None:
        """Attach the actual pre-stdin input/delivery receipt to a retained task."""
        from ..managed_process_custodian import ManagedTaskHandle
        from ..registry.resource_jobs import RootTaskInitialInputReceipt

        if type(task_handle) is not ManagedTaskHandle or type(initial_input) is not RootTaskInitialInputReceipt:
            raise AuthorityDenied("resource.native_input", "initial task input receipt types are invalid")
        with self._lock:
            run = self._runs.get(task_handle.handle_id)
            if (run is None or run.task_handle is not task_handle or run.admission_handle is not admission
                    or run.source_closure is not source or run.selected_execution is not None):
                raise AuthorityDenied("resource.native_replay", "initial task input is unbound or already recorded")
        now = self.monotonic()
        task = run.admitted_task
        process = run.process_handle
        if (not self._source_snapshot_current(admission, task, source, require_controller=False)
                or not self._admitted_task_current(task, run.profile_id)
                or self.process_custody._resolve_task_handle(task_handle).handle is not process
                or getattr(selected_execution, "kind", None) != "resource-task"
                or getattr(selected_execution, "execution_handle", None) is not admission
                or getattr(selected_execution, "process_handle", None) is not process
                or getattr(selected_execution, "profile_id", None) != run.profile_id
                or getattr(selected_execution, "generation", None) != task.process_generation
                or getattr(selected_execution, "native_package_id", None) != task.native_package_id
                or getattr(selected_execution, "native_package_generation", None) != task.native_package_generation
                or getattr(selected_execution, "service_generation_digest", None) != run.service_generation_digest
                or getattr(selected_execution, "expires_monotonic", 0) <= now):
            raise AuthorityDenied("resource.native_input", "selected task process or source changed before input")
        input_values = self._validate_initial_input_receipt(run, selected_execution, initial_input, now)
        if input_values is None:
            raise AuthorityDenied("resource.native_input", "initial input receipt lacks actual root event and delivery evidence")
        input_event, identity, native_identity, package_proof = input_values
        with self._lock:
            if self._runs.get(task_handle.handle_id) is not run or run.selected_execution is not None:
                raise AuthorityDenied("resource.native_replay", "initial input binding raced or replayed")
            run.selected_execution = selected_execution
            run.initial_input_receipt = initial_input
            run.input_event = input_event
            run.process_identity = identity
            run.native_process_identity = native_identity
            run.loaded_package_proof = package_proof
        watcher = threading.Thread(target=self._watch, args=(run,), daemon=True,
                                   name="hermes-task-native-observer")
        run.watcher = watcher
        watcher.start()

    def resolve_task_execution(self, task_handle: Any,
                               terminal_receipt_handle: str) -> RootTaskNativeExecutionReceipt:
        """Issue the one-use companion only for stored live observations and the exact terminal."""
        from ..managed_process_custodian import ManagedTaskHandle

        if (type(task_handle) is not ManagedTaskHandle or not _opaque(terminal_receipt_handle)):
            raise AuthorityDenied("resource.native_terminal", "task native terminal reference is malformed")
        with self._lock:
            run = self._runs.get(task_handle.handle_id)
            if (run is None or run.task_handle is not task_handle or run.resolving
                    or run.input_event is None or run.initial_input_receipt is None
                    or run.loaded_package_proof is None or run.process_identity is None):
                raise AuthorityDenied("resource.native_replay", "task native observations are unknown or consumed")
            run.resolving = True
            run.stop.set()
        if run.watcher is not None and run.watcher is not threading.current_thread():
            run.watcher.join(timeout=1.0)
            if run.watcher.is_alive():
                self._discard_run(task_handle.handle_id, run)
                raise AuthorityDenied("resource.native_timeout", "root native observer did not stop within its bound")
        try:
            self._capture(run)
            terminal = self.process_custody.resolve_task_terminal(
                task_handle.handle_id, terminal_receipt_handle)
            now = self.monotonic()
            self._validate_terminal(run, terminal, terminal_receipt_handle, now)
        except Exception:
            self._discard_run(task_handle.handle_id, run)
            raise
        requests = tuple(sorted(run.requests))
        results = tuple(sorted(run.responses))
        tools = tuple(sorted(run.tool_results))
        if run.required_model and (not requests or not results):
            self._discard_run(task_handle.handle_id, run)
            raise AuthorityDenied("resource.native_incomplete", "task has no observed completed native model request and result")
        if run.required_action_ids and not run.required_action_ids.issubset(set(run.tool_results.values())):
            self._discard_run(task_handle.handle_id, run)
            raise AuthorityDenied("resource.native_incomplete", "selected workflow has no observed required tool result")
        if run.tool_calls and len(tools) < len(run.tool_calls):
            self._discard_run(task_handle.handle_id, run)
            raise AuthorityDenied("resource.native_incomplete", "a requested native tool call has no completed result receipt")
        if (not requests and results) or (requests and not results) or len(requests) != len(results):
            self._discard_run(task_handle.handle_id, run)
            raise AuthorityDenied("resource.native_incomplete", "native request and result event sets do not form completed pairs")

        try:
            receipt = RootTaskNativeExecutionReceipt(
                schema=1, native_execution_receipt_handle=secrets.token_urlsafe(32),
                task_handle=task_handle.handle_id, process_id=task_handle.process_id,
                process_generation=run.admitted_task.process_generation,
                native_package_generation=run.admitted_task.native_package_generation,
                loader_ready_event_id=run.loaded_package_proof.loader_ready_event_id,
                initial_input_event_id=run.input_event.input_event_id,
                native_request_event_ids=requests, native_result_event_ids=results,
                required_tool_result_event_ids=tools,
                parent_closure_digest=run.admitted_task.parent_closure_digest,
                task_payload_sha256=run.admitted_task.task_payload_sha256,
                terminal_receipt_handle=terminal_receipt_handle,
                observed_monotonic=now,
            )
        except Exception:
            self._discard_run(task_handle.handle_id, run)
            raise
        with self._lock:
            self._runs.pop(task_handle.handle_id, None)
            key = (task_handle.handle_id, terminal_receipt_handle)
            if (key in self._consumed_terminals
                    or task_handle.handle_id in self._completed_tasks
                    or len(self._issued) >= 4096):
                raise AuthorityDenied("resource.native_replay", "terminal already has a native receipt")
            self._consumed_terminals.add(key)
            self._completed_tasks[task_handle.handle_id] = run.deadline
            self._issued[receipt.native_execution_receipt_handle] = receipt
        return receipt

    def verify_receipt(self, receipt: RootTaskNativeExecutionReceipt) -> bool:
        """Check exact in-memory issuance; a copied or reconstructed DTO is not accepted."""
        if type(receipt) is not RootTaskNativeExecutionReceipt:
            return False
        with self._lock:
            if self._issued.get(receipt.native_execution_receipt_handle) is not receipt:
                return False
            self._issued.pop(receipt.native_execution_receipt_handle, None)
            return True

    def close(self) -> None:
        with self._lock:
            self._closed = True
            runs = tuple(self._runs.values())
            self._runs.clear()
        for run in runs:
            run.stop.set()
            if run.watcher is not None and run.watcher is not threading.current_thread():
                run.watcher.join(timeout=1.0)

    def _watch(self, run: _TaskRun) -> None:
        while not run.stop.wait(_POLL_SECONDS):
            try:
                self._capture(run)
            except Exception:
                # An observer failure is retained as absence and makes final
                # resolution fail closed. It never becomes success metadata.
                return

    def _capture(self, run: _TaskRun) -> None:
        now = self.monotonic()
        if (now >= run.deadline or not self._admitted_task_current(run.admitted_task, run.profile_id)
                or getattr(self.source_observers.service, "authority_epoch", None) != run.authority_epoch
                or getattr(self.source_observers.service, "service_generation_digest", None)
                != run.service_generation_digest):
            return
        invocations = self.native_bridge.provider_response_registry
        with getattr(invocations, "_lock", threading.RLock()):
            responses = dict(getattr(invocations, "_responses", {}))
            deliveries = dict(getattr(invocations, "_deliveries", {}))
            native_calls = dict(getattr(invocations, "_invocations", {}))
        response_records = {id(item): item for item in (*responses.values(), *deliveries.values())}
        for item in response_records.values():
            if (not self._matches_task(run, item)
                    or getattr(item, "metadata_taken", False) is not True):
                continue
            request_id = getattr(item, "native_request_handle", None)
            response_handle = getattr(item, "handle", None)
            receipt_handles = getattr(item, "receipt_handles", ())
            if (not _opaque(request_id) or not _opaque(response_handle)
                    or not isinstance(receipt_handles, tuple)
                    or not self._has_full_task_lineage(run, receipt_handles)):
                continue
            source_handle = receipt_handles[-1]
            capsule = self._capsule_for(source_handle)
            receipt = self._receipt_for(source_handle)
            event_id = getattr(capsule, "event_record_id", None)
            if (receipt is None or getattr(capsule, "source_kind", None) != "provider-result"
                    or not _opaque(event_id)):
                continue
            previous_result = run.requests.get(request_id)
            if previous_result is not None and previous_result != event_id:
                continue
            run.requests[request_id] = event_id
            self._event_time(run, request_id, now)
            run.responses[event_id] = event_id
            run.response_receipts[response_handle] = receipt.receipt_id
            self._event_time(run, event_id, now)
            calls = getattr(item, "calls", {})
            if isinstance(calls, Mapping):
                for call_handle, row in calls.items():
                    action_id = row[3] if isinstance(row, tuple) and len(row) == 5 else None
                    if _opaque(call_handle) and isinstance(action_id, str) and action_id:
                        run.tool_calls[call_handle] = (response_handle, action_id, receipt.receipt_id)
        for invocation in native_calls.values():
            if not self._matches_task(run, invocation):
                continue
            call_handle = getattr(invocation, "observed_call_handle", None)
            action_id = getattr(invocation, "action_id", None)
            response_handle = getattr(invocation, "response_handle", None)
            if (_opaque(call_handle) and _opaque(response_handle) and isinstance(action_id, str)
                    and response_handle in run.response_receipts):
                run.tool_calls[call_handle] = (
                    response_handle, action_id, run.response_receipts[response_handle])

        self._capture_tool_results(run, now)

    def _capture_tool_results(self, run: _TaskRun, now: float) -> None:
        expected_actions = set(run.required_action_ids)
        expected_actions.update(action for _response, action, _receipt in run.tool_calls.values())
        if not expected_actions:
            return
        payloads = getattr(self.source_observers, "_payload_capsules", {})
        if not isinstance(payloads, Mapping):
            return
        for handle, item in tuple(payloads.items()):
            try:
                receipt, capsule, _payload, epoch = item
            except (TypeError, ValueError):
                continue
            action_id = getattr(capsule, "source_action_id", None)
            event_id = getattr(capsule, "event_record_id", None)
            if (getattr(capsule, "source_kind", None) not in {"tool-result", "provider-result"}
                    or action_id not in expected_actions or not _opaque(event_id)
                    or epoch != run.authority_epoch or not self._receipt_live(receipt, now)
                    or getattr(capsule, "source_kind", None) != "tool-result"
                    or not self._receipt_descends_from_task(run, receipt)
                    or not self._receipt_descends_from_provider(run, action_id, receipt)):
                continue
            run.tool_results[event_id] = action_id
            self._event_time(run, event_id, now)

    def _matches_task(self, run: _TaskRun, event: Any) -> bool:
        return (getattr(event, "producer_identity", None) == run.process_identity
                and getattr(event, "producer_pid", None) == getattr(run.process_handle, "pid", None)
                and getattr(event, "profile_id", None) == run.profile_id
                and getattr(event, "generation", None) == run.admitted_task.process_generation
                and getattr(event, "package_id", None) == run.admitted_task.native_package_id
                and getattr(event, "loaded_package_proof", None) == run.loaded_package_proof
                and getattr(event, "expires_monotonic", 0) > self.monotonic())

    def _has_full_task_lineage(self, run: _TaskRun, handles: tuple[str, ...]) -> bool:
        if not handles or len(handles) > 128 or len(set(handles)) != len(handles):
            return False
        receipts = self._receipt_map()
        try:
            selected = [receipts[handle] for handle in handles]
            closure = self._receipt_closure(selected, receipts)
        except (KeyError, AuthorityDenied):
            return False
        source_receipts = tuple(self._receipt_for(handle)
                                for handle in run.source_closure.verified_source_receipt_handles)
        if (not source_receipts or any(receipt is None for receipt in source_receipts)
                or len({receipt.receipt_id for receipt in source_receipts}) != len(source_receipts)):
            return False
        expected = {receipt.receipt_id for receipt in source_receipts}
        input_receipt = self._receipt_for(run.input_event.source_receipt_handle)
        if input_receipt is None:
            return False
        closure_ids = {item.receipt_id for item in closure}
        root = selected[-1]
        return (expected.issubset(closure_ids)
                and input_receipt.receipt_id in closure_ids
                and root.profile_id == run.profile_id
                and root.process_generation == run.admitted_task.process_generation
                and root.native_process_identity == run.native_process_identity
                and all(item.monotonic_expires_at > self.monotonic() for item in closure))

    def _receipt_descends_from_provider(self, run: _TaskRun, action_id: str, receipt: Any) -> bool:
        try:
            closure = self._receipt_closure([receipt], self._receipt_map())
        except (KeyError, AuthorityDenied):
            return False
        ancestors = {item.receipt_id for item in closure}
        return any(parent_action == action_id and parent_id in ancestors
                   for _response, parent_action, parent_id in run.tool_calls.values())

    def _receipt_descends_from_task(self, run: _TaskRun, receipt: Any) -> bool:
        receipts = self._receipt_map()
        try:
            closure = self._receipt_closure([receipt], receipts)
        except (KeyError, AuthorityDenied):
            return False
        input_receipt = self._receipt_for(run.input_event.source_receipt_handle)
        root = closure[0] if closure else None
        return bool(input_receipt and root
                    and input_receipt.receipt_id in {item.receipt_id for item in closure}
                    and root.profile_id == run.profile_id
                    and root.process_generation == run.admitted_task.process_generation
                    and root.native_process_identity == run.native_process_identity
                    and all(item.monotonic_expires_at > self.monotonic() for item in closure))

    def _receipt_closure(self, roots: list[Any], by_handle: Mapping[str, Any]) -> tuple[Any, ...]:
        by_id = {item.receipt_id: item for item in by_handle.values()}
        selected: dict[str, Any] = {}
        todo = list(roots)
        while todo:
            receipt = todo.pop()
            if receipt.receipt_id in selected:
                continue
            selected[receipt.receipt_id] = receipt
            if len(selected) > 128:
                raise AuthorityDenied("resource.native_lineage", "native source closure exceeds its bound")
            for parent_id in receipt.parent_receipt_ids:
                parent = by_id.get(parent_id)
                if parent is None:
                    raise KeyError(parent_id)
                todo.append(parent)
        return tuple(selected.values())

    def _receipt_map(self) -> Mapping[str, Any]:
        handles = getattr(getattr(self.source_observers, "service", None), "_source_receipt_handles", None)
        return handles if isinstance(handles, Mapping) else {}

    def _validate_initial_input_receipt(self, run: _TaskRun, selected: Any,
                                        receipt: Any, now: float) -> tuple[Any, Any, str, Any] | None:
        task = run.admitted_task
        process = run.process_handle
        pid = getattr(process, "pid", None)
        pidfd = getattr(process, "child_pidfd", None)
        profile = getattr(process, "profile", None)
        uid = getattr(profile, "owner_uid", None)
        identity_resolver = getattr(self.process_custody, "resolve_live_peer", None)
        if (getattr(receipt, "schema", None) != 1
                or not _opaque(getattr(receipt, "receipt_handle", None))
                or not _opaque(getattr(receipt, "producer_context_delivery_handle", None))
                or getattr(receipt, "task_handle", None) != run.task_handle.handle_id
                or getattr(receipt, "admission_id", None) != task.admission_id
                or getattr(receipt, "node_id", None) != task.node_id
                or getattr(receipt, "process_id", None) != run.task_handle.process_id
                or getattr(receipt, "process_generation", None) != task.process_generation
                or getattr(receipt, "selected_execution_handle", None)
                != getattr(selected, "selection_handle", None)
                or getattr(receipt, "stdin_sha256", None) != task.stdin_sha256
                or getattr(receipt, "stdin_size_bytes", None) != task.stdin_size_bytes
                or getattr(receipt, "parent_closure_digest", None) != task.parent_closure_digest
                or getattr(receipt, "service_generation_digest", None) != run.service_generation_digest
                or getattr(receipt, "resource_generation", None) != task.resource_generation
                or getattr(receipt, "issued_monotonic", now + 1) > now
                or getattr(receipt, "expires_monotonic", 0) <= now
                or getattr(receipt, "expires_monotonic", 0) > run.deadline
                or not _digest(getattr(receipt, "stdin_sha256", None))
                or type(pid) is not int or pid <= 0 or type(pidfd) is not int or pidfd < 0
                or type(uid) is not int or uid <= 0 or not callable(identity_resolver)):
            return None
        identity = identity_resolver(pid, pidfd, profile_id=run.profile_id,
                                     generation=task.process_generation)
        if identity is None:
            return None
        native_identity = self.source_observers.service._native_process_identity(pid, uid)
        package_proof = self.process_custody.resolve_loaded_native_package(
            run.task_handle.process_id, task.process_generation)
        ready_event_id = getattr(process, "native_loader_ready_event_id", None)
        mount = getattr(package_proof, "mount", None)
        if (package_proof is None
                or getattr(package_proof, "process_id", None) != run.task_handle.process_id
                or getattr(package_proof, "profile_id", None) != run.profile_id
                or getattr(package_proof, "generation", None) != task.process_generation
                or getattr(mount, "package_id", None) != task.native_package_id
                or getattr(package_proof, "loader_ready_event_id", None) != ready_event_id
                or getattr(receipt, "native_loader_ready_event_id", None) != ready_event_id):
            return None

        input_receipt_resolver = getattr(self.input_observer, "resolve_task_input_receipt", None)
        if not callable(input_receipt_resolver):
            return None
        try:
            if input_receipt_resolver(receipt.receipt_handle) is not receipt:
                return None
        except Exception:
            return None
        events = getattr(self.input_observer, "_events", None)
        if not isinstance(events, Mapping):
            return None
        matches = [event for event in events.values()
                   if self._matches_initial_input_event(run, receipt, event)]
        if len(matches) != 1:
            return None
        event = matches[0]
        if (receipt.source_receipt_handle != receipt.producer_context_delivery_handle
                or not _opaque(receipt.source_receipt_handle)):
            return None
        input_receipt = self._receipt_for(receipt.source_receipt_handle)
        delivered_resolver = getattr(self.source_observers, "resolve_delivered_source_receipt", None)
        if input_receipt is None or not callable(delivered_resolver):
            return None
        try:
            delivered = delivered_resolver(
                receipt.producer_context_delivery_handle, peer_uid=uid,
                peer_pid=pid, peer_pidfd=pidfd)
        except Exception:
            return None
        if (delivered != receipt.producer_context_delivery_handle
                or not self._receipt_live(input_receipt, now)
                or not self._receipt_descends_from_task(run, input_receipt)):
            return None
        selection_registry = getattr(self.source_observers, "native_execution_selections", None)
        verifier = getattr(selection_registry, "resolve_current_execution", None)
        if callable(verifier):
            try:
                if verifier(selected) is not selected:
                    return None
            except Exception:
                return None
        else:
            return None
        return event, identity, native_identity, package_proof

    @staticmethod
    def _matches_initial_input_event(run: _TaskRun, receipt: Any, event: Any) -> bool:
        task = run.admitted_task
        return (getattr(event, "input_origin_kind", None) == "root-admitted-task"
                and getattr(event, "source_receipt_handle", None) == receipt.source_receipt_handle
                and getattr(event, "payload_sha256", None) == task.stdin_sha256
                and getattr(event, "payload_size_bytes", None) == task.stdin_size_bytes
                and getattr(event, "producer_profile_id", None) == run.profile_id
                and getattr(event, "producer_generation", None) == task.process_generation
                and getattr(event, "parent_closure_digest", None) == task.parent_closure_digest
                and getattr(event, "native_loader_ready_event_id", None)
                == receipt.native_loader_ready_event_id
                and getattr(event, "expires_monotonic", 0) >= receipt.expires_monotonic)

    def _source_snapshot_current(self, admission_handle: Any, task: Any, source: Any,
                                 *, require_controller: bool = True) -> bool:
        """Authenticate the runner's source DTO against root-retained job state."""
        rows = getattr(self.admitted_tasks, "_running_task_handles", None)
        if not isinstance(rows, Mapping):
            return False
        registered = rows.get(getattr(admission_handle, "handle_id", None))
        if not isinstance(registered, tuple) or len(registered) != 4:
            return False
        retained_handle, child, enrollment, event = registered
        backend = getattr(enrollment, "backends", {}).get(task.backend_enrollment_id)
        binding = getattr(backend, "execution_binding", None)
        contexts = getattr(self.admitted_tasks, "_source_context_handles", {})
        context_handle = contexts.get(admission_handle.handle_id) if isinstance(contexts, Mapping) else None
        controllers = getattr(self.admitted_tasks, "_task_controller_bindings", {})
        controller = controllers.get(admission_handle.handle_id) if isinstance(controllers, Mapping) else None
        if (retained_handle is not admission_handle or child.admission_id != task.admission_id
                or child.node_id != task.node_id or event.enrollment is not enrollment
                or not isinstance(binding, Mapping) or context_handle != source.source_context_handle
                or (require_controller and (not isinstance(controller, tuple) or len(controller) != 2
                                            or controller[0] != source.controller_binding_handle))
                or getattr(enrollment, "generation", None) != task.resource_generation
                or getattr(backend, "profile_id", None) != source.profile_id
                or getattr(backend, "profile_id", None) != getattr(event.parent_context, "profile_id", None)
                or getattr(event, "lineage_hash", None) != source.lineage_hash
                or getattr(event, "sensitivity", None) != source.sensitivity
                or getattr(event.parent_context, "namespace_id", None) != source.namespace_id
                or source.parent_closure_digest != task.parent_closure_digest
                or source.principal_id != getattr(enrollment, "principal_id", None)
                or source.expires_monotonic <= self.monotonic()
                or source.expires_monotonic > admission_handle.expires_monotonic
                or self.admitted_tasks.task_handle_cancelled(admission_handle, task.node_id)
                or self.admitted_tasks._resource_generation(enrollment) != task.resource_generation):
            return False
        try:
            from ..registry.resource_jobs import _admitted_source_closure_digest, _canonical
            expected_closure = _admitted_source_closure_digest(
                event, child, enrollment.node_map[task.node_id], backend)
            receipt_map = self._receipt_map()
            expected_handles: list[str] = []
            expected_wires: list[bytes] = []
            for receipt in event.source_receipts:
                handles = [handle for handle, candidate in receipt_map.items()
                           if candidate is receipt or getattr(candidate, "receipt_id", None)
                           == receipt.receipt_id]
                if len(handles) != 1:
                    return False
                expected_handles.append(str(handles[0]))
                expected_wires.append(_canonical(receipt.to_wire()))
        except Exception:
            return False
        recipient_ceiling = set(event.source_receipts[0].recipient_ceiling) if event.source_receipts else set()
        for receipt in event.source_receipts[1:]:
            recipient_ceiling.intersection_update(receipt.recipient_ceiling)
        expiry = min(admission_handle.expires_monotonic,
                     *(receipt.monotonic_expires_at for receipt in event.source_receipts))
        return (expected_closure == task.parent_closure_digest
                and tuple(expected_handles) == source.verified_source_receipt_handles
                and tuple(expected_wires) == source.signed_receipt_wires
                and tuple(sorted(recipient_ceiling)) == source.recipient_ceiling
                and expiry == source.expires_monotonic)

    def _receipt_for(self, handle: Any) -> Any | None:
        if not isinstance(handle, str):
            return None
        return self._receipt_map().get(handle)

    def _capsule_for(self, handle: str) -> Any | None:
        item = getattr(self.source_observers, "_payload_capsules", {}).get(handle)
        return item[1] if isinstance(item, tuple) and len(item) == 4 else None

    @staticmethod
    def _receipt_live(receipt: Any, now: float) -> bool:
        return (getattr(receipt, "monotonic_expires_at", 0) > now
                and isinstance(getattr(receipt, "receipt_id", None), str))

    def _admission_handle(self, handle_id: str, node_id: str) -> Any:
        values = getattr(self.admitted_tasks, "_running_task_handles", None)
        if not isinstance(values, Mapping):
            raise AuthorityDenied("resource.native_admission", "root admitted task handle registry is unavailable")
        matches = [row[0] for row in values.values()
                   if isinstance(row, tuple) and len(row) == 4
                   and getattr(row[0], "handle_id", None) == handle_id
                   and getattr(row[0], "node_id", None) == node_id]
        if len(matches) != 1:
            raise AuthorityDenied("resource.native_admission", "root task admission handle is stale or ambiguous")
        return matches[0]

    def _selected_task_recipe(self, task: Any) -> tuple[bool, frozenset[str], str]:
        enrollments = getattr(self.admitted_tasks, "enrollments", None)
        if not isinstance(enrollments, Mapping):
            raise AuthorityDenied("resource.native_workflow", "selected task enrollment registry is unavailable")
        matches = [enrollment for enrollment in enrollments.values()
                   if getattr(enrollment, "generation", None) == task.resource_generation
                   and isinstance(getattr(enrollment, "backends", None), Mapping)
                   and task.backend_enrollment_id in enrollment.backends]
        if len(matches) != 1:
            raise AuthorityDenied("resource.native_workflow", "selected resource generation is stale or ambiguous")
        enrollment = matches[0]
        recipes = getattr(enrollment, "body_recipes", None)
        recipe = recipes.get(task.task_body_recipe_id) if isinstance(recipes, Mapping) else None
        backend = enrollment.backends[task.backend_enrollment_id]
        if recipe is None or getattr(recipe, "schema_id", None) != task.task_request_schema_id:
            raise AuthorityDenied("resource.native_workflow", "selected protected task recipe is unavailable")
        if (getattr(backend, "profile_id", None) != enrollment.profile_id
                or getattr(backend, "native_package_id", None) != task.native_package_id
                or getattr(backend, "native_package_generation", None) != task.native_package_generation
                or getattr(backend, "generation", None) != task.resource_generation):
            raise AuthorityDenied("resource.native_workflow", "selected protected backend does not match the admitted task")
        # Model use is mandatory unless the enrolled recipe is a separately
        # pinned, safe local fixture with an explicit no-model mode.
        # The current protected recipe schema has no no-model escape hatch or
        # task-specific required-tool list. Treat every selected Hermes task
        # as model-backed and bind any tool results from observed native calls.
        return True, frozenset(), getattr(enrollment, "profile_id", "")

    @staticmethod
    def _admitted_stdin(task: Any) -> bytes:
        payload = getattr(task, "task_payload_bytes", None)
        if payload is None:
            payload = getattr(task, "task_payload", None)
        try:
            value = json.loads(payload.decode("utf-8"))
            stdin = value["prompt"].encode("utf-8")
        except (AttributeError, KeyError, UnicodeError, json.JSONDecodeError, TypeError):
            raise AuthorityDenied("resource.native_input", "admitted prompt bytes are unavailable") from None
        if (not isinstance(payload, bytes) or hashlib.sha256(payload).hexdigest()
                != task.task_payload_sha256
                or hashlib.sha256(stdin).hexdigest() != task.stdin_sha256
                or len(stdin) != task.stdin_size_bytes):
            raise AuthorityDenied("resource.native_input", "admitted prompt digest or size changed")
        return stdin

    def _validate_terminal(self, run: _TaskRun, terminal: Any,
                           terminal_handle: str, now: float) -> None:
        task = run.admitted_task
        current_service = self.source_observers.service
        if (getattr(terminal, "terminal_receipt_handle", None) != terminal_handle
                or getattr(terminal, "task_handle", None) != run.task_handle.handle_id
                or getattr(terminal, "admission_id", None) != task.admission_id
                or getattr(terminal, "admission_handle_id", None) != getattr(
                    run.custody_state, "admission_handle_id", None)
                or getattr(terminal, "backend_enrollment_id", None) != task.backend_enrollment_id
                or getattr(terminal, "operation_id", None) != task.operation_id
                or getattr(terminal, "task_body_recipe_id", None) != task.task_body_recipe_id
                or getattr(terminal, "task_request_schema_id", None) != task.task_request_schema_id
                or getattr(terminal, "resource_generation", None) != task.resource_generation
                or getattr(terminal, "profile_id", None) != run.profile_id
                or getattr(terminal, "process_id", None) != run.task_handle.process_id
                or getattr(terminal, "process_generation", None) != task.process_generation
                or getattr(terminal, "parent_closure_digest", None) != task.parent_closure_digest
                or getattr(terminal, "state", None) != "completed"
                or getattr(terminal, "exit_code", None) != 0
                or any(getattr(terminal, name, True) for name in ("timed_out", "cancelled"))
                or any(not getattr(terminal, name, False) for name in (
                    "cleanup_verified", "cgroup_empty", "main_pidfd_gone",
                    "descendants_gone", "launcher_reaped", "output_complete"))
                or terminal.native_loader_ready_event_id != run.loaded_package_proof.loader_ready_event_id
                or self.process_custody.resolve_task_terminal(
                    run.task_handle.handle_id, terminal_handle) is not terminal
                or not self._admitted_task_current(task, run.profile_id)
                or not self._source_snapshot_current(
                    run.admission_handle, task, run.source_closure,
                    require_controller=False)
                or current_service.authority_epoch != run.authority_epoch
                or current_service.service_generation_digest != run.service_generation_digest
                or now >= run.deadline or now >= run.input_event.expires_monotonic
                or now >= run.loaded_package_proof.expires_monotonic):
            raise AuthorityDenied("resource.native_terminal", "task terminal or current authority does not match the retained native execution")
        if getattr(terminal, "native_execution_receipt_handle", None) not in (None, ""):
            raise AuthorityDenied("resource.native_terminal", "terminal already carries an unrelated native execution receipt")

    @staticmethod
    def _event_time(run: _TaskRun, event_id: str, now: float) -> None:
        if event_id not in run.observed_at:
            run.observed_at[event_id] = now

    def _discard_run(self, handle_id: str, run: _TaskRun) -> None:
        run.stop.set()
        with self._lock:
            if self._runs.get(handle_id) is run:
                self._runs.pop(handle_id, None)

    def _admitted_task_current(self, task: Any, expected_profile_id: str | None = None) -> bool:
        """Re-check the exact live job attempt and resource generation."""
        rows = getattr(self.admitted_tasks, "_running_task_handles", None)
        if not isinstance(rows, Mapping):
            return False
        for admission_handle, child, enrollment, _event in rows.values():
            if (getattr(admission_handle, "task_payload_sha256", None) != task.task_payload_sha256
                    or getattr(admission_handle, "parent_closure_digest", None) != task.parent_closure_digest
                    or getattr(admission_handle, "task_body_recipe_id", None) != task.task_body_recipe_id
                    or getattr(child, "admission_id", None) != task.admission_id
                    or getattr(child, "node_id", None) != task.node_id
                    or getattr(admission_handle, "backend_enrollment_id", None) != task.backend_enrollment_id
                    or getattr(enrollment, "generation", None) != task.resource_generation
                    or (expected_profile_id is not None
                        and getattr(enrollment, "profile_id", None) != expected_profile_id)):
                continue
            try:
                if (self.admitted_tasks.task_handle_cancelled(admission_handle, task.node_id)
                        or self.admitted_tasks._resource_generation(enrollment) != task.resource_generation):
                    return False
                return True
            except Exception:
                return False
        return False


__all__ = ["RootTaskNativeExecutionReceipt", "RootTaskNativeObservationRegistry"]
