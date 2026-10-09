from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from hermes_installer.authority.task_native_observation import (
    RootTaskNativeObservationRegistry,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.registry.resource_jobs import (
    ResourceJobDenied, RootTaskInitialInputReceipt, RootTaskNativeExecutionReceipt,
)


def _receipt(receipt_id: str, *, parents: tuple[str, ...] = (), profile="profile-a",
             generation="profile-generation-a", native="native-a", expires=100.0):
    return SimpleNamespace(
        receipt_id=receipt_id, parent_receipt_ids=parents, profile_id=profile,
        process_generation=generation, native_process_identity=native,
        monotonic_expires_at=expires,
    )


def _registry(receipts, payloads=None):
    service = SimpleNamespace(_source_receipt_handles=receipts)
    source = SimpleNamespace(service=service, _payload_capsules=payloads or {})
    registry = RootTaskNativeObservationRegistry.__new__(RootTaskNativeObservationRegistry)
    registry.source_observers = source
    registry.monotonic = lambda: 10.0
    registry._issued = {}
    registry._lock = threading.RLock()
    return registry


def _dto(**overrides):
    values = dict(
        schema=1, native_execution_receipt_handle="r" * 40, task_handle="t" * 40,
        process_id="p" * 32, process_generation="profile-generation-a",
        native_package_generation="package-generation-a", loader_ready_event_id="l" * 40,
        initial_input_event_id="i" * 40, native_request_event_ids=("q" * 40,),
        native_result_event_ids=("z" * 40,), required_tool_result_event_ids=(),
        parent_closure_digest="a" * 64, task_payload_sha256="b" * 64,
        terminal_receipt_handle="e" * 40, observed_monotonic=10.0,
    )
    values.update(overrides)
    return RootTaskNativeExecutionReceipt(**values)


def test_receipt_is_frozen_and_rejects_duplicate_observation_ids():
    value = _dto()
    with pytest.raises((AttributeError, TypeError)):
        value.task_handle = "x" * 40
    with pytest.raises(ResourceJobDenied):
        _dto(native_result_event_ids=("z" * 40, "z" * 40))
    with pytest.raises(ResourceJobDenied):
        _dto(parent_closure_digest="not-a-digest")


def test_initial_input_receipt_accepts_enrolled_identity_lengths_but_requires_safe_ids():
    values = dict(
        schema=1, receipt_handle="r" * 40, task_handle="t" * 40,
        admission_id="admission-1", node_id="node-a", process_id="process-1",
        process_generation="profile-generation-a", selected_execution_handle="s" * 40,
        source_receipt_handle="c" * 40, producer_context_delivery_handle="c" * 40,
        native_loader_ready_event_id="l" * 40, stdin_sha256="a" * 64,
        stdin_size_bytes=3, parent_closure_digest="b" * 64,
        service_generation_digest="c" * 64, resource_generation="resource-gen-1",
        issued_monotonic=1.0, expires_monotonic=2.0,
    )
    receipt = RootTaskInitialInputReceipt(**values)
    assert receipt.node_id == "node-a"
    with pytest.raises(ResourceJobDenied):
        RootTaskInitialInputReceipt(**{**values, "node_id": "node\x00a"})


def test_issued_receipt_is_identity_bound_and_one_use():
    registry = _registry({})
    value = _dto()
    registry._issued[value.native_execution_receipt_handle] = value
    clone = _dto()
    assert registry.verify_receipt(clone) is False
    assert registry.verify_receipt(value) is True
    assert registry.verify_receipt(value) is False


def test_model_receipt_requires_complete_task_source_ancestry():
    source = _receipt("source")
    task_input = _receipt("task-input", parents=("source",))
    result = _receipt("provider-result", parents=("task-input",))
    registry = _registry({"source-handle": source, "input-handle": task_input,
                          "result-handle": result})
    run = SimpleNamespace(
        source_closure=SimpleNamespace(verified_source_receipt_handles=("source-handle",)),
        input_event=SimpleNamespace(source_receipt_handle="input-handle"),
        profile_id="profile-a",
        admitted_task=SimpleNamespace(profile_id="profile-a", process_generation="profile-generation-a"),
        native_process_identity="native-a",
    )
    assert registry._has_full_task_lineage(run, ("input-handle", "result-handle"))
    orphan = _receipt("orphan-result")
    registry.source_observers.service._source_receipt_handles["orphan-handle"] = orphan
    assert not registry._has_full_task_lineage(run, ("orphan-handle",))

    unrelated = _receipt("wrong-process", parents=("task-input",), native="native-b")
    registry.source_observers.service._source_receipt_handles["wrong-handle"] = unrelated
    assert not registry._has_full_task_lineage(run, ("input-handle", "wrong-handle"))


def test_capture_pairs_root_retained_native_request_with_completed_result():
    source = _receipt("source")
    task_input = _receipt("task-input", parents=("source",))
    result = _receipt("provider-result", parents=("task-input",))
    provider_handle = "response-handle-12345678901234567890"
    request_id = "native-request-12345678901234567890"
    result_event = "provider-result-event-123456789012345678"
    capsule = SimpleNamespace(source_kind="provider-result", event_record_id=result_event)
    identity = object()
    package_proof = object()
    response = SimpleNamespace(
        native_request_handle=request_id, handle=provider_handle,
        receipt_handles=("input-handle", "result-handle"),
        producer_identity=identity, producer_pid=42, profile_id="profile-a",
        generation="profile-generation-a", package_id="package-a",
        loaded_package_proof=package_proof, expires_monotonic=90.0, calls={},
    )
    registry = _registry(
        {"source-handle": source, "input-handle": task_input, "result-handle": result},
        {"result-handle": (result, capsule, bytearray(b"model result"), "epoch-a")},
    )
    registry.source_observers.service.authority_epoch = "epoch-a"
    registry.source_observers.service.service_generation_digest = "c" * 64
    registry.native_bridge = SimpleNamespace(provider_response_registry=SimpleNamespace(
        _lock=threading.RLock(), _responses={provider_handle: response},
        _deliveries={}, _invocations={},
    ))
    registry._admitted_task_current = lambda _task, _profile=None: True
    run = SimpleNamespace(
        deadline=80.0, profile_id="profile-a", admitted_task=SimpleNamespace(profile_id="profile-a",
            process_generation="profile-generation-a", native_package_id="package-a"),
        process_identity=identity, native_process_identity="native-a",
        process_handle=SimpleNamespace(pid=42),
        loaded_package_proof=package_proof, source_closure=SimpleNamespace(
            verified_source_receipt_handles=("source-handle",)),
        input_event=SimpleNamespace(source_receipt_handle="input-handle"),
        authority_epoch="epoch-a", service_generation_digest="c" * 64,
        requests={}, responses={}, response_receipts={}, tool_calls={}, tool_results={},
        observed_at={}, required_action_ids=frozenset(),
    )
    registry._capture(run)
    assert run.requests == {request_id: result_event}
    assert run.responses == {result_event: result_event}


def test_tool_result_must_descend_from_matching_native_call_and_task():
    source = _receipt("source")
    task_input = _receipt("task-input", parents=("source",))
    provider = _receipt("provider-result", parents=("task-input",))
    tool = _receipt("tool-result", parents=("provider-result",))
    capsule = SimpleNamespace(source_kind="tool-result", source_action_id="selected.read",
                              event_record_id="event-tool-result-123456789012345678901234")
    payloads = {"tool-payload": (tool, capsule, bytearray(b"ok"), "epoch-a")}
    registry = _registry({"source-handle": source, "input-handle": task_input,
                          "provider-handle": provider, "tool-handle": tool}, payloads)
    registry.source_observers.service.authority_epoch = "epoch-a"
    run = SimpleNamespace(
        authority_epoch="epoch-a", required_action_ids=frozenset(),
        tool_calls={"call": ("response", "selected.read", "provider-result")},
        input_event=SimpleNamespace(source_receipt_handle="input-handle"),
        tool_results={}, observed_at={},
    )
    registry._capture_tool_results(run, 10.0)
    assert run.tool_results == {"event-tool-result-123456789012345678901234": "selected.read"}

    run.tool_calls = {"call": ("response", "selected.write", "provider-result")}
    run.tool_results.clear()
    registry._capture_tool_results(run, 10.0)
    assert run.tool_results == {}


def test_current_admission_denies_cancelled_or_replaced_generation():
    task = SimpleNamespace(task_payload_sha256="a" * 64, parent_closure_digest="b" * 64,
                           task_body_recipe_id="recipe-a", admission_id="admission-a",
                           node_id="node-a", backend_enrollment_id="backend-a",
                           resource_generation="resource-generation-a")
    handle = SimpleNamespace(task_payload_sha256=task.task_payload_sha256,
                             parent_closure_digest=task.parent_closure_digest,
                             task_body_recipe_id=task.task_body_recipe_id,
                             backend_enrollment_id=task.backend_enrollment_id)
    child = SimpleNamespace(admission_id=task.admission_id, node_id=task.node_id)
    enrollment = SimpleNamespace(generation=task.resource_generation, profile_id="profile-a")
    authority = SimpleNamespace(
        _running_task_handles={"admission": (handle, child, enrollment, object())},
        task_handle_cancelled=lambda _handle, _node: False,
        _resource_generation=lambda _enrollment: "resource-generation-a",
    )
    registry = RootTaskNativeObservationRegistry.__new__(RootTaskNativeObservationRegistry)
    registry.admitted_tasks = authority
    assert registry._admitted_task_current(task, "profile-a")
    assert not registry._admitted_task_current(task, "profile-b")
    authority.task_handle_cancelled = lambda _handle, _node: True
    assert not registry._admitted_task_current(task, "profile-a")
