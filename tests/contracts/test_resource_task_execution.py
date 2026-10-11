from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from hermes_installer.authority.resource_task_execution import (
    RootResourceTaskRunner,
    _validate_admission,
    _strict_prompt,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.authority.service import AuthorityService
from hermes_installer.managed_process_custodian import (
    ManagedTaskHandle,
    RootTaskTerminalReceipt,
)
from hermes_installer.registry.resource_jobs import (
    RootAdmittedTask,
    RootAdmittedTaskSource,
    RootResourceJobAdmissionHandle,
    RootTaskController,
    RootTaskNativeExecutionReceipt,
    ResourceJobDenied,
)


def admitted_task(*, prompt: str = "hello") -> RootAdmittedTask:
    payload = json.dumps({"prompt": prompt}, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    stdin = prompt.encode("utf-8")
    return RootAdmittedTask(
        schema=1, admission_id="child-admission-1", job_id="job-1", node_id="node-1",
        backend_enrollment_id="backend-1", resource_generation="resource-generation-1",
        process_enrollment_id="process-enrollment-1", process_generation="process-generation-1",
        native_package_id="native-package-1", native_package_generation="native-generation-1",
        operation_id="hermes-resource-profile-task-v1", task_body_recipe_id="prompt-recipe-1",
        task_request_schema_id="prompt-schema-1", task_payload_sha256=hashlib.sha256(payload).hexdigest(),
        task_payload_bytes=payload, stdin_sha256=hashlib.sha256(stdin).hexdigest(),
        stdin_size_bytes=len(stdin), parent_closure_digest="a" * 64,
        deadline_monotonic=10.0, source_context_handle="source-context-handle-1234567890123456",
    )


def terminal_receipt(**changes) -> RootTaskTerminalReceipt:
    stdout, stderr = b"answer", b""
    row = {
        "task_handle": "opaque-managed-task-handle",
        "terminal_receipt_handle": "terminal-receipt-1",
        "job_id": "job-1", "node_id": "node-1", "admission_id": "child-admission-1",
        "admission_handle_id": "job-admission-handle", "backend_enrollment_id": "backend-1",
        "operation_id": "hermes-resource-profile-task-v1",
        "task_body_recipe_id": "prompt-recipe-1", "task_request_schema_id": "prompt-schema-1",
        "resource_generation": "resource-generation-1", "profile_id": "profile-1",
        "process_generation": "process-generation-1", "process_id": "process-1",
        "exit_code": 0, "timed_out": False, "cancelled": False,
        "started_monotonic": 1.0, "finished_monotonic": 2.0,
        "cgroup_identity": "cgroup-1", "cgroup_empty": True, "main_pidfd_gone": True,
        "descendants_gone": True, "launcher_reaped": True, "cleanup_verified": True,
        "stdout": stdout, "stderr": stderr,
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "output_complete": True,
        "schema": 1, "state": "completed", "observed_monotonic": 2.0,
        "stdout_size_bytes": len(stdout), "stderr_size_bytes": len(stderr),
        "parent_closure_digest": "a" * 64,
        "native_loader_ready_event_id": "loader-ready-event-1",
    }
    row.update(changes)
    return RootTaskTerminalReceipt(**row)


def test_admitted_prompt_projects_to_exact_utf8_stdin_without_newline():
    task = admitted_task(prompt="héllo")
    assert _strict_prompt(task) == "héllo".encode("utf-8")
    assert not _strict_prompt(task).endswith(b"\n")


def test_admitted_task_rejects_mismatched_stdin_hash_and_size():
    payload = b'{"prompt":"hello"}'
    with pytest.raises(ResourceJobDenied):
        RootAdmittedTask(
            schema=1, admission_id="child-admission-1", job_id="job-1", node_id="node-1",
            backend_enrollment_id="backend-1", resource_generation="resource-generation-1",
            process_enrollment_id="process-enrollment-1", process_generation="process-generation-1",
            native_package_id="native-package-1", native_package_generation="native-generation-1",
            operation_id="hermes-resource-profile-task-v1", task_body_recipe_id="prompt-recipe-1",
            task_request_schema_id="prompt-schema-1", task_payload_sha256=hashlib.sha256(payload).hexdigest(),
            task_payload_bytes=payload, stdin_sha256="0" * 64, stdin_size_bytes=5,
            parent_closure_digest="a" * 64, deadline_monotonic=10.0,
            source_context_handle="source-context-handle-1234567890123456",
        )


def test_service_rejects_changed_parent_closure_before_any_process_start():
    """Exercise the real fixed start seam's trust join up to its side-effect gate."""
    from hermes_installer.authority.service import PrincipalBinding
    from hermes_installer.authority.types import Sensitivity
    from hermes_installer.registry.resource_backends import SelectedResourceProfileTask

    task = admitted_task()
    admission = RootResourceJobAdmissionHandle(
        handle_id="root-admission-handle-1234567890123456", job_id=task.job_id,
        node_id=task.node_id, child_admission_id=task.admission_id, attempt_index=0,
        backend_enrollment_id=task.backend_enrollment_id,
        resource_generation=task.resource_generation, profile_id="profile-1",
        profile_generation="profile-generation-1", native_package_id=task.native_package_id,
        native_package_generation=task.native_package_generation,
        process_enrollment_id=task.process_enrollment_id,
        process_generation=task.process_generation, operation_id=task.operation_id,
        child_target_id="process-target-1", child_capability="hermes-profile-invoke",
        task_body_recipe_id=task.task_body_recipe_id,
        task_request_schema_id=task.task_request_schema_id,
        task_payload=task.task_payload_bytes, task_payload_sha256=task.task_payload_sha256,
        parent_closure_digest=task.parent_closure_digest, expires_monotonic=20.0,
    )
    source = RootAdmittedTaskSource(
        source_context_handle=task.source_context_handle,
        verified_source_receipt_handles=("r" * 40,), signed_receipt_wires=(b"signed-receipt",),
        sensitivity=Sensitivity.PRIVATE, lineage_hash="b" * 64, recipient_ceiling=("profile-1",),
        principal_id="principal:one", profile_id="profile-1", namespace_id="namespace:one",
        parent_closure_digest="c" * 64, controller_binding_handle="controller-handle-123456789",
        expires_monotonic=19.0,
    )
    controller = RootTaskController(
        schema=1, controller_handle=source.controller_binding_handle, controller_kind="worker",
        controller_role_artifact_id="role-artifact", controller_role_sha256="d" * 64,
        pid=os.getpid(), pidfd=0, uid=os.getuid(), identity="identity",
        controller_profile_id="profile-1", controller_generation="profile-generation-1",
        source_receipt_id="receipt-1", subject_principal_id=source.principal_id,
        subject_profile_id=source.profile_id, subject_namespace_id=source.namespace_id,
        service_generation_digest="e" * 64, expires_monotonic=18.0,
    )
    selection = SelectedResourceProfileTask(
        resource_backend_id=task.backend_enrollment_id, resource_id="resource-1",
        resource_generation=task.resource_generation, profile_id="profile-1",
        principal_id=source.principal_id, profile_generation=admission.profile_generation,
        source_profile_id="source-profile-1", home_binding_id="home-binding-1",
        process_enrollment_id=task.process_enrollment_id,
        process_generation=task.process_generation, operation_id=task.operation_id,
        process_start_target=admission.child_target_id, native_package_id=task.native_package_id,
        native_package_generation=task.native_package_generation,
        task_body_recipe_id=task.task_body_recipe_id,
        task_request_schema_id=task.task_request_schema_id,
        process_operation=object(), launch_recipe=object(), native_package=object(),
        task_body_recipe=object(),
    )
    starts = []
    manager = SimpleNamespace(start_selected_task=lambda *args, **kwargs: starts.append((args, kwargs)))
    service = AuthorityService(
        signing_key=b"t" * 32, key_id="task-runner-test",
        bindings_by_uid={os.getuid(): PrincipalBinding(
            os.getuid(), "principal:one", "profile-1", "namespace:one",
            frozenset({"hermes-profile-invoke"}),
        )}, rules={}, handlers={}, process_effect_handler=manager,
        service_generation_digest="e" * 64,
    )
    service.resource_task_runner = object()
    service.resource_job_authority = object()
    service.native_profile_task_home_registry = object()
    service.monotonic = lambda: 1.0

    with pytest.raises(AuthorityDenied, match="source or controller binding changed"):
        service.perform_admitted_resource_process_start(
            admission, task, source, controller, selection,
            exact_stdin=_strict_prompt(task), timeout=5.0, cancelled=lambda: False,
            # The mismatched parent closure must be rejected before the home
            # proof is consulted; this deliberately unusable sentinel catches
            # any regression that reaches a later stage.
            selected_home_binding=object(),
        )
    assert starts == []


def test_root_event_controller_binding_is_typed_separately_from_worker_peer():
    """Root role PIDFDs are accepted as provenance, never as worker receipts."""
    from hermes_installer.authority.types import Sensitivity
    from hermes_installer.registry.resource_backends import SelectedResourceProfileTask

    task = admitted_task()
    admission = RootResourceJobAdmissionHandle(
        handle_id="root-admission-handle-1234567890123456", job_id=task.job_id,
        node_id=task.node_id, child_admission_id=task.admission_id, attempt_index=0,
        backend_enrollment_id=task.backend_enrollment_id,
        resource_generation=task.resource_generation, profile_id="profile-1",
        profile_generation="profile-generation-1", native_package_id=task.native_package_id,
        native_package_generation=task.native_package_generation,
        process_enrollment_id=task.process_enrollment_id,
        process_generation=task.process_generation, operation_id=task.operation_id,
        child_target_id="process-target-1", child_capability="hermes-profile-invoke",
        task_body_recipe_id=task.task_body_recipe_id,
        task_request_schema_id=task.task_request_schema_id,
        task_payload=task.task_payload_bytes, task_payload_sha256=task.task_payload_sha256,
        parent_closure_digest=task.parent_closure_digest, expires_monotonic=20.0,
    )
    source = RootAdmittedTaskSource(
        source_context_handle=task.source_context_handle,
        verified_source_receipt_handles=("r" * 40,),
        signed_receipt_wires=(b'{"receipt_id":"receipt-1"}',),
        sensitivity=Sensitivity.PRIVATE, lineage_hash="b" * 64,
        recipient_ceiling=("profile-1",), principal_id="principal:one",
        profile_id="profile-1", namespace_id="namespace:one",
        parent_closure_digest=task.parent_closure_digest,
        controller_binding_handle="controller-handle-123456789",
        expires_monotonic=19.0,
    )
    controller = RootTaskController(
        schema=1, controller_handle=source.controller_binding_handle,
        controller_kind="root-scheduler", controller_role_artifact_id="role-artifact",
        controller_role_sha256="d" * 64, pid=42, pidfd=8, uid=0,
        identity="root-scheduler-identity", controller_profile_id=None,
        controller_generation="root-controller-generation", source_receipt_id=None,
        subject_principal_id=source.principal_id, subject_profile_id=source.profile_id,
        subject_namespace_id=source.namespace_id, service_generation_digest="e" * 64,
        expires_monotonic=18.0,
    )
    selection = SelectedResourceProfileTask(
        resource_backend_id=task.backend_enrollment_id, resource_id="resource-1",
        resource_generation=task.resource_generation, profile_id="profile-1",
        principal_id=source.principal_id, profile_generation=admission.profile_generation,
        source_profile_id="source-profile-1", home_binding_id="home-binding-1",
        process_enrollment_id=task.process_enrollment_id,
        process_generation=task.process_generation, operation_id=task.operation_id,
        process_start_target=admission.child_target_id, native_package_id=task.native_package_id,
        native_package_generation=task.native_package_generation,
        task_body_recipe_id=task.task_body_recipe_id,
        task_request_schema_id=task.task_request_schema_id,
        process_operation=object(), launch_recipe=object(), native_package=object(),
        task_body_recipe=object(),
    )

    assert _validate_admission(
        admission, task, source, controller, selection, now=1.0,
        service_generation_digest="e" * 64, expected_resource_id="resource-1",
        expected_principal_id="principal:one",
    ) == b"hello"

    # A root role remains an independently authenticated controller; the
    # runner's real path also requires ResourceJobAuthority's live resolver.
    assert controller.uid == 0
    assert controller.controller_profile_id is None


@pytest.mark.parametrize("changes", [
    {"exit_code": 17, "state": "failed"},
    {"timed_out": True, "state": "failed"},
    {"cancelled": True, "state": "cancelled"},
    {"cleanup_verified": False},
    {"cgroup_empty": False},
    {"descendants_gone": False},
    {"output_complete": False},
    {"stdout_sha256": "0" * 64},
    {"parent_closure_digest": "b" * 64},
    {"admission_id": "replayed-child"},
    {"admission_handle_id": "different-root-handle"},
    {"operation_id": "different-process-recipe"},
    {"task_body_recipe_id": "different-body-recipe"},
    {"task_request_schema_id": "different-body-schema"},
    {"process_generation": "stale-process-generation"},
    {"process_id": "different-owned-process"},
    {"native_loader_ready_event_id": None},
])
def test_runner_never_accepts_unproven_terminal_as_a_result(changes):
    task = admitted_task()
    receipt = terminal_receipt(**changes)
    with pytest.raises(AuthorityDenied):
        RootResourceTaskRunner._validate_terminal(
            admission=SimpleNamespace(handle_id="job-admission-handle",
                                      operation_id=task.operation_id, profile_id="profile-1"), task=task,
            managed_handle=ManagedTaskHandle("opaque-managed-task-handle", "process-generation-1", "process-1"),
            terminal=receipt, deadline_monotonic=10.0,
        )


def test_runner_rejects_same_shape_native_companion_not_issued_by_registry():
    task = admitted_task()
    handle = ManagedTaskHandle("m" * 32, "process-generation-1", "process-1")
    terminal = terminal_receipt(
        task_handle=handle.handle_id,
        terminal_receipt_handle="t" * 32,
        native_loader_ready_event_id="l" * 32,
    )
    companion = RootTaskNativeExecutionReceipt(
        schema=1, native_execution_receipt_handle="n" * 32,
        task_handle=handle.handle_id, process_id=handle.process_id,
        process_generation=task.process_generation,
        native_package_generation=task.native_package_generation,
        loader_ready_event_id=terminal.native_loader_ready_event_id,
        initial_input_event_id="i" * 32,
        native_request_event_ids=("r" * 32,), native_result_event_ids=("s" * 32,),
        required_tool_result_event_ids=(),
        parent_closure_digest=task.parent_closure_digest,
        task_payload_sha256=task.task_payload_sha256,
        terminal_receipt_handle=terminal.terminal_receipt_handle,
        observed_monotonic=3.0,
    )
    runner = object.__new__(RootResourceTaskRunner)
    runner.native_observations = SimpleNamespace(verify_receipt=lambda _receipt: False)

    with pytest.raises(AuthorityDenied, match="forged or replayed"):
        runner._validate_native_execution(
            task, handle, terminal, companion, deadline_monotonic=10.0)
