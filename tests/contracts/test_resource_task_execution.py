from __future__ import annotations

import hashlib
import json
import os
from types import SimpleNamespace

import pytest

from hermes_installer.authority.resource_task_execution import (
    RootResourceTaskRunner,
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
    service.monotonic = lambda: 1.0

    with pytest.raises(AuthorityDenied, match="source or controller binding changed"):
        service.perform_admitted_resource_process_start(
            admission, task, source, controller, selection,
            exact_stdin=_strict_prompt(task), timeout=5.0, cancelled=lambda: False,
        )
    assert starts == []


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
