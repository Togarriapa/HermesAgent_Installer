from __future__ import annotations

import hashlib
import json

import pytest

from hermes_installer.authority.resource_task_execution import (
    RootResourceTaskRunner,
    _strict_prompt,
)
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.managed_process_custodian import (
    ManagedTaskHandle,
    RootTaskTerminalReceipt,
)
from hermes_installer.registry.resource_jobs import (
    RootAdmittedTask,
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
        "handle_id": "job-admission-handle",
        "task_handle_id": "opaque-managed-task-handle",
        "terminal_receipt_id": "terminal-receipt-1",
        "job_id": "job-1", "node_id": "node-1", "child_admission_id": "child-admission-1",
        "attempt_index": 0, "backend_enrollment_id": "backend-1",
        "resource_generation": "resource-generation-1", "profile_id": "profile-1",
        "profile_generation": "process-generation-1", "process_id": "process-1",
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
])
def test_runner_never_accepts_unproven_terminal_as_a_result(changes):
    task = admitted_task()
    receipt = terminal_receipt(**changes)
    with pytest.raises(AuthorityDenied):
        RootResourceTaskRunner._validate_terminal(
            admission=None, task=task,
            managed_handle=ManagedTaskHandle("opaque-managed-task-handle", "process-generation-1"),
            terminal=receipt,
        )

