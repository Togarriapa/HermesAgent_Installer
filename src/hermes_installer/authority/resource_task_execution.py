"""Root-owned execution and result capsules for selected Hermes resource tasks.

This runner is deliberately separate from the managed build launcher and from
worker RPC dispatch.  It accepts only the one-use in-process job handle minted
by ``ResourceJobAuthority`` and delegates the fixed ``process.start`` effect to
``AuthorityService``.  The process custodian owns stdin/EOF, PIDFD/cgroup wait,
and cleanup proof; this module joins those facts to the selected finite result
validator and retains an unforgeable, one-use root result capsule.
"""
from __future__ import annotations

import hashlib
import json
import math
import secrets
import threading
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from hermes_installer.authority.resource_jobs import (
    ResourceJobAuthority,
    RootResourceProcessReceipt,
)
from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.authority.source_observers import RootTaskNativeObservationRegistry
from hermes_installer.managed_process_custodian import (
    ManagedTaskHandle,
    RootTaskTerminalReceipt,
)
from hermes_installer.registry.resource_backends import (
    ResourceProfileTaskAdapter,
    RootArtifactValidator,
    RootSelectedResultValidator,
    SelectedResourceProfileTask,
)
from hermes_installer.registry.resource_jobs import (
    RootAdmittedTask,
    RootAdmittedTaskSource,
    RootResourceJobAdmissionHandle,
    RootTaskNativeExecutionReceipt,
    RootTaskController,
)

_MAX_PROMPT_BYTES = 262_144
_HEX64 = __import__("re").compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class _TaskCapsule:
    receipt: RootResourceProcessReceipt
    process_receipt: RootTaskTerminalReceipt
    native_execution_receipt: RootTaskNativeExecutionReceipt
    source: RootAdmittedTaskSource
    task: RootAdmittedTask
    validator: RootSelectedResultValidator
    result_fields: Mapping[str, Any]
    canonical_body: bytes
    result_receipt_id: str
    service_generation_digest: str


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise AuthorityDenied("resource.task_payload", "admitted task is not canonical UTF-8 JSON") from None


def _strict_prompt(task: RootAdmittedTask) -> bytes:
    """Re-derive the only accepted prompt frame from root-retained task bytes."""
    raw = task.task_payload_bytes
    if (not isinstance(raw, bytes) or not 1 <= len(raw) <= _MAX_PROMPT_BYTES
            or hashlib.sha256(raw).hexdigest() != task.task_payload_sha256):
        raise AuthorityDenied("resource.task_payload", "admitted task payload digest or bound is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise AuthorityDenied("resource.task_payload", "admitted task payload is malformed") from None
    if (not isinstance(value, dict) or set(value) != {"prompt"}
            or not isinstance(value["prompt"], str) or not value["prompt"]
            or _canonical_json(value) != raw):
        raise AuthorityDenied("resource.task_payload", "admitted task is not the fixed prompt recipe")
    stdin = value["prompt"].encode("utf-8")
    if (not 1 <= len(stdin) <= _MAX_PROMPT_BYTES
            or hashlib.sha256(stdin).hexdigest() != task.stdin_sha256
            or len(stdin) != task.stdin_size_bytes):
        raise AuthorityDenied("resource.task_payload", "derived task stdin differs from its admitted digest")
    return stdin


def _validate_admission(
    admission: RootResourceJobAdmissionHandle,
    task: RootAdmittedTask,
    source: RootAdmittedTaskSource,
    controller: RootTaskController,
    selection: SelectedResourceProfileTask,
    *,
    now: float,
    service_generation_digest: str,
    expected_resource_id: str,
    expected_principal_id: str,
) -> bytes:
    """Join every typed root DTO before granting any process effect."""
    try:
        source_receipt_rows = [json.loads(wire.decode("utf-8"))
                               for wire in source.signed_receipt_wires]
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
        raise AuthorityDenied("resource.task_binding", "source receipt closure is malformed") from None
    source_receipt_ids = {row.get("receipt_id") for row in source_receipt_rows
                          if isinstance(row, dict)}
    pairs = (
        (task.admission_id, admission.child_admission_id),
        (task.job_id, admission.job_id),
        (task.node_id, admission.node_id),
        (task.backend_enrollment_id, admission.backend_enrollment_id),
        (task.resource_generation, admission.resource_generation),
        (task.process_enrollment_id, admission.process_enrollment_id),
        (task.process_generation, admission.process_generation),
        (task.native_package_id, admission.native_package_id),
        (task.native_package_generation, admission.native_package_generation),
        (task.operation_id, admission.operation_id),
        (task.task_body_recipe_id, admission.task_body_recipe_id),
        (task.task_request_schema_id, admission.task_request_schema_id),
        (task.task_payload_sha256, admission.task_payload_sha256),
        (task.parent_closure_digest, admission.parent_closure_digest),
        (task.source_context_handle, source.source_context_handle),
        (source.parent_closure_digest, admission.parent_closure_digest),
        (source.profile_id, admission.profile_id),
        (source.principal_id, expected_principal_id),
        (selection.resource_backend_id, admission.backend_enrollment_id),
        (selection.resource_id, expected_resource_id),
        (selection.resource_generation, admission.resource_generation),
        (selection.profile_id, admission.profile_id),
        (selection.profile_generation, admission.profile_generation),
        (selection.process_enrollment_id, admission.process_enrollment_id),
        (selection.process_generation, admission.process_generation),
        (selection.operation_id, admission.operation_id),
        (selection.process_start_target, admission.child_target_id),
        (selection.native_package_id, admission.native_package_id),
        (selection.native_package_generation, admission.native_package_generation),
        (selection.task_body_recipe_id, admission.task_body_recipe_id),
        (selection.task_request_schema_id, admission.task_request_schema_id),
        (controller.controller_handle, source.controller_binding_handle),
        (controller.subject_profile_id, source.profile_id),
        (controller.subject_principal_id, source.principal_id),
        (controller.subject_namespace_id, source.namespace_id),
        (controller.service_generation_digest, service_generation_digest),
    )
    if any(left != right for left, right in pairs):
        raise AuthorityDenied("resource.task_binding", "selected task, lineage, controller or generation changed")
    if (controller.schema != 1 or controller.controller_kind != "worker"
            or controller.pid <= 0 or controller.pidfd < 0
            or not _HEX64.fullmatch(controller.controller_role_sha256)
            or not now < controller.expires_monotonic
            or not now < source.expires_monotonic
            or not now < task.deadline_monotonic
            or task.deadline_monotonic > admission.expires_monotonic
            or not source.verified_source_receipt_handles
            or not source.signed_receipt_wires
            or len(source.verified_source_receipt_handles) != len(source.signed_receipt_wires)
            or controller.source_receipt_id not in source_receipt_ids
            or not _HEX64.fullmatch(task.parent_closure_digest)
            or admission.child_capability != "hermes-profile-invoke"
            or admission.operation_id != "hermes-resource-profile-task-v1"):
        raise AuthorityDenied("resource.task_binding", "task lease or live controller proof is invalid")
    if (not isinstance(source.lineage_hash, str) or not _HEX64.fullmatch(source.lineage_hash)
            or selection.native_package_generation != admission.native_package_generation):
        raise AuthorityDenied("resource.task_binding", "task source lineage is malformed")
    return _strict_prompt(task)


class RootResourceTaskRunner:
    """Run one selected, admitted Hermes task and retain its private result.

    ``AuthorityService.perform_admitted_resource_process_start`` is a fixed
    root-only seam: it re-resolves the protected process profile and current
    controller, mints a fresh reduced ``process.start`` grant for the exact
    selection bytes, and calls the actual process custodian.  No supplied
    callback or argv/path is accepted here.
    """

    def __init__(self, *, service: AuthorityService,
                 job_authority: ResourceJobAuthority,
                 profile_task_adapters: Mapping[tuple[str, str], ResourceProfileTaskAdapter],
                 protected_bindings: Any,
                 result_validator: RootArtifactValidator,
                 native_observations: RootTaskNativeObservationRegistry):
        if (not isinstance(service, AuthorityService)
                or not isinstance(job_authority, ResourceJobAuthority)
                or job_authority.service is not service
                or not isinstance(profile_task_adapters, Mapping)
                or not profile_task_adapters
                or not isinstance(result_validator, RootArtifactValidator)
                or not isinstance(native_observations, RootTaskNativeObservationRegistry)
                or getattr(protected_bindings, "process_manager", None) is not service.process_effect_handler):
            raise ValueError("root resource task runtime bindings are incomplete")
        self.service = service
        self.jobs = job_authority
        self.adapters = MappingProxyType(dict(profile_task_adapters))
        self.bindings = protected_bindings
        self.results = result_validator
        self.native_observations = native_observations
        self.manager = service.process_effect_handler
        self._lock = threading.RLock()
        self._capsules: dict[str, _TaskCapsule] = {}

    def launch_resource_profile_task(
        self, admission_handle: RootResourceJobAdmissionHandle, node_id: str,
    ) -> RootResourceProcessReceipt:
        """Consume a selected admission, start one task, wait, then validate it."""
        self._expire_capsules()
        admission = self.jobs.consume_task_handle(admission_handle, node_id)
        source: RootAdmittedTaskSource | None = None
        controller: RootTaskController | None = None
        managed_handle: ManagedTaskHandle | None = None
        try:
            source = self.jobs.resolve_admitted_task_source(admission, node_id)
            # The controller resolver consumes its one-use duplicate only after
            # source resolution; this PIDFD is closed on every exit path here.
            controller = self.jobs.resolve_admitted_task_controller(admission, node_id)
            task = self.jobs.resolve_admitted_task(admission, node_id)
            adapter = self.adapters.get((admission.backend_enrollment_id, node_id))
            if (not isinstance(adapter, ResourceProfileTaskAdapter)
                    or adapter.node_id != node_id
                    or not isinstance(adapter.selection, SelectedResourceProfileTask)):
                raise AuthorityDenied("resource.task_binding", "immutable selected task adapter is unavailable")
            selection = adapter.selection
            enrollment, backend = self._selected_backend(admission)
            node = enrollment.node_map.get(node_id)
            if (node is None or node.backend_enrollment_id != backend.backend_id
                    or node.result_schema_id != backend.result_schema_id):
                raise AuthorityDenied("resource.task_binding", "selected result schema differs from its DAG node")
            now = self.service.monotonic()
            if self.service.service_generation_digest is None:
                raise AuthorityDenied("resource.task_binding", "active service generation is unavailable")
            stdin = _validate_admission(
                admission, task, source, controller, selection, now=now,
                service_generation_digest=self.service.service_generation_digest,
                expected_resource_id=enrollment.resource_id,
                expected_principal_id=enrollment.principal_id,
            )
            self.jobs.start_task_handle(admission, node_id)
            cancelled = lambda: self.jobs.task_handle_cancelled(admission, node_id)
            if cancelled():
                raise AuthorityDenied("resource.task_cancelled", "selected resource task was cancelled")
            start = getattr(self.service, "perform_admitted_resource_process_start", None)
            if not callable(start):
                raise AuthorityDenied("resource.task_unavailable", "root selected process.start effect is unavailable")
            task_deadline = min(float(task.deadline_monotonic), float(source.expires_monotonic))
            timeout = min(float(backend.maximum_seconds),
                          task_deadline - self.service.monotonic())
            if timeout <= 0:
                raise AuthorityDenied("resource.task_expired", "selected task deadline expired before launch")
            managed_handle = start(
                admission, task, source, controller, selection,
                exact_stdin=stdin, timeout=timeout, cancelled=cancelled,
            )
            if not isinstance(managed_handle, ManagedTaskHandle):
                raise AuthorityDenied("resource.task_start", "root process custodian returned no owned task handle")
            wait = getattr(self.manager, "wait_owned_task_terminal", None)
            if not callable(wait):
                raise AuthorityDenied("resource.task_unavailable", "root task terminal monitor is unavailable")
            terminal = wait(
                managed_handle,
                deadline_monotonic=task_deadline,
                cancelled=cancelled,
            )
            self._validate_terminal(admission, task, managed_handle, terminal,
                                    deadline_monotonic=task_deadline)
            native_execution = self.native_observations.resolve_task_execution(
                managed_handle, terminal.terminal_receipt_handle,
            )
            self._validate_native_execution(
                task, managed_handle, terminal, native_execution,
                deadline_monotonic=task_deadline,
            )
            result_validator = self.results.resolve_selected_result(
                admission.backend_enrollment_id, backend.result_schema_id,
                expected_service_generation_digest=self.service.service_generation_digest,
                expected_resource_generation=task.resource_generation,
            )
            fields = result_validator.validate_stdout(terminal.stdout)
            body = _canonical_json(dict(fields))
            if len(body) > backend.maximum_response_bytes:
                raise AuthorityDenied("resource.task_result", "validated result exceeds the selected backend bound")
            capsule_handle = secrets.token_urlsafe(32)
            receipt_id = secrets.token_urlsafe(24)
            expiry = min(float(task.deadline_monotonic), float(source.expires_monotonic))
            receipt = RootResourceProcessReceipt(
                job_id=task.job_id, node_id=task.node_id,
                backend_enrollment_id=task.backend_enrollment_id,
                process_id=terminal.process_id, process_generation=task.process_generation,
                native_package_generation=task.native_package_generation,
                task_payload_sha256=task.task_payload_sha256,
                parent_closure_digest=task.parent_closure_digest,
                terminal_receipt_handle=terminal.terminal_receipt_id,
                result_capsule_handle=capsule_handle, expires_monotonic=expiry,
            )
            capsule = _TaskCapsule(
                receipt=receipt, process_receipt=terminal,
                native_execution_receipt=native_execution, source=source, task=task,
                validator=result_validator, result_fields=MappingProxyType(dict(fields)),
                canonical_body=body, result_receipt_id=receipt_id,
                service_generation_digest=self.service.service_generation_digest,
            )
            with self._lock:
                if len(self._capsules) >= 256:
                    raise AuthorityDenied("resource.task_capacity", "root result capsule store is full")
                self._capsules[capsule_handle] = capsule
            return receipt
        finally:
            if controller is not None:
                try:
                    __import__("os").close(controller.pidfd)
                except OSError:
                    pass
            self.jobs.release_task_handle(admission, node_id)

    def consume_resource_task_completion(
        self, receipt: RootResourceProcessReceipt, *, cancelled: Callable[[], bool],
    ) -> Mapping[str, Any]:
        """Consume the actual root-retained result capsule exactly once."""
        if not isinstance(receipt, RootResourceProcessReceipt) or not callable(cancelled):
            raise AuthorityDenied("resource.task_result", "root result receipt or cancellation guard is invalid")
        with self._lock:
            capsule = self._capsules.pop(receipt.result_capsule_handle, None)
            if capsule is None or capsule.receipt is not receipt:
                raise AuthorityDenied("resource.task_result", "root result capsule is unknown or already consumed")
        task = capsule.task
        now = self.service.monotonic()
        if (cancelled() or not now < receipt.expires_monotonic
                or self.service.service_generation_digest != capsule.service_generation_digest
                or task.parent_closure_digest != capsule.source.parent_closure_digest
                or task.task_payload_sha256 != receipt.task_payload_sha256
                or capsule.process_receipt.terminal_receipt_id != receipt.terminal_receipt_handle):
            raise AuthorityDenied("resource.task_result", "root task result capsule is stale or cancelled")
        return MappingProxyType({
            "status": 200,
            "body": capsule.canonical_body,
            "headers": MappingProxyType({"content-type": "application/json"}),
            "receipt_id": capsule.result_receipt_id,
            "result_fields": capsule.result_fields,
        })

    def _selected_backend(self, admission: RootResourceJobAdmissionHandle) -> tuple[Any, Any]:
        matches = [(enrollment, enrollment.backends.get(admission.backend_enrollment_id))
                   for (_resource_id, generation), enrollment in self.jobs.enrollments.items()
                   if generation == admission.resource_generation]
        matches = [(enrollment, backend) for enrollment, backend in matches if backend is not None]
        if len(matches) != 1:
            raise AuthorityDenied("resource.task_binding", "selected backend is stale or ambiguous")
        enrollment, backend = matches[0]
        if (backend.backend_id != admission.backend_enrollment_id
                or backend.execution_binding is None
                or backend.execution_binding["operation_id"] != admission.operation_id
                or backend.resource_id != enrollment.resource_id
                or not enrollment.principal_id
                or admission.node_id not in enrollment.node_map
                or enrollment.node_map[admission.node_id].backend_enrollment_id != backend.backend_id
                or backend.profile_id != admission.profile_id
                or backend.profile_generation != admission.profile_generation
                or backend.native_package_id != admission.native_package_id
                or backend.native_package_generation != admission.native_package_generation):
            raise AuthorityDenied("resource.task_binding", "selected backend generation changed")
        return enrollment, backend

    def _expire_capsules(self) -> None:
        now = self.service.monotonic()
        with self._lock:
            expired = [key for key, capsule in self._capsules.items()
                       if now >= capsule.receipt.expires_monotonic]
            for key in expired:
                self._capsules.pop(key, None)

    def _validate_native_execution(
        self,
        task: RootAdmittedTask,
        managed_handle: ManagedTaskHandle,
        terminal: RootTaskTerminalReceipt,
        native_receipt: Any,
        *,
        deadline_monotonic: float,
    ) -> None:
        """Require the separately issued, one-use live native event companion."""
        if type(native_receipt) is not RootTaskNativeExecutionReceipt:
            raise AuthorityDenied("resource.task_native", "root native execution companion is unavailable")
        # Consume exact issuance before inspecting contents, so a malformed
        # companion returned by the root registry cannot be replayed later.
        if not self.native_observations.verify_receipt(native_receipt):
            raise AuthorityDenied("resource.task_native", "native execution companion is forged or replayed")
        ids = (native_receipt.native_request_event_ids,
               native_receipt.native_result_event_ids,
               native_receipt.required_tool_result_event_ids)
        if (native_receipt.schema != 1
                or native_receipt.task_handle != managed_handle.handle_id
                or native_receipt.process_id != managed_handle.process_id
                or native_receipt.process_generation != task.process_generation
                or native_receipt.native_package_generation != task.native_package_generation
                or native_receipt.loader_ready_event_id != terminal.native_loader_ready_event_id
                or not native_receipt.initial_input_event_id
                or native_receipt.parent_closure_digest != task.parent_closure_digest
                or native_receipt.task_payload_sha256 != task.task_payload_sha256
                or native_receipt.terminal_receipt_handle != terminal.terminal_receipt_handle
                or terminal.native_execution_receipt_handle not in (None, native_receipt.native_execution_receipt_handle)
                or any(not isinstance(items, tuple) for items in ids)
                or not native_receipt.native_request_event_ids
                or not native_receipt.native_result_event_ids
                or len(native_receipt.native_request_event_ids) != len(native_receipt.native_result_event_ids)
                or any(not items or any(not isinstance(item, str) or not item for item in items)
                       for items in ids[:2])
                or any(not isinstance(item, str) or not item for item in ids[2])
                or len(set(native_receipt.native_request_event_ids)) != len(native_receipt.native_request_event_ids)
                or len(set(native_receipt.native_result_event_ids)) != len(native_receipt.native_result_event_ids)
                or len(set(native_receipt.required_tool_result_event_ids)) != len(native_receipt.required_tool_result_event_ids)
                or not math.isfinite(native_receipt.observed_monotonic)
                or terminal.observed_monotonic > native_receipt.observed_monotonic
                or native_receipt.observed_monotonic > deadline_monotonic):
            raise AuthorityDenied("resource.task_native", "native execution companion differs from the admitted terminal")

    @staticmethod
    def _validate_terminal(
        admission: RootResourceJobAdmissionHandle,
        task: RootAdmittedTask,
        managed_handle: ManagedTaskHandle,
        terminal: Any,
        *,
        deadline_monotonic: float,
    ) -> None:
        required = (
            "task_handle", "terminal_receipt_handle", "job_id", "node_id",
            "admission_id", "admission_handle_id", "backend_enrollment_id",
            "operation_id", "task_body_recipe_id", "task_request_schema_id",
            "resource_generation", "profile_id", "process_generation",
            "process_id", "exit_code", "timed_out", "cancelled", "cleanup_verified",
            "cgroup_empty", "main_pidfd_gone", "descendants_gone", "launcher_reaped",
            "stdout", "stderr", "stdout_sha256", "stderr_sha256", "output_complete",
            "schema", "state", "observed_monotonic", "stdout_size_bytes",
            "stderr_size_bytes", "parent_closure_digest", "native_loader_ready_event_id",
        )
        if not isinstance(terminal, RootTaskTerminalReceipt) or any(
                not hasattr(terminal, name) for name in required):
            raise AuthorityDenied("resource.task_terminal", "root task terminal receipt is malformed")
        if (terminal.schema != 1
                or terminal.task_handle != managed_handle.handle_id
                or terminal.process_id != managed_handle.process_id
                or terminal.job_id != task.job_id or terminal.node_id != task.node_id
                or terminal.admission_id != task.admission_id
                or terminal.admission_handle_id != admission.handle_id
                or terminal.backend_enrollment_id != task.backend_enrollment_id
                or terminal.profile_id != admission.profile_id
                or terminal.operation_id != task.operation_id
                or terminal.task_body_recipe_id != task.task_body_recipe_id
                or terminal.task_request_schema_id != task.task_request_schema_id
                or terminal.resource_generation != task.resource_generation
                or terminal.process_generation != task.process_generation
                or terminal.parent_closure_digest != task.parent_closure_digest
                or not isinstance(terminal.native_loader_ready_event_id, str)
                or not terminal.native_loader_ready_event_id
                or terminal.state != "completed" or terminal.exit_code != 0
                or terminal.timed_out or terminal.cancelled
                or not terminal.cleanup_verified or not terminal.cgroup_empty
                or not terminal.main_pidfd_gone or not terminal.descendants_gone
                or not terminal.launcher_reaped or not terminal.output_complete
                or type(terminal.exit_code) is not int
                or any(type(getattr(terminal, name)) is not bool for name in (
                    "timed_out", "cancelled", "cleanup_verified", "cgroup_empty",
                    "main_pidfd_gone", "descendants_gone", "launcher_reaped", "output_complete",
                ))
                or not isinstance(terminal.terminal_receipt_handle, str)
                or not terminal.terminal_receipt_handle
                or not isinstance(terminal.cgroup_identity, str) or not terminal.cgroup_identity
                or not isinstance(terminal.process_id, str) or not terminal.process_id
                or not isinstance(terminal.stdout, bytes) or not isinstance(terminal.stderr, bytes)
                or type(terminal.stdout_size_bytes) is not int or terminal.stdout_size_bytes < 0
                or type(terminal.stderr_size_bytes) is not int or terminal.stderr_size_bytes < 0
                or len(terminal.stdout) != terminal.stdout_size_bytes
                or len(terminal.stderr) != terminal.stderr_size_bytes
                or hashlib.sha256(terminal.stdout).hexdigest() != terminal.stdout_sha256
                or hashlib.sha256(terminal.stderr).hexdigest() != terminal.stderr_sha256
                or not math.isfinite(terminal.observed_monotonic)
                or not math.isfinite(terminal.started_monotonic)
                or not math.isfinite(terminal.finished_monotonic)
                or terminal.started_monotonic > terminal.finished_monotonic
                or terminal.finished_monotonic > terminal.observed_monotonic
                or terminal.observed_monotonic > deadline_monotonic
                or terminal.finished_monotonic > deadline_monotonic):
            raise AuthorityDenied("resource.task_terminal", "task exit or cleanup proof is incomplete")
