"""Root-owned execution of a protected Resources DAG admission.

This module is called only by selected root producers after they have captured
an authenticated source event. It never accepts worker identity, action,
endpoint, profile, or event data. The event registry, job authority, durable
ledger, and selected backend rows remain the authorities for those values.
"""
from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hermes_installer.authority.resource_jobs import ResourceJobAuthority
from hermes_installer.authority.resource_source_controllers import (
    RootResourceControllerRegistry,
    RootResourceEventHandle,
)
from hermes_installer.authority.service import AuthorityDenied, AuthorityService
from hermes_installer.registry.resource_jobs import (
    ResourceJobAdmission,
    ResourceJobDenied,
    ResourceJobEnrollment,
    ResourceJobNode,
)


@dataclass(frozen=True, slots=True)
class ResourceJobExecutionSummary:
    """Bounded root-side status; never includes task output or source bytes."""

    job_id: str
    resource_id: str
    resource_generation: str
    dag_sha256: str
    status: str
    completed_node_ids: tuple[str, ...]
    failed_node_id: str | None
    expires_monotonic: float


class RootResourceDAGDispatcher:
    """Admit and execute one root-captured job in stable DAG order.

    Profile-task nodes are launched only through ``ResourceJobAuthority``'s
    root-owned backend path and the attached ``RootResourceTaskRunner``. A
    non-profile node must have its exact artifact-bound backend handler in the
    AuthorityService. Each node gets a fresh durable child admission; retries
    are permitted only while the child is still in the pre-effect admitted
    state. A running or ambiguous effect is never retried.
    """

    def __init__(self, *, service: AuthorityService,
                 job_authority: ResourceJobAuthority,
                 controller_registry: RootResourceControllerRegistry):
        if (type(service) is not AuthorityService
                or type(job_authority) is not ResourceJobAuthority
                or job_authority.service is not service
                or type(controller_registry) is not RootResourceControllerRegistry
                or controller_registry.service is not service
                or getattr(service, "resource_job_authority", None) is not job_authority
                or getattr(getattr(service, "resource_event_context_issuer", None),
                           "controller_registry", None) is not controller_registry):
            raise AuthorityDenied("resource.dispatch", "root job, issuer, and controller graph is not attached")
        self.service = service
        self.jobs = job_authority
        self.registry = controller_registry

    def run_event(self, event: RootResourceEventHandle, *, timeout: float = 600.0,
                  cancelled: Callable[[], bool] = lambda: False) -> ResourceJobExecutionSummary:
        """Durably admit exactly this root event, then execute its selected DAG."""
        if (type(event) is not RootResourceEventHandle
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0.1 <= timeout <= 600
                or not callable(cancelled)):
            raise AuthorityDenied("resource.dispatch", "root event dispatch request is malformed")
        admission = self.jobs.admit_root_resource_event(
            event, timeout=timeout, cancelled=cancelled,
        )
        return self.run_admitted(event, admission, timeout=timeout, cancelled=cancelled)

    def run_admitted(self, event: RootResourceEventHandle, admission: ResourceJobAdmission, *,
                     timeout: float = 600.0,
                     cancelled: Callable[[], bool] = lambda: False) -> ResourceJobExecutionSummary:
        """Execute only the identical retained event/admission pair."""
        if (type(event) is not RootResourceEventHandle
                or not isinstance(admission, ResourceJobAdmission)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0.1 <= timeout <= 600
                or not callable(cancelled)
                or not self.jobs.is_root_admission_current(event, admission)):
            raise AuthorityDenied("resource.dispatch", "root event admission is stale or unbound")
        enrollment = self.jobs.enrollments.get((admission.resource_id, admission.generation))
        if (not isinstance(enrollment, ResourceJobEnrollment)
                or admission.approved_dag_sha256 != enrollment.dag_sha256
                or admission.resource_id != event.resource_id
                or admission.generation != event.resource_generation):
            raise AuthorityDenied("resource.dispatch", "admission differs from the active protected DAG")
        order = _stable_topological_order(enrollment.nodes)
        completed: list[str] = []
        deadline = min(
            admission.expires_monotonic,
            self.service.monotonic() + min(float(timeout), enrollment.max_runtime_seconds),
        )
        failed_node: str | None = None
        try:
            for node in order:
                if cancelled() or self.service.monotonic() >= deadline:
                    raise AuthorityDenied("resource.cancelled", "root resource DAG was cancelled or expired")
                if not self.jobs.is_root_admission_current(event, admission):
                    raise AuthorityDenied("resource.selection", "resource generation or source closure changed")
                current_generation = self.jobs._resource_generation(enrollment)
                if current_generation != enrollment.generation:
                    raise AuthorityDenied("resource.selection", "selected resource generation was revoked")
                self._require_live_controller(event, node.node_id)
                parent_receipts = self._completed_parent_receipts(admission, enrollment, node)
                event_state = self.jobs._event(admission.job_id, enrollment)
                child_id = admission.child_admission_ids.get(node.node_id)
                if not isinstance(child_id, str) or not child_id:
                    raise AuthorityDenied("resource.child", "selected DAG node has no durable child admission")
                failure: BaseException | None = None
                node_succeeded = False
                for attempt in range(node.maximum_attempts):
                    if cancelled() or not self.jobs.is_root_admission_current(event, admission):
                        raise AuthorityDenied("resource.cancelled", "root resource DAG was revoked before child dispatch")
                    try:
                        child = self.jobs.ledger.claim_child(
                            admission, enrollment, node_id=node.node_id,
                            child_admission_id=child_id,
                            parent_result_receipt_ids=parent_receipts,
                            current_generation=current_generation,
                        )
                    except ResourceJobDenied as exc:
                        raise AuthorityDenied("resource.child", "selected child is not currently ready") from exc
                    try:
                        # Recreate the event snapshot after each prior node so
                        # only root-retained result capsules can feed recipes.
                        event_state = self.jobs._event(admission.job_id, enrollment)
                        self._require_live_controller(event, node.node_id)
                        response = self.jobs.invoke_resource_backend(
                            child, event_state,
                            timeout=max(0.1, min(deadline - self.service.monotonic(),
                                                 enrollment.max_runtime_seconds)),
                            cancelled=lambda: cancelled() or not self.jobs.ledger.is_active(
                                child, current_generation=self.jobs._resource_generation(enrollment)),
                        )
                        _validate_backend_response(response, enrollment, node)
                        successful = 200 <= response["status"] < 400
                        stored = False
                        if successful and "result_fields" in response:
                            backend = enrollment.backends[node.backend_enrollment_id]
                            self.jobs._store_result_fields(
                                child, response["receipt_id"], response["result_fields"],
                                expires=admission.expires_monotonic,
                                maximum_bytes=backend.maximum_response_bytes,
                            )
                            stored = True
                        try:
                            self.jobs.ledger.finish_child(
                                child, result_receipt_ids=(response["receipt_id"],),
                                success=successful,
                                current_generation=self.jobs._resource_generation(enrollment),
                            )
                        except Exception:
                            if stored:
                                self.jobs._discard_result_fields(admission.job_id, node.node_id)
                            raise
                        if not successful:
                            raise AuthorityDenied("resource.effect", "selected resource node returned a failed status")
                        node_succeeded = True
                        completed.append(node.node_id)
                        break
                    except Exception as exc:
                        failure = exc
                        # Retry only if the effect has not crossed the ledger's
                        # admitted -> running boundary. Once started, its remote
                        # outcome can be ambiguous and is terminal.
                        if self.jobs.ledger.is_child_admitted(
                                child, current_generation=self.jobs._resource_generation(enrollment)):
                            try:
                                self.jobs.ledger.fail_child_admission(
                                    child, current_generation=self.jobs._resource_generation(enrollment),
                                )
                            except ResourceJobDenied:
                                pass
                            if (attempt + 1 < node.maximum_attempts and not cancelled()
                                    and self.jobs.is_root_admission_current(event, admission)):
                                child_id = child.admission_id
                                continue
                            self.jobs.ledger.fail_node(admission.job_id, node.node_id)
                        elif self.jobs.ledger.is_active(
                                child, current_generation=self.jobs._resource_generation(enrollment)):
                            try:
                                self.jobs.ledger.finish_child(
                                    child, result_receipt_ids=(), success=False,
                                    current_generation=self.jobs._resource_generation(enrollment),
                                )
                            except ResourceJobDenied:
                                pass
                        break
                if not node_succeeded:
                    failed_node = node.node_id
                    if cancelled():
                        self.jobs.ledger.cancel_job(
                            admission.job_id,
                            current_generation=self.jobs._resource_generation(enrollment),
                        )
                        return self._summary(admission, enrollment, "cancelled", completed, failed_node)
                    # The child transition already closed transitive descendants.
                    # Keep a concise failure receipt; exceptions and backend
                    # output never escape to scheduler logs.
                    _ = failure
                    return self._summary(admission, enrollment, "failed", completed, failed_node)
            return self._summary(admission, enrollment, "complete", completed, None)
        except Exception:
            self.jobs.ledger.cancel_job(
                admission.job_id,
                current_generation=self.jobs._resource_generation(enrollment),
            )
            raise
        finally:
            if failed_node is not None or not self.jobs.ledger.is_job_active(
                    admission.job_id,
                    current_generation=self.jobs._resource_generation(enrollment)):
                try:
                    self.registry.cancel_event(event)
                except Exception:
                    pass

    def _require_live_controller(self, event: RootResourceEventHandle, node_id: str) -> None:
        controller = None
        try:
            controller = self.registry.resolve_for_event(event, node_id)
            if (controller.controller_kind not in {"root-scheduler", "root-webhook", "root-channel"}
                    or controller.uid != 0 or controller.controller_profile_id is not None
                    or controller.expires_monotonic <= self.service.monotonic()
                    or controller.service_generation_digest != self.service.service_generation_digest):
                raise AuthorityDenied("resource.controller", "root controller proof is stale")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("resource.controller", "selected root controller is unavailable") from None
        finally:
            if controller is not None:
                try:
                    os.close(controller.pidfd)
                except OSError:
                    pass

    def _completed_parent_receipts(self, admission: ResourceJobAdmission,
                                   enrollment: ResourceJobEnrollment,
                                   node: ResourceJobNode) -> tuple[str, ...]:
        receipts: set[str] = set()
        for parent in node.depends_on:
            try:
                _child_id, _attempt, values = self.jobs.ledger.completed_node_result_receipts(
                    admission.job_id, parent, current_generation=enrollment.generation,
                )
            except ResourceJobDenied as exc:
                raise AuthorityDenied("resource.result_closure", "selected DAG prerequisite has no current result") from exc
            receipts.update(values)
        return tuple(sorted(receipts))

    @staticmethod
    def _summary(admission: ResourceJobAdmission, enrollment: ResourceJobEnrollment,
                 status: str, completed: list[str], failed_node: str | None) -> ResourceJobExecutionSummary:
        return ResourceJobExecutionSummary(
            admission.job_id, enrollment.resource_id, enrollment.generation,
            enrollment.dag_sha256, status, tuple(completed), failed_node,
            admission.expires_monotonic,
        )


def _stable_topological_order(nodes: tuple[ResourceJobNode, ...]) -> tuple[ResourceJobNode, ...]:
    """Return stable root-selected order and recheck a DAG before any effect."""
    if (not isinstance(nodes, tuple) or not nodes
            or any(not isinstance(node, ResourceJobNode) for node in nodes)):
        raise AuthorityDenied("resource.dag", "selected root DAG is empty or malformed")
    by_id = {node.node_id: node for node in nodes}
    if len(by_id) != len(nodes):
        raise AuthorityDenied("resource.dag", "selected root DAG has duplicate nodes")
    order_index = {node.node_id: index for index, node in enumerate(nodes)}
    pending = set(by_id)
    emitted: set[str] = set()
    result: list[ResourceJobNode] = []
    while pending:
        ready = sorted(
            (node_id for node_id in pending if set(by_id[node_id].depends_on) <= emitted),
            key=order_index.__getitem__,
        )
        if not ready:
            raise AuthorityDenied("resource.dag", "selected root DAG has a missing node or cycle")
        for node_id in ready:
            result.append(by_id[node_id])
            pending.remove(node_id)
            emitted.add(node_id)
    return tuple(result)


def _validate_backend_response(response: Any, enrollment: ResourceJobEnrollment,
                               node: ResourceJobNode) -> None:
    backend = enrollment.backends.get(node.backend_enrollment_id)
    fields = {"status", "body", "headers", "receipt_id"}
    if isinstance(response, Mapping) and "result_fields" in response:
        fields.add("result_fields")
    if (not isinstance(backend, object) or not isinstance(response, Mapping)
            or set(response) != fields or type(response.get("status")) is not int
            or not 0 <= response["status"] <= 599
            or not isinstance(response.get("body"), bytes)
            or len(response["body"]) > backend.maximum_response_bytes
            or not isinstance(response.get("headers"), Mapping)
            or not isinstance(response.get("receipt_id"), str)
            or not response["receipt_id"]
            or "result_fields" in response and not isinstance(response["result_fields"], Mapping)):
        raise AuthorityDenied("resource.effect", "selected node returned a malformed bounded result")
