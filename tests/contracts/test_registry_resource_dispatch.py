from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from hermes_installer.registry.resource_dispatch import (
    RootResourceDAGDispatcher,
    _stable_topological_order,
    _validate_backend_response,
)
from hermes_installer.registry.resource_jobs import ResourceJobAdmission, ResourceJobNode
from hermes_installer.authority.service import AuthorityDenied
from hermes_installer.authority.resource_source_controllers import RootResourceEventHandle
from tests.contracts.test_authority_resource_jobs import _fixture


def test_root_dispatch_executes_selected_admission_and_closes_event_after_completion():
    *_, enrollment = _fixture()
    event = RootResourceEventHandle(
        handle="event-handle", event_id="event-1", resource_id=enrollment.resource_id,
        resource_generation=enrollment.generation, source_kind="schedule-event",
        source_observer_enrollment_id="observer-1", source_receipt_ids=("source-receipt",),
        parent_closure_digest="a" * 64, payload_sha256="b" * 64,
        issued_monotonic=0.5, expires_monotonic=100.0, authority_epoch="epoch-1",
    )
    admission = ResourceJobAdmission(
        "job-1", enrollment.resource_id, enrollment.generation, enrollment.dag_sha256,
        100.0, 1, {"node-1": "child-1"},
    )
    calls = []

    class Ledger:
        active = True

        def claim_child(self, *args, **kwargs):
            assert kwargs["node_id"] == "node-1"
            assert kwargs["parent_result_receipt_ids"] == ()
            calls.append("claim")
            return SimpleNamespace(admission_id="child-1", node_id="node-1", job_id="job-1")

        def finish_child(self, child, *, result_receipt_ids, success, current_generation):
            assert result_receipt_ids == ("receipt-1",)
            assert success is True
            self.active = False
            calls.append("finish")

        def is_active(self, *_args, **_kwargs):
            return self.active

        def is_job_active(self, *_args, **_kwargs):
            return self.active

        def cancel_job(self, *_args, **_kwargs):
            self.active = False

    class Jobs:
        def __init__(self):
            self.ledger = Ledger()
            self.enrollments = {(enrollment.resource_id, enrollment.generation): enrollment}

        def is_root_admission_current(self, received_event, received_admission):
            return received_event is event and received_admission is admission

        def _resource_generation(self, _enrollment):
            return enrollment.generation

        def _event(self, _job_id, _enrollment):
            return object()

        def invoke_resource_backend(self, child, _event, timeout, cancelled):
            assert child.node_id == "node-1"
            assert timeout > 0 and not cancelled()
            calls.append("invoke")
            return {"status": 200, "body": b"ok", "headers": {}, "receipt_id": "receipt-1"}

    class Registry:
        def resolve_for_event(self, _event, _node):
            return SimpleNamespace(
                controller_kind="root-scheduler", uid=0, controller_profile_id=None,
                expires_monotonic=90.0,
                service_generation_digest="service-generation",
                pidfd=os.open(os.devnull, os.O_RDONLY),
            )

        def cancel_event(self, received_event):
            assert received_event is event
            calls.append("cancel-event")

    dispatcher = object.__new__(RootResourceDAGDispatcher)
    dispatcher.service = SimpleNamespace(monotonic=lambda: 1.0,
                                         service_generation_digest="service-generation",
                                         authority_epoch="epoch-1")
    dispatcher.jobs = Jobs()
    dispatcher.registry = Registry()
    result = dispatcher.run_admitted(event, admission)

    assert result.status == "complete"
    assert result.completed_node_ids == ("node-1",)
    assert calls == ["claim", "invoke", "finish", "cancel-event"]


def test_root_dag_order_is_stable_and_rejects_missing_dependencies_and_cycles():
    first = ResourceJobNode(
        "first", "action", "resource.cron.run", "resource:first", None,
        b"{}", request_schema_id="request", body_recipe_id="recipe",
        backend_enrollment_id="backend", result_schema_id="result", scope_binding_id="scope",
    )
    second = ResourceJobNode(
        "second", "action", "resource.cron.run", "resource:second", None,
        b"{}", request_schema_id="request", body_recipe_id="recipe",
        backend_enrollment_id="backend", result_schema_id="result", scope_binding_id="scope",
        depends_on=("first",),
    )
    assert tuple(node.node_id for node in _stable_topological_order((second, first))) == ("first", "second")

    missing = ResourceJobNode(
        "missing", "action", "resource.cron.run", "resource:missing", None,
        b"{}", request_schema_id="request", body_recipe_id="recipe",
        backend_enrollment_id="backend", result_schema_id="result", scope_binding_id="scope",
        depends_on=("absent",),
    )
    with pytest.raises(AuthorityDenied, match="missing node or cycle"):
        _stable_topological_order((missing,))
    cyclic_first = ResourceJobNode(
        "cycle-a", "action", "resource.cron.run", "resource:cycle-a", None,
        b"{}", request_schema_id="request", body_recipe_id="recipe",
        backend_enrollment_id="backend", result_schema_id="result", scope_binding_id="scope",
        depends_on=("cycle-b",),
    )
    cyclic_second = ResourceJobNode(
        "cycle-b", "action", "resource.cron.run", "resource:cycle-b", None,
        b"{}", request_schema_id="request", body_recipe_id="recipe",
        backend_enrollment_id="backend", result_schema_id="result", scope_binding_id="scope",
        depends_on=("cycle-a",),
    )
    with pytest.raises(AuthorityDenied, match="missing node or cycle"):
        _stable_topological_order((cyclic_first, cyclic_second))


def test_root_dispatch_response_is_bounded_and_requires_receipt():
    *_, enrollment = _fixture()
    node = enrollment.nodes[0]
    _validate_backend_response(
        {"status": 200, "body": b"ok", "headers": {}, "receipt_id": "receipt"},
        enrollment, node,
    )
    with pytest.raises(AuthorityDenied, match="malformed bounded result"):
        _validate_backend_response(
            {"status": 200, "body": b"ok", "headers": {}, "receipt_id": ""},
            enrollment, node,
        )


def test_root_dispatch_cancellation_before_first_node_has_no_backend_effect():
    *_, enrollment = _fixture()
    from hermes_installer.authority.resource_source_controllers import RootResourceEventHandle

    event = RootResourceEventHandle(
        handle="event-cancel", event_id="event-cancel", resource_id=enrollment.resource_id,
        resource_generation=enrollment.generation, source_kind="schedule-event",
        source_observer_enrollment_id="observer-1", source_receipt_ids=("source-receipt",),
        parent_closure_digest="c" * 64, payload_sha256="d" * 64,
        issued_monotonic=0.5, expires_monotonic=100.0, authority_epoch="epoch-1",
    )
    admission = ResourceJobAdmission(
        "job-cancel", enrollment.resource_id, enrollment.generation, enrollment.dag_sha256,
        100.0, 1, {"node-1": "child-cancel"},
    )
    effects = []

    class Ledger:
        def cancel_job(self, *_args, **_kwargs):
            effects.append("cancel-job")

        def is_job_active(self, *_args, **_kwargs):
            return False

    class Jobs:
        ledger = Ledger()
        enrollments = {(enrollment.resource_id, enrollment.generation): enrollment}

        def is_root_admission_current(self, *_args):
            return True

        def _resource_generation(self, _enrollment):
            return enrollment.generation

    class Registry:
        def cancel_event(self, _event):
            effects.append("cancel-event")

    dispatcher = object.__new__(RootResourceDAGDispatcher)
    dispatcher.service = SimpleNamespace(monotonic=lambda: 1.0,
                                         service_generation_digest="service-generation",
                                         authority_epoch="epoch-1")
    dispatcher.jobs = Jobs()
    dispatcher.registry = Registry()

    with pytest.raises(AuthorityDenied, match="cancelled or expired"):
        dispatcher.run_admitted(event, admission, cancelled=lambda: True)
    assert effects == ["cancel-job", "cancel-event"]
