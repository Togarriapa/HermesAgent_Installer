from __future__ import annotations

import pytest

from hermes_installer.authority.resource_source_controllers import (
    RootControllerRoleEnrollment,
    RootResourceControllerRegistry,
    _event_fields_from_payload,
    parse_root_controller_role_records,
)
from hermes_installer.authority.types import AuthorityDenied


def _role(**changes):
    row = {
        "id": "controller-scheduler",
        "controller_kind": "root-scheduler",
        "daemon_unit_id": "hermes-installer-authority.service",
        "daemon_executable_artifact_id": "authority-executable-v1",
        "daemon_executable_sha256": "1" * 64,
        "role_module_artifact_id": "resource-scheduler-module-v1",
        "role_module_sha256": "2" * 64,
        "controller_generation": "resource-scheduler-gen-v1",
        "source_observer_enrollment_ids": ["schedule-observer-v1"],
        "allowed_backend_enrollment_ids": ["resource-backend-v1"],
        "allowed_operations": ["resource.cron.run", "resource.bundle.node.run"],
        "max_lease_seconds": 30,
    }
    return {**row, **changes}


def test_root_controller_role_parser_binds_exact_active_scope():
    catalog = parse_root_controller_role_records([_role()], generation_digest="a" * 64)
    role = catalog.get("controller-scheduler")

    assert isinstance(role, RootControllerRoleEnrollment)
    assert role.source_observer_enrollment_ids == ("schedule-observer-v1",)
    assert role.allowed_backend_enrollment_ids == ("resource-backend-v1",)
    assert role.allowed_operations == ("resource.cron.run", "resource.bundle.node.run")


@pytest.mark.parametrize("change", [
    {"controller_kind": "root-webhook"},
    {"daemon_unit_id": "authority.service; id"},
    {"daemon_executable_sha256": "not-a-digest"},
    {"source_observer_enrollment_ids": []},
    {"source_observer_enrollment_ids": ["schedule-observer-v1", "schedule-observer-v1"]},
    {"allowed_backend_enrollment_ids": []},
    {"allowed_operations": ["resource.webhook.run"]},
    {"max_lease_seconds": 601},
    {"unexpected": "not-in-schema"},
])
def test_root_controller_role_parser_rejects_scope_drift(change):
    with pytest.raises(AuthorityDenied):
        parse_root_controller_role_records([_role(**change)], generation_digest="a" * 64)


def test_root_controller_role_parser_rejects_duplicate_roles_and_oversized_catalog():
    row = _role()
    with pytest.raises(AuthorityDenied):
        parse_root_controller_role_records([row, row], generation_digest="a" * 64)
    with pytest.raises(AuthorityDenied):
        parse_root_controller_role_records([row] * 65, generation_digest="a" * 64)


def test_root_controller_join_requires_unique_observer_backend_and_operation_match():
    registry = object.__new__(RootResourceControllerRegistry)
    registry.roles = {role.id: role for role in
                      parse_root_controller_role_records([_role()], generation_digest="a" * 64).rows}
    selected = registry._select_role(
        observer_id="schedule-observer-v1", controller_kind="root-scheduler",
        backend_id="resource-backend-v1", operation="resource.cron.run",
    )
    assert selected.id == "controller-scheduler"

    with pytest.raises(AuthorityDenied):
        registry._select_role(
            observer_id="other-observer", controller_kind="root-scheduler",
            backend_id="resource-backend-v1", operation="resource.cron.run",
        )
    with pytest.raises(AuthorityDenied):
        registry._select_role(
            observer_id="schedule-observer-v1", controller_kind="root-scheduler",
            backend_id="other-backend", operation="resource.cron.run",
        )
    with pytest.raises(AuthorityDenied):
        registry._select_role(
            observer_id="schedule-observer-v1", controller_kind="root-scheduler",
            backend_id="resource-backend-v1", operation="resource.webhook.run",
        )


def test_ambiguous_active_controller_role_is_denied():
    registry = object.__new__(RootResourceControllerRegistry)
    first = _role()
    second = _role(id="controller-scheduler-secondary")
    registry.roles = {role.id: role for role in
                      parse_root_controller_role_records([first, second], generation_digest="a" * 64).rows}
    with pytest.raises(AuthorityDenied):
        registry._select_role(
            observer_id="schedule-observer-v1", controller_kind="root-scheduler",
            backend_id="resource-backend-v1", operation="resource.cron.run",
        )


def test_recipe_event_fields_are_derived_from_unambiguous_authenticated_payload():
    assert dict(_event_fields_from_payload(b'{"delivery_id":"d-1","count":2}')) == {
        "delivery_id": "d-1", "count": 2,
    }
    for payload in (
        b'{"delivery_id":"first","delivery_id":"second"}',
        b'["not", "an", "event object"]',
        b'{"count":NaN}',
        b'not json',
    ):
        with pytest.raises(AuthorityDenied):
            _event_fields_from_payload(payload)
