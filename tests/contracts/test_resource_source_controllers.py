from __future__ import annotations

import pytest

from hermes_installer.authority.resource_source_controllers import (
    RootControllerRoleEnrollment,
    RootResourceEventIssuerCapability,
    RootResourceControllerRegistry,
    RootResourceSourceEventProof,
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


def test_event_issuer_attachment_is_instance_scoped_and_single_use():
    class Issuer:
        calls = 0

        def issue_source_event(self, proof, capability):
            self.calls += 1
            return object()

    registry = object.__new__(RootResourceControllerRegistry)
    registry._lock = __import__("threading").RLock()
    registry._event_issuer = None
    registry._event_issuer_capability = None
    registry.job_enrollments = {}
    registry.source_observers = type("Observers", (), {"observers": {}})()
    registry.selected_specs = {}
    issuer = Issuer()
    capability = registry.attach_event_issuer(issuer)
    assert isinstance(capability, RootResourceEventIssuerCapability)
    with pytest.raises(AuthorityDenied):
        registry.attach_event_issuer(Issuer())

    proof = RootResourceSourceEventProof(
        producer_handle="p" * 32, event_id="e" * 32,
        resource_id="resource-v1", resource_generation="a" * 64,
        source_observer_enrollment_id="observer-v1", source_kind="schedule-event",
        payload=b'{"delivery":"fixture"}', verified_provenance=object(),
        issuer_token=capability._token,
    )
    with pytest.raises(AuthorityDenied):
        registry.register_issued_event(proof, issuer=Issuer())
    assert issuer.calls == 0
    with pytest.raises(AuthorityDenied):
        registry.register_issued_event(proof, issuer=issuer)
    assert issuer.calls == 0


def test_ingress_envelope_is_canonical_and_binds_raw_observation():
    import hashlib
    import json
    from hermes_installer.authority.resource_source_controllers import _validate_ingress_envelope

    raw = b'{ "ref": "refs/heads/main" }'
    fields = {
        "schema": 1, "kind": "webhook-event", "resource_id": "repo-hook",
        "resource_generation": "a" * 64, "profile_id": "profile-main",
        "controller_proof_handle": "c" * 43, "raw_observation_handle": "r" * 43,
        "raw_payload_sha256": hashlib.sha256(raw).hexdigest(),
        "event_data": {"ref": "refs/heads/main"}, "observed_monotonic": 14.25,
        "replay_key_sha256": "b" * 64,
    }
    wire = json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("ascii")
    validated = _validate_ingress_envelope(
        wire, expected_kind="webhook-event", expected_resource_id="repo-hook",
        expected_generation="a" * 64, expected_profile_id="profile-main",
        expected_controller_handle="c" * 43, expected_raw_handle="r" * 43,
        expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
        expected_replay_sha256="b" * 64, expected_observed=14.25,
        expected_event_data=fields["event_data"],
    )
    assert validated["event_data"] == fields["event_data"]
    for bad in (
        wire + b" ",
        wire.replace(b'"replay_key_sha256":"' + b"b" * 64,
                     b'"replay_key_sha256":"' + b"c" * 64),
    ):
        with pytest.raises(AuthorityDenied):
            _validate_ingress_envelope(
                bad, expected_kind="webhook-event", expected_resource_id="repo-hook",
                expected_generation="a" * 64, expected_profile_id="profile-main",
                expected_controller_handle="c" * 43, expected_raw_handle="r" * 43,
                expected_raw_sha256=hashlib.sha256(raw).hexdigest(),
                expected_replay_sha256="b" * 64, expected_observed=14.25,
                expected_event_data=fields["event_data"],
            )


def test_ingress_envelope_rejects_duplicate_and_nonfinite_fields():
    from hermes_installer.authority.resource_source_controllers import _validate_ingress_envelope

    duplicate = (b'{"schema":1,"schema":1}')
    with pytest.raises(AuthorityDenied):
        _validate_ingress_envelope(
            duplicate, expected_kind="webhook-event", expected_resource_id="r",
            expected_generation="g", expected_profile_id="p", expected_controller_handle="c",
            expected_raw_handle="o", expected_raw_sha256="a" * 64,
            expected_replay_sha256="b" * 64, expected_observed=1.0,
            expected_event_data={},
        )
