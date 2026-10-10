"""Digest-bound current projection tests for v124 memory service enablement."""
from dataclasses import fields, replace
from types import MappingProxyType, SimpleNamespace

import pytest

from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.protected_enrollment import (
    EnrollmentDenied,
    MemoryServiceEnablementProjection,
    ProtectedEnrollmentCatalog,
    _canonical,
)
import hashlib


def _enrollment(*, lifecycle=True, owner_generation=4):
    start = "memory-agentmemory-serve-v1"
    lifecycle_binding = (SimpleNamespace(
        start_operation_id=start,
        enablement_selection_handle="choice-handle-1",
    ) if lifecycle else None)
    return MemoryServiceEnrollment(
        target_id="memory-agentmemory:profile-one", provider="agentmemory",
        backend_variant="default", profile_id="profile-one", principal_id="principal-one",
        service_enrollment_id="service-one", source_revision="df3d4a83b966d8d415cb9180d5a4724b07f729dc",
        service_generation="service-gen-1", namespace_identity="namespace-one",
        literal_loopback_port=3111, fixed_route_map=MappingProxyType({}),
        data_root_id="memory-data-one", auth_reference_id="memory-auth-one",
        fixed_project_account_user_scope=MappingProxyType({}),
        authority_state_root_id="installer-authority-journal-v1",
        memory_owner_generation=owner_generation,
        private_extraction_embedding_routes=MappingProxyType({}),
        background_consent_revision="capture-consent-v1", limits=MappingProxyType({}),
        lifecycle_binding=lifecycle_binding,
    )


def _row(**overrides):
    row = {
        "selection_handle": "choice-handle-1",
        "choice_observation_id": "tty-observation-1",
        "principal_id": "principal-one",
        "profile_id": "profile-one",
        "namespace_id": "namespace-one",
        "provider": "agentmemory",
        "backend_variant": "default",
        "service_enrollment_id": "service-one",
        "service_generation": "service-gen-1",
        "memory_owner_generation": 4,
        "start_operation_id": "memory-agentmemory-serve-v1",
        "policy_revision": "memory-service-policy-v1",
        "selection_digest": "",
        "state": "enabled",
        "revocation_epoch": 1,
    }
    row.update(overrides)
    row["selection_digest"] = ""
    row["selection_digest"] = hashlib.sha256(
        _canonical({key: value for key, value in row.items() if key != "selection_digest"})
    ).hexdigest()
    return row


def _catalog(row=None, enrollment=None):
    selected = enrollment or _enrollment()
    service = SimpleNamespace(
        profile_id=selected.profile_id, principal_id=selected.principal_id,
        generation=selected.service_generation, namespace_identity=selected.namespace_identity,
    )
    rows = [] if row is None else [row]
    return ProtectedEnrollmentCatalog(
        {("service-one", "service-gen-1"): service}, digest="a" * 64,
        memory_enrollments={("service-one", "service-gen-1"): selected},
        memory_service_enablement_projections=rows,
    ), selected


def test_current_enablement_projection_is_exact_digest_bound_and_joined():
    catalog, enrollment = _catalog(_row())
    resolved = catalog.resolve_current_memory_service_enablement_selection(
        enrollment, service_generation_digest="a" * 64)
    assert type(resolved) is MappingProxyType
    assert set(resolved) == MemoryServiceEnablementProjection._FIELDS
    assert resolved["selection_handle"] == enrollment.lifecycle_binding.enablement_selection_handle
    assert resolved["start_operation_id"] == enrollment.lifecycle_binding.start_operation_id


@pytest.mark.parametrize("field,value", [
    ("principal_id", "other-principal"),
    ("profile_id", "other-profile"),
    ("namespace_id", "other-namespace"),
    ("provider", "openviking"),
    ("backend_variant", "other-variant"),
    ("service_enrollment_id", "other-service"),
    ("service_generation", "old-generation"),
    ("memory_owner_generation", 5),
    ("start_operation_id", "other-start-recipe"),
    ("selection_handle", "other-choice"),
])
def test_projection_rejects_mismatched_active_enrollment_fields(field, value):
    with pytest.raises(EnrollmentDenied):
        _catalog(_row(**{field: value}))


def test_disabled_or_revoked_projection_never_resolves_as_current():
    for state in ("disabled", "revoked"):
        catalog, enrollment = _catalog(_row(state=state, revocation_epoch=2))
        with pytest.raises(EnrollmentDenied, match="disabled or revoked"):
            catalog.resolve_current_memory_service_enablement_selection(
                enrollment, service_generation_digest="a" * 64)


def test_projection_lookup_denies_missing_stale_untyped_and_replaced_enrollment():
    catalog, enrollment = _catalog()
    with pytest.raises(EnrollmentDenied, match="projection is absent"):
        catalog.resolve_current_memory_service_enablement_selection(
            enrollment, service_generation_digest="a" * 64)
    catalog, enrollment = _catalog(_row())
    with pytest.raises(EnrollmentDenied, match="stale or untyped"):
        catalog.resolve_current_memory_service_enablement_selection(
            enrollment, service_generation_digest="b" * 64)
    with pytest.raises(EnrollmentDenied, match="stale or untyped"):
        catalog.resolve_current_memory_service_enablement_selection(
            SimpleNamespace(**{item.name: getattr(enrollment, item.name)
                               for item in fields(enrollment)}),
            service_generation_digest="a" * 64)
    replaced = replace(enrollment)
    with pytest.raises(EnrollmentDenied, match="not the active catalog object"):
        catalog.resolve_current_memory_service_enablement_selection(
            replaced, service_generation_digest="a" * 64)


def test_projection_digest_duplicate_and_missing_lifecycle_handle_are_denied():
    bad = _row()
    bad["state"] = "revoked"
    with pytest.raises(EnrollmentDenied, match="digest is invalid"):
        MemoryServiceEnablementProjection.from_protected_record(bad)
    row = _row()
    with pytest.raises(EnrollmentDenied, match="duplicated"):
        ProtectedEnrollmentCatalog(
            {("service-one", "service-gen-1"): SimpleNamespace(
                profile_id="profile-one", principal_id="principal-one", generation="service-gen-1",
                namespace_identity="namespace-one")}, digest="a" * 64,
            memory_enrollments={("service-one", "service-gen-1"): _enrollment()},
            memory_service_enablement_projections=[row, dict(row)],
        )
    missing = _enrollment(lifecycle=False)
    with pytest.raises(EnrollmentDenied, match="active owner, service, or start recipe"):
        _catalog(_row(), missing)
