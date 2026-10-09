from pathlib import Path
from dataclasses import replace
from types import MappingProxyType

import pytest

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.enrollment import ProtectedEnrollment, RootCredentialVault
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.runtime_composition import compose_root_authority_runtime
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.protected_enrollment import EnrollmentDenied


def _inputs():
    digest = "a" * 64
    artifact_catalog = ArtifactCatalog({}, {})
    enrollment = ProtectedEnrollment(
        key_id="test-key", bindings_by_uid={}, rules={}, policy=None,
        process_profiles={}, provider_enrollments={}, mcp_services={},
        mcp_http_bindings={}, delegations={}, memory_providers={}, native_bridges={},
        artifact_catalog={}, package_catalog={}, artifact_catalog_path=Path("/unused"),
        artifact_staging_directory=Path("/unused"), service_records=[],
        protected_devices=[], protected_build_records=[],
        protected_enrollment_digest=digest, native_package_records=[],
        memory_enrollments={}, operation_parameter_schemas=[], source_issuers=(),
        resource_job_records=(), remote_session_records=(),
        resource_backend_enrollment_records=(), resource_body_recipe_records=(),
        resource_scope_binding_records=(), resource_validator_records=(),
        root_journal_root_records=(),
    )
    uid = 1001
    binding = PrincipalBinding(
        uid=uid, principal_id="principal-a", profile_id="profile-a",
        namespace_id="namespace-a", capabilities=frozenset({"capability-a"}),
    )
    service = AuthorityService(
        signing_key=b"k" * 32, key_id="test-key", bindings_by_uid={uid: binding},
        rules={}, handlers={}, service_generation_digest=digest,
    )
    connector = object()
    process_manager = None
    observer_candidate = object()
    runtime_bindings = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None,
        process_manager=process_manager, effect_handlers={}, native_bridges={},
        artifact_catalog=artifact_catalog, build_store=None,
        service_connector=connector,
        source_observer_enrollments=MappingProxyType({"observer-a": observer_candidate}),
    )
    # The test verifies object identity and epoch wiring; it never resolves
    # credentials. The production caller passes the initialized vault made by
    # the protected root loader.
    vault = object.__new__(RootCredentialVault)
    return service, enrollment, runtime_bindings, artifact_catalog, vault, connector, observer_candidate


def test_composition_uses_exact_service_bindings_catalog_vault_and_epoch():
    service, enrollment, bindings, catalog, vault, connector, observer_candidate = _inputs()

    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )

    assert runtime.service is service
    assert runtime.enrollment is enrollment
    assert runtime.bindings is bindings
    assert runtime.artifact_catalog is catalog
    assert runtime.vault is vault
    assert runtime.boot_epoch == service.authority_epoch
    assert runtime.process_manager is service.process_effect_handler is None
    assert runtime.service_connector is connector
    assert dict(runtime.backend_enrollments) == {}
    assert dict(runtime.body_recipes) == {}
    assert dict(runtime.scope_bindings) == {}
    assert dict(runtime.validators) == {}
    assert dict(runtime.job_enrollments) == {}
    assert runtime.memory_runtime is None
    assert runtime.build_execution_service is None
    assert service.memory_step_effect_authority is None
    assert not any(operation.startswith("memory.") for operation, _target in service.handlers)
    assert runtime.source_observer_enrollments["observer-a"] is observer_candidate
    with pytest.raises(TypeError):
        runtime.source_observer_enrollments["forged"] = object()
    runtime.prune()
    runtime.close()


def test_composition_rejects_stale_artifact_catalog_identity():
    service, enrollment, bindings, _catalog, vault, _connector, _candidate = _inputs()

    with pytest.raises(AuthorityDenied, match="do not match this service epoch and catalog"):
        compose_root_authority_runtime(
            service=service, enrollment=enrollment, bindings=bindings,
            artifact_catalog=ArtifactCatalog({}, {}), vault=vault,
        )


def test_root_journal_resolution_is_bound_to_active_generation_and_protected_catalog():
    service, enrollment, bindings, catalog, vault, _connector, _candidate = _inputs()
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )

    with pytest.raises(AuthorityDenied, match="outside the active protected generation"):
        runtime.resolve_root_journal(
            "state-root", expected_active_generation_digest="b" * 64,
        )
    with pytest.raises(EnrollmentDenied, match="protected root journal catalog is unavailable"):
        runtime.resolve_root_journal(
            "state-root", expected_active_generation_digest=enrollment.protected_enrollment_digest,
        )


def test_runtime_closes_attached_observation_stores():
    service, enrollment, bindings, catalog, vault, _connector, _candidate = _inputs()
    closed = []

    class LoaderObservationStore:
        def close(self):
            closed.append(True)

    loader_store = LoaderObservationStore()
    gateway_observer = LoaderObservationStore()
    native_window_observer = LoaderObservationStore()
    service.native_loader_observation_store = loader_store
    service.gateway_boundary_observer = gateway_observer
    service.native_window_observer = native_window_observer
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )
    assert runtime.native_loader_observation_store is loader_store
    assert runtime.gateway_boundary_observer is gateway_observer
    assert runtime.native_window_observer is native_window_observer
    runtime.close()
    assert closed == [True, True, True]


def test_memory_rows_do_not_fall_back_when_protected_service_catalog_is_missing():
    service, enrollment, bindings, catalog, vault, _connector, _candidate = _inputs()
    active = replace(enrollment, memory_enrollments={("service-one", "generation-one"): object()})

    with pytest.raises(AuthorityDenied, match="active memory enrollments require the protected service catalog"):
        compose_root_authority_runtime(
            service=service, enrollment=active, bindings=bindings,
            artifact_catalog=catalog, vault=vault,
        )

    assert not any(operation.startswith("memory.") for operation, _target in service.handlers)
    assert service.memory_step_effect_authority is None
