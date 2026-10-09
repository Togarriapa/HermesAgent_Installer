from pathlib import Path

import pytest

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.enrollment import ProtectedEnrollment, RootCredentialVault
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.runtime_composition import compose_root_authority_runtime
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied


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
    runtime_bindings = RootRuntimeBindings(
        enrollment_catalog=None, build_catalog=None, device_catalog=None,
        process_manager=process_manager, effect_handlers={}, native_bridges={},
        artifact_catalog=artifact_catalog, build_store=None,
        service_connector=connector,
    )
    # The test verifies object identity and epoch wiring; it never resolves
    # credentials. The production caller passes the initialized vault made by
    # the protected root loader.
    vault = object.__new__(RootCredentialVault)
    return service, enrollment, runtime_bindings, artifact_catalog, vault, connector


def test_composition_uses_exact_service_bindings_catalog_vault_and_epoch():
    service, enrollment, bindings, catalog, vault, connector = _inputs()

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
    runtime.prune()
    runtime.close()


def test_composition_rejects_stale_artifact_catalog_identity():
    service, enrollment, bindings, _catalog, vault, _connector = _inputs()

    with pytest.raises(AuthorityDenied, match="do not match this service epoch and catalog"):
        compose_root_authority_runtime(
            service=service, enrollment=enrollment, bindings=bindings,
            artifact_catalog=ArtifactCatalog({}, {}), vault=vault,
        )


def test_root_journal_resolution_is_bound_to_active_generation_and_protected_catalog():
    service, enrollment, bindings, catalog, vault, _connector = _inputs()
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )

    with pytest.raises(AuthorityDenied, match="outside the active protected generation"):
        runtime.resolve_root_journal(
            "state-root", expected_active_generation_digest="b" * 64,
        )
    with pytest.raises(AuthorityDenied, match="no protected journal resolver"):
        runtime.resolve_root_journal(
            "state-root", expected_active_generation_digest=enrollment.protected_enrollment_digest,
        )
