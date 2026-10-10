from pathlib import Path
from dataclasses import replace
from types import MappingProxyType, SimpleNamespace
import hashlib
import json

import pytest

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.enrollment import ProtectedEnrollment, RootCredentialVault
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.runtime_composition import compose_root_authority_runtime
from hermes_installer.authority.runtime_composition import _compose_selected_resource_events
from hermes_installer.authority.runtime_composition import _root_resource_job_ledger_path
from hermes_installer.authority.runtime_composition import _native_json_schema_matches
from hermes_installer.authority.runtime_composition import _ProtectedNativeActionResolver
from hermes_installer.authority.service import AuthorityService, PrincipalBinding
from hermes_installer.authority.source_observers import SourceObserverEnrollment
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.protected_enrollment import RootJournalSelection
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
    assert runtime.provider_runtime_selection is None
    assert runtime.root_tty_consent_choices is None
    assert runtime.private_input_consent_registry is None
    assert runtime.memory_capture_consent_registry is None
    assert runtime.consent_unavailable_reason == (
        "a fully attached active provider invocation and bridge graph is required for root TTY choices"
    )
    assert runtime.source_observer_registry is None
    assert runtime.source_observer_unavailable_reason == (
        "source-observer candidates are not complete typed protected joins"
    )
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


def test_resource_job_ledger_path_comes_only_from_active_journal_selection():
    _service, enrollment, _bindings, _catalog, _vault, _connector, _candidate = _inputs()
    selected_root = Path("/private/var/lib/hermes-installer/authority-journal")
    bindings = type("JournalBindings", (), {
        "resolve_root_journal": staticmethod(lambda root_id, *, expected_active_generation_digest:
            RootJournalSelection(root_id, selected_root, 1, 2, "journal-gen",
                                 expected_active_generation_digest))
    })()

    assert _root_resource_job_ledger_path(bindings, enrollment) == (
        selected_root / "resource-jobs.sqlite3"
    )

    stale_bindings = type("StaleJournalBindings", (), {
        "resolve_root_journal": staticmethod(lambda root_id, *, expected_active_generation_digest:
            RootJournalSelection(root_id, selected_root, 1, 2, "journal-gen", "b" * 64))
    })()
    with pytest.raises(AuthorityDenied, match="selection is malformed"):
        _root_resource_job_ledger_path(stale_bindings, enrollment)


def test_resource_event_assembly_requires_the_attached_root_task_runtime():
    service, enrollment, bindings, _catalog, _vault, _connector, _candidate = _inputs()
    result = _compose_selected_resource_events(
        service=service, enrollment=enrollment, bindings=bindings,
        jobs={}, selected_resources=object(), source_observers=object(),
        job_authority=object(),
    )

    assert result[:6] == (None, None, None, None, None, None)
    assert result[6] == (
        "selected materialized Resources, source observers, or concrete task runtime are unavailable"
    )
    assert service.resource_event_context_issuer is None
    assert service.resource_task_authority is None


def test_native_action_schema_validator_enforces_pinned_finite_schema_subset():
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1, "maxLength": 12},
            "limit": {"type": "integer", "minimum": 1, "maximum": 4},
            "mode": {"type": "string", "enum": ["read", "search"]},
        },
        "required": ["query", "limit", "mode"],
        "additionalProperties": False,
    }
    assert _native_json_schema_matches(
        {"query": "status", "limit": 2, "mode": "read"}, schema,
    )
    assert not _native_json_schema_matches(
        {"query": "", "limit": 2, "mode": "read"}, schema,
    )
    assert not _native_json_schema_matches(
        {"query": "status", "limit": True, "mode": "read"}, schema,
    )
    assert not _native_json_schema_matches(
        {"query": "status", "limit": 2, "mode": "write"}, schema,
    )
    assert not _native_json_schema_matches(
        {"query": "status", "limit": 2, "mode": "read", "extra": "value"}, schema,
    )


def test_native_action_resolver_uses_exact_selected_workflow_and_schema_bytes():
    from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog

    _service, _enrollment, bindings, _catalog, _vault, _connector, _candidate = _inputs()
    schema = {
        "type": "object",
        "properties": {"query": {"type": "string", "minLength": 1, "maxLength": 8}},
        "required": ["query"], "additionalProperties": False,
    }
    schema_bytes = json.dumps(schema, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
    schema_digest = hashlib.sha256(schema_bytes).hexdigest()
    adapter = SimpleNamespace(
        adapter_id="adapter:lookup", action_id="action:lookup",
        operation="native.invoke", argument_schema_id="schema:lookup:arguments", result_schema_id="schema:lookup:result",
        workflow_bindings=(MappingProxyType({
            "external_tool_name": "search_records",
            "external_action_id": "search-records",
            "external_argument_schema_id": "schema:lookup:arguments",
            "external_result_schema_id": "schema:lookup:result",
            "workflow_artifact_id": "workflow:lookup",
            "workflow_sha256": "b" * 64,
        }),),
        adapter_artifact_id="artifact:adapter", adapter_sha256="c" * 64,
    )
    package = SimpleNamespace(
        package_id="package:native", profile_id="profile:producer", generation="generation:one",
        compiled_closure_artifact_id="artifact:closure",
        entrypoint_artifact_id="artifact:entry", entrypoint_sha256="d" * 64,
        resolver_artifact_id="artifact:resolver", resolver_sha256="e" * 64,
        adapter_records=MappingProxyType({adapter.adapter_id: adapter}),
    )
    catalog = SimpleNamespace(
        digest="a" * 64,
        resolve_profile_native_package=lambda profile_id, generation: package
        if (profile_id, generation) == (package.profile_id, package.generation) else None,
        resolve_native_package=lambda package_id, generation: package
        if (package_id, generation) == (package.package_id, package.generation) else None,
    )
    artifacts = {
        "artifact:closure": SimpleNamespace(sha256="f" * 64, tree_files=("entry.py",)),
        "artifact:entry": SimpleNamespace(sha256="d" * 64),
        "artifact:resolver": SimpleNamespace(sha256="e" * 64),
        "artifact:adapter": SimpleNamespace(sha256="c" * 64),
        "artifact:schema": SimpleNamespace(sha256=schema_digest),
        "workflow:lookup": SimpleNamespace(sha256="b" * 64),
    }
    bridge = SimpleNamespace(
        bridge_id="bridge:one", producer_profile_id=package.profile_id,
        producer_generation=package.generation,
    )
    root_bindings = replace(
        bindings, enrollment_catalog=catalog, artifact_catalog=SimpleNamespace(artifacts=artifacts),
        native_bridges={"bridge:one": bridge},
        native_schema_artifact_records=({
                "id": "schema:lookup:arguments", "artifact_id": "artifact:schema",
                "sha256": schema_digest, "size_bytes": len(schema_bytes),
                "derivation_receipt_handle": None, "schema_kind": "arguments",
            "native_package_id": package.package_id,
            "native_package_generation": package.generation,
            "adapter_id": adapter.adapter_id, "action_id": adapter.action_id,
            "source_receipt_handle": "source-receipt:lookup",
        },),
    )
    schema_records = ({
            "id": "schema:lookup:arguments", "artifact_id": "artifact:schema",
            "sha256": schema_digest, "size_bytes": len(schema_bytes),
            "derivation_receipt_handle": None, "schema_kind": "arguments",
        "native_package_id": package.package_id,
        "native_package_generation": package.generation,
        "adapter_id": adapter.adapter_id, "action_id": adapter.action_id,
        "source_receipt_handle": "source-receipt:lookup",
    },)
    schema_catalog = NativeMCPProtectedSchemaCatalog.from_protected_records(
        schema_records, read_artifact=lambda _artifact_id, _digest: schema_bytes,
        verify_source_receipt=lambda _handle, _identity: True,
    )
    assert dict(root_bindings.resolve_native_schema_record(
        schema_records[0]["id"], package.package_id, package.generation,
        adapter.adapter_id, adapter.action_id, "arguments",
    )) == dict(schema_records[0])
    schema_catalog.resolve(schema_records[0]["id"], native_package_id=package.package_id,
                           native_package_generation=package.generation,
                           adapter_id=adapter.adapter_id, action_id=adapter.action_id,
                           schema_kind="arguments")
    resolver = _ProtectedNativeActionResolver(
        root_bindings, schema_catalog, service_generation_digest=catalog.digest,
    )
    identity = SimpleNamespace(profile_id=package.profile_id, generation=package.generation)
    selected = resolver(bridge, identity, "search_records")
    assert (selected.package_id, selected.adapter_id, selected.action_id, selected.operation) == (
        package.package_id, adapter.adapter_id, adapter.action_id, adapter.operation,
    )
    assert selected.validate_arguments(b'{"query":"status"}') is True
    assert selected.validate_arguments(b'{"query":""}') is False
    with pytest.raises(AuthorityDenied, match="absent or ambiguous"):
        resolver(bridge, identity, "unselected_tool")


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
    task_observer = LoaderObservationStore()
    invocation_registry = LoaderObservationStore()
    bridge_broker = LoaderObservationStore()
    mcp_dispatcher = LoaderObservationStore()
    service.task_native_observations = task_observer
    service.native_invocation_registry = invocation_registry
    service.native_bridge_broker = bridge_broker
    service.native_mcp_dispatcher = mcp_dispatcher
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )
    assert runtime.native_loader_observation_store is loader_store
    assert runtime.gateway_boundary_observer is gateway_observer
    assert runtime.native_window_observer is native_window_observer
    assert runtime.task_native_observations is task_observer
    assert runtime.native_invocation_registry is invocation_registry
    assert runtime.native_bridge_broker is bridge_broker
    assert runtime.native_mcp_dispatcher is mcp_dispatcher
    runtime.close()
    assert closed == [True] * 7


def test_runtime_closes_remaining_stores_when_one_observer_close_fails():
    service, enrollment, bindings, catalog, vault, _connector, _candidate = _inputs()
    closed = []

    class CloseFailure:
        def close(self):
            closed.append("registry")
            raise RuntimeError("fixture close failure")

    class CloseStore:
        def close(self):
            closed.append("store")

    service.source_observer_registry = CloseFailure()
    service.native_loader_observation_store = CloseStore()
    service.native_bridge_broker = CloseStore()
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )
    with pytest.raises(RuntimeError, match="fixture close failure"):
        runtime.close()
    assert closed == ["store", "registry", "store"]


def test_source_metadata_stays_unavailable_without_real_manager_and_pair_joins():
    service, enrollment, bindings, catalog, vault, _connector, _candidate = _inputs()
    observer = SourceObserverEnrollment(
        observer_enrollment_id="observer.a",
        source_kind="native-input",
        origin_id="hermes.primary",
        profile_id="producer.profile",
        principal_id="producer.principal",
        namespace_id="producer.namespace",
        enrollment_id="producer.enrollment",
        generation="a" * 64,
        producer_uid=1001,
        producer_executable_sha256="b" * 64,
        package_id="package.a",
        package_sha256="c" * 64,
        role_id="adapter.a",
        role_artifact_id="adapter.artifact",
        role_sha256="d" * 64,
        channel_id="chat.request",
        capture_schema_id="request.schema",
        source_action_id="chat.request",
        target_id="provider.target",
        recipient="provider.recipient",
        allowed_parent_source_kinds=frozenset({"native-input"}),
    )
    bindings = replace(
        bindings,
        source_observer_enrollments=MappingProxyType({observer.observer_enrollment_id: observer}),
    )
    runtime = compose_root_authority_runtime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=catalog, vault=vault,
    )
    assert runtime.source_observer_registry is None
    assert runtime.native_loader_observation_store is None
    assert runtime.source_observer_unavailable_reason == (
        "root process manager lacks the registered native loader OpenFile custody hooks"
    )


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
