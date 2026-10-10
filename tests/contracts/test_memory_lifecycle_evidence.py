"""Positive and fail-closed tests for root memory lifecycle source evidence."""
from __future__ import annotations

import hashlib
import os
from dataclasses import replace
from pathlib import Path
from types import MappingProxyType, SimpleNamespace

import pytest

from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec
from hermes_installer.authority.memory_lifecycle_evidence import (
    RootMemoryEvidenceDenied,
    RootMemoryPrestartReceiptRegistry,
    RootMemorySemanticReadinessRegistry,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.memory.enrollment import MemoryLifecycleBinding, MemoryServiceEnrollment
from hermes_installer.protected_enrollment import (
    OperationLaunchRecipe, RootJournalSelection,
)


def _root_runtime(tmp_path: Path):
    if os.geteuid() != 0:
        pytest.skip("root source-custody fixture runs in the controlled Linux container")
    data = b"pinned-engine-bytes"
    sha = hashlib.sha256(data).hexdigest()
    artifact_root = tmp_path / "artifact-store"
    object_path = artifact_root / "objects" / "engine-artifact" / sha / "engine.whl"
    object_path.parent.mkdir(parents=True)
    object_path.write_bytes(data)
    object_path.chmod(0o400)
    artifact_root.chmod(0o700)
    catalog = ArtifactCatalog.from_records((ArtifactSpec(
        artifact_id="engine-artifact", version="1.0", sha256=sha,
        source_url="https://example.invalid/engine.whl", max_bytes=1024,
        size_bytes=len(data), filename="engine.whl",
    ),))
    receipt_handles = ("package-receipt", "engine-receipt")
    lifecycle = MemoryLifecycleBinding(
        service_enrollment_id="service-1", service_generation="generation-1",
        start_operation_id="memory-openviking-serve-v1",
        start_parameter_schema_id="no-caller-parameters-v1",
        prestart_receipt_handles=receipt_handles,
        readiness_route_id="openviking-ready", readiness_schema_id="ready-schema",
        restart_policy="manual-owned-restart", maximum_restart_attempts=0,
        original_deadline_seconds=60,
    )
    enrollment = MemoryServiceEnrollment(
        target_id="memory-openviking:profile-1", provider="openviking",
        backend_variant="default", profile_id="profile-1", principal_id="principal-1",
        service_enrollment_id="service-1", source_revision="e7b2e974b1fb97cd8c6087ff013181ddfec94f77",
        service_generation="generation-1", namespace_identity="namespace-1",
        literal_loopback_port=1933, fixed_route_map={}, data_root_id="data-1",
        auth_reference_id="auth-1", fixed_project_account_user_scope={},
        authority_state_root_id="state-1", memory_owner_generation=1,
        private_extraction_embedding_routes={}, background_consent_revision="consent-rev-1",
        limits={}, lifecycle_binding=lifecycle,
    )
    operation = OperationLaunchRecipe(
        operation_id=lifecycle.start_operation_id,
        executable_artifact_id="engine-artifact", executable_sha256=sha,
        argv_recipe=(), cwd_root_id="work-1", cwd_subpath=".", environment={},
        child_artifact_refs={}, max_lifetime_seconds=60, max_output_bytes=4096,
        stdin_mode="closed", parameter_schema_id="no-caller-parameters-v1",
    )
    service = SimpleNamespace(
        enrollment_id="service-1", generation="generation-1", profile_id="profile-1",
        principal_id="principal-1", service_uid=0, service_gid=0,
        operation_recipes={lifecycle.start_operation_id: operation},
    )

    class Catalog:
        digest = "a" * 64

        def resolve_memory_enrollment(self, selected, *, service_generation_digest):
            assert selected == enrollment.target_id
            assert service_generation_digest == self.digest
            return enrollment

        def resolve_current_memory_service_enablement_selection(
                self, selected_enrollment, *, service_generation_digest):
            assert selected_enrollment == enrollment
            assert service_generation_digest == self.digest
            return MappingProxyType({
                "selection_handle": "lifecycle-enable-1",
                "choice_observation_id": "root-tty-choice-1",
                "principal_id": enrollment.principal_id,
                "profile_id": enrollment.profile_id,
                "namespace_id": enrollment.namespace_identity,
                "provider": enrollment.provider,
                "backend_variant": enrollment.backend_variant,
                "service_enrollment_id": enrollment.service_enrollment_id,
                "service_generation": enrollment.service_generation,
                "memory_owner_generation": enrollment.memory_owner_generation,
                "start_operation_id": lifecycle.start_operation_id,
                "policy_revision": "policy-v1",
                "selection_digest": "b" * 64,
                "state": "enabled",
                "revocation_epoch": 0,
            })

        def resolve(self, selected, generation):
            assert (selected, generation) == ("service-1", "generation-1")
            return service

        def resolve_launch_recipe(self, selected, generation, operation_id):
            assert operation_id == lifecycle.start_operation_id
            return SimpleNamespace(
                profile_id="profile-1", service_uid=0, recipe=operation,
                parameter_schema=SimpleNamespace(fields={}),
            )

    custody = object()
    managed = SimpleNamespace(
        enrollment_id="service-1", generation="generation-1", profile_id="profile-1",
        owner_uid=0, owner_gid=0, artifact_root=artifact_root,
        child_artifact_refs={},
    )
    journal_path = tmp_path / "authority-journal"
    journal_path.mkdir(mode=0o700)
    journal = RootJournalSelection(
        root_id="installer-authority-journal-v1", path=journal_path,
        device=journal_path.stat().st_dev, inode=journal_path.stat().st_ino,
        generation="generation-1", service_generation_digest=Catalog.digest,
    )
    root_catalog = SimpleNamespace(resolve=lambda root_id, *, expected_active_generation_digest:
                                   journal if root_id == journal.root_id
                                   and expected_active_generation_digest == Catalog.digest else None)
    bindings = RootRuntimeBindings(
        enrollment_catalog=Catalog(), build_catalog=None, device_catalog=None,
        process_manager=custody, effect_handlers={}, native_bridges={},
        artifact_catalog=catalog, build_store=None, service_connector=None,
        process_profiles={"profile-1": managed}, root_journal_catalog=root_catalog,
    )
    return bindings, catalog, custody, journal, enrollment, object_path, receipt_handles


def test_root_prestart_registry_reopens_current_catalog_bytes_and_binds_active_handles(tmp_path):
    bindings, catalog, custody, journal, enrollment, artifact, receipt_handles = _root_runtime(tmp_path)
    registry = RootMemoryPrestartReceiptRegistry.from_root_runtime(
        bindings, catalog, custody, journal,
    )
    handle = registry.observe_selected_prestart(enrollment.target_id)
    receipt = registry.resolve_selected_prestart(handle, enrollment.target_id)
    recovered_registry = RootMemoryPrestartReceiptRegistry.from_root_runtime(
        bindings, catalog, custody, journal,
    )
    recovered = recovered_registry.resolve_selected_prestart(handle, enrollment.target_id)
    assert recovered.source_closure_sha256 == receipt.source_closure_sha256
    assert receipt.is_current()
    assert receipt.provider == "openviking"
    assert receipt.artifact_records[0]["artifact_id"] == "engine-artifact"
    assert receipt.artifact_records[0]["sha256"] == hashlib.sha256(b"pinned-engine-bytes").hexdigest()
    assert registry.resolve_memory_prestart_closure(
        enrollment, receipt_handles, service_generation_digest=bindings.service_generation_digest,
    ) is receipt

    artifact.chmod(0o600)
    artifact.write_bytes(b"replaced-engine-bytes")
    artifact.chmod(0o400)
    assert not receipt.is_current()
    with pytest.raises(RootMemoryEvidenceDenied, match="stale"):
        registry.resolve_selected_prestart(handle, enrollment.target_id)


def test_root_prestart_registry_rejects_unretained_handle_and_foreign_enrollment(tmp_path):
    bindings, catalog, custody, journal, enrollment, _artifact, _handles = _root_runtime(tmp_path)
    registry = RootMemoryPrestartReceiptRegistry.from_root_runtime(
        bindings, catalog, custody, journal,
    )
    with pytest.raises(RootMemoryEvidenceDenied, match="retained prestart receipt"):
        registry.resolve_selected_prestart("package-receipt", enrollment.target_id)
    handle = registry.observe_selected_prestart(enrollment.target_id)
    with pytest.raises(RootMemoryEvidenceDenied, match="retained prestart receipt"):
        registry.resolve_selected_prestart(handle, "memory-openviking:other-profile")


def test_root_prestart_registry_fails_closed_without_current_enablement_choice(tmp_path):
    bindings, catalog, custody, journal, enrollment, _artifact, _handles = _root_runtime(tmp_path)
    bindings.enrollment_catalog.resolve_current_memory_service_enablement_selection = (
        lambda *_args, **_kwargs: None)
    registry = RootMemoryPrestartReceiptRegistry.from_root_runtime(
        bindings, catalog, custody, journal,
    )
    with pytest.raises(RootMemoryEvidenceDenied, match="enablement selection"):
        registry.observe_selected_prestart(enrollment.target_id)


def test_root_prestart_receipt_currentness_tracks_enablement_revocation_epoch(tmp_path):
    bindings, catalog, custody, journal, enrollment, _artifact, _handles = _root_runtime(tmp_path)
    registry = RootMemoryPrestartReceiptRegistry.from_root_runtime(
        bindings, catalog, custody, journal,
    )
    handle = registry.observe_selected_prestart(enrollment.target_id)
    receipt = registry.resolve_selected_prestart(handle, enrollment.target_id)
    assert receipt.is_current()

    resolver = bindings.enrollment_catalog.resolve_current_memory_service_enablement_selection
    revoked = dict(resolver(enrollment, service_generation_digest=bindings.service_generation_digest))
    revoked["revocation_epoch"] = 1
    bindings.enrollment_catalog.resolve_current_memory_service_enablement_selection = (
        lambda *_args, **_kwargs: MappingProxyType(revoked))
    assert not receipt.is_current()


def test_semantic_probe_is_fixed_to_validated_provider_search_not_health_route(tmp_path):
    _bindings, _catalog, _custody, _journal, enrollment, _artifact, _handles = _root_runtime(tmp_path)
    step = SimpleNamespace(step_id="find", body_recipe_id="openviking-find-owned-v1")
    recipe = SimpleNamespace(backend_variant="default", steps=(step,))
    selected = replace(enrollment, fixed_route_map={"openviking-find": recipe})
    route_id, step_id, _body_recipe_id, selected_recipe = (
        RootMemorySemanticReadinessRegistry.selected_semantic_recipe(selected))
    assert (route_id, step_id, selected_recipe[1]) == ("openviking-find", "find", step)

    unsupported = replace(enrollment, provider="claude-mem", backend_variant="worker-observation")
    with pytest.raises(RootMemoryEvidenceDenied, match="no reviewed semantic probe"):
        RootMemorySemanticReadinessRegistry.selected_semantic_recipe(unsupported)
