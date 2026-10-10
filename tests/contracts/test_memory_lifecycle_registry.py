"""Contract tests for strict root memory lifecycle admission."""
from __future__ import annotations

import pytest

from hermes_installer.authority.memory_lifecycle_registry import (
    RootMemoryLifecycleRegistry,
    RootMemoryLifecycleRegistryDenied,
)
from hermes_installer.authority.runtime_bindings import _parse_private_memory_engine_selections
from hermes_installer.protected_enrollment import EnrollmentDenied
from hermes_installer.memory.lifecycle_authority import RootMemoryServiceLifecycle


def _lifecycle() -> RootMemoryServiceLifecycle:
    class Authority:
        def issue_root_selected_service_effect(self, *args, **kwargs):
            raise AssertionError("no effect is permitted in a construction test")

        def consume_root_selected_service_effect(self, *args, **kwargs):
            raise AssertionError("no effect is permitted in a construction test")

    class Custody:
        def perform_root_selected_service_effect(self, *args, **kwargs):
            raise AssertionError("no effect is permitted in a construction test")

    return RootMemoryServiceLifecycle(authority_service=Authority(), custody=Custody())


def _selection() -> dict[str, object]:
    return {
        "id": "private-memory-selection-1",
        "profile_id": "profile-1",
        "namespace_id": "memory-namespace-1",
        "memory_provider": "openviking",
        "memory_owner_generation": 1,
        "extract_route_id": "private-text-route",
        "embed_route_id": "private-embedding-route",
        "extraction_served_model_id": "private-glm-text-v1",
        "embedding_served_model_id": "private-embedding-v1",
        "embedding_dimensions": 1024,
        "endpoint_selection_receipt_handle": "endpoint-receipt-1",
        "extraction_model_deployment_receipt_handle": "extract-deployment-1",
        "embedding_model_deployment_receipt_handle": "embed-deployment-1",
        "protocol_artifact_id": "installer-private-memory-compatible-api-v1",
        "protocol_sha256": "a" * 64,
        "credential_reference_ids": ["private-memory-credential-1"],
        "private_consent_selection_handle": "private-selection-consent-1",
        "policy_revision": "private-memory-policy-1",
    }


def test_active_private_memory_selection_is_frozen_and_preserves_two_model_slots() -> None:
    rows = _parse_private_memory_engine_selections([_selection()])
    assert tuple(rows) == ("private-memory-selection-1",)
    row = rows["private-memory-selection-1"]
    assert row["extraction_served_model_id"] != row["embedding_served_model_id"]
    assert row["credential_reference_ids"] == ("private-memory-credential-1",)
    with pytest.raises(TypeError):
        row["policy_revision"] = "caller-mutated"  # type: ignore[index]


@pytest.mark.parametrize("mutation", [
    lambda row: row.pop("embedding_model_deployment_receipt_handle"),
    lambda row: row.update(memory_owner_generation=True),
    lambda row: row.update(protocol_sha256="not-a-digest"),
    lambda row: row.update(credential_reference_ids=["duplicate", "duplicate"]),
])
def test_private_memory_selection_rejects_incomplete_or_ambiguous_rows(mutation) -> None:
    value = _selection()
    mutation(value)
    with pytest.raises(EnrollmentDenied):
        _parse_private_memory_engine_selections([value])


def test_lifecycle_registry_requires_distinct_public_consent_and_evidence_ports() -> None:
    class Bindings:
        enrollment_catalog = type("Catalog", (), {"digest": "b" * 64})()

        def resolve_memory_enrollment(self, *args, **kwargs):
            raise AssertionError("admission is not attempted")

    class Source:
        def resolve_memory_prestart_closure(self, *args, **kwargs):
            raise AssertionError("admission is not attempted")

    class Controller:
        def resolve_memory_controller_proof(self, *args, **kwargs):
            raise AssertionError("admission is not attempted")

    class Routes:
        def resolve_selected_memory_engine(self, *args, **kwargs):
            raise AssertionError("admission is not attempted")

        def is_current(self, *args, **kwargs):
            return False

    class Connector:
        def probe_selected_readiness(self, *args, **kwargs):
            raise AssertionError("admission is not attempted")

    with pytest.raises(RootMemoryLifecycleRegistryDenied, match="evidence registries"):
        RootMemoryLifecycleRegistry.from_root_runtime(
            active_bindings=Bindings(), lifecycle=_lifecycle(),
            source_receipt_registry=Source(),
            # Capture-consent alone has no lifecycle-start resolver and is denied.
            lifecycle_consent_registry=object(),
            controller_proof_resolver=Controller(), private_route_resolver=Routes(),
            connector_registry=Connector(),
        )


def test_fresh_control_admission_is_bound_to_retained_process_and_original_deadline() -> None:
    """Controlled Linux contract fixture for SK-T145 fresh process controls."""
    import os
    import sys
    import time
    from dataclasses import replace
    from types import SimpleNamespace

    import pytest
    from hermes_installer.authority.memory_lifecycle_registry import (
        RootMemoryLifecycleRegistry,
    )
    from hermes_installer.authority.memory_lifecycle_evidence import _managed_identity_digest
    from hermes_installer.authority.selected_startup_authority import RootControllerProcessIdentityLease
    from hermes_installer.managed_process_custodian import RootSelectedServiceProcessReceipt
    from hermes_installer.memory.lifecycle_authority import (
        MemorySelectedLifecycleActionBinding, RootVerifiedMemoryLifecycleAdmission,
    )
    from test_memory_lifecycle_authority import FakeCatalog, enrolled_agentmemory
    from test_selected_startup_authority import _current_identity

    if not (sys.platform.startswith("linux") and hasattr(os, "pidfd_open") and os.geteuid() == 0):
        pytest.skip("requires the controlled Linux root PIDFD fixture")

    clock = [time.monotonic()]
    enrollment = enrolled_agentmemory()
    digest = "d" * 64
    handles = enrollment.lifecycle_binding.prestart_receipt_handles
    source = SimpleNamespace(
        source_closure_sha256="e" * 64, receipt_handles=handles,
        enablement_selection_handle="enablement-handle", expires_monotonic=clock[0] + 90,
        is_current=lambda: True,
    )
    consent = SimpleNamespace(
        consent_id="lifecycle-consent", consent_revision=enrollment.background_consent_revision,
        expires_monotonic=clock[0] + 90, profile_id=enrollment.profile_id,
        service_enrollment_id=enrollment.service_enrollment_id,
        purpose="memory-service-lifecycle", is_current=lambda: True,
    )
    selection = SimpleNamespace(selection_handle="enablement-handle")
    routes = SimpleNamespace(expires_monotonic=clock[0] + 90)
    identity = _current_identity(os.getpid())
    process_lease = SimpleNamespace(
        process_id="a" * 32, profile_id=enrollment.profile_id,
        generation=enrollment.service_generation, uid=12001, gid=12001,
        pid=os.getpid(), start_ticks=identity["start_ticks"],
        executable_device=1, executable_inode=2, executable_sha256="f" * 64,
        cgroup_identity=identity["cgroup_identity"],
        mount_namespace_inode=identity["mount_namespace_inode"],
        network_namespace_inode=identity["network_namespace_inode"],
        expires_monotonic=clock[0] + 60, close=lambda: None,
    )

    class Custody:
        def resolve_selected_service_process(self, receipt):
            return process_lease if receipt is retained_receipt and process_current[0] else None

        def perform_root_selected_service_effect(self, _profile, _effect, _payload, **kwargs):
            captured.update(kwargs)
            return "effect-receipt"

    class Authority:
        def issue_root_selected_service_effect(self, admission, binding, action, payload):
            assert admission.is_current(now=clock[0])
            assert binding.action == action
            assert payload == binding.payload()
            return object()

        def consume_root_selected_service_effect(self, *_args):
            return object()

    identity_digest = _managed_identity_digest(process_lease)
    retained_receipt = RootSelectedServiceProcessReceipt(
        1, "receipt-handle", process_lease.process_id, "memory-agentmemory", "start",
        enrollment.service_enrollment_id, enrollment.profile_id, enrollment.service_generation,
        enrollment.principal_id, enrollment.namespace_identity, 12001, 12001,
        enrollment.lifecycle_binding.start_operation_id, "target:process.start", digest,
        identity_digest, clock[0], process_lease.expires_monotonic,
    )
    catalog = FakeCatalog()
    root_lifecycle = _lifecycle()
    root_lifecycle.monotonic = lambda: clock[0]
    root_lifecycle.custody = Custody()
    root_lifecycle.authority_service = Authority()

    def controller_lease():
        return RootControllerProcessIdentityLease(
            proof_handle="a" * 43, startup_authorization_handle="b" * 43,
            pid=os.getpid(), uid=0, start_ticks=identity["start_ticks"],
            pidfd=os.pidfd_open(os.getpid(), 0),
            cgroup_identity=identity["cgroup_identity"],
            mount_namespace_inode=identity["mount_namespace_inode"],
            network_namespace_inode=identity["network_namespace_inode"],
            proof_sha256="c" * 64, expires_monotonic=clock[0] + 25,
            _current_check=lambda: True, _monotonic=lambda: clock[0],
        )

    original_controller = controller_lease()
    original_actions = {
        action: MemorySelectedLifecycleActionBinding.resolve(
            enrollment, catalog, action=action, source_closure_sha256=source.source_closure_sha256,
            source_receipt_handles=handles,
        ) for action in ("start", "status", "stop")
    }
    old_admission = RootVerifiedMemoryLifecycleAdmission._from_root_registry(
        service_generation_digest=digest, enrollment=enrollment,
        consent_id=consent.consent_id, consent_revision=consent.consent_revision,
        source_closure_sha256=source.source_closure_sha256, source_receipt_handles=handles,
        sensitivity="PRIVATE", issued_monotonic=clock[0], expires_monotonic=clock[0] + 20,
        original_deadline=retained_receipt.expires_monotonic,
        action_bindings=original_actions, controller_lease=original_controller,
        consent_record=consent, source_closure=source, current_check=lambda _admission: True,
    )

    class CurrentRoutes:
        def is_current(self, _routes):
            return True

    registry = object.__new__(RootMemoryLifecycleRegistry)
    registry.bindings = SimpleNamespace(enrollment_catalog=catalog)
    registry.lifecycle = root_lifecycle
    registry.monotonic = lambda: clock[0]
    registry.enablement_registry = SimpleNamespace(is_current=lambda _selection: True)
    registry.private_route_resolver = CurrentRoutes()
    registry._lock = __import__("threading").RLock()
    registry._admissions = {old_admission.admission_handle: old_admission}
    registry._source_closures = {}
    registry._consents = {}
    registry._routes = {}
    registry._start_receipts = {}
    registry._readiness_receipts = {}
    registry._receipts = {}
    registry._control_origins = {
        retained_receipt.receipt_handle: (
            enrollment.target_id, "consent-handle", "controller-handle",
            old_admission.admission_handle, retained_receipt,
        )
    }
    registry._control_admissions = {}
    registry._authority_handles = {old_admission.admission_handle: (
        "consent-handle", "controller-handle")}
    source_current = [True]
    process_current = [True]

    def resolve_fresh_evidence(*_args):
        if not source_current[0]:
            raise RootMemoryLifecycleRegistryDenied("source closure was revoked")
        return digest, enrollment, source, consent, routes, controller_lease(), selection

    registry._resolve_evidence = resolve_fresh_evidence
    captured = {}
    try:
        # The original launch proof has expired, while its exact process remains
        # inside the original manager deadline. Renewal must use fresh PIDFD evidence.
        clock[0] = old_admission.expires_monotonic + 1
        fresh = registry.readmit_selected_control(
            enrollment.target_id, retained_receipt, "process.status")
        assert fresh is not old_admission
        assert fresh.original_deadline == retained_receipt.expires_monotonic
        assert fresh.expires_monotonic <= clock[0] + 30
        result = registry.perform_selected_control(fresh, retained_receipt, "process.status")
        assert result == "effect-receipt"
        assert captured["memory_admission"] is fresh
        assert captured["controller_proof"] is fresh._controller_lease
        source_current[0] = False
        with pytest.raises(RootMemoryLifecycleRegistryDenied, match="source closure was revoked"):
            registry.readmit_selected_control(
                enrollment.target_id, retained_receipt, "process.status")
        source_current[0] = True
        process_current[0] = False
        with pytest.raises(RootMemoryLifecycleRegistryDenied, match="process is no longer current"):
            registry.readmit_selected_control(
                enrollment.target_id, retained_receipt, "process.status")
        process_current[0] = True
        stopped = registry.stop_selected_memory(enrollment.target_id, retained_receipt)
        assert stopped == "effect-receipt"
        with pytest.raises(RootMemoryLifecycleRegistryDenied, match="exact retained memory start"):
            registry.readmit_selected_control(
                enrollment.target_id, replace(retained_receipt), "process.status")
    finally:
        original_controller.close()
        fresh_controller = locals().get("fresh")
        if fresh_controller is not None:
            fresh_controller._controller_lease.close()
