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
