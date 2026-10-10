"""Projection-only checks for the local owner-overlay publication contract.

These fixtures exercise canonical shape/digest rejection. They are not host
installation, runtime-currentness, or effect authorization evidence.
"""
from __future__ import annotations

import hashlib

import pytest

from hermes_installer.authority.owner_overlay_publication import (
    _canonical,
    _mint_published_local_owner_adoption,
    validate_owner_overlay_adoption_row,
)


def _projection():
    handle = "a" * 64
    choice = {
        "selection_handle": "selection-1", "purpose": "native-policy-preparation",
        "key_id": "key", "signed_record_sha256": "1" * 64,
        "choice_payload_sha256": "2" * 64, "choice_epoch": 1, "revocation_epoch": 0,
        "issued_at_unix": 10.0, "setup_deadline_unix": 20.0,
        "release_deployment_receipt_sha256": "3" * 64,
        "setup_session_handle": "session", "transaction_handle": "transaction",
        "plan_id": "plan", "prepared_generation": "generation",
        "principal_selection_handle": "principal-selection",
        "namespace_selection_handle": "namespace-selection",
        "private_profile_selection_handle": "profile-selection",
        "source_member_receipt_handles": ["source-receipt"],
        "principal_id": "principal", "profile_id": "service-profile",
        "namespace_id": "namespace", "principal_binding_sha256": "4" * 64,
        "namespace_binding_sha256": "5" * 64, "service_generation_id": "generation",
        "service_generation_digest": "6" * 64, "selection_catalog_sha256": "7" * 64,
    }
    owner = {
        "principal_id": "principal", "profile_id": "service-profile", "namespace_id": "namespace",
        "principal_binding_sha256": "4" * 64, "namespace_binding_sha256": "5" * 64,
        "account_name": "owner", "account_uid": 1000, "primary_gid": 1000,
        "machine_target_sha256": "8" * 64, "service_uid": 1000, "service_gid": 1000,
        "service_generation_id": "generation", "service_generation_digest": "6" * 64,
    }
    resources = {
        "resources_profile_id": "resources", "source_receipt_handle": "s" * 40,
        "source_artifact_id": "artifact", "source_sha256": "9" * 64,
        "member_receipt_handles": ["s" * 40], "member_sha256s": ["a" * 64],
        "resource_profile_selection_handle": "resource-selection",
        "resource_profile_selection_sha256": "b" * 64,
    }
    package = {
        "package_id": "package", "profile_id": "service-profile", "generation": "generation",
        "compiled_closure_sha256": "c" * 64, "entrypoint_sha256": "d" * 64,
        "resolver_sha256": "e" * 64, "owner_overlay_operation_records_sha256": "f" * 64,
        "native_cas_transition_receipt_handle": "c" * 64,
        "native_cas_transition_sha256": "0" * 64,
    }
    view = {
        "service_profile_id": "service-profile", "resource_profile_id": "resources",
        "data_root_id": "root", "data_root_selection_handle": "data-root-selection",
        "data_root_receipt_handle": "data-root-receipt", "data_root_device": 1,
        "data_root_inode": 2, "data_root_owner_uid": 1000, "data_root_owner_gid": 1000,
        "relative_path": "native-profile-overlays/service-profile/resources",
        "view_device": 1, "view_inode": 3, "view_owner_uid": 0, "view_owner_gid": 0,
        "view_mode": 0o700, "ownership_marker_sha256": "1" * 64,
        "profile_view_selection_handle": "view-selection", "profile_view_receipt_handle": "view-receipt",
        "target_id": "target", "target_selection_handle": "target-selection",
        "target_receipt_handle": "target-receipt", "effect_enrollment_ids": ["effect-enrollment"],
    }
    operation = {
        "registration_id": "resource-overlay-store:tool:resource_overlay_read",
        "method": "read", "operation": "plugin.resource-overlay-store.read",
        "capability": "plugin:resource-overlay-store", "target_id": "target", "recipient": None,
        "effect_enrollment_id": "effect-enrollment", "profile_id": "service-profile",
        "profile_generation": "generation", "principal_id": "principal", "namespace_id": "namespace",
        "package_id": "package", "package_generation": "generation",
        "argument_schema_id": "args", "argument_schema_sha256": "2" * 64,
        "argument_schema_receipt_handle": "argument-schema-receipt",
        "result_schema_id": "result", "result_schema_sha256": "3" * 64,
        "result_schema_receipt_handle": "result-schema-receipt",
        "handler_artifact_id": "handler", "handler_sha256": "4" * 64,
        "handler_source_receipt_handle": "handler-source",
        "profile_view_selection_handle": "view-selection", "profile_view_receipt_handle": "view-receipt",
        "data_root_selection_handle": "data-root-selection", "data_root_receipt_handle": "data-root-receipt",
        "target_selection_handle": "target-selection", "target_receipt_handle": "target-receipt",
        "prepared_source_observer_selection_handle": "source-observer-selection",
        "source_observer_enrollment_ids": ["source-enrollment"], "process_role_id": "role",
        "source_issuer_id": "issuer",
    }
    members = [{
        "role": "native-source-module", "artifact_id": "artifact", "receipt_handle": "s" * 40,
        "relative_path": "module.py", "sha256": "5" * 64, "size_bytes": 1, "mode": 0o400,
    }]
    return _mint_published_local_owner_adoption(
        adoption_handle=handle, identity_kind="linux-local-owner-v1", signed_choice=choice,
        adopted_at_unix=None, setup_deadline_unix=20.0, owner=owner, resources=resources,
        native_package=package, operation_records=(operation,), view_custody=view,
        source_members=tuple(members),
    )


def test_projection_serializes_as_digest_covered_exact_row():
    projection = _projection()
    row = projection.to_claim_row(include_digest=False)
    row["adopted_at_unix"] = 15.0
    row["adoption_sha256"] = hashlib.sha256(_canonical(row)).hexdigest()
    assert validate_owner_overlay_adoption_row(row) == row
    digest = row.pop("adoption_sha256")
    assert digest == hashlib.sha256(_canonical(row)).hexdigest()


@pytest.mark.parametrize("mutation", ["view", "revision", "schema", "source", "grant", "currentness"])
def test_projection_rejects_altered_or_incomplete_publication_facts(mutation):
    row = _projection().to_claim_row(include_digest=False)
    row["adopted_at_unix"] = 15.0
    if mutation == "view":
        row["view_custody"]["target_receipt_handle"] = ""
    elif mutation == "revision":
        row["signed_choice"]["service_generation_digest"] = "z" * 64
    elif mutation == "schema":
        row["operation_records"][0]["argument_schema_sha256"] = "bad"
    elif mutation == "source":
        row["source_members"] = []
    elif mutation == "grant":
        row["operation_records"][0]["capability"] = "plugin:arbitrary"
    else:
        row["adopted_at_unix"] = 21.0
    row["adoption_sha256"] = hashlib.sha256(_canonical(row)).hexdigest()
    # Even a recomputed outer digest cannot repair contradictory source facts.
    with pytest.raises((TypeError, ValueError)):
        validate_owner_overlay_adoption_row(row)
