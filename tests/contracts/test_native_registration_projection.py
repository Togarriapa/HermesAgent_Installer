from __future__ import annotations

import json
from pathlib import Path

from hermes_installer.authority.native_registration_projection import (
    NativeRegistrationCaptureDenied,
    capture_actual_hermes_registrations,
)


ROOT = Path(__file__).resolve().parents[2]


def test_captured_registrations_match_actual_source_inventory_without_authority_claims():
    inventory_path = (ROOT / "plans/amendments/2026-10-10-native-registration-projection-v99"
                      / "source-registration-inventory.json")
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
    assert inventory["operational_projection"] is False
    assert inventory["registration_count"] == 42
    source_by_name = {row["native_tool_name"]: row for row in inventory["registrations"]}

    captured = capture_actual_hermes_registrations()
    assert len(captured) == 42
    assert {row.native_tool_name for row in captured} == set(source_by_name)
    for row in captured:
        source = source_by_name[row.native_tool_name]
        assert row.adapter_id == source["adapter_id"]
        assert row.toolset == source["toolset"]
        assert row.argument_schema == source["argument_schema"]
        assert row.native_schema_sha256 == source["native_schema_sha256"]
        assert row.registration_source_sha256 == source["registration_source_sha256"]
    # This capture type intentionally cannot be serialized as executable
    # registration authority: it has no result schema, source receipt, action
    # bindings, or observer enrollments.
    assert all(not hasattr(row, "result_schema") for row in captured)
    assert all(not hasattr(row, "registration_source_receipt_handle") for row in captured)
    assert all(not hasattr(row, "observer_enrollment_ids") for row in captured)


def test_registration_capture_rejects_duplicate_hermes_tool_names(monkeypatch):
    from hermes_installer.authority import native_registration_projection as projection

    original = projection._PLUGIN_IDS
    monkeypatch.setattr(projection, "_PLUGIN_IDS", (original[0], original[0]))
    try:
        capture_actual_hermes_registrations()
    except NativeRegistrationCaptureDenied as exc:
        assert "collide" in str(exc)
    else:
        raise AssertionError("duplicate actual Hermes registrations were accepted")
