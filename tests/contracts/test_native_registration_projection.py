from __future__ import annotations

import json
from pathlib import Path

from hermes_installer.authority.native_registration_projection import (
    NativeRegistrationCaptureDenied,
    capture_actual_hermes_registrations,
    reviewed_native_registration_definitions,
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


def test_source_reviewed_registration_map_covers_all_actual_tools_and_finite_routes():
    captured = capture_actual_hermes_registrations()
    definitions = reviewed_native_registration_definitions(captured)
    by_name = {row.native_tool_name: row for row in definitions}
    assert len(by_name) == 42
    assert {row.family for row in definitions} == {
        "agent-live-wallet", "agent-sandbox-wallet", "agent37-discovery",
        "authentik-authorization", "cloudflare-homelab", "codex", "composio",
        "ebook-toolchain", "epic-kanban", "financial-data-hub",
        "financial-execution-gateway", "github", "homelab-ops-broker",
        "kobo-bridge", "mcp-registry", "resource-overlay-store",
        "voice-pipeline", "web",
    }
    assert by_name["financial_data_read"].selector_fields == ("provider", "operation")
    data_branches = by_name["financial_data_read"].action_bindings
    assert len(data_branches) == 14
    assert all(row.action_id == "read" for row in data_branches)
    assert {tuple(sorted(row.selector_values.items())) for row in data_branches}
    assert by_name["financial_execute_one_order"].selector_fields == ("provider", "operation")
    assert len(by_name["financial_execute_one_order"].action_bindings) == 10
    assert by_name["agent_live_wallet_action"].selector_fields == ("operation",)
    assert {row.action_id for row in by_name["agent_live_wallet_action"].action_bindings} == {"read", "execute"}
    assert by_name["agent_sandbox_wallet_action"].selector_fields == ("operation",)
    assert len(by_name["agent_sandbox_wallet_action"].action_bindings) == 9
    assert by_name["homelab_ops_inspect"].selector_fields == ("query",)
    assert by_name["homelab_ops_run"].selector_fields == ("action",)
    assert by_name["epic_board"].selector_fields == ("operation",)
    assert {row.handler_kind for row in definitions} >= {
        "public-registry-read", "owner-overlay", "finite-workflow", "finite-selector",
    }


def test_source_reviewed_registration_map_rejects_unreviewed_actual_name():
    from dataclasses import replace

    captured = list(capture_actual_hermes_registrations())
    captured[0] = replace(captured[0], native_tool_name="new_unreviewed_tool")
    try:
        reviewed_native_registration_definitions(tuple(captured))
    except ValueError as exc:
        assert "does not cover" in str(exc)
    else:
        raise AssertionError("unreviewed Hermes tool registration was accepted")


def test_eight_local_result_schemas_match_exact_artifacts_and_actual_source_pins():
    from hermes_installer.authority.native_registration_projection import (
        reviewed_local_registration_result_schemas,
    )

    rows = reviewed_local_registration_result_schemas()
    assert len(rows) == 8
    assert {row.native_tool_name for row in rows} == {
        "agent37_discover_skills", "agent37_inspect_skill",
        "mcp_registry_discover", "mcp_registry_inspect",
        "resource_overlay_read", "resource_overlay_write",
        "resource_overlay_history", "resource_overlay_delete",
    }
    assert all(row.schema_id == row.artifact_id for row in rows)
    assert all(row.handler_kind in {"public-registry-read", "owner-overlay"} for row in rows)


def test_local_result_schema_rejects_changed_artifact_bytes(monkeypatch, tmp_path):
    from hermes_installer.authority import native_registration_projection as projection

    original = projection.Path.read_bytes

    def changed(path):
        value = original(path)
        if path.name == "agent37_discover_skills.result.schema.json":
            return value + b" "
        return value

    monkeypatch.setattr(projection.Path, "read_bytes", changed)
    try:
        projection.reviewed_local_registration_result_schemas()
    except ValueError as exc:
        assert "differ from the reviewed pin" in str(exc)
    else:
        raise AssertionError("changed local result schema bytes were accepted")


def test_root_registration_source_observation_fails_closed_without_held_release_receipts():
    from hermes_installer.authority.native_registration_projection import (
        NativeRegistrationSourceObservationDenied,
        observe_root_native_registrations,
    )

    captured = capture_actual_hermes_registrations()
    try:
        observe_root_native_registrations((), captured)
    except NativeRegistrationSourceObservationDenied as exc:
        assert "held release module receipts" in str(exc)
    else:
        raise AssertionError("source registration capture was promoted without root-held receipts")
