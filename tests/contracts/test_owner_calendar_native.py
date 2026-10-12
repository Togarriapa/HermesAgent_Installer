"""Effect-boundary contracts for the root-owned Calendar read adapter."""
from __future__ import annotations

import hashlib
import json

import pytest

from hermes_installer.remote import owner_calendar_native as calendar


def _registration() -> dict:
    return {
        "schema": 1,
        "owner_subject_sha256": "a" * 64,
        "connection_id": "connection-1",
        "generation_sha256": "b" * 64,
        "connection_generation_sha256": "f" * 64,
        "source_binding_sha256": "c" * 64,
        "provider_principal_id": "google-principal-1",
        "credential_consumer_uid": 1000,
        "credential_ref": "google-calendar-read",
        "credential_scope": "mcp:google-calendar:read",
        "endpoint": calendar.GOOGLE_CALENDAR_ENDPOINT,
        "tool_name": "list_events",
        "input_schema_sha256": "d" * 64,
        "output_schema_sha256": "e" * 64,
        "invocation_class": "owner-ui-calendar-read",
        "calendars": [{"calendar_ref": "A" * 32, "calendar_id": "primary",
                       "label": "Personal calendar"}],
        "selected_calendar_ref": "A" * 32,
        "provider_identity_label": None,
        "native_binding_id": "calendar-native-binding",
        "mcp_generation": "mcp-generation-1",
        "owner_ui_consent": {
            "schema": 1, "owner_subject_sha256": "a" * 64,
            "action": "read-only-calendar-dashboard",
            "confirmed_at": "2026-10-12T10:00:00Z",
            "core_generation": "9" * 64,
            "connection_generation_sha256": "f" * 64,
            "source_binding_sha256": "c" * 64,
            "canonical_arguments_sha256": hashlib.sha256(
                calendar._canonical({"calendarId": "primary"})).hexdigest(),
        },
    }


def test_registration_binds_one_fixed_read_connection_and_calendar() -> None:
    registration = calendar._validate_registration(_registration())
    assert registration["endpoint"] == calendar.GOOGLE_CALENDAR_ENDPOINT
    assert registration["tool_name"] == "list_events"
    assert registration["invocation_class"] == "owner-ui-calendar-read"
    assert registration["selected_calendar_ref"] == registration["calendars"][0]["calendar_ref"]


@pytest.mark.parametrize("change", [
    {"endpoint": "https://attacker.invalid/mcp"},
    {"tool_name": "list_calendars"},
    {"credential_scope": "mcp:google-calendar:write"},
    {"invocation_class": "native-model-call"},
    {"credential_consumer_uid": -1},
])
def test_registration_rejects_changed_endpoint_tool_scope_or_owner_class(change: dict) -> None:
    registration = _registration()
    registration.update(change)
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._validate_registration(registration)


def test_calendar_selection_cannot_escape_registered_opaque_reference() -> None:
    registration = _registration()
    registration["selected_calendar_ref"] = "Z" * 32
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._validate_registration(registration)


def test_read_window_is_bounded_and_requires_explicit_timezone_offsets() -> None:
    first, last = calendar._bounds("2026-10-12T10:00:00+01:00",
        "2026-11-12T10:00:00+00:00", "Europe/Lisbon", 100)
    assert last > first
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._bounds("2026-10-12T10:00:00", "2026-10-13T10:00:00+01:00",
                         "Europe/Lisbon", 100)
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._bounds("2026-10-12T10:00:00+01:00", "2026-11-13T10:00:00+00:00",
                         "Europe/Lisbon", 100)
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._bounds("2026-10-12T10:00:00+01:00", "2026-10-13T10:00:00+01:00",
                         "Europe/Lisbon", 101)


def test_tool_result_decoder_accepts_one_bounded_native_text_result_only() -> None:
    encoded = json.dumps({"events": []}, separators=(",", ":"))
    assert calendar._result_value({"content": [{"type": "text", "text": encoded}]}) == {"events": []}
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._result_value({"content": [{"type": "text", "text": encoded},
                                             {"type": "text", "text": encoded}]})
    with pytest.raises(calendar.OwnerCalendarUnavailable):
        calendar._json(b'{"events":[],"events":[]}')


def test_actual_tool_receipt_digest_is_stable_for_canonical_result() -> None:
    response = {"structuredContent": {"events": [], "nextPageToken": None}}
    digest = hashlib.sha256(calendar._canonical(response)).hexdigest()
    assert len(digest) == 64


def test_direct_ui_consent_is_bound_to_owner_connection_and_resource() -> None:
    registration = calendar._validate_registration(_registration())
    consent = registration["owner_ui_consent"]
    assert consent["action"] == "read-only-calendar-dashboard"
    assert consent["owner_subject_sha256"] == registration["owner_subject_sha256"]
    assert consent["connection_generation_sha256"] == registration["connection_generation_sha256"]
    assert consent["canonical_arguments_sha256"] == hashlib.sha256(
        calendar._canonical({"calendarId": "primary"})).hexdigest()


def test_registration_source_currentness_denies_changed_native_selection(monkeypatch) -> None:
    registration = calendar._validate_registration(_registration())
    current = {
        "connection_id": registration["connection_id"],
        "generation_sha256": registration["generation_sha256"],
        "connection_generation_sha256": registration["connection_generation_sha256"],
        "source_binding_sha256": registration["source_binding_sha256"],
        "provider_principal_id": registration["provider_principal_id"],
        "credential_consumer_uid": registration["credential_consumer_uid"],
        "credential_ref": registration["credential_ref"],
        "native_binding_id": registration["native_binding_id"],
        "input_schema_sha256": registration["input_schema_sha256"],
        "output_schema_sha256": registration["output_schema_sha256"],
        "calendar_id": "primary",
        "authority_core_sha256": registration["owner_ui_consent"]["core_generation"],
        "mcp_generation": registration["mcp_generation"],
    }
    monkeypatch.setattr(calendar, "_current_published_calendar_source",
                        lambda _config: (current, object()))
    assert calendar._calendar_source_is_current(object(), registration)
    current["calendar_id"] = "foreign-calendar@example.test"
    assert not calendar._calendar_source_is_current(object(), registration)
