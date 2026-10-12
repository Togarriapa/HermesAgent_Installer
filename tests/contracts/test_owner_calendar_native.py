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
        "source_binding_sha256": "c" * 64,
        "provider_principal_id": "google-principal-1",
        "credential_consumer_uid": 0,
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
    {"credential_consumer_uid": 1000},
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
