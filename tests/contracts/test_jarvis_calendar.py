import pytest

from hermes_installer.remote.jarvis_calendar import (
    CalendarProjectionError,
    MAX_EVENTS,
    project_calendar_page,
    validate_window,
)


def _event(event_id="opaque-event-1", *, title="Planning", start="2026-10-12T09:00:00+01:00",
           end="2026-10-12T10:00:00+01:00"):
    return {"opaque_event_id": event_id, "summary": title,
            "start": {"dateTime": start, "timeZone": "Europe/Lisbon"},
            "end": {"dateTime": end, "timeZone": "Europe/Lisbon"},
            "description": "private detail omitted", "htmlLink": "https://example.invalid"}


def _page(status="connected", events=None):
    return {"status": status, "opaque_account_ref": "opaque-account-1",
            "opaque_calendar_ref": "opaque-calendar-1", "account_label": "Owner calendar",
            "calendar_label": "Primary", "events": [] if events is None else events,
            "next_step": ""}


def test_projects_only_bounded_calendar_fields_and_keeps_source_time():
    projected = project_calendar_page(
        _page(events=[_event(title="Planning <img src=x onerror=alert(1)>")]),
        timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z",
    )
    assert projected["status"] == "connected"
    assert projected["source"] == "Google Calendar"
    assert projected["timezone"] == "Europe/Lisbon"
    assert projected["events"][0]["title"] == "Planning <img src=x onerror=alert(1)>"
    assert set(projected["events"][0]) == {"id", "title", "start", "end", "all_day"}
    assert "description" not in projected["events"][0]
    assert "htmlLink" not in projected["events"][0]


def test_verified_zero_events_is_empty_and_not_unavailable():
    projected = project_calendar_page(
        _page(), timezone_name="UTC", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z",
    )
    assert projected["status"] == "empty"
    assert projected["events"] == []


@pytest.mark.parametrize("window", [
    ("2026-10-12T00:00:00", "2026-10-13T00:00:00Z", "UTC"),
    ("2026-10-12T00:00:00Z", "2026-11-13T00:00:00Z", "UTC"),
    ("2026-10-12T00:00:00Z", "2026-10-13T00:00:00Z", "Not/AZone"),
])
def test_rejects_naive_oversized_or_unknown_timezone_window(window):
    with pytest.raises(CalendarProjectionError):
        validate_window(start=window[0], end=window[1], timezone_name=window[2])


def test_rejects_unavailable_source_with_events_and_oversized_page():
    args = dict(timezone_name="UTC", window_start="2026-10-12T00:00:00Z",
                window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(_page("auth-expired", [_event()]), **args)
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(_page(events=[_event(str(i)) for i in range(MAX_EVENTS + 1)]), **args)


def test_projects_all_day_events_in_requested_zone():
    page = _page(events=[{"opaque_event_id": "day-1", "summary": "Holiday",
                          "start": {"date": "2026-10-12"},
                          "end": {"date": "2026-10-13"}}])
    projected = project_calendar_page(
        page, timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")
    assert projected["events"][0]["all_day"] is True
    assert projected["events"][0]["start"].startswith("2026-10-12T00:00:00+01:00")


def test_rejects_invalid_event_interval():
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(
            _page(events=[_event(start="2026-10-12T10:00:00+01:00",
                                 end="2026-10-12T09:00:00+01:00")]),
            timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
            window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")
