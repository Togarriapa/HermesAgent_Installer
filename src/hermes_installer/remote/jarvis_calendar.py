"""Finite, read-only projection for an already authorized Calendar source.

This module deliberately does not discover accounts, resolve credentials, or
invoke MCP. Those effects belong to the root-owned selected-resource adapter.
"""
from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Mapping
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_WINDOW_DAYS = 31
MAX_EVENTS = 100
MAX_TITLE = 240
_STATUSES = frozenset({"connected", "empty", "unavailable", "auth-expired",
                       "permission-denied", "rate-limited", "partial"})


class CalendarProjectionError(ValueError):
    """The selected-source response cannot be safely projected."""


def validate_window(*, start: str, end: str, timezone_name: str) -> tuple[datetime, datetime]:
    """Validate a half-open RFC3339 window and IANA display timezone."""
    try:
        ZoneInfo(timezone_name)
        first = datetime.fromisoformat(start.replace("Z", "+00:00"))
        last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    except (ValueError, TypeError, ZoneInfoNotFoundError):
        raise CalendarProjectionError("calendar window or timezone is invalid") from None
    if (first.tzinfo is None or last.tzinfo is None or first.utcoffset() is None
            or last.utcoffset() is None or last <= first
            or (last - first).total_seconds() > MAX_WINDOW_DAYS * 86400):
        raise CalendarProjectionError("calendar window exceeds its bounded range")
    return first.astimezone(timezone.utc), last.astimezone(timezone.utc)


def _clean_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(c for c in value if ord(c) >= 0x20 and ord(c) != 0x7f).split())[:limit]


def _event_time(value: Any, *, zone_name: str) -> tuple[str, bool]:
    if not isinstance(value, Mapping):
        raise CalendarProjectionError("calendar event time is malformed")
    if set(value) == {"date"}:
        try:
            day = date.fromisoformat(value["date"])
            zone = ZoneInfo(zone_name)
        except (TypeError, ValueError, ZoneInfoNotFoundError):
            raise CalendarProjectionError("all-day event date is malformed") from None
        return datetime(day.year, day.month, day.day, tzinfo=zone).isoformat(), True
    if set(value) == {"dateTime", "timeZone"}:
        raw, event_zone = value["dateTime"], value["timeZone"]
        if not isinstance(raw, str) or not isinstance(event_zone, str):
            raise CalendarProjectionError("timed event value is malformed")
        try:
            ZoneInfo(event_zone)
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except (ValueError, ZoneInfoNotFoundError):
            raise CalendarProjectionError("timed event timezone is malformed") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise CalendarProjectionError("timed event must include an offset")
        return parsed.isoformat(), False
    raise CalendarProjectionError("calendar event time has an unsupported shape")


def project_calendar_page(source: Mapping[str, Any], *, timezone_name: str,
                          window_start: str, window_end: str,
                          observed_at: str) -> dict[str, Any]:
    """Project one verified native read result into a closed browser DTO.

    `source` must already be bound by the root adapter to the authenticated
    owner, enrolled account, selected calendar, and current native generation.
    The projector accepts no identity or authority claims from the browser.
    """
    if not isinstance(source, Mapping):
        raise CalendarProjectionError("calendar source result is malformed")
    start, end = validate_window(start=window_start, end=window_end,
                                 timezone_name=timezone_name)
    try:
        observed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except (AttributeError, TypeError, ValueError):
        raise CalendarProjectionError("calendar observation time is invalid") from None
    if observed.tzinfo is None or observed.utcoffset() is None:
        raise CalendarProjectionError("calendar observation time must include an offset")
    status = source.get("status")
    if not isinstance(status, str) or status not in _STATUSES:
        raise CalendarProjectionError("calendar source status is unsupported")
    account_ref, calendar_ref = source.get("opaque_account_ref"), source.get("opaque_calendar_ref")
    if status in {"connected", "empty", "partial"} and any(
        not isinstance(value, str) or not value or len(value) > 128
        for value in (account_ref, calendar_ref)
    ):
        raise CalendarProjectionError("selected account or calendar reference is unavailable")
    common = {
        "schema": 1,
        "status": status,
        "observed_at": observed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "Google Calendar",
        "opaque_account_ref": account_ref if isinstance(account_ref, str) else None,
        "opaque_calendar_ref": calendar_ref if isinstance(calendar_ref, str) else None,
        "timezone": timezone_name,
        "window_start": start.isoformat().replace("+00:00", "Z"),
        "window_end": end.isoformat().replace("+00:00", "Z"),
        "account_label": _clean_text(source.get("account_label"), 120),
        "calendar_label": _clean_text(source.get("calendar_label"), 120),
        "next_step": _clean_text(source.get("next_step"), 240),
        "partial": status == "partial" or source.get("partial") is True,
        "events": [],
    }
    rows = source.get("events", [])
    if not isinstance(rows, (list, tuple)) or len(rows) > MAX_EVENTS:
        raise CalendarProjectionError("calendar event page exceeds its bound")
    if status == "empty" and rows:
        raise CalendarProjectionError("verified empty calendar state contains events")
    if status in {"unavailable", "auth-expired", "permission-denied", "rate-limited"} and rows:
        raise CalendarProjectionError("unavailable calendar state cannot contain events")
    seen_event_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise CalendarProjectionError("calendar event row is malformed")
        event_id = row.get("opaque_event_id")
        if (not isinstance(event_id, str) or not event_id or len(event_id) > 128
                or event_id in seen_event_ids):
            raise CalendarProjectionError("calendar event reference is invalid")
        seen_event_ids.add(event_id)
        event_start, start_all_day = _event_time(row.get("start"), zone_name=timezone_name)
        event_end, end_all_day = _event_time(row.get("end"), zone_name=timezone_name)
        if start_all_day != end_all_day:
            raise CalendarProjectionError("calendar event interval has mixed date forms")
        if start_all_day:
            interval_start = date.fromisoformat(row["start"]["date"])
            interval_end = date.fromisoformat(row["end"]["date"])
            display_zone = ZoneInfo(timezone_name)
            bound_start = datetime(interval_start.year, interval_start.month, interval_start.day,
                                   tzinfo=display_zone).astimezone(timezone.utc)
            bound_end = datetime(interval_end.year, interval_end.month, interval_end.day,
                                 tzinfo=display_zone).astimezone(timezone.utc)
        else:
            interval_start = datetime.fromisoformat(event_start)
            interval_end = datetime.fromisoformat(event_end)
            bound_start = interval_start.astimezone(timezone.utc)
            bound_end = interval_end.astimezone(timezone.utc)
        if interval_end <= interval_start:
            raise CalendarProjectionError("calendar event interval is invalid")
        if bound_start >= end or bound_end <= start:
            raise CalendarProjectionError("calendar event falls outside the selected window")
        common["events"].append({
            "id": event_id,
            "title": _clean_text(row.get("summary"), MAX_TITLE) or "Untitled event",
            "start": event_start,
            "end": event_end,
            "all_day": start_all_day,
        })
    if status == "connected" and not common["events"]:
        common["status"] = "empty"
    return common
