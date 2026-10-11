"""Closed projection of the fixed native ``cron.manage(list)`` status result."""
from __future__ import annotations

import math
import re
import secrets
from datetime import datetime, timezone
from typing import Any

_UTC = timezone.utc
_SAFE_SCHEDULE = re.compile(r"^[A-Za-z0-9*/?.,:@+\- ]{1,160}$")
_LAST_STATES = frozenset({"ok", "success", "error", "failed", "running", "pending",
                          "missed", "cancelled", "canceled", "skipped"})


def _timestamp(value: Any) -> str | None:
    """Normalize only finite epoch values or timezone-qualified ISO timestamps to UTC."""
    try:
        if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value):
            parsed = datetime.fromtimestamp(value, _UTC)
        elif isinstance(value, str) and 1 <= len(value) <= 40 and not any(ord(c) < 0x20 for c in value):
            normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                return None
            parsed = parsed.astimezone(_UTC)
        else:
            return None
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return parsed.isoformat(timespec="seconds").replace("+00:00", "Z")


def project_schedules(rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    """Expose only schedule status, never job ids, prompts, scripts, paths or delivery data."""
    if not isinstance(rows, list):
        raise ValueError("native schedule status must be a list")
    if len(rows) > 512:
        raise ValueError("native schedule status exceeded its row bound")
    result: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        if not isinstance(row, dict):
            raise ValueError("native schedule row was invalid")
        # The fixed CoreRpcClient adapter supplies a generic safe label: upstream Hermes may
        # derive a missing job name from a prompt preview, so arbitrary names are not forwarded.
        label = f"Scheduled job {index}"
        schedule = row.get("schedule")
        summary = (schedule.strip() if isinstance(schedule, str)
                   and _SAFE_SCHEDULE.fullmatch(schedule.strip()) else "Schedule details unavailable")
        enabled = row.get("enabled")
        if enabled is not None and type(enabled) is not bool:
            raise ValueError("native schedule enabled status was invalid")
        last_status = row.get("last_status")
        last_status = last_status.strip().casefold() if isinstance(last_status, str) else None
        if last_status not in _LAST_STATES:
            last_status = None
        result.append({
            "opaque_id": secrets.token_urlsafe(18),
            "label": label,
            "enabled": enabled,
            # cron.manage list on the pinned core does not report per-job timezone.
            "timezone": None,
            "schedule_summary": summary,
            "next_run_at": _timestamp(row.get("next_run_at")),
            "last_state": last_status,
        })
    return result, bool(result)
