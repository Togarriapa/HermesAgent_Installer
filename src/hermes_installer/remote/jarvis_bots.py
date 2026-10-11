"""Owner-only, fixed native status projection for Jarvis Bots/channels/schedules.

This is deliberately a read-only adapter.  It consumes only the typed, fixed CoreRpcClient
methods reviewed for the pinned Hermes core; it is not a browser-facing RPC/CLI proxy.
"""
from __future__ import annotations

import secrets
from typing import Any

from .jarvis_channels import project_channel_status
from .jarvis_schedules import project_schedules

FEATURE_ROUTES = (
    ("GET", "/chat/api/bots"),
    ("GET", "/chat/api/channels"),
    ("GET", "/chat/api/schedules"),
)
def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean_label(value: Any, *, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    value = " ".join("".join(char for char in value if ord(char) >= 0x20 and ord(char) != 0x7f).split())
    return value[:limit]


def _profile_projection(row: dict[str, Any] | None) -> list[dict[str, Any]]:
    if row is None or row.get("is_default") is not True:
        return []
    label = _clean_label(row.get("display_name")) or _clean_label(row.get("name"))
    if not label:
        label = "Current default profile"
    return [{
        "opaque_id": secrets.token_urlsafe(18),
        "display_name": label,
        "kind": "profile",
        "state": "selected-default; Bot Mode roster unavailable",
        "bot_mode_available": False,
    }]


def build_status_snapshot(*, core_generation: str, profile: dict[str, Any] | None,
                          schedules: list[dict[str, Any]], observed_at: str | None = None) -> dict[str, Any]:
    """Project closed public fields. Inputs here are already returned by typed core adapters."""
    profiles = _profile_projection(profile)
    schedule_rows, timezone_missing = project_schedules(schedules)
    channels, channel_reason = project_channel_status()
    pending: list[str] = [
        "Bot Mode DM, groups, roster and relay are not represented by native profile inventory.",
        channel_reason,
    ]
    if not profiles:
        pending.append("The fixed native profile status did not identify a current default profile.")
    if timezone_missing:
        pending.append("The fixed native cron list does not report each schedule timezone.")
    return {
        "schema": 1,
        "observed_at": observed_at or _now(),
        "core_generation": core_generation,
        "profiles": profiles,
        "channels": channels,
        "schedules": schedule_rows,
        "pending_reasons": pending,
    }


def install_jarvis_bots_routes(app: Any, service: Any) -> None:
    """Install three authenticated read-only collection aliases on the protected gateway."""
    from aiohttp import web
    from .core_client import CoreRpcClient
    from .jarvis_chat import JarvisChatDenied, JarvisChatService, _secure_headers

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    if not isinstance(service.backend, CoreRpcClient):
        raise TypeError("fixed official core status adapter required")

    async def route(request: Any) -> Any:
        if request.path not in {path for _method, path in FEATURE_ROUTES} or request.raw_path != request.path:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers())
        try:
            principal = service._current(request)
            profiles = await service.backend.list_profiles()
            profile = _sole_default(profiles)
            observed = service._current(request)
            if (observed.subject != principal.subject
                    or observed.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner or core generation changed during status read")
            schedules = await service.backend.list_schedules()
            profiles_after = await service.backend.list_profiles()
            profile_after = _sole_default(profiles_after)
            if ((profile is None) != (profile_after is None)
                    or (profile is not None and profile_after != profile)):
                raise JarvisChatDenied("default profile changed during status read")
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner or core generation changed during status read")
            payload = build_status_snapshot(core_generation=principal.core_generation,
                                            profile=profile, schedules=schedules)
            return web.json_response(payload, headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPServiceUnavailable(text="native status is unavailable",
                                             headers=_secure_headers()) from None
        except Exception:
            # Do not copy upstream exceptions, records, credential material or method details
            # into logs or a browser response.
            raise web.HTTPServiceUnavailable(text="native status is unavailable",
                                             headers=_secure_headers()) from None

    for _method, path in FEATURE_ROUTES:
        app.router.add_get(path, route, allow_head=False)


def _sole_default(rows: Any) -> dict[str, Any] | None:
    """Accept only the typed adapter's zero-or-one current-default projection."""
    if not isinstance(rows, list) or len(rows) > 1:
        raise ValueError("native profile status exceeded its bound")
    if not rows:
        return None
    row = rows[0]
    if not isinstance(row, dict) or row.get("is_default") is not True:
        raise ValueError("native profile status was not the current default")
    return row
