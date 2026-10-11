"""Finite, read-only Jarvis overview APIs backed by current owner data.

These routes are composed into the protected core gateway. They expose aggregate chat
records and the integrity-checked offline Resources catalog; source presence remains
separate from native discovery, activation, or functional readiness.
"""
from __future__ import annotations

import asyncio
from datetime import date, datetime, time, timedelta, timezone
from functools import lru_cache
from typing import Any

UTC = timezone.utc
_ROUTES = {
    "/chat/api/overview": "overview",
    "/chat/api/capabilities": "capabilities",
    "/chat/api/settings": "settings",
}


def _iso_utc(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    try:
        value = datetime.fromtimestamp(float(timestamp), UTC)
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def _aggregate(store: Any, subject: str, *, today: date) -> dict[str, Any]:
    """Read only this principal's durable turn rows and return bounded aggregates."""
    owner = store._owner(subject)
    first_day = today - timedelta(days=6)
    start = datetime.combine(first_day, time.min, UTC).timestamp()
    end = datetime.combine(today + timedelta(days=1), time.min, UTC).timestamp()
    daily = {
        (today - timedelta(days=offset)).isoformat(): {
            "date": (today - timedelta(days=offset)).isoformat(),
            "total": 0, "completed": 0, "failed": 0, "cancelled": 0,
        }
        for offset in range(6, -1, -1)
    }
    with store._connect() as db:
        totals = db.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END) AS completed, "
            "SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) AS failed, "
            "SUM(CASE WHEN status='cancelled' THEN 1 ELSE 0 END) AS cancelled, "
            "SUM(CASE WHEN status IN ('queued','running') THEN 1 ELSE 0 END) AS active, "
            "MAX(created) AS last_created FROM turns WHERE owner=?", (owner,)
        ).fetchone()
        rows = db.execute(
            "SELECT date(created, 'unixepoch') AS day, status, COUNT(*) AS count "
            "FROM turns WHERE owner=? AND created>=? AND created<? "
            "GROUP BY day,status", (owner, start, end)
        ).fetchall()
    for row in rows:
        bucket = daily.get(row["day"])
        if bucket is None:
            continue
        amount = int(row["count"])
        bucket["total"] += amount
        if row["status"] in {"completed", "failed", "cancelled"}:
            bucket[row["status"]] += amount
    return {
        "turnCounts": {
            "total": int(totals["total"] or 0),
            "completed": int(totals["completed"] or 0),
            "failed": int(totals["failed"] or 0),
            "cancelled": int(totals["cancelled"] or 0),
            "active": int(totals["active"] or 0),
        },
        "lastTurnAt": _iso_utc(totals["last_created"]),
        "turnCountsByDay": list(daily.values()),
    }


def build_overview(store: Any, subject: str, *, observed_at: datetime | None = None,
                   core_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Project a verified principal's actual chat statistics and current core witness."""
    moment = observed_at or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC)
    aggregate = _aggregate(store, subject, today=moment.date())
    owner = store._owner(subject)
    with store._connect() as db:
        conversations = db.execute(
            "SELECT COUNT(*) FROM conversations WHERE owner=?", (owner,)
        ).fetchone()[0]
    projection = core_projection or {}
    counts = projection.get("resource_counts")
    return {
        "core": {
            "status": "process-observed",
            "readiness": "current-core-witness",
            "observedAt": moment.isoformat(timespec="seconds").replace("+00:00", "Z"),
            "version": projection.get("core_version"),
            "resourcesState": projection.get("resources_state", "pending"),
            "resourceCounts": counts,
            "resourcesRevision": projection.get("resources_revision"),
            "discoveryObservedAt": projection.get("discovery_observed_at_utc"),
            "activePromptMatchesBundledPrimary": projection.get("active_prompt_matches_bundled_primary"),
        },
        "chat": {
            "conversationCount": int(conversations),
            **aggregate,
        },
        "capabilities": {
            "readiness": "pending",
            "bundledSkills": 396,
            "bundledProfiles": 208,
            "bundledInternalProfiles": 207,
            "discoveryState": projection.get("resources_state", "pending"),
            "discoveredResourceCounts": counts,
        },
    }


def _short_text(value: Any, *, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    cleaned = " ".join("".join(ch for ch in value if ch >= " " and ch != "\x7f").split())
    return cleaned[:limit]


@lru_cache(maxsize=1)
def _verified_bundle_inventory() -> dict[str, Any]:
    """Read declarations only after the installer verifies its pinned offline bundle."""
    from ..registry.native import NativeRegistry
    from ..registry.source import load_bundled_source

    registry = NativeRegistry.from_verified_source(load_bundled_source())
    discovery = registry.discover_all()
    items = []
    for resolved in discovery.resources:
        resource = resolved.resource
        metadata = resource.body.get("metadata", {})
        display_name = _short_text(metadata.get("name"), limit=120)
        if not display_name:
            display_name = resource.id.replace("-", " ").replace("_", " ").title()
        summary = _short_text(metadata.get("description"), limit=240)
        items.append({
            "id": resource.id,
            "kind": resource.kind.value,
            "name": display_name,
            "summary": summary,
            "state": "bundled",
            "readiness": "pending",
        })
    items.sort(key=lambda item: (item["kind"], item["id"]))
    return {
        "readiness": "pending",
        "source": {
            "kind": "offline-bundle",
            "catalogVersion": registry.source.catalog_version,
            "revision": registry.source.revision,
        },
        "items": tuple(items),
    }


def build_capabilities(core_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    inventory = _verified_bundle_inventory()
    projection = core_projection or {}
    return {**inventory, "items": [dict(item) for item in inventory["items"]],
        "nativeDiscovery": {
            "state": projection.get("resources_state", "pending"),
            "resourceCounts": projection.get("resource_counts"),
            "resourcesRevision": projection.get("resources_revision"),
            "observedAt": projection.get("discovery_observed_at_utc"),
            "activePromptMatchesBundledPrimary": projection.get("active_prompt_matches_bundled_primary"),
        }}


def build_settings(core_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return only values present in the fixed root-signed sanitized projection."""
    projection = core_projection or {}
    pending = {"value": None, "status": "pending"}
    version = projection.get("core_version")
    return {
        "readiness": "pending" if not projection.get("provider") or not projection.get("model") else "configured",
        "provider": ({"value": projection["provider"], "status": "configured"}
                     if projection.get("provider") else dict(pending)),
        "model": ({"value": projection["model"], "status": "configured"}
                  if projection.get("model") else dict(pending)),
        "coreVersion": ({"value": version, "status": "verified"} if version else dict(pending)),
    }


def install_jarvis_dashboard_routes(app: Any, service: Any) -> None:
    """Add three bounded GET endpoints to the already protected core gateway app."""
    from aiohttp import web
    from .jarvis_chat import JarvisChatService

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def route(request: Any) -> Any:
        if request.path not in _ROUTES or request.raw_path != request.path:
            raise web.HTTPNotFound(text="not found")
        principal = service._current(request)
        accepted = request.get("core_ingress")
        launch = request.app.get("core_gateway_launch")
        if accepted is None or launch is None:
            raise web.HTTPServiceUnavailable(text="current core projection unavailable")
        try:
            from .core_gateway import CoreAcceptedIngressObservation
            from .core_gateway_inspector import verify_current_core_overview
            if type(accepted) is not CoreAcceptedIngressObservation:
                raise ValueError
            observation = await asyncio.wait_for(
                asyncio.to_thread(verify_current_core_overview, launch.config,
                    peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
                    accepted_ingress=accepted),
                timeout=5.0)
            if observation.core_generation != accepted.core_generation:
                raise ValueError
            core_projection = observation.projection
        except Exception:
            raise web.HTTPServiceUnavailable(text="current core projection unavailable") from None
        if request.path == "/chat/api/overview":
            return web.json_response(build_overview(service.store, principal.subject,
                core_projection=core_projection))
        if request.path == "/chat/api/capabilities":
            try:
                return web.json_response(build_capabilities(core_projection))
            except Exception:
                raise web.HTTPServiceUnavailable(text="capability inventory unavailable") from None
        return web.json_response(build_settings(core_projection))

    for path in _ROUTES:
        app.router.add_get(path, route, allow_head=False)
