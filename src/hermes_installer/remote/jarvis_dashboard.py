"""Finite, read-only Jarvis overview APIs backed by current owner data.

These routes are composed into the protected core gateway. They expose aggregate chat
records and the integrity-checked offline Resources catalog; source presence remains
separate from native discovery, activation, or functional readiness.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import secrets
import sqlite3
from datetime import datetime, time, timedelta, timezone
from functools import lru_cache
from importlib.resources import files as package_files
from typing import Any

UTC = timezone.utc
_ROUTES = {
    "/chat/api/overview": "overview",
    "/chat/api/calendar": "calendar",
    "/chat/api/capabilities": "capabilities",
    "/chat/api/settings": "settings",
    "/chat/api/resources/learning": "learning",
}
_BUNDLE_INVENTORY_NAME = "jarvis_capability_inventory.json"
_BUNDLE_INVENTORY_SHA256 = "16ba9ef9b5a5a727cbfa29a43f12862e3aca6deb1a57cab52f9d7d9b96610860"
_BUNDLE_INVENTORY_COUNTS = {
    "bundles": 55, "channels": 5, "crons": 4, "mcps": 3,
    "plugins": 18, "profiles": 208, "skills": 396, "webhooks": 3,
}
_NATIVE_ID_KEY = secrets.token_bytes(32)


def _iso_utc(timestamp: float | None) -> str | None:
    if timestamp is None:
        return None
    try:
        value = datetime.fromtimestamp(float(timestamp), UTC)
    except (OverflowError, OSError, TypeError, ValueError):
        return None
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


_DURATION_SAMPLE_LIMIT = 100
_TURN_DURATION_LIMIT_MS = 600_000


def _aggregate(store: Any, subject: str, *, observed_at: datetime) -> dict[str, Any]:
    """Read this principal's bounded turn window and current lifetime totals."""
    owner = store._owner(subject)
    first_day = observed_at.date() - timedelta(days=6)
    start = datetime.combine(first_day, time.min, UTC).timestamp()
    end = observed_at.timestamp()
    daily = {
        (observed_at.date() - timedelta(days=offset)).isoformat(): {
            "date": (observed_at.date() - timedelta(days=offset)).isoformat(),
            "total": 0, "completed": 0, "failed": 0, "cancelled": 0,
        }
        for offset in range(6, -1, -1)
    }
    window_counts = {
        "total": 0, "active": 0, "completed": 0, "failed": 0,
        "cancelled": 0, "unknown": 0,
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
        duration_rows = db.execute(
            "SELECT status,created,updated,COUNT(*) OVER () AS candidate_count FROM turns WHERE owner=? "
            "AND status IN ('completed','failed','cancelled') "
            "AND created>=? AND created<? ORDER BY created DESC LIMIT ?",
            (owner, start, end, _DURATION_SAMPLE_LIMIT),
        ).fetchall()
    for row in rows:
        amount = int(row["count"])
        window_counts["total"] += amount
        status = row["status"]
        if status in {"queued", "running"}:
            window_counts["active"] += amount
        elif status in {"completed", "failed", "cancelled"}:
            window_counts[status] += amount
        else:
            window_counts["unknown"] += amount
        bucket = daily.get(row["day"])
        if bucket is not None:
            bucket["total"] += amount
            if status in {"completed", "failed", "cancelled"}:
                bucket[status] += amount
    duration_candidate_count = int(duration_rows[0]["candidate_count"]) if duration_rows else 0
    durations = []
    for row in duration_rows:
        try:
            created, updated = float(row["created"]), float(row["updated"])
        except (TypeError, ValueError, OverflowError):
            continue
        elapsed = updated - created
        if (not math.isfinite(created) or not math.isfinite(updated)
                or not math.isfinite(elapsed) or not 0 <= elapsed <= _TURN_DURATION_LIMIT_MS / 1000):
            continue
        duration_ms = round(elapsed * 1000)
        durations.append({
            "status": row["status"],
            "acceptedAt": _iso_utc(created),
            "finishedAt": _iso_utc(updated),
            "durationMs": duration_ms,
        })
    return {
        "turnCounts": {
            "total": int(totals["total"] or 0),
            "completed": int(totals["completed"] or 0),
            "failed": int(totals["failed"] or 0),
            "cancelled": int(totals["cancelled"] or 0),
            "active": int(totals["active"] or 0),
        },
        "lastTurnAt": _iso_utc(totals["last_created"]),
        "statistics": {
            "window": {
                "startAt": _iso_utc(start),
                "endAt": _iso_utc(end),
                "timezone": "UTC",
                "basis": "turn accepted during the seven UTC calendar days ending at observation time",
            },
            "observedAt": _iso_utc(end),
            "turnCounts": window_counts,
            "duration": {
                "basis": "turn accepted to terminal status; elapsed time includes queue time",
                "sampleLimit": _DURATION_SAMPLE_LIMIT,
                "partial": duration_candidate_count > len(durations),
                "omittedCount": max(0, duration_candidate_count - len(durations)),
                "samples": list(reversed(durations)),
            },
        },
        "turnCountsByDay": list(daily.values()),
    }


def _mission_overview(store: Any, owner: str, *, observed_at: float) -> dict[str, Any]:
    """Count only live approvals still bound to their current owner mission revision."""
    try:
        with store._connect() as db:
            tables = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('jarvis_missions','jarvis_mission_approvals')")}
            if tables != {"jarvis_missions", "jarvis_mission_approvals"}:
                return {
                    "state": "unavailable", "approvedPendingCount": None,
                    "reason": "The owner mission approval projection is not installed.",
                }
            count = db.execute(
                "SELECT COUNT(DISTINCT m.id) FROM jarvis_mission_approvals AS a "
                "JOIN jarvis_missions AS m ON m.id=a.mission_id AND m.owner=a.owner "
                "WHERE a.owner=? AND a.status='approved' AND a.expires>? "
                "AND m.status='preview_pending' AND a.revision=m.revision "
                "AND a.plan_sha256=m.plan_sha256 AND a.source_binding=m.source_binding",
                (owner, observed_at),
            ).fetchone()[0]
    except sqlite3.Error:
        return {
            "state": "unavailable", "approvedPendingCount": None,
            "reason": "The owner mission approval projection could not be read.",
        }
    return {"state": "observed", "approvedPendingCount": int(count)}


def build_overview(store: Any, subject: str, *, observed_at: datetime | None = None,
                   core_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Project a verified principal's actual chat statistics and current core witness."""
    moment = observed_at or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    moment = moment.astimezone(UTC)
    owner = store._owner(subject)
    aggregate = _aggregate(store, subject, observed_at=moment)
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
        "missions": _mission_overview(store, owner, observed_at=moment.timestamp()),
        "schedules": {
            "state": "unavailable", "pausedCount": None,
            "reason": ("The current typed schedule projection exposes enabled state but no "
                       "verified paused state."),
        },
        "resources": {
            "discovery": {
                "state": projection.get("resources_state", "pending"),
                "observedAt": projection.get("discovery_observed_at_utc"),
                "counts": counts,
            },
            "dispatch": {
                "state": "unavailable", "count": None,
                "reason": ("The current verified owner projection does not include a count of "
                           "dispatched source identities."),
            },
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


@lru_cache(maxsize=1)
def _verified_bundle_inventory() -> dict[str, Any]:
    """Load only the reviewed packaged inventory; never parse registry YAML at request time."""
    raw = package_files(__package__).joinpath(_BUNDLE_INVENTORY_NAME).read_bytes()
    if hashlib.sha256(raw).hexdigest() != _BUNDLE_INVENTORY_SHA256:
        raise ValueError("packaged capability inventory digest differs")
    value = json.loads(raw)
    if (not isinstance(value, dict) or set(value) != {"readiness", "source", "items"}
            or value.get("readiness") != "pending"
            or value.get("source") != {
                "kind": "offline-bundle", "catalogVersion": "2.3.1",
                "revision": "113f42d33be9e0c8f0f47f5ca998e687323dec83",
            }
            or not isinstance(value.get("items"), list) or len(value["items"]) != 692):
        raise ValueError("packaged capability inventory schema differs")
    counts = {kind: 0 for kind in _BUNDLE_INVENTORY_COUNTS}
    previous = None
    for item in value["items"]:
        if (not isinstance(item, dict)
                or set(item) not in ({"id", "kind", "name", "summary", "state", "readiness"},
                                    {"id", "kind", "name", "summary", "state", "readiness", "displayName"})
                or item.get("kind") not in counts
                or item.get("state") != "bundled" or item.get("readiness") != "pending"
                or not all(isinstance(item.get(key), str) for key in ("id", "name", "summary"))
                or len(item["id"]) > 120 or len(item["name"]) > 120 or len(item["summary"]) > 240
                or ("displayName" in item and (not isinstance(item["displayName"], str)
                                               or len(item["displayName"]) > 120))):
            raise ValueError("packaged capability item schema differs")
        identity = (item["kind"], item["id"])
        if previous is not None and identity <= previous:
            raise ValueError("packaged capability inventory order or uniqueness differs")
        previous = identity
        counts[item["kind"]] += 1
    if counts != _BUNDLE_INVENTORY_COUNTS:
        raise ValueError("packaged capability inventory counts differ")
    return value


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


def _native_id(subject: str, core_generation: str, kind: str, name: str) -> str:
    source = f"jarvis-native-item-v1\0{subject}\0{core_generation}\0{kind}\0{name}".encode("utf-8")
    return hmac.new(_NATIVE_ID_KEY, source, hashlib.sha256).hexdigest()[:32]


def build_settings(core_projection: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return root-verified config labels; native status is added by its strict adapter."""
    projection = core_projection or {}
    pending = {"value": None, "status": "pending"}
    version = projection.get("core_version")
    provider = projection.get("provider")
    model = projection.get("model")
    return {
        "readiness": "pending",
        "provider": ({"value": provider, "status": "configured-unverified"}
                     if provider else dict(pending)),
        "model": ({"value": model, "status": "configured-unverified"}
                  if model else dict(pending)),
        "coreVersion": ({"value": version, "status": "verified"} if version else dict(pending)),
        "accountState": {"value": "unknown", "status": "pending"},
        "plugins": {"state": "unknown", "items": []},
        "mcp": {"state": "unknown", "checkedAt": None, "servers": []},
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
        if request.path == "/chat/api/calendar":
            assertions = request.headers.getall("Cf-Access-Jwt-Assertion", [])
            if len(assertions) != 1:
                raise web.HTTPForbidden(text="current authenticated Calendar ingress is required")
            from datetime import datetime, timedelta
            from zoneinfo import ZoneInfo
            zone_name = "Europe/Lisbon"
            now = datetime.now(ZoneInfo(zone_name)).replace(second=0, microsecond=0)
            start = now.isoformat()
            end = (now + timedelta(days=7)).isoformat()
            try:
                inspector = getattr(service, "inspector", None)
                if inspector is None:
                    raise ValueError
                payload = await asyncio.wait_for(asyncio.to_thread(
                    inspector.read_owner_calendar, assertions[0], accepted,
                    calendar_ref=None, start_time=start, end_time=end,
                    timezone_name=zone_name, page_size=100), timeout=5.0)
                current = service._current(request)
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation
                        or accepted.verify_current(launch.config) is not True):
                    raise ValueError
                return web.json_response(payload, dumps=lambda value: json.dumps(
                    value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            except Exception:
                # A root producer failure is an unavailable state, never a fixture or
                # a readiness claim. Keep the precise enrollment step actionable.
                from .jarvis_calendar import project_calendar_page
                payload = project_calendar_page({"status": "unavailable", "events": [],
                    "account_label": "Selected connection · identity unknown",
                    "calendar_label": "", "next_step": (
                    "Calendar is not enrolled. Resume the root-managed Google Calendar setup "
                        "with a read-only mcp:google-calendar:read credential, select a calendar, then refresh.")},
                    timezone_name=zone_name, window_start=start, window_end=end,
                    observed_at=datetime.now(UTC).isoformat())
                return web.json_response(payload, status=200, dumps=lambda value: json.dumps(
                    value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
        if request.path == "/chat/api/resources/learning":
            try:
                assertions = request.headers.getall("Cf-Access-Jwt-Assertion", [])
                if len(assertions) != 1:
                    raise ValueError
                from .core_gateway_inspector import verify_current_skill_learning
                observation = await asyncio.wait_for(asyncio.to_thread(
                    verify_current_skill_learning, launch.config,
                    access_jwt=assertions[0], accepted_ingress=accepted), timeout=5.0)
                from .jarvis_learning import build_learning_projection
                payload = build_learning_projection(
                    observation, config=launch.config,
                    peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid,
                    peer_gid=accepted.peer_gid, accepted_ingress=accepted)
                current = service._current(request)
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation
                        or observation.verify_current(launch.config,
                            peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid,
                            peer_gid=accepted.peer_gid, accepted_ingress=accepted) is not True):
                    raise ValueError
                return web.json_response(
                    payload, dumps=lambda value: json.dumps(
                        value, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
            except Exception:
                raise web.HTTPServiceUnavailable(
                    text="current native learning review is unavailable") from None
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

        def verify_before_response() -> None:
            try:
                current = service._current(request)
                from .core_gateway_inspector import CoreVerifiedOverviewObservation
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation
                        or type(observation) is not CoreVerifiedOverviewObservation
                        or observation.verify_current(launch.config,
                            peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid,
                            peer_gid=accepted.peer_gid, accepted_ingress=accepted) is not True):
                    raise ValueError
            except Exception:
                raise web.HTTPServiceUnavailable(
                    text="current core projection expired") from None

        if request.path == "/chat/api/overview":
            payload = build_overview(service.store, principal.subject,
                core_projection=core_projection)
            verify_before_response()
            return web.json_response(payload)
        if request.path == "/chat/api/capabilities":
            try:
                payload = build_capabilities(core_projection)
                verify_before_response()
                return web.json_response(payload)
            except Exception:
                raise web.HTTPServiceUnavailable(text="capability inventory unavailable") from None
        plugins = None
        mcp = None
        try:
            list_plugins = getattr(service.backend, "list_plugins")
            mcp_status = getattr(service.backend, "mcp_status")
            plugin_snapshot, mcp_snapshot = await asyncio.wait_for(
                asyncio.gather(list_plugins(), mcp_status()), timeout=1.5)
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise ValueError
            plugins = {"plugins": plugin_snapshot}
            mcp = mcp_snapshot
        except Exception:
            # Status is additive. A failure leaves it explicitly unknown; it never
            # falls back to a config/catalog inventory or blocks the dashboard.
            try:
                current = service._current(request)
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation):
                    raise ValueError
            except Exception:
                raise web.HTTPForbidden(text="forbidden") from None
        base = build_settings(core_projection)
        try:
            from .jarvis_native_controls import build_native_controls_snapshot, decode_native_controls
            payload = build_native_controls_snapshot(
                provider=base["provider"], model=base["model"],
                core_version=base["coreVersion"], plugins=plugins, mcp=mcp,
                opaque_id=lambda kind, name: _native_id(
                    principal.subject, principal.core_generation, kind, name))
            snapshot = decode_native_controls(payload.to_public_dict())
            public_payload = snapshot.to_public_dict()
            verify_before_response()
            return web.json_response(public_payload)
        except Exception:
            # The adapter is separately pinned/composed. Its absence or a strict
            # decode failure leaves the fixed settings projection pending.
            verify_before_response()
            return web.json_response(base)

    for path in _ROUTES:
        app.router.add_get(path, route, allow_head=False)
