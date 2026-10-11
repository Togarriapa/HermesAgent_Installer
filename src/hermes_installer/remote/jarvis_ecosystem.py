"""Bounded owner read projection for root-observed Jarvis worker activity."""
from __future__ import annotations

import asyncio
import hashlib
import math
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from .jarvis_chat import JarvisChatDenied, JarvisChatService, _secure_headers

FEATURE_ROUTES = (("GET", "/chat/api/ecosystem"),)

_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z", re.ASCII)
_HASH = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}\Z", re.ASCII)
_STATUSES = frozenset({"admitted", "running", "responded", "completed", "unknown"})
_EVENT_KINDS = frozenset({"admitted", "attempt", "response", "tool_call", "completed"})
_EVENT_STATUSES = frozenset({"accepted", "started", "completed", "incomplete", "observed"})
_MAX_INSTANCES = 100
_MAX_EVENTS = 200
_WINDOW_SECONDS = 7 * 24 * 60 * 60


def _timestamp(value: Any) -> str:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("native activity timestamp is invalid")
    try:
        return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise ValueError("native activity timestamp is invalid") from None


def project_native_activity_snapshot(value: Any) -> dict[str, Any]:
    """Validate and sanitize the sealed-root activity DTO for the browser."""
    if (type(value) is not dict or set(value) != {
            "schema", "observed_at", "window_seconds", "coverage", "instances", "relations"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or type(value["window_seconds"]) is not int or value["window_seconds"] != _WINDOW_SECONDS
            or value["coverage"] != "observed-callbacks"
            or type(value["instances"]) is not list or len(value["instances"]) > _MAX_INSTANCES
            or value["relations"] != []):
        raise ValueError("root activity snapshot schema is invalid")
    observed_at = _timestamp(value["observed_at"])
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    event_total = 0
    expert_stats: dict[tuple[str, str], dict[str, Any]] = {}
    observed_active = completed_observed = tool_calls_observed = 0
    response_duration_ms = 0
    response_duration_count = 0
    any_stale = False

    for item in value["instances"]:
        fields = {
            "execution_key", "display_alias", "gateway_turn_id", "mission_id", "mission_revision",
            "profile_id", "source_revision", "source_generation_sha256", "status", "stale",
            "created_at", "updated_at", "tool_count", "events",
        }
        if type(item) is not dict or set(item) != fields:
            raise ValueError("root activity instance schema is invalid")
        key = item["execution_key"]
        alias = item["display_alias"]
        profile = item["profile_id"]
        revision = item["source_revision"]
        if (not isinstance(key, str) or _ID.fullmatch(key) is None or key in seen
                or not isinstance(alias, str) or _ALIAS.fullmatch(alias) is None
                or not isinstance(profile, str) or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", profile) is None
                or not isinstance(revision, str) or not 1 <= len(revision) <= 128
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in revision)
                or not isinstance(item["source_generation_sha256"], str)
                or _HASH.fullmatch(item["source_generation_sha256"]) is None
                or not isinstance(item["gateway_turn_id"], str) or _ID.fullmatch(item["gateway_turn_id"]) is None
                or item["mission_id"] is not None and (
                    not isinstance(item["mission_id"], str) or _ID.fullmatch(item["mission_id"]) is None)
                or item["mission_revision"] is not None and (
                    type(item["mission_revision"]) is not int or item["mission_revision"] < 1)
                or (item["mission_id"] is None) != (item["mission_revision"] is None)
                or not isinstance(item["status"], str) or item["status"] not in _STATUSES
                or type(item["stale"]) is not bool
                or type(item["tool_count"]) is not int or not 0 <= item["tool_count"] <= 100_000
                or type(item["events"]) is not list or len(item["events"]) > _MAX_EVENTS):
            raise ValueError("root activity instance is malformed")
        seen.add(key)
        event_total += len(item["events"])
        if event_total > _MAX_EVENTS:
            raise ValueError("root activity event cap exceeded")
        created_at = _timestamp(item["created_at"])
        updated_at = _timestamp(item["updated_at"])
        events: list[dict[str, Any]] = []
        completed_events = 0
        instance_tool_calls = 0
        instance_response_duration = 0
        instance_response_duration_count = 0
        for event in item["events"]:
            if (type(event) is not dict or set(event) != {
                    "kind", "status", "at", "duration_ms", "tool_count"}
                    or not isinstance(event["kind"], str) or event["kind"] not in _EVENT_KINDS
                    or not isinstance(event["status"], str) or event["status"] not in _EVENT_STATUSES
                    or type(event["tool_count"]) is not int or not 0 <= event["tool_count"] <= 128
                    or event["duration_ms"] is not None and (
                        type(event["duration_ms"]) is not int or not 0 <= event["duration_ms"] <= 3_600_000)):
                raise ValueError("root activity event is malformed")
            events.append({
                "kind": event["kind"], "status": event["status"],
                "at": _timestamp(event["at"]), "duration_ms": event["duration_ms"],
                "tool_count": event["tool_count"],
            })
            if event["kind"] == "completed" and event["status"] == "completed":
                completed_events += 1
            if event["kind"] == "tool_call" and event["status"] == "observed":
                instance_tool_calls += event["tool_count"]
            if event["kind"] == "response" and event["duration_ms"] is not None:
                instance_response_duration += event["duration_ms"]
                instance_response_duration_count += 1

        status = "unknown" if item["stale"] else item["status"]
        if status == "running":
            observed_active += 1
        completed_observed += completed_events
        # The root row carries the cumulative deduplicated observed tool-call
        # count; its bounded event tail can be shorter than the full run.
        instance_tool_calls = item["tool_count"]
        tool_calls_observed += instance_tool_calls
        response_duration_ms += instance_response_duration
        response_duration_count += instance_response_duration_count
        any_stale = any_stale or item["stale"]
        if profile != "hermes" and completed_events:
            aggregate = expert_stats.setdefault((profile, revision), {
                "profile_id": profile, "source_revision": revision, "completed_executions": 0,
                "observed_tool_calls": 0, "instances": 0,
            })
            aggregate["completed_executions"] += completed_events
            aggregate["observed_tool_calls"] += instance_tool_calls
            aggregate["instances"] += 1
        rows.append({
            "id": key, "display_name": alias, "profile_id": profile,
            "source_revision": revision, "mission_id": item["mission_id"],
            "mission_revision": item["mission_revision"], "state": status,
            "stale": item["stale"], "created_at": created_at, "updated_at": updated_at,
            "observed_tool_calls": instance_tool_calls,
            "completed_executions": completed_events,
            "observed_response_duration_ms": (instance_response_duration
                                              if instance_response_duration_count else None),
            "response_duration_coverage": instance_response_duration_count,
            "events": events,
        })

    partial = (value["coverage"] != "complete" or len(rows) == _MAX_INSTANCES
               or event_total == _MAX_EVENTS or any_stale)
    top_experts = sorted(expert_stats.values(), key=lambda row: (
        -row["completed_executions"], -row["observed_tool_calls"], row["profile_id"], row["source_revision"]))[:10]
    return {
        "schema": 1,
        "observation": {
            "state": "quiet" if not rows else "partial" if partial else "observed",
            "observed_at": observed_at,
            "window": {"from": _timestamp(value["observed_at"] - value["window_seconds"]),
                       "to": observed_at, "seconds": value["window_seconds"]},
            "coverage": value["coverage"], "partial": partial,
        },
        "summary": {
            "observed_instances": len(rows),
            "active_instances": observed_active if not partial else None,
            "observed_active_instances": observed_active,
            "completed_executions": completed_observed if not partial else None,
            "observed_completed_executions": completed_observed,
            "observed_tool_calls": tool_calls_observed,
            "response_duration_ms": response_duration_ms if response_duration_count else None,
            "response_duration_coverage": response_duration_count,
            "event_summaries": event_total,
            "unknown_fields": (["active_instances", "completed_executions"] if partial else []),
        },
        "instances": rows,
        "teams": [],
        "relations": [],
        "top_experts": [{
            **row, "basis": "completed root-observed executions and their observed native tool calls",
            "coverage": value["coverage"], "partial": partial,
        } for row in top_experts],
        "pending": {
            "team_membership": "no_verified_instance_join",
            "communication_edges": "no_verified_sender_recipient_records",
        },
    }


def install_jarvis_ecosystem_routes(app: Any, service: JarvisChatService) -> None:
    """Install the fixed read-only ecosystem snapshot endpoint."""
    from aiohttp import web
    from .core_gateway_inspector import CoreGatewayInspector

    inspector = getattr(service, "inspector", None)
    if (not callable(getattr(service, "_current", None))
            or not callable(getattr(service, "_capture_owner_turn_context", None))
            or type(inspector) is not CoreGatewayInspector):
        raise TypeError("protected Jarvis chat service required")

    async def snapshot(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            proof = service._capture_owner_turn_context(request)
            if (type(proof) is not tuple or len(proof) != 3
                    or type(proof[0]) is not str or proof[1] is None or proof[2] is not None):
                raise JarvisChatDenied("current owner ingress proof is unavailable")
            access_jwt, accepted_ingress, _ = proof
            activity = await asyncio.wait_for(asyncio.to_thread(
                inspector.read_native_activity, access_jwt, accepted_ingress), timeout=5.0)
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner ingress changed during ecosystem read")
            projection = project_native_activity_snapshot(activity)
            return web.json_response(projection, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="ecosystem snapshot unavailable",
                                             headers=_secure_headers()) from None

    app.router.add_get("/chat/api/ecosystem", snapshot)


__all__ = ["FEATURE_ROUTES", "install_jarvis_ecosystem_routes", "project_native_activity_snapshot"]
