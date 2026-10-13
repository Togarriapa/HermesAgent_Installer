"""Bounded owner read projection for root-observed Jarvis worker activity."""
from __future__ import annotations

import asyncio
import math
import re
from datetime import datetime, timezone
from typing import Any

from .jarvis_chat import JarvisChatDenied, JarvisChatService, _secure_headers

FEATURE_ROUTES = (("GET", "/chat/api/ecosystem"),)

_ID = re.compile(r"[A-Za-z0-9_-]{24,64}\Z", re.ASCII)
_HASH = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._·-]{0,47}\Z", re.ASCII)
_TEAM_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z", re.ASCII)
_STATUSES = frozenset({"admitted", "running", "responded", "completed", "unknown"})
_EVENT_KINDS = frozenset({"admitted", "attempt", "response", "tool_call", "completed"})
_EVENT_STATUSES = frozenset({"accepted", "started", "completed", "incomplete", "observed"})
_MAX_INSTANCES = 100
_MAX_EVENTS = 200
_MAX_TEAMS = 100
_MAX_RELATIONS = 200
_WINDOW_SECONDS = 7 * 24 * 60 * 60
_TEAM_STATES = frozenset({"current", "historical", "stale", "partial"})


def _timestamp_seconds(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("native activity timestamp is invalid")
    return float(value)


def _timestamp(value: Any) -> str:
    seconds = _timestamp_seconds(value)
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        raise ValueError("native activity timestamp is invalid") from None


def _source_revision(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 128
            and all(0x21 <= ord(char) <= 0x7e for char in value))


def project_native_activity_snapshot(value: Any) -> dict[str, Any]:
    """Validate and sanitize the sealed-root activity DTO for the browser."""
    if type(value) is not dict or type(value.get("schema")) is not int:
        raise ValueError("root activity snapshot schema is invalid")
    schema = value["schema"]
    base_fields = {"schema", "observed_at", "window_seconds", "coverage", "instances", "relations"}
    if schema == 1:
        expected_fields = base_fields
    elif schema == 2:
        expected_fields = base_fields | {"partial", "team_instances"}
    else:
        raise ValueError("root activity snapshot schema is invalid")
    if (set(value) != expected_fields
            or type(value["window_seconds"]) is not int or value["window_seconds"] != _WINDOW_SECONDS
            or value["coverage"] != "observed-callbacks"
            or type(value["instances"]) is not list or len(value["instances"]) > _MAX_INSTANCES
            or type(value["relations"]) is not list or len(value["relations"]) > _MAX_RELATIONS
            or schema == 1 and value["relations"] != []
            or schema == 2 and (type(value["partial"]) is not bool
                                or type(value["team_instances"]) is not list
                                or len(value["team_instances"]) > _MAX_TEAMS)):
        raise ValueError("root activity snapshot schema is invalid")
    observed_seconds = _timestamp_seconds(value["observed_at"])
    window_start = observed_seconds - value["window_seconds"]
    observed_at = _timestamp(observed_seconds)
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    event_total = 0
    expert_stats: dict[tuple[str, str], dict[str, Any]] = {}
    observed_active = completed_observed = tool_calls_observed = 0
    response_duration_ms = 0
    response_duration_count = 0
    any_stale = False
    instance_by_key: dict[str, dict[str, Any]] = {}

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
        instance_by_key[key] = item
        event_total += len(item["events"])
        if event_total > _MAX_EVENTS:
            raise ValueError("root activity event cap exceeded")
        created_seconds = _timestamp_seconds(item["created_at"])
        updated_seconds = _timestamp_seconds(item["updated_at"])
        if (not window_start <= created_seconds <= observed_seconds
                or not window_start <= updated_seconds <= observed_seconds
                or created_seconds > updated_seconds):
            raise ValueError("root activity instance time is outside the observation window")
        created_at = _timestamp(created_seconds)
        updated_at = _timestamp(updated_seconds)
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
            event_seconds = _timestamp_seconds(event["at"])
            if not window_start <= event_seconds <= observed_seconds:
                raise ValueError("root activity event time is outside the observation window")
            events.append({
                "kind": event["kind"], "status": event["status"],
                "at": _timestamp(event_seconds), "duration_ms": event["duration_ms"],
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
        current_completed_events = completed_events if status == "completed" else 0
        completed_observed += current_completed_events
        # The root row carries the cumulative deduplicated observed tool-call
        # count; its bounded event tail can be shorter than the full run.
        instance_tool_calls = item["tool_count"]
        tool_calls_observed += instance_tool_calls
        response_duration_ms += instance_response_duration
        response_duration_count += instance_response_duration_count
        any_stale = any_stale or item["stale"]
        if profile != "hermes" and current_completed_events:
            aggregate = expert_stats.setdefault((profile, revision), {
                "profile_id": profile, "source_revision": revision, "completed_executions": 0,
                "observed_tool_calls": 0, "instances": 0,
            })
            aggregate["completed_executions"] += current_completed_events
            aggregate["observed_tool_calls"] += instance_tool_calls
            aggregate["instances"] += 1
        rows.append({
            "id": key, "display_name": alias, "profile_id": profile,
            "source_revision": revision, "mission_id": item["mission_id"],
            "mission_revision": item["mission_revision"], "state": status,
            "stale": item["stale"], "created_at": created_at, "updated_at": updated_at,
            "observed_tool_calls": instance_tool_calls,
            "completed_executions": current_completed_events,
            "observed_response_duration_ms": (instance_response_duration
                                              if instance_response_duration_count else None),
            "response_duration_coverage": instance_response_duration_count,
            "events": events,
        })

    partial = (value["coverage"] != "complete" or len(rows) == _MAX_INSTANCES
               or event_total == _MAX_EVENTS or any_stale
               or value.get("partial") is True)
    teams: list[dict[str, Any]] = []
    projected_relations: list[dict[str, Any]] = []
    team_by_key: dict[str, dict[str, Any]] = {}
    team_member_keys: set[str] = set()
    relation_keys: set[str] = set()
    relation_team_keys: set[str] = set()
    if schema == 2:
        for team in value["team_instances"]:
            fields = {"team_execution_key", "team_id", "source_revision", "mission_id",
                      "mission_revision", "members", "state", "coverage"}
            team_key = team.get("team_execution_key") if type(team) is dict else None
            mission_id = team.get("mission_id") if type(team) is dict else None
            revision = team.get("mission_revision") if type(team) is dict else None
            members = team.get("members") if type(team) is dict else None
            if (type(team) is not dict or set(team) != fields
                    or not isinstance(team_key, str) or _ID.fullmatch(team_key) is None
                    or team_key in team_by_key
                    or not isinstance(team["team_id"], str) or _TEAM_ID.fullmatch(team["team_id"]) is None
                    or not _source_revision(team["source_revision"])
                    or not isinstance(mission_id, str) or _ID.fullmatch(mission_id) is None
                    or type(revision) is not int or revision < 1
                    or type(members) is not list or not 1 <= len(members) <= 32
                    or any(not isinstance(member, str) or _ID.fullmatch(member) is None for member in members)
                    or len(set(members)) != len(members)
                    or not isinstance(team["state"], str) or team["state"] not in _TEAM_STATES
                    or not isinstance(team["coverage"], str)
                    or team["coverage"] not in {"observed-callbacks", "partial"}):
                raise ValueError("root activity Team instance is malformed")
            member_rows = [instance_by_key.get(member) for member in members]
            if (any(row is None for row in member_rows)
                    or any(row["mission_id"] != mission_id or row["mission_revision"] != revision
                           for row in member_rows)
                    or team_member_keys.intersection(members)):
                raise ValueError("root activity Team membership does not join included instances")
            team_member_keys.update(members)
            team_by_key[team_key] = team
            team_partial = team["state"] == "partial" or team["coverage"] == "partial"
            team_stale = team["state"] == "stale"
            partial = partial or team_partial or team_stale
            any_stale = any_stale or team_stale
            teams.append({
                "id": team_key, "team_execution_key": team_key,
                "team_id": team["team_id"], "name": team["team_id"],
                "source_revision": team["source_revision"], "mission_id": mission_id,
                "mission_revision": revision, "members": list(members),
                "state": team["state"], "coverage": team["coverage"],
                "partial": team_partial,
            })

        for relation in value["relations"]:
            fields = {"relation_key", "team_execution_key", "mission_id", "mission_revision",
                      "sender_execution_key", "recipient_execution_key", "kind", "event_at",
                      "state", "coverage"}
            if (type(relation) is not dict or set(relation) != fields
                    or not isinstance(relation["relation_key"], str)
                    or _ID.fullmatch(relation["relation_key"]) is None
                    or relation["relation_key"] in relation_keys
                    or not isinstance(relation["team_execution_key"], str)
                    or relation["team_execution_key"] not in team_by_key
                    or relation["team_execution_key"] in relation_team_keys
                    or not isinstance(relation["mission_id"], str)
                    or _ID.fullmatch(relation["mission_id"]) is None
                    or type(relation["mission_revision"]) is not int
                    or relation["mission_revision"] < 1
                    or not isinstance(relation["sender_execution_key"], str)
                    or not isinstance(relation["recipient_execution_key"], str)
                    or relation["sender_execution_key"] == relation["recipient_execution_key"]
                    or relation["kind"] != "completed_message"
                    or not isinstance(relation["state"], str) or relation["state"] not in _TEAM_STATES
                    or not isinstance(relation["coverage"], str)
                    or relation["coverage"] not in {"observed-callbacks", "partial"}):
                raise ValueError("root activity Team relation is malformed")
            event_seconds = _timestamp_seconds(relation["event_at"])
            team = team_by_key[relation["team_execution_key"]]
            sender = instance_by_key.get(relation["sender_execution_key"])
            recipient = instance_by_key.get(relation["recipient_execution_key"])
            if (not window_start <= event_seconds <= observed_seconds
                    or relation["mission_id"] != team["mission_id"]
                    or relation["mission_revision"] != team["mission_revision"]
                    or relation["sender_execution_key"] not in team["members"]
                    or relation["recipient_execution_key"] not in team["members"]
                    or sender is None or recipient is None
                    or sender["mission_id"] != relation["mission_id"]
                    or recipient["mission_id"] != relation["mission_id"]
                    or sender["mission_revision"] != relation["mission_revision"]
                    or recipient["mission_revision"] != relation["mission_revision"]
                    or event_seconds < max(sender["created_at"], recipient["created_at"])
                    or event_seconds > recipient["updated_at"]
                    or relation["state"] in {"current", "historical"}
                       and (sender["status"] != "completed" or recipient["status"] != "completed")):
                raise ValueError("root activity Team relation does not join its instances")
            relation_keys.add(relation["relation_key"])
            relation_team_keys.add(relation["team_execution_key"])
            relation_partial = (relation["state"] == "partial" or relation["coverage"] == "partial")
            relation_stale = relation["state"] == "stale"
            partial = partial or relation_partial or relation_stale
            any_stale = any_stale or relation_stale
            projected_relations.append({
                "id": relation["relation_key"], "team_id": relation["team_execution_key"],
                "team_execution_key": relation["team_execution_key"],
                "mission_id": relation["mission_id"],
                "mission_revision": relation["mission_revision"],
                "from": relation["sender_execution_key"],
                "to": relation["recipient_execution_key"],
                "sender_execution_key": relation["sender_execution_key"],
                "recipient_execution_key": relation["recipient_execution_key"],
                "kind": relation["kind"], "at": _timestamp(event_seconds),
                "state": relation["state"], "coverage": relation["coverage"],
                "partial": relation_partial,
            })

    partial = partial or any_stale
    top_experts = sorted(expert_stats.values(), key=lambda row: (
        -row["completed_executions"], -row["observed_tool_calls"], row["profile_id"], row["source_revision"]))[:10]
    return {
        "schema": 2,
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
        "teams": teams,
        "relations": projected_relations,
        "top_experts": [{
            **row, "basis": "completed root-observed executions and their observed native tool calls",
            "coverage": value["coverage"], "partial": partial,
        } for row in top_experts],
        "pending": {
            "team_membership": "verified" if teams else "no_verified_instance_join",
            "communication_edges": ("verified" if projected_relations
                                     else "no_verified_sender_recipient_records"),
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
