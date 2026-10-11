"""Sanitized, owner-bound activity observations from one native Hermes chat stream.

The browser never supplies native event dictionaries. ``CoreRpcClient`` projects the
pinned websocket frames into ``NativeActivityEvent`` first; this module persists only a
closed observation schema and never stores tool arguments, results, paths, or credentials.
"""
from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

ACTIVITY_PAGE_SIZE = 50
ACTIVITY_MAX_PAGE = 1000
ACTIVITY_MAX_PER_TURN = 500
ACTIVITY_TYPES = frozenset({
    "tool.start", "tool.complete", "tool.generating", "status.update",
    "subagent.spawn_requested", "subagent.start", "subagent.progress",
    "subagent.thinking", "subagent.tool", "subagent.complete",
    "approval", "approval.cancelled", "request.cancel", "todo.updated",
    "session.usage", "message.complete",
})
_STATUSES = frozenset({
    "running", "completed", "failed", "error", "timeout", "interrupted",
    "cancelled", "pending", "queued", "generating", "updated", "unknown",
    "status", "lifecycle", "compacting", "goal", "loop", "heartbeat", "process",
    "observed", "complete", "returned",
})
_USAGE_FIELDS = (
    "input", "output", "reasoning", "prompt", "completion", "total", "calls",
    "compressions", "context_used", "context_max", "cache_hit_pct", "cache_read",
    "cache_write", "active_subagents",
)
_MAX_COUNTER = 10**15


@dataclass(frozen=True, slots=True)
class NativeActivityEvent:
    """Closed native event projection; ``session_id`` is for server correlation only."""

    event_type: str
    status: str
    session_id: str = field(repr=False)
    source_identity: str | None = field(default=None, repr=False)
    duration_ms: int | None = None
    usage: tuple[tuple[str, int], ...] | None = None
    source_at: float | None = None

    def __post_init__(self) -> None:
        if self.event_type not in ACTIVITY_TYPES:
            raise ValueError("unsupported native activity type")
        if self.status not in _STATUSES:
            raise ValueError("unsupported native activity status")
        if not isinstance(self.session_id, str) or not 1 <= len(self.session_id) <= 512:
            raise ValueError("invalid native activity session")
        if self.source_identity is not None and (
                not isinstance(self.source_identity, str) or not 1 <= len(self.source_identity) <= 512):
            raise ValueError("invalid native activity identity")
        if self.duration_ms is not None and (
                type(self.duration_ms) is not int or not 0 <= self.duration_ms <= 3_600_000):
            raise ValueError("invalid native activity duration")
        if self.source_at is not None and (
                type(self.source_at) not in (float, int) or not math.isfinite(self.source_at)
                or self.source_at < 0):
            raise ValueError("invalid native activity source time")
        if self.usage is not None:
            if (not isinstance(self.usage, tuple) or any(
                    not isinstance(pair, tuple) or len(pair) != 2
                    or pair[0] not in _USAGE_FIELDS or type(pair[1]) is not int
                    or not 0 <= pair[1] <= _MAX_COUNTER for pair in self.usage)):
                raise ValueError("invalid native activity counters")


def _identity_digest(event: NativeActivityEvent, turn_id: str, generation: str) -> str | None:
    if event.source_identity is None:
        return None
    raw = "\0".join((generation, turn_id, event.event_type, event.source_identity))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _public_record(row: Mapping[str, Any]) -> dict[str, Any]:
    usage = None
    if row["usage"]:
        try:
            decoded = json.loads(row["usage"])
            if isinstance(decoded, dict) and all(
                    key in _USAGE_FIELDS and type(value) is int and 0 <= value <= _MAX_COUNTER
                    for key, value in decoded.items()):
                usage = {key: decoded.get(key) for key in _USAGE_FIELDS}
                # Hermes' session usage projection has no authoritative billed-dollar field.
                usage["cost_usd"] = None
        except (TypeError, ValueError):
            usage = None
    return {
        "source_event_id": row["source_event_id"],
        "type": row["event_type"],
        "sequence": row["sequence"],
        "observed_at": row["observed_at"],
        "source_at": row["source_at"],
        "status": row["status"],
        "duration_ms": row["duration_ms"],
        "usage": usage,
    }


class JarvisActivityStore:
    """Activity persistence sharing the existing protected Jarvis chat database."""

    def __init__(self, chat_store: Any):
        if not callable(getattr(chat_store, "_connect", None)):
            raise TypeError("protected Jarvis chat store required")
        self._chat_store = chat_store
        with self._chat_store._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS activity_events(
                turn_id TEXT NOT NULL REFERENCES turns(id) ON DELETE CASCADE,
                sequence INTEGER NOT NULL,
                dedupe_key TEXT,
                source_event_id TEXT,
                event_type TEXT NOT NULL,
                observed_at REAL NOT NULL,
                source_at REAL,
                status TEXT NOT NULL,
                duration_ms INTEGER,
                usage TEXT,
                PRIMARY KEY(turn_id,sequence),
                UNIQUE(turn_id,dedupe_key))""")
            db.execute("CREATE INDEX IF NOT EXISTS activity_recent ON activity_events(observed_at DESC,turn_id,sequence DESC)")

    def record_core_event(self, *, principal: Any, conversation_id: str, turn_id: str,
                          core_generation: str, event: NativeActivityEvent) -> dict[str, Any] | None:
        """Persist only a validated event correlated to the current principal/session/turn."""
        from .jarvis_chat import ChatPrincipal, JarvisChatDenied
        if not isinstance(principal, ChatPrincipal) or not isinstance(event, NativeActivityEvent):
            raise JarvisChatDenied("native activity observation is invalid")
        if (principal.core_generation != core_generation or event.source_at is not None
                and not math.isfinite(event.source_at)):
            raise JarvisChatDenied("native activity generation is stale")
        turn = self._chat_store.owned_turn(principal.subject, turn_id)
        if (turn["conversation_id"] != conversation_id
                or turn["core_generation"] != core_generation
                or turn["runtime_session_id"] != event.session_id
                or turn["status"] not in {"queued", "running"}
                or time.monotonic() >= min(turn["heartbeat_expiry"], turn["jwt_expiry"])):
            raise JarvisChatDenied("native activity ownership mapping changed")
        dedupe = _identity_digest(event, turn_id, core_generation)
        source_id = None if dedupe is None else "evt_" + dedupe[:32]
        usage = None if event.usage is None else json.dumps(dict(event.usage), sort_keys=True,
                                                            separators=(",", ":"))
        now = time.time()
        with self._chat_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            owner = self._chat_store._owner(principal.subject)
            current = db.execute(
                "SELECT t.conversation_id,t.core_generation,t.runtime_session_id,t.status,"
                "t.heartbeat_expiry,t.jwt_expiry,c.owner FROM turns t "
                "JOIN conversations c ON c.id=t.conversation_id WHERE t.id=?", (turn_id,)
            ).fetchone()
            if (current is None or current["owner"] != owner
                    or current["conversation_id"] != conversation_id
                    or current["core_generation"] != core_generation
                    or current["runtime_session_id"] != event.session_id
                    or current["status"] not in {"queued", "running"}
                    or time.monotonic() >= min(current["heartbeat_expiry"], current["jwt_expiry"])):
                db.execute("ROLLBACK")
                raise JarvisChatDenied("native activity ownership mapping changed")
            count = db.execute("SELECT COUNT(*) FROM activity_events WHERE turn_id=?", (turn_id,)).fetchone()[0]
            if count >= ACTIVITY_MAX_PER_TURN:
                db.execute("ROLLBACK")
                return None
            sequence = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM activity_events WHERE turn_id=?",
                                  (turn_id,)).fetchone()[0]
            try:
                db.execute("INSERT INTO activity_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                           (turn_id, sequence, dedupe, source_id, event.event_type, now, event.source_at,
                            event.status, event.duration_ms, usage))
            except sqlite3.IntegrityError:
                db.execute("ROLLBACK")
                return None
            row = db.execute("SELECT * FROM activity_events WHERE turn_id=? AND sequence=?",
                             (turn_id, sequence)).fetchone()
            stream_sequence = db.execute(
                "SELECT COALESCE(MAX(sequence),0)+1 FROM turn_events WHERE turn_id=?", (turn_id,)
            ).fetchone()[0]
            db.execute("INSERT INTO turn_events VALUES(?,?,?,?)", (
                turn_id, stream_sequence, "activity.event",
                json.dumps({"sequence": sequence, **_public_record(row)}, sort_keys=True,
                           separators=(",", ":")),
            ))
            db.execute("COMMIT")
        return _public_record(row)

    def for_turn(self, subject: str, turn_id: str, *, before: int | None = None,
                 limit: int = ACTIVITY_PAGE_SIZE) -> tuple[list[dict[str, Any]], int | None]:
        from .jarvis_chat import JarvisChatDenied
        if (type(limit) is not int or not 1 <= limit <= 100
                or before is not None and (type(before) is not int or before < 1)):
            raise JarvisChatDenied("activity page is invalid")
        turn = self._chat_store.owned_turn(subject, turn_id)
        params: list[Any] = [turn_id]
        where = "turn_id=?"
        if before is not None:
            where += " AND sequence<?"
            params.append(before)
        params.append(limit + 1)
        with self._chat_store._connect() as db:
            rows = db.execute(f"SELECT * FROM activity_events WHERE {where} ORDER BY sequence DESC LIMIT ?",
                              params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        rows.reverse()
        next_before = rows[0]["sequence"] if has_more and rows else None
        return [_public_record(row) for row in rows], next_before

    def recent_for_owner(self, subject: str, *, page: int = 0,
                         limit: int = ACTIVITY_PAGE_SIZE) -> dict[str, Any]:
        from .jarvis_chat import JarvisChatDenied
        if (type(page) is not int or not 0 <= page <= ACTIVITY_MAX_PAGE
                or type(limit) is not int or not 1 <= limit <= 100):
            raise JarvisChatDenied("activity page is invalid")
        owner = self._chat_store._owner(subject)
        offset = page * limit
        with self._chat_store._connect() as db:
            rows = db.execute(
                "SELECT a.*,t.conversation_id FROM activity_events a "
                "JOIN turns t ON t.id=a.turn_id JOIN conversations c ON c.id=t.conversation_id "
                "WHERE t.owner=? AND c.owner=? ORDER BY a.observed_at DESC,a.turn_id,a.sequence DESC LIMIT ? OFFSET ?",
                (owner, owner, limit + 1, offset)).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        return {"events": [{"turnId": row["turn_id"], "conversationId": row["conversation_id"],
                            **_public_record(row)} for row in rows],
                "nextPage": page + 1 if has_more and page < ACTIVITY_MAX_PAGE else None}

    def usage_for_turn(self, subject: str, turn_id: str) -> dict[str, Any]:
        self._chat_store.owned_turn(subject, turn_id)
        with self._chat_store._connect() as db:
            row = db.execute("SELECT * FROM activity_events WHERE turn_id=? AND usage IS NOT NULL "
                             "ORDER BY sequence DESC LIMIT 1", (turn_id,)).fetchone()
        record = None if row is None else _public_record(row)
        return {"turnId": turn_id,
                "usage_scope": "session_cumulative_snapshot" if record is not None else "unavailable",
                "usage": None if record is None else record["usage"],
                "observedAt": None if record is None else record["observed_at"],
                "cost_usd": None, "cost_status": "unknown"}


def _page_arg(raw: str | None, default: int, maximum: int) -> int:
    if raw is None:
        return default
    if not raw.isascii() or not raw.isdigit() or len(raw) > 8:
        raise ValueError("invalid page")
    value = int(raw)
    if value > maximum:
        raise ValueError("invalid page")
    return value


def install_jarvis_activity_routes(app: Any, service: Any) -> None:
    """Register the three finite GET-only activity/usage projections."""
    from aiohttp import web
    if not callable(getattr(service, "_current", None)) or not isinstance(
            getattr(service, "activity_store", None), JarvisActivityStore):
        raise TypeError("Jarvis activity service is required")

    async def recent(request):
        try:
            principal = service._current(request)
            page = _page_arg(request.query.get("page"), 0, ACTIVITY_MAX_PAGE)
            limit = _page_arg(request.query.get("limit"), ACTIVITY_PAGE_SIZE, 100)
            if limit == 0:
                raise ValueError
            result = service.activity_store.recent_for_owner(principal.subject, page=page, limit=limit)
            service._current(request)
            return web.json_response(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        except (ValueError, JarvisChatDenied):
            raise web.HTTPNotFound(text="not found", headers={"Cache-Control": "no-store"}) from None

    async def turn_activity(request):
        try:
            principal = service._current(request)
            turn_id = request.match_info.get("turn_id", "")
            turn = service.store.owned_turn(principal.subject, turn_id)
            if turn["status"] in {"queued", "running"} and turn["core_generation"] != principal.core_generation:
                raise JarvisChatDenied("turn generation is stale")
            before = _page_arg(request.query.get("before"), 0, 100_000) or None
            limit = _page_arg(request.query.get("limit"), ACTIVITY_PAGE_SIZE, 100)
            if limit == 0:
                raise ValueError
            events, next_before = service.activity_store.for_turn(
                principal.subject, turn_id, before=before, limit=limit)
            service._current(request)
            return web.json_response({"turnId": turn_id, "events": events, "nextBefore": next_before},
                                     headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        except (ValueError, JarvisChatDenied):
            raise web.HTTPNotFound(text="not found", headers={"Cache-Control": "no-store"}) from None

    async def usage(request):
        try:
            principal = service._current(request)
            turn_id = request.match_info.get("turn_id", "")
            turn = service.store.owned_turn(principal.subject, turn_id)
            if turn["status"] in {"queued", "running"} and turn["core_generation"] != principal.core_generation:
                raise JarvisChatDenied("turn generation is stale")
            result = service.activity_store.usage_for_turn(principal.subject, turn_id)
            service._current(request)
            return web.json_response(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers={"Cache-Control": "no-store"}) from None

    app.router.add_get("/chat/api/activity", recent, allow_head=False)
    app.router.add_get("/chat/api/turns/{turn_id}/activity", turn_activity, allow_head=False)
    app.router.add_get("/chat/api/turns/{turn_id}/usage", usage, allow_head=False)
