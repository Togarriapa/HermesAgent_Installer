"""Owner approval for one exact normal-master native tool call.

The root observer creates a pending row only after joining the call to a live
root-registered owner turn. The protected Jarvis API can approve that exact
digest once. The observer spends the approval immediately before native tool
execution; this module never treats model text or a tool name as authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Mapping

from .jarvis_chat import JarvisChatDenied, _read_body, _secure_headers

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z", re.ASCII)
_SENSITIVE_KEY = re.compile(r"(?:secret|token|password|credential|authorization|api[_-]?key|private[_-]?key|cookie)", re.I)
_SENSITIVE_TEXT = re.compile(
    r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]{8,}|"
    r"((?:token|password|secret|api[_-]?key|authorization)\s*[:=]\s*)[^\s,;]+"
)
_MAX_ARGUMENT_BYTES = 64 * 1024
_MAX_PREVIEW_BYTES = 16 * 1024
_MAX_LIFETIME = 30.0


class FinalEffectDenied(PermissionError):
    """A final native effect lacks a current exact owner approval."""


def review_digest(tool_name: str, arguments_sha256: str) -> str:
    """Bind owner review to the exact native tool and canonical argument bytes."""
    if (not isinstance(tool_name, str) or not _ID.fullmatch(tool_name)
            or not isinstance(arguments_sha256, str) or not _HASH.fullmatch(arguments_sha256)):
        raise ValueError("final-effect review identity is malformed")
    payload = json.dumps({"tool_name": tool_name, "arguments_sha256": arguments_sha256},
                         sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def _redact(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    if budget is None:
        budget = [4096]
    budget[0] -= 1
    if budget[0] < 0 or depth > 12:
        raise ValueError("review preview exceeds its structural bound")
    if isinstance(value, Mapping):
        result = {}
        for key, item in value.items():
            if type(key) is not str or len(key) > 128:
                raise ValueError("review preview contains an invalid key")
            result[key] = "[redacted]" if _SENSITIVE_KEY.search(key) else _redact(
                item, depth=depth + 1, budget=budget)
        return result
    if type(value) in (list, tuple):
        return [_redact(item, depth=depth + 1, budget=budget) for item in value[:256]]
    if type(value) is str:
        text = value[:4096]
        return _SENSITIVE_TEXT.sub(lambda match: (match.group(1) or match.group(2)) + "[redacted]", text)
    if value is None or type(value) in (bool, int, float):
        return value
    raise ValueError("review preview contains a non-JSON value")


def safe_review_preview(tool_name: str, canonical_arguments: bytes) -> str:
    """Create the owner-visible bounded redacted view from exact native bytes."""
    if (not isinstance(tool_name, str) or not _ID.fullmatch(tool_name)
            or not isinstance(canonical_arguments, bytes)
            or not 2 <= len(canonical_arguments) <= _MAX_ARGUMENT_BYTES):
        raise ValueError("native effect review input is invalid")
    try:
        decoded = json.loads(canonical_arguments.decode("utf-8", "strict"),
                             object_pairs_hook=_unique_pairs)
        if not isinstance(decoded, dict) or _canonical(decoded) != canonical_arguments:
            raise ValueError
        preview = _canonical({"tool_name": tool_name, "arguments": _redact(decoded)})
        if len(preview) > _MAX_PREVIEW_BYTES:
            raise ValueError
        return preview.decode("utf-8", "strict")
    except Exception:
        raise ValueError("native effect review preview is unavailable") from None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")


@dataclass(frozen=True, slots=True)
class FinalEffectPending:
    pending_id: str
    review_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not isinstance(self.pending_id, str) or not _OPAQUE.fullmatch(self.pending_id)
                or not isinstance(self.review_sha256, str) or not _HASH.fullmatch(self.review_sha256)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + _MAX_LIFETIME):
            raise ValueError("final-effect pending receipt is malformed")


@dataclass(frozen=True, slots=True)
class FinalEffectReview:
    """Typed root-owned review projection; carries no authority to execute."""

    pending_id: str
    review_sha256: str
    tool_name: str
    preview_json: str
    status: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.pending_id or "")
                or not _HASH.fullmatch(self.review_sha256 or "")
                or not _ID.fullmatch(self.tool_name or "")
                or type(self.preview_json) is not str
                or len(self.preview_json.encode("utf-8", "strict")) > _MAX_PREVIEW_BYTES
                or self.status not in {"pending", "approved"}
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + _MAX_LIFETIME):
            raise ValueError("final-effect review projection is malformed")
        value = json.loads(self.preview_json)
        if (type(value) is not dict or value.get("tool_name") != self.tool_name
                or _canonical(value).decode("utf-8") != self.preview_json):
            raise ValueError("final-effect review projection is not canonical")


@dataclass(frozen=True, slots=True)
class FinalEffectPermit:
    """Peer-authenticated one-use root result matching the exact current tool call."""

    pending_id: str
    owner_turn_handle: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    source_generation_sha256: str
    source_profile_id: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    review_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        hashes = (self.owner_subject_sha256, self.core_generation,
                  self.core_source_generation, self.source_generation_sha256,
                  self.arguments_sha256, self.review_sha256)
        if (not _OPAQUE.fullmatch(self.pending_id or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.gateway_turn_id or "")
                or any(not _HASH.fullmatch(value or "") for value in hashes)
                or self.source_profile_id != "hermes"
                or not _ID.fullmatch(self.tool_call_id or "")
                or not _ID.fullmatch(self.tool_name or "")
                or self.review_sha256 != review_digest(self.tool_name, self.arguments_sha256)
                or isinstance(self.expires_monotonic, bool)
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + _MAX_LIFETIME):
            raise ValueError("final-effect permit is malformed")

    def matches_call(self, observed_call: Any, *, tool_name: str,
                     arguments_sha256: str, review_sha256: str,
                     now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return (now < self.expires_monotonic
                and getattr(observed_call, "owner_turn_handle", None) == self.owner_turn_handle
                and getattr(observed_call, "tool_call_id", None) == self.tool_call_id
                and getattr(observed_call, "tool_name", None) == tool_name == self.tool_name
                and getattr(observed_call, "arguments_sha256", None) == arguments_sha256 == self.arguments_sha256
                and review_sha256 == self.review_sha256)


class RootFinalEffectLedger:
    """Small shared-ledger leaf for root IPC and protected owner approval routes."""

    def __init__(self, connection_factory: Any):
        if not callable(connection_factory):
            raise TypeError("protected Jarvis SQLite connection factory required")
        self._connect = connection_factory
        with self._connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS jarvis_final_effects(
                pending_id TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                turn_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                owner_turn_handle TEXT NOT NULL,
                core_generation TEXT NOT NULL,
                core_source_generation TEXT NOT NULL,
                source_generation_sha256 TEXT NOT NULL,
                source_profile_id TEXT NOT NULL,
                tool_call_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_sha256 TEXT NOT NULL,
                review_sha256 TEXT NOT NULL,
                preview_json TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('pending','approved','denied','spent','expired','stale')),
                decision_hash TEXT,
                created_monotonic REAL NOT NULL,
                expires_monotonic REAL NOT NULL,
                UNIQUE(owner_turn_handle,tool_call_id))""")
            db.execute("CREATE INDEX IF NOT EXISTS jarvis_final_effect_owner ON jarvis_final_effects(owner,turn_id,status)")

    @staticmethod
    def _identity(*, owner_subject_sha256: str, gateway_turn_id: str,
                  owner_turn_handle: str, core_generation: str,
                  core_source_generation: str, source_generation_sha256: str,
                  tool_call_id: str, tool_name: str, arguments_sha256: str,
                  review_sha256: str) -> None:
        if (not _HASH.fullmatch(owner_subject_sha256 or "")
                or not _ID.fullmatch(gateway_turn_id or "")
                or not _OPAQUE.fullmatch(owner_turn_handle or "")
                or not all(_HASH.fullmatch(value or "") for value in (
                    core_generation, core_source_generation, source_generation_sha256,
                    arguments_sha256, review_sha256))
                or not _ID.fullmatch(tool_call_id or "") or not _ID.fullmatch(tool_name or "")
                or review_sha256 != review_digest(tool_name, arguments_sha256)):
            raise FinalEffectDenied("final-effect identity is malformed")

    def issue_pending(self, *, owner_subject_sha256: str, gateway_turn_id: str,
                      owner_turn_handle: str, core_generation: str,
                      core_source_generation: str, source_generation_sha256: str,
                      tool_call_id: str, tool_name: str, arguments_sha256: str,
                      review_sha256: str, expires_monotonic: float,
                      canonical_arguments: bytes) -> FinalEffectPending:
        self._identity(owner_subject_sha256=owner_subject_sha256, gateway_turn_id=gateway_turn_id,
                       owner_turn_handle=owner_turn_handle, core_generation=core_generation,
                       core_source_generation=core_source_generation,
                       source_generation_sha256=source_generation_sha256,
                       tool_call_id=tool_call_id, tool_name=tool_name,
                       arguments_sha256=arguments_sha256, review_sha256=review_sha256)
        if (hashlib.sha256(canonical_arguments).hexdigest() != arguments_sha256
                or isinstance(expires_monotonic, bool)
                or type(expires_monotonic) not in (int, float)
                or not time.monotonic() < expires_monotonic <= time.monotonic() + _MAX_LIFETIME):
            raise FinalEffectDenied("final-effect request is stale or changed")
        preview = safe_review_preview(tool_name, canonical_arguments)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT * FROM jarvis_final_effects WHERE owner_turn_handle=? AND tool_call_id=?",
                                  (owner_turn_handle, tool_call_id)).fetchone()
            if existing is not None:
                exact = (existing["owner"] == owner_subject_sha256
                         and existing["turn_id"] == gateway_turn_id
                         and existing["core_generation"] == core_generation
                         and existing["core_source_generation"] == core_source_generation
                         and existing["source_generation_sha256"] == source_generation_sha256
                         and existing["tool_name"] == tool_name
                         and existing["arguments_sha256"] == arguments_sha256
                         and existing["review_sha256"] == review_sha256)
                if not exact or existing["status"] != "pending" or existing["expires_monotonic"] <= time.monotonic():
                    db.rollback()
                    raise FinalEffectDenied("final-effect call has already been decided")
                db.commit()
                return FinalEffectPending(existing["pending_id"], review_sha256,
                                          existing["expires_monotonic"])
            pending_id = secrets.token_urlsafe(32)
            db.execute("INSERT INTO jarvis_final_effects VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (pending_id, owner_subject_sha256, gateway_turn_id, gateway_turn_id,
                        owner_turn_handle, core_generation, core_source_generation,
                        source_generation_sha256, "hermes", tool_call_id, tool_name,
                        arguments_sha256, review_sha256, preview, "pending", None,
                        time.monotonic(), expires_monotonic))
            db.commit()
        return FinalEffectPending(pending_id, review_sha256, expires_monotonic)

    def pending_for_owner(self, *, owner_subject_sha256: str, gateway_turn_id: str,
                          owner_turn_handle: str, core_generation: str) -> list[dict[str, Any]]:
        if (not _HASH.fullmatch(owner_subject_sha256 or "")
                or not _ID.fullmatch(gateway_turn_id or "")
                or not _OPAQUE.fullmatch(owner_turn_handle or "")
                or not _HASH.fullmatch(core_generation or "")):
            raise FinalEffectDenied("owner review identity is malformed")
        now = time.monotonic()
        with self._connect() as db:
            rows = db.execute("SELECT * FROM jarvis_final_effects WHERE owner=? AND turn_id=? "
                              "AND owner_turn_handle=? AND core_generation=? "
                              "AND status IN ('pending','approved') ORDER BY created_monotonic LIMIT 32",
                              (owner_subject_sha256, gateway_turn_id, owner_turn_handle,
                               core_generation)).fetchall()
        results = []
        with self._connect() as db:
            for row in rows:
                if row["expires_monotonic"] <= now:
                    db.execute("UPDATE jarvis_final_effects SET status='expired' WHERE pending_id=? AND status='pending'",
                               (row["pending_id"],))
                    continue
                results.append({"pendingId": row["pending_id"], "turnId": row["turn_id"],
                                "toolName": row["tool_name"], "reviewSha256": row["review_sha256"],
                                "preview": json.loads(row["preview_json"]), "status": row["status"],
                                "expiresInMs": max(0, int((row["expires_monotonic"] - now) * 1000))})
        return results

    def decide(self, *, owner_subject_sha256: str, gateway_turn_id: str,
               owner_turn_handle: str, core_generation: str,
               pending_id: str, review_sha256: str, decision: str,
               idempotency_key: str) -> str:
        if (not _OPAQUE.fullmatch(pending_id or "") or not _HASH.fullmatch(review_sha256 or "")
                or decision not in {"approve", "deny"}
                or not isinstance(idempotency_key, str) or not _ID.fullmatch(idempotency_key)
                or not _HASH.fullmatch(owner_subject_sha256 or "")
                or not _ID.fullmatch(gateway_turn_id or "")
                or not _OPAQUE.fullmatch(owner_turn_handle or "")
                or not _HASH.fullmatch(core_generation or "")):
            raise JarvisChatDenied("final-effect decision is invalid")
        decision_hash = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM jarvis_final_effects WHERE pending_id=? AND owner=? "
                              "AND turn_id=? AND owner_turn_handle=? AND core_generation=?",
                             (pending_id, owner_subject_sha256, gateway_turn_id,
                              owner_turn_handle, core_generation)).fetchone()
            if row is None or row["review_sha256"] != review_sha256:
                db.rollback()
                raise JarvisChatDenied("final-effect request is unavailable")
            if row["status"] == "approved" and row["decision_hash"] == decision_hash:
                db.commit()
                return "approved"
            if row["status"] != "pending" or row["expires_monotonic"] <= time.monotonic():
                db.rollback()
                raise JarvisChatDenied("final-effect request is no longer pending")
            status = "approved" if decision == "approve" else "denied"
            db.execute("UPDATE jarvis_final_effects SET status=?,decision_hash=? "
                       "WHERE pending_id=? AND status='pending'",
                       (status, decision_hash, pending_id))
            db.commit()
        return status

    def poll(self, pending_id: str, review_sha256: str, *, expected: Mapping[str, Any]) -> str:
        if not _OPAQUE.fullmatch(pending_id or "") or not _HASH.fullmatch(review_sha256 or ""):
            return "stale"
        with self._connect() as db:
            row = db.execute("SELECT * FROM jarvis_final_effects WHERE pending_id=?", (pending_id,)).fetchone()
        if row is None or row["review_sha256"] != review_sha256:
            return "stale"
        checks = ("owner_turn_handle", "gateway_turn_id", "owner_subject_sha256", "core_generation",
                  "core_source_generation", "source_generation_sha256", "source_profile_id",
                  "tool_call_id", "tool_name", "arguments_sha256", "review_sha256")
        actual = {"owner_turn_handle": row["owner_turn_handle"], "gateway_turn_id": row["turn_id"],
                  "owner_subject_sha256": row["owner"], "core_generation": row["core_generation"],
                  "core_source_generation": row["core_source_generation"],
                  "source_generation_sha256": row["source_generation_sha256"],
                  "source_profile_id": row["source_profile_id"], "tool_call_id": row["tool_call_id"],
                  "tool_name": row["tool_name"], "arguments_sha256": row["arguments_sha256"],
                  "review_sha256": row["review_sha256"]}
        if any(expected.get(field) != actual[field] for field in checks):
            return "stale"
        if row["expires_monotonic"] <= time.monotonic():
            with self._connect() as db:
                db.execute("UPDATE jarvis_final_effects SET status='expired' WHERE pending_id=? "
                           "AND status IN ('pending','approved')", (pending_id,))
            return "stale"
        return row["status"]

    def consume_approval(self, pending_id: str, review_sha256: str, *, expected: Mapping[str, Any]) -> bool:
        if self.poll(pending_id, review_sha256, expected=expected) != "approved":
            return False
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("UPDATE jarvis_final_effects SET status='spent' WHERE pending_id=? "
                                "AND status='approved' AND review_sha256=? AND expires_monotonic>?",
                                (pending_id, review_sha256, time.monotonic()))
            db.commit()
        return cursor.rowcount == 1


def install_jarvis_final_effect_routes(app: Any, service: Any) -> None:
    """Install owner review routes through the gateway's root-inspector IPC client.

    The protected HTTP process must never receive the core-native observer
    client/socket. Root verifies the live ingress proof and owner-turn handle
    again before it lists or decides a pending call.
    """
    from aiohttp import web
    from .core_gateway_inspector import CoreGatewayInspector
    inspector = getattr(service, "inspector", None)
    if (not callable(getattr(service, "_current", None))
            or not callable(getattr(service, "owner_turn_handle_for", None))
            or type(inspector) is not CoreGatewayInspector):
        raise TypeError("protected Jarvis chat service required")

    def current_owner_proof(request: Any) -> tuple[str, Any]:
        proof = service._capture_owner_turn_context(request)
        if (type(proof) is not tuple or len(proof) != 3
                or type(proof[0]) is not str or proof[1] is None or proof[2] is not None):
            raise JarvisChatDenied("current owner ingress proof is unavailable")
        return proof[0], proof[1]

    async def list_pending(request: Any) -> Any:
        try:
            principal = service._current(request)
            turn_id = request.match_info.get("turn_id", "")
            turn = service.store.owned_turn(principal.subject, turn_id)
            if turn["core_generation"] != principal.core_generation:
                raise JarvisChatDenied("final-effect turn is stale")
            if turn["status"] != "running":
                return web.json_response({"turnId": turn_id, "requests": []},
                                         headers=_secure_headers())
            owner_handle = service.owner_turn_handle_for(principal, turn_id)
            if not isinstance(owner_handle, str):
                raise JarvisChatDenied("current owner-turn binding is unavailable")
            access_jwt, accepted_ingress = current_owner_proof(request)
            reviews = inspector.list_final_effects(
                access_jwt=access_jwt, accepted_ingress=accepted_ingress,
                owner_turn_handle=owner_handle,
            )
            if (type(reviews) is not tuple or len(reviews) > 32
                    or any(type(row) is not FinalEffectReview for row in reviews)):
                raise JarvisChatDenied("root final-effect review projection is invalid")
            now = time.monotonic()
            items = [{"pendingId": row.pending_id, "turnId": turn_id,
                      "toolName": row.tool_name, "reviewSha256": row.review_sha256,
                      "preview": json.loads(row.preview_json), "status": row.status,
                      "expiresInMs": max(0, int((row.expires_monotonic - now) * 1000))}
                     for row in reviews if row.expires_monotonic > now]
            service._current(request)
            return web.json_response({"turnId": turn_id, "requests": items}, headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="final-effect review unavailable",
                                             headers=_secure_headers()) from None

    async def decide(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            turn_id = request.match_info.get("turn_id", "")
            turn = service.store.owned_turn(principal.subject, turn_id)
            if turn["status"] != "running" or turn["core_generation"] != principal.core_generation:
                raise JarvisChatDenied("final-effect turn is stale")
            owner_handle = service.owner_turn_handle_for(principal, turn_id)
            if not isinstance(owner_handle, str):
                raise JarvisChatDenied("current owner-turn binding is unavailable")
            access_jwt, accepted_ingress = current_owner_proof(request)
            body = await _read_body(request, {"pending_id", "review_sha256", "decision", "idempotency_key"})
            status = inspector.decide_final_effect(
                access_jwt=access_jwt, accepted_ingress=accepted_ingress,
                owner_turn_handle=owner_handle, pending_id=body["pending_id"],
                review_sha256=body["review_sha256"], decision=body["decision"],
                idempotency_key=body["idempotency_key"],
            )
            if status not in {"approved", "denied"}:
                raise JarvisChatDenied("root final-effect decision response is invalid")
            service._current(request)
            return web.json_response({"pendingId": body["pending_id"], "status": status},
                                     headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="final-effect approval unavailable",
                                             headers=_secure_headers()) from None

    app.router.add_get("/chat/api/turns/{turn_id}/final-effects", list_pending, allow_head=False)
    # aiohttp's add_post() has no allow_head argument (only add_get exposes it).
    # Keep the fixed route method-specific through this dedicated POST helper.
    app.router.add_post("/chat/api/turns/{turn_id}/final-effects/decision", decide)


def install_jarvis_final_effect_middleware(ctx: Any, client: Any, *,
                                          obsidian_binding: Any = None) -> tuple[Any, ...]:
    """Gate every normal master native tool dispatch on a one-use root permit.

    The pinned executor supplies a lexical call tuple through
    ``current_native_tool_dispatch``. Root classifies the exact observed call
    as master read, master effect, or admitted expert research. Master effects
    require a one-use owner permit; experts never request one.
    """
    register = getattr(ctx, "register_middleware", None)
    if not callable(register):
        raise FinalEffectDenied("pinned Hermes tool middleware is unavailable")
    try:
        from .core_native_observer import CoreNativeObservationClient
    except Exception:
        raise FinalEffectDenied("root native observer client is unavailable") from None
    if type(client) is not CoreNativeObservationClient:
        raise FinalEffectDenied("root native observer client is unavailable")

    def deny(reason: str) -> dict[str, str]:
        return {"error": reason[:160], "effect_executed": "false"}

    def gate(**event: Any) -> Any:
        """Total callback: failures always return a no-execution denial."""
        next_call = event.get("next_call")
        if not callable(next_call):
            return deny("Final effect blocked: native executor is unavailable.")
        try:
            from hermes_installer.native_invocations import current_native_tool_dispatch
            from .core_native_observer import (
                ObservedNativeToolCall,
                register_tool_call_from_current_parent,
            )

            current = current_native_tool_dispatch()
            name = event.get("tool_name")
            args = event.get("args")
            if (current is None or type(name) is not str or name != current.tool_name
                    or not isinstance(args, Mapping)):
                return deny("Final effect blocked: current owner tool call could not be bound.")
            from hermes_installer.native_invocations import canonical_tool_arguments
            canonical = canonical_tool_arguments(args)
            if canonical != current.canonical_arguments:
                return deny("Final effect blocked: dispatched arguments changed after review.")

            # This fixed Resources handler consumes its own root-observed
            # lineage and performs its own bounded per-operation root checks.
            # Letting the generic middleware observe/bind the call first would
            # consume that single-use lineage and prevent the trusted handler
            # from launching the already-approved internal operation.
            if name == "resources_delegate":
                return next_call(args)

            observed = register_tool_call_from_current_parent(
                client=client, parent_agent=current.agent,
                tool_call_id=current.tool_call_id, tool_name=name, arguments=args,
            )
            if type(observed) is not ObservedNativeToolCall:
                return deny("Final effect blocked: root call observation is unavailable.")
            args_sha = hashlib.sha256(canonical).hexdigest()

            from .core_native_observer import RootVerifiedMasterReadCall
            caller_receipt = client.authorize_current_tool_call(observed_call=observed)
            if (type(caller_receipt) is not RootVerifiedMasterReadCall
                    or not caller_receipt.matches_call(
                        observed, tool_name=name, arguments_sha256=args_sha)):
                return deny("Native tool blocked: current root caller proof is unavailable.")

            # Obsidian shares this lexical dispatch and root-observed call
            # lineage, then obtains its own short-lived fixed-vault scope.
            # The scope carries no authority beyond the observed call and is
            # consumed only while dispatching the registered native handler.
            obsidian_effect = name == "obsidian_promote_reviewed_draft"
            if name.startswith("obsidian_"):
                from .obsidian_native_tools import _TOOL_NAMES, _admit_current_obsidian_call
                if name not in _TOOL_NAMES:
                    return deny("Obsidian tool blocked: name is outside the fixed tool registry.")
                try:
                    # Obtain a fresh receipt over the authenticated current
                    # Core peer. This also handles the normal startup ordering
                    # where Core registers tools before its root inspector starts.
                    binding = client.bind_obsidian_native_vault()
                    if obsidian_effect:
                        # Promotion may wait up to twelve seconds for the owner
                        # permit, while a call scope lasts at most five. Do not
                        # issue (and consume) that one-use scope until approval
                        # is valid. The same observed call and startup binding
                        # are revalidated immediately before native dispatch.
                        if caller_receipt.mode != "master_effect":
                            return deny("Obsidian tool blocked: owner promotion requires final-effect authority.")
                        scope = None
                    else:
                        scope = client.authorize_obsidian_call_scope(
                            observed_call=observed, binding=binding)
                        if (scope.tool_name != name or scope.mode != caller_receipt.mode
                                or scope.source_generation_sha256 != caller_receipt.source_generation_sha256):
                            return deny("Obsidian tool blocked: root scope differs from the current call.")
                        if scope.mode in {"master_read", "expert_read"}:
                            with _admit_current_obsidian_call(
                                    observed_call=observed, scope=scope, binding=binding,
                                    observer_client=client):
                                return next_call(args)
                        return deny("Obsidian tool blocked: only owner-reviewed promotion can request a final effect.")
                except BaseException:
                    return deny("Obsidian tool blocked: current root vault scope is unavailable.")
            else:
                binding = scope = None

            if caller_receipt.mode in {"master_read", "expert_read"}:
                if name not in {"web_search", "web_extract", "skills_list", "skill_view"}:
                    return deny("Read-only tool blocked: tool is outside the fixed research closure.")
                return next_call(args)
            if caller_receipt.mode != "master_effect":
                return deny("Native tool blocked: caller is not authorized for an owner effect review.")
            if name in {"web_search", "web_extract", "skills_list", "skill_view"}:
                return deny("Native tool blocked: research tool has an invalid root caller mode.")

            digest = review_digest(name, args_sha)
            pending = client.request_final_effect(
                observed_call_handle=observed.handle, review_sha256=digest,
            )
            if type(pending) is not FinalEffectPending or pending.review_sha256 != digest:
                return deny("Final effect blocked: owner review request is unavailable.")

            deadline = min(pending.expires_monotonic, time.monotonic() + 12.0)
            while time.monotonic() < deadline:
                permit = client.poll_final_effect(pending=pending, observed_call=observed)
                if permit is not None:
                    if (type(permit) is not FinalEffectPermit
                            or permit.pending_id != pending.pending_id
                            or not permit.matches_call(observed, tool_name=name,
                                                       arguments_sha256=args_sha,
                                                       review_sha256=digest)):
                        return deny("Final effect blocked: owner approval no longer matches this call.")
                    # This is the only path to downstream Hermes registry dispatch.
                    try:
                        if name.startswith("obsidian_"):
                            from .obsidian_native_tools import _admit_current_obsidian_call
                            if obsidian_effect:
                                # Reclassify the same observed call after the
                                # wait, then mint the single short scope against
                                # the original owner, source, registration and
                                # call deadlines. A stale/replaced caller or
                                # expired startup binding fails closed here.
                                current_receipt = client.authorize_current_tool_call(
                                    observed_call=observed)
                                if (type(current_receipt) is not RootVerifiedMasterReadCall
                                        or not current_receipt.matches_call(
                                            observed, tool_name=name,
                                            arguments_sha256=args_sha)
                                        or current_receipt.mode != "master_effect"
                                        or current_receipt.source_generation_sha256
                                            != caller_receipt.source_generation_sha256):
                                    return deny("Obsidian promotion blocked: current owner call changed during review.")
                                scope = client.authorize_obsidian_call_scope(
                                    observed_call=observed, binding=binding)
                                if (scope.tool_name != name or scope.mode != "master_effect"
                                        or scope.source_generation_sha256
                                            != current_receipt.source_generation_sha256
                                        or not scope.matches(observed, binding)):
                                    return deny("Obsidian promotion blocked: fresh root scope does not match the approved call.")
                            with _admit_current_obsidian_call(
                                    observed_call=observed, scope=scope, binding=binding,
                                    permit=permit, observer_client=client):
                                return next_call(args)
                        return next_call(args)
                    except BaseException:
                        # Do not retry a potentially partially executed effect.
                        raise
                time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
            return deny("Owner approval is pending; no action was executed. Retry after review.")
        except BaseException:
            # Hermes' middleware runner fails open when a callback raises.
            # Return a value even for cancellation/runtime faults so it cannot
            # continue into registry.dispatch without an approval receipt.
            return deny("Final effect blocked: approval could not be verified.")

    try:
        return (register("tool_execution", gate),)
    except BaseException:
        raise FinalEffectDenied("final-effect middleware registration failed") from None


__all__ = ["FinalEffectDenied", "FinalEffectPending", "FinalEffectPermit",
           "FinalEffectReview", "RootFinalEffectLedger", "install_jarvis_final_effect_middleware",
           "install_jarvis_final_effect_routes",
           "review_digest", "safe_review_preview"]
