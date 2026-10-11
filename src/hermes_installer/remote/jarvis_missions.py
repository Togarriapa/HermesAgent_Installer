"""Durable owner-only Jarvis mission drafts and truthful native-readiness previews.

Mission execution is intentionally unavailable until the protected gateway has a verified,
parent-bound Hermes Resources dispatcher and captures its real task events. This module provides
the useful planning step without manufacturing queued/running work or approval authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from .jarvis_chat import (
    IDEMPOTENCY_RE,
    ID_RE,
    JarvisChatDenied,
    JarvisChatService,
    _opaque_id,
    _read_body,
    _secure_headers,
)

FEATURE_ROUTES = (
    ("GET", "/chat/api/missions"),
    ("POST", "/chat/api/missions"),
    ("GET", "/chat/api/missions/{mission_id}"),
    ("POST", "/chat/api/missions/{mission_id}/preview"),
    ("POST", "/chat/api/missions/{mission_id}/approve"),
    ("POST", "/chat/api/missions/{mission_id}/launch"),
    ("POST", "/chat/api/missions/{mission_id}/stop"),
    ("POST", "/chat/api/missions/{mission_id}/review"),
)

_ID_RE = ID_RE
_TITLE_LIMIT = 120
_BRIEF_LIMIT = 8_000
_TEAM_LIMIT = 12
_PENDING = (
    "The current protected core source has no verified mission-specific Resources dispatcher.",
    "Hermes delegate_task requires a live parent turn; no parent-bound mission plugin or owned task-event stream is installed.",
    "Per-task private-route, permission, and additional-spend policy has not been bound to this team preview.",
)


def _clean_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(ch for ch in value if ch >= " " and ch != "\x7f").split())[:limit]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _timestamp(value: float) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@lru_cache(maxsize=1)
def _verified_team_catalog() -> dict[str, Any]:
    """Project source identities from the dashboard's already verified JSON inventory.

    The packaged inventory's exact byte digest is checked by the shared dashboard loader. This
    request path never invokes NativeRegistry, YAML parsing, or discovery against another HOME.
    """
    from .jarvis_dashboard import _BUNDLE_INVENTORY_SHA256, _verified_bundle_inventory

    inventory = _verified_bundle_inventory()
    profiles = {
        item["id"]: _clean_text(item.get("displayName") or item["name"], 120)
        for item in inventory["items"] if item["kind"] == "profiles"
    }
    return {
        "profiles": profiles,
        "source": {
            "revision": inventory["source"]["revision"],
            "catalog_version": inventory["source"]["catalogVersion"],
            "package_sha256": _BUNDLE_INVENTORY_SHA256,
        },
    }


def _initialize(store: Any) -> None:
    """Add the mission table to the existing protected chat SQLite custody boundary."""
    with store._connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS jarvis_missions (
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 1),
          title TEXT NOT NULL,
          brief TEXT NOT NULL,
          team_ids TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('draft','preview_pending')),
          create_key_hash TEXT NOT NULL,
          create_request_hash TEXT NOT NULL,
          plan_sha256 TEXT,
          source_binding TEXT,
          created REAL NOT NULL,
          updated REAL NOT NULL,
          UNIQUE(owner, create_key_hash)
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS jarvis_mission_owner ON jarvis_missions(owner, updated DESC)")
        db.execute("""CREATE TABLE IF NOT EXISTS jarvis_mission_approvals (
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          mission_id TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 1),
          plan_sha256 TEXT NOT NULL,
          source_binding TEXT NOT NULL,
          request_hash TEXT NOT NULL,
          idempotency_hash TEXT NOT NULL,
          intent_nonce TEXT NOT NULL,
          status TEXT NOT NULL CHECK(status IN ('approved','spent','expired','invalidated')),
          created REAL NOT NULL,
          expires REAL NOT NULL,
          turn_id TEXT,
          UNIQUE(owner, idempotency_hash)
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS jarvis_mission_approval_current ON jarvis_mission_approvals(owner, mission_id, revision, created DESC)")


def _row_view(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "mission_id": row["id"],
        "revision": int(row["revision"]),
        "status": row["status"],
        "title": row["title"],
        "brief": row["brief"],
        "team_ids": json.loads(row["team_ids"]),
        "created_at": _timestamp(row["created"]),
        "updated_at": _timestamp(row["updated"]),
    }


def _owned_row(store: Any, owner: str, mission_id: str) -> sqlite3.Row | None:
    if not isinstance(mission_id, str) or not _ID_RE.fullmatch(mission_id):
        return None
    with store._connect() as db:
        return db.execute("SELECT * FROM jarvis_missions WHERE id=? AND owner=?", (mission_id, owner)).fetchone()


def _approval_response(row: sqlite3.Row) -> dict[str, Any]:
    status = row["status"]
    if status == "approved" and float(row["expires"]) <= time.time():
        status = "expired"
    return {
        "schema": 1,
        "mission_id": row["mission_id"],
        "revision": int(row["revision"]),
        "plan_sha256": row["plan_sha256"],
        "status": ("approved-pending-execution" if status == "approved" else status),
        "intent_nonce": row["intent_nonce"],
        "expires_at": _timestamp(float(row["expires"])),
        "native_execution_available": False,
        "pending_reasons": list(_PENDING),
    }


def _current_approval(store: Any, owner: str, mission_id: str, revision: int) -> sqlite3.Row | None:
    with store._connect() as db:
        return db.execute(
            "SELECT * FROM jarvis_mission_approvals WHERE owner=? AND mission_id=? AND revision=? "
            "AND status IN ('approved','expired') ORDER BY created DESC LIMIT 1",
            (owner, mission_id, revision),
        ).fetchone()


def _core_source_binding(request: Any) -> dict[str, str | None]:
    """Bind plans to the accepted current root witness; never trust browser source claims."""
    proof = request.get("core_ingress")
    root = getattr(proof, "root_observation", None)
    source_generation = getattr(root, "core_source_generation", None)
    core_generation = getattr(root, "core_generation", None)
    return {
        "core_source_generation": source_generation if isinstance(source_generation, str) else None,
        "core_generation": core_generation if isinstance(core_generation, str) else None,
    }


def _recheck_principal(service: JarvisChatService, request: Any, expected: Any) -> None:
    current = service._current(request)
    if current.subject != expected.subject or current.core_generation != expected.core_generation:
        raise JarvisChatDenied("owner or core generation changed during mission request")


def _preview(store: Any, owner: str, row: sqlite3.Row, binding: dict[str, str | None],
             *, catalog: dict[str, Any], persist: bool = True,
             before_commit: Any = None) -> dict[str, Any] | None:
    selected = json.loads(row["team_ids"])
    team = [
        {
            "id": identity,
            "label": catalog["profiles"].get(identity, identity),
            "readiness": "pending",
            "reason": "Bundled source identity is verified; current native dispatch and per-task authority are not.",
        }
        for identity in selected
    ]
    pending = list(_PENDING)
    payload = {
        "schema": 1,
        "owner": owner,
        "mission_id": row["id"],
        "revision": int(row["revision"]),
        "title": row["title"],
        "brief": row["brief"],
        "team_ids": selected,
        "team": team,
        "bundled_source": catalog["source"],
        "current_core": binding,
        "native_execution_available": False,
        "pending_reasons": pending,
    }
    digest = hashlib.sha256(b"hermes-jarvis-mission-plan-v1\0" + _canonical(payload)).hexdigest()
    if persist:
        with store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM jarvis_missions WHERE id=? AND owner=?", (row["id"], owner)).fetchone()
            if current is None or int(current["revision"]) != int(row["revision"]):
                db.rollback()
                raise ValueError("mission changed")
            db.execute("UPDATE jarvis_missions SET status='preview_pending', plan_sha256=?, source_binding=?, updated=? WHERE id=? AND owner=? AND revision=?",
                       (digest, _canonical(binding).decode("utf-8"), time.time(), row["id"], owner, row["revision"]))
            try:
                if before_commit is not None:
                    before_commit()
                db.commit()
            except BaseException:
                db.rollback()
                raise
    else:
        try:
            saved_binding = json.loads(row["source_binding"] or "null")
        except (TypeError, ValueError):
            return None
        if row["plan_sha256"] != digest or saved_binding != binding:
            return None
    return {
        "schema": 1,
        "mission_id": row["id"],
        "revision": int(row["revision"]),
        "status": "preview_pending",
        "title": row["title"],
        "brief": row["brief"],
        "team": team,
        "plan_sha256": digest,
        "approval_nonce": None,
        "expires_at": None,
        "native_execution_available": False,
        "pending_reasons": pending,
    }


def install_jarvis_missions_routes(app: Any, service: JarvisChatService) -> None:
    """Install only owner-bound draft and preview routes on the protected gateway."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    _initialize(service.store)

    async def list_missions(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            owner = service.store._owner(principal.subject)
            with service.store._connect() as db:
                rows = db.execute("SELECT * FROM jarvis_missions WHERE owner=? ORDER BY updated DESC LIMIT 100", (owner,)).fetchall()
            catalog = _verified_team_catalog()
            team_options = [
                {"id": identity, "label": label, "readiness": "pending",
                 "reason": "Verified bundled identity only; no current dispatch or execution authority."}
                for identity, label in sorted(catalog["profiles"].items())
            ]
            _recheck_principal(service, request, principal)
            return web.json_response({"missions": [_row_view(row) for row in rows],
                                      "team_options": team_options}, headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None

    async def create_mission(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            body = await _read_body(request, {"title", "brief", "team_ids", "idempotency_key"})
            _recheck_principal(service, request, principal)
            title = _clean_text(body["title"], _TITLE_LIMIT)
            brief = _clean_text(body["brief"], _BRIEF_LIMIT)
            key = body["idempotency_key"]
            team_ids = body["team_ids"]
            if (not title or len(body["title"]) > _TITLE_LIMIT or not brief
                    or len(body["brief"]) > _BRIEF_LIMIT
                    or not isinstance(key, str) or not IDEMPOTENCY_RE.fullmatch(key)
                    or not isinstance(team_ids, list) or not 1 <= len(team_ids) <= _TEAM_LIMIT
                    or any(not isinstance(item, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", item) for item in team_ids)
                    or len(set(team_ids)) != len(team_ids)):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            catalog = _verified_team_catalog()
            if any(identity not in catalog["profiles"] for identity in team_ids):
                raise web.HTTPBadRequest(text="unknown team identity", headers=_secure_headers())
            _recheck_principal(service, request, principal)
            owner = service.store._owner(principal.subject)
            key_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
            canonical_input = {"title": title, "brief": brief, "team_ids": team_ids}
            request_hash = _hash(canonical_input)
            now = time.time()
            mission_id = _opaque_id()
            with service.store._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                existing = db.execute("SELECT * FROM jarvis_missions WHERE owner=? AND create_key_hash=?", (owner, key_hash)).fetchone()
                if existing is not None:
                    if existing["create_request_hash"] != request_hash:
                        db.rollback()
                        raise web.HTTPConflict(text="idempotency key conflict", headers=_secure_headers())
                    created = existing
                else:
                    db.execute("INSERT INTO jarvis_missions(id,owner,revision,title,brief,team_ids,status,create_key_hash,create_request_hash,created,updated) VALUES(?,?,?,?,?,?,'draft',?,?,?,?)",
                               (mission_id, owner, 1, title, brief, json.dumps(team_ids, separators=(",", ":")), key_hash, request_hash, now, now))
                    created = db.execute("SELECT * FROM jarvis_missions WHERE id=? AND owner=?", (mission_id, owner)).fetchone()
                _recheck_principal(service, request, principal)
                db.commit()
            return web.json_response({"mission": _row_view(created)}, status=201, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="mission planning unavailable", headers=_secure_headers()) from None

    async def detail(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            row = _owned_row(service.store, service.store._owner(principal.subject), request.match_info.get("mission_id", ""))
            if row is None:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            result = {"mission": _row_view(row), "preview": None}
            if row["status"] == "preview_pending":
                try:
                    catalog = _verified_team_catalog()
                    _recheck_principal(service, request, principal)
                    binding = _core_source_binding(request)
                    result["preview"] = _preview(service.store, service.store._owner(principal.subject), row, binding,
                                                 catalog=catalog, persist=False)
                    approval = _current_approval(service.store, service.store._owner(principal.subject),
                                                 row["id"], int(row["revision"]))
                    if approval is not None:
                        result["approval"] = {
                            "status": ("expired" if approval["expires"] <= time.time()
                                       else approval["status"]),
                            "expires_at": _timestamp(float(approval["expires"])),
                            "native_execution_available": False,
                        }
                except ValueError:
                    raise web.HTTPConflict(text="mission changed", headers=_secure_headers()) from None
            _recheck_principal(service, request, principal)
            return web.json_response(result, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="mission unavailable", headers=_secure_headers()) from None

    async def preview(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            body = await _read_body(request, {"revision"})
            _recheck_principal(service, request, principal)
            revision = body["revision"]
            if type(revision) is not int or revision < 1:
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            owner = service.store._owner(principal.subject)
            row = _owned_row(service.store, owner, request.match_info.get("mission_id", ""))
            if row is None:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            if int(row["revision"]) != revision:
                raise web.HTTPConflict(text="mission revision changed", headers=_secure_headers())
            catalog = _verified_team_catalog()
            _recheck_principal(service, request, principal)
            binding = _core_source_binding(request)
            result = _preview(service.store, owner, row, binding, catalog=catalog,
                              before_commit=lambda: _recheck_principal(service, request, principal))
            _recheck_principal(service, request, principal)
            return web.json_response(result, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except ValueError:
            raise web.HTTPConflict(text="mission changed", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="mission preview unavailable", headers=_secure_headers()) from None

    async def approve(request: Any) -> Any:
        """Persist explicit owner consent for one immutable preview, without starting work."""
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            body = await _read_body(request, {"revision", "plan_sha256", "idempotency_key"})
            _recheck_principal(service, request, principal)
            revision = body["revision"]
            plan_sha256 = body["plan_sha256"]
            key = body["idempotency_key"]
            if (type(revision) is not int or revision < 1
                    or not isinstance(plan_sha256, str)
                    or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256)
                    or not isinstance(key, str) or not IDEMPOTENCY_RE.fullmatch(key)):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())

            owner = service.store._owner(principal.subject)
            mission_id = request.match_info.get("mission_id", "")
            mission = _owned_row(service.store, owner, mission_id)
            if mission is None:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            if (mission["status"] != "preview_pending"
                    or int(mission["revision"]) != revision
                    or mission["plan_sha256"] != plan_sha256):
                raise web.HTTPConflict(text="current mission preview required", headers=_secure_headers())

            catalog = _verified_team_catalog()
            _recheck_principal(service, request, principal)
            binding = _core_source_binding(request)
            current_preview = _preview(service.store, owner, mission, binding,
                                       catalog=catalog, persist=False)
            if current_preview is None or current_preview["plan_sha256"] != plan_sha256:
                raise web.HTTPConflict(text="mission preview is stale", headers=_secure_headers())

            idem_hash = hashlib.sha256(key.encode("ascii")).hexdigest()
            request_hash = _hash({"mission_id": mission_id, "revision": revision,
                                  "plan_sha256": plan_sha256})
            now = time.time()
            now_mono = time.monotonic()
            expiry_room = min(principal.expires_monotonic - now_mono,
                              principal.witness_expires_monotonic - now_mono)
            expires = now + min(30.0, expiry_room)
            if expires <= now:
                raise JarvisChatDenied("owner approval lease expired")
            intent_nonce = secrets.token_hex(32)
            approval_id = _opaque_id()
            with service.store._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current_mission = db.execute(
                    "SELECT * FROM jarvis_missions WHERE id=? AND owner=?",
                    (mission_id, owner),
                ).fetchone()
                if (current_mission is None or current_mission["status"] != "preview_pending"
                        or int(current_mission["revision"]) != revision
                        or current_mission["plan_sha256"] != plan_sha256
                        or current_mission["source_binding"] != _canonical(binding).decode("utf-8")):
                    db.rollback()
                    raise web.HTTPConflict(text="mission preview changed", headers=_secure_headers())
                existing = db.execute(
                    "SELECT * FROM jarvis_mission_approvals WHERE owner=? AND idempotency_hash=?",
                    (owner, idem_hash),
                ).fetchone()
                if existing is not None:
                    if (existing["request_hash"] != request_hash
                            or existing["mission_id"] != mission_id):
                        db.rollback()
                        raise web.HTTPConflict(text="idempotency key conflict", headers=_secure_headers())
                    _recheck_principal(service, request, principal)
                    db.commit()
                    return web.json_response(_approval_response(existing), headers=_secure_headers())
                db.execute(
                    "UPDATE jarvis_mission_approvals SET status='invalidated' "
                    "WHERE owner=? AND mission_id=? AND status='approved'",
                    (owner, mission_id),
                )
                db.execute(
                    "INSERT INTO jarvis_mission_approvals "
                    "(id,owner,mission_id,revision,plan_sha256,source_binding,request_hash,"
                    "idempotency_hash,intent_nonce,status,created,expires) "
                    "VALUES(?,?,?,?,?,?,?,?,?,'approved',?,?)",
                    (approval_id, owner, mission_id, revision, plan_sha256,
                     _canonical(binding).decode("utf-8"), request_hash, idem_hash,
                     intent_nonce, now, expires),
                )
                created = db.execute("SELECT * FROM jarvis_mission_approvals WHERE id=?", (approval_id,)).fetchone()
                _recheck_principal(service, request, principal)
                db.commit()
            return web.json_response(_approval_response(created), headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="mission approval unavailable", headers=_secure_headers()) from None

    async def unavailable_action(request: Any) -> Any:
        """Accept closed action shapes but never invent a run, cancellation or result review."""
        try:
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            action = request.path.rsplit("/", 1)[-1]
            expected = {
                "launch": {"revision", "plan_sha256", "approval_nonce", "idempotency_key"},
                "stop": {"revision", "idempotency_key"},
                "review": {"revision", "decision", "idempotency_key"},
            }.get(action)
            if expected is None:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            body = await _read_body(request, expected)
            _recheck_principal(service, request, principal)
            revision = body["revision"]
            if type(revision) is not int or revision < 1 or not isinstance(body["idempotency_key"], str) or not IDEMPOTENCY_RE.fullmatch(body["idempotency_key"]):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            if action == "launch" and (not isinstance(body["plan_sha256"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", body["plan_sha256"])
                    or (body["approval_nonce"] is not None and
                        (not isinstance(body["approval_nonce"], str)
                         or not re.fullmatch(r"[a-f0-9]{64}", body["approval_nonce"])) )):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            if action == "review" and (not isinstance(body["decision"], str)
                    or body["decision"] not in {"accept", "reject"}):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            owner = service.store._owner(principal.subject)
            row = _owned_row(service.store, owner, request.match_info.get("mission_id", ""))
            if row is None:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            if int(row["revision"]) != revision:
                raise web.HTTPConflict(text="mission revision changed", headers=_secure_headers())
            _recheck_principal(service, request, principal)
            if action == "launch":
                nonce = body["approval_nonce"]
                if isinstance(nonce, str):
                    approval = _current_approval(service.store, owner, row["id"], revision)
                    binding = _core_source_binding(request)
                    catalog = _verified_team_catalog()
                    current_preview = _preview(service.store, owner, row, binding,
                                               catalog=catalog, persist=False)
                    _recheck_principal(service, request, principal)
                    if (approval is None or approval["expires"] <= time.time()
                            or approval["intent_nonce"] != nonce
                            or approval["plan_sha256"] != body["plan_sha256"]
                            or approval["source_binding"] != _canonical(binding).decode("utf-8")
                            or current_preview is None
                            or current_preview["plan_sha256"] != body["plan_sha256"]):
                        raise web.HTTPConflict(text="mission approval is stale or expired", headers=_secure_headers())
                raise web.HTTPConflict(text="native mission execution unavailable", headers=_secure_headers())
            if action == "stop":
                raise web.HTTPConflict(text="mission has no owned native run to stop", headers=_secure_headers())
            raise web.HTTPConflict(text="mission has no native result awaiting review", headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="mission action unavailable", headers=_secure_headers()) from None

    app.router.add_get("/chat/api/missions", list_missions, allow_head=False)
    app.router.add_post("/chat/api/missions", create_mission)
    app.router.add_get("/chat/api/missions/{mission_id}", detail, allow_head=False)
    app.router.add_post("/chat/api/missions/{mission_id}/preview", preview)
    app.router.add_post("/chat/api/missions/{mission_id}/approve", approve)
    for action in ("launch", "stop", "review"):
        app.router.add_post(f"/chat/api/missions/{{mission_id}}/{action}", unavailable_action)
