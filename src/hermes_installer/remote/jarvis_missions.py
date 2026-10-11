"""Durable owner-only Jarvis mission planning and the first bounded native handoff."""
from __future__ import annotations

import hashlib
import inspect
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
          gateway_turn_id TEXT,
          launch_idempotency_hash TEXT,
          launch_request_hash TEXT,
          UNIQUE(owner, idempotency_hash)
        )""")
        approval_columns = {row["name"] for row in db.execute("PRAGMA table_info(jarvis_mission_approvals)")}
        if "gateway_turn_id" not in approval_columns:
            db.execute("ALTER TABLE jarvis_mission_approvals ADD COLUMN gateway_turn_id TEXT")
        if "launch_idempotency_hash" not in approval_columns:
            db.execute("ALTER TABLE jarvis_mission_approvals ADD COLUMN launch_idempotency_hash TEXT")
        if "launch_request_hash" not in approval_columns:
            db.execute("ALTER TABLE jarvis_mission_approvals ADD COLUMN launch_request_hash TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS jarvis_mission_approval_current ON jarvis_mission_approvals(owner, mission_id, revision, created DESC)")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS jarvis_mission_launch_key ON jarvis_mission_approvals(owner, launch_idempotency_hash) WHERE launch_idempotency_hash IS NOT NULL")


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
        "intent_nonce": row["intent_nonce"] if status == "approved" else None,
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


def _bind_approved_intent_to_turn(store: Any, *, owner: str, mission_id: str,
                                  revision: int, plan_sha256: str, intent_nonce: str,
                                  idempotency_key: str, gateway_turn_id: str,
                                  source_binding: dict[str, str | None]) -> None:
    """Spend one fresh consent immediately before scheduling its server-owned chat turn.

    Called only from JarvisChatService.start_server_turn's pre-schedule persistence hook.
    The turn ID is generated by JarvisChatStore, never accepted from the browser. This row
    is a correlation record, not dispatch authority; the root observer still gates tool use.
    """
    if (not isinstance(owner, str) or not owner
            or not isinstance(mission_id, str) or not _ID_RE.fullmatch(mission_id)
            or type(revision) is not int or revision < 1
            or not isinstance(plan_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", plan_sha256)
            or not isinstance(intent_nonce, str) or not re.fullmatch(r"[a-f0-9]{64}", intent_nonce)
            or not isinstance(idempotency_key, str) or not IDEMPOTENCY_RE.fullmatch(idempotency_key)
            or not isinstance(gateway_turn_id, str) or not _ID_RE.fullmatch(gateway_turn_id)
            or not isinstance(source_binding, dict)):
        raise ValueError("mission turn binding is malformed")
    idem_hash = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
    request_hash = _hash({"mission_id": mission_id, "revision": revision,
                          "plan_sha256": plan_sha256})
    binding_text = _canonical(source_binding).decode("utf-8")
    with store._connect() as db:
        db.execute("BEGIN IMMEDIATE")
        approval = db.execute(
            "SELECT * FROM jarvis_mission_approvals WHERE owner=? AND mission_id=? "
            "AND revision=? AND status='approved' ORDER BY created DESC LIMIT 1",
            (owner, mission_id, revision),
        ).fetchone()
        mission = db.execute(
            "SELECT * FROM jarvis_missions WHERE id=? AND owner=?",
            (mission_id, owner),
        ).fetchone()
        if (approval is None or mission is None or approval["expires"] <= time.time()
                or approval["intent_nonce"] != intent_nonce
                or approval["plan_sha256"] != plan_sha256
                or approval["source_binding"] != binding_text
                or mission["status"] != "preview_pending"
                or int(mission["revision"]) != revision
                or mission["plan_sha256"] != plan_sha256
                or mission["source_binding"] != binding_text):
            db.rollback()
            raise ValueError("mission approval is stale, expired, or no longer current")
        collision = db.execute(
            "SELECT id,mission_id,launch_request_hash,gateway_turn_id FROM jarvis_mission_approvals "
            "WHERE owner=? AND launch_idempotency_hash=?",
            (owner, idem_hash),
        ).fetchone()
        if collision is not None:
            db.rollback()
            raise ValueError("mission launch idempotency key was already used")
        changed = db.execute(
            "UPDATE jarvis_mission_approvals SET status='spent',gateway_turn_id=?,"
            "launch_idempotency_hash=?,launch_request_hash=? WHERE id=? AND owner=? "
            "AND status='approved' AND expires>?",
            (gateway_turn_id, idem_hash, request_hash, approval["id"], owner, time.time()),
        ).rowcount
        if changed != 1:
            db.rollback()
            raise ValueError("mission approval was concurrently consumed")
        db.commit()


def _invalidate_unscheduled_mission_turn(store: Any, *, owner: str,
                                        gateway_turn_id: str) -> None:
    """Compensate the map if chat lease/currentness fails before its worker is scheduled."""
    if (not isinstance(owner, str) or not owner or not isinstance(gateway_turn_id, str)
            or not _ID_RE.fullmatch(gateway_turn_id)):
        return
    with store._connect() as db:
        db.execute(
            "UPDATE jarvis_mission_approvals SET status='invalidated' "
            "WHERE owner=? AND gateway_turn_id=? AND status='spent'",
            (owner, gateway_turn_id),
        )


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


def _mission_binding_route_ready(service: JarvisChatService) -> bool:
    """Require the Activity-owned fail-closed typed binding seam before reserving a run."""
    try:
        parameters = inspect.signature(service.start_server_turn).parameters
    except (TypeError, ValueError):
        return False
    return ("require_mission_binding" in parameters
            and "before_schedule" in parameters
            and callable(getattr(service, "_owner_turn_register", None)))


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
    """Install owner-bound mission planning and the single approved Orchestrator launch."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    _initialize(service.store)
    from .jarvis_mission_executor import MissionExecutionAdapter
    executor = MissionExecutionAdapter(service.store, service)

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
                            "intent_nonce": (approval["intent_nonce"]
                                             if approval["status"] == "approved"
                                             and approval["expires"] > time.time() else None),
                            "native_execution_available": False,
                        }
                except ValueError:
                    raise web.HTTPConflict(text="mission changed", headers=_secure_headers()) from None
            run = executor.latest_run(service.store._owner(principal.subject), row["id"],
                                      int(row["revision"]))
            if run is not None:
                result["run"] = executor.project(principal.subject, run)
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
                if db.execute(
                        "SELECT 1 FROM jarvis_mission_runs WHERE owner=? AND mission_id=? AND revision=?",
                        (owner, mission_id, revision)).fetchone() is not None:
                    db.rollback()
                    raise web.HTTPConflict(text="mission revision already has a launch reservation",
                                           headers=_secure_headers())
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

    async def mission_action(request: Any) -> Any:
        """Launch only the first fixed team; stop/review only the persisted owned native run."""
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
                    or not isinstance(body["approval_nonce"], str)
                    or not re.fullmatch(r"[a-f0-9]{64}", body["approval_nonce"])):
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
                idem_hash = hashlib.sha256(body["idempotency_key"].encode("ascii")).hexdigest()
                launch_hash = _hash({"mission_id": row["id"], "revision": revision,
                                     "plan_sha256": body["plan_sha256"]})
                from .jarvis_mission_executor import _run_by_key
                prior_run = _run_by_key(service.store, owner, idem_hash)
                if prior_run is not None:
                    if (prior_run["mission_id"] != row["id"]
                            or int(prior_run["revision"]) != revision
                            or prior_run["launch_request_hash"] != launch_hash
                            or prior_run["plan_sha256"] != body["plan_sha256"]):
                        raise web.HTTPConflict(text="mission launch idempotency conflict",
                                               headers=_secure_headers())
                    projected = executor.project(principal.subject, prior_run)
                    return web.json_response({"run": projected}, status=202, headers=_secure_headers())
                approval = _current_approval(service.store, owner, row["id"], revision)
                binding = _core_source_binding(request)
                catalog = _verified_team_catalog()
                current_preview = _preview(service.store, owner, row, binding,
                                           catalog=catalog, persist=False)
                _recheck_principal(service, request, principal)
                if (approval is None or approval["status"] != "approved"
                        or approval["expires"] <= time.time()
                        or approval["intent_nonce"] != nonce
                        or approval["plan_sha256"] != body["plan_sha256"]
                        or approval["source_binding"] != _canonical(binding).decode("utf-8")
                        or current_preview is None
                        or current_preview["plan_sha256"] != body["plan_sha256"]):
                    raise web.HTTPConflict(text="mission approval is stale or expired", headers=_secure_headers())
                if (json.loads(row["team_ids"]) != ["orchestrator"]
                        or binding["core_generation"] != principal.core_generation
                        or not re.fullmatch(r"[a-f0-9]{64}", binding["core_generation"] or "")
                        or not re.fullmatch(r"[a-f0-9]{64}", binding["core_source_generation"] or "")
                        or not _mission_binding_route_ready(service)):
                    raise web.HTTPConflict(text="first native mission route is unavailable", headers=_secure_headers())
                try:
                    run, replay = executor.reserve(
                        owner=owner, mission_id=row["id"], revision=revision,
                        plan_sha256=body["plan_sha256"], task_sha256=_hash({"goal": row["brief"]}),
                        source_binding=_canonical(binding).decode("utf-8"),
                        idempotency_hash=idem_hash, request_hash=launch_hash,
                        approval_nonce=nonce)
                except ValueError as error:
                    raise web.HTTPConflict(text=str(error), headers=_secure_headers()) from None
                if replay:
                    projected = executor.project(principal.subject, run)
                    return web.json_response({"run": projected}, status=202, headers=_secure_headers())
                try:
                    # The durable provisioning reservation exists before this external native
                    # session creation. If its outcome is ambiguous, this approval is burned.
                    backend_id, session_key = await service.backend.create_session()
                    _recheck_principal(service, request, principal)
                    conversation = service.store.create_conversation(
                        principal.subject, backend_id, session_key, principal.core_generation)
                    executor.mark(run["id"], status="conversation_ready",
                                  conversation_id=conversation["id"])
                    def before_schedule(turn_id: str):
                        return executor.binding_after_spend(
                            run_id=run["id"], owner=owner, mission_id=row["id"],
                            revision=revision, plan_sha256=body["plan_sha256"],
                            task_sha256=_hash({"goal": row["brief"]}), intent_nonce=nonce,
                            idempotency_key=body["idempotency_key"], source_binding=binding,
                            gateway_turn_id=turn_id)
                    def on_schedule_failure(turn_id: str):
                        executor.fail_schedule(run_id=run["id"], owner=owner,
                                               gateway_turn_id=turn_id)
                    queued = await service.start_server_turn(
                        request, conversation_id=conversation["id"], text=row["brief"],
                        idempotency_key=body["idempotency_key"], before_schedule=before_schedule,
                        require_mission_binding=True, on_schedule_failure=on_schedule_failure)
                    executor.mark(run["id"], status="queued",
                                  gateway_turn_id=queued["turn_id"])
                    _recheck_principal(service, request, principal)
                    projected = executor.project(principal.subject, executor.latest_run(owner, row["id"], revision))
                    return web.json_response({"run": projected}, status=202, headers=_secure_headers())
                except Exception:
                    executor.mark_unknown(run["id"])
                    latest = executor.latest_run(owner, row["id"], revision)
                    if latest is not None and latest["status"] == "not_scheduled":
                        raise web.HTTPConflict(
                            text="mission turn was not scheduled; its approval was invalidated",
                            headers=_secure_headers()) from None
                    raise web.HTTPServiceUnavailable(text="mission launch outcome is unknown; do not retry",
                                                     headers=_secure_headers()) from None
            if action == "stop":
                request_hash = _hash({"mission_id": row["id"], "revision": revision, "action": "stop"})
                try:
                    result = await executor.stop(
                        subject=principal.subject, owner=owner, mission_id=row["id"], revision=revision,
                        idempotency_hash=hashlib.sha256(body["idempotency_key"].encode("ascii")).hexdigest(),
                        request_hash=request_hash)
                except ValueError as error:
                    raise web.HTTPConflict(text=str(error), headers=_secure_headers()) from None
                _recheck_principal(service, request, principal)
                return web.json_response({"run": result}, headers=_secure_headers())
            request_hash = _hash({"mission_id": row["id"], "revision": revision,
                                  "action": "review", "decision": body["decision"]})
            try:
                result = executor.review(
                    subject=principal.subject, owner=owner, mission_id=row["id"], revision=revision,
                    decision=body["decision"],
                    idempotency_hash=hashlib.sha256(body["idempotency_key"].encode("ascii")).hexdigest(),
                    request_hash=request_hash)
            except ValueError as error:
                raise web.HTTPConflict(text=str(error), headers=_secure_headers()) from None
            _recheck_principal(service, request, principal)
            return web.json_response({"run": result}, headers=_secure_headers())
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
        app.router.add_post(f"/chat/api/missions/{{mission_id}}/{action}", mission_action)
