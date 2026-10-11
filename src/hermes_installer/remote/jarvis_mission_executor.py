"""Typed, persisted mission correlation for the first native Orchestrator handoff.

This module does not grant dispatch authority. A MissionBinding is copied only from a
persisted, already-spent owner approval; the root observer carries that value alongside
its independently observed turn, and the Resources consumer joins it back to this ledger
immediately before its one native delegation.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote


_ID_RE = re.compile(r"[A-Za-z0-9_-]{24,64}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_MISSION_BINDING_FIELDS = frozenset({
    "schema", "mission_id", "revision", "plan_sha256", "task_sha256", "source_profile_id",
    "execution_mode", "autonomy_mode", "selected_source_ids", "scope_sha256", "authorization_sha256",
})
_MISSION_BINDING_V1_FIELDS = frozenset({
    "schema", "mission_id", "revision", "plan_sha256", "task_sha256", "source_profile_id",
})
_MISSION_INSTRUCTION = (
    "Carry out exactly one owner-approved mission. Make exactly one call to the registered "
    "`resources_delegate` tool using the exact arguments object shown below. Do not rewrite, "
    "summarize, extend, or add instructions to its goal; do not execute the goal yourself, "
    "add argument keys, or call any other tools. If the tool is missing or denies the call, "
    "state that execution did not occur. "
    "Only after a successful tool return, give the owner a concise summary of the returned result."
)


def _native_child_result_state(events: Any) -> tuple[bool, bool]:
    """Require start and successful terminal event from the same opaque native child ref."""
    if not isinstance(events, list) or len(events) > 500:
        return False, False
    started: set[str] = set()
    completed: set[str] = set()
    for item in events:
        if not isinstance(item, Mapping):
            continue
        child_ref = item.get("child_ref")
        if not isinstance(child_ref, str) or _SHA256_RE.fullmatch(child_ref) is None:
            continue
        if item.get("type") == "subagent.start" and item.get("status") == "running":
            started.add(child_ref)
        elif item.get("type") == "subagent.complete" and item.get("status") == "completed":
            completed.add(child_ref)
    return bool(started), bool(started & completed)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def mission_execution_prompt(approved_brief: str) -> str:
    """Build the fixed Orchestrator request without changing the approved goal bytes."""
    if not isinstance(approved_brief, str) or not 1 <= len(approved_brief) <= 8_000:
        raise ValueError("approved mission brief is invalid")
    arguments = _canonical({"goal": approved_brief}).decode("utf-8")
    return (_MISSION_INSTRUCTION + "\n\nExact resources_delegate arguments object:\n"
            + arguments)


def mission_goal_arguments_sha256(approved_brief: str) -> str:
    """Digest the same canonical single-field object root verifies at tool observation."""
    if not isinstance(approved_brief, str) or not 1 <= len(approved_brief) <= 8_000:
        raise ValueError("approved mission brief is invalid")
    return _digest({"goal": approved_brief})


@dataclass(frozen=True, slots=True)
class MissionBinding:
    """Closed correlation from a spent mission approval to one observed turn."""

    schema: int
    mission_id: str
    revision: int
    plan_sha256: str
    task_sha256: str
    source_profile_id: str
    execution_mode: str | None = None
    autonomy_mode: str | None = None
    selected_source_ids: tuple[str, ...] | None = None
    scope_sha256: str | None = None
    authorization_sha256: str | None = None

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema not in {1, 2}
                or not isinstance(self.mission_id, str) or _ID_RE.fullmatch(self.mission_id) is None
                or type(self.revision) is not int or self.revision < 1
                or not isinstance(self.plan_sha256, str) or _SHA256_RE.fullmatch(self.plan_sha256) is None
                or not isinstance(self.task_sha256, str) or _SHA256_RE.fullmatch(self.task_sha256) is None
                or self.source_profile_id != "orchestrator"):
            raise ValueError("mission binding is malformed")
        if self.schema == 1:
            if any(value is not None for value in (
                    self.execution_mode, self.autonomy_mode, self.selected_source_ids, self.scope_sha256,
                    self.authorization_sha256)):
                raise ValueError("legacy mission binding cannot carry autonomy claims")
            return
        if (self.execution_mode not in {"oneshot", "kanban"}
                or self.autonomy_mode not in {"approval_required", "fully_autonomous"}
                or type(self.selected_source_ids) is not tuple
                or not 1 <= len(self.selected_source_ids) <= 12
                or any(not isinstance(item, str)
                       or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", item) is None
                       for item in self.selected_source_ids)
                or len(set(self.selected_source_ids)) != len(self.selected_source_ids)
                or not isinstance(self.scope_sha256, str)
                or _SHA256_RE.fullmatch(self.scope_sha256) is None
                or (self.autonomy_mode == "approval_required" and self.authorization_sha256 is not None)
                or (self.autonomy_mode == "fully_autonomous"
                    and (not isinstance(self.authorization_sha256, str)
                         or _SHA256_RE.fullmatch(self.authorization_sha256) is None))):
            raise ValueError("mission binding is malformed")

    def to_wire(self) -> dict[str, Any]:
        base = {
            "schema": self.schema,
            "mission_id": self.mission_id,
            "revision": self.revision,
            "plan_sha256": self.plan_sha256,
            "task_sha256": self.task_sha256,
            "source_profile_id": self.source_profile_id,
        }
        if self.schema == 1:
            return base
        return {
            **base,
            "execution_mode": self.execution_mode,
            "autonomy_mode": self.autonomy_mode,
            "selected_source_ids": list(self.selected_source_ids or ()),
            "scope_sha256": self.scope_sha256,
            "authorization_sha256": self.authorization_sha256,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "MissionBinding":
        if not isinstance(value, Mapping):
            raise ValueError("mission binding fields differ")
        if set(value) == _MISSION_BINDING_V1_FIELDS and value.get("schema") == 1:
            return cls(
                schema=value["schema"], mission_id=value["mission_id"],
                revision=value["revision"], plan_sha256=value["plan_sha256"],
                task_sha256=value["task_sha256"], source_profile_id=value["source_profile_id"],
            )
        if set(value) != _MISSION_BINDING_FIELDS:
            raise ValueError("mission binding fields differ")
        return cls(
            schema=value["schema"], mission_id=value["mission_id"],
            revision=value["revision"], plan_sha256=value["plan_sha256"],
            task_sha256=value["task_sha256"], source_profile_id=value["source_profile_id"],
            execution_mode=value["execution_mode"], autonomy_mode=value["autonomy_mode"],
            selected_source_ids=tuple(value["selected_source_ids"])
            if isinstance(value["selected_source_ids"], list) else value["selected_source_ids"],
            scope_sha256=value["scope_sha256"],
            authorization_sha256=value["authorization_sha256"],
        )


class MissionLedgerReader:
    """Read the fixed mission ledger without initializing or mutating chat storage."""

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("absolute mission ledger path required")
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        uri = "file:" + quote(self.path.as_posix(), safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=2000")
        return connection


def _spent_row(store: Any, binding: MissionBinding, *, gateway_turn_id: str,
               owner_subject_sha256: str, core_generation: str,
               core_source_generation: str) -> sqlite3.Row | None:
    if (type(binding) is not MissionBinding
            or not isinstance(gateway_turn_id, str) or _ID_RE.fullmatch(gateway_turn_id) is None
            or not isinstance(owner_subject_sha256, str)
            or _SHA256_RE.fullmatch(owner_subject_sha256) is None
            or not isinstance(core_generation, str) or _SHA256_RE.fullmatch(core_generation) is None
            or not isinstance(core_source_generation, str)
            or _SHA256_RE.fullmatch(core_source_generation) is None):
        return None
    try:
        with store._connect() as db:
            db.execute("BEGIN")
            rows = db.execute(
                "SELECT m.id AS mission_id,m.owner,m.revision,m.brief,m.team_ids,"
                "m.selected_source_ids,m.execution_mode,m.autonomy_mode AS mission_autonomy_mode,"
                "m.status AS mission_status,m.plan_sha256,m.source_binding,"
                "a.id AS approval_id,a.status AS approval_status,a.gateway_turn_id,a.launch_request_hash,"
                "a.launch_idempotency_hash,a.plan_sha256 AS approval_plan_sha256,"
                "a.source_binding AS approval_source_binding,a.autonomy_mode,"
                "a.scope_sha256,a.authorization_sha256 "
                "FROM jarvis_mission_approvals a JOIN jarvis_missions m "
                "ON m.id=a.mission_id AND m.owner=a.owner "
                "WHERE a.mission_id=? AND a.owner=? AND a.revision=? AND a.gateway_turn_id=?",
                (binding.mission_id, owner_subject_sha256, binding.revision, gateway_turn_id),
            ).fetchall()
            db.execute("COMMIT")
        if len(rows) != 1:
            return None
        row = rows[0]
        owner = owner_subject_sha256
        source = json.loads(row["source_binding"])
        approval_source = json.loads(row["approval_source_binding"])
        selected_source_ids = json.loads(row["selected_source_ids"] or "null")
        expected_request = _digest({
            "mission_id": binding.mission_id,
            "revision": binding.revision,
            "plan_sha256": binding.plan_sha256,
            "autonomy_mode": row["autonomy_mode"],
        })
        expected_task = _digest({"goal": row["brief"]})
        expected_scope = _digest({"owner": owner, "mission_id": binding.mission_id,
                                   "revision": binding.revision, "brief": row["brief"],
                                   "selected_source_ids": selected_source_ids,
                                   "execution_mode": row["execution_mode"],
                                   "autonomy_mode": row["autonomy_mode"],
                                   "plan_sha256": binding.plan_sha256,
                                   "source_binding": source,
                                   "limits": {"native_delegations": 1,
                                              "additional_metered_microusd": 0,
                                              "deadline": "current_owner_turn_lease"},
                                   "final_effects": "jarvis_review_and_current_owner_gate"})
        expected_authorization = (
            _digest({"approval_id": row["approval_id"], "owner": owner,
                     "mission_id": binding.mission_id, "revision": binding.revision,
                     "plan_sha256": binding.plan_sha256, "scope_sha256": expected_scope,
                     "explicit_owner_task_start": True})
            if row["autonomy_mode"] == "fully_autonomous" else None
        )
        if (row["approval_status"] != "spent" or row["mission_status"] != "preview_pending"
                or row["launch_idempotency_hash"] is None
                or row["mission_id"] != binding.mission_id
                or int(row["revision"]) != binding.revision
                or row["plan_sha256"] != binding.plan_sha256
                or row["approval_plan_sha256"] != binding.plan_sha256
                or row["launch_request_hash"] != expected_request
                or row["autonomy_mode"] not in {"approval_required", "fully_autonomous"}
                or row["mission_autonomy_mode"] != row["autonomy_mode"]
                or row["execution_mode"] not in {"oneshot", "kanban"}
                or row["scope_sha256"] != expected_scope
                or row["authorization_sha256"] != expected_authorization
                or binding.execution_mode != row["execution_mode"]
                or binding.autonomy_mode != row["autonomy_mode"]
                or type(selected_source_ids) is not list
                or tuple(selected_source_ids) != binding.selected_source_ids
                or binding.scope_sha256 != expected_scope
                or binding.authorization_sha256 != expected_authorization
                or selected_source_ids != ["orchestrator"]
                or not isinstance(row["brief"], str) or not row["brief"]
                or expected_task != binding.task_sha256
                or type(source) is not dict or set(source) != {"core_source_generation", "core_generation"}
                or source != approval_source
                or source.get("core_generation") != core_generation
                or source.get("core_source_generation") != core_source_generation):
            return None
        return row
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def resolve_spent_mission_binding(store: Any, binding: MissionBinding, *,
                                  gateway_turn_id: str, owner_subject_sha256: str,
                                  core_generation: str, core_source_generation: str) -> bool:
    """Check that the sealed turn binding is backed by exactly one persisted spent approval."""
    return _spent_row(
        store, binding, gateway_turn_id=gateway_turn_id,
        owner_subject_sha256=owner_subject_sha256, core_generation=core_generation,
        core_source_generation=core_source_generation,
    ) is not None


def resolve_spent_mission_claim(store: Any, binding: MissionBinding, gateway_turn_id: str,
                                owner_subject_sha256: str, core_generation: str,
                                core_source_generation: str, source_profile_id: str,
                                canonical_arguments_sha256: str) -> bool:
    """Join one consumed native claim to the exact approved Orchestrator goal bytes."""
    if (type(binding) is not MissionBinding or source_profile_id != "orchestrator"
            or binding.source_profile_id != source_profile_id
            or not isinstance(canonical_arguments_sha256, str)
            or _SHA256_RE.fullmatch(canonical_arguments_sha256) is None
            or canonical_arguments_sha256 != binding.task_sha256):
        return False
    return _spent_row(
        store, binding, gateway_turn_id=gateway_turn_id,
        owner_subject_sha256=owner_subject_sha256, core_generation=core_generation,
        core_source_generation=core_source_generation,
    ) is not None


__all__ = [
    "MissionBinding", "MissionLedgerReader", "resolve_spent_mission_binding",
    "resolve_spent_mission_claim", "mission_execution_prompt",
    "mission_goal_arguments_sha256",
]


_RUN_STATUSES = frozenset({
    "provisioning", "outcome_unknown", "conversation_ready", "turn_reserved",
    "queued", "not_scheduled", "accepted", "rejected",
})


def _initialize_execution_store(store: Any) -> None:
    """Create the bounded run/action ledger and close interrupted provisioning as unknown."""
    with store._connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS jarvis_mission_runs (
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          mission_id TEXT NOT NULL,
          revision INTEGER NOT NULL CHECK(revision >= 1),
          plan_sha256 TEXT NOT NULL,
          task_sha256 TEXT NOT NULL,
          source_binding TEXT NOT NULL,
          launch_idempotency_hash TEXT NOT NULL,
          launch_request_hash TEXT NOT NULL,
          conversation_id TEXT,
          gateway_turn_id TEXT UNIQUE,
          status TEXT NOT NULL CHECK(status IN (
            'provisioning','outcome_unknown','conversation_ready','turn_reserved',
            'queued','not_scheduled','accepted','rejected')),
          result_decision TEXT,
          jarvis_review_state TEXT NOT NULL DEFAULT 'pending' CHECK(jarvis_review_state IN ('pending','approved','rejected')),
          jarvis_review_result_sha256 TEXT,
          jarvis_review_turn_id TEXT,
          jarvis_review_owner_turn_handle TEXT,
          created REAL NOT NULL,
          updated REAL NOT NULL,
          UNIQUE(owner, launch_idempotency_hash),
          UNIQUE(owner, mission_id, revision)
        )""")
        run_columns = {row["name"] for row in db.execute("PRAGMA table_info(jarvis_mission_runs)")}
        if "jarvis_review_state" not in run_columns:
            db.execute("ALTER TABLE jarvis_mission_runs ADD COLUMN jarvis_review_state TEXT NOT NULL DEFAULT 'pending'")
        if "jarvis_review_result_sha256" not in run_columns:
            db.execute("ALTER TABLE jarvis_mission_runs ADD COLUMN jarvis_review_result_sha256 TEXT")
        if "jarvis_review_turn_id" not in run_columns:
            db.execute("ALTER TABLE jarvis_mission_runs ADD COLUMN jarvis_review_turn_id TEXT")
        if "jarvis_review_owner_turn_handle" not in run_columns:
            db.execute("ALTER TABLE jarvis_mission_runs ADD COLUMN jarvis_review_owner_turn_handle TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS jarvis_mission_runs_owner ON jarvis_mission_runs(owner,updated DESC)")
        db.execute("""CREATE TABLE IF NOT EXISTS jarvis_mission_actions (
          owner TEXT NOT NULL,
          mission_id TEXT NOT NULL,
          revision INTEGER NOT NULL,
          action TEXT NOT NULL CHECK(action IN ('stop','review')),
          idempotency_hash TEXT NOT NULL,
          request_hash TEXT NOT NULL,
          created REAL NOT NULL,
          PRIMARY KEY(owner,idempotency_hash)
        )""")
        db.execute("""UPDATE jarvis_mission_runs SET status='outcome_unknown',updated=?
                      WHERE status IN ('provisioning','conversation_ready')""", (time.time(),))
        db.execute("""UPDATE jarvis_mission_approvals SET status='invalidated'
                      WHERE status='approved' AND EXISTS (
                        SELECT 1 FROM jarvis_mission_runs r WHERE r.owner=jarvis_mission_approvals.owner
                        AND r.mission_id=jarvis_mission_approvals.mission_id
                        AND r.revision=jarvis_mission_approvals.revision
                        AND r.status='outcome_unknown')""")


def _run_by_key(store: Any, owner: str, idempotency_hash: str) -> sqlite3.Row | None:
    with store._connect() as db:
        return db.execute(
            "SELECT * FROM jarvis_mission_runs WHERE owner=? AND launch_idempotency_hash=?",
            (owner, idempotency_hash),
        ).fetchone()


class MissionExecutionAdapter:
    """Launch one approved Orchestrator goal through the existing owned-turn service."""

    def __init__(self, store: Any, service: Any):
        if (not callable(getattr(store, "_connect", None))
                or not callable(getattr(service, "start_server_turn", None))
                or not callable(getattr(service, "_current", None))):
            raise TypeError("protected Jarvis chat service and store are required")
        self.store = store
        self.service = service
        _initialize_execution_store(store)

    def reserve(self, *, owner: str, mission_id: str, revision: int,
                plan_sha256: str, task_sha256: str, source_binding: str,
                idempotency_hash: str, request_hash: str,
                approval_nonce: str) -> tuple[sqlite3.Row, bool]:
        """Durably reserve before creating a Hermes session; return (run, is_replay)."""
        now = time.time()
        run_id = secrets.token_urlsafe(24)
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM jarvis_mission_runs WHERE owner=? AND launch_idempotency_hash=?",
                (owner, idempotency_hash),
            ).fetchone()
            if existing is not None:
                if (existing["mission_id"] != mission_id
                        or existing["launch_request_hash"] != request_hash):
                    db.rollback()
                    raise ValueError("mission launch idempotency conflict")
                db.commit()
                return existing, True
            attempted = db.execute(
                "SELECT id FROM jarvis_mission_runs WHERE owner=? AND mission_id=? AND revision=?",
                (owner, mission_id, revision),
            ).fetchone()
            approval = db.execute(
                "SELECT * FROM jarvis_mission_approvals WHERE owner=? AND mission_id=? "
                "AND revision=? AND status='approved' ORDER BY created DESC LIMIT 1",
                (owner, mission_id, revision),
            ).fetchone()
            mission = db.execute(
                "SELECT * FROM jarvis_missions WHERE id=? AND owner=?", (mission_id, owner)
            ).fetchone()
            if attempted is not None:
                db.rollback()
                raise ValueError("mission launch already reserved for this revision")
            if (approval is None or mission is None or approval["expires"] <= now
                    or approval["intent_nonce"] != approval_nonce
                    or approval["plan_sha256"] != plan_sha256
                    or mission["status"] != "preview_pending"
                    or int(mission["revision"]) != revision
                    or mission["plan_sha256"] != plan_sha256
                    or mission["source_binding"] != source_binding
                    or json.loads(mission["selected_source_ids"] or "null") != ["orchestrator"]):
                db.rollback()
                raise ValueError("current approved Orchestrator mission required")
            db.execute(
                "INSERT INTO jarvis_mission_runs "
                "(id,owner,mission_id,revision,plan_sha256,task_sha256,source_binding,"
                "launch_idempotency_hash,launch_request_hash,status,created,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?,'provisioning',?,?)",
                (run_id, owner, mission_id, revision, plan_sha256, task_sha256, source_binding,
                 idempotency_hash, request_hash, now, now),
            )
            db.commit()
            created = db.execute("SELECT * FROM jarvis_mission_runs WHERE id=?", (run_id,)).fetchone()
        return created, False

    def mark(self, run_id: str, *, status: str, conversation_id: str | None = None,
             gateway_turn_id: str | None = None) -> None:
        if status not in _RUN_STATUSES:
            raise ValueError("unsupported mission run state")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT * FROM jarvis_mission_runs WHERE id=?", (run_id,)).fetchone()
            if current is None:
                db.rollback()
                raise ValueError("mission run disappeared")
            allowed = {
                "provisioning": {"outcome_unknown", "conversation_ready", "not_scheduled"},
                "conversation_ready": {"outcome_unknown", "turn_reserved", "not_scheduled"},
                "turn_reserved": {"queued", "not_scheduled", "outcome_unknown"},
                "queued": {"accepted", "rejected", "outcome_unknown"},
                "outcome_unknown": set(), "not_scheduled": set(),
                "accepted": set(), "rejected": set(),
            }
            if status != current["status"] and status not in allowed[current["status"]]:
                db.rollback()
                raise ValueError("mission run state transition is invalid")
            db.execute(
                "UPDATE jarvis_mission_runs SET conversation_id=COALESCE(?,conversation_id),"
                "gateway_turn_id=COALESCE(?,gateway_turn_id),status=?,updated=? WHERE id=?",
                (conversation_id, gateway_turn_id, status, time.time(), run_id),
            )
            db.commit()

    def mark_unknown(self, run_id: str) -> None:
        """Close ambiguous session creation without making that approval reusable."""
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT owner,mission_id,revision,status FROM jarvis_mission_runs WHERE id=?",
                             (run_id,)).fetchone()
            if row is None:
                db.rollback()
                return
            if row["status"] in {"provisioning", "conversation_ready"}:
                db.execute("UPDATE jarvis_mission_runs SET status='outcome_unknown',updated=? WHERE id=?",
                           (time.time(), run_id))
                db.execute("UPDATE jarvis_mission_approvals SET status='invalidated' "
                           "WHERE owner=? AND mission_id=? AND revision=? AND status='approved'",
                           (row["owner"], row["mission_id"], row["revision"]))
            db.commit()

    def binding_after_spend(self, *, run_id: str, owner: str, mission_id: str,
                            revision: int, plan_sha256: str, task_sha256: str,
                            intent_nonce: str, idempotency_key: str,
                            source_binding: Mapping[str, str | None],
                            gateway_turn_id: str) -> MissionBinding:
        """Persist consent-to-turn correlation before returning binding to root registration."""
        from .jarvis_missions import _bind_approved_intent_to_turn
        _bind_approved_intent_to_turn(
            self.store, owner=owner, mission_id=mission_id, revision=revision,
            plan_sha256=plan_sha256, intent_nonce=intent_nonce,
            idempotency_key=idempotency_key, gateway_turn_id=gateway_turn_id,
            source_binding=dict(source_binding),
        )
        self.mark(run_id, status="turn_reserved", gateway_turn_id=gateway_turn_id)
        with self.store._connect() as db:
            row = db.execute(
                "SELECT task_sha256,status FROM jarvis_mission_runs WHERE id=? AND owner=? "
                "AND mission_id=? AND revision=? AND plan_sha256=? AND gateway_turn_id=?",
                (run_id, owner, mission_id, revision, plan_sha256, gateway_turn_id),
            ).fetchone()
        if row is None or row["status"] != "turn_reserved" or row["task_sha256"] != task_sha256:
            raise ValueError("spent mission turn binding could not be persisted")
        with self.store._connect() as db:
            approval = db.execute(
                "SELECT autonomy_mode,scope_sha256,authorization_sha256 FROM jarvis_mission_approvals "
                "WHERE owner=? AND mission_id=? AND revision=? AND gateway_turn_id=? AND status='spent'",
                (owner, mission_id, revision, gateway_turn_id),
            ).fetchone()
        mission = self._mission(owner, mission_id, revision)
        try:
            selected_source_ids = tuple(json.loads(mission["selected_source_ids"] or "null")) if mission else ()
        except (TypeError, ValueError):
            selected_source_ids = ()
        if approval is None or mission is None or not selected_source_ids:
            raise ValueError("spent task-start authorization is unavailable")
        binding = MissionBinding(
            2, mission_id, revision, plan_sha256, task_sha256, "orchestrator",
            mission["execution_mode"], approval["autonomy_mode"], selected_source_ids,
            approval["scope_sha256"], approval["authorization_sha256"],
        )
        if not resolve_spent_mission_binding(
                self.store, binding, gateway_turn_id=gateway_turn_id,
                owner_subject_sha256=owner,
                core_generation=source_binding.get("core_generation") or "",
                core_source_generation=source_binding.get("core_source_generation") or ""):
            raise ValueError("spent mission binding did not resolve")
        return binding

    def _mission(self, owner: str, mission_id: str, revision: int) -> sqlite3.Row | None:
        with self.store._connect() as db:
            return db.execute("SELECT * FROM jarvis_missions WHERE owner=? AND id=? AND revision=?",
                              (owner, mission_id, revision)).fetchone()

    def fail_schedule(self, *, run_id: str, owner: str, gateway_turn_id: str) -> None:
        from .jarvis_missions import _invalidate_unscheduled_mission_turn
        _invalidate_unscheduled_mission_turn(self.store, owner=owner, gateway_turn_id=gateway_turn_id)
        self.mark(run_id, status="not_scheduled", gateway_turn_id=gateway_turn_id)

    def reserve_action(self, *, owner: str, mission_id: str, revision: int,
                       action: str, idempotency_hash: str,
                       request_hash: str) -> bool:
        if action not in {"stop", "review"}:
            raise ValueError("unsupported mission action")
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM jarvis_mission_actions WHERE owner=? AND idempotency_hash=?",
                (owner, idempotency_hash),
            ).fetchone()
            if existing is not None:
                same = (existing["mission_id"] == mission_id and existing["revision"] == revision
                        and existing["action"] == action and existing["request_hash"] == request_hash)
                db.rollback()
                if not same:
                    raise ValueError("mission action idempotency conflict")
                return False
            db.execute(
                "INSERT INTO jarvis_mission_actions VALUES(?,?,?,?,?,?,?)",
                (owner, mission_id, revision, action, idempotency_hash, request_hash, time.time()),
            )
            db.commit()
        return True

    def latest_run(self, owner: str, mission_id: str, revision: int) -> sqlite3.Row | None:
        with self.store._connect() as db:
            return db.execute(
                "SELECT * FROM jarvis_mission_runs WHERE owner=? AND mission_id=? AND revision=?",
                (owner, mission_id, revision),
            ).fetchone()

    async def stop(self, *, subject: str, owner: str, mission_id: str, revision: int,
                   idempotency_hash: str, request_hash: str) -> dict[str, Any]:
        run = self.latest_run(owner, mission_id, revision)
        if run is None or not isinstance(run["gateway_turn_id"], str):
            raise ValueError("mission has no owned native run to stop")
        prior = self._action(owner, idempotency_hash)
        if prior is not None:
            if (prior["mission_id"] != mission_id or int(prior["revision"]) != revision
                    or prior["action"] != "stop" or prior["request_hash"] != request_hash):
                raise ValueError("mission action idempotency conflict")
            return self.project(subject, run)
        projected = self.project(subject, run)
        if projected["status"] not in {"queued", "running"}:
            raise ValueError("mission has no active owned native run")
        self.reserve_action(owner=owner, mission_id=mission_id, revision=revision,
                            action="stop", idempotency_hash=idempotency_hash,
                            request_hash=request_hash)
        turn_id = run["gateway_turn_id"]
        turn = self.store.owned_turn(subject, turn_id)
        worker = self.service._workers.get(turn_id)
        if worker is not None:
            worker.cancel()
            await __import__("asyncio").gather(worker, return_exceptions=True)
        elif turn["status"] in {"queued", "running"}:
            await self.service.backend.stop(turn["runtime_session_id"])
        self.store.cancel_turn(subject, turn_id)
        return self.project(subject, run)

    def review(self, *, subject: str, owner: str, mission_id: str, revision: int,
               decision: str, idempotency_hash: str, request_hash: str) -> dict[str, Any]:
        run = self.latest_run(owner, mission_id, revision)
        if run is None:
            raise ValueError("mission has no observed result awaiting review")
        if run["jarvis_review_state"] != "approved":
            raise ValueError("Jarvis has not approved this exact draft for owner decision")
        projected = self.project(subject, run)
        current = projected["status"]
        if current in {"accepted", "rejected"}:
            if current != ("accepted" if decision == "accept" else "rejected"):
                raise ValueError("mission result review conflicts with its saved decision")
            prior = self._action(owner, idempotency_hash)
            if prior is None or (prior["mission_id"] != mission_id
                    or int(prior["revision"]) != revision or prior["action"] != "review"
                    or prior["request_hash"] != request_hash):
                raise ValueError("mission action was already reviewed")
            return projected
        elif current != "review_pending":
            raise ValueError("mission has no observed result awaiting review")
        self.reserve_action(owner=owner, mission_id=mission_id, revision=revision,
                            action="review", idempotency_hash=idempotency_hash,
                            request_hash=request_hash)
        saved = "accepted" if decision == "accept" else "rejected"
        with self.store._connect() as db:
            db.execute("UPDATE jarvis_mission_runs SET status=?,result_decision=?,updated=? "
                       "WHERE id=? AND owner=? AND status IN ('queued','accepted','rejected')",
                       (saved, decision, time.time(), run["id"], owner))
        return self.project(subject, self.latest_run(owner, mission_id, revision))

    def record_jarvis_master_review(self, decision: Any, *, config: Any,
                                    custody: Any) -> bool:
        """Persist a root-sealed Jarvis review of the exact observed expert draft.

        This changes no external state and never implies owner approval. The sealed
        decision type is produced only by the authenticated no-tools master turn path.
        """
        from .jarvis_master_planning import CoreVerifiedJarvisMasterReviewDecision
        if (type(decision) is not CoreVerifiedJarvisMasterReviewDecision
                or not decision.is_current_sealed(config, custody=custody)
                or decision.decision not in {"approved", "rejected"}
                or not isinstance(decision.result_sha256, str)
                or _SHA256_RE.fullmatch(decision.result_sha256) is None):
            return False
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            run = db.execute(
                "SELECT * FROM jarvis_mission_runs WHERE id=? AND owner=? AND mission_id=? AND revision=?",
                (decision.run_id, decision.owner_subject_sha256, decision.mission_id,
                 decision.revision),
            ).fetchone()
            if run is None or run["status"] not in {"queued", "accepted", "rejected"}:
                db.rollback()
                return False
            if run["jarvis_review_state"] in {"approved", "rejected"}:
                same = (run["jarvis_review_state"] == decision.decision
                        and run["jarvis_review_result_sha256"] == decision.result_sha256
                        and run["jarvis_review_turn_id"] == decision.gateway_turn_id
                        and run["jarvis_review_owner_turn_handle"] == decision.owner_turn_handle)
                db.rollback()
                return same
            try:
                source = json.loads(run["source_binding"])
            except (TypeError, ValueError):
                source = None
            if (type(source) is not dict
                    or set(source) != {"core_generation", "core_source_generation"}):
                db.rollback()
                return False
            turn = db.execute(
                "SELECT t.status,t.partial,t.core_generation FROM turns t JOIN conversations c "
                "ON c.id=t.conversation_id WHERE t.id=? AND t.owner=? AND c.owner=?",
                (run["gateway_turn_id"], decision.owner_subject_sha256,
                 decision.owner_subject_sha256),
            ).fetchone()
            events = db.execute(
                "SELECT child_ref,event_type AS type,status FROM activity_events "
                "WHERE turn_id=? AND child_ref IS NOT NULL AND event_type LIKE 'subagent.%' "
                "ORDER BY sequence LIMIT 500", (run["gateway_turn_id"],),
            ).fetchall()
            _started, completed = _native_child_result_state([dict(item) for item in events])
            result_sha256 = (hashlib.sha256(turn["partial"].encode("utf-8")).hexdigest()
                             if turn is not None and isinstance(turn["partial"], str) else None)
            review_turn = db.execute(
                "SELECT t.status,t.core_generation FROM turns t JOIN conversations c "
                "ON c.id=t.conversation_id WHERE t.id=? AND t.owner=? AND c.owner=?",
                (decision.gateway_turn_id, decision.owner_subject_sha256,
                 decision.owner_subject_sha256),
            ).fetchone()
            if (turn is None or turn["status"] != "completed" or not completed
                    or result_sha256 != decision.result_sha256
                    or turn["core_generation"] != source["core_generation"]
                    or source["core_generation"] != decision.core_generation
                    or source["core_source_generation"] != decision.core_source_generation
                    or review_turn is None or review_turn["status"] != "completed"
                    or review_turn["core_generation"] != decision.core_generation
                    or not decision.matches(
                        owner_subject_sha256=run["owner"], mission_id=run["mission_id"],
                        revision=int(run["revision"]), gateway_turn_id=decision.gateway_turn_id,
                        owner_turn_handle=decision.owner_turn_handle, run_id=run["id"],
                        result_sha256=result_sha256,
                        core_generation=source["core_generation"],
                        core_source_generation=source["core_source_generation"])
                    or not decision.is_current_sealed(config, custody=custody)):
                db.rollback()
                return False
            changed = db.execute(
                "UPDATE jarvis_mission_runs SET jarvis_review_state=?,"
                "jarvis_review_result_sha256=?,jarvis_review_turn_id=?,"
                "jarvis_review_owner_turn_handle=?,updated=? "
                "WHERE id=? AND owner=? AND jarvis_review_state='pending'",
                (decision.decision, decision.result_sha256, decision.gateway_turn_id,
                 decision.owner_turn_handle, time.time(), run["id"],
                 decision.owner_subject_sha256),
            ).rowcount
            if changed != 1:
                db.rollback()
                return False
            if not decision.is_current_sealed(config, custody=custody):
                db.rollback()
                return False
            db.commit()
        return True

    def _action(self, owner: str, idempotency_hash: str) -> sqlite3.Row | None:
        with self.store._connect() as db:
            return db.execute(
                "SELECT * FROM jarvis_mission_actions WHERE owner=? AND idempotency_hash=?",
                (owner, idempotency_hash),
            ).fetchone()

    def project(self, subject: str, row: sqlite3.Row) -> dict[str, Any]:
        """Project only state from the owned Jarvis turn and its native event stream."""
        run = dict(row)
        result: dict[str, Any] = {
            "run_id": run["id"], "status": run["status"],
            "created_at": run["created"], "updated_at": run["updated"],
            "turn_id": run["gateway_turn_id"], "result": None,
            "review_state": "not_started",
            "owner_decision": ("approved" if run["status"] == "accepted"
                               else "rejected" if run["status"] == "rejected" else None),
        }
        turn_id = run["gateway_turn_id"]
        if not isinstance(turn_id, str):
            return result
        try:
            turn = self.store.owned_turn(subject, turn_id)
            child_events = self.service.activity_store.native_child_events_for_turn(subject, turn_id)
        except Exception:
            result["status"] = "outcome_unknown"
            return result
        child_started, child_completed = _native_child_result_state(child_events)
        if turn["status"] == "queued":
            status = "queued"
        elif turn["status"] == "running":
            status = "running" if child_started else "queued"
        elif turn["status"] == "cancelled":
            status = "cancelled"
        elif turn["status"] == "failed":
            status = "failed"
        elif turn["status"] == "completed" and child_completed:
            status = "review_pending"
            result["result"] = turn["partial"]
        elif turn["status"] == "completed":
            status = "completed_without_native_result"
        else:
            status = "outcome_unknown"
        if run["status"] in {"accepted", "rejected"} and status == "review_pending":
            status = run["status"]
        result["status"] = status
        result["review_state"] = {
            "review_pending": "awaiting_jarvis_review",
        }.get(status, "not_started")
        result["review_state"] = {
            "pending": "awaiting_jarvis_review",
            "approved": "approved",
            "rejected": "rejected",
        }.get(run["jarvis_review_state"], result["review_state"])
        result["updated_at"] = turn["updated"]
        result["native_child_started"] = child_started
        result["native_child_completed"] = child_completed
        return result


__all__ += ["MissionExecutionAdapter"]
