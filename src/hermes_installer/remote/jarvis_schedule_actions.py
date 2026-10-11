"""Durable one-use approval ledger for the fixed pause-schedule action."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_REVISION_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_SCHEDULE_RE = re.compile(r"^[A-Za-z0-9*/?.,:@+\- ]{1,160}$")
_STATUS_VALUES = frozenset({"ok", "success", "error", "failed", "running", "pending",
                            "missed", "cancelled", "canceled", "skipped", "paused",
                            "scheduled", "disabled", "unknown", "delivery_failed",
                            "delivery_queued"})


def _revision_timestamp(value: Any) -> str | int | float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if abs(value) <= 10**15 else None
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if (isinstance(value, str) and 1 <= len(value) <= 40
            and not any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)):
        return value
    return None


class ScheduleActionDenied(PermissionError):
    """A schedule action did not satisfy its current one-use owner binding."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _owner_digest(subject: str) -> str:
    return _digest(subject)


def schedule_revision(rows: list[dict[str, Any]]) -> str:
    """Hash a stable allowlisted snapshot; native identifiers stay inside this digest."""
    if not isinstance(rows, list) or len(rows) > 512:
        raise ValueError("native schedule snapshot exceeded its bound")
    safe_rows = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("native schedule snapshot row was invalid")
        job_id = row.get("job_id")
        if not isinstance(job_id, str) or not _JOB_ID_RE.fullmatch(job_id):
            raise ValueError("native schedule identifier was invalid")
        enabled = row.get("enabled")
        if enabled is not None and type(enabled) is not bool:
            raise ValueError("native schedule enabled state was invalid")
        safe_rows.append({
            "job_id": job_id,
            "enabled": enabled,
            "schedule": (row["schedule"].strip() if isinstance(row.get("schedule"), str)
                         and _SCHEDULE_RE.fullmatch(row["schedule"].strip()) else None),
            "next_run_at": _revision_timestamp(row.get("next_run_at")),
            "last_run_at": _revision_timestamp(row.get("last_run_at")),
            "last_status": (row["last_status"].strip().casefold()
                            if isinstance(row.get("last_status"), str)
                            and row["last_status"].strip().casefold() in _STATUS_VALUES else None),
            "state": (row["state"].strip().casefold()
                      if isinstance(row.get("state"), str)
                      and row["state"].strip().casefold() in _STATUS_VALUES else "unknown"),
            "paused_at": _revision_timestamp(row.get("paused_at")),
        })
    safe_rows.sort(key=lambda item: item["job_id"])
    raw = json.dumps(safe_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return _digest(raw)


@dataclass(frozen=True, slots=True)
class ScheduleApproval:
    opaque_id: str
    approval_nonce: str
    revision: str


@dataclass(frozen=True, slots=True)
class ScheduleActionBinding:
    job_id: str
    revision: str
    opaque_id: str
    idempotency_hash: str
    action_state: str
    result: dict[str, str] | None = None


class ScheduleActionLedger:
    """Private SQLite ledger; browser receives random references, never native job IDs."""

    def __init__(self, path: Path, *, owner_uid: int | None = None):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("absolute private schedule action ledger path required")
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent = path.parent.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != expected_uid
                or stat.S_IMODE(parent.st_mode) & 0o077):
            raise ScheduleActionDenied("schedule action ledger directory custody is invalid")
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) & 0o077):
                raise ScheduleActionDenied("schedule action ledger custody is invalid")
        self.path = path
        self.owner_uid = expected_uid
        self.boot_nonce = secrets.token_hex(24)
        self._initialize()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=2000")
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS approvals(
                opaque_id TEXT PRIMARY KEY, nonce_hash TEXT NOT NULL UNIQUE,
                owner_hash TEXT NOT NULL, job_id TEXT NOT NULL,
                core_generation TEXT NOT NULL, profile_hash TEXT NOT NULL, revision TEXT NOT NULL,
                expires REAL NOT NULL, jwt_expiry REAL NOT NULL, boot_nonce TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('issued','spent','invalidated','expired')),
                created REAL NOT NULL);
              CREATE INDEX IF NOT EXISTS approval_owner ON approvals(owner_hash,state);
              CREATE TABLE IF NOT EXISTS actions(
                owner_hash TEXT NOT NULL, idempotency_hash TEXT NOT NULL,
                request_hash TEXT NOT NULL, opaque_id TEXT NOT NULL, core_generation TEXT NOT NULL,
                profile_hash TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending','complete')),
                result TEXT, created REAL NOT NULL, updated REAL NOT NULL,
                PRIMARY KEY(owner_hash,idempotency_hash));
            """)
        os.chmod(self.path, 0o600)

    def issue_snapshot(self, subject: str, core_generation: str, profile_identity: str,
                       jwt_expiry: float,
                       rows: list[dict[str, Any]]) -> list[ScheduleApproval | None]:
        if not isinstance(profile_identity, str) or not 1 <= len(profile_identity) <= 128:
            raise ScheduleActionDenied("current default profile identity is invalid")
        owner_hash = _owner_digest(subject)
        profile_hash = _digest(profile_identity)
        now = time.monotonic()
        revision = schedule_revision(rows)
        outputs: list[ScheduleApproval | None] = []
        issued: list[tuple[str, str, str, str]] = []
        for row in rows:
            job_id = row["job_id"]
            enabled = row.get("enabled")
            if enabled is not True:
                outputs.append(None)
                continue
            opaque_id = secrets.token_urlsafe(18)
            nonce = secrets.token_urlsafe(32)
            outputs.append(ScheduleApproval(opaque_id, nonce, revision))
            issued.append((opaque_id, _digest(nonce), job_id, revision))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE approvals SET state='expired' WHERE state='issued' AND expires<=?", (now,))
            db.execute("UPDATE approvals SET state='invalidated' WHERE owner_hash=? AND state='issued'",
                       (owner_hash,))
            db.execute("DELETE FROM approvals WHERE state!='issued' AND created<?", (now - 86_400.0,))
            db.execute("DELETE FROM actions WHERE state='complete' AND updated<?", (now - 30 * 86_400.0,))
            for opaque_id, nonce_hash, job_id, bound_revision in issued:
                expiry = min(now + 30.0, float(jwt_expiry))
                if expiry <= now:
                    db.execute("ROLLBACK")
                    raise ScheduleActionDenied("schedule action approval expired")
                db.execute("INSERT INTO approvals VALUES(?,?,?,?,?,?,?,?,?,?,'issued',?)",
                           (opaque_id, nonce_hash, owner_hash, job_id, core_generation,
                            profile_hash, bound_revision, expiry, float(jwt_expiry), self.boot_nonce, now))
            db.execute("COMMIT")
        return outputs

    def lookup_action(self, *, subject: str, core_generation: str, profile_identity: str,
                      opaque_id: str, revision: str,
                      approval_nonce: str, idempotency_key: str) -> ScheduleActionBinding | None:
        """Return a prior result without authorizing or repeating its native effect."""
        if (not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision)
                or not isinstance(approval_nonce, str) or not _NONCE_RE.fullmatch(approval_nonce)
                or not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key)
                or not isinstance(opaque_id, str) or not 16 <= len(opaque_id) <= 128):
            raise ScheduleActionDenied("schedule action approval was denied")
        owner_hash = _owner_digest(subject)
        idempotency_hash = _digest(owner_hash + ":" + idempotency_key)
        request_hash = _digest(core_generation + ":" + _digest(profile_identity) + ":" + revision
                               + ":" + _digest(approval_nonce) + ":" + opaque_id)
        with self._connect() as db:
            row = db.execute(
                "SELECT request_hash,opaque_id,core_generation,profile_hash,state,result FROM actions WHERE owner_hash=? AND idempotency_hash=?",
                (owner_hash, idempotency_hash)).fetchone()
        if row is None:
            return None
        if (row["request_hash"] != request_hash or row["opaque_id"] != opaque_id
                or row["core_generation"] != core_generation
                or row["profile_hash"] != _digest(profile_identity)):
            raise ScheduleActionDenied("schedule action idempotency key was already used")
        result = json.loads(row["result"]) if row["result"] else None
        return ScheduleActionBinding("", revision, opaque_id, idempotency_hash,
                                     row["state"], result)

    def resolve_approval(self, *, subject: str, core_generation: str, profile_identity: str,
                         jwt_expiry: float,
                         opaque_id: str, revision: str, approval_nonce: str) -> str:
        """Resolve only the unspent, current server-held native identifier."""
        if (not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision)
                or not isinstance(approval_nonce, str) or not _NONCE_RE.fullmatch(approval_nonce)
                or not isinstance(opaque_id, str) or not 16 <= len(opaque_id) <= 128):
            raise ScheduleActionDenied("schedule action approval was denied")
        now = time.monotonic()
        with self._connect() as db:
            row = db.execute("SELECT * FROM approvals WHERE opaque_id=? AND nonce_hash=?",
                             (opaque_id, _digest(approval_nonce))).fetchone()
        if (row is None or row["owner_hash"] != _owner_digest(subject)
                or row["core_generation"] != core_generation
                or row["profile_hash"] != _digest(profile_identity)
                or row["revision"] != revision
                or row["boot_nonce"] != self.boot_nonce or row["state"] != "issued"
                or row["expires"] <= now or row["jwt_expiry"] <= now
                or row["jwt_expiry"] > jwt_expiry):
            raise ScheduleActionDenied("schedule action approval is stale")
        if not _JOB_ID_RE.fullmatch(row["job_id"]):
            raise ScheduleActionDenied("schedule action binding is invalid")
        return row["job_id"]

    def spend(self, *, subject: str, core_generation: str, profile_identity: str,
              jwt_expiry: float,
              opaque_id: str, revision: str, approval_nonce: str,
              idempotency_key: str) -> ScheduleActionBinding:
        if (not isinstance(revision, str) or not _REVISION_RE.fullmatch(revision)
                or not isinstance(approval_nonce, str) or not _NONCE_RE.fullmatch(approval_nonce)
                or not isinstance(idempotency_key, str) or not _IDEMPOTENCY_RE.fullmatch(idempotency_key)
                or not isinstance(opaque_id, str) or not 16 <= len(opaque_id) <= 128):
            raise ScheduleActionDenied("schedule action approval was denied")
        owner_hash = _owner_digest(subject)
        nonce_hash = _digest(approval_nonce)
        idempotency_hash = _digest(owner_hash + ":" + idempotency_key)
        profile_hash = _digest(profile_identity)
        request_hash = _digest(core_generation + ":" + profile_hash + ":" + revision
                               + ":" + nonce_hash + ":" + opaque_id)
        now = time.monotonic()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT request_hash,opaque_id,core_generation,profile_hash,state,result FROM actions WHERE owner_hash=? AND idempotency_hash=?",
                (owner_hash, idempotency_hash)).fetchone()
            if existing is not None:
                if (existing["request_hash"] != request_hash or existing["opaque_id"] != opaque_id
                        or existing["core_generation"] != core_generation
                        or existing["profile_hash"] != profile_hash):
                    db.execute("ROLLBACK")
                    raise ScheduleActionDenied("schedule action idempotency key was already used")
                result = json.loads(existing["result"]) if existing["result"] else None
                db.execute("COMMIT")
                return ScheduleActionBinding("", revision, opaque_id, idempotency_hash,
                                             existing["state"], result)
            approval = db.execute(
                "SELECT * FROM approvals WHERE opaque_id=? AND nonce_hash=?",
                (opaque_id, nonce_hash)).fetchone()
            if (approval is None or approval["owner_hash"] != owner_hash
                    or approval["core_generation"] != core_generation
                    or approval["profile_hash"] != profile_hash
                    or approval["revision"] != revision
                    or approval["boot_nonce"] != self.boot_nonce
                    or approval["state"] != "issued"
                    or approval["expires"] <= now or approval["jwt_expiry"] <= now
                    or approval["jwt_expiry"] > jwt_expiry):
                if approval is not None and approval["state"] == "issued" and approval["expires"] <= now:
                    db.execute("UPDATE approvals SET state='expired' WHERE opaque_id=?", (opaque_id,))
                db.execute("ROLLBACK")
                raise ScheduleActionDenied("schedule action approval is stale")
            db.execute("UPDATE approvals SET state='spent' WHERE opaque_id=? AND state='issued'",
                       (opaque_id,))
            db.execute("INSERT INTO actions VALUES(?,?,?,?,?,?,'pending',NULL,?,?)",
                       (owner_hash, idempotency_hash, request_hash, opaque_id, core_generation,
                        profile_hash, now, now))
            db.execute("COMMIT")
            return ScheduleActionBinding(approval["job_id"], revision, opaque_id,
                                        idempotency_hash, "pending")

    def complete(self, binding: ScheduleActionBinding, result: dict[str, str]) -> None:
        if (binding.action_state != "pending"
                or set(result) != {"status"}
                or result["status"] not in {"paused", "already_paused"}):
            raise ValueError("invalid completed schedule action result")
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"))
        with self._connect() as db:
            changed = db.execute(
                "UPDATE actions SET state='complete',result=?,updated=? WHERE idempotency_hash=? AND opaque_id=? AND state='pending'",
                (encoded, time.monotonic(), binding.idempotency_hash, binding.opaque_id)).rowcount
        if changed != 1:
            raise ScheduleActionDenied("schedule action result could not be recorded")
