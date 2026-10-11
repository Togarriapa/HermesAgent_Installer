"""Root-owned durable executor for fixed memory-service compound recipes.

The executor owns job handles, step order, response captures, and replay
rejection. It never accepts worker HTTP. Each step is handed to a narrow root
effect callback with the signed source lineage and exact canonical digest; the
callback is responsible for minting and consuming a fresh HI12 grant before
network bytes. If that callback is not installed, no step is sent.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from hermes_installer.memory.compound import (
    MemoryRecipeDenied,
    MemoryRecipeUnavailable,
    MemoryRouteRecipe,
    build_memory_request,
    canonical_json,
    validate_step_outcome,
)
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.authority.types import (
    EffectAuthorization, HostContext, canonical_digest,
)
from hermes_installer.state import OwnedRoot, process_lock
from hermes_installer.memory.root_state import MemoryAuthorityStateDirectory, memory_state_lock


class MemoryExecutionUnavailable(RuntimeError):
    """The protected runtime cannot execute this enrolled memory action."""


class MemoryExecutionDenied(PermissionError):
    """A caller or service response violated the fixed memory contract."""


class MemoryStepEffect(Protocol):
    def __call__(self, reservation_handle: str,
                 canonical_connector_payload_bytes: bytes,
                 serialized_service_request_sha256: str, *,
                 timeout: float,
                 cancelled: Callable[[], bool]) -> tuple[int, bytes]: ...


@dataclass(frozen=True, slots=True)
class MemoryStepBinding:
    """Complete root-derived authorization binding for one reserved step."""

    profile_id: str
    namespace_id: str
    provider: str
    service_enrollment_id: str
    service_generation: str
    memory_owner_generation: int
    target_id: str
    approved_route_id: str
    recipe_sha256: str
    job_handle: str
    step_id: str
    sequence: int
    deadline_monotonic: float
    source_context_sha256: str
    consent_id: str | None
    consent_sha256: str | None
    parent_grant_id: str
    parent_context_digest: str
    parent_request_digest: str
    compound_envelope_sha256: str
    service_request_sha256: str


def _recipe_digest(recipe: MemoryRouteRecipe) -> str:
    return canonical_digest({
        "approved_route_id": recipe.approved_route_id,
        "backend_variant": recipe.backend_variant,
        "steps": [{"step_id": step.step_id, "method": step.method,
                   "path_template": step.path_template,
                   "body_recipe_id": step.body_recipe_id,
                   "response_schema_id": step.response_schema_id,
                   "capture_fields": list(step.capture_fields),
                   "next_step_id": step.next_step_id}
                  for step in recipe.steps],
        "request_schema_id": recipe.request_schema_id,
        "result_schema_id": recipe.result_schema_id,
        "scope_bindings": dict(recipe.scope_bindings),
        "credential_reference_id": recipe.credential_reference_id,
        "maximum_seconds": recipe.maximum_seconds,
        "maximum_bytes": recipe.maximum_bytes,
    })


def _validate_parent(enrollment: MemoryServiceEnrollment, recipe: MemoryRouteRecipe,
                     source_context_wire: bytes, parent: Any,
                     parent_request_payload: bytes) -> tuple[HostContext, str]:
    if not isinstance(parent, EffectAuthorization) or not isinstance(parent_request_payload, bytes):
        raise MemoryExecutionDenied("a consumed typed parent effect authorization is required")
    try:
        context = HostContext.from_wire(json.loads(source_context_wire.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
        raise MemoryExecutionDenied("signed parent source context is malformed") from None
    if recipe.approved_route_id in {"openviking-ready", "agentmemory-ready",
                                    "claude-sqlite-ready", "claude-postgres-ready"}:
        action = "doctor"
        capability = "memory-retrieval"
    elif "search" in recipe.approved_route_id or recipe.approved_route_id == "openviking-find":
        action = "search"
        capability = "memory-retrieval"
    else:
        action = "capture"
        capability = "memory-capture"
    target = f"memory:{enrollment.provider}:{action}"
    operation = f"memory.{action}"
    digest = hashlib.sha256(parent_request_payload).hexdigest()
    # AuthorityService verifies the original signed context before dispatch,
    # then gives root handlers a reconstructed context marked
    # ``verified-in-service``. Its signature is intentionally different,
    # so context_digest is bound to the already-verified parent grant in
    # the durable ledger rather than recomputed from that handler view.
    if (context.profile_id != enrollment.profile_id
            or context.namespace_id != enrollment.namespace_identity
            or context.principal_id != enrollment.principal_id
            or context.operation != operation
            or context.final_payload_digest != digest
            or parent.profile_id != context.profile_id
            or parent.namespace_id != context.namespace_id
            or parent.principal_id != context.principal_id
            or parent.uid != context.uid
            or parent.operation != operation
            or parent.capability != capability
            or parent.target != target
            or parent.request_digest != digest
            or parent.final_payload_digest != digest
            or parent.source_receipts != context.source_receipts
            or parent.lineage_hash != context.lineage_hash
            or parent.sensitivity != context.sensitivity):
        raise MemoryExecutionDenied("parent grant, source context, and selected memory action differ")
    return context, digest


def _canonical_map(value: Mapping[str, Any], maximum: int) -> bytes:
    return canonical_json(value, maximum)


def _wire(value: bytes | Mapping[str, Any], maximum: int, name: str) -> bytes:
    if isinstance(value, bytes):
        try:
            decoded = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError(f"{name} is malformed") from None
        if not isinstance(decoded, dict) or canonical_json(decoded, maximum) != value:
            raise ValueError(f"{name} must be canonical JSON")
        return value
    if isinstance(value, Mapping):
        return canonical_json(value, maximum)
    raise ValueError(f"{name} must be a mapping or canonical JSON bytes")


@dataclass(frozen=True, slots=True)
class MemoryJob:
    handle: str
    profile_id: str
    namespace_id: str
    provider: str
    service_generation: str
    owner_generation: int
    route_id: str
    state: str
    next_step: int
    sequence: int
    deadline_monotonic: float
    request_body: Mapping[str, Any]
    captures: Mapping[str, str]


class MemoryCompoundLedger:
    """Durable root-only one-use compound job state with atomic transitions."""

    def __init__(self, root: Path | MemoryAuthorityStateDirectory):
        self.owned = root if isinstance(root, MemoryAuthorityStateDirectory) else OwnedRoot(root)
        self.profile_scope = self.owned.profile_id if isinstance(self.owned, MemoryAuthorityStateDirectory) else None
        self.owned.ensure()
        # Share the durable capture queue database and lock when installed, so
        # revocation can atomically erase pending events and compound payloads.
        self.path = self.owned.path("memory-queue.sqlite3")
        self.lock_path = self.owned.path("memory-queue.lock")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS compound_jobs (
                        handle TEXT PRIMARY KEY, profile TEXT NOT NULL,
                        namespace TEXT NOT NULL, provider TEXT NOT NULL,
                        service_generation TEXT NOT NULL, owner_generation INTEGER NOT NULL,
                        route_id TEXT NOT NULL, state TEXT NOT NULL,
                        next_step INTEGER NOT NULL, sequence INTEGER NOT NULL,
                        deadline REAL NOT NULL, source_context BLOB NOT NULL,
                        consent BLOB, request_body BLOB NOT NULL, captures BLOB NOT NULL,
                        inflight_step TEXT, inflight_sequence INTEGER,
                        effect_consumed INTEGER NOT NULL DEFAULT 0,
                        compound_payload_sha256 TEXT, service_request_sha256 TEXT
                    );
                    CREATE INDEX IF NOT EXISTS compound_jobs_owner
                      ON compound_jobs(profile, provider, owner_generation, state);
                    CREATE TABLE IF NOT EXISTS compound_bindings (
                        handle TEXT PRIMARY KEY, target_id TEXT NOT NULL,
                        recipe_sha256 TEXT NOT NULL, parent_grant_id TEXT NOT NULL,
                        parent_context_digest TEXT NOT NULL,
                        parent_request_digest TEXT NOT NULL
                    );
                """)
                # Monotonic deadlines are not meaningful after process restart.
                # Interrupted network effects are ambiguous and must never replay.
                columns = {row[1] for row in db.execute("PRAGMA table_info(compound_jobs)")}
                for name, declaration in (
                    ("effect_consumed", "INTEGER NOT NULL DEFAULT 0"),
                    ("compound_payload_sha256", "TEXT"),
                    ("service_request_sha256", "TEXT"),
                ):
                    if name not in columns:
                        db.execute(f"ALTER TABLE compound_jobs ADD COLUMN {name} {declaration}")
                db.execute("UPDATE compound_jobs SET state='ambiguous',source_context=X'',consent=NULL,"
                           "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,"
                           "inflight_sequence=NULL,effect_consumed=0,compound_payload_sha256=NULL,"
                           "service_request_sha256=NULL WHERE state='active'")
                db.commit()
            finally:
                db.close()

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA secure_delete=ON")
        from hermes_installer.memory.owner_ledger import _secure_sqlite_files
        _secure_sqlite_files(self.path)
        return db

    def admit(self, *, enrollment: MemoryServiceEnrollment,
              recipe: MemoryRouteRecipe, request_body: Mapping[str, Any],
              source_context_wire: bytes | Mapping[str, Any],
              consent_wire: bytes | Mapping[str, Any] | None,
              target_id: str, recipe_sha256: str,
              parent_grant_id: str, parent_context_digest: str,
              parent_request_digest: str,
              deadline_monotonic: float, maximum_bytes: int) -> MemoryJob:
        if recipe.approved_route_id not in enrollment.fixed_route_map or enrollment.fixed_route_map[recipe.approved_route_id] != recipe:
            raise MemoryExecutionDenied("memory route recipe differs from protected enrollment")
        if self.profile_scope is not None and enrollment.profile_id != self.profile_scope:
            raise MemoryExecutionDenied("memory compound ledger belongs to another profile")
        if not isinstance(request_body, Mapping):
            raise MemoryExecutionDenied("memory request body must be a typed object")
        body_wire = _canonical_map(request_body, min(maximum_bytes, recipe.maximum_bytes))
        source_wire = _wire(source_context_wire, 256 * 1024, "source context")
        consent = None if consent_wire is None else _wire(consent_wire, 16 * 1024, "background consent")
        now = time.monotonic()
        if (isinstance(deadline_monotonic, bool) or not isinstance(deadline_monotonic, (int, float))
                or deadline_monotonic <= now or deadline_monotonic > now + recipe.maximum_seconds):
            raise MemoryExecutionDenied("memory compound deadline exceeds its enrolled bound")
        handle = secrets.token_urlsafe(32)
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("INSERT INTO compound_jobs(handle,profile,namespace,provider,service_generation,"
                    "owner_generation,route_id,state,next_step,sequence,deadline,source_context,consent,"
                    "request_body,captures,inflight_step,inflight_sequence) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (handle, enrollment.profile_id, enrollment.namespace_identity,
                     enrollment.provider, enrollment.service_generation,
                     enrollment.memory_owner_generation, recipe.approved_route_id,
                     "active", 0, 1, float(deadline_monotonic), source_wire,
                     consent, body_wire,
                     canonical_json({"new_session_id": secrets.token_urlsafe(18)}
                                    if enrollment.provider == "openviking"
                                    and recipe.approved_route_id == "openviking-session-capture"
                                    else {}, 16 * 1024), None, None))
                db.execute("INSERT INTO compound_bindings VALUES(?,?,?,?,?,?)",
                    (handle, target_id, recipe_sha256, parent_grant_id,
                     parent_context_digest, parent_request_digest))
                db.commit()
            finally:
                db.close()
        return self.get(handle)

    def get(self, handle: str) -> MemoryJob:
        if not isinstance(handle, str) or not handle or len(handle) > 128:
            raise MemoryExecutionDenied("memory job handle is invalid")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                row = db.execute("SELECT handle,profile,namespace,provider,service_generation,"
                    "owner_generation,route_id,state,next_step,sequence,deadline,request_body,captures "
                    "FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
            finally:
                db.close()
        if row is None:
            raise MemoryExecutionDenied("memory job handle is unknown")
        try:
            request_body = json.loads(bytes(row[11]).decode("utf-8"))
            captures = json.loads(bytes(row[12]).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MemoryExecutionUnavailable("durable memory job state is malformed") from None
        return MemoryJob(*row[:11], request_body, captures)

    def begin_step(self, handle: str, *, expected_sequence: int,
                   step_id: str, expected_step_id: str) -> tuple[bytes, bytes | None, MemoryJob]:
        if step_id != expected_step_id:
            raise MemoryExecutionDenied("memory compound step does not match the enrolled sequence")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT source_context,consent,state,sequence,deadline,"
                    "inflight_step,inflight_sequence FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
                if row is None or row[2] != "active":
                    raise MemoryExecutionDenied("memory job is absent or not active")
                source, consent, state, sequence, deadline, inflight, inflight_sequence = row
                if (sequence != expected_sequence or inflight is not None
                        or inflight_sequence is not None or time.monotonic() >= deadline):
                    raise MemoryExecutionDenied("memory step was replayed, concurrent, or expired")
                db.execute("UPDATE compound_jobs SET inflight_step=?,inflight_sequence=?,effect_consumed=0,"
                           "compound_payload_sha256=NULL,service_request_sha256=NULL WHERE handle=?",
                           (step_id, expected_sequence, handle))
                db.commit()
            finally:
                db.close()
        return bytes(source), None if consent is None else bytes(consent), self.get(handle)

    def verify_step_binding(self, binding: MemoryStepBinding) -> None:
        """Recheck the active reservation immediately before an effect."""
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                row = db.execute("""
                    SELECT j.profile,j.namespace,j.provider,j.service_generation,
                           j.owner_generation,j.route_id,j.state,j.sequence,j.deadline,
                           j.source_context,j.consent,j.inflight_step,j.inflight_sequence,
                           b.target_id,b.recipe_sha256,b.parent_grant_id,
                           b.parent_context_digest,b.parent_request_digest,
                           j.compound_payload_sha256,j.service_request_sha256,j.effect_consumed
                    FROM compound_jobs j JOIN compound_bindings b ON b.handle=j.handle
                    WHERE j.handle=?
                """, (binding.job_handle,)).fetchone()
            finally:
                db.close()
        if row is None:
            raise MemoryExecutionDenied("memory compound binding is not in the root ledger")
        source = bytes(row[9])
        consent = None if row[10] is None else bytes(row[10])
        if (row[0] != binding.profile_id or row[1] != binding.namespace_id
                or row[2] != binding.provider or row[3] != binding.service_generation
                or row[4] != binding.memory_owner_generation or row[5] != binding.approved_route_id
                or row[6] != "active" or row[7] != binding.sequence
                or row[8] != binding.deadline_monotonic or time.monotonic() >= row[8]
                or row[11] != binding.step_id or row[12] != binding.sequence
                or row[13] != binding.target_id or row[14] != binding.recipe_sha256
                or row[15] != binding.parent_grant_id
                or row[16] != binding.parent_context_digest
                or row[17] != binding.parent_request_digest
                or hashlib.sha256(source).hexdigest() != binding.source_context_sha256
                or (None if consent is None else hashlib.sha256(consent).hexdigest())
                    != binding.consent_sha256
                or row[18] != binding.compound_envelope_sha256
                or row[19] != binding.service_request_sha256
                or row[20] != 0):
            raise MemoryExecutionDenied("memory step binding is stale, revoked, or differs from durable state")

    def bind_step_payload(self, binding: MemoryStepBinding) -> None:
        """Persist final canonical payload digests against the live reservation."""
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT j.profile,j.namespace,j.provider,j.service_generation,"
                    "j.owner_generation,j.route_id,j.state,j.sequence,j.deadline,j.source_context,j.consent,"
                    "j.inflight_step,j.inflight_sequence,j.effect_consumed,j.compound_payload_sha256,"
                    "j.service_request_sha256,b.target_id,b.recipe_sha256,b.parent_grant_id,"
                    "b.parent_context_digest,b.parent_request_digest FROM compound_jobs j "
                    "JOIN compound_bindings b ON b.handle=j.handle WHERE j.handle=?",
                    (binding.job_handle,)).fetchone()
                source = b"" if row is None else bytes(row[9])
                consent = None if row is None or row[10] is None else bytes(row[10])
                if (row is None or row[0] != binding.profile_id or row[1] != binding.namespace_id
                        or row[2] != binding.provider or row[3] != binding.service_generation
                        or row[4] != binding.memory_owner_generation or row[5] != binding.approved_route_id
                        or row[6] != "active" or row[7] != binding.sequence
                        or row[8] != binding.deadline_monotonic or row[11] != binding.step_id
                        or row[12] != binding.sequence or row[13] != 0 or row[14] is not None
                        or row[15] is not None or row[16] != binding.target_id
                        or row[17] != binding.recipe_sha256 or row[18] != binding.parent_grant_id
                        or row[19] != binding.parent_context_digest
                        or row[20] != binding.parent_request_digest
                        or hashlib.sha256(source).hexdigest() != binding.source_context_sha256
                        or (None if consent is None else hashlib.sha256(consent).hexdigest())
                            != binding.consent_sha256
                        or time.monotonic() >= row[8]):
                    raise MemoryExecutionDenied("memory step payload cannot bind to a stale reservation")
                db.execute("UPDATE compound_jobs SET compound_payload_sha256=?,service_request_sha256=? "
                    "WHERE handle=? AND effect_consumed=0 AND compound_payload_sha256 IS NULL "
                    "AND service_request_sha256 IS NULL",
                    (binding.compound_envelope_sha256, binding.service_request_sha256,
                     binding.job_handle))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def consume_step_effect(self, handle: str, compound_payload: bytes,
                            service_request_sha256: str) -> Mapping[str, Any]:
        """Atomically consume one exact reservation before any HI12 connector call."""
        if (not isinstance(compound_payload, bytes)
                or not isinstance(service_request_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", service_request_sha256)):
            raise MemoryExecutionDenied("memory connector payload digest is malformed")
        payload_sha256 = hashlib.sha256(compound_payload).hexdigest()
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT profile,namespace,provider,service_generation,owner_generation,"
                    "route_id,state,sequence,deadline,source_context,consent,inflight_step,"
                    "inflight_sequence,effect_consumed,compound_payload_sha256,service_request_sha256 "
                    "FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
                bind = db.execute("SELECT target_id,recipe_sha256,parent_grant_id,"
                    "parent_context_digest,parent_request_digest FROM compound_bindings WHERE handle=?",
                    (handle,)).fetchone()
                if (row is None or bind is None or row[6] != "active" or row[11] is None
                        or row[12] != row[7] or row[13] != 0 or row[14] != payload_sha256
                        or row[15] != service_request_sha256 or time.monotonic() >= row[8]):
                    raise MemoryExecutionDenied("memory effect reservation is stale, changed, or consumed")
                changed = db.execute("UPDATE compound_jobs SET effect_consumed=1 WHERE handle=? "
                    "AND state='active' AND effect_consumed=0 AND compound_payload_sha256=? "
                    "AND service_request_sha256=?", (handle, payload_sha256,
                                                       service_request_sha256)).rowcount
                if changed != 1:
                    raise MemoryExecutionDenied("memory effect reservation was concurrently consumed")
                result = {
                    "job_handle": handle,
                    "profile_id": row[0], "namespace_id": row[1], "provider": row[2],
                    "service_generation": row[3], "owner_generation": row[4],
                    "route_id": row[5], "sequence": row[7], "deadline_monotonic": row[8],
                    "source_context_wire": bytes(row[9]),
                    "consent_wire": None if row[10] is None else bytes(row[10]),
                    "step_id": row[11], "target_id": bind[0], "recipe_sha256": bind[1],
                    "parent_grant_id": bind[2], "parent_context_digest": bind[3],
                    "parent_request_digest": bind[4],
                    "compound_payload_sha256": payload_sha256,
                    "service_request_sha256": service_request_sha256,
                }
                db.commit()
                return result
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def get_consumed_step_effect(self, handle: str, compound_payload: bytes,
                                 service_request_sha256: str) -> Mapping[str, Any]:
        """Read a consumed binding for the root connector issuer's revalidation."""
        payload_sha256 = hashlib.sha256(compound_payload).hexdigest()
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                row = db.execute("SELECT profile,namespace,provider,service_generation,owner_generation,"
                    "route_id,state,sequence,deadline,source_context,consent,inflight_step,"
                    "inflight_sequence,effect_consumed,compound_payload_sha256,service_request_sha256 "
                    "FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
                bind = db.execute("SELECT target_id,recipe_sha256,parent_grant_id,"
                    "parent_context_digest,parent_request_digest FROM compound_bindings WHERE handle=?",
                    (handle,)).fetchone()
            finally:
                db.close()
        if (row is None or bind is None or row[6] != "active" or row[11] is None
                or row[12] != row[7] or row[13] != 1 or row[14] != payload_sha256
                or row[15] != service_request_sha256 or time.monotonic() >= row[8]):
            raise MemoryExecutionDenied("consumed memory effect binding changed or expired")
        return {
            "job_handle": handle,
            "profile_id": row[0], "namespace_id": row[1], "provider": row[2],
            "service_generation": row[3], "owner_generation": row[4],
            "route_id": row[5], "sequence": row[7], "deadline_monotonic": row[8],
            "source_context_wire": bytes(row[9]),
            "consent_wire": None if row[10] is None else bytes(row[10]),
            "step_id": row[11], "target_id": bind[0], "recipe_sha256": bind[1],
            "parent_grant_id": bind[2], "parent_context_digest": bind[3],
            "parent_request_digest": bind[4], "compound_payload_sha256": payload_sha256,
            "service_request_sha256": service_request_sha256,
        }

    def commit_step(self, handle: str, *, step_id: str, sequence: int,
                    step_index: int, captures: Mapping[str, str], final: bool) -> MemoryJob:
        if any(not isinstance(key, str) or not isinstance(value, str)
               for key, value in captures.items()):
            raise MemoryExecutionDenied("memory response captures must be strings")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT state,next_step,sequence,captures,inflight_step,"
                    "inflight_sequence,effect_consumed FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
                if (row is None or row[0] != "active" or row[1] != step_index
                        or row[2] != sequence or row[4] != step_id or row[5] != sequence
                        or row[6] != 1):
                    raise MemoryExecutionDenied("memory step transition lost its one-use reservation")
                old = json.loads(bytes(row[3]).decode("utf-8"))
                if not isinstance(old, dict) or set(old) & set(captures):
                    raise MemoryExecutionDenied("memory response capture is malformed or repeated")
                old.update(captures)
                db.execute("UPDATE compound_jobs SET state=?,next_step=?,sequence=?,captures=?,"
                    "inflight_step=NULL,inflight_sequence=NULL,effect_consumed=0,"
                    "compound_payload_sha256=NULL,service_request_sha256=NULL,source_context=?,consent=? WHERE handle=?",
                    ("complete" if final else "active", step_index + 1, sequence + 1,
                     canonical_json(old, 16 * 1024), b"" if final else db.execute(
                         "SELECT source_context FROM compound_jobs WHERE handle=?", (handle,)).fetchone()[0],
                     None if final else db.execute(
                         "SELECT consent FROM compound_jobs WHERE handle=?", (handle,)).fetchone()[0], handle))
                if final:
                    db.execute("UPDATE compound_jobs SET request_body=X'7b7d' WHERE handle=?", (handle,))
                db.commit()
            finally:
                db.close()
        return self.get(handle)

    def fail_step(self, handle: str, *, step_id: str, sequence: int,
                  state: str = "failed") -> None:
        if state not in {"failed", "ambiguous", "revoked", "unavailable"}:
            raise ValueError("invalid terminal memory job state")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT state,inflight_step,inflight_sequence FROM compound_jobs WHERE handle=?",
                                 (handle,)).fetchone()
                if row is None or row[0] != "active" or row[1:] != (step_id, sequence):
                    raise MemoryExecutionDenied("memory failure does not match the active step")
                db.execute("UPDATE compound_jobs SET state=?,source_context=X'',consent=NULL,request_body=X'7b7d',"
                    "captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL,effect_consumed=0,"
                    "compound_payload_sha256=NULL,service_request_sha256=NULL WHERE handle=?",
                    (state, handle))
                db.commit()
            finally:
                db.close()

    def revoke_owner(self, profile_id: str, provider: str,
                     owner_generation: int) -> int:
        """Revoke active jobs and erase private payload/provenance in one commit."""
        if (not isinstance(profile_id, str) or not profile_id or not isinstance(provider, str)
                or not provider or type(owner_generation) is not int or owner_generation < 1):
            raise ValueError("memory owner revocation identity is invalid")
        with memory_state_lock(self.owned, self.lock_path):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                cursor = db.execute("UPDATE compound_jobs SET state='revoked',source_context=X'',consent=NULL,"
                    "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL,"
                    "effect_consumed=0,compound_payload_sha256=NULL,service_request_sha256=NULL "
                    "WHERE profile=? AND provider=? AND owner_generation=? AND state='active'",
                    (profile_id, provider, owner_generation))
                db.commit()
                return cursor.rowcount
            finally:
                db.close()


class MemoryCompoundExecutor:
    """Execute a validated compound with atomic root state and fresh per-step effects."""

    def __init__(self, ledger: MemoryCompoundLedger, effect: MemoryStepEffect | None):
        self.ledger, self.effect = ledger, effect

    def execute(self, *, enrollment: MemoryServiceEnrollment, recipe: MemoryRouteRecipe,
                body: Mapping[str, Any], source_context_wire: bytes | Mapping[str, Any],
                parent_authorization: Any, parent_request_payload: bytes,
                consent_wire: bytes | Mapping[str, Any] | None = None,
                trusted_event: Mapping[str, Any] | None = None,
                cancelled: Callable[[], bool] = lambda: False) -> Mapping[str, Any]:
        if self.effect is None:
            raise MemoryExecutionUnavailable("root-owned authenticated memory connector is not installed")
        if enrollment.fixed_route_map.get(recipe.approved_route_id) != recipe:
            raise MemoryExecutionDenied("memory recipe does not match the selected service enrollment")
        source_wire = _wire(source_context_wire, 256 * 1024, "source context")
        context, parent_digest = _validate_parent(
            enrollment, recipe, source_wire, parent_authorization, parent_request_payload)
        recipe_digest = _recipe_digest(recipe)
        target_id = enrollment.target_id
        job = self.ledger.admit(enrollment=enrollment, recipe=recipe, request_body=body,
            source_context_wire=source_wire, consent_wire=consent_wire,
            target_id=target_id, recipe_sha256=recipe_digest,
            parent_grant_id=parent_authorization.grant_id,
            parent_context_digest=parent_authorization.context_digest,
            parent_request_digest=parent_digest,
            deadline_monotonic=time.monotonic() + recipe.maximum_seconds,
            maximum_bytes=recipe.maximum_bytes)
        try:
            for index, step in enumerate(recipe.steps):
                # commit_step advances the durable sequence and returns the
                # updated job. Read that current value for every step instead
                # of carrying a loop-local counter across a retry boundary.
                sequence = job.sequence
                source, consent, job = self.ledger.begin_step(
                    job.handle, expected_sequence=sequence,
                    step_id=step.step_id, expected_step_id=step.step_id)
                if job.state != "active":
                    raise MemoryExecutionDenied("memory job was revoked before the next step")
                if cancelled():
                    self.ledger.fail_step(job.handle, step_id=step.step_id,
                                          sequence=sequence, state="revoked")
                    raise MemoryExecutionDenied("memory compound was cancelled")
                captures = dict(job.captures)
                step_body: Mapping[str, Any] = {}
                if step.step_id == "append":
                    step_body = {"content": body.get("content")}
                elif step.step_id == "find":
                    step_body = body
                elif len(recipe.steps) == 1:
                    step_body = body
                protected_recipe = {
                    "credential_reference_id": recipe.credential_reference_id,
                    "scope_bindings": dict(recipe.scope_bindings),
                }
                protected_step = {
                    "method": step.method, "path_template": step.path_template,
                    "body_recipe_id": step.body_recipe_id,
                }
                try:
                    request = build_memory_request(
                        provider=enrollment.provider, route_id=recipe.approved_route_id,
                        recipe=protected_recipe, step=protected_step, body=step_body,
                        scope_bindings=recipe.scope_bindings, captures=captures,
                        trusted_event=trusted_event, maximum_bytes=recipe.maximum_bytes)
                    compound_envelope = canonical_json({
                        "schema": 1, "handle_id": job.handle,
                        "generation": enrollment.service_generation,
                        "sequence": sequence,
                        "compound_job_handle": job.handle,
                        "step_id": step.step_id,
                        "body": dict(step_body),
                    }, recipe.maximum_bytes)
                except BaseException:
                    self.ledger.fail_step(job.handle, step_id=step.step_id,
                                          sequence=sequence, state="failed")
                    raise
                payload_digest = hashlib.sha256(compound_envelope).hexdigest()
                service_request_digest = canonical_digest({
                    "method": request.method, "path": request.path,
                    "headers": list(request.headers),
                    "body_sha256": hashlib.sha256(request.body).hexdigest(),
                })
                consent_data = {} if consent is None else json.loads(consent.decode("utf-8"))
                consent_id = consent_data.get("consent_id") if isinstance(consent_data, dict) else None
                if consent_id is not None and not isinstance(consent_id, str):
                    raise MemoryExecutionDenied("persisted consent identity is malformed")
                binding = MemoryStepBinding(
                    profile_id=enrollment.profile_id,
                    namespace_id=enrollment.namespace_identity,
                    provider=enrollment.provider,
                    service_enrollment_id=enrollment.service_enrollment_id,
                    service_generation=enrollment.service_generation,
                    memory_owner_generation=enrollment.memory_owner_generation,
                    target_id=target_id,
                    approved_route_id=recipe.approved_route_id,
                    recipe_sha256=recipe_digest,
                    job_handle=job.handle,
                    step_id=step.step_id,
                    sequence=sequence,
                    deadline_monotonic=job.deadline_monotonic,
                    source_context_sha256=hashlib.sha256(source).hexdigest(),
                    consent_id=consent_id,
                    consent_sha256=None if consent is None else hashlib.sha256(consent).hexdigest(),
                    parent_grant_id=parent_authorization.grant_id,
                    parent_context_digest=parent_authorization.context_digest,
                    parent_request_digest=parent_digest,
                    compound_envelope_sha256=payload_digest,
                    service_request_sha256=service_request_digest,
                )
                self.ledger.bind_step_payload(binding)
                self.ledger.verify_step_binding(binding)
                try:
                    remaining = job.deadline_monotonic - time.monotonic()
                    if remaining <= 0:
                        raise MemoryExecutionDenied("memory compound deadline expired before effect")
                    # Consume the final one-use reservation atomically before
                    # the authority callback may issue any HI12 connector
                    # grant or place service bytes on the namespace socket.
                    self.ledger.consume_step_effect(
                        job.handle, compound_envelope, service_request_digest)
                    # This root callback re-resolves the durable reservation,
                    # route recipe, source closure, consent, owner/service
                    # generation and current policy before minting a fresh
                    # one-use connector grant. The parent grant is audit-only.
                    status, response_body = self.effect(
                        job.handle, compound_envelope, service_request_digest,
                        timeout=remaining, cancelled=cancelled)
                    if not isinstance(response_body, bytes) or len(response_body) > enrollment.limits["response_bytes"]:
                        raise MemoryRecipeUnavailable("memory connector response exceeds enrolled bounds")
                    try:
                        value = json.loads(response_body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError):
                        raise MemoryRecipeUnavailable("memory service response is not JSON") from None
                    expected_session = captures.get("session_id")
                    outcome = validate_step_outcome(route_id=recipe.approved_route_id,
                        step_id=step.step_id, status=status, value=value,
                        expected_session_id=expected_session,
                        scope_bindings=recipe.scope_bindings)
                    job = self.ledger.commit_step(job.handle, step_id=step.step_id,
                        sequence=sequence, step_index=index, captures=outcome.captures,
                        final=index == len(recipe.steps) - 1)
                except BaseException:
                    self.ledger.fail_step(job.handle, step_id=step.step_id,
                                          sequence=sequence, state="ambiguous")
                    raise
            return {"status": "ok", "result": dict(outcome.result),
                    "receipt_id": job.handle, "profile_id": job.profile_id,
                    "namespace_id": job.namespace_id}
        except (MemoryRecipeUnavailable, MemoryExecutionUnavailable):
            raise


class RootMemoryStepEffectAuthority:
    """Root-only HI12 issuer/handler for one fixed memory recipe step.

    The outer memory grant is retained only as audit metadata in the durable
    ledger. This adapter reconstructs and validates the exact service request,
    issues a new ``connector.open`` context/grant from the signed source
    lineage, and dispatches through AuthorityService's normal one-use effect
    path. Its registered connector handler accepts only a consumed ledger
    reservation; it never accepts worker-supplied HTTP.
    """

    def __init__(self, *, service: Any,
                 enrollment_resolver: Callable[[str, str], MemoryServiceEnrollment],
                 ledger_resolver: Callable[[str], MemoryCompoundLedger],
                 service_catalog: Any, process_manager: Any, vault: Any,
                 owner_state: Callable[[str], tuple[str | None, int]],
                 consent_active: Callable[[str], bool],
                 private_network_lease_resolver: Any | None = None,
                 ledger_profiles: tuple[str, ...] = (),
                 monotonic: Callable[[], float] = time.monotonic):
        if not all(callable(value) for value in (
                enrollment_resolver, ledger_resolver, owner_state, consent_active, monotonic)):
            raise ValueError("memory step authority requires root-owned active-state resolvers")
        if (not callable(getattr(service, "_issue_context", None))
                or not callable(getattr(service, "_authorize_effect", None))
                or not callable(getattr(service, "_perform_effect", None))
                or not callable(getattr(process_manager, "resolve_namespace_lease", None))
                or not callable(getattr(vault, "resolve_reference", None))):
            raise ValueError("memory step authority requires the protected HI12 and namespace services")
        self.service = service
        self.enrollment_resolver = enrollment_resolver
        self.ledger_resolver = ledger_resolver
        self.service_catalog = service_catalog
        self.process_manager = process_manager
        self.vault = vault
        self.owner_state = owner_state
        self.consent_active = consent_active
        if any(not isinstance(profile, str) or not profile for profile in ledger_profiles):
            raise ValueError("memory ledger profile IDs are malformed")
        self.profiles = tuple(sorted(set(ledger_profiles)))
        self.monotonic = monotonic
        self._registered: set[str] = set()
        from hermes_installer.memory.namespace_connector import MemoryNamespaceConnector
        self.namespace_transport = MemoryNamespaceConnector(
            catalog=service_catalog, process_manager=process_manager, vault=vault,
            private_network_lease_resolver=private_network_lease_resolver)

    def register(self) -> tuple[str, ...]:
        """Install only connector.open handlers backed by existing protected rules."""
        handlers = self.service.handlers
        if not isinstance(handlers, dict):
            raise MemoryExecutionUnavailable("AuthorityService handler table is not root mutable")
        targets = sorted({rule.target for rule in self.service.rules.values()
                          if rule.operation == "connector.open"
                          and rule.capability == "hermes-service-connect"
                          and isinstance(rule.target, str)
                          and rule.target.startswith("memory-")})
        registered: list[str] = []
        for target in targets:
            rules = [rule for rule in self.service.rules.values()
                     if rule.operation == "connector.open" and rule.target == target
                     and rule.capability == "hermes-service-connect"]
            if len(rules) != 1:
                continue
            key = ("connector.open", target)
            existing = handlers.get(key)
            if existing is not None and existing != self.handle_connector_open:
                continue
            handlers[key] = self.handle_connector_open
            self._registered.add(target)
            registered.append(target)
        return tuple(registered)

    def perform_step(self, reservation_handle: str,
                     canonical_connector_payload_bytes: bytes,
                     serialized_service_request_sha256: str, *,
                     timeout: float,
                     cancelled: Callable[[], bool]) -> tuple[int, bytes]:
        """Resolve a consumed reservation, then issue a fresh one-use HI12 grant."""
        if (not isinstance(reservation_handle, str) or not isinstance(canonical_connector_payload_bytes, bytes)
                or not re.fullmatch(r"[0-9a-f]{64}", serialized_service_request_sha256)
                or not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60):
            raise MemoryExecutionDenied("memory step effect arguments are malformed")
        ledger_hint = None
        # The profile is resolved from the durable reservation only. Search
        # configured ledgers by root-selected profile; never trust envelope IDs.
        for resolver_key in self._ledger_profiles():
            try:
                candidate = self.ledger_resolver(resolver_key)
                binding = candidate.get_consumed_step_effect(
                    reservation_handle, canonical_connector_payload_bytes,
                    serialized_service_request_sha256)
            except (MemoryExecutionDenied, KeyError, ValueError):
                continue
            ledger_hint = candidate
            break
        if ledger_hint is None or binding is None:
            raise MemoryExecutionDenied("no root-owned consumed memory step reservation matches")
        enrollment, recipe, step, request, job, source, consent = self._revalidate_step(
            binding, canonical_connector_payload_bytes, serialized_service_request_sha256,
            cancelled=cancelled)
        if source.signature == "verified-in-service":
            # Re-issue the exact claims as a root signature for AuthorityService's
            # fresh child-context issuer. This is permitted only after the
            # original signed parent grant was verified/consumed by the broker
            # and the durable reservation's parent binding was revalidated.
            source = HostContext.from_wire(self.service._signed_context(
                source, self.service._sign(source.claims())))
            self.service._verify_context_signature(source)
        if enrollment.target_id not in self._registered:
            raise MemoryExecutionUnavailable("no protected HI12 connector.open rule is installed for memory")
        remaining = min(float(timeout), binding["deadline_monotonic"] - self.monotonic(),
                        enrollment.limits["operation_timeout_seconds"])
        if remaining <= 0:
            raise MemoryExecutionDenied("memory step deadline expired before HI12 grant")
        child_payload = canonical_json({
            "schema": 1, "job_handle": reservation_handle,
            "target_id": enrollment.target_id,
            "compound_envelope": __import__("base64").b64encode(
                canonical_connector_payload_bytes).decode("ascii"),
            "compound_payload_sha256": binding["compound_payload_sha256"],
            "service_request_sha256": serialized_service_request_sha256,
            "route_id": recipe.approved_route_id, "step_id": step.step_id,
            "sequence": binding["sequence"],
            "service_generation": enrollment.service_generation,
            "owner_generation": enrollment.memory_owner_generation,
        }, min(4 * 1024 * 1024, enrollment.limits["request_bytes"] + 32_768))
        payload_digest = canonical_digest(child_payload)
        # Context issuance itself takes time; reserve a small monotonic margin
        # so the signed child lease can never extend past the durable job's
        # original hard deadline.
        child_lease = min(remaining, binding["deadline_monotonic"] - self.monotonic(), 30.0) - 0.05
        if child_lease <= 0:
            raise MemoryExecutionDenied("memory step deadline expired before child grant")
        context_wire = self.service._issue_context(source.uid, {
            "purpose": "memory-service-connector",
            "intent": f"{reservation_handle}:{step.step_id}:{binding['sequence']}",
            "trace_id": source.trace_id,
            "lease_seconds": child_lease,
            "source_contexts": [source.to_wire()],
            "final_payload_digest": payload_digest,
            "operation": "connector.open",
        }, allow_expired_sources=True,
           inherited_process_identity=source.native_process_identity)
        context = HostContext.from_wire(context_wire)
        rule = self._connector_rule(enrollment.target_id)
        authorization_wire = self.service._authorize_effect(source.uid, {
            "context": context.to_wire(), "capability": rule.capability,
            "target": enrollment.target_id, "recipient": rule.recipient,
            "request_digest": payload_digest, "retry_index": 0,
        })
        authorization = EffectAuthorization.from_wire(authorization_wire)
        if (authorization.operation != "connector.open"
                or authorization.target != enrollment.target_id
                or authorization.request_digest != payload_digest
                or authorization.final_payload_digest != payload_digest
                or authorization.context_digest != canonical_digest(
                    {**context.claims(), "signature": context.signature})
                or authorization.monotonic_expires_at > binding["deadline_monotonic"]):
            raise MemoryExecutionDenied("AuthorityService returned a differently bound memory HI12 grant")
        result = self.service._perform_effect(source.uid, os.getpid(), {
            "authorization": authorization.to_wire(), "operation": "connector.open",
            "payload": __import__("base64").b64encode(child_payload).decode("ascii"),
            "timeout": remaining,
        }, cancelled=lambda: cancelled() or self.monotonic() >= binding["deadline_monotonic"],
            enforce_peer_identity=False)
        try:
            return result["status"], __import__("base64").b64decode(result["body"], validate=True)
        except (KeyError, TypeError, ValueError):
            raise MemoryExecutionUnavailable("root memory connector returned a malformed receipt") from None

    def perform_memory_connector_step(self, reservation_handle: str,
                     canonical_connector_payload_bytes: bytes,
                     serialized_service_request_sha256: str, *,
                     timeout: float, cancelled: Callable[[], bool]) -> tuple[int, bytes]:
        """AuthorityService's narrow root-only callback spelling."""
        return self.perform_step(reservation_handle, canonical_connector_payload_bytes,
            serialized_service_request_sha256, timeout=timeout, cancelled=cancelled)

    def handle_connector_open(self, *, context: HostContext,
                              authorization: EffectAuthorization, payload: bytes,
                              timeout: float, peer_pid: int, peer_pidfd: int | None,
                              cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """One-use internal connector handler, dispatchable only for a ledger step."""
        import base64
        try:
            value = json.loads(payload.decode("utf-8"))
            if (not isinstance(value, dict) or canonical_json(value) != payload
                    or set(value) != {"schema", "job_handle", "compound_envelope", "target_id",
                        "compound_payload_sha256", "service_request_sha256", "route_id",
                        "step_id", "sequence", "service_generation", "owner_generation"}
                    or type(value["schema"]) is not int or value["schema"] != 1):
                raise ValueError
            envelope = base64.b64decode(value["compound_envelope"], validate=True)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, KeyError):
            raise MemoryExecutionDenied("internal memory HI12 payload is malformed") from None
        ledger = self.ledger_resolver(context.profile_id)
        binding = ledger.get_consumed_step_effect(
            value["job_handle"], envelope, value["service_request_sha256"])
        if (context.operation != "connector.open"
                or authorization.operation != "connector.open"
                or authorization.target != value["target_id"]
                or binding["job_handle"] != value["job_handle"]
                or binding["profile_id"] != context.profile_id
                or binding["namespace_id"] != context.namespace_id
                or binding["compound_payload_sha256"] != value["compound_payload_sha256"]
                or value["route_id"] != binding["route_id"]
                or value["step_id"] != binding["step_id"]
                or value["sequence"] != binding["sequence"]
                or value["service_generation"] != binding["service_generation"]
                or value["owner_generation"] != binding["owner_generation"]):
            raise MemoryExecutionDenied("internal memory HI12 effect differs from consumed reservation")
        enrollment, recipe, step, request, job, source, consent = self._revalidate_step(
            binding, envelope, value["service_request_sha256"], cancelled=cancelled)
        if (authorization.target != enrollment.target_id
                or authorization.capability != "hermes-service-connect"
                or context.profile_id != enrollment.profile_id
                or context.namespace_id != enrollment.namespace_identity):
            raise MemoryExecutionDenied("memory HI12 grant differs from selected service route")
        digest = canonical_digest({
            "method": request.method, "path": request.path,
            "headers": list(request.headers),
            "body_sha256": __import__("hashlib").sha256(request.body).hexdigest(),
        })
        if digest != value["service_request_sha256"]:
            raise MemoryExecutionDenied("reconstructed memory service request digest changed")
        from hermes_installer.memory.namespace_connector import MemoryNamespaceConnector
        connector = getattr(self, "namespace_transport", None)
        if not isinstance(connector, MemoryNamespaceConnector):
            raise MemoryExecutionUnavailable("root memory namespace connector is unavailable")
        def before_connect(frame_sha256: str) -> None:
            # The outer HI12 grant was consumed by _perform_effect immediately
            # before entering this registered handler. Recheck freshness and
            # owner/consent immediately before the socket connect.
            self._revalidate_step(binding, envelope, value["service_request_sha256"],
                                  cancelled=cancelled)
            if not re.fullmatch(r"[0-9a-f]{64}", frame_sha256):
                raise MemoryExecutionDenied("memory connector frame digest is malformed")
            self.service._verify_grant_signature(authorization)
            current = self.service._binding(context.uid)
            self.service._assert_current_context(context, current, context.uid)
            self.service._assert_grant_current(authorization, current, context.uid)
            rule = self._connector_rule(enrollment.target_id)
            if not self.service.policy.allow_effect(
                    context=context, rule=rule, request_digest=authorization.request_digest,
                    retry_index=authorization.retry_index):
                raise MemoryExecutionDenied("memory HI12 policy was revoked before namespace connect")
        response = connector.request(enrollment=enrollment, route_id=recipe.approved_route_id,
            request=request, before_connect=before_connect,
            timeout=min(timeout, enrollment.limits["operation_timeout_seconds"]),
            deadline=binding["deadline_monotonic"], cancelled=cancelled)
        if not isinstance(response.body, bytes):
            raise MemoryExecutionUnavailable("memory namespace connector returned invalid bytes")
        return {"status": response.status, "body": response.body,
                "headers": {"content-type": "application/json"},
                "receipt_id": secrets.token_urlsafe(18)}

    def _connector_rule(self, target: str) -> Any:
        rules = [rule for rule in self.service.rules.values()
                 if rule.operation == "connector.open" and rule.target == target
                 and rule.capability == "hermes-service-connect"]
        if len(rules) != 1:
            raise MemoryExecutionUnavailable("exact protected HI12 connector.open rule is not enrolled")
        return rules[0]

    def _ledger_profiles(self) -> tuple[str, ...]:
        if self.profiles:
            return self.profiles
        return tuple(sorted({principal.profile_id
                             for principal in self.service.bindings_by_uid.values()}))

    def _revalidate_step(self, binding: Mapping[str, Any], envelope_wire: bytes,
                         service_request_sha256: str, *,
                         cancelled: Callable[[], bool]) -> tuple[Any, Any, Any, Any, Any, HostContext, Any]:
        if cancelled() or self.monotonic() >= binding["deadline_monotonic"]:
            raise MemoryExecutionDenied("memory step was cancelled or expired")
        profile = binding["profile_id"]
        enrollment = self.enrollment_resolver(profile, binding["service_generation"])
        if (not isinstance(enrollment, MemoryServiceEnrollment)
                or enrollment.profile_id != profile
                or enrollment.namespace_identity != binding["namespace_id"]
                or enrollment.provider != binding["provider"]
                or enrollment.service_generation != binding["service_generation"]
                or enrollment.memory_owner_generation != binding["owner_generation"]
                or enrollment.target_id != binding["target_id"]):
            raise MemoryExecutionDenied("current protected memory service differs from consumed ledger")
        if self.owner_state(profile) != (enrollment.provider, enrollment.memory_owner_generation):
            raise MemoryExecutionDenied("memory owner generation changed before connector effect")
        try:
            source_value = json.loads(binding["source_context_wire"].decode("utf-8"))
            source = HostContext.from_wire(source_value)
            if source.signature == "verified-in-service":
                # The outer fixed-effect broker already verified and consumed
                # the signed parent grant before invoking this root-only
                # handler. It reconstructs HostContext with this sentinel, so
                # only the protected compound ledger can persist it. Admission
                # bound its complete claims to the consumed grant; do not treat
                # this internal receipt marker as a client signature.
                if (not binding.get("parent_grant_id")
                        or not binding.get("parent_context_digest")
                        or not binding.get("parent_request_digest")):
                    raise ValueError("verified parent binding is absent")
            else:
                self.service._verify_context_signature(source)
        except Exception:
            raise MemoryExecutionDenied("signed memory source lineage is no longer valid") from None
        principal = self.service._binding(source.uid)
        if (source.profile_id != profile or source.namespace_id != enrollment.namespace_identity
                or source.principal_id != enrollment.principal_id
                or principal.profile_id != profile or principal.namespace_id != enrollment.namespace_identity
                or source.policy_revision != self.service._policy_revision()
                or not source.native_process_identity):
            raise MemoryExecutionDenied("source lineage no longer matches active host identity")
        consent = binding["consent_wire"]
        consent_value = None
        if consent is not None:
            try:
                consent_value = json.loads(consent.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise MemoryExecutionDenied("persisted memory consent is malformed") from None
            expected_consent_fields = {
                "kind", "consent_id", "source_context_digest", "principal_id", "profile_id",
                "namespace_id", "uid", "provider_id", "owner_generation", "policy_revision",
                "allowed_actions", "issued_at_unix", "expires_at_unix", "signature",
            }
            if not isinstance(consent_value, dict) or set(consent_value) != expected_consent_fields:
                raise MemoryExecutionDenied("persisted memory consent schema is invalid")
            consent_id = consent_value.get("consent_id") if isinstance(consent_value, dict) else None
            signature = consent_value.pop("signature", None) if isinstance(consent_value, dict) else None
            try:
                if not isinstance(signature, str):
                    raise ValueError
                self.service._verify_signature(consent_value, signature)
            except Exception:
                raise MemoryExecutionDenied("persisted memory consent signature is invalid") from None
            now_wall = self.service.wall_clock()
            source_digest = canonical_digest({**source.claims(), "signature": source.signature})
            if (not isinstance(consent_id, str) or self.consent_active(consent_id) is not True
                    or consent_value.get("kind") != "memory-background-consent-v1"
                    or consent_value.get("source_context_digest") != source_digest
                    or consent_value.get("principal_id") != enrollment.principal_id
                    or consent_value.get("uid") != source.uid
                    or consent_value.get("profile_id") != profile
                    or consent_value.get("namespace_id") != binding["namespace_id"]
                    or consent_value.get("provider_id") != binding["provider"]
                    or consent_value.get("owner_generation") != binding["owner_generation"]
                    or consent_value.get("policy_revision") != self.service._policy_revision()
                    or type(consent_value.get("issued_at_unix")) not in (int, float)
                    or consent_value.get("issued_at_unix", 0) > now_wall
                    or consent_value.get("expires_at_unix", 0) <= now_wall
                    or consent_value.get("expires_at_unix", 0) - consent_value.get("issued_at_unix", 0) > 86_400
                    or not isinstance(consent_value.get("allowed_actions"), list)
                    or len(consent_value.get("allowed_actions", [])) != len(set(consent_value.get("allowed_actions", [])))
                    or "capture" not in consent_value.get("allowed_actions", ())):
                raise MemoryExecutionDenied("memory background consent is revoked")
            consent_value["signature"] = signature
        recipe = enrollment.fixed_route_map.get(binding["route_id"])
        if not isinstance(recipe, MemoryRouteRecipe) or binding["recipe_sha256"] != _recipe_digest(recipe):
            raise MemoryExecutionDenied("active memory recipe differs from reserved digest")
        try:
            envelope = json.loads(envelope_wire.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MemoryExecutionDenied("reserved memory compound envelope is malformed") from None
        if (not isinstance(envelope, dict) or set(envelope) != {
                "schema", "handle_id", "generation", "sequence",
                "compound_job_handle", "step_id", "body"}
                or type(envelope["schema"]) is not int or envelope["schema"] != 1
                or envelope["handle_id"] != envelope["compound_job_handle"]
                or envelope["compound_job_handle"] != binding["job_handle"]
                or envelope["generation"] != enrollment.service_generation
                or envelope["sequence"] != binding["sequence"]
                or envelope["step_id"] != binding["step_id"]
                or canonical_json(envelope, recipe.maximum_bytes) != envelope_wire):
            raise MemoryExecutionDenied("memory compound envelope differs from reservation")
        handle = binding.get("job_handle")
        # get_consumed_step_effect intentionally returns no caller-supplied
        # identity. Re-read by the opaque job handle in the exact envelope.
        handle = envelope["compound_job_handle"]
        if envelope["handle_id"] != handle:
            raise MemoryExecutionDenied("memory compound job handle mismatch")
        ledger = self.ledger_resolver(profile)
        job = ledger.get(handle)
        step = recipe.steps[job.next_step] if 0 <= job.next_step < len(recipe.steps) else None
        if (step is None or step.step_id != binding["step_id"]
                or job.state != "active" or job.sequence != binding["sequence"]
                or job.profile_id != profile or job.namespace_id != enrollment.namespace_identity):
            raise MemoryExecutionDenied("current memory step does not match durable job order")
        body = envelope["body"]
        expected_body: Mapping[str, Any] = (job.request_body if step.step_id == "find"
            or len(recipe.steps) == 1 else {"content": job.request_body.get("content")}
            if step.step_id == "append" else {})
        if body != expected_body:
            raise MemoryExecutionDenied("worker step body differs from the root-selected job payload")
        protected_recipe = {"credential_reference_id": recipe.credential_reference_id,
                            "scope_bindings": dict(recipe.scope_bindings)}
        protected_step = {"method": step.method, "path_template": step.path_template,
                          "body_recipe_id": step.body_recipe_id}
        request = build_memory_request(provider=enrollment.provider,
            route_id=recipe.approved_route_id, recipe=protected_recipe,
            step=protected_step, body=body, scope_bindings=recipe.scope_bindings,
            captures=job.captures, trusted_event=None,
            maximum_bytes=recipe.maximum_bytes)
        actual_digest = canonical_digest({"method": request.method, "path": request.path,
            "headers": list(request.headers),
            "body_sha256": __import__("hashlib").sha256(request.body).hexdigest()})
        if actual_digest != service_request_sha256 or actual_digest != binding["service_request_sha256"]:
            raise MemoryExecutionDenied("fixed service serializer differs from consumed request digest")
        return enrollment, recipe, step, request, job, source, consent_value
