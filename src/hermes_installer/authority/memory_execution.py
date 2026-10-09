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
    action = "search" if "search" in recipe.approved_route_id else "capture"
    capability = "memory-retrieval" if action == "search" else "memory-capture"
    target = f"memory:{enrollment.provider}:{action}"
    operation = f"memory.{action}"
    digest = hashlib.sha256(parent_request_payload).hexdigest()
    context_digest = canonical_digest({**context.claims(), "signature": context.signature})
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
            or parent.context_digest != context_digest
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
                        inflight_step TEXT, inflight_sequence INTEGER
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
                db.execute("UPDATE compound_jobs SET state='ambiguous',source_context=X'',consent=NULL,"
                           "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,"
                           "inflight_sequence=NULL WHERE state='active'")
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
                db.execute("INSERT INTO compound_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                db.execute("UPDATE compound_jobs SET inflight_step=?,inflight_sequence=? WHERE handle=?",
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
                           b.parent_context_digest,b.parent_request_digest
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
                    != binding.consent_sha256):
            raise MemoryExecutionDenied("memory step binding is stale, revoked, or differs from durable state")

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
                    "inflight_sequence FROM compound_jobs WHERE handle=?", (handle,)).fetchone()
                if (row is None or row[0] != "active" or row[1] != step_index
                        or row[2] != sequence or row[4] != step_id or row[5] != sequence):
                    raise MemoryExecutionDenied("memory step transition lost its one-use reservation")
                old = json.loads(bytes(row[3]).decode("utf-8"))
                if not isinstance(old, dict) or set(old) & set(captures):
                    raise MemoryExecutionDenied("memory response capture is malformed or repeated")
                old.update(captures)
                db.execute("UPDATE compound_jobs SET state=?,next_step=?,sequence=?,captures=?,"
                    "inflight_step=NULL,inflight_sequence=NULL,source_context=?,consent=? WHERE handle=?",
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
                    "captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL WHERE handle=?",
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
                    "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL "
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
                sequence = job.sequence if index == 0 else sequence
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
                self.ledger.verify_step_binding(binding)
                try:
                    remaining = job.deadline_monotonic - time.monotonic()
                    if remaining <= 0:
                        raise MemoryExecutionDenied("memory compound deadline expired before effect")
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
