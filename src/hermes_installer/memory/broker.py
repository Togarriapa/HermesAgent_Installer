"""Root-owned fixed-target memory effects and durable background ingestion."""
from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

if TYPE_CHECKING:
    from hermes_installer.authority.types import EffectAuthorization, HostContext
from hermes_installer.state import OwnedRoot, process_lock
from hermes_installer.memory.owner_ledger import SQLiteOwnerLedger
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.transport import MemoryServiceIPC, RootConnectorFactory

MAX_REQUEST = 256 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_EVENT = 64 * 1024
MAX_FACTS = 64
PROVIDERS = frozenset({"openviking", "claude-mem", "agentmemory"})
SOURCE_REVISIONS = {
    "openviking": "e7b2e974b1fb97cd8c6087ff013181ddfec94f77",
    "claude-mem": "fa8ab09f06aa05f958c5225cf3756ce52a3ebb96",
    "agentmemory": "df3d4a83b966d8d415cb9180d5a4724b07f729dc",
}
ACTIONS = frozenset({"doctor", "extract", "embed", "capture", "search", "export",
                     "delete", "backup", "restore", "enqueue", "result"})
CAPABILITIES = {
    "doctor": "memory-retrieval", "search": "memory-retrieval",
    "extract": "memory-extraction", "embed": "memory-embedding",
    "capture": "memory-capture", "enqueue": "memory-capture",
    "export": "memory-export", "backup": "memory-backup",
    "restore": "memory-restore", "delete": "memory-delete", "result": "memory-retrieval",
}
ROUTE_IDS = {
    "openviking": {
        "doctor": "memory.openviking.ready.v1",
        "search": "memory.openviking.search.find.v1",
        "capture": "memory.openviking.session.capture.v1",
    },
    "claude-mem": {
        "doctor": "memory.claude-mem.healthz.v1",
        "search": "memory.claude-mem.search.v1",
        "capture": "memory.claude-mem.create.v1",
        "delete": "memory.claude-mem.delete.v1",
    },
    "agentmemory": {
        "doctor": "memory.agentmemory.livez.v1",
        "search": "memory.agentmemory.smart-search.v1",
        "capture": "memory.agentmemory.remember.v1",
        "delete": "memory.agentmemory.forget.v1",
        "export": "memory.agentmemory.export.v1",
        "backup": "memory.agentmemory.export.v1",
        "restore": "memory.agentmemory.import.v1",
    },
}


class BrokerUnavailable(RuntimeError):
    pass


class BrokerDenied(PermissionError):
    pass


class ServiceIPC(Protocol):
    """Root-owned broker transport. No endpoint, method, path, or key from a worker."""
    def request(self, *, context: HostContext, authorization: EffectAuthorization,
                service_id: str, service_generation: int, provider: str,
                route_id: str, session_id: str, deadline_monotonic: float,
                payload: bytes, timeout: float, peer_pid: int,
                peer_pidfd: int | None, cancelled: Callable[[], bool]) -> bytes: ...


class PrivateEngine(Protocol):
    engine_id: str
    route_class: str
    private: bool
    def extract(self, *, text: str, context: HostContext, timeout: float,
                cancelled: Callable[[], bool]) -> list[str]: ...
    def embed(self, *, facts: list[str], context: HostContext, timeout: float,
              cancelled: Callable[[], bool]) -> list[list[float]]: ...


class OwnerState(Protocol):
    def __call__(self, profile_id: str) -> tuple[str | None, int]: ...


class BackgroundEffect(Protocol):
    def __call__(self, *, source_context_wire: bytes, consent_wire: bytes,
                 provider_id: str, owner_generation: int, action: str,
                 capability: str, payload: bytes, timeout: float,
                 cancelled: Callable[[], bool]) -> Any: ...


class BackgroundConsentIssuer(Protocol):
    def __call__(self, *, context: HostContext, provider_id: str,
                 owner_generation: int, ttl_seconds: int = 300) -> Any: ...


def _consent_wire(value: Any) -> tuple[str, bytes]:
    """Persist the authority-issued signed consent as canonical bounded JSON."""
    serializer = getattr(value, "to_wire", None)
    wire = serializer() if callable(serializer) else value
    if not isinstance(wire, Mapping):
        raise BrokerDenied("authority did not return typed background consent")
    consent_id, signature = wire.get("consent_id"), wire.get("signature")
    if (not isinstance(consent_id, str) or not consent_id or len(consent_id) > 256
            or not isinstance(signature, str) or not signature):
        raise BrokerDenied("authority consent lacks a stable ID or signature")
    return consent_id, canonical(dict(wire), 16 * 1024)


@dataclass(frozen=True, slots=True)
class MemoryTarget:
    provider: str
    profile_id: str
    namespace_id: str
    service_id: str
    source_revision: str
    service_generation: int
    data_root_id: str
    dedicated_store: bool = True
    approved_route_ids: frozenset[str] = frozenset()
    enrollment: MemoryServiceEnrollment | None = None

    @classmethod
    def from_enrollment(cls, enrollment: MemoryServiceEnrollment) -> "MemoryTarget":
        if not isinstance(enrollment, MemoryServiceEnrollment):
            raise TypeError("MemoryServiceEnrollment is required")
        return cls(
            provider=enrollment.provider, profile_id=enrollment.profile_id,
            namespace_id=enrollment.namespace_identity,
            service_id=enrollment.service_enrollment_id,
            source_revision=enrollment.source_revision,
            service_generation=enrollment.service_generation,
            data_root_id=enrollment.data_root_id, dedicated_store=True,
            approved_route_ids=frozenset(enrollment.fixed_route_map),
            enrollment=enrollment,
        )

    def route_for(self, action: str) -> str | None:
        if self.enrollment is None:
            return ROUTE_IDS[self.provider].get(action)
        e = self.enrollment
        if self.provider == "openviking":
            choices = {"doctor": "openviking-ready", "search": "openviking-find",
                       "capture": "openviking-session-capture"}
        elif self.provider == "agentmemory":
            choices = {"doctor": "agentmemory-ready", "search": "agentmemory-search",
                       "capture": "agentmemory-capture", "delete": "agentmemory-delete",
                       "export": "agentmemory-export", "backup": "agentmemory-backup",
                       "restore": "agentmemory-restore"}
        elif e.backend_variant == "server-v1-sqlite":
            choices = {"doctor": "claude-sqlite-ready", "search": "claude-sqlite-search",
                       "capture": "claude-sqlite-capture"}
        elif e.backend_variant == "server-v1-postgres":
            choices = {"doctor": "claude-postgres-ready", "search": "claude-postgres-search",
                       "capture": "claude-postgres-capture", "delete": "claude-postgres-delete"}
        elif e.backend_variant == "worker-observation":
            choices = {"capture": "claude-worker-capture", "search": "claude-worker-search-get",
                       "delete": "claude-worker-delete"}
        else:
            return None
        route_id = choices.get(action)
        return route_id if route_id in e.fixed_route_map else None

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS or not all(
                isinstance(x, str) and x and len(x) <= 256 for x in
                (self.profile_id, self.namespace_id, self.service_id, self.data_root_id)):
            raise ValueError("invalid protected provider enrollment")
        if self.source_revision != SOURCE_REVISIONS[self.provider]:
            raise ValueError("provider source revision differs from the reviewed pin")
        if self.enrollment is None:
            if type(self.service_generation) is not int or self.service_generation < 1:
                raise ValueError("legacy fixture generation must be a positive integer")
            allowed_routes = frozenset(ROUTE_IDS[self.provider].values())
        else:
            e = self.enrollment
            if not isinstance(self.service_generation, str) or not self.service_generation:
                raise ValueError("opaque host service generation is required")
            if (self.service_generation != e.service_generation
                    or self.service_id != e.service_enrollment_id
                    or self.profile_id != e.profile_id
                    or self.namespace_id != e.namespace_identity
                    or self.data_root_id != e.data_root_id
                    or self.provider != e.provider
                    or self.source_revision != e.source_revision):
                raise ValueError("memory target differs from strict protected enrollment")
            allowed_routes = frozenset(e.fixed_route_map)
        if isinstance(self.approved_route_ids, (str, bytes)):
            raise ValueError("protected approved route IDs must be a sequence of opaque IDs")
        try:
            approved = frozenset(self.approved_route_ids)
        except TypeError as exc:
            raise ValueError("protected approved route IDs are malformed") from exc
        if any(not isinstance(route, str) or route not in allowed_routes for route in approved):
            raise ValueError("memory enrollment contains an unknown provider route ID")
        object.__setattr__(self, "approved_route_ids", approved)
        if self.provider == "agentmemory" and self.dedicated_store is not True:
            raise ValueError("AgentMemory requires an isolated per-profile service and data store")


def canonical(value: Any, maximum: int = MAX_REQUEST) -> bytes:
    data = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(data) > maximum:
        raise ValueError("memory payload exceeds its bound")
    return data


def parse_request(data: bytes) -> dict[str, Any]:
    if not isinstance(data, bytes) or len(data) > MAX_REQUEST:
        raise ValueError("memory request exceeds its byte bound")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("memory request is invalid JSON") from None
    if not isinstance(value, dict) or canonical(value) != data or type(value.get("schema")) is not int or value["schema"] != 1:
        raise ValueError("memory request must be canonical schema-1 JSON")
    return value


def _scope(context: Any, target: MemoryTarget, body: Mapping[str, Any]) -> None:
    if context.profile_id != target.profile_id or context.namespace_id != target.namespace_id:
        raise BrokerDenied("signed host scope differs from enrolled service target")
    for key, expected in (("profile", context.profile_id), ("namespace", context.namespace_id),
                          ("profile_id", context.profile_id), ("namespace_id", context.namespace_id)):
        if key in body and body[key] != expected:
            raise BrokerDenied("caller profile or namespace differs from signed host scope")


def _text(value: Any, name: str, limit: int) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > limit:
        raise ValueError(name + " is missing or oversized")
    return value


def _facts(value: Any) -> list[str]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_FACTS:
        raise ValueError("facts must contain 1..64 items")
    return [_text(item, "fact", 8192) for item in value]


def _vectors(value: Any, count: int) -> list[list[float]]:
    if not isinstance(value, list) or len(value) != count:
        raise ValueError("embedding count must match facts")
    result = []
    width = None
    for row in value:
        if not isinstance(row, list) or not 1 <= len(row) <= 8192:
            raise ValueError("embedding dimensions are invalid")
        width = len(row) if width is None else width
        if len(row) != width or any(type(x) not in (int, float) or not math.isfinite(x) for x in row):
            raise ValueError("embedding vector is malformed")
        result.append([float(x) for x in row])
    return result


def _reply(value: Mapping[str, Any], status: int = 200) -> Mapping[str, Any]:
    return {"status": status, "body": canonical(dict(value), MAX_RESPONSE),
            "headers": {"content-type": "application/json"},
            "receipt_id": secrets.token_urlsafe(18)}


class DurableMemoryQueue:
    """Root-owned durable event journal; payloads never enter logs."""

    def __init__(self, root: Path, *, owner_state: OwnerState,
                 consent_issuer: BackgroundConsentIssuer,
                 clock: Callable[[], float] = time.time):
        self.owned = OwnedRoot(root)
        self.owned.ensure()
        self.path = self.owned.path("memory-queue.sqlite3")
        self.owner_state, self.consent_issuer, self.clock = owner_state, consent_issuer, clock
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs(
                    id TEXT PRIMARY KEY, profile TEXT NOT NULL, namespace TEXT NOT NULL,
                    provider TEXT NOT NULL, owner_generation INTEGER NOT NULL,
                    source_context BLOB NOT NULL, consent BLOB NOT NULL, event BLOB NOT NULL,
                    status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                    lease_until REAL, created REAL NOT NULL, updated REAL NOT NULL,
                    result BLOB, error_code TEXT, consent_id TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS memory_jobs_ready ON jobs(status,created);
                CREATE TABLE IF NOT EXISTS consents(
                    consent_id TEXT PRIMARY KEY, profile TEXT NOT NULL, provider TEXT NOT NULL,
                    owner_generation INTEGER NOT NULL, active INTEGER NOT NULL,
                    created REAL NOT NULL, updated REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS memory_consents_owner
                    ON consents(profile,provider,owner_generation,active);
                """)
                columns = {row[1] for row in db.execute("PRAGMA table_info(jobs)")}
                if "consent_id" not in columns:
                    db.execute("ALTER TABLE jobs ADD COLUMN consent_id TEXT NOT NULL DEFAULT ''")
            finally:
                db.close()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA busy_timeout=2000")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA secure_delete=ON")
        return db

    def enqueue(self, *, target: MemoryTarget, context: HostContext,
                body: Mapping[str, Any]) -> str:
        _scope(context, target, body)
        kind = body.get("event")
        if kind == "turn":
            event = {"event": kind, "session_id": _text(body.get("session_id", "unknown"), "session_id", 256),
                     "user_content": _text(body.get("user_content"), "user content", 24 * 1024),
                     "assistant_content": _text(body.get("assistant_content"), "assistant content", 24 * 1024)}
        elif kind == "memory-write" and body.get("action") in {"add", "update"} and body.get("target") in {"memory", "user"}:
            event = {"event": kind, "content": _text(body.get("content"), "memory content", 24 * 1024)}
        else:
            raise ValueError("unsupported or recursive memory capture event")
        owner, generation = self.owner_state(context.profile_id)
        if owner != target.provider or type(generation) is not int or generation < 1:
            raise BrokerDenied("provider is not the durable capture owner")
        source = canonical(context.to_wire(), 16 * 1024)
        consent_id, consent = _consent_wire(self.consent_issuer(
            context=context, provider_id=target.provider,
            owner_generation=generation, ttl_seconds=300))
        raw_event = canonical(event, MAX_EVENT)
        receipt = secrets.token_urlsafe(24)
        now = self.clock()
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM jobs WHERE status IN ('complete','failed') AND updated<?",
                           (now - 30 * 86400,))
                db.execute("DELETE FROM consents WHERE active=0 AND updated<?", (now - 30 * 86400,))
                n = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','processing')").fetchone()[0]
                if n >= 10000:
                    raise BrokerUnavailable("durable memory queue is full")
                profile_n = db.execute("SELECT COUNT(*) FROM jobs WHERE profile=? AND status IN ('queued','processing')",
                                       (context.profile_id,)).fetchone()[0]
                if profile_n >= 1000:
                    raise BrokerUnavailable("profile memory queue is full")
                db.execute("INSERT INTO consents(consent_id,profile,provider,owner_generation,active,created,updated) VALUES(?,?,?,?,1,?,?)",
                    (consent_id, context.profile_id, target.provider, generation, now, now))
                db.execute("INSERT INTO jobs(id,profile,namespace,provider,owner_generation,source_context,consent,event,status,created,updated,consent_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (receipt, context.profile_id, context.namespace_id, target.provider,
                     generation, source, consent, raw_event, "queued", now, now, consent_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()
        return receipt

    def result(self, context: HostContext, receipt: str) -> dict[str, Any]:
        _text(receipt, "receipt", 128)
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                row = db.execute("SELECT status,result,error_code FROM jobs WHERE id=? AND profile=? AND namespace=?",
                    (receipt, context.profile_id, context.namespace_id)).fetchone()
            finally:
                db.close()
        if not row:
            return {"found": False}
        value = None
        if row[1]:
            try:
                value = json.loads(bytes(row[1]).decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = None
        return {"found": True, "status": row[0], "result": value, "error": row[2]}

    def claim(self, lease_seconds: int = 60) -> dict[str, Any] | None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("invalid queue lease")
        now = self.clock()
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                # An expired in-flight effect has an ambiguous outcome. Never
                # retry it automatically: upstream APIs may not offer idempotency.
                db.execute("UPDATE jobs SET status='failed',error_code='worker_lost_outcome_unknown',source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE status='processing' AND lease_until<?",
                           (now, now))
                db.execute("UPDATE consents SET active=0,updated=? WHERE consent_id IN (SELECT consent_id FROM jobs WHERE status='failed' AND error_code='worker_lost_outcome_unknown')",
                           (now,))
                while True:
                    row = db.execute("SELECT id,profile,namespace,provider,owner_generation,source_context,consent,event,attempts,consent_id FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
                    if row is None:
                        db.commit()
                        return None
                    try:
                        owner, generation = self.owner_state(str(row[1]))
                    except Exception:
                        # A prepared owner transition or unreadable ledger blocks
                        # queue processing without consuming or disclosing bytes.
                        db.rollback()
                        return None
                    if owner != row[3] or generation != row[4]:
                        db.execute("UPDATE jobs SET status='failed',error_code='owner_changed',source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE id=? AND status='queued'",
                                   (now, row[0]))
                        db.execute("UPDATE consents SET active=0,updated=? WHERE consent_id=?",
                                   (now, row[9]))
                        continue
                    if db.execute("UPDATE jobs SET status='processing',lease_until=?,updated=?,attempts=attempts+1 WHERE id=? AND status='queued'",
                                  (now + lease_seconds, now, row[0])).rowcount != 1:
                        db.rollback()
                        return None
                    db.commit()
                    return dict(zip(("id","profile_id","namespace_id","provider","owner_generation",
                        "source_context","consent","event","attempts","consent_id"),
                        (row[0],row[1],row[2],row[3],row[4],bytes(row[5]),bytes(row[6]),bytes(row[7]),row[8]+1,row[9])))
            finally:
                db.close()

    def finish(self, job: Mapping[str, Any], result: Mapping[str, Any] | None,
               error_code: str | None = None) -> None:
        if (result is None) == (error_code is None):
            raise ValueError("exactly one result or error is required")
        raw = canonical(dict(result), 16 * 1024) if result is not None else None
        status = "complete" if result is not None else "failed"
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("UPDATE jobs SET status=?,result=?,error_code=?,source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE id=? AND status='processing'",
                    (status, raw, error_code[:64] if error_code else None, self.clock(), job["id"])).rowcount != 1:
                    prior = db.execute("SELECT status,error_code FROM jobs WHERE id=?", (job["id"],)).fetchone()
                    if prior and prior[0] == "failed" and prior[1] in {
                            "owner_changed", "capture_disabled", "profile_removed"}:
                        db.commit()
                        return
                    db.rollback()
                    raise BrokerUnavailable("queue lease changed before completion")
                db.execute("UPDATE consents SET active=0,updated=? WHERE consent_id=?",
                           (self.clock(), job.get("consent_id", "")))
                db.commit()
            finally:
                db.close()

    def consent_active(self, consent_id: str) -> bool:
        """Fail closed unless a durable job and matching current owner remain active."""
        if not isinstance(consent_id, str) or not consent_id or len(consent_id) > 256:
            return False
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                row = db.execute("SELECT profile,provider,owner_generation,active FROM consents WHERE consent_id=?",
                                 (consent_id,)).fetchone()
            finally:
                db.close()
        if row is None or row[3] != 1:
            return False
        try:
            owner, generation = self.owner_state(str(row[0]))
        except Exception:
            return False
        return owner == row[1] and generation == row[2]

    def revoke_owner(self, profile_id: str, provider_id: str, owner_generation: int,
                     *, reason: str = "owner_changed") -> int:
        """Atomically revoke one owner's queued consent and erase private payload bytes."""
        if (not isinstance(profile_id, str) or not profile_id or len(profile_id) > 128
                or provider_id not in PROVIDERS or type(owner_generation) is not int
                or owner_generation < 1):
            raise ValueError("invalid memory owner revocation scope")
        code = reason if reason in {"capture_disabled", "profile_removed", "owner_changed"} else "owner_changed"
        now = self.clock()
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("UPDATE jobs SET status='failed',error_code=?,source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE profile=? AND provider=? AND owner_generation=? AND status IN ('queued','processing')",
                    (code, now, profile_id, provider_id, owner_generation)).rowcount
                db.execute("UPDATE consents SET active=0,updated=? WHERE profile=? AND provider=? AND owner_generation=? AND active=1",
                    (now, profile_id, provider_id, owner_generation))
                db.commit()
                return int(changed)
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()

    def revoke_profile(self, profile_id: str, *, reason: str = "capture_disabled") -> int:
        """Disable or remove pending captures and clear their private queue bytes."""
        if not isinstance(profile_id,str) or not profile_id or len(profile_id)>128:
            raise ValueError("invalid profile identifier")
        code = reason if reason in {"capture_disabled","profile_removed","owner_changed"} else "capture_disabled"
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                now = self.clock()
                changed = db.execute("UPDATE jobs SET status='failed',error_code=?,source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE profile=? AND status IN ('queued','processing')",
                    (code,now,profile_id)).rowcount
                db.execute("UPDATE consents SET active=0,updated=? WHERE profile=? AND active=1", (now,profile_id))
                db.commit()
                return int(changed)
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()


def _result(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE:
        raise BrokerUnavailable("memory response exceeds limit")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BrokerUnavailable("memory response is invalid JSON") from None
    if not isinstance(result, dict):
        raise BrokerUnavailable("memory response must be an object")
    return result


def _handler(target: MemoryTarget, action: str, *, ipc: ServiceIPC | None,
             queue: DurableMemoryQueue | None, owner_state: OwnerState,
             engines: Mapping[str, PrivateEngine],
             eligibility: Callable[[MemoryTarget, str, HostContext], bool] | None,
             maximum_timeout: float):
    def handle(*, context: HostContext, authorization: EffectAuthorization,
               payload: bytes, timeout: float, peer_pid: int,
               cancelled: Callable[[], bool], peer_pidfd: int | None = None) -> Mapping[str, Any]:
        try:
            if (authorization.target != "memory:" + target.provider + ":" + action
                    or authorization.capability != CAPABILITIES[action]
                    or authorization.principal_id != context.principal_id
                    or authorization.uid != context.uid
                    or authorization.profile_id != context.profile_id
                    or authorization.namespace_id != context.namespace_id
                    or authorization.purpose != context.purpose
                    or authorization.intent_id != context.intent_id
                    or authorization.trace_id != context.trace_id
                    or authorization.policy_revision != context.policy_revision
                    or authorization.sensitivity != context.sensitivity
                    or authorization.lineage_hash != context.lineage_hash
                    or authorization.source_receipts != context.source_receipts
                    or authorization.final_payload_digest != context.final_payload_digest
                    or authorization.request_digest != hashlib.sha256(payload).hexdigest()):
                raise BrokerDenied("effect grant is not bound to this exact host context, capability, target and payload")
            if not 0 < timeout <= maximum_timeout:
                raise ValueError("memory timeout is out of bounds")
            body = parse_request(payload)
            _scope(context, target, body)
            if cancelled():
                return _reply({"error":"cancelled"}, 499)
            enrolled_scope = (target.enrollment.fixed_project_account_user_scope
                              if target.enrollment is not None else {
                                  "project_id": target.namespace_id,
                                  "account_id": target.profile_id,
                                  "user_id": target.profile_id,
                              })
            if action == "enqueue":
                if queue is None:
                    raise BrokerUnavailable("durable queue is unavailable")
                return _reply({"queued":True,"receipt_id":queue.enqueue(target=target,context=context,body=body)},202)
            if action == "result":
                if queue is None:
                    raise BrokerUnavailable("durable queue is unavailable")
                return _reply(queue.result(context,_text(body.get("receipt_id"),"receipt",128)))
            if action in {"extract","embed"}:
                stage = "memory-" + ("extraction" if action == "extract" else "embedding")
                engine = engines.get(target.provider)
                if eligibility is None or not eligibility(target,stage,context):
                    raise BrokerUnavailable(stage + " is not policy eligible")
                if engine is None or engine.route_class != "private-local" or engine.private is not True:
                    raise BrokerUnavailable(stage + " private/local engine is not enrolled")
                if action == "extract":
                    record = body.get("record")
                    if not isinstance(record,dict):
                        raise ValueError("record is required")
                    if record.get("profile",context.profile_id) != context.profile_id or record.get("namespace",context.namespace_id) != context.namespace_id:
                        raise BrokerDenied("record scope differs from signed host scope")
                    if str(record.get("source","")).startswith("memory:"):
                        raise BrokerDenied("recursive memory ingestion denied")
                    facts = engine.extract(text=_text(record.get("text"),"record text",MAX_EVENT),
                        context=context,timeout=timeout,cancelled=cancelled)
                    facts = [_text(x,"fact",8192) for x in facts]
                    if not 1 <= len(facts) <= MAX_FACTS:
                        raise ValueError("extracted fact count is invalid")
                    return _reply({"facts":facts,"engine":engine.engine_id})
                facts = [_text(x,"fact",8192) for x in body.get("facts",[])]
                if not 1 <= len(facts) <= MAX_FACTS:
                    raise ValueError("facts are invalid")
                vectors = _vectors(engine.embed(facts=facts,context=context,timeout=timeout,cancelled=cancelled),len(facts))
                return _reply({"embeddings":vectors,"engine":engine.engine_id})
            if action in {"capture","delete"}:
                owner,generation = owner_state(context.profile_id)
                if owner != target.provider or generation < 1:
                    raise BrokerDenied("provider is no longer the single capture owner")
            if action == "capture":
                facts = [_text(x,"fact",8192) for x in body.get("facts",[])]
                vectors = _vectors(body.get("embeddings"),len(facts))
                if not facts:
                    raise ValueError("capture has no facts")
                if eligibility is None or not eligibility(target,"memory-capture",context):
                    raise BrokerUnavailable("provider internal extraction/embedding path is not private eligible")
                record_id=_text(body.get("record_id"),"record id",256)
                source=_text(body.get("source"),"source",512)
                if source.startswith("memory:"):
                    raise BrokerDenied("recursive memory ingestion denied")
                if target.provider=="claude-mem" and target.enrollment is not None and target.enrollment.backend_variant == "worker-observation":
                    request={"text":"\n".join(facts),"title":record_id,
                        "project":enrolled_scope["project_id"],
                        "metadata":{"hermes_record_id":record_id,
                        "hermes_lineage":context.lineage_hash,"hermes_source":source,
                        "owner_generation":generation}}
                elif target.provider=="claude-mem":
                    request={"projectId":enrolled_scope["project_id"],"kind":"manual","type":"fact",
                        "facts":facts,"metadata":{"hermes_record_id":record_id,
                        "hermes_lineage":context.lineage_hash,"hermes_source":source,
                        "owner_generation":generation}}
                elif target.provider=="agentmemory":
                    # Native remember accepts one content string and project; it
                    # does not accept arbitrary embeddings or provenance metadata.
                    # The root-only adapter maps this bounded body to the pinned
                    # REST operation. Per-profile service/data roots provide scope.
                    request={"content":"\n".join(facts),"type":"fact",
                        "project":enrolled_scope["project_id"],
                        "agentId":enrolled_scope["user_id"],
                        "concepts":["hermes-record:"+record_id,
                                    "hermes-lineage:"+context.lineage_hash,
                                    "hermes-source:"+source]}
                else:
                    request={"record_id":record_id,"source":source,"facts":facts,
                        "embeddings":vectors,"lineage":context.lineage_hash,
                        "owner_generation":generation}
            elif action == "search":
                q=_text(body.get("query"),"query",4096); limit=body.get("limit",10)
                if type(limit) is not int or not 1 <= limit <= 100: raise ValueError("invalid search limit")
                if target.provider=="openviking":
                    request={"query":q,"target_uri":"viking://~/memories","context_type":["memory"],"limit":limit,"read_content":True}
                elif target.provider=="claude-mem":
                    if target.enrollment is not None and target.enrollment.backend_variant == "worker-observation":
                        request={"query":q,"limit":min(limit,100)}
                    else:
                        request={"projectId":enrolled_scope["project_id"],"query":q,"limit":min(limit,50)}
                else:
                    request={"query":q,"project":enrolled_scope["project_id"],
                             "agentId":enrolled_scope["user_id"],"limit":min(limit,20)}
            elif action=="doctor":
                request={"profile_id":context.profile_id,"namespace_id":context.namespace_id,
                         "service_generation":target.service_generation}
            elif action=="delete":
                rid=_text(body.get("record_id"),"record id",256)
                if target.provider=="agentmemory":
                    request={"memoryId":rid}
                elif target.provider=="claude-mem":
                    request={"record_id":rid,"projectId":enrolled_scope["project_id"]}
                else:
                    raise BrokerUnavailable("OpenViking pinned API has no per-memory delete operation")
            elif action in {"export","backup","restore"}:
                if target.route_for(action) is None:
                    raise BrokerUnavailable(target.provider+" has no pinned safe "+action+" API")
                if action=="restore":
                    if not target.dedicated_store:
                        raise BrokerDenied("restore requires isolated provider storage")
                    request={"archive":body.get("archive"),"sha256":body.get("sha256"),
                             "profile_id":context.profile_id,"namespace_id":context.namespace_id}
                else:
                    request={"profile_id":context.profile_id,"namespace_id":context.namespace_id}
            else:
                raise BrokerUnavailable(target.provider+" "+action+" is unavailable in its pinned API")
            route_id=target.route_for(action)
            if route_id is None:
                raise BrokerUnavailable(target.provider+" "+action+" is unavailable in its pinned API")
            if route_id not in target.approved_route_ids:
                raise BrokerDenied("memory route is not in the protected enrollment")
            if ipc is None:
                raise BrokerUnavailable("root-owned authenticated memory service connector is unavailable")
            if action=="restore":
                import base64
                archive=body.get("archive")
                digest=body.get("sha256")
                if not isinstance(archive,str) or len(archive)>2*MAX_RESPONSE:
                    raise ValueError("restore archive exceeds its bound")
                try:
                    decoded=base64.b64decode(archive,validate=True)
                except (ValueError,base64.binascii.Error):
                    raise ValueError("restore archive is malformed") from None
                if hashlib.sha256(decoded).hexdigest()!=digest:
                    raise BrokerDenied("restore archive digest mismatch")
                try:
                    export_data=json.loads(decoded.decode("utf-8"))
                except (UnicodeDecodeError,json.JSONDecodeError):
                    raise ValueError("restore archive is not a provider export") from None
                if not isinstance(export_data,dict):
                    raise ValueError("restore archive must contain a provider export object")
                request={"exportData":export_data,"strategy":"replace"}
            session_id = context.trace_id
            if not isinstance(session_id, str) or not session_id or len(session_id) > 256:
                raise BrokerDenied("signed host context has no valid session ID")
            if cancelled():
                return _reply({"error":"cancelled"}, 499)
            raw_result=ipc.request(context=context, authorization=authorization,
                service_id=target.service_id, service_generation=target.service_generation,
                provider=target.provider, route_id=route_id, session_id=session_id,
                deadline_monotonic=time.monotonic()+timeout, payload=canonical(request),
                timeout=timeout, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cancelled=cancelled)
            response_status = getattr(raw_result, "status", 200)
            response_body = getattr(raw_result, "body", raw_result)
            if not 200 <= int(response_status) < 300:
                if int(response_status) in {401, 403, 404}:
                    raise BrokerDenied("memory service denied the enrolled operation")
                raise BrokerUnavailable("memory service returned a non-success status")
            result=_result(response_body)
            if action=="search":
                if target.provider=="openviking":
                    hits=result.get("memories",[])
                    rows=[{"id":item.get("uri"),"source":"openviking",
                           "text":item.get("abstract") or item.get("overview")}
                          for item in hits if isinstance(item,dict)]
                elif target.provider=="claude-mem":
                    hits=result.get("memories",result.get("observations",result.get("results",[])))
                    rows=[{"id":item.get("id"),"source":"claude-mem",
                           "text":item.get("content") or item.get("summary") or item.get("text")}
                          for item in hits if isinstance(item,dict)]
                else:
                    hits=result.get("results",result.get("memories",[]))
                    rows=[]
                    for item in hits:
                        if not isinstance(item,dict): continue
                        observation=item.get("observation",item)
                        if not isinstance(observation,dict): continue
                        rows.append({"id":observation.get("id") or observation.get("memoryId"),
                                     "source":"agentmemory",
                                     "text":observation.get("narrative") or observation.get("content") or observation.get("title")})
                records=[]
                for item in rows[:limit]:
                    if not isinstance(item.get("id"),str) or not isinstance(item.get("text"),str): continue
                    records.append({"id":item["id"],"profile":context.profile_id,
                                    "namespace":context.namespace_id,"source":item["source"],
                                    "text":item["text"][:8192],"provenance":[context.lineage_hash]})
                result={"records":records}
            elif action=="doctor":
                healthy=result.get("healthy") is True or result.get("ok") is True or result.get("status")=="ok"
                result={"healthy":healthy,"revision":target.source_revision,
                        "service_generation":target.service_generation}
            elif action=="backup":
                import base64
                archive=canonical(result,MAX_RESPONSE)
                result={"archive":base64.b64encode(archive).decode("ascii"),
                        "sha256":hashlib.sha256(archive).hexdigest()}
            result["profile_id"]=context.profile_id
            result["namespace_id"]=context.namespace_id
            return _reply(result)
        except BrokerDenied as exc:
            return _reply({"error":str(exc)},403)
        except (ValueError,TypeError) as exc:
            return _reply({"error":str(exc)},400)
        except BrokerUnavailable as exc:
            return _reply({"error":str(exc)},503)
        except Exception:
            return _reply({"error":"memory operation failed"},502)
    return handle


def build_memory_handlers(*, targets: Mapping[tuple[str,str,str],MemoryTarget],
        owner_state: OwnerState, queue: DurableMemoryQueue|None, ipc: ServiceIPC|None,
        engines: Mapping[str,PrivateEngine]|None=None,
        eligibility: Callable[[MemoryTarget,str,HostContext],bool]|None=None,
        maximum_timeout: float=20.0):
    """Return one fixed handler per provider/action; signed context resolves profile.

    Authority targets intentionally omit profile IDs, so the service selects the
    enrolled immutable instance only from its verified HostContext. No request
    field can select a sibling service or data root.
    """
    if not 0 < maximum_timeout <= 30: raise ValueError("timeout must be <=30 seconds")
    table = dict(targets)
    for key, target in table.items():
        if key != (target.profile_id,target.namespace_id,target.provider):
            raise ValueError("target map key differs from immutable enrollment")
    result={}
    engines = dict(engines or {})
    for provider in PROVIDERS:
        if not any(target.provider == provider for target in table.values()):
            continue
        for action in ACTIONS:
            opaque="memory:"+provider+":"+action
            binding=("memory."+action,opaque)
            def dispatch(*, context: HostContext, authorization: EffectAuthorization,
                         payload: bytes, timeout: float, peer_pid: int,
                         cancelled: Callable[[], bool], peer_pidfd: int | None = None,
                         _provider=provider, _action=action):
                target=table.get((context.profile_id,context.namespace_id,_provider))
                if target is None:
                    return _reply({"error":"no enrolled memory target for signed profile"},403)
                return _handler(target,_action,ipc=ipc,queue=queue,owner_state=owner_state,
                    engines=engines,eligibility=eligibility,maximum_timeout=maximum_timeout)(
                        context=context,authorization=authorization,payload=payload,
                        timeout=timeout,peer_pid=peer_pid,cancelled=cancelled,
                        peer_pidfd=peer_pidfd)
            result[binding]=dispatch
    return result

def build_memory_runtime(protected_targets: Mapping[tuple[str,str,str],MemoryTarget | MemoryServiceEnrollment],
        authority_service: Any, *, root_data_dir: Path = Path("/var/lib/hermes-installer/memory"),
        vault: Any = None, connector_factory: RootConnectorFactory | None = None) -> dict[str, Any]:
    """Assemble the static root runtime from protected enrollment only.

    The authority daemon passes its root-signed consent issuer. Service IPC
    and private model engines are deliberately absent until the process custodian
    enrolls the typed fixed-memory compound executor and eligible local/private
    runtimes. Raw HTTP connector factories are rejected.
    In that state handlers are still real, bounded handlers and data-plane
    operations truthfully return unavailable; no service is started or lazily
    installed here. The vault argument is reserved for the future root-only
    connector and is intentionally never read by worker-facing code.
    """
    targets: dict[tuple[str, str, str], MemoryTarget] = {}
    for key, item in protected_targets.items():
        target = MemoryTarget.from_enrollment(item) if isinstance(item, MemoryServiceEnrollment) else item
        if not isinstance(target, MemoryTarget) or key != (
                target.profile_id, target.namespace_id, target.provider):
            raise ValueError("memory runtime accepts only exact protected enrollment entries")
        targets[key] = target
    ledger = SQLiteOwnerLedger(root_data_dir / "owner-ledger")
    owner_state = ledger.get_owner_state
    consent_issuer = getattr(authority_service, "create_background_consent", None)
    effect_runner = getattr(authority_service, "perform_memory_effect", None)
    consent_ready = callable(consent_issuer) and callable(effect_runner)
    queue = None
    if consent_ready:
        queue = DurableMemoryQueue(root_data_dir / "queue", owner_state=owner_state,
                                   consent_issuer=consent_issuer)
    consent_active = queue.consent_active if queue is not None else (lambda _consent_id: False)
    def eligibility(target: MemoryTarget, stage: str, context: HostContext) -> bool:
        # Enabling this requires a fresh protected policy decision and an
        # explicitly enrolled private-local route at every operation boundary.
        return False
    service_ids = [target.service_id for target in targets.values()]
    data_roots = [target.data_root_id for target in targets.values()]
    if len(service_ids) != len(set(service_ids)) or len(data_roots) != len(set(data_roots)):
        raise ValueError("memory services and data roots must be separately isolated per profile")
    # Raw HTTP streams are not a valid SK01 memory transport. The only
    # accepted data plane is fixed-memory-compound-json-v1 with root-owned
    # job/step state and a fresh HI12 grant for each step. Until that typed
    # executor is composed, all service actions remain explicitly unavailable.
    if connector_factory is not None:
        raise ValueError("raw memory HTTP connector factories are not supported")
    ipc = None
    return {
        "targets": targets,
        "owner_ledger": ledger,
        "owner_state": owner_state,
        "queue": queue,
        "ipc": ipc,
        "engines": {},
        "eligibility": eligibility,
        "maximum_timeout": 15.0,
        "consent_active": consent_active,
        "consent_ready": consent_ready,
        "background_effect": effect_runner if callable(effect_runner) else None,
    }


class MemoryJobWorker:
    """Single durable worker; authority callback fresh-authorizes each stage."""
    def __init__(self,queue:DurableMemoryQueue,*,owner_state:OwnerState,
                 effect:BackgroundEffect,cancelled:Callable[[],bool]|None=None):
        self.queue,self.owner_state,self.effect=queue,owner_state,effect
        self.cancelled=cancelled or (lambda:False)

    def run_one(self)->bool:
        job=self.queue.claim()
        if job is None:return False
        try:
            self._owner(job)
            event=json.loads(job["event"].decode("utf-8"))
            source_wire=bytes(job["source_context"])
            from hermes_installer.authority.types import HostContext
            source=HostContext.from_wire(json.loads(source_wire.decode("utf-8")))
            if source.profile_id!=job["profile_id"] or source.namespace_id!=job["namespace_id"]:
                raise BrokerDenied("queued signed source context scope mismatch")
            text=("User: "+event["user_content"]+"\nAssistant: "+event["assistant_content"]
                  if event["event"]=="turn" else event["content"])
            record={"id":job["id"],"profile":job["profile_id"],"namespace":job["namespace_id"],
                    "source":"hermes-session:"+str(event.get("session_id",job["id"])),
                    "text":_text(text,"event",MAX_EVENT),"provenance":[source.lineage_hash]}
            extracted=self._perform(job,source_wire,"extract","memory-extraction",{"schema":1,"record":record})
            facts=[_text(x,"fact",8192) for x in extracted.get("facts",[])]
            if not 1<=len(facts)<=MAX_FACTS:raise ValueError("extraction output is invalid")
            embedded=self._perform(job,source_wire,"embed","memory-embedding",{"schema":1,"facts":facts})
            vectors=_vectors(embedded.get("embeddings"),len(facts))
            stored=self._perform(job,source_wire,"capture","memory-capture",
                {"schema":1,"record_id":job["id"],"source":record["source"],
                 "facts":facts,"embeddings":vectors,"provenance":record["provenance"],
                 "owner_generation":job["owner_generation"]})
            self._owner(job)
            self.queue.finish(job,{"capture_receipt":stored.get("receipt_id"),"fact_count":len(facts)})
        except BrokerDenied:
            self.queue.finish(job,None,"policy_revoked")
        except BrokerUnavailable:
            self.queue.finish(job,None,"backend_unavailable")
        except Exception:
            self.queue.finish(job,None,"capture_failed")
        return True

    def _owner(self,job:Mapping[str,Any])->None:
        owner,generation=self.owner_state(str(job["profile_id"]))
        if owner!=job["provider"] or generation!=job["owner_generation"] or self.cancelled():
            raise BrokerDenied("capture owner or policy changed before background effect")

    def _perform(self,job:Mapping[str,Any],source:bytes,action:str,purpose:str,
                 body:dict[str,Any])->dict[str,Any]:
        self._owner(job)
        raw=canonical(body)
        result=self.effect(source_context_wire=source,consent_wire=bytes(job["consent"]),
            provider_id=str(job["provider"]),owner_generation=int(job["owner_generation"]),
            action=action,capability=CAPABILITIES[action],payload=raw,timeout=15.0,
            cancelled=self.cancelled)
        status=getattr(result,"status",200)
        if not 200 <= int(status) < 300:
            if int(status) in {401,403,404}:
                raise BrokerDenied("background policy or target denied")
            raise BrokerUnavailable("background stage failed")
        result=getattr(result,"body",result)
        parsed=_result(result)
        if parsed.get("error"):
            if parsed.get("error")=="policy_revoked":raise BrokerDenied("background policy revoked")
            raise BrokerUnavailable("background provider stage is unavailable")
        return parsed
