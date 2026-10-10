"""Root-owned fixed-target memory effects and durable background ingestion."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol

if TYPE_CHECKING:
    from hermes_installer.authority.types import EffectAuthorization, HostContext
from hermes_installer.state import OwnedRoot, process_lock
from hermes_installer.memory.owner_ledger import SQLiteOwnerLedger, _secure_sqlite_files
from hermes_installer.memory.root_state import (
    MemoryAuthorityStateDirectory, memory_state_lock, resolve_memory_state_directory,
)
from hermes_installer.memory.enrollment import MemoryServiceEnrollment
from hermes_installer.memory.transport import MemoryServiceIPC, RootConnectorFactory
from hermes_installer.authority.memory_execution import (
    MemoryCompoundExecutor, MemoryExecutionDenied, MemoryExecutionUnavailable,
)
from hermes_installer.memory.compound import MemoryRecipeDenied, MemoryRecipeUnavailable

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
    route_ids: Mapping[str, str]
    def extract(self, *, text: str, context: HostContext, job_handle: str, timeout: float,
                cancelled: Callable[[], bool]) -> list[str]: ...
    def embed(self, *, facts: list[str], context: HostContext, job_handle: str, timeout: float,
              cancelled: Callable[[], bool]) -> list[list[float]]: ...


_MEMORY_JOB_RECORD_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class MemoryJobAuthorityRecord:
    """Root-only snapshot proving a durable job is actively leased for one attempt."""

    job_handle: str
    profile_id: str
    namespace_id: str
    provider: str
    owner_generation: int
    source_context_wire: bytes = field(repr=False)
    consent_wire: bytes = field(repr=False)
    consent_id: str
    attempt: int
    lease_until: float
    event_sha256: str
    source_receipt_handles: tuple[str, ...]
    source_closure_sha256: str
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _MEMORY_JOB_RECORD_SEAL:
            raise TypeError("memory job authority records are resolved by the root queue")
        if (not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.job_handle)
                or self.provider not in PROVIDERS or self.owner_generation < 1 or self.attempt < 1
                or not re.fullmatch(r"[0-9a-f]{64}", self.event_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", self.source_closure_sha256)
                or not self.source_receipt_handles or len(set(self.source_receipt_handles)) != len(self.source_receipt_handles)
                or not self.source_context_wire or not self.consent_wire):
            raise BrokerDenied("active memory job authority record is malformed")

    def __repr__(self) -> str:
        return "MemoryJobAuthorityRecord(<root-private>)"


def _build_private_engine_registry(
        targets: Mapping[tuple[str, str, str], MemoryTarget],
        resolver: Callable[[str, int], tuple[Any, Any]] | None,
        active_generation_digest: str) -> tuple[
            dict[tuple[str, str, str], PrivateEngine], dict[tuple[str, str, str], str]]:
    """Resolve only complete engine selections joined to exact memory rows."""
    engines: dict[tuple[str, str, str], PrivateEngine] = {}
    unavailable: dict[tuple[str, str, str], str] = {}
    if resolver is None:
        return engines, unavailable
    from hermes_installer.authority.types import AuthorityDenied
    from hermes_installer.memory.private_engine import (
        PrivateMemoryEngineUnavailable, RootPrivateMemoryEngine,
    )
    from hermes_installer.providers.private_memory import PrivateMemoryRouteDenied
    for key, target in targets.items():
        enrollment = target.enrollment
        if enrollment is None:
            raise ValueError("private engine resolution requires a strict selected memory enrollment")
        try:
            resolved = resolver(enrollment.service_enrollment_id, enrollment.memory_owner_generation)
            if not isinstance(resolved, tuple) or len(resolved) != 2:
                raise ValueError("private engine resolver must return selected routes and dispatcher")
            selected_routes, dispatcher = resolved
            if (selected_routes.profile_id != target.profile_id
                    or selected_routes.namespace_id != target.namespace_id
                    or selected_routes.memory_enrollment_id != enrollment.service_enrollment_id
                    or selected_routes.memory_provider != target.provider
                    or selected_routes.memory_owner_generation != enrollment.memory_owner_generation
                    or selected_routes.service_generation_digest != active_generation_digest
                    or selected_routes.extract_route_id != enrollment.private_extraction_embedding_routes.get("extract")
                    or selected_routes.embed_route_id != enrollment.private_extraction_embedding_routes.get("embed")):
                raise ValueError("selected private inference routes differ from protected memory enrollment")
            engines[key] = RootPrivateMemoryEngine.from_selected_routes(selected_routes, dispatcher)
        except (AuthorityDenied, PrivateMemoryEngineUnavailable, PrivateMemoryRouteDenied) as exc:
            # Absent selection/consent/deployment remains unavailable. Other
            # malformed protected joins are surfaced as startup errors above.
            unavailable[key] = str(exc)
    return engines, unavailable


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

    def __init__(self, root: Path | MemoryAuthorityStateDirectory, *, owner_state: OwnerState,
                 consent_issuer: BackgroundConsentIssuer,
                 clock: Callable[[], float] = time.time):
        self.owned = root if isinstance(root, MemoryAuthorityStateDirectory) else OwnedRoot(root)
        self.profile_scope = self.owned.profile_id if isinstance(self.owned, MemoryAuthorityStateDirectory) else None
        self.owned.ensure()
        self.path = self.owned.path("memory-queue.sqlite3")
        self.owner_state, self.consent_issuer, self.clock = owner_state, consent_issuer, clock
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA secure_delete=ON")
        _secure_sqlite_files(self.path)
        return db

    def enqueue(self, *, target: MemoryTarget, context: HostContext,
                body: Mapping[str, Any]) -> str:
        _scope(context, target, body)
        if self.profile_scope is not None and context.profile_id != self.profile_scope:
            raise BrokerDenied("durable memory queue belongs to another profile")
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
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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

    def enqueue_completed_turn(self, *, target: MemoryTarget, context: HostContext,
                               completed_turn: Any, transcript: bytes,
                               consent: Any) -> str:
        """Persist only a root-observed completed turn with its signed consent.

        This method is for the attached root ``RootMemoryCaptureCoordinator``;
        the ordinary memory RPC schema intentionally has no transcript field.
        """
        from hermes_installer.authority.native_turn_observation import RootCompletedNativeTurn
        from hermes_installer.authority.service import BackgroundConsent
        from hermes_installer.authority.types import HostContext, Sensitivity
        if (type(completed_turn) is not RootCompletedNativeTurn
                or not isinstance(context, HostContext)
                or type(consent) is not BackgroundConsent
                or not isinstance(transcript, bytes)
                or not 1 <= len(transcript) <= MAX_EVENT):
            raise BrokerDenied("root completed turn, signed context, consent, and bounded transcript are required")
        try:
            text = transcript.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            raise BrokerDenied("completed turn transcript is not UTF-8") from None
        if ("\x00" in text or hashlib.sha256(transcript).hexdigest() != completed_turn.transcript_sha256
                or len(transcript) != completed_turn.transcript_size_bytes):
            raise BrokerDenied("completed turn bytes differ from the root transcript receipt")
        if context.profile_id != completed_turn.profile_id:
            raise BrokerDenied("completed turn and signed memory context profile differ")
        if (context.profile_id != target.profile_id or context.namespace_id != target.namespace_id
                or target.enrollment is None
                or context.purpose != "memory-capture" or context.operation != "memory.capture"
                or context.final_payload_digest != completed_turn.transcript_sha256
                or context.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL}
                or not context.source_receipts):
            raise BrokerDenied("memory capture context is not private, source-bound, and digest-bound")
        required_receipts = {
            completed_turn.input_receipt_handle,
            *completed_turn.request_receipt_handles,
            *completed_turn.response_receipt_handles,
            *completed_turn.tool_result_receipt_handles,
            *completed_turn.delegation_receipt_handles,
        }
        source_ids = {receipt.receipt_id for receipt in context.source_receipts}
        if not required_receipts.issubset(source_ids):
            raise BrokerDenied("signed memory context does not contain the full completed-turn receipt closure")
        claims = consent.claims
        owner, generation = self.owner_state(context.profile_id)
        if (owner != target.provider or generation != target.enrollment.memory_owner_generation
                or claims.get("kind") != "memory-background-consent-v1"
                or claims.get("provider_id") != target.provider
                or claims.get("owner_generation") != generation
                or claims.get("principal_id") != context.principal_id
                or claims.get("profile_id") != context.profile_id
                or claims.get("namespace_id") != context.namespace_id
                or claims.get("uid") != context.uid
                or claims.get("policy_revision") != context.policy_revision
                or not isinstance(claims.get("issued_at_unix"), (int, float))
                or isinstance(claims.get("issued_at_unix"), bool)
                or not isinstance(claims.get("expires_at_unix"), (int, float))
                or isinstance(claims.get("expires_at_unix"), bool)
                or claims.get("issued_at_unix", float("inf")) > self.clock()
                or claims.get("expires_at_unix", 0) <= self.clock()
                or "capture" not in claims.get("allowed_actions", ())):
            raise BrokerDenied("background consent differs from the current selected profile owner")
        _scope(context, target, {})
        event = {"event": "completed-turn", "turn_id": completed_turn.turn_handle,
                 "transcript": text, "transcript_sha256": completed_turn.transcript_sha256}
        raw_event = canonical(event, MAX_EVENT)
        source = canonical(context.to_wire(), 16 * 1024)
        consent_id, consent_bytes = _consent_wire(consent)
        receipt = secrets.token_urlsafe(24)
        now = self.clock()
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                current_owner, current_generation = self.owner_state(context.profile_id)
                if (current_owner != owner or current_generation != generation
                        or current_owner != target.provider):
                    raise BrokerDenied("memory owner changed before completed turn persistence")
                n = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','processing')").fetchone()[0]
                profile_n = db.execute(
                    "SELECT COUNT(*) FROM jobs WHERE profile=? AND status IN ('queued','processing')",
                    (context.profile_id,)).fetchone()[0]
                if n >= 10000 or profile_n >= 1000:
                    raise BrokerUnavailable("durable memory queue is full")
                db.execute("INSERT INTO consents(consent_id,profile,provider,owner_generation,active,created,updated) VALUES(?,?,?,?,1,?,?)",
                    (consent_id, context.profile_id, target.provider, generation, now, now))
                db.execute("INSERT INTO jobs(id,profile,namespace,provider,owner_generation,source_context,consent,event,status,created,updated,consent_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (receipt, context.profile_id, context.namespace_id, target.provider,
                     generation, source, consent_bytes, raw_event, "queued", now, now, consent_id))
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()
        return receipt

    def result(self, context: HostContext, receipt: str) -> dict[str, Any]:
        _text(receipt, "receipt", 128)
        if self.profile_scope is not None and context.profile_id != self.profile_scope:
            raise BrokerDenied("durable memory queue belongs to another profile")
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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

    def resolve_active_job(self, job_handle: str, *, now: float | None = None) -> MemoryJobAuthorityRecord:
        """Resolve a currently processing job without returning its transcript bytes."""
        if (not isinstance(job_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", job_handle)):
            raise BrokerDenied("root durable memory job handle is malformed")
        current_time = self.clock() if now is None else now
        if isinstance(current_time, bool) or not isinstance(current_time, (int, float)) or not math.isfinite(current_time):
            raise BrokerDenied("memory job clock is invalid")
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                row = db.execute(
                    "SELECT profile,namespace,provider,owner_generation,source_context,consent,event,status,attempts,lease_until,consent_id "
                    "FROM jobs WHERE id=?", (job_handle,)).fetchone()
                if row is None:
                    raise BrokerDenied("memory job is not retained")
                (profile, namespace, provider, owner_generation, source_wire,
                 consent_wire, event_wire, status, attempt, lease_until, consent_id) = row
                if (status != "processing" or not isinstance(lease_until, (int, float))
                        or lease_until <= current_time or type(attempt) is not int or attempt < 1
                        or not isinstance(consent_id, str) or not consent_id):
                    raise BrokerDenied("memory job is not in a live processing attempt")
                consent_row = db.execute(
                    "SELECT profile,provider,owner_generation,active FROM consents WHERE consent_id=?",
                    (consent_id,)).fetchone()
                if (consent_row is None or consent_row[3] != 1
                        or consent_row[:3] != (profile, provider, owner_generation)):
                    raise BrokerDenied("memory job consent is not active for its owner")
                owner, generation = self.owner_state(str(profile))
                if owner != provider or generation != owner_generation:
                    raise BrokerDenied("memory job owner or generation is stale")
                source_bytes, consent_bytes, event_bytes = bytes(source_wire), bytes(consent_wire), bytes(event_wire)
            finally:
                db.close()
        from hermes_installer.authority.types import HostContext
        try:
            source = HostContext.from_wire(json.loads(source_bytes.decode("utf-8")))
            consent = json.loads(consent_bytes.decode("utf-8"))
        except Exception:
            raise BrokerDenied("memory job source or consent wire is malformed") from None
        receipt_handles = tuple(receipt.receipt_id for receipt in source.source_receipts)
        if (source.profile_id != profile or source.namespace_id != namespace
                or not receipt_handles or not isinstance(consent, dict)
                or consent.get("consent_id") != consent_id):
            raise BrokerDenied("memory job source closure or consent differs from its durable row")
        return MemoryJobAuthorityRecord(
            job_handle=job_handle, profile_id=profile, namespace_id=namespace,
            provider=provider, owner_generation=owner_generation,
            source_context_wire=source_bytes, consent_wire=consent_bytes,
            consent_id=consent_id, attempt=attempt, lease_until=float(lease_until),
            event_sha256=hashlib.sha256(event_bytes).hexdigest(),
            source_receipt_handles=receipt_handles, source_closure_sha256=source.lineage_hash,
            _seal=_MEMORY_JOB_RECORD_SEAL,
        )

    def is_current(self, record: MemoryJobAuthorityRecord, *, now: float | None = None) -> bool:
        """Recheck exact attempt, lease, consent and owner immediately before an effect."""
        if type(record) is not MemoryJobAuthorityRecord or record._seal is not _MEMORY_JOB_RECORD_SEAL:
            return False
        current_time = self.clock() if now is None else now
        if current_time >= record.lease_until:
            return False
        try:
            resolved = self.resolve_active_job(record.job_handle, now=current_time)
            owner, generation = self.owner_state(record.profile_id)
        except Exception:
            return False
        return (owner == record.provider and generation == record.owner_generation
                and resolved.profile_id == record.profile_id
                and resolved.namespace_id == record.namespace_id
                and resolved.provider == record.provider
                and resolved.owner_generation == record.owner_generation
                and resolved.consent_id == record.consent_id
                and resolved.attempt == record.attempt
                and resolved.lease_until == record.lease_until
                and resolved.event_sha256 == record.event_sha256
                and resolved.source_context_wire == record.source_context_wire
                and resolved.consent_wire == record.consent_wire
                and resolved.source_receipt_handles == record.source_receipt_handles
                and resolved.source_closure_sha256 == record.source_closure_sha256)

    def claim(self, lease_seconds: int = 60) -> dict[str, Any] | None:
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("invalid queue lease")
        now = self.clock()
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
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
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                changed = db.execute("UPDATE jobs SET status='failed',error_code=?,source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE profile=? AND provider=? AND owner_generation=? AND status IN ('queued','processing')",
                    (code, now, profile_id, provider_id, owner_generation)).rowcount
                db.execute("UPDATE consents SET active=0,updated=? WHERE profile=? AND provider=? AND owner_generation=? AND active=1",
                    (now, profile_id, provider_id, owner_generation))
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='compound_jobs'").fetchone():
                    db.execute("UPDATE compound_jobs SET state='revoked',source_context=X'',consent=NULL,"
                        "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL "
                        ",effect_consumed=0,compound_payload_sha256=NULL,service_request_sha256=NULL "
                        "WHERE profile=? AND provider=? AND owner_generation=? AND state='active'",
                        (profile_id, provider_id, owner_generation))
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
        with memory_state_lock(self.owned, self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                now = self.clock()
                changed = db.execute("UPDATE jobs SET status='failed',error_code=?,source_context=X'',consent=X'',event=X'',lease_until=NULL,updated=? WHERE profile=? AND status IN ('queued','processing')",
                    (code,now,profile_id)).rowcount
                db.execute("UPDATE consents SET active=0,updated=? WHERE profile=? AND active=1", (now,profile_id))
                if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='compound_jobs'").fetchone():
                    db.execute("UPDATE compound_jobs SET state='revoked',source_context=X'',consent=NULL,"
                        "request_body=X'7b7d',captures=X'7b7d',inflight_step=NULL,inflight_sequence=NULL "
                        ",effect_consumed=0,compound_payload_sha256=NULL,service_request_sha256=NULL "
                        "WHERE profile=? AND state='active'", (profile_id,))
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
             engines: Mapping[tuple[str, str, str], PrivateEngine],
             eligibility: Callable[[MemoryTarget, str, HostContext], bool] | None,
             maximum_timeout: float,
             compound_executor: MemoryCompoundExecutor | None = None):
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
            if action not in {"enqueue", "result", "extract", "embed"}:
                route_id = target.route_for(action)
                if route_id is None:
                    raise BrokerUnavailable(target.provider+" "+action+" is unavailable in its pinned API")
                if route_id not in target.approved_route_ids:
                    raise BrokerDenied("memory route is not in the protected enrollment")
            if action not in {"enqueue", "result", "extract", "embed"} and ipc is not None:
                raise BrokerUnavailable(
                    "raw HTTP memory transport is incompatible with fixed compound protocol")
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
                expected_body_fields = ({"schema", "job_handle", "record"} if action == "extract"
                                        else {"schema", "job_handle", "facts"})
                if set(body) != expected_body_fields:
                    raise BrokerDenied("private memory stage payload does not match its fixed schema")
                job_handle = body.get("job_handle")
                if not isinstance(job_handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", job_handle):
                    raise BrokerDenied("root durable memory job handle is required")
                stage = "memory-" + ("extraction" if action == "extract" else "embedding")
                # A local engine is enrolled per concrete profile target. A
                # provider-name key would let one profile accidentally reuse
                # another profile's engine, model cache, or authorization.
                engine = engines.get((target.profile_id, target.namespace_id, target.provider))
                if eligibility is None or not eligibility(target,stage,context):
                    raise BrokerUnavailable(stage + " is not policy eligible")
                if engine is None or engine.route_class != "private-local" or engine.private is not True:
                    raise BrokerUnavailable(stage + " private/local engine is not enrolled")
                enrollment = target.enrollment
                route_ids = getattr(engine, "route_ids", None)
                expected_route = (enrollment.private_extraction_embedding_routes.get(
                    "extract" if action == "extract" else "embed") if enrollment is not None else None)
                if (not isinstance(route_ids, Mapping)
                        or route_ids.get("extract" if action == "extract" else "embed") != expected_route
                        or not isinstance(expected_route, str) or not expected_route):
                    raise BrokerDenied("private engine route differs from the protected profile enrollment")
                if action == "extract":
                    record = body.get("record")
                    if (not isinstance(record,dict)
                            or set(record) != {"id", "profile", "namespace", "source", "text", "provenance"}):
                        raise ValueError("record does not match the fixed completed-memory job schema")
                    if record.get("profile",context.profile_id) != context.profile_id or record.get("namespace",context.namespace_id) != context.namespace_id:
                        raise BrokerDenied("record scope differs from signed host scope")
                    if str(record.get("source","")).startswith("memory:"):
                        raise BrokerDenied("recursive memory ingestion denied")
                    facts = engine.extract(text=_text(record.get("text"),"record text",MAX_EVENT),
                        job_handle=job_handle,
                        context=context,timeout=timeout,cancelled=cancelled)
                    facts = [_text(x,"fact",8192) for x in facts]
                    if not 1 <= len(facts) <= MAX_FACTS:
                        raise ValueError("extracted fact count is invalid")
                    return _reply({"facts":facts,"engine":engine.engine_id})
                facts = [_text(x,"fact",8192) for x in body.get("facts",[])]
                if not 1 <= len(facts) <= MAX_FACTS:
                    raise ValueError("facts are invalid")
                vectors = _vectors(engine.embed(facts=facts,job_handle=job_handle,
                    context=context,timeout=timeout,cancelled=cancelled),len(facts))
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
            if compound_executor is not None and action in {"doctor", "search", "capture"}:
                enrollment = target.enrollment
                recipe = enrollment.fixed_route_map.get(route_id) if enrollment is not None else None
                if recipe is None:
                    raise BrokerUnavailable("selected memory action has no complete protected compound recipe")
                if action == "doctor":
                    compound_body = {}
                elif action == "search":
                    compound_body = {"query": _text(body.get("query"), "query", 16384),
                                     "limit": limit}
                elif target.provider == "agentmemory":
                    compound_body = {"content": _text(request.get("content"), "content", 65536)}
                else:
                    raise BrokerUnavailable("selected memory capture lacks a root-captured event recipe")
                source_context_wire = context.to_wire()
                executed = compound_executor.execute(
                    enrollment=enrollment, recipe=recipe, body=compound_body,
                    source_context_wire=source_context_wire,
                    parent_authorization=authorization,
                    parent_request_payload=payload,
                    cancelled=cancelled)
                result = dict(executed)
                result["profile_id"] = context.profile_id
                result["namespace_id"] = context.namespace_id
                if action == "search":
                    semantic_result = result.get("result")
                    records = semantic_result.get("records") if isinstance(semantic_result, Mapping) else None
                    if not isinstance(records, list) or len(records) > limit:
                        raise BrokerUnavailable("memory search returned no bounded validated record set")
                    scoped_records = []
                    for record in records:
                        if (not isinstance(record, Mapping) or set(record) != {"id", "source", "text"}
                                or record.get("source") != target.provider
                                or not isinstance(record.get("id"), str)
                                or not isinstance(record.get("text"), str)):
                            raise BrokerUnavailable("memory search record differs from its validated provider schema")
                        # Scope labels are derived by the root broker after provider
                        # response validation; upstream/caller JSON cannot choose them.
                        scoped_records.append({**record, "profile": context.profile_id,
                                               "namespace": context.namespace_id})
                    result["records"] = scoped_records
                if action == "doctor":
                    probe = result.get("result")
                    if not isinstance(probe, Mapping):
                        raise BrokerUnavailable("memory doctor returned no validated probe outcome")
                    if probe.get("service_ready") is True:
                        status = "ready"
                    elif probe.get("service_live") is True:
                        status = "live_unqualified"
                    else:
                        status = "not_ready"
                    result["service_status"] = status
                    result["functional_memory_verified"] = False
                    result["revision"] = target.source_revision
                    result["service_generation"] = target.service_generation
                return _reply(result)
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
        except MemoryExecutionDenied as exc:
            return _reply({"error":str(exc)},403)
        except MemoryExecutionUnavailable as exc:
            return _reply({"error":str(exc)},503)
        except MemoryRecipeDenied as exc:
            return _reply({"error":str(exc)},403)
        except MemoryRecipeUnavailable as exc:
            return _reply({"error":str(exc)},503)
        except (ValueError,TypeError) as exc:
            return _reply({"error":str(exc)},400)
        except BrokerUnavailable as exc:
            return _reply({"error":str(exc)},503)
        except Exception:
            return _reply({"error":"memory operation failed"},502)
    return handle


def build_memory_handlers(*, targets: Mapping[tuple[str,str,str],MemoryTarget],
        owner_state: OwnerState, queue: DurableMemoryQueue|None, ipc: ServiceIPC|None,
        engines: Mapping[tuple[str,str,str],PrivateEngine]|None=None,
        eligibility: Callable[[MemoryTarget,str,HostContext],bool]|None=None,
        compound_executor: MemoryCompoundExecutor | None = None,
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
    if any(key not in table for key in engines):
        raise ValueError("private memory engines must be keyed by an exact enrolled profile target")
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
                    engines=engines,eligibility=eligibility,maximum_timeout=maximum_timeout,
                    compound_executor=compound_executor)(
                        context=context,authorization=authorization,payload=payload,
                        timeout=timeout,peer_pid=peer_pid,cancelled=cancelled,
                        peer_pidfd=peer_pidfd)
            result[binding]=dispatch
    return result

def build_memory_runtime(protected_targets: Mapping[tuple[str,str,str],MemoryTarget | MemoryServiceEnrollment],
        authority_service: Any, *, root_journal_resolver: Callable[..., Any] | None = None,
        expected_active_generation_digest: str | None = None,
        vault: Any = None, connector_factory: RootConnectorFactory | None = None,
        service_catalog: Any = None, process_manager: Any = None,
        enrollment_resolver: Callable[[str, str], MemoryServiceEnrollment] | None = None,
        private_engine_resolver: Callable[[str, int], tuple[Any, Any]] | None = None) -> dict[str, Any]:
    """Assemble the root memory runtime from protected enrollment only.

    Fixed compound execution is composed only with the current root service
    catalog, managed process namespace, and credential vault. A private engine
    is constructed only from a separately injected root route resolver that
    returns a current typed selection plus root dispatcher; absent that
    resolver, extraction/embedding stay unavailable.
    """
    targets: dict[tuple[str, str, str], MemoryTarget] = {}
    for key, item in protected_targets.items():
        target = MemoryTarget.from_enrollment(item) if isinstance(item, MemoryServiceEnrollment) else item
        if not isinstance(target, MemoryTarget) or key != (
                target.profile_id, target.namespace_id, target.provider):
            raise ValueError("memory runtime accepts only exact protected enrollment entries")
        targets[key] = target
    if connector_factory is not None:
        raise ValueError("raw memory HTTP connector factories are not supported")
    if not callable(root_journal_resolver) or not expected_active_generation_digest:
        # A service enrollment is not authority to choose its own state path.
        # Until the protected root-journal catalog is supplied, expose no
        # mutable memory runtime (handlers report an unavailable state root).
        def owner_state(_profile: str) -> tuple[str | None, int]:
            raise BrokerUnavailable("protected memory authority state-root catalog is unavailable")
        return {
            "targets": targets, "owner_ledger": None, "owner_state": owner_state,
            "queue": None, "ipc": None, "compound_ledger": None,
            "job_resolver": None,
            "compound_executor": None, "engines": {},
            "private_engine_unavailable": {},
            "eligibility": lambda *_: False, "maximum_timeout": 15.0,
            "consent_active": lambda _consent_id: False,
            "consent_ready": False, "background_effect": None,
            "capture_coordinator": None,
            "capture_unavailable_reason": "protected memory state-root catalog is unavailable",
            "state_directories": {}, "state_root_ready": False,
        }
    from hermes_installer.memory.root_state import resolve_memory_state_directory
    enrollments: dict[str, MemoryServiceEnrollment] = {}
    for target in targets.values():
        if target.enrollment is None:
            raise ValueError("root memory runtime requires strict protected service enrollments")
        prior = enrollments.get(target.profile_id)
        if prior is not None and (prior.authority_state_root_id != target.enrollment.authority_state_root_id
                                  or prior.data_root_id == target.enrollment.authority_state_root_id):
            raise ValueError("profile memory enrollments disagree on protected authority state root")
        enrollments[target.profile_id] = target.enrollment
    state_directories = {
        profile: resolve_memory_state_directory(
            enrollment, root_journal_resolver,
            expected_active_generation_digest=expected_active_generation_digest,
            expected_uid=0)
        for profile, enrollment in enrollments.items()
    }
    owner_ledgers = {profile: SQLiteOwnerLedger(directory)
                     for profile, directory in state_directories.items()}

    def owner_state(profile: str) -> tuple[str | None, int]:
        ledger = owner_ledgers.get(profile)
        if ledger is None:
            raise BrokerUnavailable("signed profile has no root memory authority state")
        return ledger.get_owner_state(profile)

    class ProfiledOwnerLedger:
        def get_owner(self, profile: str) -> str | None:
            ledger = owner_ledgers.get(profile)
            if ledger is None: raise BrokerUnavailable("profile has no root memory authority state")
            return ledger.get_owner(profile)

        def get_owner_state(self, profile: str) -> tuple[str | None, int]:
            return owner_state(profile)

        def set_owner(self, profile: str, provider: str | None) -> None:
            ledger = owner_ledgers.get(profile)
            if ledger is None:
                raise BrokerUnavailable("profile has no root memory authority state")
            ledger.set_owner(profile, provider)

        def begin_transition(self, profile: str, old: str | None, new: str | None) -> str:
            ledger = owner_ledgers.get(profile)
            if ledger is None: raise BrokerUnavailable("profile has no root memory authority state")
            return ledger.begin_transition(profile, old, new)

        def commit_transition(self, profile: str, transition_id: str, name: str | None) -> None:
            ledger = owner_ledgers.get(profile)
            if ledger is None: raise BrokerUnavailable("profile has no root memory authority state")
            ledger.commit_transition(profile, transition_id, name)

        def abort_transition(self, profile: str, transition_id: str, *, recovered: bool = True) -> None:
            ledger = owner_ledgers.get(profile)
            if ledger is None: raise BrokerUnavailable("profile has no root memory authority state")
            ledger.abort_transition(profile, transition_id, recovered=recovered)

    ledger = ProfiledOwnerLedger()
    consent_issuer = getattr(authority_service, "create_background_consent", None)
    effect_runner = getattr(authority_service, "perform_memory_effect", None)
    consent_ready = callable(consent_issuer) and callable(effect_runner)
    queue = None
    if consent_ready:
        class ProfiledQueue:
            def __init__(self):
                self.queues = {profile: DurableMemoryQueue(
                    state_directories[profile], owner_state=owner_state,
                    consent_issuer=consent_issuer)
                    for profile in state_directories}
            def enqueue(self, *, target: MemoryTarget, context: HostContext,
                        body: Mapping[str, Any]) -> str:
                child = self.queues.get(target.profile_id)
                if child is None: raise BrokerUnavailable("profile queue is unavailable")
                return child.enqueue(target=target, context=context, body=body)
            def enqueue_completed_turn(self, *, target: MemoryTarget, context: HostContext,
                                       completed_turn: Any, transcript: bytes,
                                       consent: Any) -> str:
                child = self.queues.get(target.profile_id)
                if child is None: raise BrokerUnavailable("profile queue is unavailable")
                return child.enqueue_completed_turn(
                    target=target, context=context, completed_turn=completed_turn,
                    transcript=transcript, consent=consent)
            def result(self, context: HostContext, receipt: str) -> Mapping[str, Any]:
                child = self.queues.get(context.profile_id)
                if child is None: raise BrokerUnavailable("profile queue is unavailable")
                return child.result(context, receipt)
            def consent_active(self, consent_id: str) -> bool:
                return any(child.consent_active(consent_id) for child in self.queues.values())
            def resolve_active_job(self, job_handle: str, *, now: float | None = None) -> MemoryJobAuthorityRecord:
                # Job IDs are random, but still reject ambiguous matches if
                # storage corruption or an impossible collision is observed.
                matches = []
                for child in self.queues.values():
                    try:
                        matches.append(child.resolve_active_job(job_handle, now=now))
                    except BrokerDenied:
                        continue
                if len(matches) != 1:
                    raise BrokerDenied("root memory job is absent or ambiguous across profile queues")
                return matches[0]
            def is_current(self, record: MemoryJobAuthorityRecord, *, now: float | None = None) -> bool:
                if type(record) is not MemoryJobAuthorityRecord:
                    return False
                child = self.queues.get(record.profile_id)
                return child is not None and child.is_current(record, now=now)
            def revoke_owner(self, profile: str, provider: str, generation: int,
                             *, reason: str = "owner_changed") -> int:
                child = self.queues.get(profile)
                return 0 if child is None else child.revoke_owner(
                    profile, provider, generation, reason=reason)
            def revoke_profile(self, profile: str, *, reason: str = "capture_disabled") -> int:
                child = self.queues.get(profile)
                return 0 if child is None else child.revoke_profile(profile, reason=reason)
        queue = ProfiledQueue()
    consent_active = queue.consent_active if queue is not None else (lambda _consent_id: False)
    private_engines, private_engine_unavailable = _build_private_engine_registry(
        targets, private_engine_resolver, expected_active_generation_digest,
    )

    def eligibility(target: MemoryTarget, stage: str, context: HostContext) -> bool:
        action = {"memory-extraction": "extract", "memory-embedding": "embed"}.get(stage)
        key = (target.profile_id, target.namespace_id, target.provider)
        engine = private_engines.get(key)
        if action is None or engine is None or type(context) is not HostContext:
            return False
        expected_purpose = "memory-extraction" if action == "extract" else "memory-embedding"
        expected_operation = "memory.extract" if action == "extract" else "memory.embed"
        if (context.purpose != expected_purpose or context.operation != expected_operation
                or context.profile_id != target.profile_id or context.namespace_id != target.namespace_id):
            return False
        # This precheck is only for exact selected route/scope. The root
        # provider dispatcher independently rechecks current consent, source
        # closure, deployment, budget, and fresh effect authority per attempt.
        return (engine.route_class == "private-local" and engine.private is True
                and engine.route_ids.get(action)
                == target.enrollment.private_extraction_embedding_routes.get(action))
    service_ids = [target.service_id for target in targets.values()]
    data_roots = [target.data_root_id for target in targets.values()]
    if len(service_ids) != len(set(service_ids)) or len(data_roots) != len(set(data_roots)):
        raise ValueError("memory services and data roots must be separately isolated per profile")
    # Raw HTTP streams are not a valid SK01 memory transport. The only
    # accepted data plane is fixed-memory-compound-json-v1 with root-owned
    # job/step state and a fresh HI12 grant for each step. Until that typed
    # executor is composed, all service actions remain explicitly unavailable.
    ipc = None
    from hermes_installer.authority.memory_execution import MemoryCompoundLedger, MemoryCompoundExecutor
    step_effect = getattr(authority_service, "perform_memory_connector_step", None)
    compound_ledgers = {profile: MemoryCompoundLedger(directory)
                        for profile, directory in state_directories.items()}
    step_authority = None
    if (service_catalog is not None and process_manager is not None and vault is not None):
        from hermes_installer.authority.memory_execution import RootMemoryStepEffectAuthority
        if enrollment_resolver is None:
            enrollment_by_key = {
                (enrollment.profile_id, enrollment.service_generation): enrollment
                for enrollment in enrollments.values()
            }
            enrollment_resolver = lambda profile, generation: enrollment_by_key[(profile, generation)]
        step_authority = RootMemoryStepEffectAuthority(
            service=authority_service, enrollment_resolver=enrollment_resolver,
            ledger_resolver=lambda profile: compound_ledgers[profile],
            service_catalog=service_catalog,
            process_manager=process_manager, vault=vault, owner_state=owner_state,
            consent_active=consent_active, ledger_profiles=tuple(compound_ledgers))
        registered = step_authority.register()
        if registered:
            # This is an in-process root callback, never a worker RPC verb.
            # It is called only by the already registered memory effect handler.
            attach = getattr(authority_service, "attach_memory_step_effect_authority", None)
            if not callable(attach):
                raise MemoryExecutionUnavailable("root AuthorityService memory effect attachment is unavailable")
            attach(step_authority)
    class ProfiledCompoundExecutor:
        def execute(self, *, enrollment: MemoryServiceEnrollment, **kwargs: Any) -> Mapping[str, Any]:
            ledger_for_profile = compound_ledgers.get(enrollment.profile_id)
            if ledger_for_profile is None:
                raise MemoryExecutionUnavailable("profile memory compound ledger is unavailable")
            return MemoryCompoundExecutor(
                ledger_for_profile,
                getattr(authority_service, "perform_memory_connector_step", None)
                if step_authority is not None else None
            ).execute(enrollment=enrollment, **kwargs)
    compound_ledger = compound_ledgers
    compound_executor = ProfiledCompoundExecutor()
    capture_coordinator = None
    capture_unavailable_reason = None
    turn_registry = getattr(authority_service, "native_turn_observation_registry", None)
    if queue is None:
        capture_unavailable_reason = "durable memory queue or background consent authority is unavailable"
    elif turn_registry is None:
        capture_unavailable_reason = "root native completed-turn observer is unavailable"
    else:
        from hermes_installer.memory.capture import (
            MemoryCaptureUnavailable, attach_root_memory_capture_coordinator,
        )
        try:
            capture_coordinator = attach_root_memory_capture_coordinator(
                service=authority_service, targets=targets, queue=queue,
                owner_state=owner_state,
                expected_active_generation_digest=expected_active_generation_digest,
            )
        except MemoryCaptureUnavailable as exc:
            capture_unavailable_reason = str(exc)
    return {
        "targets": targets,
        "owner_ledger": ledger,
        "owner_state": owner_state,
        "queue": queue,
        "ipc": ipc,
        "compound_ledger": compound_ledger,
        "compound_executor": compound_executor,
        "engines": private_engines,
        "private_engine_unavailable": private_engine_unavailable,
        "eligibility": eligibility,
        "maximum_timeout": 15.0,
        "consent_active": consent_active,
        "job_resolver": queue,
        "consent_ready": consent_ready,
        "background_effect": effect_runner if callable(effect_runner) else None,
        "capture_coordinator": capture_coordinator,
        "capture_unavailable_reason": capture_unavailable_reason,
        "step_authority": step_authority,
        "state_directories": state_directories, "state_root_ready": True,
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
            if event["event"] == "completed-turn":
                text = _text(event["transcript"], "completed turn", MAX_EVENT)
                if hashlib.sha256(text.encode("utf-8")).hexdigest() != event.get("transcript_sha256"):
                    raise BrokerDenied("queued completed transcript digest changed")
            elif event["event"] == "turn":
                text = "User: "+event["user_content"]+"\nAssistant: "+event["assistant_content"]
            else:
                text = event["content"]
            record={"id":job["id"],"profile":job["profile_id"],"namespace":job["namespace_id"],
                    "source":"hermes-session:"+str(event.get("session_id",job["id"])),
                    "text":_text(text,"event",MAX_EVENT),"provenance":[source.lineage_hash]}
            extracted=self._perform(job,source_wire,"extract","memory-extraction",
                {"schema":1,"job_handle":job["id"],"record":record})
            facts=[_text(x,"fact",8192) for x in extracted.get("facts",[])]
            if not 1<=len(facts)<=MAX_FACTS:raise ValueError("extraction output is invalid")
            embedded=self._perform(job,source_wire,"embed","memory-embedding",
                {"schema":1,"job_handle":job["id"],"facts":facts})
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
