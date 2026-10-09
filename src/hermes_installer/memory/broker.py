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
from typing import Any, Callable, Mapping, Protocol

from hermes_installer.authority.types import EffectAuthorization, HostContext
from hermes_installer.state import OwnedRoot, process_lock

MAX_REQUEST = 256 * 1024
MAX_RESPONSE = 1024 * 1024
MAX_EVENT = 64 * 1024
MAX_FACTS = 64
PROVIDERS = frozenset({"openviking", "claude-mem", "agentmemory"})
ACTIONS = frozenset({"doctor", "extract", "embed", "capture", "search", "export",
                     "delete", "backup", "restore", "enqueue", "result"})
CAPABILITIES = {
    "doctor": "memory-retrieval", "search": "memory-retrieval",
    "extract": "memory-extraction", "embed": "memory-embedding",
    "capture": "memory-capture", "enqueue": "memory-capture",
    "export": "memory-export", "backup": "memory-backup",
    "restore": "memory-restore", "delete": "memory-delete", "result": "memory-retrieval",
}
ROUTES = {
    "openviking": {
        "doctor": "GET /ready",
        "search": "POST /api/v1/search/find",
        "capture": "POST /api/v1/sessions;POST /api/v1/sessions/{id}/messages/batch;POST /api/v1/sessions/{id}/commit",
        "delete": "DELETE /api/v1/sessions/{id}",
    },
    "claude-mem": {
        "doctor": "GET /healthz",
        "search": "POST /v1/search",
        "capture": "POST /v1/memories",
        "delete": "DELETE /v1/memories/{id}",
    },
    "agentmemory": {
        "doctor": "GET /agentmemory/livez",
        "search": "POST /agentmemory/smart-search",
        "capture": "POST /agentmemory/remember",
        "delete": "DELETE /agentmemory/governance/memories",
        "export": "GET /agentmemory/export",
        "restore": "POST /agentmemory/import",
    },
}


class BrokerUnavailable(RuntimeError):
    pass


class BrokerDenied(PermissionError):
    pass


class ServiceIPC(Protocol):
    """Root-owned broker transport. No endpoint, method, path, or key from a worker."""
    def request(self, *, service_id: str, provider: str, fixed_route: str,
                payload: bytes, timeout: float,
                cancelled: Callable[[], bool]) -> bytes: ...


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
                 cancelled: Callable[[], bool]) -> bytes: ...


class BackgroundConsentIssuer(Protocol):
    def __call__(self, *, context: HostContext, provider_id: str,
                 owner_generation: int, ttl_seconds: int = 300) -> bytes: ...


@dataclass(frozen=True, slots=True)
class MemoryTarget:
    provider: str
    profile_id: str
    namespace_id: str
    service_id: str
    source_revision: str
    service_generation: int
    dedicated_store: bool = True

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS or not all(
                isinstance(x, str) and x and len(x) <= 256 for x in
                (self.profile_id, self.namespace_id, self.service_id)):
            raise ValueError("invalid protected provider enrollment")
        if (len(self.source_revision) != 40 or
                any(c not in "0123456789abcdef" for c in self.source_revision)):
            raise ValueError("provider source must be commit pinned")
        if type(self.service_generation) is not int or self.service_generation < 1:
            raise ValueError("supervised service generation is required")
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
                    result BLOB, error_code TEXT
                );
                CREATE INDEX IF NOT EXISTS memory_jobs_ready ON jobs(status,created);
                """)
            finally:
                db.close()

    def _db(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA busy_timeout=2000")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
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
        consent = self.consent_issuer(context=context, provider_id=target.provider,
                                      owner_generation=generation, ttl_seconds=300)
        if not isinstance(consent, bytes) or not 1 <= len(consent) <= 16 * 1024:
            raise BrokerDenied("authority did not issue bounded signed background consent")
        raw_event = canonical(event, MAX_EVENT)
        receipt = secrets.token_urlsafe(24)
        now = self.clock()
        with process_lock(self.owned.path("memory-queue.lock")):
            db = self._db()
            try:
                db.execute("BEGIN IMMEDIATE")
                n = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('queued','processing')").fetchone()[0]
                if n >= 10000:
                    raise BrokerUnavailable("durable memory queue is full")
                profile_n = db.execute("SELECT COUNT(*) FROM jobs WHERE profile=? AND status IN ('queued','processing')",
                                       (context.profile_id,)).fetchone()[0]
                if profile_n >= 1000:
                    raise BrokerUnavailable("profile memory queue is full")
                db.execute("INSERT INTO jobs(id,profile,namespace,provider,owner_generation,source_context,consent,event,status,created,updated) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (receipt, context.profile_id, context.namespace_id, target.provider,
                     generation, source, consent, raw_event, "queued", now, now))
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
                db.execute("UPDATE jobs SET status='queued',lease_until=NULL,updated=? WHERE status='processing' AND lease_until<?",
                           (now, now))
                row = db.execute("SELECT id,profile,namespace,provider,owner_generation,source_context,consent,event,attempts FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
                if row is None:
                    db.commit()
                    return None
                if db.execute("UPDATE jobs SET status='processing',lease_until=?,updated=?,attempts=attempts+1 WHERE id=? AND status='queued'",
                              (now + lease_seconds, now, row[0])).rowcount != 1:
                    db.rollback()
                    return None
                db.commit()
                return dict(zip(("id","profile_id","namespace_id","provider","owner_generation",
                    "source_context","consent","event","attempts"),
                    (row[0],row[1],row[2],row[3],row[4],bytes(row[5]),bytes(row[6]),bytes(row[7]),row[8]+1)))
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
                if db.execute("UPDATE jobs SET status=?,result=?,error_code=?,lease_until=NULL,updated=? WHERE id=? AND status='processing'",
                    (status, raw, error_code[:64] if error_code else None, self.clock(), job["id"])).rowcount != 1:
                    raise BrokerUnavailable("queue lease changed before completion")
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
               cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        try:
            if (authorization.target != "memory:" + target.provider + ":" + action
                    or authorization.profile_id != target.profile_id
                    or authorization.namespace_id != target.namespace_id
                    or authorization.request_digest != hashlib.sha256(payload).hexdigest()):
                raise BrokerDenied("effect grant is not bound to this exact payload and target")
            if not 0 < timeout <= maximum_timeout:
                raise ValueError("memory timeout is out of bounds")
            body = parse_request(payload)
            _scope(context, target, body)
            if cancelled():
                return _reply({"error":"cancelled"}, 499)
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
                request = {"record_id":_text(body.get("record_id"),"record id",256),
                    "source":_text(body.get("source"),"source",512),"facts":facts,"embeddings":vectors,
                    "lineage":context.lineage_hash}
                if request["source"].startswith("memory:"):
                    raise BrokerDenied("recursive memory ingestion denied")
            elif action == "search":
                q=_text(body.get("query"),"query",4096); limit=body.get("limit",10)
                if type(limit) is not int or not 1 <= limit <= 100: raise ValueError("invalid search limit")
                if target.provider=="openviking":
                    request={"query":q,"target_uri":"viking://~/memories","context_type":["memory"],"limit":limit,"read_content":True}
                elif target.provider=="claude-mem":
                    request={"projectId":target.namespace_id,"query":q,"limit":min(limit,50)}
                else:
                    request={"query":q,"limit":min(limit,20)}
            elif action=="doctor":
                request={"profile_id":context.profile_id,"namespace_id":context.namespace_id,
                         "service_generation":target.service_generation}
            elif action=="delete":
                rid=_text(body.get("record_id"),"record id",256)
                request={"record_id":rid,"profile_id":context.profile_id,"namespace_id":context.namespace_id}
            elif action in {"export","backup","restore"}:
                if action not in ROUTES[target.provider]:
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
            route=ROUTES[target.provider].get(action)
            if route is None or ipc is None:
                raise BrokerUnavailable("root-owned authenticated memory service connector is unavailable")
            result=_result(ipc.request(service_id=target.service_id,provider=target.provider,
                fixed_route=route,payload=canonical(request),timeout=timeout,cancelled=cancelled))
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
                         cancelled: Callable[[], bool], _provider=provider, _action=action):
                target=table.get((context.profile_id,context.namespace_id,_provider))
                if target is None:
                    return _reply({"error":"no enrolled memory target for signed profile"},403)
                return _handler(target,_action,ipc=ipc,queue=queue,owner_state=owner_state,
                    engines=engines,eligibility=eligibility,maximum_timeout=maximum_timeout)(
                        context=context,authorization=authorization,payload=payload,
                        timeout=timeout,peer_pid=peer_pid,cancelled=cancelled)
            result[binding]=dispatch
    return result

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
                 "facts":facts,"embeddings":vectors,"provenance":record["provenance"]})
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
        parsed=_result(result)
        if parsed.get("error"):
            if parsed.get("error")=="policy_revoked":raise BrokerDenied("background policy revoked")
            raise BrokerUnavailable("background provider stage is unavailable")
        return parsed
