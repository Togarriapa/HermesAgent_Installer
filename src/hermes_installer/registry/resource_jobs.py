"""Root-owned durable admission ledger for selected Resources jobs.

This module stores bounded immutable DAG jobs and gives each child attempt a
single-use admission. It deliberately does not mint authority contexts or
effect grants: the protected AuthorityService must verify the signed event
receipts and issue a fresh child grant after ``admit_child`` succeeds.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping, Sequence

from .resources_runtime import ResourceRuntimeError


class ResourceJobDenied(ResourceRuntimeError):
    """A resource job or child transition failed its protected bounds."""


_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_EFFECTS = frozenset({
    "resource.cron.run", "resource.webhook.run", "resource.channel.run",
    "resource.bundle.node.run",
})


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        raise ResourceJobDenied("job payload is not canonical JSON") from None


def _ident(value: object, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ResourceJobDenied(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class ResourceJobNode:
    """One reviewed immutable graph action and its exact child effect binding."""

    node_id: str
    action_id: str
    effect: str
    target: str
    recipient: str | None
    payload: bytes
    depends_on: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _ident(self.node_id, "node id")
        _ident(self.action_id, "action id")
        if self.effect not in _EFFECTS:
            raise ResourceJobDenied("child effect is not an enrolled resource operation")
        _ident(self.target, "child target")
        if self.recipient is not None:
            _ident(self.recipient, "child recipient")
        if not isinstance(self.payload, bytes) or not 1 <= len(self.payload) <= 1_048_576:
            raise ResourceJobDenied("child payload exceeds the enrolled bound")
        try:
            parsed = json.loads(self.payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ResourceJobDenied("child payload must be canonical JSON") from None
        if _canonical(parsed) != self.payload:
            raise ResourceJobDenied("child payload must be canonical JSON")
        if not isinstance(self.depends_on, tuple) or any(not isinstance(item, str) for item in self.depends_on):
            raise ResourceJobDenied("child dependencies are malformed")
        object.__setattr__(self, "depends_on", tuple(self.depends_on))

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ResourceJobEnrollment:
    """Protected root enrollment; callers never supply or mutate these fields."""

    resource_id: str
    kind: str
    generation: str
    selected_enabled: bool
    profile_id: str
    principal_id: str
    consent_revision: str
    approved_action_ids: frozenset[str]
    fixed_target_ids: frozenset[str]
    recipient_scope: frozenset[str]
    source_policy: frozenset[str]
    schedule_or_route_id: str
    nodes: tuple[ResourceJobNode, ...]
    max_children: int
    max_concurrency: int
    max_runtime_seconds: int
    max_payload_bytes: int
    max_replay_entries: int

    def __post_init__(self) -> None:
        for key in ("resource_id", "kind", "profile_id", "principal_id", "consent_revision", "schedule_or_route_id"):
            _ident(getattr(self, key), key)
        if not _DIGEST.fullmatch(self.generation):
            raise ResourceJobDenied("resource generation must be a SHA-256 digest")
        if self.kind not in {"crons", "webhooks", "channels", "bundles"}:
            raise ResourceJobDenied("resource kind cannot start a protected job")
        if type(self.selected_enabled) is not bool or not self.selected_enabled:
            raise ResourceJobDenied("resource is not selected and enabled")
        for name in ("approved_action_ids", "fixed_target_ids", "recipient_scope", "source_policy"):
            values = getattr(self, name)
            if not isinstance(values, (set, frozenset)) or any(not isinstance(item, str) for item in values):
                raise ResourceJobDenied(f"{name} must be a set of fixed identifiers")
            frozen = frozenset(_ident(item, name) for item in values)
            object.__setattr__(self, name, frozen)
        for name, maximum in (("max_children", 256), ("max_concurrency", 64),
                              ("max_runtime_seconds", 86_400), ("max_payload_bytes", 4_194_304),
                              ("max_replay_entries", 1_000_000)):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ResourceJobDenied(f"{name} is outside supported bounds")
        if (not isinstance(self.nodes, tuple) or not self.nodes
                or any(not isinstance(node, ResourceJobNode) for node in self.nodes)
                or len(self.nodes) > self.max_children):
            raise ResourceJobDenied("approved DAG exceeds the enrolled child limit")
        if sum(len(node.payload) for node in self.nodes) > self.max_payload_bytes:
            raise ResourceJobDenied("aggregate approved DAG payload exceeds the enrolled bound")
        if len({node.node_id for node in self.nodes}) != len(self.nodes):
            raise ResourceJobDenied("approved DAG contains duplicate node identities")
        action_ids = {node.action_id for node in self.nodes}
        targets = {node.target for node in self.nodes}
        if not action_ids <= self.approved_action_ids or not targets <= self.fixed_target_ids:
            raise ResourceJobDenied("approved DAG exceeds selected action or target scope")
        if any(node.recipient is not None and node.recipient not in self.recipient_scope for node in self.nodes):
            raise ResourceJobDenied("approved DAG exceeds selected recipient scope")
        _validate_dag(self.nodes)

    @property
    def dag_sha256(self) -> str:
        body = [{"node_id": n.node_id, "action_id": n.action_id, "effect": n.effect,
                 "target": n.target, "recipient": n.recipient,
                 "payload_sha256": n.payload_sha256, "depends_on": list(n.depends_on)}
                for n in self.nodes]
        return hashlib.sha256(_canonical(body)).hexdigest()

    @property
    def node_map(self) -> Mapping[str, ResourceJobNode]:
        return {node.node_id: node for node in self.nodes}


def _validate_dag(nodes: Sequence[ResourceJobNode]) -> None:
    by_id = {node.node_id: node for node in nodes}
    if any(len(node.depends_on) > len(nodes) or len(set(node.depends_on)) != len(node.depends_on)
           or any(dep not in by_id or dep == node.node_id for dep in node.depends_on)
           for node in nodes):
        raise ResourceJobDenied("approved DAG has invalid prerequisites")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node_id: str) -> None:
        if node_id in visiting:
            raise ResourceJobDenied("approved DAG contains a cycle")
        if node_id in visited:
            return
        visiting.add(node_id)
        for dependency in by_id[node_id].depends_on:
            visit(dependency)
        visiting.remove(node_id)
        visited.add(node_id)

    for node_id in by_id:
        visit(node_id)


@dataclass(frozen=True, slots=True)
class ResourceJobAdmission:
    job_id: str
    resource_id: str
    generation: str
    approved_dag_sha256: str
    expires_monotonic: float
    max_concurrency: int
    child_admission_ids: Mapping[str, str]

    def __post_init__(self) -> None:
        if not isinstance(self.child_admission_ids, Mapping):
            raise ResourceJobDenied("child admission map is malformed")
        copied = {_ident(key, "node id"): _ident(value, "child admission id")
                  for key, value in self.child_admission_ids.items()}
        object.__setattr__(self, "child_admission_ids", MappingProxyType(copied))


@dataclass(frozen=True, slots=True)
class ResourceChildAdmission:
    """Single-use bounded claim; it is not itself a HostContext or effect grant."""

    admission_id: str
    job_id: str
    resource_id: str
    generation: str
    node_id: str
    action_id: str
    effect: str
    target: str
    recipient: str | None
    canonical_payload_sha256: str
    payload: bytes
    source_receipt_ids: tuple[str, ...]
    parent_result_receipt_ids: tuple[str, ...]


class ResourceJobLedger:
    """Atomic, restart-durable job and per-child-attempt state machine.

    Construct under the protected root service directory. ``verified_event``
    must be a result of the root AuthorityService validating a signed source
    receipt; a plugin receipt, event ID, or caller boolean is not accepted by
    this API.
    """

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS jobs (
      job_id TEXT PRIMARY KEY, resource_id TEXT NOT NULL, generation TEXT NOT NULL,
      event_key TEXT NOT NULL, source_receipts TEXT NOT NULL, dag_json TEXT NOT NULL,
      dag_sha256 TEXT NOT NULL, expires REAL NOT NULL,
      max_concurrency INTEGER NOT NULL, status TEXT NOT NULL
    ) WITHOUT ROWID;
    CREATE UNIQUE INDEX IF NOT EXISTS jobs_event_once ON jobs(resource_id,generation,event_key);
    CREATE TABLE IF NOT EXISTS children (
      admission_id TEXT PRIMARY KEY, job_id TEXT NOT NULL, node_id TEXT NOT NULL,
      status TEXT NOT NULL, result_receipts TEXT NOT NULL,
      UNIQUE(job_id,node_id), FOREIGN KEY(job_id) REFERENCES jobs(job_id)
    ) WITHOUT ROWID;
    """

    def __init__(self, path: Path, *, max_jobs: int = 100_000,
                 timeout_seconds: float = 2.0, monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("resource job database path must be absolute")
        if type(max_jobs) is not int or not 1 <= max_jobs <= 1_000_000:
            raise ValueError("resource job capacity is outside supported bounds")
        if not 0.05 <= timeout_seconds <= 10.0:
            raise ValueError("resource job database timeout is outside supported bounds")
        self.path, self.max_jobs = path, max_jobs
        self.timeout_seconds, self.monotonic = float(timeout_seconds), monotonic
        self._prepare()
        db = self._connect()
        try:
            db.executescript(self._SCHEMA)
        finally:
            db.close()

    def _prepare(self) -> None:
        parent = self.path.parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ResourceJobDenied("resource job store parent must be private and root-service-owned")
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            fd = None
        if fd is not None:
            os.close(fd)
        file_info = self.path.lstat()
        if (not stat.S_ISREG(file_info.st_mode) or stat.S_ISLNK(file_info.st_mode)
                or file_info.st_uid != os.geteuid() or file_info.st_nlink != 1
                or stat.S_IMODE(file_info.st_mode) != 0o600):
            raise ResourceJobDenied("resource job database must be a private service-owned regular file")

    def _connect(self) -> sqlite3.Connection:
        try:
            db = sqlite3.connect(self.path, timeout=self.timeout_seconds, isolation_level=None)
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute(f"PRAGMA busy_timeout={int(self.timeout_seconds * 1000)}")
            return db
        except sqlite3.Error as exc:
            raise ResourceJobDenied("resource job ledger is unavailable") from exc

    @staticmethod
    def _event_key(event_id: str, receipt_ids: Sequence[str]) -> str:
        _ident(event_id, "event id")
        if not isinstance(receipt_ids, (tuple, list)) or not receipt_ids or len(receipt_ids) > 64:
            raise ResourceJobDenied("root-verified source receipts are required")
        normalized = sorted({_ident(item, "source receipt id") for item in receipt_ids})
        if len(normalized) != len(receipt_ids):
            raise ResourceJobDenied("duplicate source receipts are not allowed")
        return hashlib.sha256(_canonical({"event_id": event_id, "receipts": normalized})).hexdigest()

    def admit_job(self, enrollment: ResourceJobEnrollment, *, event_id: str,
                  verified_source_receipt_ids: Sequence[str], current_generation: str,
                  ttl_seconds: int) -> ResourceJobAdmission:
        """Consume one root-authenticated event and create bounded child slots.

        Caller data is limited to the event identity and opaque receipt IDs.
        The route/schedule issuer supplies the trusted enrollment and receipt
        IDs only after AuthorityService verified their signatures and lineage.
        """
        if not isinstance(enrollment, ResourceJobEnrollment):
            raise ResourceJobDenied("protected selected resource enrollment is required")
        if current_generation != enrollment.generation:
            raise ResourceJobDenied("selected resource generation is stale")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= enrollment.max_runtime_seconds:
            raise ResourceJobDenied("job deadline exceeds its root-enrolled runtime")
        source_kinds = {"schedule-event" if enrollment.kind == "crons" else
                        "webhook-event" if enrollment.kind == "webhooks" else
                        "native-input" if enrollment.kind == "channels" else "static-context"}
        if not source_kinds <= enrollment.source_policy:
            raise ResourceJobDenied("event source kind is not selected by root policy")
        event_key = self._event_key(event_id, verified_source_receipt_ids)
        now = self.monotonic()
        job_id = secrets.token_urlsafe(24)
        ids = {node.node_id: secrets.token_urlsafe(24) for node in enrollment.nodes}
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM jobs WHERE resource_id=? AND generation=? AND event_key=?",
                          (enrollment.resource_id, enrollment.generation, event_key)).fetchone():
                raise ResourceJobDenied("resource event was already admitted")
            count = db.execute("SELECT count(*) FROM jobs").fetchone()[0]
            resource_count = db.execute("SELECT count(*) FROM jobs WHERE resource_id=?",
                                        (enrollment.resource_id,)).fetchone()[0]
            if count >= self.max_jobs or resource_count >= enrollment.max_replay_entries:
                raise ResourceJobDenied("resource job ledger is full")
            dag_json = _canonical({node.node_id: list(node.depends_on) for node in enrollment.nodes}).decode()
            db.execute("INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)",
                       (job_id, enrollment.resource_id, enrollment.generation, event_key,
                        _canonical(sorted(verified_source_receipt_ids)).decode(),
                        dag_json, enrollment.dag_sha256, now + ttl_seconds,
                        enrollment.max_concurrency, "running"))
            db.executemany("INSERT INTO children VALUES (?,?,?,'pending','[]')",
                           ((ids[node.node_id], job_id, node.node_id) for node in enrollment.nodes))
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("resource job admission failed closed") from exc
        finally:
            db.close()
        return ResourceJobAdmission(job_id, enrollment.resource_id, enrollment.generation,
                                    enrollment.dag_sha256, now + ttl_seconds,
                                    enrollment.max_concurrency, ids)

    def admit_child(self, admission: ResourceJobAdmission, enrollment: ResourceJobEnrollment, *,
                    node_id: str, parent_result_receipt_ids: Sequence[str],
                    current_generation: str) -> ResourceChildAdmission:
        """Atomically claim a ready child; authority then mints a fresh grant."""
        if (not isinstance(admission, ResourceJobAdmission)
                or not isinstance(enrollment, ResourceJobEnrollment)
                or admission.resource_id != enrollment.resource_id
                or admission.generation != enrollment.generation
                or admission.approved_dag_sha256 != enrollment.dag_sha256):
            raise ResourceJobDenied("job admission does not match the selected immutable DAG")
        if current_generation != enrollment.generation:
            self.revoke_generation(enrollment.resource_id, enrollment.generation)
            raise ResourceJobDenied("resource generation was revoked")
        node = enrollment.node_map.get(_ident(node_id, "node id"))
        admission_id = admission.child_admission_ids.get(node_id)
        if node is None or admission_id is None:
            raise ResourceJobDenied("child identity is outside the admitted DAG")
        parents = tuple(sorted({_ident(item, "parent result receipt id") for item in parent_result_receipt_ids}))
        if len(parents) != len(parent_result_receipt_ids) or len(parents) > 64:
            raise ResourceJobDenied("parent result receipt lineage is malformed")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT resource_id,generation,source_receipts,dag_json,dag_sha256,expires,max_concurrency,status FROM jobs WHERE job_id=?",
                             (admission.job_id,)).fetchone()
            now = self.monotonic()
            if (job is None or job[0] != enrollment.resource_id or job[1] != current_generation
                    or job[4] != enrollment.dag_sha256 or job[5] <= now or job[7] != "running"
                    or admission.expires_monotonic <= now):
                raise ResourceJobDenied("job is expired, revoked, or no longer current")
            rows = {row[0]: (row[1], json.loads(row[2])) for row in db.execute(
                "SELECT node_id,status,result_receipts FROM children WHERE job_id=?", (admission.job_id,))}
            if any(rows.get(dep, (None,))[0] != "complete" for dep in node.depends_on):
                raise ResourceJobDenied("child prerequisites are not complete")
            required_parents = tuple(sorted({receipt for dep in node.depends_on for receipt in rows[dep][1]}))
            if parents != required_parents:
                raise ResourceJobDenied("child lineage does not contain the exact completed parent receipts")
            active = db.execute("SELECT count(*) FROM children WHERE job_id=? AND status IN ('admitted','running')",
                                (admission.job_id,)).fetchone()[0]
            if active >= job[6]:
                raise ResourceJobDenied("resource job concurrency limit is reached")
            cur = db.execute("UPDATE children SET status='admitted' WHERE admission_id=? AND job_id=? AND node_id=? AND status='pending'",
                             (admission_id, admission.job_id, node_id))
            if cur.rowcount != 1:
                raise ResourceJobDenied("child admission was already consumed")
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("child admission failed closed") from exc
        finally:
            db.close()
        return ResourceChildAdmission(admission_id, admission.job_id, enrollment.resource_id,
                                      enrollment.generation, node.node_id, node.action_id,
                                      node.effect, node.target, node.recipient, node.payload_sha256,
                                      node.payload, tuple(json.loads(job[2])), parents)

    def start_child(self, child: ResourceChildAdmission, *, current_generation: str) -> None:
        if current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("resource generation was revoked before child effect")
        self._transition(child, "admitted", "running", receipts=())

    def fail_child_admission(self, child: ResourceChildAdmission, *, current_generation: str) -> None:
        """Terminally fail a slot if context/grant minting fails before dispatch.

        RB07 has no retry enrollment field, so this attempt cannot be reopened;
        any later retry needs a separately specified root-owned attempt bound.
        """
        if current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("resource generation was revoked before child dispatch")
        self._transition(child, "admitted", "failed", receipts=())
        self._cancel_descendants(child.job_id, child.node_id)
        self._finish_job_if_terminal(child.job_id)

    def finish_child(self, child: ResourceChildAdmission, *, result_receipt_ids: Sequence[str],
                     success: bool, current_generation: str) -> None:
        if type(success) is not bool or current_generation != child.generation:
            self.revoke_generation(child.resource_id, child.generation)
            raise ResourceJobDenied("child result arrived after generation revocation")
        receipts = tuple(sorted({_ident(item, "result receipt id") for item in result_receipt_ids}))
        if success and not receipts:
            raise ResourceJobDenied("successful child must preserve its root-issued result receipt")
        self._transition(child, "running", "complete" if success else "failed", receipts=receipts)
        if not success:
            self._cancel_descendants(child.job_id, child.node_id)
        self._finish_job_if_terminal(child.job_id)

    def _transition(self, child: ResourceChildAdmission, before: str, after: str,
                    *, receipts: Sequence[str]) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            job = db.execute("SELECT expires,status FROM jobs WHERE job_id=?", (child.job_id,)).fetchone()
            if job is None or job[0] <= self.monotonic() or job[1] != "running":
                raise ResourceJobDenied("job expired or stopped before child transition")
            cursor = db.execute("UPDATE children SET status=?,result_receipts=? WHERE admission_id=? AND job_id=? AND node_id=? AND status=?",
                                (after, _canonical(list(receipts)).decode(), child.admission_id,
                                 child.job_id, child.node_id, before))
            if cursor.rowcount != 1:
                raise ResourceJobDenied("child attempt transition is stale or already consumed")
            db.commit()
        except ResourceJobDenied:
            db.rollback()
            raise
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("child state update failed closed") from exc
        finally:
            db.close()

    def _cancel_descendants(self, job_id: str, failed_node: str) -> None:
        """Cancel only transitive dependents, including any active owned work."""
        db = self._connect()
        try:
            graph = db.execute("SELECT dag_json FROM jobs WHERE job_id=?", (job_id,)).fetchone()
            if graph is None:
                raise ResourceJobDenied("job disappeared before descendant cancellation")
            dependencies = json.loads(graph[0])
            cancelled = {failed_node}
            changed = True
            while changed:
                changed = False
                for node_id, parents in dependencies.items():
                    if node_id not in cancelled and any(parent in cancelled for parent in parents):
                        cancelled.add(node_id)
                        changed = True
            descendants = cancelled - {failed_node}
            if descendants:
                placeholders = ",".join("?" for _ in descendants)
                db.execute(f"UPDATE children SET status='cancelled' WHERE job_id=? AND node_id IN ({placeholders}) AND status IN ('pending','admitted','running')",
                           (job_id, *sorted(descendants)))
        finally:
            db.close()

    def is_active(self, child: ResourceChildAdmission, *, current_generation: str) -> bool:
        """Fresh cancellation/deadline check suitable for the broker callback."""
        if current_generation != child.generation:
            return False
        db = self._connect()
        try:
            row = db.execute("SELECT j.generation,j.expires,j.status,c.status FROM jobs j JOIN children c ON c.job_id=j.job_id WHERE j.job_id=? AND c.admission_id=?",
                             (child.job_id, child.admission_id)).fetchone()
            return bool(row and row[0] == current_generation and row[1] > self.monotonic()
                        and row[2] == "running" and row[3] == "running")
        finally:
            db.close()

    def _finish_job_if_terminal(self, job_id: str) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            pending = db.execute("SELECT count(*) FROM children WHERE job_id=? AND status IN ('pending','admitted','running')",
                                 (job_id,)).fetchone()[0]
            if pending == 0:
                failed = db.execute("SELECT count(*) FROM children WHERE job_id=? AND status IN ('failed','cancelled')",
                                    (job_id,)).fetchone()[0]
                db.execute("UPDATE jobs SET status=? WHERE job_id=? AND status='running'",
                           ("failed" if failed else "complete", job_id))
            db.commit()
        finally:
            db.close()

    def revoke_generation(self, resource_id: str, generation: str) -> int:
        _ident(resource_id, "resource id")
        if not _DIGEST.fullmatch(generation):
            raise ResourceJobDenied("resource generation is invalid")
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE children SET status='cancelled' WHERE status IN ('pending','admitted','running') AND job_id IN (SELECT job_id FROM jobs WHERE resource_id=? AND generation=?)",
                       (resource_id, generation))
            cursor = db.execute("UPDATE jobs SET status='cancelled' WHERE resource_id=? AND generation=? AND status='running'",
                                (resource_id, generation))
            count = cursor.rowcount
            db.commit()
            return count
        except sqlite3.Error as exc:
            db.rollback()
            raise ResourceJobDenied("generation revocation failed closed") from exc
        finally:
            db.close()
