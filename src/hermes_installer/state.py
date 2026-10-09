"""Ownership-aware paths, locks, and durable install checkpoints."""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import platform
import sqlite3
import time
import stat
import uuid
from pathlib import Path
from typing import Iterator


class OwnershipError(ValueError):
    pass


class OwnedRoot:
    def __init__(self, root: Path):
        requested = root.expanduser().absolute()
        if requested.is_symlink():
            raise OwnershipError(f"Managed root cannot be a symlink: {requested}")
        self.root = _canonical_parent(requested.parent) / requested.name

    def ensure(self) -> None:
        protected = {Path("/"), Path("/etc"), Path("/usr"), Path("/opt"), Path("/home"), Path("/root"), Path("/Users"), Path("/System"), Path("/Library"), Path("/var"), Path("/private/var"), Path("/var/lib"), Path("/var/log"), Path.home().resolve()}
        home = Path.home().resolve()
        system_roots = {Path("/etc"), Path("/usr"), Path("/opt"), Path("/System"), Path("/Library"), Path("/var/lib"), Path("/var/log")}
        if self.root in protected or any(self.root.is_relative_to(root) for root in system_roots) or home.is_relative_to(self.root):
            raise OwnershipError(f"Protected system or user directory cannot be an installer-owned root: {self.root}")
        if self.root.exists() and any(self.root.iterdir()):
            marker = self.root / ".hermes-installer-owned"
            if not marker.is_file() or marker.is_symlink():
                raise OwnershipError(f"Refusing to adopt non-empty unowned directory: {self.root}")
        _reject_symlink_components(self.root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        _reject_symlink_components(self.root)
        root_info = self.root.lstat()
        if not self.root.is_dir() or root_info.st_uid != os.getuid():
            raise OwnershipError(f"Managed root must be a directory owned by the effective user: {self.root}")
        if stat.S_IMODE(root_info.st_mode) & 0o077:
            self.root.chmod(0o700)
        marker = self.root / ".hermes-installer-owned"
        if marker.exists() or marker.is_symlink():
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(marker, flags)
                try:
                    info = os.fstat(fd)
                    value = os.read(fd, 64)
                finally:
                    os.close(fd)
            except OSError:
                raise OwnershipError("Ownership marker cannot be read safely") from None
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or value != b"schema=1\n":
                raise OwnershipError("Ownership marker has invalid owner, permissions, type or contents")
        else:
            _atomic_write(marker, b"schema=1\n", 0o600)

    def path(self, relative: str) -> Path:
        rel = Path(relative)
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            raise OwnershipError("Managed path must be a non-empty relative path without '..'")
        candidate = self.root / rel
        _reject_symlink_components(candidate.parent)
        if candidate.exists() and candidate.is_symlink():
            raise OwnershipError(f"Managed path is a symlink: {candidate}")
        if not candidate.resolve(strict=False).is_relative_to(self.root.resolve(strict=False)):
            raise OwnershipError("Managed path escapes the owned root")
        return candidate


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            raise OwnershipError(f"Refusing symlink in managed path: {current}")


def _canonical_parent(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.exists() and current.is_symlink():
            target = current.resolve(strict=True)
            mac_alias = platform.system() == "Darwin" and current in {Path("/var"), Path("/tmp")} and target in {Path("/private/var"), Path("/private/tmp")}
            if not mac_alias:
                raise OwnershipError(f"Refusing symlink in managed path: {current}")
            current = target
    return current.resolve(strict=False)


def _atomic_write(path: Path, content: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


@contextlib.contextmanager
def process_lock(path: Path) -> Iterator[None]:
    requested = path.expanduser().absolute()
    if requested.exists() and requested.is_symlink():
        raise OwnershipError("Lock file cannot be a symlink")
    parent = _canonical_parent(requested.parent)
    if not (parent / ".hermes-installer-owned").is_file():
        raise OwnershipError("Process lock must live in an installer-owned root")
    path = parent / requested.name
    _reject_symlink_components(path.parent)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise OwnershipError("Process lock cannot be opened without following links") from None
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        os.close(fd)
        raise OwnershipError("Process lock must be a private regular file owned by the effective user")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        os.close(fd)
        raise RuntimeError(f"Another installer operation holds {path}") from exc
    try:
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


class Journal:
    def __init__(self, path: Path):
        requested = path.expanduser().absolute()
        if requested.exists() and requested.is_symlink():
            raise OwnershipError("Journal cannot be a symlink")
        parent = _canonical_parent(requested.parent)
        if not (parent / ".hermes-installer-owned").is_file():
            raise OwnershipError("Journal must live in an installer-owned root")
        self.path = parent / requested.name
        _reject_symlink_components(self.path.parent)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            if self.path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OwnershipError("Journal must be a private regular file owned by the effective user")
        self._initialize()
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("CREATE TABLE IF NOT EXISTS operation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, step TEXT NOT NULL, event TEXT NOT NULL, created_at REAL NOT NULL, details TEXT NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS managed_files (path TEXT PRIMARY KEY, source_digest TEXT NOT NULL, installed_digest TEXT NOT NULL, state TEXT NOT NULL, updated_at REAL NOT NULL)")
        return db

    @contextlib.contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        db = self._connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at REAL NOT NULL, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS owned_resources (kind TEXT NOT NULL, resource_id TEXT NOT NULL, created_at REAL NOT NULL, state TEXT NOT NULL, PRIMARY KEY(kind, resource_id))")
            db.execute("CREATE TABLE IF NOT EXISTS operation_events (sequence INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, step TEXT NOT NULL, event TEXT NOT NULL, created_at REAL NOT NULL, details TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS managed_files (path TEXT PRIMARY KEY, source_digest TEXT NOT NULL, installed_digest TEXT NOT NULL, state TEXT NOT NULL, updated_at REAL NOT NULL)")

    def checkpoint(self, operation: str, status: str, payload: dict[str, object]) -> None:
        if not operation or not status:
            raise ValueError("operation and status are required")
        encoded = json.dumps(_redact_metadata(payload), sort_keys=True)
        with self._transaction() as db:
            db.execute("INSERT INTO operations(id,status,updated_at,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, payload=excluded.payload", (operation, status, time.time(), encoded))

    def event(self, operation: str, step: str, event: str, details: dict[str, object] | None = None) -> None:
        """Append a redacted progress/effect record; events are never overwritten."""
        if not operation or not step or not event:
            raise ValueError("operation, step and event are required")
        encoded = json.dumps(_redact_metadata(details or {}), sort_keys=True)
        with self._transaction() as db:
            db.execute("INSERT INTO operation_events(operation_id,step,event,created_at,details) VALUES(?,?,?,?,?)",
                       (operation, step, event, time.time(), encoded))

    def events(self, operation: str, *, limit: int = 1000) -> list[dict[str, object]]:
        if not 1 <= limit <= 10_000:
            raise ValueError("event limit must be between 1 and 10000")
        with self._transaction() as db:
            rows = db.execute("SELECT sequence,step,event,created_at,details FROM operation_events WHERE operation_id=? ORDER BY sequence DESC LIMIT ?",
                              (operation, limit)).fetchall()
        return [{"sequence": row["sequence"], "step": row["step"], "event": row["event"],
                 "created_at": row["created_at"], "details": json.loads(row["details"])} for row in reversed(rows)]

    def managed_file(self, path: str) -> dict[str, object] | None:
        with self._transaction() as db:
            row = db.execute("SELECT path,source_digest,installed_digest,state,updated_at FROM managed_files WHERE path=?", (path,)).fetchone()
        return dict(row) if row is not None else None

    def record_managed_file(self, path: str, source_digest: str, installed_digest: str, state: str = "installed") -> None:
        with self._transaction() as db:
            db.execute("INSERT INTO managed_files(path,source_digest,installed_digest,state,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET source_digest=excluded.source_digest,installed_digest=excluded.installed_digest,state=excluded.state,updated_at=excluded.updated_at",
                       (path, source_digest, installed_digest, state, time.time()))

    def operation(self, operation: str) -> dict[str, object] | None:
        with self._transaction() as db:
            row = db.execute("SELECT status,updated_at,payload FROM operations WHERE id=?", (operation,)).fetchone()
        if row is None:
            return None
        return {"status": row["status"], "updated_at": row["updated_at"], "payload": json.loads(row["payload"])}

    def record_owned(self, kind: str, resource_id: str, state: str = "active") -> None:
        with self._transaction() as db:
            db.execute("INSERT INTO owned_resources(kind,resource_id,created_at,state) VALUES(?,?,?,?) ON CONFLICT(kind,resource_id) DO UPDATE SET state=excluded.state", (kind, resource_id, time.time(), state))

    def owned(self, kind: str | None = None) -> list[dict[str, object]]:
        with self._transaction() as db:
            rows = db.execute("SELECT kind,resource_id,created_at,state FROM owned_resources WHERE (? IS NULL OR kind=?) ORDER BY kind,resource_id", (kind, kind)).fetchall()
        return [dict(row) for row in rows]


_SECRET_KEY = __import__("re").compile(r"(?:secret|token|password|passwd|api[_-]?key|authorization|cookie|credential)(?:$|[_-])", __import__("re").I)
_SECRET_TEXT = __import__("re").compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+=*|(?:sk-[A-Za-z0-9_-]{16,})|((?:api[_-]?key|token|password|secret)\s*[:=]\s*)[^\s,;]+")


def _redact_text(value: str) -> str:
    return _SECRET_TEXT.sub(lambda match: (match.group(1) or match.group(2) or "") + "[REDACTED]", value)


def _redact_metadata(value: object, *, key: str = "") -> object:
    """Keep journal diagnostics useful while removing secret-shaped fields and strings."""
    if _SECRET_KEY.search(key):
        # References are identifiers, never credential material.
        if key.lower().endswith(("_ref", "_reference")):
            return value
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(name): _redact_metadata(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_metadata(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:1024]
