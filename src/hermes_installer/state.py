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
        return db

    def _initialize(self) -> None:
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at REAL NOT NULL, payload TEXT NOT NULL)")
            db.execute("CREATE TABLE IF NOT EXISTS owned_resources (kind TEXT NOT NULL, resource_id TEXT NOT NULL, created_at REAL NOT NULL, state TEXT NOT NULL, PRIMARY KEY(kind, resource_id))")

    def checkpoint(self, operation: str, status: str, payload: dict[str, object]) -> None:
        if not operation or not status:
            raise ValueError("operation and status are required")
        encoded = json.dumps(payload, sort_keys=True)
        with self._connect() as db:
            db.execute("INSERT INTO operations(id,status,updated_at,payload) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at, payload=excluded.payload", (operation, status, time.time(), encoded))

    def operation(self, operation: str) -> dict[str, object] | None:
        with self._connect() as db:
            row = db.execute("SELECT status,updated_at,payload FROM operations WHERE id=?", (operation,)).fetchone()
        if row is None:
            return None
        return {"status": row["status"], "updated_at": row["updated_at"], "payload": json.loads(row["payload"])}

    def record_owned(self, kind: str, resource_id: str, state: str = "active") -> None:
        with self._connect() as db:
            db.execute("INSERT INTO owned_resources(kind,resource_id,created_at,state) VALUES(?,?,?,?) ON CONFLICT(kind,resource_id) DO UPDATE SET state=excluded.state", (kind, resource_id, time.time(), state))

    def owned(self, kind: str | None = None) -> list[dict[str, object]]:
        with self._connect() as db:
            rows = db.execute("SELECT kind,resource_id,created_at,state FROM owned_resources WHERE (? IS NULL OR kind=?) ORDER BY kind,resource_id", (kind, kind)).fetchall()
        return [dict(row) for row in rows]
