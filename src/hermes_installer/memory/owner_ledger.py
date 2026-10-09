"""Durable profile-scoped memory capture owner ledger."""
from __future__ import annotations

import os
import sqlite3
import uuid
from pathlib import Path

from hermes_installer.state import OwnedRoot, process_lock
from hermes_installer.memory.root_state import MemoryAuthorityStateDirectory, memory_state_lock


class OwnerTransitionError(RuntimeError):
    pass


def _secure_sqlite_files(path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        candidate = Path(str(path) + suffix)
        try:
            fd = os.open(candidate, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
        except FileNotFoundError:
            continue
        except OSError:
            raise OwnerTransitionError("memory owner SQLite file cannot be opened safely") from None
        try:
            info = os.fstat(fd)
            if not __import__("stat").S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise OwnerTransitionError("memory owner SQLite file has the wrong type or owner")
            os.fchmod(fd, 0o600)
            if __import__("stat").S_IMODE(os.fstat(fd).st_mode) != 0o600:
                raise OwnerTransitionError("memory owner SQLite file is not mode 0600")
        finally:
            os.close(fd)


class SQLiteOwnerLedger:
    """Small protected journal; unresolved transitions block all ownership reads."""

    def __init__(self, root: Path | MemoryAuthorityStateDirectory):
        self.owned = root if isinstance(root, MemoryAuthorityStateDirectory) else OwnedRoot(root)
        self.profile_scope = self.owned.profile_id if isinstance(self.owned, MemoryAuthorityStateDirectory) else None
        self.owned.ensure()
        self.path = self.owned.path("owner-ledger.sqlite3")
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS owners(
                        profile TEXT PRIMARY KEY, provider TEXT, generation INTEGER NOT NULL DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS transitions(
                        id TEXT PRIMARY KEY, profile TEXT NOT NULL, old_provider TEXT,
                        new_provider TEXT, state TEXT NOT NULL
                    );
                """)
                columns = {row[1] for row in db.execute("PRAGMA table_info(owners)")}
                if "generation" not in columns:
                    db.execute("ALTER TABLE owners ADD COLUMN generation INTEGER NOT NULL DEFAULT 1")
                db.commit()
            finally:
                db.close()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=WAL")
        _secure_sqlite_files(self.path)
        return db

    @staticmethod
    def _valid(profile: str, provider: str | None = None):
        if not profile or len(profile) > 128 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in profile):
            raise ValueError("invalid profile identifier")
        if provider is not None and (not provider or len(provider) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in provider)):
            raise ValueError("invalid provider identifier")

    def _check_profile(self, profile: str) -> None:
        if self.profile_scope is not None and profile != self.profile_scope:
            raise OwnerTransitionError("memory owner ledger is bound to another profile")

    def get_owner(self, profile: str) -> str | None:
        self._valid(profile)
        self._check_profile(profile)
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                pending = db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone()
                if pending:
                    raise OwnerTransitionError("memory owner transition requires explicit recovery")
                row = db.execute("SELECT provider FROM owners WHERE profile=?", (profile,)).fetchone()
                return row[0] if row else None
            finally:
                db.close()

    def get_owner_state(self, profile: str) -> tuple[str | None, int]:
        """Return durable owner plus generation used to invalidate queued events."""
        self._valid(profile)
        self._check_profile(profile)
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                if db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone():
                    raise OwnerTransitionError("memory owner transition requires explicit recovery")
                row = db.execute("SELECT provider,generation FROM owners WHERE profile=?", (profile,)).fetchone()
                return (row[0], int(row[1])) if row else (None, 0)
            finally:
                db.close()

    def set_owner(self, profile: str, name: str | None) -> None:
        self._valid(profile, name)
        self._check_profile(profile)
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone():
                    raise OwnerTransitionError("cannot change owner during a prepared transition")
                row = db.execute("SELECT provider,generation FROM owners WHERE profile=?", (profile,)).fetchone()
                if row is None:
                    if name is not None:
                        db.execute("INSERT INTO owners(profile,provider,generation) VALUES(?,?,1)", (profile,name))
                elif row[0] != name:
                    db.execute("UPDATE owners SET provider=?,generation=generation+1 WHERE profile=?", (name,profile))
                db.commit()
            finally:
                db.close()

    def begin_transition(self, profile: str, old: str | None, new: str | None) -> str:
        self._valid(profile, old)
        self._valid(profile, new)
        self._check_profile(profile)
        transition_id = str(uuid.uuid4())
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                pending = db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone()
                if pending:
                    raise OwnerTransitionError("an earlier owner transition requires recovery")
                owner = db.execute("SELECT provider FROM owners WHERE profile=?", (profile,)).fetchone()
                current = owner[0] if owner else None
                if current != old:
                    raise OwnerTransitionError("requested old owner does not match durable owner")
                db.execute("INSERT INTO transitions(id,profile,old_provider,new_provider,state) VALUES(?,?,?,?, 'prepared')",
                           (transition_id, profile, old, new))
                db.commit()
            finally:
                db.close()
        return transition_id

    def commit_transition(self, profile: str, transition_id: str, name: str | None) -> None:
        self._valid(profile, name)
        self._check_profile(profile)
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT old_provider,new_provider,state FROM transitions WHERE id=? AND profile=?",
                                 (transition_id, profile)).fetchone()
                if not row or row[1:] != (name, "prepared"):
                    raise OwnerTransitionError("owner transition journal mismatch")
                owner = db.execute("SELECT provider FROM owners WHERE profile=?", (profile,)).fetchone()
                current = owner[0] if owner else None
                if current != row[0]:
                    raise OwnerTransitionError("durable owner changed during transition")
                if owner is None:
                    db.execute("INSERT INTO owners(profile,provider,generation) VALUES(?,?,1)", (profile,name))
                elif owner[0] != name:
                    db.execute("UPDATE owners SET provider=?,generation=generation+1 WHERE profile=?", (name,profile))
                db.execute("UPDATE transitions SET state='committed' WHERE id=?", (transition_id,))
                db.commit()
            finally:
                db.close()

    def abort_transition(self, profile: str, transition_id: str, *, recovered: bool = True) -> None:
        self._valid(profile)
        self._check_profile(profile)
        with memory_state_lock(self.owned, self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT state FROM transitions WHERE id=? AND profile=?",
                                 (transition_id, profile)).fetchone()
                if not row or row[0] != "prepared":
                    raise OwnerTransitionError("cannot abort a non-prepared owner transition")
                if recovered:
                    db.execute("UPDATE transitions SET state='aborted' WHERE id=? AND profile=? AND state='prepared'",
                               (transition_id, profile))
                # If live compensation is uncertain, retain prepared state and block reads.
                db.commit()
            finally:
                db.close()
