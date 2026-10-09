"""Durable profile-scoped memory capture owner ledger."""
from __future__ import annotations

import os
import sqlite3
import uuid
from pathlib import Path

from hermes_installer.state import OwnedRoot, process_lock


class OwnerTransitionError(RuntimeError):
    pass


class SQLiteOwnerLedger:
    """Small protected journal; unresolved transitions block all ownership reads."""

    def __init__(self, root: Path):
        self.owned = OwnedRoot(root)
        self.owned.ensure()
        self.path = self.owned.path("owner-ledger.sqlite3")
        with process_lock(self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS owners(profile TEXT PRIMARY KEY, provider TEXT);
                    CREATE TABLE IF NOT EXISTS transitions(
                        id TEXT PRIMARY KEY, profile TEXT NOT NULL, old_provider TEXT,
                        new_provider TEXT, state TEXT NOT NULL
                    );
                """)
                db.commit()
            finally:
                db.close()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        os.chmod(self.path, 0o600)
        db.execute("PRAGMA busy_timeout=5000")
        db.execute("PRAGMA journal_mode=DELETE")
        return db

    @staticmethod
    def _valid(profile: str, provider: str | None = None):
        if not profile or len(profile) > 128 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in profile):
            raise ValueError("invalid profile identifier")
        if provider is not None and (not provider or len(provider) > 64 or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in provider)):
            raise ValueError("invalid provider identifier")

    def get_owner(self, profile: str) -> str | None:
        self._valid(profile)
        with process_lock(self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                pending = db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone()
                if pending:
                    raise OwnerTransitionError("memory owner transition requires explicit recovery")
                row = db.execute("SELECT provider FROM owners WHERE profile=?", (profile,)).fetchone()
                return row[0] if row else None
            finally:
                db.close()

    def set_owner(self, profile: str, name: str | None) -> None:
        self._valid(profile, name)
        with process_lock(self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT 1 FROM transitions WHERE profile=? AND state='prepared'", (profile,)).fetchone():
                    raise OwnerTransitionError("cannot change owner during a prepared transition")
                db.execute("INSERT INTO owners(profile,provider) VALUES(?,?) ON CONFLICT(profile) DO UPDATE SET provider=excluded.provider", (profile, name))
                db.commit()
            finally:
                db.close()

    def begin_transition(self, profile: str, old: str | None, new: str | None) -> str:
        self._valid(profile, old)
        self._valid(profile, new)
        transition_id = str(uuid.uuid4())
        with process_lock(self.owned.path("owner-ledger.lock")):
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
        with process_lock(self.owned.path("owner-ledger.lock")):
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
                db.execute("INSERT INTO owners(profile,provider) VALUES(?,?) ON CONFLICT(profile) DO UPDATE SET provider=excluded.provider", (profile, name))
                db.execute("UPDATE transitions SET state='committed' WHERE id=?", (transition_id,))
                db.commit()
            finally:
                db.close()

    def abort_transition(self, profile: str, transition_id: str) -> None:
        with process_lock(self.owned.path("owner-ledger.lock")):
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute("UPDATE transitions SET state='aborted' WHERE id=? AND profile=? AND state='prepared'",
                           (transition_id, profile))
                db.commit()
            finally:
                db.close()
