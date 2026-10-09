"""Private, profile-bound SQLite lifecycle for local Epic boards."""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import time
from typing import Any, Callable

from hermes_installer.state import OwnedRoot, OwnershipError, process_lock


class BoardStoreError(RuntimeError):
    pass


class SQLiteEpicBoardStore:
    """One selected profile's ephemeral boards on an installer-owned root.

    ``acceptance_verifier`` is a trusted effect verifier supplied by the host;
    caller-provided summary text can never authorize deletion by itself.
    """
    _PROFILE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
    _EPIC = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")
    _BOARD = re.compile(r"^[a-f0-9]{32}$")
    _ITEM = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")

    def __init__(self, root: OwnedRoot, profile_id: str,
                 acceptance_verifier: Callable[[str, str, str], bool]):
        if not isinstance(root, OwnedRoot) or not callable(acceptance_verifier):
            raise TypeError("board store requires an OwnedRoot and trusted acceptance verifier")
        if not self._PROFILE.fullmatch(profile_id):
            raise BoardStoreError("invalid selected profile identity")
        root.ensure()
        self.root, self.profile_id, self._verify_acceptance = root, profile_id, acceptance_verifier
        self.relative = f"runtime/epic-boards/{profile_id}/boards.sqlite3"
        self.lock_relative = "epic-boards.lock"
        try:
            self.path = root.path(self.relative)
        except OwnershipError:
            raise BoardStoreError("board database path is unsafe") from None
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        current = root.root
        for part in Path(self.relative).parts[:-1]:
            current = current / part
            try:
                info = current.lstat()
            except OSError:
                raise BoardStoreError("board storage directory is unavailable") from None
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise BoardStoreError("board storage directory has unsafe ownership or type")
            if stat.S_IMODE(info.st_mode) & 0o077:
                os.chmod(current, 0o700, follow_symlinks=False)
        self._prepare_file()
        with self._transaction() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS boards (
                    board_id TEXT PRIMARY KEY, epic_id TEXT NOT NULL UNIQUE,
                    title TEXT NOT NULL, created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS items (
                    board_id TEXT NOT NULL REFERENCES boards(board_id) ON DELETE CASCADE,
                    item_id TEXT NOT NULL, item_type TEXT NOT NULL, title TEXT NOT NULL,
                    state TEXT NOT NULL, summary TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(board_id, item_id)
                );
                CREATE TABLE IF NOT EXISTS accepted_summaries (
                    board_id TEXT PRIMARY KEY, epic_id TEXT NOT NULL,
                    summary TEXT NOT NULL, accepted_at REAL NOT NULL,
                    summary_sha256 TEXT NOT NULL
                );
            """)

    def create(self, epic_id: str, title: str) -> str:
        if not isinstance(epic_id, str) or not self._EPIC.fullmatch(epic_id):
            raise BoardStoreError("invalid Epic identity")
        _text(title, "board title", 200)
        board_id = secrets.token_hex(16)
        with self._locked(), self._transaction() as db:
            try:
                db.execute("INSERT INTO boards VALUES(?,?,?,?)", (board_id, epic_id, title, time.time()))
            except sqlite3.IntegrityError:
                raise BoardStoreError("an active board already exists for this Epic") from None
        return board_id

    def read(self, board_id: str) -> dict[str, Any] | None:
        board_id = self._board(board_id)
        with self._locked(), self._transaction() as db:
            row = db.execute("SELECT epic_id,title,created_at FROM boards WHERE board_id=?", (board_id,)).fetchone()
            if row is None:
                return None
            items = db.execute("SELECT item_id,item_type,title,state,summary FROM items WHERE board_id=? ORDER BY item_id", (board_id,)).fetchall()
        return {"id": board_id, "epic_id": row[0], "title": row[1], "created_at": row[2],
                "items": [dict(zip(("id", "type", "title", "state", "summary"), item)) for item in items]}

    def mutate(self, board_id: str, operation: str, item: dict[str, Any]) -> dict[str, Any]:
        board_id = self._board(board_id)
        if operation not in {"add_item", "move_item"}:
            raise BoardStoreError("unsupported board mutation")
        values = _validate_item(item)
        with self._locked(), self._transaction() as db:
            if db.execute("SELECT 1 FROM boards WHERE board_id=?", (board_id,)).fetchone() is None:
                raise BoardStoreError("board does not exist in the selected profile")
            if operation == "add_item":
                try:
                    db.execute("INSERT INTO items VALUES(?,?,?,?,?,?)",
                               (board_id, *values))
                except sqlite3.IntegrityError:
                    raise BoardStoreError("board item already exists") from None
            else:
                cursor = db.execute("UPDATE items SET state=? WHERE board_id=? AND item_id=?",
                                    (values[3], board_id, values[0]))
                if cursor.rowcount != 1:
                    raise BoardStoreError("board item does not exist")
        result = self.read(board_id)
        if result is None:
            raise BoardStoreError("board disappeared during update")
        return result

    def delete_after_accepted_done(self, board_id: str, accepted_summary: str) -> bool:
        board_id = self._board(board_id)
        _text(accepted_summary, "accepted summary", 4000)
        with self._locked(), self._transaction() as db:
            row = db.execute("SELECT epic_id FROM boards WHERE board_id=?", (board_id,)).fetchone()
            if row is None:
                return False
            items = db.execute("SELECT COUNT(*), COALESCE(SUM(state='done'),0) FROM items WHERE board_id=?", (board_id,)).fetchone()
            if items[0] == 0 or items[0] != items[1]:
                return False
            if not self._verify_acceptance(self.profile_id, board_id, accepted_summary):
                raise BoardStoreError("trusted accepted-completion evidence is missing")
            digest = hashlib.sha256(accepted_summary.encode("utf-8")).hexdigest()
            db.execute("INSERT OR REPLACE INTO accepted_summaries VALUES(?,?,?,?,?)",
                       (board_id, row[0], accepted_summary, time.time(), digest))
            db.execute("DELETE FROM boards WHERE board_id=?", (board_id,))
        return True

    def accepted_summary(self, board_id: str) -> dict[str, Any] | None:
        board_id = self._board(board_id)
        with self._locked(), self._transaction() as db:
            row = db.execute("SELECT epic_id,summary,accepted_at,summary_sha256 FROM accepted_summaries WHERE board_id=?", (board_id,)).fetchone()
        if row is None:
            return None
        return {"epic_id": row[0], "summary": row[1], "accepted_at": row[2], "sha256": row[3]}

    @contextlib.contextmanager
    def _locked(self):
        with process_lock(self.root.path(self.lock_relative)):
            yield

    @contextlib.contextmanager
    def _transaction(self):
        self._check_database()
        db = sqlite3.connect(self.root.path(self.relative), timeout=5, isolation_level=None)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _prepare_file(self) -> None:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError:
            raise BoardStoreError("board database cannot be opened safely") from None
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise BoardStoreError("board database ownership or file type is unsafe")
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)

    def _check_database(self) -> None:
        try:
            path = self.root.path(self.relative)
            info = path.lstat()
        except OSError:
            raise BoardStoreError("board database is unavailable") from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise BoardStoreError("board database changed to unsafe ownership or permissions")

    def _board(self, value: str) -> str:
        if not isinstance(value, str) or not self._BOARD.fullmatch(value):
            raise BoardStoreError("invalid board id")
        return value


def _text(value: object, label: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise BoardStoreError(f"{label} must be bounded non-empty text")


def _validate_item(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    if not isinstance(item, dict) or set(item) - {"id", "type", "title", "state", "summary"}:
        raise BoardStoreError("item fields are outside the Epic board schema")
    _text(item.get("id"), "item id", 80)
    _text(item.get("title"), "item title", 200)
    if not SQLiteEpicBoardStore._ITEM.fullmatch(item["id"]):
        raise BoardStoreError("invalid item id")
    types = {"epic", "user-story", "task", "defect", "spike", "risk", "decision"}
    states = {"backlog", "ready", "in-progress", "review", "blocked", "done"}
    if item.get("type") not in types or item.get("state") not in states:
        raise BoardStoreError("item type or state is outside the fixed board workflow")
    summary = item.get("summary", "")
    if not isinstance(summary, str) or len(summary) > 4000 or any(ord(c) < 32 and c not in "\n\t" for c in summary):
        raise BoardStoreError("item summary is invalid")
    return item["id"], item["type"], item["title"], item["state"], summary
