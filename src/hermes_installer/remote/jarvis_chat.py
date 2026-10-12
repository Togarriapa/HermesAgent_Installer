"""Finite, principal-owned Jarvis chat adapter over official Hermes core TUI RPC.

The public surface never exposes Hermes runtime/stored session IDs, backend credentials, or a
generic RPC method. Principal and service currentness are supplied by the protected Unix ingress
composition; family tool/memory isolation remains a separate, unavailable capability.
"""
from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import math
import os
import re
import secrets
import sqlite3
import stat
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Protocol

MAX_BODY_BYTES = 16 * 1024
MAX_TEXT_CHARS = 8_000
MAX_ASSISTANT_CHARS = 64_000
MAX_EVENTS_PER_TURN = 8_192
MAX_ACTIVE_TURNS = 2
MAX_ACTIVE_TURNS_PER_CONVERSATION = 1
MAX_LEASE_SECONDS = 30.0
SSE_CONNECTION_SECONDS = 4.0
MAX_HISTORY_CHARS = 128_000
MAX_TURN_SECONDS = 600.0
MAX_OWNER_TURN_HANDLES = 512
CHAT_STATE_DIRECTORY = Path("/var/lib/hermes-jarvis-chat")
CHAT_STORE_PATH = CHAT_STATE_DIRECTORY / "chat.sqlite3"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
MODEL_REVISION_RE = re.compile(r"^[0-9a-f]{32}$")
MODEL_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_MODEL_SELECTION_EPOCH = secrets.token_hex(16)
_ACTIVE = ("queued", "running")
_CHAT_LOGGER = logging.getLogger(__name__)
_MESSAGE_DIAGNOSTIC_PHASES = frozenset({
    "principal", "conversation_lookup", "runtime_resume", "runtime_resume_recheck",
    "runtime_mapping", "history_rpc", "history_projection", "response",
})


def _log_messages_failure(phase: str, error: BaseException) -> None:
    """Emit bounded troubleshooting data without request, session, or backend content."""
    if phase not in _MESSAGE_DIAGNOSTIC_PHASES:
        phase = "response"
    safe_types = {ValueError, TypeError, KeyError, RuntimeError, OSError,
                  sqlite3.Error, JarvisChatDenied}
    kind = type(error).__name__ if type(error) in safe_types else "OtherError"
    _CHAT_LOGGER.warning("jarvis_chat_messages_failed phase=%s exception=%s", phase, kind)


class JarvisChatDenied(PermissionError):
    """The protected chat surface or its backend is unavailable."""


@dataclass(frozen=True, slots=True)
class ChatPrincipal:
    subject: str
    expires_monotonic: float
    witness_expires_monotonic: float
    core_generation: str = ""


class OfficialChatBackend(Protocol):
    async def create_session(self) -> tuple[str, str]: ...
    async def resume_session(self, stored_session_id: str) -> str: ...
    async def resume_history(self, stored_session_id: str) -> tuple[str, list[dict[str, Any]]]: ...
    async def history(self, session_id: str) -> list[dict[str, Any]]: ...
    def stream(self, session_id: str, text: str) -> AsyncIterator[Any]: ...
    def stream_owned_turn(self, stored_session_id: str, text: str, *,
                          before_submit: Callable[[str], Any]) -> AsyncIterator[Any]: ...
    async def stop(self, session_id: str) -> None: ...


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _opaque_id() -> str:
    return secrets.token_urlsafe(24)


def _valid_core_session_id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 512
            and not any(ord(char) < 0x20 for char in value))


def _now() -> float:
    return time.time()


def _read_private_secret(path: Path, *, owner_uid: int, allowed_group: int | None = None) -> str:
    """Read a server-only Hermes session token through a no-follow protected descriptor."""
    directory_flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                       | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        parent_fd = os.open(path.parent, directory_flags)
    except OSError:
        raise JarvisChatDenied("official API key custody is invalid") from None
    try:
        parent_before = os.fstat(parent_fd)
        parent_mode = stat.S_IMODE(parent_before.st_mode)
        if (not stat.S_ISDIR(parent_before.st_mode) or parent_before.st_uid != owner_uid
                or (allowed_group is None and parent_mode & 0o077)
                or (allowed_group is not None and (parent_before.st_gid != allowed_group
                                                   or parent_mode != 0o750))):
            raise JarvisChatDenied("official API key parent custody is invalid")
        try:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
        except OSError:
            raise JarvisChatDenied("official API key custody is invalid") from None
        try:
            info = os.fstat(fd)
            mode = stat.S_IMODE(info.st_mode)
            expected_mode = 0o600 if allowed_group is None else 0o640
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                    or info.st_nlink != 1 or mode != expected_mode
                    or (allowed_group is not None and info.st_gid != allowed_group)
                    or info.st_size < 32 or info.st_size > 4096):
                raise JarvisChatDenied("official API key custody is invalid")
            raw = os.read(fd, 4097)
            after = os.fstat(fd)
            parent_after = os.fstat(parent_fd)
            try:
                named_after = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                raise JarvisChatDenied("official API key changed while reading") from None
            def signature(item):
                return (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            if (signature(after) != signature(info) or signature(parent_after) != signature(parent_before)
                    or (named_after.st_dev, named_after.st_ino) != (info.st_dev, info.st_ino)
                    or len(raw) != info.st_size or len(raw) > 4096):
                raise JarvisChatDenied("official API key changed while reading")
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    try:
        key = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        raise JarvisChatDenied("official API key encoding is invalid") from None
    if len(key) < 32 or any(char in key for char in "\r\n\x00"):
        raise JarvisChatDenied("official API key is invalid")
    return key


class JarvisChatStore:
    """Durable owner mapping and bounded safe event log."""

    def __init__(self, path: Path, *, max_active_turns: int = MAX_ACTIVE_TURNS,
                 owner_uid: int | None = None):
        if not path.is_absolute() or type(max_active_turns) is not int or not 1 <= max_active_turns <= 2:
            raise ValueError("absolute durable store path and a maximum of two active turns are required")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        expected_uid = os.geteuid() if owner_uid is None else owner_uid
        parent_info = path.parent.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != expected_uid
                or stat.S_IMODE(parent_info.st_mode) & 0o077):
            raise JarvisChatDenied("chat store directory custody is invalid")
        if path.exists() or path.is_symlink():
            file_info = path.lstat()
            if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != expected_uid
                    or stat.S_IMODE(file_info.st_mode) & 0o077):
                raise JarvisChatDenied("chat store custody is invalid")
        self.path = path
        self.max_active_turns = max_active_turns
        self._initialize()
        self._recover_interrupted_turns()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=2, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=2000")
        return conn

    def _initialize(self):
        with self._connect() as db:
            db.executescript("""
              PRAGMA journal_mode=WAL;
              CREATE TABLE IF NOT EXISTS conversations(
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, backend_id TEXT NOT NULL UNIQUE,
                session_key TEXT NOT NULL, title TEXT NOT NULL, created REAL NOT NULL, updated REAL NOT NULL,
                core_generation TEXT NOT NULL DEFAULT '');
              CREATE INDEX IF NOT EXISTS conversation_owner ON conversations(owner, updated DESC);
              CREATE TABLE IF NOT EXISTS messages(
                id TEXT PRIMARY KEY, conversation_id TEXT NOT NULL REFERENCES conversations(id),
                role TEXT NOT NULL CHECK(role IN ('user','assistant')), content TEXT NOT NULL, created REAL NOT NULL);
              CREATE TABLE IF NOT EXISTS turns(
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, conversation_id TEXT NOT NULL REFERENCES conversations(id),
                idempotency_hash TEXT NOT NULL, request_hash TEXT NOT NULL, status TEXT NOT NULL,
                heartbeat_nonce TEXT NOT NULL, heartbeat_expiry REAL NOT NULL, jwt_expiry REAL NOT NULL,
                runtime_session_id TEXT NOT NULL DEFAULT '', core_generation TEXT NOT NULL DEFAULT '',
                partial TEXT NOT NULL DEFAULT '', error_code TEXT NOT NULL DEFAULT '', created REAL NOT NULL, updated REAL NOT NULL,
                UNIQUE(owner,idempotency_hash));
              CREATE INDEX IF NOT EXISTS turn_owner ON turns(owner, created DESC);
              CREATE TABLE IF NOT EXISTS turn_events(
                turn_id TEXT NOT NULL REFERENCES turns(id) ON DELETE CASCADE, sequence INTEGER NOT NULL,
                name TEXT NOT NULL, data TEXT NOT NULL, PRIMARY KEY(turn_id,sequence));
              CREATE TABLE IF NOT EXISTS model_selection_revisions(
                conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
                owner TEXT NOT NULL, core_generation TEXT NOT NULL, runtime_session_id TEXT NOT NULL,
                session_key_hash TEXT NOT NULL, config_sha256 TEXT NOT NULL, revision_hash TEXT NOT NULL,
                approval_hash TEXT NOT NULL, epoch TEXT NOT NULL, expires REAL NOT NULL);
              CREATE TABLE IF NOT EXISTS model_selection_ops(
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, conversation_id TEXT NOT NULL,
                idempotency_hash TEXT NOT NULL, request_hash TEXT NOT NULL, model_id TEXT NOT NULL,
                state TEXT NOT NULL, core_generation TEXT NOT NULL, runtime_session_id TEXT NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL, UNIQUE(owner,idempotency_hash));
              CREATE INDEX IF NOT EXISTS model_selection_ops_recent
                ON model_selection_ops(owner,updated DESC);
              CREATE TABLE IF NOT EXISTS model_selection_locks(
                conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
                operation_id TEXT NOT NULL UNIQUE, owner TEXT NOT NULL,
                core_generation TEXT NOT NULL, expires REAL NOT NULL);
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(conversations)")}
            if "core_generation" not in columns:
                db.execute("ALTER TABLE conversations ADD COLUMN core_generation TEXT NOT NULL DEFAULT ''")
            turn_columns = {row[1] for row in db.execute("PRAGMA table_info(turns)")}
            if "runtime_session_id" not in turn_columns:
                db.execute("ALTER TABLE turns ADD COLUMN runtime_session_id TEXT NOT NULL DEFAULT ''")
            if "core_generation" not in turn_columns:
                db.execute("ALTER TABLE turns ADD COLUMN core_generation TEXT NOT NULL DEFAULT ''")
        os.chmod(self.path, 0o600)

    def _recover_interrupted_turns(self) -> None:
        """A process restart cannot resume an upstream stream; close each old run durably."""
        with self._connect() as db:
            ids = [row[0] for row in db.execute(
                "SELECT id FROM turns WHERE status IN ('queued','running')").fetchall()]
        for turn_id in ids:
            self.finish_turn(turn_id, "cancelled")

    def _owner(self, subject: str) -> str:
        if not isinstance(subject, str) or not 1 <= len(subject) <= 512:
            raise JarvisChatDenied("verified principal is invalid")
        return _digest(subject)

    def list_conversations(self, subject: str) -> list[dict]:
        owner = self._owner(subject)
        with self._connect() as db:
            has_trash = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                   "AND name='jarvis_conversation_trash'").fetchone() is not None
            query = ("SELECT c.id,c.title,c.updated FROM conversations c WHERE c.owner=? "
                     + ("AND NOT EXISTS (SELECT 1 FROM jarvis_conversation_trash t "
                        "WHERE t.conversation_id=c.id AND t.owner=c.owner AND t.deleted=1) "
                        if has_trash else "")
                     + "ORDER BY c.updated DESC LIMIT 100")
            rows = db.execute(query,
                              (owner,)).fetchall()
        return [{"id": r["id"], "title": r["title"], "updatedAt": r["updated"]} for r in rows]

    def create_conversation(self, subject: str, backend_id: str, session_key: str,
                            core_generation: str) -> dict:
        owner = self._owner(subject)
        now = _now()
        conversation_id = _opaque_id()
        if (not _valid_core_session_id(backend_id) or not _valid_core_session_id(session_key)
                or not isinstance(core_generation, str)
                or not 1 <= len(core_generation) <= 256):
            raise JarvisChatDenied("official core session mapping is invalid")
        with self._connect() as db:
            db.execute("INSERT INTO conversations(id,owner,backend_id,session_key,title,created,updated,core_generation) "
                       "VALUES(?,?,?,?,?,?,?,?)",
                       (conversation_id, owner, backend_id, session_key, "Jarvis", now, now, core_generation))
        return {"id": conversation_id, "title": "Jarvis", "createdAt": now}

    def update_runtime_session(self, subject: str, conversation_id: str, old_generation: str,
                               runtime_id: str, core_generation: str) -> sqlite3.Row:
        if (not _valid_core_session_id(runtime_id) or not isinstance(core_generation, str)
                or not 1 <= len(core_generation) <= 256):
            raise JarvisChatDenied("official core resume mapping is invalid")
        owner = self._owner(subject)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE conversations SET backend_id=?,core_generation=? "
                "WHERE id=? AND owner=? AND core_generation=?",
                (runtime_id, core_generation, conversation_id, owner, old_generation)).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("official core session mapping changed during resume")
            db.execute("COMMIT")
        return self.get_conversation(subject, conversation_id)

    def rebind_active_turn_session(self, principal: ChatPrincipal, conversation_id: str,
                                   turn_id: str, old_runtime_id: str,
                                   runtime_id: str, *, stored_session_id: str | None = None) -> None:
        """Atomically bind a queued/running owned turn to its just-resumed native session."""
        if (not isinstance(principal, ChatPrincipal) or not ID_RE.fullmatch(conversation_id or "")
                or not ID_RE.fullmatch(turn_id or "") or not _valid_core_session_id(old_runtime_id)
                or not _valid_core_session_id(runtime_id)
                or (stored_session_id is not None and not _valid_core_session_id(stored_session_id))
                or time.monotonic() >= principal.expires_monotonic):
            raise JarvisChatDenied("official core turn mapping is stale")
        owner = self._owner(principal.subject)
        now = time.monotonic()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT c.backend_id,c.core_generation,c.owner,t.runtime_session_id,t.status,"
                "t.heartbeat_expiry,t.jwt_expiry,t.core_generation AS turn_generation,t.owner AS turn_owner "
                "FROM conversations c JOIN turns t ON t.conversation_id=c.id "
                "WHERE c.id=? AND t.id=?", (conversation_id, turn_id)).fetchone()
            if (current is None or current["owner"] != owner or current["turn_owner"] != owner
                    or current["backend_id"] != old_runtime_id
                    or current["runtime_session_id"] != old_runtime_id
                    or current["core_generation"] != principal.core_generation
                    or current["turn_generation"] != principal.core_generation
                    or current["status"] not in {"queued", "running"}
                    or now >= min(current["heartbeat_expiry"], current["jwt_expiry"])):
                db.execute("ROLLBACK")
                raise JarvisChatDenied("official core turn mapping changed before submit")
            conversation_changed = db.execute(
                "UPDATE conversations SET backend_id=?,session_key=COALESCE(?,session_key) "
                "WHERE id=? AND owner=? AND backend_id=? "
                "AND core_generation=?",
                (runtime_id, stored_session_id, conversation_id, owner, old_runtime_id,
                 principal.core_generation)).rowcount
            turn_changed = db.execute(
                "UPDATE turns SET runtime_session_id=?,updated=? WHERE id=? AND owner=? "
                "AND conversation_id=? AND runtime_session_id=? AND core_generation=? "
                "AND status IN ('queued','running') AND heartbeat_expiry>? AND jwt_expiry>?",
                (runtime_id, _now(), turn_id, owner, conversation_id, old_runtime_id,
                 principal.core_generation, now, now)).rowcount
            if conversation_changed != 1 or turn_changed != 1:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("official core turn mapping changed before submit")
            db.execute("COMMIT")

    def restore_unsubmitted_turn_session(self, principal: ChatPrincipal, conversation_id: str,
                                         turn_id: str, current_runtime_id: str,
                                         current_stored_session_id: str,
                                         original_runtime_id: str,
                                         original_stored_session_id: str) -> None:
        """Undo an isolated-session map if currentness fails before prompt.submit."""
        if (not isinstance(principal, ChatPrincipal) or not ID_RE.fullmatch(conversation_id or "")
                or not ID_RE.fullmatch(turn_id or "")
                or not all(_valid_core_session_id(value) for value in
                           (current_runtime_id, current_stored_session_id,
                            original_runtime_id, original_stored_session_id))):
            raise JarvisChatDenied("isolated session rollback is invalid")
        owner = self._owner(principal.subject)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("""SELECT c.backend_id,c.session_key,c.owner,c.core_generation,
                t.runtime_session_id,t.owner AS turn_owner,t.core_generation AS turn_generation,t.status
                FROM conversations c JOIN turns t ON t.conversation_id=c.id
                WHERE c.id=? AND t.id=?""", (conversation_id, turn_id)).fetchone()
            events = db.execute("SELECT 1 FROM turn_events WHERE turn_id=? LIMIT 1",
                                (turn_id,)).fetchone()
            if (current is None or events is not None or current["owner"] != owner
                    or current["turn_owner"] != owner
                    or current["core_generation"] != principal.core_generation
                    or current["turn_generation"] != principal.core_generation
                    or current["status"] not in _ACTIVE
                    or current["backend_id"] != current_runtime_id
                    or current["runtime_session_id"] != current_runtime_id
                    or current["session_key"] != current_stored_session_id):
                db.execute("ROLLBACK")
                raise JarvisChatDenied("isolated session rollback is no longer current")
            changed_conversation = db.execute("""UPDATE conversations SET backend_id=?,session_key=?
                WHERE id=? AND owner=? AND core_generation=? AND backend_id=? AND session_key=?""",
                (original_runtime_id, original_stored_session_id, conversation_id, owner,
                 principal.core_generation, current_runtime_id, current_stored_session_id)).rowcount
            changed_turn = db.execute("""UPDATE turns SET runtime_session_id=?,updated=?
                WHERE id=? AND owner=? AND conversation_id=? AND core_generation=?
                  AND runtime_session_id=? AND status IN ('queued','running')""",
                (original_runtime_id, _now(), turn_id, owner, conversation_id,
                 principal.core_generation, current_runtime_id)).rowcount
            if changed_conversation != 1 or changed_turn != 1:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("isolated session rollback changed")
            db.execute("COMMIT")

    def fail_active_conversation_turns(self, conversation_id: str) -> None:
        with self._connect() as db:
            ids = [row[0] for row in db.execute(
                "SELECT id FROM turns WHERE conversation_id=? AND status IN ('queued','running')",
                (conversation_id,)).fetchall()]
        for turn_id in ids:
            self.finish_turn(turn_id, "failed", error_code="core_generation_changed")

    def get_conversation(self, subject: str, conversation_id: str) -> sqlite3.Row:
        if not ID_RE.fullmatch(conversation_id or ""):
            raise JarvisChatDenied("conversation is unavailable")
        with self._connect() as db:
            row = db.execute("SELECT * FROM conversations WHERE id=? AND owner=?",
                              (conversation_id, self._owner(subject))).fetchone()
            has_trash = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                   "AND name='jarvis_conversation_trash'").fetchone() is not None
            if (row is not None and has_trash and db.execute(
                    "SELECT 1 FROM jarvis_conversation_trash WHERE conversation_id=? "
                    "AND owner=? AND deleted=1", (conversation_id, self._owner(subject))).fetchone()):
                row = None
        if row is None:
            raise JarvisChatDenied("conversation is unavailable")
        return row

    def messages(self, subject: str, conversation_id: str) -> list[dict]:
        self.get_conversation(subject, conversation_id)
        with self._connect() as db:
            rows = db.execute("SELECT id,role,content,created FROM messages WHERE conversation_id=? ORDER BY created,id LIMIT 200",
                              (conversation_id,)).fetchall()
        return [{"id": r["id"], "role": r["role"], "content": r["content"], "createdAt": r["created"]}
                for r in rows]

    def begin_turn(self, subject: str, conversation_id: str, text: str, idempotency_key: str,
                   principal: ChatPrincipal, *, turn_configuration: dict[str, Any] | None = None
                   ) -> tuple[str, str, sqlite3.Row]:
        if (not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARS
                or not IDEMPOTENCY_RE.fullmatch(idempotency_key or "")):
            raise ValueError("invalid turn request")
        owner = self._owner(subject)
        conversation = self.get_conversation(subject, conversation_id)
        if conversation["core_generation"] != principal.core_generation:
            raise JarvisChatDenied("core session generation is stale")
        now = time.monotonic()
        # The sealed request proof must be current at this point. It authorizes one bounded
        # lease, while the admitted JWT deadline remains the absolute upper bound.
        expiry = min(now + MAX_LEASE_SECONDS, principal.expires_monotonic)
        if expiry <= now:
            raise JarvisChatDenied("protected chat lease is expired")
        turn_id, nonce = _opaque_id(), secrets.token_hex(32)
        if turn_configuration is not None and (
                not isinstance(turn_configuration, dict)
                or set(turn_configuration) != {"model_id", "reasoning_effort"}
                or not isinstance(turn_configuration.get("model_id"), str)
                or (turn_configuration.get("reasoning_effort") is not None
                    and not isinstance(turn_configuration.get("reasoning_effort"), str))):
            raise JarvisChatDenied("per-message model configuration is invalid")
        request_hash = _digest(json.dumps({"text": text, "turn_configuration": turn_configuration},
                                          sort_keys=True, separators=(",", ":")))
        key_hash = _digest(owner + ":" + idempotency_key)
        wall = _now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute("SELECT id,request_hash FROM turns WHERE owner=? AND idempotency_hash=?",
                                      (owner, key_hash)).fetchone()
                if existing:
                    if existing["request_hash"] != request_hash:
                        raise JarvisChatDenied("idempotency key was already used")
                    raise JarvisChatDenied("turn request replay was denied")
                has_trash = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                                       "AND name='jarvis_conversation_trash'").fetchone() is not None
                if (has_trash and db.execute(
                        "SELECT 1 FROM jarvis_conversation_trash WHERE conversation_id=? "
                        "AND owner=? AND deleted=1", (conversation_id, owner)).fetchone()):
                    raise JarvisChatDenied("conversation is unavailable")
                active = db.execute("SELECT COUNT(*) FROM turns WHERE status IN ('queued','running')").fetchone()[0]
                active_conversation = db.execute(
                    "SELECT COUNT(*) FROM turns WHERE conversation_id=? AND status IN ('queued','running')",
                    (conversation_id,)).fetchone()[0]
                db.execute("DELETE FROM model_selection_locks WHERE expires<=?", (_now(),))
                selection_locked = db.execute(
                    "SELECT 1 FROM model_selection_locks WHERE conversation_id=? AND owner=? "
                    "AND core_generation=? AND expires>?",
                    (conversation_id, owner, principal.core_generation, _now())).fetchone()
                if selection_locked:
                    raise RuntimeError("model selection in progress")
                if (active >= self.max_active_turns
                        or active_conversation >= MAX_ACTIVE_TURNS_PER_CONVERSATION):
                    raise RuntimeError("busy")
                db.execute("INSERT INTO turns(id,owner,conversation_id,idempotency_hash,request_hash,status,heartbeat_nonce,heartbeat_expiry,jwt_expiry,runtime_session_id,core_generation,created,updated) VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?)",
                           (turn_id, owner, conversation_id, key_hash, request_hash, nonce, expiry,
                            principal.expires_monotonic, conversation["backend_id"],
                            conversation["core_generation"], wall, wall))
                db.execute("INSERT INTO messages VALUES(?,?,?,?,?)",
                           (_opaque_id(), conversation_id, "user", text, wall))
                db.execute("UPDATE conversations SET updated=? WHERE id=?", (wall, conversation_id))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return turn_id, nonce, conversation

    def issue_model_selection_revision(self, subject: str, conversation_id: str,
                                       core_generation: str, config_sha256: str) -> dict[str, str]:
        """Issue a one-use, short-lived revision for the owner's current session mapping."""
        if (not isinstance(core_generation, str) or not 1 <= len(core_generation) <= 256
                or not isinstance(config_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", config_sha256)):
            raise JarvisChatDenied("model settings revision is invalid")
        owner = self._owner(subject)
        revision, approval_nonce = secrets.token_hex(16), secrets.token_hex(32)
        expires = time.monotonic() + MAX_LEASE_SECONDS
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            conversation = db.execute(
                "SELECT backend_id,session_key,core_generation FROM conversations WHERE id=? AND owner=?",
                (conversation_id, owner)).fetchone()
            if conversation is None or conversation["core_generation"] != core_generation:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("conversation ownership or generation changed")
            active = db.execute(
                "SELECT 1 FROM turns WHERE conversation_id=? AND status IN ('queued','running') LIMIT 1",
                (conversation_id,)).fetchone()
            if active:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("model selection is unavailable while a turn is active")
            db.execute("DELETE FROM model_selection_locks WHERE expires<=?", (_now(),))
            lock = db.execute("SELECT 1 FROM model_selection_locks WHERE conversation_id=?",
                              (conversation_id,)).fetchone()
            if lock:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("model selection is already in progress")
            db.execute("""INSERT INTO model_selection_revisions(
                conversation_id,owner,core_generation,runtime_session_id,session_key_hash,
                config_sha256,revision_hash,approval_hash,epoch,expires)
                VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(conversation_id) DO UPDATE SET
                owner=excluded.owner,core_generation=excluded.core_generation,
                runtime_session_id=excluded.runtime_session_id,session_key_hash=excluded.session_key_hash,
                config_sha256=excluded.config_sha256,revision_hash=excluded.revision_hash,
                approval_hash=excluded.approval_hash,epoch=excluded.epoch,expires=excluded.expires""",
                (conversation_id, owner, core_generation, conversation["backend_id"],
                 _digest(conversation["session_key"]), config_sha256, _digest(revision),
                 _digest(approval_nonce), _MODEL_SELECTION_EPOCH, expires))
            db.execute("COMMIT")
        return {"revision": revision, "approval_nonce": approval_nonce}

    def reserve_model_selection(self, subject: str, conversation_id: str, *,
                                core_generation: str, config_sha256: str, model_id: str,
                                revision: str, approval_nonce: str, idempotency_key: str
                                ) -> dict[str, Any]:
        """Atomically consume the confirmation, enforce idle state, and block new turns."""
        from .jarvis_model_catalog import CODEX_MODEL_ID_SET
        if (not isinstance(model_id, str) or model_id not in CODEX_MODEL_ID_SET
                or not isinstance(revision, str) or not MODEL_REVISION_RE.fullmatch(revision)
                or not isinstance(approval_nonce, str) or not NONCE_RE.fullmatch(approval_nonce)
                or not isinstance(idempotency_key, str) or not MODEL_IDEMPOTENCY_RE.fullmatch(idempotency_key)
                or not isinstance(config_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", config_sha256)):
            raise JarvisChatDenied("model selection request is invalid")
        owner = self._owner(subject)
        idem_hash = _digest(owner + ":" + idempotency_key)
        request_hash = _digest("\0".join((conversation_id, core_generation, config_sha256,
                                           model_id, revision, approval_nonce)))
        now_wall, now_mono = _now(), time.monotonic()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                previous = db.execute(
                    "SELECT id,request_hash,state,model_id,runtime_session_id FROM model_selection_ops "
                    "WHERE owner=? AND idempotency_hash=?", (owner, idem_hash)).fetchone()
                if previous:
                    if previous["request_hash"] != request_hash:
                        raise JarvisChatDenied("model selection idempotency key was already used")
                    db.execute("COMMIT")
                    return {"operation_id": previous["id"], "state": previous["state"],
                            "model": previous["model_id"],
                            "runtime_session_id": previous["runtime_session_id"], "replayed": True}
                db.execute("DELETE FROM model_selection_ops WHERE owner=? AND updated<?",
                           (owner, now_wall - 86400))
                recent = db.execute(
                    "SELECT COUNT(*) FROM model_selection_ops WHERE owner=? AND updated>=?",
                    (owner, now_wall - 86400)).fetchone()[0]
                if recent >= 200:
                    raise JarvisChatDenied("model selection request limit was reached")
                conversation = db.execute(
                    "SELECT backend_id,session_key,core_generation FROM conversations "
                    "WHERE id=? AND owner=?", (conversation_id, owner)).fetchone()
                if conversation is None or conversation["core_generation"] != core_generation:
                    raise JarvisChatDenied("conversation ownership or generation changed")
                current_revision = db.execute(
                    "SELECT * FROM model_selection_revisions WHERE conversation_id=? AND owner=?",
                    (conversation_id, owner)).fetchone()
                if (current_revision is None or current_revision["epoch"] != _MODEL_SELECTION_EPOCH
                        or current_revision["expires"] <= now_mono
                        or current_revision["core_generation"] != core_generation
                        or current_revision["runtime_session_id"] != conversation["backend_id"]
                        or current_revision["session_key_hash"] != _digest(conversation["session_key"])
                        or current_revision["config_sha256"] != config_sha256
                        or current_revision["revision_hash"] != _digest(revision)
                        or current_revision["approval_hash"] != _digest(approval_nonce)):
                    raise JarvisChatDenied("model selection revision expired or changed")
                active = db.execute(
                    "SELECT 1 FROM turns WHERE conversation_id=? AND status IN ('queued','running') LIMIT 1",
                    (conversation_id,)).fetchone()
                if active:
                    raise JarvisChatDenied("model selection is unavailable while a turn is active")
                db.execute("DELETE FROM model_selection_locks WHERE expires<=?", (now_wall,))
                locked = db.execute("SELECT 1 FROM model_selection_locks WHERE conversation_id=?",
                                    (conversation_id,)).fetchone()
                if locked:
                    raise JarvisChatDenied("model selection is already in progress")
                operation_id = secrets.token_hex(16)
                db.execute("INSERT INTO model_selection_ops VALUES(?,?,?,?,?,?,'unknown-pending',?,?,?,?)",
                           (operation_id, owner, conversation_id, idem_hash, request_hash, model_id,
                            core_generation, conversation["backend_id"], now_wall, now_wall))
                db.execute("INSERT INTO model_selection_locks VALUES(?,?,?,?,?)",
                           (conversation_id, operation_id, owner, core_generation, now_wall + MAX_LEASE_SECONDS))
                db.execute("DELETE FROM model_selection_revisions WHERE conversation_id=?",
                           (conversation_id,))
                db.execute("COMMIT")
                return {"operation_id": operation_id, "state": "reserved",
                        "model": model_id, "runtime_session_id": conversation["backend_id"],
                        "replayed": False}
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def finish_model_selection(self, subject: str, operation_id: str, *, state: str,
                               runtime_session_id: str) -> None:
        if (not re.fullmatch(r"[0-9a-f]{32}", operation_id or "")
                or not _valid_core_session_id(runtime_session_id)
                or state not in {"selected-for-session", "deferred-next-turn",
                                 "confirmation-required", "unknown-pending"}):
            raise JarvisChatDenied("model selection result is invalid")
        owner, now = self._owner(subject), _now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id FROM model_selection_ops WHERE id=? AND owner=?",
                             (operation_id, owner)).fetchone()
            if row is None:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("model selection ownership changed")
            db.execute("UPDATE model_selection_ops SET state=?,runtime_session_id=?,updated=? "
                       "WHERE id=? AND owner=?",
                       (state, runtime_session_id, now, operation_id, owner))
            db.execute("DELETE FROM model_selection_locks WHERE operation_id=? AND owner=?",
                       (operation_id, owner))
            db.execute("COMMIT")

    def bind_model_selection_session(self, subject: str, operation_id: str, *,
                                     core_generation: str, runtime_session_id: str) -> bool:
        """Bind the resumed native session while this owned selection blocks new turns."""
        if (not re.fullmatch(r"[0-9a-f]{32}", operation_id or "")
                or not isinstance(core_generation, str) or not 1 <= len(core_generation) <= 256
                or not _valid_core_session_id(runtime_session_id)):
            raise JarvisChatDenied("model session binding is invalid")
        owner, now = self._owner(subject), _now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            operation = db.execute(
                "SELECT o.conversation_id,o.core_generation,o.runtime_session_id AS reserved_runtime_id,"
                "c.backend_id,c.core_generation AS current_generation "
                "FROM model_selection_ops o JOIN conversations c ON c.id=o.conversation_id "
                "WHERE o.id=? AND o.owner=? AND c.owner=? AND o.state='unknown-pending'",
                (operation_id, owner, owner)).fetchone()
            lease = db.execute(
                "SELECT 1 FROM model_selection_locks WHERE operation_id=? AND owner=? "
                "AND core_generation=? AND expires>?",
                (operation_id, owner, core_generation, now)).fetchone()
            active = (None if operation is None else db.execute(
                "SELECT 1 FROM turns WHERE conversation_id=? AND status IN ('queued','running') LIMIT 1",
                (operation["conversation_id"],)).fetchone())
            if (operation is None or lease is None or active is not None
                    or operation["core_generation"] != core_generation
                    or operation["current_generation"] != core_generation
                    or operation["backend_id"] != operation["reserved_runtime_id"]):
                db.execute("ROLLBACK")
                return False
            changed = db.execute(
                "UPDATE conversations SET backend_id=? WHERE id=? AND owner=? AND core_generation=? AND backend_id=?",
                (runtime_session_id, operation["conversation_id"], owner, core_generation,
                 operation["reserved_runtime_id"])).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                return False
            changed = db.execute(
                "UPDATE model_selection_ops SET runtime_session_id=?,updated=? WHERE id=? AND owner=? "
                "AND core_generation=? AND runtime_session_id=? AND state='unknown-pending'",
                (runtime_session_id, now, operation_id, owner, core_generation,
                 operation["reserved_runtime_id"])).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                return False
            db.execute("COMMIT")
        return True

    def latest_model_selection(self, subject: str, conversation_id: str,
                               core_generation: str, runtime_session_id: str) -> dict[str, str] | None:
        owner = self._owner(subject)
        with self._connect() as db:
            row = db.execute(
                "SELECT model_id,state FROM model_selection_ops WHERE owner=? AND conversation_id=? "
                "AND core_generation=? ORDER BY updated DESC LIMIT 1",
                (owner, conversation_id, core_generation)).fetchone()
        if row is None:
            return None
        return {"model": row["model_id"], "state": row["state"]}

    def model_selection_activity(self, subject: str, conversation_id: str,
                                 core_generation: str) -> str:
        """Return only the bounded busy/available state for an owned current conversation."""
        owner = self._owner(subject)
        with self._connect() as db:
            conversation = db.execute(
                "SELECT 1 FROM conversations WHERE id=? AND owner=? AND core_generation=?",
                (conversation_id, owner, core_generation)).fetchone()
            if conversation is None:
                raise JarvisChatDenied("conversation ownership or generation changed")
            active = db.execute(
                "SELECT 1 FROM turns WHERE conversation_id=? AND status IN ('queued','running') LIMIT 1",
                (conversation_id,)).fetchone()
            lock = db.execute(
                "SELECT 1 FROM model_selection_locks WHERE conversation_id=? AND owner=? "
                "AND core_generation=? AND expires>?",
                (conversation_id, owner, core_generation, _now())).fetchone()
        return "busy" if active or lock else "available"

    def rotate_heartbeat(self, subject: str, turn_id: str, nonce: str, principal: ChatPrincipal) -> str:
        owner = self._owner(subject)
        now = time.monotonic()
        expiry = min(now + MAX_LEASE_SECONDS, principal.expires_monotonic)
        if (expiry <= now or not ID_RE.fullmatch(turn_id or "")
                or not NONCE_RE.fullmatch(nonce or "")):
            raise JarvisChatDenied("protected chat heartbeat was denied")
        replacement = secrets.token_hex(32)
        with self._connect() as db:
            updated = db.execute("UPDATE turns SET heartbeat_nonce=?,"
                                 "heartbeat_expiry=MIN(?,jwt_expiry,?),"
                                 "jwt_expiry=MIN(jwt_expiry,?),updated=? "
                                 "WHERE id=? AND owner=? AND heartbeat_nonce=? AND status IN ('queued','running') "
                                 "AND heartbeat_expiry>? AND jwt_expiry>? AND core_generation=?",
                                 (replacement, expiry, principal.expires_monotonic,
                                  principal.expires_monotonic, _now(), turn_id, owner,
                                  nonce, now, now, principal.core_generation)).rowcount
        if updated != 1:
            raise JarvisChatDenied("protected chat heartbeat was denied")
        return replacement

    def owned_turn(self, subject: str, turn_id: str) -> sqlite3.Row:
        if not ID_RE.fullmatch(turn_id or ""):
            raise JarvisChatDenied("turn is unavailable")
        with self._connect() as db:
            row = db.execute("SELECT t.*,c.session_key FROM turns t JOIN conversations c ON c.id=t.conversation_id "
                             "WHERE t.id=? AND t.owner=? AND c.owner=?",
                             (turn_id, self._owner(subject), self._owner(subject))).fetchone()
        if row is None:
            raise JarvisChatDenied("turn is unavailable")
        return row

    def append_delta(self, turn_id: str, text: str) -> int:
        if not isinstance(text, str) or not text:
            return 0
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT partial,status,heartbeat_expiry,jwt_expiry FROM turns WHERE id=?",
                             (turn_id,)).fetchone()
            if (row is None or row["status"] not in _ACTIVE
                    or time.monotonic() >= min(row["heartbeat_expiry"], row["jwt_expiry"])):
                db.execute("ROLLBACK")
                return 0
            content = (row["partial"] + text)[:MAX_ASSISTANT_CHARS]
            if content == row["partial"]:
                db.execute("ROLLBACK")
                return 0
            sequence = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM turn_events WHERE turn_id=?",
                                  (turn_id,)).fetchone()[0]
            if sequence > MAX_EVENTS_PER_TURN:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("chat event bound exceeded")
            visible = text[:max(0, MAX_ASSISTANT_CHARS - len(row["partial"]))]
            db.execute("UPDATE turns SET partial=?,updated=? WHERE id=?", (content, _now(), turn_id))
            db.execute("INSERT INTO turn_events VALUES(?,?,?,?)",
                       (turn_id, sequence, "message.delta", json.dumps({"sequence": sequence, "text": visible})))
            db.execute("COMMIT")
        return sequence

    def append_turn_configuration(self, turn_id: str, configuration: dict[str, str]) -> int:
        """Persist the actual isolated-session readback before the native prompt is submitted."""
        required = {"provider", "modelId", "reasoningEffort", "reasoningEffortWire"}
        if (not isinstance(configuration, dict) or set(configuration) != required
                or any(not isinstance(value, str) for value in configuration.values())):
            raise JarvisChatDenied("per-message model readback is invalid")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT status,heartbeat_expiry,jwt_expiry FROM turns WHERE id=?",
                             (turn_id,)).fetchone()
            if (row is None or row["status"] not in _ACTIVE
                    or time.monotonic() >= min(row["heartbeat_expiry"], row["jwt_expiry"])):
                db.execute("ROLLBACK")
                raise JarvisChatDenied("per-message model readback arrived after its turn lease")
            sequence = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM turn_events WHERE turn_id=?",
                                  (turn_id,)).fetchone()[0]
            if sequence > MAX_EVENTS_PER_TURN:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("chat event bound exceeded")
            db.execute("INSERT INTO turn_events VALUES(?,?,?,?)",
                       (turn_id, sequence, "turn.configuration", json.dumps(configuration,
                        sort_keys=True, separators=(",", ":"))))
            db.execute("COMMIT")
        return sequence

    def finish_turn(self, turn_id: str, status: str, *, error_code: str = "") -> None:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("invalid terminal status")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT conversation_id,partial,status FROM turns WHERE id=?", (turn_id,)).fetchone()
            if row is None or row["status"] not in _ACTIVE:
                db.execute("ROLLBACK")
                return
            now = _now()
            terminal_event = {"completed": "turn.completed", "failed": "turn.failed", "cancelled": "turn.cancelled"}[status]
            sequence = db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM turn_events WHERE turn_id=?",
                                  (turn_id,)).fetchone()[0]
            if status == "completed":
                db.execute("INSERT INTO messages VALUES(?,?,?,?,?)",
                           (_opaque_id(), row["conversation_id"], "assistant", row["partial"], now))
                db.execute("INSERT INTO turn_events VALUES(?,?,?,?)",
                           (turn_id, sequence, "message.completed", "{}"))
                sequence += 1
            db.execute("INSERT INTO turn_events VALUES(?,?,?,?)", (turn_id, sequence, terminal_event, "{}"))
            db.execute("UPDATE turns SET status=?,error_code=?,heartbeat_nonce='',updated=? WHERE id=?",
                       (status, error_code, now, turn_id))
            db.execute("UPDATE conversations SET updated=? WHERE id=?", (now, row["conversation_id"]))
            db.execute("COMMIT")

    def events_after(self, subject: str, turn_id: str, sequence: int) -> tuple[list[sqlite3.Row], str, float]:
        row = self.owned_turn(subject, turn_id)
        with self._connect() as db:
            events = db.execute("SELECT sequence,name,data FROM turn_events WHERE turn_id=? AND sequence>? ORDER BY sequence LIMIT 256",
                                (turn_id, sequence)).fetchall()
        return events, row["status"], float(row["heartbeat_expiry"])

    def cancel_turn(self, subject: str, turn_id: str) -> sqlite3.Row:
        row = self.owned_turn(subject, turn_id)
        if row["status"] in _ACTIVE:
            self.finish_turn(turn_id, "cancelled")
        return row


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


async def _read_body(request, expected: set[str]) -> dict:
    from aiohttp import web
    if (request.content_type != "application/json" or request.content_length is None
            or request.content_length < 2 or request.content_length > MAX_BODY_BYTES
            or request.headers.get("Transfer-Encoding") is not None):
        raise web.HTTPBadRequest(text="invalid request")
    raw = await asyncio.wait_for(request.read(), timeout=1.5)
    if len(raw) > MAX_BODY_BYTES:
        raise web.HTTPBadRequest(text="invalid request")
    try:
        body = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError):
        raise web.HTTPBadRequest(text="invalid request") from None
    if not isinstance(body, dict) or set(body) != expected:
        raise web.HTTPBadRequest(text="invalid request")
    return body


def _secure_headers() -> dict[str, str]:
    return {"Cache-Control": "no-store", "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"}


class JarvisChatService:
    def __init__(self, store: JarvisChatStore, backend: OfficialChatBackend,
                 *, principal_from_request: Callable[[Any], ChatPrincipal],
                 owner_turn_register: Callable[..., str] | None = None):
        if not callable(principal_from_request):
            raise ValueError("typed, current ingress principal resolver is required")
        if owner_turn_register is not None and not callable(owner_turn_register):
            raise ValueError("typed root owner-turn registration callback is required")
        self.store, self.backend = store, backend
        from .jarvis_activity import JarvisActivityStore
        from .jarvis_files import JarvisFilesStore
        self.activity_store = JarvisActivityStore(store)
        self.files_store = JarvisFilesStore(store)
        self._principal_from_request = principal_from_request
        self._workers: dict[str, asyncio.Task] = {}
        self._worker_lock = asyncio.Lock()
        self._admission_lock = asyncio.Lock()
        self._resume_lock = asyncio.Lock()
        self._owner_turn_register = owner_turn_register
        self._owner_turn_handles: OrderedDict[str, str] = OrderedDict()

    @staticmethod
    def _normalize_mission_binding(mission_binding: Any | None) -> Any | None:
        if mission_binding is None:
            return None
        try:
            from .jarvis_mission_executor import MissionBinding
            if type(mission_binding) is not MissionBinding:
                raise ValueError
            normalized = MissionBinding.from_wire(mission_binding.to_wire())
            if type(normalized) is not MissionBinding:
                raise ValueError
            return normalized
        except Exception:
            raise JarvisChatDenied("approved mission turn binding is invalid") from None

    @staticmethod
    def _capture_owner_turn_context(request, mission_binding: Any | None = None
                                    ) -> tuple[str, Any, Any | None] | None:
        """Copy exact ingress proof and an optional approved mission binding for pre-submit."""
        mission_binding = JarvisChatService._normalize_mission_binding(mission_binding)
        try:
            accepted = request.get("core_ingress")
            values = request.headers.getall("Cf-Access-Jwt-Assertion", [])
            if (accepted is None or len(values) != 1 or not isinstance(values[0], str)
                    or not 1 <= len(values[0]) <= 16_384
                    or any(ord(char) < 0x20 for char in values[0])):
                return None
            return values[0], accepted, mission_binding
        except Exception:
            return None

    @staticmethod
    def _normalize_planning_context(planning_context: Any | None) -> Any | None:
        if planning_context is None:
            return None
        try:
            from .core_gateway_inspector import PlanningContext
            if type(planning_context) is not PlanningContext:
                raise ValueError
            normalized = PlanningContext.from_wire(planning_context.to_wire())
            if type(normalized) is not PlanningContext:
                raise ValueError
            return normalized
        except Exception:
            raise JarvisChatDenied("master planning context is invalid") from None

    def owner_turn_handle_for(self, principal: ChatPrincipal, turn_id: str) -> str | None:
        """Return a private process-local handle only to a trusted owner-bound server adapter."""
        if not isinstance(principal, ChatPrincipal):
            raise JarvisChatDenied("owner turn is unavailable")
        turn = self.store.owned_turn(principal.subject, turn_id)
        if turn["core_generation"] != principal.core_generation:
            raise JarvisChatDenied("owner turn is unavailable")
        return self._owner_turn_handles.get(turn_id)

    async def _ensure_current_runtime(self, request, principal: ChatPrincipal,
                                      conversation: sqlite3.Row) -> sqlite3.Row:
        async with self._resume_lock:
            current = self.store.get_conversation(principal.subject, conversation["id"])
            if current["core_generation"] == principal.core_generation:
                return current
            target_generation = principal.core_generation
            target_subject = principal.subject
            # A generation change invalidates every runtime id and any active run. Keep the exact
            # durable stored id; never substitute a new empty session for an unavailable transcript.
            self.store.fail_active_conversation_turns(current["id"])
            try:
                runtime_id = await self.backend.resume_session(current["session_key"])
            except Exception as error:
                _log_messages_failure("runtime_resume", error)
                raise
            principal = self._current(request)
            if (principal.subject != target_subject
                    or principal.core_generation != target_generation):
                raise JarvisChatDenied("core generation changed during resume")
            try:
                return self.store.update_runtime_session(
                    principal.subject, current["id"], current["core_generation"], runtime_id,
                    principal.core_generation)
            except Exception as error:
                _log_messages_failure("runtime_mapping", error)
                raise

    def install(self, app) -> None:
        """Add only finite core-backed Jarvis JSON/SSE routes to the guarded app."""
        from aiohttp import web
        app["jarvis_chat_service"] = self
        app.router.add_get("/chat/api/conversations", self.list_conversations)
        app.router.add_post("/chat/api/conversations", self.create_conversation)
        app.router.add_get("/chat/api/conversations/{conversation_id}/messages", self.messages)
        app.router.add_post("/chat/api/conversations/{conversation_id}/turns", self.begin_turn)
        app.router.add_get("/chat/api/turns/{turn_id}/events", self.events)
        app.router.add_post("/chat/api/turns/{turn_id}/stop", self.stop)
        app.router.add_post("/chat/api/heartbeat", self.heartbeat)
        from .jarvis_activity import install_jarvis_activity_routes
        install_jarvis_activity_routes(app, self)

    def _current(self, request) -> ChatPrincipal:
        try:
            principal = self._principal_from_request(request)
            if (not isinstance(principal, ChatPrincipal) or not isinstance(principal.subject, str)
                    or not 1 <= len(principal.subject) <= 512
                    or not isinstance(principal.core_generation, str)
                    or not 1 <= len(principal.core_generation) <= 256):
                raise ValueError
            if (not isinstance(principal.expires_monotonic, (int, float))
                    or not isinstance(principal.witness_expires_monotonic, (int, float))
                    or not math.isfinite(principal.expires_monotonic)
                    or not math.isfinite(principal.witness_expires_monotonic)
                    or min(principal.expires_monotonic, principal.witness_expires_monotonic)
                    <= time.monotonic()):
                raise ValueError
            return principal
        except Exception:
            raise JarvisChatDenied("protected core ingress is unavailable") from None

    async def list_conversations(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            conversations = self.store.list_conversations(principal.subject)
            self._current(request)
            return web.json_response({"conversations": conversations},
                                     headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None

    async def create_conversation(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            await _read_body(request, set())
            principal = self._current(request)
            backend_id, stored_id = await self.backend.create_session()
            principal = self._current(request)
            created = self.store.create_conversation(principal.subject, backend_id, stored_id,
                                                     principal.core_generation)
            self._current(request)
            return web.json_response({"conversation": created}, status=201, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="chat unavailable", headers=_secure_headers()) from None

    async def messages(self, request):
        from aiohttp import web
        phase = "principal"
        try:
            principal = self._current(request)
            phase = "conversation_lookup"
            conversation_id = request.match_info.get("conversation_id", "")
            conversation = self.store.get_conversation(principal.subject, conversation_id)
            # A per-call WebSocket disconnect detaches the Hermes session. Always resume by its
            # durable key and obtain history from that response; calling session.history on the
            # old runtime ID can return official error 4001 even when the core process generation
            # has not changed.
            async with self._resume_lock:
                current = self.store.get_conversation(principal.subject, conversation_id)
                if current["core_generation"] != principal.core_generation:
                    self.store.fail_active_conversation_turns(current["id"])
                target_generation, target_subject = principal.core_generation, principal.subject
                phase = "runtime_resume"
                runtime_id, history = await self.backend.resume_history(current["session_key"])
                phase = "runtime_resume_recheck"
                principal = self._current(request)
                if (principal.subject != target_subject
                        or principal.core_generation != target_generation):
                    raise JarvisChatDenied("core generation changed during resume")
                # A chat may be moved to Trash while the native history request is in
                # flight. Rejoin its live owner mapping before exposing the transcript.
                current = self.store.get_conversation(principal.subject, conversation_id)
                if (current["core_generation"] != target_generation
                        or current["backend_id"] != runtime_id):
                    phase = "runtime_mapping"
                    conversation = self.store.update_runtime_session(
                        principal.subject, current["id"], current["core_generation"], runtime_id,
                        target_generation)
                else:
                    conversation = current
            phase = "history_projection"
            self._current(request)
            projected = []
            total = 0
            for entry in reversed(history):
                content = entry.get("content") if isinstance(entry, dict) else None
                role = entry.get("role") if isinstance(entry, dict) else None
                if not isinstance(content, str) or role not in {"user", "assistant"}:
                    continue
                room = MAX_HISTORY_CHARS - total
                if room <= 0:
                    break
                content = content[-room:]
                total += len(content)
                created_at = entry.get("createdAt", 0)
                projected.append({"id": _opaque_id(), "role": role, "content": content,
                                  "createdAt": created_at if isinstance(created_at, (int, float)) else 0})
            projected.reverse()
            phase = "response"
            self._current(request)
            return web.json_response({"conversationId": conversation_id, "messages": projected},
                                     headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except Exception as error:
            _log_messages_failure(phase, error)
            raise

    async def begin_turn(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            body = await _read_body(request, {"text", "modelId", "reasoningEffort"})
            principal = self._current(request)
            keys = request.headers.getall("Idempotency-Key", [])
            if len(keys) != 1:
                raise ValueError
            key = keys[0]
            turn_configuration = None
            accepted_configuration = None
            if "modelId" in body or "reasoningEffort" in body:
                from .jarvis_model_catalog import CODEX_MODEL_EFFORTS, CODEX_SELECTABLE_MODELS
                from .jarvis_models import _native_status, _selection_ready, _verified_snapshot

                principal, _accepted, _launch, observation, verify_current = await _verified_snapshot(
                    request, self)
                native = await _native_status(self)
                verify_current()
                if not _selection_ready(observation.projection, native):
                    raise web.HTTPConflict(text="model selection unavailable", headers=_secure_headers())
                conversation_id = request.match_info.get("conversation_id", "")
                conversation = self.store.get_conversation(principal.subject, conversation_id)
                current_default = self.store.latest_model_selection(
                    principal.subject, conversation_id, principal.core_generation,
                    conversation["backend_id"])
                profile_model = observation.projection.get("model")
                selected_default = (current_default.get("model") if current_default
                                    and current_default.get("state") in {
                                        "selected-for-session", "deferred-next-turn"}
                                    else profile_model)
                requested_model = body.get("modelId")
                requested_effort = body.get("reasoningEffort")
                if (requested_model is not None and
                        (not isinstance(requested_model, str)
                         or requested_model not in CODEX_SELECTABLE_MODELS)):
                    raise web.HTTPBadRequest(text="invalid model selection", headers=_secure_headers())
                if requested_effort is not None and (
                        not isinstance(requested_effort, str)
                        or requested_effort not in CODEX_MODEL_EFFORTS.get(
                            requested_model or selected_default, ())):
                    raise web.HTTPBadRequest(text="invalid reasoning effort", headers=_secure_headers())
                resolved_model = requested_model or selected_default
                if resolved_model not in CODEX_MODEL_EFFORTS:
                    raise web.HTTPConflict(text="profile model is outside the selectable Codex catalog",
                                           headers=_secure_headers())
                turn_configuration = {"model_id": resolved_model,
                                      "reasoning_effort": requested_effort}
                accepted_configuration = {"state": "queued", "modelId": resolved_model,
                                          "reasoningEffort": requested_effort}
                verify_current()
            queued = await self.start_server_turn(
                request, conversation_id=request.match_info.get("conversation_id", ""),
                text=body["text"], idempotency_key=key,
                turn_configuration=turn_configuration)
            self._current(request)
            payload = {"turnId": queued["turn_id"], "status": "queued",
                       "heartbeatNonce": queued["heartbeat_nonce"]}
            if accepted_configuration is not None:
                payload["turnConfiguration"] = accepted_configuration
            return web.json_response(payload,
                                     status=202, headers=_secure_headers())
        except web.HTTPException:
            raise
        except RuntimeError:
            raise web.HTTPTooManyRequests(text='{"error":{"code":"busy"}}',
                                          content_type="application/json", headers=_secure_headers()) from None
        except ValueError:
            raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers()) from None
        except JarvisChatDenied:
            raise web.HTTPConflict(text='{"error":{"code":"replay_or_unavailable"}}',
                                   content_type="application/json", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="chat unavailable", headers=_secure_headers()) from None

    async def start_server_turn(self, request, *, conversation_id: str, text: str,
                                idempotency_key: str, before_schedule=None,
                                on_schedule_failure=None,
                                mission_binding: Any | None = None,
                                require_mission_binding: bool = False,
                                planning_context: Any | None = None,
                                require_planning_context: bool = False,
                                turn_configuration: dict[str, Any] | None = None) -> dict[str, str]:
        """Queue one protected turn from a trusted server feature, before any native submit.

        ``before_schedule`` is an internal durable mapping hook, not an authorization source. It
        runs after the owner-bound turn is reserved and before its worker can call ``prompt.submit``.
        Any mapping/currentness failure terminalizes the reservation and never schedules a worker.
        """
        mission_binding = self._normalize_mission_binding(mission_binding)
        planning_context = self._normalize_planning_context(planning_context)
        if type(require_mission_binding) is not bool:
            raise JarvisChatDenied("mission binding requirement is invalid")
        if type(require_planning_context) is not bool:
            raise JarvisChatDenied("planning context requirement is invalid")
        if ((require_planning_context and planning_context is None)
                or (planning_context is not None and
                    (mission_binding is not None or require_mission_binding))):
            raise JarvisChatDenied("master planning turn purpose is invalid")
        async with self._admission_lock:
            principal = self._current(request)
            conversation = self.store.get_conversation(principal.subject, conversation_id)
            conversation = await self._ensure_current_runtime(request, principal, conversation)
            principal = self._current(request)
            turn_id, nonce, conversation = self.store.begin_turn(
                principal.subject, conversation_id, text, idempotency_key, principal,
                turn_configuration=turn_configuration)
            try:
                if (require_mission_binding or mission_binding is not None
                        or planning_context is not None) and before_schedule is None:
                    raise JarvisChatDenied("mission intent must be bound before scheduling")
                if before_schedule is not None:
                    if not callable(before_schedule):
                        raise JarvisChatDenied("server turn mapping is invalid")
                    outcome = before_schedule(turn_id)
                    if inspect.isawaitable(outcome):
                        outcome = await outcome
                    if outcome is not None:
                        outcome = self._normalize_mission_binding(outcome)
                        if mission_binding is not None and outcome != mission_binding:
                            raise JarvisChatDenied("mission turn binding changed before scheduling")
                        mission_binding = outcome
                if planning_context is not None and mission_binding is not None:
                    raise JarvisChatDenied("planning and execution turn purposes cannot be combined")
                if require_mission_binding and mission_binding is None:
                    raise JarvisChatDenied("approved mission binding is unavailable")
                if mission_binding is not None or planning_context is not None:
                    if self._owner_turn_register is None:
                        raise JarvisChatDenied("mission owner-turn verification is unavailable")
                    owner_turn_context = self._capture_owner_turn_context(request, mission_binding)
                    if owner_turn_context is None:
                        raise JarvisChatDenied("mission owner-turn verification is unavailable")
                else:
                    owner_turn_context = (self._capture_owner_turn_context(request)
                                          if self._owner_turn_register is not None else None)
                current = self._current(request)
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation):
                    raise JarvisChatDenied("protected core turn changed before scheduling")
                def current_principal_check() -> ChatPrincipal:
                    # The stream worker outlives this handler. Keep only a narrow
                    # currentness callback, rather than reaching for an implicit
                    # request variable from inside the worker.
                    return self._current(request)

                async with self._worker_lock:
                    task = asyncio.create_task(self._run(
                        turn_id, conversation["backend_id"], text, principal, conversation_id,
                        stored_session_id=conversation["session_key"],
                        current_principal_check=current_principal_check,
                        owner_turn_context=owner_turn_context,
                        require_mission_binding=require_mission_binding,
                        planning_context=planning_context,
                        require_planning_context=require_planning_context,
                        turn_configuration=turn_configuration))
                    self._workers[turn_id] = task
            except BaseException:
                if on_schedule_failure is not None:
                    try:
                        if not callable(on_schedule_failure):
                            raise JarvisChatDenied("server turn compensation is invalid")
                        outcome = on_schedule_failure(turn_id)
                        if inspect.isawaitable(outcome):
                            await outcome
                    except BaseException:
                        # The turn still must not be scheduled; compensation is best effort and
                        # must not replace the scheduling/currentness exception.
                        pass
                self.store.finish_turn(turn_id, "cancelled", error_code="server_turn_not_scheduled")
                raise
        return {"turn_id": turn_id, "status": "queued", "heartbeat_nonce": nonce}

    async def _run(self, turn_id: str, session_id: str, text: str,
                   activity_principal: ChatPrincipal | None = None,
                   conversation_id: str = "", *, stored_session_id: str = "",
                   current_principal_check: Callable[[], ChatPrincipal] | None = None,
                   owner_turn_context: tuple[str, Any, Any | None] | None = None,
                   require_mission_binding: bool = False,
                   planning_context: Any | None = None,
                   require_planning_context: bool = False,
                   turn_configuration: dict[str, Any] | None = None):
        total = 0
        next_delta: asyncio.Task | None = None
        stream = None
        turn_deadline = time.monotonic() + MAX_TURN_SECONDS
        try:
            with self.store._connect() as db:
                db.execute("UPDATE turns SET status='running',updated=? WHERE id=? AND status='queued'",
                           (_now(), turn_id))
            if activity_principal is not None and conversation_id and planning_context is None:
                refs = self.files_store.claim_pending(
                    subject=activity_principal.subject, conversation_id=conversation_id,
                    turn_id=turn_id, core_generation=activity_principal.core_generation)
                if refs:
                    text = text + "\n\n" + "\n".join(refs)
            resume_stream = getattr(self.backend, "stream_owned_turn", None)
            if require_mission_binding and not callable(resume_stream):
                raise JarvisChatDenied("owned mission turn adapter is unavailable")
            if require_mission_binding and (owner_turn_context is None
                                            or owner_turn_context[2] is None
                                            or self._owner_turn_register is None):
                raise JarvisChatDenied("mission owner-turn verification is unavailable")
            if planning_context is not None or require_planning_context:
                planning_context = self._normalize_planning_context(planning_context)
                if (planning_context is None or owner_turn_context is None
                        or self._owner_turn_register is None or not callable(resume_stream)
                        or planning_context.planner_prompt_sha256 != hashlib.sha256(
                            text.encode("utf-8", errors="strict")).hexdigest()):
                    raise JarvisChatDenied("master planning owner-turn verification is unavailable")
            if callable(resume_stream):
                if (activity_principal is None or not conversation_id
                        or not _valid_core_session_id(stored_session_id)):
                    raise JarvisChatDenied("owned core turn mapping is unavailable")

                async def bind_resumed_session(actual_session_id: str) -> None:
                    nonlocal session_id
                    self.store.rebind_active_turn_session(
                        activity_principal, conversation_id, turn_id, session_id, actual_session_id)
                    session_id = actual_session_id
                    if self._owner_turn_register is not None and owner_turn_context is not None:
                        access_jwt, accepted_ingress, mission_binding = owner_turn_context
                        try:
                            registration = {
                                "access_jwt": access_jwt,
                                "accepted_ingress": accepted_ingress,
                                "session_id": actual_session_id,
                                "conversation_id": conversation_id,
                                "gateway_turn_id": turn_id,
                                "prompt_sha256": hashlib.sha256(
                                    text.encode("utf-8", errors="strict")).hexdigest(),
                            }
                            if mission_binding is not None:
                                registration["mission_binding"] = mission_binding
                            if planning_context is not None:
                                registration["planning_context"] = planning_context
                            owner_handle = await asyncio.wait_for(asyncio.to_thread(
                                self._owner_turn_register, **registration), timeout=5.0)
                            valid_handle = (isinstance(owner_handle, str)
                                            and re.fullmatch(r"[0-9a-f]{32}", owner_handle))
                            if (mission_binding is not None or planning_context is not None) and not valid_handle:
                                raise JarvisChatDenied("mission owner-turn verification was not confirmed")
                            if valid_handle:
                                if len(self._owner_turn_handles) >= MAX_OWNER_TURN_HANDLES:
                                    self._owner_turn_handles.popitem(last=False)
                                self._owner_turn_handles[turn_id] = owner_handle
                        except Exception:
                            # Ordinary chat stays useful without an optional observer, but a
                            # planning or mission turn cannot run unless root bound its exact claim.
                            if mission_binding is not None or planning_context is not None:
                                raise JarvisChatDenied(
                                    "mission owner-turn verification is unavailable") from None

                async def bind_isolated_session(actual_session_id: str,
                                                actual_stored_session_id: str) -> bool:
                    nonlocal session_id
                    if not callable(current_principal_check):
                        raise JarvisChatDenied("per-message currentness check is unavailable")
                    latest = current_principal_check()
                    if (latest.subject != activity_principal.subject
                            or latest.core_generation != activity_principal.core_generation):
                        raise JarvisChatDenied("per-message turn ownership changed")
                    original_runtime_id = session_id

                    def rollback_unsubmitted_mapping() -> None:
                        self._owner_turn_handles.pop(turn_id, None)
                        try:
                            self.store.restore_unsubmitted_turn_session(
                                activity_principal, conversation_id, turn_id,
                                actual_session_id, actual_stored_session_id,
                                original_runtime_id, stored_session_id)
                        except Exception:
                            # Keep the stale-turn denial primary. The store's exact CAS
                            # prevents compensation from overwriting a newer mapping.
                            pass

                    self.store.rebind_active_turn_session(
                        activity_principal, conversation_id, turn_id, session_id,
                        actual_session_id, stored_session_id=actual_stored_session_id)
                    session_id = actual_session_id
                    # Per-message model turns run in a branched stored session. Register
                    # that exact session with root before prompt.submit so the native
                    # llm_request middleware can attach current project context there too.
                    if self._owner_turn_register is not None and owner_turn_context is not None:
                        access_jwt, accepted_ingress, mission_binding = owner_turn_context
                        try:
                            registration = {
                                "access_jwt": access_jwt,
                                "accepted_ingress": accepted_ingress,
                                "session_id": actual_session_id,
                                "conversation_id": conversation_id,
                                "gateway_turn_id": turn_id,
                                "prompt_sha256": hashlib.sha256(
                                    text.encode("utf-8", errors="strict")).hexdigest(),
                            }
                            if mission_binding is not None:
                                registration["mission_binding"] = mission_binding
                            if planning_context is not None:
                                registration["planning_context"] = planning_context
                            owner_handle = await asyncio.wait_for(asyncio.to_thread(
                                self._owner_turn_register, **registration), timeout=5.0)
                            valid_handle = (isinstance(owner_handle, str)
                                            and re.fullmatch(r"[0-9a-f]{32}", owner_handle))
                            if (mission_binding is not None or planning_context is not None) and not valid_handle:
                                raise JarvisChatDenied("mission owner-turn verification was not confirmed")
                            if valid_handle:
                                if len(self._owner_turn_handles) >= MAX_OWNER_TURN_HANDLES:
                                    self._owner_turn_handles.popitem(last=False)
                                self._owner_turn_handles[turn_id] = owner_handle
                        except Exception:
                            if mission_binding is not None or planning_context is not None:
                                rollback_unsubmitted_mapping()
                                raise JarvisChatDenied(
                                    "mission owner-turn verification is unavailable") from None
                    # Root registration is synchronous authority work from the stream's
                    # point of view. Recheck after it too, immediately before Core resumes
                    # the same socket and sends prompt.submit.
                    try:
                        latest = current_principal_check()
                    except Exception:
                        rollback_unsubmitted_mapping()
                        raise
                    if (latest.subject != activity_principal.subject
                            or latest.core_generation != activity_principal.core_generation):
                        rollback_unsubmitted_mapping()
                        raise JarvisChatDenied("per-message turn ownership changed before submit")
                    return True

                if turn_configuration is not None:
                    stream = resume_stream(
                        stored_session_id, text,
                        isolated_model_id=turn_configuration["model_id"],
                        isolated_reasoning_effort=turn_configuration["reasoning_effort"],
                        on_isolated_session=bind_isolated_session).__aiter__()
                else:
                    stream = resume_stream(stored_session_id, text,
                                          before_submit=bind_resumed_session).__aiter__()
            else:
                # Compatibility for deterministic/fake adapters only. CoreRpcClient exposes the
                # explicit owned-turn capability above, which always resumes on its submit socket.
                stream = self.backend.stream(session_id, text).__aiter__()
            next_delta = asyncio.create_task(stream.__anext__())
            terminal_received = False
            while True:
                done, _pending = await asyncio.wait({next_delta}, timeout=0.25)
                with self.store._connect() as db:
                    lease = db.execute("SELECT status,heartbeat_expiry,jwt_expiry FROM turns WHERE id=?",
                                       (turn_id,)).fetchone()
                if (lease is None or lease["status"] not in _ACTIVE
                        or time.monotonic() >= min(lease["heartbeat_expiry"], lease["jwt_expiry"])
                        or time.monotonic() >= turn_deadline):
                    next_delta.cancel()
                    await asyncio.gather(next_delta, return_exceptions=True)
                    if lease is not None and lease["status"] in _ACTIVE:
                        await self.backend.stop(session_id)
                        self.store.finish_turn(turn_id, "cancelled")
                    return
                if not done:
                    continue
                try:
                    item = next_delta.result()
                except StopAsyncIteration:
                    break
                kind = getattr(item, "kind", None)
                if kind == "activity":
                    observation = getattr(item, "activity", None)
                    if activity_principal is not None and conversation_id:
                        try:
                            self.activity_store.record_core_event(
                                principal=activity_principal, conversation_id=conversation_id,
                                turn_id=turn_id, core_generation=activity_principal.core_generation,
                                event=observation)
                        except JarvisChatDenied:
                            # Activity is an observational projection; it cannot change the chat turn.
                            pass
                        except Exception:
                            pass
                elif kind == "configuration":
                    configuration = getattr(item, "configuration", None)
                    if not isinstance(configuration, dict):
                        raise JarvisChatDenied("per-message model readback was missing")
                    self.store.append_turn_configuration(turn_id, configuration)
                elif kind == "delta":
                    delta = getattr(item, "text", "")
                    if isinstance(delta, str):
                        room = MAX_ASSISTANT_CHARS - total
                        if room > 0:
                            delta = delta[:room]
                            total += len(delta)
                            if not self.store.append_delta(turn_id, delta):
                                self.store.finish_turn(turn_id, "cancelled")
                                await self.backend.stop(session_id)
                                return
                elif kind in {"complete", "failed", "cancelled"}:
                    terminal_received = True
                    status = {"complete": "completed", "failed": "failed", "cancelled": "cancelled"}[kind]
                    self.store.finish_turn(turn_id, status,
                                           error_code="backend_unavailable" if status == "failed" else "")
                    return
                next_delta = asyncio.create_task(stream.__anext__())
            if not terminal_received:
                raise JarvisChatDenied("official core stream ended without completion")
        except asyncio.CancelledError:
            if next_delta is not None:
                next_delta.cancel()
                await asyncio.gather(next_delta, return_exceptions=True)
            try:
                await self.backend.stop(session_id)
            except Exception:
                pass
            self.store.finish_turn(turn_id, "cancelled")
            raise
        except Exception:
            try:
                await self.backend.stop(session_id)
            except Exception:
                pass
            self.store.finish_turn(turn_id, "failed", error_code="backend_unavailable")
        finally:
            if next_delta is not None:
                if not next_delta.done():
                    next_delta.cancel()
                await asyncio.gather(next_delta, return_exceptions=True)
            try:
                if stream is not None:
                    close = getattr(stream, "aclose", None)
                    if close is not None:
                        try:
                            await close()
                        except (asyncio.CancelledError, Exception):
                            pass
            finally:
                self._workers.pop(turn_id, None)

    async def heartbeat(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            body = await _read_body(request, {"turnId", "nonce"})
            turn_id, nonce = body["turnId"], body["nonce"]
            if not isinstance(turn_id, str) or not isinstance(nonce, str):
                raise ValueError
            principal = self._current(request)
            replacement = self.store.rotate_heartbeat(principal.subject, turn_id, nonce, principal)
            self._current(request)
            return web.json_response({"turnId": turn_id, "nonce": replacement}, headers=_secure_headers())
        except web.HTTPException:
            raise
        except (ValueError, JarvisChatDenied):
            raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None

    async def events(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            turn_id = request.match_info.get("turn_id", "")
            cursor_text = request.headers.get("Last-Event-ID", "0")
            if not cursor_text.isdigit() or len(cursor_text) > 8:
                raise JarvisChatDenied("event cursor is invalid")
            cursor = int(cursor_text)
            turn = self.store.owned_turn(principal.subject, turn_id)
            if turn["core_generation"] != principal.core_generation and turn["status"] in _ACTIVE:
                self.store.finish_turn(turn_id, "failed", error_code="core_generation_changed")
            response = web.StreamResponse(status=200, headers={**_secure_headers(),
                                         "Content-Type": "text/event-stream", "X-Accel-Buffering": "no"})
            self._current(request)
            await response.prepare(request)
            terminal = False
            # An ingress observation belongs to this HTTP request and cannot be refreshed
            # from inside its response. End the transport while that observation is still
            # current; EventSource reconnects with Last-Event-ID through fresh middleware.
            # This deadline is transport-only. The separately issued turn lease and original
            # JWT deadline continue to govern the owned worker.
            witness_cutoff = principal.witness_expires_monotonic - 0.05
            stream_deadline = min(time.monotonic() + SSE_CONNECTION_SECONDS, witness_cutoff)
            while not terminal and time.monotonic() < stream_deadline:
                # The long-lived response is authorized by the separately refreshed nonce lease.
                # Each heartbeat passes fresh JWT+Unix ingress middleware and atomically rotates
                # this turn's owner-bound lease.
                rows, status, lease_expiry = self.store.events_after(principal.subject, turn_id, cursor)
                if time.monotonic() >= lease_expiry and status in _ACTIVE:
                    worker = self._workers.get(turn_id)
                    if worker is not None:
                        worker.cancel()
                    self.store.finish_turn(turn_id, "cancelled")
                    rows, status, _ = self.store.events_after(principal.subject, turn_id, cursor)
                for row in rows:
                    if time.monotonic() >= stream_deadline:
                        terminal = True
                        break
                    cursor = row["sequence"]
                    name = row["name"]
                    payload = row["data"]
                    if name not in {"message.delta", "message.completed", "turn.completed", "turn.failed",
                                    "turn.cancelled", "turn.configuration", "activity.event"}:
                        continue
                    try:
                        self._current(request)
                    except JarvisChatDenied:
                        # A request-local witness expiring only closes this SSE segment. A
                        # newly accepted reconnect obtains its own witness. JWT expiry still
                        # cancels the exact turn; an earlier currentness failure cancels it.
                        now = time.monotonic()
                        if (now >= principal.witness_expires_monotonic
                                and now < principal.expires_monotonic):
                            terminal = True
                            break
                        worker = self._workers.get(turn_id)
                        if worker is not None:
                            worker.cancel()
                        self.store.finish_turn(turn_id, "cancelled")
                        terminal = True
                        break
                    try:
                        self._current(request)
                        await response.write(f"id: {cursor}\nevent: {name}\ndata: {payload}\n\n".encode())
                    except JarvisChatDenied:
                        now = time.monotonic()
                        if (now >= principal.witness_expires_monotonic
                                and now < principal.expires_monotonic):
                            terminal = True
                            break
                        worker = self._workers.get(turn_id)
                        if worker is not None:
                            worker.cancel()
                        self.store.finish_turn(turn_id, "cancelled")
                        terminal = True
                        break
                    terminal = name in {"turn.completed", "turn.failed", "turn.cancelled"}
                if status not in _ACTIVE and not rows:
                    terminal = True
                if not terminal and time.monotonic() < stream_deadline:
                    await asyncio.sleep(min(0.2, max(0.0, stream_deadline - time.monotonic())))
            # The <=5 second ingress witness can expire during the segment. Do not write even
            # the terminating chunk unless the same sealed proof is still current.
            try:
                self._current(request)
                await response.write_eof()
            except JarvisChatDenied:
                transport = request.transport
                if transport is not None:
                    transport.close()
            return response
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            # No upstream body or detail escapes when the owner/currentness check fails.
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except (ConnectionResetError, asyncio.CancelledError):
            raise
        except Exception:
            raise web.HTTPServiceUnavailable(text="chat unavailable", headers=_secure_headers()) from None

    async def stop(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            await _read_body(request, set())
            principal = self._current(request)
            turn_id = request.match_info.get("turn_id", "")
            row = self.store.owned_turn(principal.subject, turn_id)
            if row["core_generation"] == principal.core_generation and row["status"] in _ACTIVE:
                worker = self._workers.get(turn_id)
                if worker is not None:
                    # _run owns the upstream stream and closes it on cancellation.
                    worker.cancel()
                    await asyncio.gather(worker, return_exceptions=True)
                else:
                    await self.backend.stop(row["runtime_session_id"])
            self.store.cancel_turn(principal.subject, turn_id)
            worker = self._workers.get(turn_id)
            if worker is not None:
                worker.cancel()
            self._current(request)
            return web.json_response({"turnId": turn_id, "status": "cancelled"}, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="chat unavailable", headers=_secure_headers()) from None


def install_jarvis_chat_routes(app, service: JarvisChatService) -> None:
    """Public helper imported by the manual stage app composition owner."""
    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    service.install(app)


def build_jarvis_chat_service(principal_from_request: Callable[[Any], ChatPrincipal], *,
                              owner_turn_register: Callable[..., str] | None = None) -> JarvisChatService:
    """Build the one fixed Jarvis store/core client for the protected Unix gateway service."""
    if not callable(principal_from_request):
        raise ValueError("verified core-ingress principal resolver is required")
    from .core_client import CoreRpcClient
    return JarvisChatService(
        JarvisChatStore(CHAT_STORE_PATH, owner_uid=os.geteuid()), CoreRpcClient(),
        principal_from_request=principal_from_request,
        owner_turn_register=owner_turn_register)
