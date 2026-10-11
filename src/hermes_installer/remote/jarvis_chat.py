"""Finite, principal-owned Jarvis chat adapter over official Hermes core TUI RPC.

The public surface never exposes Hermes runtime/stored session IDs, backend credentials, or a
generic RPC method. Principal and service currentness are supplied by the protected Unix ingress
composition; family tool/memory isolation remains a separate, unavailable capability.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import sqlite3
import stat
import time
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
CHAT_STATE_DIRECTORY = Path("/var/lib/hermes-jarvis-chat")
CHAT_STORE_PATH = CHAT_STATE_DIRECTORY / "chat.sqlite3"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
NONCE_RE = re.compile(r"^[0-9a-f]{64}$")
_ACTIVE = ("queued", "running")


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
    async def history(self, session_id: str) -> list[dict[str, Any]]: ...
    def stream(self, session_id: str, text: str) -> AsyncIterator[Any]: ...
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
            rows = db.execute("SELECT id,title,updated FROM conversations WHERE owner=? ORDER BY updated DESC LIMIT 100",
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
                   principal: ChatPrincipal) -> tuple[str, str, sqlite3.Row]:
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
        key_hash, text_hash = _digest(owner + ":" + idempotency_key), _digest(text)
        wall = _now()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                existing = db.execute("SELECT id,request_hash FROM turns WHERE owner=? AND idempotency_hash=?",
                                      (owner, key_hash)).fetchone()
                if existing:
                    if existing["request_hash"] != text_hash:
                        raise JarvisChatDenied("idempotency key was already used")
                    raise JarvisChatDenied("turn request replay was denied")
                active = db.execute("SELECT COUNT(*) FROM turns WHERE status IN ('queued','running')").fetchone()[0]
                active_conversation = db.execute(
                    "SELECT COUNT(*) FROM turns WHERE conversation_id=? AND status IN ('queued','running')",
                    (conversation_id,)).fetchone()[0]
                if (active >= self.max_active_turns
                        or active_conversation >= MAX_ACTIVE_TURNS_PER_CONVERSATION):
                    raise RuntimeError("busy")
                db.execute("INSERT INTO turns(id,owner,conversation_id,idempotency_hash,request_hash,status,heartbeat_nonce,heartbeat_expiry,jwt_expiry,runtime_session_id,core_generation,created,updated) VALUES(?,?,?,?,?,'queued',?,?,?,?,?,?,?)",
                           (turn_id, owner, conversation_id, key_hash, text_hash, nonce, expiry,
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
                 *, principal_from_request: Callable[[Any], ChatPrincipal]):
        if not callable(principal_from_request):
            raise ValueError("typed, current ingress principal resolver is required")
        self.store, self.backend = store, backend
        self._principal_from_request = principal_from_request
        self._workers: dict[str, asyncio.Task] = {}
        self._worker_lock = asyncio.Lock()
        self._resume_lock = asyncio.Lock()

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
            runtime_id = await self.backend.resume_session(current["session_key"])
            principal = self._current(request)
            if (principal.subject != target_subject
                    or principal.core_generation != target_generation):
                raise JarvisChatDenied("core generation changed during resume")
            return self.store.update_runtime_session(
                principal.subject, current["id"], current["core_generation"], runtime_id,
                principal.core_generation)

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
        try:
            principal = self._current(request)
            conversation_id = request.match_info.get("conversation_id", "")
            conversation = self.store.get_conversation(principal.subject, conversation_id)
            conversation = await self._ensure_current_runtime(request, principal, conversation)
            self._current(request)
            history = await self.backend.history(conversation["backend_id"])
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
            self._current(request)
            return web.json_response({"conversationId": conversation_id, "messages": projected},
                                     headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None

    async def begin_turn(self, request):
        from aiohttp import web
        try:
            principal = self._current(request)
            body = await _read_body(request, {"text"})
            principal = self._current(request)
            keys = request.headers.getall("Idempotency-Key", [])
            if len(keys) != 1:
                raise ValueError
            key = keys[0]
            conversation = self.store.get_conversation(
                principal.subject, request.match_info.get("conversation_id", ""))
            conversation = await self._ensure_current_runtime(request, principal, conversation)
            principal = self._current(request)
            turn_id, nonce, conversation = self.store.begin_turn(
                principal.subject, request.match_info.get("conversation_id", ""), body["text"], key, principal)
            async with self._worker_lock:
                task = asyncio.create_task(self._run(turn_id, conversation["backend_id"], body["text"]))
                self._workers[turn_id] = task
            self._current(request)
            return web.json_response({"turnId": turn_id, "status": "queued", "heartbeatNonce": nonce},
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

    async def _run(self, turn_id: str, session_id: str, text: str):
        total = 0
        next_delta: asyncio.Task | None = None
        stream = None
        turn_deadline = time.monotonic() + MAX_TURN_SECONDS
        try:
            with self.store._connect() as db:
                db.execute("UPDATE turns SET status='running',updated=? WHERE id=? AND status='queued'",
                           (_now(), turn_id))
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
                if kind == "delta":
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
            stream_deadline = time.monotonic() + SSE_CONNECTION_SECONDS
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
                    if name not in {"message.delta", "message.completed", "turn.completed", "turn.failed", "turn.cancelled"}:
                        continue
                    try:
                        self._current(request)
                    except JarvisChatDenied:
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


def build_jarvis_chat_service(principal_from_request: Callable[[Any], ChatPrincipal]) -> JarvisChatService:
    """Build the one fixed Jarvis store/core client for the protected Unix gateway service."""
    if not callable(principal_from_request):
        raise ValueError("verified core-ingress principal resolver is required")
    from .core_client import CoreRpcClient
    return JarvisChatService(
        JarvisChatStore(CHAT_STORE_PATH, owner_uid=os.geteuid()), CoreRpcClient(),
        principal_from_request=principal_from_request)
