"""Owner-bound text-file staging through Hermes' finite native file.attach RPC.

Hermes exposes no TUI-gateway file listing, read, preview, or download method. This
adapter only accepts small text uploads, stages them in the selected owner's existing
conversation session, and retains a closed metadata receipt plus private @file reference
for that conversation's next authorized turn.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import json
import re
import sqlite3
import time
import unicodedata
from typing import Any

from .jarvis_chat import (
    IDEMPOTENCY_RE,
    ID_RE,
    JarvisChatDenied,
    _opaque_id,
    _secure_headers,
    _unique_pairs,
)

FEATURE_ROUTES = (
    ("GET", "/chat/api/conversations"),
    ("GET", "/chat/api/conversations/{conversation_id}/files"),
    ("POST", "/chat/api/conversations/{conversation_id}/files"),
)

MAX_FILE_BYTES = 128 * 1024
MAX_FILE_BODY_BYTES = 180 * 1024
MAX_STAGED_FILES = 5
MAX_STAGED_BYTES = MAX_FILE_BYTES * MAX_STAGED_FILES
MAX_FILE_ROWS = 100
MAX_OWNER_FILE_ROWS = 500
_MEDIA_TYPES = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".csv": "text/csv",
    ".json": "application/json",
}
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$")


class JarvisFileDenied(JarvisChatDenied):
    """A bounded attachment request or native staging attempt was not accepted."""


def _initialize(store: Any) -> None:
    with store._connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS jarvis_files (
          id TEXT PRIMARY KEY,
          owner TEXT NOT NULL,
          conversation_id TEXT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
          core_generation TEXT NOT NULL,
          idempotency_hash TEXT NOT NULL,
          request_hash TEXT NOT NULL,
          name TEXT NOT NULL,
          mime_type TEXT NOT NULL,
          size_bytes INTEGER NOT NULL CHECK(size_bytes > 0),
          sha256 TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('processing','staged','used','unavailable')),
          ref_text TEXT NOT NULL DEFAULT '',
          turn_id TEXT REFERENCES turns(id),
          created REAL NOT NULL,
          updated REAL NOT NULL,
          UNIQUE(owner,idempotency_hash)
        )""")
        db.execute("CREATE INDEX IF NOT EXISTS jarvis_file_conversation "
                   "ON jarvis_files(owner,conversation_id,created DESC)")
        # A process may have died while the native response was uncertain. Never repeat the
        # non-idempotent upstream side effect; present the old attempt as unavailable.
        db.execute("UPDATE jarvis_files SET state='unavailable',ref_text='',updated=? "
                   "WHERE state='processing'", (time.time(),))


def _view(row: sqlite3.Row) -> dict[str, Any]:
    state = {"staged": "ready", "used": "attached", "processing": "pending",
             "unavailable": "unavailable"}[row["state"]]
    return {
        "id": row["id"],
        "name": row["name"],
        "mime_type": row["mime_type"],
        "size_bytes": row["size_bytes"],
        "sha256": row["sha256"],
        "state": state,
        "created_at": row["created"],
    }


class JarvisFilesStore:
    """Private metadata and one-shot next-turn references sharing the chat DB custody."""

    def __init__(self, chat_store: Any):
        if not callable(getattr(chat_store, "_connect", None)):
            raise TypeError("protected Jarvis chat store required")
        self._chat_store = chat_store
        _initialize(chat_store)

    def reserve(self, *, subject: str, conversation_id: str, core_generation: str,
                idempotency_key: str, name: str, mime_type: str, content: bytes) -> tuple[dict[str, Any], bool]:
        owner = self._chat_store._owner(subject)
        conversation = self._chat_store.get_conversation(subject, conversation_id)
        if conversation["core_generation"] != core_generation:
            raise JarvisFileDenied("conversation generation changed")
        digest = hashlib.sha256(content).hexdigest()
        request_hash = hashlib.sha256("\0".join((conversation_id, name, mime_type, digest)).encode()).hexdigest()
        key_hash = hashlib.sha256((owner + ":" + idempotency_key).encode()).hexdigest()
        now = time.time()
        with self._chat_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                "SELECT c.owner,c.core_generation FROM conversations c WHERE c.id=?", (conversation_id,)
            ).fetchone()
            if current is None or current["owner"] != owner:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("conversation is unavailable")
            if current["core_generation"] != core_generation:
                db.execute("ROLLBACK")
                raise JarvisFileDenied("conversation generation changed")
            existing = db.execute(
                "SELECT * FROM jarvis_files WHERE owner=? AND idempotency_hash=?", (owner, key_hash)
            ).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    db.execute("ROLLBACK")
                    raise JarvisFileDenied("idempotency key was already used")
                db.execute("COMMIT")
                return _view(existing), False
            active = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(size_bytes),0) FROM jarvis_files "
                "WHERE owner=? AND conversation_id=? AND state IN ('processing','staged')",
                (owner, conversation_id),
            ).fetchone()
            row_count = db.execute(
                "SELECT COUNT(*) FROM jarvis_files WHERE owner=? AND conversation_id=?",
                (owner, conversation_id),
            ).fetchone()[0]
            owner_count = db.execute(
                "SELECT COUNT(*) FROM jarvis_files WHERE owner=?", (owner,)
            ).fetchone()[0]
            if (active[0] >= MAX_STAGED_FILES or active[1] + len(content) > MAX_STAGED_BYTES
                    or row_count >= MAX_FILE_ROWS or owner_count >= MAX_OWNER_FILE_ROWS):
                db.execute("ROLLBACK")
                raise JarvisFileDenied("conversation attachment limit reached")
            file_id = _opaque_id()
            db.execute(
                "INSERT INTO jarvis_files(id,owner,conversation_id,core_generation,idempotency_hash,"
                "request_hash,name,mime_type,size_bytes,sha256,state,created,updated) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,'processing',?,?)",
                (file_id, owner, conversation_id, core_generation, key_hash, request_hash,
                 name, mime_type, len(content), digest, now, now),
            )
            row = db.execute("SELECT * FROM jarvis_files WHERE id=?", (file_id,)).fetchone()
            db.execute("COMMIT")
        return _view(row), True

    def complete(self, *, subject: str, conversation_id: str, core_generation: str,
                 file_id: str, ref_text: str) -> dict[str, Any]:
        owner = self._chat_store._owner(subject)
        with self._chat_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            updated = db.execute(
                "UPDATE jarvis_files SET state='staged',ref_text=?,updated=? WHERE id=? AND owner=? "
                "AND conversation_id=? AND core_generation=? AND state='processing'",
                (ref_text, time.time(), file_id, owner, conversation_id, core_generation),
            ).rowcount
            if updated != 1:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("attachment ownership changed")
            row = db.execute("SELECT * FROM jarvis_files WHERE id=?", (file_id,)).fetchone()
            db.execute("COMMIT")
        return _view(row)

    def fail(self, *, subject: str, file_id: str) -> None:
        owner = self._chat_store._owner(subject)
        with self._chat_store._connect() as db:
            db.execute("UPDATE jarvis_files SET state='unavailable',ref_text='',updated=? "
                       "WHERE id=? AND owner=? AND state='processing'",
                       (time.time(), file_id, owner))

    def for_conversation(self, *, subject: str, conversation_id: str,
                         core_generation: str) -> list[dict[str, Any]]:
        owner = self._chat_store._owner(subject)
        with self._chat_store._connect() as db:
            conversation = db.execute(
                "SELECT owner,core_generation FROM conversations WHERE id=?", (conversation_id,)
            ).fetchone()
            if conversation is None or conversation["owner"] != owner:
                raise JarvisChatDenied("conversation is unavailable")
            if conversation["core_generation"] != core_generation:
                raise JarvisFileDenied("conversation generation changed")
            rows = db.execute(
                "SELECT * FROM jarvis_files WHERE owner=? AND conversation_id=? "
                "ORDER BY created DESC,id DESC LIMIT ?", (owner, conversation_id, MAX_FILE_ROWS)
            ).fetchall()
        return [_view(row) for row in rows]

    def has_user_message(self, conversation_id: str) -> bool:
        with self._chat_store._connect() as db:
            return db.execute("SELECT 1 FROM messages WHERE conversation_id=? AND role='user' LIMIT 1",
                              (conversation_id,)).fetchone() is not None

    def claim_pending(self, *, subject: str, conversation_id: str, turn_id: str,
                      core_generation: str) -> tuple[str, ...]:
        """Consume staged references once, joined to the exact active owner turn."""
        owner = self._chat_store._owner(subject)
        with self._chat_store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            turn = db.execute(
                "SELECT t.owner,t.conversation_id,t.core_generation,t.status,"
                "c.owner AS conversation_owner FROM turns t JOIN conversations c ON c.id=t.conversation_id "
                "WHERE t.id=?", (turn_id,),
            ).fetchone()
            if (turn is None or turn["owner"] != owner or turn["conversation_owner"] != owner
                    or turn["conversation_id"] != conversation_id
                    or turn["core_generation"] != core_generation
                    or turn["status"] not in {"queued", "running"}):
                db.execute("ROLLBACK")
                raise JarvisChatDenied("attachment turn ownership changed")
            rows = db.execute(
                "SELECT id,ref_text FROM jarvis_files WHERE owner=? AND conversation_id=? "
                "AND core_generation=? AND state='staged' ORDER BY created,id LIMIT ?",
                (owner, conversation_id, core_generation, MAX_STAGED_FILES),
            ).fetchall()
            if not rows:
                db.execute("COMMIT")
                return ()
            now = time.time()
            for row in rows:
                changed = db.execute(
                    "UPDATE jarvis_files SET state='used',turn_id=?,updated=? WHERE id=? AND owner=? "
                    "AND state='staged'", (turn_id, now, row["id"], owner)
                ).rowcount
                if changed != 1:
                    db.execute("ROLLBACK")
                    raise JarvisChatDenied("attachment reservation changed")
            db.execute("COMMIT")
        return tuple(row["ref_text"] for row in rows)


async def _read_upload(request) -> tuple[str, str, bytes, str]:
    from aiohttp import web

    if (request.content_type != "application/json" or request.content_length is None
            or request.content_length < 2 or request.content_length > MAX_FILE_BODY_BYTES
            or request.headers.get("Transfer-Encoding") is not None):
        raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
    try:
        # This route's canonical base64 body is larger than the shared chat JSON ceiling.
        # Clone only for bounded body parsing; do not relax the app-wide limit or replace the
        # original request used for authentication/currentness checks by the caller.
        bounded_request = request.clone(client_max_size=MAX_FILE_BODY_BYTES)
        raw = await asyncio.wait_for(bounded_request.read(), timeout=2.0)
        if len(raw) > MAX_FILE_BODY_BYTES:
            raise ValueError
        body = json.loads(raw, object_pairs_hook=_unique_pairs)
    except (asyncio.TimeoutError, ValueError, UnicodeDecodeError, TypeError):
        raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers()) from None
    if not isinstance(body, dict) or set(body) != {"name", "content_base64", "idempotency_key"}:
        raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
    name, encoded, key = body["name"], body["content_base64"], body["idempotency_key"]
    if (not isinstance(name, str) or not _NAME_RE.fullmatch(name) or name in {".", ".."}
            or ".." in name or not isinstance(encoded, str)
            or not isinstance(key, str) or not IDEMPOTENCY_RE.fullmatch(key)):
        raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
    media_type = _MEDIA_TYPES.get("." + name.rsplit(".", 1)[-1].lower()) if "." in name else None
    if media_type is None or len(encoded) > (MAX_FILE_BYTES * 4 // 3 + 8):
        raise web.HTTPUnsupportedMediaType(text="unsupported text file", headers=_secure_headers())
    try:
        content = base64.b64decode(encoded, validate=True)
        if (not content or len(content) > MAX_FILE_BYTES
                or base64.b64encode(content).decode("ascii") != encoded):
            raise ValueError
        decoded = content.decode("utf-8", "strict")
        if any(unicodedata.category(char) == "Cc" and char not in "\t\n\r" for char in decoded):
            raise ValueError
        if media_type == "application/json":
            json.loads(decoded, object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        raise web.HTTPBadRequest(text="invalid text file", headers=_secure_headers()) from None
    return name, media_type, content, key


async def _ready_conversation(request, service, conversation_id: str):
    principal = service._current(request)
    conversation = service.store.get_conversation(principal.subject, conversation_id)
    conversation = await service._ensure_current_runtime(request, principal, conversation)
    current = service._current(request)
    if (current.subject != principal.subject or current.core_generation != principal.core_generation
            or conversation["core_generation"] != current.core_generation):
        raise JarvisChatDenied("protected conversation changed")
    return current, conversation


async def list_files(request):
    from aiohttp import web

    service = request.app.get("jarvis_chat_service")
    try:
        principal = service._current(request)
        conversation_id = request.match_info.get("conversation_id", "")
        if not ID_RE.fullmatch(conversation_id):
            raise JarvisChatDenied("conversation is unavailable")
        files = service.files_store.for_conversation(
            subject=principal.subject, conversation_id=conversation_id,
            core_generation=principal.core_generation)
        current = service._current(request)
        if current.subject != principal.subject or current.core_generation != principal.core_generation:
            raise JarvisChatDenied("protected conversation changed")
        return web.json_response({"schema": 1, "files": files}, headers=_secure_headers())
    except JarvisChatDenied:
        raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None


async def upload_file(request):
    from aiohttp import web

    service = request.app.get("jarvis_chat_service")
    reserved: dict[str, Any] | None = None
    principal = None
    try:
        name, media_type, content, key = await _read_upload(request)
        conversation_id = request.match_info.get("conversation_id", "")
        if not ID_RE.fullmatch(conversation_id):
            raise web.HTTPNotFound(text="not found", headers=_secure_headers())
        async with service._admission_lock:
            principal, conversation = await _ready_conversation(request, service, conversation_id)
            reserved, is_new = service.files_store.reserve(
                subject=principal.subject, conversation_id=conversation_id,
                core_generation=principal.core_generation, idempotency_key=key,
                name=name, mime_type=media_type, content=content)
            if not is_new:
                if reserved["state"] == "pending":
                    raise web.HTTPConflict(text="attachment receipt is still resolving", headers=_secure_headers())
                if reserved["state"] == "unavailable":
                    raise web.HTTPConflict(text="attachment is unavailable", headers=_secure_headers())
                return web.json_response({"file": reserved}, headers=_secure_headers())

            try:
                backend = service.backend
                attach = getattr(backend, "attach_file", None)
                if not callable(attach):
                    raise JarvisChatDenied("native attachment adapter is unavailable")
                async with service._resume_lock:
                    current_conversation = service.store.get_conversation(
                        principal.subject, conversation_id)
                    if current_conversation["core_generation"] != principal.core_generation:
                        raise JarvisChatDenied("core generation changed")
                    has_history = service.files_store.has_user_message(conversation_id)
                    if has_history:
                        runtime_id = await backend.resume_session(current_conversation["session_key"])
                        now_current = service._current(request)
                        if (now_current.subject != principal.subject
                                or now_current.core_generation != principal.core_generation):
                            raise JarvisChatDenied("core generation changed during resume")
                        current_conversation = service.store.update_runtime_session(
                            principal.subject, conversation_id, principal.core_generation,
                            runtime_id, principal.core_generation)
                    else:
                        runtime_id = current_conversation["backend_id"]
                    now_current = service._current(request)
                    if (now_current.subject != principal.subject
                            or now_current.core_generation != principal.core_generation):
                        raise JarvisChatDenied("core generation changed before attachment")
                    native = await attach(runtime_id, name=name, media_type=media_type, content=content)
                    now_current = service._current(request)
                    if (now_current.subject != principal.subject
                            or now_current.core_generation != principal.core_generation):
                        raise JarvisChatDenied("core generation changed during attachment")
                completed = service.files_store.complete(
                    subject=principal.subject, conversation_id=conversation_id,
                    core_generation=principal.core_generation, file_id=reserved["id"],
                    ref_text=native.ref_text)
                return web.json_response({"file": completed}, status=201, headers=_secure_headers())
            except BaseException:
                service.files_store.fail(subject=principal.subject, file_id=reserved["id"])
                raise
    except web.HTTPException:
        raise
    except JarvisFileDenied:
        raise web.HTTPConflict(text="attachment could not be staged", headers=_secure_headers()) from None
    except JarvisChatDenied:
        raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None
    except Exception:
        raise web.HTTPServiceUnavailable(text="file attachment is unavailable", headers=_secure_headers()) from None


def install_jarvis_files_routes(app, service) -> None:
    """Install only the fixed owner-bound file list/upload endpoints."""
    app.router.add_get("/chat/api/conversations/{conversation_id}/files", list_files, allow_head=False)
    app.router.add_post("/chat/api/conversations/{conversation_id}/files", upload_file)
