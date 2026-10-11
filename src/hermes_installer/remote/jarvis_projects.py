"""Owner-bound Projects and bounded shared context for Jarvis chats.

Projects are a lightweight grouping for ordinary chats. Their instructions and
owner-written memory live in the existing protected chat database. Context is
assembled from explicit project fields and saved messages from chats in that
same owner's project; no model call or automatic summary is performed here.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import time
from typing import Any

from .jarvis_chat import (ID_RE, IDEMPOTENCY_RE, JarvisChatDenied,
                          JarvisChatService, _read_body, _secure_headers)

CHAT_TRASH_ROUTES = (
    ("GET", "/chat/api/conversations/trash"),
    ("POST", "/chat/api/conversations/{conversation_id}/trash"),
    ("POST", "/chat/api/conversations/{conversation_id}/restore"),
)
FEATURE_ROUTES = (
    ("GET", "/chat/api/projects"),
    ("GET", "/chat/api/projects/trash"),
    ("POST", "/chat/api/projects"),
    ("GET", "/chat/api/projects/{project_id}"),
    ("POST", "/chat/api/projects/{project_id}"),
    ("POST", "/chat/api/projects/{project_id}/trash"),
    ("POST", "/chat/api/projects/{project_id}/restore"),
    ("POST", "/chat/api/conversations/{conversation_id}/project"),
    *CHAT_TRASH_ROUTES,
)
PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
_MAX_INSTRUCTIONS = 8_000
_MAX_MEMORY = 8_000
_MAX_CONTEXT = 24_000
_MAX_PROJECT_CHATS = 100
_MAX_PROJECT_MESSAGES = 12
_MAX_MESSAGE_CHARS = 1_500


class JarvisProjectsStore:
    """Project rows and chat membership on the durable owner-bound chat store."""

    def __init__(self, chat_store: Any):
        if not callable(getattr(chat_store, "_connect", None)):
            raise TypeError("protected Jarvis chat store required")
        self.store = chat_store
        with chat_store._connect() as db:
            db.executescript("""
              CREATE TABLE IF NOT EXISTS jarvis_projects(
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, title TEXT NOT NULL,
                instructions TEXT NOT NULL DEFAULT '', shared_memory TEXT NOT NULL DEFAULT '',
                obsidian_note_ids TEXT NOT NULL DEFAULT '[]', version INTEGER NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
              CREATE INDEX IF NOT EXISTS jarvis_projects_owner
                ON jarvis_projects(owner,updated DESC);
              CREATE TABLE IF NOT EXISTS jarvis_project_chats(
                conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
                project_id TEXT REFERENCES jarvis_projects(id) ON DELETE CASCADE,
                owner TEXT NOT NULL, updated REAL NOT NULL);
              CREATE INDEX IF NOT EXISTS jarvis_project_chats_project
                ON jarvis_project_chats(owner,project_id,updated DESC);
              CREATE TABLE IF NOT EXISTS jarvis_project_ops(
                owner TEXT NOT NULL, idempotency_hash TEXT NOT NULL,
                request_hash TEXT NOT NULL, response_json TEXT NOT NULL,
                created REAL NOT NULL, PRIMARY KEY(owner,idempotency_hash));
            """)
            columns = {row[1] for row in db.execute("PRAGMA table_info(jarvis_projects)")}
            if "archived" not in columns:
                db.execute("ALTER TABLE jarvis_projects ADD COLUMN archived INTEGER NOT NULL DEFAULT 0")
            db.executescript("""
              CREATE TABLE IF NOT EXISTS jarvis_conversation_trash(
                conversation_id TEXT PRIMARY KEY REFERENCES conversations(id) ON DELETE CASCADE,
                owner TEXT NOT NULL, deleted_at REAL NOT NULL, version INTEGER NOT NULL DEFAULT 1,
                deleted INTEGER NOT NULL DEFAULT 1);
              CREATE INDEX IF NOT EXISTS jarvis_conversation_trash_recent
                ON jarvis_conversation_trash(owner,deleted_at DESC);
              CREATE TABLE IF NOT EXISTS jarvis_conversation_trash_ops(
                owner TEXT NOT NULL, idempotency_hash TEXT NOT NULL, request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL, created REAL NOT NULL,
                PRIMARY KEY(owner,idempotency_hash));
            """)
            trash_columns = {row[1] for row in db.execute("PRAGMA table_info(jarvis_conversation_trash)")}
            if "deleted" not in trash_columns:
                db.execute("ALTER TABLE jarvis_conversation_trash ADD COLUMN deleted INTEGER NOT NULL DEFAULT 1")

    def _owner(self, subject: str) -> str:
        return self.store._owner(subject)

    def _require_owned_conversation(self, subject: str, conversation_id: str) -> str:
        """Check raw ownership so restore remains possible after chat readers hide Trash."""
        if not ID_RE.fullmatch(conversation_id or ""):
            raise JarvisChatDenied("conversation is unavailable")
        owner = self._owner(subject)
        with self.store._connect() as db:
            found = db.execute("SELECT 1 FROM conversations WHERE id=? AND owner=?",
                               (conversation_id, owner)).fetchone()
        if found is None:
            raise JarvisChatDenied("conversation is unavailable")
        return owner

    def conversation_version(self, subject: str, conversation_id: str) -> int:
        """Return a live chat's current trash CAS version (1 before its first delete)."""
        owner = self._require_owned_conversation(subject, conversation_id)
        with self.store._connect() as db:
            row = db.execute("SELECT version FROM jarvis_conversation_trash "
                             "WHERE conversation_id=? AND owner=?",
                             (conversation_id, owner)).fetchone()
        return 1 if row is None else int(row["version"])

    @staticmethod
    def _text(value: Any, maximum: int, *, allow_empty: bool = True) -> str:
        if (not isinstance(value, str) or len(value) > maximum
                or (not allow_empty and not value.strip())
                or any(ord(c) < 0x20 and c not in "\n\t\r" for c in value)):
            raise ValueError("invalid project text")
        return value.strip()

    @staticmethod
    def _note_ids(value: Any) -> list[str]:
        if not isinstance(value, list) or len(value) > 50:
            raise ValueError("invalid note references")
        result = []
        for item in value:
            if not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,96}", item):
                raise ValueError("invalid note reference")
            if item not in result:
                result.append(item)
        return result

    @staticmethod
    def _public(row: Any, chat_rows: list[Any] | None = None) -> dict[str, Any]:
        try:
            note_ids = json.loads(row["obsidian_note_ids"])
        except (ValueError, TypeError):
            note_ids = []
        if not isinstance(note_ids, list):
            note_ids = []
        result = {"id": row["id"], "title": row["title"],
                  "instructions": row["instructions"], "sharedMemory": row["shared_memory"],
                  "obsidianNoteIds": note_ids, "version": row["version"],
                  "createdAt": row["created"], "updatedAt": row["updated"],
                  "archived": bool(row["archived"])}
        if chat_rows is not None:
            result["chats"] = [{"id": item["id"], "title": item["title"],
                                "updatedAt": item["updated"]} for item in chat_rows]
        return result

    def list(self, subject: str) -> list[dict[str, Any]]:
        owner = self._owner(subject)
        with self.store._connect() as db:
            rows = db.execute("SELECT * FROM jarvis_projects WHERE owner=? AND archived=0 ORDER BY updated DESC LIMIT 100",
                              (owner,)).fetchall()
            result = []
            for row in rows:
                chats = db.execute("""SELECT c.id,c.title,c.updated FROM jarvis_project_chats pc
                    JOIN conversations c ON c.id=pc.conversation_id AND c.owner=pc.owner
                    WHERE pc.owner=? AND pc.project_id=? AND NOT EXISTS (
                      SELECT 1 FROM jarvis_conversation_trash ct
                      WHERE ct.conversation_id=c.id AND ct.owner=c.owner AND ct.deleted=1)
                    ORDER BY pc.updated DESC LIMIT ?""",
                    (owner, row["id"], _MAX_PROJECT_CHATS)).fetchall()
                result.append(self._public(row, chats))
            return result

    def trash(self, subject: str) -> list[dict[str, Any]]:
        owner = self._owner(subject)
        with self.store._connect() as db:
            rows = db.execute("SELECT * FROM jarvis_projects WHERE owner=? AND archived=1 ORDER BY updated DESC LIMIT 100",
                              (owner,)).fetchall()
            return [self._public(row, []) for row in rows]

    def get(self, subject: str, project_id: str) -> dict[str, Any]:
        if not PROJECT_ID_RE.fullmatch(project_id or ""):
            raise JarvisChatDenied("project is unavailable")
        owner = self._owner(subject)
        with self.store._connect() as db:
            row = db.execute("SELECT * FROM jarvis_projects WHERE id=? AND owner=?",
                             (project_id, owner)).fetchone()
            if row is None:
                raise JarvisChatDenied("project is unavailable")
            chats = db.execute("""SELECT c.id,c.title,c.updated FROM jarvis_project_chats pc
                JOIN conversations c ON c.id=pc.conversation_id AND c.owner=pc.owner
                WHERE pc.owner=? AND pc.project_id=? AND NOT EXISTS (
                  SELECT 1 FROM jarvis_conversation_trash ct
                  WHERE ct.conversation_id=c.id AND ct.owner=c.owner AND ct.deleted=1)
                ORDER BY pc.updated DESC LIMIT ?""",
                (owner, project_id, _MAX_PROJECT_CHATS)).fetchall()
        return self._public(row, chats)

    def _idempotent(self, subject: str, key: str, scope: str,
                    body: dict[str, Any], operation):
        if not IDEMPOTENCY_RE.fullmatch(key or ""):
            raise ValueError("idempotency key required")
        owner = self._owner(subject)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        request_hash = hashlib.sha256(json.dumps({"scope": scope, "body": body},
            sort_keys=True, ensure_ascii=False,
            separators=(",", ":")).encode()).hexdigest()
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT request_hash,response_json FROM jarvis_project_ops "
                                  "WHERE owner=? AND idempotency_hash=?",
                                  (owner, key_hash)).fetchone()
            if previous is not None:
                db.execute("COMMIT")
                if previous["request_hash"] != request_hash:
                    raise JarvisChatDenied("project request replay was denied")
                return json.loads(previous["response_json"]), True
            # Keep mutations and their replay record in one transaction.
            result = operation(db, owner)
            db.execute("INSERT INTO jarvis_project_ops VALUES(?,?,?,?,?)",
                       (owner, key_hash, request_hash,
                        json.dumps(result, ensure_ascii=False, separators=(",", ":")), time.time()))
            db.execute("DELETE FROM jarvis_project_ops WHERE owner=? AND created < ?",
                       (owner, time.time() - 30 * 86400))
            db.execute("COMMIT")
            return result, False

    def create(self, subject: str, key: str, body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        title = self._text(body.get("title"), 120, allow_empty=False)
        instructions = self._text(body.get("instructions", ""), _MAX_INSTRUCTIONS)
        memory = self._text(body.get("sharedMemory", ""), _MAX_MEMORY)
        note_ids = self._note_ids(body.get("obsidianNoteIds", []))
        project_id = secrets.token_urlsafe(24)
        now = time.time()
        def operation(db, owner):
            db.execute("""INSERT INTO jarvis_projects(
                id,owner,title,instructions,shared_memory,obsidian_note_ids,version,created,updated)
                VALUES(?,?,?,?,?,?,1,?,?)""",
                (project_id, owner, title, instructions, memory,
                 json.dumps(note_ids, separators=(",", ":")), now, now))
            row = db.execute("SELECT * FROM jarvis_projects WHERE id=?", (project_id,)).fetchone()
            return self._public(row, [])
        return self._idempotent(subject, key, "projects:create", body, operation)

    def update(self, subject: str, project_id: str, key: str,
               body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        title = self._text(body.get("title"), 120, allow_empty=False)
        instructions = self._text(body.get("instructions"), _MAX_INSTRUCTIONS)
        memory = self._text(body.get("sharedMemory"), _MAX_MEMORY)
        note_ids = self._note_ids(body.get("obsidianNoteIds"))
        version = body.get("version")
        if type(version) is not int or version < 1:
            raise ValueError("project version required")
        now = time.time()
        def operation(db, owner):
            changed = db.execute("""UPDATE jarvis_projects SET title=?,instructions=?,shared_memory=?,
                obsidian_note_ids=?,version=version+1,updated=? WHERE id=? AND owner=? AND version=? AND archived=0""",
                (title, instructions, memory, json.dumps(note_ids, separators=(",", ":")),
                 now, project_id, owner, version)).rowcount
            if changed != 1:
                raise JarvisChatDenied("project changed or is unavailable")
            row = db.execute("SELECT * FROM jarvis_projects WHERE id=? AND owner=?",
                             (project_id, owner)).fetchone()
            return self._public(row, [])
        return self._idempotent(subject, key, "projects:update:" + project_id, body, operation)

    def archive(self, subject: str, project_id: str, key: str,
                body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        version = body.get("version")
        if type(version) is not int or version < 1:
            raise ValueError("project version required")
        now = time.time()
        def operation(db, owner):
            changed = db.execute("""UPDATE jarvis_projects SET archived=1,version=version+1,updated=?
                WHERE id=? AND owner=? AND version=? AND archived=0""",
                (now, project_id, owner, version)).rowcount
            if changed != 1:
                raise JarvisChatDenied("project changed or is unavailable")
            row = db.execute("SELECT * FROM jarvis_projects WHERE id=? AND owner=?",
                             (project_id, owner)).fetchone()
            return self._public(row, [])
        return self._idempotent(subject, key, "projects:archive:" + project_id, body, operation)

    def restore(self, subject: str, project_id: str, key: str,
                body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        version = body.get("version")
        if type(version) is not int or version < 1:
            raise ValueError("project version required")
        now = time.time()
        def operation(db, owner):
            changed = db.execute("""UPDATE jarvis_projects SET archived=0,version=version+1,updated=?
                WHERE id=? AND owner=? AND version=? AND archived=1""",
                (now, project_id, owner, version)).rowcount
            if changed != 1:
                raise JarvisChatDenied("project changed or is unavailable")
            row = db.execute("SELECT * FROM jarvis_projects WHERE id=? AND owner=?",
                             (project_id, owner)).fetchone()
            return self._public(row, [])
        return self._idempotent(subject, key, "projects:restore:" + project_id, body, operation)

    def move_chat(self, subject: str, conversation_id: str, key: str,
                  body: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        project_id = body.get("projectId")
        if project_id is not None and (not isinstance(project_id, str)
                                       or not PROJECT_ID_RE.fullmatch(project_id)):
            raise ValueError("invalid project selection")
        owner = self._owner(subject)
        # Check ownership before the idempotency operation, including on replay.
        self._require_owned_conversation(subject, conversation_id)
        def operation(db, transaction_owner):
            if transaction_owner != owner:
                raise JarvisChatDenied("project owner changed")
            if db.execute("SELECT 1 FROM jarvis_conversation_trash "
                          "WHERE conversation_id=? AND owner=? AND deleted=1",
                          (conversation_id, owner)).fetchone() is not None:
                raise JarvisChatDenied("conversation is unavailable")
            if project_id is not None and db.execute(
                    "SELECT 1 FROM jarvis_projects WHERE id=? AND owner=? AND archived=0",
                    (project_id, owner)).fetchone() is None:
                raise JarvisChatDenied("project is unavailable")
            if project_id is None:
                db.execute("DELETE FROM jarvis_project_chats WHERE conversation_id=? AND owner=?",
                           (conversation_id, owner))
            else:
                db.execute("""INSERT INTO jarvis_project_chats(conversation_id,project_id,owner,updated)
                    VALUES(?,?,?,?) ON CONFLICT(conversation_id) DO UPDATE SET
                    project_id=excluded.project_id,owner=excluded.owner,updated=excluded.updated""",
                    (conversation_id, project_id, owner, time.time()))
            return {"conversationId": conversation_id, "projectId": project_id}
        return self._idempotent(subject, key,
                                "conversation:project:" + conversation_id, body, operation)

    def context(self, subject: str, conversation_id: str) -> str:
        """Return explicit project text plus a bounded sample of real saved project chats."""
        # Distinguish an owned chat with no attached project (empty context) from
        # a foreign/nonexistent conversation. The latter must remain owner-denied.
        self._require_owned_conversation(subject, conversation_id)
        owner = self._owner(subject)
        excerpts = []
        with self.store._connect() as db:
            row = db.execute("""SELECT p.* FROM jarvis_projects p JOIN jarvis_project_chats pc
                ON pc.project_id=p.id AND pc.owner=p.owner
                JOIN conversations current ON current.id=pc.conversation_id AND current.owner=pc.owner
                WHERE pc.conversation_id=? AND pc.owner=? AND p.archived=0
                AND NOT EXISTS (SELECT 1 FROM jarvis_conversation_trash t
                                WHERE t.conversation_id=current.id AND t.owner=current.owner AND t.deleted=1)""",
                (conversation_id, owner)).fetchone()
            if row is None:
                return ""
            chats = db.execute("""SELECT c.id,c.title,c.updated FROM jarvis_project_chats pc
                JOIN conversations c ON c.id=pc.conversation_id AND c.owner=pc.owner
                WHERE pc.project_id=? AND pc.owner=?
                  AND NOT EXISTS (SELECT 1 FROM jarvis_conversation_trash ct
                                  WHERE ct.conversation_id=c.id AND ct.owner=c.owner AND ct.deleted=1)
                ORDER BY c.updated DESC,c.id LIMIT ?""",
                (row["id"], owner, _MAX_PROJECT_CHATS)).fetchall()
            note_ids = self._note_ids(json.loads(row["obsidian_note_ids"]))
            for chat in chats:
                rows = db.execute("SELECT role,content FROM messages WHERE conversation_id=? "
                                  "ORDER BY created DESC,id DESC LIMIT ?",
                                  (chat["id"], _MAX_PROJECT_MESSAGES)).fetchall()
                for message in reversed(rows):
                    if len(excerpts) >= _MAX_PROJECT_MESSAGES:
                        break
                    excerpts.append(f"[{chat['title']} · {message['role']}]: "
                                    + message["content"][-_MAX_MESSAGE_CHARS:])
                if len(excerpts) >= _MAX_PROJECT_MESSAGES:
                    break
        # Explicit saved-memory and instructions are included as user-controlled source text.
        sections = ["Project shared context (owner-authored fields):",
                    f"Project: {row['title']}"]
        if row["instructions"]:
            sections.append("Project instructions:\n" + row["instructions"])
        if row["shared_memory"]:
            sections.append("Project shared memory (owner-authored):\n" + row["shared_memory"])
        if note_ids:
            note_refs = ", ".join(note_ids)
            if len(note_refs) > 2_000:
                note_refs = note_refs[:2_000] + " … (additional note IDs omitted)"
            sections.append("Selected owner Obsidian note IDs (note content is supplied separately): "
                            + note_refs)
        prefix = "\n\n".join(sections)
        chat_label = "Saved chat excerpts (actual stored messages; untrusted conversation content):"
        value = prefix + "\n\n" + chat_label
        context_limit = _MAX_CONTEXT - 5_000 if note_ids else _MAX_CONTEXT
        for excerpt in excerpts:
            room = context_limit - len(value) - 2
            if room <= 0:
                break
            value += "\n\n" + excerpt[:room]
        return value

    def conversation_is_live(self, subject: str, conversation_id: str) -> bool:
        owner = self._require_owned_conversation(subject, conversation_id)
        with self.store._connect() as db:
            return db.execute("SELECT 1 FROM jarvis_conversation_trash WHERE conversation_id=? AND owner=? AND deleted=1",
                              (conversation_id, owner)).fetchone() is None

    def project_note_ids(self, subject: str, conversation_id: str) -> list[str]:
        owner = self._owner(subject)
        with self.store._connect() as db:
            row = db.execute("""SELECT p.obsidian_note_ids FROM jarvis_projects p
                JOIN jarvis_project_chats pc ON pc.project_id=p.id AND pc.owner=p.owner
                JOIN conversations c ON c.id=pc.conversation_id AND c.owner=pc.owner
                WHERE pc.conversation_id=? AND pc.owner=? AND p.archived=0
                  AND NOT EXISTS (SELECT 1 FROM jarvis_conversation_trash t
                                  WHERE t.conversation_id=c.id AND t.owner=c.owner AND t.deleted=1)""",
                (conversation_id, owner)).fetchone()
        return [] if row is None else self._note_ids(json.loads(row["obsidian_note_ids"]))

    def conversation_trash(self, subject: str) -> list[dict[str, Any]]:
        owner = self._owner(subject)
        with self.store._connect() as db:
            rows = db.execute("""SELECT c.id,c.title,c.updated,t.deleted_at,t.version FROM
                jarvis_conversation_trash t JOIN conversations c ON c.id=t.conversation_id AND c.owner=t.owner
                WHERE t.owner=? AND t.deleted=1 ORDER BY t.deleted_at DESC LIMIT 100""", (owner,)).fetchall()
        return [{"id": row["id"], "title": row["title"], "updatedAt": row["updated"],
                 "deletedAt": row["deleted_at"], "version": row["version"]} for row in rows]

    def visible_conversations(self, subject: str) -> list[dict[str, Any]]:
        """Existing Chats listing with owner tombstones removed, for chat-store integration."""
        owner = self._owner(subject)
        with self.store._connect() as db:
            rows = db.execute("""SELECT c.id,c.title,c.updated,COALESCE(t.version,1) AS version
                FROM conversations c LEFT JOIN jarvis_conversation_trash t
                  ON t.conversation_id=c.id AND t.owner=c.owner
                WHERE c.owner=? AND NOT EXISTS (
                  SELECT 1 FROM jarvis_conversation_trash t
                  WHERE t.conversation_id=c.id AND t.owner=c.owner AND t.deleted=1)
                ORDER BY c.updated DESC LIMIT 100""", (owner,)).fetchall()
        return [{"id": row["id"], "title": row["title"], "updatedAt": row["updated"],
                 "version": row["version"]}
                for row in rows]

    def _conversation_trash_change(self, subject: str, conversation_id: str, key: str,
                                   version: int, *, restore: bool) -> tuple[dict[str, Any], bool]:
        owner = self._owner(subject)
        self._require_owned_conversation(subject, conversation_id)
        if type(version) is not int or version < 1 or not IDEMPOTENCY_RE.fullmatch(key or ""):
            raise ValueError("conversation trash version or idempotency key is invalid")
        operation_name = "restore" if restore else "trash"
        request_hash = hashlib.sha256(json.dumps({"operation": operation_name,
            "conversationId": conversation_id, "version": version}, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        with self.store._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT request_hash,response_json FROM jarvis_conversation_trash_ops "
                               "WHERE owner=? AND idempotency_hash=?", (owner, key_hash)).fetchone()
            if prior is not None:
                db.execute("COMMIT")
                if prior["request_hash"] != request_hash:
                    raise JarvisChatDenied("conversation trash request replay was denied")
                return json.loads(prior["response_json"]), True
            if restore:
                changed = db.execute("""UPDATE jarvis_conversation_trash SET deleted=0,version=version+1
                    WHERE conversation_id=? AND owner=? AND version=? AND deleted=1""",
                    (conversation_id, owner, version)).rowcount
            else:
                active = db.execute("SELECT 1 FROM turns WHERE owner=? AND conversation_id=? "
                                     "AND status IN ('queued','running') LIMIT 1",
                                     (owner, conversation_id)).fetchone()
                if active is not None:
                    db.execute("ROLLBACK")
                    raise JarvisProjectConflict("conversation has an active turn")
                existing = db.execute("SELECT version,deleted FROM jarvis_conversation_trash "
                                      "WHERE conversation_id=? AND owner=?", (conversation_id, owner)).fetchone()
                if existing is None:
                    changed = (db.execute("INSERT INTO jarvis_conversation_trash "
                        "(conversation_id,owner,deleted_at,version,deleted) VALUES(?,?,?,1,1)",
                        (conversation_id, owner, time.time())).rowcount if version == 1 else 0)
                elif existing["version"] == version and existing["deleted"] == 0:
                    changed = db.execute("UPDATE jarvis_conversation_trash SET deleted=1,deleted_at=?,version=version+1 "
                        "WHERE conversation_id=? AND owner=? AND version=? AND deleted=0",
                        (time.time(), conversation_id, owner, version)).rowcount
                else:
                    changed = 0
            if changed != 1:
                db.execute("ROLLBACK")
                raise JarvisChatDenied("conversation changed or is unavailable")
            row = db.execute("SELECT c.id,c.title,c.updated,t.deleted_at,t.version FROM "
                "conversations c LEFT JOIN jarvis_conversation_trash t ON t.conversation_id=c.id "
                "WHERE c.id=? AND c.owner=?", (conversation_id, owner)).fetchone()
            result = {"id": row["id"], "title": row["title"], "updatedAt": row["updated"],
                      "deleted": not restore, "deletedAt": row["deleted_at"],
                      "version": row["version"] if row["version"] is not None else version + 1}
            db.execute("INSERT INTO jarvis_conversation_trash_ops VALUES(?,?,?,?,?)",
                (owner, key_hash, request_hash, json.dumps(result, separators=(",", ":")), time.time()))
            db.execute("DELETE FROM jarvis_conversation_trash_ops WHERE owner=? AND created<?",
                       (owner, time.time() - 30 * 86400))
            db.execute("COMMIT")
            return result, False

    def trash_conversation(self, subject: str, conversation_id: str, key: str,
                           version: int) -> tuple[dict[str, Any], bool]:
        return self._conversation_trash_change(subject, conversation_id, key, version, restore=False)

    def restore_conversation(self, subject: str, conversation_id: str, key: str,
                             version: int) -> tuple[dict[str, Any], bool]:
        return self._conversation_trash_change(subject, conversation_id, key, version, restore=True)


def install_jarvis_projects_routes(app: Any, service: JarvisChatService) -> None:
    """Install finite owner-authenticated project CRUD and chat-assignment routes."""
    from aiohttp import web
    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    projects = JarvisProjectsStore(service.store)
    service.projects_store = projects

    def key(request):
        values = request.headers.getall("Idempotency-Key", [])
        if len(values) != 1:
            raise ValueError("idempotency key required")
        return values[0]

    async def route(request: Any):
        try:
            if request.raw_path != request.path:
                raise ValueError("noncanonical project request path")
            principal = service._current(request)
            if request.method == "GET" and request.path == "/chat/api/conversations/trash":
                result = projects.conversation_trash(principal.subject)
                service._current(request)
                return web.json_response({"conversations": result}, headers=_secure_headers())
            if request.method == "GET" and request.path == "/chat/api/projects":
                result = projects.list(principal.subject)
                service._current(request)
                return web.json_response({"projects": result}, headers=_secure_headers())
            if request.method == "GET" and request.path == "/chat/api/projects/trash":
                result = projects.trash(principal.subject)
                service._current(request)
                return web.json_response({"projects": result}, headers=_secure_headers())
            if request.method == "POST" and request.path == "/chat/api/projects":
                body = await _read_body(request, {"title", "instructions", "sharedMemory", "obsidianNoteIds"})
                result, replay = projects.create(principal.subject, key(request), body)
                service._current(request)
                return web.json_response({"project": result, "replayed": replay},
                                         status=200 if replay else 201, headers=_secure_headers())
            if request.method == "GET" and request.path.startswith("/chat/api/projects/"):
                result = projects.get(principal.subject, request.match_info.get("project_id", ""))
                service._current(request)
                return web.json_response({"project": result}, headers=_secure_headers())
            if request.method == "POST" and request.path.startswith("/chat/api/projects/"):
                if request.path.endswith("/trash"):
                    body = await _read_body(request, {"version"})
                    result, replay = projects.archive(principal.subject,
                        request.match_info.get("project_id", ""), key(request), body)
                    service._current(request)
                    return web.json_response({"project": result, "replayed": replay},
                                             headers=_secure_headers())
                if request.path.endswith("/restore"):
                    body = await _read_body(request, {"version"})
                    result, replay = projects.restore(principal.subject,
                        request.match_info.get("project_id", ""), key(request), body)
                    service._current(request)
                    return web.json_response({"project": result, "replayed": replay},
                                             headers=_secure_headers())
                body = await _read_body(request, {"title", "instructions", "sharedMemory",
                                                  "obsidianNoteIds", "version"})
                result, replay = projects.update(principal.subject,
                    request.match_info.get("project_id", ""), key(request), body)
                service._current(request)
                return web.json_response({"project": result, "replayed": replay}, headers=_secure_headers())
            if request.method == "POST" and "/project" in request.path:
                body = await _read_body(request, {"projectId"})
                conversation_id = request.match_info.get("conversation_id", "")
                result, replay = projects.move_chat(principal.subject, conversation_id,
                                                    key(request), body)
                service._current(request)
                return web.json_response({**result, "replayed": replay}, headers=_secure_headers())
            if request.method == "POST" and request.path.endswith("/trash"):
                body = await _read_body(request, {"version"})
                result, replay = projects.trash_conversation(principal.subject,
                    request.match_info.get("conversation_id", ""), key(request), body["version"])
                service._current(request)
                return web.json_response({"conversation": result, "replayed": replay},
                                         headers=_secure_headers())
            if request.method == "POST" and request.path.endswith("/restore"):
                body = await _read_body(request, {"version"})
                result, replay = projects.restore_conversation(principal.subject,
                    request.match_info.get("conversation_id", ""), key(request), body["version"])
                service._current(request)
                return web.json_response({"conversation": result, "replayed": replay},
                                         headers=_secure_headers())
            raise web.HTTPNotFound(text="not found", headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisProjectConflict:
            raise web.HTTPConflict(text="conversation has an active turn", headers=_secure_headers()) from None
        except (ValueError, TypeError):
            raise web.HTTPBadRequest(text="invalid project request", headers=_secure_headers()) from None
        except JarvisChatDenied:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers()) from None

    for method, path in FEATURE_ROUTES:
        if method == "GET":
            app.router.add_get(path, route, allow_head=False)
        elif method == "POST":
            app.router.add_post(path, route)
        else:
            raise ValueError("project route method is not reviewed")


async def project_context_for_turn(service: JarvisChatService, principal: Any,
                                   conversation_id: str, request: Any | None = None) -> str:
    """Build bounded context and fetch selected notes through the fixed root adapter."""
    from .jarvis_chat import ChatPrincipal
    if (not isinstance(service, JarvisChatService) or not isinstance(principal, ChatPrincipal)
            or not ID_RE.fullmatch(conversation_id or "")):
        raise JarvisChatDenied("project context is unavailable")
    projects = getattr(service, "projects_store", None)
    if not isinstance(projects, JarvisProjectsStore):
        return ""
    # The selected context is bound to the caller's current durable native session
    # generation. This must run before a per-message child-session rebind.
    conversation = service.store.get_conversation(principal.subject, conversation_id)
    if conversation["core_generation"] != principal.core_generation:
        raise JarvisChatDenied("project context session generation changed")
    context = projects.context(principal.subject, conversation_id)
    note_ids = projects.project_note_ids(principal.subject, conversation_id)
    if not note_ids:
        return context
    if request is None:
        return context + "\n\nObsidian note content remains pending without current owner ingress."
    try:
        access = request.headers.getall("Cf-Access-Jwt-Assertion", [])
        accepted = request.get("core_ingress")
        inspector = getattr(service, "inspector", None)
        read = getattr(inspector, "read_obsidian_vault", None)
        if len(access) != 1 or not callable(read):
            raise ValueError
        source_chunks = []
        for note_id in note_ids[:2]:
            note = await asyncio.wait_for(asyncio.to_thread(
                read, access[0], accepted, view="note", note_id=note_id), timeout=5.0)
            if (not isinstance(note, dict) or note.get("noteId") != note_id
                    or not isinstance(note.get("markdown"), str)
                    or len(note["markdown"]) > 200_000):
                raise ValueError
            source_chunks.append(f"[Obsidian vault note {note_id} · untrusted Markdown]\n"
                                 + note["markdown"][:1_200])
        current = service._current(request)
        if (current.subject != principal.subject
                or current.core_generation != principal.core_generation):
            raise JarvisChatDenied("owner ingress changed during project context read")
        if len(note_ids) > 2:
            source_chunks.append("Additional selected Obsidian notes are linked but omitted from this bounded context.")
        value = context + "\n\nSelected Obsidian memory (current owner vault content):\n" + "\n\n".join(source_chunks)
        if len(value) > _MAX_CONTEXT:
            raise ValueError
        return value
    except JarvisChatDenied:
        raise
    except Exception:
        return context + "\n\nObsidian note content remains pending because the current owner read was unavailable."


class JarvisProjectConflict(JarvisChatDenied):
    """An owned resource exists but cannot be changed in its current state."""
