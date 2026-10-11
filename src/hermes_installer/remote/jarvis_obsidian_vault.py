"""Owner-bound, finite read routes for the persistent Obsidian vault."""
from __future__ import annotations

import asyncio
import re
from typing import Any

from .jarvis_chat import JarvisChatDenied, JarvisChatService, _secure_headers

FEATURE_ROUTES = (
    ("GET", "/chat/api/second-brain/overview"),
    ("GET", "/chat/api/second-brain/notes"),
    ("GET", "/chat/api/second-brain/search"),
    ("GET", "/chat/api/second-brain/notes/{note_id}"),
    ("GET", "/chat/api/second-brain/notes/{note_id}/links"),
    ("GET", "/chat/api/second-brain/graph"),
)
_NOTE_ID = re.compile(r"[A-Za-z0-9_-]{1,96}\Z")
_CURSOR = re.compile(r"v1:(?:0|[1-9][0-9]{0,6})\Z")


def install_jarvis_obsidian_vault_routes(app: Any, service: JarvisChatService) -> None:
    """Install six GET-only routes backed by the root inspector and Access JWT."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def route(request: Any, view: str) -> Any:
        try:
            if request.raw_path.split("?", 1)[0] != request.path:
                raise ValueError
            principal = service._current(request)
            access = request.headers.getall("Cf-Access-Jwt-Assertion", [])
            if len(access) != 1:
                raise JarvisChatDenied("owner Access JWT is unavailable")
            args: dict[str, Any] = {"view": view}
            allowed = set()
            if view in {"notes", "search"}:
                allowed = {"limit", "cursor"}
                limits = request.query.getall("limit", [])
                cursors = request.query.getall("cursor", [])
                if len(limits) > 1 or len(cursors) > 1:
                    raise ValueError
                limit = limits[0] if limits else "20"
                if not re.fullmatch(r"(?:[1-9]|[1-4][0-9]|50)", limit):
                    raise ValueError
                cursor = cursors[0] if cursors else None
                if cursor is not None and not _CURSOR.fullmatch(cursor):
                    raise ValueError
                args.update(limit=int(limit), cursor=cursor)
            if view == "search":
                allowed.add("query")
                queries = request.query.getall("query", [])
                if len(queries) != 1 or not queries[0].strip() or len(queries[0]) > 256:
                    raise ValueError
                args["query"] = queries[0]
            if view in {"note", "links"}:
                allowed = set()
                note_id = request.match_info.get("note_id", "")
                if not _NOTE_ID.fullmatch(note_id):
                    raise ValueError
                args["note_id"] = note_id
            if not set(request.query.keys()).issubset(allowed):
                raise ValueError
            accepted = request.get("core_ingress")
            inspector = getattr(service, "inspector", None)
            read = getattr(inspector, "read_obsidian_vault", None)
            if not callable(read):
                raise RuntimeError("root Obsidian inspector is not composed")
            projection = await asyncio.wait_for(asyncio.to_thread(
                read, access[0], accepted, **args), timeout=5.0)
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner ingress changed during Obsidian read")
            return web.json_response(projection, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="Obsidian vault unavailable", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="Obsidian vault unavailable", headers=_secure_headers()) from None

    def selected(view: str):
        async def handler(request: Any) -> Any:
            return await route(request, view)
        return handler

    for (_method, path), view in zip(FEATURE_ROUTES,
                                     ("overview", "notes", "search", "note", "links", "graph")):
        app.router.add_get(path, selected(view), allow_head=False)
