"""Owner-bound, read-only Hermes session context and status projection.

The browser addresses only a Jarvis conversation. The server resolves that opaque
identifier through its authenticated owner store and uses the private native session
mapping for two fixed, read-only Hermes methods. Raw status text and context file paths
never cross this projection.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from .jarvis_chat import ID_RE, JarvisChatDenied, JarvisChatService, _secure_headers

FEATURE_ROUTES = (("GET", "/chat/api/conversations/{conversation_id}/context"),)

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:+()/-]{0,95}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+ -]{0,159}$")
_STATUS_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$")
_TOKEN_COUNT = re.compile(r"^(?:0|[1-9]\d{0,2}(?:,\d{3})*)$")
_MAX_CATEGORIES = 32
_MAX_CONTEXT_TOKENS = 2_000_000
_CONTEXT_LABELS = {
    "system_prompt": "System prompt",
    "tool_definitions": "Tool definitions",
    "rules": "Rules",
    "skills": "Skills",
    "mcp": "MCP tools",
    "subagent_definitions": "Subagent definitions",
    "memory": "Memory",
    "conversation": "Conversation",
}
_CONTEXT_SOURCES = {"local_estimate", "provider_usage", "provider_usage_plus_estimate"}


def _safe_label(value: Any, *, pattern: re.Pattern[str] = _LABEL) -> str | None:
    if (not isinstance(value, str) or not pattern.fullmatch(value)
            or ".." in value or "//" in value or "://" in value or "\\" in value):
        return None
    return value


def decode_context_breakdown(value: Any) -> dict[str, Any]:
    """Decode the finite sanitized adapter DTO; reject the whole context section on drift."""
    expected = {"categories", "context_max", "context_percent", "context_used",
                "estimated_total", "context_estimated", "context_source", "model"}
    if not isinstance(value, dict) or set(value) != expected:
        return {"state": "unknown"}
    categories = value["categories"]
    if not isinstance(categories, list) or len(categories) > _MAX_CATEGORIES:
        return {"state": "unknown"}
    decoded: list[dict[str, Any]] = []
    seen: set[str] = set()
    total = 0
    for row in categories:
        if not isinstance(row, dict) or set(row) != {"id", "label", "tokens"}:
            return {"state": "unknown"}
        category_id = _safe_label(row["id"], pattern=re.compile(r"^[a-z][a-z0-9_-]{0,47}$"))
        label = _CONTEXT_LABELS.get(category_id)
        tokens = row["tokens"]
        if (category_id is None or category_id in seen or label is None
                or type(tokens) is not int or not 0 <= tokens <= _MAX_CONTEXT_TOKENS):
            return {"state": "unknown"}
        total += tokens
        if total > _MAX_CONTEXT_TOKENS:
            return {"state": "unknown"}
        seen.add(category_id)
        decoded.append({"id": category_id, "label": label, "tokens": tokens})

    maximum, used = value["context_max"], value["context_used"]
    percent, estimated_total = value["context_percent"], value["estimated_total"]
    estimated, source, model = value["context_estimated"], value["context_source"], value["model"]
    if (type(maximum) is not int or not 0 <= maximum <= _MAX_CONTEXT_TOKENS
            or type(used) is not int or not 0 <= used <= _MAX_CONTEXT_TOKENS
            or type(percent) is not int or not 0 <= percent <= 100
            or type(estimated_total) is not int or not 0 <= estimated_total <= _MAX_CONTEXT_TOKENS
            or type(estimated) is not bool):
        return {"state": "unknown"}
    safe_source = source if isinstance(source, str) and source in _CONTEXT_SOURCES else None
    safe_model = _safe_label(model, pattern=_IDENTIFIER) if model else ""
    if safe_source is None or safe_model is None:
        return {"state": "unknown"}
    return {
        "state": "observed",
        "contextMax": maximum,
        "contextUsed": used,
        "contextPercent": percent,
        "estimatedTotal": estimated_total,
        "estimated": estimated,
        "source": safe_source,
        "model": safe_model,
        "categories": decoded,
    }


def decode_session_status(value: Any) -> dict[str, Any]:
    """Extract only harmless allowlisted labels from Hermes' rendered status text."""
    if not isinstance(value, dict) or set(value) != {"output"}:
        return {"state": "unknown", "running": None, "created": None,
                "lastActivity": None, "tokens": None}
    output = value["output"]
    if not isinstance(output, str) or len(output) > 8_192:
        return {"state": "unknown", "running": None, "created": None,
                "lastActivity": None, "tokens": None}
    values: dict[str, str] = {}
    allowed = {"Agent Running", "Created", "Last Activity", "Tokens"}
    for line in output.splitlines():
        if ": " not in line:
            continue
        key, item = line.split(": ", 1)
        if key not in allowed:
            continue
        if key in values:
            return {"state": "unknown", "running": None, "created": None,
                    "lastActivity": None, "tokens": None}
        values[key] = item
    running_text = values.get("Agent Running")
    running = {"Yes": True, "No": False}.get(running_text)
    created = values.get("Created")
    last_activity = values.get("Last Activity")
    tokens_text = values.get("Tokens")
    if running is not None and created is not None and last_activity is not None and tokens_text is not None:
        if (_STATUS_STAMP.fullmatch(created) and _STATUS_STAMP.fullmatch(last_activity)
                and len(tokens_text) <= 12 and _TOKEN_COUNT.fullmatch(tokens_text)):
            return {"state": "observed", "running": running, "created": created,
                    "lastActivity": last_activity, "tokens": int(tokens_text.replace(",", ""))}
    return {"state": "unknown", "running": None, "created": None,
            "lastActivity": None, "tokens": None}


def _unavailable() -> dict[str, Any]:
    return {
        "schema": 1,
        "state": "partial",
        "status": {"state": "unknown", "running": None, "created": None,
                    "lastActivity": None, "tokens": None},
        "context": {"state": "unknown"},
        "primaryPersona": {"state": "pending", "reason": "verified-primary-source-not-connected"},
        "workspace": {"state": "pending", "reason": "reviewed-owned-workspace-read-not-connected"},
    }


async def _context_route(request: Any, service: JarvisChatService) -> Any:
    from aiohttp import web

    if request.raw_path != request.path:
        raise web.HTTPNotFound(text="not found", headers=_secure_headers())
    try:
        principal = service._current(request)
        conversation_id = request.match_info.get("conversation_id", "")
        if not ID_RE.fullmatch(conversation_id):
            raise JarvisChatDenied("conversation is unavailable")
        conversation = service.store.get_conversation(principal.subject, conversation_id)
        if conversation["core_generation"] != principal.core_generation:
            raise JarvisChatDenied("conversation is unavailable")
        native_session_id = conversation["backend_id"]
        context_method = getattr(service.backend, "session_context_breakdown", None)
        status_method = getattr(service.backend, "session_status", None)
        context_result = status_result = None
        if callable(context_method) and callable(status_method):
            try:
                context_result, status_result = await asyncio.wait_for(
                    asyncio.gather(
                        context_method(native_session_id),
                        status_method(native_session_id),
                        return_exceptions=True,
                    ), timeout=4.0)
            except (asyncio.TimeoutError, Exception):
                context_result = status_result = None
        current = service._current(request)
        latest = service.store.get_conversation(current.subject, conversation_id)
        if (current.subject != principal.subject
                or current.core_generation != principal.core_generation
                or latest["core_generation"] != principal.core_generation
                or latest["backend_id"] != native_session_id):
            raise JarvisChatDenied("conversation changed during context read")
        context = (decode_context_breakdown(context_result)
                   if not isinstance(context_result, BaseException) else {"state": "unknown"})
        status = (decode_session_status(status_result)
                  if not isinstance(status_result, BaseException) else
                  {"state": "unknown", "running": None, "created": None,
                   "lastActivity": None, "tokens": None})
        payload = {
            "schema": 1,
            "state": "observed" if context["state"] == "observed" else "partial",
            "conversationId": conversation_id,
            "status": status,
            "context": context,
            "primaryPersona": {"state": "pending", "reason": "verified-primary-source-not-connected"},
            "workspace": {"state": "pending", "reason": "reviewed-owned-workspace-read-not-connected"},
        }
        return web.json_response(payload, headers=_secure_headers())
    except JarvisChatDenied:
        raise web.HTTPForbidden(text="forbidden", headers=_secure_headers()) from None
    except web.HTTPException:
        raise
    except Exception:
        raise web.HTTPServiceUnavailable(text="context unavailable", headers=_secure_headers()) from None


def install_jarvis_context_routes(app: Any, service: Any) -> None:
    """Install one finite authenticated read for an owner-selected Jarvis conversation."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def route(request: Any) -> Any:
        return await _context_route(request, service)

    app.router.add_get(FEATURE_ROUTES[0][1], route, allow_head=False)
