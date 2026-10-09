"""Reviewed MCP result privacy filtering applied before data leaves an adapter."""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, Callable

_REVIEWED_SERVICES = frozenset({
    "figma", "revenuecat", "google-gmail", "google-drive", "google-docs",
    "google-sheets", "google-calendar", "google-contacts", "home-assistant",
    "playwright", "google-community",
})
_SECRET_KEY = re.compile(
    r"(?:^|[_-])(access[_-]?token|refresh[_-]?token|api[_-]?key|secret|password|"
    r"authorization|cookie|client[_-]?secret|credential)(?:$|[_-])", re.I
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_SECRET_ASSIGNMENT = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|refresh[_-]?token|password)\s*[:=]\s*[^\s,;]+")


class MCPPrivacyError(ValueError):
    """MCP result cannot be safely filtered."""


def _scrub(value: Any, depth: int = 0) -> Any:
    if depth > 24:
        raise MCPPrivacyError("MCP result is too deeply nested")
    if isinstance(value, Mapping):
        if len(value) > 4096:
            raise MCPPrivacyError("MCP result object exceeds its field bound")
        result = {}
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 256:
                raise MCPPrivacyError("MCP result has an invalid field name")
            if _SECRET_KEY.search(key):
                continue
            result[key] = _scrub(item, depth + 1)
        return result
    if isinstance(value, (list, tuple)):
        if len(value) > 4096:
            raise MCPPrivacyError("MCP result array exceeds its item bound")
        return [_scrub(item, depth + 1) for item in value]
    if isinstance(value, str):
        if len(value) > 262_144:
            raise MCPPrivacyError("MCP result string exceeds its bound")
        return _SECRET_ASSIGNMENT.sub(r"\1=[REDACTED]", _BEARER.sub("Bearer [REDACTED]", value))
    if value is None or type(value) in (bool, int, float):
        return value
    raise MCPPrivacyError("MCP result contains an unsupported value")


def scrub_mcp_result(service_id: str) -> Callable[[Any], Any]:
    """Return the reviewed scrubber for one enabled service identity."""
    if service_id not in _REVIEWED_SERVICES:
        raise MCPPrivacyError("no reviewed result scrubber exists for this MCP service")

    def scrub(value: Any) -> Any:
        return _scrub(value)

    return scrub
