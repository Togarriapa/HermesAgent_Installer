"""Home Assistant adapter backed only by a protected MCP broker binding.

The endpoint is selected in root-owned enrollment and never accepted here.
Home Assistant's exposed LLM API supplies live tool names; this profile-side
list is a local ceiling, while the authority broker enforces the protected
service allowlist and per-tool read-only/schema/selection policy.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from ..authority import AuthorityClient
from .adapters import MCPService, ReadOnlyAdapter
from .transports import StreamableHTTPTransport


_ENTITY_ID = re.compile(r"[a-z0-9_]+\.[a-z0-9_]+\Z")


def adapter(client, *, entity_ids: Iterable[str], allowed_tools: Iterable[str]) -> ReadOnlyAdapter:
    authority = getattr(client, "authority_client", None)
    if type(authority) is not AuthorityClient:
        raise PermissionError("Home Assistant requires the first-party host authority")
    transport = getattr(client, "transport", None)
    if (getattr(client, "service_id", None) != "home-assistant"
            or not isinstance(transport, StreamableHTTPTransport)):
        raise PermissionError("Home Assistant requires a host-brokered HTTP client")
    entities = tuple(entity_ids)
    if (not 1 <= len(entities) <= 64
            or any(not isinstance(item, str) or not _ENTITY_ID.fullmatch(item)
                   for item in entities)
            or len(set(entities)) != len(entities)):
        raise ValueError("select one to 64 exact Home Assistant entity IDs")
    tools = frozenset(allowed_tools)
    if (not tools or any(not isinstance(name, str) or not name or len(name) > 128
                         for name in tools)
            or not tools <= frozenset(getattr(client, "allowed_tools", ()))):
        raise ValueError("Home Assistant tool ceiling must be explicit and bounded")
    selection = {"entity_id": entities[0], "entity_ids": list(entities)}
    service = MCPService(
        "home-assistant", None, tools, "host-held instance credential",
        "explicit entity selection", True,
        "https://www.home-assistant.io/integrations/mcp_server/",
    )
    return ReadOnlyAdapter(service, client, selection)
