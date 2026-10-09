"""Official Google Workspace Developer Preview MCP read adapters."""
from __future__ import annotations

from .adapters import ReadOnlyAdapter, SERVICES


def adapter(client, *, service: str, resource_id: str, preview_eligible: bool | None = None):
    service_id = "google-" + service
    if service_id not in SERVICES:
        raise ValueError("unsupported official Google Workspace service")
    if not isinstance(resource_id, str) or not resource_id.strip() or len(resource_id) > 512:
        raise ValueError("select one bounded Google resource identifier")
    if preview_eligible is False:
        raise PermissionError("Google Workspace Developer Preview eligibility is unavailable")
    # preview_eligible=True is guidance only. MCPClient's host-issued grant is
    # mandatory and the tool must match a reviewed read-only catalog contract.
    return ReadOnlyAdapter(SERVICES[service_id], client, resource_id)
