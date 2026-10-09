"""Official Google Workspace MCP catalog adapter.

Developer Preview membership and project service enablement are verified by the
host policy at each effect; this adapter accepts no caller-provided eligibility
booleans. See Google's primary setup guide in the service source metadata.
"""
from __future__ import annotations

from .adapters import ReadOnlyAdapter, SERVICES


def adapter(client, *, service: str, resource_id: str):
    service_id = "google-" + service
    if service_id not in SERVICES:
        raise ValueError("unsupported official Google Workspace service")
    if not isinstance(resource_id, str) or not resource_id.strip() or len(resource_id) > 512:
        raise ValueError("select one bounded Google resource identifier")
    return ReadOnlyAdapter(SERVICES[service_id], client, resource_id)
