"""Explicitly community-maintained Google Workspace MCP adapter."""
from __future__ import annotations

from .adapters import ReadOnlyAdapter, SERVICES
from .registry import SourceRecord


def adapter(client, *, source: SourceRecord, resource_id: str):
    if not isinstance(source, SourceRecord) or source.service_id != "google-community":
        raise PermissionError("community source provenance is not owned and pinned")
    if source.uri != SERVICES["google-community"].source_uri:
        raise PermissionError("community source URL differs from the catalog")
    if not resource_id or len(resource_id) > 512:
        raise ValueError("select one bounded Google resource")
    # Source metadata does not grant dispatch authority. Tool schema/effect
    # allowlisting and the host authorizer are still required.
    raise PermissionError("community server read-tool and effect review is pending")
