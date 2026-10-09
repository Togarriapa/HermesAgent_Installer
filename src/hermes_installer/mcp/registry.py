"""Owned MCP service catalog and fail-closed connection registry.

Catalog metadata is not dispatch authority. Every RPC is still authorized by the
host-issued DispatchContext/ContextAuthorizer in MCPClient.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..policy import ContextAuthorizer, DispatchContext
from .adapters import MCPService, ReadOnlyAdapter
from .client import MCPClient
from .transports import StdioTransport, StreamableHTTPTransport


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Immutable source identity copied from an owned, reviewed source manifest."""
    service_id: str
    uri: str
    revision: str
    digest: str
    provenance: str

    def __post_init__(self) -> None:
        if (not self.service_id or not self.uri.startswith(("https://", "git+https://"))
                or not self.revision or len(self.revision) > 128
                or len(self.digest) != 64
                or any(char not in "0123456789abcdef" for char in self.digest)
                or not self.provenance.startswith("sha256:")
                or len(self.provenance) != 71):
            raise ValueError("MCP source record is incomplete or unpinned")


# Tool names are metadata filters only. The tool's discovered JSON schema and
# the actual host-issued read grant are also checked before each call.
SERVICES: Mapping[str, MCPService] = {
    "figma": MCPService("figma", "https://mcp.figma.com/mcp",
        frozenset({"get_design_context", "get_metadata", "get_file", "get_file_nodes",
                   "get_screenshot", "download_assets", "get_figjam"}),
        "Figma OAuth", "one selected file", True,
        "https://developers.figma.com/docs/figma-mcp-server/tools-and-prompts/"),
    "revenuecat": MCPService("revenuecat", "https://mcp.revenuecat.ai/mcp",
        frozenset({"list_projects", "get_project", "list_apps", "get_app"}),
        "RevenueCat OAuth or scoped API v2 key", "one selected project", True,
        "https://www.revenuecat.com/docs/tools/mcp/tools-reference"),
    "google-gmail": MCPService("google-gmail", "https://gmailmcp.googleapis.com/mcp/v1",
        frozenset(), "Google Workspace Developer Preview OAuth", "one selected Gmail resource", True,
        "https://developers.google.com/workspace/preview"),
    "google-drive": MCPService("google-drive", "https://drivemcp.googleapis.com/mcp/v1",
        frozenset(), "Google Workspace Developer Preview OAuth", "one selected Drive resource", True,
        "https://developers.google.com/workspace/preview"),
    "google-calendar": MCPService("google-calendar", "https://calendarmcp.googleapis.com/mcp/v1",
        frozenset(), "Google Workspace Developer Preview OAuth", "one selected Calendar resource", True,
        "https://developers.google.com/workspace/preview"),
    "google-chat": MCPService("google-chat", "https://chatmcp.googleapis.com/mcp/v1",
        frozenset(), "Google Workspace Developer Preview OAuth", "one selected Chat resource", True,
        "https://developers.google.com/workspace/preview"),
    "google-people": MCPService("google-people", "https://people.googleapis.com/mcp/v1",
        frozenset(), "Google Workspace Developer Preview OAuth", "one selected People resource", True,
        "https://developers.google.com/workspace/preview"),
    "home-assistant": MCPService("home-assistant", None,
        frozenset(), "existing Home Assistant token/OAuth", "explicit selected entities", True,
        "https://www.home-assistant.io/integrations/mcp_server"),
    "google-community": MCPService("google-community", None,
        frozenset(), "user-configured OAuth", "one selected Google resource", False,
        "https://github.com/taylorwilsdon/google_workspace_mcp"),
    "playwright": MCPService("playwright", None,
        frozenset(), "host-managed pinned local process", "fresh isolated local fixture", True,
        "https://playwright.dev/docs/getting-started-mcp"),
}


class MCPConnectionRegistry:
    """Construct only catalog-bound clients; I/O still requires host authority."""

    def __init__(self, *, context: DispatchContext | None,
                 context_authorizer: ContextAuthorizer | None,
                 sources: Mapping[str, SourceRecord] | None = None,
                 timeout: float = 9.0) -> None:
        if not 0 < timeout <= 9:
            raise ValueError("MCP startup timeout must be in (0, 9] seconds")
        self.context = context
        self.context_authorizer = context_authorizer
        self.sources = dict(sources or {})
        self.timeout = timeout

    def connect(self, service_id: str, transport, *, selection,
                allowed_tools: frozenset[str] | None = None,
                result_scrubber=None) -> ReadOnlyAdapter:
        try:
            service = SERVICES[service_id]
        except KeyError:
            raise ValueError("MCP service is not in the reviewed catalog") from None
        if not isinstance(transport, (StdioTransport, StreamableHTTPTransport)):
            raise TypeError("MCP transport must be a bounded first-party transport")
        if getattr(transport, "service_id", None) != service_id:
            raise PermissionError("MCP transport is not bound to the selected service")
        if service.endpoint is not None:
            if getattr(transport, "endpoint", None) != service.endpoint:
                raise PermissionError("MCP endpoint differs from the reviewed service endpoint")
        elif service_id in {"home-assistant"}:
            # HA's user-selected existing instance URL is allowed by its adapter,
            # but its network origin still must be authorized by the host.
            if not isinstance(transport, StreamableHTTPTransport):
                raise PermissionError("Home Assistant must use its documented remote HTTP endpoint")
        elif service_id == "playwright":
            if not isinstance(transport, StdioTransport):
                raise PermissionError("Playwright requires the host-managed local process")
        elif service_id == "google-community":
            if not isinstance(transport, StdioTransport):
                raise PermissionError("The community Google option requires pinned supervised stdio")
            if service_id not in self.sources:
                raise PermissionError("Community source revision and digest are not owned and pinned")
        else:
            raise PermissionError("This MCP transport requires a reviewed endpoint binding")
        tools = service.allowed_tools
        if allowed_tools is not None:
            if not allowed_tools <= tools:
                raise PermissionError("MCP requested tools exceed the reviewed read-only allowlist")
            tools = allowed_tools
        client = MCPClient(
            transport, tools, service_id=service_id, selection=selection,
            dispatch_context=self.context, context_authorizer=self.context_authorizer,
            timeout=self.timeout, result_scrubber=result_scrubber,
        )
        return ReadOnlyAdapter(service, client, selection)
