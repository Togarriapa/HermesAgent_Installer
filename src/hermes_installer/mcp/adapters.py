"""Read-only MCP service policy, independent of user-provided labels."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class MCPService:
    id: str
    endpoint: str | None
    allowed_tools: frozenset[str]
    auth_kind: str
    selection_required: str
    official: bool = True
    source_uri: str | None = None


SERVICES: Mapping[str, MCPService] = {
    "figma": MCPService("figma", "https://mcp.figma.com/mcp",
        frozenset({"get_design_context", "get_metadata", "get_screenshot", "download_assets",
                   "get_figjam", "get_variable_defs", "get_motion_context", "get_libraries",
                   "search_design_system", "get_code_connect_map", "get_context_for_code_connect"}),
        "Figma OAuth", "selected file", True,
        "https://developers.figma.com/docs/figma-mcp-server/tools-and-prompts/"),
    "revenuecat": MCPService("revenuecat", "https://mcp.revenuecat.ai/mcp",
        frozenset({"get-app", "list-apps", "get-project-ui-config", "get-refund-request-preferences",
                   "list-audit-logs", "list-collaborators", "get-product", "list-products",
                   "get-entitlement", "list-entitlements", "get-offering", "list-offerings",
                   "get-paywall", "list-paywalls", "get-overview-metrics", "get-revenue-metric"}),
        "RevenueCat OAuth or scoped API v2 key", "selected project", True,
        "https://www.revenuecat.com/docs/tools/mcp/tools-reference"),
    "google-gmail": MCPService("google-gmail", "https://gmailmcp.googleapis.com/mcp/v1",
        frozenset({"get_message", "get_thread"}),
        "Google Workspace Developer Preview OAuth", "one selected message or thread", True,
        "https://developers.google.com/workspace/gmail/api/reference/mcp"),
    "google-drive": MCPService("google-drive", "https://drivemcp.googleapis.com/mcp/v1",
        frozenset({"get_file_metadata", "read_file_content"}),
        "Google Workspace Developer Preview OAuth", "one selected Drive file", True,
        "https://developers.google.com/workspace/drive/api/reference/mcp"),
    "google-docs": MCPService("google-docs", "https://docsmcp.googleapis.com/mcp",
        frozenset({"read_doc"}), "Google Workspace Developer Preview OAuth",
        "one selected Docs document", True,
        "https://developers.google.com/workspace/docs/api/reference/mcp"),
    "google-sheets": MCPService("google-sheets", "https://sheetsmcp.googleapis.com/mcp",
        frozenset({"get_spreadsheet", "get_values"}), "Google Workspace Developer Preview OAuth",
        "one selected spreadsheet", True,
        "https://developers.google.com/workspace/sheets/api/reference/mcp"),
    "google-calendar": MCPService("google-calendar", "https://calendarmcp.googleapis.com/mcp/v1",
        frozenset({"get_event", "list_events"}),
        "Google Workspace Developer Preview OAuth", "one selected event or calendar", True,
        "https://developers.google.com/workspace/calendar/api/v3/reference/mcp"),
    "google-contacts": MCPService("google-contacts", "https://people.googleapis.com/mcp/v1",
        frozenset({"search_contacts", "get_user_profile"}),
        "Google Workspace Developer Preview OAuth", "one explicitly selected directory person", True,
        "https://developers.google.com/people/api/mcp"),
    "home-assistant": MCPService("home-assistant", None,
        frozenset(), "existing Home Assistant token/OAuth", "explicit selected entities", True,
        "https://www.home-assistant.io/integrations/mcp_server"),
    "google-community": MCPService("google-community", None,
        frozenset(), "user-configured OAuth", "one selected Google resource", False,
        "https://github.com/taylorwilsdon/google_workspace_mcp"),
    "playwright": MCPService("playwright", None,
        frozenset({"browser_navigate", "browser_snapshot", "browser_screenshot"}), "host-managed pinned local process", "isolated loopback fixture", True,
        "https://playwright.dev/docs/getting-started-mcp"),
}


class ReadOnlyAdapter:
    """Connection state is earned by real authorized protocol responses.

    Discovery alone never enables a connector. A separate harmless selected
    resource read must succeed before functional testing is recorded.
    """

    def __init__(self, service: MCPService, client, selection):
        if not isinstance(service, MCPService):
            raise TypeError("MCP service definition is required")
        if getattr(client, "service_id", None) not in (None, service.id):
            raise ValueError("MCP client is bound to a different service")
        self.service, self.client, self.selection = service, client, selection
        self._functional = False
        self._enabled = False
        self._last_failure: str | None = None

    def _authorization_ready(self) -> bool:
        return bool(getattr(self.client, "context", None)
                    and getattr(self.client, "authorizer", None) is not None)

    def status(self) -> dict:
        client = self.client
        ready = bool(getattr(client, "ready", False))
        return {
            "service": self.service.id,
            "official": self.service.official,
            "source": self.service.source_uri,
            "selection": self.selection,
            "protocol": getattr(client, "protocol_version", None),
            "transport_ready": ready,
            "authorized": self._authorization_ready(),
            "discovered": ready,
            "tools": tuple(sorted(getattr(client, "discovered_tools", frozenset()) &
                                  self.service.allowed_tools)),
            "functionally_tested": self._functional,
            "enabled": self._enabled,
            "last_failure": self._last_failure,
        }

    async def inspect(self, *, timeout: float = 9.0) -> dict:
        if not 0 < timeout <= 9:
            raise ValueError("MCP inspect deadline must be in (0, 9] seconds")
        if not self._authorization_ready():
            result = self.status()
            result["status"] = "pending_trusted_host_authorization"
            return result
        clock = getattr(self.client, "monotonic", time.monotonic)
        deadline = clock() + timeout
        try:
            init = await self.client.initialize(deadline=deadline)
            discovered = await self.client.discover(deadline=deadline)
        except Exception:
            self._last_failure = "initialize_or_discovery_failed"
            result = self.status()
            result["status"] = self._last_failure
            return result
        self.client.allowed_tools = frozenset(self.client.allowed_tools & self.service.allowed_tools)
        # Even allowlisted names are rejected unless the server advertises the
        # MCP read-only hint. The static list remains the authoritative ceiling.
        accepted = {}
        for name, schema in discovered.items():
            annotations = schema.get("annotations", {})
            if (name in self.client.allowed_tools
                    and annotations.get("readOnlyHint") is not False
                    and annotations.get("destructiveHint") is not True):
                accepted[name] = schema
        self.client._tools = accepted
        result = self.status()
        result.update({"protocol": init["protocolVersion"],
                       "status": "discovered_read_only_tools" if result["tools"]
                                 else "no_reviewed_read_only_tools"})
        return result

    async def read(self, name: str, arguments: Mapping, *, timeout: float = 9.0):
        if not 0 < timeout <= 9:
            raise ValueError("MCP read deadline must be in (0, 9] seconds")
        if not self.selection or name not in self.service.allowed_tools:
            raise PermissionError("read outside the reviewed tool and selected-resource policy")
        if not self._authorization_ready():
            raise PermissionError("trusted host authorization is unavailable")
        if name not in getattr(self.client, "discovered_tools", frozenset()):
            raise PermissionError("MCP read tool has not passed live schema review")
        clock = getattr(self.client, "monotonic", time.monotonic)
        try:
            result = await self.client.call_read(name, arguments, deadline=clock() + timeout)
        except Exception:
            self._last_failure = "selected_resource_read_failed"
            raise
        self._functional = True
        self._last_failure = None
        return result

    def enable(self) -> None:
        if not self._functional or not self._authorization_ready():
            raise PermissionError("a harmless selected-resource read and trusted host authorization are required")
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False
