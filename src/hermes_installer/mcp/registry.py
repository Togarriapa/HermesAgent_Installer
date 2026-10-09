"""Owned MCP service catalog and fail-closed connection registry.

Catalog metadata is not dispatch authority. Every RPC is authorized by the
host-issued DispatchContext and ContextAuthorizer in MCPClient.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from ..policy import ContextAuthorizer, DispatchContext
from ..authority import AuthorityClient
from .adapters import MCPService, ReadOnlyAdapter, SERVICES
from .client import MCPClient
from .transports import StdioTransport, StreamableHTTPTransport, is_supervised_stdio_handle
from .privacy import scrub_mcp_result


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Immutable source identity copied from an owned reviewed-source manifest."""
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


class MCPConnectionRegistry:
    """Construct catalog-bound clients; I/O still requires host authority."""

    def __init__(self, *, context: DispatchContext | None,
                 context_authorizer: ContextAuthorizer | None,
                 sources: Mapping[str, SourceRecord] | None = None,
                 timeout: float = 9.0,
                 authority_client: AuthorityClient | None = None) -> None:
        if not 0 < timeout <= 9:
            raise ValueError("MCP startup timeout must be in (0, 9] seconds")
        self.context = context
        self.context_authorizer = context_authorizer
        self.sources = dict(sources or {})
        if authority_client is not None and type(authority_client) is not AuthorityClient:
            raise TypeError("MCP registry requires the first-party host authority client")
        self.authority_client = authority_client
        self.timeout = timeout

    def connect(self, service_id: str, transport, *, selection,
                allowed_tools: frozenset[str] | None = None,
                result_scrubber=None) -> ReadOnlyAdapter:
        if self.authority_client is None:
            fixture = getattr(self.context, "capabilities", frozenset())
            if "mcp:test:stdio" not in fixture and "mcp:test:loopback" not in fixture:
                raise PermissionError("protected host authority is required for MCP service I/O")
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
        elif service_id == "home-assistant":
            if (not isinstance(transport, StreamableHTTPTransport)
                    or self.authority_client is None):
                raise PermissionError("Home Assistant requires host-brokered Streamable HTTP")
        elif service_id == "playwright":
            if not isinstance(transport, StdioTransport) or not is_supervised_stdio_handle(transport._handle, service_id):
                raise PermissionError("Playwright requires a live supervisor-issued pinned process")
        elif service_id == "google-community":
            record = self.sources.get(service_id)
            if (not isinstance(transport, StdioTransport)
                    or not is_supervised_stdio_handle(transport._handle, service_id)
                    or not isinstance(record, SourceRecord) or record.service_id != service_id
                    or record.uri != service.source_uri):
                raise PermissionError("Community source revision, digest and supervised command must be owned and pinned")
            raise PermissionError("Community tool schema/effect review is pending")
        else:
            raise PermissionError("This MCP transport requires a reviewed endpoint binding")
        tools = service.allowed_tools
        if service_id == "home-assistant":
            # Home Assistant exposes the selected LLM API's live tools. The local
            # list is only a client ceiling; the protected broker independently
            # intersects it with root enrollment and explicit read-only schemas.
            if (self.authority_client is None or not allowed_tools
                    or any(not isinstance(name, str) or not name or len(name) > 128
                           for name in allowed_tools)):
                raise PermissionError("Home Assistant requires an explicit host-brokered tool ceiling")
            tools = frozenset(allowed_tools)
        elif allowed_tools is not None:
            if not allowed_tools <= tools:
                raise PermissionError("MCP requested tools exceed the reviewed read-only allowlist")
            tools = allowed_tools
        service_scrubber = scrub_mcp_result(service_id)
        if result_scrubber is not None and not callable(result_scrubber):
            raise TypeError("MCP result scrubber must be callable")
        if result_scrubber is None:
            result_scrubber = service_scrubber
        else:
            supplied_scrubber = result_scrubber
            result_scrubber = lambda value: service_scrubber(supplied_scrubber(value))
        client = MCPClient(
            transport, tools, service_id=service_id, selection=selection,
            dispatch_context=self.context, context_authorizer=self.context_authorizer,
            timeout=self.timeout, result_scrubber=result_scrubber,
            authority_client=self.authority_client,
        )
        return ReadOnlyAdapter(service, client, selection)
