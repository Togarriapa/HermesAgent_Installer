"""Root-only MCP HTTP bindings for the protected authority broker.

This module does not read worker config, environment variables, URLs, or secrets.
The daemon supplies immutable enrollment records and custody-owned credential
handles. Service routes are pinned to the reviewed first-party source catalog.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from .broker import BrokerMCPTransport, ProtectedMCPService, build_mcp_handlers
from .transports import StreamableHTTPTransport, TransportError

_ENDPOINT_SOURCES = MappingProxyType({
    "figma": ("https://mcp.figma.com/mcp",
              "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/"),
    "revenuecat": ("https://mcp.revenuecat.ai/mcp",
                   "https://www.revenuecat.com/docs/tools/mcp/setup"),
    "google-gmail": ("https://gmailmcp.googleapis.com/mcp/v1",
                     "https://developers.google.com/workspace/gmail/api/reference/mcp/tools_list/get_message"),
    "google-drive": ("https://drivemcp.googleapis.com/mcp/v1",
                     "https://developers.google.com/workspace/drive/api/reference/mcp/tools_list/get_file_metadata"),
    "google-docs": ("https://docsmcp.googleapis.com/mcp",
                    "https://developers.google.com/workspace/guides/configure-mcp-servers"),
    "google-sheets": ("https://sheetsmcp.googleapis.com/mcp",
                      "https://developers.google.com/workspace/guides/configure-mcp-servers"),
    "google-calendar": ("https://calendarmcp.googleapis.com/mcp/v1",
                        "https://developers.google.com/workspace/calendar/api/v3/reference/mcp/tools_list/list_events"),
    "google-contacts": ("https://people.googleapis.com/mcp/v1",
                        "https://developers.google.com/people/api/mcp"),
})


class MCPHTTPBindingError(ValueError):
    """A root-protected endpoint/credential binding failed validation."""


@dataclass(frozen=True, slots=True)
class ProtectedMCPHTTPBinding:
    """Host-loaded endpoint and opaque custody handle; never sent to workers."""
    binding_id: str
    service_id: str
    endpoint: str = field(repr=False)
    endpoint_source_id: str
    reviewed_revision: str
    credential_handle: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        for field_name, value in (("binding_id", self.binding_id),
                                  ("service_id", self.service_id),
                                  ("endpoint_source_id", self.endpoint_source_id)):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise MCPHTTPBindingError(f"protected HTTP {field_name} is invalid")
        expected = _ENDPOINT_SOURCES.get(self.service_id)
        if expected is None or (self.endpoint, self.endpoint_source_id) != expected:
            raise MCPHTTPBindingError("MCP endpoint/provenance is not in the reviewed official source catalog")
        parsed = urlsplit(self.endpoint)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.query or parsed.fragment):
            raise MCPHTTPBindingError("protected MCP endpoint must be a fixed HTTPS URL")
        if (not isinstance(self.reviewed_revision, str)
                or len(self.reviewed_revision) != 64
                or any(ch not in "0123456789abcdef" for ch in self.reviewed_revision)):
            raise MCPHTTPBindingError("MCP HTTP binding requires a pinned reviewed revision")
        handle = self.credential_handle
        if handle is None or not callable(getattr(handle, "headers_for", None)):
            raise MCPHTTPBindingError("MCP credential must be an opaque custody-owned handle")


class _LoopRunner:
    """One bounded event loop per host transport, preserving MCP session state."""
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self._run, name="mcp-http-broker", daemon=True)
        self.thread.start()
        if not self.ready.wait(1.0):
            raise TransportError("MCP broker event loop did not start")

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.ready.set()
        self.loop.run_forever()

    def call(self, awaitable, *, timeout: float,
             cancelled: Callable[[], bool], monotonic: Callable[[], float]) -> Any:
        future = asyncio.run_coroutine_threadsafe(awaitable, self.loop)
        deadline = monotonic() + timeout
        try:
            while True:
                if cancelled():
                    future.cancel()
                    raise TransportError("MCP request was cancelled")
                remaining = deadline - monotonic()
                if remaining <= 0:
                    future.cancel()
                    raise TransportError("MCP request deadline expired")
                try:
                    return future.result(timeout=min(0.05, remaining))
                except concurrent.futures.TimeoutError:
                    continue
        finally:
            if not future.done():
                future.cancel()


class _BrokeredHTTPTransport:
    def __init__(self, binding: ProtectedMCPHTTPBinding,
                 *, monotonic: Callable[[], float]) -> None:
        self._runner = _LoopRunner()
        self._transport = StreamableHTTPTransport(
            binding.endpoint, service_id=binding.service_id,
            credential_handle=binding.credential_handle, timeout=9.0,
            monotonic=monotonic,
        )
        self._monotonic = monotonic
        self._lock = threading.Lock()

    def exchange(self, request: Mapping[str, Any], *, context, authorization,
                 timeout: float, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not 0 < timeout <= 9 or cancelled()):
            raise TransportError("MCP request deadline is invalid")
        acquired = self._lock.acquire(timeout=min(float(timeout), 0.05))
        if not acquired:
            raise TransportError("MCP service already has an active bounded request")
        try:
            if cancelled():
                raise TransportError("MCP request was cancelled")
            self._transport.timeout = min(float(timeout), 9.0)
            return self._runner.call(
                self._transport.request(
                    request, dispatch_context=context,
                    dispatch_authorization=authorization,
                ),
                timeout=float(timeout), cancelled=cancelled, monotonic=self._monotonic,
            )
        finally:
            self._lock.release()


class ProtectedMCPHTTPTransportFactory:
    """Resolve exact enrolled binding IDs to root-owned fixed HTTP transports."""
    def __init__(self, bindings: Mapping[str, ProtectedMCPHTTPBinding], *,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if not isinstance(bindings, Mapping):
            raise MCPHTTPBindingError("protected MCP HTTP binding map is required")
        copied = dict(bindings)
        for binding_id, binding in copied.items():
            if (type(binding) is not ProtectedMCPHTTPBinding
                    or binding.binding_id != binding_id):
                raise MCPHTTPBindingError("protected MCP HTTP binding map identity mismatch")
        self._bindings = MappingProxyType(copied)
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._transports: dict[tuple[int, str, str], _BrokeredHTTPTransport] = {}

    def __call__(self, service: ProtectedMCPService, context) -> BrokerMCPTransport:
        if service.channel != "http":
            raise MCPHTTPBindingError("stdio transport is unavailable without supervisor lease integration")
        binding = self._bindings.get(service.transport_binding_id)
        if (binding is None or binding.service_id != service.service_id
                or binding.reviewed_revision != service.reviewed_revision):
            raise MCPHTTPBindingError("MCP service has no exact root-owned HTTP binding")
        key = (context.uid, context.profile_id, service.service_id)
        with self._lock:
            existing = self._transports.get(key)
            if existing is not None:
                return existing
            transport = _BrokeredHTTPTransport(binding, monotonic=self._monotonic)
            self._transports[key] = transport
            return transport


def build_enrolled_mcp_handlers(
    protected_services: Mapping[str, ProtectedMCPService],
    http_bindings: Mapping[str, ProtectedMCPHTTPBinding],
    *, monotonic: Callable[[], float] = time.monotonic,
) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Build handlers from root-issued services and endpoint enrollments.

    Unsupported channels and services without an exact binding are omitted so
    the authority effect remains unavailable. No endpoint, command, or secret
    is accepted from worker config or a caller-provided factory.
    """
    if not isinstance(protected_services, Mapping) or not isinstance(http_bindings, Mapping):
        raise MCPHTTPBindingError("protected MCP enrollment maps are required")
    eligible: dict[str, ProtectedMCPService] = {}
    binding_map = dict(http_bindings)
    for service_id, service in protected_services.items():
        if type(service) is not ProtectedMCPService or service.service_id != service_id:
            raise MCPHTTPBindingError("protected MCP service map identity mismatch")
        binding = binding_map.get(service.transport_binding_id)
        if (service.channel == "http" and binding is not None
                and type(binding) is ProtectedMCPHTTPBinding
                and binding.service_id == service_id
                and binding.reviewed_revision == service.reviewed_revision):
            eligible[service_id] = service
    if not eligible:
        return MappingProxyType({})
    factory = ProtectedMCPHTTPTransportFactory(binding_map, monotonic=monotonic)
    return build_mcp_handlers(eligible, transport_factory=factory, monotonic=monotonic)
