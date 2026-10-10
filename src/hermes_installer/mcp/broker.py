"""Protected, fixed-target MCP broker handlers.

The authority daemon injects immutable service records and the only transport
factory. Workers submit a bounded JSON-RPC intent, never a URL or command.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol

from ..authority import (
    AuthorityDenied, EffectAuthorization, HostContext, canonical_bytes,
    canonical_digest,
)
from .client import (
    MAX_RESULT_BYTES, MAX_SCHEMA_BYTES, MAX_TOOLS, SUPPORTED_PROTOCOL_VERSIONS,
    MCPError, _selection_bound, _validate_schema, _validate_value,
)
from .privacy import scrub_mcp_result

MAX_BROKER_REQUEST = 1_048_576
MAX_PAGES = 32
_METHODS = frozenset({
    "initialize", "tools/list", "tools/call", "ping",
    "notifications/initialized", "notifications/cancelled",
})
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


class MCPBrokerError(AuthorityDenied):
    """A fixed MCP target rejected an untrusted or out-of-scope request."""


@dataclass(frozen=True, slots=True)
class ProtectedMCPService:
    """Immutable root-enrolled service identity and tool ceiling.

    Endpoint, credential, and argv resolution remains inside the injected
    transport factory. transport_binding_id names that protected record
    without exposing its private configuration to the worker.
    """
    service_id: str
    channel: str
    allowed_tools: frozenset[str]
    transport_binding_id: str
    reviewed_revision: str
    selection_arguments: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.service_id, str) or not _ID.fullmatch(self.service_id):
            raise ValueError("protected MCP service identity is invalid")
        if self.channel not in {"http", "stdio"}:
            raise ValueError("protected MCP channel is invalid")
        if not isinstance(self.allowed_tools, frozenset) or not self.allowed_tools:
            raise ValueError("protected MCP tool ceiling is required")
        if any(not isinstance(name, str) or not _ID.fullmatch(name) for name in self.allowed_tools):
            raise ValueError("protected MCP tool ceiling is invalid")
        if not isinstance(self.transport_binding_id, str) or not _ID.fullmatch(self.transport_binding_id):
            raise ValueError("protected MCP transport binding is invalid")
        if (not isinstance(self.reviewed_revision, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.reviewed_revision)):
            raise ValueError("a pinned reviewed MCP service revision is required")
        if not isinstance(self.selection_arguments, Mapping):
            raise ValueError("protected MCP selection policy is invalid")
        policies = dict(self.selection_arguments)
        for tool, keys in policies.items():
            if (not isinstance(tool, str) or tool not in self.allowed_tools
                    or not isinstance(keys, tuple) or not keys
                    or len(set(keys)) != len(keys)
                    or any(not isinstance(key, str) or not _ID.fullmatch(key) for key in keys)):
                raise ValueError("protected MCP selection policy is invalid")
        if self.allowed_tools - set(policies):
            raise ValueError("every protected read tool requires an exact selection schema")
        object.__setattr__(self, "selection_arguments", MappingProxyType(policies))


class BrokerMCPTransport(Protocol):
    """Root-created transport that resolves only the supplied protected record."""
    def exchange(self, request: Mapping[str, Any], *, context: HostContext,
                 authorization: EffectAuthorization, timeout: float,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...


def _bounded_selection(value: Any) -> None:
    try:
        encoded = canonical_bytes(value if isinstance(value, (dict, list)) else {"value": value})
    except Exception:
        raise MCPBrokerError("mcp.selection", "selected MCP resource is invalid") from None
    if len(encoded) > 8192:
        raise MCPBrokerError("mcp.bounds", "selected MCP resource exceeds its bound")


def mcp_intent(service_id: str, channel: str, request_id: Any, method: str,
               selection: Any, params: Mapping[str, Any]) -> str:
    """Canonical intent shared by worker and protected broker."""
    if (not isinstance(service_id, str) or not _ID.fullmatch(service_id)
            or channel not in {"http", "stdio"} or method not in _METHODS
            or not isinstance(params, Mapping)):
        raise ValueError("MCP intent fields are invalid")
    _bounded_selection(selection)
    body = canonical_bytes({
        "service_id": service_id, "channel": channel, "request_id": request_id,
        "method": method, "selection": selection, "params": dict(params),
    })
    if len(body) > MAX_BROKER_REQUEST:
        raise ValueError("MCP intent exceeds its bound")
    return "mcp:" + service_id + ":" + channel + ":" + hashlib.sha256(body).hexdigest()


def _parse_envelope(payload: bytes) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_BROKER_REQUEST:
        raise MCPBrokerError("mcp.bounds", "MCP broker envelope is invalid")
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise MCPBrokerError("mcp.protocol", "MCP broker envelope is malformed") from None
    required = {"schema", "service_id", "request_id", "method", "selection", "params"}
    if not isinstance(value, dict):
        raise MCPBrokerError("mcp.protocol", "MCP broker envelope fields are invalid")
    if canonical_bytes(value) != payload:
        raise MCPBrokerError("mcp.protocol", "MCP broker envelope is not canonical JSON")
    if (set(value) != required or value.get("schema") != 1
            or not isinstance(value.get("service_id"), str)
            or not isinstance(value.get("method"), str) or value["method"] not in _METHODS
            or not isinstance(value.get("params"), dict)):
        raise MCPBrokerError("mcp.protocol", "MCP broker envelope fields are invalid")
    request_id = value["request_id"]
    if request_id is not None and (type(request_id) is int and request_id > 0):
        pass
    elif request_id is not None and isinstance(request_id, str) and _ID.fullmatch(request_id):
        pass
    elif request_id is not None:
        raise MCPBrokerError("mcp.protocol", "MCP request ID is invalid")
    if value["method"].startswith("notifications/") and request_id is not None:
        raise MCPBrokerError("mcp.protocol", "MCP notification must not carry a request ID")
    if not value["method"].startswith("notifications/") and request_id is None:
        raise MCPBrokerError("mcp.protocol", "MCP request is missing its request ID")
    _bounded_selection(value["selection"])
    return value


def _protected_selection_bound(keys: tuple[str, ...], arguments: Mapping[str, Any], selection: Any) -> bool:
    """Match exactly one resource parameter declared by the root service record."""
    expected = selection if isinstance(selection, Mapping) else None
    present = [key for key in keys if key in arguments]
    if not present:
        return False
    for key in present:
        wanted = expected.get(key) if expected is not None else selection
        actual = arguments[key]
        if wanted is None:
            return False
        if isinstance(wanted, (tuple, list)):
            if (not isinstance(actual, list)
                    or any(not isinstance(item, str) for item in actual)
                    or actual != list(wanted)):
                return False
        elif actual != wanted or type(actual) is not type(wanted):
            return False
    return True


class _Handler:
    def __init__(self, service: ProtectedMCPService, operation: str,
                 transport_factory: Callable[[ProtectedMCPService, HostContext], BrokerMCPTransport],
                 monotonic: Callable[[], float]) -> None:
        self.service, self.operation = service, operation
        self.transport_factory, self.monotonic = transport_factory, monotonic
        self._lock = threading.RLock()
        self._tools: dict[tuple[int, str, str], dict[str, Mapping[str, Any]]] = {}

    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float, peer_pid: int | None = None,
                 peer_pidfd: int | None = None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        # The authority owns this borrowed pidfd and closes it after dispatch.
        # MCP itself never uses a numeric PID as process ownership evidence.
        del peer_pid, peer_pidfd
        envelope = _parse_envelope(payload)
        service = self.service
        target = f"mcp:{service.service_id}:{service.channel}"
        if (envelope["service_id"] != service.service_id or authorization.target != target
                or authorization.recipient is not None
                or canonical_digest(payload) != authorization.request_digest):
            raise MCPBrokerError("mcp.binding", "MCP target, identity, or digest does not match its grant")
        method, params = envelope["method"], envelope["params"]
        capability = f"mcp:{service.service_id}:{'read' if method == 'tools/call' else 'connect'}"
        expected_intent = mcp_intent(
            service.service_id, service.channel, envelope["request_id"], method,
            envelope["selection"], params,
        )
        expected_intent_id = canonical_digest({"purpose": context.purpose, "intent": expected_intent})
        if (authorization.capability != capability or context.intent_id != expected_intent_id
                or authorization.intent_id != expected_intent_id):
            raise MCPBrokerError("mcp.binding", "MCP tool, selection, or intent does not match its grant")
        if timeout <= 0 or timeout > 9 or cancelled():
            raise MCPBrokerError("mcp.deadline", "MCP request deadline expired")
        state_key = (context.uid, context.profile_id, service.service_id)
        if method == "initialize":
            _validate_initialize(params)
            with self._lock:
                self._tools.pop(state_key, None)
        elif method == "tools/list":
            _validate_list(params)
        elif method == "tools/call":
            self._validate_call(state_key, envelope["selection"], params)
        elif method == "ping":
            if params:
                raise MCPBrokerError("mcp.protocol", "MCP ping params must be empty")
        elif method == "notifications/initialized":
            if params:
                raise MCPBrokerError("mcp.protocol", "MCP initialized notification params must be empty")
        elif method == "notifications/cancelled":
            if set(params) != {"requestId", "reason"} or type(params["requestId"]) not in (str, int):
                raise MCPBrokerError("mcp.protocol", "MCP cancellation notification is invalid")
        remaining = min(float(timeout), 9.0)
        transport = self.transport_factory(service, context)
        if not callable(getattr(transport, "exchange", None)):
            raise MCPBrokerError("mcp.transport", "protected MCP transport is unavailable")
        try:
            response = transport.exchange(
                {"jsonrpc": "2.0", "id": envelope["request_id"], "method": method, "params": params},
                context=context, authorization=authorization, timeout=remaining, cancelled=cancelled,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise MCPBrokerError("mcp.transport", "protected MCP transport failed") from None
        if cancelled():
            raise MCPBrokerError("mcp.cancelled", "MCP request was cancelled")
        if method.startswith("notifications/"):
            return {"status": 202, "body": b"", "headers": {}, "receipt_id": "mcp-notification"}
        if (not isinstance(response, Mapping) or response.get("jsonrpc") != "2.0"
                or response.get("id") != envelope["request_id"]):
            raise MCPBrokerError("mcp.response", "MCP response correlation is invalid")
        if "error" in response:
            error = response.get("error")
            code = error.get("code") if isinstance(error, Mapping) else -32000
            safe = {"jsonrpc": "2.0", "id": envelope["request_id"],
                    "error": {"code": code, "message": "protected MCP operation failed"}}
            body = canonical_bytes(safe)
        else:
            result = response.get("result")
            if method == "tools/list":
                result = self._accept_tool_page(state_key, result)
            elif method == "tools/call":
                # Result provenance is issued by AuthorityService over the
                # bytes returned below. Scrub here, before that observer sees
                # the payload, so the source receipt digest names exactly the
                # data later exposed to the native model.
                try:
                    result = scrub_mcp_result(service.service_id)(result)
                except Exception:
                    raise MCPBrokerError("mcp.privacy", "MCP result failed reviewed privacy filtering") from None
            body = canonical_bytes({"jsonrpc": "2.0", "id": envelope["request_id"], "result": result})
        if len(body) > MAX_RESULT_BYTES * 4:
            raise MCPBrokerError("mcp.bounds", "MCP response exceeds its bound")
        return {"status": 200, "body": body,
                "headers": {"content-type": "application/json"},
                "receipt_id": "mcp-" + hashlib.sha256(body).hexdigest()[:24]}

    def _accept_tool_page(self, state_key: tuple[int, str, str], result: Any) -> Mapping[str, Any]:
        if not isinstance(result, Mapping) or not isinstance(result.get("tools"), list):
            raise MCPBrokerError("mcp.tools", "MCP tools/list response is malformed")
        accepted: dict[str, Mapping[str, Any]] = {}
        for item in result["tools"]:
            if not isinstance(item, Mapping) or not isinstance(item.get("name"), str):
                raise MCPBrokerError("mcp.tools", "MCP tool schema is malformed")
            name, schema = item["name"], item.get("inputSchema")
            if (not name or len(name) > 128 or name not in self.service.allowed_tools
                    or name in accepted):
                continue
            _validate_schema(schema)
            if len(canonical_bytes(dict(item))) > MAX_SCHEMA_BYTES:
                raise MCPBrokerError("mcp.bounds", "MCP tool schema exceeds its bound")
            annotations = item.get("annotations", {})
            if not isinstance(annotations, Mapping):
                annotations = {}
            accepted[name] = {"inputSchema": dict(schema), "annotations": dict(annotations)}
        with self._lock:
            previous = self._tools.setdefault(state_key, {})
            previous.update(accepted)
            if len(previous) > MAX_TOOLS:
                raise MCPBrokerError("mcp.bounds", "MCP discovery exceeded its tool limit")
        next_cursor = result.get("nextCursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or not 1 <= len(next_cursor) <= 1024):
            raise MCPBrokerError("mcp.pagination", "MCP tools/list cursor is invalid")
        return {"tools": [
            {"name": name, "inputSchema": item["inputSchema"], "annotations": item["annotations"]}
            for name, item in accepted.items()
        ], **({"nextCursor": next_cursor} if next_cursor is not None else {})}

    def _validate_call(self, state_key: tuple[int, str, str], selection: Any,
                       params: Mapping[str, Any]) -> None:
        if set(params) != {"name", "arguments"} or not isinstance(params.get("name"), str):
            raise MCPBrokerError("mcp.call", "MCP tool call fields are invalid")
        name, arguments = params["name"], params["arguments"]
        if name not in self.service.allowed_tools or not isinstance(arguments, Mapping):
            raise MCPBrokerError("mcp.tool", "MCP tool is outside its protected allowlist")
        with self._lock:
            tool = self._tools.get(state_key, {}).get(name)
        if tool is None:
            raise MCPBrokerError("mcp.discovery", "MCP tool has not passed protected schema discovery")
        if (tool["annotations"].get("readOnlyHint") is not True
                or tool["annotations"].get("destructiveHint") is True):
            raise MCPBrokerError("mcp.effect", "MCP tool is not explicitly read-only")
        if not _protected_selection_bound(self.service.selection_arguments[name], arguments, selection):
            raise MCPBrokerError("mcp.selection", "MCP request does not bind to its selected resource")
        _validate_value(arguments, tool["inputSchema"])


def _validate_initialize(params: Mapping[str, Any]) -> None:
    required = {"protocolVersion", "capabilities", "clientInfo"}
    if set(params) != required or params["protocolVersion"] not in SUPPORTED_PROTOCOL_VERSIONS:
        raise MCPBrokerError("mcp.initialize", "MCP initialization parameters are invalid")
    if not isinstance(params["capabilities"], Mapping) or not isinstance(params["clientInfo"], Mapping):
        raise MCPBrokerError("mcp.initialize", "MCP initialization parameters are invalid")
    if params["clientInfo"].get("name") != "hermes-installer":
        raise MCPBrokerError("mcp.initialize", "MCP client identity is invalid")


def _validate_list(params: Mapping[str, Any]) -> None:
    if set(params) - {"cursor"} or ("cursor" in params and
            (not isinstance(params["cursor"], str) or not 1 <= len(params["cursor"]) <= 1024)):
        raise MCPBrokerError("mcp.pagination", "MCP tools/list parameters are invalid")


def build_mcp_handlers(
    protected_services: Mapping[str, ProtectedMCPService], *,
    transport_factory: Callable[[ProtectedMCPService, HostContext], BrokerMCPTransport],
    monotonic: Callable[[], float] = time.monotonic,
) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Build fixed-verb handlers from root-owned service enrollment records."""
    if not isinstance(protected_services, Mapping) or not protected_services:
        raise ValueError("protected MCP service records are required")
    if not callable(transport_factory):
        raise TypeError("a protected MCP transport factory is required")
    handlers: dict[tuple[str, str], Callable[..., Mapping[str, Any]]] = {}
    for service_id, service in protected_services.items():
        if type(service) is not ProtectedMCPService or service.service_id != service_id:
            raise TypeError("protected MCP service record identity mismatch")
        target = f"mcp:{service.service_id}:{service.channel}"
        operation = "mcp.request" if service.channel == "http" else "mcp.stdio"
        handlers[(operation, target)] = _Handler(service, operation, transport_factory, monotonic)
    return handlers
