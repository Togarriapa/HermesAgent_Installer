"""Bounded MCP JSON-RPC lifecycle with host-issued dispatch authority."""
from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Protocol

from ..policy import ContextAuthorizer, DispatchAuthorization, DispatchContext, PolicyDenied

SUPPORTED_PROTOCOL_VERSIONS = ("2025-03-26", "2024-11-05")
MAX_TOOLS = 512
MAX_TOOL_PAGES = 32
MAX_SCHEMA_BYTES = 65_536
MAX_RESULT_BYTES = 262_144


class MCPError(RuntimeError):
    """Safe MCP failure; never embeds args, headers, response bodies or secrets."""


class Transport(Protocol):
    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...
    async def close(self) -> None: ...


def _validate_schema(schema: Any, depth: int = 0) -> None:
    if depth > 16 or not isinstance(schema, Mapping):
        raise MCPError("tool schema is malformed or nested too deeply")
    kind = schema.get("type", "object")
    if kind not in {"object", "array", "string", "number", "integer", "boolean", "null"}:
        raise MCPError("tool schema uses an unsupported type")
    if kind == "object":
        props, required = schema.get("properties", {}), schema.get("required", [])
        if not isinstance(props, Mapping) or len(props) > 128:
            raise MCPError("tool schema has invalid properties")
        if not isinstance(required, list) or len(required) > 128 or any(not isinstance(x, str) for x in required):
            raise MCPError("tool schema has invalid required fields")
        if set(required) - set(props) or schema.get("additionalProperties", False) not in (False, True):
            raise MCPError("tool schema has invalid required or additionalProperties")
        for key, child in props.items():
            if not isinstance(key, str) or len(key) > 128:
                raise MCPError("tool schema property name is invalid")
            _validate_schema(child, depth + 1)
    if kind == "array" and "items" in schema:
        _validate_schema(schema["items"], depth + 1)
    if "enum" in schema and (not isinstance(schema["enum"], list) or len(schema["enum"]) > 256):
        raise MCPError("tool schema enum is invalid")


def _validate_value(value: Any, schema: Mapping[str, Any], depth: int = 0) -> None:
    if depth > 16:
        raise MCPError("tool arguments are nested too deeply")
    kind = schema.get("type", "object")
    checks = {
        "object": lambda x: isinstance(x, Mapping),
        "array": lambda x: isinstance(x, list),
        "string": lambda x: isinstance(x, str),
        "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
        "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
        "boolean": lambda x: isinstance(x, bool),
        "null": lambda x: x is None,
    }
    if not checks[kind](value):
        raise MCPError("tool arguments do not match the discovered schema")
    if kind == "object":
        props = schema.get("properties", {})
        if set(schema.get("required", [])) - set(value):
            raise MCPError("tool arguments omit a required field")
        if schema.get("additionalProperties") is False and set(value) - set(props):
            raise MCPError("tool arguments contain unknown fields")
        for key, item in value.items():
            if key in props:
                _validate_value(item, props[key], depth + 1)
    elif kind == "array":
        if len(value) > int(schema.get("maxItems", 1024)):
            raise MCPError("tool argument array exceeds its limit")
        for item in value:
            if "items" in schema:
                _validate_value(item, schema["items"], depth + 1)
    elif kind == "string":
        if len(value) > int(schema.get("maxLength", 65_536)):
            raise MCPError("tool argument string exceeds its limit")
        if "enum" in schema and value not in schema["enum"]:
            raise MCPError("tool argument is outside permitted values")
    elif kind in {"number", "integer"}:
        if ("minimum" in schema and value < schema["minimum"]) or ("maximum" in schema and value > schema["maximum"]):
            raise MCPError("tool argument is outside its permitted range")


_SELECTION_ARGUMENTS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "figma": {"*": ("file_key",)}, "revenuecat": {"*": ("project_id",)},
    "google-gmail": {"get_message": ("message_id",), "get_thread": ("thread_id",)},
    "google-drive": {"*": ("file_id",)}, "google-docs": {"*": ("document_id",)},
    "google-sheets": {"*": ("spreadsheet_id",)},
    "google-calendar": {"get_event": ("event_id",), "list_events": ("calendar_id",)},
    "google-contacts": {"search_contacts": ("query",)},
    "home-assistant": {"*": ("entity_id", "entity_ids")}, "playwright": {"*": ("url",)},
    "fixture": {"get_state": ("entity_id",)},
}


def _selection_bound(service_id: str, tool: str, arguments: Mapping[str, Any], selection: Any) -> bool:
    """Require an exact selected-resource argument; incidental nested values do not count."""
    accepted = _SELECTION_ARGUMENTS.get(service_id, {})
    keys = accepted.get(tool, accepted.get("*", ()))
    if not keys or not isinstance(arguments, Mapping):
        return False
    expected = selection if isinstance(selection, Mapping) else None
    matched = []
    for key in keys:
        if key not in arguments:
            continue
        actual = arguments[key]
        wanted = expected.get(key) if expected is not None else selection
        if wanted is None:
            continue
        if isinstance(wanted, (tuple, list, set, frozenset)):
            valid = (isinstance(actual, (tuple, list, set, frozenset))
                     and all(isinstance(x, str) for x in actual)
                     and set(actual) == set(wanted))
        else:
            valid = actual == wanted
        if valid:
            matched.append(key)
    return len(matched) == 1

def _intent(service_id: str, operation: str, selection: Any, tool: str | None = None, args: Any = None, binding: str = "") -> str:
    payload = json.dumps(
        {"selection": selection, "tool": tool, "args": args, "binding": binding},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return f"mcp:{service_id}:{operation}:{hashlib.sha256(payload).hexdigest()}"


class MCPClient:
    """Single configured MCP service session; no host authority means no I/O."""

    def __init__(
        self,
        transport: Transport,
        allowed_tools: set[str] | frozenset[str],
        *,
        service_id: str,
        selection: Any,
        dispatch_context: DispatchContext | None = None,
        context_authorizer: ContextAuthorizer | None = None,
        timeout: float = 9.0,
        supported_protocol_versions: tuple[str, ...] = SUPPORTED_PROTOCOL_VERSIONS,
        max_concurrency: int = 4,
        result_scrubber: Callable[[Any], Any] | None = None,
        authority_client: Any | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not service_id or not isinstance(service_id, str):
            raise ValueError("service id is required")
        if not 0 < timeout <= 9:
            raise ValueError("per-attempt timeout must be in (0, 9] seconds")
        if not 1 <= max_concurrency <= 16 or not supported_protocol_versions:
            raise ValueError("MCP concurrency or supported protocol versions are invalid")
        if any(not isinstance(n, str) or not n or len(n) > 128 for n in allowed_tools):
            raise ValueError("MCP tool allowlist contains an invalid name")
        self.transport, self.service_id, self.selection = transport, service_id, selection
        self.allowed_tools = frozenset(allowed_tools)
        self.context, self.authorizer = dispatch_context, context_authorizer
        self.authority_client = authority_client
        self.timeout, self.versions, self.monotonic = timeout, supported_protocol_versions, monotonic
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._ids = itertools.count(1)
        self._ready = False
        self._version: str | None = None
        self._tools: dict[str, Mapping[str, Any]] = {}
        self._closed = False
        self._scrubber = result_scrubber if callable(result_scrubber) else None
        self._last_error: str | None = None

    @property
    def protocol_version(self) -> str | None:
        return self._version

    @property
    def ready(self) -> bool:
        return self._ready and not self._closed

    @property
    def discovered_tools(self) -> frozenset[str]:
        return frozenset(self._tools)

    @property
    def health_status(self) -> Mapping[str, Any]:
        return {"ready": self.ready, "protocol_version": self._version,
                "tool_count": len(self._tools), "last_error": self._last_error}

    def _authorize(self, operation: str, deadline: float, *, tool: str | None = None,
                   args: Mapping[str, Any] | None = None) -> DispatchAuthorization:
        context, authorizer = self.context, self.authorizer
        now = self.monotonic()
        capability = f"mcp:{self.service_id}:{'read' if operation == 'call' else 'connect'}"
        if authorizer is None or context is None:
            raise MCPError("trusted MCP host authorization is unavailable")
        if context.cancelled() or capability not in context.capabilities:
            raise MCPError("trusted MCP capability is absent or cancelled")
        if (not context.principal_id or not context.namespace or not context.provenance
                or not context.provenance.startswith("sha256:") or not context.policy_revision
                or not context.grant_id or context.lease_expires_at <= now):
            raise MCPError("trusted MCP host context is incomplete or expired")
        actual_deadline = min(deadline, context.lease_expires_at)
        if context.deadline is not None:
            actual_deadline = min(actual_deadline, context.deadline)
        remaining = actual_deadline - now
        if remaining <= 0:
            raise MCPError("MCP request deadline expired")
        binding = getattr(self.transport, "binding_id", None) or getattr(self.transport, "endpoint", None) or f"fixture:{self.service_id}"
        intent_id = _intent(self.service_id, operation, self.selection, tool, args, binding)
        def cancelled() -> bool:
            return context.cancelled() or self.monotonic() >= actual_deadline
        try:
            grant = authorizer(context, capability, intent_id, now, remaining, cancelled)
        except Exception:
            raise MCPError("trusted MCP authorization failed") from None
        finished = self.monotonic()
        if cancelled() or finished >= actual_deadline:
            raise MCPError("MCP request was cancelled or expired during authorization")
        if not isinstance(grant, DispatchAuthorization):
            raise MCPError("trusted host denied MCP capability")
        if (grant.principal_id != context.principal_id or grant.profile_id != context.profile_id
                or grant.namespace != context.namespace or grant.trace_id != context.trace_id
                or grant.policy_revision != context.policy_revision or grant.purpose != context.purpose
                or grant.capability != capability or grant.intent_id != intent_id
                or grant.grant_id != context.grant_id or grant.lineage_sha256 != context.provenance[7:]
                or capability not in grant.capabilities or grant.expires_at_monotonic <= finished
                or grant.expires_at_monotonic > context.lease_expires_at
                or grant.expires_at_monotonic - finished > 3600):
            raise MCPError("host MCP authorization is stale or mismatched")
        return grant

    async def _rpc(self, method: str, params: Mapping[str, Any] | None = None,
                   *, deadline: float | None = None, operation: str = "connect",
                   tool: str | None = None, args: Mapping[str, Any] | None = None) -> Any:
        if self._closed:
            raise MCPError("MCP client is closed")
        deadline = deadline if deadline is not None else self.monotonic() + self.timeout
        rid = next(self._ids)
        if self.authority_client is not None:
            payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": dict(params or {})}
            response = await self._authority_request(
                payload, deadline=deadline, operation=operation, tool=tool, args=args,
            )
            if response.get("jsonrpc") != "2.0" or response.get("id") != rid:
                raise MCPError("MCP response correlation or JSON-RPC version is invalid")
            if "error" in response:
                error = response.get("error")
                code = error.get("code") if isinstance(error, Mapping) else None
                if code in {-32001, -32002, -32003}:
                    raise MCPError("MCP authentication denied or revoked")
                raise MCPError(f"{method} failed")
            if "result" not in response:
                raise MCPError(f"{method} returned no result")
            return response["result"]
        async with self._semaphore:
            grant = self._authorize(operation, deadline, tool=tool, args=args)
            remaining = min(self.timeout, deadline - self.monotonic(),
                            grant.expires_at_monotonic - self.monotonic())
            if remaining <= 0:
                raise MCPError("MCP authorization or request deadline expired")
            payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": dict(params or {})}
            try:
                request = self.transport.request
                if getattr(self.transport, "requires_dispatch_grant", False):
                    pending = request(payload, dispatch_context=self.context, dispatch_authorization=grant)
                else:
                    pending = request(payload)
                cancel_budget = min(0.25, remaining / 4) if getattr(self.transport, "cancel_request", None) else 0.0
                request_budget = remaining - cancel_budget
                response = await asyncio.wait_for(pending, request_budget)
            except asyncio.TimeoutError:
                self._last_error = f"{method}: deadline"
                await self._cancel(rid, grant, deadline)
                raise MCPError(f"{method} exceeded its bounded deadline") from None
            except asyncio.CancelledError:
                await self._cancel(rid, grant, deadline)
                raise
            except Exception as exc:
                self._last_error = f"{method}: transport"
                message = str(exc).lower()
                reason = "authentication denied or revoked" if "authentication was denied" in message else "transport disconnected"
                raise MCPError(f"{method}: {reason}") from None
        if not isinstance(response, Mapping) or response.get("jsonrpc") != "2.0" or response.get("id") != rid:
            raise MCPError("MCP response correlation or JSON-RPC version is invalid")
        if "error" in response:
            error = response.get("error")
            code = error.get("code") if isinstance(error, Mapping) else None
            if code in {-32001, -32002, -32003}:
                raise MCPError("MCP authentication denied or revoked")
            raise MCPError(f"{method} failed")
        if "result" not in response:
            raise MCPError(f"{method} returned no result")
        return response["result"]

    async def _authority_request(self, request: Mapping[str, Any], *, deadline: float,
                                 operation: str, tool: str | None = None,
                                 args: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        """Issue one JSON-RPC request through a fresh host grant and fixed MCP broker."""
        authority = self.authority_client
        if authority is None:
            raise MCPError("protected MCP authority is unavailable")
        from ..authority import AuthorityDenied, BrokeredEffectResponse, canonical_bytes, canonical_digest
        from .transports import StdioTransport, StreamableHTTPTransport
        if type(self.transport) is StreamableHTTPTransport:
            channel = "http"
        elif type(self.transport) is StdioTransport:
            channel = "stdio"
        else:
            raise MCPError("MCP broker transport is not a first-party transport")
        if getattr(self.transport, "service_id", None) != self.service_id:
            raise MCPError("MCP broker transport service binding is invalid")
        target = f"mcp:{self.service_id}:{channel}"
        payload = canonical_bytes(dict(request))
        intent_id = _intent(
            self.service_id, operation, self.selection, tool,
            {"method": request.get("method"), "params": request.get("params", {}),
             "selected_arguments": args}, channel,
        )
        purpose = "mcp-selected-resource-read" if operation == "call" else "mcp-connection-lifecycle"
        cancellation = __import__("threading").Event()
        async with self._semaphore:
            remaining = min(self.timeout, deadline - self.monotonic())
            if remaining <= 0:
                raise MCPError("MCP request deadline expired")
            try:
                context = await asyncio.wait_for(asyncio.to_thread(
                    authority.context, purpose=purpose, intent=intent_id, lease_seconds=min(30.0, remaining)
                ), remaining)
                if context.intent_id != intent_id or context.monotonic_expires_at <= self.monotonic():
                    raise MCPError("host issued a stale or mismatched MCP context")
                remaining = min(remaining, context.monotonic_expires_at - self.monotonic())
                capability = f"mcp:{self.service_id}:{'read' if operation == 'call' else 'connect'}"
                digest = canonical_digest(payload)
                grant = await asyncio.wait_for(asyncio.to_thread(
                    authority.authorize_effect, context, capability=capability, target=target,
                    recipient=None, request_digest=digest, retry_index=0,
                    cancelled=cancellation.is_set,
                ), remaining)
                if (grant.target != target or grant.capability != capability
                        or grant.request_digest != digest or grant.intent_id != intent_id
                        or grant.context_digest == ""):
                    raise MCPError("host MCP grant is stale or mismatched")
                remaining = min(remaining, grant.monotonic_expires_at - self.monotonic())
                if remaining <= 0:
                    raise MCPError("MCP authorization lease expired")
                effect = await asyncio.wait_for(asyncio.to_thread(
                    authority.mcp_request, grant, target=target, payload=payload,
                    timeout=remaining, cancelled=cancellation.is_set,
                ), remaining)
            except asyncio.TimeoutError:
                cancellation.set()
                raise MCPError(f"{request.get('method', 'MCP request')} exceeded its aggregate deadline") from None
            except asyncio.CancelledError:
                cancellation.set()
                raise
            except MCPError:
                raise
            except AuthorityDenied as exc:
                cancellation.set()
                reason = "authentication denied or revoked" if getattr(exc, "code", "").startswith(("auth.", "account.")) else "host authority denied MCP request"
                raise MCPError(reason) from None
            except Exception:
                cancellation.set()
                raise MCPError("protected MCP broker is unavailable or denied the request") from None
        if not isinstance(effect, BrokeredEffectResponse):
            raise MCPError("protected MCP broker returned an invalid response")
        if effect.status in {401, 403}:
            raise MCPError("MCP authentication denied or revoked")
        if effect.status not in {200, 202, 204}:
            raise MCPError("protected MCP broker returned an unsuccessful response")
        if not request.get("id"):
            return {}
        if not effect.body or len(effect.body) > MAX_RESULT_BYTES * 4:
            raise MCPError("protected MCP broker returned an empty or oversized response")
        try:
            response = json.loads(effect.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise MCPError("protected MCP broker returned malformed JSON-RPC") from None
        if not isinstance(response, Mapping):
            raise MCPError("protected MCP broker returned malformed JSON-RPC")
        return response

    async def _cancel(self, rid: int, grant: DispatchAuthorization, deadline: float) -> None:
        cancel = getattr(self.transport, "cancel_request", None)
        if cancel is not None:
            try:
                if getattr(self.transport, "requires_dispatch_grant", False):
                    pending = cancel(rid, dispatch_context=self.context, dispatch_authorization=grant)
                else:
                    pending = cancel(rid)
                remaining = deadline - self.monotonic()
                if remaining <= 0:
                    return
                await asyncio.wait_for(pending, min(remaining, 0.25))
            except Exception:
                pass

    async def initialize(self, *, deadline: float | None = None) -> Mapping[str, Any]:
        deadline = deadline if deadline is not None else self.monotonic() + self.timeout
        result = await self._rpc(
            "initialize", {"protocolVersion": self.versions[0], "capabilities": {},
            "clientInfo": {"name": "hermes-installer", "version": "0.1.0"}},
            deadline=deadline,
        )
        if not isinstance(result, Mapping) or result.get("protocolVersion") not in self.versions:
            raise MCPError("MCP server selected an unsupported protocol version")
        if not isinstance(result.get("capabilities"), Mapping) or not isinstance(result.get("serverInfo"), Mapping):
            raise MCPError("MCP initialize response omitted capabilities or serverInfo")
        self._version = result["protocolVersion"]
        await self._notify_initialized(deadline)
        self._ready = True
        self._last_error = None
        return {"protocolVersion": self._version, "capabilities": dict(result["capabilities"]),
                "serverInfo": {k: result["serverInfo"].get(k) for k in ("name", "version")}}

    async def _notify_initialized(self, deadline: float) -> None:
        if self.authority_client is not None:
            await self._authority_request(
                {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                deadline=deadline, operation="connect",
            )
            return
        grant = self._authorize("connect", deadline)
        try:
            payload = {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
            if getattr(self.transport, "requires_dispatch_grant", False):
                pending = self.transport.request(payload, dispatch_context=self.context, dispatch_authorization=grant)
            else:
                pending = self.transport.request(payload)
            await asyncio.wait_for(pending, min(2.0, max(0.01, deadline - self.monotonic())))
        except Exception:
            raise MCPError("MCP initialized notification failed") from None

    async def discover(self, *, deadline: float | None = None) -> Mapping[str, Mapping[str, Any]]:
        if not self.ready:
            raise MCPError("initialize MCP before discovery")
        deadline = deadline if deadline is not None else self.monotonic() + self.timeout
        cursor = None
        tools: dict[str, Mapping[str, Any]] = {}
        for _ in range(MAX_TOOL_PAGES):
            page = await self._rpc("tools/list", {"cursor": cursor} if cursor else {}, deadline=deadline)
            if not isinstance(page, Mapping) or not isinstance(page.get("tools"), list):
                raise MCPError("MCP tools/list response is malformed")
            for row in page["tools"]:
                if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
                    raise MCPError("MCP tool definition is malformed")
                name, schema = row["name"], row.get("inputSchema")
                if not name or len(name) > 128 or name in tools:
                    raise MCPError("MCP tool name is invalid or duplicated")
                _validate_schema(schema)
                if len(json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_SCHEMA_BYTES:
                    raise MCPError("MCP tool schema exceeds its size limit")
                tools[name] = {"inputSchema": dict(schema),
                               "annotations": dict(row.get("annotations", {})) if isinstance(row.get("annotations", {}), Mapping) else {}}
                if len(tools) > MAX_TOOLS:
                    raise MCPError("MCP discovery exceeded the tool limit")
            cursor = page.get("nextCursor")
            if cursor is None:
                break
            if not isinstance(cursor, str) or not cursor or len(cursor) > 1024:
                raise MCPError("MCP pagination cursor is invalid")
        else:
            raise MCPError("MCP discovery exceeded its page limit")
        self._tools = tools
        self._last_error = None
        return dict(tools)

    async def call_read(self, name: str, arguments: Mapping[str, Any], *,
                        deadline: float | None = None) -> Any:
        if not self.ready or name not in self._tools:
            raise MCPError("discover the MCP tool before invocation")
        if self._scrubber is None:
            raise MCPError("a reviewed privacy result scrubber is required before MCP reads")
        if name not in self.allowed_tools:
            raise PermissionError("MCP tool is outside the reviewed read allowlist")
        if not isinstance(arguments, Mapping) or not _selection_bound(self.service_id, name, arguments, self.selection):
            raise PermissionError("MCP request does not bind arguments to the selected resource")
        metadata = self._tools[name]
        _validate_value(arguments, metadata["inputSchema"])
        if (metadata["annotations"].get("readOnlyHint") is not True
                or metadata["annotations"].get("destructiveHint") is True):
            raise PermissionError("MCP tool is explicitly marked as not read-only")
        result = await self._rpc("tools/call", {"name": name, "arguments": dict(arguments)},
                                 deadline=deadline, operation="call", tool=name, args=arguments)
        if not isinstance(result, Mapping) or result.get("isError") is True:
            raise MCPError("MCP read returned an error")
        try:
            if len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode()) > MAX_RESULT_BYTES:
                raise MCPError("MCP result exceeds its size limit")
            return self._scrubber(result)
        except MCPError:
            raise
        except Exception:
            raise MCPError("MCP result failed privacy filtering") from None

    async def health(self, *, deadline: float | None = None) -> bool:
        if not self.ready:
            return False
        try:
            await self._rpc("ping", {}, deadline=deadline)
            self._last_error = None
            return True
        except MCPError:
            return False

    async def reconnect(self, connect: Callable[[], Awaitable[Transport]], *,
                        deadline: float | None = None) -> None:
        deadline = deadline if deadline is not None else self.monotonic() + self.timeout
        await self.transport.close()
        self.transport = await asyncio.wait_for(connect(), min(self.timeout, deadline - self.monotonic()))
        self._ready = False
        self._version = None
        self._tools.clear()
        await self.initialize(deadline=deadline)
        await self.discover(deadline=deadline)

    async def close(self) -> None:
        self._ready = False
        self._version = None
        self._tools.clear()
        self._closed = True
        await self.transport.close()
