"""Root-side executor for one observed, selected native Hermes MCP call.

The worker supplies only its lexical invocation handle and canonical tool
arguments. Root-owned composition resolves the handle through the live native
invocation registry, then this dispatcher joins the exact action, pinned
schemas, current MCP enrollment and fixed effect handler before making any
network request. No URL, tool selector, source context, credential or grant is
accepted from the worker.
"""
from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from ..authority import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext,
    canonical_bytes, canonical_digest,
)
from ..authority.types import strict_json_loads
from .broker import ProtectedMCPService, mcp_intent
from .client import (
    SUPPORTED_PROTOCOL_VERSIONS, MCPError, _validate_schema, _validate_value,
)
from .privacy import scrub_mcp_result

_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_ARGUMENT_BYTES = 1_048_576
_MAX_OUTPUT_BYTES = 262_144
_MAX_SOURCE_HANDLES = 64
_MAX_DISCOVERY_PAGES = 32
_TIMEOUT = 9.0
_ADAPTER_ID = "hermes-installer.native-mcp-dispatch.v1"


def _thaw(value: Any, *, depth: int = 0) -> Any:
    if depth > 16:
        raise ValueError("native MCP schema is too deeply nested")
    if isinstance(value, Mapping):
        return {key: _thaw(child, depth=depth + 1) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(child, depth=depth + 1) for child in value]
    return value


def _canonical_schema(value: Mapping[str, Any]) -> bytes:
    return canonical_bytes(_thaw(value))


def _bound_schema(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("native MCP schema artifact is unavailable")
    schema = _thaw(value)
    _validate_schema(schema)
    return schema


class NativeMCPExecutionDenied(AuthorityDenied):
    """The root could not prove the complete native MCP execution binding."""


@dataclass(frozen=True, slots=True)
class RootNativeMCPInvocation:
    """Typed result from the root's one-use invocation-registry resolver.

    This is transport data, not an authority token. The ``resolve`` callback
    below must atomically consume the live registry invocation after checking
    SO_PEERCRED, the borrowed PIDFD, loaded-package proof, lexical action and
    complete source-receipt closure.
    """

    invocation_handle: str
    package_id: str
    profile_id: str
    package_generation: str
    process_generation: str
    adapter_id: str
    action_id: str
    arguments_sha256: str
    parent_closure_digest: str
    expires_monotonic: float
    source_receipt_handles: tuple[str, ...]
    native_process_identity: str

    def __post_init__(self) -> None:
        for name in ("invocation_handle", "package_id", "profile_id", "package_generation",
                     "process_generation", "adapter_id", "action_id", "native_process_identity"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"root native invocation {name} is invalid")
        for name in ("invocation_handle",):
            if not _OPAQUE.fullmatch(getattr(self, name)):
                raise ValueError(f"root native invocation {name} is invalid")
        for name in ("arguments_sha256", "parent_closure_digest"):
            if not isinstance(getattr(self, name), str) or not _SHA256.fullmatch(getattr(self, name)):
                raise ValueError(f"root native invocation {name} is invalid")
        if (isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not self.expires_monotonic > 0):
            raise ValueError("root native invocation lease is invalid")
        if (not isinstance(self.source_receipt_handles, tuple)
                or len(self.source_receipt_handles) > _MAX_SOURCE_HANDLES
                or any(not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                       for handle in self.source_receipt_handles)
                or len(set(self.source_receipt_handles)) != len(self.source_receipt_handles)):
            raise ValueError("root native invocation source closure is invalid")


class NativeMCPInvocationResolver(Protocol):
    """Root-only, one-use resolver for live HI11/HI12 native tool calls."""

    def consume(self, invocation_handle: str, *, peer_uid: int, peer_pid: int,
                peer_pidfd: int) -> RootNativeMCPInvocation: ...

    def is_current(self, invocation: RootNativeMCPInvocation) -> bool:
        """Recheck process, loaded package, action and source closure at each effect."""
        ...


@dataclass(frozen=True, slots=True)
class _MCPResponse:
    value: Mapping[str, Any]
    source_receipt_handle: str | None = None


class NativeMCPDispatcher:
    """Execute a root-resolved native MCP action through fixed authority effects.

    ``registration_index``, ``schema_catalog``, ``protected_services``,
    ``current_mcp_generations`` and ``invocation_resolver`` must be created by
    the root runtime composer from active protected records. The dispatcher
    invokes AuthorityService's in-process fixed-effect path; it never opens a
    socket or constructs an HTTP transport itself.
    """

    def __init__(self, service: Any, *, registration_index: Any,
                 schema_catalog: Any,
                 protected_services: Mapping[str, ProtectedMCPService],
                 current_mcp_generations: Mapping[str, str],
                 invocation_resolver: NativeMCPInvocationResolver,
                 monotonic: Callable[[], float] = time.monotonic,
                 timeout: float = _TIMEOUT) -> None:
        if service is None or not callable(getattr(service, "_issue_context", None)):
            raise TypeError("the live root AuthorityService is required")
        if (not callable(getattr(registration_index, "resolve_action", None))
                or not callable(getattr(schema_catalog, "resolve", None))):
            raise TypeError("root native MCP registration and schema catalogs are required")
        if (not isinstance(protected_services, Mapping)
                or not isinstance(current_mcp_generations, Mapping)
                or not callable(getattr(invocation_resolver, "consume", None))
                or not callable(getattr(invocation_resolver, "is_current", None))):
            raise TypeError("root MCP enrollment and one-use invocation resolver are required")
        if not 0 < timeout <= _TIMEOUT:
            raise ValueError("native MCP aggregate timeout must be in (0, 9] seconds")
        services = dict(protected_services)
        generations = dict(current_mcp_generations)
        if any(type(row) is not ProtectedMCPService or row.service_id != key
               for key, row in services.items()):
            raise TypeError("protected MCP service catalog identity is invalid")
        if any(not isinstance(key, str) or not isinstance(value, str) or not value
               for key, value in generations.items()):
            raise TypeError("protected MCP generation map is invalid")
        self.service = service
        self._registrations = registration_index
        self._schemas = schema_catalog
        self._services = services
        self._generations = generations
        self._invocations = invocation_resolver
        self._monotonic = monotonic
        self._timeout = float(timeout)

    def dispatch_native_mcp(self, *, peer_uid: int, peer_pid: int,
                            peer_pidfd: int, invocation_handle: str,
                            canonical_arguments: bytes,
                            cancelled: Callable[[], bool]) -> BrokeredEffectResponse:
        """Resolve and execute a single selected read; all selectors are root-derived."""
        if (type(peer_uid) is not int or peer_uid <= 0 or type(peer_pid) is not int
                or peer_pid <= 0 or type(peer_pidfd) is not int or peer_pidfd < 0
                or not callable(cancelled) or cancelled()
                or not isinstance(invocation_handle, str) or not _OPAQUE.fullmatch(invocation_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= _MAX_ARGUMENT_BYTES):
            raise NativeMCPExecutionDenied("native.mcp", "native MCP invocation is unavailable or malformed")
        try:
            arguments = strict_json_loads(canonical_arguments.decode("utf-8"))
            if not isinstance(arguments, dict) or canonical_bytes(arguments) != canonical_arguments:
                raise ValueError
            invocation = self._invocations.consume(
                invocation_handle, peer_uid=peer_uid, peer_pid=peer_pid,
                peer_pidfd=peer_pidfd,
            )
            if (type(invocation) is not RootNativeMCPInvocation
                    or invocation.invocation_handle != invocation_handle
                    or invocation.expires_monotonic <= self._monotonic()
                    or invocation.arguments_sha256 != hashlib.sha256(canonical_arguments).hexdigest()):
                raise ValueError
            binding = self._registrations.resolve_action(invocation.action_id)
            self._validate_binding(binding, invocation)
            request_schema = self._resolve_schema(binding, "arguments")
            result_schema = self._resolve_schema(binding, "result")
            if hashlib.sha256(_canonical_schema(request_schema)).hexdigest() != binding.native_schema_sha256:
                raise NativeMCPExecutionDenied(
                    "native.mcp.schema", "compiled native schema digest differs from its protected artifact",
                )
            _validate_value(arguments, request_schema)
            selection = self._validate_selection(binding, arguments)
            service, operation, target = self._service_for(binding)
            self._require_result_observer(service, operation, target)
            self._require_current(invocation)
        except NativeMCPExecutionDenied:
            raise
        except Exception:
            raise NativeMCPExecutionDenied("native.mcp.binding", "native MCP action or schema binding was rejected") from None

        deadline = min(self._monotonic() + self._timeout, invocation.expires_monotonic)
        lineage_handles = list(invocation.source_receipt_handles)
        try:
            init = self._rpc_effect(
                peer_uid, peer_pid, peer_pidfd, invocation, service, operation, target,
                request_id=secrets.token_urlsafe(16), method="initialize", selection=selection,
                params={"protocolVersion": SUPPORTED_PROTOCOL_VERSIONS[0], "capabilities": {},
                        "clientInfo": {"name": "hermes-installer", "version": "0.1.0"}},
                deadline=deadline, cancelled=cancelled, lineage_handles=lineage_handles,
            )
            init_result = init.value.get("result")
            if (not isinstance(init_result, Mapping)
                    or init_result.get("protocolVersion") not in SUPPORTED_PROTOCOL_VERSIONS
                    or not isinstance(init_result.get("capabilities"), Mapping)
                    or not isinstance(init_result.get("serverInfo"), Mapping)):
                raise MCPError("MCP initialization response is invalid")
            self._rpc_effect(
                peer_uid, peer_pid, peer_pidfd, invocation, service, operation, target,
                request_id=None, method="notifications/initialized", selection=selection,
                params={}, deadline=deadline, cancelled=cancelled,
                lineage_handles=lineage_handles, notification=True,
            )
            selected_schema = self._discover(
                peer_uid, peer_pid, peer_pidfd, invocation, service, operation, target,
                selection, deadline, cancelled, lineage_handles, binding.mcp_tool_name,
            )
            if _canonical_schema(selected_schema.get("inputSchema", {})) != _canonical_schema(request_schema):
                raise MCPError("MCP discovered schema differs from its protected artifact")
            annotations = selected_schema.get("annotations", {})
            if (not isinstance(annotations, Mapping) or annotations.get("readOnlyHint") is not True
                    or annotations.get("destructiveHint") is True):
                raise MCPError("selected MCP tool is not reviewed as read-only")
            request_id = secrets.token_urlsafe(16)
            response = self._rpc_effect(
                peer_uid, peer_pid, peer_pidfd, invocation, service, operation, target,
                request_id=request_id, method="tools/call", selection=selection,
                params={"name": binding.mcp_tool_name, "arguments": arguments},
                deadline=deadline, cancelled=cancelled,
                lineage_handles=lineage_handles, consume_sources=True,
            )
            if response.source_receipt_handle is None:
                raise MCPError("MCP result was not delivered with its root source receipt")
            result = response.value["result"]
            if (not isinstance(result, Mapping) or result.get("isError") is True):
                raise MCPError("selected MCP tool returned an error")
            _validate_value(result, result_schema)
            scrubbed = scrub_mcp_result(service.service_id)(result)
            if canonical_bytes(scrubbed) != canonical_bytes(result):
                # The host broker must capture exactly the bytes exposed here.
                # If it did not scrub at the pre-capture boundary, do not claim
                # the broker's source receipt describes the exposed result.
                raise MCPError("MCP result was not scrubbed before root observation")
            body = canonical_bytes({"jsonrpc": "2.0", "id": request_id, "result": scrubbed})
            if len(body) > _MAX_OUTPUT_BYTES or cancelled() or self._monotonic() >= deadline:
                raise MCPError("native MCP result exceeded its aggregate deadline or bound")
            return BrokeredEffectResponse(
                200, body, {"content-type": "application/json"},
                "native-mcp-" + hashlib.sha256(body).hexdigest()[:24],
                source_receipt_handle=response.source_receipt_handle,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise NativeMCPExecutionDenied("native.mcp.effect", "selected native MCP read was denied or unavailable") from None

    def _validate_binding(self, binding: Any, invocation: RootNativeMCPInvocation) -> None:
        if (getattr(binding, "adapter_id", None) != _ADAPTER_ID
                or getattr(binding, "id", None) != invocation.action_id
                or getattr(binding, "adapter_id", None) != invocation.adapter_id
                or getattr(binding, "native_package_id", None) != invocation.package_id
                or getattr(binding, "native_package_generation", None) != invocation.package_generation
                or getattr(binding, "profile_id", None) != invocation.profile_id
                or getattr(binding, "process_generation", None) != invocation.process_generation
                or getattr(binding, "handler_artifact_id", None) != _ADAPTER_ID
                or getattr(binding, "effect_operation", None) not in {"mcp.request", "mcp.stdio"}
                or getattr(binding, "capability", None) != f"mcp:{getattr(binding, 'mcp_enrollment_id', '')}:read"
                or getattr(binding, "recipient", None) is not None):
            raise NativeMCPExecutionDenied("native.mcp.action", "root invocation does not match its selected MCP action")
        if (invocation.package_id != getattr(binding, "native_package_id", None)
                or invocation.package_generation != getattr(binding, "native_package_generation", None)):
            raise NativeMCPExecutionDenied("native.mcp.package", "selected native package generation changed")
        if self.service.profile_generations.get(invocation.profile_id) != invocation.process_generation:
            raise NativeMCPExecutionDenied("native.mcp.profile", "selected native process generation is stale")

    def _require_result_observer(self, service: ProtectedMCPService,
                                 operation: str, target: str) -> None:
        key = (f"mcp:{service.service_id}:read", operation, target)
        observer = getattr(self.service, "native_runtime_observer", None)
        observers = getattr(observer, "effect_observer_ids", None)
        delivery = getattr(self.service, "source_receipt_delivery", None)
        if (not isinstance(observers, Mapping) or key not in observers
                or not callable(getattr(observer, "observe_effect_result", None))
                or not callable(getattr(delivery, "take_source_receipt", None))):
            raise NativeMCPExecutionDenied(
                "native.mcp.lineage", "selected MCP result capture and peer delivery are unavailable",
            )

    def _require_current(self, invocation: RootNativeMCPInvocation) -> None:
        try:
            current = self._invocations.is_current(invocation)
        except Exception:
            current = False
        if current is not True:
            raise NativeMCPExecutionDenied(
                "native.mcp.stale", "native MCP invocation, source closure or package generation is stale",
            )

    def _resolve_schema(self, binding: Any, kind: str) -> Mapping[str, Any]:
        schema_id = (binding.request_schema_id if kind == "arguments" else binding.result_schema_id)
        schema = self._schemas.resolve(
            schema_id, native_package_id=binding.native_package_id,
            native_package_generation=binding.native_package_generation,
            adapter_id=binding.handler_artifact_id, action_id=binding.id,
            schema_kind=kind,
        )
        try:
            return _bound_schema(schema)
        except Exception:
            raise NativeMCPExecutionDenied("native.mcp.schema", "protected MCP schema artifact is unavailable") from None

    @staticmethod
    def _validate_selection(binding: Any, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        scopes = getattr(binding, "scope_bindings", None)
        if not isinstance(scopes, tuple) or not scopes:
            raise NativeMCPExecutionDenied("native.mcp.selection", "selected MCP resource binding is unavailable")
        selection = {field: resource for field, resource in scopes}
        service_selection = set(selection)
        if any(arguments.get(field) != expected or type(arguments.get(field)) is not str
               for field, expected in selection.items()):
            raise NativeMCPExecutionDenied("native.mcp.selection", "MCP arguments differ from the selected resource")
        if not service_selection:
            raise NativeMCPExecutionDenied("native.mcp.selection", "selected MCP resource binding is empty")
        return selection

    def _service_for(self, binding: Any) -> tuple[ProtectedMCPService, str, str]:
        enrollment = binding.mcp_enrollment_id
        service = self._services.get(enrollment)
        generation = self._generations.get(enrollment)
        if (type(service) is not ProtectedMCPService or generation != binding.mcp_generation
                or binding.mcp_tool_name not in service.allowed_tools
                or tuple(service.selection_arguments.get(binding.mcp_tool_name, ()))
                   != tuple(field for field, _value in binding.scope_bindings)):
            raise NativeMCPExecutionDenied("native.mcp.enrollment", "selected MCP service generation is stale")
        operation = "mcp.request" if service.channel == "http" else "mcp.stdio"
        target = f"mcp:{service.service_id}:{service.channel}"
        if (binding.effect_operation != operation or binding.effect_target != target
                or (binding.capability, operation, target) not in self.service.rules
                or (operation, target) not in self.service.handlers):
            raise NativeMCPExecutionDenied("native.mcp.effect", "selected MCP fixed effect is unavailable")
        if service.channel != "http":
            raise NativeMCPExecutionDenied("native.mcp.transport", "selected stdio service has no live supervised lease")
        return service, operation, target

    def _discover(self, uid: int, pid: int, pidfd: int, invocation: RootNativeMCPInvocation,
                  service: ProtectedMCPService, operation: str, target: str,
                  selection: Mapping[str, Any], deadline: float,
                  cancelled: Callable[[], bool], lineage_handles: list[str],
                  selected_tool: str) -> Mapping[str, Any]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        selected: Mapping[str, Any] | None = None
        for _ in range(_MAX_DISCOVERY_PAGES):
            params = {"cursor": cursor} if cursor is not None else {}
            response = self._rpc_effect(
                uid, pid, pidfd, invocation, service, operation, target,
                request_id=secrets.token_urlsafe(12), method="tools/list", selection=selection,
                params=params, deadline=deadline, cancelled=cancelled,
                lineage_handles=lineage_handles,
            )
            result = response.value.get("result")
            if not isinstance(result, Mapping) or not isinstance(result.get("tools"), list):
                raise MCPError("MCP discovery response is malformed")
            for row in result["tools"]:
                if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
                    raise MCPError("MCP discovery row is malformed")
                if row["name"] == selected_tool:
                    if selected is not None:
                        raise MCPError("MCP selected tool was duplicated across pages")
                    selected = row
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                break
            if (not isinstance(next_cursor, str) or not next_cursor
                    or len(next_cursor) > 1024 or next_cursor in seen_cursors):
                raise MCPError("MCP discovery cursor is invalid or repeated")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise MCPError("MCP discovery exceeded its page limit")
        if selected is None:
            raise MCPError("selected MCP tool was not discovered")
        return selected

    def _rpc_effect(self, uid: int, pid: int, pidfd: int,
                    invocation: RootNativeMCPInvocation,
                    service: ProtectedMCPService, operation: str, target: str, *,
                    request_id: Any, method: str, selection: Mapping[str, Any],
                    params: Mapping[str, Any], deadline: float,
                    cancelled: Callable[[], bool], lineage_handles: list[str],
                    notification: bool = False,
                    consume_sources: bool = False) -> _MCPResponse:
        remaining = min(deadline, invocation.expires_monotonic) - self._monotonic()
        self._require_current(invocation)
        if remaining <= 0 or cancelled():
            raise NativeMCPExecutionDenied("native.mcp.deadline", "MCP call was cancelled or expired")
        envelope = {
            "schema": 1, "service_id": service.service_id,
            "request_id": request_id, "method": method,
            "selection": dict(selection), "params": dict(params),
        }
        payload = canonical_bytes(envelope)
        digest = canonical_digest(payload)
        intent = mcp_intent(service.service_id, service.channel, request_id,
                            method, selection, params)
        purpose = "mcp-selected-resource-read" if method == "tools/call" else "mcp-connection-lifecycle"
        context_wire = self.service._issue_context(uid, {
            "purpose": purpose, "intent": intent,
            "trace_id": secrets.token_urlsafe(18), "lease_seconds": min(30.0, remaining),
            "source_contexts": [], "source_receipt_handles": list(lineage_handles),
            "final_payload_digest": digest, "operation": operation,
        }, peer_pid=pid, inherited_process_identity=invocation.native_process_identity)
        context = HostContext.from_wire(context_wire)
        rule = self.service.rules.get((
            f"mcp:{service.service_id}:{'read' if method == 'tools/call' else 'connect'}",
            operation, target,
        ))
        capability = f"mcp:{service.service_id}:{'read' if method == 'tools/call' else 'connect'}"
        if rule is None or rule.recipient is not None:
            raise NativeMCPExecutionDenied("native.mcp.rule", "selected MCP effect rule is unavailable")
        grant_wire = self.service._authorize_effect(uid, {
            "context": context.to_wire(), "capability": capability,
            "target": target, "recipient": None, "request_digest": digest,
            "retry_index": 0,
        }, peer_pid=pid)
        grant = EffectAuthorization.from_wire(grant_wire)
        self._require_current(invocation)
        if cancelled() or self._monotonic() >= min(deadline, invocation.expires_monotonic,
                                                    grant.monotonic_expires_at):
            raise NativeMCPExecutionDenied("native.mcp.deadline", "MCP call expired before broker dispatch")
        result = self.service._perform_effect(uid, pid, {
            "authorization": grant.to_wire(), "operation": operation,
            "payload": base64.b64encode(payload).decode("ascii"),
            "timeout": min(remaining, grant.monotonic_expires_at - self._monotonic()),
        }, cancelled=cancelled, peer_pidfd=pidfd,
            source_receipt_ids_to_consume=(frozenset(receipt.receipt_id for receipt in context.source_receipts)
                                           if consume_sources else frozenset()),
        )
        if (not isinstance(result, Mapping) or set(result) - {
                "status", "body", "headers", "receipt_id", "source_receipt_handle"}
                or not {"status", "body", "headers", "receipt_id"}.issubset(result)):
            raise NativeMCPExecutionDenied("native.mcp.response", "MCP broker response is malformed")
        if notification:
            if result["status"] not in {200, 202, 204}:
                raise MCPError("MCP notification failed")
            return _MCPResponse({})
        if result["status"] not in {200, 202, 204}:
            raise MCPError("MCP broker rejected the selected request")
        body = base64.b64decode(result["body"], validate=True)
        if not 1 <= len(body) <= _MAX_OUTPUT_BYTES:
            raise MCPError("MCP response exceeds its result bound")
        response = strict_json_loads(body.decode("utf-8"))
        if (not isinstance(response, Mapping)
                or canonical_bytes(response) != body
                or response.get("jsonrpc") != "2.0"
                or response.get("id") != request_id
                or "error" in response or "result" not in response):
            raise MCPError("MCP response failed correlation or protocol validation")
        source_handle = result.get("source_receipt_handle")
        if source_handle is not None:
            if not isinstance(source_handle, str) or not _OPAQUE.fullmatch(source_handle):
                raise NativeMCPExecutionDenied("native.mcp.lineage", "MCP result receipt handle is invalid")
            if source_handle not in lineage_handles:
                if len(lineage_handles) >= _MAX_SOURCE_HANDLES:
                    raise NativeMCPExecutionDenied("native.mcp.lineage", "MCP result receipt closure is oversized")
                lineage_handles.append(source_handle)
        return _MCPResponse(response, source_handle)
