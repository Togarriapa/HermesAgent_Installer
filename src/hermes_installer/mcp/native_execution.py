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
import json
import re
import secrets
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..authority import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext,
    canonical_bytes, canonical_digest,
)
from ..authority.native_runtime_observer import NativeInvocationRegistry
from ..authority.service import AuthorityService
from ..authority.types import strict_json_loads
from ..authority.native_runtime_observer import RootNativeMCPInvocation
from ..authority.mcp_discovery_registry import MCPDiscoveryObservationRegistry
from .broker import ProtectedMCPService, mcp_intent
from .native_dispatch import NativeMCPRegistrationIndex
from .native_schema_catalog import NativeMCPProtectedSchemaCatalog
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
    return json.dumps(
        _thaw(value), sort_keys=True, separators=(",", ":"),
        ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _bound_schema(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError("native MCP schema artifact is unavailable")
    schema = _thaw(value)
    _validate_schema(schema)
    return schema


class NativeMCPExecutionDenied(AuthorityDenied):
    """The root could not prove the complete native MCP execution binding."""


def build_native_mcp_schema_catalog(records: Any, *, authority_service: Any,
                                    artifact_catalog: Any, staging_root: Path,
                                    expected_uid: int = 0) -> Any:
    """Build the schema catalog from CAS bytes and retained signed source receipts.

    This factory is root-runtime-only. ``records`` must already be the exact
    protected native schema rows selected by ``RootRuntimeBindings``; the
    caller cannot supply artifact paths or a receipt-verification callback.
    """
    from ..artifacts import ArtifactCatalog
    from .native_schema_catalog import NativeMCPProtectedSchemaCatalog

    if (not isinstance(artifact_catalog, ArtifactCatalog)
            or not isinstance(staging_root, Path) or not staging_root.is_absolute()
            or type(expected_uid) is not int or expected_uid < 0
            or not callable(getattr(authority_service, "resolve_retained_source_receipt", None))):
        raise TypeError("root CAS and source receipt services are required")

    def read_artifact(artifact_id: str, digest: str) -> bytes:
        resolved = artifact_catalog.resolve(
            artifact_id, digest, staging_root, expected_uid=expected_uid,
        )
        body = resolved.path.read_bytes()
        if hashlib.sha256(body).hexdigest() != digest:
            raise NativeMCPExecutionDenied("native.mcp.artifact", "schema CAS bytes changed during read")
        return body

    def verify_source_receipt(handle: str, identity: Mapping[str, str]) -> bool:
        try:
            from ..authority.source_observers import SourceReceiptHandle
            authority_service.resolve_retained_source_receipt(
                SourceReceiptHandle(handle), payload_digest=identity.get("sha256", ""),
            )
        except Exception:
            return False
        return True

    return NativeMCPProtectedSchemaCatalog.from_protected_records(
        records, read_artifact=read_artifact,
        verify_source_receipt=verify_source_receipt,
    )


class NativeMCPInvocationResolver(Protocol):
    """Root-only, one-use resolver for live HI11/HI12 native tool calls."""

    def consume_native_mcp_invocation(
        self, peer_uid: int, peer_pid: int, peer_pidfd: int,
        invocation_handle: str, canonical_arguments: bytes,
    ) -> RootNativeMCPInvocation: ...

    def is_current_native_mcp_invocation(
        self, invocation: RootNativeMCPInvocation, peer_uid: int,
        peer_pid: int, peer_pidfd: int,
    ) -> bool:
        """Recheck process, loaded package, action and source closure at each effect."""
        ...


@dataclass(frozen=True, slots=True)
class _MCPResponse:
    value: Mapping[str, Any]
    source_receipt_handle: str | None = None
    request_payload: bytes | None = None
    response_payload: bytes | None = None
    context: HostContext | None = None
    authorization: EffectAuthorization | None = None
    parent_receipt_handles: tuple[str, ...] = ()


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
                 mcp_discovery_registry: MCPDiscoveryObservationRegistry,
                 monotonic: Callable[[], float] = time.monotonic,
                 timeout: float = _TIMEOUT) -> None:
        if type(service) is not AuthorityService:
            raise TypeError("the live root AuthorityService is required")
        if (type(registration_index) is not NativeMCPRegistrationIndex
                or type(schema_catalog) is not NativeMCPProtectedSchemaCatalog):
            raise TypeError("root native MCP registration and schema catalogs are required")
        if (not isinstance(protected_services, Mapping)
                or not isinstance(current_mcp_generations, Mapping)
                or type(invocation_resolver) is not NativeInvocationRegistry):
            raise TypeError("root MCP enrollment and one-use invocation resolver are required")
        if (type(mcp_discovery_registry) is not MCPDiscoveryObservationRegistry
                or mcp_discovery_registry.service is not service
                or mcp_discovery_registry.ready is not True):
            raise TypeError("root authenticated MCP discovery registry is required")
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
        self._discovery = mcp_discovery_registry
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
            invocation = self._invocations.consume_native_mcp_invocation(
                peer_uid, peer_pid, peer_pidfd, invocation_handle, canonical_arguments,
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
            self._require_current(invocation, peer_uid, peer_pid, peer_pidfd)
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
            selected_schema, discovery_response = self._discover(
                peer_uid, peer_pid, peer_pidfd, invocation, service, operation, target,
                selection, deadline, cancelled, lineage_handles, binding.mcp_tool_name,
            )
            for schema_kind, schema_key, expected_schema in (
                ("arguments", "inputSchema", request_schema),
                ("result", "outputSchema", result_schema),
            ):
                if schema_key not in selected_schema:
                    raise MCPError(f"MCP selected tool has no {schema_key}")
                discovered = selected_schema[schema_key]
                if not isinstance(discovered, Mapping) or (
                        _canonical_schema(discovered) != _canonical_schema(expected_schema)):
                    raise MCPError("MCP discovered schema differs from its protected artifact")
                self._discovery.capture_tools_list(
                    invocation=invocation, peer_uid=peer_uid, peer_pid=peer_pid,
                    peer_pidfd=peer_pidfd, service=service, binding=binding,
                    mcp_generation=self._generations[binding.mcp_enrollment_id],
                    selection=selection,
                    request_payload=discovery_response.request_payload,
                    response_payload=discovery_response.response_payload,
                    response_receipt_handle=discovery_response.source_receipt_handle,
                    context=discovery_response.context,
                    authorization=discovery_response.authorization,
                    parent_receipt_handles=discovery_response.parent_receipt_handles,
                    schema_kind=schema_kind,
                )
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
            # Invocation consumption is one-use, but revocation, profile unload,
            # process replacement, or peer termination can still happen while
            # the broker is performing I/O. Recheck the exact consumed DTO at
            # the release boundary before exposing either bytes or its receipt.
            self._require_current(invocation, peer_uid, peer_pid, peer_pidfd)
            if cancelled() or self._monotonic() >= deadline:
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
        adapter_id = getattr(binding, "adapter_id", getattr(binding, "handler_artifact_id", None))
        if (adapter_id != _ADAPTER_ID
                or getattr(binding, "id", None) != invocation.action_id
                or adapter_id != invocation.adapter_id
                or getattr(binding, "native_package_id", None) != invocation.package_id
                or getattr(binding, "process_generation", None) != invocation.generation
                or getattr(binding, "profile_id", None) != invocation.profile_id
                or getattr(binding, "process_generation", None) != invocation.generation
                or getattr(binding, "native_tool_name", None) != invocation.tool_name
                or getattr(binding, "handler_artifact_id", None) != _ADAPTER_ID
                or getattr(binding, "effect_operation", None) not in {"mcp.request", "mcp.stdio"}
                or getattr(binding, "capability", None) != f"mcp:{getattr(binding, 'mcp_enrollment_id', '')}:read"
                or getattr(binding, "recipient", None) is not None):
            raise NativeMCPExecutionDenied("native.mcp.action", "root invocation does not match its selected MCP action")
        if (invocation.package_id != getattr(binding, "native_package_id", None)
                or invocation.generation != getattr(binding, "process_generation", None)):
            raise NativeMCPExecutionDenied("native.mcp.package", "selected native package generation changed")
        if self.service.profile_generations.get(invocation.profile_id) != invocation.generation:
            raise NativeMCPExecutionDenied("native.mcp.profile", "selected native process generation is stale")
        if (not isinstance(invocation.service_generation_digest, str)
                or not _SHA256.fullmatch(invocation.service_generation_digest)
                or self.service.service_generation_digest != invocation.service_generation_digest):
            raise NativeMCPExecutionDenied("native.mcp.service", "native MCP invocation uses a stale service generation")

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

    def _require_current(self, invocation: RootNativeMCPInvocation,
                         peer_uid: int, peer_pid: int, peer_pidfd: int) -> None:
        try:
            current = self._invocations.is_current_native_mcp_invocation(
                invocation, peer_uid, peer_pid, peer_pidfd,
            )
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
                  selected_tool: str) -> tuple[Mapping[str, Any], _MCPResponse]:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        selected: Mapping[str, Any] | None = None
        selected_response: _MCPResponse | None = None
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
                    selected_response = response
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
        if selected is None or selected_response is None:
            raise MCPError("selected MCP tool was not discovered")
        return selected, selected_response

    def _rpc_effect(self, uid: int, pid: int, pidfd: int,
                    invocation: RootNativeMCPInvocation,
                    service: ProtectedMCPService, operation: str, target: str, *,
                    request_id: Any, method: str, selection: Mapping[str, Any],
                    params: Mapping[str, Any], deadline: float,
                    cancelled: Callable[[], bool], lineage_handles: list[str],
                    notification: bool = False,
                    consume_sources: bool = False) -> _MCPResponse:
        remaining = min(deadline, invocation.expires_monotonic) - self._monotonic()
        self._require_current(invocation, uid, pid, pidfd)
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
        purpose = ("mcp-selected-resource-read" if method == "tools/call"
                   else "mcp-selected-schema-discovery" if method == "tools/list"
                   else "mcp-connection-lifecycle")
        # Discovery evidence is always derived from the active publication's
        # original source closure. Earlier protocol pages are dynamic evidence,
        # not authority to enlarge that closure.
        parent_handles = (tuple(invocation.source_receipt_handles) if method == "tools/list"
                          else tuple(lineage_handles))
        context_wire = self.service._issue_context(uid, {
            "purpose": purpose, "intent": intent,
            "trace_id": secrets.token_urlsafe(18), "lease_seconds": min(30.0, remaining),
            "source_contexts": [], "source_receipt_handles": list(parent_handles),
            "final_payload_digest": digest, "operation": operation,
        }, peer_pid=pid)
        context = HostContext.from_wire(context_wire)
        rule = self.service.rules.get((
            f"mcp:{service.service_id}:{'read' if method == 'tools/call' else 'connect'}",
            operation, target,
        ))
        capability = f"mcp:{service.service_id}:{'read' if method in {'tools/list', 'tools/call'} else 'connect'}"
        if rule is None or rule.recipient is not None:
            raise NativeMCPExecutionDenied("native.mcp.rule", "selected MCP effect rule is unavailable")
        grant_wire = self.service._authorize_effect(uid, {
            "context": context.to_wire(), "capability": capability,
            "target": target, "recipient": None, "request_digest": digest,
            "retry_index": 0,
        }, peer_pid=pid)
        grant = EffectAuthorization.from_wire(grant_wire)
        self._require_current(invocation, uid, pid, pidfd)
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
        if method == "tools/list" and (not isinstance(source_handle, str)
                                         or not _OPAQUE.fullmatch(source_handle)):
            raise NativeMCPExecutionDenied(
                "native.mcp.discovery", "tools/list result lacks a root-observed source receipt",
            )
        if source_handle is not None:
            if not isinstance(source_handle, str) or not _OPAQUE.fullmatch(source_handle):
                raise NativeMCPExecutionDenied("native.mcp.lineage", "MCP result receipt handle is invalid")
            if source_handle not in lineage_handles:
                if len(lineage_handles) >= _MAX_SOURCE_HANDLES:
                    raise NativeMCPExecutionDenied("native.mcp.lineage", "MCP result receipt closure is oversized")
                lineage_handles.append(source_handle)
        return _MCPResponse(
            response, source_handle, payload, body, context, grant, parent_handles,
        )
