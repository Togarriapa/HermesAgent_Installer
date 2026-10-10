"""Root-retained witnesses for authenticated MCP ``tools/list`` schemas.

Only the in-process root MCP dispatcher can submit an observation. The
registry joins the exact fixed-effect grant, broker request/response bytes,
root source receipt, selected native action/schema row, source-parent closure,
and live native invocation. A worker cannot provide a URL, response body,
schema, receipt, process identity, or currentness callback.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .native_runtime_observer import NativeInvocationRegistry, RootNativeMCPInvocation
from .runtime_bindings import RootRuntimeBindings
from .service import AuthorityService
from .source_observers import SourceReceiptHandle
from .types import EffectAuthorization, HostContext, SourceReceipt, canonical_bytes, canonical_digest, strict_json_loads
from ..mcp.broker import ProtectedMCPService, mcp_intent
from ..mcp.native_dispatch import NativeMCPToolBinding


_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_REQUEST = 1_048_576
_MAX_RESPONSE = 1_048_576
_MAX_SCHEMA = 256 * 1024
_MAX_TOOLS = 512
_MAX_WITNESSES = 512
_MAX_LEASE = 30.0
_SCHEMA_ROLES = {"arguments": "inputSchema", "result": "outputSchema"}
_PROCESS_IDENTITY_FIELDS = (
    "profile_id", "generation", "kernel_uid", "executable_sha256", "pid",
    "pid_starttime_ticks", "executable_device", "executable_inode",
)


class MCPDiscoveryUnavailable(PermissionError):
    """The tools/list bytes are not bound to a current protected discovery."""


@dataclass(frozen=True, slots=True, repr=False)
class MCPDiscoverySchemaObservation:
    """Typed root proof consumed by ``RootSchemaDerivationReceiptRegistry``."""

    artifact_id: str
    artifact_sha256: str
    size_bytes: int
    schema_kind: str
    package_id: str
    package_generation: str
    adapter_id: str
    action_id: str
    service_generation_digest: str
    schema_bytes: bytes = field(repr=False)
    request_sha256: str
    response_sha256: str
    service_id: str
    mcp_generation: str
    mcp_tool_name: str
    native_tool_name: str
    profile_id: str
    process_generation: str
    invocation_handle: str
    invocation_proof_id: str
    response_receipt_handle: str
    parent_receipt_handles: tuple[str, ...]
    source_observation_handle: str
    expires_monotonic: float
    capability: str
    operation: str
    target: str
    selection_sha256: str


@dataclass(slots=True)
class _RetainedDiscovery:
    observation: MCPDiscoverySchemaObservation
    invocation: RootNativeMCPInvocation
    peer_uid: int
    peer_pid: int
    peer_pidfd: int
    request_payload: bytes
    response_payload: bytes
    context: HostContext
    authorization: EffectAuthorization
    selection: Mapping[str, str]
    parent_receipts: tuple[SourceReceipt, ...]
    derivation_receipt_handle: str | None = None


class MCPDiscoveryObservationRegistry:
    """Retain and revalidate root-observed schemas from selected MCP servers.

    The instance is wired into ``NativeMCPDispatcher`` by root composition.
    Its capture method is called only after ``AuthorityService._perform_effect``
    has authorized the fixed target and source-observed the complete response.
    """

    def __init__(self, *, service: AuthorityService,
                 invocation_registry: NativeInvocationRegistry | None,
                 runtime_bindings: RootRuntimeBindings,
                 registration_index: Any,
                 protected_services: Mapping[str, ProtectedMCPService],
                 current_mcp_generations: Mapping[str, str],
                 monotonic: Callable[[], float] = time.monotonic,
                 lease_seconds: float = _MAX_LEASE) -> None:
        if (type(service) is not AuthorityService
                or invocation_registry is not None and type(invocation_registry) is not NativeInvocationRegistry
                or type(runtime_bindings) is not RootRuntimeBindings):
            raise TypeError("root authority, selected runtime bindings, and native invocation registry are required")
        from ..mcp.native_dispatch import NativeMCPRegistrationIndex
        if type(registration_index) is not NativeMCPRegistrationIndex:
            raise TypeError("root native MCP registration index is required")
        if not 0 < lease_seconds <= _MAX_LEASE or not callable(monotonic):
            raise ValueError("MCP discovery observation lease is invalid")
        if not isinstance(protected_services, Mapping) or not isinstance(current_mcp_generations, Mapping):
            raise TypeError("root MCP service generations are invalid")
        services = dict(protected_services)
        generations = dict(current_mcp_generations)
        if any(type(value) is not ProtectedMCPService or value.service_id != key
               for key, value in services.items()):
            raise TypeError("protected MCP service map contains an invalid record")
        if any(not isinstance(key, str) or not isinstance(value, str) or not value
               for key, value in generations.items()):
            raise TypeError("protected MCP generation map is invalid")
        if runtime_bindings.enrollment_catalog.digest != service.service_generation_digest:
            raise MCPDiscoveryUnavailable("runtime bindings do not match the live authority generation")
        self.service = service
        self._invocations = invocation_registry
        self._schema_derivations: Any | None = None
        self._bindings = runtime_bindings
        self._registrations = registration_index
        self._services = MappingProxyType(services)
        self._generations = MappingProxyType(generations)
        self._monotonic = monotonic
        self._lease = float(lease_seconds)
        self._lock = threading.RLock()
        self._records: dict[str, _RetainedDiscovery] = {}
        self._closed = False

    @property
    def ready(self) -> bool:
        """True only after the root schema issuer and selected invocation registry attach."""
        with self._lock:
            from .artifacts import RootSchemaDerivationReceiptRegistry
            issuer = self._schema_derivations
            return (not self._closed
                    and type(self._invocations) is NativeInvocationRegistry
                    and type(issuer) is RootSchemaDerivationReceiptRegistry
                    and issuer.mcp_discovery_registry is self)

    def attach_schema_derivation_registry(self, registry: Any) -> None:
        """Attach the exact root CAS/receipt issuer once before dispatcher publication."""
        from .artifacts import RootSchemaDerivationReceiptRegistry
        if (type(registry) is not RootSchemaDerivationReceiptRegistry
                or registry.mcp_discovery_registry is not self):
            raise TypeError("the matching root schema derivation registry is required")
        with self._lock:
            if self._closed or self._schema_derivations is not None or self._records:
                raise MCPDiscoveryUnavailable("schema derivation issuer is already attached or discovery has begun")
            self._schema_derivations = registry

    def attach_invocation_registry(self, registry: NativeInvocationRegistry) -> None:
        """Complete root construction once before dispatcher publication."""
        if type(registry) is not NativeInvocationRegistry or registry.service is not self.service:
            raise TypeError("the matching root NativeInvocationRegistry is required")
        with self._lock:
            if self._closed or self._invocations is not None or self._records:
                raise MCPDiscoveryUnavailable("MCP discovery resolver is already attached or registry is closed")
            self._invocations = registry

    def capture_tools_list(
        self, *, invocation: RootNativeMCPInvocation, peer_uid: int, peer_pid: int,
        peer_pidfd: int, service: ProtectedMCPService, binding: NativeMCPToolBinding,
        mcp_generation: str, selection: Mapping[str, str], request_payload: bytes,
        response_payload: bytes, response_receipt_handle: str,
        context: HostContext, authorization: EffectAuthorization,
        parent_receipt_handles: tuple[str, ...], schema_kind: str,
    ) -> MCPDiscoverySchemaObservation:
        """Capture one selected tool schema from a successful brokered tools/list."""
        if self.ready is not True:
            raise MCPDiscoveryUnavailable("root schema issuer and invocation registry are not ready")
        if (type(invocation) is not RootNativeMCPInvocation
                or type(service) is not ProtectedMCPService
                or type(binding) is not NativeMCPToolBinding
                or type(context) is not HostContext
                or type(authorization) is not EffectAuthorization
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not isinstance(request_payload, bytes) or not 1 <= len(request_payload) <= _MAX_REQUEST
                or not isinstance(response_payload, bytes) or not 1 <= len(response_payload) <= _MAX_RESPONSE
                or not isinstance(response_receipt_handle, str) or not _OPAQUE.fullmatch(response_receipt_handle)
                or not isinstance(parent_receipt_handles, tuple)
                or not isinstance(schema_kind, str) or schema_kind not in _SCHEMA_ROLES
                or not 1 <= len(parent_receipt_handles) <= 8
                or any(not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                       for handle in parent_receipt_handles)
                or len(set(parent_receipt_handles)) != len(parent_receipt_handles)):
            raise MCPDiscoveryUnavailable("root MCP discovery observation is malformed")
        try:
            if parent_receipt_handles != invocation.source_receipt_handles:
                raise ValueError
            self._require_live(invocation, peer_uid, peer_pid, peer_pidfd, service, binding, mcp_generation)
            envelope = strict_json_loads(request_payload.decode("utf-8"))
            if not isinstance(envelope, Mapping) or canonical_bytes(envelope) != request_payload:
                raise ValueError
            expected_selection = {field: resource for field, resource in binding.scope_bindings}
            if (dict(selection) != expected_selection
                    or envelope.get("schema") != 1
                    or envelope.get("service_id") != service.service_id
                    or envelope.get("method") != "tools/list"
                    or envelope.get("selection") != expected_selection
                    or not isinstance(envelope.get("request_id"), str)
                    or not isinstance(envelope.get("params"), Mapping)):
                raise ValueError
            params = envelope["params"]
            if set(params) - {"cursor"} or (
                    "cursor" in params and (not isinstance(params["cursor"], str)
                                           or not 1 <= len(params["cursor"]) <= 1024)):
                raise ValueError
            expected_intent = mcp_intent(
                service.service_id, service.channel, envelope["request_id"],
                "tools/list", expected_selection, params,
            )
            expected_intent_id = canonical_digest({
                "purpose": "mcp-selected-schema-discovery", "intent": expected_intent,
            })
            request_digest = canonical_digest(request_payload)
            capability = f"mcp:{service.service_id}:read"
            target = f"mcp:{service.service_id}:http"
            if (service.channel != "http"
                    or context.uid != peer_uid or context.profile_id != invocation.profile_id
                    or context.generation != invocation.generation
                    or context.native_process_identity
                       != self.service._native_process_identity(peer_pid, peer_uid)
                    or context.purpose != "mcp-selected-schema-discovery"
                    or context.intent_id != expected_intent_id
                    or context.operation != "mcp.request"
                    or context.final_payload_digest != request_digest
                    or authorization.uid != peer_uid
                    or authorization.profile_id != invocation.profile_id
                    or authorization.generation != invocation.generation
                    or authorization.operation != "mcp.request"
                    or authorization.capability != capability
                    or authorization.target != target
                    or authorization.recipient is not None
                    or authorization.intent_id != expected_intent_id
                    or authorization.request_digest != request_digest
                    or authorization.final_payload_digest != request_digest
                    or authorization.retry_index != 0
                    or authorization.source_receipts != context.source_receipts
                    or tuple(sorted(receipt.receipt_id for receipt in context.source_receipts))
                       != self._parent_ids(parent_receipt_handles, context.source_receipts,
                                           peer_uid, invocation.profile_id, invocation.generation)):
                raise ValueError
            if self.service.revalidate_effect(
                    context, authorization, operation="mcp.request",
                    request_digest=request_digest, retry_index=0) is not True:
                raise ValueError
            response = strict_json_loads(response_payload.decode("utf-8"))
            if (not isinstance(response, Mapping) or canonical_bytes(response) != response_payload
                    or response.get("jsonrpc") != "2.0"
                    or response.get("id") != envelope["request_id"]
                    or not isinstance(response.get("result"), Mapping)
                    or not isinstance(response["result"].get("tools"), list)
                    or len(response["result"]["tools"]) > _MAX_TOOLS):
                raise ValueError
            candidates = [tool for tool in response["result"]["tools"]
                          if isinstance(tool, Mapping) and tool.get("name") == binding.mcp_tool_name]
            if len(candidates) != 1:
                raise ValueError
            schema = candidates[0].get(_SCHEMA_ROLES[schema_kind])
            if not isinstance(schema, Mapping):
                raise ValueError
            from ..mcp.native_schema_catalog import _validate_schema
            _validate_schema(schema, nodes=[0])
            schema_bytes = json.dumps(
                schema, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8")
            if not 1 <= len(schema_bytes) <= _MAX_SCHEMA:
                raise ValueError
            schema_digest = hashlib.sha256(schema_bytes).hexdigest()
            schema_artifact_id = f"native-mcp-schema:{schema_digest}"
            receipt = self._resolve_receipt(
                response_receipt_handle, hashlib.sha256(response_payload).hexdigest(),
                peer_uid, invocation.profile_id, invocation.generation,
            )
            expected_parent_receipts = self._resolve_parents(
                parent_receipt_handles, context.source_receipts,
                peer_uid, invocation.profile_id, invocation.generation,
            )
            expected_parent_ids = tuple(sorted(item.receipt_id for item in expected_parent_receipts))
            if (receipt.source_kind != "tool-result"
                    or tuple(sorted(receipt.parent_receipt_ids)) != expected_parent_ids):
                raise ValueError
            now = self._monotonic()
            expires = min(
                now + self._lease, invocation.expires_monotonic,
                context.monotonic_expires_at, authorization.monotonic_expires_at,
                receipt.monotonic_expires_at,
                *(item.monotonic_expires_at for item in expected_parent_receipts),
            )
            if expires <= now:
                raise ValueError
            invocation_proof_id = canonical_digest({
                "invocation_handle": invocation.invocation_handle,
                "arguments_sha256": invocation.arguments_sha256,
                "parent_closure_digest": invocation.parent_closure_digest,
                "native_process_identity": self._process_identity_claim(invocation.native_process_identity),
                "profile_id": invocation.profile_id, "generation": invocation.generation,
                "service_generation_digest": invocation.service_generation_digest,
            })
            request_sha = hashlib.sha256(request_payload).hexdigest()
            response_sha = hashlib.sha256(response_payload).hexdigest()
            identity = {
                "artifact_id": schema_artifact_id, "artifact_sha256": schema_digest,
                "size_bytes": len(schema_bytes), "schema_kind": schema_kind,
                "package_id": invocation.package_id,
                "package_generation": binding.native_package_generation,
                "adapter_id": binding.handler_artifact_id, "action_id": binding.id,
                "service_generation_digest": invocation.service_generation_digest,
                "request_sha256": request_sha, "response_sha256": response_sha,
                "service_id": service.service_id, "mcp_generation": mcp_generation,
                "mcp_tool_name": binding.mcp_tool_name,
                "native_tool_name": binding.native_tool_name,
                "profile_id": invocation.profile_id, "process_generation": invocation.generation,
                "invocation_handle": invocation.invocation_handle,
                "invocation_proof_id": invocation_proof_id,
                "response_receipt_handle": response_receipt_handle,
                "parent_receipt_handles": list(parent_receipt_handles),
                "expires_monotonic": expires, "capability": capability,
                "operation": "mcp.request", "target": target,
                "selection_sha256": canonical_digest(expected_selection),
            }
            observation_handle = canonical_digest(identity)
            observation = MCPDiscoverySchemaObservation(
                artifact_id=identity["artifact_id"], artifact_sha256=identity["artifact_sha256"],
                size_bytes=identity["size_bytes"], schema_kind=schema_kind,
                package_id=identity["package_id"], package_generation=identity["package_generation"],
                adapter_id=identity["adapter_id"], action_id=identity["action_id"],
                service_generation_digest=identity["service_generation_digest"],
                schema_bytes=schema_bytes, request_sha256=request_sha, response_sha256=response_sha,
                service_id=service.service_id, mcp_generation=mcp_generation,
                mcp_tool_name=binding.mcp_tool_name, native_tool_name=binding.native_tool_name,
                profile_id=invocation.profile_id, process_generation=invocation.generation,
                invocation_handle=invocation.invocation_handle,
                invocation_proof_id=invocation_proof_id,
                response_receipt_handle=response_receipt_handle,
                parent_receipt_handles=parent_receipt_handles,
                source_observation_handle=observation_handle,
                expires_monotonic=expires, capability=capability,
                operation="mcp.request", target=target,
                selection_sha256=identity["selection_sha256"],
            )
            self._require_live(invocation, peer_uid, peer_pid, peer_pidfd, service, binding, mcp_generation)
            peer_pidfd_copy = os.dup(peer_pidfd)
            with self._lock:
                self._prune_locked(now)
                if self._closed or len(self._records) >= _MAX_WITNESSES or observation_handle in self._records:
                    os.close(peer_pidfd_copy)
                    raise ValueError
                retained = _RetainedDiscovery(
                    observation, invocation, peer_uid, peer_pid, peer_pidfd_copy,
                    request_payload, response_payload, context, authorization,
                    MappingProxyType(dict(expected_selection)),
                    expected_parent_receipts,
                )
                self._records[observation_handle] = retained
            try:
                verified = self._schema_derivations.observe_mcp_tools_list(observation)
                receipt_handle = self._schema_derivations.mint_schema_artifact(verified)
                if not isinstance(receipt_handle, str) or not _OPAQUE.fullmatch(receipt_handle):
                    raise ValueError
                retained.derivation_receipt_handle = receipt_handle
            except Exception:
                with self._lock:
                    self._records.pop(observation_handle, None)
                os.close(peer_pidfd_copy)
                raise
            return observation
        except MCPDiscoveryUnavailable:
            raise
        except Exception:
            raise MCPDiscoveryUnavailable("authenticated selected MCP tools/list witness was rejected") from None

    def resolve_schema_observation(self, value: Mapping[str, Any]) -> MCPDiscoverySchemaObservation:
        """Return only a retained observation matching an exact derivation row."""
        if not isinstance(value, Mapping):
            raise MCPDiscoveryUnavailable("MCP schema observation identity is malformed")
        observation_handle = value.get("source_observation_handle")
        if not isinstance(observation_handle, str) or not _SHA.fullmatch(observation_handle):
            raise MCPDiscoveryUnavailable("MCP schema observation handle is malformed")
        with self._lock:
            self._prune_locked(self._monotonic())
            retained = self._records.get(observation_handle)
        if retained is None:
            raise MCPDiscoveryUnavailable("MCP tools/list witness is absent or expired")
        proof = retained.observation
        expected = {
            "schema": 1,
            "artifact_id": proof.artifact_id, "artifact_sha256": proof.artifact_sha256,
            "size_bytes": proof.size_bytes, "schema_kind": proof.schema_kind,
            "package_id": proof.package_id, "package_generation": proof.package_generation,
            "adapter_id": proof.adapter_id, "action_id": proof.action_id,
            "source_kind": "mcp-tools-list",
            "parent_receipt_handles": list(proof.parent_receipt_handles),
            "source_observation_handle": proof.source_observation_handle,
            "source_member_path": None,
            "service_generation_digest": proof.service_generation_digest,
        }
        if any(value.get(key) != expected_value for key, expected_value in expected.items()):
            raise MCPDiscoveryUnavailable("MCP tools/list witness differs from the protected schema derivation")
        self._revalidate(retained)
        return proof

    def close(self) -> None:
        with self._lock:
            self._closed = True
            records, self._records = self._records, {}
        for record in records.values():
            try:
                os.close(record.peer_pidfd)
            except OSError:
                pass

    def _revalidate(self, retained: _RetainedDiscovery) -> None:
        proof = retained.observation
        if self._closed or self._monotonic() >= proof.expires_monotonic:
            raise MCPDiscoveryUnavailable("MCP tools/list witness lease expired")
        service = self._services.get(proof.service_id)
        if (type(service) is not ProtectedMCPService
                or self._generations.get(proof.service_id) != proof.mcp_generation
                or self.service.service_generation_digest != proof.service_generation_digest
                or self._bindings.enrollment_catalog.digest != proof.service_generation_digest):
            raise MCPDiscoveryUnavailable("MCP service or root generation changed")
        try:
            self._require_invocation_current(
                retained.invocation, retained.peer_uid, retained.peer_pid, retained.peer_pidfd,
            )
            if self.service.revalidate_effect(
                    retained.context, retained.authorization,
                    operation=proof.operation,
                    request_digest=retained.authorization.request_digest,
                    retry_index=0) is not True:
                raise ValueError
            self._resolve_receipt(
                proof.response_receipt_handle, proof.response_sha256,
                retained.peer_uid, proof.profile_id, proof.process_generation,
            )
            source_receipt = self._resolve_receipt(
                proof.response_receipt_handle, proof.response_sha256,
                retained.peer_uid, proof.profile_id, proof.process_generation,
            )
            parent_receipts = self._resolve_parents(
                proof.parent_receipt_handles, retained.parent_receipts,
                retained.peer_uid, proof.profile_id, proof.process_generation,
            )
            parent_ids = tuple(sorted(item.receipt_id for item in parent_receipts))
            if tuple(sorted(source_receipt.parent_receipt_ids)) != parent_ids:
                raise ValueError
            schema_digest = hashlib.sha256(proof.schema_bytes).hexdigest()
            schema = strict_json_loads(proof.schema_bytes.decode("utf-8"))
            from ..mcp.native_schema_catalog import _validate_schema
            _validate_schema(schema, nodes=[0])
            if (proof.artifact_id != f"native-mcp-schema:{schema_digest}"
                    or schema_digest != proof.artifact_sha256
                    or len(proof.schema_bytes) != proof.size_bytes):
                raise ValueError
            identity = {
                "artifact_id": proof.artifact_id, "artifact_sha256": proof.artifact_sha256,
                "size_bytes": proof.size_bytes, "schema_kind": proof.schema_kind,
                "package_id": proof.package_id, "package_generation": proof.package_generation,
                "adapter_id": proof.adapter_id, "action_id": proof.action_id,
                "service_generation_digest": proof.service_generation_digest,
                "request_sha256": proof.request_sha256, "response_sha256": proof.response_sha256,
                "service_id": proof.service_id, "mcp_generation": proof.mcp_generation,
                "mcp_tool_name": proof.mcp_tool_name, "native_tool_name": proof.native_tool_name,
                "profile_id": proof.profile_id, "process_generation": proof.process_generation,
                "invocation_handle": proof.invocation_handle,
                "invocation_proof_id": proof.invocation_proof_id,
                "response_receipt_handle": proof.response_receipt_handle,
                "parent_receipt_handles": list(proof.parent_receipt_handles),
                "expires_monotonic": proof.expires_monotonic,
                "capability": proof.capability, "operation": proof.operation,
                "target": proof.target, "selection_sha256": proof.selection_sha256,
            }
            if canonical_digest(identity) != proof.source_observation_handle:
                raise ValueError
            request = strict_json_loads(retained.request_payload.decode("utf-8"))
            response = strict_json_loads(retained.response_payload.decode("utf-8"))
            if (canonical_bytes(request) != retained.request_payload
                    or hashlib.sha256(retained.request_payload).hexdigest() != proof.request_sha256
                    or canonical_bytes(response) != retained.response_payload
                    or hashlib.sha256(retained.response_payload).hexdigest() != proof.response_sha256):
                raise ValueError
            envelope = request
            selected = [tool for tool in response["result"]["tools"]
                        if isinstance(tool, Mapping) and tool.get("name") == proof.mcp_tool_name]
            if (envelope.get("method") != "tools/list"
                    or envelope.get("service_id") != proof.service_id
                    or envelope.get("selection") != dict(retained.selection)
                    or len(selected) != 1
                    or json.dumps(
                        selected[0].get(_SCHEMA_ROLES[proof.schema_kind]),
                        sort_keys=True, separators=(",", ":"),
                        ensure_ascii=False, allow_nan=False,
                    ).encode("utf-8") != proof.schema_bytes):
                raise ValueError
            self._require_live(
                retained.invocation, retained.peer_uid, retained.peer_pid,
                retained.peer_pidfd, service,
                self._resolve_binding(proof.action_id), proof.mcp_generation,
            )
        except MCPDiscoveryUnavailable:
            raise
        except Exception:
            raise MCPDiscoveryUnavailable("MCP tools/list witness is no longer current") from None

    def _resolve_binding(self, action_id: str) -> NativeMCPToolBinding:
        try:
            binding = self._registrations.resolve_action(action_id)
        except Exception:
            raise MCPDiscoveryUnavailable("selected MCP action is no longer active") from None
        if type(binding) is not NativeMCPToolBinding or binding.id != action_id:
            raise MCPDiscoveryUnavailable("selected MCP action is no longer unique")
        return binding

    @staticmethod
    def _process_identity_claim(identity: Any) -> Mapping[str, Any]:
        """Hash only stable scalar fields from the root's typed process proof."""
        claim: dict[str, Any] = {}
        for name in _PROCESS_IDENTITY_FIELDS:
            value = getattr(identity, name, None)
            if value is None:
                continue
            if type(value) not in (str, int):
                raise MCPDiscoveryUnavailable("native process proof contains a non-scalar identity field")
            claim[name] = value
        required = {"profile_id", "generation", "kernel_uid", "executable_sha256"}
        if (not required.issubset(claim)
                or not _SHA.fullmatch(claim["executable_sha256"])
                or claim["kernel_uid"] <= 0):
            raise MCPDiscoveryUnavailable("native process proof is incomplete")
        return claim

    def _require_live(self, invocation: RootNativeMCPInvocation, uid: int, pid: int,
                      pidfd: int, service: ProtectedMCPService,
                      binding: NativeMCPToolBinding, mcp_generation: str) -> None:
        self._require_invocation_current(invocation, uid, pid, pidfd)
        if (self.service.service_generation_digest != invocation.service_generation_digest
                or self._bindings.enrollment_catalog.digest != invocation.service_generation_digest
                or self.service.profile_generations.get(invocation.profile_id) != invocation.generation
                or self._services.get(service.service_id) != service
                or self._generations.get(service.service_id) != mcp_generation
                or mcp_generation != binding.mcp_generation
                or binding.id != invocation.action_id
                or binding.native_package_id != invocation.package_id
                or binding.profile_id != invocation.profile_id
                or binding.process_generation != invocation.generation
                or binding.native_tool_name != invocation.tool_name
                or binding.mcp_enrollment_id != service.service_id
                or binding.mcp_tool_name not in service.allowed_tools):
            raise MCPDiscoveryUnavailable("selected MCP service, action, or process generation changed")

    def _require_invocation_current(self, invocation: RootNativeMCPInvocation,
                                    uid: int, pid: int, pidfd: int) -> None:
        if (type(self._invocations) is not NativeInvocationRegistry
                or self._invocations.is_current_native_mcp_invocation(
                    invocation, uid, pid, pidfd) is not True):
            raise MCPDiscoveryUnavailable("selected native invocation or custody proof is stale")

    def _resolve_receipt(self, handle: str, digest: str, uid: int,
                         profile_id: str, generation: str) -> Any:
        return self.service.resolve_retained_source_receipt(
            SourceReceiptHandle(handle), payload_digest=digest,
            profile_id=profile_id, generation=generation,
        )

    def _resolve_parents(self, handles: tuple[str, ...], expected: tuple[SourceReceipt, ...],
                         uid: int, profile_id: str, generation: str) -> tuple[SourceReceipt, ...]:
        if len(handles) != len(expected) or not handles:
            raise MCPDiscoveryUnavailable("MCP source parent closure does not match the invocation")
        receipts = []
        for handle, signed in zip(handles, expected):
            if type(signed) is not SourceReceipt or signed.uid != uid:
                raise MCPDiscoveryUnavailable("MCP source parent is not host-issued")
            try:
                receipt = self._resolve_receipt(
                    handle, signed.payload_digest, uid, profile_id, generation,
                )
            except Exception:
                raise MCPDiscoveryUnavailable("MCP source parent receipt is unavailable") from None
            if receipt != signed:
                raise MCPDiscoveryUnavailable("MCP source parent differs from signed invocation lineage")
            receipts.append(receipt)
        ids = [receipt.receipt_id for receipt in receipts]
        if len(ids) > 8 or len(ids) != len(set(ids)):
            raise MCPDiscoveryUnavailable("MCP source parent closure is ambiguous or oversized")
        return tuple(receipts)

    def _parent_ids(self, handles: tuple[str, ...], expected: tuple[SourceReceipt, ...],
                    uid: int, profile_id: str, generation: str) -> tuple[str, ...]:
        return tuple(sorted(item.receipt_id for item in self._resolve_parents(
            handles, expected, uid, profile_id, generation,
        )))

    def _prune_locked(self, now: float) -> None:
        stale = [key for key, record in self._records.items()
                 if record.observation.expires_monotonic <= now]
        for key in stale:
            record = self._records.pop(key)
            try:
                os.close(record.peer_pidfd)
            except OSError:
                pass
