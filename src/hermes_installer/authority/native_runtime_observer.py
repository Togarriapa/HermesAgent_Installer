"""Root-side adapter for selected Hermes plugins and completed native effects.

This module contains the callpoints which must stay in the authority process:
installing the already root-selected package into the pinned Hermes plugin
manager, constructing each registration context from trusted enrollment, and
turning a validated completed effect into a one-use observed source receipt.
It is deliberately not an RPC surface. The caller of ``observe_effect_result``
must be the root authority after effect validation and before returning bytes
to the worker.
"""
from __future__ import annotations

import threading
import base64
import hashlib
import json
import math
import re
import secrets
import time
import os
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .types import (AuthorityDenied, HostContext, NativeToolCallBinding, SourceReceipt,
                    canonical_bytes, canonical_digest, strict_json_loads)

_MAX_RESULT_BYTES = 1_048_576
_MAX_PARENT_RECEIPTS = 64
_MAX_TOOL_CALLS = 128
_MAX_TOOL_ARGUMENT_BYTES = 65_536
_INVOCATION_LEASE_SECONDS = 30.0
_MAX_RETAINED_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_RETAINED_MCP_DISCOVERY_REQUESTS = 256
_MAX_RETAINED_MCP_DISCOVERY_INVOCATIONS = 128
_MAX_RETAINED_MCP_DISCOVERY_RECEIPTS = 4096
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _strict_native_json(payload: bytes) -> Any:
    """Parse bounded native JSON without duplicate keys or non-finite numbers."""
    if not isinstance(payload, bytes):
        raise AuthorityDenied("native.json", "native JSON payload is not bytes")

    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    def reject_constant(_value: str) -> Any:
        raise ValueError("non-finite JSON number")

    try:
        return json.loads(payload.decode("utf-8", errors="strict"),
                          object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except (UnicodeError, ValueError, TypeError):
        raise AuthorityDenied("native.json", "native JSON payload is malformed") from None


@dataclass(frozen=True, slots=True)
class NativeActionSelection:
    """Root-selected native action found by exact tool-name mapping."""

    package_id: str
    profile_id: str
    # Process/profile generation and native package generation are separate
    # epochs and must both be supplied by the protected action resolver.
    generation: str
    package_generation: str
    adapter_id: str
    action_id: str
    registration_id: str
    operation: str
    validate_arguments: Callable[[bytes], bool]
    result_schema_id: str
    result_schema_sha256: str
    validate_result: Callable[[bytes], bool]

    def __post_init__(self) -> None:
        if (any(not isinstance(getattr(self, name), str) or not getattr(self, name)
                for name in ("package_id", "profile_id", "generation", "package_generation",
                             "adapter_id", "action_id",
                             "registration_id", "operation"))
                or not callable(self.validate_arguments)
                or not isinstance(self.result_schema_id, str) or not self.result_schema_id
                or not _SHA256.fullmatch(self.result_schema_sha256)
                or not callable(self.validate_result)):
            raise ValueError("selected native action binding is incomplete")


@dataclass(frozen=True, slots=True)
class ProviderResponseMetadata:
    """Root-issued metadata released to the authenticated producer."""

    producer_context_handle: str
    tool_call_bindings: tuple[Any, ...]
    turn_handle: str | None = None
    final_response_delivery_handle: str | None = None

    def to_wire(self) -> dict[str, Any]:
        return {
            "producer_context_handle": self.producer_context_handle,
            "tool_call_bindings": [
                {
                    "observed_call_handle": item.observed_call_handle,
                    "provider_tool_call_id": item.provider_tool_call_id,
                    "tool_name": item.tool_name,
                    "arguments_sha256": item.arguments_sha256,
                }
                for item in self.tool_call_bindings
            ],
            "turn_handle": self.turn_handle,
            "final_response_delivery_handle": self.final_response_delivery_handle,
        }


@dataclass(frozen=True, slots=True)
class ProviderResponseDelivery:
    """Only a non-authoritative lookup token may leave the root gateway."""

    response_delivery_handle: str


@dataclass(frozen=True, slots=True)
class RootNativeToolEffectInvocation:
    """Root-retained one-use invocation resolved from a validated effect."""

    invocation_handle: str
    observed_call_handle: str
    response_observation_handle: str
    response_receipt_handle: str
    native_request_handle: str
    turn_handle: str | None
    producer_identity: Any
    producer_pid: int
    profile_id: str
    generation: str
    package_id: str
    native_package_generation: str
    service_generation_digest: str
    adapter_id: str
    action_id: str
    registration_id: str
    tool_name: str
    arguments_sha256: str
    source_receipt_handles: tuple[str, ...]
    operation: str
    request_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        opaque = (self.invocation_handle, self.observed_call_handle,
                  self.response_observation_handle, self.response_receipt_handle,
                  self.native_request_handle)
        if (any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value)
                for value in opaque)
                or type(self.producer_pid) is not int or self.producer_pid <= 0
                or any(not isinstance(value, str) or not value for value in (
                    self.profile_id, self.generation, self.package_id,
                    self.native_package_generation, self.adapter_id, self.action_id,
                    self.registration_id,
                    self.tool_name, self.operation))
                or not _SHA256.fullmatch(self.service_generation_digest)
                or not _SHA256.fullmatch(self.arguments_sha256)
                or not _SHA256.fullmatch(self.request_digest)
                or not isinstance(self.source_receipt_handles, tuple)
                or not self.source_receipt_handles or len(self.source_receipt_handles) > 128
                or any(not isinstance(value, str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value)
                       for value in self.source_receipt_handles)
                or self.producer_identity is None
                or (self.turn_handle is not None and (
                    not isinstance(self.turn_handle, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.turn_handle)))
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("root native tool invocation record is malformed")


@dataclass(frozen=True, slots=True)
class _RetainedMCPDiscoveryRequest:
    """Root-retained request binding for the one fixed tools/list witness path."""

    invocation: Any
    service: Any
    binding: Any
    observer_id: str
    context: HostContext
    authorization: Any
    peer_uid: int
    peer_pid: int
    peer_pidfd: int
    operation: str
    target: str
    request_payload: bytes
    request_sha256: str
    parent_handles: tuple[str, ...]
    selection: Mapping[str, str]
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootSelectedApplicationInvocation:
    """Root-validated native action evidence presented before app admission.

    This proves only the current selected native action and its request
    ancestry. Application/workload/runtime selection and the fresh
    ``process.start`` grant remain separate root-owned joins.
    """

    schema: int
    invocation_handle: str
    response_observation_handle: str
    turn_handle: str
    package_id: str
    profile_id: str
    profile_generation: str
    principal_id: str
    adapter_id: str
    action_id: str
    tool_name: str
    operation: str
    request_sha256: str
    source_receipt_handles: tuple[str, ...]
    source_closure_sha256: str
    service_generation_digest: str
    native_process_identity: Any
    issued_monotonic: float
    expires_monotonic: float

    def __post_init__(self) -> None:
        opaque = (self.invocation_handle, self.response_observation_handle, self.turn_handle)
        if (type(self.schema) is not int or self.schema != 1
                or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value)
                       for value in opaque)
                or any(not isinstance(value, str) or not value for value in (
                    self.package_id, self.profile_id, self.profile_generation,
                    self.principal_id, self.adapter_id, self.action_id,
                    self.tool_name, self.operation))
                or not _SHA256.fullmatch(self.request_sha256)
                or not _SHA256.fullmatch(self.source_closure_sha256)
                or not _SHA256.fullmatch(self.service_generation_digest)
                or not isinstance(self.source_receipt_handles, tuple)
                or not self.source_receipt_handles
                or len(self.source_receipt_handles) > 128
                or len(set(self.source_receipt_handles)) != len(self.source_receipt_handles)
                or any(not isinstance(item, str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                       for item in self.source_receipt_handles)
                or self.native_process_identity is None
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("selected application invocation evidence is malformed")


@dataclass(frozen=True, slots=True)
class RootNativeMCPInvocation:
    """Opaque root-resolved native MCP action admitted for one dispatch.

    Instances are also tracked by object identity inside NativeInvocationRegistry;
    copying or constructing this DTO does not create an active dispatch.
    """

    invocation_handle: str
    tool_name: str
    adapter_id: str
    action_id: str
    package_id: str
    profile_id: str
    generation: str
    arguments_sha256: str
    parent_closure_digest: str
    expires_monotonic: float
    source_receipt_handles: tuple[str, ...]
    native_process_identity: Any
    service_generation_digest: str




@dataclass(slots=True)
class _ObservedProviderResponse:
    handle: str
    delivery_handle: str
    native_request_handle: str
    response_digest: str
    receipt_handles: tuple[str, ...]
    bridge: Any
    producer_identity: Any
    producer_pid: int
    producer_pidfd: int
    gateway_identity: Any
    gateway_pid: int
    gateway_pidfd: int
    observer_id: str
    package_id: str
    profile_id: str
    generation: str
    native_package_generation: str
    loaded_package_proof: Any
    expires_monotonic: float
    calls: dict[str, tuple[str, str, str, str, bytes]]
    request_context: HostContext
    authorization: Any
    target: str
    recipient: str
    request_digest: str
    retry_index: int
    response_status: int
    response_headers: Mapping[str, str]
    response_bytes: bytes
    response_receipt_handle: str
    turn_handle: str | None = None
    final_response_delivery_handle: str | None = None
    metadata_taken: bool = False


@dataclass(slots=True)
class _NativeInvocation:
    invocation_handle: str
    response_handle: str
    observed_call_handle: str
    bridge: Any
    producer_identity: Any
    producer_pid: int
    producer_pidfd: int
    gateway_identity: Any
    gateway_pid: int
    gateway_pidfd: int
    package_id: str
    profile_id: str
    generation: str
    package_generation: str
    adapter_id: str
    action_id: str
    registration_id: str
    tool_name: str
    arguments_sha256: str
    parent_closure_digest: str
    receipt_handles: tuple[str, ...]
    canonical_arguments: bytes
    observer_id: str
    loaded_package_proof: Any
    expires_monotonic: float
    service_generation_digest: str
    operation: str = ""
    result_schema_id: str = ""
    result_schema_sha256: str = ""
    mcp_dispatch_consumed: bool = False
    effect_result_consumed: bool = False
    effect_result_schema_validated: bool = False
    effect_request_digest: str | None = None


_OWNER_OVERLAY_INVOCATION_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeOwnerOverlayInvocation:
    """Root-retained local Resources invocation; never a backend action DTO."""

    invocation_handle: str
    producer_context_handle: str
    observed_call_handle: str
    response_observation_handle: str
    response_receipt_handle: str
    turn_handle: str | None
    native_request_handle: str
    registration_id: str
    method: str
    canonical_arguments: bytes = field(repr=False)
    arguments_sha256: str
    parent_source_receipt_handles: tuple[str, ...]
    invocation_source_receipt_handle: str
    producer_identity: Any = field(repr=False, compare=False)
    producer_pid: int
    producer_pidfd: int = field(repr=False, compare=False)
    gateway_identity: Any = field(repr=False, compare=False)
    gateway_pid: int
    gateway_pidfd: int = field(repr=False, compare=False)
    bridge: Any = field(repr=False, compare=False)
    response: Any = field(repr=False, compare=False)
    source_observer: Any = field(repr=False, compare=False)
    expires_monotonic: float
    consumed: bool
    _seal: object = field(repr=False, compare=False)
    _issuer: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _OWNER_OVERLAY_INVOCATION_SEAL
                or self.registration_id not in {
                    "resource-overlay-store:tool:resource_overlay_read",
                    "resource-overlay-store:tool:resource_overlay_history",
                    "resource-overlay-store:tool:resource_overlay_write",
                    "resource-overlay-store:tool:resource_overlay_delete",
                }
                or self.method not in {"read", "history", "write", "delete"}
                or not isinstance(self.canonical_arguments, bytes)
                or hashlib.sha256(self.canonical_arguments).hexdigest() != self.arguments_sha256
                or not self.parent_source_receipt_handles
                or self.expires_monotonic <= 0):
            raise TypeError("owner-overlay invocations are root-issued typed records")

    def __repr__(self) -> str:
        return "RootNativeOwnerOverlayInvocation(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedHealthOwnerInvocation:
    """Current exact provider response and parsed health tool call."""

    request_projection: Any = field(repr=False, compare=False)
    provider_response: Any = field(repr=False, compare=False)
    owner_invocation: RootNativeOwnerOverlayInvocation = field(repr=False, compare=False)
    source_receipt_handles: tuple[str, ...]
    source_receipt_ids: tuple[str, ...]
    provider_source_receipt_handles: tuple[str, ...]
    provider_source_receipt_ids: tuple[str, ...]
    _registry: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootSelectedHealthOwnerInvocation(<root-private>)"


class NativeRuntimeObserverUnavailable(PermissionError):
    """Selected native runtime wiring or root observation is unavailable."""


class NativeInvocationContextProvider:
    """Resolve one lexical Hermes invocation to its root-registered ancestry.

    ``current_binding`` must be the installer-owned lexical accessor installed
    by the pinned Hermes dispatch hook. This provider never accepts an
    invocation handle from tool arguments or from a plugin. Root lookup is
    authenticated by ``AuthorityClient`` and every returned opaque source
    handle remains subject to the authority's normal peer, profile, generation
    and lease checks when it is used to issue an effect context.
    """

    def __init__(self, *, authority: Any, selected_package: Any,
                 current_binding: Callable[[], Any],
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if (not callable(getattr(authority, "get_invocation_contexts", None))
                or not callable(current_binding)
                or not isinstance(getattr(selected_package, "package_id", None), str)
                or not isinstance(getattr(selected_package, "profile_id", None), str)
                or not isinstance(getattr(selected_package, "generation", None), str)):
            raise NativeRuntimeObserverUnavailable("native invocation context provider is incomplete")
        self.authority = authority
        self.selected_package = selected_package
        self.current_binding = current_binding
        self.monotonic = monotonic

    def __call__(self, *, adapter_id: str, action_id: str,
                 arguments_sha256: str, purpose: str, intent: str) -> Any:
        """Return typed root ancestry only for the exact current selected action."""
        del purpose, intent  # Classification labels do not select invocation ancestry.
        if (not isinstance(adapter_id, str) or not adapter_id
                or not isinstance(action_id, str) or not action_id
                or not isinstance(arguments_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", arguments_sha256)):
            raise AuthorityDenied("native.invocation", "selected action binding is malformed")
        binding = self.current_binding()
        if binding is None:
            raise AuthorityDenied("native.invocation", "no root-bound native invocation is active")
        invocation_handle = getattr(binding, "invocation_handle", None)
        expected = (
            getattr(binding, "package_id", None) == self.selected_package.package_id
            and getattr(binding, "profile_id", None) == self.selected_package.profile_id
            and getattr(binding, "generation", None) == self.selected_package.generation
            and getattr(binding, "adapter_id", None) == adapter_id
            and getattr(binding, "action_id", None) == action_id
            and getattr(binding, "arguments_sha256", None) == arguments_sha256
            and type(getattr(binding, "expires_monotonic", None)) in (int, float)
            and self.monotonic() < binding.expires_monotonic
            and isinstance(invocation_handle, str)
            and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", invocation_handle)
        )
        if not expected:
            raise AuthorityDenied("native.invocation", "current invocation does not bind this selected action")
        contexts = self.authority.get_invocation_contexts(invocation_handle)
        if (getattr(contexts, "invocation_handle", None) != invocation_handle
                or getattr(contexts, "arguments_sha256", None) != arguments_sha256
                or getattr(contexts, "parent_closure_digest", None)
                != getattr(binding, "parent_closure_digest", None)
                or type(getattr(contexts, "expires_monotonic", None)) not in (int, float)
                or self.monotonic() >= contexts.expires_monotonic
                or not isinstance(getattr(contexts, "source_receipt_handles", None), tuple)
                or not contexts.source_receipt_handles
                or len(contexts.source_receipt_handles) > 128
                or any(not isinstance(handle, str)
                       or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)
                       for handle in contexts.source_receipt_handles)):
            raise AuthorityDenied("native.invocation", "root returned mismatched or expired invocation ancestry")
        # Keep lookup results opaque. AuthorityClient.context consumes these
        # receipt handles with the exact effect digest; no worker-created
        # HostContext or source classification is substituted here.
        return contexts


class NativeInvocationRegistry:
    """Root-private provider-response/call registry for native invocations.

    This object is constructed by root daemon composition and is never exposed
    as a worker RPC. Only the paired HI11 response observer calls
    ``register_provider_response``; worker RPCs reach the two narrow begin/get
    methods through AuthorityService, which supplies the kernel-authenticated
    peer identity and PIDFD.
    """

    def __init__(self, *, service: Any, source_observers: Any,
                 bridges: Mapping[str, Any],
                 provider_result_observer_ids: Mapping[tuple[str, str, str], str],
                 provider_tool_call_parser: Callable[[str, int, Mapping[str, str], bytes], tuple[Any, ...]],
                 process_resolver: Callable[..., Any],
                 action_resolver: Callable[[Any, Any, str], NativeActionSelection],
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if (not isinstance(bridges, Mapping) or not bridges
                or not isinstance(provider_result_observer_ids, Mapping)
                or not callable(provider_tool_call_parser)
                or not callable(process_resolver) or not callable(action_resolver)
                or not callable(getattr(source_observers, "record_observed_event", None))
                or not callable(getattr(source_observers, "capture_observed_source", None))
                or not callable(getattr(source_observers, "take_source_receipt", None))
                or not callable(getattr(source_observers, "_resolve", None))
                or not callable(getattr(source_observers, "_resolve_package_role", None))
                or not callable(getattr(source_observers, "_resolve_loaded_package_proof", None))):
            raise NativeRuntimeObserverUnavailable("root invocation registry dependencies are incomplete")
        observer_ids: dict[tuple[str, str, str], str] = {}
        for key, observer_id in provider_result_observer_ids.items():
            if (not isinstance(key, tuple) or len(key) != 3
                    or any(not isinstance(part, str) or not part for part in key)
                    or not isinstance(observer_id, str) or not observer_id):
                raise NativeRuntimeObserverUnavailable("provider-result observer map is malformed")
            observer = getattr(source_observers, "observers", {}).get(observer_id)
            if (observer is None or getattr(observer, "source_kind", None) != "provider-result"):
                raise NativeRuntimeObserverUnavailable("provider-result observer is not root enrolled")
            observer_ids[key] = observer_id
        self.service = service
        self.source_observers = source_observers
        self.bridges = dict(bridges)
        self.provider_result_observer_ids = observer_ids
        self.provider_tool_call_parser = provider_tool_call_parser
        self.process_resolver = process_resolver
        self.action_resolver = action_resolver
        self.monotonic = monotonic
        self._responses: dict[str, _ObservedProviderResponse] = {}
        self._deliveries: dict[str, _ObservedProviderResponse] = {}
        self._calls: dict[str, tuple[str, str, str, str, str, bytes]] = {}
        self._invocations: dict[str, _NativeInvocation] = {}
        self._owner_overlay_invocations: dict[str, RootNativeOwnerOverlayInvocation] = {}
        self._owner_overlay_consumed: set[str] = set()
        self._health_selection_issuer = object()
        self._selected_application_invocations: dict[str, RootSelectedApplicationInvocation] = {}
        self._mcp_dispatches: dict[str, tuple[_NativeInvocation, RootNativeMCPInvocation]] = {}
        self._issued_handles: set[str] = set()
        self._retained_response_bytes = 0
        self._native_turn_registry: Any | None = None
        self._lock = threading.RLock()
        self._closed = False

    def register_provider_response(self, *, bridge: Any, producer_identity: Any,
                                   producer_pid: int, producer_pidfd: int,
                                   gateway_identity: Any, gateway_pid: int,
                                   gateway_pidfd: int, request_context: HostContext,
                                   request_source_receipts: tuple[SourceReceipt, ...],
                                   authorization: Any, target: str, recipient: str,
                                   request_digest: str, response_status: int,
                                   response_headers: Mapping[str, str],
                                   response_bytes: bytes, response_digest: str,
                                   native_request_handle: str,
                                   expires_monotonic: float,
                                   cancelled: Callable[[], bool]) -> ProviderResponseDelivery:
        """Observe exact completed provider bytes and issue response/call handles.

        The parser output is supplied only by the root-selected response
        observer. This method independently verifies each canonical argument
        byte sequence and maps every tool name through the root-selected native
        action resolver before it creates any call binding.
        """
        from .types import EffectAuthorization

        now = self.monotonic()
        if (not isinstance(request_context, HostContext)
                or not isinstance(authorization, EffectAuthorization)
                or not isinstance(request_source_receipts, tuple)
                or any(not isinstance(item, SourceReceipt) for item in request_source_receipts)
                or len(request_source_receipts) > _MAX_PARENT_RECEIPTS
                or not isinstance(response_bytes, bytes) or not 1 <= len(response_bytes) <= 4 * 1024 * 1024
                or not isinstance(response_digest, str)
                or hashlib.sha256(response_bytes).hexdigest() != response_digest
                or not self._valid_bridge_handle(native_request_handle)
                or not isinstance(request_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", request_digest)
                or type(response_status) is not int or not 200 <= response_status < 300
                or not isinstance(response_headers, Mapping) or len(response_headers) > 32
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in response_headers.items())
                or type(producer_pidfd) is not int or producer_pidfd < 0
                or type(producer_pid) is not int or producer_pid <= 0
                or type(gateway_pidfd) is not int or gateway_pidfd < 0
                or type(gateway_pid) is not int or gateway_pid <= 0
                or isinstance(expires_monotonic, bool) or type(expires_monotonic) not in (int, float)
                or not math.isfinite(expires_monotonic) or expires_monotonic <= now
                or not callable(cancelled)):
            raise AuthorityDenied("native.invocation.response", "root-observed provider response is malformed")
        bridge_id = getattr(bridge, "bridge_id", None)
        selected_bridge = self.bridges.get(bridge_id) if isinstance(bridge_id, str) else None
        if selected_bridge != bridge:
            raise AuthorityDenied("native.invocation.bridge", "provider response has no protected bridge enrollment")
        if (target != bridge.target or recipient != bridge.recipient
                or bridge.approved_operation != "provider.dispatch"
                or authorization.operation != "provider.dispatch"
                or authorization.target != target or authorization.recipient != recipient
                or authorization.final_payload_digest != request_digest
                or authorization.request_digest != request_digest
                or request_context.final_payload_digest != request_digest
                or authorization.source_receipts != request_context.source_receipts
                or authorization.source_receipts != request_source_receipts
                or authorization.uid != bridge.producer_uid
                or authorization.profile_id != bridge.producer_profile_id
                or request_context.uid != authorization.uid
                or request_context.profile_id != authorization.profile_id
                or request_context.generation != bridge.producer_generation):
            raise AuthorityDenied("native.invocation.binding", "provider response does not match its consumed request")
        if not (self.service._binding(authorization.uid).profile_id == authorization.profile_id):
            raise AuthorityDenied("native.invocation.binding", "provider response principal binding changed")
        self.service._verify_context_signature(request_context)
        self.service._verify_grant_signature(authorization)
        self.service._assert_current_context(request_context, self.service._binding(authorization.uid),
                                             authorization.uid, peer_pid=producer_pid)
        self.service._assert_grant_current(authorization, self.service._binding(authorization.uid),
                                           authorization.uid)
        expected_process_identity = self.service._native_process_identity(
            producer_pid, bridge.producer_uid)
        if (request_context.native_process_identity != expected_process_identity
                or authorization.native_process_identity != expected_process_identity
                or request_context.principal_id != authorization.principal_id
                or request_context.generation != authorization.generation):
            raise AuthorityDenied("native.invocation.peer", "provider request context is not bound to the live producer")
        if (producer_identity is None or gateway_identity is None
                or getattr(producer_identity, "profile_id", bridge.producer_profile_id)
                != bridge.producer_profile_id
                or getattr(producer_identity, "generation", bridge.producer_generation)
                != bridge.producer_generation
                or getattr(producer_identity, "kernel_uid", bridge.producer_uid) != bridge.producer_uid
                or getattr(producer_identity, "executable_sha256", bridge.producer_executable_sha256)
                != bridge.producer_executable_sha256
                or getattr(gateway_identity, "profile_id", bridge.gateway_profile_id)
                != bridge.gateway_profile_id
                or getattr(gateway_identity, "generation", bridge.gateway_generation)
                != bridge.gateway_generation
                or getattr(gateway_identity, "kernel_uid", bridge.gateway_uid) != bridge.gateway_uid
                or getattr(gateway_identity, "executable_sha256", bridge.gateway_executable_sha256)
                != bridge.gateway_executable_sha256):
            raise AuthorityDenied("native.invocation.peer", "provider or gateway is not its selected live peer")
        current_producer = self.process_resolver(
            producer_pid, producer_pidfd, profile_id=bridge.producer_profile_id,
            generation=bridge.producer_generation)
        current_gateway = self.process_resolver(
            gateway_pid, gateway_pidfd, profile_id=bridge.gateway_profile_id,
            generation=bridge.gateway_generation)
        if current_producer != producer_identity or current_gateway != gateway_identity:
            raise AuthorityDenied("native.invocation.peer", "paired provider/gateway PIDFD identity changed")
        if cancelled():
            raise AuthorityDenied("native.invocation.cancelled", "provider response was cancelled before observation")

        try:
            parsed_tool_calls = self.provider_tool_call_parser(
                bridge.provider_enrollment_id, response_status, dict(response_headers), response_bytes)
        except Exception:
            raise AuthorityDenied("native.invocation.parser", "reviewed provider response parser rejected the result") from None
        if not isinstance(parsed_tool_calls, tuple) or len(parsed_tool_calls) > _MAX_TOOL_CALLS:
            raise AuthorityDenied("native.invocation.parser", "reviewed parser returned malformed tool bindings")

        observer_id = self.provider_result_observer_ids.get(
            (bridge.provider_enrollment_id, target, recipient))
        observer = self.source_observers.observers.get(observer_id) if observer_id else None
        if (observer is None or observer.profile_id != bridge.producer_profile_id
                or observer.generation != bridge.producer_generation
                or observer.producer_uid != bridge.producer_uid
                or getattr(observer, "capture_schema_id", None)
                != "native-root-provider-response-v1"):
            raise AuthorityDenied("native.invocation.observer", "selected provider-result observer is unavailable")
        loaded_proof = self._loaded_proof(
            observer_id, producer_identity, producer_pid, producer_pidfd)
        package, _adapter = self.source_observers._resolve_package_role(observer)
        package_generation = getattr(package, "generation", None)
        if (getattr(package, "package_id", None) != observer.package_id
                or not isinstance(package_generation, str) or not package_generation):
            raise AuthorityDenied("native.invocation.package", "selected package generation is unavailable")
        observed_registration_ids = self._require_observed_registrations(observer, loaded_proof)
        parent_handles = NativeRuntimeObserver._parent_handles(self, self.service, request_context)
        action_rows: list[tuple[str, str, str, str, bytes]] = []
        seen_call_ids: set[str] = set()
        for call in parsed_tool_calls:
            call_id = getattr(call, "provider_tool_call_id", None)
            tool_name = getattr(call, "tool_name", None)
            arguments = getattr(call, "canonical_arguments", None)
            args_digest = getattr(call, "arguments_sha256", None)
            if (not isinstance(call_id, str) or not 1 <= len(call_id) <= 256
                    or not isinstance(tool_name, str) or not 1 <= len(tool_name) <= 256
                    or not isinstance(arguments, bytes) or not 1 <= len(arguments) <= _MAX_TOOL_ARGUMENT_BYTES
                    or not isinstance(args_digest, str)
                    or hashlib.sha256(arguments).hexdigest() != args_digest
                    or call_id in seen_call_ids):
                raise AuthorityDenied("native.invocation.call", "root parsed provider tool call is malformed")
            try:
                value = json.loads(arguments.decode("utf-8"))
                canonical = json.dumps(value, ensure_ascii=False, sort_keys=True,
                                       separators=(",", ":"), allow_nan=False).encode("utf-8")
            except (UnicodeError, ValueError, TypeError):
                raise AuthorityDenied("native.invocation.call", "tool arguments are not canonical JSON") from None
            if not isinstance(value, dict) or canonical != arguments:
                raise AuthorityDenied("native.invocation.call", "tool arguments are not a canonical object")
            owner_names = {
                "resource_overlay_read": "resource-overlay-store:tool:resource_overlay_read",
                "resource_overlay_history": "resource-overlay-store:tool:resource_overlay_history",
                "resource_overlay_write": "resource-overlay-store:tool:resource_overlay_write",
                "resource_overlay_delete": "resource-overlay-store:tool:resource_overlay_delete",
            }
            owner_registration = owner_names.get(tool_name)
            if owner_registration is not None:
                owner_registry = getattr(self.service, "active_owner_overlay_registry", None)
                resolve_owner = getattr(owner_registry, "resolve_provider_tool_call", None)
                if not callable(resolve_owner):
                    raise AuthorityDenied("native.invocation.owner_overlay",
                                          "current local owner operation is unavailable")
                try:
                    owner_source = resolve_owner(
                        tool_name, producer_pid, producer_pidfd, observer.package_id,
                        bridge.producer_profile_id, bridge.producer_generation,
                        package_generation, arguments,
                    )
                    selected = owner_source.selection
                    if (selected.registration_id != owner_registration
                            or owner_source.observer_row.get("method")
                               != tool_name.removeprefix("resource_overlay_")
                            or owner_registration not in observed_registration_ids):
                        raise ValueError
                except Exception:
                    raise AuthorityDenied("native.invocation.owner_overlay",
                                          "selected owner operation schema or READY registration changed") from None
                retire = getattr(owner_registry, "_retire", None)
                if callable(retire):
                    retire(owner_source.selection.selection_handle)
                action_rows.append((call_id, tool_name, "resource-overlay-store",
                                    owner_registration, arguments))
                seen_call_ids.add(call_id)
                continue
            try:
                selection = self.action_resolver(bridge, producer_identity, tool_name)
            except Exception:
                raise AuthorityDenied("native.invocation.action", "root action selection failed") from None
            if (not isinstance(selection, NativeActionSelection)
                    or selection.package_id != observer.package_id
                    or selection.profile_id != bridge.producer_profile_id
                    or selection.generation != bridge.producer_generation
                    or not self._validate_selection(selection, arguments)):
                raise AuthorityDenied("native.invocation.action", "tool call has no exact selected action schema")
            registration_ids = self._selected_action_registration_ids(
                observer=observer, package=package, selection=selection,
            )
            if not registration_ids or not set(registration_ids).issubset(
                    set(observed_registration_ids)):
                raise AuthorityDenied(
                    "native.invocation.action", "selected action registration was not observed by the loaded role",
                )
            seen_call_ids.add(call_id)
            action_rows.append((call_id, tool_name, selection.adapter_id, selection.action_id, arguments))

        event_id = self.source_observers.record_observed_event(
            observer_id, payload_bytes=response_bytes, parent_context=request_context,
            peer_pid=producer_pid, peer_pidfd=producer_pidfd,
            parent_receipt_handles=parent_handles,
        )
        if cancelled():
            cancel = getattr(self.source_observers, "cancel_invocation_payload_capsules", None)
            if callable(cancel):
                cancel(request_context.grant_id)
            raise AuthorityDenied("native.invocation.cancelled", "provider response was cancelled before capture")
        receipt_handle = self.source_observers.capture_observed_source(
            observer_id, event_id, response_bytes, parent_receipt_handles=parent_handles)
        if cancelled():
            cancel = getattr(self.source_observers, "cancel_invocation_payload_capsules", None)
            if callable(cancel):
                cancel(request_context.grant_id)
            raise AuthorityDenied("native.invocation.cancelled", "provider response was cancelled before delivery")
        delivered = self.source_observers.take_source_receipt(
            str(receipt_handle), peer_uid=bridge.producer_uid,
            peer_pid=producer_pid, peer_pidfd=producer_pidfd)
        if str(delivered) != str(receipt_handle):
            raise AuthorityDenied("native.invocation.delivery", "provider result receipt delivery changed its handle")
        closure_handles = tuple(dict.fromkeys((*parent_handles, str(receipt_handle))))
        if not closure_handles or len(closure_handles) > 128:
            raise AuthorityDenied("native.invocation.lineage", "provider result closure is empty or oversized")
        lease = min(float(expires_monotonic), now + _INVOCATION_LEASE_SECONDS,
                    request_context.monotonic_expires_at, authorization.monotonic_expires_at)
        if lease <= self.monotonic():
            raise AuthorityDenied("native.invocation.expired", "provider response observation lease expired")
        response_handle = self._opaque_handle()
        delivery_handle = self._opaque_handle()
        pending_calls: dict[str, tuple[str, str, str, str, bytes]] = {}
        metadata_calls: list[NativeToolCallBinding] = []
        for call_id, tool_name, adapter_id, action_id, arguments in action_rows:
            observed_handle = self._opaque_handle()
            args_digest = hashlib.sha256(arguments).hexdigest()
            pending_calls[observed_handle] = (call_id, tool_name, adapter_id, action_id, arguments)
            metadata_calls.append(NativeToolCallBinding(
                observed_call_handle=observed_handle,
                provider_tool_call_id=call_id,
                tool_name=tool_name,
                arguments_sha256=args_digest,
            ))
        response = _ObservedProviderResponse(
            handle=response_handle,
            delivery_handle=delivery_handle,
            native_request_handle=native_request_handle,
            response_digest=response_digest,
            receipt_handles=closure_handles,
            bridge=bridge,
            producer_identity=producer_identity,
            producer_pid=producer_pid,
            producer_pidfd=os.dup(producer_pidfd),
            gateway_identity=gateway_identity,
            gateway_pid=gateway_pid,
            gateway_pidfd=os.dup(gateway_pidfd),
            observer_id=observer_id,
            package_id=observer.package_id,
            profile_id=observer.profile_id,
            generation=observer.generation,
            native_package_generation=package_generation,
            loaded_package_proof=loaded_proof,
            expires_monotonic=lease,
            calls=pending_calls,
            request_context=request_context,
            authorization=authorization,
            target=target,
            recipient=recipient,
            request_digest=request_digest,
            retry_index=authorization.retry_index,
            response_status=response_status,
            response_headers=MappingProxyType({
                str(key): str(value) for key, value in response_headers.items()
                if key.casefold() in {"content-type", "retry-after"}
            }),
            response_bytes=bytes(response_bytes),
            response_receipt_handle=str(receipt_handle),
        )
        with self._lock:
            self._ensure_open()
            self._prune_locked(now)
            if (len(self._responses) >= 4096 or len(self._calls) + len(pending_calls) > 8192
                    or self._retained_response_bytes + len(response_bytes)
                    > _MAX_RETAINED_RESPONSE_BYTES):
                os.close(response.producer_pidfd)
                raise AuthorityDenied("native.invocation.capacity", "root invocation registry is full")
            all_handles = (response_handle, delivery_handle, *pending_calls)
            if (len(all_handles) != len(set(all_handles))
                    or any(handle in self._issued_handles for handle in all_handles)):
                os.close(response.producer_pidfd)
                raise AuthorityDenied("native.invocation.handle", "root invocation handle collision")
            self._issued_handles.update(all_handles)
            self._responses[response_handle] = response
            self._deliveries[delivery_handle] = response
            self._retained_response_bytes += len(response.response_bytes)
            for handle, call in pending_calls.items():
                self._calls[handle] = (response_handle, *call)
        self._associate_response_with_turn(response, parent_handles)
        return ProviderResponseDelivery(delivery_handle)

    def take_native_response_metadata(self, peer_uid: int, peer_pid: int, peer_pidfd: int,
                                      response_delivery_handle: str,
                                      response_body_sha256: str,
                                      native_request_handle: str) -> ProviderResponseMetadata:
        """Release response metadata to the exact live producer once.

        The delivery handle is only an opaque lookup token. Authority comes
        from the root-held response record and the kernel-authenticated peer;
        the caller must also prove the exact response digest and request event
        handle observed by the bridge.
        """
        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not self._valid_delivery_handle(response_delivery_handle)
                or not isinstance(response_body_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", response_body_sha256)
                or not self._valid_handle(native_request_handle)):
            raise AuthorityDenied("native.response.take", "provider response lookup is malformed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            response = self._deliveries.get(response_delivery_handle)
            if (response is None or response.delivery_handle != response_delivery_handle
                    or response.metadata_taken):
                raise AuthorityDenied("native.response.take", "provider response metadata is unknown or already consumed")
            if (peer_uid != response.bridge.producer_uid or peer_pid != response.producer_pid
                    or response.native_request_handle != native_request_handle
                    or response.response_digest != response_body_sha256):
                raise AuthorityDenied("native.response.binding", "provider response does not match the observed request, bytes, or peer")
            identity = self.process_resolver(peer_pid, peer_pidfd,
                                             profile_id=response.profile_id,
                                             generation=response.generation)
            gateway = self.process_resolver(response.gateway_pid, response.gateway_pidfd,
                                            profile_id=response.bridge.gateway_profile_id,
                                            generation=response.bridge.gateway_generation)
            if identity != response.producer_identity or gateway != response.gateway_identity:
                raise AuthorityDenied("native.response.peer", "provider response peer pair changed")
            proof = self._loaded_proof(response.observer_id, identity, peer_pid, peer_pidfd)
            if proof != response.loaded_package_proof:
                raise AuthorityDenied("native.response.package", "loaded package proof changed before metadata delivery")
            response.metadata_taken = True
            self._deliveries.pop(response_delivery_handle, None)
            return ProviderResponseMetadata(
                response.handle,
                tuple(
                    # Call rows remain root-owned; the metadata copy does not
                    # consume the one-use begin handle.
                    self._native_tool_binding(handle, row)
                    for handle, row in response.calls.items()
                ),
                response.turn_handle,
                response.final_response_delivery_handle,
            )

    def attach_native_turn_observation_registry(self, registry: Any) -> None:
        """Attach the matching root turn registry exactly once during composition."""
        from .native_turn_observation import RootNativeTurnObservationRegistry

        if (type(registry) is not RootNativeTurnObservationRegistry
                or registry.service is not self.service
                or not callable(getattr(registry, "resolve_turn_for_source", None))
                or not callable(getattr(registry, "register_brokered_response", None))):
            raise AuthorityDenied("native.turn.registry", "whole-turn registry is not the matching root service")
        with self._lock:
            if self._native_turn_registry is not None:
                raise AuthorityDenied("native.turn.registry", "whole-turn registry is already attached")
            self._native_turn_registry = registry

    def resolve_turn_response_observation(self, response_observation_handle: str) -> Any:
        """Expose one immutable root observation to the paired turn registry."""
        from .native_turn_observation import RootProviderResponseObservation

        if not self._valid_handle(response_observation_handle):
            raise AuthorityDenied("native.turn.response", "provider observation handle is malformed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            response = self._responses.get(response_observation_handle)
            if response is None:
                raise AuthorityDenied("native.turn.response", "provider response observation is unavailable")
            producer = self.process_resolver(
                response.producer_pid, response.producer_pidfd,
                profile_id=response.profile_id, generation=response.generation)
            gateway = self.process_resolver(
                response.gateway_pid, response.gateway_pidfd,
                profile_id=response.bridge.gateway_profile_id,
                generation=response.bridge.gateway_generation)
            if (producer != response.producer_identity or gateway != response.gateway_identity
                    or response.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("native.turn.response", "retained response peer or lease changed")
            binding = self.service._binding(response.bridge.producer_uid)
            self.service._verify_context_signature(response.request_context)
            self.service._verify_grant_signature(response.authorization)
            self.service._assert_current_context(
                response.request_context, binding, response.bridge.producer_uid,
                peer_pid=response.producer_pid)
            self.service._assert_grant_current(
                response.authorization, binding, response.bridge.producer_uid)
            with self.service._lock:
                if any(handle not in self.service._source_receipt_handles
                       or self.service._source_receipt_handles[handle].monotonic_expires_at
                       <= self.monotonic() for handle in response.receipt_handles):
                    raise AuthorityDenied("native.turn.response", "retained response source closure expired")
            return RootProviderResponseObservation(
                response_observation_handle=response.handle,
                final_response_delivery_handle=None,
                native_request_handle=response.native_request_handle,
                source_receipt_handles=response.receipt_handles,
                response_receipt_handle=response.response_receipt_handle,
                observer_enrollment_id=response.observer_id,
                response_bytes=response.response_bytes,
                response_sha256=response.response_digest,
                producer_identity=response.producer_identity,
                producer_pid=response.producer_pid,
                producer_pidfd=response.producer_pidfd,
                profile_id=response.profile_id,
                process_generation=response.generation,
                native_package_generation=response.native_package_generation,
                service_generation_digest=self.service.service_generation_digest,
                expires_monotonic=response.expires_monotonic,
                complete=True,
                pending_tool_call_handles=tuple(response.calls),
                pending_delegation_handles=(),
                response_status=response.response_status,
                response_headers=response.response_headers,
                request_context=response.request_context,
                authorization=response.authorization,
                target=response.target,
                recipient=response.recipient,
                request_sha256=response.request_digest,
                retry_index=response.retry_index,
                gateway_identity=response.gateway_identity,
                gateway_pid=response.gateway_pid,
                gateway_pidfd=response.gateway_pidfd,
                loaded_package_proof=response.loaded_package_proof,
            )

    def _associate_response_with_turn(self, response: _ObservedProviderResponse,
                                      source_handles: tuple[str, ...]) -> None:
        registry = self._native_turn_registry
        if registry is None or not source_handles:
            return
        turns: set[str] = set()
        for source_handle in source_handles:
            try:
                turns.add(registry.resolve_turn_for_source(
                    source_handle, response.producer_identity))
            except AuthorityDenied:
                continue
        if len(turns) != 1:
            return
        turn_handle = next(iter(turns))
        # The provider observation row is already retained before this call;
        # the turn registry validates its exact bytes and request closure.
        final_handle = registry.register_brokered_response(turn_handle, response.handle)
        if final_handle is not None and not self._valid_handle(final_handle):
            raise AuthorityDenied("native.turn.response", "turn registry returned an invalid final handle")
        with self._lock:
            if self._responses.get(response.handle) is not response:
                raise AuthorityDenied("native.turn.response", "provider observation expired during turn join")
            response.turn_handle = turn_handle
            response.final_response_delivery_handle = final_handle

    @staticmethod
    def _native_tool_binding(handle: str, row: tuple[str, str, str, str, bytes]) -> Any:
        from .types import NativeToolCallBinding
        call_id, tool_name, _adapter_id, _action_id, arguments = row
        return NativeToolCallBinding(
            observed_call_handle=handle,
            provider_tool_call_id=call_id,
            tool_name=tool_name,
            arguments_sha256=hashlib.sha256(arguments).hexdigest(),
        )

    def begin_native_invocation(self, peer_uid: int, peer_pid: int, peer_pidfd: int,
                                producer_context_handle: str, observed_call_handle: str,
                                canonical_arguments: bytes):
        """Atomically bind one actual root-parsed provider tool call to action."""
        from .types import NativeInvocationBinding

        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not self._valid_handle(producer_context_handle)
                or not self._valid_handle(observed_call_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= _MAX_TOOL_ARGUMENT_BYTES):
            raise AuthorityDenied("native.invocation.begin", "native invocation request is malformed")
        with self._lock:
            self._ensure_open()
            now = self.monotonic()
            self._prune_locked(now)
            response = self._responses.get(producer_context_handle)
            call_row = self._calls.get(observed_call_handle)
            if (response is None or call_row is None or call_row[0] != producer_context_handle
                    or response.metadata_taken is False):
                raise AuthorityDenied("native.invocation.handle", "provider response or tool call handle is unavailable")
            expected_identity = response.producer_identity
            bridge = response.bridge
            if peer_uid != bridge.producer_uid or peer_pid != response.producer_pid:
                raise AuthorityDenied("native.invocation.peer", "invocation handles belong to another process")
            identity = self.process_resolver(peer_pid, peer_pidfd,
                                             profile_id=response.profile_id,
                                             generation=response.generation)
            if identity != expected_identity:
                raise AuthorityDenied("native.invocation.peer", "invocation producer PIDFD identity changed")
            current_gateway = self.process_resolver(
                response.gateway_pid, response.gateway_pidfd,
                profile_id=bridge.gateway_profile_id, generation=bridge.gateway_generation,
            )
            if current_gateway != response.gateway_identity:
                raise AuthorityDenied("native.invocation.peer", "paired gateway PIDFD identity changed")
            current_proof = self._loaded_proof(response.observer_id, identity, peer_pid, peer_pidfd)
            if current_proof != response.loaded_package_proof:
                raise AuthorityDenied("native.invocation.package", "loaded native package closure proof changed")
            call_id, tool_name, adapter_id, action_id, expected_args = call_row[1:]
            digest = hashlib.sha256(canonical_arguments).hexdigest()
            if canonical_arguments != expected_args or digest != hashlib.sha256(expected_args).hexdigest():
                raise AuthorityDenied("native.invocation.arguments", "tool arguments differ from root response parser")
            if adapter_id == "resource-overlay-store":
                owner_registry = getattr(self.service, "active_owner_overlay_registry", None)
                resolve_owner = getattr(owner_registry, "resolve_provider_tool_call", None)
                if not callable(resolve_owner) or action_id not in {
                        "resource-overlay-store:tool:resource_overlay_read",
                        "resource-overlay-store:tool:resource_overlay_history",
                        "resource-overlay-store:tool:resource_overlay_write",
                        "resource-overlay-store:tool:resource_overlay_delete"}:
                    raise AuthorityDenied("native.invocation.owner_overlay", "selected owner operation is unavailable")
                try:
                    owner_source = resolve_owner(
                        tool_name, peer_pid, peer_pidfd, response.package_id, response.profile_id,
                        response.generation, response.native_package_generation, canonical_arguments,
                    )
                    operation = owner_source.selection.operation_record
                    if (action_id != owner_source.selection.registration_id
                            or operation["method"] != tool_name.removeprefix("resource_overlay_")):
                        raise ValueError
                    handle = self._opaque_handle()
                    parent_handles = tuple(dict.fromkeys(response.receipt_handles))
                    if not parent_handles or len(parent_handles) > 64:
                        raise ValueError
                    invocation_payload = {
                        "schema": 1, "invocation_handle": handle,
                        "observed_call_handle": observed_call_handle,
                        "response_observation_handle": response.handle,
                        "response_receipt_handle": response.response_receipt_handle,
                        "turn_handle": response.turn_handle,
                        "native_request_handle": response.native_request_handle,
                        "registration_id": action_id, "method": operation["method"],
                        "arguments_sha256": digest,
                        "canonical_arguments_b64": base64.b64encode(canonical_arguments).decode("ascii"),
                        "parent_source_receipt_handles": list(parent_handles),
                    }
                    payload = json.dumps(invocation_payload, ensure_ascii=False, sort_keys=True,
                                         separators=(",", ":"), allow_nan=False).encode("utf-8")
                    owner_observer_id = owner_source.observer_row["observer_enrollment_id"]
                    event_id = self.source_observers.record_observed_event(
                        owner_observer_id, payload_bytes=payload,
                        parent_context=response.request_context, peer_pid=peer_pid,
                        peer_pidfd=peer_pidfd, parent_receipt_handles=parent_handles,
                    )
                    receipt_handle = self.source_observers.capture_observed_source(
                        owner_observer_id, event_id, payload, parent_receipt_handles=parent_handles,
                    )
                    delivered = self.source_observers.take_source_receipt(
                        str(receipt_handle), peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                    )
                    if str(delivered) != str(receipt_handle):
                        raise ValueError
                    closure_ids = tuple(sorted({self.service._source_receipt_handles[item].receipt_id
                                                for item in (*parent_handles, str(receipt_handle))
                                                if item in self.service._source_receipt_handles}))
                    if len(closure_ids) != len(parent_handles) + 1:
                        raise ValueError
                    expiry = min(response.expires_monotonic, owner_source.selection.expires_monotonic)
                    row = RootNativeOwnerOverlayInvocation(
                        handle, producer_context_handle, observed_call_handle, response.handle,
                        response.response_receipt_handle, response.turn_handle,
                        response.native_request_handle, action_id, operation["method"],
                        bytes(canonical_arguments), digest, tuple((*parent_handles, str(receipt_handle))),
                        str(receipt_handle), response.producer_identity, peer_pid, os.dup(peer_pidfd),
                        response.gateway_identity, response.gateway_pid, os.dup(response.gateway_pidfd),
                        response.bridge, response, owner_source, expiry, False,
                        _OWNER_OVERLAY_INVOCATION_SEAL, self,
                    )
                    self._calls.pop(observed_call_handle, None)
                    response.calls.pop(observed_call_handle, None)
                    self._owner_overlay_invocations[handle] = row
                    self._issued_handles.add(handle)
                    binding_unsigned = {
                        "schema": 1, "invocation_handle": handle,
                        "package_id": response.package_id, "profile_id": response.profile_id,
                        "generation": response.generation, "adapter_id": "resource-overlay-store",
                        "action_id": action_id, "arguments_sha256": digest,
                        "parent_closure_digest": canonical_digest(list(closure_ids)),
                        "expires_monotonic": expiry,
                    }
                    return NativeInvocationBinding(
                        invocation_handle=handle, package_id=response.package_id,
                        profile_id=response.profile_id, generation=response.generation,
                        adapter_id="resource-overlay-store", action_id=action_id,
                        arguments_sha256=digest,
                        parent_closure_digest=canonical_digest(list(closure_ids)),
                        expires_monotonic=expiry,
                        binding_sha256=canonical_digest(json.dumps(
                            binding_unsigned, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")),
                    )
                except AuthorityDenied:
                    raise
                except Exception:
                    raise AuthorityDenied("native.invocation.owner_overlay",
                                          "current owner operation invocation capture failed") from None
            try:
                selection = self.action_resolver(bridge, identity, tool_name)
            except Exception:
                raise AuthorityDenied("native.invocation.action", "root action selection changed") from None
            if (not isinstance(selection, NativeActionSelection)
                    or not isinstance(selection.operation, str) or not selection.operation
                    or (selection.package_id, selection.profile_id, selection.generation,
                        selection.package_generation, selection.adapter_id, selection.action_id)
                    != (response.package_id, response.profile_id, response.generation,
                        response.native_package_generation,
                        adapter_id, action_id)
                    or not self._validate_selection(selection, canonical_arguments)):
                raise AuthorityDenied("native.invocation.action", "selected action mapping changed before invocation")
            observer = self.source_observers.observers.get(response.observer_id)
            package, _role = self.source_observers._resolve_package_role(observer)
            selected_registrations = self._selected_action_registration_ids(
                observer=observer, package=package, selection=selection,
            )
            observed_registrations = self._require_observed_registrations(observer, current_proof)
            if not set(selected_registrations).issubset(observed_registrations):
                raise AuthorityDenied(
                    "native.invocation.action", "selected action registration is absent from loaded role proof",
                )
            handle = self._opaque_handle()
            with self.service._lock:
                closure_ids = tuple(sorted({self.service._source_receipt_handles[item].receipt_id
                                            for item in response.receipt_handles
                                            if item in self.service._source_receipt_handles}))
            if len(closure_ids) != len(response.receipt_handles):
                raise AuthorityDenied("native.invocation.lineage", "provider response source closure expired")
            closure_digest = canonical_digest(list(closure_ids))
            with self.service._lock:
                result_receipt = self.service._source_receipt_handles.get(response.receipt_handles[-1])
            if result_receipt is None:
                raise AuthorityDenied("native.invocation.lineage", "provider response receipt expired")
            lease = min(response.expires_monotonic, result_receipt.monotonic_expires_at)
            row = _NativeInvocation(
                handle, producer_context_handle, observed_call_handle, bridge, identity,
                peer_pid, os.dup(peer_pidfd), response.gateway_identity,
                response.gateway_pid, os.dup(response.gateway_pidfd),
                response.package_id, response.profile_id,
                response.generation, response.native_package_generation,
                adapter_id, action_id, selection.registration_id, tool_name, digest, closure_digest,
                response.receipt_handles, bytes(canonical_arguments), response.observer_id,
                current_proof, lease,
                self.service.service_generation_digest, operation=selection.operation,
                result_schema_id=selection.result_schema_id,
                result_schema_sha256=selection.result_schema_sha256,
            )
            # Consume the observed call before publishing a binding. No failed
            # or concurrent begin can re-open this response call.
            self._calls.pop(observed_call_handle, None)
            response.calls.pop(observed_call_handle, None)
            self._issued_handles.add(handle)
            self._invocations[handle] = row
            binding_unsigned = {
                "schema": 1, "invocation_handle": handle, "package_id": row.package_id,
                "profile_id": row.profile_id, "generation": row.generation,
                "adapter_id": row.adapter_id, "action_id": row.action_id,
                "arguments_sha256": row.arguments_sha256,
                "parent_closure_digest": row.parent_closure_digest,
                "expires_monotonic": row.expires_monotonic,
            }
            binding_digest = canonical_digest(json.dumps(
                binding_unsigned, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False, allow_nan=False,
            ).encode("utf-8"))
            return NativeInvocationBinding(
                invocation_handle=handle, package_id=row.package_id,
                profile_id=row.profile_id, generation=row.generation,
                adapter_id=row.adapter_id, action_id=row.action_id,
                arguments_sha256=row.arguments_sha256,
                parent_closure_digest=row.parent_closure_digest,
                expires_monotonic=row.expires_monotonic,
                binding_sha256=binding_digest,
            )

    def consume_native_mcp_invocation(self, peer_uid: int, peer_pid: int, peer_pidfd: int,
                                     invocation_handle: str,
                                     canonical_arguments: bytes) -> RootNativeMCPInvocation:
        """Consume one lexical invocation for one root MCP dispatch.

        This is a root-to-root API. It joins the opaque handle to the actual
        provider response, producer PIDFD, loaded package proof, root-selected
        action, exact canonical arguments and retained receipt closure before
        publishing an immutable capability record to the dispatcher.
        """
        if (type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not self._valid_handle(invocation_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= _MAX_TOOL_ARGUMENT_BYTES):
            raise AuthorityDenied("native.mcp.invocation", "native MCP invocation lookup is malformed")
        try:
            parsed = json.loads(canonical_arguments.decode("utf-8"))
            if not isinstance(parsed, dict) or json.dumps(
                    parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                    allow_nan=False).encode("utf-8") != canonical_arguments:
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise AuthorityDenied("native.mcp.invocation", "native MCP arguments are not canonical JSON") from None
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            invocation = self._invocations.get(invocation_handle)
            if invocation is None or invocation.mcp_dispatch_consumed:
                raise AuthorityDenied("native.mcp.invocation", "native MCP invocation is unknown or consumed")
            if not self._native_mcp_peer_current(invocation, peer_uid, peer_pid, peer_pidfd,
                                                 canonical_arguments):
                raise AuthorityDenied("native.mcp.invocation", "native MCP invocation binding is stale")
            dto = RootNativeMCPInvocation(
                invocation_handle=invocation.invocation_handle,
                tool_name=invocation.tool_name,
                adapter_id=invocation.adapter_id,
                action_id=invocation.action_id,
                package_id=invocation.package_id,
                profile_id=invocation.profile_id,
                generation=invocation.generation,
                arguments_sha256=invocation.arguments_sha256,
                parent_closure_digest=invocation.parent_closure_digest,
                expires_monotonic=invocation.expires_monotonic,
                source_receipt_handles=invocation.receipt_handles,
                native_process_identity=invocation.producer_identity,
                service_generation_digest=invocation.service_generation_digest,
            )
            invocation.mcp_dispatch_consumed = True
            self._mcp_dispatches[invocation_handle] = (invocation, dto)
            return dto

    def resolve_current_owner_overlay_invocation(
            self, invocation_handle: str, canonical_arguments: bytes, *,
            peer_uid: int, peer_pid: int, peer_pidfd: int) -> RootNativeOwnerOverlayInvocation:
        """Consume the tagged local invocation after rejoining live root facts."""
        if (not self._valid_handle(invocation_handle) or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("native.owner_overlay.invocation", "owner invocation request is malformed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            row = self._owner_overlay_invocations.get(invocation_handle)
            if (type(row) is not RootNativeOwnerOverlayInvocation
                    or row._seal is not _OWNER_OVERLAY_INVOCATION_SEAL
                    or row._issuer is not self or invocation_handle in self._owner_overlay_consumed
                    or row.expires_monotonic <= self.monotonic()
                    or row.canonical_arguments != canonical_arguments
                    or row.arguments_sha256 != hashlib.sha256(canonical_arguments).hexdigest()
                    or row.producer_pid != peer_pid or row.bridge.producer_uid != peer_uid):
                raise AuthorityDenied("native.owner_overlay.invocation", "owner invocation is stale or already consumed")
            active = None
            current = None
            try:
                identity = self.process_resolver(
                    peer_pid, peer_pidfd, profile_id=row.response.profile_id,
                    generation=row.response.generation)
                gateway = self.process_resolver(
                    row.gateway_pid, row.gateway_pidfd,
                    profile_id=row.bridge.gateway_profile_id,
                    generation=row.bridge.gateway_generation)
                proof = self._loaded_proof(row.response.observer_id, identity, peer_pid, peer_pidfd)
                active = getattr(self.service, "active_owner_overlay_registry", None)
                resolve_owner = getattr(active, "resolve_provider_tool_call", None)
                current = resolve_owner(
                    {
                        "read": "resource_overlay_read", "history": "resource_overlay_history",
                        "write": "resource_overlay_write", "delete": "resource_overlay_delete",
                    }[row.method], peer_pid, peer_pidfd, row.response.package_id,
                    row.response.profile_id, row.response.generation,
                    row.response.native_package_generation, canonical_arguments,
                )
                receipt_handles = (*row.parent_source_receipt_handles,)
                with self.service._lock:
                    retained = tuple(self.service._source_receipt_handles.get(item)
                                     for item in receipt_handles)
                if (identity != row.producer_identity or gateway != row.gateway_identity
                        or proof != row.response.loaded_package_proof
                        or current.selection.registration_id != row.registration_id
                        or current.selection.adoption_sha256 != row.source_observer.selection.adoption_sha256
                        or current.selection.operation_record != row.source_observer.selection.operation_record
                        or len(retained) != len(receipt_handles) or any(item is None for item in retained)):
                    raise ValueError
            except Exception:
                raise AuthorityDenied("native.owner_overlay.invocation", "owner source, peer, READY role or receipts changed") from None
            finally:
                retire = getattr(active, "_retire", None)
                if callable(retire) and current is not None:
                    retire(current.selection.selection_handle)
            self._owner_overlay_consumed.add(invocation_handle)
            return row

    def resolve_current_health_owner_invocation(
            self, request_projection: Any, input_event: Any, *,
            peer_uid: int, peer_pid: int, peer_pidfd: int,
            live_producer_identity: Any, expected_profile_id: str,
            expected_generation: str, expected_package_id: str,
            expected_package_generation: str, expected_service_generation_digest: str,
            expected_action_id: str) -> RootSelectedHealthOwnerInvocation:
        """Resolve the unique consumed provider call causally descended from health input."""
        from .native_request_observation import (
            RootSelectedHealthNativeRequest, NativeRequestObservationRegistry,
        )
        from .native_input_observer import RootNativeInputEvent
        if (type(request_projection) is not RootSelectedHealthNativeRequest
                or type(request_projection._registry) is not NativeRequestObservationRegistry
                or type(input_event) is not RootNativeInputEvent
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or live_producer_identity is None):
            raise AuthorityDenied("native.health.invocation", "health tool-call selection is malformed")
        observation = request_projection.observation
        request_projection._registry.verify_current_health_request_for_input(
            request_projection, input_event,
            live_producer_identity=live_producer_identity,
            producer_pid=peer_pid, producer_profile_id=expected_profile_id,
            producer_generation=expected_generation,
            native_package_generation=expected_package_generation,
        )
        if (input_event.source_receipt_handle not in observation.parent_source_receipt_handles
                or observation.producer_profile_id != expected_profile_id
                or observation.producer_process_generation != expected_generation
                or observation.native_package_generation != expected_package_generation):
            raise AuthorityDenied("native.health.invocation_lineage", "request does not descend from the selected input")
        current_identity = self.process_resolver(
            peer_pid, peer_pidfd, profile_id=expected_profile_id, generation=expected_generation,
        )
        if current_identity != live_producer_identity:
            raise AuthorityDenied("native.health.invocation_peer", "selected producer PIDFD changed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            candidates = tuple(
                row for handle, row in self._owner_overlay_invocations.items()
                if row.invocation_handle == handle
                and row.native_request_handle == observation.native_request_handle
                and row.producer_pid == peer_pid
                and row.producer_identity == live_producer_identity
                and row.invocation_handle in self._owner_overlay_consumed
                and row.registration_id == "resource-overlay-store:tool:resource_overlay_read"
                and row.method == "read"
                and row.action_id == expected_action_id
                and row.expires_monotonic > self.monotonic()
            )
        if len(candidates) != 1:
            code = ("native.health.invocation_pending" if not candidates
                    else "native.health.invocation_ambiguous")
            raise AuthorityDenied(code, "request has no unique consumed health tool call")
        row = candidates[0]
        response = row.response
        try:
            with self._lock:
                if (self._responses.get(row.response_observation_handle) is not response
                        or response.handle != row.response_observation_handle
                        or response.metadata_taken is not True
                        or response.native_request_handle != observation.native_request_handle
                        or response.producer_identity != live_producer_identity
                        or response.producer_pid != peer_pid
                        or response.profile_id != expected_profile_id
                        or response.generation != expected_generation
                        or response.package_id != expected_package_id
                        or response.native_package_generation != expected_package_generation
                        or response.request_context.service_generation_digest
                           != expected_service_generation_digest
                        or response.expires_monotonic <= self.monotonic()
                        or hashlib.sha256(response.response_bytes).hexdigest() != response.response_digest
                        or response.response_status < 200 or response.response_status >= 300
                        or input_event.source_receipt_handle not in response.receipt_handles):
                    raise ValueError
            args = _strict_native_json(row.canonical_arguments)
            canonical_args = json.dumps(args, sort_keys=True, separators=(",", ":"),
                                        ensure_ascii=False, allow_nan=False).encode("utf-8")
            if (type(args) is not dict or args != {"record_id": "hermes-health-probe-v1"}
                    or canonical_args != row.canonical_arguments
                    or hashlib.sha256(canonical_args).hexdigest() != row.arguments_sha256
                    or row.parent_source_receipt_handles != response.receipt_handles + (row.invocation_source_receipt_handle,)
                    or row.invocation_source_receipt_handle not in row.parent_source_receipt_handles):
                raise ValueError
            identity = self.process_resolver(
                peer_pid, peer_pidfd, profile_id=expected_profile_id,
                generation=expected_generation,
            )
            gateway = self.process_resolver(
                row.gateway_pid, row.gateway_pidfd,
                profile_id=row.bridge.gateway_profile_id,
                generation=row.bridge.gateway_generation,
            )
            proof = self._loaded_proof(response.observer_id, identity, peer_pid, peer_pidfd)
            active = getattr(self.service, "active_owner_overlay_registry", None)
            resolve_owner = getattr(active, "resolve_provider_tool_call", None)
            if not callable(resolve_owner):
                raise ValueError
            current = resolve_owner(
                "resource_overlay_read", peer_pid, peer_pidfd, expected_package_id,
                expected_profile_id, expected_generation, expected_package_generation,
                canonical_args,
            )
            with self.service._lock:
                receipt_rows = tuple(
                    self.service._source_receipt_handles.get(handle)
                    for handle in (*response.receipt_handles, *row.parent_source_receipt_handles)
                )
            handles = tuple((*response.receipt_handles, *row.parent_source_receipt_handles))
            if (identity != live_producer_identity or gateway != row.gateway_identity
                    or proof != response.loaded_package_proof or current is None
                    or current.selection.registration_id != row.registration_id
                    or current.selection.adoption_sha256 != row.source_observer.selection.adoption_sha256
                    or current.selection.operation_record != row.source_observer.selection.operation_record
                    or len(receipt_rows) != len(handles) or any(receipt is None for receipt in receipt_rows)):
                raise ValueError
            by_handle = dict(zip(handles, receipt_rows, strict=True))
            unique_handles = tuple(sorted(set(handles), key=lambda handle: by_handle[handle].receipt_id))
            unique_rows = tuple(by_handle[handle] for handle in unique_handles)
            for receipt in unique_rows:
                self.service._verify_source_receipt(receipt, self.service._binding(receipt.uid))
            receipt_ids = tuple(sorted(receipt.receipt_id for receipt in unique_rows))
            if len(receipt_ids) != len(set(receipt_ids)):
                raise ValueError
            with self.service._lock:
                provider_by_handle = {
                    handle: self.service._source_receipt_handles.get(handle)
                    for handle in response.receipt_handles
                }
            if any(receipt is None for receipt in provider_by_handle.values()):
                raise ValueError
            provider_handles = tuple(sorted(
                response.receipt_handles,
                key=lambda handle: provider_by_handle[handle].receipt_id,
            ))
            provider_ids = tuple(provider_by_handle[handle].receipt_id
                                  for handle in provider_handles)
            if (len(provider_by_handle) != len(response.receipt_handles)
                    or len(provider_ids) != len(set(provider_ids))):
                raise ValueError
            return RootSelectedHealthOwnerInvocation(
                request_projection=request_projection,
                provider_response=response,
                owner_invocation=row,
                source_receipt_handles=unique_handles,
                source_receipt_ids=receipt_ids,
                provider_source_receipt_handles=provider_handles,
                provider_source_receipt_ids=provider_ids,
                _registry=self, _issuer=self._health_selection_issuer,
            )
        except Exception:
            raise AuthorityDenied("native.health.invocation", "current request/provider/tool source join is unavailable") from None
        finally:
            retire = getattr(locals().get("active"), "_retire", None)
            if callable(retire) and locals().get("current") is not None:
                retire(current.selection.selection_handle)

    def verify_current_health_owner_invocation(
            self, selected: RootSelectedHealthOwnerInvocation, input_event: Any, *,
            peer_uid: int, peer_pid: int, peer_pidfd: int,
            live_producer_identity: Any, expected_profile_id: str,
            expected_generation: str, expected_package_id: str,
            expected_package_generation: str, expected_service_generation_digest: str,
            expected_action_id: str) -> RootSelectedHealthOwnerInvocation:
        """Re-resolve the unique current consumed call and require same objects."""
        if (type(selected) is not RootSelectedHealthOwnerInvocation
                or selected._registry is not self
                or selected._issuer is not self._health_selection_issuer):
            raise AuthorityDenied("native.health.invocation", "issuer-owned tool-call projection is required")
        current = self.resolve_current_health_owner_invocation(
            selected.request_projection, input_event,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            live_producer_identity=live_producer_identity,
            expected_profile_id=expected_profile_id,
            expected_generation=expected_generation,
            expected_package_id=expected_package_id,
            expected_package_generation=expected_package_generation,
            expected_service_generation_digest=expected_service_generation_digest,
            expected_action_id=expected_action_id,
        )
        if (current.owner_invocation is not selected.owner_invocation
                or current.provider_response is not selected.provider_response
                or current.request_projection.observation
                   is not selected.request_projection.observation
                or current.source_receipt_handles != selected.source_receipt_handles
                or current.source_receipt_ids != selected.source_receipt_ids
                or current.provider_source_receipt_handles != selected.provider_source_receipt_handles
                or current.provider_source_receipt_ids != selected.provider_source_receipt_ids):
            raise AuthorityDenied("native.health.invocation", "current owner call or source ancestry changed")
        return selected

    def is_current_native_mcp_invocation(self, record: RootNativeMCPInvocation,
                                         peer_uid: int, peer_pid: int,
                                         peer_pidfd: int) -> bool:
        """Revalidate the same consumed DTO before each effect or result release."""
        if (type(record) is not RootNativeMCPInvocation
                or type(peer_uid) is not int or type(peer_pid) is not int
                or type(peer_pidfd) is not int or peer_uid <= 0 or peer_pid <= 0
                or peer_pidfd < 0):
            return False
        with self._lock:
            if self._closed or self.monotonic() >= record.expires_monotonic:
                return False
            held = self._mcp_dispatches.get(record.invocation_handle)
            if held is None or held[1] is not record or held[0].mcp_dispatch_consumed is not True:
                return False
            invocation = held[0]
            if any((getattr(record, name, None) != getattr(invocation, source_name, None))
                   for name, source_name in (
                       ("tool_name", "tool_name"), ("adapter_id", "adapter_id"),
                       ("action_id", "action_id"), ("package_id", "package_id"),
                       ("profile_id", "profile_id"), ("generation", "generation"),
                       ("arguments_sha256", "arguments_sha256"),
                       ("parent_closure_digest", "parent_closure_digest"),
                       ("source_receipt_handles", "receipt_handles"),
                       ("native_process_identity", "producer_identity"),
                       ("service_generation_digest", "service_generation_digest"))):
                return False
            return self._native_mcp_peer_current(invocation, peer_uid, peer_pid,
                                                 peer_pidfd, None)

    def _native_mcp_peer_current(self, invocation: _NativeInvocation,
                                 peer_uid: int, peer_pid: int, peer_pidfd: int,
                                 canonical_arguments: bytes | None) -> bool:
        if (self.service.service_generation_digest != invocation.service_generation_digest
                or peer_uid != invocation.producer_identity.kernel_uid
                or peer_pid != invocation.producer_pid
                or self.monotonic() >= invocation.expires_monotonic
                    or (canonical_arguments is not None
                        and hashlib.sha256(canonical_arguments).hexdigest() != invocation.arguments_sha256)):
            return False
        try:
            identity = self.process_resolver(peer_pid, peer_pidfd,
                                             profile_id=invocation.profile_id,
                                             generation=invocation.generation)
            gateway = self.process_resolver(invocation.gateway_pid, invocation.gateway_pidfd,
                                             profile_id=invocation.bridge.gateway_profile_id,
                                             generation=invocation.bridge.gateway_generation)
            proof = self._loaded_proof(invocation.observer_id, identity, peer_pid, peer_pidfd)
            action = self.action_resolver(invocation.bridge, identity, invocation.tool_name)
            observer = self.source_observers.observers.get(invocation.observer_id)
            package, _role = self.source_observers._resolve_package_role(observer)
            selected_registrations = self._selected_action_registration_ids(
                observer=observer, package=package, selection=action,
            )
            observed_registrations = self._require_observed_registrations(observer, proof)
            if (identity != invocation.producer_identity or gateway != invocation.gateway_identity
                    or proof != invocation.loaded_package_proof
                    or not isinstance(action, NativeActionSelection)
                    or (action.package_id, action.profile_id, action.generation,
                        action.package_generation, action.adapter_id, action.action_id,
                        action.registration_id, action.operation,
                        action.result_schema_id, action.result_schema_sha256)
                    != (invocation.package_id, invocation.profile_id, invocation.generation,
                        invocation.package_generation, invocation.adapter_id, invocation.action_id,
                        invocation.registration_id,
                        getattr(invocation, "operation", None),
                        invocation.result_schema_id, invocation.result_schema_sha256)
                    or not set(selected_registrations).issubset(observed_registrations)
                    or not self._validate_selection(action, invocation.canonical_arguments)
                    or hashlib.sha256(invocation.canonical_arguments).hexdigest()
                    != invocation.arguments_sha256):
                return False
            with self.service._lock:
                receipts = [self.service._source_receipt_handles.get(handle)
                            for handle in invocation.receipt_handles]
            ok_receipts = (bool(receipts) and all(
                receipt is not None and receipt.profile_id == invocation.profile_id
                and receipt.process_generation == invocation.generation
                and receipt.uid == peer_uid and receipt.monotonic_expires_at > self.monotonic()
                for receipt in receipts
            ))
            return ok_receipts
        except Exception:
            return False

    def resolve_invocation_for_effect(self, context: HostContext, authorization: Any,
                                      operation: str, payload_digest: str) -> Any:
        """Resolve one root-retained tool call for a validated native effect.

        This is root-private and accepts no invocation/call identifier. The
        only candidate is selected by the signed effect claims and the exact
        source-receipt closure retained when the provider call was observed.
        The returned DTO is a one-use correlation record for the result
        observer, not an RPC capability.
        """
        if (not isinstance(context, HostContext)
                or type(operation) is not str or not operation
                or not isinstance(payload_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", payload_digest)):
            raise AuthorityDenied("native.effect.invocation", "effect invocation binding is malformed")
        from .types import EffectAuthorization
        if not isinstance(authorization, EffectAuthorization):
            raise AuthorityDenied("native.effect.invocation", "effect authorization is unavailable")
        service = self.service
        try:
            binding = service._binding(context.uid)
            # _perform_effect has already parsed and verified the signed grant,
            # then reconstructs this root-only context from that grant. That
            # internal view deliberately carries a sentinel signature; it is
            # not a second wire context to verify here.
            service._verify_grant_signature(authorization)
            service._assert_current_context(context, binding, context.uid)
            service._assert_grant_current(authorization, binding, context.uid)
            if (authorization.source_receipts != context.source_receipts
                    or authorization.final_payload_digest != context.final_payload_digest
                    or context.final_payload_digest != payload_digest
                    or authorization.request_digest != payload_digest
                    or authorization.operation != operation
                    or context.operation != operation
                    or authorization.profile_id != context.profile_id
                    or authorization.principal_id != context.principal_id
                    or authorization.uid != context.uid
                    or authorization.generation != context.generation
                    or authorization.native_process_identity != context.native_process_identity):
                raise AuthorityDenied("native.effect.invocation", "signed effect does not bind the observed payload")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.effect.invocation", "effect authority is stale or unverifiable") from None

        # Resolve each signed source receipt to its retained root handle. The
        # complete set must exactly equal one invocation's source closure.
        by_id: dict[str, str] = {}
        with service._lock:
            for handle, receipt in service._source_receipt_handles.items():
                if receipt.monotonic_expires_at > self.monotonic():
                    if receipt.receipt_id in by_id:
                        raise AuthorityDenied("native.effect.lineage", "source receipt identity is ambiguous")
                    by_id[receipt.receipt_id] = handle
        source_ids = tuple(receipt.receipt_id for receipt in context.source_receipts)
        if (not source_ids or len(source_ids) != len(set(source_ids))
                or any(receipt_id not in by_id for receipt_id in source_ids)):
            raise AuthorityDenied("native.effect.lineage", "signed source closure is unavailable")
        source_handles = tuple(by_id[receipt_id] for receipt_id in source_ids)
        runtime_observer = getattr(service, "native_runtime_observer", None)
        discovery_receipts = getattr(runtime_observer, "_mcp_discovery_receipts", {})
        if not isinstance(discovery_receipts, Mapping):
            raise AuthorityDenied("native.effect.lineage", "root MCP discovery ancestry index is unavailable")
        prune_discovery = getattr(runtime_observer, "_prune_mcp_discovery_state_locked", None)
        discovery_lock = getattr(runtime_observer, "_lock", None)
        if callable(prune_discovery) and discovery_lock is not None:
            with discovery_lock:
                prune_discovery(self.monotonic())
                discovery_receipts = {
                    key: frozenset(handles)
                    for key, handles in runtime_observer._mcp_discovery_receipts.items()
                }
        matches: list[_NativeInvocation] = []
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            for row in self._invocations.values():
                response = self._responses.get(row.response_handle)
                if source_handles[:len(row.receipt_handles)] != row.receipt_handles:
                    continue
                discovery_handles = source_handles[len(row.receipt_handles):]
                admitted_discovery_handles = discovery_receipts.get(
                    row.invocation_handle, set(),
                )
                if (row.effect_result_consumed or row.expires_monotonic <= self.monotonic()
                        or response is None
                        or row.operation != operation
                        or row.producer_identity.kernel_uid != context.uid
                        or row.profile_id != context.profile_id
                        or row.generation != context.generation
                        or not set(discovery_handles).issubset(admitted_discovery_handles)):
                    continue
                matches.append(row)
            if len(matches) != 1:
                raise AuthorityDenied("native.effect.invocation", "no unique retained native invocation matches effect")
            row = matches[0]
            response = self._responses.get(row.response_handle)
            if response is None:
                raise AuthorityDenied("native.effect.invocation", "provider response observation expired")
            producer = self.process_resolver(row.producer_pid, row.producer_pidfd,
                                             profile_id=row.profile_id, generation=row.generation)
            gateway = self.process_resolver(row.gateway_pid, row.gateway_pidfd,
                                            profile_id=row.bridge.gateway_profile_id,
                                            generation=row.bridge.gateway_generation)
            proof = self._loaded_proof(row.observer_id, producer, row.producer_pid, row.producer_pidfd)
            try:
                service._assert_current_context(
                    context, binding, context.uid, peer_pid=row.producer_pid)
            except Exception:
                raise AuthorityDenied("native.effect.peer", "effect context is not bound to the live producer") from None
            if (service._native_process_identity(row.producer_pid, context.uid)
                    != context.native_process_identity
                    or row.producer_identity.profile_id != context.profile_id
                    or row.producer_identity.generation != context.generation):
                raise AuthorityDenied("native.effect.peer", "effect peer identity changed")
            try:
                selected = self.action_resolver(row.bridge, producer, row.tool_name)
            except Exception:
                raise AuthorityDenied("native.effect.action", "selected native action is unavailable") from None
            if (producer != row.producer_identity or gateway != row.gateway_identity
                    or proof != row.loaded_package_proof
                    or not isinstance(selected, NativeActionSelection)
                    or (selected.package_id, selected.profile_id, selected.generation,
                        selected.package_generation,
                        selected.adapter_id, selected.action_id,
                        selected.registration_id, selected.operation)
                    != (row.package_id, row.profile_id, row.generation,
                        row.package_generation,
                        row.adapter_id, row.action_id, row.registration_id, operation)
                    or not self._native_mcp_peer_current(
                        row, row.producer_identity.kernel_uid, row.producer_pid,
                        row.producer_pidfd, None)):
                raise AuthorityDenied("native.effect.action", "current peer, package, or selected action changed")
            # A grant is single-use at the AuthorityService boundary. This
            # separate bit prevents a result receipt from being attached twice.
            row.effect_result_consumed = True
            row.effect_request_digest = payload_digest
            return RootNativeToolEffectInvocation(
                invocation_handle=row.invocation_handle,
                observed_call_handle=row.observed_call_handle,
                response_observation_handle=row.response_handle,
                response_receipt_handle=response.response_receipt_handle,
                native_request_handle=response.native_request_handle,
                turn_handle=response.turn_handle,
                producer_identity=row.producer_identity,
                producer_pid=row.producer_pid,
                profile_id=row.profile_id,
                generation=row.generation,
                package_id=row.package_id,
                native_package_generation=row.package_generation,
                service_generation_digest=row.service_generation_digest,
                adapter_id=row.adapter_id,
                action_id=row.action_id,
                registration_id=row.registration_id,
                tool_name=row.tool_name,
                arguments_sha256=row.arguments_sha256,
                source_receipt_handles=row.receipt_handles,
                operation=operation,
                request_digest=payload_digest,
                expires_monotonic=row.expires_monotonic,
            )

    def validate_effect_result(self, invocation: RootNativeToolEffectInvocation,
                               result_payload: bytes, *, observer_id: str) -> None:
        """Validate raw result bytes against the current protected action schema.

        The callback is re-resolved from the selected root action row. The
        invocation DTO is only a lookup key; it cannot supply a schema or a
        validator. Successful validation is one-use and precedes source-event
        recording/capture.
        """
        if (type(invocation) is not RootNativeToolEffectInvocation
                or not isinstance(result_payload, bytes)
                or not 1 <= len(result_payload) <= _MAX_RESULT_BYTES):
            raise AuthorityDenied("native.effect.result", "native result validation input is malformed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            row = self._invocations.get(invocation.invocation_handle)
            response = self._responses.get(row.response_handle) if row is not None else None
            if (row is None or response is None or not row.effect_result_consumed
                    or row.effect_result_schema_validated
                    or row.invocation_handle != invocation.invocation_handle
                    or row.observed_call_handle != invocation.observed_call_handle
                    or row.response_handle != invocation.response_observation_handle
                    or response.response_receipt_handle != invocation.response_receipt_handle
                    or response.native_request_handle != invocation.native_request_handle
                    or response.turn_handle != invocation.turn_handle
                    or row.producer_identity != invocation.producer_identity
                    or row.producer_pid != invocation.producer_pid
                    or row.profile_id != invocation.profile_id
                    or row.generation != invocation.generation
                    or row.package_id != invocation.package_id
                    or row.package_generation != invocation.native_package_generation
                    or row.service_generation_digest != invocation.service_generation_digest
                    or row.adapter_id != invocation.adapter_id
                    or row.action_id != invocation.action_id
                    or row.registration_id != invocation.registration_id
                    or row.tool_name != invocation.tool_name
                    or row.arguments_sha256 != invocation.arguments_sha256
                    or row.receipt_handles != invocation.source_receipt_handles
                    or row.operation != invocation.operation
                    or row.effect_request_digest != invocation.request_digest
                    or not math.isclose(row.expires_monotonic, invocation.expires_monotonic,
                                        rel_tol=0.0, abs_tol=0.0)
                    or row.expires_monotonic <= self.monotonic()):
                raise AuthorityDenied("native.effect.result", "native result has no current one-use invocation")
            try:
                identity = self.process_resolver(
                    row.producer_pid, row.producer_pidfd,
                    profile_id=row.profile_id, generation=row.generation)
                gateway = self.process_resolver(
                    row.gateway_pid, row.gateway_pidfd,
                    profile_id=row.bridge.gateway_profile_id,
                    generation=row.bridge.gateway_generation)
                proof = self._loaded_proof(
                    row.observer_id, identity, row.producer_pid, row.producer_pidfd)
                selected = self.action_resolver(row.bridge, identity, row.tool_name)
                observer = self.source_observers.observers.get(observer_id)
                package, _role = self.source_observers._resolve_package_role(observer)
                registrations = self._selected_action_registration_ids(
                    observer=observer, package=package, selection=selected)
                observed = self._require_observed_registrations(observer, proof)
            except Exception:
                raise AuthorityDenied("native.effect.result", "current result schema binding is unavailable") from None
            if (identity != row.producer_identity or gateway != row.gateway_identity
                    or proof != row.loaded_package_proof
                    or not isinstance(selected, NativeActionSelection)
                    or (selected.package_id, selected.profile_id, selected.generation,
                        selected.package_generation, selected.adapter_id, selected.action_id,
                        selected.registration_id, selected.operation,
                        selected.result_schema_id, selected.result_schema_sha256)
                    != (row.package_id, row.profile_id, row.generation,
                        row.package_generation, row.adapter_id, row.action_id,
                        row.registration_id, row.operation,
                        row.result_schema_id, row.result_schema_sha256)
                    or not registrations or not set(registrations).issubset(observed)
                    or observer_id not in self.source_observers.observers
                    or getattr(observer, "source_kind", None) != "tool-result"
                    or getattr(observer, "profile_id", None) != row.profile_id
                    or getattr(observer, "generation", None) != row.generation
                    or getattr(observer, "capture_schema_id", None)
                    != "native-registered-tool-result-v1"):
                raise AuthorityDenied("native.effect.result", "selected result schema or capture profile changed")
            try:
                valid = selected.validate_result(result_payload)
            except Exception:
                valid = False
            if valid is not True:
                raise AuthorityDenied("native.effect.result", "raw native tool result failed its selected schema")
            row.effect_result_schema_validated = True

    def resolve_current_invocation_for_effect(
            self, context: HostContext, authorization: Any, operation: str,
            target: str, request_digest: str,
            invocation_handle: str) -> RootNativeToolEffectInvocation:
        """Revalidate a previously selected effect invocation without consuming it.

        This lookup is for root-owned effect staging/finalization only. The
        opaque invocation handle is a selector into this registry's retained
        rows; it does not establish authority. Every signed claim, current
        peer, loaded package proof, selected action, source receipt, target,
        and lease is checked again before the current typed record is returned.
        Unlike ``resolve_invocation_for_effect`` it does not claim the
        one-use result-correlation bit, so completion validation may repeat it.
        """
        from .types import EffectAuthorization

        if (not isinstance(context, HostContext)
                or not isinstance(authorization, EffectAuthorization)
                or type(operation) is not str or not operation
                or type(target) is not str or not target
                or not isinstance(request_digest, str)
                or not _SHA256.fullmatch(request_digest)
                or not self._valid_handle(invocation_handle)):
            raise AuthorityDenied("native.effect.current", "current invocation lookup is malformed")
        service = self.service
        try:
            binding = service._binding(context.uid)
            service._verify_context_signature(context)
            service._verify_grant_signature(authorization)
            service._assert_current_context(context, binding, context.uid)
            service._assert_grant_current(authorization, binding, context.uid)
            from .service import _context_digest
            if (authorization.context_digest != _context_digest(context)
                    or authorization.source_receipts != context.source_receipts
                    or authorization.final_payload_digest != request_digest
                    or authorization.request_digest != request_digest
                    or context.final_payload_digest != request_digest
                    or authorization.operation != operation
                    or context.operation != operation
                    or authorization.target != target
                    or authorization.profile_id != context.profile_id
                    or authorization.principal_id != context.principal_id
                    or authorization.uid != context.uid
                    or authorization.generation != context.generation
                    or authorization.native_process_identity != context.native_process_identity):
                raise AuthorityDenied("native.effect.current", "signed effect does not bind the staged request")
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("native.effect.current", "effect authority is stale or unverifiable") from None

        source_ids = tuple(receipt.receipt_id for receipt in context.source_receipts)
        if not source_ids or len(source_ids) != len(set(source_ids)):
            raise AuthorityDenied("native.effect.current", "signed source closure is malformed")
        with service._lock:
            by_id: dict[str, str] = {}
            for handle, receipt in service._source_receipt_handles.items():
                if receipt.monotonic_expires_at > self.monotonic():
                    if receipt.receipt_id in by_id:
                        raise AuthorityDenied("native.effect.current", "source receipt identity is ambiguous")
                    by_id[receipt.receipt_id] = handle
        if any(receipt_id not in by_id for receipt_id in source_ids):
            raise AuthorityDenied("native.effect.current", "signed source closure is no longer retained")
        source_handles = tuple(by_id[receipt_id] for receipt_id in source_ids)

        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            row = self._invocations.get(invocation_handle)
            if row is None:
                raise AuthorityDenied("native.effect.current", "invocation is no longer retained")
            response = self._responses.get(row.response_handle)
            if (response is None or response.turn_handle is None
                    or row.expires_monotonic <= self.monotonic()
                    or row.operation != operation or row.bridge.target != target
                    or row.receipt_handles != source_handles
                    or row.producer_identity.kernel_uid != context.uid
                    or row.profile_id != context.profile_id
                    or row.generation != context.generation):
                raise AuthorityDenied("native.effect.current", "invocation no longer matches the effect")
            try:
                producer = self.process_resolver(
                    row.producer_pid, row.producer_pidfd,
                    profile_id=row.profile_id, generation=row.generation)
                gateway = self.process_resolver(
                    row.gateway_pid, row.gateway_pidfd,
                    profile_id=row.bridge.gateway_profile_id,
                    generation=row.bridge.gateway_generation)
                proof = self._loaded_proof(
                    row.observer_id, producer, row.producer_pid, row.producer_pidfd)
                selected = self.action_resolver(row.bridge, producer, row.tool_name)
                service._assert_current_context(
                    context, binding, context.uid, peer_pid=row.producer_pid)
            except Exception:
                raise AuthorityDenied("native.effect.current", "current peer or selected action is unavailable") from None
            if (producer != row.producer_identity or gateway != row.gateway_identity
                    or proof != row.loaded_package_proof
                    or service._native_process_identity(row.producer_pid, context.uid)
                    != context.native_process_identity
                    or not isinstance(selected, NativeActionSelection)
                    or (selected.package_id, selected.profile_id, selected.generation,
                        selected.package_generation,
                        selected.adapter_id, selected.action_id,
                        selected.registration_id, selected.operation)
                    != (row.package_id, row.profile_id, row.generation,
                        row.package_generation,
                        row.adapter_id, row.action_id, row.registration_id, operation)
                    or not self._validate_selection(selected, row.canonical_arguments)
                    or hashlib.sha256(row.canonical_arguments).hexdigest() != row.arguments_sha256
                    or not self._native_mcp_peer_current(
                        row, row.producer_identity.kernel_uid, row.producer_pid,
                        row.producer_pidfd, None)):
                raise AuthorityDenied("native.effect.current", "peer, package, or selected action changed")
            return RootNativeToolEffectInvocation(
                invocation_handle=row.invocation_handle,
                observed_call_handle=row.observed_call_handle,
                response_observation_handle=row.response_handle,
                response_receipt_handle=response.response_receipt_handle,
                native_request_handle=response.native_request_handle,
                turn_handle=response.turn_handle,
                producer_identity=row.producer_identity,
                producer_pid=row.producer_pid,
                profile_id=row.profile_id,
                generation=row.generation,
                package_id=row.package_id,
                native_package_generation=row.package_generation,
                service_generation_digest=row.service_generation_digest,
                adapter_id=row.adapter_id,
                action_id=row.action_id,
                registration_id=row.registration_id,
                tool_name=row.tool_name,
                arguments_sha256=row.arguments_sha256,
                source_receipt_handles=row.receipt_handles,
                operation=operation,
                request_digest=request_digest,
                expires_monotonic=row.expires_monotonic,
            )

    def get_invocation_contexts(self, peer_uid: int, peer_pid: int, peer_pidfd: int,
                                invocation_handle: str):
        """Return repeatable ancestry for one live invocation; it is not a grant."""
        from .types import NativeInvocationContexts

        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not self._valid_handle(invocation_handle)):
            raise AuthorityDenied("native.invocation.contexts", "native invocation lookup is malformed")
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            invocation = self._invocations.get(invocation_handle)
            if invocation is None or invocation.mcp_dispatch_consumed:
                raise AuthorityDenied("native.invocation.contexts", "native invocation is unknown or expired")
            if peer_uid != invocation.producer_identity.kernel_uid or peer_pid != invocation.producer_pid:
                raise AuthorityDenied("native.invocation.peer", "invocation context belongs to another process")
            identity = self.process_resolver(peer_pid, peer_pidfd,
                                             profile_id=invocation.profile_id,
                                             generation=invocation.generation)
            if identity != invocation.producer_identity:
                raise AuthorityDenied("native.invocation.peer", "invocation context PIDFD identity changed")
            current_gateway = self.process_resolver(
                invocation.gateway_pid, invocation.gateway_pidfd,
                profile_id=invocation.bridge.gateway_profile_id,
                generation=invocation.bridge.gateway_generation,
            )
            if current_gateway != invocation.gateway_identity:
                raise AuthorityDenied("native.invocation.peer", "paired gateway identity changed")
            proof = self._loaded_proof(invocation.observer_id, identity, peer_pid, peer_pidfd)
            if proof != invocation.loaded_package_proof:
                raise AuthorityDenied("native.invocation.package", "loaded package proof changed during invocation")
            for receipt_handle in invocation.receipt_handles:
                receipt = self.service._source_receipt_handles.get(receipt_handle)
                if (receipt is None or receipt.profile_id != invocation.profile_id
                        or receipt.uid != peer_uid or receipt.monotonic_expires_at <= self.monotonic()):
                    raise AuthorityDenied("native.invocation.lineage", "invocation source closure expired or changed")
            return NativeInvocationContexts(
                invocation_handle=invocation.invocation_handle,
                source_receipt_handles=invocation.receipt_handles,
                parent_closure_digest=invocation.parent_closure_digest,
                arguments_sha256=invocation.arguments_sha256,
                expires_monotonic=invocation.expires_monotonic,
            )

    def resolve_selected_application_invocation(
        self, invocation_handle: str, canonical_arguments: bytes, *,
        peer_uid: int, peer_pid: int, peer_pidfd: int,
    ) -> RootSelectedApplicationInvocation:
        """Return current root-selected native action evidence before app admission.

        The root application-workload authority performs the independent
        action-to-workload/catalog/runtime join and issues its own fresh
        ``process.start`` grant. This method accepts no workload or app label.
        """
        if (not self._valid_handle(invocation_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= _MAX_TOOL_ARGUMENT_BYTES
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0):
            raise AuthorityDenied("native.application.invocation", "selected action lookup is malformed")
        try:
            parsed = json.loads(canonical_arguments.decode("utf-8"))
            canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode("utf-8")
            if not isinstance(parsed, dict) or canonical != canonical_arguments:
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise AuthorityDenied("native.application.invocation", "selected arguments are not canonical JSON") from None
        request_digest = hashlib.sha256(canonical_arguments).hexdigest()
        with self._lock:
            self._ensure_open()
            self._prune_locked(self.monotonic())
            invocation = self._invocations.get(invocation_handle)
            if (invocation is None or invocation.mcp_dispatch_consumed
                    or invocation.canonical_arguments != canonical_arguments
                    or invocation.arguments_sha256 != request_digest
                    or peer_uid != invocation.producer_identity.kernel_uid
                    or peer_pid != invocation.producer_pid
                    or not self._native_mcp_peer_current(
                        invocation, peer_uid, peer_pid, peer_pidfd, canonical_arguments)):
                raise AuthorityDenied("native.application.invocation", "selected action is stale, foreign, or consumed")
            response = self._responses.get(invocation.response_handle)
            if (response is None or not response.metadata_taken
                    or response.turn_handle is None
                    or response.response_receipt_handle != invocation.receipt_handles[-1]
                    or response.expires_monotonic <= self.monotonic()
                    or response.profile_id != invocation.profile_id
                    or response.generation != invocation.generation
                    or response.package_id != invocation.package_id
                    or response.receipt_handles != invocation.receipt_handles
                    or response.authorization.operation != "provider.dispatch"
                    or response.authorization.target != response.target
                    or response.authorization.recipient != response.recipient
                    or response.authorization.request_digest != response.request_digest
                    or response.authorization.final_payload_digest != response.request_digest
                    or response.request_context.final_payload_digest != response.request_digest
                    or response.authorization.source_receipts != response.request_context.source_receipts):
                raise AuthorityDenied("native.application.turn", "current root provider turn is unavailable")
            with self.service._lock:
                receipts = [self.service._source_receipt_handles.get(handle)
                            for handle in invocation.receipt_handles]
                binding = self.service._binding(peer_uid)
                self.service._verify_context_signature(response.request_context)
                self.service._verify_grant_signature(response.authorization)
                self.service._assert_current_context(
                    response.request_context, binding, peer_uid, peer_pid=peer_pid)
            current_process_identity = self.service._native_process_identity(peer_pid, peer_uid)
            if (not receipts or any(
                    receipt is None or receipt.uid != peer_uid
                    or receipt.profile_id != invocation.profile_id
                    or receipt.process_generation != invocation.generation
                    or receipt.native_process_identity != current_process_identity
                    or receipt.monotonic_expires_at <= self.monotonic()
                    for receipt in receipts)):
                raise AuthorityDenied("native.application.lineage", "selected action source closure is stale")
            closure_digest = canonical_digest(sorted(receipt.receipt_id for receipt in receipts))
            request_parent_ids = {receipt.receipt_id
                                  for receipt in response.request_context.source_receipts}
            retained_parent_ids = {receipt.receipt_id for receipt in receipts[:-1]}
            if (closure_digest != invocation.parent_closure_digest
                    or self.service.service_generation_digest != invocation.service_generation_digest
                    or binding.principal_id != response.request_context.principal_id
                    or binding.profile_id != invocation.profile_id
                    or tuple(receipt.receipt_id for receipt in response.request_context.source_receipts)
                       != tuple(receipt.receipt_id for receipt in receipts[:-1])
                    or request_parent_ids != retained_parent_ids):
                raise AuthorityDenied("native.application.generation", "selected action generation or lineage changed")
            selection = self.action_resolver(
                invocation.bridge, invocation.producer_identity, invocation.tool_name)
            if (not isinstance(selection, NativeActionSelection)
                    or (selection.package_id, selection.profile_id, selection.generation,
                        selection.package_generation, selection.adapter_id, selection.action_id,
                        selection.registration_id, selection.operation)
                    != (invocation.package_id, invocation.profile_id, invocation.generation,
                        invocation.package_generation, invocation.adapter_id, invocation.action_id,
                        invocation.registration_id, invocation.operation)
                    or not self._validate_selection(selection, canonical_arguments)):
                raise AuthorityDenied("native.application.action", "root-selected action schema changed")
            now = self.monotonic()
            expires = min(invocation.expires_monotonic, response.expires_monotonic,
                          *(receipt.monotonic_expires_at for receipt in receipts))
            if expires <= now:
                raise AuthorityDenied("native.application.expired", "selected action evidence expired")
            turn_registry = self._native_turn_registry
            if turn_registry is None:
                raise AuthorityDenied("native.application.turn", "root selected-turn registry is unavailable")
            turn_handles = set()
            for source_handle in invocation.receipt_handles:
                try:
                    turn_handles.add(turn_registry.resolve_turn_for_source(
                        source_handle, invocation.producer_identity))
                except Exception:
                    raise AuthorityDenied("native.application.turn", "selected action turn is no longer current") from None
            if turn_handles != {response.turn_handle}:
                raise AuthorityDenied("native.application.turn", "selected action turn binding changed")
            result = RootSelectedApplicationInvocation(
                schema=1,
                invocation_handle=invocation.invocation_handle,
                response_observation_handle=response.handle,
                turn_handle=response.turn_handle,
                package_id=invocation.package_id,
                profile_id=invocation.profile_id,
                profile_generation=invocation.generation,
                principal_id=binding.principal_id,
                adapter_id=invocation.adapter_id,
                action_id=invocation.action_id,
                tool_name=invocation.tool_name,
                operation=invocation.operation,
                request_sha256=request_digest,
                source_receipt_handles=invocation.receipt_handles,
                source_closure_sha256=closure_digest,
                service_generation_digest=invocation.service_generation_digest,
                native_process_identity=invocation.producer_identity,
                issued_monotonic=now,
                expires_monotonic=expires,
            )
            if invocation_handle in self._selected_application_invocations:
                raise AuthorityDenied("native.application.invocation", "selected action admission was already issued")
            self._selected_application_invocations[invocation_handle] = result
            return result

    def is_selected_application_invocation_current(
        self, selected: RootSelectedApplicationInvocation,
    ) -> bool:
        """Revalidate the exact root-issued DTO against retained live evidence."""
        if type(selected) is not RootSelectedApplicationInvocation:
            return False
        with self._lock:
            if self._closed or self._selected_application_invocations.get(
                    selected.invocation_handle) is not selected:
                return False
            invocation = self._invocations.get(selected.invocation_handle)
            response = self._responses.get(invocation.response_handle) if invocation else None
            if (invocation is None or response is None
                    or self.monotonic() >= selected.expires_monotonic
                    or response.handle != selected.response_observation_handle
                    or response.turn_handle != selected.turn_handle
                    or selected.service_generation_digest != self.service.service_generation_digest):
                return False
            if not self._native_mcp_peer_current(
                    invocation, invocation.producer_identity.kernel_uid,
                    invocation.producer_pid, invocation.producer_pidfd,
                    invocation.canonical_arguments):
                return False
            binding = self.service._binding(invocation.producer_identity.kernel_uid)
            try:
                self.service._verify_context_signature(response.request_context)
                self.service._verify_grant_signature(response.authorization)
                self.service._assert_current_context(
                    response.request_context, binding, invocation.producer_identity.kernel_uid,
                    peer_pid=invocation.producer_pid)
                turn_registry = self._native_turn_registry
                if turn_registry is None:
                    return False
                turn_handles = {
                    turn_registry.resolve_turn_for_source(handle, invocation.producer_identity)
                    for handle in invocation.receipt_handles
                }
                if turn_handles != {selected.turn_handle}:
                    return False
            except Exception:
                return False
            with self.service._lock:
                receipts = [self.service._source_receipt_handles.get(handle)
                            for handle in selected.source_receipt_handles]
            if (not receipts or any(
                    receipt is None or receipt.monotonic_expires_at <= self.monotonic()
                    or receipt.profile_id != selected.profile_id
                    or receipt.process_generation != selected.profile_generation
                    for receipt in receipts)):
                return False
            try:
                return (canonical_digest(sorted(receipt.receipt_id for receipt in receipts))
                        == selected.source_closure_sha256
                        and hashlib.sha256(invocation.canonical_arguments).hexdigest()
                        == selected.request_sha256)
            except Exception:
                return False

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for response in self._responses.values():
                os.close(response.producer_pidfd)
                os.close(response.gateway_pidfd)
            for invocation in self._invocations.values():
                os.close(invocation.producer_pidfd)
                os.close(invocation.gateway_pidfd)
                invocation.canonical_arguments = b"\x00" * len(invocation.canonical_arguments)
            for invocation in getattr(self, "_owner_overlay_invocations", {}).values():
                for descriptor in (invocation.producer_pidfd, invocation.gateway_pidfd):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                invocation.canonical_arguments = b"\x00" * len(invocation.canonical_arguments)
                active = getattr(self.service, "active_owner_overlay_registry", None)
                retire = getattr(active, "_retire", None)
                if callable(retire):
                    retire(invocation.source_observer.selection.selection_handle)
            getattr(self, "_owner_overlay_invocations", {}).clear()
            getattr(self, "_owner_overlay_consumed", set()).clear()
            self._responses.clear()
            self._retained_response_bytes = 0
            self._deliveries.clear()
            self._calls.clear()
            self._invocations.clear()
            self._selected_application_invocations.clear()
            self._mcp_dispatches.clear()
            self._issued_handles.clear()

    def _loaded_proof(self, observer_id: str, identity: Any, peer_pid: int,
                      peer_pidfd: int) -> Any:
        observer = self.source_observers.observers.get(observer_id)
        if observer is None:
            raise AuthorityDenied("native.invocation.package", "provider observer enrollment was retired")
        package, _adapter = self.source_observers._resolve_package_role(observer)
        try:
            proof = self.source_observers._resolve_loaded_package_proof(
                identity, observer, package, self.monotonic(),
                peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            )
        except Exception:
            raise AuthorityDenied("native.invocation.package", "live loaded-package proof is unavailable") from None
        if proof is None:
            raise AuthorityDenied("native.invocation.package", "live loaded-package proof is unavailable")
        return proof

    def _prune_locked(self, now: float) -> None:
        for handle, response in tuple(self._responses.items()):
            if response.expires_monotonic <= now:
                self._responses.pop(handle, None)
                self._deliveries.pop(response.delivery_handle, None)
                self._retained_response_bytes = max(
                    0, self._retained_response_bytes - len(response.response_bytes))
                for call_handle in response.calls:
                    self._calls.pop(call_handle, None)
                try:
                    os.close(response.producer_pidfd)
                    os.close(response.gateway_pidfd)
                except OSError:
                    pass
        for handle, invocation in tuple(self._invocations.items()):
            if invocation.expires_monotonic <= now:
                self._invocations.pop(handle, None)
                self._selected_application_invocations.pop(handle, None)
                self._mcp_dispatches.pop(handle, None)
                try:
                    os.close(invocation.producer_pidfd)
                    os.close(invocation.gateway_pidfd)
                except OSError:
                    pass
                invocation.canonical_arguments = b"\x00" * len(invocation.canonical_arguments)
        for handle, invocation in tuple(getattr(self, "_owner_overlay_invocations", {}).items()):
            if invocation.expires_monotonic <= now:
                getattr(self, "_owner_overlay_invocations", {}).pop(handle, None)
                getattr(self, "_owner_overlay_consumed", set()).discard(handle)
                for descriptor in (invocation.producer_pidfd, invocation.gateway_pidfd):
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                invocation.canonical_arguments = b"\x00" * len(invocation.canonical_arguments)
                active = getattr(self.service, "active_owner_overlay_registry", None)
                retire = getattr(active, "_retire", None)
                if callable(retire):
                    retire(invocation.source_observer.selection.selection_handle)

    def _ensure_open(self) -> None:
        if self._closed:
            raise AuthorityDenied("native.invocation.closed", "native invocation registry is retired")

    @staticmethod
    def _valid_handle(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value) is not None

    @staticmethod
    def _valid_delivery_handle(value: Any) -> bool:
        return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", value) is not None

    _valid_bridge_handle = _valid_delivery_handle

    def _opaque_handle(self) -> str:
        for _ in range(8):
            handle = secrets.token_urlsafe(32)
            if handle not in self._issued_handles:
                return handle
        raise AuthorityDenied("native.invocation.capacity", "could not issue a unique invocation handle")

    @staticmethod
    def _require_observed_registrations(observer: Any, loaded_proof: Any) -> frozenset[str]:
        observed = getattr(loaded_proof, "observed_registration_ids", None)
        source = getattr(observer, "source_registration_ids", None)
        if (not isinstance(observed, (tuple, frozenset, set)) or not observed
                or len(observed) > 256
                or any(not isinstance(item, str) or not item for item in observed)
                or len(set(observed)) != len(observed)):
            raise AuthorityDenied(
                "native.invocation.package", "loaded proof has no authenticated registration closure",
            )
        if (not isinstance(source, tuple) or not source or len(source) > 128
                or len(set(source)) != len(source)
                or any(not isinstance(item, str) or not item for item in source)
                or not set(source).issubset(set(observed))):
            raise AuthorityDenied(
                "native.invocation.package", "loaded role does not contain the selected source registrations",
            )
        return frozenset(observed)

    @staticmethod
    def _selected_action_registration_ids(*, observer: Any, package: Any,
                                          selection: NativeActionSelection) -> tuple[str, ...]:
        """Resolve the selected action through its current role and registration FKs.

        Loader proofs authenticate registration IDs, not action IDs. This join
        deliberately begins with the exact selected adapter/action record,
        requires its action binding in the selected process role, and then
        resolves the unique role-owned registration that exposes that binding.
        """
        from collections.abc import Mapping as MappingABC

        actions = getattr(package, "action_records", None)
        roles = getattr(package, "process_role_records", None)
        registrations = getattr(package, "registration_records", None)
        workflows = getattr(package, "workflow_records", None)
        if not all(isinstance(value, MappingABC)
                   for value in (actions, roles, registrations, workflows)):
            raise AuthorityDenied("native.invocation.action", "protected action registration catalogs are unavailable")
        package_id = getattr(package, "package_id", None)
        package_generation = getattr(package, "generation", None)
        process_generation = getattr(package, "profile_generation", None)
        observer_id = getattr(observer, "observer_enrollment_id", None)
        role = roles.get(getattr(observer, "role_id", None))
        if (not isinstance(package_id, str) or not isinstance(package_generation, str)
                or not isinstance(process_generation, str) or role is None
                or selection.package_generation != package_generation
                or selection.generation != process_generation
                or getattr(observer, "package_id", None) != package_id
                or getattr(observer, "native_package_generation", None) != package_generation
                or getattr(observer, "profile_id", None) != getattr(package, "profile_id", None)
                or getattr(observer, "generation", None) != process_generation
                or getattr(role, "package_id", None) != package_id
                or getattr(role, "native_package_generation", None) != package_generation
                or getattr(role, "profile_id", None) != getattr(package, "profile_id", None)
                or getattr(role, "profile_generation", None) != process_generation
                or observer_id not in getattr(role, "observer_enrollment_ids", ())):
            raise AuthorityDenied("native.invocation.action", "selected process role is stale or foreign")

        selected_actions = [action for action in actions.values()
                            if getattr(action, "adapter_id", None) == selection.adapter_id
                            and getattr(action, "action_id", None) == selection.action_id
                            and getattr(action, "operation", None) == selection.operation
                            and getattr(action, "generation", None) == package_generation]
        if len(selected_actions) != 1:
            raise AuthorityDenied("native.invocation.action", "selected action binding is absent or ambiguous")
        action = selected_actions[0]
        binding_id = getattr(action, "action_binding_id", None)
        if (not isinstance(binding_id, str) or not binding_id
                or action not in actions.values()
                or binding_id not in getattr(role, "action_binding_ids", ())
                ):
            raise AuthorityDenied("native.invocation.action", "action is not bound to the selected process role")

        registration_id = selection.registration_id
        role_registration_ids = getattr(role, "registration_ids", ())
        if (not isinstance(role_registration_ids, (tuple, list, set, frozenset))
                or registration_id not in role_registration_ids):
            raise AuthorityDenied("native.invocation.action", "selected process role has no registrations")
        registration = registrations.get(registration_id)
        if (registration is None
                or getattr(registration, "registration_id", None) != registration_id
                or getattr(registration, "generation", None) != package_generation
                or getattr(registration, "adapter_id", None) != selection.adapter_id):
            raise AuthorityDenied("native.invocation.action", "selected registration is stale or foreign")
        exposes_binding = any(
            getattr(branch, "action_binding_id", None) == binding_id
            for branch in getattr(registration, "action_bindings", ())
        )
        for branch in getattr(registration, "action_bindings", ()):
            workflow_id = getattr(branch, "workflow_id", None)
            if workflow_id is None:
                continue
            workflow = workflows.get(workflow_id)
            if (workflow is not None
                    and getattr(workflow, "registration_id", None) == registration_id
                    and getattr(workflow, "generation", None) == package_generation
                    and binding_id in getattr(workflow, "step_action_binding_ids", ())
                    and workflow_id in getattr(role, "workflow_ids", ())):
                exposes_binding = True
        if not exposes_binding:
            raise AuthorityDenied("native.invocation.action", "selected registration does not bind the action")
        return (registration_id,)

    @staticmethod
    def _validate_selection(selection: NativeActionSelection, arguments: bytes) -> bool:
        try:
            return selection.validate_arguments(arguments) is True
        except Exception:
            return False


class NativeRuntimeObserver:
    """Root-only observer for results from registered native effects.

    Hermes' PluginManager and selected package loader run in the unprivileged
    worker. This object runs only in the root authority daemon and is called
    after the daemon validates a registered effect response.
    """

    def __init__(self, *, source_observers: Any,
                 effect_observer_ids: Mapping[tuple[str, str, str], str],
                 discovery_observer_ids: Mapping[tuple[str, str, str], str] | None = None) -> None:
        if (not callable(getattr(source_observers, "record_observed_event", None))
                or not callable(getattr(source_observers, "capture_observed_source", None))
                or not isinstance(effect_observer_ids, Mapping)
                or not effect_observer_ids):
            raise NativeRuntimeObserverUnavailable("trusted native observer inputs are incomplete")
        pairs: dict[tuple[str, str, str], str] = {}
        discovery_pairs: dict[tuple[str, str, str], str] = {}
        enrolled = getattr(source_observers, "observers", None)
        if not isinstance(enrolled, Mapping):
            raise NativeRuntimeObserverUnavailable("root source observer enrollment is unavailable")
        for key, observer_id in effect_observer_ids.items():
            if (not isinstance(key, tuple) or len(key) != 3
                    or any(not isinstance(part, str) or not part for part in key)
                    or not isinstance(observer_id, str) or observer_id not in enrolled):
                raise NativeRuntimeObserverUnavailable("effect observer mapping is malformed")
            observer = enrolled[observer_id]
            if getattr(observer, "source_kind", None) not in {"tool-result", "provider-result"}:
                raise NativeRuntimeObserverUnavailable("effect observer is not enrolled for a result channel")
            if key in pairs:
                raise NativeRuntimeObserverUnavailable("effect observer mapping is ambiguous")
            pairs[key] = observer_id
        if discovery_observer_ids is not None:
            if not isinstance(discovery_observer_ids, Mapping):
                raise NativeRuntimeObserverUnavailable("MCP discovery observer mapping is malformed")
            for key, observer_id in discovery_observer_ids.items():
                if (not isinstance(key, tuple) or len(key) != 3
                        or any(not isinstance(part, str) or not part for part in key)
                        or not isinstance(observer_id, str) or observer_id not in enrolled):
                    raise NativeRuntimeObserverUnavailable("MCP discovery observer mapping is malformed")
                source = enrolled[observer_id]
                if (getattr(source, "source_kind", None) != "tool-result"
                        or getattr(source, "capture_schema_id", None)
                        != "native-root-mcp-discovery-response-v1"
                        or getattr(source, "source_action_id", None)
                        != "root-mcp-tools-list-discovery-v1"):
                    raise NativeRuntimeObserverUnavailable(
                        "MCP discovery observer does not match the finite discovery profile",
                    )
                if key in discovery_pairs:
                    raise NativeRuntimeObserverUnavailable("MCP discovery observer mapping is ambiguous")
                discovery_pairs[key] = observer_id
        self.source_observers = source_observers
        self.effect_observer_ids = pairs
        self.discovery_observer_ids = discovery_pairs
        self.invocation_registry: Any | None = None
        self.native_turn_observation_registry: Any | None = None
        self._lock = threading.RLock()
        self._mcp_discovery_requests: dict[tuple[str, int, str], _RetainedMCPDiscoveryRequest] = {}
        # Only receipts minted by the actual tools/list observer may extend a
        # selected invocation's original provider-response ancestry.
        # Values are the genuine root source handles and their effective
        # monotonic deadlines. Keeping the deadline here lets pruning follow
        # both the selected invocation and the captured source receipt.
        self._mcp_discovery_receipts: dict[str, dict[str, float]] = {}
        self._closed = False

    def register_mcp_discovery_request(
            self, *, invocation: Any, service: Any, binding: Any,
            context: HostContext, authorization: Any, operation: str, target: str,
            request_payload: bytes, peer_uid: int, peer_pid: int, peer_pidfd: int,
            selection: Mapping[str, str], parent_receipt_handles: tuple[str, ...],
            cancelled: Callable[[], bool] = lambda: False) -> None:
        """Retain the actual root-created tools/list request before effect dispatch.

        A purpose string by itself cannot select this path: the canonical method,
        selected MCP invocation, signed request context/grant and live loaded
        source role must all join before the request is retained.
        """
        from ..mcp.broker import mcp_intent
        from ..mcp.broker import ProtectedMCPService
        from ..mcp.native_dispatch import NativeMCPToolBinding
        from .types import EffectAuthorization

        if (type(invocation) is not RootNativeMCPInvocation
                or type(service) is not ProtectedMCPService
                or type(binding) is not NativeMCPToolBinding
                or type(context) is not HostContext
                or type(authorization) is not EffectAuthorization
                or operation != "mcp.request" or target != f"mcp:{service.service_id}:http"
                or not isinstance(request_payload, bytes) or not 1 <= len(request_payload) <= _MAX_RESULT_BYTES
                or type(peer_uid) is not int or peer_uid <= 0
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not isinstance(selection, Mapping)
                or not isinstance(parent_receipt_handles, tuple)
                or not callable(cancelled) or cancelled()):
            raise AuthorityDenied("mcp.discovery.request", "root selected discovery request is malformed")
        envelope = _strict_native_json(request_payload)
        expected_selection = {field: resource for field, resource in binding.scope_bindings}
        if (not isinstance(envelope, Mapping) or canonical_bytes(envelope) != request_payload
                or set(envelope) != {"schema", "service_id", "request_id", "method", "selection", "params"}
                or envelope.get("schema") != 1 or envelope.get("service_id") != service.service_id
                or envelope.get("method") != "tools/list"
                or not isinstance(envelope.get("request_id"), str)
                or not 1 <= len(envelope["request_id"]) <= 128
                or dict(selection) != expected_selection or envelope.get("selection") != expected_selection
                or not isinstance(envelope.get("params"), Mapping)
                or (set(envelope["params"]) - {"cursor"})
                or ("cursor" in envelope["params"] and
                    (not isinstance(envelope["params"]["cursor"], str)
                     or not 1 <= len(envelope["params"]["cursor"]) <= 1024))):
            raise AuthorityDenied("mcp.discovery.request", "actual tools/list request does not match its selected binding")
        digest = canonical_digest(request_payload)
        intent = mcp_intent(service.service_id, service.channel, envelope["request_id"],
                            "tools/list", expected_selection, envelope["params"])
        expected_intent = canonical_digest({"purpose": "mcp-selected-schema-discovery", "intent": intent})
        if (context.purpose != "mcp-selected-schema-discovery"
                or context.intent_id != expected_intent or authorization.intent_id != expected_intent
                or authorization.request_digest != digest
                or authorization.final_payload_digest != digest
                or context.final_payload_digest != digest
                or authorization.operation != operation or authorization.target != target
                or authorization.capability != f"mcp:{service.service_id}:read"
                or authorization.uid != peer_uid or context.uid != peer_uid
                or authorization.profile_id != invocation.profile_id
                or context.profile_id != invocation.profile_id
                or authorization.generation != invocation.generation
                or context.generation != invocation.generation
                or authorization.source_receipts != context.source_receipts
                or tuple(parent_receipt_handles) != invocation.source_receipt_handles):
            raise AuthorityDenied("mcp.discovery.request", "tools/list context or effect grant is not the selected root request")
        now = self.source_observers.service.monotonic()
        observer_id = self.discovery_observer_ids.get((authorization.capability, operation, target))
        observer = self.source_observers.observers.get(observer_id) if observer_id else None
        if (observer is None or observer.source_kind != "tool-result"
                or observer.capture_schema_id != "native-root-mcp-discovery-response-v1"
                or observer.source_action_id != "root-mcp-tools-list-discovery-v1"
                or observer.profile_id != invocation.profile_id
                or observer.generation != invocation.generation
                or observer.producer_uid != peer_uid
                or getattr(binding, "native_package_id", None) != observer.package_id
                or getattr(binding, "native_package_generation", None)
                   != observer.native_package_generation):
            raise AuthorityDenied("mcp.discovery.observer", "selected MCP discovery source role is unavailable")
        if (invocation.adapter_id != binding.handler_artifact_id or invocation.action_id != binding.id
                or invocation.package_id != observer.package_id
                or invocation.profile_id != observer.profile_id
                or invocation.generation != observer.generation):
            raise AuthorityDenied("mcp.discovery.binding", "selected MCP action and discovery source role differ")
        service_authority = self.source_observers.service
        invocation_registry = getattr(service_authority, "native_invocation_registry", None)
        if (invocation_registry is None
                or not callable(getattr(invocation_registry, "is_current_native_mcp_invocation", None))
                or invocation_registry.is_current_native_mcp_invocation(
                    invocation, peer_uid, peer_pid, peer_pidfd) is not True):
            raise AuthorityDenied("mcp.discovery.invocation", "selected root MCP invocation is not current")
        service_authority._verify_context_signature(context)
        service_authority._verify_grant_signature(authorization)
        service_authority._assert_current_context(context, service_authority._binding(peer_uid), peer_uid,
                                                  peer_pid=peer_pid)
        service_authority._assert_grant_current(authorization, service_authority._binding(peer_uid), peer_uid)
        identity = self.source_observers._resolve(observer, peer_pid, peer_pidfd)
        package, _role = self.source_observers._resolve_package_role(observer)
        proof = self.source_observers._resolve_loaded_package_proof(
            identity, observer, package, now, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        observed = getattr(proof, "observed_registration_ids", ())
        if (getattr(package, "package_id", None) != invocation.package_id
                or getattr(package, "generation", None) != binding.native_package_generation
                or not set(getattr(observer, "source_registration_ids", ())).issubset(set(observed))):
            raise AuthorityDenied("mcp.discovery.package", "current loaded discovery source role is not proven")
        if cancelled():
            raise AuthorityDenied("mcp.discovery.cancelled", "MCP discovery was cancelled before retention")
        key = (authorization.grant_id, peer_pid, digest)
        record = _RetainedMCPDiscoveryRequest(
            invocation, service, binding, observer_id, context, authorization,
            peer_uid, peer_pid, peer_pidfd, operation, target, bytes(request_payload), digest,
            tuple(parent_receipt_handles), MappingProxyType(dict(selection)),
            min(context.monotonic_expires_at, authorization.monotonic_expires_at,
                now + observer.lease_seconds, invocation.expires_monotonic),
        )
        with self._lock:
            self._prune_mcp_discovery_state_locked(now)
            if self._closed or key in self._mcp_discovery_requests:
                raise AuthorityDenied("mcp.discovery.replay", "tools/list request is already retained or observer is closed")
            if len(self._mcp_discovery_requests) >= _MAX_RETAINED_MCP_DISCOVERY_REQUESTS:
                raise AuthorityDenied("mcp.discovery.capacity", "retained tools/list request capacity is full")
            self._mcp_discovery_requests[key] = record

    def attach_turn_observation(self, *, invocation_registry: Any,
                                native_turn_observation_registry: Any) -> None:
        """Attach the root invocation and turn registries exactly once."""
        from .native_turn_observation import RootNativeTurnObservationRegistry
        if (not callable(getattr(invocation_registry, "resolve_invocation_for_effect", None))
                or type(native_turn_observation_registry) is not RootNativeTurnObservationRegistry
                or getattr(invocation_registry, "service", None) is not getattr(
                    native_turn_observation_registry, "service", None)
                or getattr(invocation_registry, "source_observers", None) is not self.source_observers):
            raise AuthorityDenied("native.turn.attach", "selected root turn effect bindings are incompatible")
        with self._lock:
            if self.invocation_registry is not None or self.native_turn_observation_registry is not None:
                raise AuthorityDenied("native.turn.attach", "root turn effect bindings are already attached")
            self.invocation_registry = invocation_registry
            self.native_turn_observation_registry = native_turn_observation_registry

    def observe_effect_result(self, *, service: Any, context: HostContext,
                              authorization: Any, operation: str, target: str,
                              response_status: int, result_payload: bytes, peer_pid: int,
                              peer_pidfd: int,
                              request_payload: bytes | None = None,
                              request_sha256: str | None = None,
                              cancelled: Callable[[], bool] = lambda: False) -> str:
        """Issue a receipt for exact result bytes after a root-validated effect.

        ``authorization`` and the successful result must come from the
        authority's already validated effect path. This method repeats the
        relevant joins so accidental early or cross-target callsites fail
        closed. The returned opaque handle is for peer-bound receipt delivery;
        it carries no independent effect authority.
        """
        if (not isinstance(context, HostContext)
                or not isinstance(result_payload, bytes)
                or not 1 <= len(result_payload) <= _MAX_RESULT_BYTES
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or type(response_status) is not int or not 200 <= response_status < 300
                or (request_payload is not None and not isinstance(request_payload, bytes))
                or (request_sha256 is not None and not _SHA256.fullmatch(request_sha256))
                or not callable(cancelled)):
            raise AuthorityDenied("source.observation", "completed successful native result is malformed")
        capability = getattr(authorization, "capability", None)
        granted_operation = getattr(authorization, "operation", None)
        granted_target = getattr(authorization, "target", None)
        if (granted_operation != operation or granted_target != target
                or not isinstance(capability, str)
                or getattr(authorization, "profile_id", None) != context.profile_id
                or getattr(authorization, "principal_id", None) != context.principal_id
                or getattr(authorization, "uid", None) != context.uid
                or getattr(authorization, "generation", None) != context.generation
                or getattr(authorization, "native_process_identity", None) != context.native_process_identity
                or getattr(authorization, "source_receipts", None) != context.source_receipts):
            raise AuthorityDenied("source.binding", "result does not match the completed enrolled effect")
        # tools/list is a bounded discovery witness, not a selected tool call.
        # Its classification is accepted only when the exact root-retained
        # canonical request is method=tools/list and its signed purpose/grant,
        # peer and selected discovery role all match.
        if context.purpose == "mcp-selected-schema-discovery":
            return self.observe_mcp_discovery_result(
                service=service, context=context, authorization=authorization,
                operation=operation, target=target, request_payload=request_payload,
                request_sha256=request_sha256, response_status=response_status,
                result_payload=result_payload, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cancelled=cancelled,
            )
        with self._lock:
            turn_registry = self.native_turn_observation_registry
        service_authority = getattr(self.source_observers, "service", None)
        invocation_registry = getattr(
            service_authority, "native_invocation_registry", self.invocation_registry,
        )
        invocation = None
        if invocation_registry is not None or turn_registry is not None:
            if (invocation_registry is None
                    or request_payload is None or request_sha256 is None
                    or hashlib.sha256(request_payload).hexdigest() != request_sha256
                    or request_sha256 != getattr(authorization, "request_digest", None)):
                raise AuthorityDenied("native.effect", "validated native action bytes are unavailable")
            invocation = invocation_registry.resolve_invocation_for_effect(
                context, authorization, operation, request_sha256)
            if (type(invocation) is not RootNativeToolEffectInvocation
                    or invocation.operation != operation
                    or invocation.request_digest != request_sha256
                    or invocation.producer_pid != peer_pid
                    or getattr(invocation.producer_identity, "kernel_uid", None) != context.uid
                    or getattr(invocation.producer_identity, "profile_id", None) != context.profile_id
                    or getattr(invocation.producer_identity, "generation", None) != context.generation
                    or invocation.profile_id != context.profile_id
                    or invocation.generation != context.generation
                    or invocation.service_generation_digest != getattr(
                        service, "service_generation_digest", None)
                    or (invocation.turn_handle is not None and turn_registry is None)
                    or invocation.expires_monotonic <= time.monotonic()):
                raise AuthorityDenied("native.effect", "validated effect does not join a current observed call")
        observer_id = self.effect_observer_ids.get((capability, operation, target))
        observer = self.source_observers.observers.get(observer_id) if observer_id else None
        if (observer is None or getattr(observer, "source_kind", None) != "tool-result"
                or getattr(observer, "profile_id", None) != context.profile_id
                or getattr(observer, "generation", None) != context.generation
                or getattr(observer, "producer_uid", None) != context.uid):
            raise AuthorityDenied("source.observer", "completed effect has no matching root observer enrollment")
        if (invocation is None or invocation_registry is None
                or (invocation.turn_handle is not None and turn_registry is None)
                or getattr(observer, "capture_schema_id", None)
                != "native-registered-tool-result-v1"):
            raise AuthorityDenied(
                "native.effect.result", "root selected tool result schema/profile is unavailable",
            )
        validate_result = getattr(invocation_registry, "validate_effect_result", None)
        if not callable(validate_result):
            raise AuthorityDenied(
                "native.effect.result", "root selected result-schema validator is unavailable",
            )
        schema_payload = result_payload
        if invocation.operation == "mcp.request":
            schema_payload = self._mcp_tool_result_schema_payload(
                invocation, request_payload, result_payload,
            )
        validate_result(invocation, schema_payload, observer_id=observer_id)
        if cancelled():
            raise AuthorityDenied("source.cancelled", "native result delivery was cancelled")
        parent_handles = self._parent_handles(service, context)
        event_id = self.source_observers.record_observed_event(
            observer_id, payload_bytes=result_payload, parent_context=context,
            peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            parent_receipt_handles=parent_handles,
        )
        if cancelled():
            raise AuthorityDenied("source.cancelled", "native result was cancelled before receipt issue")
        receipt_handle = self.source_observers.capture_observed_source(
            observer_id, event_id, result_payload, parent_receipt_handles=parent_handles)
        if not isinstance(receipt_handle, str) or len(receipt_handle) < 32:
            raise AuthorityDenied("source.issuer", "root observer returned no opaque result handle")
        if cancelled():
            self.source_observers.revoke_source_handle(receipt_handle)
            raise AuthorityDenied("source.cancelled", "native result was cancelled before turn binding")
        if invocation.turn_handle is not None:
            try:
                turn_registry.record_tool_result(
                    invocation.turn_handle, str(receipt_handle),
                    live_producer_identity=invocation.producer_identity,
                    observed_call_handle=invocation.observed_call_handle,
                )
            except Exception:
                self.source_observers.revoke_source_handle(receipt_handle)
                raise AuthorityDenied("native.turn.result", "root result could not join the selected turn") from None
        return str(receipt_handle)

    def _mcp_tool_result_schema_payload(
            self, invocation: Any, request_payload: bytes | None,
            result_payload: bytes) -> bytes:
        """Validate MCP's root protocol envelope, then return exact result JSON.

        The source receipt still captures the unchanged full transport entity.
        Only the schema validator sees the selected tool's result value.
        """
        if not isinstance(request_payload, bytes):
            raise AuthorityDenied("native.effect.result", "MCP tool request bytes are unavailable")
        request = _strict_native_json(request_payload)
        response = _strict_native_json(result_payload)
        dispatcher = getattr(self.source_observers.service, "native_mcp_dispatcher", None)
        registration_index = getattr(dispatcher, "_registrations", None)
        try:
            binding = registration_index.resolve_action(invocation.action_id)
            selection = {field: resource for field, resource in binding.scope_bindings}
            params = request["params"]
            arguments = canonical_bytes(params["arguments"])
        except Exception:
            raise AuthorityDenied("native.effect.result", "selected MCP request binding is unavailable") from None
        if (not isinstance(request, Mapping) or canonical_bytes(request) != request_payload
                or set(request) != {"schema", "service_id", "request_id", "method", "selection", "params"}
                or request.get("schema") != 1 or request.get("method") != "tools/call"
                or request.get("service_id") != binding.native_server_name
                or request.get("selection") != selection
                or not isinstance(request.get("request_id"), str)
                or not isinstance(params, Mapping)
                or set(params) != {"name", "arguments"}
                or params.get("name") != binding.mcp_tool_name
                or not isinstance(response, Mapping)
                or canonical_bytes(response) != result_payload
                or set(response) != {"jsonrpc", "id", "result"}
                or response.get("jsonrpc") != "2.0"
                or response.get("id") != request.get("request_id")
                or not isinstance(response.get("result"), Mapping)
                or response["result"].get("isError") is True
                or hashlib.sha256(arguments).hexdigest() != invocation.arguments_sha256):
            raise AuthorityDenied("native.effect.result", "MCP result is not bound to the selected tools/call")
        return canonical_bytes(response["result"])

    def observe_mcp_discovery_result(
            self, *, service: Any, context: HostContext, authorization: Any,
            operation: str, target: str, request_payload: bytes | None,
            request_sha256: str | None, response_status: int, result_payload: bytes,
            peer_pid: int, peer_pidfd: int,
            cancelled: Callable[[], bool] = lambda: False) -> str:
        """Capture only a previously retained, exact MCP tools/list exchange.

        The source event is metadata from discovery, never a claim that a
        selected MCP tool ran. The separate tools/call path continues through
        ``validate_effect_result`` and the selected result-schema FK.
        """
        from .types import EffectAuthorization

        if (service is not self.source_observers.service
                or type(context) is not HostContext or type(authorization) is not EffectAuthorization
                or operation != "mcp.request"
                or request_payload is None or not isinstance(request_payload, bytes)
                or not isinstance(request_sha256, str)
                or canonical_digest(request_payload) != request_sha256
                or not isinstance(result_payload, bytes) or not 1 <= len(result_payload) <= _MAX_RESULT_BYTES
                or type(response_status) is not int or not 200 <= response_status < 300
                or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or not callable(cancelled) or cancelled()):
            raise AuthorityDenied("mcp.discovery.result", "root tools/list result is malformed or expired")
        request = _strict_native_json(request_payload)
        if (not isinstance(request, Mapping) or canonical_bytes(request) != request_payload
                or request.get("method") != "tools/list"):
            raise AuthorityDenied("mcp.discovery.request", "discovery source is not an actual tools/list request")
        key = (authorization.grant_id, peer_pid, request_sha256)
        with self._lock:
            self._prune_mcp_discovery_state_locked(self.source_observers.service.monotonic())
            record = self._mcp_discovery_requests.pop(key, None)
            closed = self._closed
        if (closed or record is None
                or not self._mcp_discovery_context_matches(record, context, authorization)
                or record.authorization != authorization or record.request_payload != request_payload
                or record.service.service_id != target.split(":")[1]
                or record.operation != operation
                or record.target != target or record.peer_uid != context.uid
                or record.peer_pid != peer_pid or record.peer_pidfd != peer_pidfd
                or record.expires_monotonic <= self.source_observers.service.monotonic()
                or record.invocation.expires_monotonic <= self.source_observers.service.monotonic()
                or record.request_sha256 != request_sha256):
            raise AuthorityDenied("mcp.discovery.request", "no current retained root tools/list request matches")
        with self._lock:
            invocation_registry = self.invocation_registry
        service_authority = self.source_observers.service
        if invocation_registry is None:
            invocation_registry = getattr(service_authority, "native_invocation_registry", None)
        current_ok = (invocation_registry.is_current_native_mcp_invocation(
            record.invocation, record.peer_uid, peer_pid, peer_pidfd)
            if invocation_registry is not None else False)
        if not current_ok:
            raise AuthorityDenied("mcp.discovery.invocation", "selected root MCP invocation changed before result")
        self._validate_mcp_discovery_response(request, result_payload)
        observer = self.source_observers.observers.get(record.observer_id)
        if (observer is None or observer.source_kind != "tool-result"
                or observer.capture_schema_id != "native-root-mcp-discovery-response-v1"
                or observer.source_action_id != "root-mcp-tools-list-discovery-v1"
                or observer.profile_id != context.profile_id
                or observer.generation != context.generation
                or observer.producer_uid != context.uid):
            raise AuthorityDenied("mcp.discovery.observer", "finite root MCP discovery profile changed")
        service_authority = self.source_observers.service
        # _perform_effect reconstructs a grant-bound internal context whose
        # sentinel signature is intentionally not a wire signature. Verify the
        # exact originally signed context retained at request admission.
        service_authority._verify_context_signature(record.context)
        service_authority._verify_grant_signature(authorization)
        service_authority._assert_current_context(context, service_authority._binding(context.uid),
                                                  context.uid, peer_pid=peer_pid)
        service_authority._assert_grant_current(authorization, service_authority._binding(context.uid),
                                                context.uid)
        identity = self.source_observers._resolve(observer, peer_pid, peer_pidfd)
        package, _action = self.source_observers._resolve_package_role(observer)
        proof = self.source_observers._resolve_loaded_package_proof(
            identity, observer, package, service_authority.monotonic(),
            peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        observed = getattr(proof, "observed_registration_ids", ())
        if (identity != record.invocation.native_process_identity
                or getattr(package, "package_id", None) != record.invocation.package_id
                or getattr(package, "generation", None) != record.binding.native_package_generation
                or getattr(package, "profile_generation", None) != record.invocation.generation
                or not set(getattr(observer, "source_registration_ids", ())).issubset(set(observed))):
            raise AuthorityDenied("mcp.discovery.package", "loaded MCP discovery source role is no longer current")
        if cancelled():
            raise AuthorityDenied("mcp.discovery.cancelled", "MCP discovery was cancelled before capture")
        event_id = self.source_observers.record_observed_event(
            record.observer_id, payload_bytes=result_payload, parent_context=context,
            peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            parent_receipt_handles=record.parent_handles,
        )
        if cancelled():
            raise AuthorityDenied("mcp.discovery.cancelled", "MCP discovery was cancelled before receipt issue")
        handle = self.source_observers.capture_observed_source(
            record.observer_id, event_id, result_payload,
            parent_receipt_handles=record.parent_handles,
        )
        if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
            raise AuthorityDenied("mcp.discovery.issuer", "root discovery observer returned no source handle")
        if cancelled():
            self.source_observers.revoke_source_handle(handle)
            raise AuthorityDenied("mcp.discovery.cancelled", "MCP discovery was cancelled before delivery")
        service = self.source_observers.service
        now = service.monotonic()
        with service._lock:
            captured_receipt = service._source_receipt_handles.get(handle)
            receipt_deadline = getattr(captured_receipt, "monotonic_expires_at", None)
        if (type(receipt_deadline) not in (int, float)
                or not math.isfinite(receipt_deadline) or receipt_deadline <= now):
            self.source_observers.revoke_source_handle(handle)
            raise AuthorityDenied("mcp.discovery.receipt", "captured discovery receipt is unavailable or expired")
        retention_deadline = min(record.invocation.expires_monotonic, receipt_deadline)
        self._retain_mcp_discovery_receipt(
            record.invocation.invocation_handle, handle, retention_deadline, now,
        )
        return handle

    def _retain_mcp_discovery_receipt(self, invocation_handle: str, handle: str,
                                      retention_deadline: float, now: float) -> None:
        """Admit a captured handle without evicting any still-live ancestry."""
        with self._lock:
            self._prune_mcp_discovery_state_locked(now)
            receipts = self._mcp_discovery_receipts.get(invocation_handle)
            total_receipts = sum(len(items) for items in self._mcp_discovery_receipts.values())
            if (self._closed or retention_deadline <= now or handle in (receipts or {})
                    or len(receipts or {}) >= 32
                    or (receipts is None and len(self._mcp_discovery_receipts)
                        >= _MAX_RETAINED_MCP_DISCOVERY_INVOCATIONS)
                    or total_receipts >= _MAX_RETAINED_MCP_DISCOVERY_RECEIPTS):
                admitted = False
            else:
                if receipts is None:
                    receipts = {}
                    self._mcp_discovery_receipts[invocation_handle] = receipts
                receipts[handle] = retention_deadline
                admitted = True
        if not admitted:
            self.source_observers.revoke_source_handle(handle)
            raise AuthorityDenied("mcp.discovery.capacity", "discovery receipt retention is expired or at capacity")

    def _prune_mcp_discovery_state_locked(self, now: float) -> None:
        """Drop only expired request/capture lineage; live entries are never evicted."""
        for key, record in tuple(self._mcp_discovery_requests.items()):
            if (record.expires_monotonic <= now
                    or record.invocation.expires_monotonic <= now):
                del self._mcp_discovery_requests[key]
        for invocation_handle, receipts in tuple(self._mcp_discovery_receipts.items()):
            for handle, deadline in tuple(receipts.items()):
                if deadline <= now:
                    del receipts[handle]
            if not receipts:
                del self._mcp_discovery_receipts[invocation_handle]

    def _mcp_discovery_context_matches(self, record: _RetainedMCPDiscoveryRequest,
                                       context: HostContext, authorization: Any) -> bool:
        """Join the retained signed context to the service's grant-derived view."""
        original = record.context
        service = self.source_observers.service
        original_context_digest = canonical_digest({
            **original.claims(), "signature": original.signature,
        })
        if (original_context_digest != authorization.context_digest
                or original.source_receipts != authorization.source_receipts
                or context.source_receipts != authorization.source_receipts):
            return False
        fields = (
            ("principal_id", authorization.principal_id),
            ("profile_id", authorization.profile_id),
            ("namespace_id", authorization.namespace_id),
            ("uid", authorization.uid), ("purpose", authorization.purpose),
            ("intent_id", authorization.intent_id), ("trace_id", authorization.trace_id),
            ("sensitivity", authorization.sensitivity),
            ("lineage_hash", authorization.lineage_hash),
            ("policy_revision", authorization.policy_revision),
            ("final_payload_digest", authorization.final_payload_digest),
            ("enrollment_id", authorization.enrollment_id),
            ("generation", authorization.generation), ("operation", authorization.operation),
            ("native_process_identity", authorization.native_process_identity),
        )
        return all(getattr(original, name, None) == expected
                   and getattr(context, name, None) == expected for name, expected in fields)

    @staticmethod
    def _validate_mcp_discovery_response(request: Mapping[str, Any], raw: bytes) -> None:
        if len(raw) > _MAX_RESULT_BYTES:
            raise AuthorityDenied("mcp.discovery.bounds", "MCP discovery response exceeds its finite profile")
        response = _strict_native_json(raw)
        request_id = request.get("request_id")
        if (not isinstance(response, Mapping) or canonical_bytes(response) != raw
                or set(response) != {"jsonrpc", "id", "result"}
                or response.get("jsonrpc") != "2.0" or response.get("id") != request_id
                or not isinstance(response.get("result"), Mapping)
                or set(response["result"]) - {"tools", "nextCursor"}
                or not isinstance(response["result"].get("tools"), list)
                or len(response["result"]["tools"]) > 256):
            raise AuthorityDenied("mcp.discovery.response", "MCP discovery response envelope is invalid")
        tools = response["result"]["tools"]
        seen: set[str] = set()
        from ..mcp.native_schema_catalog import _validate_schema
        for row in tools:
            if (not isinstance(row, Mapping)
                    or set(row) - {"name", "inputSchema", "outputSchema", "annotations"}
                    or not isinstance(row.get("name"), str) or not 1 <= len(row["name"]) <= 128
                    or row["name"] in seen or not isinstance(row.get("inputSchema"), Mapping)
                    or not isinstance(row.get("annotations", {}), Mapping)
                    or len(canonical_bytes(dict(row))) > 262_144):
                raise AuthorityDenied("mcp.discovery.schema", "MCP discovery tool metadata is malformed")
            seen.add(row["name"])
            try:
                _validate_schema(row["inputSchema"], nodes=[0])
                if "outputSchema" in row:
                    _validate_schema(row["outputSchema"], nodes=[0])
            except Exception:
                raise AuthorityDenied("mcp.discovery.schema", "MCP discovery schema is unsupported") from None
        cursor = response["result"].get("nextCursor")
        if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 1024):
            raise AuthorityDenied("mcp.discovery.cursor", "MCP discovery cursor is invalid")

    def close(self) -> None:
        """Stop new observations when the selected package generation is retired."""
        with self._lock:
            self._closed = True
            self._mcp_discovery_requests.clear()
            self._mcp_discovery_receipts.clear()

    def _parent_handles(self, service: Any, context: HostContext) -> tuple[str, ...]:
        with self._lock:
            if self._closed:
                raise AuthorityDenied("source.closed", "selected native runtime generation is retired")
        handles = getattr(service, "_source_receipt_handles", None)
        if not isinstance(handles, Mapping):
            if context.source_receipts:
                raise AuthorityDenied("source.lineage", "root parent receipt index is unavailable")
            return ()
        by_id = {receipt.receipt_id: handle for handle, receipt in handles.items()}
        selected: list[str] = []
        for receipt in context.source_receipts:
            handle = by_id.get(receipt.receipt_id)
            if not isinstance(handle, str):
                raise AuthorityDenied("source.lineage", "root parent receipt handle is unavailable")
            selected.append(handle)
        if len(selected) > _MAX_PARENT_RECEIPTS or len(selected) != len(set(selected)):
            raise AuthorityDenied("source.lineage", "root parent receipt closure is ambiguous or oversized")
        return tuple(selected)
