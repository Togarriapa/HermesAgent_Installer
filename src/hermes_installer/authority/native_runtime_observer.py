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
import hashlib
import json
import math
import re
import secrets
import time
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, HostContext, NativeToolCallBinding, SourceReceipt, canonical_digest

_MAX_RESULT_BYTES = 1_048_576
_MAX_PARENT_RECEIPTS = 64
_MAX_TOOL_CALLS = 128
_MAX_TOOL_ARGUMENT_BYTES = 65_536
_INVOCATION_LEASE_SECONDS = 30.0
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class NativeActionSelection:
    """Root-selected native action found by exact tool-name mapping."""

    package_id: str
    profile_id: str
    generation: str
    adapter_id: str
    action_id: str
    validate_arguments: Callable[[bytes], bool]

    def __post_init__(self) -> None:
        if (any(not isinstance(getattr(self, name), str) or not getattr(self, name)
                for name in ("package_id", "profile_id", "generation", "adapter_id", "action_id"))
                or not callable(self.validate_arguments)):
            raise ValueError("selected native action binding is incomplete")


@dataclass(frozen=True, slots=True)
class ProviderResponseMetadata:
    """Root-issued metadata released to the authenticated producer."""

    producer_context_handle: str
    tool_call_bindings: tuple[Any, ...]


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
    turn_handle: str
    producer_identity: Any
    producer_pid: int
    profile_id: str
    generation: str
    package_id: str
    native_package_generation: str
    service_generation_digest: str
    adapter_id: str
    action_id: str
    tool_name: str
    arguments_sha256: str
    source_receipt_handles: tuple[str, ...]
    operation: str
    request_digest: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        opaque = (self.invocation_handle, self.observed_call_handle,
                  self.response_observation_handle, self.response_receipt_handle,
                  self.native_request_handle, self.turn_handle)
        if (any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value)
                for value in opaque)
                or type(self.producer_pid) is not int or self.producer_pid <= 0
                or any(not isinstance(value, str) or not value for value in (
                    self.profile_id, self.generation, self.package_id,
                    self.native_package_generation, self.adapter_id, self.action_id,
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
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)):
            raise ValueError("root native tool invocation record is malformed")


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
    loaded_package_proof: Any
    expires_monotonic: float
    calls: dict[str, tuple[str, str, str, str, bytes]]
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
    adapter_id: str
    action_id: str
    tool_name: str
    arguments_sha256: str
    parent_closure_digest: str
    receipt_handles: tuple[str, ...]
    observer_id: str
    loaded_package_proof: Any
    expires_monotonic: float
    service_generation_digest: str
    mcp_dispatch_consumed: bool = False


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
        self._mcp_dispatches: dict[str, tuple[_NativeInvocation, RootNativeMCPInvocation]] = {}
        self._issued_handles: set[str] = set()
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
                or observer.producer_uid != bridge.producer_uid):
            raise AuthorityDenied("native.invocation.observer", "selected provider-result observer is unavailable")
        loaded_proof = self._loaded_proof(
            observer_id, producer_identity, producer_pid, producer_pidfd)
        observed_action_ids = getattr(loaded_proof, "observed_entrypoint_action_ids", None)
        if not isinstance(observed_action_ids, (tuple, frozenset, set)):
            raise AuthorityDenied("native.invocation.package", "loaded proof has no observed action closure")
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
            try:
                selection = self.action_resolver(bridge, producer_identity, tool_name)
            except Exception:
                raise AuthorityDenied("native.invocation.action", "root action selection failed") from None
            if (not isinstance(selection, NativeActionSelection)
                    or selection.package_id != observer.package_id
                    or selection.profile_id != bridge.producer_profile_id
                    or selection.generation != bridge.producer_generation
                    or selection.action_id not in observed_action_ids
                    or not self._validate_selection(selection, arguments)):
                raise AuthorityDenied("native.invocation.action", "tool call has no exact selected action schema")
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
            response_handle, delivery_handle, native_request_handle,
            response_digest, closure_handles, bridge, producer_identity,
            producer_pid, os.dup(producer_pidfd), gateway_identity, gateway_pid,
            os.dup(gateway_pidfd), observer_id,
            observer.package_id, observer.profile_id, observer.generation,
            loaded_proof, lease, pending_calls,
        )
        with self._lock:
            self._ensure_open()
            self._prune_locked(now)
            if len(self._responses) >= 4096 or len(self._calls) + len(pending_calls) > 8192:
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
            for handle, call in pending_calls.items():
                self._calls[handle] = (response_handle, *call)
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
            )

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
            try:
                selection = self.action_resolver(bridge, identity, tool_name)
            except Exception:
                raise AuthorityDenied("native.invocation.action", "root action selection changed") from None
            if (not isinstance(selection, NativeActionSelection)
                    or (selection.package_id, selection.profile_id, selection.generation,
                        selection.adapter_id, selection.action_id)
                    != (response.package_id, response.profile_id, response.generation,
                        adapter_id, action_id)
                    or not self._validate_selection(selection, canonical_arguments)):
                raise AuthorityDenied("native.invocation.action", "selected action mapping changed before invocation")
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
                response.generation, adapter_id, action_id, tool_name, digest, closure_digest,
                response.receipt_handles, response.observer_id, current_proof, lease,
                self.service.service_generation_digest,
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
            if (identity != invocation.producer_identity or gateway != invocation.gateway_identity
                    or proof != invocation.loaded_package_proof
                    or not isinstance(action, NativeActionSelection)
                    or (action.package_id, action.profile_id, action.generation,
                        action.adapter_id, action.action_id)
                    != (invocation.package_id, invocation.profile_id, invocation.generation,
                        invocation.adapter_id, invocation.action_id)):
                return False
            with self.service._lock:
                receipts = [self.service._source_receipt_handles.get(handle)
                            for handle in invocation.receipt_handles]
            return (bool(receipts) and all(
                receipt is not None and receipt.profile_id == invocation.profile_id
                and receipt.process_generation == invocation.generation
                and receipt.uid == peer_uid and receipt.monotonic_expires_at > self.monotonic()
                for receipt in receipts
            ))
        except Exception:
            return False

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

    def close(self) -> None:
        with self._lock:
            self._closed = True
            for response in self._responses.values():
                os.close(response.producer_pidfd)
                os.close(response.gateway_pidfd)
            for invocation in self._invocations.values():
                os.close(invocation.producer_pidfd)
                os.close(invocation.gateway_pidfd)
            self._responses.clear()
            self._deliveries.clear()
            self._calls.clear()
            self._invocations.clear()
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
                self._mcp_dispatches.pop(handle, None)
                try:
                    os.close(invocation.producer_pidfd)
                    os.close(invocation.gateway_pidfd)
                except OSError:
                    pass

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
                 effect_observer_ids: Mapping[tuple[str, str, str], str]) -> None:
        if (not callable(getattr(source_observers, "record_observed_event", None))
                or not callable(getattr(source_observers, "capture_observed_source", None))
                or not isinstance(effect_observer_ids, Mapping)
                or not effect_observer_ids):
            raise NativeRuntimeObserverUnavailable("trusted native observer inputs are incomplete")
        pairs: dict[tuple[str, str, str], str] = {}
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
        self.source_observers = source_observers
        self.effect_observer_ids = pairs
        self.invocation_registry: Any | None = None
        self.native_turn_observation_registry: Any | None = None
        self._lock = threading.RLock()
        self._closed = False

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
        with self._lock:
            invocation_registry = self.invocation_registry
            turn_registry = self.native_turn_observation_registry
        invocation = None
        if invocation_registry is not None or turn_registry is not None:
            from .native_runtime_observer import RootNativeToolEffectInvocation
            if (invocation_registry is None or turn_registry is None
                    or request_payload is None or request_sha256 is None
                    or hashlib.sha256(request_payload).hexdigest() != request_sha256
                    or request_sha256 != getattr(authorization, "request_digest", None)):
                raise AuthorityDenied("native.turn.effect", "validated native action bytes are unavailable")
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
                    or invocation.expires_monotonic <= time.monotonic()):
                raise AuthorityDenied("native.turn.effect", "validated effect does not join a current observed call")
        observer_id = self.effect_observer_ids.get((capability, operation, target))
        observer = self.source_observers.observers.get(observer_id) if observer_id else None
        if (observer is None or getattr(observer, "profile_id", None) != context.profile_id
                or getattr(observer, "generation", None) != context.generation
                or getattr(observer, "producer_uid", None) != context.uid):
            raise AuthorityDenied("source.observer", "completed effect has no matching root observer enrollment")
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
        if invocation is not None:
            turn_registry.record_tool_result(
                invocation.turn_handle, str(receipt_handle),
                live_producer_identity=invocation.producer_identity,
                observed_call_handle=invocation.observed_call_handle,
            )
        return str(receipt_handle)

    def close(self) -> None:
        """Stop new observations when the selected package generation is retired."""
        with self._lock:
            self._closed = True

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
