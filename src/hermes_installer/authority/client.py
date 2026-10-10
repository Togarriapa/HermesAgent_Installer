"""Synchronous, peer-authenticated client for the protected host authority.

Workers never receive a signing key. Host contexts and effect grants are signed
by the root-owned service; this client authenticates that service with kernel
peer credentials and asks it to verify/consume every effect grant.
"""
from __future__ import annotations

import json
import math
import os
import re
import secrets
import select
import socket
import stat
import struct
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Sequence

from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext,
    NativeEventHandle, NativeInvocationBinding, NativeInvocationContexts, NativeResponseMetadata,
    NativeToolCallBinding,
    RootCompletedNativeTurnPresentation,
    VerifiedEffectAuthorization, canonical_bytes, canonical_digest, strict_json_loads,
)
from .process_controls import ProcessControlResponse

if TYPE_CHECKING:
    from .source_observers import NativeInitialInputDelivery

_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete", "memory.extract",
    "memory.embed", "memory.backup", "memory.restore", "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "plugin.agent-live-wallet.execute",
    "plugin.agent-live-wallet.read", "plugin.agent-sandbox-wallet.execute",
    "plugin.agent-sandbox-wallet.read", "plugin.authentik-authorization.read",
    "plugin.cloudflare-homelab.read", "plugin.cloudflare-homelab.write",
    "plugin.codex.run", "plugin.composio.invoke", "plugin.ebook-toolchain.run",
    "plugin.epic-kanban.delete", "plugin.epic-kanban.read", "plugin.epic-kanban.write",
    "plugin.financial-data-hub.read", "plugin.financial-execution-gateway.execute",
    "plugin.github.admin", "plugin.github.read", "plugin.github.write",
    "plugin.homelab-ops-broker.read", "plugin.homelab-ops-broker.write",
    "plugin.kobo-bridge.deliver", "plugin.kobo-bridge.read",
    "plugin.resource-overlay-store.backup", "plugin.resource-overlay-store.read",
    "plugin.resource-overlay-store.write", "plugin.voice-pipeline.session",
    "plugin.voice-pipeline.stt", "plugin.voice-pipeline.tts", "plugin.web.read",
    "process.start", "process.status", "process.read",
    "process.write", "process.stop", "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.webhook.run", "resource.channel.run", "resource.bundle.node.run",
    "resource.job.admit", "resource.job.child.admit",
    "resource.orchestrator.recruit", "process.inspect", "connector.open",
    "connector.read", "connector.write", "connector.close",
    "native.event.prepare", "native.request.dispatch",
})

MAX_REQUEST = 6 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_TIMEOUT = 600.0
DEFAULT_SOCKET_DIR = Path("/run/hermes-installer/authority")


def default_socket_path(uid: int | None = None) -> Path:
    """Return the installed per-UID socket path without consulting environment."""
    peer_uid = os.getuid() if uid is None else uid
    if type(peer_uid) is not int or peer_uid <= 0:
        raise AuthorityDenied("authority.endpoint", "current user has no enrolled authority endpoint")
    return DEFAULT_SOCKET_DIR / f"{peer_uid}.sock"


def canonical_profile_target(profile_id: str, executable: Path, data_root: Path) -> str:
    executable = executable.resolve(strict=True)
    data_root = data_root.resolve(strict=True)
    if not executable.is_file() or not data_root.is_dir():
        raise AuthorityDenied("target.invalid", "profile executable/data root are invalid")
    import hashlib
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return f"hermes-profile-invoke:{profile_id}:{executable}:{digest}:{data_root}"


def _file_digest(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def profile_launch_envelope(*, target: str, profile_id: str, executable: Path,
                            artifact_sha256: str, artifact_root: Path, cwd: Path,
                            data_root: Path, argv: Sequence[str],
                            env_allowlist: Mapping[str, str],
                            child_artifact_refs: Mapping[str, str] | None = None,
                            max_lifetime_seconds: int = 600,
                            max_output_bytes: int = 1_048_576,
                            stdin_mode: str = "closed") -> dict[str, Any]:
    """Build the exact canonical launch binding consumed by process.start."""
    if target != canonical_profile_target(profile_id, executable, data_root):
        raise AuthorityDenied("effect.launch", "launch target is not bound to this profile")
    if len(argv) < 1 or argv[0] != str(executable.resolve(strict=True)):
        raise AuthorityDenied("effect.launch", "argv[0] must be the resolved pinned executable")
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
        raise AuthorityDenied("effect.launch", "artifact digest is invalid")
    if not 1 <= max_lifetime_seconds <= 600 or not 1 <= max_output_bytes <= 4 * 1024 * 1024:
        raise AuthorityDenied("effect.bounds", "process lifetime or output limit is invalid")
    if stdin_mode not in {"closed", "pipe"}:
        raise AuthorityDenied("effect.launch", "stdin mode is invalid")
    child_refs: dict[str, str] = {}
    for store_id, child_digest in (child_artifact_refs or {}).items():
        if (not isinstance(store_id, str) or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", store_id)
                or store_id.rsplit(":", 1)[-1] != child_digest
                or not re.fullmatch(r"[0-9a-f]{64}", child_digest)):
            raise AuthorityDenied("effect.launch", "child artifact reference is invalid")
        child_refs[store_id] = child_digest
    if any(arg.startswith("artifact:") and arg not in child_refs for arg in argv):
        raise AuthorityDenied("effect.launch", "argv names an unregistered artifact reference")
    return {
        "schema": 1, "target": target, "profile_id": profile_id,
        "executable": str(executable.resolve(strict=True)),
        "artifact_sha256": artifact_sha256,
        "artifact_root": str(artifact_root.resolve(strict=True)),
        "cwd": str(cwd.resolve(strict=True)),
        "data_root": str(data_root.resolve(strict=True)),
        "argv": list(argv), "env_allowlist": dict(env_allowlist),
        "child_artifact_refs": child_refs,
        "max_lifetime_seconds": max_lifetime_seconds,
        "max_output_bytes": max_output_bytes, "stdin_mode": stdin_mode,
    }


class AuthorityClient:
    """Client for a fixed root-owned AF_UNIX endpoint and bounded fixed verbs."""

    def __init__(self, socket_path: Path, *, server_uid: int = 0,
                 server_gid: int | None = None,
                 timeout: float = 5.0, monotonic: Callable[[], float] = time.monotonic):
        if not socket_path.is_absolute() or type(server_uid) is not int or server_uid < 0:
            raise ValueError("absolute authority socket path and server UID are required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= MAX_TIMEOUT:
            raise ValueError("authority timeout must be bounded")
        self.socket_path = socket_path
        self.server_uid = server_uid
        if server_gid is not None and (type(server_gid) is not int or server_gid < 0):
            raise ValueError("socket group ID must be nonnegative")
        self.server_gid = server_gid
        self.timeout = float(timeout)
        self.monotonic = monotonic

    @classmethod
    def for_current_process(cls, *, timeout: float = 5.0) -> "AuthorityClient":
        """Connect only to the installed fixed endpoint; never consult env vars."""
        return cls(default_socket_path(), server_uid=0, server_gid=os.getgid(), timeout=timeout)

    def context(self, *, purpose: str, intent: str, operation: str,
                source_contexts: Sequence[HostContext] = (),
                source_receipt_handles: Sequence[str] = (),
                final_payload_digest: str | None = None,
                trace_id: str | None = None,
                lease_seconds: float = 30.0,
                cancelled: Callable[[], bool] | None = None) -> HostContext:
        """Ask the host to classify intent and lineage from its own policy."""
        if not isinstance(purpose, str) or not 1 <= len(purpose) <= 128:
            raise AuthorityDenied("context.invalid", "purpose is invalid")
        if not isinstance(intent, str) or not 1 <= len(intent) <= 512:
            raise AuthorityDenied("context.invalid", "intent is invalid")
        if operation not in _OPERATIONS:
            raise AuthorityDenied("context.invalid", "operation is not a fixed host effect")
        if trace_id is not None and (not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128):
            raise AuthorityDenied("context.invalid", "trace ID is invalid")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 0 < lease_seconds <= MAX_TIMEOUT:
            raise AuthorityDenied("context.invalid", "context lease exceeds its fixed upper bound")
        if (len(source_contexts) > 64 or any(not isinstance(x, HostContext) for x in source_contexts)
                or len(source_receipt_handles) > 64
                or any(not isinstance(x, str) or not x for x in source_receipt_handles)):
            raise AuthorityDenied("context.invalid", "source lineage is invalid")
        if source_contexts and source_receipt_handles:
            raise AuthorityDenied("context.invalid", "use one complete source lineage representation")
        if final_payload_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", final_payload_digest):
            raise AuthorityDenied("context.invalid", "final payload digest is invalid")
        if source_receipt_handles and final_payload_digest is None:
            raise AuthorityDenied("context.invalid", "source receipts require a final payload digest")
        request = {
            "purpose": purpose, "intent": intent, "trace_id": trace_id,
            "lease_seconds": float(lease_seconds),
            "source_contexts": [ctx.to_wire() for ctx in source_contexts],
        }
        if source_receipt_handles:
            request["source_receipt_handles"] = list(source_receipt_handles)
        if final_payload_digest is not None:
            request["final_payload_digest"] = final_payload_digest
        request["operation"] = operation
        result = self._rpc("issue_context", {
            **request,
        }, timeout=min(self.timeout, float(lease_seconds)), cancelled=cancelled)
        return HostContext.from_wire(result)

    def capture_source(self, payload: bytes, *, parent_receipt_handles: Sequence[str] = (),
                       timeout: float = 5.0,
                       cancelled: Callable[[], bool] | None = None) -> str:
        """The old same-peer caller-byte minting endpoint is intentionally retired.

        Native evidence must use the paired producer/gateway event bridge; a
        generic enrolled worker is not a trusted source issuer.
        """
        raise AuthorityDenied("source.issuer", "generic worker source capture is not an enrolled issuer")

    def take_source_receipt(self, receipt_handle: str) -> str:
        """Take one already-issued receipt handle over the authenticated peer socket.

        The root delivery registry decides whether this process is the
        enrolled recipient. This method never creates receipt claims.
        """
        if not isinstance(receipt_handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", receipt_handle):
            raise AuthorityDenied("source.delivery", "source receipt handle is malformed")
        result = self._rpc("source.receipt.take", {"schema": 1, "receipt_handle": receipt_handle})
        if (not isinstance(result, dict) or set(result) != {"schema", "receipt_handle"}
                or result.get("schema") != 1 or result.get("receipt_handle") != receipt_handle):
            raise AuthorityDenied("source.delivery", "root returned a mismatched source receipt handle")
        return receipt_handle

    def take_selected_native_input(self, *,
                                   cancelled: Callable[[], bool] | None = None
                                   ) -> "NativeInitialInputDelivery | None":
        """Take this live producer's one queued native input, without selectors.

        The root identifies the current execution solely from SO_PEERCRED and
        the authenticated peer PIDFD. ``None`` means that no input is queued
        yet; callers may only retry under their bounded selected startup wait.
        """
        from .source_observers import NativeInitialInputDelivery

        result = self._rpc("native.input.take", {"schema": 1}, timeout=min(30.0, self.timeout),
                           cancelled=cancelled)
        if (not isinstance(result, dict) or type(result.get("schema")) is not int
                or result["schema"] != 1):
            raise AuthorityDenied("native.input.take", "authority returned a malformed input delivery")
        if set(result) == {"schema", "state"} and result.get("state") == "pending":
            return None
        fields = {"schema", "source_receipt_handle", "selected_execution_handle",
                  "input_sha256", "input_size_bytes", "expires_monotonic"}
        if set(result) not in (fields, fields | {"turn_handle"}):
            raise AuthorityDenied("native.input.take", "authority returned unexpected input delivery fields")
        turn_handle = result.get("turn_handle")
        if turn_handle is not None and (not isinstance(turn_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", turn_handle)):
            raise AuthorityDenied("native.input.take", "authority returned a malformed turn handle")
        try:
            delivery = NativeInitialInputDelivery(**result)
        except (TypeError, ValueError):
            raise AuthorityDenied("native.input.take", "authority returned an invalid input delivery") from None
        if not self.monotonic() < delivery.expires_monotonic <= self.monotonic() + 30.0:
            raise AuthorityDenied("native.input.take", "authority returned an expired input delivery")
        return delivery

    def bind_selected_channel_runtime(self, *,
                                     cancelled: Callable[[], bool] | None = None) -> Any:
        """Bind this current native Hermes process to its root-selected channel row.

        The request contains no profile, package, account, channel, or PID. The
        AuthorityService resolves them from this connection's SO_PEERCRED and
        PIDFD and returns only an opaque lease-bound lookup handle.
        """
        from .channel_peer_delivery import ChannelRuntimeBinding

        result = self._rpc("channel.runtime.bind", {"schema": 1},
                           timeout=min(10.0, self.timeout), cancelled=cancelled)
        binding = ChannelRuntimeBinding.from_wire(result)
        if not self.monotonic() < binding.expires_monotonic <= self.monotonic() + 30.0:
            raise AuthorityDenied("channel.binding", "root returned an expired channel binding")
        return binding

    def take_selected_channel_event(self, binding: Any, *,
                                    cancelled: Callable[[], bool] | None = None
                                    ) -> Any | None:
        """Take at most one event addressed to this exact bound native peer."""
        from .channel_peer_delivery import ChannelEventDelivery, ChannelRuntimeBinding

        if type(binding) is not ChannelRuntimeBinding:
            raise AuthorityDenied("channel.delivery", "a root-issued channel runtime binding is required")
        if (binding.expires_monotonic <= self.monotonic()
                or binding.service_generation_digest == ""):
            raise AuthorityDenied("channel.delivery", "selected channel runtime binding is stale")
        result = self._rpc("channel.event.take", {
            "schema": 1, "binding_handle": binding.binding_handle, "max_events": 1,
        }, timeout=min(30.0, self.timeout), cancelled=cancelled)
        if result is None:
            return None
        delivery = ChannelEventDelivery.from_wire(result)
        if (delivery.binding_handle != binding.binding_handle
                or delivery.expires_monotonic <= self.monotonic()
                or delivery.expires_monotonic > binding.expires_monotonic):
            raise AuthorityDenied("channel.delivery", "root returned a stale or mismatched channel event")
        return delivery

    def take_native_channel_context(
        self, producer_context_delivery_handle: str, *,
        cancelled: Callable[[], bool] | None = None,
    ) -> Any | None:
        """Resolve one current channel-context registration for this peer.

        The wire exposes only the source handle, delivery handle, digest, size,
        and expiry. The signed HostContext remains in the root store.
        """
        from .native_channel_context import NativeChannelContextDelivery

        if (not isinstance(producer_context_delivery_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", producer_context_delivery_handle)):
            raise AuthorityDenied("native.channel.context", "context delivery handle is malformed")
        result = self._rpc("native.channel.context.take", {
            "schema": 1,
            "producer_context_delivery_handle": producer_context_delivery_handle,
        }, timeout=min(10.0, self.timeout), cancelled=cancelled)
        if result is None:
            return None
        fields = {
            "schema", "source_receipt_handle", "producer_context_delivery_handle",
            "payload_sha256", "payload_size_bytes", "expires_monotonic",
        }
        if not isinstance(result, dict) or set(result) != fields:
            raise AuthorityDenied("native.channel.context", "authority returned unexpected context fields")
        try:
            delivery = NativeChannelContextDelivery(**result)
        except (TypeError, ValueError):
            raise AuthorityDenied("native.channel.context", "authority returned malformed context delivery") from None
        if (delivery.producer_context_delivery_handle != producer_context_delivery_handle
                or not self.monotonic() < delivery.expires_monotonic <= self.monotonic() + 30.0):
            raise AuthorityDenied("native.channel.context", "authority returned a stale or mismatched context")
        return delivery

    def take_selected_channel_context(
        self, event: Any, *, cancelled: Callable[[], bool] | None = None,
    ) -> Any | None:
        """Resolve the context handle from one root-delivered channel event.

        The authority binds the request to this socket's current peer PIDFD.
        The event's opaque context handle is the sole lookup selector; the
        response contains handles and bounded payload metadata, never a signed
        HostContext or event body.
        """
        from .channel_peer_delivery import ChannelEventDelivery
        from .native_channel_context import NativeChannelContextDelivery

        if type(event) is not ChannelEventDelivery:
            raise AuthorityDenied("channel.context", "a root-delivered channel event is required")
        result = self._rpc("native.channel.context.take", {
            "schema": 1,
            "producer_context_delivery_handle": event.producer_context_delivery_handle,
        }, timeout=min(10.0, self.timeout), cancelled=cancelled)
        if result is None:
            return None
        fields = {"schema", "source_receipt_handle", "producer_context_delivery_handle",
                  "payload_sha256", "payload_size_bytes", "expires_monotonic"}
        if not isinstance(result, dict) or set(result) != fields:
            raise AuthorityDenied("channel.context", "authority returned a malformed channel context delivery")
        try:
            delivery = NativeChannelContextDelivery(**result)
        except (TypeError, ValueError):
            raise AuthorityDenied("channel.context", "authority returned an invalid channel context delivery") from None
        if (delivery.producer_context_delivery_handle != event.producer_context_delivery_handle
                or delivery.source_receipt_handle != event.source_receipt_handle
                or delivery.payload_sha256 != event.payload_sha256
                or delivery.payload_size_bytes != len(event.normalized_payload)
                or delivery.expires_monotonic <= self.monotonic()
                or delivery.expires_monotonic > event.expires_monotonic):
            raise AuthorityDenied("channel.context", "channel context does not match its selected event")
        return delivery

    def finish_selected_native_turn(
        self, turn_handle: str, final_response_delivery_handle: str,
    ) -> RootCompletedNativeTurnPresentation:
        """Finish one peer-bound native turn and receive only its opaque receipt."""
        for name, handle in (("turn", turn_handle),
                             ("final response delivery", final_response_delivery_handle)):
            if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
                raise AuthorityDenied("native.turn.finish", f"{name} handle is malformed")
        result = self._rpc("native.turn.finish", {
            "schema": 1,
            "turn_handle": turn_handle,
            "final_response_delivery_handle": final_response_delivery_handle,
        })
        presentation = RootCompletedNativeTurnPresentation.from_wire(result)
        if (presentation.turn_handle != turn_handle
                or presentation.state != "completed"
                or not self.monotonic() < presentation.expires_monotonic):
            raise AuthorityDenied("native.turn.finish", "root returned a stale or mismatched turn receipt")
        return presentation

    def bind_selected_native_package(self) -> Mapping[str, Any]:
        """Resolve only the package actually mounted in this live peer."""
        result = self._rpc("native.package.bind", {"schema": 1})
        if (not isinstance(result, Mapping) or set(result) != {
                "schema", "opaque_binding_handle", "package_id", "profile_id", "generation",
                "resolver_digest", "compiled_closure_sha256", "entrypoint_sha256", "expires_monotonic"}
                or type(result.get("schema")) is not int or result["schema"] != 1):
            raise AuthorityDenied("native.package", "root returned an invalid selected package binding")
        return result

    def read_native_resolver(self, binding_handle: str) -> Mapping[str, Any]:
        """Read the current digest-covered resolver for this peer's binding."""
        if (not isinstance(binding_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", binding_handle)):
            raise AuthorityDenied("native.package", "native package binding handle is malformed")
        result = self._rpc("native.package.resolver.read", {
            "schema": 1, "binding_handle": binding_handle,
        })
        if not isinstance(result, Mapping):
            raise AuthorityDenied("native.package", "root returned an invalid native resolver")
        return result

    def begin_native_invocation(self, producer_context_handle: str,
                                observed_call_handle: str,
                                canonical_arguments: bytes) -> NativeInvocationBinding:
        """Resolve one root-observed tool call to its registered action binding."""
        import base64
        for name, handle in (("producer context", producer_context_handle),
                             ("observed call", observed_call_handle)):
            if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
                raise AuthorityDenied("native.invocation", f"{name} handle is malformed")
        if not isinstance(canonical_arguments, bytes) or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024:
            raise AuthorityDenied("native.invocation", "canonical native arguments exceed their bound")
        result = self._rpc("native.invocation.begin", {
            "schema": 1, "producer_context_handle": producer_context_handle,
            "observed_call_handle": observed_call_handle,
            "canonical_arguments_b64": base64.b64encode(canonical_arguments).decode("ascii"),
        })
        binding = NativeInvocationBinding.from_wire(result, monotonic=self.monotonic)
        import hashlib
        if binding.arguments_sha256 != hashlib.sha256(canonical_arguments).hexdigest():
            raise AuthorityDenied("native.invocation", "root invocation binding covers different arguments")
        return binding

    def get_invocation_contexts(self, invocation_handle: str) -> NativeInvocationContexts:
        """Fetch root-registered source ancestry bound to this native peer."""
        if not isinstance(invocation_handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", invocation_handle):
            raise AuthorityDenied("native.invocation", "native invocation handle is malformed")
        result = self._rpc("native.invocation.contexts", {
            "schema": 1, "invocation_handle": invocation_handle,
        })
        contexts = NativeInvocationContexts.from_wire(result, monotonic=self.monotonic)
        if contexts.invocation_handle != invocation_handle:
            raise AuthorityDenied("native.invocation", "root invocation context belongs to another call")
        return contexts

    def execute_owner_overlay(self, invocation_handle: str,
                              canonical_arguments: bytes) -> Mapping[str, Any]:
        """Ask root to execute one captured owner-overlay invocation.

        The request carries no registration, method, target, identity, or grant
        selector. Those are rejoined from the root-retained invocation.
        """
        import base64
        if (not isinstance(invocation_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", invocation_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024):
            raise AuthorityDenied("native.owner_overlay", "owner-overlay invocation request is malformed")
        result = self._rpc("native.owner-overlay.execute", {
            "schema": 1, "invocation_handle": invocation_handle,
            "canonical_arguments_b64": base64.b64encode(canonical_arguments).decode("ascii"),
        })
        if not isinstance(result, Mapping) or set(result) != {
                "schema", "invocation_handle", "registration_id", "result_schema_id",
                "result_sha256", "canonical_result_b64"}:
            raise AuthorityDenied("native.owner_overlay", "root returned an invalid owner-overlay result")
        if (type(result.get("schema")) is not int or result["schema"] != 1
                or result.get("invocation_handle") != invocation_handle
                or not isinstance(result.get("registration_id"), str)
                or not isinstance(result.get("result_schema_id"), str)
                or not isinstance(result.get("result_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", result["result_sha256"])
                or not isinstance(result.get("canonical_result_b64"), str)):
            raise AuthorityDenied("native.owner_overlay", "root owner-overlay result binding is malformed")
        try:
            payload = base64.b64decode(result["canonical_result_b64"], validate=True)
        except (ValueError, TypeError):
            raise AuthorityDenied("native.owner_overlay", "root owner-overlay result bytes are malformed") from None
        import hashlib
        if (not 1 <= len(payload) <= 1_048_576
                or base64.b64encode(payload).decode("ascii") != result["canonical_result_b64"]
                or hashlib.sha256(payload).hexdigest() != result["result_sha256"]):
            raise AuthorityDenied("native.owner_overlay", "root owner-overlay result digest is invalid")
        return dict(result)

    def take_native_response_metadata(self, response_delivery_handle: str,
                                      response_body_sha256: str,
                                      native_request_handle: str) -> NativeResponseMetadata:
        """Take response metadata once, bound to the raw body and original HI11 request."""
        if (not isinstance(response_delivery_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", response_delivery_handle)
                or not isinstance(native_request_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", native_request_handle)
                or not isinstance(response_body_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", response_body_sha256)):
            raise AuthorityDenied("native.response.take", "provider response lookup fields are malformed")
        result = self._rpc("native.response.take", {
            "schema": 1,
            "delivery_handle": response_delivery_handle,
            "response_body_sha256": response_body_sha256,
            "native_request_handle": native_request_handle,
        })
        return NativeResponseMetadata.from_wire(result)

    def remote_sessions(self) -> Any:
        """Return typed HI13 calls over this client's authenticated Unix RPC.

        The root service still denies every remote operation unless it was
        constructed with a complete protected RemoteSessionAuthority.
        """
        from .remote_sessions import RemoteAuthorityClient
        return RemoteAuthorityClient(lambda operation, payload: self._rpc(operation, payload))

    def prepare_native_event(self, payload: bytes, *, parent_receipt_handles: Sequence[str] = (),
                             purpose: str, intent_id: str, trace_id: str,
                             retry_index: int = 0, timeout: float = 5.0,
                             cancelled: Callable[[], bool] | None = None) -> NativeEventHandle:
        """Capture one complete SDK request for the paired root-selected gateway.

        Root enrollment selects both process identities and canonicalizer. A
        new handle is required for every retry; it never contains a bearer grant.
        """
        if (not isinstance(payload, bytes) or not 1 <= len(payload) <= 1_048_576
                or not isinstance(purpose, str) or not 1 <= len(purpose) <= 128
                or not isinstance(intent_id, str) or not 1 <= len(intent_id) <= 512
                or not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128
                or type(retry_index) is not int or not 0 <= retry_index <= 100
                or len(parent_receipt_handles) > 64
                or any(not isinstance(item, str) or not item for item in parent_receipt_handles)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= MAX_TIMEOUT):
            raise AuthorityDenied("native.request", "native source event request is malformed or outside bounds")
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "native source event was cancelled")
        import base64
        result = self._rpc("prepare_native_event", {
            "schema": 1, "payload": base64.b64encode(payload).decode("ascii"),
            "parent_receipt_handles": list(parent_receipt_handles),
            "purpose": purpose, "intent_id": intent_id, "trace_id": trace_id,
            "retry_index": retry_index,
        }, timeout=min(float(timeout), self.timeout), cancelled=cancelled)
        if not isinstance(result, dict) or set(result) != {"native_event_handle", "expires_monotonic"}:
            raise AuthorityDenied("native.handle", "authority returned a malformed native event handle")
        handle = NativeEventHandle(result["native_event_handle"], result["expires_monotonic"])
        if not self.monotonic() < handle.expires_monotonic <= self.monotonic() + 600:
            raise AuthorityDenied("native.handle", "native event handle lease is stale or overlong")
        return handle

    def dispatch_native_request(self, handle: NativeEventHandle | str, normalized_payload: bytes, *,
                                retry_index: int = 0, timeout: float = 30.0,
                                cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Atomically claim a producer event at its enrolled gateway and dispatch it.

        The worker never receives a context, effect grant, provider endpoint, or
        credential. The root validates the payload/lineage and calls its fixed
        provider handler as one broker operation.
        """
        event_key = (handle.native_event_handle if isinstance(handle, NativeEventHandle) else handle)
        if (not isinstance(event_key, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", event_key)
                or isinstance(handle, NativeEventHandle) and handle.expires_monotonic <= self.monotonic()
                or not isinstance(normalized_payload, bytes)
                or not 1 <= len(normalized_payload) <= 4 * 1024 * 1024
                or type(retry_index) is not int or not 0 <= retry_index <= 100
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= MAX_TIMEOUT):
            raise AuthorityDenied("native.dispatch", "native gateway request is malformed or expired")
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "native gateway request was cancelled")
        import base64
        result = self._rpc("dispatch_native_request", {
            "schema": 1, "native_event_handle": event_key,
            "normalized_payload": base64.b64encode(normalized_payload).decode("ascii"),
            "retry_index": retry_index,
        }, timeout=min(float(timeout), self.timeout), cancelled=cancelled)
        base_fields = {"status", "body", "headers", "receipt_id"}
        native_fields = {"producer_context_handle", "tool_call_bindings"}
        allowed_fields = (base_fields, base_fields | {"source_receipt_handle"},
                          base_fields | native_fields,
                          base_fields | native_fields | {"source_receipt_handle"})
        if not isinstance(result, dict) or set(result) not in allowed_fields:
            raise AuthorityDenied("native.dispatch", "authority returned a malformed dispatch result")
        try:
            body = base64.b64decode(result["body"], validate=True)
        except Exception:
            raise AuthorityDenied("native.dispatch", "authority returned a malformed dispatch body") from None
        headers = result["headers"]
        if (type(result["status"]) is not int or not 0 <= result["status"] <= 599
                or len(body) > 4 * 1024 * 1024 or not isinstance(headers, dict) or len(headers) > 32
                or any(not isinstance(k, str) or not isinstance(v, str)
                       or any(char in k + v for char in "\r\n\x00") for k, v in headers.items())
                or not isinstance(result["receipt_id"], str) or not result["receipt_id"]):
            raise AuthorityDenied("native.dispatch", "authority dispatch response exceeds its bound")
        source_handle = result.get("source_receipt_handle")
        if source_handle is not None and (not isinstance(source_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", source_handle)):
            raise AuthorityDenied("native.dispatch", "authority returned a malformed source result handle")
        producer_handle = result.get("producer_context_handle")
        tool_calls: tuple[NativeToolCallBinding, ...] = ()
        if native_fields.issubset(result):
            raw_calls = result["tool_call_bindings"]
            if (not isinstance(raw_calls, list) or len(raw_calls) > 128
                    or (producer_handle is None and raw_calls)
                    or (producer_handle is not None and not 200 <= result["status"] < 300)):
                raise AuthorityDenied("native.dispatch", "root provider invocation bindings are malformed")
            if producer_handle is not None and (not isinstance(producer_handle, str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", producer_handle)):
                raise AuthorityDenied("native.dispatch", "root provider context handle is malformed")
            tool_calls = tuple(NativeToolCallBinding.from_wire(item) for item in raw_calls)
        return BrokeredEffectResponse(result["status"], body, dict(headers), result["receipt_id"],
                                      source_handle, producer_handle, tool_calls)

    def dispatch_native_mcp(self, invocation_handle: str,
                            canonical_arguments: bytes) -> BrokeredEffectResponse:
        """Dispatch one root-observed native MCP tool call through the host.

        The invocation handle is a lookup key for the lexical tool binding.
        This request carries no caller-selected MCP service, tool, target,
        capability, recipient, context, or effect grant.
        """
        import base64

        if (not isinstance(invocation_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", invocation_handle)
                or not isinstance(canonical_arguments, bytes)
                or not 1 <= len(canonical_arguments) <= 2 * 1024 * 1024):
            raise AuthorityDenied("native.mcp", "native MCP invocation is malformed or over its bound")
        try:
            parsed = strict_json_loads(canonical_arguments.decode("utf-8"))
            if (not isinstance(parsed, dict)
                    or canonical_bytes(parsed) != canonical_arguments):
                raise ValueError
        except (ValueError, TypeError, UnicodeError):
            raise AuthorityDenied("native.mcp", "native MCP arguments are not a canonical JSON object") from None
        result = self._rpc("native.mcp.dispatch", {
            "schema": 1,
            "invocation_handle": invocation_handle,
            "canonical_arguments_b64": base64.b64encode(canonical_arguments).decode("ascii"),
        })
        base_fields = {"status", "body", "headers", "receipt_id"}
        allowed = {frozenset(base_fields), frozenset(base_fields | {"source_receipt_handle"})}
        if not isinstance(result, dict) or frozenset(result) not in allowed:
            raise AuthorityDenied("native.mcp", "authority returned a malformed native MCP response")
        try:
            body = base64.b64decode(result["body"], validate=True)
        except Exception:
            raise AuthorityDenied("native.mcp", "authority returned a malformed native MCP body") from None
        headers = result["headers"]
        if (type(result["status"]) is not int or not 0 <= result["status"] <= 599
                or len(body) > 4 * 1024 * 1024
                or not isinstance(headers, dict) or len(headers) > 32
                or any(not isinstance(key, str) or not isinstance(value, str)
                       or any(char in key + value for char in "\r\n\x00")
                       for key, value in headers.items())
                or not isinstance(result["receipt_id"], str)
                or not 1 <= len(result["receipt_id"]) <= 256):
            raise AuthorityDenied("native.mcp", "authority native MCP response exceeds its bound")
        source_handle = result.get("source_receipt_handle")
        if source_handle is not None and (not isinstance(source_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", source_handle)):
            raise AuthorityDenied("native.mcp", "authority returned a malformed result lineage handle")
        return BrokeredEffectResponse(
            result["status"], body, dict(headers), result["receipt_id"], source_handle,
        )

    def authorize_effect(self, context: HostContext, *, capability: str,
                         target: str, recipient: str | None = None,
                         request_digest: str, retry_index: int = 0,
                         cancelled: Callable[[], bool] | None = None) -> EffectAuthorization:
        if not isinstance(context, HostContext):
            raise AuthorityDenied("context.untrusted", "a host-issued context is required")
        if isinstance(retry_index, bool) or type(retry_index) is not int or not 0 <= retry_index <= 100:
            raise AuthorityDenied("effect.invalid", "retry index is invalid")
        if not isinstance(request_digest, str) or len(request_digest) != 64:
            raise AuthorityDenied("effect.invalid", "request digest is invalid")
        remaining = context.monotonic_expires_at - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("context.stale", "host context lease expired")
        result = self._rpc("authorize_effect", {
            "context": context.to_wire(), "capability": capability,
            "target": target, "recipient": recipient,
            "request_digest": request_digest, "retry_index": retry_index,
        }, timeout=min(self.timeout, remaining), cancelled=cancelled)
        return EffectAuthorization.from_wire(result)

    def verify_effect(self, authorization: EffectAuthorization, context: HostContext,
                      *, capability: str, target: str, recipient: str | None = None,
                      request_digest: str | None = None,
                      retry_index: int | None = None,
                      cancelled: Callable[[], bool] | None = None) -> VerifiedEffectAuthorization:
        if not isinstance(authorization, EffectAuthorization) or not isinstance(context, HostContext):
            raise AuthorityDenied("grant.invalid", "host-issued context and effect grant are required")
        remaining = min(context.monotonic_expires_at, authorization.monotonic_expires_at) - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("grant.stale", "host authorization lease expired")
        result = self._rpc("verify_effect", {
            "authorization": authorization.to_wire(), "context": context.to_wire(),
            "capability": capability, "target": target, "recipient": recipient,
            "request_digest": request_digest or authorization.request_digest,
            "retry_index": authorization.retry_index if retry_index is None else retry_index,
        }, timeout=min(self.timeout, remaining), cancelled=cancelled)
        if not isinstance(result, dict) or set(result) != {"operation", "verified_at_monotonic", "verification_receipt"}:
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        verified = result["verified_at_monotonic"]
        if isinstance(verified, bool) or not isinstance(verified, (int, float)) or not math.isfinite(verified):
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        return VerifiedEffectAuthorization(authorization, str(result["operation"]), float(verified), str(result["verification_receipt"]))

    def perform_effect(self, authorization: EffectAuthorization, *, operation: str,
                       payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Perform one registered fixed-verb effect through the host broker.

        No arbitrary URL, method, shell command, or credential resolver is
        accepted here. The host broker independently verifies and consumes the
        grant and recomputes the payload digest before calling an enrolled
        adapter.
        """
        if operation not in _OPERATIONS:
            raise AuthorityDenied("effect.operation", "effect operation is not in the fixed verb set")
        if not isinstance(authorization, EffectAuthorization) or not isinstance(payload, bytes):
            raise AuthorityDenied("effect.invalid", "effect grant and byte payload are required")
        if len(payload) > 4 * 1024 * 1024:
            raise AuthorityDenied("effect.bounds", "effect payload exceeds its bound")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
            raise AuthorityDenied("effect.bounds", "effect timeout exceeds its bound")
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "effect was cancelled before broker dispatch")
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "payload digest does not match effect grant")
        started = self.monotonic()
        request = {"authorization": authorization.to_wire(), "operation": operation,
                   "payload": __import__("base64").b64encode(payload).decode("ascii"),
                   "timeout": float(timeout)}
        remaining = authorization.monotonic_expires_at - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("grant.stale", "effect authorization lease expired")
        result = self._rpc("perform_effect", request, timeout=min(float(timeout), remaining), cancelled=cancelled)
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "effect was cancelled before response delivery")
        if self.monotonic() - started > timeout:
            raise AuthorityDenied("effect.deadline", "brokered effect exceeded its deadline")
        if (not isinstance(result, dict)
                or set(result) not in ({"status", "body", "headers", "receipt_id"},
                                      {"status", "body", "headers", "receipt_id", "source_receipt_handle"})):
            raise AuthorityDenied("effect.invalid", "broker effect response is malformed")
        import base64
        try:
            body = base64.b64decode(result["body"], validate=True)
        except Exception:
            raise AuthorityDenied("effect.invalid", "broker effect response is malformed") from None
        headers = result["headers"]
        if (type(result["status"]) is not int or not 0 <= result["status"] <= 599
                or len(body) > 4 * 1024 * 1024 or not isinstance(headers, dict)
                or len(headers) > 32
                or any(not isinstance(k, str) or not isinstance(v, str)
                       or not k or len(k) > 128 or len(v) > 2048
                       or any(char in k + v for char in "\r\n\x00") for k, v in headers.items())
                or not isinstance(result["receipt_id"], str) or not 1 <= len(result["receipt_id"]) <= 256):
            raise AuthorityDenied("effect.invalid", "broker effect response exceeds its bound")
        source_handle = result.get("source_receipt_handle")
        if source_handle is not None and (not isinstance(source_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", source_handle)):
            raise AuthorityDenied("effect.invalid", "broker source result handle is malformed")
        return BrokeredEffectResponse(result["status"], body, dict(headers), result["receipt_id"], source_handle)

    def dispatch_provider(self, authorization: EffectAuthorization, *, target: str,
                          recipient: str, request_digest: str, payload: bytes,
                          timeout: float, cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, recipient, request_digest)
        if canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "provider payload digest does not match grant")
        return self.perform_effect(authorization, operation="provider.dispatch", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def dispatch_codex(self, authorization: EffectAuthorization, *,
                       target: str = "codex://responses",
                       recipient: str = "openai:codex",
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Use the host-enrolled Codex Responses credential and exact endpoint."""
        if target != "codex://responses" or recipient != "openai:codex":
            raise AuthorityDenied("effect.target", "Codex target and account identity are fixed")
        if canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "Codex payload digest does not match request")
        self._check_binding(authorization, target, recipient, request_digest)
        return self.perform_effect(authorization, operation="provider.dispatch", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def memory_request(self, authorization: EffectAuthorization, *, target: str,
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory request target or digest is invalid")
        action = target.rsplit(":", 1)[-1]
        if action not in {"doctor", "extract", "embed", "capture", "search", "export", "delete", "backup", "restore"}:
            raise AuthorityDenied("effect.operation", "memory action is not enrolled")
        operation = "memory.doctor" if action == "doctor" else f"memory.{action}"
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def memory_enqueue(self, authorization: EffectAuthorization, *, target: str,
                       request_digest: str, payload: bytes, timeout: float = 1.0,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or target.rsplit(":", 1)[-1] != "enqueue" or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory queue target or digest is invalid")
        return self.perform_effect(authorization, operation="memory.enqueue", payload=payload,
                                   timeout=min(timeout, 1.0), cancelled=cancelled)

    def memory_result(self, authorization: EffectAuthorization, *, target: str,
                      request_digest: str, payload: bytes, timeout: float = 1.0,
                      cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or target.rsplit(":", 1)[-1] != "result" or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory result target or digest is invalid")
        return self.perform_effect(authorization, operation="memory.result", payload=payload,
                                   timeout=min(timeout, 1.0), cancelled=cancelled)

    def mcp_request(self, authorization: EffectAuthorization, *, target: str,
                    payload: bytes, timeout: float,
                    cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if authorization.target != target or not target.startswith("mcp:"):
            raise AuthorityDenied("effect.binding", "MCP target does not match its host grant")
        channel = target.rsplit(":", 1)[-1]
        if channel not in {"http", "stdio"}:
            raise AuthorityDenied("effect.target", "MCP channel is not enrolled")
        operation = "mcp.request" if channel == "http" else "mcp.stdio"
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def process_start(self, authorization: EffectAuthorization, *, target: str,
                      launch: Mapping[str, Any], timeout: float = 5.0,
                      cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if authorization.target != target or not target.startswith("hermes-profile-invoke:"):
            raise AuthorityDenied("effect.binding", "profile start target does not match its host grant")
        required = {"schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root", "cwd", "data_root", "argv", "env_allowlist", "child_artifact_refs", "max_lifetime_seconds", "max_output_bytes", "stdin_mode"}
        if not isinstance(launch, Mapping) or set(launch) != required or launch.get("schema") != 1 or launch.get("target") != target:
            raise AuthorityDenied("effect.launch", "profile launch envelope is malformed")
        argv = launch.get("argv")
        environment = launch.get("env_allowlist")
        child_refs = launch.get("child_artifact_refs")
        if (not isinstance(argv, list) or not argv or len(argv) > 128
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096 for arg in argv)
                or not isinstance(environment, Mapping)
                or not isinstance(child_refs, Mapping) or len(child_refs) > 64
                or any(not isinstance(k, str) or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", k)
                       or not isinstance(v, str) or k.rsplit(":", 1)[-1] != v
                       or not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in child_refs.items())
                or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in environment.items())):
            raise AuthorityDenied("effect.bounds", "profile launch arguments or environment are invalid")
        if (type(launch.get("max_lifetime_seconds")) is not int
                or not 1 <= launch["max_lifetime_seconds"] <= 600
                or type(launch.get("max_output_bytes")) is not int
                or not 1 <= launch["max_output_bytes"] <= 4 * 1024 * 1024
                or launch.get("stdin_mode") not in {"closed", "pipe"}):
            raise AuthorityDenied("effect.bounds", "profile launch resource bounds are invalid")
        # Credential-looking environment keys and values are never accepted.
        if any(any(mark in key.casefold() for mark in ("token", "secret", "password", "key")) for key in environment):
            raise AuthorityDenied("effect.secret", "profile launch environment contains a credential field")
        payload = canonical_bytes(launch)
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "profile launch envelope digest does not match its host grant")
        return self.perform_effect(authorization, operation="process.start", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def process_start_operation(
        self, authorization: EffectAuthorization, *, enrollment_id: str,
        generation: str, operation_id: str, parameters: Mapping[str, Any],
        timeout: float = 5.0, cancelled: Callable[[], bool] | None = None,
    ) -> BrokeredEffectResponse:
        """Request one protected launch recipe using selection-only parameters.

        Executable, roots, cwd, argv recipe, environment, and resource bounds
        are resolved by the enrolled root handler. This request intentionally
        carries no caller paths, command line, or environment.
        """
        if (not isinstance(authorization, EffectAuthorization)
                or authorization.operation != "process.start"
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", enrollment_id)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", generation)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation_id)
                or not isinstance(parameters, Mapping) or len(parameters) > 64):
            raise AuthorityDenied("effect.launch", "protected process operation selection is malformed")
        payload = canonical_bytes({"schema": 1, "enrollment_id": enrollment_id,
                                   "generation": generation, "operation_id": operation_id,
                                   "parameters": dict(parameters)})
        if (canonical_digest(payload) != authorization.request_digest
                or not authorization.target or "\x00" in authorization.target
                or any(not isinstance(value, (str, int, bool)) or isinstance(value, float)
                       for value in parameters.values())):
            raise AuthorityDenied("effect.binding", "process selection does not match its host grant")
        return self.perform_effect(authorization, operation="process.start", payload=payload,
                                   timeout=min(timeout, 30.0), cancelled=cancelled)

    def start_enrolled_process_operation(
        self, *, enrollment_id: str, generation: str, operation_id: str,
        parameters: Mapping[str, Any], purpose: str = "selected-process-operation",
        intent: str | None = None, timeout: float = 30.0,
        cancelled: Callable[[], bool] | None = None,
    ) -> BrokeredEffectResponse:
        """Start one root-selected process recipe without exposing its target.

        The authority resolves the target from protected enrollment while
        issuing the exact grant. Callers provide only the opaque selection and
        values checked against the enrolled parameter schema.
        """
        if (not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", enrollment_id)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", generation)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation_id)
                or not isinstance(parameters, Mapping) or len(parameters) > 64
                or any(not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", key)
                       or not isinstance(value, (str, int, bool)) or isinstance(value, float)
                       for key, value in parameters.items())
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= 30.0):
            raise AuthorityDenied("effect.launch", "protected process operation selection is malformed")
        body = {"schema": 1, "enrollment_id": enrollment_id,
                "generation": generation, "operation_id": operation_id,
                "parameters": dict(parameters)}
        payload = canonical_bytes(body)
        digest = canonical_digest(payload)
        context = self.context(
            purpose=purpose,
            intent=intent or f"process-start:{enrollment_id}:{generation}:{operation_id}",
            operation="process.start", final_payload_digest=digest,
            lease_seconds=min(float(timeout), 30.0), cancelled=cancelled,
        )
        result = self._rpc("authorize_process_start", {
            "context": context.to_wire(), "enrollment_id": enrollment_id,
            "generation": generation, "operation_id": operation_id,
            "request_digest": digest, "retry_index": 0,
        }, timeout=min(self.timeout, float(timeout)), cancelled=cancelled)
        authorization = EffectAuthorization.from_wire(result)
        if (authorization.operation != "process.start"
                or authorization.capability != "hermes-profile-invoke"
                or authorization.request_digest != digest
                or not authorization.target):
            raise AuthorityDenied("effect.binding", "authority returned a mismatched selected process grant")
        return self.process_start_operation(
            authorization, enrollment_id=enrollment_id, generation=generation,
            operation_id=operation_id, parameters=parameters,
            timeout=min(float(timeout), 30.0), cancelled=cancelled,
        )

    def process_control(self, authorization: EffectAuthorization, *, operation: str,
                        target: str, payload: bytes, timeout: float = 5.0,
                        cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if operation not in {"process.status", "process.read", "process.write", "process.stop", "process.inspect"}:
            raise AuthorityDenied("effect.operation", "process control verb is not fixed")
        target_valid = (target.startswith("hermes-profile-control:")
                        if operation != "process.inspect" else bool(re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}:inspect", target)))
        if authorization.target != target or not target_valid:
            raise AuthorityDenied("effect.binding", "process control target does not match its host grant")
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "process control payload digest does not match grant")
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def process_control_operation(self, operation: str, *, process_id: str,
                                  generation: str, fields: Mapping[str, Any] | None = None,
                                  timeout: float = 5.0,
                                  cancelled: Callable[[], bool] | None = None) -> ProcessControlResponse:
        """Ask root to resolve the live handle and perform one fixed control.

        This is a single root RPC; callers provide no target, context,
        capability, or grant. The root resolves all authorization bindings
        from the active process registry and protected enrollment.
        """
        from .process_controls import process_control_operation
        return process_control_operation(
            self, operation, process_id=process_id, generation=generation,
            fields=fields, timeout=timeout, cancelled=cancelled,
        )

    def inspect_profile_process(self, process_id: str, generation: str, *,
                                timeout: float = 5.0,
                                cancelled: Callable[[], bool] | None = None) -> ProcessControlResponse:
        """Inspect through root's live process-handle resolver, never caller-derived targets."""
        return self.process_control_operation(
            "process.inspect", process_id=process_id, generation=generation,
            fields={}, timeout=timeout, cancelled=cancelled,
        )

    def fetch_artifact(self, authorization: EffectAuthorization, *, target: str,
                       artifact_id: str, sha256: str, max_bytes: int,
                       timeout: float = 30.0,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Fetch a root-enrolled immutable artifact; callers cannot supply URLs or paths."""
        if (target != f"artifact:{artifact_id}:{sha256}"
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact_id)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or type(max_bytes) is not int or not 1 <= max_bytes <= 8 * 1024 * 1024 * 1024):
            raise AuthorityDenied("artifact.binding", "artifact identity or size bound is invalid")
        payload = canonical_bytes({"schema": 1, "artifact_id": artifact_id,
                                   "sha256": sha256, "max_bytes": max_bytes})
        if authorization.target != target or canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("artifact.binding", "artifact request does not match its host grant")
        return self.perform_effect(authorization, operation="artifact.fetch", payload=payload,
                                   timeout=min(timeout, MAX_TIMEOUT), cancelled=cancelled)

    def install_package(self, authorization: EffectAuthorization, *, target: str,
                        package_id: str, version: str, artifact_sha256: str,
                        timeout: float = 30.0,
                        cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Install only a root-enrolled pinned package through the host installer identity."""
        if (target != f"package:{package_id}:{version}:{artifact_sha256}"
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", package_id)
                or not re.fullmatch(r"[A-Za-z0-9+_.-]{1,128}", version)
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)):
            raise AuthorityDenied("package.binding", "package identity or pinned artifact is invalid")
        payload = canonical_bytes({"schema": 1, "package_id": package_id,
                                   "version": version, "artifact_sha256": artifact_sha256})
        if authorization.target != target or canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("package.binding", "package request does not match its host grant")
        return self.perform_effect(authorization, operation="package.install", payload=payload,
                                   timeout=min(timeout, MAX_TIMEOUT), cancelled=cancelled)

    def install_package_set(
        self, authorization: EffectAuthorization, *, package_set_id: str,
        manifest_sha256: str, enrollment_id: str, generation: str,
        timeout: float = 600.0, cancelled: Callable[[], bool] | None = None,
    ) -> BrokeredEffectResponse:
        """Install one signed root-enrolled offline package set.

        The manifest controls the runtime, exact wheel IDs/hashes and venv.
        The client sends only the opaque selection IDs; it cannot provide paths,
        package names, URLs, pip flags, or requirements.
        """
        if (not isinstance(authorization, EffectAuthorization)
                or authorization.operation != "package.install"
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", package_set_id)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest_sha256)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", enrollment_id)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", generation)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= MAX_TIMEOUT):
            raise AuthorityDenied("package.binding", "protected package-set selection is malformed")
        target = f"package-set:{package_set_id}:{manifest_sha256}"
        payload = canonical_bytes({"schema": 1, "package_set_id": package_set_id,
                                   "enrollment_id": enrollment_id, "generation": generation})
        if (authorization.target != target or canonical_digest(payload) != authorization.request_digest):
            raise AuthorityDenied("package.binding", "package-set request does not match its host grant")
        return self.perform_effect(authorization, operation="package.install", payload=payload,
                                   timeout=min(float(timeout), MAX_TIMEOUT), cancelled=cancelled)

    @staticmethod
    def _check_binding(grant: EffectAuthorization, target: str, recipient: str | None, digest: str) -> None:
        if (grant.target != target or grant.recipient != recipient or grant.request_digest != digest):
            raise AuthorityDenied("effect.binding", "effect request does not match its host grant")

    def _rpc(self, operation: str, payload: Mapping[str, Any], *, timeout: float | None = None,
             cancelled: Callable[[], bool] | None = None) -> Any:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AuthorityDenied("authority.unavailable", "authenticated Unix peer credentials are unavailable")
        deadline = self.monotonic() + (self.timeout if timeout is None else timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(0.01, deadline - self.monotonic()))
            self._check_socket_path()
            sock.connect(str(self.socket_path))
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            if uid != self.server_uid:
                raise AuthorityDenied("authority.peer", "authority service peer UID mismatch")
            hello = self._exchange(sock, {"version": 1, "operation": "hello"}, deadline, cancelled=cancelled)
            if not isinstance(hello, dict) or set(hello) != {"version", "server_nonce"} or hello["version"] != 1:
                raise AuthorityDenied("authority.protocol", "authority handshake is invalid")
            nonce = hello["server_nonce"]
            if not isinstance(nonce, str) or not 32 <= len(nonce) <= 128:
                raise AuthorityDenied("authority.protocol", "authority handshake is invalid")
            request = {"version": 1, "operation": operation, "server_nonce": nonce,
                       "client_nonce": secrets.token_urlsafe(32), "payload": payload}
            response = self._exchange(sock, request, deadline, cancelled=cancelled)
            if not isinstance(response, dict) or set(response) != {"version", "server_nonce", "result", "error"}:
                raise AuthorityDenied("authority.protocol", "authority response is malformed")
            if response["version"] != 1 or response["server_nonce"] != nonce:
                raise AuthorityDenied("authority.protocol", "authority response binding mismatch")
            if response["error"] is not None:
                error = response["error"]
                if not isinstance(error, dict) or set(error) != {"code", "message"}:
                    raise AuthorityDenied("authority.protocol", "authority denial is malformed")
                raise AuthorityDenied(str(error["code"]), str(error["message"]))
            return response["result"]
        except AuthorityDenied:
            raise
        except (OSError, TimeoutError, ValueError, TypeError, json.JSONDecodeError):
            raise AuthorityDenied("authority.unavailable", "protected host authority is unavailable") from None
        finally:
            sock.close()

    def _exchange(self, sock: socket.socket, value: Mapping[str, Any], deadline: float,
                  cancelled: Callable[[], bool] | None = None) -> Any:
        wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(wire) > MAX_REQUEST:
            raise AuthorityDenied("authority.bounds", "authority request exceeds its bound")
        sock.settimeout(max(0.01, deadline - self.monotonic()))
        sock.sendall(wire)
        line = bytearray()
        while len(line) <= MAX_RESPONSE:
            if cancelled is not None and cancelled():
                raise AuthorityDenied("effect.cancelled", "brokered effect was cancelled")
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise AuthorityDenied("authority.timeout", "authority request exceeded its deadline")
            sock.settimeout(min(0.05, remaining))
            try:
                chunk = sock.recv(1)
            except TimeoutError:
                continue
            if not chunk:
                break
            if chunk == b"\n":
                try:
                    return strict_json_loads(line.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    raise AuthorityDenied("authority.protocol", "authority response is malformed") from None
            line.extend(chunk)
        raise AuthorityDenied("authority.bounds", "authority response is incomplete or oversized")

    def _check_socket_path(self) -> None:
        try:
            info = self.socket_path.lstat()
        except OSError:
            raise AuthorityDenied("authority.unavailable", "protected authority endpoint is unavailable") from None
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.server_uid
                or info.st_mode & 0o007
                or self.server_gid is not None and (info.st_gid != self.server_gid or not info.st_mode & 0o020)):
            raise AuthorityDenied("authority.endpoint", "authority endpoint ownership or mode is invalid")
        parent = self.socket_path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != self.server_uid or parent.st_mode & 0o022
                or self.server_uid == 0 and not parent.st_mode & 0o001):
            raise AuthorityDenied("authority.endpoint", "authority endpoint directory ownership or mode is invalid")
