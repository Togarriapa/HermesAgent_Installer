"""Lexical bridge from pinned Hermes tool dispatch to root invocation records.

This module stores only root-issued opaque call handles. The provider response
adapter installs them after the root response observer has validated its peer
channel; the actual Hermes dispatch hook checks the observed call ID, tool name
and canonical post-middleware arguments before asking Authority to begin the
one-use invocation. Missing metadata leaves the lexical scope empty, which
causes the selected native effect facade to deny.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from collections import OrderedDict
from dataclasses import dataclass
import hashlib
import json
import re
import sys
import time
from typing import Any, Iterator, Mapping


_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_BINDINGS = 128
_MAX_SEEN_RESPONSES = 256
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_RESPONSE_REF = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_NATIVE_MCP_ADAPTER_ID = "hermes-installer.native-mcp-dispatch.v1"
_MAX_NATIVE_MCP_ARGUMENT_BYTES = 1_048_576
_MAX_NATIVE_MCP_RESULT_BYTES = 2 * 1024 * 1024


def _thaw_native_mcp_schema(value: Any, *, depth: int = 0, budget: list[int] | None = None) -> Any:
    """Convert immutable schema mappings into bounded plain JSON values."""
    if budget is None:
        budget = [16_384]
    budget[0] -= 1
    if budget[0] < 0 or depth > 16:
        raise ValueError("native MCP schema exceeds its structural bound")
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if type(key) is not str or key in result:
                raise ValueError("native MCP schema contains an invalid key")
            result[key] = _thaw_native_mcp_schema(item, depth=depth + 1, budget=budget)
        return result
    if type(value) in (list, tuple):
        return [_thaw_native_mcp_schema(item, depth=depth + 1, budget=budget) for item in value]
    if value is None or type(value) in (str, bool, int, float):
        return value
    raise ValueError("native MCP schema contains a non-JSON value")


class NativeInvocationUnavailable(PermissionError):
    """No exact root-observed invocation is available for this tool call."""


@dataclass(frozen=True, slots=True)
class ObservedToolCall:
    """Root-issued call binding delivered out-of-band with a provider response."""

    producer_context_handle: str
    observed_call_handle: str
    provider_tool_call_id: str
    tool_name: str
    arguments_sha256: str


_CURRENT_BINDING: ContextVar[Any | None] = ContextVar("hermes_native_invocation_binding", default=None)


def current_native_invocation_binding() -> Any | None:
    """Return the binding only inside the exact synchronous tool dispatch scope."""
    return _CURRENT_BINDING.get()


def canonical_tool_arguments(arguments: Mapping[str, Any]) -> bytes:
    """Canonical JSON for the exact argument mapping Hermes will dispatch."""
    if not isinstance(arguments, Mapping):
        raise NativeInvocationUnavailable("Hermes tool arguments are not a JSON object")
    try:
        return json.dumps(arguments, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise NativeInvocationUnavailable("Hermes tool arguments are not canonical JSON") from None


def dispatch_native_mcp_tool_call(authority: Any, registration: Any,
                                  arguments: Mapping[str, Any]) -> str:
    """Dispatch one protected in-process MCP tool under its lexical root binding.

    ``registration`` must be a root-selected ``NativeMCPToolBinding`` presented
    by the protected MCP registration index.  It is a local selector only: no
    service, target, resource, or endpoint fields are sent over the RPC.  The
    root resolves those fields again from the invocation handle and current
    enrollment before performing the effect.
    """
    binding = current_native_invocation_binding()
    if binding is None:
        raise NativeInvocationUnavailable("native MCP call has no current root invocation")
    try:
        from hermes_installer.mcp.client import _validate_schema, _validate_value
        frozen_schema = getattr(registration, "native_schema", None)
        schema_digest = getattr(registration, "native_schema_sha256", None)
        if (not isinstance(frozen_schema, Mapping) or not isinstance(schema_digest, str)
                or not _SHA256.fullmatch(schema_digest)):
            raise ValueError("protected MCP schema is unavailable")
        schema = _thaw_native_mcp_schema(frozen_schema)
        schema_bytes = json.dumps(schema, ensure_ascii=True, sort_keys=True,
                                  separators=(",", ":"), allow_nan=False).encode("ascii")
        if hashlib.sha256(schema_bytes).hexdigest() != schema_digest:
            raise ValueError("protected MCP schema pin differs")
        if type(arguments) is not dict:
            raise ValueError("native MCP arguments must be a JSON object")
        _validate_schema(schema)
        _validate_value(arguments, schema)
        arguments_bytes = canonical_tool_arguments(arguments)
        if len(arguments_bytes) > _MAX_NATIVE_MCP_ARGUMENT_BYTES:
            raise ValueError("native MCP arguments exceed their bound")
        expected = {
            "adapter_id": _NATIVE_MCP_ADAPTER_ID,
            "action_id": getattr(registration, "id", None),
            "package_id": getattr(registration, "native_package_id", None),
            "generation": getattr(registration, "native_package_generation", None),
            "profile_id": getattr(registration, "profile_id", None),
        }
        actual = {
            "adapter_id": getattr(binding, "adapter_id", None),
            "action_id": getattr(binding, "action_id", None),
            "package_id": getattr(binding, "package_id", None),
            "generation": getattr(binding, "generation", None),
            "profile_id": getattr(binding, "profile_id", None),
        }
        native_tool_name = getattr(registration, "native_tool_name", None)
        if (any(not isinstance(value, str) or not value for value in expected.values())
                or not isinstance(native_tool_name, str) or not native_tool_name
                or actual != expected):
            raise ValueError("native MCP registration does not match the root invocation")
        arguments_digest = hashlib.sha256(arguments_bytes).hexdigest()
        if getattr(binding, "arguments_sha256", None) != arguments_digest:
            raise ValueError("native MCP arguments differ from the root-observed invocation")
    except NativeInvocationUnavailable:
        raise
    except Exception:
        raise NativeInvocationUnavailable("native MCP registration or arguments were rejected") from None

    dispatch = getattr(authority, "dispatch_native_mcp", None)
    invocation_handle = getattr(binding, "invocation_handle", None)
    if not callable(dispatch) or not isinstance(invocation_handle, str) or not _OPAQUE.fullmatch(invocation_handle):
        raise NativeInvocationUnavailable("root native MCP dispatch is unavailable")
    try:
        response = dispatch(invocation_handle, arguments_bytes)
        status = getattr(response, "status", None)
        body = getattr(response, "body", None)
        if (type(status) is not int or not 200 <= status < 300
                or not isinstance(body, bytes) or not 1 <= len(body) <= _MAX_NATIVE_MCP_RESULT_BYTES):
            raise ValueError("root returned a bounded MCP dispatch failure")
        result = body.decode("utf-8", errors="strict")
    except Exception:
        raise NativeInvocationUnavailable("root native MCP dispatch was denied or unavailable") from None
    return result


def parse_observed_tool_calls(raw: object) -> tuple[ObservedToolCall, ...]:
    """Validate the exact root response metadata shape without interpreting it as authority."""
    if isinstance(raw, Mapping):
        if set(raw) != {"producer_context_handle", "tool_call_bindings"}:
            raise NativeInvocationUnavailable("root provider-response metadata is missing or malformed")
        producer, rows = raw["producer_context_handle"], raw["tool_call_bindings"]
    else:
        producer = getattr(raw, "producer_context_handle", None)
        rows = getattr(raw, "tool_call_bindings", None)
        if isinstance(rows, tuple):
            rows = list(rows)
    if (not isinstance(producer, str) or not _OPAQUE.fullmatch(producer)
            or not isinstance(rows, list) or len(rows) > _MAX_BINDINGS):
        raise NativeInvocationUnavailable("root provider-response metadata exceeds its bounds")
    parsed: list[ObservedToolCall] = []
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, Mapping):
            if set(row) != {
                "observed_call_handle", "provider_tool_call_id", "tool_name", "arguments_sha256",
            }:
                raise NativeInvocationUnavailable("root tool-call binding is malformed")
            handle, call_id, tool_name, digest = (
                row["observed_call_handle"], row["provider_tool_call_id"],
                row["tool_name"], row["arguments_sha256"],
            )
        else:
            handle, call_id, tool_name, digest = (
                getattr(row, "observed_call_handle", None),
                getattr(row, "provider_tool_call_id", None),
                getattr(row, "tool_name", None),
                getattr(row, "arguments_sha256", None),
            )
        if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                or not isinstance(call_id, str) or not 1 <= len(call_id) <= 256
                or any(ord(char) < 0x20 for char in call_id)
                or not isinstance(tool_name, str) or not 1 <= len(tool_name) <= 256
                or any(ord(char) < 0x20 for char in tool_name)
                or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                or call_id in seen):
            raise NativeInvocationUnavailable("root tool-call binding is invalid or duplicated")
        seen.add(call_id)
        parsed.append(ObservedToolCall(producer, handle, call_id, tool_name, digest))
    return tuple(parsed)


def install_observed_tool_calls(agent: object, metadata: object) -> None:
    """Store out-of-band response bindings for the next actual Hermes tool dispatch.

    The caller must be the provider response boundary after the root-selected
    gateway has authenticated the peer-bound observation channel. Call IDs are
    one-turn, removed before dispatch, and never copied into model arguments.
    """
    calls = parse_observed_tool_calls(metadata)
    if not hasattr(agent, "__dict__"):
        raise NativeInvocationUnavailable("Hermes agent cannot hold response-local call bindings")
    if getattr(agent, "_hermes_installer_observed_tool_calls", None):
        raise NativeInvocationUnavailable("previous root-observed tool-call bindings are still active")
    setattr(agent, "_hermes_installer_observed_tool_calls", {
        call.provider_tool_call_id: call for call in calls
    })


@dataclass(slots=True)
class _ProviderStreamCapture:
    response: Any
    native_request_handle: str
    chunks: bytearray
    completed_by_length: bool = False


def _response_header_values(headers: Any, name: str) -> list[str]:
    get_list = getattr(headers, "get_list", None)
    if not callable(get_list):
        raise NativeInvocationUnavailable("gateway response headers cannot be checked for duplicates")
    try:
        return list(get_list(name))
    except Exception:
        raise NativeInvocationUnavailable("gateway response metadata header is unavailable") from None


def _take_root_response_metadata(agent: object, *, response: Any, body: bytes,
                                 native_request_handle: str) -> None:
    """Take the root-held result only after hashing exact response entity bytes."""
    if (not isinstance(body, bytes) or not 1 <= len(body) <= _MAX_RESPONSE_BYTES
            or not isinstance(native_request_handle, str) or not _OPAQUE.fullmatch(native_request_handle)):
        raise NativeInvocationUnavailable("native provider response is incomplete or oversized")
    headers = getattr(response, "headers", None)
    refs = _response_header_values(headers, "x-hermes-native-response-ref")
    if len(refs) != 1 or not isinstance(refs[0], str) or not _RESPONSE_REF.fullmatch(refs[0]):
        raise NativeInvocationUnavailable("root provider-response lookup reference is missing or malformed")
    encodings = _response_header_values(headers, "content-encoding")
    if len(encodings) > 1 or (encodings and encodings[0].strip().lower() not in {"", "identity"}):
        raise NativeInvocationUnavailable("compressed provider responses are not supported")
    lengths = _response_header_values(headers, "content-length")
    if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0], re.ASCII)
            or int(lengths[0]) != len(body)):
        raise NativeInvocationUnavailable("provider response entity length is missing or incomplete")
    response_digest = hashlib.sha256(body).hexdigest()
    try:
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process(timeout=5.0)
        take = getattr(authority, "take_native_response_metadata", None)
        if not callable(take):
            raise NativeInvocationUnavailable("root provider-response metadata lookup is unavailable")
        metadata = take(refs[0], response_digest, native_request_handle)
    except NativeInvocationUnavailable:
        raise
    except Exception:
        raise NativeInvocationUnavailable("root rejected provider-response metadata lookup") from None

    if isinstance(metadata, Mapping):
        required = {"producer_context_handle", "tool_call_bindings"}
        if set(metadata) != required:
            raise NativeInvocationUnavailable("root returned malformed provider-response metadata")
        producer = metadata["producer_context_handle"]
        rows = metadata["tool_call_bindings"]
    else:
        producer = getattr(metadata, "producer_context_handle", None)
        rows = getattr(metadata, "tool_call_bindings", None)
    if not isinstance(rows, (tuple, list)):
        raise NativeInvocationUnavailable("root response metadata does not match the captured response")
    _install_once_per_provider_response(agent, {
        "producer_context_handle": producer,
        "tool_call_bindings": list(rows),
    })


def attach_provider_stream_capture(stream: object, native_request_handle: str) -> None:
    """Tee the SDK's dechunked, identity-encoded response entity without changing bytes."""
    response = getattr(stream, "response", None)
    original = getattr(response, "iter_bytes", None)
    if not callable(original):
        raise NativeInvocationUnavailable("pinned provider stream exposes no raw response entity")
    capture = _ProviderStreamCapture(response, native_request_handle, bytearray())

    def capture_iter_bytes(*args: Any, **kwargs: Any):
        try:
            for chunk in original(*args, **kwargs):
                if not isinstance(chunk, bytes) or len(capture.chunks) + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise NativeInvocationUnavailable("provider stream response exceeds its byte bound")
                capture.chunks.extend(chunk)
                yield chunk
        finally:
            lengths = _response_header_values(getattr(response, "headers", None), "content-length")
            capture.completed_by_length = (
                len(lengths) == 1 and re.fullmatch(r"[0-9]{1,10}", lengths[0], re.ASCII) is not None
                and int(lengths[0]) == len(capture.chunks)
            )

    try:
        response.iter_bytes = capture_iter_bytes
        setattr(stream, "_hermes_installer_provider_response_capture", capture)
    except Exception:
        raise NativeInvocationUnavailable("pinned provider stream cannot install bounded response capture") from None


def finish_provider_stream_response(agent: object, stream: object) -> None:
    capture = getattr(stream, "_hermes_installer_provider_response_capture", None)
    if not isinstance(capture, _ProviderStreamCapture) or not capture.completed_by_length:
        raise NativeInvocationUnavailable("provider stream ended before its exact response entity was captured")
    _take_root_response_metadata(
        agent, response=capture.response, body=bytes(capture.chunks),
        native_request_handle=capture.native_request_handle,
    )


def install_provider_response_tool_calls(agent: object, response: object,
                                         native_request_handle: str) -> None:
    """Capture a complete non-stream response and take its root-issued call bindings."""
    raw_response = getattr(response, "http_response", None)
    if raw_response is None:
        raise NativeInvocationUnavailable("pinned raw provider response is unavailable")
    try:
        body = raw_response.content
    except Exception:
        raise NativeInvocationUnavailable("provider response entity could not be read exactly") from None
    _take_root_response_metadata(agent, response=raw_response, body=body,
                                 native_request_handle=native_request_handle)


def _install_once_per_provider_response(agent: object, metadata: object) -> None:
    """Ignore repeated stream metadata while preventing post-dispatch replay."""
    calls = parse_observed_tool_calls(metadata)
    try:
        encoded = json.dumps({
            "producer_context_handle": calls[0].producer_context_handle if calls else metadata["producer_context_handle"],
            "tool_call_bindings": [{
                "observed_call_handle": call.observed_call_handle,
                "provider_tool_call_id": call.provider_tool_call_id,
                "tool_name": call.tool_name,
                "arguments_sha256": call.arguments_sha256,
            } for call in calls],
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, KeyError):
        raise NativeInvocationUnavailable("gateway response metadata is malformed") from None
    fingerprint = hashlib.sha256(encoded).hexdigest()
    seen = getattr(agent, "_hermes_installer_seen_provider_responses", None)
    if seen is None:
        seen = OrderedDict()
    if not isinstance(seen, OrderedDict):
        raise NativeInvocationUnavailable("Hermes provider response metadata state is malformed")
    if fingerprint in seen:
        seen.move_to_end(fingerprint)
        return
    if len(seen) >= _MAX_SEEN_RESPONSES:
        seen.popitem(last=False)
    # Install only after metadata parsing and capacity checks succeeded.
    install_observed_tool_calls(agent, metadata)
    seen[fingerprint] = None
    setattr(agent, "_hermes_installer_seen_provider_responses", seen)


def _is_selected_native_plugin_tool(tool_name: str) -> bool:
    """Inspect actual current Hermes registration ownership, never a model label."""
    try:
        module = sys.modules.get("hermes_cli.plugins")
        get_manager = getattr(module, "get_plugin_manager", None)
        if not callable(get_manager):
            return False
        manager = get_manager()
        selected = getattr(manager, "_hermes_installer_native_plugin_keys", ())
        if not isinstance(selected, (set, frozenset, tuple, list)):
            return False
        return any(
            (loaded := manager._plugins.get(plugin_id)) is not None
            and tool_name in getattr(loaded, "tools_registered", ())
            for plugin_id in selected
        )
    except Exception:
        return False


@contextmanager
def begin_observed_tool_invocation(agent: object, authority: Any, *,
                                   tool_call_id: str, tool_name: str,
                                   arguments: Mapping[str, Any]) -> Iterator[Any | None]:
    """Begin and lexically scope a root-registered invocation for this tool call.

    If the response had no root-observed binding, the scope remains empty for
    ordinary tools. A selected native plugin tool is rejected here before its
    handler runs.
    """
    mapping = getattr(agent, "_hermes_installer_observed_tool_calls", None)
    if not isinstance(mapping, dict) or not tool_call_id:
        if _is_selected_native_plugin_tool(tool_name):
            raise NativeInvocationUnavailable("selected native tool has no root-observed provider call binding")
        yield None
        return
    observed = mapping.pop(tool_call_id, None)
    if observed is None:
        if _is_selected_native_plugin_tool(tool_name):
            raise NativeInvocationUnavailable("selected native tool has no matching root-observed call")
        yield None
        return
    if (not isinstance(observed, ObservedToolCall)
            or observed.provider_tool_call_id != tool_call_id
            or observed.tool_name != tool_name):
        raise NativeInvocationUnavailable("provider call does not match its root observation")
    arguments_bytes = canonical_tool_arguments(arguments)
    arguments_digest = hashlib.sha256(arguments_bytes).hexdigest()
    if observed.arguments_sha256 != arguments_digest:
        raise NativeInvocationUnavailable("post-middleware arguments differ from the observed tool call")
    begin = getattr(authority, "begin_native_invocation", None)
    if not callable(begin):
        raise NativeInvocationUnavailable("root native invocation admission is unavailable")
    try:
        binding = begin(observed.producer_context_handle, observed.observed_call_handle, arguments_bytes)
    except Exception:
        raise NativeInvocationUnavailable("root native invocation admission was denied") from None
    binding_fields = (
        "package_id", "profile_id", "generation", "adapter_id", "action_id",
        "parent_closure_digest", "binding_sha256",
    )
    binding_handle = getattr(binding, "invocation_handle", None)
    binding_expiry = getattr(binding, "expires_monotonic", None)
    if (getattr(binding, "schema", None) != 1
            or not isinstance(binding_handle, str) or not _OPAQUE.fullmatch(binding_handle)
            or any(not isinstance(getattr(binding, field, None), str)
                   or not getattr(binding, field, None) for field in binding_fields)
            or not _SHA256.fullmatch(getattr(binding, "parent_closure_digest", ""))
            or not _SHA256.fullmatch(getattr(binding, "binding_sha256", ""))
            or getattr(binding, "arguments_sha256", None) != arguments_digest
            or isinstance(binding_expiry, bool) or type(binding_expiry) not in (int, float)
            or not time.monotonic() < binding_expiry <= time.monotonic() + 600):
        raise NativeInvocationUnavailable("root native invocation binding does not match the actual call")
    token: Token[Any | None] = _CURRENT_BINDING.set(binding)
    try:
        yield binding
    finally:
        _CURRENT_BINDING.reset(token)


def dispatch_observed_tool_call(agent: object, *, tool_call_id: str, tool_name: str,
                                arguments: Mapping[str, Any], execute: Any) -> Any:
    """Run actual Hermes dispatch under its root-issued invocation binding."""
    mapping = getattr(agent, "_hermes_installer_observed_tool_calls", None)
    if not isinstance(mapping, dict) or tool_call_id not in mapping:
        if _is_selected_native_plugin_tool(tool_name):
            raise NativeInvocationUnavailable("selected native tool has no root-observed provider call binding")
        return execute()
    try:
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process()
    except Exception:
        raise NativeInvocationUnavailable("host authority client is unavailable") from None
    with begin_observed_tool_invocation(
        agent, authority, tool_call_id=tool_call_id, tool_name=tool_name, arguments=arguments,
    ):
        return execute()
