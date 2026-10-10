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
import threading
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
_MAX_NATIVE_INPUT_BYTES = 1_048_576
_MAX_TRACKED_INPUT_CONVERSATIONS = 128
_CURRENT_TOOL_CALL_ID: ContextVar[str | None] = ContextVar("hermes_native_tool_call_id", default=None)
_CURRENT_NATIVE_TURN_HANDLE: ContextVar[str | None] = ContextVar("hermes_native_turn_handle", default=None)
_CURRENT_FINAL_RESPONSE: ContextVar[tuple[str, str] | None] = ContextVar(
    "hermes_native_final_response", default=None,
)
_CURRENT_MCP_RESULT: ContextVar[tuple[str, bytes, str] | None] = ContextVar(
    "hermes_native_mcp_result", default=None,
)
_native_result_lock = threading.RLock()
_pending_native_mcp_results: "OrderedDict[tuple[int, str], tuple[object, str, bytes, str]]" = OrderedDict()
_MAX_PENDING_NATIVE_MCP_RESULTS = 128
_initial_input_lock = threading.RLock()
_initial_input: tuple[str, str, int, str, float] | None = None
_initial_input_failed = False
_initial_input_messages: "OrderedDict[int, list[Any]]" = OrderedDict()


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


def read_selected_native_input(stream: Any) -> str:
    """Consume the root-queued stdin source only after the selected loader is ready.

    The endpoint returns an opaque peer-delivered source handle plus the digest
    and size of bytes already observed by root. It does not return prompt bytes
    or accept selectors. The selected task writes those same bytes on stdin;
    any mismatch prevents the first provider request.
    """
    global _initial_input, _initial_input_failed
    # A second/failed admission must not inherit a previous turn's lexical
    # completion handles, even if this process unexpectedly stays alive.
    _CURRENT_NATIVE_TURN_HANDLE.set(None)
    _CURRENT_FINAL_RESPONSE.set(None)
    with _initial_input_lock:
        _initial_input_failed = True
    try:
        from hermes_installer.native_plugin_loader import ensure_selected_native_plugins_ready
        ensure_selected_native_plugins_ready()
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process(timeout=5.0)
        take = getattr(authority, "take_selected_native_input", None)
        if not callable(take):
            raise ValueError("native input delivery API is unavailable")
        delivery = take()
        if delivery is None:
            raise ValueError("native input delivery is pending")
        if isinstance(delivery, Mapping):
            base_fields = {
                "schema", "source_receipt_handle", "selected_execution_handle",
                "input_sha256", "input_size_bytes", "expires_monotonic",
            }
            if set(delivery) not in (base_fields, base_fields | {"turn_handle"}):
                raise ValueError("native input delivery shape is invalid")
            schema = delivery["schema"]
            receipt = delivery["source_receipt_handle"]
            execution = delivery["selected_execution_handle"]
            digest = delivery["input_sha256"]
            size = delivery["input_size_bytes"]
            expires = delivery["expires_monotonic"]
            turn_handle = delivery.get("turn_handle")
        else:
            schema = getattr(delivery, "schema", None)
            receipt = getattr(delivery, "source_receipt_handle", None)
            execution = getattr(delivery, "selected_execution_handle", None)
            digest = getattr(delivery, "input_sha256", None)
            size = getattr(delivery, "input_size_bytes", None)
            expires = getattr(delivery, "expires_monotonic", None)
            turn_handle = getattr(delivery, "turn_handle", None)
        if (type(schema) is not int or schema != 1
                or not isinstance(receipt, str) or not _OPAQUE.fullmatch(receipt)
                or not isinstance(execution, str) or not _OPAQUE.fullmatch(execution)
                or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                or type(size) is not int or not 1 <= size <= _MAX_NATIVE_INPUT_BYTES
                or isinstance(expires, bool) or type(expires) not in (int, float)
                or not time.monotonic() < float(expires) <= time.monotonic() + 30.0
                or (turn_handle is not None
                    and (not isinstance(turn_handle, str) or not _OPAQUE.fullmatch(turn_handle)))
                or not callable(getattr(stream, "read", None))):
            raise ValueError("native input delivery is invalid or expired")
        raw = stream.read(size + 1)
        if (not isinstance(raw, bytes) or len(raw) != size
                or hashlib.sha256(raw).hexdigest() != digest):
            raise ValueError("stdin differs from the root-observed input")
        text = raw.decode("utf-8-sig", errors="replace")
        with _initial_input_lock:
            if _initial_input is not None:
                raise ValueError("another selected input is still active")
            _initial_input = (receipt, digest, size, text, float(expires))
            _initial_input_failed = False
        _CURRENT_NATIVE_TURN_HANDLE.set(turn_handle)
        _CURRENT_FINAL_RESPONSE.set(None)
        return text
    except NativeInvocationUnavailable:
        raise
    except Exception:
        raise NativeInvocationUnavailable(
            "selected native input could not be verified against root admission",
        ) from None


def _attach_selected_input_source(messages: Any) -> None:
    """Attach the root handle to message ancestry only when its user text is present."""
    if not isinstance(messages, list):
        return
    with _initial_input_lock:
        if _initial_input_failed:
            raise NativeInvocationUnavailable("selected native input admission failed")
        initial = _initial_input
        if initial is None:
            return
        receipt, _digest, _size, expected_text, expires = initial
        if time.monotonic() >= expires:
            return
        key = id(messages)
        if _initial_input_messages.get(key) is messages:
            _initial_input_messages.move_to_end(key)
            return
        matched = any(
            isinstance(row, Mapping) and row.get("role") == "user"
            and type(row.get("content")) is str and row.get("content") == expected_text
            for row in messages
        )
        if not matched:
            return
        try:
            from hermes_installer.native_boundary import _save_receipt
            _save_receipt(messages, receipt)
        except Exception:
            raise NativeInvocationUnavailable("root input ancestry could not be attached") from None
        _initial_input_messages[key] = messages
        while len(_initial_input_messages) > _MAX_TRACKED_INPUT_CONVERSATIONS:
            _initial_input_messages.popitem(last=False)


def prepare_native_provider_request(kwargs: Mapping[str, Any], *, purpose: str) -> dict[str, Any]:
    """Attach selected input ancestry before the existing per-attempt broker hook."""
    messages = kwargs.get("messages") if isinstance(kwargs, Mapping) else None
    try:
        _attach_selected_input_source(messages)
        from hermes_installer.native_boundary import prepare_provider_request
        return prepare_provider_request(kwargs, purpose=purpose)
    except Exception:
        if isinstance(messages, list):
            try:
                from hermes_installer.native_boundary import _block_conversation
                _block_conversation(messages)
            except Exception:
                pass
        raise


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
        input_schema = schema.get("parameters") if isinstance(schema, dict) else None
        if (not isinstance(input_schema, Mapping) or type(arguments) is not dict
                or schema.get("name") != getattr(registration, "native_tool_name", None)):
            raise ValueError("native MCP arguments must be a JSON object")
        # Sol's index digest domain is the argument schema only, encoded as
        # canonical UTF-8 JSON with ensure_ascii=False.  The Hermes envelope
        # also contains description/name and is not part of that pin.
        schema_bytes = json.dumps(input_schema, ensure_ascii=False, sort_keys=True,
                                  separators=(",", ":"), allow_nan=False).encode("utf-8")
        if (len(schema_bytes) > _MAX_NATIVE_MCP_ARGUMENT_BYTES
                or hashlib.sha256(schema_bytes).hexdigest() != schema_digest):
            raise ValueError("protected MCP argument-schema pin differs")
        _validate_schema(input_schema)
        _validate_value(arguments, input_schema)
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
        source_handle = getattr(response, "source_receipt_handle", None)
        tool_call_id = _CURRENT_TOOL_CALL_ID.get()
        if (not isinstance(source_handle, str) or not _OPAQUE.fullmatch(source_handle)
                or not isinstance(tool_call_id, str) or not tool_call_id
                or _CURRENT_MCP_RESULT.get() is not None):
            raise ValueError("root MCP result has no unique peer-delivered source receipt")
        result = body.decode("utf-8", errors="strict")
        _CURRENT_MCP_RESULT.set((native_tool_name, body, source_handle))
    except Exception:
        raise NativeInvocationUnavailable("root native MCP dispatch was denied or unavailable") from None
    return result


def _normalized_tool_call_id(value: Any) -> str | None:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(ord(char) < 0x20 for char in value)):
        return None
    return value


def _store_pending_native_mcp_result(agent: object, tool_call_id: str,
                                     result: tuple[str, bytes, str]) -> None:
    call_id = _normalized_tool_call_id(tool_call_id)
    if call_id is None:
        raise NativeInvocationUnavailable("native MCP result has no provider call identity")
    name, body, handle = result
    key = (id(agent), call_id)
    with _native_result_lock:
        for existing_key, (existing_agent, *_rest) in tuple(_pending_native_mcp_results.items()):
            if existing_key[0] == id(agent) and existing_agent is not agent:
                _pending_native_mcp_results.pop(existing_key, None)
        if key in _pending_native_mcp_results or len(_pending_native_mcp_results) >= _MAX_PENDING_NATIVE_MCP_RESULTS:
            raise NativeInvocationUnavailable("pending native MCP result capacity was exceeded")
        _pending_native_mcp_results[key] = (agent, name, body, handle)


def record_native_tool_result(agent: object, messages: list[Any], message: Mapping[str, Any],
                              function_result: Any) -> None:
    """Attach a root MCP result receipt only after the exact result is inserted.

    The root receipt is already bound to the scrubbed MCP body and current
    invocation. This boundary verifies that Hermes received the same bytes and
    that its pinned result formatter produced the inserted ToolMessage, then
    consumes the root's peer-delivery handle once. Other tools keep the existing
    fail-closed generic capture behavior.
    """
    from hermes_installer.native_boundary import _block_conversation, _save_receipt, record_tool_result

    call_id = _normalized_tool_call_id(message.get("tool_call_id")) if isinstance(message, Mapping) else None
    key = (id(agent), call_id) if call_id is not None else None
    with _native_result_lock:
        pending = _pending_native_mcp_results.pop(key, None) if key is not None else None
        if pending is not None and pending[0] is not agent:
            pending = None
    if pending is None:
        record_tool_result(messages, message)
        return
    _owner, expected_name, expected_body, handle = pending
    try:
        if (not isinstance(messages, list) or not isinstance(message, Mapping)
                or not any(item is message for item in messages)
                or type(function_result) is not str
                or function_result.encode("utf-8", errors="strict") != expected_body
                or message.get("tool_name") != expected_name
                or message.get("name") != expected_name
                or _normalized_tool_call_id(message.get("tool_call_id")) != call_id
                or not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)):
            raise ValueError
        # Re-run only the pinned deterministic presentation transforms. This
        # rejects persistence, truncation, hints, or any other change between
        # the broker result and the actual model-visible ToolMessage.
        from agent.tool_dispatch_helpers import _maybe_append_elision_notice, _maybe_wrap_untrusted
        model_content = agent._tool_result_content_for_active_model(expected_name, function_result)
        expected_content = _maybe_wrap_untrusted(
            expected_name, _maybe_append_elision_notice(expected_name, model_content),
        )
        if message.get("content") != expected_content:
            raise ValueError
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process(timeout=5.0)
        take = getattr(authority, "take_source_receipt", None)
        if not callable(take) or take(handle) != handle:
            raise ValueError
        _save_receipt(messages, handle)
    except Exception:
        _block_conversation(messages)


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
        turn_fields = {"turn_handle", "final_response_delivery_handle"}
        if set(metadata) not in (required, required | turn_fields):
            raise NativeInvocationUnavailable("root returned malformed provider-response metadata")
        producer = metadata["producer_context_handle"]
        rows = metadata["tool_call_bindings"]
        turn_handle = metadata.get("turn_handle")
        final_response_delivery_handle = metadata.get("final_response_delivery_handle")
    else:
        producer = getattr(metadata, "producer_context_handle", None)
        rows = getattr(metadata, "tool_call_bindings", None)
        turn_handle = getattr(metadata, "turn_handle", None)
        final_response_delivery_handle = getattr(metadata, "final_response_delivery_handle", None)
    if not isinstance(rows, (tuple, list)):
        raise NativeInvocationUnavailable("root response metadata does not match the captured response")
    if (turn_handle is not None and
            (not isinstance(turn_handle, str) or not _OPAQUE.fullmatch(turn_handle))):
        raise NativeInvocationUnavailable("root response turn handle is malformed")
    if (final_response_delivery_handle is not None and
            (not isinstance(final_response_delivery_handle, str)
             or not _OPAQUE.fullmatch(final_response_delivery_handle))):
        raise NativeInvocationUnavailable("root final response delivery handle is malformed")
    active_turn = _CURRENT_NATIVE_TURN_HANDLE.get()
    if (turn_handle is not None and turn_handle == active_turn
            and final_response_delivery_handle is not None):
        _CURRENT_FINAL_RESPONSE.set((turn_handle, final_response_delivery_handle))
    else:
        # A non-final/mismatched response cannot complete the active turn.
        _CURRENT_FINAL_RESPONSE.set(None)
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


def finish_selected_native_turn(agent: object, terminal_result: object) -> None:
    """Ask root to finish only from a successful pinned-facade return.

    The return value is never sent. Root validates its retained event closure;
    this worker-side gate only avoids completion calls for failed turns. Missing
    v70 DTO/client fields leave capture pending.
    """
    turn_handle = _CURRENT_NATIVE_TURN_HANDLE.get()
    final_response = _CURRENT_FINAL_RESPONSE.get()
    _CURRENT_FINAL_RESPONSE.set(None)
    if (not isinstance(terminal_result, Mapping)
            or terminal_result.get("interrupted") is True
            or terminal_result.get("failed") is True
            or turn_handle is None or final_response is None
            or final_response[0] != turn_handle):
        return
    try:
        from hermes_installer.authority.client import AuthorityClient
        authority = AuthorityClient.for_current_process(timeout=5.0)
        finish = getattr(authority, "finish_selected_native_turn", None)
        if callable(finish):
            finish(turn_handle, final_response[1])
    except Exception:
        # A denied/incomplete root observation stays pending without changing
        # the actual Hermes response or emitting evidence to the model.
        return


def clear_native_turn_scope() -> None:
    """Clear delivered turn and response metadata on every facade exit path."""
    _CURRENT_FINAL_RESPONSE.set(None)
    _CURRENT_NATIVE_TURN_HANDLE.set(None)


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
    call_token = _CURRENT_TOOL_CALL_ID.set(tool_call_id)
    result_token = _CURRENT_MCP_RESULT.set(None)
    call_token = _CURRENT_TOOL_CALL_ID.set(tool_call_id)
    result_token = _CURRENT_MCP_RESULT.set(None)
    try:
        with begin_observed_tool_invocation(
            agent, authority, tool_call_id=tool_call_id, tool_name=tool_name, arguments=arguments,
        ):
            result = execute()
            pending_result = _CURRENT_MCP_RESULT.get()
        if pending_result is not None:
            _store_pending_native_mcp_result(agent, tool_call_id, pending_result)
        return result
    finally:
        _CURRENT_MCP_RESULT.reset(result_token)
        _CURRENT_TOOL_CALL_ID.reset(call_token)
