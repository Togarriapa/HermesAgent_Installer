"""Strict root-side parsing of completed provider responses (HI08/HI11).

This module only recognizes tool calls in actual completed provider response
bytes. It never creates invocation handles or claims source authority; the root
native invocation registry binds these records to the enrolled producer and
request lineage before returning opaque metadata to Hermes.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping

from .codex_responses import completed_responses_object

MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TOOL_CALLS = 128
MAX_TOOL_ID_BYTES = 256
MAX_TOOL_NAME_BYTES = 256
MAX_ARGUMENT_BYTES = 256 * 1024


class ProviderResponseObservationDenied(PermissionError):
    """A provider response cannot safely establish root-observed calls."""


@dataclass(frozen=True, slots=True)
class ObservedProviderToolCall:
    provider_tool_call_id: str
    tool_name: str
    canonical_arguments: bytes
    arguments_sha256: str


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate JSON key")
        output[key] = value
    return output


def _json_object(raw: bytes, *, max_bytes: int) -> object:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= max_bytes:
        raise ProviderResponseObservationDenied("provider.response_bounds", "Provider response field exceeds its bound")
    try:
        return json.loads(raw, object_pairs_hook=_pairs_no_duplicates,
                          parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")))
    except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise ProviderResponseObservationDenied("provider.response_format", "Provider response field is malformed") from None


def _bounded_text(value: object, *, limit: int) -> bool:
    if (not isinstance(value, str) or not value
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= limit
    except UnicodeEncodeError:
        return False


def _canonical_arguments(value: object) -> bytes:
    if not isinstance(value, str):
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Provider tool arguments are not JSON text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Provider tool arguments are not valid UTF-8") from None
    if not 1 <= len(encoded) <= MAX_ARGUMENT_BYTES:
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Provider tool arguments exceed their bound")
    decoded = _json_object(encoded, max_bytes=MAX_ARGUMENT_BYTES)
    if not isinstance(decoded, dict):
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Provider tool arguments must be a JSON object")
    try:
        canonical = json.dumps(decoded, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Provider tool arguments cannot be canonicalized") from None
    if not 1 <= len(canonical) <= MAX_ARGUMENT_BYTES:
        raise ProviderResponseObservationDenied("provider.tool_arguments", "Canonical provider arguments exceed their bound")
    return canonical


def _bindings(raw_calls: object, *, codex: bool) -> tuple[ObservedProviderToolCall, ...]:
    if not isinstance(raw_calls, list) or len(raw_calls) > MAX_TOOL_CALLS:
        raise ProviderResponseObservationDenied("provider.tool_calls", "Provider tool call list is malformed or oversized")
    calls: list[ObservedProviderToolCall] = []
    seen: set[str] = set()
    for call in raw_calls:
        if not isinstance(call, dict):
            raise ProviderResponseObservationDenied("provider.tool_calls", "Provider tool call item is malformed")
        if codex:
            call_id, name, arguments = call.get("call_id"), call.get("name"), call.get("arguments")
            if call.get("type") != "function_call":
                raise ProviderResponseObservationDenied("provider.tool_calls", "Responses output contains an unsupported call")
        else:
            call_id = call.get("id")
            function = call.get("function")
            if call.get("type") != "function" or not isinstance(function, dict):
                raise ProviderResponseObservationDenied("provider.tool_calls", "Chat completion tool call is malformed")
            name, arguments = function.get("name"), function.get("arguments")
        if (not _bounded_text(call_id, limit=MAX_TOOL_ID_BYTES)
                or not _bounded_text(name, limit=MAX_TOOL_NAME_BYTES)
                or call_id in seen):
            raise ProviderResponseObservationDenied("provider.tool_calls", "Provider tool call identity is invalid or ambiguous")
        seen.add(call_id)
        canonical = _canonical_arguments(arguments)
        calls.append(ObservedProviderToolCall(call_id, name, canonical, hashlib.sha256(canonical).hexdigest()))
    return tuple(calls)


def parse_successful_provider_tool_calls(provider: str, status: int,
                                         headers: Mapping[str, str],
                                         response_bytes: bytes) -> tuple[ObservedProviderToolCall, ...]:
    """Extract bounded calls only from a complete successful native response.

    The caller is the root authority after fixed route dispatch; worker-supplied
    response JSON must never be passed to this function as observation proof.
    Invalid/incomplete terminal data raises and therefore creates no handles.
    """
    if (provider not in {"openrouter", "codex"} or type(status) is not int
            or not 200 <= status < 300 or not isinstance(headers, Mapping)
            or not isinstance(response_bytes, bytes)
            or not 1 <= len(response_bytes) <= MAX_RESPONSE_BYTES):
        raise ProviderResponseObservationDenied("provider.response_bounds", "Provider result is not a bounded successful response")
    content_types = [value for key, value in headers.items()
                     if isinstance(key, str) and key.casefold() == "content-type"]
    if len(content_types) != 1:
        raise ProviderResponseObservationDenied("provider.response_type", "Provider result content type is absent or ambiguous")
    content_type = content_types[0]
    if not isinstance(content_type, str) or "\r" in content_type or "\n" in content_type:
        raise ProviderResponseObservationDenied("provider.response_type", "Provider result content type is invalid")
    media_type = content_type.split(";", 1)[0].strip().casefold()
    if provider == "openrouter":
        if media_type != "application/json":
            raise ProviderResponseObservationDenied("provider.response_type", "OpenRouter result is not JSON")
        response = _json_object(response_bytes, max_bytes=MAX_RESPONSE_BYTES)
        if not isinstance(response, dict):
            raise ProviderResponseObservationDenied("provider.response_format", "OpenRouter result is not an object")
        choices = response.get("choices")
        if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
            raise ProviderResponseObservationDenied("provider.response_format", "OpenRouter result must contain one unambiguous choice")
        choice = choices[0]
        message = choice.get("message")
        finish_reason = choice.get("finish_reason")
        if not isinstance(message, dict) or not isinstance(finish_reason, str):
            raise ProviderResponseObservationDenied("provider.response_format", "OpenRouter completion is malformed")
        raw_calls = message.get("tool_calls", [])
        if not isinstance(raw_calls, list):
            raise ProviderResponseObservationDenied("provider.tool_calls", "OpenRouter tool call list is malformed")
        if raw_calls and finish_reason != "tool_calls":
            raise ProviderResponseObservationDenied("provider.tool_calls", "OpenRouter tool calls lack a terminal tool-call reason")
        if not raw_calls and finish_reason == "tool_calls":
            raise ProviderResponseObservationDenied("provider.tool_calls", "OpenRouter tool-call terminal has no calls")
        if not raw_calls and finish_reason != "stop":
            raise ProviderResponseObservationDenied("provider.response_incomplete", "OpenRouter completion did not end normally")
        return _bindings(raw_calls, codex=False)

    if media_type != "text/event-stream":
        raise ProviderResponseObservationDenied("provider.response_type", "Codex result is not a Responses event stream")
    try:
        response = completed_responses_object(response_bytes, content_type)
    except Exception:
        raise ProviderResponseObservationDenied("provider.codex_incomplete", "Codex result has no verified terminal completion") from None
    output = response.get("output") if isinstance(response, dict) else None
    if not isinstance(output, list) or len(output) > 4096:
        raise ProviderResponseObservationDenied("provider.response_format", "Codex completed output is malformed")
    raw_calls = [item for item in output if isinstance(item, dict) and item.get("type") == "function_call"]
    if any(not isinstance(item, dict) for item in output):
        raise ProviderResponseObservationDenied("provider.response_format", "Codex completed output contains malformed items")
    return _bindings(raw_calls, codex=True)
