"""Host-brokered ChatGPT-plan Responses API adapter (PR-R0124/PR-R0126).

The root-owned authority resolves the account OAuth reference and performs the
fixed OpenAI Responses request. This worker never sees a bearer token or URL.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from typing import Callable, Mapping, Protocol

from .policy import PolicyDenied, ProviderResponse

CODEX_TARGET = "codex://responses"
CODEX_RECIPIENT = "openai:codex"
MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_OUTPUT_TOKENS = 65_536
_ALLOWED_TOP_LEVEL = frozenset({
    "model", "input", "instructions", "max_output_tokens", "tools",
    "tool_choice", "parallel_tool_calls", "stream", "store", "truncation",
})
_ALLOWED_ROLES = frozenset({"system", "developer", "user", "assistant"})


class CodexAuthority(Protocol):
    def authorize_effect(self, context: object, *, capability: str, target: str,
                         recipient: str, request_digest: str, retry_index: int) -> object: ...

    def verify_effect(self, grant: object, context: object, *, capability: str,
                      target: str, recipient: str, request_digest: str,
                      retry_index: int) -> bool: ...

    def dispatch_codex(self, grant: object, *, target: str, recipient: str,
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> object: ...


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _text(value: object, *, maximum: int = 256_000) -> bool:
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8", errors="strict")) <= maximum
    except UnicodeEncodeError:
        return False


def _validate_input(value: object) -> None:
    if _text(value):
        return
    if not isinstance(value, list) or len(value) > 4096:
        raise PolicyDenied("request.input", "Codex Responses input must be bounded text")
    for item in value:
        if not isinstance(item, dict):
            raise PolicyDenied("request.input", "Codex Responses input item is malformed")
        kind = item.get("type", "message")
        if kind == "message":
            if set(item) - {"type", "role", "content"}:
                raise PolicyDenied("request.input", "Unsupported Codex message field")
            if item.get("role") not in _ALLOWED_ROLES:
                raise PolicyDenied("request.input", "Unsupported Codex message role")
            content = item.get("content")
            if _text(content):
                continue
            if not isinstance(content, list) or len(content) > 256:
                raise PolicyDenied("request.input", "Codex message content must be text only")
            for part in content:
                if not isinstance(part, dict) or set(part) != {"type", "text"} or part.get("type") not in {"input_text", "output_text"} or not _text(part.get("text")):
                    raise PolicyDenied("request.modality", "Images, audio, files and non-text inputs are unavailable")
        elif kind == "function_call_output":
            if set(item) != {"type", "call_id", "output"} or not _text(item.get("call_id"), maximum=256) or not _text(item.get("output")):
                raise PolicyDenied("request.tool_output", "Function outputs must be bounded text")
        else:
            raise PolicyDenied("request.modality", "Only text input and function-call output are supported")


def normalize_responses_request(payload: bytes) -> tuple[bytes, str, bool]:
    """Canonicalize a text-only Responses body and report actual function use."""
    if not isinstance(payload, bytes) or not payload or len(payload) > MAX_REQUEST_BYTES:
        raise PolicyDenied("request.bounds", "Codex Responses request exceeds its byte limit")
    try:
        body = json.loads(payload, object_pairs_hook=_pairs_no_duplicates,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))
    except (TypeError, ValueError, UnicodeDecodeError, RecursionError):
        raise PolicyDenied("request.format", "Codex Responses request must be valid unique-key JSON") from None
    if not isinstance(body, dict) or set(body) - _ALLOWED_TOP_LEVEL:
        raise PolicyDenied("request.fields", "Codex Responses request contains unsupported fields")
    model = body.get("model")
    if not isinstance(model, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", model):
        raise PolicyDenied("route.model", "Codex model identifier is invalid")
    if "input" not in body:
        raise PolicyDenied("request.input", "Codex Responses request requires input")
    _validate_input(body["input"])
    if "instructions" in body and not _text(body["instructions"]):
        raise PolicyDenied("request.instructions", "Codex instructions must be bounded text")
    maximum = body.get("max_output_tokens", 4096)
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= MAX_OUTPUT_TOKENS:
        raise PolicyDenied("request.bounds", "Codex output-token limit is outside its supported bound")
    tools = body.get("tools", [])
    if not isinstance(tools, list) or len(tools) > 64:
        raise PolicyDenied("request.tools", "Codex function-tool list exceeds its bound")
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function" or set(tool) - {"type", "name", "description", "parameters", "strict"}:
            raise PolicyDenied("request.tools", "Only declared function tools are supported")
        if not isinstance(tool.get("name"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", tool["name"]):
            raise PolicyDenied("request.tools", "Codex function tool name is invalid")
        if "description" in tool and not _text(tool["description"], maximum=4096):
            raise PolicyDenied("request.tools", "Codex function description is too long")
        if not isinstance(tool.get("parameters"), dict):
            raise PolicyDenied("request.tools", "Codex function tool requires a JSON schema")
        if "strict" in tool and not isinstance(tool["strict"], bool):
            raise PolicyDenied("request.tools", "Codex function strict flag is invalid")
    choice = body.get("tool_choice", "auto")
    valid_choice = (choice in {"auto", "none", "required"} if isinstance(choice, str) else (
        isinstance(choice, dict)
        and choice.get("type") == "function"
        and choice.get("name") in {t["name"] for t in tools}
        and set(choice) == {"type", "name"}
    ))
    if not valid_choice:
        raise PolicyDenied("request.tools", "Codex tool choice must name an allowed function")
    if body.get("tool_choice") == "required" and not tools:
        raise PolicyDenied("request.tools", "Required function choice has no declared functions")
    if body.get("parallel_tool_calls", False) is not False:
        raise PolicyDenied("request.tools", "Parallel function calls are disabled")
    if body.get("truncation", "disabled") != "disabled":
        raise PolicyDenied("request.fields", "Codex truncation mode is invalid")
    if body.get("stream", False) is not False or body.get("store", False) is not False:
        raise PolicyDenied("request.mode", "Streaming and server-side response storage are disabled")
    # The supported route is bounded request/response JSON only. No server side
    # conversations, background jobs, or implicit model behavior are enabled.
    body["stream"] = False
    body["store"] = False
    body["parallel_tool_calls"] = False
    body["max_output_tokens"] = maximum
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    if len(canonical) > MAX_REQUEST_BYTES:
        raise PolicyDenied("request.bounds", "Normalized Codex request exceeds its byte limit")
    uses_tools = bool(tools) or body.get("tool_choice") not in (None, "auto", "none") or any(
        isinstance(item, dict) and item.get("type") == "function_call_output"
        for item in body["input"] if isinstance(body["input"], list))
    return canonical, model, uses_tools


class CodexResponsesTransport:
    """One fresh signed grant and one fixed broker handoff per call."""

    def __init__(self, authority_client: CodexAuthority | None):
        self._authority = authority_client

    def __repr__(self) -> str:
        return "CodexResponsesTransport(authority=<host broker>, token=<host vault>)"

    def __call__(self, host_context: object, payload: bytes, *, retry_index: int = 0,
                 timeout: float = 30.0,
                 cancelled: Callable[[], bool] = lambda: False) -> ProviderResponse:
        if self._authority is None:
            raise PolicyDenied("authorization.unavailable", "Host Codex Responses broker is unavailable")
        if isinstance(retry_index, bool) or not isinstance(retry_index, int) or not 0 <= retry_index < 3:
            raise PolicyDenied("request.retry", "Codex retry index is outside its bound")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0.1 <= timeout <= 30:
            raise PolicyDenied("request.deadline", "Codex request deadline is outside its hard bound")
        if cancelled():
            raise PolicyDenied("dispatch.cancelled", "Codex request was cancelled")
        now = time.monotonic()
        expires = getattr(host_context, "monotonic_expires_at", 0.0)
        sensitivity = getattr(host_context, "sensitivity", "unknown")
        if not isinstance(sensitivity, str):
            sensitivity = getattr(sensitivity, "value", "unknown")
        if sensitivity not in {"public", "private"}:
            raise PolicyDenied("context.sensitivity", "Codex route requires explicit public or private host policy")
        if (isinstance(expires, bool) or not isinstance(expires, (int, float))
                or not math.isfinite(expires) or expires - now < min(timeout, 0.1)):
            raise PolicyDenied("context.lease", "Host Codex context has insufficient monotonic lease")
        body, _model, uses_tools = normalize_responses_request(payload)
        digest = hashlib.sha256(body).hexdigest()
        capability = "provider-tool-call" if uses_tools else "provider-inference"
        target, recipient = CODEX_TARGET, CODEX_RECIPIENT
        try:
            grant = self._authority.authorize_effect(
                host_context, capability=capability, target=target, recipient=recipient,
                request_digest=digest, retry_index=retry_index)
            if grant is None or not self._authority.verify_effect(
                grant, host_context, capability=capability, target=target,
                recipient=recipient, request_digest=digest, retry_index=retry_index):
                raise PolicyDenied("authorization.denied", "Host denied the Codex effect grant")
            grant_expires = getattr(grant, "monotonic_expires_at", None)
            if (isinstance(grant_expires, bool) or not isinstance(grant_expires, (int, float))
                    or not math.isfinite(grant_expires)):
                raise PolicyDenied("authorization.lease", "Codex grant lacks a monotonic lease")
            budget = min(float(timeout), float(expires) - now, float(grant_expires) - time.monotonic())
            if not math.isfinite(budget) or budget < 0.1:
                raise PolicyDenied("authorization.expired", "Codex effect grant has insufficient lease")
            result = self._authority.dispatch_codex(
                grant, target=target, recipient=recipient, request_digest=digest,
                payload=body, timeout=budget, cancelled=cancelled)
        except PolicyDenied:
            raise
        except Exception:
            if cancelled():
                raise PolicyDenied("dispatch.cancelled", "Codex request was cancelled") from None
            raise PolicyDenied("provider.broker", "Root-owned Codex Responses broker rejected the request") from None
        status, response_body, headers = (getattr(result, "status", None),
                                          getattr(result, "body", None),
                                          getattr(result, "headers", {}))
        if (isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599
                or not isinstance(response_body, bytes) or len(response_body) > MAX_RESPONSE_BYTES
                or not isinstance(headers, Mapping)):
            raise PolicyDenied("response.bounds", "Host broker returned an invalid Codex response")
        safe_headers = {"Content-Type": "application/json"}
        content_type = headers.get("Content-Type", "application/json")
        if isinstance(content_type, str) and content_type in {"application/json", "text/event-stream"}:
            safe_headers["Content-Type"] = content_type
        retry_after = headers.get("Retry-After")
        if retry_after is not None:
            try:
                seconds = float(retry_after)
                if math.isfinite(seconds) and 0 <= seconds <= 60:
                    safe_headers["Retry-After"] = str(seconds)
            except (TypeError, ValueError, OverflowError):
                pass
        input_tokens = output_tokens = 0
        try:
            response_json = json.loads(response_body)
            usage = response_json.get("usage", {}) if isinstance(response_json, dict) else {}
            if isinstance(usage, dict):
                prompt = usage.get("input_tokens", 0)
                completion = usage.get("output_tokens", 0)
                if isinstance(prompt, int) and not isinstance(prompt, bool) and prompt >= 0:
                    input_tokens = min(prompt, 1_000_000)
                if isinstance(completion, int) and not isinstance(completion, bool) and completion >= 0:
                    output_tokens = min(completion, MAX_OUTPUT_TOKENS)
        except (ValueError, UnicodeDecodeError):
            pass
        return ProviderResponse(status, response_body, safe_headers, input_tokens, output_tokens)
