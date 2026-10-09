"""Root-selected, bounded controls for an already registered process handle.

The caller selects only a fixed control verb, opaque process handle and
generation. The root authority resolves the live handle to its enrolled
profile, target and current operation grant, then performs the effect through
the same process custodian. This module deliberately has no target/grant input.
"""
from __future__ import annotations

import base64
import math
import re
from typing import Any, Callable, Mapping

from .types import AuthorityDenied, BrokeredEffectResponse

_OPERATIONS = frozenset({"process.status", "process.read", "process.write", "process.stop"})
_HANDLE = re.compile(r"[A-Za-z0-9_-]{16,128}\Z")
_GENERATION = re.compile(r"[A-Za-z0-9_.:-]{1,256}\Z")
_MAX_TIMEOUT = 30.0


def _control_fields(operation: str, fields: Mapping[str, Any] | None) -> dict[str, Any]:
    if fields is None:
        fields = {}
    if not isinstance(fields, Mapping):
        raise AuthorityDenied("process.control", "process control fields are malformed")
    value = dict(fields)
    if operation in {"process.status", "process.stop"}:
        if value:
            raise AuthorityDenied("process.control", "this process control has no caller parameters")
    elif operation == "process.read":
        if set(value) != {"stream", "after_cursor", "max_bytes"}:
            raise AuthorityDenied("process.control", "process read parameters are incomplete")
        if (value["stream"] not in {"stdout", "stderr"}
                or type(value["after_cursor"]) is not int or value["after_cursor"] < 0
                or type(value["max_bytes"]) is not int or not 1 <= value["max_bytes"] <= 65536):
            raise AuthorityDenied("process.control", "process read parameters exceed their bounds")
    elif operation == "process.write":
        if set(value) != {"stdin_cursor", "data"}:
            raise AuthorityDenied("process.control", "process write parameters are incomplete")
        data = value["data"]
        if (type(value["stdin_cursor"]) is not int or value["stdin_cursor"] < 0
                or not isinstance(data, str) or len(data) > 4 * 65536 // 3 + 4):
            raise AuthorityDenied("process.control", "process write parameters exceed their bounds")
        try:
            decoded = base64.b64decode(data, validate=True)
        except (ValueError, TypeError):
            raise AuthorityDenied("process.control", "process write data is malformed") from None
        if len(decoded) > 65536 or base64.b64encode(decoded).decode("ascii") != data:
            raise AuthorityDenied("process.control", "process write data exceeds its canonical bound")
    else:
        raise AuthorityDenied("process.operation", "process control verb is not fixed")
    return value


def _decode_response(value: Any, *, operation: str) -> BrokeredEffectResponse:
    if not isinstance(value, dict) or set(value) != {"status", "body", "headers", "receipt_id"}:
        raise AuthorityDenied("effect.invalid", "root process control response is malformed")
    if (type(value["status"]) is not int or not 0 <= value["status"] <= 599
            or not isinstance(value["body"], str)
            or not isinstance(value["headers"], dict) or len(value["headers"]) > 32
            or not isinstance(value["receipt_id"], str)
            or not 1 <= len(value["receipt_id"]) <= 256
            or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value["receipt_id"])):
        raise AuthorityDenied("effect.invalid", "root process control response exceeds its bound")
    if any(not isinstance(k, str) or not isinstance(v, str) or not 1 <= len(k) <= 128
           or len(v) > 2048 or any(ch in k + v for ch in "\r\n\x00")
           for k, v in value["headers"].items()):
        raise AuthorityDenied("effect.invalid", "root process control headers are malformed")
    try:
        body = base64.b64decode(value["body"], validate=True)
    except (ValueError, TypeError):
        raise AuthorityDenied("effect.invalid", "root process control body is malformed") from None
    body_limit = 65536 + 4096 if operation == "process.read" else 8192
    if len(body) > body_limit:
        raise AuthorityDenied("effect.bounds", "root process control response exceeds its operation bound")
    return BrokeredEffectResponse(value["status"], body, dict(value["headers"]), value["receipt_id"])


def process_control_operation(
    client: Any,
    operation: str,
    *,
    process_id: str,
    generation: str,
    fields: Mapping[str, Any] | None = None,
    timeout: float = 5.0,
    cancelled: Callable[[], bool] | None = None,
) -> BrokeredEffectResponse:
    """Ask root to resolve and perform one fixed operation on a live handle.

    The AF_UNIX peer identity, process registry, protected enrollment and live
    pidfd/cgroup state are checked by root. No target, capability, context or
    effect grant can be selected or supplied by the worker.
    """
    if operation not in _OPERATIONS:
        raise AuthorityDenied("process.operation", "process control verb is not fixed")
    if (not isinstance(process_id, str) or not _HANDLE.fullmatch(process_id)
            or not isinstance(generation, str) or not _GENERATION.fullmatch(generation)):
        raise AuthorityDenied("process.handle", "opaque process handle or generation is invalid")
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0.1 <= timeout <= _MAX_TIMEOUT):
        raise AuthorityDenied("effect.bounds", "process control timeout exceeds its fixed bound")
    if cancelled is not None and cancelled():
        raise AuthorityDenied("effect.cancelled", "process control was cancelled before dispatch")
    bounded_fields = _control_fields(operation, fields)
    request = {
        "schema": 1,
        "operation": operation,
        "process_id": process_id,
        "generation": generation,
        "fields": bounded_fields,
    }
    rpc = getattr(client, "_rpc", None)
    if not callable(rpc):
        raise AuthorityDenied("authority.client", "protected process control client is unavailable")
    result = rpc("process.control", request, timeout=float(timeout), cancelled=cancelled)
    if cancelled is not None and cancelled():
        raise AuthorityDenied("effect.cancelled", "process control was cancelled before response delivery")
    return _decode_response(result, operation=operation)
