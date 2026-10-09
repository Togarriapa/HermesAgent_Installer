"""Root-selected, bounded controls for an already registered process handle.

The worker supplies only a fixed verb, an opaque process handle/generation,
and that verb's typed fields. Root resolves the live process and derives the
profile, target, context and one-use grant before invoking the custodian.
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping

from .types import AuthorityDenied

_OPERATIONS = frozenset({
    "process.status", "process.read", "process.write", "process.stop", "process.inspect",
})
_HANDLE = re.compile(r"[0-9a-f]{32}\Z")
_GENERATION = re.compile(r"[A-Za-z0-9_.:-]{1,256}\Z")
_MAX_TIMEOUT = 30.0


@dataclass(frozen=True, slots=True)
class ProcessControlResponse:
    schema: int
    process_id: str
    generation: str
    operation: str
    state: str
    result: Mapping[str, Any]
    expires_monotonic: float


def _control_fields(operation: str, fields: Mapping[str, Any] | None) -> dict[str, Any]:
    if fields is None:
        fields = {}
    if not isinstance(fields, Mapping):
        raise AuthorityDenied("process.control", "process control fields are malformed")
    value = dict(fields)
    if operation in {"process.status", "process.inspect"}:
        if value:
            raise AuthorityDenied("process.control", "this process control has no caller parameters")
    elif operation == "process.read":
        if set(value) != {"stream", "maximum_bytes"}:
            raise AuthorityDenied("process.control", "process read parameters are incomplete")
        if (value["stream"] not in {"stdout", "stderr"}
                or type(value["maximum_bytes"]) is not int
                or not 1 <= value["maximum_bytes"] <= 1_048_576):
            raise AuthorityDenied("process.control", "process read parameters exceed their bounds")
    elif operation == "process.write":
        if set(value) != {"data_bytes", "sequence"}:
            raise AuthorityDenied("process.control", "process write parameters are incomplete")
        data = value["data_bytes"]
        sequence = value["sequence"]
        if type(sequence) is not int or sequence < 0 or not isinstance(data, bytes):
            raise AuthorityDenied("process.control", "process write parameters are malformed")
        if len(data) > 262_144:
            raise AuthorityDenied("process.control", "process write data exceeds its bound")
        # JSON AF_UNIX framing carries bytes as canonical base64. The authority
        # decodes this value before constructing the signed canonical effect.
        value["data_bytes"] = base64.b64encode(data).decode("ascii")
    elif operation == "process.stop":
        if set(value) != {"reason", "grace_seconds"}:
            raise AuthorityDenied("process.control", "process stop parameters are incomplete")
        if (value["reason"] not in {"cancel", "shutdown", "rollback"}
                or type(value["grace_seconds"]) is not int
                or not 0 <= value["grace_seconds"] <= 10):
            raise AuthorityDenied("process.control", "process stop parameters exceed their bounds")
    else:
        raise AuthorityDenied("process.operation", "process control verb is not fixed")
    return value


def _decode_response(value: Any, *, operation: str, process_id: str,
                     generation: str, now: float) -> ProcessControlResponse:
    # The generic host broker wraps operation bodies in its normal response
    # envelope. process.control's public result is the typed body below; the
    # worker never receives its short-lived grant.
    if not isinstance(value, dict) or set(value) != {"status", "body", "headers", "receipt_id"}:
        raise AuthorityDenied("effect.invalid", "root process control broker response is malformed")
    if (type(value["status"]) is not int or value["status"] != 200
            or not isinstance(value["body"], str)
            or not isinstance(value["headers"], dict) or len(value["headers"]) > 32
            or not isinstance(value["receipt_id"], str)
            or not 1 <= len(value["receipt_id"]) <= 256):
        raise AuthorityDenied("effect.denied", "root process control effect was denied")
    try:
        body = base64.b64decode(value["body"], validate=True)
        value = json.loads(body.decode("ascii"))
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError):
        raise AuthorityDenied("effect.invalid", "root process control body is malformed") from None
    required = {"schema", "process_id", "generation", "operation", "state", "result", "expires_monotonic"}
    if not isinstance(value, dict) or set(value) != required:
        raise AuthorityDenied("effect.invalid", "root process control response is malformed")
    expires = value["expires_monotonic"]
    result = value["result"]
    if (type(value["schema"]) is not int or value["schema"] != 1
            or value["process_id"] != process_id or value["generation"] != generation
            or value["operation"] != operation
            or not isinstance(value["state"], str) or not 1 <= len(value["state"]) <= 64
            or not isinstance(result, dict) or len(result) > 64
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not math.isfinite(expires) or not now < float(expires) <= now + 600.0):
        raise AuthorityDenied("effect.invalid", "root process control response binding or lease is invalid")
    try:
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise AuthorityDenied("effect.invalid", "root process control result is malformed") from None
    result_bound = 2 * 1024 * 1024 if operation == "process.read" else 256 * 1024
    if len(encoded) > result_bound:
        raise AuthorityDenied("effect.bounds", "root process control result exceeds its operation bound")
    return ProcessControlResponse(
        schema=1, process_id=process_id, generation=generation, operation=operation,
        state=value["state"], result=MappingProxyType(dict(result)),
        expires_monotonic=float(expires),
    )


def process_control_operation(
    client: Any,
    operation: str,
    process_id: str,
    generation: str,
    fields: Mapping[str, Any] | None = None,
    *,
    timeout: float = 5.0,
    cancelled: Callable[[], bool] | None = None,
) -> ProcessControlResponse:
    """Ask root to resolve and perform one fixed operation on a live handle.

    No target, capability, context, owner UID or bearer grant is accepted from
    the caller. The authority authenticates the AF_UNIX peer and checks current
    enrollment, handle/pidfd identity, operation policy and generation.
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
    response = rpc("process.control", request, timeout=float(timeout), cancelled=cancelled)
    if cancelled is not None and cancelled():
        raise AuthorityDenied("effect.cancelled", "process control was cancelled before response delivery")
    monotonic = getattr(client, "monotonic", time.monotonic)
    now = monotonic()
    if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now):
        raise AuthorityDenied("authority.clock", "process control monotonic clock is unavailable")
    return _decode_response(response, operation=operation, process_id=process_id,
                            generation=generation, now=float(now))
