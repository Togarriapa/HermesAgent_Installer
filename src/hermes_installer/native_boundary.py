"""Per-attempt native Hermes source capture at provider and tool-result seams.

The patched Hermes process supplies exact canonical source bytes only. The host
assigns event identity, process/profile/generation, lineage and sensitivity. This
module never accepts a caller-selected source kind, origin, PID, sensitivity or
public-clearance value.

The current source-capture API establishes private/unknown snapshots only. A
trusted UI, tool-result, memory or background issuer must be enrolled separately
before those events can carry stronger provenance.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import threading
import time
import uuid
from collections import OrderedDict
from typing import Any, Mapping, Sequence


CONTEXT_HEADER = "X-Hermes-Installer-Context"
_HANDLE = re.compile(r"[A-Za-z0-9_.:@~-]{16,512}\Z", re.ASCII)
_MAX_SOURCE_BYTES = 1_048_576
_MAX_PARENT_HANDLES = 64
_MAX_TRACKED_CONVERSATIONS = 128
_TRANSPORT_ONLY_ARGUMENTS = frozenset({"extra_headers", "timeout", "max_retries"})
_FORBIDDEN_TRUST_FIELDS = frozenset({
    "source_kind", "source_class", "origin", "origin_id", "provenance", "sensitivity",
    "public", "clearance", "receipt", "receipt_id", "receipt_ids", "parent_receipt_handles",
    "native_event_handle", "profile_id", "principal_id", "generation", "pid", "executable",
    "gateway_id",
})


class NativeBoundaryUnavailable(PermissionError):
    """The enrolled host source-capture path is unavailable or rejected input."""


def _canonical_bytes(value: Any) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise NativeBoundaryUnavailable("native source payload is not canonical JSON") from None
    if not raw or len(raw) > _MAX_SOURCE_BYTES:
        raise NativeBoundaryUnavailable("native source payload exceeds the enrolled size bound")
    return raw


def _authority_client():
    try:
        from hermes_installer.authority.client import AuthorityClient
        factory = getattr(AuthorityClient, "for_current_process", None)
        if not callable(factory):
            raise NativeBoundaryUnavailable("host authority client is not installed")
        return factory(timeout=5.0)
    except NativeBoundaryUnavailable:
        raise
    except Exception:
        raise NativeBoundaryUnavailable("host authority client is unavailable") from None


def _capture_source(payload: bytes, *, parent_receipt_handles: Sequence[str] = ()) -> str:
    """Ask the root authority to observe these bytes and mint a one-use handle.

    Importing AuthorityClient lazily keeps fixture inspection and source-overlay
    validation independent from a configured host. Production calls fail closed
    when the protected authority package/socket is missing.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= _MAX_SOURCE_BYTES:
        raise NativeBoundaryUnavailable("native source payload is outside its bound")
    if (not isinstance(parent_receipt_handles, (tuple, list))
            or len(parent_receipt_handles) > _MAX_PARENT_HANDLES
            or any(not isinstance(item, str) or not _HANDLE.fullmatch(item)
                   for item in parent_receipt_handles)):
        raise NativeBoundaryUnavailable("native source parent closure is malformed")
    try:
        client = _authority_client()
        capture = getattr(client, "capture_source", None)
        if not callable(capture):
            raise NativeBoundaryUnavailable("host source capture API is not installed")
        handle = capture(payload, parent_receipt_handles=tuple(parent_receipt_handles), timeout=5.0)
    except NativeBoundaryUnavailable:
        raise
    except Exception:
        # Do not leak peer paths, payload text, socket diagnostics or receipt data.
        raise NativeBoundaryUnavailable("host source capture is unavailable") from None
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise NativeBoundaryUnavailable("host returned a malformed source handle")
    return handle


def _prepare_native_event(
    payload: bytes, *, parent_receipt_handles: Sequence[str], purpose: str,
    intent_id: str, trace_id: str, retry_index: int,
) -> tuple[str, float]:
    """Prepare one cross-process event handle; never substitute a peer-bound receipt."""
    if (purpose not in {"native-primary", "native-auxiliary"}
            or not isinstance(intent_id, str) or not intent_id
            or not isinstance(trace_id, str) or not trace_id
            or isinstance(retry_index, bool) or type(retry_index) is not int
            or not 0 <= retry_index <= 100
            or not isinstance(parent_receipt_handles, (tuple, list))
            or len(parent_receipt_handles) > _MAX_PARENT_HANDLES
            or any(not isinstance(item, str) or not _HANDLE.fullmatch(item)
                   for item in parent_receipt_handles)):
        raise NativeBoundaryUnavailable("native event metadata is invalid")
    try:
        client = _authority_client()
        prepare = getattr(client, "prepare_native_event", None)
        if not callable(prepare):
            raise NativeBoundaryUnavailable("host native-event bridge is not installed")
        event = prepare(
            payload, parent_receipt_handles=tuple(parent_receipt_handles),
            purpose=purpose, intent_id=intent_id, trace_id=trace_id,
            retry_index=retry_index,
        )
    except NativeBoundaryUnavailable:
        raise
    except Exception:
        raise NativeBoundaryUnavailable("host native-event preparation is unavailable") from None
    if isinstance(event, Mapping):
        if set(event) != {"native_event_handle", "expires_monotonic"}:
            raise NativeBoundaryUnavailable("host returned an invalid native-event lease")
        handle = event.get("native_event_handle")
        expires = event.get("expires_monotonic")
    else:
        handle = getattr(event, "native_event_handle", None)
        expires = getattr(event, "expires_monotonic", None)
    if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not math.isfinite(float(expires))
            or not (time.monotonic() < float(expires) <= time.monotonic() + 300.0)):
        raise NativeBoundaryUnavailable("host returned an invalid native-event lease")
    return handle, float(expires)


_ledger_lock = threading.RLock()
# Keep a strong reference beside id(messages) so a recycled object ID cannot
# inherit a previous conversation's one-use receipt handles.
_pending_receipts: "OrderedDict[int, tuple[list[Any], list[str]]]" = OrderedDict()
_failed_source_events: "OrderedDict[int, list[Any]]" = OrderedDict()
_attempt_states: "OrderedDict[int, tuple[list[Any], dict[str, tuple[str, str, str, int]]]]" = OrderedDict()
_source_tracking_exhausted = False


def _conversation_receipts(messages: list[Any]) -> list[str]:
    key = id(messages)
    with _ledger_lock:
        if _source_tracking_exhausted:
            raise NativeBoundaryUnavailable("native source lineage capacity was exceeded")
        failed = _failed_source_events.get(key)
        if failed is messages:
            raise NativeBoundaryUnavailable("native source-event lineage is incomplete")
        entry = _pending_receipts.get(key)
        if entry is None or entry[0] is not messages:
            return []
        handles = list(entry[1])
        _pending_receipts.move_to_end(key)
        return handles


def _save_receipt(messages: list[Any], handle: str) -> None:
    global _source_tracking_exhausted
    with _ledger_lock:
        key = id(messages)
        entry = _pending_receipts.get(key)
        if entry is None or entry[0] is not messages:
            if len(_pending_receipts) >= _MAX_TRACKED_CONVERSATIONS:
                _source_tracking_exhausted = True
                raise NativeBoundaryUnavailable("native source lineage capacity was exceeded")
            entry = (messages, [])
        if len(entry[1]) <= _MAX_PARENT_HANDLES:
            entry[1].append(handle)
        _pending_receipts[key] = entry
        _pending_receipts.move_to_end(key)


def _block_conversation(messages: list[Any]) -> None:
    global _source_tracking_exhausted
    with _ledger_lock:
        key = id(messages)
        if len(_failed_source_events) >= _MAX_TRACKED_CONVERSATIONS and key not in _failed_source_events:
            _source_tracking_exhausted = True
            return
        _failed_source_events[key] = messages
        _failed_source_events.move_to_end(key)


def _attempt_metadata(messages: list[Any], purpose: str, payload: bytes) -> tuple[str, str, int]:
    """Keep retries of an identical envelope together; changed bodies start a new intent."""
    digest = hashlib.sha256(payload).hexdigest()
    key = id(messages)
    with _ledger_lock:
        entry = _attempt_states.get(key)
        if entry is None or entry[0] is not messages:
            entry = (messages, {})
        by_purpose = entry[1]
        previous = by_purpose.get(purpose)
        if previous is None:
            trace_id = uuid.uuid4().hex
            intent_id = uuid.uuid4().hex
            retry_index = 0
        else:
            trace_id = previous[0]
            if previous[2] == digest:
                intent_id = previous[1]
                retry_index = previous[3] + 1
            else:
                intent_id = uuid.uuid4().hex
                retry_index = 0
        by_purpose[purpose] = (trace_id, intent_id, digest, retry_index)
        _attempt_states[key] = entry
        _attempt_states.move_to_end(key)
        while len(_attempt_states) > _MAX_TRACKED_CONVERSATIONS:
            _attempt_states.popitem(last=False)
        return intent_id, trace_id, retry_index


def prepare_provider_request(kwargs: Mapping[str, Any], *, purpose: str) -> dict[str, Any]:
    """Return a copy of SDK kwargs carrying a fresh host source handle.

    Called immediately before each network attempt, including auxiliary retries
    and stream negotiation fallbacks. The gateway resolves this one-use handle
    and binds the complete normalized request body digest before provider egress.
    """
    if not isinstance(kwargs, Mapping) or purpose not in {"native-primary", "native-auxiliary"}:
        raise NativeBoundaryUnavailable("native provider request is not enrolled")
    if any(isinstance(key, str) and key.casefold() in _FORBIDDEN_TRUST_FIELDS for key in kwargs):
        raise NativeBoundaryUnavailable("caller-supplied native provenance fields are forbidden")
    if "max_retries" in kwargs:
        raise NativeBoundaryUnavailable("SDK retry count must come from the enrolled host")
    request_timeout = kwargs.get("timeout")
    if request_timeout is not None and (
        isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float))
        or not math.isfinite(float(request_timeout)) or request_timeout <= 0
    ):
        raise NativeBoundaryUnavailable("request timeout must be a bounded numeric duration")
    messages = kwargs.get("messages")
    if not isinstance(messages, list):
        raise NativeBoundaryUnavailable("native provider request has no supported messages payload")

    existing_headers = kwargs.get("extra_headers")
    if existing_headers is None:
        headers: dict[str, str] = {}
    elif isinstance(existing_headers, Mapping):
        headers = dict(existing_headers)
    else:
        raise NativeBoundaryUnavailable("native provider request headers are malformed")
    if headers:
        raise NativeBoundaryUnavailable("caller-supplied provider headers are forbidden")

    # Capture the complete JSON request envelope that the protected gateway
    # normalizer will turn into final bytes. Transport controls and headers do
    # not form part of the provider body and are omitted; all provider body
    # fields, including tools/model/stream options, remain covered.
    request_envelope = {key: value for key, value in kwargs.items()
                        if key not in _TRANSPORT_ONLY_ARGUMENTS}
    source_payload = _canonical_bytes(request_envelope)

    # Source receipts represent immutable observed ancestry; they do not grant
    # an effect. Each SDK attempt receives a distinct root-prepared bridge.
    parents = _conversation_receipts(messages)
    intent_id, trace_id, retry_index = _attempt_metadata(messages, purpose, source_payload)
    prepared_event = _prepare_native_event(
        source_payload, parent_receipt_handles=parents, purpose=purpose,
        intent_id=intent_id, trace_id=trace_id, retry_index=retry_index,
    )
    if (not isinstance(prepared_event, tuple) or len(prepared_event) != 2
            or isinstance(prepared_event[1], bool)
            or not isinstance(prepared_event[1], (int, float))
            or not math.isfinite(float(prepared_event[1]))):
        raise NativeBoundaryUnavailable("host returned an invalid native-event lease")
    handle, expires = prepared_event
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise NativeBoundaryUnavailable("host returned a malformed source handle")
    remaining = expires - time.monotonic()
    if remaining <= 0:
        raise NativeBoundaryUnavailable("host native-event lease expired before dispatch")
    if request_timeout is not None:
        remaining = min(remaining, float(request_timeout))
    result = dict(kwargs)
    result["timeout"] = remaining
    result["max_retries"] = 0
    headers[CONTEXT_HEADER] = handle
    result["extra_headers"] = headers
    return result


def record_tool_result(messages: list[Any], message: Mapping[str, Any]) -> None:
    """Capture an exact native tool-result message as a private host-observed event."""
    if not isinstance(messages, list) or not isinstance(message, Mapping):
        if isinstance(messages, list):
            _block_conversation(messages)
        return
    try:
        handle = _capture_source(_canonical_bytes(dict(message)))
        _save_receipt(messages, handle)
    except NativeBoundaryUnavailable:
        _block_conversation(messages)
        return
