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

import json
import hashlib
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
) -> str:
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
        handle = event.get("native_event_handle")
        expires = event.get("expires_monotonic")
    else:
        handle = getattr(event, "native_event_handle", None)
        expires = getattr(event, "expires_monotonic", None)
    if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
            or isinstance(expires, bool) or not isinstance(expires, (int, float))
            or not (time.monotonic() < float(expires) <= time.monotonic() + 300.0)):
        raise NativeBoundaryUnavailable("host returned an invalid native-event lease")
    return handle


_ledger_lock = threading.RLock()
# Keep a strong reference beside id(messages) so a recycled object ID cannot
# inherit a previous conversation's one-use receipt handles.
_pending_receipts: "OrderedDict[int, tuple[list[Any], list[str]]]" = OrderedDict()
_attempt_states: "OrderedDict[int, tuple[list[Any], dict[str, tuple[str, str, str, int]]]]" = OrderedDict()


def _conversation_receipts(messages: list[Any]) -> list[str]:
    key = id(messages)
    with _ledger_lock:
        entry = _pending_receipts.get(key)
        if entry is None or entry[0] is not messages:
            return []
        handles = list(entry[1])
        _pending_receipts.move_to_end(key)
        return handles


def _save_receipt(messages: list[Any], handle: str) -> None:
    with _ledger_lock:
        key = id(messages)
        entry = _pending_receipts.get(key)
        if entry is None or entry[0] is not messages:
            entry = (messages, [])
        entry[1].append(handle)
        _pending_receipts[key] = entry
        _pending_receipts.move_to_end(key)
        while len(_pending_receipts) > _MAX_TRACKED_CONVERSATIONS:
            _pending_receipts.popitem(last=False)


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
    handle = _prepare_native_event(
        source_payload, parent_receipt_handles=parents, purpose=purpose,
        intent_id=intent_id, trace_id=trace_id, retry_index=retry_index,
    )
    if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
        raise NativeBoundaryUnavailable("host returned a malformed source handle")
    result = dict(kwargs)
    headers[CONTEXT_HEADER] = handle
    result["extra_headers"] = headers
    return result


def record_tool_result(messages: list[Any], message: Mapping[str, Any]) -> None:
    """Capture an exact native tool-result message as a private host-observed event."""
    if not isinstance(messages, list) or not isinstance(message, Mapping):
        return
    try:
        handle = _capture_source(_canonical_bytes(dict(message)))
    except NativeBoundaryUnavailable:
        # The next provider request still submits its whole canonical transcript
        # for a fresh private snapshot. It will fail before egress if that path is
        # also unavailable.
        return
    _save_receipt(messages, handle)
