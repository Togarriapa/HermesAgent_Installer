"""Fixed HTTP framing over the enrolled root ServiceConnectorClient.

This adapter accepts only opaque route IDs from the protected memory catalog.
It never accepts an URL, host, port, method, path, or credential from a worker.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import quote, urlencode

from .enrollment import MemoryServiceEnrollment, RouteStep


MAX_HEADER_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")


class MemoryTransportUnavailable(RuntimeError):
    pass


class MemoryTransportDenied(PermissionError):
    pass


class ConnectorStream(Protocol):
    def read(self, max_bytes: int) -> bytes: ...
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class ServiceConnectorClient(Protocol):
    def open(self, enrollment_id: str, generation: str, target_id: str,
             approved_route_id: str, session_id: str, deadline: float) -> ConnectorStream: ...


@dataclass(frozen=True, slots=True)
class MemoryHTTPResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


class RootConnectorFactory(Protocol):
    """Root-only factory that binds fresh connector operation grants per stream."""
    def __call__(self, *, context: Any, authorization: Any,
                 enrollment: MemoryServiceEnrollment, route_id: str,
                 request_digest: str) -> ServiceConnectorClient: ...


def _parse_headers(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    marker = raw.find(b"\r\n\r\n")
    if marker < 0 or marker > MAX_HEADER_BYTES:
        raise MemoryTransportUnavailable("memory service response headers are incomplete or oversized")
    head = raw[:marker]
    try:
        lines = head.decode("iso-8859-1").split("\r\n")
    except UnicodeDecodeError:
        raise MemoryTransportUnavailable("memory service response headers are malformed") from None
    match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?", lines[0] if lines else "")
    if not match:
        raise MemoryTransportUnavailable("memory service returned an invalid HTTP status line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise MemoryTransportUnavailable("memory service returned malformed HTTP headers")
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if not key or key in headers or any(ord(c) < 0x21 or ord(c) > 0x7e for c in key):
            raise MemoryTransportUnavailable("memory service returned duplicate or invalid headers")
        headers[key] = value
    if "transfer-encoding" in headers and headers["transfer-encoding"].lower() != "identity":
        raise MemoryTransportUnavailable("chunked or encoded memory service responses are not accepted")
    if headers.get("content-encoding", "identity").lower() != "identity":
        raise MemoryTransportUnavailable("compressed memory service responses are not accepted")
    return int(match.group(1)), headers, raw[marker + 4:]


def _route_path(step: RouteStep, body: Mapping[str, Any]) -> str:
    path = step.path
    if "{owned_id}" in path:
        value = body.get("record_id")
        if not isinstance(value, str) or not _ID.fullmatch(value):
            raise ValueError("root-scoped memory record ID is required")
        path = path.replace("{owned_id}", quote(value, safe="._:-"))
    if "{" in path or "}" in path or not path.startswith("/") or "//" in path:
        raise MemoryTransportDenied("memory route path is not a closed catalog entry")
    return path


def _get_query(enrollment: MemoryServiceEnrollment, route_id: str,
               body: Mapping[str, Any]) -> str:
    # GET routes with data have a closed query schema. Scope values are forced
    # from enrollment, never copied from the request body.
    if enrollment.provider == "claude-mem" and route_id == "claude-worker-search-get":
        query = body.get("query")
        limit = body.get("limit", 20)
        if not isinstance(query, str) or not query.strip() or len(query.encode()) > 4096:
            raise ValueError("search query is missing or oversized")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("search limit is outside 1..100")
        params = {
            "query": query,
            "projectId": enrollment.fixed_project_account_user_scope["project_id"],
            "limit": str(limit),
        }
        return "?" + urlencode(params)
    return ""


def _frame_request(enrollment: MemoryServiceEnrollment, route_id: str,
                   step: RouteStep, payload: bytes) -> bytes:
    if len(payload) > min(MAX_REQUEST_BYTES, enrollment.limits["request_bytes"]):
        raise ValueError("memory service request exceeds the enrolled byte limit")
    try:
        body = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("memory service request must be UTF-8 JSON") from None
    if not isinstance(body, dict) or json.dumps(body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8") != payload:
        raise ValueError("memory service request must be canonical JSON object bytes")
    path = _route_path(step, body)
    if step.body == "none":
        wire_body = b""
    elif step.body == "recipe":
        raise MemoryTransportUnavailable(
            "OpenViking capture requires its separately authorized compound-session recipe")
    elif step.body == "query":
        path += _get_query(enrollment, route_id, body)
        wire_body = b""
    elif step.body == "json":
        wire_body = payload
    else:
        raise MemoryTransportDenied("unknown protected memory route framing mode")
    if len(wire_body) > enrollment.limits["request_bytes"]:
        raise ValueError("framed memory request exceeds enrolled limit")
    host = f"127.0.0.1:{enrollment.literal_loopback_port}"
    headers = [
        f"{step.method} {path} HTTP/1.1",
        f"Host: {host}",
        "Accept: application/json",
        "Connection: close",
    ]
    if wire_body:
        headers.extend(("Content-Type: application/json", f"Content-Length: {len(wire_body)}"))
    else:
        headers.append("Content-Length: 0")
    return ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + wire_body


class MemoryServiceIPC:
    """Authenticated route-ID-to-HTTP adapter backed by the root connector."""
    def __init__(self, enrollments: Mapping[tuple[str, str, str], MemoryServiceEnrollment],
                 connector_factory: RootConnectorFactory, *,
                 monotonic: Callable[[], float] = time.monotonic):
        self.enrollments = dict(enrollments)
        self.connector_factory = connector_factory
        self.monotonic = monotonic

    def request(self, *, context: Any, authorization: Any, service_id: str,
                service_generation: str, provider: str, route_id: str,
                session_id: str, deadline_monotonic: float, payload: bytes,
                timeout: float, peer_pid: int, peer_pidfd: int | None,
                cancelled: Callable[[], bool]) -> MemoryHTTPResponse:
        # SK01 v1 requires a root-owned compound executor: callers submit
        # typed step envelopes, while the root ledger selects the serializer,
        # service request, response schema and per-step HI12 grant. This older
        # direct request shape cannot express those atomic bindings safely.
        raise MemoryTransportUnavailable(
            "direct memory HTTP transport is retired; fixed compound executor is required")

        # Kept below only as historical source during migration; unreachable
        # code is deliberately not a registered transport path.
        key = (context.profile_id, context.namespace_id, provider)
        enrollment = self.enrollments.get(key)
        if enrollment is None:
            raise MemoryTransportUnavailable("no root-enrolled memory connector for signed profile")
        if (service_id != enrollment.service_enrollment_id
                or service_generation != enrollment.service_generation
                or enrollment.principal_id != context.principal_id
                or enrollment.namespace_identity != context.namespace_id
                or enrollment.provider != provider):
            raise MemoryTransportDenied("signed memory identity differs from protected connector enrollment")
        step = enrollment.fixed_route_map.get(route_id)
        if step is None:
            raise MemoryTransportDenied("memory route ID is not approved for selected backend variant")
        if cancelled() or self.monotonic() >= deadline_monotonic:
            raise MemoryTransportUnavailable("memory service operation was cancelled or expired")
        frame = _frame_request(enrollment, route_id, step, payload)
        digest = hashlib.sha256(frame).hexdigest()
        client = self.connector_factory(
            context=context, authorization=authorization, enrollment=enrollment,
            route_id=route_id, request_digest=digest)
        stream: ConnectorStream | None = None
        try:
            stream = client.open(
                enrollment_id=enrollment.service_enrollment_id,
                generation=enrollment.service_generation,
                target_id=enrollment.target_id,
                approved_route_id=route_id,
                session_id=session_id,
                deadline=deadline_monotonic)
            if cancelled():
                raise MemoryTransportUnavailable("memory service operation was cancelled")
            written = stream.write(frame)
            if type(written) is not int or written != len(frame):
                raise MemoryTransportUnavailable("memory connector did not accept the complete HTTP frame")
            raw = bytearray()
            header_end = -1
            expected_length: int | None = None
            status: int | None = None
            headers: dict[str, str] = {}
            body = bytearray()
            operation_deadline = min(deadline_monotonic, self.monotonic() + timeout)
            while True:
                if cancelled() or self.monotonic() >= operation_deadline:
                    raise MemoryTransportUnavailable("memory service response deadline expired")
                chunk = stream.read(min(65536, MAX_HEADER_BYTES + enrollment.limits["response_bytes"] + 4))
                if not isinstance(chunk, bytes):
                    raise MemoryTransportUnavailable("memory connector returned a non-byte stream")
                if not chunk:
                    break
                if header_end < 0:
                    raw.extend(chunk)
                    marker = raw.find(b"\r\n\r\n")
                    if marker < 0:
                        if len(raw) > MAX_HEADER_BYTES:
                            raise MemoryTransportUnavailable("memory service response headers exceed limit")
                        continue
                    if marker > MAX_HEADER_BYTES:
                        raise MemoryTransportUnavailable("memory service response headers exceed limit")
                    status, headers, first_body = _parse_headers(bytes(raw))
                    header_end = marker
                    body.extend(first_body)
                    raw.clear()
                else:
                    body.extend(chunk)
                if len(body) > min(MAX_RESPONSE_BYTES, enrollment.limits["response_bytes"]):
                    raise MemoryTransportUnavailable("memory service response exceeds enrolled limit")
                if status is not None and "content-length" in headers:
                    try:
                        expected_length = int(headers["content-length"])
                    except ValueError:
                        raise MemoryTransportUnavailable("memory service Content-Length is invalid") from None
                    if expected_length < 0 or expected_length > enrollment.limits["response_bytes"]:
                        raise MemoryTransportUnavailable("memory service Content-Length exceeds limit")
                    if len(body) >= expected_length:
                        if len(body) != expected_length:
                            raise MemoryTransportUnavailable("memory service sent bytes beyond Content-Length")
                        break
            if header_end < 0 or status is None:
                raise MemoryTransportUnavailable("memory service response ended before headers")
            if expected_length is not None and len(body) != expected_length:
                raise MemoryTransportUnavailable("memory service response length differs from Content-Length")
            if status in {301, 302, 303, 307, 308}:
                raise MemoryTransportDenied("memory service redirects are forbidden")
            if 200 <= status < 300 and "json" not in headers.get("content-type", "").lower():
                raise MemoryTransportUnavailable("memory service response is not JSON")
            return MemoryHTTPResponse(status, headers, bytes(body))
        finally:
            if stream is not None:
                stream.close()
