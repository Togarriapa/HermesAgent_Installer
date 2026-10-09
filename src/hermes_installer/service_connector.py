"""Root-owned fixed loopback service connector (HI07).

Workers receive small typed operations over the protected authority channel. They
never receive an address, descriptor, PID, namespace selector, or proxy URL.
"""
from __future__ import annotations

import hashlib
import base64
import json
import math
import os
import re
import secrets
import select
import socket
import struct
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Mapping, Protocol

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_bytes, canonical_digest
from hermes_installer.remote.client_assets import CLIENT_ASSETS, canonical_asset


@dataclass(frozen=True, slots=True)
class Route:
    target_id: str
    route_id: str
    profile_id: str
    port: int
    protocol: str
    max_frame_bytes: int
    max_session_bytes: int


ROUTES: Mapping[tuple[str, str], Route] = {
    ("xpra-native", "xpra-http"): Route("xpra-native", "xpra-http", "hermes-desktop", 14500, "xpra-http", 1_048_576, 16_777_216),
    ("xpra-native", "xpra-websocket"): Route("xpra-native", "xpra-websocket", "hermes-desktop", 14500, "websocket", 1_048_576, 16_777_216),
    ("colibri-main", "colibri-openai-v1"): Route("colibri-main", "colibri-openai-v1", "colibri-main", 8000, "openai-http", 1_048_576, 16_777_216),
}
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_REMOTE_SESSION_SEAL = object()


class NamespaceLease(Protocol):
    namespace_fd: int
    pidfd: int
    uid: int
    cgroup_identity: str
    generation: str
    process_id: str
    def close(self) -> None: ...


@dataclass(frozen=True, slots=True)
class ConnectorLimits:
    max_sessions: int = 64
    max_queue_bytes: int = 2_097_152
    max_lease_seconds: float = 60.0
    max_open_timeout: float = 2.0


@dataclass(slots=True)
class _Stream:
    connector_id: str
    route: Route
    sock: socket.socket
    lease: NamespaceLease
    owner_uid: int
    owner_pid: int
    owner_pidfd: int
    lineage_hash: str
    session_id: str
    expires: float
    remaining: int
    sequence: int = 0
    lock: threading.Lock | None = None
    ws_buffer: bytearray | None = None
    http_request_sent: bool = False


@contextmanager
def _exclusive(stream: _Stream) -> Iterator[None]:
    if not stream.lock.acquire(blocking=False):
        raise AuthorityDenied("connector.busy", "another operation is already active for this stream")
    try:
        yield
    finally:
        stream.lock.release()


def _json_response(body: Mapping[str, Any], *, status: int = 200) -> Mapping[str, Any]:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > 1_500_000:
        raise AuthorityDenied("connector.response", "connector response exceeds its fixed bound")
    return {"status": status, "body": encoded, "headers": {"content-type": "application/json"}, "receipt_id": uuid.uuid4().hex}


def _decode(payload: bytes, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    # Binary payloads use base64 on the bounded authority JSON wire, which
    # expands a one-megabyte frame to roughly 1.4 MB.
    if not isinstance(payload, bytes) or len(payload) > 1_500_000:
        raise AuthorityDenied("connector.request", "connector request exceeds its bound")
    try:
        value = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise AuthorityDenied("connector.request", "connector request is malformed") from exc
    if not isinstance(value, dict) or not required.issubset(value) or set(value) - required - optional:
        raise AuthorityDenied("connector.request", "connector request fields are invalid")
    return value


def _valid_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AuthorityDenied("connector.request", f"{name} is invalid")
    return value


def _parse_http_frame(data: bytes, route: Route) -> bytes:
    """Validate one complete HTTP request and rebuild it with fixed authority headers."""
    header, separator, body = data.partition(b"\r\n\r\n")
    if not separator or len(header) > 32_768 or b"\x00" in header:
        raise AuthorityDenied("connector.protocol", "HTTP frame is incomplete or oversized")
    try:
        lines = header.decode("ascii", "strict").split("\r\n")
    except UnicodeDecodeError:
        raise AuthorityDenied("connector.protocol", "HTTP request headers are not ASCII") from None
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] != "HTTP/1.1":
        raise AuthorityDenied("connector.protocol", "HTTP request line is malformed")
    method, target = parts[:2]
    parsed_headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise AuthorityDenied("connector.protocol", "HTTP headers contain invalid folding or syntax")
        name, value = line.split(":", 1)
        name = name.casefold()
        value = value.strip()
        if (not re.fullmatch(r"[a-z0-9-]{1,64}", name) or "\r" in value or "\n" in value
                or name in parsed_headers or len(value) > 2048):
            raise AuthorityDenied("connector.protocol", "HTTP headers are duplicated or malformed")
        parsed_headers[name] = value
    if parsed_headers.get("transfer-encoding") is not None:
        raise AuthorityDenied("connector.protocol", "chunked request framing is not exposed")
    content_length = parsed_headers.get("content-length", "0")
    if not re.fullmatch(r"0|[1-9][0-9]{0,7}", content_length):
        raise AuthorityDenied("connector.protocol", "HTTP content length is invalid")
    if int(content_length) != len(body) or len(data) > route.max_frame_bytes:
        raise AuthorityDenied("connector.protocol", "HTTP body length or frame bound is invalid")
    if route.protocol == "xpra-http":
        if (method not in {"GET", "HEAD"} or body or "?" in target or "#" in target
                or not target.startswith("/") or "\\" in target or "%" in target
                or "authorization" in parsed_headers or "cookie" in parsed_headers
                or any(part in {".", ".."} for part in target.split("/"))):
            raise AuthorityDenied("connector.protocol", "Xpra asset request is outside GET/HEAD fixed-path policy")
        try:
            canonical_asset(target)
        except (ValueError, TypeError):
            raise AuthorityDenied("connector.protocol", "Xpra path is outside the pinned asset manifest") from None
        return (f"{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{route.port}\r\n"
                "Accept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
    if route.protocol == "openai-http":
        if (method != "POST" or target != "/v1/chat/completions"
                or parsed_headers.get("content-type", "").split(";", 1)[0].strip().casefold() != "application/json"
                or "authorization" in parsed_headers or "cookie" in parsed_headers
                or not body or len(body) > route.max_frame_bytes):
            raise AuthorityDenied("connector.protocol", "Colibri route permits only unauthenticated JSON chat completions")
        try:
            request_object = json.loads(body)
        except (ValueError, UnicodeDecodeError):
            raise AuthorityDenied("connector.protocol", "Colibri chat request is not valid JSON") from None
        if not isinstance(request_object, dict) or type(request_object.get("stream", False)) is not bool:
            raise AuthorityDenied("connector.protocol", "Colibri chat request schema is invalid")
        accept = parsed_headers.get("accept", "application/json")
        if accept not in {"application/json", "text/event-stream", "application/json, text/event-stream"}:
            raise AuthorityDenied("connector.protocol", "Colibri response type is not an enrolled format")
        return (f"POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{route.port}\r\n"
                "Content-Type: application/json\r\nAccept: application/json, text/event-stream\r\n"
                f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode("ascii") + body
    raise AuthorityDenied("connector.protocol", "HTTP protocol is not enrolled")


def _websocket_client_frame(opcode: int, payload: bytes) -> bytes:
    if len(payload) > 16_777_216 or opcode not in {2, 8, 9, 10}:
        raise AuthorityDenied("connector.protocol", "WebSocket frame opcode or size is not allowed")
    mask = secrets.token_bytes(4)
    length = len(payload)
    prefix = (bytes((0x80 | opcode, 0x80 | length)) if length < 126 else
              bytes((0x80 | opcode, 0x80 | 126)) + struct.pack("!H", length) if length <= 0xFFFF else
              bytes((0x80 | opcode, 0x80 | 127)) + struct.pack("!Q", length))
    masked = bytes(value ^ mask[index & 3] for index, value in enumerate(payload))
    return prefix + mask + masked


def _websocket_handshake(sock: socket.socket, route: Route, timeout: float, *,
                         after_send: Callable[[int], None] | None = None,
                         after_receive: Callable[[int], None] | None = None) -> None:
    """Negotiate the one fixed Xpra binary WebSocket origin/path/subprotocol."""
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    request = (
        "GET / HTTP/1.1\r\n" f"Host: 127.0.0.1:{route.port}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Protocol: binary\r\n"
        f"Origin: http://127.0.0.1:{route.port}\r\n\r\n"
    ).encode("ascii")
    deadline = time.monotonic() + timeout
    try:
        sock.settimeout(max(0.01, deadline - time.monotonic()))
        sock.sendall(request)
        received = bytearray()
        while not received.endswith(b"\r\n\r\n") and len(received) <= 16_384:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("fixed WebSocket handshake deadline expired")
            sock.settimeout(remaining)
            chunk = sock.recv(1)
            if not chunk:
                break
            received.extend(chunk)
    except (OSError, TimeoutError) as exc:
        raise AuthorityDenied("connector.websocket", "fixed Xpra WebSocket handshake failed") from exc
    if not received.endswith(b"\r\n\r\n") or len(received) > 16_384:
        raise AuthorityDenied("connector.websocket", "Xpra WebSocket handshake response is malformed")
    try:
        lines = received[:-4].decode("ascii", "strict").split("\r\n")
        status = lines[0].split(" ", 2)
        headers: dict[str, str] = {}
        for line in lines[1:]:
            name, value = line.split(":", 1)
            name = name.casefold()
            if name in headers:
                raise ValueError("duplicate")
            headers[name] = value.strip()
    except (ValueError, UnicodeDecodeError):
        raise AuthorityDenied("connector.websocket", "Xpra WebSocket response headers are malformed") from None
    expected_accept = base64.b64encode(
        hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
    ).decode("ascii")
    connection_tokens = {token.strip().casefold() for token in headers.get("connection", "").split(",")}
    if (len(status) < 2 or status[1] != "101"
            or headers.get("upgrade", "").casefold() != "websocket" or "upgrade" not in connection_tokens
            or headers.get("sec-websocket-accept") != expected_accept
            or headers.get("sec-websocket-protocol") != "binary"
            or "sec-websocket-extensions" in headers or "transfer-encoding" in headers
            or headers.get("content-length", "0") != "0"):
        raise AuthorityDenied("connector.websocket", "Xpra did not accept the fixed binary-only WebSocket")
    sock.setblocking(False)


def _websocket_read(stream: _Stream, amount: int, timeout: float,
                    cancelled: Callable[[], bool],
                    before_receive: Callable[[], None] | None = None,
                    after_receive: Callable[[int], None] | None = None) -> bytes:
    """Return only payload bytes from complete, unmasked server binary frames."""
    if stream.ws_buffer is None:
        stream.ws_buffer = bytearray()
    buffer = stream.ws_buffer
    consumed = False
    def need(count: int) -> None:
        nonlocal consumed
        while len(buffer) < count:
            chunk = None
            deadline = min(stream.expires, time.monotonic() + timeout)
            while chunk is None:
                if cancelled() or not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd):
                    raise AuthorityDenied("connector.cancelled", "WebSocket stream owner exited or cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise AuthorityDenied("connector.read.timeout", "WebSocket frame read timed out")
                readable, _, _ = select.select([stream.sock], [], [], min(0.05, remaining))
                if readable:
                    try:
                        if not consumed and before_receive is not None:
                            before_receive()
                            consumed = True
                        chunk = stream.sock.recv(max(4096, count - len(buffer)))
                        if chunk and after_receive is not None:
                            after_receive(len(chunk))
                    except (OSError, TimeoutError):
                        raise AuthorityDenied("connector.read", "WebSocket frame read failed") from None
                    if not chunk:
                        raise AuthorityDenied("connector.closed", "WebSocket peer closed")
            buffer.extend(chunk)
    while True:
        need(2)
        first, second = buffer[0], buffer[1]
        fin, opcode, masked = bool(first & 0x80), first & 0x0f, bool(second & 0x80)
        if first & 0x70 or masked:
            raise AuthorityDenied("connector.protocol", "WebSocket RSV or masking bits are invalid")
        length = second & 0x7f
        offset = 2
        if length == 126:
            need(4)
            length = struct.unpack("!H", buffer[2:4])[0]
            offset = 4
        elif length == 127:
            need(10)
            length = struct.unpack("!Q", buffer[2:10])[0]
            offset = 10
            if length >> 63:
                raise AuthorityDenied("connector.protocol", "WebSocket frame length is invalid")
        if length > stream.route.max_frame_bytes:
            raise AuthorityDenied("connector.protocol", "WebSocket frame exceeds the enrolled bound")
        if opcode >= 8 and (not fin or length > 125):
            raise AuthorityDenied("connector.protocol", "WebSocket control frame violates protocol bounds")
        need(offset + length)
        payload = bytes(buffer[offset:offset + length])
        del buffer[:offset + length]
        if opcode == 8:
            raise AuthorityDenied("connector.closed", "Xpra closed the WebSocket")
        if opcode == 9:
            stream.sock.sendall(_websocket_client_frame(10, payload))
            continue
        if opcode == 10:
            continue
        if opcode != 2 or not fin:
            raise AuthorityDenied("connector.protocol", "only complete binary Xpra WebSocket messages are allowed")
        if len(payload) > amount:
            stream.ws_buffer[:0] = payload[amount:]
            payload = payload[:amount]
        return payload


def _target(profile_id: str, target_id: str) -> str:
    return f"hermes-service-connect:{profile_id}:{target_id}"


def _pidfd_alive(pidfd: int) -> bool:
    if type(pidfd) is not int or pidfd < 0:
        return False
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not bool(poller.poll(0))


class FixedServiceConnector:
    """A protected in-process stream broker; all socket I/O remains root-owned."""

    def __init__(self, *, resolve_service_namespace: Callable[[str, str, str, str, str], NamespaceLease],
                 limits: ConnectorLimits = ConnectorLimits(), monotonic: Callable[[], float] = time.monotonic,
                 _test_allow_current_namespace: bool = False,
                 remote_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None,
                 colibri_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None):
        if (type(limits.max_sessions) is not int or type(limits.max_queue_bytes) is not int
                or not 1 <= limits.max_sessions <= 1024 or not 1024 <= limits.max_queue_bytes <= 16_777_216):
            raise ValueError("connector session and queue limits are invalid")
        if (isinstance(limits.max_lease_seconds, bool) or not isinstance(limits.max_lease_seconds, (int, float))
                or isinstance(limits.max_open_timeout, bool) or not isinstance(limits.max_open_timeout, (int, float))
                or not math.isfinite(limits.max_lease_seconds) or not math.isfinite(limits.max_open_timeout)
                or not 1 <= limits.max_lease_seconds <= 600 or not 0.1 <= limits.max_open_timeout <= 10):
            raise ValueError("connector deadlines are invalid")
        self.resolve = resolve_service_namespace
        self.limits = limits
        self.monotonic = monotonic
        self._test_allow_current_namespace = _test_allow_current_namespace
        self.remote_session_validator = remote_session_validator
        self.colibri_session_validator = colibri_session_validator
        self._streams: dict[str, _Stream] = {}
        self._opening = 0
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._watchdog = threading.Thread(target=self._expire_loop, name="hermes-service-connector-watchdog", daemon=True)
        self._watchdog.start()

    def handlers(self) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
        targets = []
        if self.colibri_session_validator is not None or self._test_allow_current_namespace:
            targets.append("colibri-main")
        if self.remote_session_validator is not None or self._test_allow_current_namespace:
            targets.append("xpra-native")
        return {(operation, target): getattr(self, method)
                for operation, method in (("connector.open", "open"), ("connector.read", "read"),
                                          ("connector.write", "write"), ("connector.close", "close"))
                for target in targets}

    @staticmethod
    def _auth(context: HostContext, authorization: EffectAuthorization, operation: str,
              payload: bytes, peer_pid: int) -> None:
        context_digest = canonical_digest({**context.claims(), "signature": context.signature})
        if (authorization.operation != operation or authorization.profile_id != context.profile_id
                or authorization.uid != context.uid or authorization.request_digest != canonical_digest(payload)
                or context.operation != operation or context.final_payload_digest != canonical_digest(payload)
                or authorization.final_payload_digest != canonical_digest(payload)
                or authorization.enrollment_id != context.enrollment_id
                or authorization.generation != context.generation
                or authorization.context_digest != context_digest):
            raise AuthorityDenied("connector.binding", "connector grant is not bound to this peer and payload")

    def open(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
             timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool],
             _remote_session_seal: object | None = None) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.open", payload, peer_pid)
        body = _decode(payload, {"schema", "enrollment_id", "generation", "target_id", "action", "approved_route_id", "session_id", "deadline"})
        if type(body["schema"]) is not int or body["schema"] != 1 or body["action"] != "open":
            raise AuthorityDenied("connector.request", "connector open action is invalid")
        enrollment_id = _valid_id(body["enrollment_id"], "enrollment_id")
        generation = _valid_id(body["generation"], "generation")
        target_id = _valid_id(body["target_id"], "target_id")
        session_id = _valid_id(body["session_id"], "session_id")
        route_id = _valid_id(body["approved_route_id"], "approved_route_id")
        route = ROUTES.get((target_id, route_id))
        if route is None or route.profile_id != context.profile_id:
            raise AuthorityDenied("connector.route", "target route is not enrolled for this profile")
        if (authorization.target != target_id or authorization.capability != "hermes-service-connect"
                or body["enrollment_id"] != context.enrollment_id or generation != context.generation
                or context.operation != "connector.open" or context.intent_id != session_id):
            raise AuthorityDenied("connector.binding", "connector target does not match enrolled context")
        if (target_id == "xpra-native" and not self._test_allow_current_namespace
                and _remote_session_seal is not _REMOTE_SESSION_SEAL):
            if self.remote_session_validator is None or self.remote_session_validator(context, authorization, body) is not True:
                raise AuthorityDenied("connector.remote-session", "root-verified HI13 remote session is required")
        if target_id == "colibri-main" and not self._test_allow_current_namespace:
            if self.colibri_session_validator is None or self.colibri_session_validator(context, authorization, body) is not True:
                raise AuthorityDenied("connector.binding", "root-verified Colibri service admission is required")
        now = self.monotonic()
        deadline = body["deadline"]
        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline)
                or not now < float(deadline) <= now + self.limits.max_lease_seconds):
            raise AuthorityDenied("connector.deadline", "connector deadline is stale or exceeds the lease")
        if cancelled():
            raise AuthorityDenied("connector.cancelled", "connector open was cancelled")
        with self._lock:
            self._reap_expired_locked(now)
            if len(self._streams) + self._opening >= self.limits.max_sessions:
                raise AuthorityDenied("connector.capacity", "connector session capacity is exhausted")
            self._opening += 1
        lease: NamespaceLease | None = None
        retained_pidfd = -1
        try:
            resolved = self.resolve(enrollment_id, route.profile_id, generation, target_id, route_id)
            lease, stream_route = resolved, route
            if lease.generation != generation or not _pidfd_alive(lease.pidfd):
                raise AuthorityDenied("connector.identity", "registered service identity changed")
            if peer_pidfd is None or not _pidfd_alive(peer_pidfd):
                raise AuthorityDenied("connector.peer", "connector caller exited")
            retained_pidfd = os.dup(peer_pidfd)
            sock = self._connect_namespace(lease, stream_route, min(timeout, self.limits.max_open_timeout))
            if stream_route.protocol == "websocket":
                _websocket_handshake(sock, stream_route, min(timeout, self.limits.max_open_timeout))
            if cancelled() or not _pidfd_alive(peer_pidfd) or not _pidfd_alive(lease.pidfd):
                raise AuthorityDenied("connector.cancelled", "connector open ended after cancellation or identity exit")
        except BaseException:
            if lease is not None:
                lease.close()
            if "sock" in locals():
                sock.close()
            if retained_pidfd >= 0:
                os.close(retained_pidfd)
            with self._lock:
                self._opening -= 1
            raise
        connector_id = uuid.uuid4().hex
        stream = _Stream(connector_id, stream_route, sock, lease, context.uid, peer_pid, retained_pidfd, context.lineage_hash,
                         session_id, min(float(deadline), now + self.limits.max_lease_seconds),
                         route.max_session_bytes, lock=threading.Lock())
        with self._lock:
            self._opening -= 1
            self._streams[connector_id] = stream
        return _json_response({"schema": 1, "connector_id": connector_id, "generation": generation,
                               "expires_monotonic": stream.expires, "max_frame_bytes": route.max_frame_bytes,
                               "remaining_byte_budget": stream.remaining})

    def _connect_namespace(self, lease: NamespaceLease, route: Route, timeout: float,
                            before_connect: Callable[[], None] | None = None) -> socket.socket:
        if not hasattr(os, "setns") and not self._test_allow_current_namespace:
            raise AuthorityDenied("connector.unavailable", "Linux network namespace entry is unavailable")
        result: list[socket.socket] = []
        failure: list[BaseException] = []
        done = threading.Event()
        def worker() -> None:
            original = None
            sock = None
            try:
                if not self._test_allow_current_namespace:
                    if not hasattr(os, "setns") or lease.namespace_fd < 0:
                        raise AuthorityDenied("connector.namespace", "protected service namespace lease is unavailable")
                    original = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                    os.setns(lease.namespace_fd, getattr(os, "CLONE_NEWNET", 0))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
                sock.settimeout(timeout)
                if before_connect is not None:
                    before_connect()
                sock.connect(("127.0.0.1", route.port))
                result.append(sock)
            except BaseException as exc:
                if sock is not None:
                    sock.close()
                failure.append(exc)
            finally:
                if original is not None:
                    try:
                        os.setns(original, getattr(os, "CLONE_NEWNET", 0))
                    except OSError as exc:
                        failure.append(exc)
                    os.close(original)
                done.set()
        thread = threading.Thread(target=worker, name="hermes-service-netns-connect", daemon=True)
        thread.start()
        if not done.wait(timeout + 0.25):
            raise AuthorityDenied("connector.timeout", "namespace connector exceeded its deadline")
        if failure:
            exc = failure[0]
            if isinstance(exc, AuthorityDenied):
                raise exc
            raise AuthorityDenied("connector.connect", "fixed service loopback connection failed") from exc
        if not result:
            raise AuthorityDenied("connector.connect", "fixed service loopback connection failed")
        result[0].setblocking(False)
        return result[0]

    def _recv_bounded(self, stream: _Stream, amount: int, timeout: float,
                      cancelled: Callable[[], bool],
                      before_receive: Callable[[], None] | None = None,
                      after_receive: Callable[[int], None] | None = None) -> bytes:
        consumed = False
        deadline = min(stream.expires, self.monotonic() + timeout)
        while True:
            if cancelled() or not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd):
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector read was cancelled or its owner exited")
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                if self.monotonic() >= stream.expires:
                    self._dispose(stream)
                    raise AuthorityDenied("connector.expired", "connector lease expired during read")
                raise AuthorityDenied("connector.read.timeout", "fixed service read timed out")
            try:
                readable, _, _ = select.select([stream.sock], [], [], min(0.05, remaining))
                if readable:
                    if not consumed and before_receive is not None:
                        before_receive()
                        consumed = True
                    data = stream.sock.recv(amount)
                    if data and after_receive is not None:
                        after_receive(len(data))
                    return data
            except (OSError, TimeoutError) as exc:
                self._dispose(stream)
                raise AuthorityDenied("connector.read", "fixed service read failed") from exc

    def _send_bounded(self, stream: _Stream, data: bytes, timeout: float,
                      cancelled: Callable[[], bool],
                      before_send: Callable[[], None] | None = None,
                      after_send: Callable[[int], None] | None = None) -> None:
        deadline = min(stream.expires, self.monotonic() + timeout)
        cursor = 0
        consumed = False
        while cursor < len(data):
            if cancelled() or not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd):
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector write was cancelled or its owner exited")
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                self._dispose(stream)
                raise AuthorityDenied("connector.timeout", "fixed service write exceeded its deadline")
            try:
                _, writable, _ = select.select([], [stream.sock], [], min(0.05, remaining))
                if writable:
                    if not consumed and before_send is not None:
                        before_send()
                        consumed = True
                    sent = stream.sock.send(data[cursor:])
                    if sent == 0:
                        raise OSError("fixed stream closed while writing")
                    cursor += sent
                    if after_send is not None:
                        after_send(sent)
            except (OSError, TimeoutError) as exc:
                self._dispose(stream)
                raise AuthorityDenied("connector.write", "fixed service write failed") from exc

    def _stream(self, body: Mapping[str, Any], context: HostContext, authorization: EffectAuthorization,
                operation: str, payload: bytes, peer_pid: int) -> _Stream:
        self._auth(context, authorization, operation, payload, peer_pid)
        connector_id = _valid_id(body.get("connector_id"), "connector_id")
        with self._lock:
            stream = self._streams.get(connector_id)
        if stream is None:
            raise AuthorityDenied("connector.closed", "connector handle is unavailable")
        if not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd):
            self._dispose(stream)
            raise AuthorityDenied("connector.peer", "connector peer or service process exited")
        if (stream.owner_uid != context.uid or stream.owner_pid != peer_pid
                or stream.lineage_hash != context.lineage_hash
                or stream.session_id != body.get("session_id")
                or context.intent_id != stream.session_id
                or context.profile_id != stream.route.profile_id
                or authorization.target != stream.route.target_id
                or authorization.capability != "hermes-service-connect"
                or body.get("target_id") != stream.route.target_id
                or body.get("route_id") != stream.route.route_id):
            raise AuthorityDenied("connector.peer", "connector handle is bound to another peer or session")
        frame_deadline = body.get("deadline")
        now = self.monotonic()
        if (body.get("generation") != stream.lease.generation
                or stream.lease.generation != authorization.generation
                or isinstance(frame_deadline, bool) or not isinstance(frame_deadline, (int, float))
                or not math.isfinite(frame_deadline)
                or not now < frame_deadline <= min(now + 5.0, stream.expires)):
            self._dispose(stream)
            raise AuthorityDenied("connector.deadline", "connector frame generation or deadline is invalid")
        if now >= stream.expires:
            self._dispose(stream)
            raise AuthorityDenied("connector.expired", "connector handle expired or generation changed")
        return stream

    def read(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
             timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.read", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "generation", "deadline", "sequence", "max_bytes"})
        stream = self._stream(body, context, authorization, "connector.read", payload, peer_pid)
        amount = body["max_bytes"]
        if (type(body["schema"]) is not int or body["schema"] != 1
                or type(body["sequence"]) is not int or type(amount) is not int
                or not 1 <= amount <= stream.route.max_frame_bytes):
            raise AuthorityDenied("connector.frame", "connector read frame bounds are invalid")
        with _exclusive(stream):
            if body["sequence"] != stream.sequence:
                raise AuthorityDenied("connector.replay", "connector operation sequence is stale")
            if cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector read was cancelled")
            try:
                if stream.route.protocol == "websocket":
                    data = _websocket_read(stream, min(amount, stream.remaining), timeout, cancelled)
                else:
                    data = self._recv_bounded(stream, min(amount, stream.remaining), timeout, cancelled)
            except AuthorityDenied:
                self._dispose(stream)
                raise
            stream.sequence += 1
            stream.remaining -= len(data)
            if not data:
                self._dispose(stream)
            return _json_response({"schema": 1, "sequence": body["sequence"], "data_b64": __import__("base64").b64encode(data).decode("ascii"), "remaining_byte_budget": stream.remaining})

    def write(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
              timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.write", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "generation", "deadline", "sequence", "data_b64"})
        stream = self._stream(body, context, authorization, "connector.write", payload, peer_pid)
        import base64
        try:
            data = base64.b64decode(body["data_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise AuthorityDenied("connector.frame", "connector frame encoding is invalid") from exc
        if (type(body["schema"]) is not int or body["schema"] != 1
                or type(body["sequence"]) is not int or not data
                or len(data) > stream.route.max_frame_bytes):
            raise AuthorityDenied("connector.frame", "connector write frame bounds are invalid")
        with _exclusive(stream):
            if body["sequence"] != stream.sequence:
                raise AuthorityDenied("connector.replay", "connector operation sequence is stale")
            if len(data) > stream.remaining or cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector write exceeds budget or was cancelled")
            requested_bytes = len(data)
            if stream.route.protocol == "websocket":
                data = _websocket_client_frame(2, data)
            elif stream.route.protocol in {"xpra-http", "openai-http"}:
                if stream.http_request_sent:
                    raise AuthorityDenied("connector.protocol", "HTTP connector accepts only one fixed request frame")
                try:
                    data = _parse_http_frame(data, stream.route)
                except AuthorityDenied:
                    self._dispose(stream)
                    raise
                stream.http_request_sent = True
            if len(data) > stream.remaining:
                self._dispose(stream)
                raise AuthorityDenied("connector.frame", "framed request exceeds the remaining byte budget")
            self._send_bounded(stream, data, timeout, cancelled)
            stream.remaining -= requested_bytes
            stream.sequence += 1
        return _json_response({"schema": 1, "sequence": body["sequence"], "written": requested_bytes, "remaining_byte_budget": stream.remaining})

    def close(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
              timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.close", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "generation", "deadline", "sequence"})
        stream = self._stream(body, context, authorization, "connector.close", payload, peer_pid)
        with _exclusive(stream):
            if (type(body["schema"]) is not int or body["schema"] != 1
                    or type(body["sequence"]) is not int or body["sequence"] != stream.sequence):
                raise AuthorityDenied("connector.replay", "connector close sequence is stale")
            self._dispose(stream)
        return _json_response({"schema": 1, "closed": True})

    def _remote_open(self, binding: Any, payload: bytes, *, timeout: float,
                     peer_uid: int, peer_pid: int, peer_pidfd: int,
                     cancelled: Callable[[], bool], before_connect: Callable[[], None],
                     seal: object,
                     resolve_lease: Callable[[Any, Route], NamespaceLease] | None = None,
                     after_open_send: Callable[[int], None] | None = None,
                     after_open_receive: Callable[[int], None] | None = None
                     ) -> Mapping[str, Any]:
        """Root-only open path; the HI13/HI12 consumer runs before connect."""
        if seal is not _REMOTE_SESSION_SEAL:
            raise AuthorityDenied("connector.remote-session", "root connector seal is invalid")
        expected = open_request_bytes(
            enrollment_id=binding.enrollment_id, generation=binding.native_generation,
            target_id=binding.target_id, route_id=binding.route_id,
            session_id=binding.session_id, deadline=binding.lease_expires_monotonic)
        if payload != expected or not _pidfd_alive(peer_pidfd) or cancelled():
            raise AuthorityDenied("connector.remote-binding", "root open payload or identity is stale")
        route = ROUTES.get((binding.target_id, binding.route_id))
        if (route is None or route.profile_id != binding.native_profile_id
                or binding.target_id != "xpra-native"
                or binding.action not in {"asset-read", "websocket-attach"}
                or (binding.action == "asset-read") != (route.protocol == "xpra-http")):
            raise AuthorityDenied("connector.route", "root open target or route is outside fixed Xpra policy")
        now = self.monotonic()
        deadline = binding.lease_expires_monotonic
        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline) or not now < deadline <= now + self.limits.max_lease_seconds):
            raise AuthorityDenied("connector.deadline", "root open deadline is invalid")
        with self._lock:
            self._reap_expired_locked(now)
            if len(self._streams) + self._opening >= self.limits.max_sessions:
                raise AuthorityDenied("connector.capacity", "connector session capacity is exhausted")
            self._opening += 1
        lease: NamespaceLease | None = None
        retained_pidfd = -1
        sock: socket.socket | None = None
        try:
            if resolve_lease is None:
                lease = self.resolve(binding.enrollment_id, route.profile_id,
                                     binding.native_generation, binding.target_id, binding.route_id)
            else:
                lease = resolve_lease(binding, route)
            if (lease.generation != binding.native_generation or not _pidfd_alive(lease.pidfd)
                    or not _pidfd_alive(peer_pidfd) or cancelled()):
                raise AuthorityDenied("connector.identity", "current root service or gateway identity is unavailable")
            retained_pidfd = os.dup(peer_pidfd)
            sock = self._connect_namespace(lease, route,
                                           min(timeout, self.limits.max_open_timeout),
                                           before_connect=before_connect)
            if route.protocol == "websocket":
                _websocket_handshake(sock, route, min(timeout, self.limits.max_open_timeout),
                                     after_send=after_open_send, after_receive=after_open_receive)
            if cancelled() or not _pidfd_alive(peer_pidfd) or not _pidfd_alive(lease.pidfd):
                raise AuthorityDenied("connector.cancelled", "root connector open ended after cancellation")
        except BaseException:
            if lease is not None:
                lease.close()
            if sock is not None:
                sock.close()
            if retained_pidfd >= 0:
                os.close(retained_pidfd)
            with self._lock:
                self._opening -= 1
            raise
        connector_id = uuid.uuid4().hex
        stream = _Stream(connector_id, route, sock, lease, peer_uid, peer_pid,
                         retained_pidfd, binding.token_fingerprint, binding.session_id,
                         float(deadline), route.max_session_bytes, lock=threading.Lock())
        with self._lock:
            self._opening -= 1
            self._streams[connector_id] = stream
        return _json_response({"schema": 1, "connector_id": connector_id,
                               "generation": binding.native_generation,
                               "expires_monotonic": stream.expires,
                               "max_frame_bytes": route.max_frame_bytes,
                               "remaining_byte_budget": stream.remaining})

    def _remote_stream(self, binding: Any, connector_id: str, sequence: int,
                       peer_uid: int, peer_pid: int, peer_pidfd: int,
                       cancelled: Callable[[], bool]) -> _Stream:
        if (type(connector_id) is not str or not _ID.fullmatch(connector_id)
                or type(sequence) is not int or sequence < 0
                or binding.connector_handle != connector_id
                or binding.next_sequence != sequence):
            raise AuthorityDenied("connector.frame", "root connector handle or sequence is stale")
        with self._lock:
            stream = self._streams.get(connector_id)
        if stream is None:
            raise AuthorityDenied("connector.closed", "root connector handle is unavailable")
        now = self.monotonic()
        deadline = binding.frame_deadline_monotonic
        if (stream.owner_uid != peer_uid or stream.owner_pid != peer_pid
                or stream.session_id != binding.session_id
                or stream.route.target_id != binding.target_id or stream.route.route_id != binding.route_id
                or stream.lease.generation != binding.native_generation
                or not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd)
                or not _pidfd_alive(peer_pidfd) or cancelled()
                or now >= stream.expires
                or isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline) or not now < deadline <= min(now + 5.0, stream.expires)):
            self._dispose(stream)
            raise AuthorityDenied("connector.peer", "root connector frame binding, generation, or deadline is stale")
        if stream.sequence != sequence:
            raise AuthorityDenied("connector.replay", "root connector frame sequence was replayed")
        return stream

    def _remote_write(self, binding: Any, connector_id: str, sequence: int,
                      data: bytes, payload: bytes, *, timeout: float, peer_uid: int,
                      peer_pid: int, peer_pidfd: int, cancelled: Callable[[], bool],
                      before_send: Callable[[], None], seal: object,
                      after_send: Callable[[int], None] | None = None) -> int:
        if seal is not _REMOTE_SESSION_SEAL or not isinstance(data, bytes) or not data:
            raise AuthorityDenied("connector.remote-session", "root connector write input is invalid")
        body = {"schema": 1, "target_id": binding.target_id, "route_id": binding.route_id,
                "connector_id": connector_id, "session_id": binding.session_id,
                "generation": binding.native_generation,
                "deadline": binding.frame_deadline_monotonic,
                "sequence": sequence, "data_b64": base64.b64encode(data).decode("ascii")}
        if payload != canonical_bytes(body):
            raise AuthorityDenied("connector.remote-binding", "root write payload is not canonical")
        stream = self._remote_stream(binding, connector_id, sequence, peer_uid, peer_pid,
                                     peer_pidfd, cancelled)
        if len(data) > stream.route.max_frame_bytes or len(data) > stream.remaining:
            self._dispose(stream)
            raise AuthorityDenied("connector.frame", "root write exceeds its fixed byte budget")
        with _exclusive(stream):
            if cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "root connector write was cancelled")
            requested = len(data)
            framed = data
            if stream.route.protocol == "websocket":
                framed = _websocket_client_frame(2, data)
            elif stream.route.protocol in {"xpra-http", "openai-http"}:
                if stream.http_request_sent:
                    raise AuthorityDenied("connector.protocol", "fixed HTTP route permits one request per stream")
                framed = _parse_http_frame(data, stream.route)
                stream.http_request_sent = True
            if len(framed) > stream.remaining:
                self._dispose(stream)
                raise AuthorityDenied("connector.frame", "framed request exceeds connector byte budget")
            self._send_bounded(stream, framed, timeout, cancelled, before_send=before_send,
                               after_send=after_send)
            stream.remaining -= requested
            stream.sequence += 1
        return requested

    def _remote_read(self, binding: Any, connector_id: str, sequence: int,
                     maximum_bytes: int, payload: bytes, *, timeout: float,
                     peer_uid: int, peer_pid: int, peer_pidfd: int,
                     cancelled: Callable[[], bool], before_receive: Callable[[], None],
                     seal: object, after_receive: Callable[[int], None] | None = None
                     ) -> tuple[bytes, bool]:
        if seal is not _REMOTE_SESSION_SEAL or type(maximum_bytes) is not int:
            raise AuthorityDenied("connector.remote-session", "root connector read input is invalid")
        body = {"schema": 1, "target_id": binding.target_id, "route_id": binding.route_id,
                "connector_id": connector_id, "session_id": binding.session_id,
                "generation": binding.native_generation,
                "deadline": binding.frame_deadline_monotonic,
                "sequence": sequence, "max_bytes": maximum_bytes}
        if payload != canonical_bytes(body):
            raise AuthorityDenied("connector.remote-binding", "root read payload is not canonical")
        stream = self._remote_stream(binding, connector_id, sequence, peer_uid, peer_pid,
                                     peer_pidfd, cancelled)
        if not 1 <= maximum_bytes <= stream.route.max_frame_bytes:
            raise AuthorityDenied("connector.frame", "root read limit exceeds fixed bound")
        with _exclusive(stream):
            if cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "root connector read was cancelled")
            amount = min(maximum_bytes, stream.remaining)
            try:
                if stream.route.protocol == "websocket":
                    data = _websocket_read(stream, amount, timeout, cancelled,
                                           before_receive=before_receive, after_receive=after_receive)
                else:
                    data = self._recv_bounded(stream, amount, timeout, cancelled,
                                              before_receive=before_receive, after_receive=after_receive)
            except AuthorityDenied:
                self._dispose(stream)
                raise
            stream.sequence += 1
            stream.remaining -= len(data)
            if not data:
                self._dispose(stream)
            return data, not data

    def _remote_close(self, binding: Any, connector_id: str, authorization: Any,
                      payload: bytes, *, peer_uid: int, peer_pid: int, peer_pidfd: int,
                      before_close: Callable[[], None], cleanup: bool, seal: object) -> None:
        if seal is not _REMOTE_SESSION_SEAL:
            raise AuthorityDenied("connector.remote-session", "root connector seal is invalid")
        if cleanup and authorization is None:
            with self._lock:
                stream = self._streams.get(connector_id)
            if stream is not None:
                self._dispose(stream)
            return
        sequence = getattr(authorization, "sequence", -1)
        body = {"schema": 1, "target_id": binding.target_id, "route_id": binding.route_id,
                "connector_id": connector_id, "session_id": binding.session_id,
                "generation": binding.native_generation,
                "deadline": binding.frame_deadline_monotonic, "sequence": sequence}
        if payload != canonical_bytes(body):
            raise AuthorityDenied("connector.remote-binding", "root close payload is not canonical")
        stream = self._remote_stream(binding, connector_id, sequence, peer_uid, peer_pid,
                                     peer_pidfd, binding.cancelled)
        with _exclusive(stream):
            before_close()
            self._dispose(stream)

    def _dispose(self, stream: _Stream) -> None:
        with self._lock:
            if self._streams.pop(stream.connector_id, None) is not stream:
                return
        try:
            stream.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        stream.sock.close()
        stream.lease.close()
        os.close(stream.owner_pidfd)

    def _reap_expired_locked(self, now: float) -> None:
        for stream in tuple(self._streams.values()):
            if now >= stream.expires:
                self._dispose(stream)

    def _expire_loop(self) -> None:
        while not self._closed.wait(0.05):
            with self._lock:
                self._reap_expired_locked(self.monotonic())

    def shutdown(self) -> None:
        self._closed.set()
        with self._lock:
            for stream in tuple(self._streams.values()):
                self._dispose(stream)
        self._watchdog.join(timeout=1.0)


def build_service_connector_handlers(*, resolve_service_namespace: Callable[[str, str, str, str, str], NamespaceLease],
                                     limits: ConnectorLimits = ConnectorLimits(),
                                     remote_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None,
                                     colibri_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None
                                     ) -> tuple[FixedServiceConnector, Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]]:
    connector = FixedServiceConnector(resolve_service_namespace=resolve_service_namespace, limits=limits,
                                      remote_session_validator=remote_session_validator,
                                      colibri_session_validator=colibri_session_validator)
    return connector, connector.handlers()


def build_enrolled_service_connector_handlers(*, catalog: Any, process_manager: Any,
                                              limits: ConnectorLimits = ConnectorLimits(),
                                              remote_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None,
                                              colibri_session_validator: Callable[[HostContext, EffectAuthorization, Mapping[str, Any]], bool] | None = None
                                              ) -> tuple[FixedServiceConnector, Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]]:
    """Bind fixed route IDs to the root catalog and same live custody manager.

    Memory compound routes are intentionally handled by the separate typed
    executor; they are never registered as generic raw HTTP streams here.
    """
    def resolve(enrollment_id: str, profile_id: str, generation: str,
                target_id: str, route_id: str) -> NamespaceLease:
        try:
            binding = catalog.resolve_connector_route(enrollment_id, generation, target_id, route_id)
        except Exception as exc:
            if isinstance(exc, AuthorityDenied):
                raise
            raise AuthorityDenied("connector.route", "protected route resolution failed") from exc
        if binding.profile_id != profile_id or binding.generation != generation:
            raise AuthorityDenied("connector.binding", "protected route differs from signed service scope")
        lease = process_manager.resolve_namespace_lease(binding)
        if lease is None:
            raise AuthorityDenied("connector.identity", "no current supervised service namespace lease exists")
        route = ROUTES.get((target_id, route_id))
        if route is None:
            lease.close()
            raise AuthorityDenied("connector.route", "target route is not statically enrolled")
        return lease

    return build_service_connector_handlers(resolve_service_namespace=resolve, limits=limits,
                                            remote_session_validator=remote_session_validator,
                                            colibri_session_validator=colibri_session_validator)


class RemoteServiceConnectorBackend:
    """HI13 root backend adapter over the HI07 fixed socket effects.

    The root remote-session authority supplies its verified binding, fresh
    operation authorization, and kernel-observed gateway peer identity. No
    gateway data is trusted to choose a target, route, generation, or deadline.
    """

    def __init__(self, connector: FixedServiceConnector, *,
                 validate_binding: Callable[[Any, str, int], bool],
                 consume_effect: Callable[..., bool],
                 cancelled: Callable[[Any], bool] | None = None):
        if not callable(validate_binding) or not callable(consume_effect):
            raise ValueError("root remote-session validator and HI12 effect consumer are required")
        self.connector = connector
        self.validate_binding = validate_binding
        self.consume_effect = consume_effect
        self.cancelled = cancelled or (lambda binding: bool(binding.cancelled()))
        self._handles: dict[str, tuple[str, str]] = {}
        self._lock = threading.RLock()

    def _authorize(self, binding: Any, authorization: Any, operation: str,
                   payload: bytes, sequence: int, peer_uid: int,
                   peer_pid: int, peer_pidfd: int) -> Callable[[], None]:
        from hermes_installer.authority.remote_sessions import InternalRemoteConnectorAuthorization
        now = time.monotonic()
        deadline = (binding.lease_expires_monotonic if operation == "connector.open"
                    else binding.frame_deadline_monotonic)
        if (not isinstance(authorization, InternalRemoteConnectorAuthorization)
                or authorization.effective_principal_id != binding.principal_id
                or authorization.effective_native_profile_id != binding.native_profile_id
                or authorization.effective_native_generation != binding.native_generation
                or authorization.controller_gateway_identity_digest != binding.gateway_identity.identity_digest
                or authorization.controller_gateway_generation != binding.gateway_generation
                or authorization.remote_session_id != binding.session_id
                or authorization.token_fingerprint != binding.token_fingerprint
                or authorization.policy_revision != binding.policy_revision
                or authorization.policy_config_digest != binding.policy_config_digest
                or authorization.service_generation_digest != binding.service_generation_digest
                or authorization.connector_target_id != binding.target_id
                or authorization.route_id != binding.route_id
                or authorization.operation != operation
                or authorization.canonical_payload_sha256 != hashlib.sha256(payload).hexdigest()
                or authorization.sequence != sequence
                or authorization.issued_monotonic > now
                or not now < authorization.expires_monotonic <= min(deadline, binding.lease_expires_monotonic)
                or self.validate_binding(binding, operation, sequence) is not True):
            raise AuthorityDenied("connector.remote-authorization", "HI13 authorization is stale or not bound to this effect")

        def consume() -> None:
            if self.consume_effect(
                    authorization, binding, operation, payload, sequence,
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd) is not True:
                raise AuthorityDenied("connector.remote-authorization", "HI12 connector grant consumption failed")
        return consume

    @staticmethod
    def _peer(binding: Any, peer_uid: int, peer_pid: int, peer_pidfd: int | None) -> None:
        identity = binding.gateway_identity
        if (type(peer_uid) is not int or type(peer_pid) is not int or peer_pid <= 0
                or peer_pidfd is None or peer_pidfd < 0
                or identity.uid != peer_uid or identity.pid != peer_pid
                or identity.profile_id != binding.gateway_profile_id
                or identity.generation != binding.gateway_generation):
            raise AuthorityDenied("connector.peer", "current authority peer differs from root gateway identity")

    @staticmethod
    def _frame_timeout(binding: Any) -> float:
        remaining = binding.frame_deadline_monotonic - time.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("connector.deadline", "root remote connector frame deadline expired")
        return min(5.0, remaining)

    def _refresh_root_lease(self, binding: Any, connector_handle: str) -> None:
        """Observe only the current root lease after binding revalidation."""
        stream = self.connector._streams.get(connector_handle)
        deadline = binding.lease_expires_monotonic
        now = time.monotonic()
        if (stream is None or isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not math.isfinite(deadline) or not now < deadline <= now + 60.0):
            raise AuthorityDenied("connector.expired", "root remote lease cannot extend this connector")
        if deadline > stream.expires:
            stream.expires = float(deadline)

    def open(self, binding: Any, *, authorization: Any, peer_uid: int, peer_pid: int,
             peer_pidfd: int | None) -> str:
        self._peer(binding, peer_uid, peer_pid, peer_pidfd)
        if binding.target_id != "xpra-native" or binding.route_id not in {"xpra-http", "xpra-websocket"}:
            raise AuthorityDenied("connector.route", "HI13 Xpra connector route is not fixed and enrolled")
        if binding.action not in {"asset-read", "websocket-attach"}:
            raise AuthorityDenied("connector.action", "HI13 action is not an Xpra asset or binary WebSocket")
        route = ROUTES.get((binding.target_id, binding.route_id))
        if route is None or (binding.action == "asset-read") != (route.protocol == "xpra-http"):
            raise AuthorityDenied("connector.route", "HI13 action and fixed Xpra route disagree")
        deadline = binding.lease_expires_monotonic
        payload = open_request_bytes(enrollment_id=binding.enrollment_id,
                                     generation=binding.native_generation,
                                     target_id=binding.target_id, route_id=binding.route_id,
                                     session_id=binding.session_id, deadline=deadline)
        before_connect = self._authorize(binding, authorization, "connector.open", payload,
                                         0, peer_uid, peer_pid, peer_pidfd)
        result = self.connector._remote_open(
            binding, payload, timeout=self._frame_timeout(binding), peer_uid=peer_uid,
            peer_pid=peer_pid, peer_pidfd=peer_pidfd,
            cancelled=lambda: self.cancelled(binding), before_connect=before_connect,
            seal=_REMOTE_SESSION_SEAL)
        value = json.loads(result["body"])
        connector_id = _valid_id(value.get("connector_id"), "connector_id")
        if value.get("generation") != binding.native_generation:
            stream = self.connector._streams.get(connector_id)
            if stream is not None:
                self.connector._dispose(stream)
            raise AuthorityDenied("connector.generation", "root connector opened another service generation")
        with self._lock:
            if connector_id in self._handles:
                stream = self.connector._streams.get(connector_id)
                if stream is not None:
                    self.connector._dispose(stream)
                raise AuthorityDenied("connector.handle", "root connector returned a duplicate handle")
            self._handles[connector_id] = (binding.session_id, binding.route_id)
        return connector_id

    def read(self, binding: Any, connector_handle: str, sequence: int, maximum_bytes: int,
             *, authorization: Any, peer_uid: int, peer_pid: int, peer_pidfd: int | None,
             cancelled: Callable[[], bool]) -> tuple[bytes, bool]:
        return self._frame(binding, connector_handle, sequence, "read", authorization,
                           peer_uid, peer_pid, peer_pidfd, cancelled, max_bytes=maximum_bytes)

    def write(self, binding: Any, connector_handle: str, sequence: int, data_bytes: bytes,
              *, authorization: Any, peer_uid: int, peer_pid: int, peer_pidfd: int | None,
              cancelled: Callable[[], bool]) -> int:
        result = self._frame(binding, connector_handle, sequence, "write", authorization,
                             peer_uid, peer_pid, peer_pidfd, cancelled, data_bytes=data_bytes)
        return result

    def _frame(self, binding: Any, connector_handle: str, sequence: int, verb: str,
               authorization: Any, peer_uid: int, peer_pid: int, peer_pidfd: int | None,
               cancelled: Callable[[], bool], *, max_bytes: int | None = None,
               data_bytes: bytes | None = None) -> Any:
        self._peer(binding, peer_uid, peer_pid, peer_pidfd)
        route_id = binding.route_id
        if (type(sequence) is not int or sequence < 0
                or type(connector_handle) is not str or not _ID.fullmatch(connector_handle)):
            raise AuthorityDenied("connector.frame", "root connector frame handle or sequence is invalid")
        with self._lock:
            owner = self._handles.get(connector_handle)
        if owner != (binding.session_id, route_id):
            raise AuthorityDenied("connector.handle", "root connector handle belongs to another HI13 session")
        if binding.next_sequence != sequence or binding.connector_handle != connector_handle:
            raise AuthorityDenied("connector.replay", "frame differs from current root connector state")
        self._refresh_root_lease(binding, connector_handle)
        body: dict[str, Any] = {"schema": 1, "target_id": binding.target_id,
                                "route_id": route_id, "connector_id": connector_handle,
                                "session_id": binding.session_id,
                                "generation": binding.native_generation,
                                "deadline": binding.frame_deadline_monotonic,
                                "sequence": sequence}
        if verb == "read":
            if type(max_bytes) is not int or not 1 <= max_bytes <= 1_048_576:
                raise AuthorityDenied("connector.frame", "read frame is outside its fixed bound")
            body["max_bytes"] = max_bytes
        else:
            if not isinstance(data_bytes, bytes) or not 1 <= len(data_bytes) <= 1_048_576:
                raise AuthorityDenied("connector.frame", "write frame is outside its fixed bound")
            body["data_b64"] = base64.b64encode(data_bytes).decode("ascii")
        payload = canonical_bytes(body)
        before_effect = self._authorize(binding, authorization, "connector." + verb, payload,
                                        sequence, peer_uid, peer_pid, peer_pidfd)
        if verb == "read":
            data, eof = self.connector._remote_read(
                binding, connector_handle, sequence, max_bytes, payload,
                timeout=self._frame_timeout(binding), peer_uid=peer_uid, peer_pid=peer_pid,
                peer_pidfd=peer_pidfd, cancelled=lambda: cancelled() or self.cancelled(binding),
                before_receive=before_effect, seal=_REMOTE_SESSION_SEAL)
            if not data:
                self._forget(connector_handle)
            return data, eof
        return self.connector._remote_write(
            binding, connector_handle, sequence, data_bytes, payload,
            timeout=self._frame_timeout(binding), peer_uid=peer_uid, peer_pid=peer_pid,
            peer_pidfd=peer_pidfd, cancelled=lambda: cancelled() or self.cancelled(binding),
            before_send=before_effect, seal=_REMOTE_SESSION_SEAL)

    def close(self, binding: Any, connector_handle: str, *, authorization: Any | None,
              cleanup: bool = False, peer_uid: int | None = None,
              peer_pid: int | None = None, peer_pidfd: int | None = None) -> None:
        with self._lock:
            owner = self._handles.get(connector_handle)
        if owner != (binding.session_id, binding.route_id):
            return
        if cleanup and authorization is None:
            self.connector._remote_close(
                binding, connector_handle, None, b"", peer_uid=0, peer_pid=0, peer_pidfd=-1,
                before_close=lambda: None, cleanup=True, seal=_REMOTE_SESSION_SEAL)
            self._forget(connector_handle)
            return
        if peer_uid is None or peer_pid is None or peer_pidfd is None:
            raise AuthorityDenied("connector.close", "current gateway peer is required to consume close authorization")
        sequence = getattr(authorization, "sequence", -1)
        payload = canonical_bytes({"schema": 1, "target_id": binding.target_id,
                                   "route_id": binding.route_id, "connector_id": connector_handle,
                                   "session_id": binding.session_id,
                                   "generation": binding.native_generation,
                                   "deadline": binding.frame_deadline_monotonic,
                                   "sequence": sequence})
        before_close = self._authorize(binding, authorization, "connector.close", payload,
                                       sequence, peer_uid, peer_pid, peer_pidfd)
        self.connector._remote_close(
            binding, connector_handle, authorization, payload, peer_uid=peer_uid,
            peer_pid=peer_pid, peer_pidfd=peer_pidfd, before_close=before_close,
            cleanup=cleanup, seal=_REMOTE_SESSION_SEAL)
        self._forget(connector_handle)

    def _forget(self, connector_handle: str) -> None:
        with self._lock:
            self._handles.pop(connector_handle, None)


@dataclass(frozen=True, slots=True)
class SetupProbeAssetResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes


@dataclass(frozen=True, slots=True)
class RemoteProbeByteSnapshot:
    """Immutable byte/effect counters for one authenticated root probe window."""

    read_bytes: int
    write_bytes: int
    open_effects: int
    frame_effects: int


class SetupProbeConnectorBackend:
    """Setup-only Xpra broker driven by root probe handles and one-use HI12 grants.

    This private adapter is intentionally separate from the public HI13 session
    backend. It accepts no HTTP request bytes, path, URL, or caller-selected
    route; assets are selected by opaque manifest ID and WebSocket frames are
    binary-only through the fixed ``xpra-native`` routes.
    """

    def __init__(self, connector: FixedServiceConnector, *, catalog: Any,
                 process_manager: Any, probe_authority: Any,
                 resolve_probe_connector_binding: Callable[[str, int, int, int], Any],
                 resolve_probe_asset_path: Callable[[Any, str], str],
                 advance_sequence: Callable[..., bool] | None = None,
                 verify_observer_capability: Callable[[Any], bool] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        from hermes_installer.authority.remote_probe_connector_authority import SetupProbeConnectorAuthority
        if (not isinstance(probe_authority, SetupProbeConnectorAuthority)
                or not callable(resolve_probe_connector_binding)
                or not callable(resolve_probe_asset_path)):
            raise ValueError("root setup authority, binding, asset, and sequence APIs are required")
        if advance_sequence is None:
            advance_sequence = getattr(probe_authority, "advance_probe_connector_sequence", None)
        if not callable(advance_sequence):
            raise ValueError("root probe authority must provide atomic sequence advancement")
        self.connector = connector
        self.catalog = catalog
        self.process_manager = process_manager
        self.authority = probe_authority
        self.resolve_binding = resolve_probe_connector_binding
        self.resolve_asset_path = resolve_probe_asset_path
        self.advance_sequence = advance_sequence
        self.verify_observer_capability = verify_observer_capability
        self.monotonic = monotonic
        self._probe_ledger_lock = threading.RLock()
        self._probe_ledger: dict[tuple[str, str, str], list[int]] = {}

    def snapshot_remote_probe_bytes(self, capability: Any) -> RemoteProbeByteSnapshot:
        """Return root-owned counters only for a live, root-verified observer capability."""
        if (not callable(self.verify_observer_capability)
                or self.verify_observer_capability(capability) is not True
                or not self.monotonic() < capability.expires_monotonic
                or capability.issued_monotonic > self.monotonic()
                or capability.expires_monotonic - capability.issued_monotonic > 25.0
                or type(capability.gateway_identity_digest) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", capability.gateway_identity_digest)
                or type(capability.native_enrollment_id) is not str
                or not capability.native_enrollment_id
                or type(capability.session_id) is not str
                or not capability.session_id):
            raise AuthorityDenied("connector.ledger", "root observer capability is unavailable or expired")
        key = (capability.gateway_identity_digest, capability.native_enrollment_id,
               capability.session_id)
        with self._probe_ledger_lock:
            counts = tuple(self._probe_ledger.get(key, (0, 0, 0, 0)))
        return RemoteProbeByteSnapshot(*counts)

    def _record_probe_effect(self, binding: Any, operation: str) -> None:
        key = (binding.gateway_identity_digest, binding.native_enrollment_id, binding.session_id)
        index = 2 if operation == "connector.open" else 3
        with self._probe_ledger_lock:
            counts = self._probe_ledger.setdefault(key, [0, 0, 0, 0])
            counts[index] += 1

    def _record_probe_bytes(self, binding: Any, direction: str, count: int) -> None:
        if type(count) is not int or count <= 0:
            return
        key = (binding.gateway_identity_digest, binding.native_enrollment_id, binding.session_id)
        index = 0 if direction == "read" else 1
        with self._probe_ledger_lock:
            counts = self._probe_ledger.setdefault(key, [0, 0, 0, 0])
            counts[index] += count

    def _current(self, handle: str, uid: int, pid: int, pidfd: int,
                 action: str, asset_id: str | None,
                 connector_id: str | None = None) -> Any:
        from hermes_installer.authority.remote_probe_connector_authority import RootSetupProbeBinding
        if (type(uid) is not int or type(pid) is not int or pid <= 0
                or type(pidfd) is not int or pidfd < 0):
            raise AuthorityDenied("connector.peer", "probe peer identity is invalid")
        try:
            value = self.resolve_binding(handle, uid, pid, pidfd)
        except Exception as exc:
            raise AuthorityDenied("connector.probe", "current setup probe binding is unavailable") from exc
        now = self.monotonic()
        if (not isinstance(value, RootSetupProbeBinding) or value.probe_handle != handle
                or value.selected_action != action or value.selected_asset_id != asset_id
                or value.connector_handle != connector_id
                or value.enrollment_id != value.native_enrollment_id
                or value.target_id != "xpra-native" or value.connector_target_id != "xpra-native"
                or value.approved_route_ids != ("xpra-http", "xpra-websocket")
                or value.cancelled() or not now < value.expires_monotonic
                or not now < value.frame_deadline_monotonic
                <= min(now + 5.0, value.expires_monotonic)):
            raise AuthorityDenied("connector.probe", "setup probe is expired or outside fixed Xpra scope")
        return value

    @staticmethod
    def _route(binding: Any) -> str:
        return "xpra-websocket" if binding.selected_action == "websocket-attach" else "xpra-http"

    @staticmethod
    def _view(binding: Any, connector_id: str | None = None) -> Any:
        from types import SimpleNamespace
        return SimpleNamespace(
            enrollment_id=binding.native_enrollment_id,
            native_generation=binding.native_generation,
            native_profile_id=binding.native_profile_id,
            target_id="xpra-native", route_id=SetupProbeConnectorBackend._route(binding),
            session_id=binding.session_id,
            lease_expires_monotonic=binding.expires_monotonic,
            frame_deadline_monotonic=binding.frame_deadline_monotonic,
            action="websocket-attach" if binding.selected_action == "websocket-attach" else "asset-read",
            token_fingerprint=hashlib.sha256(("setup-probe:" + binding.probe_actor_identity_digest).encode()).hexdigest(),
            connector_handle=connector_id, next_sequence=binding.next_sequence,
            cancelled=binding.cancelled)

    def _resolve_lease(self, binding: Any, route: Route) -> NamespaceLease:
        enrollment_id = getattr(binding, "native_enrollment_id", getattr(binding, "enrollment_id", None))
        generation = getattr(binding, "native_generation", None)
        profile_id = getattr(binding, "native_profile_id", None)
        try:
            protected = self.catalog.resolve_connector_route(
                enrollment_id, generation,
                "xpra-native", route.route_id)
        except Exception as exc:
            raise AuthorityDenied("connector.route", "protected Xpra route resolution failed") from exc
        if (protected.target_id != "xpra-native" or protected.route_id != route.route_id
                or protected.profile_id != profile_id
                or protected.generation != generation):
            raise AuthorityDenied("connector.route", "catalog route differs from the selected native service")
        lease = self.process_manager.resolve_namespace_lease(protected)
        if (lease is None or lease.generation != generation
                or lease.namespace_identity != protected.namespace_identity):
            if lease is not None:
                lease.close()
            raise AuthorityDenied("connector.identity", "current native service namespace is unavailable")
        return lease

    def _effect(self, handle: str, binding: Any, operation: str, payload: bytes,
                sequence: int, uid: int, pid: int, pidfd: int) -> None:
        from hermes_installer.authority.remote_probe_connector_authority import InternalProbeConnectorAuthorization
        auth = self.authority.issue_probe_connector_effect(
            handle, operation, payload, sequence, peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd)
        expected_deadline = (binding.expires_monotonic if operation == "connector.open"
                             else binding.frame_deadline_monotonic)
        if (not isinstance(auth, InternalProbeConnectorAuthorization)
                or auth.probe_handle != handle or auth.operation != operation
                or auth.frame_sequence != sequence or auth.route_id != self._route(binding)
                or auth.target_id != "xpra-native" or auth.connector_target_id != "xpra-native"
                or auth.enrollment_id != binding.native_enrollment_id
                or auth.session_id != binding.session_id
                or auth.selected_action != binding.selected_action
                or auth.selected_asset_id != binding.selected_asset_id
                or auth.connector_handle != binding.connector_handle
                or auth.asset_ids != binding.asset_ids
                or auth.native_enrollment_id != binding.native_enrollment_id
                or auth.native_identity_digest != binding.native_identity_digest
                or auth.native_profile_id != binding.native_profile_id
                or auth.native_generation != binding.native_generation
                or auth.gateway_identity_digest != binding.gateway_identity_digest
                or auth.gateway_profile_id != binding.gateway_profile_id
                or auth.gateway_generation != binding.gateway_generation
                or auth.probe_actor_identity_digest != binding.probe_actor_identity_digest
                or auth.setup_transaction_digest != binding.setup_transaction_digest
                or auth.setup_actor_identity_digest != binding.setup_actor_identity_digest
                or auth.probe_role_sha256 != binding.probe_role_sha256
                or auth.policy_revision != binding.policy_revision
                or auth.policy_config_digest != binding.policy_config_digest
                or auth.next_sequence != binding.next_sequence
                or auth.frame_sequence != sequence
                or auth.effect_sequence != binding.effect_sequence
                or auth.service_generation_digest != binding.service_generation_digest
                or auth.canonical_payload_sha256 != hashlib.sha256(payload).hexdigest()
                or auth.issued_monotonic > self.monotonic()
                or auth.expires_monotonic != expected_deadline
                or auth.expires_monotonic <= self.monotonic()):
            raise AuthorityDenied("connector.authorization", "one-use setup grant is stale or mismatched")
        if self.authority.consume_probe_connector_effect(
                auth, handle, operation, payload, sequence,
                peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd) is not True:
            raise AuthorityDenied("connector.authorization", "HI12 setup connector effect was denied")
        self._record_probe_effect(binding, operation)

    def _open(self, handle: str, binding: Any, uid: int, pid: int, pidfd: int) -> tuple[str, Mapping[str, Any]]:
        view = self._view(binding)
        payload = open_request_bytes(enrollment_id=binding.native_enrollment_id,
            generation=binding.native_generation, target_id="xpra-native", route_id=self._route(binding),
            session_id=binding.session_id, deadline=binding.expires_monotonic)
        def before_connect() -> None:
            self._effect(handle, binding, "connector.open", payload, 0, uid, pid, pidfd)
        result = self.connector._remote_open(
            view, payload, timeout=min(2.0, binding.expires_monotonic - self.monotonic()),
            peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd,
            cancelled=lambda: binding.cancelled() or self.monotonic() >= binding.expires_monotonic,
            before_connect=before_connect, seal=_REMOTE_SESSION_SEAL,
            resolve_lease=self._resolve_lease,
            after_open_send=lambda count: self._record_probe_bytes(binding, "write", count),
            after_open_receive=lambda count: self._record_probe_bytes(binding, "read", count))
        body = json.loads(result["body"])
        connector_id = body.get("connector_id")
        if (not isinstance(connector_id, str) or not _ID.fullmatch(connector_id)
                or binding.connector_handle is not None):
            raise AuthorityDenied("connector.response", "root setup open returned an invalid handle")
        self._advance(handle, binding, "connector.open", connector_id, uid, pid, pidfd)
        return connector_id, body

    def _advance(self, handle: str, binding: Any, operation: str, connector_id: str,
                 uid: int, pid: int, pidfd: int) -> None:
        if self.advance_sequence(handle, binding.effect_sequence, binding.next_sequence,
                operation, connector_id,
                peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd) is not True:
            stream = self.connector._streams.get(connector_id)
            if stream is not None:
                self.connector._dispose(stream)
            raise AuthorityDenied("connector.sequence", "probe frame sequence update was rejected")
        stream = self.connector._streams.get(connector_id)
        if stream is not None and operation in {"connector.read", "connector.write"}:
            stream.sequence = binding.next_sequence + 1

    def _close(self, handle: str, connector_id: str, action: str, asset_id: str | None,
               uid: int, pid: int, pidfd: int) -> None:
        stream = self.connector._streams.get(connector_id)
        if stream is None:
            return
        try:
            binding = self._current(handle, uid, pid, pidfd, action, asset_id, connector_id)
        except AuthorityDenied:
            self.connector._dispose(stream)  # root cleanup after cancel/expiry; no forwarded data
            return
        seq = binding.next_sequence
        body = {"schema": 1, "target_id": "xpra-native", "route_id": stream.route.route_id,
                "connector_id": connector_id, "session_id": binding.session_id,
                "generation": binding.native_generation, "deadline": binding.frame_deadline_monotonic,
                "sequence": seq}
        payload = canonical_bytes(body)
        from types import SimpleNamespace
        try:
            self.connector._remote_close(
                self._view(binding, connector_id), connector_id, SimpleNamespace(sequence=seq), payload,
                peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd,
                before_close=lambda: self._effect(handle, binding, "connector.close", payload,
                                                  seq, uid, pid, pidfd),
                cleanup=False, seal=_REMOTE_SESSION_SEAL)
            self._advance(handle, binding, "connector.close", connector_id, uid, pid, pidfd)
        except AuthorityDenied:
            stream = self.connector._streams.get(connector_id)
            if stream is not None:
                self.connector._dispose(stream)
            raise

    def read_asset(self, root_probe_handle: str, asset_id: str, method: str, *,
                   peer_uid: int, peer_pid: int, peer_pidfd: int) -> SetupProbeAssetResponse:
        action = {"GET": "asset-get", "HEAD": "asset-head"}.get(method, "")
        binding = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd, action, asset_id)
        if asset_id not in binding.asset_ids:
            raise AuthorityDenied("connector.asset", "asset ID is not in the selected root manifest")
        from hermes_installer.remote.http_framing import HTTPFrameError, build_asset_request, read_asset_response
        try:
            path = self.resolve_asset_path(binding, asset_id)
            if (not isinstance(path, str) or hashlib.sha256(
                    b"hermes-client-asset-v1\0" + path.encode("utf-8")).hexdigest() != asset_id):
                raise ValueError("unrecognized root asset mapping")
            request = build_asset_request(method, path, canonicalize=canonical_asset)
        except Exception as exc:
            raise AuthorityDenied("connector.asset", "root asset mapping is outside the pinned manifest") from exc
        connector_id, _ = self._open(root_probe_handle, binding, peer_uid, peer_pid, peer_pidfd)
        try:
            current = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd,
                                    action, asset_id, connector_id)
            seq = current.next_sequence
            write_body = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                "connector_id": connector_id, "session_id": current.session_id,
                "generation": current.native_generation, "deadline": current.frame_deadline_monotonic,
                "sequence": seq, "data_b64": base64.b64encode(request).decode("ascii")}
            write_payload = canonical_bytes(write_body)
            count = self.connector._remote_write(
                self._view(current, connector_id), connector_id, seq, request, write_payload,
                timeout=min(5.0, current.frame_deadline_monotonic - self.monotonic()),
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cancelled=current.cancelled,
                before_send=lambda: self._effect(root_probe_handle, current, "connector.write",
                    write_payload, seq, peer_uid, peer_pid, peer_pidfd), seal=_REMOTE_SESSION_SEAL,
                after_send=lambda sent: self._record_probe_bytes(current, "write", sent))
            if count != len(request):
                raise AuthorityDenied("connector.write", "asset request was not fully sent")
            self._advance(root_probe_handle, current, "connector.write", connector_id,
                          peer_uid, peer_pid, peer_pidfd)

            def read_one(maximum: int) -> bytes:
                frame = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd,
                                      action, asset_id, connector_id)
                seq_read = frame.next_sequence
                read_body = {"schema": 1, "target_id": "xpra-native", "route_id": "xpra-http",
                    "connector_id": connector_id, "session_id": frame.session_id,
                    "generation": frame.native_generation, "deadline": frame.frame_deadline_monotonic,
                    "sequence": seq_read, "max_bytes": maximum}
                read_payload = canonical_bytes(read_body)
                data, _eof = self.connector._remote_read(
                    self._view(frame, connector_id), connector_id, seq_read, maximum, read_payload,
                    timeout=min(5.0, frame.frame_deadline_monotonic - self.monotonic()),
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                    cancelled=frame.cancelled,
                    before_receive=lambda: self._effect(root_probe_handle, frame, "connector.read",
                        read_payload, seq_read, peer_uid, peer_pid, peer_pidfd), seal=_REMOTE_SESSION_SEAL,
                    after_receive=lambda count: self._record_probe_bytes(frame, "read", count))
                self._advance(root_probe_handle, frame, "connector.read", connector_id,
                              peer_uid, peer_pid, peer_pidfd)
                return data
            try:
                result = read_asset_response(read_one, method=method)
            except HTTPFrameError as exc:
                raise AuthorityDenied("connector.http-response", "Xpra response failed fixed framing") from exc
            return SetupProbeAssetResponse(result.status, result.headers, result.body)
        finally:
            self._close(root_probe_handle, connector_id, action, asset_id,
                        peer_uid, peer_pid, peer_pidfd)

    def open_websocket(self, root_probe_handle: str, *, peer_uid: int,
                       peer_pid: int, peer_pidfd: int) -> "SetupProbeConnectorStream":
        binding = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd,
                                "websocket-attach", None)
        connector_id, opened = self._open(root_probe_handle, binding, peer_uid, peer_pid, peer_pidfd)
        return SetupProbeConnectorStream(self, root_probe_handle, connector_id,
                                         peer_uid, peer_pid, peer_pidfd,
                                         opened["max_frame_bytes"])


@dataclass(slots=True)
class SetupProbeConnectorStream:
    backend: SetupProbeConnectorBackend
    root_probe_handle: str
    connector_id: str
    peer_uid: int
    peer_pid: int
    peer_pidfd: int
    max_frame_bytes: int
    closed: bool = False

    def _current(self) -> Any:
        if self.closed:
            raise AuthorityDenied("connector.closed", "setup WebSocket stream is closed")
        return self.backend._current(self.root_probe_handle, self.peer_uid, self.peer_pid,
                                     self.peer_pidfd, "websocket-attach", None, self.connector_id)

    def write(self, data: bytes) -> int:
        if not isinstance(data, bytes) or not data or len(data) > self.max_frame_bytes:
            raise AuthorityDenied("connector.frame", "setup WebSocket input exceeds its binary bound")
        binding = self._current()
        seq = binding.next_sequence
        payload = canonical_bytes({"schema": 1, "target_id": "xpra-native",
            "route_id": "xpra-websocket", "connector_id": self.connector_id,
            "session_id": binding.session_id, "generation": binding.native_generation,
            "deadline": binding.frame_deadline_monotonic, "sequence": seq,
            "data_b64": base64.b64encode(data).decode("ascii")})
        count = self.backend.connector._remote_write(
            self.backend._view(binding, self.connector_id), self.connector_id, seq,
            data, payload, timeout=min(5.0, binding.frame_deadline_monotonic - self.backend.monotonic()),
            peer_uid=self.peer_uid, peer_pid=self.peer_pid, peer_pidfd=self.peer_pidfd,
            cancelled=binding.cancelled,
            before_send=lambda: self.backend._effect(self.root_probe_handle, binding,
                "connector.write", payload, seq, self.peer_uid, self.peer_pid, self.peer_pidfd),
            seal=_REMOTE_SESSION_SEAL,
            after_send=lambda count: self.backend._record_probe_bytes(binding, "write", count))
        self.backend._advance(self.root_probe_handle, binding, "connector.write", self.connector_id,
                              self.peer_uid, self.peer_pid, self.peer_pidfd)
        return count

    def read(self, maximum_bytes: int) -> bytes:
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= self.max_frame_bytes:
            raise AuthorityDenied("connector.frame", "setup WebSocket read bound is invalid")
        binding = self._current()
        seq = binding.next_sequence
        payload = canonical_bytes({"schema": 1, "target_id": "xpra-native",
            "route_id": "xpra-websocket", "connector_id": self.connector_id,
            "session_id": binding.session_id, "generation": binding.native_generation,
            "deadline": binding.frame_deadline_monotonic, "sequence": seq,
            "max_bytes": maximum_bytes})
        data, eof = self.backend.connector._remote_read(
            self.backend._view(binding, self.connector_id), self.connector_id, seq,
            maximum_bytes, payload,
            timeout=min(5.0, binding.frame_deadline_monotonic - self.backend.monotonic()),
            peer_uid=self.peer_uid, peer_pid=self.peer_pid, peer_pidfd=self.peer_pidfd,
            cancelled=binding.cancelled,
            before_receive=lambda: self.backend._effect(self.root_probe_handle, binding,
                "connector.read", payload, seq, self.peer_uid, self.peer_pid, self.peer_pidfd),
            seal=_REMOTE_SESSION_SEAL,
            after_receive=lambda count: self.backend._record_probe_bytes(binding, "read", count))
        self.backend._advance(self.root_probe_handle, binding, "connector.read", self.connector_id,
                              self.peer_uid, self.peer_pid, self.peer_pidfd)
        if eof:
            self.closed = True
        return data

    def close(self) -> None:
        if self.closed:
            return
        try:
            self.backend._close(self.root_probe_handle, self.connector_id,
                                "websocket-attach", None,
                                self.peer_uid, self.peer_pid, self.peer_pidfd)
        finally:
            self.closed = True


def build_remote_service_connector_backend(*, catalog: Any, process_manager: Any,
                                           validate_binding: Callable[[Any, str, int], bool],
                                           consume_effect: Callable[..., bool],
                                           limits: ConnectorLimits = ConnectorLimits(),
                                           cancelled: Callable[[Any], bool] | None = None
                                           ) -> RemoteServiceConnectorBackend:
    """Build the root-only HI13 adapter from the strict catalog and live custodian.

    Unlike the ordinary HI07 effect-handler builder, this factory exposes no
    caller-context handler map. The RemoteSessionAuthority must validate its
    opaque session and current gateway identity before each backend call.
    """
    if not callable(validate_binding) or not callable(consume_effect):
        raise ValueError("root remote-session validator and HI12 effect consumer are required")

    def resolve(enrollment_id: str, profile_id: str, generation: str,
                target_id: str, route_id: str) -> NamespaceLease:
        try:
            binding = catalog.resolve_connector_route(enrollment_id, generation, target_id, route_id)
        except Exception as exc:
            if isinstance(exc, AuthorityDenied):
                raise
            raise AuthorityDenied("connector.route", "protected route resolution failed") from exc
        if binding.profile_id != profile_id or binding.generation != generation:
            raise AuthorityDenied("connector.binding", "protected route differs from signed service scope")
        lease = process_manager.resolve_namespace_lease(binding)
        if lease is None:
            raise AuthorityDenied("connector.identity", "no current supervised service namespace lease exists")
        if (lease.generation != generation or lease.namespace_identity != binding.namespace_identity):
            lease.close()
            raise AuthorityDenied("connector.identity", "current process namespace differs from protected enrollment")
        return lease

    connector = FixedServiceConnector(resolve_service_namespace=resolve, limits=limits)
    return RemoteServiceConnectorBackend(connector, validate_binding=validate_binding,
                                         consume_effect=consume_effect,
                                         cancelled=cancelled)


def open_request_bytes(*, enrollment_id: str, generation: str, target_id: str,
                       route_id: str, session_id: str, deadline: float) -> bytes:
    """Canonical body used before effect authorization; auth metadata stays external."""
    body = {"schema": 1, "enrollment_id": enrollment_id, "generation": generation,
            "target_id": target_id, "action": "open", "approved_route_id": route_id,
            "session_id": session_id, "deadline": deadline}
    if not _DIGEST.fullmatch(hashlib.sha256(canonical_bytes(body)).hexdigest()):
        raise ValueError("invalid canonical connector body")
    return canonical_bytes(body)


@dataclass(slots=True)
class _CallerContextConnectorStream:
    """Typed worker-side facade; it never exposes the root's connected socket."""
    client: "_CallerContextServiceConnectorClient"
    connector_id: str
    target_id: str
    approved_route_id: str
    session_id: str
    generation: str
    expires_monotonic: float
    max_frame_bytes: int
    remaining_byte_budget: int
    sequence: int = 0
    closed: bool = False
    lock: threading.Lock | None = None

    def read(self, max_bytes: int) -> bytes:
        return self.client.read(self, max_bytes=max_bytes)

    def write(self, data: bytes) -> int:
        return self.client.write(self, data=data)

    def close(self) -> None:
        self.client.close(self)


class _CallerContextServiceConnectorClient:
    """Client for fixed connector effects through an authenticated AuthorityClient.

    `context_provider(operation, session_id, request_digest)` must return a fresh host-issued
    context that retains the session's complete source lineage. Effect grants
    are requested separately for each verb and are never part of body digests.
    """

    def __init__(self, authority_client: Any, *, context_provider: Callable[[str, str, str], HostContext],
                 timeout: float = 5.0, monotonic: Callable[[], float] = time.monotonic):
        if not 0.1 <= timeout <= 30:
            raise ValueError("connector RPC timeout must be bounded")
        self.authority = authority_client
        self.context_provider = context_provider
        self.timeout = timeout
        self.monotonic = monotonic

    def _request(self, operation: str, target_id: str, session_id: str,
                 body: Mapping[str, Any]) -> Mapping[str, Any]:
        payload = canonical_bytes(body)
        digest = canonical_digest(payload)
        context = self.context_provider(operation, session_id, digest)
        if (not isinstance(context, HostContext) or context.operation != operation
                or context.final_payload_digest != digest
                or context.enrollment_id is None or context.generation is None
                or context.monotonic_expires_at <= self.monotonic()):
            raise AuthorityDenied("connector.context", "fresh enrolled connector context is unavailable")
        context_digest = canonical_digest({**context.claims(), "signature": context.signature})
        grant = self.authority.authorize_effect(context, capability="hermes-service-connect",
                                                target=target_id, request_digest=digest)
        if (grant.operation != operation or grant.request_digest != digest
                or grant.context_digest != context_digest or grant.target != target_id):
            raise AuthorityDenied("connector.grant", "effect grant is not bound to the fresh request context")
        response = self.authority.perform_effect(grant, operation=operation, payload=payload,
                                                 timeout=min(self.timeout, context.monotonic_expires_at - self.monotonic()))
        if response.status != 200:
            raise AuthorityDenied("connector.remote", "protected connector rejected the operation")
        try:
            value = json.loads(response.body)
        except (ValueError, UnicodeDecodeError) as exc:
            raise AuthorityDenied("connector.response", "protected connector response is malformed") from exc
        if not isinstance(value, dict) or value.get("schema") != 1:
            raise AuthorityDenied("connector.response", "protected connector response schema is invalid")
        return value

    def open(self, *, enrollment_id: str, generation: str, target_id: str,
             approved_route_id: str, session_id: str, deadline: float) -> ConnectorStream:
        raise AuthorityDenied("connector.remote-session", "worker-supplied HostContext cannot admit a protected service stream")

    def _open_with_caller_context(self, *, enrollment_id: str, generation: str, target_id: str,
                                  approved_route_id: str, session_id: str, deadline: float) -> _CallerContextConnectorStream:
        route = ROUTES.get((target_id, approved_route_id))
        if route is None:
            raise AuthorityDenied("connector.route", "connector route is not enrolled")
        body = json.loads(open_request_bytes(enrollment_id=enrollment_id, generation=generation,
                                             target_id=target_id, route_id=approved_route_id,
                                             session_id=session_id, deadline=deadline))
        value = self._request("connector.open", target_id, session_id, body)
        required = {"schema", "connector_id", "generation", "expires_monotonic", "max_frame_bytes", "remaining_byte_budget"}
        if (set(value) != required or value["generation"] != generation
                or type(value["max_frame_bytes"]) is not int or not 1 <= value["max_frame_bytes"] <= route.max_frame_bytes
                or type(value["remaining_byte_budget"]) is not int or not 1 <= value["remaining_byte_budget"] <= route.max_session_bytes
                or isinstance(value["expires_monotonic"], bool) or not isinstance(value["expires_monotonic"], (int, float))
                or self.monotonic() >= value["expires_monotonic"]):
            raise AuthorityDenied("connector.response", "connector stream lease is invalid")
        connector_id = _valid_id(value["connector_id"], "connector_id")
        return _CallerContextConnectorStream(self, connector_id, target_id, approved_route_id, session_id, generation,
                                             float(value["expires_monotonic"]), value["max_frame_bytes"],
                                             value["remaining_byte_budget"], lock=threading.Lock())

    def read(self, stream: _CallerContextConnectorStream, *, max_bytes: int) -> bytes:
        with stream.lock:
            self._ensure_live(stream)
            if type(max_bytes) is not int or not 1 <= max_bytes <= stream.max_frame_bytes:
                raise AuthorityDenied("connector.frame", "read size exceeds its bound")
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "generation": stream.generation,
                    "deadline": min(stream.expires_monotonic, self.monotonic() + 5.0),
                    "sequence": stream.sequence, "max_bytes": max_bytes}
            value = self._request("connector.read", stream.target_id, stream.session_id, body)
            import base64
            try:
                data = base64.b64decode(value["data_b64"], validate=True)
            except (KeyError, ValueError, TypeError) as exc:
                raise AuthorityDenied("connector.response", "connector read frame is malformed") from exc
            self._check_frame_reply(value, stream, len(data))
            stream.sequence += 1
            stream.remaining_byte_budget = value["remaining_byte_budget"]
            if not data:
                stream.closed = True
            return data

    def write(self, stream: _CallerContextConnectorStream, *, data: bytes) -> int:
        with stream.lock:
            self._ensure_live(stream)
            if not isinstance(data, bytes) or not 1 <= len(data) <= stream.max_frame_bytes:
                raise AuthorityDenied("connector.frame", "write frame exceeds its bound")
            import base64
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "generation": stream.generation,
                    "deadline": min(stream.expires_monotonic, self.monotonic() + 5.0),
                    "sequence": stream.sequence,
                    "data_b64": base64.b64encode(data).decode("ascii")}
            value = self._request("connector.write", stream.target_id, stream.session_id, body)
            if value.get("written") != len(data):
                raise AuthorityDenied("connector.response", "connector write receipt is invalid")
            self._check_frame_reply(value, stream, len(data))
            stream.sequence += 1
            stream.remaining_byte_budget = value["remaining_byte_budget"]
            return len(data)

    def close(self, stream: _CallerContextConnectorStream) -> None:
        with stream.lock:
            if stream.closed:
                return
            self._ensure_live(stream)
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "generation": stream.generation,
                    "deadline": min(stream.expires_monotonic, self.monotonic() + 5.0),
                    "sequence": stream.sequence}
            value = self._request("connector.close", stream.target_id, stream.session_id, body)
            if value != {"schema": 1, "closed": True}:
                raise AuthorityDenied("connector.response", "connector close receipt is invalid")
            stream.closed = True

    def _ensure_live(self, stream: _CallerContextConnectorStream) -> None:
        if stream.closed or self.monotonic() >= stream.expires_monotonic:
            stream.closed = True
            raise AuthorityDenied("connector.expired", "connector stream lease has expired")

    @staticmethod
    def _check_frame_reply(value: Mapping[str, Any], stream: _CallerContextConnectorStream, consumed: int) -> None:
        if (value.get("sequence") != stream.sequence or type(value.get("remaining_byte_budget")) is not int
                or value["remaining_byte_budget"] != stream.remaining_byte_budget - consumed):
            raise AuthorityDenied("connector.response", "connector frame receipt is invalid")


@dataclass(slots=True)
class ConnectorStream:
    """HI13 stream facade bound only to a root-admitted remote session handle."""
    client: "ServiceConnectorClient"
    session_id: str
    connector_handle: str
    generation: str
    route_id: str
    expires_monotonic: float
    sequence: int = 0
    closed: bool = False
    lock: threading.Lock | None = None

    def read(self, maximum_bytes: int) -> bytes:
        return self.client.read(self, maximum_bytes)

    def write(self, data_bytes: bytes) -> int:
        return self.client.write(self, data_bytes)

    def close(self) -> None:
        self.client.close(self)


class ServiceConnectorClient:
    """Gateway-side HI13 adapter; never accepts caller claims or connector routes."""
    def __init__(self, authority_client: Any, remote_session_handle: str, *,
                 monotonic: Callable[[], float] = time.monotonic):
        if not isinstance(remote_session_handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", remote_session_handle):
            raise ValueError("root-issued remote session handle is required")
        self.authority = authority_client
        self._handle = remote_session_handle
        self.monotonic = monotonic

    def _call(self, method: str, *args: Any) -> Mapping[str, Any]:
        callback = getattr(self.authority, method, None)
        if not callable(callback):
            raise AuthorityDenied("connector.remote-session", "root HI13 connector API is unavailable")
        result = callback(self._handle, *args)
        if not isinstance(result, Mapping) and callable(getattr(result, "to_wire", None)):
            result = result.to_wire()
        if not isinstance(result, Mapping):
            raise AuthorityDenied("connector.response", "root remote connector response is malformed")
        return result

    def _accept_root_expiry(self, stream: ConnectorStream, reported: Any) -> None:
        if (isinstance(reported, bool) or not isinstance(reported, (int, float))
                or not math.isfinite(reported) or reported < stream.expires_monotonic
                or reported > self.monotonic() + 60.0):
            raise AuthorityDenied("connector.response", "root remote connector lease receipt is invalid")
        # This is only an observation of a lease the root renewed independently
        # after fresh JWT and policy checks; frames themselves never renew it.
        stream.expires_monotonic = float(reported)

    def open(self) -> ConnectorStream:
        value = self._call("open_remote_connector")
        required = {"schema", "session_id", "connector_handle", "generation", "route_id", "expires_monotonic"}
        if (set(value) != required or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("route_id") not in {"xpra-http", "xpra-websocket"}
                or not all(isinstance(value.get(key), str) and value[key] for key in
                           ("session_id", "connector_handle", "generation"))
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}", value["session_id"])
                or not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", value["connector_handle"])
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}", value["generation"])
                or isinstance(value.get("expires_monotonic"), bool)
                or not isinstance(value.get("expires_monotonic"), (int, float))
                or not math.isfinite(value["expires_monotonic"])
                or not self.monotonic() < value["expires_monotonic"] <= self.monotonic() + 60.0):
            raise AuthorityDenied("connector.response", "root remote connector lease is invalid")
        return ConnectorStream(self, value["session_id"], value["connector_handle"],
                               value["generation"], value["route_id"],
                               float(value["expires_monotonic"]), lock=threading.Lock())

    def _require_live(self, stream: ConnectorStream) -> None:
        if stream.closed or self.monotonic() >= stream.expires_monotonic:
            stream.closed = True
            raise AuthorityDenied("connector.expired", "root remote connector lease expired")

    def read(self, stream: ConnectorStream, maximum_bytes: int) -> bytes:
        with stream.lock:
            self._require_live(stream)
            if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 1_048_576:
                raise AuthorityDenied("connector.frame", "remote read exceeds its fixed bound")
            value = self._call("read_remote_connector", stream.connector_handle,
                               stream.sequence, maximum_bytes)
            data_bytes = value.get("data_bytes")
            if isinstance(data_bytes, str):
                try:
                    data_bytes = base64.b64decode(data_bytes, validate=True)
                except (ValueError, TypeError) as exc:
                    raise AuthorityDenied("connector.response", "root remote read frame encoding is invalid") from exc
            if (set(value) != {"schema", "session_id", "sequence", "data_bytes", "eof", "expires_monotonic"}
                    or value.get("schema") != 1 or value.get("session_id") != stream.session_id
                    or type(value.get("sequence")) is not int or value["sequence"] != stream.sequence
                    or not isinstance(data_bytes, bytes)
                    or len(data_bytes) > maximum_bytes or type(value.get("eof")) is not bool
                    or value.get("expires_monotonic") is None):
                raise AuthorityDenied("connector.response", "root remote read receipt is invalid")
            self._accept_root_expiry(stream, value["expires_monotonic"])
            stream.sequence += 1
            if value["eof"]:
                stream.closed = True
            return data_bytes

    def write(self, stream: ConnectorStream, data_bytes: bytes) -> int:
        with stream.lock:
            self._require_live(stream)
            if not isinstance(data_bytes, bytes) or not 1 <= len(data_bytes) <= 1_048_576:
                raise AuthorityDenied("connector.frame", "remote write exceeds its fixed bound")
            value = self._call("write_remote_connector", stream.connector_handle,
                               stream.sequence, data_bytes)
            if (set(value) != {"schema", "session_id", "sequence", "accepted_bytes", "expires_monotonic"}
                    or value.get("schema") != 1 or value.get("session_id") != stream.session_id
                    or type(value.get("sequence")) is not int or value["sequence"] != stream.sequence
                    or type(value.get("accepted_bytes")) is not int or value["accepted_bytes"] != len(data_bytes)
                    or value.get("expires_monotonic") is None):
                raise AuthorityDenied("connector.response", "root remote write receipt is invalid")
            self._accept_root_expiry(stream, value["expires_monotonic"])
            stream.sequence += 1
            return len(data_bytes)

    def close(self, stream: ConnectorStream) -> None:
        with stream.lock:
            if stream.closed:
                return
            value = self._call("close_remote_connector", stream.connector_handle)
            if value != {"schema": 1, "session_id": stream.session_id, "state": "closed"}:
                raise AuthorityDenied("connector.response", "root remote close receipt is invalid")
            stream.closed = True
