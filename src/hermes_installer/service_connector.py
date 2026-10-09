"""Root-owned fixed loopback service connector (HI07).

Workers receive small typed operations over the protected authority channel. They
never receive an address, descriptor, PID, namespace selector, or proxy URL.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import select
import socket
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_bytes, canonical_digest


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
    ("xpra-native", "xpra-http"): Route("xpra-native", "xpra-http", "hermes-desktop", 14500, "http", 1_048_576, 16_777_216),
    ("xpra-native", "xpra-websocket"): Route("xpra-native", "xpra-websocket", "hermes-desktop", 14500, "websocket", 1_048_576, 16_777_216),
    ("colibri-main", "colibri-openai-v1"): Route("colibri-main", "colibri-openai-v1", "colibri-main", 8000, "http", 1_048_576, 16_777_216),
}
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


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
    lock: threading.RLock | None = None


def _json_response(body: Mapping[str, Any], *, status: int = 200) -> Mapping[str, Any]:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > 1_100_000:
        raise AuthorityDenied("connector.response", "connector response exceeds its fixed bound")
    return {"status": status, "body": encoded, "headers": {"content-type": "application/json"}, "receipt_id": uuid.uuid4().hex}


def _decode(payload: bytes, required: set[str], optional: set[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) > 1_100_000:
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

    def __init__(self, *, resolve_service_namespace: Callable[[str, str, str, str], NamespaceLease],
                 limits: ConnectorLimits = ConnectorLimits(), monotonic: Callable[[], float] = time.monotonic,
                 _test_allow_current_namespace: bool = False):
        if not 1 <= limits.max_sessions <= 1024 or not 1024 <= limits.max_queue_bytes <= 16_777_216:
            raise ValueError("connector session and queue limits are invalid")
        if not 1 <= limits.max_lease_seconds <= 600 or not 0.1 <= limits.max_open_timeout <= 10:
            raise ValueError("connector deadlines are invalid")
        self.resolve = resolve_service_namespace
        self.limits = limits
        self.monotonic = monotonic
        self._test_allow_current_namespace = _test_allow_current_namespace
        self._streams: dict[str, _Stream] = {}
        self._lock = threading.RLock()
        self._closed = threading.Event()
        self._watchdog = threading.Thread(target=self._expire_loop, name="hermes-service-connector-watchdog", daemon=True)
        self._watchdog.start()

    def handlers(self) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
        return {(operation, target): getattr(self, method)
                for operation, method in (("connector.open", "open"), ("connector.read", "read"),
                                          ("connector.write", "write"), ("connector.close", "close"))
                for target in ("xpra-native", "colibri-main")}

    @staticmethod
    def _auth(context: HostContext, authorization: EffectAuthorization, operation: str,
              payload: bytes, peer_pid: int) -> None:
        context_digest = canonical_digest({**context.claims(), "signature": context.signature})
        if (authorization.operation != operation or authorization.profile_id != context.profile_id
                or authorization.uid != context.uid or authorization.request_digest != canonical_digest(payload)
                or authorization.enrollment_id != context.enrollment_id
                or authorization.generation != context.generation
                or authorization.context_digest != context_digest):
            raise AuthorityDenied("connector.binding", "connector grant is not bound to this peer and payload")

    def open(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
             timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.open", payload, peer_pid)
        body = _decode(payload, {"schema", "enrollment_id", "generation", "target_id", "action", "approved_route_id", "session_id", "deadline"})
        if body["schema"] != 1 or body["action"] != "open":
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
                or context.operation != "connector.open"):
            raise AuthorityDenied("connector.binding", "connector target does not match enrolled context")
        now = self.monotonic()
        deadline = body["deadline"]
        if (isinstance(deadline, bool) or not isinstance(deadline, (int, float))
                or not now < float(deadline) <= now + self.limits.max_lease_seconds):
            raise AuthorityDenied("connector.deadline", "connector deadline is stale or exceeds the lease")
        if cancelled():
            raise AuthorityDenied("connector.cancelled", "connector open was cancelled")
        with self._lock:
            self._reap_expired_locked(now)
            if len(self._streams) >= self.limits.max_sessions:
                raise AuthorityDenied("connector.capacity", "connector session capacity is exhausted")
        lease = self.resolve(route.profile_id, generation, target_id, route_id)
        retained_pidfd = -1
        try:
            if lease.generation != generation or not _pidfd_alive(lease.pidfd):
                raise AuthorityDenied("connector.identity", "registered service identity changed")
            if peer_pidfd is None or not _pidfd_alive(peer_pidfd):
                raise AuthorityDenied("connector.peer", "connector caller exited")
            retained_pidfd = os.dup(peer_pidfd)
            sock = self._connect_namespace(lease, route, min(timeout, self.limits.max_open_timeout))
            if cancelled() or not _pidfd_alive(peer_pidfd) or not _pidfd_alive(lease.pidfd):
                raise AuthorityDenied("connector.cancelled", "connector open ended after cancellation or identity exit")
        except BaseException:
            lease.close()
            if "sock" in locals():
                sock.close()
            if retained_pidfd >= 0:
                os.close(retained_pidfd)
            raise
        connector_id = uuid.uuid4().hex
        stream = _Stream(connector_id, route, sock, lease, context.uid, peer_pid, retained_pidfd, context.lineage_hash,
                         session_id, min(float(deadline), now + self.limits.max_lease_seconds),
                         route.max_session_bytes, lock=threading.RLock())
        with self._lock:
            self._streams[connector_id] = stream
        return _json_response({"schema": 1, "connector_id": connector_id, "generation": generation,
                               "expires_monotonic": stream.expires, "max_frame_bytes": route.max_frame_bytes,
                               "remaining_byte_budget": stream.remaining})

    def _connect_namespace(self, lease: NamespaceLease, route: Route, timeout: float) -> socket.socket:
        if not hasattr(os, "setns") and not self._test_allow_current_namespace:
            raise AuthorityDenied("connector.unavailable", "Linux network namespace entry is unavailable")
        result: list[socket.socket] = []
        failure: list[BaseException] = []
        done = threading.Event()
        def worker() -> None:
            original = None
            try:
                if not self._test_allow_current_namespace:
                    if not hasattr(os, "setns") or lease.namespace_fd < 0:
                        raise AuthorityDenied("connector.namespace", "protected service namespace lease is unavailable")
                    original = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                    os.setns(lease.namespace_fd, getattr(os, "CLONE_NEWNET", 0))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
                sock.settimeout(timeout)
                sock.connect(("127.0.0.1", route.port))
                result.append(sock)
            except BaseException as exc:
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
        result[0].settimeout(None)
        return result[0]

    def _stream(self, body: Mapping[str, Any], context: HostContext, authorization: EffectAuthorization,
                operation: str, payload: bytes, peer_pid: int) -> _Stream:
        self._auth(context, authorization, operation, payload, peer_pid)
        connector_id = _valid_id(body.get("connector_id"), "connector_id")
        with self._lock:
            stream = self._streams.get(connector_id)
        if stream is None:
            raise AuthorityDenied("connector.closed", "connector handle is unavailable")
        if (stream.owner_uid != context.uid or stream.owner_pid != peer_pid
                or not _pidfd_alive(stream.owner_pidfd) or not _pidfd_alive(stream.lease.pidfd)
                or stream.lineage_hash != context.lineage_hash
                or stream.session_id != body.get("session_id")
                or context.profile_id != stream.route.profile_id
                or authorization.target != stream.route.target_id
                or authorization.capability != "hermes-service-connect"
                or body.get("target_id") != stream.route.target_id
                or body.get("route_id") != stream.route.route_id):
            raise AuthorityDenied("connector.peer", "connector handle is bound to another peer or session")
        if self.monotonic() >= stream.expires or stream.lease.generation != authorization.generation:
            self._dispose(stream)
            raise AuthorityDenied("connector.expired", "connector handle expired or generation changed")
        return stream

    def read(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
             timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.read", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "sequence", "max_bytes"})
        stream = self._stream(body, context, authorization, "connector.read", payload, peer_pid)
        amount = body["max_bytes"]
        if body["schema"] != 1 or type(body["sequence"]) is not int or type(amount) is not int or not 1 <= amount <= stream.route.max_frame_bytes:
            raise AuthorityDenied("connector.frame", "connector read frame bounds are invalid")
        with stream.lock:
            if body["sequence"] != stream.sequence:
                raise AuthorityDenied("connector.replay", "connector operation sequence is stale")
            if cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector read was cancelled")
            stream.sock.settimeout(min(timeout, max(0.001, stream.expires - self.monotonic())))
            try:
                data = stream.sock.recv(min(amount, stream.remaining))
            except (OSError, TimeoutError) as exc:
                raise AuthorityDenied("connector.read", "fixed service read failed or timed out") from exc
            stream.sequence += 1
            stream.remaining -= len(data)
            if not data:
                self._dispose(stream)
            return _json_response({"schema": 1, "sequence": body["sequence"], "data_b64": __import__("base64").b64encode(data).decode("ascii"), "remaining_byte_budget": stream.remaining})

    def write(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
              timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.write", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "sequence", "data_b64"})
        stream = self._stream(body, context, authorization, "connector.write", payload, peer_pid)
        import base64
        try:
            data = base64.b64decode(body["data_b64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise AuthorityDenied("connector.frame", "connector frame encoding is invalid") from exc
        if body["schema"] != 1 or type(body["sequence"]) is not int or not data or len(data) > stream.route.max_frame_bytes:
            raise AuthorityDenied("connector.frame", "connector write frame bounds are invalid")
        with stream.lock:
            if body["sequence"] != stream.sequence:
                raise AuthorityDenied("connector.replay", "connector operation sequence is stale")
            if len(data) > stream.remaining or cancelled():
                self._dispose(stream)
                raise AuthorityDenied("connector.cancelled", "connector write exceeds budget or was cancelled")
            stream.sock.settimeout(min(timeout, max(0.001, stream.expires - self.monotonic())))
            try:
                stream.sock.sendall(data)
            except (OSError, TimeoutError) as exc:
                self._dispose(stream)
                raise AuthorityDenied("connector.write", "fixed service write failed or timed out") from exc
            stream.remaining -= len(data)
            stream.sequence += 1
        return _json_response({"schema": 1, "sequence": body["sequence"], "written": len(data), "remaining_byte_budget": stream.remaining})

    def close(self, *, context: HostContext, authorization: EffectAuthorization, payload: bytes,
              timeout: float, peer_pid: int, peer_pidfd: int | None, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        self._auth(context, authorization, "connector.close", payload, peer_pid)
        body = _decode(payload, {"schema", "connector_id", "target_id", "route_id", "session_id", "sequence"})
        stream = self._stream(body, context, authorization, "connector.close", payload, peer_pid)
        with stream.lock:
            if body["schema"] != 1 or type(body["sequence"]) is not int or body["sequence"] != stream.sequence:
                raise AuthorityDenied("connector.replay", "connector close sequence is stale")
            self._dispose(stream)
        return _json_response({"schema": 1, "closed": True})

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


def build_service_connector_handlers(*, resolve_service_namespace: Callable[[str, str, str, str], NamespaceLease],
                                     limits: ConnectorLimits = ConnectorLimits()) -> tuple[FixedServiceConnector, Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]]:
    connector = FixedServiceConnector(resolve_service_namespace=resolve_service_namespace, limits=limits)
    return connector, connector.handlers()


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
class ConnectorStream:
    """Typed worker-side facade; it never exposes the root's connected socket."""
    client: "ServiceConnectorClient"
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


class ServiceConnectorClient:
    """Client for fixed connector effects through an authenticated AuthorityClient.

    `context_provider(operation, session_id)` must return a fresh host-issued
    context that retains the session's complete source lineage. Effect grants
    are requested separately for each verb and are never part of body digests.
    """

    def __init__(self, authority_client: Any, *, context_provider: Callable[[str, str], HostContext],
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
        context = self.context_provider(operation, session_id)
        if (not isinstance(context, HostContext) or context.operation != operation
                or context.enrollment_id is None or context.generation is None
                or context.monotonic_expires_at <= self.monotonic()):
            raise AuthorityDenied("connector.context", "fresh enrolled connector context is unavailable")
        grant = self.authority.authorize_effect(context, capability="hermes-service-connect",
                                                target=target_id, request_digest=canonical_digest(payload))
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
        return ConnectorStream(self, connector_id, target_id, approved_route_id, session_id, generation,
                               float(value["expires_monotonic"]), value["max_frame_bytes"],
                               value["remaining_byte_budget"], lock=threading.Lock())

    def read(self, stream: ConnectorStream, *, max_bytes: int) -> bytes:
        with stream.lock:
            self._ensure_live(stream)
            if type(max_bytes) is not int or not 1 <= max_bytes <= stream.max_frame_bytes:
                raise AuthorityDenied("connector.frame", "read size exceeds its bound")
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "sequence": stream.sequence, "max_bytes": max_bytes}
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

    def write(self, stream: ConnectorStream, *, data: bytes) -> int:
        with stream.lock:
            self._ensure_live(stream)
            if not isinstance(data, bytes) or not 1 <= len(data) <= stream.max_frame_bytes:
                raise AuthorityDenied("connector.frame", "write frame exceeds its bound")
            import base64
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "sequence": stream.sequence,
                    "data_b64": base64.b64encode(data).decode("ascii")}
            value = self._request("connector.write", stream.target_id, stream.session_id, body)
            if value.get("written") != len(data):
                raise AuthorityDenied("connector.response", "connector write receipt is invalid")
            self._check_frame_reply(value, stream, len(data))
            stream.sequence += 1
            stream.remaining_byte_budget = value["remaining_byte_budget"]
            return len(data)

    def close(self, stream: ConnectorStream) -> None:
        with stream.lock:
            if stream.closed:
                return
            self._ensure_live(stream)
            body = {"schema": 1, "target_id": stream.target_id, "route_id": stream.approved_route_id,
                    "connector_id": stream.connector_id,
                    "session_id": stream.session_id, "sequence": stream.sequence}
            value = self._request("connector.close", stream.target_id, stream.session_id, body)
            if value != {"schema": 1, "closed": True}:
                raise AuthorityDenied("connector.response", "connector close receipt is invalid")
            stream.closed = True

    def _ensure_live(self, stream: ConnectorStream) -> None:
        if stream.closed or self.monotonic() >= stream.expires_monotonic:
            stream.closed = True
            raise AuthorityDenied("connector.expired", "connector stream lease has expired")

    @staticmethod
    def _check_frame_reply(value: Mapping[str, Any], stream: ConnectorStream, consumed: int) -> None:
        if (value.get("sequence") != stream.sequence or type(value.get("remaining_byte_budget")) is not int
                or value["remaining_byte_budget"] != stream.remaining_byte_budget - consumed):
            raise AuthorityDenied("connector.response", "connector frame receipt is invalid")
