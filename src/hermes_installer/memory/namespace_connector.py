"""Fixed root-only HTTP exchange with a supervised service namespace.

This module accepts only ``MemoryServiceRequest`` values produced by the
source-pinned recipe serializer. It does not accept URLs, ports, methods,
headers, or HTTP frames from the worker. The selected port and namespace lease
come from the active protected enrollment catalog.
"""
from __future__ import annotations

import re
import os
import select
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.memory.compound import MemoryServiceRequest


class MemoryNamespaceUnavailable(RuntimeError):
    """The selected supervised namespace or socket exchange is unavailable."""


class MemoryNamespaceDenied(PermissionError):
    """The protected route or response violated the fixed memory contract."""


@dataclass(frozen=True, slots=True)
class MemoryHTTPResult:
    status: int
    body: bytes


@dataclass(frozen=True, slots=True)
class _Route:
    target_id: str
    route_id: str
    profile_id: str
    port: int
    protocol: str = "openai-http"
    max_frame_bytes: int = 262_144
    max_session_bytes: int = 2_097_152


def _frame(*, enrollment: Any, route_id: str, request: MemoryServiceRequest,
           secret: str, maximum_bytes: int) -> bytes:
    if (not isinstance(request, MemoryServiceRequest)
            or route_id not in enrollment.fixed_route_map
            or not isinstance(secret, str) or not secret
            or any(char in secret for char in "\r\n\x00")):
        raise MemoryNamespaceDenied("memory request does not match protected enrollment")
    if enrollment.provider == "agentmemory":
        auth = ("Authorization", f"Bearer {secret}")
    elif enrollment.provider == "openviking":
        auth = ("X-API-Key", secret)
    else:
        raise MemoryNamespaceUnavailable("selected backend has no reviewed root credential codec")
    body = request.body
    if len(body) > maximum_bytes:
        raise MemoryNamespaceDenied("serialized memory request exceeds its enrolled bound")
    headers = [
        f"{request.method} {request.path} HTTP/1.1",
        f"Host: 127.0.0.1:{enrollment.literal_loopback_port}",
        "Connection: close",
        "Accept: application/json",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        f"{auth[0]}: {auth[1]}",
    ]
    encoded = ("\r\n".join(headers) + "\r\n\r\n").encode("ascii") + body
    if len(encoded) > maximum_bytes:
        raise MemoryNamespaceDenied("memory HTTP frame exceeds its enrolled bound")
    return encoded


def read_bounded_http_response(sock: Any, *, maximum_body: int,
                               deadline: float, cancelled: Callable[[], bool],
                               monotonic: Callable[[], float] = time.monotonic) -> MemoryHTTPResult:
    """Read one non-chunked JSON response, rejecting redirects and ambiguity."""
    data = bytearray()
    marker = b"\r\n\r\n"
    header_end = -1
    expected_length: int | None = None
    status: int | None = None
    while header_end < 0:
        if cancelled() or monotonic() >= deadline:
            raise MemoryNamespaceUnavailable("memory response was cancelled or exceeded its deadline")
        try:
            chunk = sock.recv(min(4096, 16_384 - len(data)))
        except (OSError, TimeoutError):
            raise MemoryNamespaceUnavailable("memory service response read failed") from None
        if not chunk:
            raise MemoryNamespaceUnavailable("memory service closed before complete response headers")
        data.extend(chunk)
        if len(data) > 16_384:
            raise MemoryNamespaceDenied("memory response headers exceed their bound")
        header_end = data.find(marker)
    try:
        lines = bytes(data[:header_end]).decode("ascii", "strict").split("\r\n")
        match = re.fullmatch(r"HTTP/1\.[01] ([0-9]{3})(?: [^\r\n]*)?", lines[0])
        if match is None:
            raise ValueError
        status = int(match.group(1))
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or line[0] in " \t" or ":" not in line:
                raise ValueError
            name, value = line.split(":", 1)
            name = name.casefold()
            if (not re.fullmatch(r"[a-z0-9-]{1,64}", name) or name in headers
                    or "\r" in value or "\n" in value):
                raise ValueError
            headers[name] = value.strip()
        if "transfer-encoding" in headers or "content-encoding" in headers:
            raise ValueError
        length = headers.get("content-length")
        if length is None or not re.fullmatch(r"0|[1-9][0-9]{0,8}", length):
            raise ValueError
        expected_length = int(length)
        if expected_length > maximum_body or 300 <= status < 400:
            raise ValueError
    except (UnicodeDecodeError, ValueError, IndexError):
        raise MemoryNamespaceDenied("memory service response headers are unsupported") from None
    body_start = header_end + len(marker)
    body = bytearray(data[body_start:])
    if len(body) > expected_length:
        raise MemoryNamespaceDenied("memory service sent bytes beyond Content-Length")
    while len(body) < expected_length:
        if cancelled() or monotonic() >= deadline:
            raise MemoryNamespaceUnavailable("memory response body was cancelled or exceeded its deadline")
        try:
            chunk = sock.recv(min(65_536, expected_length - len(body)))
        except (OSError, TimeoutError):
            raise MemoryNamespaceUnavailable("memory response body read failed") from None
        if not chunk:
            raise MemoryNamespaceUnavailable("memory service response body is truncated")
        body.extend(chunk)
    return MemoryHTTPResult(status, bytes(body))


class MemoryNamespaceConnector:
    """One request per protected route over a managed namespace lease.

    ``route_resolver`` must call the active ProtectedEnrollmentCatalog with the
    exact enrollment/generation/target/route tuple. ``process_manager`` is the
    same root custody object used by the service connector. The connector's
    namespace socket helper performs setns only on its bounded helper thread.
    """

    def __init__(self, *, catalog: Any, process_manager: Any,
                 vault: Any,
                 route_resolver: Callable[[Any, str], Any] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (catalog is None or process_manager is None
                or not callable(getattr(vault, "resolve_reference", None))):
            raise ValueError("protected memory catalog, process custody and root vault are required")
        self.catalog = catalog
        self.process_manager = process_manager
        self.vault = vault
        self.route_resolver = route_resolver or self._resolve_route
        self.monotonic = monotonic

    def _connect(self, lease: Any, port: int, timeout: float,
                 before_connect: Callable[[], None]) -> socket.socket:
        """Enter only the leased namespace on a helper thread and dial loopback."""
        if not hasattr(os, "setns") or getattr(lease, "namespace_fd", -1) < 0:
            raise MemoryNamespaceUnavailable("Linux supervised network namespace entry is unavailable")
        result: list[socket.socket] = []
        failures: list[BaseException] = []
        done = threading.Event()

        def worker() -> None:
            saved_ns = -1
            sock = None
            try:
                saved_ns = os.open("/proc/self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
                os.setns(lease.namespace_fd, getattr(os, "CLONE_NEWNET", 0))
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
                sock.settimeout(timeout)
                before_connect()
                sock.connect(("127.0.0.1", port))
                result.append(sock)
                sock = None
            except BaseException as exc:
                failures.append(exc)
            finally:
                if sock is not None:
                    sock.close()
                if saved_ns >= 0:
                    try:
                        os.setns(saved_ns, getattr(os, "CLONE_NEWNET", 0))
                    except OSError as exc:
                        failures.append(exc)
                    os.close(saved_ns)
                done.set()

        thread = threading.Thread(target=worker, name="memory-namespace-connect", daemon=True)
        thread.start()
        if not done.wait(timeout + 0.25):
            raise MemoryNamespaceUnavailable("memory namespace connect exceeded its bound")
        if failures:
            if isinstance(failures[0], (AuthorityDenied, MemoryNamespaceDenied)):
                raise failures[0]
            raise MemoryNamespaceUnavailable("memory namespace loopback connect failed") from None
        if len(result) != 1:
            raise MemoryNamespaceUnavailable("memory namespace connect returned no socket")
        return result[0]

    def _resolve_route(self, enrollment: Any, route_id: str) -> Any:
        return self.catalog.resolve_connector_route(
            enrollment.service_enrollment_id, enrollment.service_generation,
            enrollment.target_id, route_id)

    def request(self, *, enrollment: Any, route_id: str,
                request: MemoryServiceRequest,
                before_connect: Callable[[str], None],
                timeout: float, deadline: float,
                cancelled: Callable[[], bool]) -> MemoryHTTPResult:
        if (not isinstance(route_id, str) or route_id not in enrollment.fixed_route_map
                or not callable(before_connect) or not callable(cancelled)):
            raise MemoryNamespaceDenied("memory route is not part of the selected enrollment")
        remaining = min(float(timeout), deadline - self.monotonic())
        if remaining <= 0:
            raise MemoryNamespaceUnavailable("memory service deadline expired before connection")
        try:
            binding = self.route_resolver(enrollment, route_id)
        except Exception:
            raise MemoryNamespaceUnavailable("active memory service route could not be resolved") from None
        if (getattr(binding, "target_id", None) != enrollment.target_id
                or getattr(binding, "route_id", None) != route_id
                or getattr(binding, "profile_id", None) != enrollment.profile_id
                or getattr(binding, "generation", None) != enrollment.service_generation
                or getattr(binding, "namespace_identity", None) != enrollment.namespace_identity
                or getattr(binding, "literal_loopback_port", None) != enrollment.literal_loopback_port
                or getattr(binding, "memory_enrollment", enrollment) != enrollment):
            raise MemoryNamespaceDenied("active connector route differs from the signed memory enrollment")
        route_recipe = enrollment.fixed_route_map[route_id]
        if getattr(binding, "memory_route", route_recipe) != route_recipe:
            raise MemoryNamespaceDenied("active connector route recipe differs from memory enrollment")
        lease = self.process_manager.resolve_namespace_lease(binding)
        if lease is None:
            raise MemoryNamespaceUnavailable("selected supervised memory service has no live namespace lease")
        sock = None
        try:
            if (lease.generation != enrollment.service_generation
                    or lease.namespace_identity != enrollment.namespace_identity
                    or not callable(getattr(lease, "close", None))):
                raise MemoryNamespaceDenied("supervised memory service generation or namespace changed")
            secret = self.vault.resolve_reference(
                request.credential_reference_id, peer_uid=lease.uid,
                required_scope=f"memory.{enrollment.provider}",
                principal_id=enrollment.principal_id)
            frame = _frame(enrollment=enrollment, route_id=route_id, request=request,
                           secret=secret, maximum_bytes=enrollment.limits["request_bytes"])
            route = _Route(enrollment.target_id, route_id, enrollment.profile_id,
                           enrollment.literal_loopback_port)
            remaining = min(float(timeout), deadline - self.monotonic())
            if remaining <= 0 or cancelled():
                raise MemoryNamespaceUnavailable("memory service operation expired or was cancelled")
            # The one-use grant is spent at the exact socket-connect boundary.
            # Its signed request digest contains the serializer's complete
            # method/path/header/body digest, and the frame was rebuilt here.
            sock = self._connect(
                lease, route.port, remaining,
                before_connect=lambda: before_connect(__import__(
                    "hashlib").sha256(frame).hexdigest()))
            if cancelled() or self.monotonic() >= deadline:
                raise MemoryNamespaceUnavailable("memory service operation expired after connect")
            sock.settimeout(min(remaining, max(0.01, deadline - self.monotonic())))
            sock.sendall(frame)
            return read_bounded_http_response(
                sock, maximum_body=enrollment.limits["response_bytes"],
                deadline=min(deadline, self.monotonic() + enrollment.limits["operation_timeout_seconds"]),
                cancelled=cancelled, monotonic=self.monotonic)
        except (AuthorityDenied, MemoryNamespaceDenied, MemoryNamespaceUnavailable):
            raise
        except Exception:
            raise MemoryNamespaceUnavailable("fixed memory namespace request failed") from None
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            lease.close()
