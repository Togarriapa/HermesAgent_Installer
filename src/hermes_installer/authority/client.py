"""Synchronous, peer-authenticated client for the protected host authority.

Workers never receive a signing key. Host contexts and effect grants are signed
by the root-owned service; this client authenticates that service with kernel
peer credentials and asks it to verify/consume every effect grant.
"""
from __future__ import annotations

import json
import math
import re
import secrets
import select
import socket
import stat
import struct
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext,
    VerifiedEffectAuthorization, canonical_bytes, canonical_digest,
)

MAX_REQUEST = 6 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_TIMEOUT = 120.0
DEFAULT_SOCKET_PATH = Path("/run/hermes-installer/authority.sock")
_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor", "memory.capture",
    "memory.search", "memory.export", "memory.delete", "memory.extract",
    "memory.embed", "memory.enqueue", "memory.result", "host.write", "alert.deliver",
    "process.start", "process.status", "process.read", "process.write", "process.stop",
})


def canonical_profile_target(profile_id: str, executable: Path, data_root: Path) -> str:
    executable = executable.resolve(strict=True)
    data_root = data_root.resolve(strict=True)
    if not executable.is_file() or not data_root.is_dir():
        raise AuthorityDenied("target.invalid", "profile executable/data root are invalid")
    import hashlib
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return f"hermes-profile-invoke:{profile_id}:{executable}:{digest}:{data_root}"


def profile_launch_envelope(*, target: str, profile_id: str, executable: Path,
                            artifact_sha256: str, artifact_root: Path, cwd: Path,
                            data_root: Path, argv: Sequence[str],
                            env_allowlist: Mapping[str, str],
                            max_lifetime_seconds: int = 600,
                            max_output_bytes: int = 1_048_576,
                            stdin_mode: str = "closed") -> dict[str, Any]:
    """Build the exact canonical launch binding consumed by process.start."""
    if target != canonical_profile_target(profile_id, executable, data_root):
        raise AuthorityDenied("effect.launch", "launch target is not bound to this profile")
    if len(argv) < 1 or argv[0] != str(executable.resolve(strict=True)):
        raise AuthorityDenied("effect.launch", "argv[0] must be the resolved pinned executable")
    if not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256):
        raise AuthorityDenied("effect.launch", "artifact digest is invalid")
    if not 1 <= max_lifetime_seconds <= 600 or not 1 <= max_output_bytes <= 4 * 1024 * 1024:
        raise AuthorityDenied("effect.bounds", "process lifetime or output limit is invalid")
    if stdin_mode not in {"closed", "pipe"}:
        raise AuthorityDenied("effect.launch", "stdin mode is invalid")
    return {
        "schema": 1, "target": target, "profile_id": profile_id,
        "executable": str(executable.resolve(strict=True)),
        "artifact_sha256": artifact_sha256,
        "artifact_root": str(artifact_root.resolve(strict=True)),
        "cwd": str(cwd.resolve(strict=True)),
        "data_root": str(data_root.resolve(strict=True)),
        "argv": list(argv), "env_allowlist": dict(env_allowlist),
        "max_lifetime_seconds": max_lifetime_seconds,
        "max_output_bytes": max_output_bytes, "stdin_mode": stdin_mode,
    }


class AuthorityClient:
    """Client for a fixed root-owned AF_UNIX endpoint and bounded fixed verbs."""

    def __init__(self, socket_path: Path, *, server_uid: int = 0,
                 timeout: float = 5.0, monotonic: Callable[[], float] = time.monotonic):
        if not socket_path.is_absolute() or type(server_uid) is not int or server_uid < 0:
            raise ValueError("absolute authority socket path and server UID are required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= 30:
            raise ValueError("authority timeout must be bounded")
        self.socket_path = socket_path
        self.server_uid = server_uid
        self.timeout = float(timeout)
        self.monotonic = monotonic

    @classmethod
    def for_current_process(cls, *, timeout: float = 5.0) -> "AuthorityClient":
        """Connect only to the installed fixed endpoint; never consult env vars."""
        return cls(DEFAULT_SOCKET_PATH, server_uid=0, timeout=timeout)

    def context(self, *, purpose: str, intent: str,
                source_contexts: Sequence[HostContext] = (),
                trace_id: str | None = None,
                lease_seconds: float = 30.0) -> HostContext:
        """Ask the host to classify intent and lineage from its own policy."""
        if not isinstance(purpose, str) or not 1 <= len(purpose) <= 128:
            raise AuthorityDenied("context.invalid", "purpose is invalid")
        if not isinstance(intent, str) or not 1 <= len(intent) <= 512:
            raise AuthorityDenied("context.invalid", "intent is invalid")
        if trace_id is not None and (not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128):
            raise AuthorityDenied("context.invalid", "trace ID is invalid")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 0 < lease_seconds <= 30:
            raise AuthorityDenied("context.invalid", "context lease must be at most 30 seconds")
        if len(source_contexts) > 64 or any(not isinstance(x, HostContext) for x in source_contexts):
            raise AuthorityDenied("context.invalid", "source lineage is invalid")
        result = self._rpc("issue_context", {
            "purpose": purpose, "intent": intent, "trace_id": trace_id,
            "lease_seconds": float(lease_seconds),
            "source_contexts": [ctx.to_wire() for ctx in source_contexts],
        })
        return HostContext.from_wire(result)

    def authorize_effect(self, context: HostContext, *, capability: str,
                         target: str, recipient: str | None = None,
                         request_digest: str, retry_index: int = 0,
                         cancelled: Callable[[], bool] | None = None) -> EffectAuthorization:
        if not isinstance(context, HostContext):
            raise AuthorityDenied("context.untrusted", "a host-issued context is required")
        if isinstance(retry_index, bool) or type(retry_index) is not int or not 0 <= retry_index <= 100:
            raise AuthorityDenied("effect.invalid", "retry index is invalid")
        if not isinstance(request_digest, str) or len(request_digest) != 64:
            raise AuthorityDenied("effect.invalid", "request digest is invalid")
        remaining = context.monotonic_expires_at - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("context.stale", "host context lease expired")
        result = self._rpc("authorize_effect", {
            "context": context.to_wire(), "capability": capability,
            "target": target, "recipient": recipient,
            "request_digest": request_digest, "retry_index": retry_index,
        }, timeout=min(self.timeout, remaining), cancelled=cancelled)
        return EffectAuthorization.from_wire(result)

    def verify_effect(self, authorization: EffectAuthorization, context: HostContext,
                      *, capability: str, target: str, recipient: str | None = None,
                      request_digest: str | None = None,
                      retry_index: int | None = None,
                      cancelled: Callable[[], bool] | None = None) -> VerifiedEffectAuthorization:
        if not isinstance(authorization, EffectAuthorization) or not isinstance(context, HostContext):
            raise AuthorityDenied("grant.invalid", "host-issued context and effect grant are required")
        remaining = min(context.monotonic_expires_at, authorization.monotonic_expires_at) - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("grant.stale", "host authorization lease expired")
        result = self._rpc("verify_effect", {
            "authorization": authorization.to_wire(), "context": context.to_wire(),
            "capability": capability, "target": target, "recipient": recipient,
            "request_digest": request_digest or authorization.request_digest,
            "retry_index": authorization.retry_index if retry_index is None else retry_index,
        }, timeout=min(self.timeout, remaining), cancelled=cancelled)
        if not isinstance(result, dict) or set(result) != {"operation", "consumed_at_monotonic", "verification_receipt"}:
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        consumed = result["consumed_at_monotonic"]
        if isinstance(consumed, bool) or not isinstance(consumed, (int, float)) or not math.isfinite(consumed):
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        return VerifiedEffectAuthorization(authorization, str(result["operation"]), float(consumed), str(result["verification_receipt"]))

    def perform_effect(self, authorization: EffectAuthorization, *, operation: str,
                       payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Perform one registered fixed-verb effect through the host broker.

        No arbitrary URL, method, shell command, or credential resolver is
        accepted here. The host broker independently verifies and consumes the
        grant and recomputes the payload digest before calling an enrolled
        adapter.
        """
        if operation not in _OPERATIONS:
            raise AuthorityDenied("effect.operation", "effect operation is not in the fixed verb set")
        if not isinstance(authorization, EffectAuthorization) or not isinstance(payload, bytes):
            raise AuthorityDenied("effect.invalid", "effect grant and byte payload are required")
        if len(payload) > 4 * 1024 * 1024:
            raise AuthorityDenied("effect.bounds", "effect payload exceeds its bound")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_TIMEOUT:
            raise AuthorityDenied("effect.bounds", "effect timeout exceeds its bound")
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "effect was cancelled before broker dispatch")
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "payload digest does not match effect grant")
        started = self.monotonic()
        request = {"authorization": authorization.to_wire(), "operation": operation,
                   "payload": __import__("base64").b64encode(payload).decode("ascii"),
                   "timeout": float(timeout)}
        result = self._rpc("perform_effect", request, timeout=min(self.timeout, float(timeout)), cancelled=cancelled)
        if cancelled is not None and cancelled():
            raise AuthorityDenied("effect.cancelled", "effect was cancelled before response delivery")
        if self.monotonic() - started > timeout:
            raise AuthorityDenied("effect.deadline", "brokered effect exceeded its deadline")
        if not isinstance(result, dict) or set(result) != {"status", "body", "headers", "receipt_id"}:
            raise AuthorityDenied("effect.invalid", "broker effect response is malformed")
        import base64
        try:
            body = base64.b64decode(result["body"], validate=True)
        except Exception:
            raise AuthorityDenied("effect.invalid", "broker effect response is malformed") from None
        headers = result["headers"]
        if (type(result["status"]) is not int or not 0 <= result["status"] <= 599
                or len(body) > 4 * 1024 * 1024 or not isinstance(headers, dict)
                or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())):
            raise AuthorityDenied("effect.invalid", "broker effect response exceeds its bound")
        return BrokeredEffectResponse(result["status"], body, dict(headers), str(result["receipt_id"]))

    def dispatch_provider(self, authorization: EffectAuthorization, *, target: str,
                          recipient: str, request_digest: str, payload: bytes,
                          timeout: float, cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, recipient, request_digest)
        if canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "provider payload digest does not match grant")
        return self.perform_effect(authorization, operation="provider.dispatch", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def memory_request(self, authorization: EffectAuthorization, *, target: str,
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory request target or digest is invalid")
        action = target.rsplit(":", 1)[-1]
        if action not in {"doctor", "extract", "embed", "capture", "search", "export", "delete"}:
            raise AuthorityDenied("effect.operation", "memory action is not enrolled")
        operation = "memory.doctor" if action == "doctor" else f"memory.{action}"
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def memory_enqueue(self, authorization: EffectAuthorization, *, target: str,
                       request_digest: str, payload: bytes, timeout: float = 1.0,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or target.rsplit(":", 1)[-1] != "enqueue" or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory queue target or digest is invalid")
        return self.perform_effect(authorization, operation="memory.enqueue", payload=payload,
                                   timeout=min(timeout, 1.0), cancelled=cancelled)

    def memory_result(self, authorization: EffectAuthorization, *, target: str,
                      request_digest: str, payload: bytes, timeout: float = 1.0,
                      cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or target.rsplit(":", 1)[-1] != "result" or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory result target or digest is invalid")
        return self.perform_effect(authorization, operation="memory.result", payload=payload,
                                   timeout=min(timeout, 1.0), cancelled=cancelled)

    def mcp_request(self, authorization: EffectAuthorization, *, target: str,
                    payload: bytes, timeout: float,
                    cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if authorization.target != target or not target.startswith("mcp:"):
            raise AuthorityDenied("effect.binding", "MCP target does not match its host grant")
        channel = target.rsplit(":", 1)[-1]
        if channel not in {"http", "stdio"}:
            raise AuthorityDenied("effect.target", "MCP channel is not enrolled")
        operation = "mcp.request" if channel == "http" else "mcp.stdio"
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def process_start(self, authorization: EffectAuthorization, *, target: str,
                      launch: Mapping[str, Any], timeout: float = 5.0,
                      cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if authorization.target != target or not target.startswith("hermes-profile-invoke:"):
            raise AuthorityDenied("effect.binding", "profile start target does not match its host grant")
        required = {"schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root", "cwd", "data_root", "argv", "env_allowlist", "max_lifetime_seconds", "max_output_bytes", "stdin_mode"}
        if not isinstance(launch, Mapping) or set(launch) != required or launch.get("schema") != 1 or launch.get("target") != target:
            raise AuthorityDenied("effect.launch", "profile launch envelope is malformed")
        argv = launch.get("argv")
        environment = launch.get("env_allowlist")
        if (not isinstance(argv, list) or not argv or len(argv) > 128
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096 for arg in argv)
                or not isinstance(environment, Mapping)
                or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in environment.items())):
            raise AuthorityDenied("effect.bounds", "profile launch arguments or environment are invalid")
        if (type(launch.get("max_lifetime_seconds")) is not int
                or not 1 <= launch["max_lifetime_seconds"] <= 600
                or type(launch.get("max_output_bytes")) is not int
                or not 1 <= launch["max_output_bytes"] <= 4 * 1024 * 1024
                or launch.get("stdin_mode") not in {"closed", "pipe"}):
            raise AuthorityDenied("effect.bounds", "profile launch resource bounds are invalid")
        # Credential-looking environment keys and values are never accepted.
        if any(any(mark in key.casefold() for mark in ("token", "secret", "password", "key")) for key in environment):
            raise AuthorityDenied("effect.secret", "profile launch environment contains a credential field")
        payload = canonical_bytes(launch)
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "profile launch envelope digest does not match its host grant")
        return self.perform_effect(authorization, operation="process.start", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def process_control(self, authorization: EffectAuthorization, *, operation: str,
                        target: str, payload: bytes, timeout: float = 5.0,
                        cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        if operation not in {"process.status", "process.read", "process.write", "process.stop"}:
            raise AuthorityDenied("effect.operation", "process control verb is not fixed")
        if authorization.target != target or not target.startswith("hermes-profile-control:"):
            raise AuthorityDenied("effect.binding", "process control target does not match its host grant")
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "process control payload digest does not match grant")
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    @staticmethod
    def _check_binding(grant: EffectAuthorization, target: str, recipient: str | None, digest: str) -> None:
        if (grant.target != target or grant.recipient != recipient or grant.request_digest != digest):
            raise AuthorityDenied("effect.binding", "effect request does not match its host grant")

    def _rpc(self, operation: str, payload: Mapping[str, Any], *, timeout: float | None = None,
             cancelled: Callable[[], bool] | None = None) -> Any:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AuthorityDenied("authority.unavailable", "authenticated Unix peer credentials are unavailable")
        deadline = self.monotonic() + (self.timeout if timeout is None else timeout)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(max(0.01, deadline - self.monotonic()))
            self._check_socket_path()
            sock.connect(str(self.socket_path))
            raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            if uid != self.server_uid:
                raise AuthorityDenied("authority.peer", "authority service peer UID mismatch")
            hello = self._exchange(sock, {"version": 1, "operation": "hello"}, deadline, cancelled=cancelled)
            if not isinstance(hello, dict) or set(hello) != {"version", "server_nonce"} or hello["version"] != 1:
                raise AuthorityDenied("authority.protocol", "authority handshake is invalid")
            nonce = hello["server_nonce"]
            if not isinstance(nonce, str) or not 32 <= len(nonce) <= 128:
                raise AuthorityDenied("authority.protocol", "authority handshake is invalid")
            request = {"version": 1, "operation": operation, "server_nonce": nonce,
                       "client_nonce": secrets.token_urlsafe(32), "payload": payload}
            response = self._exchange(sock, request, deadline, cancelled=cancelled)
            if not isinstance(response, dict) or set(response) != {"version", "server_nonce", "result", "error"}:
                raise AuthorityDenied("authority.protocol", "authority response is malformed")
            if response["version"] != 1 or response["server_nonce"] != nonce:
                raise AuthorityDenied("authority.protocol", "authority response binding mismatch")
            if response["error"] is not None:
                error = response["error"]
                if not isinstance(error, dict) or set(error) != {"code", "message"}:
                    raise AuthorityDenied("authority.protocol", "authority denial is malformed")
                raise AuthorityDenied(str(error["code"]), str(error["message"]))
            return response["result"]
        except AuthorityDenied:
            raise
        except (OSError, TimeoutError, ValueError, TypeError, json.JSONDecodeError):
            raise AuthorityDenied("authority.unavailable", "protected host authority is unavailable") from None
        finally:
            sock.close()

    def _exchange(self, sock: socket.socket, value: Mapping[str, Any], deadline: float,
                  cancelled: Callable[[], bool] | None = None) -> Any:
        wire = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(wire) > MAX_REQUEST:
            raise AuthorityDenied("authority.bounds", "authority request exceeds its bound")
        sock.settimeout(max(0.01, deadline - self.monotonic()))
        sock.sendall(wire)
        line = bytearray()
        while len(line) <= MAX_RESPONSE:
            if cancelled is not None and cancelled():
                raise AuthorityDenied("effect.cancelled", "brokered effect was cancelled")
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise AuthorityDenied("authority.timeout", "authority request exceeded its deadline")
            sock.settimeout(min(0.05, remaining))
            try:
                chunk = sock.recv(1)
            except TimeoutError:
                continue
            if not chunk:
                break
            if chunk == b"\n":
                try:
                    return json.loads(line.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise AuthorityDenied("authority.protocol", "authority response is malformed") from None
            line.extend(chunk)
        raise AuthorityDenied("authority.bounds", "authority response is incomplete or oversized")

    def _check_socket_path(self) -> None:
        try:
            info = self.socket_path.lstat()
        except OSError:
            raise AuthorityDenied("authority.unavailable", "protected authority endpoint is unavailable") from None
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.server_uid or info.st_mode & 0o022:
            raise AuthorityDenied("authority.endpoint", "authority endpoint ownership or mode is invalid")
        parent = self.socket_path.parent.lstat()
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != self.server_uid or parent.st_mode & 0o022:
            raise AuthorityDenied("authority.endpoint", "authority endpoint directory ownership or mode is invalid")
