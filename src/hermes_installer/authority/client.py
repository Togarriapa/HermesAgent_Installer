"""Synchronous, peer-authenticated client for the protected host authority.

Workers never receive a signing key. Host contexts and effect grants are signed
by the root-owned service; this client authenticates that service with kernel
peer credentials and asks it to verify/consume every effect grant.
"""
from __future__ import annotations

import json
import math
import os
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

_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete", "memory.extract",
    "memory.embed", "memory.backup", "memory.restore", "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "process.start", "process.status", "process.read",
    "process.write", "process.stop", "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.orchestrator.recruit",
    "source.capture", "process.inspect", "connector.open", "connector.read",
    "connector.write", "connector.close", "native.event.prepare", "native.request.dispatch",
})

MAX_REQUEST = 6 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_TIMEOUT = 600.0
DEFAULT_SOCKET_DIR = Path("/run/hermes-installer/authority")


def default_socket_path(uid: int | None = None) -> Path:
    """Return the installed per-UID socket path without consulting environment."""
    peer_uid = os.getuid() if uid is None else uid
    if type(peer_uid) is not int or peer_uid <= 0:
        raise AuthorityDenied("authority.endpoint", "current user has no enrolled authority endpoint")
    return DEFAULT_SOCKET_DIR / f"{peer_uid}.sock"
_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor", "memory.capture",
    "memory.search", "memory.export", "memory.delete", "memory.extract",
    "memory.embed", "memory.backup", "memory.restore", "memory.enqueue", "memory.result",
    "host.write", "alert.deliver",
    "process.start", "process.status", "process.read", "process.write", "process.stop",
    "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.orchestrator.recruit",
})


def canonical_profile_target(profile_id: str, executable: Path, data_root: Path) -> str:
    executable = executable.resolve(strict=True)
    data_root = data_root.resolve(strict=True)
    if not executable.is_file() or not data_root.is_dir():
        raise AuthorityDenied("target.invalid", "profile executable/data root are invalid")
    import hashlib
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    return f"hermes-profile-invoke:{profile_id}:{executable}:{digest}:{data_root}"


def _file_digest(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def profile_launch_envelope(*, target: str, profile_id: str, executable: Path,
                            artifact_sha256: str, artifact_root: Path, cwd: Path,
                            data_root: Path, argv: Sequence[str],
                            env_allowlist: Mapping[str, str],
                            child_artifact_refs: Mapping[str, str] | None = None,
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
    child_refs: dict[str, str] = {}
    for store_id, child_digest in (child_artifact_refs or {}).items():
        if (not isinstance(store_id, str) or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", store_id)
                or store_id.rsplit(":", 1)[-1] != child_digest
                or not re.fullmatch(r"[0-9a-f]{64}", child_digest)):
            raise AuthorityDenied("effect.launch", "child artifact reference is invalid")
        child_refs[store_id] = child_digest
    if any(arg.startswith("artifact:") and arg not in child_refs for arg in argv):
        raise AuthorityDenied("effect.launch", "argv names an unregistered artifact reference")
    return {
        "schema": 1, "target": target, "profile_id": profile_id,
        "executable": str(executable.resolve(strict=True)),
        "artifact_sha256": artifact_sha256,
        "artifact_root": str(artifact_root.resolve(strict=True)),
        "cwd": str(cwd.resolve(strict=True)),
        "data_root": str(data_root.resolve(strict=True)),
        "argv": list(argv), "env_allowlist": dict(env_allowlist),
        "child_artifact_refs": child_refs,
        "max_lifetime_seconds": max_lifetime_seconds,
        "max_output_bytes": max_output_bytes, "stdin_mode": stdin_mode,
    }


class AuthorityClient:
    """Client for a fixed root-owned AF_UNIX endpoint and bounded fixed verbs."""

    def __init__(self, socket_path: Path, *, server_uid: int = 0,
                 server_gid: int | None = None,
                 timeout: float = 5.0, monotonic: Callable[[], float] = time.monotonic):
        if not socket_path.is_absolute() or type(server_uid) is not int or server_uid < 0:
            raise ValueError("absolute authority socket path and server UID are required")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0.1 <= timeout <= MAX_TIMEOUT:
            raise ValueError("authority timeout must be bounded")
        self.socket_path = socket_path
        self.server_uid = server_uid
        if server_gid is not None and (type(server_gid) is not int or server_gid < 0):
            raise ValueError("socket group ID must be nonnegative")
        self.server_gid = server_gid
        self.timeout = float(timeout)
        self.monotonic = monotonic

    @classmethod
    def for_current_process(cls, *, timeout: float = 5.0) -> "AuthorityClient":
        """Connect only to the installed fixed endpoint; never consult env vars."""
        return cls(default_socket_path(), server_uid=0, server_gid=os.getgid(), timeout=timeout)

    def context(self, *, purpose: str, intent: str, operation: str,
                source_contexts: Sequence[HostContext] = (),
                source_receipt_handles: Sequence[str] = (),
                final_payload_digest: str | None = None,
                trace_id: str | None = None,
                lease_seconds: float = 30.0,
                cancelled: Callable[[], bool] | None = None) -> HostContext:
        """Ask the host to classify intent and lineage from its own policy."""
        if not isinstance(purpose, str) or not 1 <= len(purpose) <= 128:
            raise AuthorityDenied("context.invalid", "purpose is invalid")
        if not isinstance(intent, str) or not 1 <= len(intent) <= 512:
            raise AuthorityDenied("context.invalid", "intent is invalid")
        if operation not in _OPERATIONS:
            raise AuthorityDenied("context.invalid", "operation is not a fixed host effect")
        if trace_id is not None and (not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128):
            raise AuthorityDenied("context.invalid", "trace ID is invalid")
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 0 < lease_seconds <= MAX_TIMEOUT:
            raise AuthorityDenied("context.invalid", "context lease exceeds its fixed upper bound")
        if (len(source_contexts) > 64 or any(not isinstance(x, HostContext) for x in source_contexts)
                or len(source_receipt_handles) > 64
                or any(not isinstance(x, str) or not x for x in source_receipt_handles)):
            raise AuthorityDenied("context.invalid", "source lineage is invalid")
        if source_contexts and source_receipt_handles:
            raise AuthorityDenied("context.invalid", "use one complete source lineage representation")
        if final_payload_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", final_payload_digest):
            raise AuthorityDenied("context.invalid", "final payload digest is invalid")
        if source_receipt_handles and final_payload_digest is None:
            raise AuthorityDenied("context.invalid", "source receipts require a final payload digest")
        request = {
            "purpose": purpose, "intent": intent, "trace_id": trace_id,
            "lease_seconds": float(lease_seconds),
            "source_contexts": [ctx.to_wire() for ctx in source_contexts],
        }
        if source_receipt_handles:
            request["source_receipt_handles"] = list(source_receipt_handles)
        if final_payload_digest is not None:
            request["final_payload_digest"] = final_payload_digest
        request["operation"] = operation
        result = self._rpc("issue_context", {
            **request,
        }, timeout=min(self.timeout, float(lease_seconds)), cancelled=cancelled)
        return HostContext.from_wire(result)

    def capture_source(self, payload: bytes, *, parent_receipt_handles: Sequence[str] = (),
                       timeout: float = 5.0,
                       cancelled: Callable[[], bool] | None = None) -> str:
        """Let the root broker hash exact submitted bytes and return an opaque private receipt handle."""
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= 1_048_576:
            raise AuthorityDenied("source.invalid", "source capture exceeds its fixed byte bound")
        if (len(parent_receipt_handles) > 64
                or any(not isinstance(item, str) or not item for item in parent_receipt_handles)):
            raise AuthorityDenied("source.invalid", "parent receipt handles are invalid")
        if cancelled is not None and cancelled():
            raise AuthorityDenied("source.cancelled", "source capture was cancelled")
        import base64
        result = self._rpc("capture_source", {
            "schema": 1,
            "payload": base64.b64encode(payload).decode("ascii"),
            "parent_receipt_handles": list(parent_receipt_handles),
        }, timeout=min(self.timeout, timeout), cancelled=cancelled)
        if not isinstance(result, dict) or set(result) != {"receipt_handle"}:
            raise AuthorityDenied("source.invalid", "source broker returned an invalid receipt handle")
        handle = result["receipt_handle"]
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise AuthorityDenied("source.invalid", "source broker returned an invalid receipt handle")
        return handle

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
        if not isinstance(result, dict) or set(result) != {"operation", "verified_at_monotonic", "verification_receipt"}:
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        verified = result["verified_at_monotonic"]
        if isinstance(verified, bool) or not isinstance(verified, (int, float)) or not math.isfinite(verified):
            raise AuthorityDenied("grant.invalid", "authority verification receipt is malformed")
        return VerifiedEffectAuthorization(authorization, str(result["operation"]), float(verified), str(result["verification_receipt"]))

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
        remaining = authorization.monotonic_expires_at - self.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("grant.stale", "effect authorization lease expired")
        result = self._rpc("perform_effect", request, timeout=min(float(timeout), remaining), cancelled=cancelled)
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
                or len(headers) > 32
                or any(not isinstance(k, str) or not isinstance(v, str)
                       or not k or len(k) > 128 or len(v) > 2048
                       or any(char in k + v for char in "\r\n\x00") for k, v in headers.items())
                or not isinstance(result["receipt_id"], str) or not 1 <= len(result["receipt_id"]) <= 256):
            raise AuthorityDenied("effect.invalid", "broker effect response exceeds its bound")
        return BrokeredEffectResponse(result["status"], body, dict(headers), result["receipt_id"])

    def dispatch_provider(self, authorization: EffectAuthorization, *, target: str,
                          recipient: str, request_digest: str, payload: bytes,
                          timeout: float, cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, recipient, request_digest)
        if canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "provider payload digest does not match grant")
        return self.perform_effect(authorization, operation="provider.dispatch", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def dispatch_codex(self, authorization: EffectAuthorization, *,
                       target: str = "codex://responses",
                       recipient: str = "openai:codex",
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Use the host-enrolled Codex Responses credential and exact endpoint."""
        if target != "codex://responses" or recipient != "openai:codex":
            raise AuthorityDenied("effect.target", "Codex target and account identity are fixed")
        if canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "Codex payload digest does not match request")
        self._check_binding(authorization, target, recipient, request_digest)
        return self.perform_effect(authorization, operation="provider.dispatch", payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def memory_request(self, authorization: EffectAuthorization, *, target: str,
                       request_digest: str, payload: bytes, timeout: float,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        self._check_binding(authorization, target, authorization.recipient, request_digest)
        if not target.startswith("memory:") or canonical_digest(payload) != request_digest:
            raise AuthorityDenied("effect.binding", "memory request target or digest is invalid")
        action = target.rsplit(":", 1)[-1]
        if action not in {"doctor", "extract", "embed", "capture", "search", "export", "delete", "backup", "restore"}:
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
        required = {"schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root", "cwd", "data_root", "argv", "env_allowlist", "child_artifact_refs", "max_lifetime_seconds", "max_output_bytes", "stdin_mode"}
        if not isinstance(launch, Mapping) or set(launch) != required or launch.get("schema") != 1 or launch.get("target") != target:
            raise AuthorityDenied("effect.launch", "profile launch envelope is malformed")
        argv = launch.get("argv")
        environment = launch.get("env_allowlist")
        child_refs = launch.get("child_artifact_refs")
        if (not isinstance(argv, list) or not argv or len(argv) > 128
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096 for arg in argv)
                or not isinstance(environment, Mapping)
                or not isinstance(child_refs, Mapping) or len(child_refs) > 64
                or any(not isinstance(k, str) or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", k)
                       or not isinstance(v, str) or k.rsplit(":", 1)[-1] != v
                       or not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in child_refs.items())
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
        if operation not in {"process.status", "process.read", "process.write", "process.stop", "process.inspect"}:
            raise AuthorityDenied("effect.operation", "process control verb is not fixed")
        target_valid = (target.startswith("hermes-profile-control:")
                        if operation != "process.inspect" else bool(re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}:inspect", target)))
        if authorization.target != target or not target_valid:
            raise AuthorityDenied("effect.binding", "process control target does not match its host grant")
        if canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("effect.binding", "process control payload digest does not match grant")
        return self.perform_effect(authorization, operation=operation, payload=payload,
                                   timeout=timeout, cancelled=cancelled)

    def inspect_profile_process(self, process_id: str, generation: str, *,
                                timeout: float = 5.0,
                                cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Inspect only a registered host process handle; callers never name a PID or path."""
        if (not isinstance(process_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", process_id)
                or not isinstance(generation, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", generation)):
            raise AuthorityDenied("process.inspect", "opaque process handle or generation is invalid")
        payload = canonical_bytes({"schema": 1, "process_id": process_id, "generation": generation})
        digest = canonical_digest(payload)
        context = self.context(
            purpose="remote-process-inspection", intent=f"inspect:{process_id}:{generation}",
            operation="process.inspect", final_payload_digest=digest,
            lease_seconds=min(30.0, timeout), cancelled=cancelled)
        target = f"{context.profile_id}:inspect"
        authorization = self.authorize_effect(
            context, capability="hermes-process-control", target=target,
            recipient=None, request_digest=digest, retry_index=0)
        response = self.process_control(authorization, operation="process.inspect", target=target,
                                        payload=payload, timeout=timeout, cancelled=cancelled)
        return response

    def fetch_artifact(self, authorization: EffectAuthorization, *, target: str,
                       artifact_id: str, sha256: str, max_bytes: int,
                       timeout: float = 30.0,
                       cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Fetch a root-enrolled immutable artifact; callers cannot supply URLs or paths."""
        if (target != f"artifact:{artifact_id}:{sha256}"
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact_id)
                or not re.fullmatch(r"[0-9a-f]{64}", sha256)
                or type(max_bytes) is not int or not 1 <= max_bytes <= 8 * 1024 * 1024 * 1024):
            raise AuthorityDenied("artifact.binding", "artifact identity or size bound is invalid")
        payload = canonical_bytes({"schema": 1, "artifact_id": artifact_id,
                                   "sha256": sha256, "max_bytes": max_bytes})
        if authorization.target != target or canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("artifact.binding", "artifact request does not match its host grant")
        return self.perform_effect(authorization, operation="artifact.fetch", payload=payload,
                                   timeout=min(timeout, MAX_TIMEOUT), cancelled=cancelled)

    def install_package(self, authorization: EffectAuthorization, *, target: str,
                        package_id: str, version: str, artifact_sha256: str,
                        timeout: float = 30.0,
                        cancelled: Callable[[], bool] | None = None) -> BrokeredEffectResponse:
        """Install only a root-enrolled pinned package through the host installer identity."""
        if (target != f"package:{package_id}:{version}:{artifact_sha256}"
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", package_id)
                or not re.fullmatch(r"[A-Za-z0-9+_.-]{1,128}", version)
                or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha256)):
            raise AuthorityDenied("package.binding", "package identity or pinned artifact is invalid")
        payload = canonical_bytes({"schema": 1, "package_id": package_id,
                                   "version": version, "artifact_sha256": artifact_sha256})
        if authorization.target != target or canonical_digest(payload) != authorization.request_digest:
            raise AuthorityDenied("package.binding", "package request does not match its host grant")
        return self.perform_effect(authorization, operation="package.install", payload=payload,
                                   timeout=min(timeout, MAX_TIMEOUT), cancelled=cancelled)

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
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != self.server_uid
                or info.st_mode & 0o007
                or self.server_gid is not None and (info.st_gid != self.server_gid or not info.st_mode & 0o020)):
            raise AuthorityDenied("authority.endpoint", "authority endpoint ownership or mode is invalid")
        parent = self.socket_path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != self.server_uid or parent.st_mode & 0o022
                or self.server_uid == 0 and not parent.st_mode & 0o001):
            raise AuthorityDenied("authority.endpoint", "authority endpoint directory ownership or mode is invalid")
