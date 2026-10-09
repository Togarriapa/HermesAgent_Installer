"""Root-owned signing, peer binding and one-use fixed-verb authority service.

The caller never chooses its UID, profile, namespace or principal. The service
reads SO_PEERCRED, resolves a protected binding, signs short claims with a key
that remains in this process, and independently checks/consumes every grant.
Effect handlers are explicit reviewed adapters keyed by fixed operation and
protected target IDs; this is not a URL proxy or shell interface.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import secrets
import select
import socket
import stat
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .types import (
    AuthorityDenied, EffectAuthorization, HostContext, Sensitivity,
    canonical_digest,
)

MAX_REQUEST = 4 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_CONTEXT_LEASE = 30.0
MAX_EFFECT_LEASE = 5.0
_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete",
    "memory.extract", "memory.embed", "memory.backup", "memory.restore",
    "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "process.start", "process.status",
    "process.read", "process.write", "process.stop", "artifact.fetch", "package.install",
})


@dataclass(frozen=True, slots=True)
class PrincipalBinding:
    uid: int
    principal_id: str
    profile_id: str
    namespace_id: str
    capabilities: frozenset[str]

    def __post_init__(self) -> None:
        if type(self.uid) is not int or self.uid <= 0 or not self.principal_id or not self.profile_id or not self.namespace_id:
            raise ValueError("protected principal binding is incomplete")
        if not self.capabilities or any(not isinstance(cap, str) or not cap for cap in self.capabilities):
            raise ValueError("protected principal capabilities are required")


@dataclass(frozen=True, slots=True)
class EffectRule:
    capability: str
    operation: str
    target: str
    recipient: str | None = None

    def __post_init__(self) -> None:
        if self.operation not in _OPERATIONS or not self.capability or not self.target:
            raise ValueError("effect rule must name a fixed operation, capability and target")


class AuthorityPolicy(Protocol):
    def classify(self, *, purpose: str, intent: str,
                 source_contexts: tuple[HostContext, ...],
                 binding: PrincipalBinding) -> tuple[Sensitivity, str]: ...

    def allow_effect(self, *, context: HostContext, rule: EffectRule,
                     request_digest: str, retry_index: int) -> bool: ...


class EffectHandler(Protocol):
    def __call__(self, *, context: HostContext, authorization: EffectAuthorization,
                 payload: bytes, timeout: float,
                 peer_pid: int,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]: ...


class DenyByDefaultPolicy:
    """Safe policy until protected purpose/capability rules are enrolled."""

    def classify(self, *, purpose: str, intent: str,
                 source_contexts: tuple[HostContext, ...],
                 binding: PrincipalBinding) -> tuple[Sensitivity, str]:
        if source_contexts:
            sensitivity = max((source.sensitivity for source in source_contexts), key=lambda item: list(Sensitivity).index(item))
            lineage = canonical_digest(sorted(_context_digest(source) for source in source_contexts))
            return sensitivity, lineage
        # An empty source list is unknown; never assume public from caller text.
        return Sensitivity.UNKNOWN, canonical_digest({"empty": True, "purpose": purpose})

    def allow_effect(self, *, context: HostContext, rule: EffectRule,
                     request_digest: str, retry_index: int) -> bool:
        return False


def _context_digest(context: HostContext) -> str:
    return canonical_digest({**context.claims(), "signature": context.signature})


class AuthorityService:
    """One authenticated client request per connection on the fixed socket."""

    def __init__(self, *, signing_key: bytes, key_id: str,
                 bindings_by_uid: Mapping[int, PrincipalBinding],
                 rules: Mapping[tuple[str, str], EffectRule],
                 handlers: Mapping[tuple[str, str], EffectHandler],
                 policy: AuthorityPolicy | None = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time):
        if len(signing_key) < 32 or not key_id:
            raise ValueError("authority signing key must be protected and at least 256 bits")
        if not bindings_by_uid or any(uid != binding.uid for uid, binding in bindings_by_uid.items()):
            raise ValueError("UID map must be an explicit protected identity mapping")
        enrolled_operations = {(rule.operation, rule.target) for rule in rules.values()}
        if set(handlers) - enrolled_operations:
            raise ValueError("effect handler has no protected enrollment rule")
        self._key = bytes(signing_key)
        self.key_id = key_id
        self.bindings_by_uid = dict(bindings_by_uid)
        self.rules = dict(rules)
        self.handlers = dict(handlers)
        self.policy = policy or DenyByDefaultPolicy()
        self.monotonic = monotonic
        self.wall_clock = wall_clock
        self._nonces: dict[str, float] = {}
        self._lock = threading.RLock()
        self._client_nonces: dict[str, float] = {}

    def serve_unix(self, socket_path: Path, *, socket_gid: int,
                   stop_event: threading.Event,
                   expected_uid: int = 0, max_clients: int = 32) -> None:
        """Serve bounded one-RPC connections on a protected fixed Unix socket.

        The method refuses to unlink or replace any existing path. Packaging
        owns creation of the root-controlled parent directory and service unit.
        """
        if (not socket_path.is_absolute() or type(socket_gid) is not int or socket_gid < 0
                or type(expected_uid) is not int or expected_uid < 0
                or type(max_clients) is not int or not 1 <= max_clients <= 128):
            raise ValueError("invalid authority listener configuration")
        parent = socket_path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != expected_uid or parent.st_mode & 0o022):
            raise AuthorityDenied("authority.socket", "authority socket directory custody is invalid")
        try:
            socket_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise AuthorityDenied("authority.socket", "authority socket path already exists")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        pool = ThreadPoolExecutor(max_workers=max_clients, thread_name_prefix="authority-rpc")
        slots = threading.BoundedSemaphore(max_clients)
        try:
            listener.bind(str(socket_path))
            os.chown(socket_path, expected_uid, socket_gid)
            os.chmod(socket_path, 0o660)
            listener.listen(max_clients)
            listener.settimeout(0.25)
            while not stop_event.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                if not slots.acquire(blocking=False):
                    connection.close()
                    continue
                def serve_one(conn: socket.socket = connection) -> None:
                    try:
                        self.handle_connection(conn)
                    finally:
                        conn.close()
                        slots.release()
                try:
                    pool.submit(serve_one)
                except RuntimeError:
                    connection.close()
                    slots.release()
                    raise
        finally:
            listener.close()
            pool.shutdown(wait=True, cancel_futures=True)
            try:
                info = socket_path.lstat()
                if stat.S_ISSOCK(info.st_mode) and info.st_uid == expected_uid:
                    socket_path.unlink()
            except OSError:
                pass

    @classmethod
    def from_key_file(cls, path: Path, *, key_id: str,
                      expected_uid: int = 0, **kwargs: Any) -> "AuthorityService":
        parent = path.parent.lstat()
        if (stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode)
                or parent.st_uid != expected_uid or parent.st_mode & 0o022):
            raise AuthorityDenied("key.custody", "authority signing key directory custody is invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(path, flags)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o077:
                    raise AuthorityDenied("key.custody", "authority signing key custody is invalid")
                data = os.read(fd, 33)
            finally:
                os.close(fd)
        except OSError:
            raise AuthorityDenied("key.custody", "authority signing key is unavailable") from None
        if len(data) != 32:
            raise AuthorityDenied("key.custody", "authority signing key has invalid length")
        return cls(signing_key=data, key_id=key_id, **kwargs)

    def handle_connection(self, connection: socket.socket) -> None:
        """Authenticate kernel peer, issue challenge, and process exactly one RPC."""
        try:
            connection.settimeout(125.0)
            peer_pid, uid = self._peer_credentials(connection)
            hello = self._read_json_line(connection, MAX_REQUEST)
            if hello != {"version": 1, "operation": "hello"}:
                raise AuthorityDenied("protocol.handshake", "invalid authority handshake")
            nonce = secrets.token_urlsafe(32)
            self._write_json_line(connection, {"version": 1, "server_nonce": nonce}, MAX_RESPONSE)
            request = self._read_json_line(connection, MAX_REQUEST)
            if not isinstance(request, dict) or set(request) != {"version", "operation", "server_nonce", "client_nonce", "payload"}:
                raise AuthorityDenied("protocol.request", "authority request fields are invalid")
            if request["version"] != 1 or request["server_nonce"] != nonce:
                raise AuthorityDenied("protocol.replay", "authority handshake nonce mismatch")
            client_nonce = request["client_nonce"]
            if not isinstance(client_nonce, str) or not 32 <= len(client_nonce) <= 128:
                raise AuthorityDenied("protocol.request", "authority client nonce is invalid")
            with self._lock:
                now = self.monotonic()
                self._client_nonces = {key: expiry for key, expiry in self._client_nonces.items() if expiry > now}
                if client_nonce in self._client_nonces:
                    raise AuthorityDenied("protocol.replay", "authority request nonce was replayed")
                if len(self._client_nonces) >= 100_000:
                    raise AuthorityDenied("protocol.capacity", "authority replay protection is at capacity")
                self._client_nonces[client_nonce] = now + 130.0
            result = self._dispatch(uid, peer_pid, request["operation"], request["payload"],
                                   cancelled=lambda: self._peer_disconnected(connection))
            response = {"version": 1, "server_nonce": nonce, "result": result, "error": None}
        except AuthorityDenied as exc:
            response = {"version": 1, "server_nonce": locals().get("nonce", ""), "result": None,
                        "error": {"code": exc.code, "message": str(exc)}}
        except Exception:
            response = {"version": 1, "server_nonce": locals().get("nonce", ""), "result": None,
                        "error": {"code": "authority.failure", "message": "host authority request failed"}}
        try:
            self._write_json_line(connection, response, MAX_RESPONSE)
        except (OSError, AuthorityDenied):
            pass

    def _dispatch(self, uid: int, peer_pid: int, operation: Any, payload: Any,
                  *, cancelled: Callable[[], bool]) -> Any:
        if operation == "issue_context":
            return self._issue_context(uid, payload)
        if operation == "authorize_effect":
            return self._authorize_effect(uid, payload)
        if operation == "verify_effect":
            return self._verify_effect(uid, payload)
        if operation == "perform_effect":
            return self._perform_effect(uid, peer_pid, payload, cancelled=cancelled)
        raise AuthorityDenied("protocol.operation", "authority operation is unavailable")

    def _binding(self, uid: int) -> PrincipalBinding:
        binding = self.bindings_by_uid.get(uid)
        if binding is None:
            raise AuthorityDenied("principal.unenrolled", "kernel peer UID has no enrolled profile")
        return binding

    def _issue_context(self, uid: int, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"purpose", "intent", "trace_id", "lease_seconds", "source_contexts"}:
            raise AuthorityDenied("context.request", "context request fields are invalid")
        binding = self._binding(uid)
        purpose, intent = payload["purpose"], payload["intent"]
        if (not isinstance(purpose, str) or not 1 <= len(purpose) <= 128
                or not isinstance(intent, str) or not 1 <= len(intent) <= 512):
            raise AuthorityDenied("context.request", "purpose or intent is invalid")
        lease = self._bounded(payload["lease_seconds"], MAX_CONTEXT_LEASE)
        raw_sources = payload["source_contexts"]
        if not isinstance(raw_sources, list) or len(raw_sources) > 64:
            raise AuthorityDenied("context.lineage", "source lineage exceeds its bound")
        sources = tuple(HostContext.from_wire(item) for item in raw_sources)
        for source in sources:
            self._verify_context_signature(source)
            if (source.uid != uid or source.profile_id != binding.profile_id
                    or source.principal_id != binding.principal_id
                    or source.namespace_id != binding.namespace_id):
                # Expired signed contexts may be retained as provenance for
                # bounded background work; they confer no capabilities and can
                # only increase effective sensitivity.
                raise AuthorityDenied("context.lineage", "source context belongs to another principal")
        trace_id = payload["trace_id"] or secrets.token_urlsafe(24)
        if not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128:
            raise AuthorityDenied("context.request", "trace ID is invalid")
        sensitivity, lineage_hash = self.policy.classify(
            purpose=purpose, intent=intent, source_contexts=sources, binding=binding)
        if not isinstance(sensitivity, Sensitivity):
            raise AuthorityDenied("policy.classification", "host policy returned an invalid classification")
        now = self.monotonic()
        context = HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=uid, purpose=purpose,
            intent_id=canonical_digest({"purpose": purpose, "intent": intent}),
            trace_id=trace_id, sensitivity=sensitivity, lineage_hash=lineage_hash,
            policy_revision=self._policy_revision(), capabilities=binding.capabilities,
            issued_at_monotonic=now, monotonic_expires_at=now + lease,
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24), signature="pending",
        )
        signature = self._sign(context.claims())
        return HostContext(**{**context.__dict__, "signature": signature}).to_wire() if hasattr(context, "__dict__") else self._signed_context(context, signature)

    def _signed_context(self, context: HostContext, signature: str) -> dict[str, Any]:
        fields = context.claims()
        fields["signature"] = signature
        return fields

    def _authorize_effect(self, uid: int, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect request fields are invalid")
        binding = self._binding(uid)
        context = HostContext.from_wire(payload["context"])
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, uid)
        capability, target, recipient = payload["capability"], payload["target"], payload["recipient"]
        request_digest, retry_index = payload["request_digest"], payload["retry_index"]
        if (not isinstance(capability, str) or not isinstance(target, str)
                or recipient is not None and not isinstance(recipient, str)
                or not isinstance(request_digest, str) or len(request_digest) != 64
                or type(retry_index) is not int or not 0 <= retry_index <= 100):
            raise AuthorityDenied("effect.request", "effect binding is invalid")
        rule = self.rules.get((capability, target))
        if (rule is None or rule.recipient != recipient
                or not self.policy.allow_effect(context=context, rule=rule,
                                                request_digest=request_digest, retry_index=retry_index)):
            raise AuthorityDenied("effect.denied", "host policy denied this exact effect")
        if capability not in context.capabilities:
            raise AuthorityDenied("effect.denied", "profile has no enrolled capability for this effect")
        now = self.monotonic()
        expiry = min(context.monotonic_expires_at, now + MAX_EFFECT_LEASE)
        grant = EffectAuthorization(
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace_id=context.namespace_id, uid=uid, purpose=context.purpose,
            sensitivity=context.sensitivity, trace_id=context.trace_id,
            policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
            capability=capability, intent_id=context.intent_id, target=target,
            recipient=recipient, request_digest=request_digest,
            retry_index=retry_index, issued_at_monotonic=now,
            monotonic_expires_at=expiry, grant_id=secrets.token_urlsafe(24),
            nonce=secrets.token_urlsafe(24), context_digest=_context_digest(context),
            signature="pending",
        )
        signed = self._sign(grant.claims())
        return {**grant.claims(), "signature": signed}

    def _verify_effect(self, uid: int, payload: Any) -> dict[str, Any]:
        grant, context, rule = self._parse_effect_request(uid, payload)
        self._consume(grant)
        return {"operation": rule.operation, "consumed_at_monotonic": self.monotonic(),
                "verification_receipt": secrets.token_urlsafe(24)}

    def _perform_effect(self, uid: int, peer_pid: int, payload: Any,
                        *, cancelled: Callable[[], bool]) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "operation", "payload", "timeout"}:
            raise AuthorityDenied("effect.request", "broker request fields are invalid")
        import base64
        try:
            body = base64.b64decode(payload["payload"], validate=True)
        except Exception:
            raise AuthorityDenied("effect.request", "broker payload is malformed") from None
        timeout = self._bounded(payload["timeout"], 120.0)
        grant = EffectAuthorization.from_wire(payload["authorization"])
        binding = self._binding(uid)
        self._verify_grant_signature(grant)
        self._assert_grant_current(grant, binding, uid)
        if canonical_digest(body) != grant.request_digest:
            raise AuthorityDenied("effect.binding", "broker payload digest mismatch")
        rule = self.rules.get((grant.capability, grant.target))
        if (rule is None or rule.operation != payload["operation"]
                or rule.recipient != grant.recipient):
            raise AuthorityDenied("effect.binding", "fixed effect operation does not match protected target")
        context = self._context_from_grant(grant, binding)
        if not self.policy.allow_effect(context=context, rule=rule,
                                        request_digest=grant.request_digest,
                                        retry_index=grant.retry_index):
            raise AuthorityDenied("effect.denied", "fresh host policy denied the fixed effect")
        handler = self.handlers.get((rule.operation, rule.target))
        if handler is None:
            raise AuthorityDenied("effect.unavailable", "fixed effect handler is not installed")
        self._consume(grant)
        started = self.monotonic()
        remaining = min(timeout, grant.monotonic_expires_at - started)
        if remaining <= 0:
            raise AuthorityDenied("effect.expired", "fixed effect grant expired before dispatch")
        cancellation = lambda: (self.monotonic() >= grant.monotonic_expires_at or cancelled())
        response = handler(context=context, authorization=grant,
                           payload=body, timeout=remaining,
                           peer_pid=peer_pid,
                           cancelled=cancellation)
        if cancellation():
            raise AuthorityDenied("effect.expired", "fixed effect exceeded its grant lease")
        if not isinstance(response, Mapping) or set(response) != {"status", "body", "headers", "receipt_id"}:
            raise AuthorityDenied("effect.response", "fixed effect handler returned an invalid response")
        body_bytes = response["body"]
        if not isinstance(body_bytes, bytes) or len(body_bytes) > 4 * 1024 * 1024:
            raise AuthorityDenied("effect.response", "fixed effect response exceeds its bound")
        headers = response["headers"]
        receipt_id = response["receipt_id"]
        if type(response["status"]) is not int or not 0 <= response["status"] <= 599:
            raise AuthorityDenied("effect.response", "fixed effect status is invalid")
        if (not isinstance(headers, Mapping) or len(headers) > 32
                or any(not isinstance(key, str) or not isinstance(value, str)
                       or not key or len(key) > 128 or len(value) > 2048
                       or any(char in key + value for char in "\r\n\x00")
                       for key, value in headers.items())
                or not isinstance(receipt_id, str) or not 1 <= len(receipt_id) <= 256):
            raise AuthorityDenied("effect.response", "fixed effect response headers or receipt are invalid")
        return {"status": response["status"], "body": base64.b64encode(body_bytes).decode("ascii"),
                "headers": dict(headers), "receipt_id": receipt_id}

    def _parse_effect_request(self, uid: int, payload: Any) -> tuple[EffectAuthorization, HostContext, EffectRule]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect verification fields are invalid")
        grant = EffectAuthorization.from_wire(payload["authorization"])
        context = HostContext.from_wire(payload["context"])
        binding = self._binding(uid)
        self._verify_context_signature(context)
        self._verify_grant_signature(grant)
        self._assert_current_context(context, binding, uid)
        self._assert_grant_current(grant, binding, uid)
        if (grant.context_digest != _context_digest(context)
                or grant.capability != payload["capability"] or grant.target != payload["target"]
                or grant.recipient != payload["recipient"] or grant.request_digest != payload["request_digest"]
                or grant.retry_index != payload["retry_index"]):
            raise AuthorityDenied("effect.binding", "effect grant binding mismatch")
        rule = self.rules.get((grant.capability, grant.target))
        if rule is None or rule.recipient != grant.recipient:
            raise AuthorityDenied("effect.denied", "fixed effect target is not enrolled")
        if not self.policy.allow_effect(context=context, rule=rule,
                                        request_digest=grant.request_digest,
                                        retry_index=grant.retry_index):
            raise AuthorityDenied("effect.denied", "fresh host policy denied the fixed effect")
        return grant, context, rule

    def _assert_current_context(self, context: HostContext, binding: PrincipalBinding, uid: int) -> None:
        if (context.uid != uid or context.principal_id != binding.principal_id
                or context.profile_id != binding.profile_id or context.namespace_id != binding.namespace_id
                or context.monotonic_expires_at <= self.monotonic()
                or context.policy_revision != self._policy_revision()):
            raise AuthorityDenied("context.stale", "host context is stale or bound to another principal")

    def _assert_grant_current(self, grant: EffectAuthorization, binding: PrincipalBinding, uid: int) -> None:
        if (grant.uid != uid or grant.principal_id != binding.principal_id
                or grant.profile_id != binding.profile_id or grant.namespace_id != binding.namespace_id
                or grant.monotonic_expires_at <= self.monotonic()
                or grant.policy_revision != self._policy_revision()):
            raise AuthorityDenied("grant.stale", "effect grant is stale or bound to another principal")

    def _context_from_grant(self, grant: EffectAuthorization, binding: PrincipalBinding) -> HostContext:
        # Handler receives only claims already authenticated by this service.
        return HostContext(
            principal_id=binding.principal_id, profile_id=binding.profile_id,
            namespace_id=binding.namespace_id, uid=binding.uid,
            purpose=grant.purpose, intent_id=grant.intent_id,
            trace_id=grant.trace_id, sensitivity=grant.sensitivity,
            lineage_hash=grant.lineage_hash, policy_revision=grant.policy_revision,
            capabilities=binding.capabilities, issued_at_monotonic=grant.issued_at_monotonic,
            monotonic_expires_at=grant.monotonic_expires_at, nonce=grant.nonce,
            grant_id=grant.grant_id, signature="verified-in-service",
        )

    def _consume(self, grant: EffectAuthorization) -> None:
        with self._lock:
            now = self.monotonic()
            self._nonces = {nonce: expiry for nonce, expiry in self._nonces.items() if expiry > now}
            if grant.nonce in self._nonces:
                raise AuthorityDenied("grant.replay", "effect grant was already consumed")
            if len(self._nonces) >= 100_000:
                raise AuthorityDenied("grant.capacity", "effect replay protection is at capacity")
            self._nonces[grant.nonce] = grant.monotonic_expires_at

    def _verify_context_signature(self, context: HostContext) -> None:
        self._verify_signature(context.claims(), context.signature)

    def _verify_grant_signature(self, grant: EffectAuthorization) -> None:
        self._verify_signature(grant.claims(), grant.signature)

    def _verify_signature(self, claims: Mapping[str, Any], signature: str) -> None:
        unsigned = dict(claims)
        unsigned.pop("key_id", None)
        expected = self._sign(unsigned)
        if not hmac.compare_digest(expected, signature):
            raise AuthorityDenied("signature.invalid", "host authority signature is invalid")

    def _sign(self, claims: Mapping[str, Any]) -> str:
        envelope = {"key_id": self.key_id, **claims}
        data = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hmac.new(self._key, data, hashlib.sha256).hexdigest()

    def _policy_revision(self) -> str:
        revision = getattr(self.policy, "revision", None)
        return revision if isinstance(revision, str) and revision else "authority-default-deny"

    @staticmethod
    def _bounded(value: Any, maximum: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
            raise AuthorityDenied("request.bounds", "authority duration is invalid")
        return float(value)

    @staticmethod
    def _peer_credentials(connection: socket.socket) -> tuple[int, int]:
        if not hasattr(socket, "SO_PEERCRED"):
            raise AuthorityDenied("peer.unavailable", "kernel peer credentials are unavailable")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        pid, uid, _gid = struct.unpack("3i", raw)
        if pid <= 0 or uid <= 0:
            raise AuthorityDenied("peer.invalid", "root or invalid peer identity cannot request user authority")
        return pid, uid

    @staticmethod
    def _read_json_line(connection: socket.socket, maximum: int) -> Any:
        data = bytearray()
        while len(data) <= maximum:
            chunk = connection.recv(1)
            if not chunk:
                break
            if chunk == b"\n":
                try:
                    return json.loads(data.decode("ascii"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    raise AuthorityDenied("protocol.json", "authority request is malformed") from None
            data.extend(chunk)
        raise AuthorityDenied("protocol.bounds", "authority request is incomplete or oversized")

    @staticmethod
    def _write_json_line(connection: socket.socket, value: Mapping[str, Any], maximum: int) -> None:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if len(data) > maximum:
            raise AuthorityDenied("protocol.bounds", "authority response exceeds its bound")
        connection.sendall(data)

    @staticmethod
    def _peer_disconnected(connection: socket.socket) -> bool:
        try:
            readable, _, _ = select.select([connection], [], [], 0)
            if not readable:
                return False
            return connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT) == b""
        except (BlockingIOError, InterruptedError):
            return False
        except OSError:
            return True
