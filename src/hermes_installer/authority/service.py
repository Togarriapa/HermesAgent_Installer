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
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from .types import (
    AuthorityDenied, BrokeredEffectResponse, EffectAuthorization, HostContext, Sensitivity, SourceReceipt,
    canonical_digest,
)

MAX_REQUEST = 4 * 1024 * 1024 + 16_384
MAX_RESPONSE = 4 * 1024 * 1024 + 32_768
MAX_CONTEXT_LEASE = 600.0
MAX_EFFECT_LEASE = 30.0
_EFFECT_LEASE_BY_OPERATION = {
    "artifact.fetch": 120.0,
    "package.install": 600.0,
    "process.start": 30.0,
}
_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete",
    "memory.extract", "memory.embed", "memory.backup", "memory.restore",
    "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "process.start", "process.status",
    "process.read", "process.write", "process.stop", "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.orchestrator.recruit",
    "source.capture",
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


@dataclass(frozen=True, slots=True)
class ChildDelegationRule:
    """One fixed root-only parent action to one fixed child effect."""

    delegation_id: str
    parent_profile_id: str
    parent_capability: str
    parent_operation: str
    parent_target: str
    child_profile_id: str
    child_capability: str
    child_operation: str
    child_target: str
    child_recipient: str | None
    child_purpose: str

    def __post_init__(self) -> None:
        if (not self.delegation_id or not self.parent_profile_id or not self.parent_capability
                or not self.parent_operation or not self.parent_target or not self.child_profile_id
                or not self.child_capability or not self.child_operation or not self.child_target
                or not self.child_purpose):
            raise ValueError("child delegation binding is incomplete")


@dataclass(frozen=True, slots=True)
class BackgroundConsent:
    """Root-signed durable provenance permission, distinct from an effect grant."""

    claims: Mapping[str, Any]
    signature: str

    def to_wire(self) -> dict[str, Any]:
        return {**dict(self.claims), "signature": self.signature}


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
                 peer_pidfd: int | None,
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
                 wall_clock: Callable[[], float] = time.time,
                 profile_generations: Mapping[str, str] | None = None,
                 background_consent_active: Callable[[str], bool] | None = None,
                 delegations: Mapping[str, ChildDelegationRule] | None = None):
        if len(signing_key) < 32 or not key_id:
            raise ValueError("authority signing key must be protected and at least 256 bits")
        if not bindings_by_uid or any(uid != binding.uid for uid, binding in bindings_by_uid.items()):
            raise ValueError("UID map must be an explicit protected identity mapping")
        profile_ids = [binding.profile_id for binding in bindings_by_uid.values()]
        if len(profile_ids) != len(set(profile_ids)):
            raise ValueError("each managed profile must map to exactly one host principal UID")
        if any(key != (rule.capability, rule.target) for key, rule in rules.items()):
            raise ValueError("effect rule map keys must match their protected rule bindings")
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
        self.profile_generations = dict(profile_generations or {})
        self.delegations = dict(delegations or {})
        if any(key != rule.delegation_id for key, rule in self.delegations.items()):
            raise ValueError("delegation map keys must match fixed enrollment IDs")
        self._delegated_parents: set[str] = set()
        # Queue adapters must supply a durable root-owned revocation lookup.
        self.background_consent_active = background_consent_active or (lambda _consent_id: False)
        self.memory_owner_state: Callable[[str], tuple[str | None, int]] | None = None
        self._nonces: dict[str, float] = {}
        # Receipts are provenance evidence, not reusable bearer permissions.
        # Consumption is atomic with the one-use effect nonce below.
        self._source_receipts_consumed: dict[str, float] = {}
        self._source_receipt_handles: dict[str, SourceReceipt] = {}
        self._lock = threading.RLock()
        self._client_nonces: dict[str, float] = {}

    def perform_delegated_effect(self, parent_authorization: EffectAuthorization, *,
                                 delegation_id: str, payload: bytes, peer_pid: int,
                                 timeout: float, cancelled: Callable[[], bool]) -> BrokeredEffectResponse:
        """Root-handler-only child effect with fresh child identity and one-use grant.

        This is deliberately not an RPC operation. Only an installed trusted
        effect handler can call it after validating its selected resource/action.
        """
        rule = self.delegations.get(delegation_id)
        if rule is None or not isinstance(parent_authorization, EffectAuthorization):
            raise AuthorityDenied("delegation.unavailable", "fixed delegation is not enrolled")
        parent_binding = self._binding(parent_authorization.uid)
        self._verify_grant_signature(parent_authorization)
        self._assert_grant_current(parent_authorization, parent_binding, parent_authorization.uid)
        parent_effect_rule = self.rules.get((parent_authorization.capability, parent_authorization.target))
        with self._lock:
            consumed = parent_authorization.nonce in self._nonces
            already_delegated = parent_authorization.grant_id in self._delegated_parents
            if consumed and not already_delegated and len(self._delegated_parents) < 100_000:
                self._delegated_parents.add(parent_authorization.grant_id)
        if (not consumed or already_delegated
                or len(self._delegated_parents) >= 100_000
                or parent_binding.profile_id != rule.parent_profile_id
                or parent_authorization.capability != rule.parent_capability
                or parent_effect_rule is None
                or parent_effect_rule.operation != rule.parent_operation
                or parent_effect_rule.target != rule.parent_target
                or parent_effect_rule.recipient != parent_authorization.recipient
                or not self.policy.allow_effect(
                    context=self._context_from_grant(parent_authorization, parent_binding),
                    rule=parent_effect_rule, request_digest=parent_authorization.request_digest,
                    retry_index=parent_authorization.retry_index)):
            raise AuthorityDenied("delegation.denied", "parent effect cannot delegate this child action")
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_REQUEST:
            raise AuthorityDenied("delegation.payload", "child effect payload is outside bounds")
        # All parent claims and child identity come from verified signed records;
        # no caller may select a child principal, UID, namespace or capability.
        child_binding = next((item for item in self.bindings_by_uid.values()
                              if item.profile_id == rule.child_profile_id), None)
        child_effect_rule = self.rules.get((rule.child_capability, rule.child_target))
        if (child_binding is None or rule.child_capability not in child_binding.capabilities
                or child_effect_rule is None or child_effect_rule.operation != rule.child_operation
                or child_effect_rule.recipient != rule.child_recipient
                or (child_effect_rule.operation, child_effect_rule.target) not in self.handlers):
            raise AuthorityDenied("delegation.target", "delegated child target is not enrolled")
        try:
            decoded = json.loads(payload.decode("utf-8"))
            if json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                          allow_nan=False).encode("utf-8") != payload:
                raise ValueError
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            raise AuthorityDenied("delegation.payload", "child effect payload must be canonical JSON") from None
        now = self.monotonic()
        expiry = min(parent_authorization.monotonic_expires_at, now + 30.0)
        if expiry <= now or timeout <= 0:
            raise AuthorityDenied("delegation.expired", "parent effect lease has expired")
        payload_digest = canonical_digest(payload)
        context = HostContext(
            principal_id=child_binding.principal_id, profile_id=child_binding.profile_id,
            namespace_id=child_binding.namespace_id, uid=child_binding.uid,
            purpose=rule.child_purpose,
            intent_id=canonical_digest({"delegation": delegation_id,
                                        "parent_intent": parent_authorization.intent_id,
                                        "payload_digest": payload_digest}),
            trace_id=parent_authorization.trace_id,
            sensitivity=parent_authorization.sensitivity,
            lineage_hash=canonical_digest({"parent_lineage": parent_authorization.lineage_hash,
                                           "parent_grant": parent_authorization.grant_id,
                                           "delegation": delegation_id,
                                           "payload_digest": payload_digest}),
            policy_revision=self._policy_revision(), capabilities=child_binding.capabilities,
            issued_at_monotonic=now, monotonic_expires_at=expiry,
            nonce=secrets.token_urlsafe(24), grant_id=secrets.token_urlsafe(24), signature="pending",
            source_receipts=parent_authorization.source_receipts,
            final_payload_digest=payload_digest,
            enrollment_id=canonical_digest({"uid": child_binding.uid,
                                            "principal_id": child_binding.principal_id,
                                            "profile_id": child_binding.profile_id,
                                            "namespace_id": child_binding.namespace_id,
                                            "generation": self.profile_generations.get(child_binding.profile_id, "unversioned")}),
            generation=self.profile_generations.get(child_binding.profile_id, "unversioned"),
            operation=rule.child_operation,
            native_process_identity=parent_authorization.native_process_identity)
        child_context = HostContext.from_wire(self._signed_context(context, self._sign(context.claims())))
        grant_wire = self._authorize_effect(child_binding.uid, {
            "context": child_context.to_wire(), "capability": rule.child_capability,
            "target": rule.child_target, "recipient": rule.child_recipient,
            "request_digest": payload_digest, "retry_index": 0,
        })
        grant = EffectAuthorization.from_wire(grant_wire)
        bounded_timeout = self._bounded(timeout, 30.0)
        effective_timeout = min(bounded_timeout, expiry - self.monotonic())
        if effective_timeout <= 0:
            raise AuthorityDenied("delegation.expired", "child effect lease expired before dispatch")
        response = self._perform_effect(child_binding.uid, peer_pid, {
            "authorization": grant.to_wire(), "operation": rule.child_operation,
            "payload": __import__("base64").b64encode(payload).decode("ascii"),
            "timeout": effective_timeout,
        }, cancelled=lambda: cancelled() or self.monotonic() >= expiry)
        import base64
        return BrokeredEffectResponse(response["status"], base64.b64decode(response["body"], validate=True),
                                      response["headers"], response["receipt_id"])

    def issue_source_receipt(self, parent_context: HostContext, *, source_kind: str,
                             origin_id: str, payload: bytes,
                             ttl_seconds: int = 300) -> SourceReceipt:
        """Mint private provenance only from a trusted in-process source adapter.

        This is deliberately absent from the worker RPC verb set. A registered
        root adapter calls it only after capturing the exact source bytes. No
        caller-provided sensitivity or public declassification is accepted.
        """
        if (not isinstance(parent_context, HostContext) or not isinstance(payload, bytes)
                or not 1 <= len(payload) <= MAX_REQUEST or type(ttl_seconds) is not int
                or not 1 <= ttl_seconds <= 600
                or not parent_context.native_process_identity):
            raise AuthorityDenied("source.request", "trusted source receipt request is malformed")
        if source_kind not in {"native-input", "tool-result", "memory-record", "static-context",
                               "schedule-event", "webhook-event", "provider-result"}:
            raise AuthorityDenied("source.kind", "source kind is not enrolled in the host adapter")
        if not isinstance(origin_id, str) or not 1 <= len(origin_id) <= 256:
            raise AuthorityDenied("source.origin", "source origin is invalid")
        binding = self._binding(parent_context.uid)
        self._verify_context_signature(parent_context)
        self._assert_current_context(parent_context, binding, parent_context.uid)
        now = self.monotonic()
        expiry = min(parent_context.monotonic_expires_at, now + ttl_seconds)
        if expiry <= now:
            raise AuthorityDenied("source.expired", "source context expired before receipt issuance")
        receipt = SourceReceipt(
            receipt_id=secrets.token_urlsafe(24), issuer_id="host-authority",
            source_kind=source_kind, principal_id=binding.principal_id,
            profile_id=binding.profile_id, namespace_id=binding.namespace_id, uid=binding.uid,
            origin_id=origin_id, process_generation=self.profile_generations.get(binding.profile_id, "unversioned"),
            payload_digest=canonical_digest(payload),
            sensitivity=max((Sensitivity.PRIVATE, parent_context.sensitivity),
                            key=lambda value: list(Sensitivity).index(value)),
            parent_lineage_hash=parent_context.lineage_hash,
            policy_revision=self._policy_revision(), recipient_ceiling=frozenset(),
            issued_at_monotonic=now, monotonic_expires_at=expiry, signature="pending",
            enrollment_id=parent_context.enrollment_id or canonical_digest({
                "uid": binding.uid, "principal_id": binding.principal_id,
                "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
                "generation": self.profile_generations.get(binding.profile_id, "unversioned"),
            }),
            native_process_identity=parent_context.native_process_identity,
            parent_receipt_ids=tuple(sorted(item.receipt_id for item in parent_context.source_receipts)),
            nonce=secrets.token_urlsafe(24),
        )
        return replace(receipt, signature=self._sign(receipt.claims()))

    def _capture_source(self, uid: int, peer_pid: int, payload: Any) -> dict[str, str]:
        """Hash exact bytes observed on the protected socket; the host assigns all source claims."""
        if not isinstance(payload, dict) or set(payload) != {
                "schema", "payload", "parent_receipt_handles"}:
            raise AuthorityDenied("source.request", "source capture fields are invalid")
        handles = payload["parent_receipt_handles"]
        if (type(payload["schema"]) is not int or payload["schema"] != 1
                or not isinstance(handles, list) or len(handles) > 64
                or any(not isinstance(value, str) or not value for value in handles)):
            raise AuthorityDenied("source.request", "source capture schema or parent handles are invalid")
        import base64
        try:
            source_bytes = base64.b64decode(payload["payload"], validate=True)
        except Exception:
            raise AuthorityDenied("source.request", "source capture bytes are malformed") from None
        if not 1 <= len(source_bytes) <= 1_048_576:
            raise AuthorityDenied("source.request", "source capture exceeds its fixed byte limit")
        digest = canonical_digest(source_bytes)
        parent_context = HostContext.from_wire(self._issue_context(uid, {
            "purpose": "native-source-capture", "intent": f"native-capture:{digest}",
            "trace_id": secrets.token_urlsafe(24), "lease_seconds": 60.0,
            "source_contexts": [], "source_receipt_handles": handles,
            "final_payload_digest": digest, "operation": "source.capture",
        }, peer_pid=peer_pid))
        receipt = self.issue_source_receipt(
            parent_context, source_kind="native-input",
            origin_id=f"native-event:{secrets.token_urlsafe(24)}",
            payload=source_bytes, ttl_seconds=300)
        handle = secrets.token_urlsafe(40)
        with self._lock:
            now = self.monotonic()
            self._source_receipt_handles = {
                key: value for key, value in self._source_receipt_handles.items()
                if value.monotonic_expires_at > now
            }
            if len(self._source_receipt_handles) >= 100_000:
                raise AuthorityDenied("source.capacity", "source handle store is at capacity")
            self._source_receipt_handles[handle] = receipt
        return {"receipt_handle": handle}

    def revalidate_effect(self, context: HostContext, authorization: EffectAuthorization, *,
                          operation: str, request_digest: str,
                          retry_index: int) -> bool:
        """Fresh non-consuming check for a handler's final pre-effect boundary."""
        if (not isinstance(context, HostContext)
                or not isinstance(authorization, EffectAuthorization)
                or not isinstance(operation, str)
                or not isinstance(request_digest, str)
                or not isinstance(retry_index, int) or isinstance(retry_index, bool)):
            raise AuthorityDenied("effect.revalidation", "effect revalidation binding is malformed")
        binding = self._binding(context.uid)
        self._verify_grant_signature(authorization)
        self._assert_grant_current(authorization, binding, context.uid)
        expected = self._context_from_grant(authorization, binding)
        if any(getattr(context, field) != getattr(expected, field) for field in (
                "principal_id", "profile_id", "namespace_id", "uid", "purpose", "intent_id",
                "trace_id", "sensitivity", "lineage_hash", "policy_revision", "capabilities",
                "monotonic_expires_at", "source_receipts", "final_payload_digest", "enrollment_id",
                "generation", "operation", "native_process_identity")):
            raise AuthorityDenied("effect.revalidation", "handler context differs from the signed grant")
        rule = self.rules.get((authorization.capability, authorization.target))
        if (rule is None or rule.operation != operation
                or authorization.operation != operation
                or authorization.source_receipts != context.source_receipts
                or authorization.request_digest != request_digest
                or authorization.retry_index != retry_index
                or any(rule.recipient is not None and rule.recipient not in receipt.recipient_ceiling
                       for receipt in context.source_receipts)
                or not self.policy.allow_effect(context=context, rule=rule,
                                                request_digest=request_digest,
                                                retry_index=retry_index)):
            raise AuthorityDenied("effect.revalidation", "fresh host policy denied the final effect boundary")
        return True

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
        peer_pidfd: int | None = None
        try:
            connection.settimeout(MAX_CONTEXT_LEASE + 25.0)
            peer_pid, uid = self._peer_credentials(connection)
            if not hasattr(os, "pidfd_open"):
                raise AuthorityDenied("peer.pidfd", "kernel parent-death handle is unavailable")
            try:
                # Pin the SO_PEERCRED process identity before parsing attacker-
                # controlled RPC bytes or scheduling any handler work.
                peer_pidfd = os.pidfd_open(peer_pid, 0)
            except OSError:
                raise AuthorityDenied("peer.pidfd", "kernel peer exited before authority dispatch") from None
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
            result = self._dispatch(uid, peer_pid, peer_pidfd, request["operation"], request["payload"],
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
        finally:
            if peer_pidfd is not None:
                os.close(peer_pidfd)

    def _dispatch(self, uid: int, peer_pid: int, peer_pidfd: int | None,
                  operation: Any, payload: Any,
                  *, cancelled: Callable[[], bool]) -> Any:
        if operation == "issue_context":
            if isinstance(payload, dict) and "source_receipts" in payload:
                raise AuthorityDenied("source.handle", "workers must resolve opaque source receipt handles")
            return self._issue_context(uid, payload, peer_pid=peer_pid)
        if operation == "capture_source":
            return self._capture_source(uid, peer_pid, payload)
        if operation == "authorize_effect":
            return self._authorize_effect(uid, payload, peer_pid=peer_pid)
        if operation == "verify_effect":
            return self._verify_effect(uid, payload, peer_pid=peer_pid)
        if operation == "perform_effect":
            return self._perform_effect(uid, peer_pid, payload, cancelled=cancelled,
                                        peer_pidfd=peer_pidfd)
        raise AuthorityDenied("protocol.operation", "authority operation is unavailable")

    def _binding(self, uid: int) -> PrincipalBinding:
        binding = self.bindings_by_uid.get(uid)
        if binding is None:
            raise AuthorityDenied("principal.unenrolled", "kernel peer UID has no enrolled profile")
        return binding

    def _issue_context(self, uid: int, payload: Any, *, allow_expired_sources: bool = False,
                       peer_pid: int | None = None,
                       inherited_process_identity: str | None = None) -> dict[str, Any]:
        required = {"purpose", "intent", "trace_id", "lease_seconds", "source_contexts"}
        optional = {"source_receipts", "source_receipt_handles", "final_payload_digest", "operation"}
        if (not isinstance(payload, dict) or not required.issubset(payload)
                or set(payload) - required - optional):
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
        raw_receipts = payload.get("source_receipts", [])
        raw_handles = payload.get("source_receipt_handles", [])
        if not isinstance(raw_receipts, list) or len(raw_receipts) > 64:
            raise AuthorityDenied("context.lineage", "source receipts are malformed or mixed with context lineage")
        if (not isinstance(raw_handles, list) or len(raw_handles) > 64
                or raw_receipts and raw_handles):
            raise AuthorityDenied("context.lineage", "source receipt handles are malformed")
        parsed_receipts = [SourceReceipt.from_wire(item) for item in raw_receipts]
        now = self.monotonic()
        for source in sources:
            self._verify_context_signature(source)
            if (source.uid != uid or source.profile_id != binding.profile_id
                    or source.principal_id != binding.principal_id
                    or source.namespace_id != binding.namespace_id
                    or (not allow_expired_sources and source.monotonic_expires_at <= now)
                    or source.policy_revision != self._policy_revision()):
                raise AuthorityDenied("context.lineage", "source context belongs to another principal")
            parsed_receipts.extend(source.source_receipts)
        if raw_handles:
            if peer_pid is None:
                raise AuthorityDenied("source.handle", "source handles require an authenticated native peer")
            current_identity = self._native_process_identity(peer_pid, uid)
            now_for_handles = self.monotonic()
            with self._lock:
                self._source_receipt_handles = {
                    handle: receipt for handle, receipt in self._source_receipt_handles.items()
                    if receipt.monotonic_expires_at > now_for_handles
                }
                resolved: list[SourceReceipt] = []
                for handle in raw_handles:
                    receipt = self._source_receipt_handles.get(handle) if isinstance(handle, str) else None
                    if (receipt is None or receipt.uid != uid
                            or receipt.native_process_identity != current_identity):
                        raise AuthorityDenied("source.handle", "source receipt handle is unknown or bound to another peer")
                    resolved.append(receipt)
            parsed_receipts.extend(resolved)
        if len(parsed_receipts) > 64:
            raise AuthorityDenied("context.lineage", "complete source receipt closure exceeds its bound")
        receipts = tuple({receipt.receipt_id: receipt for receipt in parsed_receipts}.values())
        if len(receipts) != len(parsed_receipts):
            # Repeated references are accepted only if they name identical
            # immutable signed evidence; conflicting copies are rejected.
            for receipt in parsed_receipts:
                if receipt != next(item for item in receipts if item.receipt_id == receipt.receipt_id):
                    raise AuthorityDenied("context.lineage", "source receipt identifier has conflicting claims")
        receipt_ids = {receipt.receipt_id for receipt in receipts}
        if any(not set(receipt.parent_receipt_ids).issubset(receipt_ids) for receipt in receipts):
            raise AuthorityDenied("context.lineage", "source receipt parent closure is incomplete")
        for receipt in receipts:
            self._verify_source_receipt(receipt, binding, allow_expired=allow_expired_sources)
        trace_id = payload["trace_id"] or secrets.token_urlsafe(24)
        if not isinstance(trace_id, str) or not 1 <= len(trace_id) <= 128:
            raise AuthorityDenied("context.request", "trace ID is invalid")
        final_payload_digest = payload.get("final_payload_digest")
        if final_payload_digest is not None and (not isinstance(final_payload_digest, str)
                                                 or len(final_payload_digest) != 64
                                                 or any(char not in "0123456789abcdef" for char in final_payload_digest)):
            raise AuthorityDenied("context.request", "final payload digest is invalid")
        if receipts and final_payload_digest is None:
            raise AuthorityDenied("context.lineage", "source receipts require a final payload digest")
        operation = payload.get("operation")
        if operation not in _OPERATIONS:
            raise AuthorityDenied("context.operation", "context operation is not a fixed host effect")
        generation = self.profile_generations.get(binding.profile_id, "unversioned")
        enrollment_id = canonical_digest({"uid": uid, "principal_id": binding.principal_id,
                                           "profile_id": binding.profile_id,
                                           "namespace_id": binding.namespace_id,
                                           "generation": generation})
        native_process_identity = inherited_process_identity
        if peer_pid is not None:
            native_process_identity = self._native_process_identity(peer_pid, uid)
        if receipts and (not native_process_identity or any(
                receipt.native_process_identity != native_process_identity for receipt in receipts)):
            raise AuthorityDenied("context.lineage", "source receipt is bound to another native process")
        if sources and (not native_process_identity or any(
                source.native_process_identity != native_process_identity for source in sources)):
            raise AuthorityDenied("context.lineage", "source context is bound to another native process")
        sensitivity, lineage_hash = self.policy.classify(
            purpose=purpose, intent=intent, source_contexts=sources, binding=binding)
        if receipts:
            order = (Sensitivity.PUBLIC, Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN)
            # A root-issued receipt may refine an otherwise empty UNKNOWN
            # source set, but can never lower sensitivity or public-clear it.
            receipt_sensitivity = max((item.sensitivity for item in receipts), key=order.index)
            sensitivity = max((sensitivity, receipt_sensitivity), key=order.index)
            lineage_hash = canonical_digest({
                "base": lineage_hash,
                "receipts": sorted((item.receipt_id, canonical_digest(item.claims())) for item in receipts),
                "parents": sorted(item.parent_lineage_hash for item in receipts),
            })
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
            source_receipts=receipts, final_payload_digest=final_payload_digest,
            enrollment_id=enrollment_id, generation=generation, operation=operation,
            native_process_identity=native_process_identity,
        )
        signature = self._sign(context.claims())
        return HostContext(**{**context.__dict__, "signature": signature}).to_wire() if hasattr(context, "__dict__") else self._signed_context(context, signature)

    def create_background_consent(self, context: HostContext, *, provider_id: str,
                                  owner_generation: int, ttl_seconds: int = 300) -> BackgroundConsent:
        """Issue source-bound consent for fixed automatic memory stages.

        Intended only for the root-owned memory enqueue handler. The user
        facing worker cannot call this method over the authority RPC protocol.
        """
        if not isinstance(context, HostContext):
            raise AuthorityDenied("memory.consent", "a host-issued context is required")
        binding = self._binding(context.uid)
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, context.uid)
        if (not isinstance(provider_id, str) or not provider_id
                or type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 86_400):
            raise AuthorityDenied("memory.consent", "memory consent binding or lifetime is invalid")
        owner_state = self.memory_owner_state
        if (owner_state is None or type(owner_generation) is not int or owner_generation < 1
                or owner_state(context.profile_id) != (provider_id, owner_generation)
                or self.rules.get(("memory-capture", f"memory:{provider_id}:enqueue")) is None):
            raise AuthorityDenied("memory.consent", "memory provider generation or enqueue target is not enrolled")
        enqueue_rule = self.rules[("memory-capture", f"memory:{provider_id}:enqueue")]
        if (enqueue_rule.operation, enqueue_rule.target) not in self.handlers:
            raise AuthorityDenied("memory.consent", "root memory enqueue handler is unavailable")
        consent_digest = canonical_digest({"context": _context_digest(context), "provider": provider_id,
                                           "owner_generation": owner_generation})
        if ("memory-capture" not in context.capabilities
                or not self.policy.allow_effect(context=context, rule=enqueue_rule,
                                                request_digest=consent_digest, retry_index=0)):
            raise AuthorityDenied("memory.consent", "fresh memory capture policy denied enqueue")
        now = self.wall_clock()
        claims = {
            "kind": "memory-background-consent-v1", "consent_id": secrets.token_urlsafe(24),
            "source_context_digest": _context_digest(context),
            "principal_id": context.principal_id, "profile_id": context.profile_id,
            "namespace_id": context.namespace_id, "uid": context.uid,
            "provider_id": provider_id, "owner_generation": owner_generation,
            "policy_revision": self._policy_revision(),
            "allowed_actions": ["extract", "embed", "capture"],
            "issued_at_unix": now, "expires_at_unix": now + ttl_seconds,
        }
        return BackgroundConsent(claims, self._sign(claims))

    def context_for_job(self, source_context_wire: bytes | Mapping[str, Any],
                        consent_wire: bytes | Mapping[str, Any], *, provider_id: str,
                        owner_generation: int, action: str, trace_id: str | None = None,
                        lease_seconds: float = 30.0,
                        final_payload_digest: str | None = None) -> HostContext:
        """Reissue a fresh short context from valid persisted source consent."""
        source = self._decode_wire(source_context_wire, "source context")
        consent = self._decode_wire(consent_wire, "background consent")
        if not isinstance(source, dict) or not isinstance(consent, dict):
            raise AuthorityDenied("memory.consent", "source or consent record is malformed")
        signature = consent.pop("signature", None)
        expected = {"kind", "consent_id", "source_context_digest", "principal_id", "profile_id",
                    "namespace_id", "uid", "provider_id", "owner_generation", "policy_revision",
                    "allowed_actions", "issued_at_unix", "expires_at_unix"}
        if set(consent) != expected or not isinstance(signature, str):
            raise AuthorityDenied("memory.consent", "background consent schema is invalid")
        self._verify_signature(consent, signature)
        source_context = HostContext.from_wire(source)
        self._verify_context_signature(source_context)
        now_wall = self.wall_clock()
        if (consent["kind"] != "memory-background-consent-v1"
                or consent["source_context_digest"] != _context_digest(source_context)
                or consent["principal_id"] != source_context.principal_id
                or consent["profile_id"] != source_context.profile_id
                or consent["namespace_id"] != source_context.namespace_id
                or consent["uid"] != source_context.uid
                or consent["provider_id"] != provider_id
                or consent["owner_generation"] != owner_generation
                or consent["policy_revision"] != self._policy_revision()
                or type(consent["owner_generation"]) is not int
                or action not in consent["allowed_actions"]
                or type(consent["issued_at_unix"]) not in (int, float)
                or type(consent["expires_at_unix"]) not in (int, float)
                or consent["expires_at_unix"] <= now_wall
                or consent["issued_at_unix"] > now_wall
                or consent["expires_at_unix"] - consent["issued_at_unix"] > 86_400
                or not self.background_consent_active(consent["consent_id"])):
            raise AuthorityDenied("memory.consent", "background consent is expired, revoked or differently bound")
        binding = self._binding(source_context.uid)
        if (binding.profile_id != source_context.profile_id
                or binding.principal_id != source_context.principal_id
                or binding.namespace_id != source_context.namespace_id
                or self.memory_owner_state is None
                or self.memory_owner_state(binding.profile_id) != (provider_id, owner_generation)):
            raise AuthorityDenied("memory.consent", "background owner identity or generation changed")
        if source_context.policy_revision != self._policy_revision():
            raise AuthorityDenied("memory.consent", "source policy revision is stale")
        intent = f"memory:{provider_id}:{action}:{source_context.lineage_hash}"
        wire = self._issue_context(source_context.uid, {
            "purpose": f"memory-{action}", "intent": intent, "trace_id": trace_id,
            "lease_seconds": lease_seconds, "source_contexts": [source_context.to_wire()],
            "final_payload_digest": final_payload_digest,
            "operation": f"memory.{action}",
        }, allow_expired_sources=True,
           inherited_process_identity=source_context.native_process_identity)
        return HostContext.from_wire(wire)

    def perform_memory_effect(self, source_context_wire: bytes | Mapping[str, Any],
                              consent_wire: bytes | Mapping[str, Any], *, provider_id: str,
                              owner_generation: int, action: str, capability: str,
                              payload: bytes,
                              trace_id: str | None = None, timeout: float = 30.0,
                              cancelled: Callable[[], bool] = lambda: False) -> Any:
        """Run one memory stage with a fresh context, authorization and broker dispatch."""
        capabilities = {"extract": "memory-extraction", "embed": "memory-embedding",
                        "capture": "memory-capture"}
        expected_capability = capabilities.get(action)
        if expected_capability is None or capability != expected_capability or not isinstance(payload, bytes):
            raise AuthorityDenied("memory.effect", "memory stage or canonical payload is invalid")
        context = self.context_for_job(source_context_wire, consent_wire, provider_id=provider_id,
                                       owner_generation=owner_generation, action=action,
                                       trace_id=trace_id, final_payload_digest=canonical_digest(payload))
        target = f"memory:{provider_id}:{action}"
        digest = canonical_digest(payload)
        authorization = self._authorize_effect(context.uid, {
            "context": context.to_wire(), "capability": capability, "target": target,
            "recipient": None, "request_digest": digest, "retry_index": 0,
        })
        consent_value = self._decode_wire(consent_wire, "background consent")
        consent_id = consent_value.get("consent_id") if isinstance(consent_value, dict) else None
        if not isinstance(consent_id, str):
            raise AuthorityDenied("memory.consent", "background consent identifier is missing")
        def effect_cancelled() -> bool:
            owner_current = (self.memory_owner_state is not None
                             and self.memory_owner_state(context.profile_id) == (provider_id, owner_generation))
            return cancelled() or not owner_current or not self.background_consent_active(consent_id)
        result = self._perform_effect(context.uid, os.getpid(), {
            "authorization": authorization, "operation": f"memory.{action}",
            "payload": __import__("base64").b64encode(payload).decode("ascii"),
            "timeout": timeout,
        }, cancelled=effect_cancelled, enforce_peer_identity=False)
        import base64
        return BrokeredEffectResponse(result["status"], base64.b64decode(result["body"], validate=True),
                                      result["headers"], result["receipt_id"])

    @staticmethod
    def _decode_wire(value: bytes | Mapping[str, Any], label: str) -> Any:
        if isinstance(value, Mapping):
            return dict(value)
        if not isinstance(value, bytes) or len(value) > 262_144:
            raise AuthorityDenied("memory.consent", f"{label} exceeds its wire bound")
        try:
            return json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorityDenied("memory.consent", f"{label} is malformed") from None

    def _signed_context(self, context: HostContext, signature: str) -> dict[str, Any]:
        fields = context.claims()
        fields["signature"] = signature
        return fields

    def _authorize_effect(self, uid: int, payload: Any, *, peer_pid: int | None = None) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect request fields are invalid")
        binding = self._binding(uid)
        context = HostContext.from_wire(payload["context"])
        self._verify_context_signature(context)
        self._assert_current_context(context, binding, uid, peer_pid=peer_pid)
        capability, target, recipient = payload["capability"], payload["target"], payload["recipient"]
        request_digest, retry_index = payload["request_digest"], payload["retry_index"]
        if (not isinstance(capability, str) or not isinstance(target, str)
                or recipient is not None and not isinstance(recipient, str)
                or not isinstance(request_digest, str) or len(request_digest) != 64
                or type(retry_index) is not int or not 0 <= retry_index <= 100):
            raise AuthorityDenied("effect.request", "effect binding is invalid")
        rule = self.rules.get((capability, target))
        if (rule is None or (rule.operation, rule.target) not in self.handlers
                or rule.recipient != recipient
                or context.operation != rule.operation
                or context.final_payload_digest != request_digest
                or any(recipient is not None and recipient not in receipt.recipient_ceiling
                       for receipt in context.source_receipts)
                or not self.policy.allow_effect(context=context, rule=rule,
                                                request_digest=request_digest, retry_index=retry_index)):
            raise AuthorityDenied("effect.denied", "host policy denied this exact effect")
        if capability not in context.capabilities:
            raise AuthorityDenied("effect.denied", "profile has no enrolled capability for this effect")
        now = self.monotonic()
        effect_lease = _EFFECT_LEASE_BY_OPERATION.get(rule.operation, MAX_EFFECT_LEASE)
        expiry = min(context.monotonic_expires_at, now + effect_lease)
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
            signature="pending", source_receipts=context.source_receipts,
            final_payload_digest=context.final_payload_digest,
            enrollment_id=context.enrollment_id, generation=context.generation,
            operation=rule.operation, native_process_identity=context.native_process_identity,
        )
        signed = self._sign(grant.claims())
        return {**grant.claims(), "signature": signed}

    def _verify_effect(self, uid: int, payload: Any, *, peer_pid: int | None = None) -> dict[str, Any]:
        grant, context, rule = self._parse_effect_request(uid, payload, peer_pid=peer_pid)
        return {"operation": rule.operation, "verified_at_monotonic": self.monotonic(),
                "verification_receipt": secrets.token_urlsafe(24)}

    def _perform_effect(self, uid: int, peer_pid: int, payload: Any,
                        *, cancelled: Callable[[], bool],
                        peer_pidfd: int | None = None,
                        enforce_peer_identity: bool = True) -> dict[str, Any]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "operation", "payload", "timeout"}:
            raise AuthorityDenied("effect.request", "broker request fields are invalid")
        import base64
        try:
            body = base64.b64decode(payload["payload"], validate=True)
        except Exception:
            raise AuthorityDenied("effect.request", "broker payload is malformed") from None
        timeout = self._bounded(payload["timeout"], MAX_CONTEXT_LEASE)
        grant = EffectAuthorization.from_wire(payload["authorization"])
        binding = self._binding(uid)
        self._verify_grant_signature(grant)
        self._assert_grant_current(grant, binding, uid)
        if canonical_digest(body) != grant.request_digest:
            raise AuthorityDenied("effect.binding", "broker payload digest mismatch")
        rule = self.rules.get((grant.capability, grant.target))
        if (rule is None or rule.operation != payload["operation"]
                or rule.recipient != grant.recipient
                or grant.operation != payload["operation"]
                or grant.final_payload_digest != grant.request_digest):
            raise AuthorityDenied("effect.binding", "fixed effect operation does not match protected target")
        context = self._context_from_grant(grant, binding)
        if (enforce_peer_identity
                and context.native_process_identity != self._native_process_identity(peer_pid, uid)):
            raise AuthorityDenied("peer.process", "effect grant belongs to a different native process")
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
        def current_or_cancelled() -> bool:
            if cancellation():
                return True
            try:
                self.revalidate_effect(context, grant, operation=rule.operation,
                                       request_digest=grant.request_digest,
                                       retry_index=grant.retry_index)
                return False
            except AuthorityDenied:
                return True
        response = handler(context=context, authorization=grant,
                           payload=body, timeout=remaining,
                           peer_pid=peer_pid,
                           peer_pidfd=peer_pidfd,
                           cancelled=current_or_cancelled)
        if current_or_cancelled():
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

    def _parse_effect_request(self, uid: int, payload: Any, *, peer_pid: int | None = None
                              ) -> tuple[EffectAuthorization, HostContext, EffectRule]:
        if not isinstance(payload, dict) or set(payload) != {"authorization", "context", "capability", "target", "recipient", "request_digest", "retry_index"}:
            raise AuthorityDenied("effect.request", "effect verification fields are invalid")
        grant = EffectAuthorization.from_wire(payload["authorization"])
        context = HostContext.from_wire(payload["context"])
        binding = self._binding(uid)
        self._verify_context_signature(context)
        self._verify_grant_signature(grant)
        self._assert_current_context(context, binding, uid, peer_pid=peer_pid)
        self._assert_grant_current(grant, binding, uid)
        if (grant.context_digest != _context_digest(context)
                or grant.source_receipts != context.source_receipts
                or grant.final_payload_digest != context.final_payload_digest
                or grant.operation != context.operation
                or context.final_payload_digest != grant.request_digest
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

    def _assert_current_context(self, context: HostContext, binding: PrincipalBinding, uid: int, *,
                                peer_pid: int | None = None) -> None:
        expected_generation = self.profile_generations.get(binding.profile_id, "unversioned")
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": expected_generation,
        })
        if (context.uid != uid or context.principal_id != binding.principal_id
                or context.profile_id != binding.profile_id or context.namespace_id != binding.namespace_id
                or context.monotonic_expires_at <= self.monotonic()
                or context.policy_revision != self._policy_revision()
                or context.generation != expected_generation
                or context.enrollment_id != expected_enrollment):
            raise AuthorityDenied("context.stale", "host context is stale or bound to another principal")
        if (peer_pid is not None
                and context.native_process_identity != self._native_process_identity(peer_pid, uid)):
            raise AuthorityDenied("context.process", "host context is bound to another native process")
        for receipt in context.source_receipts:
            self._verify_source_receipt(receipt, binding)

    def _assert_grant_current(self, grant: EffectAuthorization, binding: PrincipalBinding, uid: int) -> None:
        expected_generation = self.profile_generations.get(binding.profile_id, "unversioned")
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": expected_generation,
        })
        if (grant.uid != uid or grant.principal_id != binding.principal_id
                or grant.profile_id != binding.profile_id or grant.namespace_id != binding.namespace_id
                or grant.monotonic_expires_at <= self.monotonic()
                or grant.policy_revision != self._policy_revision()
                or grant.generation != expected_generation
                or grant.enrollment_id != expected_enrollment):
            raise AuthorityDenied("grant.stale", "effect grant is stale or bound to another principal")
        for receipt in grant.source_receipts:
            self._verify_source_receipt(receipt, binding)

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
            source_receipts=grant.source_receipts,
            final_payload_digest=grant.final_payload_digest,
            enrollment_id=grant.enrollment_id, generation=grant.generation,
            operation=grant.operation, native_process_identity=grant.native_process_identity,
        )

    def _consume(self, grant: EffectAuthorization) -> None:
        with self._lock:
            now = self.monotonic()
            self._nonces = {nonce: expiry for nonce, expiry in self._nonces.items() if expiry > now}
            self._source_receipts_consumed = {
                receipt_id: expiry for receipt_id, expiry in self._source_receipts_consumed.items()
                if expiry > now
            }
            if grant.nonce in self._nonces:
                raise AuthorityDenied("grant.replay", "effect grant was already consumed")
            receipt_ids = {receipt.receipt_id for receipt in grant.source_receipts}
            if receipt_ids & self._source_receipts_consumed.keys():
                raise AuthorityDenied("source.replay", "source receipt was already used by another effect")
            if len(self._nonces) >= 100_000 or len(self._source_receipts_consumed) + len(receipt_ids) > 100_000:
                raise AuthorityDenied("grant.capacity", "effect replay protection is at capacity")
            self._nonces[grant.nonce] = grant.monotonic_expires_at
            for receipt in grant.source_receipts:
                self._source_receipts_consumed[receipt.receipt_id] = receipt.monotonic_expires_at

    def _verify_context_signature(self, context: HostContext) -> None:
        self._verify_signature(context.claims(), context.signature)

    def _verify_source_receipt(self, receipt: SourceReceipt, binding: PrincipalBinding,
                               *, allow_expired: bool = False) -> None:
        self._verify_signature(receipt.claims(), receipt.signature)
        expected_enrollment = canonical_digest({
            "uid": binding.uid, "principal_id": binding.principal_id,
            "profile_id": binding.profile_id, "namespace_id": binding.namespace_id,
            "generation": self.profile_generations.get(binding.profile_id, "unversioned"),
        })
        if (receipt.issuer_id != "host-authority"
                or receipt.uid != binding.uid
                or receipt.principal_id != binding.principal_id
                or receipt.profile_id != binding.profile_id
                or receipt.namespace_id != binding.namespace_id
                or receipt.process_generation != self.profile_generations.get(binding.profile_id, "unversioned")
                or receipt.enrollment_id != expected_enrollment
                or not receipt.native_process_identity
                or receipt.nonce == ""
                or receipt.policy_revision != self._policy_revision()
                or receipt.sensitivity not in {Sensitivity.PRIVATE, Sensitivity.CONFIDENTIAL, Sensitivity.UNKNOWN}
                or not allow_expired and receipt.monotonic_expires_at <= self.monotonic()):
            raise AuthorityDenied("source.lineage", "source receipt is stale or bound to another host identity")

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
    def _native_process_identity(peer_pid: int, peer_uid: int) -> str:
        """Hash kernel-observed executable inode and start time for a pinned PID."""
        try:
            stat_text = Path(f"/proc/{peer_pid}/stat").read_text(encoding="ascii")
            right = stat_text.rfind(")")
            fields = stat_text[right + 2:].split()
            # After the parenthesized comm, field 22 (starttime) is offset 19.
            start_ticks = fields[19]
            status = Path(f"/proc/{peer_pid}/status").read_text(encoding="ascii")
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            real_uid = int(uid_line.split()[1])
            executable = os.stat(f"/proc/{peer_pid}/exe")
            if right < 0 or real_uid != peer_uid or not start_ticks.isdigit():
                raise ValueError("peer process identity mismatch")
            identity_hash = canonical_digest({
                "pid": peer_pid, "uid": real_uid, "start_ticks": start_ticks,
                "exe_device": executable.st_dev, "exe_inode": executable.st_ino,
            })
            return f"linux-proc:{identity_hash}"
        except (OSError, ValueError, StopIteration, IndexError):
            raise AuthorityDenied("peer.process", "kernel peer process identity is unavailable") from None

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
