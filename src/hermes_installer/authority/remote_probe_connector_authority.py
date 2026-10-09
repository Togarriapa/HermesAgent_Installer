"""Root-private HI12 issuer for setup-time native Desktop probes.

Setup probes are deliberately separate from HI13 user sessions.  The opaque
probe handle is resolved by a root-owned transaction table on every call; no
caller supplies a profile, route, target, deadline, process identity, or policy
claim.  A fresh HI12 grant and a one-use local authorization are spent at the
connector's before-syscall boundary.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any, Callable

from .remote_connector_authority import AuthorityServiceHI12Adapter
from .types import AuthorityDenied

_OPS = {"connector.open", "connector.read", "connector.write", "connector.close"}
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_PAYLOAD = 1_500_000
_MAX_FRAME = 1024 * 1024


def _deny(code: str, message: str) -> AuthorityDenied:
    return AuthorityDenied(code, message)


@dataclass(frozen=True, slots=True)
class RootSetupProbeBinding:
    """Root transaction facts returned only by the protected handle resolver.

    ``resolve_binding`` must re-resolve the caller PIDFD and the enrolled
    gateway/native process identities and role proofs on every invocation.
    """

    probe_handle: str
    setup_transaction_handle: str
    setup_transaction_digest: str
    setup_actor_identity_digest: str
    probe_actor_identity_digest: str
    setup_profile_id: str
    setup_generation: str
    setup_enrollment_id: str
    setup_role_sha256: str
    probe_enrollment_id: str
    probe_profile_id: str
    probe_generation: str
    probe_role_sha256: str
    gateway_identity_digest: str
    gateway_profile_id: str
    gateway_generation: str
    gateway_enrollment_id: str
    native_identity_digest: str
    native_enrollment_id: str
    native_profile_id: str
    native_generation: str
    enrollment_id: str
    target_id: str
    connector_target_id: str
    approved_route_ids: tuple[str, ...]
    asset_ids: tuple[str, ...]
    selected_action: str
    selected_asset_id: str | None
    session_id: str
    next_sequence: int
    policy_revision: str
    policy_config_digest: str
    service_generation_digest: str
    principal_id: str
    issued_monotonic: float
    expires_monotonic: float
    frame_deadline_monotonic: float
    cancelled: Callable[[], bool] = field(repr=False, compare=False)
    schema: int = 1

    def __post_init__(self) -> None:
        ids = (self.setup_transaction_handle, self.setup_profile_id,
               self.setup_generation, self.setup_enrollment_id,
               self.probe_enrollment_id,
               self.probe_profile_id, self.probe_generation,
               self.gateway_profile_id, self.gateway_generation, self.gateway_enrollment_id,
               self.native_enrollment_id,
               self.native_profile_id, self.native_generation, self.enrollment_id,
               self.target_id, self.session_id, self.policy_revision, self.principal_id)
        if (self.schema != 1 or not _OPAQUE.fullmatch(self.probe_handle)
                or any(not isinstance(value, str) or not _ID.fullmatch(value) for value in ids)
                or any(not _DIGEST.fullmatch(value) for value in (
                    self.setup_transaction_digest, self.setup_actor_identity_digest,
                    self.probe_actor_identity_digest, self.setup_role_sha256,
                    self.probe_role_sha256,
                    self.gateway_identity_digest,
                    self.native_identity_digest, self.policy_config_digest,
                    self.service_generation_digest))
                or not self.approved_route_ids
                or any(not isinstance(route, str) or not _ID.fullmatch(route)
                       for route in self.approved_route_ids)
                or len(set(self.approved_route_ids)) != len(self.approved_route_ids)
                or self.target_id != "xpra-native" or self.connector_target_id != self.target_id
                or set(self.approved_route_ids) != {"xpra-http", "xpra-websocket"}
                or not self.asset_ids or any(not _DIGEST.fullmatch(asset) for asset in self.asset_ids)
                or len(set(self.asset_ids)) != len(self.asset_ids)
                or self.selected_action not in {"asset-get", "asset-head", "websocket-attach"}
                or ((self.selected_action == "websocket-attach") != (self.selected_asset_id is None))
                or (self.selected_asset_id is not None
                    and self.selected_asset_id not in self.asset_ids)
                or self.enrollment_id != self.native_enrollment_id
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or not math.isfinite(self.frame_deadline_monotonic)
                or type(self.next_sequence) is not int or self.next_sequence < 0
                or self.issued_monotonic < 0
                or self.expires_monotonic <= self.issued_monotonic
                or self.frame_deadline_monotonic <= 0
                or not callable(self.cancelled)):
            raise ValueError("root setup probe binding is invalid")


@dataclass(frozen=True, slots=True)
class InternalProbeConnectorAuthorization:
    """In-process opaque capability accepted only by the root probe backend."""

    probe_handle: str
    setup_transaction_handle: str
    setup_transaction_digest: str
    setup_actor_identity_digest: str
    probe_actor_identity_digest: str
    setup_profile_id: str
    setup_generation: str
    setup_enrollment_id: str
    setup_role_sha256: str
    probe_enrollment_id: str
    probe_profile_id: str
    probe_generation: str
    probe_role_sha256: str
    gateway_identity_digest: str
    gateway_profile_id: str
    gateway_generation: str
    gateway_enrollment_id: str
    native_identity_digest: str
    native_profile_id: str
    native_generation: str
    enrollment_id: str
    native_enrollment_id: str
    target_id: str
    connector_target_id: str
    selected_action: str
    selected_asset_id: str | None
    route_id: str
    session_id: str
    next_sequence: int
    operation: str
    canonical_payload_sha256: str
    sequence: int
    one_use_nonce: str = field(repr=False)
    issued_monotonic: float
    expires_monotonic: float
    policy_revision: str
    policy_config_digest: str
    service_generation_digest: str
    asset_ids: tuple[str, ...]
    principal_id: str
    schema: int = 1

    def __post_init__(self) -> None:
        if (self.schema != 1 or not _OPAQUE.fullmatch(self.probe_handle)
                or not _OPAQUE.fullmatch(self.one_use_nonce)
                or self.operation not in _OPS
                or any(not _DIGEST.fullmatch(value) for value in (
                    self.setup_transaction_digest, self.setup_actor_identity_digest,
                    self.probe_actor_identity_digest, self.setup_role_sha256,
                    self.probe_role_sha256,
                    self.gateway_identity_digest,
                    self.native_identity_digest, self.canonical_payload_sha256,
                    self.policy_config_digest, self.service_generation_digest))
                or any(not isinstance(value, str) or not _ID.fullmatch(value) for value in (
                    self.setup_transaction_handle, self.setup_profile_id, self.setup_generation,
                    self.setup_enrollment_id, self.probe_enrollment_id, self.probe_profile_id,
                    self.probe_generation, self.gateway_profile_id, self.gateway_generation,
                    self.gateway_enrollment_id, self.native_profile_id, self.native_generation,
                    self.enrollment_id, self.native_enrollment_id, self.target_id,
                    self.connector_target_id, self.route_id, self.session_id,
                    self.policy_revision, self.principal_id))
                or self.target_id != "xpra-native" or self.connector_target_id != self.target_id
                or self.enrollment_id != self.native_enrollment_id
                or not self.asset_ids or any(not _DIGEST.fullmatch(value) for value in self.asset_ids)
                or type(self.next_sequence) is not int or self.next_sequence < 0
                or type(self.sequence) is not int or self.sequence < 0
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic):
            raise ValueError("internal setup probe authorization is invalid")


@dataclass(frozen=True, slots=True)
class _Issued:
    authorization: InternalProbeConnectorAuthorization
    binding_fingerprint: tuple[Any, ...]
    hi12_grant: Any = field(repr=False, compare=False)


class SetupProbeConnectorAuthority:
    """Issue and atomically consume setup-only fixed Xpra connector effects."""

    def __init__(self, *, resolve_binding: Callable[[str, int, int, int], RootSetupProbeBinding],
                 hi12: AuthorityServiceHI12Adapter, boot_epoch: Callable[[], str],
                 advance_sequence: Callable[[str, int, str, str, int, int, int], bool],
                 monotonic: Callable[[], float] = time.monotonic):
        if (not callable(resolve_binding)
                or not callable(getattr(hi12, "issue_remote_connector_effect", None))
                or not callable(getattr(hi12, "consume_remote_connector_effect", None))
                or not callable(boot_epoch)
                or not callable(advance_sequence)
                or not callable(monotonic)):
            raise ValueError("root setup resolver and HI12 issuer/consumer are required")
        if getattr(hi12, "_capability", None) != "hermes-service-connect":
            raise ValueError("setup probes require the fixed hermes-service-connect capability")
        self._resolve = resolve_binding
        self._hi12 = hi12
        self._boot_epoch = boot_epoch
        self._advance_sequence = advance_sequence
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._issued: dict[str, _Issued] = {}

    def issue_probe_connector_effect(self, root_probe_handle: str, operation: str,
                                     canonical_payload_bytes: bytes, sequence: int, *,
                                     peer_uid: int, peer_pid: int,
                                     peer_pidfd: int) -> InternalProbeConnectorAuthorization:
        binding = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd)
        route_id, deadline = self._validate_effect(binding, operation,
                                                    canonical_payload_bytes, sequence)
        now = self._monotonic()
        if deadline <= now:
            raise _deny("remote.probe-expired", "setup probe deadline has expired")
        hi12_binding = self._hi12_binding(binding, operation, deadline, route_id)
        grant = self._hi12.issue_remote_connector_effect(
            binding=hi12_binding, operation=operation,
            canonical_payload=canonical_payload_bytes, sequence=sequence,
            deadline=deadline, boot_epoch=self._boot_epoch())
        nonce = secrets.token_urlsafe(32)
        auth = InternalProbeConnectorAuthorization(
            probe_handle=binding.probe_handle,
            setup_transaction_handle=binding.setup_transaction_handle,
            setup_transaction_digest=binding.setup_transaction_digest,
            setup_actor_identity_digest=binding.setup_actor_identity_digest,
            probe_actor_identity_digest=binding.probe_actor_identity_digest,
            setup_profile_id=binding.setup_profile_id,
            setup_generation=binding.setup_generation,
            setup_enrollment_id=binding.setup_enrollment_id,
            setup_role_sha256=binding.setup_role_sha256,
            probe_enrollment_id=binding.probe_enrollment_id,
            probe_profile_id=binding.probe_profile_id,
            probe_generation=binding.probe_generation,
            probe_role_sha256=binding.probe_role_sha256,
            gateway_identity_digest=binding.gateway_identity_digest,
            gateway_profile_id=binding.gateway_profile_id,
            gateway_generation=binding.gateway_generation,
            gateway_enrollment_id=binding.gateway_enrollment_id,
            native_identity_digest=binding.native_identity_digest,
            native_profile_id=binding.native_profile_id,
            native_generation=binding.native_generation,
            enrollment_id=binding.enrollment_id, target_id=binding.target_id,
            connector_target_id=binding.connector_target_id,
            selected_action=binding.selected_action,
            selected_asset_id=binding.selected_asset_id,
            native_enrollment_id=binding.native_enrollment_id,
            route_id=route_id, session_id=binding.session_id,
            next_sequence=binding.next_sequence, operation=operation,
            canonical_payload_sha256=hashlib.sha256(canonical_payload_bytes).hexdigest(),
            sequence=sequence, one_use_nonce=nonce, issued_monotonic=now,
            expires_monotonic=deadline, policy_revision=binding.policy_revision,
            policy_config_digest=binding.policy_config_digest,
            service_generation_digest=binding.service_generation_digest,
            asset_ids=binding.asset_ids, principal_id=binding.principal_id)
        with self._lock:
            self._prune_expired_locked(now)
            if len(self._issued) >= 4096:
                raise _deny("remote.probe-capacity", "root setup probe grant table is full")
            # A same-handle transaction may issue multiple distinct sequence
            # grants; no nonce is accepted twice and every consume re-resolves.
            self._issued[nonce] = _Issued(auth, self._fingerprint(binding), grant)
        return auth

    def consume_probe_connector_effect(self, authorization: InternalProbeConnectorAuthorization,
                                       root_probe_handle: str, operation: str,
                                       canonical_payload_bytes: bytes, sequence: int, *,
                                       peer_uid: int, peer_pid: int,
                                       peer_pidfd: int) -> bool:
        if (not isinstance(authorization, InternalProbeConnectorAuthorization)
                or not isinstance(canonical_payload_bytes, bytes)
                or operation not in _OPS or type(sequence) is not int):
            raise _deny("remote.probe-consume", "probe connector authorization is malformed")
        binding = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd)
        route_id, deadline = self._validate_effect(binding, operation,
                                                    canonical_payload_bytes, sequence)
        expected_digest = hashlib.sha256(canonical_payload_bytes).hexdigest()
        if (authorization.probe_handle != root_probe_handle
                or authorization.operation != operation
                or authorization.sequence != sequence
                or authorization.route_id != route_id
                or authorization.expires_monotonic != deadline
                or authorization.expires_monotonic <= self._monotonic()
                or not hmac.compare_digest(authorization.canonical_payload_sha256, expected_digest)):
            raise _deny("remote.probe-binding", "probe grant is stale or differently bound")
        with self._lock:
            issued = self._issued.pop(authorization.one_use_nonce, None)
            if (issued is None or issued.authorization != authorization
                    or issued.binding_fingerprint != self._fingerprint(binding)):
                raise _deny("remote.probe-replay", "probe grant is spent or bound to another setup")
        hi12_binding = self._hi12_binding(binding, operation, deadline, route_id)
        accepted = self._hi12.consume_remote_connector_effect(
            issued.hi12_grant, binding=hi12_binding, operation=operation,
            canonical_payload=canonical_payload_bytes, sequence=sequence,
            boot_epoch=self._boot_epoch())
        if accepted is not True:
            raise _deny("remote.probe-hi12", "protected HI12 denied the setup connector effect")
        return True

    def advance_probe_connector_sequence(self, root_probe_handle: str,
                                         expected_sequence: int, operation: str,
                                         connector_handle: str, *, peer_uid: int,
                                         peer_pid: int, peer_pidfd: int) -> bool:
        """CAS the root probe state after a complete successful socket effect.

        The connector backend calls this only after the full syscall effect
        completes. The callback must atomically bind the handle on open, require
        the same handle thereafter, and advance expected_sequence exactly once.
        On effect failure or CAS failure, the caller must cancel/close the probe.
        """
        binding = self._current(root_probe_handle, peer_uid, peer_pid, peer_pidfd)
        if (operation not in _OPS or type(expected_sequence) is not int
                or expected_sequence != binding.next_sequence
                or (operation == "connector.open" and expected_sequence != 0)
                or not isinstance(connector_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", connector_handle)):
            raise _deny("remote.probe-sequence", "probe connector sequence or handle is stale")
        try:
            accepted = self._advance_sequence(root_probe_handle, expected_sequence,
                                              operation, connector_handle,
                                              peer_uid, peer_pid, peer_pidfd)
        except Exception:
            raise _deny("remote.probe-sequence", "root probe sequence transition failed") from None
        if accepted is not True:
            raise _deny("remote.probe-sequence", "root probe sequence transition was stale")
        return True

    def _current(self, handle: str, uid: int, pid: int, pidfd: int) -> RootSetupProbeBinding:
        if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                or any(type(value) is not int or value <= 0 for value in (uid, pid, pidfd))):
            raise _deny("remote.probe-peer", "root probe handle or peer identity is invalid")
        try:
            binding = self._resolve(handle, uid, pid, pidfd)
        except Exception:
            raise _deny("remote.probe-stale", "current root setup transaction or PIDFD proof is unavailable") from None
        if (not isinstance(binding, RootSetupProbeBinding)
                or binding.probe_handle != handle
                or binding.issued_monotonic > self._monotonic()
                or binding.expires_monotonic <= self._monotonic()):
            raise _deny("remote.probe-stale", "root setup probe is absent, expired, or mismatched")
        try:
            cancelled = binding.cancelled()
        except Exception:
            cancelled = True
        if cancelled:
            raise _deny("remote.probe-cancelled", "setup transaction was cancelled")
        return binding

    def _prune_expired_locked(self, now: float) -> None:
        for nonce, item in tuple(self._issued.items()):
            if item.authorization.expires_monotonic <= now:
                del self._issued[nonce]

    @staticmethod
    def _validate_effect(binding: RootSetupProbeBinding, operation: str,
                         payload: bytes, sequence: int) -> tuple[str, float]:
        if (operation not in _OPS or not isinstance(payload, bytes) or not payload
                or len(payload) > _MAX_PAYLOAD or type(sequence) is not int or sequence < 0):
            raise _deny("remote.probe-input", "setup connector effect is malformed")
        try:
            body = json.loads(payload)
            if json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii") != payload or not isinstance(body, dict):
                raise ValueError
        except (ValueError, UnicodeError, TypeError):
            raise _deny("remote.probe-payload", "setup connector payload is not canonical JSON") from None
        if operation == "connector.open":
            expected = {"schema": 1, "enrollment_id": binding.native_enrollment_id,
                        "generation": binding.native_generation, "target_id": binding.target_id,
                        "action": "open", "approved_route_id": body.get("approved_route_id"),
                        "session_id": binding.session_id, "deadline": binding.expires_monotonic}
            route = expected["approved_route_id"]
            expected_route = ("xpra-websocket" if binding.selected_action == "websocket-attach"
                              else "xpra-http")
            if (sequence != binding.next_sequence
                    or set(body) != set(expected) or body != expected or route not in binding.approved_route_ids
                    or route != expected_route
                or sequence != 0):
                raise _deny("remote.probe-payload", "probe open is outside the enrolled route")
            deadline = binding.expires_monotonic
        else:
            required = {"schema", "target_id", "route_id", "connector_id", "session_id",
                        "generation", "deadline", "sequence"}
            expected = {"schema": 1, "target_id": binding.target_id,
                        "session_id": binding.session_id, "generation": binding.native_generation,
                        "deadline": binding.frame_deadline_monotonic, "sequence": sequence}
            if operation in {"connector.read", "connector.write"}:
                required.add("max_bytes" if operation == "connector.read" else "data_b64")
            route = body.get("route_id")
            if (sequence != binding.next_sequence
                    or set(body) != required or any(body.get(key) != value for key, value in expected.items())
                    or route not in binding.approved_route_ids
                    or route != ("xpra-websocket" if binding.selected_action == "websocket-attach"
                                 else "xpra-http")
                    or not isinstance(body.get("connector_id"), str)
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", body["connector_id"])):
                raise _deny("remote.probe-payload", "probe frame differs from the root connector binding")
            if operation == "connector.read" and (type(body["max_bytes"]) is not int or not 1 <= body["max_bytes"] <= _MAX_FRAME):
                raise _deny("remote.probe-payload", "probe read bound is invalid")
            if operation == "connector.write":
                try:
                    data = base64.b64decode(body["data_b64"], validate=True)
                except Exception:
                    raise _deny("remote.probe-payload", "probe write frame is invalid") from None
                if len(data) > _MAX_FRAME:
                    raise _deny("remote.probe-payload", "probe write exceeds frame limit")
            deadline = binding.frame_deadline_monotonic
        if not math.isfinite(deadline):
            raise _deny("remote.probe-expired", "probe deadline is invalid")
        if (deadline <= binding.issued_monotonic or deadline > binding.expires_monotonic
                or deadline - binding.issued_monotonic > 60.0):
            raise _deny("remote.probe-expired", "probe effect deadline exceeds its root lease")
        return route, deadline

    @staticmethod
    def _hi12_binding(binding: RootSetupProbeBinding, operation: str,
                      deadline: float, route_id: str) -> Any:
        # This private value is assembled solely from the validated root record;
        # no worker or RPC input can select any of its fields.
        return SimpleNamespace(
            native_profile_id=binding.native_profile_id,
            native_generation=binding.native_generation,
            service_generation_digest=binding.service_generation_digest,
            target_id=binding.target_id, session_id=binding.session_id,
            lease_expires_monotonic=binding.expires_monotonic,
            frame_deadline_monotonic=deadline if operation != "connector.open" else binding.expires_monotonic,
            route_id=route_id)

    @staticmethod
    def _fingerprint(binding: RootSetupProbeBinding) -> tuple[Any, ...]:
        return (binding.probe_handle, binding.setup_transaction_handle,
                binding.setup_transaction_digest, binding.setup_actor_identity_digest,
                binding.probe_actor_identity_digest, binding.setup_profile_id,
                binding.setup_generation, binding.setup_enrollment_id, binding.setup_role_sha256,
                binding.probe_enrollment_id,
                binding.probe_profile_id, binding.probe_generation,
                binding.probe_role_sha256, binding.gateway_identity_digest,
                binding.gateway_profile_id,
                binding.gateway_generation, binding.gateway_enrollment_id,
                binding.native_identity_digest,
                binding.native_enrollment_id, binding.native_profile_id,
                binding.native_generation, binding.enrollment_id,
                binding.target_id, binding.approved_route_ids, binding.session_id,
                binding.next_sequence,
                binding.connector_target_id, binding.asset_ids,
                binding.selected_action, binding.selected_asset_id,
                binding.policy_revision, binding.policy_config_digest,
                binding.service_generation_digest, binding.expires_monotonic,
                binding.frame_deadline_monotonic)
