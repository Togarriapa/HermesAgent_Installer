"""Root-only issuer and one-use consumer for HI13 remote connector effects.

The public gateway peer remains the controller.  The selected native Desktop
profile is the effective principal whose enrolled HI12 connector capability is
used.  This module accepts only root-derived HI13 bindings and rechecks the
registered gateway, protected role proof, live enrollment and session on both
issuance and consumption.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from .remote_sessions import (
    InternalRemoteConnectorAuthorization,
    RemoteConnectorBinding,
    RemoteGatewayIdentity,
    RemoteRuntimeState,
)
from .types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest


_OPS = {"connector.open", "connector.read", "connector.write", "connector.close"}
_ID_FIELDS = ("session_id", "target_id", "route_id", "native_generation")
_HI12_DEADLINE_MARGIN_SECONDS = 0.05


def _deny(code: str, message: str) -> AuthorityDenied:
    return AuthorityDenied(code, message)


@dataclass(frozen=True, slots=True)
class GatewayRoleProof:
    """Fresh inspector output for the enrolled gateway role and entrypoint."""

    enrollment_id: str
    profile_id: str
    generation: str
    executable_sha256: str
    role_artifact_id: str
    role_sha256: str
    entrypoint_artifact_id: str
    entrypoint_sha256: str
    boot_epoch: str
    observed_monotonic: float
    expires_monotonic: float


class HI12RemoteEffectAuthority(Protocol):
    """Protected HI12 connector grant interface; implementation owns nonce spend."""

    def issue_remote_connector_effect(self, *, binding: RemoteConnectorBinding,
                                      operation: str, canonical_payload: bytes,
                                      sequence: int, deadline: float,
                                      boot_epoch: str) -> Any: ...

    def consume_remote_connector_effect(self, grant: Any, *, binding: RemoteConnectorBinding,
                                        operation: str, canonical_payload: bytes,
                                        sequence: int, boot_epoch: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class _HI12Grant:
    """Unexported HI12 records retained between issue and atomic consume."""

    context: HostContext = field(repr=False)
    authorization: EffectAuthorization = field(repr=False)
    service_epoch: str = field(repr=False)
    boot_epoch: str = field(repr=False)
    profile_uid: int


class AuthorityServiceHI12Adapter:
    """Mint and atomically spend HI12 connector grants through root service APIs.

    This adapter intentionally uses AuthorityService's private context, rule,
    signature and replay methods. It selects the single root-bound native
    service UID by profile/generation and delegates policy/rule verification to
    the installed AuthorityService; it does not construct a caller HostContext.
    """

    def __init__(self, service: Any, *, boot_epoch: Callable[[], str],
                 service_generation_digest: Callable[[], str],
                 resolve_selected_native_principal: Callable[[str, str, str], Any],
                 capability: str = "hermes-service-connect",
                 monotonic: Callable[[], float] = time.monotonic):
        if (not callable(boot_epoch) or not callable(service_generation_digest)
                or not callable(resolve_selected_native_principal)
                or not callable(getattr(service, "_issue_context", None))
                or not callable(getattr(service, "_authorize_effect", None))
                or not callable(getattr(service, "_consume", None))):
            raise ValueError("root AuthorityService HI12 APIs and active registry readers are required")
        if not isinstance(capability, str) or not capability:
            raise ValueError("fixed HI12 connector capability is required")
        self._service = service
        self._boot_epoch = boot_epoch
        self._generation_digest = service_generation_digest
        self._resolve_native_principal = resolve_selected_native_principal
        self._capability = capability
        self._monotonic = monotonic

    def issue_remote_connector_effect(self, *, binding: RemoteConnectorBinding,
                                      operation: str, canonical_payload: bytes,
                                      sequence: int, deadline: float,
                                      boot_epoch: str) -> _HI12Grant:
        uid = self._profile_uid(binding.native_profile_id, binding.native_generation)
        service = self._service
        now = self._monotonic()
        if (boot_epoch != self._boot_epoch()
                or binding.service_generation_digest != self._generation_digest()
                or not math.isfinite(deadline) or deadline <= now):
            raise _deny("remote.connector-hi12-stale", "root service generation or boot epoch changed")
        rule = self._rule(operation, binding.target_id)
        payload_digest = canonical_digest(canonical_payload)
        context_lease = min(deadline - now - _HI12_DEADLINE_MARGIN_SECONDS, 5.0)
        if context_lease <= 0:
            raise _deny("remote.connector-hi12-stale", "connector deadline is too close for a fresh grant")
        context_wire = service._issue_context(uid, {
            "purpose": "remote-desktop-connector",
            "intent": f"{binding.session_id}:{operation}:{sequence}",
            "trace_id": binding.session_id,
            "lease_seconds": context_lease,
            "source_contexts": [], "final_payload_digest": payload_digest,
            "operation": operation,
        })
        context = HostContext.from_wire(context_wire)
        grant_wire = service._authorize_effect(uid, {
            "context": context.to_wire(), "capability": rule.capability,
            "target": rule.target, "recipient": rule.recipient,
            "request_digest": payload_digest, "retry_index": 0,
        })
        grant = EffectAuthorization.from_wire(grant_wire)
        if (grant.operation != operation or grant.target != binding.target_id
                or grant.request_digest != payload_digest
                or grant.final_payload_digest != payload_digest
                or grant.profile_id != binding.native_profile_id
                or grant.generation != binding.native_generation
                or grant.monotonic_expires_at > deadline):
            raise _deny("remote.connector-hi12", "AuthorityService issued a differently bound connector grant")
        return _HI12Grant(context, grant, service.authority_epoch, boot_epoch, uid)

    def consume_remote_connector_effect(self, grant: _HI12Grant, *,
                                        binding: RemoteConnectorBinding,
                                        operation: str, canonical_payload: bytes,
                                        sequence: int, boot_epoch: str) -> bool:
        if not isinstance(grant, _HI12Grant):
            raise _deny("remote.connector-hi12", "HI12 grant is not root-issued")
        service = self._service
        context, authorization = grant.context, grant.authorization
        payload_digest = canonical_digest(canonical_payload)
        if (grant.service_epoch != service.authority_epoch
                or grant.boot_epoch != boot_epoch or boot_epoch != self._boot_epoch()
                or binding.service_generation_digest != self._generation_digest()
                or authorization.operation != operation
                or authorization.target != binding.target_id
                or authorization.request_digest != payload_digest
                or authorization.final_payload_digest != payload_digest
                or authorization.monotonic_expires_at <= self._monotonic()
                or authorization.monotonic_expires_at > min(
                    binding.lease_expires_monotonic,
                    binding.frame_deadline_monotonic if operation != "connector.open"
                    else binding.lease_expires_monotonic)):
            raise _deny("remote.connector-hi12", "HI12 grant is stale or bound to another connector effect")
        uid = self._profile_uid(binding.native_profile_id, binding.native_generation)
        if uid != grant.profile_uid:
            raise _deny("remote.connector-hi12", "native service UID changed after connector issuance")
        identity_binding = service._binding(uid)
        service._verify_context_signature(context)
        service._assert_current_context(context, identity_binding, uid)
        service._verify_grant_signature(authorization)
        service._assert_grant_current(authorization, identity_binding, uid)
        rule = self._rule(operation, binding.target_id)
        if (authorization.capability != rule.capability
                or authorization.recipient != rule.recipient
                or not service.policy.allow_effect(
                    context=context, rule=rule, request_digest=payload_digest,
                    retry_index=authorization.retry_index)):
            raise _deny("remote.connector-hi12", "current HI12 policy denied the connector effect")
        # Atomic one-use spend in the root replay table. FixedServiceConnector
        # invokes this callback at its before_io boundary, directly before the
        # actual namespace socket syscall.
        service._consume(authorization)
        return True

    def _profile_uid(self, profile_id: str, generation: str) -> int:
        service = self._service
        try:
            binding = self._resolve_native_principal(
                profile_id, generation, self._generation_digest())
            if (type(getattr(binding, "uid", None)) is not int
                    or binding.uid <= 0 or binding.profile_id != profile_id
                    or service.profile_generations.get(profile_id, "unversioned") != generation
                    or service._binding(binding.uid) != binding):
                raise ValueError("catalog/service PrincipalBinding mismatch")
        except Exception:
            raise _deny("remote.connector-profile", "selected native PrincipalBinding is not current") from None
        return binding.uid

    def _rule(self, operation: str, target: str) -> Any:
        service = self._service
        rules = [rule for rule in service.rules.values()
                 if rule.capability == self._capability
                 and rule.operation == operation and rule.target == target]
        if (len(rules) != 1 or (operation, target) not in service.handlers):
            raise _deny("remote.connector-rule", "exact HI12 connector rule or effect handler is not enrolled")
        return rules[0]


@dataclass(frozen=True, slots=True)
class _Issued:
    authorization: InternalRemoteConnectorAuthorization
    binding_fingerprint: str
    hi12_grant: Any = field(repr=False, compare=False)


class RemoteConnectorEffectAuthority:
    """Concrete HI13 root issuer/consumer suitable for RemoteSessionAuthority.

    `runtime_state` reads the current protected registry snapshot; `gateway`
    resolves SO_PEERCRED/PIDFD to the stable process record; `role_proof`
    verifies immutable role and installed entrypoint artifacts; and
    `session_current` delegates to the HI13 session table's live lease/revoke
    check. These callbacks must be root-owned adapters, never worker values.
    """

    def __init__(self, *, runtime_state: Callable[[], RemoteRuntimeState],
                 enrollment: Any, boot_epoch: Callable[[], str],
                 gateway_entrypoint_artifact_id: str,
                 gateway_entrypoint_sha256: str,
                 gateway: Callable[[int, int, int], RemoteGatewayIdentity],
                 role_proof: Callable[[RemoteGatewayIdentity], GatewayRoleProof],
                 session_current: Callable[[RemoteConnectorBinding, str, int], bool],
                 hi12: HI12RemoteEffectAuthority,
                 monotonic: Callable[[], float] = time.monotonic):
        if not all(callable(x) for x in (runtime_state, boot_epoch, gateway,
                                         role_proof, session_current, monotonic)):
            raise ValueError("remote connector authority requires root-owned live inspectors")
        if (not callable(getattr(hi12, "issue_remote_connector_effect", None))
                or not callable(getattr(hi12, "consume_remote_connector_effect", None))):
            raise ValueError("protected HI12 connector issuer and consumer are required")
        self._runtime_state = runtime_state
        self._enrollment = enrollment
        self._boot_epoch = boot_epoch
        self._entrypoint_artifact_id = gateway_entrypoint_artifact_id
        self._entrypoint_sha256 = gateway_entrypoint_sha256
        self._gateway = gateway
        self._role_proof = role_proof
        self._session_current = session_current
        self._hi12 = hi12
        self._monotonic = monotonic
        self._lock = threading.RLock()
        self._issued: dict[str, _Issued] = {}
        self._revoked_sessions: set[str] = set()

    def issue_remote_connector_effect(self, binding: RemoteConnectorBinding,
                                      operation: str, canonical_payload: bytes,
                                      sequence: int, maximum_bytes: int = 0, *,
                                      peer_uid: int | None = None, peer_pid: int | None = None,
                                      peer_pidfd: int | None = None,
                                      cleanup: bool = False) -> InternalRemoteConnectorAuthorization:
        if cleanup:
            raise _deny("remote.connector-cleanup", "cleanup cannot issue a byte-capable authorization")
        if (not isinstance(binding, RemoteConnectorBinding) or operation not in _OPS
                or not isinstance(canonical_payload, bytes) or not canonical_payload
                or len(canonical_payload) > 1_500_000 or type(sequence) is not int or sequence < 0
                or type(maximum_bytes) is not int or maximum_bytes < 0
                or any(type(x) is not int or x <= 0 for x in (peer_uid, peer_pid, peer_pidfd))):
            raise _deny("remote.connector-input", "connector effect request is malformed")
        self._assert_live(binding, operation, sequence, peer_uid, peer_pid, peer_pidfd)
        body = self._canonical_body(canonical_payload)
        self._assert_payload(binding, operation, body, sequence, maximum_bytes)
        state = self._runtime_state()
        now = self._monotonic()
        deadline = min(binding.lease_expires_monotonic,
                       binding.frame_deadline_monotonic if operation != "connector.open"
                       else binding.lease_expires_monotonic)
        if not math.isfinite(deadline) or deadline <= now:
            raise _deny("remote.connector-expired", "remote connector lease is expired")
        try:
            hi12_grant = self._hi12.issue_remote_connector_effect(
                binding=binding, operation=operation, canonical_payload=canonical_payload,
                sequence=sequence, deadline=deadline, boot_epoch=self._boot_epoch())
        except AuthorityDenied:
            raise
        except Exception:
            raise _deny("remote.connector-hi12", "protected connector capability is unavailable") from None
        nonce = secrets.token_urlsafe(32)
        authorization = InternalRemoteConnectorAuthorization(
            effective_principal_id=binding.principal_id,
            effective_native_profile_id=binding.native_profile_id,
            effective_native_generation=binding.native_generation,
            controller_gateway_identity_digest=binding.gateway_identity.identity_digest,
            controller_gateway_generation=binding.gateway_generation,
            remote_session_id=binding.session_id,
            token_fingerprint=binding.token_fingerprint,
            policy_revision=binding.policy_revision,
            policy_config_digest=binding.policy_config_digest,
            connector_target_id=binding.target_id,
            route_id=binding.route_id,
            operation=operation,
            canonical_payload_sha256=hashlib.sha256(canonical_payload).hexdigest(),
            sequence=sequence, one_use_nonce=nonce,
            issued_monotonic=now, expires_monotonic=deadline,
            service_generation_digest=state.service_generation_digest,
        )
        fingerprint = self._binding_fingerprint(binding)
        with self._lock:
            if binding.session_id in self._revoked_sessions:
                raise _deny("remote.connector-revoked", "remote session has been revoked")
            self._issued[nonce] = _Issued(authorization, fingerprint, hi12_grant)
        return authorization

    def consume_remote_connector_effect(self, authorization: InternalRemoteConnectorAuthorization,
                                        binding: RemoteConnectorBinding, operation: str,
                                        canonical_payload: bytes, sequence: int, *,
                                        peer_uid: int, peer_pid: int, peer_pidfd: int) -> bool:
        if (not isinstance(authorization, InternalRemoteConnectorAuthorization)
                or not isinstance(canonical_payload, bytes) or operation not in _OPS
                or type(sequence) is not int):
            raise _deny("remote.connector-consume", "connector authorization is malformed")
        # Recheck before spending, then atomically remove the nonce before the
        # actual socket adapter performs any byte effect.
        self._assert_live(binding, operation, sequence, peer_uid, peer_pid, peer_pidfd)
        expected_digest = hashlib.sha256(canonical_payload).hexdigest()
        if (authorization.operation != operation or authorization.sequence != sequence
                or not hmac.compare_digest(authorization.canonical_payload_sha256, expected_digest)
                or authorization.expires_monotonic <= self._monotonic()):
            raise _deny("remote.connector-binding", "connector authorization does not match this effect")
        with self._lock:
            issued = self._issued.pop(authorization.one_use_nonce, None)
            if (issued is None or issued.authorization != authorization
                    or issued.binding_fingerprint != self._binding_fingerprint(binding)
                    or binding.session_id in self._revoked_sessions):
                raise _deny("remote.connector-replay", "connector authorization is spent, revoked, or mismatched")
        try:
            accepted = self._hi12.consume_remote_connector_effect(
                issued.hi12_grant, binding=binding, operation=operation,
                canonical_payload=canonical_payload, sequence=sequence,
                boot_epoch=self._boot_epoch())
        except AuthorityDenied:
            raise
        except Exception:
            raise _deny("remote.connector-hi12", "protected connector effect was denied") from None
        if accepted is not True:
            raise _deny("remote.connector-hi12", "protected connector effect was denied")
        return True

    def revoke_session(self, session_id: str) -> None:
        """Invalidate issued frame authorizations when HI13 closes/revokes a session."""
        with self._lock:
            self._revoked_sessions.add(session_id)
            for nonce, item in tuple(self._issued.items()):
                if item.authorization.remote_session_id == session_id:
                    del self._issued[nonce]

    def _assert_live(self, binding: RemoteConnectorBinding, operation: str, sequence: int,
                     uid: int, pid: int, pidfd: int) -> None:
        state = self._runtime_state()
        enrollment = self._enrollment
        now = self._monotonic()
        try:
            current_gateway = self._gateway(uid, pid, pidfd)
            proof = self._role_proof(current_gateway)
            current = self._session_current(binding, operation, sequence)
            epoch = self._boot_epoch()
        except Exception:
            raise _deny("remote.connector-identity", "current root process or session proof is unavailable") from None
        identity = binding.gateway_identity
        effect_deadline = (binding.lease_expires_monotonic if operation == "connector.open"
                           else binding.frame_deadline_monotonic)
        try:
            cancelled = binding.cancelled()
        except Exception:
            cancelled = True
        if (not state.active
                or state.enrollment_id != enrollment.enrollment_id
                or state.gateway_generation != enrollment.gateway_generation
                or state.gateway_role_sha256 != enrollment.gateway_role_sha256
                or state.native_profile_id != enrollment.native_desktop_profile_id
                or state.native_generation != enrollment.native_generation
                or state.connector_target_id != enrollment.connector_target_id
                or state.policy_revision != enrollment.policy_revision
                or state.policy_config_digest != enrollment.policy_config_digest
                or state.service_generation_digest != binding.service_generation_digest
                or identity != current_gateway
                or identity.uid != uid or identity.pid != pid
                or identity.profile_id != enrollment.gateway_profile_id
                or identity.generation != enrollment.gateway_generation
                or identity.enrollment_id != enrollment.enrollment_id
                or identity.executable_sha256 != enrollment.gateway_role_sha256
                or proof.enrollment_id != enrollment.enrollment_id
                or proof.profile_id != enrollment.gateway_profile_id
                or proof.generation != enrollment.gateway_generation
                or proof.executable_sha256 != identity.executable_sha256
                or proof.role_artifact_id != enrollment.gateway_role_artifact_id
                or proof.role_sha256 != enrollment.gateway_role_sha256
                or proof.entrypoint_artifact_id != self._entrypoint_artifact_id
                or proof.entrypoint_sha256 != self._entrypoint_sha256
                or len(proof.role_sha256) != 64 or len(proof.entrypoint_sha256) != 64
                or proof.boot_epoch != epoch or proof.observed_monotonic > now
                or proof.expires_monotonic <= now or not current
                or cancelled or binding.lease_expires_monotonic <= now
                or effect_deadline <= now
                or binding.policy_revision != enrollment.policy_revision
                or binding.policy_config_digest != enrollment.policy_config_digest
                or binding.native_profile_id != enrollment.native_desktop_profile_id
                or binding.native_generation != enrollment.native_generation
                or binding.target_id != enrollment.connector_target_id
                or binding.gateway_generation != enrollment.gateway_generation
                or binding.session_id in self._revoked_sessions):
            raise _deny("remote.connector-stale", "gateway, session, policy, or service enrollment is stale")

    @staticmethod
    def _canonical_body(payload: bytes) -> dict[str, Any]:
        try:
            value = json.loads(payload)
            if (not isinstance(value, dict)
                    or json.dumps(value, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=True).encode("ascii") != payload):
                raise ValueError
        except (ValueError, UnicodeDecodeError, TypeError):
            raise _deny("remote.connector-payload", "connector payload is not canonical JSON") from None
        return value

    @staticmethod
    def _assert_payload(binding: RemoteConnectorBinding, operation: str,
                        body: dict[str, Any], sequence: int, maximum_bytes: int) -> None:
        if operation == "connector.open":
            expected = {"schema": 1, "enrollment_id": binding.enrollment_id,
                        "generation": binding.native_generation, "target_id": binding.target_id,
                        "action": "open", "approved_route_id": binding.route_id,
                        "session_id": binding.session_id, "deadline": binding.lease_expires_monotonic}
        else:
            if (not isinstance(binding.connector_handle, str)
                    or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", binding.connector_handle) is None):
                raise _deny("remote.connector-payload", "current connector handle is unavailable")
            required = {"schema": 1, "target_id": binding.target_id,
                        "route_id": binding.route_id, "session_id": binding.session_id,
                        "connector_id": binding.connector_handle,
                        "generation": binding.native_generation, "sequence": sequence,
                        "deadline": binding.frame_deadline_monotonic}
            if not required.items() <= body.items():
                raise _deny("remote.connector-payload", "connector frame differs from the root binding")
            expected_keys = set(required)
            if operation == "connector.read":
                expected_keys.add("max_bytes")
                if body.get("max_bytes") != maximum_bytes:
                    raise _deny("remote.connector-payload", "read limit differs from the authorized frame")
            elif operation == "connector.write":
                expected_keys.add("data_b64")
            elif operation == "connector.close":
                pass
            if set(body) != expected_keys:
                raise _deny("remote.connector-payload", "connector frame contains extra authority fields")
            return
        if body != expected:
            raise _deny("remote.connector-payload", "open payload differs from root-selected target")

    @staticmethod
    def _binding_fingerprint(binding: RemoteConnectorBinding) -> str:
        fields = (binding.enrollment_id, binding.session_id, binding.action,
                  binding.route_id, binding.target_id, binding.subject,
                  binding.principal_id, binding.profile_id, binding.profile_generation,
                  binding.gateway_profile_id, binding.gateway_generation,
                  binding.native_profile_id, binding.native_generation,
                  binding.policy_revision, binding.policy_config_digest,
                  binding.service_generation_digest, binding.connector_handle or "",
                  str(binding.next_sequence), binding.gateway_identity.identity_digest,
                  binding.token_fingerprint, repr(binding.lease_expires_monotonic),
                  repr(binding.frame_deadline_monotonic))
        return hashlib.sha256("\0".join(fields).encode()).hexdigest()
