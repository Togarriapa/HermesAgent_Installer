"""Gateway client for HI13 root-observed Access sessions.

This adapter passes the bearer JWT directly to the peer-authenticated root
AuthorityClient. It accepts no gateway Principal, PolicyGrant, claims, lease, or
connector target. Opaque root handles remain in gateway memory and are never
serialized to browser responses.
"""
from __future__ import annotations

import math
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable, Literal


class RootSessionDenied(PermissionError):
    """Root Access/session admission or a returned binding was denied."""


AdmissionAction = Literal["asset-read", "websocket-attach"]


def _finite(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise RootSessionDenied(f"root session {name} is malformed")
    return float(value)


def _opaque(value: Any, name: str) -> str:
    if not isinstance(value, str) or len(value) != 43 or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise RootSessionDenied(f"root session {name} is malformed")
    return value


@dataclass(frozen=True, slots=True)
class AdmittedRemoteSession:
    """Validated root result. Keep ``handle`` server-side only."""

    handle: Any
    session_id: str
    admission_kind: str
    principal_binding_id: str
    profile_id: str
    gateway_generation: str
    desktop_generation: str
    route_id: str
    issued_monotonic: float
    lease_expires_monotonic: float
    jwt_expires_monotonic: float
    policy_verified_monotonic: float
    policy_revision: str
    policy_config_digest: str


@dataclass(frozen=True, slots=True)
class RemoteRenewalChallenge:
    session_id: str
    renewal_nonce: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootRemoteSessionClient:
    authority: Any
    hostname: str
    origin: str
    asset_route_ids: frozenset[str]
    websocket_route_id: str
    profile_id: str = "hermes-desktop"
    monotonic: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        if (self.profile_id != "hermes-desktop" or not self.hostname or
                self.origin != f"https://{self.hostname}" or not self.asset_route_ids or
                any(not x or len(x) > 128 for x in self.asset_route_ids) or
                not self.websocket_route_id or len(self.websocket_route_id) > 128):
            raise ValueError("fixed remote session enrollment is required")

    def admit(self, *, access_jwt: str, action: AdmissionAction, route_id: str) -> AdmittedRemoteSession:
        if not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384:
            raise RootSessionDenied("Access JWT is missing or exceeds its bound")
        try:
            token = access_jwt.encode("ascii", "strict")
        except UnicodeEncodeError:
            raise RootSessionDenied("Access JWT encoding is invalid") from None
        if action == "asset-read":
            allowed = route_id in self.asset_route_ids
            expected_kind = "one-shot-asset"
        elif action == "websocket-attach":
            allowed = route_id == self.websocket_route_id
            expected_kind = "leased-websocket"
        else:
            allowed = False
            expected_kind = ""
        if not allowed:
            raise RootSessionDenied("remote route is not enrolled for this action")
        try:
            from hermes_installer.authority.remote_sessions import RemoteAdmissionRequest
            request = RemoteAdmissionRequest(
                schema=1,
                request_id=secrets.token_urlsafe(32),
                hostname=self.hostname,
                origin=self.origin,
                route_id=route_id,
                action=action,
                client_nonce=secrets.token_urlsafe(32),
            )
            response = self.authority.admit_remote_session(token, request)
        except RootSessionDenied:
            raise
        except Exception:
            raise RootSessionDenied("root Access/session admission is unavailable or denied") from None
        if getattr(response, "schema", None) != 1:
            raise RootSessionDenied("root admission response schema is invalid")
        handle = getattr(response, "remote_session_handle", None)
        handle_value = getattr(handle, "value", handle)
        _opaque(handle_value, "handle")
        route = getattr(response, "route_id", None)
        profile = getattr(response, "profile_id", None)
        kind = getattr(response, "admission_kind", None)
        session_id = getattr(response, "session_id", None)
        if (route != route_id or profile != self.profile_id or kind != expected_kind or
                not isinstance(session_id, str) or not 1 <= len(session_id) <= 128):
            raise RootSessionDenied("root admission is not bound to the requested route/profile")
        principal_id = getattr(response, "principal_binding_id", None)
        if not isinstance(principal_id, str) or not 1 <= len(principal_id) <= 128:
            raise RootSessionDenied("root admission lacks its opaque principal binding")
        gateway_generation = getattr(response, "gateway_generation", None)
        desktop_generation = getattr(response, "desktop_generation", None)
        revision = getattr(response, "policy_revision", None)
        config_digest = getattr(response, "policy_config_digest", None)
        if (not isinstance(gateway_generation, str) or not gateway_generation or
                not isinstance(desktop_generation, str) or not desktop_generation or
                not isinstance(revision, str) or not revision or
                not isinstance(config_digest, str) or len(config_digest) != 64 or
                any(c not in "0123456789abcdef" for c in config_digest)):
            raise RootSessionDenied("root admission policy/generation binding is malformed")
        issued = _finite(getattr(response, "issued_monotonic", None), "issue time")
        expiry = _finite(getattr(response, "lease_expires_monotonic", None), "lease expiry")
        jwt_expiry = _finite(getattr(response, "jwt_expires_monotonic", None), "JWT expiry")
        policy_verified = _finite(getattr(response, "policy_verified_monotonic", None), "policy time")
        now = self.monotonic()
        if (issued > now + 0.05 or policy_verified > now + 0.05 or expiry <= now or
                expiry > issued + 60 or expiry > jwt_expiry or policy_verified > issued):
            raise RootSessionDenied("root admission lease is stale or exceeds its bound")
        return AdmittedRemoteSession(handle, session_id, kind, principal_id, profile,
                                     gateway_generation, desktop_generation, route, issued,
                                     expiry, jwt_expiry, policy_verified, revision, config_digest)

    def challenge(self, handle: Any) -> RemoteRenewalChallenge:
        try:
            response = self.authority.challenge_remote_session(handle)
        except Exception:
            raise RootSessionDenied("root renewal challenge is unavailable") from None
        if getattr(response, "schema", None) != 1:
            raise RootSessionDenied("root renewal challenge schema is invalid")
        session_id = getattr(response, "session_id", None)
        nonce = getattr(response, "renewal_nonce", None)
        expiry = _finite(getattr(response, "expires_monotonic", None), "challenge expiry")
        if (not isinstance(session_id, str) or not 1 <= len(session_id) <= 128 or
                not isinstance(nonce, str) or not 20 <= len(nonce) <= 128 or
                expiry <= self.monotonic() or expiry > self.monotonic() + 30):
            raise RootSessionDenied("root renewal challenge binding or lifetime is invalid")
        return RemoteRenewalChallenge(session_id, nonce, expiry)

    def renew(self, *, handle: Any, session_id: str, access_jwt: str, renewal_nonce: str) -> float:
        if not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384:
            raise RootSessionDenied("fresh Access JWT is missing or exceeds its bound")
        try:
            token = access_jwt.encode("ascii", "strict")
            response = self.authority.renew_remote_session(handle, token, renewal_nonce)
        except Exception:
            raise RootSessionDenied("fresh root policy/session renewal was denied") from None
        if (getattr(response, "schema", None) != 1 or
                getattr(response, "session_id", None) != session_id):
            raise RootSessionDenied("renewal response is not bound to the existing root session")
        expiry = _finite(getattr(response, "lease_expires_monotonic", None), "renewed lease expiry")
        jwt_expiry = _finite(getattr(response, "jwt_expires_monotonic", None), "renewed JWT expiry")
        verified = _finite(getattr(response, "policy_verified_monotonic", None), "renewed policy time")
        now = self.monotonic()
        if expiry <= now or expiry > now + 60 or expiry > jwt_expiry or verified > now + 0.05:
            raise RootSessionDenied("renewed root lease is stale or exceeds its bound")
        return expiry

    def close(self, handle: Any, *, session_id: str | None = None) -> None:
        try:
            response = self.authority.close_remote_session(handle)
        except Exception:
            raise RootSessionDenied("root remote session cleanup failed") from None
        if (getattr(response, "schema", None) != 1 or
                getattr(response, "state", None) != "closed" or
                session_id is not None and getattr(response, "session_id", None) != session_id):
            raise RootSessionDenied("root remote session cleanup receipt is invalid")
