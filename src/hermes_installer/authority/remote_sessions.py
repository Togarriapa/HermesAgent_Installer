"""Root-owned Cloudflare Access session admission and connector leases (HI13).

This module is constructed by the privileged authority process from protected
enrollment, the isolated Access-policy verifier, and the registered gateway
process resolver.  Worker supplied identity claims, policy grants, routes,
targets, generations, and lease values are never accepted here.
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol
from urllib.parse import urlsplit

from ..remote.gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt
from ..remote.jwks import JWKSCache
from ..remote.policy import FreshAccessPolicyAuthority
from ..remote.client_assets import canonical_asset
from .types import AuthorityDenied, canonical_bytes, canonical_digest

MAX_JWT_BYTES = 16 * 1024
MAX_REQUEST_BYTES = 8 * 1024
MAX_LEASE_SECONDS = 60.0
MAX_WATCHDOG_SECONDS = 5.0
MAX_CHALLENGE_SECONDS = 30.0
MAX_FRAME_BYTES = 1024 * 1024
MAX_ASSET_BYTES = 2 * 1024 * 1024
MAX_CONNECTOR_CALL_SECONDS = 5.0
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
_EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _deny(code: str, message: str) -> AuthorityDenied:
    return AuthorityDenied(code, message)


class RemoteSessionHandle(str):
    """Opaque root lookup key whose accidental repr/log form is redacted."""

    def __new__(cls, value: str):
        _opaque(value, "remote session handle")
        return str.__new__(cls, value)

    @property
    def value(self) -> str:
        return str(self)

    def __repr__(self) -> str:
        return "RemoteSessionHandle(<opaque>)"


def _opaque(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE.fullmatch(value):
        raise _deny("remote.handle", f"{name} is invalid")
    return value


def _connector_token(value: Any) -> str:
    # HI07 returns a UUID connector_id; it is distinct from the HI13 session handle.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value):
        raise _deny("remote.connector-handle", "root connector handle is invalid")
    return value


def _connector_effect_payload(binding: "RemoteConnectorBinding", operation: str, *,
                              sequence: int, maximum_bytes: int = 0,
                              connector_id: str | None = None,
                              data_bytes: bytes | None = None) -> dict[str, Any]:
    """Exact canonical HI07 effect body whose digest the root grant must bind."""
    if operation == "connector.open":
        return {"schema": 1, "enrollment_id": binding.enrollment_id,
                "generation": binding.native_generation, "target_id": binding.target_id,
                "action": "open", "approved_route_id": binding.route_id,
                "session_id": binding.session_id, "deadline": binding.lease_expires_monotonic}
    body: dict[str, Any] = {
        "schema": 1, "target_id": binding.target_id, "route_id": binding.route_id,
        "connector_id": _connector_token(connector_id),
        "session_id": binding.session_id, "generation": binding.native_generation,
        "sequence": sequence, "deadline": binding.frame_deadline_monotonic,
    }
    if operation == "connector.read":
        body["max_bytes"] = maximum_bytes
    elif operation == "connector.write":
        if not isinstance(data_bytes, bytes):
            raise _deny("remote.connector-payload", "write payload is unavailable")
        body["data_b64"] = base64.b64encode(data_bytes).decode("ascii")
    elif operation != "connector.close":
        raise _deny("remote.connector-operation", "connector operation is not enrolled")
    return body


def _validate_asset_fetch_request(data: bytes) -> None:
    """Only a single bodyless Xpra client GET/HEAD may cross asset-read.

    The root HI07 backend also reconstructs the request with a fixed loopback
    Host. This early gate ensures an asset lease can never become Desktop input.
    """
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_FRAME_BYTES:
        raise _deny("remote.asset-request", "asset fetch frame is outside its byte bound")
    header, sep, body = data.partition(b"\r\n\r\n")
    if not sep or body or len(header) > 32_768:
        raise _deny("remote.asset-request", "asset fetch must be a bodyless bounded HTTP request")
    try:
        lines = header.decode("ascii", "strict").split("\r\n")
    except UnicodeDecodeError:
        raise _deny("remote.asset-request", "asset fetch request must use ASCII HTTP framing") from None
    parts = lines[0].split(" ")
    if (len(parts) != 3 or parts[0] not in {"GET", "HEAD"} or parts[2] != "HTTP/1.1"
            or not parts[1].startswith("/client/") or "?" in parts[1] or "#" in parts[1]
            or "\\" in parts[1] or "%" in parts[1]
            or any(part in {".", ".."} for part in parts[1].split("/"))):
        raise _deny("remote.asset-request", "asset route permits only a canonical GET/HEAD client asset")
    try:
        canonical_asset(parts[1])
    except (ValueError, TypeError):
        raise _deny("remote.asset-request", "asset path is outside the pinned client manifest") from None
    names: set[str] = set()
    for line in lines[1:]:
        if not line or line[0] in " \t" or ":" not in line:
            raise _deny("remote.asset-request", "asset request headers are malformed")
        name, value = line.split(":", 1)
        key = name.casefold()
        if (not re.fullmatch(r"[a-z0-9-]{1,64}", key) or key in names
                or "\r" in value or "\n" in value
                or key in {"authorization", "cookie", "transfer-encoding"}):
            raise _deny("remote.asset-request", "asset request contains unsafe or duplicate headers")
        names.add(key)
    content_length = next((line.split(":", 1)[1].strip() for line in lines[1:]
                           if line.split(":", 1)[0].casefold() == "content-length"), "0")
    if content_length != "0":
        raise _deny("remote.asset-request", "asset request cannot contain a body")


def _finite(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise _deny("remote.state", f"{name} is invalid")
    return float(value)


@dataclass(frozen=True, slots=True)
class RemoteAdmissionRequest:
    """Only the fixed route request fields permitted by HI13."""

    schema: int
    request_id: str
    hostname: str
    origin: str
    route_id: str
    action: str
    client_nonce: str

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not isinstance(self.request_id, str) or not _ID.fullmatch(self.request_id)
                or not isinstance(self.client_nonce, str) or not 20 <= len(self.client_nonce) <= 128
                or not isinstance(self.hostname, str) or len(self.hostname) > 253
                or not isinstance(self.origin, str) or len(self.origin) > 1024
                or not isinstance(self.route_id, str) or not _ID.fullmatch(self.route_id)
                or self.action not in {"asset-read", "websocket-attach"}):
            raise _deny("remote.request", "remote admission request is malformed")

    @classmethod
    def from_wire(cls, value: Any) -> "RemoteAdmissionRequest":
        required = {"schema", "request_id", "hostname", "origin", "route_id", "action", "client_nonce"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise _deny("remote.request", "remote admission request fields are invalid")
        try:
            return cls(**dict(value))
        except (TypeError, ValueError):
            raise _deny("remote.request", "remote admission request is malformed") from None

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "request_id": self.request_id,
            "hostname": self.hostname, "origin": self.origin,
            "route_id": self.route_id, "action": self.action,
            "client_nonce": self.client_nonce,
        }


@dataclass(frozen=True, slots=True)
class RemotePrincipalBinding:
    """Protected mapping from a verified Access subject/email to one host profile."""

    subject: str = field(repr=False)
    email: str = field(repr=False)
    principal_id: str
    profile_id: str
    profile_generation: str

    def __post_init__(self) -> None:
        if (not isinstance(self.subject, str) or not 1 <= len(self.subject) <= 256
                or not isinstance(self.email, str) or not _EMAIL.fullmatch(self.email)
                or self.email != self.email.casefold()
                or any(not isinstance(x, str) or not _ID.fullmatch(x)
                       for x in (self.principal_id, self.profile_id, self.profile_generation))):
            raise ValueError("verified remote principal/profile enrollment is invalid")


@dataclass(frozen=True, slots=True)
class RemoteSessionEnrollment:
    """Immutable root-selected Access, gateway, Desktop and connector binding."""

    enrollment_id: str
    hostname: str
    expected_origin: str
    jwt_issuer: str
    jwt_audience: str
    jwks_origin: str
    jwt_algorithm_allowlist: tuple[str, ...]
    allowed_email_reference_id: str
    policy_verifier_enrollment_id: str
    profile_id: str
    gateway_profile_id: str
    gateway_role_artifact_id: str
    gateway_role_sha256: str
    gateway_generation: str
    native_desktop_profile_id: str
    native_generation: str
    desktop_generation: str
    connector_target_id: str
    approved_asset_routes: tuple[str, ...]
    websocket_route_id: str
    policy_revision: str
    policy_config_digest: str
    principal_bindings_by_subject: Mapping[str, RemotePrincipalBinding] = field(repr=False)
    maximum_lease_seconds: float = MAX_LEASE_SECONDS
    watchdog_interval_seconds: float = MAX_WATCHDOG_SECONDS

    def __post_init__(self) -> None:
        host = self.hostname.casefold() if isinstance(self.hostname, str) else ""
        origin = urlsplit(self.expected_origin) if isinstance(self.expected_origin, str) else None
        issuer = urlsplit(self.jwt_issuer) if isinstance(self.jwt_issuer, str) else None
        if (not _ID.fullmatch(self.enrollment_id)
                or not _ID.fullmatch(self.profile_id)
                or not _ID.fullmatch(self.gateway_profile_id)
                or not _ID.fullmatch(self.gateway_role_artifact_id)
                or not _DIGEST.fullmatch(self.gateway_role_sha256)
                or not _ID.fullmatch(self.gateway_generation)
                or not _ID.fullmatch(self.native_desktop_profile_id)
                or not _ID.fullmatch(self.native_generation)
                or not _ID.fullmatch(self.desktop_generation)
                or self.native_generation != self.desktop_generation
                or not _ID.fullmatch(self.connector_target_id)
                or not self.approved_asset_routes
                or any(not _ID.fullmatch(route) for route in self.approved_asset_routes)
                or not _ID.fullmatch(self.websocket_route_id)
                or not _ID.fullmatch(self.allowed_email_reference_id)
                or not _ID.fullmatch(self.policy_verifier_enrollment_id)
                or not _ID.fullmatch(self.policy_revision)
                or not _DIGEST.fullmatch(self.policy_config_digest)
                or not isinstance(self.jwt_issuer, str) or len(self.jwt_issuer) > 256
                or issuer is None or issuer.scheme != "https" or not issuer.hostname
                or issuer.username is not None or issuer.password is not None
                or issuer.netloc.casefold() != issuer.hostname.casefold()
                or issuer.path not in {"", "/"} or issuer.query or issuer.fragment
                or not isinstance(self.jwt_audience, str) or not _ID.fullmatch(self.jwt_audience)
                or not isinstance(self.jwks_origin, str) or self.jwks_origin != self.jwt_issuer
                or self.jwt_algorithm_allowlist != ("RS256",)
                or len(host) > 253 or not re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+", host)
                or origin is None or origin.scheme != "https" or origin.netloc.casefold() != host
                or origin.path not in {"", "/"} or origin.query or origin.fragment
                or self.websocket_route_id in self.approved_asset_routes
                or isinstance(self.maximum_lease_seconds, bool)
                or not isinstance(self.maximum_lease_seconds, (int, float))
                or not 0 < self.maximum_lease_seconds <= MAX_LEASE_SECONDS
                or isinstance(self.watchdog_interval_seconds, bool)
                or not isinstance(self.watchdog_interval_seconds, (int, float))
                or not 0 < self.watchdog_interval_seconds <= MAX_WATCHDOG_SECONDS
                or not self.principal_bindings_by_subject):
            raise ValueError("remote session enrollment is invalid or exceeds lease bounds")
        bindings = dict(self.principal_bindings_by_subject)
        if any(key != binding.subject or binding.profile_id != self.profile_id
               for key, binding in bindings.items()):
            raise ValueError("subject-to-profile mapping differs from protected enrollment")
        identities = [(b.subject, b.email) for b in bindings.values()]
        if len(identities) != len(set(identities)) or len({b.email for b in bindings.values()}) != len(bindings):
            raise ValueError("remote subject/email mapping is ambiguous")
        object.__setattr__(self, "hostname", host)
        object.__setattr__(self, "approved_asset_routes", tuple(self.approved_asset_routes))
        object.__setattr__(self, "principal_bindings_by_subject", MappingProxyType(bindings))

    def allows_route(self, action: str, route_id: str) -> bool:
        if action == "asset-read":
            return route_id in self.approved_asset_routes
        if action == "websocket-attach":
            return route_id == self.websocket_route_id
        return False


@dataclass(frozen=True, slots=True)
class RemoteGatewayIdentity:
    """Root-observed result of registered-process resolution, never RPC fields."""

    uid: int
    pid: int
    start_time: str
    executable_sha256: str
    cgroup_id: str
    profile_id: str
    generation: str
    identity_digest: str
    gid: int
    pid_starttime_ticks: str
    executable_device: int
    executable_inode: int
    mount_namespace_inode: int
    network_namespace_inode: int
    enrollment_id: str
    pidfd_registry_handle: str

    def __post_init__(self) -> None:
        if (type(self.uid) is not int or self.uid <= 0 or type(self.pid) is not int or self.pid <= 0
                or not isinstance(self.start_time, str) or not self.start_time.isdecimal()
                or not _DIGEST.fullmatch(self.executable_sha256)
                or not _ID.fullmatch(self.cgroup_id) or not _ID.fullmatch(self.profile_id)
                or not _ID.fullmatch(self.generation) or not _DIGEST.fullmatch(self.identity_digest)
                or type(self.gid) is not int or self.gid < 0
                or not isinstance(self.pid_starttime_ticks, str) or not self.pid_starttime_ticks.isdecimal()
                or any(type(value) is not int or value <= 0 for value in (
                    self.executable_device, self.executable_inode,
                    self.mount_namespace_inode, self.network_namespace_inode))
                or not _ID.fullmatch(self.enrollment_id)
                or not _ID.fullmatch(self.pidfd_registry_handle)):
            raise ValueError("root-observed gateway identity is invalid")


@dataclass(frozen=True, slots=True)
class RemoteRuntimeState:
    """Fresh root snapshot used to invalidate all live sessions on drift."""

    enrollment_id: str
    policy_revision: str
    policy_config_digest: str
    gateway_generation: str
    desktop_generation: str
    native_profile_id: str
    native_generation: str
    gateway_role_sha256: str
    connector_target_id: str
    principal_mapping_digest: str
    active: bool = True


@dataclass(frozen=True, slots=True)
class VerifiedRemoteIdentity:
    email: str = field(repr=False)
    subject: str = field(repr=False)
    token_fingerprint: str = field(repr=False)
    jwt_expires_monotonic: float
    policy_verified_monotonic: float
    policy_revision: str
    policy_config_digest: str


@dataclass(frozen=True, slots=True)
class RemoteAdmissionResponse:
    schema: int
    remote_session_handle: str = field(repr=False)
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

    def __post_init__(self) -> None:
        if not isinstance(self.remote_session_handle, RemoteSessionHandle):
            object.__setattr__(self, "remote_session_handle",
                               RemoteSessionHandle(str(self.remote_session_handle)))
        _opaque(self.remote_session_handle, "remote session handle")
        if (self.schema != 1 or self.admission_kind not in {"one-shot-asset", "leased-websocket"}
                or any(not _ID.fullmatch(x) for x in (self.session_id, self.principal_binding_id,
                    self.profile_id, self.gateway_generation, self.desktop_generation,
                    self.route_id, self.policy_revision))
                or not _DIGEST.fullmatch(self.policy_config_digest)):
            raise ValueError("remote admission response is malformed")
        times = [_finite(getattr(self, n), n) for n in (
            "issued_monotonic", "lease_expires_monotonic", "jwt_expires_monotonic",
            "policy_verified_monotonic")]
        if times[1] <= times[0] or times[1] - times[0] > MAX_LEASE_SECONDS or times[1] > times[2]:
            raise ValueError("remote admission lease exceeds its bounds")

    def to_wire(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in (
            "schema", "remote_session_handle", "session_id", "admission_kind",
            "principal_binding_id", "profile_id", "gateway_generation", "desktop_generation",
            "route_id", "issued_monotonic", "lease_expires_monotonic", "jwt_expires_monotonic",
            "policy_verified_monotonic", "policy_revision", "policy_config_digest")}

    @classmethod
    def from_wire(cls, value: Any) -> "RemoteAdmissionResponse":
        fields = {"schema", "remote_session_handle", "session_id", "admission_kind", "principal_binding_id",
                  "profile_id", "gateway_generation", "desktop_generation", "route_id", "issued_monotonic",
                  "lease_expires_monotonic", "jwt_expires_monotonic", "policy_verified_monotonic",
                  "policy_revision", "policy_config_digest"}
        if not isinstance(value, Mapping) or set(value) != fields:
            raise _deny("remote.response", "remote admission response fields are invalid")
        try:
            return cls(**dict(value))
        except (ValueError, TypeError):
            raise _deny("remote.response", "remote admission response is malformed") from None


@dataclass(frozen=True, slots=True)
class RemoteChallenge:
    schema: int
    session_id: str
    renewal_nonce: str = field(repr=False)
    expires_monotonic: float

    def __post_init__(self) -> None:
        if self.schema != 1 or not _ID.fullmatch(self.session_id):
            raise ValueError("remote challenge is malformed")
        _opaque(self.renewal_nonce, "renewal nonce")
        _finite(self.expires_monotonic, "challenge expiry")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "session_id": self.session_id,
                "renewal_nonce": self.renewal_nonce, "expires_monotonic": self.expires_monotonic}


@dataclass(frozen=True, slots=True)
class RemoteLease:
    schema: int
    remote_session_handle: str = field(repr=False)
    session_id: str
    lease_expires_monotonic: float
    jwt_expires_monotonic: float
    policy_verified_monotonic: float
    policy_revision: str
    policy_config_digest: str

    def __post_init__(self) -> None:
        if (self.schema != 1 or not isinstance(self.remote_session_handle, RemoteSessionHandle)
                or not _ID.fullmatch(self.session_id)
                or not _ID.fullmatch(self.policy_revision) or not _DIGEST.fullmatch(self.policy_config_digest)):
            raise ValueError("remote lease is malformed")
        start = _finite(self.policy_verified_monotonic, "policy verification time")
        expiry = _finite(self.lease_expires_monotonic, "remote lease expiry")
        jwt_expiry = _finite(self.jwt_expires_monotonic, "JWT expiry")
        if expiry <= start or expiry - start > MAX_LEASE_SECONDS or expiry > jwt_expiry:
            raise ValueError("remote lease exceeds its bound")

    def to_wire(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in (
            "schema", "remote_session_handle", "session_id", "lease_expires_monotonic", "jwt_expires_monotonic",
            "policy_verified_monotonic", "policy_revision", "policy_config_digest")}


@dataclass(frozen=True, slots=True)
class RemoteCloseResponse:
    schema: int
    session_id: str
    state: str = "closed"

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "session_id": self.session_id, "state": self.state}


@dataclass(frozen=True, slots=True)
class RemoteConnectorBinding:
    """Private root-derived connector scope passed only to the root connector adapter."""

    enrollment_id: str
    session_id: str
    action: str
    route_id: str
    target_id: str
    subject: str = field(repr=False)
    principal_id: str
    profile_id: str
    profile_generation: str
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    native_generation: str
    gateway_identity: RemoteGatewayIdentity
    token_fingerprint: str = field(repr=False)
    issued_monotonic: float
    lease_expires_monotonic: float = 0.0
    frame_deadline_monotonic: float = 0.0
    cancelled: Callable[[], bool] = field(repr=False, compare=False, default=lambda: True)


@dataclass(frozen=True, slots=True)
class RemoteConnectorAuthorization:
    """Root-minted one-use HI12 context/grant wrapper; never a wire value."""

    operation: str
    target_id: str
    request_digest: str
    session_id: str
    sequence: int
    maximum_bytes: int
    route_id: str
    principal_id: str
    profile_id: str
    profile_generation: str
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    native_generation: str
    generation: str
    deadline: float
    lease_expires_monotonic: float
    nonce: str
    grant_id: str
    host_context: Any = field(repr=False, compare=False)
    effect_authorization: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self.operation not in {"connector.open", "connector.read", "connector.write", "connector.close"}
                or not _DIGEST.fullmatch(self.request_digest)
                or not _ID.fullmatch(self.session_id)
                or type(self.sequence) is not int or self.sequence < 0
                or type(self.maximum_bytes) is not int or self.maximum_bytes < 0
                or any(not _ID.fullmatch(x) for x in (
                    self.target_id, self.route_id, self.principal_id, self.profile_id,
                    self.profile_generation, self.gateway_profile_id, self.gateway_generation,
                    self.native_profile_id, self.native_generation, self.generation,
                    self.nonce, self.grant_id))
                or not math.isfinite(self.lease_expires_monotonic)
                or not math.isfinite(self.deadline)
                or self.host_context is None or self.effect_authorization is None):
            raise ValueError("root connector authorization is incomplete")


class RemoteConnectorBackend(Protocol):
    """Root service connector; implementation mints exact one-use HI12 grants."""

    def open(self, binding: RemoteConnectorBinding, *, authorization: RemoteConnectorAuthorization,
             peer_uid: int, peer_pid: int, peer_pidfd: int) -> str: ...
    def read(self, binding: RemoteConnectorBinding, connector_handle: str,
             sequence: int, maximum_bytes: int, *, authorization: RemoteConnectorAuthorization,
             peer_uid: int, peer_pid: int, peer_pidfd: int,
             cancelled: Callable[[], bool]) -> tuple[bytes, bool]: ...
    def write(self, binding: RemoteConnectorBinding, connector_handle: str,
              sequence: int, data_bytes: bytes, *, authorization: RemoteConnectorAuthorization,
              peer_uid: int, peer_pid: int, peer_pidfd: int,
              cancelled: Callable[[], bool]) -> int: ...
    def close(self, binding: RemoteConnectorBinding, connector_handle: str, *,
              authorization: RemoteConnectorAuthorization | None,
              cleanup: bool) -> None: ...


@dataclass(frozen=True, slots=True)
class RemoteConnectorOpen:
    schema: int
    session_id: str
    connector_handle: str = field(repr=False)
    generation: str
    route_id: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (self.schema != 1 or not _ID.fullmatch(self.session_id)
                or not _ID.fullmatch(self.generation) or not _ID.fullmatch(self.route_id)):
            raise ValueError("remote connector open response is malformed")
        _connector_token(self.connector_handle)
        _finite(self.expires_monotonic, "connector expiry")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "session_id": self.session_id,
                "connector_handle": self.connector_handle, "generation": self.generation,
                "route_id": self.route_id, "expires_monotonic": self.expires_monotonic}


@dataclass(frozen=True, slots=True)
class RemoteConnectorRead:
    schema: int
    session_id: str
    sequence: int
    data_bytes: bytes = field(repr=False)
    eof: bool
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (self.schema != 1 or not _ID.fullmatch(self.session_id) or type(self.sequence) is not int
                or self.sequence < 0 or not isinstance(self.data_bytes, bytes) or type(self.eof) is not bool):
            raise ValueError("remote connector read response is malformed")
        _finite(self.expires_monotonic, "connector expiry")

    def to_wire(self) -> dict[str, Any]:
        # JSON IPC carries bounded bytes as base64; the public key remains the
        # Sol contract's data_bytes and is decoded by RemoteAuthorityClient.
        return {"schema": self.schema, "session_id": self.session_id, "sequence": self.sequence,
                "data_bytes": base64.b64encode(self.data_bytes).decode("ascii"),
                "eof": self.eof, "expires_monotonic": self.expires_monotonic}


@dataclass(frozen=True, slots=True)
class RemoteConnectorWrite:
    schema: int
    session_id: str
    sequence: int
    accepted_bytes: int
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (self.schema != 1 or not _ID.fullmatch(self.session_id)
                or type(self.sequence) is not int or self.sequence < 0
                or type(self.accepted_bytes) is not int or self.accepted_bytes < 0):
            raise ValueError("remote connector write response is malformed")
        _finite(self.expires_monotonic, "connector expiry")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "session_id": self.session_id, "sequence": self.sequence,
                "accepted_bytes": self.accepted_bytes, "expires_monotonic": self.expires_monotonic}


@dataclass(frozen=True, slots=True)
class RemoteConnectorClose:
    schema: int
    session_id: str
    state: str = "closed"

    def __post_init__(self) -> None:
        if self.schema != 1 or not _ID.fullmatch(self.session_id) or self.state != "closed":
            raise ValueError("remote connector close response is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "session_id": self.session_id, "state": self.state}


class RootRemoteAccessVerifier:
    """Actual root-side JWT/JWKS verification followed by a fresh selected policy read."""

    def __init__(self, *, policy: RemotePolicy, jwks: JWKSCache,
                 fresh_policy: FreshAccessPolicyAuthority, policy_revision: str,
                 config_digest: str, verifier_enrollment_id: str,
                 monotonic: Callable[[], float] = time.monotonic,
                 wall_clock: Callable[[], float] = time.time):
        identity = fresh_policy.identity
        if (policy.jwks is not jwks or policy.issuer != jwks.issuer
                or policy.hostname.casefold() != identity.hostname
                or policy.audience != identity.audience
                or frozenset(x.casefold() for x in policy.allowed_emails) != identity.allowed_emails
                or not _ID.fullmatch(policy_revision) or not _DIGEST.fullmatch(config_digest)
                or not _ID.fullmatch(verifier_enrollment_id)):
            raise ValueError("root JWT, JWKS, selected policy and digest enrollment must match exactly")
        self.policy = policy
        self.jwks = jwks
        self.fresh_policy = fresh_policy
        self.policy_revision = policy_revision
        self.config_digest = config_digest
        self.verifier_enrollment_id = verifier_enrollment_id
        self.monotonic = monotonic
        self.wall_clock = wall_clock

    def verify(self, access_jwt: bytes) -> VerifiedRemoteIdentity:
        if not isinstance(access_jwt, bytes) or not 1 <= len(access_jwt) <= MAX_JWT_BYTES:
            raise _deny("remote.jwt", "Access token size is invalid")
        try:
            token = access_jwt.decode("ascii", errors="strict")
            start_mono, start_wall = self.monotonic(), self.wall_clock()
            if not math.isfinite(start_mono) or not math.isfinite(start_wall):
                raise ValueError("clock")
            deadline = start_mono + FreshAccessPolicyAuthority.MAX_READ_SECONDS
            principal: Principal = validate_access_jwt(
                token, policy=self.policy, now=lambda: start_wall,
                deadline_monotonic=deadline)
            if self.monotonic() >= deadline:
                raise GatewayDenied("Access verification deadline expired")
            allowed = self.fresh_policy.allows(
                principal.email, deadline_monotonic=deadline)
            verified = self.monotonic()
            if not allowed or verified >= deadline:
                raise GatewayDenied("fresh enrolled Access policy denied")
            jwt_deadline = start_mono + max(0.0, principal.expires_at - start_wall)
            if jwt_deadline <= verified:
                raise GatewayDenied("Access token expired during policy verification")
            return VerifiedRemoteIdentity(
                principal.email, principal.subject, principal.token_fingerprint,
                jwt_deadline, verified, self.policy_revision, self.config_digest)
        except AuthorityDenied:
            raise
        except Exception:
            # Never include token/library/provider exception text in authority logs.
            raise _deny("remote.verify", "root could not verify the current Access identity and policy") from None


@dataclass(slots=True)
class _Session:
    handle: str = field(repr=False)
    session_id: str
    principal_binding_id: str
    mapping: RemotePrincipalBinding = field(repr=False)
    identity: VerifiedRemoteIdentity = field(repr=False)
    gateway: RemoteGatewayIdentity = field(repr=False)
    enrollment_id: str
    action: str
    route_id: str
    issued_monotonic: float
    lease_expires_monotonic: float
    connector_handle: str | None = field(default=None, repr=False)
    connector_opened: bool = False
    connector_io_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    next_sequence: int = 0
    total_asset_bytes: int = 0
    asset_request_sent: bool = False
    renewal_nonce: str | None = field(default=None, repr=False)
    renewal_nonce_expires: float = 0.0
    closed: bool = False


class RemoteSessionAuthority:
    """Root-only session table and HI12 connector gate.

    `gateway_identity_resolver` must resolve `(uid,pid,pidfd)` from the actual
    AuthorityService peer and enrolled executable/process registry. No RPC
    payload may provide a RemoteGatewayIdentity. `runtime_state` and
    `gateway_identity_is_current` re-check enrollment and native process state
    on every operation and watchdog tick.
    """

    def __init__(self, *, enrollment: RemoteSessionEnrollment,
                 verifier: RootRemoteAccessVerifier,
                 gateway_identity_resolver: Callable[[int, int, int], RemoteGatewayIdentity],
                 gateway_identity_is_current: Callable[[RemoteGatewayIdentity], bool],
                 runtime_state: Callable[[], RemoteRuntimeState],
                 authorize_connector_operation: Callable[..., RemoteConnectorAuthorization],
                 connector_backend: RemoteConnectorBackend,
                 monotonic: Callable[[], float] = time.monotonic,
                 watchdog: bool = True):
        if (not isinstance(enrollment, RemoteSessionEnrollment)
                or not isinstance(verifier, RootRemoteAccessVerifier)
                or not callable(gateway_identity_resolver)
                or not callable(gateway_identity_is_current) or not callable(runtime_state)
                or not callable(authorize_connector_operation) or connector_backend is None):
            raise ValueError("root remote session authority requires protected enrollment, verifier, peer and connector adapters")
        if (verifier.policy.hostname.casefold() != enrollment.hostname
                or verifier.policy.issuer != enrollment.jwt_issuer
                or verifier.policy.audience != enrollment.jwt_audience
                or verifier.jwks.issuer != enrollment.jwks_origin
                or verifier.config_digest != enrollment.policy_config_digest
                or verifier.policy_revision != enrollment.policy_revision
                or verifier.verifier_enrollment_id != enrollment.policy_verifier_enrollment_id):
            raise ValueError("remote session and verifier enrollment differ")
        self.enrollment = enrollment
        self.verifier = verifier
        self.gateway_identity_resolver = gateway_identity_resolver
        self.gateway_identity_is_current = gateway_identity_is_current
        self.runtime_state = runtime_state
        self.authorize_connector_operation = authorize_connector_operation
        self.connector_backend = connector_backend
        self.monotonic = monotonic
        self._sessions: dict[str, _Session] = {}
        self._request_nonces: dict[str, float] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._watchdog_thread: threading.Thread | None = None
        if watchdog:
            self.start_watchdog()

    def start_watchdog(self) -> None:
        with self._lock:
            if self._watchdog_thread and self._watchdog_thread.is_alive():
                return
            self._stop.clear()
            self._watchdog_thread = threading.Thread(
                target=self._watchdog_loop, name="remote-session-watchdog", daemon=True)
            self._watchdog_thread.start()

    def stop_watchdog(self) -> None:
        self._stop.set()
        thread = self._watchdog_thread
        if thread and thread is not threading.current_thread():
            thread.join(timeout=MAX_WATCHDOG_SECONDS + 1)
        with self._lock:
            for session in tuple(self._sessions.values()):
                self._close_state(session)

    def admit_remote_session(self, access_jwt: bytes, request: RemoteAdmissionRequest, *,
                             peer_uid: int, peer_pid: int, peer_pidfd: int) -> RemoteAdmissionResponse:
        if not isinstance(request, RemoteAdmissionRequest):
            raise _deny("remote.request", "typed root admission request is required")
        if len(canonical_bytes(request.to_wire())) > MAX_REQUEST_BYTES:
            raise _deny("remote.request", "remote admission request exceeds its bound")
        if (request.hostname.casefold() != self.enrollment.hostname
                or request.origin != self.enrollment.expected_origin
                or not self.enrollment.allows_route(request.action, request.route_id)):
            raise _deny("remote.route", "remote hostname, origin, action or route is not enrolled")
        gateway = self._resolve_gateway(peer_uid, peer_pid, peer_pidfd)
        self._assert_runtime(gateway)
        now = self.monotonic()
        self._consume_request_nonce(request, now)
        try:
            identity = self.verifier.verify(access_jwt)
            binding = self.enrollment.principal_bindings_by_subject.get(identity.subject)
            if (binding is None or binding.email != identity.email
                    or identity.policy_revision != self.enrollment.policy_revision
                    or identity.policy_config_digest != self.enrollment.policy_config_digest):
                raise _deny("remote.principal", "verified Access identity has no unique active root profile mapping")
        except AuthorityDenied:
            raise
        except Exception:
            raise _deny("remote.verify", "root remote admission failed closed") from None
        issued = self.monotonic()
        expiry = min(issued + self.enrollment.maximum_lease_seconds,
                     identity.jwt_expires_monotonic,
                     identity.policy_verified_monotonic + self.enrollment.maximum_lease_seconds)
        if expiry <= issued:
            raise _deny("remote.expired", "verified Access and policy lease is already expired")
        handle = secrets.token_urlsafe(32)
        session_id = secrets.token_urlsafe(24)
        principal_ref = secrets.token_urlsafe(24)
        state = _Session(handle, session_id, principal_ref, binding, identity, gateway,
                         self.enrollment.enrollment_id, request.action, request.route_id,
                         issued, expiry)
        with self._lock:
            self._prune_nonces(issued)
            if len(self._sessions) >= 1024:
                self._sessions = {key: value for key, value in self._sessions.items()
                                  if not value.closed}
            if len(self._sessions) >= 1024:
                raise _deny("remote.capacity", "remote session table is at capacity")
            self._sessions[handle] = state
        return RemoteAdmissionResponse(
            1, handle, session_id,
            "one-shot-asset" if request.action == "asset-read" else "leased-websocket",
            principal_ref, binding.profile_id, gateway.generation,
            self.enrollment.desktop_generation, request.route_id, issued, expiry,
            identity.jwt_expires_monotonic, identity.policy_verified_monotonic,
            identity.policy_revision, identity.policy_config_digest)

    def challenge_remote_session(self, remote_session_handle: str, *, peer_uid: int,
                                 peer_pid: int, peer_pidfd: int) -> RemoteChallenge:
        session = self._owned_session(remote_session_handle, peer_uid, peer_pid, peer_pidfd)
        if session.action != "websocket-attach":
            raise _deny("remote.action", "asset admission cannot renew or attach a WebSocket")
        now = self.monotonic()
        with self._lock:
            self._assert_live(session, now)
            nonce = secrets.token_urlsafe(32)
            expires = min(now + MAX_CHALLENGE_SECONDS, session.lease_expires_monotonic)
            if expires <= now:
                self._close_state(session)
                raise _deny("remote.expired", "remote session expired before renewal challenge")
            session.renewal_nonce = nonce
            session.renewal_nonce_expires = expires
            return RemoteChallenge(1, session.session_id, nonce, expires)

    def renew_remote_session(self, remote_session_handle: str, access_jwt: bytes,
                             renewal_nonce: str, *, peer_uid: int, peer_pid: int,
                             peer_pidfd: int) -> RemoteLease:
        session = self._owned_session(remote_session_handle, peer_uid, peer_pid, peer_pidfd)
        now = self.monotonic()
        with self._lock:
            self._assert_live(session, now)
            expected = session.renewal_nonce
            nonce_expiry = session.renewal_nonce_expires
            # Consume before any verification so concurrent/replayed requests
            # cannot both renew the active stream.
            session.renewal_nonce = None
            session.renewal_nonce_expires = 0.0
            if (expected is None or not isinstance(renewal_nonce, str)
                    or now >= nonce_expiry or not secrets.compare_digest(expected, renewal_nonce)):
                self._close_state(session)
                raise _deny("remote.renewal", "renewal challenge is invalid, stale, or already consumed")
        try:
            identity = self.verifier.verify(access_jwt)
        except Exception:
            with self._lock:
                self._close_state(session)
            raise _deny("remote.renewal", "fresh protected Access renewal was denied") from None
        if (identity.subject != session.identity.subject or identity.email != session.identity.email
                or identity.policy_revision != self.enrollment.policy_revision
                or identity.policy_config_digest != self.enrollment.policy_config_digest
                or self.enrollment.principal_bindings_by_subject.get(identity.subject) != session.mapping):
            with self._lock:
                self._close_state(session)
            raise _deny("remote.renewal", "renewal identity, root mapping or current policy changed")
        with self._lock:
            self._assert_runtime(session.gateway)
            verified = self.monotonic()
            expiry = min(verified + self.enrollment.maximum_lease_seconds,
                         identity.jwt_expires_monotonic,
                         identity.policy_verified_monotonic + self.enrollment.maximum_lease_seconds)
            if expiry <= verified:
                self._close_state(session)
                raise _deny("remote.renewal", "fresh remote lease is already expired")
            session.identity = identity
            session.lease_expires_monotonic = expiry
            return self._lease(session)

    def close_remote_session(self, remote_session_handle: str, *, peer_uid: int,
                             peer_pid: int, peer_pidfd: int) -> RemoteCloseResponse:
        session = self._get(remote_session_handle)
        gateway = self._resolve_gateway(peer_uid, peer_pid, peer_pidfd)
        if gateway != session.gateway:
            raise _deny("remote.owner", "remote session belongs to a different registered gateway process")
        with self._lock:
            self._close_state(session)
        return RemoteCloseResponse(1, session.session_id)

    def open_remote_connector(self, remote_session_handle: str, *, peer_uid: int,
                              peer_pid: int, peer_pidfd: int) -> RemoteConnectorOpen:
        session = self._owned_session(remote_session_handle, peer_uid, peer_pid, peer_pidfd)
        if not session.connector_io_lock.acquire(timeout=0.05):
            raise _deny("remote.connector-busy", "another connector operation is active")
        try:
            with self._lock:
                self._assert_live(session, self.monotonic())
                if session.connector_opened:
                    raise _deny("remote.connector-replay", "remote connector is already open")
                binding = self._connector_binding(session)
                auth = self._authorize_connector(
                    binding, "connector.open", canonical_digest(_connector_effect_payload(
                        binding, "connector.open", sequence=0)),
                    0, 0, peer_uid, peer_pid, peer_pidfd)
            try:
                connector_handle = self.connector_backend.open(
                    binding, authorization=auth, peer_uid=peer_uid, peer_pid=peer_pid,
                    peer_pidfd=peer_pidfd)
            except Exception:
                with self._lock:
                    self._close_state(session)
                raise _deny("remote.connector", "root connector admission failed") from None
            _connector_token(connector_handle)
            with self._lock:
                if (session.closed or self.monotonic() >= binding.frame_deadline_monotonic
                        or self.monotonic() >= session.lease_expires_monotonic):
                    self._close_state(session)
                    expired = True
                else:
                    session.connector_handle = connector_handle
                    session.connector_opened = True
                    expired = False
            if expired:
                try:
                    self.connector_backend.close(binding, connector_handle, authorization=None, cleanup=True)
                except Exception:
                    pass
                raise _deny("remote.connector-deadline", "root connector open exceeded its frame deadline")
            return RemoteConnectorOpen(1, session.session_id, connector_handle,
                                       self.enrollment.desktop_generation,
                                       session.route_id, session.lease_expires_monotonic)
        finally:
            session.connector_io_lock.release()

    def read_remote_connector(self, remote_session_handle: str, connector_handle: str,
                              sequence: int, maximum_bytes: int, *, peer_uid: int,
                              peer_pid: int, peer_pidfd: int) -> RemoteConnectorRead:
        session = self._owned_connector(remote_session_handle, connector_handle,
                                        peer_uid, peer_pid, peer_pidfd)
        if not session.connector_io_lock.acquire(timeout=0.05):
            raise _deny("remote.connector-busy", "another connector operation is active")
        try:
            with self._lock:
                self._assert_frame(session, sequence, maximum_bytes)
                remaining = (MAX_ASSET_BYTES - session.total_asset_bytes
                             if session.action == "asset-read" else MAX_FRAME_BYTES)
                maximum_bytes = min(maximum_bytes, remaining)
                binding = self._connector_binding(session)
                auth = self._authorize_connector(
                    binding, "connector.read", canonical_digest(_connector_effect_payload(
                        binding, "connector.read", sequence=sequence,
                        maximum_bytes=maximum_bytes, connector_id=connector_handle)),
                    sequence, maximum_bytes, peer_uid, peer_pid, peer_pidfd)
            try:
                data, eof = self.connector_backend.read(
                    binding, connector_handle, sequence, maximum_bytes, authorization=auth,
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                    cancelled=binding.cancelled)
            except Exception:
                with self._lock:
                    self._close_state(session)
                raise _deny("remote.connector-read", "root connector read failed") from None
            with self._lock:
                if (session.closed or self.monotonic() >= binding.frame_deadline_monotonic
                        or self.monotonic() >= session.lease_expires_monotonic):
                    self._close_state(session)
                    raise _deny("remote.connector-deadline", "connector read was cancelled or expired")
                if (not isinstance(data, bytes) or len(data) > maximum_bytes or type(eof) is not bool
                        or session.action == "asset-read" and len(data) > remaining):
                    self._close_state(session)
                    raise _deny("remote.connector-read", "root connector returned an invalid bounded frame")
                session.next_sequence += 1
                session.total_asset_bytes += len(data)
                if session.action == "asset-read" and session.total_asset_bytes >= MAX_ASSET_BYTES and not eof:
                    self._close_state(session, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
                    raise _deny("remote.asset-bounds", "remote asset exceeded its enrolled response limit")
                if session.action == "asset-read" and eof:
                    self._close_state(session, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
                return RemoteConnectorRead(1, session.session_id, sequence, data, eof,
                                           session.lease_expires_monotonic)
        finally:
            session.connector_io_lock.release()

    def write_remote_connector(self, remote_session_handle: str, connector_handle: str,
                               sequence: int, data_bytes: bytes, *, peer_uid: int,
                               peer_pid: int, peer_pidfd: int) -> RemoteConnectorWrite:
        session = self._owned_connector(remote_session_handle, connector_handle,
                                        peer_uid, peer_pid, peer_pidfd)
        if not session.connector_io_lock.acquire(timeout=0.05):
            raise _deny("remote.connector-busy", "another connector operation is active")
        try:
            with self._lock:
                asset_request = session.action == "asset-read"
                if asset_request:
                    if session.asset_request_sent:
                        self._close_state(session)
                        raise _deny("remote.asset-replay", "asset admission allows one GET/HEAD request only")
                    try:
                        _validate_asset_fetch_request(data_bytes)
                    except AuthorityDenied:
                        self._close_state(session)
                        raise
                elif session.action != "websocket-attach":
                    raise _deny("remote.connector-write", "remote action does not permit connector writes")
                self._assert_frame(session, sequence, len(data_bytes) if isinstance(data_bytes, bytes) else 0)
                binding = self._connector_binding(session)
                payload_digest = canonical_digest(_connector_effect_payload(
                    binding, "connector.write", sequence=sequence,
                    connector_id=connector_handle, data_bytes=data_bytes))
                auth = self._authorize_connector(binding, "connector.write", payload_digest,
                                                 sequence, len(data_bytes), peer_uid, peer_pid, peer_pidfd)
                if asset_request:
                    # Consume before crossing the backend boundary so failures
                    # cannot replay a second fetch through the same admission.
                    session.asset_request_sent = True
            try:
                accepted = self.connector_backend.write(
                    binding, connector_handle, sequence, data_bytes, authorization=auth,
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                    cancelled=binding.cancelled)
            except Exception:
                with self._lock:
                    self._close_state(session)
                raise _deny("remote.connector-write", "root connector write failed") from None
            with self._lock:
                if (session.closed or self.monotonic() >= binding.frame_deadline_monotonic
                        or self.monotonic() >= session.lease_expires_monotonic):
                    self._close_state(session)
                    raise _deny("remote.connector-deadline", "connector write was cancelled or expired")
                if type(accepted) is not int or accepted != len(data_bytes):
                    self._close_state(session)
                    raise _deny("remote.connector-write", "root connector write was partial or malformed")
                session.next_sequence += 1
                return RemoteConnectorWrite(1, session.session_id, sequence, accepted,
                                            session.lease_expires_monotonic)
        finally:
            session.connector_io_lock.release()

    def close_remote_connector(self, remote_session_handle: str, connector_handle: str, *,
                               peer_uid: int, peer_pid: int, peer_pidfd: int) -> RemoteConnectorClose:
        session = self._owned_connector(remote_session_handle, connector_handle,
                                        peer_uid, peer_pid, peer_pidfd, allow_expired=True)
        with self._lock:
            self._close_state(session, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        return RemoteConnectorClose(1, session.session_id)

    def watchdog_once(self) -> None:
        now = self.monotonic()
        with self._lock:
            for session in tuple(self._sessions.values()):
                if session.closed:
                    continue
                try:
                    self._assert_runtime(session.gateway)
                    if now >= session.lease_expires_monotonic:
                        self._close_state(session)
                except Exception:
                    self._close_state(session)

    def _watchdog_loop(self) -> None:
        while not self._stop.wait(self.enrollment.watchdog_interval_seconds):
            try:
                self.watchdog_once()
            except Exception:
                # A failed state observation is fail-closed for every stream.
                with self._lock:
                    for session in tuple(self._sessions.values()):
                        self._close_state(session)

    def _resolve_gateway(self, uid: int, pid: int, pidfd: int) -> RemoteGatewayIdentity:
        try:
            identity = self.gateway_identity_resolver(uid, pid, pidfd)
        except Exception:
            raise _deny("remote.gateway", "kernel peer is not an enrolled live gateway") from None
        if (not isinstance(identity, RemoteGatewayIdentity) or identity.uid != uid or identity.pid != pid
                or identity.profile_id != self.enrollment.gateway_profile_id
                or identity.generation != self.enrollment.gateway_generation
                or identity.executable_sha256 != self.enrollment.gateway_role_sha256
                or identity.enrollment_id != self.enrollment.enrollment_id):
            raise _deny("remote.gateway", "kernel peer is not the enrolled gateway generation")
        try:
            current = self.gateway_identity_is_current(identity)
        except Exception:
            current = False
        if current is not True:
            raise _deny("remote.gateway", "registered gateway process identity is stale")
        return identity

    def _assert_runtime(self, gateway: RemoteGatewayIdentity) -> None:
        try:
            snapshot = self.runtime_state()
            alive = self.gateway_identity_is_current(gateway)
        except Exception:
            raise _deny("remote.state", "current remote enrollment could not be verified") from None
        if (not isinstance(snapshot, RemoteRuntimeState) or snapshot.active is not True or alive is not True
                or snapshot.enrollment_id != self.enrollment.enrollment_id
                or snapshot.policy_revision != self.enrollment.policy_revision
                or snapshot.policy_config_digest != self.enrollment.policy_config_digest
                or snapshot.gateway_generation != self.enrollment.gateway_generation
                or snapshot.desktop_generation != self.enrollment.desktop_generation
                or snapshot.native_profile_id != self.enrollment.native_desktop_profile_id
                or snapshot.native_generation != self.enrollment.native_generation
                or snapshot.gateway_role_sha256 != self.enrollment.gateway_role_sha256
                or snapshot.connector_target_id != self.enrollment.connector_target_id
                or snapshot.principal_mapping_digest != _principal_mapping_digest(self.enrollment.principal_bindings_by_subject)):
            raise _deny("remote.state", "remote policy, gateway, Desktop or connector enrollment changed")

    def _consume_request_nonce(self, request: RemoteAdmissionRequest, now: float) -> None:
        with self._lock:
            self._prune_nonces(now)
            key = hashlib.sha256((request.request_id + "\0" + request.client_nonce).encode()).hexdigest()
            if key in self._request_nonces:
                raise _deny("remote.replay", "remote admission request was replayed")
            if len(self._request_nonces) >= 8192:
                raise _deny("remote.capacity", "remote replay protection is at capacity")
            self._request_nonces[key] = now + 120.0

    def _prune_nonces(self, now: float) -> None:
        self._request_nonces = {key: expiry for key, expiry in self._request_nonces.items() if expiry > now}

    def _get(self, handle: str) -> _Session:
        _opaque(handle, "remote session handle")
        with self._lock:
            session = self._sessions.get(handle)
            if session is None:
                raise _deny("remote.session", "remote session is unknown or closed")
            return session

    def _owned_session(self, handle: str, uid: int, pid: int, pidfd: int) -> _Session:
        session = self._get(handle)
        gateway = self._resolve_gateway(uid, pid, pidfd)
        if gateway != session.gateway:
            raise _deny("remote.owner", "remote session belongs to a different registered gateway process")
        return session

    def _owned_connector(self, handle: str, connector_handle: str, uid: int, pid: int,
                         pidfd: int, *, allow_expired: bool = False) -> _Session:
        session = self._owned_session(handle, uid, pid, pidfd)
        _connector_token(connector_handle)
        with self._lock:
            if session.connector_handle != connector_handle:
                raise _deny("remote.connector-owner", "connector handle is not owned by this session")
            if allow_expired and not session.closed:
                # cleanup can close after lease expiry but still needs current root
                # identity; all actual reads/writes continue through _assert_live.
                self._assert_runtime(session.gateway)
            return session

    def _assert_live(self, session: _Session, now: float) -> None:
        if session.closed or now >= session.lease_expires_monotonic:
            self._close_state(session)
            raise _deny("remote.expired", "remote session lease is expired or revoked")
        self._assert_runtime(session.gateway)

    def validate_connector_binding(self, binding: RemoteConnectorBinding,
                                    operation: str, sequence: int) -> bool:
        """Backend callback: confirm this exact HI07 binding is still current.

        The connector adapter receives this closure from the root coordinator;
        no caller-provided context or gateway claim can satisfy the check.
        Cleanup close intentionally bypasses it and carries no bytes.
        """
        if (not isinstance(binding, RemoteConnectorBinding)
                or operation not in {"connector.open", "connector.read", "connector.write", "connector.close"}
                or type(sequence) is not int or sequence < 0):
            raise _deny("remote.connector-binding", "root connector binding is malformed")
        with self._lock:
            session = next((item for item in self._sessions.values()
                            if item.session_id == binding.session_id), None)
            if session is None:
                raise _deny("remote.connector-binding", "root connector session is unavailable")
            self._assert_live(session, self.monotonic())
            expected_operation = {
                "connector.open": 0,
                "connector.read": session.next_sequence,
                "connector.write": session.next_sequence,
                "connector.close": session.next_sequence,
            }[operation]
            if (sequence != expected_operation or binding.enrollment_id != self.enrollment.enrollment_id
                    or binding.action != session.action or binding.route_id != session.route_id
                    or binding.target_id != self.enrollment.connector_target_id
                    or binding.subject != session.identity.subject
                    or binding.principal_id != session.mapping.principal_id
                    or binding.profile_id != session.mapping.profile_id
                    or binding.profile_generation != session.mapping.profile_generation
                    or binding.gateway_identity != session.gateway
                    or binding.native_profile_id != self.enrollment.native_desktop_profile_id
                    or binding.native_generation != self.enrollment.native_generation
                    or binding.gateway_generation != self.enrollment.gateway_generation
                    or binding.lease_expires_monotonic != session.lease_expires_monotonic
                    or binding.frame_deadline_monotonic <= self.monotonic()):
                raise _deny("remote.connector-binding", "root connector binding no longer matches active enrollment")
            return True

    def _assert_frame(self, session: _Session, sequence: int, byte_count: int) -> None:
        self._assert_live(session, self.monotonic())
        if type(sequence) is not int or sequence != session.next_sequence:
            self._close_state(session)
            raise _deny("remote.frame-replay", "connector frame sequence is invalid or replayed")
        if type(byte_count) is not int or not 1 <= byte_count <= MAX_FRAME_BYTES:
            self._close_state(session)
            raise _deny("remote.frame-bounds", "connector frame exceeds its bound")

    def _connector_binding(self, session: _Session) -> RemoteConnectorBinding:
        now = self.monotonic()
        frame_deadline = min(session.lease_expires_monotonic, now + MAX_CONNECTOR_CALL_SECONDS)
        return RemoteConnectorBinding(
            enrollment_id=self.enrollment.enrollment_id,
            session_id=session.session_id, action=session.action, route_id=session.route_id,
            target_id=self.enrollment.connector_target_id, subject=session.identity.subject,
            principal_id=session.mapping.principal_id, profile_id=session.mapping.profile_id,
            profile_generation=session.mapping.profile_generation,
            gateway_profile_id=self.enrollment.gateway_profile_id,
            gateway_generation=self.enrollment.gateway_generation,
            native_profile_id=self.enrollment.native_desktop_profile_id,
            native_generation=self.enrollment.native_generation,
            gateway_identity=session.gateway, token_fingerprint=session.identity.token_fingerprint,
            issued_monotonic=session.issued_monotonic,
            lease_expires_monotonic=session.lease_expires_monotonic,
            frame_deadline_monotonic=frame_deadline,
            cancelled=lambda: self._cancelled(session.handle, frame_deadline))

    def _cancelled(self, handle: str, frame_deadline: float) -> bool:
        try:
            with self._lock:
                now = self.monotonic()
                session = self._sessions.get(handle)
                if (session is None or session.closed or now >= session.lease_expires_monotonic
                        or now >= frame_deadline):
                    return True
                self._assert_runtime(session.gateway)
                return False
        except Exception:
            return True

    def _lease(self, session: _Session) -> RemoteLease:
        return RemoteLease(1, RemoteSessionHandle(session.handle), session.session_id, session.lease_expires_monotonic,
                           session.identity.jwt_expires_monotonic,
                           session.identity.policy_verified_monotonic,
                           session.identity.policy_revision,
                           session.identity.policy_config_digest)

    def _close_connector(self, session: _Session, *, peer_uid: int | None = None,
                         peer_pid: int | None = None, peer_pidfd: int | None = None) -> None:
        handle = session.connector_handle
        if handle is None:
            return
        session.connector_handle = None
        binding = self._connector_binding(session)
        authorization = None
        cleanup = peer_uid is None or peer_pid is None or peer_pidfd is None
        try:
            authorization = self._authorize_connector(
                binding, "connector.close", canonical_digest(_connector_effect_payload(
                    binding, "connector.close", sequence=session.next_sequence,
                    connector_id=handle)),
                session.next_sequence, 0, peer_uid, peer_pid, peer_pidfd, cleanup=cleanup)
        except Exception:
            # Root cleanup is allowed to reap a retained connector even after
            # the original lease or identity can no longer mint a data grant.
            pass
        try:
            self.connector_backend.close(binding, handle, authorization=authorization,
                                         cleanup=authorization is None or cleanup)
        except Exception:
            # Closed state is retained even if effect cleanup reports failure;
            # root watchdog/connector owner independently reaps expired streams.
            pass

    def _close_state(self, session: _Session, *, peer_uid: int | None = None,
                     peer_pid: int | None = None, peer_pidfd: int | None = None) -> None:
        if session.closed:
            return
        session.renewal_nonce = None
        self._close_connector(session, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        session.closed = True

    def _authorize_connector(self, binding: RemoteConnectorBinding, operation: str,
                             request_digest: str, sequence: int, maximum_bytes: int,
                             peer_uid: int | None, peer_pid: int | None, peer_pidfd: int | None,
                             *, cleanup: bool = False) -> RemoteConnectorAuthorization:
        if operation not in {"connector.open", "connector.read", "connector.write", "connector.close"}:
            raise _deny("remote.connector-operation", "connector operation is not enrolled")
        peer_values = (peer_uid, peer_pid, peer_pidfd)
        if ((not cleanup and any(value is None for value in peer_values))
                or any(value is not None for value in peer_values) and any(value is None for value in peer_values)
                or not _DIGEST.fullmatch(request_digest)):
            raise _deny("remote.connector-peer", "connector grant requires current root peer identity")
        try:
            result = self.authorize_connector_operation(
                binding, operation, request_digest, sequence, maximum_bytes,
                peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd,
                cleanup=cleanup)
        except Exception:
            raise _deny("remote.connector-grant", "root could not authorize this exact connector operation") from None
        if not isinstance(result, RemoteConnectorAuthorization):
            raise _deny("remote.connector-grant", "root connector authorizer returned an invalid grant")
        expected = (operation, binding.target_id, request_digest, binding.session_id,
                    sequence, maximum_bytes, binding.route_id, binding.principal_id,
                    binding.profile_id, binding.profile_generation, binding.gateway_profile_id,
                    binding.gateway_generation, binding.native_profile_id, binding.native_generation)
        actual = (result.operation, result.target_id, result.request_digest, result.session_id,
                  result.sequence, result.maximum_bytes, result.route_id, result.principal_id,
                  result.profile_id, result.profile_generation, result.gateway_profile_id,
                  result.gateway_generation, result.native_profile_id, result.native_generation,
                  result.generation)
        expected += (binding.native_generation,)
        expected_deadline = (binding.lease_expires_monotonic if operation == "connector.open"
                             else binding.frame_deadline_monotonic)
        if (actual != expected or result.lease_expires_monotonic > binding.lease_expires_monotonic
                or result.deadline != expected_deadline
                or result.lease_expires_monotonic > expected_deadline
                or not cleanup and (self.monotonic() >= result.lease_expires_monotonic
                                    or self.monotonic() >= expected_deadline)):
            raise _deny("remote.connector-grant", "root connector grant binding or lease differs")
        return result


def _principal_mapping_digest(bindings: Mapping[str, RemotePrincipalBinding]) -> str:
    body = "\n".join("\0".join((key, value.email, value.principal_id,
                                value.profile_id, value.profile_generation))
                       for key, value in sorted(bindings.items()))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class RemoteAuthorityClient:
    """Typed helper over an authenticated root RPC callable.

    `rpc(operation, payload)` must be AuthorityClient's authenticated Unix RPC
    path. This wrapper is intentionally separate from client.py: it cannot pick
    peer identity or invoke generic operations, and keeps JWT bytes off argv.
    """

    def __init__(self, rpc: Callable[[str, Mapping[str, Any]], Mapping[str, Any]]):
        if not callable(rpc):
            raise ValueError("authenticated authority RPC callable is required")
        self._rpc = rpc

    def admit_remote_session(self, access_jwt: bytes,
                             request: RemoteAdmissionRequest) -> RemoteAdmissionResponse:
        if not isinstance(access_jwt, bytes) or not 1 <= len(access_jwt) <= MAX_JWT_BYTES:
            raise _deny("remote.jwt", "Access token size is invalid")
        if not isinstance(request, RemoteAdmissionRequest):
            raise _deny("remote.request", "typed remote admission request is required")
        payload = {"access_jwt_b64": base64.b64encode(access_jwt).decode("ascii"),
                   "request": request.to_wire()}
        return RemoteAdmissionResponse.from_wire(self._rpc("admit_remote_session", payload))

    def challenge_remote_session(self, handle: str) -> RemoteChallenge:
        _opaque(handle, "remote session handle")
        result = self._rpc("challenge_remote_session", {"remote_session_handle": handle})
        if not isinstance(result, Mapping) or set(result) != {"schema", "session_id", "renewal_nonce", "expires_monotonic"}:
            raise _deny("remote.response", "remote challenge fields are invalid")
        try:
            answer = RemoteChallenge(**dict(result))
            return answer
        except (ValueError, TypeError):
            raise _deny("remote.response", "remote challenge is malformed") from None

    def renew_remote_session(self, handle: str, access_jwt: bytes,
                             renewal_nonce: str) -> RemoteLease:
        _opaque(handle, "remote session handle")
        _opaque(renewal_nonce, "renewal nonce")
        if not isinstance(access_jwt, bytes) or not 1 <= len(access_jwt) <= MAX_JWT_BYTES:
            raise _deny("remote.jwt", "Access token size is invalid")
        result = self._rpc("renew_remote_session", {
            "remote_session_handle": handle,
            "access_jwt_b64": base64.b64encode(access_jwt).decode("ascii"),
            "renewal_nonce": renewal_nonce})
        lease = self._parse_lease(result)
        if not secrets.compare_digest(lease.remote_session_handle, handle):
            raise _deny("remote.response", "renewal response changed the root session handle")
        return lease

    def close_remote_session(self, handle: str) -> RemoteCloseResponse:
        _opaque(handle, "remote session handle")
        result = self._rpc("close_remote_session", {"remote_session_handle": handle})
        if not isinstance(result, Mapping) or set(result) != {"schema", "session_id", "state"}:
            raise _deny("remote.response", "remote close fields are invalid")
        if result["schema"] != 1 or result["state"] != "closed" or not _ID.fullmatch(result["session_id"]):
            raise _deny("remote.response", "remote close response is malformed")
        return RemoteCloseResponse(1, result["session_id"])

    def open_remote_connector(self, handle: str) -> RemoteConnectorOpen:
        _opaque(handle, "remote session handle")
        result = self._rpc("open_remote_connector", {"remote_session_handle": handle})
        fields = {"schema", "session_id", "connector_handle", "generation", "route_id", "expires_monotonic"}
        if not isinstance(result, Mapping) or set(result) != fields:
            raise _deny("remote.response", "remote connector open fields are invalid")
        try:
            answer = RemoteConnectorOpen(**dict(result))
            _connector_token(answer.connector_handle)
            _finite(answer.expires_monotonic, "connector expiry")
            return answer
        except (ValueError, TypeError):
            raise _deny("remote.response", "remote connector open response is malformed") from None

    def read_remote_connector(self, handle: str, connector_handle: str,
                              sequence: int, maximum_bytes: int) -> RemoteConnectorRead:
        _opaque(handle, "remote session handle")
        _connector_token(connector_handle)
        result = self._rpc("read_remote_connector", {
            "remote_session_handle": handle, "connector_handle": connector_handle,
            "sequence": sequence, "maximum_bytes": maximum_bytes})
        fields = {"schema", "session_id", "sequence", "data_bytes", "eof", "expires_monotonic"}
        if not isinstance(result, Mapping) or set(result) != fields or result.get("schema") != 1:
            raise _deny("remote.response", "remote connector read fields are invalid")
        try:
            raw = base64.b64decode(result["data_bytes"], validate=True)
            if len(raw) > maximum_bytes or type(result["eof"]) is not bool:
                raise ValueError
            return RemoteConnectorRead(1, result["session_id"], result["sequence"], raw,
                                       result["eof"], _finite(result["expires_monotonic"], "connector expiry"))
        except Exception:
            raise _deny("remote.response", "remote connector read response is malformed") from None

    def write_remote_connector(self, handle: str, connector_handle: str,
                               sequence: int, data_bytes: bytes) -> RemoteConnectorWrite:
        _opaque(handle, "remote session handle")
        _connector_token(connector_handle)
        if not isinstance(data_bytes, bytes) or len(data_bytes) > MAX_FRAME_BYTES:
            raise _deny("remote.frame-bounds", "connector write frame is invalid")
        result = self._rpc("write_remote_connector", {
            "remote_session_handle": handle, "connector_handle": connector_handle,
            "sequence": sequence, "data_bytes_b64": base64.b64encode(data_bytes).decode("ascii")})
        fields = {"schema", "session_id", "sequence", "accepted_bytes", "expires_monotonic"}
        if not isinstance(result, Mapping) or set(result) != fields or result.get("schema") != 1:
            raise _deny("remote.response", "remote connector write fields are invalid")
        return RemoteConnectorWrite(1, result["session_id"], result["sequence"],
                                   result["accepted_bytes"], _finite(result["expires_monotonic"], "connector expiry"))

    def close_remote_connector(self, handle: str, connector_handle: str) -> RemoteConnectorClose:
        _opaque(handle, "remote session handle")
        _connector_token(connector_handle)
        result = self._rpc("close_remote_connector", {
            "remote_session_handle": handle, "connector_handle": connector_handle})
        if not isinstance(result, Mapping) or set(result) != {"schema", "session_id", "state"}:
            raise _deny("remote.response", "remote connector close fields are invalid")
        if result.get("schema") != 1 or result.get("state") != "closed":
            raise _deny("remote.response", "remote connector close response is malformed")
        return RemoteConnectorClose(1, result["session_id"])

    @staticmethod
    def _parse_lease(result: Any) -> RemoteLease:
        fields = {"schema", "remote_session_handle", "session_id", "lease_expires_monotonic", "jwt_expires_monotonic",
                  "policy_verified_monotonic", "policy_revision", "policy_config_digest"}
        if not isinstance(result, Mapping) or set(result) != fields or result.get("schema") != 1:
            raise _deny("remote.response", "remote lease fields are invalid")
        try:
            payload = dict(result)
            payload["remote_session_handle"] = RemoteSessionHandle(payload["remote_session_handle"])
            return RemoteLease(**payload)
        except (TypeError, ValueError):
            raise _deny("remote.response", "remote lease is malformed") from None
