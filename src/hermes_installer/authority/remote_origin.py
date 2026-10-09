"""Root-owned Cloudflare tunnel token placement and native-origin readiness.

Only the active root catalog selects resources. Callers provide enrollment IDs;
paths, credentials, routes and process identities are resolved by injected
root-owned adapters. Receipts contain no credential, URL or filesystem path.
"""
from __future__ import annotations

import hashlib
import hmac
import base64
import json
import math
import os
import re
import secrets
import stat
import socket
import struct
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit
from dataclasses import dataclass, field, fields, replace as dataclass_replace
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


class RemoteOriginDenied(PermissionError):
    """Root could not prove the selected tunnel or confined origin is ready."""


class ReceiptSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class HMACReceiptSigner:
    """Small fixture signer; production should inject the authority key signer."""
    def __init__(self, key: bytes):
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("receipt signing key must contain at least 256 bits")
        self._key = key

    def sign(self, payload: bytes) -> bytes:
        return hmac.digest(self._key, payload, "sha256")

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


@dataclass(frozen=True, slots=True)
class SelectedTunnel:
    enrollment_id: str
    tunnel_id: str
    account_id: str
    generation: str
    sink_id: str
    secret_reference_id: str
    runtime_uid: int
    owned: bool


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedRemoteSetupTransaction:
    """Root-only, current transaction and exact API-response binding."""
    setup_transaction_handle_digest: str
    remote_enrollment_id: str
    tunnel_enrollment_id: str
    account_id: str
    tunnel_id: str
    generation: str
    setup_profile_id: str
    setup_generation: str
    setup_role_artifact_id: str
    setup_enrollment_id: str
    setup_role_sha256: str
    setup_transaction_policy_id: str
    token_writer_enrollment_id: str
    origin_probe_enrollment_id: str
    allowed_tunnel_enrollment_ids: tuple[str, ...]
    setup_peer_identity_digest: str
    one_use_stage_nonce: str
    response_token_sha256: str
    issued_monotonic: float
    expires_monotonic: float

    def __repr__(self) -> str:
        return "VerifiedRemoteSetupTransaction(<root-private>)"


@dataclass(frozen=True, slots=True)
class RemoteSetupWriterBinding:
    setup_profile_id: str
    setup_generation: str
    setup_role_artifact_id: str
    setup_role_sha256: str
    setup_enrollment_id: str
    setup_transaction_policy_id: str
    allowed_tunnel_enrollment_ids: tuple[str, ...]
    token_writer_enrollment_id: str
    origin_probe_enrollment_id: str


@dataclass(frozen=True, slots=True)
class RemoteOriginProbeBinding:
    profile_id: str
    generation: str
    role_artifact_id: str
    role_sha256: str
    enrollment_id: str
    control_socket_id: str


@dataclass(frozen=True, slots=True)
class SelectedRemoteOrigin:
    enrollment_id: str
    gateway_generation: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    expected_hostname: str
    expected_origin: str
    owned: bool
    gateway_profile_id: str = ""
    gateway_enrollment_id: str = ""
    gateway_role_sha256: str = ""
    native_profile_id: str = ""
    native_enrollment_id: str = ""
    setup_writer_binding: RemoteSetupWriterBinding | None = None
    probe_binding: RemoteOriginProbeBinding | None = None


class RemoteOriginCatalog(Protocol):
    """Resolver backed by the current root-owned active generation catalog."""
    def selected_tunnel(self, enrollment_id: str) -> SelectedTunnel: ...
    def selected_origin(self, enrollment_id: str) -> SelectedRemoteOrigin: ...
    def selected_origin_probe(self, enrollment_id: str) -> RemoteOriginProbeBinding: ...


class TunnelTokenWriter(Protocol):
    def write_provisioned_tunnel_token(self, enrollment_id: str, token: bytes, *,
            account_id: str, tunnel_id: str, generation: str,
            setup_transaction_handle: str) -> "ProtectedTunnelTokenReceipt": ...


class SecretResolver(Protocol):
    def resolve_tunnel_token(self, reference_id: str, tunnel_id: str) -> bytes: ...


class TokenJournal(Protocol):
    """Durable root journal; records only token digest and inode identity."""
    def lookup(self, enrollment_id: str) -> Mapping[str, Any] | None: ...
    def prepare(self, enrollment_id: str, entry: Mapping[str, Any]) -> int: ...
    def record(self, enrollment_id: str, entry: Mapping[str, Any]) -> int: ...


@dataclass(frozen=True, slots=True)
class ProtectedTunnelTokenReceipt:
    schema: int
    receipt_id: str
    tunnel_enrollment_id: str
    tunnel_id: str
    generation: str
    sink_id: str
    file_device: int
    file_inode: int
    owner_uid: int
    mode: int
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({item.name: getattr(self, item.name) for item in fields(self)
                           if item.name != "signature"})


@dataclass(frozen=True, slots=True)
class RootOriginReadinessReceipt:
    schema: int
    receipt_id: str
    remote_enrollment_id: str
    gateway_identity_digest: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    probe_receipt_handle: str
    observed_assertion_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({item.name: getattr(self, item.name) for item in fields(self)
                           if item.name != "signature"})


@dataclass(frozen=True, slots=True)
class KernelOriginEvidence:
    """Fresh facts from the root process manager, bound to pidfd and generation."""
    gateway_identity_digest: str
    gateway_generation: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    pidfd_live: bool
    pidfd_bound_to_process: bool
    start_time_stable: bool
    executable_pinned: bool
    cgroup_pinned: bool
    namespace_pinned: bool
    mount_pinned: bool
    observed_assertion_ids: tuple[str, ...]
    expires_monotonic: float = float("inf")


@dataclass(frozen=True, slots=True)
class RemoteOriginProcessIdentity:
    profile_id: str
    enrollment_id: str
    generation: str
    uid: int
    gid: int
    pid: int
    pid_starttime_ticks: int
    executable_device: int
    executable_inode: int
    executable_sha256: str
    cgroup_id: str
    mount_namespace_inode: int
    network_namespace_inode: int
    pidfd_registry_handle: str = field(repr=False)
    expires_monotonic: float


class RemoteOriginProcessManager(Protocol):
    def inspect_selected_origin(self, enrollment: SelectedRemoteOrigin) -> KernelOriginEvidence: ...
    def inspect_gateway_peer(self, enrollment: SelectedRemoteOrigin) -> RemoteOriginProcessIdentity: ...


class CustodyRemoteOriginProcessManager:
    """Production adapter over the root process custodian's PIDFD inspection API."""
    def __init__(self, custody: Any, *, monotonic: Callable[[], float] = time.monotonic):
        if not callable(getattr(custody, "inspect_enrolled_process", None)):
            raise ValueError("root process custodian lacks enrolled PIDFD inspection")
        self._custody, self._monotonic = custody, monotonic

    def inspect_selected_origin(self, enrollment: SelectedRemoteOrigin) -> KernelOriginEvidence:
        if not isinstance(enrollment, SelectedRemoteOrigin):
            raise RemoteOriginDenied("root selected remote-origin enrollment is required")
        specs = ((enrollment.gateway_profile_id, enrollment.gateway_generation,
                  enrollment.gateway_enrollment_id, enrollment.gateway_role_sha256, "gateway"),
                 (enrollment.native_profile_id, enrollment.desktop_generation,
                  enrollment.native_enrollment_id, None, "native-desktop"))
        proofs: list[Mapping[str, Any]] = []
        for profile_id, generation, enrollment_id, expected_sha, label in specs:
            if not profile_id or not enrollment_id:
                raise RemoteOriginDenied(f"selected {label} process enrollment is unavailable")
            try:
                proof = self._custody.inspect_enrolled_process(profile_id, generation)
            except Exception:
                raise RemoteOriginDenied(f"root {label} process inspection failed") from None
            required = ("process_id", "enrollment_id", "profile_id", "profile_generation",
                        "uid", "gid", "pid", "pid_starttime_ticks", "executable_device",
                        "executable_inode", "executable_sha256", "cgroup_id",
                        "mount_namespace_inode", "network_namespace_inode",
                        "pidfd_registry_handle", "expires_monotonic")
            if (proof is None or any(not hasattr(proof, name) for name in required)
                    or proof.enrollment_id != enrollment_id or proof.profile_id != profile_id
                    or proof.profile_generation != generation
                    or expected_sha is not None and proof.executable_sha256 != expected_sha
                    or proof.expires_monotonic <= self._monotonic()
                    or proof.pid <= 0 or proof.pid_starttime_ticks <= 0
                    or proof.executable_device <= 0 or proof.executable_inode <= 0
                    or proof.mount_namespace_inode <= 0 or proof.network_namespace_inode <= 0
                    or not proof.pidfd_registry_handle):
                raise RemoteOriginDenied(f"root {label} process proof is absent or mismatched")
            proofs.append({name: getattr(proof, name) for name in required})
        gateway, desktop = proofs
        identity_digest = hashlib.sha256(_canonical({"gateway": gateway, "desktop": desktop,
            "selected_remote_enrollment": enrollment.enrollment_id,
            "policy_config_digest": enrollment.policy_config_digest,
            "policy_revision": enrollment.policy_revision,
            "service_generation_digest": enrollment.service_generation_digest,
            "connector_target_id": enrollment.connector_target_id})).hexdigest()
        expires = min(float(gateway["expires_monotonic"]), float(desktop["expires_monotonic"]))
        return KernelOriginEvidence(
            identity_digest, enrollment.gateway_generation, enrollment.desktop_generation,
            enrollment.connector_target_id, enrollment.policy_config_digest,
            enrollment.policy_revision, enrollment.service_generation_digest,
            True, True, True, True, True, True, True,
            ("custody:gateway-pidfd", "custody:gateway-cgroup", "custody:gateway-namespaces",
             "custody:native-pidfd", "custody:native-cgroup", "custody:native-namespaces"), expires)

    def inspect_gateway_peer(self, enrollment: SelectedRemoteOrigin) -> RemoteOriginProcessIdentity:
        """Return the current custody-verified identity expected on the private socket."""
        proof = self._custody.inspect_enrolled_process(enrollment.gateway_profile_id,
                                                       enrollment.gateway_generation)
        required = ("profile_id", "enrollment_id", "profile_generation", "uid", "gid", "pid",
                    "pid_starttime_ticks", "executable_device", "executable_inode",
                    "executable_sha256", "cgroup_id", "mount_namespace_inode",
                    "network_namespace_inode", "pidfd_registry_handle", "expires_monotonic")
        if (proof is None or any(not hasattr(proof, name) for name in required)
                or proof.profile_id != enrollment.gateway_profile_id
                or proof.enrollment_id != enrollment.gateway_enrollment_id
                or proof.profile_generation != enrollment.gateway_generation
                or proof.executable_sha256 != enrollment.gateway_role_sha256
                or not _finite_monotonic(proof.expires_monotonic)
                or proof.expires_monotonic <= self._monotonic()
                or proof.uid <= 0 or proof.gid < 0
                or min(proof.pid, proof.pid_starttime_ticks,
                       proof.executable_device, proof.executable_inode,
                       proof.mount_namespace_inode, proof.network_namespace_inode) <= 0
                or not proof.pidfd_registry_handle):
            raise RemoteOriginDenied("selected gateway process identity is absent or stale")
        return RemoteOriginProcessIdentity(
            proof.profile_id, proof.enrollment_id, proof.profile_generation,
            proof.uid, proof.gid, proof.pid, proof.pid_starttime_ticks,
            proof.executable_device, proof.executable_inode, proof.executable_sha256,
            proof.cgroup_id, proof.mount_namespace_inode, proof.network_namespace_inode,
            proof.pidfd_registry_handle, float(proof.expires_monotonic))


ORIGIN_PROBE_OBSERVATIONS = frozenset({
    "loopback_only", "unauthenticated_denied", "authorized_asset_served",
    "authorized_websocket_attached", "official_desktop_window_observed",
    "arbitrary_route_denied", "shell_route_denied", "full_host_desktop_denied",
})
_MAX_PROBE_FRAME = 64 * 1024
_PROBE_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_PROBE_ACTIONS = {"asset-get", "asset-head", "websocket-attach"}


@dataclass(frozen=True, slots=True)
class OriginProbeActionControlRequest:
    """Exact private per-action wire; all selection stays in the child handle."""
    schema: int
    probe_handle: str
    action: str
    asset_id: str | None

    @classmethod
    def create(cls, probe_handle: str, action: str,
               asset_id: str | None) -> "OriginProbeActionControlRequest":
        _opaque_handle(probe_handle, "root per-action probe handle")
        if (action not in _PROBE_ACTIONS
                or (action == "websocket-attach") != (asset_id is None)
                or (asset_id is not None and asset_id not in _remote_probe_asset_paths())):
            raise RemoteOriginDenied("private origin probe action differs from the fixed selection")
        return cls(1, probe_handle, action, asset_id)

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "probe_handle": self.probe_handle,
                "action": self.action, "asset_id": self.asset_id}


def _remote_probe_asset_paths() -> dict[str, str]:
    """Map opaque stable IDs to the pinned client manifest, never wire paths."""
    from ..remote.client_assets import CLIENT_ASSETS
    result = {}
    for path in sorted(CLIENT_ASSETS):
        encoded = path.encode("ascii", "strict")
        opaque_id = hashlib.sha256(b"hermes-client-asset-v1\0" + encoded).hexdigest()
        result[opaque_id] = path
    return result


def resolve_probe_asset_path(binding: Any, asset_id: str) -> str:
    """Resolve an opaque selected asset ID inside root-only connector code."""
    from .remote_probe_connector_authority import RootSetupProbeBinding
    if (not isinstance(binding, RootSetupProbeBinding)
            or not isinstance(asset_id, str) or asset_id not in binding.asset_ids):
        raise RemoteOriginDenied("setup probe asset is outside its root-pinned manifest")
    path = _remote_probe_asset_paths().get(asset_id)
    if path is None:
        raise RemoteOriginDenied("setup probe asset ID is absent from the pinned manifest")
    return path


@dataclass(frozen=True, slots=True, repr=False)
class SelectedRemoteOriginControlSocket:
    """Root-resolved gateway control socket identity; the path is never serialized."""
    path: Path = field(repr=False)
    device: int
    inode: int
    owner_uid: int
    gateway_profile_id: str
    gateway_generation: str


class RemoteOriginControlSocketResolver(Protocol):
    def resolve(self, selected: SelectedRemoteOrigin) -> SelectedRemoteOriginControlSocket: ...


class ActiveCatalogControlSocketResolver:
    """Resolve a socket only by a root-selected enrollment reference."""
    def __init__(self, catalog: RemoteOriginCatalog):
        self._catalog = catalog

    def resolve(self, selected: SelectedRemoteOrigin) -> SelectedRemoteOriginControlSocket:
        binding = selected.probe_binding
        if not isinstance(binding, RemoteOriginProbeBinding):
            raise RemoteOriginDenied("selected private origin-probe role is unavailable")
        resolver = getattr(self._catalog, "selected_origin_control_socket", None)
        if not callable(resolver):
            raise RemoteOriginDenied("active catalog has no selected private control socket")
        socket_binding = resolver(binding.control_socket_id)
        if (not isinstance(socket_binding, SelectedRemoteOriginControlSocket)
                or socket_binding.gateway_profile_id != selected.gateway_profile_id
                or socket_binding.gateway_generation != selected.gateway_generation):
            raise RemoteOriginDenied("private control socket is not bound to the selected gateway")
        _validate_control_socket(socket_binding)
        return socket_binding


def _validate_control_socket(binding: SelectedRemoteOriginControlSocket) -> os.stat_result:
    path = binding.path
    if (not isinstance(path, Path) or not path.is_absolute()
            or len(os.fsencode(path)) >= 104):
        raise RemoteOriginDenied("selected private control socket path is invalid")
    current = Path(path.anchor)
    for part in path.parts[1:-1]:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            raise RemoteOriginDenied("private control socket parent is unavailable") from None
        if (stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
                or st.st_mode & 0o022):
            raise RemoteOriginDenied("private control socket parent is unsafe")
    try:
        st = path.lstat()
    except OSError:
        raise RemoteOriginDenied("selected private control socket is unavailable") from None
    if (not stat.S_ISSOCK(st.st_mode) or st.st_dev != binding.device
            or st.st_ino != binding.inode or st.st_uid != binding.owner_uid
            or stat.S_IMODE(st.st_mode) & 0o077):
        raise RemoteOriginDenied("selected private control socket identity or mode changed")
    return st


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = sock.recv(size - len(chunks))
        if not part:
            raise RemoteOriginDenied("private origin control stream closed early")
        chunks.extend(part)
    return bytes(chunks)


def _strict_json_object(raw: bytes) -> Mapping[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise RemoteOriginDenied("private origin control response is malformed") from None
    if not isinstance(value, dict):
        raise RemoteOriginDenied("private origin control response is not an object")
    return value


@dataclass(frozen=True, slots=True)
class RemoteOriginCallerIdentity:
    uid: int
    pid: int
    pid_starttime_ticks: int
    profile_id: str
    generation: str
    executable_sha256: str
    cgroup_id: str
    pidfd_registry_handle: str = field(repr=False)
    expires_monotonic: float

    def digest(self) -> str:
        return hashlib.sha256(_canonical({
            "uid": self.uid, "pid": self.pid, "pid_starttime_ticks": self.pid_starttime_ticks,
            "profile_id": self.profile_id, "generation": self.generation,
            "executable_sha256": self.executable_sha256, "cgroup_id": self.cgroup_id,
            "pidfd_registry_handle": self.pidfd_registry_handle,
        })).hexdigest()


class CurrentRemoteOriginCaller(Protocol):
    def current(self) -> RemoteOriginCallerIdentity: ...


class RemoteSetupTransactionVerifier(Protocol):
    def verify_origin_probe_transaction(self, handle: str, selected: SelectedRemoteOrigin,
            caller: RemoteOriginCallerIdentity) -> VerifiedRemoteSetupTransaction: ...


@dataclass(frozen=True, slots=True)
class RootOriginProbeReceipt:
    schema: int
    probe_receipt_handle: str
    remote_enrollment_id: str
    setup_transaction_digest: str
    setup_peer_identity_digest: str
    probe_process_identity_digest: str
    gateway_identity_digest: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    request_digest: str
    result_digest: str
    observed_assertion_ids: tuple[str, ...]
    observations: tuple[tuple[str, bool], ...]
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({item.name: getattr(self, item.name) for item in fields(self)
                           if item.name != "signature"})


@dataclass(frozen=True, slots=True)
class OriginProbeControlRequest:
    schema: int
    operation: str
    probe_handle: str
    sequence: int
    challenge: str
    remote_enrollment_id: str
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    request_digest: str

    @classmethod
    def create(cls, selected: SelectedRemoteOrigin, handle: str,
               challenge: str, sequence: int) -> "OriginProbeControlRequest":
        fields_value = dict(schema=1, operation="probe_selected_origin", probe_handle=handle,
            sequence=sequence, challenge=challenge,
            remote_enrollment_id=selected.enrollment_id,
            gateway_profile_id=selected.gateway_profile_id,
            gateway_generation=selected.gateway_generation,
            native_profile_id=selected.native_profile_id,
            desktop_generation=selected.desktop_generation,
            connector_target_id=selected.connector_target_id,
            policy_config_digest=selected.policy_config_digest,
            policy_revision=selected.policy_revision,
            service_generation_digest=selected.service_generation_digest)
        digest = hashlib.sha256(_canonical(fields_value)).hexdigest()
        return cls(**fields_value, request_digest=digest)

    def to_wire(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}


@dataclass(frozen=True, slots=True)
class OriginProbeControlResponse:
    schema: int
    operation: str
    probe_handle: str
    sequence: int
    challenge: str
    request_digest: str
    remote_enrollment_id: str
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    observations: Mapping[str, bool]
    observed_assertion_ids: tuple[str, ...]
    asset_content_sha256: str
    websocket_observation_id: str
    native_window_observation_id: str

    @classmethod
    def from_wire(cls, value: Mapping[str, Any]) -> "OriginProbeControlResponse":
        required = {"schema", "operation", "probe_handle", "sequence", "challenge",
            "request_digest", "remote_enrollment_id", "gateway_profile_id", "gateway_generation",
            "native_profile_id", "desktop_generation", "connector_target_id", "policy_config_digest",
            "policy_revision", "service_generation_digest", "observations", "observed_assertion_ids",
            "asset_content_sha256", "websocket_observation_id", "native_window_observation_id"}
        if not isinstance(value, Mapping) or set(value) != required:
            raise RemoteOriginDenied("private gateway probe response fields are invalid")
        observations = value["observations"]
        assertions = value["observed_assertion_ids"]
        if (not isinstance(observations, Mapping) or set(observations) != ORIGIN_PROBE_OBSERVATIONS
                or any(type(observations[key]) is not bool for key in ORIGIN_PROBE_OBSERVATIONS)
                or not isinstance(assertions, list) or not 1 <= len(assertions) <= 32
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", item)
                       for item in assertions)):
            raise RemoteOriginDenied("private gateway probe evidence map is malformed")
        try:
            return cls(**{**value, "observations": dict(observations),
                          "observed_assertion_ids": tuple(assertions)})
        except (TypeError, ValueError):
            raise RemoteOriginDenied("private gateway probe response could not be typed") from None

    def to_wire(self) -> dict[str, Any]:
        result = {item.name: getattr(self, item.name) for item in fields(self)}
        result["observed_assertion_ids"] = list(self.observed_assertion_ids)
        return result


class ProbeObservationMap(Mapping[str, bool]):
    """Eight-key public observation view; receipt handle remains opaque metadata."""
    __slots__ = ("_values", "probe_receipt_handle")

    def __init__(self, values: Mapping[str, bool], probe_receipt_handle: str):
        self._values = dict(values)
        self.probe_receipt_handle = probe_receipt_handle

    def __getitem__(self, key: str) -> bool:
        return self._values[key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:
        return "ProbeObservationMap(<root-verified>)"


@dataclass(slots=True, repr=False)
class _ProbeHandleRecord:
    handle: str
    selected: SelectedRemoteOrigin
    setup_transaction: VerifiedRemoteSetupTransaction
    setup_transaction_handle: str = field(repr=False)
    setup_caller_identity: RemoteOriginCallerIdentity = field(repr=False)
    setup_peer_digest: str
    probe_process_identity_digest: str
    kernel_evidence: KernelOriginEvidence
    session_id: str = field(repr=False)
    issued: float
    expires: float
    state: str = "issued"
    receipt: RootOriginProbeReceipt | None = None
    result: Mapping[str, bool] | None = None
    action_sequence: int = 0


@dataclass(slots=True, repr=False)
class _ProbeActionHandleRecord:
    handle: str
    parent: _ProbeHandleRecord
    action: str
    asset_id: str | None
    issued: float
    expires: float
    state: str = "issued"
    effect_sequence: int = 0
    frame_sequence: int = 0
    connector_handle: str | None = field(default=None, repr=False)


class RootOriginProbeRegistry:
    """Root-private, single-use probe and signed observation receipt registry."""
    def __init__(self, signer: ReceiptSigner, *, now: Callable[[], float] = time.monotonic):
        self._signer, self._now = signer, now
        self._lock = threading.RLock()
        self._handles: dict[str, _ProbeHandleRecord] = {}
        self._action_handles: dict[str, _ProbeActionHandleRecord] = {}
        self._receipts: dict[str, RootOriginProbeReceipt] = {}

    def issue(self, selected: SelectedRemoteOrigin, transaction: VerifiedRemoteSetupTransaction,
              peer_digest: str, probe_process_digest: str,
              evidence: KernelOriginEvidence, *, setup_transaction_handle: str,
              setup_caller_identity: RemoteOriginCallerIdentity) -> str:
        issued = float(self._now())
        expires = min(issued + 30.0, transaction.expires_monotonic,
                      evidence.expires_monotonic)
        if not _finite_monotonic(issued) or not _finite_monotonic(expires) or expires <= issued:
            raise RemoteOriginDenied("selected remote probe has no fresh bounded lifetime")
        handle = secrets.token_urlsafe(32)
        session_id = "setup-probe:" + secrets.token_urlsafe(24)
        with self._lock:
            self._handles[handle] = _ProbeHandleRecord(
                handle=handle, selected=selected, setup_transaction=transaction,
                setup_transaction_handle=setup_transaction_handle,
                setup_caller_identity=setup_caller_identity,
                setup_peer_digest=peer_digest,
                probe_process_identity_digest=probe_process_digest,
                kernel_evidence=evidence, session_id=session_id, issued=issued,
                expires=math.nextafter(expires, -math.inf))
        return handle

    def authorize_action(self, parent_handle: str, action: str,
                         asset_id: str | None) -> str:
        """Mint a child handle whose action and asset cannot change in transit."""
        if action not in {"asset-get", "asset-head", "websocket-attach"}:
            raise RemoteOriginDenied("setup probe action is outside the fixed route set")
        if (action == "websocket-attach") != (asset_id is None):
            raise RemoteOriginDenied("setup probe action and asset selection disagree")
        if asset_id is not None and asset_id not in _remote_probe_asset_paths():
            raise RemoteOriginDenied("setup probe asset ID is not in the pinned manifest")
        with self._lock:
            parent = self._handles.get(parent_handle)
            now = float(self._now())
            if (parent is None or parent.state != "running" or now >= parent.expires
                    or parent.action_sequence >= 16):
                raise RemoteOriginDenied("root setup probe is absent, expired, or at its action bound")
            child = secrets.token_urlsafe(32)
            self._action_handles[child] = _ProbeActionHandleRecord(
                child, parent, action, asset_id, now,
                math.nextafter(parent.expires, -math.inf))
            parent.action_sequence += 1
            return child

    def resolve_action(self, handle: str) -> _ProbeActionHandleRecord:
        with self._lock:
            action = self._action_handles.get(handle)
            now = float(self._now())
            if (action is None or action.state not in {"issued", "running"}
                    or now >= action.expires or action.parent.state != "running"
                    or now >= action.parent.expires):
                raise RemoteOriginDenied("root setup-probe action handle is absent, stale, or spent")
            return action

    def resolve_parent(self, handle: str) -> _ProbeHandleRecord:
        with self._lock:
            parent = self._handles.get(handle)
            now = float(self._now())
            if (parent is None or parent.state != "running" or now >= parent.expires):
                raise RemoteOriginDenied("root setup probe is absent, expired, or inactive")
            return parent

    def action_cancelled(self, handle: str) -> bool:
        with self._lock:
            action = self._action_handles.get(handle)
            now = float(self._now())
            return bool(action is None or action.state in {"cancelled", "consumed"}
                        or now >= action.expires or action.parent.state != "running"
                        or now >= action.parent.expires)

    def advance_connector_effect(self, handle: str, operation: str, effect_sequence: int,
                                 frame_sequence: int,
                                 connector_handle: str | None) -> bool:
        """CAS both post-effect and HI07 frame counters after a full syscall."""
        with self._lock:
            action = self._action_handles.get(handle)
            if (action is None or action.state in {"cancelled", "consumed"}
                    or float(self._now()) >= action.expires
                    or action.parent.state != "running"):
                raise RemoteOriginDenied("setup probe connector effect lost its live handle")
            if operation == "connector.open":
                if (action.state != "issued" or effect_sequence != 0 or frame_sequence != 0
                        or not isinstance(connector_handle, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", connector_handle)):
                    action.state = "cancelled"
                    raise RemoteOriginDenied("setup probe connector open state is invalid")
                action.connector_handle = connector_handle
                action.state = "running"
                action.effect_sequence += 1
                return True
            if (action.state != "running" or action.connector_handle != connector_handle
                    or type(effect_sequence) is not int
                    or effect_sequence != action.effect_sequence
                    or type(frame_sequence) is not int
                    or frame_sequence != action.frame_sequence
                    or operation not in {"connector.read", "connector.write", "connector.close"}):
                action.state = "cancelled"
                raise RemoteOriginDenied("setup probe connector sequence changed")
            if operation == "connector.close":
                action.effect_sequence += 1
                action.state = "consumed"
                return True
            action.effect_sequence += 1
            action.frame_sequence += 1
            return True

    def cancel_action(self, handle: str) -> None:
        with self._lock:
            action = self._action_handles.get(handle)
            if action is not None:
                action.state = "cancelled"

    def consume_action(self, handle: str) -> None:
        with self._lock:
            action = self._action_handles.get(handle)
            if action is None or action.state not in {"issued", "running"}:
                raise RemoteOriginDenied("root setup-probe action handle was already spent")
            action.state = "consumed"

    def begin(self, handle: str, selected: SelectedRemoteOrigin,
              peer_digest: str) -> tuple[_ProbeHandleRecord, str, int]:
        with self._lock:
            record = self._handles.get(handle)
            now = float(self._now())
            if (record is None or record.state != "issued" or now >= record.expires
                    or _selection_digest(record.selected) != _selection_digest(selected)
                    or not hmac.compare_digest(record.setup_peer_digest, peer_digest)):
                raise RemoteOriginDenied("root origin probe handle is absent, stale, reused, or mismatched")
            record.state = "running"
            challenge = secrets.token_urlsafe(32)
            return record, challenge, 1

    def complete(self, record: _ProbeHandleRecord, response: Mapping[str, Any],
                 request_digest: str) -> ProbeObservationMap:
        observations = response["observations"]
        response_bytes = _canonical(dict(response))
        result_digest = hashlib.sha256(response_bytes).hexdigest()
        issued = float(self._now())
        expiry = min(record.expires, issued + 30.0)
        handle = secrets.token_urlsafe(32)
        unsigned = dict(schema=1, probe_receipt_handle=handle,
            remote_enrollment_id=record.selected.enrollment_id,
            setup_transaction_digest=_setup_transaction_digest(record.setup_transaction),
            setup_peer_identity_digest=record.setup_peer_digest,
            probe_process_identity_digest=record.probe_process_identity_digest,
            gateway_identity_digest=record.kernel_evidence.gateway_identity_digest,
            desktop_generation=record.selected.desktop_generation,
            connector_target_id=record.selected.connector_target_id,
            policy_config_digest=record.selected.policy_config_digest,
            policy_revision=record.selected.policy_revision,
            service_generation_digest=record.selected.service_generation_digest,
            request_digest=request_digest, result_digest=result_digest,
            observed_assertion_ids=tuple(response["observed_assertion_ids"]),
            observations=tuple((key, observations[key]) for key in sorted(ORIGIN_PROBE_OBSERVATIONS)),
            issued_monotonic=issued, expires_monotonic=math.nextafter(expiry, -math.inf))
        provisional = RootOriginProbeReceipt(**unsigned, signature=b"")
        receipt = RootOriginProbeReceipt(**unsigned, signature=self._signer.sign(provisional.payload()))
        with self._lock:
            if record.state != "running" or self._handles.get(record.handle) is not record:
                raise RemoteOriginDenied("root probe registration state changed")
            record.state, record.receipt, record.result = "ready", receipt, dict(observations)
            self._receipts[handle] = receipt
        return ProbeObservationMap(observations, handle)

    def resolve_ready(self, probe_handle: str, selected: SelectedRemoteOrigin,
                      peer_digest: str) -> tuple[RootOriginProbeReceipt, Mapping[str, bool]]:
        with self._lock:
            record = self._handles.get(probe_handle)
            if (record is None or record.state != "ready" or record.receipt is None
                    or record.result is None or float(self._now()) >= record.receipt.expires_monotonic
                    or _selection_digest(record.selected) != _selection_digest(selected)
                    or not hmac.compare_digest(record.setup_peer_digest, peer_digest)):
                raise RemoteOriginDenied("root probe receipt is absent, expired, or mismatched")
            receipt = self._receipts.get(record.receipt.probe_receipt_handle)
            if receipt is not record.receipt or not self._signer.verify(receipt.payload(), receipt.signature):
                raise RemoteOriginDenied("root probe receipt signature or registry binding failed")
            record.state = "consumed"
            return receipt, dict(record.result)


def _selection_digest(selected: SelectedRemoteOrigin) -> str:
    return hashlib.sha256(_canonical({
        "remote_enrollment_id": selected.enrollment_id,
        "gateway_generation": selected.gateway_generation,
        "desktop_generation": selected.desktop_generation,
        "gateway_profile_id": selected.gateway_profile_id,
        "gateway_enrollment_id": selected.gateway_enrollment_id,
        "gateway_role_sha256": selected.gateway_role_sha256,
        "native_profile_id": selected.native_profile_id,
        "native_enrollment_id": selected.native_enrollment_id,
        "connector_target_id": selected.connector_target_id,
        "policy_config_digest": selected.policy_config_digest,
        "policy_revision": selected.policy_revision,
        "service_generation_digest": selected.service_generation_digest,
        "expected_hostname": selected.expected_hostname,
        "expected_origin": selected.expected_origin,
        "setup_writer_binding": ({item.name: getattr(selected.setup_writer_binding, item.name)
            for item in fields(selected.setup_writer_binding)}
            if isinstance(selected.setup_writer_binding, RemoteSetupWriterBinding) else None),
        "probe_binding": ({"profile_id": selected.probe_binding.profile_id,
            "generation": selected.probe_binding.generation,
            "role_artifact_id": selected.probe_binding.role_artifact_id,
            "role_sha256": selected.probe_binding.role_sha256,
            "enrollment_id": selected.probe_binding.enrollment_id,
            "control_socket_id": selected.probe_binding.control_socket_id}
            if isinstance(selected.probe_binding, RemoteOriginProbeBinding) else None),
    })).hexdigest()


def _setup_transaction_digest(proof: VerifiedRemoteSetupTransaction) -> str:
    return hashlib.sha256(_canonical({
        item.name: getattr(proof, item.name) for item in fields(proof)
        if item.name != "response_token_sha256"
    })).hexdigest()


class PrivateGatewayOriginProbe:
    """Root-only finite AF_UNIX probe client for the pinned gateway control server."""
    def __init__(self, *, socket_resolver: RemoteOriginControlSocketResolver,
                 process_manager: RemoteOriginProcessManager,
                 registry: RootOriginProbeRegistry,
                 current_peer: CurrentRemoteOriginCaller,
                 custody: Any,
                 now: Callable[[], float] = time.monotonic,
                 peer_credentials: Callable[[socket.socket], tuple[int, int, int]] | None = None,
                 timeout_seconds: float = 5.0):
        if not 0.1 <= timeout_seconds <= 5.0:
            raise ValueError("origin probe socket timeout must be <=5 seconds")
        self._socket_resolver, self._process_manager = socket_resolver, process_manager
        self._registry, self._current_peer, self._custody, self._now = registry, current_peer, custody, now
        self._peer_credentials = peer_credentials
        self._timeout = timeout_seconds

    def _verify_server_peer(self, sock: socket.socket, expected: RemoteOriginProcessIdentity) -> None:
        if self._peer_credentials is not None:
            try:
                pid, uid, gid = self._peer_credentials(sock)
            except Exception:
                raise RemoteOriginDenied("private gateway peer credentials are unavailable") from None
        else:
            if not hasattr(socket, "SO_PEERCRED"):
                raise RemoteOriginDenied("kernel peer PID credentials are unavailable on this platform")
            try:
                pid, uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET,
                    socket.SO_PEERCRED, struct.calcsize("3i")))
            except OSError:
                raise RemoteOriginDenied("private gateway peer credentials are unavailable") from None
        if pid != expected.pid or uid != expected.uid or gid != expected.gid:
            raise RemoteOriginDenied("private gateway control peer is not the selected process")

    def probe_selected_app(self, enrollment: SelectedRemoteOrigin,
                           root_probe_handle: str) -> ProbeObservationMap:
        _opaque_handle(root_probe_handle, "root origin probe handle")
        caller = self._current_peer.current()
        record, challenge, sequence = self._registry.begin(
            root_probe_handle, enrollment, caller.digest())
        fresh_kernel = self._process_manager.inspect_selected_origin(enrollment)
        if (fresh_kernel.gateway_identity_digest != record.kernel_evidence.gateway_identity_digest
                or fresh_kernel.expires_monotonic <= float(self._now())):
            raise RemoteOriginDenied("selected gateway/native process identity changed before probing")
        probe_identity = _selected_probe_process_identity(self._custody, enrollment, now=self._now)
        if probe_identity[0] != record.probe_process_identity_digest:
            raise RemoteOriginDenied("selected private probe role identity changed before probing")
        gateway_peer = self._process_manager.inspect_gateway_peer(enrollment)
        if (gateway_peer.profile_id != enrollment.gateway_profile_id
                or gateway_peer.enrollment_id != enrollment.gateway_enrollment_id
                or gateway_peer.generation != enrollment.gateway_generation):
            raise RemoteOriginDenied("gateway private control process binding changed")
        binding = self._socket_resolver.resolve(enrollment)
        if binding.owner_uid != gateway_peer.uid:
            raise RemoteOriginDenied("private control socket owner differs from selected gateway UID")
        socket_before = _validate_control_socket(binding)
        request = OriginProbeControlRequest.create(enrollment, root_probe_handle, challenge, sequence)
        request_digest = request.request_digest
        raw = _canonical(request.to_wire())
        if len(raw) > _MAX_PROBE_FRAME:
            raise RemoteOriginDenied("private gateway probe request exceeds its bound")
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self._timeout)
            try:
                sock.connect(os.fspath(binding.path))
                self._verify_server_peer(sock, gateway_peer)
                length = struct.pack("!I", len(raw))
                sock.sendall(length + raw)
                response_size = struct.unpack("!I", _recv_exact(sock, 4))[0]
                if not 1 <= response_size <= _MAX_PROBE_FRAME:
                    raise RemoteOriginDenied("private gateway probe response exceeds its bound")
                response_wire = _strict_json_object(_recv_exact(sock, response_size))
            finally:
                sock.close()
        except RemoteOriginDenied:
            raise
        except (OSError, TimeoutError):
            raise RemoteOriginDenied("private gateway origin probe transport failed") from None
        socket_after = _validate_control_socket(binding)
        if (socket_before.st_dev, socket_before.st_ino) != (socket_after.st_dev, socket_after.st_ino):
            raise RemoteOriginDenied("selected private control socket changed during probe")
        response_expected = {"schema", "operation", "probe_handle", "sequence", "challenge",
            "request_digest", "remote_enrollment_id", "gateway_profile_id", "gateway_generation",
            "native_profile_id", "desktop_generation", "connector_target_id", "policy_config_digest",
            "policy_revision", "service_generation_digest", "observations", "observed_assertion_ids",
            "asset_content_sha256", "websocket_observation_id", "native_window_observation_id"}
        response = OriginProbeControlResponse.from_wire(response_wire)
        echoes = {"schema": 1, "operation": "probe_selected_origin_result",
            "probe_handle": root_probe_handle, "sequence": sequence, "challenge": challenge,
            "request_digest": request_digest, "remote_enrollment_id": enrollment.enrollment_id,
            "gateway_profile_id": enrollment.gateway_profile_id,
            "gateway_generation": enrollment.gateway_generation,
            "native_profile_id": enrollment.native_profile_id,
            "desktop_generation": enrollment.desktop_generation,
            "connector_target_id": enrollment.connector_target_id,
            "policy_config_digest": enrollment.policy_config_digest,
            "policy_revision": enrollment.policy_revision,
            "service_generation_digest": enrollment.service_generation_digest}
        if any(getattr(response, key) != value for key, value in echoes.items()):
            raise RemoteOriginDenied("private gateway probe response does not match its challenge or selection")
        observations = response.observations
        if (any(type(observations[key]) is not bool for key in ORIGIN_PROBE_OBSERVATIONS)
                or any(observations[key] is not True for key in ORIGIN_PROBE_OBSERVATIONS)):
            raise RemoteOriginDenied("private gateway failed app-only HTTP, WebSocket, or native-window probe")
        for key in ("websocket_observation_id", "native_window_observation_id"):
            if not isinstance(getattr(response, key), str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", getattr(response, key)):
                raise RemoteOriginDenied("private gateway omitted a concrete stream or native-window observation")
        if not isinstance(response.asset_content_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", response.asset_content_sha256):
            raise RemoteOriginDenied("private gateway app asset digest is malformed")
        result = response.to_wire()
        return self._registry.complete(record, result, request_digest)


def _selected_probe_process_identity(custody: Any,
        enrollment: SelectedRemoteOrigin,
        now: Callable[[], float] = time.monotonic) -> tuple[str, float]:
    binding = enrollment.probe_binding
    if not isinstance(binding, RemoteOriginProbeBinding):
        raise RemoteOriginDenied("selected private origin probe role is unavailable")
    try:
        proof = custody.inspect_enrolled_process(binding.profile_id, binding.generation)
    except Exception:
        raise RemoteOriginDenied("root probe-role custody inspection failed") from None
    required = ("process_id", "profile_id", "enrollment_id", "profile_generation", "uid", "gid",
                "pid", "pid_starttime_ticks", "executable_device", "executable_inode",
                "executable_sha256", "cgroup_id", "mount_namespace_inode",
                "network_namespace_inode", "pidfd_registry_handle", "expires_monotonic")
    if (proof is None or any(not hasattr(proof, key) for key in required)
            or proof.profile_id != binding.profile_id or proof.enrollment_id != binding.enrollment_id
            or proof.profile_generation != binding.generation
            or proof.executable_sha256 != binding.role_sha256
            or not _finite_monotonic(proof.expires_monotonic)
            or proof.expires_monotonic <= float(now())
            or proof.uid <= 0 or proof.gid < 0 or proof.pid <= 0
            or proof.pid_starttime_ticks <= 0 or proof.executable_device <= 0
            or proof.executable_inode <= 0 or proof.mount_namespace_inode <= 0
            or proof.network_namespace_inode <= 0 or not proof.cgroup_id
            or not proof.pidfd_registry_handle):
        raise RemoteOriginDenied("selected private probe role has no live enrolled process proof")
    digest = hashlib.sha256(_canonical({key: getattr(proof, key) for key in required})).hexdigest()
    return digest, float(proof.expires_monotonic)


def _selected_enrolled_process_proof(custody: Any, profile_id: str, generation: str,
        enrollment_id: str, *, expected_sha: str | None = None,
        now: Callable[[], float] = time.monotonic) -> tuple[dict[str, Any], float]:
    try:
        proof = custody.inspect_enrolled_process(profile_id, generation)
    except Exception:
        proof = None
    required = ("process_id", "profile_id", "enrollment_id", "profile_generation", "uid", "gid",
                "pid", "pid_starttime_ticks", "executable_device", "executable_inode",
                "executable_sha256", "cgroup_id", "mount_namespace_inode",
                "network_namespace_inode", "pidfd_registry_handle", "expires_monotonic")
    if (proof is None or any(not hasattr(proof, key) for key in required)
            or proof.profile_id != profile_id or proof.profile_generation != generation
            or proof.enrollment_id != enrollment_id
            or expected_sha is not None and proof.executable_sha256 != expected_sha
            or not _finite_monotonic(proof.expires_monotonic)
            or proof.expires_monotonic <= float(now())
            or proof.uid <= 0 or proof.gid < 0 or proof.pid <= 0
            or proof.pid_starttime_ticks <= 0 or proof.executable_device <= 0
            or proof.executable_inode <= 0 or proof.mount_namespace_inode <= 0
            or proof.network_namespace_inode <= 0 or not proof.cgroup_id
            or not proof.pidfd_registry_handle):
        raise RemoteOriginDenied("selected enrolled service process proof is unavailable")
    result = {key: getattr(proof, key) for key in required}
    return result, float(proof.expires_monotonic)


def _digest_canonical(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(value))).hexdigest()


class SelectedRemoteOriginProbeAuthority:
    """Root service authority for setup-bound one-use private origin probing."""
    def __init__(self, *, catalog: RemoteOriginCatalog,
                 setup_transactions: RemoteSetupTransactionVerifier,
                 current_peer: CurrentRemoteOriginCaller,
                 process_manager: RemoteOriginProcessManager,
                 custody: Any,
                 resolve_selected_native_principal: Callable[[str, str, str], Any],
                 socket_resolver: RemoteOriginControlSocketResolver,
                 signer: ReceiptSigner,
                 now: Callable[[], float] = time.monotonic,
                 peer_credentials: Callable[[socket.socket], tuple[int, int, int]] | None = None):
        if not isinstance(process_manager, CustodyRemoteOriginProcessManager):
            raise ValueError("root custody-backed remote-origin process manager is required")
        if not callable(resolve_selected_native_principal):
            raise ValueError("root protected native PrincipalBinding resolver is required")
        self._catalog, self._setup_transactions, self._current_peer = catalog, setup_transactions, current_peer
        self._process_manager, self._custody, self._signer, self._now = process_manager, custody, signer, now
        self._resolve_selected_native_principal = resolve_selected_native_principal
        self._registry = RootOriginProbeRegistry(signer, now=now)
        self._transport = PrivateGatewayOriginProbe(socket_resolver=socket_resolver,
            process_manager=process_manager, registry=self._registry, current_peer=current_peer,
            custody=custody, now=now, peer_credentials=peer_credentials)

    def issue_selected_origin_probe(self, remote_enrollment_id: str,
                                    root_setup_transaction_handle: str) -> str:
        """Authorize one probe only for the active setup process and exact selection."""
        _validate_id(remote_enrollment_id, "remote enrollment ID")
        _opaque_handle(root_setup_transaction_handle, "setup transaction handle")
        selected = self._catalog.selected_origin(remote_enrollment_id)
        if (not isinstance(selected, SelectedRemoteOrigin)
                or selected.enrollment_id != remote_enrollment_id or not selected.owned
                or not isinstance(selected.setup_writer_binding, RemoteSetupWriterBinding)
                or not isinstance(selected.probe_binding, RemoteOriginProbeBinding)):
            raise RemoteOriginDenied("active remote setup and private probe bindings are unavailable")
        caller = self._current_peer.current()
        if (not isinstance(caller, RemoteOriginCallerIdentity)
                or caller.pid <= 0 or caller.uid <= 0 or caller.pid_starttime_ticks <= 0
                or not _finite_monotonic(caller.expires_monotonic)
                or caller.expires_monotonic <= float(self._now())):
            raise RemoteOriginDenied("current setup caller lacks a live root peer identity")
        try:
            transaction = self._setup_transactions.verify_origin_probe_transaction(
                root_setup_transaction_handle, selected, caller)
        except Exception:
            raise RemoteOriginDenied("root setup transaction is not authorized for origin probing") from None
        if not isinstance(transaction, VerifiedRemoteSetupTransaction):
            raise RemoteOriginDenied("root setup transaction proof is not typed")
        setup = selected.setup_writer_binding
        if (transaction.setup_transaction_handle_digest != hashlib.sha256(
                    root_setup_transaction_handle.encode("ascii")).hexdigest()
                or transaction.remote_enrollment_id != selected.enrollment_id
                or transaction.setup_peer_identity_digest != caller.digest()
                or transaction.setup_profile_id != setup.setup_profile_id
                or transaction.setup_generation != setup.setup_generation
                or transaction.setup_role_artifact_id != setup.setup_role_artifact_id
                or transaction.setup_role_sha256 != setup.setup_role_sha256
                or transaction.setup_enrollment_id != setup.setup_enrollment_id
                or transaction.setup_transaction_policy_id != setup.setup_transaction_policy_id
                or transaction.token_writer_enrollment_id != setup.token_writer_enrollment_id
                or transaction.origin_probe_enrollment_id != setup.origin_probe_enrollment_id
                or tuple(transaction.allowed_tunnel_enrollment_ids) != tuple(setup.allowed_tunnel_enrollment_ids)
                or selected.probe_binding.enrollment_id != setup.origin_probe_enrollment_id
                or not _finite_monotonic(transaction.issued_monotonic)
                or not _finite_monotonic(transaction.expires_monotonic)
                or not transaction.issued_monotonic <= float(self._now()) < transaction.expires_monotonic
                or transaction.expires_monotonic - transaction.issued_monotonic > 30.0):
            raise RemoteOriginDenied("root setup transaction does not match the selected writer/probe binding")
        evidence = self._process_manager.inspect_selected_origin(selected)
        if (not isinstance(evidence, KernelOriginEvidence)
                or not _finite_monotonic(evidence.expires_monotonic)
                or evidence.expires_monotonic <= float(self._now())):
            raise RemoteOriginDenied("gateway/native custody proof is unavailable or stale")
        probe_identity_digest, probe_expiry = _selected_probe_process_identity(
            self._custody, selected, now=self._now)
        socket_binding = self._transport._socket_resolver.resolve(selected)
        if (socket_binding.gateway_profile_id != selected.gateway_profile_id
                or socket_binding.gateway_generation != selected.gateway_generation):
            raise RemoteOriginDenied("private gateway control socket selection is mismatched")
        _validate_control_socket(socket_binding)
        # A root probe handle is no longer valid than its setup caller, transaction,
        # probe-role process, gateway, or native process evidence.
        evidence = dataclass_replace(evidence, expires_monotonic=min(
            evidence.expires_monotonic, probe_expiry, caller.expires_monotonic))
        return self._registry.issue(selected, transaction, caller.digest(),
                                    probe_identity_digest, evidence,
                                    setup_transaction_handle=root_setup_transaction_handle,
                                    setup_caller_identity=caller)

    def probe_selected_app(self, selected: SelectedRemoteOrigin,
                           root_probe_handle: str) -> ProbeObservationMap:
        active = self._catalog.selected_origin(selected.enrollment_id)
        if _selection_digest(active) != _selection_digest(selected):
            raise RemoteOriginDenied("root selected remote origin changed before its probe")
        return self._transport.probe_selected_app(active, root_probe_handle)

    def resolve_probe_receipt(self, selected: SelectedRemoteOrigin,
                              root_probe_handle: str) -> tuple[RootOriginProbeReceipt, Mapping[str, bool]]:
        caller = self._current_peer.current()
        if not isinstance(caller, RemoteOriginCallerIdentity):
            raise RemoteOriginDenied("current setup caller has no root process identity")
        return self._registry.resolve_ready(root_probe_handle, selected, caller.digest())

    def authorize_probe_action(self, root_probe_handle: str, action: str,
                               asset_id: str | None) -> str:
        """Create a child only after rejoining the active root transaction and peers."""
        _opaque_handle(root_probe_handle, "root origin probe handle")
        parent = self._registry.resolve_parent(root_probe_handle)
        selected = parent.selected
        caller = self._current_peer.current()
        if (not isinstance(caller, RemoteOriginCallerIdentity)
                or not hmac.compare_digest(caller.digest(), parent.setup_peer_digest)):
            raise RemoteOriginDenied("setup probe action caller differs from current root transaction")
        current = self._catalog.selected_origin(selected.enrollment_id)
        if (not isinstance(current, SelectedRemoteOrigin)
                or _selection_digest(current) != _selection_digest(selected)):
            raise RemoteOriginDenied("selected remote origin changed before child action mint")
        transaction = self._verify_current_probe_transaction(parent)
        if _setup_transaction_digest(transaction) != _setup_transaction_digest(parent.setup_transaction):
            raise RemoteOriginDenied("root setup transaction changed before child action mint")
        kernel = self._process_manager.inspect_selected_origin(current)
        if (not isinstance(kernel, KernelOriginEvidence)
                or kernel.gateway_identity_digest != parent.kernel_evidence.gateway_identity_digest
                or kernel.expires_monotonic <= float(self._now())):
            raise RemoteOriginDenied("selected gateway/native custody changed before child action mint")
        probe_identity, probe_expiry = _selected_probe_process_identity(
            self._custody, current, now=self._now)
        gateway = self._process_manager.inspect_gateway_peer(current)
        if (probe_identity != parent.probe_process_identity_digest
                or probe_expiry <= float(self._now())
                or gateway.enrollment_id != current.gateway_enrollment_id
                or gateway.profile_id != current.gateway_profile_id
                or gateway.generation != current.gateway_generation):
            raise RemoteOriginDenied("root probe or gateway role changed before child action mint")
        return self._registry.authorize_action(root_probe_handle, action, asset_id)

    def resolve_probe_connector_binding(self, handle: str, uid: int, pid: int,
                                        pidfd: int):
        """Resolve a child action handle to the authority owner's typed HI12 binding.

        This method is called by the private SetupProbeConnectorAuthority only;
        it accepts no route, target, generation, principal, path, or deadline.
        """
        _opaque_handle(handle, "root setup-probe action handle")
        if any(type(value) is not int or value <= 0 for value in (uid, pid, pidfd)):
            raise RemoteOriginDenied("setup-probe connector peer identity is malformed")
        action = self._registry.resolve_action(handle)
        parent = action.parent
        selected = parent.selected
        current = self._catalog.selected_origin(selected.enrollment_id)
        if (not isinstance(current, SelectedRemoteOrigin)
                or _selection_digest(current) != _selection_digest(selected)):
            raise RemoteOriginDenied("active selected setup probe or origin changed")
        transaction = self._verify_current_probe_transaction(parent)
        if _setup_transaction_digest(transaction) != _setup_transaction_digest(parent.setup_transaction):
            raise RemoteOriginDenied("root setup transaction changed during native probe")
        kernel = self._process_manager.inspect_selected_origin(current)
        if (not isinstance(kernel, KernelOriginEvidence)
                or kernel.gateway_identity_digest != parent.kernel_evidence.gateway_identity_digest
                or not _finite_monotonic(kernel.expires_monotonic)
                or kernel.expires_monotonic <= float(self._now())):
            raise RemoteOriginDenied("selected gateway or native process identity changed")
        probe_digest, probe_expiry = _selected_probe_process_identity(
            self._custody, current, now=self._now)
        if probe_digest != parent.probe_process_identity_digest:
            raise RemoteOriginDenied("selected root probe role changed")
        gateway = self._process_manager.inspect_gateway_peer(current)
        if (uid != gateway.uid or pid != gateway.pid
                or gateway.profile_id != current.gateway_profile_id
                or gateway.enrollment_id != current.gateway_enrollment_id
                or gateway.generation != current.gateway_generation):
            raise RemoteOriginDenied("setup connector caller is not the selected gateway process")
        try:
            live_peer = self._custody.resolve_live_peer(pid, pidfd,
                profile_id=current.gateway_profile_id, generation=current.gateway_generation)
        except Exception:
            live_peer = None
        namespace_identity = f"mnt:{gateway.mount_namespace_inode};net:{gateway.network_namespace_inode}"
        if (live_peer is None or live_peer.kernel_uid != uid
                or live_peer.start_ticks != gateway.pid_starttime_ticks
                or live_peer.executable_sha256 != gateway.executable_sha256
                or live_peer.cgroup_identity != gateway.cgroup_id
                or live_peer.namespace_identity != namespace_identity):
            raise RemoteOriginDenied("setup connector PIDFD does not match current gateway custody")
        native_proof, native_expiry = _selected_enrolled_process_proof(
            self._custody, current.native_profile_id, current.desktop_generation,
            current.native_enrollment_id, now=self._now)
        try:
            from .service import PrincipalBinding
            principal = self._resolve_selected_native_principal(current.native_profile_id,
                current.desktop_generation, current.service_generation_digest)
        except Exception:
            principal = None
        if (not isinstance(principal, PrincipalBinding)
                or principal.profile_id != current.native_profile_id
                or principal.uid != native_proof["uid"]
                or not principal.namespace_id or not principal.principal_id):
            raise RemoteOriginDenied("current protected native PrincipalBinding is unavailable")
        gateway_proof, gateway_expiry = _selected_enrolled_process_proof(
            self._custody, current.gateway_profile_id, current.gateway_generation,
            current.gateway_enrollment_id, expected_sha=current.gateway_role_sha256,
            now=self._now)
        if (gateway_proof["pid"] != gateway.pid
                or gateway_proof["uid"] != gateway.uid
                or gateway_proof["gid"] != gateway.gid
                or gateway_proof["pid_starttime_ticks"] != gateway.pid_starttime_ticks
                or gateway_proof["executable_device"] != gateway.executable_device
                or gateway_proof["executable_inode"] != gateway.executable_inode
                or gateway_proof["executable_sha256"] != gateway.executable_sha256
                or gateway_proof["cgroup_id"] != gateway.cgroup_id
                or gateway_proof["mount_namespace_inode"] != gateway.mount_namespace_inode
                or gateway_proof["network_namespace_inode"] != gateway.network_namespace_inode
                or gateway_proof["pidfd_registry_handle"] != gateway.pidfd_registry_handle):
            # Full proof equality includes executable and namespaces, not merely
            # the gateway's mutable PID number.
            raise RemoteOriginDenied("gateway enrolled proof changed during setup probe")
        from .remote_probe_connector_authority import RootSetupProbeBinding
        now = float(self._now())
        expiry = min(parent.expires, action.expires, transaction.expires_monotonic,
                     probe_expiry, native_expiry, gateway_expiry,
                     gateway.expires_monotonic, math.nextafter(now + 30.0, -math.inf))
        frame_deadline = min(expiry, math.nextafter(now + 5.0, -math.inf))
        if expiry <= now or frame_deadline <= now:
            raise RemoteOriginDenied("setup probe connector deadline expired")
        asset_ids = tuple(sorted(_remote_probe_asset_paths()))
        return RootSetupProbeBinding(
            probe_handle=handle,
            setup_transaction_handle=parent.setup_transaction_handle,
            setup_transaction_digest=_setup_transaction_digest(transaction),
            setup_actor_identity_digest=parent.setup_peer_digest,
            probe_actor_identity_digest=parent.probe_process_identity_digest,
            setup_profile_id=transaction.setup_profile_id,
            setup_generation=transaction.setup_generation,
            setup_enrollment_id=transaction.setup_enrollment_id,
            setup_role_sha256=transaction.setup_role_sha256,
            probe_enrollment_id=current.probe_binding.enrollment_id,
            probe_profile_id=current.probe_binding.profile_id,
            probe_generation=current.probe_binding.generation,
            probe_role_sha256=current.probe_binding.role_sha256,
            gateway_identity_digest=kernel.gateway_identity_digest,
            gateway_profile_id=current.gateway_profile_id,
            gateway_generation=current.gateway_generation,
            gateway_enrollment_id=current.gateway_enrollment_id,
            native_identity_digest=_digest_canonical(native_proof),
            native_enrollment_id=current.native_enrollment_id,
            native_profile_id=current.native_profile_id,
            native_generation=current.desktop_generation,
            enrollment_id=current.native_enrollment_id,
            target_id="xpra-native", connector_target_id="xpra-native",
            approved_route_ids=("xpra-http", "xpra-websocket"),
            asset_ids=asset_ids, selected_action=action.action,
            selected_asset_id=action.asset_id, session_id=parent.session_id,
            next_sequence=action.frame_sequence,
            effect_sequence=action.effect_sequence,
            policy_revision=current.policy_revision,
            policy_config_digest=current.policy_config_digest,
            service_generation_digest=current.service_generation_digest,
            principal_id=principal.principal_id,
            connector_handle=action.connector_handle,
            issued_monotonic=action.issued, expires_monotonic=expiry,
            frame_deadline_monotonic=frame_deadline,
            cancelled=lambda: self._registry.action_cancelled(handle))

    def advance_probe_connector_sequence(self, handle: str, expected_effect_sequence: int,
            expected_frame_sequence: int, operation: str, connector_handle: str, *,
            peer_uid: int, peer_pid: int, peer_pidfd: int) -> bool:
        binding = self.resolve_probe_connector_binding(handle, peer_uid, peer_pid, peer_pidfd)
        if (expected_effect_sequence != binding.effect_sequence
                or expected_frame_sequence != binding.next_sequence or operation not in {
                "connector.open", "connector.read", "connector.write", "connector.close"}):
            raise RemoteOriginDenied("setup probe effect or frame sequence changed")
        return self._registry.advance_connector_effect(handle, operation,
            expected_effect_sequence, expected_frame_sequence, connector_handle)

    def cancel_probe_action(self, handle: str, *, peer_uid: int, peer_pid: int,
                            peer_pidfd: int) -> None:
        self.resolve_probe_connector_binding(handle, peer_uid, peer_pid, peer_pidfd)
        self._registry.cancel_action(handle)

    def _verify_current_probe_transaction(self,
            record: _ProbeHandleRecord) -> VerifiedRemoteSetupTransaction:
        try:
            transaction = self._setup_transactions.verify_origin_probe_transaction(
                record.setup_transaction_handle, record.selected, record.setup_caller_identity)
        except Exception:
            raise RemoteOriginDenied("root setup transaction is no longer current") from None
        if (not isinstance(transaction, VerifiedRemoteSetupTransaction)
                or transaction.setup_peer_identity_digest != record.setup_peer_digest
                or transaction.remote_enrollment_id != record.selected.enrollment_id
                or not transaction.issued_monotonic <= float(self._now()) < transaction.expires_monotonic):
            raise RemoteOriginDenied("root setup transaction changed or expired")
        return transaction


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for c in value):
        raise RemoteOriginDenied(f"selected {label} is invalid")
    return value


def _opaque_handle(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise RemoteOriginDenied(f"{label} is invalid")
    return value


def _finite_monotonic(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)) and float(value) >= 0.0)


def _validate_tunnel_credential(token: bytes, selected: SelectedTunnel) -> None:
    """Decode cloudflared's tunnel-token envelope and join account/tunnel IDs."""
    try:
        if len(token) > 16 * 1024:
            raise ValueError
        decoded = base64.b64decode(token, validate=True)
        value = json.loads(decoded.decode("utf-8", "strict"))
        if (not isinstance(value, dict) or set(value) - {"a", "s", "t", "e"}
                or not {"a", "s", "t"}.issubset(value)
                or value["a"] != selected.account_id
                or str(uuid.UUID(value["t"])) != str(uuid.UUID(selected.tunnel_id))
                or not isinstance(value["s"], str)
                or len(base64.b64decode(value["s"], validate=True)) < 16
                or "e" in value and (not isinstance(value["e"], str) or len(value["e"]) > 1024)):
            raise ValueError
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
        raise RemoteOriginDenied("runtime credential is not scoped to the selected Cloudflare tunnel") from None


def _canonical_system_path(path: Path) -> Path:
    """Resolve only Apple's fixed `/var` and `/tmp` aliases before fd walking."""
    if sys.platform != "darwin" or not path.is_absolute():
        return path
    for alias, canonical in ((Path("/var"), Path("/private/var")),
                             (Path("/tmp"), Path("/private/tmp"))):
        if path == alias or alias in path.parents:
            if (not alias.is_symlink()
                    or Path(os.path.realpath(alias)) != canonical):
                raise RemoteOriginDenied("selected token sink uses an unexpected system alias")
            return canonical / path.relative_to(alias)
    return path


def _open_secure_directory(path: Path) -> int:
    """Walk from `/` with held O_NOFOLLOW directory FDs; reject writable ancestors."""
    path = _canonical_system_path(path)
    if (not path.is_absolute() or path == Path(path.anchor)
            or any(part in {".", ".."} for part in path.parts[1:])):
        raise RemoteOriginDenied("selected token sink must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path.anchor, flags)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode):
                raise RemoteOriginDenied("token sink path contains a non-directory")
            writable = stat.S_IMODE(info.st_mode) & 0o022
            sticky = bool(info.st_mode & stat.S_ISVTX)
            if writable and not sticky:
                raise RemoteOriginDenied("token sink path has a writable untrusted ancestor")
            if index == len(parts) - 1 and (
                    info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
                raise RemoteOriginDenied("selected token root is not private to the authority")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_tunnel_directory(token_root_fd: int, tunnel_id: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tunnel_id, flags, dir_fd=token_root_fd)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        os.close(fd)
        raise RemoteOriginDenied("selected tunnel directory is not root-private")
    return fd


def write_selected_tunnel_token(
    tunnel_enrollment_id: str, *, catalog: RemoteOriginCatalog,
    vault: SecretResolver, token_root: Path, journal: TokenJournal,
    signer: ReceiptSigner, now: Callable[[], float] = time.monotonic,
) -> ProtectedTunnelTokenReceipt:
    """Write only the root-selected dedicated credential with create-once semantics."""
    _validate_id(tunnel_enrollment_id, "tunnel enrollment ID")
    selected = catalog.selected_tunnel(tunnel_enrollment_id)
    if (not isinstance(selected, SelectedTunnel) or selected.enrollment_id != tunnel_enrollment_id
            or not selected.owned or selected.runtime_uid < 0):
        raise RemoteOriginDenied("selected tunnel is absent or not installer-owned")
    for value, name in ((selected.tunnel_id, "tunnel ID"), (selected.account_id, "account ID"),
                        (selected.generation, "generation"), (selected.sink_id, "sink ID"),
                        (selected.secret_reference_id, "secret reference")):
        _validate_id(value, name)
    if token_root != token_root.absolute():
        raise RemoteOriginDenied("token root must be absolute")
    root_fd = _open_secure_directory(token_root)
    try:
        directory_fd = _open_tunnel_directory(root_fd, selected.tunnel_id)
    finally:
        os.close(root_fd)
    try:
        sink_name = "tunnel.token"
        token = vault.resolve_tunnel_token(selected.secret_reference_id, selected.tunnel_id)
        if not isinstance(token, bytes) or not token or len(token) > 64 * 1024 or b"\x00" in token or b"\n" in token or b"\r" in token:
            raise RemoteOriginDenied("selected dedicated runtime token is invalid")
        _validate_tunnel_credential(token, selected)
        digest = hashlib.sha256(token).hexdigest()
        prior = journal.lookup(tunnel_enrollment_id)
        try:
            preexisting_sink = os.stat(sink_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            preexisting_sink = None
        if preexisting_sink is not None and prior is None:
            raise RemoteOriginDenied("preexisting token sink has no ownership journal")
        intent = {"state": "intent", "tunnel_id": selected.tunnel_id,
                  "generation": selected.generation, "sink_id": selected.sink_id,
                  "runtime_uid": selected.runtime_uid}
        if prior is None:
            journal.prepare(tunnel_enrollment_id, intent)
            prior = journal.lookup(tunnel_enrollment_id) or intent
        try:
            existing = os.stat(sink_name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
                    or stat.S_IMODE(existing.st_mode) != 0o400 or existing.st_uid != os.geteuid()
                    or not isinstance(prior, Mapping)
                    or prior.get("state") not in {"intent", "committed"}
                    or prior.get("tunnel_id") != selected.tunnel_id
                    or prior.get("generation") != selected.generation
                    or prior.get("sink_id") != selected.sink_id
                    or prior.get("runtime_uid") != selected.runtime_uid
                    or prior.get("state") == "committed" and prior.get("digest") != digest
                    or prior.get("state") == "committed" and
                       (prior.get("device") != existing.st_dev or prior.get("inode") != existing.st_ino)):
                raise RemoteOriginDenied("existing tunnel token sink is foreign, changed, or unsafe")
            fd = os.open(sink_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
            try:
                content = os.read(fd, 64 * 1024 + 1)
            finally:
                os.close(fd)
            if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), digest):
                raise RemoteOriginDenied("existing tunnel token sink contents changed")
            st = existing
        else:
            temp_name = ".token-" + secrets.token_hex(16)
            fd = os.open(temp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         0o600, dir_fd=directory_fd)
            try:
                os.fchown(fd, os.geteuid(), -1)
                os.fchmod(fd, 0o400)
                view = memoryview(token)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
                st = os.fstat(fd)
            except Exception:
                os.close(fd)
                try: os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError: pass
                raise
            else:
                os.close(fd)
            try:
                # Hard-link publication is atomic and refuses to replace a foreign path.
                os.link(temp_name, sink_name, src_dir_fd=directory_fd,
                        dst_dir_fd=directory_fd, follow_symlinks=False)
                os.fsync(directory_fd)
            except FileExistsError:
                try: os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError: pass
                raise RemoteOriginDenied("token sink appeared during protected write") from None
            finally:
                try: os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError: pass
            st = os.stat(sink_name, dir_fd=directory_fd, follow_symlinks=False)
            if (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o400
                    or not stat.S_ISREG(st.st_mode)):
                raise RemoteOriginDenied("published tunnel token file failed protection checks")
        journal.record(tunnel_enrollment_id, {"state": "committed", "digest": digest,
            "device": st.st_dev, "inode": st.st_ino, "sink_id": selected.sink_id,
            "tunnel_id": selected.tunnel_id, "generation": selected.generation,
            "runtime_uid": selected.runtime_uid})
    finally:
        os.close(directory_fd)
    # Drop secret bytes before receipt construction; no secret or digest leaves root.
    token = b""
    issued = float(now())
    if not (issued >= 0 and issued < float("inf")):
        raise RemoteOriginDenied("root monotonic clock is invalid")
    unsigned = dict(schema=1, receipt_id=secrets.token_urlsafe(24),
                    tunnel_enrollment_id=selected.enrollment_id, tunnel_id=selected.tunnel_id,
                    generation=selected.generation, sink_id=selected.sink_id,
                    file_device=st.st_dev, file_inode=st.st_ino, owner_uid=st.st_uid,
                    mode=stat.S_IMODE(st.st_mode), issued_monotonic=issued,
                        expires_monotonic=math.nextafter(issued + 30.0, -math.inf))
    provisional = ProtectedTunnelTokenReceipt(**unsigned, signature=b"")
    return ProtectedTunnelTokenReceipt(**unsigned, signature=signer.sign(provisional.payload()))


class _OneShotSecretResolver:
    def __init__(self, token: bytes):
        self._token = bytearray(token)

    def resolve_tunnel_token(self, reference_id: str, tunnel_id: str) -> bytes:
        token = bytes(self._token)
        self._token[:] = b"\0" * len(self._token)
        self._token.clear()
        return token


def write_provisioned_tunnel_token(
    selected_tunnel: SelectedTunnel, token_bytes: bytes,
    root_verified_setup_transaction: VerifiedRemoteSetupTransaction, *, token_root: Path,
    journal: TokenJournal, signer: ReceiptSigner,
    now: Callable[[], float] = time.monotonic,
) -> ProtectedTunnelTokenReceipt:
    """Persist a token only with root-authenticated current transaction provenance."""
    proof = root_verified_setup_transaction
    if not isinstance(selected_tunnel, SelectedTunnel) or not selected_tunnel.owned:
        raise RemoteOriginDenied("root selected tunnel is absent or not installer-owned")
    if not isinstance(proof, VerifiedRemoteSetupTransaction):
        raise RemoteOriginDenied("root-verified setup transaction is required")
    if not isinstance(token_bytes, bytes) or not token_bytes or len(token_bytes) > 16 * 1024:
        raise RemoteOriginDenied("provisioned tunnel token is malformed")
    t = float(now())
    if (not _finite_monotonic(proof.issued_monotonic)
            or not _finite_monotonic(proof.expires_monotonic)
            or not proof.issued_monotonic <= t < proof.expires_monotonic
            or proof.expires_monotonic - proof.issued_monotonic > 30.0):
        raise RemoteOriginDenied("root setup transaction proof is expired or malformed")
    if (proof.tunnel_enrollment_id != selected_tunnel.enrollment_id
            or proof.account_id != selected_tunnel.account_id
            or proof.tunnel_id != selected_tunnel.tunnel_id
            or proof.generation != selected_tunnel.generation
            or selected_tunnel.enrollment_id not in proof.allowed_tunnel_enrollment_ids
            or proof.response_token_sha256 != hashlib.sha256(token_bytes).hexdigest()):
        raise RemoteOriginDenied("provisioned token does not match the root transaction response")
    for value, label in ((proof.remote_enrollment_id, "remote enrollment"),
                         (proof.setup_profile_id, "setup profile"),
                         (proof.setup_generation, "setup generation"),
                         (proof.setup_enrollment_id, "setup enrollment"),
                         (proof.setup_transaction_policy_id, "setup transaction policy"),
                         (proof.token_writer_enrollment_id, "token writer enrollment"),
                         (proof.origin_probe_enrollment_id, "origin probe enrollment"),
                         (proof.one_use_stage_nonce, "one-use setup stage")):
        _validate_id(value, label)
    for value, label in ((proof.setup_transaction_handle_digest, "setup transaction digest"),
                         (proof.setup_role_sha256, "setup role digest"),
                         (proof.setup_peer_identity_digest, "setup peer digest"),
                         (proof.response_token_sha256, "response token digest")):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RemoteOriginDenied(f"{label} is malformed")
    if not proof.allowed_tunnel_enrollment_ids or len(proof.allowed_tunnel_enrollment_ids) > 64:
        raise RemoteOriginDenied("setup transaction tunnel allowlist is malformed")
    if (b"\x00" in token_bytes or b"\n" in token_bytes or b"\r" in token_bytes):
        raise RemoteOriginDenied("provisioned tunnel token is malformed")
    _validate_tunnel_credential(token_bytes, selected_tunnel)
    catalog = _SingleTunnelCatalog(selected_tunnel)
    return write_selected_tunnel_token(selected_tunnel.enrollment_id, catalog=catalog,
        vault=_OneShotSecretResolver(token_bytes), token_root=token_root, journal=journal,
        signer=signer, now=now)


class _SingleTunnelCatalog:
    def __init__(self, selected: SelectedTunnel):
        self._selected = selected

    def selected_tunnel(self, enrollment_id: str) -> SelectedTunnel | None:
        return self._selected if enrollment_id == self._selected.enrollment_id else None

    def selected_origin(self, enrollment_id: str) -> SelectedRemoteOrigin | None:
        return None


class TunnelTokenWriterClient:
    """Typed caller for the authority's authenticated private Unix RPC."""
    def __init__(self, rpc: Callable[[str, Mapping[str, Any]], Mapping[str, Any]],
                 verifier: ReceiptSigner, *, now: Callable[[], float] = time.monotonic):
        if not callable(rpc):
            raise ValueError("authenticated authority RPC callable is required")
        self._rpc, self._verifier, self._now = rpc, verifier, now

    def write_provisioned_tunnel_token(self, tunnel_enrollment_id: str, token: bytes, *,
            account_id: str, tunnel_id: str, generation: str,
            setup_transaction_handle: str) -> ProtectedTunnelTokenReceipt:
        for value, label in ((tunnel_enrollment_id, "enrollment"), (account_id, "account"),
                             (tunnel_id, "tunnel"), (generation, "generation")):
            _validate_id(value, label)
        _opaque_handle(setup_transaction_handle, "setup transaction handle")
        if not isinstance(token, bytes) or not 1 <= len(token) <= 16 * 1024:
            raise RemoteOriginDenied("provisioned tunnel token is outside the transport bound")
        payload = {"schema": 1, "setup_transaction_handle": setup_transaction_handle,
                   "tunnel_enrollment_id": tunnel_enrollment_id,
                   "account_id": account_id, "tunnel_id": tunnel_id,
                   "generation": generation,
                   "runtime_token_b64": __import__("base64").b64encode(token).decode("ascii")}
        try:
            raw = self._rpc("write_provisioned_tunnel_token", payload)
        except Exception:
            raise RemoteOriginDenied("root tunnel-token writer is unavailable") from None
        fields_required = {"schema", "receipt_id", "tunnel_enrollment_id", "tunnel_id",
            "generation", "sink_id", "file_device", "file_inode", "owner_uid", "mode",
            "issued_monotonic", "expires_monotonic", "signature_b64"}
        if not isinstance(raw, Mapping) or set(raw) != fields_required:
            raise RemoteOriginDenied("root tunnel-token receipt fields are invalid")
        try:
            import base64
            signature = base64.b64decode(raw["signature_b64"], validate=True)
            receipt = ProtectedTunnelTokenReceipt(
                schema=raw["schema"], receipt_id=raw["receipt_id"],
                tunnel_enrollment_id=raw["tunnel_enrollment_id"], tunnel_id=raw["tunnel_id"],
                generation=raw["generation"], sink_id=raw["sink_id"],
                file_device=raw["file_device"], file_inode=raw["file_inode"],
                owner_uid=raw["owner_uid"], mode=raw["mode"],
                issued_monotonic=raw["issued_monotonic"], expires_monotonic=raw["expires_monotonic"],
                signature=signature)
        except Exception:
            raise RemoteOriginDenied("root tunnel-token receipt is malformed") from None
        if (receipt.tunnel_id != tunnel_id or receipt.generation != generation
                or not verify_token_receipt(receipt, self._verifier, now=self._now,
                                            selected_enrollment_id=tunnel_enrollment_id)):
            raise RemoteOriginDenied("root tunnel-token receipt failed signature or selection checks")
        return receipt


def verify_token_receipt(receipt: ProtectedTunnelTokenReceipt, signer: ReceiptSigner, *,
                         now: Callable[[], float] = time.monotonic,
                         selected_enrollment_id: str | None = None) -> bool:
    if not isinstance(receipt, ProtectedTunnelTokenReceipt):
        return False
    t = float(now())
    return (receipt.schema == 1 and receipt.file_device > 0 and receipt.file_inode > 0
            and receipt.owner_uid >= 0 and receipt.mode == 0o400
            and receipt.issued_monotonic <= t < receipt.expires_monotonic
            and receipt.expires_monotonic - receipt.issued_monotonic <= 30.0
            and (selected_enrollment_id is None or receipt.tunnel_enrollment_id == selected_enrollment_id)
            and signer.verify(receipt.payload(), receipt.signature))


def verify_selected_remote_origin(
    remote_enrollment_id: str, *, catalog: RemoteOriginCatalog,
    process_manager: RemoteOriginProcessManager,
    gateway_probe: SelectedRemoteOriginProbeAuthority,
    root_probe_handle: str,
    signer: ReceiptSigner, now: Callable[[], float] = time.monotonic,
) -> RootOriginReadinessReceipt:
    """Issue readiness only from a current root-registered private transport result."""
    _validate_id(remote_enrollment_id, "remote enrollment ID")
    selected = catalog.selected_origin(remote_enrollment_id)
    if (not isinstance(selected, SelectedRemoteOrigin) or selected.enrollment_id != remote_enrollment_id
            or not selected.owned):
        raise RemoteOriginDenied("selected remote origin is absent or not installer-owned")
    try:
        origin = urlsplit(selected.expected_origin)
        host = selected.expected_hostname.casefold()
        if (origin.scheme != "https" or origin.netloc.casefold() != host
                or origin.path not in {"", "/"} or origin.query or origin.fragment
                or origin.username or origin.password):
            raise ValueError
    except (ValueError, AttributeError):
        raise RemoteOriginDenied("selected public origin does not match its enrolled hostname") from None
    evidence = process_manager.inspect_selected_origin(selected)
    if not isinstance(evidence, KernelOriginEvidence):
        raise RemoteOriginDenied("root process manager returned no typed kernel evidence")
    if (not _finite_monotonic(evidence.expires_monotonic)
            or evidence.expires_monotonic <= float(now())):
        raise RemoteOriginDenied("root PIDFD and native-process observation expired")
    equal_fields = ((evidence.gateway_generation, selected.gateway_generation),
                    (evidence.desktop_generation, selected.desktop_generation),
                    (evidence.connector_target_id, selected.connector_target_id),
                    (evidence.policy_config_digest, selected.policy_config_digest),
                    (evidence.policy_revision, selected.policy_revision),
                    (evidence.service_generation_digest, selected.service_generation_digest))
    if any(actual != expected for actual, expected in equal_fields):
        raise RemoteOriginDenied("selected origin generations or policy configuration changed")
    proofs = (evidence.pidfd_live, evidence.pidfd_bound_to_process, evidence.start_time_stable,
              evidence.executable_pinned, evidence.cgroup_pinned, evidence.namespace_pinned,
              evidence.mount_pinned)
    if not all(value is True for value in proofs):
        raise RemoteOriginDenied("kernel process or app-only confinement proof is incomplete")
    if not isinstance(gateway_probe, SelectedRemoteOriginProbeAuthority):
        raise RemoteOriginDenied("root selected-origin probe authority is required")
    _opaque_handle(root_probe_handle, "root origin probe handle")
    probe_receipt, probe = gateway_probe.resolve_probe_receipt(selected, root_probe_handle)
    if (not isinstance(probe, Mapping) or set(probe) != ORIGIN_PROBE_OBSERVATIONS
            or any(probe[key] is not True for key in ORIGIN_PROBE_OBSERVATIONS)
            or not signer.verify(probe_receipt.payload(), probe_receipt.signature)
            or probe_receipt.remote_enrollment_id != selected.enrollment_id
            or probe_receipt.gateway_identity_digest != evidence.gateway_identity_digest
            or probe_receipt.desktop_generation != selected.desktop_generation
            or probe_receipt.connector_target_id != selected.connector_target_id
            or probe_receipt.policy_config_digest != selected.policy_config_digest
            or probe_receipt.policy_revision != selected.policy_revision
            or probe_receipt.service_generation_digest != selected.service_generation_digest
            or not _finite_monotonic(probe_receipt.expires_monotonic)
            or probe_receipt.expires_monotonic <= float(now())):
        raise RemoteOriginDenied("live gateway did not prove the selected official app-only origin")
    assertion_ids = tuple(evidence.observed_assertion_ids)
    if (not assertion_ids or len(assertion_ids) > 64
            or any(not isinstance(v, str) or not v or len(v) > 128 for v in assertion_ids)):
        raise RemoteOriginDenied("root origin evidence assertion set is missing or malformed")
    assertion_ids = tuple(dict.fromkeys(assertion_ids + probe_receipt.observed_assertion_ids + tuple(
        "gateway:" + name for name in sorted(ORIGIN_PROBE_OBSERVATIONS))))
    issued = float(now())
    if not (issued >= 0 and issued < float("inf")):
        raise RemoteOriginDenied("root monotonic clock is invalid")
    expiry = min(probe_receipt.expires_monotonic,
                 math.nextafter(issued + 30.0, -math.inf))
    if expiry <= issued:
        raise RemoteOriginDenied("root probe receipt expired before readiness issuance")
    unsigned = dict(schema=1, receipt_id=secrets.token_urlsafe(24),
                    remote_enrollment_id=selected.enrollment_id,
                    gateway_identity_digest=evidence.gateway_identity_digest,
                    desktop_generation=selected.desktop_generation,
                    connector_target_id=selected.connector_target_id,
                    policy_config_digest=selected.policy_config_digest,
                    policy_revision=selected.policy_revision,
                    service_generation_digest=selected.service_generation_digest,
                    probe_receipt_handle=probe_receipt.probe_receipt_handle,
                    observed_assertion_ids=assertion_ids, issued_monotonic=issued,
                        expires_monotonic=expiry)
    provisional = RootOriginReadinessReceipt(**unsigned, signature=b"")
    return RootOriginReadinessReceipt(**unsigned, signature=signer.sign(provisional.payload()))


def verify_origin_receipt(receipt: RootOriginReadinessReceipt, signer: ReceiptSigner, *,
                          now: Callable[[], float] = time.monotonic,
                          selected_enrollment_id: str | None = None,
                          expected_probe_receipt_handle: str | None = None) -> bool:
    if not isinstance(receipt, RootOriginReadinessReceipt):
        return False
    t = float(now())
    return (receipt.schema == 1
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.gateway_identity_digest))
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.policy_config_digest))
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.service_generation_digest))
            and bool(_PROBE_OPAQUE.fullmatch(receipt.probe_receipt_handle))
            and bool(receipt.observed_assertion_ids)
            and receipt.issued_monotonic <= t < receipt.expires_monotonic
            and receipt.expires_monotonic - receipt.issued_monotonic <= 30.0
            and (selected_enrollment_id is None or receipt.remote_enrollment_id == selected_enrollment_id)
            and (expected_probe_receipt_handle is None
                 or receipt.probe_receipt_handle == expected_probe_receipt_handle)
            and signer.verify(receipt.payload(), receipt.signature))
