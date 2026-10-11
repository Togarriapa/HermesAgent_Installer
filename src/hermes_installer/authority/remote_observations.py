"""Root-only observations for the private remote Desktop readiness probe.

This module does not accept gateway-produced readiness flags.  The gateway
observer makes fixed loopback HTTP requests and compares them with the root
HI07/HI12 byte ledger.  The window observer connects to the catalog-selected
local X server, uses XRes' server-reported client PID for the selected window,
and joins that PID to current procfs/PIDFD/cgroup/executable custody.

The observers are intentionally Linux/X11 specific.  Wayland, X servers
without XRes local-PID support, missing PIDFD/procfs custody, or an unavailable
root connector ledger produce an unavailable result rather than a weaker
claim.  The module never stores or returns captured pixels; it hashes a bounded
sample from the selected application's mapped window in memory.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import hashlib
import json
import math
import os
import re
import select
import socket
import stat
import struct
import time
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol


class RemoteObservationUnavailable(PermissionError):
    """Required current OS or root-authority evidence is unavailable."""


class RemoteObservationSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value: str) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _lease(now: float, deadline: float) -> float:
    if (not isinstance(deadline, (int, float)) or isinstance(deadline, bool)
            or not math.isfinite(float(deadline)) or deadline <= now
            or deadline - now > 30.0):
        raise RemoteObservationUnavailable("root origin observation deadline is stale or exceeds 30 seconds")
    return float(deadline)


@dataclass(frozen=True, slots=True, repr=False)
class SelectedGatewayBoundary:
    """Immutable listener selection resolved from the active root catalog."""
    remote_enrollment_id: str
    gateway_profile_id: str
    gateway_generation: str
    gateway_identity_digest: str
    hostname: str
    listener_port: int
    policy_config_digest: str
    policy_revision: str


@dataclass(frozen=True, slots=True, repr=False)
class SelectedNativeWindow:
    """Protected display and official Desktop identity selection.

    Paths and the Xauthority cookie stay inside root. ``allowed_executable_sha256s``
    is derived from the active official package closure, not a gateway label.
    """
    remote_enrollment_id: str
    native_profile_id: str
    native_generation: str
    native_uid: int
    native_cgroup_id: str
    allowed_executable_sha256s: tuple[str, ...]
    display_server_profile_id: str
    display_server_generation: str
    display_name: str
    xauthority_path: Path = field(repr=False)
    xauthority_device: int
    xauthority_inode: int
    xauthority_uid: int
    xauthority_receipt_handle: str = field(default="", repr=False)
    xauthority_gid: int = 0
    xauthority_mode: int = 0o600
    xauthority_sha256: str = field(default="", repr=False)


class RemoteObservationCatalog(Protocol):
    """Protected active-catalog accessors; never implemented by the gateway."""
    def selected_gateway_boundary(self, remote_enrollment_id: str) -> SelectedGatewayBoundary: ...
    def selected_native_window(self, remote_enrollment_id: str) -> SelectedNativeWindow: ...


class RootConnectorByteLedger(Protocol):
    """Root HI07/HI12 effect ledger scoped to the selected remote enrollment."""
    def snapshot_remote_probe_bytes(self, capability: Any) -> Any: ...


class RootProcessCustody(Protocol):
    """The active root custody registry used for actual peer PIDFD resolution."""
    def inspect_enrolled_process(self, profile_id: str, generation: str) -> Any: ...
    def resolve_live_peer(self, pid: int, pidfd: int, *,
                          profile_id: str, generation: str) -> Any: ...
    def resolve_observer_namespace_lease(self, profile_id: str, generation: str,
                                        expected_namespace_identity: str) -> Any: ...


class RootXauthorityStartupRegistry(Protocol):
    def resolve_catalog_selection(self, catalog: Any, remote_enrollment_id: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class GatewayBoundaryHTTPFact:
    status_code: int
    application_bytes: int
    request_sha256: str
    response_sha256: str


@dataclass(frozen=True, slots=True)
class GatewayBoundaryObservation:
    gateway_identity_digest: str
    policy_config_digest: str
    policy_revision: str
    network_namespace_inode: int
    listener_addresses: tuple[str, ...]
    requests: Mapping[str, GatewayBoundaryHTTPFact]
    issued_monotonic: float
    expires_monotonic: float
    assertion_ids: tuple[str, ...]
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({
            "gateway_identity_digest": self.gateway_identity_digest,
            "policy_config_digest": self.policy_config_digest,
            "policy_revision": self.policy_revision,
            "network_namespace_inode": self.network_namespace_inode,
            "listener_addresses": list(self.listener_addresses),
            "requests": {key: {item.name: getattr(value, item.name)
                                for item in fields(value)}
                         for key, value in sorted(self.requests.items())},
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
            "assertion_ids": list(self.assertion_ids),
        })

    def verify(self, signer: RemoteObservationSigner, *, now: float,
               selected: SelectedGatewayBoundary) -> bool:
        return (isinstance(selected, SelectedGatewayBoundary)
                and self.policy_config_digest == selected.policy_config_digest
                and self.policy_revision == selected.policy_revision
                and self.gateway_identity_digest == selected.gateway_identity_digest
                and self.issued_monotonic <= now < self.expires_monotonic
                and self.expires_monotonic - self.issued_monotonic <= 30.0
                and set(self.requests) == _DENIAL_REQUESTS
                and all(f.status_code in {403, 404} and f.application_bytes == 0
                        and _sha(f.request_sha256) and _sha(f.response_sha256)
                        for f in self.requests.values())
                and self.listener_addresses == (f"127.0.0.1:{selected.listener_port}",)
                and self.network_namespace_inode > 0
                and self.assertion_ids == _GATEWAY_ASSERTIONS
                and signer.verify(self.payload(), self.signature))


@dataclass(frozen=True, slots=True)
class NativeWindowObservation:
    profile_id: str
    generation: str
    uid: int
    pid: int
    pid_starttime_ticks: int
    websocket_observation_id: str
    window_identity_sha256: str
    surface_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    assertion_ids: tuple[str, ...]
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({item.name: getattr(self, item.name) for item in fields(self)
                           if item.name != "signature"})

    def verify(self, signer: RemoteObservationSigner, *, now: float,
               selected: SelectedNativeWindow,
               websocket_observation_id: str) -> bool:
        return (isinstance(selected, SelectedNativeWindow)
                and self.profile_id == selected.native_profile_id
                and self.generation == selected.native_generation
                and self.uid == selected.native_uid and self.pid > 0
                and self.pid_starttime_ticks > 0
                and self.websocket_observation_id == websocket_observation_id
                and bool(re.fullmatch(r"[A-Za-z0-9_-]{16,128}", websocket_observation_id))
                and _sha(self.window_identity_sha256) and _sha(self.surface_sha256)
                and self.issued_monotonic <= now < self.expires_monotonic
                and self.expires_monotonic - self.issued_monotonic <= 30.0
                and self.assertion_ids == _NATIVE_ASSERTIONS
                and signer.verify(self.payload(), self.signature))


@dataclass(frozen=True, slots=True, repr=False)
class NativeWindowInputObservation:
    """Root-private sealed receipt for exactly one observed F24 key pair.

    ``window_id`` and Xauthority receipt handles are included in the signed
    payload but are intentionally hidden from repr and must never be serialized
    into a gateway or worker-visible DTO.
    """
    remote_enrollment_id: str
    websocket_observation_id: str
    native_profile_id: str
    native_generation: str
    native_pid: int
    native_pid_start_ticks: int
    display_profile_id: str
    display_generation: str
    display_name: str = field(repr=False)
    xauthority_receipt_handle: str = field(repr=False)
    window_id: int = field(repr=False)
    keycode: int
    delivered_keypress_count: int
    delivered_keyrelease_count: int
    delivered_event_types: tuple[int, ...] = field(repr=False)
    focus_stable: bool
    focus_restored: bool
    outcome: str
    focus_observation_handle: str = field(repr=False)
    event_observation_handle: str = field(repr=False)
    issued_monotonic: float
    expires_monotonic: float
    assertion_ids: tuple[str, ...]
    signature: bytes = field(repr=False, compare=False)

    def payload(self) -> bytes:
        return _canonical({item.name: getattr(self, item.name) for item in fields(self)
                           if item.name != "signature"})

    def verify(self, signer: RemoteObservationSigner, *, now: float,
               selected: SelectedNativeWindow, websocket_observation_id: str) -> bool:
        return (isinstance(selected, SelectedNativeWindow)
                and self.remote_enrollment_id == selected.remote_enrollment_id
                and self.websocket_observation_id == websocket_observation_id
                and self.native_profile_id == selected.native_profile_id
                and self.native_generation == selected.native_generation
                and self.display_profile_id == selected.display_server_profile_id
                and self.display_generation == selected.display_server_generation
                and self.display_name == selected.display_name
                and self.xauthority_receipt_handle == selected.xauthority_receipt_handle
                and self.window_id > 0 and self.native_pid > 0
                and self.native_pid_start_ticks > 0 and self.keycode > 0
                and self.delivered_keypress_count in {0, 1}
                and self.delivered_keyrelease_count in {0, 1}
                and all(event_type in {2, 3} for event_type in self.delivered_event_types)
                and self.delivered_keypress_count == self.delivered_event_types.count(2)
                and self.delivered_keyrelease_count == self.delivered_event_types.count(3)
                and self.outcome in {"complete", "partial"}
                and ((self.outcome == "complete"
                      and self.delivered_keypress_count == 1
                      and self.delivered_keyrelease_count == 1
                      and self.delivered_event_types == (2, 3) and self.focus_stable
                      and self.focus_restored)
                     or (self.outcome == "partial"
                         and not (self.delivered_keypress_count == 1
                                  and self.delivered_keyrelease_count == 1
                                  and self.delivered_event_types == (2, 3)
                                  and self.focus_stable and self.focus_restored)))
                and bool(re.fullmatch(r"[A-Za-z0-9_-]{16,128}", self.focus_observation_handle))
                and bool(re.fullmatch(r"[A-Za-z0-9_-]{16,128}", self.event_observation_handle))
                and self.issued_monotonic <= now < self.expires_monotonic
                and self.expires_monotonic - self.issued_monotonic <= 30.0
                and self.assertion_ids == _NATIVE_INPUT_ASSERTIONS
                and signer.verify(self.payload(), self.signature))


_DENIAL_REQUESTS = frozenset({"unauthenticated", "arbitrary-route", "shell-route", "full-host-desktop"})
_GATEWAY_ASSERTIONS = (
    "remote-boundary:loopback-listener", "remote-boundary:unauthenticated-before-connector",
    "remote-boundary:arbitrary-route-before-connector", "remote-boundary:shell-route-before-connector",
    "remote-boundary:full-host-desktop-before-connector",
)
_NATIVE_ASSERTIONS = (
    "remote-window:xres-local-client-pid", "remote-window:pidfd-live",
    "remote-window:profile-cgroup", "remote-window:official-package-executable",
    "remote-window:selected-xserver-peer", "remote-window:active-viewable-window",
    "remote-window:bound-websocket-observation",
)
_NATIVE_INPUT_ASSERTIONS = (
    "remote_desktop.native_input.current_selected_xres_window",
    "remote_desktop.native_input.focus_observed_at_each_f24_boundary",
    "remote_desktop.native_input.f24_event_delivery_measured",
    "remote_desktop.native_input.focus_restore_observed_and_identity_revalidated",
)


class GatewayBoundaryObserver:
    """Perform four actual bounded rejection requests at the selected loopback listener.

    This is a concrete callable for the root origin aggregator. It rejects missing
    catalog, custody or HI12 byte-ledger support during construction; there is no
    switch that treats a gateway boolean as evidence.
    """

    _PATHS = {
        "unauthenticated": "/client/bootstrap.html",
        "arbitrary-route": "/api/backend",
        "shell-route": "/terminal",
        "full-host-desktop": "/desktop",
    }

    def __init__(self, *, catalog: RemoteObservationCatalog,
                 custody: RootProcessCustody, connector_ledger: RootConnectorByteLedger,
                 signer: RemoteObservationSigner,
                 monotonic: Callable[[], float] = time.monotonic,
                 timeout_seconds: float = 2.0):
        if (not callable(getattr(catalog, "selected_gateway_boundary", None))
                or not callable(getattr(custody, "inspect_enrolled_process", None))
                or not callable(getattr(custody, "resolve_live_peer", None))
                or not callable(getattr(connector_ledger, "snapshot_remote_probe_bytes", None))
                or not callable(getattr(signer, "sign", None))
                or not 0.1 <= timeout_seconds <= 2.0):
            raise RemoteObservationUnavailable("root gateway observer dependencies are incomplete")
        self._catalog, self._custody, self._ledger, self._signer = catalog, custody, connector_ledger, signer
        self._now, self._timeout = monotonic, timeout_seconds

    def __call__(self, selected: Any, gateway_identity_digest: str,
                 gateway_proof: Any, deadline: float,
                 capability: Any) -> GatewayBoundaryObservation:
        _require_root_linux()
        now = float(self._now())
        expiry = _lease(now, deadline)
        enrollment_id = getattr(selected, "enrollment_id", None)
        if not isinstance(enrollment_id, str) or not _sha(gateway_identity_digest):
            raise RemoteObservationUnavailable("root selected gateway identity is malformed")
        _verify_ledger_capability(capability, enrollment_id=enrollment_id,
            gateway_identity_digest=gateway_identity_digest, deadline=expiry, now=now)
        row = self._catalog.selected_gateway_boundary(enrollment_id)
        if (not isinstance(row, SelectedGatewayBoundary)
                or row.remote_enrollment_id != enrollment_id
                or row.gateway_identity_digest != gateway_identity_digest
                or getattr(gateway_proof, "profile_id", None) != row.gateway_profile_id
                or getattr(gateway_proof, "generation",
                           getattr(gateway_proof, "profile_generation", None)) != row.gateway_generation
                or not 1 <= row.listener_port <= 65535
                or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", row.hostname)
                or not _sha(row.policy_config_digest)
                or not row.policy_revision):
            raise RemoteObservationUnavailable("active gateway boundary row does not match root process proof")
        identity = self._current_identity(row.gateway_profile_id, row.gateway_generation,
                                          gateway_proof)
        listeners = _observe_loopback_listener(identity, row.listener_port)
        lease_resolver = getattr(self._custody, "resolve_observer_namespace_lease", None)
        if not callable(lease_resolver):
            raise RemoteObservationUnavailable("root observer namespace lease resolver is unavailable")
        namespace_identity = f"mnt:{identity['mount_namespace_inode']};net:{identity['network_namespace_inode']}"
        try:
            namespace_lease = lease_resolver(row.gateway_profile_id, row.gateway_generation,
                                             namespace_identity)
        except Exception:
            namespace_lease = None
        if (namespace_lease is None
                or getattr(namespace_lease, "generation", None) != row.gateway_generation
                or getattr(namespace_lease, "namespace_identity", None) != namespace_identity
                or getattr(namespace_lease, "namespace_fd", -1) < 0):
            if namespace_lease is not None:
                namespace_lease.close()
            raise RemoteObservationUnavailable("selected gateway has no exact live root namespace lease")
        try:
            ledger_before = _connector_byte_snapshot(self._ledger, capability)
            facts: dict[str, GatewayBoundaryHTTPFact] = {}
            for name in ("unauthenticated", "arbitrary-route", "shell-route", "full-host-desktop"):
                if float(self._now()) >= expiry:
                    raise RemoteObservationUnavailable("gateway boundary probe exceeded its root lease")
                raw_request = _http_request(row.hostname, self._PATHS[name])
                response, raw_response = _loopback_http(
                    row.listener_port, raw_request, self._timeout,
                    namespace_fd=namespace_lease.namespace_fd)
                if response.status not in {403, 404}:
                    raise RemoteObservationUnavailable(f"selected gateway did not deny the fixed {name} route")
                facts[name] = GatewayBoundaryHTTPFact(
                    status_code=response.status, application_bytes=0,
                    request_sha256=hashlib.sha256(raw_request).hexdigest(),
                    response_sha256=hashlib.sha256(raw_response).hexdigest())
                # Any partial byte movement through the actual root HI07/HI12 connector
                # invalidates this denial regardless of what HTTP status was returned.
                current = _connector_byte_snapshot(self._ledger, capability)
                if current != ledger_before:
                    raise RemoteObservationUnavailable("connector bytes/effects changed during a denial request")
        finally:
            namespace_lease.close()
        self._current_identity(row.gateway_profile_id, row.gateway_generation, gateway_proof)
        issued = float(self._now())
        unsigned = GatewayBoundaryObservation(
            gateway_identity_digest=gateway_identity_digest,
            policy_config_digest=row.policy_config_digest, policy_revision=row.policy_revision,
            network_namespace_inode=identity["network_namespace_inode"],
            listener_addresses=listeners, requests=facts, issued_monotonic=issued,
            expires_monotonic=min(expiry, issued + 30.0), assertion_ids=_GATEWAY_ASSERTIONS,
            signature=b"")
        receipt = GatewayBoundaryObservation(**{item.name: getattr(unsigned, item.name)
            for item in fields(unsigned) if item.name != "signature"},
            signature=self._signer.sign(unsigned.payload()))
        if not receipt.verify(self._signer, now=issued, selected=row):
            raise RemoteObservationUnavailable("root-signed gateway observation failed self-validation")
        return receipt

    def _current_identity(self, profile_id: str, generation: str, expected: Any) -> dict[str, int]:
        try:
            identity = self._custody.inspect_enrolled_process(profile_id, generation)
        except Exception:
            raise RemoteObservationUnavailable("selected gateway custody proof is unavailable") from None
        facts = _verify_custody_process(identity, expected, now=float(self._now()))
        pidfd = _verify_linux_pid(identity)
        os.close(pidfd)
        return facts

    def close(self) -> None:
        """No persistent descriptors or leases are held by this observer."""
        return None


def _verify_ledger_capability(capability: Any, *, enrollment_id: str,
                              gateway_identity_digest: str, deadline: float,
                              now: float) -> None:
    """Reject worker-shaped values before the ledger's independent signature check."""
    names = ("probe_handle", "remote_enrollment_id", "gateway_identity_digest",
             "gateway_profile_id", "gateway_generation", "native_enrollment_id",
             "session_id", "policy_config_digest", "policy_revision",
             "issued_monotonic", "expires_monotonic", "signature")
    if capability is None or any(not hasattr(capability, name) for name in names):
        raise RemoteObservationUnavailable("root-signed probe-ledger capability is unavailable")
    if (not re.fullmatch(r"[A-Za-z0-9_-]{43}", capability.probe_handle)
            or capability.remote_enrollment_id != enrollment_id
            or capability.gateway_identity_digest != gateway_identity_digest
            or not isinstance(capability.gateway_profile_id, str) or not capability.gateway_profile_id
            or not isinstance(capability.gateway_generation, str) or not capability.gateway_generation
            or not isinstance(capability.native_enrollment_id, str) or not capability.native_enrollment_id
            or not isinstance(capability.session_id, str) or not capability.session_id
            or not _sha(capability.policy_config_digest)
            or not isinstance(capability.policy_revision, str) or not capability.policy_revision
            or not math.isfinite(float(capability.issued_monotonic))
            or not math.isfinite(float(capability.expires_monotonic))
            or capability.issued_monotonic > now
            or capability.expires_monotonic <= now
            or capability.expires_monotonic > min(deadline, now + 25.0)
            or not isinstance(capability.signature, bytes) or not capability.signature):
        raise RemoteObservationUnavailable("root probe-ledger capability is stale or mismatched")


def _connector_byte_snapshot(ledger: RootConnectorByteLedger,
                             capability: Any) -> tuple[int, int, int, int]:
    try:
        snapshot = ledger.snapshot_remote_probe_bytes(capability)
    except Exception:
        raise RemoteObservationUnavailable("root HI07/HI12 connector byte ledger is unavailable") from None
    names = ("read_bytes", "write_bytes", "open_effects", "frame_effects")
    values = tuple(getattr(snapshot, name, None) for name in names)
    if any(type(value) is not int or value < 0 for value in values):
        raise RemoteObservationUnavailable("root connector ledger returned no typed byte/effect counters")
    return values  # type: ignore[return-value]


def _verify_custody_process(identity: Any, expected: Any, *, now: float) -> dict[str, int]:
    names = ("profile_id", "enrollment_id", "profile_generation", "uid", "gid", "pid",
             "pid_starttime_ticks", "executable_device", "executable_inode", "executable_sha256",
             "cgroup_id", "mount_namespace_inode", "network_namespace_inode",
             "pidfd_registry_handle", "expires_monotonic")
    if any(not hasattr(identity, name) for name in names):
        raise RemoteObservationUnavailable("root gateway custody identity is incomplete")
    for name in names:
        if name == "expires_monotonic":
            continue
        expected_name = "generation" if name == "profile_generation" else name
        if getattr(identity, name) != getattr(expected, expected_name, None):
            raise RemoteObservationUnavailable("root gateway process changed after the selected proof")
    if (identity.uid <= 0 or identity.pid <= 0 or identity.pid_starttime_ticks <= 0
            or not _sha(identity.executable_sha256) or not identity.cgroup_id
            or not identity.pidfd_registry_handle or identity.expires_monotonic <= now):
        raise RemoteObservationUnavailable("root gateway process proof is stale or malformed")
    return {"pid": int(identity.pid), "start": int(identity.pid_starttime_ticks),
            "uid": int(identity.uid),
            "mount_namespace_inode": int(identity.mount_namespace_inode),
            "network_namespace_inode": int(identity.network_namespace_inode)}


def _proc_starttime(pid: int) -> int:
    if not sys_platform_linux():
        raise RemoteObservationUnavailable("procfs/PIDFD process checks require Linux")
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        # comm is parenthesized and may itself contain spaces/parentheses.
        tail = raw[raw.rfind(")") + 2:].split()
        return int(tail[19])  # field 22; tail begins at field 3
    except (OSError, ValueError, IndexError):
        raise RemoteObservationUnavailable("selected process start-time is unavailable") from None


def sys_platform_linux() -> bool:
    return os.name == "posix" and Path("/proc/self/stat").exists() and Path("/proc/net/tcp").exists()


def _require_root_linux() -> None:
    if not sys_platform_linux() or not hasattr(os, "pidfd_open") or os.geteuid() != 0:
        raise RemoteObservationUnavailable("root Linux procfs/PIDFD observer is unavailable on this host")


def _verify_linux_pid(identity: Any) -> int:
    if not sys_platform_linux() or not hasattr(os, "pidfd_open"):
        raise RemoteObservationUnavailable("Linux procfs and pidfd_open are required for gateway observation")
    pid = int(identity.pid)
    pidfd: int | None = None
    try:
        before = _proc_starttime(pid)
        pidfd = os.pidfd_open(pid, 0)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0) or before != int(identity.pid_starttime_ticks):
            raise RemoteObservationUnavailable("selected gateway PIDFD is dead or reused")
        netns = os.stat(f"/proc/{pid}/ns/net").st_ino
        exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            exe_stat = os.fstat(exe_fd)
            digest = hashlib.sha256()
            while True:
                chunk = os.read(exe_fd, 1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        finally:
            os.close(exe_fd)
        status = Path(f"/proc/{pid}/status").read_text(encoding="ascii")
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        actual_uid = int(uid_line.split()[1])
        if (netns != int(identity.network_namespace_inode)
                or actual_uid != int(identity.uid)
                or exe_stat.st_dev != int(identity.executable_device)
                or exe_stat.st_ino != int(identity.executable_inode)
                or digest.hexdigest() != identity.executable_sha256
                or before != _proc_starttime(pid)):
            raise RemoteObservationUnavailable("selected gateway executable, UID, namespace, or PID identity changed")
        return pidfd
    except RemoteObservationUnavailable:
        if pidfd is not None:
            os.close(pidfd)
        raise
    except (OSError, ValueError, TypeError):
        if pidfd is not None:
            os.close(pidfd)
        raise RemoteObservationUnavailable("selected gateway PIDFD/procfs proof is unavailable") from None


@dataclass(frozen=True, slots=True)
class _HTTPResponse:
    status: int
    body: bytes


def _http_request(host: str, path: str) -> bytes:
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n"
            "Accept: */*\r\n\r\n").encode("ascii")


def _loopback_http(port: int, request: bytes, timeout: float, *,
                   namespace_fd: int | None = None) -> tuple[_HTTPResponse, bytes]:
    sock = (_connect_in_namespace(namespace_fd, port, timeout) if namespace_fd is not None
            else socket.socket(socket.AF_INET, socket.SOCK_STREAM))
    sock.settimeout(timeout)
    try:
        if namespace_fd is None:
            sock.connect(("127.0.0.1", port))
        if sock.getpeername()[0] != "127.0.0.1":
            raise RemoteObservationUnavailable("gateway probe escaped the selected IPv4 loopback")
        sock.sendall(request)
        chunks: list[bytes] = []
        total = 0
        while total <= 64 * 1024:
            block = sock.recv(min(8192, 64 * 1024 + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        raw = b"".join(chunks)
        if len(raw) > 64 * 1024 or b"\r\n\r\n" not in raw:
            raise RemoteObservationUnavailable("gateway denial response is oversized or malformed")
        head, body = raw.split(b"\r\n\r\n", 1)
        status_line = head.split(b"\r\n", 1)[0].split()
        if len(status_line) < 3 or status_line[0] not in {b"HTTP/1.0", b"HTTP/1.1"}:
            raise RemoteObservationUnavailable("gateway denial response has an invalid status line")
        try:
            status = int(status_line[1])
        except ValueError:
            raise RemoteObservationUnavailable("gateway denial response status is malformed") from None
        if len(body) > 32 * 1024:
            raise RemoteObservationUnavailable("gateway denial body exceeds the root probe bound")
        return _HTTPResponse(status, body), raw
    except RemoteObservationUnavailable:
        raise
    except (OSError, TimeoutError):
        raise RemoteObservationUnavailable("bounded gateway loopback request failed") from None
    finally:
        sock.close()


def _connect_in_namespace(namespace_fd: int, port: int, timeout: float) -> socket.socket:
    """Connect from the selected namespace in an isolated thread, then restore it."""
    if not hasattr(os, "setns") or namespace_fd < 0:
        raise RemoteObservationUnavailable("Linux network namespace entry is unavailable")
    try:
        worker_namespace_fd = os.dup(namespace_fd)
    except OSError:
        raise RemoteObservationUnavailable("selected namespace lease descriptor is unavailable") from None
    result: list[socket.socket] = []
    failure: list[BaseException] = []
    done = threading.Event()

    def worker() -> None:
        original = None
        sock = None
        try:
            original = os.open("/proc/self/ns/net", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            os.setns(worker_namespace_fd, getattr(os, "CLONE_NEWNET", 0))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
            sock.settimeout(timeout)
            sock.connect(("127.0.0.1", port))
            result.append(sock)
            sock = None
        except BaseException as exc:
            failure.append(exc)
        finally:
            if sock is not None:
                sock.close()
            if original is not None:
                try:
                    os.setns(original, getattr(os, "CLONE_NEWNET", 0))
                except BaseException as exc:
                    failure.append(exc)
                os.close(original)
            os.close(worker_namespace_fd)
            done.set()

    thread = threading.Thread(target=worker, name="hermes-root-gateway-netns-probe", daemon=True)
    thread.start()
    if not done.wait(timeout + 0.25):
        raise RemoteObservationUnavailable("selected namespace connect exceeded its bounded deadline")
    if failure:
        for sock in result:
            sock.close()
        raise RemoteObservationUnavailable("selected namespace loopback connection failed") from None
    if len(result) != 1:
        raise RemoteObservationUnavailable("selected namespace loopback connection returned no socket")
    return result[0]


def _observe_loopback_listener(identity: Mapping[str, int], port: int) -> tuple[str, ...]:
    if not sys_platform_linux():
        raise RemoteObservationUnavailable("Linux TCP listener custody is unavailable")
    pid = identity["pid"]
    try:
        rows = Path(f"/proc/{pid}/net/tcp").read_text(encoding="ascii").splitlines()[1:]
        owned_socket_inodes = set()
        for entry in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                owned_socket_inodes.add(match.group(1))
        matching: list[str] = []
        for row in rows:
            columns = row.split()
            if len(columns) < 10 or columns[3] != "0A" or columns[9] not in owned_socket_inodes:
                continue
            address_hex, port_hex = columns[1].split(":", 1)
            address = socket.inet_ntoa(struct.pack("<I", int(address_hex, 16)))
            if address != "127.0.0.1":
                raise RemoteObservationUnavailable("selected gateway listener is not IPv4 loopback-only")
            local_port = int(port_hex, 16)
            if local_port != port:
                raise RemoteObservationUnavailable("selected gateway has an unselected TCP listener")
            matching.append(f"{address}:{local_port}")
        try:
            ipv6_rows = Path(f"/proc/{pid}/net/tcp6").read_text(encoding="ascii").splitlines()[1:]
        except FileNotFoundError:
            ipv6_rows = []
        if any(len(columns := row.split()) >= 10 and columns[3] == "0A"
               and columns[9] in owned_socket_inodes for row in ipv6_rows):
            raise RemoteObservationUnavailable("selected gateway has an unreviewed IPv6 TCP listener")
        if sorted(set(matching)) != [f"127.0.0.1:{port}"]:
            raise RemoteObservationUnavailable("selected gateway has no unique root-owned loopback listener")
        return (f"127.0.0.1:{port}",)
    except RemoteObservationUnavailable:
        raise
    except (OSError, ValueError, IndexError):
        raise RemoteObservationUnavailable("selected gateway listener inode is unavailable") from None


class NativeWindowObserver:
    """Observe the selected official app's actual X11 top-level window.

    XRes supplies the local client PID from the X server; window title, class,
    and `_NET_WM_PID` are never used as identity. The observed PID is opened as
    a pidfd and resolved through root custody to the selected native profile.
    """

    def __init__(self, *, catalog: RemoteObservationCatalog, custody: RootProcessCustody,
                 stream_registry: Any, xauthority_registry: RootXauthorityStartupRegistry,
                 signer: RemoteObservationSigner,
                 monotonic: Callable[[], float] = time.monotonic):
        if (not callable(getattr(catalog, "selected_native_window", None))
                or not callable(getattr(custody, "inspect_enrolled_process", None))
                or not callable(getattr(custody, "resolve_live_peer", None))
                or not callable(getattr(stream_registry, "resolve_window_stream", None))
                or not callable(getattr(xauthority_registry, "resolve_catalog_selection", None))
                or not callable(getattr(signer, "sign", None))):
            raise RemoteObservationUnavailable("root native-window observer dependencies are incomplete")
        self._catalog, self._custody, self._streams = catalog, custody, stream_registry
        self._xauthority = xauthority_registry
        self._signer, self._now = signer, monotonic

    def verify_input_observation(self, receipt: NativeWindowInputObservation,
                                 selected: Any, websocket_observation_id: str,
                                 *, now: float | None = None) -> bool:
        """Verify a sealed event receipt without exposing the root signer."""
        enrollment_id = getattr(selected, "enrollment_id", None)
        if not isinstance(enrollment_id, str):
            return False
        try:
            row = self._catalog.selected_native_window(enrollment_id)
        except Exception:
            return False
        return (isinstance(row, SelectedNativeWindow)
                and row.remote_enrollment_id == enrollment_id
                and isinstance(receipt, NativeWindowInputObservation)
                and receipt.verify(self._signer, now=float(self._now() if now is None else now),
                    selected=row, websocket_observation_id=websocket_observation_id))

    def __call__(self, selected: Any, native_proof: Any,
                 websocket_observation_id: str, deadline: float) -> NativeWindowObservation:
        _require_root_linux()
        now = float(self._now())
        expiry = _lease(now, deadline)
        enrollment_id = getattr(selected, "enrollment_id", None)
        row = self._catalog.selected_native_window(enrollment_id) if isinstance(enrollment_id, str) else None
        if (not isinstance(row, SelectedNativeWindow)
                or row.remote_enrollment_id != enrollment_id
                or getattr(native_proof, "profile_id", None) != row.native_profile_id
                or getattr(native_proof, "generation",
                           getattr(native_proof, "profile_generation", None)) != row.native_generation
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", websocket_observation_id)):
            raise RemoteObservationUnavailable("selected native-window row, process proof, or stream reference is mismatched")
        try:
            stream = self._streams.resolve_window_stream(
                websocket_observation_id, remote_enrollment_id=enrollment_id,
                native_profile_id=row.native_profile_id, native_generation=row.native_generation)
        except Exception:
            raise RemoteObservationUnavailable("WebSocket observation is not a current selected native stream") from None
        if (getattr(stream, "observation_id", None) != websocket_observation_id
                or getattr(stream, "remote_enrollment_id", None) != enrollment_id
                or getattr(stream, "native_profile_id", None) != row.native_profile_id
                or getattr(stream, "native_generation", None) != row.native_generation
                or getattr(stream, "binary_frame_count", 0) < 1
                or not _sha(getattr(stream, "byte_sha256", None))
                or not math.isfinite(float(getattr(stream, "expires_monotonic", 0)))
                or float(stream.expires_monotonic) <= now):
            raise RemoteObservationUnavailable("selected WebSocket stream has no live binary frame receipt")
        native_identity = self._current_profile(row.native_profile_id, row.native_generation,
                                                row.native_uid, row.native_cgroup_id,
                                                native_proof)
        server_identity = self._current_profile(row.display_server_profile_id,
            row.display_server_generation, None, None, None)
        try:
            authority_file = self._xauthority.resolve_catalog_selection(self._catalog, enrollment_id)
        except Exception:
            raise RemoteObservationUnavailable("current root Xauthority startup receipt is unavailable") from None
        try:
            _verify_xauthority_receipt(row, authority_file, server_identity)
            with _X11_LOCK:
                observed = _observe_x11_app_window(row, native_identity,
                    server_identity, self._custody, authority_file)
            _verify_xauthority_receipt(row, authority_file, server_identity)
        finally:
            close = getattr(authority_file, "close", None)
            if callable(close):
                close()
        if float(self._now()) >= expiry:
            raise RemoteObservationUnavailable("native-window probe expired before receipt creation")
        issued = float(self._now())
        unsigned = NativeWindowObservation(
            profile_id=row.native_profile_id, generation=row.native_generation,
            uid=row.native_uid, pid=observed["pid"],
            pid_starttime_ticks=observed["start"],
            websocket_observation_id=websocket_observation_id,
            window_identity_sha256=observed["window_digest"],
            surface_sha256=observed["surface_digest"], issued_monotonic=issued,
            expires_monotonic=min(expiry, float(stream.expires_monotonic), issued + 30.0),
            assertion_ids=_NATIVE_ASSERTIONS, signature=b"")
        receipt = NativeWindowObservation(**{item.name: getattr(unsigned, item.name)
            for item in fields(unsigned) if item.name != "signature"},
            signature=self._signer.sign(unsigned.payload()))
        if not receipt.verify(self._signer, now=issued, selected=row,
                              websocket_observation_id=websocket_observation_id):
            raise RemoteObservationUnavailable("root-signed native-window observation failed self-validation")
        return receipt

    @contextmanager
    def open_selected_window_target(self, selected: Any, native_proof: Any,
                                    websocket_observation_id: str,
                                    deadline: float) -> Iterator["_SelectedNativeWindowTarget"]:
        """Open a short-lived root-only target for the current observed stream.

        This deliberately accepts no XID, display name, cookie, path, PID or
        window label from the caller. Only the protected active catalog and a
        currently consumed native WebSocket observation can select a target.
        The yielded object does not expose its XID or Xlib display handle.
        """
        _require_root_linux()
        now = float(self._now())
        expiry = _lease(now, deadline)
        enrollment_id = getattr(selected, "enrollment_id", None)
        row = self._catalog.selected_native_window(enrollment_id) if isinstance(enrollment_id, str) else None
        if (not isinstance(row, SelectedNativeWindow)
                or row.remote_enrollment_id != enrollment_id
                or getattr(native_proof, "profile_id", None) != row.native_profile_id
                or getattr(native_proof, "generation",
                           getattr(native_proof, "profile_generation", None)) != row.native_generation
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", websocket_observation_id)):
            raise RemoteObservationUnavailable("selected native-window row, process proof, or stream reference is mismatched")
        try:
            stream = self._streams.resolve_window_stream(
                websocket_observation_id, remote_enrollment_id=enrollment_id,
                native_profile_id=row.native_profile_id, native_generation=row.native_generation)
        except Exception:
            raise RemoteObservationUnavailable("WebSocket observation is not a current selected native stream") from None
        stream_expiry = float(getattr(stream, "expires_monotonic", 0))
        if (getattr(stream, "observation_id", None) != websocket_observation_id
                or getattr(stream, "remote_enrollment_id", None) != enrollment_id
                or getattr(stream, "native_profile_id", None) != row.native_profile_id
                or getattr(stream, "native_generation", None) != row.native_generation
                or getattr(stream, "binary_frame_count", 0) < 1
                or not _sha(getattr(stream, "byte_sha256", None))
                or not math.isfinite(stream_expiry) or stream_expiry <= now):
            raise RemoteObservationUnavailable("selected WebSocket stream has no live binary frame receipt")
        native_identity = self._current_profile(row.native_profile_id, row.native_generation,
                                                row.native_uid, row.native_cgroup_id,
                                                native_proof)
        server_identity = self._current_profile(row.display_server_profile_id,
            row.display_server_generation, None, None, None)
        try:
            authority_file = self._xauthority.resolve_catalog_selection(self._catalog, enrollment_id)
        except Exception:
            raise RemoteObservationUnavailable("current root Xauthority startup receipt is unavailable") from None
        try:
            _verify_xauthority_receipt(row, authority_file, server_identity)
            with _X11_LOCK:
                # First derive the exact target through the ordinary observer,
                # then reconnect from the held receipt and revalidate that the
                # same XID is still owned by the same live selected process.
                observed = _observe_x11_app_window(row, native_identity,
                    server_identity, self._custody, authority_file)
                x11_name = ctypes.util.find_library("X11")
                xres_name = ctypes.util.find_library("XRes") or ctypes.util.find_library("Xres")
                if not x11_name or not xres_name:
                    raise RemoteObservationUnavailable("libX11/XRes is unavailable for selected-window input")
                x11, xres = ctypes.CDLL(x11_name), ctypes.CDLL(xres_name)
                display_number = row.display_name.split(":", 1)[1].split(".", 1)[0]
                cookie = _read_xauthority_receipt(row, authority_file, display_number, server_identity)
                try:
                    display = _xopen_authorized_display(x11, row.display_name, cookie)
                finally:
                    for index in range(len(cookie)):
                        cookie[index] = 0
                target = None
                try:
                    target = _SelectedNativeWindowTarget(
                        row=row, custody=self._custody, signer=self._signer,
                        x11=x11, xres=xres, display=display,
                        authority_file=authority_file,
                        native_identity=native_identity, server_identity=server_identity,
                        pid=observed["pid"], pid_start_ticks=observed["start"],
                        window_id=observed["xid"], websocket_observation_id=websocket_observation_id,
                        expires_monotonic=min(expiry, stream_expiry, now + 10.0),
                        monotonic=self._now)
                    target.revalidate_current()
                    yield target
                finally:
                    if target is not None:
                        target.close()
                    elif display:
                        x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
                        x11.XCloseDisplay.restype = ctypes.c_int
                        x11.XCloseDisplay(display)
        finally:
            close = getattr(authority_file, "close", None)
            if callable(close):
                close()

    def close(self) -> None:
        """No persistent descriptors or leases are held by this observer."""
        return None

    def _current_profile(self, profile_id: str, generation: str, uid: int | None,
                         cgroup_id: str | None, expected: Any) -> Any:
        try:
            current = self._custody.inspect_enrolled_process(profile_id, generation)
        except Exception:
            raise RemoteObservationUnavailable("selected native/display process custody is unavailable") from None
        if expected is not None:
            for name in ("profile_id", "generation", "uid", "pid", "pid_starttime_ticks",
                         "executable_device", "executable_inode", "executable_sha256", "cgroup_id",
                         "mount_namespace_inode", "network_namespace_inode", "pidfd_registry_handle"):
                expected_name = "profile_generation" if name == "generation" else name
                if getattr(current, name, getattr(current, expected_name, None)) != getattr(expected, name, getattr(expected, expected_name, None)):
                    raise RemoteObservationUnavailable("selected native process identity changed")
        if uid is not None and current.uid != uid:
            raise RemoteObservationUnavailable("selected native profile UID changed")
        if cgroup_id is not None and str(current.cgroup_id) != cgroup_id:
            raise RemoteObservationUnavailable("selected native process cgroup changed")
        if not _sha(getattr(current, "executable_sha256", None)):
            raise RemoteObservationUnavailable("selected process executable digest is unavailable")
        pidfd = _verify_linux_pid(current)
        os.close(pidfd)
        return current


class _X11KeyEvent(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_int), ("serial", ctypes.c_ulong),
        ("send_event", ctypes.c_int), ("display", ctypes.c_void_p),
        ("window", ctypes.c_ulong), ("root", ctypes.c_ulong),
        ("subwindow", ctypes.c_ulong), ("time", ctypes.c_ulong),
        ("x", ctypes.c_int), ("y", ctypes.c_int),
        ("x_root", ctypes.c_int), ("y_root", ctypes.c_int),
        ("state", ctypes.c_uint), ("keycode", ctypes.c_uint),
        ("same_screen", ctypes.c_int),
    ]


class _X11Event(ctypes.Union):
    # XEvent is 24 longs on both ILP32 and LP64 Xlib ABIs.
    _fields_ = [("type", ctypes.c_int), ("xkey", _X11KeyEvent),
                ("_pad", ctypes.c_long * 24)]


class _SelectedNativeWindowTarget:
    """In-memory, one-shot X11 target. No XID/display getter is exposed."""

    def __init__(self, *, row: SelectedNativeWindow, custody: RootProcessCustody,
                 signer: RemoteObservationSigner, x11: Any, xres: Any, display: int,
                 authority_file: Any, native_identity: Any, server_identity: Any,
                 pid: int, pid_start_ticks: int, window_id: int,
                 websocket_observation_id: str, expires_monotonic: float,
                 monotonic: Callable[[], float]):
        self._row, self._custody, self._signer = row, custody, signer
        self._x11, self._xres, self._display = x11, xres, display
        self._authority_file = authority_file
        self._native_identity, self._server_identity = native_identity, server_identity
        self._pid, self._pid_start = int(pid), int(pid_start_ticks)
        self._window_id = int(window_id)
        self._websocket_id, self._expires = websocket_observation_id, expires_monotonic
        self._now, self._used, self._closed = monotonic, False, False
        self._pidfd = _open_pidfd(self._pid)

    def revalidate_current(self) -> None:
        if self._closed or float(self._now()) >= self._expires:
            raise RemoteObservationUnavailable("selected native-window target lease expired")
        try:
            pid_poller = select.poll()
            pid_poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if pid_poller.poll(0) or _proc_starttime(self._pid) != self._pid_start:
                raise RemoteObservationUnavailable("selected native-window client PIDFD is stale")
            current_server = self._custody.inspect_enrolled_process(
                self._row.display_server_profile_id, self._row.display_server_generation)
            _check_xserver_peer(self._x11, self._display, current_server)
            _verify_xauthority_receipt(self._row, self._authority_file, current_server)
            cookie = _read_xauthority_receipt(self._row, self._authority_file,
                self._row.display_name.split(":", 1)[1].split(".", 1)[0], current_server)
            for index in range(len(cookie)):
                cookie[index] = 0
            process = self._custody.resolve_live_peer(self._pid, self._pidfd,
                profile_id=self._row.native_profile_id, generation=self._row.native_generation)
            process_fields = _pidfd_process_fields(process, self._pid)
            if (process_fields["start"] != self._pid_start
                    or process_fields["uid"] != self._row.native_uid
                    or process_fields["cgroup_id"] != self._row.native_cgroup_id
                    or process_fields["executable_sha256"] not in self._row.allowed_executable_sha256s
                    or process_fields["executable_sha256"] != self._native_identity.executable_sha256):
                raise RemoteObservationUnavailable("selected XRes window no longer belongs to the selected native package")
            clients = _xres_client_pids(self._x11, self._xres, self._display)
            if (_owner_pid(self._window_id, clients) != self._pid
                    or not _xwindow_viewable(self._x11, self._display, self._window_id)):
                raise RemoteObservationUnavailable("selected XRes window changed owner or is no longer viewable")
        except RemoteObservationUnavailable:
            raise
        except Exception:
            raise RemoteObservationUnavailable("selected XRes target custody could not be revalidated") from None

    def send_f24_press_release_and_observe(self) -> NativeWindowInputObservation:
        """Deliver one F24 press/release pair to this exact focused X window."""
        if self._used:
            raise RemoteObservationUnavailable("selected native-window target is one-shot")
        self._used = True
        self.revalidate_current()
        xtst_name = ctypes.util.find_library("Xtst")
        if not xtst_name:
            raise RemoteObservationUnavailable("XTest client library is unavailable")
        xtst = ctypes.CDLL(xtst_name)
        xtst.XTestQueryExtension.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
            ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)]
        xtst.XTestQueryExtension.restype = ctypes.c_int
        event_base, error_base, major, minor = (ctypes.c_int() for _ in range(4))
        if not xtst.XTestQueryExtension(self._display, ctypes.byref(event_base),
                ctypes.byref(error_base), ctypes.byref(major), ctypes.byref(minor)):
            raise RemoteObservationUnavailable("selected X server does not support XTest")
        self._x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self._x11.XKeysymToKeycode.restype = ctypes.c_ubyte
        # XK_F24 is defined by X11/keysymdef.h as 0xFFD5.
        keycode = int(self._x11.XKeysymToKeycode(self._display, 0xFFD5))
        if not keycode:
            raise RemoteObservationUnavailable("selected X server keymap has no F24 keycode")
        xtst.XTestFakeKeyEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                                           ctypes.c_int, ctypes.c_ulong]
        xtst.XTestFakeKeyEvent.restype = ctypes.c_int
        self._x11.XSelectInput.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_long]
        self._x11.XSelectInput.restype = ctypes.c_int
        self._x11.XGetInputFocus.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong),
                                             ctypes.POINTER(ctypes.c_int)]
        self._x11.XGetInputFocus.restype = ctypes.c_int
        self._x11.XSetInputFocus.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
            ctypes.c_int, ctypes.c_ulong]
        self._x11.XSetInputFocus.restype = ctypes.c_int
        self._x11.XGrabServer.argtypes = [ctypes.c_void_p]; self._x11.XGrabServer.restype = ctypes.c_int
        self._x11.XUngrabServer.argtypes = [ctypes.c_void_p]; self._x11.XUngrabServer.restype = ctypes.c_int
        self._x11.XGrabKeyboard.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_ulong]
        self._x11.XGrabKeyboard.restype = ctypes.c_int
        self._x11.XUngrabKeyboard.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self._x11.XUngrabKeyboard.restype = ctypes.c_int
        self._x11.XSync.argtypes = [ctypes.c_void_p, ctypes.c_int]; self._x11.XSync.restype = ctypes.c_int
        self._x11.XPending.argtypes = [ctypes.c_void_p]; self._x11.XPending.restype = ctypes.c_int
        self._x11.XNextEvent.argtypes = [ctypes.c_void_p, ctypes.POINTER(_X11Event)]
        self._x11.XNextEvent.restype = ctypes.c_int
        self._x11.XFlush.argtypes = [ctypes.c_void_p]; self._x11.XFlush.restype = ctypes.c_int

        previous_focus, revert = ctypes.c_ulong(), ctypes.c_int()
        self._x11.XGetInputFocus(self._display, ctypes.byref(previous_focus), ctypes.byref(revert))
        # KeyPressMask | KeyReleaseMask. Drain stale events before acquiring
        # focus so only this one operation can contribute to the receipt.
        self._x11.XSelectInput(self._display, self._window_id, (1 << 0) | (1 << 1))
        self._x11.XSync(self._display, 0)
        while self._x11.XPending(self._display):
            stale = _X11Event()
            self._x11.XNextEvent(self._display, ctypes.byref(stale))
        focus_samples: list[int] = []
        focus_id = ""
        events: list[tuple[int, int, int, int]] = []
        grabbed = False
        keyboard_grabbed = False
        press_queued = False
        focus_stable = True
        focus_restored = False
        partial_error: str | None = None
        try:
            self._x11.XGrabServer(self._display)
            grabbed = True
            self.revalidate_current()
            self._x11.XSetInputFocus(self._display, self._window_id, 2, 0)
            self._x11.XSync(self._display, 0)
            actual_focus, actual_revert = ctypes.c_ulong(), ctypes.c_int()
            self._x11.XGetInputFocus(self._display, ctypes.byref(actual_focus), ctypes.byref(actual_revert))
            if actual_focus.value != self._window_id:
                raise RemoteObservationUnavailable("selected X window did not receive input focus")
            focus_samples.append(int(actual_focus.value))
            # Route XTest key transitions only to the selected window even if
            # physical input changes X input focus while the server is grabbed.
            # A focus change still makes the observation partial and unusable.
            keyboard_grab = self._x11.XGrabKeyboard(self._display, self._window_id,
                0, 1, 1, 0)
            self._x11.XSync(self._display, 0)
            if keyboard_grab != 0:  # GrabSuccess is the X11 protocol value 0.
                raise RemoteObservationUnavailable("selected X window keyboard grab was not granted")
            keyboard_grabbed = True
            self.revalidate_current()
            before_press, before_press_revert = ctypes.c_ulong(), ctypes.c_int()
            self._x11.XGetInputFocus(self._display, ctypes.byref(before_press),
                                     ctypes.byref(before_press_revert))
            focus_samples.append(int(before_press.value))
            focus_stable = focus_stable and before_press.value == self._window_id
            if before_press.value != self._window_id:
                raise RemoteObservationUnavailable("selected X window focus changed before F24 press")
            pressed = bool(xtst.XTestFakeKeyEvent(self._display, keycode, 1, 0))
            if not pressed:
                raise RemoteObservationUnavailable("XTest could not queue exact F24 press/release")
            press_queued = True
            self._x11.XSync(self._display, 0)
            after_press, _ = ctypes.c_ulong(), ctypes.c_int()
            self._x11.XGetInputFocus(self._display, ctypes.byref(after_press), ctypes.byref(_))
            focus_samples.append(int(after_press.value))
            focus_stable = focus_stable and after_press.value == self._window_id
            released = bool(xtst.XTestFakeKeyEvent(self._display, keycode, 0, 0))
            if not released:
                # Do not leave a key logically held if release queueing fails.
                xtst.XTestFakeKeyEvent(self._display, keycode, 0, 0)
                partial_error = "XTest could not confirm exact F24 release queueing"
            self._x11.XSync(self._display, 0)
            after_release, after_release_revert = ctypes.c_ulong(), ctypes.c_int()
            self._x11.XGetInputFocus(self._display, ctypes.byref(after_release),
                                     ctypes.byref(after_release_revert))
            focus_samples.append(int(after_release.value))
            focus_stable = focus_stable and after_release.value == self._window_id
            deadline = min(self._expires, float(self._now()) + 1.0)
            while float(self._now()) < deadline and len(events) < 2:
                if not self._x11.XPending(self._display):
                    time.sleep(0.005)
                    continue
                event = _X11Event()
                self._x11.XNextEvent(self._display, ctypes.byref(event))
                key = event.xkey
                if key.window == self._window_id and key.keycode == keycode \
                        and not key.send_event and key.type in {2, 3}:
                    events.append((int(key.type), int(key.window), int(key.keycode), int(key.time)))
            self.revalidate_current()
        except RemoteObservationUnavailable as exc:
            if not press_queued:
                raise
            partial_error = partial_error or str(exc)
        except Exception:
            if not press_queued:
                raise RemoteObservationUnavailable("selected XTest request could not be made safely") from None
            partial_error = partial_error or "XTest request or observation failed after press queueing"
        finally:
            try:
                self._x11.XSetInputFocus(self._display, previous_focus.value,
                                         revert.value, 0)
                self._x11.XSync(self._display, 0)
                restored_focus, restored_revert = ctypes.c_ulong(), ctypes.c_int()
                self._x11.XGetInputFocus(self._display, ctypes.byref(restored_focus),
                                         ctypes.byref(restored_revert))
                focus_samples.append(int(restored_focus.value))
                focus_restored = restored_focus.value == previous_focus.value
            finally:
                if keyboard_grabbed:
                    self._x11.XUngrabKeyboard(self._display, 0)
                    self._x11.XSync(self._display, 0)
                if grabbed:
                    self._x11.XUngrabServer(self._display)
                    self._x11.XSync(self._display, 0)
        try:
            self.revalidate_current()
        except Exception:
            # The measured event result still needs a truthful signed partial
            # receipt if current custody changed after a press was queued.
            partial_error = partial_error or "selected native-window custody changed after F24 effect"
        press_count = sum(1 for item in events if item[0] == 2)
        release_count = sum(1 for item in events if item[0] == 3)
        focus_stable = focus_stable and len(focus_samples) == 5 and all(
            focus == self._window_id for focus in focus_samples[:4])
        focus_restored = focus_restored and focus_samples[-1] == previous_focus.value
        event_types = tuple(item[0] for item in events)
        outcome = ("complete" if press_count == 1 and release_count == 1
                   and event_types == (2, 3)
                   and focus_stable and focus_restored and partial_error is None else "partial")
        focus_id = hashlib.sha256(_canonical({
            "previous_focus": int(previous_focus.value), "revert": int(revert.value),
            "samples": focus_samples, "target": self._window_id,
            "at": float(self._now())})).hexdigest()
        issued = float(self._now())
        unsigned = NativeWindowInputObservation(
            remote_enrollment_id=self._row.remote_enrollment_id,
            websocket_observation_id=self._websocket_id,
            native_profile_id=self._row.native_profile_id,
            native_generation=self._row.native_generation,
            native_pid=self._pid, native_pid_start_ticks=self._pid_start,
            display_profile_id=self._row.display_server_profile_id,
            display_generation=self._row.display_server_generation,
            display_name=self._row.display_name,
            xauthority_receipt_handle=self._row.xauthority_receipt_handle,
            window_id=self._window_id, keycode=keycode,
            delivered_keypress_count=press_count, delivered_keyrelease_count=release_count,
            delivered_event_types=event_types,
            focus_stable=focus_stable, focus_restored=focus_restored, outcome=outcome,
            focus_observation_handle=focus_id,
            event_observation_handle=hashlib.sha256(_canonical(events)).hexdigest(),
            issued_monotonic=issued, expires_monotonic=min(self._expires, issued + 5.0),
            assertion_ids=_NATIVE_INPUT_ASSERTIONS, signature=b"")
        receipt = NativeWindowInputObservation(**{
            item.name: getattr(unsigned, item.name) for item in fields(unsigned)
            if item.name != "signature"}, signature=self._signer.sign(unsigned.payload()))
        if not receipt.verify(self._signer, now=issued, selected=self._row,
                              websocket_observation_id=self._websocket_id):
            raise RemoteObservationUnavailable("root F24 event receipt failed self-validation")
        return receipt

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            if self._pidfd >= 0:
                os.close(self._pidfd)
        finally:
            self._pidfd = -1
            if self._display:
                self._x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
                self._x11.XCloseDisplay.restype = ctypes.c_int
                self._x11.XCloseDisplay(self._display)
                self._display = 0


_X11_LOCK = threading.RLock()


def _observe_x11_app_window(row: SelectedNativeWindow, native_identity: Any,
                            server_identity: Any, custody: RootProcessCustody,
                            authority_file: Any) -> dict[str, Any]:
    if not sys_platform_linux() or not hasattr(os, "pidfd_open"):
        raise RemoteObservationUnavailable("native XRes window observation requires Linux PIDFD custody")
    if (not re.fullmatch(r":[0-9]{1,4}(?:\.[0-9]{1,2})?", row.display_name)
            or not row.allowed_executable_sha256s
            or any(not _sha(value) for value in row.allowed_executable_sha256s)):
        raise RemoteObservationUnavailable("catalog-selected local display or official package closure is malformed")
    display_number = row.display_name.split(":", 1)[1].split(".", 1)[0]
    cookie = _read_xauthority_receipt(row, authority_file, display_number,
                                      server_identity)
    x11_name = ctypes.util.find_library("X11")
    xres_name = ctypes.util.find_library("XRes") or ctypes.util.find_library("Xres")
    if not x11_name or not xres_name:
        raise RemoteObservationUnavailable("libX11 and libXRes with XRes local-PID support are required")
    try:
        x11, xres = ctypes.CDLL(x11_name), ctypes.CDLL(xres_name)
        display = _xopen_authorized_display(x11, row.display_name, cookie)
    except (OSError, AttributeError, ValueError):
        raise RemoteObservationUnavailable("selected private local X11 display could not be authenticated") from None
    try:
        _check_xserver_peer(x11, display, server_identity)
        root = _xroot_window(x11, display)
        clients = _xres_client_pids(x11, xres, display)
        window_ids = _x_descendants(x11, display, root)
        matched: list[tuple[int, int, int, str]] = []
        foreign: list[int] = []
        for xid in window_ids:
            if not _xwindow_viewable(x11, display, xid):
                continue
            owner_pid = _owner_pid(xid, clients)
            if owner_pid is None:
                raise RemoteObservationUnavailable("mapped X window has no XRes local-client PID identity")
            if owner_pid == server_identity.pid:
                # A dedicated X server may own its root support windows. Those
                # are not application surfaces and cannot satisfy the app proof.
                continue
            pidfd = _open_pidfd(owner_pid)
            try:
                process = custody.resolve_live_peer(owner_pid, pidfd,
                    profile_id=row.native_profile_id, generation=row.native_generation)
                process_fields = _pidfd_process_fields(process, owner_pid)
                if (process_fields["profile_id"] == row.native_profile_id
                        and process_fields["generation"] == row.native_generation
                        and process_fields["uid"] == row.native_uid
                        and process_fields["cgroup_id"] == row.native_cgroup_id
                        and process_fields["executable_sha256"] in row.allowed_executable_sha256s):
                    matched.append((xid, owner_pid, process_fields["start"], process_fields["executable_sha256"]))
                else:
                    foreign.append(xid)
            finally:
                os.close(pidfd)
        if not matched:
            raise RemoteObservationUnavailable("selected official Hermes Desktop has no current viewable XRes-owned window")
        # A foreign mapped app window in this dedicated display invalidates the
        # app-only claim; window titles/classes and _NET_WM_PID are not consulted.
        if foreign:
            raise RemoteObservationUnavailable("selected private display contains a mapped window outside the official package closure")
        for xid, pid, start, sha in matched:
            if _proc_starttime(pid) != start:
                raise RemoteObservationUnavailable("native XRes client PID was reused during observation")
        window_digest = hashlib.sha256(_canonical({
            "display": row.display_name,
            "server": _process_identity_digest(server_identity),
            "windows": sorted([{"xid": xid, "pid": pid, "start": start, "exe": sha}
                               for xid, pid, start, sha in matched],
                               key=lambda value: (value["xid"], value["pid"]))})).hexdigest()
        surface_digest = _hash_bounded_window_sample(x11, display, matched[0][0])
        first = matched[0]
        return {"pid": first[1], "start": first[2], "xid": first[0], "window_digest": window_digest,
                "surface_digest": surface_digest}
    finally:
        x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        x11.XCloseDisplay.restype = ctypes.c_int
        x11.XCloseDisplay(display)
        for index in range(len(cookie)):
            cookie[index] = 0


def _verify_xauthority_receipt(row: SelectedNativeWindow, receipt: Any,
                               server_identity: Any) -> None:
    names = ("file_fd", "pidfd", "device", "inode", "owner_uid", "owner_gid",
             "mode", "content_sha256", "process_id", "process_generation",
             "pid_start_ticks", "pidfd_identity", "cgroup_id", "close",
             "receipt_handle", "remote_enrollment_id", "native_profile_id",
             "native_generation", "display_profile_id", "display_generation",
             "display_name")
    if receipt is None or any(not hasattr(receipt, name) for name in names):
        raise RemoteObservationUnavailable("root Xauthority startup receipt is incomplete")
    if (type(receipt.file_fd) is not int or receipt.file_fd < 0
            or type(receipt.pidfd) is not int or receipt.pidfd < 0
            or not _sha(receipt.content_sha256)
            or receipt.receipt_handle != row.xauthority_receipt_handle
            or receipt.remote_enrollment_id != row.remote_enrollment_id
            or receipt.native_profile_id != row.native_profile_id
            or receipt.native_generation != row.native_generation
            or receipt.display_profile_id != row.display_server_profile_id
            or receipt.display_generation != row.display_server_generation
            or receipt.display_name != row.display_name
            or receipt.process_id != getattr(server_identity, "process_id", None)
            or receipt.process_generation != row.display_server_generation
            or receipt.pid_start_ticks != getattr(server_identity, "pid_starttime_ticks", None)
            or receipt.cgroup_id != getattr(server_identity, "cgroup_id", None)
            or not isinstance(receipt.pidfd_identity, str) or not receipt.pidfd_identity):
        raise RemoteObservationUnavailable("Xauthority receipt differs from selected file or live display identity")
    try:
        poller = select.poll()
        poller.register(receipt.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise RemoteObservationUnavailable("Xauthority receipt display-server PIDFD is stale")
        os.fstat(receipt.file_fd)
        os.fstat(receipt.pidfd)
    except RemoteObservationUnavailable:
        raise
    except OSError:
        raise RemoteObservationUnavailable("Xauthority receipt descriptors are no longer live") from None


def _read_xauthority_receipt(row: SelectedNativeWindow, receipt: Any,
                             display_number: str, server_identity: Any) -> bytearray:
    _verify_xauthority_receipt(row, receipt, server_identity)
    try:
        st = os.fstat(receipt.file_fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                or st.st_dev != receipt.device or st.st_ino != receipt.inode
                or st.st_uid != receipt.owner_uid or st.st_gid != receipt.owner_gid
                or stat.S_IMODE(st.st_mode) != receipt.mode or st.st_size > 64 * 1024):
            raise RemoteObservationUnavailable("held Xauthority startup file changed custody")
        raw = bytearray()
        offset = 0
        while offset <= 64 * 1024:
            block = os.pread(receipt.file_fd, min(4096, 64 * 1024 + 1 - offset), offset)
            if not block:
                break
            raw.extend(block)
            offset += len(block)
        if (len(raw) > 64 * 1024
                or hashlib.sha256(raw).hexdigest() != receipt.content_sha256):
            raise RemoteObservationUnavailable("held Xauthority bytes differ from the signed startup receipt")
        if os.fstat(receipt.file_fd).st_ino != st.st_ino:
            raise RemoteObservationUnavailable("held Xauthority inode changed during cookie read")
    except RemoteObservationUnavailable:
        raise
    except OSError:
        raise RemoteObservationUnavailable("held Xauthority startup file could not be read") from None
    return _select_xauthority_cookie(raw, display_number)


def _open_pidfd(pid: int) -> int:
    try:
        descriptor = os.pidfd_open(pid, 0)
        poller = select.poll(); poller.register(descriptor, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            os.close(descriptor)
            raise RemoteObservationUnavailable("XRes reported an exited or reused client process")
        return descriptor
    except RemoteObservationUnavailable:
        raise
    except OSError:
        raise RemoteObservationUnavailable("XRes local client PID cannot be bound to a live PIDFD") from None


def _pidfd_process_fields(process: Any, expected_pid: int) -> dict[str, Any]:
    # This DTO is deliberately the minimal live-peer identity returned by the
    # root process custodian after validating the supplied PIDFD against the
    # selected active profile/generation. PID is therefore the PIDFD we opened,
    # not a second PID value copied from an X property or worker message.
    required = ("profile_id", "generation", "kernel_uid", "start_ticks",
                "executable_sha256", "cgroup_identity", "namespace_identity")
    if process is None or any(not hasattr(process, item) for item in required):
        raise RemoteObservationUnavailable("root custody has no PIDFD-bound XRes client resolver")
    if (process.kernel_uid <= 0 or process.start_ticks != _proc_starttime(expected_pid)
            or not _sha(process.executable_sha256) or not process.cgroup_identity
            or not process.namespace_identity):
        raise RemoteObservationUnavailable("XRes client process identity is stale or incomplete")
    return {"uid": int(process.kernel_uid), "start": int(process.start_ticks),
            "cgroup_id": str(process.cgroup_identity), "executable_sha256": process.executable_sha256,
            "profile_id": process.profile_id, "generation": process.generation,
            "namespace_identity": process.namespace_identity}


def _process_identity_digest(identity: Any) -> str:
    values = {name: getattr(identity, name, None) for name in (
        "profile_id", "profile_generation", "uid", "gid", "pid", "pid_starttime_ticks",
        "executable_device", "executable_inode", "executable_sha256", "cgroup_id",
        "mount_namespace_inode", "network_namespace_inode", "pidfd_registry_handle")}
    if any(value is None for value in values.values()):
        raise RemoteObservationUnavailable("display server lacks root PIDFD identity")
    return hashlib.sha256(_canonical(values)).hexdigest()


def _read_xauthority(row: SelectedNativeWindow, display_number: str) -> bytearray:
    path = row.xauthority_path
    if not isinstance(path, Path) or not path.is_absolute():
        raise RemoteObservationUnavailable("selected Xauthority file path is invalid")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != row.xauthority_uid
                    or st.st_mode & 0o077 or st.st_dev != row.xauthority_device
                    or st.st_ino != row.xauthority_inode or st.st_size > 64 * 1024):
                raise RemoteObservationUnavailable("selected Xauthority file custody changed")
            raw = bytearray()
            while len(raw) <= 64 * 1024:
                block = os.read(fd, min(4096, 64 * 1024 + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            if len(raw) > 64 * 1024:
                raise RemoteObservationUnavailable("selected Xauthority file exceeds its bound")
        finally:
            os.close(fd)
    except RemoteObservationUnavailable:
        raise
    except OSError:
        raise RemoteObservationUnavailable("selected Xauthority file is unavailable") from None
    return _select_xauthority_cookie(raw, display_number)


def _select_xauthority_cookie(raw: bytearray, display_number: str) -> bytearray:
    hostname = socket.gethostname().encode("ascii", "ignore")
    found: list[bytearray] = []
    index = 0
    try:
        while index < len(raw):
            family = struct.unpack_from(">H", raw, index)[0]; index += 2
            fields_raw: list[bytes] = []
            for _ in range(4):
                size = struct.unpack_from(">H", raw, index)[0]; index += 2
                if size > 4096 or index + size > len(raw):
                    raise ValueError
                fields_raw.append(bytes(raw[index:index + size])); index += size
            address, number, name, data = fields_raw
            if (family in {256, 65535} and number == display_number.encode("ascii")
                    and name == b"MIT-MAGIC-COOKIE-1"
                    and (family == 65535 or address in {hostname, b""}) and 16 <= len(data) <= 256):
                found.append(bytearray(data))
        if len(found) != 1:
            raise ValueError
        cookie = found[0]
        for other in found[1:]:
            for n in range(len(other)): other[n] = 0
        for n in range(len(raw)): raw[n] = 0
        return cookie
    except (ValueError, IndexError, struct.error):
        for n in range(len(raw)): raw[n] = 0
        for candidate in found:
            for n in range(len(candidate)): candidate[n] = 0
        raise RemoteObservationUnavailable("selected local Xauthority record is malformed or ambiguous") from None


def _xopen_authorized_display(x11: Any, display_name: str, cookie: bytearray) -> int:
    # XSetAuthorization is process-global in Xlib. Serialize the only root
    # observer call and clear it immediately after XOpenDisplay has copied it.
    # The authority daemon does not use Xlib elsewhere; if that changes, replace
    # this adapter with the equivalent xcb_connect_to_display_with_auth_info.
    x11.XSetAuthorization.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    x11.XSetAuthorization.restype = None
    x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
    x11.XOpenDisplay.restype = ctypes.c_void_p
    authorization_name = b"MIT-MAGIC-COOKIE-1"
    x11.XSetAuthorization(authorization_name, len(authorization_name), bytes(cookie), len(cookie))
    display = x11.XOpenDisplay(display_name.encode("ascii"))
    x11.XSetAuthorization(b"", 0, b"", 0)
    if not display:
        raise RemoteObservationUnavailable("root could not authenticate to the selected X server")
    return int(display)


def _check_xserver_peer(x11: Any, display: int, expected: Any) -> None:
    x11.XConnectionNumber.argtypes = [ctypes.c_void_p]
    x11.XConnectionNumber.restype = ctypes.c_int
    fd = x11.XConnectionNumber(display)
    try:
        peer = socket.socket(fileno=os.dup(fd))
        try:
            if peer.family != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED"):
                raise RemoteObservationUnavailable("selected X11 display is not a local Unix-socket server")
            actual_pid, actual_uid, actual_gid = struct.unpack("3i", peer.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            expected_identity = expected
            if (actual_pid != expected_identity.pid or actual_uid != expected_identity.uid
                    or actual_gid != expected_identity.gid
                    or _proc_starttime(actual_pid) != expected_identity.pid_starttime_ticks):
                raise RemoteObservationUnavailable("X11 socket peer is not the selected native session server")
        finally:
            peer.close()
    except RemoteObservationUnavailable:
        raise
    except OSError:
        raise RemoteObservationUnavailable("selected X11 server peer credentials are unavailable") from None


class _XResClient(ctypes.Structure):
    _fields_ = [("resource_base", ctypes.c_ulong), ("resource_mask", ctypes.c_ulong)]


class _XResClientIdSpec(ctypes.Structure):
    _fields_ = [("client", ctypes.c_ulong), ("mask", ctypes.c_uint)]


class _XResClientIdValue(ctypes.Structure):
    _fields_ = [("spec", _XResClientIdSpec), ("length", ctypes.c_long),
                ("value", ctypes.c_void_p)]


class _XWindowAttributes(ctypes.Structure):
    _fields_ = [
        ("x", ctypes.c_int), ("y", ctypes.c_int), ("width", ctypes.c_int),
        ("height", ctypes.c_int), ("border_width", ctypes.c_int),
        ("depth", ctypes.c_int), ("visual", ctypes.c_void_p),
        ("root", ctypes.c_ulong), ("window_class", ctypes.c_int),
        ("bit_gravity", ctypes.c_int), ("win_gravity", ctypes.c_int),
        ("backing_store", ctypes.c_int), ("backing_planes", ctypes.c_ulong),
        ("backing_pixel", ctypes.c_ulong), ("save_under", ctypes.c_int),
        ("colormap", ctypes.c_ulong), ("map_installed", ctypes.c_int),
        ("map_state", ctypes.c_int),
        ("all_event_masks", ctypes.c_long), ("your_event_mask", ctypes.c_long),
        ("do_not_propagate_mask", ctypes.c_long), ("override_redirect", ctypes.c_int),
        ("screen", ctypes.c_void_p),
    ]


def _xroot_window(x11: Any, display: int) -> int:
    x11.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
    x11.XDefaultRootWindow.restype = ctypes.c_ulong
    return int(x11.XDefaultRootWindow(display))


def _xroot_children(x11: Any, display: int, root: int) -> tuple[int, ...]:
    x11.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ulong)), ctypes.POINTER(ctypes.c_uint)]
    x11.XQueryTree.restype = ctypes.c_int
    x11.XFree.argtypes = [ctypes.c_void_p]; x11.XFree.restype = ctypes.c_int
    root_return, parent_return = ctypes.c_ulong(), ctypes.c_ulong()
    children = ctypes.POINTER(ctypes.c_ulong)()
    count = ctypes.c_uint()
    if not x11.XQueryTree(display, root, ctypes.byref(root_return), ctypes.byref(parent_return),
                          ctypes.byref(children), ctypes.byref(count)) or count.value > 8192:
        raise RemoteObservationUnavailable("selected X server window tree is unavailable or oversized")
    try:
        return tuple(int(children[index]) for index in range(count.value))
    finally:
        if children:
            x11.XFree(children)


def _x_descendants(x11: Any, display: int, root: int) -> tuple[int, ...]:
    pending = list(_xroot_children(x11, display, root))
    seen: set[int] = set()
    while pending:
        xid = pending.pop()
        if xid in seen:
            continue
        seen.add(xid)
        if len(seen) > 8192:
            raise RemoteObservationUnavailable("selected X server window tree exceeds its node bound")
        pending.extend(_xroot_children(x11, display, xid))
    return tuple(sorted(seen))


def _xwindow_viewable(x11: Any, display: int, xid: int) -> bool:
    x11.XGetWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                         ctypes.POINTER(_XWindowAttributes)]
    x11.XGetWindowAttributes.restype = ctypes.c_int
    attrs = _XWindowAttributes()
    if not x11.XGetWindowAttributes(display, xid, ctypes.byref(attrs)):
        return False
    return attrs.map_state == 2 and 0 < attrs.width <= 16384 and 0 < attrs.height <= 16384


def _xres_client_pids(x11: Any, xres: Any, display: int) -> tuple[tuple[int, int, int], ...]:
    xres.XResQueryExtension.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                        ctypes.POINTER(ctypes.c_int)]
    xres.XResQueryExtension.restype = ctypes.c_int
    xres.XResQueryVersion.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                      ctypes.POINTER(ctypes.c_int)]
    xres.XResQueryVersion.restype = ctypes.c_int
    event_base, error_base = ctypes.c_int(), ctypes.c_int()
    major, minor = ctypes.c_int(), ctypes.c_int()
    if (not xres.XResQueryExtension(display, ctypes.byref(event_base), ctypes.byref(error_base))
            or not xres.XResQueryVersion(display, ctypes.byref(major), ctypes.byref(minor))
            or (major.value, minor.value) < (1, 2)):
        raise RemoteObservationUnavailable("XRes 1.2 client-ID support is required")
    xres.XResQueryClients.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
                                      ctypes.POINTER(ctypes.POINTER(_XResClient))]
    xres.XResQueryClients.restype = ctypes.c_int
    xres.XResQueryClientIds.argtypes = [ctypes.c_void_p, ctypes.c_long,
        ctypes.POINTER(_XResClientIdSpec), ctypes.POINTER(ctypes.c_long),
        ctypes.POINTER(ctypes.POINTER(_XResClientIdValue))]
    xres.XResQueryClientIds.restype = ctypes.c_int
    x11.XFree.argtypes = [ctypes.c_void_p]; x11.XFree.restype = ctypes.c_int
    count = ctypes.c_int()
    clients = ctypes.POINTER(_XResClient)()
    if not xres.XResQueryClients(display, ctypes.byref(count), ctypes.byref(clients)) or not 0 < count.value <= 8192:
        raise RemoteObservationUnavailable("XRes client inventory is unavailable")
    result: list[tuple[int, int, int]] = []
    try:
        resource_ranges = {int(clients[index].resource_base):
                          (int(clients[index].resource_base), int(clients[index].resource_mask))
                          for index in range(count.value)}
        # XRes 1.2 defines client=None as selecting all connected clients. The
        # server expands that wildcard to one concrete resource_base per reply;
        # querying its special server-owned base individually can raise BadValue.
        spec = _XResClientIdSpec(0, 1 << 1)  # None, LocalClientPid
        value_count = ctypes.c_long()
        values = ctypes.POINTER(_XResClientIdValue)()
        # Unlike the older Bool-returning XResQueryClients, the 1.2 API is a
        # Status function: Xlib Success is 0, and the implementation returns
        # !Success on failure. Treating this as a boolean rejects every valid
        # reply (and accepts a failed reply).
        if xres.XResQueryClientIds(display, 1, ctypes.byref(spec),
                                   ctypes.byref(value_count), ctypes.byref(values)) != 0:
            raise RemoteObservationUnavailable("XRes local-client PID query failed")
        try:
            rejected_mask = rejected_length = rejected_value = rejected_client = 0
            for value_index in range(value_count.value):
                value = values[value_index]
                if value.spec.mask != (1 << 1):
                    rejected_mask += 1
                    continue
                # XResClientIdValue.length is a byte count in libXRes 1.2.1;
                # LocalClientPid is one CARD32 (four bytes). The protocol
                # prose calls it a CARD32 count, but the library's public
                # accessor accepts length >= 4 and the reader allocates/reads
                # exactly `length` bytes.
                if value.length != ctypes.sizeof(ctypes.c_uint32):
                    rejected_length += 1
                    continue
                if not value.value:
                    rejected_value += 1
                    continue
                client_range = resource_ranges.get(int(value.spec.client))
                if client_range is not None:
                    pid_values = ctypes.cast(value.value, ctypes.POINTER(ctypes.c_uint32))
                    result.append((*client_range, int(pid_values[0])))
                else:
                    rejected_client += 1
        finally:
            if values:
                x11.XFree(values)
    finally:
        if clients:
            x11.XFree(clients)
    if not result:
        raise RemoteObservationUnavailable(
            "XRes returned no joinable server-derived local client PIDs "
            f"(ids={value_count.value}, mask={rejected_mask}, length={rejected_length}, "
            f"value={rejected_value}, client={rejected_client})")
    return tuple(result)


def _owner_pid(xid: int, clients: tuple[tuple[int, int, int], ...]) -> int | None:
    matches = [pid for base, mask, pid in clients if (xid & ~mask) == base]
    if len(matches) > 1:
        raise RemoteObservationUnavailable("XRes resource ownership is ambiguous")
    return matches[0] if matches else None


def _hash_bounded_window_sample(x11: Any, display: int, xid: int) -> str:
    x11.XGetWindowAttributes.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                         ctypes.POINTER(_XWindowAttributes)]
    x11.XGetWindowAttributes.restype = ctypes.c_int
    attrs = _XWindowAttributes()
    if not x11.XGetWindowAttributes(display, xid, ctypes.byref(attrs)):
        raise RemoteObservationUnavailable("selected app window disappeared before surface observation")
    width, height = int(attrs.width), int(attrs.height)
    if not (0 < width <= 16384 and 0 < height <= 16384):
        raise RemoteObservationUnavailable("selected app window dimensions exceed the surface bound")
    x11.XGetImage.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_int,
        ctypes.c_uint, ctypes.c_uint, ctypes.c_ulong, ctypes.c_int]
    x11.XGetImage.restype = ctypes.c_void_p
    x11.XGetPixel.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
    x11.XGetPixel.restype = ctypes.c_ulong
    x11.XDestroyImage.argtypes = [ctypes.c_void_p]; x11.XDestroyImage.restype = ctypes.c_int
    # Ask the server for at most 64x64 pixels. XGetPixel then reads only this
    # bounded tile; never allocate a full-resolution screenshot in the root
    # authority, even for an oversized client window.
    sample_width, sample_height = min(width, 64), min(height, 64)
    image = x11.XGetImage(display, xid, 0, 0, sample_width, sample_height,
                          ctypes.c_ulong(-1).value, 2)
    if not image:
        raise RemoteObservationUnavailable("X server could not read the selected app surface")
    sample = hashlib.sha256()
    try:
        sample.update(struct.pack("!II", width, height))
        for y in range(sample_height):
            for x in range(sample_width):
                sample.update(struct.pack("!Q", int(x11.XGetPixel(image, x, y))))
        return sample.hexdigest()
    finally:
        x11.XDestroyImage(image)
