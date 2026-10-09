"""Root-owned Cloudflare tunnel token placement and native-origin readiness.

Only the active root catalog selects resources. Callers provide enrollment IDs;
paths, credentials, routes and process identities are resolved by injected
root-owned adapters. Receipts contain no credential, URL or filesystem path.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field, fields
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


class RemoteOriginCatalog(Protocol):
    """Resolver backed by the current root-owned active generation catalog."""
    def selected_tunnel(self, enrollment_id: str) -> SelectedTunnel: ...
    def selected_origin(self, enrollment_id: str) -> SelectedRemoteOrigin: ...


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
    configuration_pinned: bool
    route_pinned: bool
    app_only_policy_pinned: bool
    observed_assertion_ids: tuple[str, ...]


class RemoteOriginProcessManager(Protocol):
    def inspect_selected_origin(self, enrollment: SelectedRemoteOrigin) -> KernelOriginEvidence: ...


class RemoteGatewayProbe(Protocol):
    """Performs bounded live loopback HTTP and WS checks against selected origin."""
    def probe_selected_app(self, enrollment: SelectedRemoteOrigin) -> Mapping[str, Any]: ...


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _validate_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-" for c in value):
        raise RemoteOriginDenied(f"selected {label} is invalid")
    return value


def _secure_parent(path: Path) -> None:
    """Require an existing non-symlink root-owned directory with no group/world access."""
    if not path.is_absolute():
        raise RemoteOriginDenied("selected token sink must be absolute")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            st = current.lstat()
        except FileNotFoundError:
            raise RemoteOriginDenied("selected token sink directory is not provisioned") from None
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            raise RemoteOriginDenied("selected token sink has an unsafe directory component")
    st = path.stat(follow_symlinks=False)
    if os.name == "posix" and (st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077):
        raise RemoteOriginDenied("selected token sink directory is not root-private")


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
    if token_root != token_root.absolute() or token_root.is_symlink():
        raise RemoteOriginDenied("token root must be an absolute trusted directory")
    sink = token_root / selected.tunnel_id / "tunnel.token"
    _secure_parent(token_root)
    _secure_parent(sink.parent)
    token = vault.resolve_tunnel_token(selected.secret_reference_id, selected.tunnel_id)
    if not isinstance(token, bytes) or not token or len(token) > 64 * 1024 or b"\x00" in token or b"\n" in token or b"\r" in token:
        raise RemoteOriginDenied("selected dedicated runtime token is invalid")
    digest = hashlib.sha256(token).hexdigest()
    prior = journal.lookup(tunnel_enrollment_id)
    try:
        preexisting_sink = sink.lstat()
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
        existing = sink.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        if (stat.S_ISLNK(existing.st_mode) or not stat.S_ISREG(existing.st_mode)
                or stat.S_IMODE(existing.st_mode) != 0o400 or existing.st_uid != selected.runtime_uid
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
        fd = os.open(sink, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            content = os.read(fd, 64 * 1024 + 1)
        finally:
            os.close(fd)
        if not hmac.compare_digest(hashlib.sha256(content).hexdigest(), digest):
            raise RemoteOriginDenied("existing tunnel token sink contents changed")
        st = existing
    else:
        temp = sink.parent / (".token-" + secrets.token_hex(16))
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchown(fd, selected.runtime_uid, -1)
            os.fchmod(fd, 0o400)
            view = memoryview(token)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fsync(fd)
            st = os.fstat(fd)
        except Exception:
            os.close(fd)
            temp.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)
        try:
            # Hard-link publication is atomic and refuses to replace a foreign path.
            os.link(temp, sink, follow_symlinks=False)
            dirfd = os.open(sink.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        except FileExistsError:
            temp.unlink(missing_ok=True)
            raise RemoteOriginDenied("token sink appeared during protected write") from None
        finally:
            temp.unlink(missing_ok=True)
        st = sink.stat(follow_symlinks=False)
        if (st.st_uid != selected.runtime_uid or stat.S_IMODE(st.st_mode) != 0o400
                or not stat.S_ISREG(st.st_mode)):
            raise RemoteOriginDenied("published tunnel token file failed protection checks")
    journal.record(tunnel_enrollment_id, {"state": "committed", "digest": digest,
        "device": st.st_dev, "inode": st.st_ino, "sink_id": selected.sink_id,
        "tunnel_id": selected.tunnel_id, "generation": selected.generation,
        "runtime_uid": selected.runtime_uid})
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
                    expires_monotonic=issued + 30.0)
    provisional = ProtectedTunnelTokenReceipt(**unsigned, signature=b"")
    return ProtectedTunnelTokenReceipt(**unsigned, signature=signer.sign(provisional.payload()))


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
    process_manager: RemoteOriginProcessManager, gateway_probe: RemoteGatewayProbe,
    signer: ReceiptSigner, now: Callable[[], float] = time.monotonic,
) -> RootOriginReadinessReceipt:
    """Issue a short-lived receipt only after live kernel and app-route evidence."""
    _validate_id(remote_enrollment_id, "remote enrollment ID")
    selected = catalog.selected_origin(remote_enrollment_id)
    if (not isinstance(selected, SelectedRemoteOrigin) or selected.enrollment_id != remote_enrollment_id
            or not selected.owned):
        raise RemoteOriginDenied("selected remote origin is absent or not installer-owned")
    evidence = process_manager.inspect_selected_origin(selected)
    if not isinstance(evidence, KernelOriginEvidence):
        raise RemoteOriginDenied("root process manager returned no typed kernel evidence")
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
              evidence.mount_pinned, evidence.configuration_pinned, evidence.route_pinned,
              evidence.app_only_policy_pinned)
    if not all(value is True for value in proofs):
        raise RemoteOriginDenied("kernel process or app-only confinement proof is incomplete")
    probe = gateway_probe.probe_selected_app(selected)
    required = {"loopback_only", "unauthenticated_denied", "authorized_asset_served",
                "authorized_websocket_attached", "official_desktop_window_observed",
                "arbitrary_route_denied", "shell_route_denied", "full_host_desktop_denied"}
    if (not isinstance(probe, Mapping) or set(probe) != required
            or any(probe[key] is not True for key in required)):
        raise RemoteOriginDenied("live gateway did not prove the selected official app-only origin")
    assertion_ids = tuple(evidence.observed_assertion_ids)
    if (not assertion_ids or len(assertion_ids) > 64
            or any(not isinstance(v, str) or not v or len(v) > 128 for v in assertion_ids)):
        raise RemoteOriginDenied("root origin evidence assertion set is missing or malformed")
    assertion_ids = tuple(dict.fromkeys(assertion_ids + tuple(
        "gateway:" + name for name in sorted(required))))
    issued = float(now())
    if not (issued >= 0 and issued < float("inf")):
        raise RemoteOriginDenied("root monotonic clock is invalid")
    unsigned = dict(schema=1, receipt_id=secrets.token_urlsafe(24),
                    remote_enrollment_id=selected.enrollment_id,
                    gateway_identity_digest=evidence.gateway_identity_digest,
                    desktop_generation=selected.desktop_generation,
                    connector_target_id=selected.connector_target_id,
                    policy_config_digest=selected.policy_config_digest,
                    policy_revision=selected.policy_revision,
                    service_generation_digest=selected.service_generation_digest,
                    observed_assertion_ids=assertion_ids, issued_monotonic=issued,
                    expires_monotonic=issued + 30.0)
    provisional = RootOriginReadinessReceipt(**unsigned, signature=b"")
    return RootOriginReadinessReceipt(**unsigned, signature=signer.sign(provisional.payload()))


def verify_origin_receipt(receipt: RootOriginReadinessReceipt, signer: ReceiptSigner, *,
                          now: Callable[[], float] = time.monotonic,
                          selected_enrollment_id: str | None = None) -> bool:
    if not isinstance(receipt, RootOriginReadinessReceipt):
        return False
    t = float(now())
    return (receipt.schema == 1
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.gateway_identity_digest))
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.policy_config_digest))
            and bool(re.fullmatch(r"[0-9a-f]{64}", receipt.service_generation_digest))
            and bool(receipt.observed_assertion_ids)
            and receipt.issued_monotonic <= t < receipt.expires_monotonic
            and receipt.expires_monotonic - receipt.issued_monotonic <= 30.0
            and (selected_enrollment_id is None or receipt.remote_enrollment_id == selected_enrollment_id)
            and signer.verify(receipt.payload(), receipt.signature))
