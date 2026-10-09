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
import sys
import time
import uuid
from urllib.parse import urlsplit
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
    gateway_profile_id: str = ""
    gateway_enrollment_id: str = ""
    gateway_role_sha256: str = ""
    native_profile_id: str = ""
    native_enrollment_id: str = ""


class RemoteOriginCatalog(Protocol):
    """Resolver backed by the current root-owned active generation catalog."""
    def selected_tunnel(self, enrollment_id: str) -> SelectedTunnel: ...
    def selected_origin(self, enrollment_id: str) -> SelectedRemoteOrigin: ...


class TunnelTokenWriter(Protocol):
    def write_provisioned_tunnel_token(self, enrollment_id: str, token: bytes, *,
            account_id: str, tunnel_id: str, generation: str) -> "ProtectedTunnelTokenReceipt": ...


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
    expires_monotonic: float = float("inf")


class RemoteOriginProcessManager(Protocol):
    def inspect_selected_origin(self, enrollment: SelectedRemoteOrigin) -> KernelOriginEvidence: ...


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
            True, True, True, True, True, True, True, True, True, True,
            ("custody:gateway-pidfd", "custody:gateway-cgroup", "custody:gateway-namespaces",
             "custody:native-pidfd", "custody:native-cgroup", "custody:native-namespaces",
             "catalog:remote-policy", "catalog:fixed-routes"), expires)


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
    tunnel_enrollment_id: str, token: bytes, *, account_id: str, tunnel_id: str,
    generation: str, catalog: RemoteOriginCatalog, token_root: Path,
    journal: TokenJournal, signer: ReceiptSigner,
    now: Callable[[], float] = time.monotonic,
) -> ProtectedTunnelTokenReceipt:
    """Accept one API response in root memory, after exact active selection joins."""
    selected = catalog.selected_tunnel(tunnel_enrollment_id)
    if (not isinstance(selected, SelectedTunnel) or not selected.owned
            or selected.enrollment_id != tunnel_enrollment_id
            or selected.account_id != account_id or selected.tunnel_id != tunnel_id
            or selected.generation != generation):
        raise RemoteOriginDenied("provisioned tunnel token does not match active root selection")
    if (not isinstance(token, bytes) or not token or len(token) > 16 * 1024
            or b"\x00" in token or b"\n" in token or b"\r" in token):
        raise RemoteOriginDenied("provisioned tunnel token is malformed")
    _validate_tunnel_credential(token, selected)
    return write_selected_tunnel_token(tunnel_enrollment_id, catalog=catalog,
        vault=_OneShotSecretResolver(token), token_root=token_root, journal=journal,
        signer=signer, now=now)


class TunnelTokenWriterClient:
    """Typed caller for the authority's authenticated private Unix RPC."""
    def __init__(self, rpc: Callable[[str, Mapping[str, Any]], Mapping[str, Any]],
                 verifier: ReceiptSigner, *, now: Callable[[], float] = time.monotonic):
        if not callable(rpc):
            raise ValueError("authenticated authority RPC callable is required")
        self._rpc, self._verifier, self._now = rpc, verifier, now

    def write_provisioned_tunnel_token(self, tunnel_enrollment_id: str, token: bytes, *,
            account_id: str, tunnel_id: str, generation: str) -> ProtectedTunnelTokenReceipt:
        for value, label in ((tunnel_enrollment_id, "enrollment"), (account_id, "account"),
                             (tunnel_id, "tunnel"), (generation, "generation")):
            _validate_id(value, label)
        if not isinstance(token, bytes) or not 1 <= len(token) <= 16 * 1024:
            raise RemoteOriginDenied("provisioned tunnel token is outside the transport bound")
        payload = {"schema": 1, "tunnel_enrollment_id": tunnel_enrollment_id,
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
    process_manager: RemoteOriginProcessManager, gateway_probe: RemoteGatewayProbe,
    signer: ReceiptSigner, now: Callable[[], float] = time.monotonic,
) -> RootOriginReadinessReceipt:
    """Issue a short-lived receipt only after live kernel and app-route evidence."""
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
    if evidence.expires_monotonic <= float(now()):
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
                        expires_monotonic=math.nextafter(issued + 30.0, -math.inf))
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
