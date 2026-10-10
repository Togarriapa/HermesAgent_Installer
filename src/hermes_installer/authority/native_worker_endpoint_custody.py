"""Prepared-no-effects ownership of the selected service AF_UNIX listener.

This listener is root setup infrastructure.  It answers one bounded custody
challenge and exposes no AuthorityService operations.  Active transfer is a
separate phase and is deliberately unavailable until its publisher/daemon
handoff has a reviewed implementation.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .bootstrap_enrollment import BootstrapEnrollmentPending

_SOCKET_DIR = Path("/run/hermes-installer/authority")
_ENDPOINT_ID = "hermes-agent-authority-endpoint-v1"
_PROFILE_ID = "hermes-agent-native-v1"
_MAX_LEASE = 300.0
_CHALLENGE_MAX = 4096
_CHALLENGE_TIMEOUT = 2.0


class PreparedAuthorityEndpointUnavailable(BootstrapEnrollmentPending):
    """The current setup cannot prove exclusive preactive listener custody."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _recv_bounded(connection: socket.socket) -> bytes:
    """Read one half-closed bounded JSON frame without assuming one recv()."""
    chunks: list[bytes] = []
    size = 0
    deadline = time.monotonic() + _CHALLENGE_TIMEOUT
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PreparedAuthorityEndpointUnavailable("listener challenge exceeded its fixed timeout")
        connection.settimeout(remaining)
        chunk = connection.recv(min(1024, _CHALLENGE_MAX + 1 - size))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        size += len(chunk)
        if size > _CHALLENGE_MAX:
            raise PreparedAuthorityEndpointUnavailable("listener challenge exceeds its fixed bound")


def _bind_owned_listener(directory_fd: int, leaf: str, service_gid: int) -> tuple[socket.socket, os.stat_result]:
    """Exclusively bind and hold a fixed AF_UNIX stream listener under a held dir FD."""
    if (not isinstance(leaf, str) or not leaf.endswith(".sock") or "/" in leaf
            or type(service_gid) is not int or service_gid < 1):
        raise PreparedAuthorityEndpointUnavailable("selected endpoint leaf or group is invalid")
    try:
        os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise PreparedAuthorityEndpointUnavailable("selected endpoint leaf already exists")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.set_inheritable(False)
    created_identity: tuple[int, int] | None = None
    try:
        listener.bind(f"/proc/self/fd/{directory_fd}/{leaf}")
        bound = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISSOCK(bound.st_mode) or bound.st_uid != 0:
            raise PreparedAuthorityEndpointUnavailable("new listener leaf is not the root-owned bound socket")
        created_identity = (bound.st_dev, bound.st_ino)
        os.chown(leaf, 0, service_gid, dir_fd=directory_fd, follow_symlinks=False)
        os.chmod(leaf, 0o660, dir_fd=directory_fd, follow_symlinks=False)
        listener.listen(8)
        listener.settimeout(0.2)
        observed = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISSOCK(observed.st_mode) or observed.st_uid != 0
                or observed.st_gid != service_gid or stat.S_IMODE(observed.st_mode) != 0o660
                or (observed.st_dev, observed.st_ino) != created_identity):
            raise PreparedAuthorityEndpointUnavailable("new listener leaf ownership is invalid")
        return listener, observed
    except BaseException:
        listener.close()
        try:
            current = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            if (created_identity is not None
                    and (current.st_dev, current.st_ino) == created_identity
                    and stat.S_ISSOCK(current.st_mode) and current.st_uid == 0):
                os.unlink(leaf, dir_fd=directory_fd)
        except OSError:
            pass
        raise


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedAuthorityListenerReceipt:
    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    service_identity_receipt_handle: str
    service_user: str
    service_uid: int
    service_gid: int
    profile_id: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    endpoint_id: str
    root_id: str
    relative_socket: str
    socket_device: int
    socket_inode: int
    socket_owner_uid: int
    socket_owner_gid: int
    socket_mode: int
    listener_type: str
    listen_backlog: int
    custodian_actor_receipt_handle: str
    custodian_pid: int
    custodian_start_ticks: int
    custodian_boot_epoch: str
    challenge_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)
    _listener: socket.socket = field(repr=False, compare=False)
    _directory_fd: int = field(repr=False, compare=False)
    _identity: Any = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedAuthorityListenerReceipt(<root-held prepared-no-effects>)"


class RootPreparedAuthorityEndpointCustodian:
    """Bind one current selected UID socket and retain its real listening FD."""

    def __init__(self, binding: Any, prepared_receipt: Any, held_release: Any,
                 current_actor: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or not isinstance(held_release, VerifiedInstallerReleaseReceipt)
                or not isinstance(current_actor, RootActorObservation)):
            raise PreparedAuthorityEndpointUnavailable(
                "prepared endpoint requires the current selected binding, held release, and root actor")
        session = binding._session
        session._check_live()
        current_actor.verify_current(held_release)
        prepared = session._resolve_current_prepared_enrollment()
        if (prepared_receipt is not prepared
                or prepared.state != "prepared"
                or prepared.transaction_handle != session._authorization.transaction_handle
                or not session._handle.session_id
                or not session._authorization.plan_digest):
            raise PreparedAuthorityEndpointUnavailable(
                "prepared endpoint does not join the current empty setup generation")
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED") or os.geteuid() != 0:
            raise PreparedAuthorityEndpointUnavailable("Linux root peer credentials are required")
        self.binding = binding
        self.prepared_receipt = prepared
        self.held_release = held_release
        self.current_actor = current_actor
        self._issuer = object()
        self._identities: dict[str, Any] = {}
        self._receipts: dict[str, RootPreparedAuthorityListenerReceipt] = {}
        self._listeners: dict[str, tuple[socket.socket, int, tuple[int, int], threading.Event, threading.Thread]] = {}
        self._lock = threading.RLock()
        self._nonce_lock = threading.Lock()
        self._closed = False
        self._used_nonces: set[tuple[str, str]] = set()

    @classmethod
    def from_root_setup(cls, current_binding: Any, prepared_receipt: Any,
                        held_release: Any, current_actor: Any) -> "RootPreparedAuthorityEndpointCustodian":
        return cls(current_binding, prepared_receipt, held_release, current_actor)

    def retain_prepared_identity(self, identity_receipt: Any) -> str:
        """Retain the exact fresh NSS/root-marker/root-FD projection for lookup."""
        from .native_worker_recipes import RootPreparedServiceIdentityReceipt
        self._check_live()
        if (type(identity_receipt) is not RootPreparedServiceIdentityReceipt
                or identity_receipt._issuer is not self.binding._session._seal
                or identity_receipt.expires_monotonic <= time.monotonic()):
            raise PreparedAuthorityEndpointUnavailable("service identity receipt is foreign or stale")
        self._identities[identity_receipt.receipt_handle] = identity_receipt
        return identity_receipt.receipt_handle

    def ensure_selected_listener(self, prepared_service_identity_receipt_handle: str,
                                 profile_id: str) -> RootPreparedAuthorityListenerReceipt:
        self._check_live()
        if profile_id != _PROFILE_ID:
            raise PreparedAuthorityEndpointUnavailable("selected endpoint profile is not the fixed native worker")
        identity = self._identities.get(prepared_service_identity_receipt_handle)
        if identity is None:
            raise PreparedAuthorityEndpointUnavailable("prepared service identity handle is not current")
        from .native_worker_recipes import verify_prepared_service_identity
        verify_prepared_service_identity(self.binding, identity)
        if identity.profile_id != profile_id or identity.generation != self.prepared_receipt.generation_id:
            raise PreparedAuthorityEndpointUnavailable("service identity profile/generation does not join setup")
        principal = self.binding.resolve_current_setup_identity().principal
        namespace = self.binding.resolve_current_setup_identity().namespace
        if os.geteuid() != 0:
            raise PreparedAuthorityEndpointUnavailable("listener creation requires the current root actor")
        with self._lock:
            self._check_live()
            existing = self._receipts.get(identity.receipt_handle)
            if existing is not None:
                return self.resolve_current(existing.receipt_handle)
            directory_fd = self._open_directory()
            leaf = f"{identity.service_uid}.sock"
            listener: socket.socket | None = None
            bound_identity: tuple[int, int] | None = None
            receipt_handle: str | None = None
            stop: threading.Event | None = None
            try:
                listener, entry = _bind_owned_listener(directory_fd, leaf, identity.service_gid)
                bound_identity = (entry.st_dev, entry.st_ino)
                check = self._open_directory()
                try:
                    info = os.fstat(check)
                    if (info.st_dev, info.st_ino) != (os.fstat(directory_fd).st_dev,
                                                      os.fstat(directory_fd).st_ino):
                        raise PreparedAuthorityEndpointUnavailable("authority root directory changed during bind")
                finally:
                    os.close(check)
                now = time.monotonic()
                expires = min(now + _MAX_LEASE, identity.expires_monotonic,
                              self.prepared_receipt.expires_monotonic)
                if expires <= now:
                    raise PreparedAuthorityEndpointUnavailable("prepared listener lease is already expired")
                live = self.binding._session._factory.session_store._live(
                    self.binding._session._handle)
                actor_handle = live.record.get("actor_observation_receipt_handle")
                if not isinstance(actor_handle, str) or not actor_handle:
                    raise PreparedAuthorityEndpointUnavailable("current actor receipt has no opaque handle")
                receipt_handle = secrets.token_urlsafe(36)
                challenge_sha = hashlib.sha256(_canonical({
                    "schema": 1, "state": "prepared-no-effects", "receipt": receipt_handle,
                    "device": entry.st_dev, "inode": entry.st_ino,
                })).hexdigest()
                receipt = RootPreparedAuthorityListenerReceipt(
                    schema=1, receipt_handle=receipt_handle,
                    setup_session_id=self.binding._session._handle.session_id,
                    transaction_handle=self.prepared_receipt.transaction_handle,
                    plan_sha256=self.binding._session._authorization.plan_digest,
                    prepared_generation_id=self.prepared_receipt.generation_id,
                    prepared_generation_digest=self.prepared_receipt.generation_digest,
                    service_identity_receipt_handle=identity.receipt_handle,
                    service_user=identity.service_user, service_uid=identity.service_uid,
                    service_gid=identity.service_gid, profile_id=profile_id,
                    principal_binding_sha256=principal.principal_binding_sha256,
                    namespace_binding_sha256=namespace.namespace_binding_sha256,
                    endpoint_id=_ENDPOINT_ID, root_id=_ENDPOINT_ID,
                    relative_socket=leaf, socket_device=entry.st_dev,
                    socket_inode=entry.st_ino, socket_owner_uid=0,
                    socket_owner_gid=identity.service_gid, socket_mode=0o660,
                    listener_type="AF_UNIX/SOCK_STREAM", listen_backlog=8,
                    custodian_actor_receipt_handle=actor_handle,
                    custodian_pid=self.current_actor.pid,
                    custodian_start_ticks=self.current_actor.start_time,
                    custodian_boot_epoch=self._boot_epoch(),
                    challenge_sha256=challenge_sha, issued_monotonic=now,
                    expires_monotonic=expires, _issuer=self._issuer,
                    _listener=listener, _directory_fd=directory_fd, _identity=identity,
                )
                stop = threading.Event()
                thread = threading.Thread(target=self._challenge_loop,
                                          args=(receipt, stop), name="prepared-authority-custodian",
                                          daemon=True)
                self._listeners[identity.receipt_handle] = (
                    listener, directory_fd, (entry.st_dev, entry.st_ino), stop, thread)
                self._receipts[receipt_handle] = receipt
                thread.start()
                challenge_sha = self._challenge_self(receipt)
                receipt = replace(receipt, challenge_sha256=challenge_sha)
                self._receipts[receipt_handle] = receipt
                return receipt
            except BaseException:
                if receipt_handle is not None:
                    self._receipts.pop(receipt_handle, None)
                retained = self._listeners.pop(identity.receipt_handle, None)
                if retained is not None:
                    retained[3].set()
                    try:
                        retained[0].close()
                    except OSError:
                        pass
                if listener is not None:
                    try:
                        listener.close()
                    except OSError:
                        pass
                # Cleanup only a leaf created by this exact bind attempt.
                if bound_identity is not None:
                    try:
                        leaf_info = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
                        if ((leaf_info.st_dev, leaf_info.st_ino) == bound_identity
                                and stat.S_ISSOCK(leaf_info.st_mode) and leaf_info.st_uid == 0):
                            os.unlink(leaf, dir_fd=directory_fd)
                    except OSError:
                        pass
                os.close(directory_fd)
                if retained is not None:
                    retained[4].join(timeout=1.0)
                raise

    def resolve_current(self, receipt_handle: str, *, _skip_challenge: bool = False) -> RootPreparedAuthorityListenerReceipt:
        receipt = self._receipts.get(receipt_handle)
        if (type(receipt) is not RootPreparedAuthorityListenerReceipt
                or receipt._issuer is not self._issuer
                or receipt.expires_monotonic <= time.monotonic()):
            raise PreparedAuthorityEndpointUnavailable("prepared listener receipt is foreign or expired")
        self._check_live()
        from .native_worker_recipes import verify_prepared_service_identity
        verify_prepared_service_identity(self.binding, receipt._identity)
        try:
            listener, directory_fd, leaf_identity, _, _ = self._listeners[receipt.service_identity_receipt_handle]
        except KeyError:
            raise PreparedAuthorityEndpointUnavailable("prepared listener custody has been released") from None
        try:
            directory = os.fstat(directory_fd)
            path_directory = _SOCKET_DIR.lstat()
            leaf = os.stat(receipt.relative_socket, dir_fd=directory_fd, follow_symlinks=False)
            accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        except OSError:
            raise PreparedAuthorityEndpointUnavailable("prepared listener custody changed") from None
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or directory.st_gid != 0 or stat.S_IMODE(directory.st_mode) != 0o711
                or (directory.st_dev, directory.st_ino) != (path_directory.st_dev, path_directory.st_ino)
                or (leaf.st_dev, leaf.st_ino) != leaf_identity
                or (leaf.st_dev, leaf.st_ino) != (receipt.socket_device, receipt.socket_inode)
                or not stat.S_ISSOCK(leaf.st_mode) or leaf.st_uid != 0
                or leaf.st_gid != receipt.service_gid or stat.S_IMODE(leaf.st_mode) != 0o660
                or accepting != 1 or listener.family != socket.AF_UNIX
                or listener.type & socket.SOCK_STREAM != socket.SOCK_STREAM):
            raise PreparedAuthorityEndpointUnavailable("prepared listener leaf or live socket no longer matches")
        if not _skip_challenge:
            self._challenge_self(receipt)
        return receipt

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for handle, (listener, directory_fd, leaf_identity, stop, thread) in tuple(self._listeners.items()):
                stop.set()
                try:
                    listener.close()
                except OSError:
                    pass
                try:
                    info = os.stat(f"{self._identity_uid(handle)}.sock", dir_fd=directory_fd,
                                   follow_symlinks=False)
                    if (info.st_dev, info.st_ino) == leaf_identity and stat.S_ISSOCK(info.st_mode):
                        os.unlink(f"{self._identity_uid(handle)}.sock", dir_fd=directory_fd)
                except OSError:
                    pass
                try:
                    os.close(directory_fd)
                except OSError:
                    pass
                thread.join(timeout=1.0)
            self._listeners.clear()
            self._receipts.clear()
            self._identities.clear()
            self._used_nonces.clear()

    def _challenge_loop(self, receipt: RootPreparedAuthorityListenerReceipt,
                        stop: threading.Event) -> None:
        listener = receipt._listener
        while not stop.is_set() and time.monotonic() < receipt.expires_monotonic:
            try:
                connection, _ = listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            try:
                connection.settimeout(_CHALLENGE_TIMEOUT)
                if not hasattr(socket, "SO_PEERCRED"):
                    continue
                credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                pid, uid, gid = struct.unpack("3i", credentials)
                self.current_actor.verify_current(self.held_release)
                if pid != self.current_actor.pid or uid != 0 or gid != 0:
                    continue
                request = _recv_bounded(connection)
                if len(request) > _CHALLENGE_MAX:
                    continue
                parsed = json.loads(request.decode("utf-8"))
                if (not isinstance(parsed, dict) or set(parsed) != {"schema", "operation", "nonce"}
                        or type(parsed["schema"]) is not int or parsed["schema"] != 1
                        or parsed["operation"] != "listener-custody-challenge"
                        or not isinstance(parsed["nonce"], str) or not 16 <= len(parsed["nonce"]) <= 128):
                    continue
                nonce_key = (receipt.receipt_handle, parsed["nonce"])
                with self._nonce_lock:
                    if nonce_key in self._used_nonces:
                        continue
                    self._used_nonces.add(nonce_key)
                self.resolve_current(receipt.receipt_handle, _skip_challenge=True)
                response = _canonical({
                    "schema": 1, "state": "prepared-no-effects", "nonce": parsed["nonce"],
                    "endpoint_receipt_handle": receipt.receipt_handle,
                    "socket_device": receipt.socket_device, "socket_inode": receipt.socket_inode,
                })
                if len(response) <= _CHALLENGE_MAX:
                    connection.sendall(response)
            except Exception:
                # The challenge lane returns no diagnostic or authority data.
                pass
            finally:
                connection.close()

    def _open_directory(self) -> int:
        flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            fd = os.open(_SOCKET_DIR, flags)
            info = os.fstat(fd)
            path_info = _SOCKET_DIR.lstat()
        except OSError:
            raise PreparedAuthorityEndpointUnavailable("fixed authority socket directory is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o711
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            os.close(fd)
            raise PreparedAuthorityEndpointUnavailable("fixed authority socket directory custody is invalid")
        return fd

    def _challenge_self(self, receipt: RootPreparedAuthorityListenerReceipt) -> str:
        nonce = secrets.token_urlsafe(32)
        request = _canonical({"schema": 1, "operation": "listener-custody-challenge",
                              "nonce": nonce})
        if len(request) > _CHALLENGE_MAX:
            raise PreparedAuthorityEndpointUnavailable("listener challenge request exceeds its fixed bound")
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(_CHALLENGE_TIMEOUT)
        try:
            client.connect(str(_SOCKET_DIR / receipt.relative_socket))
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
            response_bytes = _recv_bounded(client)
            if len(response_bytes) > _CHALLENGE_MAX:
                raise PreparedAuthorityEndpointUnavailable("listener challenge response exceeds its fixed bound")
            response = json.loads(response_bytes.decode("utf-8"))
            expected = {"schema": 1, "state": "prepared-no-effects", "nonce": nonce,
                        "endpoint_receipt_handle": receipt.receipt_handle,
                        "socket_device": receipt.socket_device,
                        "socket_inode": receipt.socket_inode}
            if response != expected:
                raise PreparedAuthorityEndpointUnavailable("live endpoint failed its bounded root challenge")
            return hashlib.sha256(_canonical({"request": request.decode("utf-8"),
                                              "response": response})).hexdigest()
        except (OSError, ValueError, UnicodeError):
            raise PreparedAuthorityEndpointUnavailable("live endpoint challenge was unavailable") from None
        finally:
            client.close()

    def _identity_uid(self, identity_handle: str) -> int:
        identity = self._identities.get(identity_handle)
        if identity is None:
            raise PreparedAuthorityEndpointUnavailable("listener identity was revoked")
        return identity.service_uid

    def _check_live(self) -> None:
        if self._closed:
            raise PreparedAuthorityEndpointUnavailable("prepared endpoint custodian is closed")
        session = self.binding._session
        session._check_live()
        self.current_actor.verify_current(self.held_release)
        prepared = session._resolve_current_prepared_enrollment()
        if prepared is not self.prepared_receipt:
            raise PreparedAuthorityEndpointUnavailable("prepared endpoint generation changed")

    @staticmethod
    def _boot_epoch() -> str:
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
        except OSError:
            raise PreparedAuthorityEndpointUnavailable("Linux boot identity is unavailable") from None


__all__ = ["PreparedAuthorityEndpointUnavailable", "RootPreparedAuthorityEndpointCustodian",
           "RootPreparedAuthorityListenerReceipt"]
