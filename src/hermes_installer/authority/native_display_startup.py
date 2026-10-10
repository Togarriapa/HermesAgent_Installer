"""Root-owned Xauthority startup receipts for selected native displays.

This module never accepts an Xauthority path or process identity from an RPC.
The active display selection comes from the protected observation catalog and
the process lease comes from the root process custodian. Receipts are private
authority state; they are not public evidence records.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol


_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_AUTH_NAME = b"MIT-MAGIC-COOKIE-1"
_COOKIE_BYTES = 32


class NativeDisplayStartupDenied(PermissionError):
    """Selected native display startup or current receipt proof is unavailable."""


class DisplayReceiptSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class SelectedDisplayStartup:
    """Immutable display selection resolved from the active root catalog."""
    remote_enrollment_id: str
    native_profile_id: str
    native_generation: str
    display_profile_id: str
    display_generation: str
    display_name: str
    receipt_handle: str
    display_uid: int
    display_gid: int

    def __post_init__(self) -> None:
        ids = (self.remote_enrollment_id, self.native_profile_id,
               self.native_generation, self.display_profile_id,
               self.display_generation, self.receipt_handle)
        if (any(not isinstance(item, str) or not _ID.fullmatch(item) for item in ids)
                or not _OPAQUE.fullmatch(self.receipt_handle)
                or not isinstance(self.display_name, str)
                or not re.fullmatch(r":[0-9]{1,3}(?:\.[0-9]{1,2})?", self.display_name)
                or type(self.display_uid) is not int or self.display_uid <= 0
                or type(self.display_gid) is not int or self.display_gid <= 0):
            raise ValueError("root-selected display startup identity is malformed")


@dataclass(frozen=True, slots=True, repr=False)
class PreparedXauthority:
    """Private root-created cookie file, pending a protected process start."""
    remote_enrollment_id: str
    native_profile_id: str
    native_generation: str
    display_profile_id: str
    display_generation: str
    display_name: str
    receipt_handle: str
    display_uid: int
    display_gid: int
    path: Path = field(repr=False)
    device: int
    inode: int
    owner_uid: int
    owner_gid: int
    mode: int
    content_sha256: str = field(repr=False)

    def __repr__(self) -> str:
        return "PreparedXauthority(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class XauthorityStartupReceipt:
    """Sealed one-selection startup receipt with secret metadata redacted."""
    schema: int
    receipt_handle: str
    remote_enrollment_id: str
    native_profile_id: str
    native_generation: str
    display_profile_id: str
    display_generation: str
    display_name: str
    process_id: str
    process_generation: str
    pid: int
    pid_start_ticks: int
    pidfd_identity: str
    cgroup_identity: str
    mount_namespace_inode: int
    network_namespace_inode: int
    executable_device: int
    executable_inode: int
    executable_sha256: str
    process_uid: int
    process_gid: int
    xauthority_path: Path = field(repr=False)
    xauthority_device: int
    xauthority_inode: int
    xauthority_uid: int
    xauthority_gid: int
    xauthority_mode: int
    xauthority_sha256: str = field(repr=False)
    issued_monotonic: float
    expires_monotonic: float
    signature: bytes = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "XauthorityStartupReceipt(<root-private>)"

    def payload(self) -> bytes:
        return _canonical({
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "remote_enrollment_id": self.remote_enrollment_id,
            "native_profile_id": self.native_profile_id,
            "native_generation": self.native_generation,
            "display_profile_id": self.display_profile_id,
            "display_generation": self.display_generation,
            "display_name": self.display_name,
            "process_id": self.process_id,
            "process_generation": self.process_generation,
            "pid": self.pid, "pid_start_ticks": self.pid_start_ticks,
            "pidfd_identity": self.pidfd_identity,
            "cgroup_identity": self.cgroup_identity,
            "mount_namespace_inode": self.mount_namespace_inode,
            "network_namespace_inode": self.network_namespace_inode,
            "executable_device": self.executable_device,
            "executable_inode": self.executable_inode,
            "executable_sha256": self.executable_sha256,
            "process_uid": self.process_uid, "process_gid": self.process_gid,
            "xauthority_path": str(self.xauthority_path),
            "xauthority_device": self.xauthority_device,
            "xauthority_inode": self.xauthority_inode,
            "xauthority_uid": self.xauthority_uid,
            "xauthority_gid": self.xauthority_gid,
            "xauthority_mode": self.xauthority_mode,
            "xauthority_sha256": self.xauthority_sha256,
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        })


@dataclass(slots=True, repr=False)
class SelectedXauthorityFile:
    """Root-private open file and current process lease for a native observer."""
    receipt: XauthorityStartupReceipt
    file_fd: int = field(repr=False)
    pidfd: int = field(repr=False)

    @property
    def path(self) -> Path:
        return self.receipt.xauthority_path

    @property
    def device(self) -> int:
        return self.receipt.xauthority_device

    @property
    def inode(self) -> int:
        return self.receipt.xauthority_inode

    @property
    def owner_uid(self) -> int:
        return self.receipt.xauthority_uid

    @property
    def owner_gid(self) -> int:
        return self.receipt.xauthority_gid

    @property
    def mode(self) -> int:
        return self.receipt.xauthority_mode

    @property
    def content_sha256(self) -> str:
        return self.receipt.xauthority_sha256

    @property
    def process_id(self) -> str:
        return self.receipt.process_id

    @property
    def process_generation(self) -> str:
        return self.receipt.process_generation

    @property
    def pid_start_ticks(self) -> int:
        return self.receipt.pid_start_ticks

    @property
    def pidfd_identity(self) -> str:
        return self.receipt.pidfd_identity

    @property
    def cgroup_id(self) -> str:
        return self.receipt.cgroup_identity

    @property
    def receipt_handle(self) -> str:
        return self.receipt.receipt_handle

    @property
    def remote_enrollment_id(self) -> str:
        return self.receipt.remote_enrollment_id

    @property
    def native_profile_id(self) -> str:
        return self.receipt.native_profile_id

    @property
    def native_generation(self) -> str:
        return self.receipt.native_generation

    @property
    def display_profile_id(self) -> str:
        return self.receipt.display_profile_id

    @property
    def display_generation(self) -> str:
        return self.receipt.display_generation

    @property
    def display_name(self) -> str:
        return self.receipt.display_name

    def close(self) -> None:
        for fd_name in ("file_fd", "pidfd"):
            fd = getattr(self, fd_name)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
                setattr(self, fd_name, -1)

    def __enter__(self) -> "SelectedXauthorityFile":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SelectedXauthorityFile(<root-private>)"


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def encode_xauthority(display_name: str, cookie: bytes) -> bytes:
    """Encode one FamilyWild MIT cookie entry without invoking xauth/argv."""
    if (not isinstance(display_name, str)
            or not re.fullmatch(r":[0-9]{1,3}(?:\.[0-9]{1,2})?", display_name)
            or not isinstance(cookie, bytes) or len(cookie) != _COOKIE_BYTES):
        raise ValueError("selected display or cookie is invalid")
    number = display_name[1:].split(".", 1)[0].encode("ascii")
    fields = (b"", number, _AUTH_NAME, cookie)
    encoded = bytearray((0xff, 0xff))  # FamilyWild
    for item in fields:
        if len(item) > 65535:
            raise ValueError("Xauthority field exceeds protocol bounds")
        encoded.extend(len(item).to_bytes(2, "big"))
        encoded.extend(item)
    return bytes(encoded)


def _safe_profile_dir(root: Path, display_profile_id: str, gid: int,
                      *, writer_uid: int) -> tuple[int, Path]:
    """Open a fixed root path with no symlink traversal and ensure private custody."""
    if not root.is_absolute() or os.path.normpath(root) != str(root):
        raise NativeDisplayStartupDenied("Xauthority root path is not canonical")
    try:
        if root.resolve(strict=True) != root:
            raise NativeDisplayStartupDenied("Xauthority root contains a symlink or alias")
    except OSError:
        raise NativeDisplayStartupDenied("Xauthority root is unavailable") from None
    root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                      | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        root_stat = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != writer_uid
                or stat.S_IMODE(root_stat.st_mode) & 0o022):
            raise NativeDisplayStartupDenied("Xauthority root custody is unsafe")
        directory_name = hashlib.sha256(display_profile_id.encode("ascii")).hexdigest()[:32]
        created = False
        try:
            os.mkdir(directory_name, 0o710, dir_fd=root_fd)
            created = True
        except FileExistsError:
            pass
        directory_fd = os.open(directory_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                               dir_fd=root_fd)
        try:
            if created:
                os.fchown(directory_fd, writer_uid, gid)
                os.fchmod(directory_fd, 0o710)
            directory_stat = os.fstat(directory_fd)
            if (not stat.S_ISDIR(directory_stat.st_mode) or directory_stat.st_uid != writer_uid
                    or directory_stat.st_gid != gid or stat.S_IMODE(directory_stat.st_mode) != 0o710):
                raise NativeDisplayStartupDenied("selected Xauthority directory custody is unsafe")
            return directory_fd, root / directory_name
        except BaseException:
            os.close(directory_fd)
            raise
    finally:
        os.close(root_fd)


class XauthorityStartupRegistry:
    """Issue and resolve signed receipts only for active root-custodied displays."""

    def __init__(self, *, root: Path, signer: DisplayReceiptSigner,
                 custody: Any, monotonic: Callable[[], float] = time.monotonic,
                 writer_uid: int = 0):
        if (not isinstance(root, Path) or not callable(getattr(signer, "sign", None))
                or not callable(getattr(signer, "verify", None))
                or not callable(getattr(custody, "resolve_active_process_handle", None))
                or not callable(monotonic) or type(writer_uid) is not int or writer_uid < 0):
            raise ValueError("root Xauthority receipt dependencies are incomplete")
        self.root, self.signer, self.custody = root, signer, custody
        self.monotonic, self.writer_uid = monotonic, writer_uid
        self._lock = threading.RLock()
        self._receipts: dict[str, XauthorityStartupReceipt] = {}
        self._pidfds: dict[str, int] = {}

    def prepare(self, selected: SelectedDisplayStartup) -> PreparedXauthority:
        """Create a root-owned, group-readable Xauthority file before launch.

        The cookie exists only in local memory and the mode-0440 file. It is
        never put in a process argument, journal, log, receipt or wire response.
        """
        if not isinstance(selected, SelectedDisplayStartup):
            raise NativeDisplayStartupDenied("root-selected display enrollment is required")
        directory_fd, directory_path = _safe_profile_dir(
            self.root, selected.display_profile_id, selected.display_gid,
            writer_uid=self.writer_uid)
        cookie = bytearray(os.urandom(_COOKIE_BYTES))
        content = encode_xauthority(selected.display_name, bytes(cookie))
        name = "xauthority-" + hashlib.sha256(
            (selected.receipt_handle + "\0" + selected.display_generation).encode("ascii")
        ).hexdigest()[:32]
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = -1
        created = False
        try:
            fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
            created = True
            os.fchown(fd, self.writer_uid, selected.display_gid)
            os.fchmod(fd, 0o440)
            view = memoryview(content)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short Xauthority write")
                view = view[count:]
            os.fsync(fd)
            info = os.fstat(fd)
            digest = hashlib.sha256(content).hexdigest()
            if (info.st_uid != self.writer_uid or info.st_gid != selected.display_gid
                    or stat.S_IMODE(info.st_mode) != 0o440
                    or info.st_size != len(content)):
                raise NativeDisplayStartupDenied("Xauthority file metadata is not protected")
            os.fsync(directory_fd)
            return PreparedXauthority(
                selected.remote_enrollment_id, selected.native_profile_id,
                selected.native_generation, selected.display_profile_id,
                selected.display_generation, selected.display_name,
                selected.receipt_handle, selected.display_uid, selected.display_gid,
                directory_path / name,
                info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                stat.S_IMODE(info.st_mode), digest)
        except BaseException:
            if created:
                try:
                    current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    original = os.fstat(fd) if fd >= 0 else None
                    if (original is not None and current.st_dev == original.st_dev
                            and current.st_ino == original.st_ino):
                        os.unlink(name, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                except OSError:
                    pass
            raise
        finally:
            cookie[:] = b"\0" * len(cookie)
            os.close(directory_fd)
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    def seal_started_display(self, prepared: PreparedXauthority) -> XauthorityStartupReceipt:
        """Seal only after custody proves the selected display process is live."""
        from hermes_installer.managed_process_custodian import ManagedProcessIdentityLease
        if not isinstance(prepared, PreparedXauthority):
            raise NativeDisplayStartupDenied("prepared protected Xauthority file is required")
        lease = self.custody.resolve_active_process_handle(
            prepared.display_profile_id, prepared.display_generation)
        if not isinstance(lease, ManagedProcessIdentityLease):
            raise NativeDisplayStartupDenied("current root process PIDFD proof is unavailable")
        try:
            return self._seal_with_lease(prepared, lease)
        finally:
            lease.close()

    def _seal_with_lease(self, prepared: PreparedXauthority,
                         lease: Any) -> XauthorityStartupReceipt:
        if (lease.profile_id != prepared.display_profile_id
                or lease.generation != prepared.display_generation
                or lease.uid != prepared.display_uid
                or lease.gid != prepared.display_gid):
            raise NativeDisplayStartupDenied("display process lease differs from the selected generation")
        if (lease.uid <= 0 or lease.gid <= 0 or lease.pid <= 0
                or lease.start_ticks <= 0 or lease.pidfd < 0
                or not lease.process_id or not lease.cgroup_identity
                or not _SHA256.fullmatch(lease.executable_sha256)
                or lease.executable_device <= 0 or lease.executable_inode <= 0):
            raise NativeDisplayStartupDenied("custody process identity lease is incomplete")
        info = self._open_and_check(prepared)
        os.close(info)
        now = self.monotonic()
        expiry = float(lease.expires_monotonic)
        if not now < expiry or expiry - now > 600.0:
            raise NativeDisplayStartupDenied("display process lease is expired or unbounded")
        pidfd_identity = hashlib.sha256(_canonical({
            "process_id": lease.process_id, "generation": lease.generation,
            "pid": lease.pid, "start_ticks": lease.start_ticks,
            "cgroup": lease.cgroup_identity,
        })).hexdigest()
        unsigned = {
            "schema": 1, "receipt_handle": prepared.receipt_handle,
            "remote_enrollment_id": prepared.remote_enrollment_id,
            "native_profile_id": prepared.native_profile_id,
            "native_generation": prepared.native_generation,
            "display_profile_id": prepared.display_profile_id,
            "display_generation": prepared.display_generation,
            "display_name": prepared.display_name,
            "process_id": lease.process_id, "process_generation": lease.generation,
            "pid": lease.pid, "pid_start_ticks": lease.start_ticks,
            "pidfd_identity": pidfd_identity, "cgroup_identity": lease.cgroup_identity,
            "mount_namespace_inode": lease.mount_namespace_inode,
            "network_namespace_inode": lease.network_namespace_inode,
            "executable_device": lease.executable_device,
            "executable_inode": lease.executable_inode,
            "executable_sha256": lease.executable_sha256,
            "process_uid": lease.uid, "process_gid": lease.gid,
            "xauthority_path": prepared.path,
            "xauthority_device": prepared.device, "xauthority_inode": prepared.inode,
            "xauthority_uid": prepared.owner_uid, "xauthority_gid": prepared.owner_gid,
            "xauthority_mode": prepared.mode, "xauthority_sha256": prepared.content_sha256,
            "issued_monotonic": now, "expires_monotonic": expiry,
        }
        provisional = XauthorityStartupReceipt(**unsigned, signature=b"")
        receipt = XauthorityStartupReceipt(**unsigned,
                                           signature=self.signer.sign(provisional.payload()))
        try:
            retained_pidfd = os.dup(lease.pidfd)
        except OSError:
            self.discard_prepared(prepared)
            raise NativeDisplayStartupDenied("current display PIDFD could not be retained") from None
        with self._lock:
            old = self._receipts.get(receipt.receipt_handle)
            if old is not None:
                os.close(retained_pidfd)
                if old == receipt and self.signer.verify(old.payload(), old.signature):
                    return old
                self.discard_prepared(prepared)
                raise NativeDisplayStartupDenied("display receipt handle was already used")
            self._receipts[receipt.receipt_handle] = receipt
            self._pidfds[receipt.receipt_handle] = retained_pidfd
        return receipt

    def resolve_selected(self, receipt_handle: str, *, remote_enrollment_id: str,
                         native_profile_id: str, native_generation: str,
                         display_profile_id: str, display_generation: str,
                         display_name: str) -> SelectedXauthorityFile:
        if not isinstance(receipt_handle, str) or not _OPAQUE.fullmatch(receipt_handle):
            raise NativeDisplayStartupDenied("Xauthority receipt handle is invalid")
        with self._lock:
            receipt = self._receipts.get(receipt_handle)
            pidfd = os.dup(self._pidfds[receipt_handle]) if receipt_handle in self._pidfds else -1
        if (receipt is None or pidfd < 0
                or receipt.remote_enrollment_id != remote_enrollment_id
                or receipt.native_profile_id != native_profile_id
                or receipt.native_generation != native_generation
                or receipt.display_profile_id != display_profile_id
                or receipt.display_generation != display_generation
                or receipt.display_name != display_name
                or self.monotonic() >= receipt.expires_monotonic
                or not self.signer.verify(receipt.payload(), receipt.signature)):
            if pidfd >= 0:
                os.close(pidfd)
            raise NativeDisplayStartupDenied("current selected Xauthority receipt is unavailable")
        lease = self.custody.resolve_active_process_handle(display_profile_id, display_generation)
        if lease is None:
            os.close(pidfd)
            raise NativeDisplayStartupDenied("selected display process is no longer current")
        try:
            if (lease.process_id != receipt.process_id
                    or lease.generation != receipt.process_generation
                    or lease.pid != receipt.pid
                    or lease.start_ticks != receipt.pid_start_ticks
                    or lease.uid != receipt.process_uid or lease.gid != receipt.process_gid
                    or lease.cgroup_identity != receipt.cgroup_identity
                    or lease.executable_device != receipt.executable_device
                    or lease.executable_inode != receipt.executable_inode
                    or lease.executable_sha256 != receipt.executable_sha256
                    or lease.mount_namespace_inode != receipt.mount_namespace_inode
                    or lease.network_namespace_inode != receipt.network_namespace_inode
                    or self.monotonic() >= lease.expires_monotonic):
                os.close(pidfd)
                raise NativeDisplayStartupDenied("display process identity changed after startup")
            file_fd = self._open_and_check(receipt)
            return SelectedXauthorityFile(receipt, file_fd, pidfd)
        except BaseException:
            if pidfd >= 0:
                try:
                    os.close(pidfd)
                except OSError:
                    pass
            raise
        finally:
            lease.close()

    def resolve_catalog_selection(self, catalog: Any,
                                  remote_enrollment_id: str) -> SelectedXauthorityFile:
        """Resolve only the active protected observation row and its receipt.

        The catalog owns all selected IDs and the receipt handle. This adapter
        accepts no file path, PID, display name, or generation from its caller.
        """
        getter = getattr(catalog, "selected_native_window", None)
        if not callable(getter):
            raise NativeDisplayStartupDenied("root native-window catalog is unavailable")
        try:
            selected = getter(remote_enrollment_id)
        except Exception:
            raise NativeDisplayStartupDenied("root native-window selection is unavailable") from None
        fields = (
            "remote_enrollment_id", "native_profile_id", "native_generation",
            "display_server_profile_id", "display_server_generation", "display_name",
            "xauthority_receipt_handle",
        )
        if any(not hasattr(selected, name) for name in fields):
            raise NativeDisplayStartupDenied("selected native-window row lacks protected receipt fields")
        if selected.remote_enrollment_id != remote_enrollment_id:
            raise NativeDisplayStartupDenied("native-window row belongs to another enrollment")
        resolved = self.resolve_selected(
            selected.xauthority_receipt_handle,
            remote_enrollment_id=selected.remote_enrollment_id,
            native_profile_id=selected.native_profile_id,
            native_generation=selected.native_generation,
            display_profile_id=selected.display_server_profile_id,
            display_generation=selected.display_server_generation,
            display_name=selected.display_name,
        )
        receipt = resolved.receipt
        optional_pins = (
            ("xauthority_device", receipt.xauthority_device),
            ("xauthority_inode", receipt.xauthority_inode),
            ("xauthority_uid", receipt.xauthority_uid),
            ("xauthority_gid", receipt.xauthority_gid),
            ("xauthority_mode", receipt.xauthority_mode),
            ("xauthority_sha256", receipt.xauthority_sha256),
            ("xauthority_content_sha256", receipt.xauthority_sha256),
        )
        if any(hasattr(selected, name) and getattr(selected, name) != value
               for name, value in optional_pins):
            resolved.close()
            raise NativeDisplayStartupDenied("selected Xauthority row differs from the sealed startup receipt")
        return resolved

    def discard_prepared(self, prepared: PreparedXauthority) -> None:
        if not isinstance(prepared, PreparedXauthority):
            return
        try:
            directory = os.open(prepared.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                fd = os.open(prepared.path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
                try:
                    info = os.fstat(fd)
                    if (info.st_dev == prepared.device and info.st_ino == prepared.inode
                            and info.st_uid == prepared.owner_uid and info.st_gid == prepared.owner_gid
                            and stat.S_IMODE(info.st_mode) == prepared.mode
                            and self._hash_fd(fd) == prepared.content_sha256):
                        os.unlink(prepared.path.name, dir_fd=directory)
                finally:
                    os.close(fd)
            finally:
                os.close(directory)
        except OSError:
            return

    def revoke(self, receipt_handle: str) -> bool:
        """Invalidate one sealed startup receipt and remove its exact cookie file."""
        if not isinstance(receipt_handle, str) or not _OPAQUE.fullmatch(receipt_handle):
            return False
        with self._lock:
            receipt = self._receipts.pop(receipt_handle, None)
            pidfd = self._pidfds.pop(receipt_handle, None)
        if pidfd is not None:
            try:
                os.close(pidfd)
            except OSError:
                pass
        if receipt is None:
            return False
        try:
            directory = os.open(receipt.xauthority_path.parent,
                                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                fd = os.open(receipt.xauthority_path.name,
                             os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
                try:
                    info = os.fstat(fd)
                    if ((info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                         stat.S_IMODE(info.st_mode), self._hash_fd(fd))
                            == (receipt.xauthority_device, receipt.xauthority_inode,
                                receipt.xauthority_uid, receipt.xauthority_gid,
                                receipt.xauthority_mode, receipt.xauthority_sha256)):
                        os.unlink(receipt.xauthority_path.name, dir_fd=directory)
                        os.fsync(directory)
                finally:
                    os.close(fd)
            finally:
                os.close(directory)
        except OSError:
            pass
        return True

    def _open_and_check(self, prepared: PreparedXauthority | XauthorityStartupReceipt) -> int:
        path = prepared.path if isinstance(prepared, PreparedXauthority) else prepared.xauthority_path
        expected = (prepared.device, prepared.inode, prepared.owner_uid, prepared.owner_gid,
                    prepared.mode, prepared.content_sha256) if isinstance(prepared, PreparedXauthority) else (
                    prepared.xauthority_device, prepared.xauthority_inode, prepared.xauthority_uid,
                    prepared.xauthority_gid, prepared.xauthority_mode, prepared.xauthority_sha256)
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode)
                    or (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
                    != expected[:5] or self._hash_fd(fd) != expected[5]):
                os.close(fd)
                raise NativeDisplayStartupDenied("Xauthority file changed after protected creation")
            return fd
        except OSError:
            raise NativeDisplayStartupDenied("selected protected Xauthority file is unavailable") from None

    @staticmethod
    def _hash_fd(fd: int) -> str:
        digest = hashlib.sha256()
        os.lseek(fd, 0, os.SEEK_SET)
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
