"""Cold creation and held-FD custody for the fixed authority runtime root.

The runtime tree is volatile.  Its directory names confer no ownership: this
module accepts existing entries only when the selected root setup journal has
the exact recorded inode and ownership, and it never repairs existing entries.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
import threading
import ctypes
import time
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Mapping
from typing import Any

from .bootstrap_enrollment import BootstrapEnrollmentPending

_SEAL = object()
_RUNTIME_PREFIX = "hermes-installer"
_AUTHORITY_LEAF = "authority"
_JOURNAL_DIR = "runtime-root-custody"
_JOURNAL_FILE = "authority-runtime-root-v1.json"
_SETUP_JOURNAL_ROOT = Path("/var/lib/hermes-installer/authority-journal")
_OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class RuntimeRootCustodyUnavailable(BootstrapEnrollmentPending):
    """The current setup cannot establish owned runtime-root custody."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _directory(fd: int, *, mode: int | None = None) -> os.stat_result:
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_mode & 0o022 or (mode is not None and stat.S_IMODE(info.st_mode) != mode)):
        raise RuntimeRootCustodyUnavailable("runtime directory is not safely root-owned")
    return info


def _open_fixed_directory(parent_fd: int, leaf: str, expected: dict[str, int] | None,
                          create_mode: int, created: list[tuple[int, str, int, int]]) -> tuple[int, os.stat_result, bool]:
    """Open an existing journal-owned directory or exclusively create a new one."""
    if expected is None:
        try:
            os.mkdir(leaf, create_mode, dir_fd=parent_fd)
        except FileExistsError:
            raise RuntimeRootCustodyUnavailable("unowned runtime directory already exists") from None
        fd = -1
        created_identity: tuple[int, int] | None = None
        try:
            created_entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(created_entry.st_mode) or created_entry.st_uid != 0 or created_entry.st_gid != 0:
                raise RuntimeRootCustodyUnavailable("exclusive runtime directory creation was replaced")
            created_identity = (created_entry.st_dev, created_entry.st_ino)
            fd = os.open(leaf, _OPEN_DIR, dir_fd=parent_fd)
            info = os.fstat(fd)
            if ((info.st_dev, info.st_ino) != created_identity
                    or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0):
                raise RuntimeRootCustodyUnavailable("new runtime directory was replaced")
            created.append((parent_fd, leaf, info.st_dev, info.st_ino))
            os.fchmod(fd, create_mode)
            info = _directory(fd, mode=create_mode)
            entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if (entry.st_dev, entry.st_ino) != (info.st_dev, info.st_ino):
                raise RuntimeRootCustodyUnavailable("new runtime directory changed during creation")
            return fd, info, True
        except BaseException:
            if fd >= 0:
                os.close(fd)
            if created_identity is not None:
                _remove_same_empty_directory(parent_fd, leaf, *created_identity)
            raise
    try:
        fd = os.open(leaf, _OPEN_DIR, dir_fd=parent_fd)
    except OSError as exc:
        raise RuntimeRootCustodyUnavailable("journal-owned runtime directory cannot be opened") from exc
    try:
        info = _directory(fd, mode=create_mode)
        entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(entry.st_mode) or (entry.st_dev, entry.st_ino) != (expected["device"], expected["inode"]):
            raise RuntimeRootCustodyUnavailable("journal-owned runtime directory identity changed")
        if (info.st_dev, info.st_ino) != (expected["device"], expected["inode"]):
            raise RuntimeRootCustodyUnavailable("journal-owned runtime directory inode differs")
        return fd, info, False
    except BaseException:
        os.close(fd)
        raise


def _write_journal(journal_dir: Path, document: dict[str, Any]) -> None:
    """Atomically replace one file in the already selected root-owned journal."""
    directory_fd = os.open(journal_dir, _OPEN_DIR)
    temp = ".authority-runtime-root-" + secrets.token_hex(12) + ".tmp"
    fd = -1
    try:
        _directory(directory_fd, mode=0o700)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     0o600, dir_fd=directory_fd)
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        body = _canonical(document)
        offset = 0
        while offset < len(body):
            written = os.write(fd, body[offset:])
            if written <= 0:
                raise RuntimeRootCustodyUnavailable("protected runtime-root journal write made no progress")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp, _JOURNAL_FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except OSError as exc:
        raise RuntimeRootCustodyUnavailable("protected runtime-root journal update failed") from exc
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temp, dir_fd=directory_fd)
        except OSError:
            pass
        os.close(directory_fd)


def _read_journal(journal_dir: Path) -> dict[str, Any] | None:
    directory_fd = os.open(journal_dir, _OPEN_DIR)
    try:
        _directory(directory_fd, mode=0o700)
        try:
            fd = os.open(_JOURNAL_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > 16384):
                raise RuntimeRootCustodyUnavailable("runtime-root journal file is not protected")
            chunks: list[bytes] = []
            size = 0
            while size <= 16384:
                chunk = os.read(fd, min(4096, 16385 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            raw = b"".join(chunks)
            if len(raw) != info.st_size:
                raise RuntimeRootCustodyUnavailable("runtime-root journal changed while reading")
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeRootCustodyUnavailable("runtime-root journal is malformed") from exc
    if (not isinstance(value, dict) or set(value) != {"schema", "journal", "prefix", "authority"}
            or value.get("schema") != 1 or not isinstance(value.get("journal"), dict)):
        raise RuntimeRootCustodyUnavailable("runtime-root journal has an unknown schema")
    return value


def _remove_same_empty_directory(parent_fd: int, leaf: str, device: int, inode: int) -> bool:
    try:
        fd = os.open(leaf, _OPEN_DIR, dir_fd=parent_fd)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if ((info.st_dev, info.st_ino) != (device, inode)
                or (entry.st_dev, entry.st_ino) != (device, inode)
                or info.st_uid != 0 or info.st_gid != 0 or os.listdir(fd)):
            return False
        os.rmdir(leaf, dir_fd=parent_fd)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def _rename_noreplace(parent_fd: int, source: str, target: str) -> None:
    """Use the kernel's atomic no-replace directory rename; fail closed if absent."""
    renameat2 = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if renameat2 is None:
        raise RuntimeRootCustodyUnavailable("kernel atomic no-replace rename is unavailable")
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    if renameat2(parent_fd, os.fsencode(source), parent_fd, os.fsencode(target), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), target)


def _open_journal_owned_directory(parent_fd: int, leaf: str, record: dict[str, int] | dict[str, Any] | None,
                                  mode: int, created: list[tuple[int, str, int, int]],
                                  journal_dir: Path, document: dict[str, Any], key: str
                                  ) -> tuple[int, os.stat_result, bool]:
    """Create through a journaled staging inode so interrupted publication can resume."""
    if record is not None and record.get("state") == "owned":
        return _open_fixed_directory(parent_fd, leaf, record, mode, created)
    if record is not None and record.get("state") == "pending":
        required = {"state", "device", "inode", "staging"}
        if (set(record) != required or type(record["device"]) is not int or type(record["inode"]) is not int
                or not isinstance(record["staging"], str)
                or not record["staging"].startswith(".hermes-authority-root-")
                or "/" in record["staging"]):
            raise RuntimeRootCustodyUnavailable("interrupted runtime-root creation record is malformed")
        try:
            final = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            final = None
        expected_identity = (record["device"], record["inode"])
        if final is not None:
            if (not stat.S_ISDIR(final.st_mode) or (final.st_dev, final.st_ino) != expected_identity):
                raise RuntimeRootCustodyUnavailable("runtime-root target conflicts with interrupted owned create")
        else:
            try:
                staged = os.stat(record["staging"], dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                # Neither name remains; the pending operation left no usable object.
                document[key] = None
                _write_journal(journal_dir, document)
                return _open_journal_owned_directory(parent_fd, leaf, None, mode, created,
                                                     journal_dir, document, key)
            if (not stat.S_ISDIR(staged.st_mode) or (staged.st_dev, staged.st_ino) != expected_identity
                    or staged.st_uid != 0 or staged.st_gid != 0 or stat.S_IMODE(staged.st_mode) != mode):
                raise RuntimeRootCustodyUnavailable("interrupted runtime-root staging inode changed")
            _rename_noreplace(parent_fd, record["staging"], leaf)
        document[key] = {"state": "owned", "device": expected_identity[0], "inode": expected_identity[1]}
        _write_journal(journal_dir, document)
        entry = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if (entry.st_dev, entry.st_ino) != expected_identity:
            raise RuntimeRootCustodyUnavailable("recovered runtime-root inode changed during journal update")
        return _open_fixed_directory(parent_fd, leaf, document[key], mode, created)
    if record is not None:
        raise RuntimeRootCustodyUnavailable("runtime-root journal contains an unknown create state")

    staging = ".hermes-authority-root-" + secrets.token_hex(12)
    try:
        os.mkdir(staging, mode, dir_fd=parent_fd)
    except FileExistsError:
        raise RuntimeRootCustodyUnavailable("runtime-root staging name unexpectedly exists") from None
    fd = -1
    try:
        entry = os.stat(staging, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != 0 or entry.st_gid != 0:
            raise RuntimeRootCustodyUnavailable("new runtime-root staging directory was replaced")
        identity = (entry.st_dev, entry.st_ino)
        fd = os.open(staging, _OPEN_DIR, dir_fd=parent_fd)
        info = os.fstat(fd)
        if ((info.st_dev, info.st_ino) != identity or info.st_uid != 0 or info.st_gid != 0):
            raise RuntimeRootCustodyUnavailable("new runtime-root staging inode changed")
        os.fchmod(fd, mode)
        info = _directory(fd, mode=mode)
        pending_record = {"state": "pending", "device": info.st_dev, "inode": info.st_ino,
                          "staging": staging}
        document[key] = pending_record
        _write_journal(journal_dir, document)
        durable_pending = True
        _rename_noreplace(parent_fd, staging, leaf)
        document[key] = {"state": "owned", "device": info.st_dev, "inode": info.st_ino}
        _write_journal(journal_dir, document)
        created.append((parent_fd, leaf, info.st_dev, info.st_ino))
        return _open_fixed_directory(parent_fd, leaf, document[key], mode, created)
    except BaseException:
        # Keep a journaled pending staging inode for safe recovery.  Before the
        # intent is durable, remove only the exact private staging inode.
        durable_pending = locals().get("durable_pending", False)
        if not durable_pending:
            try:
                persisted = _read_journal(journal_dir)
                durable_pending = persisted is not None and persisted.get(key) == document.get(key)
            except Exception:
                durable_pending = False
        if not durable_pending:
            try:
                staged = os.stat(staging, dir_fd=parent_fd, follow_symlinks=False)
                if fd >= 0 and (staged.st_dev, staged.st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                    os.rmdir(staging, dir_fd=parent_fd)
            except OSError:
                pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


@dataclass(slots=True, repr=False)
class RootPreparedAuthorityRootReceipt:
    """Unforgeable live handle retaining the actual fixed authority directory FD."""
    session_id: str
    transaction_handle: str
    plan_digest: str
    release_commit: str
    actor_pid: int
    actor_start_time: int
    device: int
    inode: int
    journal_device: int
    journal_inode: int
    prepared_generation_id: str
    prepared_generation_digest: str
    expires_monotonic: float
    _binding: Any = field(repr=False)
    _release: Any = field(repr=False)
    _actor: Any = field(repr=False)
    _journal_path: Path = field(repr=False)
    _run_fd: int = field(repr=False)
    _prefix_fd: int = field(repr=False)
    _root_fd: int = field(repr=False)
    _run_identity: tuple[int, int] = field(repr=False)
    _prefix_identity: tuple[int, int] = field(repr=False)
    _root_identity: tuple[int, int] = field(repr=False)
    _created: tuple[tuple[int, str, int, int], ...] = field(repr=False)
    _journal_owner: dict[str, Any] = field(repr=False)
    _issuer: Any = field(repr=False)
    _seal: object = field(repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)
    _closed: bool = field(default=False, repr=False)
    _adopted_publication: tuple[Any, ...] | None = field(default=None, repr=False)

    def __repr__(self) -> str:
        return "RootPreparedAuthorityRootReceipt(<held-root-directory>)"

    @property
    def root_fd(self) -> int:
        self.verify_current()
        return self._root_fd

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._issuer is None:
            raise RuntimeRootCustodyUnavailable("held runtime-root receipt has no issuer")
        self._issuer._verify_receipt(self)

    def _verify_current_local(self, *, allow_activation_transition: bool = False) -> None:
        with self._lock:
            if self._closed or self._seal is not _SEAL:
                raise RuntimeRootCustodyUnavailable("held runtime-root receipt is closed or invalid")
            session = self._binding._session
            session._check_live()
            self._actor.verify_current(self._release)
            if time.monotonic() >= self.expires_monotonic:
                raise RuntimeRootCustodyUnavailable("prepared authority-root receipt reached its original deadline")
            if self._adopted_publication is None and not allow_activation_transition:
                prepared = session._resolve_current_prepared_enrollment()
                if (prepared.state != "prepared" or prepared.enrollment_ids
                        or prepared.generation_id != self.prepared_generation_id
                        or prepared.generation_digest != self.prepared_generation_digest):
                    raise RuntimeRootCustodyUnavailable("original prepared authority generation is no longer current")
            elif self._adopted_publication is not None:
                self._verify_current_active_adoption(session)
            self._binding.resolve_current_setup_identity()
            session._refresh_authorization()
            current_journal = session._authorization.root_journal_root
            if (not isinstance(current_journal, Mapping)
                    or current_journal.get("root_id") != self._journal_owner["root_id"]
                    or current_journal.get("absolute_path") != self._journal_owner["absolute_path"]
                    or current_journal.get("device") != self._journal_owner["device"]
                    or current_journal.get("inode") != self._journal_owner["inode"]
                    or current_journal.get("generation") != self._journal_owner["generation"]):
                raise RuntimeRootCustodyUnavailable("selected root setup journal changed")
            from .bootstrap_enrollment import _secure_directory_identity, _verify_root_journal_selection
            _verify_root_journal_selection(current_journal, _SETUP_JOURNAL_ROOT)
            selected_info = _secure_directory_identity(_SETUP_JOURNAL_ROOT)
            if (selected_info.st_dev, selected_info.st_ino) != (
                    self._journal_owner["device"], self._journal_owner["inode"]):
                raise RuntimeRootCustodyUnavailable("selected root setup journal inode changed")
            journal_fd = os.open(self._journal_path, _OPEN_DIR)
            try:
                journal_info = _directory(journal_fd, mode=0o700)
                journal_entry = self._journal_path.lstat()
                if (stat.S_ISLNK(journal_entry.st_mode)
                        or (journal_info.st_dev, journal_info.st_ino)
                        != (self.journal_device, self.journal_inode)
                        or (journal_entry.st_dev, journal_entry.st_ino)
                        != (self.journal_device, self.journal_inode)):
                    raise RuntimeRootCustodyUnavailable("runtime-root journal directory identity changed")
            finally:
                os.close(journal_fd)
            record = _read_journal(self._journal_path)
            if (record is None or record.get("journal") != self._journal_owner
                    or record.get("prefix") != {"state": "owned", "device": self._prefix_identity[0],
                                                  "inode": self._prefix_identity[1]}
                    or record.get("authority") != {"state": "owned", "device": self._root_identity[0],
                                                     "inode": self._root_identity[1]}):
                raise RuntimeRootCustodyUnavailable("protected runtime-root ownership journal changed")
            for fd, expected in ((self._run_fd, self._run_identity),
                                 (self._prefix_fd, self._prefix_identity), (self._root_fd, self._root_identity)):
                mode = None if fd == self._run_fd else 0o711
                info = _directory(fd, mode=mode)
                if (info.st_dev, info.st_ino) != expected:
                    raise RuntimeRootCustodyUnavailable("held runtime-root directory changed")
            for parent_fd, leaf, expected in ((self._run_fd, _RUNTIME_PREFIX, self._prefix_identity),
                                               (self._prefix_fd, _AUTHORITY_LEAF, self._root_identity)):
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != expected
                    or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
                    raise RuntimeRootCustodyUnavailable("runtime-root pathname no longer names its held inode")

    def _verify_current_active_adoption(self, session: Any) -> None:
        try:
            publication = session._resolve_current_active_policy_publication()
            active = session._resolve_current_active_enrollment()
        except Exception as exc:
            raise RuntimeRootCustodyUnavailable("active adoption lost current root publication or enrollment") from exc
        current = self._publication_identity(publication)
        if (current != self._adopted_publication
                or active.state != "committed" or not active.enrollment_ids
                or active.transaction_handle != self.transaction_handle
                or publication.transaction_handle != self.transaction_handle
                or publication.prepared_generation_id != self.prepared_generation_id):
            raise RuntimeRootCustodyUnavailable("active publication no longer adopts this prepared root")

    @staticmethod
    def _publication_identity(publication: Any) -> tuple[Any, ...]:
        from .setup_policy_publication import RootSetupPublicationReceipt
        if type(publication) is not RootSetupPublicationReceipt or publication.state != "active-committed":
            raise RuntimeRootCustodyUnavailable("active adoption requires an actual active publication receipt")
        return (publication.transaction_handle, publication.publication_handle,
                publication.publication_sha256, publication.prepared_generation_id,
                publication.generation_id, publication.service_generation_digest)

    def adopt_current_active_publication(self) -> None:
        """Bind the retained prepared root to the actual current active publication."""
        with self._issuer._lock:
            with self._lock:
                if (self._issuer._closed or self._issuer._receipts.get(id(self)) is not self):
                    raise RuntimeRootCustodyUnavailable("runtime-root receipt is not held by its live issuer")
                if self._adopted_publication is not None:
                    self._verify_current_active_adoption(self._binding._session)
                    return
                self._verify_current_local(allow_activation_transition=True)
                session = self._binding._session
                try:
                    publication = session._resolve_current_active_policy_publication()
                    active = session._resolve_current_active_enrollment()
                except Exception as exc:
                    raise RuntimeRootCustodyUnavailable("there is no current active root publication to adopt") from exc
                identity = self._publication_identity(publication)
                if (publication.transaction_handle != self.transaction_handle
                        or publication.prepared_generation_id != self.prepared_generation_id
                        or active.state != "committed" or not active.enrollment_ids
                        or active.transaction_handle != self.transaction_handle):
                    raise RuntimeRootCustodyUnavailable("active publication does not join the held prepared generation")
                self._adopted_publication = identity
                try:
                    self.verify_current()
                except BaseException:
                    self._adopted_publication = None
                    raise

    def _duplicate_listener_activation_parent(self) -> "_RootRuntimePrefixFD":
        """Return only the fixed held prefix parent for the listener-activation owner."""
        with self._issuer._lock:
            with self._lock:
                self.verify_current()
                fd = os.dup(self._prefix_fd)
                os.set_inheritable(fd, False)
                try:
                    self.verify_current()
                    return _RootRuntimePrefixFD(fd, self._prefix_identity, self)
                except BaseException:
                    os.close(fd)
                    raise

    def open_relative(self, name: str, flags: int, mode: int = 0o600) -> int:
        if (not isinstance(name, str) or not name or name in {".", ".."} or "/" in name
                or "\\" in name or "\x00" in name):
            raise RuntimeRootCustodyUnavailable("runtime-root child must be one fixed relative component")
        with self._issuer._lock:
            with self._lock:
                self.verify_current()
                try:
                    fd = os.open(name, flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                                 mode, dir_fd=self._root_fd)
                except OSError as exc:
                    raise RuntimeRootCustodyUnavailable("runtime-root child could not be opened safely") from exc
                try:
                    self.verify_current()
                except BaseException:
                    os.close(fd)
                    raise
                return fd

    def cleanup_created_empty(self) -> None:
        """Remove only this receipt's still-identical empty directories."""
        with self._issuer._lock:
            with self._lock:
                self.verify_current()
                removed: set[tuple[str, tuple[int, int]]] = set()
                for parent_fd, leaf, device, inode in reversed(self._created):
                    if _remove_same_empty_directory(parent_fd, leaf, device, inode):
                        removed.add((leaf, (device, inode)))
                if removed:
                    document = _read_journal(self._journal_path)
                    if document is None:
                        raise RuntimeRootCustodyUnavailable("runtime-root ownership journal disappeared during cleanup")
                    for key, leaf in (("prefix", _RUNTIME_PREFIX), ("authority", _AUTHORITY_LEAF)):
                        record = document[key]
                        if isinstance(record, dict) and (leaf, (record.get("device"), record.get("inode"))) in removed:
                            document[key] = None
                    _write_journal(self._journal_path, document)

    def close(self) -> None:
        with self._issuer._lock:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
                self._issuer._release_receipt(self)
                for fd in (self._root_fd, self._prefix_fd, self._run_fd):
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def __enter__(self) -> "RootPreparedAuthorityRootReceipt":
        self.verify_current()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


@dataclass(slots=True, repr=False)
class _RootRuntimePrefixFD:
    """Private typed borrowed duplicate of the fixed installer runtime prefix."""
    fd: int
    identity: tuple[int, int]
    _receipt: RootPreparedAuthorityRootReceipt = field(repr=False)
    _closed: bool = False

    def verify_current(self) -> None:
        if self._closed:
            raise RuntimeRootCustodyUnavailable("runtime-prefix FD is closed")
        self._receipt.verify_current()
        info = _directory(self.fd, mode=0o711)
        if (info.st_dev, info.st_ino) != self.identity:
            raise RuntimeRootCustodyUnavailable("runtime-prefix FD identity changed")

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            os.close(self.fd)

    def __enter__(self) -> "_RootRuntimePrefixFD":
        self.verify_current()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


class RootAuthorityRuntimeRootCustodian:
    """Create/adopt the fixed /run authority root under live setup authority."""

    def __init__(self, binding: Any, release: Any, actor: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or type(release) is not VerifiedInstallerReleaseReceipt
                or type(actor) is not RootActorObservation):
            raise RuntimeRootCustodyUnavailable("runtime root requires typed current setup custody")
        session = binding._session
        session._check_live()
        if binding._seal != session._seal:
            raise RuntimeRootCustodyUnavailable("installation binding does not belong to live setup")
        actor.verify_current(release)
        prepared = session._resolve_current_prepared_enrollment()
        if prepared.state != "prepared" or prepared.enrollment_ids:
            raise RuntimeRootCustodyUnavailable("runtime root requires the current empty prepared setup")
        session._current_root_journal_selection()
        # The current observed setup identity proves setup authorization is still live.
        binding.resolve_current_setup_identity()
        if os.name != "posix" or os.geteuid() != 0:
            raise RuntimeRootCustodyUnavailable("cold runtime root creation requires the installed root actor")
        self.binding, self.release, self.actor = binding, release, actor
        self._session = session
        self._prepared = prepared
        self._lock = threading.RLock()
        self._issuer = object()
        self._receipts: dict[int, RootPreparedAuthorityRootReceipt] = {}
        self._closed = False

    @classmethod
    def from_root_setup(cls, current_binding: Any, held_release: Any,
                        current_actor: Any) -> "RootAuthorityRuntimeRootCustodian":
        return cls(current_binding, held_release, current_actor)

    def ensure_prepared_authority_root(self, current_binding: Any, held_release: Any,
                                       current_actor: Any) -> RootPreparedAuthorityRootReceipt:
        with self._lock:
            if self._closed or (current_binding is not self.binding or held_release is not self.release
                                or current_actor is not self.actor):
                raise RuntimeRootCustodyUnavailable("runtime-root request is outside the held setup session")
            current_binding._session._check_live()
            current_actor.verify_current(held_release)
            journal_selection = current_binding._session._current_root_journal_selection()
            journal_parent = journal_selection.path
            journal_dir = journal_parent / _JOURNAL_DIR
            # The selected journal root must already be the exact root-owned inode.
            from .bootstrap_enrollment import _secure_directory_identity
            journal_info = _secure_directory_identity(journal_parent)
            if (journal_info.st_dev, journal_info.st_ino) != (journal_selection.device, journal_selection.inode):
                raise RuntimeRootCustodyUnavailable("selected setup journal changed")
            try:
                os.mkdir(journal_dir, 0o700)
            except FileExistsError:
                pass
            dir_info = journal_dir.lstat()
            if (not stat.S_ISDIR(dir_info.st_mode) or stat.S_ISLNK(dir_info.st_mode)
                    or dir_info.st_uid != 0 or dir_info.st_gid != 0 or stat.S_IMODE(dir_info.st_mode) != 0o700):
                raise RuntimeRootCustodyUnavailable("runtime-root journal directory conflicts with existing data")
            journal_fd = os.open(journal_dir, _OPEN_DIR)
            try:
                journal_identity = _directory(journal_fd, mode=0o700)
            finally:
                os.close(journal_fd)
            owner = {"root_id": journal_selection.root_id, "device": journal_selection.device,
                     "inode": journal_selection.inode, "generation": journal_selection.generation,
                     "absolute_path": str(journal_selection.path)}
            document = _read_journal(journal_dir)
            if document is None:
                document = {"schema": 1, "journal": owner, "prefix": None, "authority": None}
                _write_journal(journal_dir, document)
            if document["journal"] != owner:
                raise RuntimeRootCustodyUnavailable("runtime-root journal belongs to a different setup journal")
            created: list[tuple[int, str, int, int]] = []
            run_fd = prefix_fd = root_fd = -1
            try:
                run_fd = os.open("/run", _OPEN_DIR)
                run_info = _directory(run_fd)
                if run_info.st_mode & 0o022:
                    raise RuntimeRootCustodyUnavailable("/run is writable by group or other")
                prefix_fd, prefix_info, prefix_created = _open_journal_owned_directory(
                    run_fd, _RUNTIME_PREFIX, document["prefix"], 0o711, created,
                    journal_dir, document, "prefix")
                root_fd, root_info, root_created = _open_journal_owned_directory(
                    prefix_fd, _AUTHORITY_LEAF, document["authority"], 0o711, created,
                    journal_dir, document, "authority")
                entry = os.stat(_AUTHORITY_LEAF, dir_fd=prefix_fd, follow_symlinks=False)
                if ((entry.st_dev, entry.st_ino) != (root_info.st_dev, root_info.st_ino)
                        or stat.S_IMODE(entry.st_mode) != 0o711):
                    raise RuntimeRootCustodyUnavailable("authority root changed before receipt issue")
                current_actor.verify_current(held_release)
                current_binding._session._check_live()
                receipt = RootPreparedAuthorityRootReceipt(
                    session_id=current_binding._session._handle.session_id,
                    transaction_handle=current_binding._session._authorization.transaction_handle,
                    plan_digest=current_binding._session._authorization.plan_digest,
                    release_commit=held_release.release_commit, actor_pid=current_actor.pid,
                    actor_start_time=current_actor.start_time, device=root_info.st_dev, inode=root_info.st_ino,
                    journal_device=journal_identity.st_dev, journal_inode=journal_identity.st_ino,
                    prepared_generation_id=self._prepared.generation_id,
                    prepared_generation_digest=self._prepared.generation_digest,
                    expires_monotonic=self._prepared.expires_monotonic,
                    _binding=current_binding, _release=held_release, _actor=current_actor,
                    _journal_path=journal_dir, _run_fd=run_fd, _prefix_fd=prefix_fd, _root_fd=root_fd,
                    _run_identity=(run_info.st_dev, run_info.st_ino),
                    _prefix_identity=(prefix_info.st_dev, prefix_info.st_ino),
                    _root_identity=(root_info.st_dev, root_info.st_ino),
                    _created=tuple(created), _issuer=self, _seal=_SEAL,
                    _journal_owner=owner)
                self._receipts[id(receipt)] = receipt
                try:
                    receipt.verify_current()
                except BaseException:
                    self._receipts.pop(id(receipt), None)
                    receipt._closed = True
                    raise
                run_fd = prefix_fd = root_fd = -1
                return receipt
            except BaseException:
                for parent_fd, leaf, device, inode in reversed(created):
                    try:
                        fd = os.open(leaf, _OPEN_DIR, dir_fd=parent_fd)
                        try:
                            info = os.fstat(fd)
                            if ((info.st_dev, info.st_ino) == (device, inode)
                                    and not os.listdir(fd)):
                                os.rmdir(leaf, dir_fd=parent_fd)
                        finally:
                            os.close(fd)
                    except OSError:
                        pass
                raise
            finally:
                for fd in (root_fd, prefix_fd, run_fd):
                    if fd >= 0:
                        os.close(fd)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            receipts = tuple(self._receipts.values())
            self._receipts.clear()
            for receipt in receipts:
                receipt.close()

    def _verify_receipt(self, receipt: RootPreparedAuthorityRootReceipt) -> None:
        with self._lock:
            if self._closed or self._receipts.get(id(receipt)) is not receipt:
                raise RuntimeRootCustodyUnavailable("runtime-root receipt is not held by its live issuer")
            if (receipt._issuer is not self or receipt._binding is not self.binding
                    or receipt._release is not self.release or receipt._actor is not self.actor):
                raise RuntimeRootCustodyUnavailable("runtime-root receipt issuer bindings changed")
            receipt._verify_current_local()

    def _release_receipt(self, receipt: RootPreparedAuthorityRootReceipt) -> None:
        with self._lock:
            if self._receipts.get(id(receipt)) is receipt:
                self._receipts.pop(id(receipt), None)


__all__ = ["RootAuthorityRuntimeRootCustodian", "RootPreparedAuthorityRootReceipt",
           "RuntimeRootCustodyUnavailable"]
