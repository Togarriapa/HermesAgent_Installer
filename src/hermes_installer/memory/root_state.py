"""Root-private, profile-scoped authority state for memory operations.

This is intentionally separate from ``OwnedRoot``: installer caller roots may
belong to an unprivileged user, while this state is selected by the protected
authority enrollment and must remain root-owned. Paths are opened relative to
directory descriptors with ``O_NOFOLLOW``; worker/service paths never enter
the resolver.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Iterator, Mapping


class MemoryStateDenied(PermissionError):
    """Protected memory state root or inode does not match enrollment."""


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_SAFE_FILE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_DIRECTORY_FLAGS = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))


@dataclass(frozen=True, slots=True)
class RootJournalSelection:
    """One root journal root resolved by the protected enrollment loader."""

    root_id: str
    path: Path

    def __post_init__(self) -> None:
        if not isinstance(self.root_id, str) or not _ID.fullmatch(self.root_id):
            raise ValueError("root journal selection ID is malformed")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("root journal path must be an absolute protected selection")


def resolve_memory_state_directory(enrollment: object,
                                   root_journal_roots: Mapping[str, RootJournalSelection],
                                   *, expected_uid: int = 0) -> "MemoryAuthorityStateDirectory":
    """Resolve only the state root ID carried by a validated memory enrollment."""
    state_id = getattr(enrollment, "authority_state_root_id", None)
    profile_id = getattr(enrollment, "profile_id", None)
    if (not isinstance(state_id, str) or not _ID.fullmatch(state_id)
            or not isinstance(profile_id, str) or not _ID.fullmatch(profile_id)):
        raise MemoryStateDenied("memory enrollment has no valid authority state-root identity")
    data_root_id = getattr(enrollment, "data_root_id", None)
    if not isinstance(data_root_id, str) or state_id == data_root_id:
        raise MemoryStateDenied("authority state root cannot alias service-writable data root")
    selection = root_journal_roots.get(state_id)
    if (not isinstance(selection, RootJournalSelection)
            or selection.root_id != state_id):
        raise MemoryStateDenied("authority state-root ID is not in the protected root journal catalog")
    return MemoryAuthorityStateDirectory(selection, profile_id, expected_uid=expected_uid)


class MemoryAuthorityStateDirectory:
    """FD-anchored ``authority/memory/<sha256(profile_id)>`` directory."""

    def __init__(self, selection: RootJournalSelection, profile_id: str, *,
                 expected_uid: int = 0):
        if (not isinstance(selection, RootJournalSelection)
                or not isinstance(profile_id, str) or not _ID.fullmatch(profile_id)
                or type(expected_uid) is not int or expected_uid < 0):
            raise ValueError("invalid protected memory state directory binding")
        if os.geteuid() != expected_uid:
            raise MemoryStateDenied("memory authority state creation requires the protected root UID")
        self.selection_id = selection.root_id
        self.profile_id = profile_id
        self.profile_key = hashlib.sha256(profile_id.encode("utf-8")).hexdigest()
        self.expected_uid = expected_uid
        self._root_fd = self._open_root(selection.path, expected_uid)
        self._fd = -1
        try:
            authority_fd = self._open_or_create_dir(self._root_fd, "authority", expected_uid)
            try:
                memory_fd = self._open_or_create_dir(authority_fd, "memory", expected_uid)
            finally:
                os.close(authority_fd)
            try:
                self._fd = self._open_or_create_dir(memory_fd, self.profile_key, expected_uid)
            finally:
                os.close(memory_fd)
            self._verify_private_dir(self._fd, expected_uid)
            # SQLite needs a pathname (SQLite's VFS cannot use /dev/fd/N as
            # a directory on macOS). The protected root and all descendants
            # have just been opened without following links; the resulting
            # pathname is safe because its complete ancestor chain is owned
            # by the trusted journal catalog and its profile dir is 0700.
            self.root = selection.path / "authority" / "memory" / self.profile_key
        except BaseException:
            os.close(self._root_fd)
            if self._fd >= 0:
                os.close(self._fd)
            raise

    @staticmethod
    def _fd_path(fd: int) -> Path:
        if Path("/proc/self/fd").is_dir():
            return Path(f"/proc/self/fd/{fd}")
        if Path("/dev/fd").is_dir():
            return Path(f"/dev/fd/{fd}")
        raise MemoryStateDenied("platform has no descriptor-anchored filesystem path")

    @classmethod
    def _open_root(cls, path: Path, expected_uid: int) -> int:
        if not path.is_absolute():
            raise MemoryStateDenied("root journal selection must be absolute")
        fd = os.open(path.anchor, _DIRECTORY_FLAGS)
        try:
            parts = path.parts[1:]
            if not parts:
                raise MemoryStateDenied("filesystem root cannot be a memory authority journal")
            for index, part in enumerate(parts):
                if part in {"", ".", ".."}:
                    raise MemoryStateDenied("root journal selection contains an unsafe component")
                try:
                    child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
                except OSError:
                    raise MemoryStateDenied("root journal selection contains a missing or linked component") from None
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                final = index == len(parts) - 1
                if not stat.S_ISDIR(info.st_mode):
                    raise MemoryStateDenied("root journal selection contains a non-directory component")
                if final:
                    if info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o700:
                        raise MemoryStateDenied("selected root journal must be UID-owned mode 0700")
                elif (info.st_uid not in ({0, expected_uid})
                      or (stat.S_IMODE(info.st_mode) & 0o022
                          and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX))):
                    raise MemoryStateDenied("root journal ancestor is untrusted or writable")
            return fd
        except BaseException:
            os.close(fd)
            raise

    @classmethod
    def _open_or_create_dir(cls, parent_fd: int, name: str, expected_uid: int) -> int:
        if not _SAFE_FILE.fullmatch(name):
            raise MemoryStateDenied("memory state directory component is invalid")
        try:
            child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent_fd)
                os.fsync(parent_fd)
                child = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
            except OSError:
                raise MemoryStateDenied("memory authority state directory could not be created safely") from None
        except OSError:
            raise MemoryStateDenied("memory authority state directory is linked or unavailable") from None
        try:
            cls._verify_private_dir(child, expected_uid)
            return child
        except BaseException:
            os.close(child)
            raise

    @staticmethod
    def _verify_private_dir(fd: int, expected_uid: int) -> None:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise MemoryStateDenied("memory authority state directories must be UID-owned mode 0700")

    def ensure(self) -> None:
        if self._fd < 0:
            raise MemoryStateDenied("memory authority state directory is closed")
        self._verify_private_dir(self._fd, self.expected_uid)

    def path(self, relative: str) -> Path:
        self.ensure()
        if (not isinstance(relative, str) or not _SAFE_FILE.fullmatch(relative)
                or relative in {".", ".."}):
            raise MemoryStateDenied("memory state file name is invalid")
        try:
            info = os.stat(relative, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            raise MemoryStateDenied("memory state file cannot be inspected safely") from None
        else:
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise MemoryStateDenied("memory state file must be root-owned mode 0600")
        return self.root / relative

    @contextmanager
    def lock(self, filename: str) -> Iterator[None]:
        self.ensure()
        if not _SAFE_FILE.fullmatch(filename) or not filename.endswith(".lock"):
            raise MemoryStateDenied("memory state lock name is invalid")
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            fd = os.open(filename, flags, 0o600, dir_fd=self._fd)
        except OSError:
            raise MemoryStateDenied("memory state lock cannot be opened without following links") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise MemoryStateDenied("memory state lock must be root-owned mode 0600")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RuntimeError("another memory authority operation holds the profile lock") from exc
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1
        if self._root_fd >= 0:
            os.close(self._root_fd)
            self._root_fd = -1

    def __enter__(self) -> "MemoryAuthorityStateDirectory":
        self.ensure()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def memory_state_lock(directory: object, lock_path: Path):
    """Use fd-relative root locks for authority state, legacy locks otherwise."""
    if isinstance(directory, MemoryAuthorityStateDirectory):
        return directory.lock(lock_path.name)
    from hermes_installer.state import process_lock
    return process_lock(lock_path)
