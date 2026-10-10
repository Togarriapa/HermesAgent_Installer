"""Root-owned, explicit model-store directory selection and FD custody.

The user selects an already-existing root-owned directory in the foreground
root setup UI. This module records that choice and retains the opened directory
descriptor; it never creates, copies, or changes ownership of model data.
"""
from __future__ import annotations

import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from ..protected_enrollment import RootJournalSelection
from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    _atomic_root_file,
    _canonical,
    _ensure_root_directory,
    _read_json_if_owned,
)


_SEAL = object()
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_MAX_LEASE_SECONDS = 30.0


class RootFilesystemSelectionDenied(PermissionError):
    """A selected model-store root is absent, stale, or outside root custody."""


@dataclass(frozen=True, slots=True, repr=False)
class RootOwnedFilesystemSelection:
    """Opaque journaled receipt for one foreground root-selected store."""

    selection_handle: str
    model_store_root_id: str
    model_store_root_receipt_handle: str
    choice_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    principal_id: str
    profile_id: str
    namespace_id: str
    private_profile_selection_handle: str
    controller_binding_handle: str
    source_choice_handle: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    issued_monotonic: float
    expires_monotonic: float
    journal_root_id: str
    journal_root_device: int
    journal_root_inode: int
    journal_generation: str
    journal_generation_digest: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("root filesystem selections are minted by their root registry")


@dataclass(frozen=True, slots=True, repr=False)
class RootHeldFilesystemDirectory:
    """Caller-owned duplicate of the selected directory FD; close it promptly."""

    selection: RootOwnedFilesystemSelection
    directory_fd: int
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    expires_monotonic: float


class RootOwnedFilesystemSelectionRegistry:
    """Consume a sealed root TTY path choice and keep its directory FD private."""

    def __init__(self, selected_installation_binding: Any,
                 root_journal: RootJournalSelection):
        # Import lazily because bootstrap_runtime_factory re-exports this API.
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, RootJournalSelection)):
            raise BootstrapEnrollmentPending("model-store selection requires the live root installation and journal bindings")
        session = selected_installation_binding._session
        if (selected_installation_binding._seal is not session._seal
                or not callable(getattr(session, "_check_live", None))):
            raise BootstrapEnrollmentPending("model-store selection binding is stale")
        session._check_live()
        self._binding = selected_installation_binding
        self._session = session
        self.root_journal = root_journal
        self.expected_uid = os.geteuid()
        if self.expected_uid != 0:
            raise BootstrapEnrollmentPending("root-owned model-store selection is available only in the root setup process")
        selected_journal = session._authorization.root_journal_root
        if (root_journal.root_id != selected_journal.get("root_id")
                or str(root_journal.path) != selected_journal.get("absolute_path")
                or root_journal.device != selected_journal.get("device")
                or root_journal.inode != selected_journal.get("inode")
                or root_journal.generation != selected_journal.get("generation")):
            raise BootstrapEnrollmentPending("model-store journal is not the journal selected by this root setup session")
        self._verify_journal()
        self._receipt_root = root_journal.path / "model-store-roots"
        self._selections: dict[str, tuple[RootOwnedFilesystemSelection, int, Any]] = {}
        self._closed = False

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_journal: RootJournalSelection) -> "RootOwnedFilesystemSelectionRegistry":
        """Bind the model-root registry to the live root setup and journal."""
        return cls(selected_installation_binding, root_journal)

    def observe_model_store_root(self, root_choice: Any) -> RootOwnedFilesystemSelection:
        """Consume the one-use foreground TTY choice and retain its real root FD."""
        self._check_live()
        from .bootstrap_runtime_factory import RootExistingModelStoreRootChoice
        if (type(root_choice) is not RootExistingModelStoreRootChoice
                or not callable(getattr(root_choice, "verify_current", None))):
            raise RootFilesystemSelectionDenied("model-store root requires the typed root TTY choice")
        if root_choice.verify_current() is not root_choice:
            raise RootFilesystemSelectionDenied("model-store root TTY choice is stale")
        values = self._choice_values(root_choice)
        root_path = Path(values["selected_root_path"])
        root_fd = _open_root_owned_directory(root_path, expected_uid=self.expected_uid)
        try:
            info = os.fstat(root_fd)
            self._verify_choice_generation(root_choice, values)
            now = time.monotonic()
            if (values["issued_monotonic"] > now
                    or values["expires_monotonic"] <= now
                    or values["expires_monotonic"] - values["issued_monotonic"] > 300.0):
                raise RootFilesystemSelectionDenied("model-store root TTY choice has an invalid lease")
            expiry = min(float(values["expires_monotonic"]), now + _MAX_LEASE_SECONDS)
            if expiry <= now:
                raise RootFilesystemSelectionDenied("model-store root choice lease has expired")
            store_id = values["model_store_root_id"]
            if not _ID.fullmatch(store_id):
                raise RootFilesystemSelectionDenied("model-store root identifier is malformed")
            _ensure_root_directory(self._receipt_root)
            journal_info = self.root_journal.path.stat(follow_symlinks=False)
            if (journal_info.st_dev, journal_info.st_ino) != (
                    self.root_journal.device, self.root_journal.inode):
                raise RootFilesystemSelectionDenied("selected root journal identity changed")
            handle = secrets.token_urlsafe(32)
            receipt_handle = secrets.token_urlsafe(32)
            selection = RootOwnedFilesystemSelection(
                selection_handle=handle,
                model_store_root_id=store_id,
                model_store_root_receipt_handle=receipt_handle,
                choice_handle=values["choice_handle"],
                setup_session_id=values["setup_session_id"],
                transaction_handle=values["transaction_handle"],
                plan_sha256=values["plan_sha256"],
                prepared_generation_id=values["prepared_generation_id"],
                prepared_generation_digest=values["prepared_generation_digest"],
                principal_selection_handle=values["principal_selection_handle"],
                namespace_selection_handle=values["namespace_selection_handle"],
                principal_binding_sha256=values["principal_binding_sha256"],
                namespace_binding_sha256=values["namespace_binding_sha256"],
                principal_id=values["principal_id"],
                profile_id=values["profile_id"],
                namespace_id=values["namespace_id"],
                private_profile_selection_handle=values["private_profile_selection_handle"],
                controller_binding_handle=values["controller_binding_handle"],
                source_choice_handle=receipt_handle,
                device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                issued_monotonic=now, expires_monotonic=expiry,
                journal_root_id=self.root_journal.root_id,
                journal_root_device=self.root_journal.device,
                journal_root_inode=self.root_journal.inode,
                journal_generation=self.root_journal.generation,
                journal_generation_digest=self.root_journal.service_generation_digest,
                _seal=_SEAL,
            )
            record = _selection_record(selection, root_path)
            _atomic_root_file(self._receipt_root / f"{receipt_handle}.json", _canonical(record), 0o600)
            os.set_inheritable(root_fd, False)
            self._selections[handle] = (selection, root_fd, root_choice)
            return selection
        except Exception:
            os.close(root_fd)
            raise

    def resolve_selection(self, receipt_handle: str) -> RootOwnedFilesystemSelection:
        self._check_live()
        if not isinstance(receipt_handle, str) or not _HANDLE.fullmatch(receipt_handle):
            raise RootFilesystemSelectionDenied("model-store root receipt handle is malformed")
        matches = [(item, fd, choice) for item, fd, choice in self._selections.values()
                   if secrets.compare_digest(item.model_store_root_receipt_handle, receipt_handle)]
        if len(matches) != 1:
            raise RootFilesystemSelectionDenied("model-store root receipt is absent from this live registry")
        selection, _fd, _choice = matches[0]
        return self.verify_current(selection)

    def verify_current(self, selection: RootOwnedFilesystemSelection) -> RootOwnedFilesystemSelection:
        self._check_live()
        if type(selection) is not RootOwnedFilesystemSelection or selection._seal is not _SEAL:
            raise RootFilesystemSelectionDenied("model-store root selection is not registry minted")
        retained = self._selections.get(selection.selection_handle)
        if retained is None or retained[0] is not selection:
            raise RootFilesystemSelectionDenied("model-store root selection is not retained by this registry")
        current, root_fd, root_choice = retained
        if (current is not selection or selection.expires_monotonic <= time.monotonic()
                or root_choice.verify_current() is not root_choice):
            raise RootFilesystemSelectionDenied("model-store root selection or TTY choice has expired")
        self._verify_journal()
        _verify_directory_fd(root_fd, selection.device, selection.inode,
                             selection.uid, selection.gid, selection.mode)
        selected_path = Path(root_choice.selected_root_path)
        path_fd = _open_root_owned_directory(selected_path, expected_uid=self.expected_uid)
        try:
            _verify_directory_fd(path_fd, selection.device, selection.inode,
                                 selection.uid, selection.gid, selection.mode)
        finally:
            os.close(path_fd)
        try:
            journal_record = _read_json_if_owned(
                self._receipt_root / f"{selection.model_store_root_receipt_handle}.json")
        except Exception:
            raise RootFilesystemSelectionDenied("model-store root receipt is absent or unreadable") from None
        if journal_record != _selection_record(selection, selected_path):
            raise RootFilesystemSelectionDenied("model-store root journal receipt changed")
        self._verify_choice_generation(root_choice, self._choice_values(root_choice))
        return selection

    def open_selected_directory(self, receipt_handle: str) -> RootHeldFilesystemDirectory:
        selection = self.resolve_selection(receipt_handle)
        _item, root_fd, _choice = self._selections[selection.selection_handle]
        self.verify_current(selection)
        duplicate = os.dup(root_fd)
        os.set_inheritable(duplicate, False)
        info = os.fstat(duplicate)
        return RootHeldFilesystemDirectory(
            selection, duplicate, info.st_dev, info.st_ino, info.st_uid,
            info.st_gid, stat.S_IMODE(info.st_mode), selection.expires_monotonic)

    def open_selected_subdirectory(self, receipt_handle: str,
                                   relative_path: str) -> RootHeldFilesystemDirectory:
        selection = self.resolve_selection(receipt_handle)
        self.verify_current(selection)
        if (not isinstance(relative_path, str) or not relative_path
                or "\\" in relative_path or relative_path.startswith("/")):
            raise RootFilesystemSelectionDenied("model subdirectory must be a nonempty relative path")
        path = PurePosixPath(relative_path)
        if any(part in {"", ".", ".."} for part in path.parts):
            raise RootFilesystemSelectionDenied("model subdirectory path is not canonical")
        _item, root_fd, _choice = self._selections[selection.selection_handle]
        fd = os.dup(root_fd)
        try:
            for part in path.parts:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                dir_fd=fd)
                os.close(fd)
                fd = child
                info = os.fstat(fd)
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise RootFilesystemSelectionDenied("model subdirectory is not root-owned and protected")
            info = os.fstat(fd)
            self.verify_current(selection)
            os.set_inheritable(fd, False)
            result = RootHeldFilesystemDirectory(
                selection, fd, info.st_dev, info.st_ino, info.st_uid,
                info.st_gid, stat.S_IMODE(info.st_mode), selection.expires_monotonic)
            fd = -1
            return result
        finally:
            if fd >= 0:
                os.close(fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for _selection, fd, _choice in self._selections.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self._selections.clear()

    def _check_live(self) -> None:
        if self._closed:
            raise RootFilesystemSelectionDenied("model-store registry is closed")
        try:
            self._session._check_live()
        except Exception:
            raise RootFilesystemSelectionDenied("root setup session is no longer current") from None

    def _verify_journal(self) -> None:
        try:
            info = self.root_journal.path.stat(follow_symlinks=False)
        except OSError:
            raise RootFilesystemSelectionDenied("selected root journal is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.root_journal.device, self.root_journal.inode)):
            raise RootFilesystemSelectionDenied("selected root journal custody changed")

    @staticmethod
    def _choice_values(choice: Any) -> dict[str, Any]:
        fields = (
            "choice_handle", "setup_session_id", "transaction_handle", "plan_sha256",
            "prepared_generation_id", "prepared_generation_digest",
            "principal_selection_handle", "namespace_selection_handle",
            "principal_binding_sha256", "namespace_binding_sha256", "principal_id",
            "profile_id", "namespace_id", "private_profile_selection_handle",
            "controller_binding_handle", "model_store_root_id", "selected_root_path",
            "issued_monotonic", "expires_monotonic",
        )
        values = {name: getattr(choice, name, None) for name in fields}
        string_fields = set(fields) - {"issued_monotonic", "expires_monotonic", "selected_root_path"}
        if (any(not isinstance(values[name], str) or not values[name] for name in string_fields)
                or not isinstance(values["selected_root_path"], (Path, str))
                or not Path(values["selected_root_path"]).is_absolute()
                or type(values["issued_monotonic"]) not in {float, int}
                or type(values["expires_monotonic"]) not in {float, int}
                or not _SHA.fullmatch(values["plan_sha256"])
                or not _SHA.fullmatch(values["prepared_generation_digest"])
                or not _SHA.fullmatch(values["principal_binding_sha256"])
                or not _SHA.fullmatch(values["namespace_binding_sha256"])):
            raise RootFilesystemSelectionDenied("root TTY model-store choice fields are incomplete")
        handle_fields = ("choice_handle", "principal_selection_handle",
                         "namespace_selection_handle", "private_profile_selection_handle",
                         "controller_binding_handle")
        identifier_fields = ("setup_session_id", "transaction_handle",
                             "prepared_generation_id", "principal_id", "profile_id",
                             "namespace_id", "model_store_root_id")
        if (any(not _ID.fullmatch(values[name]) for name in handle_fields)
                or any(not _ID.fullmatch(values[name]) for name in identifier_fields)):
            raise RootFilesystemSelectionDenied("root TTY model-store choice identifiers are malformed")
        values["selected_root_path"] = Path(values["selected_root_path"])
        return values

    def _verify_choice_generation(self, choice: Any, values: dict[str, Any]) -> None:
        authorization = self._session._authorization
        receipt = self._session._last_receipt
        if (choice.verify_current() is not choice or receipt is None
                or receipt.state != "prepared"
                or values["setup_session_id"] != authorization.setup_session_id
                or values["transaction_handle"] != authorization.transaction_handle
                or values["plan_sha256"] != authorization.plan_digest
                or values["prepared_generation_id"] != receipt.generation_id
                or values["prepared_generation_digest"] != receipt.generation_digest):
            raise RootFilesystemSelectionDenied("model-store choice does not match current prepared setup and selectors")


def _open_root_owned_directory(path: Path, *, expected_uid: int) -> int:
    if (not isinstance(path, Path) or not path.is_absolute() or path == Path("/")
            or ".." in path.parts):
        raise RootFilesystemSelectionDenied("model-store root must be an explicit non-root absolute path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            is_leaf = index == len(parts) - 1
            if (not stat.S_ISDIR(info.st_mode)
                    or (info.st_uid != expected_uid if is_leaf
                        else info.st_uid not in {0, expected_uid})):
                raise RootFilesystemSelectionDenied("model-store root path traverses a directory outside trusted ownership")
            writable_ancestor = (index < len(parts) - 1
                                 and stat.S_IMODE(info.st_mode) & 0o022
                                 and info.st_mode & stat.S_ISVTX)
            if stat.S_IMODE(info.st_mode) & 0o022 and not writable_ancestor:
                raise RootFilesystemSelectionDenied("model-store root path traverses a group/world-writable directory")
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise RootFilesystemSelectionDenied("model-store root is not a protected root-owned directory")
        os.set_inheritable(fd, False)
        result, fd = fd, -1
        return result
    except OSError as exc:
        raise RootFilesystemSelectionDenied("model-store root could not be opened without following symlinks") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _verify_directory_fd(fd: int, device: int, inode: int, uid: int, gid: int, mode: int) -> None:
    try:
        info = os.fstat(fd)
    except OSError:
        raise RootFilesystemSelectionDenied("retained model-store directory descriptor is closed") from None
    if (not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            != (device, inode, uid, gid, mode)
            or info.st_uid != 0 or mode & 0o022):
        raise RootFilesystemSelectionDenied("model-store directory identity or ownership changed")


def _selection_record(selection: RootOwnedFilesystemSelection, path: Path) -> dict[str, Any]:
    return {
        "schema": 1,
        "selection_handle": selection.selection_handle,
        "model_store_root_id": selection.model_store_root_id,
        "model_store_root_receipt_handle": selection.model_store_root_receipt_handle,
        "choice_handle": selection.choice_handle,
        "setup_session_id": selection.setup_session_id,
        "transaction_handle": selection.transaction_handle,
        "plan_sha256": selection.plan_sha256,
        "prepared_generation_id": selection.prepared_generation_id,
        "prepared_generation_digest": selection.prepared_generation_digest,
        "principal_selection_handle": selection.principal_selection_handle,
        "namespace_selection_handle": selection.namespace_selection_handle,
        "principal_binding_sha256": selection.principal_binding_sha256,
        "namespace_binding_sha256": selection.namespace_binding_sha256,
        "principal_id": selection.principal_id,
        "profile_id": selection.profile_id,
        "namespace_id": selection.namespace_id,
        "private_profile_selection_handle": selection.private_profile_selection_handle,
        "controller_binding_handle": selection.controller_binding_handle,
        "source_choice_handle": selection.source_choice_handle,
        "absolute_root_path": str(path),
        "device": selection.device,
        "inode": selection.inode,
        "uid": selection.uid,
        "gid": selection.gid,
        "mode": selection.mode,
        "issued_monotonic": selection.issued_monotonic,
        "expires_monotonic": selection.expires_monotonic,
        "journal_root_id": selection.journal_root_id,
        "journal_root_device": selection.journal_root_device,
        "journal_root_inode": selection.journal_root_inode,
        "journal_generation": selection.journal_generation,
        "journal_generation_digest": selection.journal_generation_digest,
    }
