"""Fixed, release-pinned model-store root observation with retained FD custody.

This module observes the reviewed root template and the already-existing
``/var/lib/hermes-installer/model-store`` directory. It never creates or changes
that directory and accepts no filesystem path from a caller.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..protected_enrollment import RootJournalSelection
from .bootstrap_enrollment import BootstrapEnrollmentPending

ROOT_ID = "installer-existing-model-store-v1"
ROOT_PATH = Path("/var/lib/hermes-installer/model-store")
TEMPLATE_ID = "installer-existing-model-store-root-template-v1"
TEMPLATE_SHA256 = "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f"
TEMPLATE_PATH = "plans/amendments/2026-10-10-existing-model-store-selection-source-v139/existing-model-store-root-template-v1.json"
TEMPLATE_SIZE = 712
TEMPLATE_ROLE = "existing-model-store-root-template"
_MAX_LEASE_SECONDS = 30.0
_CHILD = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z", re.ASCII)
_SEAL = object()


class RootFilesystemSelectionDenied(PermissionError):
    """The reviewed model-store source or its held root is unavailable/stale."""


@dataclass(frozen=True, slots=True, repr=False)
class RootOwnedFilesystemSelection:
    selection_handle: str
    root_id: str
    selection_kind: str
    template_artifact_receipt_handle: str
    template_sha256: str
    private_profile_selection_handle: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    root_device: int
    root_inode: int
    root_uid: int
    root_gid: int
    root_mode: int
    controller_binding_handle: str
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("root filesystem selections are minted by their root registry")


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedRootOwnedFilesystemSelection:
    selection: RootOwnedFilesystemSelection
    current_profile_receipt_handle: str
    current_profile_selection_sha256: str
    authority_epoch: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True, repr=False)
class RootHeldFilesystemDirectory:
    selection: RootOwnedFilesystemSelection
    directory_fd: int
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    expires_monotonic: float


class RootOwnedFilesystemSelectionRegistry:
    """Keep the fixed existing model-store root open and refresh all typed joins."""

    def __init__(self, selected_installation_binding: Any,
                 root_private_profile_selection_registry: Any,
                 root_release_module_registry: Any,
                 root_journal: RootJournalSelection,
                 authority_service: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .service import AuthorityService
        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, RootJournalSelection)
                or not isinstance(authority_service, AuthorityService)):
            raise BootstrapEnrollmentPending("model-store observer requires current root setup, journal and authority bindings")
        session = selected_installation_binding._session
        if selected_installation_binding._seal != session._seal:
            raise BootstrapEnrollmentPending("model-store installation binding is stale")
        if (getattr(root_private_profile_selection_registry, "_session", None) is not session
                or not callable(getattr(root_private_profile_selection_registry, "resolve_current", None))):
            raise BootstrapEnrollmentPending("model-store observer requires the current private-profile selection registry")
        if not callable(getattr(root_release_module_registry, "resolve_existing_model_store_template", None)):
            raise BootstrapEnrollmentPending("model-store observer requires the installed release module registry")
        if os.geteuid() != 0 or not _linux():
            raise BootstrapEnrollmentPending("model-store root observation requires the installed Linux root setup process")
        session._check_live()
        selected_journal = session._authorization.root_journal_root
        if (root_journal.root_id != selected_journal.get("root_id")
                or str(root_journal.path) != selected_journal.get("absolute_path")
                or root_journal.device != selected_journal.get("device")
                or root_journal.inode != selected_journal.get("inode")
                or root_journal.generation != selected_journal.get("generation")):
            raise BootstrapEnrollmentPending("model-store journal is not selected by this root setup session")
        _verify_secure_directory(root_journal.path, root_journal.device, root_journal.inode, 0, 0o700)
        self._binding = selected_installation_binding
        self._session = session
        self._private_profiles = root_private_profile_selection_registry
        self._release_modules = root_release_module_registry
        self.root_journal = root_journal
        self.authority = authority_service
        self._authority_instance = authority_service
        self._authority_epoch = authority_service.authority_epoch
        self._template_receipt = None
        self._root_fd: int | None = None
        self._selection: RootOwnedFilesystemSelection | None = None
        self._closed = False

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_private_profile_selection_registry: Any,
                        root_release_module_registry: Any,
                        root_journal: RootJournalSelection,
                        authority_service: Any) -> "RootOwnedFilesystemSelectionRegistry":
        return cls(selected_installation_binding, root_private_profile_selection_registry,
                   root_release_module_registry, root_journal, authority_service)

    def observe_existing_model_store(self, private_profile_selection_handle: str) -> RootOwnedFilesystemSelection:
        """Observe the reviewed template and the fixed existing root; never create it."""
        self._check_live()
        if self._selection is not None:
            raise RootFilesystemSelectionDenied("model-store root was already observed in this live registry")
        if not isinstance(private_profile_selection_handle, str) or not private_profile_selection_handle:
            raise RootFilesystemSelectionDenied("existing-model selection requires a private-profile handle")
        try:
            profile = self._private_profiles.resolve_current(
                private_profile_selection_handle, purpose="existing-model-selection")
            receipt = self._release_modules.resolve_existing_model_store_template()
            template = receipt.read_current()
        except Exception as exc:
            raise RootFilesystemSelectionDenied("current private profile or installed template receipt is unavailable") from exc
        self._verify_template_receipt(receipt, template)
        policy = _parse_template(template)
        if (policy["id"] != TEMPLATE_ID or policy["root_id"] != ROOT_ID
                or policy["absolute_path"] != str(ROOT_PATH)
                or policy["owner_uid"] != 0 or policy["directory_mode"] != 0o700
                or policy["selection_kind"] != "existing-model-store"):
            raise RootFilesystemSelectionDenied("installed template does not authorize the fixed model-store root")
        root_fd = _open_fixed_model_store_root()
        try:
            info = os.fstat(root_fd)
            current = self._session.resolve_current_setup_identity()
            principal_selector = self._session.resolve_adopted_principal_selector()
            namespace_selector = self._session.resolve_adopted_namespace_selector()
            prepared = self._session._last_receipt
            if (prepared is None or prepared.state != "prepared"
                    or profile.purpose != "existing-model-selection"
                    or profile.profile_id != "hermes-agent-native-v1"
                    or profile.privacy_classification != "private"
                    or profile.public_egress_allowed
                    or profile.additional_metered_budget_usd != 0
                    or profile.principal_selection_handle != principal_selector.selection_handle
                    or profile.namespace_selection_handle != namespace_selector.selection_handle
                    or profile.principal_id != current.principal.principal_id
                    or profile.namespace_id != current.namespace.namespace_id
                    or current.principal_selection_handle != principal_selector.selection_handle
                    or current.namespace_selection_handle != namespace_selector.selection_handle):
                raise RootFilesystemSelectionDenied("private profile and current v133 selectors do not match")
            controller_handle = getattr(profile, "controller_binding_handle", None)
            if not isinstance(controller_handle, str) or not controller_handle:
                raise RootFilesystemSelectionDenied("current private profile has no retained controller binding")
            now = time.monotonic()
            expiry = min(now + _MAX_LEASE_SECONDS, profile.expires_monotonic,
                         prepared.expires_monotonic if hasattr(prepared, "expires_monotonic") else now + _MAX_LEASE_SECONDS)
            if expiry <= now:
                raise RootFilesystemSelectionDenied("model-store selection lease expired")
            fields = dict(
                selection_handle=secrets.token_urlsafe(36), root_id=ROOT_ID,
                selection_kind="existing-model-store",
                template_artifact_receipt_handle=receipt.receipt_handle,
                template_sha256=TEMPLATE_SHA256,
                private_profile_selection_handle=private_profile_selection_handle,
                principal_selection_handle=principal_selector.selection_handle,
                namespace_selection_handle=namespace_selector.selection_handle,
                principal_id=profile.principal_id, profile_id=profile.profile_id,
                namespace_id=profile.namespace_id,
                setup_session_id=self._session._handle.session_id,
                transaction_handle=self._session._authorization.transaction_handle,
                plan_sha256=self._session._authorization.plan_digest,
                prepared_generation_id=prepared.generation_id,
                prepared_generation_digest=prepared.generation_digest,
                root_device=info.st_dev, root_inode=info.st_ino, root_uid=info.st_uid,
                root_gid=info.st_gid, root_mode=stat.S_IMODE(info.st_mode),
                controller_binding_handle=getattr(profile._selection, "controller_binding_handle", ""),
                selection_sha256="", issued_monotonic=now,
                expires_monotonic=expiry, revocation_epoch=self._authority_epoch,
                _seal=_SEAL)
            payload = {key: value for key, value in fields.items() if key not in {"selection_sha256", "_seal"}}
            fields["selection_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
            selection = RootOwnedFilesystemSelection(**fields)
            receipt.verify_current()
            self._check_live()
            self._template_receipt = receipt
            self._root_fd = root_fd
            self._selection = selection
            root_fd = -1
            return selection
        finally:
            if root_fd >= 0:
                os.close(root_fd)

    def resolve_current_root(self, selection_handle: str,
                            private_profile_selection_handle: str) -> VerifiedRootOwnedFilesystemSelection:
        selection = self._get_selection(selection_handle)
        if selection.private_profile_selection_handle != private_profile_selection_handle:
            raise RootFilesystemSelectionDenied("private-profile handle does not match model-store receipt")
        self.verify_current(selection)
        profile = self._private_profiles.resolve_current(
            private_profile_selection_handle, purpose="existing-model-selection")
        now = time.monotonic()
        expiry = min(now + _MAX_LEASE_SECONDS, selection.expires_monotonic, profile.expires_monotonic)
        if expiry <= now:
            raise RootFilesystemSelectionDenied("model-store currentness lease expired")
        return VerifiedRootOwnedFilesystemSelection(selection, profile.receipt_handle,
                                                     profile.selection_sha256,
                                                     self.authority.authority_epoch, now, expiry)

    def verify_current(self, selection: RootOwnedFilesystemSelection) -> RootOwnedFilesystemSelection:
        self._check_live()
        if type(selection) is not RootOwnedFilesystemSelection or selection._seal is not _SEAL:
            raise RootFilesystemSelectionDenied("model-store selection was not registry minted")
        if selection is not self._selection or selection.expires_monotonic <= time.monotonic():
            raise RootFilesystemSelectionDenied("model-store selection is absent, replaced or expired")
        if hashlib.sha256(_canonical(_selection_payload(selection))).hexdigest() != selection.selection_sha256:
            raise RootFilesystemSelectionDenied("model-store selection digest changed")
        if self.authority is not self._authority_instance or self.authority.authority_epoch != selection.revocation_epoch:
            raise RootFilesystemSelectionDenied("model-store authority epoch changed")
        self._session.resolve_current_setup_identity()
        self._session._verify_current_setup_controller()
        profile = self._private_profiles.resolve_current(
            selection.private_profile_selection_handle, purpose="existing-model-selection")
        if (profile.selection_sha256 == "" or profile.principal_selection_handle != selection.principal_selection_handle
                or profile.namespace_selection_handle != selection.namespace_selection_handle
                or profile.principal_id != selection.principal_id or profile.profile_id != selection.profile_id
                or profile.namespace_id != selection.namespace_id):
            raise RootFilesystemSelectionDenied("model-store private-profile selector binding changed")
        self._verify_template_receipt(self._template_receipt, self._template_receipt.read_current())
        self._template_receipt.verify_current()
        if self._root_fd is None:
            raise RootFilesystemSelectionDenied("model-store root descriptor is closed")
        _verify_fd(self._root_fd, selection.root_device, selection.root_inode,
                   selection.root_uid, selection.root_gid, selection.root_mode)
        path_fd = _open_fixed_model_store_root()
        try:
            _verify_fd(path_fd, selection.root_device, selection.root_inode,
                       selection.root_uid, selection.root_gid, selection.root_mode)
        finally:
            os.close(path_fd)
        self._check_live()
        return selection

    def open_selected_root(self, selection_handle: str) -> RootHeldFilesystemDirectory:
        self._get_selection(selection_handle)
        selection = self.verify_current(self._selection)
        assert self._root_fd is not None
        fd = os.dup(self._root_fd)
        os.set_inheritable(fd, False)
        info = os.fstat(fd)
        return RootHeldFilesystemDirectory(selection, fd, info.st_dev, info.st_ino,
                                           info.st_uid, info.st_gid,
                                           stat.S_IMODE(info.st_mode), selection.expires_monotonic)

    def list_existing_children(self, selection_handle: str) -> tuple[str, ...]:
        held = self.open_selected_root(selection_handle)
        names: list[str] = []
        try:
            entries = os.listdir(held.directory_fd)
            if len(entries) > 256:
                raise RootFilesystemSelectionDenied("model-store child enumeration exceeds the reviewed 256 entry bound")
            for name in entries:
                if name in {".", ".."} or not _CHILD.fullmatch(name):
                    continue
                try:
                    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=held.directory_fd)
                except OSError:
                    continue
                try:
                    info = os.fstat(fd)
                    if stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not (stat.S_IMODE(info.st_mode) & 0o022):
                        names.append(name)
                finally:
                    os.close(fd)
                if len(names) > 256:
                    raise RootFilesystemSelectionDenied("model-store child enumeration exceeds the reviewed 256 entry bound")
            self.verify_current(held.selection)
            return tuple(sorted(names))
        finally:
            os.close(held.directory_fd)

    def open_child_directory(self, selection_handle: str, basename: str) -> RootHeldFilesystemDirectory:
        if not isinstance(basename, str) or not _CHILD.fullmatch(basename):
            raise RootFilesystemSelectionDenied("model-store selection must be one safe direct-child basename")
        selection = self._get_selection(selection_handle)
        self.verify_current(selection)
        assert self._root_fd is not None
        fd = os.open(basename, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self._root_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RootFilesystemSelectionDenied("selected model child is not root-owned and protected")
            self.verify_current(selection)
            os.set_inheritable(fd, False)
            result = RootHeldFilesystemDirectory(selection, fd, info.st_dev, info.st_ino,
                                                 info.st_uid, info.st_gid,
                                                 stat.S_IMODE(info.st_mode), selection.expires_monotonic)
            fd = -1
            return result
        finally:
            if fd >= 0:
                os.close(fd)

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._root_fd is not None:
                os.close(self._root_fd)
                self._root_fd = None
            self._selection = None
            self._template_receipt = None

    def _get_selection(self, handle: str) -> RootOwnedFilesystemSelection:
        self._check_live()
        selection = self._selection
        if not isinstance(handle, str) or selection is None or not secrets.compare_digest(selection.selection_handle, handle):
            raise RootFilesystemSelectionDenied("model-store selection handle is unknown")
        return selection

    def _check_live(self) -> None:
        if self._closed:
            raise RootFilesystemSelectionDenied("model-store registry is closed")
        try:
            self._session._check_live()
            if self.authority.authority_epoch != self._authority_epoch:
                raise ValueError("authority epoch changed")
        except Exception:
            raise RootFilesystemSelectionDenied("root setup or authority service is no longer current") from None

    def _verify_template_receipt(self, receipt: Any, data: bytes) -> None:
        from .bootstrap_runtime_factory import RootExistingModelStoreTemplateReceipt
        if (type(receipt) is not RootExistingModelStoreTemplateReceipt
                or receipt.artifact_id != TEMPLATE_ID or receipt.relative_path != TEMPLATE_PATH
                or receipt.sha256 != TEMPLATE_SHA256 or receipt.size_bytes != TEMPLATE_SIZE
                or receipt.role != TEMPLATE_ROLE or not isinstance(data, bytes)
                or len(data) != TEMPLATE_SIZE or hashlib.sha256(data).hexdigest() != TEMPLATE_SHA256):
            raise RootFilesystemSelectionDenied("template is not the exact held installed-release receipt")


def _parse_template(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except Exception as exc:
        raise RootFilesystemSelectionDenied("installed model-store template is not valid UTF-8 JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "absolute_path", "additional_metered_budget_usd", "directory_mode", "id", "license_artifact_id",
        "model_directory_choice", "owner_uid", "public_egress_allowed", "root_id", "schema",
        "selection_kind", "source_manifest_artifact_id", "source_model_id", "source_revision",
        "supporting_source_artifact_ids",
    } or value.get("schema") != 1:
        raise RootFilesystemSelectionDenied("installed model-store template has unexpected fields")
    return value


def _selection_payload(selection: RootOwnedFilesystemSelection) -> dict[str, Any]:
    return {name: getattr(selection, name) for name in selection.__dataclass_fields__
            if name not in {"selection_sha256", "_seal"}}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _open_fixed_model_store_root() -> int:
    if os.geteuid() != 0 or not _linux():
        raise RootFilesystemSelectionDenied("fixed model-store root is observable only in the installed Linux root process")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for index, part in enumerate(ROOT_PATH.parts[1:]):
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                raise RootFilesystemSelectionDenied("fixed model-store path component is not a root-owned directory")
            final = index == len(ROOT_PATH.parts[1:]) - 1
            if final:
                if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                    raise RootFilesystemSelectionDenied("fixed model-store root must be root:root mode 0700")
            elif stat.S_IMODE(info.st_mode) & 0o022:
                raise RootFilesystemSelectionDenied("fixed model-store ancestor is group/world writable")
        os.set_inheritable(fd, False)
        result, fd = fd, -1
        return result
    except OSError as exc:
        raise RootFilesystemSelectionDenied("fixed model-store root is absent or contains a symlink") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _verify_fd(fd: int, device: int, inode: int, uid: int, gid: int, mode: int) -> None:
    try:
        info = os.fstat(fd)
    except OSError:
        raise RootFilesystemSelectionDenied("held model-store descriptor is closed") from None
    if (not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
            != (device, inode, uid, gid, mode)
            or uid != 0 or gid != 0 or mode != 0o700):
        raise RootFilesystemSelectionDenied("model-store held directory identity or custody changed")


def _verify_secure_directory(path: Path, device: int, inode: int, uid: int, mode: int) -> None:
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
            or (info.st_dev, info.st_ino) != (device, inode)
            or stat.S_IMODE(info.st_mode) != mode):
        raise RootFilesystemSelectionDenied("root journal identity or custody changed")


def _linux() -> bool:
    return os.name == "posix" and Path("/proc/self").exists()
