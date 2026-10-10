"""Stable root-owned materialization of selected native worker output members.

The CAS is the signed output source, not filesystem custody.  This registry
validates reserved CAS receipts, extracts the closed member set into a private
root-owned tree, and issues held member descriptors with actual stat identity.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import tarfile
import time
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending, VerifiedCommittedEnrollment
from .native_worker_recipes import (
    NativeWorkerRecipeUnavailable, RootPreparedNativeWorkerRecipe,
    RootSetupNativeWorkerRecipeRegistry,
)

_ROLE_ORDER = (
    "native-compiled-closure", "native-entrypoint-manifest",
    "native-action-resolver", "native-boundary-overlay", "native-candidate-index",
)
_MAX_MEMBERS = 8192
_MAX_BYTES = 512 * 1024 * 1024
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)


class NativeWorkerRuntimeMaterializationUnavailable(BootstrapEnrollmentPending):
    """Exact root-owned selected output members are not current or materializable."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _hash_fd(fd: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(fd, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return (bool(value) and not value.startswith("/") and "\\" not in value
            and "\x00" not in value and all(part not in {"", ".", ".."} for part in path.parts)
            and path.as_posix() == value)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeWorkerRuntimeMember:
    artifact_id: str
    receipt_handle: str
    relative_path: str
    kind: str
    sha256: str
    size_bytes: int
    mode: int
    owner_uid: int
    owner_gid: int
    device: int
    inode: int
    link_target: str | None
    output_role: str | None
    _fd: int = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedNativeWorkerRuntimeMember(<held>)"

    def wire_projection(self) -> Mapping[str, Any]:
        return MappingProxyType({
            "artifact_id": self.artifact_id,
            "receipt_handle": self.receipt_handle,
            "relative_path": self.relative_path,
            "kind": self.kind,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "mode": self.mode,
            "owner_uid": self.owner_uid,
            "owner_gid": self.owner_gid,
            "device": self.device,
            "inode": self.inode,
            "link_target": self.link_target,
            "output_role": self.output_role,
        })


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeWorkerRuntimeMaterialization:
    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    worker_recipe_receipt_handle: str
    worker_recipe_sha256: str
    source_choice_selection_handle: str
    source_choice_signed_record_sha256: str
    profile_id: str
    profile_generation: str
    pm_runtime_receipt_handle: str
    committed_venv_identity: Mapping[str, Any]
    pm_base_closure_sha256: str
    pm_executable_relative_path: str
    pm_executable_member_sha256: str
    pm_runtime_member_records: tuple[Mapping[str, Any], ...]
    native_output_member_records: tuple[Mapping[str, Any], ...]
    native_output_receipt_handles: tuple[str, ...]
    runtime_root_device: int
    runtime_root_inode: int
    receipt_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)
    _recipe: RootPreparedNativeWorkerRecipe = field(repr=False, compare=False)
    _runnable_closure: Any = field(repr=False, compare=False)
    _root_fd: int = field(repr=False, compare=False)
    _parent_fd: int = field(repr=False, compare=False)
    _member_fds: tuple[int, ...] = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedNativeWorkerRuntimeMaterialization(<root-held>)"


class RootPreparedNativeWorkerRuntimeMaterializationRegistry:
    """Issue and revalidate concrete filesystem members for one worker recipe."""

    def __init__(self, binding: Any, recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                 runtime_receipts: Any, output_receipts: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .pm_runtime import RootPMRuntimeReceiptRegistry
        from .native_output_receipts import RootMaterializationReceiptRegistry
        if (type(binding) is not RootSelectedInstallationBinding
                or type(recipe_registry) is not RootSetupNativeWorkerRecipeRegistry
                or recipe_registry.binding is not binding
                or type(runtime_receipts) is not RootPMRuntimeReceiptRegistry
                or runtime_receipts is not binding._session._pm_runtime_registry
                or type(output_receipts) is not RootMaterializationReceiptRegistry
                or output_receipts is not recipe_registry.native_outputs):
            raise ValueError("runtime materializer requires the exact retained root setup receipt graph")
        self.binding = binding
        self.recipe_registry = recipe_registry
        self.runtime_receipts = runtime_receipts
        self.output_receipts = output_receipts
        self._issuer = object()
        self._issued: dict[str, RootPreparedNativeWorkerRuntimeMaterialization] = {}
        self._by_selection: dict[str, RootPreparedNativeWorkerRuntimeMaterialization] = {}
        self._active_bindings: dict[str, str] = {}

    @classmethod
    def from_root_setup(cls, binding: Any,
                        recipe_registry: RootSetupNativeWorkerRecipeRegistry,
                        runtime_receipts: Any,
                        output_receipts: Any) -> "RootPreparedNativeWorkerRuntimeMaterializationRegistry":
        return cls(binding, recipe_registry, runtime_receipts, output_receipts)

    def materialize_selected(self, recipe: RootPreparedNativeWorkerRecipe,
                             runnable_closure: Any,
                             native_policy_selection: Any) -> RootPreparedNativeWorkerRuntimeMaterialization:
        session = self.binding._session
        session._check_live()
        recipe = self.recipe_registry.verify_current(recipe)
        closure = self.recipe_registry.runnable_roles.verify_current(runnable_closure)
        selection = self.binding.resolve_current_native_policy_selection(
            native_policy_selection.selection_handle)
        if (selection is not native_policy_selection
                or selection.selection_handle != getattr(self.recipe_registry, "_current_selection_handle", None)
                or closure.setup_session_id != recipe.setup_session_id
                or closure.transaction_handle != recipe.transaction_handle
                or closure.prepared_generation_id != recipe.prepared_generation_id
                or recipe.service_profile_id != selection.service_profile_id
                or recipe.profile_generation != selection.service_generation):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "selected recipe, source choice, and reserved runtime closure do not join")
        existing = self._by_selection.get(selection.selection_handle)
        if existing is not None:
            return self.verify_current(existing)
        from .bootstrap_runtime_factory import RootSelectedRunnableRoleClosure
        if type(closure) is not RootSelectedRunnableRoleClosure:
            raise NativeWorkerRuntimeMaterializationUnavailable("runnable output closure is not root issued")
        prepared = session._resolve_current_prepared_enrollment()
        if (prepared.generation_id != recipe.prepared_generation_id
                or prepared.generation_digest != recipe.prepared_generation_digest):
            raise NativeWorkerRuntimeMaterializationUnavailable("prepared generation changed before materialization")
        pm = self.runtime_receipts.resolve_runtime_projection(
            recipe.pm_runtime_receipt_handle, recipe.transaction_handle,
            recipe.prepared_generation_id)
        root_fd = -1
        parent_fd = -1
        member_fds: list[int] = []
        output_root_fd = -1
        created_leaf: str | None = None
        records: list[Mapping[str, Any]] = []
        receipt_sha: str | None = None
        try:
            committed_venv_identity = self._committed_venv_identity(pm)
            self._validate_role_closure(closure, recipe)
            parent_fd = self._open_or_create_runtime_parent()
            receipt_handle = secrets.token_urlsafe(36)
            created_leaf = receipt_handle
            os.mkdir(created_leaf, 0o700, dir_fd=parent_fd)
            os.chown(created_leaf, 0, 0, dir_fd=parent_fd, follow_symlinks=False)
            os.chmod(created_leaf, 0o700, dir_fd=parent_fd, follow_symlinks=False)
            output_root_fd = os.open(created_leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                     | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            root_info = os.fstat(output_root_fd)
            if root_info.st_uid != 0 or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700:
                raise NativeWorkerRuntimeMaterializationUnavailable("new native worker output root is not root private")
            pm_records = self._project_pm_members(pm, member_fds)
            self._materialize_native_outputs(output_root_fd, closure, member_fds, records)
            if len(records) > _MAX_MEMBERS or len(pm_records) > _MAX_MEMBERS:
                raise NativeWorkerRuntimeMaterializationUnavailable("selected runtime member closure exceeds its bound")
            now = time.monotonic()
            expires = min(prepared.expires_monotonic, recipe.expires_monotonic,
                          closure.expires_monotonic, now + 300.0)
            if expires <= now:
                raise NativeWorkerRuntimeMaterializationUnavailable("prepared runtime materialization lease expired")
            body = {
                "schema": 1, "receipt_handle": receipt_handle,
                "setup_session_id": recipe.setup_session_id,
                "transaction_handle": recipe.transaction_handle,
                "prepared_generation_id": recipe.prepared_generation_id,
                "prepared_generation_digest": recipe.prepared_generation_digest,
                "worker_recipe_receipt_handle": recipe.receipt_handle,
                "worker_recipe_sha256": recipe.complete_recipe_sha256,
                "source_choice_selection_handle": selection.selection_handle,
                "source_choice_signed_record_sha256": selection.choice_payload_sha256,
                "profile_id": recipe.service_profile_id,
                "profile_generation": recipe.profile_generation,
                "pm_runtime_receipt_handle": pm.selection.receipt_handle,
                "committed_venv_identity": dict(committed_venv_identity),
                "pm_base_closure_sha256": pm.base_closure_sha256,
                "pm_executable_relative_path": pm.executable_relative_path,
                "pm_executable_member_sha256": pm.executable_member.sha256,
                "pm_runtime_member_records": [dict(row) for row in pm_records],
                "native_output_member_records": [dict(row) for row in records],
                "native_output_receipt_handles": [row.receipt_handle for row in sorted(
                    closure.role_rows, key=lambda row: row.role)
                    if row.receipt_kind == "native-output-cas"],
                "runtime_root_device": root_info.st_dev,
                "runtime_root_inode": root_info.st_ino,
            }
            receipt_sha = _sha(body)
            self._write_manifest(output_root_fd, body, receipt_sha)
            receipt = RootPreparedNativeWorkerRuntimeMaterialization(
                schema=1, receipt_handle=receipt_handle,
                setup_session_id=recipe.setup_session_id,
                transaction_handle=recipe.transaction_handle,
                prepared_generation_id=recipe.prepared_generation_id,
                prepared_generation_digest=recipe.prepared_generation_digest,
                worker_recipe_receipt_handle=recipe.receipt_handle,
                worker_recipe_sha256=recipe.complete_recipe_sha256,
                source_choice_selection_handle=selection.selection_handle,
                source_choice_signed_record_sha256=selection.choice_payload_sha256,
                profile_id=recipe.service_profile_id,
                profile_generation=recipe.profile_generation,
                pm_runtime_receipt_handle=pm.selection.receipt_handle,
                committed_venv_identity=committed_venv_identity,
                pm_base_closure_sha256=pm.base_closure_sha256,
                pm_executable_relative_path=pm.executable_relative_path,
                pm_executable_member_sha256=pm.executable_member.sha256,
                pm_runtime_member_records=tuple(pm_records),
                native_output_member_records=tuple(records),
                native_output_receipt_handles=tuple(body["native_output_receipt_handles"]),
                runtime_root_device=root_info.st_dev, runtime_root_inode=root_info.st_ino,
                receipt_sha256=receipt_sha, issued_monotonic=now,
                expires_monotonic=expires, _issuer=self._issuer, _recipe=recipe,
                _runnable_closure=closure, _root_fd=output_root_fd,
                _parent_fd=os.dup(parent_fd), _member_fds=tuple(member_fds),
            )
            output_root_fd = -1
            member_fds = []
            self._issued[receipt_handle] = receipt
            self._by_selection[selection.selection_handle] = receipt
            os.close(parent_fd)
            parent_fd = -1
            return receipt
        except BaseException:
            expected = os.fstat(output_root_fd) if output_root_fd >= 0 else None
            if output_root_fd >= 0:
                os.close(output_root_fd)
            for descriptor in member_fds:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            if created_leaf is not None:
                self._remove_leaf_if_owned(created_leaf, expected, records, parent_fd, receipt_sha)
            raise
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)
            pm.close()

    def verify_current(self, receipt: RootPreparedNativeWorkerRuntimeMaterialization
                       ) -> RootPreparedNativeWorkerRuntimeMaterialization:
        if (type(receipt) is not RootPreparedNativeWorkerRuntimeMaterialization
                or receipt._issuer is not self._issuer
                or self._issued.get(receipt.receipt_handle) is not receipt
                or receipt.expires_monotonic <= time.monotonic()):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "prepared runtime materialization receipt is foreign, stale, or expired")
        session = self.binding._session
        prepared = session._resolve_current_prepared_enrollment()
        recipe = self.recipe_registry.verify_current(receipt._recipe)
        self.recipe_registry.runnable_roles.verify_current(receipt._runnable_closure)
        if (recipe.receipt_handle != receipt.worker_recipe_receipt_handle
                or prepared.generation_id != receipt.prepared_generation_id
                or prepared.generation_digest != receipt.prepared_generation_digest):
            raise NativeWorkerRuntimeMaterializationUnavailable("prepared runtime source or generation changed")
        self._verify_held_root_and_members(receipt)
        fresh_parent = self._open_or_create_runtime_parent(create=False)
        try:
            if (os.fstat(fresh_parent).st_dev, os.fstat(fresh_parent).st_ino) != (
                    os.fstat(receipt._parent_fd).st_dev, os.fstat(receipt._parent_fd).st_ino):
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "fixed native runtime parent was replaced after materialization")
        finally:
            os.close(fresh_parent)
        self._verify_output_receipts(receipt)
        return receipt

    def mark_active_committed(self, receipt: RootPreparedNativeWorkerRuntimeMaterialization,
                              committed: VerifiedCommittedEnrollment,
                              runtime_record_id: str) -> None:
        """Retain bytes only after the store verifies the exact committed CAS row."""
        self.verify_active_committed(receipt, committed, runtime_record_id)
        self._active_bindings[receipt.receipt_handle] = committed.receipt.generation_id

    def verify_active_committed(self, receipt: RootPreparedNativeWorkerRuntimeMaterialization,
                                committed: VerifiedCommittedEnrollment,
                                runtime_record_id: str) -> Mapping[str, Any]:
        """Reobserve the committed CAS and held bytes without prepared guards.

        Activation replaces the prepared generation.  This path therefore
        deliberately uses the store-issued committed proof and actual PM/output
        descriptors, while ``verify_current`` remains strict for preactive use.
        """
        session = self.binding._session
        if (type(committed) is not VerifiedCommittedEnrollment
                or committed._store_seal != self.prepared_enrollment_store._instance_seal
                or not isinstance(runtime_record_id, str) or not runtime_record_id):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active runtime custody requires the store-issued committed enrollment proof")
        active_receipt = self.prepared_enrollment_store.verify_committed_receipt(
            committed.receipt, session._authorization)
        if active_receipt is not committed.receipt:
            raise NativeWorkerRuntimeMaterializationUnavailable("committed enrollment proof changed")
        authority = self.prepared_enrollment_store.authority_loader_for_session()
        generation = authority.get("service_generations") if isinstance(authority, Mapping) else None
        if (not isinstance(generation, Mapping)
                or generation.get("generation_id") != active_receipt.generation_id
                or generation.get("generation_digest") != active_receipt.generation_digest):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "the root-loaded active generation is no longer the committed CAS")
        runtime_rows = generation.get("native_worker_runtime_records")
        active_rows = generation.get("active_network_generation_records")
        if (type(receipt) is not RootPreparedNativeWorkerRuntimeMaterialization
                or receipt._issuer is not self._issuer
                or self._issued.get(receipt.receipt_handle) is not receipt
                or receipt.expires_monotonic <= time.monotonic()
                or active_receipt.state != "committed"
                or active_receipt.generation_id != committed.receipt.generation_id
                or type(runtime_rows) is not list or len(runtime_rows) != 1
                or type(active_rows) is not list or len(active_rows) != 1):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "committed catalogs do not contain exactly one selected native worker runtime")
        runtime_row = runtime_rows[0]
        active_row = active_rows[0]
        expected = {
            "id": runtime_record_id,
            "generation_id": active_receipt.generation_id,
            "recipe_id": receipt._recipe.recipe_id,
            "recipe_sha256": receipt.worker_recipe_sha256,
            "source_choice_selection_handle": receipt.source_choice_selection_handle,
            "profile_id": receipt.profile_id,
            "profile_generation": receipt.profile_generation,
            "pm_runtime_receipt_handle": receipt.pm_runtime_receipt_handle,
            "committed_venv_identity": dict(receipt.committed_venv_identity),
            "pm_base_closure_sha256": receipt.pm_base_closure_sha256,
            "pm_executable_relative_path": receipt.pm_executable_relative_path,
            "pm_executable_member_sha256": receipt.pm_executable_member_sha256,
            "pm_runtime_member_records": [dict(row) for row in receipt.pm_runtime_member_records],
            "native_output_member_records": [dict(row) for row in receipt.native_output_member_records],
            "owned_runtime_root_receipt_handle": receipt.receipt_handle,
            "owned_runtime_root_receipt_sha256": receipt.receipt_sha256,
        }
        if (not isinstance(runtime_row, Mapping) or not isinstance(active_row, Mapping)
                or any(runtime_row.get(key) != value for key, value in expected.items())
                or active_row.get("worker_runtime_record_id") != runtime_record_id
                or active_row.get("worker_runtime_record_sha256") != _sha(runtime_row)
                or active_row.get("generation_id") != active_receipt.generation_id):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "committed runtime and active rows do not join the retained actual member custody")
        if (runtime_row.get("execution_mode") != "native-hermes-cli-module-v1"
                or active_receipt.generation_id != committed.receipt.generation_id):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "committed worker runtime mode or active generation is not the selected native service")
        self._verify_active_held_root_and_members(receipt, runtime_row)
        return MappingProxyType(dict(runtime_row))

    def close(self) -> None:
        for receipt in tuple(self._issued.values()):
            for fd in receipt._member_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if receipt.receipt_handle not in self._active_bindings:
                self._remove_leaf_if_owned(
                    receipt.receipt_handle,
                    (receipt.runtime_root_device, receipt.runtime_root_inode),
                    receipt.native_output_member_records, receipt._parent_fd,
                    receipt.receipt_sha256)
            try:
                os.close(receipt._root_fd)
            except OSError:
                pass
            try:
                os.close(receipt._parent_fd)
            except OSError:
                pass
        self._issued.clear()
        self._by_selection.clear()

    def _verify_active_held_root_and_members(
            self, receipt: RootPreparedNativeWorkerRuntimeMaterialization,
            runtime_row: Mapping[str, Any]) -> None:
        """Check durable PM/output custody after the prepared transaction is replaced."""
        root = os.fstat(receipt._root_fd)
        parent = os.fstat(receipt._parent_fd)
        path_info = os.stat(receipt.receipt_handle, dir_fd=receipt._parent_fd,
                            follow_symlinks=False)
        if ((root.st_dev, root.st_ino) != (receipt.runtime_root_device, receipt.runtime_root_inode)
                or root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700
                or parent.st_uid != 0 or parent.st_gid != 0 or stat.S_IMODE(parent.st_mode) != 0o700
                or not stat.S_ISDIR(path_info.st_mode)
                or (path_info.st_dev, path_info.st_ino) != (root.st_dev, root.st_ino)
                or time.monotonic() >= receipt.expires_monotonic):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active worker materialization root changed or its original setup deadline expired")
        fresh_parent = self._open_or_create_runtime_parent(create=False)
        try:
            current_parent = os.fstat(fresh_parent)
            if (current_parent.st_dev, current_parent.st_ino) != (parent.st_dev, parent.st_ino):
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "active worker runtime parent path no longer names the held parent")
        finally:
            os.close(fresh_parent)
        self._verify_materialization_manifest(receipt)
        pm_fds = receipt._member_fds[:len(receipt.pm_runtime_member_records)]
        output_fds = receipt._member_fds[len(receipt.pm_runtime_member_records):]
        if (len(pm_fds) != len(receipt.pm_runtime_member_records)
                or len(output_fds) != len(receipt.native_output_member_records)):
            raise NativeWorkerRuntimeMaterializationUnavailable("held active worker member set is incomplete")
        if not pm_fds or not output_fds:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active worker lacks its complete PM base and generated output member sets")
        for fd, row in zip(pm_fds, receipt.pm_runtime_member_records, strict=True):
            self._verify_held_member_fd(fd, row, allow_symlink=True)
        for fd, row in zip(output_fds, receipt.native_output_member_records, strict=True):
            self._verify_held_member_fd(fd, row, allow_symlink=False)
        self._verify_output_member_paths(receipt)
        self._verify_committed_pm_venv(receipt, runtime_row)

    @staticmethod
    def _verify_held_member_fd(fd: int, row: Mapping[str, Any], *, allow_symlink: bool) -> None:
        info = os.fstat(fd)
        expected = (row["device"], row["inode"], row["owner_uid"], row["owner_gid"],
                    row["mode"], row["size_bytes"])
        actual = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                  stat.S_IMODE(info.st_mode), info.st_size)
        kind_ok = (stat.S_ISREG(info.st_mode) if row["kind"] == "regular-file"
                   else allow_symlink and stat.S_ISLNK(info.st_mode))
        if not kind_ok or actual != expected:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "held active worker member no longer matches its root-owned receipt")
        if row["kind"] == "regular-file":
            if info.st_nlink != 1 or _hash_fd(fd) != row["sha256"]:
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "held active worker member bytes or link count changed")
        elif row.get("output_role") is not None:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "generated native output unexpectedly contains a symbolic link")

    def _verify_materialization_manifest(
            self, receipt: RootPreparedNativeWorkerRuntimeMaterialization) -> None:
        fd = -1
        try:
            fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=receipt._root_fd)
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size <= 0 or info.st_size > 4 * 1024 * 1024):
                raise ValueError
            data = os.pread(fd, 4 * 1024 * 1024 + 1, 0)
            parsed = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_json_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            if (len(data) != info.st_size or not isinstance(parsed, dict)
                    or set(parsed) != {"body", "body_sha256"}
                    or parsed["body_sha256"] != receipt.receipt_sha256
                    or _sha(parsed["body"]) != receipt.receipt_sha256
                    or not isinstance(parsed["body"], dict)
                    or parsed["body"].get("committed_venv_identity")
                       != dict(receipt.committed_venv_identity)):
                raise ValueError
        except Exception:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active worker materialization receipt bytes are not current") from None
        finally:
            if fd >= 0:
                os.close(fd)

    def _verify_committed_pm_venv(self,
                                  receipt: RootPreparedNativeWorkerRuntimeMaterialization,
                                  runtime_row: Mapping[str, Any]) -> None:
        """Reopen the protected PM receipt and observe the entire committed venv."""
        from .pm_runtime import (_match_receipt, _observe_runtime,
                                 observe_committed_pm_venv_tree)
        handle = receipt.pm_runtime_receipt_handle
        descriptor = dict(receipt.committed_venv_identity)
        if (runtime_row.get("committed_venv_identity") != descriptor
                or runtime_row.get("pm_runtime_receipt_handle") != handle):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active PM identity descriptor does not match the selected runtime row")
        root_fd = receipts_fd = receipt_fd = -1
        tree = None
        try:
            root_fd = os.open(self.runtime_receipts.runtime_root,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | getattr(os, "O_CLOEXEC", 0))
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                    or root_info.st_gid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
                raise ValueError
            receipts_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                  | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
            directory = os.fstat(receipts_fd)
            if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                    or directory.st_gid != 0 or stat.S_IMODE(directory.st_mode) != 0o700):
                raise ValueError
            receipt_fd = os.open(handle + ".json", os.O_RDONLY | os.O_NOFOLLOW
                                 | getattr(os, "O_CLOEXEC", 0), dir_fd=receipts_fd)
            info = os.fstat(receipt_fd)
            receipt_path = os.stat(handle + ".json", dir_fd=receipts_fd,
                                   follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (receipt_path.st_dev, receipt_path.st_ino)
                    or info.st_size <= 0 or info.st_size > 64 * 1024):
                raise ValueError
            raw = os.pread(receipt_fd, 64 * 1024 + 1, 0)
            record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            known = self.runtime_receipts._record(handle)
            if (len(raw) != info.st_size or not isinstance(record, dict) or record != known
                    or _canonical(record) != raw
                    or hashlib.sha256(raw).hexdigest() != descriptor.get("pm_receipt_sha256")
                    or record.get("handle") != handle
                    or record.get("generation") != descriptor.get("pm_generation")
                    or record.get("source_commit") != descriptor.get("source_commit")
                    or record.get("runtime_relative") != descriptor.get("runtime_relative")
                    or record.get("runtime_venv_relative") != descriptor.get("runtime_venv_relative")
                    or record.get("runtime_closure_sha256") != descriptor.get("runtime_closure_sha256")
                    or record.get("runtime_executable_artifact_id")
                       != "observed:pm-committed-venv-python"):
                raise ValueError
            generation_root = self.runtime_receipts.runtime_root / record["generation"]
            executable = generation_root / record["runtime_relative"]
            venv_root = generation_root / record["runtime_venv_relative"]
            identity = _observe_runtime(executable, expected_uid=0, expected_root=generation_root)
            _match_receipt(record, executable, identity,
                           generation_root / record["runtime_venv_relative"])
            tree = observe_committed_pm_venv_tree(
                venv_root, expected_closure_sha256=record["runtime_closure_sha256"])
            resolved = executable.resolve(strict=True)
            executable_rel = resolved.relative_to(venv_root.resolve(strict=True)).as_posix()
            member = next((row for row in tree.members
                           if row.relative_path == executable_rel and row.kind == "file"), None)
            observed = (identity["sha256"], identity["device"], identity["inode"],
                        identity["uid"], identity["gid"], identity["mode"])
            expected = (descriptor.get("executable_sha256"), descriptor.get("executable_device"),
                        descriptor.get("executable_inode"), descriptor.get("executable_uid"),
                        descriptor.get("executable_gid"), descriptor.get("executable_mode"))
            if (member is None or observed != expected
                    or (member.sha256, member.device, member.inode, member.uid,
                        member.gid, member.mode) != expected):
                raise ValueError
            if receipt.pm_runtime_member_records:
                self._verify_committed_pm_base_tree(receipt, record, runtime_row)
        except Exception:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "protected PM receipt, executable, or full committed venv closure changed") from None
        finally:
            if tree is not None:
                tree.close()
            for descriptor_fd in (receipt_fd, receipts_fd, root_fd):
                if descriptor_fd >= 0:
                    try:
                        os.close(descriptor_fd)
                    except OSError:
                        pass

    def _verify_committed_pm_base_tree(
            self, receipt: RootPreparedNativeWorkerRuntimeMaterialization,
            pm_record: Mapping[str, Any], runtime_row: Mapping[str, Any]) -> None:
        """Reopen the pinned base-Python tree and join every held member row."""
        rows = receipt.pm_runtime_member_records
        if not rows:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active worker has no held official PM base-runtime members")
        catalog = getattr(self.runtime_receipts, "catalog", None)
        artifact_root = getattr(self.runtime_receipts, "artifact_root", None)
        if catalog is None or not isinstance(artifact_root, Path):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "active worker cannot reopen the exact protected PM base-runtime catalog")
        from .pm_runtime import PYTHON_ID, PYTHON_SHA256, _open_catalog_runtime_tree
        root_fd = -1
        members = ()
        try:
            tree = catalog.materialize_tree(PYTHON_ID, PYTHON_SHA256, artifact_root,
                                            expected_uid=0)
            spec = catalog.artifacts[PYTHON_ID]
            root_fd, members, closure = _open_catalog_runtime_tree(
                tree.path, spec.tree_files,
                expected_closure_sha256=receipt.pm_base_closure_sha256)
            if (closure != runtime_row.get("pm_base_closure_sha256")
                    or closure != pm_record.get("base_python_closure_sha256")):
                raise ValueError
            current = {member.relative_path: member for member in members}
            if len(current) != len(rows) or len(current) != len(members):
                raise ValueError
            for row in rows:
                member = current.get(row["relative_path"])
                kind = "regular-file" if member is not None and member.kind == "file" else "symlink"
                if (member is None or row.get("artifact_id") != PYTHON_ID
                        or row.get("receipt_handle") != receipt.pm_runtime_receipt_handle
                        or row.get("kind") != kind or row.get("output_role") is not None
                        or (row.get("sha256"), row.get("size_bytes"), row.get("mode"),
                            row.get("owner_uid"), row.get("owner_gid"), row.get("device"),
                            row.get("inode"), row.get("link_target"))
                           != (member.sha256, member.size_bytes, member.mode, member.uid,
                               member.gid, member.device, member.inode, member.link_target)):
                    raise ValueError
        except Exception:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "current official PM base tree no longer matches all held runtime members") from None
        finally:
            for descriptor_fd in (root_fd, *(member.fd for member in members
                                              if member.fd is not None)):
                if descriptor_fd >= 0:
                    try:
                        os.close(descriptor_fd)
                    except OSError:
                        pass

    def _validate_role_closure(self, closure: Any,
                               recipe: RootPreparedNativeWorkerRecipe) -> None:
        rows = [row for row in closure.role_rows if row.receipt_kind == "native-output-cas"]
        if (len(rows) != 5 or {row.role for row in rows} != set(_ROLE_ORDER)
                or len({row.receipt_handle for row in rows}) != 5):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "current reserved native outputs do not contain the exact five fixed roles")
        session = self.binding._session
        prepared = session._resolve_current_prepared_enrollment()
        for row in rows:
            record = self.output_receipts._get_record(row.receipt_handle)
            if (record["state"] != "reserved"
                    or record["setup_session_id"] != recipe.setup_session_id
                    or record["transaction_handle"] != recipe.transaction_handle
                    or record["prepared_generation_id"] != prepared.generation_id
                    or record["artifact_role"] != row.role
                    or record["sha256"] != row.sha256
                    or record["size_bytes"] != row.size_bytes):
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "native output receipt does not match the current reserved runnable role")
            self.output_receipts._verify_record_current(record)

    def _materialize_native_outputs(self, root_fd: int, closure: Any,
                                    held_fds: list[int],
                                    projected: list[Mapping[str, Any]]) -> None:
        from .native_output_receipts import _stored_member_manifest
        role_rows = {row.role: row for row in closure.role_rows
                     if row.receipt_kind == "native-output-cas"}
        byte_total = 0
        for role in _ROLE_ORDER:
            row = role_rows[role]
            record = self.output_receipts._get_record(row.receipt_handle)
            self.output_receipts._verify_record_current(record)
            payload = self.output_receipts._read_record_payload(record)
            manifest = _stored_member_manifest(role, payload)
            if role == "native-compiled-closure":
                try:
                    with tarfile.open(fileobj=BytesIO(payload), mode="r:") as archive:
                        archive_members = list(archive)
                        files = [item for item in archive_members if item.isfile()]
                        if len(files) != len(archive_members) or len(files) != len(manifest):
                            raise ValueError
                        by_path = {item.path: item for item in manifest}
                        for member in files:
                            expected = by_path.get(member.name)
                            if expected is None or not _safe_relative(member.name):
                                raise ValueError
                            stream = archive.extractfile(member)
                            if stream is None:
                                raise ValueError
                            content = stream.read(_MAX_BYTES + 1)
                            if (len(content) != expected.size_bytes
                                    or hashlib.sha256(content).hexdigest() != expected.sha256
                                    or member.mode & 0o777 != expected.mode):
                                raise ValueError
                            byte_total += len(content)
                            projected.append(self._write_member(
                                root_fd, role, member.name, content, expected,
                                row.artifact_id, row.receipt_handle, held_fds))
                except (OSError, tarfile.TarError, ValueError):
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "reserved compiled closure differs from its verified root member manifest") from None
            else:
                if len(manifest) != 1 or not _safe_relative(manifest[0].path):
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "reserved native output does not have one exact file member")
                expected = manifest[0]
                if len(payload) != expected.size_bytes or hashlib.sha256(payload).hexdigest() != expected.sha256:
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "reserved native output bytes differ from its root member manifest")
                byte_total += len(payload)
                projected.append(self._write_member(root_fd, role, expected.path, payload,
                                                    expected, row.artifact_id,
                                                    row.receipt_handle, held_fds))
            if byte_total > _MAX_BYTES:
                raise NativeWorkerRuntimeMaterializationUnavailable("native worker output tree exceeds its byte bound")
            if len(projected) > _MAX_MEMBERS:
                raise NativeWorkerRuntimeMaterializationUnavailable("native worker output tree has too many members")

    def _project_pm_members(self, pm: Any, held_fds: list[int]) -> list[Mapping[str, Any]]:
        from .pm_runtime import PYTHON_ID
        by_path: dict[str, Any] = {}
        projected = []
        for member in pm.members:
            if member.relative_path in by_path:
                raise NativeWorkerRuntimeMaterializationUnavailable("PM runtime repeats a member path")
            by_path[member.relative_path] = member
            if member.kind not in {"file", "symlink"} or not _safe_relative(member.relative_path):
                raise NativeWorkerRuntimeMaterializationUnavailable("PM runtime contains an unsupported held member")
            if member.fd is None:
                raise NativeWorkerRuntimeMaterializationUnavailable("PM runtime member has no held descriptor")
            info = os.fstat(member.fd)
            if (info.st_dev != member.device or info.st_ino != member.inode
                    or info.st_uid != member.uid or info.st_gid != member.gid
                    or stat.S_IMODE(info.st_mode) != member.mode):
                raise NativeWorkerRuntimeMaterializationUnavailable("PM runtime member changed after projection")
            held = os.dup(member.fd)
            held_fds.append(held)
            kind = "regular-file" if member.kind == "file" else "symlink"
            projected.append(MappingProxyType({
                "artifact_id": PYTHON_ID,
                "receipt_handle": pm.selection.receipt_handle,
                "relative_path": member.relative_path,
                "kind": kind, "sha256": member.sha256,
                "size_bytes": member.size_bytes, "mode": member.mode,
                "owner_uid": member.uid, "owner_gid": member.gid,
                "device": member.device, "inode": member.inode,
                "link_target": member.link_target, "output_role": None,
            }))
        executable = by_path.get(pm.executable_relative_path)
        if (executable is None or executable.kind != "file"
                or executable.sha256 != pm.executable_member.sha256
                or executable.device != pm.executable_member.device
                or executable.inode != pm.executable_member.inode):
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "selected official interpreter is not the exact member of the held PM tree")
        return sorted(projected, key=lambda row: row["relative_path"])

    def _write_member(self, root_fd: int, role: str, member_path: str, content: bytes,
                      manifest: Any, artifact_id: str, receipt_handle: str,
                      held_fds: list[int]) -> Mapping[str, Any]:
        parts = [role, *PurePosixPath(member_path).parts]
        directory_fd = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=directory_fd)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = child
                info = os.fstat(directory_fd)
                if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o755:
                    raise NativeWorkerRuntimeMaterializationUnavailable("native output directory custody changed")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            fd = os.open(parts[-1], flags, 0o600, dir_fd=directory_fd)
            created_identity: tuple[int, int] | None = None
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, manifest.mode)
                view = memoryview(content)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short write to native worker output member")
                    view = view[written:]
                os.fsync(fd)
                info = os.fstat(fd)
                created_identity = (info.st_dev, info.st_ino)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != 0 or info.st_gid != 0
                        or stat.S_IMODE(info.st_mode) != manifest.mode
                        or info.st_size != manifest.size_bytes
                        or hashlib.sha256(content).hexdigest() != manifest.sha256):
                    raise NativeWorkerRuntimeMaterializationUnavailable("materialized native member failed root stat/hash verification")
                held = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                               dir_fd=directory_fd)
                held_info = os.fstat(held)
                if ((held_info.st_dev, held_info.st_ino) != (info.st_dev, info.st_ino)
                        or _hash_fd(held) != manifest.sha256):
                    os.close(held)
                    raise NativeWorkerRuntimeMaterializationUnavailable("reopened native member changed identity")
                held_fds.append(held)
                return MappingProxyType({
                    "artifact_id": artifact_id, "receipt_handle": receipt_handle,
                    "relative_path": "/".join(parts), "kind": "regular-file",
                    "sha256": manifest.sha256, "size_bytes": manifest.size_bytes,
                    "mode": manifest.mode, "owner_uid": info.st_uid, "owner_gid": info.st_gid,
                    "device": info.st_dev, "inode": info.st_ino,
                    "link_target": None, "output_role": role,
                })
            finally:
                os.close(fd)
        except NativeWorkerRuntimeMaterializationUnavailable:
            if "created_identity" in locals() and created_identity is not None:
                try:
                    current = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
                    if ((current.st_dev, current.st_ino) == created_identity
                            and stat.S_ISREG(current.st_mode) and current.st_uid == 0
                            and current.st_nlink == 1):
                        os.unlink(parts[-1], dir_fd=directory_fd)
                except OSError:
                    pass
            raise
        except (OSError, ValueError):
            if "created_identity" in locals() and created_identity is not None:
                try:
                    current = os.stat(parts[-1], dir_fd=directory_fd, follow_symlinks=False)
                    if ((current.st_dev, current.st_ino) == created_identity
                            and stat.S_ISREG(current.st_mode) and current.st_uid == 0
                            and current.st_nlink == 1):
                        os.unlink(parts[-1], dir_fd=directory_fd)
                except OSError:
                    pass
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "root-owned native output member could not be safely materialized") from None
        finally:
            os.close(directory_fd)

    def _open_or_create_runtime_parent(self, *, create: bool = True) -> int:
        if os.geteuid() != 0 or not hasattr(os, "O_NOFOLLOW"):
            raise NativeWorkerRuntimeMaterializationUnavailable("native output materialization requires Linux root")
        parent = self.output_receipts._cas_root.parent
        try:
            info = parent.lstat()
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                         | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            raise NativeWorkerRuntimeMaterializationUnavailable("fixed root artifact staging directory is unavailable") from None
        try:
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                    or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != 0
                    or stat.S_IMODE(opened.st_mode) != 0o700):
                raise NativeWorkerRuntimeMaterializationUnavailable("fixed root artifact staging custody is invalid")
            created = False
            if create:
                try:
                    os.mkdir("native-worker-runtime", 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
            child = -1
            try:
                child = os.open("native-worker-runtime", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                if created:
                    os.fchown(child, 0, 0)
                    os.fchmod(child, 0o700)
                root = os.fstat(child)
                if (root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700):
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "native runtime root is not private root custody")
                retained = child
                child = -1
                return retained
            except OSError:
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "native runtime root descriptor could not be verified") from None
            finally:
                if child >= 0:
                    os.close(child)
        finally:
            os.close(fd)

    def _write_manifest(self, root_fd: int, body: Mapping[str, Any], receipt_sha: str) -> None:
        payload = _canonical({"body": dict(body), "body_sha256": receipt_sha})
        fd = os.open("receipt.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=root_fd)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write to native worker runtime receipt")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(root_fd)

    def _verify_held_root_and_members(self, receipt: RootPreparedNativeWorkerRuntimeMaterialization) -> None:
        root = os.fstat(receipt._root_fd)
        path_info = os.stat(receipt.receipt_handle, dir_fd=receipt._parent_fd,
                            follow_symlinks=False)
        if ((root.st_dev, root.st_ino) != (receipt.runtime_root_device, receipt.runtime_root_inode)
                or root.st_uid != 0 or root.st_gid != 0 or stat.S_IMODE(root.st_mode) != 0o700
                or not stat.S_ISDIR(path_info.st_mode)
                or (path_info.st_dev, path_info.st_ino) != (root.st_dev, root.st_ino)
                or len(receipt._member_fds) != len(receipt.pm_runtime_member_records)
                   + len(receipt.native_output_member_records)):
            raise NativeWorkerRuntimeMaterializationUnavailable("held native runtime root or member set changed")
        expected = (*receipt.pm_runtime_member_records, *receipt.native_output_member_records)
        current_pm = self.runtime_receipts.resolve_runtime_projection(
            receipt.pm_runtime_receipt_handle, receipt.transaction_handle,
            receipt.prepared_generation_id)
        try:
            if dict(receipt.committed_venv_identity) != dict(self._committed_venv_identity(current_pm)):
                raise NativeWorkerRuntimeMaterializationUnavailable(
                    "committed PM venv identity changed after prepared materialization")
            current_pm_by_path = {member.relative_path: member for member in current_pm.members}
            for fd, row in zip(receipt._member_fds, expected, strict=True):
                info = os.fstat(fd)
                expected_stat = (row["device"], row["inode"], row["owner_uid"],
                                 row["owner_gid"], row["mode"], row["size_bytes"])
                actual_stat = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                               stat.S_IMODE(info.st_mode), info.st_size)
                kind_ok = (stat.S_ISREG(info.st_mode) if row["kind"] == "regular-file"
                           else stat.S_ISLNK(info.st_mode))
                if not kind_ok or actual_stat != expected_stat:
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "held runtime member no longer matches its root receipt")
                if row["kind"] == "regular-file":
                    if info.st_nlink != 1 or _hash_fd(fd) != row["sha256"]:
                        raise NativeWorkerRuntimeMaterializationUnavailable(
                            "held regular runtime member hash or link count changed")
                elif row["output_role"] is not None:
                    raise NativeWorkerRuntimeMaterializationUnavailable(
                        "generated runtime output unexpectedly contains a symlink")
                else:
                    current = current_pm_by_path.get(row["relative_path"])
                    if (current is None or current.kind != "symlink"
                            or current.link_target != row["link_target"]
                            or current.sha256 != row["sha256"]
                            or current.device != row["device"] or current.inode != row["inode"]):
                        raise NativeWorkerRuntimeMaterializationUnavailable(
                            "held PM symlink no longer matches its current tree")
        finally:
            current_pm.close()
        self._verify_output_member_paths(receipt)
        fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                     dir_fd=receipt._root_fd)
        try:
            data = os.read(fd, 4 * 1024 * 1024 + 1)
        finally:
            os.close(fd)
        if len(data) > 4 * 1024 * 1024:
            raise NativeWorkerRuntimeMaterializationUnavailable("materialization receipt file exceeds its bound")
        try:
            parsed = json.loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            raise NativeWorkerRuntimeMaterializationUnavailable("materialization receipt file is malformed") from None
        if (not isinstance(parsed, dict) or set(parsed) != {"body", "body_sha256"}
                or parsed["body_sha256"] != receipt.receipt_sha256
                or _sha(parsed["body"]) != receipt.receipt_sha256
                or not isinstance(parsed["body"], dict)
                or parsed["body"].get("committed_venv_identity")
                   != dict(receipt.committed_venv_identity)):
            raise NativeWorkerRuntimeMaterializationUnavailable("materialization receipt digest changed")

    def _committed_venv_identity(self, pm: Any) -> Mapping[str, Any]:
        """Copy the actual protected PM receipt and observed committed executable."""
        handle = getattr(getattr(pm, "selection", None), "receipt_handle", None)
        if not isinstance(handle, str) or not handle or "/" in handle:
            raise NativeWorkerRuntimeMaterializationUnavailable("PM receipt handle is not a fixed leaf")
        root_fd = receipts_fd = receipt_fd = -1
        try:
            root_fd = os.open(self.runtime_receipts.runtime_root,
                              os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | getattr(os, "O_CLOEXEC", 0))
            root = os.fstat(root_fd)
            if (not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_gid != 0
                    or stat.S_IMODE(root.st_mode) != 0o700):
                raise ValueError
            receipts_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                  | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
            receipt_dir = os.fstat(receipts_fd)
            if (not stat.S_ISDIR(receipt_dir.st_mode) or receipt_dir.st_uid != 0
                    or receipt_dir.st_gid != 0 or stat.S_IMODE(receipt_dir.st_mode) != 0o700):
                raise ValueError
            name = handle + ".json"
            path_info = os.stat(name, dir_fd=receipts_fd, follow_symlinks=False)
            receipt_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                                 | getattr(os, "O_CLOEXEC", 0), dir_fd=receipts_fd)
            info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
                    or info.st_size <= 0 or info.st_size > 64 * 1024):
                raise ValueError
            raw = os.pread(receipt_fd, 64 * 1024 + 1, 0)
            if len(raw) != info.st_size or len(raw) > 64 * 1024:
                raise ValueError
            record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            current = self.runtime_receipts._record(handle)
            if (not isinstance(record, dict) or record != current
                    or record.get("handle") != handle
                    or record.get("runtime_executable_artifact_id") != "observed:pm-committed-venv-python"
                    or record.get("pm_sync_outcome") != "succeeded"):
                raise ValueError
            selected = pm.selection
            from .pm_runtime import _match_receipt, _observe_runtime
            executable = selected.python_path
            base = self.runtime_receipts.runtime_root / record["generation"]
            venv_root = base / record["runtime_venv_relative"]
            observed = _observe_runtime(executable, expected_uid=0, expected_root=base)
            _match_receipt(record, executable, observed, venv_root)
            if (observed["sha256"] != selected.runtime_sha256
                    or (observed["device"], observed["inode"], observed["uid"],
                        observed["gid"], observed["mode"])
                       != (selected.device, selected.inode, selected.uid,
                           selected.gid, selected.mode)):
                raise ValueError
            return MappingProxyType({
                "schema": 1,
                "identity_kind": "pm-committed-hermes-venv-v1",
                "pm_runtime_receipt_handle": handle,
                "pm_receipt_sha256": hashlib.sha256(raw).hexdigest(),
                "pm_generation": record["generation"],
                "source_commit": record["source_commit"],
                "runtime_relative": record["runtime_relative"],
                "runtime_venv_relative": record["runtime_venv_relative"],
                "runtime_closure_sha256": record["runtime_closure_sha256"],
                "executable_identity_id": record["runtime_executable_artifact_id"],
                "executable_sha256": observed["sha256"],
                "executable_device": observed["device"],
                "executable_inode": observed["inode"],
                "executable_uid": observed["uid"],
                "executable_gid": observed["gid"],
                "executable_mode": observed["mode"],
            })
        except NativeWorkerRuntimeMaterializationUnavailable:
            raise
        except Exception:
            raise NativeWorkerRuntimeMaterializationUnavailable(
                "exact committed PM venv identity could not be observed from its protected receipt") from None
        finally:
            for descriptor_fd in (receipt_fd, receipts_fd, root_fd):
                if descriptor_fd >= 0:
                    try:
                        os.close(descriptor_fd)
                    except OSError:
                        pass

    def _verify_output_member_paths(self,
                                    receipt: RootPreparedNativeWorkerRuntimeMaterialization) -> None:
        for row in receipt.native_output_member_records:
            parts = row["relative_path"].split("/")
            if len(parts) < 2 or parts[0] not in _ROLE_ORDER:
                raise NativeWorkerRuntimeMaterializationUnavailable("native output path is outside its fixed role root")
            directory_fd = os.dup(receipt._root_fd)
            try:
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                    os.close(directory_fd)
                    directory_fd = child
                    directory_info = os.fstat(directory_fd)
                    if (directory_info.st_uid != 0 or directory_info.st_gid != 0
                            or stat.S_IMODE(directory_info.st_mode) != 0o755):
                        raise NativeWorkerRuntimeMaterializationUnavailable("native output directory custody changed")
                fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW
                             | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                try:
                    info = os.fstat(fd)
                    if ((info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                         stat.S_IMODE(info.st_mode), info.st_size, info.st_nlink)
                            != (row["device"], row["inode"], row["owner_uid"],
                                row["owner_gid"], row["mode"], row["size_bytes"], 1)
                            or not stat.S_ISREG(info.st_mode) or _hash_fd(fd) != row["sha256"]):
                        raise NativeWorkerRuntimeMaterializationUnavailable("native output path no longer names the held exact member")
                finally:
                    os.close(fd)
            finally:
                os.close(directory_fd)

    def _verify_output_receipts(self, receipt: RootPreparedNativeWorkerRuntimeMaterialization) -> None:
        for handle in receipt.native_output_receipt_handles:
            record = self.output_receipts._get_record(handle)
            if (record["state"] != "reserved"
                    or record["setup_session_id"] != receipt.setup_session_id
                    or record["transaction_handle"] != receipt.transaction_handle
                    or record["prepared_generation_id"] != receipt.prepared_generation_id):
                raise NativeWorkerRuntimeMaterializationUnavailable("native output reservation is no longer current")
            self.output_receipts._verify_record_current(record)

    def _remove_leaf_if_owned(self, receipt_handle: str, expected_root: Any,
                              records: Any, parent_fd: int,
                              receipt_sha256: str | None = None) -> None:
        if (not isinstance(receipt_handle, str) or not _HANDLE.fullmatch(receipt_handle)
                or parent_fd < 0 or expected_root is None):
            return
        if hasattr(expected_root, "st_dev"):
            root_identity = (expected_root.st_dev, expected_root.st_ino)
        elif isinstance(expected_root, tuple) and len(expected_root) == 2:
            root_identity = expected_root
        else:
            return
        root_fd = -1
        try:
            root_fd = os.open(receipt_handle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                              | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
            info = os.fstat(root_fd)
            if ((info.st_dev, info.st_ino) != root_identity or info.st_uid != 0
                    or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
                return
            expected_rows = {}
            for row in records:
                relative = row.get("relative_path")
                if (not isinstance(relative, str) or not _safe_relative(relative)
                        or relative in expected_rows or row.get("kind") != "regular-file"):
                    return
                parts = relative.split("/")
                if len(parts) < 2 or parts[0] not in _ROLE_ORDER:
                    return
                expected_rows[relative] = row

            def remove_known(directory_fd: int, prefix: str) -> bool:
                safe_to_remove = True
                for name in os.listdir(directory_fd):
                    relative = f"{prefix}/{name}" if prefix else name
                    row = expected_rows.get(relative)
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if row is not None:
                        if ((info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                             stat.S_IMODE(info.st_mode))
                                != (row["device"], row["inode"], row["owner_uid"],
                                    row["owner_gid"], row["mode"])
                                or not stat.S_ISREG(info.st_mode)):
                            return False
                        os.unlink(name, dir_fd=directory_fd)
                        expected_rows.pop(relative)
                        continue
                    if not any(path.startswith(relative + "/") for path in expected_rows):
                        # Preserve operator-owned or otherwise unrecorded data,
                        # but continue removing other exact inode-matched
                        # members. Returning here made cleanup order depend on
                        # readdir order and could strand every owned member.
                        safe_to_remove = False
                        continue
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                            or stat.S_IMODE(info.st_mode) != 0o755):
                        safe_to_remove = False
                        continue
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                    try:
                        child_safe_to_remove = remove_known(child, relative)
                    finally:
                        os.close(child)
                    if child_safe_to_remove:
                        os.rmdir(name, dir_fd=directory_fd)
                    else:
                        safe_to_remove = False
                return safe_to_remove

            if not remove_known(root_fd, "") or expected_rows:
                return
            names = set(os.listdir(root_fd))
            if "receipt.json" in names:
                if names != {"receipt.json"} or not isinstance(receipt_sha256, str):
                    return
                manifest_fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW
                                      | getattr(os, "O_CLOEXEC", 0), dir_fd=root_fd)
                try:
                    manifest_info = os.fstat(manifest_fd)
                    data = os.read(manifest_fd, 4 * 1024 * 1024 + 1)
                finally:
                    os.close(manifest_fd)
                try:
                    parsed = json.loads(data.decode("utf-8"))
                except (UnicodeError, ValueError):
                    return
                if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_uid != 0
                        or manifest_info.st_gid != 0 or stat.S_IMODE(manifest_info.st_mode) != 0o600
                        or len(data) > 4 * 1024 * 1024
                        or not isinstance(parsed, dict) or set(parsed) != {"body", "body_sha256"}
                        or parsed["body_sha256"] != receipt_sha256
                        or _sha(parsed["body"]) != receipt_sha256):
                    return
                os.unlink("receipt.json", dir_fd=root_fd)
            elif names:
                return
            os.close(root_fd)
            root_fd = -1
            os.rmdir(receipt_handle, dir_fd=parent_fd)
        except (OSError, NativeWorkerRuntimeMaterializationUnavailable, KeyError, TypeError):
            pass
        finally:
            if root_fd >= 0:
                os.close(root_fd)


__all__ = [
    "NativeWorkerRuntimeMaterializationUnavailable",
    "RootPreparedNativeWorkerRuntimeMaterialization",
    "RootPreparedNativeWorkerRuntimeMaterializationRegistry",
    "RootPreparedNativeWorkerRuntimeMember",
]
