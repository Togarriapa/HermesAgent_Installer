"""Independent active-generation observation for the selected Hermes worker.

Setup PM receipts are deliberately not resolved through their expiring setup
registry here. The active service-generation row is rejoined to the current
root journal and the PM plus native-output file closures are reopened from
their protected locations before a worker can launch.
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
from collections.abc import Mapping
from typing import Any

from .types import AuthorityDenied


class ActiveNativeWorkerRuntimeUnavailable(AuthorityDenied):
    """The active selected worker runtime is incomplete or changed."""

    def __init__(self, message: str):
        super().__init__("native_worker.runtime", message)


class _ProjectionFDCustody:
    """Idempotent owner for the duplicated member descriptors of one proof."""

    __slots__ = ("fds", "closed")

    def __init__(self, fds: tuple[int, ...]):
        self.fds = tuple(set(fds))
        self.closed = False

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        fds, self.fds = self.fds, ()
        for fd in fds:
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveNativeWorkerRuntimeProjection:
    """Short-lived root-held PM member descriptors for one active network row."""

    projection_handle: str
    network_projection_handle: str
    service_generation_digest: str
    runtime_record_id: str
    runtime_record_sha256: str
    pm_runtime_receipt_handle: str
    pm_runtime_root_device: int
    pm_runtime_root_inode: int
    native_output_root_device: int
    native_output_root_inode: int
    expires_monotonic: float
    member_fds: tuple[int, ...] = field(repr=False)
    _custody: _ProjectionFDCustody = field(repr=False, compare=False)
    _owner: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActiveNativeWorkerRuntimeProjection(<root-held PM closure>)"

    def close(self) -> None:
        self._owner._retire_projection(self)


class RootActiveNativeWorkerRuntimeRegistry:
    """Reopen active PM closure from the current protected journal, not setup."""

    def __init__(self, runtime: Any, generation_owner: Any, *, _seal: object):
        from .active_network_generation import (
            RootActiveNetworkGenerationOwner,
            RootActiveNetworkGenerationProjection,
        )
        from .runtime_composition import RootAuthorityRuntime
        if (_seal is not _RUNTIME_SEAL or type(runtime) is not RootAuthorityRuntime
                or type(generation_owner) is not RootActiveNetworkGenerationOwner
                or runtime.service.root_authority_runtime is not runtime
                or runtime.service.root_runtime_bindings is not runtime.bindings):
            raise ActiveNativeWorkerRuntimeUnavailable(
                "active PM observer requires the exact current root runtime and generation owner")
        self.runtime = runtime
        self.generation_owner = generation_owner
        self._issuer = object()
        self._issued: dict[str, RootActiveNativeWorkerRuntimeProjection] = {}
        self._network_inputs: dict[str, Any] = {}
        self._closed = False

    @classmethod
    def from_root_runtime(cls, runtime: Any, generation_owner: Any
                          ) -> "RootActiveNativeWorkerRuntimeRegistry":
        return cls(runtime, generation_owner, _seal=_RUNTIME_SEAL)

    def resolve_current(self, network_projection: Any) -> RootActiveNativeWorkerRuntimeProjection:
        from .active_network_generation import RootActiveNetworkGenerationProjection
        self._require_live()
        if type(network_projection) is not RootActiveNetworkGenerationProjection:
            raise ActiveNativeWorkerRuntimeUnavailable("active network projection is not owner-issued")
        try:
            self.generation_owner.verify_current(network_projection)
            row = network_projection.runtime_record
            if _digest(row) != network_projection.active_record["worker_runtime_record_sha256"]:
                raise ValueError("active PM row digest differs from its protected FK")
            if (row.get("id") != network_projection.active_record.get("worker_runtime_record_id")
                    or row.get("generation_id") != network_projection.active_record.get("generation_id")
                    or row.get("profile_id") != network_projection.process_profile_id
                    or row.get("profile_generation") != network_projection.profile_generation):
                raise ValueError("runtime row does not join selected active profile")
            fds, root_identity = self._open_pm_members(row, network_projection.active_record)
            try:
                fds.extend(self._open_source_definition_members(row))
                output_fds, output_root_identity = self._open_native_output_members(row)
                fds.extend(output_fds)
                self.generation_owner.verify_current(network_projection)
                projection = RootActiveNativeWorkerRuntimeProjection(
                    projection_handle=secrets.token_urlsafe(32),
                    network_projection_handle=network_projection.projection_handle,
                    service_generation_digest=network_projection.service_generation_digest,
                    runtime_record_id=row["id"],
                    runtime_record_sha256=network_projection.active_record["worker_runtime_record_sha256"],
                    pm_runtime_receipt_handle=row["pm_runtime_receipt_handle"],
                    pm_runtime_root_device=root_identity[0], pm_runtime_root_inode=root_identity[1],
                    native_output_root_device=output_root_identity[0],
                    native_output_root_inode=output_root_identity[1],
                    expires_monotonic=min(time.monotonic() + 30.0,
                                          network_projection.expires_monotonic),
                    member_fds=tuple(fds), _custody=_ProjectionFDCustody(tuple(fds)),
                    _owner=self, _issuer=self._issuer,
                )
                self._prune_expired()
                if len(self._issued) >= 64:
                    oldest = next(iter(self._issued))
                    self._retire(oldest)
                self._issued[projection.projection_handle] = projection
                self._network_inputs[projection.projection_handle] = network_projection
                return projection
            except BaseException:
                for fd in fds:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                raise
        except ActiveNativeWorkerRuntimeUnavailable:
            raise
        except Exception:
            raise ActiveNativeWorkerRuntimeUnavailable(
                "active selected PM runtime closure could not be independently re-observed") from None

    def verify_current(self, projection: RootActiveNativeWorkerRuntimeProjection
                       ) -> RootActiveNativeWorkerRuntimeProjection:
        self._require_live()
        if (type(projection) is not RootActiveNativeWorkerRuntimeProjection
                or projection._issuer is not self._issuer
                or self._issued.get(projection.projection_handle) is not projection
                or projection._custody.closed
                or projection.expires_monotonic <= time.monotonic()):
            raise ActiveNativeWorkerRuntimeUnavailable("active PM projection is foreign or stale")
        network = self._network_inputs.get(projection.projection_handle)
        if network is None:
            self.close()
            raise ActiveNativeWorkerRuntimeUnavailable("active network projection is no longer retained")
        current = self.resolve_current(network)
        try:
            if (current.runtime_record_id != projection.runtime_record_id
                    or current.runtime_record_sha256 != projection.runtime_record_sha256
                    or current.pm_runtime_receipt_handle != projection.pm_runtime_receipt_handle
                    or (current.pm_runtime_root_device, current.pm_runtime_root_inode)
                    != (projection.pm_runtime_root_device, projection.pm_runtime_root_inode)
                    or (current.native_output_root_device, current.native_output_root_inode)
                    != (projection.native_output_root_device, projection.native_output_root_inode)):
                self._retire(projection.projection_handle)
                raise ActiveNativeWorkerRuntimeUnavailable("active PM runtime projection changed")
        finally:
            self._retire(current.projection_handle)
        return projection

    def close(self) -> None:
        self._closed = True
        for handle in tuple(self._issued):
            self._retire(handle)

    def _retire(self, handle: str) -> None:
        projection = self._issued.pop(handle, None)
        self._network_inputs.pop(handle, None)
        if projection is not None:
            projection._custody.close()

    def _retire_projection(self, projection: RootActiveNativeWorkerRuntimeProjection) -> None:
        if (type(projection) is RootActiveNativeWorkerRuntimeProjection
                and projection._owner is self
                and self._issued.get(projection.projection_handle) is projection):
            self._retire(projection.projection_handle)
        else:
            projection._custody.close()

    def _prune_expired(self) -> None:
        now = time.monotonic()
        for handle, projection in tuple(self._issued.items()):
            if projection.expires_monotonic <= now:
                self._retire(handle)

    def _require_live(self) -> None:
        if self._closed:
            raise ActiveNativeWorkerRuntimeUnavailable("active PM observer is closed")
        if (self.runtime.service.root_authority_runtime is not self.runtime
                or self.runtime.service.root_runtime_bindings is not self.runtime.bindings):
            self.close()
            raise ActiveNativeWorkerRuntimeUnavailable("active root runtime identity changed")

    def _open_pm_members(self, row: Any, active: Any) -> tuple[list[int], tuple[int, int]]:
        from .pm_runtime import SOURCE_COMMIT, PYTHON_ID, PYTHON_SHA256
        bindings = self.runtime.bindings
        journal = bindings.resolve_root_journal(
            active["root_journal_id"],
            expected_active_generation_digest=bindings.enrollment_catalog.digest,
        )
        if journal.generation != active["root_journal_generation"]:
            raise ValueError("active journal generation changed")
        pm_root = journal.path / "pm-runtimes"
        root = _open_root_directory(pm_root)
        fds: list[int] = []
        keep_root = False
        try:
            root_info = os.fstat(root)
            receipts_fd = os.open("receipts", os.O_RDONLY | os.O_DIRECTORY
                                  | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
            try:
                receipts_info = os.fstat(receipts_fd)
                if (not stat.S_ISDIR(receipts_info.st_mode) or receipts_info.st_uid != 0
                        or receipts_info.st_gid != 0 or stat.S_IMODE(receipts_info.st_mode) != 0o700):
                    raise ValueError("PM receipt directory custody changed")
                receipt_name = row["pm_runtime_receipt_handle"] + ".json"
                receipt_fd = os.open(receipt_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=receipts_fd)
                path_receipt = os.stat(receipt_name, dir_fd=receipts_fd, follow_symlinks=False)
            finally:
                os.close(receipts_fd)
            fds.append(receipt_fd)
            receipt_info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(receipt_info.st_mode) or receipt_info.st_uid != 0
                    or receipt_info.st_gid != 0 or stat.S_IMODE(receipt_info.st_mode) != 0o600
                    or receipt_info.st_nlink != 1
                    or (receipt_info.st_dev, receipt_info.st_ino)
                       != (path_receipt.st_dev, path_receipt.st_ino)):
                raise ValueError("PM receipt file custody changed")
            raw = _read_fd(receipt_fd, 64 * 1024)
            receipt = json.loads(raw.decode("utf-8"))
            if (not isinstance(receipt, dict) or receipt.get("schema") != 1
                    or receipt.get("handle") != row["pm_runtime_receipt_handle"]
                    or receipt.get("source_commit") != SOURCE_COMMIT
                    or receipt.get("base_python_artifact_id") != PYTHON_ID
                    or receipt.get("base_python_sha256") != PYTHON_SHA256
                    or receipt.get("pm_sync_outcome") != "succeeded"
                    or not isinstance(receipt.get("generation"), str)
                    or not re.fullmatch(r"pm-[0-9a-f]{32}", receipt["generation"])
                    or receipt.get("setup_session_id") == ""
                    or receipt.get("transaction_handle") == ""):
                raise ValueError("PM receipt no longer matches the pinned runtime")
            base = pm_root / receipt["generation"]
            executable = base / receipt["runtime_relative"]
            runtime_root = executable.parent.parent
            from .pm_runtime import (
                _observe_runtime, _match_receipt,
            )
            identity = _observe_runtime(executable, expected_uid=0, expected_root=base)
            _match_receipt(receipt, executable, identity, runtime_root)
            self._match_committed_venv_identity(row, receipt, raw, identity, base, fds)
            base_tree = bindings.artifact_catalog.materialize_tree(
                PYTHON_ID, PYTHON_SHA256, self.runtime.enrollment.artifact_staging_directory,
                expected_uid=0,
            )
            if base_tree.path.relative_to(self.runtime.enrollment.artifact_staging_directory).as_posix() \
                    != receipt["base_python_tree_relative"]:
                raise ValueError("PM base tree path differs from receipt")
            spec = bindings.artifact_catalog.artifacts[PYTHON_ID]
            from .pm_runtime import _open_catalog_runtime_tree
            root_fd, members, closure = _open_catalog_runtime_tree(
                base_tree.path, spec.tree_files,
                expected_closure_sha256=receipt["base_python_closure_sha256"],
            )
            fds.append(root_fd)
            fds.extend(member.fd for member in members if member.fd is not None)
            observed = {member.relative_path: member for member in members}
            expected = row["pm_runtime_member_records"]
            if (not isinstance(expected, (list, tuple)) or closure != row["pm_base_closure_sha256"]
                    or len(expected) != len(observed)):
                raise ValueError("active PM member catalog is incomplete")
            for item in expected:
                member = observed.get(item["relative_path"])
                if (member is None or item["artifact_id"] != PYTHON_ID
                        or item["sha256"] != member.sha256
                        or item["size_bytes"] != member.size_bytes
                        or item["mode"] != member.mode or item["device"] != member.device
                        or item["inode"] != member.inode or item["owner_uid"] != member.uid
                        or item["owner_gid"] != member.gid
                        or item["kind"] != ("regular-file" if member.kind == "file" else "symlink")
                        or item["link_target"] != member.link_target):
                    raise ValueError("active PM member differs from held current descriptor")
            pm_executable = observed.get(row["pm_executable_relative_path"])
            if (row["pm_executable_relative_path"] != "bin/python3.14"
                    or pm_executable is None
                    or row["pm_executable_member_sha256"] != pm_executable.sha256
                    or row["pm_runtime_receipt_handle"] != receipt["handle"]
                    or any(item["receipt_handle"] != receipt["handle"] for item in expected)):
                raise ValueError("selected PM executable differs from active runtime record")
            # Output member custody is required before this projection can be
            # used by a worker manager. The sibling producer is materializing
            # those held receipts; no PM-only proof is sufficient for launch.
            if not row.get("native_output_member_records"):
                raise ValueError("active native output member custody is absent")
            fds.append(root)
            keep_root = True
            return fds, (root_info.st_dev, root_info.st_ino)
        except BaseException:
            for fd in set(fds + [root]):
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        finally:
            if not keep_root:
                try:
                    os.close(root)
                except OSError:
                    pass

    @staticmethod
    def _match_committed_venv_identity(row: Any, receipt: Any, raw_receipt: bytes,
                                       identity: Any, base: Path, held_fds: list[int]) -> None:
        """Recheck the v189 identity against receipt bytes and held full venv."""
        from .pm_runtime import observe_committed_pm_venv_tree

        descriptor = row.get("committed_venv_identity") if isinstance(row, Mapping) else None
        fields = {
            "schema", "identity_kind", "pm_runtime_receipt_handle", "pm_receipt_sha256",
            "pm_generation", "source_commit", "runtime_relative", "runtime_venv_relative",
            "runtime_closure_sha256", "executable_identity_id", "executable_sha256",
            "executable_device", "executable_inode", "executable_uid", "executable_gid",
            "executable_mode",
        }
        expected = {
            "schema": 1,
            "identity_kind": "pm-committed-hermes-venv-v1",
            "pm_runtime_receipt_handle": receipt.get("handle"),
            "pm_receipt_sha256": hashlib.sha256(raw_receipt).hexdigest(),
            "pm_generation": receipt.get("generation"),
            "source_commit": receipt.get("source_commit"),
            "runtime_relative": receipt.get("runtime_relative"),
            "runtime_venv_relative": receipt.get("runtime_venv_relative"),
            "runtime_closure_sha256": receipt.get("runtime_closure_sha256"),
            "executable_identity_id": "observed:pm-committed-venv-python",
            "executable_sha256": identity.get("sha256"),
            "executable_device": identity.get("device"),
            "executable_inode": identity.get("inode"),
            "executable_uid": identity.get("uid"),
            "executable_gid": identity.get("gid"),
            "executable_mode": identity.get("mode"),
        }
        if not isinstance(descriptor, Mapping) or set(descriptor) != fields or dict(descriptor) != expected:
            raise ValueError("committed PM executable descriptor differs from current signed receipt")
        relative = receipt.get("runtime_venv_relative")
        if not isinstance(relative, str) or not relative or relative.startswith("/"):
            raise ValueError("committed PM venv path is malformed")
        venv_root = base / relative
        observation = observe_committed_pm_venv_tree(
            venv_root, expected_closure_sha256=receipt["runtime_closure_sha256"],
        )
        held_fds.append(observation.root_fd)
        held_fds.extend(item.fd for item in observation.members if item.fd is not None)
        resolved = (base / receipt["runtime_relative"]).resolve(strict=True)
        try:
            executable_relative = resolved.relative_to(venv_root.resolve(strict=True)).as_posix()
        except ValueError:
            raise ValueError("committed PM executable resolves outside its venv") from None
        member = next((item for item in observation.members
                       if item.relative_path == executable_relative and item.kind == "file"), None)
        if (member is None or (member.device, member.inode, member.uid, member.gid,
                               member.mode, member.sha256)
                != (identity["device"], identity["inode"], identity["uid"], identity["gid"],
                    identity["mode"], identity["sha256"])):
            raise ValueError("committed PM executable is absent from held venv member closure")

    def _open_native_output_members(self, row: Any) -> tuple[list[int], tuple[int, int]]:
        """Reopen generated members from the root-private active materialization."""
        root_fd = parent_fd = generation_fd = receipt_fd = -1
        member_fds: list[int] = []
        try:
            staging_root = self.runtime.enrollment.artifact_staging_directory
            root_fd = os.open(staging_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            staging = os.fstat(root_fd)
            path_staging = staging_root.lstat()
            if ((staging.st_dev, staging.st_ino) != (path_staging.st_dev, path_staging.st_ino)
                    or staging.st_uid != 0 or staging.st_gid != 0
                    or stat.S_IMODE(staging.st_mode) != 0o700):
                raise ValueError("artifact staging root is not current root custody")
            parent_fd = os.open("native-worker-runtime", os.O_RDONLY | os.O_DIRECTORY
                                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
            parent = os.fstat(parent_fd)
            if (parent.st_uid != 0 or parent.st_gid != 0 or stat.S_IMODE(parent.st_mode) != 0o700):
                raise ValueError("native worker materialization root is not private")
            receipt_handle = row["owned_runtime_root_receipt_handle"]
            if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", receipt_handle):
                raise ValueError("native runtime root receipt handle is malformed")
            generation_fd = os.open(receipt_handle, os.O_RDONLY | os.O_DIRECTORY
                                    | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
            root_info = os.fstat(generation_fd)
            if (root_info.st_uid != 0 or root_info.st_gid != 0
                    or stat.S_IMODE(root_info.st_mode) != 0o700):
                raise ValueError("materialized native runtime root custody changed")
            receipt_fd = os.open("receipt.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=generation_fd)
            receipt_path_info = os.stat("receipt.json", dir_fd=generation_fd,
                                        follow_symlinks=False)
            receipt_info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(receipt_info.st_mode) or receipt_info.st_uid != 0
                    or receipt_info.st_gid != 0 or stat.S_IMODE(receipt_info.st_mode) != 0o600
                    or receipt_info.st_nlink != 1
                    or (receipt_info.st_dev, receipt_info.st_ino)
                       != (receipt_path_info.st_dev, receipt_path_info.st_ino)):
                raise ValueError("native runtime root receipt file custody changed")
            raw = _read_fd(receipt_fd, 4 * 1024 * 1024)
            parsed = json.loads(raw.decode("utf-8"))
            if (not isinstance(parsed, dict) or set(parsed) != {"body", "body_sha256"}
                    or parsed["body_sha256"] != row["owned_runtime_root_receipt_sha256"]
                    or _digest(parsed["body"]) != parsed["body_sha256"]):
                raise ValueError("native runtime materialization receipt digest changed")
            body = parsed["body"]
            if (body.get("receipt_handle") != receipt_handle
                    or body.get("profile_id") != row["profile_id"]
                    or body.get("profile_generation") != row["profile_generation"]
                    or body.get("source_choice_selection_handle")
                       != row["source_choice_selection_handle"]
                    or body.get("worker_recipe_sha256") != row["recipe_sha256"]
                    or body.get("pm_runtime_receipt_handle") != row["pm_runtime_receipt_handle"]
                    or body.get("runtime_root_device") != root_info.st_dev
                    or body.get("runtime_root_inode") != root_info.st_ino
                    or body.get("native_output_member_records")
                       != _plain(row["native_output_member_records"])
                    or body.get("pm_runtime_member_records")
                       != _plain(row["pm_runtime_member_records"])
                    or body.get("pm_runtime_receipt_handle") != row["pm_runtime_receipt_handle"]
                    or body.get("pm_base_closure_sha256") != row["pm_base_closure_sha256"]
                    or body.get("pm_executable_relative_path") != row["pm_executable_relative_path"]
                    or body.get("pm_executable_member_sha256") != row["pm_executable_member_sha256"]):
                raise ValueError("native runtime materialization body differs from active row")
            rows = row["native_output_member_records"]
            if (not isinstance(rows, (list, tuple)) or not rows or len(rows) > 8192
                    or len({item["relative_path"] for item in rows}) != len(rows)):
                raise ValueError("native runtime output member catalog is malformed")
            for item in rows:
                path_parts = _native_output_relative_parts(item["relative_path"])
                directory_fd = os.dup(generation_fd)
                try:
                    for segment in path_parts[:-1]:
                        next_fd = os.open(segment, os.O_RDONLY | os.O_DIRECTORY
                                          | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
                        os.close(directory_fd)
                        directory_fd = next_fd
                        directory_info = os.fstat(directory_fd)
                        if (directory_info.st_uid != 0 or directory_info.st_gid != 0
                                or stat.S_IMODE(directory_info.st_mode) != 0o755):
                            raise ValueError("native output member directory custody changed")
                    fd = os.open(path_parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=directory_fd)
                finally:
                    os.close(directory_fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                            stat.S_IMODE(info.st_mode), info.st_size)
                        != (item["device"], item["inode"], item["owner_uid"], item["owner_gid"],
                            item["mode"], item["size_bytes"])
                        or item["kind"] != "regular-file"
                        or item["output_role"] != path_parts[0]
                        or _hash_fd(fd) != item["sha256"]):
                    os.close(fd)
                    raise ValueError("native output file differs from held active member row")
                member_fds.append(fd)
            os.close(receipt_fd)
            receipt_fd = -1
            os.close(generation_fd)
            generation_fd = -1
            os.close(parent_fd)
            parent_fd = -1
            os.close(root_fd)
            root_fd = -1
            return member_fds, (root_info.st_dev, root_info.st_ino)
        except BaseException:
            for fd in member_fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise
        finally:
            for fd in (receipt_fd, generation_fd, parent_fd, root_fd):
                    if fd >= 0:
                        try:
                            os.close(fd)
                        except OSError:
                            pass

    def _open_source_definition_members(self, row: Any) -> list[int]:
        """Reopen recipe and installer source members from this daemon's held release."""
        from .installer_release import VerifiedInstallerReleaseReceipt

        release = getattr(self.runtime, "controller_release_receipt", None)
        records = row.get("source_definition_member_records")
        handles = row.get("source_member_receipt_handles")
        if type(release) is not VerifiedInstallerReleaseReceipt:
            raise ValueError("active worker source closure has no exact held release projection")
        _validate_source_member_catalog(records, handles)
        release.verify_current()
        indexed = {item.artifact_id: item for item in release.files}
        if len(indexed) != len(release.files):
            raise ValueError("held installer release has ambiguous artifact IDs")
        fds: list[int] = []
        try:
            seen: set[tuple[str, str]] = set()
            observed_handles: list[str] = []
            for item in records:
                key = (item["artifact_id"], item["relative_path"])
                if key in seen:
                    raise ValueError("active worker source member row is duplicated")
                seen.add(key)
                observed_handles.append(item["receipt_handle"])
                member = indexed.get(item["artifact_id"])
                if (member is None or member.relative_path != item["relative_path"]
                        or member.sha256 != item["sha256"] or member.size_bytes != item["size_bytes"]
                        or member.roles not in {("module",), ("source-module",)}):
                    raise ValueError("active worker source row differs from this installed release")
                fd = release.open_file(member.artifact_id)
                fds.append(fd)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode)
                        or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode), info.st_size,
                            info.st_dev, info.st_ino)
                        != (item["owner_uid"], item["owner_gid"], item["mode"], item["size_bytes"],
                            item["device"], item["inode"])
                        or _hash_fd(fd) != item["sha256"]):
                    raise ValueError("active worker source file changed after release observation")
            _validate_source_member_catalog(records, handles)
            if tuple(sorted(observed_handles)) != tuple(handles):
                raise ValueError("active worker source receipt handles do not join the signed catalog")
            release.verify_current()
            return fds
        except BaseException:
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise


def _open_root_directory(path: Path) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    info = os.fstat(fd)
    path_info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
        os.close(fd)
        raise ValueError("active PM runtime root is not protected")
    return fd


def _read_fd(fd: int, ceiling: int) -> bytes:
    chunks = bytearray()
    while len(chunks) <= ceiling:
        block = os.read(fd, min(4096, ceiling + 1 - len(chunks)))
        if not block:
            break
        chunks.extend(block)
    if len(chunks) > ceiling:
        raise ValueError("protected PM receipt exceeds size bound")
    return bytes(chunks)


def _plain(value: Any) -> Any:
    from collections.abc import Mapping
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _native_output_relative_parts(value: Any) -> tuple[str, ...]:
    if not isinstance(value, str) or len(value) > 4096 or "\\" in value:
        raise ValueError("native runtime member path is malformed")
    parts = tuple(value.split("/"))
    if (len(parts) < 2 or any(part in {"", ".", ".."} for part in parts)
            or parts[0] not in {
                "native-compiled-closure", "native-entrypoint-manifest",
                "native-action-resolver", "native-boundary-overlay", "native-candidate-index"}):
        raise ValueError("native runtime member escaped its fixed role root")
    return parts


def _validate_source_member_catalog(records: Any, handles: Any) -> None:
    required = {"artifact_id", "receipt_handle", "relative_path", "kind", "sha256",
                "size_bytes", "mode", "owner_uid", "owner_gid", "device", "inode",
                "link_target", "output_role"}
    if (not isinstance(records, (tuple, list)) or not records or len(records) > 128
            or not isinstance(handles, (tuple, list)) or not handles
            or len(handles) != len(records)
            or any(not isinstance(handle, str) or not handle for handle in handles)
            or tuple(handles) != tuple(sorted(handles)) or len(set(handles)) != len(handles)):
        raise ValueError("active worker source receipt handles are incomplete or unsorted")
    observed_handles: set[str] = set()
    seen_members: set[tuple[str, str]] = set()
    for item in records:
        if (not isinstance(item, dict) or set(item) != required
                or item["kind"] != "regular-file" or item["link_target"] is not None
                or item["output_role"] is not None
                or not isinstance(item["artifact_id"], str) or not item["artifact_id"]
                or not isinstance(item["relative_path"], str) or not item["relative_path"]
                or not isinstance(item["receipt_handle"], str) or not item["receipt_handle"]
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or any(type(item[name]) is not int or item[name] < 0 for name in
                       ("size_bytes", "mode", "owner_uid", "owner_gid", "device", "inode"))):
            raise ValueError("active worker source member row is malformed")
        key = (item["artifact_id"], item["relative_path"])
        if key in seen_members or item["receipt_handle"] in observed_handles:
            raise ValueError("active worker source member row or handle is duplicated")
        seen_members.add(key)
        observed_handles.add(item["receipt_handle"])
    if tuple(sorted(observed_handles)) != tuple(handles):
        raise ValueError("active worker source receipt handles do not join the signed catalog")


def _digest(value: Any) -> str:
    raw = json.dumps(_plain(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


_RUNTIME_SEAL = object()

__all__ = ["ActiveNativeWorkerRuntimeUnavailable", "RootActiveNativeWorkerRuntimeProjection",
           "RootActiveNativeWorkerRuntimeRegistry", "_validate_source_member_catalog"]
