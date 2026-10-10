"""Independent active-generation observation for the selected Hermes worker.

Setup PM receipts are deliberately not resolved through their expiring setup
registry here.  The active service-generation row is rejoined to the current
root journal and the receipt/file closure is reopened from that protected
location.  This first implementation covers the PM runtime closure; native
output member custody remains a required companion before a worker can launch.
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

from .types import AuthorityDenied


class ActiveNativeWorkerRuntimeUnavailable(AuthorityDenied):
    """The active selected worker runtime is incomplete or changed."""

    def __init__(self, message: str):
        super().__init__("native_worker.runtime", message)


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
    expires_monotonic: float
    member_fds: tuple[int, ...] = field(repr=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActiveNativeWorkerRuntimeProjection(<root-held PM closure>)"

    def close(self) -> None:
        for fd in set(self.member_fds):
            try:
                os.close(fd)
            except OSError:
                pass


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
                self.generation_owner.verify_current(network_projection)
                projection = RootActiveNativeWorkerRuntimeProjection(
                    projection_handle=secrets.token_urlsafe(32),
                    network_projection_handle=network_projection.projection_handle,
                    service_generation_digest=network_projection.service_generation_digest,
                    runtime_record_id=row["id"],
                    runtime_record_sha256=network_projection.active_record["worker_runtime_record_sha256"],
                    pm_runtime_receipt_handle=row["pm_runtime_receipt_handle"],
                    pm_runtime_root_device=root_identity[0], pm_runtime_root_inode=root_identity[1],
                    expires_monotonic=min(time.monotonic() + 30.0,
                                          network_projection.expires_monotonic),
                    member_fds=tuple(fds), _issuer=self._issuer,
                )
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
                    != (projection.pm_runtime_root_device, projection.pm_runtime_root_inode)):
                self._issued.pop(projection.projection_handle, None)
                raise ActiveNativeWorkerRuntimeUnavailable("active PM runtime projection changed")
        finally:
            current.close()
            self._issued.pop(current.projection_handle, None)
            self._network_inputs.pop(current.projection_handle, None)
        return projection

    def close(self) -> None:
        self._closed = True
        for projection in self._issued.values():
            projection.close()
        self._issued.clear()
        self._network_inputs.clear()

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
            from .pm_runtime import _observe_runtime, _match_receipt
            identity = _observe_runtime(executable, expected_uid=0, expected_root=base)
            _match_receipt(receipt, executable, identity, runtime_root)
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


def _digest(value: Any) -> str:
    raw = json.dumps(_plain(value), sort_keys=True, separators=(",", ":"),
                     ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


_RUNTIME_SEAL = object()

__all__ = ["ActiveNativeWorkerRuntimeUnavailable", "RootActiveNativeWorkerRuntimeProjection",
           "RootActiveNativeWorkerRuntimeRegistry"]
