"""Atomic root publication of a retained, verified installer release build.

The builder owns source/build provenance and holds the sealed output closure.
This module accepts only its opaque one-use handle and writes the two fixed
deployment locations consumed by :mod:`installer_release`.
"""
from __future__ import annotations

import fcntl
import base64
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from .installer_release import (DEPLOYMENT_RECEIPT_PATH, RELEASE_STORE_ROOT,
                                InstalledRootReleaseVerifier, MAX_FILES,
                                MAX_FILE_BYTES, MAX_MANIFEST_BYTES, MAX_RECEIPT_BYTES,
                                _artifact_id_for, _safe_relative, _unique_pairs,
                                _validate_fixed_layout_role)
from .installer_release_roles import RELEASE_MEMBER_ROLES

_RECEIPT_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
_MAX_RECORDS = 50_000
_UPDATE_TRANSACTION_ROOT = Path("/var/lib/hermes-installer/authority-journal/installer-update-transactions")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _gid(uid: int) -> int:
    return 0 if uid == 0 else os.getgid()


@dataclass(frozen=True, slots=True)
class _ReleaseRow:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    roles: tuple[str, ...]
    device: int
    inode: int


class RootInstalledStagePublisher:
    """Publish a root-retained build receipt to the fixed installed release store."""

    def __init__(self, builder: Any):
        from .installer_release_build import RootInstalledReleaseBuilder
        if not isinstance(builder, RootInstalledReleaseBuilder):
            raise ValueError("a typed root installed-release builder is required")
        self.builder = builder

    @classmethod
    def from_root_setup(cls, builder: Any) -> "RootInstalledStagePublisher":
        return cls(builder)

    def publish_installed_stage(self, release_build_receipt_handle: str, *,
                                update_transition: Any = None,
                                controller_snapshot: dict[str, Any] | None = None) -> Any:
        if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
            raise BootstrapEnrollmentPending("installed release publication requires the installed Linux root process")
        receipt = self.builder.resolve_build_receipt(release_build_receipt_handle, consume=False)
        receipt.verify_current()
        if update_transition is not None:
            from .installer_release_build import RootAdmittedInstallerUpdate
            if type(update_transition) is not RootAdmittedInstallerUpdate:
                raise BootstrapEnrollmentPending("publication requires the issuer's admitted update transition")
            update_transition.verify_current()
            if (update_transition.candidate_git_sha != receipt.candidate_git_sha
                    or receipt.deployment_predecessor != update_transition.deployment_predecessor()
                    or not isinstance(controller_snapshot, dict)):
                raise BootstrapEnrollmentPending("release build no longer matches the admitted update subject")
        predecessor = receipt.deployment_predecessor
        _publish_retained_build(
            receipt=receipt,
            release_root=RELEASE_STORE_ROOT / receipt.candidate_git_sha,
            receipt_path=DEPLOYMENT_RECEIPT_PATH,
            expected_uid=0,
            predecessor=predecessor,
            update_transition=update_transition,
            controller_snapshot=controller_snapshot,
        )
        # Verify through the same fixed-path verifier used by the stage-zero actor.
        installed = InstalledRootReleaseVerifier.verify_installed_release()
        receipt.verify_current()
        receipt.consume()
        return installed

    def rollback_installed_stage(self, update_transition: Any) -> Any:
        return self.rollback_owned_update(update_transition)

    @classmethod
    def rollback_owned_update(cls, update_transition: Any) -> Any:
        from .installer_release_build import RootAdmittedInstallerUpdate
        if (type(update_transition) is not RootAdmittedInstallerUpdate
                or update_transition._seal is None):
            raise BootstrapEnrollmentPending("rollback requires the issuer's installed update transition")
        snapshot = update_transition.snapshot()
        installed = _rollback_update_transaction(
            _UPDATE_TRANSACTION_ROOT, snapshot["update_transaction_handle"],
            DEPLOYMENT_RECEIPT_PATH, 0)
        if installed.release_commit != snapshot["pointer"]["candidate_git_sha"]:
            installed.close()
            raise BootstrapEnrollmentPending("rollback did not restore the exact verified predecessor")
        return installed


def _publish_retained_build(*, receipt: Any, release_root: Path, receipt_path: Path,
                            expected_uid: int, predecessor: Any,
                            update_transition: Any = None,
                            controller_snapshot: dict[str, Any] | None = None,
                            update_transaction_root: Path | None = None) -> None:
    """Filesystem core, parameterized only for nonprivileged temporary fixtures."""
    if (not release_root.is_absolute() or not receipt_path.is_absolute()
            or type(expected_uid) is not int or expected_uid < 0):
        raise BootstrapEnrollmentError("installed-stage publication paths or owner are invalid")
    candidate = receipt.candidate_git_sha
    if not isinstance(candidate, str) or len(candidate) != 40 or any(c not in "0123456789abcdef" for c in candidate):
        raise BootstrapEnrollmentError("build receipt candidate identity is malformed")
    receipt.verify_current()
    rows = _build_rows(receipt)
    manifest_path = receipt.closure_manifest_relative_path
    if (manifest_path != "release-manifest.json" or not _safe_relative(manifest_path)
            or manifest_path in {row.relative_path for row in rows}):
        raise BootstrapEnrollmentError("build receipt closure-manifest path is unsafe or collides")
    manifest = {"schema": 1, "candidate_git_sha": candidate,
                "files": [{"relative_path": row.relative_path, "sha256": row.sha256,
                           "size_bytes": row.size_bytes, "mode": row.mode,
                           "roles": list(row.roles)} for row in rows]}
    manifest_bytes = _canonical(manifest)
    if (len(manifest_bytes) > MAX_MANIFEST_BYTES
            or _sha(manifest_bytes) != receipt.role_closure_manifest_sha256):
        raise BootstrapEnrollmentError("builder role-closure digest differs from the fixed manifest")
    closure_digest = getattr(receipt, "closure_manifest_sha256", receipt.role_closure_manifest_sha256)
    if closure_digest != _sha(manifest_bytes):
        raise BootstrapEnrollmentError("builder closure-manifest digest differs from canonical role rows")
    if receipt.baseline_tree_sha256 != _expected_baseline_digest(rows):
        raise BootstrapEnrollmentError("build receipt baseline digest differs from its frozen file closure")
    if receipt.source_tree_sha256 == receipt.baseline_tree_sha256:
        # Distinct domains are expected in normal releases; equality is possible
        # cryptographically, but treating it as a policy error would be incorrect.
        pass
    update_record = None
    transaction = None
    if update_transition is not None:
        from .installer_release_build import RootAdmittedInstallerUpdate
        if type(update_transition) is not RootAdmittedInstallerUpdate:
            raise BootstrapEnrollmentPending("publisher requires the issuer's admitted update transition")
        update_transition.verify_current()
        if (update_transition.candidate_git_sha != candidate
                or predecessor != update_transition.deployment_predecessor()
                or not isinstance(controller_snapshot, dict)):
            raise BootstrapEnrollmentPending("publisher inputs differ from the admitted update transaction")
        update_snapshot = update_transition.snapshot()
        update_record = update_snapshot
    transaction_root = update_transaction_root or _UPDATE_TRANSACTION_ROOT
    if update_record is not None:
        _verify_update_transaction_root(transaction_root, expected_uid,
                                        allow_fixture=not (expected_uid == 0
                                                           and receipt_path == DEPLOYMENT_RECEIPT_PATH))
    fixed_root_publication = (
        release_root == RELEASE_STORE_ROOT / candidate
        and receipt_path == DEPLOYMENT_RECEIPT_PATH and expected_uid == 0)
    _verify_directory(receipt_path.parent, expected_uid, mode=None)
    if not fixed_root_publication:
        _verify_directory(release_root.parent, expected_uid, mode=None)
    lock_path = receipt_path.parent / ".publication.lock"
    lock_fd = _open_lock(lock_path, expected_uid)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        parent_info = os.stat(receipt_path.parent, follow_symlinks=False)
        try:
            _verify_predecessor(receipt_path, predecessor, expected_uid, parent_info)
        except BootstrapEnrollmentPending:
            if _already_published(receipt, receipt_path, release_root, manifest_bytes,
                                  expected_uid):
                return
            raise
        if fixed_root_publication:
            _ensure_fixed_release_store_root()
            _verify_directory(release_root.parent, expected_uid, mode=None)
        _recover_staging_journals(release_root.parent, receipt, manifest_bytes, expected_uid)
        _ensure_release(receipt, release_root, manifest_path, manifest_bytes, rows, expected_uid)
        receipt.verify_current()
        release_info = os.stat(release_root, follow_symlinks=False)
        record = {
            "schema": 1,
            "receipt_id": _new_receipt_id(),
            "candidate_git_sha": candidate,
            "release_root": str(release_root),
            "release_device": release_info.st_dev,
            "release_inode": release_info.st_ino,
            "closure_manifest_relative_path": manifest_path,
            "closure_manifest_sha256": _sha(manifest_bytes),
            "baseline_tree_sha256": receipt.baseline_tree_sha256,
            "published_monotonic": time.monotonic(),
        }
        raw = _canonical(record)
        if fixed_root_publication:
            verified = InstalledRootReleaseVerifier._mint_release(
                {**record, "_receipt_sha256": _sha(raw)}, expected_uid=0)
            verified.close()
        # Check exact prior inode/digest again immediately before pointer CAS.
        _verify_predecessor(receipt_path, predecessor, expected_uid, parent_info)
        transaction_handle = None
        transaction_bytes = None
        if update_record is not None:
            # The source-acquisition confirmation is the authority for the
            # pointer switch.  Its deadline is not extended by staging or by
            # this publisher; expiry leaves the predecessor pointer current.
            from .installer_release_build import _verify_current_selection_snapshot
            _verify_current_selection_snapshot(controller_snapshot, {
                "candidate_git_sha": candidate,
                "lifecycle_action": "update",
                "original_pid": controller_snapshot.get("controller_pid"),
                "original_start_ticks": controller_snapshot.get("controller_start_ticks"),
                "expires_monotonic": controller_snapshot.get("expires_monotonic"),
            })
            transaction_handle = update_record["update_transaction_handle"]
            old_pointer = update_record["pointer"]
            transaction = {
                "schema": 1,
                "state": "publication-prepared",
                "update_transaction_handle": transaction_handle,
                "candidate_git_sha": candidate,
                "selection_choice_sha256": update_record["selection_choice_sha256"],
                "controller": controller_snapshot,
                "old_pointer": old_pointer,
                "old_release": update_record["release"],
                "candidate_pointer_b64": base64.b64encode(raw).decode("ascii"),
                "candidate_pointer_sha256": _sha(raw),
                "candidate_release_root": str(release_root),
                "candidate_closure_manifest_sha256": _sha(manifest_bytes),
                "prepared_monotonic": time.monotonic(),
            }
            transaction_bytes = _write_update_transaction(
                transaction_root, transaction_handle, transaction, expected_uid)
        if update_record is not None:
            # Close the interval between durable rollback preparation and the
            # present-pointer CAS without refreshing or reconstructing intent.
            from .installer_release_build import _verify_current_selection_snapshot
            _verify_current_selection_snapshot(controller_snapshot, {
                "candidate_git_sha": candidate,
                "lifecycle_action": "update",
                "original_pid": controller_snapshot.get("controller_pid"),
                "original_start_ticks": controller_snapshot.get("controller_start_ticks"),
                "expires_monotonic": controller_snapshot.get("expires_monotonic"),
            })
        _replace_receipt(receipt_path, raw, expected_uid, predecessor)
        _fsync_dir(receipt_path.parent)
        if transaction is not None:
            try:
                published_raw, published_info = _read_record(receipt_path, expected_uid)
                if published_raw != raw:
                    raise BootstrapEnrollmentPending("published candidate pointer differs from its transaction")
                installed = InstalledRootReleaseVerifier.verify_installed_release()
                try:
                    if (installed.release_commit != candidate
                            or installed.closure_manifest_sha256 != _sha(manifest_bytes)):
                        raise BootstrapEnrollmentPending("published candidate closure failed exact verification")
                    installed.verify_current()
                finally:
                    installed.close()
                transaction["state"] = "pointer-published"
                transaction["candidate_pointer_device"] = published_info.st_dev
                transaction["candidate_pointer_inode"] = published_info.st_ino
                transaction["published_monotonic"] = time.monotonic()
                _replace_update_transaction(transaction_root, transaction_handle,
                                            transaction_bytes, transaction, expected_uid)
            except BaseException:
                # If the CAS did not happen (for example, controller expiry or
                # a write error), preserve the original failure and old pointer.
                # Roll back only after observing our exact candidate bytes live.
                try:
                    current_raw, _ = _read_record(receipt_path, expected_uid)
                except BaseException:
                    current_raw = None
                if current_raw == raw:
                    _rollback_update_transaction(
                        transaction_root, transaction_handle, receipt_path, expected_uid,
                        expected_current_bytes=raw, lock_is_held=True)
                raise
    finally:
        os.close(lock_fd)


def _build_rows(receipt: Any) -> tuple[_ReleaseRow, ...]:
    files = receipt.files
    if not isinstance(files, tuple) or not files or len(files) > MAX_FILES:
        raise BootstrapEnrollmentError("build receipt file closure is empty or oversized")
    rows: list[_ReleaseRow] = []
    previous = ""
    for entry in files:
        path, digest, size, mode, roles = (entry.relative_path, entry.sha256,
                                           entry.size_bytes, entry.mode, entry.roles)
        if (not _safe_relative(path) or path <= previous or not isinstance(digest, str)
                or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                or type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or type(mode) is not int or mode & ~0o777 or mode & 0o022
                or not isinstance(roles, tuple) or not roles
                or any(not isinstance(role, str) for role in roles)
                or tuple(sorted(set(roles))) != roles
                or any(role not in RELEASE_MEMBER_ROLES for role in roles)):
            raise BootstrapEnrollmentError("build receipt contains a malformed closure row")
        _validate_fixed_layout_role(path, digest, size, list(roles), mode=mode)
        artifact_id = _artifact_id_for(path, list(roles))
        if not artifact_id:
            raise BootstrapEnrollmentError("build receipt role mapping is invalid")
        previous = path
        device, inode = entry.device, entry.inode
        if type(device) is not int or device < 0 or type(inode) is not int or inode <= 0:
            raise BootstrapEnrollmentError("build receipt source file identity is malformed")
        rows.append(_ReleaseRow(path, digest, size, mode, roles, device, inode))
    return tuple(rows)


def _expected_baseline_digest(rows: Iterable[_ReleaseRow]) -> str:
    prefix = "plans/2026-10-09-v1/"
    baseline = {row.relative_path[len(prefix):]: row.sha256 for row in rows
                if row.relative_path.startswith(prefix) and row.roles == ("baseline",)}
    if not baseline:
        raise BootstrapEnrollmentError("build receipt lacks the frozen baseline closure")
    return _sha(_canonical(baseline))


def _ensure_release(receipt: Any, final: Path, manifest_path: str,
                    manifest_bytes: bytes, rows: tuple[_ReleaseRow, ...], uid: int) -> None:
    try:
        info = os.stat(final, follow_symlinks=False)
    except FileNotFoundError:
        info = None
    if info is not None:
        _verify_existing_release(final, receipt, manifest_path, manifest_bytes, rows, uid)
        return
    receipt_id = receipt.receipt_handle
    if not isinstance(receipt_id, str) or not receipt_id or len(receipt_id) > 128:
        raise BootstrapEnrollmentError("build receipt has no stable staging identity")
    prefix = f".stage-{receipt.candidate_git_sha}-{_sha(receipt_id.encode())[:16]}-"
    stage = final.parent / (prefix + secrets.token_hex(12))
    journal = Path(str(stage) + ".journal.json")
    journal_bytes = _canonical({"schema": 1, "candidate_git_sha": receipt.candidate_git_sha,
                                "build_receipt_handle": receipt_id,
                                "manifest_sha256": _sha(manifest_bytes),
                                "stage_name": stage.name})
    _atomic_create_file(journal, journal_bytes, uid, 0o600)
    journal_info = os.stat(journal, follow_symlinks=False)
    try:
        os.mkdir(stage, 0o700)
    except Exception:
        _unlink_owned_file(journal, uid, (journal_info.st_dev, journal_info.st_ino))
        raise
    try:
        root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for row in rows:
                _copy_file(receipt, root_fd, row, uid)
            _write_relative(root_fd, manifest_path, manifest_bytes, uid, 0o444)
            _seal_tree(root_fd, uid)
            os.fsync(root_fd)
            stage_info = os.fstat(root_fd)
        finally:
            os.close(root_fd)
        try:
            _rename_noreplace(stage, final)
        except FileExistsError:
            _verify_existing_release(final, receipt, manifest_path, manifest_bytes, rows, uid)
            _remove_owned_stage(stage, uid)
            _unlink_owned_file(journal, uid, (journal_info.st_dev, journal_info.st_ino))
        else:
            _fsync_dir(final.parent)
            installed = os.stat(final, follow_symlinks=False)
            if (installed.st_dev, installed.st_ino) != (stage_info.st_dev, stage_info.st_ino):
                raise BootstrapEnrollmentError("installed release identity changed during atomic rename")
            _unlink_owned_file(journal, uid, (journal_info.st_dev, journal_info.st_ino))
    except Exception:
        try:
            _remove_owned_stage(stage, uid)
        except FileNotFoundError:
            pass
        raise


def _recover_staging_journals(parent: Path, receipt: Any, manifest_bytes: bytes, uid: int) -> None:
    """Remove only stages named by this same retained one-use build receipt."""
    receipt_id = receipt.receipt_handle
    prefix = f".stage-{receipt.candidate_git_sha}-{_sha(receipt_id.encode())[:16]}-"
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with os.scandir(os.dup(parent_fd)) as entries:
            for entry in entries:
                name = entry.name
                if not name.startswith(prefix) or not name.endswith(".journal.json"):
                    continue
                info = entry.stat(follow_symlinks=False)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                    raise BootstrapEnrollmentPending("matching release staging journal has unsafe custody")
                raw, _ = _read_record_bytes(parent_fd, name, uid, 4096)
                try:
                    journal = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
                except (UnicodeError, ValueError, json.JSONDecodeError):
                    raise BootstrapEnrollmentPending("matching release staging journal is malformed") from None
                if (not isinstance(journal, dict)
                        or set(journal) != {"schema", "candidate_git_sha", "build_receipt_handle",
                                            "manifest_sha256", "stage_name"}
                        or journal.get("schema") != 1
                        or journal.get("candidate_git_sha") != receipt.candidate_git_sha
                        or journal.get("build_receipt_handle") != receipt_id
                        or journal.get("manifest_sha256") != _sha(manifest_bytes)
                        or not isinstance(journal.get("stage_name"), str)
                        or not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{24}", journal["stage_name"])
                        or name != journal["stage_name"] + ".journal.json"):
                    raise BootstrapEnrollmentPending("release staging journal differs from the retained build receipt")
                if raw != _canonical(journal):
                    raise BootstrapEnrollmentPending("release staging journal is not canonical JSON")
                stage = parent / journal["stage_name"]
                try:
                    stage_info = os.stat(stage, follow_symlinks=False)
                except FileNotFoundError:
                    stage_info = None
                if stage_info is not None:
                    if (not stat.S_ISDIR(stage_info.st_mode) or stage_info.st_uid != uid
                            or stage_info.st_gid != _gid(uid) or stage_info.st_dev != info.st_dev):
                        raise BootstrapEnrollmentPending("journaled release stage has foreign filesystem custody")
                    _remove_owned_stage(stage, uid)
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _copy_file(receipt: Any, root_fd: int, row: _ReleaseRow, uid: int) -> None:
    src_fd = receipt.open_file(row.relative_path)
    try:
        src_info = os.fstat(src_fd)
        if (not stat.S_ISREG(src_info.st_mode) or src_info.st_uid != uid
                or src_info.st_gid != _gid(uid) or src_info.st_nlink != 1
                or src_info.st_size != row.size_bytes or stat.S_IMODE(src_info.st_mode) != row.mode
                or (src_info.st_dev, src_info.st_ino) != (row.device, row.inode)):
            raise BootstrapEnrollmentError("retained build output custody differs from its closure row")
        _copy_fd_to_relative(root_fd, row.relative_path, src_fd, row, uid)
    finally:
        os.close(src_fd)


def _copy_fd_to_relative(root_fd: int, relative: str, source_fd: int,
                          row: _ReleaseRow, uid: int) -> None:
    parent_fd = _open_parent(root_fd, relative, create=True, uid=uid)
    try:
        fd = os.open(relative.rsplit("/", 1)[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, row.mode, dir_fd=parent_fd)
        try:
            source_hash = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > row.size_bytes:
                    raise BootstrapEnrollmentError("retained build output exceeds its sealed size")
                source_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short write while staging installer release")
                    view = view[count:]
            info = os.fstat(fd)
            if (total != row.size_bytes or source_hash.hexdigest() != row.sha256
                    or info.st_uid != uid or info.st_gid != _gid(uid) or info.st_nlink != 1):
                raise BootstrapEnrollmentError("staged build output differs from its sealed closure")
            os.fchmod(fd, row.mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_relative(root_fd: int, relative: str, data: bytes, uid: int, mode: int) -> None:
    parent_fd = _open_parent(root_fd, relative, create=True, uid=uid)
    try:
        fd = os.open(relative.rsplit("/", 1)[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=parent_fd)
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    raise OSError("short write while writing release manifest")
                view = view[n:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _open_parent(root_fd: int, relative: str, *, create: bool, uid: int) -> int:
    if not _safe_relative(relative):
        raise BootstrapEnrollmentError("release path is not a safe relative path")
    parts = relative.split("/")[:-1]
    fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=fd)
                os.fsync(fd)
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                os.O_CLOEXEC, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != uid or info.st_gid != _gid(uid):
                raise BootstrapEnrollmentError("release staging directory ownership differs")
        return fd
    except Exception:
        os.close(fd)
        raise


def _verify_existing_release(final: Path, receipt: Any, manifest_path: str,
                             manifest_bytes: bytes, rows: tuple[_ReleaseRow, ...], uid: int) -> None:
    root_fd = os.open(final, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        root = os.fstat(root_fd)
        if (root.st_uid != uid or root.st_gid != _gid(uid)
                or stat.S_IMODE(root.st_mode) != 0o555):
            raise BootstrapEnrollmentError("existing release candidate has unsafe ownership or mode")
        expected: dict[str, tuple[str, int, int]] = {
            row.relative_path: (row.sha256, row.size_bytes, row.mode) for row in rows}
        expected[manifest_path] = (_sha(manifest_bytes), len(manifest_bytes), 0o444)
        found: set[str] = set()

        def walk(fd: int, prefix: str) -> None:
            with os.scandir(os.dup(fd)) as entries:
                for entry in entries:
                    relative = f"{prefix}/{entry.name}" if prefix else entry.name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        if (info.st_uid != uid or info.st_gid != _gid(uid) or info.st_dev != root.st_dev
                                or stat.S_IMODE(info.st_mode) != 0o555):
                            raise BootstrapEnrollmentError("existing release directory custody differs")
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                        os.O_CLOEXEC, dir_fd=fd)
                        try:
                            walk(child, relative)
                        finally:
                            os.close(child)
                    elif (stat.S_ISREG(info.st_mode) and info.st_uid == uid
                          and info.st_gid == _gid(uid) and info.st_dev == root.st_dev
                          and info.st_nlink == 1):
                        expected_row = expected.get(relative)
                        if expected_row is None or stat.S_IMODE(info.st_mode) != expected_row[2] or info.st_size != expected_row[1]:
                            raise BootstrapEnrollmentError("existing release contains an unlisted or changed file")
                        file_fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            if _hash_fd(file_fd) != expected_row[0]:
                                raise BootstrapEnrollmentError("existing release bytes differ from retained build")
                        finally:
                            os.close(file_fd)
                        found.add(relative)
                    else:
                        raise BootstrapEnrollmentError("existing release contains an unsafe filesystem entry")
        walk(root_fd, "")
        if found != set(expected):
            raise BootstrapEnrollmentError("existing release does not match the complete build closure")
    finally:
        os.close(root_fd)


def _verify_predecessor(path: Path, predecessor: Any, uid: int,
                        parent_info: os.stat_result) -> None:
    if ((parent_info.st_dev, parent_info.st_ino)
            != (predecessor.parent_device, predecessor.parent_inode)):
        raise BootstrapEnrollmentPending("deployment receipt parent changed after build authorization")
    try:
        raw, info = _read_record(path, uid)
    except FileNotFoundError:
        if predecessor.state != "absent":
            raise BootstrapEnrollmentPending("deployment receipt disappeared after build authorization") from None
        return
    try:
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError):
        raise BootstrapEnrollmentError("current deployment receipt is malformed") from None
    receipt_fields = {"schema", "receipt_id", "candidate_git_sha", "release_root",
                      "release_device", "release_inode", "closure_manifest_relative_path",
                      "closure_manifest_sha256", "baseline_tree_sha256", "published_monotonic"}
    if (predecessor.state != "present" or _sha(raw) != predecessor.sha256
            or (info.st_dev, info.st_ino) != (predecessor.device, predecessor.inode)
            or not isinstance(record, dict) or set(record) != receipt_fields
            or record.get("schema") != 1 or record.get("candidate_git_sha") != predecessor.candidate_git_sha
            or raw != _canonical(record)):
        raise BootstrapEnrollmentPending("deployment receipt changed after build authorization")


def _already_published(receipt: Any, receipt_path: Path, release_root: Path,
                       manifest_bytes: bytes, uid: int) -> bool:
    """Recover the crash window after pointer replace and before handle consumption."""
    if receipt_path != DEPLOYMENT_RECEIPT_PATH or release_root != RELEASE_STORE_ROOT / receipt.candidate_git_sha or uid != 0:
        return False
    try:
        record = InstalledRootReleaseVerifier._load_deployment_receipt(receipt_path,
                                                                       expected_uid=uid)
        installed = InstalledRootReleaseVerifier._mint_release(record, expected_uid=uid)
    except (BootstrapEnrollmentError, BootstrapEnrollmentPending, OSError):
        return False
    try:
        return (installed.release_commit == receipt.candidate_git_sha
                and installed.closure_manifest_relative_path == receipt.closure_manifest_relative_path
                and installed.closure_manifest_sha256 == _sha(manifest_bytes)
                and installed.baseline_tree_sha256 == receipt.baseline_tree_sha256)
    finally:
        installed.close()


def _verify_update_transaction_root(path: Path, uid: int, *, allow_fixture: bool) -> None:
    if not path.is_absolute() or type(uid) is not int or uid < 0:
        raise BootstrapEnrollmentError("update transaction root identity is invalid")
    if path == _UPDATE_TRANSACTION_ROOT:
        parent = path.parent
        _verify_directory(parent, uid, mode=0o700)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        _verify_directory(path, uid, mode=0o700)
        return
    if not allow_fixture:
        raise BootstrapEnrollmentError("update transaction root is fixed by installed policy")
    _verify_directory(path, uid, mode=0o700)


def _update_record_name(handle: str) -> str:
    if not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle):
        raise BootstrapEnrollmentError("update transaction handle is malformed")
    return handle + ".json"


def _write_update_transaction(root: Path, handle: str, value: dict[str, Any], uid: int) -> bytes:
    _verify_update_transaction_root(root, uid, allow_fixture=root != _UPDATE_TRANSACTION_ROOT)
    raw = _canonical(value)
    if len(raw) > 2 * 1024 * 1024:
        raise BootstrapEnrollmentError("update transaction exceeds its fixed record bound")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        name = _update_record_name(handle)
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise BootstrapEnrollmentPending("update transaction handle already exists")
        temporary = ".tmp-" + secrets.token_hex(16)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=root_fd)
        try:
            view = memoryview(raw)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short write to update transaction")
                view = view[count:]
            os.fchown(fd, uid, _gid(uid)); os.fchmod(fd, 0o600); os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(temporary, name, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        return raw
    finally:
        os.close(root_fd)


def _read_update_transaction(root: Path, handle: str, uid: int) -> tuple[dict[str, Any], bytes]:
    _verify_update_transaction_root(root, uid, allow_fixture=root != _UPDATE_TRANSACTION_ROOT)
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(_update_record_name(handle), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 2 * 1024 * 1024):
                raise BootstrapEnrollmentError("update transaction custody is invalid")
            raw = os.read(fd, info.st_size + 1)
            if len(raw) != info.st_size:
                raise BootstrapEnrollmentError("update transaction changed during read")
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError):
        raise BootstrapEnrollmentError("update transaction record is malformed") from None
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise BootstrapEnrollmentError("update transaction is not canonical")
    return value, raw


def _replace_update_transaction(root: Path, handle: str, expected_raw: bytes,
                                value: dict[str, Any], uid: int) -> bytes:
    current, raw = _read_update_transaction(root, handle, uid)
    if raw != expected_raw:
        raise BootstrapEnrollmentPending("update transaction changed before its state transition")
    updated = _canonical(value)
    if len(updated) > 2 * 1024 * 1024:
        raise BootstrapEnrollmentError("update transaction exceeds its fixed record bound")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = ".tmp-" + secrets.token_hex(16)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=root_fd)
        try:
            view = memoryview(updated)
            while view:
                count = os.write(fd, view)
                if count <= 0:
                    raise OSError("short update transaction state write")
                view = view[count:]
            os.fchown(fd, uid, _gid(uid)); os.fchmod(fd, 0o600); os.fsync(fd)
        finally:
            os.close(fd)
        # Recheck exact inode/bytes immediately before replacing the record.
        verify, verify_raw = _read_update_transaction(root, handle, uid)
        if verify_raw != expected_raw or verify != current:
            raise BootstrapEnrollmentPending("update transaction changed before state replacement")
        os.rename(temporary, _update_record_name(handle), src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        return updated
    finally:
        try:
            os.unlink(temporary, dir_fd=root_fd)
        except FileNotFoundError:
            pass
        os.close(root_fd)


def _rollback_update_transaction(root: Path, handle: str, receipt_path: Path, uid: int,
                                 *, expected_current_bytes: bytes | None = None,
                                 lock_is_held: bool = False) -> Any:
    transaction, transaction_raw = _read_update_transaction(root, handle, uid)
    if (transaction.get("schema") != 1 or transaction.get("update_transaction_handle") != handle
            or transaction.get("state") not in {"publication-prepared", "pointer-published"}):
        raise BootstrapEnrollmentPending("update transaction is not recoverable for rollback")
    candidate_raw = base64.b64decode(transaction.get("candidate_pointer_b64", ""), validate=True)
    if expected_current_bytes is not None and candidate_raw != expected_current_bytes:
        raise BootstrapEnrollmentError("rollback expected pointer does not match its transaction")
    lock_fd = -1
    if not lock_is_held:
        lock_fd = _open_lock(receipt_path.parent / ".publication.lock", uid)
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
    try:
        current_raw, current_info = _read_record(receipt_path, uid)
        if current_raw != candidate_raw or _sha(current_raw) != transaction.get("candidate_pointer_sha256"):
            raise BootstrapEnrollmentPending("a newer or foreign deployment pointer prevents update rollback")
        if (transaction.get("candidate_pointer_device") is not None
                and (current_info.st_dev, current_info.st_ino)
                != (transaction.get("candidate_pointer_device"), transaction.get("candidate_pointer_inode"))):
            raise BootstrapEnrollmentPending("published candidate pointer identity changed before rollback")
        from .installer_release_build import DeploymentPredecessor
        parent = os.stat(receipt_path.parent, follow_symlinks=False)
        candidate_record = json.loads(current_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        candidate = DeploymentPredecessor("present", parent.st_dev, parent.st_ino,
                                          _sha(current_raw), current_info.st_dev, current_info.st_ino,
                                          candidate_record["candidate_git_sha"])
        # The candidate may be the object that failed post-CAS verification.
        # Do not require its closure to be healthy before restoring the old
        # release; the exact protected transaction bytes plus current pointer
        # CAS identify only this publisher's write. Validate the pointer's
        # immutable transaction fields, then independently verify the old
        # release closure below before replacement.
        if (not isinstance(candidate_record, dict)
                or candidate_record.get("candidate_git_sha") != transaction.get("candidate_git_sha")
                or candidate_record.get("release_root") != transaction.get("candidate_release_root")
                or candidate_record.get("closure_manifest_sha256")
                != transaction.get("candidate_closure_manifest_sha256")):
            raise BootstrapEnrollmentPending("candidate pointer no longer matches its owned update transaction")
        old_pointer = transaction.get("old_pointer")
        old_release_projection = transaction.get("old_release")
        if not isinstance(old_pointer, dict) or not isinstance(old_release_projection, dict):
            raise BootstrapEnrollmentError("update rollback record lacks its predecessor proof")
        old_raw = base64.b64decode(old_pointer.get("canonical_bytes_b64", ""), validate=True)
        if (not old_raw or _sha(old_raw) != old_pointer.get("sha256")
                or len(old_raw) > MAX_RECEIPT_BYTES):
            raise BootstrapEnrollmentError("update rollback predecessor bytes are invalid")
        old_record = json.loads(old_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        old_verified = InstalledRootReleaseVerifier._mint_release(
            {**old_record, "_receipt_sha256": _sha(old_raw)}, expected_uid=uid)
        try:
            if (old_verified.release_commit != old_pointer.get("candidate_git_sha")
                    or old_verified.root_device != old_release_projection.get("root_device")
                    or old_verified.root_inode != old_release_projection.get("root_inode")
                    or old_verified.closure_manifest_sha256
                    != old_release_projection.get("closure_manifest_sha256")
                    or old_verified.baseline_tree_sha256
                    != old_release_projection.get("baseline_tree_sha256")
                    or old_verified.amendment_manifest_sha256
                    != old_release_projection.get("amendment_manifest_sha256")):
                raise BootstrapEnrollmentPending("verified rollback predecessor closure changed")
            old_verified.verify_current()
        finally:
            old_verified.close()
        _replace_receipt(receipt_path, old_raw, uid, candidate)
        _fsync_dir(receipt_path.parent)
        restored_raw, restored_info = _read_record(receipt_path, uid)
        if restored_raw != old_raw:
            raise BootstrapEnrollmentPending("rollback did not restore the exact predecessor pointer bytes")
        restored = InstalledRootReleaseVerifier.verify_installed_release()
        if (restored.release_commit != old_pointer.get("candidate_git_sha")
                or restored.deployment_receipt_sha256 != _sha(old_raw)):
            restored.close()
            raise BootstrapEnrollmentPending("restored predecessor pointer does not resolve to the old release")
        transaction["state"] = "rolled-back"
        transaction["restored_pointer_device"] = restored_info.st_dev
        transaction["restored_pointer_inode"] = restored_info.st_ino
        transaction["rolled_back_monotonic"] = time.monotonic()
        _replace_update_transaction(root, handle, transaction_raw, transaction, uid)
        return restored
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)


def _verify_published_update_transaction(handle: str) -> dict[str, Any]:
    transaction, _ = _read_update_transaction(_UPDATE_TRANSACTION_ROOT, handle, 0)
    if (transaction.get("schema") != 1
            or transaction.get("update_transaction_handle") != handle
            or transaction.get("state") not in {
                "publication-prepared", "pointer-published", "runtime-update-pending"}):
        raise BootstrapEnrollmentPending("installed update transaction is not in a published phase")
    candidate_raw = base64.b64decode(transaction.get("candidate_pointer_b64", ""), validate=True)
    current_raw, current_info = _read_record(DEPLOYMENT_RECEIPT_PATH, 0)
    if (current_raw != candidate_raw
            or _sha(current_raw) != transaction.get("candidate_pointer_sha256")
            or transaction.get("candidate_pointer_device") is not None
            and (current_info.st_dev, current_info.st_ino)
            != (transaction.get("candidate_pointer_device"), transaction.get("candidate_pointer_inode"))):
        raise BootstrapEnrollmentPending("installed candidate pointer changed after update publication")
    installed = InstalledRootReleaseVerifier.verify_installed_release()
    try:
        if (installed.release_commit != transaction.get("candidate_git_sha")
                or installed.closure_manifest_sha256
                != transaction.get("candidate_closure_manifest_sha256")):
            raise BootstrapEnrollmentPending("installed candidate closure no longer matches its update")
        installed.verify_current()
    finally:
        installed.close()
    old_pointer = transaction.get("old_pointer")
    old_projection = transaction.get("old_release")
    if not isinstance(old_pointer, dict) or not isinstance(old_projection, dict):
        raise BootstrapEnrollmentError("published update transaction lost its verified predecessor")
    old_raw = base64.b64decode(old_pointer.get("canonical_bytes_b64", ""), validate=True)
    if _sha(old_raw) != old_pointer.get("sha256"):
        raise BootstrapEnrollmentError("published update predecessor bytes no longer match")
    old_record = json.loads(old_raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    previous = InstalledRootReleaseVerifier._mint_release(
        {**old_record, "_receipt_sha256": _sha(old_raw)}, expected_uid=0)
    try:
        if (previous.release_commit != old_pointer.get("candidate_git_sha")
                or previous.closure_manifest_sha256 != old_projection.get("closure_manifest_sha256")
                or previous.root_device != old_projection.get("root_device")
                or previous.root_inode != old_projection.get("root_inode")):
            raise BootstrapEnrollmentPending("published update predecessor closure is not retained")
        previous.verify_current()
    finally:
        previous.close()
    return transaction


def _mark_runtime_update_pending(handle: str) -> None:
    transaction = _verify_published_update_transaction(handle)
    if transaction.get("state") == "runtime-update-pending":
        raise BootstrapEnrollmentPending("installed update intent was already consumed")
    current, raw = _read_update_transaction(_UPDATE_TRANSACTION_ROOT, handle, 0)
    if current != transaction:
        raise BootstrapEnrollmentPending("installed update transaction changed before intent consumption")
    current["state"] = "runtime-update-pending"
    current["runtime_pending_monotonic"] = time.monotonic()
    _replace_update_transaction(_UPDATE_TRANSACTION_ROOT, handle, raw, current, 0)


def _read_record(path: Path, uid: int) -> tuple[bytes, os.stat_result]:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > MAX_RECEIPT_BYTES):
                raise BootstrapEnrollmentError("current deployment receipt custody is unsafe")
            data = bytearray()
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                data.extend(block)
                if len(data) > MAX_RECEIPT_BYTES:
                    raise BootstrapEnrollmentError("deployment receipt exceeds its size bound")
            return bytes(data), info
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _read_record_bytes(parent_fd: int, name: str, uid: int,
                       maximum: int) -> tuple[bytes, os.stat_result]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size > maximum):
            raise BootstrapEnrollmentPending("release staging journal file custody is unsafe")
        data = bytearray()
        while True:
            block = os.read(fd, 4096)
            if not block:
                break
            data.extend(block)
            if len(data) > maximum:
                raise BootstrapEnrollmentPending("release staging journal exceeds its size bound")
        return bytes(data), info
    finally:
        os.close(fd)


def _atomic_create_file(path: Path, data: bytes, uid: int, mode: int) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        _write_at(parent_fd, path.name, data, uid, mode)
        os.fsync(parent_fd)
    except FileExistsError:
        raise BootstrapEnrollmentPending("release staging journal already exists") from None
    finally:
        os.close(parent_fd)


def _unlink_owned_file(path: Path, uid: int, expected_identity: tuple[int, int]) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
                or info.st_nlink != 1 or (info.st_dev, info.st_ino) != expected_identity):
            raise BootstrapEnrollmentPending("release staging journal changed before cleanup")
        os.unlink(path.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _replace_receipt(path: Path, data: bytes, uid: int, predecessor: Any) -> None:
    parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    stage = ".current.json.stage-" + secrets.token_hex(12)
    try:
        parent_info = os.fstat(parent_fd)
        if (parent_info.st_dev, parent_info.st_ino) != (predecessor.parent_device,
                                                        predecessor.parent_inode):
            raise BootstrapEnrollmentPending("deployment parent changed during pointer CAS")
        _write_at(parent_fd, stage, data, uid, 0o600)
        os.fsync(parent_fd)
        try:
            current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current = None
        if predecessor.state == "absent":
            if current is not None:
                raise BootstrapEnrollmentPending("deployment pointer appeared before initial CAS")
            try:
                os.link(stage, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            except FileExistsError:
                raise BootstrapEnrollmentPending("deployment pointer appeared during initial CAS") from None
            os.unlink(stage, dir_fd=parent_fd)
        else:
            if (current is None or (current.st_dev, current.st_ino) !=
                    (predecessor.device, predecessor.inode)):
                raise BootstrapEnrollmentPending("deployment pointer inode changed before CAS")
            current_bytes, current_info = _read_record(path, uid)
            if (_sha(current_bytes) != predecessor.sha256
                    or (current_info.st_dev, current_info.st_ino) !=
                    (predecessor.device, predecessor.inode)):
                raise BootstrapEnrollmentPending("deployment pointer content changed before CAS")
            os.replace(stage, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        try:
            os.unlink(stage, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _write_at(parent_fd: int, name: str, data: bytes, uid: int, mode: int) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=parent_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or info.st_gid != _gid(uid) or info.st_nlink != 1):
            raise BootstrapEnrollmentError("deployment receipt stage is not owned regular file")
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write while publishing deployment receipt")
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _verify_directory(path: Path, uid: int, mode: int | None) -> os.stat_result:
    if not path.is_absolute():
        raise BootstrapEnrollmentError("fixed deployment directory is not absolute")
    strict_chain = uid == 0 and path in {DEPLOYMENT_RECEIPT_PATH.parent, RELEASE_STORE_ROOT}
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for index, part in enumerate(path.parts[1:]):
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            final = index == len(path.parts[1:]) - 1
            if (not stat.S_ISDIR(info.st_mode)
                    or final and (info.st_uid != uid or info.st_gid != _gid(uid)
                                  or stat.S_IMODE(info.st_mode) & 0o022
                                  or mode is not None and stat.S_IMODE(info.st_mode) != mode)
                    or strict_chain and (info.st_uid != 0 or info.st_gid != 0
                                         or stat.S_IMODE(info.st_mode) & 0o022)):
                raise BootstrapEnrollmentError("fixed deployment directory custody is unsafe")
        info = os.fstat(fd)
        if path == Path("/") and (info.st_uid != uid or info.st_gid != _gid(uid)):
            raise BootstrapEnrollmentError("deployment root directory ownership differs")
        return info
    finally:
        os.close(fd)


def _ensure_fixed_release_store_root() -> None:
    """Create only the fixed release-store children below verified /usr/lib."""
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent_fd = _open_owned_directory_chain(fd, ("usr", "lib"),
                                                expected_uid=0, expected_gid=0)
    finally:
        os.close(fd)
    try:
        _ensure_release_store_children(parent_fd, expected_uid=0, expected_gid=0)
    finally:
        os.close(parent_fd)


def _open_owned_directory_chain(parent_fd: int, components: tuple[str, ...], *,
                                expected_uid: int, expected_gid: int) -> int:
    """Open a finite directory chain without following links or trusting path strings."""
    current_fd = os.dup(parent_fd)
    try:
        for name in components:
            child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                               dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
            info = os.fstat(current_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) & 0o022):
                raise BootstrapEnrollmentError("fixed release-store parent custody is unsafe")
        return current_fd
    except OSError:
        os.close(current_fd)
        raise BootstrapEnrollmentError("fixed release-store parent custody could not be established") from None
    except BaseException:
        os.close(current_fd)
        raise


def _ensure_release_store_children(parent_fd: int, *, expected_uid: int,
                                   expected_gid: int) -> None:
    """Idempotently establish the two fixed children, never normalizing existing paths."""
    created: list[tuple[int, str, int, int, int, int]] = []
    current_fd = os.dup(parent_fd)

    def rollback_created() -> None:
        for owned_parent_fd, child_name, device, inode, owner_uid, owner_gid in reversed(created):
            try:
                current = os.stat(child_name, dir_fd=owned_parent_fd, follow_symlinks=False)
                if (stat.S_ISDIR(current.st_mode) and current.st_dev == device
                        and current.st_ino == inode and current.st_uid == owner_uid
                        and current.st_gid == owner_gid):
                    os.rmdir(child_name, dir_fd=owned_parent_fd)
                    os.fsync(owned_parent_fd)
            except OSError:
                # A concurrently populated directory is preserved for safe review.
                pass

    try:
        for name in ("hermes-installer", "releases"):
            created_here = False
            try:
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(name, 0o755, dir_fd=current_fd)
                    created_here = True
                    created_info = os.stat(name, dir_fd=current_fd, follow_symlinks=False)
                    if (not stat.S_ISDIR(created_info.st_mode)
                            or created_info.st_uid != expected_uid
                            or created_info.st_gid != expected_gid):
                        raise BootstrapEnrollmentError("new release-store directory identity is unsafe")
                    created.append((os.dup(current_fd), name, created_info.st_dev,
                                    created_info.st_ino, created_info.st_uid, created_info.st_gid))
                except FileExistsError:
                    pass
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                   dir_fd=current_fd)
            if created_here:
                opened = os.fstat(child_fd)
                if (opened.st_dev != created_info.st_dev or opened.st_ino != created_info.st_ino
                        or opened.st_uid != expected_uid or opened.st_gid != expected_gid):
                    os.close(child_fd)
                    raise BootstrapEnrollmentError("new release-store directory changed during creation")
                try:
                    os.fchmod(child_fd, 0o755)
                    os.fsync(child_fd)
                    os.fsync(current_fd)
                except BaseException:
                    os.close(child_fd)
                    raise
            os.close(current_fd)
            current_fd = child_fd
            info = os.fstat(current_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_gid != expected_gid or stat.S_IMODE(info.st_mode) & 0o022):
                raise BootstrapEnrollmentError("fixed release-store directory custody is unsafe")
    except OSError:
        rollback_created()
        raise BootstrapEnrollmentError("fixed release-store directory custody could not be established") from None
    except BaseException:
        rollback_created()
        raise
    finally:
        os.close(current_fd)
        for owned_parent_fd, *_ in created:
            os.close(owned_parent_fd)


def _open_lock(path: Path, uid: int) -> int:
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
    finally:
        os.close(parent)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid)
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        os.close(fd)
        raise BootstrapEnrollmentError("deployment lock custody is unsafe")
    return fd


def _new_receipt_id() -> str:
    value = secrets.token_urlsafe(24).replace("-", "_")
    if not value or len(value) > 160 or any(ch not in _RECEIPT_ID_ALPHABET for ch in value):
        raise BootstrapEnrollmentError("could not mint deployment receipt identity")
    return value


def _hash_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        digest.update(block)
    return digest.hexdigest()


def _seal_tree(root_fd: int, uid: int) -> None:
    root_device = os.fstat(root_fd).st_dev
    scan_fd = os.dup(root_fd)
    try:
        with os.scandir(scan_fd) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if (info.st_uid != uid or info.st_gid != _gid(uid)
                            or info.st_dev != root_device):
                        raise BootstrapEnrollmentError("release staging directory custody is unsafe")
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                    os.O_CLOEXEC, dir_fd=root_fd)
                    try:
                        _seal_tree(child, uid)
                    finally:
                        os.close(child)
                elif (stat.S_ISREG(info.st_mode) and info.st_uid == uid
                      and info.st_gid == _gid(uid) and info.st_dev == root_device
                      and info.st_nlink == 1):
                    fd = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root_fd)
                    try:
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                else:
                    raise BootstrapEnrollmentError("release staging tree contains an unsafe entry")
    finally:
        os.close(scan_fd)
    os.fchmod(root_fd, 0o555)
    os.fsync(root_fd)


def _rename_noreplace(source: Path, destination: Path) -> None:
    import ctypes
    import errno
    libc = ctypes.CDLL(None, use_errno=True)
    fn = getattr(libc, "renameat2", None)
    if fn is not None:
        fn.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        fn.restype = ctypes.c_int
        result = fn(-100, os.fsencode(source), -100, os.fsencode(destination), 1)
    elif sys.platform == "darwin":
        fn = getattr(libc, "renamex_np", None)
        if fn is None:
            raise BootstrapEnrollmentPending("atomic no-replace release installation is unavailable")
        fn.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        fn.restype = ctypes.c_int
        result = fn(os.fsencode(source), os.fsencode(destination), 0x00000004)  # RENAME_EXCL
    else:
        raise BootstrapEnrollmentPending("atomic no-replace release installation is unavailable")
    if result == 0:
        return
    error = ctypes.get_errno()
    if error == errno.EEXIST:
        raise FileExistsError(error, os.strerror(error), str(destination))
    raise OSError(error, os.strerror(error), str(destination))


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_owned_stage(path: Path, uid: int) -> None:
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != _gid(uid):
        raise BootstrapEnrollmentError("refusing to remove unowned release staging path")
    os.chmod(path, 0o700)
    for child in path.iterdir():
        row = os.stat(child, follow_symlinks=False)
        if stat.S_ISDIR(row.st_mode):
            _remove_owned_stage(child, uid)
        elif stat.S_ISREG(row.st_mode) and row.st_uid == uid and row.st_gid == _gid(uid):
            os.chmod(child, 0o600)
            child.unlink()
        else:
            raise BootstrapEnrollmentError("refusing to remove foreign staging content")
    path.rmdir()
