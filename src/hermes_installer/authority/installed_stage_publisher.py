"""Atomic root publication of a retained, verified installer release build.

The builder owns source/build provenance and holds the sealed output closure.
This module accepts only its opaque one-use handle and writes the two fixed
deployment locations consumed by :mod:`installer_release`.
"""
from __future__ import annotations

import fcntl
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
                                _artifact_id_for, _safe_relative, _unique_pairs)

_RECEIPT_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-"
_MAX_RECORDS = 50_000


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

    def publish_installed_stage(self, release_build_receipt_handle: str) -> Any:
        if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
            raise BootstrapEnrollmentPending("installed release publication requires the installed Linux root process")
        receipt = self.builder.resolve_build_receipt(release_build_receipt_handle, consume=False)
        receipt.verify_current()
        predecessor = receipt.deployment_predecessor
        _publish_retained_build(
            receipt=receipt,
            release_root=RELEASE_STORE_ROOT / receipt.candidate_git_sha,
            receipt_path=DEPLOYMENT_RECEIPT_PATH,
            expected_uid=0,
            predecessor=predecessor,
        )
        # Verify through the same fixed-path verifier used by the stage-zero actor.
        installed = InstalledRootReleaseVerifier.verify_installed_release()
        receipt.verify_current()
        receipt.consume()
        return installed


def _publish_retained_build(*, receipt: Any, release_root: Path, receipt_path: Path,
                            expected_uid: int, predecessor: Any) -> None:
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
    _verify_directory(receipt_path.parent, expected_uid, mode=None)
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
        if (release_root == RELEASE_STORE_ROOT / candidate
                and receipt_path == DEPLOYMENT_RECEIPT_PATH and expected_uid == 0):
            verified = InstalledRootReleaseVerifier._mint_release(
                {**record, "_receipt_sha256": _sha(raw)}, expected_uid=0)
            verified.close()
        # Check exact prior inode/digest again immediately before pointer CAS.
        _verify_predecessor(receipt_path, predecessor, expected_uid, parent_info)
        _replace_receipt(receipt_path, raw, expected_uid, predecessor)
        _fsync_dir(receipt_path.parent)
    finally:
        os.close(lock_fd)


def _build_rows(receipt: Any) -> tuple[_ReleaseRow, ...]:
    files = receipt.files
    if not isinstance(files, tuple) or not files or len(files) > MAX_FILES:
        raise BootstrapEnrollmentError("build receipt file closure is empty or oversized")
    rows: list[_ReleaseRow] = []
    previous = ""
    roles_allowed = {"launcher", "interpreter", "module", "template", "plan",
                     "artifact-catalog", "bootstrap-policy", "baseline", "amendment"}
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
                or any(role not in roles_allowed for role in roles)):
            raise BootstrapEnrollmentError("build receipt contains a malformed closure row")
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
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise BootstrapEnrollmentError("current deployment receipt is malformed") from None
    if (predecessor.state != "present" or _sha(raw) != predecessor.sha256
            or (info.st_dev, info.st_ino) != (predecessor.device, predecessor.inode)
            or not isinstance(record, dict) or record.get("candidate_git_sha") != predecessor.candidate_git_sha):
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
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1):
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
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (info.st_uid != uid or info.st_gid != _gid(uid)
                or stat.S_IMODE(info.st_mode) & 0o022
                or mode is not None and stat.S_IMODE(info.st_mode) != mode):
            raise BootstrapEnrollmentError("fixed deployment directory custody is unsafe")
        return info
    finally:
        os.close(fd)


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
