"""Root-owned source acquisition and sealed installer-release build inputs.

This module is deliberately separate from ``installer_release``: that module
verifies an already published release.  This one obtains the next candidate's
source before publication and never treats a source digest as an executable
digest.  Filesystem paths are fixed module policy, not caller parameters.
"""
from __future__ import annotations

import hashlib
import fcntl
import importlib.metadata
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import sysconfig
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending


SOURCE_ORIGIN = "https://github.com/Togarriapa/HermesAgent_Installer.git"
CANDIDATE_CAS_ROOT = Path("/var/lib/hermes-installer/source-cas/installer")
BUILD_CAS_ROOT = Path("/var/lib/hermes-installer/authority-journal/release-build-cas")
BASELINE_DIRECTORY = "plans/2026-10-09-v1"
BASELINE_TAG = "hermes-installer-plan-2026-10-09-v1"
BASELINE_TAG_OBJECT = "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
BASELINE_COMMIT = "653ac5fbc7a02613c9951859a7d794599603459b"
BASELINE_TREE_SHA256 = "039a6ab93f6bd44d80df01e99368c24c4348624305b6f4d17816eed25a167ade"
PLAN_TEMPLATE_PATH = "plans/amendments/2026-10-09-release-plan-active-compiler-v53/root-setup-plan-template-v1.json"
PLAN_TEMPLATE_ID = "installer-root-setup-plan-template-v1"
PLAN_TEMPLATE_SHA256 = "9f96befca8dba54a8251df80ccbed236809e9affbf1116efed42e06a7b92ac31"
PLAN_TEMPLATE_BYTES = 767
COMPILER_TEMPLATE_PATH = "plans/amendments/2026-10-09-closed-bootstrap-compiler-template-v30/bootstrap-compiler-template-v1.json"
COMPILER_TEMPLATE_ID = "installer-bootstrap-compiler-template-v1"
IDENTITY_TEMPLATE_PATH = "plans/amendments/2026-10-09-authentik-template-actor-api-v49/authentik-policy-template-v1.json"
IDENTITY_TEMPLATE_ID = "installer-authentik-policy-template-v1"
CATALOG_SOURCE_PATH = "src/hermes_installer/authority/artifact-catalog.json"
RUNTIME_REQUIREMENTS_PATH = "requirements-runtime.txt"
RELEASE_BUILDER_ARTIFACT_ID = "installer-release-builder-v1"
RELEASE_BUILD_STORE_ID = "installer-release-build-cas-v1"
MAX_SOURCE_FILES = 50_000
MAX_SOURCE_FILE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SOURCE_CAS_BYTES = 16 * 1024 * 1024 * 1024
MAX_RELEASE_BUILD_CAS_BYTES = 16 * 1024 * 1024 * 1024
RELEASE_MANIFEST_PATH = "release-manifest.json"
RELEASE_ROLES = frozenset({"launcher", "interpreter", "module", "template", "plan",
                           "artifact-catalog", "bootstrap-policy", "baseline", "amendment"})
SOURCE_CAS_V65_ROOT = Path("/var/lib/hermes-installer/source-cas/installer")
STAGED_LAUNCHER_SOURCE = "scripts/hermes-installer-root-setup"
STAGED_LAUNCHER_PATH = "bin/hermes-installer-root-setup"
STAGED_INTERPRETER_PATH = "runtime/bin/python"
STAGED_PLAN_PATH = "plans/root-setup-plan-v1.json"
STAGED_PLAN_TEMPLATE_PATH = "templates/root-setup-plan-template-v1.json"
STAGED_COMPILER_TEMPLATE_PATH = "templates/bootstrap-compiler-template-v1.json"
STAGED_IDENTITY_TEMPLATE_PATH = "templates/authentik-policy-template-v1.json"
STAGED_CATALOG_PATH = "catalog/artifacts.json"
RECEIPT_TTL_SECONDS = 300.0
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_SEAL = object()
_FIXED_SOURCE_ORIGIN_POLICY = object()


class InstallerReleaseBuildError(BootstrapEnrollmentError):
    """Candidate source or release-build custody failed verification."""


@dataclass(frozen=True, slots=True)
class DistributionFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    device: int
    inode: int


class VerifiedInstallerDistributionReceipt:
    """Sealed, held view of one exact root-owned candidate source tree."""

    __slots__ = ("candidate_git_sha", "git_tree_sha1", "source_tree_sha256",
                 "baseline_tree_sha256", "amendment_manifest_sha256",
                 "source_catalog_sha256", "files", "root_device", "root_inode",
                 "_root_fd", "_seal", "_expected_uid", "_closed", "_handle")

    def __init__(self, seal: object, *, candidate_git_sha: str, git_tree_sha1: str,
                 source_tree_sha256: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, source_catalog_sha256: str,
                 files: tuple[DistributionFile, ...], root_fd: int, expected_uid: int,
                 handle: str):
        if seal is not _SEAL:
            raise TypeError("distribution receipts can only be minted by the source CAS registry")
        self.candidate_git_sha = candidate_git_sha
        self.git_tree_sha1 = git_tree_sha1
        self.source_tree_sha256 = source_tree_sha256
        self.baseline_tree_sha256 = baseline_tree_sha256
        self.amendment_manifest_sha256 = amendment_manifest_sha256
        self.source_catalog_sha256 = source_catalog_sha256
        self.files = files
        info = os.fstat(root_fd)
        self.root_device, self.root_inode = info.st_dev, info.st_ino
        self._root_fd, self._seal, self._expected_uid = root_fd, seal, expected_uid
        self._closed, self._handle = False, handle

    @property
    def receipt_handle(self) -> str:
        return self._handle

    def verify_current(self) -> None:
        self._verify_root_current()
        for row in self.files:
            self._verify_row(row)
        if _enumerate_regular_files(self._root_fd) != tuple(sorted(row.relative_path for row in self.files)):
            raise InstallerReleaseBuildError("candidate source tree has unlisted files")

    def _verify_root_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._root_fd < 0:
            raise InstallerReleaseBuildError("candidate distribution receipt is not live")
        root = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != self._expected_uid
                or root.st_dev != self.root_device or root.st_ino != self.root_inode
                or stat.S_IMODE(root.st_mode) & 0o022):
            raise InstallerReleaseBuildError("candidate source CAS directory custody changed")

    def _verify_row(self, row: DistributionFile) -> None:
        fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != self._expected_uid or info.st_dev != row.device
                    or info.st_ino != row.inode or stat.S_IMODE(info.st_mode) != row.mode
                    or digest != row.sha256 or size != row.size_bytes):
                raise InstallerReleaseBuildError("candidate source CAS file bytes or ownership changed")
        finally:
            os.close(fd)

    def open_file(self, relative_path: str) -> int:
        self._verify_root_current()
        row = next((entry for entry in self.files if entry.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("requested source path is outside the verified candidate closure")
        self._verify_row(row)
        fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (digest != row.sha256 or size != row.size_bytes or info.st_dev != row.device
                    or info.st_ino != row.inode or info.st_uid != self._expected_uid):
                raise InstallerReleaseBuildError("candidate source changed while opening a verified file")
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except BaseException:
            os.close(fd)
            raise

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True

    def __enter__(self) -> "VerifiedInstallerDistributionReceipt":
        self.verify_current()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class RootInstallerDistributionRegistry:
    """Instance-local opaque source receipt registry; handles never carry paths."""

    def __init__(self, *, root: Path = SOURCE_CAS_V65_ROOT):
        if root != SOURCE_CAS_V65_ROOT:
            raise ValueError("installer source CAS root is fixed by installed policy")
        self._root = root
        self._receipts: dict[str, VerifiedInstallerDistributionReceipt] = {}
        self._used: set[str] = set()

    @classmethod
    def from_owned_source_CAS(cls, source_cas: "RootInstallerDistributionSourceCAS",
                              root_journal: object) -> "RootInstallerDistributionRegistry":
        if not isinstance(source_cas, RootInstallerDistributionSourceCAS) or root_journal is None:
            raise TypeError("distribution registry requires the fixed source CAS and root journal")
        return source_cas.registry

    def acquire_selected(self, candidate_git_sha: str) -> str:
        """Internal CAS operation used by RootInstallerDistributionSourceCAS."""
        _require_linux_root()
        _validate_git_sha(candidate_git_sha)
        self._prepare_root()
        lock_fd = os.open(self._root / ".acquire.lock",
                          os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise InstallerReleaseBuildError("source CAS acquisition lock custody is invalid")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._clean_incomplete_staging()
            existing = self._root / candidate_git_sha
            if existing.exists() or existing.is_symlink():
                handle, _ = self.resolve_selected(candidate_git_sha)
                return handle
            if _tree_byte_usage(self._root) + MAX_SOURCE_TREE_BYTES + 16 * 1024 * 1024 > MAX_SOURCE_CAS_BYTES:
                raise BootstrapEnrollmentPending("root source CAS has no bounded space for another candidate")
            return self._acquire_selected_locked(candidate_git_sha)
        finally:
            os.close(lock_fd)

    def _acquire_selected_locked(self, candidate_git_sha: str) -> str:
        _require_linux_root()
        work = self._root / (".fetch-" + secrets.token_hex(16))
        candidate_dir: Path | None = None
        os.mkdir(work, 0o700)
        try:
            self._git(["init", "--quiet", str(work)])
            self._git(["-C", str(work), "remote", "add", "origin", SOURCE_ORIGIN])
            origin = self._git(["-C", str(work), "remote", "get-url", "origin"]).decode("utf-8").strip()
            if origin != SOURCE_ORIGIN:
                raise InstallerReleaseBuildError("source checkout origin differs from the fixed repository")
            self._git(["-C", str(work), "fetch", "--depth=1", "--filter=blob:none", "--no-tags", "origin",
                       f"refs/tags/{BASELINE_TAG}:refs/tags/{BASELINE_TAG}"])
            self._git(["-C", str(work), "fetch", "--depth=1", "--filter=blob:none", "--no-tags",
                       "origin", candidate_git_sha])
            commit = self._git(["-C", str(work), "rev-parse", "FETCH_HEAD^{commit}"]).decode("ascii").strip()
            if commit != candidate_git_sha:
                raise InstallerReleaseBuildError("Git source acquisition did not resolve the selected commit")
            tag_object = self._git(["-C", str(work), "rev-parse", f"{BASELINE_TAG}^{{tag}}"]).decode("ascii").strip()
            baseline_commit = self._git(["-C", str(work), "rev-parse", f"{BASELINE_TAG}^{{commit}}"]).decode("ascii").strip()
            if tag_object != BASELINE_TAG_OBJECT or baseline_commit != BASELINE_COMMIT:
                raise InstallerReleaseBuildError("frozen baseline tag identity differs from the protected plan")
            tagged_baseline_tree = self._git(["-C", str(work), "rev-parse",
                                               f"{BASELINE_COMMIT}:{BASELINE_DIRECTORY}"]).decode("ascii").strip()
            selected_baseline_tree = self._git(["-C", str(work), "rev-parse",
                                                 f"{candidate_git_sha}:{BASELINE_DIRECTORY}"]).decode("ascii").strip()
            if tagged_baseline_tree != selected_baseline_tree:
                raise InstallerReleaseBuildError("selected candidate changed the frozen baseline Git tree")
            self._git(["-C", str(work), "checkout", "--detach", candidate_git_sha])
            actual = self._git(["-C", str(work), "rev-parse", "HEAD"]).decode("ascii").strip()
            tree = self._git(["-C", str(work), "rev-parse", "HEAD^{tree}"]).decode("ascii").strip()
            if actual != candidate_git_sha:
                raise InstallerReleaseBuildError("Git checkout is not the selected candidate")
            files = self._export_commit(work, candidate_git_sha)
            final_candidate_dir = self._root / candidate_git_sha
            if final_candidate_dir.exists() or final_candidate_dir.is_symlink():
                raise InstallerReleaseBuildError("candidate source CAS already contains this revision")
            candidate_dir = self._root / (".stage-" + secrets.token_hex(16))
            os.mkdir(candidate_dir, 0o700)
            final = candidate_dir / "source"
            os.rename(work, final)
            _make_immutable_tree(final)
            _fsync_dir(candidate_dir)
            _fsync_dir(self._root)
            root_fd = os.open(final, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                rows = _inspect_source_tree(root_fd, files)
                source_digest = _manifest_digest({row.relative_path: row.sha256 for row in rows})
                baseline_digest = _verify_frozen_baseline(root_fd, rows)
                if baseline_digest != BASELINE_TREE_SHA256:
                    raise InstallerReleaseBuildError("complete frozen baseline digest differs from the pinned v1 tree")
                amendment_digest = _amendment_digest(rows)
                catalog_row = next((row for row in rows if row.relative_path == CATALOG_SOURCE_PATH), None)
                if catalog_row is None:
                    raise InstallerReleaseBuildError("candidate source artifact catalog is missing")
                _validate_source_catalog(_read_relative(root_fd, CATALOG_SOURCE_PATH, 16 * 1024 * 1024))
                handle = secrets.token_urlsafe(32)
                receipt = VerifiedInstallerDistributionReceipt(
                    _SEAL, candidate_git_sha=actual, git_tree_sha1=tree,
                    source_tree_sha256=source_digest, baseline_tree_sha256=baseline_digest,
                    amendment_manifest_sha256=amendment_digest,
                    source_catalog_sha256=catalog_row.sha256, files=rows,
                    root_fd=root_fd, expected_uid=os.geteuid(), handle=handle)
                receipt.verify_current()
                _write_distribution_receipt(candidate_dir, receipt)
                os.rename(candidate_dir, final_candidate_dir)
                candidate_dir = final_candidate_dir
                _fsync_dir(self._root)
                self._receipts[handle] = receipt
                return handle
            except BaseException:
                os.close(root_fd)
                raise
        except BaseException:
            if work.exists():
                _remove_tree_no_follow(work)
            if candidate_dir is not None and candidate_dir.exists():
                _remove_tree_no_follow(candidate_dir)
            raise

    def _clean_incomplete_staging(self) -> None:
        for entry in self._root.iterdir():
            if not (entry.name.startswith(".fetch-") or entry.name.startswith(".stage-")):
                continue
            info = entry.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise InstallerReleaseBuildError("incomplete source staging entry has unsafe custody")
            _remove_tree_no_follow(entry)

    def resolve(self, handle: str, *, consume: bool = False) -> VerifiedInstallerDistributionReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle) or handle in self._used:
            raise BootstrapEnrollmentPending("candidate source CAS receipt is absent or already consumed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            receipt = self._load_distribution_receipt(handle)
            self._receipts[handle] = receipt
        receipt.verify_current()
        if consume:
            self._used.add(handle)
        return receipt

    def resolve_selected(self, candidate_git_sha: str) -> tuple[str, VerifiedInstallerDistributionReceipt]:
        _validate_git_sha(candidate_git_sha)
        _verify_private_cas_root(SOURCE_CAS_V65_ROOT)
        candidate_dir = SOURCE_CAS_V65_ROOT / candidate_git_sha
        candidate_info = candidate_dir.lstat()
        if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid != 0
                or stat.S_IMODE(candidate_info.st_mode) != 0o700):
            raise InstallerReleaseBuildError("selected source CAS directory is not root-owned and private")
        descriptor = _read_private_json(candidate_dir / "source-receipt.json", 16 * 1024 * 1024)
        handle = descriptor.get("receipt_handle")
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise InstallerReleaseBuildError("selected source CAS has no root-issued receipt handle")
        receipt = self.resolve(handle)
        if receipt.candidate_git_sha != candidate_git_sha:
            raise InstallerReleaseBuildError("selected source CAS receipt candidate does not match requested commit")
        return handle, receipt

    def _load_distribution_receipt(self, handle: str) -> VerifiedInstallerDistributionReceipt:
        _require_linux_root()
        for candidate_dir in self._root.iterdir():
            if not _GIT_SHA.fullmatch(candidate_dir.name) or candidate_dir.is_symlink():
                continue
            try:
                candidate_info = candidate_dir.lstat()
                if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid != 0
                        or stat.S_IMODE(candidate_info.st_mode) != 0o700):
                    raise InstallerReleaseBuildError("source CAS candidate directory custody changed")
                raw = _read_private_json(candidate_dir / "source-receipt.json", 16 * 1024 * 1024)
                if raw.get("receipt_handle") != handle:
                    continue
                if raw.get("candidate_git_sha") != candidate_dir.name or raw.get("schema") != 1:
                    raise InstallerReleaseBuildError("durable source receipt identity is invalid")
                source_root = candidate_dir / "source"
                root_fd = _open_secure_directory(source_root, expected_uid=0)
                root_identity = os.fstat(root_fd)
                if (root_identity.st_dev != raw.get("source_device")
                        or root_identity.st_ino != raw.get("source_inode")):
                    os.close(root_fd)
                    raise InstallerReleaseBuildError("durable source receipt root identity changed")
                manifest_fd = os.open(candidate_dir / "source-manifest.json",
                                      os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    manifest_info = os.fstat(manifest_fd)
                    if (manifest_info.st_uid != 0 or manifest_info.st_nlink != 1
                            or stat.S_IMODE(manifest_info.st_mode) != 0o600
                            or manifest_info.st_size > 16 * 1024 * 1024):
                        raise InstallerReleaseBuildError("durable source manifest custody is invalid")
                    manifest_bytes = _read_exact_fd(manifest_fd, manifest_info.st_size)
                    if hashlib.sha256(manifest_bytes).hexdigest() != raw.get("source_manifest_sha256"):
                        raise InstallerReleaseBuildError("durable source manifest digest changed")
                finally:
                    os.close(manifest_fd)
                files = tuple(DistributionFile(**item) for item in raw["files"])
                receipt = VerifiedInstallerDistributionReceipt(
                    _SEAL, candidate_git_sha=raw["candidate_git_sha"], git_tree_sha1=raw["git_tree_sha1"],
                    source_tree_sha256=raw["source_tree_sha256"], baseline_tree_sha256=raw["baseline_tree_sha256"],
                    amendment_manifest_sha256=raw["amendment_manifest_sha256"],
                    source_catalog_sha256=raw["source_catalog_sha256"], files=files, root_fd=root_fd,
                    expected_uid=0, handle=handle)
                receipt.verify_current()
                return receipt
            except FileNotFoundError:
                continue
        raise BootstrapEnrollmentPending("candidate source CAS receipt is absent or invalid")

    def _prepare_root(self) -> None:
        _ensure_root_directory(Path("/var/lib/hermes-installer"), 0o700)
        _ensure_root_directory(Path("/var/lib/hermes-installer/source-cas"), 0o700)
        _ensure_root_directory(self._root, 0o700)
        _ensure_root_directory(self._root / ".receipts", 0o700)

    @staticmethod
    def _git(arguments: list[str]) -> bytes:
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": "/bin/false",
                       "SSH_ASKPASS": "/bin/false",
                       "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
                       "GIT_OPTIONAL_LOCKS": "0", "GIT_PROTOCOL_FROM_USER": "0"}
        command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null",
                   "-c", "http.followRedirects=false",
                   "-c", "protocol.file.allow=never", *arguments]
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env=environment, timeout=600,
                                    check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise BootstrapEnrollmentPending("fixed-origin candidate source acquisition failed") from None
        if result.returncode != 0 or len(result.stdout) > MAX_SOURCE_TREE_BYTES:
            raise BootstrapEnrollmentPending("fixed-origin candidate source acquisition failed")
        return result.stdout

    @classmethod
    def _export_commit(cls, repository: Path, commit: str) -> tuple[tuple[str, str, int], ...]:
        raw = cls._git(["-C", str(repository), "ls-tree", "-rz", "--full-tree", commit])
        entries: list[tuple[str, str, int]] = []
        object_ids: list[str] = []
        for item in raw.split(b"\0"):
            if not item:
                continue
            try:
                header, path_raw = item.split(b"\t", 1)
                mode_raw, kind, object_id = header.decode("ascii").split(" ")
                path = path_raw.decode("utf-8", "strict")
            except (ValueError, UnicodeError):
                raise InstallerReleaseBuildError("candidate Git tree contains a malformed entry") from None
            _validate_relative_path(path)
            if kind != "blob" or mode_raw not in {"100644", "100755"}:
                raise InstallerReleaseBuildError("candidate Git tree contains a non-regular or linked entry")
            if len(entries) >= MAX_SOURCE_FILES:
                raise InstallerReleaseBuildError("candidate Git tree exceeds the protected file-count bound")
            entries.append((path, object_id, int(mode_raw, 8)))
            object_ids.append(object_id)
        if not entries:
            raise InstallerReleaseBuildError("candidate Git tree is empty")
        if len({path.casefold() for path, _, _ in entries}) != len(entries):
            raise InstallerReleaseBuildError("candidate Git tree has portable path collisions")
        batch = cls._git_batch(repository, object_ids)
        stage = repository / ".source-export"
        os.mkdir(stage, 0o700)
        total = 0
        out: list[tuple[str, str, int]] = []
        try:
            root_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                for (path, object_id, mode), body in zip(entries, batch, strict=True):
                    total += len(body)
                    if len(body) > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_TREE_BYTES:
                        raise InstallerReleaseBuildError("candidate Git source exceeds its byte bound")
                    digest = hashlib.sha256(body).hexdigest()
                    _write_relative(root_fd, path, body, mode=0o700 if mode == 0o100755 else 0o600)
                    out.append((path, digest, len(body)))
                _fsync_tree(root_fd)
            finally:
                os.close(root_fd)
            # Keep only the exact exported source tree; Git metadata is not part of its trust domain.
            for child in list(repository.iterdir()):
                if child.name == ".source-export":
                    continue
                if child.is_dir() and not child.is_symlink():
                    _remove_tree_no_follow(child)
                else:
                    child.unlink()
            os.rmdir(repository)
            os.rename(stage, repository)
            _fsync_dir(repository.parent)
            return tuple(out)
        except BaseException:
            if stage.exists():
                _remove_tree_no_follow(stage)
            raise

    @classmethod
    def _git_batch(cls, repository: Path, object_ids: list[str]) -> tuple[bytes, ...]:
        command = ["/usr/bin/git", "-c", "core.hooksPath=/dev/null", "-C", str(repository),
                   "cat-file", "--batch"]
        environment = {"PATH": "/usr/bin:/bin", "HOME": "/root", "LANG": "C.UTF-8",
                       "LC_ALL": "C.UTF-8", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ASKPASS": "/bin/false",
                       "SSH_ASKPASS": "/bin/false", "GIT_TERMINAL_PROMPT": "0"}
        try:
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=environment)
            assert process.stdin is not None and process.stdout is not None
            process.stdin.write(("\n".join(object_ids) + "\n").encode("ascii"))
            process.stdin.close()
            bodies: list[bytes] = []
            total = 0
            for expected in object_ids:
                header = process.stdout.readline(256)
                fields = header.decode("ascii", "strict").rstrip("\n").split(" ")
                if len(fields) != 3 or fields[0] != expected or fields[1] != "blob":
                    raise InstallerReleaseBuildError("Git source object closure changed during export")
                size = int(fields[2])
                total += size
                if size < 0 or size > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_TREE_BYTES:
                    raise InstallerReleaseBuildError("candidate source exceeds its protected byte bound")
                body = _read_exact(process.stdout, size)
                if process.stdout.read(1) != b"\n":
                    raise InstallerReleaseBuildError("Git source object framing is invalid")
                bodies.append(body)
            if process.wait(timeout=30) != 0:
                raise InstallerReleaseBuildError("Git source object export failed")
            return tuple(bodies)
        except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
            raise BootstrapEnrollmentPending("candidate Git source object export failed") from None


class RootInstallerDistributionSourceCAS:
    """Fixed-origin stage-zero source acquisition; this precedes actor/release checks."""

    def __init__(self, registry: RootInstallerDistributionRegistry):
        if not isinstance(registry, RootInstallerDistributionRegistry):
            raise TypeError("source CAS requires its in-process root distribution registry")
        self.registry = registry

    @classmethod
    def from_root_bootstrap(cls, root_journal: object,
                            verified_fixed_origin_policy: object) -> "RootInstallerDistributionSourceCAS":
        _require_linux_root()
        if root_journal is None or verified_fixed_origin_policy is not _FIXED_SOURCE_ORIGIN_POLICY:
            raise TypeError("stage-zero source acquisition requires the fixed-origin root bootstrap policy")
        return cls(RootInstallerDistributionRegistry())

    def acquire_selected(self, candidate_git_sha: str) -> str:
        return self.registry.acquire_selected(candidate_git_sha)


def fixed_source_origin_policy_for_root_bootstrap() -> object:
    _require_linux_root()
    return _FIXED_SOURCE_ORIGIN_POLICY


@dataclass(frozen=True, slots=True)
class RuntimeFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    device: int
    inode: int


class VerifiedInstallerInterpreterReceipt:
    """Actual selected isolated installer interpreter and byte-closure proof."""

    __slots__ = ("receipt_handle", "distribution_receipt_handle", "candidate_git_sha",
                 "runtime_artifact_receipt_handles", "executable_sha256", "executable_device",
                 "executable_inode", "runtime_prefix_sha256", "stdlib_closure_sha256",
                 "dependency_closure_sha256", "python_version", "implementation", "cache_tag",
                 "soabi", "machine", "owner_uid", "owner_gid", "mode", "issued_monotonic",
                 "expires_monotonic", "files", "runtime_prefix", "_prefix_fd", "_exe_fd",
                 "_seal", "_closed")

    def __init__(self, seal: object, *, receipt_handle: str, distribution_receipt_handle: str,
                 candidate_git_sha: str, runtime_artifact_receipt_handles: tuple[str, ...],
                 executable_sha256: str, executable_device: int, executable_inode: int,
                 runtime_prefix_sha256: str, stdlib_closure_sha256: str,
                 dependency_closure_sha256: str, python_version: str, implementation: str,
                 cache_tag: str, soabi: str, machine: str, owner_uid: int, owner_gid: int,
                 mode: int, issued_monotonic: float, expires_monotonic: float,
                 files: tuple[RuntimeFile, ...], runtime_prefix: Path,
                 prefix_fd: int, exe_fd: int):
        if seal is not _SEAL:
            raise TypeError("interpreter receipts can only be minted by the root interpreter registry")
        self.receipt_handle = receipt_handle
        self.distribution_receipt_handle = distribution_receipt_handle
        self.candidate_git_sha = candidate_git_sha
        self.runtime_artifact_receipt_handles = runtime_artifact_receipt_handles
        self.executable_sha256, self.executable_device = executable_sha256, executable_device
        self.executable_inode = executable_inode
        self.runtime_prefix_sha256 = runtime_prefix_sha256
        self.stdlib_closure_sha256, self.dependency_closure_sha256 = stdlib_closure_sha256, dependency_closure_sha256
        self.python_version, self.implementation, self.cache_tag = python_version, implementation, cache_tag
        self.soabi, self.machine = soabi, machine
        self.owner_uid, self.owner_gid, self.mode = owner_uid, owner_gid, mode
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, expires_monotonic
        self.files, self.runtime_prefix = files, runtime_prefix
        self._prefix_fd, self._exe_fd, self._seal, self._closed = prefix_fd, exe_fd, seal, False

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._prefix_fd < 0 or self._exe_fd < 0:
            raise InstallerReleaseBuildError("installer interpreter receipt is not live")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("installer interpreter observation expired; re-observe the bootstrap runtime")
        prefix = os.fstat(self._prefix_fd)
        if (not stat.S_ISDIR(prefix.st_mode) or prefix.st_uid != self.owner_uid
                or prefix.st_gid != self.owner_gid or stat.S_IMODE(prefix.st_mode) & 0o022):
            raise InstallerReleaseBuildError("isolated installer runtime prefix custody changed")
        executable = os.fstat(self._exe_fd)
        digest, size = _hash_fd(self._exe_fd, MAX_SOURCE_FILE_BYTES)
        if (digest != self.executable_sha256 or executable.st_dev != self.executable_device
                or executable.st_ino != self.executable_inode or not stat.S_ISREG(executable.st_mode)
                or executable.st_uid != self.owner_uid or not executable.st_mode & 0o111 or size == 0):
            raise InstallerReleaseBuildError("actual installer interpreter executable changed")
        _verify_runtime_files(self._prefix_fd, self.files, self.owner_uid, self.owner_gid)

    def open_executable(self) -> int:
        self.verify_current()
        return os.dup(self._exe_fd)

    def open_runtime_file(self, relative_path: str) -> int:
        if self._seal is not _SEAL or self._closed or self._prefix_fd < 0:
            raise InstallerReleaseBuildError("installer interpreter receipt is not live")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("installer interpreter observation expired; re-observe the bootstrap runtime")
        row = next((item for item in self.files if item.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("runtime path is outside the observed interpreter closure")
        fd = _open_relative(self._prefix_fd, row.relative_path, os.O_RDONLY)
        info = os.fstat(fd)
        digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        if (info.st_dev != row.device or info.st_ino != row.inode or info.st_uid != self.owner_uid
                or info.st_gid != self.owner_gid or digest != row.sha256 or size != row.size_bytes):
            os.close(fd)
            raise InstallerReleaseBuildError("runtime closure file changed after observation")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def close(self) -> None:
        if not self._closed:
            os.close(self._prefix_fd)
            os.close(self._exe_fd)
            self._prefix_fd, self._exe_fd, self._closed = -1, -1, True


@dataclass(frozen=True, slots=True)
class VerifiedInstallerRuntimeArtifactReceipt:
    """Observed installed dependency files joined to an exact lock identity."""

    receipt_handle: str
    package_name: str
    version: str
    files: tuple[tuple[str, str], ...]
    closure_sha256: str


class RootInstallerRuntimeArtifactRegistry:
    def __init__(self):
        self._receipts: dict[str, VerifiedInstallerRuntimeArtifactReceipt] = {}

    def _mint_observed(self, package_name: str, version: str,
                       files: Mapping[str, str], locked_versions: frozenset[str]) -> str:
        normalized = _normalize_package_name(package_name)
        if (not _ID.fullmatch(normalized) or not isinstance(version, str)
                or version not in locked_versions or not files):
            raise InstallerReleaseBuildError("runtime package is not an observed exact uv.lock entry")
        rows = tuple(sorted(files.items()))
        try:
            for path, digest in rows:
                _validate_relative_path(path)
                if not _SHA256.fullmatch(str(digest)):
                    raise InstallerReleaseBuildError("runtime package closure contains an invalid digest")
        except InstallerReleaseBuildError:
            raise
        if not rows:
            raise InstallerReleaseBuildError("runtime package closure contains an invalid measured file")
        handle = secrets.token_urlsafe(32)
        closure = _manifest_digest(dict(rows))
        self._receipts[handle] = VerifiedInstallerRuntimeArtifactReceipt(
            handle, normalized, version, rows, closure)
        return handle

    def resolve(self, handle: str) -> VerifiedInstallerRuntimeArtifactReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending("runtime artifact receipt handle is malformed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            raise BootstrapEnrollmentPending("runtime artifact receipt is absent from the root registry")
        return receipt


class RootInstallerInterpreterRegistry:
    """Observe the running bootstrap interpreter against the selected source lock."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 runtime_artifact_registry: RootInstallerRuntimeArtifactRegistry | None = None):
        if not isinstance(distribution_registry, RootInstallerDistributionRegistry):
            raise TypeError("interpreter registry requires the selected distribution registry")
        self.distribution_registry = distribution_registry
        self.runtime_artifact_registry = runtime_artifact_registry or RootInstallerRuntimeArtifactRegistry()
        if not isinstance(self.runtime_artifact_registry, RootInstallerRuntimeArtifactRegistry):
            raise TypeError("interpreter registry requires the root runtime-artifact registry")
        self._receipts: dict[str, VerifiedInstallerInterpreterReceipt] = {}

    @classmethod
    def from_owned_source_CAS(cls, distribution_registry: RootInstallerDistributionRegistry,
                              root_journal: object,
                              actual_runtime_artifact_registry: RootInstallerRuntimeArtifactRegistry
                              ) -> "RootInstallerInterpreterRegistry":
        if root_journal is None:
            raise TypeError("interpreter observer requires the retained root journal")
        return cls(distribution_registry, actual_runtime_artifact_registry)

    def observe_current_bootstrap_interpreter(self, distribution_handle: str) -> str:
        _require_linux_root()
        source = self.distribution_registry.resolve(distribution_handle)
        source.verify_current()
        if not sys.flags.isolated or sys.flags.no_user_site != 1 or not sys.prefix or sys.prefix == sys.base_prefix:
            raise BootstrapEnrollmentPending("bootstrap process is not running in its selected isolated installer interpreter")
        executable_path = Path(f"/proc/{os.getpid()}/exe")
        try:
            executable_real = executable_path.resolve(strict=True)
            configured_executable = Path(sys.executable).resolve(strict=True)
        except OSError:
            raise BootstrapEnrollmentPending("actual bootstrap interpreter executable is unavailable") from None
        if executable_real != configured_executable:
            raise InstallerReleaseBuildError("Python runtime executable differs from the kernel process executable")
        prefix_path = Path(sys.prefix)
        prefix_fd = _open_secure_directory(prefix_path, expected_uid=0)
        try:
            prefix_info = os.fstat(prefix_fd)
            runtime_files = _scan_runtime_prefix(prefix_fd, expected_uid=0, expected_gid=0)
            runtime_digest = _manifest_digest({row.relative_path: row.sha256 for row in runtime_files})
            executable_rel = _relative_below(prefix_path, executable_real)
            executable_row = next((row for row in runtime_files if row.relative_path == executable_rel), None)
            if executable_row is None:
                raise BootstrapEnrollmentPending("running interpreter is outside its dedicated runtime prefix")
            executable_fd = _open_relative(prefix_fd, executable_rel, os.O_RDONLY)
            try:
                executable_info = os.fstat(executable_fd)
                executable_sha, executable_size = _hash_fd(executable_fd, MAX_SOURCE_FILE_BYTES)
            except BaseException:
                os.close(executable_fd)
                raise
            if (executable_sha != executable_row.sha256 or executable_size == 0
                    or not executable_info.st_mode & 0o111):
                os.close(executable_fd)
                raise InstallerReleaseBuildError("runtime executable bytes differ from the measured prefix")
            project = _read_relative(source._root_fd, "pyproject.toml", 1024 * 1024)
            lock = _read_relative(source._root_fd, RUNTIME_REQUIREMENTS_PATH, 4 * 1024 * 1024)
            _require_python_requirement(project)
            stdlib_root = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
            stdlib_prefix = Path(sys.prefix).resolve(strict=True)
            if not _is_beneath(stdlib_root, stdlib_prefix):
                os.close(executable_fd)
                raise BootstrapEnrollmentPending("stdlib is outside the selected isolated installer runtime prefix")
            stdlib_rel = stdlib_root.relative_to(stdlib_prefix).as_posix()
            stdlib_rows = tuple(row for row in runtime_files
                                if row.relative_path == stdlib_rel or row.relative_path.startswith(stdlib_rel + "/"))
            if not stdlib_rows:
                os.close(executable_fd)
                raise BootstrapEnrollmentPending("isolated runtime has no measured standard-library closure")
            locked_packages = _locked_package_versions(lock)
            package_rows, artifact_handles = _runtime_dependency_receipts(
                prefix_path, locked_packages, self.runtime_artifact_registry)
            dependency_digest = _manifest_digest({name: digest for name, digest in package_rows})
            stdlib_digest = _manifest_digest({row.relative_path: row.sha256 for row in stdlib_rows})
            now = time.monotonic()
            handle = secrets.token_urlsafe(32)
            receipt = VerifiedInstallerInterpreterReceipt(
                _SEAL, receipt_handle=handle, distribution_receipt_handle=distribution_handle,
                candidate_git_sha=source.candidate_git_sha,
                runtime_artifact_receipt_handles=artifact_handles,
                executable_sha256=executable_sha, executable_device=executable_info.st_dev,
                executable_inode=executable_info.st_ino, runtime_prefix_sha256=runtime_digest,
                stdlib_closure_sha256=stdlib_digest, dependency_closure_sha256=dependency_digest,
                python_version=platform.python_version(), implementation=sys.implementation.name,
                cache_tag=sys.implementation.cache_tag or "", soabi=str(sysconfig.get_config_var("SOABI") or ""),
                machine=platform.machine(), owner_uid=prefix_info.st_uid, owner_gid=prefix_info.st_gid,
                mode=stat.S_IMODE(prefix_info.st_mode), issued_monotonic=now,
                expires_monotonic=now + RECEIPT_TTL_SECONDS, files=runtime_files,
                runtime_prefix=prefix_path, prefix_fd=prefix_fd, exe_fd=executable_fd)
            receipt.verify_current()
            self._receipts[handle] = receipt
            return handle
        except BaseException:
            os.close(prefix_fd)
            raise

    def resolve(self, handle: str, distribution_handle: str) -> VerifiedInstallerInterpreterReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise BootstrapEnrollmentPending("installer interpreter receipt handle is malformed")
        receipt = self._receipts.get(handle)
        if (receipt is None or receipt.distribution_receipt_handle != distribution_handle
                or receipt.candidate_git_sha != self.distribution_registry.resolve(distribution_handle).candidate_git_sha):
            raise BootstrapEnrollmentPending("installer interpreter proof does not match this selected source")
        receipt.verify_current()
        return receipt

    def resolve_runtime_artifact(self, handle: str, interpreter_handle: str) -> VerifiedInstallerRuntimeArtifactReceipt:
        interpreter = self._receipts.get(interpreter_handle)
        if (interpreter is None
                or handle not in interpreter.runtime_artifact_receipt_handles):
            raise BootstrapEnrollmentPending("runtime artifact receipt is absent or not bound to this interpreter")
        interpreter.verify_current()
        artifact = self.runtime_artifact_registry.resolve(handle)
        actual_rows = dict(_runtime_artifact_current_files(interpreter, artifact))
        if actual_rows != dict(artifact.files):
            raise InstallerReleaseBuildError("runtime artifact package bytes changed after observation")
        return artifact


class VerifiedRootSourceBootstrapActor:
    """PIDFD-bound proof that the current root process loaded the selected bootstrap source."""

    __slots__ = ("receipt_handle", "distribution_receipt_handle", "interpreter_receipt_handle",
                 "candidate_git_sha", "entry_module", "entry_symbol", "module_closure_sha256",
                 "executable_sha256", "pid", "pid_start_ticks", "pidfd_identity", "uid", "gid",
                 "issued_monotonic", "expires_monotonic", "module_rows", "_pidfd", "_seal")

    def __init__(self, seal: object, *, receipt_handle: str, distribution_receipt_handle: str,
                 interpreter_receipt_handle: str, candidate_git_sha: str,
                 module_rows: tuple[tuple[str, str, str, int, int], ...], executable_sha256: str,
                 pid: int, pid_start_ticks: int, pidfd: int, issued_monotonic: float,
                 expires_monotonic: float):
        if seal is not _SEAL:
            raise TypeError("bootstrap actor receipts can only be minted by RootSourceBootstrapActorVerifier")
        self.receipt_handle = receipt_handle
        self.distribution_receipt_handle, self.interpreter_receipt_handle = distribution_receipt_handle, interpreter_receipt_handle
        self.candidate_git_sha, self.entry_module = candidate_git_sha, "hermes_installer.authority.installer_release_build"
        self.entry_symbol, self.module_rows = "bootstrap_selected_release", module_rows
        self.module_closure_sha256 = _manifest_digest({name: digest for name, _, digest, _, _ in module_rows})
        self.executable_sha256 = executable_sha256
        self.pid, self.pid_start_ticks = pid, pid_start_ticks
        self._pidfd = pidfd
        self.pidfd_identity = f"{os.fstat(pidfd).st_dev}:{os.fstat(pidfd).st_ino}"
        self.uid, self.gid = os.getuid(), os.getgid()
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, expires_monotonic
        self._pidfd, self._seal = pidfd, seal

    def verify_current(self, distribution: VerifiedInstallerDistributionReceipt,
                       interpreter: VerifiedInstallerInterpreterReceipt) -> None:
        if self._seal is not _SEAL or time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("root source bootstrap actor proof is absent or expired")
        distribution.verify_current()
        interpreter.verify_current()
        if (os.getpid() != self.pid or os.getuid() != 0 or os.geteuid() != 0
                or _process_start_ticks(self.pid) != self.pid_start_ticks
                or self.uid != 0 or self.gid != 0):
            raise InstallerReleaseBuildError("current root source actor identity changed")
        try:
            if os.readlink(f"/proc/self/exe") != os.readlink(f"/proc/{self.pid}/exe"):
                raise InstallerReleaseBuildError("root source actor executable changed")
        except OSError:
            raise BootstrapEnrollmentPending("root source actor executable identity is unavailable") from None
        poll = __import__("select").poll()
        poll.register(self._pidfd, __import__("select").POLLIN | __import__("select").POLLHUP)
        if poll.poll(0):
            raise InstallerReleaseBuildError("root source actor process exited")
        for module_name, expected_path, digest, device, inode in self.module_rows:
            module = sys.modules.get(module_name)
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            if origin != expected_path:
                raise InstallerReleaseBuildError("loaded installer module origin differs from selected source")
            fd = distribution.open_file(_relative_below(distribution_root(distribution), Path(expected_path)))
            try:
                info = os.fstat(fd)
                actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if actual != digest or info.st_dev != device or info.st_ino != inode:
                    raise InstallerReleaseBuildError("loaded installer module bytes or inode changed")
            finally:
                os.close(fd)

    def close(self) -> None:
        os.close(self._pidfd)
        self._pidfd = -1


class RootSourceBootstrapActorVerifier:
    """Finite verifier for first-source root actor, independent of deployed pointers."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 interpreter_registry: RootInstallerInterpreterRegistry):
        if (not isinstance(distribution_registry, RootInstallerDistributionRegistry)
                or not isinstance(interpreter_registry, RootInstallerInterpreterRegistry)
                or interpreter_registry.distribution_registry is not distribution_registry):
            raise TypeError("source actor verifier requires one selected distribution/interpreter registry pair")
        self.distribution_registry, self.interpreter_registry = distribution_registry, interpreter_registry
        self._actors: dict[tuple[str, str], VerifiedRootSourceBootstrapActor] = {}

    @classmethod
    def from_verified_source(cls, distribution_registry: RootInstallerDistributionRegistry,
                             interpreter_registry: RootInstallerInterpreterRegistry) -> "RootSourceBootstrapActorVerifier":
        return cls(distribution_registry, interpreter_registry)

    def verify_current(self, distribution_handle: str,
                       interpreter_handle: str) -> VerifiedRootSourceBootstrapActor:
        _require_linux_root()
        distribution = self.distribution_registry.resolve(distribution_handle)
        interpreter = self.interpreter_registry.resolve(interpreter_handle, distribution_handle)
        if interpreter.candidate_git_sha != distribution.candidate_git_sha:
            raise InstallerReleaseBuildError("bootstrap interpreter was not observed for the selected candidate")
        distribution.verify_current()
        interpreter.verify_current()
        module_rows: list[tuple[str, str, str, int, int]] = []
        loaded_installer = [(name, module) for name, module in tuple(sys.modules.items())
                            if name == "hermes_installer" or name.startswith("hermes_installer.")]
        if not loaded_installer:
            raise BootstrapEnrollmentPending("selected installer source modules are not loaded in the root bootstrap actor")
        source_by_path = {row.relative_path: row for row in distribution.files}
        root = distribution_root(distribution)
        prefix = interpreter.runtime_prefix.resolve(strict=True)
        stdlib = Path(sysconfig.get_path("stdlib")).resolve(strict=True)
        allowed_paths = {str(prefix), str(root.resolve(strict=True)), str(stdlib)}
        for path in sys.path:
            if not path:
                raise InstallerReleaseBuildError("bootstrap actor imports from the ambient working directory")
            resolved = Path(path).resolve(strict=True)
            if not any(_is_beneath(resolved, Path(base)) for base in allowed_paths):
                raise InstallerReleaseBuildError("bootstrap actor import path is outside selected source/runtime closure")
        for name, module in tuple(sys.modules.items()):
            spec = getattr(module, "__spec__", None)
            origin = getattr(spec, "origin", None)
            if origin in {None, "built-in", "frozen"}:
                continue
            if not isinstance(origin, str) or not Path(origin).is_absolute():
                raise InstallerReleaseBuildError("loaded module has a non-file or relative origin")
            resolved_origin = Path(origin).resolve(strict=True)
            if name == "hermes_installer" or name.startswith("hermes_installer."):
                continue
            if not (_is_beneath(resolved_origin, prefix) or _is_beneath(resolved_origin, stdlib)):
                raise InstallerReleaseBuildError("loaded dependency module is outside measured interpreter closure")
        for name, module in sorted(loaded_installer):
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            if not isinstance(origin, str):
                raise InstallerReleaseBuildError("loaded installer module has no immutable source origin")
            relative = _relative_below(root, Path(origin))
            source_path = "src/" + relative.removeprefix("src/")
            row = source_by_path.get(source_path)
            if row is None:
                raise InstallerReleaseBuildError("loaded installer module is outside the verified candidate tree")
            if (name == "hermes_installer.authority.installer_release_build"
                    and not callable(getattr(module, "bootstrap_selected_release", None))):
                raise InstallerReleaseBuildError("selected release module lacks its fixed bootstrap entrypoint")
            fd = distribution.open_file(source_path)
            try:
                info = os.fstat(fd)
                actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if actual != row.sha256:
                    raise InstallerReleaseBuildError("loaded installer module bytes differ from source CAS")
                module_rows.append((name, str(Path(origin)), actual, info.st_dev, info.st_ino))
            finally:
                os.close(fd)
        if not any(row[0] == "hermes_installer.authority.installer_release_build" for row in module_rows):
            raise BootstrapEnrollmentPending("selected release build module is not part of the current root actor")
        pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            now = time.monotonic()
            actor = VerifiedRootSourceBootstrapActor(
                _SEAL, receipt_handle=secrets.token_urlsafe(32),
                distribution_receipt_handle=distribution_handle,
                interpreter_receipt_handle=interpreter_handle,
                candidate_git_sha=distribution.candidate_git_sha,
                module_rows=tuple(module_rows), executable_sha256=interpreter.executable_sha256,
                pid=os.getpid(), pid_start_ticks=_process_start_ticks(os.getpid()), pidfd=pidfd,
                issued_monotonic=now, expires_monotonic=min(interpreter.expires_monotonic,
                                                             now + RECEIPT_TTL_SECONDS))
            actor.verify_current(distribution, interpreter)
            self._actors[(distribution_handle, interpreter_handle)] = actor
            return actor
        except BaseException:
            os.close(pidfd)
            raise

    def resolve_current(self, distribution_handle: str,
                        interpreter_handle: str) -> VerifiedRootSourceBootstrapActor:
        actor = self._actors.get((distribution_handle, interpreter_handle))
        if actor is None:
            raise BootstrapEnrollmentPending("current source bootstrap actor proof is absent")
        actor.verify_current(self.distribution_registry.resolve(distribution_handle),
                             self.interpreter_registry.resolve(interpreter_handle, distribution_handle))
        return actor


@dataclass(frozen=True, slots=True)
class BuildOutputFile:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    roles: tuple[str, ...]
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class DeploymentPredecessor:
    """Exact predecessor snapshot; absent is a proven state, never a wildcard."""

    state: str
    parent_device: int
    parent_inode: int
    sha256: str | None = None
    device: int | None = None
    inode: int | None = None
    candidate_git_sha: str | None = None


class VerifiedInstallerReleaseBuildReceipt:
    """Sealed build-output custody consumed by the installed-stage publisher."""

    __slots__ = ("schema", "receipt_handle", "candidate_git_sha", "distribution_receipt_handle",
                 "interpreter_receipt_handle", "source_tree_sha256", "baseline_tree_sha256",
                 "amendment_manifest_sha256", "source_catalog_sha256", "role_closure_manifest_sha256",
                 "root_setup_plan_sha256", "build_output_store_id", "build_output_receipt_handle",
                 "builder_artifact_id", "builder_artifact_sha256", "issued_monotonic", "expires_monotonic",
                 "closure_manifest_relative_path", "closure_manifest_sha256", "deployment_predecessor",
                 "files", "_root_fd", "_root_device", "_root_inode", "_expected_uid", "_seal",
                 "_closed", "_consumed", "_handle")

    def __init__(self, seal: object, *, handle: str, candidate_git_sha: str,
                 distribution_receipt_handle: str, interpreter_receipt_handle: str,
                 source_tree_sha256: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, source_catalog_sha256: str,
                 role_closure_manifest_sha256: str, root_setup_plan_sha256: str,
                 builder_artifact_sha256: str, issued_monotonic: float,
                 deployment_predecessor: DeploymentPredecessor, files: tuple[BuildOutputFile, ...],
                 manifest_sha256: str, root_fd: int, expected_uid: int):
        if seal is not _SEAL:
            raise TypeError("release build receipts can only be minted by RootInstalledReleaseBuilder")
        self.schema = 1
        self.receipt_handle = handle
        self.candidate_git_sha = candidate_git_sha
        self.distribution_receipt_handle = distribution_receipt_handle
        self.interpreter_receipt_handle = interpreter_receipt_handle
        self.source_tree_sha256, self.baseline_tree_sha256 = source_tree_sha256, baseline_tree_sha256
        self.amendment_manifest_sha256, self.source_catalog_sha256 = amendment_manifest_sha256, source_catalog_sha256
        self.role_closure_manifest_sha256, self.root_setup_plan_sha256 = role_closure_manifest_sha256, root_setup_plan_sha256
        self.build_output_store_id, self.build_output_receipt_handle = RELEASE_BUILD_STORE_ID, handle
        self.builder_artifact_id, self.builder_artifact_sha256 = RELEASE_BUILDER_ARTIFACT_ID, builder_artifact_sha256
        self.issued_monotonic, self.expires_monotonic = issued_monotonic, issued_monotonic + RECEIPT_TTL_SECONDS
        self.closure_manifest_relative_path, self.closure_manifest_sha256 = RELEASE_MANIFEST_PATH, manifest_sha256
        self.deployment_predecessor, self.files = deployment_predecessor, files
        info = os.fstat(root_fd)
        self._root_fd, self._root_device, self._root_inode = root_fd, info.st_dev, info.st_ino
        self._expected_uid, self._seal = expected_uid, seal
        self._closed, self._consumed, self._handle = False, False, handle

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._consumed or self._root_fd < 0:
            raise BootstrapEnrollmentPending("release build receipt is absent or already consumed")
        if time.monotonic() >= self.expires_monotonic:
            raise BootstrapEnrollmentPending("release build receipt expired before stage publication")
        root = os.fstat(self._root_fd)
        if (not stat.S_ISDIR(root.st_mode) or root.st_uid != self._expected_uid
                or stat.S_IMODE(root.st_mode) & 0o077 or root.st_dev != self._root_device
                or root.st_ino != self._root_inode):
            raise InstallerReleaseBuildError("release build output root custody changed")
        for row in self.files:
            fd = _open_relative(self._root_fd, row.relative_path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                        or info.st_uid != self._expected_uid or info.st_dev != row.device
                        or info.st_ino != row.inode or stat.S_IMODE(info.st_mode) != row.mode
                        or digest != row.sha256 or size != row.size_bytes):
                    raise InstallerReleaseBuildError("release build output bytes or identity changed")
            finally:
                os.close(fd)
        if _enumerate_regular_files(self._root_fd) != tuple(sorted(
                [row.relative_path for row in self.files] + [RELEASE_MANIFEST_PATH])):
            raise InstallerReleaseBuildError("release build output contains files outside its sealed closure")
        manifest = _read_relative(self._root_fd, RELEASE_MANIFEST_PATH, 16 * 1024 * 1024)
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        if manifest_sha != self.closure_manifest_sha256 or manifest_sha != self.role_closure_manifest_sha256:
            raise InstallerReleaseBuildError("release manifest bytes changed after build sealing")
        try:
            value = json.loads(manifest.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError, json.JSONDecodeError):
            raise InstallerReleaseBuildError("sealed release manifest is malformed") from None
        expected_rows = [{"relative_path": row.relative_path, "sha256": row.sha256,
                          "size_bytes": row.size_bytes, "mode": row.mode, "roles": list(row.roles)}
                         for row in self.files]
        if (not isinstance(value, dict) or set(value) != {"schema", "candidate_git_sha", "files"}
                or type(value.get("schema")) is not int or value.get("schema") != 1
                or value.get("candidate_git_sha") != self.candidate_git_sha
                or value.get("files") != expected_rows or _canonical_json(value) != manifest):
            raise InstallerReleaseBuildError("sealed manifest does not describe the retained role closure")

    def open_file(self, relative_path: str) -> int:
        self.verify_current()
        row = next((item for item in self.files if item.relative_path == relative_path), None)
        if row is None:
            raise InstallerReleaseBuildError("publisher requested a file outside the sealed output closure")
        fd = _open_relative(self._root_fd, relative_path, os.O_RDONLY)
        info = os.fstat(fd)
        digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        if digest != row.sha256 or size != row.size_bytes or info.st_dev != row.device or info.st_ino != row.inode:
            os.close(fd)
            raise InstallerReleaseBuildError("release output changed while opening sealed file")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def open_manifest(self) -> int:
        self.verify_current()
        fd = _open_relative(self._root_fd, RELEASE_MANIFEST_PATH, os.O_RDONLY)
        digest, _ = _hash_fd(fd, 16 * 1024 * 1024)
        if digest != self.closure_manifest_sha256:
            os.close(fd)
            raise InstallerReleaseBuildError("release manifest changed while opening")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd

    def consume(self) -> None:
        self.verify_current()
        self._consumed = True

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True


class RootInstalledReleaseBuilder:
    """Builds a fixed installed layout solely from retained source/runtime/actor proofs."""

    def __init__(self, distribution_registry: RootInstallerDistributionRegistry,
                 interpreter_registry: RootInstallerInterpreterRegistry,
                 actor_verifier: RootSourceBootstrapActorVerifier):
        if (not isinstance(distribution_registry, RootInstallerDistributionRegistry)
                or not isinstance(interpreter_registry, RootInstallerInterpreterRegistry)
                or not isinstance(actor_verifier, RootSourceBootstrapActorVerifier)
                or interpreter_registry.distribution_registry is not distribution_registry
                or actor_verifier.distribution_registry is not distribution_registry
                or actor_verifier.interpreter_registry is not interpreter_registry):
            raise TypeError("release builder requires one fixed source/interpreter/actor registry graph")
        self.distribution_registry, self.interpreter_registry, self.actor_verifier = (
            distribution_registry, interpreter_registry, actor_verifier)
        self._receipts: dict[str, VerifiedInstallerReleaseBuildReceipt] = {}
        self._used: set[str] = set()

    def build_selected(self, distribution_handle: str, interpreter_handle: str) -> str:
        _require_linux_root()
        source = self.distribution_registry.resolve(distribution_handle)
        interpreter = self.interpreter_registry.resolve(interpreter_handle, distribution_handle)
        actor = self.actor_verifier.resolve_current(distribution_handle, interpreter_handle)
        actor.verify_current(source, interpreter)
        source.verify_current()
        interpreter.verify_current()
        if source.candidate_git_sha != interpreter.candidate_git_sha:
            raise InstallerReleaseBuildError("release source and interpreter receipts select different candidates")
        self._verify_builder_is_loaded_from_source(source)
        _ensure_root_directory(Path("/var/lib/hermes-installer/authority-journal"), 0o700)
        _ensure_root_directory(BUILD_CAS_ROOT.parent, 0o700)
        _ensure_root_directory(BUILD_CAS_ROOT, 0o700)
        if _tree_byte_usage(BUILD_CAS_ROOT) + 2 * MAX_SOURCE_TREE_BYTES > MAX_RELEASE_BUILD_CAS_BYTES:
            raise BootstrapEnrollmentPending("release build CAS has no bounded space for another sealed output")
        output = BUILD_CAS_ROOT / secrets.token_hex(24)
        os.mkdir(output, 0o700)
        root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            rows_without_identity = self._stage_fixed_layout(root_fd, source, interpreter, actor)
            plan_bytes = self._render_plan(source)
            _write_relative(root_fd, STAGED_PLAN_PATH, plan_bytes, mode=0o444)
            rows_without_identity.append((STAGED_PLAN_PATH, hashlib.sha256(plan_bytes).hexdigest(),
                                          len(plan_bytes), 0o444, ("plan",)))
            rows = self._seal_output_rows(root_fd, rows_without_identity)
            source.verify_current()
            interpreter.verify_current()
            actor.verify_current(source, interpreter)
            manifest_value = {"schema": 1, "candidate_git_sha": source.candidate_git_sha,
                              "files": [{"relative_path": row.relative_path, "sha256": row.sha256,
                                         "size_bytes": row.size_bytes, "mode": row.mode,
                                         "roles": list(row.roles)} for row in rows]}
            manifest_bytes = _canonical_json(manifest_value)
            if sum(row.size_bytes for row in rows) + len(manifest_bytes) > 2 * MAX_SOURCE_TREE_BYTES:
                raise InstallerReleaseBuildError("release output exceeds its fixed build-CAS size limit")
            _write_relative(root_fd, RELEASE_MANIFEST_PATH, manifest_bytes, mode=0o444)
            _fsync_tree(root_fd)
            _fsync_dir(output.parent)
            receipt_handle = secrets.token_urlsafe(32)
            receipt = VerifiedInstallerReleaseBuildReceipt(
                _SEAL, handle=receipt_handle, candidate_git_sha=source.candidate_git_sha,
                distribution_receipt_handle=distribution_handle, interpreter_receipt_handle=interpreter_handle,
                source_tree_sha256=source.source_tree_sha256,
                baseline_tree_sha256=source.baseline_tree_sha256,
                amendment_manifest_sha256=source.amendment_manifest_sha256,
                source_catalog_sha256=source.source_catalog_sha256,
                role_closure_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
                root_setup_plan_sha256=next(row.sha256 for row in rows if row.relative_path == STAGED_PLAN_PATH),
                builder_artifact_sha256=self._builder_digest(source), issued_monotonic=time.monotonic(),
                deployment_predecessor=_read_deployment_predecessor(), files=rows,
                manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(), root_fd=root_fd,
                expected_uid=os.geteuid())
            receipt.verify_current()
            self._receipts[receipt_handle] = receipt
            return receipt_handle
        except BaseException:
            os.close(root_fd)
            _remove_tree_no_follow(output)
            raise

    def resolve_build_receipt(self, handle: str, *, consume: bool = False) -> VerifiedInstallerReleaseBuildReceipt:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle) or handle in self._used:
            raise BootstrapEnrollmentPending("release build receipt is absent or already consumed")
        receipt = self._receipts.get(handle)
        if receipt is None:
            raise BootstrapEnrollmentPending("release build receipt belongs to another root builder")
        receipt.verify_current()
        if consume:
            self._used.add(handle)
        return receipt

    def _verify_builder_is_loaded_from_source(self, source: VerifiedInstallerDistributionReceipt) -> None:
        module = sys.modules.get("hermes_installer.authority.installer_release_build")
        origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if not isinstance(origin, str):
            raise BootstrapEnrollmentPending("release builder module is not loaded from selected source")
        relative = _relative_below(distribution_root(source), Path(origin))
        row = next((row for row in source.files if row.relative_path == relative), None)
        if row is None:
            raise InstallerReleaseBuildError("release builder is outside selected candidate source")
        fd = source.open_file(relative)
        try:
            actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if actual != row.sha256:
                raise InstallerReleaseBuildError("loaded release builder source bytes changed")
        finally:
            os.close(fd)

    def _builder_digest(self, source: VerifiedInstallerDistributionReceipt) -> str:
        module = sys.modules["hermes_installer.authority.installer_release_build"]
        relative = _relative_below(distribution_root(source), Path(module.__spec__.origin))
        row = next(item for item in source.files if item.relative_path == relative)
        return row.sha256

    def _stage_fixed_layout(self, output_fd: int, source: VerifiedInstallerDistributionReceipt,
                            interpreter: VerifiedInstallerInterpreterReceipt,
                            actor: VerifiedRootSourceBootstrapActor) -> list[tuple[str, str, int, int, tuple[str, ...]]]:
        source_files = {row.relative_path: row for row in source.files}
        staged: list[tuple[str, str, int, int, tuple[str, ...]]] = []
        self._copy_source(source, output_fd, STAGED_LAUNCHER_SOURCE, STAGED_LAUNCHER_PATH,
                          ("launcher",), executable=True)
        staged.append(self._last_output_row)
        runtime_fd = interpreter.open_executable()
        try:
            info = os.fstat(runtime_fd)
            digest, size = _hash_fd(runtime_fd, MAX_SOURCE_FILE_BYTES)
            body = _read_exact_fd(runtime_fd, size)
            _write_relative(output_fd, STAGED_INTERPRETER_PATH, body, mode=0o555)
            staged.append((STAGED_INTERPRETER_PATH, digest, size, 0o555, ("interpreter",)))
        finally:
            os.close(runtime_fd)
        for row in interpreter.files:
            if row.relative_path.startswith("bin/") and row.relative_path == "bin/python" and row.relative_path != STAGED_INTERPRETER_PATH:
                continue
            if row.relative_path == _relative_below(interpreter.runtime_prefix, Path(sysconfig.get_path("stdlib")).resolve(strict=True)):
                pass
            fd = interpreter.open_runtime_file(row.relative_path)
            try:
                body = _read_exact_fd(fd, row.size_bytes)
            finally:
                os.close(fd)
            path = "runtime/" + row.relative_path
            if path == STAGED_INTERPRETER_PATH:
                continue
            _write_relative(output_fd, path, body, mode=0o555 if row.mode & 0o111 else 0o444)
            staged.append((path, row.sha256, row.size_bytes,
                           0o555 if row.mode & 0o111 else 0o444, ("interpreter",)))
        for source_path, target, role in (
            (PLAN_TEMPLATE_PATH, STAGED_PLAN_TEMPLATE_PATH, "template"),
            (COMPILER_TEMPLATE_PATH, STAGED_COMPILER_TEMPLATE_PATH, "template"),
            (IDENTITY_TEMPLATE_PATH, STAGED_IDENTITY_TEMPLATE_PATH, "template"),
            (CATALOG_SOURCE_PATH, STAGED_CATALOG_PATH, "artifact-catalog"),
        ):
            if source_path not in source_files:
                raise InstallerReleaseBuildError("fixed release layout source input is absent")
            self._copy_source(source, output_fd, source_path, target, (role,))
            staged.append(self._last_output_row)
        # Include exact full frozen baseline and selected amendment bytes under stable roots.
        for row in source.files:
            if row.relative_path.startswith(BASELINE_DIRECTORY + "/"):
                target = row.relative_path
                self._copy_source(source, output_fd, row.relative_path, target, ("baseline",))
                staged.append(self._last_output_row)
            elif row.relative_path.startswith("plans/amendments/"):
                target = "plans/" + row.relative_path.removeprefix("plans/")
                self._copy_source(source, output_fd, row.relative_path, target, ("amendment",))
                staged.append(self._last_output_row)
        # Map only the actual loaded installer-module closure to canonical installed module paths.
        for name, _, digest, _, _ in actor.module_rows:
            if not (name == "hermes_installer" or name.startswith("hermes_installer.")):
                continue
            parts = name.split(".")
            source_path = "src/" + "/".join(parts) + ".py"
            package_init = "src/" + "/".join(parts) + "/__init__.py"
            if source_path in source_files:
                source_rel, target = source_path, "lib/python/" + "/".join(parts) + ".py"
            elif package_init in source_files:
                source_rel, target = package_init, "lib/python/" + "/".join(parts) + "/__init__.py"
            else:
                raise InstallerReleaseBuildError("loaded installer module has no fixed source module path")
            source_row = source_files[source_rel]
            if source_row.sha256 != digest:
                raise InstallerReleaseBuildError("loaded module digest differs from the exact source module")
            self._copy_source(source, output_fd, source_rel, target, ("module",))
            staged.append(self._last_output_row)
        return staged

    def _copy_source(self, source: VerifiedInstallerDistributionReceipt, output_fd: int,
                     source_path: str, target_path: str, roles: tuple[str, ...],
                     executable: bool = False) -> None:
        row = next((item for item in source.files if item.relative_path == source_path), None)
        if row is None:
            raise InstallerReleaseBuildError("release builder requested a source outside its receipt")
        if executable and not row.mode & 0o111:
            raise InstallerReleaseBuildError("fixed root setup launcher source is not executable")
        fd = source.open_file(source_path)
        try:
            body = _read_exact_fd(fd, row.size_bytes)
        finally:
            os.close(fd)
        if hashlib.sha256(body).hexdigest() != row.sha256:
            raise InstallerReleaseBuildError("release builder source bytes differ from sealed source row")
        mode = 0o555 if executable or row.mode & 0o111 else 0o444
        _write_relative(output_fd, target_path, body, mode=mode)
        self._last_output_row = (target_path, row.sha256, row.size_bytes, mode, roles)

    def _seal_output_rows(self, root_fd: int,
                          staged: list[tuple[str, str, int, int, tuple[str, ...]]]) -> tuple[BuildOutputFile, ...]:
        rows: list[BuildOutputFile] = []
        seen: set[str] = set()
        for path, digest, size, mode, roles in sorted(staged):
            if path in seen:
                raise InstallerReleaseBuildError("fixed release builder produced a duplicate output path")
            seen.add(path)
            _validate_relative_path(path)
            if (not _SHA256.fullmatch(digest) or type(size) is not int or size < 0
                    or type(mode) is not int or not 0 <= mode <= 0o7777
                    or not roles or len(set(roles)) != len(roles)
                    or any(role not in RELEASE_ROLES for role in roles)):
                raise InstallerReleaseBuildError("fixed release output row is outside the finite schema")
            fd = _open_relative(root_fd, path, os.O_RDONLY)
            try:
                info = os.fstat(fd)
                actual, actual_size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
                if (info.st_nlink != 1 or actual != digest or actual_size != size
                        or stat.S_IMODE(info.st_mode) != mode or not roles):
                    raise InstallerReleaseBuildError("staged release output differs from its sealed source mapping")
                rows.append(BuildOutputFile(path, actual, actual_size, mode, roles, info.st_dev, info.st_ino))
            finally:
                os.close(fd)
        return tuple(rows)

    def _render_plan(self, source: VerifiedInstallerDistributionReceipt) -> bytes:
        template = _read_relative(source._root_fd, PLAN_TEMPLATE_PATH, 1024 * 1024)
        if hashlib.sha256(template).hexdigest() != PLAN_TEMPLATE_SHA256 or len(template) != PLAN_TEMPLATE_BYTES:
            raise InstallerReleaseBuildError("root setup plan template changed after source verification")
        value = json.loads(template.decode("utf-8"), object_pairs_hook=_unique_pairs)
        catalog = _validate_source_catalog(_read_relative(source._root_fd, CATALOG_SOURCE_PATH, 16 * 1024 * 1024))
        allowed_ids = sorted({row["artifact_id"] for row in catalog["artifacts"]
                              if isinstance(row.get("sha256"), str) and _SHA256.fullmatch(row["sha256"])})
        value.pop("artifact_selection", None)
        value.pop("plan_artifact_id", None)
        value["id"] = "installer-root-setup-plan-v1"
        value["candidate_git_sha"] = source.candidate_git_sha
        value["baseline_tag"] = BASELINE_TAG
        value["baseline_tag_object"] = BASELINE_TAG_OBJECT
        value["baseline_commit"] = BASELINE_COMMIT
        value["baseline_tree_sha256"] = source.baseline_tree_sha256
        value["amendment_manifest_sha256"] = source.amendment_manifest_sha256
        value["allowed_artifact_ids"] = allowed_ids
        value["bootstrap_policy_artifact_id"] = "installer-bootstrap-policy-v1"
        value["template_artifact_ids"] = [COMPILER_TEMPLATE_ID, IDENTITY_TEMPLATE_ID]
        return _canonical_json(value)


def bootstrap_selected_release(candidate_git_sha: str) -> Any:
    """First-source root entry after the launcher has acquired CAS and re-execed it.

    The candidate parameter is consumed only as the exact root-selected commit;
    this callable is never wired to user-mode argv/environment. The fixed CAS
    receipt, current isolated interpreter, and loaded module origins are all
    independently re-resolved before any installed-stage publication.
    """
    _require_linux_root()
    _validate_git_sha(candidate_git_sha)
    distribution_registry = RootInstallerDistributionRegistry()
    distribution_handle, source = distribution_registry.resolve_selected(candidate_git_sha)
    runtime_registry = RootInstallerRuntimeArtifactRegistry()
    interpreter_registry = RootInstallerInterpreterRegistry(distribution_registry, runtime_registry)
    interpreter_handle = interpreter_registry.observe_current_bootstrap_interpreter(distribution_handle)
    actor_verifier = RootSourceBootstrapActorVerifier.from_verified_source(
        distribution_registry, interpreter_registry)
    actor = actor_verifier.verify_current(distribution_handle, interpreter_handle)
    actor.verify_current(source, interpreter_registry.resolve(interpreter_handle, distribution_handle))
    builder = RootInstalledReleaseBuilder(distribution_registry, interpreter_registry, actor_verifier)
    build_handle = builder.build_selected(distribution_handle, interpreter_handle)
    try:
        from .installed_stage_publisher import RootInstalledStagePublisher
    except ImportError:
        raise BootstrapEnrollmentPending("installed-stage publisher is not available in the selected source closure") from None
    publisher = RootInstalledStagePublisher.from_root_setup(builder)
    return publisher.publish_installed_stage(build_handle)


def _verify_frozen_baseline(root_fd: int, rows: tuple[DistributionFile, ...]) -> str:
    prefix = BASELINE_DIRECTORY + "/"
    actual = {row.relative_path[len(prefix):]: row.sha256 for row in rows
              if row.relative_path.startswith(prefix)}
    if not actual or any(not name for name in actual):
        raise InstallerReleaseBuildError("complete frozen baseline tree is missing")
    digest = _manifest_digest(actual)
    try:
        hashes = json.loads(_read_relative(root_fd, BASELINE_DIRECTORY + "/hashes.json", 4 * 1024 * 1024))
    except (ValueError, UnicodeError):
        raise InstallerReleaseBuildError("frozen 160-file snapshot manifest is malformed") from None
    expected_files = hashes.get("files") if isinstance(hashes, dict) else None
    if (not isinstance(hashes, dict) or hashes.get("baseline_tag") != BASELINE_TAG
            or not isinstance(expected_files, dict) or len(expected_files) != 160):
        raise InstallerReleaseBuildError("frozen 160-file snapshot manifest differs from the protected baseline")
    for path, expected in expected_files.items():
        if not isinstance(path, str) or not _SHA256.fullmatch(str(expected)):
            raise InstallerReleaseBuildError("frozen snapshot manifest contains an invalid row")
        relative = path.removeprefix(BASELINE_DIRECTORY + "/")
        if actual.get(relative) != expected:
            raise InstallerReleaseBuildError("frozen 160-file snapshot content differs from its manifest")
    return digest


def _amendment_digest(rows: tuple[DistributionFile, ...]) -> str:
    prefix = "plans/amendments/"
    selected = {row.relative_path: row.sha256 for row in rows if row.relative_path.startswith(prefix)}
    if not selected:
        raise InstallerReleaseBuildError("append-only reviewed amendment inputs are missing")
    template = next((row for row in rows if row.relative_path == PLAN_TEMPLATE_PATH), None)
    if (template is None or template.sha256 != PLAN_TEMPLATE_SHA256
            or template.size_bytes != PLAN_TEMPLATE_BYTES):
        raise InstallerReleaseBuildError("root setup plan template differs from its reviewed v53 bytes")
    return _manifest_digest(selected)


def _validate_source_catalog(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseBuildError("candidate artifact catalog is malformed") from None
    if (not isinstance(value, dict) or set(value) != {"schema", "artifacts", "packages"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or not isinstance(value["artifacts"], list) or not isinstance(value["packages"], list)):
        raise InstallerReleaseBuildError("candidate artifact catalog has an unsupported schema")
    ids: set[str] = set()
    for item in value["artifacts"]:
        if (not isinstance(item, dict) or not isinstance(item.get("artifact_id"), str)
                or not _ID.fullmatch(item["artifact_id"]) or item["artifact_id"] in ids
                or not _SHA256.fullmatch(str(item.get("sha256", "")))
                or type(item.get("size_bytes")) is not int or item["size_bytes"] < 0):
            raise InstallerReleaseBuildError("candidate artifact catalog contains an invalid or duplicate pin")
        ids.add(item["artifact_id"])
    return value


def _manifest_digest(value: Mapping[str, str]) -> str:
    return hashlib.sha256(json.dumps(dict(value), sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()


def _inspect_source_tree(root_fd: int, exported: tuple[tuple[str, str, int], ...]) -> tuple[DistributionFile, ...]:
    by_path = {path: (digest, size) for path, digest, size in exported}
    rows: list[DistributionFile] = []
    for relative, (expected_digest, expected_size) in sorted(by_path.items()):
        fd = _open_relative(root_fd, relative, os.O_RDONLY)
        try:
            info = os.fstat(fd)
            digest, size = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
                    or digest != expected_digest or size != expected_size
                    or stat.S_IMODE(info.st_mode) not in {0o444, 0o555}):
                raise InstallerReleaseBuildError("exported source file differs from exact Git blob bytes")
            rows.append(DistributionFile(relative, digest, size, stat.S_IMODE(info.st_mode),
                                         info.st_dev, info.st_ino))
        finally:
            os.close(fd)
    if len(rows) != len(by_path) or _enumerate_regular_files(root_fd) != tuple(sorted(by_path)):
        raise InstallerReleaseBuildError("candidate source tree has missing or duplicate files")
    return tuple(rows)


def _ensure_root_directory(path: Path, mode: int) -> None:
    if not path.exists():
        try:
            path.mkdir(mode=mode)
        except FileExistsError:
            pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != mode):
        raise InstallerReleaseBuildError("fixed source CAS directory ownership or mode is invalid")


def _verify_private_cas_root(path: Path) -> None:
    fd = _open_secure_directory(path, expected_uid=0)
    try:
        info = os.fstat(fd)
        if (info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700
                or info.st_dev != os.stat(path.parent, follow_symlinks=False).st_dev):
            raise InstallerReleaseBuildError("fixed source CAS root is not private root-owned storage")
    finally:
        os.close(fd)


def _enumerate_regular_files(root_fd: int) -> tuple[str, ...]:
    files: list[str] = []
    def walk(directory_fd: int, prefix: str) -> None:
        scan = os.dup(directory_fd)
        try:
            with os.scandir(scan) as entries:
                for entry in entries:
                    relative = f"{prefix}/{entry.name}" if prefix else entry.name
                    _validate_relative_path(relative)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=directory_fd)
                        try:
                            walk(child, relative)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        files.append(relative)
                    else:
                        raise InstallerReleaseBuildError("sealed source/output contains a link or special file")
        finally:
            os.close(scan)
    walk(root_fd, "")
    return tuple(sorted(files))


def _make_immutable_tree(root: Path) -> None:
    """Seal an already-built private source tree before making it addressable."""
    for directory, dirs, files in os.walk(root, topdown=False, followlinks=False):
        current = Path(directory)
        for name in files:
            path = current / name
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise InstallerReleaseBuildError("source staging contains a linked or special file")
            os.chmod(path, 0o555 if info.st_mode & 0o111 else 0o444, follow_symlinks=False)
        for name in dirs:
            path = current / name
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise InstallerReleaseBuildError("source staging contains a linked or special directory")
            os.chmod(path, 0o555, follow_symlinks=False)
        os.chmod(current, 0o555, follow_symlinks=False)
        _fsync_dir(current)


def _tree_byte_usage(root: Path) -> int:
    total = 0
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current = Path(directory)
        for name in dirs:
            info = (current / name).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                raise InstallerReleaseBuildError("source CAS contains an unsafe directory entry")
        for name in files:
            info = (current / name).lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1):
                raise InstallerReleaseBuildError("source CAS contains a linked or unowned file")
            total += info.st_size
            if total > MAX_SOURCE_CAS_BYTES:
                return total
    return total


def _write_distribution_receipt(candidate_dir: Path,
                                receipt: VerifiedInstallerDistributionReceipt) -> None:
    source_manifest_rows: list[dict[str, Any]] = []
    for row in receipt.files:
        fd = receipt.open_file(row.relative_path)
        try:
            body = _read_exact_fd(fd, row.size_bytes)
        finally:
            os.close(fd)
        blob = hashlib.sha1(b"blob " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
        source_manifest_rows.append({"path": row.relative_path, "sha256": row.sha256,
                                     "size_bytes": row.size_bytes, "mode": row.mode,
                                     "git_blob_sha1": blob})
    manifest = _canonical_json(source_manifest_rows)
    _create_private_file(candidate_dir, "source-manifest.json", manifest)
    record = {
        "schema": 1, "receipt_handle": receipt.receipt_handle,
        "candidate_git_sha": receipt.candidate_git_sha, "git_tree_sha1": receipt.git_tree_sha1,
        "source_tree_sha256": receipt.source_tree_sha256,
        "baseline_tree_sha256": receipt.baseline_tree_sha256,
        "amendment_manifest_sha256": receipt.amendment_manifest_sha256,
        "source_catalog_sha256": receipt.source_catalog_sha256,
        "source_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "source_device": receipt.root_device, "source_inode": receipt.root_inode,
        "files": [
            {"relative_path": row.relative_path, "sha256": row.sha256,
             "size_bytes": row.size_bytes, "mode": row.mode,
             "device": row.device, "inode": row.inode}
            for row in receipt.files
        ],
    }
    _create_private_file(candidate_dir, "source-receipt.json", _canonical_json(record))
    _fsync_dir(candidate_dir)


def _create_private_file(parent: Path, name: str, body: bytes) -> None:
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent_fd)
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short private receipt write")
                view = view[written:]
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _read_private_json(path: Path, maximum: int) -> dict[str, Any]:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise BootstrapEnrollmentPending("root-owned source receipt is unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
            raise InstallerReleaseBuildError("source receipt custody or size is invalid")
        raw = _read_exact_fd(fd, info.st_size)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError, json.JSONDecodeError):
        raise InstallerReleaseBuildError("root-owned source receipt is malformed") from None
    finally:
        os.close(fd)


def _read_deployment_predecessor() -> DeploymentPredecessor:
    parent_path = Path("/var/lib/hermes-installer/deployments")
    parent_fd = _open_secure_directory(parent_path, expected_uid=0)
    try:
        parent = os.fstat(parent_fd)
        try:
            fd = os.open("current.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
        except FileNotFoundError:
            return DeploymentPredecessor("absent", parent.st_dev, parent.st_ino)
        except OSError:
            raise InstallerReleaseBuildError("deployment predecessor cannot be securely opened") from None
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 1024 * 1024):
                raise InstallerReleaseBuildError("deployment predecessor receipt custody is invalid")
            raw = _read_exact_fd(fd, info.st_size)
            try:
                record = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
            except (ValueError, UnicodeError, json.JSONDecodeError):
                raise InstallerReleaseBuildError("deployment predecessor receipt is malformed") from None
            candidate = record.get("candidate_git_sha") if isinstance(record, dict) else None
            if not isinstance(candidate, str) or not _GIT_SHA.fullmatch(candidate):
                raise InstallerReleaseBuildError("deployment predecessor has no exact candidate identity")
            return DeploymentPredecessor("present", parent.st_dev, parent.st_ino,
                                         hashlib.sha256(raw).hexdigest(), info.st_dev, info.st_ino, candidate)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _open_relative(root_fd: int, relative: str, flags: int) -> int:
    _validate_relative_path(relative)
    parts = relative.split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        return os.open(parts[-1], flags | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=current)
    finally:
        os.close(current)


def _read_relative(root_fd: int, relative: str, maximum: int) -> bytes:
    fd = _open_relative(root_fd, relative, os.O_RDONLY)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise InstallerReleaseBuildError("protected source file type or size is invalid")
        body = _read_exact_fd(fd, info.st_size)
        if os.read(fd, 1):
            raise InstallerReleaseBuildError("protected source file grew during read")
        return body
    finally:
        os.close(fd)


def _write_relative(root_fd: int, relative: str, body: bytes, *, mode: int) -> None:
    _validate_relative_path(relative)
    parts = relative.split("/")
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
        fd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     mode, dir_fd=current)
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short source CAS write")
                view = view[written:]
            os.fchmod(fd, mode)
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        os.close(current)


def _hash_fd(fd: int, maximum: int) -> tuple[str, int]:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        part = os.read(fd, min(1024 * 1024, maximum + 1 - total))
        if not part:
            break
        total += len(part)
        if total > maximum:
            raise InstallerReleaseBuildError("source file exceeds the protected byte bound")
        digest.update(part)
    return digest.hexdigest(), total


def _read_exact_fd(fd: int, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = os.read(fd, size - len(chunks))
        if not part:
            raise InstallerReleaseBuildError("protected source file ended during read")
        chunks.extend(part)
    return bytes(chunks)


def _read_exact(stream: Any, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        part = stream.read(min(1024 * 1024, size - len(chunks)))
        if not part:
            raise InstallerReleaseBuildError("Git source object ended during export")
        chunks.extend(part)
    return bytes(chunks)


def _validate_relative_path(value: str) -> None:
    if (not isinstance(value, str) or not value or value.startswith("/") or "\\" in value
            or "\x00" in value or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise InstallerReleaseBuildError("source path is not a normalized portable relative path")


def _validate_git_sha(value: str) -> None:
    if not isinstance(value, str) or not _GIT_SHA.fullmatch(value):
        raise InstallerReleaseBuildError("selected installer candidate must be an exact 40-character Git commit")


def distribution_root(receipt: VerifiedInstallerDistributionReceipt) -> Path:
    if not isinstance(receipt, VerifiedInstallerDistributionReceipt) or receipt._seal is not _SEAL:
        raise TypeError("candidate source root requires a sealed distribution receipt")
    return SOURCE_CAS_V65_ROOT / receipt.candidate_git_sha / "source"


def _open_secure_directory(path: Path, *, expected_uid: int) -> int:
    if not path.is_absolute():
        raise InstallerReleaseBuildError("managed runtime prefix must be absolute")
    parts = path.parts
    current = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              dir_fd=current)
            os.close(current)
            current = next_fd
            info = os.fstat(current)
            if (info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022):
                raise InstallerReleaseBuildError("managed interpreter prefix ancestry is not root-owned and protected")
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid:
            raise InstallerReleaseBuildError("managed interpreter prefix is not a root-owned directory")
        result, current = current, -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def _relative_below(root: Path, path: Path) -> str:
    try:
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        relative = resolved_path.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        raise InstallerReleaseBuildError("observed file is outside its selected root") from None
    _validate_relative_path(relative)
    return relative


def _is_beneath(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _scan_runtime_prefix(root_fd: int, *, expected_uid: int, expected_gid: int) -> tuple[RuntimeFile, ...]:
    rows: list[RuntimeFile] = []
    total = 0

    def walk(fd: int, prefix: str) -> None:
        nonlocal total
        scan_fd = os.dup(fd)
        try:
            with os.scandir(scan_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if name in {".", ".."} or "/" in name or "\\" in name:
                        raise InstallerReleaseBuildError("runtime prefix contains an invalid path entry")
                    relative = f"{prefix}/{name}" if prefix else name
                    _validate_relative_path(relative)
                    info = entry.stat(follow_symlinks=False)
                    if info.st_uid != expected_uid or info.st_gid != expected_gid or info.st_dev != os.fstat(root_fd).st_dev:
                        raise InstallerReleaseBuildError("runtime prefix contains foreign-owned or cross-device content")
                    if stat.S_ISDIR(info.st_mode):
                        if stat.S_IMODE(info.st_mode) & 0o022:
                            raise InstallerReleaseBuildError("runtime directory is writable by group or others")
                        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=fd)
                        try:
                            walk(child_fd, relative)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022:
                            raise InstallerReleaseBuildError("runtime file is linked or writable by group or others")
                        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            digest, size = _hash_fd(file_fd, MAX_SOURCE_FILE_BYTES)
                        finally:
                            os.close(file_fd)
                        total += size
                        if total > MAX_SOURCE_TREE_BYTES or len(rows) >= MAX_SOURCE_FILES:
                            raise InstallerReleaseBuildError("isolated runtime closure exceeds its protected bound")
                        rows.append(RuntimeFile(relative, digest, size, stat.S_IMODE(info.st_mode),
                                                info.st_dev, info.st_ino))
                    else:
                        raise InstallerReleaseBuildError("runtime prefix contains a symlink or special file")
        finally:
            os.close(scan_fd)

    walk(root_fd, "")
    rows.sort(key=lambda row: row.relative_path)
    if not rows:
        raise BootstrapEnrollmentPending("selected installer runtime has no measured file closure")
    return tuple(rows)


def _verify_runtime_files(root_fd: int, rows: tuple[RuntimeFile, ...], expected_uid: int,
                          expected_gid: int) -> None:
    actual = _scan_runtime_prefix(root_fd, expected_uid=expected_uid, expected_gid=expected_gid)
    if actual != rows:
        raise InstallerReleaseBuildError("isolated installer runtime closure changed after observation")


def _require_python_requirement(project_bytes: bytes) -> None:
    try:
        project = tomllib.loads(project_bytes.decode("utf-8"))
        requires = project["project"]["requires-python"]
    except (UnicodeError, ValueError, KeyError, TypeError):
        raise InstallerReleaseBuildError("selected source has no valid installer Python requirement") from None
    if not isinstance(requires, str) or not re.search(r"(?:^|,)\s*>=\s*3\.11(?:\.|,|$)", requires):
        raise BootstrapEnrollmentPending("selected installer source does not allow the required Python 3.11 runtime")


def _locked_package_versions(lock_bytes: bytes) -> Mapping[str, frozenset[str]]:
    try:
        text = lock_bytes.decode("utf-8")
    except UnicodeError:
        raise InstallerReleaseBuildError("selected installer runtime lock is malformed") from None
    result: dict[str, set[str]] = {}
    current: tuple[str, str] | None = None
    hashes: set[str] = set()
    for raw_line in text.splitlines() + [""]:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            if current is not None and not raw_line.rstrip().endswith("\\"):
                if not hashes:
                    raise InstallerReleaseBuildError("installer runtime lock package lacks verified hashes")
                name, version = current
                result.setdefault(_normalize_package_name(name), set()).add(version)
                current, hashes = None, set()
            continue
        if current is None:
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(\\?)", line)
            if match is None:
                raise InstallerReleaseBuildError("installer runtime lock contains an unpinned requirement")
            current = (match.group(1), match.group(2))
            if not match.group(3):
                raise InstallerReleaseBuildError("installer runtime lock package lacks explicit hashes")
            continue
        match = re.fullmatch(r"--hash=sha256:([0-9a-f]{64})\s*(\\?)", line)
        if match is None:
            raise InstallerReleaseBuildError("installer runtime lock contains an invalid hash continuation")
        hashes.add(match.group(1))
        if not match.group(2):
            name, version = current
            result.setdefault(_normalize_package_name(name), set()).add(version)
            current, hashes = None, set()
    if current is not None or not result:
        raise InstallerReleaseBuildError("installer runtime lock is incomplete or empty")
    return {name: frozenset(versions) for name, versions in result.items()}


def _runtime_dependency_receipts(prefix: Path,
                                 locked: Mapping[str, frozenset[str]],
                                 registry: RootInstallerRuntimeArtifactRegistry) -> tuple[list[tuple[str, str]], tuple[str, ...]]:
    packages: list[tuple[str, str]] = []
    handles: list[str] = []
    seen: set[tuple[str, str]] = set()
    search_paths = [str(Path(sysconfig.get_path(key)).resolve(strict=True))
                    for key in ("purelib", "platlib") if sysconfig.get_path(key)]
    for dist in importlib.metadata.distributions(path=search_paths):
        name = dist.metadata.get("Name")
        version = dist.version
        if not isinstance(name, str) or not isinstance(version, str):
            raise InstallerReleaseBuildError("installed runtime dependency identity is incomplete")
        normalized = _normalize_package_name(name)
        if version not in locked.get(normalized, frozenset()):
            raise InstallerReleaseBuildError("installed runtime dependency is not pinned by selected uv.lock")
        identity = (normalized, version)
        if identity in seen:
            raise InstallerReleaseBuildError("installer runtime contains duplicate package distributions")
        seen.add(identity)
        files = dist.files
        if not files:
            raise BootstrapEnrollmentPending("runtime dependency has no installed file manifest")
        file_digests: dict[str, str] = {}
        for item in files:
            path = Path(dist.locate_file(item))
            relative = _relative_below(prefix, path)
            fd = _open_secure_file(path, expected_uid=0)
            try:
                digest, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
            finally:
                os.close(fd)
            file_digests[relative] = digest
        digest = _manifest_digest(file_digests)
        packages.append((normalized + "@" + version, digest))
        handle = registry._mint_observed(name, version, file_digests, locked[normalized])
        handles.append(handle)
    packages.sort()
    if not packages:
        raise BootstrapEnrollmentPending("selected installer runtime has no verified locked dependencies")
    return packages, tuple(handles)


def _runtime_artifact_current_files(
        interpreter: VerifiedInstallerInterpreterReceipt,
        receipt: VerifiedInstallerRuntimeArtifactReceipt) -> tuple[tuple[str, str], ...]:
    current: list[tuple[str, str]] = []
    for relative, expected in receipt.files:
        fd = interpreter.open_runtime_file(relative)
        try:
            actual, _ = _hash_fd(fd, MAX_SOURCE_FILE_BYTES)
        finally:
            os.close(fd)
        current.append((relative, actual))
    return tuple(current)


def _open_secure_file(path: Path, *, expected_uid: int) -> int:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseBuildError("runtime dependency file is unavailable without following links") from None
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise InstallerReleaseBuildError("runtime dependency file custody is unsafe")
    return fd


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _process_start_ticks(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        fields = raw[raw.rfind(")") + 2:].split()
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        raise BootstrapEnrollmentPending("root bootstrap process start time is unavailable") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _remove_tree_no_follow(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        path.unlink(missing_ok=True)
        return
    for entry in path.iterdir():
        _remove_tree_no_follow(entry)
    path.rmdir()


def _fsync_tree(root_fd: int) -> None:
    def walk(directory_fd: int) -> None:
        with os.scandir(os.dup(directory_fd)) as entries:
            for entry in entries:
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory_fd)
                    try:
                        walk(child)
                    finally:
                        os.close(child)
        os.fsync(directory_fd)
    walk(root_fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _require_linux_root() -> None:
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or os.getuid() != 0:
        raise BootstrapEnrollmentPending("installer source CAS acquisition requires the managed Linux root bootstrap")
