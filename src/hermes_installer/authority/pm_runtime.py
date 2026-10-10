"""Root-only provisioning and verification of Hermes' PM-owned Python runtime.

The installer interpreter, PM bootstrap interpreter, and PM committed application
interpreter are distinct authorities. This module only returns the last one to
root-private native operations after revalidating an opaque receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import resource
import secrets
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Protocol

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending

SOURCE_ID = "hermes-source-7085fbf7753266fc4943c55ac04926186bc90005"
SOURCE_COMMIT = "7085fbf7753266fc4943c55ac04926186bc90005"
SOURCE_SHA256 = "592ac0b09a7130cf2f8166f039098ba4ed40fb91535c601a6a7e5b1fcf889d01"
LOCK_ID = "hermes-pm-lock"
LOCK_SHA256 = "49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549"
LOCK_BYTES = 33804
UV_ID = "hermes-pm-uv-linux-arm64"
UV_SHA256 = "bb66cb52e7b1823aed1183630d8d8e5c958840d584a4c55ec10a4cfc168dcca2"
UV_BYTES = 20423730
UV_EXECUTABLE_SHA256 = "20d0be6a6bd33f55e4ceb0e52ac2f733722b1a7959498e6401ecf84bc05e48a8"
PYTHON_ID = "hermes-pm-python314-linux-arm64"
PYTHON_SHA256 = "30f1cc489be654477d895b441e196bb080738bf0456da82080ad4ab66a22d80f"
PYTHON_BYTES = 95628137
PYTHON_EXECUTABLE_SHA256 = "566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001"
_MAX_SECONDS = 1800.0


class PMRuntimeUnavailable(BootstrapEnrollmentPending):
    """The selected official PM runtime could not be provisioned or verified."""


@dataclass(frozen=True, slots=True)
class VerifiedPMRuntimeSelection:
    """Root-private verified selection. Never serialize or expose to worker RPC."""
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    source_artifact_id: str
    python_path: Path
    runtime_sha256: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    version_info: tuple[int, int, int]
    implementation: str
    cache_tag: str
    soabi: str
    machine: str


@dataclass(frozen=True, slots=True)
class VerifiedPMRuntimeProjectionMember:
    """One current catalogued member of the official PM base Python tree.

    Regular-file ``fd`` values are read-only descriptors. Symlink rows carry
    their exact catalogued target and, on Linux, an O_PATH descriptor to the
    link itself. Paths are relative to ``runtime_root_fd`` and are never
    caller supplied.
    """
    relative_path: str
    sha256: str
    size_bytes: int
    executable: bool
    mode: int
    device: int
    inode: int
    uid: int
    gid: int
    kind: str
    link_target: str | None
    fd: int | None


@dataclass(frozen=True, slots=True)
class VerifiedPMRuntimeProjection:
    """Held, receipt-backed official PM Python base runtime projection.

    The consumer owns every descriptor in this value and must call ``close``
    when it has duplicated the members it needs. ``members`` is the complete
    protected tree, ``runtime_members`` omits executable files and the
    selected interpreter, and ``other_executable_members`` preserves the
    remaining executable rows needed to verify the full source closure.
    """
    selection: VerifiedPMRuntimeSelection
    base_closure_sha256: str
    runtime_root_fd: int
    executable_relative_path: str
    executable_member: VerifiedPMRuntimeProjectionMember
    runtime_members: tuple[VerifiedPMRuntimeProjectionMember, ...]
    other_executable_members: tuple[VerifiedPMRuntimeProjectionMember, ...]
    members: tuple[VerifiedPMRuntimeProjectionMember, ...]

    def close(self) -> None:
        descriptors = {self.runtime_root_fd}
        descriptors.update(member.fd for member in self.members if member.fd is not None)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class VerifiedCommittedPMVenvTree:
    """Descriptor-held complete committed Hermes venv observation.

    Unlike the immutable PM base tree, a venv has no catalogued per-file
    inventory. Its root-owned receipt supplies the closure digest; this
    observer discovers members through no-follow directory descriptors,
    hashes their opened bytes, and retains every file/link descriptor.
    """

    root_fd: int
    root_device: int
    root_inode: int
    closure_sha256: str
    members: tuple[VerifiedPMRuntimeProjectionMember, ...]

    def close(self) -> None:
        for descriptor in {self.root_fd, *(item.fd for item in self.members
                                           if item.fd is not None)}:
            try:
                os.close(descriptor)
            except OSError:
                pass


def observe_committed_pm_venv_tree(root: Path, *, expected_closure_sha256: str
                                   ) -> VerifiedCommittedPMVenvTree:
    """Open the exact full PM venv described by a current root receipt.

    This is intentionally stricter than ``_tree_sha256``: path walking alone
    cannot support later launch-time currentness after another process changes
    an executable or dependency. The returned descriptors bind every member
    that contributed to the measured digest.
    """
    if (not root.is_absolute() or not isinstance(expected_closure_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_closure_sha256)):
        raise ValueError("committed PM venv binding is malformed")
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    root_fd = os.open(root, flags)
    held: list[int] = []
    members: list[VerifiedPMRuntimeProjectionMember] = []
    entries: dict[str, tuple[str, int, str, str | None, bool]] = {}
    total_bytes = 0
    try:
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or not _root_owned(root_info)
                or stat.S_IMODE(root_info.st_mode) & 0o022):
            raise ValueError("committed PM venv root custody is invalid")

        def visit(directory_fd: int, prefix: str) -> None:
            nonlocal total_bytes
            names = sorted(os.listdir(directory_fd))
            if len(entries) + len(names) > 50_000:
                raise ValueError("committed PM venv exceeds the member bound")
            for name in names:
                if (not name or name in {".", ".."} or "/" in name
                        or "\\" in name or "\x00" in name):
                    raise ValueError("committed PM venv contains a nonportable path")
                relative = f"{prefix}/{name}" if prefix else name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if not _root_owned(info) or stat.S_IMODE(info.st_mode) & 0o022:
                    raise ValueError("committed PM venv member ownership or mode is unsafe")
                if stat.S_ISDIR(info.st_mode):
                    entries[relative] = ("", 0, "dir", None, False)
                    child = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child)
                        if (not stat.S_ISDIR(opened.st_mode)
                                or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                                or not _root_owned(opened)
                                or stat.S_IMODE(opened.st_mode) & 0o022):
                            raise ValueError("committed PM venv directory changed while opening")
                        visit(child, relative)
                    finally:
                        os.close(child)
                    continue
                if stat.S_ISREG(info.st_mode):
                    if info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024:
                        raise ValueError("committed PM venv regular member exceeds custody bounds")
                    total_bytes += info.st_size
                    if total_bytes > 2 * 1024 * 1024 * 1024:
                        raise ValueError("committed PM venv closure exceeds byte bound")
                    member_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                        | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                    held.append(member_fd)
                    opened = os.fstat(member_fd)
                    if (not stat.S_ISREG(opened.st_mode)
                            or (opened.st_dev, opened.st_ino, opened.st_size)
                               != (info.st_dev, info.st_ino, info.st_size)
                            or not _root_owned(opened) or opened.st_nlink != 1
                            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode)):
                        raise ValueError("committed PM venv file changed while opening")
                    sha = _hash_fd(member_fd)
                    after = os.fstat(member_fd)
                    if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                         after.st_ctime_ns) != (opened.st_dev, opened.st_ino, opened.st_size,
                                                opened.st_mtime_ns, opened.st_ctime_ns)):
                        raise ValueError("committed PM venv file changed while hashing")
                    executable = bool(stat.S_IMODE(opened.st_mode) & 0o111)
                    entries[relative] = (sha, opened.st_size, "file", None, executable)
                    members.append(VerifiedPMRuntimeProjectionMember(
                        relative, sha, opened.st_size, executable, stat.S_IMODE(opened.st_mode),
                        opened.st_dev, opened.st_ino, opened.st_uid, opened.st_gid,
                        "file", None, member_fd))
                    continue
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(name, dir_fd=directory_fd)
                    if not _safe_link_target(relative, target):
                        raise ValueError("committed PM venv link escapes its root")
                    link_fd = os.open(name, getattr(os, "O_PATH", os.O_RDONLY)
                                      | getattr(os, "O_NOFOLLOW", 0)
                                      | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                    held.append(link_fd)
                    opened = os.fstat(link_fd)
                    if (not stat.S_ISLNK(opened.st_mode)
                            or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                            or os.readlink(name, dir_fd=directory_fd) != target):
                        raise ValueError("committed PM venv link changed while opening")
                    raw = target.encode("utf-8")
                    sha = hashlib.sha256(raw).hexdigest()
                    entries[relative] = (sha, len(raw), "symlink", target, False)
                    members.append(VerifiedPMRuntimeProjectionMember(
                        relative, sha, len(raw), False, stat.S_IMODE(info.st_mode),
                        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                        "symlink", target, link_fd))
                    continue
                raise ValueError("committed PM venv contains a special file")

        visit(root_fd, "")
        digest = hashlib.sha256()
        for relative, (sha, _size, kind, target, _executable) in sorted(entries.items()):
            digest.update(relative.encode("utf-8") + b"\0")
            if kind == "dir":
                digest.update(b"dir\0")
            elif kind == "symlink":
                digest.update(b"link\0" + str(target).encode("utf-8"))
            else:
                digest.update(b"file\0" + bytes.fromhex(sha))
        observed = digest.hexdigest()
        if observed != expected_closure_sha256:
            raise ValueError("committed PM venv closure differs from its protected receipt")
        members.sort(key=lambda item: item.relative_path)
        return VerifiedCommittedPMVenvTree(root_fd, root_info.st_dev, root_info.st_ino,
                                           observed, tuple(members))
    except BaseException:
        for descriptor in set(held + [root_fd]):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


@dataclass(frozen=True, slots=True)
class VerifiedPMUVToolProjection:
    """Current root-receipt-backed uv executable held read-only by descriptor."""
    receipt_handle: str
    source_receipt_handle: str
    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    transaction_handle: str
    prepared_generation_id: str
    fd: int

    def close(self) -> None:
        try:
            os.close(self.fd)
        except OSError:
            pass


class NativePMRuntimeResolver(Protocol):
    def resolve_python(self, *, pm_runtime_handle: str, enrollment_id: str,
                       service_generation: str, source_artifact_id: str) -> Path: ...


class RootPMRuntimeProvisioner:
    """Provision one source/PM-lock selection into a private generation.

    All paths and target choices are constructor-owned. Caller-visible inputs
    are opaque receipt handles minted by the active root setup session.
    """
    def __init__(self, *, setup_session: Any,
                 artifact_fetcher: Any, receipt_registry: Any, catalog: Any,
                 artifact_root: Path, runtime_root: Path,
                 authority_uid: int = 0, monotonic: Callable[[], float] = time.monotonic,
                 timeout_seconds: float = _MAX_SECONDS):
        if (authority_uid != 0 or not artifact_root.is_absolute() or not runtime_root.is_absolute()
                or not callable(getattr(setup_session, "_check_live", None))
                or not callable(getattr(getattr(getattr(setup_session, "_factory", None), "session_store", None), "_live", None))
                or not callable(getattr(artifact_fetcher, "fetch_selected_artifact", None))
                or not callable(getattr(receipt_registry, "lookup", None))
                or not callable(getattr(catalog, "materialize_tree", None))):
            raise ValueError("PM runtime provisioner requires one root setup custody set")
        if not 1 <= timeout_seconds <= _MAX_SECONDS:
            raise ValueError("PM runtime deadline exceeds the reviewed bound")
        self.setup_session = setup_session
        self.sessions = setup_session._factory.session_store
        self.session_handle = setup_session._handle
        self.fetcher = artifact_fetcher
        self.receipts = receipt_registry
        self.catalog = catalog
        self.artifact_root = artifact_root
        self.runtime_root = runtime_root
        self.authority_uid = authority_uid
        self.monotonic = monotonic
        self.timeout_seconds = timeout_seconds

    def provision_selected(self, *, prepared_setup_receipt_handle: str,
                           source_receipt_handle: str,
                           pm_lock_receipt_handle: str) -> str:
        self._require_root()
        self.setup_session._check_live()
        live = self.sessions._live(self.session_handle)
        proof = self._proof(live)
        if (not _opaque(prepared_setup_receipt_handle)
                or not _opaque(source_receipt_handle) or not _opaque(pm_lock_receipt_handle)):
            raise BootstrapEnrollmentError("PM runtime provisioning requires opaque setup receipts")
        prior = self.setup_session._last_receipt
        if (prior is None or prior.provision_receipt_handle != prepared_setup_receipt_handle
                or prior.transaction_handle != proof.transaction_handle
                or prior.state not in {"prepared", "committed"}):
            raise BootstrapEnrollmentError("prepared setup receipt is not current for this root session")
        self._lookup_exact(source_receipt_handle, proof, SOURCE_ID, SOURCE_SHA256)
        self._lookup_exact(pm_lock_receipt_handle, proof, LOCK_ID, LOCK_SHA256)
        if SOURCE_ID not in live.plan.allowed_artifact_ids or LOCK_ID not in live.plan.allowed_artifact_ids:
            raise BootstrapEnrollmentError("selected setup plan excludes the pinned Hermes source or PM lock")

        # The PM lock is the root-selected feature policy. Do not accept caller
        # package arguments or silently install the browser/driver extras.
        lock_spec = self.catalog._artifact(LOCK_ID, LOCK_SHA256)
        if lock_spec.size_bytes != LOCK_BYTES:
            raise BootstrapEnrollmentError("official PM lock differs from the source-derived size pin")
        self._verify_lock_payload()

        # Installer-owned output is nested under a fresh, private transaction
        # generation so incomplete or failed PM sync is never current.
        generation = "pm-" + secrets.token_hex(16)
        base = self.runtime_root / generation
        _mkdir_private(self.runtime_root)
        base.mkdir(mode=0o700)
        os.chmod(base, 0o700)
        _require_dir(base)
        deadline = self.monotonic() + self.timeout_seconds
        try:
            source = self._resolve_source(source_receipt_handle, proof)
            uv_handle = self.fetcher.fetch_selected_artifact(self.session_handle, UV_ID)
            python_handle = self.fetcher.fetch_selected_artifact(self.session_handle, PYTHON_ID)
            uv_artifact = self._resolve_artifact(uv_handle, proof, UV_ID, UV_SHA256, UV_BYTES)
            py_artifact = self._resolve_artifact(python_handle, proof, PYTHON_ID, PYTHON_SHA256, PYTHON_BYTES)
            uv_tree = self.catalog.materialize_tree(UV_ID, UV_SHA256, self.artifact_root, expected_uid=0)
            py_tree = self.catalog.materialize_tree(PYTHON_ID, PYTHON_SHA256, self.artifact_root, expected_uid=0)
            uv_tree_closure_sha256 = _tree_sha256(uv_tree.path)
            uv_tree_relative = uv_tree.path.relative_to(self.artifact_root).as_posix()
            if not _safe_relative(uv_tree_relative):
                raise BootstrapEnrollmentError("official PM uv tree is outside its protected artifact root")
            uv_spec = self.catalog.artifacts[UV_ID]
            uv_executable_row = next((row for row in uv_spec.tree_files if row.path == "uv"), None)
            if (uv_executable_row is None or uv_executable_row.kind != "file"
                    or not uv_executable_row.executable
                    or uv_executable_row.sha256 != UV_EXECUTABLE_SHA256):
                raise BootstrapEnrollmentError("official PM uv executable differs from the reviewed source pin")
            _verify_catalog_runtime_root(uv_tree.path, uv_spec.tree_files,
                                         expected_closure_sha256=uv_tree_closure_sha256)
            base_python_closure_sha256 = _tree_sha256(py_tree.path)
            base_python_tree_relative = py_tree.path.relative_to(self.artifact_root).as_posix()
            if not _safe_relative(base_python_tree_relative):
                raise BootstrapEnrollmentError("official PM base Python tree is outside its protected artifact root")
            python_spec = self.catalog.artifacts[PYTHON_ID]
            executable_row = next((row for row in python_spec.tree_files
                                   if row.path == "bin/python3.14"), None)
            if (executable_row is None or executable_row.kind != "file"
                    or not executable_row.executable
                    or executable_row.sha256 != PYTHON_EXECUTABLE_SHA256):
                raise BootstrapEnrollmentError("official PM Python executable differs from the reviewed source pin")
            _verify_catalog_runtime_root(py_tree.path, python_spec.tree_files,
                                         expected_closure_sha256=base_python_closure_sha256)
            uv = _find_executable(uv_tree.path, "uv")
            uv_probe = subprocess.run([str(uv), "--version"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin"},
                timeout=10, check=False, close_fds=True)
            if uv_probe.returncode != 0 or uv_probe.stdout.decode("utf-8", "replace").strip() != "uv 0.12.3":
                raise PMRuntimeUnavailable("verified pinned uv artifact did not report the selected version")
            bootstrap_python = _find_executable(py_tree.path, "python3.14")
            # Ensure root is using the platform-qualified artifacts; unsupported
            # host architectures fail closed instead of substituting a host tool.
            if (platform.system() != "Linux" or platform.machine().lower() not in {"aarch64", "arm64"}
                    or platform.libc_ver()[0].lower() != "glibc"):
                raise PMRuntimeUnavailable("no exact official PM toolchain is pinned for this platform")
            project = source.tree_path
            if source.commit != SOURCE_COMMIT or not (project / "pm" / "cli.py").is_file():
                raise BootstrapEnrollmentError("source receipt does not resolve to the pinned official PM source")
            source_lock = project / "pm" / "lock.json"
            if source_lock.stat().st_size != LOCK_BYTES or _hash(source_lock) != LOCK_SHA256:
                raise BootstrapEnrollmentError("Hermes source PM lock differs from the separately selected lock receipt")
            env_root = base / "hermes-home"
            tools_root = base / "tools"
            env = {
                "HOME": str(env_root), "HERMES_HOME": str(env_root),
                "HERMES_RUNTIME_DIR": str(tools_root), "UV_NO_CONFIG": "1",
                "UV_NO_PROJECT": "1", "UV_PYTHON_INSTALL_DIR": str(tools_root / "python"),
                "UV_CACHE_DIR": str(base / "uv-cache"), "PYTHONNOUSERSITE": "1",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8",
            }
            _mkdir_private(env_root); _mkdir_private(tools_root)
            # Root uses the verified base Python only as the PM bootstrap. PM
            # alone creates the committed application environment from its lock.
            code = (
                "import sys; sys.path.insert(0, " + repr(str(project)) + "); "
                "import pm.cli; raise SystemExit(pm.cli.main())"
            )
            remaining = max(0.1, deadline - self.monotonic())
            result = _run_managed(
                [str(bootstrap_python), "-I", "-B", "-c", code,
                 "install", "--without", "agent-browser", "--without", "cua-driver"],
                cwd=project, env=env, timeout=remaining, session_store=self.sessions,
                session_handle=self.session_handle, deadline=deadline, monotonic=self.monotonic)
            if result.returncode != 0:
                raise PMRuntimeUnavailable("official Hermes PM dependency synchronization failed")
            pm_receipt, sync_features = _read_sync_receipt(env_root / "logs" / "update_receipts" / "latest.json")
            _check_live(self.sessions, self.session_handle, self.monotonic, deadline)
            executable = _committed_python(bootstrap_python, project, env, deadline, self.monotonic,
                                           self.sessions, self.session_handle)
            identity = _observe_runtime(executable, expected_uid=0, expected_root=base)
            if identity["version_info"][0:2] != (3, 14):
                raise PMRuntimeUnavailable("PM committed environment is not Python 3.14")
            receipt = self._publish_receipt(
                base=base, generation=generation, prepared=prior, proof=proof,
                source_handle=source_receipt_handle, executable=executable,
                identity=identity, sync_receipt=pm_receipt, feature_list=sync_features,
                artifact_handles=(uv_handle, python_handle),
                uv_tree_relative=uv_tree_relative,
                uv_tree_closure_sha256=uv_tree_closure_sha256,
                base_python_tree_relative=base_python_tree_relative,
                base_python_closure_sha256=base_python_closure_sha256,
            )
            return receipt
        except BaseException:
            _remove_private(base)
            raise

    def _require_root(self) -> None:
        if os.geteuid() != 0 or os.getuid() != 0 or platform.system() != "Linux":
            raise PMRuntimeUnavailable("official PM runtime provisioning requires installed Linux root")

    def _proof(self, live: Any) -> Any:
        from .bootstrap_enrollment import _LiveRootSetupAuthorizer
        proof = _LiveRootSetupAuthorizer._proof(live)
        if proof.transaction_handle != live.record.get("transaction_handle"):
            raise BootstrapEnrollmentError("PM runtime setup transaction has changed")
        return proof

    def _lookup_exact(self, handle: str, proof: Any, artifact_id: str,
                      expected_sha: str | None) -> None:
        artifact, digest = self.receipts.lookup(handle, proof)
        if artifact != artifact_id or (expected_sha is not None and digest != expected_sha):
            raise BootstrapEnrollmentError("artifact receipt differs from the root-selected PM runtime role")
        if artifact_id not in self.catalog.artifacts:
            raise BootstrapEnrollmentPending("selected PM artifact is absent from protected catalog")

    def _verify_lock_payload(self) -> None:
        resolved = self.catalog.resolve(LOCK_ID, LOCK_SHA256, self.artifact_root, expected_uid=0)
        if resolved.size_bytes != LOCK_BYTES or resolved.sha256 != LOCK_SHA256:
            raise BootstrapEnrollmentError("official PM lock receipt failed byte verification")

    def _resolve_artifact(self, handle: str, proof: Any, artifact_id: str,
                          sha256: str, size: int) -> Any:
        self._lookup_exact(handle, proof, artifact_id, sha256)
        result = self.catalog.resolve(artifact_id, sha256, self.artifact_root, expected_uid=0)
        if result.size_bytes != size or result.sha256 != sha256:
            raise BootstrapEnrollmentError("selected PM toolchain artifact failed exact catalog verification")
        return result

    def _resolve_source(self, handle: str, proof: Any) -> Any:
        from ..hermes_source import materialize_pinned_hermes_source
        self._lookup_exact(handle, proof, SOURCE_ID, None)
        store_id = f"artifact:{SOURCE_ID}:{SOURCE_SHA256}"
        source = materialize_pinned_hermes_source(self.catalog, store_id, self.artifact_root,
                                                  expected_uid=0)
        if source.commit != SOURCE_COMMIT:
            raise BootstrapEnrollmentError("Hermes source receipt does not match the pinned commit")
        return source

    def _publish_receipt(self, *, base: Path, generation: str, prepared: Any,
                         proof: Any, source_handle: str, executable: Path,
                         identity: dict[str, Any], sync_receipt: bytes, feature_list: list[str],
                         artifact_handles: tuple[str, str],
                         uv_tree_relative: str,
                         uv_tree_closure_sha256: str,
                         base_python_tree_relative: str,
                         base_python_closure_sha256: str) -> str:
        info = executable.stat()
        runtime_sha = _hash(executable)
        venv_root = executable.parent.parent
        runtime_closure_sha = _tree_sha256(venv_root)
        pm_sha = hashlib.sha256(sync_receipt).hexdigest()
        receipt_id = "pm-runtime-" + secrets.token_hex(16)
        handle = secrets.token_urlsafe(32)
        lock_artifact, lock_sha = self.catalog.artifacts[LOCK_ID], LOCK_SHA256
        uv_spec, py_spec = self.catalog.artifacts[UV_ID], self.catalog.artifacts[PYTHON_ID]
        record = {
            "schema": 1, "receipt_id": receipt_id, "handle": handle,
            "setup_session_id": proof.setup_session_id,
            "transaction_handle": proof.transaction_handle,
            "prepared_generation_id": prepared.generation_id,
            "source_commit": SOURCE_COMMIT, "source_receipt_handle": source_handle,
            "pm_lock_artifact_id": lock_artifact.artifact_id, "pm_lock_sha256": lock_sha,
            "uv_artifact_id": uv_spec.artifact_id, "uv_sha256": uv_spec.sha256,
            "uv_source_receipt_handle": artifact_handles[0],
            "uv_tree_relative": uv_tree_relative,
            "uv_tree_closure_sha256": uv_tree_closure_sha256,
            "uv_executable_relative": "uv",
            "uv_executable_sha256": UV_EXECUTABLE_SHA256,
            "base_python_artifact_id": py_spec.artifact_id, "base_python_sha256": py_spec.sha256,
            "platform": "linux-aarch64-glibc", "generation": generation,
            "runtime_relative": executable.relative_to(base).as_posix(),
            "runtime_venv_relative": venv_root.relative_to(base).as_posix(),
            "runtime_closure_sha256": runtime_closure_sha,
            "base_python_tree_relative": base_python_tree_relative,
            "base_python_closure_sha256": base_python_closure_sha256,
            "pm_sync_receipt_sha256": pm_sha, "pm_sync_outcome": "succeeded",
            "feature_list": feature_list, "committed_venv_receipt_handle": handle,
            "runtime_executable_artifact_id": "observed:pm-committed-venv-python",
            "runtime_executable_sha256": runtime_sha, "runtime_device": info.st_dev,
            "runtime_inode": info.st_ino, "runtime_uid": info.st_uid,
            "runtime_gid": info.st_gid, "runtime_mode": stat.S_IMODE(info.st_mode),
            "version_info": list(identity["version_info"]),
            "implementation": identity["implementation"], "cache_tag": identity["cache_tag"],
            "soabi": identity["soabi"], "machine": identity["machine"],
            "cleanup_receipt_id": "cleanup-" + generation,
            "terminal_receipt_id": receipt_id,
            "issued_monotonic": self.monotonic(), "expires_monotonic": self.monotonic() + 600.0,
        }
        if not _path_inside(executable, base):
            raise BootstrapEnrollmentError("PM selected executable escaped its private generation")
        registry = self.runtime_root / "receipts"
        _mkdir_private(registry)
        data = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
        temp = registry / ("." + handle + ".tmp")
        _atomic_file(temp, data, 0o600)
        os.replace(temp, registry / (handle + ".json"))
        _fsync_dir(registry)
        return handle


class RootPMRuntimeReceiptRegistry:
    """Root-private path-free receipt store and resolver for the native factory."""
    def __init__(self, *, runtime_root: Path, setup_session: Any,
                 current_guard: Callable[[str, str], bool] | None = None,
                 catalog: Any = None, artifact_root: Path | None = None,
                 artifact_receipts: Any = None,
                 monotonic: Callable[[], float] = time.monotonic,
                 authority_uid: int = 0):
        if (authority_uid != 0 or not runtime_root.is_absolute()
                or not callable(getattr(setup_session, "_check_live", None))
                or (artifact_root is not None and not artifact_root.is_absolute())
                or (artifact_receipts is not None
                    and (catalog is None or artifact_root is None
                         or getattr(artifact_receipts, "catalog", None) is not catalog
                         or getattr(artifact_receipts, "artifact_root", None) != artifact_root))):
            raise ValueError("PM runtime registry is not bound to root setup authority")
        self.runtime_root = runtime_root
        self.setup_session = setup_session
        self.sessions = setup_session._factory.session_store
        if not callable(current_guard):
            raise ValueError("PM runtime resolver requires the root factory current-generation guard")
        self.current_guard = current_guard
        self.catalog = catalog
        self.artifact_root = artifact_root
        self.artifact_receipts = artifact_receipts
        self.monotonic = monotonic

    def resolve_runtime(self, runtime_receipt_handle: str, transaction_handle: str,
                        prepared_generation_id: str) -> VerifiedPMRuntimeSelection:
        _require_root_linux()
        record = self._record(runtime_receipt_handle)
        if (record["transaction_handle"] != transaction_handle
                or record["prepared_generation_id"] != prepared_generation_id
                or not self.current_guard(transaction_handle, prepared_generation_id)
                or self.monotonic() >= record["expires_monotonic"]):
            raise BootstrapEnrollmentError("PM runtime receipt is stale, expired, or belongs to another setup")
        executable = self.runtime_root / record["generation"] / record["runtime_relative"]
        identity = _observe_runtime(executable, expected_uid=0, expected_root=self.runtime_root / record["generation"])
        venv_root = self.runtime_root / record["generation"] / record["runtime_venv_relative"]
        _match_receipt(record, executable, identity, venv_root)
        return VerifiedPMRuntimeSelection(
            runtime_receipt_handle, record["setup_session_id"], transaction_handle,
            prepared_generation_id, SOURCE_ID, executable, record["runtime_executable_sha256"],
            record["runtime_device"], record["runtime_inode"], record["runtime_uid"],
            record["runtime_gid"], record["runtime_mode"], tuple(record["version_info"]),
            record["implementation"], record["cache_tag"], record["soabi"], record["machine"])

    def resolve_runtime_projection(self, runtime_receipt_handle: str,
                                   transaction_handle: str,
                                   prepared_generation_id: str) -> VerifiedPMRuntimeProjection:
        """Reopen the current official base interpreter and its exact held closure."""
        _require_root_linux()
        if (self.catalog is None or self.artifact_root is None
                or not callable(getattr(self.catalog, "materialize_tree", None))):
            raise BootstrapEnrollmentPending("official PM base runtime closure is not attached to the root artifact catalog")
        selected = self.resolve_runtime(runtime_receipt_handle, transaction_handle,
                                        prepared_generation_id)
        record = self._record(runtime_receipt_handle)
        runtime_root_fd: int | None = None
        members: tuple[VerifiedPMRuntimeProjectionMember, ...] = ()
        try:
            tree = self.catalog.materialize_tree(
                PYTHON_ID, PYTHON_SHA256, self.artifact_root, expected_uid=0)
            relative = tree.path.relative_to(self.artifact_root).as_posix()
            if relative != record.get("base_python_tree_relative"):
                raise ValueError
            catalog_spec = self.catalog.artifacts[PYTHON_ID]
            if (catalog_spec.sha256 != record.get("base_python_sha256")
                    or catalog_spec.artifact_id != record.get("base_python_artifact_id")):
                raise ValueError
            runtime_root_fd, members, closure_sha256 = _open_catalog_runtime_tree(
                tree.path, catalog_spec.tree_files,
                expected_closure_sha256=record.get("base_python_closure_sha256"))
            executable = next((member for member in members
                               if member.relative_path == "bin/python3.14"), None)
            if (executable is None or executable.kind != "file" or not executable.executable
                    or executable.fd is None or executable.sha256 != PYTHON_EXECUTABLE_SHA256):
                raise ValueError
            selected_members = tuple(
                member for member in members
                if member.relative_path != "bin/python3.14" and not member.executable)
            other_executables = tuple(
                member for member in members
                if member.relative_path != "bin/python3.14" and member.executable)
            return VerifiedPMRuntimeProjection(
                selection=selected, base_closure_sha256=closure_sha256,
                runtime_root_fd=runtime_root_fd,
                executable_relative_path="bin/python3.14", executable_member=executable,
                runtime_members=selected_members,
                other_executable_members=other_executables, members=members)
        except BootstrapEnrollmentPending:
            raise
        except Exception:
            descriptors = {member.fd for member in members if member.fd is not None}
            if runtime_root_fd is not None:
                descriptors.add(runtime_root_fd)
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
            raise BootstrapEnrollmentError(
                "official PM base Python closure is absent, changed, or outside its receipt") from None

    def resolve_uv_tool(self, runtime_receipt_handle: str,
                        transaction_handle: str,
                        prepared_generation_id: str) -> VerifiedPMUVToolProjection:
        """Resolve the exact fetched/catalogued uv tool held by this current PM receipt."""
        _require_root_linux()
        if (self.catalog is None or self.artifact_root is None
                or self.artifact_receipts is None
                or not callable(getattr(self.catalog, "materialize_tree", None))
                or not callable(getattr(self.artifact_receipts, "lookup", None))):
            raise BootstrapEnrollmentPending("official PM uv source receipt is not attached to root custody")
        self.resolve_runtime(runtime_receipt_handle, transaction_handle, prepared_generation_id)
        record = self._record(runtime_receipt_handle)
        self._verify_uv_source_receipt(record, transaction_handle)
        root_fd: int | None = None
        members: tuple[VerifiedPMRuntimeProjectionMember, ...] = ()
        result_fd: int | None = None
        try:
            tree = self.catalog.materialize_tree(UV_ID, UV_SHA256, self.artifact_root, expected_uid=0)
            relative = tree.path.relative_to(self.artifact_root).as_posix()
            spec = self.catalog.artifacts[UV_ID]
            if (relative != record.get("uv_tree_relative")
                    or spec.artifact_id != record.get("uv_artifact_id")
                    or spec.sha256 != record.get("uv_sha256")):
                raise ValueError
            root_fd, members, closure_sha = _open_catalog_runtime_tree(
                tree.path, spec.tree_files,
                expected_closure_sha256=record.get("uv_tree_closure_sha256"))
            if closure_sha != record.get("uv_tree_closure_sha256"):
                raise ValueError
            executable = next((member for member in members
                               if member.relative_path == "uv"), None)
            if (executable is None or executable.kind != "file" or not executable.executable
                    or executable.fd is None or executable.sha256 != UV_EXECUTABLE_SHA256):
                raise ValueError
            info = os.fstat(executable.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != executable.mode
                    or info.st_mode & 0o222):
                raise ValueError
            result_fd = os.dup(executable.fd)
            result_info = os.fstat(result_fd)
            if (result_info.st_dev != info.st_dev or result_info.st_ino != info.st_ino
                    or _hash_fd(result_fd) != UV_EXECUTABLE_SHA256):
                raise ValueError
            projection = VerifiedPMUVToolProjection(
                receipt_handle=runtime_receipt_handle,
                source_receipt_handle=record["uv_source_receipt_handle"],
                artifact_id=UV_ID, relative_path="uv", sha256=UV_EXECUTABLE_SHA256,
                size_bytes=info.st_size, device=info.st_dev, inode=info.st_ino,
                uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode),
                transaction_handle=transaction_handle,
                prepared_generation_id=prepared_generation_id, fd=result_fd)
            result_fd = None
            return projection
        except BootstrapEnrollmentPending:
            raise
        except Exception:
            raise BootstrapEnrollmentError(
                "official PM uv tool is absent, changed, or outside its source receipt") from None
        finally:
            if result_fd is not None:
                try:
                    os.close(result_fd)
                except OSError:
                    pass
            descriptors = {member.fd for member in members if member.fd is not None}
            if root_fd is not None:
                descriptors.add(root_fd)
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def verify_current_uv_tool(self, selected: VerifiedPMUVToolProjection) -> None:
        """Revalidate receipt joins and held bytes before a caller duplicates uv."""
        _require_root_linux()
        if type(selected) is not VerifiedPMUVToolProjection:
            raise BootstrapEnrollmentError("PM uv tool projection is not a root-selected descriptor")
        if (selected.artifact_id != UV_ID or selected.relative_path != "uv"
                or selected.sha256 != UV_EXECUTABLE_SHA256
                or selected.size_bytes <= 0 or selected.mode & 0o222):
            raise BootstrapEnrollmentError("PM uv tool projection does not match the official selected executable")
        record = self._record(selected.receipt_handle)
        if (record["uv_source_receipt_handle"] != selected.source_receipt_handle
                or record["transaction_handle"] != selected.transaction_handle
                or record["prepared_generation_id"] != selected.prepared_generation_id
                or not self.current_guard(selected.transaction_handle, selected.prepared_generation_id)
                or self.monotonic() >= record["expires_monotonic"]):
            raise BootstrapEnrollmentError("PM uv tool projection is stale or belongs to another setup")
        self.resolve_runtime(selected.receipt_handle, selected.transaction_handle,
                             selected.prepared_generation_id)
        self._verify_uv_source_receipt(record, selected.transaction_handle)
        try:
            info = os.fstat(selected.fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_dev != selected.device
                    or info.st_ino != selected.inode or info.st_uid != selected.uid
                    or info.st_gid != selected.gid or stat.S_IMODE(info.st_mode) != selected.mode
                    or info.st_size != selected.size_bytes or info.st_mode & 0o222
                    or _hash_fd(selected.fd) != UV_EXECUTABLE_SHA256):
                raise ValueError
        except Exception:
            raise BootstrapEnrollmentError("held PM uv executable changed after projection") from None
        current = self.resolve_uv_tool(selected.receipt_handle, selected.transaction_handle,
                                       selected.prepared_generation_id)
        try:
            if (current.device != selected.device or current.inode != selected.inode
                    or current.sha256 != selected.sha256 or current.size_bytes != selected.size_bytes
                    or current.mode != selected.mode or current.uid != selected.uid
                    or current.gid != selected.gid):
                raise BootstrapEnrollmentError("current PM uv catalog member differs from the held projection")
        finally:
            current.close()

    def _verify_uv_source_receipt(self, record: dict[str, Any],
                                  transaction_handle: str) -> None:
        if (not _opaque(record.get("uv_source_receipt_handle"))
                or record.get("transaction_handle") != transaction_handle):
            raise BootstrapEnrollmentError("PM uv source receipt binding is malformed")
        self.setup_session._check_live()
        self.setup_session._refresh_authorization()
        proof = self.setup_session._authorization
        if proof.transaction_handle != transaction_handle:
            raise BootstrapEnrollmentError("PM uv source receipt belongs to another current setup")
        artifact, digest = self.artifact_receipts.lookup(record["uv_source_receipt_handle"], proof)
        if artifact != UV_ID or digest != UV_SHA256:
            raise BootstrapEnrollmentError("PM uv source receipt differs from the official selected uv catalog artifact")

    def resolve_python(self, *, pm_runtime_handle: str, enrollment_id: str,
                       service_generation: str, source_artifact_id: str) -> Path:
        """Adapt the authorized native selection to the setup receipt registry."""
        _require_root_linux()
        # Enrollment IDs/generation names are exact joins supplied by the sealed
        # factory; no caller provides a path or account identity.
        if (not _opaque(enrollment_id) or not _opaque(service_generation)
                or source_artifact_id != SOURCE_ID):
            raise BootstrapEnrollmentError("native PM runtime selection is malformed")
        record = self._record(pm_runtime_handle)
        # The one-time root factory binds these enrollment values into the
        # registry instance before exposing its resolver. No arbitrary lookup
        # dimensions are accepted from native tool arguments.
        binding = getattr(self, "_native_bindings", {}).get(pm_runtime_handle)
        if binding != (enrollment_id, service_generation, source_artifact_id):
            raise BootstrapEnrollmentError("native selection is not bound to this current PM receipt")
        selected = self.resolve_runtime(pm_runtime_handle, record["transaction_handle"],
                                        record["prepared_generation_id"])
        return selected.python_path

    def bind_native_selection(self, handle: str, *, enrollment_id: str,
                              service_generation: str, source_artifact_id: str) -> None:
        """Root factory only: bind the active installation before handoff."""
        _require_root_linux()
        self._record(handle)
        if source_artifact_id != SOURCE_ID or not _opaque(enrollment_id) or not _opaque(service_generation):
            raise BootstrapEnrollmentError("factory native PM binding is malformed")
        if not hasattr(self, "_native_bindings"):
            self._native_bindings: dict[str, tuple[str, str, str]] = {}
        if handle in self._native_bindings:
            raise BootstrapEnrollmentError("PM runtime handle was already bound to native selection")
        self._native_bindings[handle] = (enrollment_id, service_generation, source_artifact_id)

    def _record(self, handle: str) -> dict[str, Any]:
        if not _opaque(handle):
            raise BootstrapEnrollmentError("PM runtime handle is malformed")
        path = self.runtime_root / "receipts" / (handle + ".json")
        try:
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError
            raw = path.read_bytes()
            if len(raw) > 64 * 1024:
                raise ValueError
            record = json.loads(raw)
        except Exception:
            raise BootstrapEnrollmentError("PM runtime receipt is absent or not root-owned") from None
        if not isinstance(record, dict) or record.get("handle") != handle or record.get("schema") != 1:
            raise BootstrapEnrollmentError("PM runtime receipt schema is invalid")
        if (not re.fullmatch(r"pm-[0-9a-f]{32}", str(record.get("generation", "")))
                or record.get("source_commit") != SOURCE_COMMIT
                or record.get("pm_lock_sha256") != LOCK_SHA256
                or record.get("uv_sha256") != UV_SHA256
                or record.get("base_python_artifact_id") != PYTHON_ID
                or record.get("base_python_sha256") != PYTHON_SHA256
                or record.get("pm_sync_outcome") != "succeeded"
                or not _safe_relative(record.get("runtime_relative"))
                or not _safe_relative(record.get("runtime_venv_relative"))
                or not _safe_relative(record.get("base_python_tree_relative"))
                or not _safe_relative(record.get("uv_tree_relative"))
                or not _safe_relative(record.get("uv_executable_relative"))
                or record.get("uv_executable_relative") != "uv"
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("uv_tree_closure_sha256", "")))
                or record.get("uv_executable_sha256") != UV_EXECUTABLE_SHA256
                or not _opaque(record.get("uv_source_receipt_handle"))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("base_python_closure_sha256", "")))):
            raise BootstrapEnrollmentError("PM runtime receipt no longer matches official source/tool pins")
        return record


def _read_sync_receipt(path: Path) -> tuple[bytes, list[str]]:
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) & 0o022 or info.st_size > 64 * 1024):
            raise ValueError
        raw = path.read_bytes()
        value = json.loads(raw)
        if (not isinstance(value, dict) or value.get("schema") != 1
                or value.get("kind") != "sync" or value.get("outcome") != "ok"
                or value.get("exit_code") != 0 or value.get("venv_rebuild", {}).get("ok") is not True
                or not isinstance(value.get("steps"), list) or not value["steps"]):
            raise ValueError
        features = value.get("feature_list")
        if features is not None and (not isinstance(features, list) or any(not isinstance(x, str) for x in features)):
            raise ValueError
        return raw, list(features or [])
    except Exception:
        raise PMRuntimeUnavailable("official Hermes PM success receipt is absent or unsuccessful") from None


def _committed_python(bootstrap: Path, project: Path, env: dict[str, str],
                      deadline: float, monotonic: Callable[[], float],
                      session_store: Any, session_handle: Any) -> Path:
    query = (
        "import sys,json;sys.path.insert(0," + repr(str(project)) + ");"
        "from pm.environments import committed_venv,venv_python;"
        "print(venv_python(committed_venv(" + repr(str(project)) + ")))"
    )
    result = _run_managed([str(bootstrap), "-I", "-B", "-c", query], cwd=project, env=env,
                          timeout=max(.1, deadline-monotonic()), session_store=session_store,
                          session_handle=session_handle, deadline=deadline, monotonic=monotonic)
    if result.returncode != 0:
        raise PMRuntimeUnavailable("PM committed environment selection query failed")
    candidate = result.stdout.decode("utf-8", "strict").strip()
    if "\n" in candidate:
        candidate = candidate.splitlines()[-1]
    path = Path(candidate)
    if not path.is_absolute() or not path.exists():
        raise PMRuntimeUnavailable("Hermes PM did not select a committed dependency environment")
    return path


def _observe_runtime(path: Path, *, expected_uid: int, expected_root: Path) -> dict[str, Any]:
    try:
        resolved = path.resolve(strict=True)
        if not _path_inside(resolved, expected_root):
            raise ValueError
        pi = resolved.stat(follow_symlinks=False)
        for directory in (resolved.parent, *resolved.parents):
            if not _path_inside(directory, expected_root):
                break
            di = directory.lstat()
            if (not stat.S_ISDIR(di.st_mode) or di.st_uid != expected_uid or di.st_gid != 0
                    or stat.S_IMODE(di.st_mode) & 0o022):
                raise ValueError
        if (not stat.S_ISREG(pi.st_mode) or pi.st_uid != expected_uid or pi.st_gid != 0
                or stat.S_IMODE(pi.st_mode) & 0o022 or not os.access(resolved, os.X_OK)):
            raise ValueError
        digest = _hash(path)
        code = ("import json,platform,sys,sysconfig; print(json.dumps({"
                "'version_info':list(sys.version_info[:3]),'implementation':sys.implementation.name,"
                "'cache_tag':sys.implementation.cache_tag,'soabi':sysconfig.get_config_var('SOABI'),"
                "'machine':platform.machine()}))")
        # Executable is a fixed selection; no inherited PYTHONPATH/PYTHONHOME.
        result = subprocess.run([str(path), "-I", "-B", "-c", code],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8", "PYTHONNOUSERSITE":"1"},
            timeout=10, check=True, close_fds=True)
        observed = json.loads(result.stdout.decode("utf-8"))
        observed.update({"sha256": digest, "device": pi.st_dev, "inode": pi.st_ino,
                         "uid": pi.st_uid, "gid": pi.st_gid, "mode": stat.S_IMODE(pi.st_mode)})
        if (not isinstance(observed.get("soabi"), str) or not observed["soabi"]
                or not isinstance(observed.get("cache_tag"), str) or not observed["cache_tag"]):
            raise ValueError
        return observed
    except Exception:
        raise PMRuntimeUnavailable("PM committed interpreter identity could not be observed safely") from None


def _match_receipt(record: dict[str, Any], executable: Path, identity: dict[str, Any], venv_root: Path) -> None:
    expected = {
        "runtime_executable_sha256": identity["sha256"], "runtime_device": identity["device"],
        "runtime_inode": identity["inode"], "runtime_uid": identity["uid"],
        "runtime_gid": identity["gid"], "runtime_mode": identity["mode"],
        "version_info": list(identity["version_info"]), "implementation": identity["implementation"],
        "cache_tag": identity["cache_tag"], "soabi": identity["soabi"], "machine": identity["machine"],
    }
    if (_tree_sha256(venv_root) != record.get("runtime_closure_sha256")
            or any(record.get(key) != value for key, value in expected.items())):
        raise BootstrapEnrollmentError("PM runtime identity changed after receipt publication")
    if tuple(identity["version_info"][:2]) != (3, 14):
        raise BootstrapEnrollmentError("resolved PM interpreter is not Python 3.14")


def _safe_relative(value: Any) -> bool:
    return (isinstance(value, str) and bool(value) and not value.startswith("/")
            and "\\" not in value and all(part not in {"", ".", ".."} for part in value.split("/")))


def _opaque(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{32,128}", value) is not None


def _require_root_linux() -> None:
    if os.geteuid() != 0 or os.getuid() != 0 or platform.system() != "Linux":
        raise PMRuntimeUnavailable("PM runtime receipts resolve only in installed Linux root authority")


def _check_live(store: Any, handle: Any, monotonic: Callable[[], float], deadline: float) -> None:
    if monotonic() >= deadline:
        raise PMRuntimeUnavailable("official PM provisioning deadline expired")
    store._live(handle)


def _find_executable(tree: Path, name: str) -> Path:
    candidates = [item for item in tree.rglob(name) if item.is_file() and os.access(item, os.X_OK)]
    if len(candidates) != 1:
        raise PMRuntimeUnavailable("verified official PM toolchain has no unique selected executable")
    return candidates[0]


def _tree_sha256(root: Path) -> str:
    """Digest all PM venv files and symlink targets without following links."""
    digest = hashlib.sha256()
    for item in sorted(root.rglob("*"), key=lambda entry: entry.relative_to(root).as_posix()):
        relative = item.relative_to(root).as_posix()
        info = item.lstat()
        digest.update(relative.encode("utf-8") + b"\0")
        if stat.S_ISLNK(info.st_mode):
            digest.update(b"link\0" + os.readlink(item).encode("utf-8"))
        elif stat.S_ISREG(info.st_mode):
            digest.update(b"file\0" + bytes.fromhex(_hash(item)))
        elif stat.S_ISDIR(info.st_mode):
            digest.update(b"dir\0")
        else:
            raise PMRuntimeUnavailable("PM environment contains a special file")
    return digest.hexdigest()


def _verify_catalog_runtime_root(root: Path, rows: Any,
                                 *, expected_closure_sha256: str) -> None:
    """Verify an immutable catalog tree through held member descriptors."""
    root_fd, members, observed = _open_catalog_runtime_tree(
        root, rows, expected_closure_sha256=expected_closure_sha256)
    try:
        pass
    finally:
        descriptors = {root_fd}
        descriptors.update(member.fd for member in members if member.fd is not None)
        for descriptor in descriptors:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _open_catalog_runtime_tree(root: Path, rows: Any,
                               *, expected_closure_sha256: Any
                               ) -> tuple[int, tuple[VerifiedPMRuntimeProjectionMember, ...], str]:
    """Open and hash every member of the protected PM base runtime tree.

    The walk is descriptor relative and does not follow links. Its digest uses
    the same canonical row encoding as ``_tree_sha256`` and must match both the
    receipt and the protected catalog's complete file/symlink inventory.
    """
    if (not root.is_absolute() or not isinstance(expected_closure_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_closure_sha256)):
        raise ValueError("runtime tree binding is malformed")
    expected_rows = {item.path: item for item in rows}
    if (not expected_rows or len(expected_rows) != len(rows)
            or any(not _safe_relative(name) for name in expected_rows)):
        raise ValueError("runtime catalog rows are malformed")
    root_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    root_fd = os.open(root, root_flags)
    held: list[int] = []
    observed_rows: dict[str, tuple[str, int, str, str | None, bool]] = {}
    members: list[VerifiedPMRuntimeProjectionMember] = []
    try:
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or not _root_owned(root_info)
                or stat.S_IMODE(root_info.st_mode) & 0o222):
            raise ValueError("runtime root custody is invalid")

        def visit(directory_fd: int, prefix: str) -> None:
            for name in sorted(os.listdir(directory_fd)):
                if (not name or name in {".", ".."} or "/" in name or "\\" in name or "\x00" in name):
                    raise ValueError("runtime tree contains a nonportable path")
                relative = f"{prefix}/{name}" if prefix else name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if (not _root_owned(info) or stat.S_IMODE(info.st_mode) & 0o222):
                        raise ValueError("runtime directory custody is invalid")
                    observed_rows[relative] = ("", 0, "dir", None, False)
                    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        opened = os.fstat(child_fd)
                        if (not stat.S_ISDIR(opened.st_mode) or opened.st_dev != info.st_dev
                                or opened.st_ino != info.st_ino or not _root_owned(opened)
                                or stat.S_IMODE(opened.st_mode) & 0o222):
                            raise ValueError("runtime directory changed while opening")
                        visit(child_fd, relative)
                    finally:
                        os.close(child_fd)
                    continue
                if stat.S_ISREG(info.st_mode):
                    mode = stat.S_IMODE(info.st_mode)
                    if (not _root_owned(info) or info.st_nlink != 1
                            or mode not in {0o444, 0o555}):
                        raise ValueError("runtime file custody is invalid")
                    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                    member_fd = os.open(name, flags, dir_fd=directory_fd)
                    held.append(member_fd)
                    opened = os.fstat(member_fd)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != info.st_dev
                            or opened.st_ino != info.st_ino or not _root_owned(opened)
                            or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != mode):
                        raise ValueError("runtime file changed while opening")
                    digest = hashlib.sha256()
                    offset = 0
                    while offset < opened.st_size:
                        block = os.pread(member_fd, min(1024 * 1024, opened.st_size - offset), offset)
                        if not block:
                            raise ValueError("runtime file shortened while hashing")
                        digest.update(block)
                        offset += len(block)
                    after = os.fstat(member_fd)
                    if (after.st_dev != opened.st_dev or after.st_ino != opened.st_ino
                            or after.st_size != opened.st_size or after.st_mtime_ns != opened.st_mtime_ns
                            or after.st_ctime_ns != opened.st_ctime_ns):
                        raise ValueError("runtime file changed while hashing")
                    sha = digest.hexdigest()
                    executable = bool(mode & 0o111)
                    observed_rows[relative] = (sha, opened.st_size, "file", None, executable)
                    members.append(VerifiedPMRuntimeProjectionMember(
                        relative, sha, opened.st_size, executable, mode, opened.st_dev,
                        opened.st_ino, opened.st_uid, opened.st_gid, "file", None, member_fd))
                    continue
                if stat.S_ISLNK(info.st_mode):
                    if not _root_owned(info):
                        raise ValueError("runtime link ownership is invalid")
                    target = os.readlink(name, dir_fd=directory_fd)
                    if not _safe_link_target(relative, target):
                        raise ValueError("runtime link target escapes its tree")
                    raw_target = target.encode("utf-8")
                    sha = hashlib.sha256(raw_target).hexdigest()
                    link_fd = None
                    path_only = getattr(os, "O_PATH", None)
                    if path_only is not None:
                        link_fd = os.open(name, path_only | getattr(os, "O_NOFOLLOW", 0)
                                          | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
                        held.append(link_fd)
                        opened = os.fstat(link_fd)
                        again = os.readlink(name, dir_fd=directory_fd)
                        if (not stat.S_ISLNK(opened.st_mode) or opened.st_dev != info.st_dev
                                or opened.st_ino != info.st_ino or not _root_owned(opened)
                                or again != target):
                            raise ValueError("runtime link changed while opening")
                    observed_rows[relative] = (sha, len(raw_target), "symlink", target, False)
                    members.append(VerifiedPMRuntimeProjectionMember(
                        relative, sha, len(raw_target), False, stat.S_IMODE(info.st_mode),
                        info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                        "symlink", target, link_fd))
                    continue
                raise ValueError("runtime tree contains a special member")

        visit(root_fd, "")
        expected_observed = {
            item.path: (item.sha256, item.size_bytes, item.kind, item.link_target, item.executable)
            for item in expected_rows.values()
        }
        if {key: value for key, value in observed_rows.items() if value[2] != "dir"} != expected_observed:
            raise ValueError("runtime tree differs from the protected artifact inventory")
        digest = hashlib.sha256()
        for relative, (sha, _size, kind, link_target, _executable) in sorted(observed_rows.items()):
            digest.update(relative.encode("utf-8") + b"\0")
            if kind == "dir":
                digest.update(b"dir\0")
            elif kind == "symlink":
                digest.update(b"link\0" + str(link_target).encode("utf-8"))
            else:
                digest.update(b"file\0" + bytes.fromhex(sha))
        closure_sha = digest.hexdigest()
        if closure_sha != expected_closure_sha256:
            raise ValueError("runtime closure digest differs from its receipt")
        members.sort(key=lambda member: member.relative_path)
        return root_fd, tuple(members), closure_sha
    except BaseException:
        for descriptor in set(held + [root_fd]):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _safe_link_target(relative: str, target: str) -> bool:
    if (not isinstance(target, str) or not target or target.startswith("/")
            or "\\" in target or "\x00" in target):
        return False
    import posixpath
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(relative), target))
    return resolved not in {"", ".", ".."} and not resolved.startswith("../")


def _root_owned(info: Any) -> bool:
    return info.st_uid == 0 and info.st_gid == 0


def _hash(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _hash_fd(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        block = os.pread(descriptor, 1024 * 1024, offset)
        if not block:
            return digest.hexdigest()
        digest.update(block)
        offset += len(block)


def _path_inside(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _mkdir_private(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    _require_dir(path)


def _require_dir(path: Path) -> None:
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise PMRuntimeUnavailable("private PM runtime directory ownership or mode is invalid")


def _atomic_file(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data); stream.flush(); os.fsync(stream.fileno())
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _remove_private(path: Path) -> None:
    if path.exists() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)


def _run_managed(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: float,
                 session_store: Any, session_handle: Any, deadline: float,
                 monotonic: Callable[[], float]) -> subprocess.CompletedProcess[bytes]:
    """Run the fixed PM stage in a cancellable, size-bounded process group."""
    if not argv or timeout <= 0:
        raise PMRuntimeUnavailable("PM child process deadline is exhausted")
    end = min(deadline, monotonic() + timeout)
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout_file, stderr=stderr_file, close_fds=True,
                                   start_new_session=True, preexec_fn=_child_limits)
        try:
            while True:
                _check_live(session_store, session_handle, monotonic, deadline)
                remaining = end - monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                try:
                    process.wait(timeout=min(0.5, remaining))
                    stdout_file.seek(0); stderr_file.seek(0)
                    return subprocess.CompletedProcess(argv, process.returncode,
                        stdout_file.read(1024 * 1024), stderr_file.read(1024 * 1024))
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            raise


def _child_limits() -> None:
    """Apply bounded CPU, output size and descriptor limits to PM and descendants."""
    resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**3, 8 * 1024**3))
    resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
