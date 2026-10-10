"""Root-owned finite Node/Bun source observations for Hyperframes (SK-T144.1).

The public versions and publisher digests below are the reviewed v144 source
pins. This module never consults PATH to select a toolchain and never runs an
unheld executable. Package installation and application qualification remain
separate producers.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import select
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from hermes_installer.authority.application_toolchain_sources import (
    RootSelectedApplicationToolchainSourceObserver,
    VerifiedApplicationToolchainSourceObservation,
    SOURCE_POLICY_ARTIFACT_ID,
    SOURCE_POLICY_SHA256,
)
from hermes_installer.protected_enrollment import RootJournalSelection


_MAX_EXPANDED_BYTES = 512 * 1024 * 1024
_MAX_MEMBERS = 20_000
_MAX_PROBE_OUTPUT = 128
_MAX_PROBE_SECONDS = 4.0
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_RECORD_SEAL = object()


class ApplicationToolchainDenied(PermissionError):
    """A selected toolchain, source, custody, or currentness proof is absent."""


@dataclass(frozen=True, slots=True)
class ApplicationToolchainPin:
    tool_id: str
    version: str
    platform: str
    url: str
    sha256: str
    size_bytes: int
    archive_kind: str
    executable_member: str
    redirect_hosts: tuple[str, ...] = ()
    license_url: str | None = None
    license_sha256: str | None = None
    license_size_bytes: int | None = None


TOOLCHAINS: Mapping[str, ApplicationToolchainPin] = {
    "application-node-26.7.0-linux-arm64": ApplicationToolchainPin(
        tool_id="application-node-26.7.0-linux-arm64", version="26.7.0",
        platform="linux-arm64",
        url="https://nodejs.org/dist/v26.7.0/node-v26.7.0-linux-arm64.tar.xz",
        sha256="afc7a004018485092ac8985b817b0d5684472bd9472e0b57d2ab88737e50090d",
        size_bytes=32_581_212, archive_kind="tar.xz", executable_member="bin/node"),
    "application-bun-1.4.3-linux-arm64": ApplicationToolchainPin(
        tool_id="application-bun-1.4.3-linux-arm64", version="1.4.3",
        platform="linux-arm64",
        url="https://github.com/oven-sh/bun/releases/download/bun-v1.4.3/bun-linux-aarch64.zip",
        sha256="efa9813da5ed72423bf847f916e8d2c47c0d776add972354026a75e10da9aa21",
        size_bytes=41_786_424, archive_kind="zip",
        executable_member="bun-linux-aarch64/bun",
        redirect_hosts=("release-assets.githubusercontent.com",),
        license_url="https://raw.githubusercontent.com/oven-sh/bun/c6da4a4d3010e5553438c60f6bd76d981976867c/LICENSE.md",
        license_sha256="056696884250b0d682365260cf1487a6501b1665a343ec60e23a1e647043c572",
        license_size_bytes=5807),
}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha_fd(fd: int, maximum: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    offset = 0
    while offset <= maximum:
        block = os.pread(fd, min(64 * 1024, maximum + 1 - offset), offset)
        if not block:
            break
        offset += len(block)
        if offset > maximum:
            raise ApplicationToolchainDenied("held toolchain member exceeds its pinned byte bound")
        digest.update(block)
    return digest.hexdigest(), offset


def _safe_rel(value: str) -> PurePosixPath:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or value.startswith("/") or value != PurePosixPath(value).as_posix()
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ApplicationToolchainDenied("toolchain archive contains an unsafe member path")
    return PurePosixPath(value)


def _ensure_private_directory(path: Path, expected_uid: int) -> None:
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ApplicationToolchainDenied("toolchain CAS directory is not private, owned, and nonsymlinked")


def _verify_private_tree(root: Path, *, expected_uid: int,
                         expected_members: Mapping[str, Mapping[str, Any]]) -> str:
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) != 0o555:
        raise ApplicationToolchainDenied("toolchain content tree custody changed")
    observed: dict[str, Mapping[str, Any]] = {}
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        parent = Path(base)
        for name in tuple(dirs):
            child = parent / name
            child_info = child.lstat()
            rel = child.relative_to(root).as_posix()
            if stat.S_ISLNK(child_info.st_mode):
                target = os.readlink(child)
                _safe_link_target(rel, target)
                observed[rel] = {"kind": "symlink", "target": target,
                                 "sha256": hashlib.sha256(target.encode()).hexdigest(),
                                 "size_bytes": len(target.encode()), "mode": 0o777}
                dirs.remove(name)
            elif (not stat.S_ISDIR(child_info.st_mode) or child_info.st_uid != expected_uid
                  or stat.S_IMODE(child_info.st_mode) != 0o555):
                raise ApplicationToolchainDenied("toolchain tree has an unsafe directory")
        for name in files:
            child = parent / name
            file_info = child.lstat()
            rel = child.relative_to(root).as_posix()
            if not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != expected_uid or file_info.st_nlink != 1:
                raise ApplicationToolchainDenied("toolchain tree has an unexpected special or linked member")
            mode = stat.S_IMODE(file_info.st_mode)
            if mode not in {0o444, 0o555}:
                raise ApplicationToolchainDenied("toolchain tree member mode changed")
            fd = os.open(child, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                opened = os.fstat(fd)
                digest, size = _sha_fd(fd, _MAX_EXPANDED_BYTES)
                if (opened.st_dev, opened.st_ino) != (file_info.st_dev, file_info.st_ino):
                    raise ApplicationToolchainDenied("toolchain member identity changed while opening")
            finally:
                os.close(fd)
            observed[rel] = {"kind": "file", "sha256": digest, "size_bytes": size, "mode": mode}
    if observed != dict(expected_members):
        raise ApplicationToolchainDenied("toolchain content tree no longer matches its retained manifest")
    return hashlib.sha256(_canonical({"schema": 1, "members": dict(sorted(observed.items()))})).hexdigest()


def _read_private_record(path: Path, *, expected_uid: int) -> Mapping[str, Any]:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > 1_048_576):
        raise ApplicationToolchainDenied("durable toolchain observation record custody changed")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)
                or opened.st_uid != expected_uid or opened.st_nlink != 1):
            raise ApplicationToolchainDenied("durable toolchain observation record changed while opening")
        body = os.read(fd, 1_048_577)
        if len(body) != info.st_size:
            raise ApplicationToolchainDenied("durable toolchain observation record size changed")
        value = json.loads(body.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise ApplicationToolchainDenied("durable toolchain observation record is malformed") from None
    finally:
        os.close(fd)


def _safe_link_target(relative: str, target: str) -> None:
    if (not target or "\\" in target or "\x00" in target or target.startswith("/")):
        raise ApplicationToolchainDenied("toolchain archive contains an unsafe symlink")
    resolved = PurePosixPath(relative).parent.joinpath(target)
    stack: list[str] = []
    for part in resolved.parts:
        if part == "..":
            if not stack:
                raise ApplicationToolchainDenied("toolchain symlink escapes its archive root")
            stack.pop()
        elif part not in {"", "."}:
            stack.append(part)


def _write_tree_file(root: Path, rel: str, body: bytes, executable: bool,
                     expected_uid: int) -> Mapping[str, Any]:
    path = root.joinpath(*_safe_rel(rel).parts)
    current = root
    for part in _safe_rel(rel).parts[:-1]:
        current = current / part
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        info = current.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != expected_uid):
            raise ApplicationToolchainDenied("toolchain archive member has an unsafe parent")
    mode = 0o555 if executable else 0o444
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(body)
        while view:
            count = os.write(fd, view[:64 * 1024])
            if count < 1:
                raise OSError("short toolchain tree write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    return {"kind": "file", "sha256": hashlib.sha256(body).hexdigest(),
            "size_bytes": len(body), "mode": mode}


def _write_symlink(root: Path, rel: str, target: str, expected_uid: int) -> Mapping[str, Any]:
    _safe_rel(rel)
    _safe_link_target(rel, target)
    link = root.joinpath(*PurePosixPath(rel).parts)
    parent = link.parent
    current = root
    for part in parent.relative_to(root).parts:
        current = current / part
        info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != expected_uid:
            raise ApplicationToolchainDenied("toolchain archive symlink parent is unsafe")
    os.symlink(target, link)
    raw = target.encode("utf-8")
    return {"kind": "symlink", "target": target, "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw), "mode": 0o777}


def _extract_archive(pin: ApplicationToolchainPin, archive_fd: int, destination: Path,
                     expected_uid: int) -> Mapping[str, Mapping[str, Any]]:
    _ensure_private_directory(destination, expected_uid)
    rows: dict[str, Mapping[str, Any]] = {}
    explicit_directories: set[str] = set()
    total = 0

    def add_file(name: str, body: bytes, mode: int) -> None:
        nonlocal total
        rel = _safe_rel(name).as_posix()
        if rel in rows or rel in explicit_directories or len(rows) + len(explicit_directories) >= _MAX_MEMBERS:
            raise ApplicationToolchainDenied("toolchain archive has duplicate or excess members")
        total += len(body)
        if total > _MAX_EXPANDED_BYTES:
            raise ApplicationToolchainDenied("toolchain archive expands beyond its fixed bound")
        is_executable = rel == pin.executable_member
        if is_executable and not (mode & 0o111):
            raise ApplicationToolchainDenied("pinned toolchain executable is not executable in its publisher archive")
        # The isolated distribution carries data and libraries only. Preserve
        # execute permission for the one reviewed entrypoint, never every
        # upstream helper/installer script.
        rows[rel] = _write_tree_file(destination, rel, body, is_executable, expected_uid)

    def add_link(name: str, target: str) -> None:
        rel = _safe_rel(name).as_posix()
        if rel in rows or rel in explicit_directories or len(rows) + len(explicit_directories) >= _MAX_MEMBERS:
            raise ApplicationToolchainDenied("toolchain archive has duplicate or excess members")
        rows[rel] = _write_symlink(destination, rel, target, expected_uid)

    try:
        source_stream = os.fdopen(os.dup(archive_fd), "rb")
        if pin.archive_kind == "tar.xz":
            with source_stream, tarfile.open(fileobj=source_stream, mode="r:xz") as archive:
                members = archive.getmembers()
                if len(members) > _MAX_MEMBERS:
                    raise ApplicationToolchainDenied("toolchain archive has too many members")
                prefix = "node-v26.7.0-linux-arm64/"
                for member in members:
                    name = member.name
                    if name == prefix[:-1] and member.isdir():
                        continue
                    if not name.startswith(prefix):
                        raise ApplicationToolchainDenied("Node archive member escaped its pinned distribution root")
                    rel = name[len(prefix):].rstrip("/")
                    if not rel:
                        continue
                    _safe_rel(rel)
                    if member.isdir():
                        if rel in rows or rel in explicit_directories:
                            raise ApplicationToolchainDenied("Node archive contains a duplicate directory")
                        explicit_directories.add(rel)
                        path = destination.joinpath(*PurePosixPath(rel).parts)
                        current = destination
                        for part in PurePosixPath(rel).parts:
                            current = current / part
                            try:
                                current.mkdir(mode=0o700)
                            except FileExistsError:
                                pass
                            info = current.lstat()
                            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                                raise ApplicationToolchainDenied("Node archive has an unsafe directory")
                        continue
                    if member.isfile():
                        if member.size < 0 or member.size > _MAX_EXPANDED_BYTES - total:
                            raise ApplicationToolchainDenied("Node archive expands beyond its fixed bound")
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            raise ApplicationToolchainDenied("Node archive member bytes are unavailable")
                        body = extracted.read(_MAX_EXPANDED_BYTES + 1)
                        if len(body) != member.size:
                            raise ApplicationToolchainDenied("Node archive member size differs")
                        add_file(rel, body, member.mode)
                    elif member.issym():
                        add_link(rel, member.linkname)
                    else:
                        raise ApplicationToolchainDenied("Node archive contains a hardlink, device, or unsupported type")
        elif pin.archive_kind == "zip":
            with source_stream, zipfile.ZipFile(source_stream) as archive:
                infos = archive.infolist()
                if len(infos) > _MAX_MEMBERS:
                    raise ApplicationToolchainDenied("Bun archive has too many members")
                for info in infos:
                    rel = _safe_rel(info.filename.rstrip("/")).as_posix()
                    mode = (info.external_attr >> 16) & 0xFFFF
                    if info.is_dir():
                        if rel in rows or rel in explicit_directories:
                            raise ApplicationToolchainDenied("Bun archive contains a duplicate directory")
                        explicit_directories.add(rel)
                        current = destination
                        for part in PurePosixPath(rel).parts:
                            current = current / part
                            try:
                                current.mkdir(mode=0o700)
                            except FileExistsError:
                                pass
                            parent_info = current.lstat()
                            if not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode):
                                raise ApplicationToolchainDenied("Bun archive has an unsafe directory")
                        continue
                    if stat.S_ISLNK(mode):
                        if info.file_size > 4096:
                            raise ApplicationToolchainDenied("Bun symlink target exceeds its fixed bound")
                        add_link(rel, archive.read(info).decode("utf-8", "strict"))
                    elif stat.S_ISREG(mode) or mode == 0:
                        if info.file_size > _MAX_EXPANDED_BYTES - total:
                            raise ApplicationToolchainDenied("Bun archive expands beyond its fixed bound")
                        add_file(rel, archive.read(info), mode)
                    else:
                        raise ApplicationToolchainDenied("Bun archive contains an unsupported entry type")
        else:
            raise ApplicationToolchainDenied("toolchain archive format is not in the fixed catalog")
    except ApplicationToolchainDenied:
        raise
    except (OSError, ValueError, RuntimeError, tarfile.TarError, zipfile.BadZipFile, EOFError, UnicodeError):
        raise ApplicationToolchainDenied("pinned toolchain archive could not be safely materialized") from None
    if pin.executable_member not in rows or rows[pin.executable_member]["kind"] != "file":
        raise ApplicationToolchainDenied("toolchain executable member is missing or not a regular file")
    for directory, dirs, _files in os.walk(destination, topdown=False, followlinks=False):
        for name in dirs:
            path = Path(directory) / name
            if path.is_symlink():
                continue
            os.chmod(path, 0o555)
    os.chmod(destination, 0o555)
    _verify_private_tree(destination, expected_uid=expected_uid, expected_members=rows)
    return rows


def _fixed_probe(pin: ApplicationToolchainPin, executable_fd: int, root: Path,
                 *, expected_uid: int) -> str:
    if (platform.system() != "Linux" or platform.machine().casefold() not in {"aarch64", "arm64"}
            or os.geteuid() != expected_uid):
        raise ApplicationToolchainDenied("Node/Bun execution probe requires the isolated Linux ARM64 root fixture")
    expected_version = "v" + pin.version if pin.tool_id.startswith("application-node-") else pin.version
    held = os.fstat(executable_fd)
    if (not stat.S_ISREG(held.st_mode) or held.st_uid != expected_uid
            or stat.S_IMODE(held.st_mode) != 0o555):
        raise ApplicationToolchainDenied("held toolchain executable descriptor changed")
    argv = [f"/proc/self/fd/{executable_fd}", "--version"]
    env = {"HOME": "/nonexistent", "LANG": "C", "LC_ALL": "C", "PATH": "/nonexistent"}
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            argv, executable=argv[0], cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
            pass_fds=(executable_fd,), start_new_session=True,
        )
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + _MAX_PROBE_SECONDS
        while len(output) <= _MAX_PROBE_OUTPUT and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            readable, _, _ = select.select([process.stdout], [], [], max(0.0, remaining))
            if not readable:
                break
            block = os.read(process.stdout.fileno(), min(32, _MAX_PROBE_OUTPUT + 1 - len(output)))
            if not block:
                break
            output.extend(block)
        if len(output) > _MAX_PROBE_OUTPUT:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=1)
            raise ApplicationToolchainDenied("toolchain version probe output exceeded its fixed bound")
        remaining = max(0.01, deadline - time.monotonic())
        code = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        assert process is not None
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=1)
        raise ApplicationToolchainDenied("toolchain version probe exceeded its fixed deadline") from None
    except UnicodeDecodeError:
        raise ApplicationToolchainDenied("toolchain version probe returned non-ASCII output") from None
    except OSError:
        raise ApplicationToolchainDenied("held toolchain executable could not be invoked") from None
    finally:
        try:
            if process is not None and process.stdout is not None:
                process.stdout.close()
        except Exception:
            pass
    try:
        reported = bytes(output).decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        raise ApplicationToolchainDenied("toolchain version probe returned non-ASCII output") from None
    if code != 0 or reported != expected_version:
        raise ApplicationToolchainDenied("held toolchain executable did not report its exact reviewed version")
    return hashlib.sha256(_canonical({"argv": ["--version"], "expected": expected_version,
                                    "stdout_sha256": hashlib.sha256(output).hexdigest(),
                                    "exit_code": code})).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationToolchainObservation:
    schema: int
    receipt_handle: str
    tool_id: str
    version: str
    platform: str
    source_artifact_id: str
    source_sha256: str
    source_size_bytes: int
    license_observation_handles: tuple[str, ...]
    package_notice_observation_sha256: str
    executable_member: str
    executable_sha256: str
    executable_device: int
    executable_inode: int
    executable_mode: int
    runtime_manifest_sha256: str
    toolchain_root_selection_handle: str
    runtime_preparation_selection_handle: str
    choice_selection_handle: str
    recipe_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _executable_fd: int = field(repr=False, compare=False)
    _root: Path = field(repr=False, compare=False)
    _members: Mapping[str, Mapping[str, Any]] = field(repr=False, compare=False)
    _registry_id: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _RECORD_SEAL:
            raise TypeError("toolchain observations are root-registry issued")

    def duplicate_executable_fd(self) -> int:
        return os.dup(self._executable_fd)

    def close(self) -> None:
        if self._executable_fd >= 0:
            os.close(self._executable_fd)
            object.__setattr__(self, "_executable_fd", -1)


@dataclass(slots=True)
class _ToolchainEntry:
    observation: RootApplicationToolchainObservation
    cas_target: Path
    source_observation: VerifiedApplicationToolchainSourceObservation
    license_source_observation: VerifiedApplicationToolchainSourceObservation | None
    tree_path: Path
    manifest_path: Path
    choice: Any
    prep_handle: str


class RootApplicationToolchainRegistry:
    """Materialize v144 toolchains only from root-held, selected source bytes.

    The source observer owns URL access and CAS. This registry accepts no path or
    URL input; it extracts only its current held descriptors, then keeps the
    isolated executable and a durable receipt in the protected setup journal.
    """

    def __init__(self, *, verified_release: Any, current_actor_verifier: Any,
                 root_setup_session_store: Any, artifact_source_observer: Any,
                 root_journal: RootJournalSelection, setup_choice_registry: Any,
                 expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic):
        if (not isinstance(root_journal, RootJournalSelection)
                or not callable(getattr(verified_release, "verify_current", None))
                or not callable(getattr(current_actor_verifier, "verify_current", None))
                or not callable(getattr(root_setup_session_store, "resolve_live_session_id", None))
                or not callable(getattr(setup_choice_registry, "resolve_application_setup_choice", None))
                or not callable(getattr(setup_choice_registry, "resolve_application_qualification_consent", None))
                or type(artifact_source_observer) is not RootSelectedApplicationToolchainSourceObserver
                or not callable(getattr(artifact_source_observer, "observe_selected_toolchain_source", None))
                or not callable(getattr(artifact_source_observer, "verify_current", None))
                or not callable(getattr(artifact_source_observer, "open_blob", None))
                or type(expected_uid) is not int or expected_uid < 0):
            raise ValueError("root application toolchain registry dependencies are incomplete")
        if (root_journal.root_id != "installer-authority-journal-v1"
                or not root_journal.path.is_absolute()):
            raise ValueError("toolchain source must use the selected protected setup journal")
        self.release = verified_release
        self.actor_verifier = current_actor_verifier
        self.sessions = root_setup_session_store
        self.artifact_source_observer = artifact_source_observer
        self.journal = root_journal
        self.choices = setup_choice_registry
        self.expected_uid = expected_uid
        self.monotonic = monotonic
        self.registry_id = secrets.token_urlsafe(32)
        self._entries: dict[tuple[str, str], _ToolchainEntry] = {}

    @classmethod
    def from_root_setup(cls, verified_release: Any, current_actor_verifier: Any,
                        root_setup_session_store: Any, artifact_source_observer: Any,
                        root_journal: RootJournalSelection, setup_choice_registry: Any,
                        **kwargs: Any) -> "RootApplicationToolchainRegistry":
        return cls(verified_release=verified_release,
                   current_actor_verifier=current_actor_verifier,
                   root_setup_session_store=root_setup_session_store,
                   artifact_source_observer=artifact_source_observer,
                   root_journal=root_journal,
                   setup_choice_registry=setup_choice_registry, **kwargs)

    def _selection(self, prep_handle: str) -> tuple[Any, Any, Any]:
        if not isinstance(prep_handle, str) or not _HANDLE.fullmatch(prep_handle):
            raise ApplicationToolchainDenied("runtime preparation selection handle is malformed")
        resolver = getattr(self.choices, "resolve_application_runtime_preparation_input_selection", None)
        if not callable(resolver):
            raise ApplicationToolchainDenied("current root runtime preparation selector is unavailable")
        try:
            from .application_runtime_selection import RootApplicationRuntimePreparationInputSelection
            selection = resolver(prep_handle)
            if (type(selection) is not RootApplicationRuntimePreparationInputSelection
                    or selection.selection_handle != prep_handle):
                raise ValueError
            if selection.application_id != "hyperframes":
                raise ValueError
            if selection.runtime_kind != "node":
                raise ValueError
            choice_handle = selection.qualification_choice_handle
            if not isinstance(choice_handle, str) or not _HANDLE.fullmatch(choice_handle):
                raise ValueError
            choice = self.choices.resolve_application_setup_choice(choice_handle)
            if (getattr(choice, "selection_handle", None) != choice_handle
                    or getattr(choice, "application_id", None) != "hyperframes"
                    or getattr(choice, "workflow_id", None) != "qualify-hyperframes-v1"):
                raise ValueError
            session = self.sessions.resolve_live_session_id(choice.setup_session_id)
            if getattr(session, "selected_installation", None) is not self.choices:
                raise ValueError
            self.release.verify_current()
            self.actor_verifier.verify_current(session.plan)
            if not self._journal_current():
                raise ValueError
            consent = self.choices.resolve_application_qualification_consent(
                choice_handle, "acquire-locked-runtime-packages")
            if (getattr(consent, "qualification_choice_handle", None) != choice_handle
                    or getattr(consent, "application_id", None) != "hyperframes"
                    or getattr(consent, "workflow_id", None) != "qualify-hyperframes-v1"
                    or getattr(consent, "purpose", None) != "installer-application-local-qualification"
                    or "acquire-locked-runtime-packages" not in getattr(consent, "allowed_phase_ids", ())
                    or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                    or getattr(consent, "expires_monotonic", 0) <= self.monotonic()):
                raise ValueError
            source_handle = selection.prepared_source_receipt_handle
            lock_handle = selection.selected_lock_receipt_handle
            lock_sha = selection.lock_sha256
            source_prep_handle = selection.source_preparation_selection_handle
            if (not isinstance(source_prep_handle, str) or not _HANDLE.fullmatch(source_prep_handle)
                    or not isinstance(source_handle, str) or not _HANDLE.fullmatch(source_handle)
                    or not isinstance(lock_handle, str) or not _HANDLE.fullmatch(lock_handle)
                    or not isinstance(lock_sha, str) or not _SHA.fullmatch(lock_sha)):
                raise ValueError
            return selection, choice, consent
        except ApplicationToolchainDenied:
            raise
        except Exception:
            raise ApplicationToolchainDenied("current selected Hyperframes runtime preparation or setup consent is unavailable") from None

    def _journal_current(self) -> bool:
        try:
            info = self.journal.path.lstat()
            return (stat.S_ISDIR(info.st_mode) and info.st_uid == self.expected_uid
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_dev == self.journal.device and info.st_ino == self.journal.inode)
        except OSError:
            return False

    def _observe_source(self, prep_handle: str, selection: Any, choice: Any,
                        tool_id: str, *, license_source: bool = False
                        ) -> VerifiedApplicationToolchainSourceObservation:
        """Get only a live, selected-plan source observation from the v150 broker."""
        try:
            source = self.artifact_source_observer.observe_selected_toolchain_source(
                prep_handle, tool_id)
            expected_pin = TOOLCHAINS[tool_id] if not license_source else TOOLCHAINS[
                "application-bun-1.4.3-linux-arm64"]
            expected_id = tool_id
            expected_digest = expected_pin.sha256 if not license_source else expected_pin.license_sha256
            expected_size = expected_pin.size_bytes if not license_source else expected_pin.license_size_bytes
            expected_kind = expected_pin.archive_kind if not license_source else ""
            expected_url = expected_pin.url if not license_source else expected_pin.license_url
            if (type(source) is not VerifiedApplicationToolchainSourceObservation
                    or source.artifact_id != expected_id or source.tool_id != expected_id
                    or source.sha256 != expected_digest or source.size_bytes != expected_size
                    or source.archive_kind != expected_kind
                    or source.source_kind != ("license" if license_source else "archive")
                    or source.source_url_sha256 != hashlib.sha256(expected_url.encode("utf-8")).hexdigest()
                    or source.source_policy_artifact_id != SOURCE_POLICY_ARTIFACT_ID
                    or source.source_policy_sha256 != SOURCE_POLICY_SHA256
                    or source.preparation_input_selection_handle != prep_handle
                    or source.source_preparation_selection_handle
                       != selection.source_preparation_selection_handle
                    or source.qualification_choice_handle != choice.selection_handle
                    or source.setup_session_id != choice.setup_session_id
                    or source.transaction_handle != choice.transaction_handle
                    or source.plan_sha256 != getattr(selection, "plan_sha256", None)
                    or not self.artifact_source_observer.verify_current(source, prep_handle)):
                raise ValueError
            return source
        except Exception:
            raise ApplicationToolchainDenied(
                "selected-plan toolchain source observer did not return the exact current pinned bytes"
            ) from None

    def _source_fd(self, source: VerifiedApplicationToolchainSourceObservation,
                   prep_handle: str) -> int:
        try:
            fd = self.artifact_source_observer.open_blob(source, prep_handle)
            info = os.fstat(fd)
            expected_size = source.size_bytes
            digest, size = _sha_fd(fd, expected_size)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or info.st_nlink != 1 or info.st_mode & 0o222
                    or info.st_size != expected_size or size != expected_size
                    or digest != source.sha256):
                os.close(fd)
                raise ValueError
            return fd
        except Exception:
            raise ApplicationToolchainDenied(
                "selected-plan source observer could not open its exact held bytes"
            ) from None

    def acquire_selected_toolchain(self, runtime_preparation_selection_handle: str,
                                   tool_id: str) -> RootApplicationToolchainObservation:
        """Acquire one of the two exact public Hyperframes runtime artifacts."""
        pin = TOOLCHAINS.get(tool_id)
        if pin is None:
            raise ApplicationToolchainDenied("toolchain id is outside the exact Node/Bun v144 catalog")
        selection, choice, consent = self._selection(runtime_preparation_selection_handle)
        if os.geteuid() != self.expected_uid or self.expected_uid != 0 or platform.system() != "Linux":
            raise ApplicationToolchainDenied("toolchain acquisition runs only in the installed root Linux setup actor")
        return self._acquire(pin, runtime_preparation_selection_handle, selection, choice, consent)

    def observe_selected_toolchain(self, runtime_preparation_selection_handle: str,
                                   tool_id: str) -> str:
        """Return an opaque handle for a currently acquired, held selected toolchain."""
        pin = TOOLCHAINS.get(tool_id)
        if pin is None:
            raise ApplicationToolchainDenied("toolchain id is outside the exact Node/Bun v144 catalog")
        selection, choice, consent = self._selection(runtime_preparation_selection_handle)
        entry = self._entries.get((runtime_preparation_selection_handle, tool_id))
        if entry is None:
            entry = self._acquire(pin, runtime_preparation_selection_handle, selection, choice, consent)
        self._verify_entry(entry, selection, choice, consent)
        return entry.observation.receipt_handle

    def resolve_selected_toolchain(self, receipt_handle: str,
                                   runtime_preparation_selection_handle: str) -> RootApplicationToolchainObservation:
        if not isinstance(receipt_handle, str) or not _HANDLE.fullmatch(receipt_handle):
            raise ApplicationToolchainDenied("toolchain receipt handle is malformed")
        selection, choice, consent = self._selection(runtime_preparation_selection_handle)
        rows = [entry for (prep, _tool), entry in self._entries.items()
                if prep == runtime_preparation_selection_handle
                and entry.observation.receipt_handle == receipt_handle]
        if len(rows) != 1:
            raise ApplicationToolchainDenied("toolchain receipt is not retained by this root registry")
        entry = rows[0]
        self._verify_entry(entry, selection, choice, consent)
        return entry.observation

    def resolve_current_toolchain_for_selection(
        self, runtime_preparation_selection_handle: str,
    ) -> tuple[RootApplicationToolchainObservation, RootApplicationToolchainObservation]:
        """Return the exact retained Node and Bun receipts for a current early selector.

        This is a read-only join used by the later v132 final selector. It never
        fetches a missing artifact or derives membership from a path/version.
        """
        selection, choice, consent = self._selection(runtime_preparation_selection_handle)
        rows: list[RootApplicationToolchainObservation] = []
        for tool_id in TOOLCHAINS:
            entry = self._entries.get((runtime_preparation_selection_handle, tool_id))
            if entry is None:
                raise ApplicationToolchainDenied("selected Hyperframes Node and Bun source receipts are incomplete")
            self._verify_entry(entry, selection, choice, consent)
            rows.append(entry.observation)
        if len(rows) != 2 or {item.tool_id for item in rows} != set(TOOLCHAINS):
            raise ApplicationToolchainDenied("selected Hyperframes toolchain receipt set is incomplete")
        return rows[0], rows[1]

    def _acquire(self, pin: ApplicationToolchainPin, prep_handle: str,
                 selection: Any, choice: Any, consent: Any) -> RootApplicationToolchainObservation:
        key = (prep_handle, pin.tool_id)
        prior = self._entries.get(key)
        if prior is not None:
            self._verify_entry(prior, selection, choice, consent)
            return prior.observation
        if (not _HANDLE.fullmatch(selection.prepared_source_receipt_handle)
                or not _HANDLE.fullmatch(selection.selected_lock_receipt_handle)
                or not _SHA.fullmatch(selection.lock_sha256)
                or selection.controller_binding_handle != choice.controller_binding_handle):
            raise ApplicationToolchainDenied("toolchain acquisition is not bound to prepared source, lock, and controller")
        transaction = getattr(choice, "transaction_handle", None)
        if not isinstance(transaction, str) or not _HANDLE.fullmatch(transaction):
            raise ApplicationToolchainDenied("toolchain setup transaction binding is malformed")
        base = self.journal.path / "application-toolchains" / hashlib.sha256(transaction.encode()).hexdigest()
        _ensure_private_directory(self.journal.path / "application-toolchains", self.expected_uid)
        _ensure_private_directory(base, self.expected_uid)
        target = base / pin.tool_id
        try:
            target.mkdir(mode=0o700)
        except FileExistsError:
            raise ApplicationToolchainDenied("unowned or incomplete toolchain CAS path already exists") from None
        target_info = target.lstat()
        if (not stat.S_ISDIR(target_info.st_mode) or target_info.st_uid != self.expected_uid
                or stat.S_IMODE(target_info.st_mode) != 0o700):
            raise ApplicationToolchainDenied("toolchain CAS target is not private and root-owned")
        target_identity = (target_info.st_dev, target_info.st_ino)
        tree_path = target / "tree"
        source_observation: VerifiedApplicationToolchainSourceObservation | None = None
        license_source_observation: VerifiedApplicationToolchainSourceObservation | None = None
        executable_fd: int | None = None
        try:
            # Re-resolve signed phase intent immediately before the first byte.
            current_selection, current_choice, current_consent = self._selection(prep_handle)
            if (current_selection is not selection
                    or current_selection.selection_handle != prep_handle
                    or current_selection.source_preparation_selection_handle
                       != selection.source_preparation_selection_handle
                    or current_selection.prepared_source_receipt_handle
                       != selection.prepared_source_receipt_handle
                    or current_selection.selected_lock_receipt_handle
                       != selection.selected_lock_receipt_handle
                    or current_selection.lock_sha256 != selection.lock_sha256
                    or current_choice.selection_handle != choice.selection_handle
                    or current_choice.signature != choice.signature
                    or current_consent.qualification_choice_handle != choice.selection_handle
                    or current_consent.purpose != consent.purpose
                    or "acquire-locked-runtime-packages" not in current_consent.allowed_phase_ids):
                raise ApplicationToolchainDenied("toolchain consent changed before source acquisition")
            source_observation = self._observe_source(prep_handle, selection, choice, pin.tool_id)
            source_fd = self._source_fd(source_observation, prep_handle)
            try:
                members = _extract_archive(pin, source_fd, tree_path, self.expected_uid)
            finally:
                os.close(source_fd)
            if pin.tool_id.startswith("application-bun-"):
                assert pin.license_sha256 and pin.license_size_bytes and pin.license_url
                license_source_observation = self._observe_source(
                    prep_handle, selection, choice, "application-bun-1.4.3-license",
                    license_source=True)
                license_fd = self._source_fd(license_source_observation, prep_handle)
                try:
                    license_body = os.pread(license_fd, pin.license_size_bytes + 1, 0)
                    if len(license_body) != pin.license_size_bytes:
                        raise ApplicationToolchainDenied("Bun source license size differs from its v144 pin")
                finally:
                    os.close(license_fd)
                members = dict(members)
                members[".source-license/LICENSE.md"] = _write_tree_file(
                    tree_path, ".source-license/LICENSE.md", license_body,
                    False, self.expected_uid)
                license_member = ".source-license/LICENSE.md"
            else:
                license_matches = [name for name in members
                                   if PurePosixPath(name).name.casefold() in {"license", "license.md"}
                                   and PurePosixPath(name).parent.as_posix() == "."]
                if len(license_matches) != 1:
                    raise ApplicationToolchainDenied("Node archive does not contain one exact root license member")
                license_member = license_matches[0]
            executable_path = tree_path.joinpath(*PurePosixPath(pin.executable_member).parts)
            executable_fd = os.open(executable_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            executable = os.fstat(executable_fd)
            executable_sha, executable_size = _sha_fd(executable_fd, _MAX_EXPANDED_BYTES)
            if (not stat.S_ISREG(executable.st_mode) or executable.st_uid != self.expected_uid
                    or stat.S_IMODE(executable.st_mode) != 0o555 or executable_size < 1):
                os.close(executable_fd)
                executable_fd = None
                raise ApplicationToolchainDenied("selected toolchain executable member is not held and executable")
            tree_digest = _verify_private_tree(tree_path, expected_uid=self.expected_uid,
                                               expected_members=members)
            recipe_sha = _fixed_probe(pin, executable_fd, tree_path, expected_uid=self.expected_uid)
            receipt_handle = secrets.token_urlsafe(36)
            license_handle = secrets.token_urlsafe(36)
            root_handle = secrets.token_urlsafe(36)
            now = self.monotonic()
            expiry = min(float(getattr(selection, "expires_monotonic", now + 900)),
                         float(getattr(choice, "expires_monotonic", now + 900)))
            if expiry <= now:
                os.close(executable_fd)
                executable_fd = None
                raise ApplicationToolchainDenied("toolchain source receipt expired during its probe")
            notice_rows = [
                {"path": path, **dict(record)} for path, record in sorted(members.items())
                if PurePosixPath(path).name.casefold().startswith(("license", "notice", "copying", "third_party"))
                or PurePosixPath(path).name.casefold() in {"copyright", "patents"}
            ]
            notice_digest = hashlib.sha256(_canonical(notice_rows)).hexdigest()
            claims = {
                "schema": 1, "receipt_handle": receipt_handle,
                "tool_id": pin.tool_id, "version": pin.version, "platform": pin.platform,
                "source_artifact_id": pin.tool_id, "source_sha256": pin.sha256,
                "source_size_bytes": pin.size_bytes,
                "license_observation_handles": (license_handle,),
                "package_notice_observation_sha256": notice_digest,
                "executable_member": pin.executable_member,
                "executable_sha256": executable_sha,
                "executable_device": executable.st_dev, "executable_inode": executable.st_ino,
                "executable_mode": stat.S_IMODE(executable.st_mode),
                "runtime_manifest_sha256": tree_digest,
                "toolchain_root_selection_handle": root_handle,
                "runtime_preparation_selection_handle": prep_handle,
                "choice_selection_handle": choice.selection_handle,
                "recipe_sha256": recipe_sha,
                "issued_monotonic": now, "expires_monotonic": expiry,
                # v144 explicitly requires the original signed choice record here.
                "signature": choice.signature,
            }
            self._write_receipt(target / "observation.json", claims)
            license_record = {
                "schema": 1, "receipt_handle": license_handle,
                "tool_id": pin.tool_id, "source_sha256": pin.sha256,
                "member_path": license_member,
                "sha256": members[license_member]["sha256"],
                "size_bytes": members[license_member]["size_bytes"],
                "source": ("archive-member" if pin.license_url is None else "selected-toolchain-license-source"),
                "publisher_digest": (None if pin.license_sha256 is None else pin.license_sha256),
                "source_artifact_id": (None if license_source_observation is None
                                       else license_source_observation.artifact_id),
                "source_url_sha256": (None if license_source_observation is None
                                      else license_source_observation.source_url_sha256),
                "choice_signature": choice.signature,
            }
            self._write_receipt(target / "license-observation.json", license_record)
            observation = RootApplicationToolchainObservation(
                **claims, _executable_fd=executable_fd, _root=tree_path,
                _members=dict(members), _registry_id=self.registry_id, _seal=_RECORD_SEAL)
            entry = _ToolchainEntry(observation, target, source_observation,
                                    license_source_observation, tree_path,
                                    target / "manifest.json", choice, prep_handle)
            self._write_receipt(target / "manifest.json", {
                "schema": 1, "tool_id": pin.tool_id,
                "source_sha256": pin.sha256, "source_size_bytes": pin.size_bytes,
                "members": dict(sorted(members.items())),
                "tree_sha256": tree_digest,
                "source_policy_artifact_id": SOURCE_POLICY_ARTIFACT_ID,
                "source_policy_sha256": SOURCE_POLICY_SHA256,
                "source_url_sha256": entry.source_observation.source_url_sha256,
                "license": ({"url": pin.license_url, "sha256": pin.license_sha256,
                             "size_bytes": pin.license_size_bytes}
                            if pin.license_sha256 else {"source_member": "LICENSE"}),
                "notices_sha256": notice_digest,
            })
            self._entries[key] = entry
            self._verify_entry(entry, selection, choice, consent)
            return observation
        except BaseException:
            try:
                if executable_fd is not None and key not in self._entries:
                    os.close(executable_fd)
                if key not in self._entries:
                    if source_observation is not None:
                        source_observation.close()
                    if license_source_observation is not None:
                        license_source_observation.close()
                # This target was created exclusively by this invocation. Remove
                # an incomplete attempt only while its inode still matches; a
                # completed live entry is retained and revalidated instead.
                current_target = target.lstat()
                if (key not in self._entries and stat.S_ISDIR(current_target.st_mode)
                        and (current_target.st_dev, current_target.st_ino) == target_identity
                        and current_target.st_uid == self.expected_uid
                        and stat.S_IMODE(current_target.st_mode) == 0o700):
                    shutil.rmtree(target, ignore_errors=True)
            except Exception:
                pass
            raise

    def _verify_entry(self, entry: _ToolchainEntry, selection: Any,
                      choice: Any, consent: Any) -> None:
        observation = entry.observation
        pin = TOOLCHAINS.get(observation.tool_id)
        if (pin is None or observation._registry_id != self.registry_id
                or observation._seal is not _RECORD_SEAL
                or observation.runtime_preparation_selection_handle != entry.prep_handle
                or observation.choice_selection_handle != choice.selection_handle
                or observation.signature != choice.signature
                or observation.expires_monotonic <= self.monotonic()
                or getattr(selection, "application_id", None) != "hyperframes"
                or getattr(selection, "controller_binding_handle", None) != choice.controller_binding_handle
                or getattr(consent, "receipt_handle", None) == ""):
            raise ApplicationToolchainDenied("retained toolchain observation is stale, foreign, or detached")
        self.release.verify_current()
        session = self.sessions.resolve_live_session_id(choice.setup_session_id)
        self.actor_verifier.verify_current(session.plan)
        if not self._journal_current():
            raise ApplicationToolchainDenied("selected protected toolchain journal changed")
        try:
            if not self.artifact_source_observer.verify_current(
                    entry.source_observation, entry.prep_handle):
                entry.source_observation.close()
                entry.source_observation = self._observe_source(
                    entry.prep_handle, selection, choice, pin.tool_id)
            if pin.license_sha256:
                if (entry.license_source_observation is None
                        or not self.artifact_source_observer.verify_current(
                            entry.license_source_observation, entry.prep_handle)):
                    if entry.license_source_observation is not None:
                        entry.license_source_observation.close()
                    entry.license_source_observation = self._observe_source(
                        entry.prep_handle, selection, choice,
                        "application-bun-1.4.3-license", license_source=True)
            transaction_dir = entry.cas_target.parent
            artifacts_dir = transaction_dir.parent
            for directory in (artifacts_dir, transaction_dir, entry.cas_target):
                directory_info = directory.lstat()
                if (not stat.S_ISDIR(directory_info.st_mode)
                        or directory_info.st_uid != self.expected_uid
                        or stat.S_IMODE(directory_info.st_mode) != 0o700):
                    raise ValueError
            if not self.artifact_source_observer.verify_current(
                    entry.source_observation, entry.prep_handle):
                raise ValueError
            if (entry.source_observation.sha256 != pin.sha256
                    or entry.source_observation.size_bytes != pin.size_bytes
                    or entry.source_observation.source_policy_sha256 != SOURCE_POLICY_SHA256):
                raise ValueError
            if pin.license_sha256 and (entry.license_source_observation is None
                    or not self.artifact_source_observer.verify_current(
                        entry.license_source_observation, entry.prep_handle)
                    or entry.license_source_observation.sha256 != pin.license_sha256
                    or entry.license_source_observation.size_bytes != pin.license_size_bytes):
                raise ValueError
            tree_digest = _verify_private_tree(entry.tree_path, expected_uid=self.expected_uid,
                                               expected_members=entry.observation._members)
            if tree_digest != observation.runtime_manifest_sha256:
                raise ValueError
            executable = os.fstat(observation._executable_fd)
            if ((executable.st_dev, executable.st_ino, stat.S_IMODE(executable.st_mode))
                    != (observation.executable_device, observation.executable_inode,
                        observation.executable_mode)):
                raise ValueError
            digest, _size = _sha_fd(observation._executable_fd, _MAX_EXPANDED_BYTES)
            if digest != observation.executable_sha256:
                raise ValueError
            manifest = _read_private_record(entry.manifest_path, expected_uid=self.expected_uid)
            durable_observation = _read_private_record(
                entry.cas_target / "observation.json", expected_uid=self.expected_uid)
            durable_license = _read_private_record(
                entry.cas_target / "license-observation.json", expected_uid=self.expected_uid)
            observation_claims = {
                name: getattr(observation, name)
                for name in (
                    "schema", "receipt_handle", "tool_id", "version", "platform",
                    "source_artifact_id", "source_sha256", "source_size_bytes",
                    "license_observation_handles", "package_notice_observation_sha256",
                    "executable_member", "executable_sha256", "executable_device",
                    "executable_inode", "executable_mode", "runtime_manifest_sha256",
                    "toolchain_root_selection_handle", "runtime_preparation_selection_handle",
                    "choice_selection_handle", "recipe_sha256", "issued_monotonic",
                    "expires_monotonic", "signature",
                )
            }
            license_handle = observation.license_observation_handles
            expected_license_manifest = (
                {"url": pin.license_url, "sha256": pin.license_sha256,
                 "size_bytes": pin.license_size_bytes}
                if pin.license_url else {"source_member": durable_license.get("member_path")}
            )
            if (not isinstance(manifest, dict) or manifest.get("source_sha256") != pin.sha256
                    or manifest.get("tool_id") != pin.tool_id
                    or manifest.get("source_size_bytes") != pin.size_bytes
                    or manifest.get("members") != dict(sorted(entry.observation._members.items()))
                    or manifest.get("tree_sha256") != observation.runtime_manifest_sha256
                    or manifest.get("source_policy_artifact_id") != SOURCE_POLICY_ARTIFACT_ID
                    or manifest.get("source_policy_sha256") != SOURCE_POLICY_SHA256
                    or manifest.get("source_url_sha256") != entry.source_observation.source_url_sha256
                    or manifest.get("license") != expected_license_manifest
                    or manifest.get("notices_sha256") != observation.package_notice_observation_sha256
                    or _canonical(durable_observation) != _canonical(observation_claims)
                    or durable_license.get("receipt_handle") not in license_handle
                    or durable_license.get("tool_id") != pin.tool_id
                    or durable_license.get("source_sha256") != pin.sha256
                    or durable_license.get("source") != (
                        "selected-toolchain-license-source" if pin.license_url else "archive-member")
                    or durable_license.get("publisher_digest") != pin.license_sha256
                    or durable_license.get("source_artifact_id") != (
                        None if pin.license_url is None else "application-bun-1.4.3-license")
                    or durable_license.get("source_url_sha256") != (
                        None if entry.license_source_observation is None
                        else entry.license_source_observation.source_url_sha256)
                    or durable_license.get("size_bytes") != entry.observation._members.get(
                        durable_license.get("member_path"), {}).get("size_bytes")
                    or durable_license.get("choice_signature") != choice.signature
                    or durable_license.get("sha256") != entry.observation._members.get(
                        durable_license.get("member_path"), {}).get("sha256")):
                raise ValueError
            current_consent = self.choices.resolve_application_qualification_consent(
                choice.selection_handle, "acquire-locked-runtime-packages")
            if (current_consent.qualification_choice_handle != choice.selection_handle
                    or current_consent.purpose != "installer-application-local-qualification"
                    or "acquire-locked-runtime-packages" not in current_consent.allowed_phase_ids
                    or current_consent.expires_monotonic <= self.monotonic()):
                raise ValueError
        except ApplicationToolchainDenied:
            raise
        except Exception:
            raise ApplicationToolchainDenied("retained toolchain artifact or currentness evidence changed") from None

    def _write_receipt(self, path: Path, claims: Mapping[str, Any]) -> None:
        raw = _canonical(claims) + b"\n"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view[:64 * 1024])
                if written < 1:
                    raise OSError("short toolchain receipt write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
