"""Root-owned pinned artifact and offline Python package broker.

Catalog URLs, paths and installation targets come only from a protected catalog.
Profile callers provide an artifact/package identity and digest; they never supply
an URL, filesystem path, command or package-manager option.
"""
from __future__ import annotations

import hashlib
import json
import errno
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import tempfile
import tarfile
from types import MappingProxyType
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Mapping

from .authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest

_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_VERSION = re.compile(r"[A-Za-z0-9+_.-]{1,128}\Z")
_HOST = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REQ = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.-]*)==([A-Za-z0-9][A-Za-z0-9_.+-]*)\s+--hash=sha256:([0-9a-f]{64})\Z")
_CHUNK = 128 * 1024
_MAX_FILES = 20_000


@dataclass(frozen=True, slots=True)
class TreeFile:
    path: str
    sha256: str
    size_bytes: int
    executable: bool = False

    def __post_init__(self) -> None:
        _safe_relative(self.path)
        _validate_sha(self.sha256)
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("tree file size is invalid")
        if type(self.executable) is not bool:
            raise ValueError("tree file executable flag is invalid")


@dataclass(frozen=True, slots=True)
class ArtifactSpec:
    artifact_id: str
    version: str
    sha256: str
    source_url: str
    max_bytes: int
    size_bytes: int | None = None
    redirect_hosts: tuple[str, ...] = ()
    filename: str = "artifact"
    tree_files: tuple[TreeFile, ...] = ()
    archive_format: str | None = None
    archive_root: str | None = None
    max_tree_bytes: int = 8 * 1024**3

    def __post_init__(self) -> None:
        _validate_id(self.artifact_id)
        if not _valid_version(self.version):
            raise ValueError("artifact version is invalid")
        _validate_sha(self.sha256)
        parsed = urllib.parse.urlsplit(self.source_url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username
                or parsed.password or parsed.fragment or parsed.query
                or (parsed.port is not None and parsed.port != 443)):
            raise ValueError("artifact source must be an HTTPS URL without userinfo or fragment")
        if not _HOST.fullmatch(parsed.hostname.casefold()):
            raise ValueError("artifact source host is invalid")
        if type(self.max_bytes) is not int or not 1 <= self.max_bytes <= 8 * 1024**3:
            raise ValueError("artifact byte bound is invalid")
        if self.size_bytes is not None and (type(self.size_bytes) is not int or not 1 <= self.size_bytes <= self.max_bytes):
            raise ValueError("artifact size is invalid")
        if not _safe_leaf(self.filename):
            raise ValueError("artifact filename is invalid")
        hosts = {parsed.hostname.casefold()}
        for host in self.redirect_hosts:
            if not isinstance(host, str) or not _HOST.fullmatch(host.casefold()):
                raise ValueError("artifact redirect host is invalid")
            hosts.add(host.casefold())
        object.__setattr__(self, "redirect_hosts", tuple(sorted(hosts)))
        if not isinstance(self.tree_files, tuple) or any(not isinstance(entry, TreeFile) for entry in self.tree_files):
            raise ValueError("artifact tree must contain immutable file records")
        paths = [entry.path for entry in self.tree_files]
        if len(paths) != len(set(paths)):
            raise ValueError("artifact tree has duplicate paths")
        if self.archive_format not in {None, "zip", "tar.gz"}:
            raise ValueError("artifact archive format is unsupported")
        if self.archive_root is not None:
            if (self.archive_format != "tar.gz" or not isinstance(self.archive_root, str)
                    or not self.archive_root.endswith("/")
                    or _safe_relative(self.archive_root[:-1]).as_posix() != self.archive_root[:-1]):
                raise ValueError("archive root must be a normalized tar directory prefix")
        if type(self.max_tree_bytes) is not int or not 1 <= self.max_tree_bytes <= 8 * 1024**3:
            raise ValueError("artifact tree byte bound is invalid")
        if bool(self.tree_files) != bool(self.archive_format):
            raise ValueError("artifact tree files and archive format must be enrolled together")
        if self.tree_files and sum(item.size_bytes for item in self.tree_files) > self.max_tree_bytes:
            raise ValueError("artifact tree exceeds its enrolled expanded-size bound")


@dataclass(frozen=True, slots=True)
class PackageSpec:
    package_id: str
    version: str
    artifact_id: str
    artifact_sha256: str
    runtime_id: str
    python_executable: str
    environment_root: str
    install_timeout_seconds: int = 120

    def __post_init__(self) -> None:
        _validate_id(self.package_id)
        if not _valid_version(self.version):
            raise ValueError("package version is invalid")
        _validate_id(self.artifact_id)
        _validate_sha(self.artifact_sha256)
        _validate_id(self.runtime_id)
        python_path = Path(self.python_executable)
        environment_path = Path(self.environment_root)
        if (not python_path.is_absolute() or not environment_path.is_absolute()
                or ".." in python_path.parts or ".." in environment_path.parts
                or environment_path == Path("/") or python_path == Path("/")):
            raise ValueError("package runtime paths must be absolute protected paths")
        if type(self.install_timeout_seconds) is not int or not 1 <= self.install_timeout_seconds <= 600:
            raise ValueError("package install timeout is invalid")


@dataclass(frozen=True, slots=True)
class ResolvedArtifact:
    artifact_id: str
    version: str
    path: Path
    sha256: str
    size_bytes: int
    tree_files: tuple[TreeFile, ...] = ()
    archive_format: str | None = None
    archive_root: str | None = None
    max_tree_bytes: int = 0


@dataclass(frozen=True, slots=True)
class ArtifactCatalog:
    artifacts: Mapping[str, ArtifactSpec]
    packages: Mapping[tuple[str, str], PackageSpec]

    def __post_init__(self) -> None:
        if any(key != item.artifact_id for key, item in self.artifacts.items()):
            raise ValueError("artifact catalog keys must match artifact IDs")
        if any(key != (item.package_id, item.version) for key, item in self.packages.items()):
            raise ValueError("package catalog keys must match package IDs and versions")
        for package in self.packages.values():
            artifact = self.artifacts.get(package.artifact_id)
            if artifact is None or artifact.sha256 != package.artifact_sha256:
                raise ValueError("package must bind an enrolled artifact digest")
            if artifact.archive_format != "zip" or not artifact.tree_files:
                raise ValueError("Python package installs require an enrolled ZIP content tree")
        object.__setattr__(self, "artifacts", MappingProxyType(dict(self.artifacts)))
        object.__setattr__(self, "packages", MappingProxyType(dict(self.packages)))

    @classmethod
    def from_records(cls, artifacts: tuple[ArtifactSpec, ...], packages: tuple[PackageSpec, ...] = ()) -> "ArtifactCatalog":
        artifact_map = {item.artifact_id: item for item in artifacts}
        package_map = {(item.package_id, item.version): item for item in packages}
        if len(artifact_map) != len(artifacts) or len(package_map) != len(packages):
            raise ValueError("artifact catalog contains duplicate IDs")
        return cls(artifact_map, package_map)

    def resolve(self, artifact_id: str, sha256: str, staging_root: Path | str,
                *, expected_uid: int = 0) -> ResolvedArtifact:
        """Resolve an enrolled digest only after custody, type, size and hash checks."""
        spec = self._artifact(artifact_id, sha256)
        root = _secure_directory(Path(staging_root), expected_uid)
        path = root / "objects" / artifact_id / sha256 / spec.filename
        try:
            info = path.lstat()
        except OSError:
            raise AuthorityDenied("artifact.missing", "verified artifact is not staged; resume with the enrolled artifact ID") from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o222
                or (spec.size_bytes is not None and info.st_size != spec.size_bytes)
                or info.st_size > spec.max_bytes):
            raise AuthorityDenied("artifact.custody", "staged artifact custody or size is invalid")
        digest, size = _hash_file(path, spec.max_bytes)
        if digest != sha256:
            raise AuthorityDenied("artifact.digest", "staged artifact digest no longer matches its protected catalog")
        return ResolvedArtifact(artifact_id, spec.version, path, digest, size,
                                spec.tree_files, spec.archive_format, spec.archive_root,
                                spec.max_tree_bytes)

    def resolve_store_id(self, store_id: str, staging_root: Path | str,
                         *, expected_uid: int = 0) -> ResolvedArtifact:
        """Resolve an opaque broker receipt inside the trusted host service."""
        parts = store_id.split(":") if isinstance(store_id, str) else []
        if len(parts) != 3 or parts[0] != "artifact":
            raise AuthorityDenied("artifact.binding", "artifact store receipt is malformed")
        return self.resolve(parts[1], parts[2], staging_root, expected_uid=expected_uid)

    def materialize_tree(self, artifact_id: str, sha256: str, staging_root: Path | str,
                         *, expected_uid: int = 0) -> ResolvedArtifact:
        """Safely unpack and verify an enrolled archive into immutable owned storage."""
        spec = self._artifact(artifact_id, sha256)
        if not spec.tree_files or not spec.archive_format:
            raise AuthorityDenied("artifact.tree", "artifact has no protected content-tree enrollment")
        archive = self.resolve(artifact_id, sha256, staging_root, expected_uid=expected_uid)
        root = _secure_directory(Path(staging_root), expected_uid)
        path = _materialize_tree(spec, archive.path, root, expected_uid)
        return ResolvedArtifact(artifact_id, spec.version, path, sha256,
                                sum(item.size_bytes for item in spec.tree_files),
                                spec.tree_files, spec.archive_format, spec.archive_root,
                                spec.max_tree_bytes)

    def materialize_store_id(self, store_id: str, staging_root: Path | str,
                             *, expected_uid: int = 0) -> ResolvedArtifact:
        parts = store_id.split(":") if isinstance(store_id, str) else []
        if len(parts) != 3 or parts[0] != "artifact":
            raise AuthorityDenied("artifact.binding", "artifact store receipt is malformed")
        return self.materialize_tree(parts[1], parts[2], staging_root, expected_uid=expected_uid)

    def _artifact(self, artifact_id: str, sha256: str) -> ArtifactSpec:
        _validate_id(artifact_id)
        _validate_sha(sha256)
        spec = self.artifacts.get(artifact_id)
        if spec is None or spec.sha256 != sha256:
            raise AuthorityDenied("artifact.enrollment", "artifact identity and digest are not enrolled")
        return spec


def load_protected_catalog(path: Path | str, *, expected_uid: int = 0) -> ArtifactCatalog:
    """Load a strict catalog from a root-owned, non-writable JSON file."""
    file_path = Path(path)
    _secure_file(file_path, expected_uid, max_bytes=4 * 1024 * 1024)
    try:
        raw = file_path.read_bytes()
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError
        doc = json.loads(raw, object_pairs_hook=_unique_object)
        if (not isinstance(doc, dict) or set(doc) != {"schema", "artifacts", "packages"}
                or type(doc["schema"]) is not int or doc["schema"] != 1):
            raise ValueError
        artifacts = tuple(_artifact_from_record(item) for item in doc["artifacts"])
        packages = tuple(_package_from_record(item) for item in doc["packages"])
        return ArtifactCatalog.from_records(artifacts, packages)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise AuthorityDenied("artifact.catalog", "protected artifact catalog is malformed") from None


def build_artifact_handlers(catalog: ArtifactCatalog, staging_root: Path | str,
                            *, expected_uid: int = 0, opener: Callable[..., Any] | None = None
                            ) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Build exact fixed-verb handlers for the protected authority service."""
    root = _secure_directory(Path(staging_root), expected_uid)
    if not hasattr(os, "geteuid") or os.geteuid() != expected_uid:
        raise AuthorityDenied("artifact.identity", "artifact handlers must run as their enrolled installer identity")
    fetcher = opener or _open_url
    handlers: dict[tuple[str, str], Callable[..., Mapping[str, Any]]] = {}
    for spec in catalog.artifacts.values():
        target = f"artifact:{spec.artifact_id}:{spec.sha256}"

        def fetch_handler(*, context: HostContext, authorization: EffectAuthorization,
                          payload: bytes, timeout: float, peer_pid: int,
                          cancelled: Callable[[], bool], _spec: ArtifactSpec = spec) -> Mapping[str, Any]:
            del context, peer_pid
            expected = {"schema": 1, "artifact_id": _spec.artifact_id,
                        "sha256": _spec.sha256, "max_bytes": _spec.max_bytes}
            _check_grant_payload(authorization, payload, expected, f"artifact:{_spec.artifact_id}:{_spec.sha256}")
            resolved = _fetch_artifact(_spec, root, expected_uid, fetcher, timeout, cancelled)
            receipt = {"artifact_id": resolved.artifact_id, "version": resolved.version,
                       "sha256": resolved.sha256, "size_bytes": resolved.size_bytes,
                       "store_id": f"artifact:{resolved.artifact_id}:{resolved.sha256}"}
            return _json_response(receipt)

        handlers[("artifact.fetch", target)] = fetch_handler

    for package in catalog.packages.values():
        target = f"package:{package.package_id}:{package.version}:{package.artifact_sha256}"

        def install_handler(*, context: HostContext, authorization: EffectAuthorization,
                            payload: bytes, timeout: float, peer_pid: int,
                            cancelled: Callable[[], bool], _package: PackageSpec = package) -> Mapping[str, Any]:
            del context, peer_pid
            expected = {"schema": 1, "package_id": _package.package_id,
                        "version": _package.version,
                        "artifact_sha256": _package.artifact_sha256}
            _check_grant_payload(authorization, payload, expected,
                                 f"package:{_package.package_id}:{_package.version}:{_package.artifact_sha256}")
            artifact = catalog.resolve(_package.artifact_id, _package.artifact_sha256,
                                       root, expected_uid=expected_uid)
            artifact_spec = catalog._artifact(_package.artifact_id, _package.artifact_sha256)
            artifact = ResolvedArtifact(artifact.artifact_id, artifact.version, artifact.path,
                                        artifact.sha256, artifact.size_bytes,
                                        artifact_spec.tree_files, artifact_spec.archive_format,
                                        artifact_spec.archive_root, artifact_spec.max_tree_bytes)
            installed = _install_wheelhouse(_package, artifact, expected_uid,
                                             min(timeout, _package.install_timeout_seconds), cancelled)
            return _json_response({"package_id": _package.package_id,
                                   "version": _package.version,
                                   "artifact_sha256": _package.artifact_sha256,
                                   "runtime_id": _package.runtime_id,
                                   "environment_id": installed.name,
                                   "status": "installed"})

        handlers[("package.install", target)] = install_handler
    return handlers


def _fetch_artifact(spec: ArtifactSpec, root: Path, expected_uid: int,
                    opener: Callable[..., Any], timeout: float,
                    cancelled: Callable[[], bool]) -> ResolvedArtifact:
    final = root / "objects" / spec.artifact_id / spec.sha256 / spec.filename
    if final.exists():
        return ArtifactCatalog({spec.artifact_id: spec}, {}).resolve(spec.artifact_id, spec.sha256, root,
                                                                     expected_uid=expected_uid)
    directory = _mkdir_chain(root / "objects" / spec.artifact_id / spec.sha256, expected_uid)
    part = directory / (spec.filename + ".part")
    if part.exists() or part.is_symlink():
        info = part.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o077:
            raise AuthorityDenied("artifact.partial", "resumable artifact part has invalid custody")
    offset = part.stat().st_size if part.exists() else 0
    if offset > spec.max_bytes or (spec.size_bytes is not None and offset > spec.size_bytes):
        part.unlink(missing_ok=True)
        offset = 0
    if offset:
        matches_digest = _hash_file(part, spec.max_bytes)[0] == spec.sha256
        if matches_digest and (spec.size_bytes is None or offset == spec.size_bytes):
            os.chmod(part, 0o444)
            os.replace(part, final)
            _fsync_dir(directory)
            return ArtifactCatalog({spec.artifact_id: spec}, {}).resolve(spec.artifact_id, spec.sha256, root,
                                                                         expected_uid=expected_uid)
        if spec.size_bytes is not None and offset == spec.size_bytes:
            part.unlink(missing_ok=True)
            offset = 0

    deadline = time.monotonic() + max(0.05, min(timeout, 120.0))
    headers = {"User-Agent": "HermesAgentInstaller/1", "Accept-Encoding": "identity"}
    if offset:
        headers["Range"] = f"bytes={offset}-"
    request = urllib.request.Request(spec.source_url, headers=headers, method="GET")
    remaining_timeout = max(0.05, deadline - time.monotonic())
    try:
        response = opener(request, timeout=remaining_timeout, allowed_hosts=frozenset(spec.redirect_hosts))
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        raise AuthorityDenied("artifact.network", _network_error(exc)) from None
    try:
        status = getattr(response, "status", getattr(response, "code", 200))
        expected_response_total: int | None = None
        if offset and status == 200:
            # Origin ignored Range; restart cleanly, never append a full response.
            mode = "wb"
            offset = 0
        elif status == 206 and offset:
            content_range = response.headers.get("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+|\*)", content_range)
            if (match is None or match.group(3) == "*" or int(match.group(1)) != offset
                    or int(match.group(2)) < offset
                    or (spec.size_bytes is not None and match.group(3) != str(spec.size_bytes))):
                raise AuthorityDenied("artifact.range", "artifact server returned an invalid resume range")
            range_size = int(match.group(2)) - offset + 1
            expected_response_total = int(match.group(3))
            if int(match.group(2)) >= expected_response_total:
                raise AuthorityDenied("artifact.range", "artifact server returned an invalid resume range")
            mode = "ab"
        elif status == 200 and not offset:
            mode = "wb"
        else:
            raise AuthorityDenied("artifact.http", f"artifact server returned HTTP {status}")
        content_length = response.headers.get("Content-Length")
        if content_length is not None:
            try:
                declared = int(content_length)
            except ValueError:
                raise AuthorityDenied("artifact.http", "artifact response length is invalid") from None
            if declared < 0 or offset + declared > spec.max_bytes or (spec.size_bytes is not None and offset + declared > spec.size_bytes):
                raise AuthorityDenied("artifact.size", "artifact response exceeds its enrolled size bound")
            if status == 206 and declared != range_size:
                raise AuthorityDenied("artifact.range", "artifact response length differs from its range")
            if status == 200:
                expected_response_total = offset + declared
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(part, flags, 0o600)
        total = offset
        try:
            if mode == "wb":
                os.ftruncate(fd, 0)
            else:
                if os.fstat(fd).st_size != offset:
                    raise AuthorityDenied("artifact.partial", "resumable artifact changed during fetch")
                os.lseek(fd, offset, os.SEEK_SET)
            while True:
                if cancelled():
                    raise AuthorityDenied("artifact.cancelled", "artifact fetch was cancelled; partial data is resumable")
                if time.monotonic() >= deadline:
                    raise AuthorityDenied("artifact.timeout", "artifact fetch timed out; partial data is resumable")
                try:
                    block = response.read(min(_CHUNK, spec.max_bytes - total + 1))
                except OSError:
                    raise AuthorityDenied("artifact.network", "artifact transfer ended unexpectedly; partial data is resumable") from None
                if not block:
                    break
                total += len(block)
                if total > spec.max_bytes or (spec.size_bytes is not None and total > spec.size_bytes):
                    raise AuthorityDenied("artifact.size", "artifact exceeds its enrolled byte limit")
                view = memoryview(block)
                while view:
                    try:
                        written = os.write(fd, view)
                    except OSError as exc:
                        if exc.errno == errno.ENOSPC:
                            raise AuthorityDenied("artifact.storage", "artifact staging ran out of space; free space and retry to resume") from None
                        raise AuthorityDenied("artifact.storage", "artifact staging write failed; partial data is resumable") from None
                    view = view[written:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            raise
        else:
            os.close(fd)
    except AuthorityDenied:
        raise
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise AuthorityDenied("artifact.storage", "artifact staging ran out of space; free space and retry to resume") from None
        raise AuthorityDenied("artifact.storage", "artifact staging write failed; partial data is resumable") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise AuthorityDenied("artifact.network", _network_error(exc)) from None
    finally:
        try:
            response.close()
        except Exception:
            pass
    if ((spec.size_bytes is not None and total != spec.size_bytes)
            or (expected_response_total is not None and total != expected_response_total)):
        raise AuthorityDenied("artifact.incomplete", "artifact ended before its enrolled size; retry to resume")
    digest, size = _hash_file(part, spec.max_bytes)
    if digest != spec.sha256:
        part.unlink(missing_ok=True)
        raise AuthorityDenied("artifact.digest", "downloaded artifact did not match its enrolled SHA-256")
    os.chmod(part, 0o444)
    os.replace(part, final)
    _fsync_dir(directory)
    return ArtifactCatalog({spec.artifact_id: spec}, {}).resolve(spec.artifact_id, spec.sha256, root,
                                                                 expected_uid=expected_uid)


def _install_wheelhouse(package: PackageSpec, artifact: ResolvedArtifact,
                        expected_uid: int, timeout: float,
                        cancelled: Callable[[], bool]) -> Path:
    runtime_root = _secure_directory(Path(package.environment_root), expected_uid)
    python = Path(package.python_executable)
    python = _secure_executable(python, expected_uid)
    destination = runtime_root / package.package_id / package.version
    parent = _mkdir_chain(destination.parent, expected_uid)
    if destination.exists() or destination.is_symlink():
        _secure_directory(destination, expected_uid)
        marker = destination / ".hermes-package.json"
        _secure_file(marker, expected_uid, max_bytes=4096)
        try:
            receipt = json.loads(marker.read_text("utf-8"))
        except (OSError, ValueError):
            receipt = {}
        if receipt == {"package_id": package.package_id, "version": package.version,
                       "artifact_sha256": package.artifact_sha256, "runtime_id": package.runtime_id}:
            return destination
        raise AuthorityDenied("package.conflict", "versioned runtime path is occupied by a different package")
    work = Path(tempfile.mkdtemp(prefix=".install-", dir=parent))
    os.chown(work, expected_uid, -1)
    os.chmod(work, 0o700)
    try:
        source = _extract_checked_wheelhouse(artifact, work)
        temporary_env = work / "venv"
        python_command = python.resolve(strict=True)
        _secure_executable(python_command, expected_uid)
        _run_fixed([str(python_command), "-m", "venv", "--copies", str(temporary_env)], cwd=work,
                   timeout=timeout, cancelled=cancelled, expected_uid=expected_uid)
        env_python = temporary_env / "bin" / "python"
        if not env_python.is_file():
            raise AuthorityDenied("package.runtime", "isolated Python runtime did not create its interpreter")
        manifest = source / "requirements.txt"
        _validate_requirements(manifest)
        env = {"PATH": str(temporary_env / "bin") + ":/usr/bin:/bin",
               "HOME": str(work), "PIP_CONFIG_FILE": os.devnull,
               "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
               "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"}
        _run_fixed([str(env_python.resolve(strict=True)), "-m", "pip", "install", "--no-index",
                    "--find-links", str(source), "--require-hashes", "--no-deps",
                    "--only-binary=:all:", "--no-input", "--no-cache-dir",
                    "--disable-pip-version-check", "-r", str(manifest)], cwd=work,
                   timeout=timeout, cancelled=cancelled, expected_uid=expected_uid, env=env)
        marker = temporary_env / ".hermes-package.json"
        marker.write_text(json.dumps({"package_id": package.package_id,
                                      "version": package.version,
                                      "artifact_sha256": package.artifact_sha256,
                                      "runtime_id": package.runtime_id}, sort_keys=True) + "\n",
                          encoding="utf-8")
        os.chown(marker, expected_uid, -1)
        os.chmod(marker, 0o444)
        _freeze_tree(temporary_env, expected_uid)
        if cancelled():
            raise AuthorityDenied("package.cancelled", "package install was cancelled before activation")
        os.rename(temporary_env, destination)
        _fsync_dir(parent)
        return destination
    except BaseException:
        shutil.rmtree(work, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _extract_checked_wheelhouse(artifact: ResolvedArtifact, destination: Path) -> Path:
    # The wheelhouse must have a catalog-authenticated content tree, not just a ZIP digest.
    if not artifact.tree_files or artifact.archive_format != "zip":
        raise AuthorityDenied("package.tree", "package wheelhouse has no protected content-tree manifest")
    tree = destination / "wheelhouse"
    tree.mkdir(mode=0o700)
    _extract_archive(artifact.path, artifact.archive_format, artifact.archive_root, artifact.tree_files,
                    artifact.max_tree_bytes, tree, artifact.path.stat().st_uid)
    observed = _observed_tree(tree, artifact.max_tree_bytes)
    expected = {entry.path: (entry.sha256, entry.size_bytes) for entry in artifact.tree_files}
    if observed != expected:
        raise AuthorityDenied("package.tree", "wheelhouse files differ from the protected content tree")
    if "requirements.txt" not in observed:
        raise AuthorityDenied("package.manifest", "wheelhouse has no pinned requirements.txt")
    if not any(PurePosixPath(name).parent == PurePosixPath(".") and name.endswith(".whl") for name in observed):
        raise AuthorityDenied("package.wheels", "wheelhouse contains no wheel files")
    return tree


def _materialize_tree(spec: ArtifactSpec, archive_path: Path, staging_root: Path,
                      expected_uid: int) -> Path:
    base = _mkdir_chain(staging_root / "trees" / spec.artifact_id / spec.sha256, expected_uid)
    destination = base / "content"
    if destination.exists() or destination.is_symlink():
        info = destination.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o222:
            raise AuthorityDenied("artifact.tree-custody", "materialized artifact tree custody is invalid")
        observed = _observed_tree(destination, spec.max_tree_bytes)
        expected = {entry.path: (entry.sha256, entry.size_bytes) for entry in spec.tree_files}
        if observed != expected:
            raise AuthorityDenied("artifact.tree-digest", "materialized content tree no longer matches its protected catalog")
        return destination
    temp = Path(tempfile.mkdtemp(prefix=".tree-", dir=base))
    try:
        _extract_archive(archive_path, spec.archive_format, spec.archive_root, spec.tree_files,
                         spec.max_tree_bytes, temp, expected_uid)
        observed = _observed_tree(temp, spec.max_tree_bytes)
        expected = {entry.path: (entry.sha256, entry.size_bytes) for entry in spec.tree_files}
        if observed != expected:
            raise AuthorityDenied("artifact.tree-digest", "archive content does not match its protected tree manifest")
        _freeze_tree(temp, expected_uid)
        os.rename(temp, destination)
        _fsync_dir(base)
        return destination
    except BaseException:
        _remove_private_tree(temp)
        raise


def _extract_archive(archive_path: Path, archive_format: str | None, archive_root: str | None,
                     tree_files: tuple[TreeFile, ...], max_tree_bytes: int,
                     destination: Path, expected_uid: int) -> None:
    total = 0
    count = 0
    enrolled = {entry.path: entry for entry in tree_files}
    try:
        if archive_format == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                members = archive.infolist()
                if not members or len(members) > _MAX_FILES:
                    raise AuthorityDenied("artifact.archive", "archive member count is invalid")
                for info in members:
                    name = _strip_archive_root(info.filename, archive_root)
                    if info.is_dir():
                        if name:
                            _safe_relative(name.rstrip("/"))
                        continue
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode) or info.file_size < 0:
                        raise AuthorityDenied("artifact.archive", "archive contains a link or invalid member")
                    pure = _safe_relative(name)
                    entry = enrolled.get(pure.as_posix())
                    if entry is None or entry.size_bytes != info.file_size:
                        raise AuthorityDenied("artifact.tree-digest", "archive member is absent from the protected content tree")
                    count += 1
                    total += info.file_size
                    if total > max_tree_bytes or (info.compress_size == 0 and info.file_size > 0):
                        raise AuthorityDenied("artifact.archive", "archive exceeds its expanded-size bound")
                    with archive.open(info) as source:
                        _write_tree_file(source, destination, pure, info.file_size,
                                         expected_uid, entry.executable)
        elif archive_format == "tar.gz":
            with tarfile.open(archive_path, mode="r:gz") as archive:
                members = archive.getmembers()
                if not members or len(members) > _MAX_FILES:
                    raise AuthorityDenied("artifact.archive", "archive member count is invalid")
                for info in members:
                    name = _strip_archive_root(info.name, archive_root,
                                               allow_root_directory=info.isdir())
                    if info.isdir():
                        if name:
                            _safe_relative(name.rstrip("/"))
                        continue
                    if not info.isfile() or info.size < 0:
                        raise AuthorityDenied("artifact.archive", "archive contains a link or special member")
                    pure = _safe_relative(name)
                    entry = enrolled.get(pure.as_posix())
                    if entry is None or entry.size_bytes != info.size:
                        raise AuthorityDenied("artifact.tree-digest", "archive member is absent from the protected content tree")
                    count += 1
                    total += info.size
                    if total > max_tree_bytes:
                        raise AuthorityDenied("artifact.archive", "archive exceeds its expanded-size bound")
                    source = archive.extractfile(info)
                    if source is None:
                        raise AuthorityDenied("artifact.archive", "archive member cannot be read")
                    with source:
                        _write_tree_file(source, destination, pure, info.size,
                                         expected_uid, entry.executable)
        else:
            raise AuthorityDenied("artifact.archive", "archive format is not enrolled")
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, ValueError, RuntimeError, NotImplementedError):
        raise AuthorityDenied("artifact.archive", "pinned archive is malformed") from None
    if count != len(tree_files):
        raise AuthorityDenied("artifact.tree-digest", "archive file list does not match its protected tree manifest")


def _write_tree_file(source: Any, destination: Path, relative: PurePosixPath,
                     expected_size: int, expected_uid: int, executable: bool = False) -> None:
    target = destination.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    digest = hashlib.sha256()
    count = 0
    try:
        with os.fdopen(fd, "wb") as output:
            while True:
                block = source.read(_CHUNK)
                if not block:
                    break
                count += len(block)
                if count > expected_size:
                    raise AuthorityDenied("artifact.archive", "archive member exceeded its declared size")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    if count != expected_size:
        raise AuthorityDenied("artifact.archive", "archive member size differed from metadata")
    os.chown(target, expected_uid, -1)
    os.chmod(target, 0o555 if executable else 0o444)


def _observed_tree(root: Path, max_bytes: int) -> dict[str, tuple[str, int]]:
    observed: dict[str, tuple[str, int]] = {}
    total = 0
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode):
            raise AuthorityDenied("artifact.tree-custody", "materialized tree contains a link or special file")
        relative = path.relative_to(root).as_posix()
        digest, size = _hash_file(path, max_bytes)
        total += size
        if total > max_bytes:
            raise AuthorityDenied("artifact.tree-size", "materialized tree exceeds its enrolled size bound")
        observed[relative] = (digest, size)
    return observed


def _remove_private_tree(path: Path) -> None:
    if not path.exists():
        return
    for current, dirs, _files in os.walk(path, topdown=False, followlinks=False):
        try:
            os.chmod(current, 0o700)
        except OSError:
            pass
    shutil.rmtree(path, ignore_errors=True)


def _validate_requirements(path: Path) -> None:
    try:
        lines = path.read_text("utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        raise AuthorityDenied("package.manifest", "pinned requirements manifest is unreadable") from None
    if not lines or len(lines) > 10_000:
        raise AuthorityDenied("package.manifest", "pinned requirements manifest is empty or too large")
    packages = 0
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if not _REQ.fullmatch(value):
            raise AuthorityDenied("package.manifest", "requirements may contain only exact versions with SHA-256 hashes")
        packages += 1
    if not packages:
        raise AuthorityDenied("package.manifest", "requirements manifest contains no packages")


def _run_fixed(argv: list[str], *, cwd: Path, timeout: float,
               cancelled: Callable[[], bool], expected_uid: int,
               env: Mapping[str, str] | None = None) -> None:
    if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        raise AuthorityDenied("package.argv", "fixed package command is malformed")
    # The only commands built by this module are an enrolled interpreter and its venv/pip verbs.
    if not Path(argv[0]).is_absolute():
        raise AuthorityDenied("package.argv", "package interpreter path is not canonical")
    remaining = max(0.05, min(timeout, 600.0))
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=dict(env) if env is not None else {
            "PATH": "/usr/bin:/bin", "HOME": str(cwd), "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True, bufsize=0)
    except OSError:
        raise AuthorityDenied("package.runtime", "enrolled runtime could not start the fixed package operation") from None
    output = bytearray()
    if process.stdout is not None:
        os.set_blocking(process.stdout.fileno(), False)
    started = time.monotonic()
    try:
        while process.poll() is None:
            if cancelled():
                raise AuthorityDenied("package.cancelled", "package installation was cancelled")
            if time.monotonic() - started >= remaining:
                raise AuthorityDenied("package.timeout", "package installation timed out and is resumable")
            if process.stdout is not None:
                try:
                    data = os.read(process.stdout.fileno(), 4096)
                except BlockingIOError:
                    data = b""
                if data:
                    if len(output) < 64 * 1024:
                        output.extend(data[:64 * 1024 - len(output)])
            time.sleep(0.025)
        if process.stdout is not None:
            output.extend(process.stdout.read(64 * 1024 - len(output)))
        if process.returncode != 0:
            raise AuthorityDenied("package.failed", f"pinned offline package installation failed with exit status {process.returncode}")
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=2)
        raise
    finally:
        if process.stdout is not None:
            process.stdout.close()


class _AllowlistedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]):
        super().__init__()
        self.allowed_hosts = {host.casefold() for host in allowed_hosts}

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if (parsed.scheme != "https" or not parsed.hostname
                or parsed.hostname.casefold() not in self.allowed_hosts
                or parsed.username or parsed.password or parsed.fragment
                or (parsed.port is not None and parsed.port != 443)):
            raise urllib.error.HTTPError(newurl, code, "redirect host is not enrolled", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_url(request: urllib.request.Request, *, timeout: float,
              allowed_hosts: frozenset[str]):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _AllowlistedRedirect(allowed_hosts),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return opener.open(request, timeout=timeout)


def _check_grant_payload(authorization: EffectAuthorization, payload: bytes,
                         expected: Mapping[str, Any], target: str) -> None:
    try:
        parsed = json.loads(payload)
    except (ValueError, UnicodeDecodeError):
        raise AuthorityDenied("artifact.binding", "fixed effect payload is malformed") from None
    if (parsed != dict(expected) or authorization.target != target
            or canonical_digest(payload) != authorization.request_digest
            or canonical_digest(payload) != canonical_digest(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode())):
        raise AuthorityDenied("artifact.binding", "fixed effect payload does not match enrolled identity and grant")


def _json_response(value: Mapping[str, Any]) -> Mapping[str, Any]:
    body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return {"status": 200, "body": body,
            "headers": {"content-type": "application/json"},
            "receipt_id": value.get("store_id", f"package:{value.get('package_id')}:{value.get('version')}")}


def _artifact_from_record(item: Any) -> ArtifactSpec:
    if not isinstance(item, dict):
        raise ValueError
    required = {"artifact_id", "version", "sha256", "source_url", "max_bytes", "size_bytes",
                "redirect_hosts", "filename", "tree_files", "archive_format", "archive_root", "max_tree_bytes"}
    if set(item) != required or not isinstance(item["redirect_hosts"], list) or not isinstance(item["tree_files"], list):
        raise ValueError
    tree = []
    for row in item["tree_files"]:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size_bytes", "executable"}:
            raise ValueError
        tree.append(TreeFile(**row))
    return ArtifactSpec(**{**item, "redirect_hosts": tuple(item["redirect_hosts"]), "tree_files": tuple(tree)})


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _package_from_record(item: Any) -> PackageSpec:
    if not isinstance(item, dict) or set(item) != {"package_id", "version", "artifact_id", "artifact_sha256",
                                                    "runtime_id", "python_executable", "environment_root",
                                                    "install_timeout_seconds"}:
        raise ValueError
    return PackageSpec(**item)


def _safe_relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("path is not a normalized relative path")
    return path


def _strip_archive_root(value: str, archive_root: str | None,
                        *, allow_root_directory: bool = False) -> str:
    if archive_root is None:
        return value
    if allow_root_directory and value.rstrip("/") == archive_root.rstrip("/"):
        return ""
    if not value.startswith(archive_root):
        raise AuthorityDenied("artifact.archive", "archive member is outside its enrolled root directory")
    return value[len(archive_root):]


def _safe_leaf(value: str) -> bool:
    return isinstance(value, str) and bool(value) and value not in {".", ".."} and "/" not in value and "\\" not in value and "\x00" not in value


def _validate_id(value: str) -> None:
    if not isinstance(value, str) or value in {".", ".."} or not _ID.fullmatch(value):
        raise ValueError("catalog identity is invalid")


def _valid_version(value: str) -> bool:
    return isinstance(value, str) and value not in {".", ".."} and bool(_VERSION.fullmatch(value))


def _validate_sha(value: str) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("SHA-256 digest is invalid")


def _secure_directory(path: Path, expected_uid: int) -> Path:
    if not path.is_absolute():
        raise AuthorityDenied("artifact.custody", "protected staging path must be absolute")
    try:
        info = path.lstat()
    except OSError:
        raise AuthorityDenied("artifact.custody", "protected staging directory is unavailable") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
        raise AuthorityDenied("artifact.custody", "protected staging directory ownership or mode is unsafe")
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_mode & 0o022:
        # A sticky shared temp parent is accepted only when the owned directory itself is private.
        if not (stat.S_ISDIR(parent.st_mode) and parent.st_mode & stat.S_ISVTX and path.name):
            raise AuthorityDenied("artifact.custody", "protected staging parent can be replaced by another identity")
    return path


def _secure_file(path: Path, expected_uid: int, *, max_bytes: int) -> None:
    try:
        info = path.lstat()
    except OSError:
        raise AuthorityDenied("artifact.custody", "protected catalog file is unavailable") from None
    parent = path.parent.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_size > max_bytes or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != expected_uid or parent.st_mode & 0o022):
        raise AuthorityDenied("artifact.custody", "protected catalog must be installer-owned mode 0600")


def _secure_executable(path: Path, expected_uid: int) -> Path:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        parent = resolved.parent.lstat()
    except OSError:
        raise AuthorityDenied("package.runtime", "enrolled Python runtime is unavailable") from None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022
            or not info.st_mode & 0o111 or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != expected_uid or parent.st_mode & 0o022):
        raise AuthorityDenied("package.runtime", "enrolled Python runtime custody is unsafe")
    return resolved


def _mkdir_chain(path: Path, expected_uid: int) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022:
        raise AuthorityDenied("artifact.custody", "artifact output directory ownership or mode is unsafe")
    os.chmod(path, 0o700)
    return path


def _hash_file(path: Path, max_bytes: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise AuthorityDenied("artifact.type", "artifact is not a regular file")
        while True:
            block = os.read(fd, _CHUNK)
            if not block:
                break
            size += len(block)
            if size > max_bytes:
                raise AuthorityDenied("artifact.size", "artifact exceeds its enrolled byte limit")
            digest.update(block)
    finally:
        os.close(fd)
    return digest.hexdigest(), size


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _freeze_tree(root: Path, expected_uid: int) -> None:
    for current, dirs, files in os.walk(root, followlinks=False):
        directory = Path(current)
        for name in dirs:
            entry = directory / name
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = entry.resolve(strict=True)
                if not target.is_relative_to(root.resolve()) or not target.is_dir():
                    raise AuthorityDenied("package.custody", "isolated runtime contains an unsafe directory link")
                os.chown(entry, expected_uid, -1, follow_symlinks=False)
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise AuthorityDenied("package.custody", "isolated runtime contains a non-directory path")
            os.chown(entry, expected_uid, -1)
            os.chmod(entry, 0o555)
        for name in files:
            entry = directory / name
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = entry.resolve(strict=True)
                if not target.is_relative_to(root.resolve()) or not target.is_file():
                    raise AuthorityDenied("package.custody", "isolated runtime contains an unsafe file link")
                os.chown(entry, expected_uid, -1, follow_symlinks=False)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise AuthorityDenied("package.custody", "isolated runtime contains a special file")
            os.chown(entry, expected_uid, -1)
            os.chmod(entry, 0o555 if info.st_mode & 0o111 else 0o444)
        os.chown(directory, expected_uid, -1)
        os.chmod(directory, 0o555)
        _fsync_dir(directory)


def _network_error(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"artifact request failed with HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            return "artifact TLS verification failed"
        if isinstance(reason, socket.gaierror):
            return "artifact source DNS lookup failed"
        return "artifact source connection failed"
    return "artifact source connection failed"
