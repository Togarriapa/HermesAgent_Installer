"""Root-owned pinned artifact and offline Python package broker.

Catalog URLs, paths and installation targets come only from a protected catalog.
Profile callers provide an artifact/package identity and digest; they never supply
an URL, filesystem path, command or package-manager option.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import errno
import os
import posixpath
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

PACKAGE_SET_MANIFEST_PATH = Path("/etc/hermes-installer/package-sets.json")
CORAL_PACKAGE_SET_ID = "coral-cp39-runtime-v1"
CORAL_INSTALLER_ARTIFACT_ID = "hermes-installer-artifact-broker-v1"

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
    kind: str = "file"
    link_target: str | None = None

    def __post_init__(self) -> None:
        _safe_relative(self.path)
        _validate_sha(self.sha256)
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("tree file size is invalid")
        if type(self.executable) is not bool:
            raise ValueError("tree file executable flag is invalid")
        if self.kind == "file":
            if self.link_target is not None:
                raise ValueError("regular tree files cannot declare a link target")
        elif self.kind == "symlink":
            if (self.executable or not isinstance(self.link_target, str)
                    or not self.link_target or "\\" in self.link_target or "\x00" in self.link_target
                    or self.link_target.startswith("/")
                    or posixpath.normpath(posixpath.join(posixpath.dirname(self.path), self.link_target)).startswith("../")
                    or posixpath.normpath(posixpath.join(posixpath.dirname(self.path), self.link_target)) == ".."):
                raise ValueError("tree symlink must use a safe in-root relative target")
            target = self.link_target.encode("utf-8")
            if self.size_bytes != len(target) or hashlib.sha256(target).hexdigest() != self.sha256:
                raise ValueError("tree symlink digest and size must bind its exact target")
        else:
            raise ValueError("tree entry kind is unsupported")


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
        if len(paths) > _MAX_FILES:
            raise ValueError("artifact tree exceeds its file-count bound")
        symlink_paths = {item.path for item in self.tree_files if item.kind == "symlink"}
        for item in self.tree_files:
            parent = PurePosixPath(item.path).parent
            while parent != PurePosixPath("."):
                if parent.as_posix() in symlink_paths:
                    raise ValueError("tree entry cannot be nested beneath an enrolled symlink")
                parent = parent.parent
        if self.archive_format not in {None, "zip", "tar.gz", "tar.xz"}:
            raise ValueError("artifact archive format is unsupported")
        if self.archive_root is not None:
            if (self.archive_format not in {"tar.gz", "tar.xz"} or not isinstance(self.archive_root, str)
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
class PackageWheel:
    identity: str
    version: str
    artifact_id: str
    artifact_sha256: str
    artifact_bytes: int
    license: str

    def __post_init__(self) -> None:
        if not isinstance(self.identity, str) or self.identity.count("/") != 1:
            raise ValueError("package wheel identity must be a canonical upstream project identity")
        _validate_id(self.identity.split("/")[-1])
        if not _valid_version(self.version):
            raise ValueError("package wheel version is invalid")
        _validate_id(self.artifact_id)
        _validate_sha(self.artifact_sha256)
        if type(self.artifact_bytes) is not int or self.artifact_bytes < 1:
            raise ValueError("package wheel byte length is invalid")
        if not isinstance(self.license, str) or not 1 <= len(self.license) <= 512 or "\x00" in self.license:
            raise ValueError("package wheel license metadata is invalid")

    @property
    def distribution(self) -> str:
        return _normalize_distribution(self.identity.rsplit("/", 1)[1])


@dataclass(frozen=True, slots=True)
class PackageSetSpec:
    package_set_id: str
    enrollment_id: str
    generation: str
    runtime_artifact_id: str
    runtime_build_attestation_digest: str
    runtime_executable_sha256: str
    abi: str
    target_glibc_min: str
    service_uid: int
    venv_root_id: str
    wheel_entries: tuple[PackageWheel, ...]
    reviewed_installer_artifact_id: str
    policy_revision: str
    manifest_sha256: str
    key_id: str
    signature: str

    def __post_init__(self) -> None:
        for value in (self.package_set_id, self.enrollment_id, self.generation,
                      self.runtime_artifact_id, self.venv_root_id,
                      self.reviewed_installer_artifact_id):
            _validate_id(value)
        for digest in (self.runtime_build_attestation_digest, self.runtime_executable_sha256,
                       self.manifest_sha256):
            _validate_sha(digest)
        if self.abi != "cp39/aarch64" or self.target_glibc_min != "2.34":
            raise ValueError("Coral package set requires CPython 3.9 ARM64 and glibc 2.34")
        if type(self.service_uid) is not int or self.service_uid <= 0:
            raise ValueError("package-set service UID is invalid")
        if not isinstance(self.wheel_entries, tuple) or len(self.wheel_entries) != 2 or any(
                not isinstance(item, PackageWheel) for item in self.wheel_entries):
            raise ValueError("Coral package set must contain its exact two reviewed wheels")
        expected = {
            "tensorflow/tflite-runtime": ("2.14.0", "coral-tflite-runtime-cp39-arm64",
                "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02", 2_325_666),
            "numpy/numpy": ("1.26.4", "coral-numpy-cp39-arm64",
                "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764", 14_226_281),
        }
        actual = {item.identity: (item.version, item.artifact_id, item.artifact_sha256, item.artifact_bytes)
                  for item in self.wheel_entries}
        if actual != expected:
            raise ValueError("Coral package set differs from its exact protected upstream wheel pins")
        if self.runtime_artifact_id != "coral-python39-source":
            raise ValueError("Coral package set must bind the protected CPython 3.9.25 source pin")
        if not isinstance(self.policy_revision, str) or not self.policy_revision or len(self.policy_revision) > 256:
            raise ValueError("package-set policy revision is invalid")
        if not isinstance(self.key_id, str) or not self.key_id or len(self.key_id) > 128:
            raise ValueError("package-set signing key identity is invalid")
        _validate_sha(self.signature)


@dataclass(frozen=True, slots=True)
class PackageSetRuntimeBinding:
    enrollment_id: str
    generation: str
    runtime_artifact_id: str
    runtime_build_attestation_digest: str
    runtime_executable_sha256: str
    abi: str
    glibc_version: str
    service_uid: int
    service_gid: int
    venv_root_id: str
    policy_revision: str
    runtime_executable: Path
    venv_root: Path

    def __post_init__(self) -> None:
        _validate_id(self.enrollment_id)
        _validate_id(self.generation)
        _validate_id(self.runtime_artifact_id)
        _validate_sha(self.runtime_build_attestation_digest)
        _validate_sha(self.runtime_executable_sha256)
        _validate_id(self.venv_root_id)
        if type(self.service_uid) is not int or self.service_uid <= 0 or type(self.service_gid) is not int or self.service_gid < 0:
            raise ValueError("runtime service identity is invalid")
        if not Path(self.runtime_executable).is_absolute() or not Path(self.venv_root).is_absolute():
            raise ValueError("runtime binding paths must be absolute root-resolved paths")


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

    @property
    def tree_manifest_sha256(self) -> str:
        """Hash the exact sorted content-tree contract for copy verification."""
        rows = [{"path": row.path, "sha256": row.sha256,
                 "size_bytes": row.size_bytes, "executable": row.executable}
                for row in sorted(self.tree_files, key=lambda item: item.path)]
        body = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(body).hexdigest()


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
    _secure_file(file_path, expected_uid, max_bytes=16 * 1024 * 1024)
    try:
        raw = file_path.read_bytes()
        if len(raw) > 16 * 1024 * 1024:
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


def package_set_manifest_digest(record: Mapping[str, Any]) -> str:
    """Hash a package-set manifest's canonical unsigned identity fields."""
    claims = {key: value for key, value in record.items()
              if key not in {"manifest_sha256", "key_id", "signature"}}
    body = json.dumps(claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(body).hexdigest()


def sign_package_set_manifest(record: Mapping[str, Any], *, signing_key: bytes,
                              key_id: str) -> dict[str, Any]:
    """Create the exact authority HMAC envelope for root enrollment tooling."""
    if len(signing_key) < 32 or not isinstance(key_id, str) or not key_id:
        raise ValueError("protected package-set signing key is invalid")
    body = dict(record)
    body.pop("manifest_sha256", None)
    body.pop("signature", None)
    body.pop("key_id", None)
    digest = package_set_manifest_digest(body)
    claims = {**body, "manifest_sha256": digest}
    envelope = {"key_id": key_id, **claims}
    encoded = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return {**claims, "key_id": key_id,
            "signature": hmac.new(signing_key, encoded, hashlib.sha256).hexdigest()}


def load_protected_package_sets(path: Path | str = PACKAGE_SET_MANIFEST_PATH, *,
                                catalog: ArtifactCatalog, signing_key: bytes,
                                key_id: str, expected_uid: int = 0) -> Mapping[str, PackageSetSpec]:
    """Load signed, root-protected package-set manifests and bind every wheel to the artifact catalog."""
    package_path = Path(path)
    _secure_file(package_path, expected_uid, max_bytes=1024 * 1024)
    try:
        doc = json.loads(package_path.read_bytes(), object_pairs_hook=_unique_object)
        if (not isinstance(doc, dict) or set(doc) != {"schema", "package_sets"}
                or type(doc["schema"]) is not int or doc["schema"] != 1
                or not isinstance(doc["package_sets"], list) or len(doc["package_sets"]) > 32):
            raise ValueError
        result: dict[str, PackageSetSpec] = {}
        for raw in doc["package_sets"]:
            spec = _package_set_from_record(raw, signing_key=signing_key, key_id=key_id)
            if spec.package_set_id in result:
                raise ValueError
            source = catalog.artifacts.get(spec.runtime_artifact_id)
            if (source is None or source.sha256 !=
                    "00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834"):
                raise ValueError
            for wheel in spec.wheel_entries:
                artifact = catalog.artifacts.get(wheel.artifact_id)
                if (artifact is None or artifact.sha256 != wheel.artifact_sha256
                        or artifact.size_bytes != wheel.artifact_bytes or artifact.archive_format is not None
                        or artifact.filename != _expected_wheel_filename(wheel)):
                    raise ValueError
            result[spec.package_set_id] = spec
        return MappingProxyType(result)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise AuthorityDenied("package-set.catalog", "protected package-set manifest is invalid") from None


def _package_set_from_record(raw: Any, *, signing_key: bytes, key_id: str) -> PackageSetSpec:
    required = {"schema", "package_set_id", "enrollment_id", "generation", "runtime_artifact_id",
                "runtime_build_attestation_digest", "runtime_executable_sha256", "abi", "target_glibc_min",
                "service_uid", "venv_root_id", "wheel_entries", "reviewed_installer_artifact_id",
                "policy_revision", "manifest_sha256", "key_id", "signature"}
    if (not isinstance(raw, dict) or set(raw) != required or type(raw["schema"]) is not int
            or raw["schema"] != 1 or raw["key_id"] != key_id):
        raise ValueError
    if not isinstance(raw["wheel_entries"], list) or len(raw["wheel_entries"]) != 2:
        raise ValueError
    wheel_rows = []
    for row in raw["wheel_entries"]:
        if not isinstance(row, dict) or set(row) != {
                "identity", "version", "artifact_id", "artifact_sha256", "artifact_bytes", "license"}:
            raise ValueError
        wheel_rows.append(PackageWheel(**row))
    claims = {key: value for key, value in raw.items()
              if key not in {"manifest_sha256", "key_id", "signature"}}
    digest = hashlib.sha256(json.dumps(
        claims, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
    if digest != raw["manifest_sha256"]:
        raise ValueError
    signed = {"key_id": key_id, **claims, "manifest_sha256": digest}
    expected_signature = hmac.new(
        signing_key, json.dumps(signed, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True).encode("ascii"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_signature, raw["signature"]):
        raise ValueError
    values = dict(claims)
    values.pop("schema")
    values.update(manifest_sha256=digest, key_id=key_id, signature=raw["signature"],
                  wheel_entries=tuple(wheel_rows))
    spec = PackageSetSpec(**values)
    if spec.reviewed_installer_artifact_id != CORAL_INSTALLER_ARTIFACT_ID:
        raise ValueError
    return spec


def _expected_wheel_filename(wheel: PackageWheel) -> str:
    if wheel.identity == "tensorflow/tflite-runtime":
        return "tflite_runtime-2.14.0-cp39-cp39-manylinux_2_34_aarch64.whl"
    if wheel.identity == "numpy/numpy":
        return "numpy-1.26.4-cp39-cp39-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"
    raise ValueError("package wheel is not a member of the fixed Coral set")


def build_package_set_handlers(catalog: ArtifactCatalog, staging_root: Path | str,
                               package_sets: Mapping[str, PackageSetSpec], *,
                               runtime_resolver: Callable[[PackageSetSpec], PackageSetRuntimeBinding],
                               expected_uid: int = 0, authorization_check: Callable[..., Any] | None = None
                               ) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
    """Build root-only fixed handlers for signed offline package sets."""
    root = _secure_directory(Path(staging_root), expected_uid)
    if not hasattr(os, "geteuid") or os.geteuid() != expected_uid:
        raise AuthorityDenied("package-set.identity", "package-set handler must run as its enrolled authority identity")
    handlers: dict[tuple[str, str], Callable[..., Mapping[str, Any]]] = {}
    for package_set_id, spec in package_sets.items():
        if package_set_id != spec.package_set_id:
            raise ValueError("package-set mapping key differs from its protected ID")
        target = f"package-set:{spec.package_set_id}:{spec.manifest_sha256}"

        def install_handler(*, context: HostContext, authorization: EffectAuthorization,
                            payload: bytes, timeout: float, peer_pid: int,
                            cancelled: Callable[[], bool], peer_pidfd: int | None = None,
                            _spec: PackageSetSpec = spec) -> Mapping[str, Any]:
            del peer_pid, peer_pidfd
            expected = {"schema": 1, "package_set_id": _spec.package_set_id,
                        "enrollment_id": _spec.enrollment_id, "generation": _spec.generation}
            effect_target = f"package-set:{_spec.package_set_id}:{_spec.manifest_sha256}"
            _check_grant_payload(authorization, payload, expected, effect_target)
            _revalidate_effect(context, authorization, "package.install", authorization_check, cancelled)
            runtime = runtime_resolver(_spec)
            _validate_package_set_runtime(_spec, runtime, expected_uid)
            wheels = tuple(catalog.resolve(item.artifact_id, item.artifact_sha256,
                                            root, expected_uid=expected_uid)
                           for item in _spec.wheel_entries)
            _validate_coral_wheels(_spec, wheels)
            _revalidate_effect(context, authorization, "package.install", authorization_check, cancelled)
            deadline = min(float(timeout), 600.0,
                           authorization.monotonic_expires_at - time.monotonic(),
                           context.monotonic_expires_at - time.monotonic())
            if deadline <= 0:
                raise AuthorityDenied("grant.stale", "package-set effect lease expired before install")
            effect_deadline = min(authorization.monotonic_expires_at,
                                  context.monotonic_expires_at,
                                  time.monotonic() + deadline)
            destination, tree_digest = _install_coral_package_set(
                _spec, runtime, wheels, expected_uid, deadline, effect_deadline, cancelled,
                before_process=lambda: _revalidate_effect(
                    context, authorization, "package.install", authorization_check, cancelled),
                before_activation=lambda: _revalidate_effect(
                    context, authorization, "package.install", authorization_check, cancelled))
            return _json_response({"package_set_id": _spec.package_set_id,
                                   "manifest_sha256": _spec.manifest_sha256,
                                   "enrollment_id": _spec.enrollment_id,
                                   "generation": _spec.generation,
                                   "runtime_build_attestation_digest": _spec.runtime_build_attestation_digest,
                                   "wheel_sha256": [wheel.artifact_sha256 for wheel in _spec.wheel_entries],
                                   "installed_tree_sha256": tree_digest,
                                   "status": "installed"})

        handlers[("package.install", target)] = install_handler
    return MappingProxyType(handlers)


def _validate_package_set_runtime(spec: PackageSetSpec, runtime: PackageSetRuntimeBinding,
                                  expected_uid: int) -> None:
    if not isinstance(runtime, PackageSetRuntimeBinding):
        raise AuthorityDenied("package-set.runtime", "root runtime resolver returned an invalid enrollment")
    if (runtime.enrollment_id != spec.enrollment_id or runtime.generation != spec.generation
            or runtime.runtime_artifact_id != spec.runtime_artifact_id
            or runtime.runtime_build_attestation_digest != spec.runtime_build_attestation_digest
            or runtime.runtime_executable_sha256 != spec.runtime_executable_sha256
            or runtime.abi != spec.abi or runtime.service_uid != spec.service_uid
            or runtime.venv_root_id != spec.venv_root_id
            or runtime.policy_revision != spec.policy_revision):
        raise AuthorityDenied("package-set.runtime", "runtime attestation does not match protected package-set enrollment")
    if _version_tuple(runtime.glibc_version) < _version_tuple(spec.target_glibc_min):
        raise AuthorityDenied("package-set.glibc", "runtime glibc is below the reviewed wheel minimum")
    python = _secure_executable(Path(runtime.runtime_executable), runtime.service_uid)
    if _hash_file(python, 256 * 1024 * 1024)[0] != spec.runtime_executable_sha256:
        raise AuthorityDenied("package-set.runtime", "runtime executable differs from its protected attestation")
    _secure_directory(Path(runtime.venv_root), runtime.service_uid)
    if expected_uid != 0:
        raise AuthorityDenied("package-set.identity", "package-set effects require root authority")


def _validate_coral_wheels(spec: PackageSetSpec,
                           artifacts: tuple[ResolvedArtifact, ...]) -> None:
    if len(artifacts) != 2 or len(spec.wheel_entries) != 2:
        raise AuthorityDenied("package-set.wheels", "Coral package set must resolve exactly two pinned wheels")
    by_id = {item.artifact_id: item for item in artifacts}
    for wheel in spec.wheel_entries:
        artifact = by_id.get(wheel.artifact_id)
        if (artifact is None or artifact.sha256 != wheel.artifact_sha256
                or artifact.size_bytes != wheel.artifact_bytes
                or artifact.path.name != _expected_wheel_filename(wheel)):
            raise AuthorityDenied("package-set.wheels", "wheel artifact differs from its protected package-set pin")
        _validate_wheel_metadata(artifact.path, wheel)


def _validate_wheel_metadata(path: Path, wheel: PackageWheel) -> None:
    from email.parser import BytesParser
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if not members or len(members) > 50_000:
                raise ValueError
            names: set[str] = set()
            total = 0
            metadata: bytes | None = None
            wheel_metadata: bytes | None = None
            for item in members:
                name = item.filename.rstrip("/")
                if item.is_dir():
                    if name:
                        _safe_relative(name)
                    continue
                pure = _safe_relative(name)
                if name in names:
                    raise ValueError
                names.add(name)
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                    raise ValueError
                total += item.file_size
                if item.file_size < 0 or total > 1024 * 1024 * 1024:
                    raise ValueError
                if name.endswith(".dist-info/METADATA"):
                    if item.file_size > 64 * 1024:
                        raise ValueError
                    metadata = archive.read(item)
                elif name.endswith(".dist-info/WHEEL"):
                    if item.file_size > 16 * 1024:
                        raise ValueError
                    wheel_metadata = archive.read(item)
            if metadata is None or wheel_metadata is None:
                raise ValueError
        parsed = BytesParser().parsebytes(metadata)
        if (_normalize_distribution(parsed.get("Name", "")) != wheel.distribution
                or parsed.get("Version") != wheel.version):
            raise ValueError
        text = wheel_metadata.decode("utf-8")
        required_tag = ("cp39-cp39-manylinux_2_34_aarch64"
                        if wheel.identity == "tensorflow/tflite-runtime"
                        else "cp39-cp39-manylinux_2_17_aarch64")
        if f"Tag: {required_tag}" not in text:
            raise ValueError
    except (OSError, ValueError, UnicodeError, zipfile.BadZipFile, RuntimeError):
        raise AuthorityDenied("package-set.wheel-metadata", "pinned wheel metadata or archive structure is invalid") from None


def _install_coral_package_set(spec: Any, runtime: PackageSetRuntimeBinding,
                               wheels: tuple[ResolvedArtifact, ...], expected_uid: int,
                               timeout: float, effect_deadline: float,
                               cancelled: Callable[[], bool], *,
                               before_process: Callable[[], None],
                               before_activation: Callable[[], None]) -> tuple[Path, str]:
    owner = runtime.service_uid
    base = _secure_directory(Path(runtime.venv_root), owner)
    destination_parent = _mkdir_chain(base / spec.package_set_id, owner)
    destination = destination_parent / spec.manifest_sha256
    if destination.exists() or destination.is_symlink():
        digest = _verify_installed_package_set(destination, spec, runtime)
        before_activation()
        return destination, digest
    work = Path(tempfile.mkdtemp(prefix=".package-set-", dir=destination_parent))
    os.chown(work, owner, runtime.service_gid)
    os.chmod(work, 0o700)
    try:
        wheelhouse = work / "wheelhouse"
        wheelhouse.mkdir(mode=0o700)
        os.chown(wheelhouse, owner, runtime.service_gid)
        resolved = {item.artifact_id: item for item in wheels}
        requirements: list[str] = []
        for wheel in sorted(spec.wheel_entries, key=lambda item: item.distribution):
            if cancelled():
                raise AuthorityDenied("package.cancelled", "package-set install cancelled while staging wheels")
            artifact = resolved.get(wheel.artifact_id)
            if artifact is None:
                raise AuthorityDenied("package-set.wheels", "protected wheel artifact is missing")
            _copy_verified_wheel(artifact, wheel, wheelhouse / _expected_wheel_filename(wheel),
                                 owner, runtime.service_gid, cancelled)
            requirements.append(f"{wheel.distribution}=={wheel.version} --hash=sha256:{wheel.artifact_sha256}")
        manifest = work / "requirements.txt"
        manifest.write_text("\n".join(requirements) + "\n", encoding="ascii")
        os.chown(manifest, owner, runtime.service_gid)
        os.chmod(manifest, 0o444)
        temporary_env = work / "venv"
        python = _secure_executable(Path(runtime.runtime_executable), owner)
        safe_env = {"PATH": "/usr/bin:/bin", "HOME": str(work), "PIP_CONFIG_FILE": os.devnull,
                    "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                    "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"}
        _run_fixed([str(python), "-m", "venv", "--copies", str(temporary_env)],
                   cwd=work, timeout=timeout, cancelled=cancelled, expected_uid=expected_uid,
                   env=safe_env, before_exec=before_process,
                   run_as_uid=owner, run_as_gid=runtime.service_gid, deadline=effect_deadline,
                   network_isolated=True)
        env_python = temporary_env / "bin" / "python"
        _secure_executable(env_python, owner)
        _run_fixed([str(env_python.resolve(strict=True)), "-I", "-m", "pip", "install",
                    "--no-index", "--find-links", str(wheelhouse), "--require-hashes",
                    "--no-deps", "--only-binary=:all:", "--no-input", "--no-cache-dir",
                    "--disable-pip-version-check", "-r", str(manifest)],
                   cwd=work, timeout=timeout, cancelled=cancelled, expected_uid=expected_uid,
                   env=safe_env, before_exec=before_process,
                   run_as_uid=owner, run_as_gid=runtime.service_gid, deadline=effect_deadline,
                   network_isolated=True)
        validation = (
            "import importlib.metadata as m; import numpy; import tflite_runtime.interpreter; "
            "assert m.version('numpy') == '1.26.4'; "
            "assert m.version('tflite-runtime') == '2.14.0'"
        )
        _run_fixed([str(env_python.resolve(strict=True)), "-I", "-c", validation],
                   cwd=work, timeout=min(timeout, 30), cancelled=cancelled, expected_uid=expected_uid,
                   env=safe_env, before_exec=before_process,
                   run_as_uid=owner, run_as_gid=runtime.service_gid, deadline=effect_deadline,
                   network_isolated=True)
        tree_digest = _package_tree_digest(temporary_env)
        marker = temporary_env / ".hermes-package-set.json"
        marker.write_text(json.dumps({
            "package_set_id": spec.package_set_id, "manifest_sha256": spec.manifest_sha256,
            "runtime_build_attestation_digest": spec.runtime_build_attestation_digest,
            "runtime_executable_sha256": spec.runtime_executable_sha256,
            "wheel_sha256": [item.artifact_sha256 for item in spec.wheel_entries],
            "installed_tree_sha256": tree_digest,
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
        os.chown(marker, owner, runtime.service_gid)
        os.chmod(marker, 0o444)
        _freeze_tree(temporary_env, owner)
        if cancelled():
            raise AuthorityDenied("package.cancelled", "package-set install cancelled before activation")
        before_activation()
        os.rename(temporary_env, destination)
        _fsync_dir(destination_parent)
        installed_digest = _verify_installed_package_set(destination, spec, runtime)
        return destination, installed_digest
    except OSError as exc:
        if exc.errno == errno.ENOSPC:
            raise AuthorityDenied("package.storage", "isolated package-set staging ran out of space; retry after freeing owned storage") from None
        raise AuthorityDenied("package.storage", "isolated package-set staging failed safely") from None
    finally:
        _remove_private_tree(work)


def _copy_verified_wheel(artifact: ResolvedArtifact, wheel: PackageWheel, destination: Path,
                         owner: int, group: int, cancelled: Callable[[], bool]) -> None:
    source_fd = os.open(artifact.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    target_fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        getattr(os, "O_NOFOLLOW", 0), 0o600)
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(source_fd, "rb") as src, os.fdopen(target_fd, "wb") as out:
            while True:
                if cancelled():
                    raise AuthorityDenied("package.cancelled", "package-set install cancelled while copying wheels")
                block = src.read(_CHUNK)
                if not block:
                    break
                size += len(block)
                if size > wheel.artifact_bytes:
                    raise AuthorityDenied("package.wheel-size", "pinned wheel exceeded its enrolled byte length")
                digest.update(block)
                out.write(block)
            out.flush()
            os.fsync(out.fileno())
        if size != wheel.artifact_bytes or digest.hexdigest() != wheel.artifact_sha256:
            raise AuthorityDenied("package.wheel-digest", "staged wheel failed its catalog digest check")
        os.chown(destination, owner, group)
        os.chmod(destination, 0o444)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise


def _package_tree_digest(root: Path) -> str:
    observed = _observed_tree(root, 4 * 1024**3)
    rows = [{"path": path, "sha256": values[0], "size_bytes": values[1],
             "kind": values[2], "link_target": values[3], "executable": values[4]}
            for path, values in sorted(observed.items()) if path != ".hermes-package-set.json"]
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _verify_installed_package_set(destination: Path, spec: Any,
                                  runtime: PackageSetRuntimeBinding) -> str:
    _secure_directory(destination, runtime.service_uid)
    marker = destination / ".hermes-package-set.json"
    try:
        info = marker.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != runtime.service_uid
                or info.st_mode & 0o222 or info.st_size > 4096):
            raise ValueError
        receipt = json.loads(marker.read_text("utf-8"))
        digest = _package_tree_digest(destination)
        expected = {"package_set_id": spec.package_set_id, "manifest_sha256": spec.manifest_sha256,
                    "runtime_build_attestation_digest": spec.runtime_build_attestation_digest,
                    "runtime_executable_sha256": spec.runtime_executable_sha256,
                    "wheel_sha256": [item.artifact_sha256 for item in spec.wheel_entries],
                    "installed_tree_sha256": digest}
        if receipt != expected:
            raise ValueError
        return digest
    except (OSError, ValueError, json.JSONDecodeError):
        raise AuthorityDenied("package-set.conflict", "versioned component runtime is occupied or changed") from None


def _version_tuple(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", value):
        raise AuthorityDenied("package-set.runtime", "runtime ABI version is malformed")
    return tuple(int(part) for part in value.split("."))


def _normalize_distribution(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).casefold()


def build_artifact_handlers(catalog: ArtifactCatalog, staging_root: Path | str,
                            *, expected_uid: int = 0, opener: Callable[..., Any] | None = None,
                            authorization_check: Callable[..., Any] | None = None
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
                          payload: bytes, timeout: float, peer_pid: int, peer_pidfd: int | None = None,
                          cancelled: Callable[[], bool], _spec: ArtifactSpec = spec) -> Mapping[str, Any]:
            del peer_pid, peer_pidfd
            expected = {"schema": 1, "artifact_id": _spec.artifact_id,
                        "sha256": _spec.sha256, "max_bytes": _spec.max_bytes}
            _check_grant_payload(authorization, payload, expected, f"artifact:{_spec.artifact_id}:{_spec.sha256}")
            _revalidate_effect(context, authorization, "artifact.fetch", authorization_check, cancelled)
            effect_timeout = min(float(timeout),
                                 authorization.monotonic_expires_at - time.monotonic(),
                                 context.monotonic_expires_at - time.monotonic())
            resolved = _fetch_artifact(
                _spec, root, expected_uid, fetcher, effect_timeout, cancelled,
                before_connect=lambda: _revalidate_effect(
                    context, authorization, "artifact.fetch", authorization_check,
                    cancelled),
            )
            receipt = {"artifact_id": resolved.artifact_id, "version": resolved.version,
                       "sha256": resolved.sha256, "size_bytes": resolved.size_bytes,
                       "store_id": f"artifact:{resolved.artifact_id}:{resolved.sha256}"}
            return _json_response(receipt)

        handlers[("artifact.fetch", target)] = fetch_handler

    for package in catalog.packages.values():
        target = f"package:{package.package_id}:{package.version}:{package.artifact_sha256}"

        def install_handler(*, context: HostContext, authorization: EffectAuthorization,
                            payload: bytes, timeout: float, peer_pid: int, peer_pidfd: int | None = None,
                            cancelled: Callable[[], bool], _package: PackageSpec = package) -> Mapping[str, Any]:
            del peer_pid, peer_pidfd
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
            _revalidate_effect(context, authorization, "package.install",
                               authorization_check, cancelled)
            installed = _install_wheelhouse(_package, artifact, expected_uid,
                                             min(timeout, _package.install_timeout_seconds), cancelled,
                                             before_process=lambda: _revalidate_effect(
                                                 context, authorization, "package.install",
                                                 authorization_check, cancelled))
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
                    cancelled: Callable[[], bool],
                    before_connect: Callable[[], None]) -> ResolvedArtifact:
    final = root / "objects" / spec.artifact_id / spec.sha256 / spec.filename
    if final.exists():
        # A cached receipt is still a protected effect: policy and the lease may
        # have changed since dispatch, even though no network connection is needed.
        if cancelled():
            raise AuthorityDenied("artifact.cancelled", "artifact fetch was cancelled before cached receipt")
        before_connect()
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
            if cancelled():
                raise AuthorityDenied("artifact.cancelled", "artifact fetch was cancelled before cached receipt")
            before_connect()
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
    before_connect()
    remaining_timeout = min(timeout, deadline - time.monotonic())
    if remaining_timeout <= 0:
        raise AuthorityDenied("artifact.timeout", "artifact fetch lease expired before network access")
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
                        cancelled: Callable[[], bool],
                        before_process: Callable[[], None]) -> Path:
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
                   timeout=timeout, cancelled=cancelled, expected_uid=expected_uid,
                   before_exec=before_process)
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
                   timeout=timeout, cancelled=cancelled, expected_uid=expected_uid, env=env,
                   before_exec=before_process)
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
    expected = {entry.path: _tree_signature(entry) for entry in artifact.tree_files}
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
        expected = {entry.path: _tree_signature(entry) for entry in spec.tree_files}
        if observed != expected:
            raise AuthorityDenied("artifact.tree-digest", "materialized content tree no longer matches its protected catalog")
        return destination
    temp = Path(tempfile.mkdtemp(prefix=".tree-", dir=base))
    try:
        _extract_archive(archive_path, spec.archive_format, spec.archive_root, spec.tree_files,
                         spec.max_tree_bytes, temp, expected_uid)
        observed = _observed_tree(temp, spec.max_tree_bytes)
        expected = {entry.path: _tree_signature(entry) for entry in spec.tree_files}
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
                    if info.file_size < 0:
                        raise AuthorityDenied("artifact.archive", "archive contains an invalid member")
                    pure = _safe_relative(name)
                    entry = enrolled.get(pure.as_posix())
                    if entry is None or entry.size_bytes != info.file_size:
                        raise AuthorityDenied("artifact.tree-digest", "archive member is absent from the protected content tree")
                    if stat.S_ISLNK(mode):
                        if entry.kind != "symlink":
                            raise AuthorityDenied("artifact.tree-digest", "archive link type differs from its protected content tree")
                        raw_target = archive.read(info)
                        try:
                            target = raw_target.decode("utf-8")
                        except UnicodeDecodeError:
                            raise AuthorityDenied("artifact.archive", "archive symlink target is not UTF-8") from None
                        if target != entry.link_target:
                            raise AuthorityDenied("artifact.tree-digest", "archive symlink target differs from its protected content tree")
                        _write_tree_symlink(destination, pure, target, expected_uid)
                        count += 1
                        total += entry.size_bytes
                        if total > max_tree_bytes:
                            raise AuthorityDenied("artifact.archive", "archive exceeds its expanded-size bound")
                        continue
                    if stat.S_IFMT(mode) not in {0, stat.S_IFREG}:
                        raise AuthorityDenied("artifact.archive", "archive contains a special member")
                    if entry.kind != "file":
                        raise AuthorityDenied("artifact.tree-digest", "archive regular-file type differs from its protected content tree")
                    count += 1
                    total += info.file_size
                    if total > max_tree_bytes or (info.compress_size == 0 and info.file_size > 0):
                        raise AuthorityDenied("artifact.archive", "archive exceeds its expanded-size bound")
                    with archive.open(info) as source:
                        _write_tree_file(source, destination, pure, info.file_size,
                                         expected_uid, entry.executable)
        elif archive_format in {"tar.gz", "tar.xz"}:
            mode = "r:gz" if archive_format == "tar.gz" else "r:xz"
            with tarfile.open(archive_path, mode=mode) as archive:
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
                    if info.size < 0:
                        raise AuthorityDenied("artifact.archive", "archive contains a link or special member")
                    pure = _safe_relative(name)
                    entry = enrolled.get(pure.as_posix())
                    member_size = len(info.linkname.encode("utf-8")) if info.issym() else info.size
                    if entry is None or entry.size_bytes != member_size:
                        raise AuthorityDenied("artifact.tree-digest", "archive member is absent from the protected content tree")
                    if info.issym():
                        if entry.kind != "symlink" or entry.link_target != info.linkname:
                            raise AuthorityDenied("artifact.tree-digest", "archive symlink differs from its protected content tree")
                        _write_tree_symlink(destination, pure, info.linkname, expected_uid)
                        count += 1
                        total += entry.size_bytes
                        if total > max_tree_bytes:
                            raise AuthorityDenied("artifact.archive", "archive exceeds its expanded-size bound")
                        continue
                    if not info.isfile() or entry.kind != "file":
                        raise AuthorityDenied("artifact.archive", "archive contains a link or special member")
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


def _write_tree_symlink(destination: Path, relative: PurePosixPath,
                        target_text: str, expected_uid: int) -> None:
    # TreeFile validates lexical containment. Resolve the target after publication
    # too, so links to absent targets/cycles cannot enter a materialized tree.
    target = destination.joinpath(*relative.parts)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.symlink(target_text, target)
    os.chown(target, expected_uid, -1, follow_symlinks=False)


def _observed_tree(root: Path, max_bytes: int) -> dict[str, tuple[str, int, str, str | None, bool]]:
    observed: dict[str, tuple[str, int, str, str | None, bool]] = {}
    total = 0
    root_real = root.resolve(strict=True)
    for path in root.rglob("*"):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if stat.S_ISLNK(info.st_mode):
            target_text = os.readlink(path)
            try:
                resolved_target = path.resolve(strict=True)
            except (OSError, RuntimeError):
                raise AuthorityDenied("artifact.tree-custody", "materialized symlink target is missing or cyclic") from None
            if not resolved_target.is_relative_to(root_real):
                raise AuthorityDenied("artifact.tree-custody", "materialized symlink escapes its protected tree")
            raw_target = target_text.encode("utf-8")
            digest, size = hashlib.sha256(raw_target).hexdigest(), len(raw_target)
            kind = "symlink"
            executable = False
        elif stat.S_ISREG(info.st_mode):
            digest, size = _hash_file(path, max_bytes)
            kind = "file"
            target_text = None
            executable = bool(info.st_mode & 0o111)
        else:
            raise AuthorityDenied("artifact.tree-custody", "materialized tree contains a link or special file")
        relative = path.relative_to(root).as_posix()
        total += size
        if total > max_bytes:
            raise AuthorityDenied("artifact.tree-size", "materialized tree exceeds its enrolled size bound")
        observed[relative] = (digest, size, kind, target_text, executable)
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
               env: Mapping[str, str] | None = None,
               before_exec: Callable[[], None] | None = None,
               run_as_uid: int | None = None, run_as_gid: int | None = None,
               deadline: float | None = None, network_isolated: bool = False) -> None:
    if not argv or any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
        raise AuthorityDenied("package.argv", "fixed package command is malformed")
    # The only commands built by this module are an enrolled interpreter and its venv/pip verbs.
    if not Path(argv[0]).is_absolute():
        raise AuthorityDenied("package.argv", "package interpreter path is not canonical")
    if network_isolated:
        if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
            raise AuthorityDenied("package.network-isolation", "offline package effects require root network-namespace custody")
        unshare = next((Path(candidate) for candidate in ("/usr/bin/unshare", "/bin/unshare")
                        if Path(candidate).exists()), None)
        if unshare is None:
            raise AuthorityDenied("package.network-isolation", "required Linux network namespace utility is unavailable")
        _secure_executable(unshare, 0)
        argv = [str(unshare), "--net", "--", *argv]
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise AuthorityDenied("package.timeout", "fixed package operation has no live time budget")
    command_deadline = min(time.monotonic() + timeout, deadline if deadline is not None else float("inf"))
    if cancelled():
        raise AuthorityDenied("package.cancelled", "package operation was cancelled before process start")
    if before_exec is not None:
        before_exec()
    remaining = command_deadline - time.monotonic()
    if remaining <= 0:
        raise AuthorityDenied("grant.stale", "fixed package operation lease expired before process start")
    identity: dict[str, Any] = {}
    if run_as_uid is not None:
        if type(run_as_uid) is not int or run_as_uid < 1 or type(run_as_gid) is not int or run_as_gid < 0:
            raise AuthorityDenied("package.identity", "package subprocess identity is invalid")
        if not hasattr(os, "geteuid") or os.geteuid() != expected_uid or expected_uid != 0:
            if run_as_uid != os.getuid() or run_as_gid != os.getgid():
                raise AuthorityDenied("package.identity", "privilege drop requires the root installer identity")
        identity = {"user": run_as_uid, "group": run_as_gid, "extra_groups": ()}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=dict(env) if env is not None else {
            "PATH": "/usr/bin:/bin", "HOME": str(cwd), "PYTHONNOUSERSITE": "1", "PYTHONUTF8": "1"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            close_fds=True, start_new_session=True, bufsize=0, **identity)
    except OSError:
        raise AuthorityDenied("package.runtime", "enrolled runtime could not start the fixed package operation") from None
    output = bytearray()
    if process.stdout is not None:
        os.set_blocking(process.stdout.fileno(), False)
    try:
        while process.poll() is None:
            if cancelled():
                raise AuthorityDenied("package.cancelled", "package installation was cancelled")
            if time.monotonic() >= command_deadline:
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


def _check_effect_live(context: HostContext, authorization: EffectAuthorization,
                       cancelled: Callable[[], bool]) -> None:
    if cancelled():
        raise AuthorityDenied("effect.cancelled", "fixed effect was cancelled before its side effect")
    now = time.monotonic()
    if (authorization.monotonic_expires_at <= now
            or context.monotonic_expires_at <= now
            or authorization.policy_revision != context.policy_revision
            or authorization.principal_id != context.principal_id
            or authorization.profile_id != context.profile_id
            or authorization.namespace_id != context.namespace_id
            or authorization.uid != context.uid):
        raise AuthorityDenied("grant.stale", "host effect authorization is stale before the side effect")


def _revalidate_effect(context: HostContext, authorization: EffectAuthorization,
                       operation: str, authorization_check: Callable[..., Any] | None,
                       cancelled: Callable[[], bool]) -> None:
    _check_effect_live(context, authorization, cancelled)
    if authorization_check is not None:
        result = authorization_check(
            context, authorization, operation=operation,
            request_digest=authorization.request_digest,
            retry_index=authorization.retry_index,
        )
        if result is False:
            raise AuthorityDenied("grant.stale", "host policy generation changed before the side effect")
    _check_effect_live(context, authorization, cancelled)


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
        if not isinstance(row, dict) or set(row) not in ({"path", "sha256", "size_bytes", "executable"},
                                                      {"path", "sha256", "size_bytes", "executable", "kind", "link_target"}):
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


def _tree_signature(entry: TreeFile) -> tuple[str, int, str, str | None, bool]:
    return entry.sha256, entry.size_bytes, entry.kind, entry.link_target, entry.executable


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
