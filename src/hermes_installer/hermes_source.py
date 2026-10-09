"""Verified import of the pinned official Hermes source snapshot.

The artifact broker owns the archive bytes and immutable extracted tree.  This
module adds the Git object identity check which a generic archive catalog cannot
provide: GitHub's archive exporter changes line endings in exactly 37 pinned
PowerShell files.  No URL, path or archive bytes are accepted from a profile.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tarfile
import tempfile
import time
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from .artifacts import (
    ArtifactCatalog,
    ResolvedArtifact,
    _fsync_dir,
    _freeze_tree,
    _mkdir_chain,
    _safe_relative,
    _secure_directory,
)
from .authority.types import AuthorityDenied

HERMES_SOURCE_ARTIFACT_ID = "hermes-source-7085fbf7753266fc4943c55ac04926186bc90005"
HERMES_SOURCE_SHA256 = "592ac0b09a7130cf2f8166f039098ba4ed40fb91535c601a6a7e5b1fcf889d01"
HERMES_SOURCE_BYTES = 80_347_460
HERMES_SOURCE_COMMIT = "7085fbf7753266fc4943c55ac04926186bc90005"
HERMES_SOURCE_TREE_SHA1 = "64e4a14da0e2f639a6977f90d6af07d93ea100c3"
HERMES_SOURCE_TREE_MANIFEST_SHA256 = "d2b2b093616021065671c9206b53f4c60bff3a8e4b52c7c2c56f88f6f5572b15"
HERMES_SOURCE_NORMALIZATION_SHA256 = "5dfb4361f1ecf96d355a0ce4192cf4d03eeded09e59ec42f00fddd20ffc799b9"
HERMES_SOURCE_ARCHIVE_ROOT = "hermes-agent-7085fbf7753266fc4943c55ac04926186bc90005"
_NORMALIZATION_RESOURCE = "authority/hermes-source-normalization.json"


@dataclass(frozen=True, slots=True)
class VerifiedHermesSource:
    """Root-resolved source evidence; paths stay inside the trusted service."""

    artifact_id: str
    archive_sha256: str
    archive_size_bytes: int
    commit: str
    git_tree_sha1: str
    archive_tree_manifest_sha256: str
    normalization_manifest_sha256: str
    archive_path: Path
    tree_path: Path


@dataclass(frozen=True, slots=True)
class HermesSourceReceiptHandoff:
    """Opaque setup handle plus root-private verification evidence."""

    receipt_handle: str
    source: VerifiedHermesSource


def materialize_pinned_hermes_source(
    catalog: ArtifactCatalog,
    store_id: str,
    artifact_root: Path | str,
    *,
    expected_uid: int = 0,
    cancelled: Callable[[], bool] | None = None,
    deadline_monotonic: float | None = None,
) -> VerifiedHermesSource:
    """Resolve and prove the one enrolled full Hermes snapshot.

    The only caller-controlled input is the broker store ID.  It is checked
    against the compiled identity and the root-protected catalog before either
    archive bytes or an extracted tree are returned.
    """
    if store_id != f"artifact:{HERMES_SOURCE_ARTIFACT_ID}:{HERMES_SOURCE_SHA256}":
        raise AuthorityDenied("source.binding", "Hermes source store reference is not the pinned snapshot")
    live_cancelled = cancelled or (lambda: False)
    deadline = (min(deadline_monotonic, time.monotonic() + 600.0)
                if deadline_monotonic is not None else time.monotonic() + 600.0)
    _check_source_live(live_cancelled, deadline)
    spec = catalog.artifacts.get(HERMES_SOURCE_ARTIFACT_ID)
    if (spec is None or spec.sha256 != HERMES_SOURCE_SHA256
            or spec.size_bytes != HERMES_SOURCE_BYTES or spec.max_bytes != 100_663_296
            or spec.archive_format != "tar.gz" or spec.archive_root != HERMES_SOURCE_ARCHIVE_ROOT + "/"
            or spec.tree_manifest_sha256 != HERMES_SOURCE_TREE_MANIFEST_SHA256):
        raise AuthorityDenied("source.enrollment", "Hermes source identity is absent from the protected artifact catalog")
    archive = catalog.resolve_store_id(store_id, artifact_root, expected_uid=expected_uid)
    _check_source_live(live_cancelled, deadline)
    normalization = _load_normalization_manifest()
    tree = _materialize_source_tree(archive, catalog, artifact_root, expected_uid,
                                    normalization, live_cancelled, deadline)
    return VerifiedHermesSource(
        artifact_id=HERMES_SOURCE_ARTIFACT_ID,
        archive_sha256=archive.sha256,
        archive_size_bytes=archive.size_bytes,
        commit=HERMES_SOURCE_COMMIT,
        git_tree_sha1=HERMES_SOURCE_TREE_SHA1,
        archive_tree_manifest_sha256=tree.tree_manifest_sha256,
        normalization_manifest_sha256=HERMES_SOURCE_NORMALIZATION_SHA256,
        archive_path=archive.path,
        tree_path=tree.path,
    )


def _materialize_source_tree(archive: ResolvedArtifact, catalog: ArtifactCatalog,
                             artifact_root: Path | str, expected_uid: int,
                             normalization: dict[str, dict[str, Any]],
                             cancelled: Callable[[], bool], deadline: float) -> ResolvedArtifact:
    """Extract, SHA-256 verify, and reconstruct Git tree identities in one tar pass."""
    spec = catalog.artifacts[HERMES_SOURCE_ARTIFACT_ID]
    root = _secure_directory(Path(artifact_root), expected_uid)
    base = _mkdir_chain(root / "trees" / spec.artifact_id / spec.sha256, expected_uid)
    destination = base / "content"
    if destination.exists() or destination.is_symlink():
        _verify_existing_source_tree(destination, spec, expected_uid, cancelled, deadline)
        git_tree = _git_tree_sha1_from_archive(archive.path, spec.tree_files,
                                               spec.archive_root or "", normalization,
                                               cancelled, deadline)
        if git_tree != HERMES_SOURCE_TREE_SHA1:
            raise AuthorityDenied("source.git-tree", "Hermes archive does not reconstruct the pinned upstream Git tree")
        return ResolvedArtifact(spec.artifact_id, spec.version, destination, archive.sha256,
            sum(row.size_bytes for row in spec.tree_files), spec.tree_files,
            spec.archive_format, spec.archive_root, spec.max_tree_bytes)

    expected = {row.path: row for row in spec.tree_files}
    expected_dirs: set[PurePosixPath] = {PurePosixPath(".")}
    for name in expected:
        parent = PurePosixPath(name).parent
        while parent != PurePosixPath("."):
            expected_dirs.add(parent)
            parent = parent.parent
    seen_files: set[str] = set()
    seen_dirs: set[PurePosixPath] = set()
    blob_entries: dict[PurePosixPath, list[tuple[bytes, int, str, str]]] = {}
    directories: set[PurePosixPath] = {PurePosixPath(".")}
    total = 0
    root_name = (spec.archive_root or "").rstrip("/")
    prefix = root_name + "/"
    temporary = Path(tempfile.mkdtemp(prefix=".hermes-source-", dir=base))
    try:
        with tarfile.open(archive.path, mode="r:gz") as source_archive:
            members = source_archive.getmembers()
            _check_source_live(cancelled, deadline)
            if len(members) != 19_191:
                raise ValueError
            for info in members:
                if info.isdir() and info.name.rstrip("/") == root_name:
                    if PurePosixPath(".") in seen_dirs:
                        raise ValueError
                    seen_dirs.add(PurePosixPath("."))
                    continue
                if not info.name.startswith(prefix):
                    raise ValueError
                relative = info.name[len(prefix):]
                if info.isdir():
                    if not relative:
                        raise ValueError
                    directory = _safe_relative(relative.rstrip("/"))
                    if directory in seen_dirs:
                        raise ValueError
                    seen_dirs.add(directory)
                    directories.add(directory)
                    parent = directory.parent
                    while parent != PurePosixPath("."):
                        directories.add(parent)
                        parent = parent.parent
                    continue
                if not info.isfile():
                    raise ValueError
                path = _safe_relative(relative).as_posix()
                row = expected.get(path)
                if (row is None or row.kind != "file" or path in seen_files
                        or row.size_bytes != info.size or info.size > 8 * 1024 * 1024
                        or bool(info.mode & 0o111) != row.executable):
                    raise ValueError
                total += info.size
                if total > 268_435_456:
                    raise ValueError
                stream = source_archive.extractfile(info)
                if stream is None:
                    raise ValueError
                target = temporary.joinpath(*PurePosixPath(path).parts)
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                fd = os.open(target, flags, 0o600)
                sha256 = hashlib.sha256()
                gitsha = hashlib.sha1(b"blob " + str(info.size).encode("ascii") + b"\0")
                buffer = bytearray() if path in normalization else None
                size = 0
                with stream, os.fdopen(fd, "wb") as output:
                    while True:
                        _check_source_live(cancelled, deadline)
                        block = stream.read(128 * 1024)
                        if not block:
                            break
                        size += len(block)
                        if size > info.size:
                            raise ValueError
                        sha256.update(block)
                        gitsha.update(block)
                        if buffer is not None:
                            buffer.extend(block)
                        output.write(block)
                    output.flush()
                    os.fsync(output.fileno())
                if size != info.size or sha256.hexdigest() != row.sha256:
                    raise ValueError
                blob_id = gitsha.hexdigest()
                proof = normalization.get(path)
                if proof is not None:
                    raw = bytes(buffer or b"")
                    normalized = raw.replace(b"\r\n", b"\n")
                    if (len(raw) != proof["archive_size_bytes"]
                            or hashlib.sha256(raw).hexdigest() != proof["archive_sha256"]
                            or blob_id != proof["archive_git_blob_sha1"]
                            or len(normalized) != proof["normalized_size_bytes"]
                            or _git_blob_sha1(normalized) != proof["normalized_git_blob_sha1"]
                            or proof["source_git_blob_sha1"] != proof["normalized_git_blob_sha1"]
                            or proof["source_size_bytes"] != proof["normalized_size_bytes"]):
                        raise ValueError
                    blob_id = proof["normalized_git_blob_sha1"]
                os.chown(target, expected_uid, -1)
                os.chmod(target, 0o555 if row.executable else 0o444)
                parent = PurePosixPath(path).parent
                blob_entries.setdefault(parent, []).append((PurePosixPath(path).name.encode("utf-8"),
                    0o100755 if row.executable else 0o100644, blob_id, "file"))
                while parent != PurePosixPath("."):
                    directories.add(parent)
                    parent = parent.parent
                seen_files.add(path)
        if (seen_files != set(expected) or seen_dirs != expected_dirs
                or set(normalization) != seen_files.intersection(normalization)
                or total != 210_644_925):
            raise ValueError
        if _git_tree_from_entries(blob_entries, directories) != HERMES_SOURCE_TREE_SHA1:
            raise ValueError
        _freeze_tree(temporary, expected_uid)
        os.rename(temporary, destination)
        _fsync_dir(base)
    except (OSError, tarfile.TarError, EOFError, ValueError, KeyError, UnicodeError):
        shutil.rmtree(temporary, ignore_errors=True)
        raise AuthorityDenied("source.tree", "Hermes source archive failed bounded tree import and Git identity checks") from None
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return ResolvedArtifact(spec.artifact_id, spec.version, destination, archive.sha256,
        sum(row.size_bytes for row in spec.tree_files), spec.tree_files,
        spec.archive_format, spec.archive_root, spec.max_tree_bytes)


def _verify_existing_source_tree(destination: Path, spec: Any, expected_uid: int,
                                 cancelled: Callable[[], bool], deadline: float) -> None:
    if destination.is_symlink() or not destination.is_dir():
        raise AuthorityDenied("source.tree-custody", "materialized Hermes source tree path is unsafe")
    observed: dict[str, tuple[str, int, bool]] = {}
    total = 0
    try:
        for path in destination.rglob("*"):
            _check_source_live(cancelled, deadline)
            info = path.lstat()
            relative = path.relative_to(destination).as_posix()
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != expected_uid or info.st_mode & 0o222:
                    raise ValueError
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o222:
                raise ValueError
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            observed[relative] = (digest, info.st_size, bool(info.st_mode & 0o111))
            total += info.st_size
            if total > 268_435_456:
                raise ValueError
        expected = {row.path: (row.sha256, row.size_bytes, row.executable) for row in spec.tree_files}
        if observed != expected or total != 210_644_925:
            raise ValueError
    except (OSError, ValueError):
        raise AuthorityDenied("source.tree-custody", "cached Hermes source tree changed or lost protected custody") from None


def register_pinned_hermes_source_receipt(
    catalog: ArtifactCatalog,
    store_id: str,
    fetch_receipt_id: str,
    artifact_root: Path | str,
    receipt_registry: Any,
    setup_authorization: Any,
    *,
    expected_uid: int = 0,
    cancelled: Callable[[], bool] | None = None,
    deadline_monotonic: float | None = None,
) -> HermesSourceReceiptHandoff:
    """Validate the downloaded snapshot, then mint a setup-bound opaque handle.

    This function is for the root-local setup transaction service only. The
    regular installer worker must receive only ``receipt_handle``; it never
    receives the CAS path or deterministic artifact store ID. ``receipt_registry``
    is the protected ``RootArtifactReceiptRegistry`` adapter and independently
    binds the random handle to the authenticated setup authorization.
    """
    if (not isinstance(fetch_receipt_id, str) or not fetch_receipt_id
            or len(fetch_receipt_id) > 128 or "\x00" in fetch_receipt_id):
        raise AuthorityDenied("source.receipt", "verified Hermes artifact effect receipt is malformed")
    source = materialize_pinned_hermes_source(
        catalog, store_id, artifact_root, expected_uid=expected_uid,
        cancelled=cancelled, deadline_monotonic=deadline_monotonic)
    mint = getattr(receipt_registry, "mint", None)
    if not callable(mint):
        raise AuthorityDenied("source.receipt", "protected setup receipt registry is unavailable")
    try:
        handle = mint(store_id=store_id, receipt_id=fetch_receipt_id,
                      setup_authorization=setup_authorization)
    except Exception:
        raise AuthorityDenied("source.receipt", "protected setup receipt registration failed") from None
    if not isinstance(handle, str) or not 8 <= len(handle) <= 128 or "\x00" in handle:
        raise AuthorityDenied("source.receipt", "protected setup receipt registry returned an invalid handle")
    return HermesSourceReceiptHandoff(handle, source)


def _load_normalization_manifest() -> dict[str, dict[str, Any]]:
    try:
        raw = files("hermes_installer").joinpath(_NORMALIZATION_RESOURCE).read_bytes()
        if hashlib.sha256(raw).hexdigest() != HERMES_SOURCE_NORMALIZATION_SHA256:
            raise ValueError
        rows = json.loads(raw)
        if not isinstance(rows, list) or len(rows) != 37:
            raise ValueError
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {
                    "archive_git_blob_sha1", "archive_sha256", "archive_size_bytes",
                    "normalized_git_blob_sha1", "normalized_size_bytes", "path",
                    "source_git_blob_sha1", "source_size_bytes"}):
                raise ValueError
            path = row["path"]
            if (not isinstance(path, str) or path in result or PurePosixPath(path).is_absolute()
                    or ".." in PurePosixPath(path).parts or "\\" in path):
                raise ValueError
            if (row["source_git_blob_sha1"] != row["normalized_git_blob_sha1"]
                    or row["source_size_bytes"] != row["normalized_size_bytes"]):
                raise ValueError
            for key in ("archive_git_blob_sha1", "normalized_git_blob_sha1", "source_git_blob_sha1"):
                if not isinstance(row[key], str) or len(row[key]) != 40 or any(ch not in "0123456789abcdef" for ch in row[key]):
                    raise ValueError
            for key in ("archive_sha256",):
                if not isinstance(row[key], str) or len(row[key]) != 64 or any(ch not in "0123456789abcdef" for ch in row[key]):
                    raise ValueError
            if any(type(row[key]) is not int or row[key] < 0 for key in
                   ("archive_size_bytes", "normalized_size_bytes", "source_size_bytes")):
                raise ValueError
            result[path] = row
        return result
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        raise AuthorityDenied("source.normalization", "Hermes source normalization proof is unavailable or malformed") from None


def _git_tree_sha1(root: Path, normalization: dict[str, dict[str, Any]]) -> str:
    """Reconstruct Git's recursive tree object after only the pinned CRLF fixes."""
    if root.is_symlink() or not root.is_dir():
        raise AuthorityDenied("source.tree", "Hermes source tree root is unsafe")
    files_by_parent: dict[PurePosixPath, list[tuple[bytes, int, str, str]]] = {}
    directories: set[PurePosixPath] = {PurePosixPath(".")}
    seen_files: set[str] = set()
    try:
        for current, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in tuple(dirnames):
                path = current_path / name
                if path.is_symlink():
                    raise ValueError
                relative = path.relative_to(root).as_posix()
                directories.add(PurePosixPath(relative))
            for name in filenames:
                path = current_path / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError
                relative = path.relative_to(root).as_posix()
                if relative in seen_files:
                    raise ValueError
                seen_files.add(relative)
                raw = path.read_bytes()
                row = normalization.get(relative)
                if row is not None:
                    archive_sha = hashlib.sha256(raw).hexdigest()
                    archive_blob = _git_blob_sha1(raw)
                    normalized = raw.replace(b"\r\n", b"\n")
                    if (archive_sha != row["archive_sha256"] or len(raw) != row["archive_size_bytes"]
                            or archive_blob != row["archive_git_blob_sha1"]
                            or _git_blob_sha1(normalized) != row["normalized_git_blob_sha1"]
                            or len(normalized) != row["normalized_size_bytes"]):
                        raise ValueError
                    raw = normalized
                mode = 0o100755 if info.st_mode & 0o111 else 0o100644
                parent = PurePosixPath(relative).parent
                files_by_parent.setdefault(parent, []).append((name.encode("utf-8"), mode,
                                                                 _git_blob_sha1(raw), "file"))
        if set(normalization) != seen_files.intersection(normalization):
            raise ValueError
        return _git_tree_from_entries(files_by_parent, directories)
    except (OSError, ValueError, KeyError, UnicodeError):
        raise AuthorityDenied("source.git-tree", "Hermes source tree failed exact Git identity verification") from None


def _git_tree_sha1_from_archive(archive_path: Path, tree_files: tuple[Any, ...],
                                archive_root: str,
                                normalization: dict[str, dict[str, Any]],
                                cancelled: Callable[[], bool] | None = None,
                                deadline: float | None = None) -> str:
    """Compute Git objects from the already digest-verified pinned tar stream.

    This avoids a second filesystem walk over nearly 18,000 extracted files on
    lower-power Pi hosts while retaining the same complete byte-level proof.
    """
    expected = {row.path: row for row in tree_files}
    files_by_parent: dict[PurePosixPath, list[tuple[bytes, int, str, str]]] = {}
    directories: set[PurePosixPath] = {PurePosixPath(".")}
    seen_directories: set[PurePosixPath] = set()
    seen: set[str] = set()
    expected_directories: set[PurePosixPath] = {PurePosixPath(".")}
    for path in expected:
        parent = PurePosixPath(path).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent)
            parent = parent.parent
    prefix = archive_root.rstrip("/") + "/"
    live_cancelled = cancelled or (lambda: False)
    bounded_deadline = deadline if deadline is not None else time.monotonic() + 600.0
    try:
        with tarfile.open(archive_path, mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) != 19_191 or len(expected) != 17_973:
                raise ValueError
            for info in members:
                _check_source_live(live_cancelled, bounded_deadline)
                if info.isdir() and info.name.rstrip("/") == archive_root.rstrip("/"):
                    if PurePosixPath(".") in seen_directories:
                        raise ValueError
                    seen_directories.add(PurePosixPath("."))
                    continue
                if not info.name.startswith(prefix):
                    raise ValueError
                relative = info.name[len(prefix):]
                if info.isdir():
                    if relative:
                        directory = _safe_relative(relative.rstrip("/"))
                        if directory in seen_directories:
                            raise ValueError
                        seen_directories.add(directory)
                        directories.add(directory)
                        parent = directory.parent
                        while parent != PurePosixPath("."):
                            directories.add(parent)
                            parent = parent.parent
                    continue
                if not info.isfile():
                    raise ValueError
                path = _safe_relative(relative).as_posix()
                row = expected.get(path)
                if (row is None or path in seen or info.size != row.size_bytes
                        or bool(info.mode & 0o111) != row.executable):
                    raise ValueError
                stream = archive.extractfile(info)
                if stream is None:
                    raise ValueError
                with stream:
                    raw = stream.read(row.size_bytes + 1)
                _check_source_live(live_cancelled, bounded_deadline)
                if len(raw) != row.size_bytes:
                    raise ValueError
                proof = normalization.get(path)
                if proof is not None:
                    if (hashlib.sha256(raw).hexdigest() != proof["archive_sha256"]
                            or _git_blob_sha1(raw) != proof["archive_git_blob_sha1"]
                            or len(raw) != proof["archive_size_bytes"]):
                        raise ValueError
                    normalized = raw.replace(b"\r\n", b"\n")
                    if (len(normalized) != proof["normalized_size_bytes"]
                            or _git_blob_sha1(normalized) != proof["normalized_git_blob_sha1"]
                            or proof["source_git_blob_sha1"] != proof["normalized_git_blob_sha1"]
                            or proof["source_size_bytes"] != proof["normalized_size_bytes"]):
                        raise ValueError
                    raw = normalized
                object_id = _git_blob_sha1(raw)
                mode = 0o100755 if row.executable else 0o100644
                parent = PurePosixPath(path).parent
                files_by_parent.setdefault(parent, []).append((PurePosixPath(path).name.encode("utf-8"),
                    mode, object_id, "file"))
                while parent != PurePosixPath("."):
                    directories.add(parent)
                    parent = parent.parent
                seen.add(path)
        if (seen != set(expected) or set(normalization) != seen.intersection(normalization)
                or seen_directories != expected_directories):
            raise ValueError
        return _git_tree_from_entries(files_by_parent, directories)
    except (OSError, tarfile.TarError, EOFError, ValueError, KeyError, UnicodeError):
        raise AuthorityDenied("source.git-tree", "Hermes archive failed exact upstream Git identity verification") from None


def _git_tree_from_entries(
    files_by_parent: dict[PurePosixPath, list[tuple[bytes, int, str, str]]],
    directories: set[PurePosixPath],
) -> str:
    tree_ids: dict[PurePosixPath, str] = {}
    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        entries = list(files_by_parent.get(directory, ()))
        for child in directories:
            if child == PurePosixPath(".") or child.parent != directory:
                continue
            entries.append((child.name.encode("utf-8"), 0o40000,
                            tree_ids[child], "tree"))
        entries.sort(key=lambda item: item[0] + (b"/" if item[3] == "tree" else b""))
        body = b"".join((f"{mode:o} ".encode("ascii") + name + b"\0" + bytes.fromhex(object_id))
                        for name, mode, object_id, _kind in entries)
        tree_ids[directory] = hashlib.sha1(b"tree " + str(len(body)).encode("ascii") + b"\0" + body).hexdigest()
    return tree_ids[PurePosixPath(".")]


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _check_source_live(cancelled: Callable[[], bool], deadline: float) -> None:
    if cancelled():
        raise AuthorityDenied("source.cancelled", "Hermes source import was cancelled before its receipt was issued")
    if time.monotonic() >= deadline:
        raise AuthorityDenied("source.timeout", "Hermes source import exceeded its bounded setup lease")
