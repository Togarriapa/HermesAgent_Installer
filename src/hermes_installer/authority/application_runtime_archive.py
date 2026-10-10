"""Strict deterministic archive format for pre-active application environments.

The archive is transport only. A runtime is usable only after root verifies the
entire member manifest, extracts it through no-follow directory descriptors,
reopens the resulting tree, and binds it to an independent installed-runtime
probe. Interpreter aliases are deliberately excluded: the caller must bind the
exact alias to a separately held PM runtime receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable, Mapping


MAX_ARCHIVE_BYTES = 2 * 1024**3
MAX_EXPANDED_BYTES = 2 * 1024**3
MAX_MEMBERS = 131_072
MANIFEST_NAME = "HERMES-RUNTIME-MANIFEST.json"
PYTHON_RUNTIME_ALIASES = frozenset({"bin/python", "bin/python3", "bin/python3.14"})
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class RuntimeArchiveError(ValueError):
    """An environment archive violates the fixed canonical member contract."""


@dataclass(frozen=True, slots=True)
class RuntimeArchiveMember:
    path: str
    kind: str
    mode: int
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _path(self.path)
        if self.kind not in {"file", "directory"}:
            raise RuntimeArchiveError("runtime manifest member kind is unsupported")
        if type(self.mode) is not int or self.mode not in {0o644, 0o755}:
            raise RuntimeArchiveError("runtime manifest member mode is not canonical")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise RuntimeArchiveError("runtime manifest member size is invalid")
        if not isinstance(self.sha256, str) or not _SHA.fullmatch(self.sha256):
            raise RuntimeArchiveError("runtime manifest member digest is malformed")
        if self.kind == "directory" and (self.size_bytes != 0 or self.mode != 0o755
                                          or self.sha256 != hashlib.sha256(b"").hexdigest()):
            raise RuntimeArchiveError("runtime manifest directory facts are not canonical")

    def as_wire(self) -> dict[str, object]:
        return {"path": self.path, "kind": self.kind, "mode": self.mode,
                "size_bytes": self.size_bytes, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class VerifiedRuntimeArchive:
    application_id: str
    runtime_kind: str
    entrypoint: str
    members: tuple[RuntimeArchiveMember, ...]
    interpreter_aliases: tuple[str, ...]
    manifest_sha256: str
    archive_sha256: str
    archive_size_bytes: int
    expanded_size_bytes: int


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _path(value: object, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        if allow_empty and value == "":
            return ""
        raise RuntimeArchiveError("runtime member path is malformed")
    path = PurePosixPath(value)
    if (path.is_absolute() or path.as_posix() != value
            or any(part in {"", ".", ".."} for part in path.parts)
            or value == MANIFEST_NAME):
        raise RuntimeArchiveError("runtime member path is not canonical or collides with the manifest")
    return value


def _sha_file(path: Path, *, ceiling: int) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > ceiling:
                raise RuntimeArchiveError("runtime member exceeds its fixed expanded-size ceiling")
            digest.update(chunk)
    return digest.hexdigest(), size


def _require_no_symlink_ancestors(path: Path) -> None:
    if not path.is_absolute() or path == Path("/"):
        raise RuntimeArchiveError("runtime destination must be an absolute non-root path")
    current = Path("/")
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise RuntimeArchiveError("runtime destination parent is unavailable") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RuntimeArchiveError("runtime destination traverses a symlink")
        if current != path and not stat.S_ISDIR(info.st_mode):
            raise RuntimeArchiveError("runtime destination parent is not a directory")


def _normalized_mode(mode: int, *, directory: bool) -> int:
    permissions = stat.S_IMODE(mode)
    if permissions & 0o022:
        raise RuntimeArchiveError("runtime member is group/world writable")
    # Preserve only the executable bit; root extraction chooses immutable
    # owner-readable permissions and never preserves special mode bits.
    if directory:
        return 0o755
    return 0o755 if permissions & 0o111 else 0o644


def _walk_members(root: Path, *, interpreter_aliases: frozenset[str]) -> tuple[RuntimeArchiveMember, ...]:
    try:
        root_info = root.lstat()
    except OSError as exc:
        raise RuntimeArchiveError("runtime root cannot be inspected") from exc
    if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
        raise RuntimeArchiveError("runtime root is not a real directory")
    aliases = frozenset(_path(alias) for alias in interpreter_aliases)
    result: list[RuntimeArchiveMember] = []
    expanded = 0
    for base, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base_path = Path(base)
        keep_dirs: list[str] = []
        for name in sorted(dirs):
            item = base_path / name
            info = item.lstat()
            relative = item.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                if relative in aliases:
                    continue
                raise RuntimeArchiveError("runtime archive cannot contain symlink directories")
            if not stat.S_ISDIR(info.st_mode) or info.st_nlink < 2:
                raise RuntimeArchiveError("runtime archive directory is not a normal directory")
            result.append(RuntimeArchiveMember(relative, "directory",
                                               _normalized_mode(info.st_mode, directory=True), 0,
                                               hashlib.sha256(b"").hexdigest()))
            keep_dirs.append(name)
        dirs[:] = keep_dirs
        for name in sorted(files):
            item = base_path / name
            info = item.lstat()
            relative = item.relative_to(root).as_posix()
            if stat.S_ISLNK(info.st_mode):
                if relative in aliases:
                    continue
                raise RuntimeArchiveError("runtime archive cannot contain an unselected symlink")
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != root_info.st_uid):
                raise RuntimeArchiveError("runtime archive contains a special or multiply-linked file")
            mode = _normalized_mode(info.st_mode, directory=False)
            digest, size = _sha_file(item, ceiling=MAX_EXPANDED_BYTES)
            expanded += size
            if expanded > MAX_EXPANDED_BYTES:
                raise RuntimeArchiveError("runtime archive exceeds the total expanded-size ceiling")
            result.append(RuntimeArchiveMember(relative, "file", mode, size, digest))
            if len(result) > MAX_MEMBERS:
                raise RuntimeArchiveError("runtime archive exceeds the member-count ceiling")
    result.sort(key=lambda member: member.path.encode("utf-8"))
    if len({member.path for member in result}) != len(result):
        raise RuntimeArchiveError("runtime tree contains duplicate canonical paths")
    return tuple(result)


def _manifest(application_id: str, runtime_kind: str, entrypoint: str,
              members: tuple[RuntimeArchiveMember, ...],
              interpreter_aliases: frozenset[str]) -> bytes:
    if application_id not in {"graphify", "browser-use", "hyperframes", "scrapegraph-ai"}:
        raise RuntimeArchiveError("runtime archive application is not in the fixed profile set")
    expected_kind = "node" if application_id == "hyperframes" else "python"
    if runtime_kind != expected_kind:
        raise RuntimeArchiveError("runtime kind does not match the selected application")
    allowed_aliases = PYTHON_RUNTIME_ALIASES if runtime_kind == "python" else frozenset()
    if interpreter_aliases != allowed_aliases:
        raise RuntimeArchiveError("runtime interpreter aliases differ from the fixed selected-runtime contract")
    entrypoint = _path(entrypoint)
    if not any(item.path == entrypoint and item.kind == "file" and item.mode & 0o111 for item in members):
        raise RuntimeArchiveError("runtime archive lacks its selected executable entrypoint")
    document = {"schema": 1, "application_id": application_id,
                "runtime_kind": runtime_kind, "entrypoint": entrypoint,
                "interpreter_aliases": sorted(interpreter_aliases),
                "members": [item.as_wire() for item in members]}
    body = _canonical(document)
    if len(body) > 16 * 1024 * 1024:
        raise RuntimeArchiveError("runtime member manifest exceeds its fixed bound")
    return body


def write_runtime_archive(root: Path, destination: Path, *, application_id: str,
                          runtime_kind: str, entrypoint: str,
                          interpreter_aliases: Iterable[str] = ()) -> VerifiedRuntimeArchive:
    """Create a bounded deterministic USTAR/PAX archive from a selected tree."""
    aliases = frozenset(interpreter_aliases)
    allowed_aliases = PYTHON_RUNTIME_ALIASES if runtime_kind == "python" else frozenset()
    if aliases != allowed_aliases:
        raise RuntimeArchiveError("runtime interpreter aliases differ from the fixed selected-runtime contract")
    for alias in sorted(aliases):
        candidate = root / alias
        try:
            info = candidate.lstat()
            target = os.readlink(candidate)
        except OSError as exc:
            raise RuntimeArchiveError("runtime environment is missing an exact held-interpreter alias") from exc
        if (not stat.S_ISLNK(info.st_mode) or not target or "\x00" in target
                or "\\" in target):
            raise RuntimeArchiveError("runtime interpreter alias is not a simple symlink")
    members = _walk_members(root, interpreter_aliases=aliases)
    manifest = _manifest(application_id, runtime_kind, entrypoint, members, aliases)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".runtime-", dir=destination.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as raw, tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            info = tarfile.TarInfo(MANIFEST_NAME)
            info.size, info.mode, info.uid, info.gid, info.mtime = len(manifest), 0o444, 0, 0, 0
            import io
            archive.addfile(info, io.BytesIO(manifest))
            for member in members:
                path = root / member.path
                info = tarfile.TarInfo(member.path + ("/" if member.kind == "directory" else ""))
                info.uid, info.gid, info.mtime = 0, 0, 0
                info.uname = info.gname = ""
                info.mode = member.mode
                if member.kind == "directory":
                    info.type, info.size = tarfile.DIRTYPE, 0
                    archive.addfile(info)
                else:
                    info.type, info.size = tarfile.REGTYPE, member.size_bytes
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
        size = temp.stat().st_size
        if size > MAX_ARCHIVE_BYTES:
            raise RuntimeArchiveError("runtime archive exceeds the fixed archive-size ceiling")
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
        digest, observed_size = _sha_file(destination, ceiling=MAX_ARCHIVE_BYTES)
        expanded = sum(member.size_bytes for member in members)
        return VerifiedRuntimeArchive(application_id, runtime_kind, entrypoint, members,
                                      tuple(sorted(aliases)),
                                      hashlib.sha256(manifest).hexdigest(), digest,
                                      observed_size, expanded)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def inspect_runtime_archive(stream: BinaryIO, *, expected_application_id: str,
                            expected_runtime_kind: str,
                            expected_entrypoint: str) -> VerifiedRuntimeArchive:
    """Validate one archive before root CAS publication; no extraction occurs."""
    members: list[RuntimeArchiveMember] = []
    seen: set[str] = set()
    manifest_body: bytes | None = None
    expanded = 0
    archive_digest = hashlib.sha256()
    archive_size = 0
    # The caller gives a held regular-file descriptor and enforces its inode.
    # Copy bounded bytes to a seekable spool without trusting a worker path.
    import tempfile
    with tempfile.TemporaryFile() as tmp:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            archive_size += len(block)
            if archive_size > MAX_ARCHIVE_BYTES:
                raise RuntimeArchiveError("runtime archive exceeds the fixed archive-size ceiling")
            archive_digest.update(block)
            tmp.write(block)
        tmp.seek(0)
        try:
            with tarfile.open(fileobj=tmp, mode="r:") as archive:
                for info in archive:
                    raw_name = info.name[:-1] if info.isdir() and info.name.endswith("/") else info.name
                    if raw_name == MANIFEST_NAME:
                        if (manifest_body is not None or not info.isfile() or info.size > 16 * 1024 * 1024
                                or info.mode != 0o444 or info.uid != 0 or info.gid != 0
                                or info.mtime != 0 or info.linkname):
                            raise RuntimeArchiveError("runtime archive manifest is duplicate or malformed")
                        member_stream = archive.extractfile(info)
                        if member_stream is None:
                            raise RuntimeArchiveError("runtime archive manifest bytes are unavailable")
                        manifest_body = member_stream.read(16 * 1024 * 1024 + 1)
                        if len(manifest_body) != info.size or len(manifest_body) > 16 * 1024 * 1024:
                            raise RuntimeArchiveError("runtime archive manifest size is invalid")
                        continue
                    name = _path(raw_name)
                    if name in seen:
                        raise RuntimeArchiveError("runtime archive contains duplicate paths")
                    seen.add(name)
                    if len(seen) > MAX_MEMBERS:
                        raise RuntimeArchiveError("runtime archive exceeds the member-count ceiling")
                    if info.isdir():
                        if (info.size != 0 or info.mode != 0o755 or info.uid != 0
                                or info.gid != 0 or info.mtime != 0 or info.linkname):
                            raise RuntimeArchiveError("runtime archive directory has content bytes")
                        members.append(RuntimeArchiveMember(name, "directory", _normalized_mode(info.mode, directory=True), 0,
                                                            hashlib.sha256(b"").hexdigest()))
                        continue
                    if (not info.isfile() or info.size < 0 or info.linkname
                            or info.mode not in {0o644, 0o755} or info.uid != 0
                            or info.gid != 0 or info.mtime != 0):
                        raise RuntimeArchiveError("runtime archive contains a link or special file")
                    mode = _normalized_mode(info.mode, directory=False)
                    fileobj = archive.extractfile(info)
                    if fileobj is None:
                        raise RuntimeArchiveError("runtime archive regular member bytes are unavailable")
                    digest = hashlib.sha256()
                    size = 0
                    while True:
                        block = fileobj.read(1024 * 1024)
                        if not block:
                            break
                        size += len(block)
                        expanded += len(block)
                        if size > info.size or expanded > MAX_EXPANDED_BYTES:
                            raise RuntimeArchiveError("runtime archive exceeds its expanded-size bound")
                        digest.update(block)
                    if size != info.size:
                        raise RuntimeArchiveError("runtime archive member size differs from its header")
                    members.append(RuntimeArchiveMember(name, "file", mode, size, digest.hexdigest()))
        except (tarfile.TarError, OSError) as exc:
            raise RuntimeArchiveError("runtime archive tar structure is invalid") from exc
    if manifest_body is None:
        raise RuntimeArchiveError("runtime archive has no canonical member manifest")
    try:
        document = json.loads(manifest_body.decode("ascii"))
        if not isinstance(document, dict) or set(document) != {
                "schema", "application_id", "runtime_kind", "entrypoint",
                "interpreter_aliases", "members"}:
            raise ValueError
        if (type(document["schema"]) is not int or document["schema"] != 1
                or document["application_id"] != expected_application_id
                or document["runtime_kind"] != expected_runtime_kind
                or document["entrypoint"] != expected_entrypoint
                or document["interpreter_aliases"] != sorted(
                    PYTHON_RUNTIME_ALIASES if expected_runtime_kind == "python" else ())
                or not isinstance(document["members"], list)):
            raise ValueError
        expected = tuple(RuntimeArchiveMember(**row) for row in document["members"])
    except (UnicodeDecodeError, ValueError, TypeError, KeyError):
        raise RuntimeArchiveError("runtime archive manifest schema or profile binding is invalid") from None
    actual = tuple(sorted(members, key=lambda row: row.path.encode("utf-8")))
    aliases_expected = PYTHON_RUNTIME_ALIASES if expected_runtime_kind == "python" else frozenset()
    if (actual != expected or _canonical(document) != manifest_body
            or len({row.path for row in expected}) != len(expected)
            or any(row.path in aliases_expected for row in expected)
            or not any(row.path == expected_entrypoint and row.kind == "file" and row.mode & 0o111
                       for row in expected)):
        raise RuntimeArchiveError("runtime archive members differ from its canonical embedded manifest")
    aliases = tuple(sorted(PYTHON_RUNTIME_ALIASES)) if expected_runtime_kind == "python" else ()
    return VerifiedRuntimeArchive(expected_application_id, expected_runtime_kind,
                                  expected_entrypoint, expected, aliases,
                                  hashlib.sha256(manifest_body).hexdigest(),
                                  archive_digest.hexdigest(), archive_size, expanded)


def extract_verified_runtime_archive(stream: BinaryIO, destination: Path, *,
                                     expected_application_id: str,
                                     expected_runtime_kind: str,
                                     expected_entrypoint: str,
                                     expected_uid: int = 0,
                                     held_interpreter: Path | None = None) -> VerifiedRuntimeArchive:
    """Revalidate, extract and reopen every member beneath a new root-owned tree.

    The selected PM interpreter is materialized only into the exact Python alias
    names above. Its executable is separately rechecked by the calling root PM
    runtime resolver. No archive-created link is ever followed or restored.
    """
    if type(expected_uid) is not int or expected_uid != 0:
        raise RuntimeArchiveError("runtime extraction requires enrolled root identity")
    if expected_runtime_kind == "python":
        if held_interpreter is None:
            raise RuntimeArchiveError("Python runtime extraction lacks a selected held interpreter")
        info = held_interpreter.lstat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111 or info.st_uid != expected_uid:
            raise RuntimeArchiveError("selected held interpreter is not a root-owned executable")
    elif held_interpreter is not None:
        raise RuntimeArchiveError("Node runtime extraction cannot accept a Python interpreter alias")
    _require_no_symlink_ancestors(destination)

    # First pass validates the full archive and manifest before any destination
    # path is created. The archive file is read again only from the same held
    # descriptor supplied by root.
    initial_pos = stream.tell()
    verified = inspect_runtime_archive(stream, expected_application_id=expected_application_id,
                                       expected_runtime_kind=expected_runtime_kind,
                                       expected_entrypoint=expected_entrypoint)
    stream.seek(initial_pos)
    if destination.exists() or destination.is_symlink():
        raise RuntimeArchiveError("runtime extraction destination must be a new path")
    destination.mkdir(mode=0o700, parents=False)
    root_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    expected = {member.path: member for member in verified.members}
    observed: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for info in archive:
                name = info.name[:-1] if info.isdir() and info.name.endswith("/") else info.name
                if name == MANIFEST_NAME:
                    continue
                name = _path(name)
                member = expected.get(name)
                if member is None or name in observed:
                    raise RuntimeArchiveError("runtime archive changed after its pre-extraction inspection")
                observed.add(name)
                parts = PurePosixPath(name).parts
                parent_fd = os.dup(root_fd)
                try:
                    for part in parts[:-1]:
                        try:
                            os.mkdir(part, 0o755, dir_fd=parent_fd)
                        except FileExistsError:
                            pass
                        next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                          dir_fd=parent_fd)
                        os.close(parent_fd)
                        parent_fd = next_fd
                    leaf = parts[-1]
                    if member.kind == "directory":
                        try:
                            os.mkdir(leaf, member.mode, dir_fd=parent_fd)
                        except FileExistsError:
                            child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                            dir_fd=parent_fd)
                            os.close(child)
                    else:
                        if not info.isfile() or info.size != member.size_bytes:
                            raise RuntimeArchiveError("runtime regular member changed before extraction")
                        source = archive.extractfile(info)
                        if source is None:
                            raise RuntimeArchiveError("runtime regular member is unreadable")
                        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
                        fd = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
                        digest = hashlib.sha256()
                        size = 0
                        try:
                            while True:
                                block = source.read(1024 * 1024)
                                if not block:
                                    break
                                size += len(block)
                                total += len(block)
                                if size > member.size_bytes or total > MAX_EXPANDED_BYTES:
                                    raise RuntimeArchiveError("runtime extraction exceeds its expanded-size bound")
                                digest.update(block)
                                view = memoryview(block)
                                while view:
                                    written = os.write(fd, view)
                                    view = view[written:]
                            if size != member.size_bytes or digest.hexdigest() != member.sha256:
                                raise RuntimeArchiveError("runtime extracted file hash differs from the manifest")
                            os.fchmod(fd, member.mode & 0o555)
                            os.fchown(fd, expected_uid, -1)
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                finally:
                    os.close(parent_fd)
        if observed != set(expected):
            raise RuntimeArchiveError("runtime archive omitted one or more manifest members")
        # Apply and verify canonical directory custody/modes after all children
        # have been created. This makes the manifest mode observable rather
        # than relying on the process umask at mkdir time.
        for member in verified.members:
            if member.kind != "directory":
                continue
            parent_fd = os.dup(root_fd)
            try:
                for part in PurePosixPath(member.path).parts:
                    next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                      dir_fd=parent_fd)
                    os.close(parent_fd)
                    parent_fd = next_fd
                os.fchmod(parent_fd, member.mode)
                os.fchown(parent_fd, expected_uid, -1)
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        if expected_runtime_kind == "python":
            assert held_interpreter is not None
            for alias in sorted(PYTHON_RUNTIME_ALIASES):
                parts = PurePosixPath(alias).parts
                parent_fd = os.dup(root_fd)
                try:
                    for part in parts[:-1]:
                        try:
                            os.mkdir(part, 0o755, dir_fd=parent_fd)
                        except FileExistsError:
                            pass
                        next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                          dir_fd=parent_fd)
                        os.close(parent_fd)
                        parent_fd = next_fd
                    relative_target = os.path.relpath(held_interpreter, destination / PurePosixPath(alias).parent)
                    if os.path.isabs(relative_target) or "\x00" in relative_target:
                        raise RuntimeArchiveError("selected interpreter alias cannot be represented safely")
                    os.symlink(relative_target, parts[-1], dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
        os.fsync(root_fd)
    except BaseException:
        os.close(root_fd)
        # Never recurse through links: the extraction code creates only regular
        # files and directories before this point.
        import shutil
        shutil.rmtree(destination, ignore_errors=True)
        raise
    else:
        os.close(root_fd)
    # Reopen exact tree without following links; aliases are verified against
    # the selected external runtime and omitted from the archive manifest.
    for member in verified.members:
        path = destination / member.path
        info = path.lstat()
        if member.kind == "directory":
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) != member.mode):
                raise RuntimeArchiveError("extracted runtime directory changed after publication")
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                or stat.S_IMODE(info.st_mode) != (member.mode & 0o555)):
            raise RuntimeArchiveError("extracted runtime file mode or custody changed")
        digest, size = _sha_file(path, ceiling=member.size_bytes)
        if digest != member.sha256 or size != member.size_bytes:
            raise RuntimeArchiveError("extracted runtime file no longer matches its receipt")
    if expected_runtime_kind == "python":
        for alias in PYTHON_RUNTIME_ALIASES:
            alias_path = destination / alias
            if not alias_path.is_symlink() or alias_path.resolve(strict=True) != held_interpreter.resolve(strict=True):
                raise RuntimeArchiveError("extracted Python interpreter alias is not bound to the held PM runtime")
    return verified
