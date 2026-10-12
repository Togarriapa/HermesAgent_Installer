#!/usr/bin/env python3
"""Stage one reviewed official source archive without changing live services.

Run as root with the Pi system interpreter in isolated mode. The caller supplies
the reviewed full source commit and expected archive digest as a pair. The
repository and release are fixed; the asset name derives from the commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tarfile
import urllib.request
from pathlib import PurePosixPath


REPOSITORY = "Togarriapa/HermesAgent_Installer"
RELEASE = "jarvis-mvp-stage-20261011-v1"
ARCHIVE_PREFIX = "core-source-"
RELEASE_URL = f"https://github.com/{REPOSITORY}/releases/download/{RELEASE}"
OPT = "/opt"
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 12_000
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_PATH_BYTES = 1024
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)


def _require_root_python() -> None:
    if os.geteuid() != 0 or sys.executable != "/usr/bin/python3" or not sys.flags.isolated:
        raise RuntimeError("run as root with /usr/bin/python3 -I")
    executable = os.stat(sys.executable, follow_symlinks=True)
    if (not stat.S_ISREG(executable.st_mode) or executable.st_uid != 0
            or executable.st_gid != 0 or stat.S_IMODE(executable.st_mode) & 0o022):
        raise RuntimeError("system Python executable custody differs")
    for parent in ("/usr", "/usr/bin"):
        info = os.stat(parent, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise RuntimeError("system Python parent custody differs")


def _open_root_opt() -> int:
    root = os.open("/", DIR_FLAGS)
    try:
        fd = os.open("opt", DIR_FLAGS, dir_fd=root)
    finally:
        os.close(root)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise RuntimeError("/opt directory custody differs")
    return fd


def _assert_absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise RuntimeError("candidate or temporary staging path already exists")


def _download_archive(path: str, expected_sha256: str, archive_url: str) -> None:
    var_info = os.stat("/var", follow_symlinks=False)
    if (not stat.S_ISDIR(var_info.st_mode) or var_info.st_uid != 0 or var_info.st_gid != 0
            or stat.S_IMODE(var_info.st_mode) & 0o022):
        raise RuntimeError("/var directory custody differs")
    tmp = "/var/tmp"
    info = os.stat(tmp, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or not (stat.S_IMODE(info.st_mode) & stat.S_ISVTX)):
        raise RuntimeError("/var/tmp custody differs")
    fd = os.open(path, FILE_FLAGS, 0o600)
    digest = hashlib.sha256()
    total = 0
    try:
        with urllib.request.urlopen(archive_url, timeout=45) as response:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_ARCHIVE_BYTES:
                    raise RuntimeError("official source archive exceeds its byte limit")
                digest.update(block)
                view = memoryview(block)
                while view:
                    count = os.write(fd, view)
                    if count <= 0:
                        raise OSError("short archive write")
                    view = view[count:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    os.close(fd)
    if total == 0 or digest.hexdigest() != expected_sha256:
        os.unlink(path)
        raise RuntimeError("official source archive SHA-256 differs")


def _member_path(member: tarfile.TarInfo) -> tuple[str, ...]:
    name = member.name
    if (not name or name.startswith("/") or "\\" in name or "\x00" in name
            or len(name.encode("utf-8", "strict")) > MAX_PATH_BYTES):
        raise RuntimeError("archive contains an invalid path")
    stripped = name[:-1] if member.isdir() and name.endswith("/") else name
    parsed = PurePosixPath(stripped)
    parts = parsed.parts
    if (not parts or parsed.is_absolute() or "/".join(parts) != stripped
            or any(part in {"", ".", ".."} for part in parts)):
        raise RuntimeError("archive contains a non-canonical path")
    if not (member.isdir() or member.isfile()) or member.size < 0:
        raise RuntimeError("archive may contain only regular files and directories")
    if member.isfile() and member.size > MAX_FILE_BYTES:
        raise RuntimeError("archive member exceeds the per-file size limit")
    return parts


def _validated_members(archive_path: str) -> list[tuple[tarfile.TarInfo, tuple[str, ...]]]:
    result = []
    entries: dict[tuple[str, ...], str] = {}
    total = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_MEMBERS:
            raise RuntimeError("official source archive member count differs")
        for member in members:
            parts = _member_path(member)
            kind = "dir" if member.isdir() else "file"
            if parts == (".source-provenance.json",) or parts in entries:
                raise RuntimeError("archive has a duplicate or reserved path")
            entries[parts] = kind
            if kind == "file":
                total += member.size
            if total > MAX_UNPACKED_BYTES:
                raise RuntimeError("official source archive exceeds its expanded size limit")
            result.append((member, parts))

    directories = {path[:index] for path in entries for index in range(1, len(path))}
    directories.update(path for path, kind in entries.items() if kind == "dir")
    for path, kind in entries.items():
        if any(entries.get(path[:index]) == "file" for index in range(1, len(path))):
            raise RuntimeError("archive file is used as a parent directory")
        if kind == "file" and path in directories:
            raise RuntimeError("archive path is both a file and directory")
    required = {
        ("src", "hermes_installer", "core_runtime.py"),
        ("src", "hermes_installer", "remote", "core_gateway.py"),
        ("src", "hermes_installer", "remote", "core_gateway_inspector.py"),
        ("tools", "pi_native_core_preflight.py"),
        ("tools", "pi_native_core_adopt.py"),
    }
    if not required.issubset(entries):
        raise RuntimeError("official source archive layout is incomplete")
    return result


def _open_or_create_dir(parent_fd: int, name: str) -> int:
    try:
        os.mkdir(name, 0o755, dir_fd=parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    os.fchown(fd, 0, 0)
    os.fchmod(fd, 0o755)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o755):
        os.close(fd)
        raise RuntimeError("staging directory custody differs")
    return fd


def _directory_fd(root_fd: int, parts: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for name in parts:
            child = _open_or_create_dir(current, name)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _write_member(root_fd: int, archive: tarfile.TarFile, member: tarfile.TarInfo,
                  parts: tuple[str, ...]) -> None:
    if member.isdir():
        fd = _directory_fd(root_fd, parts)
        os.close(fd)
        return
    parent_fd = _directory_fd(root_fd, parts[:-1])
    out_fd = -1
    try:
        out_fd = os.open(parts[-1], FILE_FLAGS, 0o600, dir_fd=parent_fd)
        os.fchown(out_fd, 0, 0)
        os.fchmod(out_fd, 0o644)
        stream = archive.extractfile(member)
        if stream is None:
            raise RuntimeError("regular archive member has no content")
        copied = 0
        with stream:
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                copied += len(block)
                if copied > member.size:
                    raise RuntimeError("archive member exceeded its declared size")
                view = memoryview(block)
                while view:
                    count = os.write(out_fd, view)
                    if count <= 0:
                        raise OSError("short extracted file write")
                    view = view[count:]
        if copied != member.size:
            raise RuntimeError("archive member content length differs")
        os.fsync(out_fd)
        os.fsync(parent_fd)
    finally:
        if out_fd >= 0:
            os.close(out_fd)
        os.close(parent_fd)


def _write_receipt(root_fd: int, commit: str, archive_sha256: str) -> None:
    # This root-owned receipt records the exact pair supplied and verified by
    # the operator; it is not an independent Git signature or attestation.
    raw = (json.dumps({"schema": 1, "source_commit": commit,
                       "archive_sha256": archive_sha256},
                      sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    fd = os.open(".source-provenance.json", FILE_FLAGS, 0o600, dir_fd=root_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o444)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short provenance receipt write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(root_fd)


def _remove_tree_at(parent_fd: int, name: str, expected: tuple[int, int]) -> None:
    info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != expected
            or info.st_uid != 0 or info.st_gid != 0):
        raise RuntimeError("temporary generation changed before cleanup")
    directory_fd = os.open(name, DIR_FLAGS, dir_fd=parent_fd)
    try:
        for child_name in os.listdir(directory_fd):
            child = os.stat(child_name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(child.st_mode):
                _remove_tree_at(directory_fd, child_name, (child.st_dev, child.st_ino))
            else:
                if not stat.S_ISREG(child.st_mode) or child.st_uid != 0 or child.st_gid != 0:
                    raise RuntimeError("unexpected temporary generation object blocks cleanup")
                os.unlink(child_name, dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    os.rmdir(name, dir_fd=parent_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-commit", required=True,
                        help="full reviewed 40-character source Git commit")
    parser.add_argument("--archive-sha256", required=True,
                        help="reviewed SHA-256 digest paired with the source commit")
    args = parser.parse_args()
    if re.fullmatch(r"[0-9a-f]{40}", args.source_commit) is None:
        parser.error("--source-commit must be 40 lowercase hexadecimal characters")
    if re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256) is None:
        parser.error("--archive-sha256 must be 64 lowercase hexadecimal characters")

    _require_root_python()
    prefix = args.source_commit[:9]
    archive = f"{ARCHIVE_PREFIX}{prefix}.tar.gz"
    archive_url = f"{RELEASE_URL}/{archive}"
    target_name = f"hermes-installer-core-{prefix}"
    stage_name = f".{target_name}.staging"
    target_path = f"{OPT}/{target_name}"
    stage_path = f"{OPT}/{stage_name}"
    archive_path = f"/var/tmp/{target_name}-{archive}"
    opt_fd = _open_root_opt()
    stage_fd = -1
    stage_identity = None
    archive_created = False
    published = False
    try:
        _assert_absent(opt_fd, target_name)
        _assert_absent(opt_fd, stage_name)
        # Never extract before the entire archive is bounded and matches the
        # operator-reviewed SHA paired with this candidate commit.
        _download_archive(archive_path, args.archive_sha256, archive_url)
        archive_created = True
        members = _validated_members(archive_path)

        os.mkdir(stage_name, 0o755, dir_fd=opt_fd)
        stage_fd = os.open(stage_name, DIR_FLAGS, dir_fd=opt_fd)
        os.fchown(stage_fd, 0, 0)
        os.fchmod(stage_fd, 0o755)
        stage_info = os.fstat(stage_fd)
        stage_identity = (stage_info.st_dev, stage_info.st_ino)
        if (stage_info.st_uid != 0 or stage_info.st_gid != 0
                or stat.S_IMODE(stage_info.st_mode) != 0o755):
            raise RuntimeError("temporary source generation custody differs")

        with tarfile.open(archive_path, "r:gz") as archive:
            for member, parts in members:
                _write_member(stage_fd, archive, member, parts)
        _write_receipt(stage_fd, args.source_commit, args.archive_sha256)
        os.close(stage_fd)
        stage_fd = -1
        os.unlink(archive_path)
        archive_created = False
        os.rename(stage_name, target_name, src_dir_fd=opt_fd, dst_dir_fd=opt_fd)
        os.fsync(opt_fd)
        published = True
        print(f"Staged verified source at {target_path}")
        print(f"Archive SHA-256: {args.archive_sha256}")
        print("No service, unit, gateway configuration, or Core runtime was changed.")
        return 0
    except Exception as error:
        if stage_fd >= 0:
            os.close(stage_fd)
        if stage_identity is not None and not published:
            try:
                _remove_tree_at(opt_fd, stage_name, stage_identity)
                os.fsync(opt_fd)
            except Exception:
                print(f"Incomplete root-owned staging tree requires inspection: {stage_path}",
                      file=sys.stderr)
        print(f"Source staging stopped: {type(error).__name__}", file=sys.stderr)
        return 4
    finally:
        if archive_created:
            try:
                os.unlink(archive_path)
            except OSError:
                pass
        os.close(opt_fd)


if __name__ == "__main__":
    raise SystemExit(main())
