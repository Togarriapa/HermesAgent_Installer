"""Bounded fixed-name profile file custody helpers for the root inspector.

Callers must resolve ``profile_id`` against the current verified Resources
manifest before using this module. Nothing here accepts an HTTP path.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HOME_UID = 1000
HOME_GID = 1000
MAX_FILE_BYTES = 64 * 1024
_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,95}$")
_SKILL_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_SAFE_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_FILE_NAMES = {"soul": "SOUL.md", "description": "description.md", "instructions": "instructions.md"}
_ROOT = Path("/home/admin/.hermes")
_BACKUP_ROOT = Path("/var/lib/hermes-jarvis-profile-admin")
_CORE_PYTHON = Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")


class ProfileFileCustodyError(RuntimeError):
    """A native profile path or atomic edit failed a custody check."""


@dataclass(frozen=True, slots=True)
class ProfileFileRead:
    profile_id: str
    file_kind: str
    file_name: str
    content: str
    sha256: str
    signature: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ProfileFileWrite:
    state: str
    profile_id: str
    file_kind: str
    source_generation: str | None
    sha256: str | None
    recovery_id: str | None
    readback: bool


def _valid_leaf(file_kind: Any) -> bool:
    return isinstance(file_kind, str) and file_kind in _FILE_NAMES


def _signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_fd(fd: int, *, uid: int = HOME_UID, gid: int = HOME_GID) -> tuple[bytes, tuple[int, ...]]:
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_gid != gid
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o022
            or not 0 < before.st_size <= MAX_FILE_BYTES):
        raise ProfileFileCustodyError("profile file custody differs")
    chunks = bytearray()
    while len(chunks) <= MAX_FILE_BYTES:
        part = os.read(fd, min(32 * 1024, MAX_FILE_BYTES + 1 - len(chunks)))
        if not part:
            break
        chunks.extend(part)
    after = os.fstat(fd)
    if len(chunks) != before.st_size or _signature(before) != _signature(after):
        raise ProfileFileCustodyError("profile file changed during read")
    try:
        os.listxattr(fd)
    except OSError:
        raise ProfileFileCustodyError("profile file metadata could not be verified") from None
    return bytes(chunks), _signature(before)


def _open_profile_directory(profile_id: str, *, native_default: bool = False) -> int:
    if os.geteuid() not in {0, HOME_UID} or not _ID.fullmatch(profile_id):
        raise ProfileFileCustodyError("root/Core UID and a verified profile ID are required")
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open("/", flags)
    try:
        for name, uid, gid, mode in (("home", 0, 0, 0o755),
                                     ("admin", HOME_UID, HOME_GID, 0o700),
                                     (".hermes", HOME_UID, HOME_GID, 0o700)):
            nxt = os.open(name, flags, dir_fd=fd)
            info = os.fstat(nxt)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                    or stat.S_IMODE(info.st_mode) != mode):
                os.close(nxt)
                raise ProfileFileCustodyError("native profile parent custody differs")
            os.close(fd)
            fd = nxt
        if native_default:
            return fd
        profiles_fd = os.open("profiles", flags, dir_fd=fd)
        pinfo = os.fstat(profiles_fd)
        if (not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid != HOME_UID or pinfo.st_gid != HOME_GID
                or stat.S_IMODE(pinfo.st_mode) != 0o700):
            os.close(profiles_fd)
            raise ProfileFileCustodyError("native profiles directory custody differs")
        os.close(fd)
        fd = os.open(profile_id, flags, dir_fd=profiles_fd)
        os.close(profiles_fd)
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != HOME_UID or info.st_gid != HOME_GID
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ProfileFileCustodyError("native profile directory custody differs")
        return fd
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def _read_profile_file(profile_id: str, file_kind: str) -> ProfileFileRead:
    if not _ID.fullmatch(profile_id) or not _valid_leaf(file_kind):
        raise ProfileFileCustodyError("profile file selector is invalid")
    native_default = profile_id == "hermes"
    dirname = "SOUL.md" if native_default and file_kind == "soul" else _FILE_NAMES[file_kind]
    directory = _open_profile_directory(profile_id, native_default=native_default)
    try:
        fd = os.open(dirname, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
        try:
            raw, signature = _read_fd(fd)
            named = os.stat(dirname, dir_fd=directory, follow_symlinks=False)
            if _signature(named) != signature:
                raise ProfileFileCustodyError("profile file name changed during read")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise ProfileFileCustodyError("profile file is not UTF-8") from None
    if "\x00" in content:
        raise ProfileFileCustodyError("profile file is not text")
    return ProfileFileRead(profile_id, file_kind, dirname, content,
                           hashlib.sha256(raw).hexdigest(), signature)


def _open_skill_file(skill_name: str) -> tuple[int, str]:
    """Open one existing native skill entrypoint without accepting a path."""
    if (os.geteuid() not in {0, HOME_UID} or not isinstance(skill_name, str)
            or not _SKILL_ID.fullmatch(skill_name)):
        raise ProfileFileCustodyError("native skill selector is invalid")
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open("/", flags)
    try:
        for name, uid, gid, mode in (("home", 0, 0, 0o755),
                                     ("admin", HOME_UID, HOME_GID, 0o700),
                                     (".hermes", HOME_UID, HOME_GID, 0o700),
                                     ("skills", HOME_UID, HOME_GID, None),
                                     (skill_name, HOME_UID, HOME_GID, None)):
            child = os.open(name, flags, dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                    or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
                    or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                raise ProfileFileCustodyError("native skill directory custody differs")
            os.close(fd)
            fd = child
        return fd, "SKILL.md"
    except BaseException:
        os.close(fd)
        raise


def read_profile_skill(profile_id: str, skill_name: str) -> ProfileFileRead:
    """Read an existing root-level native skill for a verified profile ID.

    The profile selector is retained in the typed result for caller-side
    current-manifest binding; filesystem resolution is the exact Hermes native
    ``skills/<name>/SKILL.md`` entrypoint.
    """
    if profile_id != "hermes":
        raise ProfileFileCustodyError("native skills are only resolved for the verified default profile")
    directory, leaf = _open_skill_file(skill_name)
    try:
        fd = os.open(leaf, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=directory)
        try:
            raw, signature = _read_fd(fd)
            named = os.stat(leaf, dir_fd=directory, follow_symlinks=False)
            if _signature(named) != signature:
                raise ProfileFileCustodyError("native skill entrypoint changed during read")
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    try:
        content = raw.decode("utf-8", "strict")
    except UnicodeError:
        raise ProfileFileCustodyError("native skill entrypoint is not UTF-8") from None
    if "\x00" in content:
        raise ProfileFileCustodyError("native skill entrypoint is not text")
    return ProfileFileRead(profile_id, "skill", f"skills/{skill_name}/{leaf}", content,
                           hashlib.sha256(raw).hexdigest(), signature)


def current_profile_skill_files(pinned_skill_ids: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
    """List exact existing Core-home SKILL.md leaves joined to pinned IDs."""
    if (os.geteuid() != 0 or type(pinned_skill_ids) is not tuple
            or len(pinned_skill_ids) > 4096
            or any(not isinstance(item, str) or not _SKILL_ID.fullmatch(item)
                   for item in pinned_skill_ids)
            or len(set(pinned_skill_ids)) != len(pinned_skill_ids)):
        raise ProfileFileCustodyError("current pinned skill inventory is invalid")
    root_fd = _open_skill_root()
    try:
        names = sorted(os.listdir(root_fd))
        if len(names) > 8192:
            raise ProfileFileCustodyError("native skill inventory exceeds its bound")
        rows = []
        for name in names:
            if not _SKILL_ID.fullmatch(name):
                continue
            try:
                result = read_profile_skill("hermes", name)
            except FileNotFoundError:
                continue
            rows.append({"skill_id": name, "name": name, "sha256": result.sha256,
                "source": "pinned" if name in pinned_skill_ids else "owner-added",
                "editable": name not in pinned_skill_ids})
        return tuple(rows)
    finally:
        os.close(root_fd)


def write_profile_skill(skill_name: str, *, expected_sha256: str, content: str,
                        idempotency_key: str, core_source_generation: str) -> ProfileFileWrite:
    """CAS-write one existing owner-added default-profile SKILL.md entrypoint."""
    if (not isinstance(skill_name, str) or not _SKILL_ID.fullmatch(skill_name)
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or not _SAFE_IDEMPOTENCY.fullmatch(idempotency_key)
            or not isinstance(core_source_generation, str)
            or not re.fullmatch(r"[0-9a-f]{64}", core_source_generation)
            or not isinstance(content, str) or "\x00" in content):
        raise ProfileFileCustodyError("native skill edit request is invalid")
    try:
        proposed = content.encode("utf-8", "strict")
    except UnicodeError:
        raise ProfileFileCustodyError("native skill edit is not UTF-8") from None
    if not 0 < len(proposed) <= MAX_FILE_BYTES or os.geteuid() != 0:
        raise ProfileFileCustodyError("bounded root skill edit is required")
    directory = _open_skill_directory(skill_name)
    backup_dir = _backup_directory()
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    journal_name = f"skill-edit-{key_hash}.json"
    try:
        lock_fd = os.open(f"skill-{skill_name}.lock", os.O_CREAT | os.O_RDWR
                          | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=backup_dir)
        try:
            lock = os.fstat(lock_fd)
            if not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0 or stat.S_IMODE(lock.st_mode) != 0o600:
                raise ProfileFileCustodyError("native skill edit lock custody differs")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            existing = read_profile_skill("hermes", skill_name)
            proposed_sha = hashlib.sha256(proposed).hexdigest()
            prior = _read_root_record(backup_dir, journal_name)
            if prior is not None:
                required = {"schema", "state", "skill_name", "core_source_generation", "base_sha256",
                    "proposed_sha256", "prior_signature", "backup_name", "idempotency_key_sha256",
                    "created_monotonic_ns"}
                keys = set(prior)
                if (keys not in (required, required | {"readback_sha256"})
                        or prior.get("schema") != 1 or prior.get("skill_name") != skill_name
                        or prior.get("core_source_generation") != core_source_generation
                        or prior.get("base_sha256") != expected_sha256
                        or prior.get("proposed_sha256") != proposed_sha
                        or prior.get("idempotency_key_sha256") != key_hash
                        or prior.get("state") not in {"prepared", "unknown-pending", "committed"}):
                    raise ProfileFileCustodyError("native skill idempotency record differs")
                recovery_id = prior.get("backup_name", "").removesuffix(".backup")
                if not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", recovery_id):
                    raise ProfileFileCustodyError("native skill recovery identity differs")
                if existing.sha256 == proposed_sha:
                    if prior["state"] != "committed":
                        prior["state"] = "committed"
                        prior["readback_sha256"] = proposed_sha
                        _atomic_root_record(backup_dir, journal_name,
                            json.dumps(prior, sort_keys=True, separators=(",", ":")).encode())
                    return ProfileFileWrite("active", "hermes", "skill",
                        hashlib.sha256((core_source_generation + "\0" + proposed_sha).encode()).hexdigest(),
                        proposed_sha, recovery_id, True)
                if existing.sha256 == expected_sha256:
                    return ProfileFileWrite("unknown-pending", "hermes", "skill", None, None, recovery_id, False)
                return ProfileFileWrite("conflict", "hermes", "skill", None, existing.sha256, None, False)
            if existing.sha256 != expected_sha256:
                return ProfileFileWrite("conflict", "hermes", "skill", None, existing.sha256, None, False)
            recovery_id = secrets.token_urlsafe(24)
            backup_name = f"{recovery_id}.backup"
            backup_fd = os.open(backup_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=backup_dir)
            try:
                _write_all(backup_fd, existing.content.encode("utf-8"))
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
            journal = {"schema": 1, "state": "prepared", "skill_name": skill_name,
                "core_source_generation": core_source_generation, "base_sha256": existing.sha256,
                "proposed_sha256": proposed_sha, "prior_signature": list(existing.signature),
                "backup_name": backup_name, "idempotency_key_sha256": key_hash,
                "created_monotonic_ns": time.monotonic_ns()}
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
            request = json.dumps({"schema": 1, "op": "replace-skill-entrypoint",
                "skill_name": skill_name, "expected_sha256": existing.sha256,
                "expected_signature": list(existing.signature), "content": content,
                "recovery_id": recovery_id}, sort_keys=True, separators=(",", ":"),
                ensure_ascii=False).encode("utf-8")
            try:
                child = subprocess.run([str(_CORE_PYTHON), "-I", str(Path(__file__).resolve()),
                        "--profile-file-helper"], input=request, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=3.0, check=False, close_fds=True,
                    user=HOME_UID, group=HOME_GID, extra_groups=(), cwd="/",
                    env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"})
                result = json.loads(child.stdout.decode("utf-8", "strict")) if child.returncode == 0 else None
            except Exception:
                result = None
            if type(result) is not dict or result != {"ok": True, "sha256": proposed_sha}:
                journal["state"] = "unknown-pending"
                _atomic_root_record(backup_dir, journal_name,
                    json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
                return ProfileFileWrite("unknown-pending", "hermes", "skill", None, None, recovery_id, False)
            readback = read_profile_skill("hermes", skill_name)
            if readback.sha256 != proposed_sha:
                raise ProfileFileCustodyError("native skill write readback differs")
            journal["state"] = "committed"
            journal["readback_sha256"] = proposed_sha
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
            return ProfileFileWrite("active", "hermes", "skill",
                hashlib.sha256((core_source_generation + "\0" + proposed_sha).encode()).hexdigest(),
                proposed_sha, recovery_id, True)
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory)
        os.close(backup_dir)


def archive_profile_skill(skill_name: str, *, expected_sha256: str,
                          idempotency_key: str, core_source_generation: str) -> ProfileFileWrite:
    """Move an owner-added skill out of discovery with a root-held recoverable backup."""
    if (not isinstance(skill_name, str) or not _SKILL_ID.fullmatch(skill_name)
            or not isinstance(expected_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or not _SAFE_IDEMPOTENCY.fullmatch(idempotency_key)
            or not isinstance(core_source_generation, str)
            or not re.fullmatch(r"[0-9a-f]{64}", core_source_generation)
            or os.geteuid() != 0):
        raise ProfileFileCustodyError("native skill archive request is invalid")
    directory = _open_skill_directory(skill_name)
    backup_dir = _backup_directory()
    key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    journal_name = f"skill-archive-{key_hash}.json"
    try:
        lock_fd = os.open(f"skill-{skill_name}.lock", os.O_CREAT | os.O_RDWR
                          | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=backup_dir)
        try:
            lock = os.fstat(lock_fd)
            if not stat.S_ISREG(lock.st_mode) or lock.st_uid != 0 or stat.S_IMODE(lock.st_mode) != 0o600:
                raise ProfileFileCustodyError("native skill archive lock custody differs")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            prior = _read_root_record(backup_dir, journal_name)
            if prior is not None:
                required = {"schema", "state", "skill_name", "core_source_generation", "base_sha256",
                    "prior_signature", "backup_name", "idempotency_key_sha256", "created_monotonic_ns"}
                recovery_id = prior.get("backup_name", "").removesuffix(".backup")
                if (set(prior) != required or prior.get("schema") != 1
                        or prior.get("skill_name") != skill_name
                        or prior.get("core_source_generation") != core_source_generation
                        or prior.get("base_sha256") != expected_sha256
                        or prior.get("idempotency_key_sha256") != key_hash
                        or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", recovery_id)):
                    raise ProfileFileCustodyError("native skill archive record differs")
                try:
                    read_profile_skill("hermes", skill_name)
                except FileNotFoundError:
                    if prior["state"] != "archived":
                        prior["state"] = "archived"
                        _atomic_root_record(backup_dir, journal_name,
                            json.dumps(prior, sort_keys=True, separators=(",", ":")).encode())
                    return ProfileFileWrite("archived", "hermes", "skill",
                        hashlib.sha256((core_source_generation + "\0archived\0" + skill_name).encode()).hexdigest(),
                        expected_sha256, recovery_id, True)
                return ProfileFileWrite("unknown-pending", "hermes", "skill", None, None, recovery_id, False)
            existing = read_profile_skill("hermes", skill_name)
            if not secrets.compare_digest(existing.sha256, expected_sha256):
                return ProfileFileWrite("conflict", "hermes", "skill", None, existing.sha256, None, False)
            key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
            recovery_id = secrets.token_urlsafe(24)
            backup_name = f"{recovery_id}.backup"
            backup_fd = os.open(backup_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=backup_dir)
            try:
                _write_all(backup_fd, existing.content.encode("utf-8"))
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
            os.fsync(backup_dir)
            journal = {"schema": 1, "state": "prepared", "skill_name": skill_name,
                "core_source_generation": core_source_generation, "base_sha256": existing.sha256,
                "prior_signature": list(existing.signature), "backup_name": backup_name,
                "idempotency_key_sha256": key_hash, "created_monotonic_ns": time.monotonic_ns()}
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
            request = json.dumps({"schema": 1, "op": "archive-skill-entrypoint",
                "skill_name": skill_name, "expected_sha256": existing.sha256,
                "expected_signature": list(existing.signature), "recovery_id": recovery_id},
                sort_keys=True, separators=(",", ":")).encode()
            try:
                child = subprocess.run([str(_CORE_PYTHON), "-I", str(Path(__file__).resolve()),
                        "--profile-file-helper"], input=request, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=3.0, check=False, close_fds=True,
                    user=HOME_UID, group=HOME_GID, extra_groups=(), cwd="/",
                    env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"})
                result = json.loads(child.stdout.decode("utf-8", "strict")) if child.returncode == 0 else None
            except Exception:
                result = None
            if result != {"ok": True, "archived": True}:
                journal["state"] = "unknown-pending"
                _atomic_root_record(backup_dir, journal_name,
                    json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
                return ProfileFileWrite("unknown-pending", "hermes", "skill", None, None, recovery_id, False)
            try:
                read_profile_skill("hermes", skill_name)
            except FileNotFoundError:
                pass
            else:
                raise ProfileFileCustodyError("native skill remained discoverable after archive")
            journal["state"] = "archived"
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode())
            return ProfileFileWrite("archived", "hermes", "skill",
                hashlib.sha256((core_source_generation + "\0archived\0" + skill_name).encode()).hexdigest(),
                existing.sha256, recovery_id, True)
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory)
        os.close(backup_dir)


def _open_skill_directory(skill_name: str) -> int:
    if not isinstance(skill_name, str) or not _SKILL_ID.fullmatch(skill_name):
        raise ProfileFileCustodyError("native skill selector is invalid")
    fd = _open_skill_root()
    try:
        child = os.open(skill_name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        info = os.fstat(child)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != HOME_UID or info.st_gid != HOME_GID
                or stat.S_IMODE(info.st_mode) & 0o022):
            os.close(child)
            raise ProfileFileCustodyError("native skill directory custody differs")
        return child
    finally:
        os.close(fd)


def _open_skill_root() -> int:
    flags = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fd = os.open("/", flags)
    try:
        for name, uid, gid, mode in (("home", 0, 0, 0o755),
                                     ("admin", HOME_UID, HOME_GID, 0o700),
                                     (".hermes", HOME_UID, HOME_GID, 0o700),
                                     ("skills", HOME_UID, HOME_GID, None)):
            child = os.open(name, flags, dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                    or (mode is not None and stat.S_IMODE(info.st_mode) != mode)
                    or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                raise ProfileFileCustodyError("native skill root custody differs")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_profile_file(profile_id: str, file_kind: str) -> ProfileFileRead:
    """Read one existing source leaf under its fixed native profile directory."""
    return _read_profile_file(profile_id, file_kind)


def _backup_directory() -> int:
    if os.geteuid() != 0:
        raise ProfileFileCustodyError("root profile backup custody is required")
    try:
        os.mkdir(_BACKUP_ROOT, 0o700)
    except FileExistsError:
        pass
    parent_fd = os.open("/var/lib", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open("hermes-jarvis-profile-admin", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                     | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            os.close(fd)
            raise ProfileFileCustodyError("profile backup directory custody differs")
        return fd
    finally:
        os.close(parent_fd)


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(fd, data[offset:])


def _atomic_root_record(directory_fd: int, name: str, body: bytes) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,96}\.json", name) or len(body) > 128 * 1024:
        raise ProfileFileCustodyError("profile journal record is invalid")
    temporary = f".{name}.{secrets.token_hex(12)}.stage"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
    try:
        _write_all(fd, body)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.rename(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)


def _read_root_record(directory_fd: int, name: str) -> dict[str, Any] | None:
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
    except FileNotFoundError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= 128 * 1024):
            raise ProfileFileCustodyError("profile recovery record custody differs")
        raw = bytearray()
        while len(raw) <= 128 * 1024:
            part = os.read(fd, min(32 * 1024, 128 * 1024 + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        if len(raw) != info.st_size or _signature(os.fstat(fd)) != _signature(info):
            raise ProfileFileCustodyError("profile recovery record changed during read")
    finally:
        os.close(fd)
    try:
        value = json.loads(bytes(raw).decode("utf-8", "strict"))
    except (ValueError, UnicodeError):
        raise ProfileFileCustodyError("profile recovery record is invalid") from None
    if type(value) is not dict:
        raise ProfileFileCustodyError("profile recovery record schema differs")
    return value


def _atomic_owner_replace(directory_fd: int, name: str, body: bytes,
                          expected: ProfileFileRead, *, recovery_id: str) -> None:
    if not body or len(body) > MAX_FILE_BYTES:
        raise ProfileFileCustodyError("replacement profile file exceeds its bound")
    fresh = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    try:
        current, signature = _read_fd(fresh)
        current_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (signature != expected.signature or _signature(current_named) != expected.signature
                or hashlib.sha256(current).hexdigest() != expected.sha256):
            raise ProfileFileCustodyError("profile file changed before atomic replacement")
        old = os.fstat(fresh)
    finally:
        os.close(fresh)
    stage = f".{name}.jarvis-{secrets.token_hex(12)}.stage"
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), stat.S_IMODE(old.st_mode), dir_fd=directory_fd)
    try:
        os.fchown(fd, old.st_uid, old.st_gid)
        os.fchmod(fd, stat.S_IMODE(old.st_mode))
        _write_all(fd, body)
        # Preserve all existing xattrs. Fail closed if this platform cannot copy them.
        source_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        try:
            for attr in os.listxattr(source_fd):
                os.setxattr(fd, attr, os.getxattr(source_fd, attr))
        finally:
            os.close(source_fd)
        os.fsync(fd)
    finally:
        os.close(fd)
    current_named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _signature(current_named) != expected.signature:
        os.unlink(stage, dir_fd=directory_fd)
        raise ProfileFileCustodyError("profile file changed during atomic replacement")
    os.replace(stage, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)
    installed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if (not stat.S_ISREG(installed.st_mode) or installed.st_uid != old.st_uid
            or installed.st_gid != old.st_gid or stat.S_IMODE(installed.st_mode) != stat.S_IMODE(old.st_mode)
            or installed.st_nlink != 1):
        raise ProfileFileCustodyError("replacement profile file metadata differs")


def write_profile_file(profile_id: str, file_kind: str, *, expected_sha256: str,
                       content: str, idempotency_key: str,
                       core_source_generation: str) -> ProfileFileWrite:
    """Journal a private backup and atomically replace one existing exact source leaf.

    The caller must first establish the current signed Core custody, authenticate
    the owner, and resolve the profile against the current registry manifest.
    """
    if (not _ID.fullmatch(profile_id) or not _valid_leaf(file_kind)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
            or not _SAFE_IDEMPOTENCY.fullmatch(idempotency_key)
            or not re.fullmatch(r"[0-9a-f]{64}", core_source_generation)
            or not isinstance(content, str) or "\x00" in content):
        raise ProfileFileCustodyError("profile edit request is invalid")
    try:
        proposed = content.encode("utf-8", "strict")
    except UnicodeError:
        raise ProfileFileCustodyError("profile edit is not UTF-8") from None
    if not 0 < len(proposed) <= MAX_FILE_BYTES:
        raise ProfileFileCustodyError("profile edit exceeds its bound")
    if os.geteuid() != 0:
        raise ProfileFileCustodyError("root profile transaction is required")
    directory = _open_profile_directory(profile_id, native_default=profile_id == "hermes")
    backup_dir = _backup_directory()
    lock_name = f"{profile_id}-{file_kind}.lock"
    try:
        lock_fd = os.open(lock_name, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                          0o600, dir_fd=backup_dir)
        try:
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ProfileFileCustodyError("profile edit lock custody differs")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            existing = _read_profile_file(profile_id, file_kind)
            key_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
            journal_name = f"edit-{key_hash}.json"
            prior_journal = _read_root_record(backup_dir, journal_name)
            if prior_journal is not None:
                required = {"schema", "state", "profile_id", "file_kind", "file_name",
                    "core_source_generation", "base_sha256", "proposed_sha256",
                    "prior_signature", "backup_name", "idempotency_key_sha256",
                    "created_monotonic_ns"}
                journal_fields = set(prior_journal)
                if (journal_fields != required and journal_fields != required | {"readback_sha256"}):
                    raise ProfileFileCustodyError("profile idempotency record schema differs")
                if (prior_journal.get("schema") != 1
                        or prior_journal.get("profile_id") != profile_id
                        or prior_journal.get("file_kind") != file_kind
                        or prior_journal.get("file_name") != existing.file_name
                        or prior_journal.get("core_source_generation") != core_source_generation
                        or prior_journal.get("base_sha256") != expected_sha256
                        or prior_journal.get("proposed_sha256") != hashlib.sha256(proposed).hexdigest()
                        or prior_journal.get("idempotency_key_sha256") != key_hash
                        or prior_journal.get("state") not in {"prepared", "unknown-pending", "committed"}):
                    raise ProfileFileCustodyError("profile idempotency record belongs to another edit")
                recovery_id = prior_journal.get("backup_name", "").removesuffix(".backup")
                if not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", recovery_id):
                    raise ProfileFileCustodyError("profile idempotency recovery identity differs")
                if existing.sha256 == prior_journal["proposed_sha256"]:
                    if prior_journal["state"] != "committed":
                        prior_journal["state"] = "committed"
                        prior_journal["readback_sha256"] = existing.sha256
                        _atomic_root_record(backup_dir, journal_name,
                            json.dumps(prior_journal, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                    return ProfileFileWrite("active", profile_id, file_kind,
                        hashlib.sha256((core_source_generation + "\0" + existing.sha256).encode()).hexdigest(),
                        existing.sha256, recovery_id, True)
                if existing.sha256 == expected_sha256:
                    return ProfileFileWrite("unknown-pending", profile_id, file_kind,
                        None, None, recovery_id, False)
                return ProfileFileWrite("conflict", profile_id, file_kind, None, existing.sha256, None, False)
            if not secrets.compare_digest(existing.sha256, expected_sha256):
                return ProfileFileWrite("conflict", profile_id, file_kind, None, existing.sha256, None, False)
            recovery_id = secrets.token_urlsafe(24)
            backup_name = f"{recovery_id}.backup"
            backup_fd = os.open(backup_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=backup_dir)
            try:
                _write_all(backup_fd, existing.content.encode("utf-8"))
                os.fsync(backup_fd)
            finally:
                os.close(backup_fd)
            os.fsync(backup_dir)
            journal = {"schema": 1, "state": "prepared", "profile_id": profile_id,
                "file_kind": file_kind, "file_name": existing.file_name,
                "core_source_generation": core_source_generation,
                "base_sha256": existing.sha256, "proposed_sha256": hashlib.sha256(proposed).hexdigest(),
                "prior_signature": list(existing.signature), "backup_name": backup_name,
                "idempotency_key_sha256": key_hash,
                "created_monotonic_ns": time.monotonic_ns()}
            journal_name = f"edit-{key_hash}.json"
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            helper_request = json.dumps({"schema": 1, "op": "replace-profile-leaf",
                "profile_id": profile_id, "file_kind": file_kind,
                "expected_sha256": existing.sha256, "expected_signature": list(existing.signature),
                "content": content, "recovery_id": recovery_id},
                sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            try:
                child = subprocess.run(
                    [str(_CORE_PYTHON), "-I", str(Path(__file__).resolve()), "--profile-file-helper"],
                    input=helper_request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    timeout=3.0, check=False, close_fds=True, user=HOME_UID, group=HOME_GID,
                    extra_groups=(), cwd="/", env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"})
                helper_result = json.loads(child.stdout.decode("utf-8", "strict")) if child.returncode == 0 else None
            except Exception:
                helper_result = None
            if (type(helper_result) is not dict or set(helper_result) != {"ok", "sha256"}
                    or helper_result.get("ok") is not True
                    or helper_result.get("sha256") != hashlib.sha256(proposed).hexdigest()):
                journal["state"] = "unknown-pending"
                _atomic_root_record(backup_dir, journal_name,
                    json.dumps(journal, sort_keys=True, separators=(",", ":")).encode("utf-8"))
                return ProfileFileWrite("unknown-pending", profile_id, file_kind,
                    None, None, recovery_id, False)
            readback = _read_profile_file(profile_id, file_kind)
            if hashlib.sha256(proposed).hexdigest() != readback.sha256:
                raise ProfileFileCustodyError("profile write readback differs")
            journal["state"] = "committed"
            journal["readback_sha256"] = readback.sha256
            _atomic_root_record(backup_dir, journal_name,
                json.dumps(journal, sort_keys=True, separators=(",", ":")).encode("utf-8"))
            return ProfileFileWrite("active", profile_id, file_kind,
                readback.sha256, readback.sha256, recovery_id, True)
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory)
        os.close(backup_dir)


def _run_profile_file_helper(request: Any) -> dict[str, Any]:
    """Apply one exact file CAS while running with the Core owner UID."""
    if type(request) is dict and request.get("op") in {"replace-skill-entrypoint", "archive-skill-entrypoint"}:
        return _run_skill_file_helper(request)
    fields = {"schema", "op", "profile_id", "file_kind", "expected_sha256",
              "expected_signature", "content", "recovery_id"}
    if (os.geteuid() != HOME_UID or type(request) is not dict or set(request) != fields
            or request.get("schema") != 1 or request.get("op") != "replace-profile-leaf"
            or not isinstance(request.get("profile_id"), str)
            or not _ID.fullmatch(request["profile_id"])
            or not _valid_leaf(request.get("file_kind"))
            or not isinstance(request.get("expected_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", request["expected_sha256"])
            or type(request.get("expected_signature")) is not list
            or len(request["expected_signature"]) != 9
            or any(type(part) is not int or part < 0 for part in request["expected_signature"])
            or not isinstance(request.get("content"), str)
            or not isinstance(request.get("recovery_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", request["recovery_id"])):
        raise ProfileFileCustodyError("Core UID profile helper request is invalid")
    expected = _read_profile_file(request["profile_id"], request["file_kind"])
    if (expected.signature != tuple(request["expected_signature"])
            or not secrets.compare_digest(expected.sha256, request["expected_sha256"])):
        raise ProfileFileCustodyError("profile file changed before Core UID write")
    directory = _open_profile_directory(request["profile_id"],
        native_default=request["profile_id"] == "hermes")
    try:
        _atomic_owner_replace(directory, expected.file_name,
            request["content"].encode("utf-8", "strict"), expected,
            recovery_id=request["recovery_id"])
    finally:
        os.close(directory)
    readback = _read_profile_file(request["profile_id"], request["file_kind"])
    return {"ok": True, "sha256": readback.sha256}


def _run_skill_file_helper(request: dict[str, Any]) -> dict[str, Any]:
    fields = {"schema", "op", "skill_name", "expected_sha256", "expected_signature", "content", "recovery_id"}
    archive_fields = {"schema", "op", "skill_name", "expected_sha256", "expected_signature", "recovery_id"}
    is_archive = request.get("op") == "archive-skill-entrypoint"
    if (os.geteuid() != HOME_UID or set(request) != (archive_fields if is_archive else fields)
            or request.get("schema") != 1
            or not isinstance(request.get("skill_name"), str) or not _SKILL_ID.fullmatch(request["skill_name"])
            or not isinstance(request.get("expected_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", request["expected_sha256"])
            or type(request.get("expected_signature")) is not list
            or len(request["expected_signature"]) != 9
            or any(type(part) is not int or part < 0 for part in request["expected_signature"])
            or (not is_archive and (not isinstance(request.get("content"), str)
                or "\x00" in request["content"] or len(request["content"].encode("utf-8")) > MAX_FILE_BYTES))
            or not isinstance(request.get("recovery_id"), str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", request["recovery_id"])):
        raise ProfileFileCustodyError("Core UID skill helper request is invalid")
    existing = read_profile_skill("hermes", request["skill_name"])
    if (existing.signature != tuple(request["expected_signature"])
            or existing.sha256 != request["expected_sha256"]):
        raise ProfileFileCustodyError("native skill changed before Core UID write")
    directory = _open_skill_directory(request["skill_name"])
    try:
        if is_archive:
            info = os.stat("SKILL.md", dir_fd=directory, follow_symlinks=False)
            if _signature(info) != existing.signature:
                raise ProfileFileCustodyError("native skill changed before archive")
            os.unlink("SKILL.md", dir_fd=directory)
            os.fsync(directory)
            return {"ok": True, "archived": True}
        _atomic_owner_replace(directory, "SKILL.md", request["content"].encode("utf-8", "strict"),
                              existing, recovery_id=request["recovery_id"])
    finally:
        os.close(directory)
    readback = read_profile_skill("hermes", request["skill_name"])
    return {"ok": True, "sha256": readback.sha256}


def current_profile_files(profile_ids: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
    """Resolve manifest IDs to only already-existing native profile files."""
    if os.geteuid() != 0 or type(profile_ids) is not tuple or len(profile_ids) > 208:
        raise ProfileFileCustodyError("current Resources profile manifest is required")
    if len(set(profile_ids)) != len(profile_ids) or any(not _ID.fullmatch(i) for i in profile_ids):
        raise ProfileFileCustodyError("current Resources profile manifest is invalid")
    output = []
    for profile_id in profile_ids:
        found = []
        for kind in _FILE_NAMES:
            try:
                result = _read_profile_file(profile_id, kind)
            except FileNotFoundError:
                continue
            found.append({"kind": kind, "name": result.file_name, "sha256": result.sha256})
        if found:
            output.append({"profile_id": profile_id,
                "display_name": "Jarvis" if profile_id == "hermes" else profile_id,
                "kind": "jarvis" if profile_id == "hermes" else "expert",
                "source_generation": hashlib.sha256("\0".join(sorted(i["sha256"] for i in found)).encode()).hexdigest(),
                "files": found})
    return tuple(output)


if __name__ == "__main__" and sys.argv[1:] == ["--profile-file-helper"]:
    try:
        raw = sys.stdin.buffer.read(96 * 1024 + 1)
        if not raw or len(raw) > 96 * 1024:
            raise ProfileFileCustodyError("Core UID profile helper input is invalid")
        value = json.loads(raw.decode("utf-8", "strict"))
        result = _run_profile_file_helper(value)
        sys.stdout.write(json.dumps(result, separators=(",", ":")))
        raise SystemExit(0)
    except BaseException:
        # The helper emits only a closed failure exit, never paths or file contents.
        raise SystemExit(1)
