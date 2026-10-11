"""Root-only enrollment and preparation for the fixed Jarvis Obsidian vault."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from typing import Any


OWNER_REGISTRATION = Path("/var/lib/hermes-installer/core-runtime/obsidian-registration.json")
OWNER_DATA_ROOT = Path("/home/admin/.hermes/jarvis-second-brain")
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OWNER_REGISTRATION_KEYS = {"schema", "core_uid", "data_root", "owner_subject_sha256"}


class ObsidianOwnerLifecycleError(RuntimeError):
    """Fixed root enrollment/preparation could not be verified."""


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate owner registration key")
        result[key] = value
    return result


def read_registration() -> tuple[Path, str, str]:
    """Read registration bytes through fixed root-owned no-follow directory FDs."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open("/", flags)
    try:
        for index, component in enumerate(("var", "lib", "hermes-installer", "core-runtime")):
            child = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = child
            info = os.fstat(current)
            mode = stat.S_IMODE(info.st_mode)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or mode & 0o022 or (index == 3 and mode != 0o700)):
                raise ObsidianOwnerLifecycleError("registration directory custody differs")
        fd = os.open(OWNER_REGISTRATION.name,
                     os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 1 <= info.st_size <= 2048):
                raise ObsidianOwnerLifecycleError("registration file custody differs")
            raw = bytearray()
            while len(raw) <= 2048:
                chunk = os.read(fd, 2049 - len(raw))
                if not chunk:
                    break
                raw.extend(chunk)
            if len(raw) != info.st_size or len(raw) > 2048:
                raise ObsidianOwnerLifecycleError("registration file size changed")
        finally:
            os.close(fd)
    finally:
        os.close(current)
    try:
        value = json.loads(bytes(raw).decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
        if (type(value) is not dict or set(value) != _OWNER_REGISTRATION_KEYS
                or type(value["schema"]) is not int or value["schema"] != 1
                or type(value["core_uid"]) is not int or value["core_uid"] != 1000
                or value["data_root"] != str(OWNER_DATA_ROOT)
                or not isinstance(value["owner_subject_sha256"], str)
                or _HASH.fullmatch(value["owner_subject_sha256"]) is None
                or json.dumps(value, sort_keys=True, separators=(",", ":"),
                              allow_nan=False).encode("utf-8") != bytes(raw)):
            raise ValueError
    except Exception:
        raise ObsidianOwnerLifecycleError("selected owner registration is malformed") from None
    return OWNER_DATA_ROOT, value["owner_subject_sha256"], hashlib.sha256(raw).hexdigest()


def _existing_chat_owners() -> tuple[str, ...]:
    from .jarvis_chat import CHAT_STATE_DIRECTORY, CHAT_STORE_PATH

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for component in CHAT_STATE_DIRECTORY.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 1000
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ObsidianOwnerLifecycleError("existing Jarvis owner database directory is unavailable")
        dbfd = os.open(CHAT_STORE_PATH.name,
                       os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            info = os.fstat(dbfd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 1000
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size < 1):
                raise ObsidianOwnerLifecycleError("existing Jarvis owner database custody differs")
            uri = f"file:/proc/self/fd/{dbfd}?mode=ro&immutable=1"
            with sqlite3.connect(uri, uri=True, timeout=1) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(conversations)")}
                if not {"id", "owner"} <= columns:
                    raise ValueError
                rows = db.execute("SELECT DISTINCT owner FROM conversations ORDER BY owner LIMIT 3").fetchall()
        except Exception:
            raise ObsidianOwnerLifecycleError("existing Jarvis owner scope could not be read") from None
        finally:
            os.close(dbfd)
    finally:
        os.close(fd)
    owners = tuple(row[0] for row in rows)
    if (not owners or len(owners) != 1 or not isinstance(owners[0], str)
            or _HASH.fullmatch(owners[0]) is None):
        raise ObsidianOwnerLifecycleError("database does not have one exact existing Jarvis owner scope")
    return owners


def _current_core(config: Any) -> tuple[int, str, str]:
    from .core_gateway_inspector import CORE_SERVICE_UNIT, _check_unit_process, _unit_properties
    deadline = time.monotonic() + 3.0
    props = _unit_properties(CORE_SERVICE_UNIT, deadline=deadline)
    pid = int(props.get("MainPID", "0"))
    if pid <= 1 or config.core_uid != 1000:
        raise ObsidianOwnerLifecycleError("selected UID-1000 Core service is unavailable")
    pidfd, start_ticks = _check_unit_process(config, unit=CORE_SERVICE_UNIT,
                                             pid=pid, deadline=deadline)
    try:
        return pid, start_ticks, props.get("InvocationID", "")
    finally:
        os.close(pidfd)


def _prepare_as_core(owner_subject_sha256: str) -> None:
    pid = os.fork()
    if pid == 0:
        try:
            os.setgroups([])
            os.setgid(1000)
            os.setuid(1000)
            from .obsidian_second_brain import (
                ObsidianVaultConfig, prepare_obsidian_vault,
                prepare_selected_owner_data_root,
            )
            data_root = prepare_selected_owner_data_root()
            prepare_obsidian_vault(ObsidianVaultConfig(
                data_root, owner_subject_sha256, owner_uid=1000))
            os._exit(0)
        except BaseException:
            os._exit(1)
    _pid, status = os.waitpid(pid, 0)
    if status != 0:
        raise ObsidianOwnerLifecycleError("UID-1000 vault preparation failed")


def _write_registration(owner_subject_sha256: str) -> None:
    root = Path("/var/lib/hermes-installer")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
        raise ObsidianOwnerLifecycleError("installer runtime registration parent custody differs")
    target_dir = root / "core-runtime"
    try:
        target_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    directory = target_dir.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or directory.st_gid != 0
            or stat.S_IMODE(directory.st_mode) != 0o700):
        raise ObsidianOwnerLifecycleError("installer core runtime directory custody differs")
    body = {"schema": 1, "core_uid": 1000, "data_root": str(OWNER_DATA_ROOT),
            "owner_subject_sha256": owner_subject_sha256}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    path = target_dir / OWNER_REGISTRATION.name
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None:
        _, current_owner, current_digest = read_registration()
        if current_owner != owner_subject_sha256:
            raise ObsidianOwnerLifecycleError("existing owner registration differs; explicit root recovery is required")
        # Idempotent only for an identical fixed registration.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            current_raw = os.read(fd, 2049)
        finally:
            os.close(fd)
        if current_raw != raw or not current_digest:
            raise ObsidianOwnerLifecycleError("existing owner registration changed")
        return
    temporary = target_dir / (".obsidian-registration-" + os.urandom(16).hex())
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short registration write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        os.link(temporary, path, follow_symlinks=False)
        os.unlink(temporary)
        dfd = os.open(target_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                      | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    if read_registration()[:2] != (OWNER_DATA_ROOT, owner_subject_sha256):
        raise ObsidianOwnerLifecycleError("selected owner registration failed readback")


def prepare_existing_chat_owner(owner_subject_sha256: str) -> dict[str, Any]:
    """Root-only explicit migration for the sole owner already present in Jarvis chat DB."""
    if os.geteuid() != 0 or not isinstance(owner_subject_sha256, str) or not _HASH.fullmatch(owner_subject_sha256):
        raise ObsidianOwnerLifecycleError("root and one exact owner scope selector are required")
    from .core_gateway import CoreGatewayConfig, _read_config_current
    config = CoreGatewayConfig.load(expected_owner_uid=0)
    if len(config.allowed_emails) != 1 or config.core_uid != 1000:
        raise ObsidianOwnerLifecycleError("one allowlisted selected-owner Core scope is required")
    _read_config_current(config)
    before = _current_core(config)
    if _existing_chat_owners() != (owner_subject_sha256,):
        raise ObsidianOwnerLifecycleError("selector does not name the sole current existing Jarvis DB owner")
    _prepare_as_core(owner_subject_sha256)
    if _current_core(config) != before:
        raise ObsidianOwnerLifecycleError("Core process changed during vault preparation")
    _write_registration(owner_subject_sha256)
    _read_config_current(config)
    return {"schema": 1, "state": "prepared", "owner_subject_sha256": owner_subject_sha256,
            "data_root": str(OWNER_DATA_ROOT), "vault_root": str(OWNER_DATA_ROOT / "obsidian-vault"),
            "owner_uid": 1000, "mode": "0700"}


__all__ = ["OWNER_DATA_ROOT", "OWNER_REGISTRATION", "ObsidianOwnerLifecycleError",
           "prepare_existing_chat_owner", "read_registration"]
