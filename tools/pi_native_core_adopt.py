#!/usr/bin/env python3
"""Transactionally adopt the active Pi Core and its fixed Jarvis ingress.

Run the read-only preflight first. This helper changes only the fixed
Inspector/Gateway unit import roots and the Gateway unit digest in its config;
the existing core_runtime API owns the Core/plugin migration and rollback.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import argparse
import base64
import hashlib
import json
import secrets
import shlex
import time
from pathlib import Path

GATEWAY = "hermes-jarvis-core-gateway.service"
INSPECTOR = "hermes-jarvis-core-inspector.service"
TUNNEL = "hermes-jarvis-mvp-tunnel.service"
FIXED_UNITS = {
    GATEWAY: Path("/etc/systemd/system/hermes-jarvis-core-gateway.service"),
    INSPECTOR: Path("/etc/systemd/system/hermes-jarvis-core-inspector.service"),
    TUNNEL: Path("/etc/systemd/system/hermes-jarvis-mvp-tunnel.service"),
}
GATEWAY_CONFIG = Path("/etc/hermes-installer/jarvis-core-gateway.json")
INGRESS_BACKUP = Path("/var/lib/hermes-installer/core-runtime/native-adoption-ingress-backup.json")
_SOURCE_PATH = re.compile(rb"/opt/hermes-installer-core-[0-9a-f]{9,64}/src\Z")


def _run(*args: str, check: bool = True) -> str:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, timeout=15,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("fixed systemd action is unavailable") from None
    if check and result.returncode:
        raise RuntimeError("fixed systemd action failed")
    return result.stdout.strip()


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _unit_state(name: str) -> str:
    return _run("systemctl", "is-active", name, check=False)


def _unit_is_exact_and_active(name: str) -> bool:
    return _unit_is_fixed(name) and _unit_state(name) == "active"


def _unit_is_fixed(name: str) -> bool:
    expected = FIXED_UNITS[name]
    fragment = _run("systemctl", "show", "--property=FragmentPath", "--value", name, check=False)
    dropins = _run("systemctl", "show", "--property=DropInPaths", "--value", name, check=False)
    return fragment == str(expected) and not dropins


def _read_fixed(path: Path, *, uid: int, gid: int, mode: int, maximum: int) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != uid or before.st_gid != gid
                or stat.S_IMODE(before.st_mode) != mode or before.st_nlink != 1
                or not 1 <= before.st_size <= maximum):
            raise RuntimeError("fixed migration input custody differs")
        chunks = bytearray()
        while len(chunks) <= maximum:
            block = os.read(fd, min(8192, maximum + 1 - len(chunks)))
            if not block:
                break
            chunks.extend(block)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (len(chunks) != before.st_size or len(chunks) > maximum
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                   != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError("fixed migration input changed during read")
        return bytes(chunks), before
    finally:
        os.close(fd)


def _unit_source(raw: bytes, module: str) -> bytes:
    expected = b"Environment=PYTHONPATH="
    rows = [line[len(expected):] for line in raw.splitlines() if line.startswith(expected)]
    if len(rows) != 1 or not _SOURCE_PATH.fullmatch(rows[0]):
        raise RuntimeError("fixed service does not name one known immutable source generation")
    if (b"ExecStart=" not in raw or raw.count(b"ExecStart=") != 1
            or b"-m hermes_installer.remote." + module.encode("ascii") not in raw):
        raise RuntimeError("fixed service entry point differs")
    return rows[0]


def _verify_installed_source(source: bytes) -> None:
    root = Path(source.decode("ascii", "strict"))
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RuntimeError("prior immutable source generation custody differs")
        for relative in ("hermes_installer/remote/core_gateway.py",
                         "hermes_installer/remote/core_gateway_inspector.py"):
            file_fd = os.open(relative, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            try:
                info = os.fstat(file_fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                        or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022):
                    raise RuntimeError("prior immutable ingress source file custody differs")
            finally:
                os.close(file_fd)
    finally:
        os.close(fd)


def _verify_inspector_process(raw: bytes, source: bytes) -> None:
    if not _unit_is_exact_and_active(INSPECTOR):
        raise RuntimeError("fixed Inspector unit ownership or state is not exact and active")
    try:
        text = raw.decode("ascii", "strict")
        exec_rows = [line[len("ExecStart="):] for line in text.splitlines()
                     if line.startswith("ExecStart=")]
        command = shlex.split(exec_rows[0], posix=True)
        if (len(exec_rows) != 1 or len(command) < 3
                or command[-2:] != ["-m", "hermes_installer.remote.core_gateway_inspector"]
                or not command[0].startswith("/opt/hermes-jarvis-mvp-")
                or not command[0].endswith("/gateway-venv/bin/python")):
            raise ValueError
        pid_text = _run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR)
        pid = int(pid_text)
        proc = Path("/proc") / str(pid)
        status = (proc / "status").read_text(encoding="ascii").splitlines()
        fields = {line.partition(":")[0]: line.partition(":")[2].split()
                  for line in status if line.partition(":")[0] in {"Uid", "Gid"}}
        argv = (proc / "cmdline").read_bytes().rstrip(b"\0").decode("utf-8", "strict").split("\0")
        cgroup = (proc / "cgroup").read_text(encoding="ascii").splitlines()
        executable = Path(os.readlink(proc / "exe")).resolve(strict=True)
        expected_executable = Path(command[0]).resolve(strict=True)
        if (pid <= 1 or len(fields.get("Uid", [])) < 2 or fields["Uid"][1] != "0"
                or len(fields.get("Gid", [])) < 2 or fields["Gid"][1] != "981"
                or argv != command or executable != expected_executable
                or f"0::/system.slice/{INSPECTOR}" not in cgroup
                or _unit_source(raw, "core_gateway_inspector") != source):
            raise ValueError
    except Exception:
        raise RuntimeError("fixed Inspector process is not bound to its exact unit/source") from None


def _replace_unit_source(raw: bytes, old: bytes, new: bytes) -> bytes:
    before = b"Environment=PYTHONPATH=" + old
    after = b"Environment=PYTHONPATH=" + new
    if raw.count(before) != 1:
        raise RuntimeError("fixed service import root changed")
    return raw.replace(before, after, 1)


def _atomic_fixed(path: Path, raw: bytes, *, uid: int, gid: int, mode: int) -> None:
    temporary = path.with_name("." + path.name + ".native-adoption-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short fixed-file write")
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    os.close(fd)
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _source_switch(candidate_source: Path):
    from hashlib import sha256

    if not _unit_is_exact_and_active(INSPECTOR):
        raise RuntimeError("fixed Inspector unit ownership or state is not exact and active")
    saved = {
        FIXED_UNITS[INSPECTOR]: _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                             mode=0o644, maximum=64 * 1024),
        FIXED_UNITS[GATEWAY]: _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                           mode=0o644, maximum=64 * 1024),
    }
    _verify_inspector_process(saved[FIXED_UNITS[INSPECTOR]][0],
                              _unit_source(saved[FIXED_UNITS[INSPECTOR]][0],
                                           "core_gateway_inspector"))
    config_raw, config_info = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                           mode=0o440, maximum=16 * 1024)
    try:
        config_value = json.loads(config_raw, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("fixed Gateway config is malformed") from None
    inspector_source = _unit_source(saved[FIXED_UNITS[INSPECTOR]][0], "core_gateway_inspector")
    gateway_source = _unit_source(saved[FIXED_UNITS[GATEWAY]][0], "core_gateway")
    if inspector_source != gateway_source or inspector_source.decode("ascii") == str(candidate_source):
        raise RuntimeError("Inspector/Gateway source generations are not one prior generation")
    _verify_installed_source(inspector_source)
    if (type(config_value) is not dict or config_value.get("gateway_unit_sha256")
            != sha256(saved[FIXED_UNITS[GATEWAY]][0]).hexdigest()):
        raise RuntimeError("Gateway config does not bind the current fixed Gateway unit")

    for name, (raw, _info) in saved.items():
        if _unit_state(INSPECTOR if name == FIXED_UNITS[INSPECTOR] else GATEWAY) != "active":
            raise RuntimeError("fixed ingress units must be active before adoption")
    new_units = {
        FIXED_UNITS[INSPECTOR]: _replace_unit_source(
            saved[FIXED_UNITS[INSPECTOR]][0], inspector_source, str(candidate_source).encode("ascii")),
        FIXED_UNITS[GATEWAY]: _replace_unit_source(
            saved[FIXED_UNITS[GATEWAY]][0], gateway_source, str(candidate_source).encode("ascii")),
    }
    config_value["gateway_unit_sha256"] = sha256(new_units[FIXED_UNITS[GATEWAY]]).hexdigest()
    new_config = (json.dumps(config_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(new_config) > 16 * 1024:
        raise RuntimeError("fixed Gateway config exceeded its bound")
    return saved, config_raw, config_info, new_units, new_config


def _save_ingress_backup(candidate_sha: str, saved, config_raw: bytes,
                         config_info: os.stat_result, new_units, new_config: bytes) -> None:
    parent = INGRESS_BACKUP.parent
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
            or parent_info.st_gid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise RuntimeError("fixed Core runtime directory custody differs")
    value = {
        "schema": 1, "state": "prepared", "candidate_sha": candidate_sha,
        "gateway_unit": base64.b64encode(saved[FIXED_UNITS[GATEWAY]][0]).decode("ascii"),
        "inspector_unit": base64.b64encode(saved[FIXED_UNITS[INSPECTOR]][0]).decode("ascii"),
        "gateway_config": base64.b64encode(config_raw).decode("ascii"),
        "gateway_mode": stat.S_IMODE(config_info.st_mode),
        "gateway_gid": config_info.st_gid,
        "new_gateway_sha256": hashlib.sha256(new_units[FIXED_UNITS[GATEWAY]]).hexdigest(),
        "new_inspector_sha256": hashlib.sha256(new_units[FIXED_UNITS[INSPECTOR]]).hexdigest(),
        "new_config_sha256": hashlib.sha256(new_config).hexdigest(),
        "old_gateway_sha256": hashlib.sha256(saved[FIXED_UNITS[GATEWAY]][0]).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(saved[FIXED_UNITS[INSPECTOR]][0]).hexdigest(),
        "old_config_sha256": hashlib.sha256(config_raw).hexdigest(),
    }
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    temporary = parent / (".native-adoption-backup-" + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short ingress rollback record write")
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        os.close(fd)
        temporary.unlink(missing_ok=True)
        raise
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    try:
        os.link(temporary, INGRESS_BACKUP, follow_symlinks=False)
    finally:
        temporary.unlink(missing_ok=True)
    dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                  | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _set_backup_state(state: str) -> None:
    raw, info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
    value = json.loads(raw, object_pairs_hook=_unique_pairs)
    if type(value) is not dict or value.get("schema") != 1:
        raise RuntimeError("fixed ingress rollback record is malformed")
    value["state"] = state
    replacement = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _atomic_fixed(INGRESS_BACKUP, replacement, uid=0, gid=0, mode=stat.S_IMODE(info.st_mode))


def _backup_value(candidate_sha: str) -> tuple[dict, bytes, bytes, bytes]:
    raw, _info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
        keys = {"schema", "state", "candidate_sha", "gateway_unit", "inspector_unit",
                "gateway_config", "gateway_mode", "gateway_gid", "old_gateway_sha256",
                "old_inspector_sha256", "old_config_sha256", "new_gateway_sha256",
                "new_inspector_sha256", "new_config_sha256"}
        if (type(value) is not dict or set(value) != keys or type(value["schema"]) is not int
                or value["schema"] != 1 or value["candidate_sha"] != candidate_sha
                or value["state"] not in {"prepared", "units-switched", "migrated", "recovery-required"}
                or value["gateway_mode"] != 0o440 or value["gateway_gid"] != 981):
            raise ValueError
        decoded = tuple(base64.b64decode(value[key], validate=True) for key in
                        ("gateway_unit", "inspector_unit", "gateway_config"))
        if any(not item or len(item) > 64 * 1024 for item in decoded):
            raise ValueError
        from hashlib import sha256
        if tuple(sha256(item).hexdigest() for item in decoded) != (
                value["old_gateway_sha256"], value["old_inspector_sha256"],
                value["old_config_sha256"]):
            raise ValueError
        return value, *decoded
    except Exception:
        raise RuntimeError("fixed ingress rollback record is malformed") from None


def _replace_ingress_units(new_units, new_config: bytes, config_info: os.stat_result) -> None:
    if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
        raise RuntimeError("fixed systemd unit ownership changed before source switch")
    _run("systemctl", "stop", TUNNEL)
    _run("systemctl", "stop", GATEWAY)
    _run("systemctl", "stop", INSPECTOR)
    _atomic_fixed(FIXED_UNITS[INSPECTOR], new_units[FIXED_UNITS[INSPECTOR]],
                  uid=0, gid=0, mode=0o644)
    _atomic_fixed(FIXED_UNITS[GATEWAY], new_units[FIXED_UNITS[GATEWAY]],
                  uid=0, gid=0, mode=0o644)
    _atomic_fixed(GATEWAY_CONFIG, new_config, uid=0, gid=config_info.st_gid,
                  mode=stat.S_IMODE(config_info.st_mode))
    _run("systemctl", "daemon-reload")


def _restore_old_ingress(value: dict, old_gateway: bytes, old_inspector: bytes,
                         old_config: bytes) -> bool:
    from hashlib import sha256

    try:
        if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
            raise RuntimeError("fixed systemd unit ownership changed before rollback")
        _run("systemctl", "stop", TUNNEL, check=False)
        _run("systemctl", "stop", GATEWAY, check=False)
        _run("systemctl", "stop", INSPECTOR, check=False)
        current_gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                          mode=0o644, maximum=64 * 1024)
        current_inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                            mode=0o644, maximum=64 * 1024)
        current_config, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                         mode=0o440, maximum=16 * 1024)
        if (sha256(current_gateway).hexdigest() not in
                {value["new_gateway_sha256"], sha256(old_gateway).hexdigest()}
                or sha256(current_inspector).hexdigest() not in
                {value["new_inspector_sha256"], sha256(old_inspector).hexdigest()}
                or sha256(current_config).hexdigest() not in
                {value["new_config_sha256"], sha256(old_config).hexdigest()}):
            raise RuntimeError("fixed ingress files changed outside this transaction")
        _atomic_fixed(FIXED_UNITS[INSPECTOR], old_inspector, uid=0, gid=0, mode=0o644)
        _atomic_fixed(FIXED_UNITS[GATEWAY], old_gateway, uid=0, gid=0, mode=0o644)
        _atomic_fixed(GATEWAY_CONFIG, old_config, uid=0, gid=value["gateway_gid"],
                      mode=value["gateway_mode"])
        _run("systemctl", "daemon-reload")
        _run("systemctl", "start", INSPECTOR)
        if (_unit_state(INSPECTOR) != "active"
                or not _unit_is_exact_and_active(INSPECTOR)):
            raise RuntimeError("old Inspector did not recover")
        _verify_inspector_process(old_inspector,
                                  _unit_source(old_inspector, "core_gateway_inspector"))
        _run("systemctl", "start", GATEWAY)
        if _unit_state(GATEWAY) != "active":
            raise RuntimeError("old Gateway did not recover")
        _run("systemctl", "start", TUNNEL)
        config = __import__("hermes_installer.remote.core_gateway", fromlist=["CoreGatewayConfig"]).CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_inspector_process(old_inspector,
                                  _unit_source(old_inspector, "core_gateway_inspector"))
        if not _verify_gateway_tunnel(config, require_active=True):
            raise RuntimeError("old Gateway/tunnel verification failed")
        if not all(_unit_state(name) == "active" for name in (INSPECTOR, GATEWAY, TUNNEL)):
            raise RuntimeError("old ingress cohort did not recover")
        return True
    except Exception:
        # A failed rollback must never leave a partly restored public ingress.
        for name in (TUNNEL, GATEWAY, INSPECTOR):
            try:
                _run("systemctl", "stop", name, check=False)
            except Exception:
                pass
        return False


def _verify_source_provenance(candidate_sha: str, source_root: Path) -> None:
    """Match the supplied full SHA to the root-stager's no-follow receipt."""
    generation = source_root.parent
    if (source_root != Path(f"/opt/hermes-installer-core-{candidate_sha[:9]}/src")
            or generation != Path(f"/opt/hermes-installer-core-{candidate_sha[:9]}")):
        raise RuntimeError("candidate source path does not match the supplied commit prefix")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    rootfd = os.open("/", flags)
    current = rootfd
    try:
        for component in generation.parts[1:]:
            child = os.open(component, flags, dir_fd=current)
            if current != rootfd:
                os.close(current)
            current = child
            info = os.fstat(current)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RuntimeError("candidate generation directory custody differs")
        source_fd = os.open("src", flags, dir_fd=current)
        try:
            source_info = os.fstat(source_fd)
            if (not stat.S_ISDIR(source_info.st_mode) or source_info.st_uid != 0
                    or source_info.st_gid != 0 or stat.S_IMODE(source_info.st_mode) & 0o022):
                raise RuntimeError("candidate source directory custody differs")
        finally:
            os.close(source_fd)
        receipt_fd = os.open(".source-provenance.json",
                             os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
        try:
            info = os.fstat(receipt_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                    or not 1 <= info.st_size <= 1024):
                raise RuntimeError("candidate provenance receipt custody differs")
            raw = bytearray()
            while len(raw) <= 1024:
                block = os.read(receipt_fd, min(1025 - len(raw), 512))
                if not block:
                    break
                raw.extend(block)
            if len(raw) != info.st_size or len(raw) > 1024:
                raise RuntimeError("candidate provenance receipt changed during read")
        finally:
            os.close(receipt_fd)
    finally:
        if current != rootfd:
            os.close(current)
        os.close(rootfd)
    try:
        value = json.loads(bytes(raw).decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError):
        raise RuntimeError("candidate provenance receipt is malformed") from None
    if (type(value) is not dict or set(value) != {"schema", "source_commit", "archive_sha256"}
            or type(value["schema"]) is not int or value["schema"] != 1
            or value["source_commit"] != candidate_sha
            or not isinstance(value["archive_sha256"], str)
            or re.fullmatch(r"[0-9a-f]{64}", value["archive_sha256"]) is None):
        raise RuntimeError("candidate provenance does not match the supplied full commit SHA")
    # Check the modules that define migration, process custody, observer RPC,
    # and the native Obsidian registration are still protected source files.
    for relative in (
            "hermes_installer/core_runtime.py",
            "hermes_installer/remote/core_gateway.py",
            "hermes_installer/remote/core_gateway_inspector.py",
            "hermes_installer/remote/core_native_observer.py",
            "hermes_installer/remote/obsidian_owner_lifecycle.py",
            "hermes_installer/remote/obsidian_native_tools.py",
            "hermes_installer/remote/jarvis_final_effects.py",
            "hermes_installer/components/resources_native_plugin_bundle/__init__.py"):
        path = source_root
        for part in Path(relative).parts[:-1]:
            path = path / part
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise RuntimeError("candidate native source directory custody differs")
        path = path / Path(relative).name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
                or info.st_size > 2 * 1024 * 1024):
            raise RuntimeError("candidate native source file custody differs")


def _verify_gateway_tunnel(config, *, require_active: bool) -> dict[str, bool]:
    """Validate fixed files and active process identity without reading environ/logs."""
    from hermes_installer.remote.core_gateway import (
        CORE_GATEWAY_UNIT_PATH, _read_config_current,
    )
    from hermes_installer.remote.core_gateway_inspector import (
        TUNNEL_EXECUTABLE, TUNNEL_UNIT_PATH, _check_unit_process, _protected_file_sha,
        _unit_properties,
    )

    _read_config_current(config)
    fixed_hashes = (
        (CORE_GATEWAY_UNIT_PATH, config.gateway_unit_sha256),
        (TUNNEL_UNIT_PATH, config.tunnel_unit_sha256),
        (TUNNEL_EXECUTABLE, config.cloudflared_binary_sha256),
    )
    deadline = time.monotonic() + 8.0
    for path, expected in fixed_hashes:
        if _protected_file_sha(path, deadline=deadline) != expected:
            raise RuntimeError("fixed gateway/tunnel file custody differs")

    active = {}
    for name in (GATEWAY, TUNNEL):
        state = _unit_state(name)
        fragment = _run("systemctl", "show", "--property=FragmentPath", "--value", name,
                        check=False)
        dropins = _run("systemctl", "show", "--property=DropInPaths", "--value", name,
                       check=False)
        if fragment != str(FIXED_UNITS[name]) or dropins != "":
            raise RuntimeError("gateway/tunnel unit path or drop-in custody differs")
        if state == "active":
            props = _unit_properties(name, deadline=deadline)
            pid = int(props.get("MainPID", "0"))
            peer_uid = peer_gid = None
            if name == TUNNEL:
                status = (Path("/proc") / str(pid) / "status").read_text(encoding="ascii")
                vectors = {line.split(":", 1)[0]: line.split(":", 1)[1].split()
                           for line in status.splitlines() if ":" in line
                           and line.split(":", 1)[0] in {"Uid", "Gid"}}
                peer_uid, peer_gid = int(vectors["Uid"][1]), int(vectors["Gid"][1])
            pidfd, _start, _invocation = _check_unit_process(
                config, unit=name, pid=pid, deadline=deadline,
                peer_uid=peer_uid, peer_gid=peer_gid)
            os.close(pidfd)
            active[name] = True
        elif state in {"inactive", "failed"}:
            if require_active:
                raise RuntimeError("gateway/tunnel is not active for the reviewed migration")
            active[name] = False
        else:
            raise RuntimeError("gateway/tunnel state is not stable")
    _read_config_current(config)
    return active


def _wait_observer_socket(*, previous_inode: tuple[int, int] | None = None) -> tuple[int, int]:
    from hermes_installer.remote.core_native_observer import CORE_NATIVE_OBSERVER_SOCKET

    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        try:
            info = CORE_NATIVE_OBSERVER_SOCKET.lstat()
            if (stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                    and info.st_gid == 1000 and stat.S_IMODE(info.st_mode) == 0o660):
                identity = (info.st_dev, info.st_ino)
                if previous_inode is None or identity != previous_inode:
                    return identity
        except FileNotFoundError:
            pass
        time.sleep(0.1)
    raise RuntimeError("fixed native-observer socket custody did not become ready")


def _restore_legacy_core(core_runtime) -> bool:
    if core_runtime._owned_listener(legacy_launcher=True):
        return True
    record = core_runtime._journal()
    if record.get("adapter_migration_state") == "preparing":
        core_runtime._recover_interrupted_adapter_migration()
        if core_runtime._owned_listener(legacy_launcher=True):
            return True
    if core_runtime._owned_listener():
        core_runtime.recover_owned_core_from_adapter_migration()
        return core_runtime._owned_listener(legacy_launcher=True)
    if not core_runtime._owned_unit_loaded():
        return False
    state = _unit_state(core_runtime.SERVICE)
    if state not in {"inactive", "failed"}:
        return False
    _run("systemctl", "start", core_runtime.SERVICE)
    return core_runtime._owned_listener(legacy_launcher=True)


def main() -> int:
    if os.geteuid() != 0:
        print("Run as root from the Pi browser terminal.", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-sha", required=True,
                        help="full qualified installer Git commit SHA (40 lowercase hex)")
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--apply", action="store_true",
                        help="switch fixed Inspector/Gateway generation and run the journaled Core migration")
    action.add_argument("--rollback", action="store_true",
                        help="restore the exact pre-adoption Core/plugin and Inspector/Gateway cohort")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha):
        parser.error("--candidate-sha must be a full lowercase 40-character Git commit SHA")
    expected_adapter_source = Path(
        f"/opt/hermes-installer-core-{args.candidate_sha[:9]}/src")

    try:
        _verify_source_provenance(args.candidate_sha, expected_adapter_source)
        sys.path.insert(0, str(expected_adapter_source))
        from hermes_installer import core_runtime
        actual_adapter = Path(core_runtime.__file__).resolve(strict=True).parents[1]
        if actual_adapter != expected_adapter_source:
            raise RuntimeError("loaded installer adapter is not the qualified fixed generation")
        core_runtime._validate_adapter_source_path()

        from hermes_installer.remote.core_gateway import CoreGatewayConfig
        from hermes_installer.remote.core_native_observer import CORE_NATIVE_OBSERVER_SOCKET

        if args.rollback:
            value, old_gateway, old_inspector, old_config = _backup_value(args.candidate_sha)
            source = str(expected_adapter_source).encode("ascii")
            current_gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                              mode=0o644, maximum=64 * 1024)
            current_inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                                mode=0o644, maximum=64 * 1024)
            current_config, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                             mode=0o440, maximum=16 * 1024)
            current_hashes = (hashlib.sha256(current_gateway).hexdigest(),
                              hashlib.sha256(current_inspector).hexdigest(),
                              hashlib.sha256(current_config).hexdigest())
            if (current_hashes[0] not in {value["new_gateway_sha256"], value["old_gateway_sha256"]}
                    or current_hashes[1] not in {value["new_inspector_sha256"], value["old_inspector_sha256"]}
                    or current_hashes[2] not in {value["new_config_sha256"], value["old_config_sha256"]}
                    or (current_hashes[0] == value["new_gateway_sha256"]
                        and _unit_source(current_gateway, "core_gateway") != source)
                    or (current_hashes[1] == value["new_inspector_sha256"]
                        and _unit_source(current_inspector, "core_gateway_inspector") != source)):
                raise RuntimeError("fixed ingress files differ from both saved transaction states")
            if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
                raise RuntimeError("fixed systemd unit ownership changed before Core rollback")
            _run("systemctl", "stop", TUNNEL)
            _run("systemctl", "stop", GATEWAY)
            if not _restore_legacy_core(core_runtime):
                raise RuntimeError("journaled Core rollback did not restore the legacy listener")
            if not _restore_old_ingress(value, old_gateway, old_inspector, old_config):
                _set_backup_state("recovery-required")
                raise RuntimeError("old Inspector/Gateway cohort did not recover; ingress remains stopped")
            INGRESS_BACKUP.unlink()
            print("Prior journal-owned Core/plugin and Inspector/Gateway/tunnel cohort restored.")
            return 0

        if INGRESS_BACKUP.exists() or INGRESS_BACKUP.is_symlink():
            raise RuntimeError("a prior adoption backup exists; use --rollback or inspect it first")
        config = CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_gateway_tunnel(config, require_active=True)
        if CORE_NATIVE_OBSERVER_SOCKET.exists() or CORE_NATIVE_OBSERVER_SOCKET.is_symlink():
            raise RuntimeError("unexpected preexisting native-observer socket blocks adoption")
        saved, old_config, config_info, new_units, new_config = _source_switch(expected_adapter_source)
        _save_ingress_backup(args.candidate_sha, saved, old_config, config_info,
                             new_units, new_config)
        old_gateway = saved[FIXED_UNITS[GATEWAY]][0]
        old_inspector = saved[FIXED_UNITS[INSPECTOR]][0]
        try:
            # Stop public ingress before switching the exact fixed import roots.
            # Start the new Inspector on the still-legacy Core first; it must
            # bind the current P-less process before the owner prestart step.
            _replace_ingress_units(new_units, new_config, config_info)
            _set_backup_state("units-switched")
            _run("systemctl", "start", INSPECTOR)
            if not _unit_is_exact_and_active(INSPECTOR):
                raise RuntimeError("new fixed Inspector did not become active")
            _verify_inspector_process(new_units[FIXED_UNITS[INSPECTOR]],
                                      str(expected_adapter_source).encode("ascii"))
            observer_identity = _wait_observer_socket()

            from hermes_installer.remote.obsidian_owner_lifecycle import (
                prepare_sole_existing_chat_owner_for_legacy_migration,
            )
            prepare_sole_existing_chat_owner_for_legacy_migration()

            # Keep both public ingress units stopped through owner preparation,
            # Core migration and fresh Inspector binding to the new Core PID.
            result = core_runtime.migrate_owned_core_to_adapter_path()
            if not core_runtime._owned_listener():
                raise RuntimeError("migrated core listener did not verify")
            _set_backup_state("migrated")

            # Refresh pidfd-bound Inspector custody after the Core PID changes.
            _run("systemctl", "restart", INSPECTOR)
            if not _unit_is_exact_and_active(INSPECTOR):
                raise RuntimeError("new fixed Inspector did not recover after Core migration")
            observer_identity = _wait_observer_socket(previous_inode=observer_identity)
            _run("systemctl", "start", GATEWAY)
            _run("systemctl", "start", TUNNEL)
            config = CoreGatewayConfig.load(expected_owner_uid=0)
            _verify_gateway_tunnel(config, require_active=True)
            print(result)
            print("New Inspector and Gateway use the same verified immutable source generation.")
            print("Selected-owner registration and fixed observer socket metadata were verified.")
            print("Peer protocol, native tool registration, and Obsidian read/write effects remain separate Pi witnesses.")
            print("Owner enrollment/vault preparation persist if Core/plugin rollback is needed.")
            print("Exact rollback command: rerun this helper with the same --candidate-sha and --rollback.")
            return 0
        except Exception as error:
            recovered = False
            try:
                _run("systemctl", "stop", TUNNEL, check=False)
                _run("systemctl", "stop", GATEWAY, check=False)
                recovered = _restore_legacy_core(core_runtime)
            except Exception:
                recovered = False
            restored = (_restore_old_ingress(_backup_value(args.candidate_sha)[0],
                                              old_gateway, old_inspector, old_config)
                        if recovered else False)
            if restored:
                INGRESS_BACKUP.unlink(missing_ok=True)
            else:
                _set_backup_state("recovery-required")
            print("Adoption did not complete; Core rollback was delegated to its journaled recovery API.")
            print("Prior Core verified: " + ("yes" if recovered else "no"))
            print("Prior Inspector/Gateway/tunnel cohort restored: " + ("yes" if restored else "no; ingress remains stopped"))
            print("Failure type: " + type(error).__name__)
            return 4
    except Exception as error:
        print("Adoption helper stopped before claiming success: " + type(error).__name__, file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
