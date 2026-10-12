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
NATIVE_OBSERVER_DIRECTORY = Path("/run/hermes-jarvis-native-observer")
NATIVE_OBSERVER_PRESTART = (
    "ExecStartPre=/usr/bin/install -d -o root -g 1000 -m 0750 "
    "/run/hermes-jarvis-native-observer")
NATIVE_OBSERVER_READ_WRITE = "ReadWritePaths=/var/lib/hermes-installer/core-runtime"
NATIVE_OBSERVER_SUPPLEMENTARY_GROUPS = "SupplementaryGroups=1000"
_SOURCE_PATH = re.compile(rb"/opt/hermes-installer-core-[0-9a-f]{9,64}/src\Z")


def _wait_legacy_listener(core_runtime, *, timeout: float = 30.0) -> None:
    """Bounded readiness wait for the exact old launcher after recovery start."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if core_runtime._owned_listener(legacy_launcher=True):
            return
        time.sleep(1.0)
    raise RuntimeError("restored legacy Core listener did not become current")

_CORE_MIGRATION_REASON_CODES = {
    "requires installed Linux root actor": "root_actor_required",
    "prior plugin selection snapshot is not verified": "prior_selection_snapshot_unverified",
    "prior plugin selection could not be journaled; migration was not started": "prior_selection_journal_failed",
    "native bridge activation did not verify the fixed plugin": "native_plugin_activation_unverified",
    "native plugin selection is not currently verified": "native_plugin_selection_unverified",
    "native bridge activation is not current": "native_bridge_generation_unverified",
    "adapter activation failed; protected migration backup retained": "activation_failed_backup_retained",
    "native bridge activation is unavailable; existing core remains active": "native_bridge_unavailable",
    "journal-owned core changed during native bridge activation": "core_changed_during_activation",
    "service unit ownership changed before restart": "unit_ownership_changed_before_restart",
    "adapter core post-restart custody is not current": "post_restart_custody_unverified",
    "adapter core journal proof differs after restart": "post_restart_journal_unverified",
    "service unit changed during migration rollback": "unit_changed_during_rollback",
    "service process is no longer the journal-owned core": "core_process_ownership_lost",
    "prior owned core did not recover after migration rollback": "prior_core_recovery_failed",
    "adapter migration failed; protected backup retained for fixed recovery": "migration_failed_backup_retained",
    "adapter migration failed; original core service files and journal were restored": "migration_failed_prior_files_restored",
    "no exact active adapter migration is eligible for recovery": "recovery_state_not_eligible",
    "current migrated core identity is not verified; ingress remains stopped": "recovery_core_identity_unverified",
    "current adapter generation or selected plugin changed": "recovery_adapter_selection_changed",
    "current migration custody could not be reverified": "recovery_custody_unverified",
    "adapter migration backup custody differs": "recovery_backup_custody_invalid",
    "adapter migration backup has unexpected entries": "recovery_backup_entries_invalid",
    "adapter migration backup manifest invalid": "recovery_backup_manifest_invalid",
    "active journal does not bind the exact migration backup": "recovery_backup_not_journal_bound",
    "prior owned core backup is not the exact reviewed legacy cohort": "recovery_legacy_backup_unverified",
    "prior core journal backup is invalid": "recovery_prior_journal_invalid",
    "prior core journal does not bind the legacy cohort": "recovery_prior_journal_mismatch",
    "prior plugin selection backup bytes changed": "recovery_plugin_backup_changed",
    "migrated core changed during recovery preflight": "recovery_core_changed_during_preflight",
    "owned adapter core did not stop cleanly; recovery halted": "recovery_core_stop_failed",
    "restored prior service unit is not the exact owned unit": "recovery_prior_unit_unverified",
    "restored legacy core cohort differs from its retained backup": "recovery_legacy_cohort_mismatch",
    "prior Hermes plugin selection is not current after recovery": "recovery_prior_plugin_selection_unverified",
    "bounded migration recovery failed; protected backup retained and ingress remains stopped": "recovery_failed_backup_retained",
}


def _core_migration_reason_code(core_runtime, error: BaseException) -> str | None:
    """Map only exact, reviewed CoreRuntimeError messages to fixed safe codes."""
    error_type = getattr(core_runtime, "CoreRuntimeError", None)
    if type(error) is not error_type or len(error.args) != 1 or type(error.args[0]) is not str:
        return None
    return _CORE_MIGRATION_REASON_CODES.get(error.args[0])


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
        "post_core_config_sha256": None,
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


def _set_runtime_inspector_digest(candidate_sha: str, base_digest: str,
                                  runtime_digest: str) -> None:
    """Journal the exact fixed Inspector repair before replacing its unit bytes."""
    value, info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
    try:
        record = json.loads(value, object_pairs_hook=_unique_pairs)
        if (type(record) is not dict or record.get("schema") != 1
                or record.get("candidate_sha") != candidate_sha
                or record.get("new_inspector_sha256") != base_digest
                or (record.get("runtime_inspector_sha256") not in (None, runtime_digest))):
            raise ValueError
        record["runtime_inspector_sha256"] = runtime_digest
    except Exception:
        raise RuntimeError("protected Inspector repair journal changed") from None
    replacement = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _atomic_fixed(INGRESS_BACKUP, replacement, uid=0, gid=0, mode=stat.S_IMODE(info.st_mode))


def _runtime_repaired_inspector(raw: bytes) -> bytes:
    """Add only the fixed observer runtime setup and private sidecar write path."""
    try:
        lines = raw.decode("ascii", "strict").splitlines()
    except UnicodeError:
        raise RuntimeError("fixed Inspector unit is not ASCII") from None
    if lines.count("[Service]") != 1:
        raise RuntimeError("fixed Inspector unit Service section is not unique")
    service_start = lines.index("[Service]") + 1
    service_end = next((i for i in range(service_start, len(lines))
                        if lines[i].startswith("[")), len(lines))
    service = lines[service_start:service_end]
    required = {"User=root", "Group=981", "ProtectSystem=strict"}
    if not required.issubset(set(service)):
        raise RuntimeError("fixed Inspector runtime security contract differs")
    runtime_dirs = [line for line in service if line.startswith("RuntimeDirectory=")]
    if runtime_dirs == ["RuntimeDirectory=hermes-jarvis-mvp-core hermes-jarvis-native-observer:root:admin"]:
        bad_runtime_line = runtime_dirs[0]
        lines[lines.index(bad_runtime_line)] = "RuntimeDirectory=hermes-jarvis-mvp-core"
        service = lines[service_start:service_end]
    if ([line for line in service if line.startswith("RuntimeDirectory=")] !=
            ["RuntimeDirectory=hermes-jarvis-mvp-core"]
            or [line for line in service if line.startswith("RuntimeDirectoryMode=")] !=
            ["RuntimeDirectoryMode=0750"]):
        raise RuntimeError("fixed Inspector runtime-directory contract differs")
    additions = (NATIVE_OBSERVER_PRESTART, NATIVE_OBSERVER_READ_WRITE,
                 NATIVE_OBSERVER_SUPPLEMENTARY_GROUPS)
    for prefix, expected in (("ExecStartPre=", NATIVE_OBSERVER_PRESTART),
                             ("ReadWritePaths=", NATIVE_OBSERVER_READ_WRITE),
                             ("SupplementaryGroups=", NATIVE_OBSERVER_SUPPLEMENTARY_GROUPS)):
        rows = [line for line in service if line.startswith(prefix)]
        if rows and rows != [expected]:
            raise RuntimeError("fixed Inspector has an unexpected runtime-access directive")
    repaired = [line for line in additions if line not in service]
    return ("\n".join(lines[:service_end] + repaired + lines[service_end:]) + "\n").encode("ascii")


def _backup_value(candidate_sha: str) -> tuple[dict, bytes, bytes, bytes]:
    raw, _info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
        keys = {"schema", "state", "candidate_sha", "gateway_unit", "inspector_unit",
                "gateway_config", "gateway_mode", "gateway_gid", "old_gateway_sha256",
                "old_inspector_sha256", "old_config_sha256", "new_gateway_sha256",
                "new_inspector_sha256", "new_config_sha256", "post_core_config_sha256",
                "runtime_inspector_sha256"}
        legacy_keys = keys - {"post_core_config_sha256", "runtime_inspector_sha256"}
        if type(value) is dict and set(value) == legacy_keys:
            value["post_core_config_sha256"] = None
            value["runtime_inspector_sha256"] = None
        elif type(value) is dict and set(value) == keys - {"runtime_inspector_sha256"}:
            value["runtime_inspector_sha256"] = None
        if (type(value) is not dict or set(value) != keys or type(value["schema"]) is not int
                or value["schema"] != 1 or value["candidate_sha"] != candidate_sha
                or value["state"] not in {"prepared", "units-switched", "migrated", "recovery-required"}
                or value["gateway_mode"] != 0o440 or value["gateway_gid"] != 981
                or (value["post_core_config_sha256"] is not None
                    and (not isinstance(value["post_core_config_sha256"], str)
                         or re.fullmatch(r"[0-9a-f]{64}", value["post_core_config_sha256"]) is None))
                or (value["runtime_inspector_sha256"] is not None
                    and (not isinstance(value["runtime_inspector_sha256"], str)
                         or re.fullmatch(r"[0-9a-f]{64}", value["runtime_inspector_sha256"]) is None))):
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


def _refresh_migrated_core_config(candidate_sha: str, expected_source: Path,
                                  core_runtime) -> bytes:
    """CAS-update only Core digests from the exact active migration journal."""
    value, old_gateway, old_inspector, old_config = _backup_value(candidate_sha)
    if value["state"] not in {"migrated", "recovery-required"}:
        raise RuntimeError("adoption backup is not in a resumable Core-migrated state")
    current_raw, config_info = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                            mode=0o440, maximum=16 * 1024)
    current_sha = hashlib.sha256(current_raw).hexdigest()
    if current_sha not in {value["new_config_sha256"], value["post_core_config_sha256"]}:
        raise RuntimeError("Gateway config is outside the saved adoption transaction")

    record = core_runtime._journal()
    if (type(record) is not dict or record.get("state") not in {"installed", "active"}
            or record.get("adapter_migration_state") != "active"
            or record.get("adapter_source") != str(expected_source)
            or not isinstance(record.get("adapter_generation"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["adapter_generation"]) is None
            or not core_runtime._owned_listener()):
        raise RuntimeError("current journal does not prove the active candidate Core")
    unit_raw, _ = _read_fixed(core_runtime.UNIT, uid=0, gid=0, mode=0o644, maximum=64 * 1024)
    launcher_raw, _ = _read_fixed(core_runtime.LAUNCHER, uid=0, gid=0, mode=0o755,
                                    maximum=64 * 1024)
    unit_sha, launcher_sha = hashlib.sha256(unit_raw).hexdigest(), hashlib.sha256(launcher_raw).hexdigest()
    if record.get("unit_sha256") != unit_sha or record.get("launcher_sha256") != launcher_sha:
        raise RuntimeError("fixed Core files differ from their current journal digests")

    if current_sha == value["post_core_config_sha256"]:
        existing = json.loads(current_raw, object_pairs_hook=_unique_pairs)
        if (type(existing) is not dict or existing.get("core_unit_sha256") != unit_sha
                or existing.get("core_launcher_sha256") != launcher_sha):
            raise RuntimeError("recorded post-Core config does not bind current journal digests")
        return current_raw
    old_source = _unit_source(old_gateway, "core_gateway")
    if _unit_source(old_inspector, "core_gateway_inspector") != old_source:
        raise RuntimeError("saved ingress units do not share one prior source generation")
    switched_gateway = _replace_unit_source(
        old_gateway, old_source, str(expected_source).encode("ascii"))
    switched_inspector = _replace_unit_source(
        old_inspector, old_source, str(expected_source).encode("ascii"))
    if (hashlib.sha256(switched_gateway).hexdigest() != value["new_gateway_sha256"]
            or hashlib.sha256(switched_inspector).hexdigest() != value["new_inspector_sha256"]):
        raise RuntimeError("saved units do not derive the recorded candidate generation")
    try:
        updated = json.loads(old_config, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("saved Gateway config is malformed") from None
    if (type(updated) is not dict
            or updated.get("gateway_unit_sha256") != hashlib.sha256(old_gateway).hexdigest()):
        raise RuntimeError("saved Gateway config does not bind the saved prior unit")
    updated["gateway_unit_sha256"] = hashlib.sha256(switched_gateway).hexdigest()
    switched_config = (json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if (len(switched_config) > 16 * 1024
            or hashlib.sha256(switched_config).hexdigest() != value["new_config_sha256"]):
        raise RuntimeError("saved config does not derive the recorded candidate transaction")
    if current_raw != switched_config:
        raise RuntimeError("pre-Core Gateway config bytes differ from the saved transaction")
    updated["core_unit_sha256"] = unit_sha
    updated["core_launcher_sha256"] = launcher_sha
    replacement = (json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(replacement) > 16 * 1024:
        raise RuntimeError("fixed Gateway config exceeded its bound")
    replacement_sha = hashlib.sha256(replacement).hexdigest()
    if value["post_core_config_sha256"] is not None:
        if replacement_sha != value["post_core_config_sha256"]:
            raise RuntimeError("recorded post-Core config digest differs from current journal")
    else:
        value["post_core_config_sha256"] = replacement_sha
        _raw, backup_info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600,
                                         maximum=128 * 1024)
        backup_bytes = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _atomic_fixed(INGRESS_BACKUP, backup_bytes, uid=0, gid=0, mode=stat.S_IMODE(backup_info.st_mode))
    _atomic_fixed(GATEWAY_CONFIG, replacement, uid=0, gid=config_info.st_gid,
                  mode=stat.S_IMODE(config_info.st_mode))
    return replacement


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
                {value["new_inspector_sha256"], value.get("runtime_inspector_sha256"),
                 sha256(old_inspector).hexdigest()}
                or sha256(current_config).hexdigest() not in
                {value["new_config_sha256"], value.get("post_core_config_sha256"),
                 sha256(old_config).hexdigest()}):
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


def _resume_adoption(candidate_sha: str, expected_source: Path, core_runtime,
                     CoreGatewayConfig, observer_socket: Path) -> None:
    """Resume only the saved candidate transaction with its current active Core."""
    value, _old_gateway, _old_inspector, _old_config = _backup_value(candidate_sha)
    if value["state"] != "recovery-required":
        raise RuntimeError("resume requires the matching recovery-required transaction")
    if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
        raise RuntimeError("fixed ingress unit ownership changed before resume")
    if _unit_state(GATEWAY) != "inactive" or _unit_state(TUNNEL) != "inactive":
        raise RuntimeError("Gateway and tunnel must remain stopped before resume")

    gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                              mode=0o644, maximum=64 * 1024)
    inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                mode=0o644, maximum=64 * 1024)
    inspector_sha = hashlib.sha256(inspector).hexdigest()
    expected_runtime_inspector = _runtime_repaired_inspector(inspector)
    runtime_inspector_sha = hashlib.sha256(expected_runtime_inspector).hexdigest()
    if (hashlib.sha256(gateway).hexdigest() != value["new_gateway_sha256"]
            or inspector_sha not in {value["new_inspector_sha256"],
                                     value.get("runtime_inspector_sha256")}
            or _unit_source(gateway, "core_gateway") != str(expected_source).encode("ascii")
            or _unit_source(inspector, "core_gateway_inspector") != str(expected_source).encode("ascii")
            or not _unit_is_exact_and_active(INSPECTOR)):
        raise RuntimeError("fixed Inspector and Gateway do not match the saved candidate")
    _verify_inspector_process(inspector, str(expected_source).encode("ascii"))

    config_raw, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                 mode=0o440, maximum=16 * 1024)
    config_digest = hashlib.sha256(config_raw).hexdigest()
    if config_digest not in {value["new_config_sha256"], value["post_core_config_sha256"]}:
        raise RuntimeError("Gateway config does not match a saved resume state")

    phase = "refresh config from current journal-owned Core"
    print("Resume phase: " + phase, flush=True)
    refreshed = _refresh_migrated_core_config(candidate_sha, expected_source, core_runtime)
    config = CoreGatewayConfig.load(expected_owner_uid=0)
    _verify_gateway_tunnel(config, require_active=False)
    if refreshed != _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                 mode=0o440, maximum=16 * 1024)[0]:
        raise RuntimeError("refreshed Core config changed before Inspector restart")

    previous_inode = None
    try:
        socket_info = observer_socket.lstat()
        if (not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0
                or socket_info.st_gid != 1000 or stat.S_IMODE(socket_info.st_mode) != 0o660):
            raise RuntimeError("preexisting native observer socket custody differs")
        previous_inode = (socket_info.st_dev, socket_info.st_ino)
    except FileNotFoundError:
        pass

    try:
        phase = "restart Inspector with journal-current Core digests"
        print("Resume phase: " + phase, flush=True)
        _run("systemctl", "restart", INSPECTOR)
        if not _unit_is_exact_and_active(INSPECTOR):
            raise RuntimeError("candidate Inspector did not recover during resume")
        _verify_inspector_process(inspector, str(expected_source).encode("ascii"))
        phase = "verify fresh native observer socket"
        print("Resume phase: " + phase, flush=True)
        observer_identity = _wait_observer_socket(previous_inode=previous_inode)
        phase = "journal and install persistent native observer runtime access"
        print("Resume phase: " + phase, flush=True)
        if inspector_sha != runtime_inspector_sha:
            if inspector_sha != value["new_inspector_sha256"]:
                raise RuntimeError("fixed Inspector differs from both journaled runtime states")
            _set_runtime_inspector_digest(candidate_sha, inspector_sha, runtime_inspector_sha)
            _atomic_fixed(FIXED_UNITS[INSPECTOR], expected_runtime_inspector,
                          uid=0, gid=0, mode=0o644)
            _run("systemctl", "daemon-reload")
            phase = "restart Inspector with persistent observer runtime access"
            print("Resume phase: " + phase, flush=True)
            _run("systemctl", "restart", INSPECTOR)
            if not _unit_is_exact_and_active(INSPECTOR):
                raise RuntimeError("Inspector did not recover with persistent observer access")
            _verify_inspector_process(expected_runtime_inspector,
                                      str(expected_source).encode("ascii"))
            phase = "verify observer after persistent runtime repair"
            print("Resume phase: " + phase, flush=True)
            observer_identity = _wait_observer_socket(previous_inode=observer_identity)
        phase = "start Gateway and tunnel"
        print("Resume phase: " + phase, flush=True)
        _run("systemctl", "start", GATEWAY)
        _run("systemctl", "start", TUNNEL)
        phase = "verify resumed ingress cohort"
        print("Resume phase: " + phase, flush=True)
        config = CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_gateway_tunnel(config, require_active=True)
        _set_backup_state("migrated")
        print("Saved candidate Core and Jarvis ingress cohort resumed and verified.")
        print("Protected transaction backup retained for explicit operator recovery.")
    except Exception:
        for name in (TUNNEL, GATEWAY):
            try:
                _run("systemctl", "stop", name, check=False)
            except Exception:
                pass
        try:
            _set_backup_state("recovery-required")
        except Exception:
            pass
        print("Resume failed during phase: " + phase + "; Gateway and tunnel remain stopped.",
              file=sys.stderr)
        raise


def _recover_installed_adapter_to_legacy(core_runtime, expected_source: Path) -> None:
    """Recover the exact installed adapter transaction whose normal API only accepts active.

    The Core migration API's public recovery path requires an ``active`` service
    journal. The installer can successfully finish the migration while the
    service journal remains ``installed``. In that one case, perform the same
    proof-and-restore sequence here, accepting only the exact helper candidate,
    journal, listener, plugin selection and immutable backup. No journal state
    is rewritten to make the normal recovery API accept it.
    """
    expected_source = expected_source.resolve(strict=True)
    if expected_source != Path(core_runtime.ADAPTER_SOURCE).resolve(strict=True):
        raise RuntimeError("rollback helper and installed Core adapter source differ")
    record = core_runtime._journal()
    if (record.get("state") != "installed"
            or record.get("adapter_migration_state") != "active"
            or record.get("adapter_source") != str(expected_source)
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("adapter_generation", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("core_source_generation", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("plugin_selection_sha256", "")))):
        raise RuntimeError("installed Core migration journal is not the exact recoverable candidate")
    if (not core_runtime._owned_unit_loaded()
            or core_runtime._core_source_generation() != record["core_source_generation"]):
        raise RuntimeError("installed adapter Core identity is not verified")

    from hermes_installer.remote.core_gateway_inspector import (
        _current_native_adapter_generation,
        verify_staged_native_resources_plugin,
    )
    from hermes_installer.remote.native_plugin_bootstrap import (
        capture_native_resources_plugin_selection,
        restore_native_resources_plugin_selection,
    )

    deadline = time.monotonic() + 35.0
    if (_current_native_adapter_generation(deadline=deadline) != record["adapter_generation"]
            or not verify_staged_native_resources_plugin(deadline=deadline)):
        raise RuntimeError("installed adapter generation or selected plugin changed")

    backup = core_runtime.ADAPTER_MIGRATION_BACKUP
    directory = backup.lstat()
    if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
            or directory.st_gid != 0 or stat.S_IMODE(directory.st_mode) != 0o700
            or set(os.listdir(backup)) != {
                "journal.json", "unit", "launcher", "plugin-selection.json", "manifest.json"}):
        raise RuntimeError("protected Core migration backup custody differs")
    manifest_raw = core_runtime._projection_file(
        backup / "manifest.json", owner=0, group=0, mode=0o600, maximum=4096)
    try:
        manifest = json.loads(manifest_raw)
    except (ValueError, TypeError):
        raise RuntimeError("protected Core migration manifest is invalid") from None
    if (type(manifest) is not dict or manifest != record.get("adapter_migration_backup")
            or set(manifest) != {"journal.json", "unit", "launcher", "plugin-selection.json"}):
        raise RuntimeError("Core journal does not bind the exact protected backup")
    backup_journal = core_runtime._projection_file(
        backup / "journal.json", owner=0, group=0, mode=0o600, maximum=256 * 1024)
    backup_unit = core_runtime._projection_file(
        backup / "unit", owner=0, group=0, mode=0o600, maximum=256 * 1024)
    backup_launcher = core_runtime._projection_file(
        backup / "launcher", owner=0, group=0, mode=0o600, maximum=256 * 1024)
    snapshot = core_runtime._projection_file(
        backup / "plugin-selection.json", owner=0, group=0, mode=0o600, maximum=32 * 1024)
    for name, data in (("journal.json", backup_journal), ("unit", backup_unit),
                       ("launcher", backup_launcher),
                       ("plugin-selection.json", snapshot)):
        if hashlib.sha256(data).hexdigest() != manifest[name]:
            raise RuntimeError("protected Core migration backup bytes differ")
    try:
        previous = json.loads(backup_journal)
    except (ValueError, TypeError):
        raise RuntimeError("protected prior Core journal is invalid") from None
    if (type(previous) is not dict or previous.get("schema") != 1
            or previous.get("service") != core_runtime.SERVICE
            or previous.get("state") not in {"installed", "active"}
            or backup_unit != core_runtime._unit()
            or backup_launcher != core_runtime._legacy_launcher()
            or previous.get("unit_sha256") != hashlib.sha256(backup_unit).hexdigest()
            or previous.get("launcher_sha256") != hashlib.sha256(backup_launcher).hexdigest()):
        raise RuntimeError("protected prior Core recipe or journal does not match")
    token = core_runtime._projection_file(
        core_runtime.TOKEN, owner=0, group=core_runtime.GATEWAY_GID,
        mode=0o640, maximum=256)
    if (len(token) != 65 or not token.endswith(b"\n")
            or any(char not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                   for char in token[:-1])
            or previous.get("token_sha256") != hashlib.sha256(token).hexdigest()):
        raise RuntimeError("protected prior Core credential does not match its journal")
    if (not core_runtime._owned_unit_loaded()
            or core_runtime._core_source_generation() != record["core_source_generation"]):
        raise RuntimeError("installed adapter Core changed during recovery preflight")
    active = core_runtime._run(["systemctl", "is-active", core_runtime.SERVICE], False).stdout.strip()
    main_pid = core_runtime._run(
        ["systemctl", "show", "--property=MainPID", "--value", core_runtime.SERVICE],
        False).stdout.strip()
    if active == "active":
        if not core_runtime._owned_listener():
            raise RuntimeError("installed adapter Core listener is not owned")
    elif active not in {"inactive", "failed"} or main_pid not in {"", "0"}:
        raise RuntimeError("interrupted Core rollback is not stopped cleanly")

    # Selection can already have been restored before a prior helper exited.
    # Capture is unbiased by plugin enablement: require the exact immutable
    # prior bytes/digest, or the journal-bound migrated selection before the
    # official restore call. A restore command may report a CLI message after
    # applying its write, so read back exact bytes before classifying failure.
    selection_state = capture_native_resources_plugin_selection()
    if (getattr(selection_state, "migrated_selection_sha256", None)
            != record["plugin_selection_sha256"]):
        raise RuntimeError("captured prior selection does not bind the migration journal")
    already_prior = (selection_state.snapshot_json == snapshot)
    if not already_prior:
        if selection_state.prior_selection_sha256 != record["plugin_selection_sha256"]:
            raise RuntimeError("current plugin selection is neither saved migration nor prior bytes")
    if active == "active":
        core_runtime._run(["systemctl", "stop", core_runtime.SERVICE])
        if (core_runtime._run(["systemctl", "is-active", core_runtime.SERVICE], False).stdout.strip()
                == "active"
                or core_runtime._run(["systemctl", "show", "--property=MainPID", "--value",
                                      core_runtime.SERVICE], False).stdout.strip() not in {"", "0"}
                or core_runtime._owned_listener()):
            raise RuntimeError("installed adapter Core did not stop cleanly")
    try:
        if not already_prior:
            try:
                restore_native_resources_plugin_selection(
                    snapshot, expected_current_sha256=record["plugin_selection_sha256"])
            except Exception:
                # The fixed Hermes CLI may emit its own status text to stdout;
                # accept only an exact post-effect readback of the saved bytes.
                pass
        restored_selection = capture_native_resources_plugin_selection()
        if (restored_selection.snapshot_json != snapshot
                or restored_selection.migrated_selection_sha256
                   != record["plugin_selection_sha256"]):
            raise RuntimeError("prior plugin selection snapshot did not read back exactly")
        core_runtime._restore_adapter_migration_backup()
        core_runtime._run(["systemctl", "daemon-reload"])
        if not core_runtime._owned_unit_loaded():
            raise RuntimeError("restored Core service unit is not the exact owned unit")
        core_runtime._run(["systemctl", "start", core_runtime.SERVICE])
        _wait_legacy_listener(core_runtime)
        restored, restored_raw, restored_files = core_runtime._read_legacy_owned_runtime()
        if (restored != previous or restored_raw != backup_journal
                or restored_files[core_runtime.UNIT] != backup_unit
                or restored_files[core_runtime.LAUNCHER] != backup_launcher):
            raise RuntimeError("restored Core differs from its protected prior bytes")
        final_selection = capture_native_resources_plugin_selection()
        if (final_selection.snapshot_json != snapshot
                or final_selection.prior_selection_sha256
                   != restored_selection.prior_selection_sha256):
            raise RuntimeError("prior Hermes plugin selection did not verify")
    except Exception:
        try:
            if (core_runtime._owned_unit_loaded()
                    and core_runtime._run(["systemctl", "is-active", core_runtime.SERVICE],
                                          False).stdout.strip() == "active"):
                core_runtime._run(["systemctl", "stop", core_runtime.SERVICE])
        except Exception:
            pass
        raise RuntimeError("bounded installed-Core recovery failed; protected backup retained") from None


def _restore_legacy_core(core_runtime, expected_source: Path | None = None) -> bool:
    # This guarded API checks the protected migration state and is a no-op
    # when no interrupted migration exists. Do not query the native journal
    # directly: its current-adapter validation is intentionally unavailable
    # while the recovered legacy launcher is active.
    core_runtime._recover_interrupted_adapter_migration()
    if core_runtime._owned_listener(legacy_launcher=True):
        return True
    if core_runtime._owned_listener():
        record = core_runtime._journal()
        if record.get("state") == "installed":
            _recover_installed_adapter_to_legacy(
                core_runtime, expected_source or Path(core_runtime.ADAPTER_SOURCE))
        else:
            core_runtime.recover_owned_core_from_adapter_migration()
        return core_runtime._owned_listener(legacy_launcher=True)
    if not core_runtime._owned_unit_loaded():
        return False
    state = _unit_state(core_runtime.SERVICE)
    if state not in {"inactive", "failed"}:
        return False
    record = core_runtime._journal()
    if (record.get("state") == "installed"
            and record.get("adapter_migration_state") == "active"):
        _recover_installed_adapter_to_legacy(
            core_runtime, expected_source or Path(core_runtime.ADAPTER_SOURCE))
        return core_runtime._owned_listener(legacy_launcher=True)
    _run("systemctl", "start", core_runtime.SERVICE)
    _wait_legacy_listener(core_runtime)
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
    action.add_argument("--resume", action="store_true",
                        help="resume the exact recovery-required candidate with its current journal-owned Core")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha):
        parser.error("--candidate-sha must be a full lowercase 40-character Git commit SHA")
    expected_adapter_source = Path(
        f"/opt/hermes-installer-core-{args.candidate_sha[:9]}/src")

    phase = "source provenance and adapter validation"
    try:
        print("Adoption phase: " + phase, flush=True)
        _verify_source_provenance(args.candidate_sha, expected_adapter_source)
        sys.path.insert(0, str(expected_adapter_source))
        from hermes_installer import core_runtime
        actual_adapter = Path(core_runtime.__file__).resolve(strict=True).parents[1]
        if actual_adapter != expected_adapter_source:
            raise RuntimeError("loaded installer adapter is not the qualified fixed generation")
        core_runtime._validate_adapter_source_path()

        from hermes_installer.remote.core_gateway import CoreGatewayConfig
        from hermes_installer.remote.core_native_observer import CORE_NATIVE_OBSERVER_SOCKET

        if args.resume:
            phase = "resume saved candidate adoption transaction"
            print("Adoption phase: " + phase, flush=True)
            _resume_adoption(args.candidate_sha, expected_adapter_source, core_runtime,
                             CoreGatewayConfig, CORE_NATIVE_OBSERVER_SOCKET)
            return 0

        if args.rollback:
            phase = "rollback journal and fixed-file validation"
            print("Adoption phase: " + phase, flush=True)
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
                    or current_hashes[1] not in {value["new_inspector_sha256"],
                                                  value.get("runtime_inspector_sha256"),
                                                  value["old_inspector_sha256"]}
                    or current_hashes[2] not in {value["new_config_sha256"], value["old_config_sha256"],
                                                 value.get("post_core_config_sha256")}
                    or (current_hashes[0] == value["new_gateway_sha256"]
                        and _unit_source(current_gateway, "core_gateway") != source)
                    or (current_hashes[1] in {value["new_inspector_sha256"],
                                              value.get("runtime_inspector_sha256")}
                        and _unit_source(current_inspector, "core_gateway_inspector") != source)):
                raise RuntimeError("fixed ingress files differ from both saved transaction states")
            if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
                raise RuntimeError("fixed systemd unit ownership changed before Core rollback")
            phase = "rollback stop public tunnel and gateway"
            print("Adoption phase: " + phase, flush=True)
            _run("systemctl", "stop", TUNNEL)
            _run("systemctl", "stop", GATEWAY)
            phase = "rollback Core through journal recovery"
            print("Adoption phase: " + phase, flush=True)
            if not _restore_legacy_core(core_runtime, expected_adapter_source):
                raise RuntimeError("journaled Core rollback did not restore the legacy listener")
            phase = "rollback restore and verify prior ingress cohort"
            print("Adoption phase: " + phase, flush=True)
            if not _restore_old_ingress(value, old_gateway, old_inspector, old_config):
                _set_backup_state("recovery-required")
                raise RuntimeError("old Inspector/Gateway cohort did not recover; ingress remains stopped")
            INGRESS_BACKUP.unlink()
            print("Prior journal-owned Core/plugin and Inspector/Gateway/tunnel cohort restored.")
            return 0

        phase = "apply preflight and active ingress validation"
        print("Adoption phase: " + phase, flush=True)
        if INGRESS_BACKUP.exists() or INGRESS_BACKUP.is_symlink():
            raise RuntimeError("a prior adoption backup exists; use --rollback or inspect it first")
        config = CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_gateway_tunnel(config, require_active=True)
        if CORE_NATIVE_OBSERVER_SOCKET.exists() or CORE_NATIVE_OBSERVER_SOCKET.is_symlink():
            raise RuntimeError("unexpected preexisting native-observer socket blocks adoption")
        phase = "build exact source switch and protected recovery backup"
        print("Adoption phase: " + phase, flush=True)
        saved, old_config, config_info, new_units, new_config = _source_switch(expected_adapter_source)
        _save_ingress_backup(args.candidate_sha, saved, old_config, config_info,
                             new_units, new_config)
        base_inspector_sha = hashlib.sha256(new_units[FIXED_UNITS[INSPECTOR]]).hexdigest()
        repaired_inspector = _runtime_repaired_inspector(new_units[FIXED_UNITS[INSPECTOR]])
        runtime_inspector_sha = hashlib.sha256(repaired_inspector).hexdigest()
        _set_runtime_inspector_digest(args.candidate_sha, base_inspector_sha,
                                      runtime_inspector_sha)
        new_units[FIXED_UNITS[INSPECTOR]] = repaired_inspector
        old_gateway = saved[FIXED_UNITS[GATEWAY]][0]
        old_inspector = saved[FIXED_UNITS[INSPECTOR]][0]
        try:
            # Stop public ingress before switching the exact fixed import roots.
            # Install and process-check the Inspector while ingress is stopped.
            # Its native observer requires a -P Core, so do not wait for a
            # socket until the owner preparation and Core migration complete.
            phase = "stop ingress and atomically switch fixed Inspector and Gateway"
            print("Adoption phase: " + phase, flush=True)
            _replace_ingress_units(new_units, new_config, config_info)
            _set_backup_state("units-switched")
            phase = "start and verify candidate Inspector"
            print("Adoption phase: " + phase, flush=True)
            _run("systemctl", "start", INSPECTOR)
            if not _unit_is_exact_and_active(INSPECTOR):
                raise RuntimeError("new fixed Inspector did not become active")
            _verify_inspector_process(new_units[FIXED_UNITS[INSPECTOR]],
                                      str(expected_adapter_source).encode("ascii"))
            phase = "prepare existing Chat owner and vault"
            print("Adoption phase: " + phase, flush=True)
            from hermes_installer.remote.obsidian_owner_lifecycle import (
                prepare_sole_existing_chat_owner_for_legacy_migration,
            )
            prepare_sole_existing_chat_owner_for_legacy_migration()

            # Keep both public ingress units stopped through owner preparation,
            # Core migration and fresh Inspector binding to the new Core PID.
            phase = "migrate owned Core and verify listener"
            print("Adoption phase: " + phase, flush=True)
            result = core_runtime.migrate_owned_core_to_adapter_path()
            if not core_runtime._owned_listener():
                raise RuntimeError("migrated core listener did not verify")
            _set_backup_state("migrated")
            phase = "bind Gateway config to journal-verified migrated Core"
            print("Adoption phase: " + phase, flush=True)
            _refresh_migrated_core_config(args.candidate_sha, expected_adapter_source,
                                          core_runtime)
            config = CoreGatewayConfig.load(expected_owner_uid=0)
            _verify_gateway_tunnel(config, require_active=False)

            # Refresh pidfd-bound Inspector custody after the Core PID changes.
            phase = "restart Inspector for migrated Core PID"
            print("Adoption phase: " + phase, flush=True)
            _run("systemctl", "restart", INSPECTOR)
            if not _unit_is_exact_and_active(INSPECTOR):
                raise RuntimeError("new fixed Inspector did not recover after Core migration")
            phase = "bind fresh Inspector observer to migrated Core"
            print("Adoption phase: " + phase, flush=True)
            observer_identity = _wait_observer_socket()
            phase = "start public Gateway and tunnel"
            print("Adoption phase: " + phase, flush=True)
            _run("systemctl", "start", GATEWAY)
            _run("systemctl", "start", TUNNEL)
            phase = "verify complete adopted ingress cohort"
            print("Adoption phase: " + phase, flush=True)
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
            failed_phase = phase
            recovered = False
            recovery_error = None
            try:
                print("Recovery phase: stop public tunnel and gateway", flush=True)
                _run("systemctl", "stop", TUNNEL, check=False)
                _run("systemctl", "stop", GATEWAY, check=False)
                print("Recovery phase: restore legacy Core through journal", flush=True)
                recovered = _restore_legacy_core(core_runtime, expected_adapter_source)
            except Exception as failure:
                recovery_error = failure
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
            print("Failed phase: " + failed_phase)
            if recovery_error is not None:
                print("Core recovery reason code: "
                      + (_core_migration_reason_code(core_runtime, recovery_error) or "unclassified"))
            if failed_phase == "migrate owned Core and verify listener":
                reason_code = _core_migration_reason_code(core_runtime, error)
                print("Core migration reason code: " + (reason_code or "unclassified"))
            print("Failure type: " + type(error).__name__)
            return 4
    except Exception as error:
        print("Adoption helper stopped before claiming success during phase: " + phase
              + "; failure type: " + type(error).__name__, file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
