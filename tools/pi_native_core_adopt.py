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
import fcntl
import contextlib
import hashlib
import json
import secrets
import shlex
import select
import socket
import struct
import time
import unicodedata
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
INGRESS_HISTORY = INGRESS_BACKUP.parent / "native-adoption-ingress-history"
CORE_QUALIFICATION_FAILURE = (
    INGRESS_BACKUP.parent / "core-adapter-qualification-last-failure.json")
ADOPTER_LOCK = Path("/run/lock/hermes-native-core-adopt.lock")
NATIVE_OBSERVER_DIRECTORY = Path("/run/hermes-jarvis-native-observer")
NATIVE_OBSERVER_PRESTART = (
    "ExecStartPre=/usr/bin/install -d -o root -g 1000 -m 0750 "
    "/run/hermes-jarvis-native-observer")
NATIVE_OBSERVER_READ_WRITE = "ReadWritePaths=/var/lib/hermes-installer/core-runtime"
NATIVE_OBSERVER_SUPPLEMENTARY_GROUPS = "SupplementaryGroups=1000"
_SOURCE_PATH = re.compile(rb"/opt/hermes-installer-core-[0-9a-f]{9,64}/src\Z")
_APPROVED_EMAIL_UNION_MAX_BYTES = 16 * 1024
_QUALIFICATION_CHECKS = frozenset({
    "candidate_adapter_is_active", "adapter_generation_changed", "prior_source_bound",
    "Core_generation_preserved", "selected_plugin_preserved", "native_plugin_transition_proven",
    "overlay_skill_bytes_preserved",
    "Obsidian_registration_and_vault_preserved", "committed_update_cohort",
    "protected_prior_backup_bound", "candidate_listener_current",
    "protected_prior_backup_matches_exact_bytes", "runtime_token_digest_preserved",
    "primary_prompt_owner_bytes_and_adopted_record_preserved",
})
_QUALIFICATION_DIAGNOSTIC_PREFIX = "HERMES_CORE_QUALIFICATION_FAILURE_V1="
_QUALIFICATION_LAST_PHASE_PREFIX = "HERMES_CORE_QUALIFICATION_LAST_PHASE_V1="
_QUALIFICATION_DIAGNOSTIC_REASONS = frozenset({
    "execution_os_error", "timeout", "tool_identity_read_failure",
    "tool_identity_change", "malformed_result_types", "output_bound",
    "report_rejected", "validated_failure", "exit_report_verification_mismatch",
    "failure_report_persistence",
})
_QUALIFICATION_CHECKPOINT_PREFIX = "HERMES_CORE_QUALIFICATION_CHECKPOINT_V1="
_QUALIFICATION_CHECKPOINT_PHASES = frozenset({
    "stage_verifier", "runtime_load", "before_snapshot", "adapter_update",
    "after_snapshot", "history_validation", "listener_verification",
    "success_checks", "report_emission",
})
_QUALIFICATION_CHECKPOINT_PHASE_ORDER = (
    "stage_verifier", "runtime_load", "before_snapshot", "adapter_update",
    "after_snapshot", "history_validation", "listener_verification",
    "success_checks", "report_emission",
)


class _QualificationDiagnosticError(RuntimeError):
    """Generic outward refusal with a closed, non-sensitive diagnostic record."""

    def __init__(self, record: dict):
        super().__init__("fixed Core adapter qualification did not verify")
        self.record = record


def _qualification_diagnostic(candidate_sha: str, archive_sha: str, reason: str,
                               returncode: object, stdout_bytes: object,
                               stderr_bytes: object, elapsed_ms: object) -> dict:
    """Build a closed record; oversized counts/time saturate at their documented caps."""
    if (type(candidate_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None
            or type(archive_sha) is not str
            or re.fullmatch(r"[0-9a-f]{64}", archive_sha) is None
            or reason not in _QUALIFICATION_DIAGNOSTIC_REASONS):
        raise ValueError("invalid fixed qualification diagnostic input")

    def bounded_count(value: object, maximum: int) -> int | None:
        if type(value) is not int or value < 0:
            return None
        return min(value, maximum)

    bounded_returncode = (returncode if type(returncode) is int and -255 <= returncode <= 255
                          else None)
    record = {
        "schema": 1,
        "candidate_commit": candidate_sha,
        "candidate_archive_sha256": archive_sha,
        "reason": reason,
        "returncode": bounded_returncode,
        "stdout_bytes": bounded_count(stdout_bytes, 64 * 1024 + 1),
        "stderr_bytes": bounded_count(stderr_bytes, 16 * 1024 + 1),
        "elapsed_ms": bounded_count(elapsed_ms, 300_000),
    }
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len((_QUALIFICATION_DIAGNOSTIC_PREFIX + raw + "\n").encode("ascii")) > 4096:
        raise ValueError("fixed qualification diagnostic exceeds its bound")
    return record


def _valid_qualification_diagnostic_record(record: object) -> bool:
    keys = {
        "schema", "candidate_commit", "candidate_archive_sha256", "reason",
        "returncode", "stdout_bytes", "stderr_bytes", "elapsed_ms",
    }
    if type(record) is not dict or set(record) != keys:
        return False
    if (type(record["schema"]) is not int or record["schema"] != 1
            or type(record["candidate_commit"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", record["candidate_commit"]) is None
            or type(record["candidate_archive_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", record["candidate_archive_sha256"]) is None
            or type(record["reason"]) is not str
            or record["reason"] not in _QUALIFICATION_DIAGNOSTIC_REASONS):
        return False
    returncode = record["returncode"]
    if returncode is not None and (type(returncode) is not int or not -255 <= returncode <= 255):
        return False
    for key, maximum in (("stdout_bytes", 64 * 1024 + 1),
                         ("stderr_bytes", 16 * 1024 + 1),
                         ("elapsed_ms", 300_000)):
        value = record[key]
        if value is not None and (type(value) is not int or not 0 <= value <= maximum):
            return False
    return True


def _emit_qualification_diagnostic(record: dict) -> None:
    if not _valid_qualification_diagnostic_record(record):
        return
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError, RecursionError):
        return
    line = _QUALIFICATION_DIAGNOSTIC_PREFIX + raw
    if len((line + "\n").encode("ascii")) > 4096:
        return
    try:
        print(line, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        # Diagnostic output must not change the established refusal/recovery path.
        pass


def _qualification_last_phase_summary(stderr: object, candidate_sha: str,
                                      archive_sha: str) -> dict:
    summary = {
        "schema": 1, "candidate_commit": candidate_sha,
        "candidate_archive_sha256": archive_sha, "last_phase": None,
        "last_sequence": None, "last_elapsed_ms": None,
        "record_count": 0, "rejected_record_count": 0,
    }
    if type(stderr) is not bytes:
        return summary
    if len(stderr) > 16 * 1024:
        summary["rejected_record_count"] = 1
        return summary
    if not stderr:
        return summary

    complete_lines = stderr.splitlines(keepends=True)
    trailing_partial = not stderr.endswith(b"\n")
    if trailing_partial and complete_lines:
        complete_lines = complete_lines[:-1]
        summary["rejected_record_count"] = 1
    valid_records = 0
    previous_elapsed = -1
    previous_phase_index = -1
    exact_keys = {
        "schema", "candidate_commit", "candidate_archive_sha256",
        "sequence", "phase", "elapsed_ms",
    }

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate record key")
            result[key] = value
        return result

    invalid = False
    if not complete_lines and trailing_partial:
        return summary
    for line in complete_lines:
        if (len(line) > 4096 or not line.endswith(b"\n") or not line.startswith(
                _QUALIFICATION_CHECKPOINT_PREFIX.encode("ascii"))):
            invalid = True
            break
        try:
            text = line[:-1].decode("ascii", "strict")
            encoded = text[len(_QUALIFICATION_CHECKPOINT_PREFIX):]
            record = json.loads(encoded, object_pairs_hook=unique_object)
            if (type(record) is not dict or set(record) != exact_keys
                    or record.get("schema") != 1 or type(record.get("schema")) is not int
                    or record.get("candidate_commit") != candidate_sha
                    or type(record.get("candidate_commit")) is not str
                    or record.get("candidate_archive_sha256") != archive_sha
                    or type(record.get("candidate_archive_sha256")) is not str
                    or type(record.get("sequence")) is not int
                    or record["sequence"] != valid_records + 1
                    or record["sequence"] > 16
                    or type(record.get("phase")) is not str
                    or record["phase"] not in _QUALIFICATION_CHECKPOINT_PHASES
                    or _QUALIFICATION_CHECKPOINT_PHASE_ORDER.index(record["phase"])
                    <= previous_phase_index
                    or type(record.get("elapsed_ms")) is not int
                    or not 0 <= record["elapsed_ms"] <= 300_000
                    or record["elapsed_ms"] < previous_elapsed
                    or encoded != json.dumps(record, sort_keys=True,
                                             separators=(",", ":"), ensure_ascii=True)):
                invalid = True
                break
        except (ValueError, TypeError, UnicodeError, RecursionError):
            invalid = True
            break
        valid_records += 1
        previous_elapsed = record["elapsed_ms"]
        previous_phase_index = _QUALIFICATION_CHECKPOINT_PHASE_ORDER.index(record["phase"])
        summary.update({"last_phase": record["phase"],
                        "last_sequence": record["sequence"],
                        "last_elapsed_ms": record["elapsed_ms"]})
    summary["record_count"] = min(valid_records, 16)
    summary["rejected_record_count"] = min(
        summary["rejected_record_count"] + (1 if invalid else 0), 16)
    if invalid:
        summary.update({"last_phase": None, "last_sequence": None,
                        "last_elapsed_ms": None})
    return summary


def _valid_qualification_last_phase_summary(summary: object) -> bool:
    keys = {
        "schema", "candidate_commit", "candidate_archive_sha256", "last_phase",
        "last_sequence", "last_elapsed_ms", "record_count", "rejected_record_count",
    }
    if type(summary) is not dict or set(summary) != keys:
        return False
    if (type(summary["schema"]) is not int or summary["schema"] != 1
            or type(summary["candidate_commit"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", summary["candidate_commit"]) is None
            or type(summary["candidate_archive_sha256"]) is not str
            or re.fullmatch(r"[0-9a-f]{64}", summary["candidate_archive_sha256"]) is None
            or type(summary["record_count"]) is not int
            or not 0 <= summary["record_count"] <= 16
            or type(summary["rejected_record_count"]) is not int
            or not 0 <= summary["rejected_record_count"] <= 16):
        return False
    phase, sequence, elapsed = (summary["last_phase"], summary["last_sequence"],
                                summary["last_elapsed_ms"])
    if phase is None or sequence is None or elapsed is None:
        return phase is sequence is elapsed is None
    return (type(phase) is str and phase in _QUALIFICATION_CHECKPOINT_PHASES
            and type(sequence) is int and 1 <= sequence <= 16
            and type(elapsed) is int and 0 <= elapsed <= 300_000
            and sequence == summary["record_count"])


def _emit_qualification_last_phase_summary(summary: dict) -> None:
    if not _valid_qualification_last_phase_summary(summary):
        return
    try:
        raw = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError, RecursionError):
        return
    line = _QUALIFICATION_LAST_PHASE_PREFIX + raw
    if len((line + "\n").encode("ascii")) > 4096:
        return
    try:
        print(line, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


def _raise_qualification_diagnostic(candidate_sha: str, archive_sha: str, reason: str,
                                     returncode: object = None,
                                     stdout_bytes: object = None,
                                     stderr_bytes: object = None,
                                     elapsed_ms: object = None,
                                     progress_stderr: object = None) -> None:
    record = _qualification_diagnostic(candidate_sha, archive_sha, reason, returncode,
                                       stdout_bytes, stderr_bytes, elapsed_ms)
    _emit_qualification_diagnostic(record)
    _emit_qualification_last_phase_summary(_qualification_last_phase_summary(
        progress_stderr, candidate_sha, archive_sha))
    raise _QualificationDiagnosticError(record) from None


_QUALIFICATION_SNAPSHOT_KEYS = frozenset({
    "journal_sha256", "unit_sha256", "launcher_sha256", "token_custody_verified",
    "token_sha256", "adapter_source", "adapter_generation", "core_source_generation",
    "plugin_selection_sha256", "resources_record_sha256", "overlay_record_sha256",
    "overlay_content_count", "overlay_contents_sha256", "primary_record_sha256",
    "obsidian_registration_state", "obsidian_registration_sha256",
    "obsidian_vault_tree_sha256", "adapter_update_state", "adapter_update_previous_source",
    "adapter_update_backup_source_generation", "primary_prompt_soul_sha256",
    "primary_prompt_state", "primary_owner_prefix_sha256", "primary_owner_prefix_length",
    "primary_immutable_backup_sha256", "native_plugin_members_sha256",
    "native_plugin_transition",
})
_NATIVE_PLUGIN_MEMBER_NAMES = ("plugin.yaml", "__init__.py")
_NATIVE_PLUGIN_BACKUP_NAMES = {
    "plugin.yaml": "native-plugin-plugin.yaml",
    "__init__.py": "native-plugin-__init__.py",
}
_ADAPTER_BACKUP_BASE_MEMBERS = frozenset({
    "journal.json", "unit", "launcher", "plugin-selection.json", "resources-record.json",
    "overlay-record.json", "primary-record.json", "obsidian-registration.json", "cohort.json",
})
_NATIVE_PLUGIN_TRANSITION_FIELDS = frozenset({
    "schema", "purpose", "old_adapter_generation", "new_adapter_generation",
    "plugin_selection_sha256", "old_members", "new_members",
})


class _IngressSnapshotConflict(RuntimeError):
    """The fixed ingress CAS failed before the first service effect."""


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


def _proc_start_ticks(pid: int) -> int:
    raw = (Path("/proc") / str(pid) / "stat").read_text(encoding="ascii")
    close = raw.rfind(")")
    fields = raw[close + 2:].split()
    if close < 0 or len(fields) <= 19:
        raise RuntimeError("fixed Inspector process identity is unavailable")
    return int(fields[19])


def _capture_inspector_custody(raw: bytes, source: bytes, observer_socket: Path) -> dict:
    """Hold the exact old Inspector peer and its existing normal socket."""
    _verify_inspector_process(raw, source)
    pid = int(_run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR))
    invocation = _run("systemctl", "show", "--property=InvocationID", "--value", INSPECTOR)
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    proc = Path("/proc") / str(pid)
    status = (proc / "status").read_text(encoding="ascii").splitlines()
    vectors = {line.partition(":")[0]: line.partition(":")[2].split()
               for line in status if line.partition(":")[0] in {"Uid", "Gid"}}
    if (not re.fullmatch(r"[0-9a-f]{32}", invocation)
            or not re.fullmatch(r"[0-9a-f-]{36}", boot_id)
            or len(vectors.get("Uid", [])) != 4 or any(v != "0" for v in vectors["Uid"])
            or len(vectors.get("Gid", [])) != 4 or vectors["Gid"][1] != "981"):
        raise RuntimeError("fixed Inspector process credentials or invocation differ")
    start_ticks = _proc_start_ticks(pid)
    executable = os.readlink(proc / "exe")
    cgroup = (proc / "cgroup").read_text(encoding="ascii").splitlines()
    parent = observer_socket.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 1000
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise RuntimeError("fixed normal observer directory custody differs")
    observer_state = "absent"
    device = inode = None
    try:
        socket_info = observer_socket.lstat()
    except FileNotFoundError:
        socket_info = None
    if socket_info is not None:
        if (not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0
                or socket_info.st_gid != 1000 or stat.S_IMODE(socket_info.st_mode) != 0o660
                or socket_info.st_nlink != 1):
            raise RuntimeError("preexisting normal observer socket is not owned")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(2.0)
            probe.connect(str(observer_socket))
            peer = struct.unpack("3i", probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                         struct.calcsize("3i")))
            current_info = observer_socket.lstat()
            if ((current_info.st_dev, current_info.st_ino) != (socket_info.st_dev, socket_info.st_ino)
                    or peer != (pid, 0, 981)):
                raise RuntimeError("normal observer socket peer is not the captured Inspector")
        except OSError:
            raise RuntimeError("normal observer socket peer could not be verified") from None
        finally:
            probe.close()
        observer_state = "verified-owned"
        device, inode = socket_info.st_dev, socket_info.st_ino
    parent_identity = (parent.st_dev, parent.st_ino)
    identity = {
        "pid": pid, "start_ticks": start_ticks, "boot_id": boot_id,
        "invocation_id": invocation, "source": source.decode("ascii"),
        "unit_sha256": hashlib.sha256(raw).hexdigest(), "executable": executable,
        "cgroup": cgroup,
    }
    pidfd = os.pidfd_open(pid, 0)
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    try:
        if (poller.poll(0) or _proc_start_ticks(pid) != start_ticks
                or _run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR) != str(pid)
                or _run("systemctl", "show", "--property=InvocationID", "--value", INSPECTOR) != invocation):
            raise RuntimeError("fixed Inspector changed during custody capture")
    except BaseException:
        os.close(pidfd)
        raise
    row = {
        "schema": 1, "purpose": "adapter-refresh",
        "old_core_journal_sha256": "", "old_core_adapter_source": "",
        "old_core_adapter_generation": "", "old_core_source_generation": "",
        "old_inspector_process_identity_sha256": hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest(),
        "old_observer_state": observer_state, "old_observer_device": device,
        "old_observer_inode": inode, "core_update_backup_reference": None,
        "core_update_cohort_transaction_id": None, "core_update_cohort_sha256": None,
    }
    return {"pidfd": pidfd, "pid": pid, "start_ticks": start_ticks,
            "boot_id": boot_id, "invocation_id": invocation, "identity": identity,
            "observer_socket": observer_socket, "observer_state": observer_state,
            "observer_device": device, "observer_inode": inode,
            "observer_parent_identity": parent_identity, "unit_raw": raw,
            "source": source, "row": row}


def _stop_captured_inspector(custody: dict) -> None:
    pidfd = custody["pidfd"]
    pid = custody["pid"]
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    _verify_inspector_process(custody["unit_raw"], custody["source"])
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    proc = Path("/proc") / str(pid)
    current_identity = {
        "pid": pid, "start_ticks": _proc_start_ticks(pid), "boot_id": boot_id,
        "invocation_id": _run("systemctl", "show", "--property=InvocationID", "--value", INSPECTOR),
        "source": custody["source"].decode("ascii"),
        "unit_sha256": hashlib.sha256(custody["unit_raw"]).hexdigest(),
        "executable": os.readlink(proc / "exe"),
        "cgroup": (proc / "cgroup").read_text(encoding="ascii").splitlines(),
    }
    if (current_identity != custody["identity"]
            or poller.poll(0) or _proc_start_ticks(pid) != custody["start_ticks"]
            or _run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR) != str(pid)
            or _run("systemctl", "show", "--property=InvocationID", "--value", INSPECTOR)
               != custody["invocation_id"]):
        raise RuntimeError("captured old Inspector changed before stop")
    _run("systemctl", "stop", INSPECTOR)
    poller.poll(30_000)
    if (not poller.poll(0) or _unit_state(INSPECTOR) not in {"inactive", "failed"}
            or _run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR, check=False)
               not in {"", "0"}):
        raise RuntimeError("captured old Inspector did not stop cleanly")
    path = custody["observer_socket"]
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 1000
            or stat.S_IMODE(parent.st_mode) != 0o750
            or (parent.st_dev, parent.st_ino) != custody["observer_parent_identity"]):
        raise RuntimeError("captured normal observer parent changed during Inspector stop")
    try:
        current = path.lstat()
    except FileNotFoundError:
        current = None
    if custody["observer_state"] == "absent":
        if current is not None:
            raise RuntimeError("an unowned normal observer socket appeared during stop")
        return
    # The existing observer's clean shutdown normally unlinks its own socket.
    # Once the held PIDFD and systemd state above prove the selected process is
    # gone, that absence is equivalent to our unlinking the captured inode.
    if current is None:
        return
    if (current is None or not stat.S_ISSOCK(current.st_mode)
            or current.st_uid != 0 or current.st_gid != 1000
            or stat.S_IMODE(current.st_mode) != 0o660 or current.st_nlink != 1
            or (current.st_dev, current.st_ino) !=
               (custody["observer_device"], custody["observer_inode"])):
        raise RuntimeError("captured normal observer socket changed during Inspector stop")
    path.unlink()
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                           | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _adapter_refresh_row(core_record: dict, core_raw: bytes, inspector: dict) -> dict:
    row = dict(inspector["row"])
    row.update({
        "old_core_journal_sha256": hashlib.sha256(core_raw).hexdigest(),
        "old_core_adapter_source": core_record["adapter_source"],
        "old_core_adapter_generation": core_record["adapter_generation"],
        "old_core_source_generation": core_record["core_source_generation"],
    })
    if not _valid_adapter_refresh_row(row):
        raise RuntimeError("current adapter refresh custody is incomplete")
    return row


def _adapter_refresh_snapshot(core_runtime, candidate_source: Path, observer_socket: Path):
    record, raw, files = core_runtime._read_active_adapter_runtime()
    if record.get("adapter_source") == str(candidate_source):
        raise RuntimeError("current native Core is not an older adapter generation")
    old_source = record["adapter_source"].encode("ascii", "strict")
    snapshots = core_runtime._snapshot_adapter_update_bindings(
        core_source_generation=record["core_source_generation"])
    ingress_source = _unit_source(
        _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0, mode=0o644,
                    maximum=64 * 1024)[0], "core_gateway_inspector")
    if ingress_source != old_source:
        raise RuntimeError("active ingress and journal-owned Core use different generations")
    inspector_raw, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                   mode=0o644, maximum=64 * 1024)
    custody = _capture_inspector_custody(inspector_raw, old_source, observer_socket)
    custody["row"] = _adapter_refresh_row(record, raw, custody)
    return record, raw, files, snapshots, custody


def _read_candidate_qualification_inputs(candidate_sha: str, source: Path) -> tuple[str, Path, tuple]:
    archive_sha = _verify_source_provenance(candidate_sha, source)
    generation = source.parent
    tool = generation / "tools" / "pi_core_lifecycle_qualification.py"
    # The source receipt authenticates the staged generation as data; hold and
    # recheck the exact fixed root-owned runner inode around the subprocess.
    for directory in (generation, source, generation / "tools"):
        info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise RuntimeError("fixed Core qualification source custody differs")
    info = tool.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022
            or not 1 <= info.st_size <= 2 * 1024 * 1024):
        raise RuntimeError("fixed Core qualification runner custody differs")
    fd = os.open(tool, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        held = os.fstat(fd)
        if (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns) != (
                info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
            raise RuntimeError("fixed Core qualification runner changed before execution")
        before = (held.st_dev, held.st_ino, held.st_size, held.st_mtime_ns, held.st_ctime_ns)
    finally:
        os.close(fd)
    return archive_sha, tool, before


def _valid_qualification_origin(value: object) -> bool:
    if value is None:
        return True
    if type(value) is not dict or set(value) != {"exception_type", "frames"}:
        return False
    name = value["exception_type"]
    frames = value["frames"]
    if (not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None
            or type(frames) is not list or not 1 <= len(frames) <= 12):
        return False
    for frame in frames:
        if type(frame) is not dict or set(frame) != {
                "source_relative_path", "function", "line"}:
            return False
        path, function, line = (frame["source_relative_path"], frame["function"],
                                frame["line"])
        if (not isinstance(path, str) or not 1 <= len(path) <= 512
                or re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", path) is None
                or path.startswith("/") or "\\" in path
                or any(part in {"", ".", ".."} for part in path.split("/"))
                or not isinstance(function, str)
                or re.fullmatch(r"[A-Za-z0-9_<>.$-]{1,256}", function) is None
                or type(line) is not int or not 1 <= line <= 10_000_000):
            return False
    return True


def _valid_qualification_snapshot(value: object) -> bool:
    if type(value) is not dict or set(value) != _QUALIFICATION_SNAPSHOT_KEYS:
        return False
    optional_digests = {
        "primary_record_sha256", "obsidian_registration_sha256", "obsidian_vault_tree_sha256",
        "adapter_update_backup_source_generation", "primary_owner_prefix_sha256",
        "primary_immutable_backup_sha256",
    }
    absent_digests = {
        "overlay_record_sha256", "primary_record_sha256",
        "obsidian_registration_sha256", "obsidian_vault_tree_sha256",
    }
    digest_pattern = r"[0-9a-f]{64}"
    for key in _QUALIFICATION_SNAPSHOT_KEYS:
        if key in optional_digests and value[key] is None:
            continue
        if key in {
                "journal_sha256", "unit_sha256", "launcher_sha256", "token_sha256",
                "adapter_generation", "core_source_generation", "plugin_selection_sha256",
                "resources_record_sha256", "overlay_record_sha256", "overlay_contents_sha256",
                "primary_prompt_soul_sha256", "primary_record_sha256",
                "obsidian_registration_sha256", "obsidian_vault_tree_sha256",
                "adapter_update_backup_source_generation", "primary_owner_prefix_sha256",
                "primary_immutable_backup_sha256"}:
            if key in optional_digests and value[key] is None:
                continue
            if (not isinstance(value[key], str)
                    or (re.fullmatch(digest_pattern, value[key]) is None
                        and not (key in absent_digests and value[key] == "absent"))):
                return False
        elif key == "token_custody_verified":
            if value[key] is not True:
                return False
        elif key == "adapter_source":
            if (not isinstance(value[key], str)
                    or re.fullmatch(r"/opt/hermes-installer-core-[0-9a-f]{9,64}/src",
                                    value[key]) is None):
                return False
        elif key == "adapter_update_previous_source":
            if value[key] is not None and (not isinstance(value[key], str)
                    or re.fullmatch(r"/opt/hermes-installer-core-[0-9a-f]{9,64}/src",
                                    value[key]) is None):
                return False
        elif key in {"overlay_content_count", "primary_owner_prefix_length"}:
            if type(value[key]) is not int or not 0 <= value[key] <= 1_000_000:
                return False
        elif key == "obsidian_registration_state":
            if value[key] not in {"registered", "absent"}:
                return False
        elif key == "adapter_update_state":
            if value[key] not in {None, "installed", "active"}:
                return False
        elif key == "primary_prompt_state":
            if value[key] not in {"adopted", "unmanaged"}:
                return False
        elif key == "native_plugin_members_sha256":
            if not _valid_native_plugin_member_digests(value[key]):
                return False
        elif key == "native_plugin_transition":
            if value[key] is not None and not _valid_native_plugin_transition(value[key]):
                return False
    # Core uses the literal sentinel only for the four optional protected
    # files/trees below.  Bind each one to the independent state/count fields
    # so an arbitrary caller cannot turn a required digest into "absent".
    registration_absent = value["obsidian_registration_state"] == "absent"
    if ((value["obsidian_registration_sha256"] == "absent") != registration_absent
            or (value["obsidian_vault_tree_sha256"] == "absent") != registration_absent):
        return False
    primary_unmanaged = value["primary_prompt_state"] == "unmanaged"
    if (value["primary_record_sha256"] == "absent") != primary_unmanaged:
        return False
    if value["overlay_record_sha256"] == "absent" and value["overlay_content_count"] != 0:
        return False
    transition = value["native_plugin_transition"]
    if transition is not None and (
            transition["new_adapter_generation"] != value["adapter_generation"]
            or transition["plugin_selection_sha256"] != value["plugin_selection_sha256"]
            or transition["new_members"] != value["native_plugin_members_sha256"]):
        return False
    return True


def _validated_qualification_report(raw: bytes, candidate_sha: str,
                                    archive_sha: str) -> tuple[dict, bool]:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 64 * 1024:
        raise ValueError
    report = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    expected = {
        "schema", "action", "candidate_commit", "candidate_archive_sha256",
        "source_receipt_is_operator_paired_not_signature",
        "ancestor_and_verifier_custody_checked_before_execution", "cli_exit_code",
        "cli_failure_origin", "cli_output", "before", "after", "after_readback_error_type",
        "cohort_phase", "checks", "outcome", "rollback_qualification",
        "interruption_recovery_qualification", "acceptance",
    }
    if (type(report) is not dict or set(report) != expected or type(report["schema"]) is not int
            or report["schema"] != 1 or report["action"] != "core-service adapter-update"
            or report["candidate_commit"] != candidate_sha
            or report["candidate_archive_sha256"] != archive_sha
            or report["source_receipt_is_operator_paired_not_signature"] is not True
            or report["ancestor_and_verifier_custody_checked_before_execution"] is not True
            or type(report["cli_exit_code"]) is not int
            or not 0 <= report["cli_exit_code"] <= 255
            or not _valid_qualification_origin(report["cli_failure_origin"])):
        raise ValueError
    cli_output = report["cli_output"]
    if (type(cli_output) is not dict
            or set(cli_output) != {"stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256"}
            or type(cli_output["stdout_bytes"]) is not int
            or not 0 <= cli_output["stdout_bytes"] <= 64 * 1024
            or type(cli_output["stderr_bytes"]) is not int
            or not 0 <= cli_output["stderr_bytes"] <= 16 * 1024
            or any(not isinstance(cli_output[key], str)
                   or re.fullmatch(r"[0-9a-f]{64}", cli_output[key]) is None
                   for key in ("stdout_sha256", "stderr_sha256"))):
        raise ValueError
    before, after, checks = report["before"], report["after"], report["checks"]
    if (not _valid_qualification_snapshot(before)
            or (after is not None and not _valid_qualification_snapshot(after))
            or type(checks) is not dict
            or (checks and (set(checks) != _QUALIFICATION_CHECKS
                            or any(type(value) is not bool for value in checks.values())))
            or (not checks and after is not None)):
        raise ValueError
    if after is not None:
        after_transition = after["native_plugin_transition"]
        if after_transition is None:
            if before["native_plugin_members_sha256"] != after["native_plugin_members_sha256"]:
                raise ValueError
        elif after_transition["new_adapter_generation"] == before["adapter_generation"]:
            # The unchanged old committed cohort can still name the transition
            # that produced the currently installed predecessor generation.
            if (after["adapter_generation"] != before["adapter_generation"]
                    or after_transition["plugin_selection_sha256"]
                       != before["plugin_selection_sha256"]
                    or after["native_plugin_members_sha256"]
                       != before["native_plugin_members_sha256"]):
                raise ValueError
        elif (after_transition["old_adapter_generation"] != before["adapter_generation"]
              or after_transition["new_adapter_generation"] != after["adapter_generation"]
              or after_transition["plugin_selection_sha256"] != before["plugin_selection_sha256"]
              or after_transition["plugin_selection_sha256"] != after["plugin_selection_sha256"]
              or after_transition["old_members"] != before["native_plugin_members_sha256"]
              or after_transition["new_members"] != after["native_plugin_members_sha256"]):
            raise ValueError
    for key in ("after_readback_error_type",):
        value = report[key]
        if value is not None and (not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value) is None):
            raise ValueError
    phase = report["cohort_phase"]
    if phase is not None and (not isinstance(phase, str)
            or re.fullmatch(r"[a-z][a-z0-9-]{0,63}", phase) is None):
        raise ValueError
    if (report["rollback_qualification"] != "not_run"
            or report["interruption_recovery_qualification"] != "not_run"
            or report["acceptance"] != "not_claimed"):
        raise ValueError
    verified = (report["cli_exit_code"] == 0 and report["outcome"] == "verified_adapter_update"
                and phase == "committed" and bool(checks)
                and all(value is True for value in checks.values()))
    if report["outcome"] != ("verified_adapter_update" if verified else "pending_or_failed"):
        raise ValueError
    if report["cli_exit_code"] == 0 and report["cli_failure_origin"] is not None:
        raise ValueError
    return report, verified


def _persist_qualification_failure(report: dict) -> None:
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    if len(raw) > 64 * 1024:
        raise RuntimeError("fixed Core qualification failure report exceeds its bound")
    report, verified = _validated_qualification_report(
        raw, report.get("candidate_commit"), report.get("candidate_archive_sha256"))
    if verified:
        raise RuntimeError("successful Core qualification is not a failure report")
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    parent = CORE_QUALIFICATION_FAILURE.parent
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
            or parent_info.st_gid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise RuntimeError("fixed Core qualification failure directory custody differs")
    _atomic_fixed(CORE_QUALIFICATION_FAILURE, raw, uid=0, gid=0, mode=0o600)
    persisted, _info = _read_fixed(CORE_QUALIFICATION_FAILURE, uid=0, gid=0,
                                   mode=0o600, maximum=64 * 1024)
    if persisted != raw:
        raise RuntimeError("fixed Core qualification failure report readback differs")


def _run_core_refresh_qualification(candidate_sha: str, archive_sha: str,
                                    tool: Path, tool_identity: tuple) -> dict:
    argv = ("/usr/bin/python3", "-I", str(tool), "--candidate-sha", candidate_sha,
            "--archive-sha256", archive_sha)
    started = time.monotonic()

    def elapsed_ms() -> int:
        elapsed = time.monotonic() - started
        if not isinstance(elapsed, (int, float)) or elapsed < 0:
            return 0
        return min(int(elapsed * 1000), 300_000)

    try:
        result = subprocess.run(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=300, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C",
                              "HOME": "/root"}, check=False)
    except subprocess.TimeoutExpired as error:
        out = error.stdout if type(error.stdout) is bytes else None
        err = error.stderr if type(error.stderr) is bytes else None
        _raise_qualification_diagnostic(
            candidate_sha, archive_sha, "timeout", None,
            len(out) if out is not None else None, len(err) if err is not None else None,
            elapsed_ms(), err)
    except OSError:
        _raise_qualification_diagnostic(candidate_sha, archive_sha,
                                         "execution_os_error", elapsed_ms=elapsed_ms())
    result_returncode = getattr(result, "returncode", None)
    result_stdout = getattr(result, "stdout", None)
    result_stderr = getattr(result, "stderr", None)
    stdout_bytes = len(result_stdout) if type(result_stdout) is bytes else None
    stderr_bytes = len(result_stderr) if type(result_stderr) is bytes else None
    try:
        current = tool.lstat()
    except OSError:
        _raise_qualification_diagnostic(candidate_sha, archive_sha,
                                         "tool_identity_read_failure", result_returncode,
                                         stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
    if (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
            current.st_ctime_ns) != tool_identity:
        _raise_qualification_diagnostic(candidate_sha, archive_sha, "tool_identity_change",
                                         result_returncode, stdout_bytes, stderr_bytes,
                                         elapsed_ms(), result_stderr)
    if (type(result_returncode) is not int or type(result_stdout) is not bytes
            or type(result_stderr) is not bytes):
        _raise_qualification_diagnostic(
            candidate_sha, archive_sha, "malformed_result_types", result_returncode,
            stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
    if stdout_bytes > 64 * 1024 or stderr_bytes > 16 * 1024:
        _raise_qualification_diagnostic(
            candidate_sha, archive_sha, "output_bound", result_returncode,
            stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
    try:
        report, verified = _validated_qualification_report(
            result_stdout, candidate_sha, archive_sha)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        _raise_qualification_diagnostic(
            candidate_sha, archive_sha, "report_rejected", result_returncode,
            stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
    if result_returncode == 0 and verified:
        return report
    if result_returncode != 0 and not verified:
        try:
            _persist_qualification_failure(report)
        except Exception:
            _raise_qualification_diagnostic(
                candidate_sha, archive_sha, "failure_report_persistence", result_returncode,
                stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
        _raise_qualification_diagnostic(
            candidate_sha, archive_sha, "validated_failure", result_returncode,
            stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)
    _raise_qualification_diagnostic(
        candidate_sha, archive_sha, "exit_report_verification_mismatch", result_returncode,
        stdout_bytes, stderr_bytes, elapsed_ms(), result_stderr)


def _verify_adapter_refresh_plugin_backup(core_runtime, old_record: dict,
                                          current_record: dict, cohort: dict,
                                          reference: dict, prior: dict,
                                          contents: dict) -> None:
    """Join an optional 11-member backup only to its actual protected Core row."""
    expected = set(_ADAPTER_BACKUP_BASE_MEMBERS)
    transition = cohort.get("native_plugin_transition")
    if transition is not None:
        if not _valid_native_plugin_transition(transition):
            raise RuntimeError("Core native plugin transition row is malformed")
        expected.update(_NATIVE_PLUGIN_BACKUP_NAMES.values())
    files = reference.get("files") if type(reference) is dict else None
    if (type(files) is not dict or set(files) != expected or set(contents) != expected
            or any(type(files[name]) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", files[name]) is None
                   or type(contents[name]) is not bytes
                   or hashlib.sha256(contents[name]).hexdigest() != files[name]
                   for name in expected)):
        raise RuntimeError("Core adapter backup member set differs from its transition")
    if (prior.get("adapter_generation") != old_record.get("adapter_generation")
            or prior.get("adapter_source") != old_record.get("adapter_source")
            or prior.get("core_source_generation") != old_record.get("core_source_generation")
            or contents.get("journal.json") is None
            or reference.get("source_generation") != old_record.get("adapter_generation")):
        raise RuntimeError("Core adapter backup does not bind the retained old tuple")
    try:
        saved_old_record = json.loads(contents["journal.json"], object_pairs_hook=_unique_pairs)
    except Exception:
        raise RuntimeError("Core adapter backup journal is malformed") from None
    if saved_old_record != old_record:
        raise RuntimeError("Core adapter backup journal differs from the retained old tuple")
    if (cohort.get("phase") != "committed"
            or cohort.get("old_source") != old_record.get("adapter_source")
            or cohort.get("old_adapter_generation") != old_record.get("adapter_generation")
            or cohort.get("old_core_source_generation") != old_record.get("core_source_generation")
            or cohort.get("new_source") != current_record.get("adapter_source")
            or cohort.get("new_adapter_generation") != current_record.get("adapter_generation")
            or cohort.get("new_core_source_generation")
               != current_record.get("core_source_generation")
            or current_record.get("core_source_generation")
               != old_record.get("core_source_generation")
            or current_record.get("adapter_migration_state") != "active"
            or current_record.get("adapter_update_state") != "active"
            or current_record.get("adapter_update_previous_source")
               != old_record.get("adapter_source")
            or current_record.get("adapter_update_cohort_transaction_id")
               != cohort.get("cohort_transaction_id")):
        raise RuntimeError("Core adapter backup does not match the committed source tuple")
    try:
        selection = json.loads(contents["plugin-selection.json"], object_pairs_hook=_unique_pairs)
    except Exception:
        raise RuntimeError("Core adapter backup plugin selection is malformed") from None
    selection_sha = old_record.get("plugin_selection_sha256")
    if (selection != {"schema": 1, "selection_sha256": selection_sha}
            or current_record.get("plugin_selection_sha256") != selection_sha):
        raise RuntimeError("Core adapter backup changed native plugin selection")
    if transition is None:
        return
    if (transition["old_adapter_generation"] != old_record.get("adapter_generation")
            or transition["new_adapter_generation"] != current_record.get("adapter_generation")
            or transition["plugin_selection_sha256"] != selection_sha):
        raise RuntimeError("Core native plugin transition differs from the old/new adapter tuple")
    old_members = {
        name: hashlib.sha256(contents[_NATIVE_PLUGIN_BACKUP_NAMES[name]]).hexdigest()
        for name in _NATIVE_PLUGIN_MEMBER_NAMES
    }
    installed = core_runtime._read_installed_native_resources_plugin_members()
    installed_members = dict(installed.members)
    if (set(installed_members) != set(_NATIVE_PLUGIN_MEMBER_NAMES)
            or any(type(value) is not bytes for value in installed_members.values())):
        raise RuntimeError("installed native plugin snapshot is not the fixed pair")
    new_members = {name: hashlib.sha256(installed_members[name]).hexdigest()
                   for name in _NATIVE_PLUGIN_MEMBER_NAMES}
    if transition["old_members"] != old_members or transition["new_members"] != new_members:
        raise RuntimeError("Core native plugin transition does not match retained and installed bytes")


def _verify_adapter_refresh_commit(core_runtime, candidate_source: Path,
                                   old_record: dict, old_raw: bytes,
                                   old_files: dict, snapshots: dict) -> tuple[dict, dict, str]:
    record, raw, current_files = core_runtime._read_active_adapter_runtime()
    cohort, cohort_raw = core_runtime._read_adapter_update_cohort()
    cohort_sha = hashlib.sha256(cohort_raw).hexdigest()
    if (record.get("adapter_source") != str(candidate_source)
            or record.get("adapter_migration_state") != "active"
            or record.get("adapter_update_state") != "active"
            or record.get("adapter_update_previous_source") != old_record.get("adapter_source")
            or record.get("adapter_update_cohort_transaction_id")
               != cohort.get("cohort_transaction_id")
            or cohort.get("phase") != "committed"
            or cohort.get("old_source") != old_record.get("adapter_source")
            or cohort.get("old_adapter_generation") != old_record.get("adapter_generation")
            or cohort.get("old_core_source_generation") != old_record.get("core_source_generation")
            or cohort.get("new_source") != str(candidate_source)
            or cohort.get("new_adapter_generation") != record.get("adapter_generation")
            or record.get("core_source_generation") != old_record.get("core_source_generation")
            or raw == old_raw):
        raise RuntimeError("current committed Core cohort differs from the adapter refresh")
    reference = core_runtime._adapter_update_backup_reference(cohort)
    previous, contents = core_runtime._read_adapter_update_backup(reference)
    _verify_adapter_refresh_plugin_backup(
        core_runtime, old_record, record, cohort, reference, previous, contents)
    if (contents.get("journal.json") != old_raw
            or previous != old_record
            or contents.get("unit") != old_files.get(core_runtime.UNIT)
            or contents.get("launcher") != old_files.get(core_runtime.LAUNCHER)
            or contents.get("resources-record.json") != snapshots["resources_record"]
            or contents.get("overlay-record.json") != snapshots["overlay_record"]
            or contents.get("primary-record.json") != snapshots["primary_record"]
            or contents.get("cohort.json") != snapshots["prior_cohort"]
            or contents.get("obsidian-registration.json") != snapshots["obsidian_registration"]):
        raise RuntimeError("Core adapter-update backup does not preserve the captured old cohort")
    if (hashlib.sha256(current_files[core_runtime.UNIT]).hexdigest()
            != record.get("unit_sha256")
            or hashlib.sha256(current_files[core_runtime.LAUNCHER]).hexdigest()
               != record.get("launcher_sha256")):
        raise RuntimeError("updated Core fixed service recipe is not journal-current")
    current_snapshots = core_runtime._snapshot_adapter_update_bindings(
        core_source_generation=old_record["core_source_generation"])
    if (current_snapshots["overlay_record"] != snapshots["overlay_record"]
            or current_snapshots["obsidian_registration"] != snapshots["obsidian_registration"]
            or current_snapshots["obsidian_registration_state"]
               != snapshots["obsidian_registration_state"]
            or current_snapshots["obsidian_vault_tree_sha256"]
               != snapshots["obsidian_vault_tree_sha256"]):
        raise RuntimeError("Core update changed retained overlay or Obsidian owner custody")
    return cohort, reference, cohort_sha


def _replace_ingress_units_for_adapter_refresh(new_units, new_config: bytes,
                                               config_info: os.stat_result,
                                               saved, old_config: bytes,
                                               inspector_custody: dict) -> None:
    """Last-CAS, stop the captured old peer, retire only its socket, then switch."""
    try:
        if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
            raise _IngressSnapshotConflict("fixed ingress unit ownership changed before refresh")
        _recheck_ingress_snapshot(saved, old_config, config_info)
    except _IngressSnapshotConflict:
        raise
    except Exception:
        raise _IngressSnapshotConflict(
            "fixed ingress custody could not be reverified before refresh") from None
    # This is private state captured by the fixed producer, not a journal or
    # caller assertion. Rollback effects are allowed only after a service
    # effect has actually been entered.
    inspector_custody["refresh_effect_started"] = True
    _run("systemctl", "stop", TUNNEL)
    _run("systemctl", "stop", GATEWAY)
    _stop_captured_inspector(inspector_custody)
    _atomic_fixed(FIXED_UNITS[INSPECTOR], new_units[FIXED_UNITS[INSPECTOR]],
                  uid=0, gid=0, mode=0o644)
    _atomic_fixed(FIXED_UNITS[GATEWAY], new_units[FIXED_UNITS[GATEWAY]],
                  uid=0, gid=0, mode=0o644)
    _atomic_fixed(GATEWAY_CONFIG, new_config, uid=0, gid=config_info.st_gid,
                  mode=stat.S_IMODE(config_info.st_mode))
    _run("systemctl", "daemon-reload")


def _verify_observer_peer(observer_socket: Path, expected_pid: int) -> tuple[int, int]:
    info = observer_socket.lstat()
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != 1000
            or stat.S_IMODE(info.st_mode) != 0o660 or info.st_nlink != 1):
        raise RuntimeError("new normal observer socket custody differs")
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.settimeout(2.0)
        peer.connect(str(observer_socket))
        credentials = struct.unpack("3i", peer.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
        current = observer_socket.lstat()
        if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or credentials != (expected_pid, 0, 981)):
            raise RuntimeError("new normal observer socket is not the verified Inspector peer")
    except OSError:
        raise RuntimeError("new normal observer peer could not be verified") from None
    finally:
        peer.close()
    return info.st_dev, info.st_ino


def _verify_adapter_refresh_bindings(core_runtime, snapshots: dict,
                                     old_record: dict) -> None:
    current = core_runtime._snapshot_adapter_update_bindings(
        core_source_generation=old_record["core_source_generation"])
    if (current["overlay_record"] != snapshots["overlay_record"]
            or current["obsidian_registration"] != snapshots["obsidian_registration"]
            or current["obsidian_registration_state"] != snapshots["obsidian_registration_state"]
            or current["obsidian_vault_tree_sha256"] != snapshots["obsidian_vault_tree_sha256"]):
        raise RuntimeError("adapter refresh changed preserved overlay or owner data")
    record, raw, _files = core_runtime._read_active_adapter_runtime()
    discovery_raw = current["resources_record"]
    discovery = json.loads(discovery_raw, object_pairs_hook=_unique_pairs)
    if (discovery.get("core_ownership_sha256") != hashlib.sha256(raw).hexdigest()
            or discovery.get("core_source_generation") != old_record["core_source_generation"]
            or discovery.get("state") != "discovered"):
        raise RuntimeError("current adapter Resources discovery does not bind the new Core")
    artifact = discovery.get("artifact_sha256")
    if not isinstance(artifact, str) or re.fullmatch(r"[0-9a-f]{64}", artifact) is None:
        raise RuntimeError("current Resources artifact identity is invalid")
    archive = core_runtime._projection_file(
        core_runtime.RESOURCES_CAS / (artifact + ".zip"), owner=0, group=0,
        mode=0o600, maximum=16 * 1024 * 1024)
    if hashlib.sha256(archive).hexdigest() != artifact:
        raise RuntimeError("current adapter Resources immutable CAS is not exact")
    from hermes_installer import primary_prompt_manager as primary
    primary_raw = core_runtime._projection_file(
        core_runtime.PRIMARY_PROMPT_JOURNAL, owner=0, group=0, mode=0o600, maximum=64 * 1024)
    primary_record = primary._read_record(core_runtime)
    soul, _signature = primary._read_soul(core_runtime)
    if (type(primary_record) is not dict or primary_record.get("state") != "adopted"
            or primary_record.get("core_source_generation") != old_record["core_source_generation"]
            or primary_record.get("artifact_sha256") != artifact
            or hashlib.sha256(soul).hexdigest() != primary_record.get("result_soul_sha256")
            or discovery.get("active_primary_prompt_sha256") != hashlib.sha256(soul).hexdigest()
            or not primary_raw):
        raise RuntimeError("current primary prompt binding is not preserved and adopted")
    if not core_runtime.read_current_resources_discovery(
            core_source_generation=old_record["core_source_generation"]).get("resources_state") == "discovered":
        raise RuntimeError("current updated Core Resources readback is not discovered")


def _adapter_refresh_current_is_old(core_runtime, row: dict) -> bool:
    try:
        record, raw, _files = core_runtime._read_active_adapter_runtime()
        return (hashlib.sha256(raw).hexdigest() == row["old_core_journal_sha256"]
                and record.get("adapter_source") == row["old_core_adapter_source"]
                and record.get("adapter_generation") == row["old_core_adapter_generation"]
                and record.get("core_source_generation") == row["old_core_source_generation"])
    except Exception:
        return False


def _restore_adapter_refresh_core(core_runtime, candidate_sha: str) -> bool:
    value, _gateway, _inspector, _config = _backup_value(candidate_sha)
    row = value.get("adapter_refresh")
    if not _valid_adapter_refresh_row(row):
        return False
    if _adapter_refresh_current_is_old(core_runtime, row):
        return True
    value["state"] = "recovery-required"
    _set_backup_state("recovery-required")
    restore = getattr(core_runtime, "restore_owned_core_adapter_update", None)
    if not callable(restore):
        return False
    try:
        restore()
        record, raw, _files = core_runtime._read_active_adapter_runtime()
        return (hashlib.sha256(raw).hexdigest() == row["old_core_journal_sha256"]
                and record.get("adapter_source") == row["old_core_adapter_source"]
                and record.get("adapter_generation") == row["old_core_adapter_generation"]
                and record.get("core_source_generation") == row["old_core_source_generation"])
    except Exception:
        return False


def _recover_adapter_refresh_core_for_resume(core_runtime, candidate_sha: str,
                                            row: dict) -> tuple[dict, bytes, dict, dict]:
    """Return the exact retained old Core tuple before replaying qualification.

    The fixed Core recovery API validates the protected candidate/old tuple and
    resolves a partial cohort under its update lock. Qualification itself must
    never be used as a recovery mechanism because its preflight requires a
    complete old active snapshot.
    """
    if not _adapter_refresh_current_is_old(core_runtime, row):
        if not _restore_adapter_refresh_core(core_runtime, candidate_sha):
            raise RuntimeError("matching interrupted Core cohort could not recover its retained prior tuple")
    record, raw, files = core_runtime._read_active_adapter_runtime()
    if (hashlib.sha256(raw).hexdigest() != row["old_core_journal_sha256"]
            or record.get("adapter_source") != row["old_core_adapter_source"]
            or record.get("adapter_generation") != row["old_core_adapter_generation"]
            or record.get("core_source_generation") != row["old_core_source_generation"]):
        raise RuntimeError("resumed Core does not match the retained old adapter tuple")
    snapshots = core_runtime._snapshot_adapter_update_bindings(
        core_source_generation=row["old_core_source_generation"])
    return record, raw, files, snapshots


def _valid_native_plugin_member_digests(value: object) -> bool:
    return (type(value) is dict and set(value) == set(_NATIVE_PLUGIN_MEMBER_NAMES)
            and all(isinstance(value[name], str)
                    and re.fullmatch(r"[0-9a-f]{64}", value[name]) is not None
                    for name in _NATIVE_PLUGIN_MEMBER_NAMES))


def _valid_native_plugin_transition(value: object) -> bool:
    if type(value) is not dict or set(value) != _NATIVE_PLUGIN_TRANSITION_FIELDS:
        return False
    return (type(value["schema"]) is int and value["schema"] == 1
            and value["purpose"] == "fixed-native-resources-plugin"
            and isinstance(value["old_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["old_adapter_generation"]) is not None
            and isinstance(value["new_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["new_adapter_generation"]) is not None
            and value["old_adapter_generation"] != value["new_adapter_generation"]
            and isinstance(value["plugin_selection_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["plugin_selection_sha256"]) is not None
            and _valid_native_plugin_member_digests(value["old_members"])
            and _valid_native_plugin_member_digests(value["new_members"])
            and value["old_members"]["plugin.yaml"] == value["new_members"]["plugin.yaml"]
            and value["old_members"]["__init__.py"] != value["new_members"]["__init__.py"])


def _finish_adapter_refresh_ingress(candidate_sha: str, expected_source: Path,
                                    core_runtime, observer_socket: Path,
                                    old_observer_identity: tuple[int, int] | None) -> None:
    _refresh_migrated_core_config(candidate_sha, expected_source, core_runtime)
    from hermes_installer.remote.core_gateway import CoreGatewayConfig
    config = CoreGatewayConfig.load(expected_owner_uid=0)
    _verify_gateway_tunnel(config, require_active=False)
    if _unit_state(INSPECTOR) in {"inactive", "failed"}:
        _run("systemctl", "start", INSPECTOR)
    if not _unit_is_exact_and_active(INSPECTOR):
        raise RuntimeError("new fixed Inspector did not become active")
    unit_raw, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                              mode=0o644, maximum=64 * 1024)
    _verify_inspector_process(unit_raw, str(expected_source).encode("ascii"))
    phase_identity = _wait_observer_socket(previous_inode=old_observer_identity)
    inspector_pid = int(_run("systemctl", "show", "--property=MainPID", "--value", INSPECTOR))
    if phase_identity != _verify_observer_peer(observer_socket, inspector_pid):
        raise RuntimeError("fresh normal observer socket changed after peer verification")
    _run("systemctl", "start", GATEWAY)
    _run("systemctl", "start", TUNNEL)
    config = CoreGatewayConfig.load(expected_owner_uid=0)
    _verify_gateway_tunnel(config, require_active=True)
    if not all(_unit_is_exact_and_active(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
        raise RuntimeError("updated ingress cohort did not verify")


def _verify_current_adapter_refresh_join(core_runtime, row: dict) -> tuple[dict, bytes, dict, dict, str]:
    record, raw, files = core_runtime._read_active_adapter_runtime()
    cohort, cohort_raw = core_runtime._read_adapter_update_cohort()
    reference = core_runtime._adapter_update_backup_reference(cohort)
    prior, contents = core_runtime._read_adapter_update_backup(reference)
    digest = hashlib.sha256(cohort_raw).hexdigest()
    _verify_adapter_refresh_plugin_backup(
        core_runtime, prior, record, cohort, reference, prior, contents)
    if (record.get("adapter_update_state") != "active"
            or cohort.get("phase") != "committed"
            or cohort.get("old_source") != row["old_core_adapter_source"]
            or cohort.get("old_adapter_generation") != row["old_core_adapter_generation"]
            or cohort.get("old_core_source_generation") != row["old_core_source_generation"]
            or hashlib.sha256(contents["journal.json"]).hexdigest()
               != row["old_core_journal_sha256"]
            or prior.get("adapter_source") != row["old_core_adapter_source"]
            or prior.get("adapter_generation") != row["old_core_adapter_generation"]
            or prior.get("core_source_generation") != row["old_core_source_generation"]
            or (row["core_update_backup_reference"] is not None
                and row["core_update_backup_reference"] != reference)
            or (row["core_update_cohort_transaction_id"] is not None
                and row["core_update_cohort_transaction_id"] != cohort.get("cohort_transaction_id"))
            or (row["core_update_cohort_sha256"] is not None
                and row["core_update_cohort_sha256"] != digest)):
        raise RuntimeError("current committed adapter update does not join the retained old Core")
    return cohort, cohort_raw, reference, contents, digest


def _snapshots_from_adapter_backup(contents: dict, cohort: dict) -> dict:
    registration = contents["obsidian-registration.json"]
    return {
        "resources_record": contents["resources-record.json"],
        "overlay_record": contents["overlay-record.json"],
        "primary_record": contents["primary-record.json"],
        "prior_cohort": contents["cohort.json"],
        "obsidian_registration": registration,
        "obsidian_registration_state": "registered" if registration else "absent",
        "obsidian_registration_sha256": hashlib.sha256(registration).hexdigest()
        if registration else "0" * 64,
        "obsidian_vault_tree_sha256": cohort.get("obsidian_vault_tree_sha256"),
    }


def _resume_prepared_adapter_refresh(candidate_sha: str, expected_source: Path,
                                    archive_sha: str, core_runtime,
                                    observer_socket: Path, value: dict,
                                    old_gateway: bytes, old_inspector: bytes,
                                    old_config: bytes) -> None:
    """Continue a successor after its prepared journal replaced a prior record."""
    _verify_archived_completed_ingress(value)
    record, raw, _files, _snapshots, custody = _adapter_refresh_snapshot(
        core_runtime, expected_source, observer_socket)
    try:
        row = value.get("adapter_refresh")
        if (not _valid_adapter_refresh_row(row)
                or hashlib.sha256(raw).hexdigest() != row["old_core_journal_sha256"]
                or record.get("adapter_source") != row["old_core_adapter_source"]
                or record.get("adapter_generation") != row["old_core_adapter_generation"]
                or record.get("core_source_generation") != row["old_core_source_generation"]):
            raise RuntimeError("prepared successor no longer joins its exact prior Core")
        actual_gateway, gateway_info = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                                   mode=0o644, maximum=64 * 1024)
        actual_inspector, inspector_info = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                                      mode=0o644, maximum=64 * 1024)
        actual_config, config_info = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                                 mode=0o440, maximum=16 * 1024)
        if (actual_gateway != old_gateway or actual_inspector != old_inspector
                or actual_config != old_config):
            raise RuntimeError("prepared successor no longer has its exact prior ingress files")
        from hermes_installer.remote.core_gateway import CoreGatewayConfig
        _verify_gateway_tunnel(CoreGatewayConfig.load(expected_owner_uid=0), require_active=True)

        old_source = record["adapter_source"].encode("ascii", "strict")
        new_units = {
            FIXED_UNITS[INSPECTOR]: _replace_unit_source(
                old_inspector, old_source, str(expected_source).encode("ascii")),
            FIXED_UNITS[GATEWAY]: _replace_unit_source(
                old_gateway, old_source, str(expected_source).encode("ascii")),
        }
        if (hashlib.sha256(new_units[FIXED_UNITS[GATEWAY]]).hexdigest()
                != value["new_gateway_sha256"]
                or hashlib.sha256(new_units[FIXED_UNITS[INSPECTOR]]).hexdigest()
                != value["new_inspector_sha256"]):
            raise RuntimeError("prepared successor fixed unit recipe differs")
        new_config = _journaled_new_gateway_config(
            value, old_gateway, old_inspector, old_config, expected_source)
        repaired = _runtime_repaired_inspector(new_units[FIXED_UNITS[INSPECTOR]])
        _set_runtime_inspector_digest(
            candidate_sha, value["new_inspector_sha256"], hashlib.sha256(repaired).hexdigest())
        new_units[FIXED_UNITS[INSPECTOR]] = repaired

        protected_raw, protected_info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0,
                                                    mode=0o600, maximum=128 * 1024)
        protected = json.loads(protected_raw, object_pairs_hook=_unique_pairs)
        protected_row = protected.get("adapter_refresh")
        immutable_old_join = ("old_core_journal_sha256", "old_core_adapter_source",
                              "old_core_adapter_generation", "old_core_source_generation")
        if (protected.get("candidate_sha") != candidate_sha
                or protected.get("state") not in {"prepared", "recovery-required"}
                or protected.get("prior_completed_ingress_sha256")
                   != value.get("prior_completed_ingress_sha256")
                or not _valid_adapter_refresh_row(protected_row)
                or any(protected_row.get(key) != row.get(key)
                       for key in immutable_old_join)):
            raise RuntimeError("prepared successor changed before current Inspector rebind")
        protected["adapter_refresh"] = custody["row"]
        rebound = (json.dumps(protected, sort_keys=True, separators=(",", ":"))
                   + "\n").encode("ascii")
        _atomic_fixed(INGRESS_BACKUP, rebound, uid=0, gid=0,
                      mode=stat.S_IMODE(protected_info.st_mode))
        _set_backup_state("recovery-required")
        saved = {FIXED_UNITS[GATEWAY]: (old_gateway, gateway_info),
                 FIXED_UNITS[INSPECTOR]: (old_inspector, inspector_info)}
        _replace_ingress_units_for_adapter_refresh(
            new_units, new_config, config_info, saved, old_config, custody)
        _set_backup_state("recovery-required")
    finally:
        os.close(custody["pidfd"])
    _resume_adapter_refresh(candidate_sha, expected_source, archive_sha,
                             core_runtime, observer_socket)


def _resume_adapter_refresh(candidate_sha: str, expected_source: Path,
                            archive_sha: str, core_runtime,
                            observer_socket: Path) -> str | None:
    value, old_gateway, old_inspector, old_config = _backup_value(candidate_sha)
    _verify_archived_completed_ingress(value)
    row = value.get("adapter_refresh")
    if (value.get("state") in {"prepared", "recovery-required"}
            and value.get("prior_completed_ingress_sha256") is not None):
        try:
            current_gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                              mode=0o644, maximum=64 * 1024)
            current_inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                                mode=0o644, maximum=64 * 1024)
            current_config, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                             mode=0o440, maximum=16 * 1024)
            still_prior = (current_gateway == old_gateway and current_inspector == old_inspector
                           and current_config == old_config)
        except Exception:
            still_prior = False
        if still_prior:
            _resume_prepared_adapter_refresh(
                candidate_sha, expected_source, archive_sha, core_runtime,
                observer_socket, value, old_gateway, old_inspector, old_config)
            return None
    if (not _valid_adapter_refresh_row(row)
            or value["state"] not in {"recovery-required", "migrated"}
            or any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL))):
        raise RuntimeError("saved adapter refresh is not eligible for exact resume")
    join_values = tuple(row[key] for key in (
        "core_update_backup_reference", "core_update_cohort_transaction_id",
        "core_update_cohort_sha256"))
    joined = all(item is not None for item in join_values)
    if not joined and any(item is not None for item in join_values):
        raise RuntimeError("adapter refresh Core recovery join is incomplete")
    if joined:
        try:
            current_cohort, _current_cohort_raw = core_runtime._read_adapter_update_cohort()
        except Exception:
            raise RuntimeError("joined adapter refresh has no readable current Core cohort") from None
        if type(current_cohort) is not dict:
            raise RuntimeError("joined adapter refresh current Core cohort is malformed")
        if current_cohort.get("phase") == "rolling-back":
            _resume_rolling_back_adapter_refresh(
                candidate_sha, expected_source, row, value, old_gateway, old_inspector, old_config,
                core_runtime, observer_socket, current_cohort)
            return "rolled-back"
        if current_cohort.get("phase") != "committed":
            raise RuntimeError("joined adapter refresh is in an unexpected Core recovery phase")
        # Validate the live Core row, full manifest, retained plugin members,
        # and installed new pair before any ingress stop during resume.
        committed = _verify_current_adapter_refresh_join(core_runtime, row)
    else:
        committed = None
    gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0, mode=0o644,
                             maximum=64 * 1024)
    inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0, mode=0o644,
                               maximum=64 * 1024)
    if (hashlib.sha256(gateway).hexdigest() != value["new_gateway_sha256"]
            or hashlib.sha256(inspector).hexdigest() not in {
                value["new_inspector_sha256"], value.get("runtime_inspector_sha256")}
            or _unit_source(gateway, "core_gateway") != str(expected_source).encode("ascii")
            or _unit_source(inspector, "core_gateway_inspector")
               != str(expected_source).encode("ascii")):
        raise RuntimeError("fixed adapter refresh units do not match the saved candidate")
    current_raw, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981, mode=0o440, maximum=16 * 1024)
    if hashlib.sha256(current_raw).hexdigest() not in {
            value["new_config_sha256"], value["post_core_config_sha256"]}:
        raise RuntimeError("adapter refresh Gateway config is outside the saved transaction")

    # A crash can occur after Gateway starts but before Tunnel does. Once the
    # fixed recipe/config CAS above is current, close any partially resumed
    # public ingress before touching the native process or Core recovery.
    for name in (TUNNEL, GATEWAY):
        state = _unit_state(name)
        if state in {"active", "failed"}:
            _run("systemctl", "stop", name, check=False)
        elif state != "inactive":
            raise RuntimeError("public ingress state is not stable for refresh resume")
    if any(_unit_state(name) != "inactive" for name in (GATEWAY, TUNNEL)):
        raise RuntimeError("public ingress did not close for refresh resume")

    if _unit_state(INSPECTOR) == "active":
        _retire_current_refresh_inspector(expected_source, observer_socket)
    elif _unit_state(INSPECTOR) not in {"inactive", "failed"}:
        raise RuntimeError("Inspector state is not stable for refresh resume")
    if joined:
        # Recheck after closing ingress so a concurrent Core tuple change cannot
        # turn the earlier pre-effect read into stale authority.
        committed = _verify_current_adapter_refresh_join(core_runtime, row)
    if committed is None:
        old_record, old_raw, old_files, snapshots = _recover_adapter_refresh_core_for_resume(
            core_runtime, candidate_sha, row)
        resumed_archive, tool, tool_identity = _read_candidate_qualification_inputs(
            candidate_sha, expected_source)
        if resumed_archive != archive_sha:
            raise RuntimeError("candidate source receipt changed before adapter refresh resume")
        _run_core_refresh_qualification(candidate_sha, archive_sha, tool, tool_identity)
        cohort, reference, cohort_sha = _verify_adapter_refresh_commit(
            core_runtime, expected_source, old_record, old_raw, old_files, snapshots)
        _verify_adapter_refresh_bindings(core_runtime, snapshots, old_record)
        _set_adapter_refresh_core_join(core_runtime, candidate_sha, reference,
                                       cohort["cohort_transaction_id"], cohort_sha)
    else:
        cohort, _raw, reference, contents, cohort_sha = committed
        snapshots = _snapshots_from_adapter_backup(contents, cohort)
        old_record = json.loads(contents["journal.json"], object_pairs_hook=_unique_pairs)
        _verify_adapter_refresh_bindings(core_runtime, snapshots, old_record)
        if row["core_update_backup_reference"] is None:
            _set_adapter_refresh_core_join(core_runtime, candidate_sha, reference,
                                           cohort["cohort_transaction_id"], cohort_sha)
    _set_backup_state("migrated")
    old_identity = ((row["old_observer_device"], row["old_observer_inode"])
                    if row["old_observer_state"] == "verified-owned" else None)
    _finish_adapter_refresh_ingress(candidate_sha, expected_source, core_runtime,
                                    observer_socket, old_identity)


def _resume_rolling_back_adapter_refresh(candidate_sha: str, expected_source: Path,
                                         row: dict, value: dict,
                                         old_gateway: bytes, old_inspector: bytes,
                                         old_config: bytes, core_runtime,
                                         observer_socket: Path, rolling_cohort: dict) -> None:
    """Finish a retained Core rollback without replaying adapter qualification."""
    if value.get("state") != "recovery-required":
        raise RuntimeError("rolling-back Core recovery requires a retained recovery transaction")
    for path, allowed in (
            (FIXED_UNITS[GATEWAY], {value["old_gateway_sha256"], value["new_gateway_sha256"]}),
            (FIXED_UNITS[INSPECTOR], {value["old_inspector_sha256"],
                                      value["new_inspector_sha256"],
                                      value.get("runtime_inspector_sha256")})):
        raw, _ = _read_fixed(path, uid=0, gid=0, mode=0o644, maximum=64 * 1024)
        if hashlib.sha256(raw).hexdigest() not in allowed:
            raise RuntimeError("rolling-back ingress unit differs from the retained old/new snapshots")
    current_config, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                     mode=0o440, maximum=16 * 1024)
    if hashlib.sha256(current_config).hexdigest() not in {
            value["old_config_sha256"], value["new_config_sha256"],
            value.get("post_core_config_sha256")}:
        raise RuntimeError("rolling-back Gateway config differs from retained snapshots")
    if (row["core_update_backup_reference"] is None
            or row["core_update_cohort_transaction_id"]
               != rolling_cohort.get("cohort_transaction_id")
            or rolling_cohort.get("old_source") != row["old_core_adapter_source"]
            or rolling_cohort.get("old_adapter_generation")
               != row["old_core_adapter_generation"]
            or rolling_cohort.get("old_core_source_generation")
               != row["old_core_source_generation"]
            or rolling_cohort.get("old_journal_sha256") != row["old_core_journal_sha256"]
            or rolling_cohort.get("new_source") != str(expected_source)):
        raise RuntimeError("rolling-back Core cohort does not match the retained update join")

    try:
        reference = core_runtime._adapter_update_backup_reference(rolling_cohort)
        prior_record, contents = core_runtime._read_adapter_update_backup(reference)
    except Exception:
        raise RuntimeError("rolling-back Core backup is not available from its protected cohort") from None
    if (reference != row["core_update_backup_reference"]
            or hashlib.sha256(contents.get("journal.json", b"")).hexdigest()
               != row["old_core_journal_sha256"]
            or prior_record.get("adapter_source") != row["old_core_adapter_source"]
            or prior_record.get("adapter_generation") != row["old_core_adapter_generation"]
            or prior_record.get("core_source_generation") != row["old_core_source_generation"]):
        raise RuntimeError("rolling-back Core backup differs from the retained old tuple")

    # Ingress first stays closed. If part of a previous restore already ran,
    # only exact transaction-owned recipes/configuration can be stopped.
    _set_backup_state("recovery-required")
    for name in (TUNNEL, GATEWAY):
        state = _unit_state(name)
        if state in {"active", "failed"}:
            _run("systemctl", "stop", name, check=False)
        elif state != "inactive":
            raise RuntimeError("public ingress state is unstable during rollback resume")
    if any(_unit_state(name) != "inactive" for name in (GATEWAY, TUNNEL)):
        raise RuntimeError("public ingress did not close for rolling-back Core recovery")
    if _unit_state(INSPECTOR) == "active":
        current_inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                           mode=0o644, maximum=64 * 1024)
        inspector_source = Path(_unit_source(current_inspector,
                                              "core_gateway_inspector").decode("ascii"))
        if str(inspector_source) not in {str(expected) for expected in (
                Path(row["old_core_adapter_source"]), expected_source)}:
            raise RuntimeError("running Inspector is outside the retained rollback sources")
        _retire_current_refresh_inspector(inspector_source, observer_socket)
    elif _unit_state(INSPECTOR) not in {"inactive", "failed"}:
        raise RuntimeError("Inspector state is unstable during rollback resume")
    else:
        try:
            observer_socket.lstat()
        except FileNotFoundError:
            pass
        else:
            raise RuntimeError("stale observer socket blocks rollback resume")

    restore = getattr(core_runtime, "restore_owned_core_adapter_update", None)
    if not callable(restore):
        raise RuntimeError("fixed Core rollback recovery is unavailable")
    try:
        restore()
    except Exception:
        raise RuntimeError("exact old Core could not be verified during rollback resume") from None
    restored_record, restored_raw, restored_files = core_runtime._read_active_adapter_runtime()
    if (hashlib.sha256(restored_raw).hexdigest() != row["old_core_journal_sha256"]
            or restored_record.get("adapter_source") != row["old_core_adapter_source"]
            or restored_record.get("adapter_generation") != row["old_core_adapter_generation"]
            or restored_record.get("core_source_generation") != row["old_core_source_generation"]
            or restored_files.get(core_runtime.UNIT) != contents.get("unit")
            or restored_files.get(core_runtime.LAUNCHER) != contents.get("launcher")):
        raise RuntimeError("restored Core does not match the retained old source and service recipe")
    current_bindings = core_runtime._snapshot_adapter_update_bindings(
        core_source_generation=row["old_core_source_generation"])
    if (current_bindings.get("resources_record") != contents.get("resources-record.json")
            or current_bindings.get("overlay_record") != contents.get("overlay-record.json")
            or current_bindings.get("primary_record") != contents.get("primary-record.json")
            or current_bindings.get("prior_cohort") != contents.get("cohort.json")
            or current_bindings.get("obsidian_registration")
               != contents.get("obsidian-registration.json")
            or current_bindings.get("obsidian_registration_state")
               != ("registered" if contents.get("obsidian-registration.json") else "absent")
            or current_bindings.get("obsidian_vault_tree_sha256")
               != rolling_cohort.get("obsidian_vault_tree_sha256")):
        raise RuntimeError("restored Core bindings differ from the retained old owner snapshot")
    if not _restore_old_ingress(value, old_gateway, old_inspector, old_config,
                                observer_socket=observer_socket,
                                expected_observer_source=Path(row["old_core_adapter_source"])):
        _set_backup_state("recovery-required")
        raise RuntimeError("old ingress did not recover; public ingress remains stopped")
    _remove_ingress_backup()


def _rollback_adapter_refresh(candidate_sha: str, expected_source: Path,
                               core_runtime, observer_socket: Path) -> None:
    value, old_gateway, old_inspector, old_config = _backup_value(candidate_sha)
    _verify_archived_completed_ingress(value)
    row = value.get("adapter_refresh")
    if (not _valid_adapter_refresh_row(row)
            or any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL))):
        raise RuntimeError("saved adapter refresh is not eligible for rollback")
    current_gateway, _ = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                      mode=0o644, maximum=64 * 1024)
    current_inspector, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                        mode=0o644, maximum=64 * 1024)
    current_config, _ = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                     mode=0o440, maximum=16 * 1024)
    if (hashlib.sha256(current_gateway).hexdigest() not in
            {value["new_gateway_sha256"], value["old_gateway_sha256"]}
            or hashlib.sha256(current_inspector).hexdigest() not in
            {value["new_inspector_sha256"], value.get("runtime_inspector_sha256"),
             value["old_inspector_sha256"]}
            or hashlib.sha256(current_config).hexdigest() not in
            {value["new_config_sha256"], value["old_config_sha256"],
             value.get("post_core_config_sha256")}):
        raise RuntimeError("fixed adapter refresh ingress differs from retained snapshots")
    joins = tuple(row[key] for key in (
        "core_update_backup_reference", "core_update_cohort_transaction_id",
        "core_update_cohort_sha256"))
    if all(item is not None for item in joins):
        current_cohort, _ = core_runtime._read_adapter_update_cohort()
        if current_cohort.get("phase") == "committed":
            _verify_current_adapter_refresh_join(core_runtime, row)
        elif current_cohort.get("phase") != "rolling-back":
            raise RuntimeError("joined adapter refresh Core tuple is not rollback-current")
    elif any(item is not None for item in joins):
        raise RuntimeError("adapter refresh Core recovery join is incomplete")
    _set_backup_state("recovery-required")
    for name in (TUNNEL, GATEWAY):
        _run("systemctl", "stop", name, check=False)
    if not _restore_adapter_refresh_core(core_runtime, candidate_sha):
        raise RuntimeError("exact prior Core could not be verified; ingress remains stopped")
    _retire_current_refresh_inspector(expected_source, observer_socket)
    if not _restore_old_ingress(value, old_gateway, old_inspector, old_config,
                                observer_socket=observer_socket,
                                expected_observer_source=Path(row["old_core_adapter_source"])):
        _set_backup_state("recovery-required")
        raise RuntimeError("exact prior ingress could not be restored; public ingress remains stopped")
    _remove_ingress_backup()


def _retire_current_refresh_inspector(expected_source: Path,
                                      observer_socket: Path) -> None:
    if _unit_state(INSPECTOR) == "active":
        unit_raw, _ = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                  mode=0o644, maximum=64 * 1024)
        custody = _capture_inspector_custody(
            unit_raw, str(expected_source).encode("ascii"), observer_socket)
        try:
            _stop_captured_inspector(custody)
        finally:
            os.close(custody["pidfd"])
    else:
        try:
            observer_socket.lstat()
        except FileNotFoundError:
            return
        raise RuntimeError("unowned stale normal observer socket blocks recovery")


def _apply_adapter_refresh(candidate_sha: str, expected_source: Path,
                           archive_sha: str, tool: Path, tool_identity: tuple,
                           core_runtime, observer_socket: Path,
                           *, approved_union: bool,
                           completed_predecessor: dict | None = None) -> int:
    custody = None
    saved = None
    old_config = None
    config_info = None
    core_record = core_raw = core_files = snapshots = None
    phase = "capture active adapter and old Inspector custody"
    try:
        core_record, core_raw, core_files, snapshots, custody = _adapter_refresh_snapshot(
            core_runtime, expected_source, observer_socket)
        phase = "validate active Gateway and tunnel"
        from hermes_installer.remote.core_gateway import CoreGatewayConfig
        config = CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_gateway_tunnel(config, require_active=True)
        phase = "build exact ingress source switch and protected refresh record"
        saved, old_config, config_info, new_units, new_config = _source_switch(
            expected_source, read_approved_email_union=approved_union)
        if (hashlib.sha256(saved[FIXED_UNITS[INSPECTOR]][0]).hexdigest()
                   != custody["identity"]["unit_sha256"]
                or _unit_source(saved[FIXED_UNITS[INSPECTOR]][0],
                                "core_gateway_inspector")
                   != core_record["adapter_source"].encode("ascii")):
            raise RuntimeError("captured Inspector changed before staging adapter refresh")
        if completed_predecessor is not None and (
                hashlib.sha256(core_raw).hexdigest()
                    != completed_predecessor["core_journal_sha256"]
                or core_record.get("adapter_source") != completed_predecessor["core_adapter_source"]
                or core_record.get("adapter_generation")
                   != completed_predecessor["core_adapter_generation"]
                or core_record.get("core_source_generation")
                   != completed_predecessor["core_source_generation"]
                or hashlib.sha256(saved[FIXED_UNITS[GATEWAY]][0]).hexdigest()
                   != completed_predecessor["gateway_unit_sha256"]
                or hashlib.sha256(saved[FIXED_UNITS[INSPECTOR]][0]).hexdigest()
                   != completed_predecessor["inspector_unit_sha256"]
                or hashlib.sha256(old_config).hexdigest()
                   != completed_predecessor["config_sha256"]):
            raise RuntimeError("active Core or ingress changed after predecessor qualification")
        row = dict(custody["row"])
        phase = "write adapter refresh rollback snapshot"
        _save_ingress_backup(candidate_sha, saved, old_config, config_info,
                             new_units, new_config, adapter_refresh=row,
                             completed_predecessor=completed_predecessor)
        # From this durable point, a reboot or interruption must resolve this
        # exact transaction before any public ingress is allowed to return.
        _set_backup_state("recovery-required")
        base_inspector_sha = hashlib.sha256(new_units[FIXED_UNITS[INSPECTOR]]).hexdigest()
        repaired_inspector = _runtime_repaired_inspector(new_units[FIXED_UNITS[INSPECTOR]])
        _set_runtime_inspector_digest(candidate_sha, base_inspector_sha,
                                      hashlib.sha256(repaired_inspector).hexdigest())
        new_units[FIXED_UNITS[INSPECTOR]] = repaired_inspector
        phase = "close ingress and retire only the captured old Inspector socket"
        _replace_ingress_units_for_adapter_refresh(new_units, new_config, config_info,
                                                   saved, old_config, custody)
        _set_backup_state("units-switched")
        phase = "run fixed Root Core adapter qualification subprocess"
        _run_core_refresh_qualification(candidate_sha, archive_sha, tool, tool_identity)
        phase = "independently verify committed Core backup and preserved bindings"
        cohort, reference, cohort_sha = _verify_adapter_refresh_commit(
            core_runtime, expected_source, core_record, core_raw, core_files, snapshots)
        _verify_adapter_refresh_bindings(core_runtime, snapshots, core_record)
        _set_adapter_refresh_core_join(core_runtime, candidate_sha, reference,
                                       cohort["cohort_transaction_id"], cohort_sha)
        _set_backup_state("migrated")
        phase = "bind config to current journaled Core"
        _finish_adapter_refresh_ingress(candidate_sha, expected_source, core_runtime,
                                        observer_socket,
                                        (custody["observer_device"], custody["observer_inode"])
                                        if custody["observer_state"] == "verified-owned" else None)
        print("Existing native Core adapter and Jarvis ingress refreshed and independently read back.")
        print("Existing owner registration/vault bytes were preserved; global owner operations remain pending their current gate.")
        print("Added-account logins and full M1 acceptance remain separate target witnesses.")
        print("Exact rollback command: rerun this helper with the same --candidate-sha and --rollback.")
        return 0
    except _IngressSnapshotConflict as error:
        print("Adapter refresh stopped before service effects; protected transaction retained.")
        print("Failure type: " + type(error).__name__)
        return 4
    except Exception as error:
        failed_phase = phase
        restored = False
        effects_started = (custody is not None
                           and custody.get("refresh_effect_started") is True)
        if saved is not None and effects_started:
            try:
                _set_backup_state("recovery-required")
                for name in (TUNNEL, GATEWAY):
                    _run("systemctl", "stop", name, check=False)
                if _adapter_refresh_current_is_old(core_runtime, custody["row"]):
                    restored = True
                else:
                    # The fixed Core API consumes only the protected row and
                    # derives either committed or interrupted recovery itself.
                    restored = _restore_adapter_refresh_core(core_runtime, candidate_sha)
                if restored:
                    _retire_current_refresh_inspector(expected_source, observer_socket)
                    value, old_gateway, old_inspector, old_cfg = _backup_value(candidate_sha)
                    restored = _restore_old_ingress(
                        value, old_gateway, old_inspector, old_cfg,
                        observer_socket=observer_socket,
                        expected_observer_source=Path(custody["source"].decode("ascii")))
                if restored:
                    INGRESS_BACKUP.unlink(missing_ok=True)
            except Exception:
                restored = False
            if not restored:
                try:
                    _set_backup_state("recovery-required")
                except Exception:
                    pass
        if saved is not None and not effects_started:
            print("Adapter refresh stopped before service effects.")
            print("No service effect began; prior public ingress remains untouched and the protected journal is retained.")
        else:
            print("Adapter refresh did not complete; automatic recovery was attempted from the retained journal.")
            print("Prior Core and ingress verified: " + ("yes" if restored else "no; public ingress remains stopped"))
        print("Failed phase: " + failed_phase)
        print("Failure type: " + type(error).__name__)
        return 4
    finally:
        if custody is not None:
            try:
                os.close(custody["pidfd"])
            except OSError:
                pass


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


def _read_approved_email_union() -> tuple[str, ...]:
    """Read one bounded, explicit JSON array without exposing its contents."""
    try:
        raw = sys.stdin.buffer.read(_APPROVED_EMAIL_UNION_MAX_BYTES + 1)
        if type(raw) is not bytes or not raw or len(raw) > _APPROVED_EMAIL_UNION_MAX_BYTES:
            raise ValueError
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
        if (type(value) is not list or not 1 <= len(value) <= 32
                or any(type(email) is not str or len(email) > 254 for email in value)):
            raise ValueError
        from hermes_installer.remote.config import _EMAIL
        normalized = []
        for email in value:
            address = email.strip().casefold()
            if (not address or len(address) > 254
                    or any(unicodedata.category(char) == "Cc" for char in email)
                    or not _EMAIL.fullmatch(address)):
                raise ValueError
            normalized.append(address)
        if len(set(normalized)) != len(normalized):
            raise ValueError
        return tuple(normalized)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise RuntimeError("approved email union input is invalid") from None


def _normalized_email_list(value) -> tuple[str, ...]:
    try:
        if (type(value) is not list or not 1 <= len(value) <= 32
                or any(type(email) is not str or len(email) > 254 for email in value)):
            raise ValueError
        from hermes_installer.remote.config import _EMAIL
        normalized = []
        for email in value:
            address = email.strip().casefold()
            if (not address or len(address) > 254
                    or any(unicodedata.category(char) == "Cc" for char in email)
                    or not _EMAIL.fullmatch(address)):
                raise ValueError
            normalized.append(address)
        if len(set(normalized)) != len(normalized):
            raise ValueError
        return tuple(normalized)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("fixed Gateway email allowlist is invalid") from None


def _source_switch(candidate_source: Path, *, read_approved_email_union: bool = False):
    from hashlib import sha256

    if read_approved_email_union and os.geteuid() != 0:
        raise RuntimeError("approved email union intake requires the fixed Root apply actor")
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
    if read_approved_email_union:
        approved_union = _read_approved_email_union()
        prior_emails = _normalized_email_list(config_value.get("allowed_emails"))
        if not set(prior_emails).issubset(approved_union):
            raise RuntimeError("approved email union must preserve every current member")
        config_value["allowed_emails"] = list(approved_union)
    config_value["gateway_unit_sha256"] = sha256(new_units[FIXED_UNITS[GATEWAY]]).hexdigest()
    new_config = (json.dumps(config_value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(new_config) > 16 * 1024:
        raise RuntimeError("fixed Gateway config exceeded its bound")
    return saved, config_raw, config_info, new_units, new_config


def _save_ingress_backup(candidate_sha: str, saved, config_raw: bytes,
                         config_info: os.stat_result, new_units, new_config: bytes,
                         *, adapter_refresh: dict | None = None,
                         completed_predecessor: dict | None = None) -> None:
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
        "new_gateway_config": base64.b64encode(new_config).decode("ascii"),
        "post_core_config_sha256": None,
        "runtime_inspector_sha256": None,
        "old_gateway_sha256": hashlib.sha256(saved[FIXED_UNITS[GATEWAY]][0]).hexdigest(),
        "old_inspector_sha256": hashlib.sha256(saved[FIXED_UNITS[INSPECTOR]][0]).hexdigest(),
        "old_config_sha256": hashlib.sha256(config_raw).hexdigest(),
        "adapter_refresh": adapter_refresh,
        "prior_completed_ingress_sha256": (
            completed_predecessor["sha256"] if completed_predecessor is not None else None),
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
    if completed_predecessor is None:
        try:
            os.link(temporary, INGRESS_BACKUP, follow_symlinks=False)
        finally:
            temporary.unlink(missing_ok=True)
    else:
        try:
            _replace_completed_ingress_backup(temporary, completed_predecessor)
        finally:
            temporary.unlink(missing_ok=True)
    dfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                  | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _ingress_backup_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _replace_completed_ingress_backup(temporary: Path, predecessor: dict) -> None:
    """CAS-replace only the exact completed backup retained under the adopter lock."""
    current, info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600,
                                maximum=128 * 1024)
    if (current != predecessor["raw"]
            or _ingress_backup_identity(info) != predecessor["identity"]):
        raise _IngressSnapshotConflict("completed ingress backup changed before successor handoff")
    os.replace(temporary, INGRESS_BACKUP)
    parent_fd = os.open(INGRESS_BACKUP.parent, os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _read_ingress_history_file(path: Path, *, allowed_links: set[int]) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_nlink not in allowed_links or not 1 <= before.st_size <= 128 * 1024):
            raise RuntimeError("fixed ingress history entry custody differs")
        raw = bytearray()
        while len(raw) <= 128 * 1024:
            chunk = os.read(fd, min(8192, 128 * 1024 + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (len(raw) != before.st_size or len(raw) > 128 * 1024
                or _ingress_backup_identity(before) != _ingress_backup_identity(after)
                or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
            raise RuntimeError("fixed ingress history entry changed during read")
        return bytes(raw), before
    finally:
        os.close(fd)


def _archive_completed_ingress_bytes(raw: bytes) -> tuple[str, tuple[int, ...]]:
    if not 1 <= len(raw) <= 128 * 1024:
        raise RuntimeError("completed ingress backup exceeds its retained bound")
    digest = hashlib.sha256(raw).hexdigest()
    parent = INGRESS_HISTORY.parent
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
            or parent_info.st_gid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o700):
        raise RuntimeError("fixed ingress history parent custody differs")
    try:
        INGRESS_HISTORY.mkdir(mode=0o700)
    except FileExistsError:
        pass
    dir_info = INGRESS_HISTORY.lstat()
    if (not stat.S_ISDIR(dir_info.st_mode) or dir_info.st_uid != 0
            or dir_info.st_gid != 0 or stat.S_IMODE(dir_info.st_mode) != 0o700
            or dir_info.st_nlink < 2):
        raise RuntimeError("fixed ingress history directory custody differs")
    archive = INGRESS_HISTORY / (digest + ".json")
    temporary = INGRESS_HISTORY / ("." + digest + ".pending")
    try:
        existing = archive.lstat()
    except FileNotFoundError:
        existing = None
    except OSError:
        raise RuntimeError("fixed ingress history path cannot be inspected") from None
    if existing is not None:
        archived, archived_info = _read_ingress_history_file(archive, allowed_links={1, 2})
        if archived != raw or hashlib.sha256(archived).hexdigest() != digest:
            raise RuntimeError("existing ingress history entry conflicts")
        if archived_info.st_nlink == 2:
            staged, staged_info = _read_ingress_history_file(temporary, allowed_links={2})
            if (staged != raw
                    or (staged_info.st_dev, staged_info.st_ino)
                       != (archived_info.st_dev, archived_info.st_ino)):
                raise RuntimeError("linked ingress history stage conflicts")
            temporary.unlink()
            archived, archived_info = _read_ingress_history_file(archive, allowed_links={1})
    else:
        try:
            staged, stage_info = _read_ingress_history_file(temporary, allowed_links={1})
        except FileNotFoundError:
            staged = None
            stage_info = None
        if staged is None:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o600)
                view = memoryview(raw)
                while view:
                    written = os.write(fd, view)
                    if written <= 0:
                        raise OSError("short ingress history write")
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
            staged, stage_info = _read_ingress_history_file(temporary, allowed_links={1})
        if staged != raw or hashlib.sha256(staged).hexdigest() != digest or stage_info is None:
            raise RuntimeError("staged ingress history entry changed")
        try:
            os.link(temporary, archive, follow_symlinks=False)
        except FileExistsError:
            archived, archived_info = _read_ingress_history_file(archive, allowed_links={1})
            if archived != raw or hashlib.sha256(archived).hexdigest() != digest:
                raise RuntimeError("existing ingress history entry conflicts") from None
        else:
            archived_info = os.stat(archive, follow_symlinks=False)
        if ((archived_info.st_dev, archived_info.st_ino)
                != (stage_info.st_dev, stage_info.st_ino)):
            raise RuntimeError("ingress history exclusive link does not match its stage")
        temporary.unlink()
        archived, archived_info = _read_ingress_history_file(archive, allowed_links={1})
        if archived != raw:
            raise RuntimeError("durable ingress history bytes differ after linking")
    history_fd = os.open(INGRESS_HISTORY, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(history_fd)
    finally:
        os.close(history_fd)
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    return digest, _ingress_backup_identity(archived_info)


def _verify_archived_completed_ingress(value: dict) -> None:
    digest = value.get("prior_completed_ingress_sha256")
    if digest is None:
        return
    if type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise RuntimeError("successor ingress predecessor reference is malformed")
    for path, label in ((INGRESS_HISTORY.parent, "parent"), (INGRESS_HISTORY, "directory")):
        try:
            directory_info = path.lstat()
        except OSError:
            raise RuntimeError(f"fixed ingress history {label} custody differs") from None
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0
                or directory_info.st_gid != 0
                or stat.S_IMODE(directory_info.st_mode) != 0o700
                or (path == INGRESS_HISTORY and directory_info.st_nlink < 2)):
            raise RuntimeError(f"fixed ingress history {label} custody differs")
    archived, _info = _read_fixed(INGRESS_HISTORY / (digest + ".json"), uid=0,
                                  gid=0, mode=0o600, maximum=128 * 1024)
    if hashlib.sha256(archived).hexdigest() != digest:
        raise RuntimeError("successor ingress predecessor archive digest differs")
    try:
        prior = json.loads(archived, object_pairs_hook=_unique_pairs)
        candidate = prior.get("candidate_sha") if type(prior) is dict else None
        if (type(prior) is not dict or prior.get("schema") != 1
                or prior.get("state") != "migrated"
                or candidate == value.get("candidate_sha")
                or type(candidate) is not str
                or re.fullmatch(r"[0-9a-f]{40}", candidate) is None):
            raise ValueError
        gateway = base64.b64decode(prior["gateway_unit"], validate=True)
        inspector = base64.b64decode(prior["inspector_unit"], validate=True)
        config = base64.b64decode(prior["gateway_config"], validate=True)
        if (not gateway or not inspector or not config
                or hashlib.sha256(gateway).hexdigest() != prior["old_gateway_sha256"]
                or hashlib.sha256(inspector).hexdigest() != prior["old_inspector_sha256"]
                or hashlib.sha256(config).hexdigest() != prior["old_config_sha256"]
                or re.fullmatch(r"[0-9a-f]{64}", prior["new_gateway_sha256"]) is None
                or re.fullmatch(r"[0-9a-f]{64}", prior["new_inspector_sha256"]) is None
                or not isinstance(prior.get("post_core_config_sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", prior["post_core_config_sha256"]) is None):
            raise ValueError
        refresh = prior.get("adapter_refresh")
        if refresh is not None and (not _valid_adapter_refresh_row(refresh)
                                    or any(refresh.get(field) is None for field in (
                                        "core_update_backup_reference",
                                        "core_update_cohort_transaction_id",
                                        "core_update_cohort_sha256"))):
            raise ValueError
    except Exception:
        raise RuntimeError("successor ingress predecessor archive is not a completed record") from None


def _retain_completed_ingress_for_refresh(core_runtime, observer_socket: Path,
                                           next_candidate_sha: str) -> dict:
    """Prove and durably archive the exact successful ingress predecessor."""
    raw, info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600,
                            maximum=128 * 1024)
    try:
        parsed = json.loads(raw, object_pairs_hook=_unique_pairs)
        previous_candidate = parsed.get("candidate_sha") if type(parsed) is dict else None
        if (not isinstance(previous_candidate, str)
                or re.fullmatch(r"[0-9a-f]{40}", previous_candidate) is None
                or previous_candidate == next_candidate_sha):
            raise ValueError
        value, _gateway, _inspector, _config = _backup_value(previous_candidate)
        rechecked, rechecked_info = _read_fixed(
            INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
        if (rechecked != raw
                or _ingress_backup_identity(rechecked_info) != _ingress_backup_identity(info)):
            raise _IngressSnapshotConflict("completed ingress journal changed during validation")
    except _IngressSnapshotConflict:
        raise
    except Exception:
        raise RuntimeError("prior ingress transaction is not a valid completed predecessor") from None
    if (value["state"] != "migrated"
            or value["candidate_sha"] != previous_candidate
            or value.get("post_core_config_sha256") is None):
        raise RuntimeError("prior ingress transaction is not complete")

    core_record, _core_raw, _core_files = core_runtime._read_active_adapter_runtime()
    gateway, _gateway_info = _read_fixed(FIXED_UNITS[GATEWAY], uid=0, gid=0,
                                         mode=0o644, maximum=64 * 1024)
    inspector, _inspector_info = _read_fixed(FIXED_UNITS[INSPECTOR], uid=0, gid=0,
                                             mode=0o644, maximum=64 * 1024)
    config_raw, _config_info = _read_fixed(GATEWAY_CONFIG, uid=0, gid=981,
                                           mode=0o440, maximum=16 * 1024)
    source = f"/opt/hermes-installer-core-{previous_candidate[:9]}/src".encode("ascii")
    inspector_digest = hashlib.sha256(inspector).hexdigest()
    expected_inspector_digests = {value["new_inspector_sha256"],
                                  value.get("runtime_inspector_sha256")}
    expected_config = value.get("post_core_config_sha256")
    if (hashlib.sha256(gateway).hexdigest() != value["new_gateway_sha256"]
            or inspector_digest not in expected_inspector_digests
            or hashlib.sha256(config_raw).hexdigest() != expected_config
            or _unit_source(gateway, "core_gateway") != source
            or _unit_source(inspector, "core_gateway_inspector") != source
            or core_record.get("adapter_source") != source.decode("ascii")
            or core_record.get("adapter_migration_state") != "active"
            or not all(_unit_is_exact_and_active(name) for name in (INSPECTOR, GATEWAY))):
        raise RuntimeError("active Core and ingress no longer match the completed predecessor")

    refresh = value.get("adapter_refresh")
    if refresh is not None:
        if (not _valid_adapter_refresh_row(refresh)
                or any(refresh.get(field) is None for field in (
                    "core_update_backup_reference", "core_update_cohort_transaction_id",
                    "core_update_cohort_sha256"))):
            raise RuntimeError("prior adapter-refresh record is malformed")
        _verify_current_adapter_refresh_join(core_runtime, refresh)
    elif core_record.get("adapter_source") != source.decode("ascii"):
        raise RuntimeError("legacy predecessor lacks an exact active Core source join")

    _verify_source_provenance(previous_candidate, Path(source.decode("ascii")))
    _verify_installed_source(source)
    from hermes_installer.remote.core_gateway import CoreGatewayConfig
    config = CoreGatewayConfig.load(expected_owner_uid=0)
    _verify_gateway_tunnel(config, require_active=True)
    _verify_inspector_process(inspector, source)
    inspector_custody = _capture_inspector_custody(inspector, source, observer_socket)
    try:
        if (inspector_custody["row"]["old_observer_state"] not in {"verified-owned", "absent"}
                or inspector_custody["identity"]["source"] != source.decode("ascii")):
            raise RuntimeError("completed predecessor observer custody is not current")
    finally:
        os.close(inspector_custody["pidfd"])

    digest, archive_identity = _archive_completed_ingress_bytes(raw)
    # Close the read-to-archive window before allowing the successor stage.
    current, current_info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600,
                                        maximum=128 * 1024)
    if current != raw or _ingress_backup_identity(current_info) != _ingress_backup_identity(info):
        raise _IngressSnapshotConflict("completed ingress backup changed during retention")
    return {"raw": raw, "identity": _ingress_backup_identity(info),
            "sha256": digest, "archive_identity": archive_identity,
            "core_journal_sha256": hashlib.sha256(_core_raw).hexdigest(),
            "core_adapter_source": core_record["adapter_source"],
            "core_adapter_generation": core_record["adapter_generation"],
            "core_source_generation": core_record["core_source_generation"],
            "gateway_unit_sha256": hashlib.sha256(gateway).hexdigest(),
            "inspector_unit_sha256": hashlib.sha256(inspector).hexdigest(),
            "config_sha256": hashlib.sha256(config_raw).hexdigest()}


def _remove_ingress_backup() -> None:
    try:
        INGRESS_BACKUP.unlink()
    except FileNotFoundError:
        return
    directory_fd = os.open(INGRESS_BACKUP.parent, os.O_RDONLY
                           | getattr(os, "O_DIRECTORY", 0)
                           | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


_ADAPTER_REFRESH_FIELDS = {
    "schema", "purpose", "old_core_journal_sha256", "old_core_adapter_source",
    "old_core_adapter_generation", "old_core_source_generation",
    "old_inspector_process_identity_sha256", "old_observer_state",
    "old_observer_device", "old_observer_inode", "core_update_backup_reference",
    "core_update_cohort_transaction_id", "core_update_cohort_sha256",
}


def _valid_adapter_refresh_row(row) -> bool:
    if type(row) is not dict or set(row) != _ADAPTER_REFRESH_FIELDS:
        return False
    digests = ("old_core_journal_sha256", "old_core_adapter_generation",
               "old_core_source_generation", "old_inspector_process_identity_sha256")
    if (type(row.get("schema")) is not int or row["schema"] != 1
            or row.get("purpose") != "adapter-refresh"
            or any(type(row.get(key)) is not str
                   or re.fullmatch(r"[0-9a-f]{64}", row[key]) is None for key in digests)
            or type(row.get("old_core_adapter_source")) is not str
            or not _SOURCE_PATH.fullmatch(row["old_core_adapter_source"].encode("ascii", "strict"))):
        return False
    if row.get("old_observer_state") == "absent":
        if row.get("old_observer_device") is not None or row.get("old_observer_inode") is not None:
            return False
    elif row.get("old_observer_state") == "verified-owned":
        if (type(row.get("old_observer_device")) is not int
                or row["old_observer_device"] < 0
                or type(row.get("old_observer_inode")) is not int
                or row["old_observer_inode"] <= 0):
            return False
    else:
        return False
    reference = row.get("core_update_backup_reference")
    txid = row.get("core_update_cohort_transaction_id")
    cohort_sha = row.get("core_update_cohort_sha256")
    if reference is None and txid is None and cohort_sha is None:
        return True
    legacy_members = set(_ADAPTER_BACKUP_BASE_MEMBERS)
    transitioned_members = legacy_members | set(_NATIVE_PLUGIN_BACKUP_NAMES.values())
    if (type(reference) is not dict or set(reference) != {"path", "source_generation", "files"}
            or type(reference.get("path")) is not str
            or type(reference.get("source_generation")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", reference["source_generation"]) is None
            or reference["source_generation"] != row["old_core_adapter_generation"]
            or reference["path"] != "/var/lib/hermes-installer/core-runtime/adapter-update-backups/"
                                    + reference["source_generation"]
            or type(reference.get("files")) is not dict
            or frozenset(reference["files"]) not in {frozenset(legacy_members),
                                                     frozenset(transitioned_members)}
            or any(type(v) is not str or re.fullmatch(r"[0-9a-f]{64}", v) is None
                   for v in reference["files"].values())
            or type(txid) is not str or re.fullmatch(r"[0-9a-f]{32}", txid) is None
            or type(cohort_sha) is not str or re.fullmatch(r"[0-9a-f]{64}", cohort_sha) is None):
        return False
    return True


def _set_adapter_refresh_core_join(core_runtime, candidate_sha: str, reference: dict,
                                   transaction_id: str, cohort_sha256: str) -> dict:
    """Persist only independently read-back committed Core recovery joins."""
    raw, info = _read_fixed(INGRESS_BACKUP, uid=0, gid=0, mode=0o600, maximum=128 * 1024)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
        row = value["adapter_refresh"]
        if (type(value) is not dict or value.get("candidate_sha") != candidate_sha
                or value.get("state") not in {"units-switched", "migrated", "recovery-required"}
                or not _valid_adapter_refresh_row(row)
                or row["core_update_backup_reference"] is not None
                or row["core_update_cohort_transaction_id"] is not None
                or row["core_update_cohort_sha256"] is not None):
            raise ValueError
        current_record, _current_journal, _current_files = core_runtime._read_active_adapter_runtime()
        cohort, cohort_raw = core_runtime._read_adapter_update_cohort()
        actual_reference = core_runtime._adapter_update_backup_reference(cohort)
        prior, contents = core_runtime._read_adapter_update_backup(actual_reference)
        if (actual_reference != reference
                or cohort.get("cohort_transaction_id") != transaction_id
                or hashlib.sha256(cohort_raw).hexdigest() != cohort_sha256
                or cohort.get("phase") != "committed"
                or hashlib.sha256(contents["journal.json"]).hexdigest()
                   != row["old_core_journal_sha256"]
                or prior.get("adapter_source") != row["old_core_adapter_source"]
                or prior.get("adapter_generation") != row["old_core_adapter_generation"]
                or prior.get("core_source_generation") != row["old_core_source_generation"]):
            raise ValueError
        _verify_adapter_refresh_plugin_backup(
            core_runtime, prior, current_record, cohort, actual_reference, prior, contents)
        row["core_update_backup_reference"] = reference
        row["core_update_cohort_transaction_id"] = transaction_id
        row["core_update_cohort_sha256"] = cohort_sha256
        if not _valid_adapter_refresh_row(row):
            raise ValueError
    except Exception:
        raise RuntimeError("protected adapter refresh join is not current") from None
    replacement = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    _atomic_fixed(INGRESS_BACKUP, replacement, uid=0, gid=0,
                  mode=stat.S_IMODE(info.st_mode))
    return row


def _prepare_existing_owner_before_migration(new_gateway_config: bytes,
                                            approved_union_requested: bool) -> bool:
    """Keep the established sole-owner preparation out of multi-email adoption."""
    try:
        new_config = json.loads(new_gateway_config, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("prospective Gateway config is malformed") from None
    if (approved_union_requested and type(new_config) is dict
            and type(new_config.get("allowed_emails")) is list
            and len(new_config["allowed_emails"]) > 1):
        print("Owner registration/vault state was preserved; global owner operations remain pending their existing gate.")
        return False
    from hermes_installer.remote.obsidian_owner_lifecycle import (
        prepare_sole_existing_chat_owner_for_legacy_migration,
    )
    prepare_sole_existing_chat_owner_for_legacy_migration()
    return True


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
        prospective_field_present = (type(value) is dict and "new_gateway_config" in value)
        keys = {"schema", "state", "candidate_sha", "gateway_unit", "inspector_unit",
                "gateway_config", "gateway_mode", "gateway_gid", "old_gateway_sha256",
                "old_inspector_sha256", "old_config_sha256", "new_gateway_sha256",
                "new_inspector_sha256", "new_config_sha256", "post_core_config_sha256",
                "runtime_inspector_sha256", "new_gateway_config", "adapter_refresh"}
        final_keys = keys | {"prior_completed_ingress_sha256"}
        legacy_keys = keys - {"post_core_config_sha256", "runtime_inspector_sha256",
                              "new_gateway_config", "adapter_refresh"}
        if type(value) is dict and set(value) == legacy_keys:
            value["post_core_config_sha256"] = None
            value["runtime_inspector_sha256"] = None
            value["new_gateway_config"] = None
            value["adapter_refresh"] = None
        elif (type(value) is dict and set(value) ==
              keys - {"runtime_inspector_sha256", "new_gateway_config", "adapter_refresh"}):
            value["runtime_inspector_sha256"] = None
            value["new_gateway_config"] = None
            value["adapter_refresh"] = None
        elif type(value) is dict and set(value) == keys - {"runtime_inspector_sha256", "adapter_refresh"}:
            value["runtime_inspector_sha256"] = None
            value["adapter_refresh"] = None
        elif type(value) is dict and set(value) == keys - {"new_gateway_config", "adapter_refresh"}:
            value["new_gateway_config"] = None
            value["adapter_refresh"] = None
        elif type(value) is dict and set(value) == keys - {"adapter_refresh"}:
            value["adapter_refresh"] = None
        elif type(value) is dict and set(value) == final_keys:
            pass
        if type(value) is dict and "prior_completed_ingress_sha256" not in value:
            value["prior_completed_ingress_sha256"] = None
        if (type(value) is not dict or set(value) != final_keys or type(value["schema"]) is not int
                or value["schema"] != 1 or value["candidate_sha"] != candidate_sha
                or value["state"] not in {"prepared", "units-switched", "migrated", "recovery-required"}
                or value["gateway_mode"] != 0o440 or value["gateway_gid"] != 981
                or (value["post_core_config_sha256"] is not None
                    and (not isinstance(value["post_core_config_sha256"], str)
                         or re.fullmatch(r"[0-9a-f]{64}", value["post_core_config_sha256"]) is None))
                or (value["runtime_inspector_sha256"] is not None
                    and (not isinstance(value["runtime_inspector_sha256"], str)
                         or re.fullmatch(r"[0-9a-f]{64}", value["runtime_inspector_sha256"]) is None))
                or (value["prior_completed_ingress_sha256"] is not None
                    and (not isinstance(value["prior_completed_ingress_sha256"], str)
                         or re.fullmatch(r"[0-9a-f]{64}",
                                         value["prior_completed_ingress_sha256"]) is None))
                or (value["adapter_refresh"] is not None
                    and not _valid_adapter_refresh_row(value["adapter_refresh"]))):
            raise ValueError
        if prospective_field_present and value["new_gateway_config"] is None:
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
        if value["new_gateway_config"] is not None:
            if (not isinstance(value["new_gateway_config"], str)
                    or len(value["new_gateway_config"]) > 4 * 16 * 1024
                    or type(value["new_config_sha256"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", value["new_config_sha256"]) is None):
                raise ValueError
            new_config = base64.b64decode(value["new_gateway_config"], validate=True)
            if (not new_config or len(new_config) > 16 * 1024
                    or sha256(new_config).hexdigest() != value["new_config_sha256"]):
                raise ValueError
        return value, *decoded
    except Exception:
        raise RuntimeError("fixed ingress rollback record is malformed") from None


def _journaled_new_gateway_config(value: dict, old_gateway: bytes,
                                 old_inspector: bytes, old_config: bytes,
                                 expected_source: Path) -> bytes:
    """Re-derive only the fixed source/unit recipe around exact journal bytes."""
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
        prior = json.loads(old_config, object_pairs_hook=_unique_pairs)
    except (ValueError, TypeError, UnicodeError):
        raise RuntimeError("saved Gateway config is malformed") from None
    if (type(prior) is not dict
            or prior.get("gateway_unit_sha256") != hashlib.sha256(old_gateway).hexdigest()):
        raise RuntimeError("saved Gateway config does not bind the saved prior unit")
    prior["gateway_unit_sha256"] = hashlib.sha256(switched_gateway).hexdigest()
    derived = (json.dumps(prior, sort_keys=True, separators=(",", ":")) + "\n").encode()

    encoded = value.get("new_gateway_config")
    if encoded is None:
        # Legacy journals predate the stored prospective bytes and can resume
        # only the original recipe, which preserves the exact old allowlist.
        prospective = derived
    else:
        prospective = base64.b64decode(encoded, validate=True)
        try:
            recorded = json.loads(prospective, object_pairs_hook=_unique_pairs)
        except (ValueError, TypeError, UnicodeError):
            raise RuntimeError("saved prospective Gateway config is malformed") from None
        if (type(recorded) is not dict
                or prospective != (json.dumps(recorded, sort_keys=True,
                                               separators=(",", ":")) + "\n").encode()
                or set(recorded) != set(prior)
                or recorded.get("gateway_unit_sha256") != prior["gateway_unit_sha256"]
                or any(recorded.get(key) != prior.get(key)
                       for key in set(prior) - {"gateway_unit_sha256", "allowed_emails"})):
            raise RuntimeError("saved prospective Gateway config differs from the fixed recipe")
        if "allowed_emails" in prior:
            previous_emails = _normalized_email_list(prior["allowed_emails"])
            recorded_emails = _normalized_email_list(recorded.get("allowed_emails"))
            if (not set(previous_emails).issubset(recorded_emails)
                    or (recorded["allowed_emails"] != prior["allowed_emails"]
                        and recorded["allowed_emails"] != list(recorded_emails))):
                raise RuntimeError("saved prospective Gateway config changes its approved email union")
        elif "allowed_emails" in recorded:
            raise RuntimeError("saved prospective Gateway config adds an unapproved email field")

    if (len(prospective) > 16 * 1024
            or hashlib.sha256(prospective).hexdigest() != value["new_config_sha256"]):
        raise RuntimeError("saved config does not derive the recorded candidate transaction")
    return prospective


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
    if value.get("adapter_refresh") is not None:
        row = value["adapter_refresh"]
        if (not _valid_adapter_refresh_row(row)
                or row["core_update_backup_reference"] is None
                or row["core_update_cohort_transaction_id"] is None
                or row["core_update_cohort_sha256"] is None
                or record.get("adapter_update_state") != "active"
                or record.get("core_source_generation") != row["old_core_source_generation"]):
            raise RuntimeError("adapter refresh Core recovery join is incomplete")
        cohort, cohort_raw = core_runtime._read_adapter_update_cohort()
        reference = core_runtime._adapter_update_backup_reference(cohort)
        previous, contents = core_runtime._read_adapter_update_backup(reference)
        if (hashlib.sha256(cohort_raw).hexdigest() != row["core_update_cohort_sha256"]
                or cohort.get("cohort_transaction_id")
                   != row["core_update_cohort_transaction_id"]
                or reference != row["core_update_backup_reference"]
                or cohort.get("phase") != "committed"
                or hashlib.sha256(contents["journal.json"]).hexdigest()
                   != row["old_core_journal_sha256"]
                or previous.get("adapter_source") != row["old_core_adapter_source"]
                or previous.get("adapter_generation") != row["old_core_adapter_generation"]
                or previous.get("core_source_generation") != row["old_core_source_generation"]):
            raise RuntimeError("committed adapter refresh Core join changed")

    switched_config = _journaled_new_gateway_config(
        value, old_gateway, old_inspector, old_config, expected_source)
    if current_sha == value["post_core_config_sha256"]:
        updated = json.loads(switched_config, object_pairs_hook=_unique_pairs)
        updated["core_unit_sha256"] = unit_sha
        updated["core_launcher_sha256"] = launcher_sha
        expected_post = (json.dumps(updated, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if (current_raw != expected_post
                or hashlib.sha256(expected_post).hexdigest() != value["post_core_config_sha256"]):
            raise RuntimeError("recorded post-Core config does not bind current journal digests")
        return current_raw
    updated = json.loads(switched_config, object_pairs_hook=_unique_pairs)
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
        if value.get("new_gateway_config") is None:
            value.pop("new_gateway_config", None)
        backup_bytes = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        _atomic_fixed(INGRESS_BACKUP, backup_bytes, uid=0, gid=0, mode=stat.S_IMODE(backup_info.st_mode))
    _atomic_fixed(GATEWAY_CONFIG, replacement, uid=0, gid=config_info.st_gid,
                  mode=stat.S_IMODE(config_info.st_mode))
    return replacement


def _stat_cas_identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_size, info.st_mtime_ns)


def _recheck_ingress_snapshot(saved, old_config: bytes,
                              config_info: os.stat_result) -> None:
    expected = {
        FIXED_UNITS[INSPECTOR]: (*saved[FIXED_UNITS[INSPECTOR]], 0, 0, 0o644, 64 * 1024),
        FIXED_UNITS[GATEWAY]: (*saved[FIXED_UNITS[GATEWAY]], 0, 0, 0o644, 64 * 1024),
        GATEWAY_CONFIG: (old_config, config_info, 0, 981, 0o440, 16 * 1024),
    }
    for path, (expected_raw, expected_info, uid, gid, mode, maximum) in expected.items():
        current_raw, current_info = _read_fixed(
            path, uid=uid, gid=gid, mode=mode, maximum=maximum)
        if (current_raw != expected_raw
                or _stat_cas_identity(current_info) != _stat_cas_identity(expected_info)):
            raise _IngressSnapshotConflict(
                "fixed ingress files changed after the adoption snapshot")


def _replace_ingress_units(new_units, new_config: bytes, config_info: os.stat_result,
                           saved, old_config: bytes) -> None:
    try:
        if any(not _unit_is_fixed(name) for name in (INSPECTOR, GATEWAY, TUNNEL)):
            raise _IngressSnapshotConflict(
                "fixed systemd unit ownership changed before source switch")
        # The approved union arrives on stdin and the protected backup is
        # written before this point. Recheck the exact captured inode, metadata
        # and bytes at the last boundary before the first service stop.
        _recheck_ingress_snapshot(saved, old_config, config_info)
    except _IngressSnapshotConflict:
        raise
    except Exception:
        # Protected-file open/read/custody failures are still pre-effect
        # conflicts. Sanitize the low-level error and never enter rollback,
        # which would itself stop a live ingress service.
        raise _IngressSnapshotConflict(
            "fixed ingress custody could not be reverified before source switch") from None
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
                         old_config: bytes, *, observer_socket: Path | None = None,
                         expected_observer_source: Path | None = None) -> bool:
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
        old_source = _unit_source(old_inspector, "core_gateway_inspector")
        if (expected_observer_source is not None
                and old_source != str(expected_observer_source).encode("ascii")):
            raise RuntimeError("restored Inspector source differs from the retained old adapter")
        _verify_inspector_process(old_inspector, old_source)
        if observer_socket is not None:
            parent = observer_socket.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                    or parent.st_gid != 1000 or stat.S_IMODE(parent.st_mode) != 0o750):
                raise RuntimeError("restored normal observer directory custody differs")
            phase_identity = _wait_observer_socket()
            inspector_pid = int(_run("systemctl", "show", "--property=MainPID",
                                     "--value", INSPECTOR))
            if phase_identity != _verify_observer_peer(observer_socket, inspector_pid):
                raise RuntimeError("restored normal observer socket is not the old Inspector peer")
        _run("systemctl", "start", GATEWAY)
        if _unit_state(GATEWAY) != "active":
            raise RuntimeError("old Gateway did not recover")
        _run("systemctl", "start", TUNNEL)
        config = __import__("hermes_installer.remote.core_gateway", fromlist=["CoreGatewayConfig"]).CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_inspector_process(old_inspector, old_source)
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


def _verify_source_provenance(candidate_sha: str, source_root: Path) -> str:
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
    return value["archive_sha256"]


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


def _main_unlocked() -> int:
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
    parser.add_argument("--approved-email-union-stdin", action="store_true",
                        help="read a bounded approved email union on stdin during --apply")
    args = parser.parse_args()
    if args.approved_email_union_stdin and not args.apply:
        parser.error("--approved-email-union-stdin is available only with --apply")
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha):
        parser.error("--candidate-sha must be a full lowercase 40-character Git commit SHA")
    expected_adapter_source = Path(
        f"/opt/hermes-installer-core-{args.candidate_sha[:9]}/src")

    phase = "source provenance and adapter validation"
    try:
        print("Adoption phase: " + phase, flush=True)
        archive_sha = _verify_source_provenance(args.candidate_sha, expected_adapter_source)
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
            saved, _og, _oi, _oc = _backup_value(args.candidate_sha)
            if saved.get("adapter_refresh") is not None:
                outcome = _resume_adapter_refresh(
                    args.candidate_sha, expected_adapter_source, archive_sha,
                    core_runtime, CORE_NATIVE_OBSERVER_SOCKET)
                if outcome == "rolled-back":
                    print("Interrupted adapter rollback completed; exact prior Core and ingress were restored.")
                    print("The retained transaction was removed after old Core and observer readback.")
                else:
                    print("Saved adapter Core and Jarvis ingress cohort resumed and verified.")
                    print("Protected transaction backup retained for exact rollback.")
                return 0
            _resume_adoption(args.candidate_sha, expected_adapter_source, core_runtime,
                             CoreGatewayConfig, CORE_NATIVE_OBSERVER_SOCKET)
            return 0

        if args.rollback:
            phase = "rollback journal and fixed-file validation"
            print("Adoption phase: " + phase, flush=True)
            value, old_gateway, old_inspector, old_config = _backup_value(args.candidate_sha)
            if value.get("adapter_refresh") is not None:
                _rollback_adapter_refresh(args.candidate_sha, expected_adapter_source,
                                          core_runtime, CORE_NATIVE_OBSERVER_SOCKET)
                print("Exact prior adapter Core and Inspector/Gateway/tunnel cohort restored.")
                return 0
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
        backup_present = INGRESS_BACKUP.exists() or INGRESS_BACKUP.is_symlink()
        active_adapter = None
        try:
            active_adapter = core_runtime._read_active_adapter_runtime()
        except core_runtime.CoreRuntimeError:
            # Preserve the original migration lane only when its own complete
            # fixed-runtime proof succeeds. A malformed/foreign Core state is
            # not interpreted as legacy by the adapter refresh selector.
            core_runtime._read_legacy_owned_runtime()
        if active_adapter is not None:
            refreshed_archive, tool, tool_identity = _read_candidate_qualification_inputs(
                args.candidate_sha, expected_adapter_source)
            if refreshed_archive != archive_sha:
                raise RuntimeError("candidate source receipt changed before adapter refresh")
            completed_predecessor = (
                _retain_completed_ingress_for_refresh(
                    core_runtime, CORE_NATIVE_OBSERVER_SOCKET, args.candidate_sha)
                if backup_present else None)
            return _apply_adapter_refresh(
                args.candidate_sha, expected_adapter_source, archive_sha, tool,
                tool_identity, core_runtime, CORE_NATIVE_OBSERVER_SOCKET,
                approved_union=args.approved_email_union_stdin,
                completed_predecessor=completed_predecessor)
        if backup_present:
            raise RuntimeError("a prior adoption backup exists; use --rollback or inspect it first")
        config = CoreGatewayConfig.load(expected_owner_uid=0)
        _verify_gateway_tunnel(config, require_active=True)
        if CORE_NATIVE_OBSERVER_SOCKET.exists() or CORE_NATIVE_OBSERVER_SOCKET.is_symlink():
            raise RuntimeError("unexpected preexisting native-observer socket blocks adoption")
        phase = "build exact source switch and protected recovery backup"
        print("Adoption phase: " + phase, flush=True)
        saved, old_config, config_info, new_units, new_config = _source_switch(
            expected_adapter_source,
            read_approved_email_union=args.approved_email_union_stdin)
        _recheck_ingress_snapshot(saved, old_config, config_info)
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
            _replace_ingress_units(new_units, new_config, config_info, saved, old_config)
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
            _prepare_existing_owner_before_migration(
                new_config, args.approved_email_union_stdin)

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
            if args.approved_email_union_stdin:
                approved_count = len(json.loads(new_config)["allowed_emails"])
                print(f"Approved email union accepted (count={approved_count}; current membership preserved=yes).")
            if (args.approved_email_union_stdin
                    and len(json.loads(new_config)["allowed_emails"]) > 1):
                print("Fixed observer socket metadata was verified; global owner operations remain pending their existing gate.")
            else:
                print("Selected-owner registration and fixed observer socket metadata were verified.")
            print("Peer protocol, native tool registration, and Obsidian read/write effects remain separate Pi witnesses.")
            if (args.approved_email_union_stdin
                    and len(json.loads(new_config)["allowed_emails"]) > 1):
                print("Existing owner registration/vault state was preserved; no multi-principal owner operation was prepared.")
            else:
                print("Owner enrollment/vault preparation persist if Core/plugin rollback is needed.")
            print("Exact rollback command: rerun this helper with the same --candidate-sha and --rollback.")
            return 0
        except _IngressSnapshotConflict as error:
            # The only issuer is the fixed pre-stop snapshot guard. Preserve
            # its protected journal for inspection and leave active services
            # untouched; the ordinary failure branch performs real rollback.
            print("Adoption stopped before service effects; protected transaction retained.")
            print("Failure type: " + type(error).__name__)
            return 4
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


@contextlib.contextmanager
def _adopter_lock():
    parent = ADOPTER_LOCK.parent
    parent_info = parent.lstat()
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
            or parent_info.st_gid != 0):
        raise RuntimeError("fixed adopter lock directory custody differs")
    fd = os.open(ADOPTER_LOCK, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise RuntimeError("fixed adopter lock file custody differs")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another fixed Core adoption transaction is active") from None
        yield
    finally:
        os.close(fd)


def main() -> int:
    if os.geteuid() != 0:
        return _main_unlocked()
    try:
        with _adopter_lock():
            return _main_unlocked()
    except Exception as error:
        print("Adoption helper stopped before claiming success; failure type: "
              + type(error).__name__, file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
