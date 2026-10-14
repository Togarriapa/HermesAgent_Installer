#!/usr/bin/env python3
"""Run one fixed root Core adapter update and emit digest-only before/after evidence.

This is a Pi-only qualification command. It consumes a source generation already
staged by ``pi_native_core_stage.py``; it does not download, install, select, or
rollback arbitrary paths. The only mutation is the fixed Core adapter update
through the candidate's normal ``core-service adapter-update`` CLI dispatch.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import sys
import threading
import time
from pathlib import Path
from types import FunctionType, ModuleType, MappingProxyType
from typing import Any

_NATIVE_PLUGIN_MEMBER_NAMES = ("plugin.yaml", "__init__.py")
_NATIVE_PLUGIN_BACKUP_NAMES = {
    "plugin.yaml": "native-plugin-plugin.yaml",
    "__init__.py": "native-plugin-__init__.py",
}
_ADAPTER_BACKUP_BASE_MEMBERS = frozenset({
    "journal.json", "unit", "launcher", "plugin-selection.json", "resources-record.json",
    "overlay-record.json", "primary-record.json", "obsidian-registration.json", "cohort.json",
})
_QUALIFICATION_CHECKPOINT_PREFIX = "HERMES_CORE_QUALIFICATION_CHECKPOINT_V1="
_QUALIFICATION_CHECKPOINT_PHASES = (
    "stage_verifier", "runtime_load", "before_snapshot", "adapter_update",
    "after_snapshot", "history_validation", "listener_verification",
    "success_checks", "report_emission",
)
_QUALIFICATION_CHECKPOINT_STREAM = sys.stderr
_QUALIFICATION_STACK_SAMPLE_PREFIX = "HERMES_CORE_QUALIFICATION_STACK_SAMPLE_V2="
_QUALIFICATION_STACK_SAMPLE_STREAM = sys.stderr
_QUALIFICATION_STACK_SAMPLE_SECONDS = 250.0
_QUALIFICATION_STACK_LABELS = frozenset({
    "updater", "importer", "generation_tree", "listener", "startup_chat",
    "reconstruction", "root_runuser", "adapter_generation",
})
_QUALIFICATION_STACK_SOURCE_FILES = {
    "hermes_installer/core_runtime.py": frozenset({
        "_update_owned_core_adapter_locked", "_run_same_materialization_import",
        "_hash_generation_tree", "_wait_for_listener", "_prove_new_cohort_startup_chat",
        "_make_adapter_update_reconstruction", "_root_runuser_proc_snapshot",
    }),
    "hermes_installer/remote/core_gateway_inspector.py": frozenset({
        "_current_native_adapter_generation",
    }),
}
_QUALIFICATION_STACK_FUNCTIONS = {
    "_update_owned_core_adapter_locked": "updater",
    "_run_same_materialization_import": "importer",
    "_hash_generation_tree": "generation_tree",
    "_wait_for_listener": "listener",
    "_prove_new_cohort_startup_chat": "startup_chat",
    "_make_adapter_update_reconstruction": "reconstruction",
    "_root_runuser_proc_snapshot": "root_runuser",
    "_current_native_adapter_generation": "adapter_generation",
}
_QUALIFICATION_STACK_FUNCTION_PATHS = {
    function: path for path, functions in _QUALIFICATION_STACK_SOURCE_FILES.items()
    for function in functions
}


def _stack_source_file_snapshot(source_fd: int, relative_path: str) -> dict[str, Any]:
    """Read one fixed source file through held no-follow Root-owned directories."""
    parts = relative_path.split("/")
    if (relative_path not in _QUALIFICATION_STACK_SOURCE_FILES
            or len(parts) not in {2, 3} or parts[0] != "hermes_installer"):
        raise RuntimeError("qualification stack source path is outside the fixed set")
    source_info = os.fstat(source_fd)
    if (not stat.S_ISDIR(source_info.st_mode) or source_info.st_uid != 0
            or source_info.st_gid != 0 or stat.S_IMODE(source_info.st_mode) & 0o022):
        raise RuntimeError("qualification stack source root custody differs")
    directory_fds = []
    parent_fd = source_fd
    file_fd = None
    try:
        for component in parts[:-1]:
            directory_fd = os.open(
                component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd)
            directory_fds.append(directory_fd)
            directory_info = os.fstat(directory_fd)
            if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0
                    or directory_info.st_gid != 0
                    or stat.S_IMODE(directory_info.st_mode) & 0o022):
                raise RuntimeError("qualification stack source directory custody differs")
            parent_fd = directory_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
        before = os.fstat(file_fd)
        named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        identity = (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_gid, before.st_nlink, before.st_size,
                    before.st_mtime_ns, before.st_ctime_ns)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1
                or not 1 <= before.st_size <= 2 * 1024 * 1024
                or identity != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                                named.st_gid, named.st_nlink, named.st_size,
                                named.st_mtime_ns, named.st_ctime_ns)):
            raise RuntimeError("qualification stack source file custody differs")
        raw = bytearray()
        while len(raw) <= before.st_size:
            block = os.read(file_fd, min(65536, before.st_size + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(file_fd)
        current_named = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        current_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                            after.st_gid, after.st_nlink, after.st_size,
                            after.st_mtime_ns, after.st_ctime_ns)
        if (len(raw) != before.st_size or current_identity != identity
                or current_identity != (current_named.st_dev, current_named.st_ino,
                                        current_named.st_mode, current_named.st_uid,
                                        current_named.st_gid, current_named.st_nlink,
                                        current_named.st_size, current_named.st_mtime_ns,
                                        current_named.st_ctime_ns)):
            raise RuntimeError("qualification stack source changed during read")
        source_bytes = bytes(raw)
        return {"sha256": hashlib.sha256(source_bytes).hexdigest(),
                "line_count": source_bytes.count(b"\n") + (0 if source_bytes.endswith(b"\n") else 1),
                "identity": identity}
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for directory_fd in reversed(directory_fds):
            os.close(directory_fd)


def _verified_qualification_stack_codes(
        candidate_src: Path, source_fd: int | None
) -> tuple[dict[int, dict[str, Any]], dict[str, dict[str, Any]], bool]:
    """Map only loaded candidate code after held source bytes and custody are verified."""
    expected_root = candidate_src / "hermes_installer"
    modules = (
        ("hermes_installer.core_runtime", expected_root / "core_runtime.py", {
            "_update_owned_core_adapter_locked": "updater",
            "_run_same_materialization_import": "importer",
            "_hash_generation_tree": "generation_tree",
            "_wait_for_listener": "listener",
            "_prove_new_cohort_startup_chat": "startup_chat",
            "_make_adapter_update_reconstruction": "reconstruction",
            "_root_runuser_proc_snapshot": "root_runuser",
        }),
        ("hermes_installer.remote.core_gateway_inspector",
         expected_root / "remote" / "core_gateway_inspector.py", {
             "_current_native_adapter_generation": "adapter_generation",
         }),
    )
    if type(source_fd) is not int or source_fd < 0:
        return {}, {}, False
    sources: dict[str, dict[str, Any]] = {}
    try:
        sources = {relative: _stack_source_file_snapshot(source_fd, relative)
                   for relative in _QUALIFICATION_STACK_SOURCE_FILES}
    except (OSError, RuntimeError, TypeError, ValueError):
        return {}, {}, False
    codes: dict[int, dict[str, Any]] = {}
    complete = True
    for module_name, expected_file, functions in modules:
        module = sys.modules.get(module_name)
        if type(module) is not ModuleType:
            complete = False
            continue
        try:
            if Path(module.__file__).resolve(strict=True) != expected_file.resolve(strict=True):
                complete = False
                continue
        except (AttributeError, OSError, RuntimeError, TypeError, ValueError):
            complete = False
            continue
        relative_path = expected_file.relative_to(candidate_src).as_posix()
        line_count = sources[relative_path]["line_count"]
        for function_name, label in functions.items():
            function = getattr(module, function_name, None)
            code = getattr(function, "__code__", None)
            if (not isinstance(function, FunctionType) or code is None
                    or Path(code.co_filename).resolve() != expected_file.resolve()
                    or code.co_name != function_name
                    or not 1 <= code.co_firstlineno <= line_count):
                complete = False
                continue
            codes[id(code)] = {"label": label, "source_relative_path": relative_path,
                               "function": function_name, "line_count": line_count}
    if {value["label"] for value in codes.values()} != _QUALIFICATION_STACK_LABELS:
        complete = False
    return codes, sources, complete


def _qualification_stack_sources_current(source_fd: int | None,
                                         expected: dict[str, dict[str, Any]]) -> bool:
    if type(source_fd) is not int or source_fd < 0 or type(expected) is not dict:
        return False
    try:
        current = {relative: _stack_source_file_snapshot(source_fd, relative)
                   for relative in _QUALIFICATION_STACK_SOURCE_FILES}
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return current == expected


def _qualification_stack_sample(candidate_sha: str, archive_sha: str,
                                 elapsed_ms: int, main_ident: int,
                                 code_labels: dict[int, dict[str, Any]], mapping_complete: bool,
                                 frames_by_ident: dict[int, Any] | None = None,
                                 source_current: bool = True) -> dict:
    """Build a bounded stack projection; frame names, locals and arguments never escape."""
    frames_by_ident = sys._current_frames() if frames_by_ident is None else frames_by_ident
    frame = frames_by_ident.get(main_ident)
    labels: list[str] = []
    source_frames: list[dict[str, Any]] = []
    examined = unmatched = 0
    truncated = False
    inconsistent = False
    while frame is not None and examined < 32:
        examined += 1
        code_row = code_labels.get(id(frame.f_code))
        if code_row is None or not source_current:
            unmatched += 1
        elif len(labels) < 12 and 1 <= frame.f_lineno <= code_row["line_count"]:
            labels.append(code_row["label"])
            source_frames.append({"source_relative_path": code_row["source_relative_path"],
                                  "function": code_row["function"], "line": frame.f_lineno})
        elif len(labels) < 12:
            inconsistent = True
            unmatched += 1
        else:
            truncated = True
        frame = frame.f_back
    if frame is not None:
        truncated = True
    unknown = (not mapping_complete or not source_current or inconsistent or not labels or truncated)
    return {
        "schema": 2,
        "candidate_commit": candidate_sha,
        "candidate_archive_sha256": archive_sha,
        "elapsed_ms": elapsed_ms,
        "labels": labels,
        "frames": source_frames,
        "examined_frames": examined,
        "unmatched_frames": unmatched,
        "truncated": truncated,
        "unknown": unknown,
    }


def _valid_qualification_stack_sample(record: object) -> bool:
    keys = {
        "schema", "candidate_commit", "candidate_archive_sha256", "elapsed_ms",
        "labels", "frames", "examined_frames", "unmatched_frames", "truncated", "unknown",
    }
    if type(record) is not dict or set(record) != keys:
        return False
    if type(record["labels"]) is not list or len(record["labels"]) > 12:
        return False
    if type(record["frames"]) is not list:
        return False
    frames = record["frames"]
    labels = record["labels"]
    valid_frames = len(frames) == len(labels)
    if valid_frames:
        for label, frame in zip(labels, frames):
            if type(frame) is not dict or set(frame) != {
                    "source_relative_path", "function", "line"}:
                valid_frames = False
                break
            relative_path = frame["source_relative_path"]
            function = frame["function"]
            line = frame["line"]
            if (type(relative_path) is not str or relative_path not in _QUALIFICATION_STACK_SOURCE_FILES
                    or type(function) is not str
                    or _QUALIFICATION_STACK_FUNCTIONS.get(function) != label
                    or function not in _QUALIFICATION_STACK_SOURCE_FILES[relative_path]
                    or type(line) is not int or not 1 <= line <= 2 * 1024 * 1024):
                valid_frames = False
                break
    return (valid_frames and type(record["schema"]) is int and record["schema"] == 2
            and type(record["candidate_commit"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", record["candidate_commit"]) is not None
            and type(record["candidate_archive_sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", record["candidate_archive_sha256"]) is not None
            and type(record["elapsed_ms"]) is int
            and 0 <= record["elapsed_ms"] <= 300_000
            and type(record["labels"]) is list and len(record["labels"]) <= 12
            and all(type(label) is str and label in _QUALIFICATION_STACK_LABELS
                    for label in record["labels"])
            and type(record["examined_frames"]) is int
            and 0 <= record["examined_frames"] <= 32
            and type(record["unmatched_frames"]) is int
            and 0 <= record["unmatched_frames"] <= record["examined_frames"]
            and len(record["labels"]) + record["unmatched_frames"]
            <= record["examined_frames"]
            and type(record["truncated"]) is bool
            and type(record["unknown"]) is bool
            and (record["unknown"]
                 or (len(record["labels"]) > 0 and not record["truncated"])))


def _emit_qualification_stack_sample(record: dict, sample_done: threading.Event,
                                     publication_lock: threading.Lock) -> None:
    """Attempt one bounded atomic write to the held original stderr pipe."""
    if not _valid_qualification_stack_sample(record):
        return
    writer_fd = None
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        payload = (_QUALIFICATION_STACK_SAMPLE_PREFIX + raw + "\n").encode("ascii")
        if len(payload) > 4096:
            return
        if sample_done.is_set():
            return
        original_fd = _QUALIFICATION_STACK_SAMPLE_STREAM.fileno()
        original_stat = os.fstat(original_fd)
        original_flags = fcntl.fcntl(original_fd, fcntl.F_GETFL)
        if not stat.S_ISFIFO(original_stat.st_mode):
            return
        writer_fd = os.open(
            f"/proc/self/fd/{original_fd}",
            os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0))
        writer_stat = os.fstat(writer_fd)
        writer_flags = fcntl.fcntl(writer_fd, fcntl.F_GETFL)
        current_original_stat = os.fstat(original_fd)
        current_original_flags = fcntl.fcntl(original_fd, fcntl.F_GETFL)
        if (not stat.S_ISFIFO(writer_stat.st_mode)
                or (writer_stat.st_dev, writer_stat.st_ino)
                != (original_stat.st_dev, original_stat.st_ino)
                or (current_original_stat.st_dev, current_original_stat.st_ino,
                    current_original_stat.st_mode)
                != (original_stat.st_dev, original_stat.st_ino, original_stat.st_mode)
                or current_original_flags != original_flags
                or not writer_flags & os.O_NONBLOCK):
            return
        pipe_buf = os.fpathconf(writer_fd, "PC_PIPE_BUF")
        if type(pipe_buf) is not int or len(payload) > min(4096, pipe_buf):
            return
        # The worker never waits for this gate. The main thread uses the same
        # gate only as a return barrier; this critical section contains one
        # nonblocking write of at most PIPE_BUF bytes.
        if not publication_lock.acquire(blocking=False):
            return
        try:
            if sample_done.is_set():
                return
            written = os.write(writer_fd, payload)
            if written != len(payload):
                return
        finally:
            publication_lock.release()
    except (AttributeError, OSError, ValueError, TypeError, OverflowError):
        return
    finally:
        if writer_fd is not None:
            try:
                os.close(writer_fd)
            except OSError:
                pass


def _emit_qualification_checkpoint(candidate_sha: str, archive_sha: str,
                                   sequence: int, phase: str, started: float,
                                   state: dict) -> None:
    if (type(candidate_sha) is not str or re.fullmatch(r"[0-9a-f]{40}", candidate_sha) is None
            or type(archive_sha) is not str
            or re.fullmatch(r"[0-9a-f]{64}", archive_sha) is None
            or type(sequence) is not int or sequence < 1 or sequence > 16
            or phase not in _QUALIFICATION_CHECKPOINT_PHASES
            or type(state) is not dict):
        return
    try:
        elapsed = time.monotonic() - started
        if not isinstance(elapsed, (int, float)) or elapsed < 0:
            return
        elapsed_ms = min(int(elapsed * 1000), 300_000)
        previous = state.get("last_elapsed_ms", -1)
        if type(previous) is not int or previous < -1 or previous > 300_000:
            return
        # Keep this an honest monotonic-clock measurement; sequence carries order.
        if elapsed_ms < previous:
            return
        state["last_elapsed_ms"] = elapsed_ms
        record = {
            "schema": 1, "candidate_commit": candidate_sha,
            "candidate_archive_sha256": archive_sha, "sequence": sequence,
            "phase": phase, "elapsed_ms": elapsed_ms,
        }
        line = _QUALIFICATION_CHECKPOINT_PREFIX + json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if len((line + "\n").encode("ascii")) > 4096:
            return
        _QUALIFICATION_CHECKPOINT_STREAM.write(line + "\n")
        _QUALIFICATION_CHECKPOINT_STREAM.flush()
    except (OSError, ValueError, TypeError):
        # A diagnostic sink failure is not an alternate update gate.
        return


def _candidate_source(commit: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("candidate commit must be a full lowercase SHA")
    return Path(f"/opt/hermes-installer-core-{commit[:9]}/src")


def _open_root_dir(parent_fd: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise RuntimeError("fixed staged source ancestor custody differs")
    return fd


def _read_held_helper(generation_fd: int) -> tuple[bytes, list[int]]:
    """Read, but never execute, the helper beneath a verified tools directory."""
    fds: list[int] = []
    try:
        generation = os.fstat(generation_fd)
        if (not stat.S_ISDIR(generation.st_mode) or generation.st_uid != 0
                or generation.st_gid != 0 or stat.S_IMODE(generation.st_mode) & 0o022):
            raise RuntimeError("fixed staged source ancestor custody differs")
        tools_fd = _open_root_dir(generation_fd, "tools")
        fds.append(tools_fd)
        helper_fd = os.open("pi_native_core_adopt.py", os.O_RDONLY
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0), dir_fd=tools_fd)
        fds.append(helper_fd)
        before = os.fstat(helper_fd)
        named = os.stat("pi_native_core_adopt.py", dir_fd=tools_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1
                or not 1 <= before.st_size <= 2 * 1024 * 1024
                or (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_gid, before.st_nlink, before.st_size)
                != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                    named.st_gid, named.st_nlink, named.st_size)):
            raise RuntimeError("fixed staged provenance verifier custody differs")
        helper = bytearray()
        while len(helper) <= 2 * 1024 * 1024:
            chunk = os.read(helper_fd, min(65536, 2 * 1024 * 1024 + 1 - len(helper)))
            if not chunk:
                break
            helper.extend(chunk)
        after = os.fstat(helper_fd)
        if (len(helper) != before.st_size or len(helper) > 2 * 1024 * 1024
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                             after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeError("fixed staged verifier changed during held read")
        return bytes(helper), fds
    except BaseException:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _load_stage_verifier(commit: str):
    """Check ancestors, tools and a held helper inode before executing it."""
    generation_name = f"hermes-installer-core-{commit[:9]}"
    fds: list[int] = []
    root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                      | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fds.append(root_fd)
    try:
        opt_fd = _open_root_dir(root_fd, "opt"); fds.append(opt_fd)
        generation_fd = _open_root_dir(opt_fd, generation_name); fds.append(generation_fd)
        src_fd = _open_root_dir(generation_fd, "src"); fds.append(src_fd)
        helper, helper_fds = _read_held_helper(generation_fd)
        fds.extend(helper_fds)
        return helper, fds, src_fd
    except BaseException:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _execute_stage_verifier(commit: str, helper_bytes: bytes):
    import types
    module = types.ModuleType("_pi_native_core_adopt_for_qualification")
    module.__file__ = f"/opt/hermes-installer-core-{commit[:9]}/tools/pi_native_core_adopt.py"
    exec(compile(helper_bytes, module.__file__, "exec"), module.__dict__)
    return module


def _verify_held_source_path(generation_fd: int, source_fd: int) -> None:
    held = os.fstat(source_fd)
    named = os.stat("src", dir_fd=generation_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(held.st_mode) or held.st_uid != 0 or held.st_gid != 0
            or stat.S_IMODE(held.st_mode) & 0o022
            or (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid)
            != (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid)):
        raise RuntimeError("fixed staged source directory changed after custody check")


def _read_source_receipt(generation_fd: int) -> dict[str, Any]:
    fd = os.open(".source-provenance.json", os.O_RDONLY
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                 dir_fd=generation_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                or not 1 <= info.st_size <= 1024):
            raise RuntimeError("source provenance receipt custody differs")
        raw = bytearray()
        while len(raw) <= 1024:
            block = os.read(fd, min(512, 1025 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        named = os.stat(".source-provenance.json", dir_fd=generation_fd,
                        follow_symlinks=False)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != info.st_size or len(raw) > 1024
                or identity != (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                                after.st_gid, after.st_nlink, after.st_size,
                                after.st_mtime_ns, after.st_ctime_ns)
                or identity != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                                named.st_gid, named.st_nlink, named.st_size,
                                named.st_mtime_ns, named.st_ctime_ns)):
            raise RuntimeError("source provenance receipt changed during read")
    finally:
        os.close(fd)
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate receipt key")
                value[key] = item
            return value
        receipt = json.loads(bytes(raw).decode("utf-8", "strict"), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise RuntimeError("source provenance receipt is malformed") from None
    if (type(receipt) is not dict or set(receipt) != {"schema", "source_commit", "archive_sha256"}
            or type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("source_commit", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("archive_sha256", "")))):
        raise RuntimeError("source provenance receipt fields differ")
    return receipt


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class _DigestSink(io.TextIOBase):
    """Discard CLI text while retaining bounded count/hash metadata only."""
    def __init__(self) -> None:
        self._hash = hashlib.sha256()
        self.byte_count = 0

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("text sink accepts strings only")
        raw = value.encode("utf-8", "replace")
        self._hash.update(raw)
        self.byte_count += len(raw)
        return len(value)

    def flush(self) -> None:
        return None

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()


def _native_plugin_transition_valid(value: object) -> bool:
    fields = {"schema", "purpose", "old_adapter_generation", "new_adapter_generation",
              "plugin_selection_sha256", "old_members", "new_members"}
    if type(value) is not dict or set(value) != fields:
        return False
    def member_map(row: object) -> bool:
        return (type(row) is dict and set(row) == {"plugin.yaml", "__init__.py"}
                and all(isinstance(row[name], str)
                        and re.fullmatch(r"[0-9a-f]{64}", row[name]) is not None
                        for name in ("plugin.yaml", "__init__.py")))
    return (type(value["schema"]) is int and value["schema"] == 1
            and value["purpose"] == "fixed-native-resources-plugin"
            and isinstance(value["old_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["old_adapter_generation"]) is not None
            and isinstance(value["new_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["new_adapter_generation"]) is not None
            and value["old_adapter_generation"] != value["new_adapter_generation"]
            and isinstance(value["plugin_selection_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["plugin_selection_sha256"]) is not None
            and member_map(value["old_members"]) and member_map(value["new_members"])
            and value["old_members"]["plugin.yaml"] == value["new_members"]["plugin.yaml"]
            and value["old_members"]["__init__.py"] != value["new_members"]["__init__.py"])


def _snapshot(runtime: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Ask CoreRuntime's real protected readers to validate active state."""
    record, raw_journal, files = runtime._read_active_adapter_runtime()
    bindings = runtime._snapshot_adapter_update_bindings(
        core_source_generation=record["core_source_generation"])
    _overlay_record, overlay_contents, _overlay_raw = runtime._read_adapter_overlay_snapshot()
    from hermes_installer.remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
    selection = verify_native_resources_plugin_selection()
    selection_sha = getattr(selection, "selection_sha256", None)
    if not isinstance(selection_sha, str) or re.fullmatch(r"[0-9a-f]{64}", selection_sha) is None:
        raise RuntimeError("selected native plugin receipt is unavailable")
    plugin_snapshot = runtime._read_installed_native_resources_plugin_members()
    plugin_members = getattr(plugin_snapshot, "members", None)
    plugin_signatures = getattr(plugin_snapshot, "signatures", None)
    plugin_names = {"plugin.yaml", "__init__.py"}
    if (type(plugin_members) not in {dict, MappingProxyType}
            or set(plugin_members) != plugin_names
            or type(plugin_signatures) not in {dict, MappingProxyType}
            or set(plugin_signatures) != plugin_names):
        raise RuntimeError("fixed native plugin member snapshot is not closed")
    plugin_members = dict(plugin_members)
    plugin_signatures = dict(plugin_signatures)
    for name, data in plugin_members.items():
        signature = plugin_signatures[name]
        if (type(data) is not bytes
                or type(signature) is not tuple or len(signature) != 9
                or any(type(item) is not int for item in signature)
                or any(item < 0 for item in signature)
                or signature[2] != 0o444 or signature[3] != 0 or signature[4] != 0
                or signature[5] != 1 or signature[6] != len(data)
                or not 1 <= len(data) <= 64 * 1024):
            raise RuntimeError("fixed native plugin member custody is invalid")
    plugin_member_sha = {name: _digest(plugin_members[name]) for name in sorted(plugin_names)}
    cohort, _cohort_raw = runtime._read_adapter_update_cohort(allow_absent=True)
    plugin_transition = cohort.get("native_plugin_transition") if cohort is not None else None
    if plugin_transition is not None:
        if (not _native_plugin_transition_valid(plugin_transition)
                or plugin_transition.get("purpose") != "fixed-native-resources-plugin"
                or plugin_transition.get("new_adapter_generation") != record.get("adapter_generation")
                or plugin_transition.get("plugin_selection_sha256") != selection_sha
                or plugin_transition.get("new_members") != plugin_member_sha):
            raise RuntimeError("fixed native plugin transition is not bound to installed members")
    primary = _primary_prompt_state(runtime)
    public = {
        "journal_sha256": _digest(raw_journal),
        "unit_sha256": _digest(files[runtime.UNIT]),
        "launcher_sha256": _digest(files[runtime.LAUNCHER]),
        "token_custody_verified": True,
        "token_sha256": _digest(files[runtime.TOKEN]),
        "adapter_source": record["adapter_source"],
        "adapter_generation": record["adapter_generation"],
        "core_source_generation": record["core_source_generation"],
        "plugin_selection_sha256": selection_sha,
        "native_plugin_members_sha256": plugin_member_sha,
        "native_plugin_transition": plugin_transition,
        "resources_record_sha256": bindings["resources_record_sha256"],
        "overlay_record_sha256": bindings["overlay_record_sha256"],
        "overlay_content_count": len(overlay_contents),
        "overlay_contents_sha256": _digest(json.dumps(
            [(key, _digest(value)) for key, value in sorted(overlay_contents.items())],
            ensure_ascii=True, separators=(",", ":")).encode("ascii")),
        "primary_record_sha256": bindings["primary_record_sha256"],
        "obsidian_registration_state": bindings["obsidian_registration_state"],
        "obsidian_registration_sha256": bindings["obsidian_registration_sha256"],
        "obsidian_vault_tree_sha256": bindings["obsidian_vault_tree_sha256"],
        "adapter_update_state": record.get("adapter_update_state"),
        "adapter_update_previous_source": record.get("adapter_update_previous_source"),
        "adapter_update_backup_source_generation": (
            record.get("adapter_update_backup", {}).get("source_generation")
            if isinstance(record.get("adapter_update_backup"), dict) else None
        ),
        "primary_prompt_soul_sha256": primary["soul_sha256"],
        "primary_prompt_state": primary["state"],
        "primary_owner_prefix_sha256": primary["owner_prefix_sha256"],
        "primary_owner_prefix_length": primary["owner_prefix_length"],
        "primary_immutable_backup_sha256": primary["immutable_backup_sha256"],
    }
    retained = {
        "journal": raw_journal,
        "unit": files[runtime.UNIT],
        "launcher": files[runtime.LAUNCHER],
        "token_sha256": _digest(files[runtime.TOKEN]),
        "resources_record": bindings.get("resources_record"),
        "overlay_record": bindings.get("overlay_record"),
        "primary_record": bindings.get("primary_record"),
        "obsidian_registration": bindings.get("obsidian_registration"),
        "prior_cohort": bindings.get("prior_cohort"),
        "adapter_generation": record["adapter_generation"],
        "plugin_selection_sha256": selection_sha,
        "native_plugin_members_sha256": plugin_member_sha,
        "native_plugin_members": plugin_members,
        "native_plugin_signatures": plugin_signatures,
        "native_plugin_transition": plugin_transition,
        "adapter_update_backup": record.get("adapter_update_backup"),
        "primary": primary,
    }
    return public, retained


def _primary_prompt_state(runtime: Any) -> dict[str, Any]:
    """Validate adopted SOUL and immutable owner backup; retain bytes privately."""
    from hermes_installer import primary_prompt_manager as manager
    from hermes_installer.registry.primary_prompt import render_managed_block, split_managed_block

    soul, signature = manager._read_soul(runtime)
    record = manager._read_record(runtime)
    if record is None:
        return {"soul_sha256": _digest(soul), "state": "unmanaged",
                "owner_prefix_sha256": _digest(soul), "owner_prefix_length": len(soul),
                "immutable_backup_sha256": None, "owner_prefix": soul,
                "backup": None, "soul": soul, "record": None, "signature": signature,
                "separator": b"", "managed_block": b""}
    if record.get("state") != "adopted":
        raise RuntimeError("primary prompt is not in its stable adopted state")
    source_generation, _discovery, artifact_sha, manifest, files, _prompt = manager._fixed_bundle(runtime)
    source = manifest.get("source") if isinstance(manifest, dict) else None
    if (source_generation != runtime._core_source_generation()
            or record.get("core_source_generation") != source_generation
            or record.get("artifact_sha256") != artifact_sha
            or not isinstance(source, dict)
            or record.get("resources_revision") != source.get("revision")
            or record.get("resources_tree") != source.get("git_tree")):
        raise RuntimeError("adopted primary prompt source/artifact binding is stale")
    prefix, separator, block = split_managed_block(
        soul, owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]))
    backup = manager._backup_read(runtime, record)
    source_prompt = files.get("registry/profiles/hermes/SOUL.md")
    if (_digest(prefix) != record["owner_prefix_sha256"]
            or _digest(backup) != record["owner_backup_name"]
            or _digest(backup) != record["prior_soul_sha256"]
            or _digest(soul) != record["result_soul_sha256"]
            or signature != record["result_soul_signature"]
            or _digest(block) != record["managed_block_sha256"]
            or not isinstance(source_prompt, bytes)
            or _digest(source_prompt) != record.get("source_prompt_sha256")
            or block != render_managed_block(source_prompt)):
        raise RuntimeError("adopted primary prompt or immutable owner backup differs")
    return {"soul_sha256": _digest(soul), "state": "adopted",
            "owner_prefix_sha256": _digest(prefix), "owner_prefix_length": len(prefix),
            "immutable_backup_sha256": _digest(backup), "owner_prefix": prefix,
            "backup": backup, "soul": soul, "record": record, "signature": signature,
            "separator": separator, "managed_block": block}


def _backup_matches_before(runtime: Any, before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Compare the protected transaction backup to exact retained old bytes."""
    try:
        current = json.loads(after["journal"])
        reference = current.get("adapter_update_backup")
        prior, contents = runtime._read_adapter_update_backup(reference)
        saved_journal = json.loads(contents["journal.json"])
        selection = json.loads(contents["plugin-selection.json"])
    except Exception:
        return False
    transition = after.get("native_plugin_transition")
    expected_members = set(_ADAPTER_BACKUP_BASE_MEMBERS)
    if transition is not None:
        if (not _native_plugin_transition_valid(transition)
                or transition["old_adapter_generation"] != before.get("adapter_generation")
                or transition["new_adapter_generation"] != after.get("adapter_generation")
                or transition["plugin_selection_sha256"] != before.get("plugin_selection_sha256")
                or transition["plugin_selection_sha256"] != after.get("plugin_selection_sha256")
                or transition["old_members"] != before.get("native_plugin_members_sha256")
                or transition["new_members"] != after.get("native_plugin_members_sha256")):
            return False
        expected_members.update(_NATIVE_PLUGIN_BACKUP_NAMES.values())
    elif (before.get("native_plugin_members_sha256")
          != after.get("native_plugin_members_sha256")):
        return False
    files = reference.get("files") if type(reference) is dict else None
    if (type(files) is not dict or set(files) != expected_members
            or set(contents) != expected_members
            or any(not isinstance(files[name], str)
                   or re.fullmatch(r"[0-9a-f]{64}", files[name]) is None
                   or not isinstance(contents[name], bytes)
                   or hashlib.sha256(contents[name]).hexdigest() != files[name]
                   for name in expected_members)):
        return False
    exact = (
        ("journal.json", "journal"), ("unit", "unit"), ("launcher", "launcher"),
        ("resources-record.json", "resources_record"),
        ("overlay-record.json", "overlay_record"),
        ("primary-record.json", "primary_record"),
        ("obsidian-registration.json", "obsidian_registration"),
        ("cohort.json", "prior_cohort"),
    )
    if not all(type(before.get(field)) is bytes and contents.get(name) == before[field]
               for name, field in exact):
        return False
    if transition is not None:
        if any(contents.get(_NATIVE_PLUGIN_BACKUP_NAMES[name])
               != before.get("native_plugin_members", {}).get(name)
               for name in _NATIVE_PLUGIN_MEMBER_NAMES):
            return False
    if (saved_journal != json.loads(before["journal"])
            or prior.get("adapter_generation") != saved_journal.get("adapter_generation")
            or selection != {"schema": 1,
                             "selection_sha256": before["plugin_selection_sha256"]}
            or before["token_sha256"] != after["token_sha256"]):
        return False
    return True


def _primary_prompt_matches_before(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Require a valid adopted result and preserve owner-authored bytes exactly."""
    old = before["primary"]
    new = after["primary"]
    if new["state"] != "adopted":
        return False
    if old["state"] == "adopted":
        return (new["soul"] == old["soul"]
                and new["owner_prefix"] == old["owner_prefix"]
                and new["backup"] == old["backup"]
                and new["record"] == old["record"]
                and new["signature"] == old["signature"])
    record = new["record"]
    return bool(record and record.get("state") == "adopted"
                and new["owner_prefix"] == old["soul"]
                and new["backup"] == old["soul"]
                and new["soul"] == (old["soul"] + new["separator"] + new["managed_block"])
                and record.get("owner_prefix_length") == len(old["soul"]))


def _success_checks(before: dict[str, Any], after: dict[str, Any], candidate_src: str,
                    *, cohort_phase: str, listener_current: bool) -> dict[str, bool]:
    """Check only outcomes established by the protected runtime's live readbacks."""
    transition = after.get("native_plugin_transition")
    if transition is None:
        plugin_transition_proven = (
            before.get("native_plugin_members_sha256")
            == after.get("native_plugin_members_sha256")
        )
    else:
        plugin_transition_proven = (
            _native_plugin_transition_valid(transition)
            and transition["old_adapter_generation"] == before.get("adapter_generation")
            and transition["new_adapter_generation"] == after.get("adapter_generation")
            and transition["plugin_selection_sha256"] == before.get("plugin_selection_sha256")
            and transition["plugin_selection_sha256"] == after.get("plugin_selection_sha256")
            and transition["old_members"] == before.get("native_plugin_members_sha256")
            and transition["new_members"] == after.get("native_plugin_members_sha256")
        )
    return {
        "candidate_adapter_is_active": after.get("adapter_source") == candidate_src,
        "adapter_generation_changed": (
            isinstance(before.get("adapter_generation"), str)
            and after.get("adapter_generation") != before.get("adapter_generation")
        ),
        "prior_source_bound": (
            after.get("adapter_update_previous_source") == before.get("adapter_source")
        ),
        "Core_generation_preserved": (
            after.get("core_source_generation") == before.get("core_source_generation")
        ),
        "selected_plugin_preserved": (
            after.get("plugin_selection_sha256") == before.get("plugin_selection_sha256")
        ),
        "native_plugin_transition_proven": plugin_transition_proven,
        "overlay_skill_bytes_preserved": (
            after.get("overlay_content_count") == before.get("overlay_content_count")
            and after.get("overlay_contents_sha256") == before.get("overlay_contents_sha256")
        ),
        "Obsidian_registration_and_vault_preserved": (
            after.get("obsidian_registration_state") == before.get("obsidian_registration_state")
            and after.get("obsidian_registration_sha256") == before.get("obsidian_registration_sha256")
            and after.get("obsidian_vault_tree_sha256") == before.get("obsidian_vault_tree_sha256")
        ),
        "committed_update_cohort": (
            after.get("adapter_update_state") == "active" and cohort_phase == "committed"
        ),
        "protected_prior_backup_bound": (
            after.get("adapter_update_backup_source_generation") == before.get("adapter_generation")
        ),
        "candidate_listener_current": listener_current is True,
    }


_TRACEBACK_UNSET = object()


def _root_setup_exception_origin(exc: BaseException, candidate_src: Path,
                                 *, outer_tb=_TRACEBACK_UNSET) -> dict | None:
    exc_type = type(exc)
    name = getattr(exc_type, "__name__", None)
    if (not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None):
        return None
    frames = []
    seen = set()
    current = exc
    use_outer_tb = outer_tb is not _TRACEBACK_UNSET
    while current is not None and len(seen) < 4 and len(frames) < 12:
        identity = id(current)
        if identity in seen:
            break
        seen.add(identity)
        if use_outer_tb:
            tb = outer_tb
            use_outer_tb = False
        else:
            tb = BaseException.__traceback__.__get__(current)
        visited = 0
        while tb is not None and visited < 128 and len(frames) < 12:
            visited += 1
            frame = tb.tb_frame
            try:
                filename = os.path.abspath(frame.f_code.co_filename)
                relative = os.path.relpath(filename, str(candidate_src))
                relative_path = Path(relative)
                function = frame.f_code.co_name
                line = tb.tb_lineno
                if (relative == "." or os.path.isabs(relative)
                        or any(part in {"", ".", ".."} for part in relative_path.parts)
                        or re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", relative) is None
                        or not isinstance(function, str)
                        or re.fullmatch(r"[A-Za-z0-9_<>.$-]{1,256}", function) is None
                        or type(line) is not int or line < 1):
                    tb = tb.tb_next
                    continue
                frames.append({"source_relative_path": relative_path.as_posix(),
                               "function": function, "line": line})
            except (OSError, ValueError, TypeError):
                pass
            tb = tb.tb_next
        cause = BaseException.__cause__.__get__(current)
        current = cause if cause is not None else BaseException.__context__.__get__(current)
    if not frames:
        return None
    return {"exception_type": name, "frames": frames}


def _run_fixed_root_adapter_update(root_setup, candidate_src: Path,
                                   candidate_sha: str,
                                   archive_sha: str,
                                   source_fd: int | None = None) -> tuple[int, dict | None]:
    if sys.gettrace() is not None:
        raise RuntimeError("qualification runner requires an untraced root CLI context")
    main = root_setup.main
    main_code = getattr(main, "__code__", None)
    if main_code is None:
        raise RuntimeError("fixed root CLI entry point has no verified code object")
    captured: dict[str, dict | None] = {"origin": None}
    sample_done = threading.Event()
    sample_lock = threading.Lock()
    main_ident = threading.get_ident()
    try:
        code_rows, source_rows, mapping_complete = _verified_qualification_stack_codes(
            candidate_src, source_fd)
    except Exception:
        code_rows, source_rows, mapping_complete = {}, {}, False
    sample_started = time.monotonic()
    main_depth = 0
    cancellation_barrier_done = False

    def cancel_sample():
        nonlocal cancellation_barrier_done
        sample_done.set()
        if cancellation_barrier_done:
            return
        # Bound the return path even if the observer is descheduled. Once
        # cancelled, it cannot begin a new publication; a write already
        # authorized under the gate may finish.
        if sample_lock.acquire(timeout=0.05):
            sample_lock.release()
        cancellation_barrier_done = True

    def sample_after_bound():
        if sample_done.wait(_QUALIFICATION_STACK_SAMPLE_SECONDS):
            return
        if sample_done.is_set():
            return
        elapsed = time.monotonic() - sample_started
        elapsed_ms = (min(int(elapsed * 1000), 300_000)
                      if isinstance(elapsed, (int, float)) and elapsed >= 0 else 0)
        try:
            source_current = _qualification_stack_sources_current(source_fd, source_rows)
            record = _qualification_stack_sample(
                candidate_sha, archive_sha, elapsed_ms, main_ident,
                code_rows, mapping_complete, source_current=source_current)
        except Exception:
            # Sampling is observational. A failed or incomplete projection
            # is represented as unknown and never changes the CLI result.
            record = {
                "schema": 2, "candidate_commit": candidate_sha,
                "candidate_archive_sha256": archive_sha,
                "elapsed_ms": elapsed_ms, "labels": [], "frames": [],
                "examined_frames": 0, "unmatched_frames": 0,
                "truncated": False, "unknown": True,
            }
        if not sample_done.is_set():
            _emit_qualification_stack_sample(record, sample_done, sample_lock)

    sampler = threading.Thread(target=sample_after_bound, daemon=True,
                               name="core-qualification-stack-sample")

    def trace(frame, event, arg):
        nonlocal main_depth
        if event == "call":
            if frame.f_code is main_code:
                main_depth += 1
                return trace
            return None
        if frame.f_code is not main_code:
            return None
        if event == "return":
            main_depth = max(0, main_depth - 1)
            if main_depth:
                return trace
            # The return trace event runs before the CLI frame is gone. It
            # cancels first and uses a bounded barrier against a publication
            # already in progress; the worker cannot start another write.
            cancel_sample()
            return trace
        if event == "exception" and frame.f_code is main_code:
            try:
                if type(arg) is not tuple or len(arg) != 3:
                    captured["origin"] = None
                    return trace
                exc = arg[1]
                if not isinstance(exc, BaseException):
                    captured["origin"] = None
                    return trace
                captured["origin"] = _root_setup_exception_origin(
                    exc, candidate_src, outer_tb=arg[2])
            except (TypeError, ValueError):
                captured["origin"] = None
        return trace

    sampler_started = False
    try:
        sampler.start()
        sampler_started = True
    except Exception:
        # A best-effort observer must never block the fixed CLI operation.
        sample_done.set()
    trace_installed = False
    try:
        sys.settrace(trace)
        trace_installed = True
        try:
            result = main(["core-service", "adapter-update"])
            cli_exit = result if type(result) is int and 0 <= result <= 255 else 1
        except Exception:
            # The trace retains only type and source locations; never inspect
            # or serialize the exception object or its arguments.
            cli_exit = 1
    finally:
        if trace_installed:
            sys.settrace(None)
        cancel_sample()
        if sampler_started:
            try:
                sampler.join(timeout=0.05)
            except Exception:
                pass
    origin = captured["origin"] if cli_exit != 0 else None
    return cli_exit, origin


def _load_candidate_runtime(source_root: Path):
    if "hermes_installer" in sys.modules:
        raise RuntimeError("unexpected installer module was loaded before source selection")
    sys.path.insert(0, str(source_root))
    from hermes_installer import core_runtime
    from hermes_installer import root_setup
    expected_root = source_root / "hermes_installer"
    if (Path(core_runtime.__file__).resolve(strict=True).parent != expected_root
            or Path(root_setup.__file__).resolve(strict=True).parent != expected_root):
        raise RuntimeError("fixed Core CLI did not load from the selected candidate")
    if core_runtime.ADAPTER_SOURCE != source_root:
        raise RuntimeError("Core adapter source does not match the selected candidate")
    return core_runtime, root_setup


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-sha", required=True,
                        help="full SHA already staged beneath the fixed /opt source root")
    parser.add_argument("--archive-sha256", required=True,
                        help="full archive digest paired by the fixed staging receipt")
    args = parser.parse_args(argv)
    if re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha) is None:
        parser.error("--candidate-sha must be 40 lowercase hexadecimal characters")
    if re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256) is None:
        parser.error("--archive-sha256 must be 64 lowercase hexadecimal characters")
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        parser.error("run this qualification on the identified Linux Pi as root")
    if sys.executable != "/usr/bin/python3" or not sys.flags.isolated:
        parser.error("run with /usr/bin/python3 -I")

    progress_started = time.monotonic()
    progress_state = {"last_elapsed_ms": -1}
    progress_sequence = 0

    def checkpoint(phase: str) -> None:
        nonlocal progress_sequence
        progress_sequence += 1
        _emit_qualification_checkpoint(args.candidate_sha, args.archive_sha256,
                                       progress_sequence, phase, progress_started,
                                       progress_state)

    candidate_src = _candidate_source(args.candidate_sha)
    helper_bytes, custody_fds, source_fd = _load_stage_verifier(args.candidate_sha)
    try:
        provenance = _read_source_receipt(custody_fds[2])
        if (provenance.get("source_commit") != args.candidate_sha
                or provenance.get("archive_sha256") != args.archive_sha256):
            raise RuntimeError("staged source/archive receipt differs from the reviewed request")
        _verify_held_source_path(custody_fds[2], source_fd)
        checkpoint("stage_verifier")
        stage = _execute_stage_verifier(args.candidate_sha, helper_bytes)
        stage._verify_source_provenance(args.candidate_sha, candidate_src)

        checkpoint("runtime_load")
        runtime, root_setup = _load_candidate_runtime(candidate_src)
        _verify_held_source_path(custody_fds[2], source_fd)
        checkpoint("before_snapshot")
        before_public, before_private = _snapshot(runtime)
        if before_public["adapter_source"] == str(candidate_src):
            raise RuntimeError("candidate adapter is already active; no update was attempted")

        # Invoke only the existing finite root CLI verb, with no target, path,
        # command, credential, or failure-injection selector from the caller.
        cli_stdout, cli_stderr = _DigestSink(), _DigestSink()
        checkpoint("adapter_update")
        with contextlib.redirect_stdout(cli_stdout), contextlib.redirect_stderr(cli_stderr):
            cli_exit, cli_failure_origin = _run_fixed_root_adapter_update(
                root_setup, candidate_src, args.candidate_sha, args.archive_sha256,
                source_fd)
        after_public = None
        after_private = None
        after_error = None
        cohort_phase = None
        listener_current = False
        try:
            checkpoint("after_snapshot")
            after_public, after_private = _snapshot(runtime)
            cohort, _cohort_raw = runtime._read_adapter_update_cohort()
            cohort_phase = cohort.get("phase")
            checkpoint("history_validation")
            runtime._validate_adapter_update_history(runtime._journal())
            checkpoint("listener_verification")
            listener_current = runtime._owned_listener_pidfd(adapter_source=candidate_src)
        except Exception as exc:
            after_error = type(exc).__name__

        checkpoint("success_checks")
        checks = (_success_checks(before_public, after_public, str(candidate_src),
                                  cohort_phase=cohort_phase,
                                  listener_current=listener_current)
                  if after_public is not None else {})
        if after_public is not None and after_private is not None:
            checks["protected_prior_backup_matches_exact_bytes"] = _backup_matches_before(
                runtime, before_private, after_private)
            checks["runtime_token_digest_preserved"] = (
                before_public["token_sha256"] == after_public["token_sha256"])
            checks["primary_prompt_owner_bytes_and_adopted_record_preserved"] = (
                _primary_prompt_matches_before(before_private, after_private))
        success = cli_exit == 0 and bool(checks) and all(checks.values())
        report = {
            "schema": 1,
            "action": "core-service adapter-update",
            "candidate_commit": args.candidate_sha,
            "candidate_archive_sha256": args.archive_sha256,
            "source_receipt_is_operator_paired_not_signature": True,
            "ancestor_and_verifier_custody_checked_before_execution": True,
            "cli_exit_code": cli_exit,
            "cli_failure_origin": cli_failure_origin,
            "cli_output": {
                "stdout_bytes": cli_stdout.byte_count, "stdout_sha256": cli_stdout.sha256,
                "stderr_bytes": cli_stderr.byte_count, "stderr_sha256": cli_stderr.sha256,
            },
            "before": before_public,
            "after": after_public,
            "after_readback_error_type": after_error,
            "cohort_phase": cohort_phase,
            "checks": checks,
            "outcome": "verified_adapter_update" if success else "pending_or_failed",
            "rollback_qualification": "not_run",
            "interruption_recovery_qualification": "not_run",
            "acceptance": "not_claimed",
        }
        checkpoint("report_emission")
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if success else 4
    finally:
        for fd in reversed(custody_fds):
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
