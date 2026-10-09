"""Fixed root-managed probes of outputs from protected hardware builds.

The only executable accepted here is the CPython binary at the fixed path
inside the unique output root returned by a protected build selection. The
custody runner independently joins that output root and terminal build receipt
before it launches the interpreter in a fresh isolated transient unit.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import sys
import time
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from .build_execution import ManagedBuildResult, managed_process_identity_digest
from .types import AuthorityDenied


_PROBE_TIMEOUT_SECONDS = 15.0
_PROBE_OUTPUT_LIMIT = 4096
_PYTHON_RELATIVE_PATH = "runtime/bin/python3.9"
_PROBE_READY_MARKER = b"HERMES_BUILD_PROBE_READY_V1\n"
_PROBE_FIELDS = frozenset({"python_version", "soabi", "debug", "glibc_version"})
_PROBE_MOUNT = "/run/hermes-installer/build/output"
_PROBE_SCRIPT = (
    "import sys\n"
    "sys.stderr.write('HERMES_BUILD_PROBE_READY_V1\\n')\n"
    "sys.stderr.flush()\n"
    "if sys.stdin.buffer.read(1)!=b'\\x01':raise SystemExit(78)\n"
    f"sys.path[:0]=[{_PROBE_MOUNT!r}+'/runtime/lib/python3.9',"
    f"{_PROBE_MOUNT!r}+'/runtime/lib/python3.9/lib-dynload'];"
    "import sysconfig,ctypes,json;"
    "libc=ctypes.CDLL('libc.so.6');"
    "libc.gnu_get_libc_version.restype=ctypes.c_char_p;"
    "print(json.dumps({'python_version':sys.version.split()[0],"
    "'soabi':sysconfig.get_config_var('SOABI'),"
    "'debug':bool(sysconfig.get_config_var('Py_DEBUG')),"
    "'glibc_version':libc.gnu_get_libc_version().decode('ascii')},"
    "sort_keys=True,separators=(',',':')))"
)
_PROBE_ARGV = ("-I", "-S", "-c", _PROBE_SCRIPT)


@dataclass(frozen=True, slots=True)
class ManagedBuildProbeResult:
    """Root-generated terminal proof for the fixed CPython output probe."""

    terminal_success_record_id: str
    build_terminal_success_record_id: str
    build_process_identity_digest: str
    process_identity_digest: str
    process_id: str
    generation: str
    uid: int
    gid: int
    pid: int
    start_ticks: int
    exit_code: int
    cleanup_verified: bool
    startup_gate_verified: bool
    cgroup_id: str
    mount_namespace_inode: int
    network_namespace_inode: int
    output_root_id: str
    output_root_device: int
    output_root_inode: int
    executable_sha256: str
    executable_size_bytes: int
    bounded_log_digest: str
    log_bytes: int
    stdout: bytes


class ManagedBuildProbeLauncher(Protocol):
    def run_attested_cpython39_probe(
        self, inputs: Any, build_result: ManagedBuildResult, *, timeout: float,
        cancelled: Callable[[], bool],
    ) -> ManagedBuildProbeResult: ...


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _parse_probe_output(value: bytes) -> Mapping[str, Any]:
    if not isinstance(value, bytes) or not 1 <= len(value) <= _PROBE_OUTPUT_LIMIT:
        raise AuthorityDenied("build.python_probe", "interpreter probe output is missing or oversized")
    try:
        text = value.decode("utf-8", "strict")
        row = json.loads(text, object_pairs_hook=_strict_object)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise AuthorityDenied("build.python_probe", "interpreter probe output is malformed") from None
    if not isinstance(row, dict) or set(row) != _PROBE_FIELDS:
        raise AuthorityDenied("build.python_probe", "interpreter probe output fields are invalid")
    if (not isinstance(row["python_version"], str) or not isinstance(row["soabi"], str)
            or type(row["debug"]) is not bool or not isinstance(row["glibc_version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", row["glibc_version"])):
        raise AuthorityDenied("build.python_probe", "interpreter probe facts have invalid types")
    return row


def _read_selected_executable(inputs: Any, executable: Path) -> tuple[str, int, os.stat_result, os.stat_result]:
    descriptors: list[int] = []
    try:
        root = Path(inputs.output_root)
        expected = root / _PYTHON_RELATIVE_PATH
        if executable != expected or not root.is_absolute():
            raise ValueError("output selection")
        root_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                          | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        descriptors.append(root_fd)
        root_info = os.fstat(root_fd)
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid != inputs.output_owner_uid
                or root_info.st_gid != inputs.output_owner_gid
                or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise ValueError("output root custody")
        current_fd = root_fd
        for part in ("runtime", "bin"):
            child_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                               dir_fd=current_fd)
            descriptors.append(child_fd)
            info = os.fstat(child_fd)
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != inputs.output_owner_uid or info.st_gid != inputs.output_owner_gid
                    or info.st_mode & 0o022):
                raise ValueError("output directory custody")
            current_fd = child_fd
        fd = os.open("python3.9", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=current_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != inputs.output_owner_uid
                    or info.st_gid != inputs.output_owner_gid
                    or not info.st_mode & 0o111 or info.st_mode & 0o022
                    or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > 64 * 1024 * 1024):
                raise ValueError("interpreter custody")
            hasher = hashlib.sha256()
            total = 0
            while block := os.read(fd, 1024 * 1024):
                total += len(block)
                if total > info.st_size:
                    raise ValueError("interpreter changed")
                hasher.update(block)
            if total != info.st_size:
                raise ValueError("interpreter changed")
            return hasher.hexdigest(), total, info, root_info
        finally:
            os.close(fd)
    except AuthorityDenied:
        raise
    except (AttributeError, OSError, TypeError, ValueError):
        raise AuthorityDenied("build.python_probe", "selected CPython output is not safely inspectable") from None
    finally:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass


class RootManagedCPython39Probe:
    """Run the fixed CPython ABI probe through the root build custody runner.

    This class does not execute a subprocess itself. The custody runner accepts
    only an already-completed selected build and derives the executable, argv,
    mount, service identity and transient-unit controls from protected records.
    """

    def __init__(self, launcher: ManagedBuildProbeLauncher, *,
                 monotonic: Callable[[], float] = time.monotonic):
        if not callable(getattr(launcher, "run_attested_cpython39_probe", None)) or not callable(monotonic):
            raise AuthorityDenied("build.python_probe", "root-managed fixed CPython probe runner is unavailable")
        self.launcher = launcher
        self.monotonic = monotonic
        self.qualified_for_host = (
            sys.platform == "linux" and platform.machine().lower() in {"aarch64", "arm64"}
        )

    def inspect_cpython39(self, profile: Any, executable: Path, *,
                          build_result: ManagedBuildResult, build_inputs: Any,
                          cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        if (not callable(cancelled) or not isinstance(build_result, ManagedBuildResult)
                or getattr(profile, "target_id", None) != "coral-cpython-build:start"
                or getattr(profile, "generation", None) != getattr(build_inputs, "generation", None)
                or getattr(build_inputs, "operation_id", None) != "coral-cpython39-source-build-v1"
                or getattr(build_inputs, "target_id", None) != "coral-cpython-build:start"
                or not build_result.terminal_success_record_id
                or build_result.exit_code != 0 or build_result.timed_out
                or build_result.cancelled or not build_result.cleanup_verified):
            raise AuthorityDenied("build.python_probe", "probe is not bound to a completed selected CPython build")
        before_digest, before_size, before_executable, before_root = _read_selected_executable(
            build_inputs, executable)
        if cancelled():
            raise AuthorityDenied("build.expired", "build probe was cancelled before launch")
        started = self.monotonic()
        try:
            probe = self.launcher.run_attested_cpython39_probe(
                build_inputs, build_result, timeout=_PROBE_TIMEOUT_SECONDS, cancelled=cancelled,
            )
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("build.python_probe", "root-managed interpreter probe failed") from None
        if cancelled():
            raise AuthorityDenied("build.expired", "build probe was cancelled before verification")
        after_digest, after_size, after_executable, after_root = _read_selected_executable(
            build_inputs, executable)
        if ((before_digest, before_size, before_executable.st_dev, before_executable.st_ino,
             before_root.st_dev, before_root.st_ino)
                != (after_digest, after_size, after_executable.st_dev, after_executable.st_ino,
                    after_root.st_dev, after_root.st_ino)):
            raise AuthorityDenied("build.python_probe", "selected output changed during interpreter probing")
        expected_fields = (
            "terminal_success_record_id", "build_terminal_success_record_id",
            "build_process_identity_digest", "process_identity_digest", "process_id", "generation",
            "uid", "gid", "pid", "start_ticks", "exit_code", "cleanup_verified", "cgroup_id",
            "mount_namespace_inode", "network_namespace_inode", "output_root_id",
            "output_root_device", "output_root_inode", "executable_sha256", "executable_size_bytes",
            "startup_gate_verified",
            "bounded_log_digest", "log_bytes", "stdout",
        )
        if any(not hasattr(probe, key) for key in expected_fields):
            raise AuthorityDenied("build.python_probe", "root probe terminal receipt is incomplete")
        # Report only fixed field names when root's typed result fails a proof
        # check. Never include receipt values, paths, PIDs, or probe output in
        # a denial: this is enough to diagnose cross-layer schema drift safely.
        stdout_valid = isinstance(probe.stdout, bytes)
        stdout_digest_valid = (
            stdout_valid and type(probe.log_bytes) is int
            and len(probe.stdout) == probe.log_bytes
            and isinstance(probe.bounded_log_digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", probe.bounded_log_digest) is not None
            and hashlib.sha256(probe.stdout).hexdigest() == probe.bounded_log_digest
        )
        receipt_checks = (
            ("terminal_success_record_id", isinstance(probe.terminal_success_record_id, str)
             and bool(probe.terminal_success_record_id)
             and probe.terminal_success_record_id != build_result.terminal_success_record_id),
            ("build_terminal_success_record_id", probe.build_terminal_success_record_id
             == build_result.terminal_success_record_id),
            ("build_process_identity_digest", probe.build_process_identity_digest
             == build_result.process_identity_digest),
            ("process_identity_digest", isinstance(probe.process_identity_digest, str)
             and re.fullmatch(r"[0-9a-f]{64}", probe.process_identity_digest) is not None
             and probe.process_identity_digest != build_result.process_identity_digest),
            ("process_id", isinstance(probe.process_id, str)
             and re.fullmatch(r"[0-9a-f]{32}", probe.process_id) is not None),
            ("generation", probe.generation == build_result.generation),
            ("uid", type(probe.uid) is int and probe.uid == build_result.uid
             and probe.uid == build_inputs.output_owner_uid),
            ("gid", type(probe.gid) is int and probe.gid == build_inputs.output_owner_gid),
            ("pid", type(probe.pid) is int and probe.pid > 1),
            ("start_ticks", type(probe.start_ticks) is int and probe.start_ticks > 0),
            ("exit_code", type(probe.exit_code) is int and probe.exit_code == 0),
            ("cleanup_verified", probe.cleanup_verified is True),
            ("startup_gate_verified", probe.startup_gate_verified is True),
            ("cgroup_id", isinstance(probe.cgroup_id, str) and bool(probe.cgroup_id)
             and probe.cgroup_id != build_result.cgroup_id),
            ("mount_namespace_inode", type(probe.mount_namespace_inode) is int
             and probe.mount_namespace_inode > 0
             and probe.mount_namespace_inode != build_result.mount_namespace_inode),
            ("network_namespace_inode", type(probe.network_namespace_inode) is int
             and probe.network_namespace_inode > 0
             and probe.network_namespace_inode != build_result.network_namespace_inode),
            ("output_root_id", probe.output_root_id == build_inputs.output_root_id),
            ("output_root_identity", type(probe.output_root_device) is int
             and type(probe.output_root_inode) is int
             and probe.output_root_device == before_root.st_dev
             and probe.output_root_inode == before_root.st_ino),
            ("executable_identity", probe.executable_sha256 == before_digest
             and type(probe.executable_size_bytes) is int
             and probe.executable_size_bytes == before_size),
            ("bounded_log_digest", isinstance(probe.bounded_log_digest, str)
             and re.fullmatch(r"[0-9a-f]{64}", probe.bounded_log_digest) is not None
             and stdout_digest_valid),
            ("log_bytes", type(probe.log_bytes) is int
             and 0 <= probe.log_bytes <= _PROBE_OUTPUT_LIMIT and stdout_valid),
            ("deadline", self.monotonic() - started <= _PROBE_TIMEOUT_SECONDS + 2),
        )
        failed = [name for name, valid in receipt_checks if not valid]
        if failed:
            # The error string is intentionally capped to stable schema keys.
            raise AuthorityDenied(
                "build.python_probe",
                "root probe receipt proof failed: " + ",".join(failed[:16]),
            )
        expected_identity = managed_process_identity_digest(
            process_id=probe.process_id, generation=probe.generation, uid=probe.uid, pid=probe.pid,
            start_ticks=probe.start_ticks, cgroup_id=probe.cgroup_id,
            mount_namespace_inode=probe.mount_namespace_inode,
            network_namespace_inode=probe.network_namespace_inode,
        )
        if expected_identity != probe.process_identity_digest:
            raise AuthorityDenied("build.python_probe", "probe process identity digest is not reproducible")
        observations = _parse_probe_output(probe.stdout)
        return {
            **dict(observations),
            "probe_execution": {
                "terminal_success_record_id": probe.terminal_success_record_id,
                "build_terminal_success_record_id": probe.build_terminal_success_record_id,
                "build_process_identity_digest": probe.build_process_identity_digest,
                "process_identity_digest": probe.process_identity_digest,
                "process_id": probe.process_id, "generation": probe.generation,
                "uid": probe.uid, "gid": probe.gid, "pid": probe.pid, "start_ticks": probe.start_ticks,
                "exit_code": probe.exit_code, "cleanup_verified": probe.cleanup_verified,
                "startup_gate_verified": probe.startup_gate_verified,
                "cgroup_id": probe.cgroup_id,
                "mount_namespace_inode": probe.mount_namespace_inode,
                "network_namespace_inode": probe.network_namespace_inode,
                "output_root_id": probe.output_root_id,
                "output_root_device": probe.output_root_device,
                "output_root_inode": probe.output_root_inode,
                "executable_sha256": probe.executable_sha256,
                "executable_size_bytes": probe.executable_size_bytes,
                "bounded_log_digest": probe.bounded_log_digest,
                "log_bytes": probe.log_bytes,
            },
        }
