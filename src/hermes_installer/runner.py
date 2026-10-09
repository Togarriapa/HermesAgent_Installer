"""Bounded subprocess interface: no shell, minimal environment, explicit cwd."""

from __future__ import annotations

import shutil
import subprocess
import threading
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class CommandRejected(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProcessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CommandRunner:
    """Runs an allowlisted read-only probe; argument vectors are never shell parsed."""

    _SAFE_PROGRAMS = {"uname", "lsblk", "findmnt", "df", "systemctl", "loginctl", "dpkg-query", "rpm", "sha256sum", "shasum"}
    _PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
    MAX_OUTPUT_BYTES = 1024 * 1024

    def __init__(self, allowed_programs: set[str] | None = None, timeout: float = 30.0):
        self.allowed_programs = allowed_programs or set(self._SAFE_PROGRAMS)
        self.timeout = timeout

    def run(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None, timeout: float | None = None) -> ProcessResult:
        if not argv or not argv[0] or Path(argv[0]).name not in self.allowed_programs or Path(argv[0]).name != argv[0]:
            raise CommandRejected("Executable is not in the reviewed allowlist")
        program = Path(argv[0]).name
        if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise CommandRejected("Arguments must be NUL-free strings")
        if not _approved_invocation(program, tuple(argv[1:])):
            raise CommandRejected(f"Invocation is not an approved read-only operation for {program}")
        executable = shutil.which(program, path=self._PATH)
        if executable is None:
            raise CommandRejected(f"Required executable not found: {Path(argv[0]).name}")
        resolved_executable = Path(executable).resolve(strict=True)
        if not any(resolved_executable.is_relative_to(Path(prefix)) for prefix in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")):
            raise CommandRejected("Executable resolved outside the fixed system tool directories")
        root = cwd.resolve(strict=True)
        if not root.is_dir():
            raise CommandRejected("Command working directory is not a directory")
        safe_env = {"PATH": "/usr/bin:/bin:/usr/local/bin", "HOME": str(Path.home()), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
        if env:
            # Callers may only add non-secret, reviewed environment values. Reject likely secret keys.
            for key, value in env.items():
                if key in safe_env or key not in {"LANG", "LC_ALL", "SYSTEMD_PAGER", "SYSTEMD_COLORS"}:
                    raise CommandRejected(f"Environment variable is outside the reviewed allowlist: {key}")
                safe_env[key] = value
        process = subprocess.Popen([str(resolved_executable), *argv[1:]], cwd=root, env=safe_env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True, start_new_session=True)
        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        stdout_thread = threading.Thread(target=_capture_bounded, args=(process.stdout, stdout_chunks, self.MAX_OUTPUT_BYTES), daemon=True)
        stderr_thread = threading.Thread(target=_capture_bounded, args=(process.stderr, stderr_chunks, self.MAX_OUTPUT_BYTES), daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        timed_out = False
        try:
            process.wait(timeout=min(timeout or self.timeout, 300))
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_group(process)
        except BaseException:
            _terminate_group(process)
            raise
        finally:
            if process.poll() is None:
                _terminate_group(process)
            stdout_thread.join(timeout=2)
            stderr_thread.join(timeout=2)
            if stdout_thread.is_alive() or stderr_thread.is_alive():
                _terminate_group(process)
                stdout_thread.join(timeout=2)
                stderr_thread.join(timeout=2)
        return ProcessResult((program, *argv[1:]), 124 if timed_out else process.returncode, _decode(b"".join(stdout_chunks)), _decode(b"".join(stderr_chunks)), timed_out)


def _capture_bounded(stream, chunks: list[bytes], maximum: int) -> None:
    kept = 0
    while True:
        block = stream.read(65536)
        if not block:
            break
        if kept < maximum:
            part = block[: maximum - kept]
            chunks.append(part)
            kept += len(part)
    stream.close()


def _terminate_group(process: subprocess.Popen) -> None:
    """Bound cleanup for this short-lived allowlisted probe only.

    Persistent commands must use ManagedProcessSupervisor so the user system
    manager retains descendant cleanup custody if the leader exits.
    """
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=0.5)
        return
    except subprocess.TimeoutExpired:
        pass
    process.kill()
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        raise RuntimeError("probe process did not exit after kill") from None


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _approved_invocation(program: str, args: tuple[str, ...]) -> bool:
    """Exact grammars keep output/config/helper flags out of the probe boundary."""
    if program == "uname":
        return len(args) == 1 and args[0] in {"-a", "-m", "-r"}
    if program == "lsblk":
        return args == ("--json", "--bytes", "--output", "PATH,TYPE,TRAN,SIZE,FSTYPE,PKNAME,MODEL,MOUNTPOINTS")
    if program == "findmnt":
        return len(args) == 3 and args[0] == "--json" and args[1] == "--target" and _safe_path_arg(args[2])
    if program == "df":
        return len(args) == 3 and args[:2] == ("-P", "-B1") and _safe_path_arg(args[2])
    if program == "systemctl":
        return args == ("list-units", "--all", "--type", "service", "--no-legend", "--no-pager") or (
            len(args) == 4 and args[:2] == ("show", "--property") and args[2] in {"ActiveState", "UnitFileState", "LoadState"} and _safe_unit_name(args[3])
        )
    if program == "loginctl":
        return args == ("list-sessions", "--no-legend", "--no-pager") or (
            len(args) == 2 and args[0] == "show-session" and args[1].isdigit() and len(args[1]) <= 12
        )
    if program == "dpkg-query":
        return len(args) == 2 and args[0] == "--show" and _safe_package_name(args[1])
    if program == "rpm":
        return args == ("--query", "--all") or (len(args) == 2 and args[0] == "--query" and _safe_package_name(args[1]))
    if program == "sha256sum":
        return len(args) == 1 and _safe_path_arg(args[0])
    if program == "shasum":
        return len(args) == 3 and args[:2] == ("-a", "256") and _safe_path_arg(args[2])
    # git, shell interpreters, package managers and network clients are not
    # generic probe tools. Their mutation-capable interfaces need dedicated adapters.
    return False


def _safe_path_arg(value: str) -> bool:
    return bool(value) and not value.startswith("-") and "\x00" not in value


def _safe_unit_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.@:-]{1,128}", value)) and value.endswith(".service")


def _safe_package_name(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+:~_-]{0,127}", value))
