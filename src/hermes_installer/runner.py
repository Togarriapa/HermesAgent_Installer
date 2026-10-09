"""Bounded subprocess interface: no shell, minimal environment, explicit cwd."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import threading
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

    _SAFE_SUBCOMMANDS = {
        "uname": {"-a", "-m", "-r"},
        "lsblk": {"--json", "-J"},
        "findmnt": {"--json", "-J", "--target"},
        "df": {"-P", "-h", "-k"},
        "systemctl": {"is-active", "show", "list-units", "list-unit-files"},
        "dpkg-query": {"-W"},
        "rpm": {"-qa", "-q"},
        "git": {"rev-parse", "show"},
        "sha256sum": set(),
        "shasum": {"-a"},
    }
    _PATH = "/usr/bin:/bin:/usr/sbin:/sbin"
    MAX_OUTPUT_BYTES = 1024 * 1024

    def __init__(self, allowed_programs: set[str] | None = None, timeout: float = 30.0):
        self.allowed_programs = allowed_programs or set(self._SAFE_SUBCOMMANDS)
        self.timeout = timeout

    def run(self, argv: Sequence[str], *, cwd: Path, env: Mapping[str, str] | None = None, timeout: float | None = None) -> ProcessResult:
        if not argv or not argv[0] or Path(argv[0]).name not in self.allowed_programs or Path(argv[0]).name != argv[0]:
            raise CommandRejected("Executable is not in the reviewed allowlist")
        program = Path(argv[0]).name
        safe_subcommands = self._SAFE_SUBCOMMANDS.get(program)
        if safe_subcommands is None:
            raise CommandRejected(f"No reviewed invocation policy exists for {program}")
        if safe_subcommands and (len(argv) < 2 or argv[1] not in safe_subcommands):
            raise CommandRejected(f"Invocation is not an approved read-only operation for {program}")
        if any(arg in {"-c", "--exec", "--upload-file", "--output", "--output-document", "--config", "--init-file"} for arg in argv[1:]):
            raise CommandRejected("Invocation contains a command, output, or configuration override option")
        if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise CommandRejected("Arguments must be NUL-free strings")
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
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    try:
        # Kill surviving descendants even if the process-group leader exited on TERM.
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    if process.poll() is None:
        process.wait()


def _decode(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value
