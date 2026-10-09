"""Owned user-systemd scopes for bounded installer child processes.

The user system manager, rather than a reusable pid or process-group number, owns
the lifetime and cleanup authority for each admitted operation. This backend is
Linux-specific and fails closed when pidfds, /proc cgroup identity, or systemd
user scopes are unavailable.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import select
import shutil
import signal
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class ManagedProcessError(RuntimeError):
    """A managed process could not be admitted or its custody was lost."""


@dataclass(frozen=True, slots=True)
class ManagedProcessSpec:
    executable: Path
    argv: tuple[str, ...]
    artifact_sha256: str
    owned_root: Path
    cwd: Path
    data_root: Path
    env_allowlist: Mapping[str, str]
    journal_operation: str
    service_identity: str
    startup_deadline_monotonic: float
    max_lifetime_seconds: float
    child_artifact_hashes: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    unit: str
    cgroup: str
    pid: int
    start_ticks: int
    executable_sha256: str
    pidfd: int


@dataclass(frozen=True, slots=True)
class ChildIdentity:
    role: str
    pid: int
    start_ticks: int
    parent_pid: int
    executable_sha256: str
    cgroup: str
    pidfd: int


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def _proc_stat(pid: int) -> tuple[int, int]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    tail = raw[raw.rfind(")") + 2:].split()
    return int(tail[1]), int(tail[19])


def _proc_cgroup(pid: int) -> str:
    lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    unified = [line.split(":", 2)[2] for line in lines if line.startswith("0::")]
    if len(unified) != 1:
        raise ManagedProcessError("Unified cgroup identity is unavailable")
    return unified[0]


def _systemctl(*args: str, timeout: float = 2.0) -> str:
    path = shutil.which("systemctl", path="/usr/bin:/bin")
    if path is None:
        raise ManagedProcessError("systemctl is unavailable")
    try:
        result = subprocess.run(
            [path, "--user", *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
            timeout=timeout, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise ManagedProcessError("user systemd operation failed") from None
    return result.stdout.decode("utf-8", "replace").strip()


def _show(unit: str, prop: str) -> str:
    if prop not in {"ControlGroup", "MainPID", "ActiveState", "SubState"}:
        raise ValueError("unsupported systemd property")
    return _systemctl("show", "--property=" + prop, "--value", unit)


def _validate_spec(spec: ManagedProcessSpec) -> tuple[Path, Path, Path]:
    root = spec.owned_root.resolve(strict=True)
    exe = spec.executable.resolve(strict=True)
    cwd = spec.cwd.resolve(strict=True)
    data = spec.data_root.resolve(strict=True)
    if not root.is_dir() or not cwd.is_dir() or not data.is_dir():
        raise ManagedProcessError("owned roots and working directory must be directories")
    if not _within(cwd, root) or not _within(data, root) or not _within(exe, root):
        raise ManagedProcessError("executable, cwd, and data root must be inside the owned root")
    if not os.access(exe, os.X_OK) or not re.fullmatch(r"[0-9a-f]{64}", spec.artifact_sha256):
        raise ManagedProcessError("executable pin is invalid")
    if _digest(exe) != spec.artifact_sha256:
        raise ManagedProcessError("executable does not match its reviewed artifact pin")
    if not spec.argv or spec.argv[0] != str(exe) or any(not isinstance(x, str) or "\x00" in x for x in spec.argv):
        raise ManagedProcessError("argv must start with the pinned executable and contain NUL-free strings")
    if not spec.journal_operation or not spec.service_identity:
        raise ManagedProcessError("journal operation and service identity are required")
    now = time.monotonic()
    if not now < spec.startup_deadline_monotonic <= now + 600:
        raise ManagedProcessError("startup deadline must be an absolute bounded monotonic time")
    if not 0 < spec.max_lifetime_seconds <= 86400:
        raise ManagedProcessError("a finite process lifetime of at most one day is required")
    for key, value in spec.env_allowlist.items():
        if key not in {"HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY",
                       "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                       "HERMES_HOME", "TMPDIR"}:
            raise ManagedProcessError("environment key is outside the reviewed allowlist")
        if not isinstance(value, str) or "\x00" in value or len(value) > 4096:
            raise ManagedProcessError("environment value is invalid")
        if re.search(r"(TOKEN|SECRET|PASSWORD|API_KEY|CREDENTIAL)", key, re.I):
            raise ManagedProcessError("secret-bearing environment values are not accepted")
    return root, exe, cwd


class ManagedProcessHandle:
    def __init__(self, spec: ManagedProcessSpec, unit: str, cgroup: str,
                 launcher: subprocess.Popen[bytes], identity: ProcessIdentity,
                 started: float):
        self.spec, self.unit, self.cgroup = spec, unit, cgroup
        self._launcher, self.identity = launcher, identity
        self._started = started
        self._closed = False
        self._watchdog = asyncio.create_task(self._enforce_lifetime())

    async def _enforce_lifetime(self) -> None:
        remaining = max(0.0, self.spec.max_lifetime_seconds - (time.monotonic() - self._started))
        await asyncio.sleep(remaining)
        if not self._closed:
            await self.stop("maximum lifetime expired", timeout=5.0)

    def _check_live(self) -> None:
        if self._closed:
            raise ManagedProcessError("process handle is closed")
        if time.monotonic() - self._started >= self.spec.max_lifetime_seconds:
            raise ManagedProcessError("managed process maximum lifetime expired")
        try:
            if _show(self.unit, "ControlGroup") != self.cgroup:
                raise ManagedProcessError("systemd unit custody changed")
            if _proc_cgroup(self.identity.pid) != self.cgroup:
                raise ManagedProcessError("managed process left its owned cgroup")
            if _proc_stat(self.identity.pid)[1] != self.identity.start_ticks:
                raise ManagedProcessError("managed process identity was reused")
        except (FileNotFoundError, ProcessLookupError):
            raise ManagedProcessError("managed process exited") from None

    def snapshot_children(self) -> tuple[ChildIdentity, ...]:
        """Return current cgroup members with pidfd, start-time, executable and ancestry proof."""
        self._check_live()
        base = Path("/sys/fs/cgroup") / self.cgroup.lstrip("/")
        try:
            pids = [int(x) for x in (base / "cgroup.procs").read_text().split()]
        except (OSError, ValueError):
            raise ManagedProcessError("owned cgroup membership cannot be observed") from None
        by_pid: dict[int, tuple[int, int, str, int]] = {}
        for pid in pids:
            try:
                parent, ticks = _proc_stat(pid)
                group = _proc_cgroup(pid)
                exe = Path(f"/proc/{pid}/exe").resolve(strict=True)
                digest = _digest(exe)
                fd = os.pidfd_open(pid, 0)
                if _proc_stat(pid)[1] != ticks or _proc_cgroup(pid) != group:
                    os.close(fd)
                    continue
                by_pid[pid] = (parent, ticks, digest, fd)
            except (OSError, ValueError, ManagedProcessError):
                continue
        out: list[ChildIdentity] = []
        pins = self.spec.child_artifact_hashes or {}
        for pid, (parent, ticks, digest, fd) in by_pid.items():
            role = next((name for name, pin in pins.items() if pin == digest), None)
            if role is None or _proc_cgroup(pid) != self.cgroup:
                os.close(fd)
                continue
            ancestor = parent
            seen: set[int] = set()
            valid = False
            while ancestor not in seen and ancestor > 1:
                if ancestor == self.identity.pid:
                    valid = True
                    break
                seen.add(ancestor)
                if ancestor not in by_pid:
                    break
                ancestor = by_pid[ancestor][0]
            if not valid:
                os.close(fd)
                continue
            out.append(ChildIdentity(role, pid, ticks, parent, digest, self.cgroup, fd))
        return tuple(out)

    async def read(self, maximum_bytes: int, timeout: float) -> bytes:
        if not 1 <= maximum_bytes <= 1_048_576 or not 0 <= timeout <= 30:
            raise ValueError("read bounds are invalid")
        self._check_live()
        return await asyncio.to_thread(self._read, maximum_bytes, timeout)

    def _read(self, maximum_bytes: int, timeout: float) -> bytes:
        stream = self._launcher.stdout
        if stream is None:
            raise ManagedProcessError("managed stdout is unavailable")
        ready, _, _ = select.select([stream], [], [], timeout)
        return os.read(stream.fileno(), maximum_bytes) if ready else b""

    async def write(self, data: bytes, timeout: float) -> int:
        if not isinstance(data, bytes) or len(data) > 65536 or not 0 <= timeout <= 30:
            raise ValueError("write bounds are invalid")
        self._check_live()
        return await asyncio.to_thread(self._write, data, timeout)

    def _write(self, data: bytes, timeout: float) -> int:
        stream = self._launcher.stdin
        if stream is None:
            raise ManagedProcessError("managed stdin is unavailable")
        _, ready, _ = select.select([], [stream], [], timeout)
        if not ready:
            return 0
        return os.write(stream.fileno(), data)

    async def wait(self, timeout: float) -> int | None:
        if not 0 <= timeout <= 30:
            raise ValueError("wait bound is invalid")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if _show(self.unit, "ActiveState") not in {"active", "activating", "reloading"}:
                    return self._launcher.poll()
            except ManagedProcessError:
                if self._launcher.poll() is not None:
                    return self._launcher.poll()
            await asyncio.sleep(0.05)
        return None

    async def stop(self, reason: str, timeout: float = 5.0) -> None:
        if not reason or len(reason) > 160 or not 0 < timeout <= 10:
            raise ValueError("stop reason or bound is invalid")
        if self._closed:
            return
        if asyncio.current_task() is not self._watchdog:
            self._watchdog.cancel()
        # The unit is the custody handle; never signal a pid or process group.
        if _show(self.unit, "ControlGroup") == self.cgroup:
            try:
                await asyncio.to_thread(_systemctl, "kill", "--kill-whom=all",
                                        "--signal=SIGTERM", self.unit, timeout=2.0)
                await asyncio.sleep(min(0.25, timeout / 4))
                if _show(self.unit, "ControlGroup") == self.cgroup:
                    await asyncio.to_thread(_systemctl, "kill", "--kill-whom=all",
                                            "--signal=SIGKILL", self.unit, timeout=2.0)
                await asyncio.to_thread(_systemctl, "stop", self.unit, timeout=2.0)
            except ManagedProcessError:
                # Lost custody means cleanup cannot be claimed.
                raise
        self._closed = True
        os.close(self.identity.pidfd)
        if self._launcher.stdout:
            self._launcher.stdout.close()
        if self._launcher.stdin:
            self._launcher.stdin.close()


class ManagedProcessSupervisor:
    """Starts commands in unique systemd user scopes and bounds all handles."""
    async def start(self, spec: ManagedProcessSpec) -> ManagedProcessHandle:
        _, exe, cwd = _validate_spec(spec)
        if not hasattr(os, "pidfd_open"):
            raise ManagedProcessError("kernel pidfd support is required")
        if not shutil.which("systemd-run", path="/usr/bin:/bin"):
            raise ManagedProcessError("systemd-run is unavailable")
        if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            raise ManagedProcessError("unified cgroup v2 is required")
        unit = "hermes-installer-" + uuid.uuid4().hex + ".scope"
        env_args = []
        for key, value in sorted(spec.env_allowlist.items()):
            env_args.extend(["--setenv=" + key + "=" + value])
        command = [
            "/usr/bin/systemd-run", "--user", "--scope", "--pipe", "--quiet",
            "--unit=" + unit, "--property=KillMode=control-group",
            "--working-directory=" + str(cwd), *env_args, str(exe), *spec.argv[1:],
        ]
        safe_env = {"PATH": "/usr/bin:/bin", "LANG": "C"}
        started = time.monotonic()
        try:
            launcher = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=safe_env,
                                        close_fds=True, shell=False)
        except OSError:
            raise ManagedProcessError("systemd scope launch failed") from None
        try:
            while time.monotonic() < spec.startup_deadline_monotonic:
                try:
                    cgroup = _show(unit, "ControlGroup")
                    pid_text = _show(unit, "MainPID")
                    pid = int(pid_text)
                    if cgroup and cgroup.startswith("/") and pid > 1:
                        break
                except (ManagedProcessError, ValueError):
                    pass
                if launcher.poll() is not None:
                    raise ManagedProcessError("systemd scope exited before admission")
                await asyncio.sleep(0.05)
            else:
                raise ManagedProcessError("managed process startup deadline expired")
            parent, ticks = _proc_stat(pid)
            del parent
            actual_group = _proc_cgroup(pid)
            executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
            digest = _digest(executable)
            if actual_group != cgroup or digest != spec.artifact_sha256:
                raise ManagedProcessError("systemd process identity does not match its cgroup and artifact pin")
            pidfd = os.pidfd_open(pid, 0)
            if _proc_stat(pid)[1] != ticks or _proc_cgroup(pid) != cgroup:
                os.close(pidfd)
                raise ManagedProcessError("process changed during admission")
            identity = ProcessIdentity(unit, cgroup, pid, ticks, digest, pidfd)
            return ManagedProcessHandle(spec, unit, cgroup, launcher, identity, started)
        except BaseException:
            try:
                cgroup = _show(unit, "ControlGroup")
                if cgroup:
                    _systemctl("kill", "--kill-whom=all", "--signal=SIGKILL", unit)
                    _systemctl("stop", unit)
            except ManagedProcessError:
                pass
            try:
                launcher.kill()
                launcher.wait(timeout=1)
            except (OSError, subprocess.SubprocessError):
                pass
            raise
