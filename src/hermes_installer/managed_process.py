"""Owned transient services for bounded, isolated installer child processes.

The user system manager owns each process cgroup and enforces a finite runtime
maximum. Cleanup authority is the manager-issued unit and cgroup, never a PID
or process-group number. Unsupported kernel or manager features fail closed.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import pwd
import select
import stat
import contextlib
from hermes_installer.state import Journal, OwnedRoot, OwnershipError
import shutil
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
    artifact_root: Path
    owned_root: OwnedRoot
    cwd: Path
    data_root: Path
    env_allowlist: Mapping[str, str]
    journal_operation: str
    journal: Journal
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


def _digest_fd(fd: int) -> str:
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while True:
        block = os.read(fd, 1024 * 1024)
        if not block:
            break
        h.update(block)
    return h.hexdigest()


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _observe_process(pid: int, expected_cgroup: str) -> tuple[int, int, str, int]:
    pidfd = os.pidfd_open(pid, 0)
    try:
        parent, ticks = _proc_stat(pid)
        if _proc_cgroup(pid) != expected_cgroup:
            raise ManagedProcessError("process is outside the manager-owned cgroup")
        exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            opened = os.fstat(exe_fd)
            digest = _digest_fd(exe_fd)
            current = os.stat(f"/proc/{pid}/exe")
            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
                raise ManagedProcessError("process executable changed during observation")
        finally:
            os.close(exe_fd)
        if _proc_stat(pid)[1] != ticks or _proc_cgroup(pid) != expected_cgroup or _pidfd_exited(pidfd):
            raise ManagedProcessError("process identity changed during observation")
        return parent, ticks, digest, pidfd
    except BaseException:
        os.close(pidfd)
        raise


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


def _bus_environment() -> dict[str, str]:
    if not hasattr(os, "geteuid") or not sys_platform_linux():
        raise ManagedProcessError("managed services require Linux user systemd")
    uid = os.getuid()
    runtime = Path(f"/run/user/{uid}")
    try:
        info = runtime.lstat()
        bus = runtime / "bus"
        bus_info = bus.lstat()
    except OSError:
        raise ManagedProcessError("owned user systemd bus is unavailable") from None
    if info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700 or not stat.S_ISDIR(info.st_mode):
        raise ManagedProcessError("user runtime directory is not private and UID-owned")
    if bus_info.st_uid != uid or not stat.S_ISSOCK(bus_info.st_mode):
        raise ManagedProcessError("user systemd bus is not an owned socket")
    return {"PATH": "/usr/bin:/bin", "LANG": "C"}


def sys_platform_linux() -> bool:
    return os.name == "posix" and Path("/proc/self/cgroup").exists()


async def _systemctl_async(*args: str, timeout: float = 2.0) -> str:
    path = shutil.which("systemctl", path="/usr/bin:/bin")
    if path is None:
        raise ManagedProcessError("systemctl is unavailable")
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            path, "-n", "systemctl", "--system", *args, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
            env=_bus_environment(), close_fds=True,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout)
        if process.returncode != 0:
            raise ManagedProcessError("user systemd operation failed")
        return stdout.decode("utf-8", "replace").strip()
    except asyncio.TimeoutError:
        if process is not None and process.returncode is None:
            process.kill()
            try:
                await asyncio.wait_for(process.wait(), 0.5)
            except asyncio.TimeoutError:
                pass
        raise ManagedProcessError("user systemd operation exceeded its bound") from None
    except asyncio.CancelledError:
        if process is not None and process.returncode is None:
            process.kill()
            await asyncio.shield(process.wait())
        raise
    except (OSError, asyncio.SubprocessError):
        raise ManagedProcessError("user systemd operation failed") from None


async def _show_async(unit: str, prop: str, timeout: float = 1.0) -> str:
    if prop not in {"ControlGroup", "MainPID", "ActiveState", "SubState", "Description", "RuntimeMaxUSec", "KillMode", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "NoNewPrivileges", "IPAddressDeny", "PrivateNetwork", "RestrictAddressFamilies", "ProtectHome", "ProtectProc", "ProcSubset", "User"}:
        raise ValueError("unsupported systemd property")
    return await _systemctl_async("show", "--property=" + prop, "--value", unit, timeout=timeout)


def _manager_environment_keys(raw: str) -> tuple[str, ...]:
    keys = set()
    for line in raw.splitlines():
        key, separator, _ = line.partition("=")
        if separator and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", key):
            keys.add(key)
    keys.update({"HOME", "USER", "LOGNAME", "SHELL", "INVOCATION_ID", "JOURNAL_STREAM",
                 "NOTIFY_SOCKET", "WATCHDOG_USEC", "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS",
                 "LISTEN_FDNAMES", "PATH", "LANG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"})
    if sum(len(key) + 1 for key in keys) > 60000:
        raise ManagedProcessError("user manager environment is too large to clear safely")
    return tuple(sorted(keys))


def _validate_spec(spec: ManagedProcessSpec) -> tuple[OwnedRoot, Path, Path, Path, Path]:
    if not isinstance(spec.owned_root, OwnedRoot) or not isinstance(spec.journal, Journal):
        raise ManagedProcessError("managed processes require an OwnedRoot and durable Journal")
    try:
        spec.owned_root.ensure()
        root = spec.owned_root.root.resolve(strict=True)
        exe = spec.owned_root.path(Path(spec.executable).relative_to(root).as_posix()).resolve(strict=True)
        artifact = spec.owned_root.path(Path(spec.artifact_root).relative_to(root).as_posix()).resolve(strict=True)
        cwd = spec.owned_root.path(Path(spec.cwd).relative_to(root).as_posix()).resolve(strict=True)
        data = spec.owned_root.path(Path(spec.data_root).relative_to(root).as_posix()).resolve(strict=True)
        journal_path = spec.journal.path.resolve(strict=True)
    except (OwnershipError, OSError, ValueError):
        raise ManagedProcessError("executable, cwd, data root, or journal is outside safe owned paths") from None
    if not (root.is_dir() and exe.is_file() and artifact.is_dir() and cwd.is_dir() and data.is_dir()):
        raise ManagedProcessError("owned roots, pinned artifact root and working directory must exist")
    if not exe.is_relative_to(artifact) or not cwd.is_relative_to(data) or not journal_path.is_relative_to(root):
        raise ManagedProcessError("working directory and journal must remain inside the owned profile root")
    info = root.lstat()
    marker = root / ".hermes-installer-owned"
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or marker.read_bytes() != b"schema=1\n":
        raise ManagedProcessError("owned root is not private or its marker is invalid")
    if not os.access(exe, os.X_OK) or not re.fullmatch(r"[0-9a-f]{64}", spec.artifact_sha256):
        raise ManagedProcessError("executable pin is invalid")
    if _digest(exe) != spec.artifact_sha256:
        raise ManagedProcessError("executable does not match its reviewed artifact pin")
    if not spec.argv or spec.argv[0] != str(exe) or any(not isinstance(x, str) or "\\x00" in x for x in spec.argv):
        raise ManagedProcessError("argv must start with the pinned executable and contain NUL-free strings")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", spec.journal_operation):
        raise ManagedProcessError("journal operation id is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", spec.service_identity):
        raise ManagedProcessError("service identity is invalid")
    now = time.monotonic()
    if not now < spec.startup_deadline_monotonic <= now + 600:
        raise ManagedProcessError("startup deadline must be an absolute bounded monotonic time")
    if not 0 < spec.max_lifetime_seconds <= 600:
        raise ManagedProcessError("manager-enforced process lifetime must be finite and at most ten minutes")
    allowed = {"HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY",
               "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HERMES_HOME", "TMPDIR"}
    for key, value in spec.env_allowlist.items():
        if key not in allowed or not isinstance(value, str) or "\\x00" in value or len(value) > 1024:
            raise ManagedProcessError("environment key or value is outside the reviewed allowlist")
        if re.search(r"(TOKEN|SECRET|PASSWORD|API_KEY|CREDENTIAL)", key, re.I):
            raise ManagedProcessError("secret-bearing environment values are not accepted")
        if any(ch in value for ch in "\n\r"):
            raise ManagedProcessError("environment values cannot contain newlines")
        if key in {"HOME", "HERMES_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR"} and not value.startswith("/hermes"):
            raise ManagedProcessError("writable profile paths must stay inside the isolated mount")
        if key == "PATH" and not re.fullmatch(r"[A-Za-z0-9_./:-]{1,512}", value):
            raise ManagedProcessError("PATH must contain only absolute executable directories")
        if key in {"LANG", "LC_ALL"} and not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", value):
            raise ManagedProcessError("locale value is invalid")
        if key in {"DISPLAY", "WAYLAND_DISPLAY"} and not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,128}", value):
            raise ManagedProcessError("display value is invalid")
    if spec.env_allowlist.get("HOME") != "/hermes":
        raise ManagedProcessError("profile HOME must be the isolated /hermes mount")
    return spec.owned_root, exe, artifact, cwd, data

class ManagedProcessHandle:
    def __init__(self, spec: ManagedProcessSpec, unit: str, cgroup: str,
                 launcher: subprocess.Popen[bytes], identity: ProcessIdentity,
                 started: float, target_env: Mapping[str, str]):
        self.spec, self.unit, self.cgroup = spec, unit, cgroup
        self._launcher, self.identity = launcher, identity
        self._started, self._target_env = started, dict(target_env)
        self._closed = False
        self._watchdog = asyncio.create_task(self._enforce_lifetime())

    async def __aenter__(self) -> "ManagedProcessHandle":
        await self._check_live()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await asyncio.shield(self.stop("operation complete" if exc is None else "operation failed"))

    async def _enforce_lifetime(self) -> None:
        await asyncio.sleep(max(0.0, self.spec.max_lifetime_seconds - (time.monotonic() - self._started)))
        if not self._closed:
            await self.stop("manager lifetime guard", timeout=5.0)

    def _check_clock(self) -> None:
        if self._closed or time.monotonic() - self._started >= self.spec.max_lifetime_seconds:
            raise ManagedProcessError("managed process is closed or expired")

    async def _check_custody(self) -> None:
        self._check_clock()
        if await _show_async(self.unit, "ControlGroup") != self.cgroup:
            raise ManagedProcessError("systemd unit custody changed")
        if await _show_async(self.unit, "Description") != self._description:
            raise ManagedProcessError("systemd operation identity changed")
    async def _check_live(self) -> None:
        await self._check_custody()
        if self._launcher.poll() is not None:
            raise ManagedProcessError("systemd service supervisor exited unexpectedly")
        try:
            if _proc_cgroup(self.identity.pid) != self.cgroup:
                raise ManagedProcessError("managed process left its owned cgroup")
            if _proc_stat(self.identity.pid)[1] != self.identity.start_ticks:
                raise ManagedProcessError("managed process identity changed")
            if _pidfd_exited(self.identity.pidfd):
                raise ManagedProcessError("managed process exited")
            self._verify_target_environment()
        except (FileNotFoundError, ProcessLookupError):
            raise ManagedProcessError("managed process exited") from None

    def _verify_target_environment(self) -> None:
        raw = Path(f"/proc/{self.identity.pid}/environ").read_bytes()
        observed = {}
        for item in raw.split(b"\x00"):
            if not item:
                continue
            key, separator, value = item.partition(b"=")
            if separator:
                observed[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
        if observed != self._target_env:
            raise ManagedProcessError("started process environment differs from the sanitized allowlist")

    async def snapshot_children(self) -> tuple[ChildIdentity, ...]:
        """Observe pinned descendants; the caller must close every returned pidfd."""
        await self._check_custody()
        base = Path("/sys/fs/cgroup") / self.cgroup.lstrip("/")
        try:
            pids = [int(x) for x in (base / "cgroup.procs").read_text().split()]
        except (OSError, ValueError):
            raise ManagedProcessError("owned cgroup membership cannot be observed") from None
        by_pid: dict[int, tuple[int, int, str, int]] = {}
        out: list[ChildIdentity] = []
        try:
            for pid in pids:
                try:
                    parent, ticks, digest, fd = _observe_process(pid, self.cgroup)
                    by_pid[pid] = (parent, ticks, digest, fd)
                except (OSError, ValueError, ManagedProcessError):
                    continue
            pins = self.spec.child_artifact_hashes or {}
            for pid, (parent, ticks, digest, fd) in tuple(by_pid.items()):
                role = next((name for name, pin in pins.items() if pin == digest), None)
                ancestor, seen, valid = parent, set(), False
                while role and ancestor not in seen and ancestor > 1:
                    if ancestor == self.identity.pid:
                        valid = True
                        break
                    seen.add(ancestor)
                    if ancestor not in by_pid:
                        break
                    ancestor = by_pid[ancestor][0]
                if role and valid and _proc_cgroup(pid) == self.cgroup and not _pidfd_exited(fd):
                    out.append(ChildIdentity(role, pid, ticks, parent, digest, self.cgroup, fd))
                    by_pid.pop(pid, None)
            return tuple(out)
        except BaseException:
            for _, _, _, fd in by_pid.values():
                with contextlib.suppress(OSError):
                    os.close(fd)
            for child in out:
                with contextlib.suppress(OSError):
                    os.close(child.pidfd)
            raise

    async def read(self, maximum_bytes: int, timeout: float) -> bytes:
        if not 1 <= maximum_bytes <= 1_048_576 or not 0 <= timeout <= 30:
            raise ValueError("read bounds are invalid")
        await self._check_live()
        stream = self._launcher.stdout
        if stream is None:
            raise ManagedProcessError("managed stdout is unavailable")
        fd, loop = stream.fileno(), asyncio.get_running_loop()
        os.set_blocking(fd, False)
        ready = loop.create_future()
        loop.add_reader(fd, lambda: None if ready.done() else ready.set_result(None))
        try:
            await asyncio.wait_for(ready, timeout)
            await self._check_live()
            return os.read(fd, maximum_bytes)
        except BlockingIOError:
            return b""
        finally:
            loop.remove_reader(fd)

    async def write(self, data: bytes, timeout: float) -> int:
        if not isinstance(data, bytes) or len(data) > 65536 or not 0 <= timeout <= 30:
            raise ValueError("write bounds are invalid")
        await self._check_live()
        stream = self._launcher.stdin
        if stream is None:
            raise ManagedProcessError("managed stdin is unavailable")
        fd, loop = stream.fileno(), asyncio.get_running_loop()
        os.set_blocking(fd, False)
        deadline, written = time.monotonic() + timeout, 0
        while written < len(data):
            await self._check_live()
            try:
                written += os.write(fd, data[written:])
                continue
            except BlockingIOError:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready = loop.create_future()
            loop.add_writer(fd, lambda: None if ready.done() else ready.set_result(None))
            try:
                await asyncio.wait_for(ready, remaining)
            finally:
                loop.remove_writer(fd)
        return written

    async def wait(self, timeout: float) -> int | None:
        if not 0 <= timeout <= 30:
            raise ValueError("wait bound is invalid")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            state = await _show_async(self.unit, "ActiveState", timeout=min(1.0, max(.1, deadline-time.monotonic())))
            if state not in {"active", "activating", "reloading"}:
                return self._launcher.poll()
            await asyncio.sleep(min(.05, max(0.0, deadline-time.monotonic())))
        return None

    def _remaining(self, deadline: float) -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise ManagedProcessError("cleanup deadline expired")
        return left

    def _cgroup_pids(self) -> tuple[int, ...]:
        path = Path("/sys/fs/cgroup") / self.cgroup.lstrip("/") / "cgroup.procs"
        try:
            return tuple(int(x) for x in path.read_text().split())
        except FileNotFoundError:
            return ()
        except (OSError, ValueError):
            raise ManagedProcessError("cannot verify that owned descendants exited") from None

    async def stop(self, reason: str, timeout: float = 5.0) -> None:
        if not reason or len(reason) > 160 or not 0 < timeout <= 10:
            raise ValueError("stop reason or bound is invalid")
        if self._closed:
            return
        if asyncio.current_task() is not self._watchdog:
            self._watchdog.cancel()
        deadline = time.monotonic() + timeout
        try:
            await self._check_custody()
            await _systemctl_async("kill", "--kill-whom=all", "--signal=SIGTERM", self.unit,
                                   timeout=min(1.0, self._remaining(deadline)))
            grace = min(deadline, time.monotonic() + .5)
            while self._cgroup_pids() and time.monotonic() < grace:
                await asyncio.sleep(min(.025, grace-time.monotonic()))
            if self._cgroup_pids():
                await _systemctl_async("kill", "--kill-whom=all", "--signal=SIGKILL", self.unit,
                                       timeout=min(1.0, self._remaining(deadline)))
            await _systemctl_async("stop", self.unit, timeout=min(1.0, self._remaining(deadline)))
            while self._cgroup_pids() and time.monotonic() < deadline:
                await asyncio.sleep(min(.025, deadline-time.monotonic()))
            if self._cgroup_pids():
                raise ManagedProcessError("manager did not empty the owned cgroup before the cleanup deadline")
            await asyncio.to_thread(self.spec.journal.checkpoint, self.spec.journal_operation,
                                    "stopped", {"unit": self.unit, "cgroup": self.cgroup,
                                                "service_identity": self.spec.service_identity,
                                                "reason": reason[:160]})
            self._closed = True
            os.close(self.identity.pidfd)
            for stream in (self._launcher.stdout, self._launcher.stdin):
                if stream:
                    stream.close()
            if self._launcher.poll() is None:
                self._launcher.kill()
                try:
                    await asyncio.wait_for(asyncio.to_thread(self._launcher.wait), self._remaining(deadline))
                except asyncio.TimeoutError:
                    raise ManagedProcessError("systemd-run client did not exit after unit cleanup") from None
        except BaseException:
            with contextlib.suppress(BaseException):
                await asyncio.shield(asyncio.to_thread(
                    self.spec.journal.checkpoint, self.spec.journal_operation,
                    "cleanup-failed", {"unit": self.unit, "cgroup": self.cgroup,
                                       "service_identity": self.spec.service_identity}))
            raise

    @property
    def _description(self) -> str:
        return "HermesInstaller " + self.spec.service_identity + " " + self.spec.journal_operation


class ManagedProcessSupervisor:
    """Starts private transient services with manager-enforced descendant custody."""
    async def start(self, spec: ManagedProcessSpec) -> ManagedProcessHandle:
        owned, exe, artifact, cwd, data = _validate_spec(spec)
        if not hasattr(os, "pidfd_open"):
            raise ManagedProcessError("kernel pidfd support is required")
        systemd_run = shutil.which("systemd-run", path="/usr/bin:/bin")
        if not systemd_run or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            raise ManagedProcessError("systemd user services and cgroup v2 are required")

        manager_env = await _systemctl_async("show-environment", timeout=3.0)
        unset_names = tuple(name for name in _manager_environment_keys(manager_env)
                            if name not in spec.env_allowlist)
        unit = "hermes-installer-" + uuid.uuid4().hex + ".service"
        description = "HermesInstaller " + spec.service_identity + " " + spec.journal_operation
        relative_cwd = cwd.relative_to(data).as_posix()
        target_cwd = "/hermes" if relative_cwd == "." else "/hermes/" + relative_cwd
        properties = [
            "--property=Type=exec",
            "--property=RuntimeMaxSec=" + str(int(spec.max_lifetime_seconds)) + "s",
            "--property=KillMode=control-group",
            "--property=Description=" + description,
            "--property=ProtectSystem=strict",
            "--property=ProtectHome=tmpfs",
            "--property=ProtectProc=invisible",
            "--property=ProcSubset=pid",
            "--property=InaccessiblePaths=-/run/user -/run/dbus/system_bus_socket -/run/docker.sock -/var/run/docker.sock -/run/containerd -/run/podman/podman.sock",
            "--property=PrivateTmp=yes",
            "--property=PrivateDevices=yes",
            "--property=NoNewPrivileges=yes",
            "--property=User=" + spec.service_user,
            "--property=SupplementaryGroups=",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=RestrictSUIDSGID=yes",
            "--property=RestrictNamespaces=user",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=PrivateNetwork=yes",
            "--property=IPAddressDeny=any",
            "--property=BindPaths=" + str(data) + ":/hermes",
            "--property=BindReadOnlyPaths=" + str(artifact) + ":" + str(artifact),
            "--property=UnsetEnvironment=" + " ".join(unset_names),
        ]
        if len(spec.env_allowlist) > 32:
            raise ManagedProcessError("environment allowlist exceeds its bound")
        env_args = ["--setenv=" + key + "=" + value
                    for key, value in sorted(spec.env_allowlist.items())]
        argv = [shutil.which("sudo", path="/usr/bin:/bin") or "/usr/bin/sudo", "-n", systemd_run, "--system", "--unit=" + unit, "--service-type=exec",
                "--wait", "--collect", "--pipe", "--quiet",
                "--working-directory=" + target_cwd, *properties, *env_args,
                str(exe), *spec.argv[1:]]
        # The manager connection needs only a validated UID-owned bus. No
        # inherited application variables or credential values enter this client.
        client_env = _bus_environment()
        started = time.monotonic()
        spec.journal.checkpoint(spec.journal_operation, "starting", {
            "unit": unit, "service_identity": spec.service_identity,
            "artifact_sha256": spec.artifact_sha256, "max_lifetime_seconds": spec.max_lifetime_seconds,
        })
        try:
            launcher = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=client_env,
                                        close_fds=True, shell=False)
        except OSError:
            spec.journal.checkpoint(spec.journal_operation, "start-failed", {
                "unit": unit, "service_identity": spec.service_identity, "reason": "client launch failed",
            })
            raise ManagedProcessError("systemd transient service launch failed") from None
        for stream in (launcher.stdin, launcher.stdout):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
        try:
            while time.monotonic() < spec.startup_deadline_monotonic:
                if launcher.poll() is not None:
                    raise ManagedProcessError("systemd service exited before admission")
                try:
                    cgroup = await _show_async(unit, "ControlGroup", timeout=.5)
                    if not cgroup.startswith("/"):
                        raise ManagedProcessError("manager did not provide a cgroup")
                    members = (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.procs").read_text().split()
                    matching = []
                    for candidate in members:
                        pid = int(candidate)
                        try:
                            observed = _observe_process(pid, cgroup)
                        except (OSError, ValueError, ManagedProcessError):
                            continue
                        parent, ticks, digest, pidfd = observed
                        os.close(pidfd)
                        if digest == spec.artifact_sha256:
                            matching.append((pid, parent, ticks))
                    if len(matching) == 1:
                        pid, parent, ticks = matching[0]
                        break
                except (ManagedProcessError, FileNotFoundError, ValueError):
                    pass
                await asyncio.sleep(.05)
            else:
                raise ManagedProcessError("managed process startup deadline expired")

            group = _proc_cgroup(pid)
            parent, ticks, digest, pidfd = _observe_process(pid, cgroup)
            if group != cgroup or digest != spec.artifact_sha256 or parent != matching[0][1] or ticks != matching[0][2]:
                os.close(pidfd)
                raise ManagedProcessError("systemd process identity changed during admission")
            for prop, expected in (("KillMode", "control-group"),
                                   ("ProtectSystem", "strict"),
                                   ("PrivateTmp", "yes"),
                                   ("PrivateDevices", "yes"),
                                   ("NoNewPrivileges", "yes"),
                                   ("IPAddressDeny", "any")):
                if await _show_async(unit, prop) != expected:
                    os.close(pidfd)
                    raise ManagedProcessError("required systemd isolation property was not applied")
            if await _show_async(unit, "Description") != description:
                os.close(pidfd)
                raise ManagedProcessError("manager operation identity does not match the journal binding")
            maximum = await _show_async(unit, "RuntimeMaxUSec")
            if not maximum.isdigit() or int(maximum) < int(spec.max_lifetime_seconds * 1_000_000):
                os.close(pidfd)
                raise ManagedProcessError("manager-enforced process lifetime is missing or too short")
            actual_env = self._read_process_environment(pid)
            if actual_env != dict(spec.env_allowlist):
                os.close(pidfd)
                raise ManagedProcessError("actual process environment differs from the sanitized allowlist")
            identity = ProcessIdentity(unit, cgroup, pid, ticks, digest, pidfd)
            await _systemctl_async("show", "--property=Description", "--value", unit, timeout=1.0)
            spec.journal.record_owned("managed-systemd-service", unit, "active")
            spec.journal.checkpoint(spec.journal_operation, "running", {
                "unit": unit, "cgroup": cgroup, "pid": pid, "start_ticks": ticks,
                "executable_sha256": digest, "service_identity": spec.service_identity,
            })
            return ManagedProcessHandle(spec, unit, cgroup, launcher, identity, started,
                                        spec.env_allowlist)
        except BaseException:
            try:
                cgroup = await _show_async(unit, "ControlGroup", timeout=.5)
                if cgroup.startswith("/"):
                    await _systemctl_async("kill", "--kill-whom=all", "--signal=SIGKILL", unit, timeout=1)
                    await _systemctl_async("stop", unit, timeout=1)
            except BaseException:
                pass
            if launcher.poll() is None:
                launcher.kill()
                try:
                    launcher.wait(timeout=.5)
                except subprocess.TimeoutExpired:
                    pass
            with contextlib.suppress(BaseException):
                spec.journal.checkpoint(spec.journal_operation, "start-failed", {
                    "unit": unit, "service_identity": spec.service_identity,
                    "reason": "admission or isolation verification failed",
                })
            raise

    @staticmethod
    def _read_process_environment(pid: int) -> dict[str, str]:
        raw = Path(f"/proc/{pid}/environ").read_bytes()
        result = {}
        for item in raw.split(b"\\x00"):
            if item:
                key, sep, value = item.partition(b"=")
                if sep:
                    result[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
        return result

    @staticmethod
    def close_child_snapshot(children: Sequence[ChildIdentity]) -> None:
        for child in children:
            try:
                os.close(child.pidfd)
            except OSError:
                pass
