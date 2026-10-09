"""Client API for root-custodied, bounded installer child processes.

The root authority broker owns service creation, cgroups, pidfds and cleanup;
this module accepts only host-issued grants and fixed process-control verbs.
"""
from __future__ import annotations

import asyncio
import base64
import json
import hashlib
import math
import os
import re
import pwd
import select
import stat
import contextlib
import threading
from hermes_installer.state import Journal, OwnedRoot, OwnershipError
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.types import (
    AuthorityDenied, EffectAuthorization, HostContext, canonical_digest,
)
from hermes_installer.authority.client import canonical_profile_target, profile_launch_envelope


class ManagedProcessError(RuntimeError):
    """A managed process could not be admitted or its custody was lost."""


@dataclass(frozen=True, slots=True)
class ManagedProcessResult:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    cleanup_verified: bool
    unit: str
    cgroup: str
    pid: int
    start_ticks: int
    executable_device: int
    executable_inode: int
    mount_namespace_inode: int
    network_namespace_inode: int
    uid: int
    gid: int
    memory_max_bytes: int | None
    cpu_quota_percent: int | None
    io_weight: int | None
    process_id: str = ""
    generation: str = ""
    kernel_limits: Mapping[str, str] | None = None


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
    service_user: str
    startup_deadline_monotonic: float
    max_lifetime_seconds: float
    profile_id: str = ""
    authority_context: HostContext | None = None
    effect_authorization: EffectAuthorization | None = None
    memory_max_bytes: int | None = None
    cpu_quota_percent: int | None = None
    io_weight: int | None = None
    child_artifact_refs: Mapping[str, str] | None = None
    max_output_bytes: int = 1_048_576
    stdin_mode: str = "pipe"


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    unit: str
    cgroup: str
    pid: int
    start_ticks: int
    executable_sha256: str
    pidfd: int
    executable_device: int = 0
    executable_inode: int = 0
    mount_namespace_inode: int = 0
    network_namespace_inode: int = 0
    uid: int = 0
    gid: int = 0
    process_id: str = ""
    generation: str = ""
    kernel_limits: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class ChildIdentity:
    role: str
    pid: int
    start_ticks: int
    parent_pid: int
    executable_sha256: str
    cgroup: str
    pidfd: int
    executable_device: int = 0
    executable_inode: int = 0


def provision_service_identity(owned_root: OwnedRoot, journal: Journal, profile_id: str,
                              operation: str) -> tuple[str, int, int]:
    """Create or verify the fixed non-login UID bound to one private profile.

    Existing account names are accepted only when the durable installer journal
    already records ownership. No account gets a shell, home directory, or
    supplemental groups.
    """
    if not isinstance(owned_root, OwnedRoot) or not isinstance(journal, Journal):
        raise ManagedProcessError("profile identity provisioning requires durable owned state")
    if not isinstance(profile_id, str) or not profile_id or len(profile_id) > 256:
        raise ManagedProcessError("profile identity is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation):
        raise ManagedProcessError("profile identity operation is invalid")
    username = "hermes-" + hashlib.sha256(profile_id.encode("utf-8")).hexdigest()[:16]
    registered = any(item["resource_id"] == username and item["state"] == "active"
                     for item in journal.owned("service-user"))
    try:
        account = pwd.getpwnam(username)
    except KeyError:
        account = None
    created = False
    if account is None:
        sudo = shutil.which("sudo", path="/usr/bin:/bin")
        useradd = shutil.which("useradd", path="/usr/sbin:/usr/bin:/bin")
        if sudo is None or useradd is None:
            raise ManagedProcessError("privileged profile identity provisioning is unavailable")
        completed = subprocess.run(
            [sudo, "-n", useradd, "--system", "--no-create-home",
             "--home-dir=/nonexistent", "--shell=/usr/sbin/nologin",
             "--user-group", username],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C"}, close_fds=True,
            timeout=5, check=False,
        )
        if completed.returncode != 0:
            raise ManagedProcessError("dedicated profile identity could not be provisioned")
        created = True
        try:
            account = pwd.getpwnam(username)
        except KeyError:
            raise ManagedProcessError("new profile identity is missing from NSS") from None
    if not created and not registered:
        raise ManagedProcessError("unrecorded existing account conflicts with the installer identity")
    assert account is not None
    if (account.pw_uid in {0, os.getuid()} or account.pw_gid in {0}
            or account.pw_dir != "/nonexistent" or account.pw_shell != "/usr/sbin/nologin"
            or os.getgrouplist(username, account.pw_gid) != [account.pw_gid]):
        raise ManagedProcessError("profile account is not an isolated non-login identity")
    journal.record_owned("service-user", username, "active")
    journal.checkpoint(operation, "identity-ready", {
        "service_user": username, "uid": account.pw_uid, "gid": account.pw_gid,
    })
    return username, account.pw_uid, account.pw_gid


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


def _privileged_output(arguments: Sequence[str], *, limit: int = 65536,
                       timeout: float = 1.5) -> bytes:
    """Run only fixed read-only system tools through noninteractive sudo."""
    sudo = shutil.which("sudo", path="/usr/bin:/bin")
    if sudo is None or not 1 <= limit <= 131072 or not 0 < timeout <= 3:
        raise ManagedProcessError("root process observation is unavailable")
    try:
        completed = subprocess.run(
            [sudo, "-n", *arguments], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            close_fds=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ManagedProcessError("bounded root process observation failed") from None
    if completed.returncode != 0 or len(completed.stdout) > limit:
        raise ManagedProcessError("root process observation was denied or exceeded its bound")
    return completed.stdout


def _proc_executable_identity(pid: int) -> tuple[str, int, int]:
    path = f"/proc/{pid}/exe"
    stat_tool = shutil.which("stat", path="/usr/bin:/bin")
    sha_tool = shutil.which("sha256sum", path="/usr/bin:/bin")
    if not stat_tool or not sha_tool:
        raise ManagedProcessError("pinned process inspection tools are unavailable")
    before = _privileged_output([stat_tool, "-Lc", "%d:%i", path], limit=128).decode("ascii").strip()
    raw = _privileged_output([sha_tool, path], limit=256).decode("ascii").split()
    after = _privileged_output([stat_tool, "-Lc", "%d:%i", path], limit=128).decode("ascii").strip()
    if not re.fullmatch(r"[0-9]+:[0-9]+", before) or before != after or not raw or not re.fullmatch(r"[0-9a-f]{64}", raw[0]):
        raise ManagedProcessError("process executable changed during inspection")
    device, inode = (int(value) for value in before.split(":"))
    return raw[0], device, inode


def _proc_inode(pid: int, namespace: str) -> int:
    if namespace not in {"mnt", "net", "user", "pid"}:
        raise ValueError("unsupported namespace")
    tool = shutil.which("stat", path="/usr/bin:/bin")
    if not tool:
        raise ManagedProcessError("namespace inspection tool is unavailable")
    raw = _privileged_output([tool, "-Lc", "%i", f"/proc/{pid}/ns/{namespace}"], limit=128).decode("ascii").strip()
    if not raw.isdigit():
        raise ManagedProcessError("namespace identity cannot be read")
    return int(raw)


def _protected_home_is_empty(pid: int) -> bool:
    tool = shutil.which("find", path="/usr/bin:/bin")
    if not tool:
        raise ManagedProcessError("home isolation probe is unavailable")
    result = _privileged_output(
        [tool, f"/proc/{pid}/root/home", "-mindepth", "1", "-maxdepth", "1", "-print", "-quit"],
        limit=4096, timeout=1.5,
    )
    return not result.strip()

def _observe_process_identity(pid: int, expected_cgroup: str) -> tuple[int, int, str, int, int, int]:
    pidfd = os.pidfd_open(pid, 0)
    try:
        parent, ticks = _proc_stat(pid)
        if _proc_cgroup(pid) != expected_cgroup:
            raise ManagedProcessError("process is outside the manager-owned cgroup")
        digest, device, inode = _proc_executable_identity(pid)
        if (_proc_stat(pid)[1] != ticks or _proc_cgroup(pid) != expected_cgroup
                or _pidfd_exited(pidfd)):
            raise ManagedProcessError("process identity changed during observation")
        return parent, ticks, digest, device, inode, pidfd
    except BaseException:
        os.close(pidfd)
        raise


def _observe_process(pid: int, expected_cgroup: str) -> tuple[int, int, str, int]:
    """Compatibility view for callers that do not need the pinned inode tuple."""
    parent, ticks, digest, _device, _inode, pidfd = _observe_process_identity(pid, expected_cgroup)
    return parent, ticks, digest, pidfd


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
    """Minimal sudo client environment; never forwards desktop or credential state."""
    if not sys_platform_linux():
        raise ManagedProcessError("managed services require Linux systemd")
    return {"PATH": "/usr/bin:/bin", "LANG": "C"}


def sys_platform_linux() -> bool:
    return os.name == "posix" and Path("/proc/self/cgroup").exists()


async def _systemctl_async(*args: str, timeout: float = 2.0) -> str:
    path = shutil.which("systemctl", path="/usr/bin:/bin")
    sudo = shutil.which("sudo", path="/usr/bin:/bin")
    if path is None or sudo is None:
        raise ManagedProcessError("system service control is unavailable")
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            sudo, "-n", path, "--system", *args, stdin=asyncio.subprocess.DEVNULL,
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
    if prop not in {"ControlGroup", "MainPID", "ActiveState", "SubState", "Description", "RuntimeMaxUSec", "KillMode", "ProtectSystem", "ProtectHome", "PrivateTmp", "PrivateDevices", "NoNewPrivileges", "IPAddressDeny", "PrivateNetwork", "RestrictAddressFamilies", "ProtectProc", "ProcSubset", "User", "MemoryMax", "CPUQuotaPerSecUSec", "IOWeight"}:
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


def _parse_systemd_timespan_us(value: str) -> int:
    """Parse the finite human timespan returned for RuntimeMaxUSec."""
    if not value or value.lower() in {"infinity", "infinite", "max"}:
        raise ManagedProcessError("manager returned a non-finite lifetime")
    if value.isdigit():
        return int(value)
    scales = {"us": 1, "usec": 1, "µs": 1, "ms": 1_000, "msec": 1_000,
              "s": 1_000_000, "sec": 1_000_000, "min": 60_000_000,
              "h": 3_600_000_000, "d": 86_400_000_000, "w": 604_800_000_000}
    matches = re.findall(r"([0-9]+(?:\\.[0-9]+)?)\\s*(usec|msec|µs|us|ms|min|sec|s|h|d|w)", value)
    residue = re.sub(r"[0-9]+(?:\\.[0-9]+)?\\s*(?:usec|msec|µs|us|ms|min|sec|s|h|d|w)\\s*", "", value)
    if not matches or residue:
        raise ManagedProcessError("manager returned an unsupported lifetime format")
    total = sum(float(number) * scales[unit] for number, unit in matches)
    if not total.is_integer() or total <= 0:
        raise ManagedProcessError("manager returned an invalid lifetime")
    return int(total)


def _verify_cgroup_limits(cgroup: str, spec: ManagedProcessSpec) -> None:
    root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    try:
        if spec.memory_max_bytes is not None:
            observed = (root / "memory.max").read_text().strip()
            if observed != str(spec.memory_max_bytes):
                raise ManagedProcessError("kernel memory.max does not match the requested bound")
        if spec.cpu_quota_percent is not None:
            quota, period = (root / "cpu.max").read_text().split()
            if quota == "max" or int(quota) * 100 != spec.cpu_quota_percent * int(period):
                raise ManagedProcessError("kernel cpu.max does not match the requested quota")
        if spec.io_weight is not None:
            fields = (root / "io.weight").read_text().split()
            if not fields or int(fields[-1]) != spec.io_weight:
                raise ManagedProcessError("kernel io.weight does not match the requested bound")
    except (OSError, ValueError, IndexError):
        raise ManagedProcessError("requested kernel resource-control files are unavailable") from None


def _validate_spec(spec: ManagedProcessSpec) -> tuple[OwnedRoot, Path, Path, Path, Path]:
    if not isinstance(spec.owned_root, OwnedRoot) or not isinstance(spec.journal, Journal):
        raise ManagedProcessError("managed processes require an OwnedRoot and durable Journal")
    try:
        root = spec.owned_root.root.resolve(strict=True)
        cwd = spec.owned_root.path(Path(spec.cwd).relative_to(root).as_posix()).resolve(strict=True)
        data = spec.owned_root.path(Path(spec.data_root).relative_to(root).as_posix()).resolve(strict=True)
        journal_path = spec.journal.path.resolve(strict=True)
    except (OwnershipError, OSError, ValueError):
        raise ManagedProcessError("executable, cwd, data root, or journal is outside safe owned paths") from None
    try:
        exe = Path(spec.executable).resolve(strict=True)
        artifact = Path(spec.artifact_root).resolve(strict=True)
    except OSError:
        raise ManagedProcessError("pinned executable or protected artifact catalog is missing") from None
    if not (root.is_dir() and exe.is_file() and artifact.is_dir() and cwd.is_dir() and data.is_dir()):
        raise ManagedProcessError("owned roots, pinned artifact root and working directory must exist")
    if not cwd.is_relative_to(data) or not journal_path.is_relative_to(root):
        raise ManagedProcessError("working directory and journal must remain inside the owned profile root")
    for protected in (exe, artifact):
        cursor = Path(protected.anchor)
        for part in protected.parts[1:]:
            cursor /= part
            info = cursor.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ManagedProcessError("pinned executable and artifact catalog cannot traverse symlinks")
    info = root.lstat()
    marker = root / ".hermes-installer-owned"
    try:
        marker_info = marker.lstat()
        marker_content = marker.read_bytes()
    except OSError:
        raise ManagedProcessError("owned root marker is missing or unreadable") from None
    if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
            or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid()
            or stat.S_IMODE(marker_info.st_mode) & 0o077
            or marker_content != b"schema=1\n"):
        raise ManagedProcessError("owned root is not private or its marker is invalid")
    if not os.access(exe, os.X_OK) or not re.fullmatch(r"[0-9a-f]{64}", spec.artifact_sha256):
        raise ManagedProcessError("executable pin is invalid")
    if _digest(exe) != spec.artifact_sha256:
        raise ManagedProcessError("executable does not match its reviewed artifact pin")
    exe_info = exe.stat(follow_symlinks=False)
    if not stat.S_ISREG(exe_info.st_mode) or exe_info.st_nlink != 1:
        raise ManagedProcessError("pinned executable must be a single-link regular file")
    for store_id, digest in (spec.child_artifact_refs or {}).items():
        if (not isinstance(store_id, str) or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", store_id)
                or store_id.rsplit(":", 1)[-1] != digest):
            raise ManagedProcessError("child artifact reference is malformed")
    if any(arg.startswith("artifact:") and arg not in (spec.child_artifact_refs or {})
           for arg in spec.argv):
        raise ManagedProcessError("argv contains an unenrolled opaque artifact reference")
    if not spec.argv or spec.argv[0] != str(exe) or any(not isinstance(x, str) or "\x00" in x for x in spec.argv):
        raise ManagedProcessError("argv must start with the pinned executable and contain NUL-free strings")
    if any(re.search(r"(?i)(?:--?(?:token|secret|password|api[-_]?key|credential)(?:=|$)|authorization:\s*bearer\s+)", value)
           for value in spec.argv[1:]):
        raise ManagedProcessError("secret-bearing command arguments are not accepted")
    if (not re.fullmatch(r"[A-Za-z0-9_.:-]{1,256}", spec.profile_id)
            or spec.profile_id in {".", ".."}):
        raise ManagedProcessError("profile identity is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", spec.journal_operation):
        raise ManagedProcessError("journal operation id is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", spec.service_identity):
        raise ManagedProcessError("service identity is invalid")
    if not re.fullmatch(r"hermes-[a-z0-9-]{1,40}", spec.service_user):
        raise ManagedProcessError("service user must be a dedicated installer identity")
    expected_user = "hermes-" + hashlib.sha256(spec.profile_id.encode("utf-8")).hexdigest()[:16]
    if spec.service_user != expected_user:
        raise ManagedProcessError("service UID does not match the authorized profile identity")
    now = time.monotonic()
    if not now < spec.startup_deadline_monotonic <= now + 600:
        raise ManagedProcessError("startup deadline must be an absolute bounded monotonic time")
    if (isinstance(spec.max_lifetime_seconds, bool) or not isinstance(spec.max_lifetime_seconds, (int, float))
            or not math.isfinite(spec.max_lifetime_seconds) or not 0 < spec.max_lifetime_seconds <= 600):
        raise ManagedProcessError("manager-enforced process lifetime must be finite and at most ten minutes")
    if spec.memory_max_bytes is not None and (type(spec.memory_max_bytes) is not int
                                               or not 16 * 1024 * 1024 <= spec.memory_max_bytes <= 64 * 1024**3):
        raise ManagedProcessError("memory cgroup limit is outside supported bounds")
    if spec.cpu_quota_percent is not None and (type(spec.cpu_quota_percent) is not int
                                                or not 1 <= spec.cpu_quota_percent <= 10_000):
        raise ManagedProcessError("CPU cgroup quota is outside supported bounds")
    if spec.io_weight is not None and (type(spec.io_weight) is not int or not 1 <= spec.io_weight <= 10_000):
        raise ManagedProcessError("I/O cgroup weight is outside supported bounds")
    allowed = {"HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY",
               "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HERMES_HOME", "TMPDIR"}
    for key, value in spec.env_allowlist.items():
        if key not in allowed or not isinstance(value, str) or "\x00" in value or len(value) > 1024:
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
    """Brokered handle to a root-owned process record and cgroup."""
    def __init__(self, spec: ManagedProcessSpec, authority: AuthorityClient,
                 identity: ProcessIdentity, generation: str, started: float, expires: float):
        self.spec, self.identity = spec, identity
        self.authority, self.generation = authority, generation
        self.unit, self.cgroup = identity.unit, identity.cgroup
        self._started, self._expires = started, expires
        self._closed = False
        self._stdout_cursor = 0
        self._stderr_cursor = 0
        self._stdin_cursor = 0
        self._exit_code: int | None = None
        self._eof = {"stdout": False, "stderr": False}
        self._watchdog = asyncio.create_task(self._enforce_lifetime())

    async def __aenter__(self) -> "ManagedProcessHandle":
        await self._check_live()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await asyncio.shield(self.stop("operation complete" if exc is None else "operation failed"))

    async def _enforce_lifetime(self) -> None:
        await asyncio.sleep(max(0.0, self._expires - time.monotonic()))
        if not self._closed:
            await self.stop("bounded lifetime expired", timeout=5.0)

    def _control_sync(self, operation: str, fields: Mapping[str, object], timeout: float) -> dict[str, object]:
        payload = json.dumps({"schema": 1, "process_id": self.identity.process_id,
                              "generation": self.generation, **fields},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        context = self.authority.context(
            purpose="managed-process-control", intent=f"{operation}:{self.identity.pid}:{self.generation}",
            source_contexts=(self.spec.authority_context,) if self.spec.authority_context else (),
            trace_id=self.spec.authority_context.trace_id if self.spec.authority_context else None,
            lease_seconds=min(5.0, max(.1, timeout)),
            final_payload_digest=canonical_digest(payload))
        verb = operation.removeprefix("process.")
        if verb not in {"status", "read", "write", "stop"}:
            raise ManagedProcessError("process control verb is not fixed")
        target = (f"hermes-profile-control:{self.spec.profile_id}:"
                  f"{Path(self.spec.data_root).resolve(strict=True)}:{verb}")
        grant = self.authority.authorize_effect(
            context, capability="hermes-process-control", target=target,
            request_digest=canonical_digest(payload), retry_index=0)
        response = self.authority.process_control(
            grant, operation=operation, target=target, payload=payload,
            timeout=min(5.0, max(.1, timeout)))
        if response.status != 200:
            raise ManagedProcessError("root process control denied the operation")
        try:
            result = json.loads(response.body.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ManagedProcessError("root process control returned a malformed receipt") from None
        if not isinstance(result, dict) or result.get("schema") != 1:
            raise ManagedProcessError("root process control returned an invalid receipt")
        return result

    async def _control(self, operation: str, fields: Mapping[str, object], timeout: float = 5.0) -> dict[str, object]:
        return await asyncio.to_thread(self._control_sync, operation, fields, timeout)

    async def _check_live(self) -> None:
        if self._closed or time.monotonic() >= self._expires:
            raise ManagedProcessError("managed process is closed or expired")
        result = await self._control("process.status", {})
        if result.get("state") != "running":
            self._exit_code = result.get("exit_code") if type(result.get("exit_code")) is int else None
            raise ManagedProcessError("managed process exited")

    async def snapshot_children(self) -> tuple[ChildIdentity, ...]:
        raise ManagedProcessError("root custodian exposes cgroup cleanup proof, not PID snapshots")

    async def read(self, maximum_bytes: int, timeout: float, *, stream: str = "stdout") -> bytes:
        if not 1 <= maximum_bytes <= 65536 or not 0 <= timeout <= 30 or stream not in {"stdout", "stderr"}:
            raise ValueError("read bounds or stream are invalid")
        if self._closed or time.monotonic() >= self._expires:
            raise ManagedProcessError("managed process is closed or expired")
        cursor = self._stdout_cursor if stream == "stdout" else self._stderr_cursor
        result = await self._control("process.read", {"stream": stream, "after_cursor": cursor,
                                                       "max_bytes": maximum_bytes}, timeout=max(1.0, timeout))
        try:
            data = base64.b64decode(result["data"], validate=True)
            new_cursor = int(result["cursor"])
        except Exception:
            raise ManagedProcessError("root process stream receipt is malformed") from None
        if new_cursor != cursor + len(data):
            raise ManagedProcessError("root process stream cursor is inconsistent")
        if stream == "stdout":
            self._stdout_cursor = new_cursor
        else:
            self._stderr_cursor = new_cursor
        self._eof[stream] = bool(result.get("eof", False))
        return data

    async def write(self, data: bytes, timeout: float) -> int:
        if not isinstance(data, bytes) or len(data) > 1_048_576 or not 0 <= timeout <= 30:
            raise ValueError("write bounds are invalid")
        await self._check_live()
        deadline, written = time.monotonic() + timeout, 0
        while written < len(data) and time.monotonic() < deadline:
            chunk = data[written:written + 65536]
            result = await self._control("process.write", {
                "stdin_cursor": self._stdin_cursor,
                "data": base64.b64encode(chunk).decode("ascii"),
            }, timeout=max(.1, min(5.0, deadline - time.monotonic())))
            count = result.get("bytes_written")
            cursor = result.get("stdin_cursor")
            if type(count) is not int or not 0 <= count <= len(chunk) or cursor != self._stdin_cursor + count:
                raise ManagedProcessError("root stdin receipt is inconsistent")
            self._stdin_cursor = int(cursor)
            written += count
            if count == 0:
                await asyncio.sleep(.01)
        return written

    async def wait(self, timeout: float) -> int | None:
        if not 0 <= timeout <= 600:
            raise ValueError("wait bound is invalid")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = await self._control("process.status", {}, timeout=min(5.0, max(.1, deadline-time.monotonic())))
            if result.get("state") != "running":
                code = result.get("exit_code")
                self._exit_code = code if type(code) is int else None
                return self._exit_code
            await asyncio.sleep(min(.2, max(0, deadline-time.monotonic())))
        return None

    async def stop(self, reason: str, timeout: float = 5.0) -> None:
        if not reason or len(reason) > 160 or not 0 < timeout <= 10:
            raise ValueError("stop reason or bound is invalid")
        if self._closed:
            return
        if asyncio.current_task() is not self._watchdog:
            self._watchdog.cancel()
        try:
            result = await asyncio.shield(self._control("process.stop", {}, timeout=timeout))
            if result.get("stopped") is not True or result.get("cleanup_verified") is not True:
                raise ManagedProcessError("root custodian did not prove process cleanup")
            await asyncio.to_thread(self.spec.journal.checkpoint, self.spec.journal_operation,
                                    "stopped", {"unit": self.unit, "cgroup": self.cgroup,
                                    "pid": self.identity.pid, "start_ticks": self.identity.start_ticks,
                                    "process_id": self.identity.process_id, "generation": self.generation,
                                    "executable_sha256": self.identity.executable_sha256,
                                    "executable_device": self.identity.executable_device,
                                    "executable_inode": self.identity.executable_inode,
                                    "mount_namespace_inode": self.identity.mount_namespace_inode,
                                    "network_namespace_inode": self.identity.network_namespace_inode,
                                    "uid": self.identity.uid, "gid": self.identity.gid,
                                    "kernel_limits": dict(self.identity.kernel_limits or {}),
                                    "reason": reason[:160], "cleanup_verified": True})
            self._closed = True
        except BaseException:
            with contextlib.suppress(BaseException):
                await asyncio.shield(asyncio.to_thread(self.spec.journal.checkpoint,
                    self.spec.journal_operation, "cleanup-failed", {"unit": self.unit,
                    "cgroup": self.cgroup, "process_id": self.identity.process_id}))
            raise


class ManagedProcessSupervisor:
    """Client of the root-owned fixed process.start and process-control verbs."""
    def __init__(self, authority_verifier: AuthorityClient | None = None):
        self.authority_verifier = authority_verifier

    async def start(self, spec: ManagedProcessSpec) -> ManagedProcessHandle:
        authority = self.authority_verifier
        if (not isinstance(authority, AuthorityClient) or not isinstance(spec.authority_context, HostContext)
                or not isinstance(spec.effect_authorization, EffectAuthorization)):
            raise ManagedProcessError("trusted host context, effect grant and authority client are required")
        if spec.authority_context.uid != os.geteuid() or spec.authority_context.profile_id != spec.profile_id:
            raise ManagedProcessError("host context does not identify this caller and exact profile")
        owned, exe, artifact, cwd, data = _validate_spec(spec)
        if type(spec.max_output_bytes) is not int or not 1 <= spec.max_output_bytes <= 4 * 1024 * 1024:
            raise ManagedProcessError("root process output limit is invalid")
        if spec.stdin_mode not in {"closed", "pipe"}:
            raise ManagedProcessError("root process stdin mode is invalid")
        target = canonical_profile_target(spec.profile_id, exe, data)
        launch = profile_launch_envelope(
            target=target, profile_id=spec.profile_id, executable=exe,
            artifact_sha256=spec.artifact_sha256, artifact_root=artifact, cwd=cwd,
            data_root=data, argv=spec.argv, env_allowlist=spec.env_allowlist,
            child_artifact_refs=spec.child_artifact_refs,
            max_lifetime_seconds=spec.max_lifetime_seconds,
            max_output_bytes=spec.max_output_bytes, stdin_mode=spec.stdin_mode,
        )
        digest = canonical_digest(launch)
        if spec.authority_context.final_payload_digest != digest:
            raise ManagedProcessError("host context does not bind the canonical process launch payload")
        grant = spec.effect_authorization
        if (grant.capability != "hermes-profile-invoke" or grant.target != target
                or grant.profile_id != spec.profile_id or grant.uid != spec.authority_context.uid
                or grant.request_digest != digest or grant.retry_index != 0):
            raise ManagedProcessError("host start grant does not match the canonical launch envelope")
        try:
            await asyncio.to_thread(spec.journal.checkpoint, spec.journal_operation, "starting", {
                "service_identity": spec.service_identity, "artifact_sha256": spec.artifact_sha256,
                "max_lifetime_seconds": spec.max_lifetime_seconds,
            })
            cancelled = threading.Event()
            try:
                response = await asyncio.to_thread(
                    authority.process_start, grant, target=target, launch=launch,
                    timeout=min(10.0, max(.1, spec.startup_deadline_monotonic - time.monotonic())),
                    cancelled=cancelled.is_set)
            except asyncio.CancelledError:
                cancelled.set()
                raise
            if response.status != 200:
                raise ManagedProcessError("root process custodian denied activation")
            receipt = json.loads(response.body.decode("ascii"))
            required = {"schema", "process_id", "pid", "uid", "gid", "namespace_id", "generation",
                        "started_at_monotonic", "stdout_cursor", "stderr_cursor", "expires_at_monotonic",
                        "cgroup", "start_ticks", "executable_device", "executable_inode",
                        "mount_namespace_inode", "network_namespace_inode", "kernel_limits"}
            if not isinstance(receipt, dict) or not required.issubset(receipt) or receipt.get("schema") != 1:
                raise ManagedProcessError("root process custodian receipt is malformed")
            identity = ProcessIdentity(
                unit=str(receipt.get("unit", "root-custodian")), cgroup=str(receipt["cgroup"]),
                pid=int(receipt["pid"]), start_ticks=int(receipt["start_ticks"]),
                executable_sha256=spec.artifact_sha256, pidfd=-1,
                executable_device=int(receipt["executable_device"]), executable_inode=int(receipt["executable_inode"]),
                mount_namespace_inode=int(receipt["mount_namespace_inode"]),
                network_namespace_inode=int(receipt["network_namespace_inode"]),
                uid=int(receipt["uid"]), gid=int(receipt["gid"]),
                process_id=str(receipt["process_id"]), generation=str(receipt["generation"]),
                kernel_limits=dict(receipt["kernel_limits"]))
            if (identity.uid == 0 or identity.gid == 0 or identity.generation == ""
                    or identity.executable_device != exe.stat().st_dev or identity.executable_inode != exe.stat().st_ino):
                raise ManagedProcessError("root process receipt does not match pinned executable identity")
            if not isinstance(receipt["kernel_limits"], dict):
                raise ManagedProcessError("root process cgroup readback is malformed")
            spec.journal.record_owned("managed-systemd-service", identity.process_id, "active")
            await asyncio.to_thread(spec.journal.checkpoint, spec.journal_operation, "running", {
                "process_id": identity.process_id, "generation": identity.generation,
                "unit": identity.unit, "cgroup": identity.cgroup, "pid": identity.pid,
                "start_ticks": identity.start_ticks, "executable_sha256": identity.executable_sha256,
                "executable_device": identity.executable_device, "executable_inode": identity.executable_inode,
                "mount_namespace_inode": identity.mount_namespace_inode,
                "network_namespace_inode": identity.network_namespace_inode,
                "uid": identity.uid, "gid": identity.gid,
                "kernel_limits": dict(identity.kernel_limits or {}),
            })
            handle = ManagedProcessHandle(spec, authority, identity, identity.generation,
                                          float(receipt["started_at_monotonic"]), float(receipt["expires_at_monotonic"]))
            return handle
        except asyncio.CancelledError:
            raise
        except ManagedProcessError:
            raise
        except BaseException:
            await asyncio.to_thread(spec.journal.checkpoint, spec.journal_operation,
                                    "start-failed", {"service_identity": spec.service_identity,
                                    "reason": "root process start or receipt validation failed"})
            raise ManagedProcessError("root process start failed or returned invalid evidence") from None

    @staticmethod
    def close_child_snapshot(children: Sequence[ChildIdentity]) -> None:
        # Child PIDs are descriptions only; cleanup stays with the root cgroup owner.
        return None


async def run_managed_process(spec: ManagedProcessSpec, *, timeout: float,
                              stdout_limit: int = 65536, stderr_limit: int = 65536,
                              input_bytes: bytes = b"",
                              authority_verifier: AuthorityClient | None = None) -> ManagedProcessResult:
    """Run through the root fixed-verb broker with bounded independent streams."""
    if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout) or not 0 < timeout <= 600
            or not 0 <= stdout_limit <= 1_048_576 or not 0 <= stderr_limit <= 1_048_576
            or not isinstance(input_bytes, bytes) or len(input_bytes) > 1_048_576
            or stdout_limit + stderr_limit > spec.max_output_bytes):
        raise ValueError("managed command bounds are invalid")
    if input_bytes and spec.stdin_mode != "pipe":
        raise ValueError("input bytes require pipe stdin mode")
    handle = await ManagedProcessSupervisor(authority_verifier).start(spec)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    caps = {"stdout": stdout_limit, "stderr": stderr_limit}
    deadline = time.monotonic() + timeout
    try:
        if input_bytes:
            written = await handle.write(input_bytes, min(30.0, max(0.0, deadline-time.monotonic())))
            if written != len(input_bytes):
                raise ManagedProcessError("managed command did not accept its bounded input")
        while time.monotonic() < deadline:
            for name in ("stdout", "stderr"):
                if handle._eof[name]:
                    continue
                block = await handle.read(min(65536, max(1, caps[name] - len(buffers[name]) + 1)),
                                          timeout=min(.2, max(.01, deadline-time.monotonic())), stream=name)
                buffers[name].extend(block)
                if len(buffers[name]) > caps[name]:
                    raise ManagedProcessError(f"managed {name} exceeded its output bound")
            code = await handle.wait(min(.01, max(.001, deadline-time.monotonic())))
            if code is not None and all(handle._eof.values()):
                break
            await asyncio.sleep(.01)
        else:
            await asyncio.shield(handle.stop("managed command deadline", timeout=5.0))
            return _managed_result(handle, None, buffers, timed_out=True)
        status = await handle._control("process.status", {})
        code = status.get("exit_code")
        await asyncio.shield(handle.stop("managed command completed", timeout=5.0))
        return _managed_result(handle, code if type(code) is int else None, buffers, timed_out=False)
    except asyncio.CancelledError:
        if not handle._closed:
            await asyncio.shield(handle.stop("managed command cancelled", timeout=5.0))
        raise
    except BaseException:
        if not handle._closed:
            await asyncio.shield(handle.stop("managed command failed", timeout=5.0))
        raise

def _managed_result(handle: ManagedProcessHandle, exit_code: int | None,
                    buffers: Mapping[str, bytearray], *, timed_out: bool) -> ManagedProcessResult:
    identity = handle.identity
    return ManagedProcessResult(exit_code, bytes(buffers["stdout"]), bytes(buffers["stderr"]),
                                timed_out, False, handle._closed, handle.unit, handle.cgroup,
                                identity.pid, identity.start_ticks, identity.executable_device,
                                identity.executable_inode, identity.mount_namespace_inode,
                                identity.network_namespace_inode, identity.uid, identity.gid,
                                handle.spec.memory_max_bytes, handle.spec.cpu_quota_percent,
                                handle.spec.io_weight, identity.process_id, identity.generation,
                                dict(identity.kernel_limits or {}))
