"""Read-only root witness for the fixed core-mode Gateway and backend."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .core_gateway import (
    CORE_CONFIG, CORE_GATEWAY_UNIT, CORE_GATEWAY_UNIT_PATH, CORE_HOST, CORE_INGRESS_SOCKET,
    CORE_INSPECTOR_SOCKET, CORE_PORT, CORE_SERVICE_UNIT, GATEWAY_ARGV, GATEWAY_EXECUTABLE,
    CoreGatewayConfig, CoreGatewayDenied,
)

TUNNEL_UNIT = "hermes-jarvis-mvp-tunnel.service"
TUNNEL_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-mvp-tunnel.service")
TUNNEL_EXECUTABLE = Path("/usr/bin/cloudflared")
TUNNEL_ARGV = ("/usr/bin/cloudflared", "--no-autoupdate", "tunnel", "run", "--token-file",
               "/run/credentials/hermes-jarvis-mvp-tunnel.service/tunnel-token")
CORE_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-core.service")
CORE_LAUNCHER = Path("/usr/local/libexec/hermes-jarvis-core-launcher")
CORE_PYTHON_LINK = Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
CORE_PYTHON_REAL = Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")
CORE_PYTHON_LINK_TARGET = "/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3"
CORE_ARGV_TAIL = ("-m", "hermes_cli.main", "serve", "--isolated", "--host",
                  CORE_HOST, "--port", str(CORE_PORT))
CORE_TOKEN_SOURCE = Path("/etc/hermes-installer/jarvis-core/session-token")
CORE_SOURCE = Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
CORE_SOURCE_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
CORE_SOURCE_FILES = {
    "pm/lock.json": "49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549",
    "uv.lock": "2bc4db483e9cba927cd7147f9ccbb09635f85bb3f1f36d6e9d51d06b65d1c67e",
    "pyproject.toml": "cadde2f6a92574d292103f43abf66408b1d841cd9ea332ca7f3e3dfc5dcc87fd",
    "hermes_cli/web_server.py": "839ee3fa8d9548c9e1875ffe1321e287eda37c3577e607dcd93288621b0403a4",
    "tui_gateway/ws.py": "1cecdb714a0abc1edf8fc0ec2d00edc1dc042f0da37baaefb8ba20ce3edeae63",
}
CORE_PYVENV_CFG_SHA256 = "d982d4b71a70c99f49afef3c0b2cf683c2f053a802da8885d366657b9565f1ad"
CORE_PYTHON_SHA256 = "566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001"
CORE_WORKSPACE = Path("/home/admin/.hermes/workspaces/jarvis-core")
CORE_PATH = "/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin"
CORE_CREDENTIALS_DIRECTORY = "/run/credentials/hermes-jarvis-core.service"
MAX_REQUEST = 1024
MAX_RESPONSE = 4096
MAX_OUTPUT = 16_384
MAX_HASH_FILE_BYTES = 512 * 1024 * 1024
MAX_PROOF_SECONDS = 5.0
IPC_TIMEOUT = 2.0
_PROOF_SEAL = object()
_OVERVIEW_PROOF_SEAL = object()
_SERVER_SLOTS = threading.BoundedSemaphore(16)
_OBSERVATION_FIELDS = (
    "schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
    "peer_pid", "peer_uid", "peer_gid", "peer_start_ticks", "tunnel_invocation_id",
    "tunnel_unit_sha256", "tunnel_executable_sha256", "origin_socket_device",
    "origin_socket_inode", "gateway_unit_sha256", "core_unit_sha256",
    "core_invocation_id", "core_pid", "core_start_ticks", "core_listener_inode",
    "core_source_generation",
    "core_generation", "config_sha256",
)


class CoreInspectionDenied(PermissionError):
    pass


def _observation_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-ingress-v1\0" + canonical).hexdigest()


def _overview_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-overview-v1\0" + canonical).hexdigest()


def _deny():
    raise CoreInspectionDenied("fixed core ingress observation denied")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _read_exact(conn: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        conn.settimeout(remaining)
        chunk = conn.recv(size - len(result))
        if not chunk:
            raise OSError("short IPC frame")
        result.extend(chunk)
    return bytes(result)


def _run_fixed(argv: tuple[str, ...], *, deadline: float, maximum: int) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=remaining, check=False, close_fds=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    if result.returncode != 0 or len(result.stdout) > maximum:
        raise ValueError("fixed observation command failed")
    return result.stdout


def _unit_properties(unit: str, *, deadline: float) -> dict[str, str]:
    allowed = {CORE_GATEWAY_UNIT, CORE_SERVICE_UNIT, TUNNEL_UNIT}
    if unit not in allowed:
        raise ValueError("unknown fixed unit")
    raw = _run_fixed(("/usr/bin/systemctl", "show", unit, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState",
        "--property=MainPID", "--property=ControlGroup", "--property=FragmentPath",
        "--property=User", "--property=Group", "--property=DynamicUser",
        "--property=SupplementaryGroups", "--property=DropInPaths",
        "--property=InvocationID"), deadline=deadline, maximum=8192)
    props = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        if "=" not in line:
            raise ValueError("malformed systemd output")
        key, value = line.split("=", 1)
        if key in props:
            raise ValueError("duplicate systemd property")
        props[key] = value
    if (props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
            or props.get("SubState") != "running" or props.get("DropInPaths") != ""
            or not re.fullmatch(r"[0-9a-fA-F-]{32,36}", props.get("InvocationID", ""))):
        _deny()
    return props


def _protected_file_sha(path: Path, *, owner_uid: int = 0, owner_gid: int | None = None,
                        exact_mode: int | None = None, deadline: float | None = None,
                        allow_owner_group_write: bool = False) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or (owner_gid is not None and info.st_gid != owner_gid)
                or (stat.S_IMODE(info.st_mode) & 0o002)
                or (not allow_owner_group_write and stat.S_IMODE(info.st_mode) & 0o020)
                or info.st_nlink != 1
                or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)
                or info.st_size > MAX_HASH_FILE_BYTES):
            raise ValueError("fixed file is not immutable root custody")
        digest = hashlib.sha256()
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("fixed file hash deadline expired")
            block = os.read(fd, 8192)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                  item.st_gid, item.st_nlink, item.st_size,
                                  item.st_mtime_ns, item.st_ctime_ns)
        if (signature(after) != signature(info) or signature(named) != signature(info)
                or (deadline is not None and time.monotonic() >= deadline)):
            raise ValueError("fixed file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _read_proc_environment(pid: int, *, deadline: float) -> dict[bytes, bytes]:
    env_fd = os.open(f"/proc/{pid}/environ", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        environment = bytearray()
        while len(environment) <= 1024 * 1024:
            if time.monotonic() >= deadline:
                raise TimeoutError("core environment deadline expired")
            block = os.read(env_fd, min(16_384, 1024 * 1024 + 1 - len(environment)))
            if not block:
                break
            environment.extend(block)
    finally:
        os.close(env_fd)
    if len(environment) > 1024 * 1024:
        _deny()
    result: dict[bytes, bytes] = {}
    # Convert the bounded mutable read buffer before splitting: bytearray keys are
    # unhashable and must never escape into the exact environment validator.
    for entry in bytes(environment).split(b"\0"):
        if not entry:
            continue
        key, sep, value = entry.partition(b"=")
        if not sep or key in result:
            _deny()
        result[key] = value
    return result


def _validate_core_process_environment(environment: dict[bytes, bytes], secret: bytes) -> None:
    token = environment.get(b"HERMES_DASHBOARD_SESSION_TOKEN")
    expected = {
        b"HOME": b"/home/admin",
        b"HERMES_HOME": b"/home/admin/.hermes",
        b"PATH": CORE_PATH.encode("ascii"),
        b"HERMES_DISABLE_LAZY_INSTALLS": b"1",
        b"PYTHONNOUSERSITE": b"1",
        b"PYTHONDONTWRITEBYTECODE": b"1",
        b"PYTHONPATH": str(CORE_SOURCE).encode("ascii"),
        b"CREDENTIALS_DIRECTORY": CORE_CREDENTIALS_DIRECTORY.encode("ascii"),
    }
    if (any(environment.get(key) != value for key, value in expected.items())
            or any(key in environment for key in (b"PYTHONHOME", b"PYTHONUSERBASE",
                                                   b"PYTHONSTARTUP", b"VIRTUAL_ENV"))
            or token is None or not secrets.compare_digest(token, secret)):
        _deny()


def _current_core_credential(pid: int, config: CoreGatewayConfig, *, deadline: float) -> None:
    """Join the protected backend token source to the live process privately."""
    parent = os.lstat(CORE_TOKEN_SOURCE.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_gid != config.gateway_gid or stat.S_IMODE(parent.st_mode) != 0o750):
        _deny()
    fd = os.open(CORE_TOKEN_SOURCE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o640
                or info.st_nlink != 1 or not 32 <= info.st_size <= 4097):
            _deny()
        secret = bytearray()
        while len(secret) <= 4097:
            if time.monotonic() >= deadline:
                raise TimeoutError("core credential deadline expired")
            block = os.read(fd, min(1024, 4098 - len(secret)))
            if not block:
                break
            secret.extend(block)
        after = os.fstat(fd)
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            _deny()
        if secret.endswith(b"\n"):
            secret = secret[:-1]
        if (not 32 <= len(secret) <= 4096
                or any(byte < 0x21 or byte > 0x7e for byte in secret)):
            _deny()
    finally:
        os.close(fd)
    # The value is neither returned, hashed into a public proof, nor logged.
    environment: dict[bytes, bytes] = {}
    try:
        environment = _read_proc_environment(pid, deadline=deadline)
        _validate_core_process_environment(environment, secret)
    finally:
        environment.clear()
        for index in range(len(secret)):
            secret[index] = 0


def _run_source_git(args: tuple[str, ...], *, deadline: float, maximum: int) -> bytes:
    argv = ("/usr/bin/git", "--no-optional-locks", "-c", f"safe.directory={CORE_SOURCE}",
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-C", str(CORE_SOURCE), *args)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, close_fds=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C",
             "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    assert proc.stdout is not None
    output = bytearray()
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                _deny()
            events = poller.poll(max(1, min(50, int(remaining * 1000))))
            if not events:
                if proc.poll() is not None:
                    break
                continue
            try:
                block = os.read(fd, min(4096, maximum + 1 - len(output)))
            except BlockingIOError:
                continue
            if not block:
                break
            output.extend(block)
            if len(output) > maximum:
                proc.kill()
                _deny()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining) != 0:
            _deny()
        return bytes(output)
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        proc.stdout.close()


def _current_core_source(config: CoreGatewayConfig, *, deadline: float) -> str:
    """Validate the exact selected official source/runtime closure without exporting paths."""
    try:
        info = os.lstat(CORE_SOURCE)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != config.core_uid
                or info.st_gid != config.core_gid or stat.S_IMODE(info.st_mode) & 0o002):
            _deny()
        git_info = os.lstat(CORE_SOURCE / ".git")
        if (not stat.S_ISDIR(git_info.st_mode) or git_info.st_uid != config.core_uid
                or git_info.st_gid != config.core_gid or stat.S_IMODE(git_info.st_mode) & 0o002):
            _deny()
        head = _run_source_git(("rev-parse", "--verify", "HEAD"), deadline=deadline, maximum=128)
        if head.strip().decode("ascii", "strict") != CORE_SOURCE_REVISION:
            _deny()
        dirty = _run_source_git(("status", "--porcelain=v1", "--untracked-files=all",
                                 "--ignore-submodules=none"), deadline=deadline, maximum=8192)
        if dirty:
            _deny()
        digests: list[str] = []
        for relative, expected in CORE_SOURCE_FILES.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("source file proof deadline expired")
            actual = _protected_file_sha(CORE_SOURCE / relative, owner_uid=config.core_uid,
                owner_gid=config.core_gid, exact_mode=0o664, deadline=deadline,
                allow_owner_group_write=True)
            if actual != expected:
                _deny()
            digests.append(actual)
        pyvenv = config.core_python.parent.parent / "pyvenv.cfg"
        actual_pyvenv = _protected_file_sha(pyvenv, owner_uid=config.core_uid,
            owner_gid=config.core_gid, deadline=deadline, allow_owner_group_write=True)
        if actual_pyvenv != CORE_PYVENV_CFG_SHA256 or config.core_python_sha256 != CORE_PYTHON_SHA256:
            _deny()
        closure = {"source_revision": CORE_SOURCE_REVISION,
                   "files": dict(zip(CORE_SOURCE_FILES, digests)),
                   "pyvenv_cfg_sha256": actual_pyvenv,
                   "python_sha256": CORE_PYTHON_SHA256}
        canonical = json.dumps(closure, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(b"hermes-jarvis-core-source-generation-v1\0" + canonical).hexdigest()
    except Exception:
        _deny()


def _proc_start_ticks(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    close = raw.rfind(")")
    fields = raw[close + 2:].split()
    if close < 0 or len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError("invalid process stat")
    return fields[19]


def _process(pid: int, *, uid: int, gid: int, argv: tuple[str, ...], executable: Path,
             executable_sha256: str, cgroup: str, deadline: float,
             supplementary_gid: int | None = None,
             executable_owner_uid: int = 0, executable_owner_gid: int | None = None,
             executable_mode: int | None = None) -> tuple[int, str]:
    if pid <= 1 or time.monotonic() >= deadline or not hasattr(os, "pidfd_open"):
        _deny()
    pidfd = os.pidfd_open(pid, 0)
    try:
        start = _proc_start_ticks(pid)
        status = Path(f"/proc/{pid}/status").read_text()
        fields = {}
        for line in status.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields[key] = value.strip().split()
        actual_uid = fields.get("Uid", [])
        actual_gid = fields.get("Gid", [])
        groups = fields.get("Groups", [])
        if (len(actual_uid) < 2 or len(actual_gid) < 2 or int(actual_uid[1]) != uid
                or int(actual_gid[1]) != gid
                or (supplementary_gid is not None and str(supplementary_gid) not in groups)):
            _deny()
        raw_argv = Path(f"/proc/{pid}/cmdline").read_bytes()
        actual_argv = tuple(item.decode("utf-8", "strict") for item in raw_argv.rstrip(b"\0").split(b"\0"))
        actual_executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        actual_cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        if (actual_argv != argv or actual_executable != executable
                or f"0::{cgroup}" not in actual_cgroup
                or _protected_file_sha(actual_executable, owner_uid=executable_owner_uid,
                    owner_gid=executable_owner_gid, exact_mode=executable_mode,
                    deadline=deadline) != executable_sha256
                or _proc_start_ticks(pid) != start):
            _deny()
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poll.poll(0):
            _deny()
        return pidfd, start
    except Exception:
        os.close(pidfd)
        raise


def _check_unit_process(config: CoreGatewayConfig, *, unit: str, pid: int, deadline: float,
                        peer_uid: int | None = None, peer_gid: int | None = None):
    props = _unit_properties(unit, deadline=deadline)
    main_pid = int(props.get("MainPID", "0"))
    if main_pid != pid or props.get("ControlGroup") != f"/system.slice/{unit}":
        _deny()
    if unit == CORE_GATEWAY_UNIT:
        path, expected_hash = CORE_GATEWAY_UNIT_PATH, config.gateway_unit_sha256
        exe, exe_hash, argv = GATEWAY_EXECUTABLE, config.gateway_python_sha256, (
            GATEWAY_ARGV[0], *GATEWAY_ARGV[1:])
        uid, gid, supplementary = config.gateway_uid, config.gateway_gid, None
        executable_owner = (0, None, None)
        if props.get("FragmentPath") != str(path) or props.get("User") != str(uid) or props.get("Group") != str(gid):
            _deny()
    elif unit == CORE_SERVICE_UNIT:
        path, expected_hash = CORE_UNIT_PATH, config.core_unit_sha256
        launcher_hash = _protected_file_sha(CORE_LAUNCHER, deadline=deadline)
        if launcher_hash != config.core_launcher_sha256:
            _deny()
        try:
            executable = config.core_python.resolve(strict=True)
        except OSError:
            _deny()
        if (config.core_python != CORE_PYTHON_LINK or executable != CORE_PYTHON_REAL
                or os.readlink(config.core_python) != CORE_PYTHON_LINK_TARGET):
            _deny()
        exe, exe_hash = executable, config.core_python_sha256
        argv = (str(config.core_python), *CORE_ARGV_TAIL)
        uid, gid, supplementary = config.core_uid, config.core_gid, None
        executable_owner = (config.core_uid, config.core_gid, 0o755)
        if (props.get("FragmentPath") != str(path) or props.get("User") != "admin"
                or props.get("Group") != str(config.core_gid)):
            _deny()
    elif unit == TUNNEL_UNIT:
        path, expected_hash = TUNNEL_UNIT_PATH, config.tunnel_unit_sha256
        exe, exe_hash, argv = TUNNEL_EXECUTABLE, config.cloudflared_binary_sha256, TUNNEL_ARGV
        uid, gid, supplementary = peer_uid, peer_gid, config.gateway_gid
        executable_owner = (0, None, None)
        if (props.get("FragmentPath") != str(path) or props.get("DynamicUser") != "yes"
                or props.get("SupplementaryGroups") != str(config.gateway_gid)):
            _deny()
    else:
        _deny()
    if _protected_file_sha(path, deadline=deadline) != expected_hash:
        _deny()
    try:
        pidfd, start = _process(main_pid, uid=uid, gid=gid, argv=argv, executable=exe,
            executable_sha256=exe_hash, cgroup=props["ControlGroup"], deadline=deadline,
            supplementary_gid=supplementary, executable_owner_uid=executable_owner[0],
            executable_owner_gid=executable_owner[1], executable_mode=executable_owner[2])
        return pidfd, start, props["InvocationID"]
    except Exception:
        raise


def _socket_identity(path: Path, config: CoreGatewayConfig) -> tuple[int, int]:
    if path != CORE_INGRESS_SOCKET:
        _deny()
    parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            info = os.fstat(next_fd)
            target = component == path.parent.name
            if (not stat.S_ISDIR(info.st_mode)
                    or (target and (info.st_uid != config.gateway_uid or info.st_gid != config.gateway_gid
                                    or stat.S_IMODE(info.st_mode) != 0o750))
                    or (not target and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022))):
                os.close(next_fd)
                _deny()
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_PATH | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != config.gateway_uid
                    or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
                _deny()
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _core_listener_inode(pid: int) -> int:
    target = f"{CORE_PORT:04X}"
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) > 9 and parts[1] == f"0100007F:{target}" and parts[3] == "0A":
            inodes.add(parts[9])
    if len(inodes) != 1:
        _deny()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", link)
        if match and match.group(1) in inodes:
            return int(match.group(1))
    _deny()


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        _deny()
    return value


def _config_current(config: CoreGatewayConfig) -> CoreGatewayConfig:
    if type(config) is not CoreGatewayConfig:
        _deny()
    current = CoreGatewayConfig.load(expected_owner_uid=0)
    if current.config_sha256 != config.config_sha256 or current.boot_id != config.boot_id:
        _deny()
    return current


def observe_current_ingress(config: CoreGatewayConfig, *, nonce: str, caller_pid: int,
                            caller_uid: int, caller_gid: int, peer_pid: int,
                            peer_uid: int, peer_gid: int, _issued: float | None = None,
                            _deadline: float | None = None,
                            _projection_factory: Any = None) -> dict[str, Any]:
    issued = time.monotonic() if _issued is None else _issued
    deadline = issued + IPC_TIMEOUT if _deadline is None else _deadline
    pidfds = []
    try:
        if (os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or (caller_uid, caller_gid) != (config.gateway_uid, config.gateway_gid)
                or _boot_id() != config.boot_id):
            _deny()
        _config_current(config)
        origin = _socket_identity(config.ingress_socket, config)
        gateway_pidfd, gateway_start, _gw_invocation = _check_unit_process(config,
            unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
        pidfds.append(gateway_pidfd)
        tunnel_pidfd, tunnel_start, tunnel_invocation = _check_unit_process(config,
            unit=TUNNEL_UNIT, pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid, deadline=deadline)
        pidfds.append(tunnel_pidfd)
        core_props = _unit_properties(CORE_SERVICE_UNIT, deadline=deadline)
        core_pid = int(core_props.get("MainPID", "0"))
        core_pidfd, core_start, core_invocation = _check_unit_process(config,
            unit=CORE_SERVICE_UNIT, pid=core_pid, deadline=deadline)
        pidfds.append(core_pidfd)
        _current_core_credential(core_pid, config, deadline=deadline)
        source_generation = _current_core_source(config, deadline=deadline)
        if Path(f"/proc/{core_pid}/cwd").resolve(strict=True) != CORE_WORKSPACE:
            _deny()
        listener_inode = _core_listener_inode(core_pid)
        generation_payload = (f"{core_invocation}\0{core_pid}\0{core_start}\0{listener_inode}\0"
                              f"{source_generation}").encode("ascii")
        core_generation = hashlib.sha256(b"hermes-jarvis-core-generation-v1\0" + generation_payload).hexdigest()
        if _projection_factory is not None:
            _projection_factory(source_generation)
            if time.monotonic() >= deadline:
                _deny()
        if (time.monotonic() >= deadline or _boot_id() != config.boot_id
                or _socket_identity(config.ingress_socket, config) != origin
                or _core_listener_inode(core_pid) != listener_inode
                or _current_core_source(config, deadline=deadline) != source_generation
                or _config_current(config).config_sha256 != config.config_sha256):
            _deny()
        for pidfd, pid, start_ticks in (
                (gateway_pidfd, caller_pid, gateway_start),
                (tunnel_pidfd, peer_pid, tunnel_start),
                (core_pidfd, core_pid, core_start)):
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0) or _proc_start_ticks(pid) != start_ticks:
                _deny()
        body: dict[str, Any] = {
            "schema": 1, "nonce": nonce, "boot_id": config.boot_id,
            "issued_monotonic": issued, "expires_monotonic": issued + MAX_PROOF_SECONDS,
            "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid,
            "peer_start_ticks": tunnel_start, "tunnel_invocation_id": tunnel_invocation,
            "tunnel_unit_sha256": config.tunnel_unit_sha256,
            "tunnel_executable_sha256": config.cloudflared_binary_sha256,
            "origin_socket_device": origin[0], "origin_socket_inode": origin[1],
            "gateway_unit_sha256": config.gateway_unit_sha256,
            "core_unit_sha256": config.core_unit_sha256,
            "core_invocation_id": core_invocation, "core_pid": core_pid,
            "core_start_ticks": core_start, "core_listener_inode": listener_inode,
            "core_source_generation": source_generation,
            "core_generation": core_generation, "config_sha256": config.config_sha256,
        }
        body["proof_sha256"] = _observation_digest(body)
        return body
    finally:
        for pidfd in pidfds:
            try:
                os.close(pidfd)
            except OSError:
                pass


_OVERVIEW_PROJECTION_FIELDS = {
    "core_version", "provider", "model", "account_state", "resources_state",
    "resource_counts", "resources_revision", "artifact_sha256",
    "discovery_observed_at_utc", "active_prompt_matches_bundled_primary",
}


def _core_overview_projection(source_generation: str) -> dict[str, Any]:
    from ..core_runtime import COMMIT, read_current_resources_discovery
    projection = read_current_resources_discovery(core_source_generation=source_generation)
    # Provider/model are deliberately unknown until a separately reviewed, bounded
    # effective-config projection exists. A present key is not proof of auth.
    projection.update({"core_version": COMMIT[:12], "provider": None, "model": None,
                       "account_state": "unknown"})
    if not _valid_overview_projection(projection):
        _deny()
    return projection


def _valid_overview_projection(projection: Any) -> bool:
    if type(projection) is not dict or set(projection) != _OVERVIEW_PROJECTION_FIELDS:
        return False
    if (projection.get("core_version") != CORE_SOURCE_REVISION[:12]
            or projection.get("account_state") not in {"unknown", "configured"}
            or projection.get("resources_state") not in {"pending", "discovered", "stale"}):
        return False
    for key in ("provider", "model"):
        value = projection.get(key)
        if value is not None and (not isinstance(value, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", value) is None):
            return False
    if projection["account_state"] == "unknown" and any(
            projection[key] is not None for key in ("provider", "model")):
        return False
    if projection["resources_state"] != "discovered":
        return all(projection[key] is None for key in (
            "resource_counts", "resources_revision", "artifact_sha256",
            "discovery_observed_at_utc", "active_prompt_matches_bundled_primary"))
    counts = projection.get("resource_counts")
    if (not isinstance(counts, dict) or set(counts) != {
            "native_skills", "internal_profiles", "source_profiles_preserved",
            "other_declarations_preserved"}
            or any(type(value) is not int or value < 0 or value > 10000
                   for value in counts.values())):
        return False
    revision = projection.get("resources_revision")
    observed = projection.get("discovery_observed_at_utc")
    if (not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or not _is_hash(projection.get("artifact_sha256"))
            or type(projection.get("active_prompt_matches_bundled_primary")) is not bool
            or not isinstance(observed, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", observed) is None):
        return False
    try:
        parsed = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except (TypeError, ValueError):
        return False


def observe_current_core_overview(config: CoreGatewayConfig, *, nonce: str,
                                  caller_pid: int, caller_uid: int, caller_gid: int,
                                  peer_pid: int, peer_uid: int, peer_gid: int,
                                  issued: float, deadline: float) -> dict[str, Any]:
    projection_holder: dict[str, Any] = {}

    def project(source_generation: str) -> None:
        projection_holder.update(_core_overview_projection(source_generation))

    ingress = observe_current_ingress(config, nonce=nonce, caller_pid=caller_pid,
        caller_uid=caller_uid, caller_gid=caller_gid, peer_pid=peer_pid,
        peer_uid=peer_uid, peer_gid=peer_gid, _issued=issued, _deadline=deadline,
        _projection_factory=project)
    if set(projection_holder) != _OVERVIEW_PROJECTION_FIELDS:
        _deny()
    body = {
        "schema": 1, "nonce": nonce, "boot_id": ingress["boot_id"],
        "issued_monotonic": issued, "expires_monotonic": min(issued + MAX_PROOF_SECONDS, deadline),
        "config_sha256": ingress["config_sha256"],
        "core_generation": ingress["core_generation"],
        "core_source_generation": ingress["core_source_generation"],
        "projection": projection_holder,
    }
    if time.monotonic() >= body["expires_monotonic"]:
        _deny()
    body["proof_sha256"] = _overview_digest(body)
    return body


@dataclass(frozen=True, slots=True)
class CoreVerifiedOverviewObservation:
    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    config_sha256: str
    core_generation: str
    core_source_generation: str
    projection: dict[str, Any]
    proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, peer_pid: int,
                       peer_uid: int, peer_gid: int,
                       accepted_ingress: Any,
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            claims = {name: getattr(self, name) for name in (
                "schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
                "config_sha256", "core_generation", "core_source_generation", "projection")}
            projection = self.projection
            if (self._seal is not _OVERVIEW_PROOF_SEAL or not _valid_overview_projection(projection)
                    or type(self.schema) is not int or self.schema != 1
                    or not re.fullmatch(r"[0-9a-f]{64}", self.nonce)
                    or self.boot_id != config.boot_id or self.config_sha256 != config.config_sha256
                    or type(projection) is not dict or set(projection) != _OVERVIEW_PROJECTION_FIELDS
                    or projection.get("account_state") not in {"unknown", "configured"}
                    or projection.get("resources_state") not in {"pending", "discovered", "stale"}
                    or any(value is not None and (not isinstance(value, str)
                        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}", value) is None)
                        for value in (projection.get("core_version"), projection.get("provider"),
                                      projection.get("model"), projection.get("resources_revision")))
                    or (projection.get("artifact_sha256") is not None
                        and not _is_hash(projection.get("artifact_sha256")))
                    or (projection.get("active_prompt_matches_bundled_primary") is not None
                        and type(projection.get("active_prompt_matches_bundled_primary")) is not bool)
                    or (projection.get("discovery_observed_at_utc") is not None
                        and (not isinstance(projection.get("discovery_observed_at_utc"), str)
                             or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                             projection["discovery_observed_at_utc"]) is None))
                    or (projection.get("resource_counts") is not None and
                        (not isinstance(projection.get("resource_counts"), dict)
                         or set(projection["resource_counts"]) != {
                             "native_skills", "internal_profiles", "source_profiles_preserved",
                             "other_declarations_preserved"}
                         or any(type(value) is not int or value < 0 or value > 10000
                                for value in projection["resource_counts"].values())))
                    or any(isinstance(value, bool) or not isinstance(value, (int, float))
                           or not math.isfinite(value) for value in
                           (self.issued_monotonic, self.expires_monotonic, current))
                    or not self.issued_monotonic <= current < self.expires_monotonic
                    or not self.issued_monotonic < self.expires_monotonic <= self.issued_monotonic + MAX_PROOF_SECONDS
                    or not _is_hash(self.config_sha256) or not _is_hash(self.core_generation)
                    or not _is_hash(self.core_source_generation) or _overview_digest(claims) != self.proof_sha256):
                return False
            from .core_gateway import CoreAcceptedIngressObservation
            return bool(type(accepted_ingress) is CoreAcceptedIngressObservation
                        and accepted_ingress.verify_current(config, now=current)
                        and (accepted_ingress.peer_pid, accepted_ingress.peer_uid, accepted_ingress.peer_gid)
                            == (peer_pid, peer_uid, peer_gid)
                        and accepted_ingress.core_generation == self.core_generation
                        and accepted_ingress.root_observation.core_source_generation == self.core_source_generation
                        and accepted_ingress.root_observation.boot_id == self.boot_id
                        and accepted_ingress._config_sha256 == self.config_sha256
                        and time.monotonic() < min(accepted_ingress.expires_monotonic, self.expires_monotonic))
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class CoreVerifiedIngressObservation:
    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_ticks: str
    tunnel_invocation_id: str
    tunnel_unit_sha256: str
    tunnel_executable_sha256: str
    origin_socket_device: int
    origin_socket_inode: int
    gateway_unit_sha256: str
    core_unit_sha256: str
    core_invocation_id: str
    core_pid: int
    core_start_ticks: str
    core_listener_inode: int
    core_source_generation: str
    core_generation: str
    config_sha256: str
    proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, peer_pid: int, peer_uid: int,
                       peer_gid: int, listener_identity: tuple[int, int],
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            claims = {name: getattr(self, name) for name in _OBSERVATION_FIELDS}
            return bool(self._seal is _PROOF_SEAL and type(self.schema) is int and self.schema == 1
                and re.fullmatch(r"[0-9a-f]{64}", self.nonce)
                and self.boot_id == config.boot_id == _boot_id()
                and self.config_sha256 == config.config_sha256
                and self.gateway_unit_sha256 == config.gateway_unit_sha256
                and self.core_unit_sha256 == config.core_unit_sha256
                and self.tunnel_unit_sha256 == config.tunnel_unit_sha256
                and self.tunnel_executable_sha256 == config.cloudflared_binary_sha256
                and (self.peer_pid, self.peer_uid, self.peer_gid) == (peer_pid, peer_uid, peer_gid)
                and (self.origin_socket_device, self.origin_socket_inode) == listener_identity
                and type(current) in (int, float) and self.issued_monotonic <= current < self.expires_monotonic
                and self.issued_monotonic < self.expires_monotonic <=
                    self.issued_monotonic + MAX_PROOF_SECONDS
                and self.peer_start_ticks.isdecimal() and self.core_start_ticks.isdecimal()
                and _is_hash(self.core_source_generation)
                and self.core_generation == hashlib.sha256(
                    b"hermes-jarvis-core-generation-v1\0" +
                    f"{self.core_invocation_id}\0{self.core_pid}\0{self.core_start_ticks}\0{self.core_listener_inode}\0{self.core_source_generation}".encode("ascii")
                ).hexdigest()
                and _observation_digest(claims) == self.proof_sha256
                and all(_is_hash(value) for value in (self.tunnel_unit_sha256,
                    self.tunnel_executable_sha256, self.gateway_unit_sha256, self.core_unit_sha256,
                    self.core_source_generation, self.config_sha256, self.proof_sha256)))
        except Exception:
            return False


def _read_frame(conn: socket.socket, deadline: float, maximum: int) -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(conn, 4, deadline))[0]
    if not 2 <= size <= maximum:
        raise ValueError("IPC message exceeded bound")
    value = json.loads(_read_exact(conn, size, deadline).decode("ascii"), object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("IPC frame is not an object")
    return value


def _serve_connection(conn: socket.socket, config: CoreGatewayConfig) -> None:
    try:
        issued = time.monotonic()
        deadline = issued + 1.5
        conn.settimeout(1.5)
        if not hasattr(socket, "SO_PEERCRED"):
            return
        caller_pid, caller_uid, caller_gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if caller_uid != config.gateway_uid or caller_pid <= 1:
            return
        request = _read_frame(conn, deadline, MAX_REQUEST)
        if set(request) != {"op", "nonce", "peer_pid", "peer_uid", "peer_gid"}:
            return
        arguments = {"nonce": request["nonce"], "caller_pid": caller_pid,
            "caller_uid": caller_uid, "caller_gid": caller_gid, "peer_pid": request["peer_pid"],
            "peer_uid": request["peer_uid"], "peer_gid": request["peer_gid"]}
        if request.get("op") == "observe-ingress":
            result = observe_current_ingress(config, **arguments)
        elif request.get("op") == "observe-core-overview":
            result = observe_current_core_overview(config, **arguments, issued=issued, deadline=deadline)
        else:
            return
        raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(raw) > MAX_RESPONSE or time.monotonic() >= deadline:
            return
        conn.sendall(struct.pack("!I", len(raw)) + raw)
    except Exception:
        return
    finally:
        _SERVER_SLOTS.release()
        conn.close()


def serve_inspection_socket(config: CoreGatewayConfig) -> None:
    if os.geteuid() != 0 or type(config) is not CoreGatewayConfig:
        raise CoreInspectionDenied("core inspector must run as root")
    if CORE_INSPECTOR_SOCKET.exists() or CORE_INSPECTOR_SOCKET.is_symlink():
        raise CoreInspectionDenied("fixed core inspector socket is occupied")
    parent = os.lstat(CORE_INSPECTOR_SOCKET.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != config.gateway_gid
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise CoreInspectionDenied("fixed core inspector directory custody differs")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    stopping = False
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    try:
        for sig in previous:
            signal.signal(sig, stop)
        server.bind(str(CORE_INSPECTOR_SOCKET))
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        identity = (info.st_dev, info.st_ino)
        os.chown(CORE_INSPECTOR_SOCKET, 0, config.gateway_gid)
        os.chmod(CORE_INSPECTOR_SOCKET, 0o660)
        server.listen(16)
        server.settimeout(0.5)
        while not stopping:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            if not _SERVER_SLOTS.acquire(blocking=False):
                conn.close()
                continue
            try:
                worker = threading.Thread(target=_serve_connection, args=(conn, config), daemon=True)
                worker.start()
            except Exception:
                _SERVER_SLOTS.release()
                conn.close()
                raise
    finally:
        server.close()
        for sig, prior in previous.items():
            signal.signal(sig, prior)
        try:
            info = os.lstat(CORE_INSPECTOR_SOCKET)
            if identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                CORE_INSPECTOR_SOCKET.unlink()
        except OSError:
            pass


def verify_current_ingress(config: CoreGatewayConfig, *, peer_pid: int,
                           peer_uid: int, peer_gid: int) -> CoreVerifiedIngressObservation:
    from .core_gateway import _log_ingress_denial, _read_config_current
    _read_config_current(config)
    nonce = os.urandom(32).hex()
    deadline = time.monotonic() + IPC_TIMEOUT
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        _log_ingress_denial("root_ipc_socket", CoreGatewayDenied())
        raise CoreGatewayDenied("root core inspector socket is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(IPC_TIMEOUT)
    try:
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {"op": "observe-ingress", "nonce": nonce,
                "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid}
        raw_request = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw_request) > MAX_REQUEST:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw_request)) + raw_request)
        result = _read_frame(conn, deadline, MAX_RESPONSE)
    except Exception as error:
        _log_ingress_denial("root_ipc_exchange", error)
        raise CoreGatewayDenied("root core ingress proof is unavailable") from None
    finally:
        conn.close()
    fields = {field.name for field in CoreVerifiedIngressObservation.__dataclass_fields__.values()
              if not field.name.startswith("_")}
    if set(result) != fields:
        _log_ingress_denial("root_ipc_schema", CoreGatewayDenied())
        raise CoreGatewayDenied("root core ingress proof has an unknown schema")
    body = dict(result)
    proof_sha = body.pop("proof_sha256", None)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if (proof_sha != hashlib.sha256(b"hermes-jarvis-core-ingress-v1\0" + canonical).hexdigest()
            or result.get("nonce") != nonce or time.monotonic() >= deadline):
        _log_ingress_denial("root_ipc_binding", CoreGatewayDenied())
        raise CoreGatewayDenied("root core ingress proof is mismatched or late")
    try:
        observation = CoreVerifiedIngressObservation(**result, _seal=_PROOF_SEAL)
        _read_config_current(config)
        listener = os.lstat(config.ingress_socket)
        if observation.verify_current(config, peer_pid=peer_pid, peer_uid=peer_uid,
            peer_gid=peer_gid, listener_identity=(listener.st_dev, listener.st_ino)) is not True:
            raise ValueError
        return observation
    except Exception as error:
        _log_ingress_denial("root_ipc_currentness", error)
        raise CoreGatewayDenied("root core ingress proof is invalid or stale") from None


def verify_current_core_overview(config: CoreGatewayConfig, *, peer_pid: int,
                                 peer_uid: int, peer_gid: int,
                                 accepted_ingress: Any) -> CoreVerifiedOverviewObservation:
    from .core_gateway import _log_ingress_denial, _read_config_current
    _read_config_current(config)
    nonce = os.urandom(32).hex()
    deadline = time.monotonic() + IPC_TIMEOUT
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        raise CoreGatewayDenied("root core overview inspector is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(IPC_TIMEOUT)
    try:
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {"op": "observe-core-overview", "nonce": nonce,
                "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_REQUEST:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw)) + raw)
        result = _read_frame(conn, deadline, MAX_RESPONSE)
    except Exception as error:
        _log_ingress_denial("root_core_overview_exchange", error)
        raise CoreGatewayDenied("root core overview proof is unavailable") from None
    finally:
        conn.close()
    fields = {"schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
              "config_sha256", "core_generation", "core_source_generation", "projection", "proof_sha256"}
    if set(result) != fields:
        raise CoreGatewayDenied("root core overview proof has an unknown schema")
    claims = dict(result)
    proof = claims.pop("proof_sha256", None)
    try:
        expected_proof = _overview_digest(claims)
    except Exception:
        raise CoreGatewayDenied("root core overview proof is malformed") from None
    if (proof != expected_proof or result.get("nonce") != nonce
            or time.monotonic() >= deadline):
        raise CoreGatewayDenied("root core overview proof is mismatched or late")
    try:
        observation = CoreVerifiedOverviewObservation(**result, _seal=_OVERVIEW_PROOF_SEAL)
        _read_config_current(config)
        if observation.verify_current(config, peer_pid=peer_pid, peer_uid=peer_uid,
                                      peer_gid=peer_gid, accepted_ingress=accepted_ingress) is not True:
            raise ValueError
        return observation
    except Exception as error:
        _log_ingress_denial("root_core_overview_currentness", error)
        raise CoreGatewayDenied("root core overview proof is invalid or stale") from None


def main() -> None:
    import argparse
    argparse.ArgumentParser(description="read-only root inspector for the core Jarvis ingress").parse_args()
    if os.geteuid() != 0:
        raise SystemExit("core ingress inspector must run as root")
    serve_inspection_socket(CoreGatewayConfig.load(expected_owner_uid=0))


if __name__ == "__main__":
    main()
