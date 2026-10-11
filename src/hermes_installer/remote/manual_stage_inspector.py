"""Fixed read-only root inspector for the manually owned Jarvis MVP stage.

This is a finite local observation helper, not installer authority: it cannot
start services, change nftables, choose a unit/path, or mint a runtime receipt.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import select
import signal
import socket
import stat
import struct
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

SOCKET_PATH = Path("/run/hermes-jarvis-mvp/inspection.sock")
INGRESS_SOCKET_PATH = Path("/run/hermes-jarvis-mvp-gateway/origin.sock")
GATEWAY_UNIT = "hermes-jarvis-mvp-gateway.service"
TUNNEL_UNIT = "hermes-jarvis-mvp-tunnel.service"
GATEWAY_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-mvp-gateway.service")
TUNNEL_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-mvp-tunnel.service")
CLOUDFLARED_PATH = Path("/usr/bin/cloudflared")
TUNNEL_ARGV = ("/usr/bin/cloudflared", "--no-autoupdate", "tunnel", "run",
               "--token-file", "/run/credentials/hermes-jarvis-mvp-tunnel.service/tunnel-token")
TABLE_FAMILY, TABLE_NAME, CHAIN_NAME = "inet", "hermes_jarvis_mvp", "output"
DISPLAY_UNIT = "hermes-xpra-stage.service"
DISPLAY_UNIT_PATH = Path("/etc/systemd/system/hermes-xpra-stage.service")
MAX_REQUEST = 1024
MAX_RESPONSE = 1024
INGRESS_MAX_RESPONSE = 2048
MAX_OUTPUT = 65_536
OBSERVATION_SECONDS = 5.0
INSPECTION_IPC_TIMEOUT_SECONDS = 2.0
MAX_INSPECTION_QUEUE_WAIT_SECONDS = 6.5
WATCHDOG_INSPECTION_QUEUE_WAIT_SECONDS = 0.5
MAX_APP_FILE_BYTES = 256 * 1024 * 1024
MAX_APP_TREE_BYTES = 2 * 1024 * 1024 * 1024
_INGRESS_SERVER_SLOTS = threading.BoundedSemaphore(8)
_SERVER_CONNECTION_SLOTS = threading.BoundedSemaphore(16)
_OBSERVATION_SERVER_SLOTS = threading.BoundedSemaphore(8)
_INGRESS_REQUEST_DEADLINE_SECONDS = 2.0
_INGRESS_PROOF_TTL_SECONDS = 5.0
_OBSERVATION_SEAL = object()
_NATIVE_OBSERVATION_SEAL = object()
_NATIVE_OBSERVATION_CONDITION = threading.Condition()
_NATIVE_OBSERVATION_SNAPSHOT: dict[str, Any] | None = None
_NATIVE_OBSERVATION_SCAN_RUNNING = False
_NATIVE_OBSERVATION_MIN_REMAINING_SECONDS = 0.15
GATEWAY_EXECUTABLE = Path("/usr/bin/python3.13")
GATEWAY_EXECUTABLE_SHA256 = "bd241b38381974ae27d7d5098a6d0e6dda0a744b5e9fdd6fe3a1ae632588961e"
GATEWAY_ARGV = ("/opt/hermes-jarvis-mvp-20261011/gateway-venv/bin/python", "-m",
                "hermes_installer.remote.manual_stage")
XPRA_CONTROL_STUB_PATH = Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/stub.py")
XPRA_CONTROL_STUB_SIZE = 5071
XPRA_CONTROL_STUB_SHA256 = "da12f27c1421dc71248b568791f186ee3d470d0969c4020da0d9d6d7a1a02279"
XPRA_CORE_PATH = Path("/usr/lib/python3/dist-packages/xpra/server/core.py")
XPRA_CORE_SIZE = 75_743
XPRA_CORE_SHA256 = "95a8bb41304181555ac33482931ba1c2460b4a1b03e458c3c5e8825adcf34e77"
XPRA_WINDOW_PATH = Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/window.py")
XPRA_WINDOW_SIZE = 42_476
XPRA_WINDOW_SHA256 = "7fd74d70e6a50e2f02727e263bdbec34826d23871abf4feedb230741ef09264f"
XPRA_COMMAND_PATH = Path("/usr/lib/python3/dist-packages/xpra/server/subsystem/command.py")
XPRA_COMMAND_SIZE = 24_117
XPRA_COMMAND_SHA256 = "09e90f7dcb8a76687c59ee8c538faef21ce2881bdaed4cafb760eb8fe141f2d3"
XPRA_PORT = 14_500
XPRA_PINNED_MODULES = (
    (XPRA_CONTROL_STUB_PATH, XPRA_CONTROL_STUB_SIZE, XPRA_CONTROL_STUB_SHA256),
    (XPRA_CORE_PATH, XPRA_CORE_SIZE, XPRA_CORE_SHA256),
    (XPRA_WINDOW_PATH, XPRA_WINDOW_SIZE, XPRA_WINDOW_SHA256),
    (XPRA_COMMAND_PATH, XPRA_COMMAND_SIZE, XPRA_COMMAND_SHA256),
)


class StageInspectionDenied(PermissionError):
    pass


@dataclass(frozen=True, slots=True)
class StageVerifiedIngressObservation:
    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_ticks: str
    tunnel_unit_sha256: str
    tunnel_config_sha256: str
    tunnel_executable_sha256: str
    origin_socket_device: int
    origin_socket_inode: int
    config_sha256: str
    proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: Any, peer_pid: int, peer_uid: int, peer_gid: int,
                       *, now: float | None = None) -> bool:
        """Validate provenance, exact request peer/config binding and short freshness."""
        current = time.monotonic() if now is None else now
        return bool(
            self._seal is _OBSERVATION_SEAL and self.schema == 1
            and self.nonce and re.fullmatch(r"[0-9a-f]{64}", self.nonce)
            and self.boot_id == config.boot_id
            and self.config_sha256 == config.config_sha256
            and self.tunnel_unit_sha256 == config.tunnel_unit_sha256
            and self.tunnel_config_sha256 == _tunnel_config_digest(config)
            and self.tunnel_executable_sha256 == config.cloudflared_binary_sha256
            and (self.peer_pid, self.peer_uid, self.peer_gid) == (peer_pid, peer_uid, peer_gid)
            and self.peer_pid > 1 and self.peer_uid >= 0 and self.peer_gid >= 0
            and self.peer_start_ticks.isdecimal()
            and type(current) in (int, float) and current >= self.issued_monotonic
            and self.issued_monotonic <= current < self.expires_monotonic
            and 0 < self.expires_monotonic - self.issued_monotonic <= _INGRESS_PROOF_TTL_SECONDS
            and all(_is_sha256(value) for value in (
                self.tunnel_unit_sha256, self.tunnel_config_sha256,
                self.tunnel_executable_sha256, self.config_sha256, self.proof_sha256))
            and type(self.origin_socket_device) is int and self.origin_socket_device >= 0
            and type(self.origin_socket_inode) is int and self.origin_socket_inode > 0
        )


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True, slots=True)
class StageNativeInspectionObservation:
    config_sha256: str
    boot_id: str
    native_observation_sha256: str
    nonce: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: Any, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return bool(
            self._seal is _NATIVE_OBSERVATION_SEAL
            and self.config_sha256 == config.config_sha256
            and self.boot_id == config.boot_id
            and re.fullmatch(r"[0-9a-f-]{36}", self.boot_id)
            and _is_sha256(self.config_sha256)
            and _is_sha256(self.native_observation_sha256)
            and re.fullmatch(r"[0-9a-f]{64}", self.nonce)
            and type(current) in (int, float) and math.isfinite(current)
            and type(self.issued_monotonic) in (int, float) and math.isfinite(self.issued_monotonic)
            and type(self.expires_monotonic) in (int, float) and math.isfinite(self.expires_monotonic)
            and self.issued_monotonic <= current < self.expires_monotonic
            and self.expires_monotonic <= self.issued_monotonic + OBSERVATION_SECONDS
        )


def _check_app_file_size(size: int) -> None:
    if type(size) is not int or size < 0 or size > MAX_APP_FILE_BYTES:
        raise _deny()


def _deny() -> StageInspectionDenied:
    return StageInspectionDenied("manual stage current-state observation is unavailable")


def _run_fixed(argv: tuple[str, ...], *, deadline: float, maximum: int = MAX_OUTPUT) -> bytes:
    if time.monotonic() >= deadline:
        raise _deny()
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                "LANG": "C", "LC_ALL": "C"}, close_fds=True)
    except OSError:
        raise _deny() from None
    assert proc.stdout is not None and proc.stderr is not None
    for stream in (proc.stdout, proc.stderr):
        os.set_blocking(stream.fileno(), False)
    selector = select.poll()
    selector.register(proc.stdout, select.POLLIN | select.POLLHUP | select.POLLERR)
    selector.register(proc.stderr, select.POLLIN | select.POLLHUP | select.POLLERR)
    rows = {proc.stdout.fileno(): bytearray(), proc.stderr.fileno(): bytearray()}
    streams = {proc.stdout.fileno(): proc.stdout, proc.stderr.fileno(): proc.stderr}
    try:
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _deny()
            events = selector.poll(max(1, min(100, int(remaining * 1000))))
            if not events and proc.poll() is not None:
                # Drain EOF/HUP on the next poll iteration.
                for fd, stream in tuple(streams.items()):
                    try:
                        part = os.read(fd, maximum + 1 - len(rows[fd]))
                    except BlockingIOError:
                        continue
                    if part:
                        rows[fd].extend(part)
                    else:
                        selector.unregister(stream)
                        streams.pop(fd, None)
            for fd, _event in events:
                try:
                    part = os.read(fd, maximum + 1 - len(rows[fd]))
                except BlockingIOError:
                    continue
                if part:
                    rows[fd].extend(part)
                    if len(rows[fd]) > maximum:
                        raise _deny()
                else:
                    selector.unregister(streams[fd])
                    streams.pop(fd, None)
        remaining = deadline - time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining) != 0 or rows[proc.stderr.fileno()]:
            raise _deny()
        return bytes(rows[proc.stdout.fileno()])
    except Exception:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        raise _deny() from None
    finally:
        proc.stdout.close()
        proc.stderr.close()


def _parse_props(raw: bytes) -> dict[str, str]:
    try:
        lines = raw.decode("utf-8", "strict").splitlines()
        result = {}
        for line in lines:
            key, sep, value = line.partition("=")
            if not sep or key in result:
                raise ValueError
            result[key] = value
        return result
    except Exception:
        raise _deny() from None


def _validate_nft(raw: bytes, gateway_uid: int) -> None:
    """Require the one owned output rule that denies other UIDs to TCP/14500."""
    try:
        value = json.loads(raw, object_pairs_hook=_unique_pairs)
        if set(value) != {"nftables"}:
            raise ValueError
        rows = value["nftables"]
        tables, chains, rules = [], [], []
        for row in rows:
            if "metainfo" in row:
                continue
            if "table" in row:
                tables.append(row["table"])
            elif "chain" in row:
                chains.append(row["chain"])
            elif "rule" in row:
                rules.append(row["rule"])
            else:
                raise ValueError
        if (len(tables) != 1 or tables[0].get("family") != TABLE_FAMILY
                or tables[0].get("name") != TABLE_NAME or len(chains) != 1
                or len(rules) != 1):
            raise ValueError
        if set(tables[0]) - {"family", "name", "handle"}:
            raise ValueError
        chain = chains[0]
        if set(chain) - {"family", "table", "name", "handle", "type", "hook", "prio", "policy"}:
            raise ValueError
        if (chain.get("family") != TABLE_FAMILY or chain.get("table") != TABLE_NAME
                or chain.get("name") != CHAIN_NAME or chain.get("type") != "filter"
                or chain.get("hook") != "output" or chain.get("prio") != -10
                or chain.get("policy") != "accept"):
            raise ValueError
        rule = rules[0]
        if (rule.get("family") != TABLE_FAMILY or rule.get("table") != TABLE_NAME
                or rule.get("chain") != CHAIN_NAME):
            raise ValueError
        expr = rule.get("expr")
        if not isinstance(expr, list) or len(expr) != 4:
            raise ValueError
        expected = {
            json.dumps({"match": {"op": "!=", "left": {"meta": {"key": "skuid"}}, "right": gateway_uid}}, sort_keys=True),
            json.dumps({"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "127.0.0.1"}}, sort_keys=True),
            json.dumps({"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 14500}}, sort_keys=True),
        }
        actual = {json.dumps(row, sort_keys=True) for row in expr[:3]}
        if actual != expected or expr[3] != {"reject": {"type": "tcp reset"}}:
            raise ValueError
        # Reject additional rule comments, counters, verdict maps or expressions.
        if (set(rule) - {"family", "table", "chain", "expr", "handle", "comment"}
                or rule.get("comment") != "Jarvis MVP display gateway only"):
            raise ValueError
    except Exception:
        raise _deny() from None


def _check_immutable_tree(appdir: Path, expected_manifest_sha256: str) -> str:
    try:
        root = os.open(appdir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            root_info = os.fstat(root)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) & 0o022:
                raise ValueError
            manifest_fd = os.open("MANIFEST.sha256", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=root)
            try:
                info = os.fstat(manifest_fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022 or info.st_size > 1_048_576:
                    raise ValueError
                raw = bytearray()
                while len(raw) <= 1_048_576:
                    chunk = os.read(manifest_fd, min(8192, 1_048_577 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
            finally:
                os.close(manifest_fd)
            digest = hashlib.sha256(raw).hexdigest()
            if digest != expected_manifest_sha256:
                raise ValueError
            seen: set[str] = set()
            expected_dirs: set[str] = set()
            total_size = 0
            for line in bytes(raw).decode("ascii", "strict").splitlines():
                sha, separator, rel = line.partition("  ")
                path = PurePosixPath(rel)
                if (not separator or len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha)
                        or path.is_absolute() or not path.parts or any(p in {"", ".", ".."} for p in path.parts)
                        or rel in seen):
                    raise ValueError
                seen.add(rel)
                expected_dirs.update("/".join(path.parts[:index]) for index in range(1, len(path.parts)))
                parent = os.dup(root)
                try:
                    for part in path.parts[:-1]:
                        nxt = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
                        part_info = os.fstat(nxt)
                        if (not stat.S_ISDIR(part_info.st_mode) or part_info.st_uid != 0
                                or stat.S_IMODE(part_info.st_mode) & 0o022):
                            os.close(nxt)
                            raise ValueError
                        os.close(parent)
                        parent = nxt
                    fd = os.open(path.parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent)
                    try:
                        file_info = os.fstat(fd)
                        if (not stat.S_ISREG(file_info.st_mode) or file_info.st_uid != 0
                                or stat.S_IMODE(file_info.st_mode) & 0o022):
                            raise ValueError
                        _check_app_file_size(file_info.st_size)
                        total_size += file_info.st_size
                        if total_size > MAX_APP_TREE_BYTES:
                            raise ValueError
                        file_hash = hashlib.sha256()
                        while True:
                            chunk = os.read(fd, 65_536)
                            if not chunk:
                                break
                            file_hash.update(chunk)
                        if file_hash.hexdigest() != sha:
                            raise ValueError
                    finally:
                        os.close(fd)
                finally:
                    os.close(parent)
            if not seen:
                raise ValueError
            actual_files, actual_dirs = _scan_tree(root, "")
            actual_files.discard("MANIFEST.sha256")
            if actual_files != seen or actual_dirs != expected_dirs:
                raise ValueError
            return digest
        finally:
            os.close(root)
    except Exception:
        raise _deny() from None


def _appdir_manifest_custody(appdir: Path, expected_manifest_sha256: str) -> tuple[int, int, int, int, int, str]:
    """Cheaply bind root-owned AppDir and manifest identity without rehashing every member."""
    parent_fd = -1
    try:
        parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
        current = parent_fd
        for component in appdir.parts[1:]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=current)
            info = os.fstat(next_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(next_fd)
                raise ValueError
            if current != parent_fd:
                os.close(current)
            current = next_fd
        app_info = os.fstat(current)
        manifest_fd = os.open("MANIFEST.sha256", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                              dir_fd=current)
        try:
            manifest_info = os.fstat(manifest_fd)
            if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_uid != 0
                    or stat.S_IMODE(manifest_info.st_mode) & 0o022
                    or manifest_info.st_nlink != 1 or manifest_info.st_size > 1_048_576):
                raise ValueError
            digest = hashlib.sha256()
            remaining = manifest_info.st_size
            while remaining:
                part = os.read(manifest_fd, min(65_536, remaining))
                if not part:
                    raise ValueError
                digest.update(part)
                remaining -= len(part)
            if os.read(manifest_fd, 1) or digest.hexdigest() != expected_manifest_sha256:
                raise ValueError
            return (app_info.st_dev, app_info.st_ino, manifest_info.st_dev,
                    manifest_info.st_ino, manifest_info.st_size, digest.hexdigest())
        finally:
            os.close(manifest_fd)
    except Exception:
        raise _deny() from None
    finally:
        if parent_fd >= 0:
            try:
                if current != parent_fd:
                    os.close(current)
            except (UnboundLocalError, OSError):
                pass
            os.close(parent_fd)


def _scan_tree(directory_fd: int, prefix: str) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    directories: set[str] = set()
    try:
        names = os.listdir(directory_fd)
        if len(names) > 50_000:
            raise ValueError
        for name in names:
            if name in {".", ".."} or "/" in name or "\0" in name:
                raise ValueError
            relative = f"{prefix}/{name}" if prefix else name
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise ValueError
                child = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
                try:
                    found_files, found_dirs = _scan_tree(child, relative)
                    files.update(found_files)
                    directories.add(relative)
                    directories.update(found_dirs)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                    raise ValueError
                files.add(relative)
            else:
                raise ValueError
            if len(files) + len(directories) > 100_000:
                raise ValueError
        return files, directories
    except Exception:
        raise _deny() from None


def _pid_start_ticks(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    return raw[raw.rfind(")") + 2:].split()[19]


def _process_argv(pid: int) -> tuple[str, ...]:
    """Read bounded kernel argv bytes without shell parsing or display truncation."""
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    if not raw or len(raw) > 16_384 or raw[-1:] != b"\0":
        raise _deny()
    try:
        values = tuple(part.decode("utf-8", "strict") for part in raw[:-1].split(b"\0"))
    except UnicodeDecodeError:
        raise _deny() from None
    if not values or any(not value or "\0" in value for value in values):
        raise _deny()
    return values


def _tunnel_config_digest(config: Any) -> str:
    """Bind the effective fixed local tunnel wiring (there is no local cloudflared config file)."""
    payload = {
        "argv": list(TUNNEL_ARGV), "binary_sha256": config.cloudflared_binary_sha256,
        "ingress_socket": str(config.ingress_socket),
        "supplementary_group": config.gateway_gid,
        "tunnel_unit_sha256": config.tunnel_unit_sha256,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-mvp-tunnel-config-v263\0" + canonical).hexdigest()


def _proc_identity(pid: int, *, expected_uid: int | None = None,
                   expected_gid: int | None = None,
                   supplementary_gid: int | None = None) -> tuple[int, int, int, str, tuple[str, ...]]:
    """Read a process under PIDFD and return UID/GID, start ticks, and exact argv."""
    if type(pid) is not int or pid <= 1:
        raise _deny()
    try:
        pidfd = os.pidfd_open(pid, 0)
        start_ticks = _pid_start_ticks(pid)
        status = Path(f"/proc/{pid}/status").read_text()
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        argv = _process_argv(pid)
        uid = next(line for line in status.splitlines() if line.startswith("Uid:")).split()
        gid = next(line for line in status.splitlines() if line.startswith("Gid:")).split()
        groups = next(line for line in status.splitlines() if line.startswith("Groups:")).split()[1:]
        if (len(uid) != 5 or len(gid) != 5 or len(set(uid[1:])) != 1
                or len(set(gid[1:])) != 1):
            raise ValueError
        real_uid, real_gid = int(uid[1]), int(gid[1])
        if ((expected_uid is not None and real_uid != expected_uid)
                or (expected_gid is not None and real_gid != expected_gid)
                or (supplementary_gid is not None and str(supplementary_gid) not in groups)
                or _pid_start_ticks(pid) != start_ticks or _pidfd_exited(pidfd)):
            raise ValueError
        return pidfd, real_uid, real_gid, start_ticks, argv
    except Exception:
        try:
            os.close(pidfd)
        except (UnboundLocalError, OSError):
            pass
        raise _deny() from None


def _unit_props(unit: str, *, deadline: float) -> dict[str, str]:
    props = _parse_props(_run_fixed(("/usr/bin/systemctl", "show", unit, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState",
        "--property=MainPID", "--property=ControlGroup", "--property=FragmentPath",
        "--property=User", "--property=Group", "--property=DynamicUser",
        "--property=SupplementaryGroups", "--property=DropInPaths",
        "--property=InvocationID"), deadline=deadline, maximum=8192))
    if (props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
            or props.get("SubState") != "running" or props.get("DropInPaths") != ""
            or not props.get("InvocationID")):
        raise _deny()
    return props


def _fixed_process(config: Any, *, unit: str, expected_pid: int | None,
                   expected_uid: int, expected_gid: int, executable: Path,
                   executable_sha256: str, argv_expected: tuple[str, ...],
                   deadline: float, supplementary_gid: int | None = None,
                   dynamic_user: bool = False) -> tuple[int, int, int, str, str, str]:
    """Check active systemd identity and exact live kernel process identity."""
    props = _unit_props(unit, deadline=deadline)
    pid = int(props.get("MainPID", "0"))
    if expected_pid is not None and pid != expected_pid:
        raise _deny()
    if (props.get("ControlGroup") != f"/system.slice/{unit}"
            or props.get("FragmentPath") != str(GATEWAY_UNIT_PATH if unit == GATEWAY_UNIT else TUNNEL_UNIT_PATH)):
        raise _deny()
    if dynamic_user:
        if props.get("DynamicUser") != "yes" or props.get("SupplementaryGroups") != str(config.gateway_gid):
            raise _deny()
    elif (props.get("User") != str(expected_uid) or props.get("Group") != str(expected_gid)):
        raise _deny()
    if _hash_path(GATEWAY_UNIT_PATH if unit == GATEWAY_UNIT else TUNNEL_UNIT_PATH,
                  require_root_readonly=True) != (config.gateway_unit_sha256 if unit == GATEWAY_UNIT
                                                   else config.tunnel_unit_sha256):
        raise _deny()
    pidfd, proc_uid, proc_gid, start_ticks, argv = _proc_identity(pid,
        expected_uid=None if dynamic_user else expected_uid,
        expected_gid=None if dynamic_user else expected_gid,
        supplementary_gid=supplementary_gid)
    try:
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        actual = Path(f"/proc/{pid}/exe").resolve(strict=True)
        if (proc_uid != expected_uid or proc_gid != expected_gid
                or argv != argv_expected or str(actual) != str(executable)
                or f"0::{props['ControlGroup']}" not in cgroup
                or _hash_path(actual, require_root_readonly=True) != executable_sha256
                or _pid_start_ticks(pid) != start_ticks or _pidfd_exited(pidfd)):
            raise _deny()
        return pidfd, proc_uid, proc_gid, start_ticks, props["InvocationID"], hashlib.sha256(
            b"\0".join(item.encode() for item in argv)).hexdigest()
    except Exception:
        os.close(pidfd)
        raise _deny() from None


def _verify_origin_socket(config: Any) -> tuple[int, int]:
    """Read only the configured fixed Unix socket and its protected parent without following links."""
    path = config.ingress_socket
    if path != INGRESS_SOCKET_PATH:
        raise _deny()
    parent_fd = -1
    try:
        parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            info = os.fstat(next_fd)
            is_target_parent = component == path.parent.name
            if (not stat.S_ISDIR(info.st_mode)
                    or (is_target_parent and (info.st_uid != config.gateway_uid
                                               or info.st_gid != config.gateway_gid
                                               or stat.S_IMODE(info.st_mode) != 0o750))
                    or (not is_target_parent and (info.st_uid != 0
                                                  or stat.S_IMODE(info.st_mode) & 0o022))):
                os.close(next_fd)
                raise ValueError
            os.close(parent_fd)
            parent_fd = next_fd
        parent = os.fstat(parent_fd)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != config.gateway_uid
                or parent.st_gid != config.gateway_gid or stat.S_IMODE(parent.st_mode) != 0o750):
            raise ValueError
        fd = os.open(path.name, os.O_PATH | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != config.gateway_uid
                    or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
                raise ValueError
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)
    except Exception:
        raise _deny() from None
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def _require_xpra_config_isolated_environment(pid: int) -> None:
    """Require Xpra's three config search roots to be explicitly disabled."""
    fd = -1
    try:
        fd = os.open(f"/proc/{pid}/environ", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise _deny()
        raw = bytearray()
        while len(raw) <= 65_536:
            block = os.read(fd, min(8192, 65_537 - len(raw)))
            if not block:
                break
            raw.extend(block)
    except OSError:
        raise _deny() from None
    finally:
        if fd >= 0:
            os.close(fd)
    if not raw or len(raw) > 65_536 or raw[-1:] != b"\0":
        raise _deny()
    required = {
        b"XPRA_DEFAULT_CONF_DIRS": 0,
        b"XPRA_SYSTEM_CONF_DIRS": 0,
        b"XPRA_USER_CONF_DIRS": 0,
    }
    found: dict[bytes, int] = {}
    for entry in bytes(raw[:-1]).split(b"\0"):
        key, separator, value = entry.partition(b"=")
        if key in required:
            if not separator or key in found:
                raise _deny()
            found[key] = len(value)
    if found != required:
        raise _deny()


def _validate_xpra_argv(config: Any, pid: int) -> str:
    argv = _process_argv(pid)
    digest = hashlib.sha256(b"\0".join(arg.encode("utf-8") for arg in argv)).hexdigest()
    # Config is root-owned and immutable during service lifetime. The digest is
    # still only an additional binding: require the fixed interpreter/script,
    # display, loopback listener and the non-secret Xpra header authenticator.
    if (digest != config.xpra_argv_sha256 or len(argv) < 6
            or argv[0] != str(config.xpra_binary)
            or argv[1] != str(config.xpra_program)
            or argv[2] != "start"
            or argv[3] != f":{config.display_number}"):
        raise _deny()
    bind_values = [arg for arg in argv[4:] if arg.startswith("--bind-tcp=")]
    if (len(bind_values) != 1
            or bind_values[0] != "--bind-tcp=127.0.0.1:14500,auth=http-header:property=X-Forwarded-Proto,value=https"):
        raise _deny()
    # The patched, pinned command module needs commands=yes to launch the one
    # fixed child. It keeps direct client command starts/signals unavailable
    # while start-new-commands=no; all non-child startup options stay absent.
    required_disabled = {
        "--daemon=no", "--systemd-run=no", "--bind=none", "--html=on",
        "--remote-logging=no",
        "--start-new-commands=no", "--exit-with-children=yes", "--terminate-children=yes",
        "--shell=no", "--control=no", "--audio=no", "--tray=no",
        "--clipboard=no", "--speaker=off", "--microphone=off", "--webcam=no",
        "--file-transfer=no", "--printing=no", "--open-files=no", "--open-url=no",
        "--forward-xdg-open=no", "--notifications=no", "--system-tray=no",
        "--sharing=no", "--mdns=no", "--dbus=no", "--dbus-control=no",
        "--dbus-launch=", "--http-scripts=off",
    }
    if not required_disabled.issubset(argv[4:]):
        raise _deny()
    if (argv[4:].count("--commands=yes") != 1
            or argv[4:].count("--start-new-commands=no") != 1):
        raise _deny()
    app_child = "--start-child=/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir/Hermes"
    start_children = [arg for arg in argv[4:] if arg.startswith("--start-child=")]
    if start_children != [app_child]:
        raise _deny()
    allowed_start_options = {app_child, "--start-new-commands=no"}
    if any(arg.startswith("--start") and arg not in allowed_start_options for arg in argv[4:]):
        raise _deny()
    xvfb_values = [arg for arg in argv[4:] if arg.startswith("--xvfb=")]
    if len(xvfb_values) != 1 or not xvfb_values[0].startswith("--xvfb=/usr/bin/Xvfb"):
        raise _deny()
    forbidden_prefixes = ("--source-start", "--exec-wrapper", "--bind-tcp=0.0.0.0",
                          "--bind-tcp=::", "--bind=0.0.0.0", "--bind=::")
    if any(any(arg.startswith(prefix) for prefix in forbidden_prefixes) for arg in argv[4:]):
        raise _deny()
    return digest


def _listener_owned_by(pid: int) -> bool:
    expected = f"0100007F:{XPRA_PORT:04X}"
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) > 9 and fields[1] == expected and fields[3] == "0A":
            inodes.add(fields[9])
    for entry in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(entry)
            if target.startswith("socket:[") and target[8:-1] in inodes:
                return True
        except OSError:
            continue
    return False


def observe_stage(config: Any, *, nonce: str) -> dict[str, Any]:
    """Observe exact configured state using only fixed commands and root-owned paths."""
    started = time.monotonic()
    deadline = started + OBSERVATION_SECONDS
    from .manual_stage import _read_config_current
    _read_config_current(config)
    if (not isinstance(nonce, str) or len(nonce) != 64
            or any(c not in "0123456789abcdef" for c in nonce)
            or os.geteuid() != 0):
        raise _deny()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if (not re.fullmatch(r"[0-9a-f-]{36}", boot_id)
            or boot_id != config.boot_id):
        raise _deny()
    table = _run_fixed(("/usr/sbin/nft", "-j", "-n", "list", "table", TABLE_FAMILY, TABLE_NAME), deadline=deadline)
    _validate_nft(table, config.gateway_uid)
    props = _parse_props(_run_fixed(("/usr/bin/systemctl", "show", DISPLAY_UNIT, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID",
        "--property=InvocationID", "--property=ControlGroup", "--property=User", "--property=FragmentPath",
        "--property=DropInPaths"),
        deadline=deadline, maximum=8192))
    pid = int(props.get("MainPID", "0"))
    if (config.unit_fragment != DISPLAY_UNIT_PATH
            or props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
            or props.get("SubState") != "running" or props.get("FragmentPath") != str(config.unit_fragment)
            or props.get("DropInPaths") != ""
            or props.get("ControlGroup") != f"/system.slice/{DISPLAY_UNIT}"
            or props.get("User") not in {str(config.xpra_uid), "hermes-xpra-stage"}
            or not props.get("InvocationID") or pid <= 1):
        raise _deny()
    pidfd = os.pidfd_open(pid, 0)
    try:
        start_ticks = _pid_start_ticks(pid)
        cgroup = Path(f"/proc/{pid}/cgroup").read_text()
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        if (int(uid_line.split()[1]) != config.xpra_uid or
                f"0::{props['ControlGroup']}" not in cgroup.splitlines()):
            raise _deny()
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        if (str(executable) != str(config.xpra_binary)
                or _hash_path(executable) != config.xpra_binary_sha256
                or _hash_path(config.xpra_program) != config.xpra_program_sha256):
            raise _deny()
        _require_xpra_config_isolated_environment(pid)
        argv_digest = _validate_xpra_argv(config, pid)
        if not _listener_owned_by(pid):
            raise _deny()
        if _hash_path(config.unit_fragment, require_root_readonly=True) != config.unit_sha256:
            raise _deny()
        xpra_pinned_modules_digest = _verify_pinned_xpra_modules()
        app_digest = _check_immutable_tree(config.appdir, config.appdir_manifest_sha256)
        _require_xpra_config_isolated_environment(pid)
        if _pid_start_ticks(pid) != start_ticks or _pidfd_exited(pidfd):
            raise _deny()
    finally:
        os.close(pidfd)
    if time.monotonic() >= deadline:
        raise _deny()
    proof = hashlib.sha256(b"hermes-manual-stage-inspection-v1\0" + b"\0".join((
        config.config_sha256.encode(), hashlib.sha256(table).hexdigest().encode(),
        props["InvocationID"].encode(), str(pid).encode(), start_ticks.encode(),
        argv_digest.encode(), b"xpra-config-search-dirs-disabled",
        xpra_pinned_modules_digest.encode(), app_digest.encode(),
        boot_id.encode(), nonce.encode()))).hexdigest()
    return {"schema": 1, "nonce": nonce, "proof_sha256": proof,
            "boot_id": boot_id, "issued_monotonic": started,
            "expires_monotonic": min(deadline, time.monotonic() + OBSERVATION_SECONDS)}


def _authenticate_gateway_inspector_peer(config: Any, *, pid: int, uid: int, gid: int,
                                         deadline: float) -> tuple[int, str]:
    if (type(pid) is not int or pid <= 1 or type(uid) is not int or type(gid) is not int
            or (uid, gid) != (config.gateway_uid, config.gateway_gid)):
        raise _deny()
    identity = _fixed_process(config, unit=GATEWAY_UNIT, expected_pid=pid,
        expected_uid=config.gateway_uid, expected_gid=config.gateway_gid,
        executable=GATEWAY_EXECUTABLE, executable_sha256=GATEWAY_EXECUTABLE_SHA256,
        argv_expected=GATEWAY_ARGV, deadline=deadline)
    return identity[0], identity[3]


def _native_response(config: Any, *, nonce: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": 2, "nonce": nonce, "config_sha256": config.config_sha256,
        "boot_id": snapshot["boot_id"],
        "native_observation_sha256": snapshot["native_observation_sha256"],
        "issued_monotonic": snapshot["issued_monotonic"],
        "expires_monotonic": snapshot["expires_monotonic"],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    body["proof_sha256"] = hashlib.sha256(
        b"hermes-manual-stage-native-observation-v264\0" + canonical).hexdigest()
    return body


def observe_current_native_observation(config: Any, *, nonce: str, caller_pid: int,
                                       caller_uid: int, caller_gid: int) -> dict[str, Any]:
    """Join fresh cheap root observations to one native fullscan within its original lease."""
    global _NATIVE_OBSERVATION_SNAPSHOT, _NATIVE_OBSERVATION_SCAN_RUNNING
    if (os.geteuid() != 0 or type(nonce) is not str or not re.fullmatch(r"[0-9a-f]{64}", nonce)):
        raise _deny()
    request_started = time.monotonic()
    request_deadline = request_started + MAX_INSPECTION_QUEUE_WAIT_SECONDS
    gateway_pidfd = -1
    try:
        from .manual_stage import _read_config_current
        _read_config_current(config)
        gateway_pidfd, gateway_start = _authenticate_gateway_inspector_peer(
            config, pid=caller_pid, uid=caller_uid, gid=caller_gid, deadline=request_deadline)
        while True:
            if time.monotonic() >= request_deadline:
                raise _deny()
            current_key, xpra_pid, boot_id = _native_currentness_key(config, deadline=request_deadline)
            with _NATIVE_OBSERVATION_CONDITION:
                now = time.monotonic()
                snapshot = _NATIVE_OBSERVATION_SNAPSHOT
                if snapshot is not None and (
                        snapshot["key"] != current_key or snapshot["boot_id"] != boot_id
                        or snapshot["config_sha256"] != config.config_sha256
                        or snapshot["expires_monotonic"] - now
                            <= _NATIVE_OBSERVATION_MIN_REMAINING_SECONDS):
                    _NATIVE_OBSERVATION_SNAPSHOT = None
                    snapshot = None
                if snapshot is not None:
                    if (_pid_start_ticks(caller_pid) != gateway_start or _pidfd_exited(gateway_pidfd)
                            or time.monotonic() >= request_deadline):
                        raise _deny()
                    return _native_response(config, nonce=nonce, snapshot=snapshot)
                if _NATIVE_OBSERVATION_SCAN_RUNNING:
                    remaining = request_deadline - now
                    if remaining <= 0:
                        raise _deny()
                    _NATIVE_OBSERVATION_CONDITION.wait(timeout=remaining)
                    continue
                _NATIVE_OBSERVATION_SCAN_RUNNING = True
                _NATIVE_OBSERVATION_SNAPSHOT = None
                break

        try:
            # Full native custody scan keeps its own true start and <=5s expiry.
            full = observe_stage(config, nonce=nonce)
            after_key, after_pid, after_boot = _native_currentness_key(config, deadline=request_deadline)
            completed = time.monotonic()
            if (after_key != current_key or after_pid != xpra_pid or after_boot != boot_id
                    or full.get("schema") != 1 or full.get("nonce") != nonce
                    or full.get("boot_id") != boot_id
                    or not _is_sha256(full.get("proof_sha256"))
                    or type(full.get("issued_monotonic")) not in (int, float)
                    or type(full.get("expires_monotonic")) not in (int, float)
                    or full["issued_monotonic"] > completed
                    or full["expires_monotonic"] <= completed + _NATIVE_OBSERVATION_MIN_REMAINING_SECONDS
                    or full["expires_monotonic"] > full["issued_monotonic"] + OBSERVATION_SECONDS
                    or time.monotonic() >= request_deadline
                    or _pid_start_ticks(caller_pid) != gateway_start or _pidfd_exited(gateway_pidfd)):
                raise _deny()
            snapshot = {
                "key": current_key, "config_sha256": config.config_sha256,
                "boot_id": boot_id, "native_observation_sha256": full["proof_sha256"],
                "issued_monotonic": full["issued_monotonic"],
                "expires_monotonic": full["expires_monotonic"],
            }
            with _NATIVE_OBSERVATION_CONDITION:
                _NATIVE_OBSERVATION_SNAPSHOT = snapshot
            return _native_response(config, nonce=nonce, snapshot=snapshot)
        finally:
            with _NATIVE_OBSERVATION_CONDITION:
                _NATIVE_OBSERVATION_SCAN_RUNNING = False
                _NATIVE_OBSERVATION_CONDITION.notify_all()
    except Exception:
        with _NATIVE_OBSERVATION_CONDITION:
            _NATIVE_OBSERVATION_SNAPSHOT = None
            _NATIVE_OBSERVATION_CONDITION.notify_all()
        raise _deny() from None
    finally:
        if gateway_pidfd >= 0:
            os.close(gateway_pidfd)


def observe_current_ingress(config: Any, *, nonce: str, caller_pid: int,
                            caller_uid: int, caller_gid: int, peer_pid: int,
                            peer_uid: int, peer_gid: int) -> dict[str, Any]:
    """Independently prove the current fixed Gateway caller and Cloudflared peer."""
    issued = time.monotonic()
    deadline = issued + _INGRESS_REQUEST_DEADLINE_SECONDS
    pidfds: list[int] = []
    try:
        from .manual_stage import _read_config_current
        if (os.geteuid() != 0 or type(nonce) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or any(type(value) is not int for value in
                       (caller_pid, caller_uid, caller_gid, peer_pid, peer_uid, peer_gid))
                or (caller_uid, caller_gid) != (config.gateway_uid, config.gateway_gid)
                or config.ingress_socket != INGRESS_SOCKET_PATH):
            raise _deny()
        _read_config_current(config)
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", boot_id) or boot_id != config.boot_id:
            raise _deny()
        origin_device, origin_inode = _verify_origin_socket(config)
        gateway = _fixed_process(config, unit=GATEWAY_UNIT, expected_pid=caller_pid,
            expected_uid=config.gateway_uid, expected_gid=config.gateway_gid,
            executable=GATEWAY_EXECUTABLE, executable_sha256=GATEWAY_EXECUTABLE_SHA256,
            argv_expected=GATEWAY_ARGV, deadline=deadline)
        pidfds.append(gateway[0])
        tunnel = _fixed_process(config, unit=TUNNEL_UNIT, expected_pid=peer_pid,
            expected_uid=peer_uid, expected_gid=peer_gid, executable=CLOUDFLARED_PATH,
            executable_sha256=config.cloudflared_binary_sha256, argv_expected=TUNNEL_ARGV,
            deadline=deadline, supplementary_gid=config.gateway_gid, dynamic_user=True)
        pidfds.append(tunnel[0])
        if type(peer_uid) is not int or type(peer_gid) is not int:
            raise _deny()
        # Re-read authority inputs after all procfs/systemd inspection.
        _read_config_current(config)
        if (Path("/proc/sys/kernel/random/boot_id").read_text().strip() != boot_id
                or _verify_origin_socket(config) != (origin_device, origin_inode)
                or _pid_start_ticks(caller_pid) != gateway[3]
                or _pid_start_ticks(peer_pid) != tunnel[3]
                or _pidfd_exited(gateway[0]) or _pidfd_exited(tunnel[0])
                or time.monotonic() >= deadline):
            raise _deny()
        expires = issued + _INGRESS_PROOF_TTL_SECONDS
        body: dict[str, Any] = {
            "schema": 1, "nonce": nonce, "boot_id": boot_id,
            "issued_monotonic": issued, "expires_monotonic": expires,
            "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid,
            "peer_start_ticks": tunnel[3],
            "tunnel_unit_sha256": config.tunnel_unit_sha256,
            "tunnel_config_sha256": _tunnel_config_digest(config),
            "tunnel_executable_sha256": config.cloudflared_binary_sha256,
            "origin_socket_device": origin_device, "origin_socket_inode": origin_inode,
            "config_sha256": config.config_sha256,
        }
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode("ascii")
        body["proof_sha256"] = hashlib.sha256(
            b"hermes-jarvis-mvp-ingress-observation-v263\0" + canonical).hexdigest()
        if len(json.dumps(body, separators=(",", ":")).encode("ascii")) > INGRESS_MAX_RESPONSE:
            raise _deny()
        return body
    except Exception:
        raise _deny() from None
    finally:
        for pidfd in pidfds:
            os.close(pidfd)


def _verify_pinned_xpra_modules() -> str:
    binding = []
    if (len(XPRA_PINNED_MODULES) != 4
            or len({row[0] for row in XPRA_PINNED_MODULES}) != 4):
        raise _deny()
    for path, size, expected_digest in XPRA_PINNED_MODULES:
        digest = _hash_path(path, expected_size=size, require_root_readonly=True)
        if digest != expected_digest:
            raise _deny()
        binding.extend((str(path).encode("ascii"), str(size).encode("ascii"), digest.encode("ascii")))
    return hashlib.sha256(b"hermes-xpra-pinned-modules-v262\0" + b"\0".join(binding)).hexdigest()


def _native_currentness_key(config: Any, *, deadline: float) -> tuple[str, int, str]:
    """Fresh cheap joins for a retained full scan; deliberately excludes AppDir member hashing."""
    from .manual_stage import _read_config_current
    _read_config_current(config)
    if config.unit_fragment != DISPLAY_UNIT_PATH:
        raise _deny()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if boot_id != config.boot_id or not re.fullmatch(r"[0-9a-f-]{36}", boot_id):
        raise _deny()
    table = _run_fixed(("/usr/sbin/nft", "-j", "-n", "list", "table", TABLE_FAMILY,
                        TABLE_NAME), deadline=deadline)
    _validate_nft(table, config.gateway_uid)
    props = _parse_props(_run_fixed(("/usr/bin/systemctl", "show", DISPLAY_UNIT, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID",
        "--property=InvocationID", "--property=ControlGroup", "--property=User", "--property=FragmentPath",
        "--property=DropInPaths"), deadline=deadline, maximum=8192))
    try:
        pid = int(props["MainPID"])
        if (props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
                or props.get("SubState") != "running" or props.get("DropInPaths") != ""
                or props.get("FragmentPath") != str(config.unit_fragment)
                or props.get("ControlGroup") != f"/system.slice/{DISPLAY_UNIT}"
                or props.get("User") not in {str(config.xpra_uid), "hermes-xpra-stage"}
                or not props.get("InvocationID") or pid <= 1):
            raise ValueError
        pidfd = os.pidfd_open(pid, 0)
    except Exception:
        raise _deny() from None
    try:
        started_ticks = _pid_start_ticks(pid)
        cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        status = Path(f"/proc/{pid}/status").read_text()
        uid = next(row for row in status.splitlines() if row.startswith("Uid:")).split()
        if (int(uid[1]) != config.xpra_uid or f"0::{props['ControlGroup']}" not in cgroup
                or Path(f"/proc/{pid}/exe").resolve(strict=True) != config.xpra_binary
                or _hash_path(config.xpra_binary) != config.xpra_binary_sha256
                or _hash_path(config.xpra_program) != config.xpra_program_sha256):
            raise _deny()
        _require_xpra_config_isolated_environment(pid)
        argv_digest = _validate_xpra_argv(config, pid)
        if not _listener_owned_by(pid):
            raise _deny()
        if _hash_path(config.unit_fragment, require_root_readonly=True) != config.unit_sha256:
            raise _deny()
        module_digest = _verify_pinned_xpra_modules()
        appdir_custody = _appdir_manifest_custody(config.appdir, config.appdir_manifest_sha256)
        if (_pid_start_ticks(pid) != started_ticks or _pidfd_exited(pidfd)
                or time.monotonic() >= deadline):
            raise _deny()
        identity = {
            "appdir_custody": list(appdir_custody), "argv_sha256": argv_digest,
            "boot_id": boot_id, "config_sha256": config.config_sha256,
            "firewall_sha256": hashlib.sha256(table).hexdigest(),
            "invocation_id": props["InvocationID"], "module_sha256": module_digest,
            "pid": pid, "pid_start_ticks": started_ticks,
            "unit_sha256": config.unit_sha256,
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode("ascii")
        return hashlib.sha256(b"hermes-manual-stage-native-currentness-v264\0" + canonical).hexdigest(), pid, boot_id
    finally:
        os.close(pidfd)


def _hash_path(path: Path, *, expected_size: int | None = None,
               require_root_readonly: bool = False) -> str:
    parent_fd = None
    if require_root_readonly:
        allowed = {row[0] for row in XPRA_PINNED_MODULES} | {
            GATEWAY_UNIT_PATH, TUNNEL_UNIT_PATH, CLOUDFLARED_PATH, GATEWAY_EXECUTABLE,
            DISPLAY_UNIT_PATH,
        }
        if path not in allowed or not path.is_absolute():
            raise _deny()
        try:
            parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                getattr(os, "O_NOFOLLOW", 0))
            root_info = os.fstat(parent_fd)
            if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0:
                raise _deny()
            for component in path.parts[1:-1]:
                next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                                   getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
                info = os.fstat(next_fd)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                        or stat.S_IMODE(info.st_mode) & 0o022):
                    os.close(next_fd)
                    raise _deny()
                os.close(parent_fd)
                parent_fd = next_fd
            fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        except StageInspectionDenied:
            if parent_fd is not None:
                os.close(parent_fd)
            raise
        except OSError:
            if parent_fd is not None:
                os.close(parent_fd)
            raise _deny() from None
    else:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise _deny()
        if expected_size is not None and info.st_size != expected_size:
            raise _deny()
        if require_root_readonly and info.st_nlink != 1:
            raise _deny()
        digest = hashlib.sha256()
        while True:
            data = os.read(fd, 65_536)
            if not data:
                break
            digest.update(data)
        return digest.hexdigest()
    finally:
        os.close(fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _pidfd_exited(fd: int) -> bool:
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def serve_inspection_socket(config: Any) -> None:
    """Root-only, fixed-path, read-only one-request Unix socket server."""
    if os.geteuid() != 0:
        raise StageInspectionDenied("stage inspector must run as root")
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        raise StageInspectionDenied("stage inspector socket path already exists")
    SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    parent_info = os.lstat(SOCKET_PATH.parent)
    if stat.S_ISDIR(parent_info.st_mode) and parent_info.st_uid == 0 and parent_info.st_gid == 0:
        os.chown(SOCKET_PATH.parent, 0, config.gateway_gid)
        os.chmod(SOCKET_PATH.parent, 0o750)
        parent_info = os.lstat(SOCKET_PATH.parent)
    if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
            or parent_info.st_gid != config.gateway_gid or stat.S_IMODE(parent_info.st_mode) != 0o750):
        raise StageInspectionDenied("stage inspector runtime directory ownership differs")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    socket_identity = None
    stopped = False
    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    def stop(_signum, _frame):
        nonlocal stopped
        stopped = True
    try:
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        server.bind(str(SOCKET_PATH))
        bound_info = os.lstat(SOCKET_PATH)
        socket_identity = (bound_info.st_dev, bound_info.st_ino)
        os.chown(SOCKET_PATH, 0, config.gateway_gid)
        os.chmod(SOCKET_PATH, 0o660)
        server.listen(16)
        server.settimeout(1)
        def serve_one(conn: socket.socket) -> None:
            acquired: threading.BoundedSemaphore | None = None
            try:
                conn.settimeout(1)
                if not hasattr(socket, "SO_PEERCRED"):
                    return
                caller_pid, caller_uid, caller_gid = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if caller_uid != config.gateway_uid or caller_pid <= 1:
                    return
                frame_deadline = time.monotonic() + 1.5
                header = _read_exact(conn, 4, deadline=frame_deadline)
                length = struct.unpack("!I", header)[0]
                if not 2 <= length <= MAX_REQUEST:
                    return
                request = json.loads(_read_exact(conn, length, deadline=frame_deadline).decode("ascii"),
                                     object_pairs_hook=_unique_pairs)
                if not isinstance(request, dict) or not isinstance(request.get("op"), str):
                    return
                if request["op"] == "observe-ingress":
                    acquired = _INGRESS_SERVER_SLOTS
                    expected = {"op", "nonce", "peer_pid", "peer_uid", "peer_gid"}
                    if set(request) != expected:
                        acquired = None
                        return
                    if not acquired.acquire(blocking=False):
                        acquired = None
                        return
                    result = observe_current_ingress(config, nonce=request["nonce"],
                        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                        peer_pid=request["peer_pid"], peer_uid=request["peer_uid"],
                        peer_gid=request["peer_gid"])
                elif request["op"] == "observe":
                    acquired = _OBSERVATION_SERVER_SLOTS
                    if set(request) != {"op", "nonce"} or caller_uid != config.gateway_uid:
                        acquired = None
                        return
                    if not acquired.acquire(blocking=False):
                        acquired = None
                        return
                    result = observe_current_native_observation(config, nonce=request["nonce"],
                        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid)
                else:
                    return
                raw = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                 allow_nan=False).encode("ascii")
                limit = INGRESS_MAX_RESPONSE if request["op"] == "observe-ingress" else MAX_RESPONSE
                response_deadline = frame_deadline + (MAX_INSPECTION_QUEUE_WAIT_SECONDS
                    if request["op"] == "observe" else 1.0)
                if len(raw) <= limit and time.monotonic() < response_deadline:
                    conn.sendall(struct.pack("!I", len(raw)) + raw)
            except Exception:
                return
            finally:
                if acquired is not None:
                    acquired.release()
                conn.close()
                _SERVER_CONNECTION_SLOTS.release()

        while not stopped:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            if not _SERVER_CONNECTION_SLOTS.acquire(blocking=False):
                conn.close()
                continue
            worker = threading.Thread(target=serve_one, args=(conn,), daemon=True)
            try:
                worker.start()
            except Exception:
                conn.close()
                _SERVER_CONNECTION_SLOTS.release()
    finally:
        server.close()
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)
        try:
            current = os.lstat(SOCKET_PATH)
            if socket_identity == (current.st_dev, current.st_ino) and stat.S_ISSOCK(current.st_mode):
                SOCKET_PATH.unlink()
        except OSError:
            pass


def _read_exact(conn: socket.socket, count: int, *, deadline: float | None = None) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn.settimeout(remaining)
        part = conn.recv(count - len(buf))
        if not part:
            raise OSError("short frame")
        buf.extend(part)
    return bytes(buf)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def verify_current_ingress(config: Any, *, peer_pid: int, peer_uid: int,
                           peer_gid: int) -> StageVerifiedIngressObservation:
    """Return a sealed one-request proof that this accepted AF_UNIX peer is live Cloudflared."""
    from .manual_stage import _read_config_current
    nonce = os.urandom(32).hex()
    deadline = time.monotonic() + _INGRESS_REQUEST_DEADLINE_SECONDS
    try:
        _read_config_current(config)
        path = config.ingress_socket
        if path != INGRESS_SOCKET_PATH:
            raise ValueError
        info = os.lstat(SOCKET_PATH)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
            raise ValueError
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(_INGRESS_REQUEST_DEADLINE_SECONDS)
        conn.connect(str(SOCKET_PATH))
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
                "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if inspector_uid != 0 or inspector_pid <= 1:
                raise ValueError
            payload = json.dumps({"op": "observe-ingress", "nonce": nonce,
                "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid},
                sort_keys=True, separators=(",", ":")).encode("ascii")
            if len(payload) > MAX_REQUEST:
                raise ValueError
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn.settimeout(remaining)
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", _read_exact(conn, 4, deadline=deadline))[0]
            if not 2 <= length <= INGRESS_MAX_RESPONSE:
                raise ValueError
            result = json.loads(_read_exact(conn, length, deadline=deadline).decode("ascii"),
                                object_pairs_hook=_unique_pairs)
        finally:
            conn.close()
        fields = {"schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
            "peer_pid", "peer_uid", "peer_gid", "peer_start_ticks", "tunnel_unit_sha256",
            "tunnel_config_sha256", "tunnel_executable_sha256", "origin_socket_device",
            "origin_socket_inode", "config_sha256", "proof_sha256"}
        if not isinstance(result, dict) or set(result) != fields:
            raise ValueError
        now = time.monotonic()
        local_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        numbers = ("issued_monotonic", "expires_monotonic")
        if any(type(result[name]) not in (int, float) or not __import__("math").isfinite(result[name])
               for name in numbers):
            raise ValueError
        int_fields = ("schema", "peer_pid", "peer_uid", "peer_gid", "origin_socket_device", "origin_socket_inode")
        if any(type(result[name]) is not int for name in int_fields):
            raise ValueError
        expected_fields = {
            "schema": 1, "nonce": nonce, "boot_id": local_boot_id,
            "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid,
            "tunnel_unit_sha256": config.tunnel_unit_sha256,
            "tunnel_config_sha256": _tunnel_config_digest(config),
            "tunnel_executable_sha256": config.cloudflared_binary_sha256,
            "config_sha256": config.config_sha256,
        }
        if any(result[key] != value for key, value in expected_fields.items()):
            raise ValueError
        if (not re.fullmatch(r"[0-9a-f-]{36}", local_boot_id)
                or not isinstance(result["peer_start_ticks"], str)
                or not result["peer_start_ticks"].isdecimal()
                or result["peer_pid"] <= 1 or result["peer_uid"] < 0 or result["peer_gid"] < 0
                or result["origin_socket_device"] < 0 or result["origin_socket_inode"] <= 0
                or result["issued_monotonic"] > now or result["expires_monotonic"] <= now
                or result["expires_monotonic"] - result["issued_monotonic"] > _INGRESS_PROOF_TTL_SECONDS
                or now >= deadline):
            raise ValueError
        for name in ("tunnel_unit_sha256", "tunnel_config_sha256", "tunnel_executable_sha256",
                     "config_sha256", "proof_sha256"):
            if not _is_sha256(result[name]):
                raise ValueError
        body = {key: value for key, value in result.items() if key != "proof_sha256"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode("ascii")
        expected_proof = hashlib.sha256(
            b"hermes-jarvis-mvp-ingress-observation-v263\0" + canonical).hexdigest()
        if result["proof_sha256"] != expected_proof:
            raise ValueError
        observation = StageVerifiedIngressObservation(**result, _seal=_OBSERVATION_SEAL)
        if not observation.verify_current(config, peer_pid, peer_uid, peer_gid, now=now):
            raise ValueError
        return observation
    except Exception:
        raise StageInspectionDenied("root current-ingress proof is unavailable or stale") from None


def verify_current_inspection(config: Any, *, queue_timeout_seconds: float = MAX_INSPECTION_QUEUE_WAIT_SECONDS) -> StageNativeInspectionObservation:
    """Request a fresh per-call join to the root's original short native observation."""
    if (type(queue_timeout_seconds) not in (int, float)
            or not 0.05 <= queue_timeout_seconds <= MAX_INSPECTION_QUEUE_WAIT_SECONDS):
        raise StageInspectionDenied("root manual-stage proof queue bound is invalid")
    return _request_current_inspection(config, queue_timeout_seconds=queue_timeout_seconds)


def _request_current_inspection(config: Any, *, queue_timeout_seconds: float) -> StageNativeInspectionObservation:
    """Perform one nonce-bound IPC; root bounds singleflight and does not extend expiry."""
    nonce = os.urandom(32).hex()
    try:
        from .manual_stage import _read_config_current
        _read_config_current(config)
        info = os.lstat(SOCKET_PATH)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
            raise ValueError
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Retain the former independent 2s IPC budget after the client lock was
        # removed; the queue argument remains an additive bounded allowance.
        ipc_budget = min(INSPECTION_IPC_TIMEOUT_SECONDS + queue_timeout_seconds, 3.0)
        deadline = time.monotonic() + ipc_budget
        conn.settimeout(ipc_budget)
        conn.connect(str(SOCKET_PATH))
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            payload = json.dumps({"op": "observe", "nonce": nonce}, sort_keys=True,
                                 separators=(",", ":")).encode("ascii")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            conn.settimeout(remaining)
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", _read_exact(conn, 4, deadline=deadline))[0]
            if not 2 <= length <= MAX_RESPONSE:
                raise ValueError
            result = json.loads(_read_exact(conn, length, deadline=deadline).decode("ascii"),
                                object_pairs_hook=_unique_pairs)
        finally:
            conn.close()
        if not isinstance(result, dict) or set(result) != {
                "schema", "nonce", "config_sha256", "boot_id", "native_observation_sha256",
                "issued_monotonic", "expires_monotonic", "proof_sha256"}:
            raise ValueError
        now = time.monotonic()
        local_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if (type(result["schema"]) is not int or result["schema"] != 2
                or result["nonce"] != nonce or result["config_sha256"] != config.config_sha256
                or result["boot_id"] != local_boot_id
                or not re.fullmatch(r"[0-9a-f-]{36}", local_boot_id)
                or not _is_sha256(result["config_sha256"])
                or not _is_sha256(result["native_observation_sha256"])
                or not _is_sha256(result["proof_sha256"])
                or type(result["issued_monotonic"]) not in (int, float)
                or type(result["expires_monotonic"]) not in (int, float)
                or not math.isfinite(result["issued_monotonic"])
                or not math.isfinite(result["expires_monotonic"])
                or result["issued_monotonic"] > now or result["expires_monotonic"] <= now
                or result["expires_monotonic"] > result["issued_monotonic"] + OBSERVATION_SECONDS
                or time.monotonic() >= deadline):
            raise ValueError
        body = {key: value for key, value in result.items() if key != "proof_sha256"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"),
                               allow_nan=False).encode("ascii")
        expected = hashlib.sha256(
            b"hermes-manual-stage-native-observation-v264\0" + canonical).hexdigest()
        if result["proof_sha256"] != expected:
            raise ValueError
        observation = StageNativeInspectionObservation(
            config_sha256=result["config_sha256"], boot_id=result["boot_id"],
            native_observation_sha256=result["native_observation_sha256"], nonce=result["nonce"],
            issued_monotonic=result["issued_monotonic"], expires_monotonic=result["expires_monotonic"],
            _seal=_NATIVE_OBSERVATION_SEAL)
        completed = time.monotonic()
        if completed >= deadline or not observation.verify_current(config, now=completed):
            raise ValueError
        return observation
    except Exception:
        raise StageInspectionDenied("root manual-stage proof is unavailable or stale") from None


def main() -> None:
    from .manual_stage import ManualGatewayStageConfig
    serve_inspection_socket(ManualGatewayStageConfig.load())


if __name__ == "__main__":
    main()
