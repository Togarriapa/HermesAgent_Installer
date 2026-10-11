"""Fixed read-only root inspector for the manually owned Jarvis MVP stage.

This is a finite local observation helper, not installer authority: it cannot
start services, change nftables, choose a unit/path, or mint a runtime receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import select
import signal
import socket
import stat
import struct
import subprocess
import time
from pathlib import Path, PurePosixPath
from typing import Any

SOCKET_PATH = Path("/run/hermes-jarvis-mvp/inspection.sock")
TABLE_FAMILY, TABLE_NAME, CHAIN_NAME = "inet", "hermes_jarvis_mvp", "output"
DISPLAY_UNIT = "hermes-xpra-stage.service"
MAX_REQUEST = 1024
MAX_RESPONSE = 1024
MAX_OUTPUT = 65_536
OBSERVATION_SECONDS = 5.0


class StageInspectionDenied(PermissionError):
    pass


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
                                or stat.S_IMODE(file_info.st_mode) & 0o022 or file_info.st_size > 64 * 1024 * 1024):
                            raise ValueError
                        total_size += file_info.st_size
                        if total_size > 2 * 1024 * 1024 * 1024:
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
    # No user-controlled command launching or remote filesystem/audio devices.
    # These exact disabled flags are part of the root-reviewed argv digest.
    required_disabled = {
        "--start-new-commands=no", "--clipboard=no", "--speaker=off",
        "--microphone=off", "--webcam=no", "--file-transfer=no",
        "--printing=no", "--open-files=no", "--open-url=no",
    }
    if not required_disabled.issubset(argv[4:]):
        raise _deny()
    forbidden_prefixes = ("--start=", "--start-child=", "--exec-wrapper=", "--bind-tcp=0.0.0.0",
                          "--bind-tcp=::", "--bind=0.0.0.0", "--bind=::")
    if any(any(arg.startswith(prefix) for prefix in forbidden_prefixes) for arg in argv[4:]):
        raise _deny()
    return digest


def _listener_owned_by(pid: int) -> bool:
    expected = "0100007F:38B4"  # 127.0.0.1:14500
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
    if Path("/proc/sys/kernel/random/boot_id").read_text().strip() != config.boot_id:
        raise _deny()
    table = _run_fixed(("/usr/sbin/nft", "-j", "-n", "list", "table", TABLE_FAMILY, TABLE_NAME), deadline=deadline)
    _validate_nft(table, config.gateway_uid)
    props = _parse_props(_run_fixed(("/usr/bin/systemctl", "show", DISPLAY_UNIT, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState", "--property=MainPID",
        "--property=InvocationID", "--property=ControlGroup", "--property=User", "--property=FragmentPath"),
        deadline=deadline, maximum=8192))
    pid = int(props.get("MainPID", "0"))
    if (props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
            or props.get("SubState") != "running" or props.get("FragmentPath") != str(config.unit_fragment)
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
        argv_digest = _validate_xpra_argv(config, pid)
        if not _listener_owned_by(pid):
            raise _deny()
        if _hash_path(config.unit_fragment) != config.unit_sha256:
            raise _deny()
        app_digest = _check_immutable_tree(config.appdir, config.appdir_manifest_sha256)
        if _pid_start_ticks(pid) != start_ticks or _pidfd_exited(pidfd):
            raise _deny()
    finally:
        os.close(pidfd)
    if time.monotonic() >= deadline:
        raise _deny()
    proof = hashlib.sha256(b"hermes-manual-stage-inspection-v1\0" + b"\0".join((
        config.config_sha256.encode(), hashlib.sha256(table).hexdigest().encode(),
        props["InvocationID"].encode(), str(pid).encode(), start_ticks.encode(),
        argv_digest.encode(), app_digest.encode(), config.boot_id.encode(), nonce.encode()))).hexdigest()
    return {"schema": 1, "nonce": nonce, "proof_sha256": proof,
            "issued_monotonic": started, "expires_monotonic": min(deadline, time.monotonic() + OBSERVATION_SECONDS)}


def _hash_path(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
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
        while not stopped:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            with conn:
                conn.settimeout(1)
                if not hasattr(socket, "SO_PEERCRED"):
                    continue
                pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if uid != config.gateway_uid or pid <= 1:
                    continue
                try:
                    frame_deadline = time.monotonic() + 2.0
                    header = _read_exact(conn, 4, deadline=frame_deadline)
                    length = struct.unpack("!I", header)[0]
                    if not 2 <= length <= MAX_REQUEST:
                        continue
                    request = json.loads(_read_exact(conn, length, deadline=frame_deadline).decode("ascii"),
                                         object_pairs_hook=_unique_pairs)
                    if (not isinstance(request, dict) or set(request) != {"op", "nonce"}
                            or request["op"] != "observe"):
                        continue
                    result = observe_stage(config, nonce=request["nonce"])
                    raw = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("ascii")
                    if len(raw) <= MAX_RESPONSE:
                        conn.sendall(struct.pack("!I", len(raw)) + raw)
                except Exception:
                    continue
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


def verify_current_inspection(config: Any) -> str:
    """Ask the root-only inspector for a fresh exact-state observation."""
    nonce = os.urandom(32).hex()
    try:
        info = os.lstat(SOCKET_PATH)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
            raise ValueError
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(2.0)
        conn.connect(str(SOCKET_PATH))
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            payload = json.dumps({"op": "observe", "nonce": nonce}, sort_keys=True,
                                 separators=(",", ":")).encode("ascii")
            conn.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", _read_exact(conn, 4))[0]
            if not 2 <= length <= MAX_RESPONSE:
                raise ValueError
            result = json.loads(_read_exact(conn, length).decode("ascii"), object_pairs_hook=_unique_pairs)
        finally:
            conn.close()
        if not isinstance(result, dict) or set(result) != {
                "schema", "nonce", "proof_sha256", "issued_monotonic", "expires_monotonic"}:
            raise ValueError
        now = time.monotonic()
        if (result["schema"] != 1 or result["nonce"] != nonce
                or not isinstance(result["proof_sha256"], str) or len(result["proof_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in result["proof_sha256"])
                or type(result["issued_monotonic"]) not in (int, float)
                or type(result["expires_monotonic"]) not in (int, float)
                or not __import__("math").isfinite(result["issued_monotonic"])
                or not __import__("math").isfinite(result["expires_monotonic"])
                or result["issued_monotonic"] > now or result["expires_monotonic"] <= now
                or result["expires_monotonic"] > result["issued_monotonic"] + OBSERVATION_SECONDS):
            raise ValueError
        return result["proof_sha256"]
    except Exception:
        raise StageInspectionDenied("root manual-stage proof is unavailable or stale") from None


def main() -> None:
    import argparse
    from .manual_stage import ManualGatewayStageConfig, STAGE_CONFIG
    parser = argparse.ArgumentParser(description="read-only Jarvis manual-stage inspector")
    parser.add_argument("--config", type=Path, default=STAGE_CONFIG)
    args = parser.parse_args()
    serve_inspection_socket(ManualGatewayStageConfig.load(args.config))


if __name__ == "__main__":
    main()
