#!/usr/bin/env python3
"""Fixed pre-application gate for one selected private-loopback worker.

The root custodian bind-mounts a read-only canonical contract at one fixed
path. The helper emits one bounded JSON observation and stops itself; the root
manager resumes its retained PIDFD only after consuming a one-use start grant.
This program intentionally accepts no caller arguments, paths, code strings,
addresses, or ports from argv/environment.
"""
from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import struct
import stat
import sys


MAX_CONTRACT = 16 * 1024
MAX_RESULT = 4 * 1024
MAX_GRANT = 1024
MAX_GATE_FRAME = 8192
GATE_FD = 3
_FRAME = struct.Struct("!I")
CONTRACT_PATH = "/run/hermes-installer/private-loopback/contract.json"
FIELDS = frozenset({
    "schema", "purpose", "nonce", "network_id", "service_generation_digest",
    "enrollment_id", "profile_id", "generation", "uid", "gid",
    "role", "allowed_bind_port", "allowed_connect_port",
    "denied_port", "application_executable", "application_argv",
    "application_environment",
})
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class GateError(Exception):
    pass


def _unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise GateError("contract contains duplicate fields")
        value[key] = item
    return value


def _read_contract():
    fd = -1
    try:
        fd = os.open(CONTRACT_PATH, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        info = os.fstat(fd)
        path_info = os.stat(CONTRACT_PATH, follow_symlinks=False)
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o222
                or flags & os.O_ACCMODE != os.O_RDONLY
                or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)):
            raise GateError("root-owned read-only contract mount is unavailable")
        raw = bytearray()
        while len(raw) <= MAX_CONTRACT:
            block = os.read(fd, min(4096, MAX_CONTRACT + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > MAX_CONTRACT:
            raise GateError("contract exceeds its fixed byte bound")
        value = json.loads(bytes(raw).decode("ascii"), object_pairs_hook=_unique_pairs)
        if (type(value) is not dict or set(value) != FIELDS
                or json.dumps(value, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii") != bytes(raw)):
            raise GateError("contract is not the exact canonical schema")
        return value, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise GateError("root-owned read-only contract could not be verified") from exc
    finally:
        if fd >= 0:
            os.close(fd)


def _validate_contract(row):
    if (type(row["schema"]) is not int or row["schema"] != 2
            or row["purpose"] != "private-loopback-worker-start"
            or not isinstance(row["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", row["nonce"])
            or any(not isinstance(row[name], str) or not _IDENT.fullmatch(row[name])
                   for name in ("network_id", "enrollment_id", "profile_id", "generation"))
            or not isinstance(row["service_generation_digest"], str)
            or not _SHA.fullmatch(row["service_generation_digest"])
            or type(row["uid"]) is not int or type(row["gid"]) is not int
            or row["uid"] <= 0 or row["gid"] <= 0
            or row["role"] not in {"listener", "client", "listener-client", "af-unix"}):
        raise GateError("contract identity fields are invalid")
    for name in ("allowed_bind_port", "allowed_connect_port", "denied_port"):
        value = row[name]
        if value is not None and (type(value) is not int or not 1 <= value <= 65535):
            raise GateError("contract port is invalid")
    listener = row["role"] in {"listener", "listener-client"}
    client = row["role"] in {"client", "listener-client"}
    if (listener != (row["allowed_bind_port"] is not None)
            or client != (row["allowed_connect_port"] is not None)
            or row["denied_port"] is None
            or row["denied_port"] == row["allowed_bind_port"]):
        raise GateError("contract role does not match its finite endpoint selection")
    executable = row["application_executable"]
    argv = row["application_argv"]
    environment = row["application_environment"]
    if (not isinstance(executable, str) or not executable.startswith("/")
            or "\x00" in executable or not isinstance(argv, list) or not argv
            or len(argv) > 64 or argv[0] != executable
            or any(not isinstance(item, str) or "\x00" in item or len(item) > 4096 for item in argv)
            or not isinstance(environment, dict) or len(environment) > 64
            or any(not isinstance(k, str) or not re.fullmatch(r"[A-Z_][A-Z0-9_]{0,63}", k)
                   or not isinstance(v, str) or "\x00" in v or len(v) > 4096
                   for k, v in environment.items())):
        raise GateError("fixed application recipe is malformed")


def _self_identity(contract):
    try:
        status = open("/proc/self/status", "rt", encoding="ascii").read().splitlines()
        caps = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                for line in status if ":" in line}
        cap_values = {name: int(caps[name], 16) for name in
                      ("CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh")}
        if any(cap_values.values()):
            raise GateError("worker gate retains Linux capabilities")
        namespace = os.stat("/proc/self/ns/net")
        if os.getuid() != contract["uid"] or os.getgid() != contract["gid"]:
            raise GateError("worker gate identity differs from the selected UID/GID")
        cgroups = open("/proc/self/cgroup", "rt", encoding="ascii").read().splitlines()
        unified = [line[3:] for line in cgroups if line.startswith("0::")]
        if len(unified) != 1 or not unified[0].startswith("/system.slice/hermes-installer-"):
            raise GateError("worker gate cgroup is not one owned transient service unit")
        stat_row = open("/proc/self/stat", "rt", encoding="ascii").read()
        fields = stat_row[stat_row.rfind(")") + 2:].split()
        if len(fields) <= 19:
            raise GateError("worker gate start-time observation is unavailable")
        return {
            "pid": os.getpid(), "uid": os.getuid(), "gid": os.getgid(),
            "start_ticks": int(fields[19]), "cgroup": unified[0],
            "namespace_device": namespace.st_dev, "namespace_inode": namespace.st_ino,
            "capabilities": cap_values,
        }
    except (OSError, ValueError, KeyError, IndexError, UnicodeError) as exc:
        raise GateError("worker gate process identity could not be observed") from exc


def _bind_probe(address_family, address, port):
    sock = None
    try:
        sock = socket.socket(address_family, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
        sock.bind((address, port))
        return {"outcome": "bound", "errno": None}
    except OSError as exc:
        return {"outcome": "error", "errno": exc.errno}
    finally:
        if sock is not None:
            sock.close()


def _connect_probe(port):
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
        sock.settimeout(0.5)
        sock.connect(("127.0.0.1", port))
        return {"outcome": "connected", "errno": None}
    except OSError as exc:
        return {"outcome": "error", "errno": exc.errno}
    finally:
        if sock is not None:
            sock.close()


def _probe(contract):
    checks = {}
    if contract["allowed_bind_port"] is not None:
        checks["allowed_bind"] = _bind_probe(
            socket.AF_INET, "127.0.0.1", contract["allowed_bind_port"])
    if contract["allowed_connect_port"] is not None:
        checks["allowed_connect"] = _connect_probe(contract["allowed_connect_port"])
    checks["af_unix_control"] = _unix_control_probe(contract)
    checks["wrong_port_bind"] = _bind_probe(
        socket.AF_INET, "127.0.0.1", contract["denied_port"])
    checks["ipv6_bind"] = _bind_probe(
        socket.AF_INET6, "::1", contract["allowed_bind_port"] or contract["denied_port"])
    checks["wildcard_bind"] = _bind_probe(
        socket.AF_INET, "0.0.0.0", contract["allowed_bind_port"] or contract["denied_port"])
    expected = {errno.EACCES, errno.EPERM}
    outcomes = []
    for name in ("wrong_port_bind", "ipv6_bind", "wildcard_bind"):
        probe = checks[name]
        outcomes.append(probe["outcome"] == "error" and probe["errno"] in expected)
    if "allowed_bind" in checks:
        outcomes.append(checks["allowed_bind"]["outcome"] == "bound")
    if "allowed_connect" in checks:
        outcomes.append(checks["allowed_connect"]["outcome"] == "connected")
    outcomes.append(checks["af_unix_control"]["outcome"] == "connected")
    return checks, "ready" if outcomes and all(outcomes) else "unsupported"


def _selected_authority_socket(uid):
    """Return the one enrolled service authority endpoint for this worker UID."""
    return f"/run/hermes-installer/authority/{uid}.sock"


def _unix_control_probe(contract):
    """Connect to the exact selected root authority endpoint as the allowed control."""
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
        sock.settimeout(0.5)
        sock.connect(_selected_authority_socket(contract["uid"]))
        return {"outcome": "connected", "errno": None}
    except OSError as exc:
        return {"outcome": "error", "errno": exc.errno}
    finally:
        if sock is not None:
            sock.close()


def _gate_channel_from_activation(env):
    """Resolve the single named manager-owned stream passed by systemd."""
    if (env.get("LISTEN_PID") != str(os.getpid()) or env.get("LISTEN_FDS") != "1"
            or env.get("LISTEN_FDNAMES") != "hermes-private-loopback-gate"):
        raise GateError("root-owned private gate channel is unavailable")
    channel = socket.socket(fileno=os.dup(GATE_FD))
    if channel.family != socket.AF_UNIX or channel.type & socket.SOCK_STREAM != socket.SOCK_STREAM:
        channel.close()
        raise GateError("root-owned private gate channel has the wrong socket type")
    if not hasattr(socket, "SO_PEERCRED"):
        channel.close()
        raise GateError("kernel-authenticated manager peer credentials are unavailable")
    peer = channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    manager_pid, manager_uid, _manager_gid = struct.unpack("3i", peer)
    if manager_pid <= 1 or manager_pid == os.getpid() or manager_uid != 0:
        channel.close()
        raise GateError("gate channel peer is not the distinct root manager")
    return channel


def _send_frame(channel, value, ceiling):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    if len(raw) > ceiling:
        raise GateError("private gate channel frame exceeds its fixed bound")
    channel.sendall(_FRAME.pack(len(raw)) + raw)


def _recv_exact(channel, count):
    result = bytearray()
    while len(result) < count:
        part = channel.recv(count - len(result))
        if not part:
            raise GateError("root gate channel closed before its one-use decision")
        result.extend(part)
    return bytes(result)


def _receive_gate_frame(channel, *, ceiling=MAX_GATE_FRAME):
    """Read one canonical, bounded frame from the private manager channel."""
    header = _recv_exact(channel, _FRAME.size)
    (length,) = _FRAME.unpack(header)
    if not 1 <= length <= ceiling:
        raise GateError("root gate frame length is invalid")
    raw = _recv_exact(channel, length)
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise GateError("root gate frame is malformed") from None
    if (type(value) is not dict
            or json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("ascii") != raw):
        raise GateError("root gate frame is not canonical closed JSON")
    return value


def _await_namespace_gate(channel, *, contract, contract_sha256, identity):
    """Authenticate the actual launch namespace before any network probe."""
    frame = _receive_gate_frame(channel)
    fields = frozenset({
        "schema", "operation", "nonce", "launch_contract_sha256",
        "service_generation_digest", "projection_handle", "unit_invocation_id",
        "pid", "start_ticks", "cgroup", "namespace_device", "namespace_inode",
    })
    if (set(frame) != fields or type(frame.get("schema")) is not int or frame.get("schema") != 2
            or frame.get("operation") != "observe-selected-namespace"
            or frame.get("nonce") != contract["nonce"]
            or frame.get("launch_contract_sha256") != contract_sha256
            or frame.get("service_generation_digest") != contract["service_generation_digest"]
            or not isinstance(frame.get("projection_handle"), str)
            or not _IDENT.fullmatch(frame["projection_handle"])
            or not isinstance(frame.get("unit_invocation_id"), str)
            or not _IDENT.fullmatch(frame["unit_invocation_id"])
            or frame.get("pid") != identity["pid"]
            or frame.get("start_ticks") != identity["start_ticks"]
            or frame.get("cgroup") != identity["cgroup"]
            or frame.get("namespace_device") != identity["namespace_device"]
            or frame.get("namespace_inode") != identity["namespace_inode"]):
        raise GateError("root namespace observation does not match this held worker")
    if (type(frame["pid"]) is not int or frame["pid"] <= 1
            or type(frame["start_ticks"]) is not int or frame["start_ticks"] <= 0
            or type(frame["namespace_device"]) is not int or frame["namespace_device"] < 0
            or type(frame["namespace_inode"]) is not int or frame["namespace_inode"] <= 0):
        raise GateError("root namespace observation identity fields are invalid")
    current = _self_identity(contract)
    if current != identity:
        raise GateError("worker identity changed before namespace probes")
    namespace = os.stat("/proc/self/ns/net")
    if (namespace.st_dev, namespace.st_ino) != (
            frame["namespace_device"], frame["namespace_inode"]):
        raise GateError("selected namespace descriptor does not name this worker namespace")
    raw = json.dumps(frame, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode("ascii")
    return frame, hashlib.sha256(raw).hexdigest()


def _await_root_release(channel, *, contract, contract_sha256,
                        namespace_gate_sha256, identity, gate_frame):
    """Block until the manager issues its separate exact application release."""
    grant = _receive_gate_frame(channel, ceiling=MAX_GRANT)
    expected = {
        "schema": 2, "operation": "release-selected-application",
        "nonce": contract["nonce"],
        "launch_contract_sha256": contract_sha256,
        "namespace_gate_sha256": namespace_gate_sha256,
        "service_generation_digest": contract["service_generation_digest"],
        "projection_handle": gate_frame["projection_handle"],
        "pid": identity["pid"], "start_ticks": identity["start_ticks"],
        "unit_invocation_id": gate_frame["unit_invocation_id"],
    }
    if (set(grant) != set(expected) or grant != expected
            or _self_identity(contract) != identity):
        raise GateError("root application release differs from the one-use worker proof")
    namespace = os.stat("/proc/self/ns/net")
    if (namespace.st_dev, namespace.st_ino) != (
            gate_frame["namespace_device"], gate_frame["namespace_inode"]):
        raise GateError("worker changed network namespace before application release")


def _emit(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_RESULT:
        raise GateError("gate result exceeds its fixed byte bound")
    os.write(1, raw + b"\n")


def main():
    if len(sys.argv) != 1:
        return 64
    identity = {}
    contract = {}
    digest = None
    try:
        contract, digest = _read_contract()
        _validate_contract(contract)
        identity = _self_identity(contract)
        channel = _gate_channel_from_activation(os.environ)
        _send_frame(channel, {
            "schema": 2, "state": "awaiting-namespace", "nonce": contract["nonce"],
            "launch_contract_sha256": digest, "pid": identity["pid"],
            "start_ticks": identity["start_ticks"], "uid": identity["uid"],
            "gid": identity["gid"],
        }, MAX_RESULT)
        gate_frame, gate_digest = _await_namespace_gate(
            channel, contract=contract, contract_sha256=digest, identity=identity)
        checks, state = _probe(contract)
        result = {
            "schema": 2, "state": state, "nonce": contract["nonce"],
            "launch_contract_sha256": digest,
            "namespace_gate_sha256": gate_digest,
            "identity": identity, "checks": checks,
        }
        _send_frame(channel, result, MAX_RESULT)
        if state != "ready":
            return 77
        _await_root_release(channel, contract=contract, contract_sha256=digest,
                            namespace_gate_sha256=gate_digest, identity=identity,
                            gate_frame=gate_frame)
        os.execve(contract["application_executable"], contract["application_argv"],
                  contract["application_environment"])
    except (GateError, OSError, ValueError, TypeError, KeyError):
        try:
            _emit({"schema": 2, "state": "unavailable", "launch_contract_sha256": digest,
                   "nonce": contract.get("nonce") if isinstance(contract, dict) else None,
                   "identity": identity, "checks": {}})
        except Exception:
            pass
        return 75
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
