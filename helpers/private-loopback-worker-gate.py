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
import signal
import socket
import stat
import sys


MAX_CONTRACT = 16 * 1024
MAX_RESULT = 4 * 1024
CONTRACT_PATH = "/run/hermes-installer/private-loopback/contract.json"
FIELDS = frozenset({
    "schema", "purpose", "nonce", "network_id", "service_generation_digest",
    "enrollment_id", "profile_id", "generation", "uid", "gid",
    "namespace_inode", "role", "allowed_bind_port", "allowed_connect_port",
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
    if (type(row["schema"]) is not int or row["schema"] != 1
            or row["purpose"] != "private-loopback-worker-start"
            or not isinstance(row["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", row["nonce"])
            or any(not isinstance(row[name], str) or not _IDENT.fullmatch(row[name])
                   for name in ("network_id", "enrollment_id", "profile_id", "generation"))
            or not isinstance(row["service_generation_digest"], str)
            or not _SHA.fullmatch(row["service_generation_digest"])
            or type(row["uid"]) is not int or type(row["gid"]) is not int
            or row["uid"] <= 0 or row["gid"] <= 0
            or type(row["namespace_inode"]) is not int or row["namespace_inode"] <= 0
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
        cap_values = {name: int(caps[name], 16) for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb")}
        if any(cap_values.values()):
            raise GateError("worker gate retains Linux capabilities")
        namespace_inode = os.stat("/proc/self/ns/net").st_ino
        if namespace_inode != contract["namespace_inode"]:
            raise GateError("worker gate is outside the selected network namespace")
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
            "namespace_inode": namespace_inode, "capabilities": cap_values,
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
    return checks, "ready" if outcomes and all(outcomes) else "unsupported"


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
        checks, state = _probe(contract)
        _emit({"schema": 1, "state": state, "contract_sha256": digest,
               "nonce": contract["nonce"], "identity": identity, "checks": checks})
        if state != "ready":
            return 77
        # The process manager independently observes this exact MainPID in the
        # selected worker cgroup while it is stopped. It resumes by pidfd only
        # after consuming its retained one-use start selection; no grant bytes
        # or caller-controlled tokens reach the helper.
        os.kill(os.getpid(), signal.SIGSTOP)
        os.execve(contract["application_executable"], contract["application_argv"],
                  contract["application_environment"])
    except (GateError, OSError, ValueError, TypeError, KeyError):
        try:
            _emit({"schema": 1, "state": "unavailable", "contract_sha256": digest,
                   "nonce": contract.get("nonce") if isinstance(contract, dict) else None,
                   "identity": identity, "checks": {}})
        except Exception:
            pass
        return 75
    return 70


if __name__ == "__main__":
    raise SystemExit(main())
