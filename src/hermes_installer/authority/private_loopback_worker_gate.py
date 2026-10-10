"""Root-owned v190 staged same-worker namespace and application-release gate.

The transport is a named AF_UNIX stream activated by systemd OpenFile. It is
purpose-specific and accepts only the helper's exact schema-2 frames. This is
not a generic process protocol or an authority source by itself.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .types import AuthorityDenied

_HEADER = struct.Struct("!I")
_CREDENTIALS = struct.Struct("3i")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_MAX_FRAME = 8192
_MAX_RESULT = 4096


@dataclass(slots=True)
class RootPrivateLoopbackGateChannel:
    listener: socket.socket = field(repr=False)
    socket_path: Path
    socket_directory: Path
    nonce: str
    socket_device: int
    socket_inode: int
    _closed: bool = False
    _accepted: socket.socket | None = field(default=None, repr=False)
    _peer_credentials: tuple[int, int, int] | None = field(default=None, repr=False)
    _initial_frame: Mapping[str, Any] | None = field(default=None, repr=False)
    _contract_sha256: str | None = field(default=None, repr=False)
    _namespace_frame: Mapping[str, Any] | None = field(default=None, repr=False)
    _namespace_gate_sha256: str | None = field(default=None, repr=False)
    _phase: str = "created"

    @property
    def systemd_open_file_property(self) -> str:
        if self._closed or self.listener.fileno() < 0:
            raise AuthorityDenied("native_worker.gate", "private gate listener is closed")
        return f"{self.socket_path}:hermes-private-loopback-gate"

    def accept_helper(self, *, expected_uid: int, deadline: float,
                      cancelled: Any) -> tuple[socket.socket, Mapping[str, Any], str]:
        if self._closed or self._accepted is not None:
            raise AuthorityDenied("native_worker.gate", "gate channel is already consumed")
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not callable(cancelled):
            raise AuthorityDenied("native_worker.gate", "gate admission deadline is invalid")
        self.listener.settimeout(min(0.25, remaining))
        while True:
            if cancelled() or time.monotonic() >= deadline:
                raise AuthorityDenied("native_worker.gate", "gate helper did not connect before its deadline")
            try:
                connected, _ = self.listener.accept()
                break
            except TimeoutError:
                continue
            except OSError:
                if self._closed:
                    raise AuthorityDenied("native_worker.gate", "gate channel closed during accept") from None
                continue
        try:
            connected.settimeout(max(0.05, min(1.0, deadline - time.monotonic())))
            connected.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError("peer credentials are unavailable")
            peer = connected.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CREDENTIALS.size)
            pid, uid, gid = _CREDENTIALS.unpack(peer)
            if pid <= 1 or pid == os.getpid() or uid != expected_uid or gid < 0:
                raise ValueError("helper peer identity differs from selected worker")
            frame, creds = _receive_frame_with_credentials(connected, _MAX_RESULT)
            if creds != (pid, uid, gid):
                raise ValueError("per-frame credentials differ from connected helper")
            self._accepted = connected
            self._peer_credentials = (pid, uid, gid)
            self._initial_frame = frame
            self._contract_sha256 = frame.get("launch_contract_sha256")
            self._phase = "awaiting-namespace"
            return connected, frame, _digest(frame)
        except BaseException:
            connected.close()
            raise AuthorityDenied("native_worker.gate", "gate helper peer or initial frame is invalid") from None

    def _receive_helper_frame(self, *, ceiling: int = _MAX_FRAME) -> Mapping[str, Any]:
        channel = self._accepted
        expected = self._peer_credentials
        if channel is None or expected is None or self._closed:
            raise AuthorityDenied("native_worker.gate", "authenticated helper channel is unavailable")
        try:
            frame, credentials = _receive_frame_with_credentials(channel, ceiling)
            if credentials != expected:
                raise ValueError("per-message helper credentials changed")
            return frame
        except Exception:
            raise AuthorityDenied("native_worker.gate", "helper frame credentials or schema are invalid") from None

    def _send_manager_frame(self, frame: Mapping[str, Any], *, ceiling: int = _MAX_FRAME) -> str:
        channel = self._accepted
        if channel is None or self._closed:
            raise AuthorityDenied("native_worker.gate", "authenticated helper channel is unavailable")
        try:
            return send_frame(channel, frame, ceiling=ceiling)
        except Exception:
            raise AuthorityDenied("native_worker.gate", "manager gate frame could not be sent") from None

    def send_namespace_observation(self, frame: Mapping[str, Any]) -> str:
        initial = self._initial_frame
        if (self._phase != "awaiting-namespace" or initial is None
                or not isinstance(frame, Mapping)
                or frame.get("schema") != 2
                or frame.get("operation") != "observe-selected-namespace"
                or frame.get("nonce") != self.nonce
                or frame.get("launch_contract_sha256") != self._contract_sha256
                or frame.get("pid") != initial.get("pid")
                or frame.get("start_ticks") != initial.get("start_ticks")):
            raise AuthorityDenied("native_worker.gate", "namespace observation is not bound to initial helper identity")
        digest = self._send_manager_frame(frame)
        self._namespace_frame = dict(frame)
        self._phase = "awaiting-probes"
        return digest

    def receive_and_validate_gate_result(self, *, expected_identity: Mapping[str, Any],
                                         allowed_bind: bool,
                                         allowed_connect: bool) -> str:
        if self._phase != "awaiting-probes" or self._namespace_frame is None:
            raise AuthorityDenied("native_worker.gate", "namespace observation was not sent exactly once")
        result = self._receive_helper_frame(ceiling=_MAX_RESULT)
        digest = validate_gate_result(
            result, nonce=self.nonce, contract_sha256=str(self._contract_sha256),
            expected_identity=expected_identity, gate_frame=self._namespace_frame,
            allowed_bind=allowed_bind, allowed_connect=allowed_connect)
        self._namespace_gate_sha256 = digest
        self._phase = "ready"
        return digest

    def send_application_release(self, *, service_generation_digest: str,
                                 projection_handle: str) -> str:
        if (self._phase != "ready" or self._namespace_frame is None
                or self._namespace_gate_sha256 is None):
            raise AuthorityDenied("native_worker.gate", "helper has not produced a current ready result")
        gate = self._namespace_frame
        frame = application_release_frame(
            nonce=self.nonce, contract_sha256=str(self._contract_sha256),
            namespace_gate_sha256=self._namespace_gate_sha256,
            service_generation_digest=service_generation_digest,
            projection_handle=projection_handle,
            pid=int(gate["pid"]), start_ticks=int(gate["start_ticks"]),
            unit_invocation_id=str(gate["unit_invocation_id"]))
        digest = self._send_manager_frame(frame, ceiling=_MAX_RESULT)
        self._phase = "released"
        return digest

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._accepted is not None:
            try:
                self._accepted.close()
            except OSError:
                pass
            self._accepted = None
        _remove_owned_socket(self.listener, self.socket_path, self.socket_directory,
                             self.socket_device, self.socket_inode)


def create_root_private_loopback_gate_channel(runtime_directory: Path) -> RootPrivateLoopbackGateChannel:
    if not isinstance(runtime_directory, Path):
        raise AuthorityDenied("native_worker.gate", "private gate runtime directory is invalid")
    try:
        directory_info = runtime_directory.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or directory_info.st_uid != 0
                or stat.S_IMODE(directory_info.st_mode) != 0o700):
            raise ValueError("gate parent directory is not root-private")
        private = runtime_directory / secrets.token_hex(16)
        private.mkdir(mode=0o700)
        info = private.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("gate launch directory changed")
        path = private / "control.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0))
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        listener.bind(str(path))
        os.chmod(path, 0o600, follow_symlinks=False)
        listener.listen(1)
        listener.set_inheritable(False)
        socket_info = path.lstat()
        if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0 or stat.S_IMODE(socket_info.st_mode) != 0o600:
            raise ValueError("gate socket path is not root-private")
        return RootPrivateLoopbackGateChannel(listener, path, private,
                                             secrets.token_urlsafe(32),
                                             socket_info.st_dev, socket_info.st_ino)
    except (OSError, ValueError, AttributeError):
        try:
            if "listener" in locals():
                listener.close()
            if "path" in locals() and path.exists():
                path.unlink()
            if "private" in locals() and private.exists():
                private.rmdir()
        except OSError:
            pass
        raise AuthorityDenied("native_worker.gate", "root-private gate listener could not be created") from None


def validate_awaiting_namespace(frame: Mapping[str, Any], *, nonce: str,
                                contract_sha256: str, expected_uid: int,
                                expected_gid: int) -> Mapping[str, int]:
    fields = {"schema", "state", "nonce", "launch_contract_sha256", "pid",
              "start_ticks", "uid", "gid"}
    if (not isinstance(frame, Mapping) or set(frame) != fields
            or type(frame.get("schema")) is not int or frame["schema"] != 2
            or frame.get("state") != "awaiting-namespace"
            or frame.get("nonce") != nonce or not _NONCE.fullmatch(nonce)
            or frame.get("launch_contract_sha256") != contract_sha256
            or not _SHA.fullmatch(contract_sha256)
            or type(frame.get("pid")) is not int or frame["pid"] <= 1
            or type(frame.get("start_ticks")) is not int or frame["start_ticks"] <= 0
            or type(frame.get("uid")) is not int or frame["uid"] != expected_uid
            or type(frame.get("gid")) is not int or frame["gid"] != expected_gid):
        raise AuthorityDenied("native_worker.gate", "helper initial identity frame is invalid")
    return {key: frame[key] for key in ("pid", "start_ticks", "uid", "gid")}


def namespace_observation_frame(*, nonce: str, contract_sha256: str,
                                service_generation_digest: str, projection_handle: str,
                                unit_invocation_id: str, pid: int, start_ticks: int,
                                cgroup: str, namespace_device: int,
                                namespace_inode: int) -> dict[str, Any]:
    if (not _NONCE.fullmatch(nonce) or not _SHA.fullmatch(contract_sha256)
            or not _SHA.fullmatch(service_generation_digest)
            or not _IDENT.fullmatch(projection_handle)
            or not _IDENT.fullmatch(unit_invocation_id)
            or type(pid) is not int or pid <= 1 or type(start_ticks) is not int or start_ticks <= 0
            or not isinstance(cgroup, str) or not cgroup.startswith("/system.slice/hermes-installer-")
            or ".." in Path(cgroup).parts
            or type(namespace_device) is not int or namespace_device < 0
            or type(namespace_inode) is not int or namespace_inode <= 0):
        raise AuthorityDenied("native_worker.gate", "observed worker namespace identity is malformed")
    return {"schema": 2, "operation": "observe-selected-namespace", "nonce": nonce,
            "launch_contract_sha256": contract_sha256,
            "service_generation_digest": service_generation_digest,
            "projection_handle": projection_handle,
            "unit_invocation_id": unit_invocation_id, "pid": pid,
            "start_ticks": start_ticks, "cgroup": cgroup,
            "namespace_device": namespace_device, "namespace_inode": namespace_inode}


def validate_gate_result(frame: Mapping[str, Any], *, nonce: str,
                         contract_sha256: str, expected_identity: Mapping[str, Any],
                         gate_frame: Mapping[str, Any],
                         allowed_bind: bool, allowed_connect: bool) -> str:
    fields = {"schema", "state", "nonce", "launch_contract_sha256",
              "namespace_gate_sha256", "identity", "checks"}
    if (not isinstance(frame, Mapping) or set(frame) != fields
            or type(frame.get("schema")) is not int or frame["schema"] != 2
            or frame.get("nonce") != nonce
            or frame.get("launch_contract_sha256") != contract_sha256
            or frame.get("namespace_gate_sha256") != _digest(gate_frame)
            or frame.get("identity") != expected_identity
            or not isinstance(frame.get("checks"), dict)):
        raise AuthorityDenied("native_worker.gate", "helper gate result does not join the observed worker")
    checks = frame["checks"]
    required = {"wrong_port_bind", "ipv6_bind", "wildcard_bind", "af_unix_control"}
    if allowed_bind:
        required.add("allowed_bind")
    if allowed_connect:
        required.add("allowed_connect")
    if set(checks) != required:
        raise AuthorityDenied("native_worker.gate", "kernel probe set differs from the selected role")
    for name in ("wrong_port_bind", "ipv6_bind", "wildcard_bind"):
        probe = checks[name]
        if (not isinstance(probe, dict) or set(probe) != {"outcome", "errno"}
                or probe["outcome"] != "error" or probe["errno"] not in {1, 13}):
            raise AuthorityDenied("native_worker.gate", "a forbidden bind succeeded or returned an unrelated error")
    if checks["af_unix_control"] != {"outcome": "connected", "errno": None}:
        raise AuthorityDenied("native_worker.gate", "selected authority control probe failed")
    if allowed_bind and checks["allowed_bind"] != {"outcome": "bound", "errno": None}:
        raise AuthorityDenied("native_worker.gate", "selected loopback bind probe failed")
    if allowed_connect and checks["allowed_connect"] != {"outcome": "connected", "errno": None}:
        raise AuthorityDenied("native_worker.gate", "selected loopback connect probe failed")
    if frame.get("state") != "ready":
        raise AuthorityDenied("native_worker.gate", "kernel probes did not authorize native worker effects")
    return str(frame["namespace_gate_sha256"])


def application_release_frame(*, nonce: str, contract_sha256: str,
                              namespace_gate_sha256: str, service_generation_digest: str,
                              projection_handle: str, pid: int, start_ticks: int,
                              unit_invocation_id: str) -> dict[str, Any]:
    if (not _NONCE.fullmatch(nonce) or not _SHA.fullmatch(contract_sha256)
            or not _SHA.fullmatch(namespace_gate_sha256)
            or not _SHA.fullmatch(service_generation_digest)
            or not _IDENT.fullmatch(projection_handle)
            or not _IDENT.fullmatch(unit_invocation_id)
            or type(pid) is not int or pid <= 1
            or type(start_ticks) is not int or start_ticks <= 0):
        raise AuthorityDenied("native_worker.gate", "one-use application release identity is malformed")
    return {"schema": 2, "operation": "release-selected-application", "nonce": nonce,
            "launch_contract_sha256": contract_sha256,
            "namespace_gate_sha256": namespace_gate_sha256,
            "service_generation_digest": service_generation_digest,
            "projection_handle": projection_handle, "pid": pid,
            "start_ticks": start_ticks, "unit_invocation_id": unit_invocation_id}


def send_frame(channel: socket.socket, frame: Mapping[str, Any], *, ceiling: int = _MAX_FRAME) -> str:
    raw = _canonical(frame)
    if not 1 <= len(raw) <= ceiling:
        raise AuthorityDenied("native_worker.gate", "private gate frame exceeds its bound")
    channel.sendall(_HEADER.pack(len(raw)) + raw)
    return hashlib.sha256(raw).hexdigest()


def receive_frame(channel: socket.socket, *, ceiling: int = _MAX_FRAME) -> Mapping[str, Any]:
    raw = _receive_raw(channel, ceiling)
    value = _decode(raw)
    return value


def _receive_frame_with_credentials(channel: socket.socket, ceiling: int) -> tuple[Mapping[str, Any], tuple[int, int, int]]:
    header = bytearray()
    credentials = None
    while len(header) < _HEADER.size:
        block, ancillary, flags, _addr = channel.recvmsg(
            _HEADER.size - len(header), socket.CMSG_SPACE(_CREDENTIALS.size))
        if not block:
            raise ValueError("truncated frame header")
        if flags & (getattr(socket, "MSG_CTRUNC", 0) | getattr(socket, "MSG_TRUNC", 0)):
            raise ValueError("truncated helper frame or ancillary data")
        header.extend(block)
        for level, kind, data in ancillary:
            if (level != socket.SOL_SOCKET or kind != socket.SCM_CREDENTIALS
                    or len(data) != _CREDENTIALS.size):
                raise ValueError("unexpected helper ancillary data")
            current = _CREDENTIALS.unpack(data)
            if credentials is not None and credentials != current:
                raise ValueError("per-frame helper credentials changed")
            credentials = current
    if credentials is None:
        raise ValueError("kernel did not attach per-message credentials")
    (length,) = _HEADER.unpack(header)
    if not 1 <= length <= ceiling:
        raise ValueError("frame length is invalid")
    raw = _recv_exact(channel, length)
    return _decode(raw), credentials


def _receive_raw(channel: socket.socket, ceiling: int) -> bytes:
    header = _recv_exact(channel, _HEADER.size)
    (length,) = _HEADER.unpack(header)
    if not 1 <= length <= ceiling:
        raise AuthorityDenied("native_worker.gate", "private gate frame length is invalid")
    return _recv_exact(channel, length)


def _recv_exact(channel: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) < size:
        block = channel.recv(size - len(output))
        if not block:
            raise AuthorityDenied("native_worker.gate", "private gate channel closed before a decision")
        output.extend(block)
    return bytes(output)


def _decode(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, TypeError, json.JSONDecodeError):
        raise AuthorityDenied("native_worker.gate", "private gate frame is malformed") from None
    if (type(value) is not dict or _canonical(value) != raw):
        raise AuthorityDenied("native_worker.gate", "private gate frame is not canonical closed JSON")
    return value


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _process_capability_identity(pid: int) -> dict[str, int]:
    try:
        rows = {}
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition(":")
            if separator and key in {"CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh"}:
                rows[key] = int(value.strip(), 16)
        if set(rows) != {"CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh"}:
            raise ValueError("process capability set is incomplete")
        return rows
    except (OSError, UnicodeError, ValueError):
        raise AuthorityDenied("native_worker.gate", "kernel capability observation is unavailable") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _remove_owned_socket(listener: socket.socket, path: Path, directory: Path,
                         device: int, inode: int) -> None:
    try:
        info = path.lstat()
        if (stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                and (info.st_dev, info.st_ino) == (device, inode)):
            path.unlink()
    except OSError:
        pass
    try:
        listener.close()
    except OSError:
        pass
    try:
        directory.rmdir()
    except OSError:
        pass


__all__ = [
    "RootPrivateLoopbackGateChannel", "create_root_private_loopback_gate_channel",
    "validate_awaiting_namespace", "namespace_observation_frame", "validate_gate_result",
    "application_release_frame", "send_frame", "receive_frame",
]
