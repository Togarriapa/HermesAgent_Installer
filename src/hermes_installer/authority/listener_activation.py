"""Supervised, one-use authority listener activation (HI-T187).

The setup actor and the long-running authority daemon are different processes.
This module joins them through a root-owned pathname SOCK_SEQPACKET channel,
the kernel's peer credentials, a systemd MainPID observation, and a single
SCM_RIGHTS transfer of the already-bound listener.  It never treats UID 0 or
an in-process socketpair as a process identity.
"""
from __future__ import annotations

import array
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .types import AuthorityDenied

_UNIT = "hermes-installer-authority.service"
_UNIT_FILE = Path("/etc/systemd/system/hermes-installer-authority.service")
_CONTROL_ROOT = Path("/run/hermes-installer/listener-activation")
_AUTHORITY_SOCKET_ROOT = Path("/run/hermes-installer/authority")
_RECORD_FIELDS = frozenset({
    "schema", "activation_id", "setup_session_id", "transaction_handle",
    "prepared_endpoint_receipt_handle", "prepared_endpoint_receipt_sha256",
    "publication_receipt_handle", "publication_sha256", "service_generation_digest",
    "profile_id", "service_enrollment_id", "service_uid", "service_gid",
    "socket_device", "socket_inode", "setup_pid", "setup_start_ticks",
    "setup_interpreter_sha256", "setup_launcher_sha256", "setup_actor_binding_sha256",
    "daemon_unit_id", "daemon_unit_fragment_sha256", "daemon_invocation_id",
    "daemon_pid", "daemon_start_ticks", "daemon_cgroup", "daemon_interpreter_sha256",
    "daemon_launcher_sha256", "release_deployment_receipt_sha256",
    "release_closure_manifest_sha256", "activation_root_device", "activation_root_inode",
    "activation_socket_device", "activation_socket_inode", "nonce_sha256",
    "issued_monotonic", "expires_monotonic", "state",
})
_MESSAGE_FIELDS = frozenset({
    "schema", "operation", "activation_id", "nonce", "activation_record_sha256",
    "publication_receipt_handle", "publication_sha256", "service_generation_digest",
    "endpoint_receipt_sha256", "socket_device", "socket_inode",
})
_MAX_MESSAGE = 8192
_MAX_TTL = 30.0
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_SETUP_LAUNCHER_SOURCE = (
    "import pathlib\n"
    "import sys\n"
    "launcher = pathlib.Path(sys.argv.pop(1)).resolve(strict=True)\n"
    "sys.argv[0] = str(launcher)\n"
    "sys.path.insert(0, str(launcher.parent.parent / (\"lib/python\" if (launcher.parent.parent / \"lib/python\").is_dir() else \"src\")))\n"
    "from hermes_installer.root_setup import main\n"
    "raise SystemExit(main())\n"
)
_OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)


class ListenerActivationUnavailable(AuthorityDenied):
    """The installed root daemon or exact listener handoff is not current."""

    def __init__(self, message: str):
        super().__init__("authority.activation", message)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _activation_generation_rows(generation: Any, publication: Any, endpoint: Any
                               ) -> tuple[Mapping[str, Any], Mapping[str, Any],
                                          Mapping[str, Any], Mapping[str, Any]]:
    """Check the producer's actual five-catalog field names and singleton joins."""
    from .native_worker_service_generation import RootPreparedNativeServiceGeneration
    if (type(generation) is not RootPreparedNativeServiceGeneration
            or generation.generation_id != publication.generation_id
            or len(generation.native_worker_runtime_records) != 1
            or len(generation.active_network_generation_records) != 1
            or len(generation.process_profile_records) != 1
            or len(generation.service_records) != 1):
        raise ValueError("selected native generation is not a current closed singleton")
    runtime_row = generation.native_worker_runtime_records[0]
    active_row = generation.active_network_generation_records[0]
    profile_row = generation.process_profile_records[0]
    service_row = generation.service_records[0]
    if not all(isinstance(row, Mapping) for row in (
            runtime_row, active_row, profile_row, service_row)):
        raise ValueError("selected native generation rows are malformed")
    if (active_row.get("worker_runtime_record_id") != runtime_row.get("id")
            or active_row.get("worker_runtime_record_sha256") != _digest(dict(runtime_row))
            or active_row.get("process_profile_id") != endpoint.profile_id
            or profile_row.get("profile_id", profile_row.get("id")) != endpoint.profile_id
            or service_row.get("profile_id") != endpoint.profile_id
            or service_row.get("service_uid", service_row.get("owner_uid")) != endpoint.service_uid
            or service_row.get("service_gid", service_row.get("owner_gid")) != endpoint.service_gid
            or runtime_row.get("profile_id") != endpoint.profile_id
            or runtime_row.get("generation_id") != generation.generation_id):
        raise ValueError("committed worker runtime, service, profile, and endpoint rows differ")
    return runtime_row, active_row, profile_row, service_row


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _read_proc_start_ticks(proc_root: Path, pid: int) -> int:
    raw = (proc_root / str(pid) / "stat").read_text()
    fields = raw[raw.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ListenerActivationUnavailable("process start observation is malformed")
    return int(fields[19])


def _read_proc_effective_ids(proc_root: Path, pid: int) -> tuple[int, int]:
    status = (proc_root / str(pid) / "status").read_text()
    uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
    gid_line = next(line for line in status.splitlines() if line.startswith("Gid:"))
    return int(uid_line.split()[2]), int(gid_line.split()[2])


def _read_peer_cred(connection: socket.socket) -> tuple[int, int, int]:
    if not hasattr(socket, "SO_PEERCRED"):
        raise ListenerActivationUnavailable("Linux Unix peer credentials are unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    if len(raw) != struct.calcsize("3i"):
        raise ListenerActivationUnavailable("Unix peer credential response is malformed")
    return struct.unpack("3i", raw)


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonUnitSelection:
    """Finite installer-owned systemd launch selection, bound to one release."""
    unit_id: str
    activation_id: str
    unit_file: Path
    unit_file_sha256: str
    launcher_path: Path
    launcher_sha256: str
    interpreter_path: Path
    interpreter_sha256: str
    deployment_receipt_sha256: str
    closure_manifest_sha256: str
    _release: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonUnitSelection(<fixed installer unit>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonPeerObservation:
    """Held PIDFD and concrete systemd/procfs facts for the daemon MainPID."""
    unit_id: str
    invocation_id: str
    pid: int
    uid: int
    gid: int
    start_ticks: int
    cgroup: str
    fragment_path: str
    fragment_sha256: str
    exec_start: str
    environment: tuple[str, ...]
    executable_path: str
    executable_sha256: str
    pidfd: int = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonPeerObservation(<systemd MainPID>)"

    def close(self) -> None:
        try:
            os.close(self.pidfd)
        except OSError:
            pass


class SystemdAuthorityDaemonInspector:
    """Observe only the fixed authority unit and its live root MainPID."""
    _PROPERTIES = ("LoadState", "ActiveState", "MainPID", "InvocationID", "ControlGroup",
                   "FragmentPath", "ExecStart", "Environment", "EnvironmentFiles",
                   "DropInPaths", "User", "Group")

    def __init__(self, *, systemctl: Path = Path("/usr/bin/systemctl"),
                 proc_root: Path = Path("/proc"), run: Any = subprocess.run,
                 euid: Any = os.geteuid, monotonic: Any = time.monotonic):
        self.systemctl, self.proc_root = systemctl, proc_root
        self.run, self.euid, self.monotonic = run, euid, monotonic

    def inspect_authority_daemon(self, selection: RootAuthorityDaemonUnitSelection
                                 ) -> RootAuthorityDaemonPeerObservation:
        if (type(selection) is not RootAuthorityDaemonUnitSelection
                or selection._issuer is not _SELECTION_ISSUER
                or selection.unit_id != _UNIT or not _HEX32.fullmatch(selection.activation_id)
                or self.euid() != 0):
            raise ListenerActivationUnavailable("fixed root authority unit selection is unavailable")
        try:
            result = self.run([str(self.systemctl), "--system", "show", "--no-pager",
                               "--property=" + ",".join(self._PROPERTIES), _UNIT],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                              timeout=3.0, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ListenerActivationUnavailable("fixed authority unit could not be observed") from None
        if result.returncode != 0 or len(result.stdout) > 32768:
            raise ListenerActivationUnavailable("fixed authority unit observation failed")
        props: dict[str, str] = {}
        for line in result.stdout.splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in self._PROPERTIES or key in props:
                raise ListenerActivationUnavailable("fixed authority unit properties are malformed")
            props[key] = value
        if (set(props) != set(self._PROPERTIES) or props["LoadState"] != "loaded"
                or props["ActiveState"] != "active" or props["User"] not in {"root", "0"}
                or props["Group"] not in {"root", "0"} or not props["ControlGroup"].startswith("/")
                or not _HEX32.fullmatch(props["InvocationID"])
                or props["EnvironmentFiles"] not in {"", "{}"}
                or props["DropInPaths"] not in {"", "{}"}
                or set(props["Environment"].split()) != {
                    "HOME=/root", "PATH=/usr/bin:/bin", "LANG=C", "PYTHONNOUSERSITE=1"}
                or not _HEX32.fullmatch(selection.activation_id)
                or props["ExecStart"].count(selection.launcher_path.as_posix()) != 1
                or f"authority-daemon-adopt --activation-id {selection.activation_id}" not in props["ExecStart"]):
            raise ListenerActivationUnavailable("active authority unit differs from its fixed launch recipe")
        pid = int(props["MainPID"] or "0")
        if pid <= 1:
            raise ListenerActivationUnavailable("authority unit has no MainPID")
        pidfd = -1
        try:
            pidfd = os.pidfd_open(pid, 0)
            if self._pidfd_exited(pidfd):
                raise ListenerActivationUnavailable("authority unit MainPID has exited")
            proc = self.proc_root / str(pid)
            start = _read_proc_start_ticks(self.proc_root, pid)
            status = (proc / "status").read_text()
            uid_line = next(x for x in status.splitlines() if x.startswith("Uid:"))
            gid_line = next(x for x in status.splitlines() if x.startswith("Gid:"))
            uid, euid = [int(v) for v in uid_line.split()[1:3]]
            gid, egid = [int(v) for v in gid_line.split()[1:3]]
            cgroups = [x.split("::", 1)[1] for x in (proc / "cgroup").read_text().splitlines() if "::" in x]
            if uid != 0 or euid != 0 or gid != 0 or egid != 0 or cgroups != [props["ControlGroup"]]:
                raise ListenerActivationUnavailable("authority MainPID identity/cgroup differs from manager")
            executable = proc / "exe"
            exe_info = os.stat(executable)
            pinned = selection.interpreter_path.stat(follow_symlinks=False)
            exe_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
            if (os.path.realpath(executable) != str(selection.interpreter_path)
                    or (exe_info.st_dev, exe_info.st_ino) != (pinned.st_dev, pinned.st_ino)
                    or exe_hash != selection.interpreter_sha256
                    or hashlib.sha256(selection.launcher_path.read_bytes()).hexdigest() != selection.launcher_sha256):
                raise ListenerActivationUnavailable("authority MainPID executable or launcher pin changed")
            fragment = Path(props["FragmentPath"])
            if fragment != selection.unit_file or not fragment.is_absolute():
                raise ListenerActivationUnavailable("authority unit fragment is not the installer-owned fixed path")
            fragment_bytes = fragment.read_bytes()
            fragment_stat = fragment.stat(follow_symlinks=False)
            if (not stat.S_ISREG(fragment_stat.st_mode) or fragment_stat.st_uid != 0
                    or fragment_stat.st_mode & 0o022
                    or hashlib.sha256(fragment_bytes).hexdigest() != selection.unit_file_sha256):
                raise ListenerActivationUnavailable("authority unit fragment custody or digest changed")
            if _read_proc_start_ticks(self.proc_root, pid) != start or self._pidfd_exited(pidfd):
                raise ListenerActivationUnavailable("authority MainPID changed during inspection")
            observation = RootAuthorityDaemonPeerObservation(
                _UNIT, props["InvocationID"], pid, uid, gid, start, props["ControlGroup"],
                str(fragment), selection.unit_file_sha256, props["ExecStart"],
                tuple(sorted(x for x in props["Environment"].split() if x)),
                str(selection.interpreter_path), exe_hash, pidfd, selection._issuer)
            pidfd = -1
            return observation
        except ListenerActivationUnavailable:
            raise
        except (OSError, ValueError, StopIteration, IndexError):
            raise ListenerActivationUnavailable("authority MainPID could not be bound to the fixed unit") from None
        finally:
            if pidfd >= 0:
                os.close(pidfd)

    def verify_current(self, observation: RootAuthorityDaemonPeerObservation,
                       selection: RootAuthorityDaemonUnitSelection) -> RootAuthorityDaemonPeerObservation:
        if (type(observation) is not RootAuthorityDaemonPeerObservation
                or observation._issuer is not selection._issuer
                or self._pidfd_exited(observation.pidfd)
                or _read_proc_start_ticks(self.proc_root, observation.pid) != observation.start_ticks):
            raise ListenerActivationUnavailable("authority daemon PIDFD/start-time observation is stale")
        current = self.inspect_authority_daemon(selection)
        try:
            fields = ("unit_id", "invocation_id", "pid", "uid", "gid", "start_ticks", "cgroup",
                      "fragment_path", "fragment_sha256", "exec_start", "environment",
                      "executable_path", "executable_sha256")
            if any(getattr(current, name) != getattr(observation, name) for name in fields):
                raise ListenerActivationUnavailable("authority daemon unit invocation or peer changed")
        finally:
            current.close()
        return observation

    def _pidfd_exited(self, pidfd: int) -> bool:
        import select
        poller = select.poll()
        try:
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            return bool(poller.poll(0))
        except (OSError, ValueError):
            return True


_SELECTION_ISSUER = object()
_ACK_SEAL = object()


def _selection_from_release(release: Any, activation_id: str) -> RootAuthorityDaemonUnitSelection:
    from .installer_release import VerifiedInstallerReleaseReceipt
    if (type(release) is not VerifiedInstallerReleaseReceipt or not _HEX32.fullmatch(activation_id)):
        raise ListenerActivationUnavailable("verified release and generated activation ID are required")
    release.verify_current()
    launcher = [row for row in release.files if row.roles == ("launcher",)]
    interpreters = [row for row in release.files if row.roles == ("interpreter",)]
    if len(launcher) != 1 or len(interpreters) != 1:
        raise ListenerActivationUnavailable("installed launcher/interpreter closure is ambiguous")
    launch_path = release.release_root / launcher[0].relative_path
    interpreter_path = release.release_root / interpreters[0].relative_path
    for row in (launcher[0], interpreters[0]):
        fd = release.open_file(row.artifact_id)
        try:
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 128 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                digest.update(chunk)
            if size != row.size_bytes or digest.hexdigest() != row.sha256:
                raise ListenerActivationUnavailable("installed launcher/interpreter held bytes changed")
        finally:
            os.close(fd)
    contents = _unit_contents(launch_path, activation_id)
    return RootAuthorityDaemonUnitSelection(
        _UNIT, activation_id, _UNIT_FILE, hashlib.sha256(contents).hexdigest(), launch_path, launcher[0].sha256,
        interpreter_path, interpreters[0].sha256, release.deployment_receipt_sha256,
        release.closure_manifest_sha256, release, _SELECTION_ISSUER)


def _unit_contents(launcher_path: Path, activation_id: str) -> bytes:
    if (not launcher_path.is_absolute() or "\n" in str(launcher_path) or " " in str(launcher_path)
            or not _HEX32.fullmatch(activation_id)):
        raise ListenerActivationUnavailable("fixed authority unit launch fields are invalid")
    return ("[Unit]\nDescription=Hermes Installer Authority Daemon\nAfter=local-fs.target\n\n"
            "[Service]\nType=exec\nUser=root\nGroup=root\nUMask=0077\n"
            "WorkingDirectory=/\nEnvironment=HOME=/root\nEnvironment=PATH=/usr/bin:/bin\n"
            "Environment=LANG=C\nEnvironment=PYTHONNOUSERSITE=1\n"
            f"ExecStart={launcher_path} authority-daemon-adopt --activation-id {activation_id}\n"
            "KillMode=control-group\nRestart=no\nRuntimeMaxSec=infinity\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nProtectHome=read-only\n\n"
            "[Install]\nWantedBy=multi-user.target\n").encode("utf-8")


def _install_fixed_unit(selection: RootAuthorityDaemonUnitSelection) -> None:
    if os.geteuid() != 0 or selection._issuer is not _SELECTION_ISSUER:
        raise ListenerActivationUnavailable("only the held installed root setup actor may prepare the daemon unit")
    parent = _UNIT_FILE.parent
    try:
        pinfo = parent.lstat()
        if (not stat.S_ISDIR(pinfo.st_mode) or stat.S_ISLNK(pinfo.st_mode)
                or pinfo.st_uid != 0 or pinfo.st_mode & 0o022):
            raise ListenerActivationUnavailable("system unit directory custody is invalid")
        expected = _unit_contents(selection.launcher_path, selection.activation_id)
        if hashlib.sha256(expected).hexdigest() != selection.unit_file_sha256:
            raise ListenerActivationUnavailable("held unit recipe digest changed")
        try:
            existing = _UNIT_FILE.lstat()
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if (not stat.S_ISREG(existing.st_mode) or stat.S_ISLNK(existing.st_mode)
                    or existing.st_uid != 0 or existing.st_mode & 0o022
                    or hashlib.sha256(_UNIT_FILE.read_bytes()).hexdigest() != selection.unit_file_sha256):
                raise ListenerActivationUnavailable("fixed daemon unit conflicts with an unowned or different file")
            return
        dir_fd = os.open(parent, _OPEN_DIR)
        temporary = ".hermes-installer-authority-" + secrets.token_hex(12)
        fd = -1
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dir_fd)
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o644)
            if os.write(fd, expected) != len(expected):
                raise ListenerActivationUnavailable("daemon unit write was short")
            os.fsync(fd)
            os.close(fd)
            fd = -1
            # linkat provides no-replace publication; a raced foreign file is preserved.
            os.link(temporary, _UNIT_FILE.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd,
                    follow_symlinks=False)
            os.unlink(temporary, dir_fd=dir_fd)
            os.fsync(dir_fd)
        except FileExistsError:
            raise ListenerActivationUnavailable("fixed daemon unit appeared during owned publication") from None
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary, dir_fd=dir_fd)
            except OSError:
                pass
            os.close(dir_fd)
        info = _UNIT_FILE.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o644
                or hashlib.sha256(_UNIT_FILE.read_bytes()).hexdigest() != selection.unit_file_sha256):
            raise ListenerActivationUnavailable("published daemon unit failed its inode/content readback")
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("fixed daemon unit could not be safely installed") from None


def _systemd_mutation(action: str, *, systemctl: Path = Path("/usr/bin/systemctl")) -> None:
    if action not in {"daemon-reload", "start", "stop"}:
        raise ListenerActivationUnavailable("system manager operation is outside the fixed adapter")
    argv = [str(systemctl), "--system", action]
    if action in {"start", "stop"}:
        argv.append(_UNIT)
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                close_fds=True, timeout=15.0, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ListenerActivationUnavailable("fixed authority unit manager operation failed") from None
    if result.returncode != 0:
        raise ListenerActivationUnavailable("fixed authority unit manager operation was rejected")


@dataclass(frozen=True, slots=True, repr=False)
class RootAuthorityDaemonSupervisorAcknowledgment:
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    socket_device: int
    socket_inode: int
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    nonce_sha256: str
    daemon_invocation_id: str
    peer_pid: int
    peer_start_ticks: int
    _issuer: object = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootAuthorityDaemonSupervisorAcknowledgment(<authenticated listener adoption>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootListenerActivationTransaction:
    """Current setup-owned transaction; construction is restricted to supervisor."""
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    endpoint_device: int
    endpoint_inode: int
    activation_root_device: int
    activation_root_inode: int
    activation_socket_device: int
    activation_socket_inode: int
    nonce: bytes = field(repr=False, compare=False)
    expires_monotonic: float
    peer: RootAuthorityDaemonPeerObservation = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootListenerActivationTransaction(<root-held one-use transaction>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootActiveAuthorityListenerReceipt:
    """Supervisor-acknowledged transfer of the exact active authority listener."""
    activation_id: str
    activation_record_sha256: str
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    socket_device: int
    socket_inode: int
    daemon_unit_id: str
    daemon_invocation_id: str
    daemon_pid: int
    daemon_start_ticks: int
    adopted_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootActiveAuthorityListenerReceipt(<supervised active listener>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootVerifiedListenerActivationSelection:
    """Setup-side source selection minted from the committed publication.

    This private object is the seam between setup-owned source/member custody
    and the endpoint custodian.  It deliberately contains no caller-provided
    peer identity and no daemon-local network projection.
    """
    endpoint_receipt_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    service_generation_digest: str
    generation_id: str
    selection_handle: str
    worker_runtime_record_id: str
    profile_id: str
    service_uid: int
    service_gid: int
    original_setup_deadline_monotonic: float
    _endpoint: Any = field(repr=False, compare=False)
    _publication: Any = field(repr=False, compare=False)
    _generation: Any = field(repr=False, compare=False)
    _materialization: Any = field(repr=False, compare=False)
    _root_receipt: Any = field(repr=False, compare=False)
    _supervisor: Any = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootVerifiedListenerActivationSelection(<committed setup source>)"


def _activation_message(*, operation: str, activation_id: str, nonce: bytes,
                        record_sha256: str, publication_handle: str,
                        publication_sha256: str, generation_sha256: str,
                        endpoint_sha256: str, socket_device: int,
                        socket_inode: int) -> dict[str, Any]:
    if (operation not in {"daemon-ready-for-listener", "transfer-listener", "listener-adopted"}
            or not _HEX32.fullmatch(activation_id) or len(nonce) != 32):
        raise ListenerActivationUnavailable("activation wire operation or nonce is invalid")
    return {
        "schema": 1, "operation": operation, "activation_id": activation_id,
        "nonce": nonce.hex(), "activation_record_sha256": record_sha256,
        "publication_receipt_handle": publication_handle,
        "publication_sha256": publication_sha256,
        "service_generation_digest": generation_sha256,
        "endpoint_receipt_sha256": endpoint_sha256,
        "socket_device": socket_device, "socket_inode": socket_inode,
    }


def _send_packet(connection: socket.socket, message: Mapping[str, Any], *, fd: int | None = None) -> None:
    payload = _canonical(dict(message))
    if len(payload) > _MAX_MESSAGE:
        raise ListenerActivationUnavailable("activation message exceeds its fixed bound")
    ancillary: list[tuple[int, int, bytes]] = []
    if fd is not None:
        if type(fd) is not int or fd < 0:
            raise ListenerActivationUnavailable("listener descriptor is invalid")
        rights = array.array("i", [fd])
        ancillary.append((socket.SOL_SOCKET, socket.SCM_RIGHTS, rights.tobytes()))
    sent = connection.sendmsg([payload], ancillary)
    if sent != len(payload):
        raise ListenerActivationUnavailable("activation packet was not sent atomically")


def _recv_packet(connection: socket.socket, *, expected_peer: tuple[int, int, int],
                 expected_fd_count: int) -> tuple[dict[str, Any], tuple[int, ...]]:
    if expected_fd_count not in {0, 1}:
        raise ListenerActivationUnavailable("activation descriptor count is outside the finite schema")
    connection.settimeout(3.0)
    if not hasattr(socket, "SO_PASSCRED"):
        raise ListenerActivationUnavailable("Linux per-message credential delivery is unavailable")
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
    cred_size = socket.CMSG_SPACE(struct.calcsize("3i"))
    rights_size = socket.CMSG_SPACE(array.array("i").itemsize * 2)
    raw, ancillary, flags, _address = connection.recvmsg(
        _MAX_MESSAGE + 1, cred_size + rights_size, getattr(socket, "MSG_CMSG_CLOEXEC", 0))
    received_fds: list[int] = []
    credentials: tuple[int, int, int] | None = None
    try:
        if (not raw or len(raw) > _MAX_MESSAGE
                or flags & (getattr(socket, "MSG_TRUNC", 0) | getattr(socket, "MSG_CTRUNC", 0))):
            raise ListenerActivationUnavailable("activation packet is empty, oversized, or truncated")
        if _read_peer_cred(connection) != expected_peer:
            raise ListenerActivationUnavailable("activation peer credentials changed")
        for level, kind, data in ancillary:
            if level != socket.SOL_SOCKET:
                raise ListenerActivationUnavailable("activation ancillary level is invalid")
            if kind == socket.SCM_CREDENTIALS:
                if credentials is not None or len(data) != struct.calcsize("3i"):
                    raise ListenerActivationUnavailable("activation credentials are duplicated or malformed")
                credentials = struct.unpack("3i", data)
            elif kind == socket.SCM_RIGHTS:
                values = array.array("i")
                if len(data) % values.itemsize:
                    raise ListenerActivationUnavailable("activation descriptor ancillary data is malformed")
                values.frombytes(data)
                received_fds.extend(values.tolist())
            else:
                raise ListenerActivationUnavailable("activation ancillary type is not permitted")
        if credentials != expected_peer or len(received_fds) != expected_fd_count:
            raise ListenerActivationUnavailable("activation packet peer or descriptor count differs")
        try:
            message = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (ValueError, UnicodeError):
            raise ListenerActivationUnavailable("activation message is not valid closed JSON") from None
        if (not isinstance(message, dict) or set(message) != _MESSAGE_FIELDS
                or type(message.get("schema")) is not int or message["schema"] != 1):
            raise ListenerActivationUnavailable("activation message fields differ from schema 1")
        if received_fds:
            for descriptor in received_fds:
                os.set_inheritable(descriptor, False)
        return message, tuple(received_fds)
    except BaseException:
        for descriptor in received_fds:
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate activation JSON field")
        result[key] = value
    return result


def _verify_packet(message: Mapping[str, Any], expected: Mapping[str, Any]) -> None:
    if set(message) != _MESSAGE_FIELDS or any(message.get(key) != value for key, value in expected.items()):
        raise ListenerActivationUnavailable("activation packet differs from the current one-use transaction")


def _verify_transferred_listener(fd: int, *, socket_device: int, socket_inode: int,
                                 owner_uid: int, owner_gid: int,
                                 socket_root: Path = _AUTHORITY_SOCKET_ROOT) -> socket.socket:
    if type(fd) is not int or fd < 0:
        raise ListenerActivationUnavailable("transferred listener descriptor is unavailable")
    try:
        listener = socket.socket(fileno=fd)
        address = listener.getsockname()
        accepting = listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        sock_type = listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        if (listener.family != socket.AF_UNIX or sock_type != socket.SOCK_STREAM or accepting != 1
                or not isinstance(address, str) or not address.startswith(str(socket_root) + "/")
                or address.rsplit("/", 1)[-1] != f"{owner_uid}.sock"):
            listener.detach()
            raise ListenerActivationUnavailable("transferred descriptor is not the selected listening endpoint")
        path_info = Path(address).lstat()
        if (not stat.S_ISSOCK(path_info.st_mode) or path_info.st_uid != 0
                or path_info.st_gid != owner_gid or stat.S_IMODE(path_info.st_mode) != 0o660
                or (path_info.st_dev, path_info.st_ino) != (socket_device, socket_inode)):
            listener.detach()
            raise ListenerActivationUnavailable("transferred endpoint leaf custody changed")
        listener.set_inheritable(False)
        return listener
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("transferred listener could not be inspected") from None


def _ensure_control_root(prefix_fd: int, prefix_identity: tuple[int, int]) -> int:
    """Create only the fixed child beneath the held, journal-owned /run prefix."""
    prefix = _CONTROL_ROOT.parent
    pfd = -1
    try:
        pfd = os.dup(prefix_fd)
        pinfo = os.fstat(pfd)
        ppath = prefix.lstat()
        if (not stat.S_ISDIR(pinfo.st_mode) or pinfo.st_uid != 0 or pinfo.st_gid != 0
                or pinfo.st_mode & 0o022
                or (pinfo.st_dev, pinfo.st_ino) != prefix_identity
                or (pinfo.st_dev, pinfo.st_ino) != (ppath.st_dev, ppath.st_ino)):
            raise ListenerActivationUnavailable("fixed /run/hermes-installer custody is invalid")
        try:
            os.mkdir(_CONTROL_ROOT.name, 0o711, dir_fd=pfd)
        except FileExistsError:
            pass
        root_fd = os.open(_CONTROL_ROOT.name, _OPEN_DIR, dir_fd=pfd)
        info = os.fstat(root_fd)
        entry = os.stat(_CONTROL_ROOT.name, dir_fd=pfd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o711 or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)):
            os.close(root_fd)
            raise ListenerActivationUnavailable("fixed listener activation root is foreign or unsafe")
        return root_fd
    except ListenerActivationUnavailable:
        raise
    except OSError:
        raise ListenerActivationUnavailable("fixed listener activation root is unavailable") from None
    finally:
        if "pfd" in locals():
            os.close(pfd)


def _create_control_listener(activation_id: str, prefix_fd: int,
                             prefix_identity: tuple[int, int]
                             ) -> tuple[int, int, socket.socket, tuple[int, int]]:
    if not _HEX32.fullmatch(activation_id) or os.geteuid() != 0:
        raise ListenerActivationUnavailable("activation directory ID or root actor is invalid")
    root_fd = _ensure_control_root(prefix_fd, prefix_identity)
    activation_fd = -1
    listener: socket.socket | None = None
    created_directory = False
    created_socket = False
    try:
        os.mkdir(activation_id, 0o700, dir_fd=root_fd)
        created_directory = True
        activation_fd = os.open(activation_id, _OPEN_DIR, dir_fd=root_fd)
        info = os.fstat(activation_fd)
        entry = os.stat(activation_id, dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)):
            raise ListenerActivationUnavailable("new activation directory identity or custody is invalid")
        canonical_directory = _CONTROL_ROOT / activation_id
        named_directory = canonical_directory.lstat()
        if (stat.S_ISLNK(named_directory.st_mode)
                or (named_directory.st_dev, named_directory.st_ino) != (info.st_dev, info.st_ino)):
            raise ListenerActivationUnavailable("activation directory pathname differs from held custody")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        listener.set_inheritable(False)
        canonical_socket = canonical_directory / "control.sock"
        listener.bind(str(canonical_socket))
        created_socket = True
        os.chown("control.sock", 0, 0, dir_fd=activation_fd, follow_symlinks=False)
        os.chmod("control.sock", 0o600, dir_fd=activation_fd, follow_symlinks=False)
        listener.listen(1)
        listener.settimeout(3.0)
        leaf = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
        after_directory = canonical_directory.lstat()
        after_socket = canonical_socket.lstat()
        if (listener.getsockname() != str(canonical_socket)
                or (after_directory.st_dev, after_directory.st_ino) != (info.st_dev, info.st_ino)
                or (after_socket.st_dev, after_socket.st_ino) != (leaf.st_dev, leaf.st_ino)
                or not stat.S_ISSOCK(leaf.st_mode) or leaf.st_uid != 0 or leaf.st_gid != 0
                or stat.S_IMODE(leaf.st_mode) != 0o600):
            raise ListenerActivationUnavailable("new activation control socket is not root-private")
        return root_fd, activation_fd, listener, (info.st_dev, info.st_ino)
    except BaseException:
        if listener is not None:
            listener.close()
        if activation_fd >= 0:
            if created_socket:
                try:
                    os.unlink("control.sock", dir_fd=activation_fd)
                except OSError:
                    pass
            os.close(activation_fd)
        if created_directory:
            try:
                os.rmdir(activation_id, dir_fd=root_fd)
            except OSError:
                pass
        os.close(root_fd)
        raise


def _read_record_at(activation_fd: int) -> tuple[dict[str, Any], str, tuple[int, int]]:
    try:
        fd = os.open("state.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), dir_fd=activation_fd)
    except OSError:
        raise ListenerActivationUnavailable("activation journal record is unavailable") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1 or info.st_size > _MAX_MESSAGE * 2):
            raise ListenerActivationUnavailable("activation journal custody is invalid")
        raw = bytearray()
        while len(raw) <= _MAX_MESSAGE * 2:
            chunk = os.read(fd, min(4096, _MAX_MESSAGE * 2 + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        if len(raw) != info.st_size:
            raise ListenerActivationUnavailable("activation journal changed during read")
    finally:
        os.close(fd)
    try:
        value = json.loads(bytes(raw).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (ValueError, UnicodeError):
        raise ListenerActivationUnavailable("activation journal is malformed") from None
    if (not isinstance(value, dict) or set(value) != _RECORD_FIELDS or value.get("schema") != 1
            or value.get("state") not in {"prepared", "receiver-verified", "fd-sent", "adopted", "cancelled"}):
        raise ListenerActivationUnavailable("activation journal schema or state is unknown")
    integer_fields = {
        "schema", "service_uid", "service_gid", "socket_device", "socket_inode",
        "setup_pid", "setup_start_ticks", "daemon_pid", "daemon_start_ticks",
        "activation_root_device", "activation_root_inode", "activation_socket_device",
        "activation_socket_inode",
    }
    text_fields = _RECORD_FIELDS - integer_fields - {"issued_monotonic", "expires_monotonic", "state"}
    digest_fields = {
        "prepared_endpoint_receipt_sha256", "publication_sha256", "service_generation_digest",
        "setup_interpreter_sha256", "setup_launcher_sha256", "setup_actor_binding_sha256",
        "daemon_unit_fragment_sha256", "daemon_interpreter_sha256", "daemon_launcher_sha256",
        "release_deployment_receipt_sha256", "release_closure_manifest_sha256", "nonce_sha256",
    }
    if (any(type(value.get(key)) is not int or value[key] < 0 for key in integer_fields)
            or any(not isinstance(value.get(key), str) or not value[key] or len(value[key]) > 1024
                   for key in text_fields)
            or any(not _HEX64.fullmatch(value[key]) for key in digest_fields)
            or any(type(value.get(key)) not in {int, float} for key in ("issued_monotonic", "expires_monotonic"))
            or not value["issued_monotonic"] < value["expires_monotonic"]
            or value["expires_monotonic"] - value["issued_monotonic"] > _MAX_TTL):
        raise ListenerActivationUnavailable("activation journal field types, hashes, or deadline are invalid")
    leaf = os.stat("state.json", dir_fd=activation_fd, follow_symlinks=False)
    if (leaf.st_dev, leaf.st_ino) != (info.st_dev, info.st_ino):
        raise ListenerActivationUnavailable("activation journal leaf changed while being read")
    return value, hashlib.sha256(raw).hexdigest(), (info.st_dev, info.st_ino)


def _write_initial_record(activation_fd: int, record: Mapping[str, Any]) -> str:
    if set(record) != _RECORD_FIELDS or record.get("schema") != 1:
        raise ListenerActivationUnavailable("initial activation record differs from closed schema 1")
    raw = _canonical(dict(record))
    if len(raw) > _MAX_MESSAGE * 2:
        raise ListenerActivationUnavailable("activation record exceeds its fixed bound")
    fd = os.open("state.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=activation_fd)
    try:
        os.fchown(fd, 0, 0)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(fd, raw[offset:])
        os.fsync(fd)
    except BaseException:
        try:
            os.unlink("state.json", dir_fd=activation_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    os.fsync(activation_fd)
    return hashlib.sha256(raw).hexdigest()


def _cas_activation_record(activation_fd: int, expected_sha256: str,
                           new_state: str) -> tuple[dict[str, Any], str]:
    import fcntl
    if new_state not in {"receiver-verified", "fd-sent", "adopted", "cancelled"}:
        raise ListenerActivationUnavailable("activation state transition is outside schema 1")
    fcntl.flock(activation_fd, fcntl.LOCK_EX)
    try:
        original, digest, old_identity = _read_record_at(activation_fd)
        if not secrets.compare_digest(digest, expected_sha256):
            raise ListenerActivationUnavailable("activation journal compare-and-swap lost its current version")
        transitions = {"prepared": {"receiver-verified", "cancelled"},
                       "receiver-verified": {"fd-sent", "cancelled"},
                       "fd-sent": {"adopted", "cancelled"},
                       "adopted": set(), "cancelled": set()}
        if new_state not in transitions[original["state"]]:
            raise ListenerActivationUnavailable("activation state transition is duplicate or out of order")
        updated = dict(original)
        updated["state"] = new_state
        raw = _canonical(updated)
        temp = ".state-" + secrets.token_hex(16)
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=activation_fd)
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        try:
            again, again_digest, identity = _read_record_at(activation_fd)
            if again_digest != expected_sha256 or identity != old_identity or again != original:
                raise ListenerActivationUnavailable("activation journal changed during compare-and-swap")
            os.replace(temp, "state.json", src_dir_fd=activation_fd, dst_dir_fd=activation_fd)
            os.fsync(activation_fd)
        except BaseException:
            try:
                os.unlink(temp, dir_fd=activation_fd)
            except OSError:
                pass
            raise
        result, result_digest, _identity = _read_record_at(activation_fd)
        return result, result_digest
    finally:
        fcntl.flock(activation_fd, fcntl.LOCK_UN)


class RootAuthorityListenerActivationSupervisor:
    """Setup-side coordinator for one real, supervised listener adoption."""

    def __init__(self, binding: Any, custodian: Any, held_release: Any,
                 current_actor: Any, authority_root_receipt: Any, *,
                 inspector: SystemdAuthorityDaemonInspector | None = None):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .native_worker_endpoint_custody import RootPreparedAuthorityEndpointCustodian
        from .runtime_root_custody import RootPreparedAuthorityRootReceipt
        if (type(binding) is not RootSelectedInstallationBinding
                or type(custodian) is not RootPreparedAuthorityEndpointCustodian
                or custodian.binding is not binding
                or type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(current_actor) is not RootActorObservation
                or type(authority_root_receipt) is not RootPreparedAuthorityRootReceipt
                or custodian.prepared_authority_root_receipt is not authority_root_receipt
                or os.geteuid() != 0):
            raise ListenerActivationUnavailable("exact live root setup, endpoint, release, and root receipts are required")
        current_actor.verify_current(held_release)
        authority_root_receipt.verify_current()
        self.binding, self.custodian = binding, custodian
        self.held_release, self.current_actor = held_release, current_actor
        self.authority_root_receipt = authority_root_receipt
        self.inspector = inspector or SystemdAuthorityDaemonInspector()
        self._issuer = object()
        self._selections: dict[str, RootVerifiedListenerActivationSelection] = {}
        self._transactions: dict[str, RootActiveAuthorityListenerReceipt] = {}
        self._closed = False

    @classmethod
    def from_root_setup(cls, current_binding: Any, custodian: Any,
                        held_release: Any, current_actor: Any,
                        authority_root_receipt: Any, *,
                        inspector: SystemdAuthorityDaemonInspector | None = None
                        ) -> "RootAuthorityListenerActivationSupervisor":
        return cls(current_binding, custodian, held_release, current_actor,
                   authority_root_receipt, inspector=inspector)

    def verify_setup_selection(self, endpoint_receipt_handle: str,
                               publication: Any) -> RootVerifiedListenerActivationSelection:
        """Resolve the selected source/member graph from the live post-CAS root."""
        self._check_setup_actor()
        from .setup_policy_publication import RootSetupPublicationReceipt
        from .native_worker_endpoint_custody import RootPreparedAuthorityListenerReceipt
        session = self.binding._session
        if (type(publication) is not RootSetupPublicationReceipt
                or publication.state != "active-committed"
                or not isinstance(endpoint_receipt_handle, str)):
            raise ListenerActivationUnavailable("a current active publication and selected endpoint are required")
        try:
            # The root receipt is explicitly adopted by the committed CAS;
            # ordinary prepared-session endpoint resolution is no longer valid.
            self.authority_root_receipt.adopt_current_active_publication()
            current_publication = session._resolve_current_active_policy_publication()
            active = session._resolve_current_active_enrollment()
            endpoint = self.custodian._receipts.get(endpoint_receipt_handle)
            selection_handle = session._current_native_policy_selection_handle
            if (type(endpoint) is not RootPreparedAuthorityListenerReceipt
                    or endpoint._issuer is not self.custodian._issuer
                    or current_publication.publication_handle != publication.publication_handle
                    or current_publication.publication_sha256 != publication.publication_sha256
                    or current_publication.generation_id != publication.generation_id
                    or current_publication.service_generation_digest != publication.service_generation_digest
                    or publication.transaction_handle != endpoint.transaction_handle
                    or publication.service_generation_digest != active.generation_digest
                    or publication.generation_id != active.generation_id
                    or active.state != "committed" or not active.enrollment_ids
                    or active.transaction_handle != endpoint.transaction_handle
                    or endpoint.setup_session_id != session._handle.session_id
                    or endpoint.plan_sha256 != session._authorization.plan_digest
                    or not isinstance(selection_handle, str) or not selection_handle):
                raise ValueError("publication, active CAS, setup session, and endpoint do not join")
            endpoint = self.custodian._resolve_current_activation_endpoint(endpoint_receipt_handle)
            producer = session.resolve_current_native_worker_service_generation_producer()
            generation = producer.resolve_current_selected_generation(selection_handle)
            if (generation.setup_session_id != session._handle.session_id
                    or generation.transaction_handle != endpoint.transaction_handle
                    or generation.source_choice_selection_handle != selection_handle):
                raise ValueError("selected native generation differs from the live setup transaction")
            runtime_row, active_row, profile_row, service_row = _activation_generation_rows(
                generation, publication, endpoint)
            committed = session._transaction.verify_committed_receipt(active, session._authorization)
            if producer.verify_active_current(generation, committed, runtime_row["id"]) is not generation:
                raise ValueError("current active native source/member receipt changed")
            materialization = generation._runtime_materialization
            materializer = session.resolve_current_native_worker_runtime_materialization_registry()
            if (materializer._active_bindings.get(materialization.receipt_handle) != active.generation_id
                    or materializer._issued.get(materialization.receipt_handle) is not materialization):
                raise ValueError("actual retained PM/output members were not adopted by the committed CAS")
            adopted = [row for row in publication.choice_adoptions
                       if row.selection_handle == selection_handle
                       and row.service_generation_digest == publication.service_generation_digest
                       and row.setup_deadline_unix > time.time()]
            if len(adopted) != 1:
                raise ValueError("signed selected worker source has no unique current publisher adoption")
            remaining = adopted[0].setup_deadline_unix - time.time()
            deadline = min(self.authority_root_receipt.expires_monotonic,
                           endpoint.expires_monotonic, time.monotonic() + remaining)
            if deadline <= time.monotonic():
                raise ValueError("original setup deadline has expired")
            self.authority_root_receipt.adopt_current_active_publication()
            self.authority_root_receipt.verify_current()
            receipt = RootVerifiedListenerActivationSelection(
                endpoint.receipt_handle, publication.receipt_handle,
                publication.publication_sha256, publication.service_generation_digest,
                publication.generation_id, selection_handle, runtime_row["id"],
                endpoint.profile_id, endpoint.service_uid, endpoint.service_gid,
                deadline, endpoint, publication, generation, materialization,
                self.authority_root_receipt, self, self._issuer)
            previous = self._selections.get(endpoint.receipt_handle)
            if previous is not None:
                if (previous._endpoint is not endpoint or previous._generation is not generation
                        or previous._materialization is not materialization
                        or previous.publication_sha256 != receipt.publication_sha256
                        or previous.service_generation_digest != receipt.service_generation_digest
                        or previous.selection_handle != receipt.selection_handle
                        or previous.profile_id != receipt.profile_id
                        or previous.service_uid != receipt.service_uid
                        or previous.service_gid != receipt.service_gid):
                    raise ValueError("previously issued activation selection changed its joined source")
                return previous
            self._selections[endpoint.receipt_handle] = receipt
            return receipt
        except ListenerActivationUnavailable:
            raise
        except Exception as exc:
            raise ListenerActivationUnavailable(
                "current committed setup source, runtime members, and endpoint do not join") from exc

    def verify_current_selection(self, selection: RootVerifiedListenerActivationSelection
                                  ) -> RootVerifiedListenerActivationSelection:
        self._check_setup_actor()
        if (type(selection) is not RootVerifiedListenerActivationSelection
                or selection._issuer is not self._issuer
                or self._selections.get(selection.endpoint_receipt_handle) is not selection):
            raise ListenerActivationUnavailable("activation selection is not a current supervisor-issued receipt")
        current_publication = self.binding._session._resolve_current_active_policy_publication()
        current = self.verify_setup_selection(selection.endpoint_receipt_handle, current_publication)
        if current is not selection:
            raise ListenerActivationUnavailable("active source selection changed after issuance")
        return selection

    def _verify_ack_for_export(self, export: Any, acknowledgment: Any) -> None:
        if (type(export) is not __import__(
                "hermes_installer.authority.native_worker_endpoint_custody",
                fromlist=["RootActiveAuthorityListenerExport"]).RootActiveAuthorityListenerExport
                or type(acknowledgment) is not RootAuthorityDaemonSupervisorAcknowledgment
                or acknowledgment._seal is not _ACK_SEAL
                or acknowledgment._issuer is not self._issuer
                or export._selection._supervisor is not self
                or export._selection._issuer is not self._issuer
                or acknowledgment.endpoint_receipt_handle != export.endpoint_receipt_handle
                or acknowledgment.publication_receipt_handle != export.publication_receipt_handle
                or acknowledgment.publication_sha256 != export.publication_sha256
                or acknowledgment.service_generation_digest != export.service_generation_digest
                or acknowledgment.socket_device != export.socket_device
                or acknowledgment.socket_inode != export.socket_inode
                or not _HEX32.fullmatch(acknowledgment.activation_id)
                or not _HEX64.fullmatch(acknowledgment.activation_record_sha256)
                or not _HEX64.fullmatch(acknowledgment.nonce_sha256)):
            raise ListenerActivationUnavailable("daemon acknowledgement is not sealed to the active listener export")
        unit_selection = _selection_from_release(self.held_release, acknowledgment.activation_id)
        peer = self.inspector.inspect_authority_daemon(unit_selection)
        try:
            if (peer.pid != acknowledgment.peer_pid
                    or peer.start_ticks != acknowledgment.peer_start_ticks
                    or peer.invocation_id != acknowledgment.daemon_invocation_id):
                raise ListenerActivationUnavailable("ACK peer is not the current fixed unit MainPID")
            self.verify_current_selection(export._selection)
        finally:
            peer.close()

    def begin_active_listener_activation(self, endpoint_receipt_handle: str,
                                         publication: Any) -> RootActiveAuthorityListenerReceipt:
        """Launch the exact fixed root daemon and consume one transferred listener FD."""
        self._check_setup_actor()
        selection = self.verify_setup_selection(endpoint_receipt_handle, publication)
        if endpoint_receipt_handle in self._transactions:
            return self.verify_active_current(self._transactions[endpoint_receipt_handle])
        activation_id = secrets.token_hex(16)
        daemon_selection = _selection_from_release(self.held_release, activation_id)
        root_fd = activation_fd = -1
        control: socket.socket | None = None
        connection: socket.socket | None = None
        exported: Any = None
        daemon_peer: RootAuthorityDaemonPeerObservation | None = None
        record_created = False
        try:
            self.authority_root_receipt.verify_current()
            root_fd, activation_fd, control, root_identity = _create_control_listener(
                activation_id, self.authority_root_receipt._prefix_fd,
                self.authority_root_receipt._prefix_identity)
            control_leaf = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
            _install_fixed_unit(daemon_selection)
            _systemd_mutation("daemon-reload")
            _systemd_mutation("start")
            daemon_peer = self.inspector.inspect_authority_daemon(daemon_selection)
            self.inspector.verify_current(daemon_peer, daemon_selection)
            endpoint_digest = _digest({
                "receipt_handle": selection._endpoint.receipt_handle,
                "profile_id": selection.profile_id,
                "service_uid": selection.service_uid,
                "service_gid": selection.service_gid,
                "socket_device": selection._endpoint.socket_device,
                "socket_inode": selection._endpoint.socket_inode,
                "challenge_sha256": selection._endpoint.challenge_sha256,
            })
            now = time.monotonic()
            expires = min(now + _MAX_TTL, selection.original_setup_deadline_monotonic,
                          selection._endpoint.expires_monotonic)
            nonce = secrets.token_bytes(32)
            record = {
                "schema": 1, "activation_id": activation_id,
                "setup_session_id": selection._endpoint.setup_session_id,
                "transaction_handle": selection._endpoint.transaction_handle,
                "prepared_endpoint_receipt_handle": selection.endpoint_receipt_handle,
                "prepared_endpoint_receipt_sha256": endpoint_digest,
                "publication_receipt_handle": selection.publication_receipt_handle,
                "publication_sha256": selection.publication_sha256,
                "service_generation_digest": selection.service_generation_digest,
                "profile_id": selection.profile_id,
                "service_enrollment_id": selection._generation.service_records[0].get("id"),
                "service_uid": selection.service_uid, "service_gid": selection.service_gid,
                "socket_device": selection._endpoint.socket_device,
                "socket_inode": selection._endpoint.socket_inode,
                "setup_pid": self.current_actor.pid,
                "setup_start_ticks": self.current_actor.start_time,
                "setup_interpreter_sha256": self.current_actor.interpreter[3],
                "setup_launcher_sha256": self.current_actor.launcher[3],
                "setup_actor_binding_sha256": _digest({
                    "pid": self.current_actor.pid, "uid": self.current_actor.uid,
                    "gid": self.current_actor.gid, "start_ticks": self.current_actor.start_time,
                    "launcher": list(self.current_actor.launcher),
                    "interpreter": list(self.current_actor.interpreter),
                    "modules": [list(row) for row in self.current_actor.module_origins],
                }),
                "daemon_unit_id": daemon_selection.unit_id,
                "daemon_unit_fragment_sha256": daemon_selection.unit_file_sha256,
                "daemon_invocation_id": daemon_peer.invocation_id,
                "daemon_pid": daemon_peer.pid,
                "daemon_start_ticks": daemon_peer.start_ticks,
                "daemon_cgroup": daemon_peer.cgroup,
                "daemon_interpreter_sha256": daemon_peer.executable_sha256,
                "daemon_launcher_sha256": daemon_selection.launcher_sha256,
                "release_deployment_receipt_sha256": daemon_selection.deployment_receipt_sha256,
                "release_closure_manifest_sha256": daemon_selection.closure_manifest_sha256,
                "activation_root_device": root_identity[0], "activation_root_inode": root_identity[1],
                "activation_socket_device": control_leaf.st_dev,
                "activation_socket_inode": control_leaf.st_ino,
                "nonce_sha256": hashlib.sha256(nonce).hexdigest(),
                "issued_monotonic": now, "expires_monotonic": expires, "state": "prepared",
            }
            record_digest = _write_initial_record(activation_fd, record)
            record_created = True
            remaining = expires - time.monotonic()
            if remaining <= 0:
                raise ListenerActivationUnavailable("activation reached its original setup deadline")
            control.settimeout(min(3.0, remaining))
            connection, _ = control.accept()
            expected_daemon = (daemon_peer.pid, 0, 0)
            if _read_peer_cred(connection) != expected_daemon:
                raise ListenerActivationUnavailable("activation socket peer differs from fixed daemon MainPID")
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            challenge = _activation_message(
                operation="daemon-ready-for-listener", activation_id=activation_id,
                nonce=nonce, record_sha256=record_digest,
                publication_handle=selection.publication_receipt_handle,
                publication_sha256=selection.publication_sha256,
                generation_sha256=selection.service_generation_digest,
                endpoint_sha256=endpoint_digest,
                socket_device=selection._endpoint.socket_device,
                socket_inode=selection._endpoint.socket_inode)
            _send_packet(connection, challenge)
            ready, fds = _recv_packet(connection, expected_peer=expected_daemon, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("daemon-ready unexpectedly carried a descriptor")
            _verify_packet(ready, challenge)
            if not secrets.compare_digest(hashlib.sha256(nonce).hexdigest(), record["nonce_sha256"]):
                raise ListenerActivationUnavailable("one-use listener nonce does not match its protected record")
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "receiver-verified")
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            exported = self.custodian._export_current_active_listener(
                selection.endpoint_receipt_handle, selection)
            if (getattr(exported, "socket_device", None) != selection._endpoint.socket_device
                    or getattr(exported, "socket_inode", None) != selection._endpoint.socket_inode):
                raise ListenerActivationUnavailable("endpoint export differs from selected live socket inode")
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "fd-sent")
            transfer = _activation_message(
                operation="transfer-listener", activation_id=activation_id,
                nonce=nonce, record_sha256=record_digest,
                publication_handle=selection.publication_receipt_handle,
                publication_sha256=selection.publication_sha256,
                generation_sha256=selection.service_generation_digest,
                endpoint_sha256=endpoint_digest,
                socket_device=selection._endpoint.socket_device,
                socket_inode=selection._endpoint.socket_inode)
            _send_packet(connection, transfer, fd=exported.listener_fd)
            ack, fds = _recv_packet(connection, expected_peer=expected_daemon, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("listener adoption acknowledgement carried an FD")
            _verify_packet(ack, {**transfer, "operation": "listener-adopted"})
            self._check_setup_actor()
            self.authority_root_receipt.verify_current()
            self.inspector.verify_current(daemon_peer, daemon_selection)
            record, record_digest = _cas_activation_record(activation_fd, record_digest, "adopted")
            ack_type = RootAuthorityDaemonSupervisorAcknowledgment
            ack_receipt = ack_type(
                activation_id, record_digest, selection.endpoint_receipt_handle,
                selection._endpoint.socket_device, selection._endpoint.socket_inode,
                selection.publication_receipt_handle, selection.publication_sha256,
                selection.service_generation_digest, hashlib.sha256(nonce).hexdigest(),
                daemon_peer.invocation_id, daemon_peer.pid, daemon_peer.start_ticks,
                self._issuer, _ACK_SEAL)
            self.custodian._adopt_after_supervisor_ack(exported, ack_receipt, self._issuer)
            final_peer = self.inspector.inspect_authority_daemon(daemon_selection)
            try:
                if (final_peer.pid != daemon_peer.pid
                        or final_peer.invocation_id != daemon_peer.invocation_id
                        or final_peer.start_ticks != daemon_peer.start_ticks):
                    raise ListenerActivationUnavailable("daemon changed after listener adoption acknowledgement")
                active = RootActiveAuthorityListenerReceipt(
                    activation_id, record_digest, selection.endpoint_receipt_handle,
                    selection.publication_receipt_handle, selection.publication_sha256,
                    selection.service_generation_digest, selection._endpoint.socket_device,
                    selection._endpoint.socket_inode, daemon_selection.unit_id,
                    final_peer.invocation_id, final_peer.pid, final_peer.start_ticks,
                    time.monotonic(), expires, self._issuer)
            finally:
                final_peer.close()
            self._transactions[endpoint_receipt_handle] = active
            return active
        except BaseException:
            if activation_fd >= 0 and record_created:
                try:
                    current, digest, _identity = _read_record_at(activation_fd)
                    if current["state"] not in {"adopted", "cancelled"}:
                        _cas_activation_record(activation_fd, digest, "cancelled")
                except Exception:
                    pass
            # Unit/socket cleanup is identity-safe and only attempted before
            # a successful adoption; a live adopted daemon owns its listener.
            if daemon_peer is not None:
                try:
                    self.inspector.verify_current(daemon_peer, daemon_selection)
                except Exception:
                    pass
            raise
        finally:
            if exported is not None:
                try:
                    exported.close()
                except Exception:
                    pass
            if connection is not None:
                connection.close()
            if control is not None:
                control.close()
            if activation_fd >= 0:
                os.close(activation_fd)
            if root_fd >= 0:
                os.close(root_fd)
            if daemon_peer is not None:
                daemon_peer.close()

    def verify_active_current(self, receipt: RootActiveAuthorityListenerReceipt
                              ) -> RootActiveAuthorityListenerReceipt:
        self._check_setup_actor()
        if (type(receipt) is not RootActiveAuthorityListenerReceipt
                or receipt._issuer is not self._issuer
                or receipt.expires_monotonic <= time.monotonic()
                or self._transactions.get(receipt.endpoint_receipt_handle) is not receipt):
            raise ListenerActivationUnavailable("active listener receipt is foreign, stale, or expired")
        self.authority_root_receipt.verify_current()
        self.verify_setup_selection(receipt.endpoint_receipt_handle,
                                    self.binding._session._resolve_current_active_policy_publication())
        return receipt

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._selections.clear()
        self._transactions.clear()

    def _check_setup_actor(self) -> None:
        if self._closed:
            raise ListenerActivationUnavailable("setup supervisor is closed")
        try:
            self.binding._session._check_live()
            self.held_release.verify_current()
            self.current_actor.verify_current(self.held_release)
            self.authority_root_receipt.verify_current()
        except Exception:
            raise ListenerActivationUnavailable("local root setup actor or held source custody is no longer current") from None


class RootAuthorityListenerActivationReceiver:
    """Installed-daemon receiver for one systemd-supervised listener handoff."""

    def __init__(self, service: Any, enrollment: Any, activation_id: str,
                 held_release: Any, current_actor: Any, *,
                 inspector: SystemdAuthorityDaemonInspector | None = None):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .runtime_composition import RootAuthorityRuntime
        runtime = getattr(service, "root_authority_runtime", None)
        if (type(held_release) is not VerifiedInstallerReleaseReceipt
                or type(current_actor) is not RootActorObservation
                or type(runtime) is not RootAuthorityRuntime or runtime.service is not service
                or os.geteuid() != 0 or not _HEX32.fullmatch(activation_id)):
            raise ListenerActivationUnavailable("current installed daemon runtime and action ID are required")
        current_actor.verify_current(held_release)
        self.service, self.enrollment = service, enrollment
        self.activation_id, self.held_release = activation_id, held_release
        self.current_actor, self.runtime = current_actor, runtime
        self.inspector = inspector or SystemdAuthorityDaemonInspector()
        self.selection = _selection_from_release(held_release, activation_id)
        self._owner = None
        self._projection = None
        self._nonce: str | None = None
        self._setup_peer_pidfd: int | None = None

    @classmethod
    def from_current_installed_daemon(cls, runtime: Any, activation_id: str,
                                      held_release: Any, current_actor: Any, *,
                                      service: Any | None = None,
                                      enrollment: Any | None = None,
                                      inspector: SystemdAuthorityDaemonInspector | None = None
                                      ) -> "RootAuthorityListenerActivationReceiver":
        service = service or getattr(runtime, "service", None)
        if service is None or runtime is not getattr(service, "root_authority_runtime", None):
            raise ListenerActivationUnavailable("receiver runtime is detached from the local authority service")
        return cls(service, enrollment, activation_id, held_release, current_actor,
                   inspector=inspector)

    def receive_listener(self) -> tuple[socket.socket, RootActiveAuthorityListenerReceipt]:
        """Adopt, acknowledge, and wait for the setup journal's final CAS."""
        self._verify_local_runtime()
        peer = self.inspector.inspect_authority_daemon(self.selection)
        connection: socket.socket | None = None
        activation_fd = -1
        setup_peer_pidfd = -1
        listener: socket.socket | None = None
        try:
            if (peer.pid != os.getpid() or peer.uid != 0 or peer.gid != 0
                    or peer.start_ticks != _read_proc_start_ticks(Path("/proc"), os.getpid())):
                raise ListenerActivationUnavailable("receiver is not this fixed systemd MainPID")
            activation_fd, root_identity, channel_identity, record, digest = self._wait_prepared_record()
            try:
                setup_peer_pidfd = os.pidfd_open(record["setup_pid"], 0)
            except OSError:
                raise ListenerActivationUnavailable("setup supervisor PIDFD could not be opened") from None
            self._setup_peer_pidfd = setup_peer_pidfd
            if (record["activation_id"] != self.activation_id
                    or record["daemon_unit_id"] != self.selection.unit_id
                    or record["daemon_unit_fragment_sha256"] != self.selection.unit_file_sha256
                    or record["daemon_invocation_id"] != peer.invocation_id
                    or record["daemon_pid"] != peer.pid
                    or record["daemon_start_ticks"] != peer.start_ticks
                    or record["daemon_cgroup"] != peer.cgroup
                    or record["daemon_interpreter_sha256"] != peer.executable_sha256
                    or record["daemon_launcher_sha256"] != self.selection.launcher_sha256
                    or record["release_deployment_receipt_sha256"] != self.held_release.deployment_receipt_sha256
                    or record["release_closure_manifest_sha256"] != self.held_release.closure_manifest_sha256
                    or (record["activation_root_device"], record["activation_root_inode"]) != root_identity
                    or (record["activation_socket_device"], record["activation_socket_inode"]) != channel_identity
                    or record["state"] != "prepared"
                    or record["expires_monotonic"] <= time.monotonic()
                    or record["expires_monotonic"] - record["issued_monotonic"] > _MAX_TTL):
                raise ListenerActivationUnavailable("protected activation record differs from this daemon incarnation")
            self._resolve_current_projection(record)
            expected_setup_peer = self._verify_setup_peer(record)
            channel_path = _CONTROL_ROOT / self.activation_id / "control.sock"
            leaf = channel_path.lstat()
            if (not stat.S_ISSOCK(leaf.st_mode) or leaf.st_uid != 0 or leaf.st_gid != 0
                    or stat.S_IMODE(leaf.st_mode) != 0o600
                    or (leaf.st_dev, leaf.st_ino) != channel_identity):
                raise ListenerActivationUnavailable("activation control pathname custody changed")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
            connection.settimeout(min(3.0, record["expires_monotonic"] - time.monotonic()))
            connection.connect(str(channel_path))
            leaf = channel_path.lstat()
            if (leaf.st_dev, leaf.st_ino) != channel_identity:
                raise ListenerActivationUnavailable("activation control pathname changed during connect")
            challenge, fds = _recv_packet(connection, expected_peer=expected_setup_peer, expected_fd_count=0)
            if fds:
                raise ListenerActivationUnavailable("readiness challenge unexpectedly carried an FD")
            self._verify_message(challenge, record, digest, "daemon-ready-for-listener")
            self._verify_local_runtime()
            self._resolve_current_projection(record)
            if self._verify_setup_peer(record) != expected_setup_peer:
                raise ListenerActivationUnavailable("setup supervisor credentials changed during activation")
            self.inspector.verify_current(peer, self.selection)
            self._nonce = challenge["nonce"]
            _send_packet(connection, challenge)
            transfer, descriptors = _recv_packet(connection, expected_peer=expected_setup_peer,
                                                 expected_fd_count=1)
            current, digest, _identity = _read_record_at(activation_fd)
            if current["state"] != "fd-sent":
                raise ListenerActivationUnavailable("listener FD arrived outside the one-use sent state")
            self._verify_message(transfer, current, digest, "transfer-listener")
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            if self._verify_setup_peer(current) != expected_setup_peer:
                raise ListenerActivationUnavailable("setup supervisor credentials changed before FD transfer")
            self.inspector.verify_current(peer, self.selection)
            if any(current[key] != record[key] for key in (
                    "socket_device", "socket_inode", "prepared_endpoint_receipt_handle",
                    "prepared_endpoint_receipt_sha256", "publication_receipt_handle",
                    "publication_sha256", "service_generation_digest", "nonce_sha256")):
                raise ListenerActivationUnavailable("current FD transfer changed its selected endpoint or source")
            try:
                listener = _verify_transferred_listener(
                    descriptors[0], socket_device=current["socket_device"],
                    socket_inode=current["socket_inode"], owner_uid=current["service_uid"],
                    owner_gid=current["service_gid"])
            except BaseException:
                for descriptor in descriptors:
                    try:
                        os.close(descriptor)
                    except OSError:
                        pass
                raise
            active = RootActiveAuthorityListenerReceipt(
                self.activation_id, digest, current["prepared_endpoint_receipt_handle"],
                current["publication_receipt_handle"], current["publication_sha256"],
                current["service_generation_digest"], current["socket_device"],
                current["socket_inode"], current["daemon_unit_id"],
                current["daemon_invocation_id"], current["daemon_pid"],
                current["daemon_start_ticks"], time.monotonic(),
                current["expires_monotonic"], _RECEIVER_ISSUER)
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            self.inspector.verify_current(peer, self.selection)
            ack = dict(transfer)
            ack["operation"] = "listener-adopted"
            _send_packet(connection, ack)
            self._await_adoption(activation_fd, record)
            self._verify_local_runtime()
            self._resolve_current_projection(current)
            self.inspector.verify_current(peer, self.selection)
            return listener, active
        except BaseException:
            if listener is not None:
                listener.close()
            raise
        finally:
            if connection is not None:
                connection.close()
            if activation_fd >= 0:
                os.close(activation_fd)
            self._setup_peer_pidfd = None
            if setup_peer_pidfd >= 0:
                os.close(setup_peer_pidfd)
            peer.close()

    def _wait_prepared_record(self) -> tuple[int, tuple[int, int], tuple[int, int],
                                               dict[str, Any], str]:
        deadline = time.monotonic() + _MAX_TTL
        while time.monotonic() < deadline:
            root_fd = activation_fd = -1
            try:
                root_fd = os.open(_CONTROL_ROOT, _OPEN_DIR)
                root = os.fstat(root_fd)
                named_root = _CONTROL_ROOT.lstat()
                if ((root.st_dev, root.st_ino) != (named_root.st_dev, named_root.st_ino)
                        or root.st_uid != 0 or root.st_gid != 0
                        or stat.S_IMODE(root.st_mode) != 0o711):
                    raise ListenerActivationUnavailable("fixed activation root is not protected")
                activation_fd = os.open(self.activation_id, _OPEN_DIR, dir_fd=root_fd)
                directory = os.fstat(activation_fd)
                named_directory = os.stat(self.activation_id, dir_fd=root_fd, follow_symlinks=False)
                if ((directory.st_dev, directory.st_ino) != (named_directory.st_dev, named_directory.st_ino)
                        or directory.st_uid != 0 or directory.st_gid != 0
                        or stat.S_IMODE(directory.st_mode) != 0o700):
                    raise ListenerActivationUnavailable("activation transaction directory is not protected")
                record, digest, _identity = _read_record_at(activation_fd)
                channel = os.stat("control.sock", dir_fd=activation_fd, follow_symlinks=False)
                if (not stat.S_ISSOCK(channel.st_mode) or channel.st_uid != 0 or channel.st_gid != 0
                        or stat.S_IMODE(channel.st_mode) != 0o600
                        or (root.st_dev, root.st_ino) != (
                            record["activation_root_device"], record["activation_root_inode"])):
                    raise ListenerActivationUnavailable("activation channel or protected root inode changed")
                identity, channel_identity = (directory.st_dev, directory.st_ino), (channel.st_dev, channel.st_ino)
                os.close(root_fd)
                return activation_fd, identity, channel_identity, record, digest
            except FileNotFoundError:
                if activation_fd >= 0:
                    os.close(activation_fd)
                if root_fd >= 0:
                    os.close(root_fd)
                time.sleep(0.025)
            except BaseException:
                if activation_fd >= 0:
                    os.close(activation_fd)
                raise
        raise ListenerActivationUnavailable("protected activation record did not appear within the bounded start interval")

    def _verify_local_runtime(self) -> None:
        try:
            self.held_release.verify_current()
            self.current_actor.verify_current(self.held_release)
            if (os.getpid() != self.current_actor.pid
                    or _read_proc_start_ticks(Path("/proc"), os.getpid()) != self.current_actor.start_time):
                raise ValueError("receiver process identity changed")
        except Exception:
            raise ListenerActivationUnavailable("daemon's own installed root actor is no longer current") from None

    def _verify_setup_peer(self, record: Mapping[str, Any]) -> tuple[int, int, int]:
        if (record["setup_pid"] <= 1 or self._setup_peer_pidfd is None
                or self.inspector._pidfd_exited(self._setup_peer_pidfd)):
            raise ListenerActivationUnavailable("setup supervisor PID/start-time witness is stale")
        try:
            start = _read_proc_start_ticks(Path("/proc"), record["setup_pid"])
            uid, gid = _read_proc_effective_ids(Path("/proc"), record["setup_pid"])
            proc = Path("/proc") / str(record["setup_pid"])
            executable = proc / "exe"
            executable_info = os.stat(executable)
            expected_interpreter = self.selection.interpreter_path.stat(follow_symlinks=False)
            executable_hash = hashlib.sha256(executable.read_bytes()).hexdigest()
            argv = (proc / "cmdline").read_bytes().split(b"\0")
            if argv and argv[-1] == b"":
                argv.pop()
            decoded_argv = [item.decode("utf-8", errors="strict") for item in argv]
            if (start != record["setup_start_ticks"] or uid != 0
                    or record["setup_launcher_sha256"] != self.selection.launcher_sha256
                    or record["setup_interpreter_sha256"] != self.selection.interpreter_sha256
                    or os.path.realpath(executable) != str(self.selection.interpreter_path)
                    or (executable_info.st_dev, executable_info.st_ino) != (
                        expected_interpreter.st_dev, expected_interpreter.st_ino)
                    or executable_hash != self.selection.interpreter_sha256
                    or len(decoded_argv) != 8
                    or decoded_argv[0] != str(self.selection.interpreter_path)
                    or decoded_argv[1:5] != ["-B", "-I", "-S", "-c"]
                    or decoded_argv[5] != _SETUP_LAUNCHER_SOURCE
                    or decoded_argv[6] != str(self.selection.launcher_path)
                    or decoded_argv[7] not in {"install", "resume", "update"}
                    or self.inspector._pidfd_exited(self._setup_peer_pidfd)
                    or _read_proc_start_ticks(Path("/proc"), record["setup_pid"]) != start
                    or _read_proc_effective_ids(Path("/proc"), record["setup_pid"]) != (uid, gid)):
                raise ValueError("setup process changed while reading credentials")
            return record["setup_pid"], uid, gid
        except (OSError, StopIteration, ValueError, IndexError, UnicodeError):
            raise ListenerActivationUnavailable("setup supervisor PID/start-time/root credentials are stale") from None

    def _resolve_current_projection(self, record: Mapping[str, Any]) -> Any:
        from .active_network_generation import RootActiveNetworkGenerationOwner
        try:
            rows = tuple(self.runtime.bindings.enrollment_catalog.active_network_generation_records)
            selected = [row for row in rows if row.get("profile_id") == record["profile_id"]]
            if len(selected) != 1:
                raise ValueError("no unique active worker row")
            if self._owner is None:
                self._owner = RootActiveNetworkGenerationOwner.from_root_runtime(self.runtime)
            projection = self._owner.resolve_selected_worker(selected[0]["network_id"], record["profile_id"])
            self._owner.verify_current(projection)
            if (projection.publication_receipt_handle != record["publication_receipt_handle"]
                    or projection.publication_sha256 != record["publication_sha256"]
                    or projection.service_generation_digest != record["service_generation_digest"]
                    or projection.enrollment_id != record["service_enrollment_id"]
                    or projection.profile_generation != self.service.profile_generations.get(record["profile_id"])
                    or projection.source_choice_selection_handle != selected[0].get("source_choice_selection_handle")):
                raise ValueError("daemon publication/source projection differs from setup selection")
            if self._projection is not None and (
                    self._projection.publication_sha256 != projection.publication_sha256
                    or self._projection.service_generation_digest != projection.service_generation_digest
                    or self._projection.source_choice_selection_handle != projection.source_choice_selection_handle):
                raise ValueError("active source projection changed during FD adoption")
            self._projection = projection
            return projection
        except Exception:
            raise ListenerActivationUnavailable("daemon could not independently reopen active source and publication") from None

    def _verify_message(self, message: Mapping[str, Any], record: Mapping[str, Any],
                        digest: str, operation: str) -> None:
        nonce = message.get("nonce") if operation == "daemon-ready-for-listener" else self._nonce
        if (not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or not secrets.compare_digest(hashlib.sha256(bytes.fromhex(nonce)).hexdigest(),
                                              record["nonce_sha256"])):
            raise ListenerActivationUnavailable("activation nonce differs from protected one-use journal")
        expected = _activation_message(
            operation=operation, activation_id=record["activation_id"], nonce=bytes.fromhex(nonce),
            record_sha256=digest, publication_handle=record["publication_receipt_handle"],
            publication_sha256=record["publication_sha256"],
            generation_sha256=record["service_generation_digest"],
            endpoint_sha256=record["prepared_endpoint_receipt_sha256"],
            socket_device=record["socket_device"], socket_inode=record["socket_inode"])
        _verify_packet(message, expected)

    def _await_adoption(self, activation_fd: int, prepared: Mapping[str, Any]) -> None:
        deadline = min(prepared["expires_monotonic"], time.monotonic() + 3.0)
        while time.monotonic() < deadline:
            current, _digest_value, _identity = _read_record_at(activation_fd)
            if current["state"] == "adopted":
                if any(current[key] != prepared[key] for key in (
                        "activation_id", "setup_pid", "setup_start_ticks", "nonce_sha256",
                        "publication_receipt_handle", "publication_sha256", "service_generation_digest",
                        "prepared_endpoint_receipt_handle", "prepared_endpoint_receipt_sha256")):
                    raise ListenerActivationUnavailable("adopted record does not join this receiver transaction")
                return
            if current["state"] == "cancelled":
                raise ListenerActivationUnavailable("setup cancelled ambiguous listener adoption")
            time.sleep(0.025)
        raise ListenerActivationUnavailable("supervisor did not commit listener adoption before its bounded deadline")


_RECEIVER_ISSUER = object()
