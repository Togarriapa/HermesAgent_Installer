"""Kernel and loaded-module custody for selected root Resources controllers.

The role catalog is supplied by the active protected service-generation
snapshot. Event bindings come from the root-private source observer registry;
neither interface is an RPC or a worker assertion. A controller is returned
only while its systemd MainPID, pidfd, procfs identity, loaded role module, and
active generation agree.
"""
from __future__ import annotations

import hashlib
import math
import marshal
import os
import re
import select
import secrets
import stat
import subprocess
import sys
import threading
import time
import types
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import FunctionType
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .types import AuthorityDenied

_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = frozenset({"root-scheduler", "root-webhook", "root-channel"})
_OPERATIONS = frozenset({"resource.cron.run", "resource.webhook.run",
                         "resource.channel.run", "resource.bundle.node.run"})
_MAX_ROLES = 64
_MAX_LEASE = 600


def _valid_id(value: object, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AuthorityDenied("controller.role", f"invalid {field}")
    return value


def _finite_number(value: int | float) -> bool:
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


@dataclass(frozen=True, slots=True)
class RootControllerRoleEnrollment:
    id: str
    controller_kind: str
    daemon_unit_id: str
    daemon_executable_artifact_id: str
    daemon_executable_sha256: str
    role_module_artifact_id: str
    role_module_sha256: str
    controller_generation: str
    source_observer_enrollment_ids: tuple[str, ...]
    allowed_backend_enrollment_ids: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    max_lease_seconds: int

    def __post_init__(self) -> None:
        for field in ("id", "daemon_unit_id", "daemon_executable_artifact_id",
                      "role_module_artifact_id", "controller_generation"):
            _valid_id(getattr(self, field), field)
        if self.controller_kind not in _KINDS:
            raise AuthorityDenied("controller.role", "controller kind is not in the protected set")
        for field in ("daemon_executable_sha256", "role_module_sha256"):
            if not isinstance(getattr(self, field), str) or not _DIGEST.fullmatch(getattr(self, field)):
                raise AuthorityDenied("controller.role", f"invalid {field}")
        for field in ("source_observer_enrollment_ids", "allowed_backend_enrollment_ids",
                      "allowed_operations"):
            values = getattr(self, field)
            if (not isinstance(values, tuple) or not values or len(values) > 64
                    or len(set(values)) != len(values)):
                raise AuthorityDenied("controller.role", f"invalid {field}")
        for item in (*self.source_observer_enrollment_ids,
                     *self.allowed_backend_enrollment_ids):
            _valid_id(item, "role enrollment reference")
        if any(item not in _OPERATIONS for item in self.allowed_operations):
            raise AuthorityDenied("controller.role", "role operation is not in the protected set")
        if type(self.max_lease_seconds) is not int or not 1 <= self.max_lease_seconds <= _MAX_LEASE:
            raise AuthorityDenied("controller.role", "role lease exceeds its protected bound")


class RootControllerRoleCatalog:
    """Strict immutable view over role rows covered by one generation digest."""

    __slots__ = ("_rows", "generation_digest")

    def __init__(self, records: Any, *, generation_digest: str) -> None:
        if not isinstance(generation_digest, str) or not _DIGEST.fullmatch(generation_digest):
            raise AuthorityDenied("controller.catalog", "active generation digest is invalid")
        if not isinstance(records, (list, tuple)) or len(records) > _MAX_ROLES:
            raise AuthorityDenied("controller.catalog", "active role catalog is malformed")
        expected = {"id", "controller_kind", "daemon_unit_id",
                    "daemon_executable_artifact_id", "daemon_executable_sha256",
                    "role_module_artifact_id", "role_module_sha256", "controller_generation",
                    "source_observer_enrollment_ids", "allowed_backend_enrollment_ids",
                    "allowed_operations", "max_lease_seconds"}
        rows: dict[str, RootControllerRoleEnrollment] = {}
        for raw in records:
            if not isinstance(raw, Mapping) or set(raw) != expected:
                raise AuthorityDenied("controller.catalog", "active role row fields are invalid")
            if any(not isinstance(raw[key], list) for key in (
                    "source_observer_enrollment_ids", "allowed_backend_enrollment_ids",
                    "allowed_operations")):
                raise AuthorityDenied("controller.catalog", "active role lists are malformed")
            try:
                row = RootControllerRoleEnrollment(
                    id=raw["id"], controller_kind=raw["controller_kind"],
                    daemon_unit_id=raw["daemon_unit_id"],
                    daemon_executable_artifact_id=raw["daemon_executable_artifact_id"],
                    daemon_executable_sha256=raw["daemon_executable_sha256"],
                    role_module_artifact_id=raw["role_module_artifact_id"],
                    role_module_sha256=raw["role_module_sha256"],
                    controller_generation=raw["controller_generation"],
                    source_observer_enrollment_ids=tuple(raw["source_observer_enrollment_ids"]),
                    allowed_backend_enrollment_ids=tuple(raw["allowed_backend_enrollment_ids"]),
                    allowed_operations=tuple(raw["allowed_operations"]),
                    max_lease_seconds=raw["max_lease_seconds"],
                )
            except (TypeError, ValueError):
                raise AuthorityDenied("controller.catalog", "active role row is invalid") from None
            if row.id in rows:
                raise AuthorityDenied("controller.catalog", "active role ID is duplicated")
            rows[row.id] = row
        self._rows = MappingProxyType(rows)
        self.generation_digest = generation_digest

    def get(self, role_id: str) -> RootControllerRoleEnrollment:
        try:
            return self._rows[role_id]
        except KeyError:
            raise AuthorityDenied("controller.role", "selected role is absent from active generation") from None

    @property
    def rows(self) -> tuple[RootControllerRoleEnrollment, ...]:
        return tuple(self._rows.values())


@dataclass(frozen=True, slots=True)
class ControllerExecutablePin:
    artifact_id: str
    path: Path
    sha256: str

    def __post_init__(self) -> None:
        _valid_id(self.artifact_id, "executable artifact ID")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise AuthorityDenied("controller.executable", "executable artifact path is invalid")
        if not isinstance(self.sha256, str) or not _DIGEST.fullmatch(self.sha256):
            raise AuthorityDenied("controller.executable", "executable artifact digest is invalid")


@dataclass(frozen=True, slots=True)
class RootControllerProcessIdentity:
    daemon_unit_id: str
    pid: int
    pidfd: int
    uid: int
    start_time_ticks: int
    cgroup: str
    executable_artifact_id: str
    executable_sha256: str
    pid_namespace: tuple[int, int]
    mount_namespace: tuple[int, int]
    user_namespace: tuple[int, int]
    observed_monotonic: float


class DaemonUnitInspector(Protocol):
    def inspect(self, unit_id: str, executable_pin: ControllerExecutablePin) -> RootControllerProcessIdentity: ...

    def duplicate_pidfd(self, pidfd: int, pid: int) -> int: ...

    def close_pidfd(self, pidfd: int) -> None: ...

    def is_pidfd_live(self, pidfd: int, pid: int) -> bool: ...


class SystemdMainPidInspector:
    """Inspect only the root-selected systemd unit's actual MainPID."""

    _PROPERTIES = ("LoadState", "ActiveState", "MainPID", "ControlGroup")

    def __init__(self, *, systemctl: Path = Path("/usr/bin/systemctl"),
                 proc_root: Path = Path("/proc"), monotonic: Callable[[], float] = time.monotonic,
                 run: Callable[..., Any] = subprocess.run, euid: Callable[[], int] = os.geteuid):
        if not systemctl.is_absolute() or not proc_root.is_absolute():
            raise ValueError("systemd and procfs paths must be absolute")
        self.systemctl, self.proc_root = systemctl, proc_root
        self.monotonic, self.run, self.euid = monotonic, run, euid

    def _pidfd_pid(self, fd: int) -> int:
        try:
            for line in (self.proc_root / "self" / "fdinfo" / str(fd)).read_text().splitlines():
                if line.startswith("Pid:"):
                    return int(line.split(":", 1)[1].strip())
        except (OSError, ValueError):
            pass
        return -1

    def is_pidfd_live(self, pidfd: int, pid: int) -> bool:
        if self._pidfd_pid(pidfd) != pid:
            return False
        poller = select.poll()
        try:
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            return not bool(poller.poll(0))
        except (OSError, ValueError):
            return False

    def duplicate_pidfd(self, pidfd: int, pid: int) -> int:
        if not self.is_pidfd_live(pidfd, pid):
            raise AuthorityDenied("controller.pidfd", "selected daemon pidfd is stale")
        duplicate = os.dup(pidfd)
        if not self.is_pidfd_live(duplicate, pid):
            os.close(duplicate)
            raise AuthorityDenied("controller.pidfd", "duplicated daemon pidfd is stale")
        return duplicate

    @staticmethod
    def close_pidfd(pidfd: int) -> None:
        try:
            os.close(pidfd)
        except OSError:
            pass

    def inspect(self, unit_id: str, executable_pin: ControllerExecutablePin) -> RootControllerProcessIdentity:
        _valid_id(unit_id, "systemd unit ID")
        if (unit_id.startswith("-") or "/" in unit_id or "\\" in unit_id
                or any(char.isspace() or ord(char) < 0x20 for char in unit_id)):
            raise AuthorityDenied("controller.systemd", "selected systemd unit ID is malformed")
        if self.euid() != 0:
            raise AuthorityDenied("controller.uid", "root controller custody requires UID 0")
        completed = self.run(
            [str(self.systemctl), "--system", "show", "--no-pager",
             "--property=" + ",".join(self._PROPERTIES), unit_id],
            check=False, capture_output=True, text=True, timeout=3.0,
        )
        if getattr(completed, "returncode", 1) != 0:
            raise AuthorityDenied("controller.systemd", "selected systemd unit could not be observed")
        props: dict[str, str] = {}
        for line in completed.stdout.splitlines():
            key, sep, value = line.partition("=")
            if not sep or key not in self._PROPERTIES or key in props:
                raise AuthorityDenied("controller.systemd", "systemd unit observation is malformed")
            props[key] = value
        if (set(props) != set(self._PROPERTIES) or props["LoadState"] != "loaded"
                or props["ActiveState"] != "active" or not props["ControlGroup"].startswith("/")):
            raise AuthorityDenied("controller.systemd", "selected systemd unit is not active")
        try:
            pid = int(props["MainPID"])
        except ValueError:
            pid = 0
        if pid <= 1:
            raise AuthorityDenied("controller.systemd", "selected unit has no live MainPID")
        proc = self.proc_root / str(pid)
        try:
            pidfd = os.pidfd_open(pid, 0)
        except (AttributeError, OSError):
            raise AuthorityDenied("controller.pidfd", "kernel pidfd support is unavailable") from None
        try:
            if not self.is_pidfd_live(pidfd, pid):
                raise AuthorityDenied("controller.pidfd", "selected daemon pidfd is not live")
            stat_text = (proc / "stat").read_text()
            close_paren = stat_text.rfind(")")
            fields = stat_text[close_paren + 2:].split()
            start_time = int(fields[19])  # proc stat field 22, after fields 3..22
            status = (proc / "status").read_text()
            uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
            uid_values = [int(value) for value in uid_line.split()[1:5]]
            if len(uid_values) != 4 or uid_values[0] != 0 or uid_values[1] != 0:
                raise AuthorityDenied("controller.uid", "selected MainPID is not effective UID 0")
            uid = uid_values[1]
            cgroup_lines = (proc / "cgroup").read_text().splitlines()
            cgroups = [line.split("::", 1)[1] for line in cgroup_lines if "::" in line]
            if cgroups != [props["ControlGroup"]]:
                raise AuthorityDenied("controller.cgroup", "MainPID cgroup differs from selected unit")
            exe_path = proc / "exe"
            exe_target = os.readlink(exe_path)
            if exe_target.endswith(" (deleted)"):
                raise AuthorityDenied("controller.executable", "selected daemon executable was deleted")
            running_stat = os.stat(exe_path)
            pinned_stat = executable_pin.path.stat()
            if (os.path.realpath(exe_path) != os.path.realpath(executable_pin.path)
                    or (running_stat.st_dev, running_stat.st_ino)
                    != (pinned_stat.st_dev, pinned_stat.st_ino)
                    or not stat.S_ISREG(pinned_stat.st_mode) or pinned_stat.st_uid != 0
                    or pinned_stat.st_mode & 0o022):
                raise AuthorityDenied("controller.executable", "MainPID executable path differs from selected artifact")
            digest = hashlib.sha256(exe_path.read_bytes()).hexdigest()
            if uid != 0 or digest != executable_pin.sha256:
                raise AuthorityDenied("controller.executable", "MainPID UID or executable pin does not match")
            namespaces = {}
            for name in ("pid", "mnt", "user"):
                info = os.stat(proc / "ns" / name)
                namespaces[name] = (info.st_dev, info.st_ino)
            root_pid_ns = os.stat(self.proc_root / "1" / "ns" / "pid")
            root_mnt_ns = os.stat(self.proc_root / "1" / "ns" / "mnt")
            root_user_ns = os.stat(self.proc_root / "1" / "ns" / "user")
            if (namespaces["pid"] != (root_pid_ns.st_dev, root_pid_ns.st_ino)
                    or namespaces["mnt"] != (root_mnt_ns.st_dev, root_mnt_ns.st_ino)
                    or namespaces["user"] != (root_user_ns.st_dev, root_user_ns.st_ino)):
                raise AuthorityDenied("controller.namespace", "MainPID is outside the root namespaces")
            after = (proc / "stat").read_text()
            after_fields = after[after.rfind(")") + 2:].split()
            if (int(after_fields[19]) != start_time or not self.is_pidfd_live(pidfd, pid)):
                raise AuthorityDenied("controller.pidfd", "MainPID changed during inspection")
            return RootControllerProcessIdentity(
                daemon_unit_id=unit_id, pid=pid, pidfd=pidfd, uid=uid,
                start_time_ticks=start_time, cgroup=props["ControlGroup"],
                executable_artifact_id=executable_pin.artifact_id,
                executable_sha256=digest, pid_namespace=namespaces["pid"],
                mount_namespace=namespaces["mnt"], user_namespace=namespaces["user"],
                observed_monotonic=float(self.monotonic()),
            )
        except BaseException:
            self.close_pidfd(pidfd)
            raise


@dataclass(frozen=True, slots=True)
class LoadedRootControllerRoleProof:
    """Opaque reference to a module imported from verified bytes in this process."""
    proof_handle: str
    module: types.ModuleType
    module_artifact_id: str
    module_sha256: str
    pid: int
    start_time_ticks: int
    service_generation_digest: str
    controller_generation: str
    module_state_sha256: str


def _module_state_digest(module: types.ModuleType) -> str:
    """Fingerprint the loaded module's executable and root-selected bindings."""
    ignored = {"__builtins__", "__cached__", "__doc__", "__file__", "__loader__",
               "__name__", "__package__", "__spec__"}

    def describe(value: Any, seen: set[int]) -> bytes:
        if value is None or type(value) in {str, int, float, bool, bytes}:
            return (type(value).__name__ + ":" + repr(value)).encode("utf-8")
        if isinstance(value, FunctionType):
            if id(value) in seen:
                return b"function:recursive"
            seen.add(id(value))
            payload = marshal.dumps(value.__code__)
            payload += describe(value.__defaults__, seen)
            payload += describe(value.__kwdefaults__, seen)
            payload += describe(value.__annotations__, seen)
            payload += describe(value.__dict__, seen)
            return b"function:" + payload
        if isinstance(value, types.ModuleType):
            return f"module:{value.__name__}:{id(value)}".encode("utf-8")
        if isinstance(value, type):
            if id(value) in seen:
                return b"class:recursive"
            seen.add(id(value))
            entries = []
            for name, item in sorted(vars(value).items()):
                if name.startswith("__") and name.endswith("__"):
                    continue
                entries.append(name.encode("utf-8") + b"=" + describe(item, seen))
            return (f"class:{value.__module__}.{value.__qualname__}:".encode("utf-8")
                    + b";".join(entries))
        if isinstance(value, Mapping):
            if id(value) in seen:
                return b"mapping:recursive"
            seen.add(id(value))
            return b"mapping:" + b";".join(
                str(key).encode("utf-8") + b"=" + describe(item, seen)
                for key, item in sorted(value.items(), key=lambda pair: str(pair[0])))
        if isinstance(value, (tuple, list, set, frozenset)):
            if id(value) in seen:
                return b"sequence:recursive"
            seen.add(id(value))
            items = [describe(item, seen) for item in value]
            return b"sequence:" + b";".join(sorted(items) if isinstance(value, (set, frozenset)) else items)
        if hasattr(value, "__dict__") and isinstance(vars(value), dict):
            if id(value) in seen:
                return b"object:recursive"
            seen.add(id(value))
            return (f"object:{type(value).__module__}.{type(value).__qualname__}:".encode("utf-8")
                    + describe(vars(value), seen))
        return f"object:{type(value).__module__}.{type(value).__qualname__}:{id(value)}".encode("utf-8")

    state = {name: value for name, value in vars(module).items() if name not in ignored}
    return hashlib.sha256(describe(state, set())).hexdigest()


class RootControllerRoleModuleRegistry:
    """Imports only catalog-pinned role bytes and proves the actual module object."""

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic,
                 pid: Callable[[], int] = os.getpid, proc_root: Path = Path("/proc"),
                 start_time_resolver: Callable[[int], int] | None = None) -> None:
        self._monotonic, self._pid, self._proc_root = monotonic, pid, proc_root
        self._start_time_resolver = start_time_resolver or self._read_start_time
        self._proofs: dict[str, LoadedRootControllerRoleProof] = {}
        self._release_receipts: dict[str, Any] = {}

    def _read_start_time(self, pid: int) -> int:
        data = (self._proc_root / str(pid) / "stat").read_text()
        return int(data[data.rfind(")") + 2:].split()[19])

    def load_verified(self, *, module_name: str, artifact_id: str, expected_sha256: str,
                      source_bytes: bytes, service_generation_digest: str,
                      controller_generation: str) -> LoadedRootControllerRoleProof:
        _valid_id(artifact_id, "role module artifact ID")
        _valid_id(controller_generation, "controller generation")
        if (not isinstance(module_name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]{0,127}", module_name)
                or not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256)
                or not isinstance(source_bytes, bytes) or not 0 < len(source_bytes) <= 1_048_576
                or hashlib.sha256(source_bytes).hexdigest() != expected_sha256
                or not isinstance(service_generation_digest, str)
                or not _DIGEST.fullmatch(service_generation_digest)):
            raise AuthorityDenied("controller.module", "role module bytes are not pinned")
        module = types.ModuleType(module_name)
        module.__file__ = f"<protected-artifact:{artifact_id}:{expected_sha256}>"
        module.__package__ = module_name.rpartition(".")[0]
        try:
            code = compile(source_bytes, module.__file__, "exec", dont_inherit=True)
            if module_name in sys.modules:
                raise AuthorityDenied("controller.module", "role module name is already occupied")
            sys.modules[module_name] = module
            exec(code, module.__dict__)
        except BaseException:
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]
            raise AuthorityDenied("controller.module", "pinned role module failed to load") from None
        try:
            pid = self._pid()
            start_time_ticks = self._start_time_resolver(pid)
            module_state_sha256 = _module_state_digest(module)
        except BaseException:
            if sys.modules.get(module_name) is module:
                del sys.modules[module_name]
            raise AuthorityDenied("controller.module", "loaded role module proof could not be formed") from None
        proof = LoadedRootControllerRoleProof(
            proof_handle=uuid.uuid4().hex, module=module,
            module_artifact_id=artifact_id, module_sha256=expected_sha256,
            pid=pid, start_time_ticks=start_time_ticks,
            service_generation_digest=service_generation_digest,
            controller_generation=controller_generation,
            module_state_sha256=module_state_sha256,
        )
        self._proofs[proof.proof_handle] = proof
        return proof

    def load_from_installed_release(self, *, release_receipt: Any,
                                    module_name: str, artifact_id: str,
                                    expected_sha256: str,
                                    service_generation_digest: str,
                                    controller_generation: str) -> LoadedRootControllerRoleProof:
        """Load bounded source from an exact module member of the held release.

        The release verifier owns path traversal, ownership and the closure
        manifest.  This method uses only its artifact-ID FD interface and
        retains the receipt in each proof so currentness is checked whenever
        the proof is consumed.
        """
        from .installer_release import VerifiedInstallerReleaseReceipt

        if not isinstance(release_receipt, VerifiedInstallerReleaseReceipt):
            raise AuthorityDenied("controller.module", "verified installed-release receipt is required")
        try:
            release_receipt.verify_current()
            members = [item for item in release_receipt.files
                       if item.artifact_id == artifact_id]
            if (len(members) != 1 or members[0].roles != ("module",)
                    or members[0].sha256 != expected_sha256
                    or not 0 < members[0].size_bytes <= 1_048_576):
                raise AuthorityDenied("controller.module", "role artifact is outside the installed module closure")
            fd = release_receipt.open_file(artifact_id)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                        or stat.S_IMODE(info.st_mode) & 0o222
                        or info.st_size != members[0].size_bytes):
                    raise AuthorityDenied("controller.module", "role module FD custody is invalid")
                chunks: list[bytes] = []
                remaining = 1_048_577
                while remaining:
                    chunk = os.read(fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                source_bytes = b"".join(chunks)
            finally:
                os.close(fd)
            if (not source_bytes or len(source_bytes) != members[0].size_bytes
                    or hashlib.sha256(source_bytes).hexdigest() != expected_sha256):
                raise AuthorityDenied("controller.module", "role module bytes differ from installed release pin")
            release_receipt.verify_current()
            proof = self.load_verified(
                module_name=module_name, artifact_id=artifact_id,
                expected_sha256=expected_sha256, source_bytes=source_bytes,
                service_generation_digest=service_generation_digest,
                controller_generation=controller_generation,
            )
            self._release_receipts[proof.proof_handle] = release_receipt
            release_receipt.verify_current()
            return proof
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("controller.module", "role module could not be loaded from current installed release") from None

    def require_loaded(self, artifact_id: str, module_sha256: str, *, pid: int,
                       start_time_ticks: int, service_generation_digest: str,
                       controller_generation: str) -> LoadedRootControllerRoleProof:
        matches = [proof for proof in self._proofs.values()
                   if proof.module_artifact_id == artifact_id
                   and proof.module_sha256 == module_sha256 and proof.pid == pid
                   and proof.start_time_ticks == start_time_ticks
                   and proof.service_generation_digest == service_generation_digest
                   and proof.controller_generation == controller_generation]
        if len(matches) != 1 or not self.verify(
                matches[0], module_artifact_id=artifact_id, module_sha256=module_sha256,
                pid=pid, start_time_ticks=start_time_ticks,
                service_generation_digest=service_generation_digest,
                controller_generation=controller_generation):
            raise AuthorityDenied("controller.module", "unique current loaded role module proof is unavailable")
        return matches[0]

    def revoke_generation(self, service_generation_digest: str) -> int:
        doomed = [key for key, proof in self._proofs.items()
                  if proof.service_generation_digest == service_generation_digest]
        for key in doomed:
            proof = self._proofs.pop(key)
            self._release_receipts.pop(key, None)
            if sys.modules.get(proof.module.__name__) is proof.module:
                del sys.modules[proof.module.__name__]
        return len(doomed)

    def verify(self, proof: LoadedRootControllerRoleProof, *, module_artifact_id: str,
               module_sha256: str, pid: int, start_time_ticks: int,
               service_generation_digest: str,
               controller_generation: str) -> bool:
        if not isinstance(proof, LoadedRootControllerRoleProof):
            return False
        registered = self._proofs.get(proof.proof_handle)
        if registered is not proof or registered.module is not proof.module:
            return False
        try:
            actual_start = self._start_time_resolver(self._pid())
            release = self._release_receipts.get(proof.proof_handle)
            if release is not None:
                release.verify_current()
        except (OSError, ValueError, IndexError):
            return False
        except Exception:
            return False
        return (
            proof.module_artifact_id == module_artifact_id
            and proof.module_sha256 == module_sha256
            and proof.pid == pid == self._pid()
            and proof.start_time_ticks == start_time_ticks == actual_start
            and proof.service_generation_digest == service_generation_digest
            and proof.controller_generation == controller_generation
            and sys.modules.get(proof.module.__name__) is proof.module
            and _module_state_digest(proof.module) == proof.module_state_sha256
        )


@dataclass(frozen=True, slots=True)
class RootControllerEventBinding:
    """Root-private event/node join returned by the source observer registry."""
    role: RootControllerRoleEnrollment
    event: Any
    resource_enrollment: Any
    node: Any
    backend: Any
    source_observer: Any
    service_generation_digest: str
    authority_epoch: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootSelectedIngressBinding:
    """Exact active static ingress selection, resolved before an event exists.

    The callback supplying this value is root-private and must join the active
    issuer, observer, resource/backend enrollment, and timer/route/account
    registration.  ``selected_ingress_binding_id`` names that static record;
    it is never an event or receipt identifier.
    """

    role: RootControllerRoleEnrollment
    source_issuer: Any
    source_observer: Any
    backend: Any
    resource_generation: str
    service_generation_digest: str
    authority_epoch: str
    selected_ingress_binding_id: str
    expires_monotonic: float


@dataclass(slots=True)
class RootIngressControllerProof:
    """Root-local proof of the selected live ingress dispatcher.

    ``pidfd`` is an owned duplicate and is closed by ``close``.  The resolver
    separately retains the custody PIDFD under ``proof_handle`` until explicit
    release, so the source registry can close this value after copying the
    proof into its retained pre-event record.
    """

    schema: int
    proof_handle: str
    controller_role_id: str
    controller_kind: str
    controller_generation: str
    source_issuer_id: str
    backend_enrollment_id: str
    resource_generation: str
    service_generation_digest: str
    authority_epoch: str
    pid: int
    pidfd: int
    uid: int
    live_peer_identity: RootControllerProcessIdentity
    role_artifact_id: str
    role_artifact_sha256: str
    namespace_id: str
    selected_ingress_binding_id: str
    issued_monotonic: float
    expires_monotonic: float
    _resolver: Any = field(repr=False, compare=False)
    _fd_closed: bool = field(default=False, init=False, repr=False, compare=False)

    def revalidate(self) -> bool:
        return self._resolver.revalidate_ingress_proof(self.proof_handle)

    def close(self) -> None:
        if not self._fd_closed:
            self._fd_closed = True
            self._resolver._inspector.close_pidfd(self.pidfd)


@dataclass(slots=True)
class _RetainedIngressProof:
    binding: RootSelectedIngressBinding
    custody: "RootControllerRoleCustody"
    proof: RootIngressControllerProof


class RootControllerRoleCustody:
    """Held custody lease for one selected root controller process and role."""

    def __init__(self, *, row: RootControllerRoleEnrollment,
                 identity: RootControllerProcessIdentity, owned_pidfd: int,
                 loaded_role_proof: LoadedRootControllerRoleProof,
                 generation_digest: str, expires_monotonic: float,
                 inspector: DaemonUnitInspector,
                 executable_pin: ControllerExecutablePin,
                 proof_registry: RootControllerRoleModuleRegistry,
                 current_generation_digest: Callable[[], str],
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        self.row, self.identity, self.pidfd = row, identity, owned_pidfd
        self.loaded_role_proof = loaded_role_proof
        self.generation_digest, self.expires_monotonic = generation_digest, expires_monotonic
        self._inspector, self._executable_pin = inspector, executable_pin
        self._proof_registry, self._current_generation_digest = proof_registry, current_generation_digest
        self._monotonic, self._closed = monotonic, False

    @property
    def pid(self) -> int:
        return self.identity.pid

    @property
    def uid(self) -> int:
        return self.identity.uid

    def duplicate_pidfd(self) -> int:
        if self._closed or not self._inspector.is_pidfd_live(self.pidfd, self.identity.pid):
            raise AuthorityDenied("controller.pidfd", "root controller pidfd is no longer live")
        duplicate = self._inspector.duplicate_pidfd(self.pidfd, self.identity.pid)
        if not self._inspector.is_pidfd_live(duplicate, self.identity.pid):
            self._inspector.close_pidfd(duplicate)
            raise AuthorityDenied("controller.pidfd", "duplicated root controller pidfd is stale")
        return duplicate

    def revalidate(self) -> bool:
        if self._closed or self._monotonic() >= self.expires_monotonic:
            return False
        if self._current_generation_digest() != self.generation_digest:
            return False
        if not self._inspector.is_pidfd_live(self.pidfd, self.identity.pid):
            return False
        try:
            current = self._inspector.inspect(self.row.daemon_unit_id, self._executable_pin)
            try:
                same_identity = (
                    current.pid == self.identity.pid
                    and current.start_time_ticks == self.identity.start_time_ticks
                    and current.cgroup == self.identity.cgroup
                    and current.uid == 0
                    and current.pid_namespace == self.identity.pid_namespace
                    and current.mount_namespace == self.identity.mount_namespace
                    and current.user_namespace == self.identity.user_namespace
                    and current.executable_artifact_id == self.row.daemon_executable_artifact_id
                    and current.executable_sha256 == self.row.daemon_executable_sha256
                )
            finally:
                self._inspector.close_pidfd(current.pidfd)
            return same_identity and self._proof_registry.verify(
                self.loaded_role_proof,
                module_artifact_id=self.row.role_module_artifact_id,
                module_sha256=self.row.role_module_sha256,
                pid=self.identity.pid, start_time_ticks=self.identity.start_time_ticks,
                service_generation_digest=self.generation_digest,
                controller_generation=self.row.controller_generation,
            )
        except (AuthorityDenied, OSError, ValueError):
            return False

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._inspector.close_pidfd(self.pidfd)

    def __enter__(self) -> "RootControllerRoleCustody":
        if not self.revalidate():
            self.close()
            raise AuthorityDenied("controller.stale", "root controller custody is stale")
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class RootControllerRoleResolver:
    """Resolve only a current observer/backend/node event to actual root custody."""

    def __init__(self, *, catalog: RootControllerRoleCatalog,
                 event_binding_resolver: Callable[[str, str], RootControllerEventBinding],
                 inspector: DaemonUnitInspector,
                 executable_resolver: Callable[[str], ControllerExecutablePin],
                 loaded_role_registry: RootControllerRoleModuleRegistry,
                 current_generation_digest: Callable[[], str],
                 selected_ingress_binding_resolver: Callable[[str, str, str], RootSelectedIngressBinding] | None = None,
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        if not all(callable(value) for value in (
                event_binding_resolver, executable_resolver,
                current_generation_digest, getattr(inspector, "inspect", None),
                getattr(inspector, "duplicate_pidfd", None), getattr(inspector, "close_pidfd", None),
                getattr(inspector, "is_pidfd_live", None))):
            raise ValueError("root controller resolver dependencies are incomplete")
        if selected_ingress_binding_resolver is not None and not callable(selected_ingress_binding_resolver):
            raise ValueError("selected ingress binding resolver must be callable")
        self.catalog = catalog
        self._event_binding_resolver = event_binding_resolver
        self._inspector, self._executable_resolver = inspector, executable_resolver
        if not isinstance(loaded_role_registry, RootControllerRoleModuleRegistry):
            raise ValueError("root loaded-role module registry is required")
        self._loaded_role_registry = loaded_role_registry
        self._current_generation_digest = current_generation_digest
        self._selected_ingress_binding_resolver = selected_ingress_binding_resolver
        self._monotonic = monotonic
        self._ingress_proofs: dict[str, _RetainedIngressProof] = {}
        self._ingress_lock = threading.RLock()

    @staticmethod
    def _ingress_join(binding: RootSelectedIngressBinding, role_id: str,
                      issuer_id: str, backend_id: str) -> None:
        """Fail closed unless this is the exact active static ingress join."""
        role, issuer = binding.role, binding.source_issuer
        observer, backend = binding.source_observer, binding.backend
        if not isinstance(role, RootControllerRoleEnrollment) or role.id != role_id:
            raise AuthorityDenied("controller.role", "selected ingress role is not the active role")
        if (getattr(issuer, "issuer_channel_id", None) != issuer_id
                or getattr(observer, "channel_id", None) != issuer_id
                or getattr(backend, "source_issuer_channel_id", None) != issuer_id
                or getattr(issuer, "producer_profile_id", None) != getattr(observer, "profile_id", None)
                or getattr(issuer, "capture_schema_id", None) != getattr(observer, "capture_schema_id", None)
                or getattr(backend, "profile_id", None) != getattr(observer, "profile_id", None)
                or getattr(backend, "principal_id", None) != getattr(observer, "principal_id", None)
                or getattr(backend, "generation", None) != binding.resource_generation):
            raise AuthorityDenied("controller.issuer", "selected ingress issuer join is invalid")
        observer_id = getattr(observer, "observer_enrollment_id", None)
        kind = {"schedule-event": "root-scheduler", "webhook-event": "root-webhook",
                "native-input": "root-channel"}.get(getattr(observer, "source_kind", None))
        if (kind != role.controller_kind or observer_id not in role.source_observer_enrollment_ids
                or getattr(issuer, "observer_enrollment_id", None) != observer_id
                or getattr(backend, "observer_enrollment_id", None) != observer_id
                or getattr(backend, "backend_id", None) != backend_id
                or backend_id not in role.allowed_backend_enrollment_ids
                or getattr(backend, "operation", None) not in role.allowed_operations):
            raise AuthorityDenied("controller.join", "selected ingress observer/backend join is invalid")
        if (not isinstance(binding.resource_generation, str)
                or not _DIGEST.fullmatch(binding.resource_generation)
                or not isinstance(binding.service_generation_digest, str)
                or not _DIGEST.fullmatch(binding.service_generation_digest)
                or not isinstance(binding.authority_epoch, str) or not binding.authority_epoch
                or not isinstance(binding.selected_ingress_binding_id, str)
                or not _ID.fullmatch(binding.selected_ingress_binding_id)
                or isinstance(binding.expires_monotonic, bool)
                or not isinstance(binding.expires_monotonic, (int, float))
                or not _finite_number(binding.expires_monotonic)):
            raise AuthorityDenied("controller.ingress", "selected ingress binding is malformed")

    def resolve_selected_ingress_controller(
            self, controller_role_id: str, selected_source_issuer_id: str,
            selected_backend_id: str) -> RootIngressControllerProof:
        """Resolve static root-selected ingress custody before any event/receipt.

        IDs are internal selection keys.  No PID, source event, receipt, or
        process identity is accepted from the caller.
        """
        role_id = _valid_id(controller_role_id, "controller role ID")
        issuer_id = _valid_id(selected_source_issuer_id, "source issuer ID")
        backend_id = _valid_id(selected_backend_id, "backend enrollment ID")
        callback = self._selected_ingress_binding_resolver
        if callback is None:
            raise AuthorityDenied("controller.ingress", "selected ingress resolver is not configured")
        if self._current_generation_digest() != self.catalog.generation_digest:
            raise AuthorityDenied("controller.generation", "active controller catalog is stale")
        binding = callback(role_id, issuer_id, backend_id)
        if not isinstance(binding, RootSelectedIngressBinding):
            raise AuthorityDenied("controller.ingress", "selected ingress resolver returned an invalid binding")
        self._ingress_join(binding, role_id, issuer_id, backend_id)
        role = binding.role
        if self.catalog.get(role.id) != role:
            raise AuthorityDenied("controller.role", "selected ingress role differs from active catalog")
        now = self._monotonic()
        if (binding.service_generation_digest != self.catalog.generation_digest
                or now >= binding.expires_monotonic
                or binding.expires_monotonic > now + role.max_lease_seconds):
            raise AuthorityDenied("controller.ingress", "selected ingress generation or lease is stale")
        if len(self._ingress_proofs) >= 256:
            self._expire_ingress_proofs()
            if len(self._ingress_proofs) >= 256:
                raise AuthorityDenied("controller.ingress", "retained ingress proof capacity is exhausted")
        pin = self._executable_resolver(role.daemon_executable_artifact_id)
        if (not isinstance(pin, ControllerExecutablePin)
                or pin.artifact_id != role.daemon_executable_artifact_id
                or pin.sha256 != role.daemon_executable_sha256):
            raise AuthorityDenied("controller.executable", "daemon executable pin does not match selected role")
        identity = self._inspector.inspect(role.daemon_unit_id, pin)
        owned_pidfd = caller_pidfd = None
        custody = None
        try:
            if (identity.daemon_unit_id != role.daemon_unit_id or identity.uid != 0
                    or identity.executable_artifact_id != role.daemon_executable_artifact_id
                    or identity.executable_sha256 != role.daemon_executable_sha256
                    or not self._inspector.is_pidfd_live(identity.pidfd, identity.pid)):
                raise AuthorityDenied("controller.identity", "selected systemd MainPID identity is invalid")
            loaded = self._loaded_role_registry.require_loaded(
                role.role_module_artifact_id, role.role_module_sha256, pid=identity.pid,
                start_time_ticks=identity.start_time_ticks,
                service_generation_digest=self.catalog.generation_digest,
                controller_generation=role.controller_generation)
            if (loaded.pid != identity.pid or loaded.start_time_ticks != identity.start_time_ticks
                    or loaded.module_artifact_id != role.role_module_artifact_id
                    or loaded.module_sha256 != role.role_module_sha256):
                raise AuthorityDenied("controller.module", "selected daemon has no current loaded role proof")
            owned_pidfd = self._inspector.duplicate_pidfd(identity.pidfd, identity.pid)
            if (not self._inspector.is_pidfd_live(owned_pidfd, identity.pid)
                    or self._current_generation_digest() != self.catalog.generation_digest
                    or self._monotonic() >= binding.expires_monotonic):
                raise AuthorityDenied("controller.stale", "selected ingress custody changed during resolution")
            expiry = min(float(binding.expires_monotonic), now + role.max_lease_seconds)
            custody = RootControllerRoleCustody(
                row=role, identity=replace(identity, pidfd=owned_pidfd), owned_pidfd=owned_pidfd,
                loaded_role_proof=loaded, generation_digest=self.catalog.generation_digest,
                expires_monotonic=expiry, inspector=self._inspector, executable_pin=pin,
                proof_registry=self._loaded_role_registry,
                current_generation_digest=self._current_generation_digest, monotonic=self._monotonic)
            caller_pidfd = custody.duplicate_pidfd()
            namespace_id = self._namespace_binding_id(identity)
            handle = secrets.token_urlsafe(32)
            proof = RootIngressControllerProof(
                schema=1, proof_handle=handle, controller_role_id=role.id,
                controller_kind=role.controller_kind, controller_generation=role.controller_generation,
                source_issuer_id=issuer_id, backend_enrollment_id=backend_id,
                resource_generation=binding.resource_generation,
                service_generation_digest=binding.service_generation_digest,
                authority_epoch=binding.authority_epoch,
                pid=identity.pid, pidfd=caller_pidfd, uid=identity.uid,
                live_peer_identity=replace(identity, pidfd=caller_pidfd),
                role_artifact_id=role.role_module_artifact_id,
                role_artifact_sha256=role.role_module_sha256, namespace_id=namespace_id,
                selected_ingress_binding_id=binding.selected_ingress_binding_id,
                issued_monotonic=now, expires_monotonic=expiry, _resolver=self)
            # Re-read the exact static binding after acquiring process custody.
            current = callback(role_id, issuer_id, backend_id)
            self._ingress_join(current, role_id, issuer_id, backend_id)
            if current != binding or self._current_generation_digest() != self.catalog.generation_digest:
                raise AuthorityDenied("controller.stale", "selected ingress changed during custody resolution")
            with self._ingress_lock:
                if len(self._ingress_proofs) >= 256:
                    raise AuthorityDenied("controller.ingress", "retained ingress proof capacity is exhausted")
                self._ingress_proofs[handle] = _RetainedIngressProof(binding, custody, proof)
            custody = None
            caller_pidfd = None
            return proof
        except BaseException:
            if custody is not None:
                custody.close()
            elif owned_pidfd is not None:
                self._inspector.close_pidfd(owned_pidfd)
            if caller_pidfd is not None:
                self._inspector.close_pidfd(caller_pidfd)
            raise
        finally:
            self._inspector.close_pidfd(identity.pidfd)

    @staticmethod
    def _namespace_binding_id(identity: RootControllerProcessIdentity) -> str:
        value = "|".join(str(part) for namespace in (
            identity.pid_namespace, identity.mount_namespace, identity.user_namespace)
                         for part in namespace)
        return "ns1:" + hashlib.sha256(value.encode("ascii")).hexdigest()

    def _expire_ingress_proofs(self) -> None:
        with self._ingress_lock:
            expired = [key for key, item in self._ingress_proofs.items()
                       if self._monotonic() >= item.proof.expires_monotonic
                       or self._current_generation_digest() != item.proof.service_generation_digest]
            for key in expired:
                item = self._ingress_proofs.pop(key)
                item.proof.close()
                item.custody.close()

    def revalidate_ingress_proof(self, proof_handle: str) -> bool:
        with self._ingress_lock:
            item = self._ingress_proofs.get(proof_handle)
        if item is None:
            return False
        if not item.custody.revalidate():
            self.release_ingress_proof(proof_handle)
            return False
        if self._selected_ingress_binding_resolver is None:
            self.release_ingress_proof(proof_handle)
            return False
        try:
            fresh = self._selected_ingress_binding_resolver(
                item.proof.controller_role_id, item.proof.source_issuer_id,
                item.proof.backend_enrollment_id)
            self._ingress_join(fresh, item.proof.controller_role_id,
                               item.proof.source_issuer_id, item.proof.backend_enrollment_id)
            valid = (fresh == item.binding
                     and fresh.service_generation_digest == item.proof.service_generation_digest
                     and fresh.authority_epoch == item.binding.authority_epoch
                     and fresh.selected_ingress_binding_id == item.proof.selected_ingress_binding_id)
        except (AuthorityDenied, OSError, ValueError, TypeError):
            valid = False
        if not valid:
            self.release_ingress_proof(proof_handle)
        return valid

    def release_ingress_proof(self, proof_handle: str) -> None:
        with self._ingress_lock:
            item = self._ingress_proofs.pop(proof_handle, None)
        if item is not None:
            item.proof.close()
            item.custody.close()

    def resolve_for_event(self, root_event_handle: str, node_id: str) -> RootControllerRoleCustody:
        _valid_id(root_event_handle, "root event handle")
        _valid_id(node_id, "resource node ID")
        if self._current_generation_digest() != self.catalog.generation_digest:
            raise AuthorityDenied("controller.generation", "active controller catalog is stale")
        binding = self._event_binding_resolver(root_event_handle, node_id)
        role = binding.role
        if not isinstance(role, RootControllerRoleEnrollment) or self.catalog.get(role.id) != role:
            raise AuthorityDenied("controller.role", "event role is not the active enrolled role")
        if (binding.service_generation_digest != self.catalog.generation_digest
                or not isinstance(binding.authority_epoch, str) or not binding.authority_epoch
                or isinstance(binding.expires_monotonic, bool)
                or not isinstance(binding.expires_monotonic, (float, int))
                or not self._monotonic() < binding.expires_monotonic
                or binding.expires_monotonic > self._monotonic() + role.max_lease_seconds):
            raise AuthorityDenied("controller.event", "event generation or lease is stale")
        observer = binding.source_observer
        backend = binding.backend
        node = binding.node
        event = binding.event
        resource = binding.resource_enrollment
        observer_id = getattr(observer, "observer_enrollment_id", None)
        expected_kind = {
            "schedule-event": "root-scheduler",
            "webhook-event": "root-webhook",
            "native-input": "root-channel",
        }.get(getattr(observer, "source_kind", None))
        if (observer_id
                not in role.source_observer_enrollment_ids
                or expected_kind != role.controller_kind
                or getattr(resource, "observer_enrollment_id", None) != observer_id
                or getattr(backend, "observer_enrollment_id", None) != observer_id
                or getattr(backend, "backend_id", getattr(backend, "id", None))
                not in role.allowed_backend_enrollment_ids
                or getattr(node, "node_id", None) != node_id
                or getattr(node, "backend_enrollment_id", None)
                != getattr(backend, "backend_id", None)
                or getattr(backend, "operation", None) not in role.allowed_operations
                or getattr(resource, "kind", None) not in {"crons", "webhooks", "channels", "bundles"}
                or getattr(resource, "selected_enabled", False) is not True
                or getattr(event, "observer_enrollment_id", observer_id) != observer_id):
            raise AuthorityDenied("controller.join", "event, observer, backend, node, or operation is not enrolled")
        resource_operation = {
            "crons": "resource.cron.run", "webhooks": "resource.webhook.run",
            "channels": "resource.channel.run", "bundles": "resource.bundle.node.run",
        }[resource.kind]
        if node.effect != resource_operation:
            raise AuthorityDenied("controller.operation", "selected node effect differs from resource kind")
        if role.daemon_unit_id != _valid_id(role.daemon_unit_id, "daemon unit ID"):
            raise AuthorityDenied("controller.unit", "selected daemon unit is invalid")
        if self._current_generation_digest() != self.catalog.generation_digest:
            raise AuthorityDenied("controller.generation", "active generation changed during event resolution")
        pin = self._executable_resolver(role.daemon_executable_artifact_id)
        if (not isinstance(pin, ControllerExecutablePin)
                or pin.artifact_id != role.daemon_executable_artifact_id
                or pin.sha256 != role.daemon_executable_sha256):
            raise AuthorityDenied("controller.executable", "daemon executable catalog pin does not match role")
        identity = self._inspector.inspect(role.daemon_unit_id, pin)
        owned_pidfd = None
        try:
            if (identity.daemon_unit_id != role.daemon_unit_id or identity.uid != 0
                    or identity.executable_artifact_id != role.daemon_executable_artifact_id
                    or identity.executable_sha256 != role.daemon_executable_sha256
                    or not self._inspector.is_pidfd_live(identity.pidfd, identity.pid)):
                raise AuthorityDenied("controller.identity", "selected systemd MainPID identity is invalid")
            loaded = self._loaded_role_registry.require_loaded(
                role.role_module_artifact_id, role.role_module_sha256,
                pid=identity.pid, start_time_ticks=identity.start_time_ticks,
                service_generation_digest=self.catalog.generation_digest,
                controller_generation=role.controller_generation,
            )
            if (not isinstance(loaded, LoadedRootControllerRoleProof)
                    or loaded.module_artifact_id != role.role_module_artifact_id
                    or loaded.module_sha256 != role.role_module_sha256
                    or loaded.pid != identity.pid
                    or loaded.start_time_ticks != identity.start_time_ticks
                    or loaded.service_generation_digest != self.catalog.generation_digest
                    or loaded.controller_generation != role.controller_generation):
                raise AuthorityDenied("controller.module", "selected daemon has no current loaded role proof")
            owned_pidfd = self._inspector.duplicate_pidfd(identity.pidfd, identity.pid)
            if not self._inspector.is_pidfd_live(owned_pidfd, identity.pid):
                raise AuthorityDenied("controller.pidfd", "owned controller pidfd failed validation")
            if (self._current_generation_digest() != self.catalog.generation_digest
                    or self._monotonic() >= binding.expires_monotonic):
                raise AuthorityDenied("controller.stale", "controller generation or event lease changed")
            return RootControllerRoleCustody(
                row=role, identity=replace(identity, pidfd=owned_pidfd), owned_pidfd=owned_pidfd,
                loaded_role_proof=loaded, generation_digest=self.catalog.generation_digest,
                expires_monotonic=float(binding.expires_monotonic), inspector=self._inspector,
                executable_pin=pin, proof_registry=self._loaded_role_registry,
                current_generation_digest=self._current_generation_digest,
                monotonic=self._monotonic,
            )
        except BaseException:
            if owned_pidfd is not None:
                self._inspector.close_pidfd(owned_pidfd)
            raise
        finally:
            self._inspector.close_pidfd(identity.pidfd)
