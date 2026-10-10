"""Root-side fixed process verbs for the protected AuthorityService.

This adapter is injected into the root-owned authority daemon. It accepts no
shell command or arbitrary manager property and trusts only protected profile
registrations plus the already verified, consumed host effect grant.
"""
from __future__ import annotations

import base64
import contextlib
import ctypes
import fcntl
import hashlib
import hmac
import json
import math
import os
import posixpath
import pwd
import re
import select
import shutil
import secrets
import stat
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest
from hermes_installer.registry.resource_jobs import RootAdmittedTask


@dataclass(frozen=True, slots=True)
class ManagedProfileCustody:
    profile_id: str
    owner_uid: int
    owner_gid: int
    service_user: str
    executable: Path
    artifact_sha256: str
    artifact_root: Path
    data_root: Path
    generation: str
    memory_max_bytes: int | None = None
    cpu_quota_percent: int | None = None
    io_weight: int | None = None
    max_lifetime_seconds: float = 600.0
    child_artifact_refs: Mapping[str, str] | None = None
    argv_recipe: tuple[str, ...] | None = None
    authority_socket: Path | None = None
    process_role_artifact_hashes: Mapping[str, str] | None = None
    # Root-resolved enrollment identity and distinct private roots. These are
    # never accepted from a worker request; the enrollment adapter supplies them.
    enrollment_id: str | None = None
    home_id: str | None = None
    work_id: str | None = None
    data_id: str | None = None
    home_root: Path | None = None
    work_root: Path | None = None
    operation_targets: Mapping[str, str] | None = None
    operation_recipes: Mapping[str, Mapping[str, Any]] | None = None
    parameter_schemas: Mapping[str, Mapping[str, Any]] | None = None
    # Root-materialized protected package binding; never supplied in an RPC.
    native_package: Any | None = None
    # Digest of the active protected service_generations snapshot. It is
    # supplied by the enrollment catalog and is never derived from this row.
    service_generation_digest: str | None = None


@dataclass(frozen=True, slots=True)
class ManagedNativePackageMount:
    """Root-only verified inputs for one immutable native package mount.

    The enrollment/runtime binder constructs this from NativePackageBinding
    and ArtifactCatalog results. Its filesystem paths never cross Authority RPC.
    """

    binding: Any
    profile_id: str
    generation: str
    closure_root: Path
    entrypoint_path: Path
    resolver_path: Path
    adapter_paths: Mapping[str, Path]
    dependency_paths: Mapping[str, Path]


@dataclass(frozen=True, slots=True)
class NativePackageMountReceipt:
    package_id: str
    profile_id: str
    generation: str
    service_mount_id: str
    compiled_closure_sha256: str
    entrypoint_sha256: str
    resolver_sha256: str
    mount_path: str
    mount_source_device: int
    mount_source_inode: int
    manifest_sha256: str
    verified_mount_options: tuple[str, ...] = ("ro", "nosuid", "nodev", "noexec")
    private_propagation: bool = True


@dataclass(frozen=True, slots=True)
class XauthorityMountReceipt:
    """Root-observed fixed display credential mount; no cookie bytes escape."""

    mount_path: str
    mount_source_device: int
    mount_source_inode: int
    source_sha256: str
    source_size_bytes: int
    owner_gid: int
    verified_mount_options: tuple[str, ...] = ("ro", "nosuid", "nodev", "noexec")
    private_propagation: bool = True


@dataclass(frozen=True, slots=True)
class LoadedNativePackageProof:
    """Root-observed package mount joined to the active registered process."""

    process_id: str
    profile_id: str
    generation: str
    kernel_uid: int
    pid_start_ticks: int
    cgroup_identity: str
    namespace_identity: str
    executable_sha256: str
    mount: NativePackageMountReceipt
    observed_monotonic: float


@dataclass(frozen=True, slots=True)
class ProcessCleanupProof:
    """Root-observed teardown facts for one managed generation."""

    process_id: str
    generation: str
    cgroup_identity: str
    cgroup_empty: bool
    main_pidfd_gone: bool
    parent_pidfd_gone: bool
    launcher_reaped: bool
    cleanup_verified: bool
    evidence_digest: str
    observed_monotonic: float


@dataclass(frozen=True, slots=True)
class LivePeerIdentity:
    """Root-observed identity for an authenticated live process peer."""

    profile_id: str
    generation: str
    kernel_uid: int
    start_ticks: int
    executable_sha256: str
    cgroup_identity: str
    namespace_identity: str


@dataclass(frozen=True, slots=True)
class RemoteOriginKernelProof:
    """Private root observation of the sole active enrolled process.

    This is kernel identity evidence only. It carries no route, config, token,
    application-window or origin-readiness claims.
    """

    process_id: str
    enrollment_id: str
    profile_id: str
    profile_generation: str
    uid: int
    gid: int
    pid: int
    pid_starttime_ticks: int
    executable_device: int
    executable_inode: int
    executable_sha256: str
    cgroup_id: str
    mount_namespace_inode: int
    network_namespace_inode: int
    pidfd_registry_handle: str
    expires_monotonic: float


@dataclass(slots=True)
class ManagedNamespaceLease:
    """Short-lived duplicated FDs for one exact live private network namespace."""

    namespace_fd: int
    pidfd: int
    uid: int
    cgroup_identity: str
    generation: str
    namespace_identity: str
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in (self.namespace_fd, self.pidfd):
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(slots=True)
class ManagedProcessIdentityLease:
    """Root-only duplicated PIDFD plus freshly revalidated process identity."""

    process_id: str
    profile_id: str
    generation: str
    uid: int
    gid: int
    pid: int
    start_ticks: int
    executable_device: int
    executable_inode: int
    executable_sha256: str
    cgroup_identity: str
    mount_namespace_inode: int
    network_namespace_inode: int
    expires_monotonic: float
    pidfd: int
    _closed: bool = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            os.close(self.pidfd)
        except OSError:
            pass


@dataclass(frozen=True, slots=True)
class RootSelectedServiceProcessReceipt:
    """Root-only reference to a process admitted by one sealed service effect.

    The receipt deliberately carries no PID, path, or descriptor.  Those facts
    are re-resolved from the manager's exact retained handle on demand.
    """

    schema: int
    receipt_handle: str
    process_id: str
    role: str
    action: str
    enrollment_id: str
    profile_id: str
    generation: str
    selected_principal_id: str
    selected_namespace_identity: str
    selected_subject_uid: int
    selected_subject_gid: int
    operation_id: str
    target: str
    service_generation_digest: str
    process_identity_digest: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootSelectedServiceStatusReceipt:
    """Typed manager observation joined to the exact retained start receipt."""

    schema: int
    receipt_handle: str
    process_receipt: RootSelectedServiceProcessReceipt = field(repr=False)
    state: str
    exit_code: int | None
    observed_monotonic: float
    process_identity_digest: str
    service_generation_digest: str


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedHealthControl:
    """Opaque root-owned control for one actual enrolled Hermes health run."""

    schema: int
    control_handle: str
    managed_process_handle: str
    process_id: str
    operation_id: str
    enrollment_id: str
    profile_id: str
    process_generation: str
    service_generation_digest: str
    bootstrap_transaction_handle: str
    committed_enrollment_receipt_id: str
    health_fixture_artifact_id: str
    health_fixture_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _manager: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or self.operation_id != "hermes-agent-health-v1"
                or any(not isinstance(getattr(self, name), str) or not getattr(self, name)
                       for name in ("control_handle", "managed_process_handle", "process_id",
                                    "enrollment_id", "profile_id", "process_generation",
                                    "bootstrap_transaction_handle", "committed_enrollment_receipt_id",
                                    "health_fixture_artifact_id"))
                or any(not isinstance(getattr(self, name), str)
                       or not re.fullmatch(r"[0-9a-f]{64}", getattr(self, name))
                       for name in ("service_generation_digest", "health_fixture_sha256"))
                or isinstance(self.issued_monotonic, bool)
                or not isinstance(self.issued_monotonic, (int, float))
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.issued_monotonic >= self.expires_monotonic
                or self._manager is None or self._seal is None):
            raise ValueError("root-selected health control is malformed")

    def is_current(self) -> bool:
        check = getattr(self._manager, "_health_control_current", None)
        return bool(callable(check) and check(self, self._seal))

    def __repr__(self) -> str:
        return "RootSelectedHealthControl(<root-private>)"


@dataclass(slots=True)
class _Handle:
    process_id: str
    profile: ManagedProfileCustody
    unit: str
    cgroup: str
    launcher: subprocess.Popen[bytes]
    parent_pidfd: int
    child_pidfd: int
    pid: int
    start_ticks: int
    kernel_namespace_id: str
    principal_id: str
    authority_namespace_id: str
    started: float
    expires: float
    output_cap: int
    artifact_mount_dir: Path
    native_mount_source: Path | None = None
    native_mount_receipt: NativePackageMountReceipt | None = None
    xauthority_mount_source: Path | None = None
    xauthority_mount_receipt: XauthorityMountReceipt | None = None
    network_namespace_fd: int | None = None
    child_artifact_identities: tuple[tuple[str, int, int], ...] = ()
    stdin_cursor: int = 0
    stdout_cursor: int = 0
    stderr_cursor: int = 0
    stdin_sequence: int = 0
    stopped: bool = False
    lock: threading.RLock | None = None
    # The immutable profile registered by the root daemon. ``profile`` may be a
    # derived record selecting one exact enrolled operation executable.
    registered_profile: ManagedProfileCustody | None = None
    task_owned: bool = False
    native_loader_observation_handle: str | None = None
    native_loader_ready_event_id: str | None = None


@dataclass(frozen=True, slots=True)
class ManagedTaskHandle:
    """Opaque root-only reference to a started task process; never put on wire."""

    handle_id: str
    generation: str
    process_id: str
    _stdin_write_receipt: list[str | None] = field(default_factory=lambda: [None],
                                                  repr=False, compare=False)

    @property
    def stdin_write_receipt_handle(self) -> str | None:
        """Manager-backed receipt handle, absent until the actual write/EOF."""
        return self._stdin_write_receipt[0]


@dataclass(frozen=True, slots=True)
class ManagedApplicationHandle:
    """Opaque manager-owned reference to a selected application process."""
    handle_id: str
    process_id: str
    profile_generation: str


@dataclass(slots=True)
class _ManagedApplicationState:
    handle: _Handle
    verified_start: Any
    step: Any
    selection_payload: bytes
    deadline: float
    cancelled: Callable[[], bool]
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_eof: bool = False
    stderr_eof: bool = False
    output_overflow: bool = False
    consumed: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock)


@dataclass(frozen=True, slots=True)
class RootApplicationTerminalReceipt:
    """Immutable bounded terminal facts from the selected-app process manager."""
    schema: int
    receipt_handle: str
    application_handle: str
    admission_handle: str
    application_id: str
    workload_id: str
    step_id: str
    sequence: int
    profile_id: str
    profile_generation: str
    service_generation_digest: str
    operation_id: str
    request_sha256: str
    source_receipt_handle: str
    runtime_receipt_handle: str
    process_id: str
    process_generation: str
    process_start_ticks: int
    executable_sha256: str
    cgroup_id: str
    namespace_digest: str
    exit_code: int | None
    stdin_eof: bool
    stdout_sha256: str
    stdout_size_bytes: int
    stderr_sha256: str
    stderr_size_bytes: int
    output_observation_handle: str
    reaped: bool
    cancelled: bool
    timed_out: bool
    state: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str

    def claims(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "signature"}


@dataclass(frozen=True, slots=True)
class RootTaskTerminalReceipt:
    """Root-observed bounded task completion and cleanup facts."""

    task_handle: str
    terminal_receipt_handle: str
    job_id: str
    node_id: str
    admission_id: str
    admission_handle_id: str
    backend_enrollment_id: str
    operation_id: str
    task_body_recipe_id: str
    task_request_schema_id: str
    resource_generation: str
    profile_id: str
    process_generation: str
    process_id: str
    exit_code: int | None
    timed_out: bool
    cancelled: bool
    started_monotonic: float
    finished_monotonic: float
    cgroup_identity: str
    cgroup_empty: bool
    main_pidfd_gone: bool
    descendants_gone: bool
    launcher_reaped: bool
    cleanup_verified: bool
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    output_complete: bool
    schema: int
    state: str
    observed_monotonic: float
    stdout_size_bytes: int
    stderr_size_bytes: int
    parent_closure_digest: str
    native_loader_ready_event_id: str | None
    # Native execution observations are issued by the companion registry and
    # remain separate from this immutable custody terminal receipt.
    native_execution_receipt_handle: str | None = None
    stdin_write_receipt_handle: str | None = None

    @property
    def task_handle_id(self) -> str:
        """Compatibility accessor for internal journal adapters."""
        return self.task_handle

    @property
    def terminal_receipt_id(self) -> str:
        """Compatibility accessor for internal journal adapters."""
        return self.terminal_receipt_handle

    @property
    def profile_generation(self) -> str:
        return self.process_generation


@dataclass(slots=True)
class _ManagedTaskState:
    handle: _Handle
    admission: RootAdmittedTask
    deadline: float
    stdin_deadline: float
    cancelled: Callable[[], bool]
    selection_payload: bytes
    admission_handle_id: str
    initial_input_receipt_handle: str | None = None
    initial_input_expires_monotonic: float | None = None
    service_generation_digest: str | None = None
    root_handle: ManagedTaskHandle | None = None
    stdin_write_receipt: Any | None = None
    input_closed: bool = False
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    stdout_eof: bool = False
    stderr_eof: bool = False
    output_overflow: bool = False
    consumed: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock)


_LAUNCH_FIELDS = {
    "schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root",
    "cwd", "data_root", "argv", "env_allowlist", "child_artifact_refs",
    "max_lifetime_seconds", "max_output_bytes", "stdin_mode",
}
_ALLOWED_ENV = {
    "HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HERMES_HOME", "TMPDIR", "XAUTHORITY",
}


def process_start_target(profile: ManagedProfileCustody) -> str:
    enrolled = (profile.operation_targets or {}).get("process.start")
    if enrolled is not None:
        return enrolled
    return (f"hermes-profile-invoke:{profile.profile_id}:{profile.executable}:"
            f"{profile.artifact_sha256}:{profile.data_root}")


def process_control_target(profile: ManagedProfileCustody, operation: str) -> str:
    if operation not in {"process.status", "process.read", "process.write", "process.stop"}:
        raise ValueError("process control operation is not fixed")
    enrolled = (profile.operation_targets or {}).get(operation)
    if enrolled is not None:
        return enrolled
    verb = operation.removeprefix("process.")
    return f"hermes-profile-control:{profile.profile_id}:{profile.data_root}:{verb}"


def process_inspect_target(profile: ManagedProfileCustody) -> str:
    enrolled = (profile.operation_targets or {}).get("process.inspect")
    if enrolled is not None:
        return enrolled
    return f"{profile.profile_id}:inspect"


def _code_interpreter(name: str) -> bool:
    normalized = name.casefold()
    return (normalized in {"bash", "sh", "dash", "zsh", "node", "ruby", "perl"}
            or normalized.startswith("python"))


_OPERATION_RECIPE_FIELDS = {
    "executable_artifact_id", "executable_sha256", "argv_recipe", "cwd_root_id",
    "cwd_subpath", "environment", "child_artifact_refs", "max_lifetime_seconds",
    "max_output_bytes", "stdin_mode", "parameter_schema_id",
}
_PARAMETER_FIELD_FIELDS = {
    "name", "type", "required", "enum", "max_length", "minimum", "maximum",
}


def _validate_service_root(path: Path, *, uid: int, gid: int) -> Path:
    if not path.is_absolute():
        raise ValueError("service roots must be absolute")
    resolved = path.resolve(strict=True)
    if resolved != path:
        raise ValueError("service roots must be canonical")
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("service roots must be private 0700 directories")
    parent = path.parent
    while parent != Path(parent.anchor):
        ancestor = parent.lstat()
        if stat.S_ISLNK(ancestor.st_mode) or ancestor.st_uid != 0 or ancestor.st_mode & 0o022:
            raise ValueError("service root ancestors must be root protected")
        parent = parent.parent
    return resolved


def _validate_operation_enrollment(profile: ManagedProfileCustody) -> None:
    targets = profile.operation_targets
    recipes = profile.operation_recipes
    schemas = profile.parameter_schemas
    roots = (profile.enrollment_id, profile.home_id, profile.work_id, profile.data_id,
             profile.home_root, profile.work_root)
    if not any(value is not None for value in roots + (targets, recipes, schemas)):
        return  # Legacy root fixture; production enrollment uses selection-only recipes.
    if (not isinstance(profile.enrollment_id, str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", profile.enrollment_id)
            or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)
                   for value in (profile.home_id, profile.work_id, profile.data_id))
            or len({profile.home_id, profile.work_id, profile.data_id}) != 3
            or profile.home_root is None or profile.work_root is None
            or not isinstance(targets, Mapping) or not isinstance(recipes, Mapping)
            or not isinstance(schemas, Mapping) or not recipes):
        raise ValueError("opaque operation enrollment or owned roots are incomplete")
    _validate_service_root(profile.home_root, uid=profile.owner_uid, gid=profile.owner_gid)
    _validate_service_root(profile.work_root, uid=profile.owner_uid, gid=profile.owner_gid)
    _validate_service_root(profile.data_root, uid=profile.owner_uid, gid=profile.owner_gid)
    if len(recipes) > 128 or len(schemas) > 128:
        raise ValueError("operation enrollment exceeds its fixed count")
    for operation, target in targets.items():
        if (not isinstance(operation, str) or not re.fullmatch(r"[a-z][a-z0-9_.-]{1,63}", operation)
                or not isinstance(target, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,256}", target)):
            raise ValueError("protected operation target is malformed")
    if "process.start" not in targets:
        raise ValueError("selection-only launch target is not enrolled")
    for recipe_id, raw in recipes.items():
        if (not isinstance(recipe_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", recipe_id)
                or not isinstance(raw, Mapping) or set(raw) != _OPERATION_RECIPE_FIELDS):
            raise ValueError("protected operation recipe fields are invalid")
        if (not isinstance(raw["executable_artifact_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", raw["executable_artifact_id"])
                or not isinstance(raw["executable_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", raw["executable_sha256"])):
            raise ValueError("operation executable binding is malformed")
        if raw["cwd_root_id"] not in {profile.home_id, profile.work_id, profile.data_id}:
            raise ValueError("operation working root is outside enrollment")
        subpath = raw["cwd_subpath"]
        if (not isinstance(subpath, str) or len(subpath) > 512 or "\\" in subpath
                or "\x00" in subpath or Path(subpath).is_absolute()
                or subpath not in {"", "."} and any(part in {"", ".", ".."} for part in Path(subpath).parts)):
            raise ValueError("operation working subpath is invalid")
        if (not isinstance(raw["argv_recipe"], (tuple, list)) or not raw["argv_recipe"]
                or len(raw["argv_recipe"]) > 128):
            raise ValueError("operation argv recipe is invalid")
        for token in raw["argv_recipe"]:
            if (not isinstance(token, Mapping) or len(token) != 1
                    or set(token) not in ({"literal"}, {"parameter"})):
                raise ValueError("argv recipe tokens must be one literal or one parameter")
            key = "literal" if "literal" in token else "parameter"
            if not isinstance(token[key], str) or not token[key] or len(token[key]) > 4096 or "\x00" in token[key]:
                raise ValueError("argv recipe token is malformed")
        if not isinstance(raw["environment"], Mapping) or not isinstance(raw["child_artifact_refs"], Mapping):
            raise ValueError("operation environment or child artifact mapping is malformed")
        if (len(raw["child_artifact_refs"]) > 32 or any(
                not isinstance(artifact_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact_id)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                for artifact_id, digest in raw["child_artifact_refs"].items())):
            raise ValueError("operation child artifact references are invalid")
        if (type(raw["max_lifetime_seconds"]) is not int
                or not 1 <= raw["max_lifetime_seconds"] <= min(profile.max_lifetime_seconds, 600)
                or type(raw["max_output_bytes"]) is not int
                or not 1 <= raw["max_output_bytes"] <= 4 * 1024 * 1024
                or raw["stdin_mode"] not in {"closed", "bounded-typed-bytes"}
                or not isinstance(raw["parameter_schema_id"], str)
                or raw["parameter_schema_id"] not in schemas):
            raise ValueError("operation recipe limits or parameter schema are invalid")
    for schema_id, schema in schemas.items():
        if (not isinstance(schema_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", schema_id)
                or not isinstance(schema, Mapping) or set(schema) != {"id", "fields"}
                or schema.get("id") != schema_id or not isinstance(schema.get("fields"), (tuple, list))):
            raise ValueError("protected parameter schema is malformed")
        names = set()
        for field in schema["fields"]:
            if not isinstance(field, Mapping) or set(field) != _PARAMETER_FIELD_FIELDS:
                raise ValueError("parameter field definition is malformed")
            name = field["name"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name)
                    or name in names or field["type"] not in {"string", "integer", "boolean"}
                    or type(field["required"]) is not bool):
                raise ValueError("parameter field name or type is invalid")
            names.add(name)
            enum = field["enum"]
            if enum is not None and (not isinstance(enum, (tuple, list)) or len(enum) > 256
                                     or any(not isinstance(item, (str, int, bool)) for item in enum)):
                raise ValueError("parameter enum is invalid")
            if field["type"] == "string":
                if (type(field["max_length"]) is not int or not 1 <= field["max_length"] <= 4096
                        or not isinstance(enum, (tuple, list)) or not enum
                        or field["minimum"] is not None or field["maximum"] is not None):
                    raise ValueError("string parameter bounds are invalid")
            elif (field["max_length"] is not None or type(field["minimum"]) is not int
                  or type(field["maximum"]) is not int or field["minimum"] > field["maximum"]):
                raise ValueError("numeric parameter bounds are invalid")


def _argv_matches_recipe(profile: ManagedProfileCustody, argv: list[str],
                         children: Mapping[str, str]) -> bool:
    """Only root-enrolled argv templates may execute; child code is catalog-bound."""
    recipe = profile.argv_recipe
    if not recipe or len(recipe) != len(argv) or recipe[0] != str(profile.executable):
        return False
    code_interpreter = _code_interpreter(profile.executable.name)
    if code_interpreter:
        # A profile may run only an immutable, catalog-enrolled script. The script
        # must be the first operand; -c/-e, interpreter flags before it, and
        # unpinned script paths are never accepted. Following arguments are still
        # exact root-recipe tokens (for example an enrolled installer stage).
        return (len(argv) >= 2 and bool(children) and argv[1] in children
                and recipe[1] == "{child_artifact}"
                and all(expected == "{child_artifact}" and actual in children or expected == actual
                        for expected, actual in zip(recipe[1:], argv[1:])))
    if any(arg.startswith("artifact:") for arg in argv[1:]):
        return False
    # Application-specific options may be present only when the protected root
    # enrollment pins them byte-for-byte in the recipe. Caller additions and
    # profile/config overrides therefore fail the exact comparison below.
    return all(expected == "{child_artifact}" and actual in children or expected == actual
               for expected, actual in zip(recipe, argv))


def _root_path(path: Path, *, directory: bool) -> Path:
    if not path.is_absolute():
        raise ValueError("protected executable paths must be absolute")
    cursor = Path(path.anchor)
    for index, part in enumerate(path.parts[1:], start=1):
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("protected executable path traverses a symlink")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("protected executable path has an untrusted writable ancestor")
    resolved = path.resolve(strict=True)
    info = resolved.stat(follow_symlinks=False)
    if (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise ValueError("protected executable path has the wrong type")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("protected executable path is writable by an untrusted identity")
    return resolved


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _pid_identity(pid: int) -> tuple[int, str, int, int]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    ticks = int(raw[raw.rfind(")") + 2:].split()[19])
    groups = [line.split(":", 2)[2] for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
              if line.startswith("0::")]
    if len(groups) != 1:
        raise AuthorityDenied("process.identity", "worker cgroup is unavailable")
    exe = Path(f"/proc/{pid}/exe")
    st = exe.stat()
    return ticks, groups[0], st.st_dev, st.st_ino


def _response(status: int, body: Mapping[str, Any]) -> Mapping[str, Any]:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > 262144:
        raise AuthorityDenied("process.response", "process receipt exceeds its bound")
    return {"status": status, "body": encoded, "headers": {"content-type": "application/json"},
            "receipt_id": uuid.uuid4().hex}


def _artifact_mount_slot(owner_uid: int, process_id: str) -> Path:
    """Create a root-only-to-modify, per-process mount target below fixed /run."""
    if type(owner_uid) is not int or owner_uid <= 0 or not re.fullmatch(r"[0-9a-f]{32}", process_id):
        raise AuthorityDenied("process.artifact", "artifact mount identity is invalid")
    base = Path("/run/hermes-installer")
    info = base.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise AuthorityDenied("process.artifact", "fixed runtime directory custody is invalid")
    parent = base / "process-artifacts"
    try:
        parent.mkdir(mode=0o711)
    except FileExistsError:
        pass
    else:
        os.chown(parent, 0, 0)
        os.chmod(parent, 0o711)
    info = parent.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "artifact runtime directory custody is invalid")
    user_dir = parent / str(owner_uid)
    try:
        user_dir.mkdir(mode=0o711)
    except FileExistsError:
        pass
    else:
        os.chown(user_dir, 0, 0)
        os.chmod(user_dir, 0o711)
    info = user_dir.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "profile artifact runtime directory custody is invalid")
    slot = user_dir / process_id
    slot.mkdir(mode=0o711)
    os.chown(slot, 0, 0)
    os.chmod(slot, 0o711)
    info = slot.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "per-process artifact mount slot is not protected")
    return slot


def _remove_artifact_mount(slot: Path) -> None:
    """Remove only the exact root-created placeholder; never recurse through a path."""
    try:
        info = slot.lstat()
    except FileNotFoundError:
        return
    parent_info = slot.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711
            or slot.parent.parent != Path("/run/hermes-installer/process-artifacts")
            or not slot.parent.name.isdecimal() or parent_info.st_uid != 0
            or not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o711
            or not re.fullmatch(r"[0-9a-f]{32}", slot.name)):
        raise AuthorityDenied("process.artifact", "artifact mount slot changed custody")
    for child in slot.iterdir():
        child_info = child.lstat()
        if (child.name != "child-1" or not stat.S_ISREG(child_info.st_mode)
                or child_info.st_uid != 0 or stat.S_IMODE(child_info.st_mode) != 0o444):
            raise AuthorityDenied("process.artifact", "unexpected artifact mount slot content")
        child.unlink()
    slot.rmdir()


def native_package_mount_target(*, package_id: str, profile_id: str, generation: str,
                               compiled_closure_sha256: str) -> Path:
    """Derive the only worker-visible native package target from protected claims."""
    if (not all(isinstance(value, str) and value and "\x00" not in value
                for value in (package_id, profile_id, generation))
            or not re.fullmatch(r"[0-9a-f]{64}", compiled_closure_sha256)):
        raise AuthorityDenied("native.mount_binding", "native package mount claims are malformed")
    identity = "\x00".join((package_id, profile_id, generation, compiled_closure_sha256)).encode("utf-8")
    return Path("/run/hermes-installer/native") / hashlib.sha256(identity).hexdigest()


def _resolved_artifact(value: Any, *, artifact_id: str, digest: str,
                       directory: bool = False) -> tuple[Path, Any]:
    path = Path(getattr(value, "path", value))
    if path != path.resolve(strict=True):
        raise AuthorityDenied("native.artifact", "native package artifact path is not canonical")
    info = path.lstat()
    if (info.st_uid != 0 or info.st_mode & 0o022
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))):
        raise AuthorityDenied("native.artifact", "native package artifact custody is invalid")
    if hasattr(value, "artifact_id") and value.artifact_id != artifact_id:
        raise AuthorityDenied("native.artifact", "native artifact ID differs from enrollment")
    if hasattr(value, "sha256") and value.sha256 != digest:
        raise AuthorityDenied("native.artifact", "native artifact digest differs from enrollment")
    if not directory:
        if info.st_nlink != 1 or info.st_size > 256 * 1024 * 1024:
            raise AuthorityDenied("native.artifact", "native artifact exceeds custody or size bounds")
        actual = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(1024 * 1024):
                actual.update(chunk)
        if actual.hexdigest() != digest:
            raise AuthorityDenied("native.artifact", "native artifact bytes changed after catalog resolution")
    return path, value


def _native_relative(value: Any) -> str:
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise AuthorityDenied("native.manifest", "native package relative path is invalid")
    return value


def _native_manifest_bytes(path: Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222 or info.st_nlink != 1 or info.st_size > 4 * 1024 * 1024:
        raise AuthorityDenied("native.manifest", "native entrypoint manifest custody is invalid")
    return path.read_bytes()


def _native_canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class ManagedProcessEffectHandler:
    """Root-only process.start/status/read/write/stop fixed-verb adapter."""

    def __init__(self, profiles: Mapping[str, ManagedProfileCustody], *,
                 systemd_run: Path = Path("/usr/bin/systemd-run"),
                 systemctl: Path = Path("/usr/bin/systemctl"),
                 artifact_resolver: Callable[[str, str], Any] | None = None,
                 native_package_resolver: Callable[[str, str], ManagedNativePackageMount | None] | None = None,
                 native_loader_observation_store: Any | None = None,
                 task_input_coordinator: Any | None = None,
                 task_admission_current: Callable[[RootAdmittedTask, bytes], bool] | None = None,
                 native_health_start_authority: Any | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if not profiles or any(key != item.profile_id for key, item in profiles.items()):
            raise ValueError("root process custody requires an explicit profile registry")
        self.profiles = dict(profiles)
        self.systemd_run = _root_path(systemd_run, directory=False)
        self.systemctl = _root_path(systemctl, directory=False)
        self.monotonic = monotonic
        self.artifact_resolver = artifact_resolver
        self.native_package_resolver = native_package_resolver
        self.native_loader_observation_store = native_loader_observation_store
        self.task_input_coordinator = None
        self._systemd_openfile_supported: bool | None = None
        self.task_admission_current = task_admission_current
        self._handles: dict[str, _Handle] = {}
        self._task_handles: dict[str, _ManagedTaskState] = {}
        self._finished: dict[str, tuple[str, float, ProcessCleanupProof]] = {}
        self._starting: set[str] = set()
        self._task_terminal_receipts: dict[str, tuple[str, RootTaskTerminalReceipt, float]] = {}
        self._application_handles: dict[str, _ManagedApplicationState] = {}
        self._application_terminal_receipts: dict[str, tuple[str, RootApplicationTerminalReceipt, float]] = {}
        self._application_outputs: dict[str, tuple[bytes, bytes, float]] = {}
        self._task_stdin_write_receipts: dict[str, tuple[ManagedTaskHandle, Any, float, str]] = {}
        self._root_selected_process_receipts: dict[
            str, tuple[RootSelectedServiceProcessReceipt, _Handle]
        ] = {}
        self._root_selected_status_receipts: dict[
            str, tuple[RootSelectedServiceStatusReceipt, RootSelectedServiceProcessReceipt, float]
        ] = {}
        self._health_controls: dict[str, tuple[RootSelectedHealthControl, _Handle, Any, object]] = {}
        self._health_observation_handles: dict[str, str] = {}
        self.native_health_start_authority: Any | None = None
        self._protected_enrollment_catalog: Any | None = None
        self._private_loopback_endpoint_leases: dict[str, tuple[Any, Any, Any]] = {}
        self._lock = threading.RLock()
        self._member_key = os.urandom(32)
        # Root-only test harness may capture bounded manager diagnostics. This
        # is never serialized to a worker or populated from caller text.
        self._diagnostic_sink: Callable[[bytes], None] | None = None
        for profile in self.profiles.values():
            self._validate_profile(profile)
        if task_input_coordinator is not None:
            self.set_task_input_coordinator(task_input_coordinator)
        if native_health_start_authority is not None:
            self.bind_native_health_start_authority(native_health_start_authority)

    def bind_native_health_start_authority(self, authority: Any) -> None:
        """Bind the one concrete root health admission issuer to this manager."""
        from hermes_installer.authority.native_health_observer import RootNativeHealthStartAuthority
        if type(authority) is not RootNativeHealthStartAuthority:
            raise AuthorityDenied("native.health.authority", "concrete root health start authority is required")
        with self._lock:
            if self.native_health_start_authority is not None and self.native_health_start_authority is not authority:
                raise AuthorityDenied("native.health.authority", "root health authority cannot be replaced")
            if authority.managed_process_custody is not self:
                raise AuthorityDenied("native.health.authority", "root health authority is bound to another manager")
            self.native_health_start_authority = authority

    def start_selected_health_operation(self, verified_effect: Any,
                                        admission_handle: str) -> RootSelectedHealthControl:
        """Launch the one committed native-health recipe under sealed root authority.

        This path accepts no worker HostContext, EffectAuthorization, peer PID,
        argv, or filesystem path.  The sealed health authority supplies the
        current committed receipt, selected profile/recipe, fixture, source
        closure and controller lease; this manager independently revalidates
        those objects before launching the immutable profile recipe.
        """
        from hermes_installer.authority.types import VerifiedRootSelectedServiceEffect
        authority = self.native_health_start_authority
        if (authority is None or type(verified_effect) is not VerifiedRootSelectedServiceEffect
                or not isinstance(admission_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", admission_handle)):
            raise AuthorityDenied("native.health.authority", "root health start authority is unavailable")
        from hermes_installer.authority.native_health_observer import (
            RootNativeHealthStartAdmission,
        )
        admission = authority.resolve_current_health_admission(admission_handle)
        if (type(admission) is not RootNativeHealthStartAdmission
                or admission.admission_handle != admission_handle
                or authority.verify_consumed_start_effect(verified_effect, admission) is not True
                or not authority.is_current(admission)):
            raise AuthorityDenied("native.health.admission", "consumed health start proof is stale")
        profile = admission._service_profile
        operation = admission._process_operation
        controller = admission._controller_lease
        if (type(profile) is not ManagedProfileCustody
                or self.profiles.get(profile.profile_id) is not profile
                or profile.profile_id != admission.profile_id
                or profile.enrollment_id != admission.enrollment_id
                or profile.generation != admission.process_generation
                or profile.owner_uid != verified_effect.selected_subject_uid
                or profile.owner_gid != verified_effect.selected_subject_gid
                or profile.service_generation_digest != admission.service_generation_digest
                or operation.operation_id != admission.operation_id
                or operation.target != verified_effect.target
                or verified_effect.profile_id != profile.profile_id
                or verified_effect.generation != profile.generation
                or verified_effect.enrollment_id != profile.enrollment_id
                or verified_effect.service_generation_digest != admission.service_generation_digest
                or verified_effect.role != "health" or verified_effect.action != "start"
                or verified_effect.admission_kind != "health"
                or verified_effect.operation != "process.start"
                or verified_effect.capability != "hermes-profile-invoke"
                or verified_effect.selected_namespace_identity != getattr(
                    admission, "_namespace_identity", verified_effect.selected_namespace_identity)
                or verified_effect.request_sha256 != hashlib.sha256(
                    json.dumps({"schema": 1, "enrollment_id": profile.enrollment_id,
                                "generation": profile.generation,
                                "operation_id": admission.operation_id, "parameters": {}},
                               sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True).encode("ascii")).hexdigest()
                or verified_effect.recipe_sha256 != admission.recipe_sha256
                or verified_effect.source_closure_sha256 != admission._source_binding.source_closure_sha256
                or verified_effect.controller_proof_handle != admission.controller_binding_handle
                or getattr(controller, "proof_sha256", None) != verified_effect.controller_proof_sha256
                or not controller.is_current()):
            raise AuthorityDenied("native.health.binding", "health start proof differs from the selected profile")
        operation_recipe = (profile.operation_recipes or {}).get(admission.operation_id)
        if (not isinstance(operation_recipe, Mapping)
                or operation_recipe.get("target") not in (None, verified_effect.target)
                or hashlib.sha256(json.dumps(dict(operation_recipe), sort_keys=True,
                    separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
                    != admission.recipe_sha256
                or type(operation_recipe.get("max_lifetime_seconds")) is not int
                or not 0 < operation_recipe["max_lifetime_seconds"] <= profile.max_lifetime_seconds):
            raise AuthorityDenied("native.health.recipe", "fixed health recipe has no bounded lifetime")
        now = self.monotonic()
        process_deadline = now + min(float(operation_recipe["max_lifetime_seconds"]),
                                     float(profile.max_lifetime_seconds))
        with self._lock:
            if (profile.profile_id in self._starting
                    or any(item.profile.profile_id == profile.profile_id for item in self._handles.values())):
                raise AuthorityDenied("process.generation", "health profile already has a managed process")
            self._starting.add(profile.profile_id)
        parent_pidfd = None
        process_id = None
        try:
            parent_pidfd = os.pidfd_open(os.getpid(), 0)
            if _pidfd_exited(parent_pidfd):
                raise AuthorityDenied("native.health.parent", "custody process lifetime anchor is not live")
            self._verify_root_controller_identity(controller, verified_effect)
            payload = json.dumps({"schema": 1, "enrollment_id": profile.enrollment_id,
                                  "generation": profile.generation,
                                  "operation_id": admission.operation_id, "parameters": {}},
                                 sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True).encode("ascii")

            def launch_current() -> bool:
                return (authority.is_current(admission)
                        and authority.verify_consumed_start_effect(verified_effect, admission) is True
                        and controller.is_current() and verified_effect.is_current()
                        and self.profiles.get(profile.profile_id) is profile)

            # Internal root recipe execution shares only the lower-level
            # selected-recipe resolver.  It deliberately has no worker grant
            # or peer identity and is admitted by this dedicated health proof.
            response = self.start_selected_operation(
                profile, None, None, payload, timeout=min(30.0, max(.1, admission.expires_monotonic - now)),
                peer_pid=None, peer_pidfd=None,
                cancelled=lambda: (not authority.is_current(admission)
                                   or not controller.is_current()),
                _start_guard=launch_current, _root_selected_effect=verified_effect,
                _root_selected_health_admission=admission,
                _root_selected_lifecycle_deadline=process_deadline,
                _daemon_liveness_pidfd=parent_pidfd,
            )
            body = response.get("body") if isinstance(response, Mapping) else None
            decoded = json.loads(body.decode("ascii")) if isinstance(body, bytes) else None
            process_id = decoded.get("process_id") if isinstance(decoded, dict) else None
            if not isinstance(process_id, str):
                raise AuthorityDenied("native.health.launch", "manager did not retain a health process")
            with self._lock:
                handle = self._handles.get(process_id)
            if (handle is None or handle.stopped or handle.profile is not profile
                    or handle.profile.generation != admission.process_generation
                    or not authority.is_current(admission)
                    or not controller.is_current()):
                raise AuthorityDenied("native.health.identity", "started health process is no longer current")
            lease = self.resolve_owned_process_handle(handle)
            if lease is None:
                raise AuthorityDenied("native.health.identity", "started health PIDFD identity is unavailable")
            try:
                # Verify the selected executable, user, cgroup and namespaces
                # against the manager's live retained child PIDFD before minting
                # a control object.
                if (lease.process_id != process_id or lease.profile_id != profile.profile_id
                        or lease.generation != profile.generation or lease.uid != profile.owner_uid
                        or lease.gid != profile.owner_gid or _pidfd_exited(lease.pidfd)):
                    raise AuthorityDenied("native.health.identity", "health child identity changed")
                issued = self.monotonic()
                control = RootSelectedHealthControl(
                    1, secrets.token_urlsafe(32), secrets.token_urlsafe(32), process_id,
                    admission.operation_id, admission.enrollment_id, admission.profile_id,
                    admission.process_generation, admission.service_generation_digest,
                    admission.bootstrap_transaction_handle, admission.committed_enrollment_receipt_id,
                    admission.health_fixture_artifact_id, admission.health_fixture_sha256,
                    issued, handle.expires, self, object(),
                )
                with self._lock:
                    self._health_controls[control.control_handle] = (control, handle, admission,
                                                                      control._seal)
                # The observer must bind actual live PIDFD and loaded closure
                # before the health fixture is delivered by its authority.
                observer = authority.health_observer
                observation_handle = observer.begin_selected_health(control.control_handle)
                if (not isinstance(observation_handle, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", observation_handle)):
                    raise AuthorityDenied("native.health.observer", "health observer returned no retained run handle")
                with self._lock:
                    self._health_observation_handles[control.control_handle] = observation_handle
                return control
            finally:
                lease.close()
        except BaseException:
            if process_id is not None:
                failed_observations: list[str] = []
                with self._lock:
                    handle = self._handles.get(process_id)
                    for key, value in tuple(self._health_controls.items()):
                        if value[1] is handle:
                            self._health_controls.pop(key, None)
                            observation = self._health_observation_handles.pop(key, None)
                            if observation is not None:
                                failed_observations.append(observation)
                for observation in failed_observations:
                    try:
                        self.native_health_start_authority.health_observer.cancel_selected_health(observation)
                    except Exception:
                        pass
                if handle is not None and not handle.stopped:
                    self._stop(handle, timeout=5.0)
            raise
        finally:
            if parent_pidfd is not None:
                os.close(parent_pidfd)
            with self._lock:
                self._starting.discard(profile.profile_id)

    def _health_control_current(self, control: RootSelectedHealthControl,
                                seal: object) -> bool:
        with self._lock:
            retained = self._health_controls.get(control.control_handle)
        if (retained is None or retained[0] is not control or retained[3] is not seal
                or retained[1].stopped or control._seal is not seal
                or self.monotonic() >= control.expires_monotonic):
            return False
        handle = retained[1]
        if (self._handles.get(handle.process_id) is not handle
                or self.profiles.get(handle.profile.profile_id) is not handle.profile
                or handle.profile.generation != control.process_generation):
            return False
        lease = self.resolve_owned_process_handle(handle)
        if lease is None:
            return False
        try:
            return bool(lease.process_id == control.process_id
                        and lease.profile_id == control.profile_id
                        and lease.generation == control.process_generation
                        and lease.uid == handle.profile.owner_uid
                        and lease.gid == handle.profile.owner_gid
                        and not _pidfd_exited(lease.pidfd))
        finally:
            lease.close()

    def resolve_selected_health_control(self, control_handle: str) -> RootSelectedHealthControl:
        with self._lock:
            retained = self._health_controls.get(control_handle)
        if retained is None or not retained[0].is_current():
            raise AuthorityDenied("native.health.control", "selected health control is stale")
        return retained[0]

    def resolve_selected_health_process(self, control_handle: str) -> ManagedProcessIdentityLease:
        """Return an owned duplicate PIDFD for the exact health-control child."""
        control = self.resolve_selected_health_control(control_handle)
        with self._lock:
            retained = self._health_controls.get(control_handle)
        if retained is None or retained[0] is not control:
            raise AuthorityDenied("native.health.control", "selected health process handle is stale")
        lease = self.resolve_owned_process_handle(retained[1])
        if (lease is None or lease.process_id != control.process_id
                or lease.profile_id != control.profile_id
                or lease.generation != control.process_generation):
            if lease is not None:
                lease.close()
            raise AuthorityDenied("native.health.identity", "selected health PIDFD identity is unavailable")
        return lease

    def resolve_selected_health_observation_handle(self, control_handle: str) -> str:
        """Resolve the actual observer run handle for the exact live health control."""
        control = self.resolve_selected_health_control(control_handle)
        with self._lock:
            retained = self._health_controls.get(control_handle)
            observation = self._health_observation_handles.get(control_handle)
        if (retained is None or retained[0] is not control
                or not isinstance(observation, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", observation)
                or not control.is_current()):
            raise AuthorityDenied("native.health.observer", "selected health observer run is stale")
        return observation

    def set_task_input_coordinator(self, coordinator: Any) -> None:
        """Install the concrete root-native pre-stdin coordinator once."""
        from hermes_installer.authority.native_observer_wiring import RootTaskInputCoordinator
        if type(coordinator) is not RootTaskInputCoordinator:
            raise ValueError("task input coordinator must be the concrete root runtime coordinator")
        with self._lock:
            if self.task_input_coordinator is not None:
                raise ValueError("task input coordinator is already installed")
            if getattr(coordinator, "process_custody", None) is not self:
                raise ValueError("task input coordinator is bound to another process manager")
        self.task_input_coordinator = coordinator

    def bind_private_memory_enrollment_catalog(self, catalog: Any) -> None:
        """Bind the exact protected catalog used to resolve endpoint selection rows."""
        from hermes_installer.protected_enrollment import ProtectedEnrollmentCatalog
        if type(catalog) is not ProtectedEnrollmentCatalog:
            raise AuthorityDenied("private_network.catalog", "root protected enrollment catalog is required")
        with self._lock:
            if self._protected_enrollment_catalog is not None and self._protected_enrollment_catalog is not catalog:
                raise AuthorityDenied("private_network.catalog", "process manager catalog cannot be replaced")
            self._protected_enrollment_catalog = catalog

    def retain_private_loopback_network_lease(self, endpoint_binding: Any, network: Any, lease: Any) -> None:
        """Retain a live namespace lease against its exact protected endpoint/network rows."""
        from hermes_installer.authority.private_loopback_network import (
            RootPrivateLoopbackNetworkLease, verify_root_network_lease,
        )
        from hermes_installer.protected_enrollment import (
            PrivateLoopbackNetworkEnrollment, RootSelectedPrivateMemoryEndpointBinding,
        )
        if (type(endpoint_binding) is not RootSelectedPrivateMemoryEndpointBinding
                or type(network) is not PrivateLoopbackNetworkEnrollment
                or type(lease) is not RootPrivateLoopbackNetworkLease):
            raise AuthorityDenied("private_network.binding", "typed protected endpoint/network and live lease are required")
        with self._lock:
            catalog = self._protected_enrollment_catalog
        if catalog is None:
            raise AuthorityDenied("private_network.catalog", "protected endpoint catalog is not bound")
        try:
            current = catalog.resolve_private_memory_endpoint_binding(endpoint_binding.binding_id)
            verify_root_network_lease(lease)
            profile = self.profiles.get(endpoint_binding.process_profile_id)
            identities = [row for row in lease.network.member_identities
                          if row.profile_id == endpoint_binding.process_profile_id
                          and row.generation == endpoint_binding.process_profile_generation]
            service = catalog.resolve(endpoint_binding.service_enrollment_id, endpoint_binding.service_generation)
            if (current is not endpoint_binding or network.id != endpoint_binding.network_binding_handle
                    or network.service_generation_digest != endpoint_binding.service_generation_digest
                    or endpoint_binding.service_enrollment_id not in network.member_enrollment_ids
                    or service.namespace_identity != network.namespace_identity
                    or lease.network.network_id != network.id
                    or lease.network.generation != network.generation
                    or lease.network.members != network.member_enrollment_ids
                    or lease.network.service_generation_digest
                    != endpoint_binding.service_generation_digest
                    or lease.network.namespace_identity != endpoint_binding.namespace_id
                    or profile is None or profile.generation != endpoint_binding.process_profile_generation
                    or profile.service_generation_digest != endpoint_binding.service_generation_digest
                    or len(identities) != 1 or identities[0].uid != profile.owner_uid):
                raise ValueError("endpoint and network membership differ")
        except Exception:
            raise AuthorityDenied("private_network.binding", "selected endpoint does not join a current private network lease") from None
        with self._lock:
            previous = self._private_loopback_endpoint_leases.get(endpoint_binding.network_binding_handle)
            if previous is not None:
                if previous[0] is endpoint_binding and previous[1] == network and previous[2] is lease:
                    return
                raise AuthorityDenied("private_network.binding", "network binding handle is already retained")
            self._private_loopback_endpoint_leases[endpoint_binding.network_binding_handle] = (
                endpoint_binding, network, lease,
            )

    def resolve_private_loopback_network_lease(self, endpoint_binding: Any) -> Any:
        """Resolve the exact retained lease by a root-resolved endpoint DTO, never a raw handle."""
        from hermes_installer.authority.private_loopback_network import (
            RootPrivateLoopbackNetworkLease, verify_root_network_lease,
        )
        from hermes_installer.protected_enrollment import RootSelectedPrivateMemoryEndpointBinding
        if type(endpoint_binding) is not RootSelectedPrivateMemoryEndpointBinding:
            raise AuthorityDenied("private_network.binding", "root-resolved endpoint binding is required")
        with self._lock:
            retained = self._private_loopback_endpoint_leases.get(endpoint_binding.network_binding_handle)
            catalog = self._protected_enrollment_catalog
        if retained is None or catalog is None or retained[0] is not endpoint_binding:
            raise AuthorityDenied("private_network.binding", "no exact retained lease exists for this protected endpoint")
        try:
            if catalog.resolve_private_memory_endpoint_binding(endpoint_binding.binding_id) is not endpoint_binding:
                raise ValueError("endpoint selection changed")
            network, lease = retained[1], retained[2]
            from hermes_installer.protected_enrollment import PrivateLoopbackNetworkEnrollment
            if type(network) is not PrivateLoopbackNetworkEnrollment:
                raise ValueError("protected network selection type changed")
            service = catalog.resolve(endpoint_binding.service_enrollment_id, endpoint_binding.service_generation)
            if type(lease) is not RootPrivateLoopbackNetworkLease:
                raise ValueError("lease type changed")
            verify_root_network_lease(lease)
            profile = self.profiles.get(endpoint_binding.process_profile_id)
            identities = [row for row in lease.network.member_identities
                          if row.profile_id == endpoint_binding.process_profile_id
                          and row.generation == endpoint_binding.process_profile_generation]
            if (network.id != endpoint_binding.network_binding_handle
                    or endpoint_binding.service_enrollment_id not in network.member_enrollment_ids
                    or service.namespace_identity != network.namespace_identity
                    or lease.network.network_id != network.id
                    or lease.network.generation != network.generation
                    or lease.network.members != network.member_enrollment_ids
                    or profile is None or profile.generation != endpoint_binding.process_profile_generation
                    or profile.service_generation_digest != endpoint_binding.service_generation_digest
                    or lease.network.service_generation_digest != endpoint_binding.service_generation_digest
                    or lease.network.namespace_identity != endpoint_binding.namespace_id
                    or len(identities) != 1 or identities[0].uid != profile.owner_uid):
                raise ValueError("lease member or selected process changed")
            return lease
        except Exception:
            raise AuthorityDenied("private_network.lease", "retained endpoint network lease is stale or mismatched") from None

    def set_native_loader_observation_store(self, store: Any) -> None:
        """Install the root-owned loader observer after manager construction.

        The observer is constructed with this manager as its custody resolver;
        workers cannot call or replace this hook.
        """
        if (store is None or not callable(getattr(store, "register_launch", None))
                or not callable(getattr(store, "receive_loader_progress", None))
                or not callable(getattr(store, "revoke_process", None))):
            raise ValueError("native loader observer must implement the fixed root API")
        with self._lock:
            if self.native_loader_observation_store is not None:
                raise ValueError("native loader observer is already installed")
            self.native_loader_observation_store = store

    def register_native_loader_channel(self, process_id: str, channel: Any, *,
                                       expected_loader_role_artifact_id: str,
                                       expected_loader_role_sha256: str,
                                       deadline_monotonic: float) -> str:
        """Attach one channel to the currently owned process registry entry."""
        with self._lock:
            handle = self._handles.get(process_id)
            store = self.native_loader_observation_store
            if handle is None or handle.stopped or store is None:
                raise AuthorityDenied("native.loader", "selected process or observer is unavailable")
            if self.monotonic() >= handle.expires or _pidfd_exited(handle.child_pidfd):
                raise AuthorityDenied("native.loader", "selected process is no longer active")
            if not self.is_owned_active_process_handle(handle):
                raise AuthorityDenied("native.loader", "selected process is not current custody state")
            observation = store.register_launch(
                handle, channel, expected_loader_role_artifact_id,
                expected_loader_role_sha256, channel.launch_nonce,
                deadline_monotonic,
            )
            handle.native_loader_observation_handle = observation
            return observation

    def receive_native_loader_progress(self, process_id: str, *,
                                       cancelled: Callable[[], bool]) -> str:
        """Wait for the selected loader's root-authenticated three-frame ready event."""
        with self._lock:
            handle = self._handles.get(process_id)
            store = self.native_loader_observation_store
            observation = (handle.native_loader_observation_handle if handle is not None else None)
            if (handle is None or handle.stopped or store is None or observation is None
                    or not self.is_owned_active_process_handle(handle)):
                raise AuthorityDenied("native.loader", "selected loader observation is not active")
        ready_event_id = store.receive_loader_progress(observation, cancelled)
        with self._lock:
            current = self._handles.get(process_id)
            if current is not handle or current.stopped or self.monotonic() >= current.expires:
                store.revoke_process(process_id, handle.profile.generation)
                raise AuthorityDenied("native.loader", "process changed during loader observation")
            current.native_loader_ready_event_id = ready_event_id
        return ready_event_id

    def _require_systemd_openfile(self) -> None:
        if self._systemd_openfile_supported is None:
            try:
                result = subprocess.run([str(self.systemctl), "--version"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                    timeout=2.0, check=False)
                first = result.stdout.splitlines()[0].decode("ascii", "strict") if result.stdout else ""
                match = re.match(r"systemd\s+(\d+)(?:\s|$)", first)
                self._systemd_openfile_supported = bool(
                    result.returncode == 0 and match is not None and int(match.group(1)) >= 253)
            except (OSError, subprocess.TimeoutExpired, UnicodeError, ValueError):
                self._systemd_openfile_supported = False
        if not self._systemd_openfile_supported:
            raise AuthorityDenied("native.loader", "systemd v253 OpenFile support is required")

    def _prepare_native_package_mount(self, profile: ManagedProfileCustody,
                                      process_id: str) -> tuple[Path | None, NativePackageMountReceipt | None]:
        resolver = self.native_package_resolver
        if resolver is None:
            if profile.native_package is not None:
                raise AuthorityDenied("native.mount", "root native package resolver is unavailable")
            return None, None
        try:
            package = resolver(profile.profile_id, profile.generation)
        except Exception:
            raise AuthorityDenied("native.mount", "root native package enrollment could not be resolved") from None
        if package is None:
            if profile.native_package is not None:
                raise AuthorityDenied("native.mount", "selected native package is missing")
            return None, None
        if not isinstance(package, ManagedNativePackageMount):
            raise AuthorityDenied("native.mount", "root native package resolver returned an invalid object")
        binding = package.binding
        names = ("package_id", "profile_id", "generation", "compiled_closure_artifact_id",
                 "compiled_closure_sha256", "entrypoint_artifact_id", "entrypoint_sha256",
                 "resolver_artifact_id", "resolver_sha256", "service_mount_id", "adapter_records")
        if any(not hasattr(binding, name) for name in names):
            raise AuthorityDenied("native.mount", "protected native package binding is incomplete")
        if (binding.profile_id != profile.profile_id or binding.generation != profile.generation
                or package.profile_id != profile.profile_id or package.generation != profile.generation
                or (profile.native_package is not None and profile.native_package != binding)):
            raise AuthorityDenied("native.mount", "native package does not join the active profile generation")
        closure, closure_artifact = _resolved_artifact(
            package.closure_root, artifact_id=binding.compiled_closure_artifact_id,
            digest=getattr(package.closure_root, "sha256", binding.compiled_closure_sha256), directory=True)
        # ArtifactCatalog's archive/tree-manifest digest has a distinct schema
        # from the HI08 compiled_closure_sha256 (which hashes the native
        # closure_files rows below). Do not conflate those digest domains: the
        # complete freshly observed tree is compared byte-for-byte with the
        # selected HI08 manifest before any bind mount is created.
        entrypoint, _ = _resolved_artifact(package.entrypoint_path,
            artifact_id=binding.entrypoint_artifact_id, digest=binding.entrypoint_sha256)
        resolver_path, _ = _resolved_artifact(package.resolver_path,
            artifact_id=binding.resolver_artifact_id, digest=binding.resolver_sha256)
        manifest_bytes = _native_manifest_bytes(entrypoint)
        if hashlib.sha256(manifest_bytes).hexdigest() != binding.entrypoint_sha256:
            raise AuthorityDenied("native.manifest", "native manifest digest changed")
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise AuthorityDenied("native.manifest", "native package manifest is malformed") from None
        if not isinstance(manifest, dict) or _native_canonical(manifest) != manifest_bytes:
            raise AuthorityDenied("native.manifest", "native package manifest is not canonical JSON")
        required_top = {"schema", "package_id", "profile_id", "generation", "closure_files", "adapters", "dependencies"}
        if (not isinstance(manifest, dict) or set(manifest) != required_top or manifest.get("schema") != 1
                or manifest.get("package_id") != binding.package_id
                or manifest.get("profile_id") != binding.profile_id
                or manifest.get("generation") != binding.generation
                or not isinstance(manifest.get("closure_files"), list)
                or not isinstance(manifest.get("adapters"), list)
                or not isinstance(manifest.get("dependencies"), list)):
            raise AuthorityDenied("native.manifest", "native package manifest does not match protected enrollment")
        rows = manifest["closure_files"]
        if not rows or len(rows) > 16384:
            raise AuthorityDenied("native.closure", "native closure file manifest is empty or oversized")
        listed: dict[str, tuple[str, int, int]] = {}
        keys: set[str] = set()
        for row in rows:
            if (not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode"}
                    or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                    or type(row["size_bytes"]) is not int or row["size_bytes"] < 0
                    or type(row["mode"]) is not int or row["mode"] & ~0o777 or row["mode"] & 0o222):
                raise AuthorityDenied("native.closure", "native closure manifest entry is invalid")
            relative = _native_relative(row["relative_path"])
            if relative in listed or relative.casefold() in keys:
                raise AuthorityDenied("native.closure", "native closure contains duplicate or case-colliding files")
            keys.add(relative.casefold())
            listed[relative] = (row["sha256"], row["size_bytes"], row["mode"])
        if rows != sorted(rows, key=lambda row: row["relative_path"]):
            raise AuthorityDenied("native.closure", "native closure manifest is not canonically ordered")
        if hashlib.sha256(_native_canonical(rows)).hexdigest() != binding.compiled_closure_sha256:
            raise AuthorityDenied("native.closure", "compiled closure digest does not bind the canonical file manifest")
        observed: dict[str, tuple[str, int, int]] = {}
        for current, dirs, files in os.walk(closure, topdown=True, followlinks=False):
            base = Path(current)
            for name in dirs:
                info = (base / name).lstat()
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                    raise AuthorityDenied("native.closure", "native closure directory custody is invalid")
            for name in files:
                path = base / name
                info = path.lstat()
                relative = _native_relative(path.relative_to(closure).as_posix())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                        or info.st_nlink != 1 or relative in observed or info.st_size > 256 * 1024 * 1024):
                    raise AuthorityDenied("native.closure", "native closure contains a mutable or special file")
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                observed[relative] = (digest, info.st_size, stat.S_IMODE(info.st_mode))
        if observed != listed:
            raise AuthorityDenied("native.closure", "materialized native closure differs from its complete manifest")
        adapters = manifest["adapters"]
        binding_adapters = dict(binding.adapter_records)
        if (len(adapters) != len(binding_adapters) or set(package.adapter_paths) != set(binding_adapters)):
            raise AuthorityDenied("native.adapters", "native adapters differ from the selected protected package")
        for row in adapters:
            fields = {"adapter_id", "relative_module_path", "module_name", "entrypoint_symbol",
                      "artifact_sha256", "allowed_internal_modules", "allowed_dependency_artifact_ids", "action_ids"}
            if not isinstance(row, dict) or set(row) != fields:
                raise AuthorityDenied("native.adapters", "native adapter manifest row is invalid")
            adapter_id = row["adapter_id"]
            enrolled = binding_adapters.get(adapter_id)
            relative = _native_relative(row["relative_module_path"])
            path_row = listed.get(relative)
            adapter_path, adapter_artifact = _resolved_artifact(package.adapter_paths.get(adapter_id),
                artifact_id=getattr(enrolled, "adapter_artifact_id", ""),
                digest=getattr(enrolled, "adapter_sha256", "")) if enrolled is not None else (None, None)
            if (enrolled is None or path_row is None or row["artifact_sha256"] != enrolled.adapter_sha256
                    or path_row[0] != enrolled.adapter_sha256
                    or hashlib.sha256(adapter_path.read_bytes()).hexdigest() != row["artifact_sha256"]
                    or row["action_ids"] != [enrolled.action_id]
                    or not isinstance(row["module_name"], str)
                    or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", row["module_name"])
                    or not isinstance(row["entrypoint_symbol"], str)
                    or row["entrypoint_symbol"] not in {"register", "PluginContext.register"}
                    or not isinstance(row["allowed_internal_modules"], list)
                    or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", name)
                           for name in row["allowed_internal_modules"])
                    or not isinstance(row["allowed_dependency_artifact_ids"], list)
                    or any(item not in package.dependency_paths for item in row["allowed_dependency_artifact_ids"])
                    or not isinstance(row["action_ids"], list)):
                raise AuthorityDenied("native.adapters", "native adapter manifest differs from protected adapter enrollment")
        dependencies = manifest["dependencies"]
        if len(dependencies) > 256 or len(package.dependency_paths) != len(dependencies):
            raise AuthorityDenied("native.dependencies", "native dependency set is incomplete or oversized")
        dependency_ids: set[str] = set()
        for row in dependencies:
            if not isinstance(row, dict) or set(row) != {"artifact_id", "sha256", "module_names"}:
                raise AuthorityDenied("native.dependencies", "native dependency row is invalid")
            artifact_id = row["artifact_id"]
            if (not isinstance(artifact_id, str) or artifact_id in dependency_ids
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact_id)
                    or not isinstance(row["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                    or not isinstance(row["module_names"], list) or len(row["module_names"]) > 512):
                raise AuthorityDenied("native.dependencies", "native dependency binding is malformed")
            if any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", name)
                   for name in row["module_names"]):
                raise AuthorityDenied("native.dependencies", "native dependency module allowlist is malformed")
            dependency_ids.add(artifact_id)
            dependency = package.dependency_paths.get(artifact_id)
            dependency_path, dep_artifact = _resolved_artifact(dependency, artifact_id=artifact_id,
                digest=row["sha256"], directory=Path(getattr(dependency, "path", dependency)).is_dir())
            if dependency_path.is_dir():
                tree_files = getattr(dep_artifact, "tree_files", None)
                if not isinstance(tree_files, tuple) or not tree_files:
                    raise AuthorityDenied("native.dependencies", "dependency tree has no protected file manifest")
                expected_files = {}
                for tree_file in tree_files:
                    relative = _native_relative(tree_file.path)
                    if tree_file.kind != "file":
                        raise AuthorityDenied("native.dependencies", "dependency tree contains a non-file entry")
                    expected_files[relative] = (tree_file.sha256, tree_file.size_bytes,
                        0o555 if tree_file.executable else 0o444)
                self._verify_native_tree(dependency_path, expected_files)
        if dependency_ids != set(package.dependency_paths):
            raise AuthorityDenied("native.dependencies", "native dependency mapping has unlisted artifacts")
        target = native_package_mount_target(package_id=binding.package_id,
            profile_id=binding.profile_id, generation=binding.generation,
            compiled_closure_sha256=binding.compiled_closure_sha256)
        source = self._stage_native_package(process_id, target, manifest_bytes, closure,
            resolver_path, package.adapter_paths, package.dependency_paths, listed)
        source_info = source.stat(follow_symlinks=False)
        receipt = NativePackageMountReceipt(binding.package_id, binding.profile_id,
            binding.generation, binding.service_mount_id, binding.compiled_closure_sha256,
            binding.entrypoint_sha256, binding.resolver_sha256, str(target),
            source_info.st_dev, source_info.st_ino, hashlib.sha256(manifest_bytes).hexdigest())
        return source, receipt

    def _prepare_xauthority_mount(
            self, profile: ManagedProfileCustody, binding: Any, registry: Any,
    ) -> tuple[Path, XauthorityMountReceipt, Any]:
        """Stage a registry-held Xauthority FD at the one protected display path."""
        from hermes_installer.authority.native_display_startup import (
            XauthorityMountBinding, XauthoritySourceLease,
        )
        if (type(binding) is not XauthorityMountBinding
                or not callable(getattr(registry, "open_mount_source", None))
                or not callable(getattr(registry, "verify_mount_source", None))
                or not registry.verify_mount_binding(binding)
                or str(binding.target_path) != "/run/hermes-installer/display/Xauthority"):
            raise AuthorityDenied("process.xauthority", "Xauthority binding is not current in its root registry")
        lease = registry.open_mount_source(binding)
        try:
            if (type(lease) is not XauthoritySourceLease
                    or not registry.verify_mount_source(lease, binding)
                    or lease.display_profile_id != profile.profile_id
                    or lease.display_generation != profile.generation
                    or lease.owner_gid != profile.owner_gid
                    or lease.size_bytes <= 0 or lease.size_bytes > 65536
                    or lease.file_fd < 0):
                raise AuthorityDenied("process.xauthority", "Xauthority source lease is not bound to the selected display")
            fd = lease.file_fd
            info = os.fstat(fd)
            access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
            if (not stat.S_ISREG(info.st_mode) or access != os.O_RDONLY
                    or (info.st_dev, info.st_ino) != (lease.device, lease.inode)
                    or info.st_uid != lease.owner_uid or info.st_gid != lease.owner_gid
                    or stat.S_IMODE(info.st_mode) != lease.mode
                    or info.st_size != lease.size_bytes or info.st_nlink != 1):
                raise AuthorityDenied("process.xauthority", "held Xauthority source identity changed")
            content = bytearray()
            offset = 0
            while offset < info.st_size:
                chunk = os.pread(fd, min(8192, info.st_size - offset), offset)
                if not chunk:
                    raise AuthorityDenied("process.xauthority", "held Xauthority source was truncated")
                content.extend(chunk)
                offset += len(chunk)
            source_digest = hashlib.sha256(content).hexdigest()
            if source_digest != lease.content_sha256 or source_digest != binding.source_sha256:
                raise AuthorityDenied("process.xauthority", "held Xauthority source digest changed")
            if not registry.verify_mount_source(lease, binding):
                raise AuthorityDenied("process.xauthority", "Xauthority source lease expired during staging")
            base = Path("/run/hermes-installer/native-staging")
            self._ensure_root_runtime_directory(base, 0o711)
            stage = base / ("xauthority-" + uuid.uuid4().hex)
            stage.mkdir(mode=0o700)
            os.chown(stage, 0, 0)
            source = stage / "Xauthority"
            out_fd = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                view = memoryview(content)
                while view:
                    written = os.write(out_fd, view)
                    if written <= 0:
                        raise OSError("short Xauthority staging write")
                    view = view[written:]
                os.fchown(out_fd, 0, profile.owner_gid)
                os.fchmod(out_fd, 0o440)
                os.fsync(out_fd)
            finally:
                os.close(out_fd)
                for index in range(len(content)):
                    content[index] = 0
            self._make_native_tree_readonly(stage)
            self._protect_native_staging_mount(stage)
            staged = source.stat(follow_symlinks=False)
            receipt = XauthorityMountReceipt(
                "/run/hermes-installer/display/Xauthority", staged.st_dev, staged.st_ino,
                source_digest, info.st_size, profile.owner_gid,
            )
            return stage, receipt, lease
        except BaseException:
            # Staging is root-owned and contains credential material.  Even a
            # failed copy or mount preparation must remove it before returning.
            try:
                if "stage" in locals() and stage.exists():
                    self._remove_native_staging(stage)
            except Exception:
                pass
            try:
                lease.close()
            except Exception:
                pass
            raise

    def _stage_native_package(self, process_id: str, target: Path, manifest: bytes,
                              closure: Path, resolver_path: Path,
                              adapters: Mapping[str, Any], dependencies: Mapping[str, Any],
                              closure_manifest: Mapping[str, tuple[str, int, int]]) -> Path:
        base = Path("/run/hermes-installer/native-staging")
        self._ensure_root_runtime_directory(base, 0o711)
        stage = base / process_id
        stage.mkdir(mode=0o700)
        os.chown(stage, 0, 0)
        self._write_native_file(stage / "manifest.json", manifest, 0o444)
        self._copy_native_tree(closure, stage / "closure", closure_manifest)
        resolved = Path(getattr(resolver_path, "path", resolver_path))
        self._write_native_file(stage / "resolver" / "resolver", resolved.read_bytes(), 0o444)
        for artifact_id, value in sorted(dependencies.items()):
            source = Path(getattr(value, "path", value))
            destination = stage / "dependencies" / artifact_id
            if source.is_dir():
                self._copy_native_tree(source, destination, None)
            else:
                self._write_native_file(destination / source.name, source.read_bytes(), 0o444)
        self._make_native_tree_readonly(stage)
        self._protect_native_staging_mount(stage)
        parent = target.parent
        self._ensure_root_runtime_directory(parent, 0o711)
        try:
            target.mkdir(mode=0o755)
            os.chown(target, 0, 0)
            os.chmod(target, 0o755)
        except FileExistsError:
            info = target.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
                raise AuthorityDenied("native.mount", "derived native mountpoint has unsafe custody")
        return stage

    @staticmethod
    def _mount_call(source: Path, target: Path, flags: int) -> None:
        """Apply a Linux mount operation to one root-owned staging path."""
        libc = ctypes.CDLL(None, use_errno=True)
        mount = libc.mount
        mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_ulong, ctypes.c_char_p)
        mount.restype = ctypes.c_int
        result = mount(os.fsencode(source), os.fsencode(target), None, flags, None)
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(target))

    @classmethod
    def _protect_native_staging_mount(cls, stage: Path) -> None:
        """Give the immutable staging tree its own private restricted mount.

        systemd's BindReadOnlyPaths has no syntax for per-bind nosuid/nodev
        mount options. Prepare those flags on a self-bind before handing the
        source to systemd; the service then gets a second read-only bind.
        """
        if not sys.platform.startswith("linux"):
            raise AuthorityDenied("native.mount", "native package mounts require Linux mount namespaces")
        info = stage.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222:
            raise AuthorityDenied("native.mount", "native staging directory is not sealed")
        ms_bind, ms_rec = 4096, 16384
        ms_private = 1 << 18
        ms_remount, ms_readonly, ms_nosuid, ms_nodev, ms_noexec = 32, 1, 2, 4, 8
        cls._mount_call(stage, stage, ms_bind | ms_rec)
        try:
            cls._mount_call(stage, stage, ms_private | ms_rec)
            cls._mount_call(stage, stage, ms_bind | ms_remount | ms_readonly |
                            ms_nosuid | ms_nodev | ms_noexec)
        except BaseException:
            try:
                cls._umount_native_staging(stage)
            except OSError:
                pass
            raise

    @staticmethod
    def _umount_native_staging(stage: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        umount2 = libc.umount2
        umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
        umount2.restype = ctypes.c_int
        if umount2(os.fsencode(stage), 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(stage))

    @staticmethod
    def _ensure_root_runtime_directory(path: Path, mode: int) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            path.mkdir(mode=mode)
            os.chown(path, 0, 0)
            os.chmod(path, mode)
            info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != mode):
            raise AuthorityDenied("native.mount", "fixed runtime mount directory custody is invalid")

    @staticmethod
    def _write_native_file(path: Path, contents: bytes, mode: int) -> None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.fchown(fd, 0, 0)
            view = memoryview(contents)
            while view:
                written = os.write(fd, view)
                view = view[written:]
            os.fchmod(fd, mode)
        finally:
            os.close(fd)

    @classmethod
    def _copy_native_tree(cls, source: Path, destination: Path,
                          expected: Mapping[str, tuple[str, int, int]] | None) -> None:
        destination.mkdir(mode=0o700, parents=True)
        for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
            base = Path(current)
            rel_dir = base.relative_to(source)
            target_dir = destination / rel_dir
            for name in dirs:
                src_dir = base / name
                info = src_dir.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise AuthorityDenied("native.mount", "native package tree contains an unsafe directory")
                (target_dir / name).mkdir(mode=0o700)
            for name in files:
                src = base / name
                info = src.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                        or info.st_nlink != 1):
                    raise AuthorityDenied("native.mount", "native package tree contains an unsafe file")
                relative = src.relative_to(source).as_posix()
                data = src.read_bytes()
                if expected is not None:
                    row = expected.get(relative)
                    if row != (hashlib.sha256(data).hexdigest(), len(data), stat.S_IMODE(info.st_mode)):
                        raise AuthorityDenied("native.mount", "native closure changed while staging")
                    mode = row[2]
                else:
                    # Catalog materialization already matched its protected
                    # tree manifest; preserve executable metadata while
                    # stripping every write bit in the mount staging copy.
                    mode = 0o555 if info.st_mode & 0o111 else 0o444
                cls._write_native_file(target_dir / name, data, mode)
        cls._make_native_tree_readonly(destination)

    @staticmethod
    def _verify_native_tree(source: Path,
                            expected: Mapping[str, tuple[str, int, int]]) -> None:
        observed: dict[str, tuple[str, int, int]] = {}
        total = 0
        for current, dirs, files in os.walk(source, topdown=True, followlinks=False):
            base = Path(current)
            for name in dirs:
                info = (base / name).lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise AuthorityDenied("native.dependencies", "dependency tree directory custody is invalid")
            for name in files:
                path = base / name
                info = path.lstat()
                relative = _native_relative(path.relative_to(source).as_posix())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                        or info.st_nlink != 1 or info.st_size > 256 * 1024 * 1024):
                    raise AuthorityDenied("native.dependencies", "dependency tree has unsafe file custody")
                total += info.st_size
                if total > 2 * 1024**3:
                    raise AuthorityDenied("native.dependencies", "dependency tree exceeds aggregate size bound")
                digest = hashlib.sha256()
                with path.open("rb") as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                observed[relative] = (digest.hexdigest(), info.st_size, stat.S_IMODE(info.st_mode))
        if observed != dict(expected):
            raise AuthorityDenied("native.dependencies", "dependency tree differs from its protected catalog manifest")

    @staticmethod
    def _make_native_tree_readonly(root: Path) -> None:
        for current, dirs, _files in os.walk(root, topdown=False, followlinks=False):
            for name in dirs:
                path = Path(current) / name
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                    raise AuthorityDenied("native.mount", "staged native package directory changed")
                os.chmod(path, 0o555)
            info = Path(current).lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                raise AuthorityDenied("native.mount", "staged native package root changed")
            os.chmod(current, 0o555)

    @staticmethod
    def _remove_native_staging(stage: Path) -> None:
        if stage.parent != Path("/run/hermes-installer/native-staging"):
            raise AuthorityDenied("native.cleanup", "native staging path is outside fixed custody")
        try:
            info = stage.lstat()
        except FileNotFoundError:
            # Several bounded preparation failures unwind through both their
            # local exception branch and the outer launch-finally block.
            return
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise AuthorityDenied("native.cleanup", "native staging tree custody changed")
        ManagedProcessEffectHandler._umount_native_staging(stage)
        for current, dirs, files in os.walk(stage, topdown=False, followlinks=False):
            base = Path(current)
            for name in files:
                item = base / name
                item_info = item.lstat()
                if not stat.S_ISREG(item_info.st_mode) or item_info.st_uid != 0 or item_info.st_nlink != 1:
                    raise AuthorityDenied("native.cleanup", "native staged file changed custody")
                item.chmod(0o600)
                item.unlink()
            for name in dirs:
                item = base / name
                item_info = item.lstat()
                if not stat.S_ISDIR(item_info.st_mode) or item_info.st_uid != 0:
                    raise AuthorityDenied("native.cleanup", "native staged directory changed custody")
                item.chmod(0o700)
                item.rmdir()
        stage.chmod(0o700)
        stage.rmdir()

    def _verify_native_package_mount(self, pid: int, receipt: NativePackageMountReceipt) -> None:
        failure_code = "procfs"
        try:
            raw = Path(f"/proc/{pid}/mountinfo").read_text()
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("mount table oversized")
            candidates = []
            for line in raw.splitlines():
                fields = line.split()
                if "-" not in fields:
                    continue
                separator = fields.index("-")
                mountpoint = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
                if mountpoint == receipt.mount_path:
                    candidates.append((fields, separator))
            if len(candidates) != 1:
                failure_code = "target"
                raise ValueError("mount target absent or ambiguous")
            fields, separator = candidates[0]
            options = set(fields[5].split(","))
            propagation = fields[6:separator]
            missing = sorted({"ro", "nosuid", "nodev", "noexec"} - options)
            if missing:
                failure_code = "mount_missing_" + "_".join(missing)
                raise ValueError("mount flags are not constrained")
            propagation_flags = [item.split(":", 1)[0] for item in propagation
                                 if item.startswith(("shared:", "master:", "propagate_from:"))]
            if propagation_flags:
                failure_code = "mount_propagation_" + "_".join(sorted(set(propagation_flags)))
                raise ValueError("mount flags are not constrained")
            observed = os.stat(f"/proc/{pid}/root{receipt.mount_path}", follow_symlinks=False)
            if (observed.st_dev, observed.st_ino) != (receipt.mount_source_device, receipt.mount_source_inode):
                failure_code = "source_identity"
                raise ValueError("mounted root inode differs from the staged package")
        except (OSError, ValueError, IndexError):
            if self._diagnostic_sink is not None:
                # Deliberately exclude filesystem paths and exception strings;
                # this bounded code is sufficient to diagnose kernel proof.
                self._diagnostic_sink(("native-mount-verification-failed:" + failure_code).encode("ascii"))
            raise AuthorityDenied("native.mount_effect", "kernel did not establish the exact private read-only package mount") from None

    def _verify_xauthority_mount(self, pid: int, receipt: XauthorityMountReceipt) -> None:
        failure_code = "procfs"
        try:
            raw = Path(f"/proc/{pid}/mountinfo").read_text()
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("mount table oversized")
            candidates = []
            for line in raw.splitlines():
                fields = line.split()
                if "-" not in fields:
                    continue
                separator = fields.index("-")
                mountpoint = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
                if mountpoint == receipt.mount_path:
                    candidates.append((fields, separator))
            if len(candidates) != 1:
                failure_code = "target"
                raise ValueError("credential target absent or ambiguous")
            fields, separator = candidates[0]
            options = set(fields[5].split(","))
            propagation = fields[6:separator]
            if {"ro", "nosuid", "nodev", "noexec"} - options:
                failure_code = "mount_flags"
                raise ValueError("credential mount flags are not constrained")
            if any(item.startswith(("shared:", "master:", "propagate_from:")) for item in propagation):
                failure_code = "propagation"
                raise ValueError("credential mount propagation is not private")
            observed = os.stat(f"/proc/{pid}/root{receipt.mount_path}", follow_symlinks=False)
            if (observed.st_dev, observed.st_ino) != (
                    receipt.mount_source_device, receipt.mount_source_inode):
                failure_code = "source_identity"
                raise ValueError("credential mount does not bind the staged inode")
            if (not stat.S_ISREG(observed.st_mode) or observed.st_size != receipt.size_bytes
                    or observed.st_gid != receipt.owner_gid or stat.S_IMODE(observed.st_mode) != 0o440):
                failure_code = "file_metadata"
                raise ValueError("credential mount metadata changed")
            mounted_digest = hashlib.sha256(
                Path(f"/proc/{pid}/root{receipt.mount_path}").read_bytes()).hexdigest()
            if mounted_digest != receipt.source_sha256:
                failure_code = "file_digest"
                raise ValueError("credential mount bytes changed")
        except (OSError, ValueError, IndexError):
            if self._diagnostic_sink is not None:
                self._diagnostic_sink(("xauthority-mount-verification-failed:" + failure_code).encode("ascii"))
            raise AuthorityDenied("process.xauthority_mount", "kernel did not establish the exact protected credential mount") from None

    @staticmethod
    def _validate_profile(profile: ManagedProfileCustody) -> None:
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile.profile_id)
                or profile.owner_uid <= 0 or profile.owner_gid <= 0):
            raise ValueError("protected process profile identity is invalid")
        if (profile.service_generation_digest is not None
                and (not isinstance(profile.service_generation_digest, str)
                     or not re.fullmatch(r"[0-9a-f]{64}", profile.service_generation_digest))):
            raise ValueError("managed process service generation digest is invalid")
        expected_user = "hermes-" + hashlib.sha256(profile.profile_id.encode()).hexdigest()[:16]
        account = pwd.getpwnam(profile.service_user)
        if (profile.service_user != expected_user or account.pw_uid != profile.owner_uid
                or account.pw_gid != profile.owner_gid or account.pw_shell != "/usr/sbin/nologin"
                or account.pw_dir != "/nonexistent" or os.getgrouplist(profile.service_user, account.pw_gid) != [account.pw_gid]):
            raise ValueError("profile does not use its dedicated non-login service identity")
        exe = _root_path(profile.executable, directory=False)
        artifacts = _root_path(profile.artifact_root, directory=True)
        if exe != profile.executable or artifacts != profile.artifact_root:
            raise ValueError("pinned executable or artifact root is not canonical")
        if hashlib.sha256(exe.read_bytes()).hexdigest() != profile.artifact_sha256:
            raise ValueError("pinned executable digest does not match protected profile registry")
        data = profile.data_root.resolve(strict=True)
        cursor = Path(data.anchor)
        for part in data.parts[1:]:
            cursor /= part
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise ValueError("profile data root traverses a symlink")
        data_info = data.stat(follow_symlinks=False)
        if data != profile.data_root or not data.is_dir() or data_info.st_uid != profile.owner_uid or data_info.st_mode & 0o077:
            raise ValueError("profile data root is not private to the service identity")
        children = profile.child_artifact_refs or {}
        if len(children) > 32 or any(
                not isinstance(store_id, str)
                or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", store_id)
                or store_id.rsplit(":", 1)[-1] != digest
                for store_id, digest in children.items()):
            raise ValueError("child artifact references are invalid")
        recipe = profile.argv_recipe
        if not profile.operation_recipes and (
                not isinstance(recipe, tuple) or not recipe or len(recipe) > 128
                or recipe[0] != str(exe)
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096
                       for arg in recipe)
                or recipe.count("{child_artifact}") > 1):
            raise ValueError("protected process argv recipe is invalid")
        role_pins = profile.process_role_artifact_hashes or {}
        allowed_roles = {"xpra-server", "electron-renderer", "electron-browser", "renderer-relaunch-monitor"}
        if (len(role_pins) > 64 or any(
                not re.fullmatch(r"[0-9a-f]{64}", digest) or role not in allowed_roles
                for digest, role in role_pins.items())):
            raise ValueError("protected process inspection role pins are invalid")
        registered_digests = {profile.artifact_sha256, *children.values()}
        if any(digest not in registered_digests for digest in role_pins):
            raise ValueError("process inspection roles must reference enrolled executable artifacts")
        if not profile.operation_recipes and _code_interpreter(exe.name) and recipe != (str(exe), "{child_artifact}"):
            raise ValueError("code interpreters require one immutable child-artifact operand")
        sock = profile.authority_socket or Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock")
        if sock != Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock"):
            raise ValueError("profile authority socket path is not the per-UID endpoint")
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", profile.generation)
                or type(profile.max_lifetime_seconds) is not int
                or not 0 < profile.max_lifetime_seconds <= 600):
            raise ValueError("profile generation or maximum lifetime is invalid")
        protected_paths = [profile.executable, profile.artifact_root, profile.data_root, sock]
        if profile.home_root is not None:
            protected_paths.append(profile.home_root)
        if profile.work_root is not None:
            protected_paths.append(profile.work_root)
        for path in protected_paths:
            if any(char.isspace() for char in str(path)) or ":" in str(path):
                raise ValueError("protected process paths cannot contain systemd property delimiters")
        for value, lower, upper, label in (
            (profile.memory_max_bytes, 16 * 1024 * 1024, 64 * 1024**3, "memory"),
            (profile.cpu_quota_percent, 1, 10_000, "CPU"),
            (profile.io_weight, 1, 10_000, "I/O"),
        ):
            if value is not None and (type(value) is not int or not lower <= value <= upper):
                raise ValueError(f"profile {label} limit is invalid")
        _validate_operation_enrollment(profile)

    def handlers(self) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
        result = {}
        for profile in self.profiles.values():
            result[("process.start", process_start_target(profile))] = self._bound(profile, "process.start")
            for verb in ("process.status", "process.read", "process.write", "process.stop"):
                target = process_control_target(profile, verb)
                result[(verb, target)] = self._bound(profile, verb)
            result[("process.inspect", process_inspect_target(profile))] = self._bound(profile, "process.inspect")
        return result

    def _bound(self, profile: ManagedProfileCustody, operation: str):
        def handler(*, context: HostContext, authorization: EffectAuthorization,
                    payload: bytes, timeout: float, peer_pid: int,
                    peer_pidfd: int | None,
                    cancelled: Callable[[], bool]) -> Mapping[str, Any]:
            # Resolve the current immutable enrollment row for this handler ID.
            # A refreshed row with the same effect target must be used for
            # admission; a changed target remains unreachable through this
            # already-registered handler key and is rejected by dispatch.
            with self._lock:
                current_profile = self.profiles.get(profile.profile_id)
            if current_profile is None:
                raise AuthorityDenied("process.profile", "enrolled process profile is no longer active")
            return self.dispatch(current_profile, operation, context=context, authorization=authorization,
                                 payload=payload, timeout=timeout, peer_pid=peer_pid,
                                 peer_pidfd=peer_pidfd,
                                 cancelled=cancelled)
        return handler

    def dispatch(self, profile: ManagedProfileCustody, operation: str, *,
                 context: HostContext, authorization: EffectAuthorization, payload: bytes,
                 timeout: float, peer_pid: int, peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        target = (process_start_target(profile) if operation == "process.start"
                  else process_inspect_target(profile) if operation == "process.inspect"
                  else process_control_target(profile, operation))
        expected_capability = "hermes-profile-invoke" if operation == "process.start" else "hermes-process-control"
        if (operation not in {"process.start", "process.status", "process.read", "process.write", "process.stop", "process.inspect"}
                or context.profile_id != profile.profile_id or authorization.profile_id != profile.profile_id
                or authorization.uid != context.uid or authorization.target != target
                or authorization.capability != expected_capability
                or authorization.principal_id != context.principal_id
                or authorization.namespace_id != context.namespace_id
                or authorization.trace_id != context.trace_id
                or authorization.intent_id != context.intent_id
                or context.operation != operation or authorization.operation != operation
                or peer_pid <= 0 or canonical_digest(payload) != authorization.request_digest):
            raise AuthorityDenied("process.binding", "process grant does not match the enrolled profile effect")
        if operation == "process.start":
            try:
                return self._start(profile, context, authorization, payload, timeout, peer_pid,
                                   peer_pidfd, cancelled)
            except Exception as exc:
                self._record_test_diagnostic("start-deny", exc)
                raise
        if operation == "process.inspect":
            try:
                return self._inspect(profile, context, payload, timeout, cancelled)
            except Exception as exc:
                self._record_test_diagnostic("inspect-deny", exc)
                raise
        return self._control(profile, context, operation, payload, timeout, cancelled)

    def _record_test_diagnostic(self, prefix: str, exc: Exception) -> None:
        """Emit only bounded exception class/code/line into root-only test evidence."""
        sink = self._diagnostic_sink
        if sink is None:
            return
        code = getattr(exc, "code", "internal")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z0-9_.-]{1,64}", code):
            code = "internal"
        exception_type = type(exc).__name__
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", exception_type):
            exception_type = "Exception"
        import traceback
        frames = traceback.extract_tb(exc.__traceback__)[-5:] if exc.__traceback__ else []
        frame_path = ",".join(f"{frame.name}:{frame.lineno}" for frame in frames)
        # Function names and source line numbers contain no request values or
        # host paths, and make root-only fixture failures actionable.
        if not re.fullmatch(r"[A-Za-z0-9_.,:< >-]{0,384}", frame_path):
            frame_path = "unavailable"
        sink((prefix + ":" + code + ":" + exception_type + ":frames=" + frame_path).encode("ascii"))

    @staticmethod
    def _json(payload: bytes) -> dict[str, Any]:
        if not isinstance(payload, bytes) or len(payload) > 131072:
            raise AuthorityDenied("process.bounds", "process request exceeds its bound")
        try:
            value = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorityDenied("process.request", "process request is malformed") from None
        if not isinstance(value, dict):
            raise AuthorityDenied("process.request", "process request must be an object")
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=True, allow_nan=False).encode("ascii")
        if canonical != payload:
            raise AuthorityDenied("process.request", "process request is not canonical JSON")
        return value

    def _start(self, profile: ManagedProfileCustody, context: HostContext,
               authorization: EffectAuthorization, payload: bytes, timeout: float,
               peer_pid: int | None, peer_pidfd: int | None,
               cancelled: Callable[[], bool], *,
               start_guard: Callable[[], bool] | None = None,
               task_admission: RootAdmittedTask | None = None,
               daemon_liveness_pidfd: int | None = None,
               root_resource_start: Any | None = None,
               root_application_start: Any | None = None) -> Mapping[str, Any]:
        with self._lock:
            if (profile.profile_id in self._starting
                    or any(item.profile.profile_id == profile.profile_id for item in self._handles.values())):
                raise AuthorityDenied("process.generation", "a managed process is already active for this profile")
            self._starting.add(profile.profile_id)
        try:
            if profile.operation_recipes:
                return self.start_selected_operation(
                    profile, context, authorization, payload, timeout=timeout,
                    peer_pid=peer_pid, peer_pidfd=peer_pidfd, cancelled=cancelled,
                    _start_guard=start_guard, _task_admission=task_admission,
                    _daemon_liveness_pidfd=daemon_liveness_pidfd,
                    _root_resource_start=root_resource_start,
                    _root_application_start=root_application_start,
                )
            return self._start_reserved(profile, context, authorization, payload, timeout,
                                        peer_pid, peer_pidfd, cancelled, start_guard=start_guard,
                                        daemon_liveness_pidfd=daemon_liveness_pidfd)
        finally:
            with self._lock:
                self._starting.discard(profile.profile_id)

    def start_selected_operation(self, profile: ManagedProfileCustody, context: HostContext,
                                 authorization: EffectAuthorization, payload: bytes, *,
                                 timeout: float, peer_pid: int | None, peer_pidfd: int | None,
                                 cancelled: Callable[[], bool],
                                 _start_guard: Callable[[], bool] | None = None,
                                 _task_admission: RootAdmittedTask | None = None,
                                 _root_selected_effect: Any | None = None,
                                 _root_selected_health_admission: Any | None = None,
                                 _root_selected_lifecycle_deadline: float | None = None,
                                 _xauthority_mount_source: Path | None = None,
                                 _daemon_liveness_pidfd: int | None = None,
                                 _root_resource_start: Any | None = None,
                                 _root_application_start: Any | None = None) -> Mapping[str, Any]:
        """Resolve a selection-only worker request to one immutable root recipe.

        This method is called only after dispatch has checked the consumed
        process.start grant against these exact selection bytes. No path, argv,
        executable, environment, PID, namespace, or socket comes from the peer.
        """
        if _root_selected_effect is not None:
            from hermes_installer.authority.types import VerifiedRootSelectedServiceEffect
            if (type(_root_selected_effect) is not VerifiedRootSelectedServiceEffect
                    or not _root_selected_effect.is_current()):
                raise AuthorityDenied("root-selected.authority", "sealed current root service effect is required")
        if _root_selected_health_admission is not None:
            from hermes_installer.authority.native_health_observer import RootNativeHealthStartAdmission
            authority = self.native_health_start_authority
            if (type(_root_selected_health_admission) is not RootNativeHealthStartAdmission
                    or authority is None
                    or not authority.is_current(_root_selected_health_admission)
                    or context is not None or authorization is not None
                    or peer_pid is not None or peer_pidfd is not None
                    or _daemon_liveness_pidfd is None
                    or _root_selected_effect is None
                    or _root_selected_effect.role != "health"
                    or _root_selected_effect.action != "start"):
                raise AuthorityDenied("native.health.admission", "current root health admission is required")
        request = self._json(payload)
        if (_root_selected_effect is not None
                and _root_selected_effect.role in {
                    "memory-openviking", "memory-agentmemory", "memory-claude-mem"}
                and (context is not None or authorization is not None
                     or peer_pid is not None or peer_pidfd is not None
                     or _daemon_liveness_pidfd is None)):
            raise AuthorityDenied("root-selected.authority", "memory lifecycle launch must use the typed root admission path")
        expected_fields = {"schema", "enrollment_id", "generation", "operation_id", "parameters"}
        if _task_admission is not None:
            expected_fields |= {"admission_handle", "node_id", "task_payload_sha256",
                                "stdin_sha256", "stdin_size_bytes"}
        if _root_application_start is not None:
            expected_fields |= {"application_admission_handle", "application_step_id"}
        if (set(request) != expected_fields
                or type(request.get("schema")) is not int or request["schema"] != 1
                or request.get("enrollment_id") != profile.enrollment_id
                or request.get("generation") != profile.generation):
            raise AuthorityDenied("process.selection", "operation selection is malformed or stale")
        operation_id = request.get("operation_id")
        recipes = profile.operation_recipes or {}
        recipe = recipes.get(operation_id) if isinstance(operation_id, str) else None
        if not isinstance(recipe, Mapping):
            raise AuthorityDenied("process.recipe", "operation recipe is not enrolled for this generation")
        if not isinstance(profile.operation_targets, Mapping) or not profile.operation_targets.get("process.start"):
            raise AuthorityDenied("process.target", "operation launch target is not enrolled")
        parameters = request.get("parameters")
        if not isinstance(parameters, dict):
            raise AuthorityDenied("process.parameters", "operation parameters must be a bounded object")
        if _root_application_start is not None:
            from hermes_installer.authority.application_workload_execution import VerifiedRootApplicationStart
            proof = _root_application_start
            service = getattr(getattr(proof, "_issuer", None), "service", None)
            verify = getattr(service, "verify_consumed_application_start", None)
            if (type(proof) is not VerifiedRootApplicationStart or proof.selected_profile is not profile
                    or not callable(verify)
                    or verify(proof, payload, selected_step_handle=proof.selected_step.handle) is not True
                    or request.get("application_admission_handle") != proof.context.admission_handle
                    or request.get("application_step_id") != proof.context.step_id
                    or profile.profile_id != proof.context.profile_id
                    or profile.generation != proof.context.profile_generation):
                raise AuthorityDenied("application.start_proof", "consumed root application proof is stale")
        if _task_admission is not None and (
                request.get("node_id") != _task_admission.node_id
                or request.get("task_payload_sha256") != _task_admission.task_payload_sha256
                or request.get("stdin_sha256") != _task_admission.stdin_sha256
                or request.get("stdin_size_bytes") != _task_admission.stdin_size_bytes
                or not isinstance(request.get("admission_handle"), str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", request["admission_handle"])):
            raise AuthorityDenied("resource.task_selection", "internal task selection differs from its admission")
        schema_id = recipe["parameter_schema_id"]
        schema = (profile.parameter_schemas or {}).get(schema_id)
        if not isinstance(schema, Mapping):
            raise AuthorityDenied("process.parameters", "operation parameter schema is unavailable")
        normalized = self._validate_operation_parameters(parameters, schema)

        grant_expiry = (float(_root_application_start.authorization.expires_monotonic)
                        if _root_application_start is not None else
                        float(_root_selected_effect.expires_monotonic)
                        if _root_selected_effect is not None else
                        float(_root_resource_start.authorization.expires_monotonic)
                        if _root_resource_start is not None else
                        float(authorization.monotonic_expires_at))
        if (cancelled() or isinstance(grant_expiry, bool)
                or not isinstance(grant_expiry, (int, float))
                or self.monotonic() >= grant_expiry):
            raise AuthorityDenied("process.start_expired", "operation grant expired before recipe resolution")
        executable_id = recipe["executable_artifact_id"]
        executable_digest = recipe["executable_sha256"]
        executable_ref = (executable_id if executable_id.startswith("artifact:")
                          else f"artifact:{executable_id}:{executable_digest}")
        executable = self._resolve_enrolled_artifact(executable_ref, executable_digest, executable=True)
        children: dict[str, str] = {}
        child_refs_by_id: dict[str, str] = {}
        for artifact_id, digest in recipe["child_artifact_refs"].items():
            ref = artifact_id if artifact_id.startswith("artifact:") else f"artifact:{artifact_id}:{digest}"
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise AuthorityDenied("process.recipe", "child artifact digest is malformed")
            children[ref] = digest
            child_refs_by_id[artifact_id] = ref
        executable_tokens = [str(executable)]
        for item in recipe["argv_recipe"]:
            if "literal" in item:
                token = item["literal"]
                token = child_refs_by_id.get(token, token)
            else:
                parameter_name = item["parameter"]
                if parameter_name not in normalized:
                    raise AuthorityDenied("process.parameters", "argv recipe references an absent optional parameter")
                value = normalized[parameter_name]
                token = ("true" if value else "false") if type(value) is bool else str(value)
            if not isinstance(token, str) or "\x00" in token or len(token) > 4096:
                raise AuthorityDenied("process.argv", "resolved operation argument exceeds its bound")
            executable_tokens.append(token)
        if any(any(secret in item.casefold() for secret in ("--token", "--secret", "--password", "--api-key", "--credential"))
               for item in executable_tokens[1:]):
            raise AuthorityDenied("process.secret", "credential-bearing argv is forbidden")
        environment = dict(recipe["environment"])
        if (len(environment) > 32 or any(key not in _ALLOWED_ENV for key in environment)
                or any(not isinstance(value, str) or "\x00" in value or "\n" in value or "\r" in value
                       or len(value) > 1024 for value in environment.values())
                or environment.get("HOME") != "/hermes" or environment.get("HERMES_HOME") != "/hermes"):
            raise AuthorityDenied("process.environment", "enrolled operation environment is invalid")
        if _root_selected_effect is not None:
            if _root_selected_effect.role == "display":
                if _xauthority_mount_source is None:
                    raise AuthorityDenied("root-selected.mount", "selected display lacks its fixed role mount")
                environment["XAUTHORITY"] = "/run/hermes-installer/display/Xauthority"
            elif _root_selected_health_admission is not None:
                from hermes_installer.authority.native_health_observer import RootNativeHealthStartAdmission
                admission = _root_selected_health_admission
                authority = self.native_health_start_authority
                operation = admission._process_operation
                if (type(admission) is not RootNativeHealthStartAdmission
                        or authority is None or not authority.is_current(admission)
                        or not authority.verify_consumed_start_effect(_root_selected_effect, admission)
                        or self.profiles.get(profile.profile_id) is not profile
                        or profile is not admission._service_profile
                        or profile.profile_id != admission.profile_id
                        or profile.enrollment_id != admission.enrollment_id
                        or profile.generation != admission.process_generation
                        or profile.service_generation_digest != admission.service_generation_digest
                        or operation is not admission._process_operation
                        or operation.operation_id != admission.operation_id
                        or operation.target != _root_selected_effect.target
                        or _root_selected_effect.operation != "process.start"
                        or _root_selected_effect.capability != "hermes-profile-invoke"
                        or _root_selected_effect.selected_principal_id != admission.principal_id
                        or _root_selected_effect.selected_subject_uid != profile.owner_uid
                        or _root_selected_effect.selected_subject_gid != profile.owner_gid):
                    raise AuthorityDenied("native.health.binding", "health effect differs from the current selected recipe")
            elif (_root_selected_effect.role not in {
                    "memory-openviking", "memory-agentmemory", "memory-claude-mem"}
                    or _root_selected_effect.admission_kind != "memory"
                    or _root_selected_effect.action != "start"
                    or _xauthority_mount_source is not None):
                raise AuthorityDenied("root-selected.mount", "selected operation has no fixed supported role binding")
        cwd_root_id = recipe["cwd_root_id"]
        root_by_id = {profile.home_id: profile.home_root, profile.work_id: profile.work_root,
                      profile.data_id: profile.data_root}
        root_path = root_by_id.get(cwd_root_id)
        if root_path is None:
            raise AuthorityDenied("process.cwd", "operation working root is not enrolled")
        relative = recipe["cwd_subpath"]
        cwd = root_path if relative in {"", "."} else root_path / relative
        try:
            resolved_cwd = cwd.resolve(strict=True)
            if not resolved_cwd.is_dir() or not resolved_cwd.is_relative_to(root_path):
                raise ValueError("working directory escapes enrolled root")
            cursor = root_path
            for part in Path(relative).parts if relative not in {"", "."} else ():
                cursor /= part
                if stat.S_ISLNK(cursor.lstat().st_mode):
                    raise ValueError("working directory traverses a symlink")
        except (OSError, ValueError):
            raise AuthorityDenied("process.cwd", "operation working directory is unavailable") from None
        recipe_argv = tuple([str(executable), *(
            "{child_artifact}" if token in children else token for token in executable_tokens[1:]
        )])
        derived = replace(profile, executable=executable, artifact_sha256=executable_digest,
                          child_artifact_refs=children, argv_recipe=recipe_argv)
        launch = {
            "schema": 1, "target": process_start_target(derived),
            "profile_id": profile.profile_id, "executable": str(executable),
            "artifact_sha256": executable_digest, "artifact_root": str(profile.artifact_root),
            "cwd": str(resolved_cwd), "data_root": str(profile.data_root),
            "argv": executable_tokens, "env_allowlist": environment,
            "child_artifact_refs": children,
            "max_lifetime_seconds": recipe["max_lifetime_seconds"],
            "max_output_bytes": recipe["max_output_bytes"],
            "stdin_mode": "pipe" if recipe["stdin_mode"] == "bounded-typed-bytes" else "closed",
        }
        launch_bytes = json.dumps(launch, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        lifecycle_deadline = (float(grant_expiry) if _root_selected_lifecycle_deadline is None
                              else _root_selected_lifecycle_deadline)
        if (isinstance(lifecycle_deadline, bool) or not isinstance(lifecycle_deadline, (int, float))
                or not math.isfinite(lifecycle_deadline) or lifecycle_deadline <= self.monotonic()):
            raise AuthorityDenied("process.start_expired", "root-selected service lifetime deadline is invalid")
        return self._start_reserved(derived, context, authorization, launch_bytes, timeout,
                                   peer_pid, peer_pidfd, cancelled, registered_profile=profile,
                                   start_guard=_start_guard,
                                   lease_expires_monotonic=float(lifecycle_deadline),
                                   process_expires_monotonic=_root_selected_lifecycle_deadline,
                                   root_selected_effect=_root_selected_effect,
                                   xauthority_mount_source=_xauthority_mount_source,
                                   daemon_liveness_pidfd=_daemon_liveness_pidfd)

    def perform_root_selected_service_effect(
            self, profile: ManagedProfileCustody, verified_effect: Any,
            canonical_payload_bytes: bytes, *, controller_proof: Any | None = None,
            memory_admission: Any | None = None,
            timeout: float, cancelled: Callable[[], bool],
            xauthority_binding: Any | None = None,
            xauthority_registry: Any | None = None) -> RootSelectedServiceProcessReceipt | RootSelectedServiceStatusReceipt | Mapping[str, Any]:
        """Launch one sealed root-selected service operation from its fixed recipe.

        The controller PIDFD is verified as provenance, while the manager owns
        the launched process lifetime. No worker context, caller path, argv, or
        synthetic ordinary grant is created for this root-only path.
        """
        from hermes_installer.authority.types import VerifiedRootSelectedServiceEffect
        from hermes_installer.authority.selected_startup_authority import (
            RootControllerProcessIdentityLease,
        )
        if cancelled is None:
            cancelled = lambda: False
        if type(verified_effect) is not VerifiedRootSelectedServiceEffect:
            raise AuthorityDenied("root-selected.effect", "sealed selected-service effect is required")
        if (type(profile) is not ManagedProfileCustody
                or self.profiles.get(profile.profile_id) is not profile
                or not isinstance(canonical_payload_bytes, bytes)
                or not callable(cancelled)
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600):
            raise AuthorityDenied("root-selected.binding", "selected service launch binding is malformed")
        request = self._json(canonical_payload_bytes)
        effect = verified_effect
        action = effect.action
        memory_role = effect.role in {
            "memory-openviking", "memory-agentmemory", "memory-claude-mem",
        }
        if memory_role:
            from hermes_installer.memory.lifecycle_authority import RootVerifiedMemoryLifecycleAdmission
            if type(memory_admission) is not RootVerifiedMemoryLifecycleAdmission:
                raise AuthorityDenied("root-selected.memory", "sealed current memory lifecycle admission is required")
            if controller_proof is None:
                controller_proof = memory_admission._controller_lease
            if (type(controller_proof) is not RootControllerProcessIdentityLease
                    or controller_proof is not memory_admission._controller_lease
                    or not memory_admission.is_current(now=self.monotonic())
                    or effect.admission_handle != memory_admission.admission_handle
                    or effect.admission_kind != "memory"
                    or effect.role != memory_admission.role
                    or effect.profile_id != memory_admission.profile_id
                    or effect.enrollment_id != memory_admission.service_enrollment_id
                    or effect.generation != memory_admission.generation
                    or effect.selected_principal_id != memory_admission.principal_id
                    or effect.selected_namespace_identity != memory_admission.namespace_identity
                    or effect.selected_subject_uid != memory_admission.subject_uid
                    or effect.selected_subject_gid != memory_admission.subject_gid
                    or effect.service_generation_digest != memory_admission.service_generation_digest
                    or effect.source_closure_sha256 != memory_admission.source_closure_sha256):
                raise AuthorityDenied("root-selected.memory", "memory effect differs from its current lifecycle admission")
            try:
                selected_action = memory_admission.action(action, now=self.monotonic())
            except Exception:
                raise AuthorityDenied("root-selected.memory", "memory lifecycle action is not current") from None
            if (selected_action.operation_id != effect.operation_id
                    or selected_action.target != effect.target
                    or selected_action.operation != effect.operation
                    or selected_action.capability != effect.capability):
                raise AuthorityDenied("root-selected.memory", "memory effect differs from its protected lifecycle action")
        if type(controller_proof) is not RootControllerProcessIdentityLease:
            raise AuthorityDenied("root-selected.controller", "root controller PIDFD lease is required")
        if memory_role:
            if effect.admission_kind != "memory":
                raise AuthorityDenied("root-selected.role", "memory operation requires a memory lifecycle admission")
            operation_id = effect.operation_id
            expected_operation = {"start": "process.start", "status": "process.status",
                                  "stop": "process.stop"}.get(action)
            expected_capability = ("hermes-profile-invoke" if action == "start"
                                   else "hermes-process-control")
            expected_target = (process_start_target(profile) if action == "start"
                               else process_control_target(profile, expected_operation or ""))
            if action == "start":
                expected_payload_fields = {"schema", "enrollment_id", "generation", "operation_id", "parameters"}
                process_id = None
            else:
                expected_payload_fields = {"schema", "process_id", "generation"}
                if action == "stop":
                    expected_payload_fields |= {"reason", "grace_seconds"}
                process_id = request.get("process_id")
            if (set(request) != expected_payload_fields or request.get("schema") != 1
                    or request.get("generation") != profile.generation
                    or (action == "start" and (
                        request.get("enrollment_id") != profile.enrollment_id
                        or request.get("operation_id") != operation_id
                        or request.get("parameters") != {}))
                    or (action != "start" and (
                        not isinstance(process_id, str) or not re.fullmatch(r"[0-9a-f]{32}", process_id)))
                    or (action == "stop" and (
                        request.get("reason") not in {"shutdown", "cancel", "rollback"}
                        or type(request.get("grace_seconds")) is not int
                        or request.get("grace_seconds") != 5))):
                raise AuthorityDenied("root-selected.payload", "memory lifecycle payload is malformed")
        else:
            operation_id = request.get("operation_id")
            expected_operation = "process.start"
            expected_capability = "hermes-profile-invoke"
            expected_target = process_start_target(profile)
            if set(request) != {"schema", "enrollment_id", "generation", "operation_id", "parameters"}:
                raise AuthorityDenied("root-selected.payload", "selected startup payload is malformed")
        profile_digest = profile.service_generation_digest
        if (not isinstance(operation_id, str)
                or effect.operation != expected_operation
                or effect.capability != expected_capability
                or effect.profile_id != profile.profile_id
                or effect.enrollment_id != profile.enrollment_id
                or effect.generation != profile.generation
                or effect.selected_subject_uid != profile.owner_uid
                or effect.selected_subject_gid != profile.owner_gid
                or effect.service_generation_digest != profile_digest
                or effect.operation_id != operation_id
                or effect.target != expected_target
                or not isinstance(profile.operation_recipes, Mapping)
                or (action == "start" and operation_id not in profile.operation_recipes)
                or (action != "start" and operation_id != "managed-process-" + action + "-v1")
                or hashlib.sha256(canonical_payload_bytes).hexdigest() != effect.request_sha256
                or (action != "start" and hashlib.sha256(json.dumps({
                    "operation": expected_operation, "target": expected_target,
                    "enrollment_id": profile.enrollment_id, "generation": profile.generation,
                }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")).hexdigest()
                    != effect.recipe_sha256)
                or action == "start" and hashlib.sha256(json.dumps(dict(profile.operation_recipes[operation_id]),
                    sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                    allow_nan=False).encode("ascii")).hexdigest() != effect.recipe_sha256
                or not isinstance(effect.controller_proof_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", effect.controller_proof_sha256)
                or getattr(controller_proof, "proof_handle", None) != effect.controller_proof_handle
                or getattr(controller_proof, "proof_sha256", None) != effect.controller_proof_sha256
                or not callable(getattr(controller_proof, "is_current", None))
                or not controller_proof.is_current()
                or not effect.is_current()
                or self.monotonic() >= min(float(effect.expires_monotonic),
                                           float(controller_proof.expires_monotonic))):
            raise AuthorityDenied("root-selected.binding", "selected service effect is stale or mismatched")
        if effect.role not in {"display", "gateway", "desktop",
                               "memory-openviking", "memory-agentmemory", "memory-claude-mem"}:
            raise AuthorityDenied("root-selected.role", "selected service role is unavailable")
        if memory_role:
            return self._perform_root_selected_memory_effect(
                profile, effect, controller_proof, memory_admission,
                canonical_payload_bytes, request,
                timeout=timeout, cancelled=cancelled,
            )
        if effect.role == "display":
            if (xauthority_binding is None or xauthority_registry is None
                    or not callable(getattr(xauthority_registry, "verify_mount_binding", None))
                    or not xauthority_registry.verify_mount_binding(xauthority_binding)):
                raise AuthorityDenied("root-selected.xauthority", "verified Xauthority mount binding is required")
            if effect.action != "start":
                raise AuthorityDenied("root-selected.action", "selected display action is not start")
            with self._lock:
                if (profile.profile_id in self._starting
                        or any(item.profile.profile_id == profile.profile_id
                               for item in self._handles.values())):
                    raise AuthorityDenied("process.generation", "a managed process is already active for this profile")
                self._starting.add(profile.profile_id)
            stage = None
            source_lease = None
            parent_pidfd = None
            launched_process_id = None
            try:
                stage, mount_receipt, source_lease = self._prepare_xauthority_mount(
                    profile, xauthority_binding, xauthority_registry)
                parent_pidfd = os.pidfd_open(os.getpid(), 0)
                if (_pidfd_exited(parent_pidfd)
                        or not controller_proof.is_current()
                        or not effect.is_current()):
                    raise AuthorityDenied("root-selected.currentness", "selected startup proof expired")
                self._verify_root_controller_identity(controller_proof, effect)
                # This metadata object is created inside the root custodian;
                # it is not a worker identity or authority grant.  The
                # verified effect supplies its expiry and all selection facts.
                root_context = SimpleNamespace(
                    principal_id=effect.selected_principal_id,
                    namespace_id=effect.selected_namespace_identity,
                )
                root_auth = SimpleNamespace(monotonic_expires_at=effect.expires_monotonic)
                launch_guard = lambda: (effect.is_current() and controller_proof.is_current()
                                        and self.monotonic() < min(effect.expires_monotonic,
                                                                   controller_proof.expires_monotonic))
                remaining = min(float(timeout), float(effect.expires_monotonic) - self.monotonic())
                if remaining <= 0:
                    raise AuthorityDenied("root-selected.deadline", "selected service effect expired")
                response = self.start_selected_operation(
                    profile, root_context, root_auth, canonical_payload_bytes,
                    timeout=remaining,
                    peer_pid=os.getpid(), peer_pidfd=parent_pidfd, cancelled=cancelled,
                    _start_guard=launch_guard, _root_selected_effect=effect,
                    _xauthority_mount_source=stage)
                body = response.get("body") if isinstance(response, Mapping) else None
                decoded = json.loads(body.decode("ascii")) if isinstance(body, bytes) else None
                process_id = decoded.get("process_id") if isinstance(decoded, dict) else None
                if not isinstance(process_id, str):
                    raise AuthorityDenied("root-selected.launch", "manager did not return an admitted process")
                launched_process_id = process_id
                lease = self.resolve_active_process_handle(profile.profile_id, profile.generation)
                if lease is None:
                    raise AuthorityDenied("root-selected.identity", "selected process is no longer live")
                try:
                    digest = self._selected_service_identity_digest(lease)
                    issued = self.monotonic()
                    receipt = RootSelectedServiceProcessReceipt(
                        1, uuid.uuid4().hex, lease.process_id, effect.role, effect.action,
                        effect.enrollment_id, effect.profile_id, effect.generation,
                        effect.selected_principal_id, effect.selected_namespace_identity,
                        effect.selected_subject_uid, effect.selected_subject_gid,
                        effect.operation_id, effect.target, effect.service_generation_digest,
                        digest, issued, lease.expires_monotonic,
                    )
                    with self._lock:
                        current_handle = self._handles.get(lease.process_id)
                        if (current_handle is None or current_handle.stopped
                                or current_handle.profile.generation != effect.generation
                                or current_handle.xauthority_mount_receipt is None
                                or current_handle.xauthority_mount_receipt != mount_receipt):
                            raise AuthorityDenied("root-selected.identity", "selected process custody changed")
                        self._root_selected_process_receipts[receipt.receipt_handle] = (receipt, current_handle)
                    return receipt
                finally:
                    lease.close()
            except BaseException:
                if launched_process_id is not None:
                    with self._lock:
                        failed_handle = self._handles.get(launched_process_id)
                    if failed_handle is not None and not failed_handle.stopped:
                        try:
                            proof = self._stop(failed_handle, timeout=5.0)
                            if not proof.cleanup_verified:
                                raise AuthorityDenied("process.cleanup_ambiguous",
                                    "failed selected launch cleanup is unproven")
                        except Exception as cleanup_error:
                            raise AuthorityDenied("process.cleanup_ambiguous",
                                "failed selected launch cleanup is unproven") from cleanup_error
                if stage is not None:
                    try:
                        self._remove_native_staging(stage)
                    except Exception:
                        pass
                raise
            finally:
                if source_lease is not None:
                    source_lease.close()
                if parent_pidfd is not None:
                    os.close(parent_pidfd)
                effect.close()
                with self._lock:
                    self._starting.discard(profile.profile_id)
        if effect.role == "desktop":
            raise AuthorityDenied("root-selected.xauthority", "desktop startup requires a sealed display-start receipt")
        if effect.role == "gateway":
            # The generic process unit is deny-all. Gateway must use the
            # separately reviewed role-scoped loopback enforcement adapter.
            raise AuthorityDenied("root-selected.network", "selected loopback network custody is unavailable")
        raise AuthorityDenied("root-selected.role", "selected service launch is unavailable")

    def _perform_root_selected_memory_effect(
            self, profile: ManagedProfileCustody, effect: Any, controller_proof: Any,
            memory_admission: Any,
            payload: bytes, request: Mapping[str, Any], *, timeout: float,
            cancelled: Callable[[], bool]) -> RootSelectedServiceProcessReceipt | RootSelectedServiceStatusReceipt | Mapping[str, Any]:
        """Execute one finite memory lifecycle action against its retained process."""
        if (effect.role not in {"memory-openviking", "memory-agentmemory", "memory-claude-mem"}
                or effect.admission_kind != "memory" or effect.action not in {"start", "status", "stop"}
                or effect.source_closure_sha256 is None):
            raise AuthorityDenied("root-selected.memory", "memory lifecycle binding is unavailable")
        if (not memory_admission.is_current(now=self.monotonic())
                or not controller_proof.is_current()
                or self.monotonic() >= min(effect.expires_monotonic, controller_proof.expires_monotonic)):
            raise AuthorityDenied("root-selected.currentness", "memory lifecycle authorization expired")
        self._verify_root_controller_identity(controller_proof, effect)
        if effect.action == "start":
            with self._lock:
                if (profile.profile_id in self._starting
                        or any(item.profile.profile_id == profile.profile_id for item in self._handles.values())):
                    raise AuthorityDenied("process.generation", "selected memory service is already active")
                self._starting.add(profile.profile_id)
            parent_pidfd = None
            launched_process_id = None
            try:
                parent_pidfd = os.pidfd_open(os.getpid(), 0)
                if (_pidfd_exited(parent_pidfd) or cancelled() or not effect.is_current()
                        or not controller_proof.is_current()):
                    raise AuthorityDenied("root-selected.currentness", "memory start admission became stale")
                guard = lambda: (memory_admission.is_current(now=self.monotonic())
                                 and controller_proof.is_current()
                                 and self.monotonic() < memory_admission.original_deadline)
                remaining = min(float(timeout), float(memory_admission.original_deadline) - self.monotonic())
                if remaining <= 0:
                    raise AuthorityDenied("root-selected.deadline", "memory start grant expired")
                response = self.start_selected_operation(
                    profile, None, None, payload, timeout=remaining,
                    peer_pid=None, peer_pidfd=None, cancelled=cancelled,
                    _start_guard=guard, _root_selected_effect=effect,
                    _root_selected_lifecycle_deadline=memory_admission.original_deadline,
                    _daemon_liveness_pidfd=parent_pidfd,
                )
                body = response.get("body") if isinstance(response, Mapping) else None
                decoded = json.loads(body.decode("ascii")) if isinstance(body, bytes) else None
                process_id = decoded.get("process_id") if isinstance(decoded, dict) else None
                if (not isinstance(process_id, str) or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                        or decoded.get("generation") != profile.generation):
                    raise AuthorityDenied("root-selected.launch", "memory service did not return an admitted process")
                launched_process_id = process_id
                lease = self.resolve_active_process_handle(profile.profile_id, profile.generation)
                if lease is None:
                    raise AuthorityDenied("root-selected.identity", "selected memory service is no longer live")
                try:
                    digest = self._selected_service_identity_digest(lease)
                    receipt = RootSelectedServiceProcessReceipt(
                        1, uuid.uuid4().hex, lease.process_id, effect.role, "start",
                        effect.enrollment_id, effect.profile_id, effect.generation,
                        effect.selected_principal_id, effect.selected_namespace_identity,
                        effect.selected_subject_uid, effect.selected_subject_gid,
                        effect.operation_id, effect.target, effect.service_generation_digest,
                        digest, self.monotonic(), lease.expires_monotonic,
                    )
                    with self._lock:
                        handle = self._handles.get(lease.process_id)
                        if (handle is None or handle.stopped or handle.profile is not profile
                                or handle.profile.generation != effect.generation):
                            raise AuthorityDenied("root-selected.identity", "memory service process custody changed")
                        self._root_selected_process_receipts[receipt.receipt_handle] = (receipt, handle)
                    return receipt
                finally:
                    lease.close()
            except BaseException:
                if launched_process_id is not None:
                    with self._lock:
                        failed = self._handles.get(launched_process_id)
                    if failed is not None and not failed.stopped:
                        proof = self._stop(failed, timeout=5.0)
                        if not proof.cleanup_verified:
                            raise AuthorityDenied("process.cleanup_ambiguous", "failed memory start cleanup is unproven")
                raise
            finally:
                if parent_pidfd is not None:
                    os.close(parent_pidfd)
                effect.close()
                with self._lock:
                    self._starting.discard(profile.profile_id)

        process_id = request.get("process_id")
        with self._lock:
            candidates = [receipt for receipt, _handle in self._root_selected_process_receipts.values()
                          if receipt.process_id == process_id and receipt.role == effect.role
                          and receipt.profile_id == profile.profile_id
                          and receipt.generation == effect.generation and receipt.action == "start"]
        if len(candidates) != 1:
            raise AuthorityDenied("root-selected.process", "memory action lacks one exact retained start receipt")
        process_receipt = candidates[0]
        if (process_receipt.enrollment_id != memory_admission.service_enrollment_id
                or process_receipt.generation != memory_admission.generation
                or process_receipt.profile_id != memory_admission.profile_id
                or process_receipt.selected_principal_id != memory_admission.principal_id
                or process_receipt.selected_namespace_identity != memory_admission.namespace_identity
                or process_receipt.service_generation_digest != memory_admission.service_generation_digest
                or process_receipt.selected_subject_uid != memory_admission.subject_uid
                or process_receipt.selected_subject_gid != memory_admission.subject_gid):
            raise AuthorityDenied("root-selected.process", "memory process receipt differs from its retained admission")
        lease = self.resolve_selected_service_process(process_receipt)
        if lease is None:
            raise AuthorityDenied("root-selected.identity", "retained memory service process is no longer current")
        try:
            if (cancelled() or not memory_admission.is_current(now=self.monotonic())
                    or not effect.is_current() or not controller_proof.is_current()):
                raise AuthorityDenied("root-selected.currentness", "memory control admission became stale")
            with self._lock:
                retained = self._root_selected_process_receipts.get(process_receipt.receipt_handle)
                handle = retained[1] if retained is not None and retained[0] is process_receipt else None
            if (handle is None or handle.stopped or handle.profile is not profile
                    or handle.process_id != process_receipt.process_id
                    or handle.profile.generation != memory_admission.generation
                    or self.monotonic() >= min(memory_admission.original_deadline, handle.expires)
                    or _pidfd_exited(handle.child_pidfd) or cancelled()):
                raise AuthorityDenied("root-selected.process", "memory lifecycle process is stale or outside its admission")
            if effect.action == "stop":
                proof = self._stop(handle, timeout=min(float(timeout), 5.0))
                if not proof.cleanup_verified:
                    raise AuthorityDenied("process.cleanup_ambiguous", "memory service stop cleanup is unproven")
                with self._lock:
                    for handle, (receipt, _owned) in tuple(self._root_selected_process_receipts.items()):
                        if receipt is process_receipt:
                            self._root_selected_process_receipts.pop(handle, None)
                return _response(200, {"schema": 1, "process_id": process_receipt.process_id,
                    "generation": process_receipt.generation, "operation": "process.stop",
                    "state": "stopped", "result": {"closed": True, "reap_state": "reaped"}})
            exit_code = handle.launcher.poll()
            if exit_code is not None and type(exit_code) is not int:
                raise AuthorityDenied("root-selected.status", "memory service exit status is malformed")
            state = "running" if exit_code is None else "exited"
            status = RootSelectedServiceStatusReceipt(
                1, uuid.uuid4().hex, process_receipt, state, exit_code, self.monotonic(),
                process_receipt.process_identity_digest, effect.service_generation_digest,
            )
            with self._lock:
                self._root_selected_status_receipts[status.receipt_handle] = (
                    status, process_receipt, min(effect.expires_monotonic, lease.expires_monotonic),
                )
            return status
        finally:
            lease.close()
            effect.close()

    def _verify_root_controller_identity(self, proof: Any, effect: Any) -> None:
        """Compare the authority-retained setup actor with live kernel identity."""
        try:
            pid = int(proof.pid)
            pidfd = int(proof.pidfd)
            if (pid <= 0 or pidfd < 0 or self._pidfd_target(pidfd) != pid
                    or _pidfd_exited(pidfd) or not proof.is_current()
                    or proof.proof_handle != effect.controller_proof_handle
                    or (effect.admission_kind not in {"memory", "health"}
                        and proof.startup_authorization_handle != effect.admission_handle)
                    or proof.proof_sha256 != effect.controller_proof_sha256):
                raise ValueError("controller lease stale")
            ticks, cgroup, _device, _inode = _pid_identity(pid)
            namespaces = tuple(os.stat(f"/proc/{pid}/ns/{name}").st_ino for name in ("mnt", "net"))
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            uids = next(line for line in status if line.startswith("Uid:")).split()[1:]
            if (ticks != proof.start_ticks or cgroup != proof.cgroup_identity
                    or namespaces != (proof.mount_namespace_inode, proof.network_namespace_inode)
                    or proof.uid != 0 or len(uids) != 4 or any(int(uid) != 0 for uid in uids)
                    or self._pidfd_target(pidfd) != pid or _pidfd_exited(pidfd)
                    or not proof.is_current()):
                raise ValueError("controller identity changed")
        except (OSError, ValueError, StopIteration, TypeError, AttributeError):
            raise AuthorityDenied("root-selected.controller", "root controller process identity is stale") from None

    @staticmethod
    def _selected_service_identity_digest(lease: ManagedProcessIdentityLease) -> str:
        body = {
            "process_id": lease.process_id, "profile_id": lease.profile_id,
            "generation": lease.generation, "uid": lease.uid, "gid": lease.gid,
            "pid": lease.pid, "start_ticks": lease.start_ticks,
            "executable_device": lease.executable_device,
            "executable_inode": lease.executable_inode,
            "executable_sha256": lease.executable_sha256,
            "cgroup_identity": lease.cgroup_identity,
            "mount_namespace_inode": lease.mount_namespace_inode,
            "network_namespace_inode": lease.network_namespace_inode,
        }
        return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=True).encode("ascii")).hexdigest()

    def resolve_selected_service_process(
            self, receipt: RootSelectedServiceProcessReceipt,
    ) -> ManagedProcessIdentityLease | None:
        """Re-resolve the exact root-retained selected start receipt to a PIDFD lease."""
        if type(receipt) is not RootSelectedServiceProcessReceipt:
            return None
        with self._lock:
            entry = self._root_selected_process_receipts.get(receipt.receipt_handle)
            if (entry is None or entry[0] is not receipt
                    or self.profiles.get(receipt.profile_id) is not entry[1].registered_profile
                    or entry[1].process_id != receipt.process_id
                    or entry[1].profile.generation != receipt.generation
                    or entry[1].stopped or entry[1].expires <= self.monotonic()):
                return None
        lease = self.resolve_active_process_handle(receipt.profile_id, receipt.generation)
        if lease is None:
            return None
        if (lease.process_id != receipt.process_id
                or lease.uid != receipt.selected_subject_uid
                or lease.gid != receipt.selected_subject_gid
                or self._selected_service_identity_digest(lease) != receipt.process_identity_digest
                or receipt.expires_monotonic <= self.monotonic()):
            lease.close()
            return None
        return lease

    def start_selected_task(self, profile: ManagedProfileCustody, context: HostContext,
                            authorization: EffectAuthorization, selection_payload: bytes, **kwargs: Any
                            ) -> ManagedTaskHandle:
        """Compatibility entry for already-admitted internal task callers.

        Root resource tasks use ``start_selected_resource_task`` and enter the
        shared custody core directly with the sealed resource proof.
        """
        return self._start_selected_task_core(
            profile, context, authorization, selection_payload, **kwargs)

    def _start_selected_task_core(self, profile: ManagedProfileCustody, context: Any,
                            authorization: EffectAuthorization, selection_payload: bytes, *,
                            task_admission: RootAdmittedTask,
                            admission_handle: Any, node_id: str, admitted_source: Any,
                            exact_stdin: bytes,
                            expected_stdin_sha256: str, peer_pid: int | None,
                            peer_pidfd: int | None, timeout: float,
                            cancelled: Callable[[], bool],
                            _verified_resource_start: Any | None = None,
                            initial_input_coordinator: Any | None = None,
                            daemon_liveness_pidfd: int | None = None) -> ManagedTaskHandle:
        """Start one admitted task and write/EOF its prompt before returning.

        This is an internal root call, not a worker RPC. The resource ledger
        must mint ``RootAdmittedTask`` only after consuming the one-use child
        admission. The request carries only a selected recipe id; executable,
        argv, environment and roots are resolved from the protected profile.
        """
        task_handle = task_admission
        if (not isinstance(task_handle, RootAdmittedTask)
                or not isinstance(exact_stdin, bytes) or len(exact_stdin) > 262144
                or not isinstance(expected_stdin_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_stdin_sha256)
                or hashlib.sha256(exact_stdin).hexdigest() != expected_stdin_sha256
                or task_handle.stdin_sha256 != expected_stdin_sha256
                or task_handle.stdin_size_bytes != len(exact_stdin)
                or not isinstance(task_handle.task_payload_bytes, bytes)
                or len(task_handle.task_payload_bytes) > 262144
                or hashlib.sha256(task_handle.task_payload_bytes).hexdigest()
                   != task_handle.task_payload_sha256
                or (_verified_resource_start is None
                    and not self._task_admission_is_current(task_handle, selection_payload))):
            raise AuthorityDenied("resource.task_admission", "root task admission or prompt digest is invalid")
        if (profile.generation != task_handle.process_generation
                or profile.enrollment_id != task_handle.process_enrollment_id
                or self.profiles.get(profile.profile_id) != profile
                or not isinstance(profile.operation_recipes, Mapping)
                or task_handle.operation_id not in profile.operation_recipes
                or task_handle.deadline_monotonic <= self.monotonic()
                or task_handle.operation_id != "hermes-resource-profile-task-v1"
                or authorization.operation != "process.start"
                or authorization.target != process_start_target(profile)
                or authorization.capability not in {"hermes-profile-invoke", "hermes-resource-task-invoke"}
                or ( _verified_resource_start is None and (
                    context.profile_id != profile.profile_id
                    or context.enrollment_id != profile.enrollment_id
                    or context.generation != profile.generation
                    or context.operation != "process.start"
                    or authorization.profile_id != profile.profile_id
                    or authorization.enrollment_id != profile.enrollment_id
                    or authorization.generation != profile.generation
                    or authorization.request_digest != canonical_digest(selection_payload)
                    or context.final_payload_digest != authorization.request_digest
                    or authorization.final_payload_digest != authorization.request_digest
                    or context.principal_id != authorization.principal_id
                    or context.namespace_id != authorization.namespace_id
                    or context.trace_id != authorization.trace_id
                    or context.intent_id != authorization.intent_id
                    or context.purpose != authorization.purpose
                    or context.sensitivity != authorization.sensitivity
                    or context.lineage_hash != authorization.lineage_hash
                    or context.policy_revision != authorization.policy_revision
                    or context.uid != authorization.uid
                ))
                or (_verified_resource_start is None and (
                    peer_pid is None or peer_pid <= 0 or peer_pidfd is None or peer_pidfd < 0
                    or _pidfd_exited(peer_pidfd) or self._pidfd_target(peer_pidfd) != peer_pid))
                or (_verified_resource_start is not None and (
                    peer_pid is not None or peer_pidfd is not None
                    or daemon_liveness_pidfd is None or daemon_liveness_pidfd < 0
                    or _pidfd_exited(daemon_liveness_pidfd)
                    or self._pidfd_target(daemon_liveness_pidfd) != os.getpid()))
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600):
            raise AuthorityDenied("resource.task_binding", "selected task, grant, profile or parent is stale")
        if _verified_resource_start is not None:
            from hermes_installer.authority.resource_task_authority import VerifiedRootResourceTaskStart
            service = getattr(getattr(_verified_resource_start, "_issuer", None), "service", None)
            verify = getattr(service, "verify_consumed_resource_task_start", None)
            if (type(_verified_resource_start) is not VerifiedRootResourceTaskStart
                    or _verified_resource_start.selected_profile is not profile
                    or not callable(verify)
                    or verify(_verified_resource_start, selection_payload,
                              task_admission=task_handle, selected_profile=profile) is not True
                    or _verified_resource_start.authorization.expires_monotonic
                       != authorization.expires_monotonic
                    or _verified_resource_start.context.selected_principal_id != context.principal_id
                    or _verified_resource_start.context.selected_namespace_identity != context.namespace_id
                    or _verified_resource_start.context.selected_subject_uid != profile.owner_uid
                    or _verified_resource_start.context.selected_subject_gid != profile.owner_gid):
                raise AuthorityDenied("resource.task_start_proof", "consumed root resource proof is invalid")
        coordinator = (self.task_input_coordinator if initial_input_coordinator is None
                       else initial_input_coordinator)
        if coordinator is not self.task_input_coordinator:
            raise AuthorityDenied("resource.task_input", "initial-input coordinator is not the root runtime instance")
        if coordinator is None:
            raise AuthorityDenied("resource.task_input", "root pre-stdin input coordinator is unavailable")
        try:
            if len(task_handle.task_payload_bytes) > 262144:
                raise ValueError("task body exceeds its bound")
            task_request = json.loads(task_handle.task_payload_bytes.decode("utf-8"))
            from hermes_installer.registry.resource_jobs import _canonical as canonical_task_json
            if canonical_task_json(task_request) != task_handle.task_payload_bytes:
                raise ValueError("task body is not canonical JSON")
            prompt_value = task_request.get("prompt")
            if (set(task_request) != {"prompt"} or not isinstance(prompt_value, str) or not prompt_value
                    or prompt_value.encode("utf-8") != exact_stdin):
                raise ValueError("task body does not resolve to the exact stdin bytes")
        except (AuthorityDenied, UnicodeError, ValueError, TypeError):
            raise AuthorityDenied("resource.task_payload", "admitted task prompt is malformed or mismatched") from None
        selection = self._json(selection_payload)
        if (set(selection) != {"schema", "enrollment_id", "generation", "operation_id", "parameters",
                               "admission_handle", "node_id", "task_payload_sha256",
                               "stdin_sha256", "stdin_size_bytes"}
                or selection.get("schema") != 1
                or selection.get("enrollment_id") != profile.enrollment_id
                or selection.get("generation") != profile.generation
                or selection.get("operation_id") != task_handle.operation_id
                or selection.get("parameters") != {}
                or selection.get("node_id") != task_handle.node_id
                or selection.get("task_payload_sha256") != task_handle.task_payload_sha256
                or selection.get("stdin_sha256") != task_handle.stdin_sha256
                or selection.get("stdin_size_bytes") != task_handle.stdin_size_bytes):
            raise AuthorityDenied("resource.task_selection", "task recipe selection is not the admitted fixed operation")
        from hermes_installer.registry.resource_jobs import (
            RootResourceJobAdmissionHandle, RootAdmittedTaskSource, RootTaskInitialInputReceipt,
        )
        if (type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(admitted_source) is not RootAdmittedTaskSource
                or node_id != task_handle.node_id
                or admission_handle.handle_id != selection.get("admission_handle")
                or admission_handle.child_admission_id != task_handle.admission_id
                or admission_handle.node_id != node_id
                or admission_handle.process_enrollment_id != profile.enrollment_id
                or admission_handle.process_generation != profile.generation
                or admission_handle.task_payload_sha256 != task_handle.task_payload_sha256
                or admission_handle.parent_closure_digest != task_handle.parent_closure_digest):
            raise AuthorityDenied("resource.task_admission", "root task admission source binding is invalid")
        recipe = profile.operation_recipes[task_handle.operation_id]
        if not isinstance(recipe, Mapping) or recipe.get("stdin_mode") != "bounded-typed-bytes":
            raise AuthorityDenied("resource.task_stdin", "selected recipe does not admit one bounded stdin frame")
        grant_expiry = (float(_verified_resource_start.authorization.expires_monotonic)
                        if _verified_resource_start is not None
                        else float(authorization.monotonic_expires_at))
        launch_deadline = min(float(task_handle.deadline_monotonic),
                              grant_expiry, self.monotonic() + timeout)
        if launch_deadline <= self.monotonic() or cancelled():
            raise AuthorityDenied("resource.task_expired", "task expired before process admission")
        response = self._start(profile, context, authorization, selection_payload,
                               launch_deadline - self.monotonic(),
                               peer_pid, peer_pidfd, cancelled,
                               task_admission=task_handle,
                               daemon_liveness_pidfd=daemon_liveness_pidfd,
                               root_resource_start=_verified_resource_start,
                               start_guard=lambda: bool(self._task_admission_is_current(task_handle, selection_payload)
                                   and self.monotonic() < task_handle.deadline_monotonic
                                   and (_verified_resource_start is None or self._root_resource_start_current(
                                       _verified_resource_start, task_handle, selection_payload, profile))
                                   and not cancelled()))
        try:
            body = json.loads(response["body"].decode("ascii"))
            process_id = body["process_id"]
            with self._lock:
                handle = self._handles.get(process_id)
            if (handle is None or handle.profile.profile_id != profile.profile_id
                    or handle.profile.generation != profile.generation or handle.stopped):
                raise AuthorityDenied("resource.task_start", "selected process did not remain registered")
            handle.task_owned = True
            task_deadline = min(float(task_handle.deadline_monotonic),
                                self.monotonic() + timeout, handle.expires)
            state = _ManagedTaskState(handle, task_handle, task_deadline,
                                      min(task_deadline, grant_expiry),
                                      cancelled, selection_payload,
                                      selection["admission_handle"])
            opaque_id = uuid.uuid4().hex
            with self._lock:
                self._task_handles[opaque_id] = state
            root_handle = ManagedTaskHandle(opaque_id, profile.generation, handle.process_id)
            state.root_handle = root_handle
            receipt = coordinator.prepare_initial_input(
                task_admission=task_handle, admission_handle=admission_handle,
                node_id=node_id, source=admitted_source, managed_task_handle=root_handle,
                exact_stdin=exact_stdin,
                timeout=max(0.001, min(task_deadline - self.monotonic(), timeout)),
                cancelled=cancelled,
            )
            if type(receipt) is not RootTaskInitialInputReceipt:
                raise AuthorityDenied("resource.task_input", "coordinator returned an invalid input receipt")
            resolved_receipt = coordinator.resolve_initial_input_receipt(
                receipt.receipt_handle, task_handle=root_handle,
                stdin_sha256=expected_stdin_sha256,
                stdin_size_bytes=len(exact_stdin),
            )
            if (resolved_receipt is not receipt
                    or receipt.task_handle != root_handle.handle_id
                    or receipt.admission_id != task_handle.admission_id
                    or receipt.node_id != node_id
                    or receipt.process_id != handle.process_id
                    or receipt.process_generation != profile.generation
                    or receipt.stdin_sha256 != expected_stdin_sha256
                    or receipt.stdin_size_bytes != len(exact_stdin)
                    or receipt.parent_closure_digest != task_handle.parent_closure_digest
                    or receipt.resource_generation != task_handle.resource_generation
                    or receipt.native_loader_ready_event_id != handle.native_loader_ready_event_id
                    or receipt.issued_monotonic > self.monotonic()
                    or receipt.expires_monotonic <= self.monotonic()
                    or cancelled()
                    or not self._task_admission_is_current(task_handle, selection_payload)):
                raise AuthorityDenied("resource.task_input", "initial input receipt does not bind this live task")
            state.initial_input_receipt_handle = receipt.receipt_handle
            state.initial_input_expires_monotonic = receipt.expires_monotonic
            state.service_generation_digest = receipt.service_generation_digest
            consumed_receipt = coordinator.consume_initial_input_receipt(
                receipt.receipt_handle, task_handle=root_handle,
                stdin_sha256=expected_stdin_sha256,
                stdin_size_bytes=len(exact_stdin),
            )
            if (consumed_receipt is not receipt or cancelled()
                    or self.monotonic() >= state.deadline
                    or not self._task_admission_is_current(task_handle, selection_payload)):
                raise AuthorityDenied("resource.task_input", "initial input receipt expired before stdin")
            self.write_initial_task_stdin_and_close(root_handle, exact_stdin)
            if (not self._task_admission_is_current(task_handle, selection_payload)
                    or self.monotonic() >= state.deadline or cancelled()):
                raise AuthorityDenied("resource.task_expired", "task admission expired while receiving stdin")
            return root_handle
        except BaseException as start_error:
            # The coordinator owns any captured source/input observation. If
            # custody rejects it before the one-time write completes, revoke
            # that exact receipt before stopping the process so no pre-input
            # observer lease survives an aborted launch.
            if "receipt" in locals() and "root_handle" in locals():
                revoke = getattr(coordinator, "revoke_initial_input_receipt", None)
                if callable(revoke):
                    try:
                        revoke(receipt.receipt_handle, task_handle=root_handle)
                    except Exception:
                        pass
            if "opaque_id" in locals():
                with self._lock:
                    self._task_handles.pop(opaque_id, None)
            if "handle" in locals() and handle is not None:
                try:
                    proof = self._stop(handle, timeout=5.0)
                except Exception:
                    raise AuthorityDenied(
                        "resource.task_cleanup_ambiguous",
                        "failed task start could not prove owned-process cleanup",
                    ) from start_error
                if not (proof.cleanup_verified and proof.cgroup_empty
                        and proof.main_pidfd_gone and proof.launcher_reaped):
                    raise AuthorityDenied(
                        "resource.task_cleanup_ambiguous",
                        "failed task start could not prove owned-process cleanup",
                    ) from start_error
            raise

    def start_selected_resource_task(
            self, selected_profile: ManagedProfileCustody, verified_start: Any,
            selection_payload: bytes, *, task_admission: RootAdmittedTask,
            admission_handle: Any, node_id: str, admitted_source: Any,
            exact_stdin: bytes, expected_stdin_sha256: str, timeout: float,
            cancelled: Callable[[], bool], initial_input_coordinator: Any,
    ) -> ManagedTaskHandle:
        """Start a task under the distinct consumed root-resource effect proof.

        The controller is never passed as the selected child peer. The root
        daemon PIDFD retains the unit; the sealed proof and jobs registry keep
        the external controller/source/admission current through EOF.
        """
        from hermes_installer.authority.resource_task_authority import VerifiedRootResourceTaskStart
        from hermes_installer.registry.resource_jobs import RootResourceJobAdmissionHandle, RootAdmittedTaskSource
        if (type(verified_start) is not VerifiedRootResourceTaskStart
                or type(selected_profile) is not ManagedProfileCustody
                or self.profiles.get(selected_profile.profile_id) is not selected_profile
                or type(admission_handle) is not RootResourceJobAdmissionHandle
                or type(admitted_source) is not RootAdmittedTaskSource
                or initial_input_coordinator is not self.task_input_coordinator
                or verified_start.selected_profile is not selected_profile
                or not isinstance(selection_payload, bytes)
                or verified_start.authorization.request_sha256 != hashlib.sha256(selection_payload).hexdigest()
                or verified_start.context.selected_profile_id != selected_profile.profile_id
                or verified_start.context.selected_generation != selected_profile.generation
                or verified_start.context.selected_subject_uid != selected_profile.owner_uid
                or verified_start.context.selected_subject_gid != selected_profile.owner_gid
                or verified_start.context.admission_handle != admission_handle.handle_id
                or verified_start.context.node_id != node_id
                or verified_start.context.stdin_sha256 != expected_stdin_sha256
                or verified_start.context.stdin_size_bytes != len(exact_stdin)):
            raise AuthorityDenied("resource.task_start_proof", "selected resource task binding is malformed")
        service = getattr(verified_start._issuer, "service", None)
        verify = getattr(service, "verify_consumed_resource_task_start", None)
        if (not callable(verify)
                or verify(verified_start, selection_payload, task_admission=task_admission,
                          selected_profile=selected_profile) is not True):
            raise AuthorityDenied("resource.task_start_proof", "consumed resource task proof is stale")
        if (cancelled() or self.monotonic() >= verified_start.authorization.expires_monotonic
                or self.monotonic() >= task_admission.deadline_monotonic):
            raise AuthorityDenied("resource.task_expired", "resource task proof expired before launch")
        daemon_pid = os.getpid()
        try:
            daemon_liveness_pidfd = os.pidfd_open(daemon_pid, 0)
        except (AttributeError, OSError):
            raise AuthorityDenied("resource.task_parent", "custody daemon lifetime PIDFD is unavailable") from None
        try:
            return self._start_selected_task_core(
                selected_profile, verified_start.context, verified_start.authorization,
                selection_payload,
                task_admission=task_admission, admission_handle=admission_handle,
                node_id=node_id, admitted_source=admitted_source, exact_stdin=exact_stdin,
                expected_stdin_sha256=expected_stdin_sha256, peer_pid=None,
                peer_pidfd=None, timeout=timeout, cancelled=cancelled,
                _verified_resource_start=verified_start,
                initial_input_coordinator=initial_input_coordinator,
                daemon_liveness_pidfd=daemon_liveness_pidfd,
            )
        finally:
            os.close(daemon_liveness_pidfd)

    def start_selected_application(self, profile_id: str, verified_start: Any,
                                   canonical_selection_payload: bytes, *,
                                   selected_step_handle: str, timeout: float,
                                   cancelled: Callable[[], bool]) -> ManagedApplicationHandle:
        """Start one selected app recipe through the existing PIDFD/systemd core.

        This root-only path accepts a consumed app-specific one-use grant and
        an opaque journal step. It never accepts argv, paths, environment or a
        caller-created process context.
        """
        from hermes_installer.authority.application_workload_execution import (
            RootApplicationSelectedStep, VerifiedRootApplicationStart,
        )
        if (type(verified_start) is not VerifiedRootApplicationStart
                or not isinstance(cancelled, Callable)
                or not isinstance(canonical_selection_payload, bytes)
                or not isinstance(selected_step_handle, str)
                or verified_start.selected_step.handle != selected_step_handle
                or verified_start.selected_profile.profile_id != profile_id
                or self.profiles.get(profile_id) is not verified_start.selected_profile
                or type(verified_start.selected_step) is not RootApplicationSelectedStep
                or hashlib.sha256(canonical_selection_payload).hexdigest()
                   != verified_start.authorization.request_sha256):
            raise AuthorityDenied("application.start_proof", "selected application start proof is malformed")
        service = getattr(getattr(verified_start, "_issuer", None), "service", None)
        verify = getattr(service, "verify_consumed_application_start", None)
        if (not callable(verify)
                or verify(verified_start, canonical_selection_payload,
                          selected_step_handle=selected_step_handle) is not True):
            raise AuthorityDenied("application.start_proof", "selected application start proof is stale")
        step = verified_start.selected_step
        profile = verified_start.selected_profile
        try:
            selection = self._json(canonical_selection_payload)
        except AuthorityDenied:
            raise
        expected = {"schema", "enrollment_id", "generation", "operation_id", "parameters",
                    "application_admission_handle", "application_step_id"}
        if (set(selection) != expected or selection.get("schema") != 1
                or selection.get("enrollment_id") != profile.enrollment_id
                or selection.get("generation") != profile.generation
                or selection.get("operation_id") != step.operation_id
                or not isinstance(selection.get("parameters"), dict)
                or selection.get("application_admission_handle") != step.admission_handle
                or selection.get("application_step_id") != step.step_id):
            raise AuthorityDenied("application.selection", "selection does not match the root-owned app recipe")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or not 0 < timeout <= 600
                or verified_start.authorization.expires_monotonic <= self.monotonic()
                or step.deadline_monotonic <= self.monotonic() or cancelled()):
            raise AuthorityDenied("application.expired", "selected application start is expired or cancelled")
        daemon_pid = os.getpid()
        try:
            daemon_fd = os.pidfd_open(daemon_pid, 0)
        except (AttributeError, OSError):
            raise AuthorityDenied("application.parent", "custody daemon PIDFD is unavailable") from None
        try:
            response = self._start(
                profile, verified_start.context, verified_start.authorization,
                canonical_selection_payload, min(float(timeout),
                    verified_start.authorization.expires_monotonic - self.monotonic()),
                None, None, cancelled, daemon_liveness_pidfd=daemon_fd,
                root_application_start=verified_start,
                start_guard=lambda: bool(verify(
                    verified_start, canonical_selection_payload,
                    selected_step_handle=selected_step_handle) is True and not cancelled()),
            )
            body = json.loads(response["body"].decode("ascii"))
            process_id = body.get("process_id")
            with self._lock:
                handle = self._handles.get(process_id)
                if handle is None or handle.profile is not profile:
                    raise AuthorityDenied("application.handle", "custody returned no retained application process")
                opaque = secrets.token_urlsafe(32)
                app_handle = ManagedApplicationHandle(opaque, process_id, profile.generation)
                deadline = min(handle.expires, step.deadline_monotonic,
                               self.monotonic() + float(timeout))
                self._application_handles[opaque] = _ManagedApplicationState(
                    handle, verified_start, step, canonical_selection_payload,
                    deadline, cancelled,
                )
                return app_handle
        finally:
            os.close(daemon_fd)

    def wait_owned_application_terminal(self, application_handle: ManagedApplicationHandle, *,
                                        timeout: float, cancelled: Callable[[], bool]
                                        ) -> RootApplicationTerminalReceipt:
        """Wait, drain bounded output, reap and retain the actual process terminal."""
        if type(application_handle) is not ManagedApplicationHandle:
            raise AuthorityDenied("application.handle", "application handle is malformed")
        with self._lock:
            state = self._application_handles.get(application_handle.handle_id)
        if (state is None or state.handle.process_id != application_handle.process_id
                or state.handle.profile.generation != application_handle.profile_generation):
            raise AuthorityDenied("application.handle", "application handle is stale")
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0 or not callable(cancelled)):
            raise AuthorityDenied("application.deadline", "application wait bounds are invalid")
        state.deadline = min(state.deadline, self.monotonic() + float(timeout))
        handle, proof, step = state.handle, state.verified_start, state.step
        issuer = proof._issuer
        was_cancelled = False
        timed_out = False
        with state.lock:
            if state.consumed:
                raise AuthorityDenied("application.handle", "application terminal was already consumed")
            while True:
                current = issuer._current(step)
                if (cancelled() or state.cancelled() or not current
                        or _pidfd_exited(handle.parent_pidfd)):
                    was_cancelled = True
                    break
                if self.monotonic() >= state.deadline:
                    timed_out = True
                    break
                self._drain_task_streams(state, [stream.fileno() for stream, eof in (
                    (handle.launcher.stdout, state.stdout_eof),
                    (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof], timeout=.05)
                if state.output_overflow:
                    break
                if handle.launcher.poll() is not None and state.stdout_eof and state.stderr_eof:
                    break
            for _ in range(16):
                fds = [stream.fileno() for stream, eof in (
                    (handle.launcher.stdout, state.stdout_eof),
                    (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof]
                if not fds:
                    break
                self._drain_task_streams(state, fds, timeout=.01)
                if handle.launcher.poll() is None:
                    break
            cleanup = self._stop(handle, timeout=5.0)
            exit_code = handle.launcher.returncode
            reaped = bool(cleanup.cleanup_verified and cleanup.cgroup_empty
                          and cleanup.main_pidfd_gone and cleanup.launcher_reaped
                          and not self._pids(handle.cgroup))
            if not reaped:
                raise AuthorityDenied("application.cleanup_ambiguous", "application descendants were not reaped")
            output_id = secrets.token_urlsafe(32)
            now = self.monotonic()
            state_name = ("cancelled" if was_cancelled else "failed" if timed_out or state.output_overflow
                          or exit_code != 0 or not (state.stdout_eof and state.stderr_eof) else "completed")
            fields = dict(
                schema=1, receipt_handle=secrets.token_urlsafe(32),
                application_handle=application_handle.handle_id,
                admission_handle=step.admission_handle, application_id=step.application_id,
                workload_id=step.workload_id, step_id=step.step_id, sequence=step.sequence,
                profile_id=handle.profile.profile_id, profile_generation=handle.profile.generation,
                service_generation_digest=step.service_generation_digest,
                operation_id=step.operation_id, request_sha256=step.request_sha256,
                source_receipt_handle=step.source_receipt_handle,
                runtime_receipt_handle=step.runtime_receipt_handle,
                process_id=handle.process_id, process_generation=handle.profile.generation,
                process_start_ticks=handle.start_ticks, executable_sha256=handle.profile.artifact_sha256,
                cgroup_id=handle.cgroup,
                namespace_digest=hashlib.sha256(handle.kernel_namespace_id.encode("ascii")).hexdigest(),
                exit_code=exit_code, stdin_eof=True,
                stdout_sha256=hashlib.sha256(state.stdout).hexdigest(), stdout_size_bytes=len(state.stdout),
                stderr_sha256=hashlib.sha256(state.stderr).hexdigest(), stderr_size_bytes=len(state.stderr),
                output_observation_handle=output_id, reaped=True, cancelled=was_cancelled,
                timed_out=timed_out, state=state_name, issued_monotonic=now,
                expires_monotonic=min(step.deadline_monotonic, now + 30.0), signature="pending")
            terminal = RootApplicationTerminalReceipt(**fields)
            terminal = RootApplicationTerminalReceipt(**{**terminal.claims(), "signature":
                issuer.service._sign_root_selected("root-application-terminal-v1", terminal.claims())})
            with self._lock:
                if len(self._application_terminal_receipts) >= 4096:
                    raise AuthorityDenied("application.receipts", "application terminal store is full")
                self._application_terminal_receipts[terminal.receipt_handle] = (
                    application_handle.handle_id, terminal, now + 30.0)
                self._application_outputs[output_id] = (bytes(state.stdout), bytes(state.stderr), now + 30.0)
                self._application_handles.pop(application_handle.handle_id, None)
                state.consumed = True
            return terminal

    def resolve_application_terminal(self, receipt_handle: str) -> RootApplicationTerminalReceipt:
        if not isinstance(receipt_handle, str):
            raise AuthorityDenied("application.terminal", "terminal handle is malformed")
        with self._lock:
            entry = self._application_terminal_receipts.get(receipt_handle)
            if entry is None:
                raise AuthorityDenied("application.terminal", "terminal receipt is unavailable")
            _handle_id, receipt, expiry = entry
            if expiry <= self.monotonic() or receipt.receipt_handle != receipt_handle:
                self._application_terminal_receipts.pop(receipt_handle, None)
                raise AuthorityDenied("application.terminal", "terminal receipt is stale")
            return receipt

    def resolve_application_output(self, output_handle: str) -> tuple[bytes, bytes]:
        with self._lock:
            entry = self._application_outputs.get(output_handle)
            if entry is None or entry[2] <= self.monotonic():
                self._application_outputs.pop(output_handle, None)
                raise AuthorityDenied("application.output", "bounded application output is unavailable")
            return entry[0], entry[1]

    def _root_resource_start_current(self, proof: Any, task: RootAdmittedTask,
                                     payload: bytes, profile: ManagedProfileCustody) -> bool:
        service = getattr(getattr(proof, "_issuer", None), "service", None)
        verify = getattr(service, "verify_consumed_resource_task_start", None)
        try:
            return bool(callable(verify) and verify(
                proof, payload, task_admission=task, selected_profile=profile) is True)
        except Exception:
            return False

    def _task_admission_is_current(self, admission: RootAdmittedTask,
                                   selection_payload: bytes) -> bool:
        callback = self.task_admission_current
        if callback is None:
            return False
        try:
            return callback(admission, selection_payload) is True
        except Exception:
            return False

    def write_initial_task_stdin_and_close(self, task_handle: ManagedTaskHandle,
                                           exact_bytes: bytes) -> int:
        """Write one complete bounded frame and close stdin within the start effect."""
        state = self._resolve_task_handle(task_handle)
        handle = state.handle
        if (not isinstance(exact_bytes, bytes) or len(exact_bytes) > 262144
                or hashlib.sha256(exact_bytes).hexdigest() != state.admission.stdin_sha256
                or len(exact_bytes) != state.admission.stdin_size_bytes):
            raise AuthorityDenied("resource.task_stdin", "stdin differs from the consumed admission")
        with state.lock:
            if (state.input_closed or handle.launcher.stdin is None or handle.stopped
                    or state.initial_input_receipt_handle is None
                    or state.initial_input_expires_monotonic is None
                    or state.service_generation_digest is None
                    or state.root_handle is not task_handle):
                raise AuthorityDenied("resource.task_stdin", "task stdin is already closed or unavailable")
            fd = handle.launcher.stdin.fileno()
            offset = 0
            while offset < len(exact_bytes):
                if (state.cancelled() or self.monotonic() >= state.stdin_deadline
                        or self.monotonic() >= state.initial_input_expires_monotonic
                        or _pidfd_exited(handle.parent_pidfd)
                        or _pidfd_exited(handle.child_pidfd)
                        or not self._task_admission_is_current(state.admission, state.selection_payload)):
                    raise AuthorityDenied("resource.task_expired", "task admission expired during stdin delivery")
                writable = []
                reads = [stream.fileno() for stream, eof in (
                    (handle.launcher.stdout, state.stdout_eof),
                    (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof]
                _, writable, _ = select.select(reads, [fd], [], min(.1, max(.001, state.stdin_deadline - self.monotonic())))
                self._drain_task_streams(state, reads, timeout=0)
                if fd in writable:
                    try:
                        count = os.write(fd, exact_bytes[offset:offset + 65536])
                    except BlockingIOError:
                        count = 0
                    except OSError:
                        raise AuthorityDenied("resource.task_stdin", "task closed stdin before receiving its frame") from None
                    if count <= 0:
                        continue
                    offset += count
                if state.output_overflow:
                    raise AuthorityDenied("resource.task_output", "task exceeded its bounded output before stdin EOF")
            # Perform one final nonblocking drain before closing stdin. This
            # keeps output backpressure bounded while making EOF a distinct,
            # observed custody transition.
            pending_reads = [stream.fileno() for stream, eof in (
                (handle.launcher.stdout, state.stdout_eof),
                (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof]
            self._drain_task_streams(state, pending_reads, timeout=0)
            if state.output_overflow:
                raise AuthorityDenied("resource.task_output", "task exceeded its bounded output before stdin EOF")
            handle.launcher.stdin.close()
            state.input_closed = True
            from hermes_installer.registry.resource_jobs import RootTaskStdinWriteReceipt
            issued = self.monotonic()
            receipt = RootTaskStdinWriteReceipt(
                schema=1, receipt_handle=uuid.uuid4().hex,
                task_handle=task_handle.handle_id, process_id=handle.process_id,
                process_generation=state.admission.process_generation,
                initial_input_receipt_handle=state.initial_input_receipt_handle,
                stdin_sha256=state.admission.stdin_sha256,
                stdin_size_bytes=offset, sequence=0,
                write_complete=(offset == len(exact_bytes)), drained=True,
                stdin_closed=handle.launcher.stdin.closed,
                service_generation_digest=state.service_generation_digest,
                issued_monotonic=issued,
                expires_monotonic=min(state.deadline, handle.expires,
                                      state.initial_input_expires_monotonic, issued + 30.0),
            )
            if (not receipt.write_complete or not receipt.stdin_closed
                    or len(exact_bytes) != receipt.stdin_size_bytes):
                raise AuthorityDenied("resource.task_stdin", "stdin write or EOF proof is incomplete")
            with self._lock:
                for receipt_id, (_task_handle, _receipt, expires, _profile_id) in tuple(
                        self._task_stdin_write_receipts.items()):
                    if expires <= issued:
                        self._task_stdin_write_receipts.pop(receipt_id, None)
                if len(self._task_stdin_write_receipts) >= 4096:
                    raise AuthorityDenied("resource.task_receipts", "stdin write receipt registry is full")
                self._task_stdin_write_receipts[receipt.receipt_handle] = (
                    task_handle, receipt, receipt.expires_monotonic, handle.profile.profile_id)
            state.stdin_write_receipt = receipt
            task_handle._stdin_write_receipt[0] = receipt.receipt_handle
            return offset

    def wait_owned_task_terminal(self, task_handle: ManagedTaskHandle, *,
                                 deadline_monotonic: float,
                                 cancelled: Callable[[], bool]) -> RootTaskTerminalReceipt:
        """Wait for one root-owned task and return truthful bounded cleanup proof."""
        state = self._resolve_task_handle(task_handle)
        if not state.input_closed:
            raise AuthorityDenied("resource.task_stdin", "task has not received its one stdin frame and EOF")
        if state.stdin_write_receipt is None:
            raise AuthorityDenied("resource.task_stdin", "task has no root-issued stdin write receipt")
        if (isinstance(deadline_monotonic, bool) or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(deadline_monotonic)):
            raise AuthorityDenied("resource.task_deadline", "task wait deadline is invalid")
        # The root may pass the original task deadline even when the manager
        # imposed a tighter per-operation cap. Intersect them; never extend.
        state.deadline = min(state.deadline, float(deadline_monotonic))
        handle, admission = state.handle, state.admission
        timed_out = False
        was_cancelled = False
        with state.lock:
            if state.consumed:
                raise AuthorityDenied("resource.task_handle", "task terminal handle is already consumed")
            try:
                while True:
                    current = self._task_admission_is_current(admission, state.selection_payload)
                    if (cancelled() or state.cancelled() or _pidfd_exited(handle.parent_pidfd)
                            or not current):
                        was_cancelled = True
                        break
                    if self.monotonic() >= state.deadline:
                        timed_out = True
                        break
                    self._drain_task_streams(state, [stream.fileno() for stream, eof in (
                        (handle.launcher.stdout, state.stdout_eof),
                        (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof], timeout=.05)
                    if state.output_overflow:
                        break
                    if (handle.launcher.poll() is not None and state.stdout_eof and state.stderr_eof):
                        break
                # Drain already buffered bytes after natural exit, without
                # allowing an unbounded child or exceeding the root cap.
                for _ in range(16):
                    fds = [stream.fileno() for stream, eof in (
                        (handle.launcher.stdout, state.stdout_eof),
                        (handle.launcher.stderr, state.stderr_eof)) if stream is not None and not eof]
                    if not fds:
                        break
                    self._drain_task_streams(state, fds, timeout=.01)
                    if handle.launcher.poll() is None:
                        break
                proof = self._stop(handle, timeout=5.0)
                exit_code = handle.launcher.returncode
                clean = bool(proof.cleanup_verified and proof.cgroup_empty
                             and proof.main_pidfd_gone and proof.launcher_reaped
                             and not self._pids(handle.cgroup))
                result = RootTaskTerminalReceipt(
                    task_handle=task_handle.handle_id,
                    terminal_receipt_handle=uuid.uuid4().hex,
                    job_id=admission.job_id,
                    node_id=admission.node_id, admission_id=admission.admission_id,
                    admission_handle_id=state.admission_handle_id,
                    backend_enrollment_id=admission.backend_enrollment_id,
                    operation_id=admission.operation_id,
                    task_body_recipe_id=admission.task_body_recipe_id,
                    task_request_schema_id=admission.task_request_schema_id,
                    resource_generation=admission.resource_generation,
                    profile_id=handle.profile.profile_id, process_generation=admission.process_generation,
                    process_id=handle.process_id, exit_code=exit_code,
                    timed_out=timed_out, cancelled=was_cancelled,
                    started_monotonic=handle.started, finished_monotonic=self.monotonic(),
                    cgroup_identity=handle.cgroup, cgroup_empty=proof.cgroup_empty,
                    main_pidfd_gone=proof.main_pidfd_gone, descendants_gone=proof.cgroup_empty,
                    launcher_reaped=proof.launcher_reaped, cleanup_verified=clean,
                    stdout=bytes(state.stdout), stderr=bytes(state.stderr),
                    stdout_sha256=hashlib.sha256(state.stdout).hexdigest(),
                    stderr_sha256=hashlib.sha256(state.stderr).hexdigest(),
                    output_complete=(not state.output_overflow and state.stdout_eof and state.stderr_eof),
                    schema=1,
                    state=("cancelled" if was_cancelled else
                           "failed" if timed_out or exit_code != 0 or state.output_overflow
                           or not (state.stdout_eof and state.stderr_eof) else "completed"),
                    observed_monotonic=self.monotonic(),
                    stdout_size_bytes=len(state.stdout), stderr_size_bytes=len(state.stderr),
                    parent_closure_digest=admission.parent_closure_digest,
                    native_loader_ready_event_id=handle.native_loader_ready_event_id,
                    stdin_write_receipt_handle=state.stdin_write_receipt.receipt_handle)
                if not clean:
                    raise AuthorityDenied("resource.task_cleanup", "task terminal cleanup was not proven")
                state.consumed = True
                with self._lock:
                    self._task_handles.pop(task_handle.handle_id, None)
                    now = self.monotonic()
                    for receipt_id, (_task_id, _receipt, expires) in tuple(self._task_terminal_receipts.items()):
                        if expires <= now:
                            self._task_terminal_receipts.pop(receipt_id, None)
                    if len(self._task_terminal_receipts) >= 4096:
                        raise AuthorityDenied("resource.task_receipts", "terminal receipt registry is full")
                    self._task_terminal_receipts[result.terminal_receipt_handle] = (
                        task_handle.handle_id, result, now + 30.0)
                return result
            except BaseException:
                raise

    def resolve_task_terminal(self, task_handle_id: str,
                              terminal_receipt_handle: str) -> RootTaskTerminalReceipt:
        """Resolve the exact recent terminal object produced by this manager.

        This root-internal lookup lets the task-native observer join terminal
        facts without reconstructing them or accepting a caller-produced DTO.
        Its consumer owns one-use semantics; the bounded receipt remains
        available only until its short resolver lease or profile generation
        ends.
        """
        if (not isinstance(task_handle_id, str) or not re.fullmatch(r"[0-9a-f]{32}", task_handle_id)
                or not isinstance(terminal_receipt_handle, str)
                or not re.fullmatch(r"[0-9a-f]{32}", terminal_receipt_handle)):
            raise AuthorityDenied("resource.task_receipt", "task terminal receipt selector is malformed")
        with self._lock:
            entry = self._task_terminal_receipts.get(terminal_receipt_handle)
            if entry is None:
                raise AuthorityDenied("resource.task_receipt", "task terminal receipt is unavailable")
            bound_task_id, receipt, expires = entry
            profile = self.profiles.get(receipt.profile_id)
            if (bound_task_id != task_handle_id or expires <= self.monotonic()
                    or profile is None or profile.generation != receipt.process_generation
                    or receipt.task_handle != task_handle_id
                    or receipt.terminal_receipt_handle != terminal_receipt_handle):
                self._task_terminal_receipts.pop(terminal_receipt_handle, None)
                raise AuthorityDenied("resource.task_receipt", "task terminal receipt is stale or mismatched")
            return receipt

    def resolve_task_stdin_write(self, task_handle: ManagedTaskHandle,
                                 receipt_handle: str) -> Any:
        """Return the exact retained successful write/EOF receipt object."""
        from hermes_installer.registry.resource_jobs import RootTaskStdinWriteReceipt
        if (type(task_handle) is not ManagedTaskHandle
                or not isinstance(receipt_handle, str)
                or not re.fullmatch(r"[0-9a-f]{32}", receipt_handle)):
            raise AuthorityDenied("resource.task_stdin_receipt", "stdin write receipt selector is malformed")
        with self._lock:
            entry = self._task_stdin_write_receipts.get(receipt_handle)
            if entry is None:
                raise AuthorityDenied("resource.task_stdin_receipt", "stdin write receipt is unavailable")
            retained_task_handle, receipt, expires, profile_id = entry
            profile = self.profiles.get(profile_id)
            if (retained_task_handle is not task_handle or expires <= self.monotonic()
                    or profile is None or profile.generation != task_handle.generation
                    or type(receipt) is not RootTaskStdinWriteReceipt
                    or receipt.task_handle != task_handle.handle_id
                    or receipt.process_id != task_handle.process_id
                    or receipt.process_generation != task_handle.generation
                    or task_handle.stdin_write_receipt_handle != receipt_handle):
                self._task_stdin_write_receipts.pop(receipt_handle, None)
                raise AuthorityDenied("resource.task_stdin_receipt", "stdin write receipt is stale or mismatched")
            return receipt

    def _resolve_task_handle(self, task_handle: ManagedTaskHandle) -> _ManagedTaskState:
        if not isinstance(task_handle, ManagedTaskHandle):
            raise AuthorityDenied("resource.task_handle", "root task handle has the wrong type")
        with self._lock:
            state = self._task_handles.get(task_handle.handle_id)
        if (state is None or state.consumed or task_handle.generation != state.admission.process_generation
                or state.root_handle is not task_handle
                or state.handle.process_id not in self._handles
                or state.handle.stopped):
            raise AuthorityDenied("resource.task_handle", "root task handle is stale or consumed")
        return state

    def _drain_task_streams(self, state: _ManagedTaskState, fds: list[int], *, timeout: float) -> None:
        if not fds:
            return
        try:
            ready, _, _ = select.select(fds, [], [], max(0.0, timeout))
        except (OSError, ValueError):
            raise AuthorityDenied("resource.task_output", "task output stream became invalid") from None
        for fd in ready:
            stream_name = "stdout" if state.handle.launcher.stdout and fd == state.handle.launcher.stdout.fileno() else "stderr"
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                setattr(state, stream_name + "_eof", True)
                continue
            target = getattr(state, stream_name)
            if len(state.stdout) + len(state.stderr) + len(chunk) > state.handle.output_cap:
                state.output_overflow = True
                remaining = max(0, state.handle.output_cap - len(state.stdout) - len(state.stderr))
                target.extend(chunk[:remaining])
            else:
                target.extend(chunk)

    @staticmethod
    def _validate_operation_parameters(parameters: Mapping[str, Any], schema: Mapping[str, Any]) -> dict[str, Any]:
        fields = schema.get("fields")
        if not isinstance(fields, (tuple, list)) or len(fields) > 128:
            raise AuthorityDenied("process.parameters", "parameter schema fields are invalid")
        definitions = {item.get("name"): item for item in fields if isinstance(item, Mapping)}
        if len(definitions) != len(fields) or set(parameters) - set(definitions):
            raise AuthorityDenied("process.parameters", "operation supplied unknown parameters")
        result: dict[str, Any] = {}
        for name, field in definitions.items():
            if name not in parameters:
                if field["required"]:
                    raise AuthorityDenied("process.parameters", "required operation parameter is missing")
                continue
            value, kind = parameters[name], field["type"]
            if kind == "string":
                if (not isinstance(value, str) or not value or len(value) > field["max_length"]
                        or any(ord(char) < 32 or ord(char) == 127 for char in value)
                        or any(char in value for char in "/\\:") or "://" in value):
                    raise AuthorityDenied("process.parameters", "string parameter is not a bounded scalar")
            elif kind == "integer":
                if type(value) is not int or not field["minimum"] <= value <= field["maximum"]:
                    raise AuthorityDenied("process.parameters", "integer parameter is outside its bounds")
            elif kind == "boolean":
                if type(value) is not bool:
                    raise AuthorityDenied("process.parameters", "boolean parameter has the wrong type")
            else:
                raise AuthorityDenied("process.parameters", "parameter type is not supported")
            enum = field["enum"]
            if enum is not None and not any(type(value) is type(candidate) and value == candidate for candidate in enum):
                raise AuthorityDenied("process.parameters", "operation parameter is outside its enrolled enum")
            result[name] = value
        return result

    def _resolve_enrolled_artifact(self, store_id: str, digest: str, *, executable: bool = False) -> Path:
        if not self.artifact_resolver:
            raise AuthorityDenied("process.artifact", "root artifact resolver is unavailable")
        try:
            resolved = self.artifact_resolver(store_id, digest)
            path = Path(getattr(resolved, "path", resolved))
            if (path != path.resolve(strict=True) or _root_path(path, directory=False) != path
                    or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                raise ValueError("artifact differs from catalog")
            info = path.stat(follow_symlinks=False)
            if executable and not info.st_mode & 0o111:
                raise ValueError("artifact is not executable")
            return path
        except Exception:
            raise AuthorityDenied("process.artifact", "root artifact resolver could not verify the enrolled artifact") from None

    def _start_reserved(self, profile: ManagedProfileCustody, context: HostContext,
                        authorization: EffectAuthorization, payload: bytes, timeout: float,
                        peer_pid: int | None, peer_pidfd: int | None,
                        cancelled: Callable[[], bool], *,
                        registered_profile: ManagedProfileCustody | None = None,
                        start_guard: Callable[[], bool] | None = None,
                        lease_expires_monotonic: float | None = None,
                        process_expires_monotonic: float | None = None,
                        root_selected_effect: Any | None = None,
                        xauthority_mount_source: Path | None = None,
                        daemon_liveness_pidfd: int | None = None) -> Mapping[str, Any]:
        if root_selected_effect is None:
            if authorization is None:
                raise AuthorityDenied("process.authority", "ordinary process start authority is malformed")
            effect_expiry = (authorization.monotonic_expires_at if lease_expires_monotonic is None
                             else lease_expires_monotonic)
        else:
            memory_root = root_selected_effect.role in {
                "memory-openviking", "memory-agentmemory", "memory-claude-mem"}
            health_root = root_selected_effect.role == "health"
            if (root_selected_effect.action != "start"
                    or (memory_root and (context is not None or authorization is not None
                                         or lease_expires_monotonic is None))
                    or (health_root and (context is not None or authorization is not None
                                         or lease_expires_monotonic is None))
                    or (not memory_root and not health_root
                        and (context is None or authorization is None))):
                raise AuthorityDenied("root-selected.authority", "root-selected launch must use its typed admission")
            effect_expiry = (lease_expires_monotonic if lease_expires_monotonic is not None
                             else getattr(authorization, "monotonic_expires_at", None))
            if not isinstance(effect_expiry, (int, float)) or isinstance(effect_expiry, bool):
                raise AuthorityDenied("root-selected.authority", "root-selected launch deadline is malformed")
        launch_deadline = min(self.monotonic() + max(0.0, timeout), effect_expiry)

        def require_live_start(parent_fd: int | None = None) -> None:
            reason = None
            if cancelled():
                reason = "cancelled"
            elif self.monotonic() >= launch_deadline:
                reason = "deadline"
            elif self.profiles.get(profile.profile_id) != (registered_profile or profile):
                reason = "profile-generation"
            elif start_guard is not None and not start_guard():
                reason = "admission-currentness"
            elif parent_fd is not None and _pidfd_exited(parent_fd):
                reason = "parent-pidfd"
            if reason is not None:
                sink = self._diagnostic_sink
                if sink is not None:
                    # Test-only root diagnostics expose a finite reason enum,
                    # never paths, credentials, payloads, or process data.
                    details = ""
                    if reason == "profile-generation":
                        current = self.profiles.get(profile.profile_id)
                        expected = registered_profile or profile
                        names = getattr(type(expected), "__dataclass_fields__", {})
                        differing = [name for name in names
                                     if getattr(current, name, object()) != getattr(expected, name, object())]
                        details = ":fields=" + ",".join(differing[:24])
                    sink(("prelaunch-deny:" + reason + details).encode("ascii", "backslashreplace")[:512])
                raise AuthorityDenied("process.start_expired", "start grant, profile enrollment or caller expired before launch")

        parent_liveness_fd = daemon_liveness_pidfd if daemon_liveness_pidfd is not None else peer_pidfd
        if parent_liveness_fd is None:
            raise AuthorityDenied("process.parent", "authority did not retain the peer pidfd")
        require_live_start()
        request = self._json(payload)
        if set(request) != _LAUNCH_FIELDS or request.get("schema") != 1:
            raise AuthorityDenied("process.launch", "launch envelope fields are invalid")
        expected = {
            "target": process_start_target(profile), "profile_id": profile.profile_id,
            "executable": str(profile.executable), "artifact_sha256": profile.artifact_sha256,
            "artifact_root": str(profile.artifact_root), "data_root": str(profile.data_root),
        }
        if any(request.get(key) != value for key, value in expected.items()):
            raise AuthorityDenied("process.binding", "launch envelope differs from protected profile registration")
        executable_info = profile.executable.stat(follow_symlinks=False)
        executable_identity = (executable_info.st_dev, executable_info.st_ino)
        if (hashlib.sha256(profile.executable.read_bytes()).hexdigest() != profile.artifact_sha256
                or not executable_info.st_mode & 0o111):
            raise AuthorityDenied("process.executable", "pinned executable changed before launch preparation")
        registered_children = dict(profile.child_artifact_refs or {})
        supplied_children = request.get("child_artifact_refs")
        if not isinstance(supplied_children, dict) or supplied_children != registered_children:
            raise AuthorityDenied("process.child", "child artifacts do not match the protected catalog")
        resolved_children: dict[str, Path] = {}
        for store_id, child_digest in supplied_children.items():
            if not self.artifact_resolver:
                raise AuthorityDenied("process.child", "protected artifact resolver is not installed")
            try:
                resolved = self.artifact_resolver(store_id, child_digest)
                child_path = Path(getattr(resolved, "path", resolved))
                if (child_path != child_path.resolve(strict=True)
                        or _root_path(child_path, directory=False) != child_path
                        or hashlib.sha256(child_path.read_bytes()).hexdigest() != child_digest):
                    raise ValueError("artifact identity mismatch")
            except Exception:
                raise AuthorityDenied("process.child", "root catalog could not resolve the enrolled artifact") from None
            resolved_children[store_id] = child_path
        child_artifact_identities = tuple(sorted(
            (digest, child_path.stat(follow_symlinks=False).st_dev,
             child_path.stat(follow_symlinks=False).st_ino)
            for store_id, child_path in resolved_children.items()
            for digest in (store_id.rsplit(":", 1)[-1],)
        ))
        argv = list(request["argv"])
        env = request["env_allowlist"]
        if (not isinstance(argv, list) or not argv or len(argv) > 128 or argv[0] != str(profile.executable)
                or any(not isinstance(item, str) or "\x00" in item or len(item) > 4096 for item in argv)
                or sum(len(item.encode()) for item in argv) > 65536):
            raise AuthorityDenied("process.argv", "argv does not match pinned executable or is oversized")
        if not _argv_matches_recipe(profile, argv, registered_children):
            raise AuthorityDenied("process.argv", "argv differs from the protected profile recipe")
        artifact_args = [index for index, item in enumerate(argv) if item in registered_children]
        if len(artifact_args) > 1:
            raise AuthorityDenied("process.child", "a launch recipe may select only one child artifact")
        selected_child_ref = argv[artifact_args[0]] if artifact_args else None
        if selected_child_ref is not None:
            argv[artifact_args[0]] = "__ROOT_ARTIFACT_MOUNT__"
        secrets = ("--token", "--secret", "--password", "--api-key", "--credential")
        if any(any(flag in item.casefold() for flag in secrets) for item in argv[1:]):
            raise AuthorityDenied("process.secret", "credential-bearing argv is forbidden")
        if (not isinstance(env, dict) or len(env) > 32
                or any(k not in _ALLOWED_ENV or not isinstance(v, str) or "\x00" in v or "\n" in v or "\r" in v
                       or len(v) > 1024 for k, v in env.items())
                or any(any(marker in k.casefold() for marker in ("token", "secret", "password", "credential", "api_key")) for k in env)
                or env.get("HOME") != "/hermes" or env.get("HERMES_HOME") != "/hermes"):
            raise AuthorityDenied("process.environment", "environment is not the sanitized profile allowlist")
        if (("XAUTHORITY" in env) != (xauthority_mount_source is not None)
                or ("XAUTHORITY" in env
                    and env["XAUTHORITY"] != "/run/hermes-installer/display/Xauthority")):
            raise AuthorityDenied("process.xauthority", "credential environment is not bound to the fixed root mount")
        if "PATH" in env:
            for raw_path in env["PATH"].split(":"):
                try:
                    _root_path(Path(raw_path), directory=True)
                except (OSError, ValueError):
                    raise AuthorityDenied("process.environment", "PATH includes an unprotected directory") from None
        for key in ("HOME", "HERMES_HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            value = env.get(key)
            if value is not None and not (value == "/hermes" or value.startswith("/hermes/")):
                raise AuthorityDenied("process.environment", "profile writable path escapes its private mount")
        cwd = Path(request["cwd"]).resolve(strict=True)
        roots = [(profile.data_root.resolve(strict=True), f"/hermes/profiles/{profile.profile_id}")]
        if profile.home_root is not None:
            roots.append((profile.home_root.resolve(strict=True), "/hermes"))
        if profile.work_root is not None:
            roots.append((profile.work_root.resolve(strict=True), "/workspace"))
        cwd_binding = next(((root, target) for root, target in roots if cwd.is_relative_to(root)), None)
        if cwd_binding is None:
            raise AuthorityDenied("process.cwd", "working directory is outside the enrolled private roots")
        cwd_root, cwd_target = cwd_binding
        lifetime, output_cap = request["max_lifetime_seconds"], request["max_output_bytes"]
        if (isinstance(lifetime, bool) or not isinstance(lifetime, (int, float))
                or not 0 < lifetime <= min(profile.max_lifetime_seconds, 600)
                or type(output_cap) is not int or not 1 <= output_cap <= 4 * 1024 * 1024
                or request["stdin_mode"] not in {"closed", "pipe"}):
            raise AuthorityDenied("process.bounds", "process lifetime or stream mode is invalid")
        require_live_start()
        try:
            parent_fd = os.dup(parent_liveness_fd)
        except OSError:
            raise AuthorityDenied("process.parent", "pidfd is required for parent-death custody") from None
        process_id = uuid.uuid4().hex
        artifact_mount_dir: Path | None = None
        artifact_target: Path | None = None
        native_mount_source: Path | None = None
        native_mount_receipt: NativePackageMountReceipt | None = None
        xauthority_mount_receipt: XauthorityMountReceipt | None = None
        native_loader_channel: Any | None = None
        artifact_path: Path | None = resolved_children.get(selected_child_ref) if selected_child_ref else None
        if selected_child_ref is not None and artifact_path is None:
            os.close(parent_fd)
            raise AuthorityDenied("process.child", "selected child artifact is not in the root catalog")
        unit = "hermes-installer-" + uuid.uuid4().hex + ".service"
        mount = f"/hermes/profiles/{profile.profile_id}"
        rel = cwd.relative_to(cwd_root).as_posix()
        target_cwd = cwd_target if rel == "." else f"{cwd_target}/{rel}"
        properties = [
            "--property=Type=exec", f"--property=RuntimeMaxSec={float(lifetime)}s",
            "--property=KillMode=control-group", f"--property=Description=HermesInstaller {profile.profile_id} {profile.generation}",
            "--property=ProtectSystem=strict", "--property=ProtectHome=tmpfs",
            "--property=ProtectProc=invisible", "--property=ProcSubset=pid",
            "--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes",
            f"--property=User={profile.service_user}", "--property=SupplementaryGroups=",
            "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
            "--property=RestrictNamespaces=user", "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=PrivateNetwork=yes", "--property=IPAddressDeny=any",
            # The product data root is created by the root installer. On a
            # clean host (and the isolated CI manager namespace) it may not
            # exist yet; systemd's `-` prefix skips only that absent path.
            # Once enrolled/installed, the same path is still masked.
            "--property=InaccessiblePaths=/etc/hermes-installer -/var/lib/hermes-installer /etc/ssh /etc/ssl/private",
        ]
        bind_paths = [f"{profile.data_root}:{mount}"]
        if profile.home_root is not None:
            bind_paths.append(f"{profile.home_root}:/hermes")
        if profile.work_root is not None:
            bind_paths.append(f"{profile.work_root}:/workspace")
        properties.append("--property=BindPaths=" + " ".join(bind_paths))
        authority_socket = profile.authority_socket or Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock")
        try:
            parent = authority_socket.parent.lstat()
            socket_info = authority_socket.lstat()
        except OSError:
            os.close(parent_fd)
            raise AuthorityDenied("process.authority_socket", "protected per-UID authority socket is unavailable") from None
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022
                or not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0
                or socket_info.st_gid != profile.owner_gid or stat.S_IMODE(socket_info.st_mode) != 0o660):
            os.close(parent_fd)
            raise AuthorityDenied("process.authority_socket", "per-UID authority socket ACL is not protected")
        properties.append(f"--property=BindPaths={authority_socket}:{authority_socket}")
        if xauthority_mount_source is not None:
            xauthority_source_file = xauthority_mount_source / "Xauthority"
            source_info = xauthority_source_file.stat(follow_symlinks=False)
            if (not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != 0
                    or source_info.st_gid != profile.owner_gid
                    or stat.S_IMODE(source_info.st_mode) != 0o440 or source_info.st_nlink != 1
                    or not 0 < source_info.st_size <= 65536):
                os.close(parent_fd)
                raise AuthorityDenied("process.xauthority", "staged credential source is not immutable and private")
            xauthority_mount_receipt = XauthorityMountReceipt(
                "/run/hermes-installer/display/Xauthority", source_info.st_dev,
                source_info.st_ino, hashlib.sha256(xauthority_source_file.read_bytes()).hexdigest(),
                source_info.st_size, profile.owner_gid,
            )
            properties.extend((
                "--property=BindReadOnlyPaths=" + str(xauthority_source_file) + ":/run/hermes-installer/display/Xauthority",
                "--property=RuntimeDirectory=hermes-installer/display",
                "--property=RuntimeDirectoryMode=0755",
                "--property=PrivateMounts=yes", "--property=MountFlags=private",
                # The source stage is already a private self-bind with the
                # kernel-enforced ro,nosuid,nodev,noexec flags. The readonly
                # file bind inherits those per-mount flags; systemd exposes
                # no per-path properties for the remaining mount flags.
                "--property=NoExecPaths=/run/hermes-installer/display/Xauthority",
            ))
        if profile.memory_max_bytes is not None:
            properties.append(f"--property=MemoryMax={profile.memory_max_bytes}")
        if profile.cpu_quota_percent is not None:
            properties.append(f"--property=CPUQuota={profile.cpu_quota_percent}%")
        if profile.io_weight is not None:
            properties.append(f"--property=IOWeight={profile.io_weight}")
        try:
            native_mount_source, native_mount_receipt = self._prepare_native_package_mount(profile, process_id)
            if native_mount_receipt is not None:
                if self.native_loader_observation_store is None:
                    raise AuthorityDenied("native.loader", "root loader observation store is unavailable")
                self._require_systemd_openfile()
                binding = getattr(profile.native_package, "binding", profile.native_package)
                role_artifact_id = getattr(binding, "entrypoint_artifact_id", None)
                role_sha256 = getattr(binding, "entrypoint_sha256", None)
                if (not isinstance(role_artifact_id, str) or not role_artifact_id
                        or not isinstance(role_sha256, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", role_sha256)):
                    raise AuthorityDenied("native.loader", "selected loader role pin is unavailable")
                runtime_dir = Path("/run/hermes-installer/native-loader")
                self._ensure_root_runtime_directory(runtime_dir.parent, 0o711)
                self._ensure_root_runtime_directory(runtime_dir, 0o700)
                from hermes_installer.authority.native_custody_proof import create_native_loader_channel
                native_loader_channel = create_native_loader_channel(runtime_dir)
                properties.append("--property=OpenFile=" + native_loader_channel.systemd_open_file_property)
        except BaseException:
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise
        env_args = ["--setenv=" + key + "=" + value for key, value in sorted(env.items())]
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise
        remaining = launch_deadline - self.monotonic()
        if remaining <= 0:
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise AuthorityDenied("process.start_expired", "start lease ended during preparation")
        try:
            manager_env = subprocess.run([str(self.systemctl), "--system", "show-environment"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=min(2.0, remaining), check=False)
        except (OSError, subprocess.TimeoutExpired):
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise AuthorityDenied("process.environment", "system manager environment could not be bounded") from None
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise
        if manager_env.returncode != 0 or len(manager_env.stdout) > 65536:
            if self._diagnostic_sink is not None:
                self._diagnostic_sink(
                    f"manager-environment-failed:returncode={manager_env.returncode}:bytes={len(manager_env.stdout)}".encode("ascii"))
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise AuthorityDenied("process.environment", "system manager environment cannot be safely cleared")
        manager_keys = {line.split("=", 1)[0] for line in manager_env.stdout.decode("utf-8", "replace").splitlines()
                        if "=" in line and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.split("=", 1)[0])}
        manager_keys.update({"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET", "WATCHDOG_USEC",
                             "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES",
                             "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME",
                             "SHELL", "PWD", "SYSTEMD_EXEC_PID", "MEMORY_PRESSURE_WATCH",
                             "MEMORY_PRESSURE_WRITE"})
        activation_keys = ({"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"}
                           if native_loader_channel is not None else set())
        unset_keys = sorted(manager_keys - set(env) - activation_keys)
        if sum(len(key) + 1 for key in unset_keys) > 60000:
            os.close(parent_fd)
            if native_loader_channel is not None:
                native_loader_channel.close()
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise AuthorityDenied("process.environment", "system manager environment exceeds its safe bound")
        if unset_keys:
            properties.append("--property=UnsetEnvironment=" + " ".join(unset_keys))
        try:
            require_live_start(parent_fd)
            artifact_mount_dir = _artifact_mount_slot(profile.owner_uid, process_id)
            require_live_start(parent_fd)
            if resolved_children:
                artifact_target = artifact_mount_dir / "child-1"
                fd = os.open(artifact_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o444)
                try:
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o444)
                finally:
                    os.close(fd)
                argv[artifact_args[0]] = str(artifact_target)
                properties.append(f"--property=BindReadOnlyPaths={artifact_path}:{artifact_target}")
            if native_mount_source is not None and native_mount_receipt is not None:
                properties.append(
                    "--property=BindReadOnlyPaths=" + str(native_mount_source) + ":"
                    + native_mount_receipt.mount_path)
                # systemd's bind tuple supports only recursion options. Apply
                # the other mount restrictions through its dedicated namespace
                # properties so mountinfo reflects kernel-enforced flags.
                properties.append("--property=PrivateMounts=yes")
                properties.append("--property=MountFlags=private")
                properties.append("--property=NoExecPaths=" + native_mount_receipt.mount_path)
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            if native_loader_channel is not None:
                native_loader_channel.close()
            raise
        command = [str(self.systemd_run), "--system", "--unit=" + unit, "--service-type=exec",
                   "--wait", "--collect", "--pipe", "--quiet", "--working-directory=" + target_cwd,
                   *properties, *env_args, str(profile.executable), *argv[1:]]
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            raise
        try:
            require_live_start(parent_fd)
            current_executable = profile.executable.stat(follow_symlinks=False)
            if ((current_executable.st_dev, current_executable.st_ino) != executable_identity
                    or hashlib.sha256(profile.executable.read_bytes()).hexdigest() != profile.artifact_sha256):
                raise AuthorityDenied("process.executable", "pinned executable changed before manager launch")
            if selected_child_ref is not None:
                current_child = artifact_path.stat(follow_symlinks=False)
                expected_child_identity = next(
                    item[1:] for item in child_artifact_identities
                    if item[0] == selected_child_ref.rsplit(":", 1)[-1]
                )
                if ((current_child.st_dev, current_child.st_ino) != expected_child_identity
                        or hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                        != selected_child_ref.rsplit(":", 1)[-1]):
                    raise AuthorityDenied("process.child", "pinned child artifact changed before manager launch")
            launcher = subprocess.Popen(command,
                stdin=subprocess.PIPE if request["stdin_mode"] == "pipe" else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True, shell=False)
        except OSError:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            if native_loader_channel is not None:
                native_loader_channel.close()
            raise AuthorityDenied("process.launcher_start", "root process manager could not start the enrolled service") from None
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
            if native_loader_channel is not None:
                native_loader_channel.close()
            raise
        started = self.monotonic()
        deadline = min(launch_deadline, started + 10.0)
        child_fd = None
        network_namespace_fd = None
        try:
            for stream in (launcher.stdin, launcher.stdout, launcher.stderr):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
            identity = None
            cgroup = ""
            while self.monotonic() < deadline:
                if cancelled() or _pidfd_exited(parent_fd):
                    raise AuthorityDenied("process.parent", "process owner ended before admission")
                try:
                    cg = self._show(unit, "ControlGroup")
                except AuthorityDenied as exc:
                    # systemd-run returns after submitting the unit but before
                    # systemd necessarily publishes it to `show`. Retry only
                    # this initial fixed-property lookup while the bounded
                    # launcher is still alive; all later readback failures
                    # remain fail-closed.
                    if exc.code != "process.manager.readback" or launcher.poll() is not None:
                        raise
                    time.sleep(.025)
                    continue
                if cg.startswith("/") and Path("/sys/fs/cgroup", *cg.strip("/").split()).exists():
                    members = (Path("/sys/fs/cgroup") / cg.lstrip("/") / "cgroup.procs").read_text().split()
                    for raw_pid in members:
                        pid = int(raw_pid)
                        try:
                            ticks, observed_cgroup, dev, ino = _pid_identity(pid)
                            proc_exe = Path(f"/proc/{pid}/exe")
                            digest = hashlib.sha256(proc_exe.read_bytes()).hexdigest()
                            pinned = profile.executable.stat(follow_symlinks=False)
                            if (observed_cgroup == cg and digest == profile.artifact_sha256
                                    and (dev, ino) == (pinned.st_dev, pinned.st_ino)):
                                identity, cgroup = (pid, ticks, dev, ino), cg
                                break
                        except (OSError, ValueError, AuthorityDenied):
                            continue
                if identity:
                    break
                if launcher.poll() is not None:
                    sink = self._diagnostic_sink
                    if sink is not None:
                        parts = [f"unit={unit} launcher-exit={launcher.returncode}".encode("ascii")]
                        for name, stream in ((b"stdout", launcher.stdout), (b"stderr", launcher.stderr)):
                            if stream is None:
                                continue
                            try:
                                output = stream.read(1024)
                            except (OSError, ValueError):
                                output = b""
                            if not isinstance(output, bytes):
                                output = b""
                            parts.append(name + b"=" + output[:1024])
                        # `systemd-run --quiet --wait --collect` intentionally
                        # keeps manager details off the worker channel. On a
                        # rejected unit the transient unit may already be
                        # collected, so capture only fixed, non-command
                        # properties and the bounded journal reason for the
                        # root-owned CI diagnostic sink. Never return this to
                        # the caller or include ExecStart/Environment fields.
                        for label, command_args in (
                            (b"unit-properties", [str(self.systemctl), "--system", "show", unit,
                                "-p", "Result", "-p", "ExecMainCode", "-p", "ExecMainStatus",
                                "-p", "StatusText", "-p", "ControlGroup", "-p", "PrivateNetwork",
                                "-p", "RestrictAddressFamilies", "-p", "RuntimeDirectory",
                                "-p", "RuntimeDirectoryMode", "-p", "PrivateMounts",
                                "-p", "MountFlags", "-p", "NoExecPaths"]),
                            (b"unit-journal", ["/usr/bin/journalctl", "--system", "--no-pager",
                                "-n", "8", "-o", "cat", "--unit", unit]),
                        ):
                            try:
                                diagnostic = subprocess.run(command_args, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                                    close_fds=True, timeout=1.0, check=False)
                                parts.append(label + b"=" + diagnostic.stdout[:1024])
                            except (OSError, subprocess.TimeoutExpired):
                                parts.append(label + b"=<unavailable>")
                        sink(b"\n".join(parts)[:2048])
                    raise AuthorityDenied("process.launcher_early_exit", "service exited before admission")
                time.sleep(.025)
            if identity is None:
                raise AuthorityDenied("process.admission_deadline", "service did not become ready before its deadline")
            pid, ticks, dev, ino = identity
            if native_mount_receipt is not None:
                self._verify_native_package_mount(pid, native_mount_receipt)
            if xauthority_mount_receipt is not None:
                self._verify_xauthority_mount(pid, xauthority_mount_receipt)
            if Path(cgroup).name != unit or ".." in Path(cgroup).parts:
                raise AuthorityDenied("process.cgroup", "service did not receive its exact cgroup")
            expected_props = {
                "KillMode": "control-group", "ProtectSystem": "strict", "PrivateTmp": "yes",
                "PrivateDevices": "yes", "NoNewPrivileges": "yes",
                # systemd expands `any` to both address-family CIDR ranges in
                # the observed unit property; compare the kernel rule form.
                "IPAddressDeny": "0.0.0.0/0 ::/0",
                "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX", "ProtectHome": "tmpfs",
                "ProtectProc": "invisible", "ProcSubset": "pid", "User": profile.service_user,
            }
            if xauthority_mount_receipt is not None:
                expected_props["RuntimeDirectory"] = "hermes-installer/display"
                expected_props["RuntimeDirectoryMode"] = "0755"
            for key, value in expected_props.items():
                actual_value = self._show(unit, key)
                matches = (set(actual_value.split()) == {"0.0.0.0/0", "::/0"}
                           if key == "IPAddressDeny" else actual_value == value)
                if not matches:
                    if self._diagnostic_sink is not None:
                        self._diagnostic_sink(
                            f"readback-mismatch:{key}:actual={actual_value[:160]!r}:expected={value!r}".encode("ascii", "backslashreplace"))
                    raise AuthorityDenied("process.sandbox", "manager isolation readback failed")
            if self._show(unit, "Description") != f"HermesInstaller {profile.profile_id} {profile.generation}":
                raise AuthorityDenied("process.unit", "manager unit is not bound to the profile generation")
            if self._show(unit, "SupplementaryGroups") not in {"", "-"}:
                raise AuthorityDenied("process.groups", "worker has unexpected supplemental groups")
            actual_environment = self._read_environment(pid)
            expected_environment = dict(env)
            if native_loader_channel is not None:
                expected_environment.update({
                    "LISTEN_PID": str(pid), "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "hermes-loader-progress",
                })
            if actual_environment != expected_environment:
                if self._diagnostic_sink is not None:
                    # Keep values out of the diagnostic path: only the
                    # variable names needed to identify manager injection are
                    # included in this root-only test sink.
                    actual_keys = sorted(actual_environment)
                    expected_keys = sorted(expected_environment)
                    self._diagnostic_sink(
                        ("child-environment-mismatch:actual_keys=" + ",".join(actual_keys)
                         + ":expected_keys=" + ",".join(expected_keys)).encode("ascii", "backslashreplace")[:1024])
                raise AuthorityDenied("process.environment", "actual child environment differs from the allowlist")
            child_fd = os.pidfd_open(pid, 0)
            actual_ticks, actual_cgroup, actual_dev, actual_ino = _pid_identity(pid)
            if ((actual_ticks, actual_cgroup, actual_dev, actual_ino) != (ticks, cgroup, dev, ino)
                    or _pidfd_exited(child_fd)):
                raise AuthorityDenied("process.identity", "kernel process identity changed during admission")
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            uids = next(line for line in status if line.startswith("Uid:")).split()[1:]
            if len(uids) != 4 or any(int(uid) != profile.owner_uid for uid in uids):
                raise AuthorityDenied("process.uid", "kernel worker UID does not match the profile")
            mnt, net = (os.stat(f"/proc/{pid}/ns/{name}").st_ino for name in ("mnt", "net"))
            if mnt == os.stat("/proc/self/ns/mnt").st_ino or net == os.stat("/proc/self/ns/net").st_ino:
                raise AuthorityDenied("process.namespace", "private mount or network namespace is missing")
            network_namespace_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            if os.fstat(network_namespace_fd).st_ino != net:
                raise AuthorityDenied("process.namespace", "network namespace changed while pinning its descriptor")
            if (_pid_identity(pid) != (ticks, cgroup, dev, ino) or _pidfd_exited(child_fd)):
                raise AuthorityDenied("process.identity", "worker changed while pinning its namespace descriptor")
            limits = self._limits(cgroup)
            if profile.memory_max_bytes is not None and limits["memory.max"] != str(profile.memory_max_bytes):
                raise AuthorityDenied("process.limits", "kernel memory.max does not match enrolled bound")
            if profile.cpu_quota_percent is not None:
                try:
                    quota, period = limits["cpu.max"].split()
                    if quota == "max" or int(quota) * 100 != profile.cpu_quota_percent * int(period):
                        raise AuthorityDenied("process.limits", "kernel cpu.max does not match enrolled bound")
                except ValueError:
                    raise AuthorityDenied("process.limits", "kernel cpu.max is unavailable") from None
            if profile.io_weight is not None:
                fields = limits["io.weight"].split()
                if not fields or int(fields[-1]) != profile.io_weight:
                    raise AuthorityDenied("process.limits", "kernel io.weight does not match enrolled bound")
            if artifact_mount_dir is None:
                raise AuthorityDenied("process.artifact", "artifact mount directory was not established")
            process_expiry = started + float(lifetime)
            if process_expires_monotonic is not None:
                if (isinstance(process_expires_monotonic, bool)
                        or not isinstance(process_expires_monotonic, (int, float))
                        or not math.isfinite(process_expires_monotonic)
                        or process_expires_monotonic <= started):
                    raise AuthorityDenied("process.start_expired", "selected process lifetime deadline is invalid")
                process_expiry = min(process_expiry, float(process_expires_monotonic))
            selected_principal = (root_selected_effect.selected_principal_id
                                  if root_selected_effect is not None else context.principal_id)
            selected_namespace = (root_selected_effect.selected_namespace_identity
                                  if root_selected_effect is not None else context.namespace_id)
            handle = _Handle(process_id, profile, unit, cgroup, launcher, parent_fd, child_fd, pid,
                ticks, f"mnt:{mnt};net:{net}", selected_principal, selected_namespace,
                started, process_expiry, output_cap, artifact_mount_dir,
                native_mount_source=native_mount_source,
                native_mount_receipt=native_mount_receipt,
                xauthority_mount_source=xauthority_mount_source,
                xauthority_mount_receipt=xauthority_mount_receipt,
                network_namespace_fd=network_namespace_fd,
                child_artifact_identities=child_artifact_identities,
                lock=threading.RLock(),
                registered_profile=registered_profile or profile)
            child_fd = None
            network_namespace_fd = None
            with self._lock:
                self._handles[process_id] = handle
            if native_loader_channel is not None:
                binding = getattr(profile.native_package, "binding", profile.native_package)
                observation = self.register_native_loader_channel(
                    process_id, native_loader_channel,
                    expected_loader_role_artifact_id=binding.entrypoint_artifact_id,
                    expected_loader_role_sha256=binding.entrypoint_sha256,
                    deadline_monotonic=min(handle.expires, self.monotonic() + 10.0),
                )
                if not native_loader_channel._transferred:
                    raise AuthorityDenied("native.loader", "system manager did not transfer the loader channel")
                handle.native_loader_observation_handle = observation
                handle.native_loader_ready_event_id = self.receive_native_loader_progress(
                    process_id,
                    cancelled=lambda: cancelled() or _pidfd_exited(handle.parent_pidfd),
                )
            threading.Thread(target=self._watch_parent, args=(handle,), daemon=True,
                             name="hermes-custody-watch").start()
            return _response(200, {"schema": 1, "process_id": process_id, "pid": pid,
            "uid": profile.owner_uid, "namespace_id": handle.kernel_namespace_id,
                "gid": profile.owner_gid, "unit": unit,
                "generation": profile.generation, "started_at_monotonic": started,
                "stdout_cursor": 0, "stderr_cursor": 0, "expires_at_monotonic": handle.expires,
                "cgroup": cgroup, "start_ticks": ticks, "executable_device": dev,
                "executable_inode": ino, "mount_namespace_inode": mnt,
                "network_namespace_inode": net, "kernel_limits": limits})
        except BaseException:
            try:
                with self._lock:
                    registered_handle = self._handles.get(process_id)
                if registered_handle is not None:
                    try:
                        proof = self._stop(registered_handle, timeout=5.0)
                    except Exception as cleanup_error:
                        raise AuthorityDenied(
                            "process.cleanup_ambiguous",
                            "failed process admission could not prove owned-process cleanup",
                        ) from cleanup_error
                    if not proof.cleanup_verified:
                        raise AuthorityDenied(
                            "process.cleanup_ambiguous",
                            "failed process admission could not prove owned-process cleanup",
                        )
                else:
                    self._stop_partial(unit, launcher)
            finally:
                try:
                    if artifact_mount_dir is not None:
                        _remove_artifact_mount(artifact_mount_dir)
                finally:
                    try:
                        if native_mount_source is not None:
                            self._remove_native_staging(native_mount_source)
                    finally:
                        if native_loader_channel is not None:
                            native_loader_channel.close()
                        for fd in (parent_fd, child_fd, network_namespace_fd):
                            if fd is not None:
                                try:
                                    os.close(fd)
                                except OSError:
                                    pass
            raise

    def _opaque_member_id(self, *, process_id: str, pid: int, ticks: int,
                          device: int, inode: int, cgroup: str) -> str:
        material = f"{process_id}:{pid}:{ticks}:{device}:{inode}:{cgroup}".encode("ascii")
        return hmac.new(self._member_key, material, hashlib.sha256).hexdigest()[:32]

    @staticmethod
    def _pidfd_target(pidfd: int) -> int | None:
        try:
            lines = Path(f"/proc/self/fdinfo/{pidfd}").read_text().splitlines()
            field = next(line for line in lines if line.startswith("Pid:"))
            value = int(field.split(":", 1)[1].strip())
            return value if value > 0 else None
        except (OSError, ValueError, StopIteration):
            return None

    def _inspect(self, profile: ManagedProfileCustody, context: HostContext,
                 payload: bytes, timeout: float,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        item = self._json(payload)
        if (set(item) != {"schema", "operation", "process_id", "generation", "fields"}
                or item.get("schema") != 1 or item.get("operation") != "process.inspect"
                or not isinstance(item.get("process_id"), str)
                or item.get("fields") != {}
                or item.get("generation") != profile.generation):
            raise AuthorityDenied("process.inspect", "inspection request is malformed or stale")
        with self._lock:
            handle = self._handles.get(item["process_id"])
        if (handle is None or handle.registered_profile != profile
                or self.profiles.get(profile.profile_id) != profile or handle.stopped
                or context.principal_id != handle.principal_id
                or context.namespace_id != handle.authority_namespace_id
                or cancelled() or self.monotonic() >= handle.expires
                or _pidfd_exited(handle.child_pidfd) or _pidfd_exited(handle.parent_pidfd)):
            raise AuthorityDenied("process.handle", "inspection handle is stale or outside its live generation")
        observed = self.monotonic()
        before = self._pids(handle.cgroup)
        if not before or len(before) > 128 or handle.pid not in before:
            raise AuthorityDenied("process.inspect", "registered cgroup has no bounded live main process")
        snapshots: dict[int, dict[str, Any]] = {}
        stable = True
        pinned_child_identities = set(handle.child_artifact_identities)
        executed_profile = handle.profile
        executable_info = executed_profile.executable.stat(follow_symlinks=False)
        pinned_child_identities.add((executed_profile.artifact_sha256,
                                     executable_info.st_dev, executable_info.st_ino))
        role_pins = dict(executed_profile.process_role_artifact_hashes or {})
        for pid in before:
            pidfd = None
            try:
                pidfd = os.pidfd_open(pid, 0)
                if self._pidfd_target(pidfd) != pid or _pidfd_exited(pidfd):
                    stable = False
                    continue
                ticks, cgroup, device, inode = _pid_identity(pid)
                if cgroup != handle.cgroup:
                    stable = False
                    continue
                status = Path(f"/proc/{pid}/status").read_text().splitlines()
                values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                          for line in status if ":" in line}
                uids = [int(value) for value in values.get("Uid", "").split()]
                if len(uids) != 4 or any(uid != profile.owner_uid for uid in uids):
                    stable = False
                    continue
                stat_fields = Path(f"/proc/{pid}/stat").read_text()
                tail = stat_fields[stat_fields.rfind(")") + 2:].split()
                parent_pid = int(tail[1])
                exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
                try:
                    exe_stat = os.fstat(exe_fd)
                    if not stat.S_ISREG(exe_stat.st_mode) or exe_stat.st_size > 1024 * 1024 * 1024:
                        stable = False
                        continue
                    digest = hashlib.sha256()
                    while True:
                        chunk = os.read(exe_fd, 1024 * 1024)
                        if not chunk:
                            break
                        digest.update(chunk)
                    exe_sha = digest.hexdigest()
                finally:
                    os.close(exe_fd)
                mnt_inode, net_inode = (os.stat(f"/proc/{pid}/ns/{name}").st_ino
                                        for name in ("mnt", "net"))
                namespace_identity = f"mnt:{mnt_inode};net:{net_inode}"
                artifact_verified = (exe_sha, device, inode) in pinned_child_identities
                role = role_pins.get(exe_sha, "main" if pid == handle.pid else "descendant")
                if role not in {"main", "descendant", "xpra-server", "electron-renderer",
                                "electron-browser", "renderer-relaunch-monitor"}:
                    stable = False
                    continue
                command = Path(f"/proc/{pid}/cmdline").read_bytes()
                if len(command) > 65536:
                    stable = False
                    continue
                arguments = [part.decode("utf-8", "replace") for part in command.rstrip(b"\x00").split(b"\x00")]
                forbidden = any(argument in {"--no-sandbox", "--disable-setuid-sandbox"}
                                for argument in arguments)
                seccomp_raw = values.get("Seccomp", "")
                no_new_privs_raw = values.get("NoNewPrivs", "")
                try:
                    seccomp_mode = int(seccomp_raw)
                    no_new_privs = int(no_new_privs_raw) == 1
                except ValueError:
                    stable = False
                    continue
                after_identity = _pid_identity(pid)
                if after_identity != (ticks, cgroup, device, inode) or _pidfd_exited(pidfd):
                    stable = False
                    continue
                member = self._opaque_member_id(process_id=handle.process_id, pid=pid,
                    ticks=ticks, device=device, inode=inode, cgroup=cgroup)
                snapshots[pid] = {
                    "member": member, "parent_pid": parent_pid, "kernel_uid": profile.owner_uid,
                    "starttime": ticks, "exe_device": device, "exe_inode": inode,
                    "exe_sha256": exe_sha, "cgroup_identity": cgroup,
                    "namespace_identity": namespace_identity, "role": role,
                    "artifact_verified": artifact_verified, "seccomp_mode": seccomp_mode,
                    "no_new_privs": no_new_privs, "forbidden_flags_present": forbidden,
                    "namespace_verified": namespace_identity == handle.kernel_namespace_id,
                }
            except (OSError, ValueError, KeyError):
                stable = False
            finally:
                if pidfd is not None:
                    os.close(pidfd)
        after = self._pids(handle.cgroup)
        stable = stable and before == after and set(snapshots) == set(before)
        member_by_pid = {pid: item["member"] for pid, item in snapshots.items()}

        def chain_reaches_main(pid: int) -> bool:
            seen: set[int] = set()
            current = pid
            for _ in range(32):
                if current == handle.pid:
                    return True
                if current in seen or current not in snapshots:
                    return False
                seen.add(current)
                current = snapshots[current]["parent_pid"]
            return False

        processes = []
        for pid, snapshot in sorted(snapshots.items(), key=lambda pair: pair[1]["member"]):
            parent_pid = snapshot["parent_pid"]
            parent_verified = pid == handle.pid or chain_reaches_main(pid)
            all_kernel_proofs = (snapshot["kernel_uid"] == profile.owner_uid
                and snapshot["cgroup_identity"] == handle.cgroup
                and snapshot["namespace_verified"] and snapshot["artifact_verified"]
                and snapshot["seccomp_mode"] == 2 and snapshot["no_new_privs"]
                and not snapshot["forbidden_flags_present"] and parent_verified)
            role_hash = role_pins.get(snapshot["exe_sha256"])
            sandbox_attestation = {
                "verified": bool(role_hash and all_kernel_proofs),
                "role": snapshot["role"],
                "artifact_verified": snapshot["artifact_verified"],
                "parent_chain_verified": parent_verified,
                "kernel_uid": snapshot["kernel_uid"],
                "cgroup_identity": snapshot["cgroup_identity"],
                "namespace_identity": snapshot["namespace_identity"],
                "seccomp_mode": snapshot["seccomp_mode"],
                "no_new_privs": snapshot["no_new_privs"],
                "forbidden_flags_present": snapshot["forbidden_flags_present"],
                "relaunch_monitor_verified": False,
                "window_denial_verified": False,
                "policy_manifest_sha256": None,
                "native_generation": None,
                "observation_monotonic": observed,
                "expires_monotonic": min(handle.expires, observed + min(max(timeout, 0.1), 30.0)),
                "evidence_refs": ["pidfd", "procfs-status", "procfs-cgroup", "procfs-exe"],
            }
            processes.append({
                "opaque_member_id": snapshot["member"],
                "parent_member_id": member_by_pid.get(parent_pid),
                "kernel_uid": snapshot["kernel_uid"],
                "pidfd_identity": "pidfd:" + snapshot["member"],
                "starttime": snapshot["starttime"],
                "exe_device": snapshot["exe_device"],
                "exe_inode": snapshot["exe_inode"],
                "exe_sha256": snapshot["exe_sha256"],
                "cgroup_identity": snapshot["cgroup_identity"],
                "role": snapshot["role"],
                "sandbox_attestation": sandbox_attestation,
            })
        if cancelled() or self.monotonic() >= handle.expires or _pidfd_exited(handle.child_pidfd):
            raise AuthorityDenied("process.expired", "process expired during inspection")
        # HI10's public inspection wire is intentionally a small top-level
        # attestation. It excludes raw host PIDs, paths, argv and environments;
        # per-member identities are opaque handles tied to this root registry.
        return _response(200, {
            "schema": 1, "process_id": handle.process_id,
            "generation": profile.generation, "operation": "process.inspect",
            "state": "running", "result": {"profile_id": profile.profile_id,
            "cgroup_identity": handle.cgroup, "observation_monotonic": observed,
            "complete": stable, "processes": processes},
            "expires_monotonic": min(handle.expires, observed + min(max(timeout, 0.1), 30.0)),
        })

    def resolve_namespace_lease(self, binding: Any) -> ManagedNamespaceLease | None:
        """Resolve a route only to the one active namespace enrolled for its profile generation."""
        profile_id = getattr(binding, "profile_id", None)
        generation = getattr(binding, "generation", None)
        namespace_identity = getattr(binding, "namespace_identity", None)
        if not isinstance(profile_id, str) or not isinstance(generation, str) or not isinstance(namespace_identity, str):
            return None
        return self._resolve_profile_namespace_lease(profile_id, generation, namespace_identity)

    def resolve_observer_namespace_lease(self, profile_id: str, generation: str,
                                         expected_namespace_identity: str
                                         ) -> ManagedNamespaceLease | None:
        """Return a short-lived namespace FD for one exact enrolled live process.

        This is the bounded root-only seam for observers that must inspect a
        protected service namespace. It selects no process or namespace from a
        caller PID/path and requires the supplied identity to equal both the
        current profile enrollment and its live manager-owned handle.
        """
        if (not isinstance(profile_id, str) or not profile_id
                or not isinstance(generation, str) or not generation
                or not isinstance(expected_namespace_identity, str)
                or not re.fullmatch(r"mnt:[1-9][0-9]*;net:[1-9][0-9]*",
                                    expected_namespace_identity)):
            return None
        registered = self.profiles.get(profile_id)
        if registered is None or registered.generation != generation:
            return None
        return self._resolve_profile_namespace_lease(
            profile_id, generation, expected_namespace_identity,
            registered_profile=registered,
        )

    def _resolve_profile_namespace_lease(self, profile_id: str, generation: str,
                                         namespace_identity: str, *,
                                         registered_profile: ManagedProfileCustody | None = None
                                         ) -> ManagedNamespaceLease | None:
        with self._lock:
            registered = registered_profile or self.profiles.get(profile_id)
            if (registered is None or registered.profile_id != profile_id
                    or registered.generation != generation):
                return None
            matches = [handle for handle in self._handles.values()
                       if handle.profile.profile_id == profile_id
                       and handle.profile.generation == generation
                       and handle.registered_profile is registered
                       and handle.kernel_namespace_id == namespace_identity]
        if len(matches) != 1:
            return None
        handle = matches[0]
        with handle.lock:
            if (handle.stopped or handle.network_namespace_fd is None
                    or self.monotonic() >= handle.expires or _pidfd_exited(handle.child_pidfd)
                    or handle.registered_profile is not registered
                    or handle.pid not in self._pids(handle.cgroup)):
                return None
            expected_net = int(namespace_identity.rsplit("net:", 1)[1])
            if os.fstat(handle.network_namespace_fd).st_ino != expected_net:
                return None
            namespace_fd = os.dup(handle.network_namespace_fd)
            try:
                pidfd = os.dup(handle.child_pidfd)
            except OSError:
                os.close(namespace_fd)
                return None
            return ManagedNamespaceLease(namespace_fd, pidfd, handle.profile.owner_uid,
                handle.cgroup, handle.profile.generation, handle.kernel_namespace_id)

    def resolve_live_peer(self, peer_pid: int, peer_pidfd: int, *,
                          profile_id: str, generation: str) -> LivePeerIdentity | None:
        """Return root-observed identity only for a live member of an enrolled process cgroup."""
        if (type(peer_pid) is not int or peer_pid <= 0 or type(peer_pidfd) is not int
                or peer_pidfd < 0 or not isinstance(profile_id, str) or not isinstance(generation, str)):
            return None
        if self._pidfd_target(peer_pidfd) != peer_pid or _pidfd_exited(peer_pidfd):
            return None
        with self._lock:
            matches = [handle for handle in self._handles.values()
                       if handle.profile.profile_id == profile_id
                       and handle.profile.generation == generation]
        if len(matches) != 1:
            return None
        handle = matches[0]
        if (handle.stopped or self.monotonic() >= handle.expires
                or peer_pid not in self._pids(handle.cgroup)):
            return None
        try:
            ticks, cgroup, device, inode = _pid_identity(peer_pid)
            if cgroup != handle.cgroup:
                return None
            status = Path(f"/proc/{peer_pid}/status").read_text().splitlines()
            uid_fields = next(line for line in status if line.startswith("Uid:")).split()[1:]
            if len(uid_fields) != 4 or any(int(uid) != handle.profile.owner_uid for uid in uid_fields):
                return None
            exe_fd = os.open(f"/proc/{peer_pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                exe_stat = os.fstat(exe_fd)
                if not stat.S_ISREG(exe_stat.st_mode) or exe_stat.st_size > 1024 * 1024 * 1024:
                    return None
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(exe_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                exe_sha256 = digest.hexdigest()
            finally:
                os.close(exe_fd)
            main = handle.profile.executable.stat(follow_symlinks=False)
            pinned = {(handle.profile.artifact_sha256, main.st_dev, main.st_ino),
                      *handle.child_artifact_identities}
            if (exe_sha256, device, inode) not in pinned:
                return None
            mnt, net = (os.stat(f"/proc/{peer_pid}/ns/{name}").st_ino for name in ("mnt", "net"))
            if f"mnt:{mnt};net:{net}" != handle.kernel_namespace_id:
                return None
            if (_pid_identity(peer_pid) != (ticks, cgroup, device, inode)
                    or self._pidfd_target(peer_pidfd) != peer_pid or _pidfd_exited(peer_pidfd)):
                return None
            return LivePeerIdentity(profile_id, generation, handle.profile.owner_uid,
                ticks, exe_sha256, cgroup, handle.kernel_namespace_id)
        except (OSError, ValueError, StopIteration):
            return None

    def is_owned_active_process_handle(self, handle: _Handle) -> bool:
        """Check exact object membership and current kernel liveness in this manager."""
        if not isinstance(handle, _Handle):
            return False
        with self._lock:
            current = self._handles.get(handle.process_id)
            if (current is not handle or handle.stopped
                    or handle.registered_profile is not self.profiles.get(handle.profile.profile_id)
                    or handle.profile.generation != handle.registered_profile.generation
                    or handle.expires <= self.monotonic()):
                return False
        try:
            pid = self._pidfd_target(handle.child_pidfd)
            return (pid == handle.pid and not _pidfd_exited(handle.child_pidfd)
                    and pid in self._pids(handle.cgroup))
        except (OSError, AuthorityDenied, ValueError):
            return False

    def inspect_enrolled_process(self, profile_id: str,
                                 generation: str) -> RemoteOriginKernelProof | None:
        """Inspect exactly one root-registered live process for an enrolled profile.

        This root-only API is intended for the remote-origin authority. It
        selects from the protected manager registry, rechecks the retained
        PIDFD/start time/executable inode and both namespaces, and returns no
        caller-selected PID/path. Application readiness and route/config
        evidence must be joined by their own authority catalogs.
        """
        if (not isinstance(profile_id, str) or not profile_id
                or not isinstance(generation, str) or not generation):
            return None
        registered = self.profiles.get(profile_id)
        if registered is None or registered.generation != generation:
            return None
        with self._lock:
            matches = [handle for handle in self._handles.values()
                       if handle.profile.profile_id == profile_id
                       and handle.profile.generation == generation
                       and handle.registered_profile is registered]
        if len(matches) != 1:
            return None
        handle = matches[0]
        pidfd = None
        try:
            if (handle.stopped or self.monotonic() >= handle.expires
                    or _pidfd_exited(handle.child_pidfd)):
                return None
            pidfd = os.dup(handle.child_pidfd)
            pid = self._pidfd_target(pidfd)
            if pid != handle.pid or _pidfd_exited(pidfd):
                return None
            ticks, cgroup, device, inode = _pid_identity(pid)
            if (ticks != handle.start_ticks or cgroup != handle.cgroup
                    or pid not in self._pids(handle.cgroup)):
                return None
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            uid_fields = next(line for line in status if line.startswith("Uid:")).split()[1:]
            gid_fields = next(line for line in status if line.startswith("Gid:")).split()[1:]
            if (len(uid_fields) != 4 or any(int(value) != handle.profile.owner_uid for value in uid_fields)
                    or len(gid_fields) != 4 or any(int(value) != handle.profile.owner_gid for value in gid_fields)):
                return None
            executable = handle.profile.executable.stat(follow_symlinks=False)
            exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                observed = os.fstat(exe_fd)
                if ((observed.st_dev, observed.st_ino) != (executable.st_dev, executable.st_ino)
                        or (device, inode) != (executable.st_dev, executable.st_ino)):
                    return None
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(exe_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                executable_sha256 = digest.hexdigest()
            finally:
                os.close(exe_fd)
            if executable_sha256 != handle.profile.artifact_sha256:
                return None
            mount_ns, network_ns = (os.stat(f"/proc/{pid}/ns/{name}").st_ino
                                    for name in ("mnt", "net"))
            if (f"mnt:{mount_ns};net:{network_ns}" != handle.kernel_namespace_id
                    or _pid_identity(pid) != (ticks, cgroup, device, inode)
                    or self._pidfd_target(pidfd) != pid or _pidfd_exited(pidfd)):
                return None
            enrollment_id = handle.profile.enrollment_id
            if not isinstance(enrollment_id, str) or not enrollment_id:
                return None
            registry_handle = self._opaque_member_id(process_id=handle.process_id,
                pid=pid, ticks=ticks, device=device, inode=inode, cgroup=cgroup)
            return RemoteOriginKernelProof(
                handle.process_id, enrollment_id, profile_id, generation,
                handle.profile.owner_uid, handle.profile.owner_gid, pid, ticks,
                device, inode, executable_sha256, cgroup, mount_ns, network_ns,
                registry_handle, handle.expires,
            )
        except (OSError, ValueError, StopIteration):
            return None
        finally:
            if pidfd is not None:
                os.close(pidfd)

    def resolve_active_process_handle(
        self, profile_id: str, generation: str,
    ) -> ManagedProcessIdentityLease | None:
        """Return a duplicated PIDFD lease for the unique active enrolled process.

        Selection is exclusively through the manager's current registry. The
        identity is re-read from procfs and compared with the retained PIDFD,
        cgroup, executable pin, and namespace identity immediately before the
        lease is returned. Callers own and must close the returned PIDFD.
        """
        proof = self.inspect_enrolled_process(profile_id, generation)
        if proof is None:
            return None
        with self._lock:
            handle = self._handles.get(proof.process_id)
            registered = self.profiles.get(profile_id)
            if (handle is None or handle.stopped or registered is None
                    or registered.generation != generation
                    or handle.registered_profile is not registered
                    or handle.profile.profile_id != profile_id
                    or handle.profile.generation != generation
                    or handle.expires <= self.monotonic()):
                return None
            try:
                lease_fd = os.dup(handle.child_pidfd)
            except OSError:
                return None
        transferred = False
        try:
            pid = self._pidfd_target(lease_fd)
            if pid != proof.pid or pid != handle.pid or _pidfd_exited(lease_fd):
                return None
            ticks, cgroup, device, inode = _pid_identity(pid)
            mount_ns, network_ns = (os.stat(f"/proc/{pid}/ns/{name}").st_ino
                                    for name in ("mnt", "net"))
            executable = handle.profile.executable.stat(follow_symlinks=False)
            if (ticks != proof.pid_starttime_ticks or ticks != handle.start_ticks
                    or cgroup != proof.cgroup_id or cgroup != handle.cgroup
                    or (device, inode) != (proof.executable_device, proof.executable_inode)
                    or (device, inode) != (executable.st_dev, executable.st_ino)
                    or mount_ns != proof.mount_namespace_inode
                    or network_ns != proof.network_namespace_inode
                    or f"mnt:{mount_ns};net:{network_ns}" != handle.kernel_namespace_id
                    or pid not in self._pids(handle.cgroup)
                    or _pidfd_exited(handle.child_pidfd)
                    or self._pidfd_target(handle.child_pidfd) != pid):
                return None
            with self._lock:
                if (self._handles.get(proof.process_id) is not handle or handle.stopped
                        or self.profiles.get(profile_id) is not registered
                        or handle.registered_profile is not registered
                        or handle.expires <= self.monotonic()):
                    return None
            lease = ManagedProcessIdentityLease(
                process_id=proof.process_id, profile_id=profile_id,
                generation=generation, uid=proof.uid, gid=proof.gid,
                pid=pid, start_ticks=ticks, executable_device=device,
                executable_inode=inode, executable_sha256=proof.executable_sha256,
                cgroup_identity=cgroup, mount_namespace_inode=mount_ns,
                network_namespace_inode=network_ns,
                expires_monotonic=min(proof.expires_monotonic, handle.expires),
                pidfd=lease_fd,
            )
            transferred = True
            return lease
        except (OSError, ValueError):
            return None
        finally:
            if not transferred:
                try:
                    os.close(lease_fd)
                except OSError:
                    pass

    def resolve_managed_task_process_handle(
        self, task_handle: ManagedTaskHandle,
    ) -> ManagedProcessIdentityLease | None:
        """Resolve one exact active root task to a duplicated PIDFD lease."""
        if not isinstance(task_handle, ManagedTaskHandle):
            return None
        try:
            state = self._resolve_task_handle(task_handle)
        except AuthorityDenied:
            return None
        handle = state.handle
        with self._lock:
            if (self._task_handles.get(task_handle.handle_id) is not state
                    or self._handles.get(task_handle.process_id) is not handle
                    or handle.process_id != task_handle.process_id
                    or handle.profile.generation != task_handle.generation
                    or handle.stopped or state.consumed
                    or state.deadline <= self.monotonic()):
                return None
            try:
                lease_fd = os.dup(handle.child_pidfd)
            except OSError:
                return None
        transferred = False
        try:
            pid = self._pidfd_target(lease_fd)
            if pid != handle.pid or _pidfd_exited(lease_fd):
                return None
            ticks, cgroup, device, inode = _pid_identity(pid)
            executable = handle.profile.executable.stat(follow_symlinks=False)
            mount_ns, network_ns = (os.stat(f"/proc/{pid}/ns/{name}").st_ino
                                    for name in ("mnt", "net"))
            if (ticks != handle.start_ticks or cgroup != handle.cgroup
                    or (device, inode) != (executable.st_dev, executable.st_ino)
                    or pid not in self._pids(handle.cgroup)
                    or f"mnt:{mount_ns};net:{network_ns}" != handle.kernel_namespace_id
                    or _pidfd_exited(handle.child_pidfd)
                    or self._pidfd_target(handle.child_pidfd) != pid):
                return None
            digest = hashlib.sha256()
            exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                observed = os.fstat(exe_fd)
                if (observed.st_dev, observed.st_ino) != (device, inode):
                    return None
                while True:
                    chunk = os.read(exe_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(exe_fd)
            exe_sha256 = digest.hexdigest()
            if exe_sha256 != handle.profile.artifact_sha256:
                return None
            with self._lock:
                if (self._task_handles.get(task_handle.handle_id) is not state
                        or self._handles.get(task_handle.process_id) is not handle
                        or handle.stopped or state.consumed
                        or state.deadline <= self.monotonic()):
                    return None
            lease = ManagedProcessIdentityLease(
                process_id=handle.process_id, profile_id=handle.profile.profile_id,
                generation=handle.profile.generation, uid=handle.profile.owner_uid,
                gid=handle.profile.owner_gid, pid=pid, start_ticks=ticks,
                executable_device=device, executable_inode=inode,
                executable_sha256=exe_sha256, cgroup_identity=cgroup,
                mount_namespace_inode=mount_ns,
                network_namespace_inode=network_ns,
                expires_monotonic=min(handle.expires, state.deadline), pidfd=lease_fd)
            transferred = True
            return lease
        except (OSError, ValueError, AuthorityDenied):
            return None
        finally:
            if not transferred:
                try:
                    os.close(lease_fd)
                except OSError:
                    pass

    def resolve_owned_process_handle(
        self, handle: _Handle,
    ) -> ManagedProcessIdentityLease | None:
        """Resolve a root-held active manager handle without profile selection.

        This is for root registries that already selected and retained the
        exact manager handle. It deliberately rejects structurally similar or
        stale handles by object identity against this manager's live registry.
        """
        if not isinstance(handle, _Handle):
            return None
        with self._lock:
            registered = self.profiles.get(handle.profile.profile_id)
            if (self._handles.get(handle.process_id) is not handle or handle.stopped
                    or registered is None or handle.registered_profile is not registered
                    or handle.profile.generation != handle.registered_profile.generation
                    or handle.expires <= self.monotonic()):
                return None
            try:
                lease_fd = os.dup(handle.child_pidfd)
            except OSError:
                return None
        transferred = False
        try:
            pid = self._pidfd_target(lease_fd)
            if pid != handle.pid or _pidfd_exited(lease_fd):
                return None
            ticks, cgroup, device, inode = _pid_identity(pid)
            executable = handle.profile.executable.stat(follow_symlinks=False)
            mount_ns, network_ns = (os.stat(f"/proc/{pid}/ns/{name}").st_ino
                                    for name in ("mnt", "net"))
            if (ticks != handle.start_ticks or cgroup != handle.cgroup
                    or (device, inode) != (executable.st_dev, executable.st_ino)
                    or pid not in self._pids(handle.cgroup)
                    or f"mnt:{mount_ns};net:{network_ns}" != handle.kernel_namespace_id
                    or _pidfd_exited(handle.child_pidfd)
                    or self._pidfd_target(handle.child_pidfd) != pid):
                return None
            digest = hashlib.sha256()
            exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                observed = os.fstat(exe_fd)
                if (observed.st_dev, observed.st_ino) != (device, inode):
                    return None
                while True:
                    chunk = os.read(exe_fd, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
            finally:
                os.close(exe_fd)
            exe_sha256 = digest.hexdigest()
            if exe_sha256 != handle.profile.artifact_sha256:
                return None
            with self._lock:
                registered = self.profiles.get(handle.profile.profile_id)
                if (self._handles.get(handle.process_id) is not handle or handle.stopped
                        or registered is None or handle.registered_profile is not registered
                        or handle.expires <= self.monotonic()):
                    return None
            lease = ManagedProcessIdentityLease(
                process_id=handle.process_id, profile_id=handle.profile.profile_id,
                generation=handle.profile.generation, uid=handle.profile.owner_uid,
                gid=handle.profile.owner_gid, pid=pid, start_ticks=ticks,
                executable_device=device, executable_inode=inode,
                executable_sha256=exe_sha256, cgroup_identity=cgroup,
                mount_namespace_inode=mount_ns,
                network_namespace_inode=network_ns,
                expires_monotonic=handle.expires, pidfd=lease_fd)
            transferred = True
            return lease
        except (OSError, ValueError, AuthorityDenied):
            return None
        finally:
            if not transferred:
                try:
                    os.close(lease_fd)
                except OSError:
                    pass

    def resolve_process_operation(self, process_id: str, generation: str, operation: str, *,
                                  peer_uid: int, peer_pid: int,
                                  peer_pidfd: int) -> tuple[ManagedProfileCustody, str] | None:
        """Resolve an opaque live handle to its fixed root-enrolled control target.

        This root-only method accepts no target, path, PID selector, or caller
        profile label.  The supplied peer identity must be a live, pinned member
        of the same enrolled process generation.
        """
        if (not isinstance(process_id, str) or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                or not isinstance(generation, str)
                or operation not in {"process.status", "process.read", "process.write", "process.stop", "process.inspect"}
                or type(peer_uid) is not int or peer_uid <= 0):
            return None
        with self._lock:
            handle = self._handles.get(process_id)
        if (handle is None or handle.stopped or handle.profile.generation != generation
                or handle.registered_profile is not self.profiles.get(handle.profile.profile_id)
                or peer_uid != handle.profile.owner_uid):
            return None
        if (self._pidfd_target(peer_pidfd) != peer_pid or _pidfd_exited(peer_pidfd)):
            return None
        # The control caller is either the exact root-captured process that
        # created this handle, or a pinned descendant in this same cgroup.
        parent_pid = self._pidfd_target(handle.parent_pidfd)
        identity = (self.resolve_live_peer(peer_pid, peer_pidfd,
                    profile_id=handle.profile.profile_id, generation=generation)
                    if peer_pid != parent_pid else None)
        if peer_pid == parent_pid:
            try:
                status = Path(f"/proc/{peer_pid}/status").read_text().splitlines()
                uids = next(line for line in status if line.startswith("Uid:")).split()[1:]
                allowed = len(uids) == 4 and all(int(uid) == peer_uid for uid in uids)
            except (OSError, ValueError, StopIteration):
                return None
            if not allowed or _pidfd_exited(handle.parent_pidfd):
                return None
        elif identity is None or identity.kernel_uid != peer_uid:
            return None
        target = (process_inspect_target(handle.registered_profile) if operation == "process.inspect"
                  else process_control_target(handle.registered_profile, operation))
        return handle.registered_profile, target

    def resolve_loaded_native_package(self, process_id: str, generation: str) -> LoadedNativePackageProof | None:
        """Resolve the package actually mounted in one active registered process."""
        if (not isinstance(process_id, str) or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                or not isinstance(generation, str)):
            return None
        with self._lock:
            handle = self._handles.get(process_id)
        if (handle is None or handle.profile.generation != generation or handle.stopped
                or self.profiles.get(handle.profile.profile_id) != handle.registered_profile
                or handle.native_mount_receipt is None or handle.native_mount_source is None
                or self.monotonic() >= handle.expires or _pidfd_exited(handle.child_pidfd)
                or handle.pid not in self._pids(handle.cgroup)):
            return None
        try:
            self._verify_native_package_mount(handle.pid, handle.native_mount_receipt)
            ticks, cgroup, device, inode = _pid_identity(handle.pid)
            pinned = handle.profile.executable.stat(follow_symlinks=False)
            if (ticks != handle.start_ticks or cgroup != handle.cgroup
                    or (device, inode) != (pinned.st_dev, pinned.st_ino)
                    or _pidfd_exited(handle.child_pidfd)):
                return None
        except (OSError, AuthorityDenied):
            return None
        return LoadedNativePackageProof(
            process_id, handle.profile.profile_id, generation, handle.profile.owner_uid,
            ticks, cgroup, handle.kernel_namespace_id, handle.profile.artifact_sha256,
            handle.native_mount_receipt, self.monotonic(),
        )

    def resolve_native_package_for_peer(self, peer_pid: int,
                                        peer_pidfd: int) -> LoadedNativePackageProof | None:
        """Resolve package custody for the authenticated RPC peer, without a worker selector.

        The only identity inputs are the SO_PEERCRED PID and pidfd captured by
        AuthorityService. The root registry selects the unique active process
        generation; callers cannot submit process IDs, profile IDs or paths.
        """
        if (type(peer_pid) is not int or peer_pid <= 0 or type(peer_pidfd) is not int
                or peer_pidfd < 0 or self._pidfd_target(peer_pidfd) != peer_pid
                or _pidfd_exited(peer_pidfd)):
            return None
        with self._lock:
            candidates = [handle for handle in self._handles.values()
                          if not handle.stopped and handle.native_mount_receipt is not None
                          and handle.profile.generation == handle.native_mount_receipt.generation
                          and peer_pid in self._pids(handle.cgroup)]
        if len(candidates) != 1:
            return None
        handle = candidates[0]
        identity = self.resolve_live_peer(peer_pid, peer_pidfd,
            profile_id=handle.profile.profile_id, generation=handle.profile.generation)
        if identity is None or identity.kernel_uid != handle.profile.owner_uid:
            return None
        proof = self.resolve_loaded_native_package(handle.process_id, handle.profile.generation)
        if (proof is None or self._pidfd_target(peer_pidfd) != peer_pid
                or _pidfd_exited(peer_pidfd)):
            return None
        return proof

    @staticmethod
    def _read_environment(pid: int) -> dict[str, str]:
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError:
            raise AuthorityDenied("process.environment", "kernel child environment cannot be observed") from None
        if len(raw) > 65536:
            raise AuthorityDenied("process.environment", "kernel child environment exceeds its bound")
        values = {}
        for item in raw.split(b"\x00"):
            if item:
                key, sep, value = item.partition(b"=")
                if sep:
                    values[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
        return values

    def _control(self, profile: ManagedProfileCustody, context: HostContext, operation: str,
                 payload: bytes, timeout: float, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        item = self._json(payload)
        common = {"schema", "operation", "process_id", "generation", "fields"}
        extras = {"process.status": set(), "process.stop": {"reason", "grace_seconds"},
                  "process.read": {"stream", "maximum_bytes"},
                  "process.write": {"data_bytes", "sequence"}}[operation]
        if (set(item) != common or item.get("schema") != 1 or item.get("operation") != operation
                or not isinstance(item.get("process_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", item["process_id"])
                or not isinstance(item.get("fields"), dict) or set(item["fields"]) != extras
                or item.get("generation") != profile.generation):
            raise AuthorityDenied("process.control", "control envelope is malformed")
        fields = item["fields"]
        if operation == "process.stop" and (
                fields["reason"] not in {"cancel", "shutdown", "rollback"}
                or type(fields["grace_seconds"]) is not int
                or not 0 <= fields["grace_seconds"] <= 10):
            raise AuthorityDenied("process.stop", "stop reason or grace period is invalid")
        with self._lock:
            handle = self._handles.get(item["process_id"])
            finished = self._finished.get(item["process_id"])
        if handle is None and operation == "process.stop" and finished and finished[0] == profile.generation:
            proof = finished[2]
            return _response(200, {"schema": 1, "process_id": item["process_id"],
                "generation": profile.generation, "operation": operation, "state": "stopped",
                "result": {"closed": proof.cleanup_verified,
                    "reap_state": "reaped" if proof.cleanup_verified else "unverified"},
                "expires_monotonic": self.monotonic() + 5.0})
        if (handle is None or handle.profile.profile_id != profile.profile_id
                or item["generation"] != profile.generation
                or context.principal_id != handle.principal_id
                or context.namespace_id != handle.authority_namespace_id):
            raise AuthorityDenied("process.handle", "process handle is stale or belongs to another principal")
        if operation != "process.stop" and (cancelled() or _pidfd_exited(handle.parent_pidfd)
                                               or self.monotonic() >= handle.expires):
            self._stop(handle, timeout=min(timeout, 5.0))
            raise AuthorityDenied("process.expired", "parent, lease or service lifetime ended")
        if handle.task_owned:
            raise AuthorityDenied("process.task_owned", "resource task streams are root-owned")
        if operation == "process.status":
            code = handle.launcher.poll()
            # Control status is deliberately non-identifying. Detailed host
            # identity is available only through the separately authorized,
            # bounded process.inspect attestation.
            result = {"exit_code": code}
            return _response(200, {"schema": 1, "process_id": handle.process_id,
                "generation": profile.generation, "operation": operation,
                "state": "running" if code is None else "exited", "result": result,
                "expires_monotonic": min(handle.expires, self.monotonic() + 5.0)})
        if operation == "process.read":
            stream_name, maximum = fields["stream"], fields["maximum_bytes"]
            if (stream_name not in {"stdout", "stderr"} or type(maximum) is not int
                    or not 1 <= maximum <= 1_048_576):
                raise AuthorityDenied("process.read", "stream or read bounds are invalid")
            with handle.lock or contextlib.nullcontext():
                remaining_output = handle.output_cap - handle.stdout_cursor - handle.stderr_cursor
                if remaining_output <= 0:
                    self._stop(handle, timeout=min(timeout, 5.0))
                    raise AuthorityDenied("process.output", "managed process exceeded its output cap")
                maximum = min(maximum, remaining_output)
                stream = getattr(handle.launcher, stream_name)
                ready, _, _ = select.select([stream.fileno()], [], [], min(max(timeout, 0), .75))
                data = os.read(stream.fileno(), maximum) if ready else b""
                eof = bool(ready and not data)
                if stream_name == "stdout":
                    handle.stdout_cursor += len(data)
                else:
                    handle.stderr_cursor += len(data)
            return _response(200, {"schema": 1, "process_id": handle.process_id,
                "generation": profile.generation, "operation": operation,
                "state": "running" if handle.launcher.poll() is None else "exited",
                "result": {"data_bytes": base64.b64encode(data).decode("ascii"),
                    "eof": eof, "redacted": False},
                "expires_monotonic": min(handle.expires, self.monotonic() + 5.0)})
        if operation == "process.write":
            cursor = fields["sequence"]
            try:
                data = base64.b64decode(fields["data_bytes"], validate=True)
            except Exception:
                raise AuthorityDenied("process.write", "stdin data is malformed") from None
            if (type(cursor) is not int or cursor != handle.stdin_sequence or len(data) > 262144
                    or base64.b64encode(data).decode("ascii") != fields["data_bytes"]
                    or handle.launcher.stdin is None):
                raise AuthorityDenied("process.cursor", "stdin cursor or data length is invalid")
            with handle.lock or contextlib.nullcontext():
                fd = handle.launcher.stdin.fileno()
                _, writable, _ = select.select([], [fd], [], min(max(timeout, 0), .75))
                try:
                    written = os.write(fd, data) if writable else 0
                except BlockingIOError:
                    written = 0
                handle.stdin_cursor += written
                # A request sequence is consumed once admitted, even if the pipe
                # cannot currently accept bytes. The caller retries with a fresh
                # sequence, never replaying an ambiguous partial frame.
                handle.stdin_sequence += 1
            return _response(200, {"schema": 1, "process_id": handle.process_id,
                "generation": profile.generation, "operation": operation,
                "state": "running", "result": {"accepted_bytes": written,
                    "sequence": handle.stdin_sequence},
                "expires_monotonic": min(handle.expires, self.monotonic() + 5.0)})
        reason, grace = fields["reason"], fields["grace_seconds"]
        proof = self._stop(handle, timeout=min(timeout, max(.1, float(grace))))
        return _response(200, {"schema": 1, "process_id": handle.process_id,
            "generation": profile.generation, "operation": operation, "state": "stopped",
            "result": {"closed": proof.cleanup_verified,
                "reap_state": "reaped" if proof.cleanup_verified else "unverified"},
            "expires_monotonic": self.monotonic() + 5.0})

    def _watch_parent(self, handle: _Handle) -> None:
        poller = select.poll()
        poller.register(handle.parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while not handle.stopped:
            remaining = handle.expires - self.monotonic()
            if remaining <= 0 or poller.poll(min(250, max(1, int(remaining * 1000)))):
                self._stop(handle, timeout=5.0)
                return

    def _show(self, unit: str, prop: str) -> str:
        allowed = {"ControlGroup", "Description", "KillMode", "ProtectSystem", "PrivateTmp", "PrivateDevices",
            "NoNewPrivileges", "IPAddressDeny", "PrivateNetwork", "RestrictAddressFamilies", "ProtectHome",
            "ProtectProc", "ProcSubset", "User", "SupplementaryGroups", "RuntimeMaxUSec", "MemoryMax",
            "CPUQuotaPerSecUSec", "IOWeight"}
        if prop not in allowed or not unit.startswith("hermes-installer-") or not unit.endswith(".service"):
            raise AuthorityDenied("process.manager", "manager property or unit is outside the fixed set")
        result = subprocess.run([str(self.systemctl), "--system", "show", "--property=" + prop, "--value", unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True, timeout=1.5, check=False)
        if result.returncode or len(result.stdout) > 4096:
            raise AuthorityDenied("process.manager.readback", "manager readback failed")
        return result.stdout.decode("utf-8", "strict").strip()

    def _ctl(self, args: list[str], timeout: float) -> None:
        if not args or args[0] not in {"kill", "stop"} or not args[-1].startswith("hermes-installer-"):
            raise AuthorityDenied("process.manager", "manager control verb or unit is invalid")
        result = subprocess.run([str(self.systemctl), "--system", *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            close_fds=True, timeout=timeout, check=False)
        if result.returncode:
            raise AuthorityDenied("process.manager", "manager control failed")

    @staticmethod
    def _pids(cgroup: str) -> tuple[int, ...]:
        if not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise AuthorityDenied("process.cgroup", "invalid cgroup identity")
        root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        try:
            return tuple(int(value) for value in (root / "cgroup.procs").read_text().split())
        except (FileNotFoundError, NotADirectoryError):
            return ()
        except (OSError, ValueError):
            # A systemd transient unit can be collected between the cgroup
            # read and error handling. Treat only a vanished exact leaf as
            # empty; an extant but unreadable cgroup remains a hard denial.
            try:
                root.lstat()
            except (FileNotFoundError, NotADirectoryError):
                return ()
            raise AuthorityDenied("process.cgroup", "cgroup membership is unavailable") from None

    @staticmethod
    def _limits(cgroup: str) -> dict[str, str]:
        root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        out = {}
        for name in ("memory.max", "cpu.max", "io.weight"):
            try:
                out[name] = (root / name).read_text().strip()
            except OSError:
                out[name] = "unavailable"
        return out

    def _stop(self, handle: _Handle, *, timeout: float) -> ProcessCleanupProof:
        with handle.lock:
            if handle.stopped:
                with self._lock:
                    prior = self._finished.get(handle.process_id)
                if prior and prior[0] == handle.profile.generation:
                    return prior[2]
                raise AuthorityDenied("process.cleanup", "stopped handle has no retained cleanup proof")
            deadline = time.monotonic() + min(max(timeout, .1), 10)
            try:
                owned = self._show(handle.unit, "ControlGroup") == handle.cgroup
            except AuthorityDenied:
                owned = False
            if owned:
                if self._pids(handle.cgroup):
                    try:
                        self._ctl(["kill", "--kill-whom=all", "--signal=SIGTERM", handle.unit], 1)
                    except AuthorityDenied:
                        if self._pids(handle.cgroup):
                            raise AuthorityDenied("process.cleanup", "owned unit rejected termination") from None
                if self._pids(handle.cgroup):
                    time.sleep(min(.25, max(0, deadline - time.monotonic())))
                if self._pids(handle.cgroup):
                    try:
                        self._ctl(["kill", "--kill-whom=all", "--signal=SIGKILL", handle.unit], 1)
                    except AuthorityDenied:
                        if self._pids(handle.cgroup):
                            raise AuthorityDenied("process.cleanup", "owned unit rejected forced termination") from None
                if self._pids(handle.cgroup):
                    try:
                        self._ctl(["stop", handle.unit], min(1, max(.1, deadline - time.monotonic())))
                    except AuthorityDenied:
                        if self._pids(handle.cgroup):
                            raise AuthorityDenied("process.cleanup", "owned unit could not be stopped") from None
            while self._pids(handle.cgroup) and time.monotonic() < deadline:
                time.sleep(.02)
            cgroup_empty = not self._pids(handle.cgroup)
            if not cgroup_empty:
                raise AuthorityDenied("process.cleanup", "manager failed to empty the owned cgroup")
            while not _pidfd_exited(handle.child_pidfd) and time.monotonic() < deadline:
                select.select([handle.child_pidfd], [], [], min(.02, max(0, deadline - time.monotonic())))
            main_gone = _pidfd_exited(handle.child_pidfd)
            if not main_gone:
                raise AuthorityDenied("process.cleanup", "main process pidfd remained live after cgroup cleanup")
            handle.stopped = True
            health_observations: list[str] = []
            with self._lock:
                self._handles.pop(handle.process_id, None)
                for control_handle, retained in tuple(self._health_controls.items()):
                    if retained[1] is handle:
                        self._health_controls.pop(control_handle, None)
                        observation = self._health_observation_handles.pop(control_handle, None)
                        if observation is not None:
                            health_observations.append(observation)
            if self.native_health_start_authority is not None:
                for observation in health_observations:
                    try:
                        self.native_health_start_authority.health_observer.cancel_selected_health(observation)
                    except Exception:
                        pass
            for stream in (handle.launcher.stdin, handle.launcher.stdout, handle.launcher.stderr):
                if stream:
                    stream.close()
            if handle.launcher.poll() is None:
                handle.launcher.kill()
            try:
                handle.launcher.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                raise AuthorityDenied("process.cleanup", "root service launcher did not reap") from None
            if handle.launcher.returncode is None:
                raise AuthorityDenied("process.cleanup", "root service launcher was not reaped")
            if handle.native_loader_observation_handle is not None:
                store = self.native_loader_observation_store
                if store is None:
                    raise AuthorityDenied("native.loader", "loader observer disappeared during cleanup")
                store.revoke_process(handle.process_id, handle.profile.generation)
            try:
                _remove_artifact_mount(handle.artifact_mount_dir)
            finally:
                try:
                    if handle.native_mount_source is not None:
                        self._remove_native_staging(handle.native_mount_source)
                finally:
                    if handle.xauthority_mount_source is not None:
                        self._remove_native_staging(handle.xauthority_mount_source)
            parent_gone = _pidfd_exited(handle.parent_pidfd)
            evidence = {
                "process_id": handle.process_id, "generation": handle.profile.generation,
                "cgroup": handle.cgroup, "cgroup_empty": cgroup_empty,
                "main_pidfd_gone": main_gone, "parent_pidfd_gone": parent_gone,
                "launcher_reaped": True,
            }
            proof = ProcessCleanupProof(handle.process_id, handle.profile.generation,
                handle.cgroup, cgroup_empty, main_gone, parent_gone, True, True,
                canonical_digest(evidence), self.monotonic())
            for fd in (handle.parent_pidfd, handle.child_pidfd, handle.network_namespace_fd):
                try:
                    if fd is not None:
                        os.close(fd)
                except OSError:
                    pass
            with self._lock:
                self._finished[handle.process_id] = (handle.profile.generation,
                    self.monotonic() + 600, proof)
                now = self.monotonic()
                self._finished = {key: item for key, item in self._finished.items() if item[1] > now}
            return proof

    def _stop_partial(self, unit: str, launcher: subprocess.Popen[bytes]) -> None:
        if unit.startswith("hermes-installer-"):
            cgroup = f"/system.slice/{unit}"
            for command in (["kill", "--kill-whom=all", "--signal=SIGKILL", unit],
                            ["stop", unit]):
                try:
                    self._ctl(command, 1)
                except AuthorityDenied:
                    # systemd returns failure when --collect already removed
                    # a transient unit. Treat that as clean only when the
                    # exact registered system.slice cgroup is absent/empty.
                    if self._pids(cgroup):
                        raise AuthorityDenied("process.cleanup", "partial unit cgroup could not be stopped") from None
        if launcher.poll() is None:
            launcher.kill()
        try:
            launcher.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            raise AuthorityDenied("process.cleanup", "partial root service launcher did not reap") from None
        if unit.startswith("hermes-installer-") and self._pids(f"/system.slice/{unit}"):
            raise AuthorityDenied("process.cleanup", "partial unit cgroup remains populated")


def build_managed_process_handlers(profiles: Mapping[str, ManagedProfileCustody], **kwargs: Any):
    """Build the fixed root process handler map for AuthorityService."""
    return create_managed_process_handler(profiles, **kwargs).handlers()


def create_managed_process_handler(profiles: Mapping[str, ManagedProfileCustody], **kwargs: Any) -> ManagedProcessEffectHandler:
    """Create the root registry object shared by process, inspect and connector handlers."""
    return ManagedProcessEffectHandler(profiles, **kwargs)


@dataclass(frozen=True, slots=True)
class _RootPreparedBuildRuntime:
    """Private kernel limits projected from the prepared setup template."""
    profile_id: str
    owner_uid: int
    owner_gid: int
    service_user: str
    generation: str
    max_lifetime_seconds: float
    memory_max_bytes: int
    cpu_quota_percent: int | None
    io_weight: int | None
    tasks_max: int


@dataclass(frozen=True, slots=True)
class _RootApplicationBuildInputs:
    """Private path projection for the shared kernel build executor.

    This is data assembled from the sealed descriptor bundle by the app-only
    adapter. It is not an authority context or a substitute admission DTO.
    """
    target_id: str
    generation: str
    service_generation_digest: str
    build_service_enrollment_id: str
    build_service_generation: str
    enrollment_id: str
    operation_id: str
    selection_digest: str
    source_artifact_id: str
    source_sha256: str
    source_root: Path
    source_tree_files: tuple[Any, ...]
    source_tree_manifest_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    toolchain_root: Path
    toolchain_tree_files: tuple[Any, ...]
    toolchain_tree_manifest_sha256: str
    builder_artifact_id: str
    builder_sha256: str
    builder_executable: Path
    argv_recipe: tuple[Any, ...]
    environment: Mapping[str, str]
    output_specs: Mapping[str, Any]
    output_root: Path
    output_root_id: str
    output_owner_uid: int
    output_owner_gid: int
    max_lifetime_seconds: int
    output_root_fd: int


@dataclass(frozen=True, slots=True)
class _ApplicationHeldMember:
    relative_path: str
    fd: int
    sha256: str
    size_bytes: int
    executable: bool
    receipt_handle: str
    kind: str = "file"
    link_target: str | None = None


class ManagedBuildJobRunner:
    """Run one root-selected build recipe in a private transient systemd unit.

    This adapter deliberately uses a separate, terminal lifecycle from the
    long-lived profile handles. The consumed ``process.start`` authorization
    admits exactly one immutable build selection; this object then observes,
    cancels, and reaps that already-admitted unit as root-private bookkeeping.
    It never exposes status/read/stop controls or accepts a path/argv from the
    worker.
    """

    _LOG_LIMIT = 1024 * 1024
    _MOUNT_RESERVATION = ("__fixed-build-mounts__", "__root__")
    _MOUNTS = {
        "builder": "/run/hermes-installer/build/builder",
        "source": "/run/hermes-installer/build/source",
        "toolchain": "/run/hermes-installer/build/toolchain",
        "work": "/run/hermes-installer/build/work",
        "output": "/run/hermes-installer/build/output",
    }
    # These targets are reserved for the finite application-environment build
    # adapter. They are intentionally absent from the generic/Xpra recipe
    # grammar and are supplied only by that adapter after selection recheck.
    _APPLICATION_MOUNTS = {
        "packages": "/run/hermes-installer/build/packages",
        "backend": "/run/hermes-installer/build/backend",
        "uv": "/run/hermes-installer/build/uv",
        "recipe": "/run/hermes-installer/build/recipe",
        "python-runtime": "/run/hermes-installer/build/python-runtime",
    }

    def __init__(self, manager: ManagedProcessEffectHandler, *,
                 process_profile_resolver: Callable[[str, str], ManagedProfileCustody],
                 diagnostic_observer: Callable[[bytes], None] | None = None):
        if not isinstance(manager, ManagedProcessEffectHandler) or not callable(process_profile_resolver):
            raise ValueError("build runner requires the root process manager and protected profile resolver")
        if diagnostic_observer is not None and not callable(diagnostic_observer):
            raise ValueError("build diagnostic observer must be callable")
        self.manager = manager
        self.process_profile_resolver = process_profile_resolver
        self._diagnostic_observer = diagnostic_observer
        self._active: set[tuple[str, str]] = set()
        self._records: dict[str, Mapping[str, Any]] = {}
        self._lock = threading.RLock()
        self._setup_build_grant_issuer: Any | None = None
        self._application_build_grant_issuer: Any | None = None

    def bind_application_build_grant_issuer(self, issuer: Any) -> None:
        """Bind the one root app-setup admission issuer for the fixed runner."""
        from hermes_installer.authority.application_build_admission import RootApplicationSetupBuildGrantIssuer
        if (os.geteuid() != 0 or type(issuer) is not RootApplicationSetupBuildGrantIssuer
                or not callable(getattr(getattr(issuer, "admission", None), "verify_current", None))):
            raise ValueError("application setup build grant issuer is unavailable")
        with self._lock:
            if self._application_build_grant_issuer not in (None, issuer):
                raise ValueError("a different root application build issuer is already bound")
            self._application_build_grant_issuer = issuer

    def run_selected_application_runtime_build(self, inputs: Any, *, selection: Any,
                                               grant: Any, timeout: float,
                                               cancelled: Callable[[], bool]):
        """Run a fixed application environment build from root-held input FDs.

        This app-only route consumes the sealed application setup grant and
        stages verified descriptors into private root-owned trees. It never
        accepts a worker effect, host path, caller argv, or generic profile
        lookup. The shared executor provides the transient-unit/PIDFD/cgroup,
        namespace, mount, deadline and cleanup proof.
        """
        from hermes_installer.authority.application_build_admission import (
            RootApplicationBuildInputMember, RootApplicationSetupBuildGrant, RootResolvedApplicationBuildInputs,
            RootSelectedApplicationBuildSelection,
        )
        from hermes_installer.authority.build_execution import (
            BUILD_MOUNT_TARGETS, ManagedBuildResult, _BuildInputTreeFile,
            managed_process_identity_digest,
        )
        from hermes_installer.authority.types import AuthorityDenied
        from hermes_installer.protected_enrollment import FixedBuildProfile

        with self._lock:
            issuer = self._application_build_grant_issuer
        if (os.geteuid() != 0 or not sys.platform.startswith("linux")
                or issuer is None or type(selection) is not RootSelectedApplicationBuildSelection
                or type(grant) is not RootApplicationSetupBuildGrant
                or type(inputs) is not RootResolvedApplicationBuildInputs
                or inputs._selection is not selection or inputs._registry is not issuer.admission
                or selection._registry is not issuer.admission
                or not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 600):
            raise AuthorityDenied("build.application", "selected application build admission is unavailable")

        registry = issuer.admission
        profile = selection.build_profile
        build_service = selection.build_service
        fixed_profiles = {
            "application-graphify-runtime-prepare-v1": ("graphify", "qualify-graphify-v1",
                "application-graphify-runtime-prepare:start"),
            "application-browser-use-runtime-prepare-v1": ("browser-use", "qualify-browser-use-v1",
                "application-browser-use-runtime-prepare:start"),
            "application-scrapegraph-ai-runtime-prepare-v1": ("scrapegraph-ai", "qualify-scrapegraph-v1",
                "application-scrapegraph-ai-runtime-prepare:start"),
            "application-hyperframes-runtime-prepare-v1": ("hyperframes", "qualify-hyperframes-v1",
                "application-hyperframes-runtime-prepare:start"),
        }
        finite = fixed_profiles.get(selection.build_profile_id)
        if (type(profile) is not FixedBuildProfile or finite is None
                or selection.application_id != finite[0] or selection.workflow_id != finite[1]
                or selection.target_id != finite[2] or selection.operation_id != selection.build_profile_id
                or selection.application_id == "hyperframes"
                or profile.target_id != selection.target_id or profile.generation.startswith("app-setup-") is False
                or profile.build_service_enrollment_id != selection.build_service_enrollment_id
                or profile.build_service_generation != selection.build_service_generation
                or profile.output_root_id != selection.output_root_receipt_handle
                or profile.output_owner_uid != inputs.output_owner_uid
                or selection.recipe_sha256 != grant.recipe_sha256
                or selection.controller_binding_handle != grant.controller_binding_handle
                or selection.builder_module.relative_path
                    != "lib/python/hermes_installer/authority/application_environment_builder.py"
                or selection.pm_uv.relative_path != "uv"):
            raise AuthorityDenied("build.application_binding", "application selection differs from its finite protected recipe")
        expected_argv = (
            {"build_path": {"mount_id": "builder", "relative_path": ""}},
            {"literal": "-I"},
            {"build_path": {"mount_id": "toolchain", "relative_path":
                             "hermes_installer/authority/application_environment_builder.py"}},
        )
        if (tuple(profile.argv_recipe) != expected_argv or dict(profile.environment)
                or set(profile.output_specs) != {"runtime-environment.tar"}
                or profile.output_specs["runtime-environment.tar"].relative_path != "runtime-environment.tar"
                or profile.output_specs["runtime-environment.tar"].kind != "file"):
            raise AuthorityDenied("build.application_recipe", "application build recipe is not the fixed offline driver")
        if (selection.pm_runtime_closure_sha256 != getattr(selection.pm_projection, "base_closure_sha256", None)
                or selection.pm_runtime_closure_sha256 != getattr(inputs, "pm_runtime_closure_sha256", None)
                or not inputs.python_runtime_members
                or len(inputs.runtime_toolchain_receipt_handles) != 2
                or inputs.uv_fd is None or inputs.uv_sha256 is None
                or inputs.uv_size_bytes is None):
            raise AuthorityDenied("build.application_runtime", "complete current PM runtime closure is unavailable")

        expected_pairs = (
            (inputs.selection_handle, selection.selection_handle),
            (inputs.application_id, selection.application_id),
            (inputs.build_profile_id, selection.build_profile_id),
            (inputs.runtime_preparation_selection_handle, selection.runtime_preparation_selection_handle),
            (inputs.plan_sha256, selection.plan_sha256),
            (inputs.target_id, selection.target_id), (inputs.operation_id, selection.operation_id),
            (inputs.setup_session_id, selection.setup_session_id),
            (inputs.transaction_handle, selection.transaction_handle),
            (inputs.prepared_generation_id, selection.prepared_generation_id),
            (inputs.prepared_generation_digest, selection.prepared_generation_digest),
            (inputs.source_receipt_handle, selection.source_receipt_handle),
            (inputs.source_manifest_sha256, selection.source_manifest_sha256),
            (inputs.pm_runtime_closure_sha256, selection.pm_runtime_closure_sha256),
            (inputs.lock_receipt_handle, selection.lock_receipt_handle),
            (inputs.lock_sha256, selection.lock_sha256),
            (inputs.package_closure_receipt_handle, selection.package_closure_receipt_handle),
            (inputs.build_backend_closure_receipt_handle, selection.build_backend_closure_receipt_handle),
            (inputs.recipe_sha256, selection.recipe_sha256),
            (inputs.builder_sha256, profile.builder_sha256),
            (inputs.builder_receipt_handle, selection.pm_runtime.receipt_handle),
            (inputs.driver_receipt_handle, selection.builder_module_receipt_handle),
            (inputs.driver_sha256, selection.builder_module_sha256),
            (inputs.driver_size_bytes, selection.builder_module.size_bytes),
            (inputs.runtime_toolchain_receipt_handles, selection.runtime_toolchain_receipt_handles),
            (inputs.uv_source_receipt_handle, selection.pm_uv.source_receipt_handle),
            (inputs.uv_artifact_id, selection.pm_uv.artifact_id),
            (inputs.build_service_id, selection.build_service_enrollment_id),
            (inputs.build_service_selection_handle, selection.build_service_selection_handle),
            (inputs.build_service_generation, selection.build_service_generation),
            (inputs.output_root_id, selection.output_root_receipt_handle),
            (inputs.controller_binding_handle, selection.controller_binding_handle),
            (inputs.output_owner_uid, build_service.service_uid),
            (inputs.output_owner_gid, build_service.service_gid),
        )
        if any(left != right for left, right in expected_pairs):
            raise AuthorityDenied("build.application_binding", "held application inputs differ from their sealed selection")
        python_executable_member = inputs.python_executable_member
        if (type(python_executable_member) is not RootApplicationBuildInputMember
                or python_executable_member.relative_path != "bin/python3.14"
                or python_executable_member.kind != "file" or python_executable_member.link_target is not None
                or python_executable_member.fd != inputs.builder_fd
                or python_executable_member.receipt_handle != inputs.builder_receipt_handle
                or python_executable_member.sha256 != inputs.builder_sha256
                or python_executable_member.size_bytes != inputs.builder_size_bytes
                or python_executable_member.executable is not True):
            raise AuthorityDenied("build.application_runtime", "PM interpreter member differs from its held executable")
        if (len(inputs.runtime_toolchain_receipt_handles) != 2
                or inputs.runtime_toolchain_receipt_handles[0] != inputs.builder_receipt_handle
                or inputs.runtime_toolchain_receipt_handles[1] != selection.pm_uv.receipt_handle):
            raise AuthorityDenied("build.application_runtime", "PM Python/uv receipts differ from the prepared toolchain")
        all_members = (inputs.source_members + inputs.package_members + inputs.backend_members
                       + inputs.python_runtime_members + (inputs.recipe_member,))
        if any(type(member) is not RootApplicationBuildInputMember for member in all_members):
            raise AuthorityDenied("build.application_input", "application input includes an unissued member descriptor")

        selection_digest = hashlib.sha256(json.dumps({
            "selection_handle": selection.selection_handle,
            "recipe_sha256": selection.recipe_sha256,
            "grant_id": grant.grant_id,
            "operation_id": selection.operation_id,
            "parameters": {},
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
        if (grant.selection_handle != selection.selection_handle
                or grant.target != selection.target_id or grant.operation_id != selection.operation_id
                or grant.parameters_digest != hashlib.sha256(b"{}").hexdigest()
                or grant.selection_handle != inputs.selection_handle):
            raise AuthorityDenied("build.application_grant", "one-use application setup grant does not bind this selection")

        # Check every controller fact from the registry-issued descriptor bundle.
        controller_fd = -1
        daemon_fd = -1
        output_fd = -1
        staging_root: Path | None = None
        active_key = (selection.target_id, profile.generation)
        try:
            controller_fd = os.dup(inputs.controller_pidfd)
            if (inputs.controller_pid != os.getpid() or inputs.controller_uid != 0
                    or self.manager._pidfd_target(controller_fd) != inputs.controller_pid
                    or _pidfd_exited(controller_fd)
                    or _pid_identity(inputs.controller_pid)[0] != inputs.controller_start_ticks):
                raise AuthorityDenied("build.application_controller", "selected setup controller identity is stale")
            status = Path(f"/proc/{inputs.controller_pid}/status").read_text().splitlines()
            uids = next(line for line in status if line.startswith("Uid:")).split()[1:]
            gids = next(line for line in status if line.startswith("Gid:")).split()[1:]
            if (not uids or not gids or any(int(value) != inputs.controller_uid for value in uids)
                    or any(int(value) != inputs.controller_gid for value in gids)):
                raise AuthorityDenied("build.application_controller", "selected setup controller credentials changed")
            if (build_service.verify_current() is not build_service
                    or profile.build_service_generation != build_service.generation
                    or profile.service_generation_digest != selection.prepared_generation_digest):
                raise AuthorityDenied("build.application_service", "prepared application build service is stale")
            try:
                account = pwd.getpwuid(inputs.output_owner_uid)
                groups = os.getgrouplist(account.pw_name, account.pw_gid)
            except (KeyError, OSError):
                raise AuthorityDenied("build.application_service", "dedicated application build account is unavailable") from None
            if (account.pw_gid != inputs.output_owner_gid or set(groups) != {inputs.output_owner_gid}
                    or inputs.output_owner_uid <= 0):
                raise AuthorityDenied("build.application_service", "application build service account is not exclusive")

            fresh = registry.verify_current(selection)
            try:
                if (type(fresh) is not RootResolvedApplicationBuildInputs
                        or fresh.selection_handle != selection.selection_handle
                        or fresh._registry is not registry
                        or fresh._selection is not selection
                        or fresh.controller_pid != inputs.controller_pid
                        or fresh.controller_start_ticks != inputs.controller_start_ticks
                        or fresh.controller_uid != inputs.controller_uid
                        or fresh.controller_gid != inputs.controller_gid
                        or self._application_inputs_fingerprint(fresh)
                            != self._application_inputs_fingerprint(inputs)):
                    raise AuthorityDenied("build.application_current", "current application input projection changed")
            finally:
                fresh.close()

            # Stage into a unique root-only input root. These files are copied
            # exclusively from sealed/readonly root-held FDs by digest.
            parent = Path("/run/hermes-installer/application-build-inputs")
            self.manager._ensure_root_runtime_directory(parent, 0o700)
            staging_root = parent / secrets.token_hex(24)
            staging_root.mkdir(mode=0o700)
            os.chown(staging_root, 0, 0)
            os.chmod(staging_root, 0o700)
            source_root = staging_root / "source"
            toolchain_root = staging_root / "toolchain"
            package_root = staging_root / "packages"
            backend_root = staging_root / "backend"
            uv_root = staging_root / "uv"
            recipe_root = staging_root / "recipe"
            python_root = staging_root / "python-runtime"
            source_rows = self._stage_application_held_members(inputs.source_members, source_root)
            package_rows = self._stage_application_held_members(inputs.package_members, package_root)
            backend_rows = self._stage_application_held_members(inputs.backend_members, backend_root)
            if not backend_rows and inputs.build_backend_closure_receipt_handle is not None:
                raise AuthorityDenied("build.application_backend", "selected backend closure has no held members")
            if not package_rows or not backend_rows:
                raise AuthorityDenied("build.application_closure", "complete offline app/backend wheels are unavailable")
            toolchain_root.mkdir(mode=0o700)
            driver_member = _ApplicationHeldMember(
                "hermes_installer/authority/application_environment_builder.py", inputs.driver_fd,
                inputs.driver_sha256, inputs.driver_size_bytes, False, selection.builder_module_receipt_handle)
            toolchain_rows = self._stage_application_held_members((driver_member,), toolchain_root)
            uv_member = _ApplicationHeldMember("uv", inputs.uv_fd, inputs.uv_sha256,
                                               inputs.uv_size_bytes, True, inputs.runtime_toolchain_receipt_handles[1])
            uv_rows = self._stage_application_held_members((uv_member,), uv_root)
            if len(uv_rows) != 1 or uv_rows[0].path != "uv":
                raise AuthorityDenied("build.application_uv", "selected uv executable staging failed")
            recipe_root.mkdir(mode=0o700)
            recipe_member = inputs.recipe_member
            if (recipe_member.relative_path != "application-build-input.json"
                    or hashlib.sha256(inputs.recipe_config_bytes).hexdigest() != inputs.recipe_config_sha256
                    or recipe_member.sha256 != inputs.recipe_config_sha256
                    or recipe_member.size_bytes != len(inputs.recipe_config_bytes)):
                raise AuthorityDenied("build.application_recipe", "held application build config differs from recipe receipt")
            try:
                config = json.loads(inputs.recipe_config_bytes.decode("utf-8"),
                                    object_pairs_hook=_reject_duplicate_json_keys)
            except (UnicodeError, ValueError, json.JSONDecodeError):
                raise AuthorityDenied("build.application_recipe", "held application config is not strict JSON") from None
            config_fields = {
                "schema", "application_id", "source_manifest_sha256", "lock_sha256",
                "package_closure_sha256", "backend_closure_sha256", "packages",
                "backend_packages", "recipe_sha256", "uv_executable_sha256",
                "python_executable_sha256", "python_runtime_closure_sha256",
                "python_runtime_executable_relative_path",
            }
            if (not isinstance(config, dict) or set(config) != config_fields
                    or type(config.get("schema")) is not int or config["schema"] != 1
                    or config.get("application_id") != selection.application_id
                    or config.get("source_manifest_sha256") != selection.source_manifest_sha256
                    or config.get("lock_sha256") != selection.lock_sha256
                    or config.get("package_closure_sha256") != selection.package_closure.package_closure_sha256
                    or config.get("backend_closure_sha256") != getattr(selection.backend_closure, "backend_closure_sha256", None)
                    or config.get("recipe_sha256") != selection.recipe_sha256
                    or config.get("uv_executable_sha256") != inputs.uv_sha256
                    or config.get("python_executable_sha256") != inputs.builder_sha256
                    or config.get("python_runtime_closure_sha256") != selection.pm_runtime_closure_sha256
                    or config.get("python_runtime_executable_relative_path") != "bin/python3.14"):
                raise AuthorityDenied("build.application_recipe", "held application config differs from exact selected inputs")
            self._validate_application_wheel_config(config, inputs.package_members,
                                                    inputs.backend_members)
            recipe_rows = self._stage_application_held_members((recipe_member,), recipe_root)

            # PM interpreter is both argv[0] and a receipt-bound runtime member.
            runtime_members = tuple(inputs.python_runtime_members) + (inputs.python_executable_member,)
            python_root.mkdir(mode=0o700)
            python_rows = self._stage_application_held_members(
                runtime_members, python_root, allow_symlinks=True)
            if not any(row.path == "bin/python3.14" and row.sha256 == inputs.builder_sha256
                       for row in python_rows):
                raise AuthorityDenied("build.application_runtime", "PM base interpreter is absent from staged closure")

            builder_dir = staging_root / "builder"
            builder_dir.mkdir(mode=0o700)
            builder_file = builder_dir / "python3.14"
            self._copy_application_held_file(inputs.builder_fd, inputs.builder_sha256,
                                              inputs.builder_size_bytes, builder_file, executable=True)
            output_fd = os.dup(inputs.output_root_fd)
            output_info = os.fstat(output_fd)
            output_cap_fd = selection.output_root.open_current()
            try:
                output_cap_info = os.fstat(output_cap_fd)
            finally:
                os.close(output_cap_fd)
            if ((output_info.st_dev, output_info.st_ino) != (output_cap_info.st_dev, output_cap_info.st_ino)
                    or not stat.S_ISDIR(output_info.st_mode) or output_info.st_uid != inputs.output_owner_uid
                    or output_info.st_gid != inputs.output_owner_gid or stat.S_IMODE(output_info.st_mode) != 0o700
                    or os.listdir(output_fd)):
                raise AuthorityDenied("build.application_output", "held application output root is stale or nonempty")

            internal_inputs = _RootApplicationBuildInputs(
                target_id=selection.target_id, generation=profile.generation,
                service_generation_digest=profile.service_generation_digest,
                build_service_enrollment_id=selection.build_service_enrollment_id,
                build_service_generation=selection.build_service_generation,
                enrollment_id=selection.setup_session_id, operation_id=selection.operation_id,
                selection_digest=selection_digest, source_artifact_id=profile.source_artifact_id,
                source_sha256=profile.source_sha256, source_root=source_root,
                source_tree_files=source_rows,
                source_tree_manifest_sha256=self._application_tree_manifest(source_rows),
                toolchain_artifact_id=profile.toolchain_artifact_id,
                toolchain_sha256=profile.toolchain_sha256, toolchain_root=toolchain_root,
                toolchain_tree_files=toolchain_rows,
                toolchain_tree_manifest_sha256=self._application_tree_manifest(toolchain_rows),
                builder_artifact_id=profile.builder_artifact_id,
                builder_sha256=profile.builder_sha256, builder_executable=builder_file,
                argv_recipe=profile.argv_recipe, environment=profile.environment,
                # The shared transient-unit core needs a mount source string;
                # it is anchored to this still-open descriptor, never a
                # selection or caller path. The core separately validates
                # output_root_fd identity and contents before and after run.
                output_specs=profile.output_specs,
                output_root=Path(f"/proc/self/fd/{output_fd}"),
                output_root_id=inputs.output_root_id, output_owner_uid=inputs.output_owner_uid,
                output_owner_gid=inputs.output_owner_gid,
                max_lifetime_seconds=profile.max_lifetime_seconds, output_root_fd=output_fd)

            additional_mounts = {
                "packages": package_root, "backend": backend_root, "uv": uv_root,
                "recipe": recipe_root, "python-runtime": python_root,
            }
            root_profile = _RootPreparedBuildRuntime(
                profile_id=selection.build_profile_id, owner_uid=inputs.output_owner_uid,
                owner_gid=inputs.output_owner_gid, service_user=account.pw_name,
                generation=profile.generation,
                max_lifetime_seconds=float(profile.max_lifetime_seconds),
                memory_max_bytes=536_870_912, cpu_quota_percent=100, io_weight=100,
                tasks_max=64)
            daemon_fd = os.pidfd_open(os.getpid(), 0)

            def revalidate_app() -> bool:
                if cancelled() or _pidfd_exited(daemon_fd) or _pidfd_exited(controller_fd):
                    return False
                try:
                    now_inputs = registry.verify_current(selection)
                    try:
                        same = (type(now_inputs) is RootResolvedApplicationBuildInputs
                            and now_inputs._selection is selection
                            and self._application_inputs_fingerprint(now_inputs)
                                == self._application_inputs_fingerprint(inputs)
                            and now_inputs.controller_pidfd >= 0
                            and self.manager._pidfd_target(now_inputs.controller_pidfd) == inputs.controller_pid
                            and not _pidfd_exited(now_inputs.controller_pidfd))
                    finally:
                        now_inputs.close()
                    return (same and build_service.verify_current() is build_service
                            and self.manager._pidfd_target(controller_fd) == inputs.controller_pid
                            and _pid_identity(inputs.controller_pid)[0] == inputs.controller_start_ticks)
                except Exception:
                    return False

            reservation = (selection.target_id, profile.generation)
            with self._lock:
                if reservation in self._active or self._MOUNT_RESERVATION in self._active:
                    raise AuthorityDenied("build.application", "fixed app build mounts are already reserved")
                self._active.update((reservation, self._MOUNT_RESERVATION))
            try:
                consumed = False
                def launch_admission_current() -> bool:
                    nonlocal consumed
                    if not revalidate_app() or issuer.monotonic() >= grant.expires_monotonic:
                        return False
                    if not consumed:
                        try:
                            issuer.consume(grant, selection)
                        except Exception:
                            return False
                        consumed = True
                    return (issuer._issued.get(grant.grant_id) is grant
                            and grant.grant_id in issuer._spent)
                return self._run_one(
                    internal_inputs, root_profile, None, None, os.getpid(), daemon_fd,
                    float(timeout), cancelled, ManagedBuildResult, managed_process_identity_digest,
                    BUILD_MOUNT_TARGETS,
                    root_currentness=revalidate_app,
                    root_selection_digest=selection_digest,
                    root_effect_check=launch_admission_current,
                    output_root_fd=output_fd,
                    additional_readonly_mounts=additional_mounts,
                    require_root_effect=True)
            finally:
                with self._lock:
                    self._active.discard(reservation)
                    self._active.discard(self._MOUNT_RESERVATION)
        except AuthorityDenied:
            raise
        except Exception:
            raise AuthorityDenied("build.application", "root application build admission failed closed") from None
        finally:
            for fd in (output_fd, controller_fd, daemon_fd):
                if type(fd) is int and fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            with contextlib.suppress(Exception):
                inputs.close()
            if staging_root is not None:
                with contextlib.suppress(Exception):
                    shutil.rmtree(staging_root)

    def bind_setup_build_grant_issuer(self, issuer: Any) -> None:
        """Bind the one root setup issuer used by the fixed Xpra build path."""
        from hermes_installer.authority.xpra_build_selection import RootXpraSetupBuildGrantIssuer
        if (os.geteuid() != 0 or type(issuer) is not RootXpraSetupBuildGrantIssuer
                or not callable(getattr(getattr(issuer, "producer", None), "revalidate", None))):
            raise ValueError("setup build grant issuer is unavailable")
        with self._lock:
            if self._setup_build_grant_issuer not in (None, issuer):
                raise ValueError("a different root setup build issuer is already bound")
            self._setup_build_grant_issuer = issuer

    def run_selected_setup_build(self, inputs: Any, *, selection: Any, grant: Any,
                                 controller_pidfd: int, timeout: float,
                                 cancelled: Callable[[], bool]):
        """Run only the prepared Xpra setup recipe under its distinct sealed grant.

        This path never fabricates a worker HostContext or EffectAuthorization,
        and never resolves or registers an active worker process profile. The
        setup selection, one-use issuer, held output directory FD and live
        setup-controller PIDFD form a separate root-owned admission.
        """
        from hermes_installer.authority.bootstrap_runtime_factory import RootPreparedBuildServiceSelection
        from hermes_installer.authority.build_execution import (
            BUILD_MOUNT_TARGETS, ManagedBuildResult, _canonical, managed_process_identity_digest,
        )
        from hermes_installer.authority.xpra_build_selection import (
            BUILD_OPERATION_ID, BUILD_TARGET, RootSelectedXpraBuildSelection,
            RootXpraSetupBuildGrant, XpraBuildSelectionDenied,
        )

        manager = self.manager
        with self._lock:
            issuer = self._setup_build_grant_issuer
        if (os.geteuid() != 0 or not sys.platform.startswith("linux")
                or type(selection) is not RootSelectedXpraBuildSelection
                or type(grant) is not RootXpraSetupBuildGrant
                or issuer is None or type(getattr(selection, "setup_build_subject", None))
                    is not RootPreparedBuildServiceSelection
                or type(controller_pidfd) is not int or controller_pidfd < 0
                or not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 300):
            raise AuthorityDenied("build.setup", "root setup build admission is unavailable")
        subject = selection.setup_build_subject
        profile = selection.build_profile
        expected_input_fields = (
            "target_id", "generation", "service_generation_digest", "build_service_enrollment_id",
            "build_service_generation", "operation_id", "selection_digest", "source_artifact_id",
            "source_sha256", "source_root", "source_tree_files", "source_tree_manifest_sha256",
            "toolchain_artifact_id", "toolchain_sha256", "toolchain_root", "toolchain_tree_files",
            "toolchain_tree_manifest_sha256", "builder_artifact_id", "builder_sha256",
            "builder_executable", "argv_recipe", "environment", "output_specs", "output_root",
            "output_root_fd", "output_root_id", "output_owner_uid", "output_owner_gid",
            "max_lifetime_seconds",
        )
        if any(not hasattr(inputs, name) for name in expected_input_fields):
            raise AuthorityDenied("build.inputs", "selected setup build inputs are incomplete")
        if (inputs.target_id != BUILD_TARGET or inputs.operation_id != BUILD_OPERATION_ID
                or inputs.output_root is not None or type(inputs.output_root_fd) is not int
                or inputs.output_root_fd < 0 or inputs.output_root_id != selection.output_root_id
                or inputs.build_service_enrollment_id != subject.id
                or inputs.build_service_generation != subject.generation
                or inputs.output_owner_uid != subject.service_uid
                or inputs.output_owner_gid != subject.service_gid
                or inputs.generation != profile.generation
                or inputs.service_generation_digest != profile.service_generation_digest
                or inputs.builder_artifact_id != selection.builder_artifact_id
                or inputs.builder_sha256 != selection.builder_sha256
                or inputs.source_artifact_id != selection.source_artifact_id
                or inputs.source_sha256 != selection.source_sha256
                or inputs.toolchain_artifact_id != selection.toolchain_artifact_id
                or inputs.toolchain_sha256 != selection.toolchain_sha256
                or inputs.source_tree_manifest_sha256 != selection.compiled_source_manifest_sha256
                or inputs.original_source_manifest_sha256 != selection.source_manifest_sha256
                or inputs.builder_executable != selection.pm_runtime.python_path
                or inputs.max_lifetime_seconds > profile.max_lifetime_seconds
                or tuple(inputs.argv_recipe) != tuple(profile.argv_recipe)
                or dict(inputs.environment) != dict(profile.environment)
                or not isinstance(inputs.selection_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", inputs.selection_digest)
                or type(inputs.max_lifetime_seconds) is not int
                or not 1 <= inputs.max_lifetime_seconds <= 300):
            raise AuthorityDenied("build.setup_binding", "setup build inputs differ from the sealed Xpra selection")
        source_rows = tuple(getattr(selection.source.tree, "tree_files", ()))
        expected_source_files = {
            item.path: item for item in source_rows if getattr(item, "kind", "file") == "file"
        }
        provided_source_files = {getattr(item, "path", None): item for item in inputs.source_tree_files}
        if (set(provided_source_files) != set(expected_source_files)
                or any((getattr(provided_source_files[name], "sha256", None),
                        getattr(provided_source_files[name], "size_bytes", None),
                        getattr(provided_source_files[name], "executable", None))
                       != (expected_source_files[name].sha256, expected_source_files[name].size_bytes,
                           expected_source_files[name].executable)
                       for name in expected_source_files)):
            raise AuthorityDenied("build.setup_source", "staged source projection differs from the selected archive")
        module_receipt = selection.module_receipt
        toolchain_rows = tuple(inputs.toolchain_tree_files)
        if (len(toolchain_rows) != 1
                or getattr(toolchain_rows[0], "path", None) != module_receipt.relative_path
                or getattr(toolchain_rows[0], "sha256", None) != module_receipt.sha256
                or getattr(toolchain_rows[0], "size_bytes", None) != module_receipt.size_bytes
                or getattr(toolchain_rows[0], "executable", None) is not False):
            raise AuthorityDenied("build.setup_toolchain", "staged transform module differs from its installed receipt")
        expected_specs = set(profile.output_specs)
        if set(inputs.output_specs) != expected_specs or any(
                getattr(inputs.output_specs[name], "relative_path", None)
                    != profile.output_specs[name].relative_path
                or getattr(inputs.output_specs[name], "kind", None) != profile.output_specs[name].kind
                or getattr(inputs.output_specs[name], "maximum_bytes", None)
                    != profile.output_specs[name].maximum_bytes
                or getattr(inputs.output_specs[name], "executable_role", None)
                    != profile.output_specs[name].executable_role
                or getattr(inputs.output_specs[name], "target_facts", None)
                    != profile.output_specs[name].target_facts
                for name in expected_specs):
            raise AuthorityDenied("build.setup_outputs", "setup output specification differs from the fixed recipe")
        expected_digest = hashlib.sha256(_canonical({
            "selection_handle": selection.selection_handle,
            "recipe_sha256": selection.recipe_sha256,
            "grant_id": grant.grant_id,
            "operation_id": BUILD_OPERATION_ID,
            "parameters": {},
        })).hexdigest()
        if inputs.selection_digest != expected_digest:
            raise AuthorityDenied("build.setup_binding", "setup build request digest is not canonical")

        output_fd = controller_fd = -1
        daemon_lifetime_fd = -1
        try:
            output_fd = os.dup(inputs.output_root_fd)
            controller_fd = os.dup(controller_pidfd)
            output_stat = os.fstat(output_fd)
            capability_fd = selection.output_root.open_current()
            try:
                capability_stat = os.fstat(capability_fd)
            finally:
                os.close(capability_fd)
            if ((output_stat.st_dev, output_stat.st_ino) != (capability_stat.st_dev, capability_stat.st_ino)
                    or not stat.S_ISDIR(output_stat.st_mode) or output_stat.st_uid != subject.service_uid
                    or output_stat.st_gid != subject.service_gid or stat.S_IMODE(output_stat.st_mode) != 0o700
                    or os.listdir(output_fd)):
                raise AuthorityDenied("build.output", "prepared output-root descriptor is stale or not fresh")
            if manager._pidfd_target(controller_fd) != selection._session._factory.session_store._live(
                    selection._session._handle).record["root_actor_identity"]["pid"] or _pidfd_exited(controller_fd):
                raise AuthorityDenied("build.controller", "selected setup controller PIDFD is not current")
            daemon_lifetime_fd = os.pidfd_open(os.getpid(), 0)
            producer = getattr(issuer, "producer", None)
            if (producer is None or getattr(producer, "session", None) is not selection._session
                    or subject.verify_current() != subject):
                raise AuthorityDenied("build.setup_subject", "prepared build subject is no longer current")

            # Grant consumption is the one-use start admission. All checks that
            # can run before it are complete; after it, only this method owns
            # the terminal lifecycle and output descriptor.
            issuer.consume(grant, selection)
            root_profile = _RootPreparedBuildRuntime(
                profile_id=subject.profile_id, owner_uid=subject.service_uid,
                owner_gid=subject.service_gid, service_user=pwd.getpwuid(subject.service_uid).pw_name,
                generation=subject.generation, max_lifetime_seconds=min(300.0, float(inputs.max_lifetime_seconds)),
                memory_max_bytes=536_870_912, cpu_quota_percent=None, io_weight=None,
                tasks_max=64,
            )
            groups = os.getgrouplist(root_profile.service_user, subject.service_gid)
            if pwd.getpwuid(subject.service_uid).pw_gid != subject.service_gid or set(groups) != {subject.service_gid}:
                raise AuthorityDenied("build.setup_subject", "prepared build service account changed")
            output_path = Path(f"/proc/self/fd/{output_fd}")
            fd_inputs = replace(inputs, output_root=output_path)

            def revalidate_setup() -> bool:
                if cancelled() or _pidfd_exited(controller_fd) or _pidfd_exited(daemon_lifetime_fd):
                    return False
                try:
                    producer.revalidate(selection)
                    current_subject = subject.verify_current()
                    current_live = selection._session._factory.session_store._live(selection._session._handle)
                    return (current_subject == subject
                            and current_live.record.get("root_actor_identity", {}).get("pid")
                                == manager._pidfd_target(controller_fd))
                except Exception:
                    return False

            reservation = (BUILD_TARGET, subject.generation)
            with self._lock:
                if reservation in self._active or self._MOUNT_RESERVATION in self._active:
                    raise AuthorityDenied("build.setup", "fixed setup build mounts are already reserved")
                self._active.update((reservation, self._MOUNT_RESERVATION))
            try:
                return self._run_one(
                    fd_inputs, root_profile, None, None, os.getpid(), daemon_lifetime_fd,
                    float(timeout), cancelled, ManagedBuildResult, managed_process_identity_digest,
                    BUILD_MOUNT_TARGETS, root_currentness=revalidate_setup,
                    root_selection_digest=inputs.selection_digest, output_root_fd=output_fd,
                    root_effect_check=lambda: (issuer._issued.get(grant.grant_id) is grant
                        and grant.grant_id in issuer._spent
                        and issuer.monotonic() < grant.expires_monotonic
                        and revalidate_setup()),
                    require_root_effect=True,
                )
            finally:
                with self._lock:
                    self._active.discard(reservation)
                    self._active.discard(self._MOUNT_RESERVATION)
        except (OSError, XpraBuildSelectionDenied):
            raise AuthorityDenied("build.setup", "prepared Xpra setup build admission failed") from None
        finally:
            for fd in (output_fd, controller_fd, daemon_lifetime_fd):
                if type(fd) is int and fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)

    def run_selected_build(self, inputs: Any, *, context: HostContext,
                           authorization: EffectAuthorization, peer_pid: int,
                           peer_pidfd: int, timeout: float,
                           cancelled: Callable[[], bool]):
        from hermes_installer.authority.build_execution import (
            BUILD_MOUNT_TARGETS, ManagedBuildResult, managed_process_identity_digest,
        )

        start = self.manager.monotonic()
        if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                or not callable(cancelled) or type(peer_pid) is not int or peer_pid <= 0
                or type(peer_pidfd) is not int or peer_pidfd < 0
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not math.isfinite(timeout) or timeout <= 0
                or not sys.platform.startswith("linux") or os.geteuid() != 0):
            raise AuthorityDenied("build.runner", "root Linux build runner inputs are unavailable")
        required_input_fields = (
            "target_id", "generation", "service_generation_digest", "enrollment_id",
            "operation_id", "selection_digest", "source_artifact_id", "source_sha256",
            "source_root", "source_tree_files", "source_tree_manifest_sha256",
            "toolchain_artifact_id", "toolchain_sha256", "toolchain_root",
            "toolchain_tree_files", "toolchain_tree_manifest_sha256", "builder_artifact_id",
            "builder_sha256", "builder_executable", "argv_recipe", "environment",
            "output_root", "output_root_id", "output_owner_uid", "max_lifetime_seconds",
            "output_owner_gid", "output_specs",
        )
        if any(not hasattr(inputs, name) for name in required_input_fields):
            raise AuthorityDenied("build.inputs", "root build catalog returned an incomplete immutable recipe")
        service_enrollment = getattr(inputs, "build_service_enrollment_id", None)
        service_generation = getattr(inputs, "build_service_generation", None)
        if (not isinstance(service_enrollment, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", service_enrollment)
                or not isinstance(service_generation, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", service_generation)
                or type(inputs.max_lifetime_seconds) is not int or not 1 <= inputs.max_lifetime_seconds <= 600
                or type(inputs.output_owner_uid) is not int or inputs.output_owner_uid <= 0
                or type(inputs.output_owner_gid) is not int or inputs.output_owner_gid <= 0
                or any(not isinstance(getattr(inputs, field), str)
                       or not re.fullmatch(r"[0-9a-f]{64}", getattr(inputs, field))
                       for field in ("service_generation_digest", "selection_digest", "source_sha256",
                                     "source_tree_manifest_sha256", "toolchain_sha256",
                                     "toolchain_tree_manifest_sha256", "builder_sha256"))
                or isinstance(timeout, bool) or not 0 < timeout <= 600):
            raise AuthorityDenied("build.service_join", "build record has no protected service enrollment join")
        if (authorization.operation != "process.start" or context.operation != "process.start"
                or authorization.capability != "hermes-profile-invoke"
                or authorization.request_digest != inputs.selection_digest
                or authorization.enrollment_id != inputs.enrollment_id
                or context.enrollment_id != inputs.enrollment_id
                or authorization.generation != inputs.generation
                or context.generation != inputs.generation
                or authorization.target != inputs.target_id
                or authorization.profile_id != context.profile_id
                or authorization.uid != context.uid
                or context.final_payload_digest != inputs.selection_digest):
            raise AuthorityDenied("build.authorization", "consumed start authorization does not bind the selected build")
        if (_pidfd_exited(peer_pidfd) or self.manager._pidfd_target(peer_pidfd) != peer_pid):
            raise AuthorityDenied("build.parent", "build requester is no longer live")
        try:
            # The build catalog joins the selected build target and build
            # generation to a separate protected service enrollment. The
            # resolver performs that join and returns the service profile;
            # never treat the build record's generation as the service epoch.
            profile = self.process_profile_resolver(inputs.target_id, inputs.generation)
        except Exception:
            raise AuthorityDenied("build.service_join", "root build service enrollment is unavailable") from None
        if (not isinstance(profile, ManagedProfileCustody)
                or self.manager.profiles.get(profile.profile_id) is not profile
                or profile.enrollment_id != service_enrollment
                or profile.generation != service_generation
                or profile.operation_targets is None
                or profile.operation_targets.get("process.start") != inputs.target_id
                or profile.owner_uid != inputs.output_owner_uid
                or profile.owner_gid != inputs.output_owner_gid
                or profile.owner_uid <= 0 or profile.owner_uid == context.uid
                or profile.owner_uid == 0
                or type(profile.memory_max_bytes) is not int
                or type(profile.cpu_quota_percent) is not int
                or type(profile.io_weight) is not int):
            raise AuthorityDenied("build.service_join", "build service identity does not match its protected enrollment")
        try:
            account = pwd.getpwuid(profile.owner_uid)
            groups = os.getgrouplist(account.pw_name, account.pw_gid)
        except (KeyError, OSError):
            raise AuthorityDenied("build.service_identity", "dedicated build service account is unavailable") from None
        if (account.pw_gid != profile.owner_gid or set(groups) != {profile.owner_gid}
                or account.pw_name != profile.service_user):
            raise AuthorityDenied("build.service_identity", "build service account or exclusive primary group changed")

        target_generation = (inputs.target_id, service_generation)
        with self._lock:
            if target_generation in self._active or self._MOUNT_RESERVATION in self._active:
                raise AuthorityDenied("build.generation", "fixed build mount targets already have an active job")
            self._active.add(target_generation)
            self._active.add(self._MOUNT_RESERVATION)
        try:
            return self._run_one(inputs, profile, context, authorization, peer_pid,
                                 peer_pidfd, float(timeout), cancelled,
                                 ManagedBuildResult, managed_process_identity_digest,
                                 BUILD_MOUNT_TARGETS)
        finally:
            with self._lock:
                self._active.discard(target_generation)
                self._active.discard(self._MOUNT_RESERVATION)

    def run_attested_cpython39_probe(self, inputs: Any, build_result: Any, *,
                                     timeout: float,
                                     cancelled: Callable[[], bool]):
        """Run the sole enrolled-output ABI probe as root-private build bookkeeping.

        This is not a public process effect. It can only follow a successful
        build terminal receipt retained by this runner, and all executable,
        mount, UID/GID, argv and output limits are constants selected here.
        """
        from hermes_installer.authority.build_execution import managed_process_identity_digest
        from hermes_installer.authority.build_probe import (
            ManagedBuildProbeResult, _PROBE_ARGV, _read_selected_executable,
        )

        manager = self.manager
        if (not callable(cancelled) or isinstance(timeout, bool)
                or not isinstance(timeout, (int, float)) or not math.isfinite(timeout)
                or not 0 < timeout <= 15 or not sys.platform.startswith("linux") or os.geteuid() != 0):
            raise AuthorityDenied("build.python_probe", "fixed root CPython probe inputs are unavailable")
        if (getattr(inputs, "target_id", None) != "coral-cpython-build:start"
                or getattr(inputs, "operation_id", None) != "coral-cpython39-source-build-v1"
                or getattr(inputs, "build_service_enrollment_id", None) is None
                or getattr(inputs, "build_service_generation", None) is None
                or type(getattr(inputs, "output_owner_uid", None)) is not int
                or type(getattr(inputs, "output_owner_gid", None)) is not int):
            raise AuthorityDenied("build.python_probe", "probe is not bound to the fixed CPython build selection")
        terminal_id = getattr(build_result, "terminal_success_record_id", None)
        if (not terminal_id or getattr(build_result, "exit_code", None) != 0
                or getattr(build_result, "timed_out", True) or getattr(build_result, "cancelled", True)
                or getattr(build_result, "cleanup_verified", False) is not True):
            raise AuthorityDenied("build.python_probe", "probe requires a clean successful build terminal")
        with self._lock:
            record = self._records.get(terminal_id)
            if record is None:
                raise AuthorityDenied("build.python_probe", "build terminal is not owned by this root runner")
            record = dict(record)
        try:
            profile = self.process_profile_resolver(inputs.target_id, inputs.generation)
        except Exception:
            raise AuthorityDenied("build.service_join", "selected build service generation is unavailable") from None
        if (not isinstance(profile, ManagedProfileCustody)
                or self.manager.profiles.get(profile.profile_id) is not profile
                or record.get("target") != inputs.target_id
                or record.get("generation") != inputs.generation
                or record.get("selection_digest") != inputs.selection_digest
                or record.get("service_generation") != inputs.build_service_generation
                or profile.enrollment_id != inputs.build_service_enrollment_id
                or profile.generation != inputs.build_service_generation
                or profile.operation_targets is None
                or profile.operation_targets.get("process.start") != inputs.target_id
                or profile.owner_uid != inputs.output_owner_uid
                or profile.owner_gid != inputs.output_owner_gid
                or record.get("uid") != profile.owner_uid or record.get("gid") != profile.owner_gid
                or record.get("uid") != getattr(build_result, "uid", None)
                or record.get("generation") != getattr(build_result, "generation", None)
                or record.get("cleanup") is not True
                or record.get("exit_code") != 0 or record.get("timed_out") is not False
                or record.get("cancelled") is not False
                or record.get("exit_code") != getattr(build_result, "exit_code", None)
                or record.get("timed_out") != getattr(build_result, "timed_out", None)
                or record.get("cancelled") != getattr(build_result, "cancelled", None)
                or record.get("cleanup") != getattr(build_result, "cleanup_verified", None)
                or record.get("process_identity_digest") != build_result.process_identity_digest
                or record.get("process_id") != build_result.process_id
                or record.get("pid") != build_result.pid
                or record.get("start_ticks") != build_result.start_ticks
                or record.get("cgroup") != build_result.cgroup_id
                or record.get("mount_ns") != build_result.mount_namespace_inode
                or record.get("network_ns") != build_result.network_namespace_inode
                or record.get("limits") != getattr(build_result, "kernel_limits", None)
                or record.get("log_digest") != getattr(build_result, "bounded_log_digest", None)
                or record.get("log_bytes") != getattr(build_result, "log_bytes", None)
                or record.get("output_root_id") != inputs.output_root_id
                or record.get("output_root_path") != str(Path(inputs.output_root))):
            raise AuthorityDenied("build.python_probe", "build receipt does not match the protected current profile")
        if (type(profile.memory_max_bytes) is not int or type(profile.cpu_quota_percent) is not int
                or type(profile.io_weight) is not int or profile.owner_uid <= 0
                or profile.owner_gid <= 0 or isinstance(profile.max_lifetime_seconds, bool)
                or not isinstance(profile.max_lifetime_seconds, (int, float))
                or not math.isfinite(profile.max_lifetime_seconds) or profile.max_lifetime_seconds <= 0):
            raise AuthorityDenied("build.service_identity", "selected build resource identity is incomplete")
        try:
            account = pwd.getpwuid(profile.owner_uid)
            groups = os.getgrouplist(account.pw_name, account.pw_gid)
        except (KeyError, OSError):
            raise AuthorityDenied("build.service_identity", "selected build service account is unavailable") from None
        if account.pw_gid != profile.owner_gid or set(groups) != {profile.owner_gid}:
            raise AuthorityDenied("build.service_identity", "selected build group is no longer exclusive")

        executable = Path(inputs.output_root) / "runtime/bin/python3.9"
        executable_sha256, executable_size, executable_info, output_info = _read_selected_executable(
            inputs, executable)
        if (record.get("output_root_device") != output_info.st_dev
                or record.get("output_root_inode") != output_info.st_ino
                or record.get("output_root_path") != str(Path(inputs.output_root))):
            raise AuthorityDenied("build.python_probe", "selected output root changed after build completion")
        if cancelled():
            raise AuthorityDenied("build.expired", "fixed CPython probe was cancelled before launch")
        reservation = (inputs.target_id, profile.generation)
        with self._lock:
            if reservation in self._active or self._MOUNT_RESERVATION in self._active:
                raise AuthorityDenied("build.generation", "another build action owns the fixed build mount namespace")
            self._active.add(reservation)
            self._active.add(self._MOUNT_RESERVATION)

        job_id = uuid.uuid4().hex
        unit = "hermes-installer-build-probe-" + job_id + ".service"
        cgroup = "/system.slice/" + unit
        probe_lifetime = min(float(timeout), 15.0, float(profile.max_lifetime_seconds))
        deadline = manager.monotonic() + probe_lifetime
        job_root = Path("/run/hermes-installer/build-jobs") / ("probe-" + job_id)
        work = job_root / "work"
        empty_source = job_root / "source"
        empty_toolchain = job_root / "toolchain"
        launcher: subprocess.Popen[bytes] | None = None
        selector = None
        main_pidfd: int | None = None
        main_pid: int | None = None
        start_ticks = mount_ns = network_ns = 0
        observed_cgroup = ""
        limits: dict[str, str] = {}
        cgroup_limits: dict[str, str] = {}
        log = bytearray()
        stderr_output = bytearray()
        timed_out = False
        was_cancelled = False
        cgroup_empty = pidfd_gone = launcher_reaped = False
        unit_started = False
        startup_gate_verified = False
        ready_marker = b"HERMES_BUILD_PROBE_READY_V1\n"
        combined_output_bytes = 0
        try:
            current = self.process_profile_resolver(inputs.target_id, inputs.generation)
            if (current is not profile or manager.profiles.get(profile.profile_id) is not profile
                    or manager.monotonic() >= deadline or cancelled()):
                raise AuthorityDenied("build.generation", "build profile changed before the fixed probe")
            self._prepare_mount_targets()
            manager._ensure_root_runtime_directory(Path("/run/hermes-installer/build-jobs"), 0o700)
            job_root.mkdir(mode=0o700)
            os.chown(job_root, 0, 0)
            os.chmod(job_root, 0o700)
            for directory in (work, empty_source, empty_toolchain):
                directory.mkdir(mode=0o700)
                os.chown(directory, profile.owner_uid, profile.owner_gid)
                os.chmod(directory, 0o700)
            mount_targets = dict(self._MOUNTS)
            argv = [mount_targets["builder"], *_PROBE_ARGV]
            properties = [
                "--property=Type=exec", f"--property=RuntimeMaxSec={probe_lifetime:.3f}s",
                "--property=KillMode=control-group", "--property=ProtectSystem=strict",
                "--property=ProtectHome=tmpfs", "--property=PrivateTmp=yes",
                "--property=ProtectProc=invisible", "--property=ProcSubset=pid",
                "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes",
                "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
                "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
                "--property=RestrictNamespaces=user", "--property=RestrictAddressFamilies=AF_UNIX",
                "--property=PrivateNetwork=yes", "--property=IPAddressDeny=any",
                "--property=MountFlags=private", "--property=PrivateMounts=yes",
                f"--property=User={profile.service_user}", "--property=SupplementaryGroups=",
                "--property=Description=HermesInstaller CPython probe " + job_id,
                "--property=WorkingDirectory=" + mount_targets["work"],
                "--property=BindReadOnlyPaths=" + str(executable) + ":" + mount_targets["builder"],
                "--property=BindReadOnlyPaths=" + str(empty_source) + ":" + mount_targets["source"],
                "--property=BindReadOnlyPaths=" + str(empty_toolchain) + ":" + mount_targets["toolchain"],
                "--property=BindPaths=" + str(work) + ":" + mount_targets["work"],
                "--property=BindReadOnlyPaths=" + str(inputs.output_root) + ":" + mount_targets["output"],
                "--property=InaccessiblePaths=-/etc/hermes-installer -/var/lib/hermes-installer -/etc/ssh -/etc/ssl/private",
            ]
            if profile.memory_max_bytes is not None:
                properties.append(f"--property=MemoryMax={profile.memory_max_bytes}")
            if profile.cpu_quota_percent is not None:
                properties.append(f"--property=CPUQuota={profile.cpu_quota_percent}%")
            if profile.io_weight is not None:
                properties.append(f"--property=IOWeight={profile.io_weight}")
            manager_env = subprocess.run([str(manager.systemctl), "--system", "show-environment"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=min(1.0, max(.1, deadline-manager.monotonic())), check=False)
            if manager_env.returncode or len(manager_env.stdout) > 65536:
                raise AuthorityDenied("build.environment", "system manager environment could not be cleared")
            manager_keys = {line.split("=", 1)[0] for line in manager_env.stdout.decode("utf-8", "replace").splitlines()
                            if "=" in line and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.split("=", 1)[0])}
            manager_keys.update({"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET", "WATCHDOG_USEC",
                "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME", "SHELL", "PWD", "SYSTEMD_EXEC_PID",
                "MEMORY_PRESSURE_WATCH", "MEMORY_PRESSURE_WRITE", "LC_CTYPE"})
            if sum(len(key) + 1 for key in manager_keys) > 60000:
                raise AuthorityDenied("build.environment", "manager environment exceeds the fixed probe clear bound")
            if manager_keys:
                properties.append("--property=UnsetEnvironment=" + " ".join(sorted(manager_keys)))
            command = [str(manager.systemd_run), "--system", "--unit=" + unit,
                "--quiet", "--service-type=exec", "--wait", "--pipe", *properties,
                "--setenv=LANG=C", "--setenv=LC_ALL=C", "--setenv=HOME=/tmp",
                "--setenv=TMPDIR=/tmp", "--setenv=PATH=/usr/bin:/bin", *argv]
            launcher = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                close_fds=True, shell=False)
            unit_started = True
            import selectors as selectors_module
            selector = selectors_module.DefaultSelector()
            assert launcher.stdout is not None and launcher.stderr is not None
            os.set_blocking(launcher.stdout.fileno(), False)
            os.set_blocking(launcher.stderr.fileno(), False)
            selector.register(launcher.stdout, selectors_module.EVENT_READ, "stdout")
            selector.register(launcher.stderr, selectors_module.EVENT_READ, "stderr")
            capture_inputs = SimpleNamespace(builder_executable=executable, builder_sha256=executable_sha256)
            while launcher.poll() is None:
                if cancelled() or manager.monotonic() >= deadline:
                    was_cancelled = cancelled()
                    timed_out = not was_cancelled
                    break
                if manager.profiles.get(profile.profile_id) is not profile:
                    raise AuthorityDenied("build.generation", "build service profile changed during probe")
                if self.process_profile_resolver(inputs.target_id, inputs.generation) is not profile:
                    raise AuthorityDenied("build.generation", "build service generation changed during probe")
                if main_pid is None:
                    observed = self._capture_build_identity(
                        unit, cgroup, capture_inputs, profile, output_readonly=True)
                    if observed is not None:
                        main_pid = observed["pid"]
                        start_ticks = observed["ticks"]
                        observed_cgroup = observed["cgroup"]
                        mount_ns = observed["mount_ns"]
                        network_ns = observed["network_ns"]
                        limits = observed["limits"]
                        cgroup_limits = observed["cgroup_limits"]
                        main_pidfd = observed["pidfd"]
                for key, _ in selector.select(.02):
                    chunk = os.read(key.fileobj.fileno(), 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    destination = log if key.data == "stdout" else stderr_output
                    combined_output_bytes += len(chunk)
                    if combined_output_bytes > 4096:
                        raise AuthorityDenied("build.python_probe", "CPython probe output exceeded its bound")
                    destination.extend(chunk)
                if not startup_gate_verified and bytes(stderr_output).startswith(ready_marker):
                    if bytes(stderr_output) != ready_marker:
                        raise AuthorityDenied("build.python_probe", "CPython startup marker was not exact")
                    if main_pid is not None and main_pidfd is not None:
                        if launcher.stdin is None:
                            raise AuthorityDenied("build.python_probe", "CPython startup gate has no owned input")
                        launcher.stdin.write(b"\x01")
                        launcher.stdin.flush()
                        launcher.stdin.close()
                        startup_gate_verified = True
            if was_cancelled or timed_out:
                self._terminate_unit(unit, cgroup, launcher)
            if launcher.poll() is None:
                try:
                    launcher.wait(timeout=max(.1, min(2.0, deadline-manager.monotonic()+2.0)))
                except subprocess.TimeoutExpired:
                    launcher.kill()
                    launcher.wait(timeout=1.0)
            if selector is not None:
                for key in list(selector.get_map().values()):
                    while True:
                        try:
                            chunk = os.read(key.fileobj.fileno(), 4096)
                        except BlockingIOError:
                            break
                        if not chunk:
                            break
                        destination = log if key.data == "stdout" else stderr_output
                        combined_output_bytes += len(chunk)
                        if combined_output_bytes > 4096:
                            raise AuthorityDenied("build.python_probe", "CPython probe output exceeded its bound")
                        destination.extend(chunk)
            exit_code = launcher.returncode
            launcher_reaped = exit_code is not None
            if manager._pids(cgroup):
                self._terminate_unit(unit, cgroup, launcher)
            cgroup_empty = not manager._pids(cgroup)
            if main_pidfd is not None:
                end = time.monotonic() + 2.0
                while not _pidfd_exited(main_pidfd) and time.monotonic() < end:
                    select.select([main_pidfd], [], [], .02)
                pidfd_gone = _pidfd_exited(main_pidfd)
            if (not cgroup_empty or not pidfd_gone or not launcher_reaped or not main_pid
                    or not observed_cgroup or not start_ticks or not mount_ns or not network_ns
                    or not limits or not cgroup_limits or not startup_gate_verified):
                raise AuthorityDenied("build.python_probe", "probe terminal cleanup or process identity is unproven")
            if timed_out or was_cancelled or exit_code != 0 or bytes(stderr_output) != ready_marker:
                raise AuthorityDenied("build.python_probe", "isolated CPython ABI probe did not exit cleanly")
            after_sha, after_size, after_executable, after_root = _read_selected_executable(inputs, executable)
            if ((after_sha, after_size, after_executable.st_dev, after_executable.st_ino,
                 after_root.st_dev, after_root.st_ino)
                    != (executable_sha256, executable_size, executable_info.st_dev, executable_info.st_ino,
                        output_info.st_dev, output_info.st_ino)):
                raise AuthorityDenied("build.python_probe", "CPython output changed during isolated probing")
            identity = managed_process_identity_digest(
                process_id=job_id, generation=inputs.generation, uid=profile.owner_uid,
                pid=main_pid, start_ticks=start_ticks, cgroup_id=observed_cgroup,
                mount_namespace_inode=mount_ns, network_namespace_inode=network_ns)
            probe_terminal_id = uuid.uuid4().hex
            stdout = bytes(log)
            probe_evidence = {
                "terminal_success_record_id": probe_terminal_id,
                "build_terminal_success_record_id": terminal_id,
                "build_process_identity_digest": build_result.process_identity_digest,
                "process_identity_digest": identity, "process_id": job_id,
                "target": inputs.target_id, "generation": inputs.generation,
                "service_generation": profile.generation, "output_root_id": inputs.output_root_id,
                "output_root_path": str(Path(inputs.output_root)),
                "output_root_device": output_info.st_dev, "output_root_inode": output_info.st_ino,
                "executable_sha256": executable_sha256, "executable_size_bytes": executable_size,
                "uid": profile.owner_uid, "gid": profile.owner_gid,
                "pid": main_pid, "start_ticks": start_ticks, "cgroup": observed_cgroup,
                "mount_ns": mount_ns, "network_ns": network_ns, "exit_code": 0,
                "cleanup": True, "limits": limits, "cgroup_limits": cgroup_limits,
                "log_digest": hashlib.sha256(stdout).hexdigest(), "log_bytes": len(stdout),
                "startup_gate_verified": startup_gate_verified,
            }
            with self._lock:
                self._records[probe_terminal_id] = probe_evidence
            return ManagedBuildProbeResult(
                terminal_success_record_id=probe_terminal_id,
                build_terminal_success_record_id=terminal_id,
                build_process_identity_digest=build_result.process_identity_digest,
                process_identity_digest=identity,
                process_id=job_id, generation=inputs.generation,
                uid=profile.owner_uid, gid=profile.owner_gid, pid=main_pid,
                start_ticks=start_ticks, exit_code=0, cleanup_verified=True,
                cgroup_id=observed_cgroup, mount_namespace_inode=mount_ns,
                network_namespace_inode=network_ns, output_root_id=inputs.output_root_id,
                output_root_device=output_info.st_dev, output_root_inode=output_info.st_ino,
                executable_sha256=executable_sha256, executable_size_bytes=executable_size,
                bounded_log_digest=hashlib.sha256(stdout).hexdigest(), log_bytes=len(stdout),
                startup_gate_verified=startup_gate_verified,
                stdout=stdout)
        except BaseException:
            if unit_started and launcher is not None:
                with contextlib.suppress(Exception):
                    self._terminate_unit(unit, cgroup, launcher)
            raise
        finally:
            if selector is not None:
                with contextlib.suppress(Exception):
                    selector.close()
            if launcher is not None:
                for stream in (launcher.stdout, launcher.stderr):
                    if stream is not None:
                        with contextlib.suppress(Exception):
                            stream.close()
                if launcher.poll() is None:
                    with contextlib.suppress(Exception):
                        launcher.kill()
                with contextlib.suppress(Exception):
                    launcher.wait(timeout=1.0)
            if main_pidfd is not None:
                with contextlib.suppress(OSError):
                    os.close(main_pidfd)
            if job_root.exists():
                shutil.rmtree(job_root)
            if unit_started:
                subprocess.run([str(manager.systemctl), "--system", "stop", unit],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                    timeout=1.0, check=False)
                subprocess.run([str(manager.systemctl), "--system", "reset-failed", unit],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                    timeout=1.0, check=False)
            with self._lock:
                self._active.discard(reservation)
                self._active.discard(self._MOUNT_RESERVATION)

    def _run_one(self, inputs: Any, profile: Any, context: HostContext | None,
                 authorization: EffectAuthorization | None, peer_pid: int, peer_pidfd: int,
                 timeout: float, cancelled: Callable[[], bool], result_type: Any,
                 identity_digest: Callable[..., str], mount_targets: Mapping[str, str], *,
                 root_currentness: Callable[[], bool] | None = None,
                 root_selection_digest: str | None = None,
                 root_effect_check: Callable[[], bool] | None = None,
                 output_root_fd: int | None = None,
                 additional_readonly_mounts: Mapping[str, Path] | None = None,
                 require_root_effect: bool = False):
        manager = self.manager
        job_id = uuid.uuid4().hex
        service_generation = profile.generation
        unit = f"hermes-installer-build-{job_id}.service"
        cgroup = f"/system.slice/{unit}"
        # Authorization is checked again at the launch effect point below.
        # Once admitted, the one-use start effect owns this exact job; its
        # protected max lifetime is the terminal bookkeeping deadline. The
        # manager must never mint another public effect or extend the job.
        deadline = min(manager.monotonic() + timeout,
                       manager.monotonic() + float(inputs.max_lifetime_seconds),
                       manager.monotonic() + profile.max_lifetime_seconds)
        parent_fd = os.dup(peer_pidfd)
        unit_started = False
        launcher: subprocess.Popen[bytes] | None = None
        main_pidfd: int | None = None
        main_pid: int | None = None
        start_ticks = 0
        mount_ns = 0
        network_ns = 0
        observed_cgroup = ""
        kernel_limits: dict[str, str] = {}
        cgroup_limits: dict[str, str] = {}
        mounted: list[Path] = []
        output_root_info: os.stat_result | None = None
        job_root = Path("/run/hermes-installer/build-jobs") / job_id
        log = bytearray()
        selector = None
        timed_out = False
        was_cancelled = False
        exit_code: int | None = None
        launcher_reaped = False
        cgroup_empty = False
        pidfd_gone = False
        started = manager.monotonic()
        last_generation_check = float("-inf")
        capture_rejection: str | None = None

        def require_active() -> None:
            nonlocal last_generation_check
            if cancelled() or manager.monotonic() >= deadline or _pidfd_exited(parent_fd):
                raise AuthorityDenied("build.expired", "build lease, caller or service generation expired")
            if root_currentness is not None:
                now = manager.monotonic()
                if now - last_generation_check >= 0.25:
                    if not root_currentness():
                        raise AuthorityDenied("build.generation", "root setup selection or controller is no longer current")
                    last_generation_check = now
                return
            if self.manager.profiles.get(profile.profile_id) is not profile:
                raise AuthorityDenied("build.expired", "build lease, caller or service generation expired")
            now = manager.monotonic()
            if now - last_generation_check >= 0.25:
                try:
                    current = self.process_profile_resolver(inputs.target_id, inputs.generation)
                except Exception:
                    raise AuthorityDenied("build.generation", "active build service generation could not be revalidated") from None
                if not isinstance(current, ManagedProfileCustody) or current != profile:
                    raise AuthorityDenied("build.generation", "selected build service generation was revoked or replaced")
                last_generation_check = now

        try:
            require_active()
            self._verify_inputs(inputs)
            if output_root_fd is None:
                self._validate_output_root(Path(inputs.output_root), profile.owner_uid, profile.owner_gid)
                output_root_info = Path(inputs.output_root).lstat()
            else:
                output_root_info = os.fstat(output_root_fd)
                self._validate_output_root_fd(output_root_info, profile.owner_uid, profile.owner_gid)
                if os.listdir(output_root_fd):
                    raise AuthorityDenied("build.output", "selected output directory is not empty")
            extra_mounts = dict(additional_readonly_mounts or {})
            if (set(extra_mounts) - set(self._APPLICATION_MOUNTS)
                    or any(key not in mount_targets or mount_targets[key] != self._APPLICATION_MOUNTS[key]
                           for key in extra_mounts)):
                raise AuthorityDenied("build.mount", "application build mount set is outside its fixed allowlist")
            if set(mount_targets) != set(self._MOUNTS) | set(extra_mounts):
                raise AuthorityDenied("build.mount", "build mount targets differ from the selected fixed recipe")
            self._prepare_mount_targets(mount_targets)
            manager._ensure_root_runtime_directory(Path("/run/hermes-installer/build-jobs"), 0o700)
            job_root.mkdir(mode=0o700)
            os.chown(job_root, 0, 0)
            os.chmod(job_root, 0o700)
            work = job_root / "work"
            work.mkdir(mode=0o700)
            os.chown(work, profile.owner_uid, profile.owner_gid)
            os.chmod(work, 0o700)
            for child in ("home", "tmp", "source"):
                path = work / child
                path.mkdir(mode=0o700)
                os.chown(path, profile.owner_uid, profile.owner_gid)
                os.chmod(path, 0o700)
            self._copy_build_tree(Path(inputs.source_root), work / "source",
                                  inputs.source_tree_files, profile.owner_uid, profile.owner_gid)
            mount_inputs = {
                "builder": Path(inputs.builder_executable),
                "source": Path(inputs.source_root),
                "toolchain": Path(inputs.toolchain_root),
                "work": work,
                "output": Path(inputs.output_root),
            }
            mount_inputs.update({name: Path(path) for name, path in extra_mounts.items()})
            self._verify_file(mount_inputs["builder"], inputs.builder_sha256, executable=True)
            for name, path in mount_inputs.items():
                if name in {"source", "toolchain", "builder", *extra_mounts}:
                    self._protect_build_mount(path, readonly=True)
                else:
                    self._protect_build_mount(path, readonly=False)
                mounted.append(path)
            require_active()
            argv = self._resolve_build_argv(inputs.argv_recipe, mount_targets)
            if argv[0] != mount_targets["builder"]:
                raise AuthorityDenied("build.argv", "argv[0] does not resolve to the fixed selected builder")
            env = self._build_environment(inputs.environment, mount_targets)
            properties = [
                "--property=Type=exec", f"--property=RuntimeMaxSec={max(.1, deadline-manager.monotonic()):.3f}s",
                "--property=KillMode=control-group", "--property=ProtectSystem=strict",
                "--property=ProtectHome=tmpfs", "--property=PrivateTmp=yes",
                "--property=ProtectProc=invisible", "--property=ProcSubset=pid",
                "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes",
                "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
                "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
                "--property=RestrictNamespaces=user", "--property=RestrictAddressFamilies=AF_UNIX",
                "--property=PrivateNetwork=yes", "--property=IPAddressDeny=any",
                "--property=MountFlags=private", "--property=PrivateMounts=yes",
                f"--property=User={profile.service_user}", "--property=SupplementaryGroups=",
                "--property=Description=HermesInstaller build " + job_id,
                "--property=WorkingDirectory=" + mount_targets["work"],
                "--property=BindReadOnlyPaths=" + str(inputs.builder_executable) + ":" + mount_targets["builder"],
                "--property=BindReadOnlyPaths=" + str(inputs.source_root) + ":" + mount_targets["source"],
                "--property=BindReadOnlyPaths=" + str(inputs.toolchain_root) + ":" + mount_targets["toolchain"],
                "--property=BindPaths=" + str(work) + ":" + mount_targets["work"],
                "--property=BindPaths=" + (
                    f"/proc/{os.getpid()}/fd/{output_root_fd}" if output_root_fd is not None
                    else str(inputs.output_root)) + ":" + mount_targets["output"],
                # Every mask is optional on a clean development host: systemd
                # rejects the namespace if an unprefixed masked path is absent.
                "--property=InaccessiblePaths=-/etc/hermes-installer -/var/lib/hermes-installer -/etc/ssh -/etc/ssl/private",
            ]
            properties.extend(
                "--property=BindReadOnlyPaths=" + str(mount_inputs[name]) + ":" + mount_targets[name]
                for name in sorted(extra_mounts)
            )
            if profile.memory_max_bytes is not None:
                properties.append(f"--property=MemoryMax={profile.memory_max_bytes}")
            if profile.cpu_quota_percent is not None:
                properties.append(f"--property=CPUQuota={profile.cpu_quota_percent}%")
            if profile.io_weight is not None:
                properties.append(f"--property=IOWeight={profile.io_weight}")
            if getattr(profile, "tasks_max", None) is not None:
                properties.append(f"--property=TasksMax={profile.tasks_max}")
            env_args = ["--setenv=" + name + "=" + value for name, value in sorted(env.items())]
            # Drop manager/user-session variables before setting the closed build environment.
            manager_env = subprocess.run([str(manager.systemctl), "--system", "show-environment"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=min(2.0, max(.1, deadline - manager.monotonic())), check=False)
            if manager_env.returncode or len(manager_env.stdout) > 65536:
                raise AuthorityDenied("build.environment", "system manager environment could not be safely cleared")
            manager_keys = {line.split("=", 1)[0] for line in manager_env.stdout.decode("utf-8", "replace").splitlines()
                            if "=" in line and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.split("=", 1)[0])}
            manager_keys.update({"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET", "WATCHDOG_USEC",
                "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES", "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME", "SHELL", "PWD", "SYSTEMD_EXEC_PID",
                "MEMORY_PRESSURE_WATCH", "MEMORY_PRESSURE_WRITE", "LC_CTYPE"})
            unset = sorted(manager_keys - set(env))
            if sum(len(key) + 1 for key in unset) > 60000:
                raise AuthorityDenied("build.environment", "manager environment exceeds the safe clear bound")
            if unset:
                properties.append("--property=UnsetEnvironment=" + " ".join(unset))
            require_active()
            # Re-stat and rehash the builder and both immutable trees at the
            # effect point, after mounts and unit properties are prepared.
            self._verify_inputs(inputs)
            command = [str(manager.systemd_run), "--system", "--unit=" + unit,
                "--service-type=exec", "--wait", "--pipe",
                "--working-directory=" + mount_targets["work"], *properties, *env_args, *argv]
            require_active()
            if authorization is not None:
                if manager.monotonic() >= authorization.monotonic_expires_at:
                    raise AuthorityDenied("build.expired", "start authorization expired before the unit launch effect")
            elif require_root_effect:
                if root_effect_check is None or not root_effect_check():
                    raise AuthorityDenied("build.expired", "root setup build admission expired before launch")
            launcher = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
                close_fds=True, shell=False)
            unit_started = True
            import selectors as selectors_module
            selector = selectors_module.DefaultSelector()
            for stream_name, stream in (("stdout", launcher.stdout), ("stderr", launcher.stderr)):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, selectors_module.EVENT_READ, stream_name)
            started = manager.monotonic()
            while launcher.poll() is None:
                try:
                    require_active()
                except AuthorityDenied as exc:
                    if exc.code == "build.expired":
                        was_cancelled = cancelled() or _pidfd_exited(parent_fd)
                        timed_out = not was_cancelled
                        break
                    raise
                if main_pid is None:
                    observed = self._capture_build_identity(unit, cgroup, inputs, profile,
                                                            mount_targets=mount_targets)
                    if observed is not None:
                        main_pid = observed["pid"]
                        start_ticks = observed["ticks"]
                        observed_cgroup = observed["cgroup"]
                        mount_ns = observed["mount_ns"]
                        network_ns = observed["network_ns"]
                        kernel_limits = observed["limits"]
                        cgroup_limits = observed["cgroup_limits"]
                        main_pidfd = observed["pidfd"]
                    else:
                        capture_rejection = getattr(self, "_last_build_capture_rejection", "unknown")
                for key, _ in selector.select(.02):
                    data = os.read(key.fileobj.fileno(), 65536)
                    if data:
                        if len(log) + len(data) > self._LOG_LIMIT:
                            raise AuthorityDenied("build.logs", "build emitted more than the root log bound")
                        log.extend(data)
                    else:
                        selector.unregister(key.fileobj)
                if launcher.poll() is None and not selector.get_map():
                    time.sleep(.01)
            if was_cancelled or timed_out:
                self._terminate_unit(unit, cgroup, launcher)
            if launcher.poll() is None:
                try:
                    launcher.wait(timeout=max(.1, min(3.0, deadline-manager.monotonic()+3.0)))
                except subprocess.TimeoutExpired:
                    launcher.kill()
                    launcher.wait(timeout=1.0)
            # Drain the remaining pipe bytes without blocking or exceeding the cap.
            if selector is not None:
                for key in list(selector.get_map().values()):
                    stream = key.fileobj
                    while True:
                        try:
                            data = os.read(stream.fileno(), 65536)
                        except BlockingIOError:
                            break
                        if not data:
                            break
                        if len(log) + len(data) > self._LOG_LIMIT:
                            raise AuthorityDenied("build.logs", "build emitted more than the root log bound")
                        log.extend(data)
                    with contextlib.suppress(Exception):
                        selector.unregister(stream)
            exit_code = launcher.returncode
            launcher_reaped = exit_code is not None
            # systemd-run --wait holds its caller until the transient unit is
            # terminal; force cleanup of any surviving cgroup descendants.
            if manager._pids(cgroup):
                self._terminate_unit(unit, cgroup, launcher)
            cgroup_empty = not manager._pids(cgroup)
            if main_pidfd is None and main_pid is not None:
                try:
                    main_pidfd = os.pidfd_open(main_pid, 0)
                except OSError:
                    main_pidfd = None
            if main_pidfd is not None:
                deadline_cleanup = time.monotonic() + 3.0
                while not _pidfd_exited(main_pidfd) and time.monotonic() < deadline_cleanup:
                    select.select([main_pidfd], [], [], .02)
                pidfd_gone = _pidfd_exited(main_pidfd)
            else:
                pidfd_gone = main_pid is not None and main_pid not in manager._pids(cgroup)
            # The manager launcher must be reaped even on normal completion.
            if launcher.poll() is None:
                launcher.wait(timeout=1.0)
            launcher_reaped = launcher.returncode is not None
            if root_currentness is not None:
                # A setup build is not allowed to publish artifacts after its
                # prepared selection/controller has gone stale, even when the
                # child happened to exit cleanly at that boundary.
                require_active()
            output_root_after = os.fstat(output_root_fd) if output_root_fd is not None else Path(inputs.output_root).lstat()
            if (output_root_info is None or (output_root_info.st_dev, output_root_info.st_ino)
                    != (output_root_after.st_dev, output_root_after.st_ino)):
                raise AuthorityDenied("build.output", "selected output root changed before terminal attestation")
            missing_proof = [name for name, valid in (
                ("cgroup_empty", cgroup_empty), ("pidfd_gone", pidfd_gone),
                ("launcher_reaped", launcher_reaped), ("cgroup_identity", bool(observed_cgroup)),
                ("main_pid", bool(main_pid)), ("start_ticks", bool(start_ticks)),
                ("mount_namespace", bool(mount_ns)), ("network_namespace", bool(network_ns)),
                ("kernel_limits", bool(kernel_limits)),
            ) if not valid]
            if missing_proof:
                # Only stable field names leave the root handler; no host path,
                # PID, cgroup path, command output, or environment is included.
                if capture_rejection is not None:
                    missing_proof.append("capture_" + capture_rejection)
                if exit_code is not None:
                    missing_proof.append("exit_code_" + str(exit_code))
                output = bytes(log).decode("utf-8", "replace").casefold()
                diagnostic_sources = [output]
                diagnostic_bytes = [bytes(log)]
                if exit_code == 226:
                    try:
                        journal = subprocess.run([str(manager.systemctl), "--system", "status",
                            "--no-pager", "--full", unit], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                            timeout=1.0, check=False)
                        # `systemctl status` returns nonzero for a failed unit
                        # while still placing the diagnostic status on stdout.
                        if len(journal.stdout) <= 16384 and journal.stdout:
                            diagnostic_bytes.append(journal.stdout)
                            diagnostic_sources.append(journal.stdout.decode("utf-8", "replace").casefold())
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                for needle, category in (
                    ("mount namespacing", "mount_namespace_setup"),
                    ("network namespacing", "network_namespace_setup"),
                    ("failed to set up namespace", "namespace_setup"),
                    ("failed to set up mount", "mount_setup"),
                    ("failed to set up network", "network_setup"),
                    ("failed at step namespace", "namespace_setup"),
                    ("failed at step mount", "mount_setup"),
                    ("failed at step setgroups", "group_setup"),
                    ("permission denied", "permission_denied"),
                    ("no such file", "missing_runtime_input"),
                ):
                    if any(needle in source for source in diagnostic_sources):
                        missing_proof.append("systemd_" + category)
                        break
                if self._diagnostic_observer is not None:
                    # Root-only injected diagnostic sink for isolated fixture
                    # tests; normal production assembly leaves this unset.
                    with contextlib.suppress(Exception):
                        self._diagnostic_observer(b"\n".join(diagnostic_bytes))
                raise AuthorityDenied("build.cleanup", "terminal proof is incomplete: " + ",".join(missing_proof))
            finished = manager.monotonic()
            proc_id = job_id
            identity = identity_digest(process_id=proc_id, generation=inputs.generation,
                uid=profile.owner_uid, pid=main_pid, start_ticks=start_ticks, cgroup_id=observed_cgroup,
                mount_namespace_inode=mount_ns, network_namespace_inode=network_ns)
            log_digest = hashlib.sha256(bytes(log)).hexdigest()
            successful = exit_code == 0 and not timed_out and not was_cancelled
            terminal_id = uuid.uuid4().hex if successful else ""
            evidence = {
                "terminal_success_record_id": terminal_id, "target": inputs.target_id,
                "generation": inputs.generation, "service_generation": service_generation,
                "selection_digest": (authorization.request_digest if authorization is not None
                                     else root_selection_digest), "process_identity_digest": identity,
                "output_root_id": inputs.output_root_id,
                "output_root_path": ("<held-output-root-fd>" if output_root_fd is not None
                                     else str(Path(inputs.output_root))),
                "output_root_device": output_root_info.st_dev,
                "output_root_inode": output_root_info.st_ino,
                "process_id": proc_id, "uid": profile.owner_uid, "gid": profile.owner_gid,
                "pid": main_pid,
                "start_ticks": start_ticks, "cgroup": observed_cgroup,
                "mount_ns": mount_ns, "network_ns": network_ns, "exit_code": exit_code,
                "timed_out": timed_out, "cancelled": was_cancelled, "cleanup": cgroup_empty and pidfd_gone and launcher_reaped,
                "limits": kernel_limits, "cgroup_limits": cgroup_limits,
                "log_digest": log_digest, "log_bytes": len(log),
                "started": started, "finished": finished,
            }
            if successful:
                with self._lock:
                    self._records[terminal_id] = dict(evidence)
            return result_type(
                process_id=proc_id, generation=inputs.generation, uid=profile.owner_uid,
                pid=main_pid, start_ticks=start_ticks, exit_code=exit_code,
                timed_out=timed_out, cancelled=was_cancelled,
                cleanup_verified=bool(cgroup_empty and pidfd_gone and launcher_reaped),
                started_monotonic=started, finished_monotonic=finished,
                kernel_limits=dict(kernel_limits), terminal_success_record_id=terminal_id,
                process_identity_digest=identity, cgroup_id=observed_cgroup,
                mount_namespace_inode=mount_ns, network_namespace_inode=network_ns,
                bounded_log_digest=log_digest, log_bytes=len(log),
            )
        except BaseException:
            if unit_started and launcher is not None:
                with contextlib.suppress(Exception):
                    self._terminate_unit(unit, cgroup, launcher)
            raise
        finally:
            if selector is not None:
                with contextlib.suppress(Exception):
                    selector.close()
            if launcher is not None:
                for stream in (launcher.stdout, launcher.stderr, launcher.stdin):
                    if stream is not None:
                        with contextlib.suppress(Exception):
                            stream.close()
                if launcher.poll() is None:
                    with contextlib.suppress(Exception):
                        launcher.kill()
                with contextlib.suppress(Exception):
                    launcher.wait(timeout=1.0)
            for fd in (parent_fd, main_pidfd):
                if fd is not None:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            # Mount teardown follows unit death, and never recursively follows
            # worker-controlled paths. A leaked mount is a hard failure.
            for path in reversed(mounted):
                try:
                    self._umount_build(path)
                except OSError as exc:
                    raise AuthorityDenied("build.mount_cleanup", "private build input mount could not be removed") from exc
            if job_root.exists():
                shutil.rmtree(job_root)
            # The unique transient unit is not auto-collected, so status can
            # be inspected on failure. Remove its manager record after process
            # and mount cleanup on every path.
            subprocess.run([str(manager.systemctl), "--system", "stop", unit],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=1.0, check=False)
            subprocess.run([str(manager.systemctl), "--system", "reset-failed", unit],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=1.0, check=False)

    def _capture_build_identity(self, unit: str, cgroup: str, inputs: Any,
                                profile: ManagedProfileCustody, *,
                                output_readonly: bool = False,
                                mount_targets: Mapping[str, str] | None = None) -> Mapping[str, Any] | None:
        manager = self.manager
        pidfd: int | None = None
        def reject(reason: str) -> None:
            self._last_build_capture_rejection = reason
            return None
        try:
            output = subprocess.run([str(manager.systemctl), "--system", "show", unit,
                "-p", "MainPID", "-p", "ControlGroup"], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=.25, check=False)
        except (OSError, subprocess.TimeoutExpired):
            return reject("systemd_query")
        if output.returncode or len(output.stdout) > 4096:
            return reject("systemd_response")
        values = dict(line.split("=", 1) for line in output.stdout.decode("ascii", "ignore").splitlines()
                      if "=" in line)
        try:
            pid = int(values.get("MainPID", "0"))
            observed_cgroup = values.get("ControlGroup", "")
            if pid <= 1:
                return reject("main_pid_unavailable")
            if observed_cgroup != cgroup:
                return reject("cgroup_mismatch")
            ticks, actual_cgroup, device, inode = _pid_identity(pid)
            expected = Path(inputs.builder_executable).stat(follow_symlinks=False)
            exe_fd = os.open(f"/proc/{pid}/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                exe_info = os.fstat(exe_fd)
                hasher = hashlib.sha256()
                while chunk := os.read(exe_fd, 128 * 1024):
                    hasher.update(chunk)
                digest = hasher.hexdigest()
            finally:
                os.close(exe_fd)
            if ((device, inode, digest) != (expected.st_dev, expected.st_ino, inputs.builder_sha256)
                    or actual_cgroup != cgroup):
                return reject("executable_or_membership")
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            uid_fields = next(line for line in status if line.startswith("Uid:")).split()[1:]
            if len(uid_fields) != 4 or any(int(uid) != profile.owner_uid for uid in uid_fields):
                return reject("uid_mismatch")
            gid_fields = next(line for line in status if line.startswith("Gid:")).split()[1:]
            if len(gid_fields) != 4 or any(int(gid) != profile.owner_gid for gid in gid_fields):
                return reject("gid_mismatch")
            status_map = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                          for line in status if ":" in line}
            if status_map.get("NoNewPrivs") != "1":
                return reject("no_new_privileges")
            mount_ns, network_ns = (os.stat(f"/proc/{pid}/ns/{name}").st_ino for name in ("mnt", "net"))
            if mount_ns == os.stat("/proc/self/ns/mnt").st_ino or network_ns == os.stat("/proc/self/ns/net").st_ino:
                return reject("namespace_not_private")
            pidfd = os.pidfd_open(pid, 0)
            if (self.manager._pidfd_target(pidfd) != pid or _pidfd_exited(pidfd)
                    or _pid_identity(pid) != (ticks, cgroup, device, inode)):
                os.close(pidfd)
                pidfd = None
                return reject("pidfd_identity")
            cgroup_limits = manager._limits(cgroup)
            cpu_fields = cgroup_limits.get("cpu.max", "").split()
            io_fields = cgroup_limits.get("io.weight", "").split()
            if len(io_fields) % 2:
                return reject("io_weight_format")
            io_weight = dict(zip(io_fields[::2], io_fields[1::2])).get("default")
            expected_quota = str(profile.cpu_quota_percent * 1000)
            if (cgroup_limits.get("memory.max") != str(profile.memory_max_bytes)
                    or len(cpu_fields) != 2 or cpu_fields[0] != expected_quota
                    or cpu_fields[1] != "100000" or io_weight != str(profile.io_weight)):
                return reject("cgroup_limits")
            expected_limits = {"PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
                               "NoNewPrivileges": "yes", "ProtectSystem": "strict"}
            readback = {}
            for key, expected_value in expected_limits.items():
                actual = manager._show(unit, key)
                if key == "IPAddressDeny":
                    if set(actual.split()) != {"0.0.0.0/0", "::/0"}:
                        os.close(pidfd)
                        pidfd = None
                        return reject("network_property")
                    actual = "0.0.0.0/0 ::/0"
                elif actual != expected_value:
                    os.close(pidfd)
                    pidfd = None
                    return reject("unit_property")
                readback[key] = actual
            self._verify_build_mountinfo(pid, mount_targets or self._MOUNTS,
                                        output_readonly=output_readonly)
            if (_pidfd_exited(pidfd) or _pid_identity(pid) != (ticks, cgroup, device, inode)):
                os.close(pidfd)
                pidfd = None
                return reject("process_changed")
            retained_pidfd = pidfd
            pidfd = None
            self._last_build_capture_rejection = ""
            return {"pid": pid, "ticks": ticks, "cgroup": actual_cgroup,
                    "mount_ns": mount_ns, "network_ns": network_ns,
                    "limits": readback, "cgroup_limits": cgroup_limits,
                    "uid": profile.owner_uid, "pidfd": retained_pidfd}
        except (OSError, ValueError, StopIteration, AuthorityDenied):
            if pidfd is not None:
                with contextlib.suppress(OSError):
                    os.close(pidfd)
            return reject("proc_observation")

    @staticmethod
    def _verify_build_mountinfo(pid: int, targets: Mapping[str, str], *,
                                output_readonly: bool = False) -> None:
        rows: dict[str, tuple[set[str], set[str]]] = {}
        for line in Path(f"/proc/{pid}/mountinfo").read_text().splitlines():
            parts = line.split()
            try:
                separator = parts.index("-")
                mountpoint = parts[4].replace("\\040", " ").replace("\\134", "\\")
                options = set(parts[5].split(","))
                optional = set(parts[6:separator])
                superoptions = set(parts[separator + 3].split(","))
            except (IndexError, ValueError):
                continue
            rows[mountpoint] = (options | superoptions, optional)
        for target in targets.values():
            observed = rows.get(target)
            if observed is None:
                raise AuthorityDenied("build.mount", "required fixed build mount is absent")
            options, propagation = observed
            if "nosuid" not in options or "nodev" not in options or {"shared", "master"} & {
                    key.split(":", 1)[0] for key in propagation}:
                raise AuthorityDenied("build.mount", "fixed build mount flags or propagation are unsafe")
            writable_targets = {targets["work"]}
            if not output_readonly:
                writable_targets.add(targets["output"])
            readonly = target not in writable_targets
            if (readonly and "ro" not in options) or (not readonly and "rw" not in options):
                raise AuthorityDenied("build.mount", "fixed build mount access mode differs from policy")

    def _prepare_mount_targets(self, targets: Mapping[str, str] | None = None) -> None:
        root = Path("/run/hermes-installer/build")
        self.manager._ensure_root_runtime_directory(root, 0o755)
        targets = self._MOUNTS if targets is None else targets
        if (not isinstance(targets, Mapping) or targets.get("builder") != self._MOUNTS["builder"]
                or targets.get("output") != self._MOUNTS["output"]
                or any(value not in {*self._MOUNTS.values(), *self._APPLICATION_MOUNTS.values()}
                       for value in targets.values())):
            raise AuthorityDenied("build.mount", "fixed build target map is malformed")
        for key, raw in targets.items():
            target = Path(raw)
            parent = target.parent
            if parent != root:
                self.manager._ensure_root_runtime_directory(parent, 0o755)
            try:
                info = target.lstat()
            except FileNotFoundError:
                if key == "builder":
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o555)
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o555)
                    os.close(fd)
                else:
                    target.mkdir(mode=0o755)
                    os.chown(target, 0, 0)
                    os.chmod(target, 0o755)
                info = target.lstat()
            is_directory = key != "builder"
            if (info.st_uid != 0 or stat.S_ISLNK(info.st_mode)
                    or (is_directory and not stat.S_ISDIR(info.st_mode))
                    or (not is_directory and not stat.S_ISREG(info.st_mode))
                    or info.st_mode & 0o022):
                raise AuthorityDenied("build.mount", "fixed build mountpoint custody is invalid")

    @staticmethod
    def _tree_rows(tree_files: Any) -> list[dict[str, Any]]:
        if not isinstance(tree_files, (tuple, list)) or not tree_files or len(tree_files) > 20000:
            raise AuthorityDenied("build.tree", "build tree catalog manifest is absent or oversized")
        rows = []
        names = set()
        for item in tree_files:
            relative = getattr(item, "path", None)
            if (not isinstance(relative, str) or not relative or "\\" in relative
                    or Path(relative).is_absolute() or any(part in {"", ".", ".."} for part in relative.split("/"))
                    or getattr(item, "kind", None) != "file" or getattr(item, "link_target", None) is not None
                    or relative in names):
                raise AuthorityDenied("build.tree", "build input tree contains an invalid path or non-file entry")
            names.add(relative)
            digest = getattr(item, "sha256", None)
            size = getattr(item, "size_bytes", None)
            executable = getattr(item, "executable", None)
            if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or type(size) is not int or size < 0 or type(executable) is not bool):
                raise AuthorityDenied("build.tree", "build tree row is malformed")
            rows.append({"path": relative, "sha256": digest,
                         "size_bytes": size, "executable": executable})
        if rows != sorted(rows, key=lambda item: item["path"]):
            raise AuthorityDenied("build.tree", "build tree rows are not canonically sorted")
        return rows

    def _verify_build_tree(self, root: Path, tree_files: Any, manifest_sha256: str) -> None:
        rows = self._tree_rows(tree_files)
        digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=False).encode("utf-8")).hexdigest()
        if digest != manifest_sha256:
            raise AuthorityDenied("build.tree", "catalog tree manifest digest changed")
        root = _root_path(root, directory=True)
        observed = {}
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            base = Path(current)
            for dirname in dirs:
                info = (base / dirname).lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise AuthorityDenied("build.tree", "build tree contains an untrusted directory")
            for filename in files:
                path = base / filename
                info = path.lstat()
                relative = path.relative_to(root).as_posix()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                        or info.st_nlink != 1):
                    raise AuthorityDenied("build.tree", "build tree contains a mutable or special file")
                content = hashlib.sha256(path.read_bytes()).hexdigest()
                observed[relative] = {"path": relative, "sha256": content,
                    "size_bytes": info.st_size, "executable": bool(info.st_mode & 0o111)}
        if sorted(observed.values(), key=lambda item: item["path"]) != rows:
            raise AuthorityDenied("build.tree", "materialized build input differs from its catalog file manifest")

    def _verify_inputs(self, inputs: Any) -> None:
        self._verify_build_tree(Path(inputs.source_root), inputs.source_tree_files,
                                inputs.source_tree_manifest_sha256)
        self._verify_build_tree(Path(inputs.toolchain_root), inputs.toolchain_tree_files,
                                inputs.toolchain_tree_manifest_sha256)
        self._verify_file(Path(inputs.builder_executable), inputs.builder_sha256, executable=True)

    @staticmethod
    def _verify_file(path: Path, digest: str, *, executable: bool) -> None:
        resolved = _root_path(path, directory=False)
        info = resolved.stat(follow_symlinks=False)
        if (info.st_nlink != 1 or info.st_size > 512 * 1024 * 1024
                or executable and not info.st_mode & 0o111
                or hashlib.sha256(resolved.read_bytes()).hexdigest() != digest):
            raise AuthorityDenied("build.artifact", "selected build executable differs from its immutable root pin")

    @staticmethod
    def _validate_output_root(path: Path, uid: int, gid: int) -> None:
        if not path.is_absolute() or path != path.resolve(strict=True):
            raise AuthorityDenied("build.output", "selected output root is not canonical")
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700
                or any(path.iterdir())):
            raise AuthorityDenied("build.output", "selected output root is not a fresh private directory")

    @staticmethod
    def _validate_output_root_fd(info: os.stat_result, uid: int, gid: int) -> None:
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise AuthorityDenied("build.output", "held output root is not a private selected directory")

    @staticmethod
    def _copy_build_tree(source: Path, destination: Path, tree_files: Any, uid: int, gid: int) -> None:
        rows = ManagedBuildJobRunner._tree_rows(tree_files)
        expected = {item["path"]: item for item in rows}
        for relative, row in expected.items():
            source_file = source / relative
            fd = os.open(source_file, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o222
                        or info.st_nlink != 1 or info.st_size != row["size_bytes"]):
                    raise AuthorityDenied("build.source", "source file changed before work-copy staging")
                target = destination / relative
                directory = destination
                for part in Path(relative).parts[:-1]:
                    directory = directory / part
                    try:
                        directory.mkdir(mode=0o700)
                    except FileExistsError:
                        pass
                    info = directory.lstat()
                    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                        raise AuthorityDenied("build.source", "source path contains a non-directory component")
                    os.chown(directory, uid, gid)
                    os.chmod(directory, 0o700)
                out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                              | getattr(os, "O_NOFOLLOW", 0), 0o700 if row["executable"] else 0o600)
                digest = hashlib.sha256()
                try:
                    while chunk := os.read(fd, 128 * 1024):
                        digest.update(chunk)
                        view = memoryview(chunk)
                        while view:
                            count = os.write(out, view)
                            view = view[count:]
                    if digest.hexdigest() != row["sha256"]:
                        raise AuthorityDenied("build.source", "source bytes changed during work-copy staging")
                    os.fchown(out, uid, gid)
                    os.fchmod(out, 0o700 if row["executable"] else 0o600)
                finally:
                    os.close(out)
            finally:
                os.close(fd)

    @staticmethod
    def _application_inputs_fingerprint(inputs: Any) -> tuple[Any, ...]:
        """Bind every registry projection field/member to retained descriptor identity."""
        scalar_names = (
            "selection_handle", "application_id", "build_profile_id", "target_id", "operation_id",
            "runtime_preparation_selection_handle", "plan_sha256", "setup_session_id",
            "transaction_handle", "prepared_generation_id", "prepared_generation_digest",
            "source_receipt_handle", "source_manifest_sha256", "pm_runtime_closure_sha256",
            "lock_receipt_handle", "lock_sha256", "package_closure_receipt_handle",
            "build_backend_closure_receipt_handle", "recipe_sha256", "builder_receipt_handle",
            "builder_sha256", "builder_size_bytes", "driver_receipt_handle", "driver_sha256",
            "driver_size_bytes", "recipe_config_sha256", "output_root_id", "output_owner_uid",
            "output_owner_gid", "build_service_id", "build_service_selection_handle",
            "build_service_generation", "runtime_toolchain_receipt_handles", "controller_binding_handle",
            "controller_pid", "controller_start_ticks", "controller_uid", "controller_gid",
            "uv_sha256", "uv_size_bytes",
            "uv_source_receipt_handle", "uv_artifact_id",
        )
        try:
            scalars = tuple(getattr(inputs, name) for name in scalar_names)
            scalars += (hashlib.sha256(inputs.recipe_config_bytes).hexdigest(),)
            descriptor_fields = (
                ("builder_fd",), ("uv_fd",), ("driver_fd",), ("output_root_fd",),
                ("controller_pidfd",),
            )
            descriptors = []
            for group in descriptor_fields:
                fd = getattr(inputs, group[0])
                if fd is None:
                    descriptors.append(None)
                    continue
                info = os.fstat(fd)
                descriptors.append((info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                    info.st_uid, info.st_gid))
            members = []
            for group_name in ("source_members", "package_members", "backend_members",
                               "python_runtime_members", "recipe_member", "python_executable_member"):
                value = getattr(inputs, group_name)
                group = value if isinstance(value, (tuple, list)) else (value,)
                rows = []
                for item in group:
                    info = os.fstat(item.fd)
                    rows.append((item.relative_path, item.sha256, item.size_bytes, item.executable,
                                 item.receipt_handle, item.kind, item.link_target,
                                 info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_uid, info.st_gid))
                members.append((group_name, tuple(rows)))
            return scalars + (tuple(descriptors), tuple(members))
        except (AttributeError, OSError, TypeError, ValueError):
            raise AuthorityDenied("build.application_current", "application descriptor projection is stale") from None

    @staticmethod
    def _stage_application_held_members(members: Any, destination: Path, *,
                                        allow_symlinks: bool = False) -> tuple[Any, ...]:
        """Copy a bounded held-member closure into a fresh private tree.

        Entries are internal resolved observations with ``relative_path``,
        ``fd``, ``sha256``, ``size_bytes`` and ``executable`` members. No path
        from an entry is opened; every byte comes from its already-held
        descriptor and is rehashed while copied. Symlinks are accepted only
        for the PM-runtime mount, where an O_PATH|O_NOFOLLOW descriptor,
        exact link text digest, in-tree target closure, and acyclic resolution
        are all checked before the link is created.
        """
        from hermes_installer.authority.build_execution import _BuildInputTreeFile

        if (os.geteuid() != 0 or not isinstance(members, (tuple, list))
                or not members or len(members) > 20_000):
            raise AuthorityDenied("build.application_input", "held application input closure is unavailable")
        try:
            destination.mkdir(mode=0o700)
        except OSError:
            raise AuthorityDenied("build.application_input", "application input staging root is not fresh") from None
        root_info = destination.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode)
                or root_info.st_uid != 0 or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise AuthorityDenied("build.application_input", "application input staging root is unsafe")

        rows: list[_BuildInputTreeFile] = []
        seen: set[str] = set()
        entries: dict[str, Any] = {}
        total = 0
        for entry in members:
            relative = getattr(entry, "relative_path", None)
            fd = getattr(entry, "fd", None)
            digest = getattr(entry, "sha256", None)
            size = getattr(entry, "size_bytes", None)
            executable = getattr(entry, "executable", None)
            if (not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative
                    or Path(relative).is_absolute()
                    or any(part in {"", ".", ".."} for part in relative.split("/"))
                    or PurePosixPath(relative).as_posix() != relative or relative in seen
                    or type(fd) is not int or fd < 0
                    or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                    or not isinstance(getattr(entry, "receipt_handle", None), str)
                    or not 32 <= len(entry.receipt_handle) <= 128
                    or type(size) is not int or not 0 <= size <= 512 * 1024 * 1024
                    or type(executable) is not bool):
                raise AuthorityDenied("build.application_input", "held application member is malformed")
            seen.add(relative)
            entries[relative] = entry
            total += size
            if total > 2 * 1024**3:
                raise AuthorityDenied("build.application_input", "held application input closure exceeds its byte bound")
            try:
                source_info = os.fstat(fd)
            except OSError:
                raise AuthorityDenied("build.application_input", "held application member FD is stale") from None
            sealed = False
            immutable = not (source_info.st_mode & 0o222)
            if hasattr(fcntl, "F_GET_SEALS"):
                try:
                    seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                    required_seals = (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
                                      | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
                    sealed = seals & required_seals == required_seals
                    immutable = immutable or sealed
                except OSError:
                    pass
            kind = getattr(entry, "kind", "file")
            link_target = getattr(entry, "link_target", None)
            if kind == "symlink":
                if not allow_symlinks:
                    raise AuthorityDenied("build.application_input", "symlink is not allowed in this application mount")
                target_bytes = ManagedBuildJobRunner._read_held_symlink(fd)
                if (not stat.S_ISLNK(source_info.st_mode) or source_info.st_uid != 0
                        or source_info.st_size != size or not isinstance(link_target, str)
                        or target_bytes != link_target.encode("utf-8", "strict")
                        or hashlib.sha256(target_bytes).hexdigest() != digest
                        or size != len(target_bytes) or executable):
                    raise AuthorityDenied("build.application_input", "held PM symlink identity or target digest changed")
                continue
            if (kind != "file" or link_target is not None
                    or not stat.S_ISREG(source_info.st_mode) or source_info.st_uid != 0
                    or not immutable
                    or (source_info.st_nlink != 1 and not (sealed and source_info.st_nlink == 0))
                    or source_info.st_size != size):
                raise AuthorityDenied("build.application_input", "held application member is not immutable root data")

            target = destination
            parts = relative.split("/")
            for part in parts[:-1]:
                target = target / part
                try:
                    target.mkdir(mode=0o700)
                except FileExistsError:
                    pass
                info = target.lstat()
                if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or info.st_uid != 0 or info.st_mode & 0o022):
                    raise AuthorityDenied("build.application_input", "held application member has unsafe parent path")
            target = target / parts[-1]
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                          | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o600)
            hasher = hashlib.sha256()
            count = 0
            try:
                while count < size:
                    chunk = os.pread(fd, min(128 * 1024, size - count), count)
                    if not chunk:
                        raise AuthorityDenied("build.application_input", "held application member ended early")
                    hasher.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(out, view)
                        if written <= 0:
                            raise AuthorityDenied("build.application_input", "application member staging write stalled")
                        view = view[written:]
                    count += len(chunk)
                if os.pread(fd, 1, size) or hasher.hexdigest() != digest:
                    raise AuthorityDenied("build.application_input", "held application member bytes changed")
                mode = 0o555 if executable else 0o444
                os.fchown(out, 0, 0)
                os.fchmod(out, mode)
            finally:
                os.close(out)
            rows.append(_BuildInputTreeFile(relative, digest, size, executable))
        symlink_entries = {name: item for name, item in entries.items()
                           if getattr(item, "kind", "file") == "symlink"}
        if symlink_entries:
            if not allow_symlinks:
                raise AuthorityDenied("build.application_input", "symlink is not allowed in this application mount")
            ManagedBuildJobRunner._validate_application_symlink_closure(entries, symlink_entries)
            for relative, entry in sorted(symlink_entries.items()):
                target = entry.link_target
                path = destination.joinpath(*relative.split("/"))
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.symlink(target, path)
                rows.append(_BuildInputTreeFile(relative, entry.sha256, entry.size_bytes,
                                                False, kind="symlink", link_target=target))
        # Reject file/directory aliasing (for example a member named `a` plus
        # another member `a/b`) before the staged tree can be mounted.
        for name in seen:
            parts = name.split("/")
            if any("/".join(parts[:index]) in seen for index in range(1, len(parts))):
                raise AuthorityDenied("build.application_input", "application member tree has a path collision")
        return tuple(sorted(rows, key=lambda row: row.path))

    @staticmethod
    def _read_held_symlink(fd: int) -> bytes:
        """Read link text from an O_PATH symlink FD using readlinkat(AT_EMPTY_PATH)."""
        if not sys.platform.startswith("linux"):
            raise AuthorityDenied("build.application_input", "held symlink verification requires Linux")
        libc = ctypes.CDLL(None, use_errno=True)
        readlinkat = libc.readlinkat
        readlinkat.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t)
        readlinkat.restype = ctypes.c_ssize_t
        buffer = ctypes.create_string_buffer(4097)
        size = readlinkat(fd, b"", buffer, 4096)
        if size < 0 or size > 4095:
            raise AuthorityDenied("build.application_input", "held symlink text could not be verified")
        return bytes(buffer.raw[:size])

    @staticmethod
    def _validate_application_symlink_closure(entries: Mapping[str, Any],
                                               symlinks: Mapping[str, Any]) -> None:
        """Require every PM symlink to resolve through the staged manifest in-root."""
        names = set(entries)
        for name in symlinks:
            parts = name.split("/")
            if any("/".join(parts[:index]) in symlinks for index in range(1, len(parts))):
                raise AuthorityDenied("build.application_input", "PM symlink has a symlink parent path")
        for link_path, entry in symlinks.items():
            target = getattr(entry, "link_target", None)
            if (not isinstance(target, str) or not target or target.startswith("/")
                    or "\\" in target or "\x00" in target or len(target.encode("utf-8")) > 4095):
                raise AuthorityDenied("build.application_input", "PM symlink target is not a bounded relative path")
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
            if resolved in {"", ".", ".."} or resolved.startswith("../"):
                raise AuthorityDenied("build.application_input", "PM symlink escapes the held runtime root")
            pending = resolved.split("/")
            visited: set[str] = set()
            hops = 0
            while True:
                prefix = ""
                replaced = False
                for index, component in enumerate(pending):
                    prefix = component if not prefix else prefix + "/" + component
                    target_entry = symlinks.get(prefix)
                    if target_entry is None:
                        continue
                    if prefix in visited:
                        raise AuthorityDenied("build.application_input", "PM symlink closure contains a cycle")
                    visited.add(prefix)
                    hops += 1
                    if hops > 40:
                        raise AuthorityDenied("build.application_input", "PM symlink closure exceeds its resolution bound")
                    tail = pending[index + 1:]
                    replacement = posixpath.normpath(posixpath.join(posixpath.dirname(prefix),
                                                                      target_entry.link_target))
                    candidate = posixpath.normpath(posixpath.join(replacement, *tail)) if tail else replacement
                    if candidate in {"", ".", ".."} or candidate.startswith("../"):
                        raise AuthorityDenied("build.application_input", "PM symlink chain escapes the held runtime root")
                    pending = candidate.split("/")
                    replaced = True
                    break
                if replaced:
                    continue
                final = "/".join(pending)
                # Directory rows are implicit in a regular-file projection.
                if final not in names and not any(name.startswith(final.rstrip("/") + "/") for name in names):
                    raise AuthorityDenied("build.application_input", "PM symlink target has no receipt-bound member")
                break

    @staticmethod
    def _copy_application_held_file(fd: int, digest: str, size: int, destination: Path, *,
                                    executable: bool) -> None:
        if (type(fd) is not int or fd < 0 or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or size <= 0):
            raise AuthorityDenied("build.application_input", "held executable is malformed")
        info = os.fstat(fd)
        sealed = False
        if hasattr(fcntl, "F_GET_SEALS"):
            with contextlib.suppress(OSError):
                seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
                sealed = seals & (fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
                                  | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE) == (
                                      fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK
                                      | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != size
                or (info.st_mode & 0o222 and not sealed)
                or (info.st_nlink != 1 and not (sealed and info.st_nlink == 0))):
            raise AuthorityDenied("build.application_input", "held executable is not immutable root data")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                      | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o700)
        hasher = hashlib.sha256()
        offset = 0
        try:
            while offset < size:
                block = os.pread(fd, min(128 * 1024, size - offset), offset)
                if not block:
                    raise AuthorityDenied("build.application_input", "held executable ended early")
                hasher.update(block)
                view = memoryview(block)
                while view:
                    written = os.write(out, view)
                    if written <= 0:
                        raise AuthorityDenied("build.application_input", "executable staging write stalled")
                    view = view[written:]
                offset += len(block)
            if os.pread(fd, 1, size) or hasher.hexdigest() != digest:
                raise AuthorityDenied("build.application_input", "held executable bytes differ from selected digest")
            os.fchown(out, 0, 0)
            os.fchmod(out, 0o555 if executable else 0o444)
        finally:
            os.close(out)

    @staticmethod
    def _application_tree_manifest(rows: tuple[Any, ...]) -> str:
        serialized = []
        for row in sorted(rows, key=lambda value: value.path):
            serialized.append({"path": row.path, "sha256": row.sha256,
                               "size_bytes": row.size_bytes, "executable": row.executable})
        return hashlib.sha256(json.dumps(serialized, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False).encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_application_wheel_config(config: Mapping[str, Any], packages: Any,
                                           backend: Any) -> None:
        """Join driver wheel pins to the exact held artifact member rows."""
        def check(key: str, members: Any) -> None:
            rows = config.get(key)
            if (not isinstance(rows, list) or not rows or len(rows) > 8192
                    or not isinstance(members, (tuple, list)) or len(rows) != len(members)):
                raise AuthorityDenied("build.application_recipe", "offline wheel configuration is incomplete")
            by_name = {}
            for member in members:
                relative = getattr(member, "relative_path", None)
                if (not isinstance(relative, str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}\.whl", relative)):
                    raise AuthorityDenied("build.application_recipe", "wheel member path is outside its fixed closure")
                name = relative
                if name in by_name:
                    raise AuthorityDenied("build.application_recipe", "wheel closure contains a duplicate filename")
                by_name[name] = member
            seen: set[str] = set()
            for row in rows:
                if (not isinstance(row, dict)
                        or set(row) != {"name", "version", "filename", "sha256", "size_bytes"}
                        or not isinstance(row.get("name"), str) or not row["name"]
                        or not isinstance(row.get("version"), str) or not row["version"]
                        or not isinstance(row.get("filename"), str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}\.whl", row["filename"])
                        or not isinstance(row.get("sha256"), str)
                        or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                        or type(row.get("size_bytes")) is not int or row["size_bytes"] <= 0
                        or row["filename"] in seen):
                    raise AuthorityDenied("build.application_recipe", "offline wheel pin is malformed or duplicated")
                seen.add(row["filename"])
                member = by_name.get(row["filename"])
                if (member is None or member.sha256 != row["sha256"]
                        or member.size_bytes != row["size_bytes"]):
                    raise AuthorityDenied("build.application_recipe", "offline wheel pin differs from held bytes")
            if seen != set(by_name):
                raise AuthorityDenied("build.application_recipe", "offline wheel pin set differs from held artifacts")

        check("packages", packages)
        check("backend_packages", backend)

    @staticmethod
    def _protect_build_mount(path: Path, *, readonly: bool) -> None:
        flags_bind, flags_rec = 4096, 16384
        flags_private = 1 << 18
        flags_remount, flags_ro, flags_nosuid, flags_nodev = 32, 1, 2, 4
        ManagedProcessEffectHandler._mount_call(path, path, flags_bind | flags_rec)
        try:
            ManagedProcessEffectHandler._mount_call(path, path, flags_private | flags_rec)
            flags = flags_bind | flags_remount | flags_nosuid | flags_nodev
            if readonly:
                flags |= flags_ro
            ManagedProcessEffectHandler._mount_call(path, path, flags)
        except BaseException:
            with contextlib.suppress(OSError):
                ManagedBuildJobRunner._umount_build(path)
            raise

    @staticmethod
    def _umount_build(path: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        umount2 = libc.umount2
        umount2.argtypes = (ctypes.c_char_p, ctypes.c_int)
        umount2.restype = ctypes.c_int
        if umount2(os.fsencode(path), 0) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(path))

    @classmethod
    def _resolve_build_argv(cls, recipe: Any, targets: Mapping[str, str]) -> list[str]:
        from hermes_installer.authority.build_execution import _resolve_argv_recipe
        additional = tuple(sorted(set(targets) - set(cls._MOUNTS)))
        if set(additional) - set(cls._APPLICATION_MOUNTS):
            raise AuthorityDenied("build.argv", "build recipe requested an unknown app-only mount")
        normalized = _resolve_argv_recipe(recipe, additional_mount_ids=additional)
        argv = []
        for index, node in enumerate(normalized):
            if "literal" in node:
                value = node["literal"]
            else:
                value = node["build_path"]
                mount_id = value["mount_id"]
                relative = value["relative_path"]
                if mount_id == "builder" and relative:
                    raise AuthorityDenied("build.argv", "builder executable path must be its fixed mount root")
                value = targets[mount_id] if not relative else str(Path(targets[mount_id]) / relative)
            if not isinstance(value, str) or "\x00" in value or len(value) > 4096:
                raise AuthorityDenied("build.argv", "resolved build argv token is invalid")
            argv.append(value)
        if not argv or argv[0] != targets["builder"] or sum(len(arg.encode()) for arg in argv) > 65536:
            raise AuthorityDenied("build.argv", "build argv differs from the exact fixed builder recipe")
        if any(any(flag in value.casefold() for flag in ("--token", "--secret", "--password", "--api-key", "--credential"))
               for value in argv[1:]):
            raise AuthorityDenied("build.argv", "credential-bearing build arguments are forbidden")
        return argv

    @staticmethod
    def _build_environment(raw: Mapping[str, str], targets: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(raw, Mapping) or len(raw) > 32:
            raise AuthorityDenied("build.environment", "root build environment is malformed")
        fixed = {
            "HOME": targets["work"] + "/home",
            "TMPDIR": targets["work"] + "/tmp",
            "PATH": targets["toolchain"] + "/bin",
        }
        result = dict(raw)
        for key, value in fixed.items():
            if key in result and result[key] != value:
                raise AuthorityDenied("build.environment", "build root path differs from the fixed mount contract")
            result[key] = value
        for key, value in result.items():
            if (not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or key not in {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH",
                                  "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS"}
                    or not isinstance(value, str) or len(value) > 4096
                    or any(char in value for char in ("\x00", "\n", "\r", "`", "$"))
                    or re.search(r"token|secret|credential|password|api[_-]?key", value, re.I)
                    or re.search(r"token|secret|credential|password|api[_-]?key", key, re.I)):
                raise AuthorityDenied("build.environment", "build environment is outside its reviewed finite allowlist")
        result.setdefault("LANG", "C")
        result.setdefault("LC_ALL", "C")
        return result

    def _terminate_unit(self, unit: str, cgroup: str,
                        launcher: subprocess.Popen[bytes] | None) -> None:
        manager = self.manager
        for signal_name in ("SIGTERM", "SIGKILL"):
            if not manager._pids(cgroup):
                break
            with contextlib.suppress(AuthorityDenied):
                manager._ctl(["kill", "--kill-whom=all", "--signal=" + signal_name, unit], 1.0)
            if signal_name == "SIGTERM":
                until = time.monotonic() + .25
                while manager._pids(cgroup) and time.monotonic() < until:
                    time.sleep(.01)
        if manager._pids(cgroup):
            with contextlib.suppress(AuthorityDenied):
                manager._ctl(["stop", unit], 1.0)
        until = time.monotonic() + 2.0
        while manager._pids(cgroup) and time.monotonic() < until:
            time.sleep(.02)
        if launcher is not None and launcher.poll() is None:
            with contextlib.suppress(subprocess.TimeoutExpired):
                launcher.wait(timeout=.2)
            if launcher.poll() is None:
                launcher.kill()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    launcher.wait(timeout=1.0)
