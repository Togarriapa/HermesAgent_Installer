"""Root-side fixed process verbs for the protected AuthorityService.

This adapter is injected into the root-owned authority daemon. It accepts no
shell command or arbitrary manager property and trusts only protected profile
registrations plus the already verified, consumed host effect grant.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import pwd
import re
import select
import shutil
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest


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
    network_namespace_fd: int | None = None
    child_artifact_identities: tuple[tuple[str, int, int], ...] = ()
    stdin_cursor: int = 0
    stdout_cursor: int = 0
    stderr_cursor: int = 0
    stopped: bool = False
    lock: threading.RLock | None = None
    # The immutable profile registered by the root daemon. ``profile`` may be a
    # derived record selecting one exact enrolled operation executable.
    registered_profile: ManagedProfileCustody | None = None


_LAUNCH_FIELDS = {
    "schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root",
    "cwd", "data_root", "argv", "env_allowlist", "child_artifact_refs",
    "max_lifetime_seconds", "max_output_bytes", "stdin_mode",
}
_ALLOWED_ENV = {
    "HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HERMES_HOME", "TMPDIR",
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
    if not directory and hashlib.sha256(path.read_bytes()).hexdigest() != digest:
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
                 monotonic: Callable[[], float] = time.monotonic):
        if not profiles or any(key != item.profile_id for key, item in profiles.items()):
            raise ValueError("root process custody requires an explicit profile registry")
        self.profiles = dict(profiles)
        self.systemd_run = _root_path(systemd_run, directory=False)
        self.systemctl = _root_path(systemctl, directory=False)
        self.monotonic = monotonic
        self.artifact_resolver = artifact_resolver
        self.native_package_resolver = native_package_resolver
        self._handles: dict[str, _Handle] = {}
        self._finished: dict[str, tuple[str, float, ProcessCleanupProof]] = {}
        self._starting: set[str] = set()
        self._lock = threading.RLock()
        self._member_key = os.urandom(32)
        # Root-only test harness may capture bounded manager diagnostics. This
        # is never serialized to a worker or populated from caller text.
        self._diagnostic_sink: Callable[[bytes], None] | None = None
        for profile in self.profiles.values():
            self._validate_profile(profile)

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
        if (getattr(closure_artifact, "tree_manifest_sha256", binding.compiled_closure_sha256)
                != binding.compiled_closure_sha256):
            raise AuthorityDenied("native.closure", "native closure tree manifest digest changed")
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
                cls._write_native_file(target_dir / name, data, 0o444)
        cls._make_native_tree_readonly(destination)

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
        info = stage.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise AuthorityDenied("native.cleanup", "native staging tree custody changed")
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

    @staticmethod
    def _verify_native_package_mount(pid: int, receipt: NativePackageMountReceipt) -> None:
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
                raise ValueError("mount target absent or ambiguous")
            fields, separator = candidates[0]
            options = set(fields[5].split(","))
            propagation = fields[6:separator]
            if (not {"ro", "nosuid", "nodev", "noexec"}.issubset(options)
                    or any(item.startswith(("shared:", "master:", "propagate_from:")) for item in propagation)):
                raise ValueError("mount flags are not constrained")
            observed = os.stat(f"/proc/{pid}/root{receipt.mount_path}", follow_symlinks=False)
            if (observed.st_dev, observed.st_ino) != (receipt.mount_source_device, receipt.mount_source_inode):
                raise ValueError("mounted root inode differs from the staged package")
        except (OSError, ValueError, IndexError):
            raise AuthorityDenied("native.mount_effect", "kernel did not establish the exact private read-only package mount") from None

    @staticmethod
    def _validate_profile(profile: ManagedProfileCustody) -> None:
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile.profile_id)
                or profile.owner_uid <= 0 or profile.owner_gid <= 0):
            raise ValueError("protected process profile identity is invalid")
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
            return self.dispatch(profile, operation, context=context, authorization=authorization,
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
            return self._start(profile, context, authorization, payload, timeout, peer_pid,
                               peer_pidfd, cancelled)
        if operation == "process.inspect":
            return self._inspect(profile, context, payload, timeout, cancelled)
        return self._control(profile, context, operation, payload, timeout, cancelled)

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
        return value

    def _start(self, profile: ManagedProfileCustody, context: HostContext,
               authorization: EffectAuthorization, payload: bytes, timeout: float,
               peer_pid: int, peer_pidfd: int | None,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]:
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
                )
            return self._start_reserved(profile, context, authorization, payload, timeout,
                                        peer_pid, peer_pidfd, cancelled)
        finally:
            with self._lock:
                self._starting.discard(profile.profile_id)

    def start_selected_operation(self, profile: ManagedProfileCustody, context: HostContext,
                                 authorization: EffectAuthorization, payload: bytes, *,
                                 timeout: float, peer_pid: int, peer_pidfd: int | None,
                                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        """Resolve a selection-only worker request to one immutable root recipe.

        This method is called only after dispatch has checked the consumed
        process.start grant against these exact selection bytes. No path, argv,
        executable, environment, PID, namespace, or socket comes from the peer.
        """
        request = self._json(payload)
        if (set(request) != {"schema", "enrollment_id", "generation", "operation_id", "parameters"}
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
        schema_id = recipe["parameter_schema_id"]
        schema = (profile.parameter_schemas or {}).get(schema_id)
        if not isinstance(schema, Mapping):
            raise AuthorityDenied("process.parameters", "operation parameter schema is unavailable")
        normalized = self._validate_operation_parameters(parameters, schema)

        if cancelled() or self.monotonic() >= authorization.monotonic_expires_at:
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
        return self._start_reserved(derived, context, authorization, launch_bytes, timeout,
                                   peer_pid, peer_pidfd, cancelled, registered_profile=profile)

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
                        peer_pid: int, peer_pidfd: int | None,
                        cancelled: Callable[[], bool], *,
                        registered_profile: ManagedProfileCustody | None = None) -> Mapping[str, Any]:
        launch_deadline = min(self.monotonic() + max(0.0, timeout),
                              authorization.monotonic_expires_at)

        def require_live_start(parent_fd: int | None = None) -> None:
            if (cancelled() or self.monotonic() >= launch_deadline
                    or self.profiles.get(profile.profile_id) is not (registered_profile or profile)
                    or (parent_fd is not None and _pidfd_exited(parent_fd))):
                raise AuthorityDenied("process.start_expired", "start grant, profile enrollment or caller expired before launch")

        if peer_pidfd is None:
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
            parent_fd = os.dup(peer_pidfd)
        except OSError:
            raise AuthorityDenied("process.parent", "pidfd is required for parent-death custody") from None
        process_id = uuid.uuid4().hex
        artifact_mount_dir: Path | None = None
        artifact_target: Path | None = None
        native_mount_source: Path | None = None
        native_mount_receipt: NativePackageMountReceipt | None = None
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
        if profile.memory_max_bytes is not None:
            properties.append(f"--property=MemoryMax={profile.memory_max_bytes}")
        if profile.cpu_quota_percent is not None:
            properties.append(f"--property=CPUQuota={profile.cpu_quota_percent}%")
        if profile.io_weight is not None:
            properties.append(f"--property=IOWeight={profile.io_weight}")
        env_args = ["--setenv=" + key + "=" + value for key, value in sorted(env.items())]
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        remaining = launch_deadline - self.monotonic()
        if remaining <= 0:
            os.close(parent_fd)
            raise AuthorityDenied("process.start_expired", "start lease ended during preparation")
        try:
            manager_env = subprocess.run([str(self.systemctl), "--system", "show-environment"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=min(2.0, remaining), check=False)
        except (OSError, subprocess.TimeoutExpired):
            os.close(parent_fd)
            raise AuthorityDenied("process.environment", "system manager environment could not be bounded") from None
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        if manager_env.returncode != 0 or len(manager_env.stdout) > 65536:
            if self._diagnostic_sink is not None:
                self._diagnostic_sink(
                    f"manager-environment-failed:returncode={manager_env.returncode}:bytes={len(manager_env.stdout)}".encode("ascii"))
            os.close(parent_fd)
            raise AuthorityDenied("process.environment", "system manager environment cannot be safely cleared")
        import re
        manager_keys = {line.split("=", 1)[0] for line in manager_env.stdout.decode("utf-8", "replace").splitlines()
                        if "=" in line and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.split("=", 1)[0])}
        manager_keys.update({"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET", "WATCHDOG_USEC",
                             "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES",
                             "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME",
                             "SHELL", "PWD", "SYSTEMD_EXEC_PID", "MEMORY_PRESSURE_WATCH",
                             "MEMORY_PRESSURE_WRITE"})
        unset_keys = sorted(manager_keys - set(env))
        if sum(len(key) + 1 for key in unset_keys) > 60000:
            os.close(parent_fd)
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
            native_mount_source, native_mount_receipt = self._prepare_native_package_mount(profile, process_id)
            if native_mount_source is not None and native_mount_receipt is not None:
                properties.append(
                    "--property=BindReadOnlyPaths=" + str(native_mount_source) + ":"
                    + native_mount_receipt.mount_path + ":ro:nosuid:nodev:noexec")
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
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
            raise AuthorityDenied("process.launcher_start", "root process manager could not start the enrolled service") from None
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            if native_mount_source is not None:
                self._remove_native_staging(native_mount_source)
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
                        parts = [f"launcher-exit={launcher.returncode}".encode("ascii")]
                        for name, stream in ((b"stdout", launcher.stdout), (b"stderr", launcher.stderr)):
                            if stream is None:
                                continue
                            try:
                                output = stream.read(1024)
                            except (OSError, ValueError):
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
                                "-p", "RestrictAddressFamilies"]),
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
            if actual_environment != env:
                if self._diagnostic_sink is not None:
                    # Keep values out of the diagnostic path: only the
                    # variable names needed to identify manager injection are
                    # included in this root-only test sink.
                    actual_keys = sorted(actual_environment)
                    expected_keys = sorted(env)
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
            handle = _Handle(process_id, profile, unit, cgroup, launcher, parent_fd, child_fd, pid,
                ticks, f"mnt:{mnt};net:{net}", context.principal_id, context.namespace_id,
                started, started + float(lifetime), output_cap, artifact_mount_dir,
                native_mount_source=native_mount_source,
                native_mount_receipt=native_mount_receipt,
                network_namespace_fd=network_namespace_fd,
                child_artifact_identities=child_artifact_identities,
                lock=threading.RLock(),
                registered_profile=registered_profile or profile)
            child_fd = None
            network_namespace_fd = None
            with self._lock:
                self._handles[process_id] = handle
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
        if (set(item) != {"schema", "process_id", "generation"} or item.get("schema") != 1
                or not isinstance(item.get("process_id"), str)
                or item.get("generation") != profile.generation):
            raise AuthorityDenied("process.inspect", "inspection request is malformed or stale")
        with self._lock:
            handle = self._handles.get(item["process_id"])
        if (handle is None or handle.registered_profile is not profile
                or self.profiles.get(profile.profile_id) is not profile or handle.stopped
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
        return _response(200, {
            "schema": 1, "process_id": handle.process_id, "generation": profile.generation,
            "profile_id": profile.profile_id, "cgroup_identity": handle.cgroup,
            "observation_monotonic": observed,
            "expires_monotonic": min(handle.expires, observed + min(max(timeout, 0.1), 30.0)),
            "complete": stable, "processes": processes,
        })

    def resolve_namespace_lease(self, binding: Any) -> ManagedNamespaceLease | None:
        """Resolve a route only to the one active namespace enrolled for its profile generation."""
        profile_id = getattr(binding, "profile_id", None)
        generation = getattr(binding, "generation", None)
        namespace_identity = getattr(binding, "namespace_identity", None)
        if not isinstance(profile_id, str) or not isinstance(generation, str) or not isinstance(namespace_identity, str):
            return None
        with self._lock:
            matches = [handle for handle in self._handles.values()
                       if handle.profile.profile_id == profile_id
                       and handle.profile.generation == generation
                       and handle.kernel_namespace_id == namespace_identity]
        if len(matches) != 1:
            return None
        handle = matches[0]
        with handle.lock:
            if (handle.stopped or handle.network_namespace_fd is None
                    or self.monotonic() >= handle.expires or _pidfd_exited(handle.child_pidfd)
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
                or operation not in {"process.status", "process.read", "process.write", "process.stop"}
                or type(peer_uid) is not int or peer_uid <= 0):
            return None
        with self._lock:
            handle = self._handles.get(process_id)
        if (handle is None or handle.stopped or handle.profile.generation != generation
                or handle.registered_profile is not self.profiles.get(handle.profile.profile_id)
                or peer_uid != handle.profile.owner_uid):
            return None
        identity = self.resolve_live_peer(peer_pid, peer_pidfd,
            profile_id=handle.profile.profile_id, generation=generation)
        if identity is None or identity.kernel_uid != peer_uid:
            return None
        target = process_control_target(handle.registered_profile, operation)
        return handle.registered_profile, target

    def resolve_loaded_native_package(self, process_id: str, generation: str) -> LoadedNativePackageProof | None:
        """Resolve the package actually mounted in one active registered process."""
        if (not isinstance(process_id, str) or not re.fullmatch(r"[0-9a-f]{32}", process_id)
                or not isinstance(generation, str)):
            return None
        with self._lock:
            handle = self._handles.get(process_id)
        if (handle is None or handle.profile.generation != generation or handle.stopped
                or self.profiles.get(handle.profile.profile_id) is not handle.registered_profile
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
        common = {"schema", "process_id", "generation"}
        extras = {"process.status": set(), "process.stop": set(),
                  "process.read": {"stream", "after_cursor", "max_bytes"},
                  "process.write": {"data", "stdin_cursor"}}[operation]
        if set(item) != common | extras or item.get("schema") != 1 or not isinstance(item.get("process_id"), str):
            raise AuthorityDenied("process.control", "control envelope is malformed")
        with self._lock:
            handle = self._handles.get(item["process_id"])
            finished = self._finished.get(item["process_id"])
        if handle is None and operation == "process.stop" and finished and finished[0] == profile.generation:
            proof = finished[2]
            return _response(200, {"schema": 1, "stopped": True,
                "cleanup_verified": proof.cleanup_verified, "cgroup_empty": proof.cgroup_empty,
                "pidfd_gone": proof.main_pidfd_gone, "evidence_digest": proof.evidence_digest})
        if (handle is None or handle.profile.profile_id != profile.profile_id
                or item["generation"] != profile.generation
                or context.principal_id != handle.principal_id
                or context.namespace_id != handle.authority_namespace_id):
            raise AuthorityDenied("process.handle", "process handle is stale or belongs to another principal")
        if operation != "process.stop" and (cancelled() or _pidfd_exited(handle.parent_pidfd)
                                               or self.monotonic() >= handle.expires):
            self._stop(handle, timeout=min(timeout, 5.0))
            raise AuthorityDenied("process.expired", "parent, lease or service lifetime ended")
        if operation == "process.status":
            code = handle.launcher.poll()
            if item.get("include_children", False):
                raise AuthorityDenied("process.status", "child snapshots are not available through this fixed status schema")
            return _response(200, {"schema": 1, "state": "running" if code is None else "exited",
                "pid": handle.pid, "uid": profile.owner_uid, "namespace_id": handle.kernel_namespace_id,
                "generation": profile.generation, "stdout_cursor": handle.stdout_cursor,
                "stderr_cursor": handle.stderr_cursor, "expires_at_monotonic": handle.expires,
                "exit_code": code, "cgroup": handle.cgroup, "kernel_limits": self._limits(handle.cgroup)})
        if operation == "process.read":
            stream_name, cursor, maximum = item["stream"], item["after_cursor"], item["max_bytes"]
            if (stream_name not in {"stdout", "stderr"} or type(cursor) is not int
                    or type(maximum) is not int or not 1 <= maximum <= 65536):
                raise AuthorityDenied("process.read", "stream or read bounds are invalid")
            current = handle.stdout_cursor if stream_name == "stdout" else handle.stderr_cursor
            if cursor != current:
                raise AuthorityDenied("process.cursor", "read cursor is stale")
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
                current = handle.stdout_cursor
            else:
                handle.stderr_cursor += len(data)
                current = handle.stderr_cursor
            return _response(200, {"schema": 1, "stream": stream_name, "cursor": current,
                "data": base64.b64encode(data).decode("ascii"), "eof": eof})
        if operation == "process.write":
            cursor = item["stdin_cursor"]
            try:
                data = base64.b64decode(item["data"], validate=True)
            except Exception:
                raise AuthorityDenied("process.write", "stdin data is malformed") from None
            if (type(cursor) is not int or cursor != handle.stdin_cursor or len(data) > 65536
                    or handle.launcher.stdin is None):
                raise AuthorityDenied("process.cursor", "stdin cursor or data length is invalid")
            fd = handle.launcher.stdin.fileno()
            _, writable, _ = select.select([], [fd], [], min(max(timeout, 0), .75))
            try:
                written = os.write(fd, data) if writable else 0
            except BlockingIOError:
                written = 0
            handle.stdin_cursor += written
            return _response(200, {"schema": 1, "stdin_cursor": handle.stdin_cursor, "bytes_written": written})
        proof = self._stop(handle, timeout=min(timeout, 5.0))
        return _response(200, {"schema": 1, "stopped": True,
            "cleanup_verified": proof.cleanup_verified, "cgroup_empty": proof.cgroup_empty,
            "pidfd_gone": proof.main_pidfd_gone, "evidence_digest": proof.evidence_digest})

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
            with self._lock:
                self._handles.pop(handle.process_id, None)
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
            try:
                _remove_artifact_mount(handle.artifact_mount_dir)
            finally:
                if handle.native_mount_source is not None:
                    self._remove_native_staging(handle.native_mount_source)
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
