"""Root-resolved immutable service, device, and fixed build enrollments.

This module contains no privilege escalation or generic command runner. It turns
root-owned enrollment records into immutable policies used by already reviewed
host handlers. Callers provide opaque IDs and generation only.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping


class EnrollmentDenied(PermissionError):
    """Protected enrollment is absent, stale, malformed, or no longer attested."""


_BUILD_ENV = frozenset({"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH",
                        "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS"})
_PROFILE_ENV = frozenset({"HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY",
                          "XDG_RUNTIME_DIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "TMPDIR"})
_FIXED_OPERATIONS = frozenset({"process.start", "process.status", "process.read", "process.write",
                               "process.stop", "process.inspect", "connector.open", "package.install"})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _id(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value)):
        raise EnrollmentDenied(f"protected {label} is invalid")
    return value


def _absolute(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not Path(value).is_absolute() or "\x00" in value:
        raise EnrollmentDenied(f"protected {label} path is invalid")
    return Path(value)


def _owned_path(path: Path, *, uid: int, directory: bool) -> Path:
    """Require every ancestor and final object to be non-symlink and trusted."""
    if not path.is_absolute():
        raise EnrollmentDenied("protected path must be absolute")
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        try:
            info = cursor.lstat()
        except OSError:
            raise EnrollmentDenied("protected path is unavailable") from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
            raise EnrollmentDenied("protected path custody is invalid")
    info = path.stat(follow_symlinks=False)
    if directory != stat.S_ISDIR(info.st_mode):
        raise EnrollmentDenied("protected path type is invalid")
    return path


@dataclass(frozen=True, slots=True)
class OwnedRoots:
    home_id: str
    work_id: str
    data_id: str
    home: Path
    work: Path
    data: Path
    owner_uid: int
    owner_gid: int

    def validate(self, *, root_uid: int = 0) -> None:
        paths = (self.home, self.work, self.data)
        if len({str(path) for path in paths}) != 3:
            raise EnrollmentDenied("service home, work, and data roots must be distinct")
        for path in paths:
            try:
                info = path.lstat()
            except OSError:
                raise EnrollmentDenied("service root is unavailable") from None
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != self.owner_uid or info.st_gid != self.owner_gid
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise EnrollmentDenied("service roots must be owner-only 0700 directories")
        # Root-owned policies and ancestors protect the names; the leaf itself is
        # service-owned and intentionally writable by that one service identity.
        for path in paths:
            parent = path.parent
            while parent != Path(parent.anchor):
                info = parent.lstat()
                if stat.S_ISLNK(info.st_mode) or info.st_uid != root_uid or info.st_mode & 0o022:
                    raise EnrollmentDenied("service root ancestor is not root protected")
                parent = parent.parent


@dataclass(frozen=True, slots=True)
class PackageRuntimeEnrollment:
    runtime_artifact_id: str
    runtime_build_attestation_digest: str
    runtime_executable_sha256: str
    runtime_build_output: str
    abi: str
    target_glibc_min: str
    venv_root_id: str
    policy_revision: str
    runtime_executable: Path
    venv_root: Path
    build_target: str
    build_generation: str


@dataclass(frozen=True, slots=True)
class HostServiceProfile:
    enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    service_uid: int
    service_gid: int
    service_user: str
    executable: Path
    executable_sha256: str
    runtime_artifact_ids: tuple[str, ...]
    package_runtime_records: Mapping[str, "PackageRuntimeEnrollment"]
    roots: OwnedRoots
    authority_endpoint_id: str
    namespace_identity: str
    socket_policy_id: str
    target_route_ids: tuple[str, ...]
    operation_targets: Mapping[str, str]
    argv_recipe: tuple[str, ...]
    environment: Mapping[str, str]
    max_lifetime_seconds: int
    memory_max_bytes: int
    cpu_quota_percent: int
    io_weight: int

    def as_managed_profile(self, *, artifact_root: Path, child_artifact_refs: Mapping[str, str]):
        """Create the process-custodian record using only root-resolved fields."""
        from hermes_installer.managed_process_custodian import ManagedProfileCustody
        self.roots.validate()
        return ManagedProfileCustody(
            profile_id=self.profile_id, owner_uid=self.service_uid,
            owner_gid=self.service_gid, service_user=self.service_user,
            executable=self.executable, artifact_sha256=self.executable_sha256,
            artifact_root=artifact_root, data_root=self.roots.data,
            generation=self.generation, memory_max_bytes=self.memory_max_bytes,
            cpu_quota_percent=self.cpu_quota_percent, io_weight=self.io_weight,
            max_lifetime_seconds=self.max_lifetime_seconds,
            child_artifact_refs=dict(child_artifact_refs), argv_recipe=self.argv_recipe,
        )


class ProtectedEnrollmentCatalog:
    """Immutable root-owned mapping from caller opaque IDs to service policy."""

    def __init__(self, records: Mapping[tuple[str, str], HostServiceProfile], *, digest: str):
        if not records:
            raise EnrollmentDenied("protected service enrollment is empty")
        self._records = MappingProxyType(dict(records))
        self.digest = digest

    @classmethod
    def from_file(cls, path: Path, *, signature_verifier: Callable[[bytes, str], bool],
                  expected_uid: int = 0) -> "ProtectedEnrollmentCatalog":
        _owned_path(path, uid=expected_uid, directory=False)
        info = path.stat(follow_symlinks=False)
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise EnrollmentDenied("protected enrollment file must be mode 0600")
        try:
            raw_bytes = path.read_bytes()
            doc = json.loads(raw_bytes.decode("utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise EnrollmentDenied("protected enrollment file is malformed") from None
        if not isinstance(doc, dict) or set(doc) != {"schema", "records", "manifest_sha256", "signature"}:
            raise EnrollmentDenied("protected enrollment manifest fields are invalid")
        if type(doc["schema"]) is not int or doc["schema"] != 1 or not isinstance(doc["records"], list):
            raise EnrollmentDenied("protected enrollment schema is invalid")
        unsigned = {key: doc[key] for key in ("schema", "records")}
        digest = hashlib.sha256(_canonical(unsigned)).hexdigest()
        if digest != doc["manifest_sha256"] or not signature_verifier(bytes.fromhex(digest), doc["signature"]):
            raise EnrollmentDenied("protected enrollment signature or digest is invalid")
        return cls.from_verified_records(doc["records"], protected_digest=digest,
                                         expected_uid=expected_uid)

    @classmethod
    def from_verified_records(cls, raw_records: list[Mapping[str, Any]], *,
                              protected_digest: str, expected_uid: int = 0) -> "ProtectedEnrollmentCatalog":
        """Build from records already authenticated by the root enrollment loader."""
        if (not isinstance(protected_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", protected_digest)
                or not isinstance(raw_records, list)):
            raise EnrollmentDenied("verified enrollment source is malformed")
        records = {}
        for item in raw_records:
            profile = _parse_profile(item)
            key = (profile.enrollment_id, profile.generation)
            if key in records:
                raise EnrollmentDenied("protected enrollment ID and generation are duplicated")
            profile.roots.validate(root_uid=expected_uid)
            records[key] = profile
        return cls(records, digest=protected_digest)

    def resolve(self, enrollment_id: str, generation: str) -> HostServiceProfile:
        key = (_id(enrollment_id, "enrollment ID"), _id(generation, "generation"))
        profile = self._records.get(key)
        if profile is None:
            raise EnrollmentDenied("opaque enrollment or generation is not current")
        profile.roots.validate()
        try:
            account = pwd.getpwnam(profile.service_user)
        except KeyError:
            raise EnrollmentDenied("enrolled service account is unavailable") from None
        if account.pw_uid != profile.service_uid or account.pw_gid != profile.service_gid:
            raise EnrollmentDenied("enrolled service account UID/GID changed")
        executable = _owned_path(profile.executable, uid=0, directory=False)
        executable_info = executable.stat(follow_symlinks=False)
        if (not executable_info.st_mode & 0o111
                or hashlib.sha256(executable.read_bytes()).hexdigest() != profile.executable_sha256):
            raise EnrollmentDenied("enrolled service executable changed or is not executable")
        return profile

    def resolve_package_runtime(self, enrollment_id: str, generation: str,
                                package_set_id: str, build_catalog: "ProtectedBuildCatalog"):
        """Resolve a Coral runtime binding from protected enrollment and attested outputs."""
        profile = self.resolve(enrollment_id, generation)
        package_id = _id(package_set_id, "package set ID")
        if package_id != "coral-cp39-runtime-v1":
            raise EnrollmentDenied("package set is not root-enrolled")
        record = profile.package_runtime_records.get(package_id)
        if record is None:
            raise EnrollmentDenied("package runtime is not enrolled")
        if (record.runtime_artifact_id != "coral-python39-source" or record.abi != "cp39/aarch64"
                or record.target_glibc_min != "2.34"
                or record.build_target != "coral-cpython-build:start"):
            raise EnrollmentDenied("Coral package set is bound to a different runtime or build recipe")
        if record.runtime_artifact_id not in profile.runtime_artifact_ids:
            raise EnrollmentDenied("runtime artifact is outside the profile artifact closure")
        if record.build_generation != profile.generation:
            raise EnrollmentDenied("package runtime build generation is stale")
        build = build_catalog.resolve(record.build_target, record.build_generation)
        output_digests = build.attest_outputs()
        if (record.runtime_build_output not in output_digests
                or output_digests[record.runtime_build_output] != record.runtime_executable_sha256):
            raise EnrollmentDenied("installed runtime executable is not an attested build output")
        attestation = hashlib.sha256(_canonical({
            "target_id": build.target_id, "generation": build.generation,
            "source_artifact_id": build.source_artifact_id, "source_sha256": build.source_sha256,
            "toolchain_artifact_id": build.toolchain_artifact_id, "toolchain_sha256": build.toolchain_sha256,
            "builder_artifact_id": build.builder_artifact_id, "builder_sha256": build.builder_sha256,
            "outputs": output_digests,
        })).hexdigest()
        if attestation != record.runtime_build_attestation_digest:
            raise EnrollmentDenied("runtime build attestation does not match root enrollment")
        glibc = _system_glibc_version()
        if not _version_at_least(glibc, record.target_glibc_min):
            raise EnrollmentDenied("target glibc is below the enrolled Coral runtime minimum")
        executable = _owned_path(record.runtime_executable, uid=0, directory=False)
        if hashlib.sha256(executable.read_bytes()).hexdigest() != record.runtime_executable_sha256:
            raise EnrollmentDenied("root-enrolled runtime executable digest changed")
        venv = record.venv_root
        venv_info = venv.lstat()
        if (stat.S_ISLNK(venv_info.st_mode) or not stat.S_ISDIR(venv_info.st_mode)
                or venv_info.st_uid != profile.service_uid or venv_info.st_gid != profile.service_gid
                or stat.S_IMODE(venv_info.st_mode) != 0o700):
            raise EnrollmentDenied("dedicated package venv root custody is invalid")
        if venv in {profile.roots.home, profile.roots.work, profile.roots.data}:
            raise EnrollmentDenied("package venv must have a distinct service-owned root")
        for parent in venv.parents:
            if parent == Path(parent.anchor):
                break
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise EnrollmentDenied("package venv ancestor is not root protected")
        from hermes_installer.artifacts import PackageSetRuntimeBinding
        return PackageSetRuntimeBinding(
            enrollment_id=profile.enrollment_id, generation=profile.generation,
            runtime_artifact_id=record.runtime_artifact_id,
            runtime_build_attestation_digest=attestation,
            runtime_executable_sha256=record.runtime_executable_sha256,
            abi=record.abi, glibc_version=glibc,
            service_uid=profile.service_uid, service_gid=profile.service_gid,
            venv_root_id=record.venv_root_id, policy_revision=record.policy_revision,
            runtime_executable=executable, venv_root=venv,
        )

    def resolve_connector_route(self, enrollment_id: str, generation: str,
                                target_id: str, route_id: str) -> "ConnectorRouteBinding":
        profile = self.resolve(enrollment_id, generation)
        target = _id(target_id, "connector target")
        route = _id(route_id, "connector route")
        if target not in {"xpra-native", "colibri-main"} or route not in profile.target_route_ids:
            raise EnrollmentDenied("connector target or route is outside protected enrollment")
        if target == "xpra-native" and profile.profile_id != "hermes-desktop":
            raise EnrollmentDenied("Xpra target is not bound to the enrolled Desktop profile")
        if target == "colibri-main" and "colibri" not in profile.profile_id:
            raise EnrollmentDenied("Colibri target is not bound to its enrolled service profile")
        return ConnectorRouteBinding(profile.profile_id, profile.generation,
                                     profile.namespace_identity, target, route)

    def resolve_operation(self, enrollment_id: str, generation: str,
                          operation: str) -> OperationBinding:
        profile = self.resolve(enrollment_id, generation)
        verb = _id(operation, "operation")
        if verb not in _FIXED_OPERATIONS:
            raise EnrollmentDenied("operation is not in the fixed host-service interface")
        target = profile.operation_targets.get(verb)
        if target is None:
            raise EnrollmentDenied("operation is not enrolled for this service generation")
        return OperationBinding(profile.enrollment_id, profile.generation, profile.profile_id,
                                profile.principal_id, verb, target, profile.service_uid,
                                profile.service_gid, profile.authority_endpoint_id,
                                profile.namespace_identity)


def _system_glibc_version() -> str:
    try:
        value = os.confstr("CS_GNU_LIBC_VERSION")
    except (OSError, ValueError):
        value = None
    match = re.fullmatch(r"glibc ([0-9]+\.[0-9]+(?:\.[0-9]+)?)", value or "")
    if match is None:
        raise EnrollmentDenied("target glibc version cannot be established")
    return match.group(1)


def _version_at_least(actual: str, required: str) -> bool:
    def parts(value: str) -> tuple[int, ...]:
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,2}", value):
            raise EnrollmentDenied("glibc version is malformed")
        return tuple(int(part) for part in value.split("."))
    left, right = parts(actual), parts(required)
    width = max(len(left), len(right))
    return left + (0,) * (width - len(left)) >= right + (0,) * (width - len(right))


@dataclass(frozen=True, slots=True)
class ConnectorRouteBinding:
    """Route authorization metadata; not a socket or namespace descriptor."""
    profile_id: str
    generation: str
    namespace_identity: str
    target_id: str
    route_id: str


@dataclass(frozen=True, slots=True)
class OperationBinding:
    """Root-enrolled operation target; contains no caller-selected resource path."""
    enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    operation: str
    target_id: str
    service_uid: int
    service_gid: int
    authority_endpoint_id: str
    namespace_identity: str


def _parse_profile(item: Any) -> HostServiceProfile:
    fields = {"enrollment_id", "generation", "profile_id", "principal_id", "service_uid", "service_gid", "service_user",
              "executable", "executable_sha256", "runtime_artifact_ids", "package_runtime_records", "roots", "authority_endpoint_id",
              "namespace_identity", "socket_policy_id", "target_route_ids", "operation_targets", "argv_recipe", "environment",
              "max_lifetime_seconds", "memory_max_bytes", "cpu_quota_percent", "io_weight"}
    if not isinstance(item, dict) or set(item) != fields:
        raise EnrollmentDenied("protected service profile fields are invalid")
    roots = item["roots"]
    if not isinstance(roots, dict) or set(roots) != {"home_id", "work_id", "data_id", "home", "work", "data"}:
        raise EnrollmentDenied("protected root mapping is malformed")
    uid, gid = item["service_uid"], item["service_gid"]
    ints = (uid, gid, item["max_lifetime_seconds"], item["memory_max_bytes"], item["cpu_quota_percent"], item["io_weight"])
    if any(type(number) is not int or number <= 0 for number in ints):
        raise EnrollmentDenied("protected service limits or identity are invalid")
    executable = _absolute(item["executable"], "executable")
    if not re.fullmatch(r"[0-9a-f]{64}", str(item["executable_sha256"])):
        raise EnrollmentDenied("protected executable digest is invalid")
    if not isinstance(item["runtime_artifact_ids"], list) or not item["runtime_artifact_ids"]:
        raise EnrollmentDenied("immutable runtime artifacts are required")
    recipe = item["argv_recipe"]
    env = item["environment"]
    targets = item["operation_targets"]
    routes = item["target_route_ids"]
    raw_packages = item["package_runtime_records"]
    if (not isinstance(recipe, list) or not recipe or any(not isinstance(x, str) or "\x00" in x for x in recipe)
            or not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in env.items())
            or not isinstance(targets, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in targets.items())
            or not isinstance(routes, list) or any(not isinstance(route, str) for route in routes)
            or len(routes) != len(set(routes)) or not isinstance(raw_packages, dict)):
        raise EnrollmentDenied("protected launch or operation policy is malformed")
    if set(env) - _PROFILE_ENV or any(re.search(r"token|secret|credential|password|api[_-]?key", key, re.I) for key in env):
        raise EnrollmentDenied("profile environment contains an unapproved or credential-like variable")
    if set(targets) - _FIXED_OPERATIONS:
        raise EnrollmentDenied("protected operation map contains an unreviewed operation")
    packages = {}
    package_fields = {"runtime_artifact_id", "runtime_build_attestation_digest", "runtime_executable_sha256",
                      "runtime_build_output", "abi", "target_glibc_min", "venv_root_id", "policy_revision", "runtime_executable",
                      "venv_root", "build_target", "build_generation"}
    for package_id, raw in raw_packages.items():
        if not isinstance(raw, dict) or set(raw) != package_fields:
            raise EnrollmentDenied("protected package runtime fields are malformed")
        digests = (raw["runtime_build_attestation_digest"], raw["runtime_executable_sha256"])
        if any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in digests):
            raise EnrollmentDenied("protected package runtime digest is malformed")
        glibc = raw["target_glibc_min"]
        if not isinstance(glibc, str) or not re.fullmatch(r"[0-9]+\.[0-9]+", glibc):
            raise EnrollmentDenied("protected package minimum glibc is malformed")
        build_output = raw["runtime_build_output"]
        output_path = Path(build_output) if isinstance(build_output, str) else Path("/")
        if not isinstance(build_output, str) or output_path.is_absolute() or any(part in {"", ".", ".."} for part in output_path.parts):
            raise EnrollmentDenied("protected runtime build output path is unsafe")
        packages[_id(package_id, "package set ID")] = PackageRuntimeEnrollment(
            _id(raw["runtime_artifact_id"], "runtime artifact ID"), digests[0], digests[1],
            build_output,
            _id(raw["abi"], "runtime ABI"), glibc, _id(raw["venv_root_id"], "venv root ID"),
            _id(raw["policy_revision"], "runtime policy revision"),
            _absolute(raw["runtime_executable"], "runtime executable"),
            _absolute(raw["venv_root"], "venv root"), _id(raw["build_target"], "build target"),
            _id(raw["build_generation"], "build generation"))
    return HostServiceProfile(
        _id(item["enrollment_id"], "enrollment ID"), _id(item["generation"], "generation"),
        _id(item["profile_id"], "profile ID"), _id(item["principal_id"], "principal ID"), uid, gid,
        _id(item["service_user"], "service username"), executable, item["executable_sha256"],
        tuple(_id(x, "runtime artifact ID") for x in item["runtime_artifact_ids"]), MappingProxyType(packages),
        OwnedRoots(_id(roots["home_id"], "home root ID"), _id(roots["work_id"], "work root ID"),
                   _id(roots["data_id"], "data root ID"), _absolute(roots["home"], "home"),
                   _absolute(roots["work"], "work"), _absolute(roots["data"], "data"), uid, gid),
        _id(item["authority_endpoint_id"], "authority endpoint ID"),
        _id(item["namespace_identity"], "namespace identity"), _id(item["socket_policy_id"], "socket policy ID"),
        tuple(_id(route, "target route ID") for route in routes),
        MappingProxyType({_id(key, "operation"): _id(value, "operation target")
                          for key, value in targets.items()}),
        tuple(recipe), MappingProxyType(dict(env)),
        item["max_lifetime_seconds"], item["memory_max_bytes"],
        item["cpu_quota_percent"], item["io_weight"],
    )


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Exact root-selected Coral device identity, re-attested before each use."""
    transport: str
    physical_identity: str
    sysfs_path: Path
    device_node: Path
    major: int
    minor: int
    inode: int
    generation: str
    vendor_id: str
    product_id: str
    interface_identity: str | None = None
    interface_sysfs_path: Path | None = None
    driver: str | None = None

    @property
    def device_allow(self) -> str:
        return f"char-{self.major}:{self.minor}:rwm"

    @property
    def selection_digest(self) -> str:
        payload = {"transport": self.transport, "physical_identity": self.physical_identity,
                   "sysfs_path": str(self.sysfs_path), "device_node": str(self.device_node),
                   "major": self.major, "minor": self.minor, "inode": self.inode,
                   "generation": self.generation, "vendor_id": self.vendor_id,
                   "product_id": self.product_id, "interface_identity": self.interface_identity,
                   "interface_sysfs_path": str(self.interface_sysfs_path) if self.interface_sysfs_path else None,
                   "driver": self.driver}
        return hashlib.sha256(_canonical(payload)).hexdigest()

    def verify_current(self) -> None:
        if self.transport not in {"usb", "pci"} or not self.sysfs_path.is_absolute() or not self.device_node.is_absolute():
            raise EnrollmentDenied("selected Coral device identity is malformed")
        try:
            sysfs = self.sysfs_path.resolve(strict=True)
            node = self.device_node.stat(follow_symlinks=False)
            if self.transport == "usb":
                vendor = (self.sysfs_path / "idVendor").read_text().strip().lower()
                product = (self.sysfs_path / "idProduct").read_text().strip().lower()
                if vendor != self.vendor_id or product != self.product_id:
                    raise EnrollmentDenied("selected USB TPU identity changed")
                if (self.interface_identity is None or self.interface_sysfs_path is None
                        or self.interface_sysfs_path.name != self.interface_identity):
                    raise EnrollmentDenied("selected USB interface identity is incomplete")
                self.interface_sysfs_path.resolve(strict=True)
            else:
                vendor = (self.sysfs_path / "vendor").read_text().strip().lower()
                product = (self.sysfs_path / "device").read_text().strip().lower()
                if vendor != self.vendor_id or product != self.product_id:
                    raise EnrollmentDenied("selected PCI TPU identity changed")
                current_driver = (self.sysfs_path / "driver").resolve(strict=True).name
                if current_driver != self.driver:
                    raise EnrollmentDenied("selected PCI TPU driver changed")
        except EnrollmentDenied:
            raise
        except OSError:
            raise EnrollmentDenied("selected TPU was removed; enrollment generation is invalid") from None
        if (sysfs != self.sysfs_path.resolve() or not stat.S_ISCHR(node.st_mode)
                or os.major(node.st_rdev) != self.major or os.minor(node.st_rdev) != self.minor
                or node.st_ino != self.inode):
            raise EnrollmentDenied("selected TPU path was reused or changed")


class ProtectedDeviceCatalog:
    """Opaque selector to root-selected device; every resolve rechecks hotplug state."""

    def __init__(self, devices: Mapping[str, DeviceIdentity]):
        if not devices or len(devices) != len(set(devices)):
            raise EnrollmentDenied("protected TPU device catalog is empty or duplicated")
        physical = [device.physical_identity for device in devices.values()]
        if len(physical) != len(set(physical)):
            raise EnrollmentDenied("one physical TPU cannot have multiple active enrollment IDs")
        self._devices = MappingProxyType(dict(devices))

    @classmethod
    def from_protected_records(cls, records: list[Mapping[str, Any]]) -> "ProtectedDeviceCatalog":
        devices = {}
        fields = {"device_id", "transport", "physical_identity", "sysfs_path", "device_node",
                  "major", "minor", "inode", "generation", "vendor_id", "product_id",
                  "interface_identity", "interface_sysfs_path", "driver"}
        for record in records:
            if set(record) != fields:
                raise EnrollmentDenied("protected TPU identity record fields are invalid")
            device_id = _id(record["device_id"], "device ID")
            transport = record["transport"]
            if transport not in {"usb", "pci"}:
                raise EnrollmentDenied("protected TPU transport is unsupported")
            numbers = (record["major"], record["minor"], record["inode"])
            if any(type(n) is not int or n < 0 for n in numbers) or record["inode"] == 0:
                raise EnrollmentDenied("protected TPU device node identity is malformed")
            vendor = str(record["vendor_id"]).lower()
            product = str(record["product_id"]).lower()
            expected_width = 4
            if not re.fullmatch(rf"[0-9a-f]{{{expected_width}}}", vendor) or not re.fullmatch(rf"[0-9a-f]{{{expected_width}}}", product):
                raise EnrollmentDenied("protected TPU vendor/product identity is malformed")
            physical = _id(record["physical_identity"], "physical device identity")
            driver = None if record["driver"] is None else _id(record["driver"], "device driver")
            if transport == "pci" and (driver is None or not re.fullmatch(r"[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]", physical)):
                raise EnrollmentDenied("PCI TPU requires an exact BDF and enrolled driver")
            if transport == "usb" and driver is not None:
                raise EnrollmentDenied("USB TPU records cannot select a PCI driver")
            if transport == "usb":
                interface_identity = _id(record["interface_identity"], "USB interface identity")
                interface_path = _absolute(record["interface_sysfs_path"], "USB interface sysfs")
                if not re.fullmatch(re.escape(physical) + r":[0-9]+\.[0-9]+", interface_identity) or interface_path.name != interface_identity:
                    raise EnrollmentDenied("USB TPU requires one exact sysfs interface")
            else:
                if record["interface_identity"] is not None or record["interface_sysfs_path"] is not None:
                    raise EnrollmentDenied("PCI TPU cannot select a USB interface")
                interface_identity, interface_path = None, None
            if transport == "usb" and (vendor, product) != ("18d1", "9302"):
                raise EnrollmentDenied("USB identity is not the supported Coral TPU")
            if transport == "pci" and (vendor, product) != ("1ac1", "089a"):
                raise EnrollmentDenied("PCI identity is not the supported Coral TPU")
            sysfs_path = _absolute(record["sysfs_path"], "TPU sysfs")
            device_node = _absolute(record["device_node"], "TPU node")
            if (sysfs_path.name.casefold() != physical.casefold()
                    or transport == "usb" and not re.fullmatch(r"/dev/bus/usb/[0-9]{3}/[0-9]{3}", str(device_node))
                    or transport == "pci" and not re.fullmatch(r"/dev/apex_[0-9]+", str(device_node))):
                raise EnrollmentDenied("TPU physical path or device node is not exact")
            device = DeviceIdentity(transport, physical,
                sysfs_path, device_node,
                record["major"], record["minor"], record["inode"], _id(record["generation"], "generation"),
                vendor, product, interface_identity, interface_path, driver)
            if device_id in devices:
                raise EnrollmentDenied("protected TPU device ID is duplicated")
            devices[device_id] = device
        return cls(devices)

    def resolve(self, device_id: str, generation: str) -> DeviceIdentity:
        selected = self._devices.get(_id(device_id, "device ID"))
        if selected is None or selected.generation != _id(generation, "generation"):
            raise EnrollmentDenied("selected TPU enrollment or generation is stale")
        selected.verify_current()
        return selected


@dataclass(frozen=True, slots=True)
class FixedBuildProfile:
    target_id: str
    generation: str
    source_artifact_id: str
    source_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    builder_artifact_id: str
    builder_sha256: str
    argv_recipe: tuple[str, ...]
    environment: Mapping[str, str]
    max_lifetime_seconds: int
    output_root_id: str
    output_root: Path
    output_owner_uid: int
    required_outputs: Mapping[str, str]

    @classmethod
    def from_protected_record(cls, item: Mapping[str, Any]) -> "FixedBuildProfile":
        required = {"target_id", "generation", "source_artifact_id", "source_sha256", "toolchain_artifact_id",
                    "toolchain_sha256", "builder_artifact_id", "builder_sha256", "argv_recipe", "environment",
                    "max_lifetime_seconds", "output_root_id", "output_root", "output_owner_uid", "required_outputs"}
        if set(item) != required or item.get("target_id") not in {"coral-cpython-build:start", "colibri-source-build:start"}:
            raise EnrollmentDenied("fixed native build profile is unknown or malformed")
        for name in ("source_sha256", "toolchain_sha256", "builder_sha256"):
            if not isinstance(item[name], str) or not re.fullmatch(r"[0-9a-f]{64}", item[name]):
                raise EnrollmentDenied("fixed build source/toolchain/builder digest is invalid")
        recipe = item["argv_recipe"]
        env = item["environment"]
        outputs = item["required_outputs"]
        if (not isinstance(recipe, list) or not recipe or any(not isinstance(arg, str) or "\x00" in arg for arg in recipe)
                or not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in env.items())
                or not isinstance(outputs, dict) or not outputs or any(not isinstance(k, str) or not re.fullmatch(r"[0-9a-f]{64}", str(v)) for k, v in outputs.items())):
            raise EnrollmentDenied("fixed native build recipe or outputs are malformed")
        if (set(env) - _BUILD_ENV
                or any(re.search(r"token|secret|credential|password|api[_-]?key", key, re.I) for key in env)
                or any("\n" in value or "\r" in value or "$" in value or "`" in value for value in env.values())):
            raise EnrollmentDenied("fixed native build environment is not sanitized")
        for output in outputs:
            path = Path(output)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise EnrollmentDenied("fixed build output path is unsafe")
        if (not Path(recipe[0]).is_absolute()
                or Path(recipe[0]).name.casefold() in {"sh", "bash", "dash", "zsh"}
                or any(token in {"-c", "-e", "--command"} for token in recipe[1:])
                or any("{caller" in token or "${" in token for token in recipe)):
            raise EnrollmentDenied("fixed native build recipe cannot select shell or caller code")
        lifetime = item["max_lifetime_seconds"]
        owner_uid = item["output_owner_uid"]
        if type(lifetime) is not int or not 1 <= lifetime <= 600 or type(owner_uid) is not int or owner_uid <= 0:
            raise EnrollmentDenied("fixed native build deadline is invalid")
        return cls(_id(item["target_id"], "build target"), _id(item["generation"], "generation"),
                   _id(item["source_artifact_id"], "source artifact ID"), item["source_sha256"],
                   _id(item["toolchain_artifact_id"], "toolchain artifact ID"), item["toolchain_sha256"],
                   _id(item["builder_artifact_id"], "builder artifact ID"), item["builder_sha256"],
                   tuple(recipe), MappingProxyType(dict(env)),
                   lifetime, _id(item["output_root_id"], "output root ID"),
                   _absolute(item["output_root"], "build output root"), owner_uid, MappingProxyType(dict(outputs)))

    def attest_outputs(self, output_root: Path | None = None) -> Mapping[str, str]:
        root = self.output_root if output_root is None else output_root
        if root != self.output_root:
            raise EnrollmentDenied("caller-selected build output path is forbidden")
        if root != self.output_root or not root.is_absolute():
            raise EnrollmentDenied("caller-selected build output path is forbidden")
        for parent in (root.parent, *root.parent.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise EnrollmentDenied("build output ancestor is not root protected")
        root_info = root.lstat()
        if (stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid != self.output_owner_uid or stat.S_IMODE(root_info.st_mode) != 0o700):
            raise EnrollmentDenied("build output staging root custody is invalid")
        observed = {}
        for relative, expected in self.required_outputs.items():
            pure = Path(relative)
            if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
                raise EnrollmentDenied("protected build output path is unsafe")
            candidate = root / relative
            try:
                cursor = root
                for part in pure.parts[:-1]:
                    cursor = cursor / part
                    directory = cursor.lstat()
                    if (stat.S_ISLNK(directory.st_mode) or not stat.S_ISDIR(directory.st_mode)
                            or directory.st_uid != self.output_owner_uid):
                        raise EnrollmentDenied("native build output directory custody is invalid")
                info = candidate.lstat()
                if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                        or info.st_uid != self.output_owner_uid):
                    raise EnrollmentDenied("native build output custody is invalid")
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            except EnrollmentDenied:
                raise
            except OSError:
                raise EnrollmentDenied("required native build output is missing") from None
            if digest != expected:
                raise EnrollmentDenied("native build output digest does not match protected attestation")
            observed[relative] = digest
        return observed


class ProtectedBuildCatalog:
    """The only startable hardware build targets and their fixed root recipes."""

    REQUIRED_TARGETS = frozenset({"coral-cpython-build:start", "colibri-source-build:start"})

    def __init__(self, profiles: Mapping[tuple[str, str], FixedBuildProfile]):
        self._profiles = MappingProxyType(dict(profiles))
        if not self._profiles:
            raise EnrollmentDenied("protected build catalog is empty")
        if any(target not in self.REQUIRED_TARGETS for target, _ in self._profiles):
            raise EnrollmentDenied("unknown hardware build target is not allowed")

    @classmethod
    def from_protected_records(cls, records: list[Mapping[str, Any]]) -> "ProtectedBuildCatalog":
        profiles = {}
        for item in records:
            profile = FixedBuildProfile.from_protected_record(item)
            key = (profile.target_id, profile.generation)
            if key in profiles:
                raise EnrollmentDenied("fixed build target generation is duplicated")
            profiles[key] = profile
        return cls(profiles)

    def resolve(self, target_id: str, generation: str) -> FixedBuildProfile:
        target = _id(target_id, "build target")
        if target not in self.REQUIRED_TARGETS:
            raise EnrollmentDenied("build target is not root-enrolled")
        profile = self._profiles.get((target, _id(generation, "generation")))
        if profile is None:
            raise EnrollmentDenied("fixed build profile generation is stale")
        return profile
