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
import unicodedata
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
_OPERATION_ENV = frozenset({"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR", "SOURCE_DATE_EPOCH",
                            "CC", "CXX", "AR", "RANLIB", "CFLAGS", "CPPFLAGS", "LDFLAGS", "MAKEFLAGS"})
_FIXED_OPERATIONS = frozenset({"process.start", "process.status", "process.read", "process.write",
                               "process.stop", "process.inspect", "connector.open", "package.install"})
OPERATION_PARAMETER_CATALOG_PATH = Path("/etc/hermes-installer/operation-parameters.json")


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
class OperationParameterField:
    name: str
    type: str
    required: bool
    enum: tuple[str, ...] | None = None
    max_length: int | None = None
    minimum: int | None = None
    maximum: int | None = None


@dataclass(frozen=True, slots=True)
class OperationParameterSchema:
    schema_id: str
    fields: Mapping[str, OperationParameterField]

    @classmethod
    def from_protected_record(cls, item: Mapping[str, Any]) -> "OperationParameterSchema":
        if not isinstance(item, Mapping) or set(item) != {"id", "fields"}:
            raise EnrollmentDenied("protected operation parameter schema fields are invalid")
        schema_id = _id(item["id"], "operation parameter schema ID")
        rows = item["fields"]
        if not isinstance(rows, list) or len(rows) > 64:
            raise EnrollmentDenied("operation parameter schema fields are invalid")
        fields = {}
        for row in rows:
            keys = {"name", "type", "required", "enum", "max_length", "minimum", "maximum"}
            if not isinstance(row, Mapping) or set(row) != keys:
                raise EnrollmentDenied("operation parameter field shape is invalid")
            name, kind, required = row["name"], row["type"], row["required"]
            if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name)
                    or name in fields or not isinstance(kind, str) or kind not in {"string", "integer", "boolean"}
                    or type(required) is not bool):
                raise EnrollmentDenied("operation parameter field identity or type is invalid")
            enum = row["enum"]
            max_length, minimum, maximum = row["max_length"], row["minimum"], row["maximum"]
            if kind == "string":
                if (enum is not None and (not isinstance(enum, list) or not enum
                        or any(not isinstance(v, str) or not v or any(unicodedata.category(c) == "Cc" for c in v)
                               for v in enum)
                        or len(enum) != len(set(enum)))
                        or type(max_length) is not int or not 1 <= max_length <= 4096
                        or minimum is not None or maximum is not None or enum is None):
                    raise EnrollmentDenied("bounded string parameter schema is invalid")
            elif kind == "integer":
                if (enum is not None or max_length is not None or type(minimum) is not int
                        or type(maximum) is not int or minimum > maximum):
                    raise EnrollmentDenied("bounded integer parameter schema is invalid")
            elif enum is not None or max_length is not None or minimum is not None or maximum is not None:
                raise EnrollmentDenied("boolean parameter schema has unsupported constraints")
            fields[name] = OperationParameterField(
                name, kind, required, None if enum is None else tuple(enum),
                max_length, minimum, maximum,
            )
        return cls(schema_id, MappingProxyType(fields))

    def validate(self, value: Any) -> Mapping[str, str]:
        if not isinstance(value, Mapping) or set(value) - self.fields.keys():
            raise EnrollmentDenied("operation parameters contain unknown fields")
        rendered = {}
        for name, field in self.fields.items():
            if name not in value:
                if field.required:
                    raise EnrollmentDenied("required operation parameter is absent")
                continue
            item = value[name]
            if field.type == "string":
                if (not isinstance(item, str) or not item or len(item) > field.max_length
                        or any(unicodedata.category(char) == "Cc" for char in item)
                        or field.enum is not None and item not in field.enum):
                    raise EnrollmentDenied("string operation parameter is invalid")
                rendered[name] = item
            elif field.type == "integer":
                if type(item) is not int or not field.minimum <= item <= field.maximum:
                    raise EnrollmentDenied("integer operation parameter is invalid")
                rendered[name] = str(item)
            else:
                if type(item) is not bool:
                    raise EnrollmentDenied("boolean operation parameter is invalid")
                rendered[name] = "true" if item else "false"
        return MappingProxyType(rendered)


def load_operation_parameter_schemas(
    path: Path = OPERATION_PARAMETER_CATALOG_PATH, *, expected_uid: int = 0,
) -> tuple[OperationParameterSchema, ...]:
    """Load the exact root-owned parameter catalog used by launch recipes."""
    if path != OPERATION_PARAMETER_CATALOG_PATH or type(expected_uid) is not int or expected_uid != 0:
        raise EnrollmentDenied("operation parameter catalog path and owner are fixed")
    _owned_path(path, uid=expected_uid, directory=False)
    info = path.stat(follow_symlinks=False)
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise EnrollmentDenied("operation parameter catalog must be mode 0600")

    def unique_pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError):
        raise EnrollmentDenied("operation parameter catalog is malformed") from None
    if (not isinstance(raw, dict) or set(raw) != {"schema", "parameter_schemas"}
            or type(raw["schema"]) is not int or raw["schema"] != 1
            or not isinstance(raw["parameter_schemas"], list)
            or len(raw["parameter_schemas"]) > 1024):
        raise EnrollmentDenied("operation parameter catalog schema is invalid")
    result = []
    ids = set()
    for row in raw["parameter_schemas"]:
        schema = OperationParameterSchema.from_protected_record(row)
        if schema.schema_id in ids:
            raise EnrollmentDenied("operation parameter schema ID is duplicated")
        ids.add(schema.schema_id)
        result.append(schema)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class OperationLaunchRecipe:
    operation_id: str
    executable_artifact_id: str
    executable_sha256: str
    argv_recipe: tuple[Mapping[str, str], ...]
    cwd_root_id: str
    cwd_subpath: str
    environment: Mapping[str, str]
    child_artifact_refs: Mapping[str, str]
    max_lifetime_seconds: int
    max_output_bytes: int
    stdin_mode: str
    parameter_schema_id: str


@dataclass(frozen=True, slots=True)
class ResolvedLaunchRecipe:
    enrollment_id: str
    generation: str
    profile_id: str
    principal_id: str
    service_uid: int
    service_gid: int
    operation_id: str
    process_start_target: str
    recipe: OperationLaunchRecipe
    executable_artifact_id: str
    cwd: Path
    parameter_schema: OperationParameterSchema


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
    operation_recipes: Mapping[str, OperationLaunchRecipe]
    argv_recipe: tuple[str, ...]
    environment: Mapping[str, str]
    max_lifetime_seconds: int
    memory_max_bytes: int
    cpu_quota_percent: int
    io_weight: int

    def as_managed_profile(self, *, artifact_root: Path, child_artifact_refs: Mapping[str, str],
                           parameter_schemas: Mapping[str, OperationParameterSchema] | None = None):
        """Create the process-custodian record using only root-resolved fields."""
        from hermes_installer.managed_process_custodian import ManagedProfileCustody
        self.roots.validate()
        return ManagedProfileCustody(
            enrollment_id=self.enrollment_id,
            home_id=self.roots.home_id, work_id=self.roots.work_id,
            data_id=self.roots.data_id,
            profile_id=self.profile_id, owner_uid=self.service_uid,
            owner_gid=self.service_gid, service_user=self.service_user,
            executable=self.executable, artifact_sha256=self.executable_sha256,
            artifact_root=artifact_root, data_root=self.roots.data,
            home_root=self.roots.home, work_root=self.roots.work,
            generation=self.generation, memory_max_bytes=self.memory_max_bytes,
            cpu_quota_percent=self.cpu_quota_percent, io_weight=self.io_weight,
            max_lifetime_seconds=self.max_lifetime_seconds,
            child_artifact_refs=dict(child_artifact_refs), argv_recipe=self.argv_recipe,
            operation_targets=dict(self.operation_targets),
            operation_recipes={key: {
                "executable_artifact_id": value.executable_artifact_id,
                "executable_sha256": value.executable_sha256,
                "argv_recipe": [dict(token) for token in value.argv_recipe],
                "cwd_root_id": value.cwd_root_id, "cwd_subpath": value.cwd_subpath,
                "environment": dict(value.environment),
                "child_artifact_refs": dict(value.child_artifact_refs),
                "max_lifetime_seconds": value.max_lifetime_seconds,
                "max_output_bytes": value.max_output_bytes, "stdin_mode": value.stdin_mode,
                "parameter_schema_id": value.parameter_schema_id,
            } for key, value in self.operation_recipes.items()},
            parameter_schemas={key: {
                "id": value.schema_id,
                "fields": [{"name": field.name, "type": field.type,
                            "required": field.required,
                            "enum": list(field.enum) if field.enum is not None else None,
                            "max_length": field.max_length, "minimum": field.minimum,
                            "maximum": field.maximum}
                           for field in value.fields.values()],
            } for key, value in (parameter_schemas or {}).items()},
        )


class ProtectedEnrollmentCatalog:
    """Immutable root-owned mapping from caller opaque IDs to service policy."""

    def __init__(self, records: Mapping[tuple[str, str], HostServiceProfile], *, digest: str,
                 native_packages: list[Mapping[str, Any]] | None = None,
                 memory_enrollments: Mapping[tuple[str, str], Any] | None = None,
                 parameter_schemas: list[Mapping[str, Any]] | None = None):
        if not records:
            raise EnrollmentDenied("protected service enrollment is empty")
        self._records = MappingProxyType(dict(records))
        self.digest = digest
        parsed_native = {}
        for raw in native_packages or []:
            package = NativePackageBinding.from_protected_record(raw)
            key = (package.package_id, package.generation)
            if key in parsed_native:
                raise EnrollmentDenied("native package generation is duplicated")
            parsed_native[key] = package
        self._native_packages = MappingProxyType(parsed_native)
        self._memory_enrollments = MappingProxyType(dict(memory_enrollments or {}))
        parsed_schemas = {}
        for raw in parameter_schemas or []:
            schema = OperationParameterSchema.from_protected_record(raw)
            if schema.schema_id in parsed_schemas:
                raise EnrollmentDenied("operation parameter schema ID is duplicated")
            parsed_schemas[schema.schema_id] = schema
        self._parameter_schemas = MappingProxyType(parsed_schemas)

    def resolve_native_package(self, package_id: str, generation: str) -> "NativePackageBinding":
        """Resolve a selected package row joined to this exact service generation.

        Package rows remain metadata-only here. Materialization is available
        only after custody resolves the opaque mount IDs and verifies the actual
        read-only closure; this method never interprets them as filesystem paths.
        """
        selected_id = _id(package_id, "native package ID")
        selected_generation = _id(generation, "native package generation")
        row = self._native_packages.get((selected_id, selected_generation))
        if row is None:
            raise EnrollmentDenied("native package or generation is not enrolled")
        candidates = [profile for (enrollment_id, current_generation), profile in self._records.items()
                     if profile.profile_id == row.profile_id and current_generation == row.generation]
        if len(candidates) != 1:
            raise EnrollmentDenied("native package service profile generation is not uniquely enrolled")
        service = self.resolve(candidates[0].enrollment_id, row.generation)
        if service.generation != row.generation:
            raise EnrollmentDenied("native package belongs to a stale service generation")
        return row

    @property
    def parameter_schemas(self) -> Mapping[str, OperationParameterSchema]:
        return self._parameter_schemas

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
                              protected_digest: str, expected_uid: int = 0,
                              native_packages: list[Mapping[str, Any]] | None = None,
                              memory_enrollments: Mapping[tuple[str, str], Any] | None = None,
                              parameter_schemas: list[Mapping[str, Any]] | None = None) -> "ProtectedEnrollmentCatalog":
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
        return cls(records, digest=protected_digest, native_packages=native_packages,
                   memory_enrollments=memory_enrollments,
                   parameter_schemas=parameter_schemas)

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
        if target.startswith("memory-"):
            parts = target.split(":", 1)
            if len(parts) != 2 or parts[0] not in {
                    "memory-openviking", "memory-claude-mem", "memory-agentmemory"}:
                raise EnrollmentDenied("memory connector target is malformed")
            provider, profile_id = parts[0].removeprefix("memory-"), parts[1]
            matches = [record for (service_id, service_generation), record in self._memory_enrollments.items()
                       if service_id == profile.enrollment_id and service_generation == profile.generation
                       and getattr(record, "profile_id", None) == profile_id
                       and getattr(record, "provider", None) == provider]
            if len(matches) != 1:
                raise EnrollmentDenied("memory connector target is not joined to this service generation")
            memory = matches[0]
            if (getattr(memory, "principal_id", None) != profile.principal_id
                    or getattr(memory, "namespace_identity", None) != profile.namespace_identity
                    or getattr(memory, "data_root_id", None) != profile.roots.data_id):
                raise EnrollmentDenied("memory connector identity, namespace, or store root changed")
            port = getattr(memory, "literal_loopback_port", None)
            if type(port) is not int or not 1 <= port <= 65535:
                raise EnrollmentDenied("memory connector literal loopback port is invalid")
            routes = getattr(memory, "fixed_route_map", None)
            if not isinstance(routes, Mapping) or route not in routes:
                raise EnrollmentDenied("memory connector route is outside the selected backend variant")
            route_record = routes[route]
            if (not isinstance(route_record, Mapping) or set(route_record) != {"method", "path", "body"}
                    or not isinstance(route_record["method"], str)
                    or not isinstance(route_record["path"], str)
                    or not isinstance(route_record["body"], Mapping)):
                raise EnrollmentDenied("memory connector route schema is malformed")
            variant = getattr(memory, "backend_variant", None)
            if provider == "claude-mem" and variant not in {
                    "server-v1-sqlite", "server-v1-postgres", "worker-observation"}:
                raise EnrollmentDenied("Claude memory connector backend variant is unsupported")
            return ConnectorRouteBinding(
                profile_id, profile.generation, profile.namespace_identity, target, route,
                variant, port, MappingProxyType(dict(route_record)),
            )
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

    def resolve_launch_recipe(self, enrollment_id: str, generation: str,
                              operation_id: str) -> ResolvedLaunchRecipe:
        profile = self.resolve(enrollment_id, generation)
        selected_id = _id(operation_id, "operation recipe ID")
        recipe = profile.operation_recipes.get(selected_id)
        if recipe is None:
            raise EnrollmentDenied("operation recipe is not enrolled for this generation")
        if "process.start" not in profile.operation_targets:
            raise EnrollmentDenied("operation recipe has no fixed process.start effect target")
        schema = self._parameter_schemas.get(recipe.parameter_schema_id)
        if schema is None:
            raise EnrollmentDenied("operation parameter schema is unavailable")
        for token in recipe.argv_recipe:
            parameter = token.get("parameter")
            if parameter is not None:
                field = schema.fields.get(parameter)
                if field is None or not field.required:
                    raise EnrollmentDenied("argv recipe references an absent or optional parameter")
        roots = {profile.roots.home_id: profile.roots.home,
                 profile.roots.work_id: profile.roots.work,
                 profile.roots.data_id: profile.roots.data}
        root = roots.get(recipe.cwd_root_id)
        if root is None:
            raise EnrollmentDenied("operation cwd root is outside the enrolled service roots")
        cwd = root.joinpath(*Path(recipe.cwd_subpath).parts)
        try:
            resolved = cwd.resolve(strict=True)
        except OSError:
            raise EnrollmentDenied("operation cwd is unavailable") from None
        if resolved != cwd or (root not in cwd.parents and cwd != root):
            raise EnrollmentDenied("operation cwd escapes its enrolled root")
        return ResolvedLaunchRecipe(
            profile.enrollment_id, profile.generation, profile.profile_id, profile.principal_id,
            profile.service_uid, profile.service_gid, selected_id,
            profile.operation_targets["process.start"], recipe,
            recipe.executable_artifact_id, cwd, schema,
        )


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
    backend_variant: str | None = None
    literal_loopback_port: int | None = None
    route_record: Mapping[str, Any] | None = None


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


@dataclass(frozen=True, slots=True)
class NativeAdapterBinding:
    adapter_id: str
    manifest_sha256: str
    adapter_artifact_id: str
    adapter_sha256: str
    action_id: str
    argument_schema_id: str
    result_schema_id: str
    effect_enrollment_id: str
    operation: str
    capability: str
    target_id: str
    recipient: str
    generation: str


@dataclass(frozen=True, slots=True)
class NativePackageBinding:
    """Typed native closure metadata joined to a protected service generation.

    Mount IDs are intentionally opaque. The root custody layer must resolve
    and verify them before returning any loader-visible mount handle.
    """
    package_id: str
    profile_id: str
    generation: str
    source_revision: str
    source_tree_sha256: str
    compiled_closure_artifact_id: str
    compiled_closure_sha256: str
    entrypoint_artifact_id: str
    entrypoint_sha256: str
    resolver_artifact_id: str
    resolver_sha256: str
    service_package_root_id: str
    service_mount_id: str
    adapter_records: Mapping[str, NativeAdapterBinding]

    @classmethod
    def from_protected_record(cls, item: Mapping[str, Any]) -> "NativePackageBinding":
        expected = {"package_id", "profile_id", "generation", "source_revision",
                    "source_tree_sha256", "compiled_closure_artifact_id",
                    "compiled_closure_sha256", "entrypoint_artifact_id", "entrypoint_sha256",
                    "resolver_artifact_id", "resolver_sha256", "service_package_root_id",
                    "service_mount_id", "adapter_records"}
        if not isinstance(item, Mapping) or set(item) != expected:
            raise EnrollmentDenied("protected native package record fields are invalid")
        digests = ("source_tree_sha256", "compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256")
        if any(not isinstance(item[name], str) or not re.fullmatch(r"[0-9a-f]{64}", item[name])
               for name in digests):
            raise EnrollmentDenied("protected native package digest is invalid")
        revision = item["source_revision"]
        if not isinstance(revision, str) or not 1 <= len(revision) <= 256 or any(c in revision for c in "\x00\r\n"):
            raise EnrollmentDenied("protected native package source revision is invalid")
        raw_adapters = item["adapter_records"]
        if not isinstance(raw_adapters, list) or not raw_adapters:
            raise EnrollmentDenied("protected native package adapter closure is empty")
        adapters: dict[str, NativeAdapterBinding] = {}
        fields = {"adapter_id", "manifest_sha256", "adapter_artifact_id", "adapter_sha256",
                  "action_id", "argument_schema_id", "result_schema_id", "effect_enrollment_id",
                  "operation", "capability", "target_id", "recipient", "generation"}
        for raw in raw_adapters:
            if not isinstance(raw, Mapping) or set(raw) != fields:
                raise EnrollmentDenied("protected native adapter fields are invalid")
            for name in ("manifest_sha256", "adapter_sha256"):
                if not isinstance(raw[name], str) or not re.fullmatch(r"[0-9a-f]{64}", raw[name]):
                    raise EnrollmentDenied("protected native adapter digest is invalid")
            adapter_id = _id(raw["adapter_id"], "native adapter ID")
            if adapter_id in adapters:
                raise EnrollmentDenied("protected native adapter ID is duplicated")
            operation = _id(raw["operation"], "native adapter operation")
            if not operation.startswith("plugin."):
                raise EnrollmentDenied("native adapter operation is outside fixed plugin verbs")
            if _id(raw["generation"], "native adapter generation") != _id(item["generation"], "generation"):
                raise EnrollmentDenied("native adapter generation differs from its package")
            adapters[adapter_id] = NativeAdapterBinding(
                adapter_id, raw["manifest_sha256"], _id(raw["adapter_artifact_id"], "adapter artifact ID"),
                raw["adapter_sha256"], _id(raw["action_id"], "native action ID"),
                _id(raw["argument_schema_id"], "argument schema ID"),
                _id(raw["result_schema_id"], "result schema ID"),
                _id(raw["effect_enrollment_id"], "effect enrollment ID"), operation,
                _id(raw["capability"], "native capability"), _id(raw["target_id"], "native target ID"),
                _id(raw["recipient"], "native recipient"), raw["generation"],
            )
        return cls(
            _id(item["package_id"], "native package ID"), _id(item["profile_id"], "profile ID"),
            _id(item["generation"], "generation"), revision, item["source_tree_sha256"],
            _id(item["compiled_closure_artifact_id"], "compiled closure artifact ID"),
            item["compiled_closure_sha256"], _id(item["entrypoint_artifact_id"], "entrypoint artifact ID"),
            item["entrypoint_sha256"], _id(item["resolver_artifact_id"], "resolver artifact ID"),
            item["resolver_sha256"], _id(item["service_package_root_id"], "service package root ID"),
            _id(item["service_mount_id"], "service mount ID"), MappingProxyType(adapters),
        )


def _parse_profile(item: Any) -> HostServiceProfile:
    fields = {"enrollment_id", "generation", "profile_id", "principal_id", "service_uid", "service_gid", "service_user",
              "executable", "executable_sha256", "runtime_artifact_ids", "package_runtime_records", "roots", "authority_endpoint_id",
              "namespace_identity", "socket_policy_id", "target_route_ids", "operation_targets", "operation_recipes", "argv_recipe", "environment",
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
    raw_operation_recipes = item["operation_recipes"]
    routes = item["target_route_ids"]
    raw_packages = item["package_runtime_records"]
    if (not isinstance(recipe, list) or not recipe or any(not isinstance(x, str) or "\x00" in x for x in recipe)
            or not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in env.items())
            or not isinstance(targets, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in targets.items())
            or not isinstance(raw_operation_recipes, dict) or not raw_operation_recipes
            or not isinstance(routes, list) or any(not isinstance(route, str) for route in routes)
            or len(routes) != len(set(routes)) or not isinstance(raw_packages, dict)):
        raise EnrollmentDenied("protected launch or operation policy is malformed")
    if set(env) - _PROFILE_ENV or any(re.search(r"token|secret|credential|password|api[_-]?key", key, re.I) for key in env):
        raise EnrollmentDenied("profile environment contains an unapproved or credential-like variable")
    if set(targets) - _FIXED_OPERATIONS:
        raise EnrollmentDenied("protected operation map contains an unreviewed operation")
    roots_by_id = {roots[name + "_id"] for name in ("home", "work", "data")}
    operation_recipes = {}
    recipe_fields = {"executable_artifact_id", "executable_sha256", "argv_recipe", "cwd_root_id",
                     "cwd_subpath", "environment", "child_artifact_refs", "max_lifetime_seconds",
                     "max_output_bytes", "stdin_mode", "parameter_schema_id"}
    for operation_id, raw in raw_operation_recipes.items():
        operation_id = _id(operation_id, "operation recipe ID")
        if not isinstance(raw, dict) or set(raw) != recipe_fields:
            raise EnrollmentDenied("operation launch recipe fields are invalid")
        if (not isinstance(raw["executable_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", raw["executable_sha256"])):
            raise EnrollmentDenied("operation executable digest is invalid")
        argv = raw["argv_recipe"]
        if not isinstance(argv, list) or not argv or len(argv) > 128:
            raise EnrollmentDenied("operation argv recipe is invalid")
        tokens = []
        for token in argv:
            if not isinstance(token, dict) or len(token) != 1:
                raise EnrollmentDenied("operation argv token must be one fixed literal or typed parameter")
            if set(token) == {"literal"}:
                literal = token["literal"]
                if not isinstance(literal, str) or "\x00" in literal or len(literal) > 4096:
                    raise EnrollmentDenied("operation argv literal is invalid")
                tokens.append(MappingProxyType({"literal": literal}))
            elif set(token) == {"parameter"}:
                tokens.append(MappingProxyType({"parameter": _id(token["parameter"], "parameter name")}))
            else:
                raise EnrollmentDenied("operation argv token has unknown fields")
        cwd_root = _id(raw["cwd_root_id"], "cwd root ID")
        if cwd_root not in roots_by_id:
            raise EnrollmentDenied("operation cwd root is outside protected service roots")
        subpath = raw["cwd_subpath"]
        if (not isinstance(subpath, str) or "\\" in subpath or "\x00" in subpath
                or Path(subpath).is_absolute() or any(part in {"", ".", ".."} for part in Path(subpath).parts)):
            raise EnrollmentDenied("operation cwd subpath is unsafe")
        environment = raw["environment"]
        if (not isinstance(environment, dict) or set(environment) - _OPERATION_ENV
                or any(not isinstance(k, str) or not isinstance(v, str) or any(c in v for c in "\x00\r\n")
                       or "$" in v or "`" in v for k, v in environment.items())
                or any(re.search(r"token|secret|credential|password|api[_-]?key", k, re.I) for k in environment)):
            raise EnrollmentDenied("operation environment is not a fixed sanitized mapping")
        refs = raw["child_artifact_refs"]
        if (not isinstance(refs, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                or not re.fullmatch(r"[0-9a-f]{64}", v) for k, v in refs.items())):
            raise EnrollmentDenied("operation child artifact pins are malformed")
        lifetime, output_cap = raw["max_lifetime_seconds"], raw["max_output_bytes"]
        if (type(lifetime) is not int or not 1 <= lifetime <= 600
                or type(output_cap) is not int or not 1 <= output_cap <= 4 * 1024 * 1024
                or not isinstance(raw["stdin_mode"], str)
                or raw["stdin_mode"] not in {"closed", "bounded-typed-bytes"}):
            raise EnrollmentDenied("operation launch bounds or stdin mode are invalid")
        operation_recipes[operation_id] = OperationLaunchRecipe(
            operation_id, _id(raw["executable_artifact_id"], "executable artifact ID"),
            raw["executable_sha256"], tuple(tokens), cwd_root, subpath,
            MappingProxyType(dict(environment)), MappingProxyType(dict(refs)),
            lifetime, output_cap, raw["stdin_mode"], _id(raw["parameter_schema_id"], "parameter schema ID"),
        )
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
        MappingProxyType(operation_recipes),
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
