"""Root-resolved immutable service, device, and fixed build enrollments.

This module contains no privilege escalation or generic command runner. It turns
root-owned enrollment records into immutable policies used by already reviewed
host handlers. Callers provide opaque IDs and generation only.
"""
from __future__ import annotations

import hashlib
import grp
import json
import os
import pwd
import re
import stat
import unicodedata
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
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
    device_enrollment_id: str | None
    expected_device_generation: str | None
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
                 source_issuers: tuple[Any, ...] | list[Any] | None = None,
                 memory_enrollments: Mapping[tuple[str, str], Any] | None = None,
                 parameter_schemas: list[Mapping[str, Any]] | None = None,
                 selected_application_runtimes: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                 native_schema_artifacts: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                 native_mcp_tool_bindings: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                 private_memory_endpoint_selections: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                 private_memory_model_selections: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None):
        if not records:
            raise EnrollmentDenied("protected service enrollment is empty")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise EnrollmentDenied("protected service enrollment digest is invalid")
        self._records = MappingProxyType(dict(records))
        self.digest = digest
        parsed_native = {}
        for raw in native_packages or []:
            package = NativePackageBinding.from_protected_record(raw)
            key = (package.package_id, package.generation)
            if key in parsed_native:
                raise EnrollmentDenied("native package generation is duplicated")
            profile_matches = [profile for profile in records.values()
                               if profile.profile_id == package.profile_id
                               and profile.generation == package.profile_generation]
            if len(profile_matches) != 1:
                raise EnrollmentDenied("native package does not join one exact process profile generation")
            parsed_native[key] = package
        self._native_packages = MappingProxyType(parsed_native)
        schema_rows: dict[tuple[str, str, str, str, str], Mapping[str, Any]] = {}
        for raw in native_schema_artifacts or ():
            if not isinstance(raw, Mapping):
                raise EnrollmentDenied("native schema artifact row is malformed")
            row_key = (raw.get("native_package_id"), raw.get("native_package_generation"),
                       raw.get("adapter_id"), raw.get("action_id"), raw.get("id"))
            if any(not isinstance(part, str) for part in row_key) or row_key in schema_rows:
                raise EnrollmentDenied("native schema artifact identity is absent or duplicated")
            schema_rows[row_key] = MappingProxyType(dict(raw))
        self._native_schema_artifacts = MappingProxyType(schema_rows)
        mcp_rows: dict[str, Mapping[str, Any]] = {}
        for raw in native_mcp_tool_bindings or ():
            if not isinstance(raw, Mapping) or not isinstance(raw.get("id"), str) or raw["id"] in mcp_rows:
                raise EnrollmentDenied("native MCP binding ID is malformed or duplicated")
            mcp_rows[raw["id"]] = MappingProxyType(dict(raw))
        self._native_mcp_tool_bindings = MappingProxyType(mcp_rows)
        issuer_by_id: dict[str, Any] = {}
        for issuer in source_issuers or ():
            observer_id = getattr(issuer, "observer_enrollment_id", None)
            if not isinstance(observer_id, str) or observer_id in issuer_by_id:
                raise EnrollmentDenied("active source issuer observer ID is invalid or duplicated")
            issuer_by_id[observer_id] = issuer
        observer_joins: dict[str, NativeSourceObserverJoin] = {}
        for package in parsed_native.values():
            package_roles = {observer_id: role for role in package.process_role_records.values()
                             for observer_id in role.observer_enrollment_ids}
            for role in package.process_role_records.values():
                for observer_id in role.observer_enrollment_ids:
                    issuer = issuer_by_id.get(observer_id)
                    if (issuer is None
                            or getattr(issuer, "producer_profile_id", None) != package.profile_id
                            or getattr(issuer, "generation", None) != package.profile_generation
                            or getattr(issuer, "producer_role_artifact_id", None) != role.role_artifact_id
                            or getattr(issuer, "producer_role_sha256", None) != role.role_sha256):
                        raise EnrollmentDenied("native process role does not join its exact active source issuer")
            for action in package.action_records.values():
                for observer_id in action.observer_enrollment_ids:
                    issuer = issuer_by_id.get(observer_id)
                    if issuer is None:
                        raise EnrollmentDenied("native action observer reference is absent")
                    if (getattr(issuer, "producer_profile_id", None) != package.profile_id
                            or getattr(issuer, "generation", None) != package.profile_generation):
                        raise EnrollmentDenied("native action observer does not match its process profile generation")
                    role = package_roles.get(observer_id)
                    if role is None or action.action_binding_id not in role.action_binding_ids:
                        raise EnrollmentDenied("native action observer has no exact process-role action join")
                    if action.action_id not in getattr(issuer, "source_action_ids", ()):
                        raise EnrollmentDenied("native action observer source action does not match its action binding")
            for registration in package.registration_records.values():
                lexical_actions: set[str] = set()
                for binding in registration.action_bindings:
                    if binding.action_binding_id is not None:
                        lexical_actions.add(package.action_records[binding.action_binding_id].action_id)
                    elif binding.workflow_id is not None:
                        lexical_actions.update(
                            package.action_records[action_id].action_id
                            for action_id in package.workflow_records[binding.workflow_id].step_action_binding_ids
                        )
                expected_lexical = (registration.handler_id if registration.handler_kind == "mcp-dispatch"
                                    else registration.registration_id)
                if registration.handler_kind == "effect-action" and len(lexical_actions) == 1:
                    expected_lexical = next(iter(lexical_actions))
                for observer_id in registration.observer_enrollment_ids:
                    issuer = issuer_by_id.get(observer_id)
                    if (issuer is None
                            or getattr(issuer, "producer_profile_id", None) != package.profile_id
                            or getattr(issuer, "generation", None) != package.profile_generation
                            or expected_lexical not in getattr(issuer, "source_action_ids", ())):
                        raise EnrollmentDenied("native registration observer does not join its current issuer action")
                    role = package_roles.get(observer_id)
                    if (role is None or registration.registration_id not in role.registration_ids
                            or any(binding.action_binding_id is not None
                                   and binding.action_binding_id not in role.action_binding_ids
                                   for binding in registration.action_bindings)
                            or any(binding.workflow_id is not None
                                   and binding.workflow_id not in role.workflow_ids
                                   for binding in registration.action_bindings)):
                        raise EnrollmentDenied("native registration observer has no exact process-role registration join")
            for role in package.process_role_records.values():
                for observer_id in role.observer_enrollment_ids:
                    issuer = issuer_by_id[observer_id]
                    actions: dict[str, NativeActionRecord] = {}
                    registrations: dict[str, NativeRegistrationRecord] = {}
                    source_action_ids = set(getattr(issuer, "source_action_ids", ()))
                    for registration_id in role.registration_ids:
                        registration = package.registration_records[registration_id]
                        child_actions: set[str] = set()
                        for binding in registration.action_bindings:
                            if binding.action_binding_id is not None:
                                child_actions.add(binding.action_binding_id)
                            elif binding.workflow_id is not None:
                                child_actions.update(
                                    package.workflow_records[binding.workflow_id].step_action_binding_ids,
                                )
                        lexical_ids = {registration.registration_id}
                        if registration.handler_kind == "mcp-dispatch":
                            lexical_ids.add(registration.handler_id)
                        direct_action_ids = {package.action_records[key].action_id for key in child_actions}
                        if not source_action_ids.intersection(lexical_ids | direct_action_ids):
                            continue
                        registrations[registration_id] = registration
                        for action_binding_id in child_actions:
                            actions[action_binding_id] = package.action_records[action_binding_id]
                    for action_binding_id in role.action_binding_ids:
                        action = package.action_records[action_binding_id]
                        if action.action_id in source_action_ids:
                            actions[action_binding_id] = action
                    if not registrations and not actions:
                        raise EnrollmentDenied("native process role source action has no exact registration/action join")
                    if observer_id in observer_joins:
                        raise EnrollmentDenied("native observer is assigned to multiple packages or process roles")
                    observer_joins[observer_id] = NativeSourceObserverJoin(
                        issuer, package, role, MappingProxyType(actions), MappingProxyType(registrations),
                    )
            for action in package.action_records.values():
                for kind, schema_id in (("arguments", action.argument_schema_id),
                                         ("result", action.result_schema_id)):
                    if native_schema_artifacts is not None:
                        matches = [row for key, row in schema_rows.items()
                                   if key == (package.package_id, package.generation,
                                              action.adapter_id, action.action_id, schema_id)
                                   and row.get("schema_kind") == kind]
                        if len(matches) != 1:
                            raise EnrollmentDenied("native action schema lacks one exact active schema artifact join")
            for registration in package.registration_records.values():
                if native_schema_artifacts is not None:
                    for kind, schema_id in (("arguments", registration.argument_schema_id),
                                            ("result", registration.result_schema_id)):
                        matches = [row for key, row in schema_rows.items()
                                   if key == (package.package_id, package.generation,
                                              registration.adapter_id, registration.registration_id,
                                              schema_id)
                                   and row.get("schema_kind") == kind]
                        if len(matches) != 1:
                            raise EnrollmentDenied(
                                "native registration schema lacks one exact active registration schema join",
                            )
                if registration.handler_kind == "mcp-dispatch":
                    mcp = mcp_rows.get(registration.handler_id)
                    if (mcp is None or mcp.get("native_package_id") != package.package_id
                            or mcp.get("native_package_generation") != package.generation
                            or mcp.get("native_tool_name") != registration.native_tool_name
                            or mcp.get("native_server_name") != registration.native_server_name):
                        raise EnrollmentDenied("native MCP registration does not join its exact active MCP binding")
        self._source_observer_joins = MappingProxyType(observer_joins)
        self._memory_enrollments = MappingProxyType(dict(memory_enrollments or {}))
        endpoint_rows: dict[str, RootSelectedPrivateMemoryEndpointBinding] = {}
        for raw in private_memory_endpoint_selections or ():
            endpoint = RootSelectedPrivateMemoryEndpointBinding.from_protected_record(
                raw, service_generation_digest=digest,
            )
            if endpoint.binding_id in endpoint_rows:
                raise EnrollmentDenied("private memory endpoint binding ID is duplicated")
            try:
                service = self.resolve(endpoint.service_enrollment_id, endpoint.service_generation)
                memory_matches = [memory for (enrollment_id, generation), memory in self._memory_enrollments.items()
                                  if enrollment_id == endpoint.service_enrollment_id
                                  and generation == endpoint.service_generation
                                  and memory.profile_id == endpoint.profile_id]
                process = self.resolve_profile_generation(
                    endpoint.process_profile_id, endpoint.process_profile_generation,
                )
                if (service.profile_id != endpoint.profile_id
                        or service.principal_id != endpoint.principal_id
                        or service.namespace_identity != endpoint.namespace_id
                        or len(memory_matches) != 1
                        or memory_matches[0].principal_id != endpoint.principal_id
                        or memory_matches[0].namespace_identity != endpoint.namespace_id
                        or memory_matches[0].service_enrollment_id != endpoint.service_enrollment_id
                        or memory_matches[0].service_generation != endpoint.service_generation
                        or process.profile_id != endpoint.process_profile_id
                        or process.generation != endpoint.process_profile_generation
                        or process.principal_id != endpoint.principal_id
                        or process.namespace_identity != endpoint.namespace_id
                        or endpoint.endpoint_target_id != memory_matches[0].target_id
                        or endpoint.credential_reference_id != memory_matches[0].auth_reference_id
                        or any(route_id not in memory_matches[0].fixed_route_map
                               for route_id in endpoint.connector_route_ids)):
                    raise EnrollmentDenied("private memory endpoint binding does not join active service/route/process")
                # Resolve every fixed route now. This proves the route IDs and
                # backend metadata are current; it does not prove a live listener.
                for route_id in endpoint.connector_route_ids:
                    self.resolve_connector_route(
                        endpoint.service_enrollment_id, endpoint.service_generation,
                        endpoint.endpoint_target_id, route_id,
                    )
            except (KeyError, AttributeError, TypeError, ValueError, PermissionError):
                raise EnrollmentDenied("private memory endpoint binding is stale or incomplete") from None
            endpoint_rows[endpoint.binding_id] = endpoint
        self._private_memory_endpoint_selections = MappingProxyType(endpoint_rows)
        model_rows: dict[str, RootSelectedPrivateMemoryModelBinding] = {}
        for raw in private_memory_model_selections or ():
            model = RootSelectedPrivateMemoryModelBinding.from_protected_record(
                raw, service_generation_digest=digest,
            )
            if model.binding_id in model_rows:
                raise EnrollmentDenied("private memory model binding ID is duplicated")
            endpoint = endpoint_rows.get(model.endpoint_binding_id)
            if endpoint is None:
                raise EnrollmentDenied("private memory model endpoint foreign key is absent")
            if model.service_generation_digest != endpoint.service_generation_digest:
                raise EnrollmentDenied("private memory model and endpoint generations differ")
            model_rows[model.binding_id] = model
        self._private_memory_model_selections = MappingProxyType(model_rows)
        selected_applications: dict[str, Mapping[str, Any]] = {}
        for raw in selected_application_runtimes or ():
            if not isinstance(raw, Mapping):
                raise EnrollmentDenied("selected application runtime record is malformed")
            application_id = raw.get("application_id")
            profile_id = raw.get("profile_id")
            if not isinstance(application_id, str) or not application_id or not isinstance(profile_id, str):
                raise EnrollmentDenied("selected application runtime identity is malformed")
            if application_id in selected_applications:
                raise EnrollmentDenied("selected application runtime is absent or ambiguous")
            frozen = dict(raw)
            for field in ("capability_ids", "provider_route_ids", "credential_reference_ids"):
                values = frozen.get(field)
                if not isinstance(values, (list, tuple)):
                    raise EnrollmentDenied("selected application runtime sequence is malformed")
                frozen[field] = tuple(values)
            # Keep the active row's field values while freezing finite lists;
            # the enclosing digest is separate and never enters its own
            # signed snapshot preimage.
            selected_applications[application_id] = MappingProxyType(frozen)
        self._selected_application_runtimes = MappingProxyType(selected_applications)
        parsed_schemas = {}
        for raw in parameter_schemas or []:
            schema = (raw if isinstance(raw, OperationParameterSchema)
                      else OperationParameterSchema.from_protected_record(raw))
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
                     if profile.profile_id == row.profile_id and current_generation == row.profile_generation]
        if len(candidates) != 1:
            raise EnrollmentDenied("native package service profile generation is not uniquely enrolled")
        service = self.resolve(candidates[0].enrollment_id, row.profile_generation)
        if service.generation != row.profile_generation:
            raise EnrollmentDenied("native package belongs to a stale service generation")
        return row

    def resolve_profile_native_package(self, profile_id: str, generation: str) -> "NativePackageBinding":
        """Resolve the single protected package selected for one current process role."""
        selected_profile = _id(profile_id, "native package profile ID")
        selected_generation = _id(generation, "native package process generation")
        matches = [row for row in self._native_packages.values()
                   if row.profile_id == selected_profile and row.profile_generation == selected_generation]
        if len(matches) != 1:
            raise EnrollmentDenied("native peer has no unique current protected package role")
        services = [record for record in self._records.values()
                    if record.profile_id == selected_profile and record.generation == selected_generation]
        if len(services) != 1:
            raise EnrollmentDenied("native peer package has no unique current service generation")
        self.resolve(services[0].enrollment_id, selected_generation)
        return matches[0]

    def resolve_native_action_record(self, package_id: str, package_generation: str,
                                     action_binding_id: str, *, profile_id: str,
                                     process_generation: str,
                                     service_generation_digest: str) -> NativeActionRecord:
        """Return a typed action selection after rejoining the active process epoch.

        This is protected selection metadata only. The caller must still
        authorize the referenced operation/effect and verify current artifacts
        and peer identity before dispatch.
        """
        if service_generation_digest != self.digest:
            raise EnrollmentDenied("native action selection belongs to a stale service snapshot")
        package = self.resolve_native_package(package_id, package_generation)
        if package.profile_id != _id(profile_id, "native action profile ID") or package.profile_generation != _id(
                process_generation, "native action process generation"):
            raise EnrollmentDenied("native action package is not selected for the current process profile")
        action = package.action_records.get(_native_catalog_id(action_binding_id, "native action binding ID"))
        if action is None:
            raise EnrollmentDenied("native action binding is not selected")
        service = self.resolve_profile_generation(package.profile_id, package.profile_generation)
        if service.profile_id != package.profile_id or service.generation != package.profile_generation:
            raise EnrollmentDenied("native action process generation is no longer current")
        return action

    def resolve_native_registration_record(self, package_id: str, package_generation: str,
                                           registration_id: str, *, profile_id: str,
                                           process_generation: str,
                                           service_generation_digest: str) -> NativeRegistrationRecord:
        if service_generation_digest != self.digest:
            raise EnrollmentDenied("native registration belongs to a stale service snapshot")
        package = self.resolve_native_package(package_id, package_generation)
        if (package.profile_id != _id(profile_id, "native registration profile ID")
                or package.profile_generation != _id(process_generation, "native registration process generation")):
            raise EnrollmentDenied("native registration package is not selected for the current process profile")
        registration = package.registration_records.get(
            _native_catalog_id(registration_id, "native registration ID"),
        )
        if registration is None:
            raise EnrollmentDenied("native registration is not selected")
        for branch in registration.action_bindings:
            if branch.action_binding_id is not None:
                self.resolve_native_action_record(
                    package_id, package_generation, branch.action_binding_id,
                    profile_id=profile_id, process_generation=process_generation,
                    service_generation_digest=service_generation_digest,
                )
            if branch.workflow_id is not None:
                workflow = package.workflow_records.get(branch.workflow_id)
                if workflow is None or workflow.registration_id != registration.registration_id:
                    raise EnrollmentDenied("native registration workflow join is stale")
                for action_id in workflow.step_action_binding_ids:
                    self.resolve_native_action_record(
                        package_id, package_generation, action_id, profile_id=profile_id,
                        process_generation=process_generation,
                        service_generation_digest=service_generation_digest,
                    )
        return registration

    def resolve_native_registration_schema_artifact(
        self, package_id: str, package_generation: str, registration_id: str, schema_kind: str,
        *, profile_id: str, process_generation: str, service_generation_digest: str,
    ) -> Mapping[str, Any]:
        """Resolve the exact external schema artifact for one registered tool.

        Registration schemas are keyed by the registration's lexical ID in
        the existing native schema catalog. They are not inherited from a
        child backend action even when the tool dispatches that action.
        """
        if schema_kind not in {"arguments", "result"}:
            raise EnrollmentDenied("native registration schema kind is invalid")
        registration = self.resolve_native_registration_record(
            package_id, package_generation, registration_id, profile_id=profile_id,
            process_generation=process_generation,
            service_generation_digest=service_generation_digest,
        )
        schema_id = (registration.argument_schema_id if schema_kind == "arguments"
                     else registration.result_schema_id)
        matches = [row for key, row in self._native_schema_artifacts.items()
                   if key == (package_id, package_generation, registration.adapter_id,
                              registration.registration_id, schema_id)
                   and row.get("schema_kind") == schema_kind]
        if len(matches) != 1:
            raise EnrollmentDenied("native registration schema artifact is absent or ambiguous")
        return matches[0]

    def resolve_selected_native_process_role(
        self, package_id: str, native_package_generation: str, role_id: str,
    ) -> NativeProcessRoleRecord:
        package = self.resolve_native_package(package_id, native_package_generation)
        role = package.process_role_records.get(_native_catalog_id(role_id, "native process role ID"))
        if role is None:
            raise EnrollmentDenied("selected native process role is absent")
        service = self.resolve_profile_generation(package.profile_id, package.profile_generation)
        if (role.profile_id != service.profile_id or role.profile_generation != service.generation
                or role.package_id != package.package_id
                or role.native_package_generation != package.generation):
            raise EnrollmentDenied("selected native process role is stale for its process profile")
        return role

    @property
    def parameter_schemas(self) -> Mapping[str, OperationParameterSchema]:
        return self._parameter_schemas

    @property
    def source_observer_joins(self) -> Mapping[str, NativeSourceObserverJoin]:
        return self._source_observer_joins

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
                              source_issuers: tuple[Any, ...] | list[Any] | None = None,
                              memory_enrollments: Mapping[tuple[str, str], Any] | None = None,
                              parameter_schemas: list[Mapping[str, Any]] | None = None,
                              selected_application_runtimes: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                              native_schema_artifacts: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                              native_mcp_tool_bindings: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                              private_memory_endpoint_selections: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None,
                              private_memory_model_selections: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]] | None = None) -> "ProtectedEnrollmentCatalog":
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
                   source_issuers=source_issuers,
                   memory_enrollments=memory_enrollments,
                   parameter_schemas=parameter_schemas,
                   selected_application_runtimes=selected_application_runtimes,
                   native_schema_artifacts=native_schema_artifacts,
                   native_mcp_tool_bindings=native_mcp_tool_bindings,
                   private_memory_endpoint_selections=private_memory_endpoint_selections,
                   private_memory_model_selections=private_memory_model_selections)

    def resolve_private_memory_endpoint_binding(
        self, binding_id: str,
    ) -> RootSelectedPrivateMemoryEndpointBinding:
        selected = _id(binding_id, "private memory endpoint binding ID")
        row = self._private_memory_endpoint_selections.get(selected)
        if row is None or row.service_generation_digest != self.digest:
            raise EnrollmentDenied("private memory endpoint binding is absent or stale")
        # Re-resolve the service and fixed routes at each getter call so a
        # changed host profile or backend catalog invalidates this projection.
        try:
            service = self.resolve(row.service_enrollment_id, row.service_generation)
            process = self.resolve_profile_generation(row.process_profile_id, row.process_profile_generation)
            memory = self._memory_enrollments.get((row.service_enrollment_id, row.service_generation))
            if (service.profile_id != row.profile_id or service.principal_id != row.principal_id
                    or service.namespace_identity != row.namespace_id or memory is None
                    or memory.profile_id != row.profile_id or memory.principal_id != row.principal_id
                    or memory.namespace_identity != row.namespace_id
                    or memory.target_id != row.endpoint_target_id
                    or memory.auth_reference_id != row.credential_reference_id
                    or process.profile_id != row.process_profile_id
                    or process.generation != row.process_profile_generation
                    or process.principal_id != row.principal_id
                    or process.namespace_identity != row.namespace_id):
                raise EnrollmentDenied("private memory endpoint identity changed")
            for route_id in row.connector_route_ids:
                self.resolve_connector_route(row.service_enrollment_id, row.service_generation,
                                             row.endpoint_target_id, route_id)
        except Exception:
            raise EnrollmentDenied("private memory endpoint binding is no longer current") from None
        return row

    def resolve_private_memory_model_binding(
        self, binding_id: str, endpoint_binding_id: str | None = None,
    ) -> RootSelectedPrivateMemoryModelBinding:
        selected = _id(binding_id, "private memory model binding ID")
        row = self._private_memory_model_selections.get(selected)
        if row is None or row.service_generation_digest != self.digest:
            raise EnrollmentDenied("private memory model binding is absent or stale")
        endpoint = self.resolve_private_memory_endpoint_binding(row.endpoint_binding_id)
        if endpoint_binding_id is not None and _id(endpoint_binding_id, "private memory endpoint binding ID") != endpoint.binding_id:
            raise EnrollmentDenied("private memory model binding belongs to another endpoint")
        return row

    def selected_application_runtime_record(self, application_id: str) -> Mapping[str, Any]:
        """Return the unique active application row with its snapshot kept separate.

        Callers must also compare ``catalog.digest`` and resolve the row's
        signed source/runtime receipt handles before execution.
        """
        selected = _id(application_id, "selected application ID")
        row = self._selected_application_runtimes.get(selected)
        if row is None:
            raise EnrollmentDenied("selected application runtime is not enrolled")
        return row

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

    def resolve_enrollment(self, enrollment_id: str) -> HostServiceProfile:
        """Resolve a unique current service enrollment by its opaque ID."""
        selected = _id(enrollment_id, "enrollment ID")
        matches = [profile for profile in self._records.values() if profile.enrollment_id == selected]
        if len(matches) != 1:
            raise EnrollmentDenied("service enrollment is absent or ambiguous")
        return self.resolve(matches[0].enrollment_id, matches[0].generation)

    def resolve_profile_generation(self, profile_id: str, generation: str) -> HostServiceProfile:
        selected_profile = _id(profile_id, "service profile ID")
        selected_generation = _id(generation, "service generation")
        matches = [profile for (enrollment_id, current_generation), profile in self._records.items()
                   if profile.profile_id == selected_profile and current_generation == selected_generation]
        if len(matches) != 1:
            raise EnrollmentDenied("service profile generation is absent or ambiguous")
        return self.resolve(matches[0].enrollment_id, selected_generation)

    def resolve_package_runtime(self, enrollment_id: str, generation: str,
                                package_set_id: str, build_catalog: "ProtectedBuildCatalog",
                                *, build_store: Any):
        """Resolve a Coral runtime only from a completed, signed root build receipt."""
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
        if build_store is None:
            raise EnrollmentDenied("completed root build attestation is unavailable")
        try:
            receipt = build_store.resolve(build)
            executable = build_store.resolve_output(build, record.runtime_artifact_id)
        except Exception:
            raise EnrollmentDenied("completed root build attestation is unavailable or invalid") from None
        if (receipt.target_id != record.build_target
                or receipt.enrollment_id != profile.enrollment_id
                or receipt.generation != profile.generation
                or receipt.operation_id != "coral-cpython39-source-build-v1"
                or receipt.attestation_sha256 != record.runtime_build_attestation_digest):
            raise EnrollmentDenied("runtime build attestation does not match root enrollment")
        output = next((item for item in receipt.outputs
                       if item.artifact_id == record.runtime_artifact_id), None)
        if (output is None or output.name != record.runtime_build_output
                or output.sha256 != record.runtime_executable_sha256
                or executable != record.runtime_executable):
            raise EnrollmentDenied("installed runtime executable is not the selected attested build output")
        glibc = _system_glibc_version()
        if not _version_at_least(glibc, record.target_glibc_min):
            raise EnrollmentDenied("target glibc is below the enrolled Coral runtime minimum")
        executable = _owned_path(executable, uid=0, directory=False)
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
            runtime_build_attestation_digest=receipt.attestation_sha256,
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
            memory_route = routes[route]
            raw_steps = getattr(memory_route, "steps", None)
            if not isinstance(raw_steps, (list, tuple)) or not raw_steps or len(raw_steps) > 16:
                raise EnrollmentDenied("memory connector compound route is malformed")
            steps = []
            step_ids = set()
            for step in raw_steps:
                step_fields = ("step_id", "method", "path_template", "body_recipe_id",
                               "response_schema_id", "capture_fields", "next_step_id")
                if any(not hasattr(step, field) for field in step_fields):
                    raise EnrollmentDenied("memory connector step fields are invalid")
                step_id = _id(step.step_id, "memory route step ID")
                method = step.method
                path = step.path_template
                if (step_id in step_ids or method not in {"GET", "POST", "DELETE"}
                        or not isinstance(path, str) or not path.startswith("/")
                        or path.startswith("//") or "\\" in path or "?" in path or "#" in path
                        or any(part in {".", ".."} for part in path.split("/") if part)):
                    raise EnrollmentDenied("memory connector route method or path is invalid")
                body_recipe = step.body_recipe_id
                response_schema = _id(step.response_schema_id, "memory response schema ID")
                capture_fields = step.capture_fields
                next_step = step.next_step_id
                if (body_recipe is not None and not isinstance(body_recipe, str)
                        or not isinstance(capture_fields, (list, tuple)) or len(capture_fields) > 32
                        or any(not isinstance(field, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", field)
                               for field in capture_fields)
                        or len(capture_fields) != len(set(capture_fields))
                        or next_step is not None and not isinstance(next_step, str)):
                    raise EnrollmentDenied("memory connector route dataflow is invalid")
                step_ids.add(step_id)
                steps.append(MappingProxyType({
                    "step_id": step_id, "method": method, "path_template": path,
                    "body_recipe_id": body_recipe, "response_schema_id": response_schema,
                    "capture_fields": tuple(capture_fields), "next_step_id": next_step,
                }))
            if any(step["next_step_id"] is not None and step["next_step_id"] not in step_ids
                   for step in steps):
                raise EnrollmentDenied("memory compound route references an unknown next step")
            variant = getattr(memory, "backend_variant", None)
            if provider == "claude-mem" and variant not in {
                    "server-v1-sqlite", "server-v1-postgres", "worker-observation"}:
                raise EnrollmentDenied("Claude memory connector backend variant is unsupported")
            route_variant = getattr(memory_route, "backend_variant", None)
            request_schema_id = getattr(memory_route, "request_schema_id", None)
            result_schema_id = getattr(memory_route, "result_schema_id", None)
            scope_bindings = getattr(memory_route, "scope_bindings", None)
            credential_reference_id = getattr(memory_route, "credential_reference_id", None)
            maximum_seconds = getattr(memory_route, "maximum_seconds", None)
            maximum_bytes = getattr(memory_route, "maximum_bytes", None)
            if (route_variant != variant or not isinstance(scope_bindings, Mapping)
                    or not isinstance(maximum_seconds, int) or isinstance(maximum_seconds, bool)
                    or not 1 <= maximum_seconds <= 60
                    or not isinstance(maximum_bytes, int) or isinstance(maximum_bytes, bool)
                    or not 1 <= maximum_bytes <= 2 * 1024 * 1024):
                raise EnrollmentDenied("memory route-level variant, scope, or limits are invalid")
            return ConnectorRouteBinding(
                profile_id, profile.generation, profile.namespace_identity, target, route,
                variant, port, MappingProxyType({
                    "steps": tuple(steps),
                    "request_schema_id": _id(request_schema_id, "memory request schema ID"),
                    "result_schema_id": _id(result_schema_id, "memory result schema ID"),
                    "scope_bindings": MappingProxyType(dict(scope_bindings)),
                    "credential_reference_id": _id(credential_reference_id, "memory credential reference ID"),
                    "maximum_seconds": maximum_seconds,
                    "maximum_bytes": maximum_bytes,
                }), memory, memory_route,
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

    def resolve_device(self, enrollment_id: str, generation: str,
                       device_catalog: "ProtectedDeviceCatalog") -> "DeviceIdentity":
        """Resolve only the exact independently versioned device join."""
        profile = self.resolve(enrollment_id, generation)
        if profile.device_enrollment_id is None or profile.expected_device_generation is None:
            raise EnrollmentDenied("profile has no protected Coral device selection")
        return device_catalog.resolve(profile.device_enrollment_id,
                                      profile.expected_device_generation)


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
    memory_enrollment: Any | None = None
    memory_route: Any | None = None


@dataclass(frozen=True, slots=True)
class RootSelectedPrivateMemoryEndpointBinding:
    """Digest-bound endpoint selection metadata, never a deployment receipt."""

    binding_id: str
    profile_id: str
    namespace_id: str
    principal_id: str
    service_enrollment_id: str
    service_generation: str
    process_profile_id: str
    process_profile_generation: str
    endpoint_target_id: str
    connector_route_ids: tuple[str, ...]
    recipient_id: str
    credential_reference_id: str
    server_config_artifact_id: str
    server_config_sha256: str
    runtime_artifact_ids: tuple[str, ...]
    network_binding_handle: str
    service_generation_digest: str

    @classmethod
    def from_protected_record(cls, record: Mapping[str, Any], *,
                              service_generation_digest: str) -> "RootSelectedPrivateMemoryEndpointBinding":
        fields = {
            "binding_id", "profile_id", "namespace_id", "principal_id",
            "service_enrollment_id", "service_generation", "process_profile_id",
            "process_profile_generation", "endpoint_target_id", "connector_route_ids",
            "recipient_id", "credential_reference_id", "server_config_artifact_id",
            "server_config_sha256", "runtime_artifact_ids", "network_binding_handle",
        }
        if not isinstance(record, Mapping) or set(record) != fields:
            raise EnrollmentDenied("private memory endpoint selection fields are invalid")
        if not isinstance(service_generation_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest):
            raise EnrollmentDenied("private memory endpoint selection digest is invalid")
        values = {key: _id(record[key], f"private memory endpoint {key}") for key in fields - {
            "connector_route_ids", "runtime_artifact_ids", "server_config_sha256",
        }}
        digest = record["server_config_sha256"]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise EnrollmentDenied("private memory endpoint server config digest is invalid")
        routes = record["connector_route_ids"]
        artifacts = record["runtime_artifact_ids"]
        if (not isinstance(routes, (list, tuple)) or not 1 <= len(routes) <= 32
                or any(not isinstance(value, str) for value in routes)
                or len(routes) != len(set(routes))):
            raise EnrollmentDenied("private memory endpoint route selection is invalid")
        if (not isinstance(artifacts, (list, tuple)) or not 1 <= len(artifacts) <= 64
                or any(not isinstance(value, str) for value in artifacts)
                or len(artifacts) != len(set(artifacts))):
            raise EnrollmentDenied("private memory endpoint runtime artifact selection is invalid")
        checked_routes = tuple(_id(value, "private memory endpoint route ID") for value in routes)
        checked_artifacts = tuple(_id(value, "private memory endpoint runtime artifact ID") for value in artifacts)
        return cls(**values, connector_route_ids=checked_routes,
                   server_config_sha256=digest, runtime_artifact_ids=checked_artifacts,
                   service_generation_digest=service_generation_digest)


@dataclass(frozen=True, slots=True)
class RootSelectedPrivateMemoryModelBinding:
    """Digest-bound model selection metadata, never proof of installed weights."""

    binding_id: str
    endpoint_binding_id: str
    served_model_id: str
    source_model_id: str
    source_revision: str
    license_artifact_id: str
    license_sha256: str
    model_artifact_id: str
    model_artifact_sha256: str
    model_tree_manifest_sha256: str
    runtime_artifact_id: str
    runtime_artifact_sha256: str
    load_config_artifact_id: str
    load_config_sha256: str
    capability: str
    dimensions: int | None
    service_generation_digest: str

    @classmethod
    def from_protected_record(cls, record: Mapping[str, Any], *,
                              service_generation_digest: str) -> "RootSelectedPrivateMemoryModelBinding":
        fields = {
            "binding_id", "endpoint_binding_id", "served_model_id", "source_model_id",
            "source_revision", "license_artifact_id", "license_sha256", "model_artifact_id",
            "model_artifact_sha256", "model_tree_manifest_sha256", "runtime_artifact_id",
            "runtime_artifact_sha256", "load_config_artifact_id", "load_config_sha256",
            "capability", "dimensions",
        }
        if not isinstance(record, Mapping) or set(record) != fields:
            raise EnrollmentDenied("private memory model selection fields are invalid")
        if not isinstance(service_generation_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest):
            raise EnrollmentDenied("private memory model selection digest is invalid")
        digest_fields = {"license_sha256", "model_artifact_sha256", "model_tree_manifest_sha256",
                         "runtime_artifact_sha256", "load_config_sha256"}
        values: dict[str, Any] = {}
        for key in fields - digest_fields - {"capability", "dimensions"}:
            values[key] = _id(record[key], f"private memory model {key}")
        for key in digest_fields:
            value = record[key]
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise EnrollmentDenied(f"private memory model {key} is invalid")
            values[key] = value
        capability = record["capability"]
        dimensions = record["dimensions"]
        if capability == "extraction-text":
            if dimensions is not None:
                raise EnrollmentDenied("text model selection cannot declare embedding dimensions")
        elif capability == "embedding":
            if type(dimensions) is not int or not 1 <= dimensions <= 8192:
                raise EnrollmentDenied("embedding model selection dimensions are invalid")
        else:
            raise EnrollmentDenied("private memory model capability is unsupported")
        return cls(**values, capability=capability, dimensions=dimensions,
                   service_generation_digest=service_generation_digest)


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
    observer_enrollment_ids: tuple[str, ...]
    workflow_bindings: tuple[Mapping[str, str], ...]


def _native_catalog_id(value: Any, label: str, *, maximum: int = 512) -> str:
    if (not isinstance(value, str) or len(value) > maximum
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", value, re.ASCII)):
        raise EnrollmentDenied(f"protected {label} is invalid")
    return value


def _native_catalog_sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise EnrollmentDenied(f"protected {label} digest is invalid")
    return value


@dataclass(frozen=True, slots=True)
class NativeActionRecord:
    action_binding_id: str
    adapter_id: str
    action_id: str
    manifest_sha256: str
    adapter_artifact_id: str
    adapter_sha256: str
    argument_schema_id: str
    result_schema_id: str
    effect_enrollment_id: str
    operation: str
    capability: str
    target_id: str
    recipient: str | None
    generation: str
    observer_enrollment_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeActionBindingRef:
    selector_values: Mapping[str, str]
    action_binding_id: str | None
    argument_projection: tuple[Mapping[str, str], ...]
    workflow_id: str | None


@dataclass(frozen=True, slots=True)
class NativeRegistrationRecord:
    registration_id: str
    native_tool_name: str
    native_server_name: str
    toolset: str
    family: str
    adapter_id: str
    argument_schema_id: str
    result_schema_id: str
    native_schema_sha256: str
    registration_source_artifact_id: str
    registration_source_sha256: str
    registration_source_receipt_handle: str
    handler_kind: str
    handler_id: str
    selector_fields: tuple[str, ...]
    action_bindings: tuple[NativeActionBindingRef, ...]
    observer_enrollment_ids: tuple[str, ...]
    generation: str


@dataclass(frozen=True, slots=True)
class NativeWorkflowRecord:
    workflow_id: str
    registration_id: str
    external_argument_schema_id: str
    external_result_schema_id: str
    workflow_artifact_id: str
    workflow_sha256: str
    workflow_source_receipt_handle: str
    step_action_binding_ids: tuple[str, ...]
    generation: str


@dataclass(frozen=True, slots=True)
class NativeProcessRoleRecord:
    role_id: str
    package_id: str
    native_package_generation: str
    profile_id: str
    profile_generation: str
    role_artifact_id: str
    role_sha256: str
    role_source_receipt_handle: str
    module_name: str
    closure_member_path: str
    role_source_revision: str
    role_source_tree_sha256: str
    observer_enrollment_ids: tuple[str, ...]
    registration_ids: tuple[str, ...]
    action_binding_ids: tuple[str, ...]
    workflow_ids: tuple[str, ...]


def _parse_native_process_role_records(value: Any, *, package_id: str, generation: str,
                                       profile_id: str, profile_generation: str,
                                       actions: Mapping[str, NativeActionRecord],
                                       registrations: Mapping[str, NativeRegistrationRecord],
                                       workflows: Mapping[str, NativeWorkflowRecord]) -> dict[str, NativeProcessRoleRecord]:
    fields = {
        "role_id", "package_id", "native_package_generation", "profile_id", "profile_generation",
        "role_artifact_id", "role_sha256", "role_source_receipt_handle", "module_name",
        "closure_member_path", "role_source_revision", "role_source_tree_sha256",
        "observer_enrollment_ids", "registration_ids", "action_binding_ids", "workflow_ids",
    }
    if not isinstance(value, list) or len(value) > 128:
        raise EnrollmentDenied("protected native process-role catalog is malformed")
    result: dict[str, NativeProcessRoleRecord] = {}
    observers: set[str] = set()
    module_names: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise EnrollmentDenied("protected native process-role record fields are invalid")
        role_id = _native_catalog_id(raw["role_id"], "native process role ID")
        if role_id in result:
            raise EnrollmentDenied("protected native process role is duplicated")
        ids = {
            "package_id": _native_catalog_id(raw["package_id"], "native process-role package ID"),
            "native_package_generation": _native_catalog_id(
                raw["native_package_generation"], "native process-role package generation"),
            "profile_id": _native_catalog_id(raw["profile_id"], "native process-role profile ID"),
            "profile_generation": _native_catalog_id(raw["profile_generation"], "native process-role process generation"),
        }
        if ids != {"package_id": package_id, "native_package_generation": generation,
                   "profile_id": profile_id, "profile_generation": profile_generation}:
            raise EnrollmentDenied("native process role belongs to another package or profile generation")
        role_sha = _native_catalog_sha(raw["role_sha256"], "native process-role artifact")
        source_tree_sha = _native_catalog_sha(raw["role_source_tree_sha256"], "native process-role source tree")
        role_artifact_id = _native_catalog_id(raw["role_artifact_id"], "native process-role artifact ID")
        receipt = _native_catalog_id(raw["role_source_receipt_handle"], "native process-role source receipt")
        module_name = raw["module_name"]
        if (not isinstance(module_name, str) or len(module_name) > 256
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*", module_name, re.ASCII)
                or module_name in module_names):
            raise EnrollmentDenied("native process-role module name is invalid or duplicated")
        module_names.add(module_name)
        member_path = raw["closure_member_path"]
        if (not isinstance(member_path, str) or not member_path or len(member_path) > 512
                or "\\" in member_path or any(ord(char) < 0x20 for char in member_path)):
            raise EnrollmentDenied("native process-role closure member path is invalid")
        parsed_path = PurePosixPath(member_path)
        if (parsed_path.is_absolute() or any(part in {"", ".", ".."} for part in parsed_path.parts)
                or parsed_path.as_posix() != member_path):
            raise EnrollmentDenied("native process-role closure member path is not normalized and relative")
        revision = raw["role_source_revision"]
        if (not isinstance(revision, str) or not 1 <= len(revision) <= 256
                or any(ord(char) < 0x20 for char in revision)):
            raise EnrollmentDenied("native process-role source revision is invalid")
        observer_ids = _native_unique_ids(raw["observer_enrollment_ids"],
                                          "native process-role observer ID", maximum=512)
        registration_ids = _native_unique_ids(raw["registration_ids"],
                                              "native process-role registration ID", maximum=512)
        action_ids = _native_unique_ids(raw["action_binding_ids"],
                                        "native process-role action binding ID", maximum=512)
        workflow_ids = _native_unique_ids(raw["workflow_ids"],
                                          "native process-role workflow ID", maximum=512)
        if (any(item not in registrations for item in registration_ids)
                or any(item not in actions for item in action_ids)
                or any(item not in workflows for item in workflow_ids)):
            raise EnrollmentDenied("native process role references an absent action, registration or workflow")
        if any(workflows[item].registration_id not in registration_ids for item in workflow_ids):
            raise EnrollmentDenied("native process-role workflow is outside its registration set")
        if observers.intersection(observer_ids):
            raise EnrollmentDenied("native source observer is ambiguously assigned to process roles")
        observers.update(observer_ids)
        result[role_id] = NativeProcessRoleRecord(
            role_id, package_id, generation, profile_id, profile_generation, role_artifact_id,
            role_sha, receipt, module_name, member_path, revision, source_tree_sha,
            observer_ids, registration_ids, action_ids, workflow_ids,
        )
    return result


_NATIVE_HANDLER_KINDS = frozenset({
    "effect-action", "finite-selector", "finite-workflow",
    "public-registry-read", "owner-overlay", "mcp-dispatch",
})


def _native_unique_ids(value: Any, label: str, *, maximum: int, item_limit: int = 128) -> tuple[str, ...]:
    if (not isinstance(value, list) or len(value) > item_limit
            or any(not isinstance(item, str) for item in value)):
        raise EnrollmentDenied(f"protected {label} list is malformed")
    result = tuple(_native_catalog_id(item, label, maximum=maximum) for item in value)
    if len(set(result)) != len(result):
        raise EnrollmentDenied(f"protected {label} is duplicated")
    return result


def _parse_native_action_records(value: Any, *, generation: str) -> dict[str, NativeActionRecord]:
    fields = {
        "action_binding_id", "adapter_id", "action_id", "manifest_sha256",
        "adapter_artifact_id", "adapter_sha256", "argument_schema_id", "result_schema_id",
        "effect_enrollment_id", "operation", "capability", "target_id", "recipient",
        "generation", "observer_enrollment_ids",
    }
    if not isinstance(value, list) or len(value) > 256:
        raise EnrollmentDenied("protected native action catalog is malformed")
    result: dict[str, NativeActionRecord] = {}
    by_pair: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise EnrollmentDenied("protected native action record fields are invalid")
        adapter_id = _native_catalog_id(raw["adapter_id"], "native action adapter ID", maximum=128)
        action_id = _native_catalog_id(raw["action_id"], "native action ID", maximum=128)
        binding_id = _native_catalog_id(raw["action_binding_id"], "native action binding ID")
        if binding_id != f"{adapter_id}:action:{action_id}" or binding_id in result:
            raise EnrollmentDenied("protected native action identity is conflicting or duplicated")
        pair = (adapter_id, action_id)
        if pair in by_pair:
            raise EnrollmentDenied("protected native adapter/action pair is duplicated")
        by_pair.add(pair)
        if _native_catalog_id(raw["generation"], "native action generation") != generation:
            raise EnrollmentDenied("protected native action generation differs from package")
        for name in ("manifest_sha256", "adapter_sha256"):
            _native_catalog_sha(raw[name], f"native action {name}")
        operation = _native_catalog_id(raw["operation"], "native action operation", maximum=256)
        capability = _native_catalog_id(raw["capability"], "native action capability", maximum=256)
        if operation != f"plugin.{adapter_id}.{action_id}" and not operation.startswith(f"plugin.{adapter_id}."):
            raise EnrollmentDenied("protected native action operation does not join its adapter")
        if capability != f"plugin:{adapter_id}":
            raise EnrollmentDenied("protected native action capability does not join its adapter")
        recipient = raw["recipient"]
        if recipient is not None:
            recipient = _native_catalog_id(recipient, "native action recipient", maximum=512)
        record = NativeActionRecord(
            binding_id, adapter_id, action_id,
            _native_catalog_sha(raw["manifest_sha256"], "native action manifest"),
            _native_catalog_id(raw["adapter_artifact_id"], "native action artifact ID"),
            _native_catalog_sha(raw["adapter_sha256"], "native action artifact"),
            _native_catalog_id(raw["argument_schema_id"], "native action argument schema ID"),
            _native_catalog_id(raw["result_schema_id"], "native action result schema ID"),
            _native_catalog_id(raw["effect_enrollment_id"], "native action effect enrollment ID"),
            operation, capability,
            _native_catalog_id(raw["target_id"], "native action target ID"), recipient,
            generation, _native_unique_ids(raw["observer_enrollment_ids"],
                                            "native action observer ID", maximum=512),
        )
        result[binding_id] = record
    return result


def _parse_native_registration_records(value: Any, *, generation: str) -> dict[str, NativeRegistrationRecord]:
    fields = {
        "registration_id", "native_tool_name", "native_server_name", "toolset", "family",
        "adapter_id", "argument_schema_id", "result_schema_id", "native_schema_sha256",
        "registration_source_artifact_id", "registration_source_sha256",
        "registration_source_receipt_handle", "handler_kind", "handler_id", "selector_fields",
        "action_bindings", "observer_enrollment_ids", "generation",
    }
    binding_fields = {"selector_values", "action_binding_id", "argument_projection", "workflow_id"}
    if not isinstance(value, list) or len(value) > 128:
        raise EnrollmentDenied("protected native registration catalog is malformed")
    result: dict[str, NativeRegistrationRecord] = {}
    tool_keys: set[tuple[str, str]] = set()
    tool_names: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise EnrollmentDenied("protected native registration record fields are invalid")
        registration_id = _native_catalog_id(raw["registration_id"], "native registration ID")
        adapter_id = _native_catalog_id(raw["adapter_id"], "native registration adapter ID", maximum=128)
        tool_name = _native_catalog_id(raw["native_tool_name"], "native tool name", maximum=128)
        server_name = _native_catalog_id(raw["native_server_name"], "native server name", maximum=128)
        if registration_id != f"{adapter_id}:tool:{tool_name}" or registration_id in result:
            raise EnrollmentDenied("protected native registration identity is conflicting or duplicated")
        if (server_name, tool_name) in tool_keys or tool_name in tool_names:
            raise EnrollmentDenied("protected native server/tool name is duplicated")
        tool_keys.add((server_name, tool_name))
        tool_names.add(tool_name)
        if _native_catalog_id(raw["generation"], "native registration generation") != generation:
            raise EnrollmentDenied("protected native registration generation differs from package")
        kind = raw["handler_kind"]
        if not isinstance(kind, str) or kind not in _NATIVE_HANDLER_KINDS:
            raise EnrollmentDenied("protected native registration handler kind is unsupported")
        schema_sha = _native_catalog_sha(raw["native_schema_sha256"], "native registration schema")
        source_sha = _native_catalog_sha(raw["registration_source_sha256"], "native registration source")
        selector_fields = _native_unique_ids(raw["selector_fields"],
                                              "native registration selector field", maximum=128)
        raw_bindings = raw["action_bindings"]
        if (not isinstance(raw_bindings, list) or not 1 <= len(raw_bindings) <= 128
                or any(not isinstance(binding, Mapping) or set(binding) != binding_fields
                       for binding in raw_bindings)):
            raise EnrollmentDenied("protected native registration action bindings are malformed")
        bindings: list[NativeActionBindingRef] = []
        selector_tuples: set[tuple[tuple[str, str], ...]] = set()
        for binding in raw_bindings:
            values = binding["selector_values"]
            if (not isinstance(values, Mapping) or len(values) > 128
                    or any(not isinstance(key, str) or not isinstance(value, str)
                           for key, value in values.items())):
                raise EnrollmentDenied("protected native registration selector values are malformed")
            normalized_values = {
                _native_catalog_id(key, "native selector field", maximum=128):
                _native_catalog_id(value, "native selector value", maximum=128)
                for key, value in values.items()
            }
            if not set(normalized_values).issubset(selector_fields):
                raise EnrollmentDenied("protected native registration selector uses an undeclared field")
            if kind == "finite-selector" and set(normalized_values) != set(selector_fields):
                raise EnrollmentDenied("finite selector branch does not bind every selector field")
            selector_key = tuple(sorted(normalized_values.items()))
            if selector_key in selector_tuples:
                raise EnrollmentDenied("protected native registration selector branch is duplicated")
            selector_tuples.add(selector_key)
            action_id = binding["action_binding_id"]
            workflow_id = binding["workflow_id"]
            if action_id is not None:
                action_id = _native_catalog_id(action_id, "native action binding ID")
            if workflow_id is not None:
                workflow_id = _native_catalog_id(workflow_id, "native workflow ID")
            raw_projection = binding["argument_projection"]
            if not isinstance(raw_projection, list) or len(raw_projection) > 128:
                raise EnrollmentDenied("protected native argument projection is malformed")
            projection: list[Mapping[str, str]] = []
            output_fields: set[str] = set()
            source_fields: set[str] = set()
            for item in raw_projection:
                if not isinstance(item, Mapping) or set(item) != {"name", "source_field"}:
                    raise EnrollmentDenied("protected native argument projection fields are invalid")
                name = _native_catalog_id(item["name"], "projected argument name", maximum=128)
                source_field = _native_catalog_id(item["source_field"], "projection source field", maximum=128)
                if name in output_fields or source_field in source_fields:
                    raise EnrollmentDenied("protected native argument projection is duplicated")
                output_fields.add(name)
                source_fields.add(source_field)
                projection.append(MappingProxyType({"name": name, "source_field": source_field}))
            if kind in {"effect-action", "finite-selector"}:
                if action_id is None or workflow_id is not None:
                    raise EnrollmentDenied("protected effect registration binding is incomplete")
                if kind == "effect-action" and (normalized_values or selector_fields or len(raw_bindings) != 1):
                    raise EnrollmentDenied("direct effect registration cannot select among branches")
                if kind == "finite-selector" and (not selector_fields or not normalized_values):
                    raise EnrollmentDenied("finite selector registration has no finite branch value")
            elif kind == "finite-workflow":
                if action_id is not None or workflow_id is None or normalized_values or selector_fields:
                    raise EnrollmentDenied("finite workflow registration binding is malformed")
            elif kind in {"public-registry-read", "owner-overlay"}:
                if (action_id is not None or workflow_id is not None or normalized_values
                        or selector_fields or len(raw_bindings) != 1):
                    raise EnrollmentDenied("fixed root handler registration binding is malformed")
            elif kind == "mcp-dispatch":
                if (action_id is not None or workflow_id is not None or normalized_values
                        or selector_fields or projection or len(raw_bindings) != 1):
                    raise EnrollmentDenied("MCP registration must use only its protected MCP binding")
            bindings.append(NativeActionBindingRef(
                MappingProxyType(normalized_values), action_id, tuple(projection), workflow_id,
            ))
        observer_ids = _native_unique_ids(raw["observer_enrollment_ids"],
                                          "native registration observer ID", maximum=512)
        if (not isinstance(raw["toolset"], str) or not raw["toolset"] or len(raw["toolset"]) > 128
                or not isinstance(raw["family"], str) or not raw["family"] or len(raw["family"]) > 128):
            raise EnrollmentDenied("protected native registration source family is malformed")
        result[registration_id] = NativeRegistrationRecord(
            registration_id, tool_name, server_name, raw["toolset"], raw["family"], adapter_id,
            _native_catalog_id(raw["argument_schema_id"], "registration argument schema ID"),
            _native_catalog_id(raw["result_schema_id"], "registration result schema ID"), schema_sha,
            _native_catalog_id(raw["registration_source_artifact_id"], "registration source artifact ID"),
            source_sha,
            _native_catalog_id(raw["registration_source_receipt_handle"], "registration source receipt handle"),
            kind, _native_catalog_id(raw["handler_id"], "registration handler ID"),
            selector_fields, tuple(bindings), observer_ids, generation,
        )
    return result


def _parse_native_workflow_records(value: Any, *, generation: str) -> dict[str, NativeWorkflowRecord]:
    fields = {"id", "registration_id", "external_argument_schema_id", "external_result_schema_id",
              "workflow_artifact_id", "workflow_sha256", "workflow_source_receipt_handle",
              "step_action_binding_ids", "generation"}
    if not isinstance(value, list) or len(value) > 64:
        raise EnrollmentDenied("protected native workflow catalog is malformed")
    result: dict[str, NativeWorkflowRecord] = {}
    for raw in value:
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise EnrollmentDenied("protected native workflow record fields are invalid")
        workflow_id = _native_catalog_id(raw["id"], "native workflow ID")
        if workflow_id in result or _native_catalog_id(raw["generation"], "workflow generation") != generation:
            raise EnrollmentDenied("protected native workflow ID or generation is invalid")
        result[workflow_id] = NativeWorkflowRecord(
            workflow_id, _native_catalog_id(raw["registration_id"], "workflow registration ID"),
            _native_catalog_id(raw["external_argument_schema_id"], "workflow argument schema ID"),
            _native_catalog_id(raw["external_result_schema_id"], "workflow result schema ID"),
            _native_catalog_id(raw["workflow_artifact_id"], "workflow artifact ID"),
            _native_catalog_sha(raw["workflow_sha256"], "workflow"),
            _native_catalog_id(raw["workflow_source_receipt_handle"], "workflow source receipt handle"),
            _native_unique_ids(raw["step_action_binding_ids"], "workflow action binding ID",
                               maximum=512, item_limit=16), generation,
        )
    return result


def _validate_native_record_joins(*, adapters: Mapping[str, NativeAdapterBinding],
                                  actions: Mapping[str, NativeActionRecord],
                                  registrations: Mapping[str, NativeRegistrationRecord],
                                  workflows: Mapping[str, NativeWorkflowRecord], package_id: str) -> None:
    action_by_pair = {(action.adapter_id, action.action_id): action for action in actions.values()}
    # The old map is migration-only. A selected legacy single-action row must
    # mirror exactly one current action record; it cannot create an action.
    for legacy in adapters.values():
        action = action_by_pair.get((legacy.adapter_id, legacy.action_id))
        if action is None:
            raise EnrollmentDenied("legacy native adapter has no exact v113 action record")
        if (legacy.manifest_sha256 != action.manifest_sha256
                or legacy.adapter_artifact_id != action.adapter_artifact_id
                or legacy.adapter_sha256 != action.adapter_sha256
                or legacy.argument_schema_id != action.argument_schema_id
                or legacy.result_schema_id != action.result_schema_id
                or legacy.effect_enrollment_id != action.effect_enrollment_id
                or legacy.operation != action.operation or legacy.capability != action.capability
                or legacy.target_id != action.target_id or legacy.recipient != action.recipient
                or legacy.generation != action.generation
                or legacy.observer_enrollment_ids != action.observer_enrollment_ids):
            raise EnrollmentDenied("legacy singular adapter record conflicts with v113 action record")
    for action in actions.values():
        legacy = adapters.get(action.adapter_id)
        if legacy is not None and legacy.action_id != action.action_id:
            raise EnrollmentDenied("legacy adapter ID ambiguously maps multiple v113 actions")
    for registration in registrations.values():
        if registration.handler_kind != "mcp-dispatch" and registration.native_server_name != "hermes-installer":
            raise EnrollmentDenied("non-MCP native registration uses an unprotected server name")
        if registration.adapter_id not in adapters and not any(
                action.adapter_id == registration.adapter_id for action in actions.values()):
            raise EnrollmentDenied("native registration has no selected action/adapter package record")
        for binding in registration.action_bindings:
            if binding.action_binding_id is not None:
                action = actions.get(binding.action_binding_id)
                if action is None:
                    raise EnrollmentDenied("native registration action binding is absent")
                if action.adapter_id != registration.adapter_id:
                    raise EnrollmentDenied("native registration action belongs to another adapter")
            if binding.workflow_id is not None:
                workflow = workflows.get(binding.workflow_id)
                if workflow is None:
                    raise EnrollmentDenied("native registration workflow binding is absent")
                if workflow.registration_id != registration.registration_id:
                    raise EnrollmentDenied("native registration workflow belongs to another registration")
    for workflow in workflows.values():
        registration = registrations.get(workflow.registration_id)
        if registration is None or registration.handler_kind != "finite-workflow":
            raise EnrollmentDenied("native workflow does not join one finite-workflow registration")
        if not workflow.step_action_binding_ids or any(key not in actions for key in workflow.step_action_binding_ids):
            raise EnrollmentDenied("native workflow step action binding is absent")
        if any(actions[key].adapter_id != registration.adapter_id
               for key in workflow.step_action_binding_ids):
            raise EnrollmentDenied("native workflow action belongs to another adapter")
        if all(binding.workflow_id != workflow.workflow_id for binding in registration.action_bindings):
            raise EnrollmentDenied("native workflow is not selected by its registration")


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
    profile_generation: str
    action_records: Mapping[str, NativeActionRecord]
    registration_records: Mapping[str, NativeRegistrationRecord]
    workflow_records: Mapping[str, NativeWorkflowRecord]
    process_role_records: Mapping[str, NativeProcessRoleRecord]

    @classmethod
    def from_protected_record(cls, item: Mapping[str, Any]) -> "NativePackageBinding":
        expected = {"package_id", "profile_id", "generation", "profile_generation", "source_revision",
                    "source_tree_sha256", "compiled_closure_artifact_id",
                    "compiled_closure_sha256", "entrypoint_artifact_id", "entrypoint_sha256",
                    "resolver_artifact_id", "resolver_sha256", "service_package_root_id",
                    "service_mount_id", "adapter_records", "action_records",
                    "registration_records", "workflow_records", "process_role_records"}
        if not isinstance(item, Mapping) or set(item) != expected:
            raise EnrollmentDenied("protected native package record fields are invalid")
        digests = ("source_tree_sha256", "compiled_closure_sha256", "entrypoint_sha256", "resolver_sha256")
        if any(not isinstance(item[name], str) or not re.fullmatch(r"[0-9a-f]{64}", item[name])
               for name in digests):
            raise EnrollmentDenied("protected native package digest is invalid")
        revision = item["source_revision"]
        if not isinstance(revision, str) or not 1 <= len(revision) <= 256 or any(c in revision for c in "\x00\r\n"):
            raise EnrollmentDenied("protected native package source revision is invalid")
        package_id = _native_catalog_id(item["package_id"], "native package ID")
        profile_id = _native_catalog_id(item["profile_id"], "profile ID")
        generation = _native_catalog_id(item["generation"], "native package generation")
        profile_generation = _native_catalog_id(item["profile_generation"], "native process generation")
        raw_adapters = item["adapter_records"]
        if not isinstance(raw_adapters, list) or len(raw_adapters) > 692:
            raise EnrollmentDenied("protected legacy native adapter map is malformed")
        adapters: dict[str, NativeAdapterBinding] = {}
        fields = {"adapter_id", "manifest_sha256", "adapter_artifact_id", "adapter_sha256",
                  "action_id", "argument_schema_id", "result_schema_id", "effect_enrollment_id",
                  "operation", "capability", "target_id", "recipient", "generation",
                  "observer_enrollment_ids", "workflow_bindings"}
        for raw in raw_adapters:
            if not isinstance(raw, Mapping) or set(raw) != fields:
                raise EnrollmentDenied("protected native adapter fields are invalid")
            for name in ("manifest_sha256", "adapter_sha256"):
                if not isinstance(raw[name], str) or not re.fullmatch(r"[0-9a-f]{64}", raw[name]):
                    raise EnrollmentDenied("protected native adapter digest is invalid")
            adapter_id = _native_catalog_id(raw["adapter_id"], "native adapter ID", maximum=128)
            if adapter_id in adapters:
                raise EnrollmentDenied("protected native adapter ID is duplicated")
            operation = _native_catalog_id(raw["operation"], "native adapter operation", maximum=256)
            if not operation.startswith("plugin."):
                raise EnrollmentDenied("native adapter operation is outside fixed plugin verbs")
            if _native_catalog_id(raw["generation"], "native adapter generation") != generation:
                raise EnrollmentDenied("native adapter generation differs from its package")
            raw_observers = raw["observer_enrollment_ids"]
            if (not isinstance(raw_observers, list) or len(raw_observers) > 128
                    or any(not isinstance(value, str) for value in raw_observers)
                    or len(set(raw_observers)) != len(raw_observers)):
                raise EnrollmentDenied("native adapter observer references are malformed")
            observer_ids = tuple(_native_catalog_id(value, "native observer enrollment ID")
                                 for value in raw_observers)
            raw_workflows = raw["workflow_bindings"]
            workflow_fields = {
                "external_tool_name", "external_action_id", "external_argument_schema_id",
                "external_result_schema_id", "workflow_artifact_id", "workflow_sha256",
            }
            if not isinstance(raw_workflows, list) or len(raw_workflows) > 61:
                raise EnrollmentDenied("native adapter workflow bindings are malformed")
            workflows: list[Mapping[str, str]] = []
            workflow_keys: set[tuple[str, str, str, str]] = set()
            for workflow in raw_workflows:
                if not isinstance(workflow, Mapping) or set(workflow) != workflow_fields:
                    raise EnrollmentDenied("native adapter workflow fields are invalid")
                if (not isinstance(workflow["workflow_sha256"], str)
                        or not re.fullmatch(r"[0-9a-f]{64}", workflow["workflow_sha256"])):
                    raise EnrollmentDenied("native workflow digest is invalid")
                selected = {name: _native_catalog_id(workflow[name], f"native workflow {name}", maximum=256)
                            for name in workflow_fields - {"workflow_sha256"}}
                selected["workflow_sha256"] = workflow["workflow_sha256"]
                identity = (selected["external_tool_name"], selected["external_action_id"],
                            selected["external_argument_schema_id"],
                            selected["external_result_schema_id"])
                if identity in workflow_keys:
                    raise EnrollmentDenied("native adapter workflow action is duplicated")
                workflow_keys.add(identity)
                workflows.append(MappingProxyType(selected))
            adapters[adapter_id] = NativeAdapterBinding(
                adapter_id, raw["manifest_sha256"], _native_catalog_id(raw["adapter_artifact_id"], "adapter artifact ID"),
                raw["adapter_sha256"], _native_catalog_id(raw["action_id"], "native action ID"),
                _native_catalog_id(raw["argument_schema_id"], "argument schema ID"),
                _native_catalog_id(raw["result_schema_id"], "result schema ID"),
                _native_catalog_id(raw["effect_enrollment_id"], "effect enrollment ID"), operation,
                _native_catalog_id(raw["capability"], "native capability"), _native_catalog_id(raw["target_id"], "native target ID"),
                _native_catalog_id(raw["recipient"], "native recipient"), raw["generation"],
                observer_ids, tuple(workflows),
            )
        action_records = _parse_native_action_records(item["action_records"], generation=generation)
        registration_records = _parse_native_registration_records(
            item["registration_records"], generation=generation,
        )
        workflow_records = _parse_native_workflow_records(item["workflow_records"], generation=generation)
        _validate_native_record_joins(
            adapters=adapters, actions=action_records, registrations=registration_records,
            workflows=workflow_records, package_id=package_id,
        )
        process_role_records = _parse_native_process_role_records(
            item["process_role_records"], package_id=package_id, generation=generation,
            profile_id=profile_id, profile_generation=profile_generation,
            actions=action_records, registrations=registration_records, workflows=workflow_records,
        )
        return cls(
            package_id, profile_id, generation, revision, item["source_tree_sha256"],
            _native_catalog_id(item["compiled_closure_artifact_id"], "compiled closure artifact ID"),
            item["compiled_closure_sha256"], _native_catalog_id(item["entrypoint_artifact_id"], "entrypoint artifact ID"),
            item["entrypoint_sha256"], _native_catalog_id(item["resolver_artifact_id"], "resolver artifact ID"),
            item["resolver_sha256"], _native_catalog_id(item["service_package_root_id"], "service package root ID"),
            _native_catalog_id(item["service_mount_id"], "service mount ID"), MappingProxyType(adapters),
            profile_generation, MappingProxyType(action_records), MappingProxyType(registration_records),
            MappingProxyType(workflow_records), MappingProxyType(process_role_records),
        )


@dataclass(frozen=True, slots=True)
class NativeCandidateIndexManifestEntry:
    """Fixed root-selected index member named by the pinned entrypoint manifest."""

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int

    @classmethod
    def from_entrypoint_manifest(
        cls, manifest: Mapping[str, Any], binding: Any,
    ) -> "NativeCandidateIndexManifestEntry | None":
        """Parse the nested member pin after the enclosing manifest is verified.

        Missing candidate_index means pre-discovery is unavailable. This method
        does not read the manifest artifact, verify its enclosing digest, or
        claim that the closure mount/member bytes have been checked.
        """
        if not isinstance(manifest, Mapping):
            raise EnrollmentDenied("native entrypoint manifest binding is unavailable")
        try:
            package_id = _id(getattr(binding, "package_id"), "native package ID")
            profile_id = _id(getattr(binding, "profile_id"), "native profile ID")
            generation = _id(getattr(binding, "generation"), "native package generation")
        except (AttributeError, TypeError, ValueError, EnrollmentDenied):
            raise EnrollmentDenied("native entrypoint manifest binding is unavailable") from None
        if (manifest.get("schema") != 1 or manifest.get("package_id") != package_id
                or manifest.get("profile_id") != profile_id
                or manifest.get("generation") != generation):
            raise EnrollmentDenied("native entrypoint manifest does not join the protected package")
        raw = manifest.get("candidate_index")
        if raw is None:
            return None
        fields = {"artifact_id", "relative_path", "sha256", "size_bytes"}
        if not isinstance(raw, Mapping) or set(raw) != fields:
            raise EnrollmentDenied("native candidate index manifest pin fields are invalid")
        expected_id = f"native-candidate-index:{package_id}:{generation}"
        if (raw["artifact_id"] != expected_id
                or raw["relative_path"] != "catalog/native-candidates.json"):
            raise EnrollmentDenied("native candidate index is not the fixed package closure member")
        digest, size = raw["sha256"], raw["size_bytes"]
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or not 1 <= size <= 2 * 1024 * 1024):
            raise EnrollmentDenied("native candidate index digest or size is invalid")
        closure_files = manifest.get("closure_files")
        if not isinstance(closure_files, list):
            raise EnrollmentDenied("native entrypoint closure file list is invalid")
        members = [item for item in closure_files
                   if isinstance(item, Mapping)
                   and item.get("relative_path") == "catalog/native-candidates.json"]
        if len(members) != 1:
            raise EnrollmentDenied("native candidate index is absent or ambiguous in the closure manifest")
        member = members[0]
        if member.get("sha256") != digest or member.get("size_bytes") != size:
            raise EnrollmentDenied("native candidate index pin differs from its closure file record")
        return cls(expected_id, "catalog/native-candidates.json", digest, size)


@dataclass(frozen=True, slots=True)
class PrivateLoopbackNetworkEnrollment:
    """Digest-bound private loopback policy selection; not an enforcement receipt."""

    id: str
    generation: str
    namespace_identity: str
    member_enrollment_ids: tuple[str, ...]
    listener_bindings: tuple[Mapping[str, Any], ...]
    client_bindings: tuple[Mapping[str, Any], ...]
    policy_artifact_id: str
    policy_sha256: str
    service_generation_digest: str

    @classmethod
    def from_protected_record(cls, row: Mapping[str, Any], *, digest: str) -> "PrivateLoopbackNetworkEnrollment":
        fields = {"id", "generation", "namespace_identity", "member_enrollment_ids",
                  "listener_bindings", "client_bindings", "policy_artifact_id", "policy_sha256"}
        if not isinstance(row, Mapping) or set(row) != fields:
            raise EnrollmentDenied("protected loopback network fields are invalid")
        def ident(value: Any, label: str) -> str:
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
                raise EnrollmentDenied(f"protected loopback {label} is invalid")
            return value
        members = row["member_enrollment_ids"]
        if (not isinstance(members, (list, tuple)) or not 2 <= len(members) <= 32
                or len(set(members)) != len(members)):
            raise EnrollmentDenied("protected loopback members are invalid")
        member_ids = tuple(ident(value, "member enrollment") for value in members)
        listeners = []
        for raw in row["listener_bindings"]:
            if not isinstance(raw, Mapping) or set(raw) != {"enrollment_id", "role", "ipv4", "port"}:
                raise EnrollmentDenied("protected loopback listener fields are invalid")
            enrollment_id = ident(raw["enrollment_id"], "listener enrollment")
            role = ident(raw["role"], "listener role")
            port = raw["port"]
            if enrollment_id not in member_ids or raw["ipv4"] != "127.0.0.1" or type(port) is not int or not 1 <= port <= 65535:
                raise EnrollmentDenied("protected loopback listener binding is invalid")
            listeners.append(MappingProxyType({"enrollment_id": enrollment_id, "role": role,
                                               "ipv4": "127.0.0.1", "port": port}))
        clients = []
        for raw in row["client_bindings"]:
            if not isinstance(raw, Mapping) or set(raw) != {"enrollment_id", "listener_enrollment_id", "port"}:
                raise EnrollmentDenied("protected loopback client fields are invalid")
            enrollment_id = ident(raw["enrollment_id"], "client enrollment")
            listener_id = ident(raw["listener_enrollment_id"], "client listener")
            port = raw["port"]
            if (enrollment_id not in member_ids or listener_id not in member_ids or enrollment_id == listener_id
                    or type(port) is not int or not 1 <= port <= 65535
                    or not any(item["enrollment_id"] == listener_id and item["port"] == port for item in listeners)):
                raise EnrollmentDenied("protected loopback client binding is invalid")
            clients.append(MappingProxyType({"enrollment_id": enrollment_id,
                                             "listener_enrollment_id": listener_id, "port": port}))
        sha = row["policy_sha256"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise EnrollmentDenied("protected loopback policy digest is invalid")
        return cls(ident(row["id"], "network ID"), ident(row["generation"], "generation"),
                   ident(row["namespace_identity"], "namespace identity"), member_ids,
                   tuple(listeners), tuple(clients), ident(row["policy_artifact_id"], "policy artifact"),
                   sha, digest)


@dataclass(frozen=True, slots=True)
class ProtectedSelectedResourceExecution:
    """Digest-covered selection metadata, not verified materialized source."""

    resource_id: str
    resource_kind: str
    source_revision: str
    source_manifest_sha256: str
    resource_generation: str
    profile_id: str
    profile_generation: str
    service_generation_digest: str
    materialization_receipt_handle: str
    materialized_member_path: str
    materialized_member_sha256: str
    materialized_member_size_bytes: int
    effective_spec_sha256: str
    backend_enrollment_id: str
    operation: str
    capability: str
    target_id: str
    recipient: str | None
    delegation_id: str | None
    enabled: bool

    @classmethod
    def from_protected_record(
        cls, row: Mapping[str, Any], *, service_generation_digest: str,
    ) -> "ProtectedSelectedResourceExecution":
        fields = {
            "resource_id", "resource_kind", "source_revision", "source_manifest_sha256",
            "resource_generation", "profile_id", "profile_generation",
            "materialization_receipt_handle", "materialized_member_path", "materialized_member_sha256",
            "materialized_member_size_bytes", "effective_spec_sha256", "backend_enrollment_id",
            "operation", "capability", "target_id", "recipient", "delegation_id", "enabled",
        }
        if not isinstance(row, Mapping) or set(row) != fields:
            raise EnrollmentDenied("protected selected resource execution fields are invalid")
        if not isinstance(service_generation_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest):
            raise EnrollmentDenied("selected resource enclosing generation digest is invalid")
        return cls(**dict(row), service_generation_digest=service_generation_digest)


@dataclass(frozen=True, slots=True)
class SelectedApplicationRuntimeEnrollment:
    """Digest-covered application selection metadata, not source/runtime proof."""

    record: Mapping[str, Any]
    service_generation_digest: str

    @classmethod
    def from_protected_record(
        cls, row: Mapping[str, Any], *, service_generation_digest: str,
    ) -> "SelectedApplicationRuntimeEnrollment":
        fields = {
            "application_id", "profile_id", "profile_generation", "principal_id", "adapter_id",
            "source_identity", "source_revision", "source_tree_sha256", "source_generation_receipt_handle",
            "source_generation_manifest_sha256", "runtime_id", "runtime_receipt_handle",
            "runtime_manifest_sha256", "lock_sha256", "work_root_id", "data_root_id", "operation_id",
            "process_start_target", "request_schema_id", "request_schema_sha256", "result_schema_id",
            "result_validator_artifact_id", "result_validator_sha256", "capability_ids", "provider_route_ids",
            "credential_reference_ids", "account_eligibility_receipt_handle", "memory_owner_generation",
            "max_lifetime_seconds", "max_memory_bytes", "max_workers", "metered_budget_usd", "enabled",
        }
        if not isinstance(row, Mapping) or set(row) != fields:
            raise EnrollmentDenied("protected selected application runtime fields are invalid")
        if (not isinstance(service_generation_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest)):
            raise EnrollmentDenied("selected application enclosing generation digest is invalid")
        copied = dict(row)
        for name in ("capability_ids", "provider_route_ids", "credential_reference_ids"):
            values = copied.get(name)
            if not isinstance(values, (list, tuple)):
                raise EnrollmentDenied(f"selected application {name} must be a finite sequence")
            copied[name] = tuple(values)
        return cls(MappingProxyType(copied), service_generation_digest)

    @property
    def application_id(self) -> str:
        return self.record["application_id"]

    @property
    def profile_id(self) -> str:
        return self.record["profile_id"]

    @property
    def profile_generation(self) -> str:
        return self.record["profile_generation"]


@dataclass(frozen=True, slots=True)
class RemoteStartupEnrollment:
    """Selection-only startup row from the active protected service snapshot."""

    id: str
    remote_enrollment_id: str
    display_enrollment_id: str
    display_generation: str
    display_operation_id: str
    gateway_enrollment_id: str
    gateway_generation: str
    gateway_operation_id: str
    desktop_enrollment_id: str
    desktop_generation: str
    desktop_operation_id: str
    network_enrollment_id: str
    xauthority_mount_id: str
    xpra_xauthority_overlay_artifact_id: str
    xpra_xauthority_overlay_sha256: str
    xpra_xauthority_patch_receipt_handle: str
    service_generation_digest: str

    @classmethod
    def from_protected_record(cls, row: Mapping[str, Any], *, digest: str) -> "RemoteStartupEnrollment":
        fields = {"id", "remote_enrollment_id", "display_enrollment_id", "display_generation",
                  "display_operation_id", "gateway_enrollment_id", "gateway_generation",
                  "gateway_operation_id", "desktop_enrollment_id", "desktop_generation",
                  "desktop_operation_id", "network_enrollment_id", "xauthority_mount_id",
                  "xpra_xauthority_overlay_artifact_id", "xpra_xauthority_overlay_sha256",
                  "xpra_xauthority_patch_receipt_handle"}
        if not isinstance(row, Mapping) or set(row) != fields:
            raise EnrollmentDenied("protected remote startup fields are invalid")
        for field in fields - {"xpra_xauthority_overlay_sha256"}:
            value = row[field]
            if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
                raise EnrollmentDenied(f"protected remote startup {field} is invalid")
        if row["display_operation_id"] != "native-display-start-v1":
            raise EnrollmentDenied("protected display operation is not fixed")
        if row["gateway_operation_id"] != "native-remote-gateway-start-v1":
            raise EnrollmentDenied("protected gateway operation is not fixed")
        if row["desktop_operation_id"] != "native-desktop-app-start-v1":
            raise EnrollmentDenied("protected desktop operation is not fixed")
        sha = row["xpra_xauthority_overlay_sha256"]
        if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise EnrollmentDenied("protected Xpra overlay digest is invalid")
        return cls(**{field: row[field] for field in fields}, service_generation_digest=digest)


@dataclass(frozen=True, slots=True)
class RootSelectedRemoteStartup:
    """Current joined startup selection; runtime receipts are still required."""

    startup: RemoteStartupEnrollment
    remote_session: Any
    display_service: HostServiceProfile
    gateway_service: HostServiceProfile
    desktop_service: HostServiceProfile
    network: PrivateLoopbackNetworkEnrollment
    service_generation_digest: str
    observation: Mapping[str, Any]

    @property
    def id(self) -> str:
        return self.startup.id

    @property
    def remote_enrollment_id(self) -> str:
        return self.startup.remote_enrollment_id

    @property
    def display_enrollment_id(self) -> str:
        return self.startup.display_enrollment_id

    @property
    def display_generation(self) -> str:
        return self.startup.display_generation

    @property
    def display_operation_id(self) -> str:
        return self.startup.display_operation_id

    @property
    def gateway_enrollment_id(self) -> str:
        return self.startup.gateway_enrollment_id

    @property
    def gateway_generation(self) -> str:
        return self.startup.gateway_generation

    @property
    def gateway_operation_id(self) -> str:
        return self.startup.gateway_operation_id

    @property
    def desktop_enrollment_id(self) -> str:
        return self.startup.desktop_enrollment_id

    @property
    def desktop_generation(self) -> str:
        return self.startup.desktop_generation

    @property
    def desktop_operation_id(self) -> str:
        return self.startup.desktop_operation_id

    @property
    def network_enrollment_id(self) -> str:
        return self.startup.network_enrollment_id

    @property
    def xauthority_mount_id(self) -> str:
        return self.startup.xauthority_mount_id

    @property
    def xpra_xauthority_overlay_artifact_id(self) -> str:
        return self.startup.xpra_xauthority_overlay_artifact_id

    @property
    def xpra_xauthority_overlay_sha256(self) -> str:
        return self.startup.xpra_xauthority_overlay_sha256

    @property
    def xpra_xauthority_patch_receipt_handle(self) -> str:
        return self.startup.xpra_xauthority_patch_receipt_handle

    @property
    def native_profile_id(self) -> str:
        return self.desktop_service.profile_id

    @property
    def native_generation(self) -> str:
        return self.desktop_service.generation

    @property
    def display_name(self) -> str:
        return self.observation["display_name"]

    @property
    def xauthority_receipt_handle(self) -> str:
        return self.observation["xauthority_receipt_handle"]

    @property
    def xauthority_reader_gid(self) -> int:
        # This is the already enrolled native Desktop service group. The
        # receipt registry still verifies the actual cookie inode/mode/group.
        return self.desktop_service.service_gid


@dataclass(frozen=True, slots=True)
class NativeSourceObserverJoin:
    """Metadata-only source join; it is not a loaded-closure or peer proof."""

    issuer: Any
    package: NativePackageBinding
    process_role: NativeProcessRoleRecord
    actions: Mapping[str, NativeActionRecord]
    registrations: Mapping[str, NativeRegistrationRecord]

    @property
    def action(self) -> NativeActionRecord:
        if len(self.actions) != 1:
            raise EnrollmentDenied("source observer has multiple selected action bindings")
        return next(iter(self.actions.values()))


def _parse_profile(item: Any) -> HostServiceProfile:
    fields = {"enrollment_id", "generation", "profile_id", "principal_id", "service_uid", "service_gid", "service_user",
              "device_enrollment_id", "expected_device_generation",
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
    device_enrollment_id = item["device_enrollment_id"]
    expected_device_generation = item["expected_device_generation"]
    if ((device_enrollment_id is None) != (expected_device_generation is None)
            or device_enrollment_id is not None and not isinstance(device_enrollment_id, str)
            or expected_device_generation is not None and not isinstance(expected_device_generation, str)):
        raise EnrollmentDenied("protected device selection ID and generation must be paired")
    if device_enrollment_id is not None:
        device_enrollment_id = _id(device_enrollment_id, "device enrollment ID")
        expected_device_generation = _id(expected_device_generation, "expected device generation")
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
        _id(item["service_user"], "service username"), device_enrollment_id,
        expected_device_generation, executable, item["executable_sha256"],
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
        if len(devices) != len(set(devices)):
            raise EnrollmentDenied("protected TPU device catalog is duplicated")
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
class RootJournalSelection:
    root_id: str
    path: Path
    device: int
    inode: int
    generation: str
    service_generation_digest: str


class ProtectedRootJournalCatalog:
    """Resolve opaque root journal IDs only from the active generation snapshot."""

    def __init__(self, records: Mapping[str, Mapping[str, Any]], *, generation_digest: str):
        if not re.fullmatch(r"[0-9a-f]{64}", generation_digest):
            raise EnrollmentDenied("root journal catalog generation digest is invalid")
        self.generation_digest = generation_digest
        self._records = MappingProxyType({key: MappingProxyType(dict(row))
                                          for key, row in records.items()})

    @classmethod
    def from_protected_records(cls, records: list[Mapping[str, Any]], *,
                               generation_digest: str) -> "ProtectedRootJournalCatalog":
        parsed: dict[str, Mapping[str, Any]] = {}
        fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
                  "device", "inode", "generation", "purpose"}
        for row in records:
            if not isinstance(row, Mapping) or set(row) != fields:
                raise EnrollmentDenied("protected root journal record fields are invalid")
            root_id = _id(row["root_id"], "root journal ID")
            if root_id in parsed:
                raise EnrollmentDenied("protected root journal ID is duplicated")
            path = _absolute(row["absolute_path"], "root journal path")
            numbers = (row["owner_uid"], row["owner_gid"], row["mode"], row["device"], row["inode"])
            if (any(type(value) is not int for value in numbers)
                    or row["owner_uid"] != 0 or row["owner_gid"] != 0
                    or row["mode"] != 0o700 or row["device"] < 0 or row["inode"] <= 0
                    or row["purpose"] != "authority-journal"):
                raise EnrollmentDenied("protected root journal identity or purpose is invalid")
            generation = _id(row["generation"], "root journal generation")
            parsed[root_id] = MappingProxyType({
                **dict(row), "absolute_path": path, "generation": generation,
            })
        return cls(parsed, generation_digest=generation_digest)

    def resolve(self, root_id: str, *, expected_active_generation_digest: str) -> RootJournalSelection:
        if expected_active_generation_digest != self.generation_digest:
            raise EnrollmentDenied("root journal selection belongs to a stale active generation")
        selected_id = _id(root_id, "root journal ID")
        row = self._records.get(selected_id)
        if row is None:
            raise EnrollmentDenied("root journal ID is not active")
        path = row["absolute_path"]
        try:
            _owned_path(path, uid=0, directory=True)
            info = path.stat(follow_symlinks=False)
        except (OSError, EnrollmentDenied):
            raise EnrollmentDenied("root journal path custody is unavailable") from None
        if (stat.S_IMODE(info.st_mode) != row["mode"] or info.st_gid != row["owner_gid"]
                or info.st_dev != row["device"] or info.st_ino != row["inode"]):
            raise EnrollmentDenied("root journal path identity changed")
        return RootJournalSelection(
            selected_id, path, info.st_dev, info.st_ino, row["generation"],
            self.generation_digest,
        )


@dataclass(frozen=True, slots=True)
class FixedBuildOutputSpec:
    relative_path: str
    kind: str
    maximum_bytes: int
    executable_role: str | None
    target_facts: Mapping[str, Any]


def _freeze_build_facts(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze_build_facts(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_build_facts(child) for child in value)
    if type(value) in {str, int, bool} or value is None:
        return value
    raise EnrollmentDenied("fixed build target fact value is not canonical JSON")


@dataclass(frozen=True, slots=True)
class FixedBuildProfile:
    target_id: str
    generation: str
    build_service_enrollment_id: str
    build_service_generation: str
    source_artifact_id: str
    source_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    builder_artifact_id: str
    builder_sha256: str
    argv_recipe: tuple[Mapping[str, Any], ...]
    environment: Mapping[str, str]
    max_lifetime_seconds: int
    output_root_id: str
    output_root: Path | None
    output_owner_uid: int
    output_specs: Mapping[str, FixedBuildOutputSpec]
    service_generation_digest: str = ""

    @staticmethod
    def _parse_argv_recipe(value: Any) -> tuple[Mapping[str, Any], ...]:
        """Parse the active generation's tagged, root-only build argv grammar."""
        mount_ids = {"builder", "source", "toolchain", "work", "output"}
        if not isinstance(value, list) or not value or len(value) > 128:
            raise EnrollmentDenied("fixed native build argv recipe is malformed")
        parsed: list[Mapping[str, Any]] = []
        for node in value:
            if not isinstance(node, Mapping):
                raise EnrollmentDenied("fixed build argv nodes must use tagged objects")
            if set(node) == {"literal"}:
                literal = node["literal"]
                if (not isinstance(literal, str) or len(literal) > 4096
                        or any(char in literal for char in ("\x00", "\n", "\r"))
                        or "${" in literal or "`" in literal):
                    raise EnrollmentDenied("fixed build argv literal is malformed")
                parsed.append(MappingProxyType({"literal": literal}))
                continue
            if set(node) != {"build_path"} or not isinstance(node["build_path"], Mapping):
                raise EnrollmentDenied("fixed build argv node has unknown tags or fields")
            path_node = node["build_path"]
            if set(path_node) != {"mount_id", "relative_path"}:
                raise EnrollmentDenied("fixed build path node fields are invalid")
            mount_id, relative_path = path_node["mount_id"], path_node["relative_path"]
            if (not isinstance(mount_id, str) or mount_id not in mount_ids
                    or not isinstance(relative_path, str) or "\\" in relative_path
                    or "\x00" in relative_path):
                raise EnrollmentDenied("fixed build path mount is not in the protected catalog")
            if relative_path:
                path = PurePosixPath(relative_path)
                if (path.is_absolute() or path.as_posix() != relative_path
                        or any(part in {"", ".", ".."} for part in path.parts)):
                    raise EnrollmentDenied("fixed build path is not a normalized relative path")
            parsed.append(MappingProxyType({"build_path": MappingProxyType({
                "mount_id": mount_id, "relative_path": relative_path,
            })}))
        if parsed[0] != {"build_path": {"mount_id": "builder", "relative_path": ""}}:
            raise EnrollmentDenied("fixed build argv[0] must be the enrolled builder executable mount")
        return tuple(parsed)

    @classmethod
    def from_protected_record(cls, item: Mapping[str, Any]) -> "FixedBuildProfile":
        required = {"target_id", "generation", "source_artifact_id", "source_sha256", "toolchain_artifact_id",
                    "toolchain_sha256", "builder_artifact_id", "builder_sha256", "argv_recipe", "environment",
                    "max_lifetime_seconds", "output_root_id", "output_root", "output_owner_uid", "output_specs",
                    "build_service_enrollment_id", "build_service_generation"}
        known_targets = {"coral-cpython-build:start", "colibri-source-build:start",
                         "xpra-root-xauthority-transform:start"}
        if set(item) != required or item.get("target_id") not in known_targets:
            raise EnrollmentDenied("fixed native build profile is unknown or malformed")
        for name in ("source_sha256", "toolchain_sha256", "builder_sha256"):
            if not isinstance(item[name], str) or not re.fullmatch(r"[0-9a-f]{64}", item[name]):
                raise EnrollmentDenied("fixed build source/toolchain/builder digest is invalid")
        recipe_value, env, outputs = item["argv_recipe"], item["environment"], item["output_specs"]
        if (not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) or "\x00" in v for k, v in env.items())
                or not isinstance(outputs, list) or not outputs or len(outputs) > 64):
            raise EnrollmentDenied("fixed native build recipe or outputs are malformed")
        recipe = cls._parse_argv_recipe(recipe_value)
        if (set(env) - _BUILD_ENV
                or any(re.search(r"token|secret|credential|password|api[_-]?key", key, re.I) for key in env)
                or any("\n" in value or "\r" in value or "$" in value or "`" in value for value in env.values())):
            raise EnrollmentDenied("fixed native build environment is not sanitized")
        output_specs: dict[str, FixedBuildOutputSpec] = {}
        for row in outputs:
            fields = {"relative_path", "kind", "maximum_bytes", "executable_role", "target_facts"}
            if not isinstance(row, Mapping) or set(row) != fields:
                raise EnrollmentDenied("fixed build output constraint fields are invalid")
            relative, kind = row["relative_path"], row["kind"]
            maximum, role, facts = row["maximum_bytes"], row["executable_role"], row["target_facts"]
            path = Path(relative) if isinstance(relative, str) else Path("/")
            if (not isinstance(relative, str) or "\\" in relative or "\x00" in relative or path.is_absolute()
                    or any(part in {"", ".", ".."} for part in path.parts)
                    or path.as_posix() != relative or relative in output_specs
                    or not isinstance(kind, str) or kind not in {"file", "tree"} or type(maximum) is not int
                    or not 1 <= maximum <= 2 * 1024**3
                    or (role is not None and (not isinstance(role, str)
                        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", role)))
                    or not isinstance(facts, Mapping) or not facts):
                raise EnrollmentDenied("fixed build output constraints are malformed")
            output_specs[relative] = FixedBuildOutputSpec(
                relative, kind, maximum, role, _freeze_build_facts(facts))
        if item["target_id"] == "colibri-source-build:start":
            expected_specs = {
                "c/colibri": {"kind": "file", "maximum_bytes": 67108864,
                    "executable_role": "colibri-engine", "target_facts": {
                        "elf_class": 64, "elf_machine": "EM_AARCH64", "os": "linux",
                        "required_runtime_dependencies": ["libgomp.so.1", "libm", "libc"],
                        "instruction_policy": "actual target compatible ARM64 flags; no x86 default or unmeasured CPUflags",
                    }},
            }
        elif item["target_id"] == "coral-cpython-build:start":
            expected_specs = {
                "runtime/bin/python3.9": {"kind": "file", "maximum_bytes": 67108864,
                    "executable_role": "coral-cpython39", "target_facts": {
                        "elf_class": 64, "elf_machine": "EM_AARCH64", "python_version": "3.9.25",
                        "soabi": "cpython-39-aarch64-linux-gnu", "debug": False,
                        "glibc_minimum": "2.34 for selected TFLite wheel",
                    }},
                "runtime/lib/python3.9": {"kind": "tree", "maximum_bytes": 268435456,
                    "executable_role": "cpython-stdlib-and-extension-closure", "target_facts": {
                        "python_version": "3.9.25", "target": "linux-aarch64",
                        "all_native_extensions": "ELF64EM_AARCH64, actual dependency closure verified",
                    }},
            }
        else:
            expected_specs = {
                "xpra-overlay.tar": {"kind": "file", "maximum_bytes": 134217728,
                    "executable_role": "data", "target_facts": {
                        "encoding": "deterministic tar emitted by pinned module",
                        "source_commit": "521b0d2e762c770b2641d258b93d23575fa9cbea",
                        "source_manifest_sha256": "108ab4e20dc62160fa3617f1622054b8b1ff3784ec2916f4a0e051aa961cec63",
                        "manifest_member": "hermes-installer-xpra-root-xauthority-overlay-v1.json",
                        "required_observed_facts": [
                            "source_tree_digest", "transform_module_sha256", "patched_file_sha256s",
                            "transformed_tree_sha256", "output_archive_sha256", "patch_manifest_sha256",
                        ],
                    }},
            }
        if set(output_specs) != set(expected_specs) or any(
                output_specs[name].kind != expected["kind"]
                or output_specs[name].maximum_bytes != expected["maximum_bytes"]
                or output_specs[name].executable_role != expected["executable_role"]
                or output_specs[name].target_facts != _freeze_build_facts(expected["target_facts"])
                for name, expected in expected_specs.items()):
            raise EnrollmentDenied("fixed build output constraints differ from the reviewed target profile")
        if any(node.get("literal") in {"-c", "-e", "--command"} for node in recipe[1:]
               if "literal" in node):
            raise EnrollmentDenied("fixed native build recipe cannot select shell or caller code")
        lifetime, owner_uid = item["max_lifetime_seconds"], item["output_owner_uid"]
        if type(lifetime) is not int or not 1 <= lifetime <= 600 or type(owner_uid) is not int or owner_uid <= 0:
            raise EnrollmentDenied("fixed native build deadline is invalid")
        return cls(_id(item["target_id"], "build target"), _id(item["generation"], "generation"),
                   _id(item["build_service_enrollment_id"], "build service enrollment"),
                   _id(item["build_service_generation"], "build service generation"),
                   _id(item["source_artifact_id"], "source artifact ID"), item["source_sha256"],
                   _id(item["toolchain_artifact_id"], "toolchain artifact ID"), item["toolchain_sha256"],
                   _id(item["builder_artifact_id"], "builder artifact ID"), item["builder_sha256"],
                   recipe, MappingProxyType(dict(env)), lifetime,
                   _id(item["output_root_id"], "output root ID"),
                   _absolute(item["output_root"], "build output root"), owner_uid,
                   MappingProxyType(output_specs))


class ProtectedBuildCatalog:
    """The only startable hardware build targets and their fixed root recipes."""

    REQUIRED_TARGETS = frozenset({"coral-cpython-build:start", "colibri-source-build:start",
                                  "xpra-root-xauthority-transform:start"})

    def __init__(self, profiles: Mapping[tuple[str, str], FixedBuildProfile], *,
                 service_generation_digest: str = ""):
        if service_generation_digest and not re.fullmatch(r"[0-9a-f]{64}", service_generation_digest):
            raise EnrollmentDenied("service generation digest is malformed")
        self.service_generation_digest = service_generation_digest
        self._profiles = MappingProxyType({key: replace(profile,
            service_generation_digest=service_generation_digest) for key, profile in profiles.items()})
        if any(target not in self.REQUIRED_TARGETS for target, _ in self._profiles):
            raise EnrollmentDenied("unknown hardware build target is not allowed")

    @classmethod
    def from_protected_records(cls, records: list[Mapping[str, Any]], *,
                               service_generation_digest: str = "") -> "ProtectedBuildCatalog":
        profiles = {}
        for item in records:
            profile = FixedBuildProfile.from_protected_record(item)
            key = (profile.target_id, profile.generation)
            if key in profiles:
                raise EnrollmentDenied("fixed build target generation is duplicated")
            profiles[key] = profile
        return cls(profiles, service_generation_digest=service_generation_digest)

    def resolve(self, target_id: str, generation: str) -> FixedBuildProfile:
        target = _id(target_id, "build target")
        if target not in self.REQUIRED_TARGETS:
            raise EnrollmentDenied("build target is not root-enrolled")
        profile = self._profiles.get((target, _id(generation, "generation")))
        if profile is None:
            raise EnrollmentDenied("fixed build profile generation is stale")
        return profile

    def resolve_service(self, target_id: str, generation: str,
                        service_catalog: ProtectedEnrollmentCatalog
                        ) -> tuple[FixedBuildProfile, HostServiceProfile]:
        """Join one build profile to its exact currently selected service identity."""
        profile = self.resolve(target_id, generation)
        service = service_catalog.resolve(
            profile.build_service_enrollment_id, profile.build_service_generation)
        try:
            account = pwd.getpwnam(service.service_user)
            group = grp.getgrgid(service.service_gid)
            primary_members = {
                row.pw_name for row in pwd.getpwall()
                if row.pw_gid == service.service_gid
            }
        except KeyError:
            raise EnrollmentDenied("dedicated build service account or group is unavailable") from None
        if (service.operation_targets.get("process.start") != profile.target_id
                or service.service_uid != profile.output_owner_uid
                or service.service_uid <= 0 or service.service_gid <= 0
                or account.pw_uid != service.service_uid or account.pw_gid != service.service_gid
                or group.gr_mem and set(group.gr_mem) != {service.service_user}
                or primary_members != {service.service_user}):
            raise EnrollmentDenied("fixed build profile does not join its dedicated selected service")
        return profile, service
