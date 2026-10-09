"""Root-owned authority enrollment and credential custody.

This is the only parser for `/etc/hermes-installer/authority.json`. Worker
configuration never flows into these records, and secret values are read from
individual root-only files only when Authentik authority is queried.
"""
from __future__ import annotations

import json
import hashlib
import os
import re
import secrets
import stat
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .authentik import (
    AuthentikEnrollment, AuthentikSystemPolicy, PrincipalIdentity,
    TLSAuthentikTransport,
)
from .service import AuthorityPolicy, ChildDelegationRule, EffectRule, PrincipalBinding
from .types import AuthorityDenied, Sensitivity

AUTHORITY_CONFIG_PATH = Path("/etc/hermes-installer/authority.json")
AUTHORITY_KEY_PATH = Path("/etc/hermes-installer/authority.key")
CREDENTIAL_DIRECTORY = Path("/etc/hermes-installer/credentials")
ARTIFACT_CATALOG_PATH = Path("/etc/hermes-installer/artifact-catalog.json")
ARTIFACT_STAGING_DIRECTORY = Path("/var/lib/hermes-installer/artifacts")
MAX_CONFIG_BYTES = 8 * 1_048_576
MAX_CREDENTIAL_BYTES = 16_384


def _secure_path(path: Path, *, expected_uid: int, allow_missing_leaf: bool = False) -> None:
    if not path.is_absolute():
        raise AuthorityDenied("custody.path", "protected path must be absolute")
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        is_leaf = index == len(path.parts[1:]) - 1
        try:
            info = current.lstat()
        except FileNotFoundError:
            if is_leaf and allow_missing_leaf:
                return
            raise AuthorityDenied("custody.path", "protected path is unavailable") from None
        if stat.S_ISLNK(info.st_mode):
            raise AuthorityDenied("custody.path", "protected path contains a symlink")
        if not is_leaf:
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise AuthorityDenied("custody.path", "protected directory ownership or mode is invalid")


def read_protected_file(path: Path, *, expected_uid: int = 0,
                        maximum: int = MAX_CONFIG_BYTES) -> bytes:
    _secure_path(path, expected_uid=expected_uid)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > maximum):
                raise AuthorityDenied("custody.file", "protected file ownership, mode, or size is invalid")
            data = bytearray()
            while len(data) <= maximum:
                block = os.read(fd, min(65536, maximum + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > maximum:
                raise AuthorityDenied("custody.file", "protected file exceeds its size bound")
            return bytes(data)
        finally:
            os.close(fd)
    except AuthorityDenied:
        raise
    except OSError:
        raise AuthorityDenied("custody.file", "protected file could not be read") from None


def write_protected_file(path: Path, data: bytes, *, expected_uid: int = 0,
                         maximum: int = MAX_CONFIG_BYTES) -> None:
    """Atomically create/replace a root-only config or secret without following links."""
    if os.geteuid() != expected_uid:
        raise AuthorityDenied("custody.write", "protected enrollment writer has the wrong UID")
    if not (path in {AUTHORITY_CONFIG_PATH, AUTHORITY_KEY_PATH, ARTIFACT_CATALOG_PATH}
            or path.parent == CREDENTIAL_DIRECTORY and _is_credential_reference(path.name)):
        raise AuthorityDenied("custody.write", "protected file destination is not enrolled")
    if not isinstance(data, bytes) or len(data) > maximum or not path.is_absolute():
        raise AuthorityDenied("custody.write", "protected file contents or path exceed bounds")
    _secure_path(path.parent / "placeholder", expected_uid=expected_uid,
                 allow_missing_leaf=True)
    _secure_path(path, expected_uid=expected_uid, allow_missing_leaf=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    if existing is not None and (not stat.S_ISREG(existing.st_mode)
                                 or existing.st_uid != expected_uid
                                 or stat.S_IMODE(existing.st_mode) != 0o600):
        raise AuthorityDenied("custody.write", "existing protected file has invalid custody")
    parent = path.parent
    temp_path = parent / f".{path.name}.{secrets.token_hex(12)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = -1
    try:
        fd = os.open(temp_path, flags, 0o600)
        os.fchmod(fd, 0o600)
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temp_path, path)
        dirfd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except AuthorityDenied:
        raise
    except OSError:
        raise AuthorityDenied("custody.write", "protected file update failed") from None
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            temp_path.unlink()
        except OSError:
            pass


def _reject_secret_material(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold().replace("-", "_")
            if normalized in {"token", "secret", "password", "access_token", "refresh_token", "bearer_token", "credential"}:
                raise AuthorityDenied("enrollment.secret", "authority configuration must contain credential references only")
            _reject_secret_material(child)
    elif isinstance(value, list):
        for child in value:
            _reject_secret_material(child)


def write_authority_config(document: Mapping[str, Any], *, expected_uid: int = 0) -> None:
    """Atomically install a strict reference-only authority configuration."""
    if expected_uid != 0 or not isinstance(document, Mapping):
        raise AuthorityDenied("enrollment.schema", "authority configuration must be a mapping")
    root = dict(document)
    _reject_secret_material(root)
    required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                "native_bridges", "normalization_policies", "delegations", "service_generations"}
    root = _exact(root, required, "authority")
    if root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "authority configuration schema version is unsupported")
    _validate_service_generations(root["service_generations"])
    encoded = json.dumps(root, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    write_protected_file(AUTHORITY_CONFIG_PATH, encoded, expected_uid=expected_uid)


def write_artifact_catalog(document: Mapping[str, Any], *, expected_uid: int = 0) -> None:
    if expected_uid != 0 or not isinstance(document, Mapping) or set(document) != {"schema", "artifacts", "packages"} or document.get("schema") != 1:
        raise AuthorityDenied("enrollment.catalog", "artifact catalog schema is invalid")
    encoded = json.dumps(dict(document), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    write_protected_file(ARTIFACT_CATALOG_PATH, encoded, expected_uid=expected_uid)


def create_authority_signing_key(*, expected_uid: int = 0) -> None:
    """Create the authority HMAC key once; rotation is a separate reviewed operation."""
    if os.geteuid() != expected_uid or expected_uid != 0:
        raise AuthorityDenied("key.enrollment", "signing-key enrollment requires the root authority identity")
    path = AUTHORITY_KEY_PATH
    _secure_path(path.parent / "placeholder", expected_uid=expected_uid, allow_missing_leaf=True)
    data = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags, 0o600)
        try:
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    except FileExistsError:
        raise AuthorityDenied("key.exists", "authority signing key already exists") from None
    except OSError:
        raise AuthorityDenied("key.enrollment", "authority signing key could not be created") from None
    finally:
        del data


class RootCredentialVault:
    """Resolve opaque IDs only from the fixed root-owned credential directory."""

    def __init__(self, directory: Path = CREDENTIAL_DIRECTORY, *, expected_uid: int = 0):
        if directory != CREDENTIAL_DIRECTORY or type(expected_uid) is not int or expected_uid != 0:
            raise ValueError("credential vault path and owner are fixed")
        _secure_path(directory / "entry", expected_uid=expected_uid, allow_missing_leaf=True)
        self.directory = directory
        self.expected_uid = expected_uid

    def resolve_reference(self, reference: str, *, peer_uid: int | None = None,
                          required_scope: str | None = None,
                          principal_id: str | None = None) -> str:
        if (not isinstance(reference, str) or not 1 <= len(reference) <= 96
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in reference)):
            raise AuthorityDenied("credential.reference", "credential reference is invalid")
        secret = read_protected_file(self.directory / reference,
                                     expected_uid=self.expected_uid,
                                     maximum=MAX_CREDENTIAL_BYTES)
        try:
            record = json.loads(secret.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise AuthorityDenied("credential.value", "protected credential is malformed")
        item = _exact(record, {"schema", "credential", "principal_id", "allowed_uids", "scopes"}, "credential")
        if (type(item["schema"]) is not int or item["schema"] != 1
                or not isinstance(item["principal_id"], str)
                or not isinstance(item["credential"], str)
                or not item["credential"] or any(char in item["credential"] for char in "\x00\r\n")
                or not isinstance(item["allowed_uids"], list) or not isinstance(item["scopes"], list)
                or not item["allowed_uids"]
                or any(type(uid) is not int or uid < 0 for uid in item["allowed_uids"])
                or any(not isinstance(scope, str) or not scope for scope in item["scopes"])):
            raise AuthorityDenied("credential.value", "protected credential metadata is malformed")
        if principal_id is not None and item["principal_id"] != principal_id:
            raise AuthorityDenied("credential.principal", "credential belongs to a different principal")
        if peer_uid is not None and (type(peer_uid) is not int or peer_uid not in item["allowed_uids"]):
            raise AuthorityDenied("credential.uid", "credential is not enrolled for this peer UID")
        if required_scope is not None and required_scope not in item["scopes"]:
            raise AuthorityDenied("credential.scope", "credential does not carry the required enrolled scope")
        return item["credential"]

    def write_credential(self, reference: str, credential: str, *,
                         principal_id: str, allowed_uids: list[int], scopes: list[str]) -> None:
        if (not isinstance(reference, str) or not 1 <= len(reference) <= 96
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in reference)
                or not isinstance(credential, str) or not credential
                or any(char in credential for char in "\x00\r\n")
                or not isinstance(allowed_uids, list) or not allowed_uids
                or any(type(uid) is not int or uid < 0 for uid in allowed_uids)
                or len(set(allowed_uids)) != len(allowed_uids)
                or not isinstance(scopes, list) or not scopes
                or any(not isinstance(scope, str) or not 1 <= len(scope) <= 128 for scope in scopes)
                or len(set(scopes)) != len(scopes)):
            raise AuthorityDenied("credential.enrollment", "credential enrollment metadata is invalid")
        payload = json.dumps({"schema": 1, "credential": credential,
                              "principal_id": _read_id(principal_id, "principal ID"),
                              "allowed_uids": sorted(allowed_uids), "scopes": sorted(scopes)},
                             sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        write_protected_file(self.directory / reference, payload,
                             expected_uid=self.expected_uid, maximum=MAX_CREDENTIAL_BYTES)


class RootMCPCredentialHandle:
    """Opaque root-only MCP bearer resolver; it never crosses the IPC boundary."""

    __slots__ = ("_service_id", "_reference", "_vault")

    def __init__(self, service_id: str, reference: str, vault: RootCredentialVault):
        self._service_id = service_id
        self._reference = reference
        self._vault = vault

    def headers_for(self, service_id: str, context: Any, authorization: Any) -> Mapping[str, str]:
        if (service_id != self._service_id or context.principal_id != authorization.principal_id
                or context.uid != authorization.uid
                or authorization.capability not in {f"mcp:{service_id}:read", f"mcp:{service_id}:connect"}):
            raise AuthorityDenied("mcp.credential", "MCP credential handle is outside its protected binding")
        scope = (f"mcp:{service_id}:connect" if authorization.capability == f"mcp:{service_id}:connect"
                 else f"mcp:{service_id}:read")
        token = self._vault.resolve_reference(
            self._reference, peer_uid=context.uid,
            required_scope=scope, principal_id=context.principal_id)
        return {"Authorization": f"Bearer {token}"}

    def __repr__(self) -> str:
        return "<RootMCPCredentialHandle protected>"


def _is_credential_reference(value: str) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 96
            and all(char in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-" for char in value))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AuthorityDenied("enrollment.schema", f"protected {label} schema is invalid")
    return value


def _read_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(char) < 0x21 or char in "\\\x7f" for char in value):
        raise AuthorityDenied("enrollment.schema", f"protected {label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class NativeBridgeEnrollment:
    """Root-selected producer/gateway pair and exact canonical provider route."""

    bridge_id: str
    producer_profile_id: str
    producer_uid: int
    producer_generation: str
    producer_executable: Path
    producer_executable_sha256: str
    producer_principal_id: str
    gateway_profile_id: str
    gateway_uid: int
    gateway_generation: str
    gateway_executable: Path
    gateway_executable_sha256: str
    gateway_principal_id: str
    canonicalizer_artifact_id: str
    canonicalizer_sha256: str
    normalization_policy_id: str
    normalization_policy_sha256: str
    normalization_policy_revision: int
    route_schema_id: str
    output_limit_mode: str
    output_limit_ceiling: int | None
    approved_operation: str
    provider_enrollment_id: str
    target: str
    recipient: str


@dataclass(frozen=True, slots=True)
class SourceIssuerRecord:
    issuer_channel_id: str
    producer_profile_id: str
    producer_role_artifact_id: str
    producer_role_sha256: str
    capture_schema_id: str
    allowed_parent_channels: tuple[str, ...]
    generation: str
    observer_enrollment_id: str
    source_action_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProtectedEnrollment:
    key_id: str
    bindings_by_uid: Mapping[int, PrincipalBinding]
    rules: Mapping[tuple[str, str, str], EffectRule]
    policy: AuthorityPolicy
    process_profiles: Mapping[str, Any]
    provider_enrollments: Mapping[str, Any]
    mcp_services: Mapping[str, Any]
    mcp_http_bindings: Mapping[str, Any]
    delegations: Mapping[str, ChildDelegationRule]
    memory_providers: Mapping[str, Any]
    native_bridges: Mapping[str, NativeBridgeEnrollment]
    artifact_catalog: Mapping[str, Any]
    package_catalog: Mapping[str, Any]
    artifact_catalog_path: Path
    artifact_staging_directory: Path
    service_records: list[Mapping[str, Any]]
    protected_devices: list[Mapping[str, Any]]
    protected_build_records: list[Mapping[str, Any]]
    protected_enrollment_digest: str
    native_package_records: list[Mapping[str, Any]]
    memory_enrollments: Mapping[tuple[str, str], Any]
    operation_parameter_schemas: list[Mapping[str, Any]]
    source_issuers: tuple[SourceIssuerRecord, ...]
    resource_job_records: tuple[Mapping[str, Any], ...]
    remote_session_records: tuple[Mapping[str, Any], ...]
    resource_backend_enrollment_records: tuple[Mapping[str, Any], ...]
    resource_body_recipe_records: tuple[Mapping[str, Any], ...]
    resource_scope_bindings: Mapping[str, Mapping[str, Any]]
    resource_validators: Mapping[str, Mapping[str, Any]]
    root_journal_root_records: tuple[Mapping[str, Any], ...]


_SOURCE_ACTIONS_BY_CHANNEL = {
    "native-input": frozenset({"authenticated-input"}),
    "tool-result": frozenset({"registered-tool-result"}),
    "memory-result": frozenset({"registered-memory-result"}),
    "effect-result": frozenset({"registered-effect-result"}),
    "delegated-child": frozenset({"registered-child-result"}),
    "schedule-event": frozenset({"root-timer-event"}),
}


def _parse_source_issuers(value: Any) -> tuple[SourceIssuerRecord, ...]:
    if not isinstance(value, list) or len(value) > 1024:
        raise AuthorityDenied("enrollment.source", "protected source issuer catalog is invalid")
    result = []
    seen_ids: set[str] = set()
    seen_bindings: set[tuple[str, str, str]] = set()
    expected = {"issuer_channel_id", "producer_profile_id", "producer_role_artifact_id",
                "producer_role_sha256", "capture_schema_id", "allowed_parent_channels",
                "generation", "observer_enrollment_id", "source_action_ids"}
    channels = set(_SOURCE_ACTIONS_BY_CHANNEL)
    for row in value:
        item = _exact(row, expected, "source issuer")
        channel = _read_id(item["issuer_channel_id"], "issuer channel")
        profile = _read_id(item["producer_profile_id"], "source producer profile")
        role_artifact = _read_id(item["producer_role_artifact_id"], "source producer role artifact")
        capture_schema = _read_id(item["capture_schema_id"], "source capture schema")
        generation = _read_id(item["generation"], "source producer generation")
        observer_id = _read_id(item["observer_enrollment_id"], "source observer enrollment")
        role_sha = item["producer_role_sha256"]
        actions = item["source_action_ids"]
        parents = item["allowed_parent_channels"]
        if (channel not in channels or not isinstance(role_sha, str)
                or not re.fullmatch(r"[0-9a-f]{64}", role_sha)
                or not isinstance(actions, list) or not actions or len(actions) > 16
                or any(not isinstance(action, str) for action in actions)
                or len(actions) != len(set(actions))
                or not set(actions).issubset(_SOURCE_ACTIONS_BY_CHANNEL[channel])
                or not isinstance(parents, list) or len(parents) > len(channels)
                or any(not isinstance(parent, str) or parent not in channels for parent in parents)
                or len(parents) != len(set(parents))):
            raise AuthorityDenied("enrollment.source", "protected source issuer row is malformed")
        binding_key = (channel, profile, generation)
        if observer_id in seen_ids or binding_key in seen_bindings:
            raise AuthorityDenied("enrollment.source", "protected source issuer is duplicated")
        seen_ids.add(observer_id)
        seen_bindings.add(binding_key)
        result.append(SourceIssuerRecord(
            channel, profile, role_artifact, role_sha, capture_schema,
            tuple(parents), generation, observer_id, tuple(actions),
        ))
    return tuple(result)


def _validate_service_generations(value: Any) -> dict[str, Any]:
    """Validate the one active, root-owned HI09 catalog snapshot and its digest."""
    keys = {"schema", "generation_id", "service_records", "protected_devices",
            "protected_build_records", "native_packages", "memory_enrollments",
            "operation_parameter_schemas", "source_issuers", "resource_jobs",
            "remote_session_enrollments", "resource_backend_enrollments",
            "resource_body_recipes", "resource_scope_bindings", "resource_validators",
            "root_journal_roots", "generation_digest"}
    item = _exact(value, keys, "service generation snapshot")
    if type(item["schema"]) is not int or item["schema"] != 1:
        raise AuthorityDenied("enrollment.generation", "service generation snapshot schema is unsupported")
    _read_id(item["generation_id"], "service generation snapshot ID")
    digest = item["generation_digest"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise AuthorityDenied("enrollment.generation", "service generation snapshot digest is invalid")
    unsigned = {key: child for key, child in item.items() if key != "generation_digest"}
    actual = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    if actual != digest:
        raise AuthorityDenied("enrollment.generation", "service generation snapshot digest does not match")
    list_fields = ("service_records", "protected_devices", "protected_build_records",
                   "native_packages", "memory_enrollments", "operation_parameter_schemas",
                   "source_issuers")
    for name in list_fields:
        rows = item[name]
        if (not isinstance(rows, list) or len(rows) > 1024
                or any(not isinstance(row, dict) for row in rows)):
            raise AuthorityDenied("enrollment.generation", f"protected {name} catalog is invalid")
    jobs = item["resource_jobs"]
    if (not isinstance(jobs, list) or len(jobs) > 692
            or any(not isinstance(row, dict) for row in jobs)):
        raise AuthorityDenied("enrollment.generation", "protected resource_jobs catalog is invalid")
    resource_fields = {
        "resource_id", "kind", "selected_enabled", "profile_id", "principal_id",
        "generation", "consent_revision", "approved_action_ids", "fixed_target_ids",
        "credential_reference_ids", "recipient_scope", "source_policy", "schedule_or_route_id",
        "max_children", "max_concurrency", "max_runtime_seconds", "max_payload_bytes",
        "max_replay_entries", "enrollment_id", "source_issuer_channel_id",
        "observer_enrollment_id", "backend_enrollment_id", "approved_dag",
    }
    seen_resource_ids: set[str] = set()
    for row in jobs:
        resource = _exact(row, resource_fields, "resource job enrollment")
        resource_id = _read_id(resource["resource_id"], "resource job ID")
        if resource_id in seen_resource_ids:
            raise AuthorityDenied("enrollment.generation", "resource job enrollment is duplicated")
        seen_resource_ids.add(resource_id)
        dag = _exact(resource["approved_dag"], {"dag_sha256", "nodes"}, "resource job DAG")
        if (not isinstance(dag["dag_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", dag["dag_sha256"])
                or not isinstance(dag["nodes"], list) or not 1 <= len(dag["nodes"]) <= 128):
            raise AuthorityDenied("enrollment.generation", "protected resource job DAG is malformed")
        node_fields = {"node_id", "resource_id", "action_id", "operation", "target_id",
                       "recipient", "request_schema_id", "body_recipe_id", "depends_on",
                       "maximum_attempts"}
        node_ids: set[str] = set()
        for raw_node in dag["nodes"]:
            node = _exact(raw_node, node_fields, "resource job DAG node")
            node_id = _read_id(node["node_id"], "resource DAG node ID")
            if node_id in node_ids:
                raise AuthorityDenied("enrollment.generation", "resource job DAG node is duplicated")
            node_ids.add(node_id)
    remote_rows = item["remote_session_enrollments"]
    if not isinstance(remote_rows, list) or len(remote_rows) > 128:
        raise AuthorityDenied("enrollment.generation", "protected remote session catalog is invalid")
    remote_fields = {
        "id", "gateway_profile_id", "gateway_role_artifact_id", "gateway_role_sha256",
        "native_desktop_profile_id", "native_generation", "connector_target_id",
        "approved_asset_routes", "approved_websocket_route", "expected_hostname",
        "expected_origin", "jwt_issuer", "jwt_audience", "jwks_origin",
        "jwt_algorithm_allowlist", "allowed_email_reference_id", "policy_verifier_enrollment_id",
        "policy_config_digest", "maximum_lease_seconds", "watchdog_interval_seconds",
        "policy_revision", "principal_bindings_by_subject", "access_policy_binding",
        "tunnel_runtime_binding",
    }
    access_fields = {
        "verifier_enrollment_id", "account_id", "application_id", "policy_id",
        "otp_identity_provider_id", "otp_provider_type", "verifier_config_digest",
        "read_credential_reference_id",
    }
    tunnel_fields = {
        "tunnel_enrollment_id", "tunnel_id", "cloudflared_profile_id",
        "tunnel_token_reference_id", "token_sink_id", "origin_readiness_policy_id",
    }
    seen_remote_ids: set[str] = set()
    for row in remote_rows:
        remote = _exact(row, remote_fields, "remote session enrollment")
        remote_id = _read_id(remote["id"], "remote session enrollment ID")
        if remote_id in seen_remote_ids:
            raise AuthorityDenied("enrollment.generation", "remote session enrollment is duplicated")
        try:
            for name in (
                "gateway_profile_id", "gateway_role_artifact_id", "native_desktop_profile_id",
                "native_generation", "connector_target_id", "approved_websocket_route",
                "expected_hostname", "expected_origin", "jwt_issuer", "jwt_audience",
                "jwks_origin", "allowed_email_reference_id", "policy_verifier_enrollment_id",
                "policy_revision",
            ):
                _read_id(remote[name], f"remote session {name}")
            if (not isinstance(remote["gateway_role_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", remote["gateway_role_sha256"])
                    or not isinstance(remote["policy_config_digest"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", remote["policy_config_digest"])):
                raise ValueError("remote session digest is invalid")
            assets = remote["approved_asset_routes"]
            algorithms = remote["jwt_algorithm_allowlist"]
            if (not isinstance(assets, list) or not assets or len(assets) > 32
                    or any(not isinstance(route, str) for route in assets)
                    or len(assets) != len(set(assets))
                    or not isinstance(algorithms, list) or algorithms != ["RS256"]
                    or type(remote["maximum_lease_seconds"]) is not int
                    or not 1 <= remote["maximum_lease_seconds"] <= 60
                    or type(remote["watchdog_interval_seconds"]) is not int
                    or not 1 <= remote["watchdog_interval_seconds"] <= 5):
                raise ValueError("remote session routes, JWT, or lease bounds are invalid")
            for route in assets:
                _read_id(route, "remote approved asset route")
            principals = remote["principal_bindings_by_subject"]
            if not isinstance(principals, dict) or not principals or len(principals) > 256:
                raise ValueError("remote principal subject map is invalid")
            for subject, binding in principals.items():
                _read_id(subject, "remote verified subject")
                item_binding = _exact(binding, {"principal_id", "profile_id", "email"},
                                      "remote verified principal binding")
                _read_id(item_binding["principal_id"], "remote principal ID")
                _read_id(item_binding["profile_id"], "remote profile ID")
                email = item_binding["email"]
                if (not isinstance(email, str) or len(email) > 320 or "@" not in email
                        or email != email.casefold() or any(c.isspace() for c in email)):
                    raise ValueError("remote verified email binding is invalid")
            access = _exact(remote["access_policy_binding"], access_fields,
                            "remote Access policy binding")
            for name in access_fields - {"otp_provider_type", "verifier_config_digest"}:
                _read_id(access[name], f"remote access {name}")
            if (access["otp_provider_type"] != "onetimepin"
                    or not isinstance(access["verifier_config_digest"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", access["verifier_config_digest"])):
                raise ValueError("remote Access verifier binding is invalid")
            tunnel = _exact(remote["tunnel_runtime_binding"], tunnel_fields,
                            "remote tunnel runtime binding")
            for name in tunnel_fields:
                _read_id(tunnel[name], f"remote tunnel {name}")
        except (TypeError, ValueError, AuthorityDenied):
            raise AuthorityDenied("enrollment.generation", "protected remote session record is malformed") from None
        seen_remote_ids.add(remote_id)
    backend_rows = item["resource_backend_enrollments"]
    if (not isinstance(backend_rows, list) or len(backend_rows) > 692
            or any(not isinstance(row, dict) for row in backend_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource backend catalog is invalid")
    backend_fields = {
        "id", "resource_id", "profile_id", "principal_id", "generation", "consent_revision",
        "source_issuer_channel_id", "observer_enrollment_id", "native_package_id",
        "native_package_generation", "handler_artifact_id", "handler_sha256",
        "approved_action_ids", "operation", "target_id", "recipient",
        "credential_reference_ids", "request_schema_id", "result_schema_id", "body_recipe_id",
        "scope_binding_id", "maximum_request_bytes", "maximum_response_bytes", "maximum_seconds",
    }
    seen_backend_ids: set[str] = set()
    for row in backend_rows:
        backend = _exact(row, backend_fields, "resource backend enrollment")
        backend_id = _read_id(backend["id"], "resource backend enrollment ID")
        if backend_id in seen_backend_ids:
            raise AuthorityDenied("enrollment.generation", "resource backend enrollment is duplicated")
        seen_backend_ids.add(backend_id)
        for name in (backend_fields - {"handler_sha256", "approved_action_ids",
                                       "credential_reference_ids", "maximum_request_bytes",
                                       "maximum_response_bytes", "maximum_seconds", "recipient"}):
            _read_id(backend[name], f"resource backend {name}")
        if (not isinstance(backend["handler_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", backend["handler_sha256"])
                or not isinstance(backend["approved_action_ids"], list)
                or not backend["approved_action_ids"]
                or len(backend["approved_action_ids"]) > 64
                or any(not isinstance(value, str) for value in backend["approved_action_ids"])
                or len(set(backend["approved_action_ids"])) != len(backend["approved_action_ids"])
                or not isinstance(backend["credential_reference_ids"], list)
                or len(backend["credential_reference_ids"]) > 64
                or any(not _is_credential_reference(value) for value in backend["credential_reference_ids"])
                or len(set(backend["credential_reference_ids"])) != len(backend["credential_reference_ids"])
                or type(backend["maximum_request_bytes"]) is not int
                or not 1 <= backend["maximum_request_bytes"] <= 256 * 1024
                or type(backend["maximum_response_bytes"]) is not int
                or not 1 <= backend["maximum_response_bytes"] <= 2 * 1024 * 1024
                or type(backend["maximum_seconds"]) is not int
                or not 1 <= backend["maximum_seconds"] <= 600):
            raise AuthorityDenied("enrollment.generation", "protected resource backend bounds are invalid")
        for action in backend["approved_action_ids"]:
            _read_id(action, "resource backend action ID")
        if backend["recipient"] is not None:
            _read_id(backend["recipient"], "resource backend recipient")
    body_rows = item["resource_body_recipes"]
    if (not isinstance(body_rows, list) or len(body_rows) > 4096
            or any(not isinstance(row, dict) for row in body_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource body recipe catalog is invalid")
    body_fields = {"id", "schema_id", "source_artifact_id", "source_sha256",
                   "output_fields", "scope_bindings", "maximum_bytes"}
    seen_body_ids: set[str] = set()
    for row in body_rows:
        body = _exact(row, body_fields, "resource body recipe")
        body_id = _read_id(body["id"], "resource body recipe ID")
        if body_id in seen_body_ids:
            raise AuthorityDenied("enrollment.generation", "resource body recipe is duplicated")
        seen_body_ids.add(body_id)
        for name in ("schema_id", "source_artifact_id"):
            _read_id(body[name], f"resource body recipe {name}")
        if (not isinstance(body["source_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", body["source_sha256"])
                or type(body["maximum_bytes"]) is not int
                or not 1 <= body["maximum_bytes"] <= 256 * 1024
                or not isinstance(body["output_fields"], list)
                or not 1 <= len(body["output_fields"]) <= 64
                or not isinstance(body["scope_bindings"], dict)
                or len(body["scope_bindings"]) > 64):
            raise AuthorityDenied("enrollment.generation", "protected resource body recipe is malformed")
        output_names: set[str] = set()
        for output in body["output_fields"]:
            item_output = _exact(output, {"name", "source", "value", "validator_id"},
                                 "resource body recipe output")
            name = _read_id(item_output["name"], "resource body field name")
            if (name in output_names or item_output["source"] not in {
                    "literal", "observed-event-field", "owned-parent-result-field"}):
                raise AuthorityDenied("enrollment.generation", "resource body recipe output is invalid")
            _read_id(item_output["validator_id"], "resource body validator ID")
            output_names.add(name)
        for scope_name, scope_id in body["scope_bindings"].items():
            _read_id(scope_name, "resource body scope name")
            _read_id(scope_id, "resource body scope binding ID")
    scope_rows = item["resource_scope_bindings"]
    if (not isinstance(scope_rows, list) or len(scope_rows) > 4096
            or any(not isinstance(row, dict) for row in scope_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource scope catalog is invalid")
    scope_fields = {"id", "resource_id", "profile_id", "principal_id", "resource_generation",
                    "profile_generation", "backend_enrollment_id", "fixed_fields",
                    "credential_reference_ids", "recipient"}
    seen_scope_ids: set[str] = set()
    for row in scope_rows:
        scope = _exact(row, scope_fields, "resource scope binding")
        scope_id = _read_id(scope["id"], "resource scope binding ID")
        if scope_id in seen_scope_ids:
            raise AuthorityDenied("enrollment.generation", "resource scope binding is duplicated")
        seen_scope_ids.add(scope_id)
        for name in ("resource_id", "profile_id", "principal_id", "resource_generation",
                     "profile_generation", "backend_enrollment_id"):
            _read_id(scope[name], f"resource scope {name}")
        fixed = scope["fixed_fields"]
        refs = scope["credential_reference_ids"]
        if (not isinstance(fixed, dict) or len(fixed) > 64
                or not isinstance(refs, list) or len(refs) > 64
                or any(not _is_credential_reference(value) for value in refs)
                or len(refs) != len(set(refs))):
            raise AuthorityDenied("enrollment.generation", "resource scope fixed values or credentials are invalid")
        for name, value in fixed.items():
            _read_id(name, "resource scope fixed field")
            normalized = name.casefold().replace("-", "_")
            if (any(term in normalized for term in ("token", "secret", "password", "credential", "api_key"))
                    or isinstance(value, (dict, list, float)) or value is None
                    or not isinstance(value, (str, int, bool))):
                raise AuthorityDenied("enrollment.generation", "resource scope fixed field is not a safe typed scalar")
            if isinstance(value, str) and (len(value) > 4096 or any(ch in value for ch in "\x00\r\n")
                                           or "://" in value or value.startswith(("/", "~"))):
                raise AuthorityDenied("enrollment.generation", "resource scope fixed value contains a path or URL")
        if scope["recipient"] is not None:
            _read_id(scope["recipient"], "resource scope recipient")
    validator_rows = item["resource_validators"]
    if (not isinstance(validator_rows, list) or len(validator_rows) > 4096
            or any(not isinstance(row, dict) for row in validator_rows)):
        raise AuthorityDenied("enrollment.generation", "protected resource validator catalog is invalid")
    validator_fields = {"id", "kind", "maximum_bytes", "minimum", "maximum",
                        "allowed_values", "schema_artifact_id", "schema_sha256"}
    validator_kinds = {"utf8-string", "opaque-id", "integer", "boolean", "enum", "bounded-json"}
    seen_validator_ids: set[str] = set()
    for row in validator_rows:
        validator = _exact(row, validator_fields, "resource validator")
        validator_id = _read_id(validator["id"], "resource validator ID")
        kind = validator["kind"]
        if validator_id in seen_validator_ids or kind not in validator_kinds:
            raise AuthorityDenied("enrollment.generation", "resource validator identity or kind is invalid")
        seen_validator_ids.add(validator_id)
        maximum_bytes = validator["maximum_bytes"]
        minimum, maximum = validator["minimum"], validator["maximum"]
        allowed = validator["allowed_values"]
        artifact_id, artifact_sha = validator["schema_artifact_id"], validator["schema_sha256"]
        if kind in {"utf8-string", "opaque-id", "bounded-json"}:
            cap = 128 if kind == "opaque-id" else 262_144
            if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= cap:
                raise AuthorityDenied("enrollment.generation", "resource validator byte bound is invalid")
        elif maximum_bytes is not None:
            raise AuthorityDenied("enrollment.generation", "resource validator has an inapplicable byte bound")
        if kind == "integer":
            if (type(minimum) is not int or type(maximum) is not int or minimum > maximum
                    or allowed is not None):
                raise AuthorityDenied("enrollment.generation", "resource integer validator bounds are invalid")
        elif minimum is not None or maximum is not None:
            raise AuthorityDenied("enrollment.generation", "resource validator has inapplicable numeric bounds")
        if kind == "enum":
            if (not isinstance(allowed, list) or not 1 <= len(allowed) <= 128
                    or len({(type(value).__name__, repr(value)) for value in allowed}) != len(allowed)
                    or any(value is None or isinstance(value, (dict, list, float))
                           or not isinstance(value, (str, int, bool)) for value in allowed)):
                raise AuthorityDenied("enrollment.generation", "resource enum validator values are invalid")
        elif allowed is not None:
            raise AuthorityDenied("enrollment.generation", "resource validator has inapplicable enum values")
        if kind == "bounded-json":
            _read_id(artifact_id, "resource validator schema artifact ID")
            if not isinstance(artifact_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", artifact_sha):
                raise AuthorityDenied("enrollment.generation", "resource JSON schema artifact digest is invalid")
        elif artifact_id is not None or artifact_sha is not None:
            raise AuthorityDenied("enrollment.generation", "resource validator has an inapplicable schema artifact")
    journal_rows = item["root_journal_roots"]
    if (not isinstance(journal_rows, list) or len(journal_rows) > 1024
            or any(not isinstance(row, dict) for row in journal_rows)):
        raise AuthorityDenied("enrollment.generation", "protected root journal catalog is invalid")
    journal_fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
                      "device", "inode", "generation", "purpose"}
    seen_journal_ids: set[str] = set()
    for row in journal_rows:
        journal = _exact(row, journal_fields, "root journal root")
        root_id = _read_id(journal["root_id"], "root journal ID")
        path = journal["absolute_path"]
        numbers = (journal["owner_uid"], journal["owner_gid"], journal["mode"],
                   journal["device"], journal["inode"])
        if (root_id in seen_journal_ids or not isinstance(path, str)
                or not Path(path).is_absolute() or "\x00" in path
                or any(type(number) is not int for number in numbers)
                or journal["owner_uid"] != 0 or journal["owner_gid"] != 0
                or journal["mode"] != 0o700 or journal["device"] < 0
                or journal["inode"] <= 0 or journal["purpose"] != "authority-journal"):
            raise AuthorityDenied("enrollment.generation", "root journal root identity or purpose is invalid")
        _read_id(journal["generation"], "root journal generation")
        seen_journal_ids.add(root_id)
    # Parse the exact active source-issuer schema here, after verifying the
    # digest, so callers cannot fall back to an unsigned sidecar catalog.
    _parse_source_issuers(item["source_issuers"])
    return item


def _verify_active_process_rules(service_profiles: Mapping[str, Any],
                                authority_profiles: Mapping[str, Any],
                                bindings: Mapping[int, Any],
                                rules: Mapping[tuple[str, str, str], Any]) -> None:
    """Require one exact authority rule for every root-registered process verb."""
    if set(service_profiles) != set(authority_profiles):
        raise ValueError("active service generations and authority process profiles differ")
    binding_by_profile: dict[str, Any] = {}
    for binding in bindings.values():
        if binding.profile_id in binding_by_profile:
            raise ValueError("authority process profile principal is duplicated")
        binding_by_profile[binding.profile_id] = binding
    process_operations = (
        ("hermes-profile-invoke", "process.start"),
        ("hermes-process-control", "process.status"),
        ("hermes-process-control", "process.read"),
        ("hermes-process-control", "process.write"),
        ("hermes-process-control", "process.stop"),
        ("hermes-process-control", "process.inspect"),
    )
    seen_targets: set[tuple[str, str]] = set()
    for profile_id, service in service_profiles.items():
        authority_profile = authority_profiles[profile_id]
        binding = binding_by_profile.get(profile_id)
        if (authority_profile.owner_uid != service.service_uid
                or authority_profile.owner_gid != service.service_gid
                or authority_profile.generation != service.generation
                or binding is None or binding.principal_id != service.principal_id
                or binding.profile_id != service.profile_id
                or binding.namespace_id != service.namespace_identity
                or binding.uid != service.service_uid):
            raise ValueError("service generation does not join its authority process identity")
        for capability, operation in process_operations:
            target = service.operation_targets.get(operation)
            if not isinstance(target, str) or not target:
                raise ValueError("active service generation omits a registered process target")
            handler_key = (operation, target)
            if handler_key in seen_targets:
                raise ValueError("managed process target is duplicated")
            seen_targets.add(handler_key)
            rule = rules.get((capability, operation, target))
            if (rule is None or rule.operation != operation or rule.recipient is not None
                    or capability not in binding.capabilities):
                raise ValueError("managed process handler has no exact authority rule")


def load_protected_enrollment(path: Path = AUTHORITY_CONFIG_PATH, *,
                              vault: RootCredentialVault | None = None,
                              expected_uid: int = 0) -> ProtectedEnrollment:
    if path != AUTHORITY_CONFIG_PATH or expected_uid != 0:
        raise ValueError("authority configuration path and owner are fixed")
    vault = vault or RootCredentialVault(expected_uid=expected_uid)
    try:
        value = json.loads(read_protected_file(path, expected_uid=expected_uid).decode("utf-8"),
                           object_pairs_hook=_unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        raise AuthorityDenied("enrollment.schema", "protected authority configuration is malformed") from None
    root = _exact(value, {"schema", "key_id", "principals", "rules", "authentik", "process_profiles", "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges", "normalization_policies", "delegations", "service_generations"}, "authority")
    _reject_secret_material(root)
    if type(root["schema"]) is not int or root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "protected authority schema version is unsupported")
    service_generations = _validate_service_generations(root["service_generations"])
    key_id = _read_id(root["key_id"], "key_id")
    if not isinstance(root["principals"], list) or not root["principals"] or len(root["principals"]) > 256:
        raise AuthorityDenied("enrollment.schema", "protected principal catalog is invalid")
    bindings: dict[int, PrincipalBinding] = {}
    profiles_seen: set[str] = set()
    identities: dict[str, PrincipalIdentity] = {}
    actor_refs: dict[str, str] = {}
    uid_by_principal: dict[str, int] = {}
    for raw in root["principals"]:
        item = _exact(raw, {"uid", "principal_id", "profile_id", "namespace_id", "capabilities", "username", "email", "authentik_subject_id", "actor_credential_ref"}, "principal")
        uid = item["uid"]
        if type(uid) is not int or uid <= 0 or uid in bindings:
            raise AuthorityDenied("enrollment.principal", "protected principal UID is invalid or duplicated")
        principal_id = _read_id(item["principal_id"], "principal ID")
        if principal_id in identities:
            raise AuthorityDenied("enrollment.principal", "protected principal identity is duplicated")
        caps = item["capabilities"]
        if not isinstance(caps, list) or not caps or len(caps) > 256 or any(not isinstance(cap, str) for cap in caps) or len(set(caps)) != len(caps):
            raise AuthorityDenied("enrollment.principal", "protected capability set is invalid")
        binding = PrincipalBinding(uid, principal_id,
                                   _read_id(item["profile_id"], "profile ID"),
                                   _read_id(item["namespace_id"], "namespace ID"),
                                   frozenset(caps))
        if binding.profile_id in profiles_seen:
            raise AuthorityDenied("enrollment.principal", "each managed profile has one protected principal UID")
        profiles_seen.add(binding.profile_id)
        bindings[uid] = binding
        try:
            identities[principal_id] = PrincipalIdentity(
                _read_id(item["username"], "Authentik username"),
                _read_id(item["email"], "Authentik email"),
                _read_id(item["authentik_subject_id"], "Authentik subject ID"),
            )
        except (TypeError, ValueError):
            raise AuthorityDenied("enrollment.principal", "protected Authentik identity is malformed") from None
        actor_refs[principal_id] = _read_id(item["actor_credential_ref"], "actor credential reference")
        uid_by_principal[principal_id] = uid
    if not isinstance(root["rules"], list) or not root["rules"] or len(root["rules"]) > 4096:
        raise AuthorityDenied("enrollment.schema", "protected effect rule catalog is invalid")
    rules: dict[tuple[str, str, str], EffectRule] = {}
    for raw in root["rules"]:
        item = _exact(raw, {"capability", "operation", "target", "recipient"}, "effect rule")
        capability = _read_id(item["capability"], "capability")
        target = _read_id(item["target"], "effect target")
        rule = EffectRule(capability, _read_id(item["operation"], "operation"), target,
                          None if item["recipient"] is None else _read_id(item["recipient"], "recipient"))
        key = (capability, rule.operation, target)
        if key in rules:
            raise AuthorityDenied("enrollment.rule", "protected effect rule is duplicated")
        rules[key] = rule
    auth = _exact(root["authentik"], {"base_url", "system_group_id", "write_group_by_target", "recipient_group_id", "recipient_email_by_id", "allowed_effects", "public_profile_purposes", "max_sensitivity_by_capability", "directory_credential_ref", "policy_revision"}, "Authentik policy")
    write_groups = auth["write_group_by_target"]
    emails = auth["recipient_email_by_id"]
    maxima = auth["max_sensitivity_by_capability"]
    if (not isinstance(write_groups, dict) or not isinstance(emails, dict)
            or not isinstance(maxima, dict) or not isinstance(auth["allowed_effects"], list)
            or not isinstance(auth["public_profile_purposes"], list)):
        raise AuthorityDenied("enrollment.authentik", "protected Authentik policy fields are malformed")
    allowed: set[tuple[str, str]] = set()
    for pair in auth["allowed_effects"]:
        if not isinstance(pair, list) or len(pair) != 2:
            raise AuthorityDenied("enrollment.authentik", "protected Authentik effect allowlist is malformed")
        parsed_pair = (_read_id(pair[0], "capability"), _read_id(pair[1], "effect target"))
        if parsed_pair in allowed:
            raise AuthorityDenied("enrollment.authentik", "protected Authentik effect is duplicated")
        allowed.add(parsed_pair)
    public: set[tuple[str, str]] = set()
    for pair in auth["public_profile_purposes"]:
        if not isinstance(pair, list) or len(pair) != 2:
            raise AuthorityDenied("enrollment.authentik", "protected public purpose rule is malformed")
        parsed_pair = (_read_id(pair[0], "profile ID"), _read_id(pair[1], "purpose"))
        if parsed_pair in public:
            raise AuthorityDenied("enrollment.authentik", "protected public purpose rule is duplicated")
        public.add(parsed_pair)
    if public:
        raise AuthorityDenied("enrollment.public-policy", "purpose labels cannot enroll public-data declassification")
    try:
        max_sensitivity = { _read_id(cap, "capability"): Sensitivity(value)
                           for cap, value in maxima.items() }
    except (ValueError, TypeError):
        raise AuthorityDenied("enrollment.authentik", "sensitivity ceiling is invalid") from None
    try:
        enrollment = AuthentikEnrollment(
            principal_identities=identities,
            system_group_id=_read_id(auth["system_group_id"], "System group ID"),
            write_group_by_target={_read_id(k, "target"): _read_id(v, "group ID") for k, v in write_groups.items()},
            recipient_group_id=_read_id(auth["recipient_group_id"], "recipient group ID"),
            recipient_email_by_id={_read_id(k, "recipient ID"): _read_id(v, "recipient email") for k, v in emails.items()},
            allowed_effects=frozenset(allowed), public_profile_purposes=frozenset(public),
            max_sensitivity_by_capability=max_sensitivity,
            policy_revision=_read_id(auth["policy_revision"], "policy revision"),
        )
        policy = AuthentikSystemPolicy(
            enrollment=enrollment,
            actor_token=lambda principal: vault.resolve_reference(
                actor_refs[principal], peer_uid=uid_by_principal[principal], required_scope="authentik-system-read",
                principal_id=principal) if principal in actor_refs else None,
            directory_token=lambda: vault.resolve_reference(
                _read_id(auth["directory_credential_ref"], "directory credential reference"),
                peer_uid=0, required_scope="authentik-directory-read",
                principal_id="authority:directory"),
            transport=TLSAuthentikTransport(auth["base_url"]),
        )
    except (TypeError, ValueError):
        raise AuthorityDenied("enrollment.authentik", "protected Authentik transport enrollment is invalid") from None
    for (cap, _operation, _target), rule in rules.items():
        if (cap, rule.target) not in enrollment.allowed_effects:
            raise AuthorityDenied("enrollment.rule", "effect rule is outside Authentik protected allowlist")
    if not isinstance(root["delegations"], list) or len(root["delegations"]) > 512:
        raise AuthorityDenied("enrollment.delegation", "protected delegation catalog is invalid")
    delegations: dict[str, ChildDelegationRule] = {}
    profiles_by_id = {binding.profile_id: binding for binding in bindings.values()}
    for raw in root["delegations"]:
        item = _exact(raw, {"id", "parent_profile_id", "parent_capability", "parent_operation",
                            "parent_target", "child_profile_id", "child_capability", "child_operation",
                            "child_target", "child_recipient", "child_purpose"}, "child delegation")
        rule = ChildDelegationRule(
            delegation_id=_read_id(item["id"], "delegation ID"),
            parent_profile_id=_read_id(item["parent_profile_id"], "parent profile ID"),
            parent_capability=_read_id(item["parent_capability"], "parent capability"),
            parent_operation=_read_id(item["parent_operation"], "parent operation"),
            parent_target=_read_id(item["parent_target"], "parent target"),
            child_profile_id=_read_id(item["child_profile_id"], "child profile ID"),
            child_capability=_read_id(item["child_capability"], "child capability"),
            child_operation=_read_id(item["child_operation"], "child operation"),
            child_target=_read_id(item["child_target"], "child target"),
            child_recipient=None if item["child_recipient"] is None else _read_id(item["child_recipient"], "child recipient"),
            child_purpose=_read_id(item["child_purpose"], "child purpose"),
        )
        parent_binding = profiles_by_id.get(rule.parent_profile_id)
        child_binding = profiles_by_id.get(rule.child_profile_id)
        parent_rule = rules.get((rule.parent_capability, rule.parent_operation, rule.parent_target))
        child_rule = rules.get((rule.child_capability, rule.child_operation, rule.child_target))
        if (rule.delegation_id in delegations or parent_binding is None or child_binding is None
                or rule.parent_capability not in parent_binding.capabilities
                or rule.child_capability not in child_binding.capabilities
                or parent_rule is None or parent_rule.operation != rule.parent_operation
                or child_rule is None or child_rule.operation != rule.child_operation
                or child_rule.recipient != rule.child_recipient):
            raise AuthorityDenied("enrollment.delegation", "child delegation is outside protected principal/effect rules")
        delegations[rule.delegation_id] = rule
    profiles = root["process_profiles"]
    if not isinstance(profiles, list) or len(profiles) > 256:
        raise AuthorityDenied("enrollment.process", "protected process profile catalog is invalid")
    process_profiles: dict[str, Any] = {}
    for raw in profiles:
        from hermes_installer.managed_process_custodian import ManagedProfileCustody
        item = _exact(raw, {"profile_id", "owner_uid", "owner_gid", "service_user", "executable", "artifact_sha256", "artifact_root", "data_root", "generation", "memory_max_bytes", "cpu_quota_percent", "io_weight", "max_lifetime_seconds", "child_artifact_refs", "argv_recipe"}, "process profile")
        profile_id = _read_id(item["profile_id"], "process profile ID")
        if profile_id in process_profiles:
            raise AuthorityDenied("enrollment.process", "process profile is duplicated")
        recipe = item["argv_recipe"]
        if (not isinstance(recipe, list) or not recipe or len(recipe) > 64
                or any(not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg for arg in recipe)):
            raise AuthorityDenied("enrollment.process", "protected argv recipe is malformed")
        process_profiles[profile_id] = ManagedProfileCustody(
            profile_id=profile_id, owner_uid=item["owner_uid"], owner_gid=item["owner_gid"],
            service_user=_read_id(item["service_user"], "service user"),
            executable=Path(_read_id(item["executable"], "executable path")),
            artifact_sha256=item["artifact_sha256"],
            artifact_root=Path(_read_id(item["artifact_root"], "artifact root")),
            data_root=Path(_read_id(item["data_root"], "data root")),
            generation=_read_id(item["generation"], "generation"),
            memory_max_bytes=item["memory_max_bytes"], cpu_quota_percent=item["cpu_quota_percent"],
            io_weight=item["io_weight"], max_lifetime_seconds=item["max_lifetime_seconds"],
            child_artifact_refs=item["child_artifact_refs"],
            argv_recipe=tuple(recipe),
            authority_socket=Path(f"/run/hermes-installer/authority/{item['owner_uid']}.sock"),
        )
    if (not process_profiles or any(binding.profile_id not in process_profiles
                                    or process_profiles[binding.profile_id].owner_uid != uid
                                    for uid, binding in bindings.items())):
        raise AuthorityDenied("enrollment.principal", "each socket principal must map to its exact managed profile UID")
    primary_gids = [process_profiles[binding.profile_id].owner_gid for binding in bindings.values()]
    if len(primary_gids) != len(set(primary_gids)) or any(type(gid) is not int or gid <= 0 for gid in primary_gids):
        raise AuthorityDenied("enrollment.principal", "socket principals require unique protected primary groups")
    catalogs = {}
    for field in ("provider_enrollments", "mcp_services", "memory_providers"):
        entries = root[field]
        if not isinstance(entries, list) or len(entries) > 4096:
            raise AuthorityDenied("enrollment.catalog", f"protected {field} catalog is invalid")
        index: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict) or "id" not in entry:
                raise AuthorityDenied("enrollment.catalog", f"protected {field} entry is invalid")
            entry_id = _read_id(entry["id"], f"{field} entry ID")
            if entry_id in index:
                raise AuthorityDenied("enrollment.catalog", f"protected {field} entry is duplicated")
            index[entry_id] = dict(entry)
        catalogs[field] = index
    for raw in catalogs["provider_enrollments"].values():
        item = _exact(raw, {"id", "provider", "account_id", "principal_id", "target", "recipient",
                            "credential_ref", "credential_scope", "models", "allowed_sensitivities",
                            "additional_metered_fee_usd"}, "provider enrollment")
        if (not _is_credential_reference(item["credential_ref"])
                or not isinstance(item["models"], list) or not item["models"]
                or len(item["models"]) != len(set(item["models"]))
                or any(not isinstance(model, str) or not model for model in item["models"])
                or not isinstance(item["allowed_sensitivities"], list)
                or not item["allowed_sensitivities"]
                or len(item["allowed_sensitivities"]) != len(set(item["allowed_sensitivities"]))
                or any(value not in {s.value for s in Sensitivity} for value in item["allowed_sensitivities"])
                or not isinstance(item["additional_metered_fee_usd"], (int, float))
                or isinstance(item["additional_metered_fee_usd"], bool)
                or item["additional_metered_fee_usd"] < 0):
            raise AuthorityDenied("enrollment.provider", "provider enrollment lacks a precise protected route binding")
    # HI11 root role pairing. The producer and gateway are selected only from
    # protected process/principal records; worker payloads never name either.
    raw_bridges = root["native_bridges"]
    if not isinstance(raw_bridges, list) or len(raw_bridges) > 128:
        raise AuthorityDenied("enrollment.native_bridge", "protected native bridge catalog is invalid")
    native_bridges: dict[str, Any] = {}
    bridge_pairs: set[tuple[str, str]] = set()
    binding_by_profile = {binding.profile_id: binding for binding in bindings.values()}
    for raw in raw_bridges:
        item = _exact(raw, {"id", "producer_profile_id", "gateway_profile_id",
                            "canonicalizer_artifact_id", "canonicalizer_sha256",
                            "normalization_policy_id", "normalization_policy_sha256",
                            "normalization_policy_revision", "route_schema_id",
                            "output_limit_mode", "output_limit_ceiling",
                            "approved_operation"}, "native bridge")
        bridge_id = _read_id(item["id"], "native bridge ID")
        producer_id = _read_id(item["producer_profile_id"], "native producer profile")
        gateway_id = _read_id(item["gateway_profile_id"], "native gateway profile")
        canonicalizer_id = _read_id(item["canonicalizer_artifact_id"], "native canonicalizer artifact")
        canonicalizer_sha = item["canonicalizer_sha256"]
        policy_id = _read_id(item["normalization_policy_id"], "normalization policy ID")
        policy_sha = item["normalization_policy_sha256"]
        policy_revision = item["normalization_policy_revision"]
        route_schema_id = _read_id(item["route_schema_id"], "provider route schema")
        limit_mode = item["output_limit_mode"]
        output_ceiling = item["output_limit_ceiling"]
        pair = (producer_id, gateway_id)
        producer = process_profiles.get(producer_id)
        gateway = process_profiles.get(gateway_id)
        producer_binding = binding_by_profile.get(producer_id)
        gateway_binding = binding_by_profile.get(gateway_id)
        if (bridge_id in native_bridges or pair in bridge_pairs or producer_id == gateway_id
                or item["approved_operation"] != "provider.dispatch"
                or canonicalizer_id != "provider-canonicalizer-v1"
                or canonicalizer_sha != "8539e50998ca68e1075030c021a5cb9d698fb2b01b50806f7218d8d1d1a50a52"
                or not isinstance(canonicalizer_sha, str)
                or not re.fullmatch(r"[0-9a-f]{64}", canonicalizer_sha)
                or producer is None or gateway is None
                or producer_binding is None or gateway_binding is None
                or producer.owner_uid == gateway.owner_uid
                or producer_binding.uid != producer.owner_uid
                or gateway_binding.uid != gateway.owner_uid):
            raise AuthorityDenied("enrollment.native_bridge", "native bridge identity or canonicalizer binding is invalid")
        provider_routes = [route for route in catalogs["provider_enrollments"].values()
                           if route["principal_id"] == producer_binding.principal_id]
        if len(provider_routes) != 1 or "provider-dispatch" not in producer_binding.capabilities:
            raise AuthorityDenied("enrollment.native_bridge", "producer must have one exact enrolled provider route")
        route = provider_routes[0]
        raw_policies = root["normalization_policies"]
        if not isinstance(raw_policies, list) or len(raw_policies) > 64:
            raise AuthorityDenied("enrollment.native_bridge", "normalization policy catalog is invalid")
        policy_catalog: dict[str, dict[str, Any]] = {}
        for raw_policy in raw_policies:
            policy = _exact(raw_policy, {"id", "revision", "route_schema_id", "output_limit_mode",
                                         "output_limit_ceiling", "canonicalizer_artifact_id",
                                         "canonicalizer_sha256", "normalization_policy_sha256"},
                            "normalization policy")
            item_id = _read_id(policy["id"], "normalization policy ID")
            if item_id in policy_catalog:
                raise AuthorityDenied("enrollment.native_bridge", "normalization policy is duplicated")
            revision = policy["revision"]
            module_hash = policy["canonicalizer_sha256"]
            policy_hash = policy["normalization_policy_sha256"]
            body = {key: value for key, value in policy.items() if key != "normalization_policy_sha256"}
            expected_policy_hash = hashlib.sha256(json.dumps(
                body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
            if (type(revision) is not int or revision < 1
                    or not isinstance(module_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", module_hash)
                    or not isinstance(policy_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", policy_hash)
                    or policy_hash != expected_policy_hash):
                raise AuthorityDenied("enrollment.native_bridge", "normalization policy hash or revision is invalid")
            policy_catalog[item_id] = policy
        if route["provider"] == "openrouter":
            expected_policy = ("provider-output-reject-4096-v1", 1, "provider-chat-compatible-v1",
                              "reject-over-ceiling", 4096)
        elif route["provider"] == "codex":
            expected_policy = ("siwc-output-unsupported-v1", 1, "siwc-responses-preview-v1",
                              "unsupported-field-reject", None)
        else:
            raise AuthorityDenied("enrollment.native_bridge", "provider route has no reviewed native normalization policy")
        policy_record = policy_catalog.get(policy_id)
        if (policy_record is None or type(policy_revision) is not int or policy_revision < 1
                or policy_record["id"] != expected_policy[0]
                or policy_revision != expected_policy[1]
                or policy_record["revision"] != policy_revision
                or policy_record["normalization_policy_sha256"] != policy_sha
                or (policy_record["route_schema_id"], policy_record["output_limit_mode"],
                    policy_record["output_limit_ceiling"]) != expected_policy[2:]
                or (policy_id, policy_revision, route_schema_id, limit_mode, output_ceiling) != expected_policy
                or policy_record["canonicalizer_artifact_id"] != canonicalizer_id
                or policy_record["canonicalizer_sha256"] != canonicalizer_sha):
            raise AuthorityDenied("enrollment.native_bridge", "native request normalization policy is not the selected route policy")
        provider_target = _read_id(route["target"], "native provider target")
        provider_recipient = _read_id(route["recipient"], "native provider recipient")
        native_bridges[bridge_id] = NativeBridgeEnrollment(
            bridge_id=bridge_id, producer_profile_id=producer_id,
            producer_uid=producer.owner_uid, producer_generation=producer.generation,
            producer_executable=producer.executable, producer_executable_sha256=producer.artifact_sha256,
            producer_principal_id=producer_binding.principal_id,
            gateway_profile_id=gateway_id, gateway_uid=gateway.owner_uid,
            gateway_generation=gateway.generation, gateway_executable=gateway.executable,
            gateway_executable_sha256=gateway.artifact_sha256,
            gateway_principal_id=gateway_binding.principal_id,
            canonicalizer_artifact_id=canonicalizer_id, canonicalizer_sha256=canonicalizer_sha,
            normalization_policy_id=policy_id, normalization_policy_sha256=policy_sha,
            normalization_policy_revision=policy_revision, route_schema_id=route_schema_id,
            output_limit_mode=limit_mode, output_limit_ceiling=output_ceiling,
            approved_operation="provider.dispatch", provider_enrollment_id=route["id"],
            target=provider_target, recipient=provider_recipient,
        )
        bridge_pairs.add(pair)
    mcp_bindings: dict[str, Any] = {}
    raw_bindings = root["mcp_http_bindings"]
    if not isinstance(raw_bindings, list) or len(raw_bindings) > 256:
        raise AuthorityDenied("enrollment.mcp", "protected MCP HTTP binding catalog is invalid")
    try:
        from hermes_installer.mcp.broker import ProtectedMCPService
        from hermes_installer.mcp.enrolled_transport import ProtectedMCPHTTPBinding
        protected_services: dict[str, Any] = {}
        for raw in catalogs["mcp_services"].values():
            item = _exact(raw, {"id", "channel", "allowed_tools", "transport_binding_id",
                                "reviewed_revision", "selection_arguments"}, "MCP service")
            service_id = _read_id(item["id"], "MCP service ID")
            if (not isinstance(item["allowed_tools"], list)
                    or not isinstance(item["selection_arguments"], dict)
                    or set(item["selection_arguments"]) != set(item["allowed_tools"])):
                raise ValueError("MCP service tool selection schema is invalid")
            selections = {}
            for tool, arguments in item["selection_arguments"].items():
                if (not isinstance(tool, str) or not isinstance(arguments, list) or not arguments
                        or any(not isinstance(arg, str) or not arg for arg in arguments)
                        or len(arguments) != len(set(arguments))):
                    raise ValueError("MCP selected-resource arguments are invalid")
                selections[tool] = tuple(arguments)
            protected_services[service_id] = ProtectedMCPService(
                service_id=service_id, channel=item["channel"],
                allowed_tools=frozenset(item["allowed_tools"]),
                transport_binding_id=_read_id(item["transport_binding_id"], "MCP transport binding"),
                reviewed_revision=item["reviewed_revision"], selection_arguments=selections)
        for raw in raw_bindings:
            item = _exact(raw, {"binding_id", "service_id", "endpoint", "endpoint_source_id",
                                "reviewed_revision", "credential_ref"}, "MCP HTTP binding")
            binding_id = _read_id(item["binding_id"], "MCP HTTP binding ID")
            service_id = _read_id(item["service_id"], "MCP service ID")
            service = protected_services.get(service_id)
            endpoint = item["endpoint"]
            parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
            if (binding_id in mcp_bindings or service is None or service.channel != "http"
                    or service.transport_binding_id != binding_id
                    or service.reviewed_revision != item["reviewed_revision"]
                    or parsed is None or parsed.scheme != "https" or not parsed.hostname
                    or parsed.username or parsed.password or parsed.query or parsed.fragment):
                raise ValueError("MCP endpoint does not match its reviewed HTTP service")
            reference = _read_id(item["credential_ref"], "MCP credential reference")
            if not _is_credential_reference(reference):
                raise ValueError("MCP credential reference is invalid")
            handle = RootMCPCredentialHandle(service_id, reference, vault)
            mcp_bindings[binding_id] = ProtectedMCPHTTPBinding(
                binding_id=binding_id, service_id=service_id, endpoint=endpoint,
                endpoint_source_id=_read_id(item["endpoint_source_id"], "MCP endpoint source"),
                reviewed_revision=item["reviewed_revision"], credential_handle=handle)
        if len(mcp_bindings) != sum(1 for service in protected_services.values() if service.channel == "http"):
            raise ValueError("every protected HTTP service needs exactly one binding")
    except (TypeError, ValueError, ImportError):
        raise AuthorityDenied("enrollment.mcp", "protected MCP service/endpoint enrollment is invalid") from None
    if catalogs["memory_providers"]:
        raise AuthorityDenied("enrollment.memory", "legacy memory provider rows cannot authorize active services")
    memory_enrollments: dict[tuple[str, str], Any] = {}
    if service_generations["memory_enrollments"]:
        try:
            from hermes_installer.memory.enrollment import MemoryServiceEnrollment
            generation_records: dict[tuple[str, str], Mapping[str, Any]] = {}
            for service_record in service_generations["service_records"]:
                identity = (service_record.get("enrollment_id"), service_record.get("generation"))
                if not all(isinstance(value, str) and value for value in identity) or identity in generation_records:
                    raise ValueError("service generation identity is malformed or duplicated")
                generation_records[identity] = service_record
            for raw_memory in service_generations["memory_enrollments"]:
                memory = MemoryServiceEnrollment.from_protected_record(raw_memory)
                key = (memory.service_enrollment_id, memory.service_generation)
                if key in memory_enrollments:
                    raise ValueError("memory service enrollment generation is duplicated")
                service_record = generation_records.get(key)
                profile = process_profiles.get(memory.profile_id)
                principal = next((binding for binding in bindings.values()
                                  if binding.profile_id == memory.profile_id), None)
                if (service_record is None or service_record.get("profile_id") != memory.profile_id
                        or service_record.get("principal_id") != memory.principal_id
                        or service_record.get("namespace_identity") != memory.namespace_identity
                        or profile is None or profile.generation != memory.service_generation
                        or principal is None
                        or memory.principal_id != principal.principal_id
                        or memory.namespace_identity != principal.namespace_id
                        or memory.data_root_id != profile.data_id):
                    raise ValueError("memory row does not join its protected service identity and data root")
                memory_enrollments[key] = memory
        except (ImportError, TypeError, ValueError, KeyError):
            raise AuthorityDenied("enrollment.memory", "protected memory service generation is invalid") from None
    # Process effect rules are joined to the active digest-bound service
    # snapshot, not targets reconstructed from caller journal/profile paths.
    # The root manager registers precisely these six handlers per profile.
    try:
        from hermes_installer.protected_enrollment import ProtectedEnrollmentCatalog
        generation_catalog = ProtectedEnrollmentCatalog.from_verified_records(
            service_generations["service_records"],
            protected_digest=service_generations["generation_digest"],
            expected_uid=0,
            native_packages=service_generations["native_packages"],
            memory_enrollments=memory_enrollments,
            parameter_schemas=service_generations["operation_parameter_schemas"],
        )
        generation_profiles = {}
        for service_record in service_generations["service_records"]:
            service = generation_catalog.resolve(
                service_record["enrollment_id"], service_record["generation"],
            )
            if service.profile_id in generation_profiles:
                raise ValueError("service profile is duplicated")
            authority_profile = process_profiles.get(service.profile_id)
            if (authority_profile is None
                    or authority_profile.owner_uid != service.service_uid
                    or authority_profile.owner_gid != service.service_gid
                    or authority_profile.generation != service.generation):
                raise ValueError("service generation does not join its authority process identity")
            generation_profiles[service.profile_id] = service
        _verify_active_process_rules(generation_profiles, process_profiles, bindings, rules)
    except (ImportError, AttributeError, KeyError, PermissionError, TypeError, ValueError):
        raise AuthorityDenied("enrollment.process", "managed process targets do not join the active service generation") from None
    return ProtectedEnrollment(
        key_id, bindings, rules, policy, process_profiles,
        catalogs["provider_enrollments"], catalogs["mcp_services"],
        mcp_bindings, delegations, catalogs["memory_providers"],
        native_bridges, {}, {}, ARTIFACT_CATALOG_PATH,
        ARTIFACT_STAGING_DIRECTORY,
        service_generations["service_records"],
        service_generations["protected_devices"],
        service_generations["protected_build_records"],
        service_generations["generation_digest"],
        service_generations["native_packages"],
        MappingProxyType(memory_enrollments),
        service_generations["operation_parameter_schemas"],
        _parse_source_issuers(service_generations["source_issuers"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_jobs"]),
        tuple(dict(row) for row in service_generations["remote_session_enrollments"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_backend_enrollments"]),
        tuple(MappingProxyType(dict(row)) for row in service_generations["resource_body_recipes"]),
        MappingProxyType({row["id"]: MappingProxyType(dict(row))
                          for row in service_generations["resource_scope_bindings"]}),
        MappingProxyType({row["id"]: MappingProxyType(dict(row))
                          for row in service_generations["resource_validators"]}),
        tuple(MappingProxyType(dict(row)) for row in service_generations["root_journal_roots"]),
    )


def load_artifact_catalog(enrollment: ProtectedEnrollment) -> Any:
    """Read the separately protected immutable artifact/package catalog."""
    from hermes_installer.artifacts import load_protected_catalog
    return load_protected_catalog(enrollment.artifact_catalog_path, expected_uid=0)
