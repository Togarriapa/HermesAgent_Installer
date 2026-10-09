"""Root-owned authority enrollment and credential custody.

This is the only parser for `/etc/hermes-installer/authority.json`. Worker
configuration never flows into these records, and secret values are read from
individual root-only files only when Authentik authority is queried.
"""
from __future__ import annotations

import json
import os
import secrets
import stat
from urllib.parse import urlsplit
from dataclasses import dataclass
from pathlib import Path
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
MAX_CONFIG_BYTES = 1_048_576
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
                "native_bridges", "delegations"}
    root = _exact(root, required, "authority")
    if root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "authority configuration schema version is unsupported")
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
    approved_operation: str
    provider_enrollment_id: str
    target: str
    recipient: str


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
    root = _exact(value, {"schema", "key_id", "principals", "rules", "authentik", "process_profiles", "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges", "delegations"}, "authority")
    _reject_secret_material(root)
    if type(root["schema"]) is not int or root["schema"] != 1:
        raise AuthorityDenied("enrollment.schema", "protected authority schema version is unsupported")
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
    from hermes_installer.managed_process_custodian import process_control_target, process_start_target
    for profile in process_profiles.values():
        required_process_rules = [
            ("hermes-profile-invoke", "process.start", process_start_target(profile)),
            ("hermes-process-control", "process.inspect", f"{profile.profile_id}:inspect"),
            *(("hermes-process-control", operation, process_control_target(profile, operation))
              for operation in ("process.status", "process.read", "process.write", "process.stop")),
        ]
        for capability, operation, target in required_process_rules:
            rule = rules.get((capability, operation, target))
            if (rule is None or rule.operation != operation or rule.recipient is not None
                    or any(capability not in binding.capabilities
                           for binding in bindings.values() if binding.profile_id == profile.profile_id)):
                raise AuthorityDenied("enrollment.process", "managed process verb is not explicitly enrolled")
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
                            "approved_operation"}, "native bridge")
        bridge_id = _read_id(item["id"], "native bridge ID")
        producer_id = _read_id(item["producer_profile_id"], "native producer profile")
        gateway_id = _read_id(item["gateway_profile_id"], "native gateway profile")
        canonicalizer_id = _read_id(item["canonicalizer_artifact_id"], "native canonicalizer artifact")
        canonicalizer_sha = item["canonicalizer_sha256"]
        pair = (producer_id, gateway_id)
        producer = process_profiles.get(producer_id)
        gateway = process_profiles.get(gateway_id)
        producer_binding = binding_by_profile.get(producer_id)
        gateway_binding = binding_by_profile.get(gateway_id)
        if (bridge_id in native_bridges or pair in bridge_pairs or producer_id == gateway_id
                or item["approved_operation"] != "provider.dispatch"
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
    memory_targets: set[tuple[str, str, str]] = set()
    used_memory_paths: set[tuple[str, str, str]] = set()
    profiles_by_id = process_profiles
    bindings_by_profile = {binding.profile_id: binding for binding in bindings.values()}
    for raw in catalogs["memory_providers"].values():
        target = _exact(raw, {"id", "provider", "profile_id", "namespace_id", "service_id",
                              "source_revision", "service_generation", "data_root_id", "dedicated_store",
                              "approved_route_ids"},
                        "memory provider")
        profile_id = _read_id(target["profile_id"], "memory profile ID")
        namespace_id = _read_id(target["namespace_id"], "memory namespace ID")
        provider = _read_id(target["provider"], "memory provider ID")
        service_id = _read_id(target["service_id"], "memory service ID")
        source_revision = _read_id(target["source_revision"], "memory source revision")
        service_generation = target["service_generation"]
        if type(service_generation) is not int or service_generation < 1:
            raise AuthorityDenied("enrollment.memory", "memory service generation is invalid")
        data_root_id = _read_id(target["data_root_id"], "memory data-root identity")
        route_ids = target["approved_route_ids"]
        route_catalog = {
            "openviking": {"memory.openviking.ready.v1", "memory.openviking.search.find.v1",
                           "memory.openviking.session.capture.v1"},
            "claude-mem": {"memory.claude-mem.healthz.v1", "memory.claude-mem.search.v1",
                           "memory.claude-mem.create.v1", "memory.claude-mem.delete.v1"},
            "agentmemory": {"memory.agentmemory.livez.v1", "memory.agentmemory.smart-search.v1",
                            "memory.agentmemory.remember.v1", "memory.agentmemory.forget.v1",
                            "memory.agentmemory.export.v1", "memory.agentmemory.import.v1"},
        }
        if (not isinstance(route_ids, list) or not route_ids or len(route_ids) > 16
                or any(not isinstance(route, str) for route in route_ids)
                or len(route_ids) != len(set(route_ids))
                or not set(route_ids).issubset(route_catalog.get(provider, set()))):
            raise AuthorityDenied("enrollment.memory", "approved memory route IDs are invalid")
        profile = profiles_by_id.get(profile_id)
        binding = bindings_by_profile.get(profile_id)
        if (provider not in {"openviking", "claude-mem", "agentmemory"}
                or target["dedicated_store"] is not True
                or profile is None or binding is None
                or binding.namespace_id != namespace_id
                or not Path(data_root_id).is_absolute()
                or Path(data_root_id) != profile.data_root):
            raise AuthorityDenied("enrollment.memory", "memory target lacks a matching protected profile data root")
        key = (profile_id, namespace_id, provider)
        uniqueness = (profile_id, service_id, data_root_id)
        if key in memory_targets or uniqueness in used_memory_paths:
            raise AuthorityDenied("enrollment.memory", "memory target or private store is duplicated")
        memory_targets.add(key)
        used_memory_paths.add(uniqueness)
    return ProtectedEnrollment(key_id, bindings, rules, policy, process_profiles,
                               catalogs["provider_enrollments"], catalogs["mcp_services"],
                               mcp_bindings, delegations, catalogs["memory_providers"],
                               native_bridges, {}, {}, ARTIFACT_CATALOG_PATH,
                               ARTIFACT_STAGING_DIRECTORY)


def load_artifact_catalog(enrollment: ProtectedEnrollment) -> Any:
    """Read the separately protected immutable artifact/package catalog."""
    from hermes_installer.artifacts import load_protected_catalog
    return load_protected_catalog(enrollment.artifact_catalog_path, expected_uid=0)
