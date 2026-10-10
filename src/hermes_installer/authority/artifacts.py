"""Root-held parent-to-child derivation receipts for selected JSON schemas.

The generic artifact store proves downloaded bytes. It does not prove that a
schema belongs to a selected package action or an authenticated MCP discovery.
This registry stores that distinct derivation and reopens every parent and
child from the current protected catalogs before returning it.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog, ResolvedArtifact
from hermes_installer.authority.bootstrap_enrollment import (
    RootArtifactReceiptRegistry,
    _read_json_if_owned,
)
from hermes_installer.authority.setup_policy_publication import (
    PolicyPublicationReceiptResolver,
    RootSetupPublicationReceipt,
)
from hermes_installer.protected_enrollment import RootJournalSelection


_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z", re.ASCII)
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_DERIVATION_FIELDS = frozenset({
    "schema", "receipt_handle", "artifact_id", "artifact_sha256", "size_bytes",
    "schema_kind", "package_id", "package_generation", "adapter_id", "action_id",
    "source_kind", "parent_receipt_handles", "source_observation_handle",
    "source_member_path", "service_generation_digest", "issued_monotonic",
    "expires_monotonic",
})
_RECORD_FIELDS = _DERIVATION_FIELDS | {"journal_root_device", "journal_root_inode"}
_SEAL = object()


class SchemaDerivationDenied(PermissionError):
    """A schema derivation is absent, stale, or not bound to protected bytes."""


class SchemaDerivationPending(RuntimeError):
    """A reviewed source observation required to derive this schema is absent."""


@dataclass(frozen=True, slots=True, repr=False)
class RootSchemaDerivationReceipt:
    schema: int
    receipt_handle: str
    artifact_id: str
    artifact_sha256: str
    size_bytes: int
    schema_kind: str
    package_id: str
    package_generation: str
    adapter_id: str
    action_id: str
    source_kind: str
    parent_receipt_handles: tuple[str, ...]
    source_observation_handle: str
    source_member_path: str | None
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("schema derivation receipts are minted by the root registry")


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedSchemaObservation:
    """Private bytes and provenance produced by a root source observer."""

    artifact_id: str
    artifact_sha256: str
    size_bytes: int
    schema_kind: str
    package_id: str
    package_generation: str
    adapter_id: str
    action_id: str
    source_kind: str
    parent_receipt_handles: tuple[str, ...]
    source_observation_handle: str
    source_member_path: str | None
    service_generation_digest: str
    _bytes: bytes = field(repr=False)
    _registry_id: str = field(repr=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("schema observations are created by the root derivation registry")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _observation_handle(*, artifact_id: str, sha256: str, size: int, schema_kind: str,
                       package_id: str, package_generation: str, adapter_id: str,
                       action_id: str, parent_handles: tuple[str, ...], member_path: str,
                       service_generation_digest: str) -> str:
    payload = {
        "artifact_id": artifact_id, "artifact_sha256": sha256, "size_bytes": size,
        "schema_kind": schema_kind, "package_id": package_id,
        "package_generation": package_generation, "adapter_id": adapter_id,
        "action_id": action_id, "parent_receipt_handles": list(parent_handles),
        "source_member_path": member_path,
        "service_generation_digest": service_generation_digest,
    }
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _safe_member(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
            or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts)
            or path.as_posix() != value):
        raise SchemaDerivationDenied("schema member path is not a normalized relative path")
    return path


def _read_registry_json(path: Path, *, expected_uid: int,
                        required_fields: frozenset[str] = _RECORD_FIELDS) -> Mapping[str, Any]:
    """Read one no-follow root journal row with its directory chain pinned."""
    current = Path(path.anchor)
    try:
        for part in path.parts[1:-1]:
            current /= part
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022):
                raise SchemaDerivationDenied("schema receipt directory custody changed")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or info.st_size > 32 * 1024):
                raise SchemaDerivationDenied("schema derivation receipt custody is invalid")
            chunks = bytearray()
            while len(chunks) <= 32 * 1024:
                block = os.read(fd, min(4096, 32 * 1024 + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            if len(chunks) > 32 * 1024:
                raise SchemaDerivationDenied("schema derivation receipt exceeds its bound")
        finally:
            os.close(fd)
    except SchemaDerivationDenied:
        raise
    except OSError:
        raise SchemaDerivationDenied("schema derivation receipt is unavailable") from None
    try:
        value = json.loads(bytes(chunks).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except Exception:
        raise SchemaDerivationDenied("schema derivation receipt is malformed") from None
    if not isinstance(value, dict) or set(value) != required_fields:
        raise SchemaDerivationDenied("schema derivation receipt has an unsupported shape")
    return MappingProxyType(value)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _parent_record(registry: RootArtifactReceiptRegistry, handle: str,
                   *, expected_uid: int) -> Mapping[str, Any]:
    if not _HANDLE.fullmatch(handle):
        raise SchemaDerivationDenied("schema parent receipt handle is malformed")
    value = _read_json_if_owned(registry.root / f"{handle}.json")
    required = {
        "schema", "handle", "receipt_id", "setup_session_id", "transaction_handle",
        "target_id", "operation_target_id", "plan_digest", "operator_uid",
        "artifact_role", "artifact_id", "sha256", "size_bytes",
    }
    if (not isinstance(value, Mapping) or set(value) != required or value.get("schema") != 1
            or value.get("handle") != handle or value.get("artifact_role") != value.get("artifact_id")
            or not _ID.fullmatch(str(value.get("artifact_id", "")))
            or not _SHA.fullmatch(str(value.get("sha256", "")))
            or type(value.get("size_bytes")) is not int):
        raise SchemaDerivationDenied("schema parent receipt is invalid")
    try:
        spec = registry.catalog._artifact(value["artifact_id"], value["sha256"])
        artifact = registry.catalog.resolve(value["artifact_id"], value["sha256"],
                                            registry.artifact_root, expected_uid=expected_uid)
    except Exception:
        raise SchemaDerivationDenied("schema parent receipt bytes are absent from root CAS") from None
    if spec.size_bytes != value["size_bytes"] or artifact.size_bytes != value["size_bytes"]:
        raise SchemaDerivationDenied("schema parent receipt size differs from catalog bytes")
    return MappingProxyType(dict(value))


def _read_regular_member(root: Path, relative: str, *, expected_uid: int,
                         maximum: int) -> bytes:
    parts = _safe_member(relative).parts
    flags_dir = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        directory_fd = os.open(root, flags_dir)
        for part in parts[:-1]:
            next_fd = os.open(part, flags_dir, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid
                    or info.st_nlink != 1 or info.st_size > maximum):
                raise SchemaDerivationDenied("schema source member custody or size is invalid")
            data = bytearray()
            while len(data) <= maximum:
                block = os.read(fd, min(64 * 1024, maximum + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) > maximum:
                raise SchemaDerivationDenied("schema source member exceeds its bound")
            return bytes(data)
        finally:
            os.close(fd)
            os.close(directory_fd)
    except SchemaDerivationDenied:
        raise
    except OSError:
        raise SchemaDerivationDenied("schema source member could not be opened safely") from None


@dataclass(slots=True)
class RootSchemaDerivationReceiptRegistry:
    """Root-private verifier and issuer for exact schema derivation receipts."""

    protected_artifact_catalog: ArtifactCatalog
    artifact_receipt_registry: RootArtifactReceiptRegistry
    native_package_registry: Any
    mcp_discovery_registry: Any
    root_journal: RootJournalSelection
    expected_uid: int = 0
    _instance_id: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)

    @classmethod
    def from_root_runtime(
        cls,
        protected_artifact_catalog: ArtifactCatalog,
        artifact_receipt_registry: RootArtifactReceiptRegistry,
        native_package_registry: Any,
        mcp_discovery_registry: Any,
        root_journal: RootJournalSelection,
        *,
        expected_uid: int = 0,
    ) -> "RootSchemaDerivationReceiptRegistry":
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not isinstance(protected_artifact_catalog, ArtifactCatalog)
                or not isinstance(artifact_receipt_registry, RootArtifactReceiptRegistry)
                or artifact_receipt_registry.catalog is not protected_artifact_catalog
                or not callable(getattr(native_package_registry, "resolve_native_package", None))
                or not isinstance(root_journal, RootJournalSelection)
                or root_journal.service_generation_digest == ""):
            raise SchemaDerivationDenied("root schema derivation dependencies are unavailable")
        return cls(protected_artifact_catalog, artifact_receipt_registry,
                   native_package_registry, mcp_discovery_registry, root_journal,
                   expected_uid)

    @property
    def receipt_root(self) -> Path:
        return self.root_journal.path / "schema-derivations"

    def observe_packaged_schema(
        self,
        *,
        schema_record: Mapping[str, Any],
        parent_receipt_handle: str,
    ) -> VerifiedSchemaObservation:
        """Derive child schema bytes from one selected source-tree member.

        The member is found by the protected child digest and size, not by a
        caller-provided path. Ambiguous duplicate-content members fail closed.
        """
        _require_root(self.expected_uid)
        row = _schema_record(schema_record)
        if not isinstance(parent_receipt_handle, str) or not _HANDLE.fullmatch(parent_receipt_handle):
            raise SchemaDerivationDenied("selected package source receipt handle is malformed")
        package = self.native_package_registry.resolve_native_package(
            row["native_package_id"], row["native_package_generation"],
        )
        if (package.generation != row["native_package_generation"]
                or package.profile_id == ""):
            raise SchemaDerivationDenied("native package is not selected in the active generation")
        self._require_selected_schema_row(row)
        parent = _parent_record(self.artifact_receipt_registry, parent_receipt_handle,
                                expected_uid=self.expected_uid)
        spec = self.protected_artifact_catalog._artifact(parent["artifact_id"], parent["sha256"])
        if (not spec.tree_files or not spec.archive_format
                or spec.tree_manifest_sha256 != package.source_tree_sha256
                or spec.version != package.source_revision):
            raise SchemaDerivationDenied("package source receipt does not match the selected source tree")
        child_spec = self.protected_artifact_catalog._artifact(row["artifact_id"], row["sha256"])
        if child_spec.size_bytes is None or not 1 <= child_spec.size_bytes <= 256 * 1024:
            raise SchemaDerivationDenied("selected schema artifact has no exact bounded byte size")
        matches = [entry.path for entry in spec.tree_files
                   if entry.kind == "file" and entry.sha256 == row["sha256"]
                   and entry.size_bytes == child_spec.size_bytes]
        if len(matches) != 1:
            raise SchemaDerivationDenied("selected schema bytes are absent or ambiguous in the package tree")
        source = self.protected_artifact_catalog.materialize_tree(
            parent["artifact_id"], parent["sha256"],
            self.artifact_receipt_registry.artifact_root, expected_uid=self.expected_uid,
        )
        source_bytes = _read_regular_member(source.path, matches[0],
                                            expected_uid=self.expected_uid,
                                            maximum=256 * 1024)
        if hashlib.sha256(source_bytes).hexdigest() != row["sha256"]:
            raise SchemaDerivationDenied("selected package schema member digest changed")
        child = self.protected_artifact_catalog.resolve(
            row["artifact_id"], row["sha256"], self.artifact_receipt_registry.artifact_root,
            expected_uid=self.expected_uid,
        )
        child_bytes = _read_regular_member(child.path.parent, child.path.name,
                                           expected_uid=self.expected_uid,
                                           maximum=256 * 1024)
        if source_bytes != child_bytes or len(child_bytes) != child_spec.size_bytes:
            raise SchemaDerivationDenied("derived schema bytes differ from selected immutable child artifact")
        try:
            parsed = json.loads(child_bytes.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            if _canonical(parsed) != child_bytes:
                raise ValueError
        except Exception:
            raise SchemaDerivationDenied("derived schema bytes are not canonical finite JSON") from None
        _active_publication_with_parent(parent_receipt_handle)
        observation_handle = _observation_handle(
            artifact_id=row["artifact_id"], sha256=row["sha256"], size=len(child_bytes),
            schema_kind=row["schema_kind"], package_id=row["native_package_id"],
            package_generation=row["native_package_generation"], adapter_id=row["adapter_id"],
            action_id=row["action_id"], parent_handles=(parent_receipt_handle,),
            member_path=matches[0], service_generation_digest=self.root_journal.service_generation_digest,
        )
        return VerifiedSchemaObservation(
            row["artifact_id"], row["sha256"], len(child_bytes), row["schema_kind"],
            row["native_package_id"], row["native_package_generation"], row["adapter_id"],
            row["action_id"], "packaged-schema", (parent_receipt_handle,),
            observation_handle, matches[0], self.root_journal.service_generation_digest,
            child_bytes, self._instance_id, _SEAL,
        )

    def mint_schema_artifact(self, verified_schema_observation: VerifiedSchemaObservation,
                             *, ttl_seconds: float = 3600.0) -> str:
        """Persist a receipt only from a live observation made by this instance."""
        _require_root(self.expected_uid)
        observation = verified_schema_observation
        if (type(observation) is not VerifiedSchemaObservation or observation._seal is not _SEAL
                or observation._registry_id != self._instance_id
                or observation.service_generation_digest != self.root_journal.service_generation_digest
                or not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool)
                or not math.isfinite(ttl_seconds) or not 1 <= ttl_seconds <= 3600
                or hashlib.sha256(observation._bytes).hexdigest() != observation.artifact_sha256
                or len(observation._bytes) != observation.size_bytes):
            raise SchemaDerivationDenied("schema observation is unverified, stale, or outside its lease")
        now = time.monotonic()
        handle = secrets.token_urlsafe(32)
        record = {
            "schema": 1, "receipt_handle": handle,
            "artifact_id": observation.artifact_id,
            "artifact_sha256": observation.artifact_sha256,
            "size_bytes": observation.size_bytes, "schema_kind": observation.schema_kind,
            "package_id": observation.package_id,
            "package_generation": observation.package_generation,
            "adapter_id": observation.adapter_id, "action_id": observation.action_id,
            "source_kind": observation.source_kind,
            "parent_receipt_handles": list(observation.parent_receipt_handles),
            "source_observation_handle": observation.source_observation_handle,
            "source_member_path": observation.source_member_path,
            "service_generation_digest": observation.service_generation_digest,
            "issued_monotonic": now, "expires_monotonic": now + float(ttl_seconds),
            "journal_root_device": self.root_journal.device,
            "journal_root_inode": self.root_journal.inode,
        }
        root = self._secure_receipt_root(create=True)
        path = root / f"{handle}.json"
        observation_root = self._secure_observation_root(create=True)
        observation_path = observation_root / f"{observation.source_observation_handle}.json"
        observation_record = {
            "schema": 1, "observation_handle": observation.source_observation_handle,
            "artifact_id": observation.artifact_id, "artifact_sha256": observation.artifact_sha256,
            "size_bytes": observation.size_bytes, "schema_kind": observation.schema_kind,
            "package_id": observation.package_id, "package_generation": observation.package_generation,
            "adapter_id": observation.adapter_id, "action_id": observation.action_id,
            "source_kind": observation.source_kind,
            "parent_receipt_handles": list(observation.parent_receipt_handles),
            "source_member_path": observation.source_member_path,
            "service_generation_digest": observation.service_generation_digest,
        }
        self._write_root_json(observation_path, observation_record)
        payload = _canonical(record)
        self._write_root_bytes(path, payload)
        return handle

    def resolve_schema_derivation(
        self,
        handle: str,
        *,
        artifact_id: str,
        artifact_sha256: str,
        size_bytes: int,
        service_generation_digest: str,
    ) -> RootSchemaDerivationReceipt:
        """Revalidate current generation, receipt ancestry and exact member bytes."""
        _require_root(self.expected_uid)
        if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
                or not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id)
                or not isinstance(artifact_sha256, str) or not _SHA.fullmatch(artifact_sha256)
                or type(size_bytes) is not int or not 1 <= size_bytes <= 256 * 1024
                or service_generation_digest != self.root_journal.service_generation_digest):
            raise SchemaDerivationDenied("schema derivation lookup identity is malformed or stale")
        root = self._secure_receipt_root(create=False)
        value = _read_registry_json(root / f"{handle}.json", expected_uid=self.expected_uid)
        _validate_derivation_record(value, handle)
        now = time.monotonic()
        if (value["artifact_id"] != artifact_id or value["artifact_sha256"] != artifact_sha256
                or value["size_bytes"] != size_bytes
                or value["service_generation_digest"] != service_generation_digest
                or value["journal_root_device"] != self.root_journal.device
                or value["journal_root_inode"] != self.root_journal.inode
                or now < value["issued_monotonic"] or now >= value["expires_monotonic"]):
            raise SchemaDerivationDenied("schema derivation receipt identity or lease is stale")
        self._verify_observation(value)
        publication = _active_publication()
        if (handle not in publication.input_receipt_handles
                or any(parent not in publication.input_receipt_handles
                       for parent in value["parent_receipt_handles"])):
            raise SchemaDerivationDenied("schema receipt or parent is absent from current active publication")
        row = self._resolve_selected_row(value)
        if (row["artifact_id"] != artifact_id or row["sha256"] != artifact_sha256
                or row["schema_kind"] != value["schema_kind"]
                or row["native_package_id"] != value["package_id"]
                or row["native_package_generation"] != value["package_generation"]
                or row["adapter_id"] != value["adapter_id"]
                or row["action_id"] != value["action_id"]
                or row["source_receipt_handle"] != handle):
            raise SchemaDerivationDenied("schema derivation does not match the selected active schema row")
        if value["source_kind"] == "packaged-schema":
            self._revalidate_packaged_derivation(value)
        elif value["source_kind"] == "mcp-tools-list":
            self._revalidate_discovery_derivation(value)
        else:
            raise SchemaDerivationDenied("schema receipt source kind is unsupported")
        return RootSchemaDerivationReceipt(
            1, handle, value["artifact_id"], value["artifact_sha256"], value["size_bytes"],
            value["schema_kind"], value["package_id"], value["package_generation"],
            value["adapter_id"], value["action_id"], value["source_kind"],
            tuple(value["parent_receipt_handles"]), value["source_observation_handle"],
            value["source_member_path"], value["service_generation_digest"],
            value["issued_monotonic"], value["expires_monotonic"], _SEAL,
        )

    def _resolve_selected_row(self, value: Mapping[str, Any]) -> Mapping[str, Any]:
        records = getattr(self.native_package_registry, "native_schema_artifact_records", ())
        candidates = [row for row in records
                      if isinstance(row, Mapping)
                      and row.get("artifact_id") == value["artifact_id"]
                      and row.get("sha256") == value["artifact_sha256"]
                      and row.get("schema_kind") == value["schema_kind"]
                      and row.get("native_package_id") == value["package_id"]
                      and row.get("native_package_generation") == value["package_generation"]
                      and row.get("adapter_id") == value["adapter_id"]
                      and row.get("action_id") == value["action_id"]
                      and row.get("source_receipt_handle") == value["receipt_handle"]]
        if len(candidates) != 1:
            raise SchemaDerivationDenied("derived schema receipt is not uniquely selected in the active generation")
        return self._require_selected_schema_row(candidates[0])

    def _require_selected_schema_row(self, raw: Mapping[str, Any]) -> Mapping[str, Any]:
        resolver = getattr(self.native_package_registry, "resolve_native_schema_record", None)
        if not callable(resolver):
            raise SchemaDerivationPending("active native schema row resolver is unavailable")
        row = _schema_record(raw)
        try:
            selected = resolver(row["id"], row["native_package_id"],
                                row["native_package_generation"], row["adapter_id"],
                                row["action_id"], row["schema_kind"])
        except Exception:
            raise SchemaDerivationDenied("schema row is not selected by the active package action") from None
        if not isinstance(selected, Mapping) or dict(selected) != dict(row):
            raise SchemaDerivationDenied("resolved schema row differs from the active protected row")
        return MappingProxyType(dict(selected))

    def _verify_observation(self, value: Mapping[str, Any]) -> None:
        if value["source_kind"] != "packaged-schema":
            return
        path = self._secure_observation_root(create=False) / f"{value['source_observation_handle']}.json"
        expected = {
            "schema": 1, "observation_handle": value["source_observation_handle"],
            "artifact_id": value["artifact_id"], "artifact_sha256": value["artifact_sha256"],
            "size_bytes": value["size_bytes"], "schema_kind": value["schema_kind"],
            "package_id": value["package_id"], "package_generation": value["package_generation"],
            "adapter_id": value["adapter_id"], "action_id": value["action_id"],
            "source_kind": value["source_kind"],
            "parent_receipt_handles": value["parent_receipt_handles"],
            "source_member_path": value["source_member_path"],
            "service_generation_digest": value["service_generation_digest"],
        }
        observation = _read_registry_json(path, expected_uid=self.expected_uid,
                                          required_fields=frozenset(expected))
        if set(observation) != set(expected) or dict(observation) != expected:
            raise SchemaDerivationDenied("retained root schema observation differs from its receipt")
        if value["source_kind"] == "packaged-schema":
            recomputed = _observation_handle(
                artifact_id=value["artifact_id"], sha256=value["artifact_sha256"],
                size=value["size_bytes"], schema_kind=value["schema_kind"],
                package_id=value["package_id"],
                package_generation=value["package_generation"],
                adapter_id=value["adapter_id"], action_id=value["action_id"],
                parent_handles=tuple(value["parent_receipt_handles"]),
                member_path=value["source_member_path"],
                service_generation_digest=value["service_generation_digest"],
            )
            if recomputed != value["source_observation_handle"]:
                raise SchemaDerivationDenied("retained root schema observation handle is not content-bound")

    def _revalidate_packaged_derivation(self, value: Mapping[str, Any]) -> None:
        if not isinstance(value["source_member_path"], str):
            raise SchemaDerivationDenied("packaged schema derivation has no member path")
        package = self.native_package_registry.resolve_native_package(
            value["package_id"], value["package_generation"],
        )
        parents = [_parent_record(self.artifact_receipt_registry, parent,
                                 expected_uid=self.expected_uid)
                   for parent in value["parent_receipt_handles"]]
        matches = []
        for parent in parents:
            spec = self.protected_artifact_catalog._artifact(parent["artifact_id"], parent["sha256"])
            if (spec.tree_files and spec.tree_manifest_sha256 == package.source_tree_sha256
                    and spec.version == package.source_revision):
                matches.append((parent, spec))
        if len(matches) != 1:
            raise SchemaDerivationDenied("schema source parent does not uniquely match selected package tree")
        parent, spec = matches[0]
        if not _safe_member(value["source_member_path"]).as_posix():
            raise SchemaDerivationDenied("schema source path is invalid")
        expected = [entry for entry in spec.tree_files
                    if entry.path == value["source_member_path"]
                    and entry.sha256 == value["artifact_sha256"]
                    and entry.size_bytes == value["size_bytes"] and entry.kind == "file"]
        if len(expected) != 1:
            raise SchemaDerivationDenied("schema member path does not belong to the selected package tree")
        source = self.protected_artifact_catalog.materialize_tree(
            parent["artifact_id"], parent["sha256"],
            self.artifact_receipt_registry.artifact_root, expected_uid=self.expected_uid,
        )
        body = _read_regular_member(source.path, value["source_member_path"],
                                    expected_uid=self.expected_uid, maximum=256 * 1024)
        self._verify_child_bytes(value, body)

    def _revalidate_discovery_derivation(self, value: Mapping[str, Any]) -> None:
        resolver = getattr(self.mcp_discovery_registry, "resolve_schema_observation", None)
        if not callable(resolver):
            raise SchemaDerivationPending("authenticated MCP tools/list observation resolver is unavailable")
        raise SchemaDerivationPending(
            "MCP tools/list observation has no typed current-generation verifier contract yet")

    def _verify_child_bytes(self, value: Mapping[str, Any], body: bytes) -> None:
        if (not isinstance(body, bytes) or len(body) != value["size_bytes"]
                or hashlib.sha256(body).hexdigest() != value["artifact_sha256"]):
            raise SchemaDerivationDenied("derived child schema bytes changed")
        spec = self.protected_artifact_catalog._artifact(
            value["artifact_id"], value["artifact_sha256"],
        )
        resolved = self.protected_artifact_catalog.resolve(
            value["artifact_id"], value["artifact_sha256"],
            self.artifact_receipt_registry.artifact_root, expected_uid=self.expected_uid,
        )
        if resolved.size_bytes != value["size_bytes"] or spec.size_bytes != value["size_bytes"]:
            raise SchemaDerivationDenied("derived schema artifact size differs from protected CAS")
        child = _read_regular_member(resolved.path.parent, resolved.path.name,
                                    expected_uid=self.expected_uid, maximum=256 * 1024)
        if body != child:
            raise SchemaDerivationDenied("derived schema bytes differ from immutable artifact CAS")
        try:
            parsed = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_pairs,
                                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
            if _canonical(parsed) != body:
                raise ValueError
        except Exception:
            raise SchemaDerivationDenied("derived schema is not canonical finite JSON") from None

    def _secure_receipt_root(self, *, create: bool) -> Path:
        return self._secure_child_root("schema-derivations", create=create)

    def _secure_observation_root(self, *, create: bool) -> Path:
        return self._secure_child_root("schema-observations", create=create)

    def _secure_child_root(self, name: str, *, create: bool) -> Path:
        root = self.root_journal.path
        try:
            info = root.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != self.expected_uid or stat.S_IMODE(info.st_mode) != 0o700
                    or (info.st_dev, info.st_ino) != (self.root_journal.device, self.root_journal.inode)):
                raise SchemaDerivationDenied("selected root journal custody changed")
            target = root / name
            if create:
                try:
                    target.mkdir(mode=0o700)
                except FileExistsError:
                    pass
            child = target.lstat()
            if (not stat.S_ISDIR(child.st_mode) or stat.S_ISLNK(child.st_mode)
                    or child.st_uid != self.expected_uid or stat.S_IMODE(child.st_mode) != 0o700
                    or child.st_dev != info.st_dev):
                raise SchemaDerivationDenied("schema derivation registry custody is invalid")
            return target
        except SchemaDerivationDenied:
            raise
        except OSError:
            raise SchemaDerivationDenied("schema derivation registry is unavailable") from None

    def _write_root_json(self, path: Path, value: Mapping[str, Any]) -> None:
        self._write_root_bytes(path, _canonical(value))

    def _write_root_bytes(self, path: Path, payload: bytes) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short schema receipt write")
                view = view[written:]
            os.fsync(fd)
        finally:
            os.close(fd)
        dirfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)


def _schema_record(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    fields = {"id", "artifact_id", "sha256", "schema_kind", "native_package_id",
              "native_package_generation", "adapter_id", "action_id", "source_receipt_handle"}
    if not isinstance(raw, Mapping) or set(raw) != fields:
        raise SchemaDerivationDenied("protected schema record has an unsupported shape")
    if (any(not isinstance(raw[key], str) or not _ID.fullmatch(raw[key])
            for key in fields - {"sha256", "schema_kind", "source_receipt_handle"})
            or not isinstance(raw["sha256"], str) or not _SHA.fullmatch(raw["sha256"])
            or not isinstance(raw["source_receipt_handle"], str)
            or not _HANDLE.fullmatch(raw["source_receipt_handle"])
            or raw["schema_kind"] not in {"arguments", "result"}):
        raise SchemaDerivationDenied("protected schema record identity is invalid")
    return MappingProxyType(dict(raw))


def _validate_derivation_record(value: Mapping[str, Any], handle: str) -> None:
    if set(value) != _RECORD_FIELDS or value.get("schema") != 1 or value.get("receipt_handle") != handle:
        raise SchemaDerivationDenied("schema derivation record fields are invalid")
    for name in ("artifact_id", "package_id", "package_generation", "adapter_id", "action_id",
                 "source_observation_handle"):
        if not isinstance(value.get(name), str) or not _ID.fullmatch(value[name]):
            raise SchemaDerivationDenied("schema derivation identity field is invalid")
    if (not isinstance(value.get("artifact_sha256"), str) or not _SHA.fullmatch(value["artifact_sha256"])
            or not isinstance(value.get("service_generation_digest"), str)
            or not _SHA.fullmatch(value["service_generation_digest"])
            or type(value.get("size_bytes")) is not int or not 1 <= value["size_bytes"] <= 256 * 1024
            or value.get("schema_kind") not in {"arguments", "result"}
            or value.get("source_kind") not in {"packaged-schema", "mcp-tools-list"}
            or not isinstance(value.get("parent_receipt_handles"), list)
            or not 1 <= len(value["parent_receipt_handles"]) <= 8
            or any(not isinstance(parent, str) or not _HANDLE.fullmatch(parent)
                   for parent in value["parent_receipt_handles"])
            or len(set(value["parent_receipt_handles"])) != len(value["parent_receipt_handles"])
            or type(value.get("journal_root_device")) is not int
            or type(value.get("journal_root_inode")) is not int
            or value["journal_root_device"] < 0 or value["journal_root_inode"] <= 0
            or not isinstance(value.get("issued_monotonic"), (int, float))
            or isinstance(value.get("issued_monotonic"), bool)
            or not math.isfinite(value["issued_monotonic"])
            or not isinstance(value.get("expires_monotonic"), (int, float))
            or isinstance(value.get("expires_monotonic"), bool)
            or not math.isfinite(value["expires_monotonic"])
            or value["expires_monotonic"] <= value["issued_monotonic"]):
        raise SchemaDerivationDenied("schema derivation receipt value is invalid")
    member = value.get("source_member_path")
    if value["source_kind"] == "packaged-schema":
        if not isinstance(member, str):
            raise SchemaDerivationDenied("packaged schema receipt has no member path")
        _safe_member(member)
    elif member is not None:
        raise SchemaDerivationDenied("discovered schema receipt cannot claim a package member")


def _active_publication_with_parent(parent_handle: str) -> RootSetupPublicationReceipt:
    try:
        receipt = PolicyPublicationReceiptResolver.resolve_current()
    except Exception:
        raise SchemaDerivationPending("no current selected policy publication receipt") from None
    if (type(receipt) is not RootSetupPublicationReceipt
            or receipt.state not in {"prepared", "active"}
            or parent_handle not in receipt.input_receipt_handles):
        raise SchemaDerivationDenied("source parent is not in the current selected publication")
    return receipt


def _active_publication() -> RootSetupPublicationReceipt:
    try:
        receipt = PolicyPublicationReceiptResolver.resolve_current()
    except Exception:
        raise SchemaDerivationPending("no current selected policy publication receipt") from None
    if type(receipt) is not RootSetupPublicationReceipt or receipt.state != "active":
        raise SchemaDerivationPending("active policy generation has not incorporated schema receipts")
    return receipt


def _require_root(expected_uid: int) -> None:
    if os.geteuid() != expected_uid or expected_uid != 0 or not sys_platform_linux():
        raise SchemaDerivationDenied("schema derivation requires the root Linux authority identity")


def sys_platform_linux() -> bool:
    import sys
    return sys.platform.startswith("linux")
