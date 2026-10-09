"""Root-resolved, immutable JSON-schema artifacts for native MCP tools.

Schema bodies are read by artifact ID and digest from the protected CAS and
are tied to a protected source receipt plus the exact selected package/action.
No MCP schema is inferred from a tool name or accepted from worker discovery.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from hermes_installer.authority.types import strict_json_loads
from hermes_installer.mcp.native_dispatch import canonical_json


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FIELDS = frozenset({
    "id", "artifact_id", "sha256", "schema_kind", "native_package_id",
    "native_package_generation", "adapter_id", "action_id", "source_receipt_handle",
})
_MAX_ARTIFACT_BYTES = 256 * 1024
_MAX_SCHEMA_NODES = 16_384
_MAX_SCHEMA_RECORDS = 4096
_MAX_CANDIDATE_INDEX_BYTES = 2 * 1024 * 1024
_SCHEMA_KEYS = frozenset({
    "type", "properties", "required", "additionalProperties", "items", "enum",
    "minimum", "maximum", "minLength", "maxLength", "minItems", "maxItems",
})
_TYPES = frozenset({"object", "array", "string", "integer", "number", "boolean", "null"})


class NativeSchemaCatalogError(ValueError):
    """A protected schema artifact failed identity, source, or schema validation."""


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(child) for child in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(child) for child in value]
    return value


def _validate_schema(value: Any, *, nodes: list[int], depth: int = 0) -> None:
    nodes[0] += 1
    if nodes[0] > _MAX_SCHEMA_NODES or depth > 16 or not isinstance(value, Mapping):
        raise NativeSchemaCatalogError("protected JSON schema exceeds its structural bound")
    if set(value) - _SCHEMA_KEYS:
        raise NativeSchemaCatalogError("protected JSON schema uses an unsupported keyword")
    kind = value.get("type")
    if kind not in _TYPES:
        raise NativeSchemaCatalogError("protected JSON schema type is unsupported")
    if kind == "object":
        properties = value.get("properties", {})
        required = value.get("required", [])
        if (not isinstance(properties, Mapping) or len(properties) > 128
                or not isinstance(required, (list, tuple)) or len(required) > 128
                or any(not isinstance(name, str) for name in required)
                or len(required) != len(set(required))
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name)
                       for name in properties)
                or not set(required).issubset(properties)
                or type(value.get("additionalProperties", False)) is not bool):
            raise NativeSchemaCatalogError("protected object schema fields are malformed")
        for child in properties.values():
            _validate_schema(child, nodes=nodes, depth=depth + 1)
    elif kind == "array":
        if "items" not in value:
            raise NativeSchemaCatalogError("protected array schema has no item schema")
        _validate_schema(value["items"], nodes=nodes, depth=depth + 1)

    for low, high in (("minLength", "maxLength"), ("minItems", "maxItems")):
        if low in value or high in value:
            if kind != ("string" if "Length" in low else "array"):
                raise NativeSchemaCatalogError("protected JSON schema bound does not match its type")
            for bound in (low, high):
                if bound in value and (type(value[bound]) is not int or value[bound] < 0):
                    raise NativeSchemaCatalogError("protected JSON schema size bound is invalid")
            if low in value and high in value and value[low] > value[high]:
                raise NativeSchemaCatalogError("protected JSON schema size range is inverted")
    if "minimum" in value or "maximum" in value:
        if kind not in {"integer", "number"}:
            raise NativeSchemaCatalogError("protected numeric bound does not match its type")
        for bound in ("minimum", "maximum"):
            number = value.get(bound)
            if number is not None and (isinstance(number, bool)
                    or not isinstance(number, (int, float))
                    or isinstance(number, float) and not math.isfinite(number)):
                raise NativeSchemaCatalogError("protected numeric schema bound is invalid")
        if ("minimum" in value and "maximum" in value
                and value["minimum"] > value["maximum"]):
            raise NativeSchemaCatalogError("protected numeric schema range is inverted")
    if "enum" in value:
        choices = value["enum"]
        if (not isinstance(choices, (list, tuple)) or not choices or len(choices) > 256
                or len({canonical_json(choice) for choice in choices}) != len(choices)):
            raise NativeSchemaCatalogError("protected schema enum is invalid")


@dataclass(frozen=True, slots=True)
class NativeSchemaArtifact:
    id: str
    artifact_id: str
    sha256: str
    schema_kind: str
    native_package_id: str
    native_package_generation: str
    adapter_id: str
    action_id: str
    source_receipt_handle: str
    schema: Mapping[str, Any]


class NativeMCPProtectedSchemaCatalog:
    """Finite schema bodies joined to source receipts and package actions.

    ``read_artifact`` and ``verify_source_receipt`` are root-created closures
    over the active artifact catalog and source-observer registry. Their public
    inputs are opaque IDs/digests, never paths or schema JSON supplied by a
    worker.
    """

    def __init__(self, rows: Sequence[NativeSchemaArtifact]) -> None:
        if not isinstance(rows, (tuple, list)) or not 1 <= len(rows) <= _MAX_SCHEMA_RECORDS:
            raise NativeSchemaCatalogError("protected schema artifact catalog is empty or oversized")
        by_id: dict[str, NativeSchemaArtifact] = {}
        for row in rows:
            if not isinstance(row, NativeSchemaArtifact) or row.id in by_id:
                raise NativeSchemaCatalogError("protected schema artifact ID is invalid or duplicated")
            by_id[row.id] = row
        self._by_id = MappingProxyType(by_id)

    @classmethod
    def from_protected_records(
        cls,
        records: Sequence[Mapping[str, Any]],
        *,
        read_artifact: Callable[[str, str], bytes],
        verify_source_receipt: Callable[[str, Mapping[str, str]], bool],
    ) -> "NativeMCPProtectedSchemaCatalog":
        if (not isinstance(records, (tuple, list)) or len(records) > _MAX_SCHEMA_RECORDS
                or not callable(read_artifact) or not callable(verify_source_receipt)):
            raise NativeSchemaCatalogError("protected schema catalog inputs are invalid")
        rows: list[NativeSchemaArtifact] = []
        for raw in records:
            if not isinstance(raw, Mapping) or set(raw) != _FIELDS:
                raise NativeSchemaCatalogError("protected schema artifact row has an unsupported shape")
            for field in ("id", "artifact_id", "native_package_id", "native_package_generation",
                          "adapter_id", "action_id", "source_receipt_handle"):
                value = raw[field]
                if not isinstance(value, str) or not _ID.fullmatch(value):
                    raise NativeSchemaCatalogError(f"protected schema {field} is invalid")
            if raw["schema_kind"] not in {"arguments", "result"}:
                raise NativeSchemaCatalogError("protected schema kind is unsupported")
            digest = raw["sha256"]
            if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
                raise NativeSchemaCatalogError("protected schema artifact digest is invalid")
            identity = {
                "schema_id": raw["id"], "sha256": digest,
                "schema_kind": raw["schema_kind"],
                "native_package_id": raw["native_package_id"],
                "native_package_generation": raw["native_package_generation"],
                "adapter_id": raw["adapter_id"], "action_id": raw["action_id"],
            }
            try:
                if verify_source_receipt(raw["source_receipt_handle"], identity) is not True:
                    raise NativeSchemaCatalogError("protected schema source receipt is not current")
                artifact = read_artifact(raw["artifact_id"], digest)
            except NativeSchemaCatalogError:
                raise
            except Exception:
                raise NativeSchemaCatalogError("protected schema source could not be verified") from None
            if not isinstance(artifact, bytes) or not 1 <= len(artifact) <= _MAX_ARTIFACT_BYTES:
                raise NativeSchemaCatalogError("protected schema artifact is unavailable or oversized")
            if hashlib.sha256(artifact).hexdigest() != digest:
                raise NativeSchemaCatalogError("protected schema artifact digest does not match")
            try:
                parsed = strict_json_loads(artifact.decode("utf-8"))
                canonical = canonical_json(parsed)
            except Exception:
                raise NativeSchemaCatalogError("protected schema artifact is not strict JSON") from None
            if canonical != artifact:
                raise NativeSchemaCatalogError("protected schema artifact is not canonical JSON")
            _validate_schema(parsed, nodes=[0])
            if not isinstance(parsed, Mapping):
                raise NativeSchemaCatalogError("protected schema artifact root is not an object")
            rows.append(NativeSchemaArtifact(
                id=raw["id"], artifact_id=raw["artifact_id"], sha256=digest,
                schema_kind=raw["schema_kind"], native_package_id=raw["native_package_id"],
                native_package_generation=raw["native_package_generation"],
                adapter_id=raw["adapter_id"], action_id=raw["action_id"],
                source_receipt_handle=raw["source_receipt_handle"], schema=_freeze(parsed),
            ))
        return cls(rows)

    def resolve(self, schema_id: str, *, native_package_id: str,
                native_package_generation: str, adapter_id: str,
                action_id: str, schema_kind: str) -> Mapping[str, Any]:
        row = self._by_id.get(schema_id) if isinstance(schema_id, str) else None
        if (row is None or row.native_package_id != native_package_id
                or row.native_package_generation != native_package_generation
                or row.adapter_id != adapter_id or row.action_id != action_id
                or row.schema_kind != schema_kind):
            raise NativeSchemaCatalogError("schema reference is not joined to the selected package action")
        return row.schema

    def __len__(self) -> int:
        return len(self._by_id)


@dataclass(frozen=True, slots=True)
class NativeCandidateIndex:
    """Immutable candidate document compiled for one selected native package."""

    package_id: str
    profile_id: str
    generation: str
    resolver_sha256: str
    candidates: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        for label, value in (("package", self.package_id), ("profile", self.profile_id),
                             ("generation", self.generation)):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise NativeSchemaCatalogError(f"native candidate index {label} identity is invalid")
        if not isinstance(self.resolver_sha256, str) or not _SHA256.fullmatch(self.resolver_sha256):
            raise NativeSchemaCatalogError("native candidate index resolver digest is invalid")
        if not isinstance(self.candidates, tuple) or not 1 <= len(self.candidates) <= 1024:
            raise NativeSchemaCatalogError("native candidate index is empty or oversized")
        try:
            frozen_candidates = tuple(_freeze(_thaw(candidate)) for candidate in self.candidates)
        except Exception:
            raise NativeSchemaCatalogError("native candidate index could not be frozen") from None
        object.__setattr__(self, "candidates", frozen_candidates)
        names: set[str] = set()
        actions: set[tuple[str, str]] = set()
        for candidate in self.candidates:
            expected = {"native_tool_name", "adapter_id", "action_id", "argument_schema",
                        "result_schema", "native_schema_sha256", "observer_enrollment_ids",
                        "native_server_name", "description"}
            if not isinstance(candidate, Mapping) or set(candidate) != expected:
                raise NativeSchemaCatalogError("native candidate row has an unsupported shape")
            name = candidate["native_tool_name"]
            adapter_id, action_id = candidate["adapter_id"], candidate["action_id"]
            server_name, description = candidate["native_server_name"], candidate["description"]
            if (not isinstance(name, str) or not _TOOL_NAME.fullmatch(name)
                    or not isinstance(adapter_id, str) or not _ID.fullmatch(adapter_id)
                    or not isinstance(action_id, str) or not _ID.fullmatch(action_id)
                    or not isinstance(server_name, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", server_name)
                    or not isinstance(description, str) or not description or len(description) > 4096
                    or any(ord(char) < 0x20 for char in description)
                    or name in names or (adapter_id, action_id) in actions):
                raise NativeSchemaCatalogError("native candidate identity is invalid or duplicated")
            names.add(name)
            actions.add((adapter_id, action_id))
            digest = candidate["native_schema_sha256"]
            if (not isinstance(digest, str) or not _SHA256.fullmatch(digest)
                    or hashlib.sha256(canonical_json(_thaw(candidate["argument_schema"]))).hexdigest() != digest):
                raise NativeSchemaCatalogError("native candidate argument schema digest does not match")
            _validate_schema(candidate["argument_schema"], nodes=[0])
            _validate_schema(candidate["result_schema"], nodes=[0])
            observer_ids = candidate["observer_enrollment_ids"]
            if (not isinstance(observer_ids, (tuple, list)) or not 1 <= len(observer_ids) <= 64
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in observer_ids)
                    or len(set(observer_ids)) != len(observer_ids)):
                raise NativeSchemaCatalogError("native candidate observer join is missing or invalid")

    @classmethod
    def from_native_mcp_bindings(
        cls,
        bindings: Sequence[Any],
        schema_catalog: NativeMCPProtectedSchemaCatalog,
        *,
        profile_id: str,
        native_package_id: str,
        native_package_generation: str,
        resolver_sha256: str,
        observer_enrollment_ids_by_action: Mapping[str, Sequence[str]],
    ) -> "NativeCandidateIndex":
        """Compile only exact selected MCP row/schema/observer joins.

        Root composition supplies ``bindings`` from the active protected
        registration index and observer IDs from its loaded package/source
        observer join. Schema IDs resolve through verified CAS records; no
        schema or observer identity is inferred from a tool/server label.
        """
        from hermes_installer.mcp.native_dispatch import HANDLER_ARTIFACT_ID, NativeMCPToolBinding

        if (not isinstance(bindings, (tuple, list)) or not 1 <= len(bindings) <= 1024
                or not isinstance(schema_catalog, NativeMCPProtectedSchemaCatalog)
                or not isinstance(observer_enrollment_ids_by_action, Mapping)):
            raise NativeSchemaCatalogError("native MCP candidate compiler inputs are invalid")
        candidates = []
        for binding in bindings:
            if (type(binding) is not NativeMCPToolBinding
                    or binding.profile_id != profile_id
                    or binding.native_package_id != native_package_id
                    or binding.native_package_generation != native_package_generation
                    or binding.handler_artifact_id != HANDLER_ARTIFACT_ID):
                raise NativeSchemaCatalogError("native MCP candidate differs from selected package identity")
            argument_schema = schema_catalog.resolve(
                binding.request_schema_id, native_package_id=native_package_id,
                native_package_generation=native_package_generation,
                adapter_id=HANDLER_ARTIFACT_ID, action_id=binding.id,
                schema_kind="arguments",
            )
            result_schema = schema_catalog.resolve(
                binding.result_schema_id, native_package_id=native_package_id,
                native_package_generation=native_package_generation,
                adapter_id=HANDLER_ARTIFACT_ID, action_id=binding.id,
                schema_kind="result",
            )
            digest = hashlib.sha256(canonical_json(_thaw(argument_schema))).hexdigest()
            if digest != binding.native_schema_sha256:
                raise NativeSchemaCatalogError("MCP binding argument schema digest differs from protected schema")
            observer_ids = observer_enrollment_ids_by_action.get(binding.id)
            candidate = MappingProxyType({
                "native_tool_name": binding.native_tool_name,
                "native_server_name": binding.native_server_name,
                "description": "Protected installer action",
                "adapter_id": HANDLER_ARTIFACT_ID,
                "action_id": binding.id,
                "argument_schema": argument_schema,
                "result_schema": result_schema,
                "native_schema_sha256": binding.native_schema_sha256,
                "observer_enrollment_ids": tuple(observer_ids) if isinstance(observer_ids, (tuple, list)) else (),
            })
            candidates.append(candidate)
        return cls(native_package_id, profile_id, native_package_generation,
                   resolver_sha256, tuple(candidates))

    def to_bytes(self) -> bytes:
        document = {
            "schema": 1, "package_id": self.package_id, "profile_id": self.profile_id,
            "generation": self.generation, "resolver_sha256": self.resolver_sha256,
            "candidates": [_thaw(candidate) for candidate in self.candidates],
        }
        payload = canonical_json(document)
        if len(payload) > _MAX_CANDIDATE_INDEX_BYTES:
            raise NativeSchemaCatalogError("native candidate index exceeds its artifact bound")
        return payload
