"""Root-selected MCP registrations for Hermes' native in-process tool path.

These records are copied from the active protected service generation. They are
not read from a profile YAML file or from model arguments. The native Hermes
hook uses this index to replace an exact candidate handler only after both its
registered tool name and schema digest match the root enrollment.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Mapping, Sequence


class NativeMCPBindingError(ValueError):
    """The protected MCP-to-Hermes registration join is incomplete or stale."""


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_TOOL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z", re.ASCII)
_SERVER_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ROW_FIELDS = frozenset({
    "id", "profile_id", "process_generation", "native_package_id",
    "native_package_generation", "native_server_name", "native_tool_name", "native_schema_sha256",
    "mcp_enrollment_id", "mcp_generation", "mcp_tool_name", "request_schema_id",
    "result_schema_id", "effect_operation", "effect_target", "capability",
    "recipient", "scope_bindings", "handler_artifact_id", "handler_artifact_sha256",
})
_SCOPE_FIELDS = frozenset({"argument_field", "selected_resource_id"})
HANDLER_ARTIFACT_ID = "hermes-installer.native-mcp-dispatch.v1"
_MAX_BINDINGS = 1024
_MAX_SCOPE_BINDINGS = 64
_MAX_SCHEMA_BYTES = 1_048_576


def canonical_json(value: Any) -> bytes:
    """Canonical bounded JSON used for candidate schema identity."""
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise NativeMCPBindingError("native MCP registration is not canonical JSON") from None
    if len(encoded) > _MAX_SCHEMA_BYTES:
        raise NativeMCPBindingError("native MCP registration exceeds its schema bound")
    return encoded


def schema_sha256(schema: Mapping[str, Any]) -> str:
    if not isinstance(schema, Mapping):
        raise NativeMCPBindingError("native MCP candidate schema is malformed")
    return hashlib.sha256(canonical_json(dict(schema))).hexdigest()


@dataclass(frozen=True, slots=True)
class NativeMCPToolBinding:
    """One protected native-name/schema to selected MCP backend join."""

    id: str
    profile_id: str
    process_generation: str
    native_package_id: str
    native_package_generation: str
    native_server_name: str
    native_tool_name: str
    native_schema_sha256: str
    mcp_enrollment_id: str
    mcp_generation: str
    mcp_tool_name: str
    request_schema_id: str
    result_schema_id: str
    effect_operation: str
    effect_target: str
    capability: str
    recipient: str | None
    scope_bindings: tuple[tuple[str, str], ...]
    handler_artifact_id: str
    handler_artifact_sha256: str
    # Populated only by resolve() from the actual pinned Hermes candidate.
    # It is deliberately absent from root enrollment, which stores its digest.
    native_schema: Mapping[str, Any] | None = None

    @classmethod
    def from_protected_record(cls, raw: Mapping[str, Any]) -> "NativeMCPToolBinding":
        if not isinstance(raw, Mapping) or set(raw) != _ROW_FIELDS:
            raise NativeMCPBindingError("protected native MCP row has an unsupported shape")
        for key in (
            "id", "profile_id", "process_generation", "native_package_id",
            "native_package_generation", "mcp_enrollment_id",
            "mcp_generation", "request_schema_id", "result_schema_id",
            "effect_operation", "effect_target", "capability", "handler_artifact_id",
        ):
            value = raw[key]
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise NativeMCPBindingError(f"protected native MCP {key} is invalid")
        for key in ("native_tool_name", "mcp_tool_name"):
            if not isinstance(raw[key], str) or not _TOOL_NAME.fullmatch(raw[key]):
                raise NativeMCPBindingError(f"protected native MCP {key} is invalid")
        if not isinstance(raw["native_server_name"], str) or not _SERVER_NAME.fullmatch(raw["native_server_name"]):
            raise NativeMCPBindingError("protected native MCP native_server_name is invalid")
        for key in ("native_schema_sha256", "handler_artifact_sha256"):
            if not isinstance(raw[key], str) or not _SHA256.fullmatch(raw[key]):
                raise NativeMCPBindingError(f"protected native MCP {key} is invalid")
        if raw["effect_operation"] not in {"mcp.request", "mcp.stdio"}:
            raise NativeMCPBindingError("native MCP effect operation is not a fixed broker verb")
        if (not isinstance(raw["recipient"], (str, type(None)))
                or (raw["recipient"] is not None and not _ID.fullmatch(raw["recipient"]))):
            raise NativeMCPBindingError("protected native MCP recipient is invalid")
        raw_scopes = raw["scope_bindings"]
        if not isinstance(raw_scopes, list) or not 1 <= len(raw_scopes) <= _MAX_SCOPE_BINDINGS:
            raise NativeMCPBindingError("protected native MCP resource scopes are missing or oversized")
        scopes: list[tuple[str, str]] = []
        seen_fields: set[str] = set()
        for item in raw_scopes:
            if not isinstance(item, Mapping) or set(item) != _SCOPE_FIELDS:
                raise NativeMCPBindingError("protected native MCP resource scope is malformed")
            field_name, selected_id = item["argument_field"], item["selected_resource_id"]
            if (not isinstance(field_name, str) or not _ID.fullmatch(field_name)
                    or not isinstance(selected_id, str) or not _ID.fullmatch(selected_id)
                    or field_name in seen_fields):
                raise NativeMCPBindingError("protected native MCP resource scope is invalid or duplicated")
            scopes.append((field_name, selected_id))
            seen_fields.add(field_name)
        return cls(
            id=raw["id"], profile_id=raw["profile_id"],
            process_generation=raw["process_generation"],
            native_package_id=raw["native_package_id"],
            native_package_generation=raw["native_package_generation"],
            native_server_name=raw["native_server_name"],
            native_tool_name=raw["native_tool_name"],
            native_schema_sha256=raw["native_schema_sha256"],
            mcp_enrollment_id=raw["mcp_enrollment_id"], mcp_generation=raw["mcp_generation"],
            mcp_tool_name=raw["mcp_tool_name"], request_schema_id=raw["request_schema_id"],
            result_schema_id=raw["result_schema_id"], effect_operation=raw["effect_operation"],
            effect_target=raw["effect_target"], capability=raw["capability"],
            recipient=raw["recipient"], scope_bindings=tuple(scopes),
            handler_artifact_id=raw["handler_artifact_id"],
            handler_artifact_sha256=raw["handler_artifact_sha256"],
        )


class NativeMCPRegistrationIndex:
    """Immutable index loaded from one active root-selected generation.

    ``services`` must be the already parsed root enrollment catalog keyed by
    MCP enrollment ID. Each entry is checked against this row's fixed tool,
    transport and selection-argument policy before it can enter the index.
    """

    def __init__(self, bindings: Sequence[NativeMCPToolBinding], *,
                 services: Mapping[str, Any], mcp_generation_by_enrollment: Mapping[str, str],
                 profile_id: str,
                 process_generation: str, native_package_id: str,
                 native_package_generation: str,
                 handler_artifact_sha256: str):
        if (not isinstance(bindings, (tuple, list)) or not bindings
                or len(bindings) > _MAX_BINDINGS or not isinstance(services, Mapping)
                or not isinstance(mcp_generation_by_enrollment, Mapping)):
            raise NativeMCPBindingError("active native MCP binding catalog is empty or oversized")
        for label, value in (("profile", profile_id), ("process generation", process_generation),
                             ("native package", native_package_id),
                             ("native package generation", native_package_generation)):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise NativeMCPBindingError(f"active {label} identity is invalid")
        if not isinstance(handler_artifact_sha256, str) or not _SHA256.fullmatch(handler_artifact_sha256):
            raise NativeMCPBindingError("native MCP handler artifact digest is invalid")
        by_name: dict[str, NativeMCPToolBinding] = {}
        by_id: dict[str, NativeMCPToolBinding] = {}
        for binding in bindings:
            if not isinstance(binding, NativeMCPToolBinding):
                raise NativeMCPBindingError("active MCP binding was not parsed from protected enrollment")
            if (binding.profile_id != profile_id or binding.process_generation != process_generation
                    or binding.native_package_id != native_package_id
                    or binding.native_package_generation != native_package_generation
                    or binding.handler_artifact_id != HANDLER_ARTIFACT_ID
                    or binding.handler_artifact_sha256 != handler_artifact_sha256):
                raise NativeMCPBindingError("native MCP binding differs from the active process or handler artifact")
            if binding.native_tool_name in by_name or binding.id in by_id:
                raise NativeMCPBindingError("native MCP tool name or binding ID is duplicated")
            service = services.get(binding.mcp_enrollment_id)
            self._validate_service_join(binding, service,
                                        mcp_generation_by_enrollment.get(binding.mcp_enrollment_id))
            by_name[binding.native_tool_name] = binding
            by_id[binding.id] = binding
        self.profile_id = profile_id
        self.process_generation = process_generation
        self.native_package_id = native_package_id
        self.native_package_generation = native_package_generation
        self.handler_artifact_sha256 = handler_artifact_sha256
        self._by_name = MappingProxyType(by_name)
        self._by_id = MappingProxyType(by_id)

    @classmethod
    def from_protected_records(cls, records: Sequence[Mapping[str, Any]], **kwargs: Any) -> "NativeMCPRegistrationIndex":
        if not isinstance(records, (tuple, list)) or len(records) > _MAX_BINDINGS:
            raise NativeMCPBindingError("protected native MCP record list is invalid")
        parsed = tuple(NativeMCPToolBinding.from_protected_record(row) for row in records)
        return cls(parsed, **kwargs)

    @staticmethod
    def _validate_service_join(binding: NativeMCPToolBinding, service: Any,
                               selected_generation: Any) -> None:
        # The protected broker catalog uses a frozen dataclass, while enrollment
        # snapshots use strict mappings. Accept only those two root-owned forms.
        if isinstance(service, Mapping):
            service_id = service.get("id", service.get("service_id"))
            channel = service.get("channel")
            allowed = service.get("allowed_tools")
            schemas = service.get("selection_arguments")
        else:
            from .broker import ProtectedMCPService
            if type(service) is not ProtectedMCPService:
                raise NativeMCPBindingError("native MCP row has no matching protected MCP enrollment")
            service_id = service.service_id
            channel = service.channel
            allowed = service.allowed_tools
            schemas = service.selection_arguments
        if service_id != binding.mcp_enrollment_id or selected_generation != binding.mcp_generation:
            raise NativeMCPBindingError("native MCP row references a stale MCP enrollment generation")
        if (not isinstance(allowed, (tuple, list, set, frozenset))
                or binding.mcp_tool_name not in allowed or not isinstance(schemas, Mapping)):
            raise NativeMCPBindingError("native MCP tool is outside its selected service allowlist")
        expected_channel = "http" if binding.effect_operation == "mcp.request" else "stdio"
        if channel != expected_channel:
            raise NativeMCPBindingError("native MCP operation differs from its enrolled transport")
        target = f"mcp:{service_id}:{expected_channel}"
        if binding.effect_target != target or binding.capability != f"mcp:{service_id}:read":
            raise NativeMCPBindingError("native MCP target or capability differs from its protected service")
        if binding.recipient is not None:
            raise NativeMCPBindingError("native MCP reads cannot select a caller-supplied recipient")
        expected_fields = schemas.get(binding.mcp_tool_name)
        if not isinstance(expected_fields, (tuple, list)) or not expected_fields:
            raise NativeMCPBindingError("native MCP tool has no protected resource selection schema")
        bound_fields = {field for field, _resource in binding.scope_bindings}
        if bound_fields != set(expected_fields):
            raise NativeMCPBindingError("native MCP resource binding differs from its selected argument schema")

    def resolve(self, native_tool_name: str, schema: Mapping[str, Any]) -> NativeMCPToolBinding:
        """Return a binding only for the exact name and pinned inputSchema body.

        The protected ``native_schema_sha256`` digest domain is the canonical
        argument schema, not Hermes' surrounding ``name/description/parameters``
        tool-registration object.
        """
        binding = self._by_name.get(native_tool_name)
        if (binding is None or not isinstance(schema, Mapping)
                or schema.get("name") != native_tool_name
                or not isinstance(schema.get("parameters"), Mapping)
                or schema_sha256(schema["parameters"]) != binding.native_schema_sha256):
            raise NativeMCPBindingError("native MCP candidate is unknown or its registered schema changed")
        return replace(binding, native_schema=MappingProxyType(dict(schema)))

    def resolve_action(self, action_id: str) -> NativeMCPToolBinding:
        """Return a protected row by exact action ID for root invocation joins."""
        if not isinstance(action_id, str):
            raise NativeMCPBindingError("native MCP action selector is invalid")
        binding = self._by_id.get(action_id)
        if binding is None:
            raise NativeMCPBindingError("native MCP action is not selected in this generation")
        return binding

    def selected_candidates(self, candidate_schemas: Mapping[str, Mapping[str, Any]]) -> tuple[
            tuple[str, Mapping[str, Any], NativeMCPToolBinding], ...]:
        """Resolve selected tool descriptors from a root-owned schema catalog.

        Candidate schemas are supplied by the trusted package/runtime loader,
        never from worker JSON, Hermes config, or a discovery cache. A missing
        schema leaves that selected tool unavailable. Any present schema for a
        selected tool must match the protected digest or the generation fails
        closed. Non-selected catalog entries are ignored.
        """
        if not isinstance(candidate_schemas, Mapping) or len(candidate_schemas) > _MAX_BINDINGS:
            raise NativeMCPBindingError("root native MCP candidate schema catalog is invalid")
        selected = []
        for name, schema in candidate_schemas.items():
            if name not in self._by_name:
                continue
            registration = self.resolve(name, schema)
            selected.append((name, registration.native_schema, registration))
        return tuple(selected)

    def by_id(self, binding_id: str) -> NativeMCPToolBinding | None:
        return self._by_id.get(binding_id)

    @property
    def bindings(self) -> tuple[NativeMCPToolBinding, ...]:
        """Return the immutable root-selected bindings in stable identity order."""
        return tuple(self._by_id[key] for key in sorted(self._by_id))

    def __len__(self) -> int:
        return len(self._by_id)


def build_handler(authority: Any, registration: NativeMCPToolBinding):
    """Bind a resolved registration to the lexical native invocation helper.

    This does not construct an MCP client or carry an endpoint/credential. The
    helper obtains the active lexical invocation context and performs the one
    fixed root dispatch; it is intentionally imported lazily so source-pinned
    Hermes integration can provide it without a module cycle.
    """
    if registration.native_schema is None:
        raise NativeMCPBindingError("native MCP registration was not resolved against a Hermes candidate")
    from hermes_installer.native_invocations import dispatch_native_mcp_tool_call

    def handler(arguments: Mapping[str, Any]) -> str:
        return dispatch_native_mcp_tool_call(authority, registration, arguments)

    return handler
