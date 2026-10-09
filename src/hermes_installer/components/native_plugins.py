"""Typed bridge from preserved Plugin resources to reviewed native adapters.

Resource manifests supply identity and declared capabilities only. They never
supply Python callables, endpoints, or credential values. Implementations are
resolved from the installer-owned selected-adapter registry.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
import base64
import binascii
import re
from collections.abc import Mapping


@dataclass(frozen=True, slots=True)
class NativePluginAdapterContract:
    adapter_id: str
    resource_id: str
    component_adapter_id: str | None
    status: str
    blocker: str | None


_PLUGIN_IDS = (
    "agent-live-wallet",
    "agent-sandbox-wallet",
    "agent37-discovery",
    "authentik-authorization",
    "cloudflare-homelab",
    "codex",
    "composio",
    "ebook-toolchain",
    "epic-kanban",
    "financial-data-hub",
    "financial-execution-gateway",
    "github",
    "homelab-ops-broker",
    "kobo-bridge",
    "mcp-registry",
    "resource-overlay-store",
    "voice-pipeline",
    "web",
)

# Plugin resources are source identities from the user's preserved registry,
# not aliases for unrelated seed repositories. A matching source adapter ID is
# attached only after a reviewed one-to-one source crosswalk exists.
NATIVE_PLUGIN_ADAPTERS = tuple(
    NativePluginAdapterContract(
        adapter_id=plugin_id,
        resource_id=plugin_id,
        component_adapter_id=None,
        status="typed-adapter-registry-required",
        blocker="No one-to-one reviewed seed-source crosswalk or registered native handler yet",
    )
    for plugin_id in _PLUGIN_IDS
)
_PLUGIN_BY_ID = {row.adapter_id: row for row in NATIVE_PLUGIN_ADAPTERS}


class NativePluginImplementation(Protocol):
    def register(self, ctx: object, runtime_context: object) -> None:
        """Register only the implementation's fixed reviewed Hermes tools."""


class PluginAdapterRegistry(Protocol):
    def resolve_plugin_adapter(self, adapter_id: str) -> NativePluginImplementation | None:
        """Resolve an implementation from installer-owned reviewed adapters."""


class NativePluginRuntimeContext(Protocol):
    selected_adapters: PluginAdapterRegistry


class NativePluginUnavailable(RuntimeError):
    """A preserved plugin has no reviewed native handler available."""


def resolve_native_plugin_adapter(adapter_id: str) -> NativePluginAdapterContract:
    try:
        return _PLUGIN_BY_ID[adapter_id]
    except (KeyError, TypeError):
        raise KeyError(f"unknown native Plugin adapter ID {adapter_id!r}") from None


def create_native_plugin_handler(adapter_id: str, runtime_context: NativePluginRuntimeContext):
    """Return a native `register(ctx)` closure backed by a typed adapter.

    The registry is installer-owned and accepts implementations, never
    callables declared by imported plugin YAML. Missing implementations fail
    explicitly so resource discovery cannot imply activation.
    """
    contract = resolve_native_plugin_adapter(adapter_id)
    if runtime_context is None or not hasattr(runtime_context, "selected_adapters"):
        raise NativePluginUnavailable(f"{adapter_id}: trusted selected-adapter registry is unavailable")
    implementation = runtime_context.selected_adapters.resolve_plugin_adapter(adapter_id)
    if implementation is None:
        raise NativePluginUnavailable(
            f"{adapter_id}: {contract.blocker}; preserve as discovered/pending until a reviewed adapter is registered"
        )

    def register(ctx: object) -> None:
        implementation.register(ctx, runtime_context)

    return register


# Resource-overlay-store has a native, profile-scoped local implementation.
# Its backup capability intentionally has no registration until lifecycle's
# encrypted-backup API is available.
_RECORD_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_OVERLAY_BYTES = 1_048_576


class ProfileOverlayView(Protocol):
    def read(self, record_id: str): ...
    def write(self, record_id: str, value: bytes, expected_revision: str | None) -> str: ...
    def history(self, record_id: str) -> tuple[str, ...]: ...
    def delete(self, record_id: str, expected_revision: str | None) -> str: ...


def _tool_object(value: object, *, fields: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or set(value) - fields:
        raise ValueError("tool arguments must be an object with only reviewed fields")
    return value


def _record_id(value: object) -> str:
    if not isinstance(value, str) or not _RECORD_ID.fullmatch(value):
        raise ValueError("record_id must be a bounded opaque identifier")
    return value


class ResourceOverlayStoreImplementation:
    """Fixed native tools over an installer-scoped profile overlay view."""

    def register(self, ctx: object, runtime_context: object) -> None:
        view = getattr(runtime_context, "local_overlay_store", None)
        if view is None:
            raise NativePluginUnavailable("resource-overlay-store: selected profile overlay view is unavailable")
        methods = ("read", "write", "history", "delete")
        if any(not callable(getattr(view, method, None)) for method in methods):
            raise NativePluginUnavailable("resource-overlay-store: profile overlay view lacks the reviewed CAS API")
        register_tool = getattr(ctx, "register_tool", None)
        if not callable(register_tool):
            raise NativePluginUnavailable("resource-overlay-store: Hermes PluginContext.register_tool is unavailable")
        read_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}}, "required": ["record_id"], "additionalProperties": False}
        write_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}, "value_base64": {"type": "string", "maxLength": 1398104}, "expected_revision": {"type": ["string", "null"], "maxLength": 64}}, "required": ["record_id", "value_base64"], "additionalProperties": False}
        delete_schema = {"type": "object", "properties": {"record_id": {"type": "string", "maxLength": 128}, "expected_revision": {"type": ["string", "null"], "maxLength": 64}}, "required": ["record_id", "expected_revision"], "additionalProperties": False}

        def read(args: object):
            record_id = _record_id(_tool_object(args, fields=frozenset({"record_id"})).get("record_id"))
            value = view.read(record_id)
            if value is None:
                return {"found": False, "record_id": record_id}
            body = getattr(value, "value", None)
            revision = getattr(value, "revision", None)
            if not isinstance(body, bytes) or len(body) > _MAX_OVERLAY_BYTES or not isinstance(revision, str):
                raise RuntimeError("overlay store returned an invalid bounded value")
            return {"found": True, "record_id": record_id, "value_base64": base64.b64encode(body).decode("ascii"), "revision": revision}

        def write(args: object):
            fields = _tool_object(args, fields=frozenset({"record_id", "value_base64", "expected_revision"}))
            record_id = _record_id(fields.get("record_id"))
            encoded = fields.get("value_base64")
            if not isinstance(encoded, str) or len(encoded) > 1_398_104:
                raise ValueError("value_base64 is missing or exceeds the one MiB decoded limit")
            try:
                body = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                raise ValueError("value_base64 must be canonical base64") from None
            if len(body) > _MAX_OVERLAY_BYTES or base64.b64encode(body).decode("ascii") != encoded:
                raise ValueError("overlay value exceeds one MiB or is not canonical base64")
            expected = fields.get("expected_revision")
            if expected is not None and (not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
                raise ValueError("expected_revision must be a SHA-256 revision or null")
            revision = view.write(record_id, body, expected)
            if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
                raise RuntimeError("overlay store returned an invalid revision")
            return {"record_id": record_id, "revision": revision}

        def history(args: object):
            record_id = _record_id(_tool_object(args, fields=frozenset({"record_id"})).get("record_id"))
            revisions = view.history(record_id)
            if (not isinstance(revisions, tuple) or len(revisions) > 256
                    or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in revisions)):
                raise RuntimeError("overlay store returned invalid version history")
            return {"record_id": record_id, "revisions": list(revisions)}

        def delete(args: object):
            fields = _tool_object(args, fields=frozenset({"record_id", "expected_revision"}))
            record_id = _record_id(fields.get("record_id"))
            expected = fields.get("expected_revision")
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("delete requires the exact current SHA-256 revision")
            tombstone = view.delete(record_id, expected)
            if not isinstance(tombstone, str) or not re.fullmatch(r"[0-9a-f]{64}", tombstone):
                raise RuntimeError("overlay store returned an invalid tombstone revision")
            return {"record_id": record_id, "deleted_revision": tombstone}

        for suffix, schema, handler, description in (
            ("read", read_schema, read, "Read a private overlay from the selected profile."),
            ("write", write_schema, write, "Write a private overlay with optional compare-and-swap revision."),
            ("history", read_schema, history, "Read bounded revision history for a private overlay."),
            ("delete", delete_schema, delete, "Soft-delete a private overlay using its exact current revision."),
        ):
            register_tool(
                name=f"resource_overlay_{suffix}", toolset="resource_overlay_store",
                schema=schema, handler=handler, requires_env=None, is_async=False,
                description=description,
            )


RESOURCE_OVERLAY_STORE_IMPLEMENTATION = ResourceOverlayStoreImplementation()
