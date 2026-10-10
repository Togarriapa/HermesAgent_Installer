"""Capture the actual Hermes ``register_tool`` source surface without effects.

This producer invokes only each reviewed implementation's registration method
with an inert context. Captured metadata is source evidence, not an authority
receipt: callers must join source, bounded result-schema and observer receipts
before converting these rows into executable native candidates.
"""
from __future__ import annotations

import hashlib
import inspect
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.components.native_plugins import (
    _PLUGIN_IDS,
    _PLUGIN_VERSIONS,
    resolve_native_plugin_implementation,
)
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
    ReviewedPluginAdapterRegistry,
)


class NativeRegistrationCaptureDenied(ValueError):
    """The pinned component registration surface could not be captured safely."""


@dataclass(frozen=True, slots=True)
class CapturedHermesRegistration:
    adapter_id: str
    native_tool_name: str
    toolset: str
    argument_schema: Mapping[str, Any]
    description: str
    handler_id: str
    handler_module: str
    registration_source_path: str
    registration_source_sha256: str
    native_schema_sha256: str


class _NoEffects:
    def invoke(self, *_args: Any, **_kwargs: Any) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted an effect")


class _NoAuthority:
    def __getattr__(self, _name: str) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted authority access")


class _OverlayFixture:
    def read(self, _record_id: str) -> None:
        return None

    def write(self, _record_id: str, _value: bytes, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay write")

    def history(self, _record_id: str) -> tuple[str, ...]:
        return ()

    def delete(self, _record_id: str, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay delete")


class _CaptureContext:
    def __init__(self, adapter_id: str):
        self.adapter_id = adapter_id
        self.rows: list[CapturedHermesRegistration] = []

    def register_tool(self, *args: Any, **kwargs: Any) -> None:
        if args:
            if len(args) not in {4, 5}:
                raise NativeRegistrationCaptureDenied("Hermes tool registration positional shape is unsupported")
            fields = {"name": args[0], "toolset": args[1], "schema": args[2], "handler": args[3]}
            if len(args) == 5:
                fields["description"] = args[4]
            if set(fields) & set(kwargs):
                raise NativeRegistrationCaptureDenied("Hermes tool registration duplicates a field")
            fields.update(kwargs)
        else:
            fields = dict(kwargs)
        required = {"name", "toolset", "schema", "handler", "description"}
        allowed = required | {"requires_env", "is_async"}
        if set(fields) - allowed or not required.issubset(fields):
            raise NativeRegistrationCaptureDenied("Hermes tool registration has an unreviewed shape")
        name, toolset = fields["name"], fields["toolset"]
        schema, description, handler = fields["schema"], fields["description"], fields["handler"]
        if (not isinstance(name, str) or not name or len(name) > 512
                or not isinstance(toolset, str) or not toolset or len(toolset) > 128
                or not isinstance(schema, Mapping) or schema.get("type") != "object"
                or not isinstance(description, str) or not description
                or not callable(handler) or fields.get("is_async", False) is not False
                or fields.get("requires_env") is not None):
            raise NativeRegistrationCaptureDenied("Hermes tool registration fields are invalid")
        handler_module = getattr(handler, "__module__", None)
        handler_id = getattr(handler, "__qualname__", None)
        if not isinstance(handler_module, str) or not isinstance(handler_id, str):
            raise NativeRegistrationCaptureDenied("captured tool handler has no stable source identity")
        code = getattr(handler, "__code__", None)
        source_filename = getattr(code, "co_filename", None)
        if not isinstance(source_filename, str):
            source_filename = inspect.getsourcefile(handler)
        source_path = _relative_component_path(source_filename)
        source_bytes = (Path(__file__).resolve().parents[2] / source_path).read_bytes()
        plain_schema = json.loads(json.dumps(schema, sort_keys=True, ensure_ascii=False, allow_nan=False))
        schema_bytes = _canonical(plain_schema)
        self.rows.append(CapturedHermesRegistration(
            self.adapter_id, name, toolset, plain_schema, description,
            handler_id, handler_module, source_path,
            hashlib.sha256(source_bytes).hexdigest(),
            hashlib.sha256(schema_bytes).hexdigest(),
        ))


def capture_actual_hermes_registrations() -> tuple[CapturedHermesRegistration, ...]:
    """Run all 18 implementation registration methods with an effect-denying context.

    The returned projection reflects actual ``PluginContext.register_tool``
    calls. It deliberately lacks result schemas, source receipt handles, and
    observer enrollment IDs, so it cannot itself qualify a candidate index.
    """
    result: list[CapturedHermesRegistration] = []
    identity_digest = "0" * 64
    for adapter_id in _PLUGIN_IDS:
        implementation = resolve_native_plugin_implementation(adapter_id)
        if implementation is None or not callable(getattr(implementation, "register", None)):
            raise NativeRegistrationCaptureDenied("one reviewed native plugin has no registration implementation")
        identity = ResourceIdentity(
            adapter_id, "plugins", _PLUGIN_VERSIONS[adapter_id],
            f"plugins/{adapter_id}.yaml", "source-capture", identity_digest,
        )
        runtime = NativePluginRuntimeContext(
            identity=identity, declared_capabilities=(), authority=_NoAuthority(),
            invocation_contexts=lambda **_kwargs: (),
            selected_adapters=ReviewedPluginAdapterRegistry(),
            plugin_effects=_NoEffects(), local_overlay_store=_OverlayFixture(),
            voice_session_enrollment_id="capture-only-voice-session",
        )
        context = _CaptureContext(adapter_id)
        try:
            implementation.register(context, runtime)
        except NativeRegistrationCaptureDenied:
            raise
        except Exception as exc:
            raise NativeRegistrationCaptureDenied(
                f"source registration capture failed for {adapter_id}: {type(exc).__name__}"
            ) from None
        if not context.rows:
            raise NativeRegistrationCaptureDenied("native plugin registered no Hermes tools")
        result.extend(context.rows)
    names = [row.native_tool_name for row in result]
    if len(names) != len(set(names)):
        raise NativeRegistrationCaptureDenied("actual Hermes registration names collide")
    return tuple(sorted(result, key=lambda row: row.native_tool_name))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _relative_component_path(filename: str | None) -> str:
    if not isinstance(filename, str):
        raise NativeRegistrationCaptureDenied("registration source path is unavailable")
    root = Path(__file__).resolve().parents[2]
    try:
        relative = Path(filename).resolve(strict=True).relative_to(root).as_posix()
    except (OSError, ValueError):
        raise NativeRegistrationCaptureDenied("registration source is outside the installed component root") from None
    if not relative.startswith("hermes_installer/components/"):
        raise NativeRegistrationCaptureDenied("registration source is outside the reviewed component modules")
    return relative
