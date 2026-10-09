"""Source-reviewed immutable RB08 schemas for ebook and Kobo Plugin actions.

The handler digest binds these rows to plugin_documents.py; manifest digests
bind each row to the exact vendored adapter declaration. Root enrollments must
match both digests and every action/schema identifier.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any

from hermes_installer.components.plugin_effects import PluginActionSchema

_PLUGIN_DIR = Path(__file__).resolve().parents[3] / "resources/vendor/hermes-agent-resources-2.3.1/plugins"
_MANIFEST_SHA256 = {
    "ebook-toolchain": "5fedf94c58d32b076af69429c04bd1d71fe83fbfd57e00c175fdd623b955ecff",
    "kobo-bridge": "d7577722c50c6ab5cb2f057084717b9b41d77b315b3f14ca55438160f3d21f30",
}


def _adapter_digest() -> str:
    return sha256((Path(__file__).with_name("plugin_documents.py")).read_bytes()).hexdigest()


PLUGIN_DOCUMENT_ADAPTER_SHA256 = "678255485e6b131ee4eb1db08c30cdc5ec9f258e351bb3632c5721a1126e53d4"


def _freeze(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _obj(properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def _string(maximum: int = 128, minimum: int = 1) -> dict[str, Any]:
    return {"type": "string", "minLength": minimum, "maxLength": maximum,
            "pattern": "^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$"}


def _receipt(*, max_size: int = 2_097_152) -> dict[str, Any]:
    return _obj({
        "artifact_id": _string(),
        "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "size_bytes": {"type": "integer", "minimum": 1, "maximum": max_size},
        "media_type": {"type": "string", "enum": ["application/epub+zip", "application/pdf",
                                                        "application/octet-stream", "text/plain"]},
        "profile_id": _string(), "owner_generation": _string(), "operation_id": _string(),
        "source_receipt_handle": _string(),
        "expires_monotonic": {"type": "number", "minimum": 0},
    }, ["artifact_id", "sha256", "size_bytes", "media_type", "profile_id", "owner_generation",
        "operation_id", "source_receipt_handle", "expires_monotonic"])


def _row(adapter: str, action: str, operation: str, arguments: dict[str, Any],
         result: dict[str, Any], *, committed: bool = False, confirmation: bool = False) -> PluginActionSchema:
    return PluginActionSchema(
        adapter_id=adapter, action_id=action,
        argument_schema_id=f"{adapter}.{action}.arguments.v1",
        result_schema_id=f"{adapter}.{action}.result.v1", operation=operation,
        adapter_sha256=PLUGIN_DOCUMENT_ADAPTER_SHA256,
        argument_schema=_freeze(arguments), result_schema=_freeze(result),
        request_bytes_limit=262_144, response_bytes_limit=2_097_152, deadline_seconds=30.0,
        requires_idempotency=committed, requires_confirmation=confirmation,
        expected_state="committed" if committed else "read-complete")


def _ref() -> dict[str, Any]:
    return _string()


def _build_args() -> dict[str, Any]:
    return _obj({"source_id": _ref(), "format": {"type": "string", "enum": ["epub3", "pdf"]},
                 "title": {"type": "string", "minLength": 1, "maxLength": 256},
                 "recipe_id": _ref()}, ["source_id", "format", "title", "recipe_id"])


def _source_recipe_args() -> dict[str, Any]:
    return _obj({"source_id": _ref(), "recipe_id": _ref()}, ["source_id", "recipe_id"])


def _enrollment_ref() -> dict[str, Any]:
    return {"type": "string", "minLength": 1, "maxLength": 64,
            "pattern": "^[a-z0-9][a-z0-9_-]{0,63}$"}


def _kobo_read_args() -> dict[str, Any]:
    return _obj({"book_id": _ref(), "enrollment_id": _enrollment_ref()}, ["book_id", "enrollment_id"])


def _kobo_deliver_args() -> dict[str, Any]:
    return _obj({"export_id": _ref(), "enrollment_id": _enrollment_ref()}, ["export_id", "enrollment_id"])


def _ebuild_result() -> dict[str, Any]:
    return _obj({"artifact": _receipt(),
                 "validation_status": {"type": "string", "enum": ["valid"]},
                 "validation_report_id": _string()}, ["artifact", "validation_status", "validation_report_id"])


def _inspect_result() -> dict[str, Any]:
    return _obj({"source_id": _ref(), "media_type": {"type": "string", "maxLength": 128},
                 "size_bytes": {"type": "integer", "minimum": 0, "maximum": 2_097_152},
                 "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"}},
                ["source_id", "media_type", "size_bytes", "sha256"])


def _validate_result() -> dict[str, Any]:
    return _obj({"artifact_id": _ref(), "validation_status": {"type": "string", "enum": ["valid"]},
                 "validation_report_id": _string()}, ["artifact_id", "validation_status", "validation_report_id"])


def _read_result() -> dict[str, Any]:
    return _obj({"artifact": _receipt(), "book_id": _ref(), "enrollment_id": _ref(),
                 "provenance_receipt_id": _string()},
                ["artifact", "book_id", "enrollment_id", "provenance_receipt_id"])


def _deliver_result() -> dict[str, Any]:
    return _obj({"delivery_receipt_id": _string(), "export_id": _ref(), "enrollment_id": _ref(),
                 "model_id": _ref(), "generation": _ref(),
                 "sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                 "verified": {"type": "boolean", "enum": [True]}},
                ["delivery_receipt_id", "export_id", "enrollment_id", "model_id", "generation",
                 "sha256", "verified"])


PLUGIN_ACTION_SCHEMAS = MappingProxyType({
    ("ebook-toolchain", "run"): _row("ebook-toolchain", "run", "plugin.ebook-toolchain.run",
        _build_args(), _ebuild_result(), committed=True),
    ("ebook-toolchain", "inspect"): _row("ebook-toolchain", "inspect", "plugin.ebook-toolchain.run",
        _source_recipe_args(), _inspect_result()),
    ("ebook-toolchain", "validate"): _row("ebook-toolchain", "validate", "plugin.ebook-toolchain.run",
        _source_recipe_args(), _validate_result()),
    ("kobo-bridge", "read"): _row("kobo-bridge", "read", "plugin.kobo-bridge.read",
        _kobo_read_args(), _read_result()),
    ("kobo-bridge", "deliver"): _row("kobo-bridge", "deliver", "plugin.kobo-bridge.deliver",
        _kobo_deliver_args(), _deliver_result(), committed=True, confirmation=True),
})


def validate_document_action_pins() -> None:
    """Fail closed if reviewed manifests or adapter source changed without repinning."""
    for adapter_id, expected in _MANIFEST_SHA256.items():
        path = _PLUGIN_DIR / f"{adapter_id}.yaml"
        if sha256(path.read_bytes()).hexdigest() != expected:
            raise RuntimeError(f"vendored {adapter_id} manifest changed; Sol review and repinning are required")
    if _adapter_digest() != PLUGIN_DOCUMENT_ADAPTER_SHA256:
        raise RuntimeError("document adapter digest changed; update the action schema catalog")
