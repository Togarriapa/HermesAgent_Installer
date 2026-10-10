"""Fixed v185 source payload schemas for local owner-overlay calls.

The release module containing these definitions is itself source-pinned.  The
hashes below are hashes of canonical JSON schema bytes, not authority tokens;
callers still need the current held release-module receipt and current loaded
invocation source to use them.
"""
from __future__ import annotations

import hashlib
import json
from types import MappingProxyType
from typing import Any, Mapping


INVOCATION_SCHEMA_ID = "native-owner-overlay-invocation-v1"
RESULT_SCHEMA_ID = "native-owner-overlay-result-v1"


def _schema(properties: Mapping[str, Any], required: tuple[str, ...]) -> bytes:
    return json.dumps({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object", "properties": dict(properties),
        "required": list(required), "additionalProperties": False,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


_HANDLE = {"type": "string", "minLength": 32, "maxLength": 128,
           "pattern": "^[A-Za-z0-9_-]{32,128}$"}
_SHA256 = {"type": "string", "minLength": 64, "maxLength": 64,
           "pattern": "^[0-9a-f]{64}$"}
_PARENTS = {"type": "array", "minItems": 1, "maxItems": 64,
            "uniqueItems": True, "items": dict(_HANDLE)}

INVOCATION_SCHEMA_BYTES = _schema({
    "schema": {"const": 1},
    "invocation_handle": dict(_HANDLE),
    "observed_call_handle": dict(_HANDLE),
    "response_observation_handle": dict(_HANDLE),
    "response_receipt_handle": dict(_HANDLE),
    "turn_handle": {"oneOf": [dict(_HANDLE), {"type": "null"}]},
    "native_request_handle": dict(_HANDLE),
    "registration_id": {"type": "string", "enum": [
        "resource-overlay-store:tool:resource_overlay_read",
        "resource-overlay-store:tool:resource_overlay_history",
        "resource-overlay-store:tool:resource_overlay_write",
        "resource-overlay-store:tool:resource_overlay_delete",
    ]},
    "method": {"type": "string", "enum": ["read", "history", "write", "delete"]},
    "arguments_sha256": dict(_SHA256),
    "canonical_arguments_b64": {"type": "string", "minLength": 4, "maxLength": 2800000},
    "parent_source_receipt_handles": dict(_PARENTS),
}, ("schema", "invocation_handle", "observed_call_handle", "response_observation_handle",
    "response_receipt_handle", "turn_handle", "native_request_handle", "registration_id",
    "method", "arguments_sha256", "canonical_arguments_b64", "parent_source_receipt_handles"))

RESULT_SCHEMA_BYTES = _schema({
    "schema": {"const": 1},
    "invocation_handle": dict(_HANDLE),
    "registration_id": {"type": "string", "enum": [
        "resource-overlay-store:tool:resource_overlay_read",
        "resource-overlay-store:tool:resource_overlay_history",
        "resource-overlay-store:tool:resource_overlay_write",
        "resource-overlay-store:tool:resource_overlay_delete",
    ]},
    "result_schema_id": {"type": "string", "const": RESULT_SCHEMA_ID},
    "result_sha256": dict(_SHA256),
    "canonical_result_b64": {"type": "string", "minLength": 4, "maxLength": 2800000},
    "parent_source_receipt_handles": dict(_PARENTS),
}, ("schema", "invocation_handle", "registration_id", "result_schema_id", "result_sha256",
    "canonical_result_b64", "parent_source_receipt_handles"))

INVOCATION_SCHEMA_SHA256 = hashlib.sha256(INVOCATION_SCHEMA_BYTES).hexdigest()
RESULT_SCHEMA_SHA256 = hashlib.sha256(RESULT_SCHEMA_BYTES).hexdigest()


def capture_schema_bytes(schema_id: str) -> bytes:
    """Return one fixed schema body; callers must separately prove its source pin."""
    if schema_id == INVOCATION_SCHEMA_ID:
        return INVOCATION_SCHEMA_BYTES
    if schema_id == RESULT_SCHEMA_ID:
        return RESULT_SCHEMA_BYTES
    raise ValueError("owner-overlay capture schema ID is not selected")


def verify_held_capture_schema(receipt: Any, schema_id: str) -> tuple[bytes, str]:
    """Read and verify the exact release-held module before using its schema.

    This accepts the concrete setup held-release receipt only.  It deliberately
    does not accept a filename, module constant, path or arbitrary object.
    Active issuance must establish its own current loaded/source joins.
    """
    from .bootstrap_runtime_factory import RootReleaseModuleReceipt

    if (type(receipt) is not RootReleaseModuleReceipt
            or receipt.artifact_id != "installer-module:hermes_installer.authority.owner_overlay_capture_schemas"
            or receipt.relative_path != "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py"):
        raise TypeError("owner-overlay capture schema requires its exact held release module")
    source = receipt.read_current()
    expected_schema = capture_schema_bytes(schema_id)
    expected_hash = (INVOCATION_SCHEMA_SHA256 if schema_id == INVOCATION_SCHEMA_ID
                     else RESULT_SCHEMA_SHA256 if schema_id == RESULT_SCHEMA_ID else None)
    if (expected_hash is None or not source or len(source) != receipt.size_bytes
            or hashlib.sha256(source).hexdigest() != receipt.sha256):
        raise ValueError("held owner-overlay capture schema source changed")
    return expected_schema, expected_hash


CAPTURE_SCHEMAS = MappingProxyType({
    INVOCATION_SCHEMA_ID: (INVOCATION_SCHEMA_BYTES, INVOCATION_SCHEMA_SHA256),
    RESULT_SCHEMA_ID: (RESULT_SCHEMA_BYTES, RESULT_SCHEMA_SHA256),
})
