"""Closed v184 native worker network generation row schemas and validator."""
from __future__ import annotations

import json
import math
import re
from typing import Any

# Kept as generated, digest-contract data from planning/network-row-wire-v184.json.
NETWORK_ROW_DEFS = json.loads('{"active_network_generation_record":{"additionalProperties":false,"properties":{"generation_id":{"maxLength":256,"minLength":1,"type":"string"},"id":{"maxLength":256,"minLength":1,"type":"string"},"identity_kind":{"enum":["linux-local-owner-v1","authentik-subject-v1"]},"namespace_binding_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"namespace_id":{"maxLength":256,"minLength":1,"type":"string"},"network_catalog":{"const":"native_worker_network_records"},"network_generation":{"maxLength":256,"minLength":1,"type":"string"},"network_id":{"maxLength":256,"minLength":1,"type":"string"},"network_row_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"principal_binding_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"principal_id":{"maxLength":256,"minLength":1,"type":"string"},"process_profile_generation":{"maxLength":256,"minLength":1,"type":"string"},"process_profile_id":{"maxLength":256,"minLength":1,"type":"string"},"process_row_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"recipe_definition_receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"recipe_definition_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"recipe_id":{"maxLength":256,"minLength":1,"type":"string"},"recipe_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"root_journal_generation":{"maxLength":256,"minLength":1,"type":"string"},"root_journal_id":{"maxLength":256,"minLength":1,"type":"string"},"schema":{"const":1,"type":"integer"},"service_enrollment_id":{"maxLength":256,"minLength":1,"type":"string"},"service_generation":{"maxLength":256,"minLength":1,"type":"string"},"service_row_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"source_choice_epoch":{"minimum":1,"type":"integer"},"source_choice_payload_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"source_choice_purpose":{"const":"native-policy-preparation"},"source_choice_revocation_epoch":{"minimum":1,"type":"integer"},"source_choice_selection_handle":{"maxLength":256,"minLength":1,"type":"string"},"source_choice_signed_record_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"source_member_receipt_handles":{"items":{"maxLength":256,"minLength":1,"type":"string"},"maxItems":256,"minItems":1,"type":"array","uniqueItems":true},"source_original_setup_deadline_unix":{"exclusiveMinimum":0,"type":"number"},"worker_runtime_record_id":{"maxLength":256,"minLength":1,"type":"string"},"worker_runtime_record_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"}},"required":["schema","id","generation_id","recipe_id","recipe_sha256","recipe_definition_receipt_handle","recipe_definition_sha256","source_choice_selection_handle","source_choice_purpose","source_choice_signed_record_sha256","source_choice_payload_sha256","source_choice_epoch","source_choice_revocation_epoch","source_original_setup_deadline_unix","source_member_receipt_handles","identity_kind","principal_id","namespace_id","principal_binding_sha256","namespace_binding_sha256","service_enrollment_id","service_generation","service_row_sha256","process_profile_id","process_profile_generation","process_row_sha256","network_catalog","network_id","network_generation","network_row_sha256","root_journal_id","root_journal_generation","worker_runtime_record_id","worker_runtime_record_sha256"],"type":"object"},"native_worker_network_record":{"additionalProperties":false,"properties":{"authority_endpoint_id":{"maxLength":256,"minLength":1,"type":"string"},"endpoint_receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"endpoint_receipt_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"endpoint_relative_socket":{"maxLength":256,"minLength":1,"type":"string"},"endpoint_root_id":{"maxLength":256,"minLength":1,"type":"string"},"generation":{"maxLength":256,"minLength":1,"type":"string"},"id":{"maxLength":256,"minLength":1,"type":"string"},"namespace_identity":{"maxLength":256,"minLength":1,"type":"string"},"policy_artifact_id":{"maxLength":256,"minLength":1,"type":"string"},"policy_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"role":{"const":"af-unix"},"schema":{"const":1,"type":"integer"},"worker_enrollment_id":{"maxLength":256,"minLength":1,"type":"string"},"worker_profile_id":{"maxLength":256,"minLength":1,"type":"string"}},"required":["schema","id","generation","namespace_identity","worker_enrollment_id","worker_profile_id","role","authority_endpoint_id","endpoint_root_id","endpoint_relative_socket","endpoint_receipt_handle","endpoint_receipt_sha256","policy_artifact_id","policy_sha256"],"type":"object"},"native_worker_runtime_record":{"additionalProperties":false,"properties":{"generation_id":{"maxLength":256,"minLength":1,"type":"string"},"hermes_source_artifact_id":{"maxLength":256,"minLength":1,"type":"string"},"hermes_source_receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"hermes_source_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"id":{"maxLength":256,"minLength":1,"type":"string"},"native_output_member_records":{"items":{"$ref":"#/$defs/runtime_member_record"},"maxItems":256,"minItems":1,"type":"array"},"native_package_generation":{"maxLength":256,"minLength":1,"type":"string"},"native_package_id":{"maxLength":256,"minLength":1,"type":"string"},"owned_runtime_root_receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"owned_runtime_root_receipt_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"pm_base_closure_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"pm_executable_member_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"pm_executable_relative_path":{"maxLength":4096,"minLength":1,"type":"string"},"pm_runtime_member_records":{"items":{"$ref":"#/$defs/runtime_member_record"},"maxItems":8192,"minItems":1,"type":"array"},"pm_runtime_receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"profile_generation":{"maxLength":256,"minLength":1,"type":"string"},"profile_id":{"maxLength":256,"minLength":1,"type":"string"},"recipe_id":{"maxLength":256,"minLength":1,"type":"string"},"recipe_sha256":{"pattern":"^[0-9a-f]{64}$","type":"string"},"schema":{"const":1,"type":"integer"},"service_enrollment_id":{"maxLength":256,"minLength":1,"type":"string"},"source_choice_selection_handle":{"maxLength":256,"minLength":1,"type":"string"},"source_definition_member_records":{"items":{"$ref":"#/$defs/runtime_member_record"},"maxItems":256,"minItems":1,"type":"array"},"source_member_receipt_handles":{"items":{"maxLength":256,"minLength":1,"type":"string"},"maxItems":256,"minItems":1,"type":"array","uniqueItems":true}},"required":["schema","id","generation_id","recipe_id","recipe_sha256","source_choice_selection_handle","profile_id","profile_generation","service_enrollment_id","hermes_source_receipt_handle","hermes_source_artifact_id","hermes_source_sha256","pm_runtime_receipt_handle","pm_base_closure_sha256","pm_executable_relative_path","pm_executable_member_sha256","pm_runtime_member_records","native_output_member_records","source_member_receipt_handles","source_definition_member_records","owned_runtime_root_receipt_handle","owned_runtime_root_receipt_sha256","native_package_id","native_package_generation"],"type":"object"},"runtime_member_record":{"additionalProperties":false,"properties":{"artifact_id":{"maxLength":256,"minLength":1,"type":"string"},"device":{"minimum":0,"type":"integer"},"inode":{"minimum":0,"type":"integer"},"kind":{"enum":["regular-file","symlink"]},"link_target":{"maxLength":4096,"type":["string","null"]},"mode":{"minimum":0,"type":"integer"},"output_role":{"enum":[null,"native-compiled-closure","native-entrypoint-manifest","native-action-resolver","native-boundary-overlay","native-candidate-index"],"type":["string","null"]},"owner_gid":{"minimum":0,"type":"integer"},"owner_uid":{"minimum":0,"type":"integer"},"receipt_handle":{"maxLength":256,"minLength":1,"type":"string"},"relative_path":{"maxLength":4096,"minLength":1,"type":"string"},"sha256":{"maxLength":256,"minLength":1,"type":"string"},"size_bytes":{"minimum":0,"type":"integer"}},"required":["artifact_id","receipt_handle","relative_path","kind","sha256","size_bytes","mode","owner_uid","owner_gid","device","inode","link_target","output_role"],"type":"object"}}')


def validate_row(value: Any, definition: str, *, path: str = "row") -> None:
    """Validate the finite Draft 2020-12 subset used by the closed v184 schema."""
    _validate(value, {"$ref": "#/$defs/" + definition}, path)


def _validate(value: Any, schema: dict[str, Any], path: str) -> None:
    reference = schema.get("$ref")
    if reference is not None:
        prefix = "#/$defs/"
        if not isinstance(reference, str) or not reference.startswith(prefix):
            raise ValueError(f"{path} has an unsupported schema reference")
        _validate(value, NETWORK_ROW_DEFS[reference[len(prefix):]], path)
        return
    expected = schema.get("type")
    types = expected if isinstance(expected, list) else [expected]
    if expected is not None:
        valid = False
        for kind in types:
            if kind == "object" and type(value) is dict: valid = True
            elif kind == "array" and type(value) is list: valid = True
            elif kind == "string" and type(value) is str: valid = True
            elif kind == "integer" and type(value) is int: valid = True
            elif kind == "number" and type(value) in (int, float): valid = True
            elif kind == "boolean" and type(value) is bool: valid = True
            elif kind == "null" and value is None: valid = True
        if not valid:
            raise ValueError(f"{path} has the wrong JSON type")
    if "const" in schema and value != schema["const"]:
        raise ValueError(f"{path} differs from its required constant")
    if "enum" in schema and value not in schema["enum"]:
        raise ValueError(f"{path} is outside its finite enum")
    if isinstance(value, dict):
        required = schema.get("required", [])
        properties = schema.get("properties", {})
        if any(name not in value for name in required):
            raise ValueError(f"{path} is missing a required field")
        if schema.get("additionalProperties") is False and set(value) != set(properties) & set(value):
            raise ValueError(f"{path} has unknown fields")
        for name, child in value.items():
            if name in properties:
                _validate(child, properties[name], f"{path}.{name}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 1 << 30):
            raise ValueError(f"{path} has an invalid item count")
        if schema.get("uniqueItems") and len({_canonical(item) for item in value}) != len(value):
            raise ValueError(f"{path} contains duplicate items")
        item_schema = schema.get("items")
        if item_schema:
            for index, child in enumerate(value):
                _validate(child, item_schema, f"{path}[{index}]")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0) or len(value) > schema.get("maxLength", 1 << 30):
            raise ValueError(f"{path} has an invalid length")
        pattern = schema.get("pattern")
        if pattern is not None and not re.fullmatch(pattern, value):
            raise ValueError(f"{path} has an invalid format")
    if type(value) in (int, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} is not a finite JSON number")
        if value < schema.get("minimum", float("-inf")) or value > schema.get("maximum", float("inf")):
            raise ValueError(f"{path} is outside its numeric range")
        if value <= schema.get("exclusiveMinimum", float("-inf")):
            raise ValueError(f"{path} is below its exclusive minimum")
        if value >= schema.get("exclusiveMaximum", float("inf")):
            raise ValueError(f"{path} is above its exclusive maximum")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")
