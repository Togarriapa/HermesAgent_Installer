from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest

from hermes_installer.authority.native_worker_generation_schema import NETWORK_ROW_DEFS, validate_row
from hermes_installer.authority.enrollment import _validate_native_worker_generation_rows


def test_runtime_row_schema_adds_only_the_v189_committed_venv_identity():
    root = Path(__file__).resolve().parents[2]
    contract = json.loads((root / "planning/network-row-wire-v184.json").read_text())
    actual = json.loads(json.dumps(NETWORK_ROW_DEFS))
    runtime = actual["native_worker_runtime_record"]
    identity = runtime["properties"].pop("committed_venv_identity")
    runtime["required"].remove("committed_venv_identity")
    assert runtime["properties"].pop("execution_mode") == {
        "const": "native-hermes-cli-module-v1", "type": "string"}
    runtime["required"].remove("execution_mode")
    assert actual == contract["json_schema"]["$defs"]
    assert set(identity["properties"]) == {
        "schema", "identity_kind", "pm_runtime_receipt_handle", "pm_receipt_sha256",
        "pm_generation", "source_commit", "runtime_relative", "runtime_venv_relative",
        "runtime_closure_sha256", "executable_identity_id", "executable_sha256",
        "executable_device", "executable_inode", "executable_uid", "executable_gid",
        "executable_mode",
    }
    assert identity["additionalProperties"] is False


def test_committed_venv_identity_is_closed_and_binds_exact_observed_runtime_token():
    runtime = _sample(NETWORK_ROW_DEFS["native_worker_runtime_record"])
    identity = runtime["committed_venv_identity"]
    validate_row(runtime, "native_worker_runtime_record")
    with pytest.raises(ValueError, match="unknown fields"):
        validate_row({**runtime, "committed_venv_identity":
                      {**identity, "catalog_executable_path": "/usr/bin/python"}},
                     "native_worker_runtime_record")
    with pytest.raises(ValueError, match="required constant"):
        validate_row({**runtime, "committed_venv_identity":
                      {**identity, "executable_identity_id": "arbitrary:python"}},
                     "native_worker_runtime_record")
    with pytest.raises(ValueError, match="required constant"):
        validate_row({**runtime, "execution_mode": "generic-python"},
                     "native_worker_runtime_record")


def test_runtime_row_validator_rejects_open_fields_and_wrong_types():
    row = {
        "schema": 1,
        "id": "network-a",
        "generation": "generation-a",
        "namespace_identity": "namespace-a",
        "worker_enrollment_id": "enrollment-a",
        "worker_profile_id": "profile-a",
        "role": "af-unix",
        "authority_endpoint_id": "endpoint-a",
        "endpoint_root_id": "root-a",
        "endpoint_relative_socket": "authority.sock",
        "endpoint_receipt_handle": "receipt-a",
        "endpoint_receipt_sha256": "a" * 64,
        "policy_artifact_id": "policy-a",
        "policy_sha256": "b" * 64,
    }
    validate_row(row, "native_worker_network_record")
    with pytest.raises(ValueError, match="unknown fields"):
        validate_row({**row, "caller_supplied": True}, "native_worker_network_record")
    with pytest.raises(ValueError, match="wrong JSON type"):
        validate_row({**row, "schema": True}, "native_worker_network_record")
    with pytest.raises(ValueError, match="required constant"):
        validate_row({**row, "role": "tcp"}, "native_worker_network_record")


def _sample(schema, seed="x"):
    if "$ref" in schema:
        return _sample(NETWORK_ROW_DEFS[schema["$ref"].split("/")[-1]], seed)
    if "const" in schema:
        return schema["const"]
    if "enum" in schema:
        return schema["enum"][0]
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = next((item for item in kind if item != "null"), "null")
    if kind == "object":
        return {name: _sample(schema["properties"][name], seed + name[:1])
                for name in schema.get("required", ())}
    if kind == "array":
        count = schema.get("minItems", 0)
        return [_sample(schema["items"], seed + str(index)) for index in range(count)]
    if kind == "string":
        if schema.get("pattern") == "^[0-9a-f]{64}$":
            return "a" * 64
        return seed * max(1, schema.get("minLength", 1))
    if kind == "integer":
        return int(schema.get("minimum", schema.get("exclusiveMinimum", 1)))
    if kind == "number":
        return float(schema.get("exclusiveMinimum", schema.get("minimum", 1))) + 1
    raise AssertionError(f"unsupported fixture schema {schema}")


def test_v184_full_child_digests_and_cross_catalog_links_are_checked():
    network = _sample({"$ref": "#/$defs/native_worker_network_record"})
    active = _sample({"$ref": "#/$defs/active_network_generation_record"})
    runtime = _sample({"$ref": "#/$defs/native_worker_runtime_record"})
    service = {
        "enrollment_id": "enrollment-a", "generation": "service-gen-a",
        "profile_id": "profile-a", "principal_id": "principal-a",
        "namespace_identity": "namespace-a",
    }
    network.update({
        "generation": "service-gen-a", "worker_enrollment_id": "enrollment-a",
        "worker_profile_id": "profile-a", "namespace_identity": "namespace-a",
    })
    runtime.update({
        "generation_id": "container-a", "profile_id": "profile-a",
        "profile_generation": "service-gen-a", "service_enrollment_id": "enrollment-a",
        "recipe_id": active["recipe_id"], "recipe_sha256": active["recipe_sha256"],
        "source_choice_selection_handle": active["source_choice_selection_handle"],
    })
    runtime["committed_venv_identity"]["pm_runtime_receipt_handle"] = runtime["pm_runtime_receipt_handle"]
    active.update({
        "generation_id": "container-a", "service_enrollment_id": "enrollment-a",
        "service_generation": "service-gen-a", "service_row_sha256": _sha(service),
        "process_profile_id": "profile-a", "process_profile_generation": "service-gen-a",
        "network_catalog": "native_worker_network_records", "network_id": network["id"],
        "network_generation": network["generation"], "network_row_sha256": _sha(network),
        "worker_runtime_record_id": runtime["id"],
        "worker_runtime_record_sha256": _sha(runtime),
        "principal_id": "principal-a", "namespace_id": "namespace-a",
    })
    item = {
        "generation_id": "container-a", "service_records": [service],
        "native_worker_network_records": [network],
        "active_network_generation_records": [active],
        "native_worker_runtime_records": [runtime],
    }
    _validate_native_worker_generation_rows(item)
    changed = dict(item)
    changed["native_worker_runtime_records"] = [{**runtime, "pm_executable_member_sha256": "b" * 64}]
    with pytest.raises(ValueError, match="complete child body"):
        _validate_native_worker_generation_rows(changed)


def test_active_network_owner_refuses_unobserved_runtime():
    from hermes_installer.authority.active_network_generation import RootActiveNetworkGenerationOwner
    from hermes_installer.authority.types import AuthorityDenied

    for runtime in (None, object()):
        with pytest.raises(AuthorityDenied):
            RootActiveNetworkGenerationOwner.from_root_runtime(runtime)


def test_active_network_owner_denies_when_v97_policy_has_no_held_release_member():
    from types import SimpleNamespace
    from hermes_installer.authority.active_network_generation import RootActiveNetworkGenerationOwner

    owner = object.__new__(RootActiveNetworkGenerationOwner)
    owner._release = SimpleNamespace(files=())
    with pytest.raises(ValueError, match="exact held installer template member"):
        owner._verify_selected_policy_source({
            "policy_artifact_id": "installer-private-loopback-nft-v1",
            "policy_sha256": "77a48f3a31f115693b04245146158e3c2467f297ff14746a52375850d76237cc",
        })


def _sha(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode()).hexdigest()
