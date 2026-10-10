from __future__ import annotations

import hashlib
import json

from hermes_installer.authority.native_assembler import assemble_native_package
from hermes_installer.authority.native_output_receipts import _verify_payload


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class Selection:
    package_id = "hermes-agent-native-package-v1"
    service_profile_id = "hermes-agent-native-v1"
    resource_profile_id = "basic"
    native_package_generation = "a" * 64
    compiler_artifact_id = "installer-module:hermes_installer.authority.native_materialization"
    compiler_sha256 = "b" * 64
    service_generation = "process-generation-1"


class Member:
    relative_path = "plugins/demo.py"
    sha256 = hashlib.sha256(b"selected adapter bytes").hexdigest()
    size_bytes = len(b"selected adapter bytes")
    mode = 0o644
    artifact_receipt_handle = "root-receipt-handle-demo"


class Definitions:
    adapter_records = ()
    dependency_records = ()
    source_issuer_records = ()
    native_schema_records = ({"schema_id": "schema-demo"},)
    native_schema_bytes = (("schema-demo", b'{"type":"object"}'),)
    action_registration_records = ({"adapter_id": "demo", "action_id": "lookup"},)
    registration_records = ()
    closure_members = (Member(),)
    effect_selection_receipt_handles = ("effect-proof-demo",)
    candidate_records = ({
        "native_tool_name": "demo_lookup",
        "native_server_name": "hermes-installer",
        "description": "Selected demo action",
        "adapter_id": "demo",
        "action_id": "lookup",
        "argument_schema": {"type": "object", "properties": {}},
        "result_schema": {"type": "object", "properties": {}},
        "native_schema_sha256": hashlib.sha256(
            _canonical({"type": "object", "properties": {}})
        ).hexdigest(),
        "observer_enrollment_ids": ("observer-demo",),
        "registration_id": "demo:tool:demo_lookup",
        "toolset": "demo",
        "family": "demo-family",
        "handler_kind": "effect-action",
    },)
    process_role_records = ()
    boundary_overlay_source_commit = "c" * 40
    boundary_overlay_bytes = b""


def test_assembler_compiles_five_consistent_finite_output_documents():
    member = b"selected adapter bytes"
    overlay = {
        "schema": 1,
        "source_commit": Definitions.boundary_overlay_source_commit,
        "compiler_artifact_id": Selection.compiler_artifact_id,
        "compiler_sha256": Selection.compiler_sha256,
        "members": [{"path": Member.relative_path, "sha256": Member.sha256,
                     "size_bytes": Member.size_bytes, "mode": Member.mode}],
    }
    Definitions.boundary_overlay_bytes = _canonical(overlay)
    argument_schema = Definitions.candidate_records[0]["argument_schema"]
    result_schema = Definitions.candidate_records[0]["result_schema"]
    registration = {
        "registration_id": "demo:tool:demo_lookup",
        "native_tool_name": "demo_lookup",
        "native_server_name": "hermes-installer",
        "toolset": "demo",
        "family": "demo-family",
        "adapter_id": "demo",
        "argument_schema": argument_schema,
        "result_schema": result_schema,
        "native_schema_sha256": hashlib.sha256(_canonical(argument_schema)).hexdigest(),
        "registration_source_artifact_id": "demo-source-module",
        "registration_source_sha256": Member.sha256,
        "registration_source_receipt_handle": "source-receipt-demo",
        "handler_kind": "effect-action",
        "handler_id": "demo.lookup",
        "selector_fields": [],
        "action_bindings": [{"selector_values": {}, "action_id": "lookup",
                             "argument_projection": [], "workflow_id": None}],
        "observer_enrollment_ids": ["observer-demo"],
    }
    Definitions.registration_records = (registration,)
    Definitions.process_role_records = ({
        "role_id": "hermes-native-loader",
        "package_id": Selection.package_id,
        "native_package_generation": Selection.native_package_generation,
        "profile_id": Selection.service_profile_id,
        "profile_generation": Selection.service_generation,
        "role_artifact_id": "role:hermes-native-loader",
        "role_sha256": Member.sha256,
        "role_source_receipt_handle": "role-source-receipt-demo",
        "module_name": "hermes_installer.native_plugin_loader",
        "closure_member_path": Member.relative_path,
        "role_source_revision": "d" * 40,
        "role_source_tree_sha256": "e" * 64,
        "observer_enrollment_ids": ["observer-demo"],
        "registration_ids": ["demo:tool:demo_lookup"],
        "action_binding_ids": ["demo:action:lookup"],
        "workflow_ids": [],
    },)
    output = assemble_native_package(Selection(), Definitions(),
                                     {Member.artifact_receipt_handle: member})
    assert output.entrypoint_manifest
    assert output.action_resolver
    assert output.boundary_overlay == Definitions.boundary_overlay_bytes
    assert output.candidate_index
    assert output.compiled_closure
    manifest = json.loads(output.entrypoint_manifest)
    resolver = json.loads(output.action_resolver)
    role_digest = hashlib.sha256(_canonical(list(Definitions.process_role_records))).hexdigest()
    assert manifest["process_role_records"] == list(Definitions.process_role_records)
    assert manifest["process_role_records_sha256"] == role_digest
    assert resolver["process_role_records_sha256"] == role_digest
    assert manifest["resolver_sha256"] == hashlib.sha256(output.action_resolver).hexdigest()
    _verify_payload("native-compiled-closure", "compiled-closure",
                    output.compiled_closure, output.closure_members)
    _verify_payload("native-entrypoint-manifest", "entrypoint-json",
                    output.entrypoint_manifest, (
                        __import__("hermes_installer.authority.native_output_receipts", fromlist=["NativeOutputMember"]).NativeOutputMember(
                            "manifest.json", hashlib.sha256(output.entrypoint_manifest).hexdigest(),
                            len(output.entrypoint_manifest), 0o644),
                    ))
