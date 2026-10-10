"""Exact protected enrollment joins for the native MCP tool registration hook."""
import copy
import hashlib
import time
import unittest

from hermes_installer.mcp.native_dispatch import (
    HANDLER_ARTIFACT_ID,
    NativeMCPBindingError,
    NativeMCPRegistrationIndex,
    build_handler,
    schema_sha256,
)
from hermes_installer.mcp.broker import ProtectedMCPService


class NativeMCPRegistrationIndexTests(unittest.TestCase):
    def setUp(self):
        self.schema = {
            "name": "mcp_figma_get_file",
            "description": "Read the selected Figma file",
            "parameters": {
                "type": "object",
                "properties": {"file_key": {"type": "string"}},
                "required": ["file_key"],
            },
        }
        self.handler_digest = hashlib.sha256(b"root-pinned native MCP handler").hexdigest()
        self.record = {
            "id": "mcp-binding-figma-file",
            "profile_id": "primary",
            "process_generation": "worker-generation-1",
            "native_package_id": "native-package-1",
            "native_package_generation": "native-generation-1",
            "native_server_name": "figma-native",
            "native_tool_name": self.schema["name"],
            "native_schema_sha256": schema_sha256(self.schema["parameters"]),
            "mcp_enrollment_id": "figma",
            "mcp_generation": "mcp-generation-1",
            "mcp_tool_name": "get_file",
            "request_schema_id": "mcp-figma-get-file-request-v1",
            "result_schema_id": "mcp-figma-get-file-result-v1",
            "effect_operation": "mcp.request",
            "effect_target": "mcp:figma:http",
            "capability": "mcp:figma:read",
            "recipient": None,
            "scope_bindings": [{
                "argument_field": "file_key",
                "selected_resource_id": "resource-selection-figma-1",
            }],
            "handler_artifact_id": HANDLER_ARTIFACT_ID,
            "handler_artifact_sha256": self.handler_digest,
        }
        self.services = {
            "figma": {
                "id": "figma",
                "channel": "http",
                "allowed_tools": ["get_file"],
                "selection_arguments": {"get_file": ["file_key"]},
            },
        }
        self.index = NativeMCPRegistrationIndex.from_protected_records(
            [self.record], services=self.services,
            mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
            profile_id="primary", process_generation="worker-generation-1",
            native_package_id="native-package-1",
            native_package_generation="native-generation-1",
            handler_artifact_sha256=self.handler_digest,
        )

    def test_exact_name_and_schema_resolve_only_selected_binding(self):
        binding = self.index.resolve(self.schema["name"], self.schema)
        self.assertEqual(binding.mcp_enrollment_id, "figma")
        self.assertEqual(binding.mcp_tool_name, "get_file")
        self.assertEqual(binding.scope_bindings, (("file_key", "resource-selection-figma-1"),))

    def test_joins_the_protected_broker_service_type(self):
        service = ProtectedMCPService(
            service_id="figma", channel="http", allowed_tools=frozenset({"get_file"}),
            transport_binding_id="figma-binding", reviewed_revision="a" * 64,
            selection_arguments={"get_file": ("file_key",)},
        )
        index = NativeMCPRegistrationIndex.from_protected_records(
            [self.record], services={"figma": service},
            mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
            profile_id="primary", process_generation="worker-generation-1",
            native_package_id="native-package-1",
            native_package_generation="native-generation-1",
            handler_artifact_sha256=self.handler_digest,
        )
        self.assertEqual(index.resolve(self.schema["name"], self.schema).id,
                         "mcp-binding-figma-file")

    def test_selected_candidates_use_only_exact_root_schema_catalog_entries(self):
        selected = self.index.selected_candidates({
            self.schema["name"]: self.schema,
            "unselected-native-tool": {"name": "unselected-native-tool"},
        })
        self.assertEqual(len(selected), 1)
        name, schema, registration = selected[0]
        self.assertEqual(name, self.schema["name"])
        self.assertEqual(dict(schema), self.schema)
        self.assertEqual(registration.id, self.record["id"])
        with self.assertRaises(NativeMCPBindingError):
            self.index.selected_candidates({
                self.schema["name"]: {"name": self.schema["name"]},
            })

    def test_handler_uses_lexical_root_binding_and_only_fixed_dispatch_arguments(self):
        from hermes_installer.authority.types import BrokeredEffectResponse, NativeInvocationBinding
        from hermes_installer.native_invocations import (
            _CURRENT_BINDING, _CURRENT_MCP_RESULT, _CURRENT_TOOL_CALL_ID,
            canonical_tool_arguments,
        )

        arguments = {"file_key": "root-selected-file"}
        registration = self.index.resolve(self.schema["name"], self.schema)
        binding = NativeInvocationBinding(
            invocation_handle="i" * 40,
            package_id=registration.native_package_id,
            profile_id=registration.profile_id,
            generation=registration.native_package_generation,
            adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id=registration.id,
            arguments_sha256=hashlib.sha256(canonical_tool_arguments(arguments)).hexdigest(),
            parent_closure_digest="b" * 64,
            expires_monotonic=time.monotonic() + 30,
            binding_sha256="d" * 64,
        )

        class Authority:
            calls = []

            def dispatch_native_mcp(self, handle, canonical_arguments):
                self.calls.append((handle, canonical_arguments))
                return BrokeredEffectResponse(
                    200, b"{\"ok\":true}", {}, "mcp-receipt",
                    source_receipt_handle="h" * 40,
                )

        authority = Authority()
        handler = build_handler(authority, registration)
        token = _CURRENT_BINDING.set(binding)
        call_token = _CURRENT_TOOL_CALL_ID.set("call-1")
        result_token = _CURRENT_MCP_RESULT.set(None)
        try:
            self.assertEqual(handler(arguments), '{"ok":true}')
            self.assertEqual(_CURRENT_MCP_RESULT.get(), (
                registration.native_tool_name, b'{"ok":true}', "h" * 40,
            ))
        finally:
            _CURRENT_MCP_RESULT.reset(result_token)
            _CURRENT_TOOL_CALL_ID.reset(call_token)
            _CURRENT_BINDING.reset(token)
        self.assertEqual(authority.calls, [("i" * 40, canonical_tool_arguments(arguments))])

        wrong_binding = NativeInvocationBinding(
            invocation_handle="j" * 40,
            package_id=registration.native_package_id,
            profile_id=registration.profile_id,
            generation=registration.native_package_generation,
            adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="another-action",
            arguments_sha256=binding.arguments_sha256,
            parent_closure_digest="b" * 64,
            expires_monotonic=time.monotonic() + 30,
            binding_sha256="e" * 64,
        )
        token = _CURRENT_BINDING.set(wrong_binding)
        try:
            with self.assertRaises(PermissionError):
                handler(arguments)
        finally:
            _CURRENT_BINDING.reset(token)
        self.assertEqual(len(authority.calls), 1)

    def test_unknown_name_or_schema_drift_fails_before_registration(self):
        with self.assertRaises(NativeMCPBindingError):
            self.index.resolve("mcp_other_get_file", self.schema)
        changed = copy.deepcopy(self.schema)
        changed["parameters"]["properties"]["file_key"]["description"] = "caller-changed"
        with self.assertRaises(NativeMCPBindingError):
            self.index.resolve(self.schema["name"], changed)
        renamed = copy.deepcopy(self.schema)
        renamed["name"] = "different-native-name"
        with self.assertRaises(NativeMCPBindingError):
            self.index.resolve(self.schema["name"], renamed)

    def test_schema_digest_is_canonical_and_rejects_non_json_numbers(self):
        self.assertEqual(
            schema_sha256({"b": 2, "a": 1}),
            schema_sha256({"a": 1, "b": 2}),
        )
        with self.assertRaises(NativeMCPBindingError):
            schema_sha256({"maximum": float("nan")})

    def test_rejects_stale_generation_and_tool_widening(self):
        for change in (
            lambda row: row.update(process_generation="stale-worker"),
            lambda row: row.update(mcp_generation="stale-mcp-generation"),
            lambda row: row.update(mcp_tool_name="delete_file"),
        ):
            record = copy.deepcopy(self.record)
            change(record)
            with self.subTest(record=record):
                with self.assertRaises(NativeMCPBindingError):
                    NativeMCPRegistrationIndex.from_protected_records(
                        [record], services=self.services,
                        mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
                        profile_id="primary", process_generation="worker-generation-1",
                        native_package_id="native-package-1",
                        native_package_generation="native-generation-1",
                        handler_artifact_sha256=self.handler_digest,
                    )

    def test_rejects_direct_target_recipient_and_handler_artifact_drift(self):
        for field, value in (
            ("effect_target", "https://attacker.example/mcp"),
            ("recipient", "other-account"),
            ("handler_artifact_id", "worker-selected-handler"),
            ("handler_artifact_sha256", "a" * 64),
        ):
            record = copy.deepcopy(self.record)
            record[field] = value
            with self.subTest(field=field):
                with self.assertRaises(NativeMCPBindingError):
                    NativeMCPRegistrationIndex.from_protected_records(
                        [record], services=self.services,
                        mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
                        profile_id="primary", process_generation="worker-generation-1",
                        native_package_id="native-package-1",
                        native_package_generation="native-generation-1",
                        handler_artifact_sha256=self.handler_digest,
                    )

    def test_rejects_duplicate_names_and_unknown_row_fields(self):
        duplicate = copy.deepcopy(self.record)
        duplicate["id"] = "another-id"
        with self.assertRaisesRegex(NativeMCPBindingError, "duplicated"):
            NativeMCPRegistrationIndex.from_protected_records(
                [self.record, duplicate], services=self.services,
                mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
                profile_id="primary", process_generation="worker-generation-1",
                native_package_id="native-package-1",
                native_package_generation="native-generation-1",
                handler_artifact_sha256=self.handler_digest,
            )
        malformed = copy.deepcopy(self.record)
        malformed["endpoint"] = "https://attacker.example"
        with self.assertRaises(NativeMCPBindingError):
            NativeMCPRegistrationIndex.from_protected_records(
                [malformed], services=self.services,
                mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
                profile_id="primary", process_generation="worker-generation-1",
                native_package_id="native-package-1",
                native_package_generation="native-generation-1",
                        handler_artifact_sha256=self.handler_digest,
                    )

    def test_rejects_native_server_name_that_cannot_be_merged_into_hermes(self):
        for name in ("Figma", "../figma", "figma:other"):
            record = copy.deepcopy(self.record)
            record["native_server_name"] = name
            with self.subTest(name=name), self.assertRaises(NativeMCPBindingError):
                NativeMCPRegistrationIndex.from_protected_records(
                    [record], services=self.services,
                    mcp_generation_by_enrollment={"figma": "mcp-generation-1"},
                    profile_id="primary", process_generation="worker-generation-1",
                    native_package_id="native-package-1",
                    native_package_generation="native-generation-1",
                    handler_artifact_sha256=self.handler_digest,
                )


if __name__ == "__main__":
    unittest.main()
