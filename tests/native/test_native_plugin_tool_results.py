from __future__ import annotations

import unittest
import hashlib
import json
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from hermes_installer.native_plugin_loader import (
    _NativePluginContextResultAdapter,
    _MAX_BACKEND_RESULT_DEPTH,
    _UNSAFE_PLUGIN_RESULT,
    _bounded_backend_tool_result,
    _plugin_tool_result,
)


class NativePluginToolResultTests(unittest.TestCase):
    def test_strings_are_returned_unchanged(self):
        value = "already supported"
        self.assertIs(_plugin_tool_result(value), value)

    def test_json_values_become_canonical_text(self):
        self.assertEqual(_plugin_tool_result({"z": 1, "a": [True, None]}),
                         '{"a":[true,null],"z":1}')
        self.assertEqual(_plugin_tool_result(["a", 2]), '["a",2]')

    def test_supported_multimodal_envelope_is_preserved(self):
        value = {"_multimodal": True, "content": [{"type": "text", "text": "ok"}]}
        self.assertIs(_plugin_tool_result(value), value)

    def test_non_json_and_oversized_values_use_static_safe_error(self):
        self.assertEqual(_plugin_tool_result({"credential": object()}), _UNSAFE_PLUGIN_RESULT)
        self.assertEqual(_plugin_tool_result({"large": "x" * (2 * 1024 * 1024)}), _UNSAFE_PLUGIN_RESULT)
        self.assertEqual(_plugin_tool_result(["x" * 1_100_000, "y" * 1_100_000]),
                         _UNSAFE_PLUGIN_RESULT)

    def test_proxy_preserves_registration_options_and_wraps_handler(self):
        class Context:
            def register_tool(self, **kwargs):
                return kwargs

        handler = lambda _args: {"answer": 42}
        parameters = {"type": "object", "properties": {}, "additionalProperties": False}
        schema = parameters
        digest = hashlib.sha256(json.dumps(
            parameters, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")).hexdigest()
        candidate = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        candidate = candidate.SelectedNativeCandidate(
            "fixture", "fixture-adapter", "fixture.action", MappingProxyType(parameters),
            MappingProxyType({"type": "object"}), digest, (), "hermes-installer", "fixture",
            "fixture-adapter:tool:fixture", "github", "fixture-adapter", "effect-action",
        )

        class Package:
            candidate_rows = ()
            def __init__(self):
                self.candidate_rows = (candidate,)
            def candidate(self, name):
                return next((item for item in self.candidate_rows if item.native_tool_name == name), None)
            def _mark_candidate_registered(self, *_args): pass

        registered = _NativePluginContextResultAdapter(Context(), Package(), "fixture-adapter").register_tool(
            "fixture", "github", schema, handler,
            check_fn="check", requires_env=["FIXTURE"], description="fixture",
            emoji="x", override=True,
        )
        self.assertEqual(registered["check_fn"], "check")
        self.assertEqual(registered["requires_env"], ["FIXTURE"])
        self.assertTrue(registered["override"])
        self.assertEqual(registered["handler"]({}), '{"answer":42}')

    def test_proxy_requires_actual_source_toolset(self):
        from hermes_installer.native_plugin_loader import NativePluginLoadUnavailable

        class Context:
            def register_tool(self, **kwargs):
                return kwargs

        parameters = {"type": "object", "properties": {}, "additionalProperties": False}
        schema = {"name": "fixture", "description": "fixture", "parameters": parameters}
        candidate = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        selected = candidate.SelectedNativeCandidate(
            "fixture", "fixture-adapter", "fixture.action", MappingProxyType(parameters),
            MappingProxyType({"type": "object"}), "a" * 64, (), "hermes-installer", "fixture",
            "fixture-adapter:tool:fixture", "github", "fixture-adapter", "effect-action",
        )

        class Package:
            candidate_rows = (selected,)
            def candidate(self, name):
                return selected if name == "fixture" else None
            def _mark_candidate_registered(self, *_args): pass

        proxy = _NativePluginContextResultAdapter(Context(), Package(), "fixture-adapter")
        with self.assertRaises(NativePluginLoadUnavailable):
            proxy.register_tool("fixture", "hermes-installer", schema, lambda _args: "ok",
                                description="fixture")

    def test_v113_backend_result_is_exact_untrusted_envelope(self):
        import json

        schema_path = (Path(__file__).resolve().parents[2] / "plans/amendments/2026-10-10-"
                       "protected-native-registration-records-v113/"
                       "bounded-native-backend-result-v1.schema.json")
        result_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        result = {"status": "accepted", "receipt": {"id": "opaque", "count": 2}}
        candidate_module = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        for adapter_id, tool_name in (
            ("financial-execution-gateway", "financial_execute_one_order"),
            ("agent-live-wallet", "agent_live_wallet_action"),
            ("agent-sandbox-wallet", "agent_sandbox_wallet_action"),
        ):
            with self.subTest(tool_name=tool_name):
                registration_id = f"{adapter_id}:tool:{tool_name}"
                candidate = candidate_module.SelectedNativeCandidate(
                    tool_name, adapter_id, registration_id, MappingProxyType({"type": "object"}),
                    MappingProxyType(result_schema), "a" * 64, ("observer-fixture",),
                    "hermes-installer", "Protected installer action", registration_id, adapter_id,
                    adapter_id, "finite-selector", "installer-native-bounded-backend-result-v1",
                )
                encoded = _bounded_backend_tool_result(result, candidate)
        self.assertEqual(json.loads(encoded), {
                    "schema": 1, "result_trust": "untrusted-backend-data", "result": result,
                })

    def test_v113_backend_result_accepts_arrays_and_bounds_escaped_serialization(self):
        import json

        schema_path = (Path(__file__).resolve().parents[2] / "plans/amendments/2026-10-10-"
                       "protected-native-registration-records-v113/"
                       "bounded-native-backend-result-v1.schema.json")
        candidate_module = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        candidate = candidate_module.SelectedNativeCandidate(
            "financial_execute_one_order", "financial-execution-gateway",
            "financial-execution-gateway:tool:financial_execute_one_order",
            MappingProxyType({"type": "object"}),
            MappingProxyType(json.loads(schema_path.read_text(encoding="utf-8"))),
            "a" * 64, ("observer-fixture",), "hermes-installer", "Protected installer action",
            "financial-execution-gateway:tool:financial_execute_one_order",
            "finance", "financial-execution-gateway", "finite-selector",
            "installer-native-bounded-backend-result-v1",
        )
        result = [{"leg": 1}, {"leg": 2}]
        self.assertEqual(json.loads(_bounded_backend_tool_result(result, candidate))["result"], result)
        escaped_but_raw_bounded = {"text": "\n" * 1_100_000}
        self.assertEqual(_bounded_backend_tool_result(escaped_but_raw_bounded, candidate),
                         _UNSAFE_PLUGIN_RESULT)

    def test_v113_backend_result_rejects_untrusted_scalars_and_bounds(self):
        import json

        schema_path = (Path(__file__).resolve().parents[2] / "plans/amendments/2026-10-10-"
                       "protected-native-registration-records-v113/"
                       "bounded-native-backend-result-v1.schema.json")
        result_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        candidate_module = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        candidate = candidate_module.SelectedNativeCandidate(
            "agent_live_wallet_action", "agent-live-wallet", "agent-live-wallet:tool:agent_live_wallet_action",
            MappingProxyType({"type": "object"}), MappingProxyType(result_schema), "a" * 64, ("observer-fixture",),
            "hermes-installer", "Protected installer action",
            "agent-live-wallet:tool:agent_live_wallet_action", "agent-live-wallet", "agent-live-wallet",
            "finite-selector", "installer-native-bounded-backend-result-v1",
        )
        too_deep = 0
        for _ in range(_MAX_BACKEND_RESULT_DEPTH + 1):
            too_deep = {"nested": too_deep}
        for invalid in ("backend text", 7, True, None, float("nan"), {"x": object()},
                       {"x": "y" * (2 * 1024 * 1024)}, too_deep):
            self.assertEqual(_bounded_backend_tool_result(invalid, candidate), _UNSAFE_PLUGIN_RESULT)
        self.assertEqual(_bounded_backend_tool_result('{"duplicate":1,"duplicate":2}', candidate),
                         _UNSAFE_PLUGIN_RESULT)
        self.assertEqual(_bounded_backend_tool_result([None] * 65_536, candidate),
                         _UNSAFE_PLUGIN_RESULT)

    def test_proxy_applies_wrapper_only_to_exact_selected_registration_and_schema(self):
        import json

        schema_path = (Path(__file__).resolve().parents[2] / "plans/amendments/2026-10-10-"
                       "protected-native-registration-records-v113/"
                       "bounded-native-backend-result-v1.schema.json")
        result_schema = json.loads(schema_path.read_text(encoding="utf-8"))
        candidate_module = __import__("hermes_installer.native_plugin_loader", fromlist=["SelectedNativeCandidate"])
        adapter_id = "agent-sandbox-wallet"
        name = "agent_sandbox_wallet_action"
        registration_id = f"{adapter_id}:tool:{name}"
        parameters = {"type": "object", "properties": {}, "additionalProperties": False}
        schema = {"name": name, "description": "sandbox", "parameters": parameters}
        candidate = candidate_module.SelectedNativeCandidate(
            name, adapter_id, registration_id, MappingProxyType(parameters),
            MappingProxyType(result_schema), "a" * 64, ("observer-fixture",),
            "hermes-installer", "sandbox", registration_id, adapter_id, adapter_id,
            "finite-selector", "installer-native-bounded-backend-result-v1",
        )

        class Context:
            def register_tool(self, **kwargs):
                return kwargs

        class Package:
            def candidate(self, tool_name):
                return candidate if tool_name == name else None
            def _mark_candidate_registered(self, *_args):
                pass

        adapter = _NativePluginContextResultAdapter(Context(), Package(), adapter_id)
        registered = adapter.register_tool(name, adapter_id, schema,
            lambda _args: {"result": "raw-backend", "schema": 1}, description="sandbox")
        response = json.loads(registered["handler"]({}))
        self.assertEqual(response, {"schema": 1, "result_trust": "untrusted-backend-data",
                                    "result": {"result": "raw-backend", "schema": 1}})


if __name__ == "__main__":
    unittest.main()
