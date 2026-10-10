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
    _UNSAFE_PLUGIN_RESULT,
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


if __name__ == "__main__":
    unittest.main()
