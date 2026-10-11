from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_health_observer import RootValidatedNativeHealthResult
from hermes_installer.native_health_fixture import (
    ACTION_ID,
    FIXTURE_ARTIFACT_ID,
    FIXTURE_ID,
    PROVIDER_REQUIRED,
    PROVIDER_ROUTE_CLASS,
    RECORD_ID,
    RESULT_SCHEMA_ID,
    TOOL_NAME,
    fixture_asset_digests,
    read_asset,
    validate_tool_result,
)
from hermes_installer.registry.resources_runtime import ResourceOverlayStore
from hermes_installer.state import Journal, OwnedRoot


class NativeHealthFixtureTests(unittest.TestCase):
    def test_fixture_binds_pinned_local_registration_to_private_provider_request(self):
        recipe = json.loads(read_asset("recipe.json"))
        request = read_asset("request.txt").decode("utf-8")
        seed = read_asset("seed-value.txt")
        self.assertEqual(recipe, {
            "action_id": ACTION_ID,
            "artifact_id": FIXTURE_ARTIFACT_ID,
            "fixture_id": FIXTURE_ID,
            "provider": {
                "additional_budget": 0,
                "required": True,
                "route_class": PROVIDER_ROUTE_CLASS,
            },
            "request_asset": "request.txt",
            "result_schema_asset": "tool-result.schema.json",
            "result_schema_id": RESULT_SCHEMA_ID,
            "result_source_asset": "expected-tool-result.json",
            "schema": 1,
            "seed": {
                "cleanup_policy": "journal-owned-fixture-generation-only",
                "conflict_policy": "deny-preexisting-unowned-record",
                "record_id": RECORD_ID,
                "revision": hashlib.sha256(seed + b"\0").hexdigest(),
                "sha256": hashlib.sha256(seed).hexdigest(),
                "size_bytes": len(seed),
                "source_asset": "seed-value.txt",
            },
            "tool_name": TOOL_NAME,
        })
        self.assertIn('resource_overlay_read exactly once', request)
        self.assertIn(RECORD_ID, request)
        self.assertNotIn("https://", request)
        self.assertNotIn("model", recipe)
        self.assertNotIn("endpoint", recipe)
        expected = json.loads(read_asset("expected-tool-result.json"))
        schema = json.loads(read_asset("tool-result.schema.json"))
        self.assertEqual(schema["additionalProperties"], False)
        self.assertEqual(set(schema["required"]), set(expected))
        self.assertEqual(set(schema["properties"]), set(expected))
        for name, value in expected.items():
            self.assertEqual(schema["properties"][name]["const"], value)
        self.assertEqual(set(fixture_asset_digests()), {
            "request.txt", "seed-value.txt", "expected-tool-result.json",
            "tool-result.schema.json", "recipe.json",
        })

    def test_expected_result_is_observed_from_real_profile_overlay_handler(self):
        seed = b"Hermes native health probe v1: local selected overlay is readable.\n"
        with tempfile.TemporaryDirectory() as temp:
            owned = OwnedRoot(Path(temp) / "installer")
            owned.ensure()
            overlay = ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3")))
            view = overlay.for_profile("health-fixture")
            revision = view.write(RECORD_ID, seed, expected_revision=None)

            class PluginContext:
                def __init__(self):
                    self.handlers = {}

                def register_tool(self, *, name, handler, **_kwargs):
                    self.handlers[name] = handler

            plugin = PluginContext()
            from hermes_installer.components.native_plugins import RESOURCE_OVERLAY_STORE_IMPLEMENTATION
            RESOURCE_OVERLAY_STORE_IMPLEMENTATION.register(
                plugin, SimpleNamespace(local_overlay_store=view),
            )
            actual = plugin.handlers[TOOL_NAME]({"record_id": RECORD_ID})
            self.assertEqual(actual, {
                "found": True,
                "record_id": RECORD_ID,
                "revision": revision,
                "value_base64": base64.b64encode(seed).decode("ascii"),
            })
            self.assertEqual(revision, hashlib.sha256(seed + b"\0").hexdigest())
            result_bytes = json.dumps(actual, ensure_ascii=False, sort_keys=True,
                                      separators=(",", ":"), allow_nan=False).encode("utf-8")
            self.assertEqual(result_bytes, read_asset("expected-tool-result.json").strip())
            validated = validate_tool_result(RESULT_SCHEMA_ID, result_bytes)
            self.assertIs(type(validated), RootValidatedNativeHealthResult)
            self.assertEqual(validated.semantic_outcome, "passed")
            self.assertEqual(validated.result_sha256, hashlib.sha256(result_bytes).hexdigest())

    def test_result_validator_rejects_wrong_schema_data_duplicates_and_noncanonical_bytes(self):
        expected = read_asset("expected-tool-result.json").strip()
        with self.assertRaises(ValueError):
            validate_tool_result("unselected-schema", expected)
        wrong = json.loads(expected)
        wrong["record_id"] = "different-record"
        with self.assertRaisesRegex(ValueError, "differs"):
            validate_tool_result(RESULT_SCHEMA_ID, json.dumps(wrong, sort_keys=True,
                                    separators=(",", ":")).encode())
        duplicate = expected[:-1] + b',"found":false}'
        with self.assertRaisesRegex(ValueError, "strict JSON"):
            validate_tool_result(RESULT_SCHEMA_ID, duplicate)
        with self.assertRaisesRegex(ValueError, "differs"):
            validate_tool_result(RESULT_SCHEMA_ID, expected + b"\n")
        with self.assertRaises(ValueError):
            validate_tool_result(RESULT_SCHEMA_ID, b'{"found":NaN}')


if __name__ == "__main__":
    unittest.main()
