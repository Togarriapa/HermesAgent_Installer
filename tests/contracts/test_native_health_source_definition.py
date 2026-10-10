from __future__ import annotations

import hashlib
import unittest
from pathlib import Path

from hermes_installer.authority.native_health_source import _MEMBERS, _strict_json


REPO = Path(__file__).resolve().parents[2]


class NativeHealthSourceDefinitionContracts(unittest.TestCase):
    def test_exact_source_fixture_set_and_semantics_are_present(self) -> None:
        expected_paths = {
            "hermes-agent-health-fixture-v1": "fixtures/native-health/recipe.json",
            "hermes-agent-health-request-v1": "fixtures/native-health/request.txt",
            "hermes-agent-health-seed-v1": "fixtures/native-health/seed-value.txt",
            "hermes-agent-health-expected-result-v1": "fixtures/native-health/expected-tool-result.json",
            "hermes-agent-health-overlay-read-result-v1": "fixtures/native-health/tool-result.schema.json",
        }
        self.assertEqual({key: row[0] for key, row in _MEMBERS.items()}, expected_paths)
        bodies: dict[str, bytes] = {}
        for artifact_id, (relative, digest, size) in _MEMBERS.items():
            body = (REPO / "src/hermes_installer/native_health_fixture" / relative.rsplit("/", 1)[-1]).read_bytes()
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (size, digest))
            bodies[artifact_id] = body
        recipe = _strict_json(bodies["hermes-agent-health-fixture-v1"])
        self.assertEqual(recipe["fixture_id"], "hermes-agent-health-v1")
        self.assertEqual(recipe["provider"], {
            "additional_budget": 0,
            "required": True,
            "route_class": "private-zero-additional-budget",
        })
        self.assertEqual(recipe["action_id"], "resource-overlay-store:tool:resource_overlay_read")
        schema = _strict_json(bodies["hermes-agent-health-overlay-read-result-v1"])
        result = _strict_json(bodies["hermes-agent-health-expected-result-v1"])
        self.assertEqual(result["record_id"], schema["properties"]["record_id"]["const"])
        self.assertEqual(result["revision"], schema["properties"]["revision"]["const"])
        self.assertEqual(result["value_base64"], schema["properties"]["value_base64"]["const"])

    def test_duplicate_or_nonfinite_json_members_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            _strict_json(b'{"provider":{"required":true,"required":false}}')
        with self.assertRaises(ValueError):
            _strict_json(b'{"revision":NaN}')


if __name__ == "__main__":
    unittest.main()
