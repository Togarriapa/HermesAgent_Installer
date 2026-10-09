"""Security contracts for fixed memory-compound recipes (SK01, SK-T01)."""
import json
import unittest

from hermes_installer.memory.compound import (
    MemoryRecipeDenied,
    MemoryRecipeUnavailable,
    build_memory_request,
    validate_compound_envelope,
)


class MemoryCompoundTests(unittest.TestCase):
    def setUp(self):
        self.scope = {
            "backend_project_ref": "project-root-owned",
            "backend_agent_ref": "agent-profile-owned",
        }
        self.recipe = {"credential_reference_id": "vault-memory-key"}

    def test_agentmemory_search_serializes_only_content_and_forces_scope(self):
        request = build_memory_request(
            provider="agentmemory", route_id="agentmemory-search",
            recipe=self.recipe,
            step={"method": "POST", "path_template": "/agentmemory/smart-search",
                  "body_recipe_id": "agentmemory-search-owned-v1"},
            body={"query": "synthetic fact", "limit": 8},
            scope_bindings=self.scope,
        )
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.path, "/agentmemory/smart-search")
        self.assertNotIn("authorization", dict(request.headers))
        self.assertEqual(json.loads(request.body), {
            "agentId": "agent-profile-owned", "limit": 8, "project": "project-root-owned",
            "query": "synthetic fact",
        })
        self.assertEqual(request.credential_reference_id, "vault-memory-key")

    def test_agentmemory_rejects_caller_scope_or_unreviewed_capture_fields(self):
        base = dict(provider="agentmemory", route_id="agentmemory-capture",
                    recipe=self.recipe,
                    step={"method": "POST", "path_template": "/agentmemory/remember",
                          "body_recipe_id": "agentmemory-remember-owned-v1"},
                    scope_bindings=self.scope)
        with self.assertRaises(MemoryRecipeDenied):
            build_memory_request(**base, body={"content": "x", "project": "sibling"})
        with self.assertRaises(MemoryRecipeDenied):
            build_memory_request(**base, body={"content": "x", "ttlDays": 30})

    def test_unknown_route_and_openviking_unreviewed_capture_fail_before_effect(self):
        with self.assertRaises(MemoryRecipeUnavailable):
            build_memory_request(
                provider="claude-mem", route_id="claude-worker-capture",
                recipe=self.recipe, step={"method": "POST", "path_template": "/api/memory/save",
                                          "body_recipe_id": "unreviewed"},
                body={"text": "x"}, scope_bindings=self.scope)
        with self.assertRaises(MemoryRecipeUnavailable):
            build_memory_request(
                provider="openviking", route_id="openviking-session-capture",
                recipe=self.recipe,
                step={"method": "POST", "path_template": "/api/v1/sessions",
                      "body_recipe_id": "openviking-create-owned-session-v1"},
                body={"content": "x"}, scope_bindings=self.scope)

    def test_agentmemory_arbitrary_json_is_not_accepted_as_semantic_success(self):
        from hermes_installer.memory.compound import validate_step_outcome
        with self.assertRaises(MemoryRecipeUnavailable):
            validate_step_outcome(route_id="agentmemory-capture", step_id="capture",
                                  status=201, value={"anything": "looks successful"})

    def test_envelope_requires_exact_fields_and_canonical_bytes(self):
        value = {"schema": 1, "handle_id": "handle-1", "generation": "gen-1",
                 "sequence": 1, "compound_job_handle": "job-1", "step_id": "create",
                 "body": {"content": "x"}}
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.assertEqual(validate_compound_envelope(raw), value)
        with self.assertRaises(ValueError):
            validate_compound_envelope(raw + b" ")
        value["url"] = "http://127.0.0.1:1"
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        with self.assertRaises(ValueError):
            validate_compound_envelope(raw)


if __name__ == "__main__":
    unittest.main()
