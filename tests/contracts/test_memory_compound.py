"""Security contracts for fixed memory-compound recipes (SK01, SK-T01)."""
import json
import unittest

from hermes_installer.memory.compound import (
    MemoryRecipeDenied,
    MemoryRecipeUnavailable,
    build_memory_request,
    MemoryRouteRecipe,
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

    def test_openviking_session_recipe_uses_root_session_and_captured_event(self):
        from hermes_installer.memory.compound import validate_step_outcome
        create = build_memory_request(
            provider="openviking", route_id="openviking-session-capture",
            recipe=self.recipe,
            step={"method": "POST", "path_template": "/api/v1/sessions",
                  "body_recipe_id": "openviking-create-owned-session-v1"},
            body={}, scope_bindings=self.scope,
            captures={"new_session_id": "session-root-1"})
        self.assertEqual(create.path, "/api/v1/sessions")
        self.assertEqual(json.loads(create.body), {
            "auto_commit_policy": None, "session_id": "session-root-1", "telemetry": False,
        })
        created = validate_step_outcome(
            route_id="openviking-session-capture", step_id="create", status=200,
            value={"status": "ok", "result": {"session_id": "session-root-1"}},
            expected_session_id="session-root-1")
        self.assertEqual(created.captures, {"session_id": "session-root-1"})
        with self.assertRaises(MemoryRecipeDenied):
            validate_step_outcome(
                route_id="openviking-session-capture", step_id="create", status=200,
                value={"status": "ok", "result": {"session_id": "sibling-session"}},
                expected_session_id="session-root-1")

        append = build_memory_request(
            provider="openviking", route_id="openviking-session-capture",
            recipe=self.recipe,
            step={"method": "POST",
                  "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/messages",
                  "body_recipe_id": "openviking-append-captured-event-v1"},
            body={"content": "synthetic captured fact"}, scope_bindings=self.scope,
            captures={"session_id": "session-root-1"},
            trusted_event={"content": "synthetic captured fact", "role": "user",
                           "source_message_ids": ["source-message-1"]})
        self.assertEqual(append.path, "/api/v1/sessions/session-root-1/messages")
        self.assertEqual(json.loads(append.body), {
            "content": "synthetic captured fact", "role": "user",
            "source_message_ids": ["source-message-1"], "telemetry": False,
        })
        with self.assertRaises(MemoryRecipeDenied):
            build_memory_request(
                provider="openviking", route_id="openviking-session-capture",
                recipe=self.recipe,
                step={"method": "POST",
                      "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/messages",
                      "body_recipe_id": "openviking-append-captured-event-v1"},
                body={"content": "changed"}, scope_bindings=self.scope,
                captures={"session_id": "session-root-1"},
                trusted_event={"content": "synthetic captured fact", "role": "user"})

        with self.assertRaises(MemoryRecipeUnavailable):
            build_memory_request(
                provider="openviking", route_id="openviking-session-capture",
                recipe=self.recipe,
                step={"method": "POST",
                      "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}",
                      "body_recipe_id": "openviking-finalize-private-v1"},
                body={}, scope_bindings=self.scope,
                captures={"session_id": "session-root-1", "finalize_action": "extract"})
        private_scope = {**self.scope, "private_provider_route_ref": "private-route-root"}
        finalize = build_memory_request(
            provider="openviking", route_id="openviking-session-capture",
            recipe=self.recipe,
            step={"method": "POST",
                  "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}",
                  "body_recipe_id": "openviking-finalize-private-v1"},
            body={}, scope_bindings=private_scope,
            captures={"session_id": "session-root-1", "finalize_action": "extract"})
        self.assertEqual(finalize.path, "/api/v1/sessions/session-root-1/extract")
        self.assertEqual(finalize.body, b"{}")

    def test_agentmemory_arbitrary_json_is_not_accepted_as_semantic_success(self):
        from hermes_installer.memory.compound import validate_step_outcome
        with self.assertRaises(MemoryRecipeUnavailable):
            validate_step_outcome(route_id="agentmemory-capture", step_id="capture",
                                  status=201, value={"anything": "looks successful"})

    def test_agentmemory_pinned_results_require_exact_semantic_shapes(self):
        from hermes_installer.memory.compound import validate_step_outcome

        found = validate_step_outcome(
            route_id="agentmemory-search", step_id="search", status=200,
            value={"mode": "compact", "results": [{
                "obsId": "observation-1", "sessionId": "session-1",
                "title": "synthetic fact", "type": "fact", "score": 0.75,
                "timestamp": "2026-10-09T12:00:00Z",
            }]})
        self.assertEqual(found.result, {
            "records": [{"id": "observation-1", "source": "agentmemory",
                         "text": "synthetic fact"}],
        })
        saved = validate_step_outcome(
            route_id="agentmemory-capture", step_id="capture", status=201,
            value={"success": True, "memory": {"id": "memory-1", "title": "synthetic fact"}})
        self.assertEqual(saved.captures, {"memory_id": "memory-1"})
        self.assertEqual(saved.result, {"success": True, "id": "memory-1"})

        invalid_results = [
            {"mode": "full", "results": []},
            {"mode": "compact", "results": [{"obsId": "x"}]},
            {"mode": "compact", "results": [{
                "obsId": "observation-1", "sessionId": "session-1",
                "title": "synthetic fact", "type": "fact", "score": float("nan"),
                "timestamp": "2026-10-09T12:00:00Z",
            }]},
            {"mode": "compact", "results": [{
                "obsId": "observation-1", "sessionId": "session-1",
                "title": "synthetic fact", "type": "fact", "score": 0.5,
                "timestamp": "2026-10-09T12:00:00Z", "sibling_scope": "private",
            }]},
        ]
        for value in invalid_results:
            with self.subTest(value=value), self.assertRaises(MemoryRecipeUnavailable):
                validate_step_outcome(route_id="agentmemory-search", step_id="search",
                                      status=200, value=value)
        for value in ({"success": True, "memory": {"id": "../other"}},
                      {"success": False, "memory": {"id": "memory-1"}},
                      {"success": True, "memory": {}}):
            with self.subTest(value=value), self.assertRaises(MemoryRecipeUnavailable):
                validate_step_outcome(route_id="agentmemory-capture", step_id="capture",
                                      status=201, value=value)

    def test_openviking_find_needs_a_protected_uri_resolver(self):
        with self.assertRaises(MemoryRecipeUnavailable):
            build_memory_request(
                provider="openviking", route_id="openviking-find",
                recipe=self.recipe,
                step={"method": "POST", "path_template": "/api/v1/search/find",
                      "body_recipe_id": "openviking-find-owned-v1"},
                body={"query": "synthetic fact", "limit": 8},
                scope_bindings=self.scope,
            )

    def test_protected_recipe_is_strictly_route_bound(self):
        route = {
            "approved_route_id": "agentmemory-search",
            "backend_variant": "default",
            "steps": [{
                "step_id": "search", "method": "POST",
                "path_template": "/agentmemory/smart-search",
                "body_recipe_id": "agentmemory-search-owned-v1",
                "response_schema_id": "agentmemory-search-result-v1",
                "capture_fields": [], "next_step_id": None,
            }],
            "request_schema_id": "agentmemory-search-request-v1",
            "result_schema_id": "agentmemory-search-result-v1",
            "scope_bindings": {
                "profile_id": "profile-1", "service_generation": "service-gen-1",
                "memory_owner_generation": 1, "backend_project_ref": "project-1",
                "backend_agent_ref": "agent-1", "backend_session_ref": None,
                "private_provider_route_ref": None, "credential_reference_id": "vault-ref-1",
            },
            "credential_reference_id": "vault-ref-1",
            "maximum_seconds": 10, "maximum_bytes": 65536,
        }
        limits = {"whole_compound_timeout_seconds": 60, "request_bytes": 262144}
        parsed = MemoryRouteRecipe.from_protected_record(
            "agentmemory-search", route, backend_variant="default", limits=limits)
        self.assertEqual(parsed.steps[0].path_template, "/agentmemory/smart-search")
        route["steps"][0]["path_template"] = "/agentmemory/export"
        with self.assertRaises(MemoryRecipeDenied):
            MemoryRouteRecipe.from_protected_record(
                "agentmemory-search", route, backend_variant="default", limits=limits)

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
