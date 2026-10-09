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

    def test_doctor_routes_keep_liveness_distinct_from_subsystem_readiness(self):
        from hermes_installer.memory.compound import validate_step_outcome

        ready = build_memory_request(
            provider="openviking", route_id="openviking-ready", recipe=self.recipe,
            step={"method": "GET", "path_template": "/ready",
                  "body_recipe_id": "openviking-ready-empty-v1"},
            body={}, scope_bindings=self.scope)
        self.assertEqual(ready.method, "GET")
        self.assertEqual(ready.path, "/ready")
        self.assertEqual(ready.body, b"")
        self.assertEqual(ready.headers, (("accept", "application/json"),))
        probe = validate_step_outcome(
            route_id="openviking-ready", step_id="ready", status=200,
            value={"status": "ready", "checks": {
                "agfs": {"status": "ok", "checks": {
                    "filesystem": "ok", "multiwrite_sync": "not_supported"}},
                "vectordb": "not_configured", "api_key_manager": "ok",
                "embedding": "ok", "ollama": "not_configured",
            }})
        self.assertIs(probe.result["service_ready"], True)
        self.assertNotIn("functional_memory_verified", probe.result)
        for invalid in (
            {"status": "ok", "healthy": True, "checks": {}},
            {"status": "ready", "checks": {"agfs": "ok"}},
            {"status": "ready", "checks": {
                "agfs": "ok", "vectordb": "ok", "api_key_manager": "ok",
                "embedding": "not_initialized", "ollama": "ok"}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(MemoryRecipeUnavailable):
                validate_step_outcome(route_id="openviking-ready", step_id="ready",
                                      status=200, value=invalid)

        live = build_memory_request(
            provider="agentmemory", route_id="agentmemory-ready", recipe=self.recipe,
            step={"method": "GET", "path_template": "/agentmemory/livez",
                  "body_recipe_id": "agentmemory-livez-empty-v1"},
            body={}, scope_bindings=self.scope)
        self.assertEqual((live.method, live.path, live.body),
                         ("GET", "/agentmemory/livez", b""))
        liveness = validate_step_outcome(
            route_id="agentmemory-ready", step_id="livez", status=200,
            value={"status": "ok", "service": "agentmemory", "viewerPort": None,
                   "viewerSkipped": True, "streamsPort": 3112})
        self.assertIs(liveness.result["service_live"], True)
        self.assertIs(liveness.result["memory_ready"], False)
        self.assertNotIn("service_ready", liveness.result)
        for invalid in (
            {"status": "critical", "service": "agentmemory", "viewerPort": None,
             "viewerSkipped": True, "streamsPort": 3112},
            {"status": "ok", "service": "agentmemory", "viewerPort": None,
             "viewerSkipped": True, "streamsPort": 3112, "healthy": True},
            {"status": "ok", "service": "agentmemory", "viewerPort": None,
             "viewerSkipped": "true", "streamsPort": 3112},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(MemoryRecipeUnavailable):
                validate_step_outcome(route_id="agentmemory-ready", step_id="livez",
                                      status=200, value=invalid)

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

    def test_openviking_find_arbitrary_json_is_not_a_semantic_result(self):
        from hermes_installer.memory.compound import validate_step_outcome
        with self.assertRaises(MemoryRecipeUnavailable):
            validate_step_outcome(
                route_id="openviking-find", step_id="find", status=200,
                value={"status": "ok", "result": {"anything": "accepted"}})

    def test_openviking_find_uses_authenticated_home_alias_and_memory_only(self):
        request = build_memory_request(
            provider="openviking", route_id="openviking-find",
            recipe=self.recipe,
            step={"method": "POST", "path_template": "/api/v1/search/find",
                  "body_recipe_id": "openviking-find-owned-v1"},
            body={"query": "synthetic fact", "limit": 8},
            scope_bindings=self.scope,
        )
        self.assertEqual(json.loads(request.body), {
            "context_type": "memory", "limit": 8, "query": "synthetic fact",
            "read_content": False, "target_uri": "viking://~/memories", "telemetry": False,
        })

    def test_openviking_find_accepts_only_bounded_authenticated_memory_hits(self):
        from hermes_installer.memory.compound import validate_step_outcome
        found = validate_step_outcome(
            route_id="openviking-find", step_id="find", status=200,
            value={"status": "ok", "result": {
                "memories": [{"uri": "viking://user/agent-profile-owned/memories/fact-1",
                              "context_type": "memory", "level": 0,
                              "abstract": "synthetic fact", "overview": None,
                              "category": "", "score": 0.12, "match_reason": ""}],
                "resources": [], "skills": [], "total": 1,
            }},
            scope_bindings=self.scope,
        )
        self.assertEqual(found.result, {"records": [{
            "id": "viking://user/agent-profile-owned/memories/fact-1",
            "source": "openviking", "text": "synthetic fact",
        }]})
        invalid = [
            {"uri": "viking://user/sibling/memories/fact-1", "context_type": "memory",
             "level": 0, "abstract": "private", "overview": None, "category": "",
             "score": 0.5, "match_reason": ""},
            {"uri": "viking://user/agent-profile-owned/resources/fact-1", "context_type": "resource",
             "level": 0, "abstract": "resource", "overview": None, "category": "",
             "score": 0.5, "match_reason": ""},
            {"uri": "viking://user/agent-profile-owned/memories/fact-1", "context_type": "memory",
             "level": 0, "abstract": "private", "overview": None, "category": "",
             "score": 0.5, "match_reason": "", "content": "full content"},
        ]
        for hit in invalid:
            with self.subTest(hit=hit), self.assertRaises(MemoryRecipeUnavailable):
                validate_step_outcome(
                    route_id="openviking-find", step_id="find", status=200,
                    value={"status": "ok", "result": {
                        "memories": [hit], "resources": [], "skills": [], "total": 1,
                    }},
                    scope_bindings=self.scope,
                )
        with self.assertRaises(MemoryRecipeUnavailable):
            validate_step_outcome(
                route_id="openviking-find", step_id="find", status=200,
                value={"status": "ok", "result": {
                    "memories": [], "resources": [{"uri": "viking://resources/x"}],
                    "skills": [], "total": 0,
                }}, scope_bindings=self.scope)

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

    def test_memory_enrollment_joins_each_route_to_compound_scope(self):
        from hermes_installer.memory.enrollment import (
            MemoryEnrollmentError, MemoryServiceEnrollment, SOURCE_PINS,
        )

        scope_bindings = {
            "profile_id": "profile-1", "service_generation": "service-gen-1",
            "memory_owner_generation": 1, "backend_project_ref": "project-1",
            "backend_agent_ref": "profile-1", "backend_session_ref": None,
            "private_provider_route_ref": None, "credential_reference_id": "vault-ref-1",
        }
        route = {
            "approved_route_id": "agentmemory-search", "backend_variant": "default",
            "steps": [{
                "step_id": "search", "method": "POST",
                "path_template": "/agentmemory/smart-search",
                "body_recipe_id": "agentmemory-search-owned-v1",
                "response_schema_id": "agentmemory-search-result-v1",
                "capture_fields": [], "next_step_id": None,
            }],
            "request_schema_id": "agentmemory-search-request-v1",
            "result_schema_id": "agentmemory-search-result-v1",
            "scope_bindings": scope_bindings,
            "credential_reference_id": "vault-ref-1",
            "maximum_seconds": 10, "maximum_bytes": 65536,
        }
        record = {
            "target_id": "memory-agentmemory:profile-1", "provider": "agentmemory",
            "backend_variant": "default", "profile_id": "profile-1",
            "principal_id": "principal-1", "service_enrollment_id": "service-1",
            "source_revision": SOURCE_PINS["agentmemory"],
            "service_generation": "service-gen-1", "namespace_identity": "ns-1",
            "literal_loopback_port": 3111, "fixed_route_map": {"agentmemory-search": route},
            "data_root_id": "data-1", "auth_reference_id": "vault-ref-1",
            "authority_state_root_id": "authority-root-1",
            "fixed_project_account_user_scope": {
                "project_id": "project-1", "account_id": "account-1", "user_id": "profile-1",
            },
            "memory_owner_generation": 1,
            "private_extraction_embedding_routes": {
                "extract": "private-extract-1", "embed": "private-embed-1",
            },
            "background_consent_revision": "consent-policy-1",
            "limits": {
                "request_bytes": 262144, "response_bytes": 2097152, "result_limit": 100,
                "operation_timeout_seconds": 15, "whole_compound_timeout_seconds": 60,
            },
        }
        enrollment = MemoryServiceEnrollment.from_protected_record(record)
        self.assertEqual(enrollment.fixed_route_map["agentmemory-search"].steps[0].step_id, "search")

        mismatched = json.loads(json.dumps(record))
        mismatched["fixed_route_map"]["agentmemory-search"]["scope_bindings"]["backend_project_ref"] = "sibling-project"
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(mismatched)

        legacy = json.loads(json.dumps(record))
        legacy["fixed_route_map"]["agentmemory-search"] = {
            "method": "POST", "path": "/agentmemory/smart-search", "body": "json",
        }
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(legacy)

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
