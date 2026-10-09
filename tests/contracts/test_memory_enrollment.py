"""Strict source and compound-recipe enrollment tests (SK01, SK-T01)."""
import unittest

from hermes_installer.memory.broker import MemoryTarget
from hermes_installer.memory.enrollment import (
    MemoryEnrollmentError, MemoryServiceEnrollment, ROUTES, SOURCE_PINS,
)


def recipe(provider, route_id):
    variant = "default"
    scope = {
        "profile_id": "profile-one", "service_generation": "service-gen-7",
        "memory_owner_generation": 4, "backend_project_ref": "project-one",
        "backend_agent_ref": "profile-one", "backend_session_ref": None,
        "private_provider_route_ref": "private-extract-one",
        "credential_reference_id": f"memory-auth-{provider}-one",
    }
    rows = {
        "agentmemory-search": (
            "agentmemory-search-request-v1", "agentmemory-search-result-v1",
            [{"step_id": "search", "method": "POST", "path_template": "/agentmemory/smart-search",
              "body_recipe_id": "agentmemory-search-owned-v1",
              "response_schema_id": "agentmemory-search-result-v1", "capture_fields": [], "next_step_id": None}],
        ),
        "agentmemory-capture": (
            "agentmemory-capture-request-v1", "agentmemory-remember-result-v1",
            [{"step_id": "capture", "method": "POST", "path_template": "/agentmemory/remember",
              "body_recipe_id": "agentmemory-remember-owned-v1",
              "response_schema_id": "agentmemory-remember-result-v1", "capture_fields": [], "next_step_id": None}],
        ),
        "openviking-session-capture": (
            "openviking-capture-event-v1", "openviking-capture-result-v1",
            [
                {"step_id": "create", "method": "POST", "path_template": "/api/v1/sessions",
                 "body_recipe_id": "openviking-create-owned-session-v1",
                 "response_schema_id": "openviking-create-result-v1", "capture_fields": ["session_id"], "next_step_id": "append"},
                {"step_id": "append", "method": "POST", "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/messages",
                 "body_recipe_id": "openviking-append-captured-event-v1",
                 "response_schema_id": "openviking-append-result-v1", "capture_fields": [], "next_step_id": "finalize"},
                {"step_id": "finalize", "method": "POST", "path_template": "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}",
                 "body_recipe_id": "openviking-finalize-private-v1",
                 "response_schema_id": "openviking-finalize-result-v1", "capture_fields": [], "next_step_id": None},
            ],
        ),
    }
    request_schema, result_schema, steps = rows[route_id]
    return {
        "approved_route_id": route_id, "backend_variant": variant, "steps": steps,
        "request_schema_id": request_schema, "result_schema_id": result_schema,
        "scope_bindings": scope, "credential_reference_id": scope["credential_reference_id"],
        "maximum_seconds": 15, "maximum_bytes": 262144,
    }


def record(provider="agentmemory", variant="default", port=3111):
    if provider == "agentmemory":
        route_ids = ("agentmemory-search", "agentmemory-capture")
    elif provider == "openviking":
        route_ids = ("openviking-session-capture",)
    else:
        route_ids = ("claude-sqlite-search",) if variant == "server-v1-sqlite" else (
            "claude-postgres-search",)
    fixed_routes = {}
    for route_id in route_ids:
        if provider == "claude-mem":
            route = ROUTES[provider][variant][route_id]
            fixed_routes[route_id] = {"method": route.method, "path": route.path, "body": route.body}
        else:
            fixed_routes[route_id] = recipe(provider, route_id)
    return {
        "target_id": f"memory-{provider}:profile-one", "provider": provider,
        "backend_variant": variant, "profile_id": "profile-one", "principal_id": "principal-one",
        "service_enrollment_id": f"service-{provider}-one", "source_revision": SOURCE_PINS[provider],
        "service_generation": "service-gen-7", "namespace_identity": "namespace-one",
        "literal_loopback_port": port, "fixed_route_map": fixed_routes,
        "data_root_id": f"memory-data-{provider}-one", "auth_reference_id": f"memory-auth-{provider}-one",
        "fixed_project_account_user_scope": {"project_id": "project-one", "account_id": "account-one", "user_id": "profile-one"},
        "memory_owner_generation": 4,
        "private_extraction_embedding_routes": {"extract": "private-extract-route-one", "embed": "private-embed-route-one"},
        "background_consent_revision": "consent-policy-one",
        "limits": {"request_bytes": 262144, "response_bytes": 2097152, "result_limit": 100,
                   "operation_timeout_seconds": 15, "whole_compound_timeout_seconds": 60},
    }


class MemoryEnrollmentTests(unittest.TestCase):
    def test_pins_literal_listener_ports_and_source_pinned_recipes_are_required(self):
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(record()).literal_loopback_port, 3111)
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(
            record("openviking", "default", 1933)).literal_loopback_port, 1933)
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(record(port=0))
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(record("openviking", "default", 1932))
        with self.assertRaises(MemoryEnrollmentError):
            value = record(); del value["literal_loopback_port"]
            MemoryServiceEnrollment.from_protected_record(value)

    def test_route_ids_paths_and_methods_are_variant_bound(self):
        sqlite_routes = ROUTES["claude-mem"]["server-v1-sqlite"]
        postgres_routes = ROUTES["claude-mem"]["server-v1-postgres"]
        self.assertEqual(sqlite_routes["claude-sqlite-search"].path, "/v1/search")
        self.assertNotIn("claude-sqlite-delete", sqlite_routes)
        self.assertEqual(postgres_routes["claude-postgres-delete"].method, "DELETE")
        # Route names alone are insufficient: unsupported Claude serializers
        # and semantic validators remain unavailable until independently reviewed.
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(record("claude-mem", "server-v1-sqlite", 43892))
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(record("claude-mem", "server-v1-postgres", 43892))
        value = record(); value["fixed_route_map"]["invented-delete"] = {}
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)

    def test_service_generation_is_opaque_and_owner_epoch_stays_integer(self):
        value = record(); value["service_generation"] = "svc-generation-opaque-17"
        for route in value["fixed_route_map"].values():
            route["scope_bindings"]["service_generation"] = value["service_generation"]
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(value).service_generation,
                         "svc-generation-opaque-17")
        value["service_generation"] = 17
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)

    def test_scope_generation_and_limits_are_bound_to_protected_record(self):
        value = record(); value["fixed_project_account_user_scope"]["user_id"] = "sibling-profile"
        with self.assertRaises(MemoryEnrollmentError): MemoryServiceEnrollment.from_protected_record(value)
        value = record(); value["memory_owner_generation"] = 0
        with self.assertRaises(MemoryEnrollmentError): MemoryServiceEnrollment.from_protected_record(value)
        value = record(); value["limits"]["operation_timeout_seconds"] = 16
        with self.assertRaises(MemoryEnrollmentError): MemoryServiceEnrollment.from_protected_record(value)

    def test_target_resolves_only_routes_with_complete_selected_recipes(self):
        agent = MemoryTarget.from_enrollment(MemoryServiceEnrollment.from_protected_record(record()))
        self.assertEqual(agent.service_generation, "service-gen-7")
        self.assertEqual(agent.route_for("search"), "agentmemory-search")
        self.assertEqual(agent.route_for("capture"), "agentmemory-capture")
        self.assertIsNone(agent.route_for("doctor"))
        self.assertIsNone(agent.route_for("restore"))
        openviking = MemoryTarget.from_enrollment(MemoryServiceEnrollment.from_protected_record(
            record("openviking", "default", 1933)))
        self.assertEqual(openviking.route_for("capture"), "openviking-session-capture")
        self.assertIsNone(openviking.route_for("delete"))

    def test_target_and_source_pin_are_not_caller_selectable(self):
        value = record(); value["target_id"] = "memory-agentmemory:sibling-profile"
        with self.assertRaises(MemoryEnrollmentError): MemoryServiceEnrollment.from_protected_record(value)
        value = record(); value["source_revision"] = "latest"
        with self.assertRaises(MemoryEnrollmentError): MemoryServiceEnrollment.from_protected_record(value)


if __name__ == "__main__":
    unittest.main()
