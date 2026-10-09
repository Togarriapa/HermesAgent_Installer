"""Strict memory source and root enrollment catalog tests (SK01, SK-T01)."""
import unittest

from hermes_installer.memory.broker import MemoryTarget
from hermes_installer.memory.enrollment import (
    MemoryEnrollmentError, MemoryServiceEnrollment, ROUTES, SOURCE_PINS,
)


def record(provider="agentmemory", variant="default", port=3111):
    supported = {
        "agentmemory": {"agentmemory-search", "agentmemory-capture"},
        "openviking": {"openviking-find", "openviking-session-capture"},
    }
    routes = {key: route for key, route in ROUTES[provider][variant].items()
              if key in supported.get(provider, set())}
    scope = {"profile_id": "profile-one", "service_generation": "service-gen-7",
             "memory_owner_generation": 4, "backend_project_ref": "project-one",
             "backend_agent_ref": "profile-one", "backend_session_ref": None,
             "private_provider_route_ref": None, "credential_reference_id": f"memory-auth-{provider}-one"}
    schemas = {
        "agentmemory-search": ("agentmemory-search-request-v1", "agentmemory-search-result-v1",
            "search", "POST", "/agentmemory/smart-search", "agentmemory-search-owned-v1", "agentmemory-search-result-v1", (), None),
        "agentmemory-capture": ("agentmemory-capture-request-v1", "agentmemory-remember-result-v1",
            "capture", "POST", "/agentmemory/remember", "agentmemory-remember-owned-v1", "agentmemory-remember-result-v1", (), None),
        "openviking-find": ("openviking-find-request-v1", "openviking-find-result-v1",
            "find", "POST", "/api/v1/search/find", "openviking-find-owned-v1", "openviking-find-result-v1", (), None),
    }
    fixed_routes = {}
    for route_id, route in routes.items():
        if route_id == "openviking-session-capture":
            req, result, rows = "openviking-capture-event-v1", "openviking-capture-result-v1", [
                ("create", "POST", "/api/v1/sessions", "openviking-create-owned-session-v1", "openviking-create-result-v1", ["session_id"], "append"),
                ("append", "POST", "/api/v1/sessions/{root-captured-owned-session-id}/messages", "openviking-append-captured-event-v1", "openviking-append-result-v1", [], "finalize"),
                ("finalize", "POST", "/api/v1/sessions/{root-captured-owned-session-id}/{root-selected-commit-or-extract}", "openviking-finalize-private-v1", "openviking-finalize-result-v1", [], None),
            ]
        else:
            req, result, *row = schemas[route_id]
            step, method, path, body, response, captures, next_step = row
            rows = [(step, method, path, body, response, list(captures), next_step)]
        fixed_routes[route_id] = {
            "approved_route_id": route_id, "backend_variant": variant,
            "steps": [{"step_id": s, "method": m, "path_template": p,
                       "body_recipe_id": b, "response_schema_id": r,
                       "capture_fields": c, "next_step_id": n}
                      for s, m, p, b, r, c, n in rows],
            "request_schema_id": req, "result_schema_id": result,
            "scope_bindings": scope,
            "credential_reference_id": f"memory-auth-{provider}-one",
            "maximum_seconds": 10, "maximum_bytes": 65536,
        }
    return {
        "target_id": f"memory-{provider}:profile-one",
        "provider": provider,
        "backend_variant": variant,
        "profile_id": "profile-one",
        "principal_id": "principal-one",
        "service_enrollment_id": f"service-{provider}-one",
        "source_revision": SOURCE_PINS[provider],
        "service_generation": "service-gen-7",
        "namespace_identity": "namespace-one",
        "literal_loopback_port": port,
        "fixed_route_map": fixed_routes,
        "data_root_id": f"memory-data-{provider}-one",
        "auth_reference_id": f"memory-auth-{provider}-one",
        "authority_state_root_id": "authority-journal-one",
        "fixed_project_account_user_scope": {
            "project_id": "project-one", "account_id": "account-one",
            "user_id": "profile-one",
        },
        "memory_owner_generation": 4,
        "private_extraction_embedding_routes": {
            "extract": "private-extract-route-one",
            "embed": "private-embed-route-one",
        },
        "background_consent_revision": "consent-policy-one",
        "limits": {
            "request_bytes": 262144, "response_bytes": 2097152, "result_limit": 100,
            "operation_timeout_seconds": 15, "whole_compound_timeout_seconds": 60,
        },
    }


class MemoryEnrollmentTests(unittest.TestCase):
    def test_source_pins_and_literal_listener_ports_are_required(self):
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(record()).literal_loopback_port, 3111)
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(
            record("openviking", "default", 1933)).literal_loopback_port, 1933)
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(record(port=0))
        with self.assertRaises(MemoryEnrollmentError):
            value = record("claude-mem", "server-v1-sqlite", 43892)
            del value["literal_loopback_port"]
            MemoryServiceEnrollment.from_protected_record(value)

    def test_route_ids_paths_and_methods_are_variant_bound(self):
        sqlite = record("claude-mem", "server-v1-sqlite", 43892)
        self.assertIn("claude-sqlite-capture", ROUTES["claude-mem"]["server-v1-sqlite"])
        self.assertNotIn("claude-sqlite-delete", ROUTES["claude-mem"]["server-v1-sqlite"])
        # Claude route names are source-pinned, but no selected variant has a
        # complete reviewed compound serializer/result validator yet.
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(sqlite)
        self.assertIn("claude-worker-search-get", ROUTES["claude-mem"]["worker-observation"])

    def test_service_generation_is_an_opaque_host_id_and_owner_epoch_stays_integer(self):
        value = record()
        value["service_generation"] = "svc-generation-opaque-17"
        for route in value["fixed_route_map"].values():
            route["scope_bindings"]["service_generation"] = value["service_generation"]
        self.assertEqual(MemoryServiceEnrollment.from_protected_record(value).service_generation,
                         "svc-generation-opaque-17")
        value["service_generation"] = 17
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)

    def test_scope_generation_and_limits_are_bound_to_protected_record(self):
        value = record()
        value["fixed_project_account_user_scope"]["user_id"] = "sibling-profile"
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)
        value = record()
        value["memory_owner_generation"] = 0
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)
        value = record()
        value["limits"]["operation_timeout_seconds"] = 16
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)

    def test_broker_target_resolves_only_routes_for_selected_source_variant(self):
        for variant in ("server-v1-sqlite", "server-v1-postgres"):
            with self.assertRaises(MemoryEnrollmentError):
                MemoryServiceEnrollment.from_protected_record(
                    record("claude-mem", variant, 43892))
        agent = MemoryTarget.from_enrollment(MemoryServiceEnrollment.from_protected_record(record()))
        self.assertEqual(agent.route_for("search"), "agentmemory-search")
        self.assertIsNone(agent.route_for("restore"))
        openviking = MemoryTarget.from_enrollment(MemoryServiceEnrollment.from_protected_record(
            record("openviking", "default", 1933)))
        self.assertEqual(openviking.route_for("capture"), "openviking-session-capture")
        self.assertIsNone(openviking.route_for("delete"))

    def test_target_and_source_pin_are_not_caller_selectable(self):
        value = record()
        value["target_id"] = "memory-agentmemory:sibling-profile"
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)
        value = record()
        value["source_revision"] = "latest"
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(value)


if __name__ == "__main__":
    unittest.main()
