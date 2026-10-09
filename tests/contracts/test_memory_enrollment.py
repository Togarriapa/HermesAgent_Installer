"""Strict memory source and root enrollment catalog tests (SK01, SK-T01)."""
import unittest

from hermes_installer.memory.enrollment import (
    MemoryEnrollmentError, MemoryServiceEnrollment, ROUTES, SOURCE_PINS,
)


def record(provider="agentmemory", variant="default", port=3111):
    routes = ROUTES[provider][variant]
    return {
        "target_id": f"memory-{provider}:profile-one",
        "provider": provider,
        "backend_variant": variant,
        "profile_id": "profile-one",
        "principal_id": "principal-one",
        "service_enrollment_id": f"service-{provider}-one",
        "source_revision": SOURCE_PINS[provider],
        "service_generation": 7,
        "namespace_identity": "namespace-one",
        "literal_loopback_port": port,
        "fixed_route_map": {
            route_id: {"method": route.method, "path": route.path, "body": route.body}
            for route_id, route in routes.items()
        },
        "data_root_id": f"memory-data-{provider}-one",
        "auth_reference_id": f"memory-auth-{provider}-one",
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
        self.assertIn("claude-sqlite-capture", sqlite["fixed_route_map"])
        self.assertNotIn("claude-sqlite-delete", sqlite["fixed_route_map"])
        parsed = MemoryServiceEnrollment.from_protected_record(sqlite)
        self.assertNotIn("claude-sqlite-delete", parsed.fixed_route_map)
        sqlite["fixed_route_map"]["invented-delete"] = {
            "method": "DELETE", "path": "/v1/memories/{id}", "body": "none"}
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(sqlite)
        worker = record("claude-mem", "worker-observation", 43891)
        worker["fixed_route_map"]["claude-worker-search-get"]["path"] = "/api/mem-search"
        with self.assertRaises(MemoryEnrollmentError):
            MemoryServiceEnrollment.from_protected_record(worker)

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
