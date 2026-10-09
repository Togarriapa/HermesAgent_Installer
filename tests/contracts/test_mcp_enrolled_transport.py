"""Tests for root-enrolled fixed MCP HTTP handler assembly."""
from __future__ import annotations

import unittest

from hermes_installer.mcp.broker import ProtectedMCPService
from hermes_installer.mcp.enrolled_transport import (
    MCPHTTPBindingError, ProtectedMCPHTTPBinding, build_enrolled_mcp_handlers,
    _ENDPOINT_SOURCES,
)
from hermes_installer.mcp.adapters import SERVICES


class _CredentialHandle:
    def headers_for(self, service_id, context, grant):
        return {"Authorization": "Bearer <opaque>"}


class EnrolledMCPTransportTests(unittest.TestCase):
    def setUp(self):
        self.revision = "a" * 64
        self.service = ProtectedMCPService(
            "figma", "http", frozenset({"get_metadata"}),
            "figma-binding", self.revision,
            selection_arguments={"get_metadata": ("fileKey",)},
        )
        self.binding = ProtectedMCPHTTPBinding(
            "figma-binding", "figma", "https://mcp.figma.com/mcp",
            "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/",
            self.revision, _CredentialHandle(),
        )

    def test_google_endpoints_match_official_workspace_routes(self):
        expected = {
            "google-gmail": "https://gmailmcp.googleapis.com/mcp/v1",
            "google-drive": "https://drivemcp.googleapis.com/mcp/v1",
            "google-docs": "https://docsmcp.googleapis.com/mcp/v1",
            "google-sheets": "https://sheetsmcp.googleapis.com/mcp/v1",
            "google-calendar": "https://calendarmcp.googleapis.com/mcp/v1",
            "google-contacts": "https://people.googleapis.com/mcp/v1",
        }
        for service_id, endpoint in expected.items():
            with self.subTest(service=service_id):
                self.assertEqual(SERVICES[service_id].endpoint, endpoint)
                self.assertEqual(_ENDPOINT_SOURCES[service_id][0], endpoint)
                self.assertTrue(_ENDPOINT_SOURCES[service_id][1].startswith("https://developers.google.com/"))

    def test_builds_only_exact_root_enrolled_http_target(self):
        handlers = build_enrolled_mcp_handlers(
            {"figma": self.service}, {"figma-binding": self.binding},
        )
        self.assertEqual(set(handlers), {("mcp.request", "mcp:figma:http")})

    def test_rejects_endpoint_or_provenance_substitution(self):
        with self.assertRaises(MCPHTTPBindingError):
            ProtectedMCPHTTPBinding(
                "figma-binding", "figma", "https://attacker.example/mcp",
                "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/",
                self.revision, _CredentialHandle(),
            )
        with self.assertRaises(MCPHTTPBindingError):
            ProtectedMCPHTTPBinding(
                "figma-binding", "figma", "https://mcp.figma.com/mcp",
                "https://attacker.example/claimed-official-docs",
                self.revision, _CredentialHandle(),
            )

    def test_missing_revision_binding_leaves_effect_unavailable(self):
        mismatched = ProtectedMCPHTTPBinding(
            "figma-binding", "figma", "https://mcp.figma.com/mcp",
            "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/",
            "b" * 64, _CredentialHandle(),
        )
        self.assertEqual(
            build_enrolled_mcp_handlers(
                {"figma": self.service}, {"figma-binding": mismatched},
            ),
            {},
        )

    def test_worker_config_cannot_supply_or_select_route(self):
        fake = dict(self.binding.__dict__) if hasattr(self.binding, "__dict__") else {
            "binding_id": "figma-binding", "service_id": "figma",
            "endpoint": "https://attacker.example/mcp",
            "endpoint_source_id": "https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/",
            "reviewed_revision": self.revision,
            "credential_handle": _CredentialHandle(),
        }
        with self.assertRaises(MCPHTTPBindingError):
            ProtectedMCPHTTPBinding(**fake)


if __name__ == "__main__":
    unittest.main()
