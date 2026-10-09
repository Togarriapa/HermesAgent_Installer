"""MCP account and target constraints are executable stdlib checks."""
import unittest
from hermes_installer.mcp.google import adapter as google
from hermes_installer.mcp.adapters import SERVICES
from hermes_installer.mcp.home_assistant import adapter as ha
from hermes_installer.mcp.playwright_mcp import validate_fixture_origin

class MCPAccountTests(unittest.TestCase):
    def test_google_eligibility_and_service_are_explicit(self):
        with self.assertRaises(TypeError):
            google(None, service="drive", resource_id="file-1", preview_eligible=False)
        with self.assertRaises(TypeError):
            google(None, service="drive", resource_id="file-1", preview_eligible=True)
        self.assertEqual(google(None, service="drive", resource_id="file-1").service.id,
                         "google-drive")
        with self.assertRaises(ValueError):
            google(None, service="unknown", resource_id="x")

    def test_google_catalog_uses_current_official_endpoints_and_read_tools(self):
        self.assertEqual(SERVICES["google-gmail"].endpoint, "https://gmailmcp.googleapis.com/mcp/v1")
        self.assertEqual(SERVICES["google-drive"].allowed_tools, frozenset({"get_file_metadata", "read_file_content"}))
        self.assertEqual(SERVICES["google-sheets"].allowed_tools, frozenset({"get_spreadsheet", "get_values"}))
        self.assertEqual(SERVICES["google-calendar"].allowed_tools, frozenset({"get_event", "list_events"}))
        self.assertEqual(SERVICES["google-contacts"].endpoint, "https://people.googleapis.com/mcp/v1")
        self.assertEqual(SERVICES["google-contacts"].allowed_tools, frozenset({"search_contacts"}))

    def test_home_assistant_targets_existing_instance_and_selected_entities(self):
        with self.assertRaises(ValueError):
            ha(None, endpoint="http://ha.local/", entity_ids=("sensor.temp",))
        with self.assertRaises(ValueError):
            ha(None, endpoint="http://ha.local/api/mcp", entity_ids=())

    def test_playwright_rejects_external_origin(self):
        validate_fixture_origin("http://127.0.0.1:5000")
        with self.assertRaises(PermissionError):
            validate_fixture_origin("https://example.org")

if __name__ == "__main__":
    unittest.main()
