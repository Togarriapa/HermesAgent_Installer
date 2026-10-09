"""MCP account and target constraints are executable stdlib checks."""
import unittest
from hermes_installer.mcp.google import adapter as google
from hermes_installer.mcp.home_assistant import adapter as ha
from hermes_installer.mcp.playwright_mcp import validate_fixture_origin

class MCPAccountTests(unittest.TestCase):
    def test_google_eligibility_and_service_are_explicit(self):
        with self.assertRaises(PermissionError):
            google(None, service="drive", resource_id="file-1", preview_eligible=False)
        with self.assertRaises(ValueError):
            google(None, service="unknown", resource_id="x", preview_eligible=True)

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
