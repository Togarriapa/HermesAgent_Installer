"""Hermes MCP config merge tests against the pinned native config shape."""
import unittest

import yaml

from hermes_installer.mcp.hermes_config import (
    HermesMCPConfigError,
    entry_fingerprint,
    merge_hermes_mcp_config,
)


class HermesMCPConfigTests(unittest.TestCase):
    ENTRY = {
        "url": "https://mcp.figma.com/mcp",
        "auth": "oauth",
        "enabled": False,
        "timeout": 9,
        "connect_timeout": 9,
        "tools": {"include": ["get_file"]},
    }

    def test_merge_preserves_unowned_config_and_returns_owner_fingerprint(self):
        existing = yaml.safe_dump({
            "model": "GLM-5.2",
            "mcp_servers": {"user_server": {"url": "https://example.test/mcp", "enabled": True}},
        }, sort_keys=False)
        rendered, owners = merge_hermes_mcp_config(existing, {"installer-figma": self.ENTRY})
        actual = yaml.safe_load(rendered)
        self.assertEqual(actual["model"], "GLM-5.2")
        self.assertEqual(actual["mcp_servers"]["user_server"]["enabled"], True)
        self.assertEqual(actual["mcp_servers"]["installer-figma"], self.ENTRY)
        self.assertEqual(owners["installer-figma"], entry_fingerprint(self.ENTRY))

    def test_refuses_unowned_conflicts_and_user_modified_owned_entry(self):
        existing = yaml.safe_dump({"mcp_servers": {"installer-figma": self.ENTRY}})
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config(existing, {"installer-figma": self.ENTRY})
        owners = {"installer-figma": entry_fingerprint(self.ENTRY)}
        modified = yaml.safe_dump({"mcp_servers": {"installer-figma": {**self.ENTRY, "enabled": True}}})
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config(modified, {"installer-figma": self.ENTRY}, owned_fingerprints=owners)

    def test_rejects_non_tls_and_unbounded_or_unallowlisted_entries(self):
        for bad in (
            {**self.ENTRY, "url": "http://mcp.example.test/mcp"},
            {**self.ENTRY, "timeout": 10},
            {**self.ENTRY, "tools": {"exclude": ["delete_project"]}},
            {**self.ENTRY, "headers": {"Authorization": "Bearer canary-secret"}},
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(HermesMCPConfigError):
                    merge_hermes_mcp_config(None, {"installer-figma": bad})

    def test_rejects_unknown_hermes_config_shape_without_destroying_it(self):
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config("mcp_servers: []\n", {"installer-figma": self.ENTRY})
        unsafe = "!!python/object/apply:os.system ['echo unsafe']"
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config(unsafe, {"installer-figma": self.ENTRY})


if __name__ == "__main__":
    unittest.main()
