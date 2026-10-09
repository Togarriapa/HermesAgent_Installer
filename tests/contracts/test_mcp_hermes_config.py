"""Hermes MCP config merge tests against the pinned native config shape."""
import os
import stat
import tempfile
import unittest
from pathlib import Path

import yaml

from hermes_installer.mcp.hermes_config import (
    HermesMCPConfigError,
    entry_fingerprint,
    merge_hermes_mcp_config,
    write_selected_profile_mcp_config,
)


def stat_mode(path):
    return stat.S_IMODE(path.stat().st_mode)


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

    def test_profile_config_write_is_private_and_preserves_foreign_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            selected = home / "profiles" / "selected"
            selected.mkdir(mode=0o700, parents=True)
            os.chmod(home, 0o700)
            os.chmod(home / "profiles", 0o700)
            os.chmod(selected, 0o700)
            config = selected / "config.yaml"
            config.write_text("model: GLM-5.2\nmcp_servers:\n  user_server:\n    url: https://example.test/mcp\n", encoding="utf-8")
            os.chmod(config, 0o600)
            owners, digest = write_selected_profile_mcp_config(
                hermes_home=home, config_path=config, proposed={"installer-figma": self.ENTRY},
                owned_fingerprints=None, expected_owner_uid=os.geteuid(),
            )
            self.assertEqual(len(digest), 64)
            self.assertEqual(owners["installer-figma"], entry_fingerprint(self.ENTRY))
            actual = yaml.safe_load(config.read_text(encoding="utf-8"))
            self.assertEqual(actual["mcp_servers"]["user_server"]["url"], "https://example.test/mcp")
            self.assertEqual(stat_mode(config), 0o600)

    def test_profile_config_write_rejects_symlink_and_outside_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            home = base / "instance"
            selected = home / "profiles" / "selected"
            selected.mkdir(mode=0o700, parents=True)
            os.chmod(home, 0o700)
            os.chmod(home / "profiles", 0o700)
            os.chmod(selected, 0o700)
            link = base / "linked"
            link.symlink_to(home, target_is_directory=True)
            with self.assertRaises(HermesMCPConfigError):
                write_selected_profile_mcp_config(
                    hermes_home=link, config_path=link / "config.yaml",
                    proposed={"installer-figma": self.ENTRY}, owned_fingerprints=None,
                    expected_owner_uid=os.geteuid(),
                )
            with self.assertRaises(HermesMCPConfigError):
                write_selected_profile_mcp_config(
                    hermes_home=home, config_path=base / "outside.yaml",
                    proposed={"installer-figma": self.ENTRY}, owned_fingerprints=None,
                    expected_owner_uid=os.geteuid(),
                )

    def test_rejects_unknown_hermes_config_shape_without_destroying_it(self):
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config("mcp_servers: []\n", {"installer-figma": self.ENTRY})
        unsafe = "!!python/object/apply:os.system ['echo unsafe']"
        with self.assertRaises(HermesMCPConfigError):
            merge_hermes_mcp_config(unsafe, {"installer-figma": self.ENTRY})


if __name__ == "__main__":
    unittest.main()
