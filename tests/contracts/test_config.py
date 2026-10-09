from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.config import ConfigError, load_config, validate_config, write_example


class ConfigContractTests(unittest.TestCase):
    def test_secret_free_example_is_valid_and_never_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "installer.json"
            write_example(path)
            config = load_config(path)
            self.assertEqual(config.timezone, "Europe/Lisbon")
            self.assertEqual(config.privacy["additional_metered_budget"], 0)
            before = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_example(path)
            self.assertEqual(path.read_bytes(), before)

    def test_hostname_can_be_blank_only_for_configure_later(self) -> None:
        data = {"schema_version": 1, "remote_desktop": {"hostname": ""}}
        self.assertEqual(validate_config(data).remote_desktop["hostname"], "")
        for invalid in ("https://example.com", "-bad.example.com", "example..com", "example.com/path"):
            with self.subTest(invalid=invalid), self.assertRaises(ConfigError):
                validate_config({"schema_version": 1, "remote_desktop": {"hostname": invalid}})

    def test_nonzero_metered_budget_and_unknown_fields_fail_closed(self) -> None:
        with self.assertRaises(ConfigError):
            validate_config({"schema_version": 1, "privacy": {"additional_metered_budget": 1}})
        with self.assertRaises(ConfigError):
            validate_config({"schema_version": 1, "surprise": True})

    def test_inline_secrets_unknown_remote_fields_and_unknown_privacy_fields_are_rejected(self) -> None:
        base={"schema_version":1,"components":{"remote_desktop":True},"remote_desktop":{"hostname":"desk.example.org","allowed_emails":["a@example.org"],"management_token_ref":"keyring://cf/token"}}
        for extra in ({"management_token":"plaintext-secret"},{"api_token":"plaintext-secret"},{"password":"plaintext-secret"}):
            data={**base,"remote_desktop":{**base["remote_desktop"],**extra}}
            with self.subTest(extra=tuple(extra)), self.assertRaises(ConfigError):
                validate_config(data)
        with self.assertRaises(ConfigError):
            validate_config({"schema_version":1,"privacy":{"unknown":True}})
        with self.assertRaises(ConfigError):
            validate_config({"schema_version":1,"privacy":{"additional_metered_budget":False}})

    def test_remote_selection_requires_explicit_hostname_emails_and_secret_reference(self) -> None:
        with self.assertRaises(ConfigError):
            validate_config({"schema_version": 1, "components": {"remote_desktop": True}})
        config = validate_config({"schema_version": 1, "components": {"remote_desktop": True}, "remote_desktop": {"hostname": "desktop.example.org", "allowed_emails": ["owner@example.org"], "management_token_ref": "keyring://hermes/cloudflare"}})
        self.assertEqual(config.remote_desktop["hostname"], "desktop.example.org")
        with self.assertRaises(ConfigError):
            validate_config({"schema_version": 1, "components": {"remote_desktop": True}, "remote_desktop": {"hostname": "desktop.example.org", "allowed_emails": ["owner@example.org"], "management_token_ref": "cf-secret-value"}})


if __name__ == "__main__":
    unittest.main()
