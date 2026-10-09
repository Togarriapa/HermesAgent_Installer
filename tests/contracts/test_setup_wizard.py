from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from hermes_installer.config import validate_config
from hermes_installer.setup_wizard import CloudflareDesktopAdapter, PrivateFileCredentialStore, run_setup_wizard


class FakeCloudflare:
    def __init__(self, token: str):
        self.token = token
        if token not in {"setup-token", "read-token"}:
            raise ValueError("credential rejected")

    def discover_zones(self, hostname: str):
        from hermes_installer.remote.cloudflare import CloudflareZone
        self.hostname = hostname
        return (CloudflareZone("zone-1", "example.test", "account-1", "active"),)

    def organization(self, account_id: str):
        self.account_id = account_id
        return {"auth_domain": "team.example.cloudflareaccess.com"}


def _inputs(*, hostname="desktop.example.test", include_policy="later"):
    values = {
        "fresh": "fresh",
        "coral": "no", "colibri": "no", "hermes_agent": "yes",
        "hermes_desktop": "yes", "memory": "no", "mcp": "no",
        "providers": "no", "registry": "yes", "remote_desktop": "yes",
        "hostname": hostname, "email": "owner@example.test", "provision": "now",
        "data_path": "", "state_path": "", "model_path": "",
    }
    def answer(prompt: str) -> str:
        if "Installation type" in prompt: return values["fresh"]
        if "Select " in prompt:
            for key, value in values.items():
                if f"Select {key.replace('_', ' ')} " in prompt:
                    return value
        if "Installer data path" in prompt: return values["data_path"]
        if "Private installer state path" in prompt: return values["state_path"]
        if "Optional model storage path" in prompt: return values["model_path"]
        if "Hostname (" in prompt: return values["hostname"]
        if "Allowed email addresses" in prompt: return values["email"]
        if "Configure Cloudflare now" in prompt: return values["provision"]
        if "separate existing read-only token" in prompt: return include_policy
        raise AssertionError(f"Unexpected prompt: {prompt}")
    return answer


class WizardTests(unittest.TestCase):
    def test_private_store_writes_mode_600_resolvable_file_reference(self):
        with tempfile.TemporaryDirectory() as td:
            store = PrivateFileCredentialStore(Path(td) / "state")
            reference = store.put("example-token", "hidden-value")
            self.assertTrue(reference.startswith("file://"))
            path = Path(reference[7:])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(path.read_text(encoding="utf-8"), "hidden-value\n")

    def test_remote_configure_later_stores_reference_and_never_records_secret(self):
        with tempfile.TemporaryDirectory() as td:
            state_root = Path(td) / "state"
            config = {"schema_version": 1, "paths": {"state_root": str(state_root)}}
            output: list[str] = []
            secrets = iter(("setup-token",))
            journal = _Journal()
            result = run_setup_wizard(config, input_fn=_inputs(), output_fn=output.append,
                                      secret_reader=lambda _prompt: next(secrets),
                                      adapters={"remote_desktop": CloudflareDesktopAdapter(FakeCloudflare)},
                                      journal=journal)
            self.assertEqual(result.state, "pending")
            self.assertTrue(result.selected_components["remote_desktop"])
            self.assertFalse(result.config["components"].get("remote_desktop", False))
            self.assertIn("management_token_ref", result.config["remote_desktop"])
            self.assertEqual(result.account_states["remote_desktop"], "pending")
            self.assertNotIn("setup-token", "\n".join(output))
            self.assertNotIn("setup-token", json.dumps(journal.payload))
            token_path = Path(result.config["remote_desktop"]["management_token_ref"][7:])
            self.assertEqual(token_path.read_text(encoding="utf-8"), "setup-token\n")

    def test_remote_setup_requires_and_tests_two_distinct_credentials(self):
        with tempfile.TemporaryDirectory() as td:
            config = {"schema_version": 1, "paths": {"state_root": str(Path(td) / "state")}}
            secrets = iter(("setup-token", "read-token"))
            result = run_setup_wizard(config, input_fn=_inputs(include_policy="now"), output_fn=lambda _: None,
                                      secret_reader=lambda _prompt: next(secrets),
                                      adapters={"remote_desktop": CloudflareDesktopAdapter(FakeCloudflare)})
            self.assertEqual(result.state, "ready")
            self.assertTrue(result.config["components"]["remote_desktop"])
            self.assertNotEqual(result.config["remote_desktop"]["management_token_ref"], result.config["remote_desktop"]["policy_read_token_ref"])
            validate_config(dict(result.config))

    def test_noninteractive_remote_setup_requires_separate_read_reference(self):
        with tempfile.TemporaryDirectory() as td:
            store = PrivateFileCredentialStore(Path(td) / "state")
            setup_ref = store.put("setup", "setup-token")
            config = {"schema_version": 1, "components": {"remote_desktop": True},
                      "remote_desktop": {"hostname": "desktop.example.test", "allowed_emails": ["owner@example.test"],
                                         "management_token_ref": setup_ref}}
            result = run_setup_wizard(config, interactive=False, output_fn=lambda _: None)
            self.assertEqual(result.state, "pending")
            self.assertFalse(result.config["components"].get("remote_desktop", False))
            self.assertTrue(any("policy_read_token_ref" in step for step in result.next_steps))

    def test_blank_hostname_defers_without_collecting_or_sending_a_secret(self):
        with tempfile.TemporaryDirectory() as td:
            config = {"schema_version": 1, "paths": {"state_root": str(Path(td) / "state")}}
            calls: list[str] = []
            result = run_setup_wizard(config, input_fn=_inputs(hostname=""), output_fn=lambda _: None,
                                      secret_reader=lambda prompt: calls.append(prompt) or "must-not-be-read",
                                      adapters={"remote_desktop": CloudflareDesktopAdapter(FakeCloudflare)})
            self.assertEqual(result.state, "pending")
            self.assertEqual(calls, [])
            self.assertFalse(result.config["components"].get("remote_desktop", False))

    def test_unowned_state_directory_is_preserved_when_secret_storage_is_refused(self):
        with tempfile.TemporaryDirectory() as td:
            state_root = Path(td) / "state"
            state_root.mkdir()
            sentinel = state_root / "existing.conf"
            sentinel.write_bytes(b"user-owned-data\n")
            config = {"schema_version": 1, "paths": {"state_root": str(state_root)}}
            result = run_setup_wizard(config, input_fn=_inputs(), output_fn=lambda _: None,
                                      secret_reader=lambda _: "setup-token",
                                      adapters={"remote_desktop": CloudflareDesktopAdapter(FakeCloudflare)})
            self.assertEqual(result.state, "failed")
            self.assertEqual(sentinel.read_bytes(), b"user-owned-data\n")
            self.assertEqual(list(state_root.iterdir()), [sentinel])


class _Journal:
    def checkpoint(self, _operation, _status, payload):
        self.payload = payload


if __name__ == "__main__":
    unittest.main()
