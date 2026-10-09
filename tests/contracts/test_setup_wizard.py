from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.config import validate_config
from hermes_installer.remote.cloudflare import CloudflareError, CloudflareZone
from hermes_installer.remote.lifecycle import OwnedResource, RemoteJournal
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


class FakePolicyCloudflare(FakeCloudflare):
    def __init__(self, token: str, requests: list[tuple[str, str]], *, deny: set[str] | None = None):
        super().__init__(token)
        if token not in {"setup-token", "read-token"}:
            raise ValueError("credential rejected")
        self.requests = requests
        self.deny = deny or set()

    def request(self, method: str, path: str):
        self.requests.append((method, path))
        if path in self.deny:
            raise CloudflareError("Cloudflare API rejected the request")
        if path == "/accounts/account-1/access/apps/installer-app":
            return {"id": "installer-app", "name": "HermesInstaller:operation-1:desktop",
                    "aud": "audience-1", "type": "self_hosted", "domain": "desktop.example.test",
                    "self_hosted_domains": [], "allowed_idps": ["installer-idp"],
                    "enable_binding_cookie": False}
        if path.startswith("/accounts/account-1/access/apps/installer-app/policies?"):
            return [{"id": "installer-policy", "name": "HermesInstaller:operation-1:allowed-emails",
                     "decision": "allow", "include": [{"email": {"email": "owner@example.test"}}],
                     "exclude": [], "require": [], "precedence": 1}]
        if path == "/accounts/account-1/access/identity_providers/installer-idp":
            return {"id": "installer-idp", "name": "HermesInstaller:operation-1:email-code",
                    "type": "onetimepin"}
        raise AssertionError(f"Unexpected Cloudflare read path: {path}")


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

    def test_remote_setup_stores_distinct_credentials_but_waits_for_owned_resources(self):
        with tempfile.TemporaryDirectory() as td:
            config = {"schema_version": 1, "paths": {"state_root": str(Path(td) / "state")}}
            secrets = iter(("setup-token", "read-token"))
            result = run_setup_wizard(config, input_fn=_inputs(include_policy="now"), output_fn=lambda _: None,
                                      secret_reader=lambda _prompt: next(secrets),
                                      adapters={"remote_desktop": CloudflareDesktopAdapter(FakeCloudflare)})
            self.assertEqual(result.state, "pending")
            self.assertFalse(result.config["components"].get("remote_desktop", False))
            self.assertNotEqual(result.config["remote_desktop"]["management_token_ref"], result.config["remote_desktop"]["policy_read_token_ref"])
            validate_config(dict(result.config))
            self.assertTrue(any("checkpointed" in step for step in result.next_steps))

    def test_policy_read_probe_uses_only_checkpointed_owned_access_resources(self):
        requests: list[tuple[str, str]] = []
        adapter = CloudflareDesktopAdapter(lambda token: FakePolicyCloudflare(token, requests))
        setup = SimpleNamespace(hostname="desktop.example.test", allowed_emails=("owner@example.test",),
            zone=CloudflareZone("zone-1", "example.test", "account-1", "active"),
            auth_domain="team.example.cloudflareaccess.com", management_token="setup-token")
        with tempfile.TemporaryDirectory() as td:
            reference = PrivateFileCredentialStore(Path(td) / "state").put("policy", "read-token")
            with self.assertRaisesRegex(ValueError, "IDs are not checkpointed"):
                adapter._test_policy_read(reference, setup)
            self.assertEqual(requests, [])

            journal = RemoteJournal("operation-1", setup.hostname)
            journal.resources = {
                "access_app": OwnedResource("access_app", "installer-app", journal.operation_id, True),
                "access_policy": OwnedResource("access_policy", "installer-policy", journal.operation_id, True),
                "identity_provider": OwnedResource("identity_provider", "installer-idp", journal.operation_id, True),
            }
            adapter._test_policy_read(reference, setup, journal)

        paths = [path for _method, path in requests]
        self.assertIn("/accounts/account-1/access/apps/installer-app", paths)
        self.assertTrue(any(path.startswith("/accounts/account-1/access/apps/installer-app/policies?") for path in paths))
        self.assertIn("/accounts/account-1/access/identity_providers/installer-idp", paths)

    def test_noninteractive_resume_restores_pending_choice_then_promotes_after_exact_probe(self):
        requests: list[tuple[str, str]] = []
        adapter = CloudflareDesktopAdapter(lambda token: FakePolicyCloudflare(token, requests))
        with tempfile.TemporaryDirectory() as td:
            store = PrivateFileCredentialStore(Path(td) / "state")
            config = {"schema_version": 1, "components": {"hermes_agent": True, "remote_desktop": False},
                "remote_desktop": {"hostname": "desktop.example.test", "allowed_emails": ["owner@example.test"],
                    "management_token_ref": store.put("setup", "setup-token"),
                    "policy_read_token_ref": store.put("policy", "read-token")}}
            journal = _Journal({"selected_components": {"hermes_agent": True, "remote_desktop": True}})
            remote_journal = RemoteJournal("operation-1", "desktop.example.test")
            remote_journal.resources = {
                "access_app": OwnedResource("access_app", "installer-app", remote_journal.operation_id, True),
                "access_policy": OwnedResource("access_policy", "installer-policy", remote_journal.operation_id, True),
                "identity_provider": OwnedResource("identity_provider", "installer-idp", remote_journal.operation_id, True),
            }
            result = run_setup_wizard(config, output_fn=lambda _: None, journal=journal,
                remote_journal=remote_journal, interactive=False,
                adapters={"remote_desktop": adapter})

        self.assertEqual(result.state, "ready")
        self.assertTrue(result.selected_components["remote_desktop"])
        self.assertTrue(result.config["components"]["remote_desktop"])
        self.assertEqual(result.account_states["remote_desktop"], "ready")
        self.assertTrue(any("/access/apps/installer-app/policies?" in path for _method, path in requests))

    def test_policy_read_probe_rejects_foreign_checkpoint_and_missing_policy_read_scope(self):
        requests: list[tuple[str, str]] = []
        adapter = CloudflareDesktopAdapter(lambda token: FakePolicyCloudflare(token, requests,
            deny={"/accounts/account-1/access/identity_providers/installer-idp"}))
        setup = SimpleNamespace(hostname="desktop.example.test", allowed_emails=("owner@example.test",),
            zone=CloudflareZone("zone-1", "example.test", "account-1", "active"),
            auth_domain="team.example.cloudflareaccess.com", management_token="setup-token")
        with tempfile.TemporaryDirectory() as td:
            store = PrivateFileCredentialStore(Path(td) / "state")
            reference = store.put("policy", "read-token")
            same_as_setup = store.put("same-token", "setup-token")
            journal = RemoteJournal("operation-1", setup.hostname)
            journal.resources = {
                "access_app": OwnedResource("access_app", "installer-app", journal.operation_id, True),
                "access_policy": OwnedResource("access_policy", "installer-policy", "foreign-operation", False),
                "identity_provider": OwnedResource("identity_provider", "installer-idp", journal.operation_id, True),
            }
            with self.assertRaisesRegex(ValueError, "not all checkpointed"):
                adapter._test_policy_read(reference, setup, journal)
            self.assertEqual(requests, [])

            journal.resources["access_policy"] = OwnedResource("access_policy", "installer-policy", journal.operation_id, True)
            with self.assertRaisesRegex(ValueError, "distinct token"):
                adapter._test_policy_read(same_as_setup, setup, journal)
            self.assertEqual(requests, [])
            with self.assertRaisesRegex(ValueError, "could not verify the exact installer-owned") as error:
                adapter._test_policy_read(reference, setup, journal)
            self.assertNotIn("read-token", str(error.exception))

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
    def __init__(self, prior_payload=None):
        self.prior_payload = prior_payload

    def operation(self, _operation):
        return {"status": "pending", "payload": self.prior_payload} if self.prior_payload is not None else None

    def checkpoint(self, _operation, _status, payload):
        self.payload = payload


if __name__ == "__main__":
    unittest.main()
