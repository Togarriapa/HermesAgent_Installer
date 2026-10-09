from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.enrollment import run_remote_desktop_enrollment
from hermes_installer.setup_wizard import PrivateFileCredentialStore
from hermes_installer.state import Journal, OwnedRoot


class CloudflareFixture:
    """Effectful API fixture for ownership, checkpoint and policy-read tests."""

    def __init__(self):
        self.identity_providers: list[dict] = []
        self.apps: list[dict] = []
        self.policies: dict[str, list[dict]] = {}
        self.tunnels: list[dict] = []
        self.dns: list[dict] = []
        self.effects: list[tuple[str, str, dict | None, str]] = []
        self.read_denied = False
        self.fail_once: set[tuple[str, str]] = set()
        self.next_id = 1

    def client_factory(self, token: str):
        if token not in {"fixture-setup-token", "fixture-policy-token", "fixture-denied-token"}:
            raise ValueError("fixture rejected credential")
        return CloudflareFixtureClient(self, token)

    def id(self, prefix: str) -> str:
        value = f"{prefix}-{self.next_id}"
        self.next_id += 1
        return value


class CloudflareFixtureClient:
    def __init__(self, server: CloudflareFixture, token: str):
        self.server = server
        self.token = token
        self.network = None

    def discover_zones(self, hostname: str):
        from hermes_installer.remote.cloudflare import CloudflareZone

        return (CloudflareZone("zone-1", "example.test", "account-1", "active"),)

    def organization(self, account_id: str):
        return {"auth_domain": "team.example.cloudflareaccess.com"}

    @staticmethod
    def _path(path: str) -> str:
        return path.split("?", 1)[0]

    def pages(self, path: str, *, filters=None):
        return self.request("GET", path)

    def request(self, method: str, path: str, payload=None):
        server = self.server
        clean = self._path(path)
        server.effects.append((method, clean, payload, self.token))
        if (method, clean) in server.fail_once:
            server.fail_once.remove((method, clean))
            raise RuntimeError("fixture transient operation failed with credential leak sentinel")
        if self.token == "fixture-denied-token" and server.read_denied:
            raise RuntimeError("fixture read denied with fixture-policy-token leak sentinel")

        if clean == "/accounts/account-1/access/identity_providers":
            if method == "GET":
                return list(server.identity_providers)
            if method == "POST":
                row = {**payload, "id": server.id("idp")}
                server.identity_providers.append(row)
                return row
        if clean.startswith("/accounts/account-1/access/identity_providers/") and method == "GET":
            resource_id = clean.rsplit("/", 1)[-1]
            row = next((item for item in server.identity_providers if item.get("id") == resource_id), None)
            if row is None:
                raise RuntimeError("fixture identity provider missing")
            return row
        if clean == "/accounts/account-1/access/apps":
            if method == "GET":
                return list(server.apps)
            if method == "POST":
                row = {**payload, "id": server.id("app"), "aud": server.id("aud")}
                server.apps.append(row)
                return row
        if clean.startswith("/accounts/account-1/access/apps/"):
            parts = clean.split("/")
            app_id = parts[5]
            if len(parts) == 7 and parts[6] == "policies":
                if method == "GET":
                    return list(server.policies.get(app_id, []))
                if method == "POST":
                    row = {**payload, "id": server.id("policy")}
                    server.policies.setdefault(app_id, []).append(row)
                    return row
            if len(parts) == 6 and method == "GET":
                row = next((app for app in server.apps if app.get("id") == app_id), None)
                if row is None:
                    raise RuntimeError("fixture app missing")
                return row
        if clean == "/accounts/account-1/cfd_tunnel":
            if method == "GET":
                return list(server.tunnels)
            if method == "POST":
                row = {**payload, "id": server.id("tunnel")}
                server.tunnels.append(row)
                return row
        if clean == "/zones/zone-1/dns_records":
            if method == "GET":
                return list(server.dns)
            if method == "POST":
                row = {**payload, "id": server.id("dns")}
                server.dns.append(row)
                return row
        raise AssertionError(f"Unexpected fixture API request: {method} {path}")


class RemoteEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name) / "state"
        OwnedRoot(root).ensure()
        self.journal = Journal(root / "journal.sqlite")
        self.credentials = PrivateFileCredentialStore(root)
        self.server = CloudflareFixture()
        self.setup_ref = self.credentials.put("cloudflare-setup", "fixture-setup-token")
        self.read_ref = self.credentials.put("cloudflare-policy-read", "fixture-policy-token")
        self.config = {
            "schema_version": 1,
            "remote_desktop": {
                "hostname": "desktop.example.test",
                "allowed_emails": ["owner@example.test"],
                "management_token_ref": self.setup_ref,
            },
        }

    def run_enrollment(self, **kwargs):
        return run_remote_desktop_enrollment(
            self.config, self.journal,
            client_factory=self.server.client_factory,
            **kwargs,
        )

    def write_effects(self):
        return [effect for effect in self.server.effects if effect[0] in {"POST", "PUT", "PATCH", "DELETE"}]

    def route_effects(self):
        return [effect for effect in self.write_effects()
                if "/cfd_tunnel" in effect[1] or effect[1].endswith("/dns_records")]

    def test_stages_access_then_resumes_exact_policy_reads_without_route_writes(self):
        staged = self.run_enrollment()
        self.assertEqual((staged.state, staged.access_state, staged.policy_read_state),
                         ("pending", "ready", "pending"))
        self.assertEqual(len(self.server.apps), 1)
        self.assertEqual(len(self.server.identity_providers), 1)
        self.assertEqual(len(next(iter(self.server.policies.values()))), 1)
        self.assertEqual(self.route_effects(), [])

        self.config["remote_desktop"]["policy_read_token_ref"] = self.read_ref
        resumed = self.run_enrollment()
        self.assertEqual((resumed.state, resumed.access_state, resumed.policy_read_state, resumed.route_state),
                         ("pending", "ready", "verified", "pending"))
        self.assertTrue(resumed.component_installable)
        self.assertEqual(resumed.resource_ids["access_app"], staged.resource_ids["access_app"])
        self.assertEqual(self.route_effects(), [])
        self.assertEqual((len(self.server.apps), len(self.server.identity_providers)), (1, 1))
        self.assertEqual(sum(len(items) for items in self.server.policies.values()), 1)

        read_paths = [path for method, path, _payload, token in self.server.effects
                      if method == "GET" and token == "fixture-policy-token"]
        app_id = resumed.resource_ids["access_app"]
        policy_id = resumed.resource_ids["access_policy"]
        idp_id = resumed.resource_ids["identity_provider"]
        self.assertIn(f"/accounts/account-1/access/apps/{app_id}", read_paths)
        self.assertTrue(any(path.startswith(f"/accounts/account-1/access/apps/{app_id}/policies") for path in read_paths))
        self.assertIn(f"/accounts/account-1/access/identity_providers/{idp_id}", read_paths)
        self.assertIn(policy_id, [row["id"] for rows in self.server.policies.values() for row in rows])

    def test_policy_read_denial_keeps_owned_access_and_never_creates_tunnel_or_dns(self):
        self.config["remote_desktop"]["policy_read_token_ref"] = self.credentials.put(
            "cloudflare-denied-policy-read", "fixture-denied-token")
        self.server.read_denied = True
        result = self.run_enrollment()
        self.assertEqual(result.state, "pending")
        self.assertEqual(result.policy_read_state, "pending")
        self.assertEqual(len(self.server.apps), 1)
        self.assertEqual(len(self.server.identity_providers), 1)
        self.assertEqual(self.route_effects(), [])
        self.assertNotIn("fixture-policy-token", Path(self.journal.path).read_bytes().decode("latin1"))
        self.assertNotIn("fixture-denied-token", Path(self.journal.path).read_bytes().decode("latin1"))
        self.assertNotIn("leak sentinel", result.message)

    def test_transient_access_failure_resumes_from_journal_without_duplicate_idp(self):
        self.server.fail_once.add(("POST", "/accounts/account-1/access/apps"))
        first = self.run_enrollment()
        self.assertEqual(first.state, "pending")
        self.assertEqual(len(self.server.identity_providers), 1)
        self.assertEqual(self.server.apps, [])
        self.assertEqual(self.route_effects(), [])

        second = self.run_enrollment()
        self.assertEqual(second.access_state, "ready")
        self.assertEqual(len(self.server.identity_providers), 1)
        self.assertEqual(len(self.server.apps), 1)
        self.assertEqual(self.route_effects(), [])
        idp_posts = [effect for effect in self.write_effects() if effect[1] == "/accounts/account-1/access/identity_providers"]
        self.assertEqual(len(idp_posts), 1)
        self.assertNotIn("leak sentinel", second.message)

    def test_route_activation_requires_root_bound_receipts_before_tunnel_or_dns(self):
        self.config["remote_desktop"]["policy_read_token_ref"] = self.read_ref
        result = self.run_enrollment(activate_route=True)
        self.assertEqual((result.state, result.policy_read_state, result.route_state),
                         ("pending", "verified", "pending"))
        self.assertTrue(result.component_installable)
        self.assertEqual(self.route_effects(), [])
        with_setup_only = self.run_enrollment(
            activate_route=True, setup_transaction_handle="A" * 43)
        self.assertEqual(with_setup_only.route_state, "pending")
        self.assertEqual(self.route_effects(), [])
        with_sink_only = self.run_enrollment(
            activate_route=True, setup_transaction_handle="A" * 43,
            runtime_token_writer=lambda *_args, **_kwargs: None)
        self.assertEqual(with_sink_only.route_state, "pending")
        self.assertEqual(self.route_effects(), [])
        self.assertIn("signed private-origin readiness receipt", with_sink_only.message)

    def test_foreign_hostname_access_application_is_preserved_before_any_write(self):
        self.server.apps.append({"id": "foreign-app", "name": "Existing user's app",
                                 "type": "self_hosted", "domain": "desktop.example.test",
                                 "allowed_idps": ["foreign-idp"]})
        result = self.run_enrollment()
        self.assertEqual(result.state, "failed")
        self.assertEqual(self.write_effects(), [])
        self.assertEqual(self.server.apps[0]["id"], "foreign-app")

    def test_corrupt_saved_owner_journal_fails_closed_before_access_mutation(self):
        from hermes_installer.remote.enrollment import _operation_key

        key = _operation_key("desktop.example.test")
        self.journal.checkpoint(key, "pending", {"remote_journal": {
            "schema": 1, "operation_id": "not-owned", "hostname": "desktop.example.test",
            "phase": "access_ready", "resources": {
                "access_app": {"kind": "access_app", "resource_id": "foreign-app",
                               "owner_marker": "other-operation", "created": True}},
            "completed": [], "error_code": None,
        }})
        result = self.run_enrollment()
        self.assertEqual(result.state, "failed")
        self.assertEqual(self.write_effects(), [])


if __name__ == "__main__":
    unittest.main()
