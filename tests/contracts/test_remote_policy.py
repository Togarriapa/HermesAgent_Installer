import threading
import unittest

from hermes_installer.remote.policy import AccessPolicyIdentity, FreshAccessPolicyAuthority


class FixtureClient:
    def __init__(self, app, provider, policies):
        self.app = app
        self.provider = provider
        self.policies = policies
        self.reads = []
        self.network = None

    def request(self, method, path, payload=None):
        self.reads.append((method, path))
        if method != "GET":
            raise AssertionError("policy authority must be read-only")
        if path.endswith("/access/apps/app-1"):
            return self.app
        if path.endswith("/access/identity_providers/idp-1"):
            return self.provider
        if "/policies?" in path:
            page = int(path.rsplit("page=", 1)[1])
            start = (page - 1) * 100
            return self.policies[start:start + 100]
        raise AssertionError("verifier attempted an unreviewed API path")


class FreshAccessPolicyAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.identity = AccessPolicyIdentity(
            account_id="acct-1",
            application_id="app-1",
            policy_id="policy-1",
            identity_provider_id="idp-1",
            hostname="desk.example.net",
            application_name="HermesInstaller:operation-1:desktop",
            policy_name="HermesInstaller:operation-1:allowed-emails",
            identity_provider_name="HermesInstaller:operation-1:email-code",
            allowed_emails=frozenset({"owner@example.net"}),
        )
        self.app = {
            "id": "app-1",
            "name": self.identity.application_name,
            "type": "self_hosted",
            "domain": "desk.example.net",
            "allowed_idps": ["idp-1"],
            "self_hosted_domains": [],
        }
        self.provider = {"id": "idp-1", "name": self.identity.identity_provider_name, "type": "onetimepin"}
        self.policy = {
            "id": "policy-1",
            "name": self.identity.policy_name,
            "decision": "allow",
            "include": [{"email": {"email": "owner@example.net"}}],
            "exclude": [],
            "require": [],
            "precedence": 1,
        }
        self.client = FixtureClient(self.app, self.provider, [self.policy])
        self.resolutions = []
        self.authority = FreshAccessPolicyAuthority(
            self.identity,
            "vault://remote/access-read",
            lambda ref: self.resolutions.append(ref) or "fixture-secret-value",
            lambda token: self.client,
        )

    def test_reads_exact_app_all_policies_and_otp_provider_without_cache(self):
        self.assertTrue(self.authority.allows("owner@example.net"))
        self.assertTrue(self.authority.allows("OWNER@example.net"))
        self.assertEqual(len(self.client.reads), 12)
        self.assertEqual(self.resolutions, ["vault://remote/access-read"] * 2)
        self.assertTrue(all(method == "GET" for method, _ in self.client.reads))
        self.assertNotIn("fixture-secret-value", repr(self.authority))

    def test_policy_removal_broadening_and_page_overflow_deny(self):
        self.assertTrue(self.authority.allows("owner@example.net"))
        self.client.policies = []
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.policies = [dict(self.policy, exclude=[{"email": {"email": "other@example.net"}}])]
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.policies = [self.policy, dict(self.policy, id="policy-2", name="foreign", include=[{"everyone": {}}])]
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.policies = [dict(self.policy, id=f"foreign-{i}", name=f"foreign-{i}") for i in range(500)]
        self.assertFalse(self.authority.allows("owner@example.net"))

    def test_changed_otp_app_and_unavailable_authority_deny(self):
        self.client.provider = dict(self.provider, type="github")
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.provider = self.provider
        self.client.app = dict(self.app, allowed_idps=["idp-1", "foreign"])
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.app = self.app
        self.client.provider = dict(self.provider, name="unowned")
        self.assertFalse(self.authority.allows("owner@example.net"))
        unavailable = FreshAccessPolicyAuthority(
            self.identity, "vault://remote/access-read",
            lambda _ref: (_ for _ in ()).throw(RuntimeError("unavailable")),
            lambda _token: self.client,
        )
        self.assertFalse(unavailable.allows("owner@example.net"))
        self.assertFalse(self.authority.allows("outsider@example.net"))

    def test_cancelled_or_expired_read_does_not_resolve_secret_or_call_api(self):
        cancel = threading.Event()
        cancel.set()
        self.assertFalse(self.authority.allows("owner@example.net", cancel_event=cancel))
        self.assertEqual(self.resolutions, [])
        self.assertEqual(self.client.reads, [])
