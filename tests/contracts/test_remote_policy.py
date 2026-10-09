import unittest

from hermes_installer.remote.policy import AccessPolicyIdentity, FreshAccessPolicyAuthority


class FixtureClient:
    def __init__(self, app, policies):
        self.app = app
        self.policies = policies
        self.reads = []

    def request(self, method, path, payload=None):
        self.reads.append((method, path))
        if method != "GET":
            raise AssertionError("policy authority must be read-only")
        return self.app

    def pages(self, path, *, filters=None):
        self.reads.append(("GET pages", path))
        return self.policies


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
        self.policy = {
            "id": "policy-1",
            "name": self.identity.policy_name,
            "decision": "allow",
            "include": [{"email": {"email": "owner@example.net"}}],
            "exclude": [],
            "require": [],
        }
        self.client = FixtureClient(self.app, [self.policy])
        self.resolutions = []
        self.authority = FreshAccessPolicyAuthority(
            self.identity,
            "vault://remote/access-read",
            lambda ref: self.resolutions.append(ref) or "fixture-secret-value",
            lambda token: self.client,
        )

    def test_requires_fresh_exact_application_and_policy_each_time(self):
        self.assertTrue(self.authority.allows("owner@example.net"))
        self.assertTrue(self.authority.allows("OWNER@example.net"))
        self.assertEqual(len(self.client.reads), 4)
        self.assertEqual(self.resolutions, ["vault://remote/access-read"] * 2)
        self.assertNotIn("fixture-secret-value", repr(self.authority))

    def test_policy_removal_and_broadening_deny_same_jwt_principal(self):
        self.assertTrue(self.authority.allows("owner@example.net"))
        self.client.policies = []
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.policies = [dict(self.policy, exclude=[{"email": {"email": "other@example.net"}}])]
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.policies = [self.policy, dict(self.policy, id="policy-2", name="other", include=[{"everyone": {}}])]
        self.assertFalse(self.authority.allows("owner@example.net"))

    def test_changed_or_unowned_application_and_unavailable_authority_deny(self):
        self.client.app = dict(self.app, allowed_idps=["idp-1", "foreign"])
        self.assertFalse(self.authority.allows("owner@example.net"))
        self.client.app = self.app
        self.client.policies = [dict(self.policy, decision="bypass")]
        self.assertFalse(self.authority.allows("owner@example.net"))
        unavailable = FreshAccessPolicyAuthority(
            self.identity, "vault://remote/access-read",
            lambda _ref: (_ for _ in ()).throw(RuntimeError("unavailable")),
            lambda _token: self.client,
        )
        self.assertFalse(unavailable.allows("owner@example.net"))
        self.assertFalse(self.authority.allows("outsider@example.net"))
