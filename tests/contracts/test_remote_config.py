from __future__ import annotations
import unittest
from hermes_installer.remote.config import RemoteConfigError, validate_emails, validate_hostname, collect_remote_setup
from hermes_installer.remote.cloudflare import CloudflareZone

class FakeClient:
    def __init__(self, token): self.token=token
    def discover_zones(self, hostname):
        self.hostname=hostname
        return (CloudflareZone("z1","example.uk","a1","active"),)
    def organization(self, account):
        return {"auth_domain":"team.example.cloudflareaccess.com"}

class RemoteConfigTests(unittest.TestCase):
    def test_no_hostname_default_or_prefill(self):
        prompts=[]
        def prompt(text): prompts.append(text); return ""
        with self.assertRaisesRegex(RemoteConfigError,"no default"): collect_remote_setup(interactive=True,input_fn=prompt,hidden_reader=lambda _: "secret",client_factory=FakeClient)
        self.assertIn("Hostname to publish",prompts[0])
        self.assertIn("leave blank",prompts[0])
    def test_explicit_hostname_and_email_validation(self):
        self.assertEqual(validate_hostname("Home.Example.UK"),"home.example.uk")
        with self.assertRaises(RemoteConfigError): validate_hostname("")
        self.assertEqual(validate_emails(["A@example.uk","a@example.uk"]),("a@example.uk",))
        with self.assertRaises(RemoteConfigError): validate_emails(["not-an-email"])
    def test_secure_interactive_collection_and_zone_discovery(self):
        prompts=iter(["home.example.uk","a@example.uk","keyring://hermes/access-read"])
        result=collect_remote_setup(interactive=True,input_fn=lambda _:next(prompts),hidden_reader=lambda _: "memory-only",client_factory=FakeClient)
        self.assertEqual(result.hostname,"home.example.uk")
        self.assertEqual(result.zone.zone_id,"z1")
        self.assertEqual(result.auth_domain,"team.example.cloudflareaccess.com")
        self.assertEqual(result.management_token,"memory-only")
        self.assertEqual(result.policy_read_token_ref,"keyring://hermes/access-read")
    def test_result_repr_does_not_expose_token_and_missing_zone_is_actionable(self):
        from hermes_installer.remote.config import RemoteSetup
        setup=RemoteSetup("home.example.uk",("a@example.uk",),CloudflareZone("z1","example.uk","a1","active"),"team.example.cloudflareaccess.com","sensitive")
        self.assertNotIn("sensitive",repr(setup))
        class NoMatch(FakeClient):
            def discover_zones(self, hostname): return ()
        prompts=iter(["home.example.uk","a@example.uk","keyring://hermes/access-read"])
        with self.assertRaisesRegex(RemoteConfigError,"No accessible active Cloudflare zone"):
            collect_remote_setup(interactive=True,input_fn=lambda _: next(prompts),hidden_reader=lambda _: "t",client_factory=NoMatch)
    def test_noninteractive_requires_secure_reference(self):
        with self.assertRaises(RemoteConfigError):
            collect_remote_setup(interactive=False,config={"hostname":"home.example.uk","allowed_emails":["a@example.uk"],"management_token":"inline"},client_factory=FakeClient)
        result=collect_remote_setup(interactive=False,config={"hostname":"home.example.uk","allowed_emails":["a@example.uk"],"management_token_ref":"env://CF"},environ={"CF":"token"},client_factory=FakeClient)
        self.assertEqual(result.management_token,"token")
        self.assertIsNone(result.policy_read_token_ref)

    def test_policy_read_reference_is_separate_and_reference_only(self):
        base={"hostname":"home.example.uk","allowed_emails":["a@example.uk"],"management_token_ref":"env://CF"}
        result=collect_remote_setup(interactive=False,config={**base,"policy_read_token_ref":"keyring://hermes/read"},environ={"CF":"setup-token"},client_factory=FakeClient)
        self.assertEqual(result.policy_read_token_ref,"keyring://hermes/read")
        with self.assertRaisesRegex(RemoteConfigError,"separate reference"):
            collect_remote_setup(interactive=False,config={**base,"policy_read_token_ref":"env://CF"},environ={"CF":"setup-token"},client_factory=FakeClient)
        with self.assertRaisesRegex(RemoteConfigError,"secure"):
            collect_remote_setup(interactive=False,config={**base,"policy_read_token_ref":"raw-secret"},environ={"CF":"setup-token"},client_factory=FakeClient)
        with self.assertRaisesRegex(RemoteConfigError,"protected"):
            collect_remote_setup(interactive=False,config={**base,"policy_read_token_ref":"env://CF"},environ={"CF":"setup-token"},client_factory=FakeClient)

if __name__ == "__main__": unittest.main()
