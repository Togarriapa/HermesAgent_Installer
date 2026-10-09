"""Semver, provenance, authority and runtime effects using the standard library."""
import hashlib, json, unittest
from hermes_installer.registry.resolver import AuthorizationLease, RawResource, RegistryError, RegistryResolver, ResourceEvidence

class RegistryTests(unittest.TestCase):
    @staticmethod
    def raw(identity, version, requires=(), capabilities=(), revision="a"*40, observed=None):
        doc={"spec":{"requires":list(requires),"capabilities":list(capabilities)}}
        digest=RegistryResolver.document_digest(doc)
        return RawResource(identity,"profiles",version,doc,"https://example.invalid/catalog",revision,observed or revision,digest)
    def resolver(self, rows, now=lambda:100):
        return RegistryResolver(rows,source_verifier=lambda repository,revision: repository=="https://example.invalid/catalog" and len(revision)==40,now=now)

    def test_constrained_dependency_selects_compatible_version_then_authorizes(self):
        rows={"app":self.raw("app","1.3.0",("helper@^2.0.0",),("delegate","network")),
              "helper2":self.raw("helper","2.4.0",capabilities=("delegate",)),
              "helper3":self.raw("helper","3.0.0",capabilities=("delegate",))}
        resolver=self.resolver(rows)
        resolved=resolver.resolve(["app@~1.3.0"])
        self.assertEqual([(x.resource.id,x.resource.version) for x in resolved],[("helper","2.4.0"),("app","1.3.0")])
        lease=AuthorizationLease("operator","profile","private",frozenset({"delegate"}),90,110,"policy-v4","grant-1")
        authorized=resolver.authorize(resolved,profile_id="profile",namespace="private",subject="operator",
            host_capabilities={"delegate","network"},lease_provider=lambda *_:lease)
        self.assertEqual(authorized[-1].capabilities,frozenset({"delegate"}))
        with self.assertRaises(RegistryError): resolver.activate(authorized,configure=lambda _:True,health_check=lambda _:True,runtime_revision="g1")
    def test_successful_runtime_requires_configured_healthy_and_fresh_lease(self):
        resolver=self.resolver({"app":self.raw("app","1.0.0",capabilities=("delegate",))})
        resolved=resolver.resolve(["app"])
        lease=AuthorizationLease("operator","profile","private",frozenset({"delegate"}),90,110,"policy","grant")
        allowed=resolver.authorize(resolved,profile_id="profile",namespace="private",subject="operator",host_capabilities={"delegate"},lease_provider=lambda *_:lease)
        runtime=resolver.activate(allowed,configure=lambda _:True,health_check=lambda _:True,runtime_revision="gen-1")
        self.assertEqual(runtime[0].runtime_revision,"gen-1")
        with self.assertRaises(RegistryError): resolver.activate(allowed,configure=lambda _:True,health_check=lambda _:False,runtime_revision="gen-2")
    def test_stale_wrong_profile_or_unverified_commit_is_denied(self):
        stale=self.resolver({"app":self.raw("app","1.0.0",capabilities=("delegate",))},now=lambda:20)
        lease=AuthorizationLease("operator","other","private",frozenset({"delegate"}),1,10,"policy","grant")
        with self.assertRaises(RegistryError):
            stale.authorize(stale.resolve(["app"]),profile_id="profile",namespace="private",subject="operator",host_capabilities={"delegate"},lease_provider=lambda *_:lease)
        bad=self.raw("app","1.0.0",revision="a"*40,observed="b"*40)
        with self.assertRaises(RegistryError): self.resolver({"app":bad}).resolve(["app"])
    def test_cycles_missing_compatible_version_and_unknown_constraint_fail_closed(self):
        rows={"a":self.raw("a","1.0.0",("b@^1.0.0",)),"b":self.raw("b","1.1.0",("a@^1.0.0",))}
        resolver=self.resolver(rows)
        with self.assertRaises(RegistryError): resolver.resolve(["a"])
        with self.assertRaises(RegistryError): self.resolver({"a":self.raw("a","1.0.0")}).resolve(["a@^2.0.0"])
        with self.assertRaises(RegistryError): self.resolver({"a":self.raw("a","1.0.0")}).resolve(["a@latest"])
    def test_readiness_requires_actual_target_broker_health_and_fresh_host_authority(self):
        ready=ResourceEvidence(downloaded=True,installed=True,discoverable=True,configured=True,authenticated=True,
            reachable=True,functionally_tested=True,enabled=True,actual_target_revision="rev",broker_healthy=True,host_authorization_fresh=True)
        status=RegistryResolver.readiness({"app":ready},["app"])
        self.assertTrue(status["full_registry_compliance"])
        incomplete=ResourceEvidence(downloaded=True,installed=True,discoverable=True,configured=True,authenticated=True,
            reachable=True,functionally_tested=True,enabled=True)
        self.assertFalse(RegistryResolver.readiness({"app":incomplete},["app"])["full_registry_compliance"])

if __name__ == "__main__": unittest.main()
