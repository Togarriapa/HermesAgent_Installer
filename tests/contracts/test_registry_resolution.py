"""Validation against the pinned HermesAgent_Resources envelope."""
import unittest
from hermes_installer.registry.resolver import AuthorizationLease,RawResource,RegistryError,RegistryResolver,ResourceEvidence

class ResolverTests(unittest.TestCase):
    @staticmethod
    def raw(name,kind,version,*,requires=None,extends=None,capabilities=(),revision="a"*40,observed=None):
        doc={"apiVersion":"hermes.togarriapa/v1","kind":{"profiles":"Profile","skills":"Skill","plugins":"Plugin","mcps":"MCP","bundles":"Bundle","channels":"Channel","crons":"Cron","webhooks":"Webhook"}[kind],
             "metadata":{"name":name,"version":version},"spec":{"requires":requires or {},"capabilities":list(capabilities)}}
        if extends is not None: doc["spec"]["extends"]=extends
        return RawResource(name,kind,version,doc,"https://example.invalid/catalog",revision,observed or revision,RegistryResolver.document_digest(doc))
    def resolver(self,rows,now=lambda:100):
        return RegistryResolver(rows,source_verifier=lambda repo,rev:repo=="https://example.invalid/catalog" and len(rev)==40,now=now)
    def test_typed_dependencies_resolve_semver_before_host_authorization(self):
        rows={"app":self.raw("app","profiles","1.3.0",requires={"skills":["helper@^2.0.0"]},capabilities=("delegate","network")),
              "h2":self.raw("helper","skills","2.4.0",capabilities=("delegate",)),
              "h3":self.raw("helper","skills","3.0.0",capabilities=("delegate",))}
        resolver=self.resolver(rows); resolved=resolver.resolve(["profiles/app@~1.3.0"])
        self.assertEqual([(x.resource.kind.value,x.resource.id,x.resource.version) for x in resolved],[("skills","helper","2.4.0"),("profiles","app","1.3.0")])
        lease=AuthorizationLease("operator","profile","private",frozenset({"delegate"}),90,110,"policy-r4","grant")
        allowed=resolver.authorize(resolved,profile_id="profile",namespace="private",subject="operator",host_capabilities={"delegate","network"},lease_provider=lambda *_:lease)
        self.assertEqual(allowed[-1].capabilities,frozenset({"delegate"}))
        with self.assertRaises(RegistryError): resolver.activate(allowed,configure=lambda _:True,health_check=lambda _:True,runtime_revision="g1")
    def test_profile_extends_same_kind_and_detects_cycles(self):
        rows={"base":self.raw("base","profiles","1.2.0"),"child":self.raw("child","profiles","1.0.0",extends="base@^1.0.0")}
        result=self.resolver(rows).resolve(["profiles/child"])
        self.assertEqual([x.resource.id for x in result],["base","child"])
        cycle={"a":self.raw("a","profiles","1.0.0",extends="b"),"b":self.raw("b","profiles","1.0.0",extends="a")}
        with self.assertRaises(RegistryError): self.resolver(cycle).resolve(["profiles/a"])
    def test_runtime_requires_live_matching_lease_and_verified_source(self):
        resolver=self.resolver({"app":self.raw("app","profiles","1.0.0",capabilities=("delegate",))})
        raw=resolver.resolve(["profiles/app"])
        lease=AuthorizationLease("operator","profile","private",frozenset({"delegate"}),90,110,"p","g")
        allowed=resolver.authorize(raw,profile_id="profile",namespace="private",subject="operator",host_capabilities={"delegate"},lease_provider=lambda *_:lease)
        runtime=resolver.activate(allowed,configure=lambda _:True,health_check=lambda _:True,runtime_revision="generation-1")
        self.assertEqual(runtime[0].runtime_revision,"generation-1")
        wrong=AuthorizationLease("operator","other","private",frozenset({"delegate"}),90,110,"p","g")
        with self.assertRaises(RegistryError): resolver.authorize(raw,profile_id="profile",namespace="private",subject="operator",host_capabilities={"delegate"},lease_provider=lambda *_:wrong)
        unverified=self.raw("app","profiles","1.0.0",revision="a"*40,observed="b"*40)
        with self.assertRaises(RegistryError): self.resolver({"app":unverified}).resolve(["profiles/app"])
        with self.assertRaises(RegistryError): RegistryResolver({"app":self.raw("app","profiles","1.0.0")}).resolve(["profiles/app"])
    def test_missing_incompatible_or_unknown_requirements_fail_closed(self):
        with self.assertRaises(RegistryError): self.resolver({"app":self.raw("app","profiles","1.0.0",requires={"skills":["missing@^1.0.0"]})}).resolve(["profiles/app"])
        with self.assertRaises(RegistryError): self.resolver({"app":self.raw("app","profiles","1.0.0")}).resolve(["profiles/app@latest"])
    def test_readiness_distinguishes_actual_target_and_broker_evidence(self):
        ready=ResourceEvidence(downloaded=True,installed=True,discoverable=True,configured=True,authenticated=True,reachable=True,functionally_tested=True,enabled=True,actual_target_revision="sha",broker_healthy=True,host_authorization_fresh=True)
        self.assertTrue(RegistryResolver.readiness({"app":ready},["app"])["full_registry_compliance"])
        not_live=ResourceEvidence(downloaded=True,installed=True,discoverable=True,configured=True,authenticated=True,reachable=True,functionally_tested=True,enabled=True)
        self.assertFalse(RegistryResolver.readiness({"app":not_live},["app"])["full_registry_compliance"])
if __name__=="__main__": unittest.main()
