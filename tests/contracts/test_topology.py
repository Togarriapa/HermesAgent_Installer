"""Broker and orchestration effects use only stdlib unittest."""
import asyncio, types, unittest
from hermes_installer.topology import BrokerDenied, CapabilityLease, DispatchBroker, Orchestrator, RecruitmentDenied, SpecialistCall, WorkResult

def ctx(*, cancelled=lambda:False, sensitivity="PUBLIC", effective=None, capabilities=frozenset({"delegate"}), provenance=("trusted-server",)):
    return types.SimpleNamespace(profile_id="profile", purpose="native-hermes-chat", sensitivity=sensitivity,
        effective_sensitivity=sensitivity if effective is None else effective, namespace="private", trace_id="trace-1",
        provenance=provenance, capabilities=capabilities, cancelled=cancelled)

class TopologyTests(unittest.IsolatedAsyncioTestCase):
    def broker(self, authorize):
        return DispatchBroker(authorize=authorize, now=lambda:10)
    def lease(self, **updates):
        values={"profile_id":"profile","namespace":"private","trace_id":"trace-1","capabilities":frozenset({"delegate"}),
            "policy_revision":"r1","grant_id":"grant","expires_at":100}
        values.update(updates); return CapabilityLease(**values)
    async def test_ungranted_roster_has_no_side_effect(self):
        effects=[]
        async def work(req): effects.append(1); return WorkResult(req.request_id,"worker","ok")
        async def auth(context,call): return self.lease()
        service=Orchestrator({"worker":work,"denied":work},{"worker":frozenset({"delegate"}),"denied":frozenset()},
            broker=self.broker(auth),context_factory=lambda _:ctx())
        with self.assertRaises(RecruitmentDenied): await service.recruit("user","task",["worker","denied"])
        self.assertEqual(effects,[])
    async def test_runtime_dispatch_returns_correlated_result(self):
        async def work(req): return WorkResult(req.request_id,"worker","ok",dissent=("uncertain",),child_id=req.child_id)
        async def auth(context,call): return self.lease()
        service=Orchestrator({"worker":work},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:ctx())
        report=await service.recruit_report("user","task",["worker"],request_id="af0e7bca-500f-43c2-a585-c5f7db2e4121")
        self.assertEqual(report.request_id,"af0e7bca-500f-43c2-a585-c5f7db2e4121")
        self.assertTrue(report.results[0].child_id)
        self.assertEqual(report.results[0].dissent,("uncertain",))
    async def test_expired_lease_prevents_side_effect(self):
        effects=[]
        async def work(req): effects.append(1); return WorkResult(req.request_id,"worker","ok")
        async def auth(context,call): return self.lease(expires_at=5)
        service=Orchestrator({"worker":work},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:ctx())
        with self.assertRaises(BrokerDenied): await service.recruit("u","t",["worker"])
        self.assertEqual(effects,[])
    async def test_failure_cancels_sibling_and_explicit_cancel_joins_child(self):
        stopped=asyncio.Event()
        async def fail(req): await asyncio.sleep(0); raise ValueError("fixture")
        async def wait(req):
            try: await asyncio.Event().wait()
            finally: stopped.set()
        async def auth(context,call): return self.lease()
        service=Orchestrator({"fail":fail,"wait":wait},{"fail":frozenset({"delegate"}),"wait":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:ctx())
        with self.assertRaises(RuntimeError): await service.recruit("u","t",["fail","wait"])
        self.assertTrue(stopped.is_set())
        entered=asyncio.Event(); cancelled=asyncio.Event()
        async def blocked(req):
            entered.set()
            try: await asyncio.Event().wait()
            finally: cancelled.set()
        service=Orchestrator({"worker":blocked},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:ctx())
        task=asyncio.create_task(service.recruit("u","t",["worker"],request_id="80eb7097-b78a-4538-bd1c-25442826758a"))
        await entered.wait()
        self.assertTrue(await service.cancel("80eb7097-b78a-4538-bd1c-25442826758a"))
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(cancelled.is_set())
    async def test_derived_private_classification_overrides_public_declaration(self):
        effects=[]
        async def authorize(context,call): return self.lease()
        async def effect(): effects.append(1)
        call=SpecialistCall("worker","r","c","delegate",frozenset({"delegate"}))
        with self.assertRaises(BrokerDenied):
            await self.broker(authorize).call(ctx(sensitivity="PUBLIC",effective="PRIVATE"),call,effect)
        self.assertEqual(effects,[])

    async def test_unknown_or_untrusted_context_is_denied_before_side_effect(self):
        effects=[]
        async def authorize(context,call): return self.lease()
        async def effect(): effects.append(1)
        gate=self.broker(authorize)
        call=SpecialistCall("worker","r","c","delegate",frozenset({"delegate"}))
        with self.assertRaises(BrokerDenied): await gate.call(ctx(sensitivity="UNKNOWN"),call,effect)
        with self.assertRaises(BrokerDenied): await gate.call(ctx(provenance=()),call,effect)
        with self.assertRaises(BrokerDenied): await gate.call(ctx(capabilities=frozenset()),call,effect)
        self.assertEqual(effects,[])
if __name__=="__main__": unittest.main()
