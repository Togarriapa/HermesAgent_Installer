"""Specialist failure/cancellation and broker side-effect contracts."""
import asyncio, types, unittest
from hermes_installer.topology import BrokerDenied, CapabilityLease, DispatchBroker, Orchestrator, RecruitmentDenied, SpecialistCall, WorkResult

def context(cancelled=lambda:False, sensitivity="PUBLIC"):
    return types.SimpleNamespace(profile_id="profile",purpose="native-hermes-chat",sensitivity=sensitivity,
        namespace="private",trace_id="trace-1",provenance=("trusted-server",),capabilities=frozenset({"delegate"}),cancelled=cancelled)

class TopologyTests(unittest.IsolatedAsyncioTestCase):
    def broker(self, authorize, now=lambda:10):
        return DispatchBroker(authorize=authorize,now=now)
    def lease(self, **kw):
        data=dict(profile_id="profile",namespace="private",trace_id="trace-1",capabilities=frozenset({"delegate"}),
            policy_revision="policy-r1",grant_id="g1",expires_at=100)
        data.update(kw); return CapabilityLease(**data)
    async def test_roster_denial_is_deterministic_and_starts_no_work(self):
        ran=[]
        async def worker(req): ran.append(1); return WorkResult(req.request_id,"worker","done")
        async def auth(ctx,call): return self.lease()
        orch=Orchestrator({"worker":worker,"denied":worker},{"worker":frozenset({"delegate"}),"denied":frozenset()},
            broker=self.broker(auth),context_factory=lambda _:context())
        with self.assertRaises(RecruitmentDenied): await orch.recruit("user","task",["worker","denied"])
        self.assertEqual(ran,[])
    async def test_broker_authorizes_before_effect_and_correlates_children(self):
        ran=[]
        async def worker(req):
            ran.append(req.child_id)
            return WorkResult(req.request_id,"worker","ok",dissent=("uncertain",),child_id=req.child_id)
        async def auth(ctx,call): return self.lease()
        orch=Orchestrator({"worker":worker},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:context())
        report=await orch.recruit_report("user","task",["worker"],request_id="af0e7bca-500f-43c2-a585-c5f7db2e4121")
        self.assertEqual(report.request_id,"af0e7bca-500f-43c2-a585-c5f7db2e4121")
        self.assertEqual(report.results[0].child_id,ran[0])
        self.assertEqual(report.results[0].dissent,("uncertain",))
    async def test_stale_lease_prevents_dispatch_effect(self):
        ran=[]
        async def worker(req): ran.append(1); return WorkResult(req.request_id,"worker","done")
        async def auth(ctx,call): return self.lease(expires_at=5)
        orch=Orchestrator({"worker":worker},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:context())
        with self.assertRaises(RuntimeError): await orch.recruit("u","t",["worker"])
        self.assertEqual(ran,[])
    async def test_failure_cancels_joins_sibling_and_request_cancel_is_observable(self):
        stopped=asyncio.Event()
        async def fail(req): await asyncio.sleep(0); raise ValueError("fixture failure")
        async def wait(req):
            try: await asyncio.Event().wait()
            finally: stopped.set()
        async def auth(ctx,call): return self.lease()
        orch=Orchestrator({"fail":fail,"wait":wait},{"fail":frozenset({"delegate"}),"wait":frozenset({"delegate"})},
            broker=self.broker(auth),context_factory=lambda _:context())
        with self.assertRaises(RuntimeError): await orch.recruit("u","t",["fail","wait"])
        self.assertTrue(stopped.is_set())
        entered=asyncio.Event(); cancelled=asyncio.Event()
        async def blocked(req):
            entered.set()
            try: await asyncio.Event().wait()
            finally: cancelled.set()
        orch=Orchestrator({"worker":blocked},{"worker":frozenset({"delegate"})},broker=self.broker(auth),context_factory=lambda _:context())
        task=asyncio.create_task(orch.recruit("u","t",["worker"],request_id="80eb7097-b78a-4538-bd1c-25442826758a"))
        await entered.wait()
        self.assertTrue(await orch.cancel("80eb7097-b78a-4538-bd1c-25442826758a"))
        with self.assertRaises(asyncio.CancelledError): await task
        self.assertTrue(cancelled.is_set())
    async def test_unknown_provenance_or_missing_context_capability_denies(self):
        effects=[]
        async def auth(ctx,call): return self.lease()
        async def run(): effects.append("effect")
        broker=self.broker(auth)
        call=SpecialistCall("worker","r","c","delegate",frozenset({"delegate"}))
        with self.assertRaises(BrokerDenied): await broker.call(context(sensitivity="UNKNOWN"),call,run)
        with self.assertRaises(BrokerDenied): await broker.call(types.SimpleNamespace(**{**context().__dict__,"provenance":()}),call,run)
        self.assertEqual(effects,[])

if __name__ == "__main__": unittest.main()
