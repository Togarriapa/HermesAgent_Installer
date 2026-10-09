import asyncio
import pytest
from hermes_installer.topology import Orchestrator,WorkResult
@pytest.mark.asyncio
async def test_only_granted_correlated_internal_workers_run_and_cancel():
    seen=[]
    async def specialist(req):seen.append(req.request_id);return WorkResult(req.request_id,"worker","done",dissent=("uncertain",))
    orchestrator=Orchestrator({"worker":specialist,"denied":specialist},{"worker":frozenset({"delegate"}),"denied":frozenset()})
    results=await orchestrator.recruit("user","task",["worker","denied"])
    assert len(results)==1 and results[0].specialist=="worker" and results[0].dissent==("uncertain",)
    assert len(seen)==1
