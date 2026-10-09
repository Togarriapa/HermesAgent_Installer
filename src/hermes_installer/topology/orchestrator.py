import asyncio,uuid
from dataclasses import dataclass,field
from typing import Awaitable,Callable,Mapping,Sequence
@dataclass(frozen=True,slots=True)
class WorkRequest:
    request_id:str; user_id:str; task:str; parent_id:str|None=None
@dataclass(frozen=True,slots=True)
class WorkResult:
    request_id:str; specialist:str; content:str; evidence:tuple[str,...]=(); dissent:tuple[str,...]=()
Specialist=Callable[[WorkRequest],Awaitable[WorkResult]]
@dataclass
class Orchestrator:
    specialists:Mapping[str,Specialist]; grants:Mapping[str,frozenset[str]]; max_concurrency:int=3
    _active:dict[str,asyncio.Task]=field(default_factory=dict,init=False)
    async def recruit(self,user_id:str,task:str,roster:Sequence[str])->tuple[WorkResult,...]:
        rid=str(uuid.uuid4()); sem=asyncio.Semaphore(max(1,self.max_concurrency)); names=[n for n in roster if n in self.specialists and "delegate" in self.grants.get(n,frozenset())]
        async def invoke(name):
            async with sem:
                result=await self.specialists[name](WorkRequest(rid,user_id,task))
                if result.request_id!=rid or result.specialist!=name:raise ValueError("specialist correlation mismatch")
                return result
        jobs=[asyncio.create_task(invoke(name)) for name in names]; self._active[rid]=asyncio.current_task()
        try:return tuple(await asyncio.gather(*jobs))
        except asyncio.CancelledError:
            for job in jobs:job.cancel()
            await asyncio.gather(*jobs,return_exceptions=True); raise
        finally:self._active.pop(rid,None)
    async def cancel(self,request_id:str)->bool:
        task=self._active.get(request_id)
        if task is None:return False
        task.cancel(); return True
