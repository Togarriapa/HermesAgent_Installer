"""On-demand component work with capability, privacy and resource ceilings."""
from dataclasses import dataclass
from typing import Callable,Mapping,Sequence
@dataclass(frozen=True,slots=True)
class Workload:
    id:str; argv:tuple[str,...]; environment:Mapping[str,str]; capabilities:frozenset[str]; memory_mb:int; timeout_seconds:int; mode:str="on_demand"
class WorkloadScheduler:
    def __init__(self,run:Callable,granted:frozenset[str],*,memory_budget_mb:int,max_workers:int=1):
        self.run=run; self.granted=granted; self.memory_budget_mb=memory_budget_mb; self.max_workers=max(1,max_workers); self.active=0
    def execute(self,work:Workload):
        if work.mode!="on_demand":raise PermissionError("component is not an approved on-demand workload")
        if not work.argv or work.argv[0].startswith("-") or any("\x00" in a for a in work.argv):raise ValueError("invalid fixed workload argv")
        missing=work.capabilities-self.granted
        if missing:raise PermissionError("capability denied: "+", ".join(sorted(missing)))
        if work.memory_mb<=0 or work.memory_mb>self.memory_budget_mb:raise MemoryError("workload exceeds reserved memory")
        if work.timeout_seconds<=0 or work.timeout_seconds>3600:raise TimeoutError("workload timeout outside policy")
        if self.active>=self.max_workers:raise RuntimeError("workload concurrency limit reached")
        self.active+=1
        try:return self.run(work.argv,dict(work.environment),timeout=work.timeout_seconds,memory_mb=work.memory_mb)
        finally:self.active-=1
