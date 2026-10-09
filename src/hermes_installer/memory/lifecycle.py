from dataclasses import dataclass
from typing import Callable,Iterable,Protocol
@dataclass(frozen=True,slots=True)
class MemoryRecord:
    id:str; namespace:str; profile:str; source:str; text:str; provenance:tuple[str,...]=()
class Provider(Protocol):
    name:str
    def capture(self,record:MemoryRecord)->None:...
    def search(self,namespace:str,query:str,limit:int)->list[MemoryRecord]:...
    def export(self,namespace:str)->list[MemoryRecord]:...
    def remove(self,namespace:str,record_id:str)->bool:...
class MemoryManager:
    def __init__(self,providers:Iterable[Provider],route_allowed:Callable[[str,str],tuple[bool,str]]):self.providers={p.name:p for p in providers}; self.route_allowed=route_allowed; self.owner={}
    def select_owner(self,profile:str,name:str|None):
        if name is None:self.owner.pop(profile,None); return
        if name not in self.providers:raise ValueError(f"provider unavailable: {name}")
        self.owner[profile]=name
    def ingest(self,record:MemoryRecord,generated_by_memory:bool=False):
        if generated_by_memory or record.source.startswith("memory:"):raise PermissionError("recursive ingestion denied")
        owner=self.owner.get(record.profile)
        if owner is None:raise RuntimeError("profile has no capture owner")
        ok,reason=self.route_allowed(record.source,"memory_extraction")
        if not ok:raise PermissionError(reason)
        self.providers[owner].capture(record)
    def search(self,name:str,namespace:str,query:str,limit:int=10):
        if name not in self.providers:raise ValueError("provider unavailable")
        if not 1<=limit<=100:raise ValueError("limit outside 1..100")
        ok,reason=self.route_allowed(namespace,"memory_retrieval")
        if not ok:raise PermissionError(reason)
        return [r for r in self.providers[name].search(namespace,query,limit) if r.namespace==namespace][:limit]
