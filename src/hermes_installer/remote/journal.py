"""Remote durable-journal adapter. Caller owns process_lock and atomic write."""
from __future__ import annotations
from typing import Any,Callable,Mapping
from .lifecycle import OwnedResource,RemoteJournal,RemotePhase
KEY="remote_desktop"
def dump(j:RemoteJournal)->dict[str,Any]:
    return {"schema":1,"operation_id":j.operation_id,"hostname":j.hostname,"phase":j.phase.value,
      "resources":{k:{"kind":v.kind,"resource_id":v.resource_id,"owner_marker":v.owner_marker,"created":v.created} for k,v in j.resources.items()},
      "completed":sorted(j.completed),"error_code":j.error_code}
def load(raw:Mapping[str,Any]|None,*,operation_id:str,hostname:str)->RemoteJournal:
    if raw is None:return RemoteJournal(operation_id,hostname)
    if raw.get("schema")!=1 or raw.get("operation_id")!=operation_id or raw.get("hostname")!=hostname:raise ValueError("remote journal identity mismatch")
    resources={}
    for k,v in raw.get("resources",{}).items():
        if not isinstance(v,dict) or set(v)!={"kind","resource_id","owner_marker","created"} or k!=v["kind"] or v["owner_marker"]!=operation_id:raise ValueError("invalid remote journal resource")
        resources[k]=OwnedResource(**v)
    return RemoteJournal(operation_id,hostname,RemotePhase(raw["phase"]),resources,set(raw.get("completed",[])),raw.get("error_code"))
class SharedJournalAdapter:
    def __init__(self,read:Callable[[],Mapping[str,Any]],write:Callable[[Mapping[str,Any]],None],*,operation_id:str,hostname:str):
        self.read,self.write=read,write; self.operation_id,self.hostname=operation_id,hostname
        self.remote=load(read().get(KEY),operation_id=operation_id,hostname=hostname)
    def checkpoint(self,journal:RemoteJournal|None=None)->None:
        value=dict(self.read()); value[KEY]=dump(journal or self.remote); self.write(value)
    def recover(self)->RemoteJournal:
        self.remote=load(self.read().get(KEY),operation_id=self.operation_id,hostname=self.hostname); return self.remote
