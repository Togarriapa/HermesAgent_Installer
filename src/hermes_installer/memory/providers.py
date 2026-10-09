"""Distinct client bridges for OpenViking, claude-mem and Agent Memory."""
from __future__ import annotations
from typing import Any,Protocol
from .lifecycle import MemoryRecord
class MemoryClient(Protocol):
    def capture(self,record:dict[str,Any])->Any:...
    def search(self,namespace:str,query:str,limit:int)->list[dict[str,Any]]:...
    def export(self,namespace:str)->list[dict[str,Any]]:...
    def remove(self,namespace:str,record_id:str)->bool:...
class NamespacedProvider:
    name="base"
    def __init__(self,client:MemoryClient,authorize):self.client=client; self.authorize=authorize
    def capture(self,record:MemoryRecord):
        ok,why=self.authorize(record.source,"memory_extraction")
        if not ok:raise PermissionError(why)
        self.client.capture({"id":record.id,"namespace":record.namespace,"profile":record.profile,"source":record.source,"text":record.text,"provenance":record.provenance})
    def search(self,namespace,query,limit):
        ok,why=self.authorize(namespace,"memory_retrieval")
        if not ok:raise PermissionError(why)
        return [MemoryRecord(str(r["id"]),str(r["namespace"]),str(r.get("profile","")),str(r.get("source","")),str(r["text"]),tuple(r.get("provenance",()))) for r in self.client.search(namespace,query,limit) if r.get("namespace")==namespace]
    def export(self,namespace):return [r for r in self.search(namespace,"",100) if r.namespace==namespace]
    def remove(self,namespace,record_id):return self.client.remove(namespace,record_id)
class OpenVikingProvider(NamespacedProvider):
    name="open_viking"
    def doctor(self):
        result=self.client.doctor()
        if not result.get("healthy"):raise RuntimeError("OpenViking doctor failed")
        return result
class ClaudeMemProvider(NamespacedProvider):name="claude_mem"
class AgentMemoryProvider(NamespacedProvider):name="agent_memory"
