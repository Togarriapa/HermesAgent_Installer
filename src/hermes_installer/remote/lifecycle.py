"""Checkpointed ownership-aware remote setup phases."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Callable

class RemotePhase(StrEnum):
    EMPTY="empty"; CREDENTIALS="credentials_validated"; ACCESS_READY="access_ready"
    ORIGIN_READY="origin_ready"; TUNNEL_READY="tunnel_ready"; ACTIVE="active"; DISABLED="disabled"
_ORDER={RemotePhase.EMPTY:0,RemotePhase.CREDENTIALS:1,RemotePhase.ACCESS_READY:2,
        RemotePhase.ORIGIN_READY:3,RemotePhase.TUNNEL_READY:4,RemotePhase.ACTIVE:5,RemotePhase.DISABLED:0}

@dataclass(frozen=True)
class OwnedResource:
    kind:str; resource_id:str; owner_marker:str; created:bool

@dataclass
class RemoteJournal:
    operation_id:str
    hostname:str
    phase:RemotePhase=RemotePhase.EMPTY
    resources:dict[str,OwnedResource]=field(default_factory=dict)
    completed:set[str]=field(default_factory=set)
    error_code:str|None=None
    def record(self,step:str,resource:OwnedResource|None=None):
        if resource:
            old=self.resources.get(resource.kind)
            if old and old.resource_id!=resource.resource_id: raise ValueError("resource identity changed")
            self.resources[resource.kind]=resource
        self.completed.add(step)

def provision_fail_closed(journal:RemoteJournal,*,prepare_access:Callable[[],OwnedResource],
 prepare_origin:Callable[[],None],make_tunnel:Callable[[],OwnedResource],activate_route:Callable[[],None]):
    try:
        if _ORDER[journal.phase]<_ORDER[RemotePhase.ACCESS_READY]:
            journal.record("access",prepare_access()); journal.phase=RemotePhase.ACCESS_READY
        if _ORDER[journal.phase]<_ORDER[RemotePhase.ORIGIN_READY]:
            prepare_origin(); journal.record("origin"); journal.phase=RemotePhase.ORIGIN_READY
        if _ORDER[journal.phase]<_ORDER[RemotePhase.TUNNEL_READY]:
            journal.record("tunnel",make_tunnel()); journal.phase=RemotePhase.TUNNEL_READY
        if _ORDER[journal.phase]<_ORDER[RemotePhase.ACTIVE]:
            activate_route(); journal.record("route"); journal.phase=RemotePhase.ACTIVE
        return journal
    except Exception:
        journal.error_code="REMOTE_SETUP_INCOMPLETE"; raise

def owned_cleanup(journal:RemoteJournal,remove:Callable[[OwnedResource],None]):
    for r in reversed(tuple(journal.resources.values())):
        if r.created and r.owner_marker==journal.operation_id: remove(r)
