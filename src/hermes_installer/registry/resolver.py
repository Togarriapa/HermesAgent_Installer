from __future__ import annotations
from collections.abc import Callable,Iterable,Mapping
from dataclasses import dataclass
from typing import Any
from .types import Resource
class RegistryError(ValueError):pass
@dataclass(frozen=True,slots=True)
class AuthorizedResource:
    resource:Resource; capabilities:frozenset[str]; unavailable_reasons:tuple[str,...]=()
class RegistryResolver:
    def __init__(self,resources:Mapping[str,Resource],host_capabilities:Iterable[str]=()):self.resources=dict(resources); self.host_capabilities=frozenset(host_capabilities)
    def resolve(self,selectors:Iterable[str])->tuple[Resource,...]:
        ordered=[]; visiting=set(); visited=set()
        def visit(key):
            if key in visited:return
            if key in visiting:raise RegistryError(f"dependency or inheritance cycle at {key}")
            item=self.resources.get(key)
            if item is None:raise RegistryError(f"required resource {key!r} is missing")
            visiting.add(key)
            for dep in (*item.inherits,*item.requires):visit(dep)
            visiting.remove(key); visited.add(key); ordered.append(item)
        for key in selectors:visit(key)
        return tuple(ordered)
    def authorize(self,resources:Iterable[Resource],policy:Callable[[Resource,str],tuple[bool,str|None]]):
        result=[]
        for item in resources:
            allow=set(); denied=[]
            for cap in sorted(item.capabilities):
                if cap not in self.host_capabilities:denied.append(f"host policy does not grant {cap}"); continue
                ok,reason=policy(item,cap)
                if ok:allow.add(cap)
                else:denied.append(reason or f"runtime authorization denied {cap}")
            result.append(AuthorizedResource(item,frozenset(allow),tuple(denied)))
        return tuple(result)
    @staticmethod
    def inherit(parent:Mapping[str,Any],child:Mapping[str,Any])->dict[str,Any]:
        result=dict(parent)
        for key,value in child.items():
            old=result.get(key); result[key]=RegistryResolver.inherit(old,value) if isinstance(old,Mapping) and isinstance(value,Mapping) else value
        return result
    @staticmethod
    def readiness(source_resolved:bool,text_core_ready:bool,states:Mapping[str,str],required:Iterable[str]):
        required=tuple(required)
        return {"source_resolved":source_resolved,"text_core_ready":text_core_ready,"resources":dict(states),"full_registry_compliance":bool(source_resolved and text_core_ready and required) and all(states.get(k)=="functionally_tested" for k in required)}
