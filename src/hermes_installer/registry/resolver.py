"""Typed source validation and raw/resolved/authorized/runtime registry phases."""
from __future__ import annotations
import hashlib, json, math, re, time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from functools import cmp_to_key
from typing import Any
from .types import Resource, ResourceKind

class RegistryError(ValueError):
    """Invalid source, manifest, dependency graph, policy, or runtime state."""

@dataclass(frozen=True, slots=True)
class RawResource:
    identity: str
    kind: str
    version: str
    document: Mapping[str, Any]
    repository: str
    selected_revision: str
    observed_revision: str
    content_digest: str

@dataclass(frozen=True, slots=True)
class ResolvedResource:
    resource: Resource
    dependencies: tuple[str, ...]
    provenance_verified: bool = True
    effective_spec: Mapping[str, Any] | None = None
    applied_overlays: tuple[str, ...] = ()

@dataclass(frozen=True, slots=True)
class AuthorizationLease:
    subject: str
    profile_id: str
    namespace: str
    capabilities: frozenset[str]
    issued_at: float
    expires_at: float
    policy_revision: str
    grant_id: str

@dataclass(frozen=True, slots=True)
class AuthorizedResource:
    resolved: ResolvedResource
    lease: AuthorizationLease
    capabilities: frozenset[str]
    denied: tuple[str, ...] = ()
    @property
    def resource(self): return self.resolved.resource

@dataclass(frozen=True, slots=True)
class RuntimeResource:
    authorized: AuthorizedResource
    configured: bool
    healthy: bool
    runtime_revision: str
    activated_at: float
    @property
    def resource(self): return self.authorized.resource

@dataclass(frozen=True, slots=True)
class ResourceEvidence:
    downloaded: bool = False
    installed: bool = False
    discoverable: bool = False
    configured: bool = False
    authenticated: bool = False
    reachable: bool = False
    functionally_tested: bool = False
    enabled: bool = False
    actual_target_revision: str | None = None
    broker_healthy: bool = False
    host_authorization_fresh: bool = False

_VERSION = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_CLAUSE = re.compile(r"(\^|~|>=|<=|>|<|=)?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)")
_KINDS = {kind.value: kind for kind in ResourceKind}
_SINGULAR = {ResourceKind.PROFILE:"Profile", ResourceKind.SKILL:"Skill", ResourceKind.PLUGIN:"Plugin",
    ResourceKind.MCP:"MCP", ResourceKind.BUNDLE:"Bundle", ResourceKind.CHANNEL:"Channel",
    ResourceKind.CRON:"Cron", ResourceKind.WEBHOOK:"Webhook"}

def _parts(value):
    match = _VERSION.fullmatch(value)
    if not match: raise RegistryError(f"invalid semantic version: {value!r}")
    prerelease = tuple(match[4].split(".")) if match[4] else None
    if prerelease and any(not item or (item.isdigit() and len(item) > 1 and item.startswith("0")) for item in prerelease):
        raise RegistryError(f"invalid semantic prerelease: {value!r}")
    return (int(match[1]),int(match[2]),int(match[3])),prerelease

def _compare(left,right):
    core_a,pre_a=_parts(left); core_b,pre_b=_parts(right)
    if core_a != core_b: return (core_a > core_b) - (core_a < core_b)
    if pre_a is None or pre_b is None: return 0 if pre_a is pre_b else (1 if pre_a is None else -1)
    for a,b in zip(pre_a,pre_b):
        if a==b: continue
        if a.isdigit() and b.isdigit(): return (int(a)>int(b))-(int(a)<int(b))
        if a.isdigit()!=b.isdigit(): return -1 if a.isdigit() else 1
        return (a>b)-(a<b)
    return (len(pre_a)>len(pre_b))-(len(pre_a)<len(pre_b))

def satisfies(version: str, expression: str) -> bool:
    _parts(version)
    if expression in {"","*"}: return True
    clauses=expression.split()
    if not clauses: raise RegistryError("empty semver constraint")
    for clause in clauses:
        match=_CLAUSE.fullmatch(clause)
        if not match: raise RegistryError(f"unsupported semver constraint: {expression!r}")
        op,target=match.groups(); op=op or "="; cmp=_compare(version,target)
        if op=="=" and cmp!=0 or op==">=" and cmp<0 or op==">" and cmp<=0 or op=="<=" and cmp>0 or op=="<" and cmp>=0: return False
        if op in {"^","~"}:
            (major,minor,patch),_=_parts(target)
            upper=(f"{major+1}.0.0" if major else f"0.{minor+1}.0" if minor else f"0.0.{patch+1}") if op=="^" else f"{major}.{minor+1}.0"
            if cmp<0 or _compare(version,upper)>=0: return False
    return True

def _merge_policy_values(low: Any, high: Any) -> Any:
    """Match pinned registry merge semantics: recursive mappings, stable list union."""
    if isinstance(low,dict) and isinstance(high,Mapping):
        out=dict(low)
        for key,value in high.items():
            out[key]=_merge_policy_values(out[key],value) if key in out else value
        return out
    if isinstance(low,list) and isinstance(high,(list,tuple)):
        out=list(low)
        for value in high:
            if value not in out: out.append(value)
        return out
    if isinstance(high,Mapping): return dict(high)
    if isinstance(high,(list,tuple)): return list(high)
    return high

def _policy_overlay_matches(name: str, tags: set[str], match: Mapping[str,Any]) -> bool:
    contains=match.get("nameContains") or []
    tags_any=set(match.get("tagsAny") or [])
    if not isinstance(contains,(list,tuple)) or any(not isinstance(x,str) for x in contains): return False
    if not isinstance(match.get("tagsAny") or [],(list,tuple)): return False
    return any(fragment in name for fragment in contains) or bool(tags & tags_any)

class RegistryResolver:
    def __init__(self, resources: Mapping[str,RawResource], *,
                 source_verifier: Callable[[str,str],bool] | None = None, now: Callable[[],float] = time.time,
                 quality_policy: Mapping[str, Any] | None = None):
        self.raw=dict(resources); self.source_verifier=source_verifier; self.now=now
        self.quality_policy=dict(quality_policy or {})

    @staticmethod
    def document_digest(document: Mapping[str,Any]) -> str:
        try: encoded=json.dumps(document,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
        except (TypeError,ValueError): raise RegistryError("manifest is not canonical JSON-compatible data") from None
        return hashlib.sha256(b"hermes-resource-v1\0"+len(encoded).to_bytes(8,"big")+encoded).hexdigest()

    def _parse(self, raw: RawResource) -> Resource:
        if not isinstance(raw.document, Mapping):
            raise RegistryError("raw manifest document must be a mapping")
        try:
            source_ok = self.source_verifier is not None and self.source_verifier(raw.repository, raw.selected_revision)
        except Exception as error:
            raise RegistryError(f"pinned source verifier failed: {type(error).__name__}") from None
        if (raw.selected_revision != raw.observed_revision
            or not re.fullmatch(r"[a-fA-F0-9]{40,64}", raw.selected_revision) or not source_ok):
            raise RegistryError(f"pinned source commit was not independently verified: {raw.identity}")
        if not raw.repository.startswith("https://") or "@" in raw.repository: raise RegistryError("registry source must use HTTPS without credentials")
        if self.document_digest(raw.document)!=raw.content_digest: raise RegistryError(f"resource digest mismatch: {raw.identity}")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",raw.identity): raise RegistryError("identity must be lowercase kebab case")
        try: kind=ResourceKind(raw.kind)
        except ValueError: raise RegistryError(f"unrecognized catalog root: {raw.kind}") from None
        _parts(raw.version)
        metadata=raw.document.get("metadata")
        spec=raw.document.get("spec")
        if (raw.document.get("apiVersion")!="hermes.togarriapa/v1" or raw.document.get("kind")!=_SINGULAR[kind]
            or not isinstance(metadata,Mapping) or metadata.get("name")!=raw.identity or metadata.get("version")!=raw.version
            or not isinstance(spec,Mapping)):
            raise RegistryError(f"manifest envelope/root/filename identity mismatch: {raw.identity}")
        self._references(spec,kind)
        extends = spec.get("extends", [])
        if isinstance(extends, str): extends = [extends]
        inherited = tuple(f"{kind.value}/{identity}@{expr}" for identity, expr in (self._selector(x) for x in extends))
        required = []
        for root, selectors in spec.get("requires", {}).items():
            dependency_kind = _KINDS.get(root)
            required.extend(f"{dependency_kind.value}/{identity}@{expr}" for identity, expr in
                            (self._selector(x) for x in selectors))
        caps=spec.get("capabilities",[])
        if isinstance(caps,(list,tuple)):
            if any(not isinstance(cap,str) or not cap for cap in caps): raise RegistryError("capabilities list contains an invalid entry")
            flat_caps=frozenset(caps)
        elif isinstance(caps,Mapping):
            if any(not isinstance(key,str) or not key for key in caps): raise RegistryError("structured capability keys must be nonempty strings")
            flat_caps=frozenset()
        else: raise RegistryError("capabilities must be a list or structured mapping")
        return Resource(raw.identity,kind,raw.version,dict(spec),raw.selected_revision,tuple(required),inherited,flat_caps,raw.content_digest)

    @staticmethod
    def _references(spec: Mapping[str,Any], own_kind: ResourceKind):
        refs=[]
        extends=spec.get("extends",[])
        if isinstance(extends,str): extends=[extends]
        if not isinstance(extends,(tuple,list)): raise RegistryError("spec.extends must be a selector or list")
        for selector in extends: refs.append((own_kind,*RegistryResolver._selector(selector)))
        required=spec.get("requires",{})
        if not isinstance(required,Mapping): raise RegistryError("spec.requires must map catalog roots to selectors")
        for root,selectors in required.items():
            kind=_KINDS.get(root)
            if kind is None: raise RegistryError(f"unknown dependency root: {root}")
            if not isinstance(selectors,(tuple,list)): raise RegistryError(f"requires.{root} must be a list")
            for selector in selectors: refs.append((kind,*RegistryResolver._selector(selector)))
        imports=spec.get("imports",{})
        if not isinstance(imports,Mapping): raise RegistryError("spec.imports must map catalog roots to selectors")
        for root,selectors in imports.items():
            kind=_KINDS.get(root)
            if kind is None: raise RegistryError(f"unknown import root: {root}")
            if not isinstance(selectors,(tuple,list)): raise RegistryError(f"imports.{root} must be a list")
            for selector in selectors: refs.append((kind,*RegistryResolver._selector(selector)))
        return tuple(refs)

    @staticmethod
    def _selector(value):
        if not isinstance(value,str) or not value: raise RegistryError("dependency selector must be text")
        identity,marked,expr=value.partition("@")
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*",identity): raise RegistryError(f"invalid dependency identity: {identity!r}")
        if marked: satisfies("0.0.0",expr)
        return identity,expr if marked else "*"

    def resolve(self, selectors: Iterable[str]) -> tuple[ResolvedResource,...]:
        catalog={}
        for raw in self.raw.values():
            item=self._parse(raw); catalog.setdefault((item.kind,item.id),[]).append(item)
        for items in catalog.values(): items.sort(key=cmp_to_key(lambda a,b:_compare(a.version,b.version)),reverse=True)
        ordered=[]; visited=set(); active=set(); effective_cache={}
        def select(kind,identity,expr):
            candidates=[item for item in catalog.get((kind,identity),()) if satisfies(item.version,expr)]
            if not candidates: raise RegistryError(f"no compatible resource: {kind.value}/{identity}@{expr}")
            return candidates[0]
        def visit(kind,identity,expr):
            item=select(kind,identity,expr); node=(kind,item.id,item.version)
            if node in active: raise RegistryError(f"dependency or inheritance cycle at {kind.value}/{item.id}@{item.version}")
            if node in visited: return
            active.add(node); dependencies=[]
            for dep_kind,dep_id,dep_expr in self._references(item.body,kind):
                dep=select(dep_kind,dep_id,dep_expr)
                dependencies.append(f"{dep_kind.value}/{dep.id}@{dep.version}")
                visit(dep_kind,dep_id,dep_expr)
            active.remove(node); visited.add(node)
            # Resolve spec.extends recursively, then apply source QUALITY_POLICY in its
            # documented order. Keep Resource.capabilities as the raw manifest list;
            # policy capabilities are a separate effective field and never enter it.
            def inherit(current, stack=()):
                key=(current.kind,current.id,current.version)
                if key in stack: raise RegistryError(f"inheritance cycle at {current.kind.value}/{current.id}@{current.version}")
                cached=effective_cache.get(key)
                if cached is not None: return dict(cached)
                result={}
                extends=current.body.get("extends",[])
                if isinstance(extends,str): extends=[extends]
                for parent_id,parent_expr in (self._selector(value) for value in extends):
                    parent=select(current.kind,parent_id,parent_expr)
                    result=_merge_policy_values(result,inherit(parent,stack+(key,)))
                result=_merge_policy_values(result,current.body)
                effective_cache[key]=dict(result)
                return result
            raw=self.raw.get(f"{item.kind.value}/{item.id}@{item.version}")
            tags=set()
            if raw is not None:
                metadata=raw.document.get("metadata",{})
                if isinstance(metadata,Mapping) and isinstance(metadata.get("tags",[]),(tuple,list)):
                    tags={tag for tag in metadata.get("tags",[]) if isinstance(tag,str)}
            policy=self.quality_policy
            effective=dict(policy.get("universal") or {})
            defaults=policy.get("defaults") or {}
            if isinstance(defaults,Mapping): effective=_merge_policy_values(effective,defaults.get(item.kind.value) or {})
            overlays=[]
            for overlay in policy.get("domainOverlays") or []:
                if isinstance(overlay,Mapping) and _policy_overlay_matches(item.id,tags,overlay.get("match") or {}):
                    effective=_merge_policy_values(effective,overlay.get("apply") or {})
                    overlays.append(str(overlay.get("name", "unnamed")))
            effective=_merge_policy_values(effective,inherit(item))
            # Retain dependency order and raw Resource compatibility projections.
            ordered.append(ResolvedResource(item, tuple(dependencies), True, effective, tuple(overlays)))
        for selector in selectors:
            if not isinstance(selector,str) or not selector: raise RegistryError("root selector must be kind/name[@semver]")
            first,slash,tail=selector.partition("/")
            if slash:
                kind=_KINDS.get(first)
                if kind is None: raise RegistryError(f"unknown root selector kind: {first}")
                identity,marked,expr=tail.partition("@")
            else:
                identity,marked,expr=selector.partition("@")
                matches=[kind for kind,name in catalog if name==identity]
                if len(set(matches))!=1: raise RegistryError(f"root selector {identity!r} is ambiguous; include its kind")
                kind=matches[0]
            visit(kind,identity,expr if marked else "*")
        return tuple(ordered)

    def authorize(self,resources: Iterable[ResolvedResource], *, profile_id: str,namespace: str,subject: str,
                  host_capabilities: Iterable[str],lease_provider: Callable[[ResolvedResource,str,str,str],AuthorizationLease]):
        now,host,result=self.now(),frozenset(host_capabilities),[]
        for item in resources:
            lease=lease_provider(item,profile_id,namespace,subject)
            if (not item.provenance_verified or lease.subject!=subject or lease.profile_id!=profile_id or lease.namespace!=namespace
                or not math.isfinite(lease.issued_at) or not math.isfinite(lease.expires_at)
                or lease.issued_at > now or lease.expires_at <= now or lease.expires_at <= lease.issued_at
                or lease.expires_at - lease.issued_at > 3600 or not lease.policy_revision or not lease.grant_id):
                raise RegistryError(f"missing/stale/mismatched host lease for {item.resource.id}")
            allowed=item.resource.capabilities & host & lease.capabilities
            denied=set(item.resource.capabilities-allowed)
            if isinstance(item.resource.body.get("capabilities"),Mapping) and item.resource.body.get("capabilities"):
                denied.add("structured-capabilities-require-host-policy-adapter")
            result.append(AuthorizedResource(item,lease,frozenset(allowed),tuple(sorted(denied))))
        return tuple(result)

    def activate(self,resources: Iterable[AuthorizedResource], *, configure,health_check,runtime_revision: str):
        if not runtime_revision: raise RegistryError("runtime revision required")
        output=[]
        for item in resources:
            if item.denied: raise RegistryError(f"capabilities denied for {item.resource.id}: {item.denied}")
            if item.lease.expires_at<=self.now(): raise RegistryError("authorization expired before runtime activation")
            if not configure(item): raise RegistryError(f"configuration failed: {item.resource.id}")
            if not health_check(item): raise RegistryError(f"runtime health failed: {item.resource.id}")
            output.append(RuntimeResource(item,True,True,runtime_revision,self.now()))
        return tuple(output)

    @staticmethod
    def readiness(evidence: Mapping[str,ResourceEvidence],required: Iterable[str]):
        fields=("downloaded","installed","discoverable","configured","authenticated","reachable","functionally_tested","enabled")
        states={}
        for identity,facts in evidence.items():
            state="not_downloaded"
            for field in fields:
                if not getattr(facts,field): break
                state=field
            if facts.functionally_tested and facts.actual_target_revision: state="actual_target_verified"
            states[identity]=state
        required=tuple(required)
        ready=bool(required) and all(identity in evidence and evidence[identity].functionally_tested and evidence[identity].enabled
            and evidence[identity].actual_target_revision and evidence[identity].broker_healthy and evidence[identity].host_authorization_fresh
            for identity in required)
        return {"resources":states,"full_registry_compliance":bool(ready)}
