"""Offline discovery and safe native materialization of verified Hermes Resources."""
from __future__ import annotations
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from .resolver import RawResource, RegistryError, RegistryResolver, ResolvedResource, _merge_policy_values
from .source import VerifiedSource

_ROOTS=("profiles","skills","plugins","mcps","bundles","channels","crons","webhooks")

def _yaml():
    try: import yaml
    except ImportError: raise RegistryError("PyYAML is required for bundled Resources discovery") from None
    return yaml

def _load(data):
    try: return _yaml().safe_load(data.decode("utf-8"))
    except Exception as exc: raise RegistryError(f"invalid bundled YAML: {type(exc).__name__}") from None

@dataclass(frozen=True,slots=True)
class NativeDiscovery:
    resources: tuple[ResolvedResource,...]
    catalog_version: str
    source_revision: str
    root_counts: Mapping[str,int]

@dataclass(frozen=True,slots=True)
class NativeRegistry:
    source: VerifiedSource
    resolver: RegistryResolver
    paths: Mapping[str,str]
    catalog: Mapping[str,Any]
    root_counts: Mapping[str,int]

    @classmethod
    def from_verified_source(cls,source:VerifiedSource)->"NativeRegistry":
        catalog=_load(source.files["catalog.yaml"])
        if not isinstance(catalog,Mapping) or catalog.get("kind")!="Catalog" or not isinstance(catalog.get("spec"),Mapping):
            raise RegistryError("verified snapshot has no valid Hermes Catalog")
        policy={"domainOverlays":[]}
        qpaths=catalog["spec"].get("qualityPolicyFiles")
        if not isinstance(qpaths,(list,tuple)) or not qpaths: raise RegistryError("Catalog has no quality policy files")
        for path in qpaths:
            if not isinstance(path,str) or path not in source.files: raise RegistryError("quality policy is outside verified source")
            doc=_load(source.files[path])
            if not isinstance(doc,Mapping) or doc.get("kind")!="RegistryQualityPolicy" or not isinstance(doc.get("spec"),Mapping):
                raise RegistryError(f"invalid quality policy: {path}")
            spec=doc["spec"]; overlays=spec.get("domainOverlays") or []
            if not isinstance(overlays,(list,tuple)): raise RegistryError("domainOverlays must be a list")
            policy=_merge_policy_values(policy,{k:v for k,v in spec.items() if k!="domainOverlays"})
            policy["domainOverlays"]=list(policy.get("domainOverlays",()))+list(overlays)
        raw={}; paths={}; counts={}
        for root in _ROOTS:
            entries=sorted(p for p in source.files if p.startswith(root+"/") and p.endswith(".yaml"))
            counts[root]=len(entries)
            for path in entries:
                doc=_load(source.files[path])
                if not isinstance(doc,Mapping) or not isinstance(doc.get("metadata"),Mapping):
                    raise RegistryError(f"manifest envelope missing metadata: {path}")
                meta=doc["metadata"]; name,version=meta.get("name"),meta.get("version")
                if not isinstance(name,str) or not isinstance(version,str): raise RegistryError(f"manifest identity missing: {path}")
                key=f"{root}/{name}@{version}"
                if key in raw: raise RegistryError(f"duplicate manifest identity/version: {key}")
                raw[key]=RawResource(name,root,version,doc,source.repository,source.revision,source.revision,
                                     RegistryResolver.document_digest(doc))
                paths[key]=path
        resolver=RegistryResolver(raw,source_verifier=lambda repo,rev:repo==source.repository and rev==source.revision,
                                  quality_policy=policy)
        return cls(source,resolver,paths,catalog,counts)

    def discover(self,selectors:tuple[str,...]|list[str])->NativeDiscovery:
        return NativeDiscovery(self.resolver.resolve(selectors),self.source.catalog_version,self.source.revision,dict(self.root_counts))

    def discover_all(self)->NativeDiscovery:
        return self.discover(tuple(sorted(self.resolver.raw)))

    def materialize(self,discovery:NativeDiscovery|None=None)->dict[str,bytes]:
        import copy
        yaml=_yaml(); selected=discovery or self.discover_all(); out={}
        for item in selected.resources:
            key=f"{item.resource.kind.value}/{item.resource.id}@{item.resource.version}"
            doc=copy.deepcopy(dict(self.resolver.raw[key].document))
            effective=copy.deepcopy(dict(item.effective_spec or item.resource.body))
            # These bundled scheduled jobs used to fetch Togarriapa/HermesAgent_Resources.
            # The runtime form now addresses the Installer-owned immutable snapshot and
            # cannot fall back to the original repository or a moving branch.
            if item.resource.kind.value=="crons" and item.resource.id in {"resource-sync","daily-resource-reconcile"}:
                action=effective.get("action")
                if not isinstance(action,Mapping):
                    raise RegistryError(f"bundled update cron has no action mapping: {item.resource.id}")
                action=dict(action)
                action.pop("repository",None); action.pop("ref",None)
                action["type"]="installer-resource-candidate-assessment"
                action["source"]={"kind":"installer-bundle",
                    "path":f"resources/vendor/hermes-agent-resources-{self.source.catalog_version}",
                    "catalogVersion":self.source.catalog_version,"revision":self.source.revision}
                action["mode"]="candidate-assessment"
                effective["action"]=action
            doc["spec"]=effective
            meta=dict(doc.get("metadata") or {}); ann=dict(meta.get("annotations") or {})
            ann.update({"hermes.togarriapa/installer-source-revision":self.source.revision,
                "hermes.togarriapa/quality-policy-applied":"true",
                "hermes.togarriapa/host-authorization-applied":"false",
                "hermes.togarriapa/secrets-resolved":"false"})
            meta["annotations"]=ann; doc["metadata"]=meta
            out[self.paths[key]]=yaml.safe_dump(doc,sort_keys=False,allow_unicode=True).encode("utf-8")
        if not out: raise RegistryError("refusing to materialize an empty selection")
        # Keep the native discovery contract and policy document beside the
        # effective roots so Hermes can discover the selected manifests offline.
        out["catalog.yaml"]=self.source.files["catalog.yaml"]
        for quality_path in self.catalog["spec"]["qualityPolicyFiles"]:
            out[quality_path]=self.source.files[quality_path]
        return out

    def stage(self,store:Any,generation_id:str,discovery:NativeDiscovery|None=None):
        files=self.materialize(discovery)
        return store.stage(generation_id,files,file_modes={path:0o644 for path in files})
