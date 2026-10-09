"""Provision journal-owned Cloudflare resources and activate exact DNS last."""
from __future__ import annotations
import hashlib,re
from dataclasses import dataclass,field
from typing import Any,Callable,Mapping
from .cloudflare import CloudflareClient,CloudflareError
from .config import RemoteSetup
from .lifecycle import OwnedResource,RemoteJournal

class RemoteConflict(RuntimeError): """An unowned or incompatible object blocks provisioning."""
@dataclass(frozen=True)
class ProvisionedRemote:
    tunnel_id:str
    access_app_id:str
    identity_provider_id:str
    dns_record_id:str
    runtime_token:str=field(repr=False,compare=False)

class RemoteCloudflareProvisioner:
    def __init__(self,client:CloudflareClient,setup:RemoteSetup,journal:RemoteJournal,*,checkpoint:Callable[[RemoteJournal],None],origin_ready:Callable[[],bool],gateway_port:int=8765):
        self.client,self.setup,self.journal=client,setup,journal
        self.checkpoint,self.origin_ready,self.gateway_port=checkpoint,origin_ready,gateway_port
        self.account,self.zone=setup.zone.account_id,setup.zone.zone_id
        self.marker="HermesInstaller:"+journal.operation_id
        self.tunnel_name="hermes-installer-"+hashlib.sha256((journal.operation_id+setup.hostname).encode()).hexdigest()[:20]
    def _rows(self,path:str,predicate:Callable[[dict[str,Any]],bool])->list[dict[str,Any]]:
        return [r for r in self.client.pages(path) if predicate(r)]
    @staticmethod
    def _id(row:Mapping[str,Any])->str:
        rid=row.get("id")
        if not isinstance(rid,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",rid):raise CloudflareError("Cloudflare returned an invalid resource identifier")
        return rid
    def _intent(self,step:str):
        self.journal.completed.add("intent:"+step); self.checkpoint(self.journal)
    def _save(self,step:str,kind:str,rid:str,created:bool):
        self.journal.record(step,OwnedResource(kind,rid,self.journal.operation_id,created)); self.checkpoint(self.journal)
    @staticmethod
    def _one(rows:list[dict[str,Any]],name:str):
        if len(rows)>1:raise RemoteConflict("Multiple "+name+" resources match; no changes made")
        return rows[0] if rows else None
    def _create(self,path:str,payload:dict[str,Any],predicate:Callable[[dict[str,Any]],bool],name:str)->dict[str,Any]:
        self._intent(name)
        try:
            value=self.client.request("POST",path,payload)
            if isinstance(value,dict):return value
        except CloudflareError:
            found=self._one(self._rows(path,predicate),name)
            if found:return found
            raise
        raise CloudflareError("Cloudflare did not return created "+name)
    def ensure_identity_provider(self)->str:
        path=f"/accounts/{self.account}/access/identity_providers"
        row=self._one(self._rows(path,lambda x:x.get("type")=="onetimepin"),"email-code identity provider")
        # Existing OTP can be shared safely because the app pins its exact ID.
        if row:return self._id(row)
        name=self.marker+":email-code"; payload={"name":name,"type":"onetimepin"}
        row=self._create(path,payload,lambda x:x.get("name")==name and x.get("type")=="onetimepin","identity provider")
        rid=self._id(row); self._save("identity_provider","identity_provider",rid,True); return rid
    def ensure_access_app(self,idp_id:str)->str:
        path=f"/accounts/{self.account}/access/apps"; host=self.setup.hostname; name=self.marker+":desktop"
        def matches(x):
            domains=([x.get("domain")] if isinstance(x.get("domain"),str) else [])
            domains+=x.get("self_hosted_domains",[]) if isinstance(x.get("self_hosted_domains"),list) else []
            return host in domains
        row=self._one(self._rows(path,matches),"hostname Access application")
        if row:
            if row.get("name")!=name or row.get("type") not in {"self_hosted","self_hosted_app"}:
                raise RemoteConflict("Hostname belongs to unowned or incompatible Access application")
            prior=self.journal.resources.get("access_app")
            if not prior and "intent:access_app" not in self.journal.completed:raise RemoteConflict("Access app is not present in the ownership journal")
            rid=self._id(row)
            if prior and prior.resource_id!=rid:raise RemoteConflict("Journaled Access app ID changed")
            if row.get("allowed_idps")!=[idp_id]:
                # Update only an app whose creation intent/ID is in this journal.
                self._intent("access_app_idp")
                row=self.client.request("PUT",path+"/"+rid,{"allowed_idps":[idp_id]})
                if not isinstance(row,dict):raise CloudflareError("Could not restrict Access identity providers")
            self._save("access_app","access_app",rid,bool(prior and prior.created)); return rid
        payload={"name":name,"type":"self_hosted","domain":host,"allowed_idps":[idp_id],
                 "auto_redirect_to_identity":False,"session_duration":"24h"}
        row=self._create(path,payload,lambda x:x.get("name")==name and x.get("domain")==host,"Access application")
        rid=self._id(row); self._save("access_app","access_app",rid,True); return rid
    def ensure_email_policy(self,app_id:str):
        path=f"/accounts/{self.account}/access/apps/{app_id}/policies"
        emails=sorted({e.casefold() for e in self.setup.allowed_emails})
        include=[{"email":{"email":e}} for e in emails]; name=self.marker+":allowed-emails"
        row=self._one(self._rows(path,lambda x:x.get("name")==name),"installer Access policy")
        if row:
            if row.get("decision")!="allow" or row.get("include")!=include:raise RemoteConflict("Owned Access allowlist differs from setup")
            self._save("access_policy","access_policy",self._id(row),False); return
        if self._rows(path,lambda x:x.get("decision")=="allow"):
            raise RemoteConflict("An unowned Access allow policy exists; refusing to widen access")
        payload={"name":name,"decision":"allow","include":include,"exclude":[],"require":[],"precedence":1}
        row=self._create(path,payload,lambda x:x.get("name")==name,"Access policy")
        self._save("access_policy","access_policy",self._id(row),True)
    def ensure_tunnel(self)->tuple[str,str]:
        path=f"/accounts/{self.account}/cfd_tunnel"; name=self.tunnel_name
        row=self._one(self._rows(path,lambda x:x.get("name")==name and x.get("config_src")=="cloudflare"),"installer tunnel")
        prior=self.journal.resources.get("tunnel")
        if row and not prior and "intent:tunnel" not in self.journal.completed:raise RemoteConflict("Same-named tunnel is not journal-owned")
        created=row is None
        if created:row=self._create(path,{"name":name,"config_src":"cloudflare"},lambda x:x.get("name")==name and x.get("config_src")=="cloudflare","tunnel")
        tid=self._id(row)
        if prior and prior.resource_id!=tid:raise RemoteConflict("Journaled tunnel ID changed")
        self._save("tunnel","tunnel",tid,created or bool(prior and prior.created))
        conf=f"/accounts/{self.account}/cfd_tunnel/{tid}/configurations"
        self._intent("tunnel_configuration")
        self.client.request("PUT",conf,{"config":{"ingress":[{"hostname":self.setup.hostname,"service":f"http://127.0.0.1:{self.gateway_port}"},{"service":"http_status:404"}]}})
        token=self.client.request("GET",f"/accounts/{self.account}/cfd_tunnel/{tid}/token")
        if not isinstance(token,str) or not token:raise CloudflareError("Runtime tunnel token unavailable")
        return tid,token
    def activate_dns(self,tunnel_id:str)->str:
        path=f"/zones/{self.zone}/dns_records"; host=self.setup.hostname; target=tunnel_id+".cfargotunnel.com"
        row=self._one(self._rows(path,lambda x:x.get("name","").rstrip(".").casefold()==host.casefold()),"hostname DNS record")
        prior=self.journal.resources.get("dns")
        if row:
            if not prior and "intent:dns" not in self.journal.completed:raise RemoteConflict("Hostname has an existing unowned DNS record")
            if prior and prior.resource_id!=row.get("id"):raise RemoteConflict("Journaled DNS record ID changed")
            if row.get("type")!="CNAME" or row.get("content")!=target or row.get("proxied") is not True:
                raise RemoteConflict("Journaled DNS record does not match guarded tunnel route")
            rid=self._id(row); created=bool(prior and prior.created)
        else:
            payload={"type":"CNAME","name":host,"content":target,"proxied":True,"comment":self.marker+":hostname"}
            row=self._create(path,payload,lambda x:x.get("name")==host and x.get("comment")==payload["comment"],"DNS record")
            rid=self._id(row); created=True
        self._save("dns","dns",rid,created); return rid
    def provision(self)->ProvisionedRemote:
        idp=self.ensure_identity_provider(); app=self.ensure_access_app(idp); self.ensure_email_policy(app)
        if not self.origin_ready():raise CloudflareError("Loopback gateway is not ready; hostname remains unpublished")
        tunnel,token=self.ensure_tunnel(); dns=self.activate_dns(tunnel)
        return ProvisionedRemote(tunnel,app,idp,dns,token)
