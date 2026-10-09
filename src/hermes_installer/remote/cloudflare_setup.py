"""Guarded, preflighted Cloudflare provisioning; public route is always last."""
from __future__ import annotations
import hashlib,re
from dataclasses import dataclass,field
from typing import Any,Callable,Mapping
from .cloudflare import CloudflareClient,CloudflareError
from .config import RemoteSetup
from .lifecycle import OwnedResource,RemoteJournal

class RemoteConflict(RuntimeError): pass
@dataclass(frozen=True)
class ProvisionedRemote:
    tunnel_id:str
    access_app_id:str
    identity_provider_id:str
    dns_record_id:str
    runtime_token:str=field(repr=False,compare=False)

class RemoteCloudflareProvisioner:
    """Only the caller-owned checkpoint callback persists state under process_lock."""
    def __init__(self,client:CloudflareClient,setup:RemoteSetup,journal:RemoteJournal,*,checkpoint:Callable[[RemoteJournal],None],origin_ready:Callable[[],bool],gateway_port:int=8765):
        self.client,self.setup,self.journal=client,setup,journal
        self.checkpoint,self.origin_ready,self.gateway_port=checkpoint,origin_ready,gateway_port
        self.account,self.zone=setup.zone.account_id,setup.zone.zone_id
        self.marker="HermesInstaller:"+journal.operation_id
        self.tunnel_name="hermes-installer-"+hashlib.sha256((journal.operation_id+setup.hostname).encode()).hexdigest()[:20]
    def _rows(self,path,predicate):
        return [r for r in self.client.pages(path) if predicate(r)]
    @staticmethod
    def _id(row):
        rid=row.get("id")
        if not isinstance(rid,str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",rid): raise CloudflareError("Cloudflare returned an invalid resource identifier")
        return rid
    def _intent(self,step):
        self.journal.completed.add("intent:"+step); self.checkpoint(self.journal)
    def _save(self,step,kind,rid,created):
        prior=self.journal.resources.get(kind)
        if prior and prior.resource_id!=rid: raise RemoteConflict("Journaled resource ID changed")
        created=created or bool(prior and prior.created)
        self.journal.record(step,OwnedResource(kind,rid,self.journal.operation_id,created)); self.checkpoint(self.journal)
    @staticmethod
    def _one(rows,label):
        if len(rows)>1: raise RemoteConflict("Multiple "+label+" resources match")
        return rows[0] if rows else None
    def _preflight(self):
        host=self.setup.hostname.casefold()
        dns=self._rows(f"/zones/{self.zone}/dns_records",lambda r:r.get("name","").rstrip(".").casefold()==host)
        if dns:
            prior=self.journal.resources.get("dns")
            if len(dns)!=1 or not prior or prior.resource_id!=dns[0].get("id"): raise RemoteConflict("Hostname has an existing unowned DNS record")
        apps=self._rows(f"/accounts/{self.account}/access/apps",lambda r:host in (([r.get("domain")] if isinstance(r.get("domain"),str) else [])+(r.get("self_hosted_domains",[]) if isinstance(r.get("self_hosted_domains"),list) else [])))
        if apps:
            prior=self.journal.resources.get("access_app")
            if len(apps)!=1 or not prior or prior.resource_id!=apps[0].get("id"): raise RemoteConflict("Hostname belongs to an unowned Access application")
        tunnels=self._rows(f"/accounts/{self.account}/cfd_tunnel",lambda r:r.get("name")==self.tunnel_name)
        if tunnels:
            prior=self.journal.resources.get("tunnel")
            if len(tunnels)!=1 or not prior or prior.resource_id!=tunnels[0].get("id"): raise RemoteConflict("Same-named tunnel is not journal-owned")
    def _create(self,path,payload,predicate,label,step):
        self._intent(step)
        try:
            value=self.client.request("POST",path,payload)
            if isinstance(value,dict): return value
        except CloudflareError:
            found=self._one(self._rows(path,predicate),label)
            if found: return found
            raise
        raise CloudflareError("Cloudflare did not return created "+label)
    def ensure_identity_provider(self):
        path=f"/accounts/{self.account}/access/identity_providers"
        matches=self._rows(path,lambda x:x.get("type")=="onetimepin")
        if len(matches)>1: raise RemoteConflict("Multiple OTP identity providers require explicit selection")
        if matches: return self._id(matches[0])
        name=self.marker+":email-code"
        row=self._create(path,{"name":name,"type":"onetimepin"},lambda x:x.get("name")==name and x.get("type")=="onetimepin","identity provider","identity_provider")
        rid=self._id(row); self._save("identity_provider","identity_provider",rid,True); return rid
    def ensure_access_app(self,idp_id):
        path=f"/accounts/{self.account}/access/apps"; host=self.setup.hostname; name=self.marker+":desktop"
        row=self._one(self._rows(path,lambda x:x.get("domain")==host or host in (x.get("self_hosted_domains") or [])),"hostname Access app")
        prior=self.journal.resources.get("access_app")
        if row:
            rid=self._id(row)
            if not prior or prior.resource_id!=rid or row.get("name")!=name: raise RemoteConflict("Hostname Access app is unowned")
            if row.get("allowed_idps")!=[idp_id]:
                self._intent("access_app_update")
                body={"name":name,"type":"self_hosted","domain":host,"self_hosted_domains":row.get("self_hosted_domains") or [],"allowed_idps":[idp_id],"auto_redirect_to_identity":False,"session_duration":row.get("session_duration") or "24h","options":row.get("options") or {}}
                row=self.client.request("PUT",path+"/"+rid,body)
                if not isinstance(row,dict) or row.get("allowed_idps")!=[idp_id]: raise CloudflareError("Access app protection update was not verified")
            self._save("access_app","access_app",rid,prior.created); return rid
        row=self._create(path,{"name":name,"type":"self_hosted","domain":host,"self_hosted_domains":[],"allowed_idps":[idp_id],"auto_redirect_to_identity":False,"session_duration":"24h","options":{}},lambda x:x.get("name")==name and x.get("domain")==host,"Access app","access_app")
        rid=self._id(row); self._save("access_app","access_app",rid,True); return rid
    def ensure_email_policy(self,app_id):
        path=f"/accounts/{self.account}/access/apps/{app_id}/policies"; policies=self.client.pages(path)
        name=self.marker+":allowed-emails"; include=[{"email":{"email":x.casefold()}} for x in sorted(set(self.setup.allowed_emails))]
        for p in policies:
            if p.get("decision") in {"bypass","non_identity","service_auth"}: raise RemoteConflict("Bypass or service-token policy conflicts with the protected app")
            if p.get("decision")=="allow" and p.get("name")!=name: raise RemoteConflict("Unowned Access allow policy conflicts with exact allowlist")
        row=self._one([p for p in policies if p.get("name")==name],"installer policy")
        if row:
            prior=self.journal.resources.get("access_policy")
            rid=self._id(row)
            if not prior or prior.resource_id!=rid: raise RemoteConflict("Same-named Access policy is not journal-owned")
            if row.get("decision")!="allow" or row.get("include")!=include or row.get("exclude") not in (None,[]) or row.get("require") not in (None,[]): raise RemoteConflict("Installer policy differs from exact email allowlist")
            self._save("access_policy","access_policy",rid,prior.created); return
        row=self._create(path,{"name":name,"decision":"allow","include":include,"exclude":[],"require":[],"precedence":1},lambda x:x.get("name")==name,"Access policy","access_policy")
        self._save("access_policy","access_policy",self._id(row),True)
    def ensure_tunnel(self):
        path=f"/accounts/{self.account}/cfd_tunnel"; prior=self.journal.resources.get("tunnel")
        row=self._one(self._rows(path,lambda x:x.get("name")==self.tunnel_name),"installer tunnel")
        created=row is None
        if row and (not prior or prior.resource_id!=row.get("id")): raise RemoteConflict("Same-named tunnel is not journal-owned")
        if row is None: row=self._create(path,{"name":self.tunnel_name,"config_src":"cloudflare"},lambda x:x.get("name")==self.tunnel_name,"tunnel","tunnel")
        rid=self._id(row); self._save("tunnel","tunnel",rid,created or bool(prior and prior.created))
        conf=f"/accounts/{self.account}/cfd_tunnel/{rid}/configurations"
        self._intent("tunnel_configuration")
        self.client.request("PUT",conf,{"config":{"ingress":[{"hostname":self.setup.hostname,"service":f"http://127.0.0.1:{self.gateway_port}"},{"service":"http_status:404"}]}})
        token=self.client.request("GET",f"/accounts/{self.account}/cfd_tunnel/{rid}/token")
        if not isinstance(token,str) or not token: raise CloudflareError("Runtime tunnel token unavailable")
        return rid,token
    def activate_dns(self,tunnel_id):
        path=f"/zones/{self.zone}/dns_records"; host=self.setup.hostname; target=tunnel_id+".cfargotunnel.com"; prior=self.journal.resources.get("dns")
        row=self._one(self._rows(path,lambda x:x.get("name","").rstrip(".").casefold()==host.casefold()),"hostname DNS")
        if row:
            rid=self._id(row)
            if not prior or prior.resource_id!=rid or row.get("type")!="CNAME" or row.get("content")!=target or row.get("proxied") is not True: raise RemoteConflict("Hostname DNS is not the journal-owned tunnel route")
            created=prior.created
        else:
            payload={"type":"CNAME","name":host,"content":target,"proxied":True,"comment":self.marker+":hostname"}
            row=self._create(path,payload,lambda x:x.get("name")==host and x.get("comment")==payload["comment"],"DNS record","dns")
            rid=self._id(row); created=True
        self._save("dns","dns",rid,created); return rid
    def provision(self):
        self._preflight() # no resource mutation before all exact conflicts have been checked
        idp=self.ensure_identity_provider(); app=self.ensure_access_app(idp); self.ensure_email_policy(app)
        if not self.origin_ready(): raise CloudflareError("Loopback gateway is not ready; hostname remains unpublished")
        tunnel,token=self.ensure_tunnel(); dns=self.activate_dns(tunnel)
        return ProvisionedRemote(tunnel,app,idp,dns,token)
