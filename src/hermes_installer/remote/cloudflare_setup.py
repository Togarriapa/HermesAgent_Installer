"""Guarded, preflighted Cloudflare provisioning; public route is always last."""
from __future__ import annotations
import hashlib,re
from dataclasses import dataclass
from typing import Any,Callable,Mapping
from .cloudflare import CloudflareClient,CloudflareError
from .config import RemoteSetup
from .lifecycle import OwnedResource,RemoteJournal,RemotePhase
from ..authority.remote_origin import (ProtectedTunnelTokenReceipt, RootOriginReadinessReceipt,
    ReceiptSigner, RemoteOriginDenied, verify_origin_receipt, verify_token_receipt)

class RemoteConflict(RuntimeError): pass
class PolicyReadReferenceRequired(RuntimeError):
    """Access setup is checkpointed, but no isolated read authority is configured."""
@dataclass(frozen=True)
class ProvisionedRemote:
    tunnel_id:str
    access_app_id:str
    identity_provider_id:str
    dns_record_id:str

@dataclass(frozen=True)
class PreparedAccessResources:
    access_app_id:str
    access_policy_id:str
    identity_provider_id:str

class RemoteCloudflareProvisioner:
    """Only the caller-owned checkpoint callback persists state under process_lock."""
    def __init__(self,client:CloudflareClient,setup:RemoteSetup,journal:RemoteJournal,*,checkpoint:Callable[[RemoteJournal],None],policy_read_check:Callable[[RemoteJournal],Any]|None=None,gateway_port:int=8765):
        self.client,self.setup,self.journal=client,setup,journal
        self.checkpoint,self.policy_read_check,self.gateway_port=checkpoint,policy_read_check,gateway_port
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
            tunnel=self.journal.resources.get("tunnel")
            if len(dns)!=1 or not prior or prior.resource_id!=dns[0].get("id") or not tunnel or dns[0].get("comment")!=self.marker+":hostname" or dns[0].get("type")!="CNAME" or dns[0].get("content")!=tunnel.resource_id+".cfargotunnel.com" or dns[0].get("proxied") is not True: raise RemoteConflict("Hostname has an existing unowned or changed DNS record")
        apps=self._rows(f"/accounts/{self.account}/access/apps",lambda r:host in (([r.get("domain")] if isinstance(r.get("domain"),str) else [])+(r.get("self_hosted_domains",[]) if isinstance(r.get("self_hosted_domains"),list) else [])))
        if apps:
            prior=self.journal.resources.get("access_app")
            if len(apps)!=1 or not prior or prior.resource_id!=apps[0].get("id"): raise RemoteConflict("Hostname belongs to an unowned Access application")
            # Inspect the complete policy set before the first POST/PUT. A retry
            # must not create an OTP provider or modify this app before noticing
            # a pre-existing bypass, service-token, or broadened allow rule.
            app=apps[0]
            policy_path=f"/accounts/{self.account}/access/apps/{prior.resource_id}/policies"
            policies=self.client.pages(policy_path)
            own_name=self.marker+":allowed-emails"
            exact_include=[{"email":{"email":email.casefold()}} for email in sorted(set(self.setup.allowed_emails))]
            journaled_policy=self.journal.resources.get("access_policy")
            for policy in policies:
                decision=policy.get("decision")
                if decision in {"bypass","non_identity","service_auth"}:
                    raise RemoteConflict("Bypass or service-token policy conflicts with the protected app")
                if decision=="allow" and policy.get("name")!=own_name:
                    raise RemoteConflict("Unowned Access allow policy conflicts with exact allowlist")
                if policy.get("name")==own_name:
                    if not journaled_policy or journaled_policy.resource_id!=policy.get("id"):
                        raise RemoteConflict("Same-named Access policy is not journal-owned")
                    if (decision!="allow" or policy.get("include")!=exact_include
                            or policy.get("exclude") not in (None,[])
                            or policy.get("require") not in (None,[])):
                        raise RemoteConflict("Installer policy differs from exact email allowlist")
        tunnels=self._rows(f"/accounts/{self.account}/cfd_tunnel",lambda r:r.get("name")==self.tunnel_name)
        if tunnels:
            prior=self.journal.resources.get("tunnel")
            if len(tunnels)!=1 or not prior or prior.resource_id!=tunnels[0].get("id"): raise RemoteConflict("Same-named tunnel is not journal-owned")
            if not prior.created:
                conf=self.client.request("GET",f"/accounts/{self.account}/cfd_tunnel/{prior.resource_id}/configurations")
                expected={"ingress":[{"hostname":self.setup.hostname,"service":f"http://127.0.0.1:{self.gateway_port}","originRequest":{"httpHostHeader":self.setup.hostname}},{"service":"http_status:404"}]}
                if not isinstance(conf,dict) or conf.get("config")!=expected: raise RemoteConflict("Refusing to overwrite pre-existing journaled tunnel configuration")
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
        path=f"/accounts/{self.account}/access/identity_providers"; name=self.marker+":email-code"
        rows=self._rows(path,lambda x:x.get("type")=="onetimepin")
        marked=[x for x in rows if x.get("name")==name]
        prior=self.journal.resources.get("identity_provider")
        if len(marked)>1: raise RemoteConflict("Multiple installer OTP providers match")
        if marked:
            rid=self._id(marked[0])
            if prior and prior.resource_id!=rid:raise RemoteConflict("Journaled identity-provider ID changed")
            if not prior and "intent:identity_provider" not in self.journal.completed:raise RemoteConflict("Same-named OTP provider is not journal-owned")
            self._save("identity_provider","identity_provider",rid,bool(prior and prior.created) or True);return rid
        if prior:
            if prior.created:raise RemoteConflict("Journaled identity provider is missing")
            matches=[x for x in rows if x.get("id")==prior.resource_id]
            if len(matches)!=1:raise RemoteConflict("Journaled shared identity provider is missing")
            return prior.resource_id
        if len(rows)>1:raise RemoteConflict("Multiple OTP identity providers require explicit selection")
        if rows:
            rid=self._id(rows[0]);self._save("identity_provider","identity_provider",rid,False);return rid
        row=self._create(path,{"name":name,"type":"onetimepin"},lambda x:x.get("name")==name and x.get("type")=="onetimepin","identity provider","identity_provider")
        rid=self._id(row);self._save("identity_provider","identity_provider",rid,True);return rid
    def ensure_access_app(self,idp_id):
        path=f"/accounts/{self.account}/access/apps"; host=self.setup.hostname; name=self.marker+":desktop"
        row=self._one(self._rows(path,lambda x:x.get("domain")==host or host in (x.get("self_hosted_domains") or [])),"hostname Access app")
        prior=self.journal.resources.get("access_app")
        if row:
            rid=self._id(row)
            if not prior or prior.resource_id!=rid or row.get("name")!=name: raise RemoteConflict("Hostname Access app is unowned")
            if row.get("allowed_idps")!=[idp_id]:
                if not prior.created: raise RemoteConflict("Refusing to overwrite pre-existing journaled Access app settings")
                self._intent("access_app_update")
                body={"name":name,"type":"self_hosted","domain":host,"self_hosted_domains":row.get("self_hosted_domains") or [],"allowed_idps":[idp_id],"auto_redirect_to_identity":False,"session_duration":row.get("session_duration") or "24h","options":row.get("options") or {}}
                row=self.client.request("PUT",path+"/"+rid,body)
                if not isinstance(row,dict) or row.get("allowed_idps")!=[idp_id] or row.get("domain")!=host or row.get("type") not in {"self_hosted","self_hosted_app"}: raise CloudflareError("Access app protection update was not verified")
            self._save("access_app","access_app",rid,prior.created); return rid
        row=self._create(path,{"name":name,"type":"self_hosted","domain":host,"self_hosted_domains":[],"allowed_idps":[idp_id],"auto_redirect_to_identity":False,"session_duration":"24h","options":{}},lambda x:x.get("name")==name and x.get("domain")==host,"Access app","access_app")
        if not isinstance(row,dict) or row.get("allowed_idps")!=[idp_id] or row.get("domain")!=host or row.get("type") not in {"self_hosted","self_hosted_app"}:raise CloudflareError("Created Access app protection was not verified")
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
        desired={"ingress":[{"hostname":self.setup.hostname,"service":f"http://127.0.0.1:{self.gateway_port}","originRequest":{"httpHostHeader":self.setup.hostname}},{"service":"http_status:404"}]}
        existing=self.client.request("GET",conf) if prior and not prior.created else None
        if existing is not None:
            if not isinstance(existing,dict) or existing.get("config")!=desired: raise RemoteConflict("Refusing to overwrite non-matching tunnel configuration")
        else:
            self._intent("tunnel_configuration")
            self.client.request("PUT",conf,{"config":desired})
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
    def prepare_access_resources(self):
        """Checkpoint exact owned Access resources before route activation."""
        self._preflight()
        try:
            idp=self.ensure_identity_provider()
            app=self.ensure_access_app(idp)
            self.ensure_email_policy(app)
            policy=self.journal.resources.get("access_policy")
            if policy is None:
                raise CloudflareError("Installer-owned Access policy was not checkpointed")
            self.journal.phase=RemotePhase.ACCESS_READY
            self.journal.completed.add("access_ready")
            self.journal.completed.discard("policy_read_verified")
            self.journal.error_code=None
            self.checkpoint(self.journal)
            return PreparedAccessResources(app,policy.resource_id,idp)
        except Exception:
            self.journal.error_code="ACCESS_SETUP_INCOMPLETE"
            self.checkpoint(self.journal)
            raise
    def provision_protected(self, *, runtime_token_writer: Callable[..., ProtectedTunnelTokenReceipt] | None = None,
                            setup_transaction_handle: str | None = None,
                            tunnel_enrollment_id: str | None = None,
                            tunnel_generation: str | None = None,
                            remote_enrollment_id: str | None = None,
                            origin_receipt: RootOriginReadinessReceipt | None = None,
                            receipt_signer: ReceiptSigner | None = None):
        """Require root-signed origin and protected-token receipts before DNS."""
        if (not callable(runtime_token_writer) or not setup_transaction_handle
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", setup_transaction_handle)
                or not tunnel_enrollment_id
                or not tunnel_generation or not remote_enrollment_id or receipt_signer is None):
            raise CloudflareError("Protected writer, active enrollment binding and receipt verifier are required")
        self._preflight() # no resource mutation before exact hostname conflicts are checked
        try:
            access=self.prepare_access_resources()
            idp,app=access.identity_provider_id,access.access_app_id
            if self.journal.phase.value not in {RemotePhase.ACCESS_READY.value,RemotePhase.ORIGIN_READY.value,RemotePhase.TUNNEL_READY.value,RemotePhase.ACTIVE.value}:
                self.journal.phase=RemotePhase.ACCESS_READY
                self.journal.completed.add("access_ready")
                self.checkpoint(self.journal)
            if not self.setup.policy_read_token_ref or not callable(self.policy_read_check):
                self.journal.phase=RemotePhase.ACCESS_READY
                self.journal.error_code="POLICY_READ_REFERENCE_REQUIRED"
                self.journal.completed.add("resume:policy_read_token_ref")
                self.checkpoint(self.journal)
                raise PolicyReadReferenceRequired(
                    "Owned Access setup is checkpointed; configure remote_desktop.policy_read_token_ref and its separate verifier before tunnel activation"
                )
            # Reverify the exact journal-owned app, complete policies and
            # identity provider on each activation attempt. Setup-time discovery
            # alone is not authority to publish the origin.
            try:
                if self.policy_read_check(self.journal) is not True:
                    raise CloudflareError("Fresh protected Access policy verification did not approve activation")
            except Exception:
                self.journal.phase=RemotePhase.ACCESS_READY
                self.journal.error_code="POLICY_READ_NOT_VERIFIED"
                self.journal.completed.discard("policy_read_verified")
                self.checkpoint(self.journal)
                raise CloudflareError("Fresh protected Access policy verification failed; hostname remains unpublished") from None
            self.journal.completed.add("policy_read_verified")
            self.checkpoint(self.journal)
            if not verify_origin_receipt(origin_receipt, receipt_signer,
                                         selected_enrollment_id=remote_enrollment_id):
                self.journal.phase=RemotePhase.ACCESS_READY
                self.journal.error_code="ORIGIN_READINESS_NOT_VERIFIED"
                self.journal.completed.discard("origin_ready")
                self.checkpoint(self.journal)
                raise CloudflareError("Root origin readiness receipt is absent, stale or invalid; hostname remains unpublished")
            if self.journal.phase.value not in {RemotePhase.ORIGIN_READY.value,RemotePhase.TUNNEL_READY.value,RemotePhase.ACTIVE.value}:
                self.journal.phase=RemotePhase.ORIGIN_READY
                self.journal.completed.add("origin_ready")
                self.checkpoint(self.journal)
            tunnel,token=self.ensure_tunnel()
            try:
                receipt = runtime_token_writer(
                    tunnel_enrollment_id, token.encode("ascii"),
                    setup_transaction_handle=setup_transaction_handle, account_id=self.account,
                    tunnel_id=tunnel, generation=tunnel_generation,
                )
                if (not verify_token_receipt(receipt, receipt_signer,
                                             selected_enrollment_id=tunnel_enrollment_id)
                        or receipt.tunnel_id != tunnel or receipt.generation != tunnel_generation
                        or receipt.owner_uid != 0 or receipt.mode != 0o400):
                    raise RemoteOriginDenied("protected token receipt did not match the selected root sink")
            except Exception:
                # Never include the token, callback exception, or path in the
                # journal/error surface. Public routing has not been activated.
                token = ""
                raise CloudflareError("Protected tunnel-token storage failed; public hostname remains unpublished") from None
            token = ""
            self.journal.completed.add("runtime_token_stored")
            self.checkpoint(self.journal)
            if self.journal.phase.value not in {RemotePhase.TUNNEL_READY.value,RemotePhase.ACTIVE.value}:
                self.journal.phase=RemotePhase.TUNNEL_READY
                self.journal.completed.add("tunnel_ready")
                self.checkpoint(self.journal)
            dns=self.activate_dns(tunnel)
            self.journal.phase=RemotePhase.ACTIVE
            self.journal.error_code=None
            self.journal.completed.add("active")
            self.checkpoint(self.journal)
            return ProvisionedRemote(tunnel,app,idp,dns)
        except PolicyReadReferenceRequired:
            # Preserve the exact journal-owned Access checkpoint so the setup
            # can resume when the separate verifier token reference is supplied.
            raise
        except CloudflareError as exc:
            if self.journal.error_code in {"POLICY_READ_NOT_VERIFIED", "POLICY_READ_REFERENCE_REQUIRED"}:
                raise
            self.journal.error_code="REMOTE_SETUP_INCOMPLETE"
            self.checkpoint(self.journal)
            raise
        except Exception:
            self.journal.error_code="REMOTE_SETUP_INCOMPLETE"
            self.checkpoint(self.journal)
            try:self.rollback()
            except Exception:pass
            raise

    def provision(self, *, runtime_token_writer: Callable[..., ProtectedTunnelTokenReceipt] | None = None,
                  setup_transaction_handle: str | None = None,
                  tunnel_enrollment_id: str | None = None,
                  tunnel_generation: str | None = None,
                  remote_enrollment_id: str | None = None,
                  origin_receipt: RootOriginReadinessReceipt | None = None,
                  receipt_signer: ReceiptSigner | None = None):
        """Compatibility name; protected verification and token storage are mandatory."""
        return self.provision_protected(runtime_token_writer=runtime_token_writer,
            setup_transaction_handle=setup_transaction_handle,
            tunnel_enrollment_id=tunnel_enrollment_id, tunnel_generation=tunnel_generation,
            remote_enrollment_id=remote_enrollment_id, origin_receipt=origin_receipt,
            receipt_signer=receipt_signer)
    def rollback(self):
        """Delete only journal-created, marker-matching resources in reverse order."""
        from .lifecycle import RemotePhase
        for kind in ("dns","tunnel","access_policy","access_app","identity_provider"):
            resource=self.journal.resources.get(kind)
            if not resource or not resource.created:continue
            if resource.owner_marker!=self.journal.operation_id:raise RemoteConflict("refusing rollback of foreign resource")
            if kind=="dns":
                path=f"/zones/{self.zone}/dns_records";rows=self._rows(path,lambda x:x.get("id")==resource.resource_id)
                tunnel=self.journal.resources.get("tunnel");target=(tunnel.resource_id+".cfargotunnel.com") if tunnel else None
                if rows and (rows[0].get("comment")!=self.marker+":hostname" or rows[0].get("type")!="CNAME" or rows[0].get("content")!=target or rows[0].get("proxied") is not True):raise RemoteConflict("refusing to remove changed DNS record")
                endpoint=path+"/"+resource.resource_id
            elif kind=="tunnel":
                path=f"/accounts/{self.account}/cfd_tunnel";rows=self._rows(path,lambda x:x.get("id")==resource.resource_id)
                if rows and rows[0].get("name")!=self.tunnel_name:raise RemoteConflict("refusing to remove changed tunnel")
                endpoint=path+"/"+resource.resource_id
            elif kind=="access_app":
                path=f"/accounts/{self.account}/access/apps";rows=self._rows(path,lambda x:x.get("id")==resource.resource_id)
                if rows and rows[0].get("name")!=self.marker+":desktop":raise RemoteConflict("refusing to remove changed Access app")
                endpoint=path+"/"+resource.resource_id
            elif kind=="access_policy":
                app=self.journal.resources.get("access_app")
                if not app:raise RemoteConflict("cannot identify owning Access app for rollback")
                path=f"/accounts/{self.account}/access/apps/{app.resource_id}/policies";rows=self._rows(path,lambda x:x.get("id")==resource.resource_id)
                if rows and rows[0].get("name")!=self.marker+":allowed-emails":raise RemoteConflict("refusing to remove changed Access policy")
                endpoint=path+"/"+resource.resource_id
            else:
                path=f"/accounts/{self.account}/access/identity_providers";rows=self._rows(path,lambda x:x.get("id")==resource.resource_id)
                if rows and (rows[0].get("name")!=self.marker+":email-code" or rows[0].get("type")!="onetimepin"):raise RemoteConflict("refusing to remove changed identity provider")
                endpoint=path+"/"+resource.resource_id
            self._intent("rollback:"+kind)
            try:
                if rows:self.client.request("DELETE",endpoint)
            except CloudflareError:
                if self._rows(path,lambda x:x.get("id")==resource.resource_id):raise
            if self._rows(path,lambda x:x.get("id")==resource.resource_id):raise CloudflareError("Remote rollback could not verify deletion")
            self.journal.resources.pop(kind,None);self.journal.completed.add("rolled_back:"+kind);self.checkpoint(self.journal)
        self.journal.phase=RemotePhase.DISABLED;self.journal.completed.add("rollback_complete");self.checkpoint(self.journal)
