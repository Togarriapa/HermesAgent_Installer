import unittest
from hermes_installer.remote.cloudflare_setup import RemoteCloudflareProvisioner,RemoteConflict
from hermes_installer.remote.cloudflare import CloudflareZone,CloudflareError
from hermes_installer.remote.config import RemoteSetup
from hermes_installer.remote.lifecycle import RemoteJournal,RemotePhase
class Recorder:
 def __init__(self):self.rows={};self.calls=[];self.fail_dns=False
 def pages(self,path):self.calls.append(("GET",path,None));return list(self.rows.get(path,[]))
 def request(self,method,path,payload=None):
  self.calls.append((method,path,payload))
  if method=="POST":
   if self.fail_dns and path.endswith("/dns_records"):raise CloudflareError("fixture timeout")
   row={**(payload or {}),"id":"id-"+str(len(self.calls))};self.rows.setdefault(path,[]).append(row);return row
  if method=="DELETE":
   collection=path.rsplit("/",1)[0];rid=path.rsplit("/",1)[1];self.rows[collection]=[x for x in self.rows.get(collection,[]) if x.get("id")!=rid];return {"id":rid}
  if path.endswith("/token"):return "protected-runtime-token"
  if method=="PUT":return {"id":path.rsplit("/",1)[-1],**(payload or {})}
  return {"id":path.rsplit("/",1)[-1]}
class RemoteProvisionerTests(unittest.TestCase):
 def setUp(self):self.setup=RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret","keyring://hermes/access-read")
 def make(self,api,operation="op1",ready=True):
  snapshots=[];p=RemoteCloudflareProvisioner(api,self.setup,RemoteJournal(operation,self.setup.hostname),checkpoint=lambda j:snapshots.append((j.operation_id,set(j.completed))),origin_ready=lambda:ready,policy_read_check=lambda _journal:True);return p,snapshots
 def activate(self,p,writer=None):
  stored=[]
  result=p.provision_protected(runtime_token_writer=writer or stored.append)
  return result,stored
 def test_access_resources_checkpoint_without_route_and_resume_idempotently(self):
  api=Recorder();p,_=self.make(api,"op-access")
  prepared=p.prepare_access_resources()
  self.assertEqual(prepared.access_app_id,p.journal.resources["access_app"].resource_id)
  self.assertEqual(prepared.access_policy_id,p.journal.resources["access_policy"].resource_id)
  self.assertEqual(prepared.identity_provider_id,p.journal.resources["identity_provider"].resource_id)
  self.assertEqual(p.journal.phase,RemotePhase.ACCESS_READY)
  self.assertFalse(any(path.endswith("/dns_records") or path.endswith("/cfd_tunnel") for method,path,_ in api.calls if method in {"POST","PUT","DELETE"}))
  creates=sum(method=="POST" for method,_,_ in api.calls)
  self.assertEqual(p.prepare_access_resources(),prepared)
  self.assertEqual(sum(method=="POST" for method,_,_ in api.calls),creates)
 def test_policy_origin_tunnel_precede_dns_and_token_is_separate(self):
  api=Recorder();p,_=self.make(api);result,stored=self.activate(p);writes=[(i,m,path) for i,(m,path,_) in enumerate(api.calls)]
  policy=next(i for i,m,path in writes if m=="POST" and path.endswith("/policies"));dns=next(i for i,m,path in writes if m=="POST" and path.endswith("/dns_records"))
  self.assertLess(policy,dns);self.assertEqual(stored,["protected-runtime-token"]);self.assertFalse(hasattr(result,"runtime_token"));self.assertNotIn("protected-runtime-token",repr(result));self.assertIn("policy_read_verified",p.journal.completed);self.assertEqual(api.calls[dns][2]["content"],result.tunnel_id+".cfargotunnel.com");self.assertTrue(api.calls[dns][2]["proxied"]);self.assertEqual(p.journal.phase,RemotePhase.ACTIVE)
 def test_token_sink_failure_and_fresh_policy_denial_never_publish_dns(self):
  api=Recorder();p,_=self.make(api,"op-sink")
  with self.assertRaisesRegex(CloudflareError,"Protected tunnel-token storage failed"):
   p.provision_protected(runtime_token_writer=lambda _token:(_ for _ in ()).throw(RuntimeError("secret path detail")))
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
  self.assertNotIn("secret path detail",repr(p.journal))
  api=Recorder();p,_=self.make(api,"op-policy")
  p.policy_read_check=lambda _journal:False
  with self.assertRaisesRegex(CloudflareError,"Fresh protected Access"):
   p.provision_protected(runtime_token_writer=lambda _token:None)
  self.assertFalse(any(path.endswith("/cfd_tunnel") and m in {"POST","PUT"} for m,path,_ in api.calls))
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
 def test_missing_token_sink_has_no_cloudflare_effects(self):
  api=Recorder();p,_=self.make(api,"op-no-sink")
  with self.assertRaisesRegex(CloudflareError,"protected tunnel-token file writer"):
   p.provision_protected()
  self.assertEqual(api.calls,[])
 def test_unready_origin_rolls_back_owned_resources_and_never_publishes_dns(self):
  api=Recorder();p,_=self.make(api,"op2",False)
  with self.assertRaises(Exception):self.activate(p)[0]
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls));self.assertTrue({"identity_provider","access_app","access_policy"}.issubset(p.journal.resources));self.assertEqual(p.journal.phase,RemotePhase.ACCESS_READY)
 def test_missing_policy_read_reference_checkpoints_access_and_never_activates(self):
  from hermes_installer.remote.cloudflare_setup import PolicyReadReferenceRequired
  setup=RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret")
  api=Recorder();snapshots=[]
  p=RemoteCloudflareProvisioner(api,setup,RemoteJournal("op-read-ref",setup.hostname),checkpoint=lambda j:snapshots.append((j.phase,j.error_code,set(j.completed))),origin_ready=lambda:True)
  with self.assertRaisesRegex(PolicyReadReferenceRequired,"policy_read_token_ref"):
   p.provision_protected(runtime_token_writer=lambda _token:None)
  self.assertEqual(p.journal.phase,RemotePhase.ACCESS_READY)
  self.assertEqual(p.journal.error_code,"POLICY_READ_REFERENCE_REQUIRED")
  self.assertTrue({"identity_provider","access_app","access_policy"}.issubset(p.journal.resources))
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
  self.assertFalse(any(path.endswith("/cfd_tunnel") and m in {"POST","PUT"} for m,path,_ in api.calls))
  self.assertTrue(any("resume:policy_read_token_ref" in completed for _,_,completed in snapshots))
  resumed_setup=RemoteSetup(setup.hostname,setup.allowed_emails,setup.zone,setup.auth_domain,setup.management_token,"keyring://hermes/access-read")
  resumed=RemoteCloudflareProvisioner(api,resumed_setup,p.journal,checkpoint=lambda _j:None,origin_ready=lambda:True,policy_read_check=lambda _journal:True)
  activated=resumed.provision_protected(runtime_token_writer=lambda _token:None)
  self.assertEqual(resumed.journal.phase,RemotePhase.ACTIVE)
  self.assertTrue(activated.tunnel_id)
 def test_preflight_rejects_foreign_dns_before_any_mutation(self):
  api=Recorder();api.rows["/zones/z1/dns_records"]=[{"id":"foreign","name":self.setup.hostname,"type":"A","content":"192.0.2.1"}]
  p,_=self.make(api,"op3")
  with self.assertRaises(RemoteConflict):self.activate(p)[0]
  self.assertFalse(any(m in {"POST","PUT","DELETE"} for m,path,_ in api.calls))
 def test_unowned_allow_or_bypass_policy_is_preserved(self):
  api=Recorder();api.rows["/accounts/a1/access/apps/app/policies"]=[{"id":"foreign","name":"old","decision":"bypass"}]
  p,_=self.make(api,"op4")
  with self.assertRaises(RemoteConflict):p.ensure_email_policy("app")
  self.assertFalse(any(m=="POST" and path.endswith("/policies") for m,path,_ in api.calls))
 def test_ambiguous_dns_creation_failure_reconciles_then_rolls_back_only_owned(self):
  api=Recorder();api.fail_dns=True;p,_=self.make(api,"op5")
  with self.assertRaises(CloudflareError):self.activate(p)[0]
  self.assertIn("access_app",p.journal.resources);self.assertIn("tunnel",p.journal.resources)
  self.assertNotIn("dns",p.journal.resources);self.assertEqual(p.journal.phase,RemotePhase.TUNNEL_READY)
  self.assertTrue(any(rows for path,rows in api.rows.items() if path.endswith("/access/apps") or path.endswith("/cfd_tunnel")))
 def test_preflight_checks_existing_access_policy_before_identity_writes(self):
  from hermes_installer.remote.lifecycle import OwnedResource
  api=Recorder();p,_=self.make(api,"op6")
  p.journal.resources["access_app"]=OwnedResource("access_app","app","op6",True)
  api.rows["/accounts/a1/access/apps"]=[{"id":"app","name":"HermesInstaller:op6:desktop","type":"self_hosted","domain":self.setup.hostname,"allowed_idps":["idp"]}]
  api.rows["/accounts/a1/access/apps/app/policies"]=[{"id":"foreign","name":"bypass-old","decision":"bypass"}]
  with self.assertRaises(RemoteConflict):self.activate(p)[0]
  self.assertFalse(any(m in {"POST","PUT","DELETE"} for m,path,_ in api.calls))
