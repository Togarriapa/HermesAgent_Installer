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
 def setUp(self):self.setup=RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret")
 def make(self,api,operation="op1",ready=True):
  snapshots=[];p=RemoteCloudflareProvisioner(api,self.setup,RemoteJournal(operation,self.setup.hostname),checkpoint=lambda j:snapshots.append((j.operation_id,set(j.completed))),origin_ready=lambda:ready);return p,snapshots
 def test_policy_origin_tunnel_precede_dns_and_token_is_separate(self):
  api=Recorder();p,_=self.make(api);result=p.provision();writes=[(i,m,path) for i,(m,path,_) in enumerate(api.calls)]
  policy=next(i for i,m,path in writes if m=="POST" and path.endswith("/policies"));dns=next(i for i,m,path in writes if m=="POST" and path.endswith("/dns_records"))
  self.assertLess(policy,dns);self.assertEqual(result.runtime_token,"protected-runtime-token");self.assertEqual(api.calls[dns][2]["content"],result.tunnel_id+".cfargotunnel.com");self.assertTrue(api.calls[dns][2]["proxied"])
 def test_unready_origin_rolls_back_owned_resources_and_never_publishes_dns(self):
  api=Recorder();p,_=self.make(api,"op2",False)
  with self.assertRaises(Exception):p.provision()
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls));self.assertFalse(p.journal.resources);self.assertEqual(p.journal.phase,RemotePhase.DISABLED)
 def test_preflight_rejects_foreign_dns_before_any_mutation(self):
  api=Recorder();api.rows["/zones/z1/dns_records"]=[{"id":"foreign","name":self.setup.hostname,"type":"A","content":"192.0.2.1"}]
  p,_=self.make(api,"op3")
  with self.assertRaises(RemoteConflict):p.provision()
  self.assertFalse(any(m in {"POST","PUT","DELETE"} for m,path,_ in api.calls))
 def test_unowned_allow_or_bypass_policy_is_preserved(self):
  api=Recorder();api.rows["/accounts/a1/access/apps/app/policies"]=[{"id":"foreign","name":"old","decision":"bypass"}]
  p,_=self.make(api,"op4")
  with self.assertRaises(RemoteConflict):p.ensure_email_policy("app")
  self.assertFalse(any(m=="POST" and path.endswith("/policies") for m,path,_ in api.calls))
 def test_ambiguous_dns_creation_failure_reconciles_then_rolls_back_only_owned(self):
  api=Recorder();api.fail_dns=True;p,_=self.make(api,"op5")
  with self.assertRaises(CloudflareError):p.provision()
  self.assertFalse(p.journal.resources);self.assertEqual(p.journal.phase,RemotePhase.DISABLED)
  self.assertFalse(any(rows for path,rows in api.rows.items() if path.endswith("/access/apps") or path.endswith("/cfd_tunnel")))
 def test_preflight_checks_existing_access_policy_before_identity_writes(self):
  from hermes_installer.remote.lifecycle import OwnedResource
  api=Recorder();p,_=self.make(api,"op6")
  p.journal.resources["access_app"]=OwnedResource("access_app","app","op6",True)
  api.rows["/accounts/a1/access/apps"]=[{"id":"app","name":"HermesInstaller:op6:desktop","type":"self_hosted","domain":self.setup.hostname,"allowed_idps":["idp"]}]
  api.rows["/accounts/a1/access/apps/app/policies"]=[{"id":"foreign","name":"bypass-old","decision":"bypass"}]
  with self.assertRaises(RemoteConflict):p.provision()
  self.assertFalse(any(m in {"POST","PUT","DELETE"} for m,path,_ in api.calls))
