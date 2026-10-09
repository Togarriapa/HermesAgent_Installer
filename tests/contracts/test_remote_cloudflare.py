import unittest
import time
import base64,json,uuid
from hermes_installer.authority.remote_origin import (HMACReceiptSigner, ProtectedTunnelTokenReceipt,
    RootOriginReadinessReceipt)
from hermes_installer.remote.cloudflare_setup import RemoteCloudflareProvisioner,RemoteConflict
from hermes_installer.remote.cloudflare import CloudflareZone,CloudflareError
from hermes_installer.remote.config import RemoteSetup
from hermes_installer.remote.lifecycle import RemoteJournal,RemotePhase
class Recorder:
 def __init__(self):self.rows={};self.calls=[];self.fail_dns=False;self.tunnel_id=None
 def pages(self,path):self.calls.append(("GET",path,None));return list(self.rows.get(path,[]))
 def request(self,method,path,payload=None):
  self.calls.append((method,path,payload))
  if method=="POST":
   if self.fail_dns and path.endswith("/dns_records"):raise CloudflareError("fixture timeout")
   rid=str(uuid.uuid4()) if path.endswith("/cfd_tunnel") else "id-"+str(len(self.calls))
   row={**(payload or {}),"id":rid};self.rows.setdefault(path,[]).append(row)
   if path.endswith("/cfd_tunnel"):self.tunnel_id=rid
   return row
  if method=="DELETE":
   collection=path.rsplit("/",1)[0];rid=path.rsplit("/",1)[1];self.rows[collection]=[x for x in self.rows.get(collection,[]) if x.get("id")!=rid];return {"id":rid}
  if path.endswith("/token"):
   envelope={"a":"a1","t":self.tunnel_id,"s":base64.b64encode(b"s"*32).decode("ascii")}
   return base64.b64encode(json.dumps(envelope).encode()).decode("ascii")
  if method=="PUT":return {"id":path.rsplit("/",1)[-1],**(payload or {})}
  return {"id":path.rsplit("/",1)[-1]}
class RemoteProvisionerTests(unittest.TestCase):
 def setUp(self):self.setup=RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret","keyring://hermes/access-read")
 def make(self,api,operation="op1",ready=True):
  snapshots=[];p=RemoteCloudflareProvisioner(api,self.setup,RemoteJournal(operation,self.setup.hostname),checkpoint=lambda j:snapshots.append((j.operation_id,set(j.completed))),policy_read_check=lambda _journal:True);return p,snapshots
 def receipts(self):
  from hermes_installer.authority.remote_origin import _canonical
  signer=HMACReceiptSigner(b"t"*32);now=time.monotonic()
  origin=RootOriginReadinessReceipt(1,"origin-receipt","remote-enrollment","a"*64,"desktop-generation","xpra-native","b"*64,"policy-revision","c"*64,("probe:http","probe:websocket"),now,now+20,b"")
  origin=RootOriginReadinessReceipt(*[getattr(origin,f) for f in ("schema","receipt_id","remote_enrollment_id","gateway_identity_digest","desktop_generation","connector_target_id","policy_config_digest","policy_revision","service_generation_digest","observed_assertion_ids","issued_monotonic","expires_monotonic")],signer.sign(origin.payload()))
  def writer(enrollment,token,*,setup_transaction_handle,account_id,tunnel_id,generation):
   if setup_transaction_handle!="setup-handle-"+"x"*32:raise AssertionError("setup transaction binding missing")
   receipt=ProtectedTunnelTokenReceipt(1,"token-receipt",enrollment,tunnel_id,generation,"sink",1,2,0,0o400,now,now+20,b"")
   return ProtectedTunnelTokenReceipt(*[getattr(receipt,f) for f in ("schema","receipt_id","tunnel_enrollment_id","tunnel_id","generation","sink_id","file_device","file_inode","owner_uid","mode","issued_monotonic","expires_monotonic")],signer.sign(receipt.payload()))
  return signer,origin,writer
 def activation(self,p,writer=None,origin=None,signer=None):
  default_signer,default_origin,default_writer=self.receipts()
  signer=signer or default_signer;origin=origin or default_origin;writer=writer or default_writer
  return p.provision_protected(runtime_token_writer=writer,
      setup_transaction_handle="setup-handle-"+"x"*32,
      tunnel_enrollment_id="tunnel-enrollment",tunnel_generation="cloudflared-generation",
      remote_enrollment_id="remote-enrollment",origin_receipt=origin,receipt_signer=signer)
 def activate(self,p,writer=None):
  signer,origin,stored_writer=self.receipts();stored=[]
  def sink(*args,**kwargs):stored.append(args[1]);return stored_writer(*args,**kwargs)
  result=self.activation(p,writer or sink,origin,signer)
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
  self.assertLess(policy,dns);self.assertEqual(len(stored),1);self.assertIsInstance(stored[0],bytes);self.assertFalse(hasattr(result,"runtime_token"));self.assertNotIn(stored[0].decode(),repr(result));self.assertIn("policy_read_verified",p.journal.completed);self.assertEqual(api.calls[dns][2]["content"],result.tunnel_id+".cfargotunnel.com");self.assertTrue(api.calls[dns][2]["proxied"]);self.assertEqual(p.journal.phase,RemotePhase.ACTIVE)
 def test_token_sink_failure_and_fresh_policy_denial_never_publish_dns(self):
  api=Recorder();p,_=self.make(api,"op-sink")
  signer,origin,_=self.receipts()
  with self.assertRaisesRegex(CloudflareError,"Protected tunnel-token storage failed"):
   self.activation(p,lambda *args,**kwargs:(_ for _ in ()).throw(RuntimeError("secret path detail")),origin,signer)
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
  self.assertNotIn("secret path detail",repr(p.journal))
  api=Recorder();p,_=self.make(api,"op-policy")
  p.policy_read_check=lambda _journal:False
  with self.assertRaisesRegex(CloudflareError,"Fresh protected Access"):
   self.activation(p,lambda *args,**kwargs:None,origin,signer)
  self.assertFalse(any(path.endswith("/cfd_tunnel") and m in {"POST","PUT"} for m,path,_ in api.calls))
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
 def test_missing_token_sink_has_no_cloudflare_effects(self):
  api=Recorder();p,_=self.make(api,"op-no-sink")
  with self.assertRaisesRegex(CloudflareError,"Protected writer"):
   p.provision_protected()
  self.assertEqual(api.calls,[])
 def test_missing_or_malformed_setup_transaction_handle_has_no_effects(self):
  api=Recorder();p,_=self.make(api,"op-no-transaction")
  signer,origin,writer=self.receipts()
  with self.assertRaisesRegex(CloudflareError,"Protected writer"):
   p.provision_protected(runtime_token_writer=writer,
       tunnel_enrollment_id="tunnel-enrollment",tunnel_generation="cloudflared-generation",
       remote_enrollment_id="remote-enrollment",origin_receipt=origin,receipt_signer=signer)
  with self.assertRaisesRegex(CloudflareError,"Protected writer"):
   p.provision_protected(runtime_token_writer=writer,setup_transaction_handle="short",
       tunnel_enrollment_id="tunnel-enrollment",tunnel_generation="cloudflared-generation",
       remote_enrollment_id="remote-enrollment",origin_receipt=origin,receipt_signer=signer)
  self.assertEqual(api.calls,[])
 def test_unready_origin_rolls_back_owned_resources_and_never_publishes_dns(self):
  api=Recorder();p,_=self.make(api,"op2",False)
  signer,origin,_=self.receipts()
  expired=RootOriginReadinessReceipt(1,"bad","remote-enrollment","a"*64,"desktop-generation","xpra-native","b"*64,"policy-revision","c"*64,("probe",),time.monotonic()-40,time.monotonic()-10,b"")
  with self.assertRaises(Exception):self.activation(p,None,expired,signer)
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls));self.assertTrue({"identity_provider","access_app","access_policy"}.issubset(p.journal.resources));self.assertEqual(p.journal.phase,RemotePhase.ACCESS_READY)
 def test_missing_policy_read_reference_checkpoints_access_and_never_activates(self):
  from hermes_installer.remote.cloudflare_setup import PolicyReadReferenceRequired
  setup=RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret")
  api=Recorder();snapshots=[]
  p=RemoteCloudflareProvisioner(api,setup,RemoteJournal("op-read-ref",setup.hostname),checkpoint=lambda j:snapshots.append((j.phase,j.error_code,set(j.completed))))
  signer,origin,writer=self.receipts()
  with self.assertRaisesRegex(PolicyReadReferenceRequired,"policy_read_token_ref"):
   self.activation(p,writer,origin,signer)
  self.assertEqual(p.journal.phase,RemotePhase.ACCESS_READY)
  self.assertEqual(p.journal.error_code,"POLICY_READ_REFERENCE_REQUIRED")
  self.assertTrue({"identity_provider","access_app","access_policy"}.issubset(p.journal.resources))
  self.assertFalse(any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls))
  self.assertFalse(any(path.endswith("/cfd_tunnel") and m in {"POST","PUT"} for m,path,_ in api.calls))
  self.assertTrue(any("resume:policy_read_token_ref" in completed for _,_,completed in snapshots))
  resumed_setup=RemoteSetup(setup.hostname,setup.allowed_emails,setup.zone,setup.auth_domain,setup.management_token,"keyring://hermes/access-read")
  resumed=RemoteCloudflareProvisioner(api,resumed_setup,p.journal,checkpoint=lambda _j:None,policy_read_check=lambda _journal:True)
  signer,origin,writer=self.receipts()
  activated=self.activation(resumed,writer,origin,signer)
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
