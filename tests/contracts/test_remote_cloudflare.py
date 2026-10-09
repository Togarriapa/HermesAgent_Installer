from hermes_installer.remote.cloudflare_setup import RemoteCloudflareProvisioner,RemoteConflict
from hermes_installer.remote.cloudflare import CloudflareZone
from hermes_installer.remote.config import RemoteSetup
from hermes_installer.remote.lifecycle import RemoteJournal
import pytest

class Recorder:
 def __init__(self):self.rows={};self.calls=[]
 def pages(self,path):self.calls.append(("GET",path,None));return list(self.rows.get(path,[]))
 def request(self,method,path,payload=None):
  self.calls.append((method,path,payload))
  if method=="POST":
   row={**payload,"id":"id-"+str(len(self.calls))};self.rows.setdefault(path,[]).append(row);return row
  if path.endswith("/token"):return "protected-runtime-token"
  return {"id":path.rsplit("/",1)[-1]}

@pytest.fixture
def setup():
 return RemoteSetup("desk.example.net",("owner@example.net",),CloudflareZone("z1","example.net","a1","active"),"team.cloudflareaccess.com","setup-secret")

def factory(api,setup,journal,ready=lambda:True):
 snapshots=[]
 return RemoteCloudflareProvisioner(api,setup,journal,checkpoint=lambda j:snapshots.append((j.operation_id,set(j.completed))),
   origin_ready=ready),snapshots

def test_policy_origin_and_tunnel_precede_dns_and_token_is_separate(setup):
 api=Recorder(); p,_=factory(api,setup,RemoteJournal("op1",setup.hostname)); result=p.provision()
 writes=[(i,m,path) for i,(m,path,_) in enumerate(api.calls)]
 policy=next(i for i,m,path in writes if m=="POST" and path.endswith("/policies"))
 dns=next(i for i,m,path in writes if m=="POST" and path.endswith("/dns_records"))
 assert policy<dns and result.runtime_token=="protected-runtime-token"
 assert api.calls[dns][2]["content"]==result.tunnel_id+".cfargotunnel.com"
 assert api.calls[dns][2]["proxied"] is True

def test_unready_origin_never_creates_public_dns(setup):
 api=Recorder(); p,_=factory(api,setup,RemoteJournal("op2",setup.hostname),lambda:False)
 with pytest.raises(Exception):p.provision()
 assert not any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls)

def test_foreign_dns_and_allow_policy_are_preserved(setup):
 api=Recorder(); api.rows["/zones/z1/dns_records"]=[{"id":"foreign","name":setup.hostname,"type":"A","content":"192.0.2.1"}]
 p,_=factory(api,setup,RemoteJournal("op3",setup.hostname))
 with pytest.raises(RemoteConflict):p.activate_dns("tunnel")
 assert not any(m=="POST" and path.endswith("/dns_records") for m,path,_ in api.calls)
 api=Recorder(); path="/accounts/a1/access/apps/app/policies";api.rows[path]=[{"id":"foreign","name":"old","decision":"allow"}]
 p,_=factory(api,setup,RemoteJournal("op4",setup.hostname))
 with pytest.raises(RemoteConflict):p.ensure_email_policy("app")
 assert not any(m=="POST" and x==path for m,x,_ in api.calls)
