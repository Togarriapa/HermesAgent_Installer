import pytest
from hermes_installer.remote.gateway import GatewayDenied, Principal, RemotePolicy, SocketLease, authorize_request, websocket_target

@pytest.fixture
def policy():
 return RemotePolicy("desk.example.net","https://team.cloudflareaccess.com","aud-1",
     frozenset({"owner@example.net"}),{"kid":{"kty":"RSA","kid":"kid"}})

def test_gate_denies_missing_identity_bad_route_and_host(policy):
 for kw in (dict(token=None,method="GET",path="/",host=policy.hostname,origin=None),
  dict(token="a.b.c",method="GET",path="/admin",host=policy.hostname,origin=None),
  dict(token="a.b.c",method="GET",path="/",host="evil.example",origin=None)):
  with pytest.raises(GatewayDenied): authorize_request(policy=policy,**kw)

def test_lease_cap_expiry_and_principal_bound_single_use_renewal():
 p=Principal("owner@example.net","s1",1000,"digest")
 lease=SocketLease.create(p,now=100,requested_seconds=600)
 assert lease.expires_at==160
 with pytest.raises(GatewayDenied): lease.authorize_frame(now=160)
 lease=SocketLease.create(p,now=100); challenge=lease.renewal_challenge
 other=Principal("other@example.net","s2",2000,"other")
 with pytest.raises(GatewayDenied): lease.renew(other,challenge=challenge,now=110,policy_current=lambda _:True)
 assert lease.closed
 lease=SocketLease.create(p,now=100); challenge=lease.renewal_challenge
 lease.renew(p,challenge=challenge,now=110,policy_current=lambda _:True)
 with pytest.raises(GatewayDenied): lease.renew(p,challenge=challenge,now=120,policy_current=lambda _:True)

def test_websocket_checks_exact_origin(policy):
 p=Principal("owner@example.net","s1",1000,"digest")
 with pytest.raises(GatewayDenied):
  websocket_target("/stream",principal=p,host=policy.hostname,origin="https://evil.example",policy=policy)
