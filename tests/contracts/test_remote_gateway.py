import unittest
from hermes_installer.remote.gateway import GatewayDenied,Principal,RemotePolicy,SocketLease,authorize_request,websocket_target
from hermes_installer.remote.server import canonical_asset
class RemoteGatewayTests(unittest.TestCase):
 def setUp(self):self.policy=RemotePolicy("desk.example.net","https://team.cloudflareaccess.com","aud-1",frozenset({"owner@example.net"}),{"kid":{"kty":"RSA","kid":"kid"}})
 def test_gate_denies_missing_identity_bad_route_and_host(self):
  cases=(dict(token=None,method="GET",path="/",host=self.policy.hostname,origin=None),dict(token="a.b.c",method="GET",path="/admin",host=self.policy.hostname,origin=None),dict(token="a.b.c",method="GET",path="/",host="evil.example",origin=None))
  for kw in cases:
   with self.subTest(kw=kw),self.assertRaises(GatewayDenied):authorize_request(policy=self.policy,**kw)
 def test_lease_cap_expiry_and_principal_bound_single_use_renewal(self):
  p=Principal("owner@example.net","s1",1000,"digest");lease=SocketLease.create(p,now=100,requested_seconds=600);self.assertEqual(lease.expires_at,160)
  with self.assertRaises(GatewayDenied):lease.authorize_frame(now=160)
  lease=SocketLease.create(p,now=100);challenge=lease.renewal_challenge;other=Principal("other@example.net","s2",2000,"other")
  with self.assertRaises(GatewayDenied):lease.renew(other,challenge=challenge,now=110,policy_current=lambda _:True)
  self.assertTrue(lease.closed)
  lease=SocketLease.create(p,now=100);challenge=lease.renewal_challenge;lease.renew(p,challenge=challenge,now=110,policy_current=lambda _:True)
  with self.assertRaises(GatewayDenied):lease.renew(p,challenge=challenge,now=120,policy_current=lambda _:True)
 def test_exact_origin_and_canonical_asset_path(self):
  p=Principal("owner@example.net","s1",1000,"digest")
  with self.assertRaises(GatewayDenied):websocket_target("/stream",principal=p,host=self.policy.hostname,origin="https://evil.example",policy=self.policy)
  self.assertEqual(canonical_asset("/client/index.html"),"/client/index.html")
  for path in ("/client/%2e%2e/secret","/client/../secret","/client/%252e%252e/secret"):
   with self.subTest(path=path),self.assertRaises(GatewayDenied):canonical_asset(path)
