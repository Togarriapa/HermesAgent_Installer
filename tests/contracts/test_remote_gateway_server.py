import asyncio,base64,importlib.util
import unittest
from unittest.mock import patch
from hermes_installer.remote.gateway import GatewayDenied
from hermes_installer.remote.jwks import JWKSCache
from hermes_installer.network import HTTPResult

class FakeNetwork:
 def __init__(self,**kwargs):self.options=kwargs;self.requested=None;self.result=None
 def request(self,url,*,method,headers,cancelled=None):
  self.requested=(url,method,headers)
  if cancelled is not None and cancelled():raise GatewayDenied("cancelled")
  return self.result

class RemoteAssetManifestTests(unittest.TestCase):
 def test_only_exact_pinned_client_assets_are_exposed(self):
  from hermes_installer.remote.server import canonical_asset
  self.assertEqual(canonical_asset("/client/js/Client.js"),"/client/js/Client.js")
  for path in ("/client/js/not-shipped.js","/client/server-info","/client/../etc/passwd",
               "/client/js/%2e%2e/admin.js","/client/sw.js","/client/"):
   with self.subTest(path=path),self.assertRaises(GatewayDenied):canonical_asset(path)


class RemoteJWKSUnitTests(unittest.TestCase):
 def test_issuer_and_key_set_are_fixed_bounded_and_cached(self):
  with self.assertRaises(ValueError):JWKSCache("https://evil.example")
  body=b'{"keys":[{"kty":"RSA","kid":"kid1","use":"sig","alg":"RS256","n":"a","e":"AQAB"},{"kty":"oct","kid":"bad"}]}'
  seen=[]
  def factory(**kw):
   network=FakeNetwork(**kw);network.result=HTTPResult(200,{"Content-Length":str(len(body))},body);seen.append(network);return network
  now=[0.0]
  cache=JWKSCache("https://team.cloudflareaccess.com",clock=lambda:now[0])
  with patch("hermes_installer.remote.jwks.BoundedNetwork",factory):
   first=cache.load();self.assertEqual(set(first),{"kid1"});self.assertEqual(cache.key("kid1")["kty"],"RSA")
   self.assertEqual(len(seen),1);self.assertEqual(seen[0].requested[0],"https://team.cloudflareaccess.com/cdn-cgi/access/certs")
   with self.assertRaises(GatewayDenied):cache.key("missing")
   self.assertEqual(len(seen),2)
   with self.assertRaises(GatewayDenied):cache.key("still-missing")
   self.assertEqual(len(seen),2)
 def test_read_deadline_uses_the_injected_monotonic_clock(self):
  body=b'{"keys":[{"kty":"RSA","kid":"kid1","use":"sig","alg":"RS256","n":"a","e":"AQAB"}]}'
  now=[0.0];seen=[]
  def factory(**kwargs):
   network=FakeNetwork(**kwargs);network.result=HTTPResult(200,{"Content-Length":str(len(body))},body);seen.append(network);return network
  cache=JWKSCache("https://team.cloudflareaccess.com",clock=lambda:now[0])
  with patch("hermes_installer.remote.jwks.BoundedNetwork",factory):
   self.assertEqual(set(cache.load(deadline_monotonic=2)),{"kid1"})
  self.assertEqual(len(seen),1)
 def test_jwks_redirect_compression_and_oversize_are_rejected(self):
  cases=(
   HTTPResult(302,{"Location":"https://evil.example"},b"{}"),
   HTTPResult(200,{"Content-Encoding":"gzip"},b"{}"),
   HTTPResult(200,{"Content-Length":"999999"},b"{}"),
   HTTPResult(200,{},b"x"*(262144+1)),
  )
  for result in cases:
   def factory(**kw):
    network=FakeNetwork(**kw);network.result=result;return network
   cache=JWKSCache("https://team.cloudflareaccess.com")
   with patch("hermes_installer.remote.jwks.BoundedNetwork",factory):
    with self.assertRaises(GatewayDenied):cache.load()

@unittest.skipUnless(importlib.util.find_spec("aiohttp"),"isolated remote aiohttp runtime not installed")
class RemoteGatewayPacketTests(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  from aiohttp.test_utils import TestClient,TestServer
  from hermes_installer.remote.gateway import RemotePolicy
  from hermes_installer.remote.server import GatewayRuntime,create_app
  policy=RemotePolicy("desk.example.net","https://team.cloudflareaccess.com","aud",frozenset({"owner@example.net"}),{})
  app=create_app(GatewayRuntime(policy,upstream="http://127.0.0.1:1/"))
  self.client=TestClient(TestServer(app));await self.client.start_server()
 async def asyncTearDown(self):await self.client.close()
 async def test_unauthorized_asset_session_renew_and_websocket_are_rejected_before_upstream(self):
  host={"Host":"desk.example.net","Origin":"https://desk.example.net"}
  for method,path in (("GET","/client/index.html"),("POST","/session"),("POST","/renew")):
   with self.subTest(method=method,path=path):
    response=await self.client.request(method,path,headers=host)
    self.assertEqual(response.status,403);self.assertEqual(await response.text(),"Forbidden")
  from aiohttp.client_exceptions import WSServerHandshakeError
  with self.assertRaises(WSServerHandshakeError):await self.client.ws_connect("/client/?lease=forged",headers=host)


class FixtureVerifier:
 def __init__(self,monotonic,wall,membership):
  self.monotonic,self.wall,self.membership=monotonic,wall,membership
  self.actions=[]
 async def authorize(self,*,action,session_id,access_jwt,expected):
  self.actions.append((action,session_id))
  if not self.membership[0]:raise GatewayDenied("fixture policy removed")
  start=self.monotonic();jwt_deadline=start+max(0,expected.expires_at-self.wall)
  from hermes_installer.remote.verifier_ipc import PolicyGrant
  return PolicyGrant(action,session_id,expected,start,start,jwt_deadline,min(start+60,jwt_deadline),"a"*64,"b"*40)

CRYPTO_AVAILABLE=importlib.util.find_spec("jwt") is not None and importlib.util.find_spec("cryptography") is not None
@unittest.skipUnless(CRYPTO_AVAILABLE and importlib.util.find_spec("aiohttp"),"install isolated remote lock before HTTP/WebSocket cohort")
class RemoteGatewayAuthorizedFlowTests(unittest.IsolatedAsyncioTestCase):
 async def asyncSetUp(self):
  import time
  import jwt
  from aiohttp import web,WSMsgType
  from aiohttp.test_utils import TestClient,TestServer
  from cryptography.hazmat.primitives.asymmetric import rsa
  from hermes_installer.remote.gateway import RemotePolicy
  from hermes_installer.remote.server import GatewayRuntime,create_app
  self.wall=int(time.time());self.monotonic=[1000.0]
  self.key=rsa.generate_private_key(public_exponent=65537,key_size=2048);pub=self.key.public_key().public_numbers()
  def b64(value):return base64.urlsafe_b64encode(value.to_bytes((value.bit_length()+7)//8,"big")).rstrip(b"=").decode()
  jwk={"kty":"RSA","kid":"test-kid","alg":"RS256","use":"sig","n":b64(pub.n),"e":b64(pub.e)}
  self.policy=RemotePolicy("desk.example.net","https://team.cloudflareaccess.com","app-aud",frozenset({"owner@example.net"}),{"test-kid":jwk})
  self.token=jwt.encode({"iss":self.policy.issuer,"aud":["app-aud"],"iat":self.wall,"nbf":self.wall,"exp":self.wall+300,"sub":"subject-1","email":"owner@example.net"},self.key,algorithm="RS256",headers={"kid":"test-kid"})
  upstream_app=web.Application()
  async def index(_):return web.Response(text="<!doctype html><body>pinned html5 client</body>",content_type="text/html")
  async def css(_):return web.Response(text="body{margin:0}",content_type="text/css")
  async def echo(request):
   socket=web.WebSocketResponse(protocols=("binary",),autoping=False,autoclose=False)
   await socket.prepare(request)
   async for msg in socket:
    if msg.type==WSMsgType.BINARY:await socket.send_bytes(msg.data)
   return socket
  upstream_app.router.add_get("/index.html",index);upstream_app.router.add_get("/css/client.css",css);upstream_app.router.add_get("/",echo)
  self.upstream=TestServer(upstream_app);await self.upstream.start_server()
  self.membership=[True]
  verifier=FixtureVerifier(lambda:self.monotonic[0],self.wall,self.membership)
  self.runtime=GatewayRuntime(self.policy,upstream=str(self.upstream.make_url("/")),monotonic=lambda:self.monotonic[0],verifier=verifier,max_lease_seconds=1,watchdog_seconds=1)
  self.gateway=TestClient(TestServer(create_app(self.runtime)));await self.gateway.start_server()
  self.headers={"Host":self.policy.hostname,"Origin":"https://"+self.policy.hostname,"Cf-Access-Jwt-Assertion":self.token}
 async def asyncTearDown(self):
  await self.gateway.close();await self.upstream.close()
 async def test_access_protected_assets_empty_post_and_css_minimal_client(self):
  response=await self.gateway.get("/client/index.html",headers=self.headers)
  self.assertEqual(response.status,200);self.assertIn("setInterval(renew,25000)",await response.text())
  css=await self.gateway.get("/client/css/client.css",headers=self.headers)
  self.assertEqual(css.status,200);self.assertIn("#float_menu{display:none!important}",await css.text())
  blocked=await self.gateway.get("/client/connect.html",headers=self.headers)
  self.assertEqual(blocked.status,403)
  created=await self.gateway.post("/session",headers=self.headers)
  self.assertEqual(created.status,200);session=await created.json();self.assertTrue(session["socket_nonce"])
 async def test_access_protected_renewal_challenge_is_single_use(self):
  created=await self.gateway.post("/session",headers=self.headers);self.assertEqual(created.status,200);session=await created.json()
  renewed=await self.gateway.post("/renew",headers=self.headers,json={"lease_id":session["lease_id"],"challenge":session["renewal_challenge"]})
  self.assertEqual(renewed.status,200);fresh=(await renewed.json())["renewal_challenge"]
  replay=await self.gateway.post("/renew",headers=self.headers,json={"lease_id":session["lease_id"],"challenge":session["renewal_challenge"]})
  self.assertEqual(replay.status,403);self.assertNotEqual(fresh,session["renewal_challenge"])
 async def test_explicit_logout_requires_current_challenge_and_removes_lease(self):
  created=await self.gateway.post("/session",headers=self.headers);session=await created.json()
  denied=await self.gateway.post("/logout",headers=self.headers,json={"lease_id":session["lease_id"],"challenge":"wrong"})
  self.assertEqual(denied.status,403);self.assertIn(session["lease_id"],self.runtime.leases)
  response=await self.gateway.post("/logout",headers=self.headers,json={"lease_id":session["lease_id"],"challenge":session["renewal_challenge"]})
  self.assertEqual(response.status,204);self.assertNotIn(session["lease_id"],self.runtime.leases)
 async def test_fresh_policy_removal_denies_initial_issue_and_same_jwt_renewal(self):
  created=await self.gateway.post("/session",headers=self.headers)
  self.assertEqual(created.status,200);session=await created.json()
  self.membership[0]=False
  denied=await self.gateway.post("/renew",headers=self.headers,json={"lease_id":session["lease_id"],"challenge":session["renewal_challenge"]})
  self.assertEqual(denied.status,403)
  new_session=await self.gateway.post("/session",headers=self.headers)
  self.assertEqual(new_session.status,403)
 async def test_binary_websocket_is_closed_by_monotonic_lease_watchdog(self):
  from aiohttp import WSMsgType
  created=await self.gateway.post("/session",headers=self.headers);self.assertEqual(created.status,200);session=await created.json()
  path="/client/?lease="+session["lease_id"]+"&profile=hermes-desktop&nonce="+session["socket_nonce"]
  socket=await self.gateway.ws_connect(path,headers=self.headers,protocols=("binary",))
  await socket.send_bytes(b"allowed-pixels")
  message=await asyncio.wait_for(socket.receive(),timeout=3)
  self.assertEqual(message.data,b"allowed-pixels")
  self.monotonic[0]=1003.0
  close=await asyncio.wait_for(socket.receive(),timeout=4)
  self.assertIn(close.type,{WSMsgType.CLOSE,WSMsgType.CLOSED})
  await socket.close()
