import asyncio,base64,importlib.util
import unittest
from unittest.mock import patch
from hermes_installer.remote.gateway import GatewayDenied
from hermes_installer.remote.jwks import JWKSCache
class FakeResponse:
 status=200
 def __init__(self,body,headers=None):self.body=body;self.headers=headers or {"Content-Length":str(len(body))}
 def getheader(self,key):return self.headers.get(key)
 def read(self,n):return self.body[:n]
class FakeConnection:
 def __init__(self,host,port,timeout,context,response):self.host,self.port,self.timeout,self.context,self.response=host,port,timeout,context,response;self.requested=None;self.closed=False
 def request(self,*a,**kw):self.requested=(a,kw)
 def getresponse(self):return self.response
 def close(self):self.closed=True
class RemoteJWKSUnitTests(unittest.TestCase):
 def test_issuer_and_key_set_are_fixed_bounded_and_cached(self):
  with self.assertRaises(ValueError):JWKSCache("https://evil.example")
  body=b'{"keys":[{"kty":"RSA","kid":"kid1","use":"sig","alg":"RS256","n":"a","e":"AQAB"},{"kty":"oct","kid":"bad"}]}'
  response=FakeResponse(body);seen=[]
  def factory(host,port,timeout,context):
   c=FakeConnection(host,port,timeout,context,response);seen.append(c);return c
  cache=JWKSCache("https://team.cloudflareaccess.com")
  with patch("hermes_installer.remote.jwks.http.client.HTTPSConnection",factory):
   first=cache.load();self.assertEqual(set(first),{"kid1"});self.assertEqual(cache.key("kid1")["kty"],"RSA");self.assertEqual(len(seen),1)
   self.assertEqual(seen[0].requested[0][1],"/cdn-cgi/access/certs");self.assertTrue(seen[0].closed)
  with self.assertRaises(GatewayDenied):cache.key("missing")
 def test_jwks_redirect_and_oversize_are_rejected(self):
  for response in (FakeResponse(b'{"keys":[]}',{"Location":"https://evil.example"}),FakeResponse(b'{}',{"Content-Length":"999999"})):
   cache=JWKSCache("https://team.cloudflareaccess.com")
   with patch("hermes_installer.remote.jwks.http.client.HTTPSConnection",lambda *a,**k:FakeConnection(*a,response=response,**k)):
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
   async with self.subTest(method=method,path=path):
    response=await self.client.request(method,path,headers=host)
    self.assertEqual(response.status,403);self.assertEqual(await response.text(),"Forbidden")
  from aiohttp.client_exceptions import WSServerHandshakeError
  with self.assertRaises(WSServerHandshakeError):await self.client.ws_connect("/client/?lease=forged",headers=host)


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
  self.membership=[True]\n  runtime=GatewayRuntime(self.policy,upstream=str(self.upstream.make_url("/")),monotonic=lambda:self.monotonic[0],policy_current=lambda email:self.membership[0] and email=="owner@example.net",max_lease_seconds=1,watchdog_seconds=1)
  self.gateway=TestClient(TestServer(create_app(runtime)));await self.gateway.start_server()
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
