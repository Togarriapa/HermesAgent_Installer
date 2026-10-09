import importlib.util
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
