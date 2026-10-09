"""Bounded Cloudflare Access JWKS retrieval pinned to the configured team origin."""
from __future__ import annotations
import http.client,json,ssl,time
from dataclasses import dataclass,field
from typing import Callable,Mapping
from urllib.parse import urlsplit
from .gateway import GatewayDenied
JWKS_PATH="/cdn-cgi/access/certs"
MAX_JWKS_BYTES=262144
@dataclass
class JWKSCache:
 issuer:str
 ttl_seconds:int=300
 timeout_seconds:float=3.0
 clock:Callable[[],float]=time.monotonic
 _keys:dict[str,dict[str,object]]=field(default_factory=dict,repr=False)
 _expires_at:float=0
 def __post_init__(self):
  u=urlsplit(self.issuer)
  if u.scheme!="https" or not u.hostname or not u.hostname.endswith(".cloudflareaccess.com") or len(u.hostname.split("."))!=3 or u.path not in {"","/"} or u.query or u.fragment or u.port not in {None,443}:raise ValueError("invalid fixed Cloudflare Access issuer")
  if not 1<=self.ttl_seconds<=3600 or not 0.1<=self.timeout_seconds<=5:raise ValueError("JWKS bounds exceeded")
  self.host=u.hostname
 def load(self,*,force:bool=False)->Mapping[str,Mapping[str,object]]:
  if not force and self._keys and self.clock()<self._expires_at:return self._keys
  conn=http.client.HTTPSConnection(self.host,443,timeout=self.timeout_seconds,context=ssl.create_default_context())
  try:
   conn.request("GET",JWKS_PATH,headers={"Accept":"application/json","Host":self.host,"Connection":"close"})
   response=conn.getresponse()
   if response.status!=200 or response.getheader("Location") is not None:raise GatewayDenied("Access signing-key endpoint unavailable")
   if response.getheader("Content-Encoding") not in (None,"identity"):raise GatewayDenied("compressed JWKS is not accepted")
   length=response.getheader("Content-Length")
   if length is not None and (not length.isdecimal() or int(length)>MAX_JWKS_BYTES):raise GatewayDenied("JWKS response exceeds bound")
   body=response.read(MAX_JWKS_BYTES+1)
   if len(body)>MAX_JWKS_BYTES:raise GatewayDenied("JWKS response exceeds bound")
   document=json.loads(body)
  except GatewayDenied:raise
  except Exception:raise GatewayDenied("Access signing keys could not be fetched") from None
  finally:conn.close()
  rows=document.get("keys") if isinstance(document,dict) else None
  if not isinstance(rows,list) or not rows or len(rows)>64:raise GatewayDenied("invalid Access JWKS")
  keys={}
  for row in rows:
   if not isinstance(row,dict) or row.get("kty")!="RSA" or row.get("use") not in (None,"sig") or row.get("alg") not in (None,"RS256"):continue
   kid=row.get("kid")
   if isinstance(kid,str) and 1<=len(kid)<=128:keys[kid]=row
  if not keys:raise GatewayDenied("Access JWKS has no acceptable signing key")
  self._keys=keys;self._expires_at=self.clock()+self.ttl_seconds
  return self._keys
 def key(self,kid:str)->Mapping[str,object]:
  if not isinstance(kid,str) or not 1<=len(kid)<=128:raise GatewayDenied("invalid signing key identifier")
  if not self._keys or self.clock()>=self._expires_at:self.load()
  row=self._keys.get(kid)
  if row is None:
   # A single bounded refresh handles normal key rotation; unknown-kid storms
   # cannot trigger refresh before cache expiry again.
   self.load(force=True);row=self._keys.get(kid)
  if row is None:raise GatewayDenied("Access signing key unavailable")
  return row
