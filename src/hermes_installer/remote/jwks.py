"""Bounded Cloudflare Access JWKS retrieval pinned to the configured team origin."""
from __future__ import annotations
import json,threading,time
from dataclasses import dataclass,field
from typing import Callable,Mapping
from urllib.parse import urlsplit
from ..network import BoundedNetwork,NetworkError
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
 _last_unknown_refresh:float=field(default=0,repr=False)
 _lock:threading.RLock=field(default_factory=threading.RLock,repr=False)
 def __post_init__(self):
  u=urlsplit(self.issuer)
  if u.scheme!="https" or not u.hostname or not u.hostname.endswith(".cloudflareaccess.com") or len(u.hostname.split("."))!=3 or u.path not in {"","/"} or u.query or u.fragment or u.port not in {None,443}:raise ValueError("invalid fixed Cloudflare Access issuer")
  if not 1<=self.ttl_seconds<=3600 or not 0.1<=self.timeout_seconds<=5:raise ValueError("JWKS bounds exceeded")
  self.host=u.hostname
 def load(self,*,force:bool=False,cancel_event=None,deadline_monotonic:float|None=None)->Mapping[str,Mapping[str,object]]:
  with self._lock:
   now=self.clock()
   if not force and self._keys and now<self._expires_at:return self._keys
   remaining=self.timeout_seconds
   if deadline_monotonic is not None:remaining=min(remaining,deadline_monotonic-time.monotonic())
   if remaining<=0.1 or (cancel_event is not None and cancel_event.is_set()):raise GatewayDenied("Access signing-key read was cancelled or expired")
   network=BoundedNetwork(deadline_seconds=remaining,socket_timeout=min(remaining,4.0),max_response_bytes=MAX_JWKS_BYTES)
   try:
    response=network.request(f"https://{self.host}{JWKS_PATH}",method="GET",headers={"Accept":"application/json","Host":self.host,"Connection":"close"},cancelled=cancel_event.is_set if cancel_event is not None else None)
    if response.status!=200 or response.headers.get("Location") is not None:raise GatewayDenied("Access signing-key endpoint unavailable")
    if response.headers.get("Content-Encoding") not in (None,"identity"):raise GatewayDenied("compressed JWKS is not accepted")
    length=response.headers.get("Content-Length")
    if length is not None and (not length.isdecimal() or int(length)>MAX_JWKS_BYTES):raise GatewayDenied("JWKS response exceeds bound")
    if len(response.body)>MAX_JWKS_BYTES:raise GatewayDenied("JWKS response exceeds bound")
    document=json.loads(response.body)
   except GatewayDenied:raise
   except Exception:raise GatewayDenied("Access signing keys could not be fetched") from None
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
 def key(self,kid:str,*,cancel_event=None,deadline_monotonic:float|None=None)->Mapping[str,object]:
  if not isinstance(kid,str) or not 1<=len(kid)<=128:raise GatewayDenied("invalid signing key identifier")
  with self._lock:
   if not self._keys or self.clock()>=self._expires_at:self.load(cancel_event=cancel_event,deadline_monotonic=deadline_monotonic)
   row=self._keys.get(kid)
   if row is None:
    now=self.clock()
    # At most one cache-bypassing rotation check per cooldown, even under
    # attacker-controlled unknown-kid traffic.
    if now-self._last_unknown_refresh < min(30,self.ttl_seconds):
     raise GatewayDenied("Access signing key unavailable")
    self._last_unknown_refresh=now
    self.load(force=True,cancel_event=cancel_event,deadline_monotonic=deadline_monotonic);row=self._keys.get(kid)
   if row is None:raise GatewayDenied("Access signing key unavailable")
   return row
