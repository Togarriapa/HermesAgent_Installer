"""Strict Cloudflare Access JWT and request authorization primitives."""
from __future__ import annotations
import hashlib,math,re,secrets,time
from dataclasses import dataclass,field
from typing import Callable,Mapping
from urllib.parse import urlsplit
class GatewayDenied(PermissionError):"""Request denied before response bytes, pixels, input or worker launch."""
@dataclass(frozen=True)
class RemotePolicy:
 hostname:str
 issuer:str
 audience:str
 allowed_emails:frozenset[str]
 jwks:Mapping[str,Mapping[str,object]]=field(repr=False,compare=False)
 clock_skew_seconds:int=30
 def __post_init__(self):
  u=urlsplit(self.issuer)
  if not re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+",self.hostname) or not self.audience or not self.allowed_emails or u.scheme!="https" or not u.hostname or not u.hostname.endswith(".cloudflareaccess.com") or len(u.hostname.split("."))!=3 or u.path not in {"","/"} or u.query or u.fragment or u.username or u.password:raise ValueError("canonical Cloudflare Access team issuer, audience, hostname and allowlist required")
  if not 0<=self.clock_skew_seconds<=60:raise ValueError("clock skew must be bounded to 60 seconds")
@dataclass(frozen=True)
class Principal:
 email:str
 subject:str
 expires_at:float
 token_fingerprint:str=field(repr=False)
def validate_access_jwt(token:str,*,policy:RemotePolicy,now:Callable[[],float]=time.time)->Principal:
 try:
  import jwt
  from jwt import PyJWK
  if not isinstance(token,str) or len(token)>16384 or token.count(".")!=2:raise GatewayDenied("invalid Access token")
  hdr=jwt.get_unverified_header(token);kid=hdr.get("kid")
  if hdr.get("alg")!="RS256" or hdr.get("crit") is not None or any(k in hdr for k in ("jku","jwk","x5u","x5c")) or not isinstance(kid,str) or not 1<=len(kid)<=128:raise GatewayDenied("unsupported Access token algorithm")
  jwk=policy.jwks.key(kid) if callable(getattr(policy.jwks,"key",None)) else policy.jwks.get(kid)
  if not isinstance(jwk,Mapping) or jwk.get("kty")!="RSA" or jwk.get("alg") not in (None,"RS256") or jwk.get("use") not in (None,"sig"):raise GatewayDenied("Access signing key unavailable")
  key=PyJWK.from_dict(dict(jwk),algorithm="RS256").key
  claims=jwt.decode(token,key,algorithms=["RS256"],issuer=policy.issuer,audience=None,leeway=0,options={"require":["iss","aud","exp","nbf","iat","sub","email"],"verify_signature":True,"verify_exp":False,"verify_nbf":False,"verify_iat":False,"verify_aud":False})
 except GatewayDenied:raise
 except Exception:raise GatewayDenied("Access token validation failed") from None
 ts=now()
 try:
  if isinstance(ts,bool) or not isinstance(ts,(int,float)):raise ValueError
  ts=float(ts)
  if not math.isfinite(ts):raise ValueError
 except (TypeError,ValueError,OverflowError):raise GatewayDenied("gateway clock is invalid") from None
 aud=claims.get("aud")
 if not (aud==policy.audience or (isinstance(aud,list) and len(aud)==1 and aud[0]==policy.audience)) or claims.get("iss")!=policy.issuer:raise GatewayDenied("Access issuer or audience mismatch")
 email,subject=claims.get("email"),claims.get("sub");numeric={k:claims.get(k) for k in ("iat","nbf","exp")}
 try:
  if any(isinstance(v,bool) or not isinstance(v,(int,float)) for v in numeric.values()):raise ValueError
  numeric={k:float(v) for k,v in numeric.items()}
  if not all(math.isfinite(v) for v in numeric.values()):raise ValueError
 except (TypeError,ValueError,OverflowError):raise GatewayDenied("Access time/principal claims are invalid") from None
 if not math.isfinite(ts) or not isinstance(email,str) or not email.strip() or email.casefold() not in policy.allowed_emails:raise GatewayDenied("Access principal is not allowed")
 if not isinstance(subject,str) or not subject or any(not isinstance(v,float) for v in numeric.values()):raise GatewayDenied("Access time/principal claims are invalid")
 if numeric["iat"]>ts+policy.clock_skew_seconds or numeric["nbf"]>ts+policy.clock_skew_seconds or numeric["exp"]<=ts or numeric["iat"]>=numeric["exp"] or numeric["nbf"]>=numeric["exp"]:raise GatewayDenied("Access token is not currently valid")
 return Principal(email.casefold(),subject,float(numeric["exp"]),hashlib.sha256(token.encode()).hexdigest())
def authorize_request(*,token:str|None,policy:RemotePolicy,method:str,path:str,host:str,origin:str|None,now:Callable[[],float]=time.time)->Principal:
 if not (path in {"/","/session","/renew","/stream","/client/"} or (path.startswith("/client/") and all(x not in {".",".."} for x in path.split("/")))):raise GatewayDenied("route is not exposed")
 if method not in {"GET","HEAD","POST"} or host.casefold()!=policy.hostname.casefold():raise GatewayDenied("request target is not allowed")
 if origin is not None:
  u=urlsplit(origin)
  if u.scheme!="https" or u.netloc.casefold()!=policy.hostname.casefold() or u.path not in {"","/"} or u.query or u.fragment:raise GatewayDenied("browser origin is not allowed")
 if not token:raise GatewayDenied("Cloudflare Access identity required")
 return validate_access_jwt(token,policy=policy,now=now)
MAX_LEASE_SECONDS=60
MAX_WATCHDOG_SECONDS=5
@dataclass
class SocketLease:
 principal:Principal
 socket_nonce:str
 expires_at:float
 max_jwt_expiry:float
 _renew_nonce:str=field(default_factory=lambda:secrets.token_urlsafe(32),repr=False)
 _closed:bool=False
 socket_consumed:bool=False
 @classmethod
 def create(cls,principal:Principal,*,now:float,wall_now:float,requested_seconds:int=60):
  seconds=min(MAX_LEASE_SECONDS,max(1,int(requested_seconds)));remaining=principal.expires_at-wall_now
  if remaining<=0:raise GatewayDenied("Access token expired")
  expiry=now+min(seconds,remaining)
  return cls(principal,secrets.token_urlsafe(24),expiry,now+remaining)
 def authorize_frame(self,*,now:float):
  if self._closed or now>=self.expires_at or now>=self.max_jwt_expiry:self._closed=True;raise GatewayDenied("WebSocket authorization lease expired")
 def renew(self,fresh:Principal,*,challenge:str,now:float,wall_now:float,policy_current:Callable[[str],bool]|None,requested_seconds:int=60):
  self.authorize_frame(now=now)
  try:
   member=policy_current is not None and policy_current(fresh.email) is True
  except Exception:
   member=False
  if (not secrets.compare_digest(challenge,self._renew_nonce) or fresh.subject!=self.principal.subject or fresh.email.casefold()!=self.principal.email.casefold() or not member):
   self._closed=True;raise GatewayDenied("fresh protected HTTP membership renewal was denied")
  remaining=fresh.expires_at-wall_now
  if remaining<=0:self._closed=True;raise GatewayDenied("renewal token expired")
  self.principal=fresh;self.max_jwt_expiry=now+remaining;self.expires_at=min(now+min(MAX_LEASE_SECONDS,max(1,int(requested_seconds))),self.max_jwt_expiry);self._renew_nonce=secrets.token_urlsafe(32)
 def claim_socket(self,nonce:str,*,now:float):
  self.authorize_frame(now=now)
  if self.socket_consumed or not secrets.compare_digest(nonce,self.socket_nonce):
   self._closed=True;raise GatewayDenied("socket nonce is invalid or already used")
  self.socket_consumed=True
 @property
 def renewal_challenge(self):return self._renew_nonce
 @property
 def closed(self):return self._closed
def websocket_target(path:str,*,principal:Principal,host:str,origin:str|None,policy:RemotePolicy):
 if path!="/stream" or host.casefold()!=policy.hostname.casefold():raise GatewayDenied("WebSocket target is not allowed")
 if origin!=f"https://{policy.hostname}" or principal.email.casefold() not in policy.allowed_emails:raise GatewayDenied("WebSocket origin or principal is not allowed")
