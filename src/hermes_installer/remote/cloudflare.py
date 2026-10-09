"""Scoped Cloudflare API client with fixed endpoint/query allowlists and pagination."""
from __future__ import annotations
import json,re
from dataclasses import dataclass
from typing import Any,Mapping
from urllib.parse import parse_qsl,urlencode
from ..network import BoundedNetwork,NetworkError

class CloudflareError(RuntimeError):
    """Redacted Cloudflare API error safe for CLI display."""
@dataclass(frozen=True)
class CloudflareZone:
    zone_id:str
    name:str
    account_id:str
    status:str

class CloudflareClient:
    base="https://api.cloudflare.com/client/v4"
    _account_paths=re.compile(r"/accounts/[A-Za-z0-9_-]{1,128}/(?:access/organizations|access/identity_providers(?:/[A-Za-z0-9_-]{1,128})?|access/apps(?:/[A-Za-z0-9_-]{1,128}(?:/policies(?:/[A-Za-z0-9_-]{1,128})?)?)?|cfd_tunnel(?:/[A-Za-z0-9_-]{1,128}(?:/(?:configurations|token))?)?)$")
    _zone_paths=re.compile(r"/zones(?:/[A-Za-z0-9_-]{1,128}(?:/dns_records(?:/[A-Za-z0-9_-]{1,128})?)?)?$")
    _query_names=frozenset({"page","per_page","status","type","name","is_deleted"})
    def __init__(self,token:str,*,network:BoundedNetwork|None=None):
        if not isinstance(token,str) or not token.strip() or len(token)>4096 or "\n" in token or "\r" in token:
            raise ValueError("A valid Cloudflare API token is required")
        self.__token=token.strip(); self.network=network or BoundedNetwork()
    @classmethod
    def _valid_path(cls,path:str)->bool:
        endpoint=path.split("?",1)[0]
        return endpoint=="/zones" or bool(cls._account_paths.fullmatch(endpoint) or cls._zone_paths.fullmatch(endpoint))
    def request(self,method:str,path:str,payload:Mapping[str,Any]|None=None)->Any:
        if method not in {"GET","POST","PUT","PATCH","DELETE"} or not isinstance(path,str) or not self._valid_path(path):
            raise ValueError("Cloudflare API endpoint must be fixed and relative")
        parts=path.split("?",1)
        if len(parts)==2:
            try: params=parse_qsl(parts[1],keep_blank_values=False,strict_parsing=True)
            except ValueError: raise ValueError("Invalid Cloudflare query") from None
            if any(k not in self._query_names or not v or len(v)>253 for k,v in params) or len({k for k,_ in params})!=len(params):
                raise ValueError("Cloudflare query contains unsupported parameters")
        body=None if payload is None else json.dumps(payload,separators=(",",":"),ensure_ascii=False).encode()
        try:
            response=self.network.request(self.base+path,method=method,headers={"Authorization":"Bearer "+self.__token,
              "Accept":"application/json","Content-Type":"application/json"},body=body)
        except NetworkError: raise CloudflareError("Cloudflare API request failed or exceeded its hard deadline") from None
        try: data=json.loads(response.body) if response.body else {}
        except (UnicodeDecodeError,json.JSONDecodeError): raise CloudflareError("Cloudflare returned an invalid response") from None
        if not isinstance(data,dict) or not isinstance(data.get("success"),bool):
            raise CloudflareError("Cloudflare returned an invalid response")
        if response.status<200 or response.status>=300 or not data["success"]:
            codes=[str(e["code"]) for e in data.get("errors",[])[:4] if isinstance(e,dict) and isinstance(e.get("code"),int)] if isinstance(data.get("errors"),list) else []
            raise CloudflareError(f"Cloudflare API rejected the request with HTTP {response.status}"+(f" ({','.join(codes)})" if codes else ""))
        return data.get("result")
    def pages(self,path:str,*,filters:Mapping[str,str]|None=None)->list[dict[str,Any]]:
        if "?" in path or not self._valid_path(path): raise ValueError("Pagination path must be a fixed endpoint")
        params=dict(filters or {})
        if set(params)-self._query_names: raise ValueError("Unsupported Cloudflare list filter")
        rows=[]
        for page in range(1,101):
            q={**params,"per_page":"100","page":str(page)}
            result=self.request("GET",path+"?"+urlencode(q))
            if not isinstance(result,list) or any(not isinstance(x,dict) for x in result):
                raise CloudflareError("Cloudflare returned an invalid paginated list")
            rows.extend(result)
            if len(result)<100:return rows
        raise CloudflareError("Cloudflare pagination exceeded bounded page limit")
    def discover_zones(self,hostname:str)->tuple[CloudflareZone,...]:
        suffix=hostname.rstrip(".").lower(); label=r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(suffix)>253 or not re.fullmatch(rf"(?:{label}\.)*{label}",suffix): raise ValueError("Invalid hostname or zone suffix")
        rows=self.pages("/zones",filters={"status":"active"}); zones=[]
        for row in rows:
            account=row.get("account"); name=row.get("name"); zid=row.get("id"); status=row.get("status")
            aid=account.get("id") if isinstance(account,dict) else None
            if not all(isinstance(x,str) for x in (name,zid,status,aid)):continue
            name=name.lower().rstrip(".")
            if status=="active" and (suffix==name or suffix.endswith("."+name)):
                zones.append(CloudflareZone(zid,name,aid,status))
        return tuple(sorted(zones,key=lambda z:len(z.name),reverse=True))
    def organization(self,account_id:str)->Mapping[str,Any]:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}",account_id):raise ValueError("Invalid Cloudflare account identifier")
        result=self.request("GET",f"/accounts/{account_id}/access/organizations")
        if not isinstance(result,dict):raise CloudflareError("Cloudflare Zero Trust organization is not enrolled")
        domain=result.get("auth_domain")
        if not isinstance(domain,str) or not re.fullmatch(r"[A-Za-z0-9.-]+",domain) or domain.startswith(".") or domain.endswith("."):
            raise CloudflareError("Cloudflare organization has no valid Access authentication domain")
        return result
