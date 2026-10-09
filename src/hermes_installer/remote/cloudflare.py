"""Scoped Cloudflare API client. Resource reconciliation is separate."""
from __future__ import annotations
import json, re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import quote
from ..network import BoundedNetwork, NetworkError

class CloudflareError(RuntimeError):
    """Redacted Cloudflare API error safe for CLI display."""

@dataclass(frozen=True)
class CloudflareZone:
    zone_id: str
    name: str
    account_id: str
    status: str

class CloudflareClient:
    base = "https://api.cloudflare.com/client/v4"
    def __init__(self, token: str, *, network: BoundedNetwork | None = None):
        if not isinstance(token, str) or not token.strip() or len(token) > 4096 or "\n" in token or "\r" in token:
            raise ValueError("A valid Cloudflare API token is required")
        self.__token = token.strip()
        self.network = network or BoundedNetwork()
    @staticmethod
    def _object_id(value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value):
            raise ValueError("Invalid Cloudflare resource identifier")
        return quote(value, safe="")
    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        allowed = path in {"/zones", "/zones?per_page=100&status=active"} or (re.fullmatch(r"/(?:accounts|zones)/[A-Za-z0-9_-]{1,128}(?:/[A-Za-z0-9._/-]*)?", path) is not None and ".." not in path)
        if not allowed:
            raise ValueError("Cloudflare API path must be fixed and relative")
        body = None if payload is None else json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            response = self.network.request(self.base + path, method=method, headers={
                "Authorization": "Bearer " + self.__token, "Accept": "application/json",
                "Content-Type": "application/json"}, body=body)
        except NetworkError:
            raise CloudflareError("Cloudflare API request failed or exceeded its hard deadline") from None
        try:
            decoded = json.loads(response.body) if response.body else {}
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise CloudflareError("Cloudflare returned an invalid response") from None
        if not isinstance(decoded, dict) or not isinstance(decoded.get("success"), bool):
            raise CloudflareError("Cloudflare returned an invalid response")
        if response.status < 200 or response.status >= 300 or not decoded["success"]:
            codes = [str(e["code"]) for e in decoded.get("errors", [])[:4]
                     if isinstance(e, dict) and isinstance(e.get("code"), int)] if isinstance(decoded.get("errors"), list) else []
            raise CloudflareError(f"Cloudflare API rejected the request with HTTP {response.status}" + (f" ({','.join(codes)})" if codes else ""))
        return decoded.get("result")
    def discover_zones(self, suffix: str) -> tuple[CloudflareZone, ...]:
        normalized = suffix.rstrip(".").lower()
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if len(normalized) > 253 or not re.fullmatch(rf"(?:{label}\.)*{label}", normalized):
            raise ValueError("Invalid hostname or zone suffix")
        result = self.request("GET", "/zones?per_page=100&status=active")
        if not isinstance(result, list):
            raise CloudflareError("Cloudflare returned an invalid zones list")
        zones = []
        for item in result:
            if not isinstance(item, dict): continue
            account = item.get("account")
            name, zid, status = item.get("name"), item.get("id"), item.get("status")
            aid = account.get("id") if isinstance(account, dict) else None
            if not all(isinstance(v, str) for v in (name, zid, status, aid)): continue
            name = name.lower().rstrip(".")
            if status == "active" and (normalized == name or normalized.endswith("." + name)):
                zones.append(CloudflareZone(zid, name, aid, status))
        return tuple(sorted(zones, key=lambda z: len(z.name), reverse=True))
    def organization(self, account_id: str) -> Mapping[str, Any]:
        result = self.request("GET", f"/accounts/{self._object_id(account_id)}/access/organizations")
        if not isinstance(result, dict):
            raise CloudflareError("Cloudflare Zero Trust organization is not enrolled")
        domain = result.get("auth_domain")
        if not isinstance(domain, str) or not re.fullmatch(r"[A-Za-z0-9.-]+", domain) or domain.startswith(".") or domain.endswith("."):
            raise CloudflareError("Cloudflare organization has no valid Access authentication domain")
        return result
