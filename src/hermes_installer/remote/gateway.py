"""Fail-closed origin authorization for Hermes Desktop browser bridge."""
from __future__ import annotations
import hashlib, secrets, time
from dataclasses import dataclass, field
from typing import Callable, Mapping
from urllib.parse import urlsplit

class GatewayDenied(PermissionError):
    """Request denied before response bytes, pixels, input, or worker launch."""

@dataclass(frozen=True)
class RemotePolicy:
    hostname: str
    issuer: str
    audience: str
    allowed_emails: frozenset[str]
    jwks: Mapping[str, Mapping[str, object]] = field(repr=False, compare=False)
    clock_skew_seconds: int = 30

    def __post_init__(self):
        if not self.hostname or not self.issuer.startswith("https://") or not self.audience or not self.allowed_emails:
            raise ValueError("Remote Access hostname, issuer, audience, and allowed emails are required")
        if not 0 <= self.clock_skew_seconds <= 60:
            raise ValueError("Clock skew must be bounded to 60 seconds")

@dataclass(frozen=True)
class Principal:
    email: str
    subject: str
    expires_at: float
    token_fingerprint: str = field(repr=False)

def validate_access_jwt(token: str, *, policy: RemotePolicy, now: Callable[[], float] = time.time) -> Principal:
    """RS256 only; JWKS is fixed URL, bounded, and supplied by trusted cache."""
    try:
        import jwt
        from jwt import PyJWK
        if not isinstance(token, str) or len(token) > 16384 or token.count(".") != 2:
            raise GatewayDenied("invalid Access token")
        hdr = jwt.get_unverified_header(token)
        if hdr.get("alg") != "RS256" or not isinstance(hdr.get("kid"), str):
            raise GatewayDenied("unsupported Access token algorithm")
        jwk = policy.jwks.get(hdr["kid"])
        if not isinstance(jwk, Mapping) or jwk.get("kty") != "RSA":
            raise GatewayDenied("Access signing key unavailable")
        key = PyJWK.from_dict(dict(jwk), algorithm="RS256").key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=policy.issuer,
            audience=policy.audience, leeway=policy.clock_skew_seconds,
            options={"require": ["iss", "aud", "exp", "nbf", "sub", "email"]})
    except GatewayDenied:
        raise
    except Exception:
        raise GatewayDenied("Access token validation failed") from None
    email, subject, expiry = claims.get("email"), claims.get("sub"), claims.get("exp")
    if not isinstance(email, str) or email.casefold() not in policy.allowed_emails:
        raise GatewayDenied("Access principal is not allowed")
    if not isinstance(subject, str) or not subject or not isinstance(expiry, (int, float)) or expiry <= now():
        raise GatewayDenied("Access token is expired or incomplete")
    return Principal(email.casefold(), subject, float(expiry), hashlib.sha256(token.encode()).hexdigest())

def authorize_request(*, token: str | None, policy: RemotePolicy, method: str,
                      path: str, host: str, origin: str | None,
                      now: Callable[[], float] = time.time) -> Principal:
    if not (path in {"/", "/session", "/renew", "/stream"} or
            (path.startswith("/client/") and ".." not in path.split("/"))):
        raise GatewayDenied("route is not exposed")
    if method not in {"GET", "HEAD", "POST"} or host.casefold() != policy.hostname.casefold():
        raise GatewayDenied("request target is not allowed")
    if origin is not None:
        u = urlsplit(origin)
        if u.scheme != "https" or u.netloc.casefold() != policy.hostname.casefold() or u.path not in {"", "/"}:
            raise GatewayDenied("browser origin is not allowed")
    if not token:
        raise GatewayDenied("Cloudflare Access identity required")
    return validate_access_jwt(token, policy=policy, now=now)

MAX_LEASE_SECONDS = 60
MAX_WATCHDOG_SECONDS = 5

@dataclass
class SocketLease:
    principal: Principal
    socket_nonce: str
    expires_at: float
    max_jwt_expiry: float
    _renew_nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    _closed: bool = False

    @classmethod
    def create(cls, principal: Principal, *, now: float, requested_seconds: int = 60):
        expiry = min(now + min(MAX_LEASE_SECONDS, max(1, int(requested_seconds))), principal.expires_at)
        if expiry <= now: raise GatewayDenied("Access token expired")
        return cls(principal, secrets.token_urlsafe(24), expiry, principal.expires_at)

    def authorize_frame(self, *, now: float):
        if self._closed or now >= self.expires_at or now >= self.max_jwt_expiry:
            self._closed = True
            raise GatewayDenied("WebSocket authorization lease expired")

    def renew(self, fresh: Principal, *, challenge: str, now: float,
              policy_current: Callable[[str], bool], requested_seconds: int = 60):
        self.authorize_frame(now=now)
        if (not secrets.compare_digest(challenge, self._renew_nonce)
                or fresh.subject != self.principal.subject
                or fresh.email.casefold() != self.principal.email.casefold()
                or not policy_current(fresh.email)):
            self._closed = True
            raise GatewayDenied("fresh protected HTTP renewal was denied")
        self.max_jwt_expiry = fresh.expires_at
        self.expires_at = min(now + min(MAX_LEASE_SECONDS, max(1, int(requested_seconds))), fresh.expires_at)
        self._renew_nonce = secrets.token_urlsafe(32)

    @property
    def renewal_challenge(self): return self._renew_nonce
    @property
    def closed(self): return self._closed

def websocket_target(path: str, *, principal: Principal, host: str, origin: str | None, policy: RemotePolicy):
    if path != "/stream" or host.casefold() != policy.hostname.casefold():
        raise GatewayDenied("WebSocket target is not allowed")
    if origin != f"https://{policy.hostname}" or principal.email.casefold() not in policy.allowed_emails:
        raise GatewayDenied("WebSocket origin or principal is not allowed")
