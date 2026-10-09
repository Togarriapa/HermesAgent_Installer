"""Host-managed Sign in with ChatGPT public-client flow (PR-F01 / PR-R0124/25).

All HTTP and credential persistence are injected host-broker interfaces. This
module never opens a network connection or writes reusable tokens to profiles.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable, Mapping, Protocol
from urllib.parse import urlencode, urlsplit, parse_qs

from .credentials import CredentialError

AUTHORIZE_ENDPOINT = "https://auth.openai.com/api/accounts/authorize"
TOKEN_ENDPOINT = "https://auth.openai.com/api/accounts/oauth/token"
RESOURCE = "https://api.openai.com/v1"
ISSUER = "https://auth.openai.com"
DYNAMIC_CLIENT_ID = "dynamic_agent_client"
PLAN_SCOPE = "chatgpt.tokens.use.direct"
SCOPES = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
CALLBACK_PATH = "/auth/callback"
MAX_TOKEN_LIFETIME = 86_400
DISCOVERY_ENDPOINT = "https://auth.openai.com/.well-known/openid-configuration"


class OAuthAttemptError(CredentialError):
    """Safe sign-in or refresh failure."""


class OAuthTransport(Protocol):
    def post_form(self, endpoint: str, values: Mapping[str, str], *, timeout: float) -> Mapping[str, object]: ...
    def get_json(self, endpoint: str, *, timeout: float) -> Mapping[str, object]: ...


class HostCredentialVault(Protocol):
    """Host-owned vault; implementations store encrypted/protected credentials by reference."""

    def save(self, reference: str, account: "ChatGPTAccount") -> None: ...
    def load(self, reference: str) -> "ChatGPTAccount": ...
    def clear_tokens(self, reference: str) -> None: ...


@dataclass(frozen=True, slots=True)
class OAuthAttempt:
    callback_uri: str
    host_id: str
    client_id: str
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    verifier: str = field(repr=False)
    authorize_url: str = field(repr=False)
    issued_at_monotonic: float = field(default=0.0, repr=False)
    monotonic_expires_at: float = field(default=0.0, repr=False)


@dataclass(frozen=True, slots=True)
class ChatGPTAccount:
    client_id: str
    host_id: str
    subject: str
    email: str | None
    scopes: frozenset[str]
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    id_token: str = field(repr=False)
    expires_at: float


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _validate_callback_uri(uri: str) -> None:
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except (TypeError, ValueError):
        raise OAuthAttemptError("OAuth loopback callback URI is invalid") from None
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
            or parsed.path != CALLBACK_PATH or parsed.query or parsed.fragment
            or parsed.username or parsed.password or not port or not 1024 <= port <= 65535):
        raise OAuthAttemptError("OAuth callback must use the exact 127.0.0.1 loopback callback path")


def _nonempty(value: object, key: str, limit: int = 8192) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise OAuthAttemptError(f"OpenAI authorization response has invalid {key}")
    return value


def _token_response(value: Mapping[str, object], *, inherited_scopes: frozenset[str] | None = None,
                    now: float | None = None) -> tuple[str, str, str, frozenset[str], float]:
    if not isinstance(value, Mapping):
        raise OAuthAttemptError("OpenAI token response is malformed")
    access = _nonempty(value.get("access_token"), "access token")
    refresh = _nonempty(value.get("refresh_token"), "refresh token")
    identity = _nonempty(value.get("id_token"), "ID token")
    if value.get("token_type") != "Bearer":
        raise OAuthAttemptError("OpenAI token response has an unsupported token type")
    raw_scope = value.get("scope")
    if raw_scope is None and inherited_scopes is not None:
        scopes = inherited_scopes
    else:
        scopes = frozenset(_nonempty(raw_scope, "granted scopes", 2048).split())
    if PLAN_SCOPE not in scopes:
        raise OAuthAttemptError("ChatGPT plan permission was not granted for Responses API use")
    lifetime = value.get("expires_in")
    if isinstance(lifetime, bool) or not isinstance(lifetime, int) or not 1 <= lifetime <= MAX_TOKEN_LIFETIME:
        raise OAuthAttemptError("OpenAI token lifetime is outside its supported bound")
    return access, refresh, identity, scopes, (time.time() if now is None else now) + lifetime


def _decode_jwt_part(part: str) -> bytes:
    if not isinstance(part, str) or len(part) > 16_384:
        raise OAuthAttemptError("OpenAI ID token is malformed")
    try:
        return base64.b64decode(part + "=" * ((4 - len(part) % 4) % 4),
                                altchars=b"-_", validate=True)
    except Exception:
        raise OAuthAttemptError("OpenAI ID token is malformed") from None


def _json_object(raw: bytes) -> Mapping[str, object]:
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate JSON member")
            value[key] = item
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_pairs)
    except Exception:
        raise OAuthAttemptError("OpenAI ID token contains invalid claims") from None
    if not isinstance(value, dict):
        raise OAuthAttemptError("OpenAI ID token contains invalid claims")
    return value


class OpenAIIDTokenVerifier:
    """Small RS256/OIDC verifier using only the issuer's fixed discovery and JWKS endpoints."""

    def __init__(self, transport: OAuthTransport, *, clock: Callable[[], float] = time.time):
        self.transport, self.clock = transport, clock

    def __call__(self, token: str, expected_nonce: str, audience: str) -> Mapping[str, object]:
        if not isinstance(token, str) or len(token) > 32_768 or not isinstance(audience, str):
            raise OAuthAttemptError("OpenAI ID token is malformed")
        parts = token.split(".")
        if len(parts) != 3:
            raise OAuthAttemptError("OpenAI ID token is malformed")
        header, claims = _json_object(_decode_jwt_part(parts[0])), _json_object(_decode_jwt_part(parts[1]))
        if header.get("alg") != "RS256" or header.get("crit") or not isinstance(header.get("kid"), str):
            raise OAuthAttemptError("OpenAI ID token uses an unsupported signing key")
        try:
            discovery = self.transport.get_json(DISCOVERY_ENDPOINT, timeout=10)
            if not isinstance(discovery, Mapping) or discovery.get("issuer") != ISSUER:
                raise OAuthAttemptError("OpenAI identity issuer metadata is invalid")
            jwks_uri = discovery.get("jwks_uri")
            if jwks_uri != ISSUER + "/.well-known/jwks.json":
                raise OAuthAttemptError("OpenAI identity key endpoint is not approved")
            jwks = self.transport.get_json(jwks_uri, timeout=10)
            keys = jwks.get("keys") if isinstance(jwks, Mapping) else None
        except OAuthAttemptError:
            raise
        except Exception:
            raise OAuthAttemptError("OpenAI identity signing keys could not be loaded") from None
        if not isinstance(keys, list) or len(keys) > 32:
            raise OAuthAttemptError("OpenAI identity signing keys are malformed")
        matches = [key for key in keys if isinstance(key, Mapping) and key.get("kid") == header["kid"]]
        if len(matches) != 1:
            raise OAuthAttemptError("OpenAI ID token signing key was not found")
        key = matches[0]
        if key.get("kty") != "RSA" or key.get("use", "sig") != "sig" or key.get("alg", "RS256") != "RS256":
            raise OAuthAttemptError("OpenAI identity signing key is not valid for RS256")
        try:
            modulus_bytes = _decode_jwt_part(key["n"])
            exponent_bytes = _decode_jwt_part(key["e"])
            modulus, exponent = int.from_bytes(modulus_bytes, "big"), int.from_bytes(exponent_bytes, "big")
            signature = _decode_jwt_part(parts[2])
            if modulus.bit_length() < 2048 or modulus.bit_length() > 8192 or exponent < 3 or exponent % 2 == 0:
                raise ValueError("key size")
            width = (modulus.bit_length() + 7) // 8
            if len(signature) != width:
                raise ValueError("signature width")
            encoded = pow(int.from_bytes(signature, "big"), exponent, modulus).to_bytes(width, "big")
            digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(
                (parts[0] + "." + parts[1]).encode("ascii")).digest()
            padding_len = width - len(digest_info) - 3
            expected = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + digest_info
            if padding_len < 8 or not hmac.compare_digest(encoded, expected):
                raise ValueError("signature")
        except (KeyError, TypeError, ValueError, OverflowError):
            raise OAuthAttemptError("OpenAI ID token signature is invalid") from None

        now = self.clock()
        subject, issuer = claims.get("sub"), claims.get("iss")
        token_aud = claims.get("aud")
        audiences = {token_aud} if isinstance(token_aud, str) else set(token_aud) if isinstance(token_aud, list) else set()
        expiry, not_before, issued = claims.get("exp"), claims.get("nbf", 0), claims.get("iat", now)
        if (issuer != ISSUER or audience not in audiences or not isinstance(subject, str) or not subject
                or isinstance(expiry, bool) or not isinstance(expiry, (int, float)) or not math.isfinite(expiry)
                or expiry <= now or isinstance(not_before, bool) or not isinstance(not_before, (int, float))
                or not_before > now or isinstance(issued, bool) or not isinstance(issued, (int, float))
                or issued > now + 60):
            raise OAuthAttemptError("OpenAI ID token issuer, audience or lifetime is invalid")
        azp = claims.get("azp")
        if (len(audiences) > 1 and azp != audience) or (azp is not None and azp != audience):
            raise OAuthAttemptError("OpenAI ID token authorized party is invalid")
        if expected_nonce and (not isinstance(claims.get("nonce"), str)
                               or not hmac.compare_digest(claims["nonce"], expected_nonce)):
            raise OAuthAttemptError("OpenAI ID token nonce did not match")
        return claims


class ChatGPTPlanAuth:
    """OAuth code+PKCE integration for eligible ChatGPT-plan Responses calls."""

    def __init__(self, *, host_id: str, agent_name: str, transport: OAuthTransport,
                 vault: HostCredentialVault,
                 verify_id_token: Callable[[str, str, str], Mapping[str, object]] | None = None,
                 clock: Callable[[], float] = time.time,
                 monotonic_clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        try:
            canonical_host_id = "urn:uuid:" + str(uuid.UUID(host_id.removeprefix("urn:uuid:")))
        except (TypeError, ValueError, AttributeError):
            raise ValueError("a stable urn:uuid host ID is required") from None
        if host_id != canonical_host_id:
            raise ValueError("a stable canonical urn:uuid host ID is required")
        if not agent_name or len(agent_name) > 128:
            raise ValueError("a stable application name is required")
        self.host_id, self.agent_name = host_id, agent_name
        self.transport, self.vault = transport, vault
        self.verify_id_token = verify_id_token or OpenAIIDTokenVerifier(transport, clock=clock)
        if not callable(clock) or not callable(monotonic_clock) or not callable(sleep):
            raise ValueError("OAuth clocks and sleeper must be callable")
        self.clock, self.monotonic_clock, self.sleep = clock, monotonic_clock, sleep
        self._locks_guard = threading.Lock()
        self._account_locks: dict[str, threading.Lock] = {}
        self._used_attempts: dict[str, float] = {}
        self._attempts_lock = threading.Lock()

    def begin(self, *, callback_uri: str, client_id: str | None = None,
              id_token_hint: str | None = None, login_hint: str | None = None) -> OAuthAttempt:
        _validate_callback_uri(callback_uri)
        selected = _nonempty(client_id, "registered client ID", 256) if client_id else DYNAMIC_CLIENT_ID
        if selected == DYNAMIC_CLIENT_ID and id_token_hint:
            raise OAuthAttemptError("A returning account must use its issued client ID")
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = _b64url(secrets.token_bytes(48))
        challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
        params = {
            "client_id": selected, "ext_agent_host_id": self.host_id,
            "response_type": "code", "redirect_uri": callback_uri,
            "scope": SCOPES, "resource": RESOURCE, "state": state, "nonce": nonce,
            "code_challenge_method": "S256", "code_challenge": challenge,
        }
        if selected == DYNAMIC_CLIENT_ID:
            params["agent_name_hint"] = self.agent_name
        if id_token_hint:
            params["id_token_hint"] = _nonempty(id_token_hint, "account hint")
        if login_hint:
            params["login_hint"] = _nonempty(login_hint, "login hint", 512)
        url = AUTHORIZE_ENDPOINT + "?" + urlencode(params)
        issued = self.monotonic_clock()
        if isinstance(issued, bool) or not isinstance(issued, (int, float)) or not math.isfinite(issued):
            raise OAuthAttemptError("Host monotonic clock is unavailable")
        return OAuthAttempt(callback_uri, self.host_id, selected, state, nonce, verifier, url,
                            float(issued), float(issued) + 600.0)

    def complete(self, attempt: OAuthAttempt, callback_url: str, *, credential_ref: str,
                 expected_subject: str | None = None) -> ChatGPTAccount:
        if not isinstance(attempt, OAuthAttempt) or attempt.host_id != self.host_id:
            raise OAuthAttemptError("Pending OAuth attempt does not belong to this host")
        _validate_callback_uri(attempt.callback_uri)
        try:
            parsed = urlsplit(callback_url)
            expected = urlsplit(attempt.callback_uri)
            callback_port = parsed.port
            expected_port = expected.port
        except (TypeError, ValueError):
            raise OAuthAttemptError("OAuth callback endpoint is invalid") from None
        if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1"
                or callback_port != expected_port or parsed.path != CALLBACK_PATH
                or parsed.username or parsed.password
                or parsed.netloc != f"127.0.0.1:{expected_port}"):
            raise OAuthAttemptError("OAuth callback endpoint does not match the pending request")
        now = self.monotonic_clock()
        if (isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(now)
                or attempt.issued_at_monotonic > now or attempt.monotonic_expires_at <= now
                or attempt.monotonic_expires_at - attempt.issued_at_monotonic > 600):
            raise OAuthAttemptError("OpenAI sign-in attempt expired")
        fields = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if any(len(v) != 1 for v in fields.values()):
            raise OAuthAttemptError("OAuth callback contains duplicate parameters")
        state = _nonempty(fields.get("state", [None])[0], "state", 256)
        if not secrets.compare_digest(state, attempt.state):
            raise OAuthAttemptError("OAuth callback state did not match")
        state_key = hashlib.sha256(state.encode("utf-8")).hexdigest()
        with self._attempts_lock:
            self._used_attempts = {key: expiry for key, expiry in self._used_attempts.items() if expiry > now}
            if state_key in self._used_attempts:
                raise OAuthAttemptError("OpenAI sign-in callback was already consumed")
            self._used_attempts[state_key] = float(attempt.monotonic_expires_at)
        if fields.get("error"):
            raise OAuthAttemptError("OpenAI authorization was declined or failed")
        code = _nonempty(fields.get("code", [None])[0], "authorization code")
        callback_client = fields.get("client_id", [None])[0]
        if attempt.client_id == DYNAMIC_CLIENT_ID:
            client_id = _nonempty(callback_client, "issued client ID", 256)
            if client_id == DYNAMIC_CLIENT_ID:
                raise OAuthAttemptError("Dynamic registration did not issue a reusable client ID")
        else:
            client_id = attempt.client_id
            if callback_client and not secrets.compare_digest(callback_client, client_id):
                raise OAuthAttemptError("OAuth callback client ID did not match the selected account")
        form = {
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": attempt.verifier, "redirect_uri": attempt.callback_uri,
            "resource": RESOURCE,
        }
        try:
            tokens = self.transport.post_form(TOKEN_ENDPOINT, form, timeout=15)
            access, refresh, id_token, scopes, expires = _token_response(tokens, now=self.clock())
            claims = self.verify_id_token(id_token, attempt.nonce, client_id)
        except OAuthAttemptError:
            raise
        except Exception:
            raise OAuthAttemptError("OpenAI sign-in exchange or ID-token verification failed") from None
        subject = _nonempty(claims.get("sub"), "verified account subject", 512)
        issuer = claims.get("iss")
        aud = claims.get("aud")
        nonce = claims.get("nonce")
        audiences = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()
        if (issuer != ISSUER or client_id not in audiences or not isinstance(nonce, str)
                or not secrets.compare_digest(nonce, attempt.nonce)
                or (expected_subject and not secrets.compare_digest(subject, expected_subject))):
            raise OAuthAttemptError("OpenAI ID token identity, audience, issuer or nonce did not match")
        email = claims.get("email")
        if email is not None:
            email = _nonempty(email, "verified account email", 512)
        account = ChatGPTAccount(client_id, self.host_id, subject, email, scopes,
                                 access, refresh, id_token, expires)
        try:
            self.vault.save(credential_ref, account)
        except Exception:
            raise OAuthAttemptError("Host credential vault could not securely store the account") from None
        return account

    def revoke(self, *, credential_ref: str) -> bool:
        """Revoke through the issuer's advertised endpoint, then clear local tokens.

        False means remote revocation could not be confirmed; registration
        identity/client mapping remains available for a later sign-in.
        """
        try:
            account = self.vault.load(credential_ref)
            if account.host_id != self.host_id or not account.refresh_token:
                raise OAuthAttemptError("Stored ChatGPT session is unavailable")
            configuration = self.transport.get_json(DISCOVERY_ENDPOINT, timeout=10)
            endpoint = configuration.get("revocation_endpoint") if isinstance(configuration, Mapping) else None
            parsed = urlsplit(endpoint) if isinstance(endpoint, str) else None
            if (parsed is None or parsed.scheme != "https" or parsed.hostname != "auth.openai.com"
                    or parsed.path != "/api/accounts/oauth/revoke" or parsed.query or parsed.fragment):
                raise OAuthAttemptError("OpenAI revocation endpoint is not the issuer endpoint")
            form = {
                "token": account.refresh_token, "token_type_hint": "refresh_token",
                "client_id": account.client_id,
            }
            confirmed = False
            for attempt in range(3):
                try:
                    response = self.transport.post_form(endpoint, form, timeout=15)
                    status = response.get("status_code", 200) if isinstance(response, Mapping) else 0
                    if status == 200:
                        confirmed = True
                        break
                    if not isinstance(status, int) or not 500 <= status <= 599:
                        break
                except Exception:
                    if attempt == 2:
                        break
                if attempt < 2:
                    self.sleep((0.1, 0.3)[attempt])
        except Exception:
            confirmed = False
        finally:
            try:
                self.vault.clear_tokens(credential_ref)
            except Exception:
                # Keep the result truthful: callers must not report local sign-out
                # until their vault confirms token removal.
                raise OAuthAttemptError("Host credential vault could not clear the local session") from None
        return confirmed

    def refresh(self, *, credential_ref: str) -> ChatGPTAccount:
        with self._locks_guard:
            lock = self._account_locks.setdefault(credential_ref, threading.Lock())
        with lock:
            try:
                account = self.vault.load(credential_ref)
                if account.host_id != self.host_id or PLAN_SCOPE not in account.scopes:
                    raise OAuthAttemptError("Stored ChatGPT account is not eligible for plan inference")
                response = self.transport.post_form(TOKEN_ENDPOINT, {
                    "grant_type": "refresh_token", "client_id": account.client_id,
                    "refresh_token": account.refresh_token, "resource": RESOURCE,
                }, timeout=15)
                access, refresh, identity, scopes, expires = _token_response(
                response, inherited_scopes=account.scopes, now=self.clock())
                if "id_token" in response:
                    claims = self.verify_id_token(identity, "", account.client_id)
                    subject = _nonempty(claims.get("sub"), "verified account subject", 512)
                    if claims.get("iss") != ISSUER or subject != account.subject:
                        raise OAuthAttemptError("Refreshed OpenAI identity changed")
                else:
                    identity = account.id_token
                    subject = account.subject
                updated = ChatGPTAccount(account.client_id, account.host_id, subject,
                    account.email, scopes, access, refresh, identity, expires)
                self.vault.save(credential_ref, updated)
                return updated
            except OAuthAttemptError:
                raise
            except Exception:
                raise OAuthAttemptError("OpenAI credential refresh failed safely") from None
