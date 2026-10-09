"""Host-managed Sign in with ChatGPT public-client flow (PR-F01 / PR-R0124/25).

All HTTP and credential persistence are injected host-broker interfaces. This
module never opens a network connection or writes reusable tokens to profiles.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
import threading
import time
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


class OAuthAttemptError(CredentialError):
    """Safe sign-in or refresh failure."""


class OAuthTransport(Protocol):
    def post_form(self, endpoint: str, values: Mapping[str, str], *, timeout: float) -> Mapping[str, object]: ...


class HostCredentialVault(Protocol):
    """Host-owned vault; implementations store encrypted/protected credentials by reference."""

    def save(self, reference: str, account: "ChatGPTAccount") -> None: ...
    def load(self, reference: str) -> "ChatGPTAccount": ...
    def delete(self, reference: str) -> None: ...


@dataclass(frozen=True, slots=True)
class OAuthAttempt:
    callback_uri: str
    host_id: str
    client_id: str
    state: str = field(repr=False)
    nonce: str = field(repr=False)
    verifier: str = field(repr=False)
    authorize_url: str = field(repr=False)


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


class ChatGPTPlanAuth:
    """OAuth code+PKCE integration for eligible ChatGPT-plan Responses calls."""

    def __init__(self, *, host_id: str, agent_name: str, transport: OAuthTransport,
                 vault: HostCredentialVault,
                 verify_id_token: Callable[[str, str, str], Mapping[str, object]],
                 clock: Callable[[], float] = time.time):
        if not host_id.startswith("urn:uuid:") or len(host_id) > 64:
            raise ValueError("a stable urn:uuid host ID is required")
        if not agent_name or len(agent_name) > 128:
            raise ValueError("a stable application name is required")
        self.host_id, self.agent_name = host_id, agent_name
        self.transport, self.vault, self.verify_id_token = transport, vault, verify_id_token
        self.clock = clock
        self._locks_guard = threading.Lock()
        self._account_locks: dict[str, threading.Lock] = {}

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
        return OAuthAttempt(callback_uri, self.host_id, selected, state, nonce, verifier, url)

    def complete(self, attempt: OAuthAttempt, callback_url: str, *, credential_ref: str,
                 expected_subject: str | None = None) -> ChatGPTAccount:
        if not isinstance(attempt, OAuthAttempt) or attempt.host_id != self.host_id:
            raise OAuthAttemptError("Pending OAuth attempt does not belong to this host")
        _validate_callback_uri(attempt.callback_uri)
        parsed = urlsplit(callback_url)
        if (parsed.scheme, parsed.hostname, parsed.port, parsed.path) != (
                "http", "127.0.0.1", urlsplit(attempt.callback_uri).port, CALLBACK_PATH):
            raise OAuthAttemptError("OAuth callback endpoint does not match the pending request")
        fields = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
        if any(len(v) != 1 for v in fields.values()):
            raise OAuthAttemptError("OAuth callback contains duplicate parameters")
        state = _nonempty(fields.get("state", [None])[0], "state", 256)
        if not secrets.compare_digest(state, attempt.state):
            raise OAuthAttemptError("OAuth callback state did not match")
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
            access, refresh, id_token, scopes, expires = _token_response(tokens)
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
