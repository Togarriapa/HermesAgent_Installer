"""Narrow manually owned Jarvis gateway stage; distinct from installer authority.

The only public proof used here is a fresh round trip through the same protected
Access edge using the user's original application token. This module does not
construct RootRemoteSessionClient, authority rows, or installer receipts.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import signal
import socket
import ssl
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlsplit

from .gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt
from ..network import BoundedNetwork, HTTPResult, NetworkError

STAGE_CONFIG = Path("/etc/hermes-installer/gateway-stage.json")
GATEWAY_HOST, GATEWAY_PORT = "127.0.0.1", 8765
XPRA_HOST, XPRA_PORT = "127.0.0.1", 14500
XPRA_UNIT = "hermes-xpra-stage.service"
PROFILE = "hermes-desktop"
MAX_LEASE_SECONDS = 30
MAX_PROBE_SECONDS = 5
MAX_PROBES = 4096


class ManualStageDenied(PermissionError):
    """The separate manual-stage gateway is unavailable or denied."""


@dataclass(frozen=True, slots=True)
class ManualGatewayStageConfig:
    hostname: str
    issuer: str
    audience: str
    allowed_emails: frozenset[str]
    gateway_uid: int
    gateway_gid: int
    xpra_uid: int
    display_number: int
    xpra_binary: Path
    xpra_binary_sha256: str
    xpra_program: Path
    xpra_program_sha256: str
    xpra_argv_sha256: str
    unit_fragment: Path
    unit_sha256: str
    appdir: Path
    appdir_manifest_sha256: str
    boot_id: str
    config_path: Path = field(repr=False)
    config_sha256: str = field(repr=False)

    @classmethod
    def load(cls, path: Path = STAGE_CONFIG, *, expected_owner_uid: int = 0) -> "ManualGatewayStageConfig":
        if path != STAGE_CONFIG or not path.is_absolute():
            raise ManualStageDenied("manual stage config must use the fixed protected path")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner_uid
                        or stat.S_IMODE(info.st_mode) not in {0o400, 0o600} or info.st_size > 16_384):
                    raise ManualStageDenied("manual stage config is not an owned private regular file")
                raw = b""
                while len(raw) <= 16_384:
                    chunk = os.read(fd, min(4096, 16_385 - len(raw)))
                    if not chunk:
                        break
                    raw += chunk
            finally:
                os.close(fd)
        except OSError:
            raise ManualStageDenied("manual stage config is unavailable") from None
        if not raw or len(raw) > 16_384:
            raise ManualStageDenied("manual stage config exceeds its bound")
        try:
            value = json.loads(raw, object_pairs_hook=_unique_json_pairs)
        except Exception:
            raise ManualStageDenied("manual stage config is malformed") from None
        expected = {"schema", "hostname", "issuer", "audience", "allowed_emails",
                    "listener_host", "listener_port", "xpra_host", "xpra_port", "xpra_unit",
                    "gateway_uid", "gateway_gid", "xpra_uid", "display_number", "xpra_binary", "xpra_binary_sha256",
                    "xpra_program", "xpra_program_sha256", "xpra_argv_sha256",
                    "unit_fragment", "unit_sha256", "appdir", "appdir_manifest_sha256", "boot_id"}
        if not isinstance(value, dict) or set(value) != expected or type(value.get("schema")) is not int or value["schema"] != 1:
            raise ManualStageDenied("manual stage config has an unknown schema")
        if ((value["listener_host"], value["listener_port"], value["xpra_host"], value["xpra_port"], value["xpra_unit"])
                != (GATEWAY_HOST, GATEWAY_PORT, XPRA_HOST, XPRA_PORT, XPRA_UNIT)):
            raise ManualStageDenied("manual stage endpoints or unit differ from the fixed Gateway contract")
        try:
            emails = value["allowed_emails"]
            if (not isinstance(emails, list) or not emails or len(emails) > 16
                    or any(not isinstance(x, str) or not x for x in emails)):
                raise ValueError
            result = cls(value["hostname"], value["issuer"], value["audience"],
                         frozenset(x.casefold() for x in emails), value["gateway_uid"],
                         value["gateway_gid"], value["xpra_uid"], value["display_number"],
                         Path(value["xpra_binary"]), value["xpra_binary_sha256"],
                         Path(value["xpra_program"]),
                         value["xpra_program_sha256"],
                         value["xpra_argv_sha256"],
                         Path(value["unit_fragment"]), value["unit_sha256"],
                         Path(value["appdir"]), value["appdir_manifest_sha256"], value["boot_id"], path,
                         hashlib.sha256(raw).hexdigest())
            if (type(result.gateway_uid) is not int or result.gateway_uid <= 0
                    or type(result.gateway_gid) is not int or result.gateway_gid <= 0
                    or type(result.xpra_uid) is not int or result.xpra_uid <= 0
                    or type(result.display_number) is not int or not 1 <= result.display_number <= 999
                    or result.gateway_uid == result.xpra_uid
                    or not result.xpra_binary.is_absolute() or not result.unit_fragment.is_absolute() or
                    not result.appdir.is_absolute() or result.xpra_program != Path("/usr/bin/xpra")
                    or not _digest(result.xpra_binary_sha256) or not _digest(result.xpra_program_sha256)
                    or not _digest(result.xpra_argv_sha256) or not _digest(result.unit_sha256)
                    or not _digest(result.appdir_manifest_sha256)
                    or not re.fullmatch(r"[0-9a-f-]{36}", result.boot_id)):
                raise ValueError
            if result.hostname != "jarvis.togarriapahome.uk":
                raise ValueError
            RemotePolicy(result.hostname, result.issuer, result.audience, result.allowed_emails,
                         _FreshStageJWKS(result.issuer))
            return result
        except Exception:
            raise ManualStageDenied("manual stage Access identity or Xpra binding is invalid") from None


def _digest(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


class _FreshStageJWKS:
    """Use the existing bounded Cloudflare JWKS reader without stale cache hits."""
    def __init__(self, issuer: str):
        from .jwks import JWKSCache
        self.cache = JWKSCache(issuer, ttl_seconds=1)

    def key(self, kid: str, *, cancel_event=None, deadline_monotonic=None):
        self.cache.load(force=True, cancel_event=cancel_event, deadline_monotonic=deadline_monotonic)
        return self.cache.key(kid, cancel_event=cancel_event, deadline_monotonic=deadline_monotonic)


@dataclass(frozen=True, slots=True)
class _PendingProbe:
    action: str
    session_id: str
    token_sha256: str
    email: str
    subject: str
    config_sha256: str
    expires: float


class StageEdgeAccessVerifier:
    """One-use same-app Access-edge witness; no URL, proxy, or token callback."""
    def __init__(self, config: ManualGatewayStageConfig, *, monotonic=time.monotonic):
        self.config = config
        self.policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                                   config.allowed_emails, _FreshStageJWKS(config.issuer))
        self.monotonic = monotonic
        self._pending: dict[str, _PendingProbe] = {}
        self._lock = threading.Lock()

    def verify(self, access_jwt: str, *, action: str, session_id: str) -> tuple[Principal, float, float]:
        if (action not in {"asset-read", "websocket-attach", "renew"}
                or not isinstance(session_id, str) or not 20 <= len(session_id) <= 128
                or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in session_id)):
            raise ManualStageDenied("edge verification action/session is invalid")
        started = self.monotonic()
        probe_deadline = started + MAX_PROBE_SECONDS
        principal = validate_access_jwt(access_jwt, policy=self.policy,
                                        deadline_monotonic=probe_deadline)
        now = self.monotonic()
        nonce = secrets.token_urlsafe(32)
        fingerprint = hashlib.sha256(access_jwt.encode("ascii", "strict")).hexdigest()
        with self._lock:
            self._purge(now)
            if len(self._pending) >= MAX_PROBES:
                raise ManualStageDenied("Access edge-probe capacity is exhausted")
            self._pending[nonce] = _PendingProbe(action, session_id, fingerprint, principal.email, principal.subject,
                                                  self.config.config_sha256, now + MAX_PROBE_SECONDS)
        try:
            path = "/__stage_access_probe?" + urlencode({"nonce": nonce})
            remaining = probe_deadline - self.monotonic()
            if remaining < 0.1:
                raise ManualStageDenied("Access edge verification exceeded its hard deadline")
            response = BoundedNetwork(deadline_seconds=remaining, socket_timeout=min(3.0, remaining),
                                      max_response_bytes=4096, requester=_stage_edge_https_request).request(
                f"https://{self.config.hostname}{path}", method="GET", headers={
                    "Host": self.config.hostname,
                    "Cookie": "CF_Authorization=" + access_jwt,
                    "Cache-Control": "no-cache, no-store, max-age=0",
                    "Pragma": "no-cache", "Accept": "application/json",
                    "Accept-Encoding": "identity", "Connection": "close",
                })
            cache_control = {part.strip().casefold() for part in response.headers.get("cache-control", "").split(",")}
            if (response.status != 200 or response.headers.get("location") is not None
                    or response.headers.get("content-encoding") not in (None, "identity")
                    or response.headers.get("content-type", "").split(";", 1)[0].casefold() != "application/json"
                    or not {"no-store", "no-cache"}.issubset(cache_control)):
                raise ManualStageDenied("Access edge did not return a fresh protected probe")
            length = response.headers.get("content-length")
            if length is not None and (not length.isdecimal() or int(length) > 4096):
                raise ManualStageDenied("Access edge probe response exceeds its bound")
            body = response.body
            if not body or len(body) > 4096 or (length is not None and int(length) != len(body)):
                raise ManualStageDenied("Access edge probe response exceeds its bound")
            answer = json.loads(body)
            expected = {"schema", "nonce", "token_sha256", "email", "subject", "config_sha256"}
            if (not isinstance(answer, dict) or set(answer) != expected or answer.get("schema") != 1
                    or not secrets.compare_digest(str(answer.get("nonce", "")), nonce)
                    or not secrets.compare_digest(str(answer.get("token_sha256", "")), fingerprint)
                    or answer.get("email") != principal.email or answer.get("subject") != principal.subject
                    or answer.get("config_sha256") != self.config.config_sha256):
                raise ManualStageDenied("Access edge witness does not bind the submitted identity")
            now_mono = self.monotonic()
            jwt_deadline = now_mono + max(0.0, principal.expires_at - time.time())
            grant_until = min(jwt_deadline, now_mono + MAX_LEASE_SECONDS)
            if grant_until <= self.monotonic():
                raise ManualStageDenied("Access edge authorization expired")
            return principal, grant_until, jwt_deadline
        except ManualStageDenied:
            raise
        except Exception:
            raise ManualStageDenied("fresh protected Access edge verification failed") from None
        finally:
            with self._lock:
                self._pending.pop(nonce, None)


    def consume_probe(self, *, nonce: str, cookie_jwt: str, forwarded_jwt: str) -> bytes:
        # Consume first, even when the presented assertion is wrong, so the
        # nonce cannot be retried with a different identity or header set.
        with self._lock:
            record = self._pending.pop(nonce, None)
        if (not isinstance(nonce, str) or not nonce or len(nonce) > 128
                or not isinstance(cookie_jwt, str) or not isinstance(forwarded_jwt, str)
                or not cookie_jwt or not forwarded_jwt):
            raise ManualStageDenied("probe assertion or nonce is invalid")
        try:
            submitted = cookie_jwt.encode("ascii", "strict")
            forwarded = forwarded_jwt.encode("ascii", "strict")
            fingerprint = hashlib.sha256(submitted).hexdigest()
        except (UnicodeError, ValueError):
            raise ManualStageDenied("probe assertion is not valid ASCII") from None
        if (record is None or self.monotonic() >= record.expires
                or not secrets.compare_digest(submitted, forwarded)
                or not secrets.compare_digest(record.token_sha256, fingerprint)
                or record.config_sha256 != self.config.config_sha256):
            raise ManualStageDenied("probe nonce is unknown, stale, replayed, or configuration-stale")
        principal = validate_access_jwt(cookie_jwt, policy=self.policy,
                                        deadline_monotonic=record.expires)
        if principal.email != record.email or principal.subject != record.subject:
            raise ManualStageDenied("probe principal differs from its registered token")
        return json.dumps({"schema": 1, "nonce": nonce, "token_sha256": fingerprint,
                           "email": principal.email, "subject": principal.subject,
                           "config_sha256": record.config_sha256},
                          sort_keys=True, separators=(",", ":")).encode("ascii")

    def _purge(self, now: float) -> None:
        self._pending = {n: p for n, p in self._pending.items() if p.expires > now}


def _stage_edge_https_request(url: str, method: str, headers: dict[str, str], body: bytes | None,
                              socket_timeout: float, maximum: int) -> HTTPResult:
    """BoundedNetwork child requester; fixed origin, no proxy or redirect."""
    import http.client
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != "jarvis.togarriapahome.uk"
            or parsed.port not in {None, 443} or parsed.username or parsed.password
            or parsed.fragment or parsed.path != "/__stage_access_probe"
            or method != "GET" or body is not None):
        raise NetworkError("manual edge probe origin or route differs")
    expected_headers = {"host", "cookie", "cache-control", "pragma", "accept",
                        "accept-encoding", "connection"}
    if (not isinstance(headers, dict) or {key.casefold() for key in headers} != expected_headers
            or headers.get("Host") != "jarvis.togarriapahome.uk"
            or headers.get("Cache-Control") != "no-cache, no-store, max-age=0"
            or headers.get("Pragma") != "no-cache"
            or headers.get("Accept") != "application/json"
            or headers.get("Accept-Encoding") != "identity"
            or headers.get("Connection") != "close"
            or not isinstance(headers.get("Cookie"), str)
            or not headers["Cookie"].startswith("CF_Authorization=")):
        raise NetworkError("manual edge probe headers differ")
    token = headers["Cookie"][len("CF_Authorization="):]
    if (not token or len(token) > 16_384 or any(c in token for c in "\r\n; ")):
        raise NetworkError("manual edge probe cookie is invalid")
    from urllib.parse import parse_qsl
    try:
        params = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise NetworkError("manual edge probe query differs") from None
    if (len(params) != 1 or params[0][0] != "nonce"
            or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", params[0][1])):
        raise NetworkError("manual edge probe query differs")
    connection = http.client.HTTPSConnection(parsed.hostname, 443, timeout=socket_timeout,
                                             context=ssl.create_default_context())
    try:
        connection.request("GET", parsed.path + "?" + parsed.query, headers=headers)
        response = connection.getresponse()
        data = response.read(maximum + 1)
        if len(data) > maximum:
            raise NetworkError("manual edge response exceeds bound")
        rows: dict[str, str] = {}
        for key, value in response.getheaders():
            folded = key.casefold()
            if folded in rows:
                raise NetworkError("duplicate manual edge response header")
            rows[folded] = value
        return HTTPResult(response.status, rows, data)
    finally:
        connection.close()



@dataclass(frozen=True, slots=True)
class StageGatewayAdmission:
    """Stage-only record. It intentionally makes no root/session-generation claim."""
    handle: str = field(repr=False)
    session_id: str
    admission_kind: str
    principal_binding_id: str
    profile_id: str
    gateway_generation: str
    desktop_generation: str
    route_id: str
    issued_monotonic: float
    lease_expires_monotonic: float
    jwt_expires_monotonic: float
    policy_verified_monotonic: float
    policy_revision: str
    policy_config_digest: str


@dataclass(frozen=True, slots=True)
class StageGatewayChallenge:
    session_id: str
    renewal_nonce: str = field(repr=False)
    expires_monotonic: float


@dataclass(slots=True)
class _StageRecord:
    admission: StageGatewayAdmission
    principal: Principal
    access_jwt: str = field(repr=False)
    last_edge_check: float = 0.0
    challenge: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)
    challenge_expiry: float = 0.0


class StageGatewayPolicySessionAdapter:
    """Issuer-retained manual-stage sessions backed by fresh Access-edge proofs."""
    def __init__(self, config: ManualGatewayStageConfig, verifier: StageEdgeAccessVerifier):
        if verifier.config is not config:
            raise ValueError("stage session and edge verifier must share the exact config object")
        self.config, self.verifier = config, verifier
        # GatewayRuntime uses this public field only to assert that policy and
        # session issuers share the configured hostname.
        self.hostname = config.hostname
        self._records: dict[str, _StageRecord] = {}
        self._lock = threading.RLock()
        self.monotonic = time.monotonic

    def admit(self, *, access_jwt: str, action: str, route_id: str) -> StageGatewayAdmission:
        expected_kind = ("one-shot-asset" if action == "asset-read" and route_id == "xpra-http"
                         else "leased-websocket" if action == "websocket-attach" and route_id == "xpra-websocket"
                         else None)
        if expected_kind is None:
            raise ManualStageDenied("manual-stage route is outside the fixed Xpra surface")
        _read_config_current(self.config)
        sid = secrets.token_urlsafe(24)
        principal, expiry, jwt_deadline = self.verifier.verify(access_jwt, action=action, session_id=sid)
        self._verify_xpra_current()
        now = self.monotonic()
        with self._lock:
            self._purge(now)
            if expected_kind == "leased-websocket" and sum(
                    row.admission.admission_kind == "leased-websocket" for row in self._records.values()) >= 1:
                raise ManualStageDenied("manual-stage has one active WebSocket lease")
            handle = secrets.token_urlsafe(32)
            admission = StageGatewayAdmission(
                handle, sid, expected_kind, hashlib.sha256((principal.email + "\0" + principal.subject).encode()).hexdigest(),
                PROFILE, "manual-stage", "manual-stage-xpra", route_id, now, expiry,
                jwt_deadline, now, "manual-edge-probe-v1", self.config.config_sha256)
            # Existing browser code renews every 25 seconds; leave a small
            # scheduling margin while keeping the grant itself at <=30s.
            record = _StageRecord(admission, principal, access_jwt, now,
                                  challenge_expiry=min(expiry, now + 29))
            self._records[handle] = record
            return admission

    def challenge(self, handle: Any) -> StageGatewayChallenge:
        with self._lock:
            record = self._current(handle)
            if record.admission.admission_kind != "leased-websocket":
                raise ManualStageDenied("renewal challenge is only available for a WebSocket session")
            return StageGatewayChallenge(record.admission.session_id, record.challenge, record.challenge_expiry)

    def renew(self, *, handle: Any, session_id: str, access_jwt: str, renewal_nonce: str) -> float:
        with self._lock:
            record = self._current(handle)
            if (record.admission.admission_kind != "leased-websocket"
                    or record.admission.session_id != session_id
                    or self.monotonic() >= record.challenge_expiry
                    or not secrets.compare_digest(record.challenge, renewal_nonce)):
                self._records.pop(handle, None)
                raise ManualStageDenied("manual-stage renewal challenge is stale or mismatched")
            record.challenge = ""  # consume before the edge roundtrip
        try:
            principal, expiry, jwt_deadline = self.verifier.verify(access_jwt, action="renew", session_id=session_id)
            if (principal.subject != record.principal.subject or principal.email != record.principal.email
                    or expiry <= self.monotonic()):
                raise ManualStageDenied("fresh Access edge renewal changed principal or expired")
            self._verify_xpra_current()
        except Exception:
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("fresh Access edge renewal was denied") from None
        with self._lock:
            current = self._current(handle)
            now = self.monotonic()
            current.principal = principal
            current.access_jwt = access_jwt
            current.last_edge_check = now
            current.challenge = secrets.token_urlsafe(32)
            current.challenge_expiry = min(expiry, now + 29)
            current.admission = StageGatewayAdmission(
                current.admission.handle, current.admission.session_id, current.admission.admission_kind,
                current.admission.principal_binding_id, current.admission.profile_id,
                current.admission.gateway_generation, current.admission.desktop_generation,
                current.admission.route_id, current.admission.issued_monotonic,
                min(expiry, now + MAX_LEASE_SECONDS), jwt_deadline, now,
                "manual-edge-probe-v1", self.config.config_sha256)
            return current.admission.lease_expires_monotonic

    def close(self, handle: Any, *, session_id: str | None = None) -> None:
        with self._lock:
            record = self._records.get(handle)
            if record is not None and (session_id is None or record.admission.session_id == session_id):
                self._records.pop(handle, None)

    def current(self, handle: Any) -> StageGatewayAdmission:
        with self._lock:
            return self._current(handle).admission

    def verify_fresh_access_edge(self, handle: Any) -> None:
        """Recheck the active token at most every four seconds while streaming."""
        with self._lock:
            record = self._current(handle)
            now = self.monotonic()
            if now - record.last_edge_check < 4.0:
                return
            token = record.access_jwt
            session_id = record.admission.session_id
            principal_before = record.principal
        try:
            principal, _lease, _jwt_deadline = self.verifier.verify(
                token, action="renew", session_id=session_id)
            if principal.subject != principal_before.subject or principal.email != principal_before.email:
                raise ManualStageDenied("fresh Access edge check changed the active principal")
        except Exception:
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("active Access edge authorization is no longer current") from None
        with self._lock:
            current = self._current(handle)
            if current is not record:
                raise ManualStageDenied("active Access session changed during edge check")
            current.last_edge_check = self.monotonic()

    def _current(self, handle: Any) -> _StageRecord:
        record = self._records.get(handle)
        if (record is None or record.admission.lease_expires_monotonic <= self.monotonic()
                or record.admission.policy_config_digest != self.config.config_sha256):
            self._records.pop(handle, None)
            raise ManualStageDenied("manual-stage session is absent, stale, or configuration-changed")
        return record

    def _verify_xpra_current(self) -> None:
        StageXpraUnitReadback(self.config).verify()


    def _purge(self, now: float) -> None:
        self._records = {h: r for h, r in self._records.items()
                         if r.admission.lease_expires_monotonic > now}


class StageXpraUnitReadback:
    """Use the root-only fixed inspector for current UID/firewall/unit proof."""
    def __init__(self, config: ManualGatewayStageConfig):
        self.config = config

    def verify(self) -> None:
        if os.geteuid() != self.config.gateway_uid:
            raise ManualStageDenied("manual gateway process does not match its dedicated configured UID")
        try:
            from .manual_stage_inspector import verify_current_inspection
            verify_current_inspection(self.config)
        except Exception:
            raise ManualStageDenied("root current firewall, Xpra unit, or app readback is unavailable") from None


class StageEdgeProbeHandler:
    def __init__(self, verifier: StageEdgeAccessVerifier):
        self.verifier = verifier

    async def __call__(self, request):
        from aiohttp import web
        try:
            hosts = request.headers.getall("Host", [])
            cookie_headers = request.headers.getall("Cookie", [])
            forwarded_headers = request.headers.getall("Cf-Access-Jwt-Assertion", [])
            if (request.method != "GET" or len(hosts) != 1
                    or hosts[0].casefold() != self.verifier.config.hostname.casefold()
                    or len(request.query) != 1 or set(request.query) != {"nonce"}
                    or request.can_read_body or request.content_length not in (None, 0)
                    or request.headers.get("Transfer-Encoding") is not None
                    or len(cookie_headers) != 1 or len(forwarded_headers) != 1):
                raise ManualStageDenied("invalid probe request")
            forwarded = forwarded_headers[0]
            cookie = cookie_headers[0]
            token = _cookie_value(cookie, "CF_Authorization")
            body = await asyncio.to_thread(self.verifier.consume_probe, nonce=request.query["nonce"],
                                           cookie_jwt=token, forwarded_jwt=forwarded)
            return web.Response(body=body, content_type="application/json", headers={
                "Cache-Control": "no-store, no-cache, max-age=0", "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff"})
        except Exception:
            return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})


def _cookie_value(header: str, name: str) -> str:
    if not isinstance(header, str) or len(header) > 20_000:
        raise ManualStageDenied("cookie header exceeds bound")
    values: dict[str, str] = {}
    for item in header.split(";"):
        key, separator, value = item.strip().partition("=")
        if not separator or not key or key in values:
            raise ManualStageDenied("cookie header is ambiguous")
        values[key] = value.strip()
    if name not in values or not values[name] or values[name].count("="):
        raise ManualStageDenied("original Access cookie is absent")
    return values[name]


def _read_config_current(config: ManualGatewayStageConfig) -> None:
    try:
        fd = os.open(config.config_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o600}):
                raise ValueError
            digest = hashlib.sha256()
            total = 0
            while True:
                data = os.read(fd, 8192)
                if not data:
                    break
                total += len(data)
                if total > 16_384:
                    raise ValueError
                digest.update(data)
        finally:
            os.close(fd)
        if digest.hexdigest() != config.config_sha256:
            raise ValueError
    except Exception:
        raise ManualStageDenied("root-owned manual stage config changed") from None


class StageFixedXpraConnector:
    """Server-compatible stream bound to one currently verified Xpra stage unit."""
    def __init__(self, config: ManualGatewayStageConfig, sessions: StageGatewayPolicySessionAdapter):
        if sessions.config is not config:
            raise ValueError("fixed connector and session issuer must share exact stage config")
        self.config, self.sessions = config, sessions

    def open(self, handle: Any):
        _read_config_current(self.config)
        self.sessions._verify_xpra_current()
        admission = self.sessions.current(handle)
        if admission.route_id == "xpra-http":
            return _StageHTTPConnector(self, admission)
        if admission.route_id == "xpra-websocket":
            return _StageWebSocketConnector(self, admission)
        raise ManualStageDenied("connector route is not the fixed Xpra app")

    def verify_current(self, admission: StageGatewayAdmission) -> None:
        _read_config_current(self.config)
        current = self.sessions.current(admission.handle)
        if (current.session_id != admission.session_id or current.route_id != admission.route_id
                or current.lease_expires_monotonic <= time.monotonic()):
            raise ManualStageDenied("Xpra connector lease is no longer current")
        self.sessions.verify_fresh_access_edge(admission.handle)
        self.sessions._verify_xpra_current()


class _StageHTTPConnector:
    def __init__(self, owner: StageFixedXpraConnector, admission: StageGatewayAdmission):
        self.owner, self.admission = owner, admission
        self.session_id, self.route_id = admission.session_id, admission.route_id
        self.expires_monotonic = admission.lease_expires_monotonic
        self.sock = socket.create_connection((XPRA_HOST, XPRA_PORT), timeout=4)
        self.sock.settimeout(4)

    def write(self, data: bytes) -> None:
        self.owner.verify_current(self.admission)
        if not isinstance(data, bytes) or len(data) > 65_536 or b"X-Forwarded-Proto:" in data:
            raise ManualStageDenied("Xpra asset request exceeds bound")
        split = data.find(b"\r\n\r\n")
        if split < 0 or b"\r\nHost: 127.0.0.1:14500\r\n" not in data[:split + 2]:
            raise ManualStageDenied("Xpra asset request is not the fixed framed route")
        self.sock.sendall(data[:split] + b"\r\nX-Forwarded-Proto: https\r\n\r\n")

    def read(self, maximum_bytes: int = 65_536) -> bytes:
        self.owner.verify_current(self.admission)
        if not 1 <= maximum_bytes <= 65_536:
            raise ManualStageDenied("Xpra asset response read exceeds bound")
        return self.sock.recv(maximum_bytes)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


class _StageWebSocketConnector:
    def __init__(self, owner: StageFixedXpraConnector, admission: StageGatewayAdmission):
        self.owner, self.admission = owner, admission
        self.session_id, self.route_id = admission.session_id, admission.route_id
        self.expires_monotonic = admission.lease_expires_monotonic
        self._ready = threading.Event()
        self._failure: BaseException | None = None
        self._thread = threading.Thread(target=self._thread_main, name="jarvis-xpra-stage-ws", daemon=True)
        self._thread.start()
        if not self._ready.wait(6) or self._failure is not None:
            self.close()
            raise ManualStageDenied("fixed loopback Xpra WebSocket is unavailable") from self._failure

    def _thread_main(self) -> None:
        import concurrent.futures
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            from aiohttp import ClientSession, ClientTimeout
            async def connect():
                self.client = ClientSession(timeout=ClientTimeout(total=None, connect=4, sock_read=4))
                self.websocket = await self.client.ws_connect(
                    f"http://{XPRA_HOST}:{XPRA_PORT}/client/", protocols=("binary",),
                    autoping=False, autoclose=False, compress=0,
                    headers={"X-Forwarded-Proto": "https"})
                async def edge_watchdog():
                    while not self.websocket.closed:
                        await asyncio.sleep(4)
                        try:
                            await asyncio.to_thread(self.owner.verify_current, self.admission)
                        except Exception:
                            await self.websocket.close(code=1008, message=b"Access edge authorization expired")
                            return
                self._edge_watchdog = asyncio.create_task(edge_watchdog())
            self.loop.run_until_complete(connect())
        except BaseException as exc:
            self._failure = exc
        finally:
            self._ready.set()
        if self._failure is None:
            self.loop.run_forever()
        pending = asyncio.all_tasks(self.loop)
        for task in pending:
            task.cancel()
        if pending:
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        self.loop.close()

    def _run(self, coro, timeout=5):
        if self._failure is not None:
            raise ManualStageDenied("loopback Xpra WebSocket failed")
        self.owner.verify_current(self.admission)
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result(timeout=timeout)

    def write(self, data: bytes) -> None:
        if not isinstance(data, bytes) or len(data) > 1_048_576:
            raise ManualStageDenied("Xpra WebSocket frame exceeds bound")
        self._run(self.websocket.send_bytes(data), timeout=5)

    def read(self, maximum_bytes: int = 65_536) -> bytes:
        from aiohttp import WSMsgType
        if not 1 <= maximum_bytes <= 65_536:
            raise ManualStageDenied("Xpra WebSocket read exceeds bound")
        async def receive():
            while True:
                msg = await self.websocket.receive(timeout=4)
                if msg.type == WSMsgType.BINARY:
                    if len(msg.data) > maximum_bytes:
                        raise ManualStageDenied("Xpra WebSocket frame exceeds bound")
                    return msg.data
                if msg.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING, WSMsgType.ERROR}:
                    return b""
                if msg.type == WSMsgType.PING:
                    await self.websocket.pong(msg.data)
        try:
            return self._run(receive(), timeout=5)
        except Exception:
            return b""

    def close(self) -> None:
        if getattr(self, "loop", None) is not None and self.loop.is_running():
            async def cleanup():
                if getattr(self, "websocket", None) is not None and not self.websocket.closed:
                    await self.websocket.close()
                if getattr(self, "client", None) is not None:
                    await self.client.close()
            try:
                asyncio.run_coroutine_threadsafe(cleanup(), self.loop).result(timeout=3)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
            self._thread.join(timeout=3)


class StageGatewayLaunch:
    def __init__(self, policy: RemotePolicy, stage_sessions: StageGatewayPolicySessionAdapter,
                 fixed_connector: StageFixedXpraConnector):
        if (stage_sessions.config is not fixed_connector.config
                or policy.hostname != stage_sessions.config.hostname
                or policy.issuer != stage_sessions.config.issuer
                or policy.audience != stage_sessions.config.audience
                or policy.allowed_emails != stage_sessions.config.allowed_emails):
            raise ManualStageDenied("manual stage launch inputs are not the same root-owned policy/config")
        self.policy, self.stage_sessions, self.fixed_connector = policy, stage_sessions, fixed_connector


async def serve_stage_gateway(launch: StageGatewayLaunch, stop: asyncio.Event) -> None:
    """Serve the typed manual stage through existing route/framing/session guards."""
    from aiohttp import web
    if not isinstance(launch, StageGatewayLaunch) or not isinstance(stop, asyncio.Event):
        raise ManualStageDenied("typed manual stage launch is required")
    _read_config_current(launch.stage_sessions.config)
    launch.stage_sessions._verify_xpra_current()
    app = create_stage_gateway_app(launch)
    runner = web.AppRunner(app, access_log=None, handle_signals=False)
    await runner.setup()
    site = web.TCPSite(runner, host=GATEWAY_HOST, port=GATEWAY_PORT, reuse_address=False)
    try:
        await site.start()
        sockets = tuple(getattr(getattr(site, "_server", None), "sockets", ()) or ())
        if not sockets or any(sock.getsockname()[:2] != (GATEWAY_HOST, GATEWAY_PORT) for sock in sockets):
            raise ManualStageDenied("manual gateway did not bind its exact loopback socket")
        await stop.wait()
    finally:
        await runner.cleanup()


def create_stage_gateway_app(launch: StageGatewayLaunch):
    """Compose the reviewed existing route handlers with the sole edge probe."""
    from .server import GatewayRuntime, create_app
    if not isinstance(launch, StageGatewayLaunch):
        raise ManualStageDenied("typed manual stage launch is required")
    config = launch.stage_sessions.config
    if (config is not launch.fixed_connector.config
            or launch.policy.hostname != config.hostname
            or launch.policy.issuer != config.issuer
            or launch.policy.audience != config.audience
            or launch.policy.allowed_emails != config.allowed_emails):
        raise ManualStageDenied("manual stage app policy/config binding changed")
    runtime = GatewayRuntime(policy=launch.policy, root_sessions=launch.stage_sessions,
                             connector_factory=launch.fixed_connector.open,
                             max_lease_seconds=MAX_LEASE_SECONDS, max_active_sockets=1,
                             watchdog_seconds=5)
    app = create_app(runtime)
    app.router.add_get("/__stage_access_probe", StageEdgeProbeHandler(launch.stage_sessions.verifier))
    return app


def main() -> None:
    """The service config is root-owned; the gateway starts only as a non-root UID."""
    parser = argparse.ArgumentParser(description="separately owned Jarvis manual gateway stage")
    parser.add_argument("--config", type=Path, default=STAGE_CONFIG)
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise SystemExit("manual Access gateway must run as its dedicated unprivileged service UID")
    config = ManualGatewayStageConfig.load(args.config)
    policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                          config.allowed_emails, _FreshStageJWKS(config.issuer))
    edge = StageEdgeAccessVerifier(config)
    sessions = StageGatewayPolicySessionAdapter(config, edge)
    connector = StageFixedXpraConnector(config, sessions)
    launch = StageGatewayLaunch(policy, sessions, connector)
    stop = asyncio.Event()
    async def run():
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(sig, stop.set)
        await serve_stage_gateway(launch, stop)
    asyncio.run(run())


if __name__ == "__main__":
    main()
