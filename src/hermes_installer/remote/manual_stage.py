"""Narrow manually owned Jarvis gateway stage; distinct from installer authority.

Public requests arrive only over the fixed cloudflared Unix origin. Each request
is bound to kernel peer credentials and a fresh root observation; browser
heartbeats keep active WebSocket forwarding inside the short witness lifetime.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import math
import os
import re
import secrets
import signal
import socket
import stat
import threading
import time
import contextvars
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt

STAGE_CONFIG = Path("/etc/hermes-installer/gateway-stage.json")
GATEWAY_HOST, GATEWAY_PORT = "127.0.0.1", 8765
GATEWAY_INGRESS_SOCKET = Path("/run/hermes-jarvis-mvp-gateway/origin.sock")
GATEWAY_UNIT = "hermes-jarvis-mvp-gateway.service"
TUNNEL_UNIT = "hermes-jarvis-mvp-tunnel.service"
XPRA_HOST, XPRA_PORT = "127.0.0.1", 14500
XPRA_UNIT = "hermes-xpra-stage.service"
HERMES_STAGE_EXECUTABLE = Path("/opt/hermes-jarvis-mvp-20261011/Hermes-Desktop.AppDir/Hermes")
PROFILE = "hermes-desktop"
MAX_LEASE_SECONDS = 30
MAX_PROBE_SECONDS = 5
_STAGE_DIAGNOSTIC = logging.getLogger("hermes_installer.remote.manual_stage")
_STAGE_PHASES = frozenset({"headers", "jwt", "unix-peer", "root-inspector", "listener-join",
                           "ingress-proof-join", "middleware-ingress", "handler", "heartbeat-handler", "route-response",
                           "response-currentness", "session-response", "index-injection"})
_INGRESS_CURRENTNESS_PHASES = frozenset({"shape", "request-age", "root-proof", "listener-path"})


def _log_stage_denial(phase: str, exception: BaseException | str) -> None:
    """Emit fixed phase and exception type only; never include request data or exception text."""
    if phase not in _STAGE_PHASES:
        phase = "handler"
    name = exception if isinstance(exception, str) else type(exception).__name__
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", name):
        name = "OtherException"
    _STAGE_DIAGNOSTIC.warning("manual-stage denial phase=%s exception=%s", phase, name)


def _log_ingress_currentness_failure(phase: str, elapsed_ms: int) -> None:
    """Log only a fixed subphase and bounded monotonic age, never request data."""
    if phase not in _INGRESS_CURRENTNESS_PHASES:
        phase = "shape"
    if type(elapsed_ms) is not int:
        elapsed_ms = 0
    elapsed_ms = min(60_000, max(0, elapsed_ms))
    _STAGE_DIAGNOSTIC.warning("manual-stage ingress-currentness phase=%s elapsed_ms=%d", phase, elapsed_ms)


class ManualStageDenied(PermissionError):
    """The separate manual-stage gateway is unavailable or denied."""


_INGRESS_SEAL = object()
_CURRENT_INGRESS: contextvars.ContextVar["StageAcceptedIngressObservation | None"] = contextvars.ContextVar(
    "hermes_manual_stage_ingress", default=None)
@dataclass(slots=True)
class _RequestNativeObservationCapture:
    """Mutable request-local handoff across asyncio.to_thread context copies."""
    observation: Any | None = None


_CURRENT_NATIVE_OBSERVATION: contextvars.ContextVar[_RequestNativeObservationCapture | None] = contextvars.ContextVar(
    "hermes_manual_stage_native_observation", default=None)


@dataclass(frozen=True, slots=True)
class StageAcceptedIngressObservation:
    """Private join of this request's Unix peer, local JWT and root readback."""
    request_started_monotonic: float
    witness_expires_monotonic: float
    token_sha256: str = field(repr=False)
    principal: Principal = field(repr=False)
    jwt_expires_monotonic: float
    peer_pid: int
    peer_uid: int
    peer_gid: int
    config_sha256: str
    _root_observation: Any = field(repr=False, compare=False)
    listener_device: int
    listener_inode: int
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: "ManualGatewayStageConfig", *, now: float | None = None) -> None:
        observed_now = time.monotonic() if now is None else now
        elapsed_ms = int(min(60_000, max(0, (observed_now - self.request_started_monotonic) * 1000)))
        if (self._seal is not _INGRESS_SEAL or self.config_sha256 != config.config_sha256
                or not _digest(self.token_sha256) or not _digest(self.config_sha256)
                or type(self.peer_pid) is not int or self.peer_pid <= 1
                or type(self.peer_uid) is not int or self.peer_uid <= 0
                or type(self.peer_gid) is not int or self.peer_gid <= 0
                or self.witness_expires_monotonic > self.request_started_monotonic + MAX_PROBE_SECONDS
                or observed_now < self.request_started_monotonic
                or observed_now >= self.jwt_expires_monotonic):
            _log_ingress_currentness_failure("shape", elapsed_ms)
            raise ManualStageDenied("protected ingress witness is stale or mismatched")
        if observed_now >= self.witness_expires_monotonic:
            _log_ingress_currentness_failure("request-age", elapsed_ms)
            raise ManualStageDenied("protected ingress witness is stale or mismatched")
        try:
            from .manual_stage_inspector import StageVerifiedIngressObservation
            if type(self._root_observation) is not StageVerifiedIngressObservation:
                _log_ingress_currentness_failure("root-proof", elapsed_ms)
                raise ValueError
            if self._root_observation.verify_current(
                    config, self.peer_pid, self.peer_uid, self.peer_gid, now=observed_now) is not True:
                _log_ingress_currentness_failure("root-proof", elapsed_ms)
                raise ValueError
            listener = os.lstat(config.ingress_socket)
            if (not stat.S_ISSOCK(listener.st_mode)
                    or listener.st_uid != config.gateway_uid
                    or listener.st_gid != config.gateway_gid
                    or stat.S_IMODE(listener.st_mode) != 0o660
                    or (listener.st_dev, listener.st_ino) != (self.listener_device, self.listener_inode)
                    or (listener.st_dev, listener.st_ino) != (
                        self._root_observation.origin_socket_device,
                        self._root_observation.origin_socket_inode)):
                _log_ingress_currentness_failure("listener-path", elapsed_ms)
                raise ValueError
        except Exception:
            raise ManualStageDenied("root cloudflared ingress or listener proof is no longer current") from None


def _mint_accepted_ingress(config: "ManualGatewayStageConfig", *, request_started: float,
                           token: str, principal: Principal, peer_pid: int, peer_uid: int,
                           peer_gid: int, root_observation: Any,
                           listener_identity: tuple[int, int]) -> StageAcceptedIngressObservation:
    fingerprint = hashlib.sha256(token.encode("ascii", "strict")).hexdigest()
    jwt_deadline = request_started + max(0.0, principal.expires_at - time.time())
    witness_deadline = min(root_observation.expires_monotonic,
                           request_started + MAX_PROBE_SECONDS, jwt_deadline)
    result = StageAcceptedIngressObservation(request_started, witness_deadline, fingerprint,
        principal, jwt_deadline, peer_pid, peer_uid, peer_gid, config.config_sha256,
        root_observation, listener_identity[0], listener_identity[1], _INGRESS_SEAL)
    result.verify_current(config)
    return result


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
    gateway_unit_sha256: str
    tunnel_unit_sha256: str
    cloudflared_binary_sha256: str
    ingress_socket: Path
    config_path: Path = field(repr=False)
    config_sha256: str = field(repr=False)

    @classmethod
    def load(cls, path: Path = STAGE_CONFIG, *, expected_owner_uid: int = 0,
             allow_stale_boot_id: bool = False) -> "ManualGatewayStageConfig":
        if path != STAGE_CONFIG or not path.is_absolute():
            raise ManualStageDenied("manual stage config must use the fixed protected path")
        if allow_stale_boot_id and os.geteuid() != 0:
            raise ManualStageDenied("only the root boot-refresh helper may read a stale boot identity")
        try:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner_uid
                        or stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o600}
                        or info.st_size > 16_384):
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
                    "unit_fragment", "unit_sha256", "appdir", "appdir_manifest_sha256", "boot_id",
                    "gateway_unit_sha256", "tunnel_unit_sha256", "cloudflared_binary_sha256", "ingress_socket"}
        if not isinstance(value, dict) or set(value) != expected or type(value.get("schema")) is not int or value["schema"] != 2:
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
                         Path(value["appdir"]), value["appdir_manifest_sha256"], value["boot_id"],
                         value["gateway_unit_sha256"], value["tunnel_unit_sha256"],
                         value["cloudflared_binary_sha256"], Path(value["ingress_socket"]), path,
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
                    or not _digest(result.gateway_unit_sha256)
                    or not _digest(result.tunnel_unit_sha256)
                    or not _digest(result.cloudflared_binary_sha256)
                    or result.ingress_socket != GATEWAY_INGRESS_SOCKET
                    or result.appdir != HERMES_STAGE_EXECUTABLE.parent
                    or not re.fullmatch(r"[0-9a-f-]{36}", result.boot_id)
                    or (not allow_stale_boot_id and
                        Path("/proc/sys/kernel/random/boot_id").read_text().strip() != result.boot_id)):
                raise ValueError
            if (os.geteuid() not in {expected_owner_uid, result.gateway_uid}
                    or (stat.S_IMODE(info.st_mode) == 0o440 and info.st_gid != result.gateway_gid)):
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
    """Use the bounded Cloudflare reader with a one-second signing-key cache."""
    def __init__(self, issuer: str):
        from .jwks import JWKSCache
        self.cache = JWKSCache(issuer, ttl_seconds=1)

    def key(self, kid: str, *, cancel_event=None, deadline_monotonic=None):
        return self.cache.key(kid, cancel_event=cancel_event, deadline_monotonic=deadline_monotonic)


class StageEdgeAccessVerifier:
    """Validate locally verified JWTs bound to this request's protected ingress."""
    def __init__(self, config: ManualGatewayStageConfig, *, monotonic=time.monotonic):
        self.config = config
        self.policy = RemotePolicy(config.hostname, config.issuer, config.audience,
                                   config.allowed_emails, _FreshStageJWKS(config.issuer))
        self.monotonic = monotonic

    def verify(self, access_jwt: str, *, action: str, session_id: str,
               accepted_ingress: StageAcceptedIngressObservation | None = None,
               probe_budget_seconds: float = MAX_PROBE_SECONDS) -> tuple[Principal, float, float]:
        if (action not in {"asset-read", "websocket-attach", "renew"}
                or not isinstance(session_id, str) or not 20 <= len(session_id) <= 128
                or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in session_id)
                or type(probe_budget_seconds) not in (int, float)
                or not 0.5 <= probe_budget_seconds <= MAX_PROBE_SECONDS):
            raise ManualStageDenied("edge verification action/session is invalid")
        if accepted_ingress is None:
            accepted_ingress = _CURRENT_INGRESS.get()
        if accepted_ingress is None:
            raise ManualStageDenied("current protected cloudflared ingress is required")
        accepted_ingress.verify_current(self.config, now=self.monotonic())
        fingerprint = hashlib.sha256(access_jwt.encode("ascii", "strict")).hexdigest()
        if not secrets.compare_digest(fingerprint, accepted_ingress.token_sha256):
            raise ManualStageDenied("Access assertion differs from the current protected request")
        principal = accepted_ingress.principal
        if (action not in {"asset-read", "websocket-attach", "renew"}
                or not isinstance(session_id, str) or not 20 <= len(session_id) <= 128):
            raise ManualStageDenied("stage authorization action is invalid")
        now_mono = accepted_ingress.request_started_monotonic
        jwt_deadline = accepted_ingress.jwt_expires_monotonic
        grant_until = min(jwt_deadline, now_mono + MAX_LEASE_SECONDS)
        if grant_until <= self.monotonic():
            raise ManualStageDenied("Access authorization expired")
        return principal, grant_until, jwt_deadline



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
    heartbeat_nonce: str = field(default_factory=lambda: secrets.token_hex(32), repr=False)
    heartbeat_expiry: float = 0.0
    last_ingress: StageAcceptedIngressObservation | None = field(default=None, repr=False)
    native_observation: Any = field(default=None, repr=False)


class StageGatewayPolicySessionAdapter:
    """Issuer-retained stage sessions backed by each protected Unix ingress."""
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
        ingress = _CURRENT_INGRESS.get()
        if ingress is None:
            raise ManualStageDenied("a current protected cloudflared ingress is required")
        ingress.verify_current(self.config, now=self.monotonic())
        _read_config_current(self.config)
        sid = secrets.token_urlsafe(24)
        principal, expiry, jwt_deadline = self.verifier.verify(access_jwt, action=action,
            session_id=sid, accepted_ingress=ingress)
        native_observation = self._verify_xpra_current()
        now = self.monotonic()
        ingress.verify_current(self.config, now=now)
        _verify_native_observation_current(self.config, native_observation, now=now)
        if (now - ingress.request_started_monotonic > MAX_PROBE_SECONDS
                or now >= min(expiry, jwt_deadline)):
            raise ManualStageDenied("manual-stage request witness expired while checking Xpra state")
        with self._lock:
            self._purge(now)
            if expected_kind == "leased-websocket" and sum(
                    row.admission.admission_kind == "leased-websocket" for row in self._records.values()) >= 1:
                raise ManualStageDenied("manual-stage has one active WebSocket lease")
            handle = secrets.token_urlsafe(32)
            admission = StageGatewayAdmission(
                handle, sid, expected_kind, hashlib.sha256((principal.email + "\0" + principal.subject).encode()).hexdigest(),
                PROFILE, "manual-stage", "manual-stage-xpra", route_id, now, expiry,
                jwt_deadline, ingress.request_started_monotonic, "manual-unix-ingress-v263",
                self.config.config_sha256)
            record = _StageRecord(admission, principal, access_jwt,
                                  last_edge_check=ingress.request_started_monotonic,
                                  challenge_expiry=min(expiry, now + 29),
                                  heartbeat_expiry=min(expiry, ingress.witness_expires_monotonic),
                                  last_ingress=ingress, native_observation=native_observation)
            self._records[handle] = record
            capture = _CURRENT_NATIVE_OBSERVATION.get()
            if capture is not None:
                capture.observation = native_observation
            return admission

    def heartbeat_material(self, handle: Any) -> tuple[str, str]:
        with self._lock:
            record = self._current(handle)
            if record.admission.admission_kind != "leased-websocket":
                raise ManualStageDenied("heartbeat requires the active WebSocket session")
            return record.admission.session_id, record.heartbeat_nonce

    def heartbeat(self, *, session_id: str, nonce: str,
                  accepted_ingress: StageAcceptedIngressObservation) -> tuple[str, float]:
        with self._lock:
            record = next((item for item in self._records.values()
                           if item.admission.session_id == session_id), None)
            now = self.monotonic()
            if (record is None or record.admission.admission_kind != "leased-websocket"
                    or record.admission.lease_expires_monotonic <= now
                    or record.admission.jwt_expires_monotonic <= now
                    or record.heartbeat_expiry <= now
                    or not secrets.compare_digest(record.heartbeat_nonce, nonce)):
                if record is not None:
                    self._records.pop(record.admission.handle, None)
                raise ManualStageDenied("stage heartbeat nonce is absent, stale, or replayed")
            record.heartbeat_nonce = ""  # consume before any proof or state lookup
            handle = record.admission.handle
            original_principal = record.principal
            original_fingerprint = hashlib.sha256(record.access_jwt.encode("ascii", "strict")).hexdigest()
        try:
            accepted_ingress.verify_current(self.config, now=self.monotonic())
            if (accepted_ingress.request_started_monotonic > accepted_ingress.witness_expires_monotonic
                    or self.monotonic() - accepted_ingress.request_started_monotonic > MAX_PROBE_SECONDS
                    or not secrets.compare_digest(accepted_ingress.token_sha256, original_fingerprint)
                    or accepted_ingress.principal.subject != original_principal.subject
                    or accepted_ingress.principal.email != original_principal.email):
                raise ManualStageDenied("stage heartbeat binding mismatch")
        except Exception:
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("stage heartbeat is not bound to the original Access session")
        with self._lock:
            current = self._current(handle)
            if current is not record:
                raise ManualStageDenied("stage session changed during heartbeat verification")
            current.last_edge_check = accepted_ingress.request_started_monotonic
            current.last_ingress = accepted_ingress
            current.heartbeat_nonce = secrets.token_hex(32)
            current.heartbeat_expiry = min(current.admission.lease_expires_monotonic,
                                           current.admission.jwt_expires_monotonic,
                                           accepted_ingress.witness_expires_monotonic,
                                           accepted_ingress.request_started_monotonic + MAX_PROBE_SECONDS)
            return current.heartbeat_nonce, current.heartbeat_expiry

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
            record.challenge = ""  # consume before proof validation or renewal
            original_fingerprint = hashlib.sha256(record.access_jwt.encode("ascii", "strict")).hexdigest()
            original_jwt_deadline = record.admission.jwt_expires_monotonic
        ingress = _CURRENT_INGRESS.get()
        if ingress is None:
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("a fresh protected ingress is required for renewal")
        ingress.verify_current(self.config, now=self.monotonic())
        if not secrets.compare_digest(ingress.token_sha256,
                                      hashlib.sha256(access_jwt.encode("ascii", "strict")).hexdigest()):
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("renewal Access assertion differs from protected request")
        try:
            principal, expiry, jwt_deadline = self.verifier.verify(access_jwt, action="renew",
                session_id=session_id, accepted_ingress=ingress)
            if (principal.subject != record.principal.subject or principal.email != record.principal.email
                    or not secrets.compare_digest(original_fingerprint, ingress.token_sha256)
                    or expiry <= self.monotonic()):
                raise ManualStageDenied("protected Access renewal changed principal or expired")
            jwt_deadline = min(original_jwt_deadline, jwt_deadline)
            native_observation = self._verify_xpra_current()
            ingress.verify_current(self.config, now=self.monotonic())
            _verify_native_observation_current(self.config, native_observation, now=self.monotonic())
            if (self.monotonic() - ingress.request_started_monotonic > MAX_PROBE_SECONDS
                    or self.monotonic() >= min(expiry, jwt_deadline)):
                raise ManualStageDenied("manual-stage renewal witness expired during current-state checks")
        except Exception:
            self.close(handle, session_id=session_id)
            raise ManualStageDenied("fresh Access edge renewal was denied") from None
        with self._lock:
            current = self._current(handle)
            now = self.monotonic()
            current.principal = principal
            current.access_jwt = access_jwt
            current.last_edge_check = ingress.request_started_monotonic
            current.native_observation = native_observation
            capture = _CURRENT_NATIVE_OBSERVATION.get()
            if capture is not None:
                capture.observation = native_observation
            current.challenge = secrets.token_urlsafe(32)
            current.challenge_expiry = min(expiry, jwt_deadline, now + 29)
            current.admission = StageGatewayAdmission(
                current.admission.handle, current.admission.session_id, current.admission.admission_kind,
                current.admission.principal_binding_id, current.admission.profile_id,
                current.admission.gateway_generation, current.admission.desktop_generation,
                current.admission.route_id, current.admission.issued_monotonic,
                min(expiry, jwt_deadline, now + MAX_LEASE_SECONDS), jwt_deadline,
                ingress.request_started_monotonic, "manual-unix-ingress-v263", self.config.config_sha256)
            current.heartbeat_expiry = min(current.admission.lease_expires_monotonic,
                                           ingress.request_started_monotonic + MAX_PROBE_SECONDS)
            current.last_ingress = ingress
            return current.admission.lease_expires_monotonic

    def close(self, handle: Any, *, session_id: str | None = None) -> None:
        with self._lock:
            record = self._records.get(handle)
            if record is not None and (session_id is None or record.admission.session_id == session_id):
                self._records.pop(handle, None)

    def current(self, handle: Any) -> StageGatewayAdmission:
        with self._lock:
            return self._current(handle).admission

    def assert_current_proofs(self, handle: Any) -> None:
        """Require both current witnesses before any Xpra connector I/O."""
        with self._lock:
            record = self._current(handle)
            now = self.monotonic()
            if now - record.last_edge_check > MAX_PROBE_SECONDS:
                self._records.pop(handle, None)
                raise ManualStageDenied("active edge or root observation proof is stale")
            if record.last_ingress is None:
                self._records.pop(handle, None)
                raise ManualStageDenied("active protected ingress receipt is absent")
            try:
                record.last_ingress.verify_current(self.config, now=now)
            except Exception:
                self._records.pop(handle, None)
                raise ManualStageDenied("active protected ingress receipt is stale") from None
            try:
                _verify_native_observation_current(self.config, record.native_observation, now=now)
            except Exception:
                self._records.pop(handle, None)
                raise ManualStageDenied("active native Xpra observation is stale") from None

    def refresh_active_edge(self, handle: Any) -> None:
        """Check the browser's fresh protected heartbeat; never replay a token."""
        self.assert_current_proofs(handle)

    def refresh_active_inspection(self, handle: Any) -> None:
        with self._lock:
            record = self._current(handle)
        # The WebSocket watchdog has a three-second overall budget.  Keep its
        # wait behind concurrent admissions bounded well below that budget.
        from .manual_stage_inspector import WATCHDOG_INSPECTION_QUEUE_WAIT_SECONDS
        native_observation = self._verify_xpra_current(queue_timeout_seconds=WATCHDOG_INSPECTION_QUEUE_WAIT_SECONDS)
        inspected_at = self.monotonic()
        try:
            _verify_native_observation_current(self.config, native_observation, now=inspected_at)
        except Exception:
            self.close(handle, session_id=record.admission.session_id)
            raise ManualStageDenied("fresh root Xpra inspection exceeded its proof lifetime")
        with self._lock:
            current = self._current(handle)
            if current is not record:
                raise ManualStageDenied("active Xpra stage changed during root inspection")
            current.native_observation = native_observation

    def _current(self, handle: Any) -> _StageRecord:
        record = self._records.get(handle)
        if (record is None or record.admission.lease_expires_monotonic <= self.monotonic()
                or record.admission.policy_config_digest != self.config.config_sha256):
            self._records.pop(handle, None)
            raise ManualStageDenied("manual-stage session is absent, stale, or configuration-changed")
        return record

    def _verify_xpra_current(self, *, queue_timeout_seconds: float | None = None):
        return StageXpraUnitReadback(self.config).verify(queue_timeout_seconds=queue_timeout_seconds)


    def _purge(self, now: float) -> None:
        self._records = {h: r for h, r in self._records.items()
                         if r.admission.lease_expires_monotonic > now}


class StageXpraUnitReadback:
    """Use the root-only fixed inspector for current UID/firewall/unit proof."""
    def __init__(self, config: ManualGatewayStageConfig):
        self.config = config

    def verify(self, *, queue_timeout_seconds: float | None = None):
        if os.geteuid() != self.config.gateway_uid:
            raise ManualStageDenied("manual gateway process does not match its dedicated configured UID")
        try:
            from .manual_stage_inspector import verify_current_inspection
            if queue_timeout_seconds is None:
                observation = verify_current_inspection(self.config)
            else:
                observation = verify_current_inspection(self.config, queue_timeout_seconds=queue_timeout_seconds)
            _verify_native_observation_current(self.config, observation, now=time.monotonic())
            return observation
        except Exception:
            raise ManualStageDenied("root current firewall, Xpra unit, or app readback is unavailable") from None


def _verify_native_observation_current(config: ManualGatewayStageConfig, observation: Any, *, now: float) -> None:
    """Require the exact root-minted native snapshot and its original live lease."""
    from .manual_stage_inspector import StageNativeInspectionObservation
    if (type(observation) is not StageNativeInspectionObservation
            or type(observation.issued_monotonic) not in (int, float)
            or type(observation.expires_monotonic) not in (int, float)
            or not math.isfinite(observation.issued_monotonic)
            or not math.isfinite(observation.expires_monotonic)
            or observation.issued_monotonic > now
            or not observation.issued_monotonic < observation.expires_monotonic <=
                observation.issued_monotonic + MAX_PROBE_SECONDS
            or observation.expires_monotonic <= now
            or observation.verify_current(config, now=now) is not True):
        raise ManualStageDenied("root native Xpra observation is stale or mismatched")


def _read_config_current(config: ManualGatewayStageConfig) -> None:
    try:
        fd = os.open(config.config_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o600}
                    or (stat.S_IMODE(info.st_mode) == 0o440 and info.st_gid != config.gateway_gid)):
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
        # Admission already performed a fresh nonce-bound full root inspection.
        # Reuse only that exact session witness while assert_current_proofs
        # confirms it remains inside its five-second validity window.
        self.sessions.assert_current_proofs(handle)
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
        self.sessions.assert_current_proofs(admission.handle)


class _StageHTTPConnector:
    def __init__(self, owner: StageFixedXpraConnector, admission: StageGatewayAdmission):
        self.owner, self.admission = owner, admission
        self.session_id, self.route_id = admission.session_id, admission.route_id
        self.expires_monotonic = admission.lease_expires_monotonic
        self.sock = socket.create_connection((XPRA_HOST, XPRA_PORT), timeout=4)
        self.sock.settimeout(4)

    def write(self, data: bytes) -> None:
        self.owner.verify_current(self.admission)
        if not isinstance(data, bytes) or len(data) > 65_536:
            raise ManualStageDenied("Xpra asset request exceeds bound")
        split = data.find(b"\r\n\r\n")
        if split < 0:
            raise ManualStageDenied("Xpra asset request is not the fixed framed route")
        try:
            lines = data[:split].decode("ascii", "strict").split("\r\n")
            request_parts = lines[0].split(" ")
            if len(request_parts) != 3 or request_parts[2] != "HTTP/1.1":
                raise ValueError
            method, public_path, _version = request_parts
            from .client_assets import canonical_asset
            canonical = canonical_asset(public_path)
            if canonical != public_path:
                raise ValueError
            origin_path = "/" + canonical.removeprefix("/client/")
            expected_headers = [
                "Host: 127.0.0.1:14500", "Accept: */*",
                "Accept-Encoding: identity", "Connection: close",
            ]
            if method not in {"GET", "HEAD"} or lines[1:] != expected_headers:
                raise ValueError
        except Exception:
            raise ManualStageDenied("Xpra asset request is not the fixed canonical route") from None
        # The public /client/ namespace is a fixed adapter over Xpra's actual
        # root-relative HTML layout. Only canonical manifest members cross it;
        # browser headers and caller-selected origin paths never reach Xpra.
        rewritten = (f"{method} {origin_path} HTTP/1.1\r\n" +
                     "\r\n".join(expected_headers) +
                     "\r\nX-Forwarded-Proto: https\r\n\r\n").encode("ascii")
        self.sock.sendall(rewritten)

    def read(self, maximum_bytes: int = 65_536) -> bytes:
        self.owner.verify_current(self.admission)
        if not 1 <= maximum_bytes <= 65_536:
            raise ManualStageDenied("Xpra asset response read exceeds bound")
        data = self.sock.recv(maximum_bytes)
        # A read may block until the native observation expires. Do not hand
        # newly received app bytes to the HTTP response after that deadline.
        self.owner.verify_current(self.admission)
        return data

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
        self._rx_lock = threading.Lock()
        self._rx_buffer = bytearray()
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
                        await asyncio.sleep(2)
                        try:
                            await asyncio.wait_for(asyncio.gather(
                                asyncio.to_thread(self.owner.sessions.refresh_active_edge, self.admission.handle),
                                asyncio.to_thread(self.owner.sessions.refresh_active_inspection, self.admission.handle)),
                                timeout=3)
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
            if hasattr(coro, "close"):
                coro.close()
            raise ManualStageDenied("loopback Xpra WebSocket failed")
        try:
            self.owner.verify_current(self.admission)
        except Exception:
            if hasattr(coro, "close"):
                coro.close()
            raise
        try:
            future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        except Exception:
            if hasattr(coro, "close"):
                coro.close()
            raise
        return future.result(timeout=timeout)

    def write(self, data: bytes) -> None:
        if not isinstance(data, bytes) or len(data) > 1_048_576:
            raise ManualStageDenied("Xpra WebSocket frame exceeds bound")
        self._run(self.websocket.send_bytes(data), timeout=5)

    def read(self, maximum_bytes: int = 65_536) -> bytes | None:
        from aiohttp import WSMsgType
        if not 1 <= maximum_bytes <= 65_536:
            raise ManualStageDenied("Xpra WebSocket read exceeds bound")
        with self._rx_lock:
            if self._rx_buffer:
                self.owner.verify_current(self.admission)
                data = bytes(self._rx_buffer[:maximum_bytes])
                del self._rx_buffer[:maximum_bytes]
                return data
        async def receive():
            while True:
                try:
                    msg = await self.websocket.receive(timeout=4)
                except asyncio.TimeoutError:
                    return None
                if msg.type == WSMsgType.BINARY:
                    if len(msg.data) > 1_048_576:
                        raise ManualStageDenied("Xpra WebSocket frame exceeds bound")
                    return msg.data
                if msg.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING, WSMsgType.ERROR}:
                    return b""
                if msg.type == WSMsgType.PING:
                    await self.websocket.pong(msg.data)
        try:
            data = self._run(receive(), timeout=5)
            if data is None:
                return None
            self.owner.verify_current(self.admission)
            if len(data) > maximum_bytes:
                with self._rx_lock:
                    self._rx_buffer.extend(data[maximum_bytes:])
                return data[:maximum_bytes]
            return data
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


_STAGE_HEARTBEAT_SCRIPT = r"""<script>(()=>{
const sid=sessionStorage.getItem('hd-stage-sid');let nonce=sessionStorage.getItem('hd-stage-heartbeat');
if(!sid||!nonce)return;let busy=false,stopped=false;
async function beat(){if(busy||stopped)return;busy=true;const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),1500);
try{const r=await fetch('/__stage_access_heartbeat',{method:'POST',cache:'no-store',credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sid,nonce})});
if(!r.ok)throw Error();const x=await r.json();if(!x||Object.keys(x).sort().join(',')!=='nonce,session_id'||x.session_id!==sid||typeof x.nonce!=='string'||!/^[0-9a-f]{64}$/.test(x.nonce))throw Error();nonce=x.nonce;sessionStorage.setItem('hd-stage-heartbeat',nonce);
}catch(_){stopped=true;sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');sessionStorage.removeItem('hd-stage-sid');sessionStorage.removeItem('hd-stage-heartbeat');location.replace('/client/bootstrap.html')}
finally{clearTimeout(timer);busy=false}}
beat();setInterval(beat,1500);
})();</script>"""


def _request_peer_credentials(request, config: ManualGatewayStageConfig) -> tuple[int, int, int]:
    try:
        transport = request.transport
        peer = transport.get_extra_info("socket") if transport is not None else None
        if (peer is None or peer.family != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED")
                or peer.getsockname() != str(config.ingress_socket)):
            raise ValueError
        pid, uid, gid = __import__("struct").unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid <= 1 or uid <= 0 or gid <= 0:
            raise ValueError
        listener = os.lstat(config.ingress_socket)
        if (not stat.S_ISSOCK(listener.st_mode) or listener.st_uid != config.gateway_uid
                or listener.st_gid != config.gateway_gid or stat.S_IMODE(listener.st_mode) != 0o660):
            raise ValueError
        return pid, uid, gid
    except Exception:
        raise ManualStageDenied("request did not arrive over the protected Unix ingress") from None


def _consume_validation_task(task: asyncio.Task) -> None:
    """Observe a cancelled worker's eventual exception without exposing its value."""
    try:
        task.exception()
    except BaseException:
        pass


async def _validate_stage_access_jwt(token: str, policy: RemotePolicy, *, deadline_monotonic: float) -> Principal:
    """Run bounded JWKS/TLS work off-loop; a late worker result is never authority."""
    cancellation = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(validate_access_jwt, token, policy=policy,
        cancel_event=cancellation, deadline_monotonic=deadline_monotonic))
    try:
        remaining = max(0.0, deadline_monotonic - time.monotonic())
        done, _pending = await asyncio.wait({task}, timeout=remaining)
        if not done:
            cancellation.set()
            task.add_done_callback(_consume_validation_task)
            raise GatewayDenied("Access verification deadline expired")
        principal = task.result()
        if cancellation.is_set() or time.monotonic() >= deadline_monotonic:
            cancellation.set()
            raise GatewayDenied("Access verification deadline expired")
        return principal
    except asyncio.CancelledError:
        cancellation.set()
        task.add_done_callback(_consume_validation_task)
        raise


async def _accept_stage_ingress(request, config: ManualGatewayStageConfig,
                                policy: RemotePolicy, *,
                                listener_identity: tuple[int, int] | None = None) -> StageAcceptedIngressObservation:
    request_started = time.monotonic()
    phase = "headers"
    try:
        host_rows = request.headers.getall("Host", [])
        assertion_rows = request.headers.getall("Cf-Access-Jwt-Assertion", [])
        if (len(host_rows) != 1 or host_rows[0].casefold() != config.hostname.casefold()
                or len(assertion_rows) != 1):
            raise ValueError
        origin = request.headers.get("Origin")
        if origin is not None and origin != f"https://{config.hostname}":
            raise ValueError
        if request.path == "/__stage_access_heartbeat" and (
                request.method != "POST" or origin != f"https://{config.hostname}"
                or request.headers.get("Sec-Fetch-Site") not in (None, "same-origin")):
            raise ValueError
        token = assertion_rows[0]
        if not isinstance(token, str) or not 1 <= len(token) <= 16_384:
            raise ValueError
        phase = "jwt"
        principal = await _validate_stage_access_jwt(token, policy=policy,
            deadline_monotonic=request_started + MAX_PROBE_SECONDS)
        phase = "unix-peer"
        peer_pid, peer_uid, peer_gid = _request_peer_credentials(request, config)
        listener = os.lstat(config.ingress_socket)
        current_identity = (listener.st_dev, listener.st_ino)
        if (listener_identity is not None and current_identity != listener_identity):
            raise ValueError
        phase = "root-inspector"
        from .manual_stage_inspector import verify_current_ingress
        observation = await asyncio.wait_for(asyncio.to_thread(
            verify_current_ingress, config, peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid),
            timeout=MAX_PROBE_SECONDS)
        phase = "listener-join"
        if (observation.origin_socket_device != listener.st_dev
                or observation.origin_socket_inode != listener.st_ino
                or os.lstat(config.ingress_socket).st_ino != listener.st_ino
                or os.lstat(config.ingress_socket).st_dev != listener.st_dev):
            raise ValueError
        phase = "ingress-proof-join"
        accepted = _mint_accepted_ingress(config, request_started=request_started,
            token=token, principal=principal, peer_pid=peer_pid, peer_uid=peer_uid,
            peer_gid=peer_gid, root_observation=observation,
            listener_identity=current_identity)
        if time.monotonic() - request_started > MAX_PROBE_SECONDS:
            raise ValueError
        return accepted
    except Exception as exc:
        _log_stage_denial(phase, exc)
        raise ManualStageDenied("protected Access ingress is unavailable or stale") from None


async def _stage_heartbeat(request):
    from aiohttp import web
    launch: StageGatewayLaunch = request.app["manual_stage_launch"]
    try:
        if (request.content_type != "application/json" or request.content_length is None
                or not 1 <= request.content_length <= 2048
                or request.headers.get("Transfer-Encoding") is not None):
            raise ValueError
        raw = await asyncio.wait_for(request.read(), timeout=1.5)
        if len(raw) > 2048:
            raise ValueError
        body = json.loads(raw, object_pairs_hook=_unique_json_pairs)
        if (not isinstance(body, dict) or set(body) != {"session_id", "nonce"}
                or not isinstance(body["session_id"], str) or not 20 <= len(body["session_id"]) <= 64
                or not re.fullmatch(r"[A-Za-z0-9_-]+", body["session_id"])
                or not isinstance(body["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", body["nonce"])):
            raise ValueError
        accepted = request.get("stage_ingress")
        if not isinstance(accepted, StageAcceptedIngressObservation):
            raise ValueError
        next_nonce, _expiry = launch.stage_sessions.heartbeat(
            session_id=body["session_id"], nonce=body["nonce"], accepted_ingress=accepted)
        return web.json_response({"session_id": body["session_id"], "nonce": next_nonce},
            headers={"Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})
    except Exception as exc:
        _log_stage_denial("heartbeat-handler", exc)
        raise ManualStageDenied("stage heartbeat was denied") from None


async def _stage_ingress_middleware(request, handler):
    from aiohttp import web
    launch: StageGatewayLaunch = request.app["manual_stage_launch"]
    try:
        listener_identity = request.app.get("stage_listener_identity")
        if (not isinstance(listener_identity, tuple) or len(listener_identity) != 2
                or any(type(item) is not int or item < 0 for item in listener_identity)):
            raise ManualStageDenied("fixed stage listener identity is unavailable")
        accepted = await _accept_stage_ingress(request, launch.stage_sessions.config, launch.policy,
                                               listener_identity=listener_identity)
    except Exception as exc:
        _log_stage_denial("middleware-ingress", exc)
        return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})
    request["stage_ingress"] = accepted
    context_token = _CURRENT_INGRESS.set(accepted)
    capture = _RequestNativeObservationCapture()
    native_context_token = _CURRENT_NATIVE_OBSERVATION.set(capture)
    try:
        response = await handler(request)
    except Exception as exc:
        _log_stage_denial("handler", exc)
        raise
    finally:
        _CURRENT_NATIVE_OBSERVATION.reset(native_context_token)
        _CURRENT_INGRESS.reset(context_token)
    if response.status >= 400:
        _log_stage_denial("route-response", "HTTPException")
    if request.headers.get("Upgrade", "").casefold() != "websocket":
        try:
            _read_config_current(launch.stage_sessions.config)
            accepted.verify_current(launch.stage_sessions.config)
            if capture.observation is not None:
                _verify_native_observation_current(
                    launch.stage_sessions.config, capture.observation, now=time.monotonic())
        except Exception as exc:
            _log_stage_denial("response-currentness", exc)
            return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})
    if request.path == "/session" and 200 <= response.status < 300:
        try:
            body = json.loads(response.body)
            key = body["lease_id"]
            session = request.app["gateway_runtime"].sessions[key]
            if session.admission.admission_kind == "leased-websocket":
                session_id, nonce = launch.stage_sessions.heartbeat_material(session.admission.handle)
                body["stage_session_id"] = session_id
                body["stage_heartbeat_nonce"] = nonce
                headers = {key: value for key, value in response.headers.items()
                           if key.casefold() not in {"content-length", "content-type"}}
                response = web.json_response(body, status=response.status, headers=headers)
        except Exception as exc:
            _log_stage_denial("session-response", exc)
            return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})
    if (request.path == "/client/index.html" and 200 <= response.status < 300
            and "text/html" in response.headers.get("Content-Type", "")):
        try:
            data = response.body
            text = data.decode("utf-8", "strict")
            head = re.search(r"<head(?:\s[^>]*)?>", text, flags=re.IGNORECASE)
            if head is None:
                raise ValueError
            text = text[:head.end()] + _STAGE_HEARTBEAT_SCRIPT + text[head.end():]
            headers = {key: value for key, value in response.headers.items()
                       if key.casefold() != "content-length"}
            response = web.Response(status=response.status, body=text.encode("utf-8"),
                headers={**headers, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        except Exception as exc:
            _log_stage_denial("index-injection", exc)
            return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})
    return response


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
    socket_path = launch.stage_sessions.config.ingress_socket
    try:
        parent_info = os.lstat(socket_path.parent)
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != launch.stage_sessions.config.gateway_uid
                or parent_info.st_gid != launch.stage_sessions.config.gateway_gid
                or stat.S_IMODE(parent_info.st_mode) != 0o750
                or socket_path.exists() or socket_path.is_symlink()):
            raise ValueError
    except Exception:
        await runner.cleanup()
        raise ManualStageDenied("fixed Unix ingress directory is unavailable or occupied") from None
    site = web.UnixSite(runner, str(socket_path))
    socket_identity = None
    try:
        await site.start()
        socket_info = os.lstat(socket_path)
        if (not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != launch.stage_sessions.config.gateway_uid
                or socket_info.st_gid != launch.stage_sessions.config.gateway_gid):
            raise ManualStageDenied("manual gateway Unix listener has unexpected custody")
        socket_identity = (socket_info.st_dev, socket_info.st_ino)
        os.chmod(socket_path, 0o660)
        app["stage_listener_identity"] = socket_identity
        await stop.wait()
    finally:
        await runner.cleanup()
        if socket_identity is not None:
            try:
                current = os.lstat(socket_path)
                if socket_identity == (current.st_dev, current.st_ino) and stat.S_ISSOCK(current.st_mode):
                    socket_path.unlink()
            except OSError:
                pass


def create_stage_gateway_app(launch: StageGatewayLaunch):
    """Compose existing fixed routes behind protected cloudflared Unix ingress."""
    from aiohttp import web
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
    app["gateway_runtime"] = runtime
    app["manual_stage_launch"] = launch
    app.middlewares.insert(0, web.middleware(_stage_ingress_middleware))
    app.router.add_post("/__stage_access_heartbeat", _stage_heartbeat)
    return app


def main() -> None:
    """The service config is root-owned; the gateway starts only as a non-root UID."""
    argparse.ArgumentParser(description="separately owned Jarvis manual gateway stage").parse_args()
    if os.geteuid() == 0:
        raise SystemExit("manual Access gateway must run as its dedicated unprivileged service UID")
    config = ManualGatewayStageConfig.load()
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
