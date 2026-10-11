"""Core-first Jarvis ingress: fixed Cloudflare policy and current Unix-peer proof.

This is deliberately separate from ``manual_stage``: a core-mode request never
creates an Xpra session or accepts a native Desktop route.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import signal
import socket
import stat
import struct
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .gateway import GatewayDenied, Principal, RemotePolicy, validate_access_jwt

CORE_CONFIG = Path("/etc/hermes-installer/jarvis-core-gateway.json")
CORE_CONFIG_DIR = CORE_CONFIG.parent
CORE_INGRESS_SOCKET = Path("/run/hermes-jarvis-mvp-gateway/origin.sock")
CORE_INSPECTOR_SOCKET = Path("/run/hermes-jarvis-mvp-core/inspection.sock")
CORE_GATEWAY_UNIT = "hermes-jarvis-core-gateway.service"
CORE_GATEWAY_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-core-gateway.service")
CORE_SERVICE_UNIT = "hermes-jarvis-core.service"
CORE_HOST = "127.0.0.1"
CORE_PORT = 8766
CORE_PYTHON_LINK = Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
GATEWAY_EXECUTABLE = Path("/usr/bin/python3.13")
GATEWAY_ARGV = ("/opt/hermes-jarvis-mvp-20261011/gateway-venv/bin/python", "-m",
                "hermes_installer.remote.core_gateway")
MAX_CONFIG_BYTES = 16_384
MAX_REQUEST_BYTES = 1_024
MAX_RESPONSE_BYTES = 4_096
MAX_PROBE_SECONDS = 5.0
_ACCEPTED_INGRESS_SEAL = object()
_LOGGER = logging.getLogger(__name__)
_INGRESS_DIAGNOSTIC_STAGES = frozenset({
    "headers", "origin", "jwt", "unix_peer", "root_inspection", "accepted_proof",
    "config_before_ingress", "accept_ingress", "proof_before_handler", "route_handler",
    "proof_after_handler", "config_before_response", "proof_before_response",
    "unix_peer_socket", "unix_peer_family", "unix_peer_credentials",
    "unix_peer_address", "unix_peer_identity", "unix_peer_listener_metadata",
    "unix_peer_listener_expected", "root_ipc_socket", "root_ipc_exchange",
    "root_ipc_schema", "root_ipc_binding", "root_ipc_currentness",
})
_CHAT_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; "
    "form-action 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "connect-src 'self'; font-src 'self'"
)


def _accepted_claim_digest(*, principal: Principal, jwt_expiry: float, root_proof: Any,
                           peer: tuple[int, int, int], listener: tuple[int, int],
                           issued: float, expiry: float, core_generation: str,
                           config_sha256: str) -> str:
    value = {
        "principal_email": principal.email,
        "principal_subject": principal.subject,
        "principal_expiry": principal.expires_at,
        "principal_token_fingerprint": principal.token_fingerprint,
        "jwt_expires_monotonic": jwt_expiry,
        "root_proof_sha256": root_proof.proof_sha256,
        "peer_pid": peer[0], "peer_uid": peer[1], "peer_gid": peer[2],
        "listener_device": listener[0], "listener_inode": listener[1],
        "issued_monotonic": issued, "expires_monotonic": expiry,
        "core_generation": core_generation, "config_sha256": config_sha256,
    }
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-accepted-ingress-v1\0" + canonical).hexdigest()


class CoreGatewayDenied(PermissionError):
    """Protected core ingress failed closed."""


def _diagnostic_exception_kind(error: BaseException) -> str:
    """Collapse failures to a finite type label; never log exception text or data."""
    known = (CoreGatewayDenied, GatewayDenied, TimeoutError, ValueError, TypeError,
             OSError, PermissionError)
    if type(error) in known:
        return type(error).__name__
    return "OtherError"


def _log_ingress_denial(stage: str, error: BaseException) -> None:
    # Only fixed labels and exact known exception types are emitted, never request material.
    if stage not in _INGRESS_DIAGNOSTIC_STAGES:
        stage = "headers"
    _LOGGER.warning("core_gateway_denied stage=%s exception=%s",
                    stage, _diagnostic_exception_kind(error))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True, slots=True)
class CoreGatewayConfig:
    hostname: str
    issuer: str
    audience: str
    allowed_emails: frozenset[str]
    gateway_uid: int
    gateway_gid: int
    core_uid: int
    core_gid: int
    boot_id: str
    gateway_unit_sha256: str
    gateway_python_sha256: str
    tunnel_unit_sha256: str
    cloudflared_binary_sha256: str
    core_unit_sha256: str
    core_launcher_sha256: str
    core_python: Path
    core_python_sha256: str
    ingress_socket: Path
    config_path: Path = field(repr=False)
    config_sha256: str = field(repr=False)

    @classmethod
    def load(cls, path: Path = CORE_CONFIG, *, expected_owner_uid: int = 0) -> "CoreGatewayConfig":
        if path != CORE_CONFIG or not path.is_absolute():
            raise CoreGatewayDenied("core gateway config must use its fixed path")
        try:
            parent = os.lstat(CORE_CONFIG_DIR)
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != 0
                    or stat.S_IMODE(parent.st_mode) != 0o755):
                raise ValueError
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0))
            try:
                info = os.fstat(fd)
                mode = stat.S_IMODE(info.st_mode)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_owner_uid
                        or info.st_nlink != 1
                        or mode not in {0o400, 0o440, 0o600}
                        or (mode == 0o440 and info.st_gid != 981)
                        or info.st_size > MAX_CONFIG_BYTES):
                    raise ValueError
                raw = bytearray()
                while len(raw) <= MAX_CONFIG_BYTES:
                    part = os.read(fd, min(4096, MAX_CONFIG_BYTES + 1 - len(raw)))
                    if not part:
                        break
                    raw.extend(part)
            finally:
                os.close(fd)
            if not raw or len(raw) > MAX_CONFIG_BYTES:
                raise ValueError
            value = json.loads(bytes(raw), object_pairs_hook=_unique_pairs)
            expected = {
                "schema", "hostname", "issuer", "audience", "allowed_emails",
                "gateway_uid", "gateway_gid", "core_uid", "core_gid", "boot_id",
                "gateway_unit_sha256", "gateway_python_sha256", "tunnel_unit_sha256",
                "cloudflared_binary_sha256", "core_unit_sha256", "core_launcher_sha256",
                "core_python", "core_python_sha256", "ingress_socket",
            }
            if (not isinstance(value, dict) or set(value) != expected
                    or type(value.get("schema")) is not int or value["schema"] != 1):
                raise ValueError
            emails = value["allowed_emails"]
            if (not isinstance(emails, list) or len(emails) != 1
                    or any(not isinstance(email, str) or not email.strip() for email in emails)):
                raise ValueError
            result = cls(value["hostname"], value["issuer"], value["audience"],
                frozenset(email.casefold() for email in emails), value["gateway_uid"],
                value["gateway_gid"], value["core_uid"], value["core_gid"], value["boot_id"],
                value["gateway_unit_sha256"], value["gateway_python_sha256"],
                value["tunnel_unit_sha256"], value["cloudflared_binary_sha256"],
                value["core_unit_sha256"], value["core_launcher_sha256"],
                Path(value["core_python"]), value["core_python_sha256"],
                Path(value["ingress_socket"]), path, hashlib.sha256(raw).hexdigest())
            if ((result.gateway_uid, result.gateway_gid, result.core_uid, result.core_gid)
                    != (996, 981, 1000, 1000)
                    or result.ingress_socket != CORE_INGRESS_SOCKET
                    or result.core_python != CORE_PYTHON_LINK
                    or result.core_python != Path(value["core_python"])
                    or not isinstance(value["core_python"], str)
                    or value["core_python"] != str(CORE_PYTHON_LINK)
                    or not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", result.boot_id)
                    or not all(_sha256(getattr(result, field_name)) for field_name in (
                        "gateway_unit_sha256", "gateway_python_sha256", "tunnel_unit_sha256",
                        "cloudflared_binary_sha256", "core_unit_sha256",
                        "core_launcher_sha256", "core_python_sha256"))):
                raise ValueError
            # Reuse the strict policy validator; no desktop route/session state enters it.
            RemotePolicy(result.hostname, result.issuer, result.audience,
                         result.allowed_emails, {})
            return result
        except Exception:
            raise CoreGatewayDenied("root-owned core gateway config is invalid or unavailable") from None

    def policy(self, jwks: Any) -> RemotePolicy:
        return RemotePolicy(self.hostname, self.issuer, self.audience, self.allowed_emails, jwks)


def _read_config_current(config: CoreGatewayConfig) -> None:
    if type(config) is not CoreGatewayConfig or config.config_path != CORE_CONFIG:
        raise CoreGatewayDenied("core gateway config path changed")
    try:
        fd = os.open(config.config_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) not in {0o400, 0o440, 0o600}
                    or (stat.S_IMODE(info.st_mode) == 0o440 and info.st_gid != config.gateway_gid)):
                raise ValueError
            digest = hashlib.sha256()
            size = 0
            while True:
                chunk = os.read(fd, 8192)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_CONFIG_BYTES:
                    raise ValueError
                digest.update(chunk)
        finally:
            os.close(fd)
        if digest.hexdigest() != config.config_sha256:
            raise ValueError
    except Exception:
        raise CoreGatewayDenied("core gateway config changed") from None


@dataclass(frozen=True, slots=True)
class CoreAcceptedIngressObservation:
    principal: Principal
    jwt_expires_monotonic: float
    root_observation: Any = field(repr=False, compare=False)
    peer_pid: int
    peer_uid: int
    peer_gid: int
    listener_device: int
    listener_inode: int
    issued_monotonic: float
    expires_monotonic: float
    core_generation: str
    _config_sha256: str = field(repr=False)
    _claim_sha256: str = field(repr=False)
    _seal: object = field(repr=False, compare=False)

    @property
    def core_expires_monotonic(self) -> float:
        return self.root_observation.expires_monotonic

    def verify_current(self, config: CoreGatewayConfig, *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            from .core_gateway_inspector import CoreVerifiedIngressObservation
            _read_config_current(config)
            if (self._seal is not _ACCEPTED_INGRESS_SEAL
                    or type(self.principal) is not Principal
                    or not isinstance(self.principal.email, str)
                    or self.principal.email.casefold() not in config.allowed_emails
                    or not isinstance(self.principal.subject, str) or not self.principal.subject
                    or not _sha256(self.principal.token_fingerprint)
                    or type(self.root_observation) is not CoreVerifiedIngressObservation
                    or self._config_sha256 != config.config_sha256
                    or any(type(value) is not int or value < 0 for value in
                           (self.peer_pid, self.peer_uid, self.peer_gid))
                    or self.peer_pid <= 1
                    or any(isinstance(value, bool) or not isinstance(value, (int, float))
                           or not math.isfinite(value) for value in (
                               self.jwt_expires_monotonic, self.issued_monotonic,
                               self.expires_monotonic, current))
                    or self.issued_monotonic > current
                    or not self.issued_monotonic < self.expires_monotonic <=
                        self.issued_monotonic + MAX_PROBE_SECONDS
                    or current >= self.expires_monotonic
                    or current >= self.jwt_expires_monotonic
                    or self.expires_monotonic > self.jwt_expires_monotonic
                    or not self.root_observation.issued_monotonic <= self.expires_monotonic
                    or self.expires_monotonic > self.root_observation.expires_monotonic
                    or self.root_observation.core_generation != self.core_generation
                    or self._claim_sha256 != _accepted_claim_digest(
                        principal=self.principal, jwt_expiry=self.jwt_expires_monotonic,
                        root_proof=self.root_observation,
                        peer=(self.peer_pid, self.peer_uid, self.peer_gid),
                        listener=(self.listener_device, self.listener_inode),
                        issued=self.issued_monotonic, expiry=self.expires_monotonic,
                        core_generation=self.core_generation, config_sha256=self._config_sha256)
                    or self.root_observation.verify_current(config, peer_pid=self.peer_pid,
                        peer_uid=self.peer_uid, peer_gid=self.peer_gid,
                        listener_identity=(self.listener_device, self.listener_inode), now=current) is not True):
                return False
            info = os.lstat(config.ingress_socket)
            return bool(stat.S_ISSOCK(info.st_mode)
                and (info.st_dev, info.st_ino) == (self.listener_device, self.listener_inode))
        except Exception:
            return False


def _request_peer(request: Any, config: CoreGatewayConfig,
                  expected_listener: tuple[int, int] | None) -> tuple[int, int, int, tuple[int, int]]:
    def deny(stage: str, error: BaseException) -> None:
        _log_ingress_denial(stage, error)
        raise CoreGatewayDenied(
            "request did not arrive through the owned Cloudflare Unix ingress") from None

    try:
        transport = request.transport
        peer = transport.get_extra_info("socket") if transport is not None else None
    except Exception as error:
        deny("unix_peer_socket", error)
    if peer is None:
        deny("unix_peer_socket", ValueError())
    if peer.family != socket.AF_UNIX:
        deny("unix_peer_family", ValueError())
    if not hasattr(socket, "SO_PEERCRED"):
        deny("unix_peer_credentials", OSError())
    try:
        pid, uid, gid = struct.unpack(
            "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    except Exception as error:
        deny("unix_peer_credentials", error)
    try:
        peer_address = peer.getsockname()
    except Exception as error:
        deny("unix_peer_address", error)
    if peer_address != str(config.ingress_socket):
        deny("unix_peer_address", ValueError())
    # cloudflared uses a systemd DynamicUser. The root inspector binds this exact
    # kernel tuple to its current unit PID/UID/GID and required gateway group.
    if (any(type(value) is not int or value < 0 for value in (pid, uid, gid))
            or pid <= 1):
        deny("unix_peer_identity", ValueError())
    try:
        listener = os.lstat(config.ingress_socket)
    except Exception as error:
        deny("unix_peer_listener_metadata", error)
    if (not stat.S_ISSOCK(listener.st_mode) or listener.st_uid != config.gateway_uid
            or listener.st_gid != config.gateway_gid or stat.S_IMODE(listener.st_mode) != 0o660):
        deny("unix_peer_listener_metadata", ValueError())
    if (expected_listener is None
            or (listener.st_dev, listener.st_ino) != expected_listener):
        deny("unix_peer_listener_expected", ValueError())
    return pid, uid, gid, (listener.st_dev, listener.st_ino)


async def _validate_jwt(token: str, policy: RemotePolicy, *, deadline: float) -> Principal:
    cancellation = threading.Event()
    task = asyncio.create_task(asyncio.to_thread(validate_access_jwt, token,
        policy=policy, cancel_event=cancellation, deadline_monotonic=deadline))
    try:
        done, _pending = await asyncio.wait({task}, timeout=max(0.0, deadline-time.monotonic()))
        if not done:
            cancellation.set()
            task.add_done_callback(lambda finished: finished.exception() if not finished.cancelled() else None)
            raise GatewayDenied("Access verification deadline expired")
        result = task.result()
        if cancellation.is_set() or time.monotonic() >= deadline:
            raise GatewayDenied("Access verification deadline expired")
        return result
    except asyncio.CancelledError:
        cancellation.set()
        task.add_done_callback(lambda finished: finished.exception() if not finished.cancelled() else None)
        raise


async def accept_core_ingress(request: Any, config: CoreGatewayConfig,
                              policy: RemotePolicy) -> CoreAcceptedIngressObservation:
    started = time.monotonic()
    stage = "headers"
    try:
        hosts = request.headers.getall("Host", [])
        assertions = request.headers.getall("Cf-Access-Jwt-Assertion", [])
        origins = request.headers.getall("Origin", [])
        if (len(hosts) != 1 or hosts[0].casefold() != config.hostname.casefold()
                or len(assertions) != 1 or len(origins) > 1):
            raise ValueError
        stage = "origin"
        origin = origins[0] if origins else None
        is_mutation = request.method not in {"GET", "HEAD", "OPTIONS"}
        is_websocket = request.headers.get("Upgrade", "").casefold() == "websocket"
        if ((origin is not None and origin != f"https://{config.hostname}")
                or ((is_mutation or is_websocket) and origin != f"https://{config.hostname}")):
            raise ValueError
        token = assertions[0]
        if not isinstance(token, str) or not 1 <= len(token) <= 16_384:
            raise ValueError
        stage = "jwt"
        principal = await _validate_jwt(token, policy, deadline=started + MAX_PROBE_SECONDS)
        stage = "unix_peer"
        listener_identity = request.app.get("core_listener_identity")
        peer_pid, peer_uid, peer_gid, listener = _request_peer(request, config, listener_identity)
        stage = "root_inspection"
        from .core_gateway_inspector import verify_current_ingress
        proof = await asyncio.wait_for(asyncio.to_thread(verify_current_ingress, config,
            peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid), timeout=MAX_PROBE_SECONDS)
        stage = "accepted_proof"
        jwt_deadline = started + max(0.0, principal.expires_at - time.time())
        expiry = min(started + MAX_PROBE_SECONDS, jwt_deadline, proof.expires_monotonic)
        accepted = CoreAcceptedIngressObservation(principal, jwt_deadline, proof,
            peer_pid, peer_uid, peer_gid, listener[0], listener[1], started,
            expiry, proof.core_generation, config.config_sha256,
            _accepted_claim_digest(principal=principal, jwt_expiry=jwt_deadline,
                root_proof=proof, peer=(peer_pid, peer_uid, peer_gid), listener=listener,
                issued=started, expiry=expiry, core_generation=proof.core_generation,
                config_sha256=config.config_sha256), _ACCEPTED_INGRESS_SEAL)
        if time.monotonic() >= expiry or not accepted.verify_current(config):
            raise ValueError
        return accepted
    except asyncio.CancelledError:
        raise
    except Exception as error:
        _log_ingress_denial(stage, error)
        raise CoreGatewayDenied("protected core ingress is unavailable or stale") from None


@dataclass(frozen=True, slots=True)
class CoreGatewayLaunch:
    config: CoreGatewayConfig
    policy: RemotePolicy

    def principal_from_request(self, request: Any) -> Any:
        proof = request.get("core_ingress")
        if type(proof) is not CoreAcceptedIngressObservation or not proof.verify_current(self.config):
            raise CoreGatewayDenied("current protected core ingress is required")
        from .jarvis_chat import ChatPrincipal
        return ChatPrincipal(proof.principal.subject, proof.jwt_expires_monotonic,
                             proof.expires_monotonic, proof.core_generation)


def create_core_gateway_app(launch: CoreGatewayLaunch):
    """Compose the finite Jarvis UI and chat adapter behind Access middleware."""
    from aiohttp import web
    from .jarvis_chat import build_jarvis_chat_service, install_jarvis_chat_routes
    from .jarvis_dashboard import install_jarvis_dashboard_routes

    if (type(launch) is not CoreGatewayLaunch or launch.policy.hostname != launch.config.hostname
            or launch.policy.issuer != launch.config.issuer
            or launch.policy.audience != launch.config.audience
            or launch.policy.allowed_emails != launch.config.allowed_emails):
        raise CoreGatewayDenied("core gateway policy/config binding changed")
    app = web.Application(client_max_size=64 * 1024)
    app["core_gateway_launch"] = launch
    service = build_jarvis_chat_service(launch.principal_from_request)
    install_jarvis_chat_routes(app, service)
    install_jarvis_dashboard_routes(app, service)
    _install_core_chat_asset_routes(app)
    app.middlewares.insert(0, web.middleware(_core_ingress_middleware))
    app.on_response_prepare.append(_verify_ingress_before_response_bytes)
    return app


def _install_core_chat_asset_routes(app: Any) -> None:
    """Install only the reviewed UI paths; no static root or arbitrary file route."""
    from aiohttp import web
    from .jarvis_chat_assets import reviewed_chat_asset

    async def home(request: Any):
        if request.raw_path != "/":
            raise web.HTTPNotFound(text="not found")
        raise web.HTTPFound(location="/chat", headers={"Cache-Control": "no-store"})

    async def asset(request: Any):
        try:
            # raw_path makes encoded aliases and query-bearing asset URLs fail closed.
            content_type, body = reviewed_chat_asset(request.raw_path)
        except ValueError:
            raise web.HTTPNotFound(text="not found") from None
        headers = {"Content-Type": content_type}
        if request.raw_path in {"/chat", "/chat/"}:
            headers["Content-Security-Policy"] = _CHAT_CONTENT_SECURITY_POLICY
        return web.Response(body=body, headers=headers)

    app.router.add_get("/", home, allow_head=False)
    for path in ("/chat", "/chat/", "/chat/assets/app.css", "/chat/assets/app.js"):
        app.router.add_get(path, asset, allow_head=False)


async def _verify_ingress_before_response_bytes(request: Any, response: Any) -> None:
    """Recheck the bounded witness immediately before aiohttp emits response headers."""
    proof = request.get("core_ingress")
    if proof is None:
        return
    launch: CoreGatewayLaunch = request.app["core_gateway_launch"]
    if (type(proof) is not CoreAcceptedIngressObservation
            or not proof.verify_current(launch.config)):
        from aiohttp import web
        raise web.HTTPForbidden(text="Forbidden", headers={
            "Cache-Control": "no-store", "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff"})
    _read_config_current(launch.config)
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"


async def _core_ingress_middleware(request: Any, handler):
    from aiohttp import web
    launch: CoreGatewayLaunch = request.app["core_gateway_launch"]
    stage = "config_before_ingress"
    try:
        _read_config_current(launch.config)
        stage = "accept_ingress"
        proof = await accept_core_ingress(request, launch.config, launch.policy)
        request["core_ingress"] = proof
        stage = "proof_before_handler"
        if not proof.verify_current(launch.config):
            raise CoreGatewayDenied("core ingress expired before handler dispatch")
        stage = "route_handler"
        response = await handler(request)
        stage = "proof_after_handler"
        if time.monotonic() >= proof.expires_monotonic:
            raise CoreGatewayDenied("core ingress expired before response")
        stage = "config_before_response"
        _read_config_current(launch.config)
        stage = "proof_before_response"
        if not proof.verify_current(launch.config):
            raise CoreGatewayDenied("core ingress changed before response")
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response
    except asyncio.CancelledError:
        raise
    except web.HTTPException as response:
        _log_ingress_denial(stage, response)
        proof = request.get("core_ingress")
        if (type(proof) is CoreAcceptedIngressObservation
                and proof.verify_current(launch.config)):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        return web.Response(status=403, text="Forbidden", headers={
            "Cache-Control": "no-store", "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff"})
    except Exception as error:
        _log_ingress_denial(stage, error)
        return web.Response(status=403, text="Forbidden", headers={
            "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff"})


async def serve_core_gateway(launch: CoreGatewayLaunch, stop: asyncio.Event) -> None:
    """Serve the finite BFF only through the fixed Cloudflare-owned Unix socket."""
    from aiohttp import web
    if type(launch) is not CoreGatewayLaunch or not isinstance(stop, asyncio.Event):
        raise CoreGatewayDenied("typed core gateway launch is required")
    if os.geteuid() != launch.config.gateway_uid:
        raise CoreGatewayDenied("core gateway process UID differs")
    _read_config_current(launch.config)
    app = create_core_gateway_app(launch)
    runner = web.AppRunner(app, access_log=None, handle_signals=False)
    await runner.setup()
    path = launch.config.ingress_socket
    try:
        parent = os.lstat(path.parent)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != launch.config.gateway_uid
                or parent.st_gid != launch.config.gateway_gid or stat.S_IMODE(parent.st_mode) != 0o750
                or path.exists() or path.is_symlink()):
            raise ValueError
    except Exception:
        await runner.cleanup()
        raise CoreGatewayDenied("fixed core gateway Unix socket path is unavailable") from None
    site = web.UnixSite(runner, str(path))
    identity = None
    try:
        await site.start()
        info = os.lstat(path)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != launch.config.gateway_uid
                or info.st_gid != launch.config.gateway_gid):
            raise CoreGatewayDenied("core gateway Unix listener custody differs")
        identity = (info.st_dev, info.st_ino)
        os.chmod(path, 0o660)
        app["core_listener_identity"] = identity
        await stop.wait()
    finally:
        await runner.cleanup()
        if identity is not None:
            try:
                info = os.lstat(path)
                if identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                    path.unlink()
            except OSError:
                pass


def main() -> None:
    import argparse
    from .jwks import JWKSCache
    argparse.ArgumentParser(description="finite Jarvis core Access gateway").parse_args()
    if os.geteuid() != 996:
        raise SystemExit("core gateway must run as its dedicated UID")
    config = CoreGatewayConfig.load()
    policy = config.policy(JWKSCache(config.issuer, ttl_seconds=1, timeout_seconds=3.0))
    launch = CoreGatewayLaunch(config, policy)
    stop = asyncio.Event()

    async def run() -> None:
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stop.set)
        await serve_core_gateway(launch, stop)

    asyncio.run(run())


if __name__ == "__main__":
    # ``python -m`` executes this file as ``__main__``.  Keep runtime classes,
    # seals, and configuration construction in the canonical package module.
    from hermes_installer.remote.core_gateway import main as canonical_main

    canonical_main()
