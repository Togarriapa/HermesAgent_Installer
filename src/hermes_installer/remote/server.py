"""Root-authorized browser gateway for the pinned Hermes Desktop Xpra route.

The gateway does not authorize a connector effect from local JWT claims or a
PolicyGrant. It passes the raw Access JWT to root AuthorityClient admission and
uses only the returned opaque session handle with the fixed connector client.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs

from .gateway import GatewayDenied, RemotePolicy
from .http_framing import HTTPFrameError, build_asset_request, read_asset_response
from .root_sessions import AdmittedRemoteSession, RootRemoteSessionClient, RootSessionDenied
from .client_assets import CLIENT_ASSETS as _CLIENT_ASSETS, canonical_asset as _canonical_asset


_ORIGIN_OBSERVATIONS = frozenset({
    "loopback_only", "unauthenticated_denied", "authorized_asset_served",
    "authorized_websocket_attached", "official_desktop_window_observed",
    "arbitrary_route_denied", "shell_route_denied", "full_host_desktop_denied",
})
_ORIGIN_PROBE_REQUEST_FIELDS = frozenset({
    "schema", "operation", "probe_handle", "sequence", "challenge",
    "remote_enrollment_id", "gateway_profile_id", "gateway_generation",
    "native_profile_id", "desktop_generation",
    "connector_target_id", "policy_config_digest", "policy_revision",
    "service_generation_digest", "request_digest",
})
_ORIGIN_PROBE_MAX_FRAME = 8192


class PrivateOriginProbeDenied(PermissionError):
    """The root-private origin probe could not be safely completed."""


@dataclass(frozen=True, slots=True)
class SelectedOriginProbeBinding:
    """Immutable pins resolved from the root-selected active enrollment."""
    remote_enrollment_id: str
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    desktop_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str

    def __post_init__(self) -> None:
        values = (self.remote_enrollment_id, self.gateway_profile_id, self.gateway_generation,
                  self.native_profile_id, self.desktop_generation,
                  self.connector_target_id, self.policy_revision)
        if (any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", value)
                for value in values)
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in (self.policy_config_digest, self.service_generation_digest))):
            raise ValueError("selected origin probe binding is malformed")
        if self.connector_target_id != "xpra-native":
            raise ValueError("selected origin probe must bind the fixed native Xpra connector")


@dataclass(frozen=True, slots=True)
class SelectedOriginProbeListener:
    """Root-catalog identity for the systemd-created private listening socket."""
    device: int
    inode: int
    owner_uid: int
    gateway_profile_id: str
    gateway_generation: str

    def __post_init__(self) -> None:
        if (self.device <= 0 or self.inode <= 0 or self.owner_uid < 0
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", self.gateway_profile_id)
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", self.gateway_generation)):
            raise ValueError("selected origin-probe listener identity is malformed")


@dataclass(frozen=True, slots=True)
class OriginProbeObservation:
    """Facts collected by the protected native app probe, never from request JSON."""
    assertions: Mapping[str, bool]
    assertion_ids: tuple[str, ...]
    asset_sha256: str
    websocket_observation_id: str
    native_window_observation_id: str

    def __post_init__(self) -> None:
        if (not isinstance(self.assertions, Mapping)
                or set(self.assertions) != _ORIGIN_OBSERVATIONS
                or any(value is not True for value in self.assertions.values())
                or not isinstance(self.assertion_ids, tuple)
                or not 1 <= len(self.assertion_ids) <= 32
                or any(not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", value)
                       for value in self.assertion_ids)
                or not isinstance(self.asset_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.asset_sha256)
                or not isinstance(self.websocket_observation_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.websocket_observation_id)
                or not isinstance(self.native_window_observation_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", self.native_window_observation_id)):
            raise PrivateOriginProbeDenied("protected origin probe observations are incomplete")


class PrivateOriginProbeExecutor:
    """Adapter to the enrolled gateway's fixed Xpra/app-only observation path.

    Implementations must collect HTTP/WS bytes and the root-correlated native
    window observation. The control protocol intentionally accepts no booleans,
    URLs, socket addresses, or caller-selected targets from the root request.
    """
    async def run_selected_probe(self, binding: SelectedOriginProbeBinding,
                                 request: Mapping[str, Any]) -> OriginProbeObservation:
        raise NotImplementedError


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _reject_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _valid_probe_request(raw: Any, selected: SelectedOriginProbeBinding) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != _ORIGIN_PROBE_REQUEST_FIELDS:
        raise PrivateOriginProbeDenied("private probe request fields are invalid")
    if raw["schema"] != 1 or raw["operation"] != "probe_selected_origin" or raw["sequence"] != 1:
        raise PrivateOriginProbeDenied("private probe operation or sequence is invalid")
    for key in ("remote_enrollment_id", "gateway_profile_id", "gateway_generation",
                "native_profile_id", "desktop_generation",
                "connector_target_id", "policy_config_digest", "policy_revision",
                "service_generation_digest"):
        if raw[key] != getattr(selected, key):
            raise PrivateOriginProbeDenied("private probe does not match selected root enrollment")
    if (not isinstance(raw["probe_handle"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", raw["probe_handle"])
            or not isinstance(raw["challenge"], str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{40,64}", raw["challenge"])
            or not isinstance(raw["request_digest"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", raw["request_digest"])):
        raise PrivateOriginProbeDenied("private probe capability or nonce is invalid")
    digest_body = {key: value for key, value in raw.items() if key != "request_digest"}
    expected = hashlib.sha256(_canonical_json(digest_body)).hexdigest()
    if not hmac.compare_digest(raw["request_digest"], expected):
        raise PrivateOriginProbeDenied("private probe request digest is invalid")
    return raw


def _unix_peer_credentials(conn: socket.socket) -> tuple[int, int, int, int]:
    if conn.family != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED") or not hasattr(os, "pidfd_open"):
        raise PrivateOriginProbeDenied("kernel-authenticated private Unix peer credentials are unavailable")
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PrivateOriginProbeDenied("private Unix peer credentials are invalid")
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError:
        raise PrivateOriginProbeDenied("private probe peer process identity is unavailable") from None
    return uid, gid, pid, pidfd


async def create_private_origin_probe_server(
    listener: socket.socket,
    selected: SelectedOriginProbeBinding,
    *,
    listener_identity: SelectedOriginProbeListener,
    peer_authorizer: Callable[[int, int, int, int, SelectedOriginProbeBinding], bool],
    executor: PrivateOriginProbeExecutor,
    monotonic: Callable[[], float] = time.monotonic,
    operation_timeout: float = 25.0,
) -> asyncio.AbstractServer:
    """Serve one-use origin probes on a root-created, already-bound AF_UNIX socket.

    The caller must obtain ``listener`` from the selected systemd socket unit;
    this function never creates or chooses a pathname. The public aiohttp app
    does not register this protocol or expose it over HTTP.
    """
    if (not isinstance(listener, socket.socket) or listener.family != socket.AF_UNIX
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
            or not isinstance(selected, SelectedOriginProbeBinding)
            or not isinstance(listener_identity, SelectedOriginProbeListener)
            or listener_identity.gateway_profile_id != selected.gateway_profile_id
            or listener_identity.gateway_generation != selected.gateway_generation
            or not callable(peer_authorizer)
            or not isinstance(executor, PrivateOriginProbeExecutor)
            or not 1 <= operation_timeout <= 25):
        raise ValueError("root-selected private origin probe socket and adapters are required")
    try:
        socket_stat = os.fstat(listener.fileno())
    except OSError:
        raise ValueError("root-selected origin probe socket identity is unavailable") from None
    if (socket_stat.st_dev != listener_identity.device
            or socket_stat.st_ino != listener_identity.inode
            or socket_stat.st_uid != listener_identity.owner_uid):
        raise ValueError("private origin probe socket differs from the root-selected identity")
    used_handles: set[str] = set()

    async def serve(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        conn = writer.get_extra_info("socket")
        pidfd = -1
        try:
            if conn is None:
                raise PrivateOriginProbeDenied("private probe socket is unavailable")
            uid, gid, pid, pidfd = _unix_peer_credentials(conn)
            if peer_authorizer(uid, gid, pid, pidfd, selected) is not True:
                raise PrivateOriginProbeDenied("private probe peer is not root-authorized")
            header = await asyncio.wait_for(reader.readexactly(4), timeout=2)
            length = struct.unpack("!I", header)[0]
            if not 2 <= length <= _ORIGIN_PROBE_MAX_FRAME:
                raise PrivateOriginProbeDenied("private probe frame exceeds its bound")
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=2)
            raw = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs,
                             parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid constant")))
            request = _valid_probe_request(raw, selected)
            handle = request["probe_handle"]
            if handle in used_handles or len(used_handles) >= 4096:
                raise PrivateOriginProbeDenied("private probe handle was replayed or capacity is exhausted")
            used_handles.add(handle)
            observation = await asyncio.wait_for(
                executor.run_selected_probe(selected, request), timeout=min(operation_timeout, 25.0))
            if not isinstance(observation, OriginProbeObservation):
                raise PrivateOriginProbeDenied("protected Xpra/app probe did not return typed observations")
            response = {
                "schema": 1, "operation": "probe_selected_origin_result", "probe_handle": handle,
                "sequence": 1, "challenge": request["challenge"],
                "request_digest": request["request_digest"],
                "remote_enrollment_id": selected.remote_enrollment_id,
                "gateway_profile_id": selected.gateway_profile_id,
                "gateway_generation": selected.gateway_generation,
                "native_profile_id": selected.native_profile_id,
                "desktop_generation": selected.desktop_generation,
                "connector_target_id": selected.connector_target_id,
                "policy_config_digest": selected.policy_config_digest,
                "policy_revision": selected.policy_revision,
                "service_generation_digest": selected.service_generation_digest,
                "observations": dict(observation.assertions),
                "observed_assertion_ids": list(observation.assertion_ids),
                "asset_content_sha256": observation.asset_sha256,
                "websocket_observation_id": observation.websocket_observation_id,
                "native_window_observation_id": observation.native_window_observation_id,
            }
            encoded = _canonical_json(response)
            if len(encoded) > _ORIGIN_PROBE_MAX_FRAME:
                raise PrivateOriginProbeDenied("private probe response exceeds its bound")
            writer.write(struct.pack("!I", len(encoded)) + encoded)
            await asyncio.wait_for(writer.drain(), timeout=2)
        except Exception:
            # Keep the private socket response generic; details stay in root
            # diagnostics and no untrusted payload is echoed on failure.
            try:
                body = _canonical_json({"schema": 1, "error": "origin_probe_denied"})
                writer.write(struct.pack("!I", len(body)) + body)
                await asyncio.wait_for(writer.drain(), timeout=1)
            except Exception:
                pass
        finally:
            if pidfd >= 0:
                try:
                    os.close(pidfd)
                except OSError:
                    pass
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1)
            except Exception:
                pass

    return await asyncio.start_unix_server(serve, sock=listener, limit=_ORIGIN_PROBE_MAX_FRAME + 4)


def canonical_asset(raw: str) -> str:
    try:
        return _canonical_asset(raw)
    except ValueError as exc:
        raise GatewayDenied(str(exc)) from None


@dataclass(slots=True)
class _GatewaySession:
    admission: AdmittedRemoteSession
    socket_nonce: str
    renewal_challenge: str
    root_renewal_nonce: str
    challenge_expires: float
    expires: float
    socket_claimed: bool = False
    socket: Any = field(default=None, repr=False)
    connector: Any = field(default=None, repr=False)


@dataclass
class GatewayRuntime:
    policy: RemotePolicy
    root_sessions: RootRemoteSessionClient | None = None
    connector_factory: Callable[[Any], Any] | None = field(default=None, repr=False)
    monotonic: Callable[[], float] = time.monotonic
    max_lease_seconds: int = 60
    max_active_sockets: int = 1
    watchdog_seconds: int = 5
    sessions: dict[str, _GatewaySession] = field(default_factory=dict, repr=False)

    def __post_init__(self):
        if (not 1 <= self.max_lease_seconds <= 60 or not 1 <= self.watchdog_seconds <= 5 or
                self.max_active_sockets != 1):
            raise ValueError("remote session lease/watchdog/concurrency exceeds its reviewed bound")
        if self.policy.hostname != (self.root_sessions.hostname if self.root_sessions else self.policy.hostname):
            raise ValueError("gateway and root enrollment hostname differ")

    def validate_request_origin(self, request, *, require_origin: bool = False) -> str:
        host = request.headers.get("Host", "").casefold()
        if host != self.policy.hostname.casefold():
            raise GatewayDenied("request host is not enrolled")
        origin = request.headers.get("Origin")
        if require_origin and origin != f"https://{self.policy.hostname}":
            raise GatewayDenied("browser origin is not enrolled")
        if origin is not None and origin != f"https://{self.policy.hostname}":
            raise GatewayDenied("browser origin is not enrolled")
        return f"https://{self.policy.hostname}"

    def require_root(self) -> RootRemoteSessionClient:
        if self.root_sessions is None:
            raise GatewayDenied("root Access/session authority is not installed")
        return self.root_sessions

    def connector(self, handle: Any):
        if self.connector_factory is not None:
            return self.connector_factory(handle)
        root = self.require_root()
        from hermes_installer.service_connector import ServiceConnectorClient
        return ServiceConnectorClient(root.authority, handle).open()


_BOOTSTRAP = """<!doctype html><meta charset=utf-8><title>Hermes Desktop</title><p id=s>Starting protected Desktop session…</p><script>
(async()=>{try{const r=await fetch('/session',{method:'POST',cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-lease',x.lease_id);sessionStorage.setItem('hd-challenge',x.renewal_challenge);location.replace('/client/index.html?path='+encodeURIComponent('/client/?lease='+encodeURIComponent(x.lease_id)+'&profile=hermes-desktop&nonce='+encodeURIComponent(x.socket_nonce)))}catch(e){document.getElementById('s').textContent='Access authorization required.'}})();
</script>"""
_RENEW = """<script>(()=>{let busy=false;async function renew(){if(busy)return;busy=true;try{const id=sessionStorage.getItem('hd-lease'),challenge=sessionStorage.getItem('hd-challenge');if(!id||!challenge)throw Error();const r=await fetch('/renew',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({lease_id:id,challenge})});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-challenge',x.renewal_challenge)}catch(_){sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');location.replace('/client/bootstrap.html')}finally{busy=false}}const b=document.createElement('button');b.textContent='End Desktop session';b.setAttribute('aria-label','End Desktop session');b.style='position:fixed;top:8px;right:8px;z-index:2147483647;padding:8px;background:#7b1d1d;color:white';b.onclick=async()=>{b.disabled=true;try{const id=sessionStorage.getItem('hd-lease'),challenge=sessionStorage.getItem('hd-challenge');if(id&&challenge)await fetch('/logout',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({lease_id:id,challenge})})}finally{sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');location.replace('/client/bootstrap.html')}};const addButton=()=>document.body.appendChild(b);if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',addButton,{once:true});else addButton();setInterval(renew,25000);})();</script>"""


def _token(request) -> str:
    token = request.headers.get("Cf-Access-Jwt-Assertion", "")
    if not isinstance(token, str) or not 1 <= len(token) <= 16_384:
        raise GatewayDenied("Cloudflare Access token is unavailable")
    return token


def _index_path_binding(request) -> None:
    if set(request.query) != {"path"}:
        raise GatewayDenied("Xpra index route parameters are invalid")
    nested = request.query.get("path", "")
    try:
        query = parse_qs(nested.partition("?")[2], keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise GatewayDenied("Xpra index route parameters are malformed") from None
    if (nested.partition("?")[0] != "/client/" or set(query) != {"lease", "profile", "nonce"} or
            len(query["lease"]) != 1 or len(query["profile"]) != 1 or len(query["nonce"]) != 1 or
            query["profile"][0] != "hermes-desktop" or
            not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", query["lease"][0]) or
            not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", query["nonce"][0])):
        raise GatewayDenied("Xpra index route binding is invalid")


def create_app(runtime: GatewayRuntime):
    from aiohttp import web, WSMsgType

    app = web.Application(client_max_size=2048)

    @web.middleware
    async def auth_errors(request, handler):
        try:
            return await handler(request)
        except (GatewayDenied, RootSessionDenied, HTTPFrameError, PermissionError):
            return web.Response(status=403, text="Forbidden", headers={"Cache-Control": "no-store"})

    async def close_root(handle, session_id=None):
        try:
            root = runtime.require_root()
            await asyncio.wait_for(asyncio.to_thread(root.close, handle, session_id=session_id), timeout=5)
        except Exception:
            # Root expiry watchdog owns cleanup if this bounded best-effort close fails.
            pass

    async def root(request):
        runtime.validate_request_origin(request)
        raise web.HTTPFound("/client/bootstrap.html")

    async def create(request):
        runtime.validate_request_origin(request, require_origin=True)
        if request.can_read_body:
            raise GatewayDenied("session request body is forbidden")
        token = _token(request)
        now = runtime.monotonic()
        for key, old in tuple(runtime.sessions.items()):
            if old.expires <= now:
                runtime.sessions.pop(key, None)
                await close_root(old.admission.handle, old.admission.session_id)
        if len(runtime.sessions) >= runtime.max_active_sockets:
            raise GatewayDenied("Desktop session limit reached")
        root_client = runtime.require_root()
        try:
            admission = await asyncio.wait_for(asyncio.to_thread(
                root_client.admit, access_jwt=token, action="websocket-attach", route_id="xpra-websocket"), timeout=9)
            challenge = await asyncio.wait_for(asyncio.to_thread(root_client.challenge, admission.handle), timeout=5)
        except Exception:
            if "admission" in locals():
                await close_root(admission.handle, admission.session_id)
            raise GatewayDenied("root Access/session admission failed") from None
        if (admission.admission_kind != "leased-websocket" or
                challenge.session_id != admission.session_id or
                admission.lease_expires_monotonic <= runtime.monotonic()):
            await close_root(admission.handle, admission.session_id)
            raise GatewayDenied("root WebSocket admission binding is invalid")
        key = secrets.token_urlsafe(24)
        local_challenge = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(24)
        runtime.sessions[key] = _GatewaySession(admission, nonce, local_challenge,
                                                challenge.renewal_nonce, challenge.expires_monotonic,
                                                admission.lease_expires_monotonic)
        return web.json_response({"lease_id": key, "profile_id": "hermes-desktop",
                                  "renewal_challenge": local_challenge, "socket_nonce": nonce,
                                  "expires_in": max(0, int(admission.lease_expires_monotonic - runtime.monotonic()))},
                                 headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def renew(request):
        runtime.validate_request_origin(request, require_origin=True)
        if request.content_length is None or request.content_length > 2048:
            raise GatewayDenied("invalid renewal body")
        try:
            body = await asyncio.wait_for(request.json(), timeout=3)
        except Exception:
            raise GatewayDenied("invalid renewal body") from None
        if not isinstance(body, dict) or set(body) != {"lease_id", "challenge"} or not all(isinstance(body[x], str) for x in body):
            raise GatewayDenied("invalid renewal fields")
        session = runtime.sessions.get(body["lease_id"])
        if (session is None or session.expires <= runtime.monotonic() or
                session.challenge_expires <= runtime.monotonic() or
                not secrets.compare_digest(session.renewal_challenge, body["challenge"])):
            raise GatewayDenied("local renewal challenge is invalid or expired")
        session.renewal_challenge = ""  # consume before any remote effect
        root_client = runtime.require_root()
        try:
            expiry = await asyncio.wait_for(asyncio.to_thread(
                root_client.renew, handle=session.admission.handle, session_id=session.admission.session_id,
                access_jwt=_token(request), renewal_nonce=session.root_renewal_nonce), timeout=9)
            challenge = await asyncio.wait_for(asyncio.to_thread(root_client.challenge, session.admission.handle), timeout=5)
        except Exception:
            runtime.sessions.pop(body["lease_id"], None)
            await close_root(session.admission.handle, session.admission.session_id)
            if session.socket is not None:
                try:
                    await asyncio.wait_for(session.socket.close(code=1008, message=b"authorization renewal denied"), timeout=2)
                except Exception:
                    pass
            raise GatewayDenied("fresh root Access/policy renewal was denied") from None
        if (challenge.session_id != session.admission.session_id or expiry <= runtime.monotonic() or
                expiry > runtime.monotonic() + runtime.max_lease_seconds or
                challenge.expires_monotonic <= runtime.monotonic()):
            runtime.sessions.pop(body["lease_id"], None)
            await close_root(session.admission.handle, session.admission.session_id)
            raise GatewayDenied("renewed root session lease is malformed")
        session.expires = expiry
        session.root_renewal_nonce = challenge.renewal_nonce
        session.challenge_expires = challenge.expires_monotonic
        session.renewal_challenge = secrets.token_urlsafe(32)
        return web.json_response({"renewal_challenge": session.renewal_challenge,
                                  "expires_in": max(0, int(expiry - runtime.monotonic()))},
                                 headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def logout(request):
        runtime.validate_request_origin(request, require_origin=True)
        if request.content_length is None or request.content_length > 2048:
            raise GatewayDenied("invalid logout body")
        try:
            body = await asyncio.wait_for(request.json(), timeout=3)
        except Exception:
            raise GatewayDenied("invalid logout body") from None
        if not isinstance(body, dict) or set(body) != {"lease_id", "challenge"} or not all(isinstance(body[x], str) for x in body):
            raise GatewayDenied("invalid logout fields")
        session = runtime.sessions.get(body["lease_id"])
        if (session is None or not secrets.compare_digest(session.renewal_challenge, body["challenge"])):
            raise GatewayDenied("logout session proof is invalid")
        runtime.sessions.pop(body["lease_id"], None)
        await close_root(session.admission.handle, session.admission.session_id)
        if session.connector is not None:
            try:
                await asyncio.wait_for(asyncio.to_thread(session.connector.close), timeout=3)
            except Exception:
                pass
        if session.socket is not None:
            try:
                await asyncio.wait_for(session.socket.close(code=1000, message=b"user logout"), timeout=2)
            except Exception:
                pass
        return web.Response(status=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def client(request):
        runtime.validate_request_origin(request)
        if request.path == "/client/" and request.headers.get("Upgrade", "").casefold() == "websocket":
            return await stream(request)
        path = canonical_asset(request.path)
        if request.method not in {"GET", "HEAD"}:
            raise GatewayDenied("read-only asset route")
        if path == "/client/index.html":
            _index_path_binding(request)
        elif request.query_string:
            raise GatewayDenied("Xpra assets do not accept query parameters")
        token = _token(request)
        root_client = runtime.require_root()
        connector = None
        asset_success = False
        try:
            admission = await asyncio.wait_for(asyncio.to_thread(
                root_client.admit, access_jwt=token, action="asset-read", route_id="xpra-http"), timeout=9)
            if admission.admission_kind != "one-shot-asset":
                raise GatewayDenied("root did not issue one-shot asset admission")
            if path == "/client/bootstrap.html":
                await close_root(admission.handle, admission.session_id)
                return web.Response(text=_BOOTSTRAP, content_type="text/html", headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'; connect-src 'self' wss:; object-src 'none'; base-uri 'none'",
                    "X-Content-Type-Options": "nosniff",
                })
            connector = await asyncio.wait_for(asyncio.to_thread(runtime.connector, admission.handle), timeout=5)
            if (getattr(connector, "session_id", None) != admission.session_id or
                    getattr(connector, "route_id", None) != "xpra-http" or
                    getattr(connector, "expires_monotonic", admission.lease_expires_monotonic) > admission.lease_expires_monotonic):
                raise GatewayDenied("root connector is not bound to the admitted asset route")
            frame = build_asset_request(request.method, path, canonicalize=canonical_asset)
            def exchange():
                connector.write(frame)
                return read_asset_response(connector.read, method=request.method)
            response = await asyncio.wait_for(asyncio.to_thread(exchange), timeout=30)
            data = response.body
            if path == "/client/index.html" and request.method != "HEAD" and "text/html" in response.headers.get("content-type", ""):
                text = data.decode("utf-8", "strict")
                if "</body>" not in text.casefold():
                    raise GatewayDenied("unexpected HTML client document")
                pos = text.casefold().rfind("</body>")
                text = text[:pos] + _RENEW + text[pos:]
                data = text.encode("utf-8")
            if path == "/client/css/client.css" and request.method != "HEAD":
                data += b"\n#float_menu{display:none!important}\n"
            asset_success = True
            return web.Response(status=response.status, body=data, headers={
                **response.headers, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        except (RootSessionDenied, HTTPFrameError, PermissionError, asyncio.TimeoutError):
            raise GatewayDenied("root-authorized Xpra asset request failed") from None
        finally:
            # On a timed-out/failed in-flight read, close the root session first
            # so root cancellation releases its relay before client cleanup waits
            # on the connector's serialized operation lock.
            if "admission" in locals() and not asset_success:
                await close_root(admission.handle, admission.session_id)
            if connector is not None:
                try:
                    await asyncio.wait_for(asyncio.to_thread(connector.close), timeout=3)
                except Exception:
                    pass
            if "admission" in locals() and asset_success:
                await close_root(admission.handle, admission.session_id)

    async def stream(request):
        runtime.validate_request_origin(request, require_origin=True)
        if request.headers.get("Sec-WebSocket-Protocol") != "binary":
            raise GatewayDenied("unexpected Xpra WebSocket protocol")
        if set(request.query) != {"lease", "profile", "nonce"} or request.query["profile"] != "hermes-desktop":
            raise GatewayDenied("socket profile/lease binding required")
        key = request.query["lease"]
        session = runtime.sessions.get(key)
        if (session is None or session.socket_claimed or session.expires <= runtime.monotonic() or
                not secrets.compare_digest(session.socket_nonce, request.query["nonce"])):
            raise GatewayDenied("socket lease/nonce is invalid or already consumed")
        session.socket_claimed = True
        connector = None
        downstream = web.WebSocketResponse(protocols=("binary",), max_msg_size=1_048_576,
                                           autoping=False, autoclose=False, compress=False)
        try:
            connector = await asyncio.wait_for(asyncio.to_thread(runtime.connector, session.admission.handle), timeout=5)
            if (getattr(connector, "session_id", None) != session.admission.session_id or
                    getattr(connector, "route_id", None) != "xpra-websocket" or
                    getattr(connector, "expires_monotonic", session.expires) > session.expires):
                raise GatewayDenied("root connector is not bound to the admitted WebSocket session")
            await downstream.prepare(request)
            session.socket = downstream
            session.connector = connector

            async def browser_to_xpra():
                while not downstream.closed:
                    message = await downstream.receive()
                    if message.type == WSMsgType.BINARY:
                        if runtime.monotonic() >= session.expires:
                            raise GatewayDenied("root session lease expired")
                        await asyncio.wait_for(asyncio.to_thread(connector.write, message.data), timeout=5)
                    elif message.type == WSMsgType.PING:
                        await downstream.pong(message.data)
                    elif message.type == WSMsgType.PONG:
                        continue
                    elif message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.CLOSING, WSMsgType.ERROR}:
                        return
                    else:
                        raise GatewayDenied("only binary Xpra WebSocket messages are permitted")

            async def xpra_to_browser():
                while not downstream.closed:
                    if runtime.monotonic() >= session.expires:
                        raise GatewayDenied("root session lease expired")
                    data = await asyncio.wait_for(asyncio.to_thread(connector.read, 65_536), timeout=7)
                    if not data:
                        return
                    await asyncio.wait_for(downstream.send_bytes(data), timeout=5)

            async def watchdog_close():
                while not downstream.closed:
                    await asyncio.sleep(runtime.watchdog_seconds)
                    if runtime.monotonic() >= session.expires:
                        await downstream.close(code=1008, message=b"root session lease expired")
                        return

            tasks = {asyncio.create_task(browser_to_xpra()), asyncio.create_task(xpra_to_browser()),
                     asyncio.create_task(watchdog_close())}
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.wait(pending, timeout=5)
                for task in done:
                    if not task.cancelled() and task.exception():
                        raise task.exception()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.wait(tasks, timeout=5)
            return downstream
        except Exception:
            try:
                await asyncio.wait_for(downstream.close(code=1008, message=b"root connector unavailable"), timeout=2)
            except Exception:
                pass
            raise GatewayDenied("root-authorized WebSocket connector failed") from None
        finally:
            runtime.sessions.pop(key, None)
            session.connector = None
            session.socket = None
            # Root close revokes/cancels its retained relay before local stream
            # cleanup waits behind any in-flight synchronous connector read.
            await close_root(session.admission.handle, session.admission.session_id)
            if connector is not None:
                try:
                    await asyncio.wait_for(asyncio.to_thread(connector.close), timeout=3)
                except Exception:
                    pass

    app.router.add_get("/", root)
    app.router.add_post("/session", create)
    app.router.add_post("/renew", renew)
    app.router.add_post("/logout", logout)
    app.router.add_get("/client/{tail:.*}", client)
    app.router.add_get("/client/", client)
    app.middlewares.append(auth_errors)
    return app
