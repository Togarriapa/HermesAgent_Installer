"""Root-authorized browser gateway for the pinned Hermes Desktop Xpra route.

The gateway does not authorize a connector effect from local JWT claims or a
PolicyGrant. It passes the raw Access JWT to root AuthorityClient admission and
uses only the returned opaque session handle with the fixed connector client.
"""
from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
import base64
import hashlib
import json
import os
import re
import secrets
import socket
import struct
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping
from urllib.parse import parse_qs

from .gateway import GatewayDenied, RemotePolicy
from .http_framing import HTTPFrameError, build_asset_request, read_asset_response
from .root_sessions import AdmittedRemoteSession, RootRemoteSessionClient, RootSessionDenied
from .client_assets import canonical_asset as _canonical_asset


_ORIGIN_PROBE_REQUEST_FIELDS = frozenset({"schema", "probe_handle", "action", "asset_id"})
_ORIGIN_PROBE_MAX_REQUEST = 8192
_ORIGIN_PROBE_MAX_RESPONSE = 1_500_000
_ORIGIN_PROBE_MAX_ASSET = 1024 * 1024
_ORIGIN_PROBE_MAX_WS_SAMPLE = 64 * 1024


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
    path: str | Path
    device: int
    inode: int
    owner_uid: int
    gateway_profile_id: str
    gateway_generation: str

    def __post_init__(self) -> None:
        try:
            path = os.fspath(self.path)
        except TypeError:
            path = ""
        if (not path or not os.path.isabs(path)
                or os.path.normpath(path) != path
                or self.device <= 0 or self.inode <= 0 or self.owner_uid < 0
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", self.gateway_profile_id)
                or not re.fullmatch(r"[A-Za-z0-9_.:@/-]{1,128}", self.gateway_generation)):
            raise ValueError("selected origin-probe listener identity is malformed")


@dataclass(frozen=True, slots=True)
class OriginProbeActionResult:
    """One measured response from a root-authorized finite Xpra action."""
    action: str
    asset_id: str | None
    result: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.action in {"asset-get", "asset-head"}:
            required = {"status_code", "headers", "body_b64", "body_sha256"}
            if (self.asset_id is None or set(self.result) != required
                    or type(self.result.get("status_code")) is not int
                    or not 100 <= self.result["status_code"] <= 599
                    or not isinstance(self.result.get("headers"), Mapping)
                    or not set(self.result["headers"]).issubset({"content-type", "content-length", "cache-control"})
                    or any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 1024
                           for k, v in self.result["headers"].items())
                    or not isinstance(self.result.get("body_b64"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", self.result.get("body_sha256", ""))):
                raise PrivateOriginProbeDenied("asset probe response is malformed")
            try:
                body = base64.b64decode(self.result["body_b64"], validate=True)
            except Exception:
                raise PrivateOriginProbeDenied("asset probe response encoding is malformed") from None
            if (len(body) > _ORIGIN_PROBE_MAX_ASSET
                    or (self.action == "asset-head" and body)
                    or hashlib.sha256(body).hexdigest() != self.result["body_sha256"]):
                raise PrivateOriginProbeDenied("asset probe response bytes are invalid")
        elif self.action == "websocket-attach":
            required = {"status_code", "frame_b64", "frame_bytes", "frame_count", "frame_sha256", "observation_id"}
            if (self.asset_id is not None or set(self.result) != required
                    or self.result.get("status_code") != 101
                    or type(self.result.get("frame_bytes")) is not int
                    or not 0 <= self.result["frame_bytes"] <= _ORIGIN_PROBE_MAX_WS_SAMPLE
                    or type(self.result.get("frame_count")) is not int
                    or not 0 <= self.result["frame_count"] <= 1
                    or not isinstance(self.result.get("frame_b64"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", self.result.get("frame_sha256", ""))
                    or not re.fullmatch(r"[0-9a-f]{64}", self.result.get("observation_id", ""))):
                raise PrivateOriginProbeDenied("WebSocket probe response is malformed")
            try:
                frame = base64.b64decode(self.result["frame_b64"], validate=True)
            except Exception:
                raise PrivateOriginProbeDenied("WebSocket sample encoding is malformed") from None
            if (len(frame) != self.result["frame_bytes"] or len(frame) > _ORIGIN_PROBE_MAX_WS_SAMPLE
                    or (1 if frame else 0) != self.result["frame_count"]
                    or hashlib.sha256(frame).hexdigest() != self.result["frame_sha256"]
                    or hashlib.sha256(b"hermes-probe-ws-v1\0" + frame).hexdigest() != self.result["observation_id"]):
                raise PrivateOriginProbeDenied("WebSocket probe sample does not match its digest")
        else:
            raise PrivateOriginProbeDenied("private probe action is outside the finite allowlist")
        object.__setattr__(self, "result", MappingProxyType(dict(self.result)))


@dataclass(frozen=True, slots=True)
class ProbeActionAuthorization:
    """Action-scoped identity copied from the root-resolved probe binding."""
    probe_handle: str
    action: str
    asset_id: str | None
    gateway_profile_id: str
    gateway_generation: str
    native_profile_id: str
    native_generation: str
    connector_target_id: str
    policy_config_digest: str
    policy_revision: str
    service_generation_digest: str
    expires_monotonic: float


class PrivateOriginProbeExecutor(ABC):
    """Adapter to the root-selected fixed Xpra connector; emits bytes, not claims."""
    @abstractmethod
    async def authorize_action(self, binding: SelectedOriginProbeBinding,
                              request: Mapping[str, Any], *, peer_uid: int,
                              peer_pid: int, peer_pidfd: int) -> ProbeActionAuthorization:
        """Resolve the opaque action handle against current kernel/custody state."""

    @abstractmethod
    async def run_selected_action(self, binding: SelectedOriginProbeBinding,
                                  request: Mapping[str, Any], *, peer_uid: int,
                                  peer_pid: int, peer_pidfd: int) -> OriginProbeActionResult:
        """Run the one action selected by its root-minted, single-use child handle."""


class SetupProbeOriginExecutor(PrivateOriginProbeExecutor):
    """Concrete adapter over the separate root-owned HI12 setup connector."""
    def __init__(self, backend: Any):
        from ..service_connector import SetupProbeConnectorBackend
        if not isinstance(backend, SetupProbeConnectorBackend):
            raise ValueError("root-private setup probe connector backend is required")
        self._backend = backend

    async def authorize_action(self, binding: SelectedOriginProbeBinding,
                              request: Mapping[str, Any], *, peer_uid: int,
                              peer_pid: int, peer_pidfd: int) -> ProbeActionAuthorization:
        try:
            root_binding = await asyncio.to_thread(self._backend._current,
                request["probe_handle"], peer_uid, peer_pid, peer_pidfd,
                request["action"], request["asset_id"])
        except Exception:
            raise PrivateOriginProbeDenied("root action handle is not current for this peer") from None
        if (root_binding.gateway_profile_id != binding.gateway_profile_id
                or root_binding.gateway_generation != binding.gateway_generation
                or root_binding.native_profile_id != binding.native_profile_id
                or root_binding.native_generation != binding.desktop_generation
                or root_binding.connector_target_id != binding.connector_target_id
                or root_binding.policy_config_digest != binding.policy_config_digest
                or root_binding.policy_revision != binding.policy_revision
                or root_binding.service_generation_digest != binding.service_generation_digest):
            raise PrivateOriginProbeDenied("root action handle differs from selected service pins")
        return ProbeActionAuthorization(
            probe_handle=root_binding.probe_handle, action=root_binding.selected_action,
            asset_id=root_binding.selected_asset_id,
            gateway_profile_id=root_binding.gateway_profile_id,
            gateway_generation=root_binding.gateway_generation,
            native_profile_id=root_binding.native_profile_id,
            native_generation=root_binding.native_generation,
            connector_target_id=root_binding.connector_target_id,
            policy_config_digest=root_binding.policy_config_digest,
            policy_revision=root_binding.policy_revision,
            service_generation_digest=root_binding.service_generation_digest,
            expires_monotonic=root_binding.expires_monotonic)

    async def run_selected_action(self, binding: SelectedOriginProbeBinding,
                                  request: Mapping[str, Any], *, peer_uid: int,
                                  peer_pid: int, peer_pidfd: int) -> OriginProbeActionResult:
        handle, action, asset_id = request["probe_handle"], request["action"], request["asset_id"]
        try:
            if action in {"asset-get", "asset-head"}:
                response = await asyncio.to_thread(
                    self._backend.read_asset, handle, asset_id,
                    "GET" if action == "asset-get" else "HEAD",
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
                headers = {str(key).casefold(): str(value)[:1024]
                           for key, value in response.headers.items()
                           if str(key).casefold() in {"content-type", "content-length", "cache-control"}}
                body = response.body
                if not isinstance(body, bytes) or len(body) > _ORIGIN_PROBE_MAX_ASSET:
                    raise PrivateOriginProbeDenied("root connector returned an oversized asset body")
                result = {"status_code": response.status, "headers": headers,
                          "body_b64": base64.b64encode(body).decode("ascii"),
                          "body_sha256": hashlib.sha256(body).hexdigest()}
            elif action == "websocket-attach":
                stream = await asyncio.to_thread(
                    self._backend.open_websocket, handle,
                    peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
                try:
                    frame = await asyncio.to_thread(stream.read, _ORIGIN_PROBE_MAX_WS_SAMPLE)
                finally:
                    await asyncio.to_thread(stream.close)
                if not isinstance(frame, bytes) or len(frame) > _ORIGIN_PROBE_MAX_WS_SAMPLE:
                    raise PrivateOriginProbeDenied("root connector returned an invalid WebSocket sample")
                digest = hashlib.sha256(frame).hexdigest()
                result = {"status_code": 101, "frame_b64": base64.b64encode(frame).decode("ascii"),
                          "frame_bytes": len(frame), "frame_count": 1 if frame else 0,
                          "frame_sha256": digest,
                          "observation_id": hashlib.sha256(b"hermes-probe-ws-v1\0" + frame).hexdigest()}
            else:
                raise PrivateOriginProbeDenied("private probe action is outside the finite allowlist")
            return OriginProbeActionResult(action, asset_id, result)
        except PrivateOriginProbeDenied:
            raise
        except Exception:
            raise PrivateOriginProbeDenied("root-authorized Xpra action failed") from None


@dataclass(slots=True)
class PrivateOriginProbeControl:
    """Root-assembled private probe dependencies for one selected gateway."""
    listener: socket.socket = field(repr=False)
    binding: SelectedOriginProbeBinding
    listener_identity: SelectedOriginProbeListener
    executor: PrivateOriginProbeExecutor = field(repr=False)
    server: asyncio.AbstractServer | None = field(default=None, init=False, repr=False)

    @classmethod
    def from_root_backend(cls, listener: socket.socket,
                          binding: SelectedOriginProbeBinding,
                          listener_identity: SelectedOriginProbeListener,
                          backend: Any) -> "PrivateOriginProbeControl":
        """Build the production adapter from the root-selected HI12 backend."""
        return cls(listener=listener, binding=binding,
                   listener_identity=listener_identity,
                   executor=SetupProbeOriginExecutor(backend))


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
    if raw["schema"] != 1:
        raise PrivateOriginProbeDenied("private probe schema is invalid")
    if not isinstance(raw["probe_handle"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", raw["probe_handle"]):
        raise PrivateOriginProbeDenied("private probe child handle is invalid")
    action, asset_id = raw["action"], raw["asset_id"]
    if action not in {"asset-get", "asset-head", "websocket-attach"}:
        raise PrivateOriginProbeDenied("private probe action is outside the finite allowlist")
    if ((action == "websocket-attach" and asset_id is not None)
            or (action != "websocket-attach"
                and (not isinstance(asset_id, str) or not re.fullmatch(r"[0-9a-f]{64}", asset_id)))):
        raise PrivateOriginProbeDenied("private probe asset selector is invalid")
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
            or not isinstance(executor, PrivateOriginProbeExecutor)
            or not 1 <= operation_timeout <= 25):
        raise ValueError("root-selected private origin probe socket and adapters are required")
    try:
        expected_path = os.fspath(listener_identity.path)
        bound_path = listener.getsockname()
        socket_stat = os.lstat(expected_path)
    except OSError:
        raise ValueError("root-selected origin probe socket identity is unavailable") from None
    if (bound_path != expected_path or stat.S_ISLNK(socket_stat.st_mode)
            or not stat.S_ISSOCK(socket_stat.st_mode)
            or stat.S_IMODE(socket_stat.st_mode) & 0o077
            or socket_stat.st_dev != listener_identity.device
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
            header = await asyncio.wait_for(reader.readexactly(4), timeout=2)
            length = struct.unpack("!I", header)[0]
            if not 2 <= length <= _ORIGIN_PROBE_MAX_REQUEST:
                raise PrivateOriginProbeDenied("private probe frame exceeds its bound")
            payload = await asyncio.wait_for(reader.readexactly(length), timeout=2)
            raw = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_pairs,
                             parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid constant")))
            request = _valid_probe_request(raw, selected)
            handle = request["probe_handle"]
            if handle in used_handles or len(used_handles) >= 4096:
                raise PrivateOriginProbeDenied("private probe handle was replayed or capacity is exhausted")
            frozen_request = MappingProxyType(dict(request))
            authorization = await asyncio.wait_for(executor.authorize_action(
                selected, frozen_request, peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd),
                timeout=min(operation_timeout, 5.0))
            if (not isinstance(authorization, ProbeActionAuthorization)
                    or authorization.probe_handle != handle
                    or authorization.action != request["action"]
                    or authorization.asset_id != request["asset_id"]
                    or authorization.gateway_profile_id != selected.gateway_profile_id
                    or authorization.gateway_generation != selected.gateway_generation
                    or authorization.native_profile_id != selected.native_profile_id
                    or authorization.native_generation != selected.desktop_generation
                    or authorization.connector_target_id != selected.connector_target_id
                    or authorization.policy_config_digest != selected.policy_config_digest
                    or authorization.policy_revision != selected.policy_revision
                    or authorization.service_generation_digest != selected.service_generation_digest
                    or not monotonic() < authorization.expires_monotonic):
                raise PrivateOriginProbeDenied("private probe action handle is not currently authorized")
            used_handles.add(handle)
            observation = await asyncio.wait_for(executor.run_selected_action(
                selected, frozen_request, peer_uid=uid, peer_pid=pid, peer_pidfd=pidfd),
                timeout=min(operation_timeout, 25.0))
            if (not isinstance(observation, OriginProbeActionResult)
                    or observation.action != request["action"]
                    or observation.asset_id != request["asset_id"]):
                raise PrivateOriginProbeDenied("root connector returned a mismatched action result")
            result = dict(observation.result)
            response_body = {"schema": 1, "operation": "probe_action_result",
                             "probe_handle": handle, "action": observation.action,
                             "asset_id": observation.asset_id, "result": result}
            response = {**response_body,
                        "result_digest": hashlib.sha256(_canonical_json(response_body)).hexdigest()}
            encoded = _canonical_json(response)
            if len(encoded) > _ORIGIN_PROBE_MAX_RESPONSE:
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

    return await asyncio.start_unix_server(serve, sock=listener, limit=_ORIGIN_PROBE_MAX_REQUEST + 4)


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
    private_origin_probe: PrivateOriginProbeControl | None = field(default=None, repr=False)
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
        if (self.private_origin_probe is not None
                and not isinstance(self.private_origin_probe, PrivateOriginProbeControl)):
            raise ValueError("private origin probe must be assembled from a typed root-selected control")

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

    async def start_private_origin_probe(application):
        control = runtime.private_origin_probe
        if control is not None:
            control.server = await create_private_origin_probe_server(
                control.listener, control.binding, listener_identity=control.listener_identity,
                executor=control.executor,
                monotonic=runtime.monotonic)
            application["private_origin_probe_server"] = control.server

    async def stop_private_origin_probe(application):
        server = application.get("private_origin_probe_server")
        if server is not None:
            server.close()
            await server.wait_closed()
            runtime.private_origin_probe.server = None

    app.on_startup.append(start_private_origin_probe)
    app.on_cleanup.append(stop_private_origin_probe)

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
                    if data is None:
                        # A fixed connector may report a bounded idle poll. It
                        # is distinct from EOF so a quiet native desktop does
                        # not terminate its active authorization lease.
                        continue
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
