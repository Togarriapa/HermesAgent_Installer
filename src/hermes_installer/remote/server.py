"""Root-authorized browser gateway for the pinned Hermes Desktop Xpra route.

The gateway does not authorize a connector effect from local JWT claims or a
PolicyGrant. It passes the raw Access JWT to root AuthorityClient admission and
uses only the returned opaque session handle with the fixed connector client.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs, unquote

from .gateway import GatewayDenied, RemotePolicy
from .http_framing import HTTPFrameError, build_asset_request, parse_asset_response, read_asset_response
from .root_sessions import AdmittedRemoteSession, RootRemoteSessionClient, RootSessionDenied


_CLIENT_ASSETS = frozenset({
    "/client/index.html", "/client/bootstrap.html", "/client/favicon.png", "/client/favicon.ico",
    "/client/css/client.css", "/client/css/connect.css", "/client/css/icon.css",
    "/client/css/menu-skin.css", "/client/css/menu.css", "/client/css/simple-keyboard.css",
    "/client/css/slick.css", "/client/css/spinner.css",
    "/client/icons/authentication.png", "/client/icons/close.png", "/client/icons/default_cursor.png",
    "/client/icons/empty.png", "/client/icons/eye-slash.png", "/client/icons/eye.png",
    "/client/icons/fullscreen.png", "/client/icons/maximize.png", "/client/icons/minimize.png",
    "/client/icons/noicon.png", "/client/icons/unfullscreen.png", "/client/icons/xpra-logo.png",
    "/client/icons/materialicons-regular.ttf", "/client/icons/materialicons-regular.woff",
    "/client/icons/materialicons-regular.woff2",
    *{"/client/js/" + name for name in (
        "Client.js", "Constants.js", "DecodeWorker.js", "ImageDecoder.js", "Keycodes.js",
        "MediaSourceUtil.js", "Menu.js", "MenuCustom.js", "Notifications.js",
        "OffscreenDecodeWorker.js", "OffscreenDecodeWorkerHelper.js", "Protocol.js",
        "RgbHelpers.js", "Utilities.js", "VideoDecoder.js", "WebTransport.js", "Window.js",
        "lib/FileSaver.js", "lib/StreamSaver.js", "lib/aurora/aac.js", "lib/aurora/aurora-xpra.js",
        "lib/aurora/aurora.js", "lib/aurora/flac.js", "lib/aurora/mp3.js",
        "lib/brotli_decode.js", "lib/detect-zoom.js", "lib/hmac.js",
        "lib/jquery-transform-draggable.js", "lib/jquery-ui.js", "lib/jquery.ba-throttle-debounce.js",
        "lib/jquery.js", "lib/lz4.js", "lib/rencode.js", "lib/simple-keyboard.js", "lib/slick.js",
        "lib/web-streams-ponyfill.es6.js",
    )}
})


def canonical_asset(raw: str) -> str:
    path = raw.split("?", 1)[0]
    if (not path.startswith("/") or "\\" in path or unquote(path) != path or
            unquote(unquote(path)) != path or any(s in {".", ".."} for s in path.split("/"))):
        raise GatewayDenied("non-canonical asset path")
    if path not in _CLIENT_ASSETS:
        raise GatewayDenied("asset is outside the pinned Xpra client manifest")
    return path


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


def _index_path_binding(request, session: _GatewaySession | None = None) -> None:
    if set(request.query) != {"path"}:
        raise GatewayDenied("Xpra index route parameters are invalid")
    nested = request.query.get("path", "")
    query = parse_qs(nested.partition("?")[2], keep_blank_values=True, strict_parsing=True)
    if (nested.partition("?")[0] != "/client/" or set(query) != {"lease", "profile", "nonce"} or
            len(query["lease"]) != 1 or len(query["profile"]) != 1 or len(query["nonce"]) != 1 or
            query["profile"][0] != "hermes-desktop"):
        raise GatewayDenied("Xpra index route binding is invalid")
    if session is not None and (query["lease"][0] == "" or query["nonce"][0] == ""):
        raise GatewayDenied("Xpra index route binding is incomplete")


def create_app(runtime: GatewayRuntime):
    from aiohttp import web, WSMsgType

    app = web.Application(client_max_size=2048)
    app["runtime"] = runtime

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
            return web.Response(status=response.status, body=data, headers={
                **response.headers, "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        except (RootSessionDenied, HTTPFrameError, PermissionError, asyncio.TimeoutError):
            raise GatewayDenied("root-authorized Xpra asset request failed") from None
        finally:
            if "connector" in locals():
                try:
                    await asyncio.wait_for(asyncio.to_thread(connector.close), timeout=3)
                except Exception:
                    pass
            if "admission" in locals():
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

            async def watchdog():
                while not downstream.closed:
                    await asyncio.sleep(runtime.watchdog_seconds)
                    if runtime.monotonic() >= session.expires:
                        await asyncio.wait_for(downstream.close(code=1008, message=b"root session lease expired"), timeout=2)
                        return

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
            if connector is not None:
                try:
                    await asyncio.wait_for(asyncio.to_thread(connector.close), timeout=3)
                except Exception:
                    pass
            runtime.sessions.pop(key, None)
            session.connector = None
            session.socket = None
            await close_root(session.admission.handle, session.admission.session_id)

    app.router.add_get("/", root)
    app.router.add_post("/session", create)
    app.router.add_post("/renew", renew)
    app.router.add_post("/logout", logout)
    app.router.add_get("/client/{tail:.*}", client)
    app.router.add_get("/client/", client)
    app.middlewares.append(auth_errors)
    return app
