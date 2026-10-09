"""Loopback-only HTTP/WebSocket bridge with Access authorization before bytes."""
from __future__ import annotations
import asyncio,secrets,time
from dataclasses import dataclass,field
from typing import Callable
from urllib.parse import quote,unquote,urlsplit
from .gateway import GatewayDenied,RemotePolicy,SocketLease,authorize_request,websocket_target
from .verifier_ipc import PolicyGrant, PolicyVerifierClient

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


def canonical_asset(raw:str)->str:
    path=raw.split("?",1)[0]
    if not path.startswith("/") or "\\" in path or unquote(path)!=path or unquote(unquote(path))!=path or any(s in {".",".."} for s in path.split("/")):
        raise GatewayDenied("non-canonical asset path")
    if path not in _CLIENT_ASSETS:
        raise GatewayDenied("asset is outside the pinned Xpra client manifest")
    return path
@dataclass
class GatewayRuntime:
    policy:RemotePolicy
    upstream:str="http://127.0.0.1:14500/"
    profile_id:str="hermes-desktop"
    clock:Callable[[],float]=time.time
    monotonic:Callable[[],float]=time.monotonic
    verifier:PolicyVerifierClient|None=None
    max_lease_seconds:int=60
    max_active_sockets:int=4
    watchdog_seconds:int=5
    leases:dict[str,SocketLease]=field(default_factory=dict)
    sockets:dict[str,object]=field(default_factory=dict,repr=False)
    def __post_init__(self):
        u=urlsplit(self.upstream)
        if u.scheme!="http" or u.hostname not in {"127.0.0.1","::1"} or u.username or u.password:raise ValueError("fixed loopback upstream required")
        if not 1<=self.max_lease_seconds<=60 or not 1<=self.watchdog_seconds<=5 or not 1<=self.max_active_sockets<=4:raise ValueError("lease/watchdog exceeds hard bound")
        if self.profile_id!="hermes-desktop":raise ValueError("only the pinned Hermes Desktop profile may be exposed")
    def principal(self,request,method,path):
        return authorize_request(token=request.headers.get("Cf-Access-Jwt-Assertion"),policy=self.policy,method=method,path=path,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),now=self.clock)
    async def authorize_current(self,*,action,session_id,access_jwt,principal):
        if self.verifier is None:raise GatewayDenied("isolated current Access verifier is not configured")
        grant=await self.verifier.authorize(action=action,session_id=session_id,access_jwt=access_jwt,expected=principal)
        if not isinstance(grant,PolicyGrant) or grant.action!=action or grant.session_id!=session_id or grant.principal.token_fingerprint!=principal.token_fingerprint:
            raise GatewayDenied("isolated Access verifier returned an unbound decision")
        return grant
    def create_lease(self,principal,grant,session_id):
        if (grant.action!="issue" or grant.session_id!=session_id or
                grant.principal.token_fingerprint!=principal.token_fingerprint or session_id in self.leases):
            raise GatewayDenied("session grant binding mismatch")
        key=session_id
        for old_key,old in tuple(self.leases.items()):
            try:old.authorize_frame(now=self.monotonic())
            except GatewayDenied:self.leases.pop(old_key,None)
        if len(self.leases)>=self.max_active_sockets or any(x.principal.subject==principal.subject for x in self.leases.values()):raise GatewayDenied("profile session limit reached")
        lease=SocketLease.create(principal,now=self.monotonic(),wall_now=self.clock(),requested_seconds=self.max_lease_seconds,
            authorization_started_monotonic=grant.observed_start_monotonic,
            authorization_deadline_monotonic=grant.valid_until_monotonic,
            jwt_deadline_monotonic=grant.jwt_deadline_monotonic)
        self.leases[key]=lease;return key,lease
    def renew(self,key,principal,challenge,grant):
        lease=self.leases.get(key)
        if lease is None:raise GatewayDenied("unknown lease")
        if (grant.action!="renew" or grant.session_id!=key or
                grant.principal.token_fingerprint!=principal.token_fingerprint):
            raise GatewayDenied("renewal grant binding mismatch")
        lease.renew(principal,challenge=challenge,now=self.monotonic(),wall_now=self.clock(),
            policy_current=lambda email:email==grant.principal.email,requested_seconds=self.max_lease_seconds,
            authorization_started_monotonic=grant.observed_start_monotonic,
            authorization_deadline_monotonic=grant.valid_until_monotonic,
            jwt_deadline_monotonic=grant.jwt_deadline_monotonic)
        return lease
    def logout(self,key,challenge):
        lease=self.leases.get(key)
        if lease is None or not isinstance(challenge,str) or not secrets.compare_digest(lease.renewal_challenge,challenge):
            raise GatewayDenied("logout session proof is invalid")
        self.leases.pop(key,None)
        return self.sockets.pop(key,None)

_BOOTSTRAP="""<!doctype html><meta charset=utf-8><title>Hermes Desktop</title><p id=s>Starting protected Desktop session…</p><script>
(async()=>{try{const r=await fetch('/session',{method:'POST',cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-lease',x.lease_id);sessionStorage.setItem('hd-challenge',x.renewal_challenge);location.replace('/client/index.html?path='+encodeURIComponent('/client/?lease='+encodeURIComponent(x.lease_id)+'&profile=hermes-desktop&nonce='+encodeURIComponent(x.socket_nonce)))}catch(e){document.getElementById('s').textContent='Access authorization required.'}})();
</script>"""
_RENEW="""<script>(()=>{let busy=false;async function renew(){if(busy)return;busy=true;try{const id=sessionStorage.getItem('hd-lease'),challenge=sessionStorage.getItem('hd-challenge');if(!id||!challenge)throw Error();const r=await fetch('/renew',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({lease_id:id,challenge})});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-challenge',x.renewal_challenge)}catch(_){sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');location.replace('/client/bootstrap.html')}finally{busy=false}}const b=document.createElement('button');b.textContent='End Desktop session';b.setAttribute('aria-label','End Desktop session');b.style='position:fixed;top:8px;right:8px;z-index:2147483647;padding:8px;background:#7b1d1d;color:white';b.onclick=async()=>{b.disabled=true;try{const id=sessionStorage.getItem('hd-lease'),challenge=sessionStorage.getItem('hd-challenge');if(id&&challenge)await fetch('/logout',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({lease_id:id,challenge})})}finally{sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');location.replace('/client/bootstrap.html')}};const addButton=()=>document.body.appendChild(b);if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',addButton,{once:true});else addButton();setInterval(renew,25000);})();</script>"""

def create_app(runtime:GatewayRuntime):
    from aiohttp import ClientSession,web,WSMsgType
    app=web.Application(client_max_size=2048);app["runtime"]=runtime
    async def startup(a):a["client"]=ClientSession(timeout=__import__("aiohttp").ClientTimeout(total=30,connect=3,sock_read=10),connector=__import__("aiohttp").TCPConnector(limit=12,limit_per_host=8),trust_env=False,auto_decompress=False)
    async def cleanup(a):await a["client"].close()
    @web.middleware
    async def auth_errors(request,handler):
        try:return await handler(request)
        except GatewayDenied:return web.Response(status=403,text="Forbidden",headers={"Cache-Control":"no-store"})
    async def root(request):
        runtime.principal(request,"GET","/")
        raise web.HTTPFound("/client/bootstrap.html")
    async def create(request):
        p=runtime.principal(request,"POST","/session")
        if request.can_read_body:raise GatewayDenied("request body forbidden")
        token=request.headers.get("Cf-Access-Jwt-Assertion","")
        session_id=secrets.token_urlsafe(24)
        grant=await runtime.authorize_current(action="issue",session_id=session_id,access_jwt=token,principal=p)
        key,lease=runtime.create_lease(p,grant,session_id)
        return web.json_response({"lease_id":key,"profile_id":runtime.profile_id,"renewal_challenge":lease.renewal_challenge,"socket_nonce":lease.socket_nonce,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store","Pragma":"no-cache"})
    async def renew(request):
        p=runtime.principal(request,"POST","/renew")
        if request.content_length is None or request.content_length>2048:raise GatewayDenied("invalid renewal body")
        try:body=await asyncio.wait_for(request.json(),timeout=3)
        except Exception:raise GatewayDenied("invalid renewal body") from None
        if not isinstance(body,dict) or set(body)!={"lease_id","challenge"} or not all(isinstance(body[x],str) for x in body):raise GatewayDenied("invalid renewal fields")
        token=request.headers.get("Cf-Access-Jwt-Assertion","")
        grant=await runtime.authorize_current(action="renew",session_id=body["lease_id"],access_jwt=token,principal=p)
        lease=runtime.renew(body["lease_id"],p,body["challenge"],grant)
        return web.json_response({"renewal_challenge":lease.renewal_challenge,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store","Pragma":"no-cache"})
    async def logout(request):
        runtime.principal(request,"POST","/logout")
        if request.content_length is None or request.content_length>2048:raise GatewayDenied("invalid logout body")
        try:body=await asyncio.wait_for(request.json(),timeout=3)
        except Exception:raise GatewayDenied("invalid logout body") from None
        if not isinstance(body,dict) or set(body)!={"lease_id","challenge"} or not all(isinstance(body[x],str) for x in body):raise GatewayDenied("invalid logout fields")
        socket=runtime.logout(body["lease_id"],body["challenge"])
        if socket is not None:
            try:await asyncio.wait_for(socket.close(code=1000,message=b"user logout"),timeout=2)
            except Exception:pass
        return web.Response(status=204,headers={"Cache-Control":"no-store","Pragma":"no-cache"})
    async def client(request):
        if request.path=="/client/" and request.headers.get("Upgrade","").casefold()=="websocket":return await stream(request)
        path=canonical_asset(request.raw_path)
        if request.method not in {"GET","HEAD"}:raise GatewayDenied("read-only asset route")
        runtime.principal(request,request.method,path)
        if path=="/client/bootstrap.html":
            return web.Response(text=_BOOTSTRAP,content_type="text/html",headers={"Cache-Control":"no-store","Content-Security-Policy":"default-src 'self'; script-src 'unsafe-inline'; connect-src 'self' wss:; object-src 'none'; base-uri 'none'","X-Content-Type-Options":"nosniff"})
        if request.query_string and any(k.casefold() in {"server","host","port","ssl","url"} for k in request.query):raise GatewayDenied("upstream override denied")
        suffix=path[len("/client/"):]
        upstream=runtime.upstream.rstrip("/")+"/"+quote(suffix,safe="/-._~")
        async with request.app["client"].request(request.method,upstream,allow_redirects=False,headers={"Accept":request.headers.get("Accept","*/*"),"Accept-Encoding":"identity"}) as response:
            if response.status in {301,302,303,307,308}:raise GatewayDenied("upstream redirect denied")
            length=response.headers.get("Content-Length")
            if length is not None:
                try:
                    if int(length)<0 or int(length)>16*1024*1024:raise GatewayDenied("upstream asset exceeds bound")
                except ValueError:raise GatewayDenied("invalid upstream content length") from None
            data=b""
            if request.method!="HEAD":
                chunks=[];size=0
                while True:
                    chunk=await response.content.read(min(65536,16*1024*1024+1-size))
                    if not chunk:break
                    chunks.append(chunk);size+=len(chunk)
                    if size>16*1024*1024:raise GatewayDenied("upstream asset exceeds bound")
                data=b"".join(chunks)
            ctype=response.headers.get("Content-Type","")
            if path=="/client/index.html" and "text/html" in ctype:
                text=data.decode("utf-8","strict")
                if "</body>" not in text.casefold():raise GatewayDenied("unexpected HTML client document")
                pos=text.casefold().rfind("</body>")
                text=text[:pos]+_RENEW+text[pos:];data=text.encode("utf-8")
            if path=="/client/css/client.css":data+=b"\n#float_menu{display:none!important}\n"
            headers={k:v for k,v in response.headers.items() if k.lower() in {"content-type","etag","last-modified"}}
            headers["Cache-Control"]="no-store"
            return web.Response(status=response.status,body=data,headers=headers)
    async def stream(request):
        p=runtime.principal(request,"GET","/client/")
        if request.headers.get("Sec-WebSocket-Protocol")!="binary":raise GatewayDenied("unexpected Xpra WebSocket protocol")
        websocket_target("/stream",principal=p,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),policy=runtime.policy)
        if set(request.query)!={"lease","profile","nonce"} or request.query["profile"]!=runtime.profile_id:raise GatewayDenied("socket profile/lease binding required")
        key=request.query["lease"];lease=runtime.leases.get(key)
        if lease is None or (lease.principal.subject,lease.principal.email)!=(p.subject,p.email):raise GatewayDenied("socket/principal mismatch")
        token=request.headers.get("Cf-Access-Jwt-Assertion","")
        grant=await runtime.authorize_current(action="socket",session_id=key,access_jwt=token,principal=p)
        if grant.valid_until_monotonic<=runtime.monotonic():raise GatewayDenied("socket policy grant expired")
        lease.claim_socket(request.query["nonce"],now=runtime.monotonic())
        from yarl import URL
        up=urlsplit(runtime.upstream);wsurl=URL.build(scheme="ws",host=up.hostname,port=up.port or 80,path="/")
        async with request.app["client"].ws_connect(wsurl,protocols=("binary",),origin=runtime.upstream.rstrip("/"),timeout=3,receive_timeout=None,max_msg_size=16777216,autoping=False,autoclose=False) as upstream:
            downstream=web.WebSocketResponse(protocols=("binary",),max_msg_size=16777216,autoping=False,autoclose=False,compress=False)
                await downstream.prepare(request)
                runtime.sockets[key]=downstream
            async def watchdog():
                while not downstream.closed:
                    await asyncio.sleep(runtime.watchdog_seconds)
                    try:lease.authorize_frame(now=runtime.monotonic())
                    except GatewayDenied:await asyncio.wait_for(downstream.close(code=1008,message=b"lease expired"),timeout=2);return
            async def relay(src,dst):
                async for msg in src:
                    lease.authorize_frame(now=runtime.monotonic())
                    if msg.type==WSMsgType.BINARY:await asyncio.wait_for(dst.send_bytes(msg.data),timeout=5)
                    elif msg.type==WSMsgType.TEXT:await asyncio.wait_for(dst.send_str(msg.data),timeout=5)
                    elif msg.type==WSMsgType.PING:await asyncio.wait_for(dst.ping(msg.data),timeout=5)
                    elif msg.type==WSMsgType.PONG:await asyncio.wait_for(dst.pong(msg.data),timeout=5)
                    elif msg.type==WSMsgType.CLOSE:await asyncio.wait_for(dst.close(),timeout=2);return
            wd=asyncio.create_task(watchdog())
            relays={asyncio.create_task(relay(downstream,upstream)),asyncio.create_task(relay(upstream,downstream)),wd}
            try:
                done,pending=await asyncio.wait(relays,return_when=asyncio.FIRST_COMPLETED)
                for task in pending:task.cancel()
                if pending:await asyncio.wait(pending,timeout=5)
                for task in done:
                    if task is not wd and not task.cancelled() and task.exception():raise task.exception()
            finally:
                runtime.leases.pop(key,None);runtime.sockets.pop(key,None)
                for close in (upstream.close(),downstream.close()):
                    try:await asyncio.wait_for(close,timeout=2)
                    except Exception:pass
                for task in relays:task.cancel()
                await asyncio.wait(relays,timeout=5)
            return downstream
    app.router.add_get("/",root);app.router.add_post("/session",create);app.router.add_post("/renew",renew);app.router.add_post("/logout",logout)
    app.router.add_get("/client/{tail:.*}",client);app.router.add_get("/client/",client)
    app.middlewares.append(auth_errors);app.on_startup.append(startup);app.on_cleanup.append(cleanup)
    return app
