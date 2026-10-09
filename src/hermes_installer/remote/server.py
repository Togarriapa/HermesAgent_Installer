"""Loopback-only HTTP/WebSocket bridge with Access authorization before bytes."""
from __future__ import annotations
import asyncio,secrets,time
from dataclasses import dataclass,field
from typing import Callable
from urllib.parse import quote,unquote,urlsplit
from .gateway import GatewayDenied,RemotePolicy,SocketLease,authorize_request,websocket_target

def canonical_asset(raw:str)->str:
    path=raw.split("?",1)[0]
    if not path.startswith("/") or "\\" in path or unquote(path)!=path or unquote(unquote(path))!=path or any(s in {".",".."} for s in path.split("/")):raise GatewayDenied("non-canonical asset path")
    if not path.startswith("/client/") or path=="/client/":raise GatewayDenied("asset route denied")
    return path
@dataclass
class GatewayRuntime:
    policy:RemotePolicy
    upstream:str="http://127.0.0.1:14500/"
    profile_id:str="hermes-desktop"
    clock:Callable[[],float]=time.time
    monotonic:Callable[[],float]=time.monotonic
    policy_current:Callable[[str],bool]|None=None
    max_lease_seconds:int=60
    max_active_sockets:int=4
    watchdog_seconds:int=5
    leases:dict[str,SocketLease]=field(default_factory=dict)
    def __post_init__(self):
        u=urlsplit(self.upstream)
        if u.scheme!="http" or u.hostname not in {"127.0.0.1","::1"} or u.username or u.password:raise ValueError("fixed loopback upstream required")
        if not 1<=self.max_lease_seconds<=60 or not 1<=self.watchdog_seconds<=5:raise ValueError("lease/watchdog exceeds hard bound")
    def principal(self,request,method,path):
        return authorize_request(token=request.headers.get("Cf-Access-Jwt-Assertion"),policy=self.policy,method=method,path=path,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),now=self.clock)
    def create_lease(self,principal):
        key=secrets.token_urlsafe(24)
        for old_key,old in tuple(self.leases.items()):
            try:old.authorize_frame(now=self.monotonic())
            except GatewayDenied:self.leases.pop(old_key,None)
        if len(self.leases)>=self.max_active_sockets or any(x.principal.subject==principal.subject for x in self.leases.values()):raise GatewayDenied("profile session limit reached")
        lease=SocketLease.create(principal,now=self.monotonic(),wall_now=self.clock(),requested_seconds=self.max_lease_seconds)
        self.leases[key]=lease;return key,lease
    def renew(self,key,principal,challenge):
        lease=self.leases.get(key)
        if lease is None:raise GatewayDenied("unknown lease")
        lease.renew(principal,challenge=challenge,now=self.monotonic(),wall_now=self.clock(),policy_current=self.policy_current,requested_seconds=self.max_lease_seconds);return lease

_BOOTSTRAP="""<!doctype html><meta charset=utf-8><title>Hermes Desktop</title><p id=s>Starting protected Desktop session…</p><script>
(async()=>{try{const r=await fetch('/session',{method:'POST',cache:'no-store',credentials:'same-origin'});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-lease',x.lease_id);sessionStorage.setItem('hd-challenge',x.renewal_challenge);location.replace('/client/index.html?path='+encodeURIComponent('/client/?lease='+encodeURIComponent(x.lease_id)+'&profile=hermes-desktop'))}catch(e){document.getElementById('s').textContent='Access authorization required.'}})();
</script>"""
_RENEW="""<script>(()=>{let busy=false;async function renew(){if(busy)return;busy=true;try{const id=sessionStorage.getItem('hd-lease'),challenge=sessionStorage.getItem('hd-challenge');if(!id||!challenge)throw Error();const r=await fetch('/renew',{method:'POST',cache:'no-store',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({lease_id:id,challenge})});if(!r.ok)throw Error();const x=await r.json();sessionStorage.setItem('hd-challenge',x.renewal_challenge)}catch(_){sessionStorage.removeItem('hd-lease');sessionStorage.removeItem('hd-challenge');location.replace('/client/bootstrap.html')}finally{busy=false}}setInterval(renew,25000);})();</script>"""

def create_app(runtime:GatewayRuntime):
    from aiohttp import ClientSession,web,WSMsgType
    app=web.Application(client_max_size=2048);app["runtime"]=runtime
    async def startup(a):a["client"]=ClientSession(timeout=__import__("aiohttp").ClientTimeout(total=30,connect=3,sock_read=10),trust_env=False,auto_decompress=False)
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
        if request.content_length not in (None,0):raise GatewayDenied("request body forbidden")
        key,lease=runtime.create_lease(p)
        return web.json_response({"lease_id":key,"profile_id":runtime.profile_id,"renewal_challenge":lease.renewal_challenge,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store","Pragma":"no-cache"})
    async def renew(request):
        p=runtime.principal(request,"POST","/renew")
        if request.content_length is None or request.content_length>2048:raise GatewayDenied("invalid renewal body")
        try:body=await request.json()
        except Exception:raise GatewayDenied("invalid renewal body") from None
        if not isinstance(body,dict) or set(body)!={"lease_id","challenge"} or not all(isinstance(body[x],str) for x in body):raise GatewayDenied("invalid renewal fields")
        lease=runtime.renew(body["lease_id"],p,body["challenge"])
        return web.json_response({"renewal_challenge":lease.renewal_challenge,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store","Pragma":"no-cache"})
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
        async with request.app["client"].request(request.method,upstream,allow_redirects=False,headers={"Accept":request.headers.get("Accept","*/*")}) as response:
            if response.status in {301,302,303,307,308}:raise GatewayDenied("upstream redirect denied")
            data=b"" if request.method=="HEAD" else await response.content.read(16*1024*1024+1)
            if len(data)>16*1024*1024:raise GatewayDenied("upstream asset exceeds bound")
            ctype=response.headers.get("Content-Type","")
            if path=="/client/index.html" and "text/html" in ctype:
                text=data.decode("utf-8","strict")
                if "</body>" not in text.casefold():raise GatewayDenied("unexpected HTML client document")
                pos=text.casefold().rfind("</body>")
                text=text[:pos]+_RENEW+text[pos:];data=text.encode("utf-8")
            headers={k:v for k,v in response.headers.items() if k.lower() in {"content-type","etag","last-modified"}}
            headers["Cache-Control"]="no-store"
            return web.Response(status=response.status,body=data,headers=headers)
    async def stream(request):
        p=runtime.principal(request,"GET","/client/")
        if request.headers.get("Sec-WebSocket-Protocol")!="binary":raise GatewayDenied("unexpected Xpra WebSocket protocol")
        websocket_target("/stream",principal=p,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),policy=runtime.policy)
        if set(request.query)!={"lease","profile"} or request.query["profile"]!=runtime.profile_id:raise GatewayDenied("socket profile/lease binding required")
        key=request.query["lease"];lease=runtime.leases.get(key)
        if lease is None or (lease.principal.subject,lease.principal.email)!=(p.subject,p.email):raise GatewayDenied("socket/principal mismatch")
        lease.authorize_frame(now=runtime.monotonic())
        from yarl import URL
        up=urlsplit(runtime.upstream);wsurl=URL.build(scheme="ws",host=up.hostname,port=up.port or 80,path="/")
        async with request.app["client"].ws_connect(wsurl,protocols=("binary",),max_msg_size=1048576,autoping=False,autoclose=False) as upstream:
            downstream=web.WebSocketResponse(protocols=("binary",),max_msg_size=1048576,autoping=False,autoclose=False,compress=False)
            await downstream.prepare(request)
            async def watchdog():
                while not downstream.closed:
                    await asyncio.sleep(runtime.watchdog_seconds)
                    try:lease.authorize_frame(now=runtime.monotonic())
                    except GatewayDenied:await downstream.close(code=1008,message=b"lease expired");return
            async def relay(src,dst):
                async for msg in src:
                    lease.authorize_frame(now=runtime.monotonic())
                    if msg.type==WSMsgType.BINARY:await dst.send_bytes(msg.data)
                    elif msg.type==WSMsgType.TEXT:await dst.send_str(msg.data)
                    elif msg.type==WSMsgType.PING:await dst.ping(msg.data)
                    elif msg.type==WSMsgType.PONG:await dst.pong(msg.data)
                    elif msg.type==WSMsgType.CLOSE:await dst.close();return
            wd=asyncio.create_task(watchdog())
            relays={asyncio.create_task(relay(downstream,upstream)),asyncio.create_task(relay(upstream,downstream)),wd}
            try:
                done,pending=await asyncio.wait(relays,return_when=asyncio.FIRST_COMPLETED)
                for task in pending:task.cancel()
                await asyncio.gather(*pending,return_exceptions=True)
                for task in done:
                    if task is not wd and task.exception():raise task.exception()
            finally:
                for task in relays:task.cancel()
                await asyncio.gather(*relays,return_exceptions=True)
                runtime.leases.pop(key,None);await upstream.close();await downstream.close()
            return downstream
    app.router.add_get("/",root);app.router.add_post("/session",create);app.router.add_post("/renew",renew)
    app.router.add_get("/client/{tail:.*}",client);app.router.add_get("/client/",client)
    app.middlewares.append(auth_errors);app.on_startup.append(startup);app.on_cleanup.append(cleanup)
    return app
