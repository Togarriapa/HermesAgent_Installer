"""Loopback HTTP/WebSocket bridge with Access authorization before all bytes."""
from __future__ import annotations
import asyncio,time,secrets
from dataclasses import dataclass,field
from typing import Callable
from urllib.parse import unquote,urlsplit
from .gateway import GatewayDenied,RemotePolicy,SocketLease,authorize_request,websocket_target

def canonical_asset(raw:str)->str:
    path=raw.split("?",1)[0]
    if not path.startswith("/") or "\\" in path or unquote(path)!=path or any(x in {".",".."} for x in path.split("/")): raise GatewayDenied("non-canonical asset path")
    if not path.startswith("/client/") or path=="/client/": raise GatewayDenied("asset route denied")
    return path
@dataclass
class GatewayRuntime:
    policy:RemotePolicy
    upstream:str="http://127.0.0.1:14500/"
    clock:Callable[[],float]=time.time
    monotonic:Callable[[],float]=time.monotonic
    policy_current:Callable[[str],bool]=lambda _email:True
    max_lease_seconds:int=60
    watchdog_seconds:int=5
    leases:dict[str,SocketLease]=field(default_factory=dict)
    def __post_init__(self):
        u=urlsplit(self.upstream)
        if u.scheme!="http" or u.hostname not in {"127.0.0.1","::1"} or u.username or u.password: raise ValueError("fixed loopback upstream required")
        if not 1<=self.max_lease_seconds<=60 or not 1<=self.watchdog_seconds<=5: raise ValueError("lease/watchdog exceeds hard bound")
    def principal(self,request,method,path):
        return authorize_request(token=request.headers.get("Cf-Access-Jwt-Assertion"),policy=self.policy,method=method,path=path,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),now=self.clock)
    def create_lease(self,principal):
        key=secrets.token_urlsafe(24); lease=SocketLease.create(principal,now=self.monotonic(),requested_seconds=self.max_lease_seconds); self.leases[key]=lease; return key,lease
    def renew(self,key,principal,challenge):
        lease=self.leases.get(key)
        if lease is None: raise GatewayDenied("unknown lease")
        lease.renew(principal,challenge=challenge,now=self.monotonic(),policy_current=self.policy_current,requested_seconds=self.max_lease_seconds); return lease

def create_app(runtime:GatewayRuntime):
    from aiohttp import ClientSession,web,WSMsgType
    app=web.Application(client_max_size=2048); app["runtime"]=runtime
    async def startup(a): a["client"]=ClientSession(timeout=None,trust_env=False,auto_decompress=False)
    async def cleanup(a): await a["client"].close()
    @web.middleware
    async def auth_errors(request,handler):
        try: return await handler(request)
        except GatewayDenied: return web.Response(status=403,text="Forbidden",headers={"Cache-Control":"no-store"})
    async def root(request):
        runtime.principal(request,"GET","/")
        raise web.HTTPFound("/client/index.html?path=%2Fclient%2F")
    async def create(request):
        p=runtime.principal(request,"POST","/session")
        if request.content_length not in (None,0): raise GatewayDenied("request body forbidden")
        key,lease=runtime.create_lease(p)
        return web.json_response({"lease_id":key,"renewal_challenge":lease.renewal_challenge,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store"})
    async def renew(request):
        p=runtime.principal(request,"POST","/renew")
        body=await request.json()
        if not isinstance(body,dict) or set(body)!={"lease_id","challenge"}: raise GatewayDenied("invalid renewal request")
        lease=runtime.renew(body["lease_id"],p,body["challenge"])
        return web.json_response({"renewal_challenge":lease.renewal_challenge,"expires_in":max(0,int(lease.expires_at-runtime.monotonic()))},headers={"Cache-Control":"no-store"})
    async def client_route(request):
        if request.path=="/client/" and request.headers.get("Upgrade","").casefold()=="websocket": return await stream(request)
        path=canonical_asset(request.raw_path)
        if request.method not in {"GET","HEAD"}: raise GatewayDenied("read-only asset route")
        if request.query_string and any(k.casefold() in {"server","host","port","ssl","url"} for k in request.query): raise GatewayDenied("upstream override denied")
        runtime.principal(request,request.method,path)
        suffix=path[len("/client/"):]
        u=urlsplit(runtime.upstream)
        async with request.app["client"].request(request.method,runtime.upstream.rstrip("/")+"/"+suffix,allow_redirects=False,headers={"Accept":request.headers.get("Accept","*/*")}) as response:
            if response.status in {301,302,303,307,308}: raise GatewayDenied("upstream redirect denied")
            data=b"" if request.method=="HEAD" else await response.read()
            headers={k:v for k,v in response.headers.items() if k.lower() in {"content-type","content-length","etag","last-modified"}}
            headers["Cache-Control"]="no-store"
            return web.Response(status=response.status,body=data,headers=headers)
    async def stream(request):
        path="/client/"
        p=runtime.principal(request,"GET",path)
        websocket_target("/stream",principal=p,host=request.headers.get("Host",""),origin=request.headers.get("Origin"),policy=runtime.policy)
        if set(request.query)!={"lease"}: raise GatewayDenied("socket lease required")
        key=request.query["lease"]; lease=runtime.leases.get(key)
        if lease is None or (lease.principal.subject,lease.principal.email)!=(p.subject,p.email): raise GatewayDenied("socket/principal mismatch")
        lease.authorize_frame(now=runtime.monotonic())
        from yarl import URL
        u=urlsplit(runtime.upstream); wsurl=URL.build(scheme="ws",host=u.hostname,port=u.port or 80,path="/")
        async with request.app["client"].ws_connect(wsurl,max_msg_size=1048576,autoping=False,autoclose=False) as upstream:
            down=web.WebSocketResponse(max_msg_size=1048576,autoping=False,autoclose=False,compress=False)
            await down.prepare(request)
            async def watchdog():
                while not down.closed:
                    await asyncio.sleep(runtime.watchdog_seconds)
                    try: lease.authorize_frame(now=runtime.monotonic())
                    except GatewayDenied: await down.close(code=1008,message=b"lease expired"); return
            async def relay(src,dst):
                async for m in src:
                    lease.authorize_frame(now=runtime.monotonic())
                    if m.type==WSMsgType.BINARY: await dst.send_bytes(m.data)
                    elif m.type==WSMsgType.TEXT: await dst.send_str(m.data)
                    elif m.type==WSMsgType.PING: await dst.ping(m.data)
                    elif m.type==WSMsgType.PONG: await dst.pong(m.data)
                    elif m.type==WSMsgType.CLOSE: await dst.close(); return
            task=asyncio.create_task(watchdog())
            try: await asyncio.gather(relay(down,upstream),relay(upstream,down))
            finally:
                task.cancel(); runtime.leases.pop(key,None); await upstream.close(); await down.close()
            return down
    app.router.add_get("/",root); app.router.add_post("/session",create); app.router.add_post("/renew",renew)
    app.router.add_get("/client/{tail:.*}",client_route); app.router.add_get("/client/",client_route)
    app.middlewares.append(auth_errors); app.on_startup.append(startup); app.on_cleanup.append(cleanup)
    return app
