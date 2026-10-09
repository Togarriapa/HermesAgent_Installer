import asyncio,itertools
from typing import Any,Awaitable,Callable,Mapping,Protocol
class MCPError(RuntimeError):pass
class Transport(Protocol):
    async def request(self,payload:Mapping[str,Any])->Mapping[str,Any]:...
    async def close(self)->None:...
class MCPClient:
    def __init__(self,transport:Transport,allowed_tools:set[str],timeout:float=15):
        if not 0<timeout<=120:raise ValueError("timeout outside 0..120 seconds")
        self.transport=transport; self.allowed_tools=frozenset(allowed_tools); self.timeout=timeout; self.ids=itertools.count(1); self.ready=False; self.tools={}
    async def rpc(self,method:str,params:Mapping[str,Any]|None=None):
        rid=next(self.ids)
        try:response=await asyncio.wait_for(self.transport.request({"jsonrpc":"2.0","id":rid,"method":method,"params":dict(params or {})}),self.timeout)
        except (asyncio.TimeoutError,OSError) as exc:raise MCPError(f"{method} timed out or disconnected") from exc
        if response.get("id")!=rid:raise MCPError("response correlation mismatch")
        if "error" in response:raise MCPError("MCP operation failed")
        return response.get("result")
    async def initialize(self):
        result=await self.rpc("initialize",{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"hermes-installer","version":"1"}})
        if not isinstance(result,Mapping) or not result.get("protocolVersion"):raise MCPError("invalid initialize response")
        await self.transport.request({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}); self.ready=True; return result
    async def discover(self):
        if not self.ready:raise MCPError("initialize first")
        result=await self.rpc("tools/list"); rows=result.get("tools") if isinstance(result,Mapping) else None
        if not isinstance(rows,list):raise MCPError("invalid tools/list")
        found={}
        for row in rows:
            if not isinstance(row,Mapping) or not isinstance(row.get("name"),str) or not isinstance(row.get("inputSchema"),Mapping):raise MCPError("malformed tool schema")
            if row["name"] in found:raise MCPError("duplicate tool name")
            found[row["name"]]=row["inputSchema"]
        self.tools=found; return dict(found)
    async def call_read(self,name:str,arguments:Mapping[str,Any]):
        if not self.ready or name not in self.tools:raise MCPError("discover tool before invocation")
        if name not in self.allowed_tools:raise PermissionError("tool outside read allowlist")
        return await self.rpc("tools/call",{"name":name,"arguments":dict(arguments)})
    async def reconnect(self,connect:Callable[[],Awaitable[Transport]]):
        await self.transport.close(); self.transport=await connect(); self.ready=False; self.tools={}; await self.initialize(); await self.discover()
    async def close(self):self.ready=False; self.tools={}; await self.transport.close()
