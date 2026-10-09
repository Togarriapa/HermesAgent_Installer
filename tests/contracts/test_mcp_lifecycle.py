import asyncio
import pytest
from hermes_installer.mcp.client import MCPClient,MCPError
class Fake:
    def __init__(self):self.calls=[];self.closed=False
    async def request(self,p):
        self.calls.append(p); method=p["method"]
        if method=="initialize":return {"jsonrpc":"2.0","id":p["id"],"result":{"protocolVersion":"2025-03-26"}}
        if method=="tools/list":return {"jsonrpc":"2.0","id":p["id"],"result":{"tools":[{"name":"read","inputSchema":{"type":"object"}},{"name":"write","inputSchema":{"type":"object"}}]}}
        if method=="tools/call":return {"jsonrpc":"2.0","id":p["id"],"result":{"content":[{"type":"text","text":"fixture"}]}}
        return {}
    async def close(self):self.closed=True
@pytest.mark.asyncio
async def test_initialize_discover_read_allowlist_and_reconnect():
    f=Fake(); c=MCPClient(f,{"read"}); await c.initialize(); await c.discover()
    assert (await c.call_read("read",{}))["content"][0]["text"]=="fixture"
    with pytest.raises(PermissionError):await c.call_read("write",{})
    f2=Fake(); await c.reconnect(lambda:asyncio.sleep(0,result=f2)); assert c.tools
    assert f.closed
@pytest.mark.asyncio
async def test_bad_correlation_and_deadline_fail_closed():
    class Slow(Fake):
        async def request(self,p):await asyncio.sleep(.03); return await super().request(p)
    with pytest.raises(MCPError):await MCPClient(Slow(),set(),timeout=.001).initialize()
