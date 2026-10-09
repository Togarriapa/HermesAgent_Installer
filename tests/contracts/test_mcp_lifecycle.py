"""MCP service adapters remain unavailable until source schemas are reviewed."""
import asyncio
import unittest
from hermes_installer.mcp.adapters import MCPService,ReadOnlyAdapter

class NeverConnect:
    def __init__(self): self.calls=0
    async def initialize(self): self.calls+=1; raise AssertionError("unverified adapter attempted a connection")
    async def discover(self): self.calls+=1; raise AssertionError("unverified adapter attempted discovery")
    async def call_read(self,*args): self.calls+=1; raise AssertionError("unverified adapter attempted a call")

class MCPGateTests(unittest.IsolatedAsyncioTestCase):
    async def test_unverified_service_reports_pending_without_connection(self):
        client=NeverConnect()
        service=MCPService("figma",None,frozenset({"guessed"}),"configure-later","selected file")
        adapter=ReadOnlyAdapter(service,client,"file-1")
        status=await adapter.inspect()
        self.assertFalse(status["functionally_tested"])
        self.assertFalse(status["enabled"])
        self.assertEqual(status["tools"],())
        with self.assertRaises(PermissionError): await adapter.read("guessed",{})
        self.assertEqual(client.calls,0)
if __name__=="__main__": unittest.main()
