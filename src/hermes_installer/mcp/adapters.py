from dataclasses import dataclass
from typing import Mapping
@dataclass(frozen=True,slots=True)
class MCPService:
    id:str; endpoint:str|None; allowed_tools:frozenset[str]; auth_kind:str; selection_required:str; official:bool=True; source_verified:bool=False
SERVICES:Mapping[str,MCPService]={
 "figma":MCPService("figma","https://mcp.figma.com/mcp",frozenset({"get_file","get_file_nodes","get_screenshot","get_metadata"}),"OAuth","selected file"),
 "revenuecat":MCPService("revenuecat","https://mcp.revenuecat.ai/mcp",frozenset({"list_projects","get_project","list_apps","get_app"}),"OAuth or scoped API v2","selected project"),
 "google":MCPService("google",None,frozenset(),"Developer Preview OAuth","service and resource"),
 "google-community":MCPService("google-community",None,frozenset(),"user OAuth","service and resource",False),
 "home-assistant":MCPService("home-assistant",None,frozenset({"GetLiveContext","GetStates","ListEntities"}),"credential reference","selected entities"),
 "playwright":MCPService("playwright",None,frozenset({"browser_navigate","browser_snapshot","browser_screenshot","browser_inspect"}),"local process","loopback fixture")}
class ReadOnlyAdapter:
    def __init__(self,service,client,selection):self.service=service; self.client=client; self.selection=selection
    async def inspect(self):
        if not self.service.source_verified:
            return {"service":self.service.id,"official":self.service.official,"selection":self.selection,
                    "status":"pending_source_schema_transport_and_authorization_verification",
                    "tools":(),"functionally_tested":False,"enabled":False}
        init=await self.client.initialize()
        tools=await self.client.discover()
        self.client.allowed_tools=frozenset(set(tools)&set(self.service.allowed_tools))
        return {"service":self.service.id,"official":self.service.official,"selection":self.selection,
                "protocol":init["protocolVersion"],"tools":tuple(sorted(self.client.allowed_tools)),
                "status":"discovered_not_enabled","functionally_tested":False,"enabled":False}
    async def read(self,name,arguments):
        if not self.service.source_verified:
            raise PermissionError("native MCP service schema, transport and host-policy verification is pending")
        if not self.selection or name not in self.service.allowed_tools:
            raise PermissionError("read outside selected-resource policy")
        return await self.client.call_read(name,arguments)
