from urllib.parse import urlsplit
from .adapters import MCPService,ReadOnlyAdapter
def adapter(client,*,endpoint:str,entity_ids:tuple[str,...]):
    p=urlsplit(endpoint)
    if p.scheme not in {"http","https"} or not p.netloc or not p.path.rstrip("/").endswith(("/api/mcp","/api/mcp/assist")):raise ValueError("use existing Home Assistant MCP endpoint")
    if not entity_ids or any("." not in e or e.startswith("homeassistant.") for e in entity_ids):raise ValueError("select existing entity ids")
    policy=MCPService("home-assistant",endpoint,frozenset({"GetLiveContext","GetStates","ListEntities"}),"existing instance auth","selected entities")
    return ReadOnlyAdapter(policy,client,",".join(entity_ids))
