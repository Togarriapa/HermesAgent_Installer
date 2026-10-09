from .adapters import MCPService,ReadOnlyAdapter
def adapter(client,*,endpoint:str,service:str,resource_id:str,reviewed:bool):
    if not reviewed:raise PermissionError("community source and command review required")
    if service not in {"gmail","drive","docs","sheets","calendar","contacts"} or not resource_id:raise ValueError("select a supported Google service and resource")
    policy=MCPService("google-community-"+service,endpoint,frozenset(),"user configured OAuth","selected resource",False)
    return ReadOnlyAdapter(policy,client,resource_id)
