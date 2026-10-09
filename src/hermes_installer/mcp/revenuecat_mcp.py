from .adapters import ReadOnlyAdapter,SERVICES
def adapter(client,*,project_id:str):
    if not project_id.strip():raise ValueError("select one RevenueCat project")
    return ReadOnlyAdapter(SERVICES["revenuecat"],client,project_id)
