from .adapters import ReadOnlyAdapter,SERVICES
def adapter(client,*,file_key:str):
    if not file_key or "/" in file_key:raise ValueError("select one Figma file key")
    return ReadOnlyAdapter(SERVICES["figma"],client,file_key)
