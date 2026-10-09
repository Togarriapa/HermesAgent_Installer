from urllib.parse import urlsplit
from .adapters import ReadOnlyAdapter,SERVICES
def validate_fixture_origin(origin:str):
    p=urlsplit(origin)
    if p.scheme!="http" or p.hostname not in {"127.0.0.1","localhost","::1"}:raise PermissionError("verification requires loopback HTTP fixture")
def adapter(client,*,fixture_origin:str):
    validate_fixture_origin(fixture_origin)
    return ReadOnlyAdapter(SERVICES["playwright"],client,fixture_origin)
