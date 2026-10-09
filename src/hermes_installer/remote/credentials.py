"""Remote component credential placement and redacted inspection."""
from __future__ import annotations
import os, stat
from pathlib import Path

class RemoteCredentialError(PermissionError): pass

def write_runtime_tunnel_token(path: Path, token: str):
    if not token or "\n" in token or "\r" in token:
        raise RemoteCredentialError("A valid dedicated tunnel token is required")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent,0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as f:
        f.write(token+"\n"); f.flush(); os.fsync(f.fileno())
    os.chmod(path,0o600)
    if stat.S_IMODE(path.stat().st_mode)!=0o600: raise RemoteCredentialError("Tunnel token file is not private")

def cloudflared_argv(*, executable: str, token_file: Path) -> tuple[str,...]:
    if not executable.startswith("/") or not token_file.is_absolute():
        raise RemoteCredentialError("Runtime paths must be absolute")
    return (executable,"tunnel","--no-autoupdate","--token-file",str(token_file),"run")

def assert_management_token_absent(*, argv: tuple[str,...], environment: dict[str,str], token: str):
    if token and (any(token in a for a in argv) or any(token in v for v in environment.values())):
        raise RemoteCredentialError("Cloudflare setup token crossed into runtime boundary")
