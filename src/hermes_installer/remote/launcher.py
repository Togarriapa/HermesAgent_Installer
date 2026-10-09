"""Constrained Xpra launcher. Readiness requires live process and Electron proof."""
from __future__ import annotations
import os,signal,subprocess
from pathlib import Path
from typing import Callable,Mapping
from .session import SessionSpec,SessionUnavailable,require_sandbox_evidence
class XpraLauncher:
    def __init__(self,spec:SessionSpec,*,xpra:str,runtime_dir:Path,sandbox_probe:Callable[[int],tuple[bool,bool]],process_probe:Callable[[int],Mapping[str,object]]):
        if not Path(xpra).is_absolute() or not runtime_dir.is_absolute():raise SessionUnavailable("absolute binaries/runtime paths required")
        self.spec,self.xpra,self.runtime_dir=spec,xpra,runtime_dir;self.sandbox_probe,self.process_probe=sandbox_probe,process_probe;self.process=None
    def command(self):
        return [self.xpra,"seamless",self.spec.display,"--socket-dirs="+str(self.runtime_dir),"--bind-tcp=none","--start-child="+self.spec.hermes_executable,"--start-new-commands=no","--start-new-session=no","--start-desktop=no","--start-shadow=no","--start-proxy=no","--control=no","--clipboard=no","--file-transfer=no","--open-files=no","--printing=no","--webcam=no","--speaker=off","--microphone=off","--remote-logging=no","--http=no","--dbus-proxy=no","--socket-permissions=600"]
    def start(self):
        self.runtime_dir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(self.runtime_dir,0o700)
        if self.runtime_dir.stat().st_mode&0o077:raise SessionUnavailable("unsafe private Xpra runtime permissions")
        env={"PATH":"/usr/bin:/bin","HOME":self.spec.home,"DISPLAY":self.spec.display,"XDG_RUNTIME_DIR":str(self.runtime_dir),"DBUS_SESSION_BUS_ADDRESS":"disabled:"}
        p=subprocess.Popen(self.command(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,close_fds=True,start_new_session=True);self.process=p
        try:
            e=self.process_probe(p.pid)
            if e.get("pid")!=p.pid or e.get("display")!=self.spec.display or e.get("foreign_children")!=0 or e.get("foreign_windows")!=0 or e.get("hermes_build_sha")!=self.spec.hermes_build_sha:raise SessionUnavailable("dedicated session process/window/build check failed")
            sandboxed,marker=self.sandbox_probe(p.pid);require_sandbox_evidence(renderer_sandboxed=sandboxed,no_sandbox_marker=marker)
            return {"pid":p.pid,"display":self.spec.display,"sandboxed":sandboxed,"no_sandbox_marker":marker}
        except Exception:self.stop();raise
    def stop(self):
        p,self.process=self.process,None
        if p and p.poll() is None:
            try:os.killpg(p.pid,signal.SIGTERM);p.wait(timeout=5)
            except Exception:
                try:os.killpg(p.pid,signal.SIGKILL)
                except ProcessLookupError:pass
