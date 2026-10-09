"""Run Xpra under caller-owned service/cgroup custody and verify renderer readiness."""
from __future__ import annotations
import os,shlex,subprocess
from pathlib import Path
from typing import Callable,Mapping
from .session import SessionSpec,SessionUnavailable,require_sandbox_evidence
class XpraLauncher:
 def __init__(self,spec:SessionSpec,*,xpra:str,runtime_dir:Path,sandbox_probe:Callable[[int],tuple[bool,bool]],process_probe:Callable[[int],Mapping[str,object]],window_patch_ready:Callable[[frozenset[str]],bool],stop_scope:Callable[[int],None]):
  if not Path(xpra).is_absolute() or not runtime_dir.is_absolute():raise SessionUnavailable("absolute Xpra and runtime paths required")
  if spec.uid is None:raise SessionUnavailable("installer service must assign a dedicated UID")
  self.spec,self.xpra,self.runtime_dir=spec,xpra,runtime_dir
  self.sandbox_probe,self.process_probe=sandbox_probe,process_probe
  self.window_patch_ready,self.stop_scope=window_patch_ready,stop_scope
  self.process=None
 def command(self):
  child=shlex.join([self.spec.hermes_executable,*self.spec.hermes_arguments])
  return [self.xpra,"seamless",self.spec.display,"--socket-dirs="+str(self.runtime_dir),"--bind-tcp=127.0.0.1:14500","--html=on","--start-child="+child,"--start-new-commands=no","--start-new-session=no","--start-desktop=no","--start-shadow=no","--start-proxy=no","--control=no","--clipboard=no","--file-transfer=no","--open-files=no","--printing=no","--webcam=no","--speaker=off","--microphone=off","--remote-logging=no","--dbus-proxy=no","--socket-permissions=600"]
 def start(self):
  if os.geteuid()!=self.spec.uid:raise SessionUnavailable("Xpra launcher is not running as the dedicated session UID")
  if not self.window_patch_ready(self.spec.allowed_window_classes):raise SessionUnavailable("pinned Xpra deny-by-default patch is not active")
  self.runtime_dir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(self.runtime_dir,0o700)
  if self.runtime_dir.stat().st_mode&0o077:raise SessionUnavailable("unsafe private Xpra runtime permissions")
  env={"PATH":"/usr/bin:/bin","HOME":self.spec.home,"DISPLAY":self.spec.display,"XDG_RUNTIME_DIR":str(self.runtime_dir),"DBUS_SESSION_BUS_ADDRESS":"disabled:","HERMES_XPRA_ALLOWED_CLASSES":",".join(sorted(self.spec.allowed_window_classes))}
  env.update(self.spec.hermes_environment)
  p=subprocess.Popen(self.command(),stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,close_fds=True,start_new_session=True);self.process=p
  try:
   evidence=self.process_probe(p.pid)
   if evidence.get("pid")!=p.pid or evidence.get("display")!=self.spec.display or evidence.get("foreign_children")!=0 or evidence.get("foreign_windows")!=0 or evidence.get("hermes_build_sha")!=self.spec.hermes_build_sha:raise SessionUnavailable("dedicated session process/window/build check failed")
   renderer=evidence.get("renderer_pid")
   if not isinstance(renderer,int) or evidence.get("renderer_owner_pid")!=p.pid:raise SessionUnavailable("owned Hermes renderer process not found")
   sandboxed,marker=self.sandbox_probe(renderer);require_sandbox_evidence(renderer_sandboxed=sandboxed,no_sandbox_marker=marker)
   if evidence.get("renderer_relaunch_monitor") is not True:raise SessionUnavailable("renderer relaunch monitor is not active")
   return {"pid":p.pid,"renderer_pid":renderer,"display":self.spec.display,"sandboxed":sandboxed,"no_sandbox_marker":marker}
  except Exception:self.stop();raise
 def stop(self):
  p,self.process=self.process,None
  if not p:return
  try:self.stop_scope(p.pid)
  except Exception as exc:raise SessionUnavailable("managed Xpra process scope could not be stopped") from exc
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:raise SessionUnavailable("managed Xpra process scope did not stop within five seconds") from None
