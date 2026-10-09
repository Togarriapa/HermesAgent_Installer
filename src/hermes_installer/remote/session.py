"""Constrained Xpra seamless session spec for the official Hermes Desktop."""
from __future__ import annotations
import re
from dataclasses import dataclass,field
from typing import Mapping
class SessionUnavailable(RuntimeError):pass
XPRA_DISABLED_FEATURES=("start-new-commands","start-new-session","start-desktop","start-shadow","start-proxy","shell","control","dbus","file-transfer","open-files","clipboard","printing","webcam","audio","speaker","microphone","devices","remote-logging","http-diagnostics","abstract-sockets")
_ALLOWED_ENV=frozenset({"HERMES_HOME","PATH"})
@dataclass(frozen=True)
class SessionSpec:
 user:str
 display:str
 home:str
 hermes_executable:str
 hermes_build_sha:str
 allowed_window_classes:frozenset[str]
 xpra_version:str="5.1"
 html5_revision:str="ac907bc82f439080fa136c2acb05faf303f7b2af"
 electron_sandbox_required:bool=True
 uid:int|None=None
 hermes_arguments:tuple[str,...]=()
 hermes_environment:Mapping[str,str]=field(default_factory=dict,repr=False)
 def __post_init__(self):
  if not self.user or self.user in {"root","pi"} or not self.hermes_executable.startswith("/"):raise SessionUnavailable("dedicated unprivileged session and absolute Desktop executable required")
  if len(self.hermes_build_sha)!=40 or not self.allowed_window_classes:raise SessionUnavailable("verified Hermes build and window allowlist required")
  if any(not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",c) for c in self.allowed_window_classes):raise SessionUnavailable("invalid window class allowlist")
  if any("\x00" in a for a in self.hermes_arguments):raise SessionUnavailable("invalid Desktop argv")
  if set(self.hermes_environment)-_ALLOWED_ENV or any(not isinstance(v,str) or "\x00" in v for v in self.hermes_environment.values()):raise SessionUnavailable("Desktop environment contains an unapproved variable")
  for key,value in self.hermes_environment.items():
   parts=value.split(":") if key=="PATH" else [value]
   if any(not p.startswith("/") or ".." in p.split("/") for p in parts):raise SessionUnavailable("Desktop environment path must stay absolute and confined")
  if self.uid is not None and self.uid<=0:raise SessionUnavailable("dedicated unprivileged uid required")
def server_policy(spec:SessionSpec)->Mapping[str,object]:
 return {"mode":"seamless","start_child":(spec.hermes_executable,*spec.hermes_arguments),"start_new_commands":False,"start_new_sessions":False,"start_desktop":False,"start_shadow":False,"start_proxy":False,"clipboard":False,"printing":False,"file_transfer":False,"open_files":False,"audio":False,"webcam":False,"devices":False,"dbus":False,"shell":False,"abstract_sockets":False,"bind_tcp":"127.0.0.1:14500","html5":"on","control":False,"bind_unix":"private-runtime-dir-only","window_policy":"patched_default_deny_allowlist","allowed_window_classes":tuple(sorted(spec.allowed_window_classes)),"electron_sandbox":"verify_each_launch_before_ready","foreign_window_injection":"reject","denied_features":XPRA_DISABLED_FEATURES}
def require_sandbox_evidence(*,renderer_sandboxed:bool,no_sandbox_marker:bool):
 if not renderer_sandboxed or no_sandbox_marker:raise SessionUnavailable("Desktop renderer sandbox unavailable; remote session remains disabled")
