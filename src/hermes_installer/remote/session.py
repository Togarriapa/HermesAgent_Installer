"""Constrained Xpra seamless session plan for the official Hermes Desktop."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping

class SessionUnavailable(RuntimeError): pass

XPRA_DISABLED_FEATURES = (
 "start-new-commands","start-new-session","start-desktop","start-shadow","start-proxy",
 "shell","control","dbus","file-transfer","open-files","clipboard","printing","webcam",
 "audio","speaker","microphone","devices","remote-logging","http-diagnostics","abstract-sockets")

@dataclass(frozen=True)
class SessionSpec:
    user: str
    display: str
    home: str
    hermes_executable: str
    hermes_build_sha: str
    allowed_window_classes: frozenset[str]
    xpra_version: str = "5.1"
    html5_revision: str = "ac907bc82f439080fa136c2acb05faf303f7b2af"
    electron_sandbox_required: bool = True
    def __post_init__(self):
        if not self.user or self.user in {"root","pi"} or not self.hermes_executable.startswith("/"):
            raise SessionUnavailable("Dedicated unprivileged session and absolute Desktop executable required")
        if len(self.hermes_build_sha) != 40 or not self.allowed_window_classes:
            raise SessionUnavailable("Verified Hermes build and window allowlist required")

def server_policy(spec: SessionSpec) -> Mapping[str, object]:
    return {"mode":"seamless","start_child":(spec.hermes_executable,),
      "start_new_commands":False,"start_new_sessions":False,"start_desktop":False,
      "start_shadow":False,"start_proxy":False,"clipboard":False,"printing":False,
      "file_transfer":False,"open_files":False,"audio":False,"webcam":False,"devices":False,
      "dbus":False,"shell":False,"abstract_sockets":False,"bind_tcp":False,
      "bind_unix":"private-runtime-dir-only","window_policy":"deny_unmatched_server_side",
      "allowed_window_classes":tuple(sorted(spec.allowed_window_classes)),
      "electron_sandbox":"verify_each_launch_before_ready","foreign_window_injection":"reject",
      "denied_features":XPRA_DISABLED_FEATURES}

def require_sandbox_evidence(*, renderer_sandboxed: bool, no_sandbox_marker: bool):
    if not renderer_sandboxed or no_sandbox_marker:
        raise SessionUnavailable("Desktop renderer sandbox unavailable; remote session remains disabled")
