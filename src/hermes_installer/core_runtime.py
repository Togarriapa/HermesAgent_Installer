"""Fixed, journaled adoption of the pinned Hermes core service."""
from __future__ import annotations
import grp, hashlib, json, os, pwd, secrets, stat, subprocess, tempfile
from pathlib import Path
SOURCE=Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
PYTHON=Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
HOME=Path("/home/admin"); HERMES_HOME=HOME/".hermes"
UNIT=Path("/etc/systemd/system/hermes-jarvis-core.service")
LAUNCHER=Path("/usr/local/libexec/hermes-jarvis-core-launcher")
TOKEN=Path("/etc/hermes-installer/credentials/jarvis-core-session-token")
JOURNAL=Path("/var/lib/hermes-installer/core-runtime/ownership.json")
SERVICE="hermes-jarvis-core.service"; COMMIT="7085fbf7753266fc4943c55ac04926186bc90005"
LOCK_SHA256="49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549"
class CoreRuntimeError(RuntimeError): pass
def _digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()
def _run(argv,check=True):
 try: r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),"LANG":"C.UTF-8"})
 except (OSError,subprocess.TimeoutExpired) as e: raise CoreRuntimeError("fixed action unavailable") from e
 if check and r.returncode: raise CoreRuntimeError("fixed service action failed")
 return r
def _atomic(path,body,mode,uid=0,gid=0):
 path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
 if path.exists() or path.is_symlink(): raise CoreRuntimeError("fixed path occupied")
 fd,name=tempfile.mkstemp(prefix=".core-",dir=path.parent); tmp=Path(name)
 try:
  os.fchmod(fd,mode); os.fchown(fd,uid,gid)
  with os.fdopen(fd,"wb") as f: f.write(body); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,path)
 finally: tmp.unlink(missing_ok=True)
def _identity():
 if not SOURCE.is_dir() or SOURCE.is_symlink(): raise CoreRuntimeError("pinned source unavailable")
 rev=_run(["git","-C",str(SOURCE),"rev-parse","HEAD"]).stdout.strip()
 dirty=_run(["git","-C",str(SOURCE),"status","--porcelain"]).stdout.strip()
 lock=SOURCE/"pm"/"lock.json"
 if rev!=COMMIT or dirty or not lock.is_file() or _digest(lock)!=LOCK_SHA256: raise CoreRuntimeError("source or PM lock differs from pin")
 if not PYTHON.is_file() or PYTHON.is_symlink() or _run([str(PYTHON),"--version"]).stdout.strip()!="Python 3.14.7": raise CoreRuntimeError("pinned PM Python unavailable or mismatched")
 return {"commit":rev,"lock_sha256":LOCK_SHA256,"python_sha256":_digest(PYTHON)}
def _launcher():
 return b"""#!/bin/sh
set -eu
cred="$CREDENTIALS_DIRECTORY/hermes-session-token"
test -f "$cred" && test ! -L "$cred"
IFS= read -r HERMES_DASHBOARD_SESSION_TOKEN < "$cred"
test -n "$HERMES_DASHBOARD_SESSION_TOKEN"
export HERMES_DASHBOARD_SESSION_TOKEN
export HOME=/home/admin HERMES_HOME=/home/admin/.hermes
export PYTHONPATH=/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532
cd /home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532
exec /home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python -m hermes_cli.main serve --isolated --host 127.0.0.1 --port 8766
"""
def _unit():
 a=pwd.getpwnam("admin")
 if a.pw_uid!=1000 or a.pw_dir!="/home/admin": raise CoreRuntimeError("admin identity mismatch")
 return f"""[Unit]
Description=Jarvis isolated Hermes core
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=admin
Group={grp.getgrgid(a.pw_gid).gr_name}
WorkingDirectory={SOURCE}
Environment=HOME={HOME}
Environment=HERMES_HOME={HERMES_HOME}
LoadCredential=hermes-session-token:{TOKEN}
ExecStart={LAUNCHER}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={HERMES_HOME}
[Install]
WantedBy=multi-user.target
""".encode()
def _journal():
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): raise CoreRuntimeError("core ownership journal missing")
 st=JOURNAL.stat()
 if st.st_uid!=0 or stat.S_IMODE(st.st_mode)!=0o600: raise CoreRuntimeError("core journal permissions unsafe")
 try: d=json.loads(JOURNAL.read_text())
 except (OSError,ValueError) as e: raise CoreRuntimeError("core journal invalid") from e
 if d.get("schema")!=1 or d.get("service")!=SERVICE: raise CoreRuntimeError("core journal identity unsupported")
 for p,k in ((UNIT,"unit_sha256"),(LAUNCHER,"launcher_sha256"),(TOKEN,"token_sha256")):
  if not p.is_file() or p.is_symlink() or _digest(p)!=d.get(k): raise CoreRuntimeError("owned service file changed")
 return d
def status():
 try: d=_journal()
 except CoreRuntimeError as e: return "pending: "+str(e)
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 return f"owned service {active or 'unknown'} at 127.0.0.1:8766; authenticated chat and restart proof pending; source {d['source_commit']}"
def install_or_resume():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 if JOURNAL.exists():
  _journal(); _run(["systemctl","daemon-reload"]); _run(["systemctl","enable","--now",SERVICE]); return status()
 d=_identity(); a=pwd.getpwnam("admin")
 try: gid=grp.getgrgid(981).gr_gid
 except KeyError as e: raise CoreRuntimeError("gateway credential group 981 unavailable") from e
 if any(p.exists() or p.is_symlink() for p in (UNIT,LAUNCHER,TOKEN)): raise CoreRuntimeError("fixed path contains unjournaled state")
 secret=(secrets.token_urlsafe(48)+"\n").encode(); launcher=_launcher(); unit=_unit()
 _atomic(TOKEN,secret,0o640,0,gid); _atomic(LAUNCHER,launcher,0o755); _atomic(UNIT,unit,0o644)
 record={"schema":1,"service":SERVICE,"source_commit":d["commit"],"lock_sha256":d["lock_sha256"],"python_sha256":d["python_sha256"],"admin_uid":a.pw_uid,"admin_gid":a.pw_gid,"host":"127.0.0.1","port":8766,"token_sha256":_digest(TOKEN),"unit_sha256":_digest(UNIT),"launcher_sha256":_digest(LAUNCHER)}
 _atomic(JOURNAL,(json.dumps(record,sort_keys=True)+"\n").encode(),0o600)
 _run(["systemctl","daemon-reload"]); _run(["systemctl","enable","--now",SERVICE]); return status()
def rollback():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 _journal(); _run(["systemctl","disable","--now",SERVICE],False)
 if _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active": raise CoreRuntimeError("unit remains active; files preserved")
 _run(["systemctl","daemon-reload"])
 for p in (UNIT,LAUNCHER,TOKEN,JOURNAL): p.unlink()
 return "owned service files removed; Hermes home and runtime preserved"
__all__=["CoreRuntimeError","install_or_resume","rollback","status"]
