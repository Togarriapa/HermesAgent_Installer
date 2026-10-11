"""Fixed, journaled adoption of the pinned Hermes core service."""
from __future__ import annotations
import grp, hashlib, json, os, pwd, secrets, stat, subprocess, tempfile, time
from pathlib import Path
SOURCE=Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
PYTHON=Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
PYTHON_LINK_TARGET="/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3"
PYTHON_REAL=Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")
PYTHON_SHA256="566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001"
PYVENV_CFG_SHA256="d982d4b71a70c99f49afef3c0b2cf683c2f053a802da8885d366657b9565f1ad"
HOME=Path("/home/admin"); HERMES_HOME=HOME/".hermes"
UNIT=Path("/etc/systemd/system/hermes-jarvis-core.service")
LAUNCHER=Path("/usr/local/libexec/hermes-jarvis-core-launcher")
TOKEN=Path("/etc/hermes-installer/jarvis-core/session-token")
JOURNAL=Path("/var/lib/hermes-installer/core-runtime/ownership.json")
SERVICE="hermes-jarvis-core.service"; COMMIT="7085fbf7753266fc4943c55ac04926186bc90005"
LOCK_SHA256="49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549"
WORKSPACE=HERMES_HOME/"workspaces"/"jarvis-core"
ROOT_UID=0; GATEWAY_GID=981
FILE_CONTRACT=((UNIT,"unit_sha256",ROOT_UID,ROOT_UID,0o644),(LAUNCHER,"launcher_sha256",ROOT_UID,ROOT_UID,0o755),
               (TOKEN,"token_sha256",ROOT_UID,GATEWAY_GID,0o640))
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
def _ensure_dir(path,uid,gid,mode):
 if path.is_symlink(): raise CoreRuntimeError("service directory may not be a symlink")
 if not path.exists():
  path.mkdir(mode=mode)
  os.chown(path,uid,gid)
  os.chmod(path,mode)
 st=path.stat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=uid or st.st_gid!=gid or stat.S_IMODE(st.st_mode)!=mode:
  raise CoreRuntimeError("service directory ownership or mode differs from reviewed contract")

def _ensure_workspace(uid,gid):
 if HERMES_HOME.is_symlink() or not HERMES_HOME.is_dir():
  raise CoreRuntimeError("existing Hermes home must be a real directory")
 parent=WORKSPACE.parent
 if parent.is_symlink() or (parent.exists() and not parent.is_dir()): raise CoreRuntimeError("Jarvis workspace parent is unsafe")
 if not parent.exists():
  parent.mkdir(mode=0o700); os.chown(parent,uid,gid)
  os.chmod(parent,0o700)
 pst=parent.stat()
 if not stat.S_ISDIR(pst.st_mode) or pst.st_uid!=uid or pst.st_gid!=gid or (stat.S_IMODE(pst.st_mode)&0o022):
  raise CoreRuntimeError("Jarvis workspace parent ownership or mode is unsafe")
 if WORKSPACE.is_symlink(): raise CoreRuntimeError("Jarvis workspace may not be a symlink")
 if not WORKSPACE.exists():
  WORKSPACE.mkdir(mode=0o700); os.chown(WORKSPACE,uid,gid)
  os.chmod(WORKSPACE,0o700)
 st=WORKSPACE.stat()
 if not stat.S_ISDIR(st.st_mode) or st.st_uid!=uid or st.st_gid!=gid or stat.S_IMODE(st.st_mode)!=0o700:
  raise CoreRuntimeError("Jarvis workspace ownership or mode is unsafe")

def _atomic(path,body,mode,uid=0,gid=0):
 flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0)
 try: fd=os.open(path,flags,mode)
 except FileExistsError as e: raise CoreRuntimeError("fixed path occupied") from e
 try:
  os.fchown(fd,uid,gid); os.fchmod(fd,mode)
  with os.fdopen(fd,"wb") as f: f.write(body); f.flush(); os.fsync(f.fileno())
  dfd=os.open(path.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
  try: os.fsync(dfd)
  finally: os.close(dfd)
 except BaseException:
  path.unlink(missing_ok=True)
  raise

def _replace_journal(record):
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): raise CoreRuntimeError("ownership journal disappeared")
 st=JOURNAL.stat()
 if st.st_uid!=ROOT_UID or stat.S_IMODE(st.st_mode)!=0o600: raise CoreRuntimeError("ownership journal permissions changed")
 fd,name=tempfile.mkstemp(prefix=".core-journal-",dir=JOURNAL.parent); tmp=Path(name)
 try:
  os.fchmod(fd,0o600); os.fchown(fd,0,0)
  with os.fdopen(fd,"wb") as f:
   f.write((json.dumps(record,sort_keys=True)+"\n").encode()); f.flush(); os.fsync(f.fileno())
  os.replace(tmp,JOURNAL)
  dfd=os.open(JOURNAL.parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
  try: os.fsync(dfd)
  finally: os.close(dfd)
 finally: tmp.unlink(missing_ok=True)

def _owned_file(path,body,mode,uid,gid,expected,repair):
 if path.exists() or path.is_symlink():
  if path.is_symlink() or not path.is_file(): raise CoreRuntimeError("owned service path has unsafe type")
  st=path.stat()
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode))!=(uid,gid,mode): raise CoreRuntimeError("owned service path metadata changed")
  if _digest(path)==expected: return
  if not repair: raise CoreRuntimeError("journal-owned service content changed")
  path.unlink()
 _atomic(path,body,mode,uid,gid)
def _identity():
 if not SOURCE.is_dir() or SOURCE.is_symlink(): raise CoreRuntimeError("pinned source unavailable")
 rev=_run(["git","-C",str(SOURCE),"rev-parse","HEAD"]).stdout.strip()
 dirty=_run(["git","-C",str(SOURCE),"status","--porcelain"]).stdout.strip()
 lock=SOURCE/"pm"/"lock.json"
 if rev!=COMMIT or dirty or not lock.is_file() or _digest(lock)!=LOCK_SHA256: raise CoreRuntimeError("source or PM lock differs from pin")
 if not PYTHON.is_symlink() or os.readlink(PYTHON)!=PYTHON_LINK_TARGET or PYTHON.resolve(strict=True)!=PYTHON_REAL or not PYTHON_REAL.is_file() or PYTHON_REAL.is_symlink(): raise CoreRuntimeError("PM Python link or realpath differs from reviewed pin")
 if _run([str(PYTHON),"--version"]).stdout.strip()!="Python 3.14.7": raise CoreRuntimeError("pinned PM Python version mismatch")
 st=PYTHON_REAL.stat()
 cfg=PYTHON.parent.parent/"pyvenv.cfg"
 if (st.st_uid!=1000 or st.st_gid!=1000 or stat.S_IMODE(st.st_mode)!=0o755 or st.st_nlink!=1
     or _digest(PYTHON_REAL)!=PYTHON_SHA256 or not cfg.is_file() or _digest(cfg)!=PYVENV_CFG_SHA256):
  raise CoreRuntimeError("PM Python executable or venv provenance differs from reviewed pin")
 return {"commit":rev,"lock_sha256":LOCK_SHA256,"python_sha256":_digest(PYTHON_REAL),
         "python_link":os.readlink(PYTHON),"python_uid":st.st_uid,"python_gid":st.st_gid,"python_mode":stat.S_IMODE(st.st_mode)}
def _launcher():
 return b"""#!/bin/sh
set -eu
cred="$CREDENTIALS_DIRECTORY/hermes-session-token"
test -f "$cred" && test ! -L "$cred"
IFS= read -r HERMES_DASHBOARD_SESSION_TOKEN < "$cred"
test -n "$HERMES_DASHBOARD_SESSION_TOKEN"
export HERMES_DASHBOARD_SESSION_TOKEN
export HOME=/home/admin HERMES_HOME=/home/admin/.hermes
export PATH=/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin
export HERMES_DISABLE_LAZY_INSTALLS=1
export PYTHONPATH=/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532
cd /home/admin/.hermes/workspaces/jarvis-core
exec /home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python -m hermes_cli.main serve --isolated --host 127.0.0.1 --port 8766
"""
def _unit():
 a=pwd.getpwnam("admin")
 if a.pw_uid!=1000 or a.pw_gid!=1000 or a.pw_dir!="/home/admin": raise CoreRuntimeError("admin identity mismatch")
 return f"""[Unit]
Description=Jarvis isolated Hermes core
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=admin
Group=1000
WorkingDirectory={WORKSPACE}
Environment=HOME={HOME}
Environment=HERMES_HOME={HERMES_HOME}
Environment=PATH=/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=HERMES_DISABLE_LAZY_INSTALLS=1
LoadCredential=hermes-session-token:{TOKEN}
ExecStart={LAUNCHER}
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={WORKSPACE}
[Install]
WantedBy=multi-user.target
""".encode()
def _journal():
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): raise CoreRuntimeError("core ownership journal missing")
 st=JOURNAL.stat()
 if st.st_uid!=ROOT_UID or stat.S_IMODE(st.st_mode)!=0o600: raise CoreRuntimeError("core journal permissions unsafe")
 try: d=json.loads(JOURNAL.read_text())
 except (OSError,ValueError) as e: raise CoreRuntimeError("core journal invalid") from e
 if d.get("schema")!=1 or d.get("service")!=SERVICE or d.get("state") not in {"preparing","installed","active"}: raise CoreRuntimeError("core journal identity unsupported")
 if d["state"]!="preparing":
  for p,k,uid,gid,mode in FILE_CONTRACT:
   if not p.is_file() or p.is_symlink() or _digest(p)!=d.get(k): raise CoreRuntimeError("owned service file changed")
   ps=p.stat()
   if (ps.st_uid,ps.st_gid,stat.S_IMODE(ps.st_mode),ps.st_nlink)!=(uid,gid,mode,1): raise CoreRuntimeError("owned service file metadata changed")
  if hashlib.sha256(_unit()).hexdigest()!=d["unit_sha256"] or hashlib.sha256(_launcher()).hexdigest()!=d["launcher_sha256"]:
   raise CoreRuntimeError("owned service recipe differs from the reviewed source")
 return d
def status():
 try: d=_journal()
 except CoreRuntimeError as e: return "pending: "+str(e)
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 if active!="active" or not _owned_listener():
  return f"pending: owned unit is {active or 'unknown'} or its process-bound loopback listener is unproven"
 return f"owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766; authenticated chat and restart proof pending; source {d['source_commit']}"

def _owned_listener():
 """Require systemd MainPID, expected argv/cgroup/UID, and its bound socket inode."""
 try:
  pid_text=_run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()
  pid=int(pid_text)
  if pid<=1: return False
  proc=Path("/proc")/str(pid)
  if int(proc.stat().st_uid)!=1000: return False
  argv=(proc/"cmdline").read_bytes().decode(errors="replace").split("\0")
  if argv[-1]=="": argv.pop()
  expected=[str(PYTHON),"-m","hermes_cli.main","serve","--isolated","--host","127.0.0.1","--port","8766"]
  if argv!=expected: return False
  if not any(SERVICE in line for line in (proc/"cgroup").read_text().splitlines()): return False
  socket_inodes=set()
  for fd in (proc/"fd").iterdir():
   try: link=os.readlink(fd)
   except OSError: continue
   if link.startswith("socket:[") and link.endswith("]"): socket_inodes.add(link[8:-1])
  for table in (Path("/proc/net/tcp"),Path("/proc/net/tcp6")):
   if not table.is_file(): continue
   for row in table.read_text().splitlines()[1:]:
    columns=row.split()
    if len(columns)>9 and columns[3]=="0A" and columns[9] in socket_inodes:
     address,port=columns[1].split(":")
     if int(port,16)==8766 and address in {"0100007F","00000000000000000000000001000000"}:
      return True
 except (OSError,ValueError,UnicodeError):
  return False
 return False
def install_or_resume():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 identity=_identity(); account=pwd.getpwnam("admin")
 if account.pw_uid!=1000 or account.pw_dir!="/home/admin": raise CoreRuntimeError("admin identity mismatch")
 try: gid=grp.getgrgid(GATEWAY_GID).gr_gid
 except KeyError as e: raise CoreRuntimeError("gateway credential group 981 unavailable") from e
 _ensure_dir(Path("/etc/hermes-installer"),0,0,0o755)
 _ensure_dir(TOKEN.parent,0,gid,0o750)
 _ensure_dir(LAUNCHER.parent,0,0,0o755)
 _ensure_dir(UNIT.parent,0,0,0o755)
 _ensure_dir(JOURNAL.parent.parent,0,0,0o700)
 _ensure_dir(JOURNAL.parent,0,0,0o700)
 launcher,unit=_launcher(),_unit()
 if JOURNAL.exists() or JOURNAL.is_symlink():
  record=_journal()
  if any(record.get(key)!=identity.get(source_key) for key,source_key in
         (("source_commit","commit"),("lock_sha256","lock_sha256"),("python_sha256","python_sha256"),
          ("python_link","python_link"),("python_uid","python_uid"),("python_gid","python_gid"),("python_mode","python_mode"))):
   raise CoreRuntimeError("pinned runtime identity changed since core service enrollment")
 else:
  if any(p.exists() or p.is_symlink() for p in (UNIT,LAUNCHER,TOKEN,WORKSPACE)): raise CoreRuntimeError("fixed path contains unjournaled state")
  record={"schema":1,"state":"preparing","service":SERVICE,"source_commit":identity["commit"],
          "lock_sha256":identity["lock_sha256"],"python_sha256":identity["python_sha256"],
          "python_link":identity["python_link"],"python_uid":identity["python_uid"],
          "python_gid":identity["python_gid"],"python_mode":identity["python_mode"],
          "admin_uid":account.pw_uid,"admin_gid":account.pw_gid,"host":"127.0.0.1","port":8766,
          "token_sha256":None,"unit_sha256":hashlib.sha256(unit).hexdigest(),
          "launcher_sha256":hashlib.sha256(launcher).hexdigest()}
  _atomic(JOURNAL,(json.dumps(record,sort_keys=True)+"\n").encode(),0o600)
 if record["state"]=="preparing":
  token_valid=False
  if TOKEN.exists() or TOKEN.is_symlink():
   if TOKEN.is_symlink() or not TOKEN.is_file(): raise CoreRuntimeError("interrupted credential has unsafe type")
   ts=TOKEN.stat(); raw=TOKEN.read_bytes()
   if (ts.st_uid,ts.st_gid,stat.S_IMODE(ts.st_mode))!=(0,gid,0o640):
    raise CoreRuntimeError("interrupted credential owner or mode changed")
   token_valid=(len(raw)==65 and raw.endswith(b"\n") and
                all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in raw[:-1]))
   if token_valid and record.get("token_sha256") is not None:
    token_valid=_digest(TOKEN)==record["token_sha256"]
   if not token_valid: TOKEN.unlink()
  if not token_valid:
   raw=(secrets.token_urlsafe(48)+"\n").encode()
   _atomic(TOKEN,raw,0o640,0,gid)
  if record.get("token_sha256")!=_digest(TOKEN):
   record["token_sha256"]=_digest(TOKEN)
   _replace_journal(record)
 _ensure_workspace(account.pw_uid,account.pw_gid)
 _owned_file(LAUNCHER,launcher,0o755,0,0,record["launcher_sha256"],record["state"]=="preparing")
 _owned_file(UNIT,unit,0o644,0,0,record["unit_sha256"],record["state"]=="preparing")
 if record["state"]=="preparing":
  record["state"]="installed"
  _replace_journal(record)
 _journal()
 _run(["systemctl","daemon-reload"]); _run(["systemctl","enable","--now",SERVICE]); _wait_for_listener(); return status()

def _wait_for_listener():
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  if _owned_listener(): return
  time.sleep(1)
 raise CoreRuntimeError("owned service did not prove its isolated loopback listener within 30 seconds")
def rollback():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 _journal(); _run(["systemctl","disable","--now",SERVICE],False)
 if _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active": raise CoreRuntimeError("unit remains active; files preserved")
 _run(["systemctl","daemon-reload"])
 for p in (UNIT,LAUNCHER,TOKEN,JOURNAL): p.unlink()
 return "owned service files removed; Hermes home and runtime preserved"
__all__=["CoreRuntimeError","install_or_resume","rollback","status"]
