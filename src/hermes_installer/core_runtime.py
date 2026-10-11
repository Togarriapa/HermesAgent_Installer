"""Fixed, journaled adoption of the pinned Hermes core service."""
from __future__ import annotations
import grp, hashlib, json, os, pwd, re, secrets, shlex, stat, subprocess, sys, tempfile, time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
SOURCE=Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
ADAPTER_SOURCE=Path(__file__).resolve(strict=True).parents[1]
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
RESOURCES_RECORD=Path("/var/lib/hermes-installer/core-runtime/resources-discovery.json")
RESOURCES_CAS=Path("/var/lib/hermes-installer/core-runtime/resources-cas")
RESOURCES_MIGRATION_RECORD=Path("/var/lib/hermes-installer/core-runtime/resources-migration-backup.json")
PRIMARY_PROMPT_JOURNAL=Path("/var/lib/hermes-installer/core-runtime/primary-prompt-ownership.json")
PRIMARY_PROMPT_BACKUPS=Path("/var/lib/hermes-installer/core-runtime/primary-prompt-backups")
ADAPTER_MIGRATION_BACKUP=Path("/var/lib/hermes-installer/core-runtime/adapter-migration-backup")
# This exact older package was materialized before the importer helper was
# hardened. Its only difference from the current package is that helper member;
# the helper itself is not installed into the owner's Hermes tree.
LEGACY_MATERIALIZED_RESOURCES_ARTIFACT_SHA256="f73463c641ac3744007ee8395b663802d5c916f59256fa8184ad2b4f5594b274"
# Exact PM paths observed with the original 002 umask. Only these admin-owned
# directories may be normalized by the explicit root Resources refresh.
PM_DIRECTORY_MODE_CONTRACT={
 Path("/home"):(0,0,0o755), Path("/home/admin"):(1000,1000,0o700),
 Path("/home/admin/HermesInstaller"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data"):(1000,1000,0o700),
 Path("/home/admin/HermesInstaller/data/installs"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/tools"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64"):(1000,1000,0o775),
 Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin"):(1000,1000,0o775),
}
ETC_INSTALLER=Path("/etc/hermes-installer")
VAR_LIB_INSTALLER=Path("/var/lib/hermes-installer")
SYSTEMD_UNIT_DIR=Path("/etc/systemd/system")
LIBEXEC_DIR=Path("/usr/local/libexec")
RUNUSER=Path("/usr/sbin/runuser")
SERVICE="hermes-jarvis-core.service"; COMMIT="7085fbf7753266fc4943c55ac04926186bc90005"
LOCK_SHA256="49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549"
CORE_SOURCE_FILES={
 "pm/lock.json":"49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549",
 "uv.lock":"2bc4db483e9cba927cd7147f9ccbb09635f85bb3f1f36d6e9d51d06b65d1c67e",
 "pyproject.toml":"cadde2f6a92574d292103f43abf66408b1d841cd9ea332ca7f3e3dfc5dcc87fd",
 "hermes_cli/web_server.py":"839ee3fa8d9548c9e1875ffe1321e287eda37c3577e607dcd93288621b0403a4",
 "tui_gateway/ws.py":"1cecdb714a0abc1edf8fc0ec2d00edc1dc042f0da37baaefb8ba20ce3edeae63",
}
WORKSPACE=HERMES_HOME/"workspaces"/"jarvis-core"
ROOT_UID=0; GATEWAY_GID=981
FILE_CONTRACT=((UNIT,"unit_sha256",ROOT_UID,ROOT_UID,0o644),(LAUNCHER,"launcher_sha256",ROOT_UID,ROOT_UID,0o755),
               (TOKEN,"token_sha256",ROOT_UID,GATEWAY_GID,0o640))
class CoreRuntimeError(RuntimeError): pass

_RESOURCES_PROFILE_SOURCE_SEAL = object()

@dataclass(frozen=True, slots=True)
class VerifiedResourcesProfileSource:
 """Short-lived root-verified bytes for the one fixed orchestrator profile."""
 schema:int
 core_source_generation:str
 hermes_revision:str
 resources_revision:str
 resources_tree:str
 artifact_sha256:str
 ownership_manifest_sha256:str
 loaded_skill_inventory_sha256:str
 profile_id:str
 profile_prompt:bytes
 profile_prompt_sha256:str
 profile_manifest:bytes
 profile_manifest_sha256:str
 profile_member_manifest:bytes
 profile_member_manifest_sha256:str
 observed_at_utc:str
 expires_monotonic:float
 _seal:object=field(repr=False,compare=False)

 def verify_current(self, *, core_source_generation, now=None):
  """Re-read fixed root custody and require this exact snapshot to remain current."""
  current=time.monotonic() if now is None else now
  try:
   if (type(self) is not VerifiedResourcesProfileSource
       or self._seal is not _RESOURCES_PROFILE_SOURCE_SEAL
       or current>=self.expires_monotonic
       or core_source_generation!=self.core_source_generation):
    return False
   fresh=read_current_resources_profile_source(core_source_generation=core_source_generation)
   return bool(fresh is not None and fresh._seal is _RESOURCES_PROFILE_SOURCE_SEAL
    and fresh.profile_prompt_sha256==self.profile_prompt_sha256
   and fresh.profile_manifest_sha256==self.profile_manifest_sha256
    and fresh.profile_member_manifest_sha256==self.profile_member_manifest_sha256
    and fresh.artifact_sha256==self.artifact_sha256
    and fresh.ownership_manifest_sha256==self.ownership_manifest_sha256
    and fresh.resources_revision==self.resources_revision
    and fresh.resources_tree==self.resources_tree
    and fresh.core_source_generation==self.core_source_generation
    and current<self.expires_monotonic)
  except Exception:
   return False

 def is_current_sealed(self, custody, now=None):
  try:
   from .remote import core_gateway_inspector as inspector
   if (type(custody) is not inspector.CoreNativeObserverCustody
       or custody._seal is not inspector._NATIVE_CUSTODY_SEAL
       or custody.core_source_generation!=self.core_source_generation):
    return False
   return self.verify_current(core_source_generation=custody.core_source_generation,now=now)
  except Exception:
   return False

 def resolve_current(self, custody):
  try:
   from .remote import core_gateway_inspector as inspector
   if (type(self) is not VerifiedResourcesProfileSource
       or self._seal is not _RESOURCES_PROFILE_SOURCE_SEAL
       or type(custody) is not inspector.CoreNativeObserverCustody
       or custody._seal is not inspector._NATIVE_CUSTODY_SEAL
       or custody.core_source_generation!=self.core_source_generation):
    return None
   current=read_current_resources_profile_source(
    core_source_generation=custody.core_source_generation)
   if (current is None or current.profile_prompt_sha256!=self.profile_prompt_sha256
       or current.profile_manifest_sha256!=self.profile_manifest_sha256
       or current.profile_member_manifest_sha256!=self.profile_member_manifest_sha256
       or not current.is_current_sealed(custody)):
    return None
   return current
  except Exception:
   return None
def _digest(path):
 h=hashlib.sha256()
 with path.open("rb") as f:
  for b in iter(lambda:f.read(1048576),b""): h.update(b)
 return h.hexdigest()

def _core_source_generation():
 """Match the inspector's fixed source/PM generation digest for receipt binding."""
 digests={}
 for relative,expected in CORE_SOURCE_FILES.items():
  actual=_digest(SOURCE/relative)
  if actual!=expected: raise CoreRuntimeError("pinned core source closure differs")
  digests[relative]=actual
 pyvenv=PYTHON.parent.parent/"pyvenv.cfg"
 pyvenv_sha=_digest(pyvenv)
 if pyvenv_sha!=PYVENV_CFG_SHA256 or _digest(PYTHON_REAL)!=PYTHON_SHA256:
  raise CoreRuntimeError("pinned core Python closure differs")
 closure={"source_revision":COMMIT,"files":digests,
          "pyvenv_cfg_sha256":pyvenv_sha,"python_sha256":PYTHON_SHA256}
 canonical=json.dumps(closure,sort_keys=True,separators=(",",":")).encode("ascii")
 return hashlib.sha256(b"hermes-jarvis-core-source-generation-v1\0"+canonical).hexdigest()

def _sync_directory(path):
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
 try: os.fsync(fd)
 finally: os.close(fd)
def _run(argv,check=True):
 try: r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=30,env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),"LANG":"C.UTF-8"})
 except (OSError,subprocess.TimeoutExpired) as e: raise CoreRuntimeError("fixed action unavailable") from e
 if check and r.returncode: raise CoreRuntimeError("fixed service action failed")
 return r
def _validated_executable(path,allowed_uids):
 """Validate an executable chain while retaining its original venv entrypoint."""
 path=Path(path)
 if not path.is_absolute(): raise CoreRuntimeError("fixed executable path must be absolute")
 allowed=set(allowed_uids)
 directory_owners=allowed|{0}
 candidate=path
 for _ in range(40):
  parent=candidate.parent
  for directory in reversed((parent,*parent.parents)):
   try: info=directory.lstat()
   except OSError as exc: raise CoreRuntimeError("fixed executable parent is unavailable") from exc
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in directory_owners
       or (stat.S_IMODE(info.st_mode)&0o022 and
           not (info.st_uid==0 and info.st_mode&stat.S_ISVTX))):
    raise CoreRuntimeError("fixed executable parent custody is unsafe")
  try: info=candidate.lstat()
  except OSError as exc: raise CoreRuntimeError("fixed executable is unavailable") from exc
  if info.st_uid not in allowed:
   raise CoreRuntimeError("fixed executable ownership is unsafe")
  if stat.S_ISLNK(info.st_mode):
   try: target=os.readlink(candidate)
   except OSError as exc: raise CoreRuntimeError("fixed executable link is unsafe") from exc
   candidate=Path(os.path.abspath(target if os.path.isabs(target) else candidate.parent/target))
   continue
  if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)&0o022
      or not (info.st_mode&0o111)):
   raise CoreRuntimeError("fixed executable target is unsafe")
  return path
 raise CoreRuntimeError("fixed executable link chain is too deep")
def _install_bundled_resources(account):
 """Run the vendored offline importer as admin before enabling public interaction."""
 previous_archive=None
 previous_sha=LEGACY_MATERIALIZED_RESOURCES_ARTIFACT_SHA256
 previous_manifest=None; previous_files=None
 try:
  from .registry import manual_jarvis_skills as native
  current_archive=native.build_manual_jarvis_skills_artifact()
  current_sha=hashlib.sha256(current_archive).hexdigest()
  current_manifest,current_files=native._read_artifact(current_archive,current_sha)
  previous_cas=RESOURCES_CAS/(previous_sha+".zip")
  generation_path=HERMES_HOME/"skills"/native._GENERATION
  generation_exists=generation_path.exists() or generation_path.is_symlink()
  current_generation=False
  if generation_exists:
   try:
    _hash_generation_tree(HERMES_HOME,current_manifest,current_files,current_sha)
    current_generation=True
   except CoreRuntimeError:
    if not (previous_cas.exists() or previous_cas.is_symlink()):
     raise
  if generation_exists and not current_generation and (previous_cas.exists() or previous_cas.is_symlink()):
   previous_archive=_projection_file(previous_cas,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
   if hashlib.sha256(previous_archive).hexdigest()!=previous_sha:
    raise CoreRuntimeError("retained legacy Resources artifact digest differs")
   previous_manifest,previous_files=native._read_artifact(previous_archive,previous_sha)
   # The importer performs its own held-owner verification and atomic exchange;
   # root independently proves the only eligible old target against protected CAS.
   _hash_generation_tree(HERMES_HOME,previous_manifest,previous_files,previous_sha)
  elif generation_exists and not current_generation:
   raise CoreRuntimeError("existing Resources generation has no eligible current or legacy ownership proof")
 except FileNotFoundError:
  previous_archive=None
 except Exception as exc:
  raise CoreRuntimeError("existing Resources generation is not eligible for the exact owned migration") from exc
 try:
  python=Path(sys.executable)
  interpreter=_validated_executable(python,{ROOT_UID,account.pw_uid})
  runuser=_validated_executable(RUNUSER,{ROOT_UID})
  if runuser!=RUNUSER: raise CoreRuntimeError("account-switch executable path differs from its fixed location")
  argv=[str(RUNUSER),"-u","admin","--",str(interpreter),"-m",
        "hermes_installer.registry.manual_jarvis_skills","import-bundled",
        "--home",str(HERMES_HOME),"--hermes-source",str(SOURCE),"--python",str(PYTHON)]
  if previous_archive is not None:
   argv.extend(["--replace-owned-from-sha256",previous_sha])
  env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","HOME":str(HOME),
       "HERMES_HOME":str(HERMES_HOME),"LANG":"C.UTF-8",
       "PYTHONPATH":str(Path(__file__).resolve().parents[1]),
       "PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1"}
  if previous_archive is not None:
   result=subprocess.run(argv,input=previous_archive,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,timeout=600,env=env)
  else:
   result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,text=True,timeout=600,env=env)
 except (OSError,subprocess.TimeoutExpired,ValueError) as exc:
  raise CoreRuntimeError("offline Jarvis resource import is pending") from exc
 if result.returncode:
  raise CoreRuntimeError("offline Jarvis resource import is pending")
 try:
  if len(result.stdout)>8*1024*1024: raise ValueError
  admin_receipt=json.loads(result.stdout)
  if not isinstance(admin_receipt,dict): raise ValueError
 except (ValueError,TypeError):
  raise CoreRuntimeError("offline Jarvis resource receipt is invalid") from None
 if previous_archive is not None:
  try:
   from .registry import manual_jarvis_skills as native
   if admin_receipt.get("artifact_sha256")!=current_sha:
    raise CoreRuntimeError("importer returned a different current Resources artifact")
   backup=Path(admin_receipt["previous_generation_backup"])
   if (backup.parent!=HERMES_HOME or not backup.name.startswith(".jarvis-resources-skills-")
       or backup.is_symlink()):
    raise CoreRuntimeError("retained Resources backup path differs from the fixed migration contract")
   backup_info=backup.lstat()
   if (not stat.S_ISDIR(backup_info.st_mode) or backup_info.st_uid!=account.pw_uid
       or backup_info.st_gid!=account.pw_gid or stat.S_IMODE(backup_info.st_mode)!=0o700):
    raise CoreRuntimeError("retained Resources backup directory custody differs")
   if previous_manifest is None or previous_files is None:
    raise CoreRuntimeError("retained Resources backup has no verified old artifact")
   old_tree_sha=_hash_generation_tree(HERMES_HOME,previous_manifest,previous_files,previous_sha,
                                      target_path=backup)
   migration={"schema":1,"state":"retained","previous_artifact_sha256":previous_sha,
    "previous_ownership_manifest_sha256":old_tree_sha,"backup_path":str(backup),
    "current_artifact_sha256":current_sha}
   _ensure_dir(RESOURCES_MIGRATION_RECORD.parent,ROOT_UID,ROOT_UID,0o700)
   encoded=(json.dumps(migration,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
   if RESOURCES_MIGRATION_RECORD.exists() or RESOURCES_MIGRATION_RECORD.is_symlink():
    if _projection_file(RESOURCES_MIGRATION_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)!=encoded:
     raise CoreRuntimeError("an earlier Resources migration backup record differs")
   else:
    _atomic(RESOURCES_MIGRATION_RECORD,encoded,0o600,ROOT_UID,ROOT_UID)
  except Exception as exc:
   raise CoreRuntimeError("retained Resources migration backup could not be independently verified") from exc
 # The admin response is only an import-attempt signal. Root independently
 # rereads every owned byte and runs its own pinned native-loader query below.
 return {}
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

def _atomic_replace(path,body,mode,uid=0,gid=0):
 """Atomically replace a fixed root-owned projection after fsyncing its parent."""
 try:
  existing=os.lstat(path)
 except FileNotFoundError:
  existing=None
 if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_uid!=uid
     or existing.st_gid!=gid or stat.S_IMODE(existing.st_mode)!=mode or existing.st_nlink!=1):
  raise CoreRuntimeError("existing fixed projection custody differs")
 fd,name=tempfile.mkstemp(prefix=".resources-projection-",dir=path.parent); tmp=Path(name)
 try:
  os.fchown(fd,uid,gid); os.fchmod(fd,mode)
  with os.fdopen(fd,"wb") as stream:
   stream.write(body); stream.flush(); os.fsync(stream.fileno())
  os.replace(tmp,path)
  _sync_directory(path.parent)
 finally:
  tmp.unlink(missing_ok=True)

def _projection_file(path,*,owner,group=None,mode=None,maximum):
 """Read one bounded no-follow file and reject replacement or metadata races."""
 fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0))
 try:
  before=os.fstat(fd)
  if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner
      or (group is not None and before.st_gid!=group)
      or (mode is not None and stat.S_IMODE(before.st_mode)!=mode)
      or before.st_nlink!=1 or before.st_size>maximum):
   raise CoreRuntimeError("fixed projection file custody differs")
  data=bytearray()
  while len(data)<=maximum:
   block=os.read(fd,min(65536,maximum+1-len(data)))
   if not block: break
   data.extend(block)
  after=os.fstat(fd)
  try: named=os.stat(path,follow_symlinks=False)
  except OSError as exc: raise CoreRuntimeError("fixed projection file was replaced") from exc
  signature=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                         item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
  if (len(data)!=before.st_size or len(data)>maximum or signature(before)!=signature(after)
      or signature(before)!=signature(named)):
   raise CoreRuntimeError("fixed projection file changed while reading")
  return bytes(data)
 finally:
  os.close(fd)

def _projection_at(parent_fd,name,*,owner,group=None,mode=None,maximum):
 """Read one bounded file through an already verified directory descriptor."""
 if not isinstance(name,str) or name in {"",".",".."} or "/" in name:
  raise CoreRuntimeError("fixed projection member name is invalid")
 fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=parent_fd)
 try:
  before=os.fstat(fd)
  if (not stat.S_ISREG(before.st_mode) or before.st_uid!=owner
      or (group is not None and before.st_gid!=group)
      or (mode is not None and stat.S_IMODE(before.st_mode)!=mode)
      or before.st_nlink!=1 or before.st_size>maximum):
   raise CoreRuntimeError("fixed projection file custody differs")
  data=bytearray()
  while len(data)<=maximum:
   block=os.read(fd,min(65536,maximum+1-len(data)))
   if not block: break
   data.extend(block)
  after=os.fstat(fd)
  try: named=os.stat(name,dir_fd=parent_fd,follow_symlinks=False)
  except OSError as exc: raise CoreRuntimeError("fixed projection member was replaced") from exc
  signature=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                         item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
  if (len(data)!=before.st_size or len(data)>maximum or signature(before)!=signature(after)
      or signature(before)!=signature(named)):
   raise CoreRuntimeError("fixed projection file changed while reading")
  return bytes(data)
 finally:
  os.close(fd)

def _hash_generation_tree(home,manifest,files,artifact_sha,*,repair_umask_dirs=False,target_path=None):
 """Independently verify the exact admin-owned materialization and journal."""
 from .registry import manual_jarvis_skills as native
 target_name=native._GENERATION
 expected_owner=native._canonical_json({
  "schema":1,"stage":"manual-owned-bundled-resources-import",
  "artifact_sha256":artifact_sha,"source_revision":native.PINNED_REVISION,
  "source_tree":native.PINNED_TREE,"profile_source_id":native.PRIMARY_PROFILE,
  "user_visible_profile":{"source_id":native.PRIMARY_PROFILE,"native_key":"default","display_name":"Jarvis"},
  "internal_profile_count":native._BUNDLE_PROFILE_COUNT-1,
  "target_home_role":"jarvis-primary-home",
  "members":[{"path":f"{target_name}/{name}","sha256":hashlib.sha256(content).hexdigest(),
              "size_bytes":len(content)} for name,content in sorted(files.items())],
 })
 flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
 directory_modes={}
 def directory(parent,name,owner,exact_mode=None,allow_umask_mode=False):
  fd=os.open(name,flags,dir_fd=parent)
  info=os.fstat(fd)
  if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=owner or info.st_nlink<2
      or (exact_mode is not None and stat.S_IMODE(info.st_mode)!=exact_mode)
      or (exact_mode is None and stat.S_IMODE(info.st_mode)&0o022
          and not (allow_umask_mode and stat.S_IMODE(info.st_mode)==0o775))):
   os.close(fd); raise CoreRuntimeError("owned Resources directory custody differs")
  return fd
 rootfd=os.open("/",flags)
 fds=[rootfd]
 try:
  target=Path(home)
  if not target.is_absolute(): raise CoreRuntimeError("owned Resources home is not absolute")
  parentfd=rootfd
  for component in target.parts[1:]:
   owner=1000 if component in {"admin",".hermes"} else 0
   exact=0o700 if component in {"admin",".hermes"} else None
   child=directory(parentfd,component,owner,exact); fds.append(child); parentfd=child
  hermesfd=parentfd
  if target_path is None:
   skillsfd=directory(hermesfd,"skills",1000); fds.append(skillsfd)
   genfd=directory(skillsfd,target_name,1000,0o700); fds.append(genfd)
  else:
   backup=Path(target_path)
   if (backup.parent!=Path(home) or not backup.name.startswith(".jarvis-resources-skills-")):
    raise CoreRuntimeError("retained Resources backup path is outside its fixed home")
   genfd=directory(hermesfd,backup.name,1000,0o700); fds.append(genfd)
  expected=set(files)|{native._OWNER_FILE}
  expected_directories={
   "/".join(PurePosixPath(name).parts[:depth])
   for name in files for depth in range(1,len(PurePosixPath(name).parts))
  }
  actual={}
  actual_directories=set()
  def walk(fd,prefix=""):
   for name in os.listdir(fd):
    if not isinstance(name,str) or name in {".",".."} or "/" in name:
     raise CoreRuntimeError("owned Resources member name is malformed")
    relative=f"{prefix}/{name}" if prefix else name
    info=os.stat(name,dir_fd=fd,follow_symlinks=False)
    if stat.S_ISDIR(info.st_mode):
     actual_directories.add(relative)
     child=directory(fd,name,1000,allow_umask_mode=repair_umask_dirs)
     child_info=os.fstat(child)
     directory_modes[relative]=(child_info.st_dev,child_info.st_ino,stat.S_IMODE(child_info.st_mode))
     try: walk(child,relative)
     finally: os.close(child)
     continue
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=1000 or info.st_nlink!=1:
     raise CoreRuntimeError("owned Resources member custody differs")
    maximum=2*1024*1024 if relative==native._OWNER_FILE else (
     native._PACKAGE_MEMBER_LIMIT if relative.startswith("registry/package/") else native._MEMBER_LIMIT)
    filefd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=fd)
    try:
     before=os.fstat(filefd)
     if (before.st_dev!=info.st_dev or before.st_ino!=info.st_ino or before.st_uid!=1000
         or not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>maximum):
      raise CoreRuntimeError("owned Resources member changed while opening")
     digest=hashlib.sha256(); size=0
     while True:
      block=os.read(filefd,65536)
      if not block: break
      size+=len(block)
      if size>maximum: raise CoreRuntimeError("owned Resources member exceeded its bound")
      digest.update(block)
     after=os.fstat(filefd); named=os.stat(name,dir_fd=fd,follow_symlinks=False)
     signature=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,
                            item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
     if signature(before)!=signature(after) or signature(before)!=signature(named) or size!=before.st_size:
      raise CoreRuntimeError("owned Resources member changed while reading")
     actual[relative]=(size,digest.hexdigest())
    finally: os.close(filefd)
  walk(genfd)
  if set(actual)!=expected or actual_directories!=expected_directories:
   raise CoreRuntimeError("owned Resources generation membership differs")
  for name,content in files.items():
   if actual[name]!=(len(content),hashlib.sha256(content).hexdigest()):
    raise CoreRuntimeError("owned Resources member content differs from the pinned bundle")
  marker=_projection_at(genfd,native._OWNER_FILE,owner=1000,mode=0o600,maximum=2*1024*1024)
  if marker!=expected_owner: raise CoreRuntimeError("owned Resources manifest differs from the pinned bundle")
  drifted=sorted(name for name,(_dev,_ino,mode) in directory_modes.items() if mode==0o775)
  if drifted:
   # This is the sole recognized umask artifact from the original importer. Do
   # not normalize permissions until the exact journal, membership, and every
   # member digest above have all matched the pinned CAS payload.
   if not repair_umask_dirs or os.geteuid()!=ROOT_UID:
    raise CoreRuntimeError("owned Resources nested directory permissions differ")
   for relative in drifted:
    parent=os.dup(genfd)
    try:
     parts=PurePosixPath(relative).parts
     for part in parts:
      child=os.open(part,flags,dir_fd=parent)
      os.close(parent); parent=child
     info=os.fstat(parent)
     expected_dev,expected_ino,expected_mode=directory_modes[relative]
     if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=1000 or info.st_nlink<2
         or (info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode))!=(expected_dev,expected_ino,expected_mode)
         or expected_mode!=0o775):
      raise CoreRuntimeError("owned Resources directory changed during metadata repair")
     os.fchmod(parent,0o755)
     if stat.S_IMODE(os.fstat(parent).st_mode)!=0o755:
      raise CoreRuntimeError("owned Resources directory metadata repair failed")
    finally:
     try: os.close(parent)
     except OSError: pass
   # Re-run the complete verifier with repair disabled. This also catches a
   # concurrent content, membership, or custody change during the repair.
   return _hash_generation_tree(home,manifest,files,artifact_sha,repair_umask_dirs=False)
  return hashlib.sha256(marker).hexdigest()
 finally:
  for fd in reversed(fds):
   try: os.close(fd)
   except OSError: pass

def _current_primary_prompt():
 """Read the active primary identity through verified admin-home directories."""
 flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
 rootfd=os.open("/",flags); fds=[rootfd]
 try:
  current=rootfd
  for component in HERMES_HOME.parts[1:]:
   child=os.open(component,flags,dir_fd=current); info=os.fstat(child)
   expected_owner=1000 if component in {"admin",".hermes"} else 0
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=expected_owner
       or (component in {"admin",".hermes"} and stat.S_IMODE(info.st_mode)!=0o700)):
    os.close(child); raise CoreRuntimeError("Hermes home parent custody differs")
   fds.append(child); current=child
  return _projection_at(current,"SOUL.md",owner=1000,maximum=1024*1024)
 finally:
  for fd in reversed(fds): os.close(fd)

def _root_native_readback(manifest,files,active_prompt,*,expected_managed_block_sha256=None):
 """Independently ask the pinned native loader to read the root-verified files."""
 from .registry.native_install import _PROBE
 account=pwd.getpwnam("admin")
 if (account.pw_uid!=1000 or account.pw_gid!=1000 or account.pw_dir!="/home/admin"
     or _validated_executable(RUNUSER,{ROOT_UID})!=RUNUSER
     or _validated_executable(PYTHON,{ROOT_UID,account.pw_uid})!=PYTHON):
  raise CoreRuntimeError("pinned native read-back executables differ")
 skill_ids=sorted(row["skill_id"] for row in manifest["skill_members"])
 env={"PATH":"/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin",
  "HOME":str(HERMES_HOME),"HERMES_HOME":str(HERMES_HOME),"TMPDIR":"/tmp",
  "HERMES_DISABLE_LAZY_INSTALLS":"1","PYTHONPATH":str(SOURCE),
  "PYTHONNOUSERSITE":"1","PYTHONDONTWRITEBYTECODE":"1"}
 argv=[str(RUNUSER),"-u","admin","--",str(PYTHON),"-c",_PROBE,
  str(SOURCE),"default",json.dumps(skill_ids,separators=(",",":")),
  expected_managed_block_sha256 or ""]
 try:
  result=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
   stderr=subprocess.DEVNULL,timeout=300,env=env,cwd=str(SOURCE),check=False)
 except (OSError,subprocess.TimeoutExpired):
  raise CoreRuntimeError("independent pinned native read-back is pending") from None
 if result.returncode or len(result.stdout)>8*1024*1024:
  raise CoreRuntimeError("independent pinned native read-back is pending")
 try: value=json.loads(result.stdout)
 except (ValueError,TypeError):
  raise CoreRuntimeError("independent pinned native read-back is invalid") from None
 expected_keys={"python_version","profile","skills","loaded","visible_profiles",
  "profile_display_name","profile_file_sha256","managed_prompt_block_sha256",
  "effective_prompt_contains_managed_block","effective_prompt_truncated",
  "native_effective_prompt_sha256","native_effective_prompt_chars",
  "expected_managed_block_sha256","digests"}
 expected_digests={"profile:default":hashlib.sha256(active_prompt).hexdigest()}
 expected_digests.update({"skill:"+row["skill_id"]:hashlib.sha256(files[row["archive_path"]]).hexdigest()
  for row in manifest["skill_members"]})
 discovered=value.get("skills") if isinstance(value,dict) else None
 loaded=value.get("loaded") if isinstance(value,dict) else None
 profiles=value.get("visible_profiles") if isinstance(value,dict) else None
 diagnostic=_native_readback_mismatch(value,expected_keys,skill_ids,expected_digests,
                                     expected_managed_block_sha256=expected_managed_block_sha256)
 if diagnostic["mismatches"]:
  encoded=json.dumps(diagnostic,sort_keys=True,separators=(",",":"))
  raise CoreRuntimeError("independent pinned native read-back did not match the root-verified files; "+encoded)
 bundled_sha=hashlib.sha256(files["registry/profiles/hermes/SOUL.md"]).hexdigest()
 return {"hermes_revision":COMMIT,"python_version":value["python_version"],
  "profile_id":"default","profile_identity_loaded":True,
  "loaded_skill_count":len(skill_ids),
  "loaded_skill_inventory_sha256":hashlib.sha256(native_inventory_bytes(manifest,files)).hexdigest(),
  "active_primary_prompt_sha256":expected_digests["profile:default"],
  "native_loaded_primary_prompt_sha256":value["digests"]["profile:default"],
  "bundled_primary_prompt_sha256":bundled_sha,
  "active_prompt_matches_bundled_primary":expected_digests["profile:default"]==bundled_sha,
  "managed_prompt_block_sha256":value["managed_prompt_block_sha256"],
  "effective_prompt_contains_managed_block":value["effective_prompt_contains_managed_block"],
  "effective_prompt_truncated":value["effective_prompt_truncated"],
  "native_effective_prompt_sha256":value["native_effective_prompt_sha256"],
  "native_effective_prompt_chars":value["native_effective_prompt_chars"]}

def _native_readback_mismatch(value,expected_keys,skill_ids,expected_digests,*,expected_managed_block_sha256=None):
 """Return bounded, non-content diagnostics for a failed native projection."""
 codes=[]; details={"schema":1,"expected_skill_count":len(skill_ids)}
 if not isinstance(value,dict):
  codes.append("response_not_object")
  details["observed_type"]=type(value).__name__[:40]
  details["mismatches"]=codes
  return details
 keys=set(value)
 missing=expected_keys-keys; extra=keys-expected_keys
 if missing:
  codes.append("response_fields_missing")
  details["missing_fields"]=sorted(missing)
 if extra: codes.append("response_fields_extra"); details["extra_field_count"]=len(extra)
 if value.get("python_version")!="3.14.7": codes.append("python_version")
 if value.get("profile")!="default": codes.append("profile")
 discovered=value.get("skills")
 if not isinstance(discovered,list) or any(not isinstance(name,str) for name in discovered):
  codes.append("skills_shape")
  discovered=[]
 else:
  details["discovered_skill_count"]=len(discovered)
  if discovered!=sorted(set(discovered)): codes.append("skills_order_or_duplicates")
  missing_skills=set(skill_ids)-set(discovered)
  if missing_skills:
   codes.append("expected_skills_missing")
   details["missing_expected_skill_count"]=len(missing_skills)
 loaded=value.get("loaded")
 if not isinstance(loaded,list) or any(not isinstance(name,str) for name in loaded):
  codes.append("loaded_shape")
  details["loaded_skill_count"]=len(loaded) if isinstance(loaded,list) else None
 elif loaded!=skill_ids:
  codes.append("loaded_mismatch")
  details["loaded_skill_count"]=len(loaded)
  details["loaded_expected_mismatch_count"]=sum(
   left!=right for left,right in zip(loaded,skill_ids))+abs(len(loaded)-len(skill_ids))
 profiles=value.get("visible_profiles")
 if not isinstance(profiles,list) or any(not isinstance(name,str) for name in profiles):
  codes.append("profiles_shape")
 else:
  details["visible_profile_count"]=len(profiles)
  if profiles!=sorted(set(profiles)): codes.append("profiles_order_or_duplicates")
  if "default" not in profiles: codes.append("default_profile_missing")
 display=value.get("profile_display_name")
 if not isinstance(display,str): codes.append("profile_display_name_shape")
 else:
  details["profile_display_name_length"]=len(display)
  details["profile_display_name_sha256"]=hashlib.sha256(display.encode("utf-8",errors="replace")).hexdigest()
  if len(display)>120: codes.append("profile_display_name_length")
 block_sha=value.get("managed_prompt_block_sha256")
 block_loaded=value.get("effective_prompt_contains_managed_block")
 truncated=value.get("effective_prompt_truncated")
 expected_block=value.get("expected_managed_block_sha256")
 effective_sha=value.get("native_effective_prompt_sha256")
 effective_chars=value.get("native_effective_prompt_chars")
 details["managed_prompt_block_present"]=isinstance(block_sha,str)
 details["effective_prompt_contains_managed_block"]=block_loaded is True
 details["effective_prompt_truncated"]=truncated is True
 if (type(block_loaded) is not bool or type(truncated) is not bool
     or not isinstance(effective_sha,str) or re.fullmatch(r"[0-9a-f]{64}",effective_sha) is None
     or type(effective_chars) is not int or not 0<effective_chars<=1024*1024
     or expected_block!=expected_managed_block_sha256):
  codes.append("managed_prompt_readback_shape")
 if expected_managed_block_sha256 is not None:
  if (block_sha!=expected_managed_block_sha256 or block_loaded is not True
      or truncated is not False):
   codes.append("managed_prompt_not_fully_effective")
 elif block_sha is not None and (not isinstance(block_sha,str)
      or re.fullmatch(r"[0-9a-f]{64}",block_sha) is None):
  codes.append("managed_prompt_block_digest_shape")
 expected_profile_sha=expected_digests.get("profile:default")
 observed_profile_sha=value.get("profile_file_sha256")
 profile_file_matches=(isinstance(observed_profile_sha,str)
                       and observed_profile_sha==expected_profile_sha)
 details["profile_file_matches_expected"]=profile_file_matches
 if not profile_file_matches: codes.append("profile_file_digest_mismatch")
 observed=value.get("digests")
 if not isinstance(observed,dict) or any(not isinstance(key,str) or not isinstance(item,str)
                                          for key,item in observed.items()):
  codes.append("digests_shape")
 else:
  if observed.get("profile:default")!=effective_sha:
   codes.append("effective_prompt_digest_mismatch")
  expected_skill_keys={key for key in expected_digests if key.startswith("skill:")}
  observed_skill_keys={key for key in observed if key.startswith("skill:")}
  expected_keys=expected_skill_keys|{"profile:default"}
  observed_keys=set(observed)
  details["expected_digest_count"]=len(expected_keys)
  details["observed_digest_count"]=len(observed_keys)
  details["missing_digest_count"]=len(expected_keys-observed_keys)
  details["extra_digest_count"]=len(observed_keys-expected_keys)
  details["digest_value_mismatch_count"]=sum(
   observed.get(key)!=expected_digests[key] for key in expected_skill_keys&observed_keys)
  loaded_profile_sha=observed.get("profile:default")
  valid_loaded_profile_sha=(isinstance(loaded_profile_sha,str)
                            and re.fullmatch(r"[0-9a-f]{64}",loaded_profile_sha) is not None)
  details["loaded_profile_digest_valid"]=valid_loaded_profile_sha
  if valid_loaded_profile_sha:
   details["loaded_profile_digest_sha256"]=loaded_profile_sha
  else:
   codes.append("loaded_profile_digest_invalid")
  details["profile_digest_mismatch_count"]=int(not valid_loaded_profile_sha)
  details["skill_digest_mismatch_count"]=sum(
   key.startswith("skill:") and observed.get(key)!=expected_digests[key]
   for key in expected_skill_keys&observed_keys)
  if (expected_skill_keys!=observed_skill_keys
      or any(observed.get(key)!=expected_digests[key] for key in expected_skill_keys&observed_keys)
      or "profile:default" not in observed or observed_keys!=expected_keys):
   codes.append("digests_mismatch")
  try:
   canonical=json.dumps(observed,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
   details["observed_digest_map_sha256"]=hashlib.sha256(canonical).hexdigest()
   expected_skills={key:value for key,value in expected_digests.items() if key.startswith("skill:")}
   expected_canonical=json.dumps(expected_skills,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
   details["expected_skill_digest_map_sha256"]=hashlib.sha256(expected_canonical).hexdigest()
  except (TypeError,ValueError,UnicodeError):
   codes.append("digests_not_canonical")
 details["mismatches"]=sorted(set(codes))
 return details

def native_inventory_bytes(manifest,files):
 """Canonical digest of the IDs and bytes independently returned by Hermes."""
 return json.dumps([{"skill_id":row["skill_id"],
  "sha256":hashlib.sha256(files[row["archive_path"]]).hexdigest()}
  for row in sorted(manifest["skill_members"],key=lambda item:item["skill_id"])],
  sort_keys=True,separators=(",",":")).encode("ascii")+b"\n"

def _verified_legacy_materialization(native,current_manifest,current_files,*,repair_umask_dirs):
 """Prove the exact pre-hardening artifact still owns the current byte-identical tree.

 This is deliberately available only to the explicit root refresh path. The
 archive digest is pinned, the independently parsed manifests must match after
 removing only the non-materialized installer row, and every materialized
 member must be byte-identical to today's verified package.
 """
 if not repair_umask_dirs or os.geteuid()!=ROOT_UID:
  raise CoreRuntimeError("legacy Resources materialization is not authorized here")
 artifact_sha=LEGACY_MATERIALIZED_RESOURCES_ARTIFACT_SHA256
 archive=_projection_file(RESOURCES_CAS/(artifact_sha+".zip"),owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
 if hashlib.sha256(archive).hexdigest()!=artifact_sha:
  raise CoreRuntimeError("legacy Resources package digest differs")
 try:
  old_manifest,old_files=native._read_artifact(archive,artifact_sha)
 except Exception as exc:
  raise CoreRuntimeError("legacy Resources package is invalid") from exc
 current_projection=dict(current_manifest); current_projection.pop("installer",None)
 old_projection=dict(old_manifest); old_projection.pop("installer",None)
 if (native._canonical_json(current_projection)!=native._canonical_json(old_projection)
     or old_files!=current_files):
  raise CoreRuntimeError("legacy Resources package is not byte-compatible with current bundle")
 # The journal's artifact identity and all member bytes are checked by the
 # same strict verifier used for current artifacts. Only the pinned old digest
 # can reproduce this retained ownership marker.
 manifest_sha=_hash_generation_tree(HERMES_HOME,old_manifest,old_files,artifact_sha,
   repair_umask_dirs=True)
 return archive,old_manifest,old_files,artifact_sha,manifest_sha

def _verified_resources_payload(_admin_receipt=None,*,repair_umask_dirs=False):
 """Build a root-derived receipt and initiate a fresh pinned native-loader query."""
 from .registry import manual_jarvis_skills as native
 archive=native.build_manual_jarvis_skills_artifact()
 artifact_sha=hashlib.sha256(archive).hexdigest()
 manifest,files=native._read_artifact(archive,artifact_sha)
 expected_other=len(manifest["bundled_resource_inventory"])-len(manifest["skill_members"])-len(manifest["profile_members"])
 if len(manifest["skill_members"])!=396 or len(manifest["profile_members"])!=208 or expected_other!=88:
  raise CoreRuntimeError("pinned offline Resources inventory differs")
 counts={"native_skills":396,"internal_profiles":207,
  "source_profiles_preserved":208,"other_declarations_preserved":expected_other}
 overlay=manifest.get("effective_overlay")
 if not isinstance(overlay,dict):
  raise CoreRuntimeError("compiled Jarvis master overlay provenance is missing")
 overlay_receipt={
  "overlay_id":overlay.get("overlay_id"),"approval_commit":overlay.get("approval_commit"),
  "sha256":overlay.get("sha256"),"upstream_revision":overlay.get("upstream_revision"),
  "upstream_tree":overlay.get("upstream_tree"),
  "source_declarations":overlay.get("source_declarations"),
  "compiled_profiles":overlay.get("compiled_profiles"),
  "compiled_bundle":overlay.get("compiled_bundle"),
 }
 if (overlay_receipt["overlay_id"]!="jarvis-master-semantics-v2"
     or not isinstance(overlay_receipt["sha256"],str)
     or re.fullmatch(r"[0-9a-f]{64}",overlay_receipt["sha256"]) is None):
  raise CoreRuntimeError("compiled Jarvis master overlay provenance is malformed")
 source_generation=_core_source_generation()
 try:
  manifest_sha=_hash_generation_tree(HERMES_HOME,manifest,files,artifact_sha,
    repair_umask_dirs=repair_umask_dirs)
 except CoreRuntimeError as exc:
  # Existing generations retain their original artifact identity. A helper
  # source update changes the ZIP digest even though that helper is not among
  # the installed members. Permit only the single exact legacy package above,
  # only during an explicit root refresh, and only after complete byte proof.
  if "owned Resources manifest differs from the pinned bundle" not in str(exc):
   raise
  archive,manifest,files,artifact_sha,manifest_sha=_verified_legacy_materialization(
    native,manifest,files,repair_umask_dirs=repair_umask_dirs)
 active_prompt=_current_primary_prompt()
 try: active_prompt.decode("utf-8")
 except UnicodeDecodeError: raise CoreRuntimeError("primary Jarvis prompt encoding is invalid") from None
 active_sha=hashlib.sha256(active_prompt).hexdigest()
 bundled_sha=hashlib.sha256(files["registry/profiles/hermes/SOUL.md"]).hexdigest()
 native_receipt=_root_native_readback(manifest,files,active_prompt)
 if (_core_source_generation()!=source_generation
     or _hash_generation_tree(HERMES_HOME,manifest,files,artifact_sha,
       repair_umask_dirs=False)!=manifest_sha
     or hashlib.sha256(_current_primary_prompt()).hexdigest()!=active_sha):
  raise CoreRuntimeError("pinned source or owned Resources changed during native read-back")
 if (native_receipt["active_primary_prompt_sha256"]!=active_sha
     or native_receipt["bundled_primary_prompt_sha256"]!=bundled_sha
     or native_receipt["active_prompt_matches_bundled_primary"] is not (active_sha==bundled_sha)):
  raise CoreRuntimeError("root native read-back differs from active owned prompt")
 journal=_journal()
 if journal.get("state") not in {"installed","active"}:
  raise CoreRuntimeError("core ownership journal is not installed")
 journal_bytes=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 if json.loads(journal_bytes)!=journal:
  raise CoreRuntimeError("core ownership journal changed during Resources verification")
 return archive,{
  "schema":3,"native_readback_method":"root-pinned-hermes-loader-v2",
  "core_source_generation":source_generation,"core_ownership_sha256":hashlib.sha256(journal_bytes).hexdigest(),
  "hermes_revision":COMMIT,"python_version":"3.14.7",
  "resources_revision":manifest["source"]["revision"],"resources_tree":manifest["source"]["git_tree"],
  "artifact_sha256":artifact_sha,"ownership_manifest_sha256":manifest_sha,
  "loaded_skill_inventory_sha256":native_receipt["loaded_skill_inventory_sha256"],"active_primary_prompt_sha256":active_sha,
  "bundled_primary_prompt_sha256":bundled_sha,"active_prompt_matches_bundled_primary":active_sha==bundled_sha,
  "effective_overlay":overlay_receipt,
  "resource_counts":counts,
  "observed_at_utc":datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z"),
  "state":"discovered","functional":False,"enabled":False,"target_verified":False,
 }

def _write_resources_discovery(*,repair_umask_dirs=False):
 """Retain the source-bound artifact and independently read-backed receipt as root."""
 _ensure_dir(RESOURCES_RECORD.parent,ROOT_UID,ROOT_UID,0o700)
 archive,record=_verified_resources_payload(repair_umask_dirs=repair_umask_dirs)
 _ensure_dir(RESOURCES_CAS,ROOT_UID,ROOT_UID,0o700)
 cas=RESOURCES_CAS/(record["artifact_sha256"]+".zip")
 try: os.lstat(cas); cas_present=True
 except FileNotFoundError: cas_present=False
 if cas_present:
  if _projection_file(cas,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)!=archive:
   raise CoreRuntimeError("retained Resources artifact differs from its digest")
 else:
  _atomic(cas,archive,0o600,ROOT_UID,ROOT_UID)
 _atomic_replace(RESOURCES_RECORD,(json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode("ascii"),0o600,ROOT_UID,ROOT_UID)
 return record

def read_current_resources_discovery(*,core_source_generation):
 """Recheck the root receipt, held CAS, owner manifest, and every installed member."""
 pending={"core_version":None,"provider":None,"model":None,"account_state":"unknown",
  "resources_state":"pending","resource_counts":None,"resources_revision":None,
  "artifact_sha256":None,"discovery_observed_at_utc":None,
  "active_prompt_matches_bundled_primary":None}
 try:
  record_bytes=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
 except FileNotFoundError:
  return pending
 try:
  record=json.loads(record_bytes)
  fields={"schema","native_readback_method","core_source_generation","core_ownership_sha256","hermes_revision","python_version",
   "resources_revision","resources_tree","artifact_sha256","ownership_manifest_sha256",
   "loaded_skill_inventory_sha256","active_primary_prompt_sha256","bundled_primary_prompt_sha256",
   "active_prompt_matches_bundled_primary","effective_overlay","resource_counts","observed_at_utc","state",
   "functional","enabled","target_verified"}
  if (set(record)!=fields or type(record.get("schema")) is not int or record["schema"]!=3
      or record.get("native_readback_method")!="root-pinned-hermes-loader-v2"):
   return {**pending,"resources_state":"stale"}
  hashes=("core_source_generation","core_ownership_sha256","hermes_revision","resources_tree",
          "artifact_sha256","ownership_manifest_sha256","loaded_skill_inventory_sha256",
          "active_primary_prompt_sha256","bundled_primary_prompt_sha256")
  if any(not isinstance(record.get(key),str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}",record[key]) is None
         for key in hashes):
   return {**pending,"resources_state":"stale"}
  try:
   observed=datetime.fromisoformat(record["observed_at_utc"].replace("Z","+00:00"))
   if (observed.tzinfo is None or observed.utcoffset()!=timezone.utc.utcoffset(observed)
       or observed.isoformat(timespec="seconds").replace("+00:00","Z")!=record["observed_at_utc"]):
    return {**pending,"resources_state":"stale"}
  except (AttributeError,TypeError,ValueError):
   return {**pending,"resources_state":"stale"}
  journal=_journal()
  if journal.get("state") not in {"installed","active"}:
   return {**pending,"resources_state":"stale"}
  current_journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
  if json.loads(current_journal)!=journal:
   return {**pending,"resources_state":"stale"}
  if (record["core_source_generation"]!=core_source_generation
      or record["core_source_generation"]!=_core_source_generation()
      or record["hermes_revision"]!=COMMIT
      or record["core_ownership_sha256"]!=hashlib.sha256(current_journal).hexdigest()
      or record["state"]!="discovered" or record["functional"] is not False
      or record["enabled"] is not False or record["target_verified"] is not False):
   return {**pending,"resources_state":"stale"}
  _journal()
  artifact_sha=record["artifact_sha256"]
  if not isinstance(artifact_sha,str) or len(artifact_sha)!=64 or any(c not in "0123456789abcdef" for c in artifact_sha):
   return {**pending,"resources_state":"stale"}
  cas=RESOURCES_CAS/(artifact_sha+".zip")
  archive=_projection_file(cas,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  if hashlib.sha256(archive).hexdigest()!=artifact_sha: return {**pending,"resources_state":"stale"}
  from .registry import manual_jarvis_skills as native
  manifest,files=native._read_artifact(archive,artifact_sha)
  overlay=manifest.get("effective_overlay")
  if not isinstance(overlay,dict): return {**pending,"resources_state":"stale"}
  expected_overlay={key:overlay.get(key) for key in (
   "overlay_id","approval_commit","sha256","upstream_revision","upstream_tree",
   "source_declarations","compiled_profiles","compiled_bundle")}
  if record.get("effective_overlay")!=expected_overlay:
   return {**pending,"resources_state":"stale"}
  expected_inventory=native._canonical_json([
   {"skill_id":row["skill_id"],"sha256":hashlib.sha256(files[row["archive_path"]]).hexdigest()}
   for row in sorted(manifest["skill_members"],key=lambda row:row["skill_id"])])
  if (hashlib.sha256(expected_inventory).hexdigest()!=record["loaded_skill_inventory_sha256"]
      or record["python_version"]!="3.14.7"
      or not isinstance(record["resources_revision"],str)
      or not isinstance(record["resources_tree"],str)):
   return {**pending,"resources_state":"stale"}
  manifest_sha=_hash_generation_tree(HERMES_HOME,manifest,files,artifact_sha)
  if manifest_sha!=record["ownership_manifest_sha256"]: return {**pending,"resources_state":"stale"}
  flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
  rootfd=os.open("/",flags); fds=[rootfd]
  try:
   current=rootfd
   for component in HERMES_HOME.parts[1:]:
    child=os.open(component,flags,dir_fd=current); info=os.fstat(child)
    expected_owner=1000 if component in {"admin",".hermes"} else 0
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=expected_owner or (component in {"admin",".hermes"} and stat.S_IMODE(info.st_mode)!=0o700):
     os.close(child); raise CoreRuntimeError("Hermes home parent custody differs")
    fds.append(child); current=child
   active=hashlib.sha256(_projection_at(current,"SOUL.md",owner=1000,maximum=1024*1024)).hexdigest()
  finally:
   for fd in reversed(fds): os.close(fd)
  bundled=hashlib.sha256(files["registry/profiles/hermes/SOUL.md"]).hexdigest()
  if (active!=record["active_primary_prompt_sha256"] or bundled!=record["bundled_primary_prompt_sha256"]
      or (active==bundled) is not record["active_prompt_matches_bundled_primary"]):
   return {**pending,"resources_state":"stale"}
  counts=record["resource_counts"]
  expected_counts={"native_skills":396,"internal_profiles":207,"source_profiles_preserved":208,
   "other_declarations_preserved":len(manifest["bundled_resource_inventory"])-396-208}
  if (not isinstance(counts,dict) or counts!=expected_counts
      or type(record["active_prompt_matches_bundled_primary"]) is not bool
      or record["resources_revision"]!=manifest["source"]["revision"]
      or record["resources_tree"]!=manifest["source"]["git_tree"]):
   return {**pending,"resources_state":"stale"}
  return {"core_version":COMMIT[:12],"provider":None,"model":None,"account_state":"unknown",
   "resources_state":"discovered","resource_counts":counts,"resources_revision":record["resources_revision"],
   "artifact_sha256":artifact_sha,"discovery_observed_at_utc":record["observed_at_utc"],
   "active_prompt_matches_bundled_primary":record["active_prompt_matches_bundled_primary"]}
 except FileNotFoundError:
  return {**pending,"resources_state":"stale"}
 except Exception:
  return {**pending,"resources_state":"stale"}

def read_current_resources_profile_source(*,core_source_generation):
 """Return the fixed packaged orchestrator prompt only from a current root receipt.

 The returned bytes are an internal root-process value, never a dashboard DTO.
 Its short expiry and verifier force callers to re-read the receipt, CAS, owner
 manifest, and complete installed member closure around any later projection.
 """
 if (os.geteuid()!=ROOT_UID or not isinstance(core_source_generation,str)
     or re.fullmatch(r"[0-9a-f]{64}",core_source_generation) is None):
  return None
 before=read_current_resources_discovery(core_source_generation=core_source_generation)
 if before.get("resources_state")!="discovered": return None
 try:
  record_bytes=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024)
  record=json.loads(record_bytes)
  if (record.get("core_source_generation")!=core_source_generation
      or record.get("artifact_sha256")!=before.get("artifact_sha256")
      or record.get("ownership_manifest_sha256") is None
      or record.get("loaded_skill_inventory_sha256") is None):
   return None
  artifact_sha=record["artifact_sha256"]
  archive=_projection_file(RESOURCES_CAS/(artifact_sha+".zip"),owner=ROOT_UID,
   group=ROOT_UID,mode=0o600,maximum=16*1024*1024)
  if hashlib.sha256(archive).hexdigest()!=artifact_sha: return None
  from .registry import manual_jarvis_skills as native
  manifest,files=native._read_artifact(archive,artifact_sha)
  row=next((item for item in manifest["profile_members"]
            if item.get("source_id")=="orchestrator"),None)
  if not isinstance(row,dict): return None
  prompt=files["registry/profiles/orchestrator/SOUL.md"]
  profile_manifest=files["registry/profiles/orchestrator/profile.yaml"]
  if (not prompt or not profile_manifest or len(prompt)>1024*1024
      or len(profile_manifest)>1024*1024
      or hashlib.sha256(prompt).hexdigest()!=row.get("identity_sha256")
      or hashlib.sha256(profile_manifest).hexdigest()!=row.get("profile_yaml_sha256")):
   return None
  prompt.decode("utf-8")
  profile_manifest.decode("utf-8")
  ownership_sha=_hash_generation_tree(HERMES_HOME,manifest,files,artifact_sha)
  if ownership_sha!=record.get("ownership_manifest_sha256"): return None
  profile_member_manifest=native._canonical_json(row)
  profile_row_sha=hashlib.sha256(profile_member_manifest).hexdigest()
  # Re-read both the durable receipt and full public projection after all
  # archive/member work; no mutable dict from an earlier observation is trusted.
  after_record=_projection_file(RESOURCES_RECORD,owner=ROOT_UID,group=ROOT_UID,
   mode=0o600,maximum=16*1024)
  after=read_current_resources_discovery(core_source_generation=core_source_generation)
  if (after_record!=record_bytes or after!=before
      or hashlib.sha256(_projection_file(RESOURCES_CAS/(artifact_sha+".zip"),
       owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=16*1024*1024)).hexdigest()!=artifact_sha
      or _hash_generation_tree(HERMES_HOME,manifest,files,artifact_sha)!=ownership_sha):
   return None
  return VerifiedResourcesProfileSource(
   schema=1,core_source_generation=core_source_generation,hermes_revision=record["hermes_revision"],
   resources_revision=record["resources_revision"],resources_tree=record["resources_tree"],
   artifact_sha256=artifact_sha,ownership_manifest_sha256=ownership_sha,
   loaded_skill_inventory_sha256=record["loaded_skill_inventory_sha256"],profile_id="orchestrator",
   profile_prompt=bytes(prompt),profile_prompt_sha256=hashlib.sha256(prompt).hexdigest(),
   profile_manifest=bytes(profile_manifest),profile_manifest_sha256=hashlib.sha256(profile_manifest).hexdigest(),
   profile_member_manifest=bytes(profile_member_manifest),profile_member_manifest_sha256=profile_row_sha,
   observed_at_utc=record["observed_at_utc"],
   expires_monotonic=time.monotonic()+5.0,_seal=_RESOURCES_PROFILE_SOURCE_SEAL)
 except Exception:
  return None

def _replace_journal(record):
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): raise CoreRuntimeError("ownership journal disappeared")
 st=JOURNAL.stat()
 if st.st_uid!=ROOT_UID or stat.S_IMODE(st.st_mode)!=0o600: raise CoreRuntimeError("ownership journal permissions changed")
 fd,name=tempfile.mkstemp(prefix=".core-journal-",dir=JOURNAL.parent); tmp=Path(name)
 try:
  os.fchmod(fd,0o600); os.fchown(fd,ROOT_UID,ROOT_UID)
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
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)!=(uid,gid,mode,1): raise CoreRuntimeError("owned service path metadata changed")
  if _digest(path)==expected: return
  if not repair: raise CoreRuntimeError("journal-owned service content changed")
  path.unlink()
  _sync_directory(path.parent)
 _atomic(path,body,mode,uid,gid)
def _validate_adapter_source_path():
 """Only add the root-owned immutable installer generation to core imports."""
 declared=Path(__file__).absolute()
 resolved=Path(__file__).resolve(strict=True)
 if (declared!=resolved or ADAPTER_SOURCE!=resolved.parents[1]
     or ADAPTER_SOURCE.parent.parent!=Path("/opt")
     or not re.fullmatch(r"hermes-installer-core-[0-9a-f]{9,64}",ADAPTER_SOURCE.parent.name)):
  raise CoreRuntimeError("fixed installer adapter generation path differs")
 fd=os.open("/",os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
 try:
  for component in ADAPTER_SOURCE.parts[1:]:
   child=os.open(component,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)
                 |getattr(os,"O_NOFOLLOW",0),dir_fd=fd)
   info=os.fstat(child)
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=ROOT_UID
       or stat.S_IMODE(info.st_mode)&0o022):
    os.close(child); raise CoreRuntimeError("installer adapter generation custody differs")
   os.close(fd); fd=child
  info=os.stat(resolved,follow_symlinks=False)
  if (not stat.S_ISREG(info.st_mode) or info.st_uid!=ROOT_UID or info.st_nlink!=1
      or stat.S_IMODE(info.st_mode)&0o022):
   raise CoreRuntimeError("installer adapter source file custody differs")
 finally:
  os.close(fd)

def _identity(*,verify_python_version=True):
 _validate_adapter_source_path()
 if not SOURCE.is_dir() or SOURCE.is_symlink(): raise CoreRuntimeError("pinned source unavailable")
 # The reviewed generation lives beneath admin's private installer tree. Reject
 # symlinked or differently-owned path components before asking Git to inspect it.
 admin_home=Path("/home/admin")
 if SOURCE!=Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532") or not SOURCE.is_absolute():
  raise CoreRuntimeError("pinned source path differs from reviewed location")
 home_stat=admin_home.lstat()
 if stat.S_ISLNK(home_stat.st_mode) or not stat.S_ISDIR(home_stat.st_mode) or home_stat.st_uid!=1000:
  raise CoreRuntimeError("admin home is not the reviewed real directory")
 current=admin_home
 for part in SOURCE.relative_to(admin_home).parts:
  current=current/part
  try: component_stat=current.lstat()
  except OSError as exc: raise CoreRuntimeError("pinned source parent chain is incomplete") from exc
  if stat.S_ISLNK(component_stat.st_mode) or not stat.S_ISDIR(component_stat.st_mode) or component_stat.st_uid!=1000:
   raise CoreRuntimeError("pinned source parent chain is not admin-owned directories")
 source_stat=SOURCE.lstat()
 git_dir=SOURCE/".git"
 if source_stat.st_uid!=1000 or git_dir.is_symlink() or not git_dir.is_dir() or git_dir.stat().st_uid!=1000:
  raise CoreRuntimeError("pinned source custody differs from the reviewed admin-owned checkout")
 git_prefix=["git","-c","safe.directory="+str(SOURCE),"-C",str(SOURCE)]
 rev=_run([*git_prefix,"rev-parse","HEAD"]).stdout.strip()
 dirty=_run([*git_prefix,"status","--porcelain"]).stdout.strip()
 lock=SOURCE/"pm"/"lock.json"
 if rev!=COMMIT or dirty or not lock.is_file() or _digest(lock)!=LOCK_SHA256: raise CoreRuntimeError("source or PM lock differs from pin")
 if not PYTHON.is_symlink() or os.readlink(PYTHON)!=PYTHON_LINK_TARGET or PYTHON.resolve(strict=True)!=PYTHON_REAL or not PYTHON_REAL.is_file() or PYTHON_REAL.is_symlink(): raise CoreRuntimeError("PM Python link or realpath differs from reviewed pin")
 st=PYTHON_REAL.stat()
 cfg=PYTHON.parent.parent/"pyvenv.cfg"
 if (st.st_uid!=1000 or st.st_gid!=1000 or stat.S_IMODE(st.st_mode)!=0o755 or st.st_nlink!=1
     or _digest(PYTHON_REAL)!=PYTHON_SHA256 or not cfg.is_file() or _digest(cfg)!=PYVENV_CFG_SHA256):
  raise CoreRuntimeError("PM Python executable or venv provenance differs from reviewed pin")
 if verify_python_version:
  _validated_executable(PYTHON,{1000})
  if _run([str(PYTHON),"--version"]).stdout.strip()!="Python 3.14.7": raise CoreRuntimeError("pinned PM Python version mismatch")
 return {"commit":rev,"lock_sha256":LOCK_SHA256,"python_sha256":_digest(PYTHON_REAL),
         "python_link":os.readlink(PYTHON),"python_uid":st.st_uid,"python_gid":st.st_gid,"python_mode":stat.S_IMODE(st.st_mode)}

def _repair_pinned_pm_directory_modes(identity,record):
 """Normalize only the enumerated PM ancestors after proving their payloads."""
 if os.geteuid()!=ROOT_UID or type(identity) is not dict or type(record) is not dict:
  raise CoreRuntimeError("PM directory repair requires the explicit root refresh")
 expected_identity={"commit":COMMIT,"lock_sha256":LOCK_SHA256,"python_sha256":PYTHON_SHA256,
  "python_link":PYTHON_LINK_TARGET,"python_uid":1000,"python_gid":1000,"python_mode":0o755}
 if identity!=expected_identity:
  raise CoreRuntimeError("PM runtime identity differs before directory repair")
 if (_journal()!=record or record.get("state") not in {"installed","active"}
     or any(record.get(field)!=identity[key] for field,key in (
      ("source_commit","commit"),("lock_sha256","lock_sha256"),
      ("python_sha256","python_sha256"),("python_link","python_link"),
      ("python_uid","python_uid"),("python_gid","python_gid"),("python_mode","python_mode")))):
  raise CoreRuntimeError("core ownership journal differs before PM directory repair")
 if (PYTHON!=Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
     or PYTHON_REAL!=Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")
     or PYTHON_LINK_TARGET!="/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3"):
  raise CoreRuntimeError("fixed PM directory repair paths differ")
 flags=os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0)
 rootfd=os.open("/",flags); opened={Path("/"):rootfd}; parents={}
 try:
  for path in sorted(PM_DIRECTORY_MODE_CONTRACT,key=lambda item:len(item.parts)):
   if not path.is_absolute() or path==Path("/"):
    raise CoreRuntimeError("PM directory repair contract is malformed")
   parent=path.parent
   if parent not in opened: raise CoreRuntimeError("PM directory repair parent is not pinned")
   fd=os.open(path.name,flags,dir_fd=opened[parent]); info=os.fstat(fd)
   uid,gid,expected_mode=PM_DIRECTORY_MODE_CONTRACT[path]
   mode=stat.S_IMODE(info.st_mode)
   allowed_modes={expected_mode}
   if expected_mode==0o775: allowed_modes.add(0o755)
   if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=uid or info.st_gid!=gid
       or info.st_nlink<2 or mode not in allowed_modes):
    os.close(fd); raise CoreRuntimeError("pinned PM directory custody differs")
   opened[path]=fd; parents[path]=opened[parent]

  # Re-prove the exact venv link, real executable, and pyvenv.cfg through the
  # held directory descriptors before changing any ancestor metadata.
  link_parent=Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin")
  link_info=os.stat(PYTHON.name,dir_fd=opened[link_parent],follow_symlinks=False)
  if (not stat.S_ISLNK(link_info.st_mode) or link_info.st_uid!=1000 or link_info.st_gid!=1000
      or os.readlink(PYTHON.name,dir_fd=opened[link_parent])!=PYTHON_LINK_TARGET):
   raise CoreRuntimeError("PM Python link differs before directory repair")
  target_parent=Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin")
  binary=os.open(PYTHON_REAL.name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=opened[target_parent])
  try:
   before=os.fstat(binary)
   if (not stat.S_ISREG(before.st_mode) or (before.st_uid,before.st_gid,stat.S_IMODE(before.st_mode),before.st_nlink)
       !=(1000,1000,0o755,1)):
    raise CoreRuntimeError("PM Python executable metadata differs before directory repair")
   digest=hashlib.sha256()
   while True:
    block=os.read(binary,1024*1024)
    if not block: break
    digest.update(block)
   after=os.fstat(binary)
   named=os.stat(PYTHON_REAL.name,dir_fd=opened[target_parent],follow_symlinks=False)
   signature=lambda item:(item.st_dev,item.st_ino,item.st_mode,item.st_uid,item.st_gid,item.st_nlink,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
   if signature(before)!=signature(after) or signature(before)!=signature(named) or digest.hexdigest()!=PYTHON_SHA256:
    raise CoreRuntimeError("PM Python bytes changed before directory repair")
  finally: os.close(binary)
  venv=Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv")
  cfg=os.open("pyvenv.cfg",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_CLOEXEC",0),dir_fd=opened[venv])
  try:
   before=os.fstat(cfg)
   if not stat.S_ISREG(before.st_mode) or before.st_uid!=1000 or before.st_nlink!=1 or before.st_size>65536:
    raise CoreRuntimeError("PM venv provenance metadata differs before directory repair")
   body=bytearray()
   while len(body)<=65536:
    block=os.read(cfg,65537-len(body))
    if not block: break
    body.extend(block)
   after=os.fstat(cfg); named=os.stat("pyvenv.cfg",dir_fd=opened[venv],follow_symlinks=False)
   if (len(body)!=before.st_size or hashlib.sha256(body).hexdigest()!=PYVENV_CFG_SHA256
       or (before.st_dev,before.st_ino,before.st_mode,before.st_size,before.st_mtime_ns,before.st_ctime_ns)
        !=(after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)
       or (before.st_dev,before.st_ino,before.st_mode,before.st_size)
        !=(named.st_dev,named.st_ino,named.st_mode,named.st_size)):
    raise CoreRuntimeError("PM venv provenance changed before directory repair")
  finally: os.close(cfg)

  _repair_verified_pm_directory_fds(opened,parents,PM_DIRECTORY_MODE_CONTRACT)
 finally:
  for fd in reversed(list(opened.values())):
   try: os.close(fd)
   except OSError: pass
 # Strictly recheck the original source/runtime identity and executable chain.
 if _identity()!=identity: raise CoreRuntimeError("PM identity changed after directory repair")
 _validated_executable(PYTHON,{1000})

def _repair_verified_pm_directory_fds(opened,parents,contract):
 """Apply the exact 0775-to-0755 normalization to preverified held directory FDs."""
 if os.geteuid()!=ROOT_UID or type(contract) is not dict:
  raise CoreRuntimeError("PM directory metadata repair is not authorized")
 pending=[]
 for path,(_uid,_gid,expected_mode) in contract.items():
  if expected_mode!=0o775: continue
  fd=opened[path]; info=os.fstat(fd); mode=stat.S_IMODE(info.st_mode)
  if mode==0o755: continue
  parent=parents[path]
  named=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if (mode!=0o775 or (named.st_dev,named.st_ino,named.st_uid,named.st_gid,named.st_mode)
      !=(info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode)):
   raise CoreRuntimeError("PM directory changed during metadata repair")
  pending.append(fd)
 for fd in pending:
  os.fchmod(fd,0o755)
  if stat.S_IMODE(os.fstat(fd).st_mode)!=0o755:
   raise CoreRuntimeError("PM directory metadata repair failed")
def _launcher():
 pythonpath=shlex.quote(f"{SOURCE}:{ADAPTER_SOURCE}")
 return f"""#!/bin/sh
set -eu
cred="$CREDENTIALS_DIRECTORY/hermes-session-token"
test -f "$cred" && test ! -L "$cred"
IFS= read -r HERMES_DASHBOARD_SESSION_TOKEN < "$cred"
test -n "$HERMES_DASHBOARD_SESSION_TOKEN"
export HERMES_DASHBOARD_SESSION_TOKEN
unset PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP VIRTUAL_ENV
export HOME=/home/admin HERMES_HOME=/home/admin/.hermes
export PATH=/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin
export HERMES_DISABLE_LAZY_INSTALLS=1
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH={pythonpath}
cd /home/admin/.hermes/workspaces/jarvis-core
exec /home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python -P -m hermes_cli.main serve --isolated --host 127.0.0.1 --port 8766
""".encode("ascii")
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
Environment=PYTHONNOUSERSITE=1
Environment=PYTHONDONTWRITEBYTECODE=1
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
 if st.st_uid!=ROOT_UID or stat.S_IMODE(st.st_mode)!=0o600: raise CoreRuntimeError("core journal permissions unsafe")
 try: d=json.loads(JOURNAL.read_text())
 except (OSError,ValueError) as e: raise CoreRuntimeError("core journal invalid") from e
 if d.get("schema")!=1 or d.get("service")!=SERVICE or d.get("state") not in {"preparing","installed","active","retiring"}: raise CoreRuntimeError("core journal identity unsupported")
 if d["state"] in {"installed","active","retiring"}:
  for p,k,uid,gid,mode in FILE_CONTRACT:
   if not p.exists() and not p.is_symlink() and d["state"]=="retiring": continue
   if not p.is_file() or p.is_symlink(): raise CoreRuntimeError("owned service file changed")
   ps=p.stat()
   if (ps.st_uid,ps.st_gid,stat.S_IMODE(ps.st_mode),ps.st_nlink)!=(uid,gid,mode,1): raise CoreRuntimeError("owned service file metadata changed")
   if not (d["state"]=="retiring" and d.get("cleanup_allow_partial")) and _digest(p)!=d.get(k):
    raise CoreRuntimeError("owned service file changed")
  if d.get("adapter_migration_state") == "preparing":
   raise CoreRuntimeError("adapter source migration recovery is required")
  if d.get("adapter_migration_state") == "active":
   if (d.get("adapter_source")!=str(ADAPTER_SOURCE)
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("adapter_generation","")))
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("core_source_generation","")))
       or not re.fullmatch(r"[0-9a-f]{64}",str(d.get("plugin_selection_sha256","")))):
    raise CoreRuntimeError("adapter migration custody record is incomplete")
  if d["state"]!="retiring" and (hashlib.sha256(_unit()).hexdigest()!=d["unit_sha256"] or hashlib.sha256(_launcher()).hexdigest()!=d["launcher_sha256"]):
   raise CoreRuntimeError("owned service recipe differs from the reviewed source")
 return d
def status():
 try: d=_journal()
 except CoreRuntimeError as e: return "pending: "+str(e)
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 if active!="active" or not _owned_listener():
  return f"pending: owned unit is {active or 'unknown'} or its process-bound loopback listener is unproven"
 return f"owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766; authenticated chat and restart proof pending; source {d['source_commit']}"

def _owned_listener(*,legacy_launcher=False):
 """Require systemd MainPID, expected argv/cgroup/UID, and its bound socket inode."""
 try:
  pid_text=_run(["systemctl","show","--property=MainPID","--value",SERVICE]).stdout.strip()
  pid=int(pid_text)
  if pid<=1: return False
  proc=Path("/proc")/str(pid)
  if int(proc.stat().st_uid)!=1000: return False
  status_fields={line.split(":",1)[0]:line.split(":",1)[1].split()
                 for line in (proc/"status").read_text().splitlines() if ":" in line}
  if status_fields.get("Uid")!=["1000"]*4 or status_fields.get("Gid")!=["1000"]*4:
   return False
  if Path(os.readlink(proc/"exe")).resolve(strict=True)!=PYTHON_REAL: return False
  if Path(os.readlink(proc/"cwd")).resolve(strict=True)!=WORKSPACE.resolve(strict=True): return False
  argv=(proc/"cmdline").read_bytes().decode(errors="replace").split("\0")
  if argv[-1]=="": argv.pop()
  expected=[str(PYTHON),*([] if legacy_launcher else ["-P"]),"-m","hermes_cli.main","serve","--isolated","--host","127.0.0.1","--port","8766"]
  if argv!=expected: return False
  environment=(proc/"environ").read_bytes().split(b"\0")
  pythonpaths=[item[len(b"PYTHONPATH="):] for item in environment if item.startswith(b"PYTHONPATH=")]
  expected_path=str(SOURCE if legacy_launcher else Path(f"{SOURCE}:{ADAPTER_SOURCE}")).encode("ascii")
  if pythonpaths!=[expected_path]: return False
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

def _legacy_launcher():
 """Exact pre-adapter launcher eligible for the one-time journaled migration."""
 return b"""#!/bin/sh
set -eu
cred="$CREDENTIALS_DIRECTORY/hermes-session-token"
test -f "$cred" && test ! -L "$cred"
IFS= read -r HERMES_DASHBOARD_SESSION_TOKEN < "$cred"
test -n "$HERMES_DASHBOARD_SESSION_TOKEN"
export HERMES_DASHBOARD_SESSION_TOKEN
unset PYTHONHOME PYTHONUSERBASE PYTHONSTARTUP VIRTUAL_ENV
export HOME=/home/admin HERMES_HOME=/home/admin/.hermes
export PATH=/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin
export HERMES_DISABLE_LAZY_INSTALLS=1
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH=/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532
cd /home/admin/.hermes/workspaces/jarvis-core
exec /home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python -m hermes_cli.main serve --isolated --host 127.0.0.1 --port 8766
"""

def _read_legacy_owned_runtime():
 """Read back the complete fixed old journal/file/credential set without mutation."""
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): raise CoreRuntimeError("legacy core journal unavailable")
 raw_journal=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 try: record=json.loads(raw_journal)
 except (ValueError,TypeError): raise CoreRuntimeError("legacy core journal invalid") from None
 if (type(record) is not dict or record.get("schema")!=1 or record.get("service")!=SERVICE
     or record.get("state") not in {"installed","active"} or record.get("port")!=8766
     or record.get("host")!="127.0.0.1"):
  raise CoreRuntimeError("legacy core journal identity unsupported")
 identity=_identity()
 for key,source_key in (("source_commit","commit"),("lock_sha256","lock_sha256"),
                        ("python_sha256","python_sha256"),("python_link","python_link"),
                        ("python_uid","python_uid"),("python_gid","python_gid"),
                        ("python_mode","python_mode")):
  if record.get(key)!=identity.get(source_key):
   raise CoreRuntimeError("legacy core runtime identity changed")
 files={}
 for path,key,uid,gid,mode in FILE_CONTRACT:
  content=_projection_file(path,owner=uid,group=gid,mode=mode,maximum=256*1024)
  if record.get(key)!=hashlib.sha256(content).hexdigest():
   raise CoreRuntimeError("legacy journal-owned file or credential changed")
  files[path]=content
 if files[UNIT]!=_unit():
  raise CoreRuntimeError("legacy service unit differs from the fixed owned unit")
 if files[LAUNCHER]!=_legacy_launcher():
  raise CoreRuntimeError("legacy launcher differs from the fixed prior recipe")
 token=files[TOKEN]
 if (len(token)!=65 or not token.endswith(b"\n")
     or any(char not in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for char in token[:-1])):
  raise CoreRuntimeError("legacy service credential content is invalid")
 if not _owned_unit_loaded():
  raise CoreRuntimeError("service name is not bound to the journal-owned unit")
 if _run(["systemctl","is-active",SERVICE],False).stdout.strip()!="active" or not _owned_listener(legacy_launcher=True):
  raise CoreRuntimeError("legacy owned core listener is not current")
 return record,raw_journal,files

def _owned_unit_loaded():
 """Reject aliases and drop-ins that could change the journal-owned unit behavior."""
 fragment=_run(["systemctl","show","--property=FragmentPath","--value",SERVICE],False).stdout.strip()
 dropins=_run(["systemctl","show","--property=DropInPaths","--value",SERVICE],False).stdout.strip()
 return fragment==str(UNIT) and not dropins

def _save_adapter_migration_backup(raw_journal,files,plugin_selection_json):
 """Keep immutable rollback bytes under root-only custody before any mutation."""
 _ensure_dir(ADAPTER_MIGRATION_BACKUP,ROOT_UID,ROOT_UID,0o700)
 if not isinstance(plugin_selection_json,bytes) or not 1<=len(plugin_selection_json)<=32*1024:
  raise CoreRuntimeError("prior plugin selection snapshot is unavailable")
 names={"journal.json":raw_journal,"unit":files[UNIT],"launcher":files[LAUNCHER],
        "plugin-selection.json":plugin_selection_json}
 manifest={name:hashlib.sha256(content).hexdigest() for name,content in names.items()}
 manifest_bytes=(json.dumps(manifest,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
 allowed=set(names)|{"manifest.json"}
 if not set(os.listdir(ADAPTER_MIGRATION_BACKUP))<=allowed:
  raise CoreRuntimeError("adapter migration backup contains unowned entries")
 for name,content in names.items():
  path=ADAPTER_MIGRATION_BACKUP/name
  if path.exists() or path.is_symlink():
   existing=_projection_file(path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=256*1024)
   if existing!=content: raise CoreRuntimeError("prior adapter migration backup differs")
  else: _atomic(path,content,0o600,ROOT_UID,ROOT_UID)
 manifest_path=ADAPTER_MIGRATION_BACKUP/"manifest.json"
 if manifest_path.exists() or manifest_path.is_symlink():
  if _projection_file(manifest_path,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=4096)!=manifest_bytes:
   raise CoreRuntimeError("prior adapter migration backup manifest differs")
 else: _atomic(manifest_path,manifest_bytes,0o600,ROOT_UID,ROOT_UID)
 return manifest

def _restore_adapter_migration_backup():
 """Restore only the three exact root-journal-owned prior bytes."""
 directory=ADAPTER_MIGRATION_BACKUP.lstat()
 if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=ROOT_UID
     or directory.st_gid!=ROOT_UID or stat.S_IMODE(directory.st_mode)!=0o700):
  raise CoreRuntimeError("adapter migration backup custody differs")
 if set(os.listdir(ADAPTER_MIGRATION_BACKUP))!={"journal.json","unit","launcher","plugin-selection.json","manifest.json"}:
  raise CoreRuntimeError("adapter migration backup is incomplete")
 manifest_raw=_projection_file(ADAPTER_MIGRATION_BACKUP/"manifest.json",owner=ROOT_UID,
                               group=ROOT_UID,mode=0o600,maximum=4096)
 try: manifest=json.loads(manifest_raw)
 except (ValueError,TypeError): raise CoreRuntimeError("adapter migration backup manifest invalid") from None
 if type(manifest) is not dict or set(manifest)!={"journal.json","unit","launcher","plugin-selection.json"}:
  raise CoreRuntimeError("adapter migration backup manifest invalid")
 paths={"journal.json":JOURNAL,"unit":UNIT,"launcher":LAUNCHER,
        "plugin-selection.json":ADAPTER_MIGRATION_BACKUP/"plugin-selection.json"}
 contents={}
 for name,path in paths.items():
  data=_projection_file(ADAPTER_MIGRATION_BACKUP/name,owner=ROOT_UID,group=ROOT_UID,
                        mode=0o600,maximum=256*1024)
  if manifest.get(name)!=hashlib.sha256(data).hexdigest():
   raise CoreRuntimeError("adapter migration backup bytes changed")
  contents[name]=data
 for name,path in (("unit",UNIT),("launcher",LAUNCHER)):
  mode=0o644 if path==UNIT else 0o755
  _atomic_replace(path,contents[name],mode,ROOT_UID,ROOT_UID)
 _atomic_replace(JOURNAL,contents["journal.json"],0o600,ROOT_UID,ROOT_UID)
 return contents["journal.json"]

def _restore_migration_plugin_selection(record):
 try:
  directory=ADAPTER_MIGRATION_BACKUP.lstat()
  if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=ROOT_UID
      or directory.st_gid!=ROOT_UID or stat.S_IMODE(directory.st_mode)!=0o700):
   raise CoreRuntimeError("adapter migration backup custody differs")
  if set(os.listdir(ADAPTER_MIGRATION_BACKUP))!={"journal.json","unit","launcher","plugin-selection.json","manifest.json"}:
   raise CoreRuntimeError("adapter migration backup has unexpected entries")
  manifest_raw=_projection_file(ADAPTER_MIGRATION_BACKUP/"manifest.json",owner=ROOT_UID,
                                group=ROOT_UID,mode=0o600,maximum=4096)
  manifest=json.loads(manifest_raw)
  if (type(manifest) is not dict or manifest!=record.get("adapter_migration_backup")
      or set(manifest)!={"journal.json","unit","launcher","plugin-selection.json"}):
   raise CoreRuntimeError("adapter migration backup manifest is not journal-bound")
  for name in manifest:
   data=_projection_file(ADAPTER_MIGRATION_BACKUP/name,owner=ROOT_UID,group=ROOT_UID,
                        mode=0o600,maximum=256*1024)
   if hashlib.sha256(data).hexdigest()!=manifest[name]:
    raise CoreRuntimeError("journaled adapter migration backup bytes changed")
  snapshot=_projection_file(ADAPTER_MIGRATION_BACKUP/"plugin-selection.json",owner=ROOT_UID,
                            group=ROOT_UID,mode=0o600,maximum=32*1024)
  if hashlib.sha256(snapshot).hexdigest()!=manifest["plugin-selection.json"]:
   raise CoreRuntimeError("journaled plugin selection bytes changed")
  from hermes_installer.remote.native_plugin_bootstrap import restore_native_resources_plugin_selection
  restored=restore_native_resources_plugin_selection(
   snapshot,expected_current_sha256=record.get("plugin_selection_sha256"))
  if not re.fullmatch(r"[0-9a-f]{64}",str(restored or "")):
   raise CoreRuntimeError("prior plugin selection receipt is malformed")
 except Exception:
  raise CoreRuntimeError("journaled plugin selection could not be restored exactly") from None

def _recover_interrupted_adapter_migration():
 """Undo an interrupted file switch before ordinary journal validation resumes."""
 if not JOURNAL.is_file() or JOURNAL.is_symlink(): return
 raw=_projection_file(JOURNAL,owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=64*1024)
 try: record=json.loads(raw)
 except (ValueError,TypeError): return
 if type(record) is not dict or record.get("adapter_migration_state")!="preparing": return
 _restore_migration_plugin_selection(record)
 _restore_adapter_migration_backup()
 _run(["systemctl","daemon-reload"])
 if not _owned_unit_loaded(): raise CoreRuntimeError("service unit changed during interrupted migration")
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 if active=="active":
  if _owned_listener(legacy_launcher=True): return
  if not _owned_listener():
   raise CoreRuntimeError("interrupted migration left an unrecognized core process active")
  _run(["systemctl","restart",SERVICE])
  if not _owned_listener(legacy_launcher=True):
   raise CoreRuntimeError("prior owned core did not recover from interrupted migration")

def migrate_owned_core_to_adapter_path():
 """Journaled one-time adoption of the exact active pre-adapter core service."""
 if os.geteuid()!=ROOT_UID or not Path("/proc").is_dir():
  raise CoreRuntimeError("requires installed Linux root actor")
 _validate_adapter_source_path()
 _recover_interrupted_adapter_migration()
 current=_core_source_generation()
 record,raw_journal,files=_read_legacy_owned_runtime()
 try:
  from hermes_installer.remote.native_plugin_bootstrap import capture_native_resources_plugin_selection
  selection_backup=capture_native_resources_plugin_selection()
  if (getattr(selection_backup,"plugin_key",None) not in (None,"hermes-installer-resources-delegation")
      or not re.fullmatch(r"[0-9a-f]{64}",str(getattr(selection_backup,"prior_selection_sha256", "")))
      or not re.fullmatch(r"[0-9a-f]{64}",str(getattr(selection_backup,"migrated_selection_sha256", "")))):
   raise CoreRuntimeError("prior plugin selection snapshot is not verified")
  backup_manifest=_save_adapter_migration_backup(
   raw_journal,files,selection_backup.snapshot_json)
 except CoreRuntimeError:
  raise
 except Exception:
  raise CoreRuntimeError("prior plugin selection could not be journaled; migration was not started") from None
 marker={**record,"adapter_migration_state":"preparing",
         "adapter_migration_backup":backup_manifest,
         "adapter_source":str(ADAPTER_SOURCE),"core_source_generation":current,
         "plugin_selection_sha256":selection_backup.migrated_selection_sha256}
 _replace_journal(marker)
 marker_raw=(json.dumps(marker,sort_keys=True)+"\n").encode()
 # The bridge transaction stages immutable code and uses Hermes' official enable
 # API. It must succeed before this service's journaled files or process change.
 try:
  from hermes_installer.remote.native_plugin_bootstrap import (
   enable_native_resources_plugin,verify_native_resources_plugin_selection,
  )
  staged=enable_native_resources_plugin()
  if getattr(staged,"plugin_key",None)!="hermes-installer-resources-delegation":
   raise CoreRuntimeError("native bridge activation did not verify the fixed plugin")
  selection=verify_native_resources_plugin_selection()
  selection_digest=getattr(selection,"selection_sha256",None)
  if (getattr(selection,"plugin_key",None)!="hermes-installer-resources-delegation"
      or not re.fullmatch(r"[0-9a-f]{64}",str(selection_digest or ""))):
   raise CoreRuntimeError("native plugin selection is not currently verified")
  from hermes_installer.remote.core_gateway_inspector import (
   _current_native_adapter_generation,verify_staged_native_resources_plugin,
  )
  deadline=time.monotonic()+35.0
  adapter_generation=_current_native_adapter_generation(deadline=deadline)
  staged_digest=verify_staged_native_resources_plugin(deadline=deadline)
  if not adapter_generation or not staged_digest:
   raise CoreRuntimeError("native bridge activation is not current")
 except CoreRuntimeError:
  try:
   _restore_migration_plugin_selection(marker)
   _restore_adapter_migration_backup()
  except Exception:
   raise CoreRuntimeError("adapter activation failed; protected migration backup retained") from None
  raise
 except Exception:
  try:
   _restore_migration_plugin_selection(marker)
   _restore_adapter_migration_backup()
  except Exception:
   raise CoreRuntimeError("adapter activation failed; protected migration backup retained") from None
  raise CoreRuntimeError("native bridge activation is unavailable; existing core remains active") from None
 # Activation runs a separate fixed PM interpreter. Rejoin the complete old
 # unit, launcher, credential, journal and listener before changing any of them.
 rechecked,raw_rechecked,files_rechecked=_read_legacy_owned_runtime()
 if (raw_rechecked!=marker_raw or rechecked!=marker
     or files_rechecked!=files):
  raise CoreRuntimeError("journal-owned core changed during native bridge activation")
 marker={**marker,"adapter_generation":adapter_generation,
         "plugin_selection_sha256":selection_digest}
 _replace_journal(marker)
 restart_attempted=False
 try:
  new_launcher,new_unit=_launcher(),_unit()
  _atomic_replace(LAUNCHER,new_launcher,0o755,ROOT_UID,ROOT_UID)
  _atomic_replace(UNIT,new_unit,0o644,ROOT_UID,ROOT_UID)
  updated={**record,"unit_sha256":hashlib.sha256(new_unit).hexdigest(),
           "launcher_sha256":hashlib.sha256(new_launcher).hexdigest(),
           "adapter_source":str(ADAPTER_SOURCE),"adapter_generation":adapter_generation,
           "adapter_migration_state":"active","adapter_migration_backup":backup_manifest,
           "core_source_generation":current,"plugin_selection_sha256":selection_digest}
  _replace_journal(updated)
  _run(["systemctl","daemon-reload"])
  if not _owned_unit_loaded():
   raise CoreRuntimeError("service unit ownership changed before restart")
  restart_attempted=True
  _run(["systemctl","restart",SERVICE])
  _wait_for_listener()
  deadline=time.monotonic()+35.0
  if (not _owned_listener()
      or _current_native_adapter_generation(deadline=deadline)!=adapter_generation
      or verify_staged_native_resources_plugin(deadline=deadline)!=staged_digest
      or getattr(verify_native_resources_plugin_selection(),"selection_sha256",None)!=selection_digest
      or _core_source_generation()!=current):
   raise CoreRuntimeError("adapter core post-restart custody is not current")
  final=_journal()
  if (final.get("adapter_generation")!=adapter_generation
      or final.get("adapter_source")!=str(ADAPTER_SOURCE)):
   raise CoreRuntimeError("adapter core journal proof differs after restart")
  return "journal-owned Hermes core migrated to the immutable installer adapter generation and verified active"
 except Exception as exc:
  try:
   active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
   if not _owned_unit_loaded(): raise CoreRuntimeError("service unit changed during migration rollback")
   if active=="active" and not (_owned_listener() or _owned_listener(legacy_launcher=True)):
    raise CoreRuntimeError("service process is no longer the journal-owned core")
   _restore_migration_plugin_selection(marker)
   _restore_adapter_migration_backup()
   _run(["systemctl","daemon-reload"])
   if active=="active" or restart_attempted:
    _run(["systemctl","restart",SERVICE])
    if not _owned_listener(legacy_launcher=True):
     raise CoreRuntimeError("prior owned core did not recover after migration rollback")
  except Exception:
   raise CoreRuntimeError("adapter migration failed; protected backup retained for fixed recovery") from None
  if isinstance(exc,CoreRuntimeError): raise
  raise CoreRuntimeError("adapter migration failed; original core service files and journal were restored") from None

def recover_owned_core_from_adapter_migration():
 """Restore the exact prior owned core cohort after a later BFF startup failure.

 This is intentionally narrower than installer rollback: it only accepts the
 exact active adapter migration and its immutable root backup, then restores
 that prior core and plugin selection. Any identity drift leaves ingress down.
 """
 if os.geteuid()!=ROOT_UID or not Path("/proc").is_dir():
  raise CoreRuntimeError("requires installed Linux root actor")
 record=_journal()
 if (record.get("state")!="active" or record.get("adapter_migration_state")!="active"
     or record.get("adapter_source")!=str(ADAPTER_SOURCE)
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("adapter_generation","")))
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("core_source_generation","")))
     or not re.fullmatch(r"[0-9a-f]{64}",str(record.get("plugin_selection_sha256","")))):
  raise CoreRuntimeError("no exact active adapter migration is eligible for recovery")
 if (not _owned_unit_loaded() or not _owned_listener()
     or _core_source_generation()!=record["core_source_generation"]):
  raise CoreRuntimeError("current migrated core identity is not verified; ingress remains stopped")
 try:
  from hermes_installer.remote.core_gateway_inspector import (
   _current_native_adapter_generation,verify_staged_native_resources_plugin,
  )
  from hermes_installer.remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
  deadline=time.monotonic()+35.0
  if (_current_native_adapter_generation(deadline=deadline)!=record["adapter_generation"]
      or not verify_staged_native_resources_plugin(deadline=deadline)
      or getattr(verify_native_resources_plugin_selection(),"selection_sha256",None)
         !=record["plugin_selection_sha256"]):
   raise CoreRuntimeError("current adapter generation or selected plugin changed")
 except CoreRuntimeError:
  raise
 except Exception:
  raise CoreRuntimeError("current migration custody could not be reverified") from None
 # Validate every immutable backup byte and manifest before stopping the only
 # owned service. No general rollback/retirement path is involved.
 directory=ADAPTER_MIGRATION_BACKUP.lstat()
 if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid!=ROOT_UID
     or directory.st_gid!=ROOT_UID or stat.S_IMODE(directory.st_mode)!=0o700):
  raise CoreRuntimeError("adapter migration backup custody differs")
 if set(os.listdir(ADAPTER_MIGRATION_BACKUP))!={"journal.json","unit","launcher","plugin-selection.json","manifest.json"}:
  raise CoreRuntimeError("adapter migration backup has unexpected entries")
 manifest_raw=_projection_file(ADAPTER_MIGRATION_BACKUP/"manifest.json",owner=ROOT_UID,
                               group=ROOT_UID,mode=0o600,maximum=4096)
 try: manifest=json.loads(manifest_raw)
 except (ValueError,TypeError): raise CoreRuntimeError("adapter migration backup manifest invalid") from None
 if (type(manifest) is not dict or manifest!=record.get("adapter_migration_backup")
     or set(manifest)!={"journal.json","unit","launcher","plugin-selection.json"}):
  raise CoreRuntimeError("active journal does not bind the exact migration backup")
 # Validate backup files without replacing anything, including the previous
 # journal's identity and full legacy recipe. _read_legacy_owned_runtime is
 # intentionally called only after its old listener has restarted.
 backup_journal=_projection_file(ADAPTER_MIGRATION_BACKUP/"journal.json",owner=ROOT_UID,
                                  group=ROOT_UID,mode=0o600,maximum=256*1024)
 backup_unit=_projection_file(ADAPTER_MIGRATION_BACKUP/"unit",owner=ROOT_UID,
                               group=ROOT_UID,mode=0o600,maximum=256*1024)
 backup_launcher=_projection_file(ADAPTER_MIGRATION_BACKUP/"launcher",owner=ROOT_UID,
                                  group=ROOT_UID,mode=0o600,maximum=256*1024)
 if (hashlib.sha256(backup_journal).hexdigest()!=manifest["journal.json"]
     or hashlib.sha256(backup_unit).hexdigest()!=manifest["unit"]
     or hashlib.sha256(backup_launcher).hexdigest()!=manifest["launcher"]
     or backup_unit!=_unit() or backup_launcher!=_legacy_launcher()):
  raise CoreRuntimeError("prior owned core backup is not the exact reviewed legacy cohort")
 try:
  previous=json.loads(backup_journal)
 except (ValueError,TypeError): raise CoreRuntimeError("prior core journal backup is invalid") from None
 if (type(previous) is not dict or previous.get("schema")!=1
     or previous.get("service")!=SERVICE or previous.get("state")!="active"
     or previous.get("launcher_sha256")!=hashlib.sha256(backup_launcher).hexdigest()
     or previous.get("unit_sha256")!=hashlib.sha256(backup_unit).hexdigest()):
  raise CoreRuntimeError("prior core journal does not bind the legacy cohort")
 selection_snapshot=_projection_file(ADAPTER_MIGRATION_BACKUP/"plugin-selection.json",
                                     owner=ROOT_UID,group=ROOT_UID,mode=0o600,maximum=32*1024)
 if hashlib.sha256(selection_snapshot).hexdigest()!=manifest["plugin-selection.json"]:
  raise CoreRuntimeError("prior plugin selection backup bytes changed")
 if (not _owned_unit_loaded() or not _owned_listener()
     or _core_source_generation()!=record["core_source_generation"]):
  raise CoreRuntimeError("migrated core changed during recovery preflight")
 _run(["systemctl","stop",SERVICE])
 if (_run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active"
     or _run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip() not in {"","0"}
     or _owned_listener()):
  raise CoreRuntimeError("owned adapter core did not stop cleanly; recovery halted")
 try:
  from hermes_installer.remote.native_plugin_bootstrap import restore_native_resources_plugin_selection
  restored_selection=restore_native_resources_plugin_selection(
   selection_snapshot,expected_current_sha256=record["plugin_selection_sha256"])
  _restore_adapter_migration_backup()
  _run(["systemctl","daemon-reload"])
  if not _owned_unit_loaded():
   raise CoreRuntimeError("restored prior service unit is not the exact owned unit")
  _run(["systemctl","start",SERVICE])
  restored_record,restored_raw,restored_files=_read_legacy_owned_runtime()
  if (restored_record!=previous or restored_raw!=backup_journal
      or restored_files[UNIT]!=backup_unit or restored_files[LAUNCHER]!=backup_launcher):
   raise CoreRuntimeError("restored legacy core cohort differs from its retained backup")
  selection=verify_native_resources_plugin_selection()
  if getattr(selection,"selection_sha256",None)!=restored_selection:
   raise CoreRuntimeError("prior Hermes plugin selection is not current after recovery")
 except Exception:
  # A partial recovery is deliberately left stopped; only an operator can
  # inspect/reconcile the retained journal and backup after this point.
  try:
   if _owned_unit_loaded() and _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active":
    _run(["systemctl","stop",SERVICE])
  except Exception:
   pass
  raise CoreRuntimeError("bounded migration recovery failed; protected backup retained and ingress remains stopped") from None
 return "exact prior Hermes core and plugin selection restored; gateway/BFF may be resumed"

def install_or_resume():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 identity=_identity(); account=pwd.getpwnam("admin")
 if account.pw_uid!=1000 or account.pw_dir!="/home/admin": raise CoreRuntimeError("admin identity mismatch")
 try: gid=grp.getgrgid(GATEWAY_GID).gr_gid
 except KeyError as e: raise CoreRuntimeError("gateway credential group 981 unavailable") from e
 _ensure_dir(ETC_INSTALLER,ROOT_UID,ROOT_UID,0o755)
 _ensure_dir(TOKEN.parent,ROOT_UID,gid,0o750)
 _ensure_dir(LIBEXEC_DIR,ROOT_UID,ROOT_UID,0o755)
 _ensure_dir(SYSTEMD_UNIT_DIR,ROOT_UID,ROOT_UID,0o755)
 _ensure_dir(VAR_LIB_INSTALLER,ROOT_UID,ROOT_UID,0o700)
 _ensure_dir(JOURNAL.parent,ROOT_UID,ROOT_UID,0o700)
 launcher,unit=_launcher(),_unit()
 if JOURNAL.exists() or JOURNAL.is_symlink():
  try:
   record=_journal()
  except CoreRuntimeError:
   return migrate_owned_core_to_adapter_path()
  if record["state"]=="retiring":
   raise CoreRuntimeError("core service retirement is in progress; use the fixed rollback action")
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
  _atomic(JOURNAL,(json.dumps(record,sort_keys=True)+"\n").encode(),0o600,ROOT_UID,ROOT_UID)
 if record["state"]=="preparing":
  token_valid=False
  if TOKEN.exists() or TOKEN.is_symlink():
   if TOKEN.is_symlink() or not TOKEN.is_file(): raise CoreRuntimeError("interrupted credential has unsafe type")
   ts=TOKEN.stat(); raw=TOKEN.read_bytes()
   if (ts.st_uid,ts.st_gid,stat.S_IMODE(ts.st_mode),ts.st_nlink)!=(0,gid,0o640,1):
    raise CoreRuntimeError("interrupted credential owner or mode changed")
   token_valid=(len(raw)==65 and raw.endswith(b"\n") and
                all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in raw[:-1]))
   if token_valid and record.get("token_sha256") is not None:
    token_valid=_digest(TOKEN)==record["token_sha256"]
   if not token_valid:
    TOKEN.unlink()
    _sync_directory(TOKEN.parent)
  if not token_valid:
   raw=(secrets.token_urlsafe(48)+"\n").encode()
   _atomic(TOKEN,raw,0o640,ROOT_UID,gid)
  if record.get("token_sha256")!=_digest(TOKEN):
   record["token_sha256"]=_digest(TOKEN)
   _replace_journal(record)
 _ensure_workspace(account.pw_uid,account.pw_gid)
 _install_bundled_resources(account)
 _owned_file(LAUNCHER,launcher,0o755,ROOT_UID,ROOT_UID,record["launcher_sha256"],record["state"]=="preparing")
 _owned_file(UNIT,unit,0o644,ROOT_UID,ROOT_UID,record["unit_sha256"],record["state"]=="preparing")
 if record["state"]=="preparing":
  record["state"]="installed"
  _replace_journal(record)
 _journal()
 resources=_write_resources_discovery()
 _run(["systemctl","daemon-reload"]); _run(["systemctl","enable","--now",SERVICE]); _wait_for_listener()
 counts=resources["resource_counts"]
 prompt_status=("the active Jarvis prompt matches the bundled primary prompt"
                if resources["active_prompt_matches_bundled_primary"]
                else "active prompt integration remains pending")
 return (status()+f"; packaged Resources materialized and Hermes-read-back discovered "
         f"{counts['native_skills']} skills with {counts['source_profiles_preserved']} source profiles preserved; "
         f"{prompt_status}; functional use remains unverified")

def _wait_for_listener():
 deadline=time.monotonic()+30
 while time.monotonic()<deadline:
  if _owned_listener(): return
  time.sleep(1)
 raise CoreRuntimeError("owned service did not prove its isolated loopback listener within 30 seconds")

def refresh_resources_discovery():
 """Refresh only the root discovery receipt for an already-running owned core."""
 if os.geteuid()!=ROOT_UID or not Path("/proc").is_dir():
  raise CoreRuntimeError("requires installed Linux root actor")
 # Do not execute the PM interpreter until the known umask-created writable
 # ancestors have been proven and normalized below. This first identity pass
 # checks only the pinned source, link, executable bytes, and venv provenance.
 identity=_identity(verify_python_version=False)
 record=_journal()
 if (record.get("state") not in {"installed","active"}
     or record.get("source_commit")!=identity["commit"]):
  raise CoreRuntimeError("journal-owned core is not in a refreshable installed state")
 _repair_pinned_pm_directory_modes(identity,record)
 if not status().startswith("owned isolated service and process-bound loopback listener verified at 127.0.0.1:8766;"):
  raise CoreRuntimeError("owned core must already be active before receipt refresh")
 # This explicit root operator action is the only path allowed to repair the
 # original importer's known umask-created 0775 nested directories. Ordinary
 # discovery/profile reads remain strict and read-only.
 projection=_write_resources_discovery(repair_umask_dirs=True)
 counts=projection["resource_counts"]
 return (f"root native discovery refreshed for the existing owned 127.0.0.1:8766 core; "
         f"{counts['native_skills']} skills read back; service lifecycle unchanged; "
         "functional use remains unverified")

def rollback():
 if os.geteuid()!=0 or not Path("/proc").is_dir(): raise CoreRuntimeError("requires installed Linux root actor")
 record=_journal()
 if record["state"]!="retiring":
  if record["state"]=="preparing":
   record["cleanup_allow_partial"]=True
  else:
   fragment=_run(["systemctl","show","--property=FragmentPath","--value",SERVICE],False).stdout.strip()
   active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
   if fragment and Path(fragment)!=UNIT:
    raise CoreRuntimeError("service name resolves to a different unit; preserving all state")
   if active=="active" and fragment!=str(UNIT):
    raise CoreRuntimeError("active unit is not the journal-owned unit; preserving all state")
   record["cleanup_allow_partial"]=False
  record["state"]="retiring"
  _replace_journal(record)
 active=_run(["systemctl","is-active",SERVICE],False).stdout.strip()
 fragment=_run(["systemctl","show","--property=FragmentPath","--value",SERVICE],False).stdout.strip()
 if active=="active":
  if fragment!=str(UNIT): raise CoreRuntimeError("active service is not journal-owned; preserving all state")
  _run(["systemctl","disable","--now",SERVICE])
 if _run(["systemctl","is-active",SERVICE],False).stdout.strip()=="active":
  raise CoreRuntimeError("journal-owned service remains active; preserving files")
 mainpid=_run(["systemctl","show","--property=MainPID","--value",SERVICE],False).stdout.strip()
 if mainpid and mainpid!="0" and Path("/proc",mainpid).exists():
  raise CoreRuntimeError("service process remains after stop; preserving files")
 if _owned_listener(): raise CoreRuntimeError("journal-owned listener remains after stop; preserving files")
 for path,key,uid,gid,mode in FILE_CONTRACT:
  if not path.exists() and not path.is_symlink(): continue
  if path.is_symlink() or not path.is_file():
   raise CoreRuntimeError("owned service path has unsafe type; preserving remaining files")
  st=path.stat()
  if (st.st_uid,st.st_gid,stat.S_IMODE(st.st_mode),st.st_nlink)!=(uid,gid,mode,1):
   raise CoreRuntimeError("owned service path metadata changed; preserving remaining files")
  if not record.get("cleanup_allow_partial") and _digest(path)!=record.get(key):
   raise CoreRuntimeError("owned service file changed; preserving remaining files")
  if path==TOKEN and record.get(key) is None:
   raw=path.read_bytes()
   if not raw.endswith(b"\n") or len(raw)!=65:
    raise CoreRuntimeError("partial credential is not the journaled generated token")
  path.unlink()
 _run(["systemctl","daemon-reload"])
 JOURNAL.unlink()
 _sync_directory(JOURNAL.parent)
 return "journal-owned core service files removed; Hermes home, PM runtime, and workspace preserved"
__all__=["CoreRuntimeError","install_or_resume","migrate_owned_core_to_adapter_path",
         "recover_owned_core_from_adapter_migration","refresh_resources_discovery","rollback","status"]
